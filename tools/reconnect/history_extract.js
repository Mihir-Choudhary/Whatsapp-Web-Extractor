// Full paginating on-demand history extractor. Loads on-disk Signal state so E2E works, reconnects
// once, and for each chat repeatedly fetches messages OLDER than the oldest known (re-anchoring on
// each page's oldest) until the chat is exhausted. Downloads+decrypts+parses each HistorySync blob
// in-process. Merges with the on-disk id set and writes recovered (not-on-disk) messages.
// Own account only. Env: TOP (chats, default 5), COUNT (per page, 50), MAXPAGES (per chat, 10).
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
// Baileys' generated proto is behind the live client. proto_patch adds the fields WA Web actually
// sends, with the field numbers read from WA Web's own internalSpec (not guessed).
try{ const {patched}=require('./proto_patch').patch(B);
     if(patched.length) console.error('[i] proto patched:', patched.join(', ')); }
catch(e){ console.error('[!] proto patch skipped:', e&&e.message); }
const fs = require('fs'), path = require('path'), crypto = require('crypto'), https = require('https'), zlib = require('zlib');
let P=null; try{P=require('pino');}catch(e){}
const TOP=+(process.env.TOP||5), COUNT=+(process.env.COUNT||50), MAXPAGES=+(process.env.MAXPAGES||10);
// inputs (creds_in.json etc.) may be written by the frozen .exe into CWD, not this folder — resolve flexibly.
const findFile=(name)=>{ for(const c of [path.resolve(process.cwd(),name), path.join(__dirname,name)]){ if(fs.existsSync(c)) return c; } return null; };
const mustFind=(name)=>{ const p=findFile(name); if(!p){ console.error('[!] '+name+' not found in CWD or '+__dirname); process.exit(4); } return p; };
const OUT=path.resolve(process.cwd(),'history_recovered.json');

const sleep=ms=>new Promise(r=>setTimeout(r,ms));

// Headers copied verbatim from a NetLog capture of WhatsApp Web fetching a real history chunk. They
// are not cosmetic: static.whatsapp.net already returned HTTP 400 to this project for a request whose
// only fault was a bare `Accept: */*`, so these endpoints do inspect the header set. The captured GET
// carried no credential of any kind -- the `oh=` signature in the URL IS the authorization.
const CDN_HEADERS={
  'accept':'*/*',
  'accept-language':'en-US,en;q=0.9',
  'origin':'https://web.whatsapp.com',
  'referer':'https://web.whatsapp.com/',
  'sec-fetch-site':'cross-site',
  'sec-fetch-mode':'cors',
  'sec-fetch-dest':'empty',
  'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
              +'Chrome/154.0.0.0 Safari/537.36',
};

// PREFER THE SIGNED URL the notification gives us. The same capture shows the real client fetching
//   https://media-<pop>.cdn.whatsapp.net/v/t62.31111-24/<name>.enc?ccb=11-4&oh=<sig>&oe=<expiry>
//     &_nc_sid=..&hash=<fileEncSha256>&mms-type=md-msg-hist
// i.e. a SIGNED object on a per-PoP CDN host, in the history bucket t62.31111-24. Rebuilding
// "https://mmg.whatsapp.net"+directPath throws the signature away. That is the same mistake that
// previously capped media recovery at roughly one day: an unsigned path is served only briefly.
// History chunks survive it today because the phone uploaded them seconds earlier, which makes this
// a latent failure rather than a visible one -- exactly the kind that reappears as "the phone stopped
// answering". Baileys has the same flaw and cannot be relied on here: its guard is
//   isValidMediaUrl = url?.startsWith('https://mmg.whatsapp.net/')
// so it REJECTS the signed media-*.cdn.whatsapp.net URL as invalid and falls back to the unsigned
// rebuild. We take the signed one when the notification carries it.
function fetchBlobOnce(ref){ return new Promise((res,rej)=>{
  const direct=typeof ref==='string'?ref:(ref&&ref.directPath);
  const signed =typeof ref==='string'?null:(ref&&ref.url);
  // a signed absolute URL on any whatsapp.net CDN host wins; otherwise the unsigned reconstruction
  const target=(signed&&/^https:\/\/[^/]*\.whatsapp\.net\//.test(signed)&&/[?&]oh=/.test(signed))
    ? signed : ("https://mmg.whatsapp.net"+direct);
  const req=https.get(target,{headers:CDN_HEADERS},
    r=>{ if(r.statusCode!==200){ r.resume(); return rej(new Error('HTTP '+r.statusCode)); } const c=[]; r.on('data',d=>c.push(d)); r.on('end',()=>res(Buffer.concat(c))); });
  req.on('error',rej);
  req.setTimeout(20000, ()=>req.destroy(new Error('socket timeout')));   // don't let a stalled CDN socket hang forever
}); }
async function fetchBlob(ref){ let e; for(let i=0;i<3;i++){ try{ return await fetchBlobOnce(ref); }catch(err){ e=err; await sleep(800); } } throw e; }
function decryptHistory(blob, mediaKey){
  const exp=Buffer.from(crypto.hkdfSync('sha256', mediaKey, Buffer.alloc(32), Buffer.from('WhatsApp History Keys'), 112));
  const iv=exp.subarray(0,16), ck=exp.subarray(16,48);
  const d=crypto.createDecipheriv('aes-256-cbc', ck, iv);
  const pt=Buffer.concat([d.update(blob.subarray(0,-10)), d.final()]);
  try { return zlib.inflateSync(pt); }                       // history blobs are zlib; fall back to gzip/raw for parity
  catch(e){ try { return zlib.gunzipSync(pt); } catch(e2){ return pt; } } }
function txt(m){ if(!m) return ''; const c=m.conversation||m.extendedTextMessage?.text
  ||m.imageMessage?.caption||m.videoMessage?.caption||m.documentMessage?.caption; return c||''; }
function flatten(hs){ const out=[]; for(const conv of (hs.conversations||[])){ for(const hm of (conv.messages||[])){
  const w=hm.message; if(!w||!w.key) continue; out.push({chat:conv.id||w.key.remoteJid, id:w.key.id,
    fromMe:!!w.key.fromMe, ts:Number(w.messageTimestamp)||0, text:txt(w.message), type:w.message?Object.keys(w.message)[0]:'?'}); } } return out; }
function histNotif(message){ // dig through device/ephemeral wrappers
  let m=message; for(let i=0;i<4&&m;i++){ if(m.protocolMessage?.historySyncNotification) return m.protocolMessage.historySyncNotification;
    m=m.deviceSentMessage?.message||m.ephemeralMessage?.message||m.viewOnceMessage?.message; } return null; }

(async()=>{
  const inp=JSON.parse(fs.readFileSync(mustFind('creds_in.json')));
  if(!inp.account){ console.error('[!] creds_in.json has no account (adv_signed_identity missing) — re-run export_baileys_creds'); process.exit(2); }
  const S=JSON.parse(fs.readFileSync(mustFind('signal_state.json')));
  const A=JSON.parse(fs.readFileSync(mustFind('anchors.json')));
  if(!A||!Array.isArray(A.anchors)||!Array.isArray(A.ondisk_ids)) throw new Error("anchors.json malformed: need {anchors:[...], ondisk_ids:[...]}");
  for(const a of A.anchors){ if(!a.chat||!a.oldest_id||a.oldest_ts==null) throw new Error("anchors.json entry missing chat/oldest_id/oldest_ts: "+JSON.stringify(a).slice(0,80)); }
  const ondisk=new Set(A.ondisk_ids); const targets=A.anchors.slice(0,TOP);
  const bb=b=>Buffer.from(b,'base64');
  const creds=B.initAuthCreds();
  creds.noiseKey={private:bb(inp.noise_priv),public:bb(inp.noise_pub)};
  creds.signedIdentityKey={private:bb(S.signedIdentityKey.private),public:bb(S.signedIdentityKey.public)};
  creds.registrationId=S.registrationId;
  creds.signedPreKey={keyId:S.signedPreKey.keyId,keyPair:{private:bb(S.signedPreKey.private),public:bb(S.signedPreKey.public)},signature:S.signedPreKey.signature?bb(S.signedPreKey.signature):Buffer.alloc(0)};
  creds.me={id:inp.me_id,lid:inp.lid};
  creds.account={details:bb(inp.account.details),accountSignatureKey:bb(inp.account.accountSignatureKey),accountSignature:bb(inp.account.accountSignature),deviceSignature:bb(inp.account.deviceSignature)};
  creds.registered=true; creds.platform='web';
  // creds_in.json and signal_state.json are exported SEPARATELY, and `creds` is assembled from both
  // (me/account/noise from the first, registrationId/identity/prekeys from the second). Refresh one
  // and not the other and you get a chimera: the old device's identity with the new device's
  // registration, which authenticates as nothing in particular and is then impossible to diagnose
  // from the symptom, because the symptom is silence. They both carry registrationId, so compare it.
  if(inp.registrationId!=null && S.registrationId!=null && Number(inp.registrationId)!==Number(S.registrationId)){
    console.error(`[x] creds_in.json (regId ${inp.registrationId}, device :${inp.device}) and `
      +`signal_state.json (regId ${S.registrationId}) describe DIFFERENT registrations -- one of them is `
      +`stale. Re-export BOTH from the same profile: \`wawf history\` does this itself, or run `
      +`scripts/export_signal_state.py and the creds export together.`);
    process.exit(5);
  }
  // Signal sessions + sender keys recovered from the browser profile, plus whatever this tool
  // learned on earlier runs. Without these every inbound payload fails to decrypt (SessionError)
  // and is dropped, including the phone's history reply.
  // If this tool has been paired as its OWN device (tools/reconnect/pair.js), use that instead of
  // anything derived from the browser profile. That severs the dependency that caused every failure
  // in this project: our own registration, our own Signal identity and prekeys, our own session to
  // repair -- so history works however long it has been since WhatsApp Web last ran, and nothing we
  // do can degrade the subject's linked device.
  const DEVICE_DIR=path.join(__dirname,'wawf_device');
  let ownDevice=null;
  if(fs.existsSync(path.join(DEVICE_DIR,'creds.json'))){
    try{
      const st=await B.useMultiFileAuthState(DEVICE_DIR);
      if(st.state&&st.state.creds&&st.state.creds.registered&&st.state.creds.me){ ownDevice=st; }
    }catch(e){ console.error('[!] could not load the paired device state:', e&&e.message); }
  }
  if(ownDevice){
    const red=x=>String(x||'').replace(/\d{5,}/g,m=>m.slice(0,4)+'*'.repeat(m.length-4));
    console.error(`[i] using THIS TOOL'S OWN linked device (${red(ownDevice.state.creds.me.id)}) — `
      +`independent of the browser profile`);
  }

  const signalStore=require('./signal_store');
  const _askPath=findFile('appstate_keys.json');
  const appStateKeys=_askPath?JSON.parse(fs.readFileSync(_askPath,'utf8')):{};
  // Which device does the runtime overlay belong to? With our own paired device, NOT the profile's:
  // its sessions and prekeys live in wawf_device/ (useMultiFileAuthState) and the profile's Signal
  // material is for a different registration. Opening the overlay against the profile anyway meant
  // the persisted decrypt-retry counters -- the one part of it own-device mode actually uses -- were
  // keyed to the wrong registration, and signal_store's own sameDevice check compared creds that had
  // nothing to do with the socket's. So own-device mode gets its own overlay beside its credentials.
  const rt=ownDevice
    ? signalStore.open({signalState:{},creds:ownDevice.state.creds,appStateKeys,
        statePath:signalStore.defaultStatePath(DEVICE_DIR), bufferJSON:B.BufferJSON})
    : signalStore.open({signalState:S,creds,appStateKeys,
        statePath:signalStore.defaultStatePath(path.dirname(mustFind('signal_state.json'))),
        bufferJSON:B.BufferJSON});
  const store=rt.keys;
  console.error(`[i] signal state (${ownDevice?'own paired device':'browser profile'}): `
    +`${rt.stats.sessions} session(s), ${rt.stats.senderKeys} sender key(s), `
    +`${rt.stats.preKeys} prekey(s) | runtime overlay: ${rt.stats.state}, ${rt.stats.carried} record(s) carried over`);
  // Only meaningful when riding the browser profile's registration. With our own paired device the
  // profile's session count is irrelevant -- ownDevice.state carries its own keys.
  if(!ownDevice&&!rt.stats.sessions&&!rt.stats.carried) console.error('[!] no Signal sessions recovered -- inbound messages will NOT decrypt; re-run the credential export against the browser profile');
  // Announce the build THIS profile's browser runs, taken from its own WAVersionBase, in preference to
  // Baileys' default of asking a third-party endpoint (fetchLatestBaileysVersion) and falling back to a
  // hardcoded constant. Not cosmetic: WhatsApp gates on-demand history on an AB prop
  // (`history_sync_on_demand_companion`), and AB prop values are assigned by the server per client
  // version and platform, so announcing a stale build asks for a version-gated feature as the wrong
  // client. Measured on this profile: we announced 2.3000.1043857760, the browser 2.3000.1049127777.
  // Falls back to the old lookup when the profile did not carry one.
  let version=[2,3000,1023223821];
  if(Array.isArray(inp.wa_version)&&inp.wa_version.length===3){
    version=inp.wa_version.map(Number);
    console.error('[i] announcing the profile\'s own client version '+version.join('.'));
  } else {
    try{version=(await B.fetchLatestBaileysVersion()).version;}catch(e){}
    console.error('[i] no wa_version in creds — falling back to '+version.join('.')
      +' (re-export creds to announce the profile\'s build)');
  }
  // Make the FIRST retry receipt carry a fresh prekey bundle. When a payload cannot be decrypted
  // (inevitable here: the session in the profile is a snapshot of a live ratchet that has moved on)
  // the only way to recover is to ask the sender to re-encrypt to a NEW session, and the sender can
  // only do that if the retry receipt includes our keys. Baileys attaches them from retry #2
  // (`if (retryCount > 1 || forceIncludeKeys)`) and keeps the counter in a per-process cache, so a
  // short forensic run never reached #2: every retry just fetched the same unreadable ciphertext
  // again. Starting the counter at 1 asks for re-encryption immediately. The prekey it mints is
  // persisted by signal_store, so the phone's re-encrypted copy is still decryptable next run.
  // ... but NEVER for a peer message. A PDO response is one-shot: the phone does not re-encrypt one
  // on retry (observed 0 of ~100). Retrying it only keeps it queued, and an unacked queue is fatal
  // here -- see the forced flush below. So peer messages report a count above maxMsgRetryCount,
  // which makes Baileys skip the retry, and we acknowledge them instead.
  const peerIds=new Set();
  const retryCounters=new Map();
  const msgRetryCounterCache={ get:k=>{ const id=String(k).split(':')[0];
      if(peerIds.has(id)) return 1e6;                 // peer replies are one-shot: never retry
      const v=retryCounters.get(k);
      // seed from the PERSISTED count so Baileys' maxMsgRetryCount caps across runs, not per-process
      return v===undefined ? Math.max(1, rt.retryCount(id)) : v; },
    set:(k,v)=>retryCounters.set(k,v), del:k=>retryCounters.delete(k) };
  const authState = ownDevice ? ownDevice.state : {creds,keys:store};
  // OPT-IN, default OFF: WA_SUBPLATFORM=win32 (or darwin) makes Baileys declare
  // ClientPayload.WebInfo.webSubPlatform as WIN32/DARWIN instead of WEB_BROWSER. It only takes effect
  // via getWebInfo(), which needs BOTH browser[0] to be a known OS name and syncFullHistory true --
  // and on an already-registered login syncFullHistory touches nothing else: requireFullSync and
  // historySyncConfig live in generateRegistrationNode (pairing only), and shouldSyncHistoryMessage is
  // ours, so Baileys' auto-derived one is never used.
  //
  // Why it is worth having: WhatsApp's getEarliestHistorySyncDate() grants a desktop client
  // ABProp('history_sync_on_demand_time_boundary_days_desktops') = 1095 days of reachable history,
  // against YEAR_SECONDS for a browser. Three years instead of one.
  //
  // Why it is NOT the default: it means claiming to be the Windows desktop app while the DeviceProps
  // registered at pair time -- by a browser -- say otherwise, and the real browser, which demonstrably
  // CAN fetch history, sends WEB_BROWSER. So this is a deliberate DIVERGENCE from the reference
  // client, not alignment with it. The last time this project diverged on a hunch (duplicating the ED
  // routing parameter) it silently broke serving and cost a day. Enable it to test, with a probe.
  const SUBPLAT=String(process.env.WA_SUBPLATFORM||'').toLowerCase();
  const subplatOS={win32:'Windows',darwin:'Mac OS'}[SUBPLAT];
  if(subplatOS) console.error(`[i] declaring webSubPlatform ${SUBPLAT.toUpperCase()} (WA_SUBPLATFORM) `
    +`— diverges from the browser, which sends WEB_BROWSER`);
  const sock=makeWASocket({version,auth:authState,syncFullHistory:!!subplatOS,logger:P?P({level:'silent'}):undefined,msgRetryCounterCache,
    printQRInTerminal:false,markOnlineOnConnect:true,syncFullHistory:false,
    // CRITICAL: accept ON_DEMAND history only, and decline the INITIAL (RECENT/bootstrap) sync.
    // On connect Baileys calls ev.buffer() and holds every event. If this predicate says yes to the
    // initial sync it waits for that notification, enters 'Syncing', and only flushes after
    // resyncAppState() finishes. (We DO restore app-state-sync keys now -- export_appstate_keys.py
    // recovers them from the profile and resyncAppState is driven explicitly after connect -- but
    // tying the event flush to it is still the wrong dependency: one failed patch fetch would strand
    // every on-demand reply in the buffer, looking exactly like "the phone never answered".)
    // Declining here takes the 'History sync is disabled by config' branch -> Online + immediate flush,
    // while ON_DEMAND notifications are still processed (ON_DEMAND is in PROCESSABLE_HISTORY_TYPES).
    shouldSyncHistoryMessage:h=>{ try{ return !!h && h.syncType===B.proto.Message.HistorySyncNotification.HistorySyncType.ON_DEMAND; }catch(e){ return false; } },
    getMessage:async()=>undefined,browser:[subplatOS||'Forensic','Recovery','1.0']});

  // Correlate each response to its request by peerDataRequestSessionId (== the fetchMessageHistory id),
  // so a late/duplicate notification can't resolve a different chat's page. Only matched notifications
  // are downloaded. The resolver is bound to its own promise, so a late completion after timeout is a no-op.
  const pending=new Map();          // requestId -> resolver
  let lastRequestId=null;           // fallback target when a reply's session id doesn't match (see resolveFor)
  // Never DISCARD a history blob we were sent. If the reply's peerDataRequestSessionId doesn't match a
  // pending id (id schemes can differ by WhatsApp/Baileys version), fall back to the outstanding request
  // instead of dropping recovered evidence on the floor -- silently ignoring it is indistinguishable from
  // "the phone never answered", which is exactly the failure that is hardest to diagnose.
  const resolveFor=(sid,what)=>{
    let r=sid!=null && pending.get(sid);
    if(r){ pending.delete(sid); return r; }
    if(pending.size===1){ const [k,v]=pending.entries().next().value;
      console.error(`  [${what}] session id ${sid} did not match; attributing to the single outstanding request ${k}`);
      pending.delete(k); return v; }
    if(lastRequestId!=null && pending.has(lastRequestId)){ const v=pending.get(lastRequestId);
      console.error(`  [${what}] session id ${sid} did not match; attributing to the most recent request ${lastRequestId}`);
      pending.delete(lastRequestId); return v; }
    console.error(`  [${what}] unmatched reply (session ${sid}) and no outstanding request -- ignored`);
    return null;
  };
  sock.ev.on('creds.update', ()=>{ if(ownDevice) ownDevice.saveCreds(); else rt.save(); });   // persist rotated prekeys / app-state ids
  // Note which stanzas are peer messages before Baileys' async decrypt reaches its retry decision.
  sock.ws.on('CB:message', node=>{ const at=node.attrs||{}; if(at.category==='peer') peerIds.add(at.id); });
  // Raising the retry floor above skips the placeholder-resend request Baileys makes on retry #1,
  // so ask for it explicitly: the two mechanisms are complementary. The retry receipt hands the
  // sender our keys so it CAN re-encrypt; the placeholder request asks the phone to actually
  // resend the specific message it could not deliver readably. Peer messages get neither -- they
  // get acknowledged, because an unacked message stays in the offline queue forever.
  // An undecryptable message must not be retried forever. Baileys sends a retry INSTEAD of a
  // delivery receipt, so such a message is never acknowledged, stays in the offline queue, is
  // redelivered on every connect and earns another retry -- observed: 53 stanzas producing 1,677
  // decrypt attempts, 1,637 of them "Bad MAC" and 27 "Key used already or never filled". The latter
  // are provably messages we ALREADY decrypted on an earlier run (libsignal deletes each message key
  // after use), so they can never succeed no matter how often the primary resends them.
  // After MAX_DECRYPT_ATTEMPTS across ALL runs we stop: no more retries, and no acknowledgement
  // either. Record it as unrecoverable and move on.
  const MAX_DECRYPT_ATTEMPTS=Number(process.env.MAX_DECRYPT_ATTEMPTS||3);
  const unrecoverable=[]; const reportedUndecryptable=new Set();
  sock.ev.on('messages.upsert',u=>{ for(const m of (u.messages||[])){
    if(m.messageStubType!==B.proto.WebMessageInfo.StubType.CIPHERTEXT||!m.key) continue;
    if(peerIds.has(m.key.id)){
      Promise.resolve(sock.sendReceipt(m.key.remoteJid,undefined,[m.key.id],'peer_msg')).catch(()=>{});
      continue;
    }
    const n=rt.bumpRetry(m.key.id);
    if(n>MAX_DECRYPT_ATTEMPTS){
      // Give up QUIETLY. Do not acknowledge it -- an ack says "received and processed", and saying
      // that about a payload we could not read is a lie to the server. Do not keep retrying either:
      // 974 retry receipts across runs is what a broken or hostile companion looks like, and device
      // :43 was revoked after exactly that. Record it and move on.
      if(!reportedUndecryptable.has(m.key.id)){ reportedUndecryptable.add(m.key.id);
        unrecoverable.push({id:m.key.id,chat:m.key.remoteJid,attempts:n}); }
    } else {
      Promise.resolve(sock.requestPlaceholderResend(m.key)).catch(()=>{});
    }
  } });
  const all=new Map(); let done=false, opened=false, cooldownTripped=false;
  // Checkpoint the accumulated messages to disk. Called after EVERY page (not just at the end) so a
  // kill/crash/timeout never loses what was already pulled (writes atomically via a temp rename).
  const writeOut=()=>{ try{
    const arr=[...all.values()]; const nw=arr.filter(m=>!ondisk.has(m.id));
    const byChat={}; for(const m of nw) byChat[m.chat]=(byChat[m.chat]||0)+1;
    fs.writeFileSync(OUT+'.tmp', JSON.stringify({recovered_total:arr.length, new_not_on_disk:nw.length, by_chat:byChat, messages:nw},null,1));
    fs.renameSync(OUT+'.tmp', OUT);
    return {tot:arr.length, nw:nw.length, chats:Object.keys(byChat).length};
  }catch(e){ console.error('  [checkpoint err]', e.message); return null; } };
  // Declared ABOVE the event handlers on purpose. The handlers bank late arrivals into `all`
  // and checkpoint through `writeOut`, and both are `const`: if an await were ever introduced
  // between registering a handler and these lines, an early event would hit the temporal dead
  // zone and throw instead of saving messages. Keeping them first removes that possibility.

  sock.ev.on('messages.upsert', async u=>{ for(const m of (u.messages||[])){
    const hn=histNotif(m.message); if(!hn) continue;
    const sid=hn.peerDataRequestSessionId; const r=resolveFor(sid,'upsert');
    // SALVAGE A LATE ANSWER. `resolveFor` returning null means no request is waiting any more --
    // almost always because we timed out and deleted the pending entry. The old code did
    // `if(!r) continue;` here, i.e. it threw the notification away without downloading it, which
    // directly contradicts the rule stated above this handler: never discard a history blob we were
    // sent. It also made a slow phone indistinguishable from a silent one, and shortening the
    // per-request deadline to the reference client's 10s widened the window in which that happens.
    // The chunk is still valid evidence and every message in it carries its own chat, so it needs no
    // promise to be filed correctly -- download it, bank it, and say so.
    let msgs=null;                  // null = download/decode error (distinct from [] = genuine empty page)
    try{ const blob=await fetchBlob(hn); const inf=decryptHistory(blob, Buffer.from(hn.mediaKey));
         msgs=flatten(B.proto.HistorySync.decode(inf)); }
    catch(e){ console.error('  blob err', e.message); }
    if(!r){
      if(msgs&&msgs.length){
        let fresh=0; for(const mm of msgs){ if(!all.has(mm.id)) fresh++; all.set(mm.id,mm); }
        const w=writeOut();
        console.error(`  [late] a notification arrived after its request had timed out: banked `
          +`${msgs.length} message(s), ${fresh} new`+(w?` (total ${w.tot})`:''));
      }
      continue;
    }
    r(msgs); } });

  // Baileys ALSO processes the on-demand history internally (Utils/process-message.js) and emits it here
  // — its own download+decrypt of the same blob, keyed by the same peerDataRequestSessionId. This is the
  // event Baileys officially emits for history; the messages.upsert path above may not fire on every
  // version, so listen on both and let whichever resolves first win (the other is a no-op).
  sock.ev.on('messaging-history.set', d=>{
    if(!d) return;
    const sid=d.peerDataRequestSessionId; const r=resolveFor(sid,'messaging-history.set');
    // Same salvage as above: Baileys has already downloaded and decrypted this one itself, so a late
    // arrival costs nothing to keep and dropping it would lose recovered messages outright.
    if(!r){
      const late=(d.messages||[]).map(w=>({ chat:w.key&&w.key.remoteJid, id:w.key&&w.key.id,
        fromMe:!!(w.key&&w.key.fromMe), ts:Number(w.messageTimestamp)||0, text:txt(w.message),
        type:w.message?Object.keys(w.message)[0]:'?' })).filter(x=>x.id);
      if(late.length){
        let fresh=0; for(const mm of late){ if(!all.has(mm.id)) fresh++; all.set(mm.id,mm); }
        const w2=writeOut();
        console.error(`  [late] history set arrived after its request had timed out: banked `
          +`${late.length} message(s), ${fresh} new`+(w2?` (total ${w2.tot})`:''));
      }
      return;
    }
    const msgs=(d.messages||[]).map(w=>({ chat:w.key&&w.key.remoteJid, id:w.key&&w.key.id, fromMe:!!(w.key&&w.key.fromMe),
      ts:Number(w.messageTimestamp)||0, text:txt(w.message), type:w.message?Object.keys(w.message)[0]:'?' })).filter(m=>m.chat&&m.id);
    console.error('  [messaging-history.set] '+msgs.length+' msgs for session '+sid);
    r(msgs);
  });

  // The proto field is HistorySyncOnDemandRequest.oldestMsgTimestampMs -- MILLISECONDS. WhatsApp Web's
  // on-disk `t` and WebMessageInfo.messageTimestamp are both SECONDS, so passing them through unscaled
  // asked the phone for messages older than ~Jan 1970: nothing is older, so the phone answered nothing and
  // every chat timed out as "no response". The browser's own button sends real milliseconds, which is why
  // it worked where this did not. Convert here, tolerating a value that is already ms.
  const toMs=t=>{ t=Number(t)||0; return t>1e12 ? Math.round(t) : Math.round(t*1000); };
  // Register the resolver under the returned id — the id resolves locally, long before any round-trip
  // response, so there is no registration race.
  // Ask for a page ourselves instead of via sock.fetchMessageHistory(), for one reason: WHICH self
  // jid the peer message is addressed to decides WHICH Signal session encrypts it. relayMessage's
  // peer path derives the recipient as
  //   jidEncode(isMe && isLid ? creds.me.lid : user, isLid ? 'lid' : 's.whatsapp.net', device)
  // and fetchMessageHistory -> sendPeerDataOperationMessage always passes the PHONE-NUMBER jid. So
  // the request went out on the <pn>.0 session while the phone's answers come back on <lid>.0 --
  // two different sessions. We renegotiate the one we send on, so the phone could always READ our
  // request (it acks it), but it never re-keys the one it ANSWERS on, so every reply landed on a
  // ratchet we only had a stale snapshot of and was discarded. Addressing the LID jid puts the
  // request on that same session, so the phone re-keys it and the answer is readable.
  // Measured, same chat and anchor in one run: PN-routed -> silent, LID-routed -> 50 messages.
  const PDO_TYPE=B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE;
  const selfLid=(()=>{ const l=ownDevice?ownDevice.state.creds.me&&ownDevice.state.creds.me.lid:inp.lid;
                       return l?B.jidNormalizedUser(l):null; })();
  const askHistory=(count,key,tsMs)=>{
    // EXACTLY the field set WhatsApp Web sends, no more. Its own request builder is:
    //   return {chatJid:r, oldestMsgId:a?.id.id, oldestMsgFromMe:a?.id.fromMe,
    //           onDemandMsgCount:i, oldestMsgTimestampMs:a?.t*1e3, supportInlineResponse:!0}
    // `accountLid` exists in the proto (field 6) and we used to populate it, but the reference
    // client never sets it on THIS request -- 0 of its 88 `accountLid` references sit in a
    // history-on-demand path. Sending a field the real client omits is gratuitous divergence on the
    // one request whose shape we cannot observe being accepted, so we stop sending it. LID *routing*
    // below is unrelated: that is the envelope's destination, not a field inside the request.
    const req={chatJid:key.remoteJid, oldestMsgId:key.id, oldestMsgFromMe:!!key.fromMe,
      onDemandMsgCount:count, oldestMsgTimestampMs:tsMs, supportInlineResponse:true};
    const pdo={historySyncOnDemandRequest:req, peerDataOperationRequestType:B.proto.Message.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND};
    if(!selfLid) return sock.sendPeerDataOperationMessage(pdo);        // no LID known: old behaviour
    return sock.relayMessage(selfLid, {protocolMessage:{peerDataOperationRequestMessage:pdo, type:PDO_TYPE}},
      {additionalAttributes:{category:'peer', push_priority:'high_force'}});
  };

  // WhatsApp Web's own per-request deadline is the AB prop `history_sync_on_demand_timeout_ms`,
  // whose value is 10000: it declares a request FAILED after 10s and feeds that into the failure
  // record below. We waited 45s, which is not more robust -- it just means a pass over ~250 chats
  // spends 4.5x as long waiting for answers the reference client would already have given up on.
  const REQ_TIMEOUT=Number(process.env.REQ_TIMEOUT_MS||10000);
  const requestPage=(key,tsSec)=>new Promise(res=>{
    let id=null; const timer=setTimeout(()=>{ if(id!=null) pending.delete(id); res(null); }, REQ_TIMEOUT);
    askHistory(COUNT, key, toMs(tsSec))
      .then(rid=>{ id=rid; lastRequestId=rid; pending.set(rid, msgs=>{ clearTimeout(timer); res(msgs); }); })
      .catch(e=>{ clearTimeout(timer); console.error('  fetch err', e.message); res(null); }); });

  const finish=(c)=>{ if(done)return; done=true;
    const r=writeOut();
    if(r) console.error(`\n[DONE] recovered=${r.tot} NEW(not-on-disk)=${r.nw} across ${r.chats} chats -> ${OUT}`);
    try{sock.end();}catch(e){} process.exit(c); };
  // Also flush on external kill (timeout/orphan cleanup) so nothing pulled is lost.
  for(const sig of ['SIGTERM','SIGINT','SIGHUP']) process.on(sig, ()=>finish(0));

  sock.ev.on('connection.update', async u=>{
    if(u.qr){ console.error('[!] QR => creds rejected'); finish(2); }
    if(u.connection==='close'){ const e=u.lastDisconnect&&u.lastDisconnect.error; console.error('[x] closed', e&&e.output&&e.output.statusCode, e&&e.message); finish(opened?0:4); }  // non-zero if we never connected
    if(u.connection==='open'){ opened=true; console.error('[+] OPEN — paginating history for',targets.length,'chats');
      try{await sock.sendPresenceUpdate('available');}catch(e){}
      // THE reason this tool reported "no response" for every chat even when the phone answered.
      // Baileys calls ev.buffer() on connect and flushes it ONLY when the server sends
      // <ib><offline/>, its "offline queue fully handled" marker. That marker needs every queued
      // message acknowledged -- but Baileys does not acknowledge a message it failed to decrypt (it
      // sends a retry request instead), so one unreadable payload wedges the buffer permanently.
      // Nothing then reaches messaging-history.set or messages.upsert: a history page could arrive,
      // decrypt perfectly, and still be recorded as "no response". WhatsApp Web never hits this
      // because it can decrypt everything it is sent. Drive the flush ourselves instead of trusting
      // the queue to complete, and keep driving it, because Baileys re-buffers around its own node
      // processing (processNodeWithBuffer) and around each app-state sync.
      const pump=setInterval(()=>{ try{ if(sock.ev.isBuffering()) sock.ev.flush(); }catch(e){} },1500);
      if(pump.unref) pump.unref();
      await sleep(4000);
      // Rebuild the Signal session with our own primary device from a freshly fetched prekey
      // bundle before asking it for anything. The copy in the browser profile is a snapshot of a
      // live ratchet the phone has since advanced, so its replies would arrive on a chain we
      // cannot derive and be dropped as undecryptable. Forcing the rebuild makes US the initiator,
      // so the reply comes back on a ratchet we hold end to end.
      // Unconditionally, every run: the phone may have re-keyed since (it does so whenever it
      // cannot read something we sent), and a renegotiation costs one of its one-time prekeys,
      // which is far cheaper than a whole pass that returns nothing because the reply was dropped.
      // Hoisted out of the try below: the registration check further down needs it too, and a
      // const inside that block would be a ReferenceError there rather than a syntax error.
      const _me = ownDevice ? ownDevice.state.creds.me : {id:inp.me_id,lid:inp.lid};
      try{
        const selfJids=[...new Set([_me.lid,_me.id].filter(Boolean).map(B.jidNormalizedUser))];
        // force=false: only fetch a prekey bundle if we genuinely have no session. Forcing a fresh
        // handshake on EVERY connect (~56 times over three days) burns one of the peer's one-time
        // prekeys each time and makes us look like a client that cannot hold a session.
        const fetched=await sock.assertSessions(selfJids,false);
        console.error(fetched?'[i] no session with our own device — negotiated one'
                             :'[i] reusing the existing Signal session with our own device');
        if(Object.keys(appStateKeys).length){
          try{ await sock.resyncAppState(B.ALL_WA_PATCH_NAMES,true);
               console.error(`[i] resyncAppState done (${Object.keys(appStateKeys).length} app-state key(s)) — what a live WhatsApp Web session does on every connect`); }
          catch(e){ console.error('[!] resyncAppState failed:', e&&e.message); }
        }
      }catch(e){ console.error('[!] could not rebuild the self session:', e&&e.message, '-- replies may not decrypt'); }

      // IS THIS DEVICE STILL REGISTERED? Ask the server, before spending a pass finding out.
      //
      // This is the check whose absence produced the whole "history works, then stops working, then
      // works again after I reopen WhatsApp Web" loop. A REVOKED companion still completes the Noise
      // handshake and still reaches Baileys' `open`, so connecting proves nothing. Worse, the
      // credentials on disk are a SNAPSHOT: when the browser re-pairs -- which is exactly what
      // "reconnecting WhatsApp Web" does -- the account gets a new device slot with a brand-new
      // registrationId and a brand-new Signal identity, and the exported files silently describe a
      // device that no longer exists. Measured on this profile: stored regId 10115 / device :43
      // against a live profile on regId 11966 / device :44, with a different signedIdentityKey.
      // Running anyway authenticates as the dead device, asks every chat, receives nothing, and looks
      // identical to throttling or to a phone that is simply refusing.
      //
      // A USync device query against our own account settles it in one round trip: if our slot is not
      // in the account's device list, the registration is gone and no amount of retrying will help --
      // the fix is to re-export from the profile, which `wawf history` does on every run.
      try{
        const q=new B.USyncQuery().withDeviceProtocol();
        q.withUser(new B.USyncUser().withId(B.jidNormalizedUser(_me.id)));
        const res=await sock.executeUSyncQuery(q);
        // The device protocol's parser returns { deviceList, keyIndex }, and executeUSyncQuery puts
        // it on each list entry under the protocol's name ('devices'), so the slots live at
        // entry.devices.deviceList. Iterating entry.devices itself throws "object is not iterable",
        // which the catch below would turn into a warning -- leaving this check silently dead.
        const slots=[];
        for(const u2 of ((res&&res.list)||[])){
          const dl=(u2&&u2.devices&&(u2.devices.deviceList||u2.devices))||[];
          if(Array.isArray(dl)) for(const d of dl) slots.push(d.id);
        }
        const ours=(()=>{ const u=String(_me.id||'').split('@')[0]; return u.includes(':')?Number(u.split(':')[1]):0; })();
        if(slots.length && !slots.includes(ours)){
          console.error(`\n[x] this device (:${ours}) is NOT on the account any more -- account device slots: `
            +`[${slots.join(', ')}]. The registration has been revoked or superseded, which is what happens `
            +`when WhatsApp Web re-pairs. History cannot work with these credentials and retrying will not `
            +`change that.\n    FIX: re-export creds + Signal state from the browser profile (\`wawf history\` `
            +`does it automatically every run) so they describe the device the profile is actually on.`);
          return finish(6);
        }
        console.error(`[i] registration confirmed: device :${ours} is on the account (slots [${slots.join(', ')}])`);
      }catch(e){ console.error('[!] could not verify the registration (USync failed:', e&&e.message,
        ') -- continuing, but a silent pass may just mean this device is no longer registered'); }

      // If the first few chats all go unanswered, the phone is not serving this device at all --
      // most likely its companion registration is no longer valid. Say so in seconds rather than
      // grinding through every chat at 45s a time and reporting a mystery hours later.
      const PROBE=Number(process.env.PROBE_CHATS||4); let probeSilent=0, probed=0;
      // WhatsApp Web's own circuit breaker, which this tool did not have. Its failure record is:
      //   on success -> reset {failureCount:0, firstFailureRequestTimeStampSec:undefined}
      //   on failure -> failureCount+=1; firstFailure ??= now;
      //                 if (failureCount >= history_sync_on_demand_failure_limit /*10*/ &&
      //                     now - firstFailure < history_sync_on_demand_cooldown_sec /*7200*/)
      //                        disableRequestSending = true, re-enabled after the cooldown
      // A real client stops asking after 10 unanswered requests in a 2-hour window and then stays
      // quiet for two hours. Ours kept asking for every chat no matter what came back, which is
      // both the slow path and exactly the behaviour that makes a companion look broken.
      const FAIL_LIMIT=Number(process.env.FAIL_LIMIT||10), COOLDOWN=Number(process.env.COOLDOWN_SEC||7200);
      let failCount=0, firstFailSec=null, tripped=false;
      const noteFailure=()=>{ const now=Math.floor(Date.now()/1000);
        if(firstFailSec===null) firstFailSec=now;
        if(++failCount>=FAIL_LIMIT && now-firstFailSec<COOLDOWN) tripped=true; };
      const noteSuccess=()=>{ failCount=0; firstFailSec=null; };
      for(const a of targets){
        let key={remoteJid:a.chat,id:a.oldest_id,fromMe:!!a.oldest_fromMe}, ts=a.oldest_ts, got=0;
        for(let pg=0; pg<MAXPAGES; pg++){
          const msgs=await requestPage(key, ts);
          if(msgs===null){ console.error(`  ${a.chat.slice(0,22)} page${pg}: no response`);
            if(pg===0){ probeSilent++; }
            noteFailure();
            break; }
          noteSuccess();
          if(!msgs.length){ console.error(`  ${a.chat.slice(0,22)} page${pg}: empty (start reached)`); break; }
          for(const m of msgs) all.set(m.id,m);
          got+=msgs.length; msgs.sort((x,y)=>x.ts-y.ts); const o=msgs[0];
          const newc=msgs.filter(m=>!ondisk.has(m.id)).length;
          writeOut();                                     // checkpoint after every page (crash-safe)
          console.error(`  ${a.chat.slice(0,22)} page${pg}: +${msgs.length} (new ${newc}) oldest=${new Date(o.ts*1000).toISOString().slice(0,10)}`);
          key={remoteJid:a.chat,id:o.id,fromMe:!!o.fromMe}; ts=o.ts;
          if(msgs.length<COUNT) { console.error(`  ${a.chat.slice(0,22)}: short page -> done (${got} total)`); break; }
          await sleep(500);
        }
        probed++;
        if(tripped){
          cooldownTripped=true;            // reported to the caller as exit 7, so a pass can be resumed
          console.error(`
[!] ${failCount} unanswered requests inside the ${COOLDOWN}s window. WhatsApp Web itself stops `
            +`here (history_sync_on_demand_failure_limit=${FAIL_LIMIT}) and goes quiet for the `
            +`cooldown, so we do the same rather than keep asking. Run `
            +`tools/reconnect/diag_health.js to tell the causes apart: it asks the server whether `
            +`this device slot is still registered, which is definitive.`);
          break;
        }
        if(probed>=PROBE && probeSilent>=PROBE){
          // Deliberately does NOT claim the registration is dead. Silence has more than one cause
          // and this tool repeatedly mis-attributed it; diag_health.js settles it with a USync
          // device query instead of inferring from silence.
          console.error(`
[!] the first ${PROBE} chats returned NOTHING -- stopping rather than grinding through `
            +`${targets.length} chats. This does not by itself mean the device was revoked. Run `
            +`tools/reconnect/diag_health.js: it reports CONNECT / REGISTERED / SERVED separately, `
            +`and only a REGISTERED failure means the linked device is gone.`);
          break;
        }
        await sleep(Number(process.env.CHAT_DELAY_MS||400));   // be a polite client between chats
      }
      // Exit 7 means "stopped by the cooldown breaker, not finished". The caller can then wait out
      // WhatsApp's cooldown and resume from the checkpoint rather than treating the pass as a failure;
      // a full sweep of a few hundred chats cannot fit inside one cooldown window.
      console.error(cooldownTripped
        ? '[*] stopped by the cooldown breaker — resume after the cooldown to continue deeper'
        : '[*] pagination complete');
      finish(cooldownTripped?7:0);
    }
  });
  setTimeout(()=>{ console.error('[maxrun]'); finish(0); }, 590000);
})().catch(e=>{ console.error('FATAL',e); process.exit(9); });
