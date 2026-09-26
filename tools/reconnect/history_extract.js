// Full paginating on-demand history extractor. Loads on-disk Signal state so E2E works, reconnects
// once, and for each chat repeatedly fetches messages OLDER than the oldest known (re-anchoring on
// each page's oldest) until the chat is exhausted. Downloads+decrypts+parses each HistorySync blob
// in-process. Merges with the on-disk id set and writes recovered (not-on-disk) messages.
// Own account only. Env: TOP (chats, default 5), COUNT (per page, 50), MAXPAGES (per chat, 10).
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path'), crypto = require('crypto'), https = require('https'), zlib = require('zlib');
let P=null; try{P=require('pino');}catch(e){}
const TOP=+(process.env.TOP||5), COUNT=+(process.env.COUNT||50), MAXPAGES=+(process.env.MAXPAGES||10);
// inputs (creds_in.json etc.) may be written by the frozen .exe into CWD, not this folder — resolve flexibly.
const findFile=(name)=>{ for(const c of [path.resolve(process.cwd(),name), path.join(__dirname,name)]){ if(fs.existsSync(c)) return c; } return null; };
const mustFind=(name)=>{ const p=findFile(name); if(!p){ console.error('[!] '+name+' not found in CWD or '+__dirname); process.exit(4); } return p; };
const OUT=path.resolve(process.cwd(),'history_recovered.json');

const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function fetchBlobOnce(directPath){ return new Promise((res,rej)=>{
  const req=https.get("https://mmg.whatsapp.net"+directPath,{headers:{'User-Agent':'WhatsApp/2.3000.0','Origin':'https://web.whatsapp.com'}},
    r=>{ if(r.statusCode!==200){ r.resume(); return rej(new Error('HTTP '+r.statusCode)); } const c=[]; r.on('data',d=>c.push(d)); r.on('end',()=>res(Buffer.concat(c))); });
  req.on('error',rej);
  req.setTimeout(20000, ()=>req.destroy(new Error('socket timeout')));   // don't let a stalled CDN socket hang forever
}); }
async function fetchBlob(directPath){ let e; for(let i=0;i<3;i++){ try{ return await fetchBlobOnce(directPath); }catch(err){ e=err; await sleep(800); } } throw e; }
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
  const preKeys=S.preKeys, mem={};
  const store={ get:(t,ids)=>{const d={};for(const id of ids){const k=mem[`${t}-${id}`];if(k!==undefined){if(k!==null)d[id]=k;continue;}if(t==='pre-key'){const p=preKeys[String(id)];if(p)d[id]={private:bb(p.private),public:bb(p.public)};}}return d;},
    set:data=>{for(const t in data)for(const id in data[t])mem[`${t}-${id}`]=data[t][id];} };
  let version=[2,3000,1023223821]; try{version=(await B.fetchLatestBaileysVersion()).version;}catch(e){}
  const sock=makeWASocket({version,auth:{creds,keys:store},logger:P?P({level:'silent'}):undefined,
    printQRInTerminal:false,markOnlineOnConnect:true,syncFullHistory:false,
    // CRITICAL: accept ON_DEMAND history only, and decline the INITIAL (RECENT/bootstrap) sync.
    // On connect Baileys calls ev.buffer() and holds every event. If this predicate says yes to the
    // initial sync it waits for that notification, enters 'Syncing', and only flushes after
    // resyncAppState() finishes -- which needs app-state-sync keys we deliberately do not restore (we
    // recover identity + prekeys only). resyncAppState then never completes, ev.flush() never runs, and
    // the on-demand replies sit in the buffer forever, looking exactly like "the phone never answered".
    // Declining here takes the 'History sync is disabled by config' branch -> Online + immediate flush,
    // while ON_DEMAND notifications are still processed (ON_DEMAND is in PROCESSABLE_HISTORY_TYPES).
    shouldSyncHistoryMessage:h=>{ try{ return !!h && h.syncType===B.proto.Message.HistorySyncNotification.HistorySyncType.ON_DEMAND; }catch(e){ return false; } },
    getMessage:async()=>undefined,browser:['Forensic','Recovery','1.0']});

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
  sock.ev.on('messages.upsert', async u=>{ for(const m of (u.messages||[])){
    const hn=histNotif(m.message); if(!hn) continue;
    const sid=hn.peerDataRequestSessionId; const r=resolveFor(sid,'upsert');
    if(!r) continue;
    let msgs=null;                  // null = download/decode error (distinct from [] = genuine empty page)
    try{ const blob=await fetchBlob(hn.directPath); const inf=decryptHistory(blob, Buffer.from(hn.mediaKey));
         msgs=flatten(B.proto.HistorySync.decode(inf)); }
    catch(e){ console.error('  blob err', e.message); }
    r(msgs); } });

  // Baileys ALSO processes the on-demand history internally (Utils/process-message.js) and emits it here
  // — its own download+decrypt of the same blob, keyed by the same peerDataRequestSessionId. This is the
  // event Baileys officially emits for history; the messages.upsert path above may not fire on every
  // version, so listen on both and let whichever resolves first win (the other is a no-op).
  sock.ev.on('messaging-history.set', d=>{
    if(!d) return;
    const sid=d.peerDataRequestSessionId; const r=resolveFor(sid,'messaging-history.set');
    if(!r) return;
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
  const requestPage=(key,tsSec)=>new Promise(res=>{
    let id=null; const timer=setTimeout(()=>{ if(id!=null) pending.delete(id); res(null); }, 45000);
    sock.fetchMessageHistory(COUNT, key, toMs(tsSec))
      .then(rid=>{ id=rid; lastRequestId=rid; pending.set(rid, msgs=>{ clearTimeout(timer); res(msgs); }); })
      .catch(e=>{ clearTimeout(timer); console.error('  fetch err', e.message); res(null); }); });

  const all=new Map(); let done=false, opened=false;
  // Checkpoint the accumulated messages to disk. Called after EVERY page (not just at the end) so a
  // kill/crash/timeout never loses what was already pulled (writes atomically via a temp rename).
  const writeOut=()=>{ try{
    const arr=[...all.values()]; const nw=arr.filter(m=>!ondisk.has(m.id));
    const byChat={}; for(const m of nw) byChat[m.chat]=(byChat[m.chat]||0)+1;
    fs.writeFileSync(OUT+'.tmp', JSON.stringify({recovered_total:arr.length, new_not_on_disk:nw.length, by_chat:byChat, messages:nw},null,1));
    fs.renameSync(OUT+'.tmp', OUT);
    return {tot:arr.length, nw:nw.length, chats:Object.keys(byChat).length};
  }catch(e){ console.error('  [checkpoint err]', e.message); return null; } };
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
      await sleep(4000);
      for(const a of targets){
        let key={remoteJid:a.chat,id:a.oldest_id,fromMe:!!a.oldest_fromMe}, ts=a.oldest_ts, got=0;
        for(let pg=0; pg<MAXPAGES; pg++){
          const msgs=await requestPage(key, ts);
          if(msgs===null){ console.error(`  ${a.chat.slice(0,22)} page${pg}: no response`); break; }
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
      }
      console.error('[*] pagination complete'); finish(0);
    }
  });
  setTimeout(()=>{ console.error('[maxrun]'); finish(0); }, 590000);
})().catch(e=>{ console.error('FATAL',e); process.exit(9); });
