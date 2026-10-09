// diag_onehistory.js -- ONE history request for ONE chat, with every inbound stanza logged, to tell
// "the request was refused" apart from "the request was accepted and nobody answered".
//
// The problem this solves
// -----------------------
// A silent history request has had at least three indistinguishable causes: the stanza was never
// accepted, it was accepted but the phone declined, or we are inside a throttle window. Every probe so
// far reported the same thing for all three -- "no response" -- so no amount of repeating it could
// separate them. Repeating it is also the one thing that makes a throttle worse.
//
// The discriminator is the ACK. WhatsApp acknowledges a peer stanza it has accepted, and in a capture
// of the real client the ack came back about 300ms after the request while the history notification
// followed at ~1.7s -- two different responders, so two separately observable facts:
//
//   no ack at all              -> the server did not accept the stanza. Transport or envelope.
//   explicit error / nack      -> refused, with a reason we can read.
//   ack, then nothing          -> WhatsApp took it; the phone did not answer. Throttle or phone-side.
//   ack, then a notification   -> served. History works.
//
// Baileys emits every decoded inbound frame as `ws.on('frame')` before any tag dispatch, so this sees
// the whole conversation rather than the subset Baileys has handlers for.
//
// Deliberately minimal: ONE chat, ONE request, no pagination, no retries, no renegotiation. That
// matters because the cost of being wrong here is another burned throttle window.
//
//   node diag_onehistory.js                  first non-group anchor
//   node diag_onehistory.js --chat <jid>      a specific chat
//   node diag_onehistory.js --wait 90         seconds to listen (default 60)
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const need = n => { const p = findFile(n); if (!p) { console.error('[one] missing ' + n); process.exit(4); } return p; };
const inp = JSON.parse(fs.readFileSync(need('creds_in.json'), 'utf8'));
const S = JSON.parse(fs.readFileSync(need('signal_state.json'), 'utf8'));
const A = JSON.parse(fs.readFileSync(need('anchors.json'), 'utf8'));

const argv = process.argv.slice(2);
const arg = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const WAIT = Number(arg('--wait', 60)) * 1000;
const WANT = arg('--chat', null);
// --as re-addresses the SAME anchor under a different jid, which is the only way to test whether the
// ADDRESSING form is what decides being served, holding the anchor (chat, oldest id/ts) constant.
// build_anchors puts the wire `@s.whatsapp.net` form in `chat` and the local id in `chat_id`; for a
// LID-migrated 1:1 chat those differ, and measured over the 6 chats one run happened to ask in both
// forms, PN-addressed returned 3 messages in total while LID-addressed returned 1,157.
const AS = arg('--as', null);
// --quiet-peer: send the phone NOTHING but the history request. On every message it cannot decrypt,
// Baileys sends the phone a retry receipt and, on the first retry, a placeholder-resend request -- a
// peer-data-operation message on the same channel as our history request. Measured during a 15-minute
// listen: one every ~5 s, 21 in the first 90 s, with 812 decrypt failures behind them. WhatsApp Web
// decrypts everything and sends none. This switch (maxMsgRetryCount: 0) tests whether those requests
// are what delays the phone's answer to ours.
const QUIET_PEER = argv.includes('--quiet-peer');
// --webstanza: send the request EXACTLY as WhatsApp Web builds it, instead of through Baileys'
// relayMessage. From WA Web's own WAWebSendNonMessageDataRequest + WAWebSendAppStateSyncMsgJob +
// WAWebSendMsgCreateDeviceStanza (bundle fetched 2026-10-09, the build in the cold capture):
//   - recipient: getMyPrimaryForOutgoingPeerMessage() = own LID user, device 0, ONE device
//   - payload: the protocolMessage itself. WA Web wraps own-account messages in deviceSentMessage
//     EXCEPT this type: `isMeAccount(to) && type !== AppStateSync ? wrapDeviceSentMessage : as-is`.
//     Baileys always wraps (meMsg = {deviceSentMessage:{destinationJid, message}}), and on the peer
//     path sends only participants[0] -- which is that wrapped copy. So the phone has been receiving
//     our request disguised as "a message this companion sent", not as a request.
//   - attrs: category="peer", push_priority="high_force", privacy_sensitive="1" (OnDemand; Baileys
//     never sends it), type="text"
//   - <enc v="2" type="msg|pkmsg">, plus <device-identity> when pkmsg
const WEB_STANZA = argv.includes('--webstanza');
// --passive: log in with ClientPayload.passive = true and NEVER send <iq xmlns="passive"><active/>.
// Baileys hard-codes passive:false and sends `active` the moment <success> arrives; WhatsApp Web
// logs in passive when it has pending passive tasks (WAWebRegisterPassiveTasksForConnect) and goes
// active afterwards. This is an experiment: what does the server send a companion that stays passive?
const PASSIVE = argv.includes('--passive');
// --cookies FILE: send this Cookie header on the WebSocket upgrade, as the browser does
// (wa_ul, wa_web_lang_pref, wa_csrf, wa_lang_pref, wa_web_access_token). Baileys sends none.
const COOKIE_FILE = arg('--cookies', null);
const COOKIE = COOKIE_FILE ? fs.readFileSync(COOKIE_FILE, 'utf8').trim() : null;

const red = s => String(s == null ? '' : s).replace(/\d{5,}/g, m => m.slice(0, 4) + '*'.repeat(m.length - 4));
const bb = b => Buffer.from(b, 'base64');
const quiet = { level: 'silent', child: () => quiet, trace(){}, debug(){}, info(){}, warn(){}, error(){}, fatal(){} };

const creds = B.initAuthCreds();
creds.noiseKey = { private: bb(inp.noise_priv), public: bb(inp.noise_pub) };
creds.signedIdentityKey = { private: bb(S.signedIdentityKey.private), public: bb(S.signedIdentityKey.public) };
creds.registrationId = S.registrationId;
creds.signedPreKey = { keyId: S.signedPreKey.keyId, keyPair: { private: bb(S.signedPreKey.private), public: bb(S.signedPreKey.public) }, signature: S.signedPreKey.signature ? bb(S.signedPreKey.signature) : Buffer.alloc(0) };
creds.me = { id: inp.me_id, lid: inp.lid };
creds.account = { details: bb(inp.account.details), accountSignatureKey: bb(inp.account.accountSignatureKey), accountSignature: bb(inp.account.accountSignature), deviceSignature: bb(inp.account.deviceSignature) };
creds.registered = true; creds.platform = 'web';

const signalStore = require('./signal_store');
const askPath = findFile('appstate_keys.json');
const rt = signalStore.open({ signalState: S, creds,
  appStateKeys: askPath ? JSON.parse(fs.readFileSync(askPath, 'utf8')) : {},
  statePath: signalStore.defaultStatePath(path.dirname(need('signal_state.json'))), bufferJSON: B.BufferJSON });

let version = [2, 3000, 1023223821];
if (Array.isArray(inp.wa_version) && inp.wa_version.length === 3) version = inp.wa_version.map(Number);

// pick exactly one chat
const anchors = (A.anchors || []);
let a = WANT ? anchors.find(x => String(x.chat) === WANT || String(x.chat_id) === WANT)
             : (anchors.find(x => !String(x.chat).endsWith('@g.us')) || anchors[0]);
if (!a) { console.error('[one] no usable anchor' + (WANT ? ' matching ' + WANT : '')); process.exit(4); }

// --- observation state -------------------------------------------------------------------------
let t0 = null;                       // when the request went out
const seen = [];                     // every inbound stanza after the request
let ourStanzaId = null;
let ack = null, errored = null, notified = null, receipt = null, histAck = null;
const rel = () => t0 ? ((Date.now() - t0) / 1000).toFixed(2) + 's' : '  pre ';

const SUMMARY_ATTRS = ['id', 'from', 'to', 'type', 'class', 'category', 'error', 'code', 'text', 'offline', 't'];
const brief = node => {
  const at = node.attrs || {};
  const parts = SUMMARY_ATTRS.filter(k => at[k] !== undefined).map(k => `${k}=${red(at[k])}`);
  const kids = Array.isArray(node.content) ? node.content.filter(c => c && c.tag).map(c => c.tag) : [];
  return `<${node.tag} ${parts.join(' ')}>` + (kids.length ? ` [${kids.join(',')}]` : '');
};

(async () => {
  console.error(`[one] device :${inp.device}  announcing ${version.join('.')}`);
  if (AS) console.error(`[one] ADDRESSING IT AS: ${red(AS)}  (anchor's own chat is ${red(a.chat)})`);
  console.error(`[one] asking ONE chat: ${red(a.chat)}`
    + (a.chat_id && a.chat_id !== a.chat ? `  (local id ${red(a.chat_id)})` : '')
    + `  oldest_ts=${a.oldest_ts}`);

  try { require('./proto_patch').patch(B); } catch (e) {}

  if (PASSIVE && !B.proto.ClientPayload.__wawfPassive) {
    const enc = B.proto.ClientPayload.encode;
    B.proto.ClientPayload.encode = function (m, w) { if (m) m.passive = true; return enc.call(this, m, w); };
    B.proto.ClientPayload.__wawfPassive = true;
  }
  const sock = makeWASocket({ version, auth: { creds, keys: rt.keys }, logger: quiet,
    ...(COOKIE ? { options: { headers: { Cookie: COOKIE } } } : {}),
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: h => { try { return !!h && h.syncType === B.proto.Message.HistorySyncNotification.HistorySyncType.ON_DEMAND; } catch (e) { return false; } },
    getMessage: async () => undefined, browser: ['Forensic', 'Recovery', '1.0'],
    ...(QUIET_PEER ? { maxMsgRetryCount: 0 } : {}) });
  if (QUIET_PEER) console.error('[one] --quiet-peer: no retry receipts, no placeholder resends -- only the history request goes to the phone');
  if (COOKIE) console.error(`[one] --cookies: sending the browser's Cookie header (${COOKIE.split(';').length} cookies, values not shown)`);
  if (PASSIVE) {
    // Reproduce Baileys' CB:success handler minus `sendPassiveIq('active')`.
    sock.ws.removeAllListeners('CB:success');
    sock.ws.on('CB:success', async (node) => {
      try { await sock.uploadPreKeysToServerIfRequired(); } catch (e) {}
      sock.ev.emit('creds.update', { me: { ...sock.authState.creds.me, lid: node.attrs.lid } });
      sock.ev.emit('connection.update', { connection: 'open' });
    });
    console.error('[one] --passive: logged in passive=true; the passive->active IQ is suppressed');
  }
  // The offline-delivery-finished marker, caught from the moment the socket exists, and the batch
  // pump that gets us there. The server delivers the offline queue only in batches the client asks
  // for; Baileys asks once (100). Without draining, the phone's answer is queued behind the backlog
  // and this diagnostic reproduced exactly the failure it was meant to explain. --no-drain keeps the
  // old behaviour for comparison.
  const NO_DRAIN = argv.includes('--no-drain');
  const off = { done: false, preview: null, batches: 0, lastIn: Date.now() };
  sock.ws.on('CB:ib,,offline', (node) => {
    const c = (node.content || []).find(x => x && x.tag === 'offline');
    off.done = true;
    console.error(`  [offline] server says offline delivery finished: ${c && c.attrs ? c.attrs.count : '?'} item(s)`
      + (t0 ? ` (${((Date.now() - t0) / 1000).toFixed(2)}s after our request)` : ' (before our request)'));
  });
  sock.ws.on('CB:ib,,offline_preview', (node) => {
    const c = (node.content || []).find(x => x && x.tag === 'offline_preview');
    off.preview = c && c.attrs ? { ...c.attrs } : {}; off.lastIn = Date.now();
  });
  for (const tag of ['CB:message', 'CB:notification', 'CB:receipt', 'CB:call']) sock.ws.on(tag, () => { off.lastIn = Date.now(); });
  const pump = setInterval(() => {
    if (NO_DRAIN || off.done || off.preview == null || off.batches >= 2000 || Date.now() - off.lastIn < 1000) return;
    off.batches++; off.lastIn = Date.now();
    Promise.resolve(sock.sendNode({ tag: 'ib', attrs: {}, content: [{ tag: 'offline_batch', attrs: { count: '100' } }] })).catch(() => {});
  }, 500);
  if (pump.unref) pump.unref();

  // EVERY inbound stanza, before Baileys' tag dispatch.
  sock.ws.on('frame', node => {
    if (!node || node instanceof Uint8Array || !node.tag) return;
    const at = node.attrs || {};
    const line = `  ${rel().padStart(7)}  IN   ${brief(node)}`;
    if (t0) seen.push(line);
    // classify the things that decide the verdict
    if (node.tag === 'ack' && ourStanzaId && String(at.id) === ourStanzaId) { ack = ack || { at: rel(), node: brief(node) }; }
    // `type=hist_sync` on a receipt-class ack is WhatsApp acknowledging the history delivery itself,
    // a stronger signal than a plain message ack: it means a chunk was actually produced for us.
    if (node.tag === 'ack' && at.type === 'hist_sync') { histAck = histAck || { at: rel(), node: brief(node) }; }
    if (node.tag === 'receipt' && ourStanzaId && at.id === ourStanzaId) { receipt = receipt || { at: rel(), node: brief(node) }; }
    if (node.tag === 'stream:error' || at.type === 'error' || node.tag === 'nack'
        || (node.tag === 'failure')) { errored = errored || { at: rel(), node: brief(node) }; }
    if (t0) console.error(line);
  });

  let finished = false;
  const done = c => { if (finished) return; finished = true; try { sock.end(); } catch (e) {} process.exit(c); };

  sock.ev.on('messages.upsert', u => { for (const m of (u.messages || [])) {
    let x = m.message;
    for (let i = 0; i < 5 && x; i++) {
      if (x.protocolMessage && x.protocolMessage.historySyncNotification) {
        notified = notified || { at: rel(), chunk: x.protocolMessage.historySyncNotification };
        console.error(`  ${rel().padStart(7)}  ***  historySyncNotification received`);
        return;
      }
      x = x.deviceSentMessage?.message || x.ephemeralMessage?.message || x.viewOnceMessage?.message;
    }
  } });
  // Recovered messages are evidence even on a diagnostic run. The first time this probe succeeded it
  // pulled 50 real messages and discarded them -- the same mistake the late-chunk path used to make.
  const recovered = [];
  sock.ev.on('messaging-history.set', d => {
    if (d && (d.messages || []).length) {
      notified = notified || { at: rel(), count: d.messages.length };
      for (const w of d.messages) {
        // The WHOLE key, not a chosen subset: which field carries the group sender is exactly the
        // kind of question this tool exists to answer, and the proto has `participant` while this
        // Baileys adds `participantPn` and `participantLid` -- so a diagnostic that pre-selects one
        // of them cannot tell you which the account actually uses.
        if (w && w.key && w.key.id) recovered.push({ key: w.key, pushName: w.pushName || null,
                                                     chat: w.key.remoteJid, id: w.key.id,
          fromMe: !!w.key.fromMe, ts: Number(w.messageTimestamp) || 0 });
      }
      console.error(`  ${rel().padStart(7)}  ***  messaging-history.set with ${d.messages.length} message(s)`);
    }
  });

  sock.ev.on('connection.update', async u => {
    if (finished) return;
    if (u.qr) { console.error('[one] CONNECT FAIL — server asked for a QR'); return done(2); }
    if (u.connection === 'close') {
      const e = u.lastDisconnect && u.lastDisconnect.error;
      console.error('[one] closed', e && e.output && e.output.statusCode, e && e.message);
      return done(3);
    }
    if (u.connection !== 'open') return;
    console.error('[one] CONNECT ok');

    // registration first: a revoked device explains silence by itself, and costs one round trip
    try {
      const q = new B.USyncQuery().withDeviceProtocol();
      q.withUser(new B.USyncUser().withId(B.jidNormalizedUser(inp.me_id)));
      const res = await sock.executeUSyncQuery(q);
      const slots = [];
      for (const u2 of ((res && res.list) || [])) {
        const dl = (u2 && u2.devices && (u2.devices.deviceList || u2.devices)) || [];
        if (Array.isArray(dl)) for (const d of dl) slots.push(d.id);
      }
      const ours = Number(String(inp.me_id).split('@')[0].split(':')[1] || 0);
      console.error(`[one] REGISTERED ${slots.includes(ours) ? 'ok' : 'FAIL'} — slots [${slots.join(', ')}], ours :${ours}`);
      if (slots.length && !slots.includes(ours)) {
        console.error('\n[one] VERDICT: REVOKED. Not a throttle — this device is no longer on the account.');
        return done(7);
      }
    } catch (e) { console.error('[one] REGISTERED unknown —', e && e.message); }

    // WhatsApp Web sends no peer request before offline delivery has ended; neither do we.
    if (!NO_DRAIN) {
      const w0 = Date.now(), LIMIT = Number(process.env.SETTLE_MAX_MS || 300000);
      while (!off.done && Date.now() - w0 < LIMIT) await new Promise(r => setTimeout(r, 250));
      clearInterval(pump);
      console.error(off.done
        ? `[one] offline queue drained (preview ${JSON.stringify(off.preview)}, ${off.batches} extra batch request(s)) in ${((Date.now() - w0) / 1000).toFixed(1)}s`
        : `[one] offline queue NOT drained within ${LIMIT / 1000}s -- an unanswered request below is then expected`);
    }
    // capture our own outbound stanza id so acks can be matched to it
    const origSendNode = sock.sendNode;
    sock.sendNode = function (node) {
      const at = (node && node.attrs) || {};
      if (node && node.tag === 'message' && at.category === 'peer') {
        ourStanzaId = at.id;
        console.error(`  ${'  out '.padStart(7)}  OUT  ${brief(node)}`);
      }
      return origSendNode.apply(this, arguments);
    };

    const selfLid = creds.me && creds.me.lid ? B.jidNormalizedUser(creds.me.lid) : null;
    const tsMs = a.oldest_ts > 1e12 ? a.oldest_ts : a.oldest_ts * 1000;
    const req = { chatJid: AS || a.chat, oldestMsgId: a.oldest_id, oldestMsgFromMe: !!a.oldest_fromMe,
      onDemandMsgCount: 50, oldestMsgTimestampMs: tsMs, supportInlineResponse: true };
    const pdo = { historySyncOnDemandRequest: req,
      peerDataOperationRequestType: B.proto.Message.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND };

    t0 = Date.now();
    let reqId = null;
    try {
      if (WEB_STANZA) {
        if (!selfLid) throw new Error('--webstanza needs our own LID');
        const to = selfLid;                                        // device 0 = the primary
        const msg = B.proto.Message.fromObject({ protocolMessage: { peerDataOperationRequestMessage: pdo,
          type: B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE } });
        await sock.assertSessions([to], false);
        const enc = await sock.signalRepository.encryptMessage({ jid: to, data: B.encodeWAMessage(msg) });
        const content = [{ tag: 'enc', attrs: { v: '2', type: enc.type }, content: enc.ciphertext }];
        if (enc.type === 'pkmsg') content.push({ tag: 'device-identity', attrs: {},
          content: B.encodeSignedDeviceIdentity(sock.authState.creds.account, true) });
        reqId = B.generateMessageIDV2(sock.user && sock.user.id);
        const stanza = { tag: 'message', attrs: { to, id: reqId, type: 'text', category: 'peer',
          push_priority: 'high_force', privacy_sensitive: '1' }, content };
        console.error(`[one] --webstanza: sending as WhatsApp Web does -- unwrapped protocolMessage, `
          + `enc=${enc.type}, attrs ${JSON.stringify(stanza.attrs).replace(/\d{6,}/g, m => m.slice(0, 4) + '…')}`);
        await origSendNode.call(sock, stanza);
      } else
      reqId = selfLid
        ? await sock.relayMessage(selfLid,
            { protocolMessage: { peerDataOperationRequestMessage: pdo,
              type: B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE } },
            { additionalAttributes: { category: 'peer', push_priority: 'high_force' } })
        : await sock.sendPeerDataOperationMessage(pdo);
      // Match acks against the id relayMessage actually used. The sendNode hook above does not fire
      // for this path -- relayMessage calls an internal sendNode closure, not the exported one -- so
      // relying on it meant `ack for our stanza` always read NO even when the ack plainly arrived.
      if (reqId) ourStanzaId = String(reqId);
      console.error(`[one] request sent via ${WEB_STANZA ? 'the WA Web stanza' : selfLid ? 'LID' : 'PN'} routing, msg id ${reqId}`);
      console.error(`[one] listening ${WAIT / 1000}s — every inbound stanza below\n`);
    } catch (e) {
      console.error('\n[one] VERDICT: the request could not even be SENT:', e && e.message);
      console.error('[one] That is not a throttle. The transport or the envelope is the problem.');
      return done(5);
    }

    setTimeout(() => {
      console.error('\n' + '='.repeat(78));
      console.error(`observed in ${WAIT / 1000}s: ${seen.length} inbound stanza(s)`);
      console.error(`  ack for our stanza      : ${ack ? 'YES at ' + ack.at + '  ' + ack.node : 'NO'}`);
      console.error(`  receipt for our stanza  : ${receipt ? 'YES at ' + receipt.at : 'no'}`);
      console.error(`  hist_sync ack           : ${histAck ? 'YES at ' + histAck.at : 'no'}`);
      console.error(`  explicit error / nack   : ${errored ? 'YES at ' + errored.at + '  ' + errored.node : 'no'}`);
      console.error(`  history notification    : ${notified ? 'YES at ' + notified.at : 'NO'}`);
      console.error('='.repeat(78));

      if (notified) {
        if (recovered.length) {
          const out = 'onehistory_recovered.json';
          try {
            const span = recovered.map(m => m.ts).filter(Boolean).sort((x, y) => x - y);
            fs.writeFileSync(out, JSON.stringify({ chat: a.chat, chat_id: a.chat_id,
              asked_oldest_ts: a.oldest_ts, count: recovered.length,
              oldest: span[0], newest: span[span.length - 1], messages: recovered }, null, 1));
            console.error(`
[one] ${recovered.length} message(s) recovered and SAVED -> ${out}`);
            if (span.length) console.error(`[one] spanning ${new Date(span[0]*1000).toISOString().slice(0,10)}`
              + ` .. ${new Date(span[span.length-1]*1000).toISOString().slice(0,10)}`
              + `, against an anchor at ${new Date(a.oldest_ts*1000).toISOString().slice(0,10)}`);
          } catch (e) { console.error('[one] could not save the recovered messages:', e && e.message); }
        }
        console.error('\nVERDICT: SERVED. History is working right now — we are NOT in a cooldown.');
        return done(0);
      }
      if (errored) {
        console.error('\nVERDICT: REFUSED, explicitly. The stanza above carries the reason; this is a');
        console.error('refusal rather than a silence, so read it rather than retrying.');
        return done(6);
      }
      if (!ack) {
        console.error('\nVERDICT: NOT ACCEPTED. WhatsApp never acknowledged the stanza, so it did not take');
        console.error('the request at all. This is NOT a cooldown -- a throttled request still gets acked.');
        console.error('Look at the envelope and the transport, not at pacing.');
        return done(8);
      }
      console.error('\nVERDICT: ACCEPTED BUT UNANSWERED. WhatsApp acked our request'
        + (ack ? ' at ' + ack.at : '') + ', so it');
      console.error('reached the server and the stanza was well formed. Nothing came back from the phone.');
      console.error((!NO_DRAIN && !off.done)
        ? 'The offline queue was not drained, so the answer is most likely queued behind that backlog.'
        : 'The offline queue WAS drained, so this is not the backlog stall. Not a broken request, a dead');
      console.error('registration, or a disabled feature either -- those are ruled out above. Listen');
      console.error('longer (--wait), or check the phone is online with WhatsApp open; then re-run.');
      console.error('(Earlier versions called this a throttle and prescribed pacing; that was wrong.)');
      done(1);
    }, WAIT);
  });
})().catch(e => { console.error('[one] FATAL', e); process.exit(9); });
