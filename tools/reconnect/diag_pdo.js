// diag_pdo.js -- WHY does the phone answer WhatsApp Web's "load older messages" but not ours?
//
// The phone demonstrably serves on-demand history right now (clicking the button in the browser
// works), and it sends us live `receipt type="peer_msg"` acks for our requests, so it is online and
// it IS receiving them. It just never answers. That means the difference is in the REQUEST, not in
// connectivity, and not in the decryption work done earlier.
//
// One concrete difference is visible in the protocol definition: HistorySyncOnDemandRequest has an
// `accountLid` field that Baileys' fetchMessageHistory() never sets. Every chat in this profile is
// LID-addressed, so a phone that resolves the request by account LID would have nothing to match.
//
// This sends the SAME request for the SAME chat several ways, a couple of seconds apart, and prints
// which request id (if any) comes back. Variants:
//   A  baseline        -- exactly what fetchMessageHistory() sends today
//   B  +accountLid     -- same, plus our own account LID
//   C  +accountLid, chatJid rewritten to the phone-number form (if we can resolve one)
// Run from tools/reconnect after a `wawf --history` has produced creds_in/signal_state/anchors.
//   node diag_pdo.js            [CHATS=3]  [WAIT=150]
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const inp = JSON.parse(fs.readFileSync(findFile('creds_in.json')));
const S   = JSON.parse(fs.readFileSync(findFile('signal_state.json')));
const A   = JSON.parse(fs.readFileSync(findFile('anchors.json')));
const CHATS = Number(process.env.CHATS || 3);
const WAIT  = Number(process.env.WAIT || 150) * 1000;

const redact = s => String(s).replace(/\d{5,}/g, m => m.slice(0, 4) + '*'.repeat(m.length - 4));
const mk = lvl => ({ level: lvl, child: () => mk(lvl),
  trace: () => {}, debug: (...a) => log('DEBUG', a), info: (...a) => log('INFO', a),
  warn: (...a) => log('WARN', a), error: (...a) => log('ERROR', a), fatal: (...a) => log('FATAL', a) });
const KEEP = /pdo|peer|history|sync|notification|fail|error|retry|decrypt/i;
function log(lvl, args) {
  const rep = (k, v) => (v instanceof Error ? { name: v.name, message: v.message } : v);
  let s = args.map(a => { try { return typeof a === 'string' ? a : JSON.stringify(a, rep); } catch (e) { return String(a); } }).join(' ');
  if (s.length > 600) s = s.slice(0, 600) + '...';
  if (lvl === 'ERROR' || lvl === 'WARN' || KEEP.test(s)) console.error(`[${lvl}] ${redact(s)}`);
}

const bb = b => Buffer.from(b, 'base64');
const creds = B.initAuthCreds();
creds.noiseKey = { private: bb(inp.noise_priv), public: bb(inp.noise_pub) };
creds.signedIdentityKey = { private: bb(S.signedIdentityKey.private), public: bb(S.signedIdentityKey.public) };
creds.registrationId = S.registrationId;
creds.signedPreKey = { keyId: S.signedPreKey.keyId, keyPair: { private: bb(S.signedPreKey.private), public: bb(S.signedPreKey.public) }, signature: S.signedPreKey.signature ? bb(S.signedPreKey.signature) : Buffer.alloc(0) };
creds.me = { id: inp.me_id, lid: inp.lid };
creds.account = { details: bb(inp.account.details), accountSignatureKey: bb(inp.account.accountSignatureKey), accountSignature: bb(inp.account.accountSignature), deviceSignature: bb(inp.account.deviceSignature) };
creds.registered = true; creds.platform = 'web';

const signalStore = require('./signal_store');
const rt = signalStore.open({ signalState: S, creds,
  statePath: signalStore.defaultStatePath(path.dirname(findFile('signal_state.json'))), bufferJSON: B.BufferJSON });

// request id -> {variant, chat} ; filled as we send, ticked off as replies arrive
const sent = new Map();
const answered = new Set();

(async () => {
  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  const accountLid = inp.lid ? B.jidNormalizedUser(inp.lid) : undefined;
  console.error(`[pdo] WA ${version.join('.')} | accountLid = ${redact(accountLid)} | sessions ${rt.stats.sessions}, carried ${rt.stats.carried}`);

  // A PDO response is one-shot: across every run tonight the phone has never re-encrypted one on
  // retry (0 of ~100). But Baileys only sends the delivery receipt when a message DECRYPTS -- on
  // failure it sends a retry request instead -- so each unreadable peer reply stays in the offline
  // queue forever, is replayed on every connect, and earns another retry receipt. The phone ends up
  // buried in retries and stops answering the requests we actually care about (p2: 105 queued
  // replays, zero live replies). So: never retry a peer message, ACK it and let the queue drain.
  const peerIds = new Set();
  const retryCounters = new Map();
  const sock = makeWASocket({
    version, auth: { creds, keys: rt.keys }, logger: mk('debug'),
    msgRetryCounterCache: {
      get: k => {
        if (peerIds.has(String(k).split(':')[0])) return 1e6;   // >= maxMsgRetryCount: skip the retry
        const v = retryCounters.get(k); return v === undefined ? 1 : v;
      },
      set: (k, v) => retryCounters.set(k, v), del: k => retryCounters.delete(k) },
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: h => { try { return !!h && h.syncType === B.proto.Message.HistorySyncNotification.HistorySyncType.ON_DEMAND; } catch (e) { return false; } },
    getMessage: async () => undefined, browser: ['Forensic', 'Recovery', '1.0'],
  });
  sock.ev.on('creds.update', () => rt.save());

  // Learn which incoming stanzas are peer messages (before Baileys' async decrypt gets to the retry
  // decision), and record live-vs-queued so a real reply can be told apart from a queue replay.
  let live = 0, queued = 0, acked = 0;
  sock.ws.on('CB:message', node => {
    const at = node.attrs || {};
    if (at.category === 'peer') {
      peerIds.add(at.id);
      // A connect-time burst frequently carries NO `offline` attribute, so absence does not mean
      // live -- treating it as live made a pure backlog look like the phone answering us. What
      // actually distinguishes an answer is arriving AFTER we asked something.
      const after = sent.size > 0;
      if (after) live++; else queued++;
      console.error(`[pdo] <- peer stanza ${after ? 'AFTER-REQUEST (a real candidate reply)' : 'pre-request (backlog)'}`
        + ` offline=${at.offline || '-'} id=${String(at.id).slice(0, 4)}...`);
    }
  });

  // Anything that comes back at all. A PDO response carries the id of the request it answers, so a
  // reply can be attributed to the exact variant that earned it.
  const note = (src, sid, extra) => {
    const hit = sid && sent.get(sid);
    if (hit) { answered.add(sid); console.error(`[pdo] *** ANSWERED *** variant ${hit.variant} (${redact(hit.chat)}) via ${src} ${extra || ''}`); }
    else console.error(`[pdo] reply with unknown/absent session id ${redact(sid)} via ${src} ${extra || ''}`);
  };
  sock.ev.on('messaging-history.set', d => note('messaging-history.set', d && d.peerDataRequestSessionId,
    `messages=${(d && d.messages || []).length}`));
  // Is the event pipeline even delivering? Baileys buffers events during the initial sync and a
  // buffer that never flushes makes every handler below silent -- which looks identical to "no
  // reply arrived". Log the raw arrival before doing anything with it.
  let upserts = 0;
  sock.ev.on('messages.upsert', u => { upserts += (u.messages || []).length;
    console.error(`[pdo] messages.upsert type=${u.type} n=${(u.messages||[]).length} stubs=${(u.messages||[]).filter(x=>x.messageStubType===B.proto.WebMessageInfo.StubType.CIPHERTEXT).length}`);
    for (const m of (u.messages || [])) {
    let x = m.message;
    for (let i = 0; i < 4 && x; i++) {
      const pm = x.protocolMessage;
      if (pm && pm.historySyncNotification) return note('historySyncNotification', pm.peerDataRequestSessionId,
        `type=${pm.historySyncNotification.syncType} progress=${pm.historySyncNotification.progress}`);
      if (pm && pm.peerDataOperationRequestResponseMessage) {
        const r = pm.peerDataOperationRequestResponseMessage;
        return note('peerDataOperationRequestResponseMessage', r.stanzaId,
          `type=${r.peerDataOperationRequestType} results=${(r.peerDataOperationResult || []).length}`);
      }
      x = x.deviceSentMessage?.message || x.ephemeralMessage?.message || x.viewOnceMessage?.message;
    }
    if (m.messageStubType === B.proto.WebMessageInfo.StubType.CIPHERTEXT && m.key) {
      if (peerIds.has(m.key.id)) {
        // Ack it so the server stops replaying it. The content is a history page we can ask for
        // again; leaving it queued costs us every future run.
        acked++;
        Promise.resolve(sock.sendReceipt(m.key.remoteJid, undefined, [m.key.id], 'peer_msg'))
          .then(() => console.error(`[pdo] acked undecryptable peer reply ${String(m.key.id).slice(0, 4)}... (drains the queue)`))
          .catch(e => console.error('[pdo] ack FAILED:', e && e.message));
      } else {
        Promise.resolve(sock.requestPlaceholderResend(m.key)).catch(() => {});
      }
    }
  } });

  const T = B.proto.Message.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND;
  const PDO_TYPE = B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE;
  const PEER_ATTRS = { additionalAttributes: { category: 'peer', push_priority: 'high_force' } };

  // WHICH self-jid we address the request to decides WHICH Signal session encrypts it, because
  // relayMessage's peer path derives the recipient from the target jid's server:
  //   jidEncode(isMe && isLid ? creds.me.lid : user, isLid ? 'lid' : 's.whatsapp.net', device)
  // sendPeerDataOperationMessage() always passes the PHONE-NUMBER jid, so the request goes out on
  // the <pn>.0 session -- while the phone's answers arrive on <lid>.0. Two different sessions: we
  // renegotiated the one we send on (hence the phone can read us and does answer) but never the one
  // it answers on, so its replies land on a ratchet we only have a stale snapshot of.
  const send = {
    pn:  m => sock.sendPeerDataOperationMessage(m),                                  // today's behaviour
    lid: m => sock.relayMessage(B.jidNormalizedUser(inp.lid),
      { protocolMessage: { peerDataOperationRequestMessage: m, type: PDO_TYPE } }, PEER_ATTRS),
  };

  const ask = async (variant, route, a, mutate) => {
    const req = { chatJid: a.chat, oldestMsgId: a.oldest_id, oldestMsgFromMe: !!a.oldest_fromMe,
      oldestMsgTimestampMs: a.oldest_ts > 1e12 ? a.oldest_ts : a.oldest_ts * 1000, onDemandMsgCount: 50 };
    mutate(req);
    try {
      const id = await send[route]({ historySyncOnDemandRequest: req, peerDataOperationRequestType: T });
      sent.set(id, { variant, chat: a.chat });
      console.error(`[pdo] sent ${variant} via ${route} -> ${redact(a.chat)} req=${id} fields=${JSON.stringify(Object.keys(req))}`);
    } catch (e) { console.error(`[pdo] send ${variant} via ${route} FAILED:`, e && e.message); }
    await new Promise(r => setTimeout(r, 2500));
  };

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[pdo] QR requested => creds rejected'); process.exit(2); }
    if (u.connection === 'close') { const e = u.lastDisconnect && u.lastDisconnect.error; console.error('[pdo] CLOSED', e && e.output && e.output.statusCode, e && e.message); process.exit(4); }
    if (u.connection !== 'open') return;
    console.error('[pdo] OPEN, letting the offline queue drain for 10s ...');
    // Baileys buffers every event from connect and flushes only on the server's
    // <ib><offline/> "queue fully handled" marker. Messages we cannot decrypt are never acked,
    // so that marker never arrives, the buffer stays shut, and NOTHING reaches any handler --
    // a decrypted history page would still be recorded as "no response". Drive the flush
    // ourselves, repeatedly, since Baileys re-buffers around its own node processing.
    const pump = setInterval(() => { if (sock.ev.isBuffering()) { const f = sock.ev.flush(); if (f) console.error('[pdo] forced event-buffer flush'); } }, 1500);
    if (pump.unref) pump.unref();
    await new Promise(r => setTimeout(r, 10000));
    try { await sock.assertSessions([...new Set([inp.lid, inp.me_id].filter(Boolean).map(B.jidNormalizedUser))], true); } catch (e) {}

    // one-to-one chats only: the browser click that is known to work was a 1:1 conversation, and a
    // group may well be served by a different (or no) path
    const targets = A.anchors.filter(a => !String(a.chat).endsWith('@g.us')).slice(0, CHATS);
    console.error(`[pdo] testing ${targets.length} one-to-one chat(s), 2 variants each`);
    for (const a of targets) {
      await ask('A-pn-baseline',   'pn',  a, () => {});
      await ask('B-pn-accountLid', 'pn',  a, r => { if (accountLid) r.accountLid = accountLid; });
      await ask('C-LID-route',     'lid', a, () => {});
      await ask('D-LID+accountLid','lid', a, r => { if (accountLid) r.accountLid = accountLid; });
    }
    // and one group, to see whether chat type is what decides it
    const g = A.anchors.find(a => String(a.chat).endsWith('@g.us'));
    if (g) await ask('E-group-LID', 'lid', g, r => { if (accountLid) r.accountLid = accountLid; });

    setTimeout(() => {
      console.error('[pdo] ==== RESULT ====');
      for (const [id, v] of sent) console.error(`   ${answered.has(id) ? 'ANSWERED' : 'silent  '}  ${v.variant}  ${redact(v.chat)}`);
      console.error(`[pdo] peer stanzas: ${live} after our requests, ${queued} before them (backlog) | acked ${acked} | upserts delivered ${upserts} | ev.isBuffering=${sock.ev.isBuffering && sock.ev.isBuffering()}`);
      process.exit(0);
    }, WAIT);
  });
})().catch(e => { console.error('[pdo] FATAL', e); process.exit(9); });
