// diag_fullhistory.js -- try the BULK history path instead of the per-chat one.
//
// Everything so far used PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND (3): ask per chat, for
// messages older than a given anchor. That path has gone silent on this account while the profile
// is cold, across every variant tried.
//
// Reading WhatsApp Web's own cached protobuf schema out of the browser's Code Cache turned up two
// request types Baileys' generated proto does not even define -- HistorySyncChunkRetryRequest and
// FullHistorySyncOnDemandConfig{historyFromTimestamp, historyDurationDays} -- plus a field on the
// per-chat request we never send, `supportInlineResponse`. So our protobuf is behind the real
// client's, which is reason enough to stop assuming the per-chat path is the only one.
//
// Baileys DOES have the enum value and the message for the bulk request:
//     FULL_HISTORY_SYNC_ON_DEMAND = 6
//     FullHistorySyncOnDemandRequest { requestMetadata{requestId}, historySyncConfig }
//     HistorySyncConfig { fullSyncDaysLimit, fullSyncSizeMbLimit, storageQuotaMb,
//                         inlineInitialPayloadInE2EeMsg, recentSyncDaysLimit, ... }
// so this asks for the whole history at once and reports whatever comes back. Unlike the per-chat
// request it accepts EVERY history-sync type, because a full sync arrives as bootstrap/full chunks
// rather than ON_DEMAND ones.
//
//   node diag_fullhistory.js      [DAYS=3650] [WAIT=180]
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const { patched } = require('./proto_patch').patch(B);
console.error('[fh] proto patched:', patched.join(', ') || '(nothing)');
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const inp = JSON.parse(fs.readFileSync(findFile('creds_in.json')));
const S   = JSON.parse(fs.readFileSync(findFile('signal_state.json')));
const DAYS = Number(process.env.DAYS || 3650);
const WAIT = Number(process.env.WAIT || 180) * 1000;

const redact = s => String(s).replace(/\d{5,}/g, m => m.slice(0, 4) + '*'.repeat(m.length - 4));
const KEEP = /pdo|peer|history|sync|notification|fail|error|retry|decrypt|chunk/i;
const mk = lvl => ({ level: lvl, child: () => mk(lvl), trace: () => {}, debug: (...a) => log('DEBUG', a),
  info: (...a) => log('INFO', a), warn: (...a) => log('WARN', a), error: (...a) => log('ERROR', a), fatal: (...a) => log('FATAL', a) });
function log(l, args) {
  const rep = (k, v) => (v instanceof Error ? { name: v.name, message: v.message } : v);
  let s = args.map(a => { try { return typeof a === 'string' ? a : JSON.stringify(a, rep); } catch (e) { return String(a); } }).join(' ');
  if (s.length > 700) s = s.slice(0, 700) + '...';
  if (l === 'ERROR' || l === 'WARN' || KEEP.test(s)) console.error(`[${l}] ${redact(s)}`);
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
const askPath = findFile('appstate_keys.json');
const appStateKeys = askPath ? JSON.parse(fs.readFileSync(askPath, 'utf8')) : {};
const rt = signalStore.open({ signalState: S, creds, appStateKeys,
  statePath: signalStore.defaultStatePath(path.dirname(findFile('signal_state.json'))), bufferJSON: B.BufferJSON });

let notifs = 0, setEvents = 0, msgs = 0;

(async () => {
  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  console.error(`[fh] WA ${version.join('.')} | sessions ${rt.stats.sessions}, carried ${rt.stats.carried}, appStateKeys ${rt.stats.appStateKeys}`);

  const peerIds = new Set();
  const retryCounters = new Map();
  const sock = makeWASocket({
    version, auth: { creds, keys: rt.keys }, logger: mk('debug'),
    msgRetryCounterCache: { get: k => { if (peerIds.has(String(k).split(':')[0])) return 1e6;
        const v = retryCounters.get(k); return v === undefined ? 1 : v; },
      set: (k, v) => retryCounters.set(k, v), del: k => retryCounters.delete(k) },
    printQRInTerminal: false, markOnlineOnConnect: true,
    syncFullHistory: true,                       // we WANT the bulk payload
    shouldSyncHistoryMessage: () => true,        // accept every history-sync type, not just ON_DEMAND
    getMessage: async () => undefined, browser: ['Forensic', 'Recovery', '1.0'],
  });
  sock.ev.on('creds.update', () => rt.save());
  sock.ws.on('CB:message', node => { const at = node.attrs || {}; if (at.category === 'peer') peerIds.add(at.id); });

  sock.ev.on('messages.upsert', u => { for (const m of (u.messages || [])) {
    if (m.messageStubType === B.proto.WebMessageInfo.StubType.CIPHERTEXT && m.key && peerIds.has(m.key.id))
      Promise.resolve(sock.sendReceipt(m.key.remoteJid, undefined, [m.key.id], 'peer_msg')).catch(() => {});
    let x = m.message;
    for (let i = 0; i < 4 && x; i++) {
      const pm = x.protocolMessage;
      if (pm && pm.historySyncNotification) {
        const h = pm.historySyncNotification;
        notifs++;
        console.error(`[fh] *** historySyncNotification #${notifs} *** syncType=${h.syncType} `
          + `chunkOrder=${h.chunkOrder} progress=${h.progress} hasDirectPath=${!!h.directPath}`);
      }
      if (pm && pm.peerDataOperationRequestResponseMessage) {
        const r = pm.peerDataOperationRequestResponseMessage;
        console.error(`[fh] PDO response: type=${r.peerDataOperationRequestType} results=${(r.peerDataOperationResult || []).length}`);
      }
      x = x.deviceSentMessage?.message || x.ephemeralMessage?.message || x.viewOnceMessage?.message;
    }
  } });
  sock.ev.on('messaging-history.set', d => {
    setEvents++; msgs += (d && d.messages || []).length;
    console.error(`[fh] *** messaging-history.set #${setEvents} *** messages=${(d && d.messages || []).length} `
      + `chats=${(d && d.chats || []).length} isLatest=${d && d.isLatest} progress=${d && d.progress}`);
  });

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[fh] QR requested => creds rejected'); process.exit(2); }
    if (u.connection === 'close') { const e = u.lastDisconnect && u.lastDisconnect.error; console.error('[fh] CLOSED', e && e.output && e.output.statusCode, e && e.message); process.exit(4); }
    if (u.connection !== 'open') return;
    const pump = setInterval(() => { try { if (sock.ev.isBuffering()) sock.ev.flush(); } catch (e) {} }, 1500);
    if (pump.unref) pump.unref();
    console.error('[fh] OPEN, settling 8s ...');
    await new Promise(r => setTimeout(r, 8000));
    try { await sock.assertSessions([...new Set([inp.lid, inp.me_id].filter(Boolean).map(B.jidNormalizedUser))], true); } catch (e) {}
    if (Object.keys(appStateKeys).length) {
      try { await sock.resyncAppState(B.ALL_WA_PATCH_NAMES, true); console.error('[fh] resyncAppState done'); }
      catch (e) { console.error('[fh] resyncAppState failed:', e && e.message); }
    }

    const req = {
      fullHistorySyncOnDemandRequest: {
        requestMetadata: { requestId: 'wawf-' + Date.now() },
        // field 3 -- says WHICH history to fetch. The first attempt omitted it entirely, so the
        // request carried no window at all.
        fullHistorySyncOnDemandConfig: {
          historyFromTimestamp: 0,
          historyDurationDays: DAYS,
        },
        historySyncConfig: {
          fullSyncDaysLimit: DAYS,
          fullSyncSizeMbLimit: 2048,
          storageQuotaMb: 8192,
          inlineInitialPayloadInE2EeMsg: false,
          recentSyncDaysLimit: DAYS,
          supportCallLogHistory: true,
        },
      },
      peerDataOperationRequestType: B.proto.Message.PeerDataOperationRequestType.FULL_HISTORY_SYNC_ON_DEMAND,
    };
    console.error(`[fh] requesting FULL history sync on demand (${DAYS} days) ...`);
    try {
      const id = await sock.sendPeerDataOperationMessage(req);
      console.error('[fh] sent via sendPeerDataOperationMessage, req id =', id);
    } catch (e) { console.error('[fh] send FAILED:', e && e.message); }
    // and once more addressed to our own LID, which is the session the phone answers on
    try {
      const PDO_TYPE = B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE;
      const id2 = await sock.relayMessage(B.jidNormalizedUser(inp.lid),
        { protocolMessage: { peerDataOperationRequestMessage: req, type: PDO_TYPE } },
        { additionalAttributes: { category: 'peer', push_priority: 'high_force' } });
      console.error('[fh] sent via LID route, req id =', id2);
    } catch (e) { console.error('[fh] LID route FAILED:', e && e.message); }

    setTimeout(() => {
      console.error(`[fh] ==== RESULT: ${notifs} historySyncNotification(s), ${setEvents} messaging-history.set event(s), ${msgs} message(s) ====`);
      process.exit(0);
    }, WAIT);
  });
})().catch(e => { console.error('[fh] FATAL', e); process.exit(9); });
