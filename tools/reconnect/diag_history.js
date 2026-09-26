// Diagnostic: why does the phone not answer our on-demand history request, when the browser's own
// "load older messages" button works? Reuses the creds/signal/anchors already recovered by `wawf history`,
// connects with FULL Baileys logging, sends exactly ONE request, and dumps everything that happens.
//   node diag_history.js            (run from tools/reconnect, after a `wawf history` has produced the inputs)
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const inp = JSON.parse(fs.readFileSync(findFile('creds_in.json')));
const S   = JSON.parse(fs.readFileSync(findFile('signal_state.json')));
const A   = JSON.parse(fs.readFileSync(findFile('anchors.json')));

// verbose logger so we can see relay/decrypt/stanza activity
const mk = (lvl) => ({
  level: lvl,
  child: () => mk(lvl),
  trace: (...a) => log('TRACE', a), debug: (...a) => log('DEBUG', a),
  info:  (...a) => log('INFO', a),  warn:  (...a) => log('WARN', a),
  error: (...a) => log('ERROR', a), fatal: (...a) => log('FATAL', a),
});
const INTERESTING = /pdo|peer|history|prekey|session|device|relay|encrypt|decrypt|receipt|notification|fail|error|retry/i;
// Tally decrypt outcomes: this is the number that tells us whether restoring the Signal session
// store actually fixed inbound decryption.
const tally = { ok: 0, sessionError: 0, preKeyError: 0, otherFail: 0 };
function log(lvl, args) {
  // JSON.stringify drops Error.message/stack (they are non-enumerable), which hid the actual
  // libsignal failure behind a bare {"name":"SessionError"}. Expand errors explicitly.
  const rep = (k, v) => (v instanceof Error ? { name: v.name, message: v.message, stack: (v.stack || '').split('\n').slice(1, 4).join(' | ') } : v);
  let s = args.map(a => { try { return typeof a === 'string' ? a : JSON.stringify(a, rep); } catch (e) { return String(a); } }).join(' ');
  if (/SessionError/.test(s)) tally.sessionError++;
  else if (/PreKeyError/.test(s)) tally.preKeyError++;
  else if (/failed to decrypt/i.test(s)) tally.otherFail++;   // Baileys logs no success line;
                                                              // tally.ok is counted on upsert
  if (s.length > 1500) s = s.slice(0, 1500) + '...';
  if (lvl === 'ERROR' || lvl === 'WARN' || lvl === 'FATAL' || INTERESTING.test(s)) console.error(`[${lvl}] ${s}`);
}
process.on('exit', () => console.error('[diag] DECRYPT TALLY ' + JSON.stringify(tally)));

const bb = b => Buffer.from(b, 'base64');
const creds = B.initAuthCreds();
creds.noiseKey = { private: bb(inp.noise_priv), public: bb(inp.noise_pub) };
creds.signedIdentityKey = { private: bb(S.signedIdentityKey.private), public: bb(S.signedIdentityKey.public) };
creds.registrationId = S.registrationId;
creds.signedPreKey = { keyId: S.signedPreKey.keyId, keyPair: { private: bb(S.signedPreKey.private), public: bb(S.signedPreKey.public) }, signature: S.signedPreKey.signature ? bb(S.signedPreKey.signature) : Buffer.alloc(0) };
creds.me = { id: inp.me_id, lid: inp.lid };
creds.account = { details: bb(inp.account.details), accountSignatureKey: bb(inp.account.accountSignatureKey), accountSignature: bb(inp.account.accountSignature), deviceSignature: bb(inp.account.deviceSignature) };
creds.registered = true; creds.platform = 'web';
// Instrument libsignal's decrypt so a failure says WHICH stage failed. "Bad MAC" alone cannot
// distinguish a stale chain index from a stale ratchet from a wrong identity key.
try {
  const SC = require('libsignal/src/session_cipher.js');
  const proto = SC.SessionCipher ? SC.SessionCipher.prototype : SC.prototype;
  const orig = proto.doDecryptWhisperMessage;
  const pfx = b => (Buffer.isBuffer(b) ? b.toString('base64').slice(0, 6) : String(b));
  proto.doDecryptWhisperMessage = async function (buf, session) {
    const pb = require('libsignal/src/protobufs.js');
    let info = {};
    try {
      const m = pb.WhisperMessage.decode(buf.slice(1, -8));
      const chain = session.getChain(m.ephemeralKey);
      info = {
        addr: String(this.addr), msgCounter: m.counter, msgPrev: m.previousCounter,
        eph: pfx(m.ephemeralKey), haveChain: !!chain,
        chainType: chain && chain.chainType, chainCounter: chain && chain.chainKey.counter,
        chains: Object.keys(session._chains).length,
        lastRemote: pfx(session.currentRatchet.lastRemoteEphemeralKey),
        ourRatchet: pfx(session.currentRatchet.ephemeralKeyPair.pubKey),
        baseKeyType: session.indexInfo.baseKeyType, closed: session.indexInfo.closed !== -1,
        remoteIdent: pfx(session.indexInfo.remoteIdentityKey),
      };
    } catch (e) { info = { decodeErr: e.message }; }
    try {
      const r = await orig.call(this, buf, session);
      console.error('[sig] OK   ' + JSON.stringify(info));
      return r;
    } catch (e) {
      console.error('[sig] FAIL ' + e.message + ' ' + JSON.stringify(info));
      throw e;
    }
  };
  console.error('[diag] libsignal decrypt instrumented');
} catch (e) { console.error('[diag] could not instrument libsignal:', e.message); }

const signalStore = require('./signal_store');
const rt = signalStore.open({
  signalState: S, creds,
  statePath: signalStore.defaultStatePath(path.dirname(findFile('signal_state.json'))),
  bufferJSON: B.BufferJSON,
});
const store = rt.keys;
console.error(`[diag] signal state: ${rt.stats.sessions} session(s), ${rt.stats.senderKeys} sender key(s), `
  + `${rt.stats.preKeys} prekey(s) | runtime overlay: ${rt.stats.state}, ${rt.stats.carried} record(s) carried over`);

(async () => {
  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  console.error('[diag] WA version', version.join('.'), '| me =', inp.me_id, '| lid =', inp.lid);

  // Make the FIRST retry receipt carry our prekey bundle. Baileys only attaches keys from
  // retry #2 (`if (retryCount > 1 || forceIncludeKeys)`), and without keys the sender has no way
  // to rebuild the session, so it just re-sends the same ciphertext we already cannot read. The
  // counter also lives in a per-process cache, so a short forensic run never reached #2 and the
  // undecryptable backlog was redelivered forever. Starting the count at 1 asks the sender to
  // re-encrypt to a fresh session immediately, which is the whole point of the retry.
  const retryCounters = new Map();
  const msgRetryCounterCache = {
    get: k => { const v = retryCounters.get(k); return v === undefined ? 1 : v; },
    set: (k, v) => retryCounters.set(k, v),
    del: k => retryCounters.delete(k),
  };

  const T = B.proto.Message.HistorySyncNotification.HistorySyncType;
  const sock = makeWASocket({
    version, auth: { creds, keys: store }, logger: mk('debug'), msgRetryCounterCache,
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: h => { try { return !!h && h.syncType === T.ON_DEMAND; } catch (e) { return false; } },
    getMessage: async () => undefined, browser: ['Forensic', 'Recovery', '1.0'],
  });

  // Wire level: who is actually sending us these stanzas, and in what envelope. The Signal
  // address alone cannot distinguish a group participant from our own phone's sent-message
  // mirror, and that distinction decides which session should have decrypted it.
  try {
    sock.ws.on('CB:message', node => {
      const a = node.attrs || {};
      const encs = (Array.isArray(node.content) ? node.content : []).filter(c => c.tag === 'enc')
        .map(c => (c.attrs || {}).type + (((c.attrs || {}).v) ? '/v' + c.attrs.v : ''));
      console.error(`[stanza] from=${a.from} participant=${a.participant || '-'} recipient=${a.recipient || '-'}`
        + ` type=${a.type || '-'} cat=${a.category || '-'} addressing=${a.addressing_mode || '-'} enc=${JSON.stringify(encs)}`);
    });
  } catch (e) { console.error('[diag] could not hook CB:message:', e.message); }

  // dump EVERY event we care about, matched or not
  sock.ev.on('messaging-history.set', d => {
    console.error('[EVENT messaging-history.set] sid=', d && d.peerDataRequestSessionId,
      'messages=', (d && d.messages || []).length, 'chats=', (d && d.chats || []).length, 'isLatest=', d && d.isLatest);
  });
  sock.ev.on('messages.upsert', u => {
    for (const m of (u.messages || [])) {
      if (m.message) tally.ok++;
      const keys = m.message ? Object.keys(m.message) : [];
      const pm = m.message && m.message.protocolMessage;
      console.error('[EVENT messages.upsert]', u.type, 'from=', m.key && m.key.remoteJid, 'fromMe=', m.key && m.key.fromMe,
        'content=', JSON.stringify(keys), pm ? ('protocolType=' + pm.type + ' hasHistNotif=' + !!pm.historySyncNotification) : '');
    }
  });
  sock.ev.on('creds.update', () => rt.save());    // keep the rotated prekeys/app-state ids
  // The retry floor above skips Baileys' own retry-#1 placeholder request, so ask explicitly.
  sock.ev.on('messages.upsert', u => { for (const m of (u.messages || [])) {
    if (m.messageStubType === B.proto.WebMessageInfo.StubType.CIPHERTEXT && m.key)
      Promise.resolve(sock.requestPlaceholderResend(m.key)).catch(() => {}); } });

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[diag] QR requested => creds rejected'); process.exit(2); }
    if (u.connection === 'close') { const e = u.lastDisconnect && u.lastDisconnect.error; console.error('[diag] CLOSED', e && e.output && e.output.statusCode, e && e.message); process.exit(4); }
    if (u.connection !== 'open') return;
    console.error('[diag] CONNECTION OPEN. waiting 8s for the server to settle...');
    await new Promise(r => setTimeout(r, 8000));

    // Force a brand-new Signal session with our own primary device before asking it for history.
    // The session in the browser profile is a snapshot of a live ratchet: the phone has moved on
    // since (every earlier attempt of ours nudged it further), so its replies arrive on chains we
    // can no longer derive and fail with Bad MAC. Fetching the prekey bundle and rebuilding the
    // session makes US the initiator, so the reply comes back on a ratchet we own end to end.
    const selfJids = [...new Set([inp.lid, inp.me_id].filter(Boolean).map(B.jidNormalizedUser))];
    try {
      const fetched = await sock.assertSessions(selfJids, true);
      console.error('[diag] forced fresh session with own devices', JSON.stringify(selfJids.map(j => j.replace(/\d{6,}/, 'NNN'))), '=> fetched:', fetched);
    } catch (e) { console.error('[diag] assertSessions(force) FAILED:', e && e.message); }

    const a = A.anchors[0];
    const tsSec = a.oldest_ts, tsMs = tsSec > 1e12 ? tsSec : tsSec * 1000;
    console.error('[diag] requesting ONE page:', JSON.stringify({ chat: a.chat, id: a.oldest_id, fromMe: !!a.oldest_fromMe, tsSec, tsMs, count: 50 }));
    try {
      const rid = await sock.fetchMessageHistory(50, { remoteJid: a.chat, id: a.oldest_id, fromMe: !!a.oldest_fromMe }, tsMs);
      console.error('[diag] fetchMessageHistory returned request id =', rid);
    } catch (e) { console.error('[diag] fetchMessageHistory THREW:', e && e.message); }
    setTimeout(() => { console.error('[diag] wait window elapsed, no more waiting. Exiting.'); process.exit(0); }, 170000);
  });
})().catch(e => { console.error('[diag] FATAL', e); process.exit(9); });
