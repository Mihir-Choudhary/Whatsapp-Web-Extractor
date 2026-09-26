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
function log(lvl, args) {
  let s = args.map(a => { try { return typeof a === 'string' ? a : JSON.stringify(a); } catch (e) { return String(a); } }).join(' ');
  if (s.length > 400) s = s.slice(0, 400) + '...';
  if (lvl === 'ERROR' || lvl === 'WARN' || lvl === 'FATAL' || INTERESTING.test(s)) console.error(`[${lvl}] ${s}`);
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
const preKeys = S.preKeys, mem = {};
const store = {
  get: (t, ids) => { const d = {}; for (const id of ids) { const k = mem[`${t}-${id}`]; if (k !== undefined) { if (k !== null) d[id] = k; continue; } if (t === 'pre-key') { const p = preKeys[String(id)]; if (p) d[id] = { private: bb(p.private), public: bb(p.public) }; } } return d; },
  set: data => { for (const t in data) for (const id in data[t]) mem[`${t}-${id}`] = data[t][id]; }
};

(async () => {
  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  console.error('[diag] WA version', version.join('.'), '| me =', inp.me_id, '| lid =', inp.lid);

  const T = B.proto.Message.HistorySyncNotification.HistorySyncType;
  const sock = makeWASocket({
    version, auth: { creds, keys: store }, logger: mk('debug'),
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: h => { try { return !!h && h.syncType === T.ON_DEMAND; } catch (e) { return false; } },
    getMessage: async () => undefined, browser: ['Forensic', 'Recovery', '1.0'],
  });

  // dump EVERY event we care about, matched or not
  sock.ev.on('messaging-history.set', d => {
    console.error('[EVENT messaging-history.set] sid=', d && d.peerDataRequestSessionId,
      'messages=', (d && d.messages || []).length, 'chats=', (d && d.chats || []).length, 'isLatest=', d && d.isLatest);
  });
  sock.ev.on('messages.upsert', u => {
    for (const m of (u.messages || [])) {
      const keys = m.message ? Object.keys(m.message) : [];
      const pm = m.message && m.message.protocolMessage;
      console.error('[EVENT messages.upsert]', u.type, 'from=', m.key && m.key.remoteJid, 'fromMe=', m.key && m.key.fromMe,
        'content=', JSON.stringify(keys), pm ? ('protocolType=' + pm.type + ' hasHistNotif=' + !!pm.historySyncNotification) : '');
    }
  });
  sock.ev.on('creds.update', () => {});

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[diag] QR requested => creds rejected'); process.exit(2); }
    if (u.connection === 'close') { const e = u.lastDisconnect && u.lastDisconnect.error; console.error('[diag] CLOSED', e && e.output && e.output.statusCode, e && e.message); process.exit(4); }
    if (u.connection !== 'open') return;
    console.error('[diag] CONNECTION OPEN. waiting 8s for the server to settle...');
    await new Promise(r => setTimeout(r, 8000));
    const a = A.anchors[0];
    const tsSec = a.oldest_ts, tsMs = tsSec > 1e12 ? tsSec : tsSec * 1000;
    console.error('[diag] requesting ONE page:', JSON.stringify({ chat: a.chat, id: a.oldest_id, fromMe: !!a.oldest_fromMe, tsSec, tsMs, count: 50 }));
    try {
      const rid = await sock.fetchMessageHistory(50, { remoteJid: a.chat, id: a.oldest_id, fromMe: !!a.oldest_fromMe }, tsMs);
      console.error('[diag] fetchMessageHistory returned request id =', rid);
    } catch (e) { console.error('[diag] fetchMessageHistory THREW:', e && e.message); }
    setTimeout(() => { console.error('[diag] 75s elapsed, no more waiting. Exiting.'); process.exit(0); }, 75000);
  });
})().catch(e => { console.error('[diag] FATAL', e); process.exit(9); });
