// diag_media_retry.js -- can we recover media whose CDN directPath has EXPIRED?
//
// A message's `directPath` is a capability URL with a short life: measured on this profile, media
// from the newest day still serves (HTTP 206) while anything a week or older returns 403. The
// mediaKey never expires, so the ciphertext is still decryptable -- we just cannot fetch it any more.
//
// WhatsApp's own answer to that is a media re-upload request: a `receipt type="server-error"`
// carrying an `rmr` node for the message, which makes the sender re-upload the media and hand back
// a FRESH directPath (Baileys: encryptMediaRetryRequest / decodeMediaRetryNode -> the
// 'messages.media-update' event). This proves whether that path works for us, since it is the only
// way to reach media older than a couple of days.
//
// Input:  media_retry_in.json  {"items":[{rid,id,remoteJid,fromMe,participant,mediaKey,mime}, ...]}
// Output: media_retry_out.json {"results":[{rid,id,ok,directPath?,mediaKey?,error?}, ...]}
//   node diag_media_retry.js        [WAIT=90]
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const inp = JSON.parse(fs.readFileSync(findFile('creds_in.json')));
const S   = JSON.parse(fs.readFileSync(findFile('signal_state.json')));
const IN  = JSON.parse(fs.readFileSync(findFile('media_retry_in.json'), 'utf8')).items || [];
const WAIT = Number(process.env.WAIT || 90) * 1000;
const OUT = path.join(path.dirname(findFile('media_retry_in.json')), 'media_retry_out.json');

const redact = s => String(s).replace(/\d{5,}/g, m => m.slice(0, 4) + '*'.repeat(m.length - 4));
const mk = lvl => ({ level: lvl, child: () => mk(lvl), trace: () => {}, debug: () => {},
  info: () => {}, warn: (...a) => log('WARN', a), error: (...a) => log('ERROR', a), fatal: (...a) => log('FATAL', a) });
function log(l, args) {
  const rep = (k, v) => (v instanceof Error ? { name: v.name, message: v.message } : v);
  let s = args.map(a => { try { return typeof a === 'string' ? a : JSON.stringify(a, rep); } catch (e) { return String(a); } }).join(' ');
  console.error(`[${l}] ${redact(s).slice(0, 300)}`);
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

const results = new Map();
const save = () => fs.writeFileSync(OUT, JSON.stringify({ results: [...results.values()] }, null, 1));

(async () => {
  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  console.error(`[mr] WA ${version.join('.')} | ${IN.length} expired-media request(s) | sessions ${rt.stats.sessions}, carried ${rt.stats.carried}`);

  const peerIds = new Set();
  const retryCounters = new Map();
  const sock = makeWASocket({
    version, auth: { creds, keys: rt.keys }, logger: mk('warn'),
    msgRetryCounterCache: { get: k => { if (peerIds.has(String(k).split(':')[0])) return 1e6;
        const v = retryCounters.get(k); return v === undefined ? 1 : v; },
      set: (k, v) => retryCounters.set(k, v), del: k => retryCounters.delete(k) },
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: () => false, getMessage: async () => undefined,
    browser: ['Forensic', 'Recovery', '1.0'],
  });
  sock.ev.on('creds.update', () => rt.save());
  sock.ws.on('CB:message', node => { const at = node.attrs || {}; if (at.category === 'peer') peerIds.add(at.id); });
  sock.ev.on('messages.upsert', u => { for (const m of (u.messages || [])) {
    if (m.messageStubType === B.proto.WebMessageInfo.StubType.CIPHERTEXT && m.key && peerIds.has(m.key.id))
      Promise.resolve(sock.sendReceipt(m.key.remoteJid, undefined, [m.key.id], 'peer_msg')).catch(() => {}); } });

  // The re-upload answer arrives as this event (Baileys decodes the `rmr` receipt for us).
  // The reply does NOT carry the new directPath in the clear. `media` is {ciphertext, iv}: an
  // AES-GCM-wrapped proto.MediaRetryNotification keyed by HKDF(mediaKey, "WhatsApp Media Retry
  // Notification"), with the message id as AAD. Decrypt it to get {result, directPath}.
  const keyById = new Map(IN.map(i => [i.id, i.mediaKey]));
  sock.ev.on('messages.media-update', async updates => {
    for (const u of (updates || [])) {
      const id = u.key && u.key.id;
      const rec = results.get(id);
      if (!rec) { console.error('[mr] media-update for an id we did not ask about:', redact(id)); continue; }
      if (u.error) {
        rec.ok = false; rec.error = `${u.error.output && u.error.output.statusCode}: ${u.error.message}`;
      } else if (u.media && u.media.ciphertext && u.media.iv) {
        try {
          const note = await B.decryptMediaRetryData(u.media, bb(keyById.get(id)), id);
          rec.result = note.result;
          rec.resultName = Object.keys(B.proto.MediaRetryNotification.ResultType)
            .find(k => B.proto.MediaRetryNotification.ResultType[k] === note.result) || String(note.result);
          // MediaRetryNotification also carries `messageSecret`. The re-uploaded object is NOT
          // decryptable with the original mediaKey (MAC fails under every info string), so this
          // is the only other key material on offer -- capture it for analysis.
          if (note.messageSecret && note.messageSecret.length)
            rec.messageSecret = Buffer.from(note.messageSecret).toString('base64');
          if (note.directPath) { rec.ok = true; rec.directPath = note.directPath; }
          else { rec.ok = false; rec.error = `result=${rec.resultName}, no directPath`; }
        } catch (e) { rec.ok = false; rec.error = 'could not decrypt the retry notification: ' + e.message; }
      } else { rec.ok = false; rec.error = 'reply carried neither an error nor a ciphertext'; }
      console.error(`[mr] ${rec.ok ? 'RE-UPLOADED' : 'refused   '}  rid=${rec.rid}  ${rec.ok ? 'fresh directPath received' : rec.error}`);
      save();
    }
  });

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[mr] QR requested => creds rejected'); process.exit(2); }
    if (u.connection === 'close') { const e = u.lastDisconnect && u.lastDisconnect.error; console.error('[mr] CLOSED', e && e.output && e.output.statusCode, e && e.message); save(); process.exit(4); }
    if (u.connection !== 'open') return;
    // Same wedged-buffer problem as the history path: without this, 'messages.media-update' never fires.
    const pump = setInterval(() => { try { if (sock.ev.isBuffering()) sock.ev.flush(); } catch (e) {} }, 1500);
    if (pump.unref) pump.unref();
    console.error('[mr] OPEN, settling 8s ...');
    await new Promise(r => setTimeout(r, 8000));

    for (const it of IN) {
      const key = { id: it.id, remoteJid: it.remoteJid, fromMe: !!it.fromMe, participant: it.participant || undefined };
      results.set(it.id, { rid: it.rid, id: it.id, mime: it.mime, ok: null });
      try {
        const node = await B.encryptMediaRetryRequest(key, bb(it.mediaKey), creds.me.id);
        await sock.sendNode(node);
        console.error(`[mr] asked for a re-upload: rid=${it.rid} (${it.mime || '?'})`);
      } catch (e) {
        results.get(it.id).ok = false; results.get(it.id).error = String(e && e.message);
        console.error(`[mr] send failed rid=${it.rid}:`, e && e.message);
      }
      await new Promise(r => setTimeout(r, 800));
    }
    save();
    setTimeout(() => {
      const got = [...results.values()].filter(r => r.ok === true).length;
      const no  = [...results.values()].filter(r => r.ok === false).length;
      console.error(`[mr] ==== RESULT: ${got} re-uploaded, ${no} refused, ${IN.length - got - no} no answer ==== -> ${OUT}`);
      save(); process.exit(0);
    }, WAIT);
  });
})().catch(e => { console.error('[mr] FATAL', e); save(); process.exit(9); });
