// Reconnect to WhatsApp using disk-recovered Noise creds; capture companion_enc_static from <success>.
const B = require('@whiskeysockets/baileys');
const makeWASocket = B.default;
const fs = require('fs');
const path = require('path');
let P = null; try { P = require('pino'); } catch (e) {}   // require() throws if absent; a ternary can't catch that

// creds_in.json is produced by `wawf creds`, which (as a frozen .exe) writes it to the CURRENT
// directory — not into this folder. So resolve it flexibly: explicit arg, then CWD, then here.
const findFile = (name, override) => {
  for (const c of [override, path.resolve(process.cwd(), name), path.join(__dirname, name)]) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
};

(async () => {
  const credsPath = findFile('creds_in.json', process.argv[2]);
  if (!credsPath) {
    console.error('[!] creds_in.json not found. Run `wawf creds <profile>` first, then either run this\n' +
      '    from the same folder, or pass the path:  node reconnect.js C:\\path\\to\\creds_in.json');
    process.exit(4);
  }
  const inp = JSON.parse(fs.readFileSync(credsPath));
  if (!inp.account) { console.error('[!] creds_in.json has no account (adv_signed_identity missing) — re-run export_baileys_creds'); process.exit(2); }
  const bb = (b64) => Buffer.from(b64, 'base64');

  const creds = B.initAuthCreds();               // fresh; override identity bits with recovered ones
  creds.noiseKey = { private: bb(inp.noise_priv), public: bb(inp.noise_pub) };
  creds.registrationId = inp.registrationId;
  creds.me = { id: inp.me_id, lid: inp.lid };
  creds.account = {
    details: bb(inp.account.details),
    accountSignatureKey: bb(inp.account.accountSignatureKey),
    accountSignature: bb(inp.account.accountSignature),
    deviceSignature: bb(inp.account.deviceSignature),
  };
  creds.registered = true;
  creds.platform = 'web';

  const keys = {};                               // in-memory signal key store
  const store = {
    get: (type, ids) => { const d = {}; for (const id of ids) { const v = keys[`${type}-${id}`]; if (v) d[id] = v; } return d; },
    set: (data) => { for (const t in data) for (const id in data[t]) keys[`${t}-${id}`] = data[t][id]; },
  };

  let version = [2, 3000, 1023223821];
  try { const r = await B.fetchLatestBaileysVersion(); version = r.version; console.error('[v] using WA version', version.join('.')); }
  catch (e) { console.error('[v] fetchLatestBaileysVersion failed, fallback', version.join('.')); }

  const logger = P ? P({ level: 'silent' }) : undefined;
  const sock = makeWASocket({
    version, auth: { creds, keys: store }, logger,
    printQRInTerminal: false, markOnlineOnConnect: false,
    syncFullHistory: false, browser: ['Forensic', 'Recovery', '1.0'],
  });

  let captured = null;
  const scan = (node, depth=0) => {
    if (!node || depth > 6) return;
    if (node.attrs) for (const k in node.attrs) {
      if (/companion_enc_static|companion_enc|enc_static/i.test(k)) {
        captured = node.attrs[k];
        console.log('CAPTURED ' + k + ' = ' + captured);
      }
    }
    if (Array.isArray(node.content)) node.content.forEach(c => scan(c, depth+1));
  };
  sock.ws.on('frame', (f) => { try { scan(f); if (f && f.tag) console.error('[node]', f.tag, JSON.stringify(f.attrs||{}).slice(0,200)); } catch(e){} });
  sock.ws.on('CB:success', (n) => { scan(n); });

  const done = (code) => { try { sock.end(); } catch(e){}
    if (captured) {
      const outPath = path.resolve(process.cwd(), 'companion_enc_static.txt');
      fs.writeFileSync(outPath, captured);
      console.error('[done] captured=YES -> ' + outPath);
    } else { console.error('[done] captured=NO'); }
    process.exit(captured?0:code); };

  sock.ev.on('connection.update', (u) => {
    if (u.qr) { console.error('[!] server issued QR => creds NOT accepted (login failed)'); done(2); }
    if (u.connection === 'open') { console.error('[+] connection OPEN'); setTimeout(()=>done(captured?0:3), 1500); }
    if (u.connection === 'close') { const s=u.lastDisconnect&&u.lastDisconnect.error; console.error('[x] closed:', s&&s.message); setTimeout(()=>done(captured?0:4), 500); }
  });

  setTimeout(() => { console.error('[timeout]'); done(5); }, 30000);
})().catch(e => { console.error('FATAL', e); process.exit(9); });
