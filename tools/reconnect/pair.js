// pair.js -- make this tool its OWN linked device, instead of borrowing the browser's.
//
// Why this exists
// ---------------
// Until now `--history` rode on the browser profile's companion registration. That coupling is the
// single cause of every failure in this project: when the browser's device (:43) was revoked, the
// tool had no session, no way to notice (a revoked device still reaches Baileys' `open`), and no way
// to recover. It also meant the tool's own misbehaviour -- retry storms, forced renegotiations --
// degraded the SUBJECT's device, which is unacceptable for a forensic tool.
//
// Pairing our own device fixes all of that at the root:
//   * we hold our own Noise key, Signal identity and prekeys, independent of the profile;
//   * nothing we do can degrade the browser's registration;
//   * the session is ours to repair, and history keeps working however long it has been since
//     WhatsApp Web last ran, because we no longer depend on the browser having run at all.
//
// What it CANNOT do, and why that is not a gap in this implementation
// -------------------------------------------------------------------
// Linking a companion requires approval on the PRIMARY phone -- scanning a QR or entering an
// 8-character code. There is no path, in this tool or in WhatsApp Web, that re-links a device from
// disk artifacts alone: if there were, anyone holding a copy of an old profile could attach to the
// account permanently. When the browser "repaired itself", a human scanned the code. So this needs
// lawful access to the unlocked phone, once.
//
// FORENSIC NOTICE: pairing creates a NEW device on the account. It is visible in the phone's Linked
// Devices list, it notifies the account holder, and it changes account state. That is an overt act
// and must be recorded in the case notes. It is not a covert technique and is not presented as one.
//
//   node pair.js                 show a QR to scan   (WhatsApp > Linked devices > Link a device)
//   node pair.js --phone 919XXXXXXXXX   get an 8-char code to type on the phone instead
//
// On success the device credentials are written to ./wawf_device/ and history_extract.js uses them
// in preference to anything derived from the browser profile.
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const DIR = path.join(__dirname, 'wawf_device');
const argv = process.argv.slice(2);
const phoneIdx = argv.indexOf('--phone');
const PHONE = phoneIdx >= 0 ? String(argv[phoneIdx + 1] || '').replace(/[^0-9]/g, '') : null;

const quiet = { level: 'silent', child: () => quiet, trace(){}, debug(){}, info(){}, warn(){}, error(){}, fatal(){} };

(async () => {
  const { state, saveCreds } = await B.useMultiFileAuthState(DIR);
  if (state.creds && state.creds.registered && state.creds.me) {
    console.error(`[pair] this tool is ALREADY linked as ${String(state.creds.me.id).replace(/\d{5,}/, m => m.slice(0,4)+'*'.repeat(m.length-4))}`);
    console.error('[pair] delete ' + DIR + ' first if you want to link again.');
    process.exit(0);
  }

  let version = [2, 3000, 1023223821];
  try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}

  const sock = makeWASocket({
    version, auth: state, logger: quiet, printQRInTerminal: false,
    markOnlineOnConnect: false,                 // stay quiet: do not steal presence from the phone
    syncFullHistory: false, shouldSyncHistoryMessage: () => false,
    getMessage: async () => undefined,
    browser: B.Browsers.appropriate('Desktop'),  // present as an ordinary desktop companion
  });
  sock.ev.on('creds.update', saveCreds);

  let askedForCode = false;
  sock.ev.on('connection.update', async u => {
    if (u.qr && !PHONE) {
      try {
        const qrcode = require('qrcode-terminal');
        console.error('\n[pair] On the phone: WhatsApp > Settings > Linked devices > Link a device, then scan:\n');
        qrcode.generate(u.qr, { small: true });
      } catch (e) {
        console.error('\n[pair] scan this QR payload (install qrcode-terminal for a drawn code):\n');
        console.error(u.qr + '\n');
      }
    }
    if (u.qr && PHONE && !askedForCode) {
      askedForCode = true;
      try {
        const code = await sock.requestPairingCode(PHONE);
        console.error('\n[pair] On the phone: WhatsApp > Settings > Linked devices > Link with phone number');
        console.error(`[pair] enter this code:   ${String(code).match(/.{1,4}/g).join('-')}\n`);
      } catch (e) { console.error('[pair] could not request a pairing code:', e && e.message); process.exit(3); }
    }
    if (u.connection === 'open') {
      const me = state.creds.me || {};
      const red = s => String(s || '').replace(/\d{5,}/g, m => m.slice(0,4)+'*'.repeat(m.length-4));
      console.error(`\n[pair] LINKED. this tool is now its own device: ${red(me.id)}  lid=${red(me.lid)}`);
      console.error(`[pair] credentials saved to ${DIR}`);
      console.error('[pair] it no longer depends on the browser profile for history, and nothing it does');
      console.error('[pair] can affect the browser\'s own linked device.');
      console.error('[pair] RECORD IN THE CASE NOTES: a new linked device was added to this account.');
      setTimeout(() => process.exit(0), 1500);
    }
    if (u.connection === 'close') {
      const e = u.lastDisconnect && u.lastDisconnect.error;
      const code = e && e.output && e.output.statusCode;
      if (code === B.DisconnectReason.restartRequired) {
        console.error('[pair] pairing accepted; reconnecting to finish...');
        return process.exit(75);          // caller re-runs; Baileys requires a restart after pairing
      }
      console.error('[pair] closed', code, e && e.message);
      process.exit(4);
    }
  });
})().catch(e => { console.error('[pair] FATAL', e); process.exit(9); });
