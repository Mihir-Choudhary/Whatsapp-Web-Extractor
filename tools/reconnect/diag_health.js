// diag_health.js -- is this linked device ACTUALLY able to fetch history, right now?
//
// Written because the debugging loop was costing a day per iteration: run a 4-hour history job,
// get silence, guess at a cause, wait 24h, repeat. This answers the same question in ~60 seconds
// and distinguishes the cases that were previously indistinguishable.
//
// Three checks, in order, because each one makes the next interpretable:
//
//   1. CONNECT. Baileys reports `open` purely on the Noise/transport handshake succeeding. A
//      REVOKED companion still gets `open` -- that is precisely why device :43 looked healthy for
//      two days while the phone ignored everything it said. So "connected" proves nothing on its own.
//
//   2. REGISTERED? Ask the server, via a USync device query against our own account, for the list
//      of device slots on this account. If our own slot is absent, the registration is gone and
//      NOTHING will work until the browser re-pairs. This is the check the tool never had, and it is
//      definitive rather than inferential.
//
//   3. SERVED? Send exactly ONE on-demand history request and wait. Registered but unanswered is a
//      different fault from unregistered, and needs a different response.
//
// Deliberately tiny footprint: one connection, one USync, one PDO, no retries, no renegotiation, no
// pagination. Safe to run repeatedly -- which is the point, since mapping how a device decays needs
// frequent cheap samples, not another four-hour job.
//
//   node diag_health.js        [WAIT=45]
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const need = n => { const p = findFile(n); if (!p) { console.error('[health] missing ' + n); process.exit(4); } return p; };
const inp = JSON.parse(fs.readFileSync(need('creds_in.json')));
const S   = JSON.parse(fs.readFileSync(need('signal_state.json')));
const A   = JSON.parse(fs.readFileSync(need('anchors.json')));
const WAIT = Number(process.env.WAIT || 45) * 1000;

const redact = s => String(s).replace(/\d{5,}/g, m => m.slice(0, 4) + '*'.repeat(m.length - 4));
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

const ourDevice = (() => {                       // ":44" out of "1234:44@s.whatsapp.net"
  const u = String(inp.me_id || '').split('@')[0];
  return u.includes(':') ? Number(u.split(':')[1]) : 0;
})();

let answered = false, verdict = 'UNKNOWN';
(async () => {
  // Announce the build THIS profile's browser runs, taken from its own WAVersionBase, in preference to
  // Baileys' default of asking a third-party endpoint (fetchLatestBaileysVersion) and falling back to a
  // hardcoded constant. Not cosmetic: WhatsApp gates on-demand history on an AB prop
  // (`history_sync_on_demand_companion`), and AB prop values are assigned by the server per client
  // version and platform, so announcing a stale build asks for a version-gated feature as the wrong
  // client. Measured on this profile: we announced 2.3000.1043857760, the browser 2.3000.1049127777.
  // Falls back to the old lookup when the profile did not carry one.
  let version = [2, 3000, 1023223821];
  if (Array.isArray(inp.wa_version) && inp.wa_version.length === 3) {
    version = inp.wa_version.map(Number);
  } else {
    try { version = (await B.fetchLatestBaileysVersion()).version; } catch (e) {}
  }
  console.error(`[health] device slot :${ourDevice}  registrationId ${creds.registrationId}  WA ${version.join('.')}`);

  const sock = makeWASocket({ version, auth: { creds, keys: rt.keys }, logger: quiet,
    printQRInTerminal: false, markOnlineOnConnect: true, syncFullHistory: false,
    shouldSyncHistoryMessage: () => false, getMessage: async () => undefined,
    browser: ['Forensic', 'Recovery', '1.0'] });

  sock.ev.on('messages.upsert', u => { for (const m of (u.messages || [])) {
    let x = m.message;
    for (let i = 0; i < 4 && x; i++) {
      if (x.protocolMessage && x.protocolMessage.historySyncNotification) { answered = true; return; }
      x = x.deviceSentMessage?.message || x.ephemeralMessage?.message || x.viewOnceMessage?.message;
    }
  } });
  sock.ev.on('messaging-history.set', d => { if ((d && d.messages || []).length) answered = true; });

  sock.ev.on('connection.update', async u => {
    if (u.qr) { console.error('[health] 1. CONNECT   FAIL — server asked for a QR: these credentials are no longer accepted'); process.exit(2); }
    if (u.connection === 'close') {
      const e = u.lastDisconnect && u.lastDisconnect.error;
      const code = e && e.output && e.output.statusCode;
      console.error(`[health] 1. CONNECT   FAIL — closed (${code}) ${e && e.message}`);
      if (code === 401 || code === 403) console.error('           that status means this device is LOGGED OUT server-side.');
      process.exit(3);
    }
    if (u.connection !== 'open') return;
    console.error('[health] 1. CONNECT   ok — but note this only proves the Noise handshake; a REVOKED device also reaches "open"');

    // --- 2. is this device still registered on the account? -------------------------------------
    let registered = null, slots = [];
    try {
      const q = new B.USyncQuery().withDeviceProtocol();
      q.withUser(new B.USyncUser().withId(B.jidNormalizedUser(inp.me_id)));
      const res = await sock.executeUSyncQuery(q);
      const list = (res && res.list) || [];
      // The device protocol's parser returns { deviceList, keyIndex }, and executeUSyncQuery puts it
      // on each list entry under the protocol's name ('devices'). So the slots are at
      // entry.devices.deviceList -- iterating entry.devices itself throws "object is not iterable",
      // which the catch below turns into a warning, leaving the check silently non-functional.
      for (const u2 of list) {
        const dl = (u2 && u2.devices && (u2.devices.deviceList || u2.devices)) || [];
        if (Array.isArray(dl)) for (const d of dl) slots.push(d.id);
      }
      registered = slots.includes(ourDevice);
      console.error(`[health] 2. REGISTERED ${registered ? 'ok' : 'FAIL'} — account device slots: [${slots.join(', ')}]`
        + (registered ? `, ours (:${ourDevice}) present` : `, ours (:${ourDevice}) IS ABSENT`));
    } catch (e) {
      console.error('[health] 2. REGISTERED unknown — USync device query failed:', e && e.message);
    }

    if (registered === false) {
      verdict = 'REVOKED';
      console.error('\n[health] VERDICT: this linked device has been REVOKED. History cannot work and will not '
        + 'work until WhatsApp Web is opened and re-paired. Nothing in the profile can restore it.');
      process.exit(0);
    }

    // --- 3. will the phone actually serve us? ---------------------------------------------------
    const a = (A.anchors || []).find(x => !String(x.chat).endsWith('@g.us')) || (A.anchors || [])[0];
    if (!a) { console.error('[health] 3. SERVED    skipped — no anchors'); process.exit(0); }
    const tsMs = a.oldest_ts > 1e12 ? a.oldest_ts : a.oldest_ts * 1000;
    // Send EXACTLY what history_extract.js sends, or a SERVED failure means nothing. Two details
    // matter and both were missing here: supportInlineResponse (field 7, which the reference client
    // always sets, added by proto_patch) and LID routing. Baileys' sendPeerDataOperationMessage
    // always addresses the PN jid, whereas WhatsApp Web addresses
    // getMyPrimaryForOutgoingPeerMessage() = device 0 of the LID jid when peer_message_lid_migration_
    // outgoing is on -- and it ships a validator that logs an error for a peer message sent to a PN
    // in that mode. A probe that asks differently from the real run cannot clear or convict it.
    try { require('./proto_patch').patch(B); } catch (e) {}
    const selfLid = creds.me && creds.me.lid ? B.jidNormalizedUser(creds.me.lid) : null;
    try {
      const req = { chatJid: a.chat, oldestMsgId: a.oldest_id, oldestMsgFromMe: !!a.oldest_fromMe,
        onDemandMsgCount: 10, oldestMsgTimestampMs: tsMs, supportInlineResponse: true };
      const pdo = { historySyncOnDemandRequest: req,
        peerDataOperationRequestType: B.proto.Message.PeerDataOperationRequestType.HISTORY_SYNC_ON_DEMAND };
      const id = selfLid
        ? await sock.relayMessage(selfLid,
            { protocolMessage: { peerDataOperationRequestMessage: pdo,
                type: B.proto.Message.ProtocolMessage.Type.PEER_DATA_OPERATION_REQUEST_MESSAGE } },
            { additionalAttributes: { category: 'peer', push_priority: 'high_force' } })
        : await sock.sendPeerDataOperationMessage(pdo);
      console.error(`[health] 3. SERVED    asked ${redact(a.chat)} for 10 messages via `
        + `${selfLid ? 'LID' : 'PN'} routing (req ${id}); waiting ${WAIT / 1000}s ...`);
    } catch (e) { console.error('[health] 3. SERVED    FAIL — could not send:', e && e.message); process.exit(5); }

    setTimeout(() => {
      if (answered) {
        verdict = 'HEALTHY';
        console.error('\n[health] 3. SERVED    ok — the phone answered\n[health] VERDICT: HEALTHY. History will work.');
      } else {
        verdict = 'REGISTERED_BUT_SILENT';
        console.error('\n[health] 3. SERVED    FAIL — no answer\n[health] VERDICT: the device is still REGISTERED but the '
          + 'phone is not serving it. That is a different fault from revocation: the registration is intact, so '
          + 'something else (session state, throttling, or the phone itself) is refusing.');
      }
      process.exit(0);
    }, WAIT);
  });
})().catch(e => { console.error('[health] FATAL', e); process.exit(9); });
