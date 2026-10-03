// diag_abprops.js -- ask the server what features are enabled FOR US, instead of inferring it.
//
// Why this exists
// ---------------
// WhatsApp gates on-demand history on an A/B prop. From its own bundle:
//
//   isHistorySyncOnDemandEnabled():
//     if (!PrimaryFeatures.historySyncOnDemand) return false;
//     ...
//     return isWindows ? (PrimaryFeatures.extendedHistorySyncOnDemand
//                         && getABPropConfigValue('history_sync_on_demand_companion')) : true;
//
// Those prop values are not baked into the client -- WhatsApp Web FETCHES them during the loading
// screen, with an iq we never sent:
//
//   <iq xmlns="abt" to="s.whatsapp.net" type="get" id="...">
//     <props protocol="1" [hash="..."] [refresh_id="..."]/>
//   </iq>
//
// and the reply carries one <prop> per value:
//
//   <iq type="result">
//     <props protocol="1" ab_key=".." hash=".." refresh=".." refresh_id=".." delta_update="..">
//       <prop config_code="<int>" config_value="<string>" [config_expo_key="<int>"]/>
//       <prop event_code="<int>" sampling_weight="<int>"/>        (sampling, not a feature flag)
//     </props>
//     <erid>..</erid>
//   </iq>
//
// (request builder: WASmaxOutAbPropsGetExperimentConfigRequest; reply parser:
//  WASmaxInAbPropsGetExperimentConfigResponseSuccess + WASmaxInAbPropsExperimentConfigMixin.)
//
// Because we never asked, every silent history request has been uninterpretable: we could not tell a
// throttled device from one the feature was simply switched off for. This answers that directly.
//
// It also costs nothing against the history budget. This is an iq to s.whatsapp.net, not a peer
// message to the phone, so it neither asks the phone for anything nor counts toward
// history_sync_on_demand_failure_limit. Safe to run inside a cooldown.
//
//   node diag_abprops.js                      announce the version from creds_in.json
//   WA_VERSION=2.3000.1043857760 node diag_abprops.js       override, to A/B the announced build
//   node diag_abprops.js --json out.json      also dump every prop the server returned
'use strict';
const B = require('@whiskeysockets/baileys'); const makeWASocket = B.default;
const fs = require('fs'), path = require('path');

const findFile = n => { for (const c of [path.resolve(process.cwd(), n), path.join(__dirname, n)]) if (fs.existsSync(c)) return c; return null; };
const need = n => { const p = findFile(n); if (!p) { console.error('[abprops] missing ' + n); process.exit(4); } return p; };
const inp = JSON.parse(fs.readFileSync(need('creds_in.json'), 'utf8'));
const S = JSON.parse(fs.readFileSync(need('signal_state.json'), 'utf8'));
const argv = process.argv.slice(2);
const jsonIdx = argv.indexOf('--json');
const JSON_OUT = jsonIdx >= 0 ? (argv[jsonIdx + 1] || 'abprops.json') : null;

// The props this project actually reasons about. The server answers by numeric config_code, so an id
// we do not name here is still reported, just as `#<code>`. Extracted from WAWebABPropsConfigs.
const KNOWN = {
  3337: ['history_sync_on_demand', 'bool'],
  17198: ['history_sync_on_demand_companion', 'bool'],
  4365: ['history_sync_on_demand_cooldown_sec', 'int'],
  4364: ['history_sync_on_demand_failure_limit', 'int'],
  3811: ['history_sync_on_demand_message_count', 'int'],
  18391: ['history_sync_on_demand_time_boundary_days_desktops', 'int'],
  3882: ['history_sync_on_demand_timeout_ms', 'int'],
  4135: ['history_sync_on_demand_with_android_beta', 'bool'],
  19110: ['wa_web_history_sync_dynamic_throttling', 'bool'],
  24343: ['web_force_lid_chats_in_history', 'bool'],
  24147: ['web_history_sync_worker_enabled', 'bool'],
  600: ['web_abprop_drop_full_history_sync', 'bool'],
  5106: ['web_noncritical_history_sync_message_processing_break_iteration', 'int'],
  26888: ['remove_pn_dependencies', 'bool'],
  24184: ['peer_message_lid_migration_outgoing', 'bool'],
};
// The ones that decide whether we are even allowed to ask for history.
const HEADLINE = [3337, 17198, 4135, 19110, 24343, 4364, 4365, 3811, 3882, 18391];

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
const rt = signalStore.open({ signalState: S, creds, appStateKeys: {},
  statePath: signalStore.defaultStatePath(path.dirname(need('signal_state.json'))), bufferJSON: B.BufferJSON });

// Which build do we announce? This is the whole point of the A/B: AB prop values are assigned by the
// server per client version and platform, so the answer below is a function of what we claim to be.
let version = [2, 3000, 1023223821], vsrc = 'hardcoded fallback';
if (process.env.WA_VERSION) {
  const p = String(process.env.WA_VERSION).split('.').map(Number);
  if (p.length === 3 && p.every(n => Number.isFinite(n))) { version = p; vsrc = 'WA_VERSION override'; }
} else if (Array.isArray(inp.wa_version) && inp.wa_version.length === 3) {
  version = inp.wa_version.map(Number); vsrc = "profile WAVersionBase";
}

const fmt = (code, raw) => {
  const k = KNOWN[code];
  const name = k ? k[0] : `#${code}`;
  let val = raw;
  if (k && k[1] === 'bool') val = (raw === 'true' || raw === '1') ? 'true' : (raw === 'false' || raw === '0') ? 'false' : raw;
  return { code, name, value: val, known: !!k };
};

(async () => {
  console.error(`[abprops] announcing ${version.join('.')}  (${vsrc})   device :${String(inp.device)}`);
  const sock = makeWASocket({ version, auth: { creds, keys: rt.keys }, logger: quiet,
    printQRInTerminal: false, markOnlineOnConnect: false, syncFullHistory: false,
    shouldSyncHistoryMessage: () => false, getMessage: async () => undefined,
    browser: ['Forensic', 'Recovery', '1.0'] });

  let finished = false;
  const done = c => { if (finished) return; finished = true; try { sock.end(); } catch (e) {} process.exit(c); };
  setTimeout(() => { console.error('[abprops] timed out waiting for the server'); done(6); }, 60000);

  sock.ev.on('connection.update', async u => {
    if (finished) return;      // the close that follows our own sock.end() is not a failure
    if (u.qr) { console.error('[abprops] CONNECT FAIL — server asked for a QR; these credentials are not accepted'); return done(2); }
    if (u.connection === 'close') {
      const e = u.lastDisconnect && u.lastDisconnect.error;
      console.error('[abprops] CONNECT FAIL —', e && e.output && e.output.statusCode, e && e.message);
      return done(3);
    }
    if (u.connection !== 'open') return;
    console.error('[abprops] connected; sending <iq xmlns="abt"><props protocol="1"/></iq>');

    let res;
    try {
      res = await sock.query({ tag: 'iq',
        attrs: { to: B.S_WHATSAPP_NET, xmlns: 'abt', type: 'get' },
        content: [{ tag: 'props', attrs: { protocol: '1' } }] });
    } catch (e) {
      // A refusal is itself a finding: it says this client is not being treated as a full web client.
      console.error('[abprops] the server REFUSED the experiment-config query:', e && e.message);
      console.error('[abprops] that is a result, not a crash — WhatsApp Web sends this on every load,');
      console.error('[abprops] so a refusal means our client is not accepted as one.');
      return done(5);
    }

    const propsNode = (res.content || []).find(n => n && n.tag === 'props');
    if (!propsNode) {
      console.error('[abprops] reply had no <props> element:', JSON.stringify(res).slice(0, 400));
      return done(5);
    }
    const attrs = propsNode.attrs || {};
    console.error(`[abprops] props protocol=${attrs.protocol} ab_key=${attrs.ab_key || '-'} `
      + `hash=${attrs.hash || '-'} refresh=${attrs.refresh || '-'} refresh_id=${attrs.refresh_id || '-'} `
      + `delta_update=${attrs.delta_update || '-'}`);

    const experiments = [], sampling = [];
    for (const n of (propsNode.content || [])) {
      if (!n || n.tag !== 'prop') continue;
      const a = n.attrs || {};
      if (a.config_code !== undefined) experiments.push(fmt(Number(a.config_code), a.config_value));
      else if (a.event_code !== undefined) sampling.push({ code: Number(a.event_code), weight: Number(a.sampling_weight) });
    }
    console.error(`[abprops] server returned ${experiments.length} experiment prop(s), ${sampling.length} sampling entr(ies)\n`);

    const byCode = new Map(experiments.map(e => [e.code, e]));
    console.error('=== the props that decide whether we may ask for history ===');
    for (const code of HEADLINE) {
      const name = (KNOWN[code] || [`#${code}`])[0];
      const got = byCode.get(code);
      console.error(`  ${name.padEnd(52)} ${got ? String(got.value) : '(not returned — client default applies)'}`);
    }

    const gate = byCode.get(17198), base = byCode.get(3337);
    console.error('\n=== reading ===');
    if (!gate && !base) {
      console.error('  Neither history_sync_on_demand nor _companion came back, so the server is not');
      console.error('  overriding them and the client defaults stand: both are FALSE by default, and the');
      console.error('  companion one has a second default of TRUE. That the browser works while we do not');
      console.error('  is therefore NOT explained by these values — look elsewhere.');
    } else {
      const on = v => v && (v.value === 'true' || v.value === '1');
      console.error(`  history_sync_on_demand            = ${base ? base.value : '(default)'}`);
      console.error(`  history_sync_on_demand_companion  = ${gate ? gate.value : '(default)'}`);
      if (gate && !on(gate)) {
        console.error('  -> the companion gate is OFF for the client we just announced. Re-run with');
        console.error('     WA_VERSION set to the browser\'s build and compare: if it flips to true, the');
        console.error('     version we announce IS the root cause.');
      } else if (on(gate) || on(base)) {
        console.error('  -> the feature is ENABLED for this client, so eligibility is not the blocker.');
        console.error('     Stop investigating the gate; the silence is throttling, routing or the phone.');
      }
    }

    const unknown = experiments.filter(e => !e.known).length;
    console.error(`\n[abprops] ${unknown} returned prop(s) are outside this script's name table`
      + (JSON_OUT ? '' : ' — pass --json <file> to dump them all'));
    if (JSON_OUT) {
      fs.writeFileSync(JSON_OUT, JSON.stringify({
        announcedVersion: version.join('.'), versionSource: vsrc, device: inp.device,
        propsAttrs: attrs, experiments, sampling }, null, 1));
      console.error(`[abprops] full dump -> ${JSON_OUT}`);
    }
    done(0);
  });
})().catch(e => { console.error('[abprops] FATAL', e); process.exit(9); });
