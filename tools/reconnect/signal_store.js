// signal_store.js -- Baileys auth state for a recovered companion device: the Signal material read
// out of the browser profile, plus a runtime overlay that PERSISTS what this tool learns.
//
// Two problems this solves.
//
// 1. Nothing inbound could be decrypted. Baileys asks the key store for four key types; only
//    'pre-key' was served and everything else came from an empty map. Every inbound payload is
//    encrypted to an existing Double Ratchet session, so with no session store libsignal threw
//    SessionError and the message -- including the historySyncNotification the phone returns for
//    an on-demand history request -- was dropped before it could be processed.
//
//      'session'     <- signal_state.sessions[<user>.<device>]   (SessionRecord.serialize() shape)
//      'sender-key'  <- signal_state.senderKeys[<group>::<user>::<device>]
//      'pre-key'     <- signal_state.preKeys[<id>]
//
//    Byte encoding differs per type, which is why sender keys cannot be passed straight through:
//    libsignal's SessionEntry.deserialize() does Buffer.from(x, 'base64') itself, but Baileys'
//    SenderChainKey constructor does Buffer.from(seed) -- handing it a base64 STRING there would
//    silently store the UTF-8 bytes of the base64 text as the chain key. So sender keys are
//    decoded here and sessions are left as base64.
//
// 2. Every run threw its state away. A Double Ratchet advances: the moment we decrypt or send,
//    our session no longer matches the copy in the profile, and the phone's copy has moved too.
//    When a payload cannot be decrypted Baileys asks the sender to retry, and WhatsApp answers a
//    retry by REBUILDING the session from our prekeys -- so the first run of a recovered device
//    usually fails on a backlog and then gets a fresh session. Keeping that only in memory meant
//    the next run went back to the stale profile copy and failed the same way forever, each run
//    leaving the phone on yet another ratchet we had no record of.
//
//    So everything Baileys writes back (new/advanced sessions, sender keys, consumed prekeys,
//    app-state keys) and the mutable half of `creds` are persisted next to the recovered state and
//    reloaded on the next run, with the browser profile acting only as the initial seed.
//
// The profile itself is never written to: the overlay is a separate file, and it always shadows
// the recovered values.
'use strict';

const fs = require('fs');
const path = require('path');

const bb = b => Buffer.from(b, 'base64');
const RUNTIME_VERSION = 1;

function decodeSenderKeys(raw) {
  const out = {};
  for (const [name, states] of Object.entries(raw || {})) {
    if (!Array.isArray(states) || !states.length) continue;
    out[name] = states.map(st => {
      const signing = { public: bb(st.senderSigningKey.public) };
      if (st.senderSigningKey.private) signing.private = bb(st.senderSigningKey.private);
      return {
        senderKeyId: st.senderKeyId,
        senderChainKey: { iteration: st.senderChainKey.iteration, seed: bb(st.senderChainKey.seed) },
        senderSigningKey: signing,
        senderMessageKeys: [],
      };
    });
  }
  return out;
}

// creds fields that describe WHICH device we are. They come from the profile and must never be
// taken from the overlay, so a re-pair in the browser cannot be papered over by a stale file.
const IDENTITY_FIELDS = new Set([
  'noiseKey', 'signedIdentityKey', 'registrationId', 'me', 'account', 'platform', 'registered',
  'advSecretKey', 'signalIdentities',
  // the browser owns the signed prekey: whatever it last published is what peers will reference
  'signedPreKey',
]);

/**
 * open({ signalState, creds, statePath, bufferJSON }) -> { keys, creds, stats, save, flush }
 *
 *   signalState  parsed signal_state.json (sessions / senderKeys / preKeys)
 *   creds        the creds assembled from the profile; mutated in place with the overlay's values
 *   statePath    where the runtime overlay lives; omit to run without persistence
 *   bufferJSON   Baileys' BufferJSON { replacer, reviver } (Buffers do not survive plain JSON)
 */
function open({ signalState, creds, statePath, bufferJSON, appStateKeys }) {
  const S = signalState || {};
  // App-state sync keys, recovered by scripts/export_appstate_keys.py. Without these Baileys cannot
  // resyncAppState, which is the SyncD handshake a live WhatsApp Web session performs on EVERY
  // connect. Skipping it is why on-demand history only worked while the browser's own sync was
  // still fresh: the primary stopped treating this companion as in sync, and stopped serving.
  const appKeys = {};
  for (const [kid, v] of Object.entries(appStateKeys || {})) {
    appKeys[kid] = { keyData: bb(v.keyData), fingerprint: v.fingerprint, timestamp: v.timestamp };
  }
  const preKeys = S.preKeys || {};
  const sessions = S.sessions || {};
  const senderKeys = decodeSenderKeys(S.senderKeys);

  // Mint new one-time prekeys ABOVE the ids already in the profile. initAuthCreds() starts the
  // counter at 1, and the browser's own prekeys occupy 1..N, so a prekey we generate for a retry
  // receipt would be stored under an id that already belongs to a different key and shadow it --
  // after which any peer still holding the browser's key with that id gets a PreKeyError.
  const maxPreKeyId = Object.keys(preKeys).reduce((m, k) => Math.max(m, Number(k) || 0), 0);
  if (maxPreKeyId && (creds.nextPreKeyId || 0) <= maxPreKeyId) {
    creds.nextPreKeyId = maxPreKeyId + 1;
    creds.firstUnuploadedPreKeyId = maxPreKeyId + 1;
  }

  let mem = {};                       // "<type>-<id>" -> value ; shadows the recovered state
  let carried = 0, reason = 'no previous state';
  // This file is NOT a cache. It holds the only copy of every key this tool has minted -- prekeys we
  // published to the server that peers are now encrypting to, and ratchet state the phone has
  // already moved past. Lose it and those payloads become permanently unreadable: observed directly,
  // moving it aside produced "Invalid PreKey ID" on 8 inbound PreKeyWhisperMessages that decrypted
  // again the moment it was restored. So keep a rolling backup and fall back to it.
  const bakPath = statePath ? statePath + '.bak' : null;
  let readFrom = null;
  if (statePath && fs.existsSync(statePath)) readFrom = statePath;
  else if (bakPath && fs.existsSync(bakPath)) {
    readFrom = bakPath;
    console.error('[!] ' + statePath + ' is missing; falling back to the .bak copy. That file is KEY '
      + 'MATERIAL, not a cache -- losing both makes anything encrypted to its keys unrecoverable.');
  }
  if (readFrom) {
    try {
      const saved = JSON.parse(fs.readFileSync(readFrom, 'utf8'), bufferJSON && bufferJSON.reviver);
      const sameDevice = saved.registrationId === creds.registrationId
        && saved.meId === (creds.me && creds.me.id);
      if (saved.version !== RUNTIME_VERSION) reason = `state file version ${saved.version} != ${RUNTIME_VERSION}`;
      else if (!sameDevice) reason = 'state file belongs to a different device (re-paired?)';
      else {
        mem = saved.keys || {};
        carried = Object.keys(mem).length;
        for (const [k, v] of Object.entries(saved.creds || {})) {
          if (!IDENTITY_FIELDS.has(k)) creds[k] = v;     // keep identity from the profile
        }
        reason = 'loaded';
      }
    } catch (e) {
      reason = 'unreadable (' + e.message + ')';
    }
    if (reason !== 'loaded') console.error(`[!] runtime state ignored: ${reason} -- starting from the profile copy`);
  }

  let timer = null, dirty = false, rotated = false;
  function flush() {
    if (!statePath || !dirty) return;
    dirty = false;
    const body = JSON.stringify(
      { version: RUNTIME_VERSION, registrationId: creds.registrationId, meId: creds.me && creds.me.id,
        savedUtc: new Date().toISOString(), creds, keys: mem },
      bufferJSON && bufferJSON.replacer);
    const tmp = statePath + '.tmp';
    try {
      if (!rotated) {                       // keep the state this run STARTED from, once per run
        rotated = true;
        try { if (fs.existsSync(statePath)) fs.copyFileSync(statePath, bakPath); } catch (e) {}
      }
      fs.writeFileSync(tmp, body);
      fs.renameSync(tmp, statePath);        // atomic: a crash mid-write cannot truncate the state
    } catch (e) {
      console.error('[!] could not persist runtime state:', e.message);
    }
  }
  function save() {
    if (!statePath) return;
    dirty = true;
    if (timer) return;
    timer = setTimeout(() => { timer = null; flush(); }, 300);
    if (timer.unref) timer.unref();
  }
  if (statePath) process.on('exit', flush);

  const keys = {
    get: (t, ids) => {
      const d = {};
      for (const id of ids) {
        const k = mem[`${t}-${id}`];
        if (k !== undefined) { if (k !== null) d[id] = k; continue; }
        if (t === 'pre-key') {
          const p = preKeys[String(id)];
          if (p) d[id] = { private: bb(p.private), public: bb(p.public) };
        } else if (t === 'session') {
          const s = sessions[id];
          if (s) d[id] = s;                  // deserialize() copies into Buffers; not mutated
        } else if (t === 'sender-key') {
          const s = senderKeys[id];
          if (s) d[id] = s;
        } else if (t === 'app-state-sync-key') {
          const k = appKeys[id];
          if (k) d[id] = k;
        }
      }
      return d;
    },
    set: data => {
      for (const t in data) for (const id in data[t]) mem[`${t}-${id}`] = data[t][id];
      save();
    },
  };

  return {
    keys, creds, save, flush,
    stats: {
      sessions: Object.keys(sessions).length,
      senderKeys: Object.keys(senderKeys).length,
      preKeys: Object.keys(preKeys).length,
      appStateKeys: Object.keys(appKeys).length,
      carried,                                 // key records restored from the previous run
      state: reason,
    },
  };
}

/** Default location of the runtime overlay, beside the recovered signal_state.json. */
function defaultStatePath(dir) { return path.join(dir, 'signal_runtime.json'); }

module.exports = { open, defaultStatePath };
