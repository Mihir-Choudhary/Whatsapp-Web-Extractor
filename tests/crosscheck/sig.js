// Reference party for scripts/selftest_signal.py: libsignal-node (the library Baileys uses), driven one
// operation per invocation, its whole state kept in a JSON file. Not part of the tool.
//   node sig.js STATE new                       -> prints {bundle}  (identity, signed prekey, one prekey)
//   node sig.js STATE bundle ADDR BUNDLE.json   -> start a session from the other side's bundle
//   node sig.js STATE encrypt ADDR B64          -> {type, body}
//   node sig.js STATE decrypt ADDR TYPE B64     -> {plaintext}
//   node sig.js STATE record ADDR               -> the session record as libsignal serialises it
//   node sig.js STATE setrecord ADDR REC.json   -> replace a session record (from the other implementation)
const fs = require('fs')
const libsignal = require('libsignal')
const [, , statePath, op, ...args] = process.argv
const b = s => Buffer.from(s, 'base64'), s = x => Buffer.from(x).toString('base64')
const load = () => fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : null
let st = load()
const save = () => fs.writeFileSync(statePath, JSON.stringify(st))
const kp = k => ({ pubKey: b(k.pubKey), privKey: b(k.privKey) })
const store = {
  getOurIdentity: async () => kp(st.identity),
  getOurRegistrationId: async () => st.registrationId,
  isTrustedIdentity: async () => true,
  loadSession: async a => st.sessions[a] ? libsignal.SessionRecord.deserialize(st.sessions[a]) : undefined,
  storeSession: async (a, r) => { st.sessions[a] = r.serialize() },
  loadPreKey: async id => st.preKeys[id] ? kp(st.preKeys[id]) : undefined,
  removePreKey: async id => { delete st.preKeys[id] },
  loadSignedPreKey: async id => st.signedPreKeys[id] ? kp(st.signedPreKeys[id]) : undefined,
}
const addr = a => libsignal.ProtocolAddress.from(a)
;(async () => {
  let out
  if (op === 'new') {
    const id = libsignal.curve.generateKeyPair(), spk = libsignal.curve.generateKeyPair(), pk = libsignal.curve.generateKeyPair()
    const sig = libsignal.curve.calculateSignature(id.privKey, spk.pubKey)
    st = { identity: { pubKey: s(id.pubKey), privKey: s(id.privKey) }, registrationId: 4242,
           signedPreKeys: { 7: { pubKey: s(spk.pubKey), privKey: s(spk.privKey) } },
           preKeys: { 31: { pubKey: s(pk.pubKey), privKey: s(pk.privKey) } }, sessions: {} }
    out = { identityKey: s(id.pubKey), registrationId: 4242,
            signedPreKey: { keyId: 7, publicKey: s(spk.pubKey), signature: s(sig) },
            preKey: { keyId: 31, publicKey: s(pk.pubKey) } }
  } else if (op === 'bundle') {
    const d = JSON.parse(fs.readFileSync(args[1], 'utf8'))
    await new libsignal.SessionBuilder(store, addr(args[0])).initOutgoing({
      identityKey: b(d.identityKey), registrationId: d.registrationId,
      signedPreKey: { keyId: d.signedPreKey.keyId, publicKey: b(d.signedPreKey.publicKey), signature: b(d.signedPreKey.signature) },
      preKey: d.preKey ? { keyId: d.preKey.keyId, publicKey: b(d.preKey.publicKey) } : undefined })
    out = { ok: true }
  } else if (op === 'encrypt') {
    const r = await new libsignal.SessionCipher(store, addr(args[0])).encrypt(b(args[1]))
    out = { type: r.type === 3 ? 'pkmsg' : 'msg', body: s(r.body) }
  } else if (op === 'decrypt') {
    const c = new libsignal.SessionCipher(store, addr(args[0]))
    const pt = args[1] === 'pkmsg' ? await c.decryptPreKeyWhisperMessage(b(args[2])) : await c.decryptWhisperMessage(b(args[2]))
    out = { plaintext: s(pt) }
  } else if (op === 'record') {
    out = st.sessions[args[0]]
  } else if (op === 'setrecord') {
    st.sessions[args[0]] = JSON.parse(fs.readFileSync(args[1], 'utf8')); out = { ok: true }
  }
  save()
  console.log(JSON.stringify(out))
})().catch(e => { console.error(String(e && e.stack || e)); process.exit(2) })
