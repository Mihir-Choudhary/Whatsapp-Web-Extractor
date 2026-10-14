// Reference party for scripts/selftest_signal.py: Baileys' own group cipher (lib/Signal/Group) as the
// SENDER of a group. Not part of the tool.
//   node grp.mjs NODE_MODULES N [PLAINTEXTS.json]   -> {skdm, record, msgs:[{body, plaintext}]}
// PLAINTEXTS.json (optional): a list of base64 payloads to encrypt instead of generated text.
// Creates a sender key, prints its SenderKeyDistributionMessage, encrypts N messages and prints them
// with the plaintexts, so the Python receiver can be checked against what Baileys sends.
import path from 'path'
import { pathToFileURL } from 'url'
const [, , mods, nArg, ptFile] = process.argv
import fs from 'fs'
const given = ptFile ? JSON.parse(fs.readFileSync(ptFile, 'utf8')) : null
await import(pathToFileURL(path.join(mods, '@whiskeysockets', 'baileys', 'lib', 'index.js')).href)   // initialise the package first (circular imports)
const G = await import(pathToFileURL(path.join(mods, '@whiskeysockets', 'baileys', 'lib', 'Signal', 'Group', 'index.js')).href)
const records = {}
const store = {
  loadSenderKey: async n => records[n.toString()] || new G.SenderKeyRecord(),
  storeSenderKey: async (n, r) => { records[n.toString()] = r },
}
const name = new G.SenderKeyName('123456789-1@g.us', { id: '15550001111', deviceId: 0 })
const skdm = await new G.GroupSessionBuilder(store).create(name)
const cipher = new G.GroupCipher(store, name)
const s = x => Buffer.from(x).toString('base64')
const msgs = []
const count = given ? given.length : Number(nArg || 5)
for (let i = 0; i < count; i++) {
  const pt = given ? Buffer.from(given[i], 'base64') : Buffer.from(`group message ${i} ` + 'x'.repeat(i * 7))
  msgs.push({ body: s(await cipher.encrypt(pt)), plaintext: s(pt) })
}
const rec = records[name.toString()].serialize().map(st => JSON.parse(JSON.stringify(st, (k, v) =>
  v && v.type === 'Buffer' ? Buffer.from(v.data).toString('base64') : v)))
console.log(JSON.stringify({ skdm: s(skdm.serialize()), record: rec, msgs }))
