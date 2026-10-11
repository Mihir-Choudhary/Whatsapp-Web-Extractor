// Reference encoder for scripts/selftest_binary.py: Baileys' own encodeBinaryNode. Not part of the tool.
const fs = require('fs')
const { encodeBinaryNode } = require('@whiskeysockets/baileys')
const fix = n => ({ tag: n.tag, attrs: n.attrs, content: n.content == null ? undefined :
  (typeof n.content === 'object' && n.content.b64 !== undefined) ? Buffer.from(n.content.b64, 'base64') :
  Array.isArray(n.content) ? n.content.map(fix) : n.content })
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
console.log(JSON.stringify(cases.map(c => Buffer.from(encodeBinaryNode(fix(c))).toString('hex'))))
