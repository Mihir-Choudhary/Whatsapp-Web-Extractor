// Reference protobufs for scripts/selftest_binary.py: Baileys' own WAProto. Not part of the tool.
const { proto } = require('@whiskeysockets/baileys')
const req = { chatJid: '120363000000000000@g.us', oldestMsgId: '3EB0A1B2C3D4E5F60718AB', oldestMsgFromMe: false,
  onDemandMsgCount: 50, oldestMsgTimestampMs: 1783952047000 }
const m = proto.Message.encode({ protocolMessage: { type: 16, peerDataOperationRequestMessage: {
  peerDataOperationRequestType: 3, historySyncOnDemandRequest: req } } }).finish()
const hs = proto.HistorySync.encode({ syncType: 6, chunkOrder: 2, progress: 40, conversations: [{ id: '919000000001@s.whatsapp.net',
  endOfHistoryTransferType: 1, messages: [{ msgOrderId: 7, message: { key: { remoteJid: '919000000001@s.whatsapp.net', fromMe: true, id: 'ABC123' },
  messageTimestamp: 1783952047, pushName: 'Someone', message: { extendedTextMessage: { text: 'hello https://x.y', title: 'X' } } } },
  { message: { key: { remoteJid: '919000000001@s.whatsapp.net', fromMe: false, id: 'DEF456' }, messageTimestamp: 1783952050,
    message: { ephemeralMessage: { message: { imageMessage: { caption: 'a photo', mimetype: 'image/jpeg', mediaKey: Buffer.from([1,2,3]) } } } } } }] }],
  pushnames: [{ id: '919000000001@s.whatsapp.net', pushname: 'Someone' }] }).finish()
console.log(JSON.stringify({ req: Buffer.from(m).toString('hex'), hs: Buffer.from(hs).toString('hex') }))
