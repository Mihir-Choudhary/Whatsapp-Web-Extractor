"""wa_proto.py — the WhatsApp protobuf messages the history client sends and reads, without a protobuf
dependency.

Field numbers are taken from Baileys' WAProto.proto (6.7.24) and, for the one field Baileys lacks
(HistorySyncOnDemandRequest.supportInlineResponse = 7), from WhatsApp Web's own message specs — the same
source tools/reconnect/proto_patch.js cites. Unknown fields are kept (as raw (field, wire type, value)
triples under "_unknown") so a decoded record never silently loses data.

Schemas: {field number: (name, kind[, sub-schema])}; kind is one of
  s string, y bytes, b bool, u uint varint, i int64/int32 varint (two's complement), e enum, m message,
and a trailing "*" marks a repeated field.
"""
from __future__ import annotations

# ---------------------------------------------------------------- codec
def _varint(n):
    n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def _read_varint(b, i):
    r = s = 0
    while True:
        if i >= len(b): raise ValueError("truncated varint")
        c = b[i]; i += 1; r |= (c & 0x7F) << s
        if not c & 0x80: return r, i
        s += 7

def encode(obj: dict, schema: dict) -> bytes:
    by_name = {v[0]: (k, v) for k, v in schema.items()}
    out = bytearray()
    for name in sorted(obj, key=lambda n: by_name[n][0] if n in by_name else 1 << 30):
        if name == "_unknown" or obj[name] is None: continue
        if name not in by_name: raise KeyError(f"no field {name!r} in schema")
        f, spec = by_name[name]
        kind = spec[1].rstrip("*")
        values = obj[name] if spec[1].endswith("*") else [obj[name]]
        for v in values:
            if kind in ("u", "i", "e"):
                out += _varint(f << 3) + _varint(int(v))
            elif kind == "b":
                out += _varint(f << 3) + _varint(1 if v else 0)
            else:
                if kind == "s": v = v.encode("utf-8")
                elif kind == "m": v = encode(v, spec[2])
                out += _varint(f << 3 | 2) + _varint(len(v)) + bytes(v)
    return bytes(out)

def decode(buf: bytes, schema: dict) -> dict:
    out, unknown, i = {}, [], 0
    buf = bytes(buf)
    while i < len(buf):
        tag, i = _read_varint(buf, i)
        f, wt = tag >> 3, tag & 7
        if wt == 0: v, i = _read_varint(buf, i)
        elif wt == 2:
            n, i = _read_varint(buf, i)
            if i + n > len(buf): raise ValueError("truncated field %d" % f)
            v = buf[i:i + n]; i += n
        elif wt == 1: v = buf[i:i + 8]; i += 8
        elif wt == 5: v = buf[i:i + 4]; i += 4
        else: raise ValueError("wire type %d" % wt)
        spec = schema.get(f)
        if spec is None:
            unknown.append((f, wt, v)); continue
        name, kind = spec[0], spec[1].rstrip("*")
        if kind == "s": v = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
        elif kind == "b": v = bool(v)
        elif kind == "i" and v >= 1 << 63: v -= 1 << 64
        elif kind == "m": v = decode(v, spec[2])
        if spec[1].endswith("*"): out.setdefault(name, []).append(v)
        else: out[name] = v
    if unknown: out["_unknown"] = unknown
    return out


# ---------------------------------------------------------------- schemas
MESSAGE_KEY = {1: ("remoteJid", "s"), 2: ("fromMe", "b"), 3: ("id", "s"), 4: ("participant", "s")}

HISTORY_SYNC_ON_DEMAND_REQUEST = {1: ("chatJid", "s"), 2: ("oldestMsgId", "s"), 3: ("oldestMsgFromMe", "b"),
                                  4: ("onDemandMsgCount", "i"), 5: ("oldestMsgTimestampMs", "i"),
                                  6: ("accountLid", "s"), 7: ("supportInlineResponse", "b")}
PLACEHOLDER_RESEND_REQUEST = {1: ("messageKey", "m", MESSAGE_KEY)}
PDO_REQUEST = {1: ("peerDataOperationRequestType", "e"),
               4: ("historySyncOnDemandRequest", "m", HISTORY_SYNC_ON_DEMAND_REQUEST),
               5: ("placeholderMessageResendRequest", "m*", PLACEHOLDER_RESEND_REQUEST)}
PDO_RESULT = {4: ("placeholderMessageResendResponse", "m", {1: ("webMessageInfoBytes", "y")})}
PDO_RESPONSE = {1: ("peerDataOperationRequestType", "e"), 2: ("stanzaId", "s"),
                3: ("peerDataOperationResult", "m*", PDO_RESULT)}
HISTORY_SYNC_NOTIFICATION = {1: ("fileSha256", "y"), 2: ("fileLength", "u"), 3: ("mediaKey", "y"),
                             4: ("fileEncSha256", "y"), 5: ("directPath", "s"), 6: ("syncType", "e"),
                             7: ("chunkOrder", "u"), 8: ("originalMessageId", "s"), 9: ("progress", "u"),
                             10: ("oldestMsgInChunkTimestampSec", "i"), 11: ("initialHistBootstrapInlinePayload", "y"),
                             12: ("peerDataRequestSessionId", "s"), 14: ("encHandle", "s")}
PROTOCOL_MESSAGE = {1: ("key", "m", MESSAGE_KEY), 2: ("type", "e"), 6: ("historySyncNotification", "m", HISTORY_SYNC_NOTIFICATION),
                    15: ("timestampMs", "i"), 16: ("peerDataOperationRequestMessage", "m", PDO_REQUEST),
                    17: ("peerDataOperationRequestResponseMessage", "m", PDO_RESPONSE)}

# Message: the content fields named (for message types), with the few whose content is read here
MESSAGE: dict = {}
PROTOCOL_MESSAGE[14] = ("editedMessage", "m", MESSAGE)        # MESSAGE_EDIT carries the new message
DEVICE_SENT = {1: ("destinationJid", "s"), 2: ("message", "m", MESSAGE), 3: ("phash", "s")}
FUTURE_PROOF = {1: ("message", "m", MESSAGE)}
EXTENDED_TEXT = {1: ("text", "s"), 6: ("title", "s")}
CAPTIONED = {"imageMessage": {3: ("caption", "s"), 2: ("mimetype", "s")},
             "videoMessage": {7: ("caption", "s"), 2: ("mimetype", "s")},
             "documentMessage": {20: ("caption", "s"), 3: ("title", "s"), 8: ("fileName", "s"), 2: ("mimetype", "s")},
             "locationMessage": {3: ("name", "s")}, "contactMessage": {1: ("displayName", "s")},
             "reactionMessage": {1: ("key", "m", MESSAGE_KEY), 2: ("text", "s")}, "pollCreationMessage": {2: ("name", "s")}}
_MESSAGE_FIELDS = {1: 'conversation', 2: 'senderKeyDistributionMessage', 3: 'imageMessage', 4: 'contactMessage',
    5: 'locationMessage', 6: 'extendedTextMessage', 7: 'documentMessage', 8: 'audioMessage', 9: 'videoMessage',
    10: 'call', 11: 'chat', 12: 'protocolMessage', 13: 'contactsArrayMessage', 14: 'highlyStructuredMessage',
    15: 'fastRatchetKeySenderKeyDistributionMessage', 16: 'sendPaymentMessage', 18: 'liveLocationMessage',
    22: 'requestPaymentMessage', 23: 'declinePaymentRequestMessage', 24: 'cancelPaymentRequestMessage',
    25: 'templateMessage', 26: 'stickerMessage', 28: 'groupInviteMessage', 29: 'templateButtonReplyMessage',
    30: 'productMessage', 31: 'deviceSentMessage', 35: 'messageContextInfo', 36: 'listMessage',
    37: 'viewOnceMessage', 38: 'orderMessage', 39: 'listResponseMessage', 40: 'ephemeralMessage',
    41: 'invoiceMessage', 42: 'buttonsMessage', 43: 'buttonsResponseMessage', 44: 'paymentInviteMessage',
    45: 'interactiveMessage', 46: 'reactionMessage', 47: 'stickerSyncRmrMessage', 48: 'interactiveResponseMessage',
    49: 'pollCreationMessage', 50: 'pollUpdateMessage', 51: 'keepInChatMessage', 53: 'documentWithCaptionMessage',
    54: 'requestPhoneNumberMessage', 55: 'viewOnceMessageV2', 56: 'encReactionMessage', 58: 'editedMessage',
    59: 'viewOnceMessageV2Extension', 60: 'pollCreationMessageV2', 61: 'scheduledCallCreationMessage',
    62: 'groupMentionedMessage', 63: 'pinInChatMessage', 64: 'pollCreationMessageV3', 65: 'scheduledCallEditMessage',
    66: 'ptvMessage', 67: 'botInvokeMessage', 69: 'callLogMesssage', 70: 'messageHistoryBundle',
    71: 'encCommentMessage', 72: 'bcallMessage', 74: 'lottieStickerMessage', 75: 'eventMessage',
    76: 'encEventResponseMessage', 77: 'commentMessage', 78: 'newsletterAdminInviteMessage', 80: 'placeholderMessage',
    82: 'secretEncryptedMessage', 83: 'albumMessage', 85: 'eventCoverImage', 86: 'stickerPackMessage',
    87: 'statusMentionMessage', 88: 'pollResultSnapshotMessage', 90: 'pollCreationOptionImageMessage',
    91: 'associatedChildMessage', 92: 'groupStatusMentionMessage', 93: 'pollCreationMessageV4',
    94: 'pollCreationMessageV5', 95: 'statusAddYours', 96: 'groupStatusMessage', 97: 'richResponseMessage',
    98: 'statusNotificationMessage', 99: 'limitSharingMessage', 100: 'botTaskMessage', 101: 'questionMessage',
    102: 'messageHistoryNotice'}
_WRAPPERS = {"viewOnceMessage", "ephemeralMessage", "documentWithCaptionMessage", "viewOnceMessageV2",
             "editedMessage", "viewOnceMessageV2Extension", "groupMentionedMessage", "botInvokeMessage",
             "associatedChildMessage", "groupStatusMessage"}
for _f, _n in _MESSAGE_FIELDS.items():
    if _n == "conversation": MESSAGE[_f] = (_n, "s")
    elif _n == "extendedTextMessage": MESSAGE[_f] = (_n, "m", EXTENDED_TEXT)
    elif _n == "protocolMessage": MESSAGE[_f] = (_n, "m", PROTOCOL_MESSAGE)
    elif _n == "deviceSentMessage": MESSAGE[_f] = (_n, "m", DEVICE_SENT)
    elif _n == "senderKeyDistributionMessage": MESSAGE[_f] = (_n, "m", {1: ("groupId", "s"),
                                                                       2: ("axolotlSenderKeyDistributionMessage", "y")})
    elif _n in _WRAPPERS: MESSAGE[_f] = (_n, "m", FUTURE_PROOF)
    elif _n in CAPTIONED: MESSAGE[_f] = (_n, "m", CAPTIONED[_n])
    else: MESSAGE[_f] = (_n, "y")          # kept as raw bytes: present (so the type is known), content untouched

WEB_MESSAGE_INFO = {1: ("key", "m", MESSAGE_KEY), 2: ("message", "m", MESSAGE), 3: ("messageTimestamp", "u"),
                    4: ("status", "e"), 5: ("participant", "s"), 17: ("starred", "b"), 18: ("broadcast", "b"),
                    19: ("pushName", "s"), 24: ("messageStubType", "e"), 26: ("messageStubParameters", "s*")}
HISTORY_SYNC_MSG = {1: ("message", "m", WEB_MESSAGE_INFO), 2: ("msgOrderId", "u")}
CONVERSATION = {1: ("id", "s"), 2: ("messages", "m*", HISTORY_SYNC_MSG), 3: ("newJid", "s"), 4: ("oldJid", "s"),
                5: ("lastMsgTimestamp", "u"), 8: ("endOfHistoryTransfer", "b"), 11: ("endOfHistoryTransferType", "e"),
                13: ("name", "s"), 38: ("displayName", "s"), 39: ("pnJid", "s"), 42: ("lidJid", "s"),
                9: ("ephemeralExpiration", "u"), 16: ("archived", "b"), 24: ("pinned", "u"), 25: ("muteEndTime", "u"),
                33: ("description", "s"), 43: ("username", "s"),
                20: ("participant", "m*", {1: ("userJid", "s"), 2: ("rank", "e")})}
CALL_LOG_RECORD = {1: ("callResult", "e"), 4: ("duration", "i"), 5: ("startTime", "i"), 6: ("isIncoming", "b"),
                   7: ("isVideo", "b"), 8: ("isCallLink", "b"), 11: ("callId", "s"), 12: ("callCreatorJid", "s"),
                   13: ("groupJid", "s"), 14: ("participants", "m*", {1: ("userJid", "s"), 2: ("callResult", "e")}),
                   15: ("callType", "e")}
HISTORY_SYNC = {1: ("syncType", "e"), 2: ("conversations", "m*", CONVERSATION), 5: ("chunkOrder", "u"),
                6: ("progress", "u"), 7: ("pushnames", "m*", {1: ("id", "s"), 2: ("pushname", "s")}),
                15: ("phoneNumberToLidMappings", "m*", {1: ("pnJid", "s"), 2: ("lidJid", "s")}),
                3: ("statusV3Messages", "m*", WEB_MESSAGE_INFO),
                12: ("pastParticipants", "m*", {1: ("groupJid", "s"), 2: ("pastParticipants", "m*",
                                                {1: ("userJid", "s"), 2: ("leaveReason", "e"), 3: ("leaveTs", "u")})}),
                13: ("callLogRecords", "m*", CALL_LOG_RECORD)}
ADV_SIGNED_DEVICE_IDENTITY = {1: ("details", "y"), 2: ("accountSignatureKey", "y"), 3: ("accountSignature", "y"),
                              4: ("deviceSignature", "y")}

PROTOCOL_TYPE_PDO_REQUEST, PROTOCOL_TYPE_PDO_RESPONSE, PROTOCOL_TYPE_HISTORY_NOTIFICATION = 16, 17, 5
PDO_HISTORY_SYNC_ON_DEMAND, PDO_PLACEHOLDER_RESEND = 3, 4
HISTORY_SYNC_ON_DEMAND = 6


# ---------------------------------------------------------------- helpers
def history_request(chat_jid, oldest_id, oldest_from_me, count, oldest_ts):
    """Message bytes asking the phone for `count` messages of `chat_jid` older than the anchor -- exactly the
    fields WhatsApp Web's own request carries (no accountLid; the timestamp in MILLISECONDS)."""
    ts = int(oldest_ts); ts = ts if ts > 10 ** 12 else ts * 1000
    return encode({"protocolMessage": {
        "type": PROTOCOL_TYPE_PDO_REQUEST,
        "peerDataOperationRequestMessage": {
            "peerDataOperationRequestType": PDO_HISTORY_SYNC_ON_DEMAND,
            "historySyncOnDemandRequest": {"chatJid": chat_jid, "oldestMsgId": oldest_id,
                                           "oldestMsgFromMe": bool(oldest_from_me), "onDemandMsgCount": count,
                                           "oldestMsgTimestampMs": ts, "supportInlineResponse": True}}}}, MESSAGE)

def unwrap(msg: dict) -> dict:
    """The innermost Message, through device-sent / ephemeral / view-once / edited wrappers."""
    seen = 0
    while isinstance(msg, dict) and seen < 8:
        seen += 1
        if "deviceSentMessage" in msg and isinstance(msg["deviceSentMessage"].get("message"), dict):
            msg = msg["deviceSentMessage"]["message"]; continue
        w = next((k for k in _WRAPPERS if k in msg and isinstance(msg[k].get("message"), dict)), None)
        if w: msg = msg[w]["message"]; continue
        break
    return msg

def message_type(msg: dict) -> str:
    m = unwrap(msg or {})
    for k in m:
        if k not in ("messageContextInfo", "_unknown"): return k
    return "unknown"

def message_text(msg: dict) -> str:
    m = unwrap(msg or {})
    if m.get("conversation"): return m["conversation"]
    if m.get("extendedTextMessage"): return m["extendedTextMessage"].get("text") or ""
    for k in ("imageMessage", "videoMessage", "documentMessage"):
        if m.get(k): return m[k].get("caption") or ""
    if m.get("reactionMessage"): return m["reactionMessage"].get("text") or ""
    if m.get("pollCreationMessage"): return m["pollCreationMessage"].get("name") or ""
    if m.get("locationMessage"): return m["locationMessage"].get("name") or ""
    if m.get("contactMessage"): return m["contactMessage"].get("displayName") or ""
    return ""
