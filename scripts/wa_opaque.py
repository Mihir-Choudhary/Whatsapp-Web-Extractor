"""wa_opaque.py — decode a decrypted `msgRowOpaqueData` body by its schema.

WhatsApp Web stores a message's content in IndexedDB as `MsgRowOpaqueData`, a protobuf of its own
(not the wire `Message`), encrypted at rest. Its schema ships in WhatsApp Web's JavaScript, module
`WAWebProtobufsMdStorageMsgRowOpaqueData.pb`, and the field map below is transcribed from it:

    MsgRowOpaqueData { currentMsg = 1 : MsgOpaqueData, quotedMsg = 2 : MsgOpaqueData }

Reading fields by number is what separates a message's text from the link preview, location name,
poll options or event details that ride in the same record. A schema-free scrape of "every string"
cannot tell them apart and glues them together.

`decode_row()` returns None for a body that does not fit the schema -- including one carrying a
field this map does not know -- so callers fall back to a generic reader and lose nothing.
"""
from __future__ import annotations
import struct

# kind: s=string, y=bytes, d=double, b=bool, i=varint int, e=enum, m=message (with sub-map), *=repeated
_OPTION = {1: ("name", "s"), 2: ("hash", "s"), 3: ("addOptionMsgKey", "s")}
_ENCVAL = {1: ("encPayload", "y"), 2: ("encIv", "y")}
_EVLOC = {1: ("degreesLatitude", "d"), 2: ("degreesLongitude", "d"), 3: ("name", "s"), 4: ("address", "s"),
          5: ("url", "s"), 6: ("jpegThumbnail", "y")}
_VOTE = {1: ("option", "m", _OPTION), 2: ("optionVoteCount", "i")}
_VOTES = {1: ("pollVotes", "m*", _VOTE)}

MSG_OPAQUE_DATA = {
    1: ("body", "s"), 3: ("caption", "s"), 5: ("lng", "d"), 6: ("isLive", "b"), 7: ("lat", "d"),
    8: ("paymentAmount1000", "i"), 9: ("paymentNoteMsgBody", "s"), 11: ("matchedText", "s"),
    12: ("title", "s"), 13: ("description", "s"), 14: ("futureproofBuffer", "y"), 15: ("clientUrl", "s"),
    16: ("loc", "s"), 17: ("pollName", "s"), 18: ("pollOptions", "m*", _OPTION),
    20: ("pollSelectableOptionsCount", "i"), 21: ("messageSecret", "y"), 22: ("senderTimestampMs", "i"),
    23: ("pollUpdateParentKey", "s"), 24: ("encPollVote", "m", _ENCVAL),
    25: ("encReactionTargetMessageKey", "s"), 26: ("encReactionEncPayload", "y"), 27: ("encReactionEncIv", "y"),
    28: ("isSentCagPollCreation", "b"), 29: ("botMessageSecret", "y"), 30: ("targetMessageKey", "s"),
    31: ("encPayload", "y"), 32: ("encIv", "y"), 33: ("eventName", "s"), 34: ("isEventCanceled", "b"),
    35: ("eventDescription", "s"), 36: ("eventJoinLink", "s"), 37: ("eventStartTime", "i"),
    38: ("eventLocation", "m", _EVLOC), 40: ("eventEndTime", "i"), 41: ("pollVotesSnapshot", "m", _VOTES),
    42: ("pollContentType", "e"), 43: ("plainProtobufBytes", "y"), 44: ("eventIsScheduledCall", "b"),
    45: ("eventExtraGuestsAllowed", "b"), 46: ("pollType", "e"), 47: ("correctOptionIndex", "i"),
    48: ("quarantineExtractedText", "s"), 49: ("pollEndTime", "i"), 50: ("pollHideVoterNames", "b"),
    51: ("originalSelfAuthor", "s"), 52: ("pollAllowAddOption", "b"), 53: ("sharableEventInviteId", "s"),
    54: ("sharableEventInviteTitle", "s"), 55: ("sharableEventInviteStartTime", "i"),
    56: ("sharableEventInviteEndTime", "i"), 57: ("sharableEventInviteCaption", "s"),
    58: ("sharableEventInviteIsCanceled", "b"), 59: ("sharableEventInviteJpegThumbnail", "y"),
    60: ("sharableEventInviteCallLink", "s"), 61: ("mediaPngThumbnail", "s"), 62: ("qrUrl", "s"),
}
MSG_ROW_OPAQUE_DATA = {1: ("currentMsg", "m", MSG_OPAQUE_DATA), 2: ("quotedMsg", "m", MSG_OPAQUE_DATA)}

POLL_TYPE = {0: "POLL", 1: "QUIZ"}
POLL_CONTENT_TYPE = {0: "UNKNOWN", 1: "TEXT", 2: "IMAGE"}


class SchemaMismatch(ValueError):
    pass


def _varint(b, i):
    r = s = 0
    while True:
        if i >= len(b): raise SchemaMismatch("truncated varint")
        c = b[i]; i += 1
        r |= (c & 0x7F) << s
        if not c & 0x80: return r, i
        s += 7
        if s > 63: raise SchemaMismatch("varint too long")


def decode(buf: bytes, spec: dict) -> dict:
    """Decode `buf` against `spec`. Raises SchemaMismatch if the bytes do not fit it."""
    out, unknown, seen = {}, [], set()
    i, n = 0, len(buf)
    while i < n:
        tag, i = _varint(buf, i)
        f, wt = tag >> 3, tag & 7
        if f == 0: raise SchemaMismatch("field 0")
        if wt == 0:
            v, i = _varint(buf, i)
        elif wt == 1:
            if i + 8 > n: raise SchemaMismatch("truncated fixed64")
            v = buf[i:i + 8]; i += 8
        elif wt == 5:
            if i + 4 > n: raise SchemaMismatch("truncated fixed32")
            v = buf[i:i + 4]; i += 4
        elif wt == 2:
            ln, i = _varint(buf, i)
            if i + ln > n: raise SchemaMismatch("truncated length-delimited")
            v = buf[i:i + ln]; i += ln
        else:
            raise SchemaMismatch(f"wire type {wt}")
        if f not in spec:
            unknown.append(f); continue
        name, kind = spec[f][0], spec[f][1]
        if kind == "m" and f in seen:
            # protobuf would MERGE a repeated singular message and lose the first copy's values
            raise SchemaMismatch(f"field {f} ({name}) occurs twice")
        seen.add(f)
        want = {"s": 2, "y": 2, "m": 2, "m*": 2, "d": 1, "b": 0, "i": 0, "e": 0}[kind]
        if wt != want:
            raise SchemaMismatch(f"field {f} ({name}) has wire type {wt}, schema says {want}")
        if kind == "s":
            try: v = v.decode("utf-8")
            except UnicodeDecodeError: raise SchemaMismatch(f"field {f} ({name}) is not UTF-8")
        elif kind == "d":
            v = struct.unpack("<d", v)[0]
        elif kind == "b":
            v = bool(v)
        elif kind == "i" and v >= 1 << 63:
            v -= 1 << 64                                  # int64 two's complement
        elif kind in ("m", "m*"):
            v = decode(v, spec[f][2])
        if kind == "m*":
            out.setdefault(name, []).append(v)
        else:
            out[name] = v                                 # last one wins, as protobuf specifies
    if unknown:
        out["_unknown"] = sorted(set(unknown))
    return out


def decode_row(pt: bytes):
    """-> (currentMsg dict, quotedMsg dict or None), or None if `pt` is not a MsgRowOpaqueData."""
    if not pt: return None
    try:
        row = decode(pt, MSG_ROW_OPAQUE_DATA)
    except SchemaMismatch:
        return None
    if "_unknown" in row or "currentMsg" not in row and "quotedMsg" not in row:
        return None
    # A field this map does not know may hold text. Rather than drop it, let the caller use its
    # schema-free reader, which keeps every string.
    if any(isinstance(row.get(k), dict) and "_unknown" in row[k] for k in ("currentMsg", "quotedMsg")):
        return None
    return row.get("currentMsg") or {}, row.get("quotedMsg")


def details(msg: dict | None) -> dict:
    """The structured, non-text parts of one MsgOpaqueData, in export-friendly shape (empty parts omitted)."""
    if not msg: return {}
    d = {}
    if any(msg.get(k) for k in ("matchedText", "title", "description", "clientUrl")):
        d["link"] = {k: msg.get(src) for k, src in (("url", "matchedText"), ("title", "title"),
                                                     ("description", "description"), ("client_url", "clientUrl"))
                     if msg.get(src)}
    if "lat" in msg or "lng" in msg:
        d["location"] = {"lat": msg.get("lat"), "lng": msg.get("lng"), "name": msg.get("loc"),
                         "live": msg.get("isLive")}
    if msg.get("pollName") or msg.get("pollOptions"):
        d["poll"] = {"name": msg.get("pollName"),
                     "options": [o.get("name") for o in msg.get("pollOptions", [])],
                     "selectable": msg.get("pollSelectableOptionsCount"),
                     "type": POLL_TYPE.get(msg.get("pollType")),
                     "end_time": msg.get("pollEndTime")}
        if msg.get("pollVotesSnapshot"):
            d["poll"]["votes"] = [{"option": (v.get("option") or {}).get("name"), "count": v.get("optionVoteCount")}
                                  for v in msg["pollVotesSnapshot"].get("pollVotes", [])]
    if msg.get("eventName") or msg.get("eventStartTime"):
        loc = msg.get("eventLocation") or {}
        d["event"] = {"name": msg.get("eventName"), "description": msg.get("eventDescription"),
                      "start": msg.get("eventStartTime"), "end": msg.get("eventEndTime"),
                      "join_link": msg.get("eventJoinLink"), "canceled": msg.get("isEventCanceled"),
                      "location": {k: loc.get(k) for k in ("name", "address", "degreesLatitude", "degreesLongitude")
                                   if loc.get(k) is not None} or None}
    if msg.get("paymentAmount1000") is not None or msg.get("paymentNoteMsgBody"):
        d["payment"] = {"amount_1000": msg.get("paymentAmount1000"), "note": msg.get("paymentNoteMsgBody")}
    if msg.get("targetMessageKey"):
        d["target_message_key"] = msg["targetMessageKey"]
    if msg.get("_unknown"):
        d["unknown_fields"] = msg["_unknown"]
    return d
