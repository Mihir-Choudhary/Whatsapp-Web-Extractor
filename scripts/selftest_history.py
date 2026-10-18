#!/usr/bin/env python3
"""selftest_history.py — folding messages the phone served into an export of the local store.

The two sides describe a message differently, and every difference is a way for the merge to go
wrong silently:

  * the phone returns the STANZA id; the store uses a composite `false_<chat>_<stanza>` — so dedup
    has to compare stanzas, or every recovered message looks new and the export doubles;
  * the phone returns the WIRE jid for a chat (`@s.whatsapp.net`) where the store may have filed it
    under `@lid` — so a chat has to be mapped through the identity, or one conversation splits in two;
  * the phone returns the protobuf field name (`stickerMessage`) where the store says `sticker`;
  * in a group the sender is `key.participant`, which the extractor did not use to capture at all.

Run:  python3 scripts/selftest_history.py        (exit 0 = all cases pass)
"""
import os, sys, json, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# This prints message text and contact names, which include emoji. On a Windows console that is
# cp1252 by default -- which is what CI runs -- printing one raises UnicodeEncodeError and the suite
# dies mid-run with a traceback instead of a result.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

from wa_decrypt import (Identities, canon_jid, hist_type, stanza_of, hist_row, merge_history,
                        bank_history, msg_row, write_transcripts)

FAIL = []
def check(name, got, want):
    if got == want: print("  ok   %s: %r" % (name, got))
    else: FAIL.append(name); print("  FAIL %s: got %r want %r" % (name, got, want))

def ts(v):
    try:
        v = float(v); v = v / 1000 if v > 1e12 else v
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

def _vi(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def pb(*strings):
    body = b""
    for i, v in enumerate(strings, start=1):
        b = v.encode(); body += bytes([i << 3 | 2]) + _vi(len(b)) + b
    return bytes([0x0a]) + _vi(len(body)) + body

LS = {"last-wid-md": json.dumps("919000000001:44@c.us"), "WALid": json.dumps("133400000001:44@lid")}
STORES = {"contact": [
    {"id": "965000000001@lid", "phoneNumber": "919500000002@c.us", "name": "Priya Desk"},
    {"id": "133400000001@lid", "phoneNumber": "919000000001@c.us", "pushname": "Riya"},
    {"id": "888800000003@lid", "phoneNumber": "919900000003@c.us", "pushname": "Nikhil"}],
    "group-metadata": [{"id": "120300000009@g.us", "subject": "Weekend plans"}]}
IDS = Identities(STORES, LS)

print("the phone's vocabulary maps onto the store's")
check("conversation is a chat message", hist_type("conversation"), "chat")
check("extendedTextMessage is a chat message", hist_type("extendedTextMessage"), "chat")
check("stickerMessage is a sticker", hist_type("stickerMessage"), "sticker")
check("an unmapped xMessage drops the suffix", hist_type("albumMessage"), "album")
check("something else is passed through lowercased", hist_type("Weird"), "weird")
check("nothing becomes unknown", hist_type(""), "unknown")
check("no message payload ('?', a stub) is a system event", hist_type("?"), "notification")

print("\nthe id the two sides share is the stanza")
check("a stored composite yields its stanza", stanza_of("false_120300000009@g.us_ABC123"), "ABC123")
check("a composite with a sender suffix still yields the stanza",
      stanza_of("true_120300000009@g.us_ABC123_919000000001@c.us"), "ABC123")
check("a bare stanza is itself", stanza_of("ABC123"), "ABC123")
check("nothing is empty", stanza_of(None), "")

print("\na recovered message says who sent it")
grp = hist_row({"chat": "120300000009@g.us", "id": "S1", "fromMe": False,
                "participant": "965000000001@lid", "ts": 1760000000, "text": "hi all",
                "type": "conversation"}, IDS, ts(1760000000))
check("group sender comes from participant", grp["sender"], "965000000001@lid")
check("...and resolves to a name", grp["sender_name"], "Priya Desk")
check("the chat is named", grp["chat_name"], "Weekend plans")
check("marked as served by the phone", grp["source"], "phone")
check("direction is theirs", grp["dir"], "them")
check("type is the store's word", grp["type"], "chat")
check("the id is the store's shape", grp["id"], "false_120300000009@g.us_S1")

one = hist_row({"chat": "965000000001@lid", "id": "S2", "fromMe": False, "participant": None,
                "ts": 1760000001, "text": "just you and me", "type": "conversation"},
               IDS, ts(1760000001))
check("in a 1:1 the sender is the chat", one["sender"], "965000000001@lid")
check("...named", one["sender_name"], "Priya Desk")

mine = hist_row({"chat": "965000000001@lid", "id": "S3", "fromMe": True, "participant": None,
                 "ts": 1760000002, "text": "mine", "type": "conversation"}, IDS, ts(1760000002))
check("my own recovered message is mine", mine["dir"], "me")
check("...and attributed to me", IDS.is_me(mine["sender"]), True)
spaced = hist_row({"chat": "965000000001@lid", "id": "S3b", "fromMe": False, "participant": None,
                   "ts": 1760000003, "text": "  indented reply\n\n", "type": "conversation"},
                  IDS, ts(1760000003))
check("recovered text is kept exactly as sent, whitespace included", spaced["text"], "  indented reply\n\n")

noone = hist_row({"chat": "120300000009@g.us", "id": "S4", "fromMe": False, "participant": None,
                  "ts": 1760000003, "text": "?", "type": "conversation"}, IDS, ts(1760000003))
check("a group message with no participant does not invent a sender", noone["sender"], None)
check("...and says so rather than guessing", noone["sender_name"], "(unknown)")

# The phone also sends `pushName`, the name the sender chose for themselves. When their jid is
# missing, or is one the profile cannot name, that is the only identification there is -- and it
# beats printing "(unknown)" or a bare number.
named = hist_row({"chat": "120300000009@g.us", "id": "S5", "fromMe": False, "participant": None,
                  "pushName": "Dev", "ts": 1760000005, "text": "hi", "type": "conversation"},
                 IDS, ts(1760000005))
check("a nameless sender is labelled by the name they gave", named["sender_name"], "Dev")
check("...with the provenance of that name", named["sender_source"], "history-pushname")
check("...and no jid is invented for them", named["sender"], None)

stranger = hist_row({"chat": "120300000009@g.us", "id": "S6", "fromMe": False,
                     "participant": "999900009999@lid", "pushName": "Sam",
                     "ts": 1760000006, "text": "hi", "type": "conversation"}, IDS, ts(1760000006))
check("a jid the profile cannot name falls back to the name they gave",
      stranger["sender_name"], "Sam")
check("...and keeps the jid, which is real", stranger["sender"], "999900009999@lid")
known = hist_row({"chat": "120300000009@g.us", "id": "S7", "fromMe": False,
                  "participant": "965000000001@lid", "pushName": "Whatever They Typed",
                  "ts": 1760000007, "text": "hi", "type": "conversation"}, IDS, ts(1760000007))
check("the address book still wins over a self-chosen name", known["sender_name"], "Priya Desk")

print("\nthe merge")
def local():
    """An export of the local store: one group chat and one 1:1, filed under the forms it uses."""
    rows = {}
    rows["120300000009@g.us"] = [
        msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 1760000100,
                 "sender": "965000000001@lid", "id": "false_120300000009@g.us_CACHED1"},
                ts(1760000100), pb("already here"), IDS)]
    rows["965000000001@lid"] = [
        msg_row({"chat": "965000000001@lid", "from_me": False, "type": "chat", "t": 1760000200,
                 "sender": "965000000001@lid", "id": "false_965000000001@lid_CACHED2"},
                ts(1760000200), pb("also already here"), IDS)]
    return rows

REC = [
    # older than the cache, in the group -- should be added
    {"chat": "120300000009@g.us", "id": "NEW1", "fromMe": False, "participant": "888800000003@lid",
     "ts": 1759000000, "text": "older group message", "type": "conversation"},
    # the SAME message the cache already has, returned by the phone as a stanza -- must not double
    {"chat": "120300000009@g.us", "id": "CACHED1", "fromMe": False,
     "participant": "965000000001@lid", "ts": 1760000100, "text": "already here",
     "type": "conversation"},
    # the 1:1 chat, but in the WIRE form of the phone number rather than the lid the store used
    {"chat": "919500000002@s.whatsapp.net", "id": "NEW2", "fromMe": False, "participant": None,
     "ts": 1759000001, "text": "older direct message", "type": "conversation"},
    # a chat the local store does not have at all
    {"chat": "777700000008@g.us", "id": "NEW3", "fromMe": False, "participant": "888800000003@lid",
     "ts": 1759000002, "text": "from a chat not in the cache", "type": "stickerMessage"},
    # junk the phone should never send, but must not crash the merge
    {"chat": None, "id": "NOPE", "fromMe": False, "ts": 0, "text": "", "type": "?"},
    {"chat": "120300000009@g.us", "id": "", "fromMe": False, "ts": 0, "text": "", "type": "?"},
]

rows = local()
added, skipped, touched = merge_history(rows, REC, IDS, ts)
check("new messages added", added, 3)
check("the one the cache already had was skipped", skipped, 1)
check("no duplicate of the cached message",
      len([m for m in rows["120300000009@g.us"] if stanza_of(m["id"]) == "CACHED1"]), 1)
check("the wire-form chat folded into the lid chat the store used",
      len(rows["965000000001@lid"]), 2)
check("...and did not create a second chat for the same person",
      "919500000002@c.us" in rows, False)
check("a chat the cache lacks is created", "777700000008@g.us" in rows, True)
check("malformed records are ignored", sum(len(v) for v in rows.values()), 5)
check("the group chat is in time order",
      [m["t"] for m in rows["120300000009@g.us"]],
      sorted(m["t"] for m in rows["120300000009@g.us"]))
check("the recovered message sorts BEFORE the cached one it predates",
      rows["120300000009@g.us"][0]["text"], "older group message")
check("cached rows still say cache", rows["965000000001@lid"][1]["source"], "cache")
check("recovered rows say phone", rows["965000000001@lid"][0]["source"], "phone")
check("a recovered row carries the same fields as a cached one",
      sorted(rows["120300000009@g.us"][0]), sorted(rows["120300000009@g.us"][1]))

print("\nmerging twice does not grow the export")
again = merge_history(rows, REC, IDS, ts)
check("nothing added the second time", again[0], 0)
check("everything recognised as already present", again[1], 4)
check("total unchanged", sum(len(v) for v in rows.values()), 5)

print("\nbanking a pass: new messages added, banked ones enriched")
# A run that banked a message before the extractor captured the group sender must be able to GAIN
# one when a later pull serves the same message again. "First copy wins" made that impossible.
ledger = {"S1": {"id": "S1", "chat": "120300000009@g.us", "fromMe": False, "ts": 1759000000,
                 "text": "older group message", "type": "conversation"}}          # no participant
served = [{"id": "S1", "chat": "120300000009@g.us", "fromMe": False, "ts": 1759000000,
           "text": "older group message", "type": "conversation",
           "participant": "888800000003@lid", "pushName": "Nikhil"},               # same msg, richer
          {"id": "S2", "chat": "120300000009@g.us", "fromMe": False, "ts": 1759000001,
           "text": "brand new", "type": "conversation", "participant": "965000000001@lid"}]
new_n, enriched_n = bank_history(ledger, served)
check("the genuinely new message is added", new_n, 1)
check("the banked one is counted as enriched, not as new", enriched_n, 1)
check("...and it now has the sender it lacked", ledger["S1"]["participant"], "888800000003@lid")
check("...and the name that came with it", ledger["S1"]["pushName"], "Nikhil")
check("a field the banked copy already had is NOT overwritten",
      ledger["S1"]["text"], "older group message")
check("banking the same pass twice changes nothing", bank_history(ledger, served), (0, 0))
check("fromMe=False is not mistaken for a missing value",
      bank_history({"S3": {"id": "S3", "fromMe": False}}, [{"id": "S3", "fromMe": True}]), (0, 0))
check("a record with no id is ignored", bank_history({}, [{"chat": "x@g.us"}]), (0, 0))

print("\nthe merged export still writes a transcript")
import tempfile
p = os.path.join(tempfile.mkdtemp(), "t.txt")
write_transcripts(p, rows, IDS)
txt = open(p, encoding="utf-8").read()
check("every merged message has a line",
      len([l for l in txt.split("\n") if l.startswith("[")]), 5)
check("a recovered group message names its sender", "Nikhil" in txt, True)
check("the sticker from a cache-less chat is shown as its type", "(sticker)" in txt, True)

# A group message recovered before the extractor captured key.participant has no author. The line
# says "(unknown)", so the legend has to as well -- otherwise the file contradicts its own promise
# that every line's sender is listed above it.
rows2 = {"120300000009@g.us": [hist_row(
    {"chat": "120300000009@g.us", "id": "S9", "fromMe": False, "participant": None,
     "ts": 1759000009, "text": "who said this", "type": "conversation"}, IDS, ts(1759000009))]}
p2 = os.path.join(tempfile.mkdtemp(), "u.txt")
write_transcripts(p2, rows2, IDS)
ut = open(p2, encoding="utf-8").read()
legend = [l[4:].split("  ")[0].strip() for l in ut.split("\n") if l.startswith("  - ")]
lines = [l.split("] ", 1)[1].split(": ", 1)[0].strip()[3:].strip()
         for l in ut.split("\n") if l.startswith("[")]
check("the line names an unknown sender", lines, ["(unknown)"])
check("...and the legend lists it", legend, ["(unknown)"])
check("...saying the message carried no sender", "(no sender recorded in the message)" in ut, True)

print("\na receipt-only row is replaced by the message the phone serves")
# The store held only a receipt for these (an id and its ack): the phone's copy is the message itself,
# so it must be added -- not skipped as "already present" -- and the receipt row it stood in for goes.
from wa_decrypt import bodyless_row, _norm_msg
rows = local()
rows["120300000009@g.us"].insert(0, bodyless_row(_norm_msg({"id": "false_120300000009@g.us_RCPTA", "ack": 2}), "", IDS, "none"))
rows["555500000098@g.us"] = [bodyless_row(_norm_msg({"id": "false_555500000098@g.us_RCPTB", "ack": 2}), "", IDS, "none")]
REC2 = [{"chat": "120300000009@g.us", "id": "RCPTA", "fromMe": False, "participant": "965000000001@lid",
         "ts": 1759500000, "text": "the message itself", "type": "conversation"},
        {"chat": "555500000099@g.us", "id": "RCPTB", "fromMe": False, "participant": "965000000001@lid",
         "ts": 1759500001, "text": "filed under another chat", "type": "conversation"}]
added, skipped, touched = merge_history(rows, REC2, IDS, ts)
grp = rows["120300000009@g.us"]
check("the phone's copies are added, not skipped as already present", (added, skipped), (2, 0))
check("...the receipt row is gone and the message is there with its text",
      [(m.get("body_status"), m["text"]) for m in grp if stanza_of(m["id"]) == "RCPTA"], [(None, "the message itself")])
check("a chat left holding nothing is removed, not kept as an empty list", "555500000098@g.us" in rows, False)

print()
if FAIL:
    print("%d CASE(S) FAILED" % len(FAIL))
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all history-merge cases pass")
