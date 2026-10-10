#!/usr/bin/env python3
"""selftest_identities.py — the identity resolver, against synthetic records of the real shape.

`Identities` decides whose name goes on a message, so a quiet mistake here mislabels evidence rather
than failing loudly. The cases below are the ones that cost real coverage when they were wrong:

  * the SAME PERSON has two contact records, one keyed `@lid` and one keyed `@s.whatsapp.net`, and the
    address-book name can be on either — if they are not merged, the name is found only half the time;
  * `@c.us` and `@s.whatsapp.net` are one address space (UI form vs wire form) and a `:device` suffix
    identifies a device, not a person — a message addressed one way must find a contact stored the
    other way;
  * my own lid and my own phone number must resolve to ONE identity, or my outgoing messages get two
    different names inside a single transcript;
  * a label is NEVER invented: with nothing known, the jid is returned unchanged, so "unidentified"
    stays visibly different from "identified".

Run:  python3 scripts/selftest_identities.py       (exit 0 = all cases pass)
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wa_decrypt import (Identities, canon_jid, msg_row, write_transcripts, message_text,
                        quoted_text, split_body)

FAIL = []
# These tests print message text and contact names, which include emoji. On a Windows console that
# is cp1252 by default -- which is what CI runs -- printing one raises UnicodeEncodeError and the
# suite dies mid-run with a traceback instead of a result.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass


# A decrypted body is {1: this message, 2: the message it replies to}. Inside a message, field 1 is
# `conversation`; a bare jid anywhere in the tree is addressing metadata.
def _vi(n):
    """A protobuf varint, so a fixture string may be any length (a 1-byte length caps it at 127)."""
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def fields(*pairs):
    out = b""
    for f, v in pairs:
        b = v.encode(); out += bytes([f << 3 | 2]) + _vi(len(b)) + b
    return out

def msg(*strings):
    return fields(*[(i, v) for i, v in enumerate(strings, start=1)])

def pb(*strings, quoted=None):
    """A body: own content, optionally with a quoted message beside it."""
    m = msg(*strings)
    out = bytes([0x0a]) + _vi(len(m)) + m
    if quoted is not None:
        q = msg(quoted); out += bytes([0x12]) + _vi(len(q)) + q
    return out

def check(name, got, want):
    if got != want:
        FAIL.append(f"{name}: got {got!r}, want {want!r}")
        print(f"  FAIL {name}: got {got!r}, want {want!r}")
    else:
        print(f"  ok   {name}: {got!r}")

# ---- the fixture: shapes copied from a real profile, values invented ---------------------------
LS = {"last-wid-md": json.dumps("919000000001:44@c.us"), "WALid": json.dumps("133400000001:44@lid")}
STORES = {
    "contact": [
        # the name is on the LID record, the pushname on the PN record: only a merge sees both
        {"id": "965000000001@lid", "phoneNumber": "919500000002@c.us", "name": "Priya Desk",
         "isAddressBookContact": 1},
        {"id": "919500000002@s.whatsapp.net", "pushname": "Priya R Desai"},
        # ...and here the other way round: pushname on the lid record, nothing on the pn record
        {"id": "993800000003@lid", "phoneNumber": "918400000003@c.us", "pushname": "Nikhil"},
        {"id": "918400000003@s.whatsapp.net"},
        # known number, no name anywhere: the number is the label, not the lid
        {"id": "703600000004@lid", "phoneNumber": "918100000004@c.us"},
        # my own lid carries a pushname; my own phone form has no record at all
        {"id": "133400000001@lid", "pushname": "Riya"},
        # a stale, superseded copy of the first contact, as the Chromium reader yields them
        # (newest first) — it must NOT overwrite the live name
        {"id": "965000000001@lid", "phoneNumber": "919500000002@c.us", "name": "OLD NAME"},
    ],
    "group-metadata": [{"id": "120300000009@g.us", "subject": "Weekend plans"}],
    "chat": [{"id": "120300000009@g.us", "name": "stale group name"},
             {"id": "0@c.us", "name": "WhatsApp"},
             # WhatsApp's own display name for a 1:1 chat, on a contact who IS in the address book:
             # the address book must win, because that is the name that identifies them to this user
             {"id": "965000000001@lid", "name": "whatsapp's own rendering"},
             # ...and on one who is not named anywhere else, it fills the gap
             {"id": "703600000004@lid", "name": "named only by the chat store"}],
    "participant": [{"groupId": "120300000009@g.us",
                     "participants": ["965000000001@lid", "133400000001@lid"],
                     "pastParticipants": ["703600000004@lid"],
                     "admins": ["133400000001@lid"], "superAdmins": []}],
}
ids = Identities(STORES, LS)

print("canonicalisation")
check("device suffix dropped", canon_jid("919500000002:44@c.us"), "919500000002@c.us")
check("wire form folds to UI form", canon_jid("919500000002@s.whatsapp.net"), "919500000002@c.us")
check("lid is its own space", canon_jid("965000000001@lid"), "965000000001@lid")
check("group jid untouched", canon_jid("120300000009@g.us"), "120300000009@g.us")
check("empty stays empty", canon_jid(None), "")

print("\nthe lid/pn merge")
check("name via lid", ids.label("965000000001@lid"), "Priya Desk")
check("same name via the phone form", ids.label("919500000002@c.us"), "Priya Desk")
check("same name via the wire form", ids.label("919500000002@s.whatsapp.net"), "Priya Desk")
check("same name with a device suffix", ids.label("965000000001:3@lid"), "Priya Desk")
check("address book beats pushname", ids.entry("919500000002@c.us")["pushname"], "Priya R Desai")
check("pushname reached from the pn side", ids.label("918400000003@c.us"), "Nikhil")
check("lid->phone correlation present", ids.row("965000000001@lid")["phone"], "919500000002@c.us")
check("phone->lid correlation present", ids.row("919500000002@c.us")["lid"], "965000000001@lid")

print("\nnaming priority and provenance")
check("source: address book", ids.source("965000000001@lid"), "address-book")
check("source: pushname", ids.source("993800000003@lid"), "pushname")
bare = Identities({"contact": [{"id": "703600000005@lid", "phoneNumber": "918100000005@c.us"}]})
check("source: phone only", bare.source("703600000005@lid"), "phone")
check("number used when nothing is named", bare.label("703600000005@lid"), "+918100000005")
check("superseded record does not win", ids.label("965000000001@lid"), "Priya Desk")
# ...but the lid<->phone mapping is harvested even from a superseded record, because it is an
# identifier that does not change and losing it costs an identity
gapped = Identities({"contact": [
    {"id": "703600000007@lid", "pushname": "Later"},                      # live: no phoneNumber
    {"id": "703600000007@lid", "phoneNumber": "918100000007@c.us"}]}, {})  # superseded: has it
check("the link survives a live record that omits it",
      gapped.row("703600000007@lid")["phone"], "918100000007@c.us")
check("...while the live record still supplies the name",
      gapped.label("703600000007@lid"), "Later")

print("\nmy own identity")
check("my lid is me", ids.is_me("133400000001@lid"), True)
check("my phone form is me", ids.is_me("919000000001@c.us"), True)
check("my phone form with a device suffix is me", ids.is_me("919000000001:44@c.us"), True)
check("one identity for both of my forms",
      ids.label("919000000001@c.us"), ids.label("133400000001@lid"))
check("...and it is named", ids.label("133400000001@lid"), "Riya")
check("me marker only when asked", ids.label("133400000001@lid", mark_me=True), "Riya (me)")
check("a contact is not me", ids.is_me("965000000001@lid"), False)

print("\nmy identity survives a profile that names only one of my forms")
# `last-wid-md` is present on any logged-in profile; `WALid` is not guaranteed. With only the phone
# form known and my own messages authored by my lid, a literal membership test calls every outgoing
# message incoming.
HALF = {"last-wid-md": json.dumps("919000000001:44@c.us")}          # no WALid
# mechanism 1: a contact record ties my lid to my number (the usual case -- the real profile has it)
linked = Identities({"contact": STORES["contact"] + [
    {"id": "133400000001@lid", "phoneNumber": "919000000001@c.us", "pushname": "Riya"}]}, HALF)
check("my lid is me when a contact record ties it to my number",
      linked.is_me("133400000001@lid"), True)
# mechanism 2: nothing links them, so it is learned from who authored the outgoing messages
half = Identities(STORES, HALF)
check("unknown before learning", half.is_me("133400000001@lid"), False)
half.learn_me([{"from_me": True, "sender": "133400000001@lid"} for _ in range(50)] +
              [{"from_me": True, "sender": "965000000001@lid"}] +      # a system event's actor
              [{"from_me": False, "sender": "965000000001@lid"} for _ in range(20)])
check("my lid is learned from message authorship", half.is_me("133400000001@lid"), True)
check("a rare mismatching actor is NOT taken for me", half.is_me("965000000001@lid"), False)
check("learning adds nothing when the profile already named both forms",
      Identities(STORES, LS).learn_me([{"from_me": True, "sender": "133400000001@lid"}]), set())
check("my phone form is me", half.is_me("919000000001@c.us"), True)
check("a contact is still not me", half.is_me("965000000001@lid"), False)
check("my own message is not relabelled as incoming",
      msg_row({"chat": "x@c.us", "from_me": True, "type": "chat", "t": 0,
               "sender": "133400000001@lid", "id": "true_x_1"}, "t", pb("mine"), half)["dir"], "me")

print("\none person, one label")
# A chat-store name attached to the phone form must be found from the lid form too, or chats.json
# and identities.json name the same person differently.
two = Identities({"contact": [{"id": "965000000001@lid", "phoneNumber": "919500000002@c.us"}],
                  "chat": [{"id": "919500000002@c.us", "name": "Alice ChatStore"}]}, LS)
check("label via the lid form", two.label("965000000001@lid"), "Alice ChatStore")
check("label via the phone form", two.label("919500000002@c.us"), "Alice ChatStore")
check("label via the identity key", two.label(two.key("965000000001@lid")), "Alice ChatStore")
check("and the provenance says where it came from", two.source("965000000001@lid"), "chat-name")

print("\nchats and groups")
check("group subject wins over chat name", ids.label("120300000009@g.us"), "Weekend plans")
check("source: group subject", ids.source("120300000009@g.us"), "group-subject")
check("system pseudo-chat named", ids.label("status@broadcast"), "Status updates")
check("address book beats the chat store", ids.label("965000000001@lid"), "Priya Desk")
check("chat store fills a gap", ids.label("703600000004@lid"), "named only by the chat store")
check("...and says where that came from", ids.source("703600000004@lid"), "chat-name")
# a group whose metadata is missing (left, or never synced) still has the chat store's name, and
# that IS its name -- but it must not be reported as the authoritative subject
nosub = Identities({"chat": [{"id": "120300000099@g.us", "name": "not from metadata"}]})
check("group falls back to the chat store", nosub.label("120300000099@g.us"), "not from metadata")
check("...reported as chat-name, not subject", nosub.source("120300000099@g.us"), "chat-name")
check("a group with no name anywhere is not guessed at",
      Identities().label("120300000099@g.us"), "120300000099@g.us")
check("group membership kept", len(ids.groups["120300000009@g.us"]["participants"]), 2)
check("past participants kept", ids.groups["120300000009@g.us"]["past_participants"],
      ["703600000004@lid"])

print("\nnothing is invented")
check("unknown lid labels as itself", ids.label("999900009999@lid"), "999900009999@lid")
check("...and says so", ids.source("999900009999@lid"), "unresolved")
check("unknown phone jid still reads as a number", ids.label("919900000099@c.us"), "+919900000099")
check("empty sender", ids.label(""), "(unknown)")
check("no stores at all still works", Identities().label("965000000001@lid"), "965000000001@lid")

print("\nthe exported table")
tbl = ids.table(["965000000001@lid", "120300000009@g.us", "999900009999@lid",
                 "965000000001:3@lid"])           # the last is a duplicate of the first, canonicalised
check("one row per identity", len(tbl["identities"]), 3)
check("my own jids listed", sorted(tbl["me"]), ["133400000001@lid", "919000000001@c.us"])
check("group members labelled",
      [p["label"] for p in tbl["groups"]["120300000009@g.us"]["participants"]],
      ["Priya Desk", "Riya (me)"])
check("past participants labelled too",
      [p["label"] for p in tbl["groups"]["120300000009@g.us"]["past_participants"]],
      ["named only by the chat store"])
check("row fields", sorted(tbl["identities"][0]),
      ["address_book", "is_me", "jid", "jids", "label", "lid", "name", "phone", "pushname", "source"])
# one row per PERSON: a contact reached by lid and by phone number is one entry, listing both forms
one = ids.table(["965000000001@lid", "919500000002@c.us", "919500000002@s.whatsapp.net"])
check("every form of one person folds into a single row", len(one["identities"]), 1)
check("...and the row lists the forms seen", one["identities"][0]["jids"],
      ["919500000002@c.us", "965000000001@lid"])

print("\nthe message row and the transcript")
M = {"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
     "sender": "965000000001:3@lid", "id": "false_120300000009@g.us_AAA"}
row = msg_row(M, "2026-01-01 00:00:00", pb("hello", quoted="earlier words"), ids)
check("raw sender preserved verbatim", row["sender"], "965000000001:3@lid")
check("resolved name added beside it", row["sender_name"], "Priya Desk")
check("lid added", row["sender_lid"], "965000000001@lid")
check("phone added", row["sender_phone"], "919500000002@c.us")
check("chat named", row["chat_name"], "Weekend plans")
check("direction kept", row["dir"], "them")
check("the message id is carried", row["id"], "false_120300000009@g.us_AAA")
check("own text on the row", row["text"], "hello")
check("quote on the row, in its own field", row["quoted_text"], "earlier words")

mine = msg_row({"chat": "120300000009@g.us", "from_me": True, "type": "chat", "t": 0,
                "sender": "919000000001@c.us"}, "2026-01-01 00:00:01", pb("hi"), ids)
check("my own message resolves to my name", mine["sender_name"], "Riya")
# direction follows the sender, so a system event flagged outgoing but acted by someone else is not
# reported as mine
evt = msg_row({"chat": "120300000009@g.us", "from_me": True, "type": "gp2", "t": 0,
               "sender": "965000000001@lid", "id": "true_120300000009@g.us_E1"},
              "2026-01-01 00:00:03", pb("New subject"), ids)
check("an event acted by someone else is not attributed to me", evt["dir"], "them")
check("...and the stored flag is still visible in the id", evt["id"].startswith("true_"), True)
# with no own-jid keys in the profile there is nobody to compare against, so the stored flag is all
# there is -- and it must still be used, or every message would read as incoming
blind = Identities(STORES, {})
check("direction falls back to the stored flag when 'me' is unknown",
      msg_row({"chat": "x@c.us", "from_me": True, "type": "chat", "t": 0,
               "sender": "965000000001@lid", "id": "true_x_1"}, "t", pb("hi"), blind)["dir"], "me")

import tempfile
p = os.path.join(tempfile.mkdtemp(), "t.txt")
write_transcripts(p, {"120300000009@g.us": [row, mine]}, ids)
txt = open(p, encoding="utf-8").read()
check("header carries name AND jid",
      "Weekend plans  [120300000009@g.us]" in txt, True)
check("legend lists the sender's jid forms",
      "Priya Desk" in txt and "965000000001@lid  919500000002@c.us" in txt, True)
check("legend marks me", "(me)" in txt, True)
check("one legend row per person, not per address form",     # my lid AND my phone form are both here
      txt.count("Riya"), 2)                                 # once in the legend, once on my message
# computed, not hardcoded: the assertion is direction marker + right-aligned name + colon
check("incoming line names the sender", "<- %22s: hello" % "Priya Desk" in txt, True)
check("outgoing line is marked", "-> %22s: hi" % "Riya" in txt, True)
check("no 'them' left in the body", " them:" not in txt, True)

# A sticker reply has no text of its own; its quote is the only record of what it answered, and
# before this it produced no line at all.
stick = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "sticker", "t": 0,
                 "sender": "965000000001@lid", "id": "false_x_3"}, "2026-01-01 00:00:04",
                bytes([0x12]) + _vi(len(msg("their words"))) + msg("their words"), ids)
plain = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "image", "t": 0,
                 "sender": "965000000001@lid", "id": "false_x_4"}, "2026-01-01 00:00:05",
                pb("919500000002@s.whatsapp.net"), ids)
p6 = os.path.join(tempfile.mkdtemp(), "s.txt")
write_transcripts(p6, {"120300000009@g.us": [stick, plain]}, ids)
st = open(p6, encoding="utf-8").read()
check("a text-less message still gets a line", len([l for l in st.split("\n") if l.startswith("[")]), 2)
check("...shown as its type", "(sticker)" in st and "(image)" in st, True)
check("...and the sticker reply's quote is finally visible", "re: their words" in st, True)
check("the header counts messages and texted messages separately",
      "(group; 2 msgs, 0 with text)" in st, True)
check("the quote is shown as context, not as the message", "re: earlier words" in txt, True)

# a message that spans lines must stay attributable: continuations are indented under '|', so no
# content can sit at column 0 where the file's own structure lives
multi = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
                 "sender": "965000000001@lid"}, "2026-01-01 00:00:02",
                pb("first line\n# second line\r\nthird"), ids)
p2 = os.path.join(tempfile.mkdtemp(), "m.txt")
write_transcripts(p2, {"120300000009@g.us": [multi]}, ids)
mt = open(p2, encoding="utf-8").read()
body = [l for l in mt.split("\n") if l and not l.startswith("#") and not l.startswith("=====")]
check("the message's first line is attributed", any(l.startswith("[2026-01-01 00:00:02] <-") for l in body), True)
check("continuations are indented under a bar", sum(1 for l in body if l.lstrip().startswith("| ")), 2)
check("no content line starts at column 0",
      all(l.startswith("[") or l.startswith(" ") for l in body), True)
check("a '#' inside a message cannot look like a header",
      not any(l.startswith("#") for l in mt.split("=====")[-1].split("\n")), True)
check("CRLF does not leave a stray carriage return", "\r" not in mt, True)

# A name or group subject is user-controlled text and can contain a newline. The transcript is a
# line-structured file, so a label must be flattened before it is written -- otherwise one contact
# name splits a header in two and every line after it is misread.
hostile = Identities({"contact": [{"id": "965000000009@lid", "name": "Line\nBreak\tName"}],
                      "group-metadata": [{"id": "120300000009@g.us", "subject": "Sub\nject"}]}, LS)
hrow = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
                "sender": "965000000009@lid", "id": "false_x_1"}, "2026-01-01 00:00:00",
               pb("hello"), hostile)
p3 = os.path.join(tempfile.mkdtemp(), "h.txt")
write_transcripts(p3, {"120300000009@g.us": [hrow]}, hostile)
ht = open(p3, encoding="utf-8").read()
check("a newline in a label cannot split the header", ht.count("====="), 2)
check("...or the legend", len([l for l in ht.split("\n") if l.startswith("  - ")]), 1)
check("...or a message line", len([l for l in ht.split("\n") if l.startswith("[")]), 1)
check("the label still reads as the name", "Line Break Name" in ht, True)
check("chats.json keeps the label verbatim", hrow["sender_name"], "Line\nBreak\tName")

# A long name must read the SAME on a message line as in the legend, and must stay separable from
# the jid beside it. Flattening labels per call site with different widths produced one person in two
# renderings, and a label long enough to fill the column left a single space between it and the jid,
# which is also the separator the legend is parsed on.
LONGNAME = "Aaaaaaaaaa Bbbbbbbbbb Cccccccccc Dddddddddd Eeeeeeeeee"      # 54 chars
longids = Identities({"contact": [{"id": "965000000001@lid", "name": LONGNAME}],
                      "group-metadata": [{"id": "120300000009@g.us", "subject": "G"}]}, LS)
lrow = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
                "sender": "965000000001@lid", "id": "false_x_1"}, "2026-01-01 00:00:00",
               pb("hi"), longids)
p4 = os.path.join(tempfile.mkdtemp(), "l.txt")
write_transcripts(p4, {"120300000009@g.us": [lrow]}, longids)
lt = open(p4, encoding="utf-8").read()
leg = [l[4:] for l in lt.split("\n") if l.startswith("  - ")]
msgl = [l for l in lt.split("\n") if l.startswith("[")]
legend_label = leg[0].split("  ")[0].strip()
line_label = msgl[0].split("] ", 1)[1].split(": ", 1)[0].strip()[3:].strip()
check("a long label reads the same on the line as in the legend", line_label, legend_label)
# Truncation must be visible. A label cut at the column width, or a quote cut at the line budget,
# reads as the whole value if nothing says otherwise -- and in a transcript that is a quiet claim
# about what somebody wrote. The full value is in chats.json; the mark is what sends a reader there.
check("a truncated label says so", line_label.endswith("\u2026"), True)
qrow = msg_row({"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
                "sender": "965000000001@lid", "id": "false_x_2"}, "2026-01-01 00:00:00",
               pb("short reply", quoted="quoted words " * 20), longids)   # spaces: an unbroken
               # run of base64-legal characters is dropped by the text filter as a blob
p5 = os.path.join(tempfile.mkdtemp(), "q.txt")
write_transcripts(p5, {"120300000009@g.us": [qrow]}, longids)
qt = [l for l in open(p5, encoding="utf-8").read().split("\n") if l.lstrip().startswith("re: ")]
check("a truncated quote says so", qt[0].rstrip().endswith("\u2026"), True)
check("...and the full quote is still on the row", len(qrow["quoted_text"]), 260)
check("a long label stays separable from the jid that follows it", "  " in leg[0], True)
check("...and the jid is still recoverable from the legend row",
      "965000000001@lid" in leg[0].split("  ", 1)[-1], True)

print()
print("message text: addressing is noise, but never the whole message")
check("sender jid stripped from text", message_text(pb("hello there", "919500000002@s.whatsapp.net")),
      "hello there")
check("lid form stripped too", message_text(pb("ok", "965000000001@lid")), "ok")
# A body whose own content is NOTHING BUT addressing has no text, and must not be given one.
# This used to return the address, on the reasoning that it was "all the text there is" -- which
# was about the whole body, before own and quoted content were separated. Once they are, a media
# message with no caption genuinely has no text, and printing its routing jid as the message is
# worse than printing nothing: the record stays in chats.json with its type, and the transcript
# already omits messages that have none.
check("a body that is only addressing has no text",
      message_text(pb("919500000002@s.whatsapp.net")), "")
check("...and an address alongside real text is still just stripped",
      message_text(pb("see you", "919500000002@s.whatsapp.net")), "see you")
check("real text that merely contains digits is untouched",
      message_text(pb("call me on 9876543")), "call me on 9876543")
check("an email address is not an address jid", message_text(pb("a@b.com", "ok")), "a@b.com ok")

# The 90%-printable rule that keeps binary out has twice thrown real messages away with it. These
# are the exact shapes that were lost: a blank line inside a message, and emoji built from joiners
# and variation selectors, none of which str.isprintable() accepts.
check("a blank line inside a message survives",
      message_text(pb("Hello there,\n\nI want to connect")), "Hello there,\n\nI want to connect")
check("several short lines survive", message_text(pb("Deloitte \nPwc \nTcs")), "Deloitte \nPwc \nTcs")
check("zero-width-joiner emoji survive", message_text(pb("Same pg \U0001f62e\u200d\U0001f4a8")),
      "Same pg \U0001f62e\u200d\U0001f4a8")
check("a joiner-and-variation-selector emoji on its own survives",
      message_text(pb("\U0001f937\u200d\u2642\ufe0f")), "\U0001f937\u200d\u2642\ufe0f")
check("a tag-sequence flag survives",
      message_text(pb("England \U0001f3f4\U000e0067\U000e0062")),
      "England \U0001f3f4\U000e0067\U000e0062")
check("...but a real control character is still rejected as binary",
      message_text(pb("ok") + bytes([0x1a, 6]) + b"\x00\x01\x02\x03\x04\x05"), "ok")
# NOTE: a long run of base64-legal characters with no spaces is dropped by the text filter as a
# blob, so the padding string here deliberately contains spaces.
check("cap applied", len(message_text(pb("word " * 24), cap=100)), 100)

print()
print("a reply's own words are its own; the quote stays separate")
reply = pb("my answer", quoted="what they said")
check("own text only", message_text(reply), "my answer")
check("quote kept, not merged", quoted_text(reply), "what they said")
check("no quote means no quoted text", quoted_text(pb("just me")), "")
only_quote = bytes([0x12]) + _vi(len(msg("theirs"))) + msg("theirs")
check("body with only a quote has no own text", message_text(only_quote), "")
check("...and the quote is still readable", quoted_text(only_quote), "theirs")
check("an unparseable body falls back to scraping the whole thing",
      split_body(b"\xff\xff\xff")[0], b"\xff\xff\xff")
# Anything that is not the quote is this message's own content, so an unfamiliar field cannot take
# text out of the export without saying so.
odd = bytes([0x0a]) + _vi(len(msg("mine"))) + msg("mine") + \
      bytes([0x1a]) + _vi(len(msg("in field three"))) + msg("in field three")
check("text in an unexpected field is kept", message_text(odd), "mine in field three")
twice = bytes([0x0a]) + _vi(len(msg("first"))) + msg("first") + \
        bytes([0x0a]) + _vi(len(msg("second copy"))) + msg("second copy")
check("a repeated own-content field is kept", message_text(twice), "first second copy")
check("...and the quote is still only the first field 2",
      quoted_text(bytes([0x12]) + _vi(len(msg("q1"))) + msg("q1") +
                  bytes([0x12]) + _vi(len(msg("q2"))) + msg("q2")), "q1")

print()
print("formatting controls cannot rewrite a line")
rlo = "\u202e"
check("a joiner is still text", message_text(pb("a\u200db")), "a\u200db")
check("a bidi override survives into chats.json", rlo in message_text(pb("hello " + rlo + "world")), True)
bidi_ids = Identities({"contact": [{"id": "1@lid", "name": "Ann" + rlo + "Bob"}]}, LS)
brow = msg_row({"chat": "1@lid", "from_me": False, "type": "chat", "t": 0, "sender": "1@lid",
                "id": "false_x_5"}, "2026-01-01 00:00:00", pb("see " + rlo + "this"), bidi_ids)
p7 = os.path.join(tempfile.mkdtemp(), "b.txt")
write_transcripts(p7, {"1@lid": [brow]}, bidi_ids)
bt = open(p7, encoding="utf-8").read()
check("...but not into the transcript's text", rlo in bt, False)
check("...nor into a label there", "AnnBob" in bt, True)
check("the row still holds the characters the store held", rlo in brow["text"], True)

print()
print("a message's own body field is read verbatim, whatever it looks like")
# Measured on the reference store: every one of these decrypted, and every one exported EMPTY or
# truncated, because the generic scraper's guards (12+ digits, 40+ base64-looking, 90% "text-like",
# protobuf-tag first byte) were applied to the message's own text field.
import wa_decrypt as _WD
def _pb(field, payload):
    v, n, out = (field << 3) | 2, len(payload), bytearray()
    out.append(v)
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: break
    return bytes(out) + payload
def _body(text):                       # top-level field 1 = this message; its field 1 = body
    return _pb(1, _pb(1, text.encode("utf-8")))
for label, txt in [("a number someone sent", "1234567812345678"),
                   ("a phone number as the whole message", "919876543210"),
                   ("a pasted hex hash", "ae4f5d0932e7e10a8e4dfdbbe9bc7773dbbb5936ab25b310f8ceb44fe99f"),
                   ("an emoji newer than the interpreter's Unicode tables", "\U0001FAE9"),
                   ("text ending in new emoji", "Are.....\U0001FAE9\U0001FAE9\U0001FAE9"),
                   ("WhatsApp *bold* -- first byte '*' is also a protobuf tag", "*Wallet Update*\nDear Customer")]:
    check(label, _WD.texts(_body(txt))[0], txt)
thumb = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLS0tLS0yMjIyMjI="
check("a stored JPEG thumbnail in the body field is NOT text", _WD.texts(_body(thumb))[0], "")
check("...a base64-shaped hash is not mistaken for one", _WD._is_encoded_image(
      "ae4f5d0932e7e10a8e4dfdbbe9bc7773dbbb5936ab25b310f8ceb44fe99f"), False)
q = _pb(1, _pb(1, b"reply")) + _pb(2, _pb(1, b"*the quoted one*"))
check("own and quoted stay apart", _WD.texts(q), ("reply", "*the quoted one*"))
# A long message is evidence like any other: no length cap. JSON used to cut every message at 2,000
# characters and SQLite at 8,000, so a pasted document or a long forward lost its tail silently.
long_txt = "".join("A long forwarded notice, line %d.\n" % i for i in range(400))
check("a long message is kept whole", _WD.texts(_body(long_txt))[0], long_txt)
check("...and so is a long quote", _WD.texts(_pb(1, _pb(1, b"ok")) + _pb(2, _pb(1, long_txt.encode())))[1], long_txt)

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all identity cases pass")
