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

# A decrypted body is {1: this message, 2: the message it replies to}. Inside a message, field 1 is
# `conversation`; a bare jid anywhere in the tree is addressing metadata.
def fields(*pairs):
    out = b""
    for f, v in pairs:
        b = v.encode(); out += bytes([f << 3 | 2, len(b)]) + b
    return out

def msg(*strings):
    return fields(*[(i, v) for i, v in enumerate(strings, start=1)])

def pb(*strings, quoted=None):
    """A body: own content, optionally with a quoted message beside it."""
    out = bytes([0x0a, len(msg(*strings))]) + msg(*strings)
    if quoted is not None:
        q = msg(quoted); out += bytes([0x12, len(q)]) + q
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

print("\nmy own identity")
check("my lid is me", ids.is_me("133400000001@lid"), True)
check("my phone form is me", ids.is_me("919000000001@c.us"), True)
check("my phone form with a device suffix is me", ids.is_me("919000000001:44@c.us"), True)
check("one identity for both of my forms",
      ids.label("919000000001@c.us"), ids.label("133400000001@lid"))
check("...and it is named", ids.label("133400000001@lid"), "Riya")
check("me marker only when asked", ids.label("133400000001@lid", mark_me=True), "Riya (me)")
check("a contact is not me", ids.is_me("965000000001@lid"), False)

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

print()
print("message text: addressing is noise, but never the whole message")
check("sender jid stripped from text", message_text(pb("hello there", "919500000002@s.whatsapp.net")),
      "hello there")
check("lid form stripped too", message_text(pb("ok", "965000000001@lid")), "ok")
check("a jid-only body keeps its jid rather than vanishing",
      message_text(pb("919500000002@s.whatsapp.net")), "919500000002@s.whatsapp.net")
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
only_quote = bytes([0x12, len(msg("theirs"))]) + msg("theirs")
check("body with only a quote has no own text", message_text(only_quote), "")
check("...and the quote is still readable", quoted_text(only_quote), "theirs")
check("an unparseable body falls back to scraping the whole thing",
      split_body(b"\xff\xff\xff")[0], b"\xff\xff\xff")

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all identity cases pass")
