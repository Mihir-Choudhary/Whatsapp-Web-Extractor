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
from wa_decrypt import Identities, canon_jid, msg_row, write_transcripts, message_text

FAIL = []

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
      ["address_book", "is_me", "jid", "label", "lid", "name", "phone", "pushname", "source"])

print("\nthe message row and the transcript")
M = {"chat": "120300000009@g.us", "from_me": False, "type": "chat", "t": 0,
     "sender": "965000000001:3@lid", "id": "false_120300000009@g.us_AAA"}
row = msg_row(M, "2026-01-01 00:00:00", "hello", ids)
check("raw sender preserved verbatim", row["sender"], "965000000001:3@lid")
check("resolved name added beside it", row["sender_name"], "Priya Desk")
check("lid added", row["sender_lid"], "965000000001@lid")
check("phone added", row["sender_phone"], "919500000002@c.us")
check("chat named", row["chat_name"], "Weekend plans")
check("direction kept", row["dir"], "them")

mine = msg_row({"chat": "120300000009@g.us", "from_me": True, "type": "chat", "t": 0,
                "sender": "919000000001@c.us"}, "2026-01-01 00:00:01", "hi", ids)
check("my own message resolves to my name", mine["sender_name"], "Riya")

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

print()
print("message text: addressing is noise, but never the whole message")
# field 1 of a Message is `conversation`; a bare jid elsewhere in the tree is addressing metadata
def pb(*strings):
    out = b""
    for i, v in enumerate(strings, start=1):
        b = v.encode(); out += bytes([i << 3 | 2, len(b)]) + b
    return bytes([0x0a, len(out)]) + out
check("sender jid stripped from text", message_text(pb("hello there", "919500000002@s.whatsapp.net")),
      "hello there")
check("lid form stripped too", message_text(pb("ok", "965000000001@lid")), "ok")
check("a jid-only body keeps its jid rather than vanishing",
      message_text(pb("919500000002@s.whatsapp.net")), "919500000002@s.whatsapp.net")
check("real text that merely contains digits is untouched",
      message_text(pb("call me on 9876543")), "call me on 9876543")
check("an email address is not an address jid", message_text(pb("a@b.com", "ok")), "a@b.com ok")
check("cap applied", len(message_text(pb("x" * 120), cap=100)), 100)   # pb() writes 1-byte lengths

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all identity cases pass")
