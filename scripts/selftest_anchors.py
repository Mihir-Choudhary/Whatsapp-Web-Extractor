#!/usr/bin/env python3
"""selftest_anchors.py — guards the anchor plumbing, which has broken silently twice.

Both failures looked identical from the outside: the phone simply did not answer, which is also what
a revoked device, a throttled device and an exhausted chat look like. Neither raised anything. So the
invariants are asserted here instead of being re-derived by hand.

  1. `chat` must be the jid WhatsApp Web actually sends. For a LID-migrated chat that is
     `createWid(chatRecord.historyChatId).toJid()`, and Wid.toJid() maps server `c.us` ->
     `s.whatsapp.net`. Sending the stored `@c.us` value names a jid the client never sends.
  2. `more_on_primary` must follow primaryHasMoreMessagesReadyToLoad(): asking a chat whose
     endOfHistoryTransferType says the primary holds nothing older cannot succeed.
  3. `_deepen_anchors` must UPDATE anchors, not rebuild them. The phone labels a recovered message
     with its own choice of jid form, so rebuilding from the message dropped the wire-form `chat`,
     dropped `more_on_primary`, and appended a duplicate anchor instead of deepening the real one.

  python3 scripts/selftest_anchors.py
"""
import json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {got!r}" + ("" if ok else f"  (expected {want!r})"))
    if not ok:
        fails.append(label)


# ---------------------------------------------------------------- 1. the wire form
import build_anchors

print("Wid.toJid(): server c.us -> s.whatsapp.net, everything else unchanged")
check("c.us mapped", build_anchors._to_jid("9199@c.us"), "9199@s.whatsapp.net")
check("lid untouched", build_anchors._to_jid("6627@lid"), "6627@lid")
check("group untouched", build_anchors._to_jid("120363@g.us"), "120363@g.us")
check("s.whatsapp.net untouched", build_anchors._to_jid("9199@s.whatsapp.net"), "9199@s.whatsapp.net")

# ---------------------------------------------------------------- 2. the futility table
print("\nprimaryHasMoreMessagesReadyToLoad(endOfHistoryTransferType)")
WANT = {0: True,    # COMPLETE_BUT_MORE_MESSAGES_REMAIN_ON_PRIMARY
        1: False,   # COMPLETE_AND_NO_MORE_MESSAGE_REMAIN_ON_PRIMARY
        2: False,   # INCOMPLETE
        3: True,    # NOT_INCLUDED_IN_HIST_SYNC
        4: True,    # COMPLETE_ON_DEMAND_SYNC_BUT_MORE_MSG_REMAIN_ON_PRIMARY
        5: True}    # COMPLETE_ON_DEMAND_SYNC_WITH_MORE_MSG_ON_PRIMARY_BUT_NO_ACCESS
check("table", build_anchors._MORE_ON_PRIMARY, WANT)
check("unknown value defaults to askable", build_anchors._MORE_ON_PRIMARY.get(99, True), True)

# ---------------------------------------------------------------- 3. deepening preserves the anchor
sys.argv = ['wawf.py']
import wawf

print("\n_deepen_anchors: the phone labels the message @lid, the anchor is addressed @s.whatsapp.net")
d = tempfile.mkdtemp()
ap = os.path.join(d, 'anchors.json')
anchors = [
    {"chat": "9199@s.whatsapp.net", "chat_id": "6627@lid", "oldest_id": "OLD1",
     "oldest_ts": 1_780_000_000, "oldest_fromMe": False, "more_on_primary": True},
    {"chat": "120363@g.us", "chat_id": "120363@g.us", "oldest_id": "OLDG",
     "oldest_ts": 1_781_000_000, "oldest_fromMe": False, "more_on_primary": True},
]
json.dump({"anchors": anchors, "ondisk_ids": ["OLD1", "OLDG"]}, open(ap, "w", encoding="utf-8"))
master = {
    "M1": {"id": "M1", "chat": "6627@lid",    "ts": 1_770_000_000, "fromMe": False},
    "M2": {"id": "M2", "chat": "6627@lid",    "ts": 1_775_000_000, "fromMe": True},
    "MG": {"id": "MG", "chat": "120363@g.us", "ts": 1_779_000_000, "fromMe": False},
}
wawf._deepen_anchors(ap, master)
out = json.load(open(ap, encoding="utf-8"))
check("no duplicate anchor appended", len(out["anchors"]), 2)
one = {x["chat_id"]: x for x in out["anchors"]}["6627@lid"]
check("wire-form chat preserved", one["chat"], "9199@s.whatsapp.net")
check("chat_id preserved", one["chat_id"], "6627@lid")
check("more_on_primary preserved", one.get("more_on_primary"), True)
check("re-anchored on the oldest", (one["oldest_id"], one["oldest_ts"]), ("M1", 1_770_000_000))
check("fromMe carried", one["oldest_fromMe"], False)
check("recovered ids added to ondisk", set(out["ondisk_ids"]), {"OLD1", "OLDG", "M1", "M2", "MG"})

print("\n_deepen_anchors: a chat with no anchor is adopted, not dropped")
wawf._deepen_anchors(ap, {"X": {"id": "X", "chat": "999@s.whatsapp.net", "ts": 1_760_000_000, "fromMe": False}})
out2 = json.load(open(ap, encoding="utf-8"))
check("adopted", len(out2["anchors"]), 3)
check("adopted with both forms set",
      [x for x in out2["anchors"] if x["chat_id"] == "999@s.whatsapp.net"][0]["chat"], "999@s.whatsapp.net")

print("\nstub messages (ts<=0) cannot anchor a request")
json.dump({"anchors": [dict(anchors[0])], "ondisk_ids": []}, open(ap, "w", encoding="utf-8"))
wawf._deepen_anchors(ap, {"S": {"id": "S", "chat": "6627@lid", "ts": 0, "fromMe": False}})
out3 = json.load(open(ap, encoding="utf-8"))
check("anchor left alone", out3["anchors"][0]["oldest_id"], "OLD1")
check("but the id is still recorded as on-disk", set(out3["ondisk_ids"]), {"S"})

print()
if fails:
    print(f"FAILED ({len(fails)}): " + ", ".join(fails))
    sys.exit(1)
print("all anchor self-tests passed")
