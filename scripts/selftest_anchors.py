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

# These tests print message text and contact names, which include emoji. On a Windows console that
# is cp1252 by default -- which is what CI runs -- printing one raises UnicodeEncodeError and the
# suite dies mid-run with a traceback instead of a result.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass


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
# Asserting the dict against a literal copy of itself only catches an accidental edit, not a WRONG
# mapping -- and one entry here is load-bearing: value 2 (INCOMPLETE) maps to False, which makes
# build_anchors DROP those chats by default. Invert that one and the tool permanently stops asking
# for exactly the chats whose history sync is unfinished, and the symptom is the silence this whole
# changeset exists to disambiguate. So assert the PROPERTY the reference function has, derived from
# its own truth table, rather than restating our copy of it.
#   primaryHasMoreMessagesReadyToLoad() returns true for {0,3,4,5} and false for {1,2}.
check("true set", {k for k, v in build_anchors._MORE_ON_PRIMARY.items() if v}, {0, 3, 4, 5})
check("false set", {k for k, v in build_anchors._MORE_ON_PRIMARY.items() if not v}, {1, 2})
check("INCOMPLETE(2) is not askable", build_anchors._MORE_ON_PRIMARY[2], False)
check("COMPLETE_AND_NO_MORE(1) is not askable", build_anchors._MORE_ON_PRIMARY[1], False)
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

print("\n_deepen_anchors: `only` confines a targeted refetch, and survives being deepened")
# A refetch narrows anchors.json to the chats that are missing something. The adoption below is what
# defeated that: every chat in the ledger has recovered messages and no anchor, so the first deepen
# re-created one for all 185 of them and the subset was gone. Measured on the real ledger before the
# fix: filtered to 20, back to 185 after one pass.
json.dump({"anchors": [
    {"chat": "1203@g.us", "chat_id": "1203@g.us", "more_on_primary": True,
     "oldest_id": "A0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "9195@s.whatsapp.net", "chat_id": "9650@lid", "more_on_primary": True,
     "oldest_id": "B0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False}],
    "ondisk_ids": []}, open(ap, "w", encoding="utf-8"))
wawf._deepen_anchors(ap, {
    "G1": {"id": "G1", "chat": "1203@g.us", "ts": 1_759_000_000, "fromMe": False},
    "D1": {"id": "D1", "chat": "9195@s.whatsapp.net", "ts": 1_759_000_000, "fromMe": False},
    "X1": {"id": "X1", "chat": "7777@g.us", "ts": 1_759_000_000, "fromMe": False}},
    only={"1203@g.us"})
a = json.load(open(ap, encoding="utf-8"))
check("only the targeted chat remains", sorted(str(x["chat"]) for x in a["anchors"]), ["1203@g.us"])
g = a["anchors"][0]
check("...and it was still deepened", (g["oldest_id"], g["oldest_ts"]), ("G1", 1_759_000_000))
check("...keeping its wire form and more_on_primary",
      (g["chat"], g["more_on_primary"]), ("1203@g.us", True))

print()
print("_deepen_anchors: the phone's 'start reached' is recorded, and drained chats go last")
# This is the bug that produced "the phone answered NONE of the requests". An empty page is the
# phone ANSWERING that it has nothing older -- the one unambiguous end-of-history signal there is.
# Nothing recorded it, so 103 of 253 chats kept more_on_primary=True, and the old ordering ("chats
# we just went deeper on first") put exactly those drained chats at the HEAD of the queue. The
# client probes its first few chats and then stops, so every later run spent the probe on chats
# already known to be finished and reported the phone as unresponsive -- having asked 4 of 253.
json.dump({"anchors": [
    {"chat": "ended@g.us", "chat_id": "ended@g.us", "more_on_primary": True,
     "oldest_id": "E0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "live@s.whatsapp.net", "chat_id": "live@lid", "more_on_primary": True,
     "oldest_id": "L0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "bylid@s.whatsapp.net", "chat_id": "bylid@lid", "more_on_primary": True,
     "oldest_id": "M0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False}],
    "ondisk_ids": []}, open(ap, "w", encoding="utf-8"))
wawf._deepen_anchors(ap, {
    "E1": {"id": "E1", "chat": "ended@g.us", "ts": 1_759_000_000, "fromMe": False},
    "L1": {"id": "L1", "chat": "live@s.whatsapp.net", "ts": 1_759_000_000, "fromMe": False}},
    start_reached={"ended@g.us", "bylid@lid"})       # one matched by `chat`, one by its `chat_id`
a = json.load(open(ap, encoding="utf-8"))
order = [str(x["chat"]) for x in a["anchors"]]
by = {str(x["chat"]): x for x in a["anchors"]}
check("the chat the phone ended is marked", by["ended@g.us"]["more_on_primary"], False)
check("matched by chat_id too", by["bylid@s.whatsapp.net"]["more_on_primary"], False)
check("a chat that still answers is untouched", by["live@s.whatsapp.net"]["more_on_primary"], True)
check("an askable chat leads the queue, so the probe samples a live one", order[0],
      "live@s.whatsapp.net")
check("both drained chats sit at the end",
      sorted(order[-2:]), ["bylid@s.whatsapp.net", "ended@g.us"])
check("being ended does not throw the anchor away", by["ended@g.us"]["oldest_id"], "E1")

print()
print("chat state: outcomes survive the anchors being rebuilt from the profile")
# The first version of the end-of-history fix recorded "ended" only inside anchors.json. wawf rebuilds
# that file from the browser profile at the start of every run, so the marks were gone before the
# client started: a real run asked the same four finished chats again and stopped. The outcomes now
# live in their own file and are re-applied to whatever build_anchors produces.
sp = os.path.join(os.path.dirname(ap), "chat_state_selftest.json")
if os.path.exists(sp): os.remove(sp)
st = wawf._load_chat_state(sp)
check("a missing state file is an empty state", (st["ended"], st["silent"]), (set(), {}))
wawf._note_pass(st, {"start_reached": ["ended@g.us"], "silent_chats": ["mute@g.us", "flaky@g.us"],
                     "answered_chats": ["good@g.us"]})
wawf._note_pass(st, {"silent_chats": ["mute@g.us"], "answered_chats": ["flaky@g.us"]})
check("silence accumulates run over run", st["silent"].get("mute@g.us"), 2)
check("any answer clears the silent count", "flaky@g.us" in st["silent"], False)
wawf._save_chat_state(sp, st)
st2 = wawf._load_chat_state(sp)
check("round-trips through disk", (st2["ended"], st2["silent"]), ({"ended@g.us"}, {"mute@g.us": 2}))

# a FRESHLY REBUILT anchors file: nothing marked, in the order build_anchors happened to emit
json.dump({"anchors": [
    {"chat": "mute@g.us", "chat_id": "mute@g.us", "more_on_primary": True,
     "oldest_id": "M0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "ended@g.us", "chat_id": "ended@g.us", "more_on_primary": True,
     "oldest_id": "E0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "good@g.us", "chat_id": "good@g.us", "more_on_primary": True,
     "oldest_id": "G0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False}],
    "ondisk_ids": []}, open(ap, "w", encoding="utf-8"))
ledger = os.path.join(os.path.dirname(ap), "ledger_selftest.json")
json.dump({"messages": [{"id": "G1", "chat": "good@g.us", "ts": 1_759_000_000, "fromMe": False}]},
          open(ledger, "w", encoding="utf-8"))
wawf._resume_master(ledger, ap, {}, deepen=True, chat_state=st2)
a = json.load(open(ap, encoding="utf-8"))
order = [str(x["chat"]) for x in a["anchors"]]
by = {str(x["chat"]): x for x in a["anchors"]}
check("the ended chat is marked again after a rebuild", by["ended@g.us"]["more_on_primary"], False)
check("queue: answerable first, repeatedly-silent next, ended last",
      order, ["good@g.us", "mute@g.us", "ended@g.us"])
wawf._resume_master(ledger, ap, {}, deepen=False, chat_state=st2)      # the --history-refetch path
a = json.load(open(ap, encoding="utf-8"))
check("...and on the refetch path, which does not deepen",
      [str(x["chat"]) for x in a["anchors"]][-1], "ended@g.us")
# no ledger yet (first run, or after a reset): saved outcomes must still be applied
json.dump({"anchors": [
    {"chat": "ended@g.us", "chat_id": "ended@g.us", "more_on_primary": True,
     "oldest_id": "E0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False},
    {"chat": "good@g.us", "chat_id": "good@g.us", "more_on_primary": True,
     "oldest_id": "G0", "oldest_ts": 1_760_000_000, "oldest_fromMe": False}],
    "ondisk_ids": []}, open(ap, "w", encoding="utf-8"))
missing = os.path.join(os.path.dirname(ap), "no_such_ledger.json")
wawf._resume_master(missing, ap, {}, deepen=True, chat_state=st2)
a = json.load(open(ap, encoding="utf-8"))
check("saved outcomes apply even with no ledger yet",
      {str(x["chat"]): x["more_on_primary"] for x in a["anchors"]}, {"ended@g.us": False, "good@g.us": True})
for f in (sp, ledger):
    if os.path.exists(f): os.remove(f)

print()
if fails:
    print(f"FAILED ({len(fails)}): " + ", ".join(fails))
    sys.exit(1)
print("all anchor self-tests passed")
