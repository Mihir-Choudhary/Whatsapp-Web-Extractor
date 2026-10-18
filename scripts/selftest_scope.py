#!/usr/bin/env python3
"""selftest_scope.py — `--chat`: which chats a name, number, lid or jid names, offline.

  * a phone number, its lid and every jid form find the same 1:1 chat, filed under either form;
  * a name matches exactly (case and spacing ignored): address-book name, pushname, group subject;
  * a name or number that fits two chats, or none, stops with the candidates listed -- never a guess;
  * a contact with no messages in the store cannot be scoped (nothing to anchor on).

Run:  python3 scripts/selftest_scope.py        (exit 0 = all cases pass)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wa_decrypt as WD, chat_scope as CS

FAIL = []
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)

stores = {
    "contact": [
        {"id": "1111@lid", "phoneNumber": "15555550101@c.us", "name": "Juno Example", "pushname": "Juno"},
        {"id": "15555550101@c.us", "name": "Juno Example"},
        {"id": "2222@lid", "phoneNumber": "15555550102@c.us", "pushname": "Juno"},
        {"id": "3333@lid", "phoneNumber": "15555550103@c.us", "name": "Anna  Lee"},
        {"id": "4444@lid", "phoneNumber": "15555550104@c.us", "name": "No Messages"},
        {"id": "5555@lid", "phoneNumber": "15555550105@c.us", "name": "Mom @home"},
    ],
    "group-metadata": [{"id": "120363000000000001@g.us", "subject": "Book club"},
                       {"id": "120363000000000002@g.us", "subject": "Juno Example"},
                       {"id": "120363000000000003@g.us", "subject": "2024"}],
    "chat": [],
}
ids = WD.Identities(stores, {"last-wid-md": '"15555550199@c.us"'})
# Juno Example's 1:1 chat is filed under BOTH forms (older messages by number, newer by lid)
counts = {"120363000000000003@g.us": 2, "5555@lid": 1, "15555550101@c.us": 5, "1111@lid": 7, "2222@lid": 3, "3333@lid": 2,
          "120363000000000001@g.us": 9, "120363000000000002@g.us": 4}

def one(spec):
    try:
        p = CS.resolve([spec], ids, counts)
        return list(p.values())[0], None
    except CS.ScopeError as e:
        return None, str(e)

print("one person, any form")
for spec in ("+1 555 555 0101", "15555550101", "15555550101@s.whatsapp.net", "15555550101:12@s.whatsapp.net",
             "15555550101@c.us", "1111@lid", "1111"):
    c, err = one(spec)
    check("%-34s -> Juno Example's chat, both forms, 12 messages" % spec,
          c is not None and {"1111@lid", "15555550101@c.us"} <= set(c["forms"]) and c["messages"] == 12)
c, _ = one("anna lee")
check("a name matches whatever its case and spacing", c is not None and c["label"] == "Anna  Lee")
c, _ = one("mom @home")
check("a name holding an '@' is a name, not an address", c is not None and c["label"] == "Mom @home")
c, _ = one("Book Club")
check("a group by its subject", c is not None and c["forms"] == ["120363000000000001@g.us"])
c, _ = one("2024")
check("a group whose name is all digits, by its name", c is not None and c["forms"] == ["120363000000000003@g.us"])
c, _ = one("120363000000000002@g.us")
check("a group by its jid", c is not None and c["label"] == "Juno Example")

print("never a guess")
c, err = one("Juno")
check("two people who both call themselves 'Juno': stops and lists both",
      c is None and "fits 2 chats" in err and "1111@lid" in err and "2222@lid" in err)
c, err = one("Juno Example")
check("a name shared by a contact and a group stops and lists both", c is None and "fits 2 chats" in err
      and "1111@lid" in err and "120363000000000002@g.us" in err)
c, err = one("Jun")
check("no exact name: stops and suggests the near ones", c is None and "did you mean" in err and "Juno" in err)
c, err = one("5555550101")
check("a number without its country code is not guessed: stops and lists the number it ends",
      c is None and "country code" in err and "15555550101" in err)
c, err = one("No Messages")
check("a contact with no messages cannot be scoped", c is None and "at least one message" in err)
c, err = one("15555550104@s.whatsapp.net")
check("...nor by its jid", c is None and "at least one message" in err)

print("several chats, and what the export keeps")
p = CS.resolve(["1111@lid", "Book club"], ids, counts)
sc = CS.forms(p)
check("--chat is repeatable", len(p) == 2)
check("in_scope accepts every form of a chosen chat",
      all(CS.in_scope(j, sc) for j in ("15555550101@s.whatsapp.net", "15555550101:3@s.whatsapp.net", "1111@lid",
                                       "120363000000000001@g.us")))
check("in_scope rejects everything else", not any(CS.in_scope(j, sc) for j in ("2222@lid", "120363000000000002@g.us")))
check("no scope means everything", CS.in_scope("2222@lid", None) and CS.in_scope("2222@lid", []))

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all scope cases pass")
