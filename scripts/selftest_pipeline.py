#!/usr/bin/env python3
"""selftest_pipeline.py — decrypt and write, end to end, on a synthetic store.

`selftest_identities.py` covers who-is-who in isolation. This covers the pipeline around it, which
nothing else did: HKDF derivation from the on-disk root key, the key VALIDATION that is supposed to
refuse a wrong key rather than write garbage, the scheme filter, and all three writers. It also
exercises `wa_decrypt.py`'s standalone `main()`, which is a documented entry point.

A real profile takes minutes to parse, so the store is built in memory — but nothing is faked below
the storage layer: real HKDF, real AES-CBC ciphertext, real protobuf bodies, real writers.

Run:  python3 scripts/selftest_pipeline.py        (exit 0 = all cases pass)
"""
import os, sys, json, base64, tempfile, shutil, io, contextlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import wa_decrypt as WD
from wa_decrypt import _dedupe_msgs

FAIL = []
# These tests print message text and contact names, which include emoji. On a Windows console that
# is cp1252 by default -- which is what CI runs -- printing one raises UnicodeEncodeError and the
# suite dies mid-run with a traceback instead of a result.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass


def check(name, cond):
    if cond:
        print("  ok   " + name)
    else:
        FAIL.append(name); print("  FAIL " + name)

ROOT = bytes(range(32))                       # stands in for wawc_db_enc/keys
SALT_WS = bytes(range(100, 132))              # stands in for WAWebEncKeySalt
ENC_STATIC = bytes(range(200, 232))           # the server-issued value, never on disk
KEY = HKDF(algorithm=hashes.SHA256(), length=16, salt=ENC_STATIC, info=SALT_WS).derive(ROOT)

def _vi(n):
    """A protobuf varint, so a fixture string may be any length (a 1-byte length caps it at 127)."""
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def msg(*strings):
    out = b""
    for i, v in enumerate(strings, start=1):
        b = v.encode(); out += bytes([i << 3 | 2]) + _vi(len(b)) + b
    return out

def pb(*strings, quoted=None):
    """A decrypted body: field 1 is this message, field 2 the message it replies to."""
    m = msg(*strings); out = bytes([0x0a]) + _vi(len(m)) + m
    if quoted is not None:
        q = msg(quoted); out += bytes([0x12]) + _vi(len(q)) + q
    return out

def enc(pt, key=KEY):
    pad = 16 - len(pt) % 16
    iv = b"\x11" * 16
    return iv, Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(pt + bytes([pad]) * pad)

LS = {"WAWebEncKeySalt": json.dumps(base64.b64encode(SALT_WS).decode()),
      "last-wid-md": json.dumps("919000000001:44@c.us"),
      "WALid": json.dumps("133400000001:44@lid")}
STORES = {
    "contact": [{"id": "965000000001@lid", "phoneNumber": "919500000002@c.us", "name": "Priya Desk",
                 "isAddressBookContact": 1},
                {"id": "919500000002@s.whatsapp.net", "pushname": "Priya R Desai"},
                {"id": "133400000001@lid", "pushname": "Riya"}],
    "group-metadata": [{"id": "120300000009@g.us", "subject": "Weekend plans"}],
    "chat": [],
    "participant": [{"groupId": "120300000009@g.us",
                     "participants": ["965000000001@lid", "133400000001@lid"],
                     "pastParticipants": [], "admins": [], "superAdmins": []}],
}

def store(extra=()):
    msgs = []
    for frm, sender, text in ((False, "965000000001@lid", "hello there"),
                              (True, "133400000001@lid", "hi back"),
                              (False, "965000000001:3@lid", "and a device suffix")):
        # own text + the sender's own jid in the tree + a quoted message beside it
        iv, ct = enc(pb(text, "919500000002@s.whatsapp.net", quoted="what was said before"))
        msgs.append({"id": ("true" if frm else "false") + "_120300000009@g.us_" + text[:3],
                     "chat": "120300000009@g.us", "from_me": frm, "type": "chat", "t": 1760000000,
                     "sender": sender, "iv": iv, "data": ct, "scheme": 1})
    msgs.extend(extra)
    return msgs

def run(msgs, enc_static=ENC_STATIC):
    """Drive the standalone entry point over a synthetic store; returns (out_dir, stdout, exit)."""
    WD.load = lambda profile=None, origin=None: (
        "synthetic", LS, ROOT, _dedupe_msgs(msgs),      # every real loader dedupes; so must this one
        {"contact": 3, "group-metadata": 1, "chat": 0}, WD.Identities(STORES, LS))
    out = tempfile.mkdtemp()
    sys.argv = ["wa_decrypt.py", "--profile", "X", "--out", out,
                "--enc-static", base64.b64encode(enc_static).decode()]
    buf = io.StringIO(); code = 0
    try:
        with contextlib.redirect_stdout(buf): WD.main()
    except SystemExit as e:
        code = e.code or 0
    return out, buf.getvalue(), code

print("the happy path")
out, log, code = run(store())
t = open(os.path.join(out, "transcripts.txt"), encoding="utf-8").read()
ch = json.load(open(os.path.join(out, "chats.json"), encoding="utf-8"))
ids = json.load(open(os.path.join(out, "identities.json"), encoding="utf-8"))
row = ch["120300000009@g.us"][0]
check("exits clean", code == 0)
check("all three artifacts written", all(os.path.isfile(os.path.join(out, f)) for f in
                                         ("transcripts.txt", "chats.json", "identities.json")))
check("key validated against reference ciphertext", "VALIDATED (3/3" in log)
check("all three bodies decrypted", "decrypted 3 bodies (0 failed)" in log)
check("coverage reported", "senders identified: address-book=2  pushname=1" in log)
check("plaintext recovered", row["text"] == "hello there")
check("sender named rather than 'them'", row["sender_name"] == "Priya Desk" and " them:" not in t)
check("lid/phone pair on the row", row["sender_lid"] == "965000000001@lid"
      and row["sender_phone"] == "919500000002@c.us")
check("raw sender preserved", row["sender"] == "965000000001@lid")
check("group named in the header", "Weekend plans  [120300000009@g.us]" in t)
check("the sender's own jid is not in the message text", "@s.whatsapp.net" not in t.split("=====")[-1])
check("a quoted message is not counted as this message's text", row["text"] == "hello there")
check("the quote is kept in its own field", row["quoted_text"] == "what was said before")
check("the quote reaches the transcript as context", "re: what was said before" in t)
check("a device suffix does not split one person in two", t.count("Priya Desk") == 3)
check("my own message marked outgoing", "->" in t and ch["120300000009@g.us"][1]["dir"] == "me")
check("identities exported", len(ids["identities"]) == 3 and len(ids["groups"]) == 1)
shutil.rmtree(out, ignore_errors=True)

print("\na wrong key is refused, not written")
# Right key => every body has valid PKCS7. Wrong key => ~0.4% do. The writers must stop.
out, log, code = run(store(), enc_static=bytes(range(1, 33)))
check("exits 3", code == 3)
check("says so plainly", "INVALID" in log)
check("writes nothing", not os.path.isfile(os.path.join(out, "chats.json")))
shutil.rmtree(out, ignore_errors=True)

print("\nscheme-0 bodies are skipped, not decrypted into garbage")
iv, ct = enc(pb("would be garbage"))
extra = [{"id": "false_120300000009@g.us_S0", "chat": "120300000009@g.us", "from_me": False,
          "type": "chat", "t": 1760000000, "sender": "965000000001@lid",
          "iv": iv, "data": ct, "scheme": 0}]
out, log, code = run(store(extra))
check("the scheme-0 body is not counted as decrypted", "decrypted 3 bodies" in log)
check("...and does not reach the transcript",
      "would be garbage" not in open(os.path.join(out, "transcripts.txt"), encoding="utf-8").read())
shutil.rmtree(out, ignore_errors=True)

print("\nan exact duplicate record is one message, not two")
dup = store()
dup.append(dict(dup[0]))                       # the same record read twice, as LevelDB yields it
out, log, code = run(dup)
ch2 = json.load(open(os.path.join(out, "chats.json"), encoding="utf-8"))
check("the duplicate is dropped", len(ch2["120300000009@g.us"]) == 3)
check("...before it reaches the counts", "decrypted 3 bodies" in log)
near = dict(dup[0]); near["t"] = 1760000001    # a record that genuinely differs is NOT a duplicate
out2, log2, _ = run(store() + [near])
ch3 = json.load(open(os.path.join(out2, "chats.json"), encoding="utf-8"))
check("a record that differs is kept", len(ch3["120300000009@g.us"]) == 4)
shutil.rmtree(out, ignore_errors=True); shutil.rmtree(out2, ignore_errors=True)

print("\na body that will not decrypt is counted as failed, not dropped silently")
out, log, code = run(store([{"id": "false_120300000009@g.us_BAD", "chat": "120300000009@g.us",
                             "from_me": False, "type": "chat", "t": 1760000000,
                             "sender": "965000000001@lid", "iv": b"\x11" * 16,
                             "data": b"\x00" * 7, "scheme": 1}]))   # not a block multiple
check("failure counted", "(1 failed)" in log)
check("the other three still written", "decrypted 3 bodies" in log)
shutil.rmtree(out, ignore_errors=True)

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all pipeline cases pass")
