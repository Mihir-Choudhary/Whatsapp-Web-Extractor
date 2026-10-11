#!/usr/bin/env python3
"""selftest_signal.py — signal_core against itself and against libsignal-node.

Always: full conversations between two Python parties (session from a prekey bundle, pkmsg then msg,
replies, several ratchet turns, out-of-order delivery, a replayed message refused, a tampered one refused,
a session record surviving serialisation).

With Node and libsignal available (tools/reconnect after `npm install`, or WAWF_XTEST_NODE_MODULES
pointing at a node_modules that has it), the same conversations run between Python and libsignal-node
in both roles, and session records are handed from one implementation to the other mid-conversation.
That is the evidence the port is interchangeable with what Baileys runs.

Run:  python3 scripts/selftest_signal.py        (exit 0 = all cases pass)
"""
import os, sys, json, base64, shutil, subprocess, tempfile, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import signal_core as S

FAIL = []
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)

def py_party(reg_id):
    ident = S.generate_key_pair(); spk = S.generate_key_pair(); pk = S.generate_key_pair()
    store = S.MemoryStore(ident, reg_id, {31: pk}, {7: spk})
    bundle = {"identityKey": ident["pubKey"], "registrationId": reg_id,
              "signedPreKey": {"keyId": 7, "publicKey": spk["pubKey"], "signature": b"\0" * 64},
              "preKey": {"keyId": 31, "publicKey": pk["pubKey"]}}
    return store, bundle

def raises(fn):
    try: fn(); return False
    except Exception: return True

# ---------------------------------------------------------------- Python <-> Python
print("python <-> python")
alice, _ = py_party(1111); bob, bob_bundle = py_party(2222)
S.SessionBuilder(alice, "bob.1").init_outgoing(bob_bundle)
ac, bc = S.SessionCipher(alice, "bob.1"), S.SessionCipher(bob, "alice.1")
m1 = ac.encrypt(b"hello bob"); m2 = ac.encrypt(b"second, before any reply")
check("the first messages carry the session setup (pkmsg)", m1["type"] == "pkmsg" and m2["type"] == "pkmsg")
check("bob decrypts the setup message", bc.decrypt_prekey_whisper_message(m1["body"]) == b"hello bob")
check("...and the second one", bc.decrypt_prekey_whisper_message(m2["body"]) == b"second, before any reply")
check("the used one-time prekey is consumed", 31 not in bob.pre_keys)
r1 = bc.encrypt(b"hi alice")
check("bob's reply is an ordinary message", r1["type"] == "msg")
check("alice decrypts it", ac.decrypt_whisper_message(r1["body"]) == b"hi alice")
check("after a reply alice stops sending setup messages", ac.encrypt(b"x")["type"] == "msg")
# several ratchet turns with out-of-order delivery
ok = True
for turn in range(6):
    sender, receiver = (ac, bc) if turn % 2 == 0 else (bc, ac)
    msgs = [(f"t{turn} m{i}".encode(), sender.encrypt(f"t{turn} m{i}".encode())) for i in range(5)]
    random.shuffle(msgs)
    for pt, m in msgs:
        got = (receiver.decrypt_prekey_whisper_message if m["type"] == "pkmsg" else receiver.decrypt_whisper_message)(m["body"])
        ok &= got == pt
check("six ratchet turns, messages delivered out of order", ok)
late = ac.encrypt(b"replayed")
bc.decrypt_whisper_message(late["body"])
check("a replayed message is refused", raises(lambda: bc.decrypt_whisper_message(late["body"])))
t = ac.encrypt(b"tampered"); body = bytearray(t["body"]); body[-1] ^= 1
check("a tampered message is refused", raises(lambda: bc.decrypt_whisper_message(bytes(body))))
ser = json.loads(json.dumps(alice.load_session("bob.1").serialize()))
alice.store_session("bob.1", S.SessionRecord.deserialize(ser))
check("a session record survives serialisation", bc.decrypt_whisper_message(ac.encrypt(b"after reload")["body"]) == b"after reload")

# ---------------------------------------------------------------- Python <-> libsignal-node
mods = os.environ.get("WAWF_XTEST_NODE_MODULES") or os.path.join(os.path.dirname(HERE), "tools", "reconnect", "node_modules")
node = shutil.which("node") or (r"C:\Program Files\nodejs\node.exe" if os.path.isfile(r"C:\Program Files\nodejs\node.exe") else None)
harness = os.path.join(os.path.dirname(HERE), "tests", "crosscheck", "sig.js")
if not (node and os.path.isdir(os.path.join(mods, "libsignal")) and os.path.isfile(harness)):
    print("\nlibsignal-node not available: cross-implementation cases skipped "
          "(npm install in tools/reconnect, or set WAWF_XTEST_NODE_MODULES)")
else:
    tmp = tempfile.mkdtemp(prefix="wawf_sig_")
    env = dict(os.environ, NODE_PATH=mods)
    def js(state, *a):
        r = subprocess.run([node, harness, os.path.join(tmp, state)] + [str(x) for x in a],
                           capture_output=True, text=True, env=env)
        if r.returncode: raise RuntimeError(r.stderr.strip()[-300:])
        return json.loads(r.stdout)
    b64 = lambda x: base64.b64encode(x).decode()
    def bundle_from_js(d):
        return {"identityKey": base64.b64decode(d["identityKey"]), "registrationId": d["registrationId"],
                "signedPreKey": {"keyId": d["signedPreKey"]["keyId"], "publicKey": base64.b64decode(d["signedPreKey"]["publicKey"]),
                                 "signature": base64.b64decode(d["signedPreKey"]["signature"])},
                "preKey": {"keyId": d["preKey"]["keyId"], "publicKey": base64.b64decode(d["preKey"]["publicKey"])}}
    def js_decrypt(state, a, m):
        return base64.b64decode(js(state, "decrypt", a, m["type"], b64(m["body"]))["plaintext"])
    def py_decrypt(c, m):
        return (c.decrypt_prekey_whisper_message if m["type"] == "pkmsg" else c.decrypt_whisper_message)(m["body"])
    def js_encrypt(state, a, pt):
        r = js(state, "encrypt", a, b64(pt)); return {"type": r["type"], "body": base64.b64decode(r["body"])}
    try:
        print("python (initiator) -> libsignal-node (responder)")
        node_bundle = bundle_from_js(js("n1", "new"))
        py, _ = py_party(3333)
        S.SessionBuilder(py, "node.1").init_outgoing(node_bundle)
        pc = S.SessionCipher(py, "node.1")
        msgs = [pc.encrypt(b"py setup %d" % i) for i in range(3)]
        check("libsignal-node decrypts Python's pkmsg", all(js_decrypt("n1", "py.1", m) == b"py setup %d" % i for i, m in enumerate(msgs)))
        rep = js_encrypt("n1", "py.1", b"node reply")
        check("Python decrypts libsignal-node's reply", rep["type"] == "msg" and py_decrypt(pc, rep) == b"node reply")
        ok = True
        for turn in range(6):
            if turn % 2 == 0:
                ms = [(b"p%d.%d" % (turn, i), pc.encrypt(b"p%d.%d" % (turn, i))) for i in range(4)]; random.shuffle(ms)
                ok &= all(js_decrypt("n1", "py.1", m) == pt for pt, m in ms)
            else:
                ms = [(b"n%d.%d" % (turn, i), js_encrypt("n1", "py.1", b"n%d.%d" % (turn, i))) for i in range(4)]; random.shuffle(ms)
                ok &= all(py_decrypt(pc, m) == pt for pt, m in ms)
        check("six ratchet turns both ways, out of order", ok)

        print("libsignal-node (initiator) -> python (responder)")
        js("n2", "new")
        py2, py2_bundle = py_party(4444)
        bf = os.path.join(tmp, "b.json")
        json.dump({"identityKey": b64(py2_bundle["identityKey"]), "registrationId": 4444,
                   "signedPreKey": {"keyId": 7, "publicKey": b64(py2_bundle["signedPreKey"]["publicKey"]),
                                    "signature": b64(b"\0" * 64)},
                   "preKey": {"keyId": 31, "publicKey": b64(py2_bundle["preKey"]["publicKey"])}}, open(bf, "w"))
        js("n2", "bundle", "py.1", bf)
        pc2 = S.SessionCipher(py2, "node.1")
        nm = [js_encrypt("n2", "py.1", b"node setup %d" % i) for i in range(3)]
        check("Python decrypts libsignal-node's pkmsg", all(m["type"] == "pkmsg" for m in nm)
              and all(py_decrypt(pc2, m) == b"node setup %d" % i for i, m in enumerate(nm)))
        pr = pc2.encrypt(b"python reply")
        check("libsignal-node decrypts Python's reply", pr["type"] == "msg" and js_decrypt("n2", "py.1", pr) == b"python reply")

        print("session records handed between implementations")
        rec = js("n1", "record", "py.1")                    # libsignal's record of the conversation with Python
        nodeside = S.SessionRecord.deserialize(rec)
        check("Python reads a libsignal-node session record", nodeside.get_open_session() is not None)
        # Python takes over libsignal-node's side, keeps talking to the original Python party
        ident_n1 = json.load(open(os.path.join(tmp, "n1")))["identity"]
        take = S.MemoryStore({"pubKey": base64.b64decode(ident_n1["pubKey"]), "privKey": base64.b64decode(ident_n1["privKey"])},
                             4242, sessions={"py.1": nodeside})
        tc = S.SessionCipher(take, "py.1")
        check("...and continues that conversation", py_decrypt(pc, tc.encrypt(b"continued in python")) == b"continued in python"
              and py_decrypt(tc, pc.encrypt(b"answer")) == b"answer")
        rf = os.path.join(tmp, "r.json"); json.dump(take.load_session("py.1").serialize(), open(rf, "w"))
        js("n1", "setrecord", "py.1", rf)
        check("libsignal-node resumes from Python's session record",
              js_decrypt("n1", "py.1", pc.encrypt(b"back to node")) == b"back to node"
              and py_decrypt(pc, js_encrypt("n1", "py.1", b"node again")) == b"node again")
    except Exception as e:
        check("cross-implementation run (%s)" % e, False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all signal cases pass")
