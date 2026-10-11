#!/usr/bin/env python3
"""selftest_capture.py — the linked-device client's receive path, offline: what it keeps and what it
acknowledges.

Stanzas are handed to wa_client.Client._handle as if the server had sent them (no network):
  * every stanza is journalled -- the transport-decrypted bytes and each decrypted payload -- before
    anything is acknowledged, and with the default policy nothing is acknowledged at all;
  * with ack="saved" only fully decrypted messages, and other stanzas once journalled, are acknowledged;
  * a 1:1 message, a group key handover followed by the group message it unlocks (sender side: Baileys'
    group cipher, when Node is available), a status, a channel post (plaintext) are decrypted;
  * a group message whose sender key is unknown is kept as ciphertext and never acknowledged;
  * nothing a contact could see (receipt, presence) is sent.

Run:  python3 scripts/selftest_capture.py        (exit 0 = all cases pass)
"""
import os, sys, json, base64, shutil, subprocess, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import signal_core as S, signal_group as G, wa_client as WC, wa_proto as WP
import queue_capture as QC

FAIL = []
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)

class Store(S.MemoryStore):
    def __init__(self, *a, **k):
        super().__init__(*a, **k); self.sender_keys = {}
    def save(self): pass

def party(reg):
    ident, spk, pk = S.generate_key_pair(), S.generate_key_pair(), S.generate_key_pair()
    st = Store(ident, reg, {31: pk}, {7: spk})
    return st, {"identityKey": ident["pubKey"], "registrationId": reg,
                "signedPreKey": {"keyId": 7, "publicKey": spk["pubKey"], "signature": b"\0" * 64},
                "preKey": {"keyId": 31, "publicKey": pk["pubKey"]}}

def msg_bytes(fields):
    return WP.encode(fields, WP.MESSAGE)

tmp = tempfile.mkdtemp(prefix="wawf_cap_")
def client(ack):
    me, me_bundle = party(1001)
    c = WC.Client({"user": "15550000000", "lid": "99990000000@lid"}, me, log=lambda m: None,
                  journal=os.path.join(tmp, "j_%s.jsonl" % ack), ack=ack)
    c.sent = []
    c.send = lambda node: c.sent.append(node)
    return c, me, me_bundle

def feed(c, node):
    c._last_frame = b"frame:" + (node["attrs"].get("id") or "").encode()
    c._handle(node)

def enc_node(et, body): return {"tag": "enc", "attrs": {"v": "2", "type": et}, "content": body}

for ack in ("none", "saved"):
    print("ack policy: %s" % ack)
    c, me, me_bundle = client(ack)
    # a contact opens a session with us and sends a 1:1 text
    alice, _ = party(2002)
    S.SessionBuilder(alice, "15550000000.0").init_outgoing(me_bundle)
    ac = S.SessionCipher(alice, "15551112222.0")
    alice.sessions["15551112222.0"] = alice.sessions.pop("15550000000.0")
    m1 = ac.encrypt(WC._pad(msg_bytes({"conversation": "hello from alice"})))
    feed(c, {"tag": "message", "attrs": {"id": "A1", "from": "15551112222@s.whatsapp.net", "t": "1760000000",
                                          "type": "text", "notify": "Alice"}, "content": [enc_node(m1["type"], m1["body"])]})
    # a group message from a sender whose key we never got
    feed(c, {"tag": "message", "attrs": {"id": "G0", "from": "123456789-1@g.us", "participant": "15553334444@s.whatsapp.net",
                                          "t": "1760000001", "type": "text"}, "content": [enc_node("skmsg", b"\x33" + b"\x08\x01" + b"\0" * 64)]})
    # a channel post
    feed(c, {"tag": "message", "attrs": {"id": "N1", "from": "120363000000000000@newsletter", "t": "1760000002", "type": "text"},
             "content": [{"tag": "plaintext", "attrs": {}, "content": msg_bytes({"conversation": "channel post"})}]})
    # a receipt for one of our messages
    feed(c, {"tag": "receipt", "attrs": {"id": "X1", "from": "15551112222@s.whatsapp.net", "type": "read", "t": "1760000003"}})

    lines = [json.loads(l) for l in open(os.path.join(tmp, "j_%s.jsonl" % ack), encoding="utf-8")]
    check("every stanza journalled (4)", len(lines) == 4 and c.stats["journalled"] == 4)
    check("the stanza bytes are kept", all(base64.b64decode(l["stanza_b64"]).startswith(b"frame:") for l in lines))
    j = {l["attrs"].get("id"): l for l in lines}
    p = WP.decode(base64.b64decode(j["A1"]["decrypted"][0]["plaintext_b64"]), WP.MESSAGE)
    check("the 1:1 message decrypted and kept as protobuf", p.get("conversation") == "hello from alice")
    check("the unknown-sender group message is kept as ciphertext",
          not j["G0"]["all_decrypted"] and j["G0"]["decrypted"][0].get("ciphertext_b64"))
    check("the channel post is kept", WP.decode(base64.b64decode(j["N1"]["decrypted"][0]["plaintext_b64"]), WP.MESSAGE).get("conversation") == "channel post")
    acks = [n for n in c.sent if n["tag"] == "ack"]
    if ack == "none":
        check("nothing acknowledged", not acks and c.stats["acked"] == 0)
    else:
        ids = {n["attrs"]["id"] for n in acks}
        check("decrypted stanzas acknowledged after saving", {"A1", "N1", "X1"} <= ids)
        check("the undecrypted group message is NOT acknowledged", "G0" not in ids)
    check("no receipt or presence sent", not [n for n in c.sent if n["tag"] in ("receipt", "presence")])
    rows = QC.readable(os.path.join(tmp, "j_%s.jsonl" % ack))
    kinds = {r["id"]: r["chat_kind"] for r in rows}
    check("readable output: chat kinds", kinds.get("A1") == "1:1" and kinds.get("G0") == "group" and kinds.get("N1") == "channel")

print("readable rows: own messages from the phone, reactions")
c, me, me_bundle = client("none")
phone, _ = party(4004)
S.SessionBuilder(phone, "x").init_outgoing(me_bundle)
phone.sessions["15550000000.0"] = phone.sessions.pop("x")
pc = S.SessionCipher(phone, "15550000000.0")
sent =WP.encode({"deviceSentMessage": {"destinationJid": "15551112222@s.whatsapp.net",
                                        "message": {"conversation": "sent from my phone"}}}, WP.MESSAGE)
m = pc.encrypt(WC._pad(sent))
feed(c, {"tag": "message", "attrs": {"id": "S1", "from": "15550000000@s.whatsapp.net", "recipient": "15551112222@s.whatsapp.net",
                                      "t": "1760000020", "type": "text"}, "content": [enc_node(m["type"], m["body"])]})
react = WP.encode({"reactionMessage": {"key": {"remoteJid": "15551112222@s.whatsapp.net", "fromMe": True, "id": "S1"},
                                       "text": "👍"}}, WP.MESSAGE)
m = pc.encrypt(WC._pad(WP.encode({"deviceSentMessage": {"destinationJid": "15551112222@s.whatsapp.net",
                                                        "message": WP.decode(react, WP.MESSAGE)}}, WP.MESSAGE)))
feed(c, {"tag": "message", "attrs": {"id": "S2", "from": "15550000000@s.whatsapp.net", "recipient": "15551112222@s.whatsapp.net",
                                      "t": "1760000021", "type": "reaction"}, "content": [enc_node(m["type"], m["body"])]})
rows = {r["id"]: r for r in QC.readable(os.path.join(tmp, "j_none.jsonl"), own=("15550000000",))}
s1, s2 = rows.get("S1", {}), rows.get("S2", {})
check("an own message from the phone is filed under the chat it went to, marked from me",
      s1.get("chat") == "15551112222@s.whatsapp.net" and s1.get("from_me") is True and s1.get("text") == "sent from my phone")
check("a reaction names the message it reacts to", s2.get("action") == "reaction" and s2.get("target_id") == "S1"
      and s2.get("text") == "👍")

# ---------------------------------------------------------------- group handover + message, sender = Baileys
mods = os.environ.get("WAWF_XTEST_NODE_MODULES") or os.path.join(os.path.dirname(HERE), "tools", "reconnect", "node_modules")
node = shutil.which("node") or (r"C:\Program Files\nodejs\node.exe" if os.path.isfile(r"C:\Program Files\nodejs\node.exe") else None)
grp = os.path.join(os.path.dirname(HERE), "tests", "crosscheck", "grp.mjs")
if not (node and os.path.isdir(os.path.join(mods, "@whiskeysockets", "baileys"))):
    print("\nBaileys not available: group handover case skipped (set WAWF_XTEST_NODE_MODULES)")
else:
    print("group: key handover (1:1) then group messages and a status (Baileys sender)")
    c, me, me_bundle = client("saved")
    payloads = [msg_bytes({"conversation": "group hello"}), msg_bytes({"conversation": "group second"})]
    pf = os.path.join(tmp, "pts.json"); json.dump([base64.b64encode(WC._pad(x)).decode() for x in payloads], open(pf, "w"))
    r = subprocess.run([node, grp, mods, "0", pf], capture_output=True, text=True)
    if r.returncode:
        check("Baileys harness ran (%s)" % r.stderr.strip()[-200:], False)
    else:
        g = json.loads(r.stdout)
        bob, _ = party(3003)
        S.SessionBuilder(bob, "x").init_outgoing(me_bundle)
        bob.sessions["15550001111.0"] = bob.sessions.pop("x")
        bc = S.SessionCipher(bob, "15550001111.0")
        skdm = WP.encode({"senderKeyDistributionMessage": {"groupId": "123456789-1@g.us",
                          "axolotlSenderKeyDistributionMessage": base64.b64decode(g["skdm"])}}, WP.MESSAGE)
        hand = bc.encrypt(WC._pad(skdm))
        # WhatsApp sends the handover and the first group message in ONE stanza (pkmsg + skmsg)
        feed(c, {"tag": "message", "attrs": {"id": "G1", "from": "123456789-1@g.us", "participant": "15550001111@s.whatsapp.net",
                                              "t": "1760000010", "type": "text"},
                 "content": [enc_node("skmsg", base64.b64decode(g["msgs"][0]["body"])), enc_node(hand["type"], hand["body"])]})
        feed(c, {"tag": "message", "attrs": {"id": "G2", "from": "123456789-1@g.us", "participant": "15550001111@s.whatsapp.net",
                                              "t": "1760000011", "type": "text"},
                 "content": [enc_node("skmsg", base64.b64decode(g["msgs"][1]["body"]))]})
        rows = {r["id"]: r for r in QC.readable(os.path.join(tmp, "j_saved.jsonl"))}
        check("handover processed before the group message in the same stanza",
              any(x.get("text") == "group hello" for x in QC.readable(os.path.join(tmp, "j_saved.jsonl")) if x["id"] == "G1"))
        check("the next group message decrypts with the stored key", rows.get("G2", {}).get("text") == "group second")
        check("the sender key is stored under '<group>::<user>::<device>'", "123456789-1@g.us::15550001111::0" in me.sender_keys)
        acks = {n["attrs"]["id"] for n in c.sent if n["tag"] == "ack"}
        check("both group stanzas acknowledged (fully decrypted, ack=saved)", {"G1", "G2"} <= acks)

shutil.rmtree(tmp, ignore_errors=True)
print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all capture cases pass")
