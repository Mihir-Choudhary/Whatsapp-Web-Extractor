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
CLIENTS = []                                      # their journals are closed before tmp is removed (Windows)
def client(ack, name=None, peer_receipts=None):
    me, me_bundle = party(1001)
    c = WC.Client({"user": "15550000000", "lid": "99990000000@lid"}, me, log=lambda m: None,
                  journal=os.path.join(tmp, "j_%s.jsonl" % (name or ack)), ack=ack,
                  peer_receipts=ack != "none" if peer_receipts is None else peer_receipts)
    c.sent = []
    c.send = lambda node: c.sent.append(node)
    CLIENTS.append(c)
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
# a peer message from the phone (category="peer": an app-state key share, a history notification)
peer = pc.encrypt(WC._pad(WP.encode({"conversation": "peer"}, WP.MESSAGE)))
peer_node = {"tag": "message", "attrs": {"id": "P1", "from": "15550000000@s.whatsapp.net", "category": "peer",
                                         "t": "1760000022", "type": "text"}, "content": [enc_node(peer["type"], peer["body"])]}
feed(c, peer_node)
check("a peer message from the phone is not receipted when nothing is acknowledged",
      not [n for n in c.sent if n["tag"] == "receipt"])
c2, _, me_bundle2 = client("none", "peer", peer_receipts=True)     # the history client: answers as WhatsApp Web does
phone2, _ = party(4005)
S.SessionBuilder(phone2, "x").init_outgoing(me_bundle2)
phone2.sessions["15550000000.0"] = phone2.sessions.pop("x")
peer = S.SessionCipher(phone2, "15550000000.0").encrypt(WC._pad(WP.encode({"conversation": "peer"}, WP.MESSAGE)))
feed(c2, dict(peer_node, content=[enc_node(peer["type"], peer["body"])]))
check("with peer receipts on, the phone's peer message gets its peer_msg receipt",
      [n["attrs"].get("type") for n in c2.sent if n["tag"] == "receipt"] == ["peer_msg"])
# an encrypted edit (secretEncryptedMessage) of a message whose secret is in the same capture
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
rows = {r["id"]: r for r in QC.readable(os.path.join(tmp, "j_none.jsonl"), own=("15550000000",))}
s1, s2 = rows.get("S1", {}), rows.get("S2", {})
check("an own message from the phone is filed under the chat it went to, marked from me",
      s1.get("chat") == "15551112222@s.whatsapp.net" and s1.get("from_me") is True and s1.get("text") == "sent from my phone")
check("a reaction names the message it reacts to", s2.get("action") == "reaction" and s2.get("target_id") == "S1"
      and s2.get("text") == "👍")
c, me, me_bundle = client("none", "edit")                 # a fresh device: its one-time prekey is still unused
alice2, _ = party(5005)
S.SessionBuilder(alice2, "x").init_outgoing(me_bundle)
alice2.sessions["15557778888.0"] = alice2.sessions.pop("x")
a2 = S.SessionCipher(alice2, "15557778888.0")
secret = os.urandom(32)
orig = WP.encode({"conversation": "teh original"}, WP.MESSAGE) + bytes([0x9a, 0x02, 34, 0x1a, 32]) + secret   # messageContextInfo{messageSecret}
m = a2.encrypt(WC._pad(orig))
feed(c, {"tag": "message", "attrs": {"id": "O1", "from": "15557778888@s.whatsapp.net", "t": "1760000030", "type": "text"},
         "content": [enc_node(m["type"], m["body"])]})
edited = WP.encode({"protocolMessage": {"key": {"remoteJid": "15557778888@s.whatsapp.net", "fromMe": False, "id": "O1"},
                                        "type": 14, "editedMessage": {"conversation": "the original"}}}, WP.MESSAGE)
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
           info=b"O1" + b"15557778888@s.whatsapp.net" * 2 + b"Message Edit").derive(secret)
iv = os.urandom(12)
inner = (WP.encode({"key": {"remoteJid": "15557778888@s.whatsapp.net", "fromMe": False, "id": "O1"}}, {1: ("key", "m", WP.MESSAGE_KEY)})
         + bytes([0x12]) + WP._varint(len(AESGCM(key).encrypt(iv, edited, None))) + AESGCM(key).encrypt(iv, edited, None)
         + bytes([0x1a, 12]) + iv + bytes([0x20, 2]))
sec = bytes([0x92, 0x05]) + WP._varint(len(inner)) + inner                       # Message field 82
m = a2.encrypt(WC._pad(sec))
feed(c, {"tag": "message", "attrs": {"id": "E1", "from": "15557778888@s.whatsapp.net", "t": "1760000031", "type": "text"},
         "content": [enc_node(m["type"], m["body"])]})
rows = {r["id"]: r for r in QC.readable(os.path.join(tmp, "j_edit.jsonl"), own=("15550000000",))}
e1 = rows.get("E1", {})
check("an encrypted edit is decrypted with the original message's secret",
      (e1.get("action"), e1.get("target_id"), e1.get("text"), e1.get("encrypted_addon")) == ("edit", "O1", "the original", "decrypted"))

print("a further Signal state, tried when the device's own cannot decrypt")
c, me, me_bundle = client("none", "fb")
other, other_bundle = party(6006)                     # a state that holds the session the sender used
bob3, _ = party(7007)
S.SessionBuilder(bob3, "x").init_outgoing(other_bundle)
bob3.sessions["15550000000.0"] = bob3.sessions.pop("x")
m = S.SessionCipher(bob3, "15550000000.0").encrypt(WC._pad(WP.encode({"conversation": "only the other state can read this"}, WP.MESSAGE)))
c.fallbacks.append(("extra state 1", other))
feed(c, {"tag": "message", "attrs": {"id": "F1", "from": "15552223333@s.whatsapp.net", "t": "1760000040", "type": "text"},
         "content": [enc_node(m["type"], m["body"])]})
f1 = {r["id"]: r for r in QC.readable(os.path.join(tmp, "j_fb.jsonl"))}.get("F1", {})
check("the fallback decrypts it and the row says which state did",
      f1.get("text") == "only the other state can read this" and f1.get("decrypted_with") == "extra state 1")

print("why the server ended a session")
check("a replaced connection names the likely cause (the browser open)",
      "WhatsApp Web" in WC.stream_error_reason({"tag": "stream:error", "attrs": {},
                                               "content": [{"tag": "conflict", "attrs": {"type": "replaced"}}]}))
check("a logged-out device says so", "logged out" in WC.stream_error_reason({"tag": "stream:error", "attrs": {"code": "401"}}))
check("a restart request says nothing was lost", "nothing was lost" in WC.stream_error_reason({"tag": "stream:error", "attrs": {"code": "515"}}))
c, me, me_bundle = client("none", "err")
feed(c, {"tag": "stream:error", "attrs": {}, "content": [{"tag": "conflict", "attrs": {"type": "replaced"}}]})
check("the client keeps the reason, journals the stanza and closes",
      c.stream_error and c.closed.is_set() and c.stats["journalled"] == 1)

print("queue rows as merged into the export")
h = QC.as_history([
    {"id": "T1", "chat": "1@g.us", "chat_kind": "group", "from_me": False, "sender": "9:3@lid", "push_name": "P",
     "t": 5, "status": "decrypted", "type": "conversation", "text": "hi"},
    {"id": "R1", "chat": "1@g.us", "chat_kind": "group", "from_me": False, "sender": "9@lid", "t": 6,
     "status": "decrypted", "type": "reactionMessage", "action": "reaction", "text": "x"},
    {"id": "K1", "chat": "1@g.us", "chat_kind": "group", "sender": "9@lid", "t": 7, "status": "decrypted",
     "type": "senderKeyDistributionMessage"},
    {"id": "V1", "chat": "8@lid", "chat_kind": "1:1", "from_me": False, "sender": "8@lid", "t": 8,
     "status": "withheld from linked devices (view_once)"},
    {"id": "N1", "chat": "1@g.us", "chat_kind": "group", "sender": "9@lid", "t": 9, "status": "not decrypted"}])["messages"]
ids_ = [m["id"] for m in h]
check("messages kept; reactions, key handovers and undecrypted rows left out", ids_ == ["T1", "V1"])
check("a group message names its sender without the device", h[0]["participant"] == "9@lid" and h[0]["source"] == "server-queue")
check("a view-once stub is kept and says so", "view-once" in h[1]["text"])

# ---------------------------------------------------------------- group handover + message, sender = Baileys
mods = os.environ.get("WAWF_XTEST_NODE_MODULES") or os.path.join(os.path.dirname(HERE), "tools", "reconnect", "node_modules")
node = shutil.which("node") or (r"C:\Program Files\nodejs\node.exe" if os.path.isfile(r"C:\Program Files\nodejs\node.exe") else None)
grp = os.path.join(os.path.dirname(HERE), "tests", "crosscheck", "grp.mjs")
if not (node and os.path.isdir(os.path.join(mods, "@whiskeysockets", "baileys"))):
    print("\nBaileys not available: group handover case skipped (set WAWF_XTEST_NODE_MODULES)")
    if os.environ.get("WAWF_XTEST_REQUIRE"):          # CI installs them: a skip there is a failure
        FAIL.append("Baileys not available (WAWF_XTEST_REQUIRE is set)"); print("  FAIL Baileys not available (WAWF_XTEST_REQUIRE is set)")
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

print("\nsending to the account's phone when the session has to be started (prekey message)")
import wa_reconnect as WR
ACCOUNT = {"details": base64.b64encode(b"details-bytes").decode(),
           "accountSignatureKey": base64.b64encode(b"\x05" + b"k" * 32).decode(),
           "accountSignature": base64.b64encode(b"s" * 64).decode(),
           "deviceSignature": base64.b64encode(b"d" * 64).decode()}   # as cmd_creds writes creds_in.json
c, me, _b = client("none", name="pkmsg")
c.creds["account"] = ACCOUNT
phone, phone_bundle = party(4242)
S.SessionBuilder(me, "99990000000.0").init_outgoing(phone_bundle)    # a new session: its first message is a pkmsg
try:
    c.send_peer("99990000000@lid", b"\x0a\x01x")
    sent = c.sent[-1]
    kinds = [(x["tag"], (x.get("attrs") or {}).get("type")) for x in sent["content"]]
    ident = next((x["content"] for x in sent["content"] if x["tag"] == "device-identity"), None)
    got = WR._pb_read(ident) if ident else {}
    check("a prekey message is sent with the device's identity", ("enc", "pkmsg") in kinds and ident is not None)
    check("the identity is the signed device identity protobuf (details, key, account and device signatures)",
          [got.get(i, [None])[0] for i in (1, 2, 3, 4)] ==
          [base64.b64decode(ACCOUNT[k]) for k in ("details", "accountSignatureKey", "accountSignature", "deviceSignature")])
except Exception as e:
    check("a prekey message can be sent (%s: %s)" % (type(e).__name__, e), False)

print("\nstarting a session with the phone before the first request (ensure_session)")
# The reader thread decrypts under the crypto lock; ensure_session must read and change the same state
# under it too, but fetch the bundle OUTSIDE it -- the bundle's reply is delivered by the reader thread.
c, me, _b = client("none", name="ensure")
phone, phone_bundle = party(4343)
seen = {"load_locked": [], "fetch_locked": None, "fetches": 0}
_load = me.load_session
def _spy_load(addr):
    seen["load_locked"].append(c._crypto_lock._is_owned()); return _load(addr)
me.load_session = _spy_load
def _spy_fetch(jid):
    seen["fetches"] += 1; seen["fetch_locked"] = c._crypto_lock._is_owned(); return phone_bundle
c.fetch_prekey_bundle = _spy_fetch
OWN = "99990000000@lid"
started = c.ensure_session(OWN)
rec = _load(WC._addr(OWN))
check("no session yet: one is started from the phone's prekey bundle",
      started is True and rec is not None and rec.get_open_session().registrationId == 4343)
check("the Signal state is read and changed under the crypto lock",
      bool(seen["load_locked"]) and all(seen["load_locked"]))
check("...and the bundle is fetched outside it (the reader thread delivers the reply)", seen["fetch_locked"] is False)
check("a session already open: nothing is fetched, nothing replaced",
      c.ensure_session(OWN) is False and seen["fetches"] == 1)
# the phone opens a session itself while the bundle is on its way: that one is kept, not replaced
c2, me2, _b2 = client("none", name="ensure2")
def _phone_starts_meanwhile(jid):
    S.SessionBuilder(me2, WC._addr(jid)).init_outgoing(party(4444)[1])   # what the reader thread did meanwhile
    return phone_bundle
c2.fetch_prekey_bundle = _phone_starts_meanwhile
kept = c2.ensure_session(OWN)
rec2 = me2.load_session(WC._addr(OWN))
check("a session the device started meanwhile is kept, not replaced",
      kept is False and rec2.get_open_session().registrationId == 4444
      and not any(s.registrationId == 4343 for s in rec2.sessions.values()))

print("\nthe phone cannot decrypt a request and sends a retry receipt")
# The .exe's --history (2026-10-18): the session in the browser profile's Signal state was one the phone no
# longer held. The phone answered each of the 4 requests with <receipt type="retry"> (count 1, its
# registration, no keys); the client ignored them, so every request timed out and the run blamed the phone.
# Here the phone is a real Signal party: it decrypts what the client sends, or answers with a retry receipt.
import queue as _queue, threading as _threading, history_extract as HX
PHONE_JID, ME_ADDR = "99990000000@lid", "99990000000.45"     # the phone, and this device as the phone names it

class Phone:
    def __init__(self, c, me_bundle, keys_in_receipt=False):
        self.st, _ = party(5151)
        self.c, self.keys_in_receipt, self.next_pk = c, keys_in_receipt, 40
        self.got, self.retries_sent, self.fetches, self.answer, self.broken = [], [], 0, True, False
        S.SessionBuilder(self.st, ME_ADDR).init_outgoing(me_bundle)      # the phone and this device talk ...
        self.say("hello")                                                 # ... both ways: the client now sends msg
        c.fetch_prekey_bundle = self.bundle
    def fresh_bundle(self):
        pk = S.generate_key_pair(); self.next_pk += 1; self.st.pre_keys[self.next_pk] = pk
        sp = self.st.signed_pre_keys[7]
        return {"identityKey": self.st.identity["pubKey"], "registrationId": 5151,
                "signedPreKey": {"keyId": 7, "publicKey": sp["pubKey"], "signature": b"\0" * 64},
                "preKey": {"keyId": self.next_pk, "publicKey": pk["pubKey"]}}
    def bundle(self, jid):
        self.fetches += 1; return self.fresh_bundle()
    def say(self, text, extra=None):
        m = S.SessionCipher(self.st, ME_ADDR).encrypt(WC._pad(WP.encode(extra or {"conversation": text}, WP.MESSAGE)))
        feed(self.c, {"tag": "message", "attrs": {"id": "PH%d" % len(self.got), "from": PHONE_JID, "category": "peer",
                                                  "t": "1760000100", "type": "text"}, "content": [enc_node(m["type"], m["body"])]})
    def forget(self):
        self.st.sessions.clear()             # the phone no longer holds the session the client's state has
    def receive(self, node):
        if node["tag"] != "message": return
        enc = next(x for x in node["content"] if x["tag"] == "enc")
        cipher = S.SessionCipher(self.st, ME_ADDR)
        try:
            if self.broken: raise S.SignalError("this phone never decrypts")
            pt = (cipher.decrypt_prekey_whisper_message if enc["attrs"]["type"] == "pkmsg"
                  else cipher.decrypt_whisper_message)(bytes(enc["content"]))
        except Exception:
            count = len([r for r in self.retries_sent if r == node["attrs"]["id"]]) + 1
            self.retries_sent.append(node["attrs"]["id"])
            kids = [{"tag": "retry", "attrs": {"count": str(count), "id": node["attrs"]["id"], "t": "1760000101", "v": "1"}},
                    {"tag": "registration", "attrs": {}, "content": (5151).to_bytes(4, "big")}]
            if self.keys_in_receipt:
                b = self.fresh_bundle(); i3 = lambda v: v.to_bytes(3, "big")
                kids.append({"tag": "keys", "attrs": {}, "content": [
                    {"tag": "type", "attrs": {}, "content": b"\x05"},
                    {"tag": "identity", "attrs": {}, "content": b["identityKey"][1:]},
                    {"tag": "key", "attrs": {}, "content": [{"tag": "id", "attrs": {}, "content": i3(b["preKey"]["keyId"])},
                                                           {"tag": "value", "attrs": {}, "content": b["preKey"]["publicKey"][1:]}]},
                    {"tag": "skey", "attrs": {}, "content": [{"tag": "id", "attrs": {}, "content": i3(7)},
                                                            {"tag": "value", "attrs": {}, "content": b["signedPreKey"]["publicKey"][1:]},
                                                            {"tag": "signature", "attrs": {}, "content": b"\0" * 64}]}]})
            feed(self.c, {"tag": "receipt", "attrs": {"id": node["attrs"]["id"], "from": PHONE_JID, "type": "retry",
                                                      "category": "peer", "t": "1760000101"}, "content": kids})
            return
        self.got.append((node, WP.decode(WC._unpad(pt), WP.MESSAGE)))
        if self.answer:                       # the phone's answer: a history notification for this request
            self.say(None, {"protocolMessage": {"type": 5, "historySyncNotification": {
                "peerDataRequestSessionId": node["attrs"]["id"], "syncType": 6}}})

def retry_client(name, keys_in_receipt=False):
    c, me, me_bundle = client("none", name=name, peer_receipts=False)
    c.creds["account"] = ACCOUNT
    c.run_async = lambda f, *args: f(*args)
    ph = Phone(c, me_bundle, keys_in_receipt)
    out = _queue.Queue()
    c.send = lambda node: (c.sent.append(node), out.put(node))
    def wire():                               # the server: delivers what the client sends to the phone, in order
        while True:
            node = out.get()
            if node is None: return
            ph.receive(node)
    _threading.Thread(target=wire, daemon=True).start()
    while not c.messages.empty(): c.messages.get()       # the phone's hello
    return c, me, ph, out

def wait_for(cond, secs=5):
    import time as _t
    end = _t.time() + secs
    while not cond() and _t.time() < end: _t.sleep(0.02)
    return cond()

c, me, ph, wire = retry_client("retry")
ph.forget()
req = WP.history_request("15551112222@s.whatsapp.net", "OLD1", False, 50, 1700000000)
mid = c.send_peer(PHONE_JID, req, {"category": "peer", "push_priority": "high_force", "privacy_sensitive": "1"})
check("the request goes out on the old session (msg) and the phone cannot decrypt it",
      wait_for(lambda: ph.retries_sent == [mid]) and c.sent[0]["content"][0]["attrs"]["type"] == "msg")
check("the client sends it again: same id, a prekey message on a new session, retry count, device identity",
      wait_for(lambda: len(ph.got) == 1) and ph.got[0][0]["attrs"]["id"] == mid
      and [x["tag"] for x in ph.got[0][0]["content"]] == ["enc", "device-identity"]
      and ph.got[0][0]["content"][0]["attrs"].get("type") == "pkmsg" and ph.got[0][0]["content"][0]["attrs"].get("count") == "1")
check("...the same request the phone could not read, to the phone only, with the original attributes",
      ph.got and ph.got[0][1] == WP.decode(req, WP.MESSAGE)
      and {k: ph.got[0][0]["attrs"].get(k) for k in ("to", "category", "push_priority", "privacy_sensitive", "device_fanout")}
      == {"to": PHONE_JID, "category": "peer", "push_priority": "high_force", "privacy_sensitive": "1", "device_fanout": "false"})
check("the new session came from the phone's prekey bundle on the server (no keys in the receipt)", ph.fetches == 1)
mid2 = c.send_peer(PHONE_JID, req, {"category": "peer"})
check("the next request goes out on the new session and the phone reads it at once",
      wait_for(lambda: len(ph.got) == 2) and ph.retries_sent == [mid] and ph.fetches == 1)
check("counted: one retry receipt, one resend", c.stats.get("retry_receipts") == 1 and c.stats.get("resent") == 1
      and set(getattr(c, "retry_asked", {})) == {mid})

# the receipt carries the phone's keys: the session is started from them, nothing is fetched
c, me, ph, wire = retry_client("retry_keys", keys_in_receipt=True)
ph.forget()
mid = c.send_peer(PHONE_JID, req, {"category": "peer"})
check("keys in the retry receipt: the new session is started from them and the phone reads the resend",
      wait_for(lambda: len(ph.got) == 1) and ph.got[0][0]["attrs"]["id"] == mid and ph.fetches == 0)

# a phone that keeps failing: sent again at most RETRY_MAX times
c, me, ph, wire = retry_client("retry_cap")
ph.broken = True
mid = c.send_peer(PHONE_JID, req, {"category": "peer"})
wait_for(lambda: len(ph.retries_sent) > getattr(WC, "RETRY_MAX", 5), secs=3)
check("a device that never decrypts it gets it again at most RETRY_MAX (5) times",
      ph.retries_sent.count(mid) == getattr(WC, "RETRY_MAX", 5) + 1 and c.stats.get("resent") == getattr(WC, "RETRY_MAX", 5))

# retry receipts the client does not answer: a message it never sent, a device of another account
c, me, ph, wire = retry_client("retry_other")
n_before = len(c.sent)
feed(c, {"tag": "receipt", "attrs": {"id": "3EB0NOTOURS", "from": PHONE_JID, "type": "retry"},
         "content": [{"tag": "retry", "attrs": {"count": "1", "id": "3EB0NOTOURS"}}]})
mid = c.send_peer(PHONE_JID, req, {"category": "peer"})            # read by the phone: not lost, no retry
wait_for(lambda: len(ph.got) == 1)
feed(c, {"tag": "receipt", "attrs": {"id": mid, "from": "15553334444@s.whatsapp.net", "type": "retry"},
         "content": [{"tag": "retry", "attrs": {"count": "1", "id": mid}}]})
check("a retry receipt for a message the client did not send, or from a contact, is not answered",
      len([n for n in c.sent if n["tag"] == "message"]) == 1 and ph.fetches == 0 and c.stats.get("resent", 0) == 0)

print("\nthe history client waits for the answer to a request it had to send again")
def history_run(c):
    r = HX.Run.__new__(HX.Run)
    r.c, r.own = c, PHONE_JID
    r.pending, r.our_ids, r.late_seen = {}, set(), set()
    r.late = r.late_msgs = r.late_ours = 0
    r.asked_again, r.unreadable, r.last_unreadable = set(), set(), None
    r.write_out = lambda: (0, 0, 0)
    r.on_notification = lambda n, m: (n.get("peerDataRequestSessionId"), [{"id": "H1", "chat": "x", "ts": 1}])
    return r
c, me, ph, wire = retry_client("retry_history")
ph.forget()
r = history_run(c)
got = r.request_page({"remoteJid": "15551112222@s.whatsapp.net", "id": "OLD1", "fromMe": False}, 1700000000)
check("a request the phone could not decrypt is answered after it is sent again",
      got == [{"id": "H1", "chat": "x", "ts": 1}] and r.unreadable == set() and len(r.asked_again) == 1)
ph.answer = False
ph.forget()
_t0 = HX.REQ_TIMEOUT; HX.REQ_TIMEOUT = 1.0
try:
    got = r.request_page({"remoteJid": "15551112222@s.whatsapp.net", "id": "OLD1", "fromMe": False}, 1700000000)
finally:
    HX.REQ_TIMEOUT = _t0
check("one it could not decrypt and that stays unanswered is named as such, not as the phone's silence",
      got is None and len(r.unreadable) == 1 and "could not decrypt" in (r.last_unreadable or ""))
# the phone's keys cannot be fetched: the request is not sent again, and nothing may say it was
c, me, ph, wire = retry_client("retry_nofetch")
ph.forget()
def _no_bundle(jid): raise RuntimeError("no prekey bundle for %s" % jid)
c.fetch_prekey_bundle = _no_bundle
r = history_run(c)
_t0 = HX.REQ_TIMEOUT; HX.REQ_TIMEOUT = 1.0
try:
    got = r.request_page({"remoteJid": "15551112222@s.whatsapp.net", "id": "OLD1", "fromMe": False}, 1700000000)
finally:
    HX.REQ_TIMEOUT = _t0
check("a request that could not be sent again says so, not that it was",
      got is None and c.stats.get("resend_failed") == 1 and "could not be sent again" in (r.last_unreadable or ""))
r.all, r.ondisk, r.meta = {}, set(), {}
r.start_reached, r.silent, r.answered = set(), set(), set()
r.out, r.meta_path = os.path.join(tmp, "hr.json"), os.path.join(tmp, "hm.json")
HX.Run.write_out(r)
_w = json.load(open(r.out, encoding="utf-8"))
check("...and the pass file counts it apart from the ones sent again",
      (_w.get("requests_unreadable"), _w.get("requests_not_resent")) == (1, 1))

print("\nwhat the client prints about messages it cannot read, and about its own close")
# The live run (2026-10-18): ~1,000 messages held for the browser that this state cannot read are delivered
# again on every connection, and each printed a line -- ~500 a pass, 4,700 in the run, burying the rest.
c, me, _b = client("none", name="flood")
_lines = []; c.log = _lines.append
for i in range(40):
    feed(c, {"tag": "message", "attrs": {"id": "F%d" % i, "from": "1203630000%02d@g.us" % i, "participant": "1555%07d@s.whatsapp.net" % i,
                                          "t": "1760000200", "type": "text"}, "content": [enc_node("skmsg", b"\x33" + b"\x08\x01" + b"\0" * 64)]})
_j = [json.loads(x) for x in open(os.path.join(tmp, "j_flood.jsonl"), encoding="utf-8")]
check("40 unreadable messages print 3 lines, the third saying the rest are counted",
      len([x for x in _lines if "could not decrypt" in x]) == 3 and "counted, not printed" in _lines[2])
check("...each one is still in the journal with its error and ciphertext",
      len(_j) == 40 and all(x["decrypted"][0].get("error") and x["decrypted"][0].get("ciphertext_b64") for x in _j))
_sum = c.decrypt_failure_summary()
check("...and the summary counts them by kind, without who sent them",
      _sum.startswith("40 message part(s) could not be decrypted") and "x40" in _sum and "1555" not in _sum and "@" not in _sum)
check("a client that read everything has no summary", client("none", name="nofail")[0].decrypt_failure_summary() == "")
# Every pass ended with "connection closed: Connection to remote host was lost." -- the client's own close()
c, me, _b = client("none", name="close")
_lines = []; c.log = _lines.append
def _recv_after_close(timeout=5):
    c.closed.set(); raise ConnectionError("Connection to remote host was lost.")
c._read_frame = _recv_after_close; c._reader()
check("the client closing its own connection prints nothing", _lines == [])
c.closed.clear()
def _dropped(timeout=5): raise ConnectionError("Connection to remote host was lost.")
c._read_frame = _dropped; c._reader()
check("...a connection the server dropped is still reported", any("connection closed" in x for x in _lines))

print("\na system event the phone serves in history")
# One history row in the live run was a group system event (no payload, fromMe, naming another member):
# the Python client typed it "unknown", so the export showed a message by someone else sent as mine.
import wa_decrypt as WD, types
_hs = {"conversations": [{"id": "120363000000000001@g.us", "messages": [
    {"message": {"key": {"remoteJid": "120363000000000001@g.us", "fromMe": True, "id": "STUB1"},
                 "participant": "15553334444@s.whatsapp.net", "messageTimestamp": 1700000000, "messageStubType": 27}},
    {"message": {"key": {"remoteJid": "120363000000000001@g.us", "fromMe": False, "id": "M1",
                         "participant": "15553334444@s.whatsapp.net"},
                 "messageTimestamp": 1700000001, "message": {"conversation": "hi"}}}]}]}
_rows = {r["id"]: r for r in HX.flatten(_hs)}
check("a record with no payload is typed as a system event, with its stub type",
      _rows["STUB1"]["type"] == "?" and _rows["STUB1"].get("stub_type") == 27 and _rows["M1"]["type"] == "conversation")
check("...and the export types it as a notification",
      WD.hist_type(_rows["STUB1"]["type"]) == "notification")
_ids = types.SimpleNamespace(me={"15550000000@s.whatsapp.net"}, entry=lambda j: {}, is_me=lambda j: j in {"15550000000@s.whatsapp.net"},
                             source=lambda j: "unresolved", label=lambda j: j)
_old = {"chat": "120363000000000001@g.us", "id": "STUB0", "fromMe": True, "participant": "15553334444@s.whatsapp.net",
        "ts": 1700000000, "text": "", "type": "unknown"}
check("a row banked before the fix ('unknown', nothing undecoded) is read as the system event it is",
      WD.hist_row(_old, _ids, "2023-11-14 22:13:20")["type"] == "notification")
check("...while one the client could not decode stays 'unknown'",
      WD.hist_row(dict(_old, undecoded={"reason": "empty message"}), _ids, "2023-11-14 22:13:20")["type"] == "unknown")

# key material is written owner-only: the Signal state the client persists, and any file open_private writes
import stat, idbutil
rt = os.path.join(tmp, "signal_runtime.py.json")
_b = lambda x: base64.b64encode(x).decode()
_id, _spk = S.generate_key_pair(), S.generate_key_pair()
WC.SignalState({"registrationId": 77, "signedIdentityKey": {"public": _b(_id["pubKey"]), "private": _b(_id["privKey"])},
                "signedPreKey": {"keyId": 1, "public": _b(_spk["pubKey"]), "private": _b(_spk["privKey"])},
                "preKeys": {}, "sessions": {}, "senderKeys": {}}, rt).save()
loose = os.path.join(tmp, "creds_in.json")
with open(loose, "w") as fh: fh.write("{}")
os.chmod(loose, 0o644)                                       # an earlier version's file, as the umask left it
with idbutil.open_private(loose) as fh: fh.write('{"noise_priv": "x"}')
if os.name == "posix":
    check("the persisted Signal state is readable by its owner only (0600)",
          stat.S_IMODE(os.stat(rt).st_mode) == 0o600)
    check("an existing key file is tightened to 0600 when it is rewritten",
          stat.S_IMODE(os.stat(loose).st_mode) == 0o600)
else:
    check("the persisted Signal state is written", json.load(open(rt)).get("sessions") == {})
check("open_private writes the whole content", json.load(open(loose)) == {"noise_priv": "x"})

for c in CLIENTS: c._journal.close()
shutil.rmtree(tmp, ignore_errors=True)
print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all capture cases pass")
