"""wa_client.py — a minimal WhatsApp linked-device client in Python: log in, keep the connection, send and
receive Signal-encrypted 1:1 messages. Enough for on-demand history; nothing else.

Builds on wa_reconnect (Noise_XX handshake, login payload, stanza decoder), wa_binary (stanza encoder),
signal_core (the Signal protocol) and wa_proto (protobufs). Networked: it signs in as the linked device
whose credentials it is given, so the account sees activity. Own account / authorised use only.
"""
from __future__ import annotations
import base64, json, os, queue, secrets, threading, time

import wa_reconnect as WR
import wa_binary as WB
import signal_core as SC
import wa_proto as WP

N = WB.node
S_WA = "s.whatsapp.net"


def _addr(jid):
    """libsignal address of a device jid: '<user>.<device>' (as Baileys' jidToSignalProtocolAddress)."""
    user = jid.split("@")[0]
    u, _, dev = user.partition(":")
    return f"{u.split('_')[0]}.{int(dev) if dev else 0}"

def _pub33(b):
    return b if len(b) == 33 else b"\x05" + b

def _pad(b):
    n = secrets.randbelow(15) + 1                     # 1..15, as Baileys writeRandomPadMax16
    return b + bytes([n]) * n

def _unpad(b):
    n = b[-1] if b else 0
    if not 0 < n <= 16 or n > len(b): raise ValueError("bad padding")
    return b[:-n]


class SignalState(SC.MemoryStore):
    """signal_core store loaded from export_signal_state.py's JSON, persisted to a runtime file."""
    def __init__(self, state: dict, path: str):
        ident = {"pubKey": _pub33(base64.b64decode(state["signedIdentityKey"]["public"])),
                 "privKey": base64.b64decode(state["signedIdentityKey"]["private"])}
        spk = state["signedPreKey"]
        spks = {int(spk["keyId"]): {"pubKey": _pub33(base64.b64decode(spk["public"])),
                                    "privKey": base64.b64decode(spk["private"])}}
        pks = {int(k): {"pubKey": _pub33(base64.b64decode(v["public"])), "privKey": base64.b64decode(v["private"])}
               for k, v in (state.get("preKeys") or {}).items()}
        sessions = {a: SC.SessionRecord.deserialize(r) for a, r in (state.get("sessions") or {}).items()}
        super().__init__(ident, int(state["registrationId"]), pks, spks, sessions)
        self.path = path
        self.state = state

    def save(self):
        if not self.path: return
        out = dict(self.state, sessions={a: r.serialize() for a, r in self.sessions.items()},
                   preKeys={str(k): {"public": base64.b64encode(v["pubKey"][1:]).decode(),
                                     "private": base64.b64encode(v["privKey"]).decode()}
                            for k, v in self.pre_keys.items()},
                   savedUtc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f: json.dump(out, f)
        os.replace(tmp, self.path)


class Client:
    def __init__(self, creds: dict, signal: SignalState, log=print):
        self.creds, self.signal, self.log = creds, signal, log
        self.ws = None
        self.noise = None
        self._send_lock = threading.Lock()
        self._iq = {}                          # id -> queue for the reply
        self._msg_id = secrets.token_hex(2)
        self._counter = 0
        self.messages = queue.Queue()          # decrypted inbound messages: dicts
        self.events = queue.Queue()            # other notable stanzas (receipts on our messages, failures)
        self.closed = threading.Event()
        self.ready = threading.Event()
        self.me_lid = (creds.get("lid") or "").split(":")[0].split("@")[0]
        self.me_pn = str(creds.get("user") or "").split(":")[0].split("@")[0]
        self.stats = {"in": 0, "acked": 0, "decrypted": 0, "decrypt_failed": 0, "sent": 0}
        # what arrived, counted -- never content: stanza tags, and for messages who sent them and what type
        import collections
        self.tally = collections.Counter()

    # ---------------------------------------------------------------- connection
    def connect(self, timeout=30):
        import websocket
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        c = self.creds
        noise_priv, noise_pub = base64.b64decode(c["noise_priv"]), base64.b64decode(c["noise_pub"])
        eph = X25519PrivateKey.generate()
        eph_priv, eph_pub = eph.private_bytes_raw(), eph.public_key().public_bytes_raw()
        self.noise = WR.Noise(eph_pub)
        version = c.get("wa_version") or WR.FALLBACK_VERSION
        self.ws = websocket.create_connection(WR.WS_URL, timeout=20,
                                              header=["Origin: https://web.whatsapp.com", "User-Agent: Mozilla/5.0"])
        self._inbuf = bytearray(); self._sent_intro = False
        self._raw_send(WR._fld_len(2, WR._fld_len(1, eph_pub)))
        hello = self._read_frame(raw=True, timeout=20)
        sh = WR._pb_read(WR._pb_read(hello)[3][0])
        key_enc = self.noise.process_handshake(sh[1][0], sh[2][0], sh[3][0], noise_priv, noise_pub, eph_priv)
        payload = self.noise.encrypt(WR.build_client_payload(c["user"], int(c.get("device") or 0), version))
        self._raw_send(WR._fld_len(4, WR._fld_len(1, key_enc) + WR._fld_len(2, payload)))
        self.noise.finish()
        deadline = time.time() + timeout
        while time.time() < deadline:
            n = self._read_frame(timeout=max(1, deadline - time.time()))
            if n is None: continue
            if n["tag"] == "success":
                self.success = n["attrs"]; break
            if n["tag"] == "failure":
                raise ConnectionError("login rejected: %s" % n["attrs"])
            self._handle(n)
        else:
            raise TimeoutError("no <success> after login")
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()
        self.ready.set()
        return self.success

    def close(self):
        self.closed.set()
        try: self.ws.close()
        except Exception: pass

    def _raw_send(self, data):
        self.ws.send_binary(self.noise.encode_frame(data, self._sent_intro)); self._sent_intro = True

    def send(self, node):
        with self._send_lock:
            self._raw_send(WB.encode_binary_node(node))

    def _read_frame(self, raw=False, timeout=30):
        import websocket
        while True:
            if len(self._inbuf) >= 3:
                size = (self._inbuf[0] << 16) | (self._inbuf[1] << 8) | self._inbuf[2]
                if len(self._inbuf) >= size + 3:
                    frame = bytes(self._inbuf[3:size + 3]); del self._inbuf[:size + 3]
                    return frame if raw else WR.decode_binary_node(self.noise.decrypt(frame))
            self.ws.settimeout(timeout)
            try:
                self._inbuf.extend(self.ws.recv())
            except websocket.WebSocketTimeoutException:
                return None

    def _reader(self):
        while not self.closed.is_set():
            try:
                n = self._read_frame(timeout=5)
            except Exception as e:
                self.log("connection closed: %s" % e); self.closed.set(); return
            if n is not None:
                try: self._handle(n)
                except Exception as e: self.log("handler error on <%s>: %s" % (n.get("tag"), e))

    def _keepalive(self):
        while not self.closed.wait(25):
            try: self.query(N("iq", {"to": S_WA, "type": "get", "xmlns": "w:p"}, [N("ping")]), timeout=20)
            except Exception as e: self.log("keepalive: %s" % e)

    # ---------------------------------------------------------------- ids, IQs, acks
    def new_id(self):
        self._counter += 1
        return f"{self._msg_id}.{self._counter}"

    @staticmethod
    def message_id():
        return "3EB0" + secrets.token_hex(9).upper()

    def query(self, node, timeout=20):
        node["attrs"].setdefault("id", self.new_id())
        q = queue.Queue(); self._iq[node["attrs"]["id"]] = q
        self.send(node)
        try:
            return q.get(timeout=timeout)
        finally:
            self._iq.pop(node["attrs"]["id"], None)

    def ack(self, n):
        a = n["attrs"]
        attrs = {"id": a.get("id"), "to": a.get("from"), "class": n["tag"]}
        if a.get("participant"): attrs["participant"] = a["participant"]
        if a.get("recipient"): attrs["recipient"] = a["recipient"]
        if n["tag"] != "message" and a.get("type"): attrs["type"] = a["type"]
        self.send(N("ack", attrs)); self.stats["acked"] += 1

    def _handle(self, n):
        tag, a = n["tag"], n["attrs"]
        self.stats["in"] += 1
        self.tally["stanza:" + tag + (":" + a["type"] if tag in ("notification", "receipt") and a.get("type") else "")] += 1
        if tag == "iq":
            if a.get("type") in ("result", "error") and a.get("id") in self._iq:
                self._iq[a["id"]].put(n); return
            if a.get("type") == "get" and a.get("xmlns") == "urn:xmpp:ping":
                self.send(N("iq", {"to": a.get("from", S_WA), "type": "result", "id": a.get("id")})); return
            return
        if tag == "message":
            try: self._on_message(n)
            finally: self.ack(n)
            return
        if tag in ("receipt", "notification"):
            self.events.put(n); self.ack(n); return
        if tag in ("stream:error", "failure", "xmlstreamend"):
            self.events.put(n); self.closed.set(); return
        self.events.put(n)

    # ---------------------------------------------------------------- Signal
    def _on_message(self, n):
        a = n["attrs"]
        sender = a.get("participant") or a.get("from")
        for enc in [c for c in (n["content"] or []) if isinstance(c, dict) and c["tag"] == "enc"]:
            et = enc["attrs"].get("type")
            if et not in ("msg", "pkmsg"):
                self.tally["message:%s:%s (group, not decrypted)" % (self.sender_kind(sender), et)] += 1
                continue                                   # group sender keys are not needed for history
            cipher = SC.SessionCipher(self.signal, _addr(sender))
            try:
                body = bytes(enc["content"])
                pt = (cipher.decrypt_prekey_whisper_message if et == "pkmsg" else cipher.decrypt_whisper_message)(body)
                msg = WP.decode(_unpad(pt), WP.MESSAGE)
                self.stats["decrypted"] += 1
                self.tally["message:%s:%s" % (self.sender_kind(sender), WP.message_type(msg))] += 1
                self.signal.save()
                self.messages.put({"from": sender, "id": a.get("id"), "category": a.get("category"),
                                   "t": a.get("t"), "message": msg})
                if a.get("category") == "peer":
                    self.send(N("receipt", {"id": a.get("id"), "to": a.get("from"), "type": "peer_msg"}))
            except Exception as e:
                self.stats["decrypt_failed"] += 1
                self.tally["undecryptable:%s:%s" % (self.sender_kind(sender), et)] += 1
                self.log("could not decrypt %s from %s: %s" % (et, sender, e))
                self.events.put({"tag": "decrypt-failed", "attrs": dict(a, enc_type=et, error=str(e))})

    def sender_kind(self, jid):
        """own-phone / own-other-device / contact / group-member: who a message came from, for the tally."""
        user = (jid or "").split("@")[0]; u, _, dev = user.partition(":")
        if u in (self.me_lid, self.me_pn):
            return "own-phone" if not dev or dev == "0" else "own-device-%s" % dev
        return "contact"

    def fetch_prekey_bundle(self, jid):
        res = self.query(N("iq", {"to": S_WA, "type": "get", "xmlns": "encrypt"},
                           [N("key", {}, [N("user", {"jid": jid})])]))
        def child(nd, tag):
            return next((c for c in (nd.get("content") or []) if isinstance(c, dict) and c["tag"] == tag), None)
        user = child(child(res, "list"), "user")
        if user is None or child(user, "error"):
            raise RuntimeError("no prekey bundle for %s" % jid)
        reg = int.from_bytes(bytes(child(user, "registration")["content"]), "big")
        ident = bytes(child(user, "identity")["content"])
        sk = child(user, "skey"); k = child(user, "key")
        bundle = {"identityKey": _pub33(ident), "registrationId": reg,
                  "signedPreKey": {"keyId": int.from_bytes(bytes(child(sk, "id")["content"]), "big"),
                                   "publicKey": _pub33(bytes(child(sk, "value")["content"])),
                                   "signature": bytes(child(sk, "signature")["content"])}}
        if k is not None:
            bundle["preKey"] = {"keyId": int.from_bytes(bytes(child(k, "id")["content"]), "big"),
                                "publicKey": _pub33(bytes(child(k, "value")["content"]))}
        return bundle

    def ensure_session(self, jid, force=False):
        addr = _addr(jid)
        rec = self.signal.load_session(addr)
        if force or not rec or not rec.have_open_session():
            SC.SessionBuilder(self.signal, addr).init_outgoing(self.fetch_prekey_bundle(jid))
            self.signal.save()
            return True
        return False

    def send_peer(self, jid, message_bytes, attrs=None):
        """Encrypt a Message to one device of our own account and send it as a peer message. -> message id"""
        cipher = SC.SessionCipher(self.signal, _addr(jid))
        enc = cipher.encrypt(_pad(message_bytes))
        self.signal.save()
        content = [N("enc", {"v": "2", "type": enc["type"]}, enc["body"])]
        if enc["type"] == "pkmsg":
            content.append(N("device-identity", {}, base64.b64decode(self.creds["account"])))
        mid = self.message_id()
        self.send(N("message", dict({"to": jid, "id": mid, "type": "text"}, **(attrs or {})), content))
        self.stats["sent"] += 1
        return mid
