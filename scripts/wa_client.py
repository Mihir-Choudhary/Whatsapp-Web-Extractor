"""wa_client.py — a minimal WhatsApp linked-device client in Python: log in, keep the connection, send
Signal-encrypted 1:1 messages, receive 1:1 and group messages. Enough for on-demand history and for
capturing what the server holds for the device; nothing else.

Everything the server delivers is written to a journal (JSON lines: the stanza exactly as received after
transport decryption, and each decrypted payload) and synced to disk BEFORE anything is acknowledged.
An acknowledgement makes the server delete the stanza from this device's queue -- the queue the browser
being examined would otherwise receive -- so by default nothing is acknowledged (ack="none"): the server
delivers it again on the next connection. ack="saved" acknowledges a stanza once it is journalled and, for
a message, once every part of it decrypted; what could not be decrypted is never acknowledged.

Builds on wa_reconnect (Noise_XX handshake, login payload, stanza decoder), wa_binary (stanza encoder),
signal_core (the Signal protocol) and wa_proto (protobufs). Networked: it signs in as the linked device
whose credentials it is given, so the account sees activity. Own account / authorised use only.
"""
from __future__ import annotations
import base64, json, os, queue, secrets, threading, time

import wa_reconnect as WR
import wa_binary as WB
import signal_core as SC
import signal_group as SG
import wa_proto as WP

N = WB.node
S_WA = "s.whatsapp.net"


def _addr(jid):
    """libsignal address of a device jid: '<user>.<device>' (as Baileys' jidToSignalProtocolAddress)."""
    user = jid.split("@")[0]
    u, _, dev = user.partition(":")
    return f"{u.split('_')[0]}.{int(dev) if dev else 0}"

def chat_kind(jid):
    """group / status / channel / broadcast list / 1:1, from the chat jid's server."""
    jid = jid or ""
    if jid == "status@broadcast": return "status"
    if jid.endswith("@g.us"): return "group"
    if jid.endswith("@newsletter"): return "channel"
    if jid.endswith("@broadcast"): return "broadcast-list"
    if jid.endswith("@call"): return "call"
    return "1:1"

def stream_error_reason(n):
    """A <stream:error>/<failure> stanza -> one sentence an examiner can act on."""
    a = n.get("attrs") or {}
    kids = [c for c in (n.get("content") or []) if isinstance(c, dict)]
    tags = {c["tag"]: (c.get("attrs") or {}) for c in kids}
    code = str(a.get("code") or a.get("reason") or "")
    if "conflict" in tags:
        return ("another connection signed in as this device and replaced this one (type %s) -- is WhatsApp Web "
                "open in the browser, or a second copy of this tool running?" % tags["conflict"].get("type", "?"))
    if code in ("401",) or "device_removed" in str(tags) or tags.get("conflict", {}).get("type") == "device_removed":
        return "the server says this device is logged out / no longer linked to the account (%s)" % (code or "401")
    if code == "515":
        return "the server asked the client to reconnect (515); nothing was lost -- run again"
    if code == "503":
        return "WhatsApp's server is unavailable (503); try again later"
    return "the server ended the session (%s %s)" % (n.get("tag"), code or sorted(tags))

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
        self.sender_keys = dict(state.get("senderKeys") or {})     # '<group>::<user>::<dev>' -> record

    _save_lock = threading.Lock()                 # the reader thread and the sender both persist the state

    def save(self):
        if not self.path: return
        with self._save_lock:
            self._save()

    def _save(self):
        out = dict(self.state, sessions={a: r.serialize() for a, r in self.sessions.items()},
                   senderKeys=self.sender_keys,
                   preKeys={str(k): {"public": base64.b64encode(v["pubKey"][1:]).decode(),
                                     "private": base64.b64encode(v["privKey"]).decode()}
                            for k, v in self.pre_keys.items()},
                   savedUtc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f: json.dump(out, f)
        for i in range(10):                         # Windows: a scanner or sync client may hold the file briefly
            try: os.replace(tmp, self.path); break
            except PermissionError:
                if i == 9: raise
                time.sleep(0.2)


class Client:
    def __init__(self, creds: dict, signal: SignalState, log=print, journal=None, ack="none"):
        if ack not in ("none", "saved"): raise ValueError("ack must be 'none' or 'saved'")
        self.creds, self.signal, self.log = creds, signal, log
        self.ack_policy = ack
        self._journal = open(journal, "a", encoding="utf-8") if journal else None
        self._last_frame = b""
        self.stream_error = None                # why the server ended the session, if it did
        self.ws = None
        self.noise = None
        self._send_lock = threading.Lock()
        self._crypto_lock = threading.RLock()      # one Signal operation at a time (reader thread vs sender)
        self._iq = {}                          # id -> queue for the reply
        self._msg_id = secrets.token_hex(2)
        self._counter = 0
        self.messages = queue.Queue()          # decrypted inbound messages: dicts
        self.events = queue.Queue()            # other notable stanzas (receipts on our messages, failures)
        self.closed = threading.Event()
        self.ready = threading.Event()
        self.me_lid = (creds.get("lid") or "").split(":")[0].split("@")[0]
        self.me_pn = str(creds.get("user") or "").split(":")[0].split("@")[0]
        self.stats = {"in": 0, "acked": 0, "not_acked": 0, "journalled": 0, "decrypted": 0,
                      "decrypt_failed": 0, "sent": 0}
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
                    if raw: return frame
                    self._last_frame = self.noise.decrypt(frame)
                    return WR.decode_binary_node(self._last_frame)
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

    def journal(self, n, **extra):
        """Append the stanza as received (transport-decrypted binary node, base64) and what was made of it,
        then flush and fsync: on return it is on disk."""
        if self._journal is None: return
        a = n.get("attrs") or {}
        rec = {"received_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tag": n.get("tag"),
               "attrs": {k: str(v) for k, v in a.items()},
               "stanza_b64": base64.b64encode(self._last_frame).decode()}
        rec.update(extra)
        self._journal.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._journal.flush(); os.fsync(self._journal.fileno())
        self.stats["journalled"] += 1

    def settle(self, n, decrypted_ok=True):
        """Acknowledge per policy: only what is journalled, never a message that did not fully decrypt."""
        if self.ack_policy == "saved" and decrypted_ok and self._journal is not None:
            self.ack(n)
        else:
            self.stats["not_acked"] += 1

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
            ok, parts = False, []
            try:
                with self._crypto_lock: ok, parts = self._on_message(n)
            except Exception as e: parts = [{"error": "handler: %s" % e}]
            self.journal(n, decrypted=parts, all_decrypted=ok)
            self.settle(n, ok)
            return
        if tag in ("receipt", "notification"):
            self.journal(n)
            self.events.put(n); self.settle(n); return
        # everything else the server pushes (call offers, presence, chat state, <ib> markers, errors) is kept too
        self.journal(n)
        if tag in ("stream:error", "failure", "xmlstreamend"):
            if tag != "xmlstreamend":
                self.stream_error = stream_error_reason(n)
                self.log("SESSION ENDED BY THE SERVER: " + self.stream_error)
            self.events.put(n); self.closed.set(); return
        self.events.put(n)

    # ---------------------------------------------------------------- Signal
    def _on_message(self, n):
        """Decrypt every <enc> of a message. Returns (all decrypted, [part, ...]); a part carries the
        unpadded plaintext (base64: the protobuf exactly as sent) or the error and the ciphertext."""
        a = n["attrs"]
        sender = a.get("participant") or a.get("from")
        chat = a.get("from") or ""
        kids = [c for c in (n["content"] or []) if isinstance(c, dict)]
        # channel (newsletter) posts are not end-to-end encrypted: the Message protobuf comes in <plaintext>
        encs = [c for c in kids if c["tag"] in ("enc", "plaintext")]
        encs.sort(key=lambda e: e["attrs"].get("type") == "skmsg")   # a key handover first, then what it unlocks
        parts, ok = [], True
        # content the server withholds from linked devices (view-once media: <unavailable type="view_once"/>)
        # arrives as a placeholder with no payload at all
        for u in [c for c in kids if c["tag"] == "unavailable"]:
            parts.append({"enc": None, "unavailable": (u.get("attrs") or {}).get("type") or "unknown"})
            self.tally["unavailable:%s:%s" % (chat_kind(chat), parts[-1]["unavailable"])] += 1
        for enc in encs:
            et = "plaintext" if enc["tag"] == "plaintext" else enc["attrs"].get("type")
            body = bytes(enc["content"] or b"")
            try:
                if et == "plaintext":
                    pt = body
                elif et in ("msg", "pkmsg"):
                    cipher = SC.SessionCipher(self.signal, _addr(sender))
                    pt = (cipher.decrypt_prekey_whisper_message if et == "pkmsg" else cipher.decrypt_whisper_message)(body)
                elif et == "skmsg":
                    pt = SG.GroupCipher(self.signal.sender_keys, SG.sender_key_name(chat, _addr(sender))).decrypt(body)
                else:
                    raise SC.SignalError("unsupported encryption type %r" % et)
                if et != "plaintext": pt = _unpad(pt)
                msg = WP.decode(pt, WP.MESSAGE)
                skdm = msg.get("senderKeyDistributionMessage") or {}
                if skdm.get("axolotlSenderKeyDistributionMessage"):
                    SG.GroupSessionBuilder(self.signal.sender_keys).process(
                        SG.sender_key_name(skdm.get("groupId") or chat, _addr(sender)),
                        bytes(skdm["axolotlSenderKeyDistributionMessage"]))
                self.stats["decrypted"] += 1
                kind = WP.message_type(msg)
                self.tally["message:%s:%s:%s" % (self.sender_kind(sender), chat_kind(chat), kind)] += 1
                parts.append({"enc": et, "type": kind, "plaintext_b64": base64.b64encode(pt).decode()})
                self.messages.put({"from": sender, "chat": chat, "id": a.get("id"), "category": a.get("category"),
                                   "t": a.get("t"), "message": msg})
                if a.get("category") == "peer":
                    self.send(N("receipt", {"id": a.get("id"), "to": a.get("from"), "type": "peer_msg"}))
            except Exception as e:
                ok = False
                self.stats["decrypt_failed"] += 1
                self.tally["undecryptable:%s:%s" % (self.sender_kind(sender), et)] += 1
                parts.append({"enc": et, "error": str(e), "ciphertext_b64": base64.b64encode(body).decode()})
                self.log("could not decrypt %s from %s: %s" % (et, sender, e))
                self.events.put({"tag": "decrypt-failed", "attrs": dict(a, enc_type=et, error=str(e))})
        self.signal.save()
        return ok, parts

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
        with self._crypto_lock:
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
