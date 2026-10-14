"""signal_core.py — the Signal 1:1 protocol as WhatsApp clients speak it, in Python.

A port of the `libsignal` package Baileys uses (WhiskeySockets' libsignal-node 6.x): X3DH session setup
in both directions, the Double Ratchet, WhisperMessage / PreKeyWhisperMessage encryption and decryption.
It is written to be interchangeable with it:

  * session records serialise to the same JSON shape (SessionRecord.serialize: `_sessions` keyed by base
    key, `currentRatchet`, `indexInfo`, `_chains`, `pendingPreKey`, `version: "v1"`), so a record can move
    between this module and libsignal-node, and the tool's existing signal_runtime.json keeps working;
  * every byte that is MACed or sent is laid out as libsignal lays it out.

Interoperability is tested against libsignal-node itself (scripts/selftest_signal.py): messages encrypted
by one are decrypted by the other, in both directions, including session setup.

Only what WhatsApp's 1:1 path needs is here: no sender keys (groups), no signing of prekeys (the
browser's own signed prekey is reused), and identity keys are trusted as libsignal's Baileys store does.
"""
from __future__ import annotations
import base64, hmac, hashlib, os, time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.primitives import serialization

VERSION = 3
CLOSED_SESSIONS_MAX = 40
BASE_OURS, BASE_THEIRS = 1, 2
CHAIN_SENDING, CHAIN_RECEIVING = 1, 2
KEY_TYPE = b"\x05"


class SignalError(Exception): pass
class SessionError(SignalError): pass
class MessageCounterError(SignalError): pass
class PreKeyError(SignalError): pass


def _b64(b): return base64.b64encode(b).decode() if b is not None else None
def _unb64(s): return base64.b64decode(s) if s is not None else None
def _now_ms(): return int(time.time() * 1000)


# ---------------------------------------------------------------- primitives (crypto.js, curve.js)
def hmac256(key, data): return hmac.new(key, data, hashlib.sha256).digest()

def derive_secrets(input_, salt, info, chunks=3):
    """libsignal's HKDF: RFC 5869 with a 32-byte salt, returning the first 1-3 32-byte blocks."""
    if len(salt) != 32: raise ValueError("Got salt of incorrect length")
    prk = hmac256(salt, input_)
    out, prev = [], b""
    for i in range(1, chunks + 1):
        prev = hmac256(prk, prev + info + bytes([i]))
        out.append(prev)
    return out

def aes_cbc_encrypt(key, data, iv):
    p = _padding.PKCS7(128).padder(); data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()

def aes_cbc_decrypt(key, data, iv):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = d.update(data) + d.finalize()
    u = _padding.PKCS7(128).unpadder()
    return u.update(out) + u.finalize()

def generate_key_pair():
    """{'pubKey': 33 bytes (0x05 + X25519), 'privKey': 32 bytes} — libsignal's key-pair shape."""
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"pubKey": KEY_TYPE + pub, "privKey": priv}

def _scrub(pub):
    if len(pub) == 33 and pub[0] == 5: return pub[1:]
    if len(pub) == 32: return pub
    raise ValueError("Invalid public key")

def calculate_agreement(pub, priv):
    if len(priv) != 32: raise ValueError("Incorrect private key length")
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(_scrub(pub)))


# ---------------------------------------------------------------- protobufs (WhisperTextProtocol)
def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def _read_varint(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1; r |= (c & 0x7F) << s
        if not c & 0x80: return r, i
        s += 7

def _encode(fields):
    """[(field number, value)] in field order; ints as uint32 varints, bytes length-delimited."""
    out = bytearray()
    for f, v in sorted(fields, key=lambda x: x[0]):
        if v is None: continue
        if isinstance(v, int): out += _varint(f << 3) + _varint(v & 0xFFFFFFFF)
        else: out += _varint(f << 3 | 2) + _varint(len(v)) + bytes(v)
    return bytes(out)

def _decode(b):
    out, i = {}, 0
    while i < len(b):
        tag, i = _read_varint(b, i); f, wt = tag >> 3, tag & 7
        if wt == 0: v, i = _read_varint(b, i)
        elif wt == 2:
            n, i = _read_varint(b, i); v = bytes(b[i:i + n]); i += n
        elif wt == 5: v = b[i:i + 4]; i += 4
        elif wt == 1: v = b[i:i + 8]; i += 8
        else: raise SignalError("bad wire type")
        out[f] = v
    return out

def encode_whisper(ephemeral_key, counter, previous_counter, ciphertext):
    return _encode([(1, ephemeral_key), (2, counter), (3, previous_counter), (4, ciphertext)])

def decode_whisper(b):
    d = _decode(b)
    return {"ephemeralKey": d.get(1), "counter": d.get(2, 0), "previousCounter": d.get(3, 0), "ciphertext": d.get(4)}

def encode_prekey_whisper(pre_key_id, base_key, identity_key, message, registration_id, signed_pre_key_id):
    return _encode([(1, pre_key_id), (2, base_key), (3, identity_key), (4, message), (5, registration_id),
                    (6, signed_pre_key_id)])

def decode_prekey_whisper(b):
    d = _decode(b)
    return {"preKeyId": d.get(1), "baseKey": d.get(2), "identityKey": d.get(3), "message": d.get(4),
            "registrationId": d.get(5), "signedPreKeyId": d.get(6)}

def _tuple(a, b): return (a << 4) | b


# ---------------------------------------------------------------- session record (session_record.js)
class SessionEntry:
    def __init__(self):
        self.registrationId = None
        self.currentRatchet = None
        self.indexInfo = None
        self.pendingPreKey = None
        self._chains = {}

    def add_chain(self, key, value):
        k = _b64(key)
        if k in self._chains: raise SignalError("Overwrite attempt")
        self._chains[k] = value

    def get_chain(self, key): return self._chains.get(_b64(key))

    def delete_chain(self, key):
        k = _b64(key)
        if k not in self._chains: raise SignalError("Not Found")
        del self._chains[k]

    def serialize(self):
        r = self.currentRatchet; ii = self.indexInfo
        data = {
            "registrationId": self.registrationId,
            "currentRatchet": {
                "ephemeralKeyPair": {"pubKey": _b64(r["ephemeralKeyPair"]["pubKey"]),
                                     "privKey": _b64(r["ephemeralKeyPair"]["privKey"])},
                "lastRemoteEphemeralKey": _b64(r["lastRemoteEphemeralKey"]),
                "previousCounter": r["previousCounter"],
                "rootKey": _b64(r["rootKey"])},
            "indexInfo": {"baseKey": _b64(ii["baseKey"]), "baseKeyType": ii["baseKeyType"], "closed": ii["closed"],
                          "used": ii["used"], "created": ii["created"],
                          "remoteIdentityKey": _b64(ii["remoteIdentityKey"])},
            "_chains": {k: {"chainKey": {"counter": c["chainKey"]["counter"],
                                         **({"key": _b64(c["chainKey"]["key"])} if c["chainKey"].get("key") is not None else {})},
                            "chainType": c["chainType"],
                            "messageKeys": {str(i): _b64(mk) for i, mk in c["messageKeys"].items()}}
                        for k, c in self._chains.items()},
        }
        if self.pendingPreKey:
            data["pendingPreKey"] = dict(self.pendingPreKey, baseKey=_b64(self.pendingPreKey["baseKey"]))
        return data

    @classmethod
    def deserialize(cls, d):
        e = cls()
        e.registrationId = d.get("registrationId")
        r = d["currentRatchet"]
        e.currentRatchet = {
            "ephemeralKeyPair": {"pubKey": _unb64(r["ephemeralKeyPair"]["pubKey"]),
                                 "privKey": _unb64(r["ephemeralKeyPair"]["privKey"])},
            "lastRemoteEphemeralKey": _unb64(r["lastRemoteEphemeralKey"]),
            "previousCounter": r["previousCounter"], "rootKey": _unb64(r["rootKey"])}
        ii = d["indexInfo"]
        e.indexInfo = {"baseKey": _unb64(ii["baseKey"]), "baseKeyType": ii["baseKeyType"], "closed": ii["closed"],
                       "used": ii.get("used"), "created": ii.get("created"),
                       "remoteIdentityKey": _unb64(ii["remoteIdentityKey"])}
        e._chains = {k: {"chainKey": {"counter": c["chainKey"]["counter"], "key": _unb64(c["chainKey"].get("key"))},
                         "chainType": c["chainType"],
                         "messageKeys": {int(i): _unb64(mk) for i, mk in c["messageKeys"].items()}}
                     for k, c in d.get("_chains", {}).items()}
        if d.get("pendingPreKey"):
            e.pendingPreKey = dict(d["pendingPreKey"], baseKey=_unb64(d["pendingPreKey"]["baseKey"]))
        return e


class SessionRecord:
    def __init__(self):
        self.sessions = {}
        self.version = "v1"

    @classmethod
    def deserialize(cls, data):
        rec = cls()
        if data.get("version") != "v1":                 # libsignal's v1 migration: fill registrationId
            reg = data.get("registrationId")
            for s in (data.get("_sessions") or {}).values():
                if reg and not s.get("registrationId"): s["registrationId"] = reg
        for k, v in (data.get("_sessions") or {}).items():
            rec.sessions[k] = SessionEntry.deserialize(v)
        return rec

    def serialize(self):
        return {"_sessions": {k: s.serialize() for k, s in self.sessions.items()}, "version": self.version}

    def have_open_session(self):
        s = self.get_open_session()
        return bool(s) and isinstance(s.registrationId, int)

    def get_session(self, base_key):
        s = self.sessions.get(_b64(base_key))
        if s and s.indexInfo["baseKeyType"] == BASE_OURS:
            raise SignalError("Tried to lookup a session using our basekey")
        return s

    def get_open_session(self):
        for s in self.sessions.values():
            if not self.is_closed(s): return s
        return None

    def set_session(self, s): self.sessions[_b64(s.indexInfo["baseKey"])] = s

    def get_sessions(self):
        return sorted(self.sessions.values(), key=lambda s: -(s.indexInfo.get("used") or 0))

    def close_session(self, s):
        if not self.is_closed(s): s.indexInfo["closed"] = _now_ms()

    def open_session(self, s): s.indexInfo["closed"] = -1

    @staticmethod
    def is_closed(s): return s.indexInfo["closed"] != -1

    def remove_old_sessions(self):
        while len(self.sessions) > CLOSED_SESSIONS_MAX:
            closed = [(k, s) for k, s in self.sessions.items() if s.indexInfo["closed"] != -1]
            if not closed: raise SignalError("Corrupt sessions object")
            k, _ = min(closed, key=lambda kv: kv[1].indexInfo["closed"])
            del self.sessions[k]


# ---------------------------------------------------------------- storage
class MemoryStore:
    """What the cipher needs from a store; subclass or replace to persist.

    identity: {'pubKey': 33 bytes, 'privKey': 32}; registration_id: int; pre_keys / signed_pre_keys:
    {id: key pair}; sessions: {"<user>.<device>": SessionRecord}. Identities are trusted, as Baileys'
    store trusts them.
    """
    def __init__(self, identity, registration_id, pre_keys=None, signed_pre_keys=None, sessions=None):
        self.identity, self.registration_id = identity, registration_id
        self.pre_keys = dict(pre_keys or {}); self.signed_pre_keys = dict(signed_pre_keys or {})
        self.sessions = dict(sessions or {})
    def get_our_identity(self): return self.identity
    def get_our_registration_id(self): return self.registration_id
    def is_trusted_identity(self, addr, key): return True
    def load_session(self, addr): return self.sessions.get(addr)
    def store_session(self, addr, record): self.sessions[addr] = record
    def load_pre_key(self, key_id): return self.pre_keys.get(key_id)
    def remove_pre_key(self, key_id): self.pre_keys.pop(key_id, None)
    def load_signed_pre_key(self, key_id): return self.signed_pre_keys.get(key_id)


# ---------------------------------------------------------------- session setup (session_builder.js)
class SessionBuilder:
    def __init__(self, store, addr):
        self.store, self.addr = store, addr

    def init_outgoing(self, device):
        """device: {'identityKey', 'registrationId', 'signedPreKey': {'keyId','publicKey','signature'},
        'preKey': {'keyId','publicKey'} or None} — a prekey bundle fetched from the server."""
        base_key = generate_key_pair()
        dev_pre = (device.get("preKey") or {}).get("publicKey")
        session = self._init_session(True, base_key, None, device["identityKey"], dev_pre,
                                     device["signedPreKey"]["publicKey"], device["registrationId"])
        session.pendingPreKey = {"signedKeyId": device["signedPreKey"]["keyId"], "baseKey": base_key["pubKey"]}
        if device.get("preKey"):
            session.pendingPreKey["preKeyId"] = device["preKey"]["keyId"]
        record = self.store.load_session(self.addr)
        if record is None:
            record = SessionRecord()
        else:
            open_ = record.get_open_session()
            if open_: record.close_session(open_)
        record.set_session(session)
        self.store.store_session(self.addr, record)

    def init_incoming(self, record, msg):
        if record.get_session(msg["baseKey"]):
            return None
        pre = self.store.load_pre_key(msg["preKeyId"]) if msg.get("preKeyId") is not None else None
        if msg.get("preKeyId") and not pre:
            raise PreKeyError("Invalid PreKey ID")
        signed = self.store.load_signed_pre_key(msg["signedPreKeyId"])
        if not signed:
            raise PreKeyError("Missing SignedPreKey")
        open_ = record.get_open_session()
        if open_: record.close_session(open_)
        record.set_session(self._init_session(False, pre, signed, msg["identityKey"], msg["baseKey"], None,
                                              msg["registrationId"]))
        return msg.get("preKeyId")

    def _init_session(self, initiator, our_eph, our_signed, their_identity, their_eph, their_signed, reg_id):
        if initiator:
            if our_signed: raise SignalError("Invalid call to initSession")
            our_signed = our_eph
        else:
            if their_signed: raise SignalError("Invalid call to initSession")
            their_signed = their_eph
        n = 4 if (not our_eph or not their_eph) else 5
        secret = bytearray(32 * n); secret[:32] = b"\xff" * 32
        ident = self.store.get_our_identity()
        a1 = calculate_agreement(their_signed, ident["privKey"])
        a2 = calculate_agreement(their_identity, our_signed["privKey"])
        a3 = calculate_agreement(their_signed, our_signed["privKey"])
        if initiator:
            secret[32:64], secret[64:96] = a1, a2
        else:
            secret[64:96], secret[32:64] = a1, a2
        secret[96:128] = a3
        if our_eph and their_eph:
            secret[128:160] = calculate_agreement(their_eph, our_eph["privKey"])
        master = derive_secrets(bytes(secret), b"\x00" * 32, b"WhisperText")
        s = SessionEntry()
        s.registrationId = reg_id
        s.currentRatchet = {"rootKey": master[0],
                            "ephemeralKeyPair": generate_key_pair() if initiator else our_signed,
                            "lastRemoteEphemeralKey": their_signed, "previousCounter": 0}
        now = _now_ms()
        s.indexInfo = {"created": now, "used": now, "remoteIdentityKey": their_identity,
                       "baseKey": our_eph["pubKey"] if initiator else their_eph,
                       "baseKeyType": BASE_OURS if initiator else BASE_THEIRS, "closed": -1}
        if initiator:
            r = s.currentRatchet
            shared = calculate_agreement(their_signed, r["ephemeralKeyPair"]["privKey"])
            mk = derive_secrets(shared, r["rootKey"], b"WhisperRatchet")
            s.add_chain(r["ephemeralKeyPair"]["pubKey"],
                        {"messageKeys": {}, "chainKey": {"counter": -1, "key": mk[1]}, "chainType": CHAIN_SENDING})
            r["rootKey"] = mk[0]
        return s


# ---------------------------------------------------------------- the cipher (session_cipher.js)
class SessionCipher:
    def __init__(self, store, addr):
        self.store, self.addr = store, addr

    def _record(self):
        return self.store.load_session(self.addr)

    def _store(self, record):
        record.remove_old_sessions()
        self.store.store_session(self.addr, record)

    def encrypt(self, data: bytes):
        """-> {'type': 'pkmsg'|'msg', 'body': bytes, 'registrationId': int}"""
        ident = self.store.get_our_identity()
        record = self._record()
        if not record: raise SessionError("No sessions")
        session = record.get_open_session()
        if not session: raise SessionError("No open session")
        chain = session.get_chain(session.currentRatchet["ephemeralKeyPair"]["pubKey"])
        if chain["chainType"] == CHAIN_RECEIVING: raise SignalError("Tried to encrypt on a receiving chain")
        self._fill(chain, chain["chainKey"]["counter"] + 1)
        ctr = chain["chainKey"]["counter"]
        keys = derive_secrets(chain["messageKeys"][ctr], b"\x00" * 32, b"WhisperMessageKeys")
        del chain["messageKeys"][ctr]
        msg = encode_whisper(session.currentRatchet["ephemeralKeyPair"]["pubKey"], ctr,
                             session.currentRatchet["previousCounter"], aes_cbc_encrypt(keys[0], data, keys[2][:16]))
        mac_input = ident["pubKey"] + session.indexInfo["remoteIdentityKey"] + bytes([_tuple(VERSION, VERSION)]) + msg
        result = bytes([_tuple(VERSION, VERSION)]) + msg + hmac256(keys[1], mac_input)[:8]
        self._store(record)
        if session.pendingPreKey:
            p = session.pendingPreKey
            body = bytes([_tuple(VERSION, VERSION)]) + encode_prekey_whisper(
                p.get("preKeyId"), p["baseKey"], ident["pubKey"], result,
                self.store.get_our_registration_id(), p["signedKeyId"])
            return {"type": "pkmsg", "body": body, "registrationId": session.registrationId}
        return {"type": "msg", "body": result, "registrationId": session.registrationId}

    def decrypt_whisper_message(self, data: bytes):
        record = self._record()
        if not record: raise SessionError("No session record")
        errs = []
        for session in record.get_sessions():
            snapshot = session.serialize()          # a failed attempt must not advance this session's state
            try:
                pt = self._do_decrypt(data, session)
                session.indexInfo["used"] = _now_ms()
                self._store(record)
                return pt
            except Exception as e:
                restored = SessionEntry.deserialize(snapshot)
                session.__dict__.update(restored.__dict__)
                errs.append(e)
        raise SessionError("No matching sessions found for message: " + "; ".join(map(str, errs[:3])))

    def decrypt_prekey_whisper_message(self, data: bytes):
        v = data[0]
        if (v & 0xF) > 3 or (v >> 4) < 3: raise SignalError("Incompatible version number on PreKeyWhisperMessage")
        record = self._record()
        proto = decode_prekey_whisper(data[1:])
        if record is None:
            if proto.get("registrationId") is None: raise SignalError("No registrationId")
            record = SessionRecord()
        pre_key_id = SessionBuilder(self.store, self.addr).init_incoming(record, proto)
        session = record.get_session(proto["baseKey"])
        pt = self._do_decrypt(proto["message"], session)
        self._store(record)
        if pre_key_id:
            self.store.remove_pre_key(pre_key_id)
        return pt

    def _do_decrypt(self, buf, session):
        if session is None: raise TypeError("session required")
        v = buf[0]
        if (v & 0xF) > 3 or (v >> 4) < 3: raise SignalError("Incompatible version number on WhisperMessage")
        proto = buf[1:-8]
        m = decode_whisper(proto)
        self._maybe_step_ratchet(session, m["ephemeralKey"], m["previousCounter"])
        chain = session.get_chain(m["ephemeralKey"])
        if chain["chainType"] == CHAIN_SENDING: raise SignalError("Tried to decrypt on a sending chain")
        self._fill(chain, m["counter"])
        if m["counter"] not in chain["messageKeys"]:
            raise MessageCounterError("Key used already or never filled")
        mk = chain["messageKeys"].pop(m["counter"])
        keys = derive_secrets(mk, b"\x00" * 32, b"WhisperMessageKeys")
        ident = self.store.get_our_identity()
        mac_input = session.indexInfo["remoteIdentityKey"] + ident["pubKey"] + bytes([_tuple(VERSION, VERSION)]) + proto
        if not hmac.compare_digest(hmac256(keys[1], mac_input)[:8], buf[-8:]):
            raise SignalError("Bad MAC")
        pt = aes_cbc_decrypt(keys[0], m["ciphertext"], keys[2][:16])
        session.pendingPreKey = None
        return pt

    def _fill(self, chain, counter):
        while chain["chainKey"]["counter"] < counter:
            if counter - chain["chainKey"]["counter"] > 2000:
                raise SessionError("Over 2000 messages into the future!")
            key = chain["chainKey"].get("key")
            if key is None: raise SessionError("Chain closed")
            chain["messageKeys"][chain["chainKey"]["counter"] + 1] = hmac256(key, b"\x01")
            chain["chainKey"]["key"] = hmac256(key, b"\x02")
            chain["chainKey"]["counter"] += 1

    def _maybe_step_ratchet(self, session, remote_key, previous_counter):
        if session.get_chain(remote_key): return
        r = session.currentRatchet
        prev = session.get_chain(r["lastRemoteEphemeralKey"])
        if prev:
            self._fill(prev, previous_counter)
            prev["chainKey"].pop("key", None); prev["chainKey"]["key"] = None
        self._calc_ratchet(session, remote_key, False)
        prev_sending = session.get_chain(r["ephemeralKeyPair"]["pubKey"])
        if prev_sending:
            r["previousCounter"] = prev_sending["chainKey"]["counter"]
            session.delete_chain(r["ephemeralKeyPair"]["pubKey"])
        r["ephemeralKeyPair"] = generate_key_pair()
        self._calc_ratchet(session, remote_key, True)
        r["lastRemoteEphemeralKey"] = remote_key

    def _calc_ratchet(self, session, remote_key, sending):
        r = session.currentRatchet
        shared = calculate_agreement(remote_key, r["ephemeralKeyPair"]["privKey"])
        mk = derive_secrets(shared, r["rootKey"], b"WhisperRatchet", 2)
        session.add_chain(r["ephemeralKeyPair"]["pubKey"] if sending else remote_key,
                          {"messageKeys": {}, "chainKey": {"counter": -1, "key": mk[1]},
                           "chainType": CHAIN_SENDING if sending else CHAIN_RECEIVING})
        r["rootKey"] = mk[0]

    def has_open_session(self):
        rec = self._record()
        return bool(rec) and rec.have_open_session()
