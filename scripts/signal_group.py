"""signal_group.py — Signal sender keys (group messages) as WhatsApp clients speak them, in Python.

A port of the group cipher Baileys ships (lib/Signal/Group: SenderKeyRecord, SenderKeyState,
SenderChainKey, SenderMessageKey, SenderKeyMessage, SenderKeyDistributionMessage, GroupCipher,
GroupSessionBuilder), kept interchangeable with it:

  * a sender-key record serialises to the same JSON shape Baileys stores (a list of
    {senderKeyId, senderChainKey{iteration, seed}, senderSigningKey{public[, private]},
    senderMessageKeys[{iteration, seed}]}, bytes as base64), which is also what
    export_signal_state.py writes from the browser's `senderkey-store`;
  * a SenderKeyMessage is checked against the sender's signing key exactly as libsignal does
    (XEdDSA: the Curve25519 key is mapped to its Ed25519 form, the sign bit is carried in the
    signature's last byte).

Only receiving is implemented: a forensic client never needs to send to a group.
Interoperability is tested against Baileys' own group cipher (scripts/selftest_signal.py).
"""
from __future__ import annotations
import base64, copy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from signal_core import hmac256, derive_secrets, aes_cbc_decrypt, SignalError, _decode

MAX_STATES = 5
MAX_MESSAGE_KEYS = 2000
MAX_FORWARD = 2000
SIGNATURE_LENGTH = 64


def _b(v):
    if v is None: return b""
    if isinstance(v, (bytes, bytearray)): return bytes(v)
    if isinstance(v, str): return base64.b64decode(v)
    if isinstance(v, dict) and v.get("type") == "Buffer":            # BufferJSON from Baileys
        d = v.get("data")
        return base64.b64decode(d) if isinstance(d, str) else bytes(d)
    return bytes(v)

def _s(b): return base64.b64encode(b).decode()


# ---------------------------------------------------------------- XEdDSA verification
_P = 2 ** 255 - 19

def xeddsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """libsignal's curve25519 signature check: Montgomery u -> Edwards y = (u-1)/(u+1), the sign bit
    taken from signature[63], then an ordinary Ed25519 verification."""
    pk = public_key[1:] if len(public_key) == 33 else public_key
    if len(pk) != 32 or len(signature) != 64:
        return False
    u = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    if u >= _P or (u + 1) % _P == 0:
        return False
    y = (u - 1) * pow(u + 1, _P - 2, _P) % _P
    ed = bytearray(y.to_bytes(32, "little"))
    ed[31] = (ed[31] & 0x7F) | (signature[63] & 0x80)
    sig = bytearray(signature); sig[63] &= 0x7F
    try:
        Ed25519PublicKey.from_public_bytes(bytes(ed)).verify(bytes(sig), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- keys
class SenderMessageKey:
    def __init__(self, iteration, seed):
        d = derive_secrets(seed, b"\0" * 32, b"WhisperGroup", 2)
        self.iteration, self.seed = iteration, seed
        self.iv = d[0][:16]
        self.cipher_key = d[0][16:] + d[1][:16]


class SenderChainKey:
    def __init__(self, iteration, chain_key):
        self.iteration, self.seed = iteration, chain_key
    def message_key(self): return SenderMessageKey(self.iteration, hmac256(self.seed, b"\x01"))
    def next(self): return SenderChainKey(self.iteration + 1, hmac256(self.seed, b"\x02"))


class SenderKeyState:
    def __init__(self, structure):
        self.s = structure
        self.s.setdefault("senderMessageKeys", [])

    @classmethod
    def new(cls, key_id, iteration, chain_key, signing_public):
        return cls({"senderKeyId": key_id,
                    "senderChainKey": {"iteration": iteration or 0, "seed": _s(chain_key)},
                    "senderSigningKey": {"public": _s(signing_public)},
                    "senderMessageKeys": []})

    @property
    def key_id(self): return self.s.get("senderKeyId")
    def chain_key(self):
        c = self.s["senderChainKey"]; return SenderChainKey(int(c.get("iteration") or 0), _b(c.get("seed")))
    def set_chain_key(self, ck): self.s["senderChainKey"] = {"iteration": ck.iteration, "seed": _s(ck.seed)}
    def signing_public(self): return _b(self.s["senderSigningKey"].get("public"))

    def pop_message_key(self, iteration):
        for i, k in enumerate(self.s["senderMessageKeys"]):
            if k.get("iteration") == iteration:
                del self.s["senderMessageKeys"][i]
                return SenderMessageKey(iteration, _b(k.get("seed")))
        return None

    def add_message_key(self, mk):
        self.s["senderMessageKeys"].append({"iteration": mk.iteration, "seed": _s(mk.seed)})
        if len(self.s["senderMessageKeys"]) > MAX_MESSAGE_KEYS:
            self.s["senderMessageKeys"].pop(0)


class SenderKeyRecord:
    def __init__(self, states=None):
        self.states = [SenderKeyState(copy.deepcopy(s)) for s in (states or [])]

    @classmethod
    def deserialize(cls, data): return cls(data or [])
    def serialize(self): return [st.s for st in self.states]
    def is_empty(self): return not self.states

    def state(self, key_id=None):
        if key_id is None:
            return self.states[-1] if self.states else None
        return next((st for st in self.states if st.key_id == key_id), None)

    def add_state(self, key_id, iteration, chain_key, signing_public):
        self.states.append(SenderKeyState.new(key_id, iteration, chain_key, signing_public))
        if len(self.states) > MAX_STATES:
            self.states.pop(0)


# ---------------------------------------------------------------- wire messages
def parse_distribution(serialized: bytes) -> dict:
    """SenderKeyDistributionMessage: one version byte, then {id=1, iteration=2, chainKey=3, signingKey=4}."""
    f = _decode(serialized[1:])
    return {"id": f.get(1, 0), "iteration": f.get(2, 0),
            "chainKey": f.get(3, b""), "signingKey": f.get(4, b"")}

def parse_message(serialized: bytes) -> dict:
    """SenderKeyMessage: version byte, {id=1, iteration=2, ciphertext=3}, 64-byte signature."""
    body = serialized[1:-SIGNATURE_LENGTH]
    f = _decode(body)
    return {"version": serialized[0] >> 4, "id": f.get(1, 0), "iteration": f.get(2, 0),
            "ciphertext": f.get(3, b""), "signed": serialized[:-SIGNATURE_LENGTH],
            "signature": serialized[-SIGNATURE_LENGTH:]}


# ---------------------------------------------------------------- store + cipher
def sender_key_name(group: str, sender_addr: str) -> str:
    """The key the browser export and Baileys use: '<group>::<user>::<device>'."""
    user, _, dev = sender_addr.rpartition(".")
    return "%s::%s::%s" % (group, user, dev or "0")


class GroupSessionBuilder:
    def __init__(self, records: dict):
        self.records = records                       # name -> serialised record (list), shared with the store

    def process(self, name: str, distribution: bytes):
        d = parse_distribution(distribution)
        rec = SenderKeyRecord.deserialize(self.records.get(name))
        rec.add_state(d["id"], d["iteration"], d["chainKey"], d["signingKey"])
        self.records[name] = rec.serialize()
        return d


class GroupCipher:
    def __init__(self, records: dict, name: str):
        self.records, self.name = records, name

    def decrypt(self, serialized: bytes) -> bytes:
        rec = SenderKeyRecord.deserialize(self.records.get(self.name))
        if rec.is_empty():
            raise SignalError("no sender key for %s" % self.name)
        m = parse_message(serialized)
        st = rec.state(m["id"])
        if st is None:
            raise SignalError("no sender key state with id %s" % m["id"])
        if not xeddsa_verify(st.signing_public(), m["signed"], m["signature"]):
            raise SignalError("sender key message signature invalid")
        mk = self._message_key(st, m["iteration"])
        pt = aes_cbc_decrypt(mk.cipher_key, m["ciphertext"], mk.iv)
        self.records[self.name] = rec.serialize()     # commit the advanced chain only after success
        return pt

    @staticmethod
    def _message_key(st, iteration):
        ck = st.chain_key()
        if ck.iteration > iteration:
            mk = st.pop_message_key(iteration)
            if mk is None:
                raise SignalError("old counter: chain at %d, message %d" % (ck.iteration, iteration))
            return mk
        if iteration - ck.iteration > MAX_FORWARD:
            raise SignalError("over %d messages into the future" % MAX_FORWARD)
        while ck.iteration < iteration:
            st.add_message_key(ck.message_key())
            ck = ck.next()
        st.set_chain_key(ck.next())
        return ck.message_key()
