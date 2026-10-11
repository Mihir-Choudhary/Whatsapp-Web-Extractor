"""wa_binary.py — encode WhatsApp binary stanzas (port of Baileys WABinary/encode.js).

The decoder lives in wa_reconnect.py (NodeReader / decode_binary_node); this is its inverse, so the tool
can send stanzas, not only read them. A node is {"tag": str, "attrs": {str: str}, "content": None |
str | bytes | [node, ...]}, the same shape the decoder returns.
"""
from __future__ import annotations
from _wa_tokens import TAGS, SINGLE_BYTE_TOKENS, DOUBLE_BYTE_TOKENS

TOKEN_MAP = {}
for _i, _t in enumerate(SINGLE_BYTE_TOKENS):
    TOKEN_MAP.setdefault(_t, (None, _i))
for _d, _tokens in enumerate(DOUBLE_BYTE_TOKENS):
    for _i, _t in enumerate(_tokens):
        TOKEN_MAP.setdefault(_t, (_d, _i))

_NIBBLE = set("0123456789-.")
_HEX = set("0123456789ABCDEF")


def jid_decode(jid: str):
    """-> {user, device, server, domain_type} or None (not a jid)."""
    if not isinstance(jid, str) or "@" not in jid:
        return None
    user_combined, server = jid.split("@", 1)
    user_agent, _, device = user_combined.partition(":")
    user = user_agent.split("_")[0]
    return {"user": user, "server": server, "device": int(device) if device else None,
            "domain_type": 1 if server == "lid" else 0}


class _Writer:
    def __init__(self):
        self.out = bytearray()

    def byte(self, v): self.out.append(v & 0xFF)

    def int_n(self, v, n):
        for i in range(n - 1, -1, -1): self.out.append((v >> (8 * i)) & 0xFF)

    def int20(self, v):
        self.out += bytes(((v >> 16) & 0x0F, (v >> 8) & 0xFF, v & 0xFF))

    def byte_length(self, n):
        if n >= 1 << 32: raise ValueError("string too large to encode: %d" % n)
        if n >= 1 << 20: self.byte(TAGS["BINARY_32"]); self.int_n(n, 4)
        elif n >= 256: self.byte(TAGS["BINARY_20"]); self.int20(n)
        else: self.byte(TAGS["BINARY_8"]); self.byte(n)

    def raw(self, s: str):
        b = s.encode("utf-8")
        self.byte_length(len(b)); self.out += b

    def list_start(self, n):
        if n == 0: self.byte(TAGS["LIST_EMPTY"])
        elif n < 256: self.byte(TAGS["LIST_8"]); self.byte(n)
        else: self.byte(TAGS["LIST_16"]); self.int_n(n, 2)

    @staticmethod
    def _pack(c, hexa):
        if c == "\0": return 15
        if "0" <= c <= "9": return ord(c) - ord("0")
        if not hexa:
            if c == "-": return 10
            if c == ".": return 11
        elif "A" <= c <= "F":
            return 10 + ord(c) - ord("A")
        raise ValueError("cannot pack %r" % c)

    def packed(self, s, hexa):
        if len(s) > TAGS["PACKED_MAX"]: raise ValueError("too long to pack")
        self.byte(TAGS["HEX_8"] if hexa else TAGS["NIBBLE_8"])
        rounded = (len(s) + 1) // 2
        if len(s) % 2: rounded |= 128
        self.byte(rounded)
        for i in range(len(s) // 2):
            self.byte((self._pack(s[2 * i], hexa) << 4) | self._pack(s[2 * i + 1], hexa))
        if len(s) % 2:
            self.byte((self._pack(s[-1], hexa) << 4) | self._pack("\0", hexa))

    def jid(self, j):
        if j["device"] is not None:
            self.byte(TAGS["AD_JID"]); self.byte(j["domain_type"]); self.byte(j["device"])
            self.string(j["user"])
        else:
            self.byte(TAGS["JID_PAIR"])
            if j["user"]: self.string(j["user"])
            else: self.byte(TAGS["LIST_EMPTY"])
            self.string(j["server"])

    def string(self, s):
        if s is None:
            self.byte(TAGS["LIST_EMPTY"]); return
        tok = TOKEN_MAP.get(s)
        if tok is not None:
            d, i = tok
            if d is not None: self.byte(TAGS["DICTIONARY_0"] + d)
            self.byte(i); return
        if s and len(s) <= TAGS["PACKED_MAX"] and set(s) <= _NIBBLE:
            self.packed(s, False); return
        if s and len(s) <= TAGS["PACKED_MAX"] and set(s) <= _HEX:
            self.packed(s, True); return
        j = jid_decode(s)
        if j is not None:
            self.jid(j); return
        self.raw(s)

    def node(self, n):
        attrs = {k: v for k, v in (n.get("attrs") or {}).items() if v is not None}
        content = n.get("content")
        self.list_start(2 * len(attrs) + 1 + (0 if content is None else 1))
        self.string(n["tag"])
        for k, v in attrs.items():
            self.string(k); self.string(str(v))
        if isinstance(content, str):
            self.string(content)
        elif isinstance(content, (bytes, bytearray)):
            self.byte_length(len(content)); self.out += content
        elif isinstance(content, (list, tuple)):
            self.list_start(len(content))
            for c in content: self.node(c)
        elif content is not None:
            raise TypeError("invalid node content %r" % type(content))


def encode_binary_node(node) -> bytes:
    """A stanza ready to be Noise-encrypted and framed: one leading flags byte (0 = not compressed)."""
    w = _Writer(); w.byte(0); w.node(node)
    return bytes(w.out)


def node(tag, attrs=None, content=None):
    return {"tag": tag, "attrs": dict(attrs or {}), "content": content}
