"""Minimal Mozilla structured-clone reader (Firefox IndexedDB values)."""
import struct

HEADER      = 0xFFF10000
NULL        = 0xFFFF0000
UNDEFINED   = 0xFFFF0001
BOOLEAN     = 0xFFFF0002
INT32       = 0xFFFF0003
STRING      = 0xFFFF0004
DATE        = 0xFFFF0005
REGEXP      = 0xFFFF0006
ARRAY       = 0xFFFF0007
OBJECT      = 0xFFFF0008
ARRAYBUF_V2 = 0xFFFF0009
BOOL_OBJ    = 0xFFFF000A
STR_OBJ     = 0xFFFF000B
NUM_OBJ     = 0xFFFF000C
BACKREF     = 0xFFFF000D
TYPEDARR_V2 = 0xFFFF0010
MAP         = 0xFFFF0011
SET         = 0xFFFF0012
END_OF_KEYS = 0xFFFF0013
DATAVIEW_V2 = 0xFFFF0015
BIGINT      = 0xFFFF001D
ARRAYBUF    = 0xFFFF001F
TYPEDARR    = 0xFFFF0020
DATAVIEW    = 0xFFFF0021
TRANSFER_MAP= 0xFFFF0100

class Reader:
    def __init__(self, buf):
        self.b = buf; self.p = 0; self.objs = []
    def word(self):
        if self.p + 8 > len(self.b): raise EOFError
        w = struct.unpack_from('<Q', self.b, self.p)[0]; self.p += 8
        return w
    def pair(self):
        w = self.word()
        return (w >> 32) & 0xFFFFFFFF, w & 0xFFFFFFFF
    def bytes_(self, n):
        d = self.b[self.p:self.p+n]; self.p += n
        self.p += (-n) % 8          # pad to 8-byte boundary
        return d
    def string(self, data):
        latin1 = bool(data & 0x80000000)
        ln = data & 0x7FFFFFFF
        raw = self.bytes_(ln if latin1 else ln*2)
        return raw.decode('latin-1') if latin1 else raw.decode('utf-16-le', 'replace')

    def value(self, tag=None, data=None):
        if tag is None: tag, data = self.pair()
        if tag < 0xFFFF0000:                       # canonical double: whole word is the double
            self.p -= 8
            d = struct.unpack('<d', self.b[self.p:self.p+8])[0]; self.p += 8
            return d
        if tag == NULL: return None
        if tag == UNDEFINED: return None
        if tag == BOOLEAN or tag == BOOL_OBJ: return bool(data)
        if tag == INT32: return struct.unpack('<i', struct.pack('<I', data))[0]
        if tag == STRING or tag == STR_OBJ: return self.string(data)
        if tag == NUM_OBJ:
            d = struct.unpack('<d', self.b[self.p:self.p+8])[0]; self.p += 8
            return d
        if tag == DATE:
            d = struct.unpack('<d', self.b[self.p:self.p+8])[0]; self.p += 8
            return {"__date_ms": d}
        if tag == BACKREF:
            return self.objs[data] if data < len(self.objs) else {"__backref": data}
        if tag in (ARRAYBUF, ARRAYBUF_V2):
            n = data if tag == ARRAYBUF_V2 else self.word()
            return {"__bytes": self.bytes_(n)}
        if tag in (TYPEDARR, TYPEDARR_V2, DATAVIEW, DATAVIEW_V2):
            # nbytes/length word, then the buffer value, then offset
            _ = self.word(); buf = self.value(); _ = self.word()
            return buf
        if tag == BIGINT:
            neg = bool(data & 0x80000000); ln = data & 0x7FFFFFFF
            raw = self.bytes_(ln*8)
            v = int.from_bytes(raw, 'little')
            return -v if neg else v
        if tag == OBJECT:
            o = {}; self.objs.append(o)
            while True:
                t, d = self.pair()
                if t == END_OF_KEYS: break
                k = self.value(t, d)
                o[k if isinstance(k, str) else str(k)] = self.value()
            return o
        if tag == ARRAY:
            a = []; self.objs.append(a)
            while True:
                t, d = self.pair()
                if t == END_OF_KEYS: break
                idx = self.value(t, d); v = self.value()
                if isinstance(idx, (int, float)):
                    i = int(idx)
                    while len(a) <= i: a.append(None)
                    a[i] = v
                else: a.append(v)
            return a
        if tag in (MAP, SET):
            items = []; self.objs.append(items)
            while True:
                t, d = self.pair()
                if t == END_OF_KEYS: break
                if tag == MAP:
                    items.append((self.value(t, d), self.value()))
                else:
                    items.append(self.value(t, d))
            return {"__map": items} if tag == MAP else {"__set": items}
        if tag == REGEXP:
            _flags = data; src = self.value()
            return {"__regexp": src}
        raise ValueError(f"unhandled tag 0x{tag:08X} data=0x{data:08X} at {self.p-8}")

def loads(buf):
    r = Reader(buf)
    tag, data = r.pair()
    if tag == HEADER:
        tag, data = r.pair()
    if tag == TRANSFER_MAP:
        for _ in range(data): r.word(); r.word(); r.word(); r.word()
        tag, data = r.pair()
    return r.value(tag, data)
