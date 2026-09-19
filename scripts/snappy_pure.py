import struct
def uncompress(src):
    """Pure-python Snappy raw-format decompressor."""
    n, pos = 0, 0
    shift = 0
    while True:
        b = src[pos]; pos += 1
        n |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80): break
    out = bytearray()
    end = len(src)
    while pos < end:
        tag = src[pos]; pos += 1
        t = tag & 0x03
        if t == 0:                      # literal
            ln = tag >> 2
            if ln < 60:
                ln += 1
            else:
                nb = ln - 59
                ln = int.from_bytes(src[pos:pos+nb], 'little') + 1
                pos += nb
            out += src[pos:pos+ln]; pos += ln
        else:
            if t == 1:
                ln = 4 + ((tag >> 2) & 0x07)
                off = ((tag >> 5) << 8) | src[pos]; pos += 1
            elif t == 2:
                ln = (tag >> 2) + 1
                off = int.from_bytes(src[pos:pos+2], 'little'); pos += 2
            else:
                ln = (tag >> 2) + 1
                off = int.from_bytes(src[pos:pos+4], 'little'); pos += 4
            start = len(out) - off
            if start < 0: raise ValueError("bad offset")
            for i in range(ln):
                out.append(out[start + i])
    if len(out) != n:
        raise ValueError(f"length mismatch {len(out)} != {n}")
    return bytes(out)
