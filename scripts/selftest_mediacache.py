#!/usr/bin/env python3
"""selftest_mediacache.py — prove the cached-media scanner handles EVERY browser cache layout.

Media recovery is only as good as the number of cache formats it can parse, and those formats are
undocumented, version-dependent and easy to get subtly wrong (the Chromium simple-cache body sits
4 bytes past where its own EOF record implies). A real profile only exercises whichever layout that
browser happens to use, so this builds one synthetic entry in each layout, each holding a different
random blob, and checks the scanner finds all of them by hash.

    python3 scripts/selftest_mediacache.py        # exits non-zero if any layout regresses
"""
import base64, hashlib, os, shutil, struct, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mediacache as mc

LAYOUTS = ["chromium CacheStorage (simple cache)", "chromium http cache (blockfile f_*)",
           "firefox CacheStorage (morgue .final)", "firefox http cache (cache2 entries)"]

def build(tmp):
    bodies = {n: os.urandom(4096 + i * 17) for i, n in enumerate(LAYOUTS)}

    def w(rel, data):
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

    # Chromium simple cache: header || key || 4-byte prefix || body || EOF || response headers || EOF
    b = bodies[LAYOUTS[0]]
    key = b"_dk_https://web.whatsapp.com x https://media.example/v/t62/x_n.enc"
    w("Service Worker/CacheStorage/bucket/cache/0123456789abcdef_0",
      struct.pack("<QIII", mc.SIMPLE_MAGIC, 5, len(key), 0) + key + b"\0\0\0\0" + b
      + struct.pack("<QIIq", mc.SIMPLE_EOF, 0, 0, len(b) + 4)
      + b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n" % len(b)
      + struct.pack("<QIIq", mc.SIMPLE_EOF, 0, 0, 40))
    # Chromium blockfile cache: bodies too large for the block files land in f_###### as raw bytes
    w("Cache/Cache_Data/f_000123", bodies[LAYOUTS[1]])
    # Firefox CacheStorage, under the origin's storage dir
    w("storage/default/https+++web.whatsapp.com/cache/morgue/7/deadbeef.final", bodies[LAYOUTS[2]])
    # Firefox cache2: body || metadata || uint32be(offset at which the metadata starts)
    b4 = bodies[LAYOUTS[3]]
    w("cache2/entries/AABBCCDDEE", b4 + b"a:metadata:blob" * 8 + struct.pack(">I", len(b4)))
    return bodies

def main():
    tmp = tempfile.mkdtemp(prefix="wawf_mediacache_selftest_")
    # in a folder named like a real case folder: a '[' there is a glob character class, and the scan
    # used to find nothing at all under it
    root = os.path.join(tmp, "Case #12 [m] 100%")
    try:
        bodies = build(root)
        want = {base64.b64encode(hashlib.sha256(b).digest()).decode(): n for n, b in bodies.items()}
        found, st = mc.recover(want.keys(), root)
        print(f"scanned {st['files']} file(s) under {st['roots']} root(s), "
              f"{st['bodies']} candidate body/bodies")
        print("matched by source:", st["by_source"] or "{}")
        missed = [n for h, n in want.items() if h not in found]
        for h, n in want.items():
            print(f"   {'FOUND ' if h in found else 'MISSED'}  {n}")
        if missed:
            print(f"\nFAIL: {len(missed)} layout(s) regressed: {missed}")
            return 1
        # the ciphertext must come back byte-identical, not merely the right length
        for h, body in found.items():
            if base64.b64encode(hashlib.sha256(body).digest()).decode() != h:
                print("\nFAIL: a recovered body did not re-hash to its own key")
                return 1
        print(f"\nPASS: all {len(want)} browser cache layouts recovered, byte-identical")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
