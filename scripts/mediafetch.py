#!/usr/bin/env python3
"""mediafetch.py — recover full-resolution WhatsApp Web media for an exported case.

WhatsApp Web never stores decrypted media on disk. What it keeps is the ENCRYPTED blob exactly as
the CDN served it, plus, in each message record, the `mediaKey` needed to decrypt it. So media
recovery is a separate step from message decryption, and there are three sources, in descending
forensic preference:

  1. CACHE  (offline, no network)  The browser's HTTP cache holds the ciphertext byte-for-byte.
     Nothing can change under us and the evidence device is not contacted. Chromium keeps these in
     `Service Worker/CacheStorage/<origin>/<bucket>/<hash>_0` in the "simple cache" format; Firefox
     keeps them in the origin's `cache/morgue` (export_sqlite.py already handles the Firefox side).
  2. CDN    (networked)            GET the message's `directPath` from mmg.whatsapp.net. Recovers
     media that was never cached, but touches the network and a directPath can expire.
  3. THUMBNAIL                     `jpegThumbnail` is embedded in the message record itself and is
     already exported by export_sqlite.py. Low resolution, but free and always available.

Decryption is identical for 1 and 2:
    HKDF-SHA256(mediaKey, salt=0x00*32, info=<per-type string>, len=112)
        -> iv(16) || cipherKey(32) || macKey(32) || unused(32)
    plaintext = unpad(AES-256-CBC(cipherKey, iv, ciphertext[:-10]))
The trailing 10 bytes are a truncated HMAC-SHA256. Every recovered file is verified against the
message's `fileSha256`, so a wrong key, a truncated cache entry or a corrupted download is reported
rather than written out as if it were evidence.

  python3 scripts/mediafetch.py --db out.db --profile <chromium profile> [--cdn] [--out DIR]

Reads the SQLite export produced by `wawf --out sqlite:PATH` (message_media), writes the recovered
files and, unless --no-update-db, points each message_media.file_path at its file so the exported
database and the media directory stay consistent.
"""
from __future__ import annotations
import argparse, base64, glob, hashlib, os, sqlite3, struct, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# WhatsApp's per-type HKDF info strings. A sticker is an image as far as the key schedule cares.
INFO_BY_PREFIX = [("image/", b"WhatsApp Image Keys"), ("video/", b"WhatsApp Video Keys"),
                  ("audio/", b"WhatsApp Audio Keys")]
INFO_DEFAULT = b"WhatsApp Document Keys"
EXT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
       "video/mp4": "mp4", "video/3gpp": "3gp", "video/quicktime": "mov",
       "audio/ogg": "ogg", "audio/ogg; codecs=opus": "ogg", "audio/mpeg": "mp3",
       "audio/mp4": "m4a", "audio/aac": "aac", "audio/amr": "amr",
       "application/pdf": "pdf", "text/plain": "txt", "application/zip": "zip"}

def info_for(mime: str) -> bytes:
    m = (mime or "").lower()
    for pre, inf in INFO_BY_PREFIX:
        if m.startswith(pre):
            return inf
    return INFO_DEFAULT

def ext_for(mime: str) -> str:
    m = (mime or "").lower()
    if m in EXT: return EXT[m]
    base = m.split(";")[0].strip()
    return EXT.get(base) or (base.split("/")[-1][:8] if "/" in base else "bin")

def decrypt_media(ciphertext: bytes, media_key: bytes, mime: str):
    """Return plaintext, or None if the blob is not decryptable with this key."""
    if not ciphertext or len(ciphertext) <= 10 or not media_key:
        return None
    exp = HKDF(algorithm=hashes.SHA256(), length=112, salt=b"\x00" * 32,
               info=info_for(mime)).derive(media_key)
    iv, ckey = exp[:16], exp[16:48]
    try:
        pt = Cipher(algorithms.AES(ckey), modes.CBC(iv)).decryptor().update(ciphertext[:-10])
    except Exception:
        return None
    if not pt:
        return None
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 else pt          # PKCS#7, tolerate an unpadded tail

# ---------------------------------------------------------------- Chromium simple cache ----------
# net/disk_cache/simple/simple_entry_format.h
SIMPLE_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_EOF   = 0xF4FA6F45970D41D8
EOF_STRUCT   = struct.Struct("<QIIq")                  # magic, flags, data_crc32, stream_size

_CL_RE = __import__("re").compile(rb"content-length[\x00-\x20]*:?[\x00-\x20]*(\d+)", __import__("re").I)
_BODY_PREFIX = 4        # see below

def simple_cache_entry(path: str):
    """(key, body) from one Chromium simple-cache file, or None if it is not one / is unusable.

    Layout: SimpleFileHeader(20B) || key || stream1 || SimpleFileEOF(24B) || stream0 || EOF.
    Stream 1 is the response BODY; stream 0 is the response metadata.

    The EOF record's `stream_size` is 4 bytes LARGER than the response's own Content-Length: the
    stream carries a 4-byte prefix before the body proper. Determined empirically and then confirmed
    the only way that counts — by checking which slice reproduces an encFileSha256 that the message
    store already knows: taking Content-Length bytes back from the EOF record matched 35 of the 36
    cached media blobs (the 36th is simply not a message in this export), while using stream_size
    matched none. So prefer Content-Length when the metadata gives it, and fall back to skipping the
    prefix.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 44:
        return None
    magic, _version, key_len, _key_hash = struct.unpack_from("<QIII", data, 0)
    if magic != SIMPLE_MAGIC or key_len <= 0 or 20 + key_len > len(data):
        return None
    key = data[20:20 + key_len].decode("utf-8", "replace")
    pos = 20 + key_len
    at = data.find(struct.pack("<Q", SIMPLE_EOF), pos)
    if at < 0 or at + EOF_STRUCT.size > len(data):
        return None
    m = _CL_RE.search(data, at)                 # the headers live in stream 0, after this EOF
    if not m:
        m = _CL_RE.search(data)
    if m:
        cl = int(m.group(1))
        if 0 < cl <= at - pos:
            return key, data[at - cl:at]
    return key, data[pos + _BODY_PREFIX:at]

def scan_chromium_cache(profile: str, wanted: dict, verbose=False):
    """Match cached ciphertext against the enc-hashes we are looking for. {enc_sha256_b64: body}"""
    root = os.path.join(profile, "Service Worker", "CacheStorage")
    found, scanned = {}, 0
    if not os.path.isdir(root):
        return found, scanned
    for path in glob.iglob(os.path.join(root, "**", "*_0"), recursive=True):
        ent = simple_cache_entry(path)
        if not ent:
            continue
        scanned += 1
        key, body = ent
        if not body:
            continue
        h = base64.b64encode(hashlib.sha256(body).digest()).decode()
        if h in wanted and h not in found:
            found[h] = body
            if verbose:
                print(f"    cache hit: {key.rsplit('/', 1)[-1][:48]}  {len(body):,} B")
    return found, scanned

# ---------------------------------------------------------------- CDN ----------------------------
def cdn_get(direct_path: str, timeout=30):
    import urllib.request
    url = "https://mmg.whatsapp.net" + direct_path
    req = urllib.request.Request(url, headers={"User-Agent": "WhatsApp/2.2412.54 W"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

# ---------------------------------------------------------------- main ---------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True, help="the SQLite export from `wawf --out sqlite:PATH`")
    ap.add_argument("--profile", help="Chromium profile dir, to recover from its cache (offline)")
    ap.add_argument("--cdn", action="store_true", help="also download what the cache does not have (NETWORKED)")
    ap.add_argument("--out", help="media output dir (default: <db dir>/Media/WhatsApp Web)")
    ap.add_argument("--retry-json", help="media_retry_out.json from tools/reconnect/diag_media_retry.js: "
                                         "FRESH directPaths for media whose original path expired")
    ap.add_argument("--no-update-db", action="store_true", help="do not set message_media.file_path")
    ap.add_argument("--limit", type=int, default=0, help="stop after N CDN downloads (0 = no limit)")
    a = ap.parse_args()

    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.db)), "Media", "WhatsApp Web")
    os.makedirs(out, exist_ok=True)
    db = sqlite3.connect(a.db)
    rows = db.execute("""SELECT message_row_id, direct_path, file_hash, enc_file_hash, media_key,
                                mime_type, file_size FROM message_media
                         WHERE media_key IS NOT NULL AND file_hash IS NOT NULL""").fetchall()
    print(f"[i] {len(rows)} media message(s) with a mediaKey in {a.db}")
    if not rows:
        print("[!] nothing to do — the export has no media rows with keys"); return 0

    by_ench = {}
    for r in rows:
        if r[3]:
            by_ench.setdefault(r[3], []).append(r)
    print(f"[i] {len(by_ench)} distinct encrypted-blob hashes to look for")

    cached, scanned = ({}, 0)
    if a.profile:
        print("[1/2] scanning the browser cache (offline) ...")
        cached, scanned = scan_chromium_cache(a.profile, by_ench, verbose=True)
        print(f"      {scanned} cache entries parsed, {len(cached)} matched a message")

    # A directPath is a capability URL that expires in DAYS (measured on a real profile: the newest
    # day serves HTTP 206, a week-old path returns 403). The mediaKey never expires, so old media is
    # still decryptable -- it just needs a fresh path, which the phone/sender will mint on request.
    # That is what diag_media_retry.js collects, and it overrides the stale path from the export.
    fresh = {}
    if a.retry_json:
        import json
        for r in json.load(open(a.retry_json, encoding="utf-8")).get("results", []):
            if r.get("ok") and r.get("directPath"):
                fresh[r["rid"]] = r["directPath"]
        print(f"[i] {len(fresh)} re-uploaded directPath(s) from {a.retry_json}")

    ok = failed = nocache = 0
    dl = dl_bytes = 0        # CDN downloads attempted / bytes pulled
    updates = []
    for (rid, dpath, fhash, ench, mkey, mime, _size) in rows:
        dpath = fresh.get(rid, dpath)
        body = cached.get(ench)
        src = "cache"
        if body is None and a.cdn and dpath and (not a.limit or dl < a.limit):
            try:
                dl += 1
                body = cdn_get(dpath); src = "cdn"; dl_bytes += len(body)
            except Exception as e:
                print(f"    [cdn err] msg {rid}: {type(e).__name__}: {e}"); body = None
        if body is None:
            nocache += 1
            continue
        pt = decrypt_media(body, bytes(mkey), mime)
        if pt is None or base64.b64encode(hashlib.sha256(pt).digest()).decode() != fhash:
            print(f"    [verify FAIL] msg {rid} ({mime}) via {src} — sha256 mismatch, not written")
            failed += 1
            continue
        name = f"{rid}.{ext_for(mime)}"
        rel = f"Media/WhatsApp Web/{name}"              # the path shape WAInsight/Android expect
        with open(os.path.join(out, name), "wb") as f:
            f.write(pt)
        updates.append((rel, rid)); ok += 1

    if updates and not a.no_update_db:
        db.executemany("UPDATE message_media SET file_path=? WHERE message_row_id=?", updates)
        db.commit()
    db.close()
    print(f"\n[+] recovered {ok} media file(s), VERIFIED against fileSha256 -> {out}")
    if a.cdn:
        print(f"[i] CDN: {dl} download(s) attempted, {dl_bytes/1048576:.1f} MiB pulled")
    if failed:  print(f"[!] {failed} blob(s) found but failed verification (not written)")
    if nocache: print(f"[i] {nocache} media message(s) had no cached blob"
                      + ("" if a.cdn else " — re-run with --cdn to download them"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
