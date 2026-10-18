#!/usr/bin/env python3
"""mediacache.py — browser-agnostic recovery of CACHED WhatsApp media, offline.

WhatsApp Web never writes decrypted media to disk. What the browser keeps is the ENCRYPTED blob
exactly as the CDN served it; the `mediaKey` that opens it lives in the message record. So any
browser's HTTP / CacheStorage layer is a legitimate offline evidence source — no network, and the
bytes cannot have changed under us.

Every browser stores it differently, and a single browser uses more than one format at once, so
this module tries a set of EXTRACTORS against every candidate file and keeps whatever hashes to an
encFileSha256 the message store is looking for. Nothing is trusted on faith: a wrong parse simply
fails to match, and the final plaintext is separately checked against fileSha256 by the caller.

Formats handled
  Chromium family (Chrome / Edge / Brave / Opera / Vivaldi):
    * "simple cache" entries `<hash>_0` and `<hash>_1`, used by Service Worker CacheStorage:
      SimpleFileHeader(20B) || key || stream || SimpleFileEOF(24B) || ...
      The EOF record's `stream_size` is 4 bytes LARGER than the response Content-Length (the stream
      carries a 4-byte prefix), so the body is taken as Content-Length bytes back from the EOF
      record. Verified against known hashes: stream_size matched 0/36, Content-Length matched 35/36.
    * "blockfile" cache (`index` magic c3ca03c1 + data_0..data_3), still used for the HTTP cache on
      Windows: bodies too big for the block files are written to `f_######` as RAW bytes.
  Firefox:
    * CacheStorage: `<origin>/cache/morgue/<n>/<uuid>.final`, optionally snappy-framed.
    * HTTP cache: `cache2/entries/<hash>` — body first, then metadata, with the last 4 bytes being
      the big-endian offset at which the metadata starts.

This is the offline route only. Media the browser never cached needs the CDN or a re-upload request;
see scripts/mediafetch.py.
"""
from __future__ import annotations
import base64, glob, hashlib, os, re, struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------- media crypto -------------------
INFO_BY_PREFIX = [("image/", b"WhatsApp Image Keys"), ("video/", b"WhatsApp Video Keys"),
                  ("audio/", b"WhatsApp Audio Keys")]
INFO_DEFAULT = b"WhatsApp Document Keys"
# WhatsApp's own type words, for callers that have a type rather than a mime
INFO_BY_TYPE = {"image": b"WhatsApp Image Keys", "sticker": b"WhatsApp Image Keys",
                "video": b"WhatsApp Video Keys", "gif": b"WhatsApp Video Keys",
                "audio": b"WhatsApp Audio Keys", "ptt": b"WhatsApp Audio Keys",
                "document": b"WhatsApp Document Keys"}
EXT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
       "video/mp4": "mp4", "video/3gpp": "3gp", "video/quicktime": "mov", "video/webm": "webm",
       "audio/ogg": "ogg", "audio/mpeg": "mp3", "audio/mp4": "m4a", "audio/aac": "aac",
       "audio/amr": "amr", "audio/wav": "wav",
       "application/pdf": "pdf", "text/plain": "txt", "application/zip": "zip",
       "text/markdown": "md", "text/html": "html", "text/csv": "csv", "application/json": "json",
       "application/vnd.android.package-archive": "apk",
       "application/msword": "doc", "application/vnd.ms-excel": "xls",
       "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
       "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx"}

def info_for(mime_or_type) -> bytes:
    s = (mime_or_type or "").lower()
    if s in INFO_BY_TYPE:
        return INFO_BY_TYPE[s]
    for pre, inf in INFO_BY_PREFIX:
        if s.startswith(pre):
            return inf
    return INFO_DEFAULT

def ext_for(mime: str) -> str:
    """A file extension a viewer will dispatch on. The fallback is sanitised: a subtype like
    `vnd.android.package-archive` must not become a filename with dots in it, because then the real
    extension is whatever follows the last one."""
    m = (mime or "").lower()
    if m in EXT: return EXT[m]
    base = m.split(";")[0].strip()
    if base in EXT: return EXT[base]
    sub = base.split("/")[-1] if "/" in base else ""
    sub = sub.rsplit(".", 1)[-1]                      # vnd.android.package-archive -> package-archive
    sub = "".join(ch for ch in sub if ch.isalnum())[:8]
    return sub or "bin"

def decrypt_media(ciphertext: bytes, media_key: bytes, mime_or_type) -> bytes | None:
    """AES-256-CBC body with a 10-byte truncated HMAC appended. None if it cannot be opened."""
    if not ciphertext or len(ciphertext) <= 10 or not media_key:
        return None
    exp = HKDF(algorithm=hashes.SHA256(), length=112, salt=b"\x00" * 32,
               info=info_for(mime_or_type)).derive(bytes(media_key))
    try:
        pt = Cipher(algorithms.AES(exp[16:48]), modes.CBC(exp[:16])).decryptor().update(ciphertext[:-10])
    except Exception:
        return None
    if not pt:
        return None
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 else pt

# ---------------------------------------------------------------- extractors ---------------------
SIMPLE_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_EOF   = 0xF4FA6F45970D41D8
_EOF = struct.Struct("<QIIq")
_CL_RE = re.compile(rb"content-length[\x00-\x20]*:?[\x00-\x20]*(\d+)", re.I)

def _chromium_simple(data: bytes):
    """Body of a Chromium simple-cache entry (see module docstring for the 4-byte prefix)."""
    if len(data) < 44:
        return
    magic, _ver, key_len, _kh = struct.unpack_from("<QIII", data, 0)
    if magic != SIMPLE_MAGIC or key_len <= 0 or 20 + key_len > len(data):
        return
    pos = 20 + key_len
    at = data.find(struct.pack("<Q", SIMPLE_EOF), pos)
    if at < 0 or at + _EOF.size > len(data):
        return
    m = _CL_RE.search(data, at) or _CL_RE.search(data)
    if m:
        cl = int(m.group(1))
        if 0 < cl <= at - pos:
            yield data[at - cl:at]
    yield data[pos + 4:at]                      # fall back to skipping the prefix
    _m, _f, _c, ssz = _EOF.unpack_from(data, at)
    if 0 < ssz <= at - pos:
        yield data[at - ssz:at]

def _raw(data: bytes):
    """The whole file: Chromium blockfile `f_######` bodies, and Firefox .final once unframed."""
    yield data

def _firefox_morgue(data: bytes):
    """Firefox CacheStorage body, which may be framed-snappy."""
    if data[:4] != b"\xff\x06\x00\x00":
        return
    try:
        import cramjam
        raw = cramjam.snappy.decompress_raw
    except Exception:
        return
    out = bytearray(); p = 10
    while p + 4 <= len(data):
        t = data[p]; ln = int.from_bytes(data[p + 1:p + 4], "little"); p += 4
        chunk = data[p:p + ln]; p += ln
        if t == 0x00:
            try: out += bytes(raw(chunk[4:]))
            except Exception: break
        elif t == 0x01:
            out += chunk[4:]
        else:
            break
    if out:
        yield bytes(out)

def _firefox_cache2(data: bytes):
    """Firefox cache2 entry: body || metadata || uint32be(offset of metadata)."""
    if len(data) < 8:
        return
    off = int.from_bytes(data[-4:], "big")
    if 0 < off < len(data) - 4:
        yield data[:off]

# (glob pattern relative to a root, extractors to try) — patterns that match nothing cost nothing,
# so the same list is used for every browser and every root.
SOURCES = [
    ("chromium CacheStorage", "Service Worker/CacheStorage/**/*_0", (_chromium_simple,)),
    ("chromium CacheStorage", "Service Worker/CacheStorage/**/*_1", (_chromium_simple, _raw)),
    # newer Chromium/Edge keep a partitioned origin's CacheStorage inside its storage bucket
    ("chromium CacheStorage", "WebStorage/*/CacheStorage/**/*_0",   (_chromium_simple,)),
    ("chromium CacheStorage", "WebStorage/*/CacheStorage/**/*_1",   (_chromium_simple, _raw)),
    ("chromium http cache",   "Cache/Cache_Data/**/*_0",            (_chromium_simple,)),
    ("chromium http cache",   "Cache/Cache_Data/f_*",               (_raw,)),
    ("chromium http cache",   "Cache/f_*",                          (_raw,)),
    ("firefox CacheStorage",  "**/cache/morgue/**/*.final",         (_firefox_morgue, _raw)),
    ("firefox http cache",    "cache2/entries/*",                   (_firefox_cache2, _raw)),
]

# A cache folder given on its own (wawf --media-cache) is not at a known place inside a profile, so
# every cache-entry shape is looked for anywhere beneath it.
GIVEN = [
    ("given cache", "**/*_0",          (_chromium_simple,)),
    ("given cache", "**/*_1",          (_chromium_simple, _raw)),
    ("given cache", "**/f_*",          (_raw,)),
    ("given cache", "**/*.final",      (_firefox_morgue, _raw)),
    ("given cache", "**/entries/*",    (_firefox_cache2, _raw)),
]

def _given_caches(path):
    """Cache folders named in a given-stores description (see chromium_reader.PARTS_FILE)."""
    out = [p for p in (os.environ.get("WAWF_MEDIA_CACHE") or "").split(os.pathsep) if p and os.path.isdir(p)]
    f = os.path.join(path or "", "wawf_parts.json")
    if os.path.isfile(f):
        import json
        with open(f, encoding="utf-8") as fh:
            out += [p for p in (json.load(fh).get("media_cache") or []) if os.path.isdir(p)]
    return out

MIN_BLOB = 64                  # nothing smaller can be an encrypted media object
MAX_BLOB = 256 * 1024 * 1024   # don't read a pathological file into memory

def cache_roots(*paths) -> list[str]:
    """Widen the given profile/origin dirs to everywhere a browser might have cached media.

    A Firefox `--origin` points at `<profile>/storage/default/https+++web.whatsapp.com`, which holds
    `cache/morgue` but not `cache2`; so when an origin is given, its profile root is added too.
    """
    roots = []
    for p in paths:
        if not p:
            continue
        p = os.path.abspath(p)
        if os.path.isdir(p):
            roots.append(p)
        parts = p.replace("\\", "/").split("/")
        if "storage" in parts:                          # .../<profile>/storage/default/<origin>
            up = "/".join(parts[:parts.index("storage")])
            if up and os.path.isdir(up):
                roots.append(up)
    seen, out = set(), []
    for r in roots:
        k = os.path.normcase(r)
        if k not in seen:
            seen.add(k); out.append(r)
    return out

def recover(wanted, *paths, verbose=False, log=print):
    """wanted: iterable/dict of encFileSha256 (base64 str). -> ({enc_sha: ciphertext}, stats).

    Every candidate body is hashed and kept only if the message store asked for that exact hash, so
    a misparsed entry can never be mistaken for evidence.
    """
    want = set(wanted)
    found, stats = {}, {"roots": 0, "files": 0, "bodies": 0, "by_source": {}}
    if not want:
        return found, stats
    jobs = [(r, SOURCES) for r in cache_roots(*paths)]
    seen_given = set()
    for p in list(paths) + [None]:
        for c in _given_caches(p):
            if os.path.normcase(c) not in seen_given:
                seen_given.add(os.path.normcase(c)); jobs.append((c, GIVEN))
    for root, sources in jobs:
        stats["roots"] += 1
        for label, pattern, extractors in sources:
            # the root is escaped: a '[' in a case folder's name is a glob character class, and every
            # pattern under it matched nothing -- 0 of 3,135 cached files on such a copy
            for path in glob.iglob(os.path.join(glob.escape(root), pattern), recursive=True):
                if not os.path.isfile(path):
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size < MIN_BLOB or size > MAX_BLOB:
                    continue
                stats["files"] += 1
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                for ex in extractors:
                    try: bodies = list(ex(data))
                    except Exception: bodies = []
                    for body in bodies:
                        if not body or len(body) < MIN_BLOB:
                            continue
                        stats["bodies"] += 1
                        h = base64.b64encode(hashlib.sha256(body).digest()).decode()
                        if h in want and h not in found:
                            found[h] = body
                            stats["by_source"][label] = stats["by_source"].get(label, 0) + 1
                            if verbose:
                                log(f"    cache hit ({label}): {len(body):,} B  {os.path.basename(path)}")
                            break
                    else:
                        continue
                    break
    return found, stats
