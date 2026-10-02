#!/usr/bin/env python3
"""mediafetch.py — recover full-resolution WhatsApp Web media for an exported case.

WhatsApp Web never stores decrypted media on disk. What it keeps is the ENCRYPTED blob exactly as
the CDN served it, plus, in each message record, the `mediaKey` needed to decrypt it. So media
recovery is a separate step from message decryption, and there are three sources, in descending
forensic preference:

  1. CACHE  (offline, no network)  The browser's cache holds the ciphertext byte-for-byte. Nothing
     can change under us and the evidence device is not contacted. Every browser and every cache
     layer is handled by scripts/mediacache.py (Chromium simple-cache + blockfile, Firefox
     CacheStorage + cache2), so this works the same on Chrome, Edge, Brave, Opera and Firefox.
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
import sys as _sys
def _force_utf8_stdio():
    """Redirected/piped stdout defaults to the locale encoding, so a box-drawing character
    in a summary raises UnicodeEncodeError and takes the rest of the output with it."""
    for _s in (_sys.stdout, _sys.stderr):
        try: _s.reconfigure(encoding='utf-8', errors='replace')
        except Exception: pass
_force_utf8_stdio()
import argparse, base64, hashlib, os, sqlite3, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mediacache import decrypt_media, ext_for, recover as recover_from_cache

# ---------------------------------------------------------------- CDN ----------------------------
CDN_HOST = "https://mmg.whatsapp.net"

def signature_expiry(url):
    """A WhatsApp CDN url is SIGNED: `oh=` is the signature and `oe=` its expiry, as a hex unix time.
    Returns that expiry, or None when the url carries no signature."""
    import re
    m = re.search(r"[?&]oe=([0-9A-Fa-f]+)", url or "")
    return int(m.group(1), 16) if m else None

# Copied verbatim from a NetLog capture of WhatsApp Web fetching a real media/history object. Header
# fidelity is not cosmetic on these endpoints: static.whatsapp.net returned HTTP 400 to this project
# for a request whose only fault was a bare `Accept: */*`. The captured GET carried no credential of
# any kind -- the `oh=` signature in the URL is the whole authorization -- so matching the browser's
# header set is the only thing that distinguishes an accepted request from a rejected one.
CDN_HEADERS = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9",
    "origin": "https://web.whatsapp.com",
    "referer": "https://web.whatsapp.com/",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/154.0.0.0 Safari/537.36"),
}


def cdn_get(url_or_path: str, timeout=30):
    """Fetch a media object. `url_or_path` is either a COMPLETE signed CDN url or a bare directPath.

    Prefer the complete url the message itself carries (`message_url`, from WhatsApp's
    deprecatedMms3Url): it includes the `oh=`/`oe=` signature, and without that signature the CDN
    only serves objects for a day or two. Measured on a real profile: reconstructing
    mmg.whatsapp.net+directPath gave 403 for everything older than the newest day, while the signed
    url served media a MONTH old. Baileys does the same thing
    (`downloadUrl = isValidMediaUrl ? url : getUrlFromDirectPath(directPath)`), and it is how
    WAInsight fetches media too.
    """
    import urllib.request
    url = url_or_path if str(url_or_path).startswith("http") else CDN_HOST + url_or_path
    req = urllib.request.Request(url, headers=CDN_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

# ---------------------------------------------------------------- main ---------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True, help="the SQLite export from `wawf --out sqlite:PATH`")
    ap.add_argument("--profile", help="browser profile dir, to recover from its cache (offline)")
    ap.add_argument("--origin", help="Firefox web.whatsapp.com storage dir (adds its cache too)")
    ap.add_argument("--cdn", action="store_true", help="also download what the cache does not have (NETWORKED)")
    ap.add_argument("--out", help="media output dir (default: <db dir>/Media/WhatsApp Web)")
    ap.add_argument("--retry-json", help="media_retry_out.json from tools/reconnect/diag_media_retry.js: "
                                         "FRESH directPaths for media whose original path expired")
    ap.add_argument("--no-update-db", action="store_true", help="do not set message_media.file_path")
    ap.add_argument("--limit", type=int, default=0, help="stop after N CDN downloads (0 = no limit)")
    ap.add_argument("--ignore-expiry", action="store_true",
                    help="try the CDN even when the url signature (oe=) has already expired")
    a = ap.parse_args()

    out = a.out or os.path.join(os.path.dirname(os.path.abspath(a.db)), "Media", "WhatsApp Web")
    os.makedirs(out, exist_ok=True)
    db = sqlite3.connect(a.db)
    rows = db.execute("""SELECT message_row_id, direct_path, file_hash, enc_file_hash, media_key,
                                mime_type, file_size, message_url FROM message_media
                         WHERE media_key IS NOT NULL AND file_hash IS NOT NULL""").fetchall()
    print(f"[i] {len(rows)} media message(s) with a mediaKey in {a.db}")
    if not rows:
        print("[!] nothing to do — the export has no media rows with keys"); return 0

    by_ench = {}
    for r in rows:
        if r[3]:
            by_ench.setdefault(r[3], []).append(r)
    print(f"[i] {len(by_ench)} distinct encrypted-blob hashes to look for")

    cached = {}
    if a.profile or a.origin:
        print("[1/2] scanning the browser cache (offline, all cache formats) ...")
        cached, st = recover_from_cache(by_ench, a.profile, a.origin, verbose=True)
        print(f"      {st['files']} cache file(s) under {st['roots']} root(s), "
              f"{len(cached)} matched a message  {st['by_source'] or ''}")

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

    ok = failed = nocache = expired = 0
    dl = dl_bytes = 0        # CDN downloads attempted / bytes pulled
    gone = {}                # HTTP status -> count, so a wall of 403/410 collapses to a tally
    updates = []
    import time as _time
    now = int(_time.time())
    for (rid, dpath, fhash, ench, mkey, mime, _size, murl) in rows:
        body = cached.get(ench)
        src = "cache"
        if body is None and a.cdn:
            # a re-upload gives us a brand-new path; otherwise the signed url beats the bare path
            target = fresh.get(rid) or murl or dpath
            exp = signature_expiry(target)
            if exp and exp <= now and not a.ignore_expiry and rid not in fresh:
                expired += 1                     # the CDN will answer 403; do not waste the request
            elif target and (not a.limit or dl < a.limit):
                try:
                    dl += 1
                    body = cdn_get(target); src = "cdn"; dl_bytes += len(body)
                except Exception as e:
                    code = getattr(e, "code", None)
                    gone[code] = gone.get(code, 0) + 1
                    if len(gone) <= 3 and gone[code] <= 2:
                        print(f"    [cdn {code or type(e).__name__}] msg {rid}")
                    body = None
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
        print(f"[i] CDN: {dl} download(s) attempted, {dl_bytes/1048576:.1f} MiB pulled"
              + (f"; skipped {expired} with an already-expired url signature" if expired else "")
              + (f"; refused: {gone}" if gone else ""))
        # 403 vs 410 are different problems and only one of them is about the URL. Confirmed against
        # the live CDN using signed urls captured from WhatsApp Web itself: a request whose oe= has
        # passed returns 403 (so the expiry IS strictly enforced, and skipping those above is right),
        # while a url whose signature is still valid but whose object WhatsApp has already collected
        # returns 410. Media fetched successfully by the browser was answering 410 two days later,
        # whereas history-sync chunks from the same session were still being served -- message media
        # is purged well before its signature expires, so for a 410 the bytes are gone server-side and
        # no amount of url or signature work recovers them.
        if gone.get(403):
            print(f"[i] {gone[403]} object(s) answered 403 Forbidden — the url signature (oe=) had"
                  " expired. The object may well still exist; a fresh signed path from a re-upload"
                  " request would reach it.")
        if gone.get(410):
            print(f"[i] {gone[410]} object(s) answered 410 Gone — the signature was still valid but"
                  " WhatsApp has purged the object itself. Nothing in the url can recover those;"
                  " only a re-upload could, and the re-upload key problem is still open.")
    if failed:  print(f"[!] {failed} blob(s) found but failed verification (not written)")
    if nocache: print(f"[i] {nocache} media message(s) had no cached blob"
                      + ("" if a.cdn else " — re-run with --cdn to download them"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
