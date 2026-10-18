#!/usr/bin/env python3
"""export_appstate_keys.py — recover WhatsApp Web's APP-STATE SYNC keys from a browser profile.

Why this matters for `--history`
--------------------------------
On-demand history turned out to work only while WhatsApp Web had been active recently: a run ~30
minutes after the browser last synced returned 11,108 messages, while the same request for the same
chats returned NOTHING 7 hours later and again 38 hours later. The code was identical, the phone was
online and acking, the event pipeline was healthy and the queue was clean — the phone simply stopped
answering.

The difference is what a real WhatsApp Web session does on EVERY connect and this tool never did:
an app-state sync (`resyncAppState`) — the SyncD handshake that pulls the primary's mutation log for
critical_block / critical_unblock_low / regular / regular_high / regular_low. Baileys cannot perform
it without the app-state sync keys, so we skipped it and were simply riding on the freshness of the
browser's last sync. Once the primary no longer considered this companion in sync, on-demand history
stopped being served.

Those keys ARE recoverable. WhatsApp Web keeps them in IndexedDB `model-storage/sync-keys`, one
record per key epoch, shaped exactly like Baileys' own app-state key:

    {keyId: <6 bytes>, timestamp, keyEpoch,
     fingerprint: {rawId, currentIndex, deviceIndexes},
     keyData: {_data, iv, _keyId: 1, _scheme: 1}}      <- EAR-encrypted, scheme 1

`keyData` is wrapped with the SAME at-rest key that decrypts message bodies —
HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt, len=16), AES-CBC-128 — so recovering it
needs the at-rest key (`--enc-static`, from a reconnect or from memory). Each record yields exactly
32 bytes of plaintext, which is the app-state sync key.

    python3 scripts/export_appstate_keys.py --profile <dir> --enc-static <b64> [--out appstate_keys.json]

Output is keyed by the base64 keyId, which is exactly how Baileys addresses
`app-state-sync-key-<id>`:
    {"<b64 keyId>": {"keyData": "<b64 32 bytes>",
                     "fingerprint": {"rawId": .., "currentIndex": .., "deviceIndexes": [..]},
                     "timestamp": ..}}

TREAT THE OUTPUT AS KEY MATERIAL.
"""
from __future__ import annotations
import argparse, base64, glob, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from idbutil import store_id, connect_ro, as_bytes as ab
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def unpad(pt: bytes):
    if not pt:
        return None
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p]) * p:
        return pt[:-p]
    return pt


def load_chromium(profile):
    import chromium_reader as cr
    src = cr.load_source(profile)
    idb, ls = src["idb"], src["localStorage"]
    keys = (idb.get("wawc_db_enc") or {}).get("keys") or []
    if not keys:
        raise SystemExit("wawc_db_enc/keys not found — not a logged-in WhatsApp Web profile?")
    root = ab(keys[0].get("key"))
    salt = ls.get("WAWebEncKeySalt")
    salt = base64.b64decode(salt) if isinstance(salt, str) else ab(salt)
    recs = [r for r in ((idb.get("model-storage") or {}).get("sync-keys") or []) if isinstance(r, dict)]
    return root, salt, recs


def load_firefox(origin):
    from snappy_pure import uncompress
    import sclone
    wc = glob.glob(f"{glob.escape(origin)}/idb/*wcanwec__bd*.sqlite")
    if not wc:
        raise SystemExit("wawc_db_enc IndexedDB not found under " + origin)
    con = connect_ro(wc[0])
    sid = store_id(con, "keys")
    row = con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)).fetchone() if sid else None
    if not row:
        raise SystemExit("root key store 'keys' not found/empty")
    d = uncompress(row[0])
    i = d.find(b"\x0a\x80\xff\xff")                      # CryptoKey marker, as in export_sqlite
    j = d.find(b"\x1f\x00\xff\xff", i)
    root = d[j + 12:j + 12 + 128] if j >= 0 else None
    lsdb = connect_ro(f"{origin}/ls/data.sqlite")
    r = lsdb.execute("SELECT value FROM data WHERE key=?", ("WAWebEncKeySalt",)).fetchone()
    salt = r[0].encode("latin-1", "ignore") if r else None
    mm = glob.glob(f"{glob.escape(origin)}/idb/*meogdaerlo*.sqlite")
    if not mm:
        raise SystemExit("model-storage IndexedDB not found under " + origin)
    con2 = connect_ro(mm[0])
    sid2 = store_id(con2, "sync-keys")
    recs = []
    if sid2 is not None:
        for (raw,) in con2.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid2,)):
            try:
                ob = sclone.loads(uncompress(raw))
            except Exception:
                continue
            if isinstance(ob, dict):
                recs.append(ob)
    return root, salt, recs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", help="Chromium profile dir")
    ap.add_argument("--origin", help="Firefox web.whatsapp.com storage dir")
    ap.add_argument("--enc-static", required=True, help="the at-rest key (companion_enc_static, base64)")
    ap.add_argument("--out", default="appstate_keys.json")
    a = ap.parse_args()
    if not (a.profile or a.origin):
        raise SystemExit("pass --profile (Chromium) or --origin (Firefox)")

    root, salt, recs = (load_chromium(a.profile) if a.profile else load_firefox(a.origin))
    if not root or not salt:
        raise SystemExit("could not read the root key / WAWebEncKeySalt from this profile")
    enc_static = base64.b64decode(a.enc_static)
    # the same scheme-1 key that decrypts message bodies; HKDF is length-agnostic, so a 32B or 128B
    # root both work
    msgkey = HKDF(algorithm=hashes.SHA256(), length=16, salt=enc_static, info=salt).derive(root)

    out, bad = {}, 0
    for r in recs:
        kid, blob = ab(r.get("keyId")), r.get("keyData")
        if not kid or not isinstance(blob, dict):
            bad += 1
            continue
        ct, iv = ab(blob.get("_data")), ab(blob.get("iv"))
        if not ct or not iv:
            bad += 1
            continue
        try:
            pt = unpad(Cipher(algorithms.AES(msgkey), modes.CBC(iv)).decryptor().update(ct))
        except Exception:
            pt = None
        if not pt or len(pt) != 32:            # an app-state sync key is exactly 32 bytes
            bad += 1
            continue
        fp = r.get("fingerprint") or {}
        di = ab(fp.get("deviceIndexes"))
        out[base64.b64encode(kid).decode()] = {
            "keyData": base64.b64encode(pt).decode(),
            "fingerprint": {"rawId": int(fp.get("rawId") or 0),
                            "currentIndex": int(fp.get("currentIndex") or 0),
                            "deviceIndexes": list(di) if di else []},
            "timestamp": int(r.get("timestamp") or 0),
        }
    if not out:
        raise SystemExit("no app-state sync key could be decrypted — is --enc-static the right key "
                         "for THIS profile?")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print(f"[+] app-state sync keys: {len(out)} recovered"
          + (f" ({bad} unusable)" if bad else "") + f" -> {a.out}")
    print("    these let the reconnect perform a real resyncAppState, which is what a live WhatsApp "
          "Web session does on every connect")
    return 0


if __name__ == "__main__":
    sys.exit(main())
