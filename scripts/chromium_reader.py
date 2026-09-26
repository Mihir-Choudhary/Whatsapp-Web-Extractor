#!/usr/bin/env python3
"""chromium_reader.py — read WhatsApp Web storage from a Chromium profile (Chrome / Edge / Brave / Opera).

Chromium stores IndexedDB as LevelDB (V8/Blink serialization) and localStorage in its own LevelDB —
totally different from Firefox's SQLite + Mozilla structured-clone. This module normalises both into
the SAME shapes our Firefox path produces, so the decryption + SQLite export logic is reused unchanged:

    localStorage -> { key: value_str }                      (like Firefox ls/data.sqlite)
    idb          -> { db_name: { store_name: [ {..}, ... ] } }   (like model-storage / wawc_db_enc / signal-storage)

Binary values come back as Python `bytes` (Firefox wrapped them as {'__bytes': b'..'}); callers should
use `as_bytes()` to accept either shape.

Requires: ccl_chromium_reader  (pip install "git+https://github.com/cclgroupltd/ccl_chromium_reader.git")

Default Chromium profile locations:
  Chrome  : ~/.config/google-chrome/Default
  Edge    : ~/.config/microsoft-edge/Default
  Brave   : ~/.config/BraveSoftware/Brave-Browser/Default
  (Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default , ...\\Microsoft\\Edge\\User Data\\Default)
"""
from __future__ import annotations
import os, glob, json, shutil, tempfile
from pathlib import Path
import logging
log = logging.getLogger('wawf.chromium')

WA_ORIGIN = "https://web.whatsapp.com"
WA_IDB_GLOB = "IndexedDB/https_web.whatsapp.com_0.indexeddb.leveldb"

def as_bytes(v):
    """Accept CCL bytes OR Firefox {'__bytes': b'..'} and return bytes (or None)."""
    if isinstance(v, (bytes, bytearray)): return bytes(v)
    if isinstance(v, dict) and '__bytes' in v: return bytes(v['__bytes'])
    return None

def find_profiles():
    """Return candidate Chromium profile dirs that have web.whatsapp.com IndexedDB."""
    roots = [
        "~/.config/google-chrome", "~/.config/microsoft-edge", "~/.config/chromium",
        "~/.config/BraveSoftware/Brave-Browser", "~/.config/opera",
        "~/snap/chromium/common/chromium",
    ]
    hits = []
    for r in roots:
        for prof in glob.glob(os.path.expanduser(r) + "/*/"):
            if os.path.isdir(os.path.join(prof, WA_IDB_GLOB.split("/")[0])) and \
               glob.glob(os.path.join(prof, WA_IDB_GLOB)):
                hits.append(prof.rstrip("/"))
    return hits

_TMP = []
def _copy(src):
    """Copy a leveldb dir to temp (Chromium may hold a lock). Tracked for cleanup."""
    d = tempfile.mkdtemp(prefix="waread_"); _TMP.append(d)
    dst = os.path.join(d, os.path.basename(src))
    shutil.copytree(src, dst)
    return dst
def cleanup():
    """Remove temp copies made by _copy (call after reads are materialized)."""
    for d in _TMP: shutil.rmtree(d, ignore_errors=True)
    _TMP.clear()

def read_localstorage(profile: str) -> dict:
    from ccl_chromium_reader import ccl_chromium_localstorage as cls
    src = os.path.join(profile, "Local Storage/leveldb")
    db = cls.LocalStoreDb(Path(_copy(src)))
    out = {}
    for rec in db.iter_records_for_storage_key(WA_ORIGIN):
        out[rec.script_key] = rec.value
    db.close()
    return out

def _recency(rec):
    """Sort key for an IndexedDbRecord: live records first, then newest LevelDB write first.

    LevelDB never overwrites in place, so an object store holds older versions of a key next to
    the current one. ccl surfaces `is_live` (this is the value a read would return) and
    `ldb_seq_no` (monotonic write order), which together give a reliable recency ordering — far
    better than guessing from the record's contents.
    """
    try: seq = int(getattr(rec, "ldb_seq_no", 0) or 0)
    except (TypeError, ValueError): seq = 0
    return (1 if getattr(rec, "is_live", False) else 0, seq)

def read_indexeddb(profile: str) -> dict:
    from ccl_chromium_reader import ccl_chromium_indexeddb as idb
    src = glob.glob(os.path.join(profile, WA_IDB_GLOB))
    if not src: return {}
    ldb = _copy(src[0])                                   # <origin>.indexeddb.leveldb
    blob_src = src[0][:-len(".leveldb")] + ".blob"        # sibling <origin>.indexeddb.blob (external values)
    blob = _copy(blob_src) if os.path.isdir(blob_src) else None
    w = idb.WrappedIndexDB(ldb, blob)
    skipped = {}                                          # (db,store) -> count of records that failed to deserialize
    out = {}
    for dbid in w.database_ids:
        db = w[dbid.dbid_no]
        stores = {}
        for osn in db.object_store_names:
            recs = []
            _sk = [0]
            def _skip(*a, _c=_sk, **k): _c[0] += 1        # count bad records instead of silently dropping them
            try:
                for r in db.get_object_store_by_name(osn).iterate_records(bad_deserializer_data_handler=_skip):
                    recs.append(r)
            except Exception as e:                        # a forensic store must not truncate silently -> warn, loud
                log.warning("idb %s/%s: iteration stopped early after %d records (%s) — store may be INCOMPLETE",
                            dbid.name, osn, len(recs), e)
            if _sk[0]: skipped[f"{dbid.name}/{osn}"] = _sk[0]
            # We deliberately read superseded and deleted versions too (they are evidence), so the
            # same key can appear several times. Order NEWEST FIRST — live before stale, then by
            # descending LevelDB sequence number — so a caller that wants the current value can
            # just take the first match, while the older copies stay available behind it.
            recs.sort(key=_recency, reverse=True)
            stores[osn] = [r.value for r in recs]
        out[dbid.name] = stores
    if skipped:                                           # surface dropped records at default log level
        log.warning("idb: %d record(s) across %d store(s) could not be deserialized and were skipped: %s",
                    sum(skipped.values()), len(skipped), skipped)
    return out

def load_source(profile: str) -> dict:
    """Normalised WhatsApp Web source from a Chromium profile: {'localStorage':{}, 'idb':{db:{store:[..]}}}."""
    try:
        return {"localStorage": read_localstorage(profile), "idb": read_indexeddb(profile)}
    finally:
        cleanup()   # records are fully materialised above; safe to delete temp copies

if __name__ == "__main__":
    import sys
    profs = [sys.argv[1]] if len(sys.argv) > 1 else find_profiles()
    if not profs:
        print("No Chromium profile with web.whatsapp.com IndexedDB found.")
        print("Log into WhatsApp Web on Chrome/Edge first, or pass a profile dir.")
        sys.exit(1)
    for p in profs:
        print(f"=== {p} ===")
        src = load_source(p)
        print(f"  localStorage keys: {len(src['localStorage'])}")
        for k in ("WAWebEncKeySalt", "WANoiseInfo", "WALid", "last-wid-md"):
            print(f"    {k}: {'present' if k in src['localStorage'] else 'MISSING'}")
        for dbn, stores in src["idb"].items():
            print(f"  IDB '{dbn}': " + ", ".join(f"{s}={len(r)}" for s, r in list(stores.items())[:8]))
