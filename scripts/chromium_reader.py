#!/usr/bin/env python3
"""chromium_reader.py — read WhatsApp Web storage from a Chromium profile (Chrome / Edge / Brave / Opera).

Chromium stores IndexedDB as LevelDB (V8/Blink serialization) and localStorage in its own LevelDB —
totally different from Firefox's SQLite + Mozilla structured-clone. This module normalises both into
the SAME shapes our Firefox path produces, so the decryption + SQLite export logic is reused unchanged:

    localStorage -> { key: value_str }                      (like Firefox ls/data.sqlite)
    idb          -> { db_name: { store_name: [ {..}, ... ] } }   (like model-storage / wawc_db_enc / signal-storage)

Binary values come back as Python `bytes` (Firefox wrapped them as {'__bytes': b'..'}); callers should
use `as_bytes()` to accept either shape.

Where the store lives
---------------------
A profile can hold WhatsApp Web under more than one *storage key*. The plain origin keeps the legacy
layout, `IndexedDB/https_web.whatsapp.com_0.indexeddb.leveldb`, but current Chromium/Edge builds can put
the session under a partitioned key instead (`https://web.whatsapp.com/^1<hi>^2<lo>`, a nonce
partition), whose IndexedDB is `WebStorage/<bucket id>/IndexedDB/indexeddb.leveldb` and whose
localStorage is a separate storage key in `Local Storage/leveldb`. The bucket id -> storage key map is
`WebStorage/QuotaManager`. Every partition is enumerated, each localStorage is paired with the IndexedDB
of the SAME storage key, and the partition holding the signed-in session is the one returned. All of
them are reported in `ACQUISITION`.

Damaged acquisitions
--------------------
A profile copied while the browser is still writing typically contains zero-length or half-written
tables and a torn write-ahead log. A forensic reader must not die on the first bad block, and must not
pretend nothing was lost either: unreadable tables and torn log records are skipped, counted, and
reported. If the IndexedDB metadata itself was lost (database and object-store names), records are
still read by their numeric ids and the stores are identified by the fields their records carry
(`wa_store_signatures`); such names are flagged as inferred.

Requires: ccl_chromium_reader  (pip install "git+https://github.com/cclgroupltd/ccl_chromium_reader.git")

Default Chromium profile locations:
  Chrome  : ~/.config/google-chrome/Default
  Edge    : ~/.config/microsoft-edge/Default
  Brave   : ~/.config/BraveSoftware/Brave-Browser/Default
  (Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default , ...\\Microsoft\\Edge\\User Data\\Default)
"""
from __future__ import annotations
import os, glob, io, json, re, shutil, sqlite3, struct, tempfile, time
from pathlib import Path
import logging
log = logging.getLogger('wawf.chromium')

WA_ORIGIN = "https://web.whatsapp.com"
WA_HOST = "web.whatsapp.com"
WA_IDB_GLOB = "IndexedDB/https_web.whatsapp.com_0.indexeddb.leveldb"

# What the last load_source() found: every partition, which one was used, and what could not be read.
ACQUISITION: dict = {}

# A "profile" can also be a folder holding only this file, naming the stores to read wherever they are:
#   {"idb": [<IndexedDB leveldb dir>, ...], "local_storage": <Local Storage leveldb dir>, "media_cache": [...]}
# so an examiner who has the stores but not the profile around them can still run the tool.
PARTS_FILE = "wawf_parts.json"

def parts(profile):
    """The given-stores description, or None for an ordinary profile folder."""
    f = os.path.join(profile or "", PARTS_FILE)
    if not os.path.isfile(f): return None
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)

def resolve_idb(d):
    """Accept the LevelDB folder itself, or the folder around it (".../IndexedDB", a WebStorage bucket)."""
    for c in (d, os.path.join(d, "indexeddb.leveldb"), os.path.join(d, "IndexedDB", "indexeddb.leveldb"),
              os.path.join(d, "https_web.whatsapp.com_0.indexeddb.leveldb"),
              os.path.join(d, "IndexedDB", "https_web.whatsapp.com_0.indexeddb.leveldb")):
        if os.path.isdir(c) and any(n.startswith("MANIFEST-") or n.endswith((".ldb", ".log")) for n in os.listdir(c)):
            return c
    return None


def as_bytes(v):
    """Accept CCL bytes OR Firefox {'__bytes': b'..'} and return bytes (or None)."""
    if isinstance(v, (bytes, bytearray)): return bytes(v)
    if isinstance(v, dict) and '__bytes' in v: return bytes(v['__bytes'])
    return None


# ---------------------------------------------------------------- damaged-LevelDB tolerance
_DAMAGE = {"tables_skipped": [], "log_records_torn": 0, "deleted_files_ignored": [], "tables_missing": []}


def manifest_live_tables(ldb_dir):
    """Table numbers the database's current MANIFEST lists as live, or None if it cannot be read.
    A table file that is empty or absent but listed here held data the copy does not have; one that is
    not listed is a deleted file, of no consequence."""
    try:
        cur = open(os.path.join(ldb_dir, "CURRENT")).read().strip()
        data = open(os.path.join(ldb_dir, cur), "rb").read()
    except OSError:
        return None
    recs, i, frag = [], 0, b""
    while i + 7 <= len(data):
        left = 32768 - (i % 32768)
        if left < 7: i += left; continue
        ln = data[i + 4] | (data[i + 5] << 8); t = data[i + 6]; p = data[i + 7:i + 7 + ln]; i += 7 + ln
        if t == 1: recs.append(p)
        elif t == 2: frag = p
        elif t == 3: frag += p
        elif t == 4: recs.append(frag + p); frag = b""
        else: break
    def vi(b, j):
        n = s = 0
        while True:
            x = b[j]; j += 1; n |= (x & 0x7f) << s; s += 7
            if not x & 0x80: return n, j
    def sl(b, j):
        n, j = vi(b, j); return b[j:j + n], j + n
    live = set()
    for r in recs:
        j = 0
        try:
            while j < len(r):
                tag, j = vi(r, j)
                if tag == 1: _, j = sl(r, j)
                elif tag in (2, 3, 4, 9): _, j = vi(r, j)
                elif tag == 5: _, j = vi(r, j); _, j = sl(r, j)
                elif tag == 6: _, j = vi(r, j); f, j = vi(r, j); live.discard(f)
                elif tag == 7:
                    _, j = vi(r, j); f, j = vi(r, j); _, j = vi(r, j); _, j = sl(r, j); _, j = sl(r, j); live.add(f)
                else: break
        except IndexError:
            continue
    return live
_HARDENED = False

def _harden_ccl():
    """Make ccl's LevelDB reader skip what a live copy breaks, and count it, instead of raising.

    - a table (.ldb/.sst) that is zero-length or has no valid footer is skipped as a whole;
    - in a write-ahead log, a record cut off by the copy is dropped, and a zero-filled tail (LevelDB
      pre-allocates) ends the block, as LevelDB's own reader does.
    """
    global _HARDENED
    if _HARDENED: return
    from ccl_chromium_reader.storage_formats import ccl_leveldb as L
    BS = L.LogFile.LOG_BLOCK_SIZE

    def _batches(self):
        in_rec, start, buf = False, 0, b""
        for idx, chunk in enumerate(self._get_raw_blocks()):
            with io.BytesIO(chunk) as b:
                while b.tell() < BS - 6:
                    hdr = b.read(7)
                    if len(hdr) < 7: break
                    _crc, length, typ = struct.unpack("<IHB", hdr)
                    if typ not in (1, 2, 3, 4):           # zero padding or garbage: rest of block unusable
                        if in_rec: _DAMAGE["log_records_torn"] += 1
                        in_rec = False
                        break
                    data = b.read(length)
                    if len(data) < length:                # record runs past the end of what was copied
                        if in_rec or typ in (1, 2): _DAMAGE["log_records_torn"] += 1
                        in_rec = False
                        break
                    off = idx * BS + b.tell()
                    if typ == 1:
                        if in_rec: _DAMAGE["log_records_torn"] += 1
                        in_rec = False
                        yield off, data
                    elif typ == 2:
                        if in_rec: _DAMAGE["log_records_torn"] += 1
                        start, buf, in_rec = off, data, True
                    elif not in_rec:                      # middle/last fragment with no first
                        _DAMAGE["log_records_torn"] += 1
                    elif typ == 3:
                        buf += data
                    else:
                        in_rec = False
                        yield start, buf + data
        if in_rec: _DAMAGE["log_records_torn"] += 1

    def _init(self, in_dir):
        self._in_dir = Path(in_dir)
        if not self._in_dir.is_dir():
            raise ValueError("in_dir is not a directory")
        self._files, latest = [], (0, None)
        live = manifest_live_tables(str(self._in_dir))
        present = set()
        for f in self._in_dir.iterdir():
            if not f.is_file(): continue
            if re.match(L.RawLevelDb.DATA_FILE_PATTERN, f.name):
                try:
                    if f.suffix.lower() == ".log":
                        self._files.append(L.LogFile(f))
                    elif f.suffix.lower() in (".ldb", ".sst"):
                        present.add(int(f.stem))
                        if f.stat().st_size == 0: raise ValueError("zero-length table")
                        self._files.append(L.LdbFile(f))
                except Exception as e:
                    num = int(f.stem) if f.stem.isdigit() else None
                    if live is not None and num is not None and f.suffix.lower() in (".ldb", ".sst") and num not in live:
                        _DAMAGE["deleted_files_ignored"].append(f.name)
                    else:
                        _DAMAGE["tables_skipped"].append({"file": f.name, "bytes": f.stat().st_size,
                                                          "reason": str(e).split(" in ")[0][:80]})
            m = re.match(L.ManifestFile.MANIFEST_FILENAME_PATTERN, f.name)
            if m and f.is_file():
                n = int(m.group(1), 16)
                if latest[0] < n: latest = (n, f)
        if live is not None:
            _DAMAGE["tables_missing"].extend("%06d.ldb" % n for n in sorted(live - present))
        try:
            self.manifest = L.ManifestFile(latest[1]) if latest[1] is not None else None
        except Exception as e:
            log.warning("leveldb %s: MANIFEST unreadable (%s); reading tables without it", in_dir, e)
            self.manifest = None

    L.LogFile._get_batches = _batches
    L.ManifestFile._get_batches = _batches
    L.RawLevelDb.__init__ = _init

    # LevelDB blocks are Snappy-compressed; ccl decodes them in pure Python, which dominates the read of
    # a large store. cramjam's compiled decoder gives the same bytes; the original is kept as a fallback.
    try:
        import cramjam
        snappy = L.ccl_simplesnappy
        slow = snappy.decompress
        def _fast(buff):
            data = buff.read()
            try:
                return bytes(cramjam.snappy.decompress_raw(data))
            except Exception:
                return slow(io.BytesIO(data))
        snappy.decompress = _fast
    except ImportError:
        pass
    _HARDENED = True


# ---------------------------------------------------------------- partitions
def _norm_key(k: str) -> str:
    """'https://web.whatsapp.com/' and 'https://web.whatsapp.com' are the same storage key."""
    return re.sub(r"/(?=\^|$)", "", k or "")

def _is_wa_key(k: str) -> bool:
    return bool(re.match(r"https://web\.whatsapp\.com(/|\^|$)", k or ""))

def _quota_buckets(profile: str) -> list:
    """[(bucket_id, storage_key)] for web.whatsapp.com from WebStorage/QuotaManager (empty if unreadable)."""
    qm = os.path.join(profile, "WebStorage", "QuotaManager")
    if not os.path.isfile(qm): return []
    tmp = tempfile.mkdtemp(prefix="waquota_"); _TMP.append(tmp)
    shutil.copy2(qm, tmp)
    j = qm + "-journal"
    if os.path.isfile(j): shutil.copy2(j, tmp)
    try:
        con = sqlite3.connect(os.path.join(tmp, "QuotaManager"))
        rows = con.execute("SELECT id, storage_key FROM buckets").fetchall()
        con.close()
    except Exception as e:
        log.warning("QuotaManager unreadable (%s); WebStorage buckets will be identified by content", e)
        return [(None, None)]
    return [(i, k) for i, k in rows if _is_wa_key(k)]

def find_partitions(profile: str) -> list:
    """Every web.whatsapp.com IndexedDB in the profile: [{storage_key, leveldb, blob, layout}]."""
    out = []
    given = parts(profile)
    if given is not None:
        for d in given.get("idb") or []:
            ldb = resolve_idb(d)
            if not ldb: continue
            blob = ldb[:-len(".leveldb")] + ".blob"
            out.append({"storage_key": None, "leveldb": ldb, "layout": "given: " + ldb,
                        "blob": blob if os.path.isdir(blob) else None})
        return out
    legacy = os.path.join(profile, WA_IDB_GLOB)
    if os.path.isdir(legacy):
        out.append({"storage_key": WA_ORIGIN, "leveldb": legacy, "layout": "IndexedDB (legacy)",
                    "blob": legacy[:-len(".leveldb")] + ".blob"})
    ws = os.path.join(profile, "WebStorage")
    if os.path.isdir(ws):
        buckets = _quota_buckets(profile)
        known = {str(i): k for i, k in buckets if i is not None}
        unknown_map = buckets == [(None, None)]
        for d in sorted(os.listdir(ws)):
            ldb = os.path.join(ws, d, "IndexedDB", "indexeddb.leveldb")
            if not os.path.isdir(ldb): continue
            if d in known or unknown_map:
                out.append({"storage_key": known.get(d), "leveldb": ldb, "layout": f"WebStorage/{d}",
                            "blob": os.path.join(ws, d, "IndexedDB", "indexeddb.blob")})
    for p in out:
        if not os.path.isdir(p["blob"]): p["blob"] = None
    return out

def is_chromium_profile(path) -> bool:
    """A Chromium profile: legacy IndexedDB dir, or the WebStorage bucket layout newer builds use."""
    return bool(path) and (os.path.isdir(os.path.join(path, "IndexedDB")) or
                           os.path.isdir(os.path.join(path, "WebStorage")) or
                           os.path.isfile(os.path.join(path, PARTS_FILE)))

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
            if find_partitions(prof.rstrip("/")):
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


# ---------------------------------------------------------------- localStorage
def read_localstorage_all(profile: str) -> dict:
    """{normalised storage key: {key: value}} for every web.whatsapp.com storage key."""
    _harden_ccl()
    from ccl_chromium_reader import ccl_chromium_localstorage as cls
    given = parts(profile)
    src = (given.get("local_storage") or "") if given is not None else os.path.join(profile, "Local Storage/leveldb")
    if src and not os.path.isfile(os.path.join(src, "CURRENT")) and os.path.isdir(os.path.join(src, "leveldb")):
        src = os.path.join(src, "leveldb")                # the "Local Storage" folder itself was given
    if not src or not os.path.isdir(src): return {}
    db = cls.LocalStoreDb(Path(_copy(src)))
    out = {}
    try:
        for sk in db.iter_storage_keys():
            if not _is_wa_key(sk): continue
            best = {}
            for rec in db.iter_records_for_storage_key(sk):
                seq = getattr(rec, "leveldb_seq_number", 0) or 0
                cur = best.get(rec.script_key)
                if getattr(rec, "is_live", True) and (cur is None or seq > cur[0]):
                    best[rec.script_key] = (seq, rec.value)
            out[_norm_key(sk)] = {k: v for k, (_s, v) in best.items()}
    finally:
        db.close()
    return out

def read_localstorage(profile: str) -> dict:
    """localStorage of the selected (signed-in) partition."""
    return load_source(profile)["localStorage"]


# ---------------------------------------------------------------- IndexedDB
def _recency(rec):
    """Sort key for a record: live records first, then newest LevelDB write first.

    LevelDB never overwrites in place, so an object store holds older versions of a key next to
    the current one. `is_live` (this is the value a read would return) and `seq` (monotonic write
    order) together give a reliable recency ordering — far better than guessing from contents.
    """
    return (1 if rec[0] else 0, rec[1])

def _store_fields(values, sample=400):
    from collections import Counter
    c, k = Counter(), 0
    for v in values:
        if isinstance(v, dict):
            c.update(v.keys()); k += 1
            if k >= sample: break
    return {f for f, n in c.items() if n >= 0.5 * k} if k else set()

def _infer_names(unnamed: dict) -> dict:
    """{(db_id, store_id): fieldset} -> {(db_id, store_id): (db_name, store_name, score)} by signature."""
    try:
        from wa_store_signatures import SIGNATURES
    except ImportError:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from wa_store_signatures import SIGNATURES
        except ImportError:
            log.warning("store signatures unavailable; stores without metadata keep numeric names")
            return {}
    flat = [(db, st, set(f)) for db, stores in SIGNATURES.items() for st, f in stores.items() if f]
    out = {}
    for key, fields in unnamed.items():
        if not fields: continue
        best = max(flat, key=lambda s: len(fields & s[2]) / len(fields | s[2]))
        score = len(fields & best[2]) / len(fields | best[2])
        if score >= 0.6: out[key] = (best[0], best[1], round(score, 3))
    # one database id -> one database name: the name most of its stores voted for
    from collections import Counter
    votes = {}
    for (dbid, _sid), (dbn, _stn, _sc) in out.items():
        votes.setdefault(dbid, Counter())[dbn] += 1
    return {k: v for k, v in out.items() if votes[k[0]].most_common(1)[0][0] == v[0]}

def _read_idb_dir(ldb_dir: str, blob_dir: str | None) -> tuple:
    """-> ({db_name: {store_name: [values newest-first]}}, report). One pass over the LevelDB."""
    _harden_ccl()
    from ccl_chromium_reader import ccl_chromium_indexeddb as idb
    from ccl_chromium_reader.serialization_formats import ccl_blink_value_deserializer, ccl_v8_value_deserializer
    from ccl_chromium_reader.storage_formats import ccl_leveldb as L
    _DAMAGE["tables_skipped"], _DAMAGE["log_records_torn"] = [], 0
    _DAMAGE["deleted_files_ignored"], _DAMAGE["tables_missing"] = [], []
    raw = idb.IndexedDb(ldb_dir, blob_dir)
    names = {d.dbid_no: d.name for d in raw.global_metadata.db_ids}
    T = idb.ObjectStoreMetadataType

    # bucket data records (index id 1) by (db, store) in ONE pass; ccl's per-store iteration rescans
    # every record of the database for every store.
    groups = {}
    blob_index = []                                      # index id 3: where externally stored values live
    for r in raw._fetched_records:
        k = r.key
        if not k: continue
        try:
            dbid, sid, iid, plen = idb.IndexedDb.read_prefix(io.BytesIO(k))
        except ValueError:
            continue
        if iid == 3 and dbid and sid: blob_index.append(r)
        if dbid == 0 or sid == 0 or iid != 1: continue      # metadata, not object data
        groups.setdefault((dbid, sid), []).append((r, k[plen:]))
    # Metadata is already parsed and only the blob index is consulted again, so ccl keeps just that
    # (otherwise every raw record is held twice alongside the decoded values).
    raw._fetched_records = blob_index

    blink = ccl_blink_value_deserializer.BlinkV8Deserializer()
    bad = {}
    decoded = {}
    for dbid, sid in list(groups):
        recs = groups.pop((dbid, sid))                   # each store's raw bytes are released once decoded
        vals = []
        for r, kraw in recs:
            live = r.state == L.KeyState.Live
            if not r.value:
                vals.append((live, r.seq, None)); continue
            key = idb.IdbKey(kraw)
            def _bad(*_a, _c=(dbid, sid)): bad[_c] = bad.get(_c, 0) + 1
            try:
                _ver, vraw = idb._le_varint_from_bytes(r.value)
                pre = raw.read_record_precursor(key, dbid, sid, r.value[len(vraw):], _bad)
                if pre is None: continue
                _bv, obj_raw, _tr, _ext = pre
                v = ccl_v8_value_deserializer.Deserializer(obj_raw, host_object_delegate=blink.read).read()
            except Exception:
                _bad(); continue
            vals.append((live, r.seq, v))
        vals.sort(key=_recency, reverse=True)
        decoded[(dbid, sid)] = [v for _l, _s, v in vals]

    out, inferred = {}, {}
    unnamed = {}
    for (dbid, sid), vals in decoded.items():
        dbn = names.get(dbid)
        stn = None
        if dbn is not None:
            try: stn = raw.get_object_store_metadata(dbid, sid, T.StoreName)
            except Exception: stn = None
        if dbn is None or not stn:
            unnamed[(dbid, sid)] = _store_fields(vals)
            continue
        out.setdefault(dbn, {})[stn] = vals
    if unnamed:
        guess = _infer_names(unnamed)
        for (dbid, sid), vals in decoded.items():
            if (dbid, sid) not in unnamed: continue
            if (dbid, sid) in guess:
                dbn, stn, sc = guess[(dbid, sid)]
                if stn in out.get(dbn, {}):                   # never shadow a store that kept its name
                    stn = f"{stn}#{sid}"
                inferred[f"{dbn}/{stn}"] = {"db_id": dbid, "store_id": sid, "score": sc, "records": len(vals)}
            else:
                dbn, stn = names.get(dbid) or f"db{dbid}", f"store{sid}"
                inferred[f"{dbn}/{stn}"] = {"db_id": dbid, "store_id": sid, "score": None, "records": len(vals)}
            out.setdefault(dbn, {})[stn] = vals
    rep = {
        "databases": {d: {s: len(v) for s, v in st.items()} for d, st in out.items()},
        "metadata_intact": not unnamed,
        "inferred_stores": inferred,
        "undeserializable": {f"{names.get(d, d)}/{s}": n for (d, s), n in bad.items()},
        "tables_skipped": list(_DAMAGE["tables_skipped"]),
        "tables_missing": list(_DAMAGE["tables_missing"]),
        "deleted_files_ignored": list(_DAMAGE["deleted_files_ignored"]),
        "log_records_torn": _DAMAGE["log_records_torn"],
    }
    try: raw.close()
    except Exception: pass
    return out, rep

def _given_ls_key(lss, dbs, partition=None):
    """Pair a store given on its own with a localStorage storage key. Only a store holding a session
    (messages + key store) is paired; with several signed-in keys, --partition picks the account."""
    if not dbs.get("model-storage", {}).get("message"): return None
    signed = [k for k, v in lss.items() if _account(v)]
    if partition:
        want = str(partition).split(":")[0].lstrip("+")
        hit = [k for k in signed if _account(lss[k]) == want or k == _norm_key(partition)]
        if hit: return hit[0]
    if len(signed) == 1: return signed[0]
    if len(signed) > 1:
        log.warning("the given localStorage holds %d signed-in sessions (%s); pass --partition <account> "
                    "to say which one the given IndexedDB belongs to", len(signed),
                    ", ".join(_account(lss[k]) for k in signed))
    return None

def _account(ls: dict):
    """The signed-in account of one partition, from its own localStorage ('<number>:<device>@...')."""
    for k in ("last-wid-md", "last-wid"):
        v = ls.get(k)
        if not v: continue
        try: v = json.loads(v)
        except Exception: pass
        if isinstance(v, str) and "@" in v:
            return v.split("@")[0].split(":")[0]          # '<number>:<device>@s.whatsapp.net' -> number
    return None

def _wid(ls: dict):
    """'<number>:<device>' of the session's own linked device, or None."""
    for k in ("last-wid-md", "last-wid"):
        v = ls.get(k)
        if not v: continue
        try: v = json.loads(v)
        except Exception: pass
        if isinstance(v, str) and "@" in v:
            return v.split("@")[0]
    return None

def _device(ls: dict):
    w = _wid(ls) or ""
    return int(w.split(":")[1]) if ":" in w and w.split(":")[1].isdigit() else None

def _incomplete(rep: dict) -> int:
    return len(rep.get("tables_skipped") or []) + len(rep.get("tables_missing") or [])

def _msg_range(dbs: dict):
    ts = []
    for m in dbs.get("model-storage", {}).get("message", []):
        try:
            t = float(m.get("t") or 0)
            if 1e9 < t < 4e9: ts.append(t)
        except (TypeError, ValueError):
            pass
    return (min(ts), max(ts)) if ts else (None, None)

def session_labels(rows):
    """{index: label} for partitions: the most recent login (highest linked-device number of an account)
    and the earlier ones it replaced. Device numbers increase with every new link of an account."""
    out, by_acct = {}, {}
    for i, r in enumerate(rows):
        if r.get("account") and r.get("device") is not None:
            by_acct.setdefault(r["account"], []).append((r["device"], i))
    for acct, devs in by_acct.items():
        top = max(devs)[0]
        for d, i in devs:
            out[i] = "most recent login" if d == top else "earlier login (replaced by device %d)" % top
    for i, r in enumerate(rows):
        if i not in out:
            out[i] = "no signed-in account" if not r.get("account") else "signed in (device unknown)"
    return out

def _score(idb_dbs: dict, ls: dict) -> tuple:
    """How much this partition looks like the signed-in session (higher = more)."""
    keys = bool(idb_dbs.get("wawc_db_enc", {}).get("keys"))
    msgs = len(idb_dbs.get("model-storage", {}).get("message", []))
    signed = 1 if ("WALid" in ls or "last-wid-md" in ls) and msgs else 0
    return (1 if keys and "WAWebEncKeySalt" in ls else 0, signed, _device(ls) or -1, msgs)

def choose_partition(results, partition=None):
    """results: [(info, storage_key, idb, localStorage, report)]. An explicit `partition` (storage key,
    layout name or account) must match; otherwise the signed-in session with the most messages."""
    if partition is not None:
        want = str(partition).lstrip("+")
        hit = [r for r in results if r[1] == _norm_key(partition) or r[0].get("layout") == partition
               or (_wid(r[3]) or "") == want
               or (":" not in want and _account(r[3]) == want)]
        if len(hit) > 1 and ":" not in want:
            raise SystemExit("account %s has %d sessions in this profile; name one as <account>:<device> "
                             "(%s) or by its storage key" % (want, len(hit), ", ".join(_wid(r[3]) or "?" for r in hit)))
        if not hit:
            raise SystemExit(f"partition {partition!r} not found; present: "
                             f"{[(r[0].get('layout'), _account(r[3]), r[1]) for r in results]}")
        return hit[0]
    return max(results, key=lambda r: _score(r[2], r[3])) if results else None


def session_summary(rows):
    """The sessions of a profile as text lines for the log and the console."""
    labels = session_labels(rows)
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "-"
    lines = []
    for i, r in enumerate(rows):
        state = ("INCOMPLETE COPY: %d table(s) this database lists as live are empty or missing in the copy"
                 % r["incomplete_tables"]) if r.get("incomplete_tables") else "complete"
        lines.append("  %d. %-11s device %-4s %-40s %8s messages  %s .. %s  root key: %-3s  %s%s" % (
            i + 1, r.get("account") or "-", r.get("device") if r.get("device") is not None else "-", labels[i],
            "{:,}".format(r.get("messages") or 0), fmt(r.get("oldest")), fmt(r.get("newest")),
            "yes" if r.get("has_root_key") else "no", state,
            "   <- selected" if r.get("selected") else ""))
        if r.get("deleted_files_ignored"):
            lines.append("       (%d empty file(s) the database no longer lists -- deleted files in the copy -- ignored)"
                         % r["deleted_files_ignored"])
    return lines

class _Heartbeat:
    """Logs a line every `every` seconds until stopped, so a long read is visibly alive."""
    def __init__(self, what, t0, every=20):
        import threading
        self.what, self.t0, self.every = what, t0, every
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
    def _run(self):
        while not self._stop.wait(self.every):
            log.info("  ... %s: %ds", self.what, time.time() - self.t0)
    def stop(self):
        self._stop.set()

def _dir_mb(d):
    try:
        return int(sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(d) for f in fs) / 1e6)
    except OSError:
        return 0

_CACHE = {}

def load_source(profile: str, partition: str | None = None) -> dict:
    """Normalised WhatsApp Web source from a Chromium profile: {'localStorage':{}, 'idb':{db:{store:[..]}}}.

    `partition` selects a storage key explicitly (as printed in ACQUISITION); by default the partition
    holding the signed-in session is chosen. Results are cached per profile for the process: callers
    ask for the same profile several times in one run and the read is the expensive part.
    """
    partition = partition or os.environ.get("WAWF_PARTITION") or None
    ck = (os.path.abspath(profile), partition)
    if ck in _CACHE:
        return _CACHE[ck]
    disk = _disk_cache_path(ck)
    if disk and os.path.isfile(disk):
        try:
            import pickle
            with open(disk, "rb") as fh:
                res, acq = pickle.load(fh)
            ACQUISITION.clear(); ACQUISITION.update(acq)
            _CACHE[ck] = res
            return res
        except Exception as e:
            log.debug("source cache unreadable (%s); reading the profile", e)
    try:
        lss = read_localstorage_all(profile)
        parts = find_partitions(profile)
        results = []
        for n, p in enumerate(parts, 1):
            mb = _dir_mb(p["leveldb"])
            log.info("reading WhatsApp store %d of %d (%s, %d MB) ...", n, len(parts), p["layout"], mb)
            t0 = time.time()
            ldb = _copy(p["leveldb"])
            blob = _copy(p["blob"]) if p["blob"] else None
            beat = _Heartbeat("still reading store %d of %d (%s)" % (n, len(parts), p["layout"]), t0)
            try:
                dbs, rep = _read_idb_dir(ldb, blob)
            except Exception as e:
                log.warning("IndexedDB %s could not be read: %s", p["layout"], e)
                dbs, rep = {}, {"error": str(e)}
            finally:
                beat.stop()
            log.info("  store %d read in %ds: %s records", n, time.time() - t0,
                     "{:,}".format(sum(len(v) for st in dbs.values() for v in st.values())))
            sk = _norm_key(p["storage_key"]) if p["storage_key"] else None
            if sk is None and p["layout"].startswith("given: "):
                sk = _given_ls_key(lss, dbs, partition)    # a given store has no storage key: pair by content
            ls = lss.get(sk, {}) if sk else {}
            results.append((p, sk, dbs, ls, rep))
            cleanup()                                     # free the copy before the next partition
        chosen = choose_partition(results, partition)
        ACQUISITION.clear()
        ACQUISITION.update({
            "profile": os.path.abspath(profile),
            "partitions": [{"storage_key": r[1], "layout": r[0]["layout"], "leveldb": r[0]["leveldb"],
                            "localStorage_keys": len(r[3]),
                            "messages": len(r[2].get("model-storage", {}).get("message", [])),
                            "has_root_key": bool(r[2].get("wawc_db_enc", {}).get("keys")),
                            "signed_in": "WALid" in r[3] or "last-wid-md" in r[3],
                            "account": _account(r[3]), "device": _device(r[3]), "wid": _wid(r[3]),
                            "oldest": _msg_range(r[2])[0], "newest": _msg_range(r[2])[1],
                            "incomplete_tables": _incomplete(r[4]),
                            "deleted_files_ignored": len(r[4].get("deleted_files_ignored") or []),
                            "selected": r is chosen,
                            "read": r[4]} for r in results],
            "localStorage_keys_without_idb": sorted(set(lss) - {r[1] for r in results}),
            "selected": chosen[1] if chosen else None,
            "selected_layout": chosen[0]["layout"] if chosen else None,
        })
        rows = ACQUISITION["partitions"]
        if len(results) > 1 or any(r["incomplete_tables"] for r in rows):
            log.info("WhatsApp sessions in this profile:")
            for line in session_summary(rows):
                log.info(line)
        signed = [r for r in results if _account(r[3]) and r[2].get("model-storage", {}).get("message")]
        if len(signed) > 1:
            ACQUISITION["multiple_accounts"] = [_wid(r[3]) or _account(r[3]) for r in signed]
        if chosen:
            rep = chosen[4]
            if _incomplete(rep):
                log.warning("the selected session's copy is incomplete: %d table(s) its database lists as live "
                            "are empty or missing -- usually a copy taken while the browser was still writing, or "
                            "read below the file system before recent writes reached the disk. Records in them are "
                            "missing from every output; copy the profile again (browser closed) for a complete set.",
                            _incomplete(rep))
            if rep.get("log_records_torn"):
                log.warning("%d log record(s) cut off in the copy were skipped", rep.get("log_records_torn", 0))
            if rep.get("inferred_stores"):
                log.warning("IndexedDB metadata is missing (copied while the browser was writing?); "
                            "%d store(s) identified by their record fields instead of by name",
                            len(rep["inferred_stores"]))
        res = {"localStorage": chosen[3] if chosen else {}, "idb": chosen[2] if chosen else {}}
        _CACHE[ck] = res
        if disk:
            try:
                import pickle
                with open(disk, "wb") as fh:
                    pickle.dump((res, dict(ACQUISITION)), fh, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception as e:
                log.debug("could not write source cache: %s", e)
        return res
    finally:
        cleanup()

def release():
    """Drop this process's parsed copy of the store. A helper process about to read the same store
    gets it from the run's disk cache, so holding a second copy here only doubles peak memory."""
    _CACHE.clear()
    import gc
    gc.collect()

def _disk_cache_path(ck):
    """Per-run cache shared with helper subprocesses, only when the parent run set WAWF_SOURCE_CACHE.

    The parent creates that directory privately and removes it when the run ends. It holds what the
    profile itself holds (including key material), parsed, so a helper does not spend minutes
    re-reading the same LevelDB.
    """
    d = os.environ.get("WAWF_SOURCE_CACHE")
    if not d or not os.path.isdir(d): return None
    import hashlib
    st = []
    for p in find_partitions(ck[0]):
        for f in (p["leveldb"], os.path.join(ck[0], "Local Storage", "leveldb")):
            try: st += [(e.name, e.stat().st_size, e.stat().st_mtime_ns) for e in os.scandir(f)]
            except OSError: pass
    h = hashlib.sha256(repr((ck, sorted(st))).encode()).hexdigest()[:24]
    return os.path.join(d, f"src_{h}.pkl")

def read_indexeddb(profile: str) -> dict:
    return load_source(profile)["idb"]

if __name__ == "__main__":
    import sys
    profs = [sys.argv[1]] if len(sys.argv) > 1 else find_profiles()
    if not profs:
        print("No Chromium profile with web.whatsapp.com IndexedDB found.")
        print("Log into WhatsApp Web on Chrome/Edge first, or pass a profile dir.")
        sys.exit(1)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    for p in profs:
        print(f"=== {p} ===")
        src = load_source(p)
        print(f"  localStorage keys: {len(src['localStorage'])}")
        for k in ("WAWebEncKeySalt", "WANoiseInfo", "WALid", "last-wid-md"):
            print(f"    {k}: {'present' if k in src['localStorage'] else 'MISSING'}")
        for dbn, stores in src["idb"].items():
            print(f"  IDB '{dbn}': " + ", ".join(f"{s}={len(r)}" for s, r in list(stores.items())[:8]))
        print(json.dumps(ACQUISITION, indent=1, default=str)[:6000])
