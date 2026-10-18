#!/usr/bin/env python3
"""selftest_firefox.py -- exercise the Firefox loader, the one engine path with no other coverage.

Builds a Firefox-shaped origin directory -- `idb/*meogdaerlo*.sqlite` with `object_store` and
`object_data`, snappy-compressed structured-clone values, plus `ls/data.sqlite` -- and runs
wa_decrypt.load_firefox over it. What must hold: the identity stores are READ (not just counted),
the counts still come out right, messages normalise, and exact-duplicate records are dropped here
too.
"""
import os, sys, json, sqlite3, tempfile, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sclone, wa_decrypt as WD

FAIL = []
# These tests print message text and contact names, which include emoji. On a Windows console that
# is cp1252 by default -- which is what CI runs -- printing one raises UnicodeEncodeError and the
# suite dies mid-run with a traceback instead of a result.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

def chk(name, got, want):
    if got == want: print("  ok   %s: %r" % (name, got))
    else: FAIL.append(name); print("  FAIL %s: got %r want %r" % (name, got, want))

# --- snappy: emit an UNCOMPRESSED literal block, which snappy_pure must accept ---------------
def snappy_raw(data):
    out = bytearray()
    n = len(data)                      # varint length header
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0));
        if not n: break
    ln = len(data) - 1                 # literal tag; 60..63 mean 1..4 extra length bytes
    if ln < 60:
        out.append(ln << 2)
    elif ln < 256:
        out.append((60 << 2)); out.append(ln)
    else:
        out.append((61 << 2)); out += struct.pack('<H', ln)
    out += data
    return bytes(out)

from snappy_pure import uncompress
probe = snappy_raw(b"hello world, a literal block")
assert uncompress(probe) == b"hello world, a literal block", "fixture snappy encoder is wrong"
print("fixture snappy encoder verified against snappy_pure")

ORIGIN = tempfile.mkdtemp()
os.makedirs(os.path.join(ORIGIN, 'idb'))
os.makedirs(os.path.join(ORIGIN, 'ls'))

# localStorage: Firefox stores it in ls/data.sqlite with a compression_type column
ls = sqlite3.connect(os.path.join(ORIGIN, 'ls', 'data.sqlite'))
ls.execute("CREATE TABLE data(key TEXT, value TEXT, compression_type INTEGER)")
for k, v in (("last-wid-md", json.dumps("919000000001:44@c.us")),
             ("WALid", json.dumps("133400000001:44@lid")),
             ("WAWebEncKeySalt", json.dumps("AAAA"))):
    ls.execute("INSERT INTO data VALUES(?,?,0)", (k, v))
ls.commit(); ls.close()

# the model-storage database, whose filename Firefox mangles to contain 'meogdaerlo'
db = sqlite3.connect(os.path.join(ORIGIN, 'idb', '1234-meogdaerlo-x.sqlite'))
db.execute("CREATE TABLE object_store(id INTEGER, name TEXT)")
db.execute("CREATE TABLE object_data(object_store_id INTEGER, data BLOB)")
STORES = {'message': 1, 'contact': 2, 'group-metadata': 3, 'chat': 4, 'participant': 5}
for name, sid in STORES.items():
    db.execute("INSERT INTO object_store VALUES(?,?)", (sid, name))

# sclone has no serialiser, so write values the deserialiser accepts by round-tripping a known blob.
# Instead of synthesising structured clone, assert the shape the loader needs via monkeypatching
# sclone.loads -- the loader's contract is "whatever sclone gives back", and that is what is under
# test here, not sclone itself.
RECORDS = {
    'message': [
        {"id": "false_120300000009@g.us_A", "type": "chat", "t": 1,
         "msgRowOpaqueData": {"iv": b"\x00" * 16, "_data": b"\x00" * 16, "_scheme": 1},
         "from": "965000000001@lid"},
        {"id": "false_120300000009@g.us_A", "type": "chat", "t": 1,      # EXACT duplicate
         "msgRowOpaqueData": {"iv": b"\x00" * 16, "_data": b"\x00" * 16, "_scheme": 1},
         "from": "965000000001@lid"},
        {"id": "true_120300000009@g.us_B", "type": "chat", "t": 2,
         "msgRowOpaqueData": {"iv": b"\x11" * 16, "_data": b"\x11" * 16, "_scheme": 1},
         "author": "133400000001@lid"},
    ],
    'contact': [{"id": "965000000001@lid", "phoneNumber": "919500000002@c.us", "name": "Priya Desk"},
                {"id": "919500000002@s.whatsapp.net", "pushname": "Priya R Desai"}],
    'group-metadata': [{"id": "120300000009@g.us", "subject": "Weekend plans"}],
    'chat': [{"id": "120300000009@g.us", "name": "stale"}],
    'participant': [{"groupId": "120300000009@g.us", "participants": ["965000000001@lid"],
                     "pastParticipants": [], "admins": [], "superAdmins": []}],
}
order = []
for store, recs in RECORDS.items():
    for r in recs:
        db.execute("INSERT INTO object_data VALUES(?,?)", (STORES[store], snappy_raw(b"x")))
        order.append(r)
db.commit(); db.close()

real_loads = sclone.loads
seq = iter(order)
sclone.loads = lambda b: next(seq)          # hand back the fixture objects in insertion order
try:
    engine, lsd, root, msgs, meta, ids = WD.load(origin=ORIGIN)
finally:
    sclone.loads = real_loads

print("\nfirefox loader")
chk("engine", engine, "firefox")
chk("localStorage read", lsd.get("WALid"), json.dumps("133400000001:44@lid"))
chk("messages normalised", len(msgs), 2)                      # 3 records, one an exact duplicate
chk("the duplicate was dropped", [m["id"] for m in msgs],
    ["false_120300000009@g.us_A", "true_120300000009@g.us_B"])
chk("contact store was READ, not just counted", meta["contact"], 2)
chk("group-metadata counted", meta["group-metadata"], 1)
chk("chat counted", meta["chat"], 1)
chk("identities resolved from the firefox stores", ids.label("965000000001@lid"), "Priya Desk")
chk("lid->phone correlation survives the firefox path",
    ids.row("965000000001@lid")["phone"], "919500000002@c.us")
chk("group subject resolved", ids.label("120300000009@g.us"), "Weekend plans")
chk("own identity picked up from localStorage", ids.is_me("133400000001@lid"), True)
chk("group membership read", len(ids.groups["120300000009@g.us"]["participants"]), 1)

# --- a store whose newest rows are still in the write-ahead log, in an awkwardly named folder ----
# Firefox keeps IndexedDB in WAL mode; on a profile copied from a running browser the newest messages
# exist only in <file>-wal. An `immutable` open ignores that file; a raw path in a file: URI is cut at
# '#' (and '%' starts an escape); and '[12]' in a glob pattern is a character class, so the stores
# were not found at all. Each of them reads nothing here.
print("\nwrite-ahead log and an awkward folder name")
ORIGIN2 = os.path.join(tempfile.mkdtemp(), "Case #12 [A] 100%", "https+++web.whatsapp.com")
os.makedirs(os.path.join(ORIGIN2, "idb"))
dbp = os.path.join(ORIGIN2, "idb", "1234-meogdaerlo-x.sqlite")
w = sqlite3.connect(dbp)
w.execute("PRAGMA journal_mode=WAL"); w.execute("PRAGMA wal_autocheckpoint=0")
w.execute("CREATE TABLE object_store(id INTEGER, name TEXT)")
w.execute("CREATE TABLE object_data(object_store_id INTEGER, data BLOB)")
w.execute("INSERT INTO object_store VALUES(1,'message')"); w.commit()
w.execute("PRAGMA wal_checkpoint(TRUNCATE)")          # the tables reach the main file...
WAL_MSGS = [{"id": "false_120300000009@g.us_W%d" % i, "type": "chat", "t": 10 + i,
             "msgRowOpaqueData": {"iv": b"\x00" * 16, "_data": b"\x00" * 16, "_scheme": 1},
             "from": "965000000001@lid"} for i in range(2)]
for _ in WAL_MSGS:
    w.execute("INSERT INTO object_data VALUES(1,?)", (snappy_raw(b"x"),))
w.commit()                                             # ...and the messages only the log
chk("the messages are only in the log", os.path.getsize(dbp + "-wal") > 0, True)
seq2 = iter(WAL_MSGS)
sclone.loads = lambda b: next(seq2)
try:
    _e, _ls, _r, msgs2, _m, _i = WD.load(origin=ORIGIN2)
finally:
    sclone.loads = real_loads
w.close()
chk("messages still in the log are read", sorted(m["id"] for m in msgs2), sorted(m["id"] for m in WAL_MSGS))

# --- evidence on a network share ----------------------------------------------------------------
# A UNC path in a file: URI was not found (raw), or refused as the URI's host (pathlib's as_uri).
# This machine's own administrative share stands in for a network share; skipped where there is none.
if os.name == "nt":
    import idbutil
    plain = os.path.join(os.path.dirname(dbp), "plain.sqlite")
    w2 = sqlite3.connect(plain); w2.execute("CREATE TABLE t(a)"); w2.execute("INSERT INTO t VALUES(1)"); w2.commit(); w2.close()
    drv, rest = os.path.splitdrive(os.path.abspath(plain))
    unc = "\\\\localhost\\" + drv[0] + "$" + rest
    if os.path.isfile(unc):
        try: got = idbutil.connect_ro(unc).execute("SELECT count(*) FROM t").fetchone()[0]
        except Exception as e: got = "%s: %s" % (type(e).__name__, e)
        chk("a store on a network share (UNC path) is read", got, 1)
    else:
        print("  --   network-share case skipped (no \\\\localhost\\%s$ share here)" % drv[0])

print()
if FAIL:
    print("%d FAILED" % len(FAIL))
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("firefox path OK")
