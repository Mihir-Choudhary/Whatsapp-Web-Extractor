#!/usr/bin/env python3
"""selftest_chromium.py — storage partitions, damaged LevelDB, and the message-body schema.

Covers what a real profile exposed and nothing else exercised:
  * a profile can hold WhatsApp Web under several storage keys (the plain origin and partitioned
    keys under WebStorage/<bucket>); the signed-in one is chosen, and an explicit choice wins;
  * a LevelDB copied while the browser was writing: a torn write-ahead-log record and unreadable
    tables are skipped and counted instead of aborting the read;
  * the decrypted body decoded by WhatsApp Web's own schema keeps a link preview out of the text,
    and a body that does not fit the schema is left to the lossless fallback.

Run:  python3 scripts/selftest_chromium.py        (exit 0 = all cases pass)
"""
import os, sys, struct, tempfile, shutil, sqlite3, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chromium_reader as cr
import wa_opaque as WO
import wa_decrypt as WD

FAIL = []
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)

def _vi(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def ld(field, payload):                       # length-delimited protobuf field
    if isinstance(payload, str): payload = payload.encode()
    return _vi(field << 3 | 2) + _vi(len(payload)) + payload

# ---------------------------------------------------------------- body schema
print("message body schema")
cur = ld(1, "see https://example.org") + ld(11, "https://example.org") + ld(12, "Example Domain") + \
      ld(13, "This domain is for use in examples")
row = ld(1, cur)
own, quoted = WD.texts(row)
check("a link message's text is its body only", own == "see https://example.org")
det = WD.body_details(row)
check("...and the preview is exported separately",
      det.get("link") == {"url": "https://example.org", "title": "Example Domain",
                          "description": "This domain is for use in examples"})
media = ld(1, ld(1, "/9j/" + "A" * 80) + ld(3, "holiday photo"))
check("media: the caption is the text, not the stored thumbnail", WD.texts(media)[0] == "holiday photo")
loc = ld(1, _vi(7 << 3 | 1) + struct.pack("<d", 17.385) + _vi(5 << 3 | 1) + struct.pack("<d", 78.4867) + ld(16, "Hyderabad"))
check("a location's coordinates and name are decoded", WD.body_details(loc).get("location", {}).get("name") == "Hyderabad"
      and abs(WD.body_details(loc)["location"]["lat"] - 17.385) < 1e-9)
poll = ld(1, ld(17, "Lunch?") + ld(18, ld(1, "Biryani")) + ld(18, ld(1, "Dosa")) + _vi(20 << 3) + _vi(1))
p = WD.body_details(poll).get("poll", {})
check("a poll's name and every option are decoded", p.get("name") == "Lunch?" and p.get("options") == ["Biryani", "Dosa"])
reply = ld(1, ld(1, "agreed")) + ld(2, ld(1, "shall we meet at 5?"))
check("a reply keeps its own text and the quote apart", WD.texts(reply) == ("agreed", "shall we meet at 5?"))
unknown = ld(1, ld(1, "mine") + ld(2, "a field the schema does not define"))
check("a body with an unknown field is left to the lossless reader",
      WO.decode_row(unknown) is None and "a field the schema does not define" in WD.texts(unknown)[0])
twice = ld(1, ld(1, "first")) + ld(1, ld(1, "second"))
check("a repeated singular message is not merged (nothing is dropped)",
      WO.decode_row(twice) is None and "first" in WD.texts(twice)[0] and "second" in WD.texts(twice)[0])
check("bytes that are not a protobuf do not fit", WO.decode_row(b"\xff\xff\xff") is None)

# ---------------------------------------------------------------- partitions
print("storage partitions")
def res(layout, sk, account, msgs, key=True):
    ls = {"WAWebEncKeySalt": '"c2FsdA=="'}
    if account: ls["last-wid-md"] = '"%s:7@s.whatsapp.net"' % account
    idb = {"model-storage": {"message": [{}] * msgs}, "wawc_db_enc": {"keys": [{}] if key else []}}
    return ({"layout": layout}, sk, idb, ls, {})
qr_leftover = res("IndexedDB (legacy)", "https://web.whatsapp.com", None, 0)
a = res("WebStorage/4", "https://web.whatsapp.com^1123^2456", "919000000001", 1200)
b = res("WebStorage/7", "https://web.whatsapp.com^1789^2012", "919000000002", 300)
check("the signed-in session is chosen over a leftover QR-stage store",
      cr.choose_partition([qr_leftover, a])[1] == a[1])
check("with two accounts the larger session is the default", cr.choose_partition([qr_leftover, b, a])[1] == a[1])
check("an explicit account selects the other session", cr.choose_partition([qr_leftover, a, b], "919000000002")[1] == b[1])
check("...as does its layout name", cr.choose_partition([a, b], "WebStorage/7")[1] == b[1])
check("...or its storage key", cr.choose_partition([a, b], "https://web.whatsapp.com/^1789^2012")[1] == b[1])
try:
    cr.choose_partition([a, b], "919999999999"); check("an unknown selection is refused", False)
except SystemExit as e:
    check("an unknown selection is refused, naming what is present", "919000000001" in str(e))
check("account is read from the partition's own localStorage", cr._account(a[3]) == "919000000001")
check("'https://web.whatsapp.com/' and '...com' are one storage key",
      cr._norm_key("https://web.whatsapp.com/") == cr._norm_key("https://web.whatsapp.com"))

tmp = tempfile.mkdtemp(prefix="wawf_selftest_")
try:
    prof = os.path.join(tmp, "Profile 1")
    for d in ("IndexedDB/https_web.whatsapp.com_0.indexeddb.leveldb", "WebStorage/4/IndexedDB/indexeddb.leveldb",
              "WebStorage/9/IndexedDB/indexeddb.leveldb"):
        os.makedirs(os.path.join(prof, d))
    con = sqlite3.connect(os.path.join(prof, "WebStorage", "QuotaManager"))
    con.execute("CREATE TABLE buckets(id INTEGER PRIMARY KEY, storage_key TEXT)")
    con.executemany("INSERT INTO buckets VALUES(?,?)", [(3, "https://web.whatsapp.com/"),
                    (4, "https://web.whatsapp.com/^1123^2456"), (9, "https://example.com/")])
    con.commit(); con.close()
    parts = cr.find_partitions(prof)
    check("both the legacy store and a WebStorage bucket are found",
          [p["layout"] for p in parts] == ["IndexedDB (legacy)", "WebStorage/4"])
    check("a bucket belonging to another site is ignored", all("9" not in p["layout"] for p in parts))
    check("a profile with only the WebStorage layout is still Chromium",
          cr.is_chromium_profile(prof) and not cr.is_chromium_profile(tmp))

    # ------------------------------------------------------------ profile identity
    print("profile identity")
    import json as _json
    import profile_identity as PI
    moved = os.path.join(tmp, "evidence", "item-07")               # copied elsewhere AND renamed
    os.makedirs(os.path.join(moved, "Local Storage", "leveldb"))
    open(os.path.join(moved, "Edge Profile.ico"), "wb").close()
    _json.dump({"profile": {"name": "Work", "creation_time": "13436191516098894"},
                "extensions": {"last_chrome_version": "154.0.4258.62"}},
               open(os.path.join(moved, "Preferences"), "w"))
    with open(os.path.join(moved, "Local Storage", "leveldb", "LOG"), "w") as f:
        f.write("2026/10/11-16:55:16.243 5f4c Creating DB C:\\Users\\examiner\\AppData\\Local\\Microsoft\\Edge"
                "\\User Data\\Profile 8\\Local Storage\\leveldb since it was missing.\n")
    info = PI.identify(moved)
    check("the browser is identified from its own files", info.get("browser") == "Microsoft Edge")
    check("...with the version that last wrote it", info.get("version") == "154.0.4258.62")
    check("the original folder name is recovered from a LevelDB LOG",
          info.get("original_folder_name") == "Profile 8"
          and info.get("original_path", "").endswith("\\Edge\\User Data\\Profile 8"))
    check("...and the OS user it lived under", info.get("os_user") == "examiner")
    check("the in-browser label is kept apart from the folder name", info.get("display_name") == "Work")
    lin = os.path.join(tmp, "evidence", "item-08")                 # a Linux Brave profile, renamed
    os.makedirs(os.path.join(lin, "Local Storage", "leveldb"))
    with open(os.path.join(lin, "Local Storage", "leveldb", "LOG"), "w") as f:
        f.write("2026/10/11-16:55:16.243 7f2a Creating DB /home/analyst/.config/BraveSoftware/Brave-Browser"
                "/Profile 2/Local Storage/leveldb since it was missing.\n")
    li = PI.identify(lin)
    check("a Linux profile's original path and folder are recovered too",
          li.get("original_folder_name") == "Profile 2" and li.get("os_user") == "analyst"
          and "/.config/BraveSoftware/" in li.get("original_path", ""))

    # ------------------------------------------------------------ stores given without their profile
    print("stores given on their own")
    loose = os.path.join(tmp, "handed-over")
    idbdir = os.path.join(loose, "store-a", "indexeddb.leveldb"); os.makedirs(idbdir)
    open(os.path.join(idbdir, "MANIFEST-000001"), "wb").close()
    with open(os.path.join(idbdir, "LOG"), "w") as f:
        f.write("2026/10/11-16:55:16.300 5f4c Creating DB C:\\Users\\examiner\\AppData\\Local\\Microsoft\\Edge"
                "\\User Data\\Profile 8\\WebStorage\\4\\IndexedDB\\indexeddb.leveldb since it was missing.\n")
    lsdir = os.path.join(loose, "ls", "leveldb"); os.makedirs(lsdir)
    desc = os.path.join(tmp, "desc"); os.makedirs(desc)
    _json.dump({"idb": [os.path.dirname(idbdir)], "local_storage": os.path.dirname(lsdir), "media_cache": []},
               open(os.path.join(desc, cr.PARTS_FILE), "w"))
    gp = cr.find_partitions(desc)
    check("a given store is found from the folder around it", len(gp) == 1 and gp[0]["leveldb"] == idbdir)
    check("a store description counts as a Chromium source", cr.is_chromium_profile(desc))
    gi = PI.identify(desc)
    check("a given store still names the profile it came from",
          gi.get("original_folder_name") == "Profile 8" and gi.get("browser") == "Microsoft Edge")

    # ------------------------------------------------------------ damaged write-ahead log
    print("damaged LevelDB")
    cr._harden_ccl()
    from ccl_chromium_reader.storage_formats import ccl_leveldb as L
    def frag(typ, data):
        return struct.pack("<IHB", zlib.crc32(data) & 0xffffffff, len(data), typ) + data
    def batch(seq, key, val):
        return struct.pack("<QI", seq, 1) + b"\x01" + _vi(len(key)) + key + _vi(len(val)) + val
    good = batch(1, b"k1", b"v1")
    torn = batch(2, b"k2", b"v" * 200)
    logp = os.path.join(tmp, "000003.log")
    with open(logp, "wb") as f:
        f.write(frag(1, good) + frag(2, torn[:100]))          # FIRST fragment, and the copy ends there
    cr._DAMAGE["log_records_torn"] = 0
    recs = list(L.LogFile(L.pathlib.Path(logp)))
    check("the complete record before a torn one is still read", [r.key for r in recs] == [b"k1"])
    check("...and the torn record is counted, not silently dropped", cr._DAMAGE["log_records_torn"] == 1)
    ldbdir = os.path.join(tmp, "db.leveldb"); os.makedirs(ldbdir)
    open(os.path.join(ldbdir, "000005.ldb"), "wb").close()                       # zero-length table
    open(os.path.join(ldbdir, "000006.ldb"), "wb").write(b"\x00" * 100)         # no valid footer
    shutil.copy(logp, os.path.join(ldbdir, "000007.log"))
    cr._DAMAGE["tables_skipped"] = []
    db = L.RawLevelDb(ldbdir)
    check("unreadable tables are skipped instead of aborting the read",
          sorted(t["file"] for t in cr._DAMAGE["tables_skipped"]) == ["000005.ldb", "000006.ldb"])
    check("...and what survives is still read", [r.key for r in db.iterate_records_raw()] == [b"k1"])
    db.close()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all chromium cases pass")
