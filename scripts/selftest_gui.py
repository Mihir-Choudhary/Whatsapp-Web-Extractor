#!/usr/bin/env python3
"""selftest_gui.py — the window builds the same command lines the CLI documents.

Drives the real window (hidden) through every option and checks the command it would run, that each
invalid combination is refused with a message instead of being run, and that the command shown for
copying parses back to exactly the arguments that will be executed. Needs a display; without one
(e.g. a headless CI runner) it reports that and exits 0.

Run:  python3 scripts/selftest_gui.py        (exit 0 = all cases pass)
"""
import os, sys, tempfile, shutil, json
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "scripts"))
FAIL = []
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)

print("Stop ends the run and every helper it started (no display needed)")
# A run starts helpers (export_sqlite, the history and queue clients). Ending the run alone left them going:
# on Linux and macOS a history client went on asking the phone after Stop. Here a 'run' starts a 'helper'
# that writes a heartbeat; the window's own start options and Stop end both.
import subprocess, time, types
_stubbed = False
try:
    import tkinter as _tkcheck                              # noqa: F401
except ImportError:                                         # no Tk at all: the process handling needs none
    _tk = types.ModuleType("tkinter"); _tk.Tk = object
    for _n in ("ttk", "filedialog", "messagebox"):
        _m = types.ModuleType("tkinter." + _n); setattr(_tk, _n, _m); sys.modules["tkinter." + _n] = _m
    sys.modules["tkinter"] = _tk; _stubbed = True
import wawf_gui as _G
_t = tempfile.mkdtemp(prefix="wawf_guitest_"); _beat = os.path.join(_t, "beat")
_helper = "import time,sys\nwhile True:\n    open(sys.argv[1],'w').write(str(time.time())); time.sleep(0.2)\n"
_run = "import subprocess,sys\nsubprocess.run([sys.executable,'-c',%r,%r])\n" % (_helper, _beat)
_p = subprocess.Popen([sys.executable, "-c", _run], **_G._run_popen_kwargs())
for _ in range(50):
    if os.path.exists(_beat): break
    time.sleep(0.1)
_G.App.stop(types.SimpleNamespace(proc=_p, status=types.SimpleNamespace(configure=lambda **k: None)))
_p.wait(timeout=20); time.sleep(0.6)
_m1 = os.path.getmtime(_beat); time.sleep(1.0); _m2 = os.path.getmtime(_beat)
check("Stop ends the helper the run started, not only the run", _m2 == _m1)
if _m2 != _m1 and sys.platform != "win32":
    os.system("pkill -f %s" % _beat)                       # the helper it left running
shutil.rmtree(_t, ignore_errors=True)
if _stubbed:
    for _n in [n for n in sys.modules if n == "tkinter" or n.startswith("tkinter.")] + ["wawf_gui"]:
        sys.modules.pop(_n, None)

try:
    import tkinter as tk
    import wawf_gui as G
    app = G.App(); app.withdraw()
except Exception as e:                                     # no display / no Tk
    if FAIL: print("FAILED: " + ", ".join(FAIL)); sys.exit(1)
    print(f"skipped: the window cannot be created here ({type(e).__name__}: {e})"); sys.exit(0)

tmp = tempfile.mkdtemp(prefix="wawf_guitest_")
try:
    prof = os.path.join(tmp, "Profile 1"); os.makedirs(os.path.join(prof, "IndexedDB"))
    out = os.path.join(tmp, "case")
    key = os.path.join(tmp, "companion_enc_static.txt"); open(key, "w").write("x")
    creds = os.path.join(tmp, "creds_in.json"); open(creds, "w").write("{}")
    idb = os.path.join(tmp, "stores", "IndexedDB"); os.makedirs(idb)
    ls = os.path.join(tmp, "stores", "Local Storage"); os.makedirs(ls)
    cache = os.path.join(tmp, "stores", "CacheStorage"); os.makedirs(cache)
    ff = os.path.join(tmp, "https+++web.whatsapp.com"); os.makedirs(os.path.join(ff, "idb")); os.makedirs(os.path.join(ff, "ls"))

    def reset():
        app.src_mode.set("profile"); app.profile.set(prof); app._labels = {}; app._accounts = []
        app.out.set(out); app.fmt_text.set(True); app.fmt_sqlite.set(True); app.fmt_raw.set(False)
        app.key_mode.set("online"); app.key.set(""); app.fetch_media.set(False)
        app.history.set(False); app.refetch.set(False); app.install_node.set(False); app.queue.set(False)
        app.raw_keys.set(False); app.verbose.set(False); app.audit_mode.set("on"); app.creds.set("")
        app.case_id.set(""); app.examiner.set(""); app.case_notes.set(""); app.chats.set("")
        app.st_idb.set(""); app.st_ls.set(""); app.st_cache.set("")
    def args():
        cmd, _ = app._command()
        return cmd[len(app._exe()):]
    def refused(msg_part):
        try:
            app._command(); return False
        except ValueError as e:
            return msg_part.lower() in str(e).lower()
    def pair(a, flag):                                     # value that follows a flag
        return a[a.index(flag) + 1] if flag in a else None

    print("default run")
    reset(); a = args()
    check("profile first, then text+json and sqlite outputs",
          a[0] == prof and pair(a, "--out") == os.path.join(out, "export") and
          ("sqlite:" + os.path.join(out, "database")) in a)
    check("online key capture is the default (no --offline, no --key)", "--offline" not in a and "--key" not in a)
    check("audit database and log file inside the results folder",
          pair(a, "--audit-db") == os.path.join(out, "wawf_audit.db") and pair(a, "--log-file") == os.path.join(out, "wawf.log"))

    print("only some chats")
    reset(); app.chats.set(" Book club ; +1 555 555 0101;;120363000000000001@g.us "); a = args()
    check("one --chat per entry, trimmed, empty entries ignored",
          [a[i + 1] for i, x in enumerate(a) if x == "--chat"] == ["Book club", "+1 555 555 0101", "120363000000000001@g.us"])
    reset(); a = args()
    check("no --chat when the field is empty", "--chat" not in a)
    reset(); app.chats.set("Book club"); app.fmt_raw.set(True)
    check("chats with the raw dump is refused", refused("raw store dump"))

    print("outputs and keys")
    reset(); app.fmt_raw.set(True); app.raw_keys.set(True); a = args()
    check("raw dump with key material", ("raw:" + os.path.join(out, "raw")) in a and "--raw-include-keys" in a)
    reset(); app.key_mode.set("file"); app.key.set(key); a = args()
    check("saved key decrypts offline", pair(a, "--key") == key and "--offline" in a)
    key2 = os.path.join(tmp, "companion_enc_static_device7.txt"); open(key2, "w").write("y")
    reset(); app.key_mode.set("file"); app.key.set(key + "; " + key2); a = args()
    check("two saved keys, one --key each", [a[i + 1] for i, x in enumerate(a) if x == "--key"] == [key, key2])
    reset(); app.key_mode.set("file"); app.key.set(key + "; " + os.path.join(tmp, "missing.txt"))
    check("a missing one of several keys is refused", refused("companion_enc_static"))
    reset(); app.key_mode.set("offline"); a = args()
    check("don't go online", "--offline" in a and "--key" not in a)
    reset(); app.fetch_media.set(True); a = args()
    check("media download", "--fetch-media" in a)
    reset(); app.key_mode.set("file"); app.key.set(key); app.fetch_media.set(True); a = args()
    check("saved key + media download stays online for the media only", "--offline" not in a and "--fetch-media" in a)
    reset(); app.creds.set(creds); a = args()
    check("saved credentials", pair(a, "--creds") == creds)

    print("history, audit, log")
    reset(); app.history.set(True); app.refetch.set(True); app.install_node.set(True); a = args()
    check("history with refetch and Node install, answering prompts with --yes",
          all(x in a for x in ("--history", "--yes", "--history-refetch", "--install-node")))
    reset(); app.queue.set(True); a = args()
    check("server queue recorded after the export", "--queue" in a and "--offline" not in a)
    reset(); app.queue.set(True); app.key_mode.set("file"); app.key.set(key); a = args()
    check("a saved key with the queue stays online", "--queue" in a and "--offline" not in a and pair(a, "--key") == key)
    reset(); app.audit_mode.set("secrets"); a = args()
    check("audit with raw key values", "--audit-secrets" in a and "--audit-db" in a)
    reset(); app.audit_mode.set("off"); a = args()
    check("no audit", "--no-audit" in a and "--audit-db" not in a)
    reset(); app.verbose.set(True); a = args()
    check("detailed log", "-v" in a)
    reset(); app.case_id.set("EX-07"); app.examiner.set("A. Examiner"); app.case_notes.set("item 7, laptop"); a = args()
    check("case number, examiner and notes go to the audit database",
          pair(a, "--case-id") == "EX-07" and pair(a, "--examiner") == "A. Examiner"
          and pair(a, "--case-notes") == "item 7, laptop")

    print("sources")
    reset(); app.src_mode.set("stores"); app.st_idb.set(idb); app.st_ls.set(ls); app.st_cache.set(cache); a = args()
    check("stores given separately", pair(a, "--idb") == idb and pair(a, "--local-storage") == ls
          and pair(a, "--media-cache") == cache and prof not in a)
    reset(); app.src_mode.set("stores"); app.st_idb.set(ff); a = args()
    check("a Firefox origin folder becomes --origin, no Local Storage needed", pair(a, "--origin") == ff and "--idb" not in a)
    accts = [("919000000001 · device 8 · most recent login", "919000000001:8"),
             ("919000000001 · device 7 · earlier login, replaced by device 8", "919000000001:7")]
    reset(); app._accounts = accts; app.account.set(accts[1][0]); a = args()
    check("one session picked: --partition account:device", pair(a, "--partition") == "919000000001:7")
    reset(); app._accounts = accts; app.account.set(G.ALL_SESSIONS); a = args()
    check("all sessions: no --partition", "--partition" not in a)

    print("refusals")
    reset(); app.profile.set(os.path.join(tmp, "missing"))
    check("a missing profile folder", refused("profile folder"))
    reset(); app.fmt_text.set(False); app.fmt_sqlite.set(False)
    check("no output ticked", refused("at least one output"))
    reset(); app.key_mode.set("offline"); app.fetch_media.set(True)
    check("offline with media download", refused("go online"))
    reset(); app.key_mode.set("offline"); app.history.set(True)
    check("offline with history", refused("go online"))
    reset(); app.key_mode.set("offline"); app.queue.set(True)
    check("offline with the server queue", refused("go online"))
    reset(); app.queue.set(True); app.history.set(True); a = args()
    check("server queue and history together in one run", "--queue" in a and "--history" in a)
    reset(); app.fetch_media.set(True); app.fmt_sqlite.set(False)
    check("media download without the database", refused("SQLite"))
    reset(); app.refetch.set(True)
    check("refetch without history", refused("history recovery"))
    reset(); app.raw_keys.set(True)
    check("key material without the raw dump", refused("raw store dump"))
    reset(); app.key_mode.set("file"); app.key.set(os.path.join(tmp, "nope.txt"))
    check("a missing key file", refused("companion_enc_static"))
    reset(); app.src_mode.set("stores"); app.st_idb.set(idb)
    check("Chromium stores without Local Storage", refused("Local Storage"))
    reset(); app.audit_mode.set("off"); app.examiner.set("A. Examiner")
    check("case details with recording switched off", refused("chain-of-custody"))

    print("the command shown for copying")
    reset(); app.out.set(os.path.join(tmp, "a folder with spaces & \"quotes\"")); cmd, _ = app._command()
    shown = G._cmdline(cmd)
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        f = ctypes.windll.shell32.CommandLineToArgvW
        f.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]; f.restype = ctypes.POINTER(wintypes.LPWSTR)
        n = ctypes.c_int(); argv = f(shown, ctypes.byref(n)); back = [argv[i] for i in range(n.value)]
        ctypes.windll.kernel32.LocalFree(argv)
    else:
        import shlex
        back = shlex.split(shown)
    check("parses back to exactly the arguments that run (spaces, quotes, &)", back == cmd)
finally:
    app.destroy()
    shutil.rmtree(tmp, ignore_errors=True)

print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all window cases pass")
