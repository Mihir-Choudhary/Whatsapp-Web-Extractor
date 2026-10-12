#!/usr/bin/env python3
"""wawf — WhatsApp Web Forensics: one CLI for Firefox + Chromium (Chrome/Edge/Brave/Opera).

A single tool (PyInstaller-packageable to a .exe) that decrypts and exports WhatsApp Web from a
browser profile. Global -v/--verbose surfaces DEBUG logs and full tracebacks; --log-file mirrors
everything to a file.

There are no sub-commands. Point the tool at a browser profile and it does the whole job:

  wawf <PROFILE>        recover the device credentials -> capture the at-rest key (reconnect)
                        -> decrypt.  (Formerly the separate creds / reconnect / decrypt commands.)

You must say WHICH profile to examine — nothing is auto-detected. For Chromium
(Chrome/Edge/Brave/Opera/Vivaldi) pass the profile folder itself (the one containing "IndexedDB");
for Firefox pass the profile folder, or --origin for its web.whatsapp.com storage folder.

Output is chosen with --out [FORMAT:]PATH (repeatable; FORMAT = txt | json | sqlite/db | raw). A plain
path writes transcripts.txt + chats.json; sqlite: writes an Android-style msgstore.db + wa.db; raw:
writes every object store verbatim with the bodies decrypted in place, changing nothing else. A
Windows drive letter is never mistaken for a FORMAT.

Two alternative actions replace the default job:
  --history                     pull chat history OLDER than the browser cache from the phone (Node)

Examples:
  wawf "C:\\Users\\<you>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
  wawf <PROFILE> --out sqlite:D:\\case\\db --out txt:D:\\case\\out
  wawf <PROFILE> --key companion_enc_static.txt --out json:D:\\case
"""
from __future__ import annotations
import argparse, sys, os, re, json, base64, hashlib, logging, collections, datetime as dt, subprocess, time

HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # _MEIPASS when frozen (.exe)
sys.path.insert(0, os.path.join(HERE, "scripts")); sys.path.insert(0, HERE)
log = logging.getLogger("wawf")

import audit                                   # chain-of-custody DB (on by default; --no-audit turns it off)
AUDIT = audit.NoAudit()                        # replaced in main() when --audit is given

def _evidence_paths(src):
    """The actual WhatsApp Web store inside a profile. Recording (and walking) a browser's ENTIRE profile is
    slow and misleading — most of it is unrelated cache, and the byte count would describe the browser, not
    the evidence. For Chromium that's the web.whatsapp.com IndexedDB (+ its external blob dir) and the
    localStorage LevelDB; a Firefox --origin dir already IS the store."""
    out = []
    if _is_chromium(src):
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import chromium_reader as cr
        for p in cr.find_partitions(src):                    # legacy layout AND WebStorage/<bucket> partitions
            out.append(p["leveldb"])
            if p["blob"]: out.append(p["blob"])
        for extra in (os.path.join("Local Storage", "leveldb"), os.path.join("WebStorage", "QuotaManager")):
            if os.path.exists(os.path.join(src, extra)): out.append(os.path.join(src, extra))
    return out or [src]

def _is_chromium(path):
    """A Chromium source: a profile (either IndexedDB layout) or stores given on their own -- one
    definition, chromium_reader's, so the CLI and every reader agree."""
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    import chromium_reader as cr
    return cr.is_chromium_profile(path)

def _audit_evidence(src):
    """Record the evidence source: the profile/origin it came from, plus each WhatsApp store inside it with
    file count and total bytes."""
    if not src: return
    AUDIT.event("evidence source", category="acquire", detail={"profile_or_origin": src})
    # Where the profile came from, read from its own files -- the folder may have been copied anywhere
    # and renamed. Best effort: an unidentifiable profile is still examined.
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import profile_identity as _pi
        info = _pi.identify(src)
        log.info("profile: %s", _pi.summary(info))
        AUDIT.event("profile identity", category="acquire", detail=info)
    except Exception as e:
        log.debug("profile identity not determined: %s", e)
    for p in _evidence_paths(src):
        AUDIT.dir_read(p, purpose="WhatsApp Web store (evidence)")

def _audit_db_path(a):
    """The case DB lives WHERE THE OUTPUT GOES, so each case/output dir keeps its own history. --out may be
    a directory (decrypt/sqlite) or a file (creds/reconnect); commands without --out fall back to the CWD."""
    v = getattr(a, "audit_db", None)
    if v: return v                                          # explicit --audit-db <path>
    out = getattr(a, "out", None)
    # The top-level CLI takes --out REPEATEDLY (action="append"), so this is a list there and a plain
    # string on the internal single-output paths. Each entry may also carry a FORMAT: prefix, which is
    # not part of any path. Passing either straight to os.path crashed the run outright -- reachable
    # only by actually typing `--audit --out FORMAT:DIR`, which is why the unit paths never saw it.
    if isinstance(out, (list, tuple)):
        out = _parse_out(out[0])[1] if out else None
    elif isinstance(out, str):
        out = _parse_out(out)[1]
    if out:
        base = _out_workdir(out)        # the folder an --out target lives in
    else:
        base = os.getcwd()
    return os.path.join(base or ".", "wawf_audit.db")

# lazy imports so a missing optional dep (e.g. ccl for Chromium) only bites when actually used
def _imp():
    import wa_decrypt, export_baileys_creds
    return wa_decrypt, export_baileys_creds

def setup_logging(verbose: bool, logfile: str | None):
    lvl = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-7s %(name)s %(message)s" if verbose else "%(levelname)-7s %(message)s"
    root = logging.getLogger()
    root.setLevel(lvl)
    for h in list(root.handlers): root.removeHandler(h)
    sh = logging.StreamHandler(sys.stderr); sh.setFormatter(logging.Formatter(fmt)); root.addHandler(sh)
    if logfile:
        # utf-8, not the locale codepage: on Windows cp1252 dropped every log line holding a name or an arrow
        fh = logging.FileHandler(logfile, encoding="utf-8"); fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s"))
        fh.setLevel(logging.DEBUG); root.addHandler(fh)
        log.debug("logging to file %s", logfile)

# ---------------- profile / origin plumbing ----------------
def _profile_help():
    """Where browser profiles live on THIS machine. Paths are fully expanded (no %LOCALAPPDATA% style
    placeholders) so they can be copy-pasted straight onto the command line."""
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        la = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return ("  Chromium - pass the profile folder itself (the one containing 'IndexedDB'):\n"
                "    " + os.path.join(la, "Google", "Chrome", "User Data", "Default") + "\n"
                "    " + os.path.join(la, "Microsoft", "Edge", "User Data", "Default") + "\n"
                "    " + os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data", "Default") + "\n"
                "  Firefox - the profile folder (or --origin for its web.whatsapp.com storage folder):\n"
                "    " + os.path.join(ad, "Mozilla", "Firefox", "Profiles", "<name>.default"))
    if sys.platform == "darwin":
        asup = os.path.join(home, "Library", "Application Support")
        return ("  Chromium - pass the profile folder itself (the one containing 'IndexedDB'):\n"
                "    " + os.path.join(asup, "Google", "Chrome", "Default") + "\n"
                "    " + os.path.join(asup, "Microsoft Edge", "Default") + "\n"
                "  Firefox - the profile folder (or --origin for its web.whatsapp.com storage folder):\n"
                "    " + os.path.join(asup, "Firefox", "Profiles", "<name>.default"))
    return ("  Chromium - pass the profile folder itself (the one containing 'IndexedDB'):\n"
            "    " + os.path.join(home, ".config", "google-chrome", "Default") + "\n"
            "    " + os.path.join(home, ".config", "microsoft-edge", "Default") + "\n"
            "  Firefox - the profile folder (or --origin for its web.whatsapp.com storage folder):\n"
            "    " + os.path.join(home, ".mozilla", "firefox", "<name>.default"))

def _example_profile():
    """One real, copy-pasteable profile path for this machine, used in the help examples."""
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        la = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        return os.path.join(la, "Microsoft", "Edge", "User Data", "Default")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "Google", "Chrome", "Default")
    return os.path.join(home, ".config", "google-chrome", "Default")

_OUT_FORMATS = ("txt", "json", "sqlite", "db", "raw")

EXPORT_MANIFEST = "wawf_export.json"

def _write_export_manifest(outdir, composition, counts, files):
    """Leave a receipt in an output folder: what this export contains, and what produced it.

    Two jobs. It tells a reader whether they are looking at the local store alone or the local store
    plus messages recovered from the phone -- the artifacts themselves do not say, and the difference
    is one of provenance, not detail. And it lets a later `--history` run NAME what is already in a
    folder instead of silently writing over it.
    """
    try:
        os.makedirs(outdir, exist_ok=True)
        rec = {"tool": "wawf", "version": _wawf_version(), "created_utc": dt.datetime.now(dt.timezone.utc)
               .strftime("%Y-%m-%d %H:%M:%S"), "composition": composition, "counts": counts,
               "artifacts": sorted(f for f in files if os.path.isfile(os.path.join(outdir, f)))}
        tmp = os.path.join(outdir, EXPORT_MANIFEST + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rec, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(outdir, EXPORT_MANIFEST))
    except Exception as e:                       # a missing receipt must never fail an export
        log.debug("could not write %s: %s", EXPORT_MANIFEST, e)

def _read_export_manifest(outdir):
    try:
        with open(os.path.join(outdir, EXPORT_MANIFEST), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

_EXPORT_ARTIFACTS = ("chats.json", "transcripts.txt", "identities.json", "msgstore.db", "wa.db",
                     "_manifest.json")

def _holds_export(path):
    """Does this folder already hold an export? The receipt if there is one, else its artifacts."""
    m = _read_export_manifest(path)
    if m: return m
    try:
        if any(os.path.isfile(os.path.join(path, f)) for f in _EXPORT_ARTIFACTS):
            return {"composition": "unknown", "created_utc": "?", "counts": {}}
    except Exception as e:
        log.debug("could not inspect %s: %s", path, e)
    return None

WAWF_RELEASE = "1.0.2"                  # the last tagged release this code descends from

def _wawf_version():
    """The exact code that produced an artifact: release + git commit (+ ".dirty" if the working tree
    has uncommitted changes), or the release alone in a frozen build / outside a checkout.

    This used to return the first line of the module docstring, so every export receipt said its
    version was "wawf - WhatsApp Web Forensics: one CLI for ...", and the audit database recorded a
    hard-coded "1.0" for every build. Neither can tell an examiner which extractor wrote an export --
    and the extractor's output changed materially between commits."""
    if os.environ.get("WAWF_VERSION"):
        return os.environ["WAWF_VERSION"]
    v = WAWF_RELEASE
    if not getattr(sys, "frozen", False):
        try:
            import subprocess
            here = os.path.dirname(os.path.abspath(__file__))
            sha = subprocess.run(["git", "-C", here, "rev-parse", "--short=12", "HEAD"], capture_output=True,
                                 text=True, timeout=5).stdout.strip()
            if sha:
                dirty = subprocess.run(["git", "-C", here, "status", "--porcelain", "--untracked-files=no"],
                                       capture_output=True, text=True, timeout=5).stdout.strip()
                v += "+git." + sha + (".dirty" if dirty else "")
        except Exception:
            pass
    return v

def _parse_out(spec):
    """'--out FORMAT:PATH' -> (format, path); a bare path -> (None, path) meaning 'all text formats'.

    A single-character head is always a drive letter, so `D:\\case\\out` keeps it instead of being read
    as format 'D'. A longer head that is not a known format is a TYPO, and used to be swallowed: a
    mistyped `--out sqlit:D:\\case\\db` silently became a path, so the run quietly wrote text and JSON
    into a folder named after the mistake instead of the database that was asked for. It is an error
    now. A real path that genuinely contains a colon can still be given as `./my:dir`, which has a
    separator in the head and so is left alone.
    """
    if ":" in spec:
        head, rest = spec.split(":", 1)
        low = head.lower()
        if low in _OUT_FORMATS and rest:
            return ("sqlite" if low in ("sqlite", "db") else low), rest
        if len(head) > 1 and rest and not any(c in head for c in "\\/"):
            _usage("unrecognised output format %r in --out %s\n\nFORMAT must be one of: %s\n"
                   "If that is really a path, write it as ./%s" %
                   (head, spec, ", ".join(_OUT_FORMATS), spec))
    return None, spec

def _out_workdir(path):
    """The folder an --out target lives in (the target itself when it names a folder)."""
    return path if (os.path.isdir(path) or not os.path.splitext(path)[1]) else (os.path.dirname(path) or ".")

def _usage(msg):
    """A usage error: say what is wrong, then exit 2.

    `raise SystemExit("text")` prints the text but exits 1, and the documented contract is
    `0 ok · 1 error · 2 bad usage · 3 wrong key · 4 file not found` -- so every bad-usage path was
    returning the code for "something went wrong" instead, which a script cannot tell apart from a
    failed decrypt.
    """
    log.error("%s", msg)
    raise SystemExit(2)

def _require_source(a, cmd="<command>"):
    """Every data command needs an explicit profile (or Firefox --origin). Nothing is guessed: which
    profile gets examined is always the user's choice. Fail with the paths to look in, not a bare usage line."""
    prof, orig = getattr(a, "profile", None), getattr(a, "origin", None)
    if not prof and not orig:
        _usage("no profile given. Pass the browser profile directory to examine, or --origin for a "
               "Firefox\nweb.whatsapp.com storage dir. Profiles are NOT auto-detected.\n\n"
               "Profile locations on this system:\n" + _profile_help() +
               "\n\nExample:\n  wawf " + cmd + " <profile-dir>")
    # Checked HERE, not discovered three minutes later inside a storage reader. Pointing at a path
    # that does not exist used to surface as `OperationalError: unable to open database file`, which
    # says nothing about the profile being wrong -- and only after an audit database had been created
    # for a run that could never work.
    for what, path in (("--origin", orig), ("profile", prof)):
        if path and not os.path.isdir(path):
            _usage("no such %s directory:\n  %s\n\nProfile locations on this system:\n%s"
                   % (what, path, _profile_help()))
    if prof and not orig:
        chromium = _is_chromium(prof)
        firefox = os.path.isdir(os.path.join(prof, "storage", "default", "https+++web.whatsapp.com"))
        if not chromium and not firefox:
            # the profile may be nested inside the given folder: use it if there is exactly one
            found = _nested_profiles(prof)
            if len(found) == 1:
                log.info("using the profile inside the given folder: %s", found[0])
                a.profile = prof = found[0]
                chromium = _is_chromium(prof)
                firefox = not chromium
            elif len(found) > 1:
                _usage("that folder holds %d browser profiles with WhatsApp Web storage; pass the one to examine:\n  %s"
                       % (len(found), "\n  ".join(found)))
        if not chromium and not firefox:
            _usage("that directory is not a browser profile with WhatsApp Web storage:\n  %s\n\n"
                   "Expected either an IndexedDB folder (Chrome/Edge/Brave/Opera) or\n"
                   "storage/default/https+++web.whatsapp.com (Firefox) inside it.\n\n"
                   "Profile locations on this system:\n%s" % (prof, _profile_help()))

def _has_whatsapp_storage(d):
    """Cheap test (no store is read): does this profile folder hold WhatsApp Web storage?"""
    if os.path.isdir(os.path.join(d, "storage", "default", "https+++web.whatsapp.com")):
        return True
    idb = os.path.join(d, "IndexedDB")
    if os.path.isdir(idb) and any(n.startswith("https_web.whatsapp.com") for n in os.listdir(idb)):
        return True
    if os.path.isdir(os.path.join(d, "WebStorage")):
        import chromium_reader as _cr
        return bool(_cr._quota_buckets(d))       # the bucket index names each bucket's site
    return False

def _nested_profiles(root, depth=4):
    """Profile folders with WhatsApp Web storage under `root`, at most `depth` levels down."""
    out = []
    for cur, dirs, _ in os.walk(root):
        rel = os.path.relpath(cur, root)
        level = 0 if rel == "." else rel.count(os.sep) + 1
        if level > depth:
            dirs[:] = []; continue
        if level and (_is_chromium(cur) or os.path.isdir(os.path.join(cur, "storage", "default"))) \
                and _has_whatsapp_storage(cur):
            out.append(os.path.normpath(cur)); dirs[:] = []          # do not descend into a profile
    return sorted(out)

def _require_session(ls, what="that profile"):
    """A browser can hold WhatsApp Web storage without being a logged-in session (site merely visited, or
    logged out). Say so plainly instead of dying with a KeyError deep inside the key derivation."""
    missing = [k for k in ("last-wid-md", "WAWebEncKeySalt", "WANoiseInfo") if k not in ls]
    if missing:
        _usage("%s has WhatsApp Web storage but is not a logged-in session (missing: %s). Log in to "
               "web.whatsapp.com in that browser, or pass a different profile." % (what, ", ".join(missing)))

# ---------------- subcommands ----------------
def _load_wa(a):
    WD, _ = _imp()
    _require_source(a, "decrypt")                           # a profile (or --origin) is required; nothing is auto-detected
    src = getattr(a, "profile", None) or getattr(a, "origin", None)
    _audit_evidence(src)
    # breadcrumb BEFORE the long read: if the process is killed mid-load, the audit trail still shows the
    # exact stage it died in rather than just 'started'.
    AUDIT.event("reading browser storage (IndexedDB + localStorage) — can take a minute on a large profile",
                category="stage", detail={"source": src})
    engine, ls, root, msgs, meta, ids = WD.load(getattr(a, "profile", None), getattr(a, "origin", None))
    _audit_acquisition(engine)
    log.info("engine=%s  messages=%d  root_key=%s  ls_keys=%d", engine, len(msgs), "yes" if root else "NO", len(ls))
    # what came OUT of the evidence source, and the on-disk root key that everything derives from
    AUDIT.event("loaded WhatsApp Web store", category="acquire",
                detail={"engine": engine, "source": src, "messages": len(msgs),
                        "localStorage_keys": len(ls), "stores": meta, "root_key_found": bool(root)})
    if root:
        AUDIT.crypto("recover", key=root, key_source="IndexedDB wawc_db_enc/keys (root key, non-extractable "
                     "CryptoKey serialized to disk)", input_desc=src,
                     detail={"engine": engine, "root_len": len(root)})
    if not root:
        if getattr(a, "enc_static", None) or not msgs:
            raise SystemExit("root key not found in wawc_db_enc/keys (is this a WhatsApp Web profile?)")
        # A damaged copy can keep the messages and lose the key store. Everything but text still exports.
        log.warning("root key not found in wawc_db_enc/keys: message text cannot be decrypted from this "
                    "copy; exporting everything else")
    return WD, engine, ls, root, msgs, meta, ids

def _audit_acquisition(engine):
    """Record which storage partition was examined, every other one found, and what was unreadable."""
    if engine != "chromium": return
    try:
        import chromium_reader as cr
    except ImportError:
        return
    if cr.ACQUISITION:
        AUDIT.event("storage partitions", category="acquire", detail=cr.ACQUISITION)

def _msg_date(v):
    try:
        v = float(v); v = v/1000 if v > 1e12 else v
        return dt.datetime.fromtimestamp(v, dt.timezone.utc) if 1e9 < v < 2e9 else None
    except Exception: return None

def _summary(engine, ls, msgs, meta):
    """Human-readable stats block for the terminal: message count, date range, chats, contacts, types."""
    try: wid = json.loads(ls.get("last-wid-md", '""')).split("@")[0] or "?"
    except Exception: wid = "?"
    dates = [d for d in (_msg_date(m.get("t")) for m in msgs) if d]
    oldest = min(dates).strftime("%Y-%m-%d") if dates else "?"
    newest = max(dates).strftime("%Y-%m-%d") if dates else "?"
    chats = set(m["chat"] for m in msgs if m.get("chat") and m["chat"] != "?")
    groups = sum(1 for c in chats if c.endswith("@g.us"))
    sent = sum(1 for m in msgs if m.get("from_me")); recv = len(msgs) - sent
    MEDIA = {"image", "video", "audio", "ptt", "document", "sticker", "gif"}
    media = sum(1 for m in msgs if m.get("type") in MEDIA)
    types = collections.Counter((m.get("type") or "?") for m in msgs)
    top = "  ".join(f"{t}:{n}" for t, n in types.most_common(6))
    log.info("──────────── summary ────────────")
    log.info("  account     : %s   (engine=%s)", wid, engine)
    log.info("  messages    : %s total   (%s sent / %s received)", f"{len(msgs):,}", f"{sent:,}", f"{recv:,}")
    log.info("  date range  : %s  →  %s", oldest, newest)
    log.info("  chats       : %d   (%d direct, %d groups)", len(chats), len(chats) - groups, groups)
    if meta:
        log.info("  contacts    : %s   ·   groups: %s   ·   chats(saved): %s",
                 f"{meta.get('contact', 0):,}", f"{meta.get('group-metadata', 0):,}", f"{meta.get('chat', 0):,}")
    log.info("  media msgs  : %s", f"{media:,}")
    log.info("  msg types   : %s", top)
    log.info("─────────────────────────────────")

def cmd_run(a):
    """THE DEFAULT ACTION and the whole point of the tool: recover the device credentials from the profile,
    obtain the at-rest key, and decrypt — in one step. Previously this was three separate sub-commands
    (creds -> reconnect -> decrypt) that the user had to chain by hand."""
    _require_source(a, "")
    outs = [_parse_out(s) for s in (a.out or [])] or [(None, "wawf_out")]
    workdir = _out_workdir(outs[0][1])
    os.makedirs(workdir, exist_ok=True)

    # A named --key is checked BEFORE the expensive part. Reading the browser storage takes minutes
    # on a real profile, and a typo in the path used to be reported only after all of it -- the run
    # did four minutes of work to tell the user a filename was wrong.
    if getattr(a, "key", None):
        if not os.path.isfile(a.key):
            log.error("--key: no such file: %s", a.key)
            return 3
        if not _read_key_file(a.key):
            return 3

    # --creds is documented as "an existing creds_in.json to reuse instead of recovering credentials
    # again", and the default run ignored it completely: it always re-ran the recovery, which is the
    # minutes-long read of the browser storage that the flag exists to skip.
    creds_path = getattr(a, "creds", None)
    if creds_path:
        if not os.path.isfile(creds_path):
            log.error("--creds: no such file: %s", creds_path)
            return 4
        log.info("[1/3] using the credentials in %s (no recovery needed)", os.path.abspath(creds_path))
    else:
        log.info("[1/3] recovering device credentials from the profile ...")
        creds_path = os.path.join(workdir, "creds_in.json")
        if getattr(a, "offline", False):
            creds_path = None                         # credentials only serve the network login
            log.info("      --offline: skipped (they are only needed to sign in)")
        elif cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=creds_path, _internal=True)):
            log.warning("device credentials could not be recovered; continuing without network key capture")
            creds_path = None

    key = _find_key(a, workdir, outs)
    # Record provenance HERE, where it is actually known. It used to be inferred further down as
    # `not a.key`, which is also true of a key the reconnect had just captured -- so a single decrypt
    # failure made the tool discard a seconds-old key, announce it was "left over from before the
    # browser last re-paired", and perform a second pointless network reconnect.
    key_was_guessed = key is not None and not getattr(a, "key", None)
    if not key and getattr(a, "key", None):
        # The user named this file. Falling back to a networked reconnect here would contradict the
        # entire reason --key exists -- it is how you decrypt WITHOUT touching the account -- and
        # would quietly do the one thing the flag was chosen to avoid. _find_key has already said
        # what is wrong with the file.
        log.error("--key was given but could not be used, so stopping rather than reaching for the "
                  "network. Fix the file, or omit --key to capture a fresh one deliberately.")
        return 3
    if not key and getattr(a, "offline", False):
        log.info("[2/3] --offline: no key on hand and the network is not used -- exporting everything "
                 "except message text")
        key_was_guessed = False
    elif not key:
        log.info("[2/3] reconnecting as the linked device to capture the at-rest key (NETWORKED) ...")
        keyfile = os.path.join(workdir, KEY_FILENAME)
        rc = cmd_reconnect(argparse.Namespace(profile=a.profile, origin=a.origin, creds=creds_path,
                                              out=keyfile, verbose=a.verbose)) if creds_path else 3
        key = _read_key_file(keyfile) if not rc else None
        if not key:
            log.warning("could not capture the at-rest key, so message TEXT cannot be decrypted. Exporting "
                        "everything else. To decrypt later, point --key at a companion_enc_static.txt "
                        "captured earlier.")
        key_was_guessed = False          # just captured from the server; not a guess

    # An auto-detected key can be STALE, and silently trusting it is the exact mistake that cost this
    # project days with creds_in.json: the at-rest key changes when the browser re-pairs, just as the
    # Signal identity does, so a companion_enc_static.txt left over from a previous device decrypts
    # nothing. Measured on this very profile after a re-pair: 0 of 60 reference messages validated.
    # cmd_decrypt already refuses a wrong key rather than writing garbage (it returns 3), so when the
    # key was one we GUESSED at, treat that as "guess was wrong" and go capture a real one. An
    # explicit --key is different: the user named that file, so a failure is reported, not papered over.
    guessed = key_was_guessed

    def _decrypt_all(k):
        for fmt, path in outs:
            hf = getattr(a, "history_file", None)
            if fmt == "sqlite":
                rc = cmd_sqlite(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k,
                                                   out=path, history_file=hf))
            elif fmt == "raw":
                # `raw` is a verbatim image of what is IN the store, so recovered messages have no
                # place in it: they were never stored. Said out loud rather than quietly skipped.
                if hf: log.info("raw: an image of the local store only -- messages recovered from the "
                                "phone were never in it, so they are in the other formats")
                rc = cmd_raw(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k, out=path,
                                                raw_include_keys=getattr(a, "raw_include_keys", False)))
            else:
                rc = cmd_decrypt(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k,
                                                    out=path, only=fmt, history_file=hf))
            if rc:
                return rc
        return 0

    if guessed and key:
        log.info("[3/3] decrypting to %d output(s) ...", len(outs))
        rc = _decrypt_all(key)
        if rc != 3:
            return rc
        log.warning("that key does not match this profile -- it is almost certainly left over from "
                    "before the browser last re-paired. Discarding it and capturing a fresh one.")
        keyfile = os.path.join(workdir, KEY_FILENAME)
        rc = cmd_reconnect(argparse.Namespace(profile=a.profile, origin=a.origin, creds=creds_path,
                                              out=keyfile, verbose=a.verbose))
        if rc:
            log.error("could not capture a fresh at-rest key, so there is nothing to decrypt with.")
            return rc
        key = _read_key_file(keyfile)
        if not key:
            return 3

    log.info("[3/3] decrypting to %d output(s) ...", len(outs))
    hf = getattr(a, "history_file", None)
    for fmt, path in outs:
        if fmt == "sqlite":
            rc = cmd_sqlite(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key,
                                               out=path, history_file=hf))
        elif fmt == "raw":
            if hf: log.info("raw: an image of the local store only -- messages recovered from the "
                            "phone were never in it, so they are in the other formats")
            rc = cmd_raw(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key, out=path,
                                            raw_include_keys=getattr(a, "raw_include_keys", False)))
        else:
            rc = cmd_decrypt(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key,
                                                out=path, only=fmt, history_file=hf))
        if rc: return rc
    # A --history run fetches media itself once the recovered messages are merged; a plain run does it here.
    if getattr(a, "fetch_media", False) and not hf:
        _fetch_media(a, [path for fmt, path in outs if fmt == "sqlite"])
    return 0

def _fetch_media(a, sqlite_dirs):
    """Download, decrypt and verify media the browser never cached, from WhatsApp's CDN (networked).
    Each message carries its own mediaKey; a url whose signature has expired is skipped unasked."""
    if not sqlite_dirs:
        log.warning("--fetch-media needs an --out sqlite:PATH export to work from; nothing fetched")
        return
    for path in sqlite_dirs:
        db = os.path.join(path, "msgstore.db")
        if not os.path.isfile(db):
            log.warning("--fetch-media: no msgstore.db in %s", path); continue
        log.info("--fetch-media: downloading media the browser never cached from WhatsApp's CDN "
                 "(NETWORKED; newest first; expired links are skipped)")
        _sub("mediafetch.py", ["--db", db, "--cdn"] + (["--profile", a.profile] if a.profile else []) +
             (["--origin", a.origin] if a.origin else []))

KEY_FILENAME = "companion_enc_static.txt"


def _read_key_file(path):
    """Read a companion_enc_static.txt and sanity-check it before it is trusted as a key.

    The file holds base64 of a 32-byte secret. Checking that here turns "it decrypted nothing and I
    cannot tell why" into one clear sentence, for the cost of a single decode.
    """
    try:
        raw = open(path, encoding="utf-8").read().strip()
    except OSError as e:
        log.error("could not read the key file %s (%s)", path, e)
        return None
    if not raw:
        log.error("the key file %s is empty", path)
        return None
    try:
        if len(base64.b64decode(raw, validate=True)) != 32:
            log.error("%s does not look like companion_enc_static: expected base64 of 32 bytes", path)
            return None
    except Exception:
        log.error("%s is not valid base64, so it is not a companion_enc_static file", path)
        return None
    return raw


def _find_key(a, workdir, outs):
    """Locate the at-rest key WITHOUT asking the user to type it.

    `companion_enc_static` is issued by WhatsApp's servers and never written to disk by the browser,
    so it has to come from somewhere: the networked reconnect, a memory scan, or a copy this tool
    captured earlier. It used to be passed in as base64 on the command line, which is the one thing a
    tool handling someone else's key material should not invite -- an inline secret lands in shell
    history, in process listings and in anything that audits commands. So it is read from a FILE, and
    in the normal case found with no flag at all: this tool writes it beside its own work, so a re-run
    picks it up and skips the network entirely.

    Returns the base64 key, or None meaning "go and capture one".
    """
    if getattr(a, "key", None):                      # an explicit --key FILE wins
        if not os.path.isfile(a.key):
            log.error("--key: no such file: %s", a.key)
            return None
        k = _read_key_file(a.key)
        if k:
            log.info("[2/3] using the at-rest key from %s (no reconnect needed)", os.path.abspath(a.key))
        return k
    seen = []
    for d in [workdir, os.getcwd()] + [path for _fmt, path in outs]:
        if not d or d in seen:
            continue
        seen.append(d)
        cand = os.path.join(d, KEY_FILENAME)
        if os.path.isfile(cand):
            k = _read_key_file(cand)
            if k:
                log.info("[2/3] found a previously captured at-rest key at %s -- trying it, so this "
                         "run can stay OFFLINE", os.path.abspath(cand))
                return k
    return None


def _pb_tree(buf, depth=0):
    """Decode a protobuf into a field tree WITHOUT a schema.

    The decrypted payload is protobuf: field 1 holds the Message, whose field 1 is `conversation`,
    the text. Keeping it as a tree of (field number, wire type, value) preserves everything the
    bytes say while needing none of WhatsApp's .proto definitions -- so it cannot silently go stale
    when they add a field, and an examiner can see which field a string actually came from instead
    of trusting that it was the message body.
    """
    out, i, n = [], 0, len(buf)

    def varint(j):
        v, sh = 0, 0
        while j < n:
            b = buf[j]; j += 1
            v |= (b & 0x7F) << sh; sh += 7
            if not b & 0x80:
                break
        return v, j

    while i < n:
        try:
            tag, i = varint(i)
            fnum, wt = tag >> 3, tag & 7
            if fnum == 0:
                break
            if wt == 0:
                v, i = varint(i); out.append({"field": fnum, "type": "varint", "value": v})
            elif wt == 5:
                out.append({"field": fnum, "type": "fixed32", "value": buf[i:i + 4].hex()}); i += 4
            elif wt == 1:
                out.append({"field": fnum, "type": "fixed64", "value": buf[i:i + 8].hex()}); i += 8
            elif wt == 2:
                ln, i = varint(i)
                seg = buf[i:i + ln]; i += ln
                try:
                    t = seg.decode("utf-8")
                    if t and all(c.isprintable() or c in "\n\r\t" for c in t):
                        out.append({"field": fnum, "type": "string", "value": t}); continue
                except UnicodeDecodeError:
                    pass
                sub = _pb_tree(seg, depth + 1) if (seg and depth < 6) else None
                if sub:
                    out.append({"field": fnum, "type": "message", "value": sub})
                else:
                    out.append({"field": fnum, "type": "bytes", "b64": base64.b64encode(seg).decode()})
            else:
                break
        except Exception:
            break
    return out


_JSONABLE_MAX_DEPTH = 32


def _jsonable(o, depth=0, seen=None):
    """Make a structured-clone record JSON-serialisable WITHOUT reshaping it.

    Field names, ordering and the literal "<Undefined>" markers are all left exactly as the browser
    stored them -- that fidelity is the entire point of this format. Only things JSON cannot express
    are converted: bytes become {"__bytes__": <base64>, "len": n} so they stay verifiable, and an
    object that is neither of those is rendered as its repr rather than dropped.
    """
    from idbutil import as_bytes as _ab
    if o is None or isinstance(o, (bool, int, float, str)):
        return o
    if isinstance(o, (bytes, bytearray, memoryview)):
        b = bytes(o)
        return {"__bytes__": base64.b64encode(b).decode(), "len": len(b)}
    # The structured clone format PERMITS CYCLES -- an object may reference itself or an ancestor --
    # and `depth` used to be threaded through here without ever being compared to anything, so it
    # read like a guard while being none. One self-referencing record would then recurse until
    # RecursionError and take the whole dump down, losing every store after it. Neither condition
    # occurred in the 70,476 records of this profile, which is exactly why it needs handling now
    # rather than when it appears on someone else's.
    if depth > _JSONABLE_MAX_DEPTH:
        return {"__truncated__": "nesting deeper than %d" % _JSONABLE_MAX_DEPTH}
    if seen is None:
        seen = ()
    if id(o) in seen:
        return {"__cycle__": True}
    if isinstance(o, dict):
        seen = seen + (id(o),)
        return {str(k): _jsonable(v, depth + 1, seen) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        seen = seen + (id(o),)
        return [_jsonable(v, depth + 1, seen) for v in o]
    # JavaScript `undefined` is a VALUE in these records, and distinct from null -- the structured
    # clone format keeps them apart, and whether a field was never set or was explicitly nulled can
    # matter. JSON has neither, so it gets an unambiguous marker of its own rather than falling into
    # the generic repr bucket, where it was indistinguishable from an object we simply could not
    # serialise. Not mapped to null: that would silently merge two different states.
    if type(o).__name__ in ("Undefined", "JSUndefined") or repr(o) == "<Undefined>":
        return {"__undefined__": True}
    # A JavaScript Date. The Chromium deserialiser hands back a NAIVE datetime built as epoch + ms, so
    # it is UTC -- but its repr ("datetime.datetime(2026, 10, 1, 16, 52, 56, 102000)") said neither
    # that nor anything a non-Python reader could parse. Emit the same marker the Firefox reader
    # (sclone) produces, the exact epoch milliseconds, plus the UTC instant spelled out.
    if isinstance(o, dt.datetime):
        if o.tzinfo is None:
            ms = (o - dt.datetime(1970, 1, 1)) / dt.timedelta(milliseconds=1)
        else:
            ms = o.timestamp() * 1000
        utc = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=ms)
        return {"__date_ms": ms, "utc": utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    b = None
    try:
        b = _ab(o)
    except Exception:
        b = None
    if b:
        return {"__bytes__": base64.b64encode(bytes(b)).decode(), "len": len(bytes(b))}
    return {"__repr__": repr(o)}         # whole: a raw export is not the place to shorten anything


# Stores holding key material rather than evidence. A raw dump is meant to travel with a case, and
# these would turn it into a copy of the account's Signal keys and the at-rest root key.
_RAW_SKIP_DBS = ("signal-storage", "wawc_db_enc")


def cmd_raw(a):
    """--out raw:DIR -- decrypt, and change NOTHING else.

    Every other output reshapes: the text writer scrapes strings out of the decrypted protobuf with a
    heuristic walker and dedupes them, so field identity and every
    non-string field are lost. This one emits each record as the browser stored it -- a JavaScript
    object, same field names, same "<Undefined>" markers, nothing renamed or dropped -- and ADDS the
    decrypted payload beside the original rather than in place of it:

        _wawf_plaintext_b64     the decrypted bytes verbatim, so the decryption can be re-checked
        _wawf_plaintext_fields  the same bytes as a schema-free protobuf field tree

    The encrypted msgRowOpaqueData stays exactly where it was, so the file remains a faithful image of
    the store plus a decryption, and never a substitute for it. One JSONL file per object store.
    """
    _require_source(a, "raw")
    if a.profile and _is_chromium(a.profile):
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import chromium_reader as cr
        # ONE call: load_source has no cache -- it re-reads localStorage and the whole IndexedDB and
        # then cleans up on every call -- so asking twice parsed a 54 MB LevelDB twice for nothing.
        _src = cr.load_source(a.profile)
        idb, ls = _src["idb"], _src["localStorage"]
    else:
        log.error("raw output currently supports Chromium profiles only (the Firefox reader returns "
                  "one store at a time); use --out json:DIR for Firefox.")
        return 2

    root = None
    ck = idb.get("wawc_db_enc", {}).get("keys", [])
    if ck and isinstance(ck[0], dict) and hasattr(ck[0].get("key"), "key_data"):
        root = ck[0]["key"].key_data

    cipher_key = None
    if a.enc_static and root and ls.get("WAWebEncKeySalt"):
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        cipher_key = HKDF(algorithm=hashes.SHA256(), length=16,
                          salt=base64.b64decode(a.enc_static),
                          info=base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))).derive(root)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from idbutil import as_bytes as ab

    def decrypt(op):
        """(plaintext, reason) -- reason is None on success, else why it was not decrypted."""
        if cipher_key is None:
            return None, "no key available"
        data, iv = ab(op.get("_data")), ab(op.get("iv"))
        if not data or not iv:
            return None, "no _data/iv on the record"
        if op.get("_scheme") != 1:
            return None, f"scheme {op.get('_scheme')} (this key derives scheme 1 only)"
        try:
            pt = Cipher(algorithms.AES(cipher_key), modes.CBC(bytes(iv))).decryptor().update(bytes(data))
        except Exception as e:
            return None, f"cipher error: {e}"
        if not pt or not (1 <= pt[-1] <= 16) or pt[-pt[-1]:] != bytes([pt[-1]]) * pt[-1]:
            return None, "padding check failed (wrong key for this record)"
        return pt[:-pt[-1]], None

    if cipher_key is None:
        log.warning("no at-rest key available: the raw dump will carry the records as stored, with "
                    "msgRowOpaqueData still encrypted.")
    else:
        # VALIDATE BEFORE WRITING, and report a wrong key with the same exit code the other writers
        # use (3). Without this, cmd_raw returned 0 whatever happened: a stale key produced a dump in
        # which every single body had failed to decrypt, the run said "success", and the caller's
        # stale-key recovery -- which triggers on rc 3 -- never fired. The examiner would get a
        # complete-looking raw dump with nothing decrypted in it, which is the worst possible outcome
        # because nothing about it looks wrong.
        _refs, _good = [], 0
        for _r in idb.get("model-storage", {}).get("message", []):
            if not isinstance(_r, dict):
                continue
            _op = _r.get("msgRowOpaqueData")
            if isinstance(_op, dict) and _op.get("_scheme") == 1 and ab(_op.get("_data")):
                _refs.append(_op)
                if len(_refs) >= 40:
                    break
        for _op in _refs:
            if decrypt(_op)[0] is not None:
                _good += 1
        if _refs and _good < len(_refs) * 0.5:
            log.error("the at-rest key is INVALID for this profile/device (%d/%d reference bodies "
                      "validate). Refusing to write a raw dump with nothing decrypted in it.",
                      _good, len(_refs))
            return 3
        if _refs:
            log.info("at-rest key VALIDATED against %d/%d reference bodies", _good, len(_refs))


    os.makedirs(a.out, exist_ok=True)
    totals = {"stores": 0, "records": 0, "encrypted": 0, "decrypted": 0}
    skipped = collections.Counter()      # encrypted bodies we could NOT decrypt, by reason
    excluded = {}                        # whole stores deliberately not dumped, by database
    manifest = []
    for db in sorted(idb):
        if db in _RAW_SKIP_DBS and not getattr(a, "raw_include_keys", False):
            excluded[db] = sum(len(v) for v in idb[db].values())
            continue
        for st in sorted(idb[db]):
            recs = idb[db][st]
            if not recs:
                # An empty store still EXISTED; for an image of the database that is a fact, so it is
                # listed rather than silently left out.
                manifest.append({"database": db, "store": st, "file": None, "records": 0,
                                 "encrypted": 0, "decrypted": 0, "sha256": None})
                continue
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{db}__{st}")
            path = os.path.join(a.out, safe + ".jsonl")
            n = enc = dec = 0
            with open(path, "w", encoding="utf-8") as f:
                for r in recs:
                    rec = _jsonable(r)
                    if isinstance(r, dict) and isinstance(r.get("msgRowOpaqueData"), dict):
                        enc += 1
                        pt, why = decrypt(r["msgRowOpaqueData"])
                        if pt is not None:
                            dec += 1
                            rec["_wawf_plaintext_b64"] = base64.b64encode(pt).decode()
                            rec["_wawf_plaintext_fields"] = _pb_tree(pt)
                        else:
                            rec["_wawf_plaintext_error"] = why
                            skipped[why] += 1
                    f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                    n += 1
            totals["stores"] += 1; totals["records"] += n
            totals["encrypted"] += enc; totals["decrypted"] += dec
            # The file's hash in the manifest itself: the audit database records it too, but a raw
            # export made with --no-audit otherwise carried no integrity record at all.
            manifest.append({"database": db, "store": st, "file": safe + ".jsonl",
                             "records": n, "encrypted": enc, "decrypted": dec,
                             "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()})
            AUDIT.artifact(path, kind=f"raw store dump ({db}/{st})", records=n)
    json.dump({"format": "wawf-raw/1", "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
               "profile": os.path.abspath(a.profile) if a.profile else None,
               "decryption": "AES-CBC-128, HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt)",
               "note": "records are verbatim as stored; _wawf_plaintext_* fields are ADDED, "
                       "msgRowOpaqueData is left untouched",
               "markers": {"__bytes__": "base64 of a binary value, with its length",
                           "__undefined__": "JavaScript undefined, which JSON cannot express and "
                                            "which is NOT the same as null",
                           "__date_ms": "a JavaScript Date: milliseconds since 1970-01-01 UTC "
                                        "(with `utc`, the same instant as ISO 8601)",
                           "__repr__": "a value no other marker covers, as its Python repr",
                           "__cycle__": "a reference back to an enclosing object",
                           "__truncated__": "nesting beyond the depth cap",
                           "_wawf_plaintext_b64": "decrypted msgRowOpaqueData._data, verbatim",
                           "_wawf_plaintext_fields": "the same bytes as a schema-free protobuf tree",
                           "_wawf_plaintext_error": "why a body could not be decrypted"},
               "totals": totals, "not_decrypted": dict(skipped),
               "excluded_databases": {"reason": "holds key material, not evidence; pass "
                                                "--raw-include-keys to override",
                                      "records_not_dumped": excluded},
               "stores": manifest},
              open(os.path.join(a.out, "_manifest.json"), "w", encoding="utf-8"), indent=1)
    log.info("raw: %d store(s), %d record(s) -> %s", totals["stores"], totals["records"],
             os.path.abspath(a.out))
    log.info("raw: %d record(s) carried an encrypted body, %d decrypted%s",
             totals["encrypted"], totals["decrypted"],
             "" if totals["encrypted"] == totals["decrypted"]
             else f" ({totals['encrypted'] - totals['decrypted']} not -- see _manifest.json)")
    for why, cnt in skipped.most_common():
        log.info("raw:   %d not decrypted: %s", cnt, why)
    if excluded:
        log.info("raw: excluded %d record(s) in %s -- key material, not evidence",
                 sum(excluded.values()), ", ".join(sorted(excluded)))
    return 0


def cmd_decrypt(a):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    WD, engine, ls, root, msgs, meta, ids = _load_wa(a)
    _require_session(ls, getattr(a, "profile", None) or getattr(a, "origin", None))
    _summary(engine, ls, msgs, meta)
    sch = collections.Counter(m["scheme"] for m in msgs if m["data"])
    log.info("message schemes: %s", dict(sch))
    key = None
    if not a.enc_static:
        log.warning("no message key: exporting everything except message text (bodies stay encrypted, "
                    "marked body_status=encrypted)")
        AUDIT.event("metadata-only export: message bodies left encrypted", category="crypto")
    else:
        enc_static = base64.b64decode(a.enc_static)
        salt_ws = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
        key = HKDF(algorithm=hashes.SHA256(), length=16, salt=enc_static, info=salt_ws).derive(root)
        # exactly what derived the message key, so an examiner can reproduce it: root (on disk) + server-only
        # companion_enc_static as HKDF salt + WAWebEncKeySalt as info -> AES-CBC-128
        AUDIT.crypto("derive", algorithm="AES-CBC-128", kdf="HKDF-SHA256 len=16", scheme="1 (final)",
                     key=key, key_source="HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt)",
                     salt=enc_static, salt_source="companion_enc_static (server-issued, never written to disk by the browser)",
                     info="WAWebEncKeySalt (localStorage)", input_desc="msgRowOpaqueData._data (scheme 1)",
                     detail={"root_fp": audit.fp(root), "root_len": len(root), "salt_len": len(enc_static)})
        def strict(b): return bool(b) and len(b) % 16 == 0 and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]])*b[-1]
        refs = [m for m in msgs if m["data"] and m["scheme"] == 1][:40]; good = 0   # scheme-1 only
        for m in refs:
            try:
                if strict(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"])): good += 1
            except Exception as e: log.debug("ref decrypt error: %s", e)
        if refs and good < len(refs) * 0.5:
            log.error("companion_enc_static INVALID for this profile/device (%d/%d refs validate). Not writing garbage.", good, len(refs))
            AUDIT.crypto("verify", algorithm="AES-CBC-128", key=key, validated="FAILED",
                         input_desc="strict PKCS7 on reference ciphertexts", records_in=len(refs), records_ok=good)
            return 3
        log.info("companion_enc_static VALIDATED (%d/%d reference messages)", good, len(refs))
        AUDIT.crypto("verify", algorithm="AES-CBC-128", key=key, validated="OK",
                     input_desc="strict PKCS7 on reference ciphertexts", records_in=len(refs), records_ok=good)
    os.makedirs(a.out, exist_ok=True)
    def ts(v):
        try:
            v = float(v); v = v/1000 if v > 1e12 else v
            return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if 1e9 < v < 2e9 else ""
        except Exception: return ""
    chats = collections.defaultdict(list); ok = fail = nobody = other = 0
    for m in msgs:
        # Every message is written. One without a decryptable body used to be skipped here, so it was
        # missing from chats.json and the transcript while msgstore.db kept it (a sender-deleted
        # message, measured). It is now a row with no text and a body_status saying why.
        if not m["data"]:
            nobody += 1; chats[m["chat"]].append(WD.bodyless_row(m, ts(m["t"]), ids, "none")); continue
        if key is None:
            chats[m["chat"]].append(WD.bodyless_row(m, ts(m["t"]), ids, "encrypted")); continue
        if m["scheme"] != 1:                     # never decrypt another scheme's body into garbage
            other += 1; chats[m["chat"]].append(WD.bodyless_row(m, ts(m["t"]), ids, "other-scheme")); continue
        # CBC consumes whole blocks: update() on a ciphertext that is not a multiple of 16 returns the
        # blocks it could and silently buffers the tail, so a truncated record decrypts to a SHORT
        # plaintext and is still counted as a success. Count it as what it is. None of the 22,121
        # bodies in the reference profile are misaligned; this is about the counts staying truthful
        # on a damaged store, which is exactly the case where they are what is being measured.
        if len(m["data"]) % 16:
            fail += 1; log.debug("misaligned body %s: %d bytes", m["id"][:24], len(m["data"]))
            chats[m["chat"]].append(WD.bodyless_row(m, ts(m["t"]), ids, "failed")); continue
        try: pt = WD.pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception as e:
            fail += 1; log.debug("decrypt fail %s: %s", m["id"][:24], e)
            chats[m["chat"]].append(WD.bodyless_row(m, ts(m["t"]), ids, "failed")); continue
        chats[m["chat"]].append(WD.msg_row(m, ts(m["t"]), pt, ids))
        ok += 1
    for c in chats: chats[c].sort(key=lambda x: x["t"])
    # Messages the phone served, folded in before anything is written, so the export is ONE timeline
    # per chat rather than two files to reconcile by hand. Dedup is on the stanza id and the cached
    # copy wins; every row says which side it came from.
    hist_added = 0
    hf = getattr(a, "history_file", None)
    if hf and os.path.isfile(hf):
        try:
            rec = (json.load(open(hf, encoding="utf-8")) or {}).get("messages") or []
            hist_added, hist_skipped, touched = WD.merge_history(chats, rec, ids, ts)
            _from = ("the server queue" if rec and all(r.get("source") == "server-queue" for r in rec)
                     else "the phone")
            log.info("merged: +%s message(s) from %s across %d chat(s); "
                     "%s already present in the browser's own store",
                     f"{hist_added:,}", _from, len(touched), f"{hist_skipped:,}")
        except Exception as e:
            log.error("could not merge recovered history from %s: %s", hf, e)
            return 1
    # Who is who, measured rather than assumed: every sender's label and where that label came from.
    # "unresolved" is the number an examiner cares about -- jids the profile itself cannot name.
    senders = [m["sender"] for ml in chats.values() for m in ml if m.get("sender")]  # for coverage
    cov = ids.coverage(senders)
    log.info("senders identified: %s", "  ".join(f"{k}={v:,}" for k, v in cov.most_common()) or "none")
    if cov.get("unresolved"):
        log.info("  %d message(s) from jids this profile holds no name or number for — the raw jid is "
                 "used as the label, never a guess", cov["unresolved"])
    only = getattr(a, "only", None)                      # 'txt' / 'json' from --out FORMAT:PATH; None = both
    if only != "txt":
        json.dump(chats, open(f"{a.out}/chats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
        # The correlation table itself, as its own artifact: jid <-> lid <-> phone <-> name, plus group
        # subjects and membership. chats.json carries the resolved name on every message; this is what
        # you join on, and what shows the alternatives a label was chosen from.
        tbl = ids.table(set(chats) | set(senders))
        json.dump(tbl, open(f"{a.out}/identities.json", "w", encoding="utf-8"), ensure_ascii=False,
                  indent=1, default=str)
        AUDIT.artifact(f"{a.out}/identities.json", kind="identity correlation (jid/lid/phone/name)",
                       records=len(tbl["identities"]))
        nc = WD.write_contacts_csv(f"{a.out}/contacts.csv", ids)
        AUDIT.artifact(f"{a.out}/contacts.csv", kind="contacts (contact store, one row per record)", records=nc)
        log.info("contacts: %s record(s) -> %s/contacts.csv", f"{nc:,}", a.out)
    if only == "json":
        log.info("%s -> %s/ (chats.json + identities.json)",
                 "metadata only (no text)" if key is None else "decrypted %d bodies (%d failed)" % (ok, fail), a.out)
        AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=sum(len(v) for v in chats.values()))
        # the same receipt the other formats leave: this branch returned before writing one, so a
        # json-only export was the one kind a later --history run could not describe
        _write_export_manifest(a.out, "cache+phone" if hist_added else "cache",
                               {"messages": sum(len(v) for v in chats.values()), "chats": len(chats),
                                "decrypted_from_cache": ok, "recovered_from_phone": hist_added},
                               ("chats.json", "identities.json"))
        return 0
    WD.write_transcripts(f"{a.out}/transcripts.txt", chats, ids)
    # name what was actually written: with --out txt:PATH the JSON side is skipped, and a log line
    # that lists files that are not there is a log line that gets believed
    wrote = "transcripts.txt" if only == "txt" else "chats.json + identities.json + transcripts.txt"
    if key is None:
        log.info("metadata only: %d messages written without text -> %s/ (%s)",
                 sum(len(v) for v in chats.values()), a.out, wrote)
    else:
        log.info("decrypted %d bodies (%d failed) -> %s/ (%s)", ok, fail, a.out, wrote)
    if nobody or other or fail:
        log.info("also written without text, not dropped: %d message(s) with no stored body, %d with a "
                 "body of another scheme, %d that failed to decrypt (see body_status)", nobody, other, fail)
    # outcome of the bulk decrypt + hashes of what was produced (so the exports are tamper-evident)
    if key is not None: AUDIT.crypto("decrypt", algorithm="AES-CBC-128", scheme="1 (final)", key=key,
                 input_desc="all scheme-1 msgRowOpaqueData bodies", records_in=ok + fail,
                 records_ok=ok, records_failed=fail, detail={"chats": len(chats)})
    # only record artifacts that were actually produced: with --out txt:PATH there is no chats.json,
    # and a custody record asserting a file that does not exist is worse than no record
    if only != "txt":
        AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=sum(len(v) for v in chats.values()))
    AUDIT.artifact(f"{a.out}/transcripts.txt", kind="decrypted transcripts (text)", records=sum(len(v) for v in chats.values()))
    _write_export_manifest(a.out, "cache+phone" if hist_added else "cache",
                           {"messages": sum(len(v) for v in chats.values()), "chats": len(chats),
                            "decrypted_from_cache": ok, "recovered_from_phone": hist_added},
                           ("chats.json", "identities.json", "transcripts.txt"))
    return 0

def _wa_user_prefs(profile, origin):
    """Read WhatsApp Web's own `model-storage/user-prefs` key/value store off the profile.

    This is a different store from the one the credential export reads (`wawc/user`), and it holds
    the client's self-description: the build it runs, its edge routing, the feature list its phone
    advertised. Exception-safe by design -- every caller treats a missing value as "fall back to the
    old behaviour", so a profile shape we have not seen degrades instead of failing.
    """
    try:
        if profile and _is_chromium(profile):
            sys.path.insert(0, os.path.join(HERE, "scripts"))
            import chromium_reader as _cr
            recs = _cr.load_source(profile)["idb"].get("model-storage", {}).get("user-prefs", [])
        elif origin:
            import glob as _glob, sqlite3 as _sq
            sys.path.insert(0, os.path.join(HERE, "scripts"))
            from snappy_pure import uncompress as _unc
            from idbutil import store_id as _sidf
            import sclone as _sc
            mm = _glob.glob(f"{origin}/idb/*meogdaerlo*.sqlite")
            if not mm:
                return {}
            con = _sq.connect(f"file:{mm[0]}?mode=ro&immutable=1", uri=True)
            sid = _sidf(con, "user-prefs")
            if sid is None:
                return {}
            recs = []
            for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
                try:
                    recs.append(_sc.loads(_unc(row)))
                except Exception:
                    continue
        else:
            return {}
        return {str(r.get("key")): r.get("value") for r in (recs or [])
                if isinstance(r, dict) and r.get("key") is not None}
    except Exception as e:
        log.debug("could not read user-prefs: %s", e)
        return {}


def _wa_version(profile, origin):
    """The client version WhatsApp Web announces in its ClientPayload, taken from the profile.

    `WAVersionBase` in model-storage/user-prefs is the build the browser actually runs, and it is
    corroborated by the loader's own urls (`__spin_r=<build>`, `btmanifest/<build>/whatsapp/main`).

    This matters because it is not a cosmetic string. WhatsApp gates features on it: the on-demand
    history check is

        isWindows ? (PrimaryFeatures.extendedHistorySyncOnDemand
                     && getABPropConfigValue('history_sync_on_demand_companion')) : true

    and AB prop values are assigned by the server per client version and platform. Baileys instead
    asks a THIRD-PARTY endpoint (fetchLatestBaileysVersion) and falls back to a hardcoded constant,
    so we were announcing 2.3000.1043857760 while this profile's browser announced 2.3000.1049127777
    -- over five million builds stale, on the one field a version-gated feature keys off.

    Returns [major, minor, build] or None.
    """
    raw = _wa_user_prefs(profile, origin).get("WAVersionBase")
    if raw is None:
        return None
    try:
        parts = str(raw).strip().strip('"').split(".")
        v = [int(x) for x in parts[:3]]
        return v if len(v) == 3 else None
    except (TypeError, ValueError):
        return None


def _edge_routing(profile, origin):
    """The `ED=` query parameter WhatsApp Web puts on its own WebSocket url.

    Observed in a NetLog capture of a real session:

        wss://web.whatsapp.com/ws/chat?ED=CBIIDQgC
        wss://web.whatsapp.com:5222/ws/chat?ED=CBIIDQgC      (both raced in parallel)

    and `CBIIDQgC` is exactly `WARoutingInfo.edgeRouting` as stored in the profile's
    model-storage/user-prefs ({"domain": "fb", "edgeRouting": "CBIIDQgC"}). It is WhatsApp's edge
    routing hint: the client persists it and replays it so reconnects land on the same edge. Baileys
    defaults to a bare wss://web.whatsapp.com/ws/chat with no ED at all.

    DO NOT REPLAY THIS VALUE ON OUR OWN SOCKET. Measured on a live account, alternating runs of
    diag_health.js against the same device and anchor:

        bare wss://web.whatsapp.com/ws/chat            -> SERVED ok   2 of 2
        the same url with ?ED=<the profile's value>    -> SERVED FAIL 0 of 2

    CONNECT and REGISTERED passed in all four runs, so the socket opens and the device is accepted
    either way; what changes is whether the phone's answer comes back. The value is evidently bound to
    the browser's own connection context rather than to the account, so replaying it routes us to an
    edge that will not serve us. This is a case where copying the reference client exactly is the wrong
    move, which is why the field is exported for the record and deliberately NOT used.

    Exported purely as an artefact: it is part of the profile's state and worth having in the case file,
    and it documents the measurement above. On any failure the field is simply omitted.
    """
    try:
        import json as _json
        v = _wa_user_prefs(profile, origin).get("WARoutingInfo")
        if isinstance(v, str):
            v = _json.loads(v)
        if isinstance(v, dict):
            er = v.get("edgeRouting")
            return er if isinstance(er, str) and er else None
    except Exception as e:
        log.debug("edge routing unavailable: %s", e)
    return None


def cmd_creds(a):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    _, BC = _imp()
    _require_source(a, "creds")                             # a profile (or --origin) is required; nothing is auto-detected
    if a.origin: ls, root, meta = BC.load_firefox(a.origin)
    elif a.profile and _is_chromium(a.profile): ls, root, meta = BC.load_chromium(a.profile)
    elif a.profile: ls, root, meta = BC.load_firefox(os.path.join(a.profile, "storage/default/https+++web.whatsapp.com"))
    else: log.error("pass a profile or --origin"); return 2
    _require_session(ls, a.profile or a.origin)          # storage present but not logged in -> clear error
    _audit_evidence(a.profile or a.origin)
    salt = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    K = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"\x00").derive(root)
    AUDIT.crypto("recover", key=root, key_source="IndexedDB wawc_db_enc/keys (root key)",
                 input_desc=(a.profile or a.origin), detail={"root_len": len(root)})
    # the PRELIMINARY key: derivable from disk alone, and what unwraps the Noise device credential
    AUDIT.crypto("derive", algorithm="AES-CBC-128", kdf="HKDF-SHA256 len=16", scheme="0 (preliminary)",
                 key=K, key_source="HKDF(root, salt=WAWebEncKeySalt, info=0x00)",
                 salt=salt, salt_source="WAWebEncKeySalt (localStorage, on disk)", info="0x00",
                 input_desc="WANoiseInfo (privKey/pubKey/certificateChainBuffer)")
    ni = json.loads(ls["WANoiseInfo"]); ivs = [base64.b64decode(x) for x in json.loads(ls["WANoiseInfoIv"])]
    def dc(b64, iv):
        pt = Cipher(algorithms.AES(K), modes.CBC(iv)).decryptor().update(base64.b64decode(b64)); p = pt[-1]
        return pt[:-p] if 1 <= p <= 16 and pt[-p:] == bytes([p])*p else pt
    priv = pub = None
    for pi in range(len(ivs)):                       # WANoiseInfoIv may hold fewer than 4 IVs
        for qi in range(len(ivs)):
            a1, b1 = dc(ni["privKey"], ivs[pi]), dc(ni["pubKey"], ivs[qi])
            if len(a1) == 32 == len(b1):
                try:
                    if X25519PrivateKey.from_private_bytes(a1).public_key().public_bytes_raw() == b1: priv, pub = a1, b1
                except Exception as e: log.debug("x25519 check: %s", e)
    if not priv:
        AUDIT.crypto("verify", algorithm="X25519", validated="FAILED",
                     input_desc="WANoiseInfo.privKey/pubKey unwrapped with the preliminary key")
        log.error("could not recover/verify the Noise keypair"); return 3
    # the device credential itself: recovered from disk and proven by X25519 pub == derive(priv)
    AUDIT.crypto("recover", algorithm="AES-CBC-128 unwrap + X25519", key=priv,
                 key_source="WANoiseInfo.privKey (AES-CBC, preliminary key) — Noise device private key",
                 validated="OK (X25519 pub matches)", input_desc="WANoiseInfo",
                 detail={"noise_pub_fp": audit.fp(pub), "ivs_available": len(ivs)})
    cert = None                                       # device certificate chain (WANoiseInfo.certificateChainBuffer)
    if ni.get("certificateChainBuffer"):
        for iv in ivs:
            try:
                t = dc(ni["certificateChainBuffer"], iv)
                if t[:1] == b'{': cert = json.loads(t); break
            except Exception as e: log.debug("cert decode: %s", e)
    adv = None; regid = None
    for o in meta:
        if o.get("key") == "adv_signed_identity":
            v = o["value"]; adv = {k: base64.b64encode(BC.as_bytes(v.get(k))).decode()
                                   for k in ("details","accountSignatureKey","accountSignature","deviceSignature") if BC.as_bytes(v.get(k))}
        if o.get("key") == "signal_reg_id": regid = o.get("value")
    wid = json.loads(ls["last-wid-md"]); lid = json.loads(ls["WALid"])
    _ud = wid.split("@")[0].split(":"); user, dev = _ud[0], (_ud[1] if len(_ud) > 1 else "0")
    out = {"noise_priv": base64.b64encode(priv).decode(), "noise_pub": base64.b64encode(pub).decode(),
           "registrationId": int(regid) if regid is not None else None, "user": user, "device": int(dev),
           "me_id": f"{user}:{dev}@s.whatsapp.net", "lid": lid, "account": adv, "cert_chain": cert}
    _er = _edge_routing(a.profile, a.origin)        # the ED= the real client puts on its socket url
    if _er:
        out["edge_routing"] = _er
    _wv = _wa_version(a.profile, a.origin)         # announce the build THIS profile's browser runs
    if _wv:
        out["wa_version"] = _wv
        log.info("client version from the profile: %s (announced instead of a third-party lookup)",
                 ".".join(str(x) for x in _wv))
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(out, open(a.out, "w", encoding="utf-8"), indent=1)
    abs_out = os.path.abspath(a.out)
    log.info("Noise keypair VERIFIED (X25519). reg_id=%s device=:%s account=%s -> %s",
             int(regid) if regid is not None else "?", dev, "present" if adv else "MISSING", abs_out)
    # creds_in.json holds the recovered device private key: record it as an artifact (hashed), not its content
    AUDIT.artifact(abs_out, kind="reconnect credentials (Noise keypair + account identity)",
                   detail={"device": dev, "registrationId": (int(regid) if regid is not None else None),
                           "account_present": bool(adv), "cert_chain": bool(cert)})
    if getattr(sys, "frozen", False) and not getattr(a, "_internal", False):
        # standalone `creds` on the .exe: the reconnect is the pure-Python `wawf reconnect`, or the
        # repo's Node client for history sync. (Suppressed when `reconnect` calls creds internally.)
        log.info("next: run `wawf reconnect` (captures companion_enc_static), or use creds_in.json with "
                 "the repo's tools/reconnect Node client for history sync")
    return 0

def _sub(script, extra, secret_env=None):
    """Run a helper script that owns its CLI (wa_forensic / export_sqlite).
    Dev mode: `python scripts/foo.py ...`. Frozen (.exe): re-exec self through the
    `_runpy` dispatch, since a bundled binary can't execute a loose .py file."""
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "_runpy", script] + extra
    else:
        cmd = [sys.executable, os.path.join(HERE, "scripts", script)] + extra
    log.info("running %s", " ".join(cmd))
    AUDIT.event("helper subprocess start", category="subprocess", detail={"script": script, "argv": cmd})
    # Force UTF-8 stdio on the child. Its stdout is a PIPE here, so Python picks the LOCALE
    # encoding (cp1252 on Windows) and any box-drawing character in a summary raises
    # UnicodeEncodeError. That killed export_sqlite.py's entire summary block -- including the
    # one line that told Chromium users why no media was written -- AFTER the database had
    # already been written, so the failure looked like a silent omission.
    _env = dict(AUDIT.child_env() or os.environ)
    _env.setdefault("PYTHONIOENCODING", "utf-8")
    _env.setdefault("PYTHONUTF8", "1")
    # Key material goes through the ENVIRONMENT, never argv. `--key` is justified to users on the
    # grounds that "no secret reaches your shell history, process list or command auditing", and
    # passing the base64 key as a child argument broke exactly that: on Windows a child's command
    # line is readable from Task Manager and Win32_Process, so every --memory and every
    # --out sqlite: run published the at-rest key to any process on the machine.
    if secret_env:
        _env.update({k: v for k, v in secret_env.items() if v})
    rc = subprocess.run(cmd, env=_env).returncode        # child appends to the same case DB
    AUDIT.event("helper subprocess exit rc=%s" % rc, level=("INFO" if rc == 0 else "ERROR"),
                category="subprocess", detail={"script": script, "rc": rc})
    return rc

def cmd_memory(a):
    """NOT REACHABLE from the CLI -- its arguments are withdrawn (see the note in main()). Kept whole,
    with wa_forensic.py, so the mode can be restored once it can validate candidates against a
    Chromium store as well as a Firefox one."""
    # The scan finds candidate keys in RAM and then VALIDATES each against ciphertext from the
    # profile -- and that reader is the Firefox one (`idb/*.sqlite`). Given a Chromium profile there
    # is nothing to validate against, and the child reported "Could not locate a Firefox WhatsApp
    # Web profile; pass --origin or --profile", which reads like the path was wrong when the real
    # answer is that this mode does not cover that engine. Said here, before spawning anything.
    if getattr(a, "profile", None) and not getattr(a, "origin", None) \
            and _is_chromium(a.profile):
        log.error("the memory scan validates candidate keys against a FIREFOX WhatsApp Web store, "
                  "and that is a Chromium profile. Either point --origin at a Firefox "
                  "storage/default/https+++web.whatsapp.com folder, or just run `wawf <PROFILE>`, "
                  "which captures the key over the network instead.")
        return 2
    extra = []
    # getattr, because the arguments these read are no longer defined -- the function is kept whole
    # for a later restoration, and must not rot into an AttributeError in the meantime
    if getattr(a, "live", False): extra.append("--live")
    if getattr(a, "memimage", None): extra += ["--memimage", a.memimage]
    if getattr(a, "deep", False): extra.append("--deep")
    # Renaming --enc-static to --key removed this attribute from the top-level namespace, and this
    # line then crashed every --memory/--memimage run with AttributeError. Resolve from the key FILE.
    _k = getattr(a, "enc_static", None) or (_read_key_file(a.key) if getattr(a, "key", None)
                                            and os.path.isfile(a.key) else None)
    if a.origin: extra += ["--origin", a.origin]
    # ...and the profile, which was never forwarded: the child then looked for a profile of its own
    # and told the user to pass the very thing they had passed.
    elif getattr(a, "profile", None): extra += ["--profile", a.profile]
    if a.yes: extra.append("--yes")
    return _sub("wa_forensic.py", extra, secret_env={"WAWF_ENC_STATIC": _k})

def cmd_reconnect(a):
    """Recover Noise creds (unless --creds given), then log back in as the linked companion device
    with the pure-Python Noise handshake and capture companion_enc_static. Networked; own account only."""
    creds_path = a.creds
    if not creds_path:
        creds_path = "creds_in.json"
        _require_source(a, "reconnect")                         # a profile (or --origin) is required; nothing is auto-detected
        rc = cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=creds_path, _internal=True))
        if rc: return rc
    elif not os.path.exists(creds_path):
        log.error("creds file not found: %s", creds_path); return 4
    log.warning("reconnect is NETWORKED — it logs in as your linked device and registers activity. "
                "Own account / authorized investigation only.")
    extra = ["--creds", creds_path, "--out", a.out]
    if a.verbose: extra.append("-v")
    rc = _sub("wa_reconnect.py", extra)
    if rc == 0 and os.path.exists(a.out):
        # The key itself is deliberately NOT logged. It used to be, to spell out the next command
        # back when reconnect and decrypt were separate steps -- but logs get mirrored to disk and
        # travel with cases, and this is the one secret the browser never stored anywhere. The path
        # is the part worth recording.
        log.info("at-rest key captured -> %s", os.path.abspath(a.out))
    return rc

def _senderless_chats(master):
    """The chats holding recovered messages with no sender -- the only ones a refetch has to ask.

    A sender-less message is one an older extractor banked before it captured `key.participant`. In a
    1:1 chat the sender is the chat itself and in my own messages it is me, so only group messages
    can be missing one, which is why this is a small fraction of the chats recovered.
    """
    out = set()
    for m in master.values():
        chat = str(m.get("chat") or "")
        if not chat or not chat.endswith("@g.us"): continue
        if m.get("fromMe"): continue
        if m.get("participant") or m.get("pushName"): continue
        out.add(chat)
    return out

def _target_anchors(anchors_path, chats):
    """Keep only the anchors for `chats`, so a refetch spends its request budget on what is broken.

    Re-asking every chat that has ever been recovered is the same sweep as the original -- hours of
    requests inside a window WhatsApp rate-limits -- when the messages missing a sender are in a
    handful of group chats. Returns (kept, dropped); restores nothing, because the next ordinary run
    rebuilds anchors from the profile anyway.
    """
    a = json.load(open(anchors_path, encoding="utf-8"))
    anchors = list(a.get("anchors") or [])
    keep = [x for x in anchors
            if str(x.get("chat")) in chats or str(x.get("chat_id")) in chats]
    if not keep:
        return 0, len(anchors)
    a["anchors"] = keep
    tmp = anchors_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(a, fh)
    os.replace(tmp, anchors_path)
    return len(keep), len(anchors) - len(keep)

def _load_chat_state(path):
    """Per-chat outcomes that must survive a run: {"ended": [jid, ...], "silent": {jid: n}}.

    anchors.json cannot hold them. It is rebuilt from the browser profile at the start of every run,
    so anything recorded only there is gone before the client starts -- which is exactly what
    happened to the first version of this fix: 103 chats were marked as ended, the next run rebuilt
    the file with none marked, and the client probed the same four finished chats again.
    """
    try:
        d = json.load(open(path, encoding="utf-8"))
        return {"ended": set(map(str, d.get("ended") or ())),
                "silent": {str(k): int(v) for k, v in (d.get("silent") or {}).items()}}
    except Exception:
        return {"ended": set(), "silent": {}}


def _save_chat_state(path, st):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"ended": sorted(st["ended"]), "silent": st["silent"]}, f, indent=1)
    os.replace(tmp, path)


def _note_pass(st, passd):
    """Fold one pass's per-chat outcomes into the state. An answer of any kind clears the silent
    count: silence is only a reason to demote a chat while it is unbroken."""
    for c in passd.get("start_reached") or ():
        st["ended"].add(str(c))
    for c in passd.get("answered_chats") or ():
        st["silent"].pop(str(c), None)
    for c in passd.get("silent_chats") or ():
        st["silent"][str(c)] = st["silent"].get(str(c), 0) + 1


def _deepen_anchors(anchors_path, master, only=None, start_reached=(), silent=None):
    """Re-anchor each chat on the OLDEST message recovered so far and add all recovered ids to the
    on-disk set, so the next history pass continues further back instead of re-pulling the same window.

    Anchors are UPDATED IN PLACE rather than rebuilt. An anchor carries more than a timestamp: `chat`
    is the jid WhatsApp Web actually addresses (the historyChatId in its wire `@s.whatsapp.net` form,
    which is NOT the chat id), `chat_id` is the local chat id, and `more_on_primary` records whether
    the primary still holds older messages -- initially from the browser's own
    primaryHasMoreMessagesReadyToLoad(), and thereafter from the phone answering "start reached". Rebuilding an
    anchor from a recovered message threw all three away: it replaced the wire-form `chat` with
    whatever form the phone happened to return, so chats went back to being asked for by a jid the
    reference client never sends; it dropped `more_on_primary`, so chats build_anchors had excluded as
    unanswerable came back from pass 2 onward; and because the dict was keyed on that form, a chat
    whose returned jid differed from its anchor's got a SECOND anchor appended instead of being
    deepened -- re-requesting the window it had just finished.
    """
    a = json.load(open(anchors_path, encoding="utf-8"))
    ondisk = set(a["ondisk_ids"]); anchors = list(a["anchors"])
    # `only` confines this to a set of chats, for a refetch that deliberately asks a subset. Without
    # it the adoption below defeated that subset entirely: the anchors were filtered down to the 20
    # chats missing a sender, and then the first call here re-created one for every chat in the
    # ledger -- 185 of them -- because every one of those chats has recovered messages and no anchor.
    if only is not None:
        anchors = [x for x in anchors
                   if str(x.get("chat")) in only or str(x.get("chat_id")) in only]
    # Index every jid form an anchor is known by, so a recovered message maps back to ITS anchor
    # whichever form the phone used to label it.
    idx = {}
    for x in anchors:
        for k in (x.get("chat"), x.get("chat_id")):
            if k: idx.setdefault(str(k), x)
    deepest = {}                                           # id(anchor) -> (anchor, ts, msg_id, fromMe)
    for m in master.values():
        if m.get("id"): ondisk.add(m["id"])
        c = m.get("chat"); ts = m.get("ts", 0)
        if not c or not m.get("id") or ts <= 0: continue   # ts<=0 (stubs) can't anchor fetchMessageHistory
        if only is not None and str(c) not in only: continue   # outside a targeted refetch's scope
        x = idx.get(str(c))
        if x is None:                                      # a chat with no anchor: adopt it as-is
            x = {"chat": c, "chat_id": c, "more_on_primary": True}
            anchors.append(x); idx[str(c)] = x
        cur = deepest.get(id(x))
        if cur is None or ts < cur[1]:
            deepest[id(x)] = (x, ts, m["id"], bool(m.get("fromMe")))
    for x, ts, mid, fromme in deepest.values():            # mutate: every other field is preserved
        x["oldest_id"], x["oldest_ts"], x["oldest_fromMe"] = mid, ts, fromme
    # The phone's "start reached" is the one unambiguous end-of-history signal there is: it located
    # the anchor and had nothing before it. Record it the same way build_anchors records
    # primaryHasMoreMessagesReadyToLoad(), so the client stops asking.
    sr = {str(c) for c in (start_reached or ())}
    ended = 0
    if sr:
        for x in anchors:
            if x.get("more_on_primary") is False: continue
            if str(x.get("chat")) in sr or str(x.get("chat_id")) in sr:
                x["more_on_primary"] = False; ended += 1
    # Order: chats that can still answer first, drained chats last. The old order was "chats we just
    # went deeper on first, then the rest", which front-loaded the chats closest to their floor --
    # and because nothing recorded exhaustion, 103 chats the phone had already ended stayed at the
    # head of the queue. The client only probes its first few chats before giving up, so it spent
    # every later run on drained chats and reported the phone as unresponsive after asking 4 of 253.
    live = [x for x in anchors if x.get("more_on_primary") is not False]
    done = [x for x in anchors if x.get("more_on_primary") is False]
    live = [x for x in live if id(x) in deepest] + [x for x in live if id(x) not in deepest]
    # Among chats that can still answer, the ones that have been silent run after run go behind the
    # rest (stable, so the order above is kept within equal counts). One chat on this ledger was
    # silent in six runs out of six and led the queue every time.
    sil = silent or {}
    live.sort(key=lambda x: max(sil.get(str(x.get("chat")), 0), sil.get(str(x.get("chat_id")), 0)))
    newanchors = live + done
    tmp = anchors_path + ".tmp"                            # atomic write: a failed/interrupted write must not
    with open(tmp, "w", encoding="utf-8") as f: json.dump({"anchors": newanchors, "ondisk_ids": sorted(ondisk)}, f)  # corrupt
    os.replace(tmp, anchors_path)                          # the anchors.json the node client reads next pass

def _resume_master(accum, anchors_path, master, deepen=True, chat_state=None):
    """Reload messages recovered on prior `wawf history` runs (from the accumulated ledger) into `master`
    and push the freshly-built anchors past them, so a new run continues older than prior runs instead of
    re-requesting the same window. Returns how many prior messages were reloaded (0 if none / on error)."""
    cs = chat_state or {"ended": set(), "silent": {}}
    if not os.path.exists(accum):
        # No ledger yet, but saved per-chat outcomes still apply to the freshly built anchors.
        if cs["ended"] or cs["silent"]:
            try: _deepen_anchors(anchors_path, {}, start_reached=cs["ended"], silent=cs["silent"])
            except Exception as e: log.warning("could not apply saved chat state (%s)", e)
        return 0
    try:
        WD, _ = _imp()
        WD.bank_history(master, json.load(open(accum, encoding="utf-8")).get("messages"))
        # Deepening is what makes a second run continue OLDER than the first instead of re-asking
        # the same window. `--history-refetch` is the case where re-asking is the entire point: the
        # messages are banked but missing fields an older extractor never captured (the group
        # sender), and the only way to fill them is to have the phone serve them again.
        if master and deepen:
            _deepen_anchors(anchors_path, master, start_reached=cs["ended"], silent=cs["silent"])
        elif cs["ended"] or cs["silent"]:                    # refetch: no deepening, state still applies
            _deepen_anchors(anchors_path, {}, start_reached=cs["ended"], silent=cs["silent"])
        return len(master)
    except Exception as e:
        log.warning("could not reload prior history (%s) — starting fresh.", e)
        return 0

def _find_reconnect_dir():
    """Locate the Node client dir (tools/reconnect). The bundled Python scripts live inside the .exe, but the
    Node/Baileys stack can't be frozen — so when running as a frozen exe, look next to the executable and in
    the CWD (NOT in HERE, which is the temp extraction dir). Returns the dir, or None if not found."""
    cands = [os.path.join(HERE, "tools", "reconnect")]   # from source: the repo's own copy
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        # A standalone build carries its own verified client (js + node_modules) under HERE, so prefer that
        # over whatever happens to sit on disk — pairing the bundled Node with a stray/partial node_modules
        # produces confusing failures. For the lean build HERE has no client, so the on-disk lookups apply.
        cands = cands + [os.path.join(exe_dir, "tools", "reconnect"),                  # .exe in the repo root
                         os.path.join(os.path.dirname(exe_dir), "tools", "reconnect"), # .exe in dist/, repo above
                         os.path.join(os.getcwd(), "tools", "reconnect")]              # run from in the repo
    for c in cands:
        if os.path.isfile(os.path.join(c, "history_extract.js")):
            return c
    return None

def _prompt_yes(question, assume_yes=False):
    if assume_yes:
        log.info("%s  -> yes (--yes)", question); return True
    try:
        return input(question + " [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:                                     # non-interactive stdin -> treat as no
        return False

def _find_node():
    """Any usable Node, from the places it actually lives. The path, or None.

    Offering to INSTALL Node is a last resort -- it modifies the machine -- so this looks everywhere
    a copy plausibly is before concluding there is none. PATH alone is not enough: a portable Node
    unzipped beside the tool is the normal arrangement on a locked-down examination machine, and a
    version manager (nvm, nvs, scoop, chocolatey, winget) puts it somewhere PATH may not mention in
    this process. WAWF_NODE points straight at a binary when all else fails.
    """
    import shutil, glob
    exe = "node.exe" if sys.platform == "win32" else "node"
    cands = []
    env = os.environ.get("WAWF_NODE")
    if env: cands += [env, os.path.join(env, exe), os.path.join(env, "bin", exe)]
    # bundled inside the standalone build, or unzipped next to the tool / the reconnect client
    roots = [HERE, os.path.dirname(os.path.abspath(sys.argv[0] or ".")), os.getcwd()]
    rec = _find_reconnect_dir() if "_find_reconnect_dir" in globals() else None
    if rec: roots.append(rec)
    for r in roots:
        cands += [os.path.join(r, "node", exe), os.path.join(r, "node", "bin", exe),
                  os.path.join(r, exe)]
        cands += sorted(glob.glob(os.path.join(r, "node-v*", exe)), reverse=True)
    for c in cands:
        if c and os.path.isfile(c): return c
    n = shutil.which("node")
    if n: return n
    more = [r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs\node.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links\node.exe"),
            os.path.expandvars(r"%USERPROFILE%\scoop\apps\nodejs\current\node.exe"),
            os.path.expandvars(r"%ChocolateyInstall%\bin\node.exe"),
            r"C:\ProgramData\chocolatey\bin\node.exe"]
    more += sorted(glob.glob(os.path.expandvars(r"%APPDATA%\nvm\v*\node.exe")), reverse=True)
    more += sorted(glob.glob(os.path.expandvars(r"%LOCALAPPDATA%\nvs\node\*\*\node.exe")), reverse=True)
    for c in more:
        if os.path.isfile(c): return c
    return None

def _ensure_node(assume_yes=False, install_ok=False):
    """Return a path to node, offering to install Node.js if it's missing. None if unavailable."""
    _ensure_node._explicit = bool(install_ok)
    node = _find_node()
    if node: return node
    if sys.platform != "win32":
        log.error("Node.js is required for history sync. Install it from https://nodejs.org and re-run."); return None
    # Deliberately NOT covered by --yes. Everything else --yes waves through happens inside this
    # tool's own folder; this one installs software on the examiner's machine, with an elevation
    # prompt, as a side effect of asking for chat history. That needs to be asked for by name.
    if not _prompt_yes("history sync needs Node.js, and none was found. Install it now via winget?",
                       getattr(_ensure_node, "_explicit", False)):
        log.error("Node.js is required for --history. Three ways, cheapest first:\n"
                  "  * unzip a portable Node beside this tool (a node-v*/ folder, or node/node.exe) "
                  "-- nothing is installed and nothing needs elevation\n"
                  "  * point WAWF_NODE at an existing node binary\n"
                  "  * install it: https://nodejs.org, or re-run with --install-node to do it via "
                  "winget (modifies this machine, asks for elevation)")
        return None
    log.info("installing Node.js LTS via winget (a UAC prompt may appear) ...")
    try:
        subprocess.run(["winget", "install", "--id", "OpenJS.NodeJS.LTS", "-e",
                        "--accept-source-agreements", "--accept-package-agreements"])
    except Exception as e:
        log.error("could not run winget (%s). Install Node.js from https://nodejs.org and re-run.", e); return None
    node = _find_node()
    if not node:
        log.error("Node.js still not found after install — open a NEW terminal (to pick up PATH) and re-run."); return None
    log.info("Node.js ready: %s", node)
    return node

def _ensure_baileys(rec, node, assume_yes=False):
    """Ensure tools/reconnect/node_modules (Baileys) exists, offering to `npm install` if missing."""
    if os.path.isdir(os.path.join(rec, "node_modules")): return True
    if not _prompt_yes("the Baileys packages aren't installed in tools/reconnect. Run `npm install` now?", assume_yes):
        log.error("Baileys is required — run `npm install` in %s once, then re-run.", rec); return False
    npm_cli = os.path.join(os.path.dirname(node), "node_modules", "npm", "bin", "npm-cli.js")
    cmd = [node, npm_cli, "install"] if os.path.isfile(npm_cli) else None
    if cmd is None:
        import shutil
        cmd = [shutil.which("npm") or "npm", "install"]
    log.info("running `npm install` in %s (one-time, ~1 min) ...", rec)
    try:
        rc = subprocess.run(cmd, cwd=rec).returncode
    except Exception as e:
        log.error("npm install failed (%s). Run it manually in %s.", e, rec); return False
    if rc != 0 or not os.path.isdir(os.path.join(rec, "node_modules")):
        log.error("npm install did not complete — run it manually in %s.", rec); return False
    return True

_NODE_PAGE_RE = None    # compiled lazily: "  <chat> page<N>: <result>" from history_extract.js

def _audit_node_line(line, pass_no):
    """Record one line of Node-client output. The client prints a line per history page request and per
    outcome, so parse those shapes EXPLICITLY: loose substring matching mislabels the chain of custody
    (e.g. 'Closing open session ...' is a Signal log, not a request, and '+50 (new 50)' is a response
    even though it contains no 'response')."""
    global _NODE_PAGE_RE
    if _NODE_PAGE_RE is None:
        import re
        _NODE_PAGE_RE = re.compile(r"^\s*(?P<chat>\S+)\s+page(?P<page>\d+):\s*(?P<rest>.+)$")
    m = _NODE_PAGE_RE.match(line)
    if m:
        rest = m.group("rest").strip()
        if rest.startswith("no response"):                   # request sent, nothing came back in time
            direction, status = "out", "no response (timeout)"
        elif rest.startswith("empty"):                       # reply arrived, nothing older to give
            direction, status = "in", "empty (start of chat reached)"
        else:                                                # reply arrived with messages
            direction, status = "in", "data returned"
        AUDIT.net(direction, endpoint="web.whatsapp.com", protocol="noise/websocket",
                  kind="fetchMessageHistory", status=status,
                  detail={"pass": pass_no, "chat": m.group("chat"), "page": int(m.group("page")),
                          "result": rest})
        return
    if line.startswith("[+] OPEN") or line.startswith("[x] closed"):
        AUDIT.net("in" if line.startswith("[x]") else "out", endpoint="web.whatsapp.com",
                  protocol="noise/websocket", kind="connection", status=line.strip(),
                  detail={"pass": pass_no})
        return
    AUDIT.event(line, category="node", detail={"pass": pass_no})   # everything else is narrative

def _run_node_audited(cmd, cwd, env, pass_no):
    """Run the Node extractor with its output teed into the audit DB. The client prints a line per chat page
    request and per response ('page0: no response', '[+] OPEN', '[DONE] recovered=...'), so capturing them
    puts every on-demand history request/response into the chain of custody. Console output is preserved."""
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)
    for line in proc.stdout:
        line = line.rstrip("\r\n")
        if not line: continue
        sys.stderr.write(line + "\n"); sys.stderr.flush()    # keep the live view the user expects
        _audit_node_line(line, pass_no)
    proc.wait()
    return proc.returncode

def _pick_work_dir():
    """A persistent, WRITABLE folder for history output, used when the Node client is bundled inside the
    .exe (whose extraction dir is wiped on exit). Prefers a folder beside the executable; falls back to
    per-user app data when the executable sits somewhere read-only (Program Files, a share, read-only media)."""
    cands = [os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "wawf-history")]
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~")
    cands.append(os.path.join(base, "wawf", "history"))
    for c in cands:
        try:
            os.makedirs(c, exist_ok=True)
            probe = os.path.join(c, ".write-test")       # creatable != writable; prove it
            with open(probe, "w"): pass
            os.remove(probe)
            return c
        except Exception as e:
            log.debug("work dir unusable (%s): %s", c, e)
    raise SystemExit("could not create a writable folder for history output (tried: %s)" % ", ".join(cands))

def _history_out_targets(a):
    """Where a `--history --out` run writes, never over an earlier run's export.

    A history run produces a DIFFERENT dataset from a plain one -- the local store plus whatever the
    phone gave back -- so it must not land on top of an export that is already there. Rather than
    refusing and making the user think of a new path, the new dataset is written beside the old one
    under a `-history` name, and the log says exactly what was already there and where this one went.
    """
    outs = [_parse_out(spec) for spec in (a.out or [])]
    resolved = []
    for fmt, path in outs:
        held = _holds_export(path)
        if not held:
            resolved.append((fmt, path)); continue
        base, n = path.rstrip("\\/") + "-history", 1
        cand = base
        while _holds_export(cand):
            n += 1; cand = "%s-%d" % (base, n)
        comp = held.get("composition") or "unknown"
        n = (held.get("counts") or {}).get("messages")
        what = ("an export of unrecorded composition" if comp == "unknown"
                else "a %s export" % comp)
        when = held.get("created_utc") or "?"
        detail = "%s, %s messages" % (when, f"{n:,}") if isinstance(n, int) else "no receipt"
        log.info("%s already holds %s (%s). This run produces the local store PLUS what the phone "
                 "returns, which is a different dataset, so it is written to %s and the existing one "
                 "is left untouched.", path, what, detail, cand)
        resolved.append((fmt, cand))
    return resolved

def _history_export(a, targets, history_file=None):
    """Write the export(s) a `--history --out` run owns. Called twice: once before the pulls, so a
    complete local dataset exists within minutes, and once after, with the recovered messages folded
    in. Both write the same paths -- the auto-naming that protects an EARLIER run's export happened
    once, before either call."""
    if not targets: return 0
    ns = argparse.Namespace(profile=a.profile, origin=a.origin, out=["%s:%s" % (f, p) if f else p
                                                                     for f, p in targets],
                            key=getattr(a, "key", None), verbose=getattr(a, "verbose", False),
                            raw_include_keys=getattr(a, "raw_include_keys", False),
                            history_file=history_file)
    return cmd_run(ns)

def cmd_queue(a):
    """--queue: record what WhatsApp's server is holding for the examined device, without taking it.

    While the browser session is closed, the server queues for that device everything the account
    receives (messages, group key handovers, receipts, call offers, notifications). This exports the
    device's credentials and the browser's OWN Signal state (identity, sessions, group sender keys)
    into a new folder, signs in as the device and journals every stanza the server delivers --
    exactly as received, and each payload decrypted -- acknowledging nothing, so the server keeps
    the queue for the browser. Each run starts from the browser's state again, in a folder of its own.

    Networked: recorded as activity on the account. Nothing a contact can see is sent (no receipts,
    no presence)."""
    _require_source(a, "queue")
    if a.profile and _is_chromium(a.profile):
        eng = ["--profile", a.profile]
    else:
        origin = a.origin or (os.path.join(a.profile, "storage/default/https+++web.whatsapp.com") if a.profile else None)
        if not origin: log.error("pass a profile or --origin"); return 2
        eng = ["--origin", origin]
    base = None
    for spec in (a.out or []):
        _, path = _parse_out(spec)
        base = path; break
    base = base or _pick_work_dir()
    work = os.path.join(base, "server-queue", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(work, exist_ok=True)
    log.info("server queue capture -> %s", work)
    log.info("[1/3] recovering the device credentials ...")
    if a.creds:
        import shutil
        shutil.copyfile(a.creds, os.path.join(work, "creds_in.json"))
    elif cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=os.path.join(work, "creds_in.json"), _internal=True)):
        return 3
    log.info("[2/3] exporting the browser's Signal state (sessions, group sender keys) ...")
    if _sub("export_signal_state.py", eng + ["--out", os.path.join(work, "signal_state.json")]): return 3
    log.info("[3/3] signing in as the device and recording the queue (nothing is acknowledged) ...")
    if getattr(sys, "frozen", False):
        qcmd = [sys.executable, "_runpy", "queue_capture.py"]
    else:
        qcmd = [sys.executable, os.path.join(HERE, "scripts", "queue_capture.py")]
    env = dict(AUDIT.child_env() or os.environ)
    env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYINSTALLER_RESET_ENVIRONMENT="1")
    # The state this tool's own history runs left for this device (if any): after talking to the phone,
    # its sessions with the phone are newer than the browser's, and the phone encrypts to them.
    extra = [p for p in (os.path.join(d, "signal_runtime.py.json") for d in
                         (os.path.join(HERE, "tools", "reconnect"), _pick_work_dir())) if os.path.isfile(p)]
    if extra and not env.get("WAWF_QUEUE_EXTRA_STATE"):
        env["WAWF_QUEUE_EXTRA_STATE"] = os.pathsep.join(extra)
        log.info("also trying the Signal state this tool's history runs left: %s", ", ".join(extra))
    AUDIT.event("server queue capture start", category="network",
                detail={"argv": qcmd, "cwd": work, "ack_policy": env.get("WAWF_QUEUE_ACK", "none")})
    rc = subprocess.run(qcmd, cwd=work, env=env).returncode
    summ = {}
    try: summ = json.load(open(os.path.join(work, "queue_summary.json"), encoding="utf-8"))
    except Exception: pass
    for name, kind in (("queue_journal.jsonl", "server queue journal (stanzas as received + decrypted payloads)"),
                       ("queue_messages.json", "server queue, readable (one row per message)"),
                       ("queue_summary.json", "server queue capture summary"),
                       ("queue_for_export.json", "server queue messages as merged into the export")):
        p = os.path.join(work, name)
        if os.path.isfile(p): AUDIT.artifact(p, kind=kind)
    AUDIT.event("server queue capture exit rc=%s" % rc, level="INFO" if rc == 0 else "ERROR", category="network",
                detail={k: summ.get(k) for k in ("stats", "end_of_queue_marker", "messages", "decrypted", "not_decrypted")})
    if summ.get("session_ended_by_server"):
        log.warning("server queue: %s", summ["session_ended_by_server"])
    if rc:
        log.error("queue capture failed (exit %s)%s", rc,
                  " -- close WhatsApp Web in every browser using this profile, then run again" if rc == 6 else
                  " -- the server refused this device's login (the reason is printed above)" if rc == 2 else "")
        return rc
    st = summ.get("stats") or {}
    log.info("server queue: %s stanzas recorded, %s acknowledged; %s messages (%s decrypted, %s not); "
             "end-of-queue marker %s", st.get("journalled"), st.get("acked"), summ.get("messages"),
             summ.get("decrypted"), summ.get("not_decrypted"),
             "received" if summ.get("end_of_queue_marker") is not None else "NOT received (queue may be partial)")
    log.info("readable: %s", os.path.join(work, "queue_messages.json"))
    a.queue_export_file = os.path.join(work, "queue_for_export.json")
    log.warning("%s holds the device's credentials and Signal state: key material -- keep it with the case, "
                "never share it.", work)
    return 0

def cmd_history(a):
    """On-demand history sync: pull messages OLDER than the browser cache from the account's phone, per
    chat, going back toward each chat's start -- ITERATIVELY: each pass re-anchors on the oldest message
    recovered so far and pulls deeper, accumulating (deduped) until it converges. Recovers creds, Signal
    state and anchors from the profile, then runs the history client: scripts/history_extract.py (pure
    Python, its own Signal implementation, no Node; works from the .exe), or the Baileys client in
    tools/reconnect when WAWF_HISTORY_ENGINE=node."""
    # The history client is pure Python by default (scripts/history_extract.py): no Node.js, and it runs
    # from the standalone .exe. WAWF_HISTORY_ENGINE=node keeps the Baileys client (tools/reconnect).
    engine = os.environ.get("WAWF_HISTORY_ENGINE", "python").strip().lower()
    rec = _find_reconnect_dir()
    node = None
    if engine == "node":
        if not rec:
            log.error("WAWF_HISTORY_ENGINE=node needs the Node client (tools/reconnect/history_extract.js), "
                      "which is not bundled in the .exe. Run wawf from the repo, or leave the engine at its "
                      "default (python).")
            return 2
        # --install-node, not --yes: see the note in _ensure_node
        node = _ensure_node(getattr(a, "yes", False), getattr(a, "install_node", False))
        if not node: return 2
        node_dir = os.path.dirname(node)                 # make node/npm resolvable for this run's subprocesses
        if node_dir and node_dir not in os.environ.get("PATH", "").split(os.pathsep):
            os.environ["PATH"] = node_dir + os.pathsep + os.environ.get("PATH", "")
        if not _ensure_baileys(rec, node, getattr(a, "yes", False)): return 2
    # Where OUTPUTS (creds/state/anchors/recovered history) go: beside a repo checkout's tools/reconnect,
    # so earlier runs' ledgers keep resuming; for the .exe, a persistent folder next to the executable.
    if rec and not (getattr(sys, "frozen", False) and
                    os.path.abspath(rec) == os.path.abspath(os.path.join(HERE, "tools", "reconnect"))):
        work = rec
    else:
        work = _pick_work_dir()
        log.info("history data dir: %s", work)
    # engine args shared by creds / signal-state / anchors
    _require_source(a, "history")                           # a profile (or --origin) is required; nothing is auto-detected
    if a.profile and _is_chromium(a.profile):
        eng = ["--profile", a.profile]
    else:
        origin = a.origin or (os.path.join(a.profile, "storage/default/https+++web.whatsapp.com") if a.profile else None)
        if not origin: log.error("pass a profile or --origin"); return 2
        eng = ["--origin", origin]
    log.info("[1/4] recovering reconnect creds ...")
    if cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=os.path.join(work, "creds_in.json"), _internal=True)):
        return 3
    log.info("[2/4] recovering Signal state (identity, prekeys, sessions, sender keys) ...")
    if _sub("export_signal_state.py", eng + ["--out", os.path.join(work, "signal_state.json")]): return 3
    # Verify what we just exported actually describes the device this profile is on. This should
    # always pass here -- we exported it a line ago -- so a failure means the export path is broken,
    # which is worth stopping for. The check matters far more for the diag_*.js tools, which read
    # whatever happens to be on disk: when WhatsApp Web re-pairs (what "reconnecting" does, and what
    # happens by itself when a device is revoked) the account gets a new registrationId and a new
    # Signal identity, and a stale snapshot then authenticates as a device that no longer exists.
    # That connects, asks every chat, receives nothing, and is indistinguishable from throttling.
    # check_identity exits 0 = current, 1 = stale, 2 = could not tell. Only 1 is a mismatch. Treating
    # every non-zero code as fatal aborted a healthy run with a wrong diagnosis whenever the check
    # itself could not complete -- for instance a transient lock on its second read of the profile.
    _ident = _sub("check_identity.py", eng + ["--dir", work, "--quiet"])
    if _ident == 1:
        log.error("the credentials just exported do not match the profile — refusing to run with them. "
                  "Run scripts/check_identity.py --profile <profile> --dir %s for the details.", work)
        return 3
    if _ident:
        log.warning("could not verify the exported credentials against the profile (check exited %s); "
                    "continuing, since this is not evidence of a mismatch.", _ident)
    log.info("[3/4] building anchors from on-disk messages ...")
    if _sub("build_anchors.py", eng + ["--out", os.path.join(work, "anchors.json")]): return 3
    log.warning("[4/4] NETWORKED iterative history sync — logs in as your linked device and asks your phone, "
                "chat by chat, for messages older than the cache, re-anchoring deeper each pass until the "
                "phone's retained history is drained. Own account / authorized use only; this can take many "
                "minutes and repeated passes.")
    log.warning("HOW THIS WORKS: the messages come from your PHONE. The servers only relay the "
                "request, so each chat costs one round trip to the phone and back. Measured on a "
                "healthy device: the server acknowledges the request in about 0.3s and a chunk of up "
                "to 50 messages arrives about 3s later.")
    log.warning("WHY IT IS SLOW: WhatsApp rate-limits this, which is confirmed server-side "
                "(wa_web_history_sync_dynamic_throttling). The limit counts FAILURES rather than "
                "requests -- its counter resets on every success -- so roughly ten UNANSWERED "
                "requests inside two hours puts the account quiet for two hours. This tool therefore "
                "paces itself, doubles its delay each time an answer does not arrive, eases off again "
                "once they do, and when it does hit the limit it waits the cooldown out and resumes "
                "instead of giving up. None of that can be rushed: it is the server's rate, not ours.")
    log.warning("SO EXPECT IT TO TAKE A WHILE. A first pass over a few hundred chats is typically "
                "tens of minutes. Draining a long history runs for hours and will sit idle for two "
                "hours at a time when the limit trips. Progress is checkpointed after every page, so "
                "stopping it costs nothing and re-running simply continues deeper. An empty pass is a "
                "known outcome, not a failure.")
    # Which registration the run uses decides whether on-demand history keeps working at all, and
    # it was previously visible only as one informational line from the Node client. Riding the
    # profile's registration works while its Signal snapshot is still near the primary's ratchet and
    # decays after that, with a symptom -- every request silent -- that reads as a phone problem.
    if not os.path.isdir(os.path.join(rec, "wawf_device")):
        log.warning("MODE: this run rides the BROWSER PROFILE's registration, because this tool has "
                    "not been paired as its own device. On-demand history is a REQUEST TO THE LIVE "
                    "PRIMARY PHONE -- it is not recoverable from the image, and the profile's Signal "
                    "material is a snapshot of a ratchet the phone keeps advancing. It serves history "
                    "while that snapshot is still current and then stops, and nothing on disk can "
                    "repair it. Everything else this tool extracts (cached messages, contacts, media, "
                    "identities, app-state) comes from the files and is unaffected.")
        log.warning("TO MAKE HISTORY KEEP WORKING: pair this tool as its own linked device, once -- "
                    "`node tools/reconnect/pair.js`. It then holds its own Noise key, Signal identity "
                    "and prekeys, so the session is ours to keep current and nothing this tool does "
                    "can degrade the subject's own linked device. It needs lawful access to the "
                    "UNLOCKED PHONE once: companion linking requires approval on the primary, and no "
                    "tool can re-link from disk artifacts alone -- if one could, anyone holding a copy "
                    "of an old profile could attach to the account permanently. FORENSIC NOTICE: it "
                    "creates a NEW device, visible in the phone's Linked Devices list and notified to "
                    "the account holder. That is an overt act and belongs in the case notes.")
    log.warning("FOR THE BEST CHANCE: keep WhatsApp open on your phone with a stable network, and "
                "CLOSE every web.whatsapp.com tab -- a live web session competes for the same linked "
                "device. If a run comes back empty, do not immediately retry: that burns the failure "
                "budget and extends the quiet window. Run tools/reconnect/diag_onehistory.js instead, "
                "which sends ONE request and reports whether the server acknowledged it, so a throttle "
                "is distinguishable from a refusal.")
    log.warning("SIDE EFFECT ON THE DEVICE: your phone's replies are end-to-end encrypted to a Signal "
                "session, and the copy in the browser profile is a snapshot of a ratchet that keeps moving, "
                "so this renegotiates that session and then keeps its own copy (signal_runtime.py.json, or "
                "signal_runtime.json for the Node client, next to the output — treat it as key material). The browser's stored session for this linked "
                "device therefore goes stale; WhatsApp Web re-establishes it by itself the next time you "
                "open it. Nothing on the phone or in the profile is modified.")
    log.warning("KEEP signal_runtime.py.json / signal_runtime.json WITH THE CASE — it is NOT a cache. It holds the "
                "only copy of the prekeys this tool published to WhatsApp's servers, which peers then "
                "encrypt to, and of ratchet state the phone has already moved past. Delete it and "
                "anything encrypted to those keys is permanently unreadable, even from the same profile. "
                "Every run also advances that shared state, so run deliberately, not repeatedly.")
    # every chat, page until exhausted -- unless TOP / MAXPAGES / COUNT are set to bound the sweep
    env = dict(os.environ, TOP=os.environ.get("TOP", "100000"), COUNT=os.environ.get("COUNT", "50"),
               MAXPAGES=os.environ.get("MAXPAGES", "100000"))
    anchors_path = os.path.join(work, "anchors.json")
    pass_out = os.path.join(work, "history_recovered.json")   # human-facing final output (full accumulated set)
    accum = os.path.join(work, "history_all.json")            # resume ledger, accumulated across ALL runs
    master = {}                                              # msg id -> msg (dedup across passes AND runs)

    def _checkpoint(path):
        by = collections.Counter(m.get("chat") for m in master.values())
        tmp = path + ".tmp"                                  # atomic write: never leave a half-written file
        json.dump({"recovered_total": len(master), "new_not_on_disk": len(master),
                   "by_chat": dict(by), "messages": list(master.values())}, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, path)
        return by

    # RESUME across separate `wawf history` runs: step [3/4] just rebuilt anchors.json fresh from what's on
    # disk (i.e. back at the browser-cache boundary), so reload everything recovered on prior runs and push
    # the anchors + on-disk id set past it — otherwise run 2 would re-request run 1's window and overwrite it.
    refetch = bool(getattr(a, "history_refetch", False))
    refetch_only = None                                  # the chats a refetch confines itself to
    # Per-chat outcomes from earlier runs, re-applied to the freshly rebuilt anchors.
    state_path = os.path.join(work, "history_chat_state.json")
    chat_state = _load_chat_state(state_path)
    if chat_state["ended"] or chat_state["silent"]:
        log.info("from earlier runs: %d chat(s) the phone has ended (skipped), %d chat(s) silent on "
                 "their last attempt (asked last).", len(chat_state["ended"]), len(chat_state["silent"]))
    n = _resume_master(accum, anchors_path, master, deepen=not refetch, chat_state=chat_state)
    if n and not refetch:
        log.info("resuming: %s messages recovered on prior runs — continuing older than those.", f"{n:,}")
    elif n:
        gaps = _senderless_chats(master)
        missing = sum(1 for m in master.values()
                      if str(m.get("chat") or "").endswith("@g.us") and not m.get("fromMe")
                      and not (m.get("participant") or m.get("pushName")))
        if not gaps:
            log.info("--history-refetch: every recovered message already names its sender — nothing "
                     "to fill in. Run without the flag to fetch history deeper instead.")
            return 0
        kept, dropped = _target_anchors(anchors_path, gaps)
        refetch_only = gaps                              # keep every later deepen inside this set
        log.warning("--history-refetch: %s recovered message(s) in %d group chat(s) have no sender, "
                    "because the extractor that banked them did not capture it. Re-asking those %d "
                    "chat(s) only (%d other chat(s) set aside), so the request budget goes where the "
                    "gap is. Nothing new is found by design; the phone must answer for this to fill "
                    "anything in.", f"{missing:,}", len(gaps), kept, dropped)

    # --out now applies to a history run. The dataset it produces is the local store PLUS whatever
    # the phone returns, so it is written to its own folder (see _history_out_targets) and an earlier
    # run's export is never touched. The local half is written FIRST: the pulls take hours, and there
    # is no reason to have nothing on disk until they finish.
    targets = _history_out_targets(a) if getattr(a, "out", None) else []
    if targets:
        log.info("──── decrypting the local store first, before pulling anything ────")
        rc = _history_export(a, targets)
        if rc:
            log.error("the local decrypt failed (%d), so there would be nothing to append the "
                      "recovered messages to. Fix that first; nothing has been requested from the "
                      "phone yet.", rc)
            return rc

    MIN_NEW, MAX_PASSES = 40, 25                             # stop when a pass adds < MIN_NEW; hard safety cap
    # Exit 7 from the Node client means its cooldown breaker stopped the pass: ten unanswered requests
    # inside WhatsApp's own 7200-second window. That is not a failure and must not be treated as one.
    # A sweep of a few hundred chats cannot fit inside one window, so the right response is to wait the
    # cooldown out and resume from the checkpoint -- which costs nothing, because every pass re-anchors
    # on the oldest message recovered so far. Set WAWF_COOLDOWN_SEC=0 to get the old behaviour of
    # stopping instead, and WAWF_MAX_COOLDOWNS to bound how long a run may sit waiting.
    COOLDOWN_RC = 7
    # Mirrors PROBE_CHATS in history_extract.js: the client asks this many chats and, if none of them
    # answers, stops rather than spend the whole queue. Reported in the messages below, because a run
    # that "got nothing" may simply never have asked more than this many chats.
    _PROBE_CHATS = int(os.environ.get("PROBE_CHATS", 4))
    COOLDOWN = int(os.environ.get("WAWF_COOLDOWN_SEC", 7200))
    MAX_COOLDOWNS = int(os.environ.get("WAWF_MAX_COOLDOWNS", 6))
    cooldowns_used = 0
    served_any = False                                   # did the phone serve anything, any pass?
    ended_chats = chat_state["ended"]                    # chats the phone answered "start reached" for
    try:
        for p in range(1, MAX_PASSES + 1):
            log.info("──── history pass %d ────", p)
            if os.path.exists(pass_out): os.remove(pass_out)   # else a node failure re-reads a stale pass as "new"
            if engine == "node":
                ncmd = [node, os.path.join(rec, "history_extract.js")]
            elif getattr(sys, "frozen", False):
                ncmd = [sys.executable, "_runpy", "history_extract.py"]
            else:
                ncmd = [sys.executable, os.path.join(HERE, "scripts", "history_extract.py")]
            env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            AUDIT.event("history pass %d: launching the %s history client" % (p, engine), category="stage",
                        detail={"argv": ncmd, "cwd": work})
            rc = (_run_node_audited(ncmd, work, env, p) if AUDIT.enabled
                  else subprocess.run(ncmd, cwd=work, env=env).returncode)
            # utf-8 EXPLICITLY: the Node client writes this file with JSON.stringify, which does not
            # escape non-ASCII, so any emoji or non-Latin script in a recovered message is raw UTF-8.
            # Python's default here is the locale encoding (cp1252 on Windows), which raises
            # UnicodeDecodeError -- and this read is wrapped in `except Exception`, so a successful
            # pass was reported as "produced no output" and then OVERWRITTEN with an empty file by the
            # final _checkpoint. Measured: a 10,842-message pass discarded in full.
            try: passd = json.load(open(pass_out, encoding="utf-8"))
            except Exception:
                log.error("pass %d produced no output (node exit=%s; connection failed / phone not serving) "
                          "— stopping.", p, rc); break
            WD, _ = _imp()
            # What the phone actually served this pass, as distinct from what was NEW in it: a pass
            # can be served hundreds of messages and have none of them be new (a refetch), or be
            # served nothing at all (throttled). Those mean opposite things to the user.
            served = len(passd.get("messages") or [])
            # Chats that ANSWERED, whether or not the answer held any messages. Counting only
            # messages reported a pass in which 30 chats answered "nothing older" as "no chat
            # answered", and pointed the user at the phone.
            answered = len(passd.get("answered_chats") or [])
            served_any = served_any or served > 0
            # Chats the phone itself ended this pass. Accumulated across passes because the anchors
            # are rewritten every pass and a chat ended in pass 1 must stay ended in pass 3.
            _note_pass(chat_state, passd)
            _save_chat_state(state_path, chat_state)
            new, enriched = WD.bank_history(master, passd.get("messages"))
            by = _checkpoint(accum)                          # checkpoint the accumulated set every pass
            log.info("pass %d: +%d new%s  ·  total recovered: %d across %d chats", p, new,
                     (", %d enriched" % enriched) if enriched else "", len(master), len(by))
            if rc == COOLDOWN_RC:
                _deepen_anchors(anchors_path, master, only=refetch_only,
                                start_reached=ended_chats, silent=chat_state["silent"])                 # bank before the wait
                if COOLDOWN and cooldowns_used < MAX_COOLDOWNS:
                    cooldowns_used += 1
                    log.warning("pass %d was stopped by the cooldown breaker (%d/%d). WhatsApp Web waits "
                                "%ds after this many unanswered requests, so we wait too, then resume "
                                "deeper. %s messages are already banked and nothing is lost if this is "
                                "interrupted.", p, cooldowns_used, MAX_COOLDOWNS, COOLDOWN, f"{len(master):,}")
                    time.sleep(COOLDOWN)
                    continue
                log.warning("pass %d stopped by the cooldown breaker and the wait budget is spent "
                            "(%d used). Re-run later to continue deeper; progress is saved.",
                            p, cooldowns_used)
                break
            # In a refetch the phone is being asked for messages we already have, so "new" is 0 by
            # design and the loop would stop after one pass. What counts as progress there is how
            # many banked records gained a field.
            progress = new + (enriched if refetch else 0)
            if progress < MIN_NEW:
                # "Converged" means we reached the start of the history the phone will give us. It is
                # NOT what happened when the phone answered nothing -- and that distinction decides
                # whether a user should re-run later or stop asking. The old test was `if master`,
                # which is the ACCUMULATED ledger: once any earlier run had recovered anything, a
                # pass that was served nothing at all still reported "converged", i.e. "your history
                # is exhausted". The client even stops after the first few silent chats, deliberately,
                # to stay under the failure limit -- so a run can try 4 chats out of 253, be told
                # nothing, and announce that the history had run out.
                if served == 0 and answered:
                    log.info("pass %d: %d chat(s) answered, none with messages older than what is "
                             "already recovered -- the phone says the rest has nothing older to give "
                             "at this depth, or no more yet. Stopping.", p, answered)
                elif served == 0:
                    # Say what was actually asked. This used to read "the phone answered NONE of the
                    # requests ... it is the throttling described above", which was wrong twice over:
                    # the client stops after its first few chats, so "none of the requests" was four
                    # chats out of 253; and those four were at the head of a queue that front-loaded
                    # chats the phone had already answered "start reached" for. Throttling was an
                    # inference from our own sampling, and it sent the user looking at their phone.
                    log.warning("pass %d: no chat answered among the %d the client asked before it "
                                "stopped (it probes the first PROBE_CHATS=%s and gives up, to stay "
                                "under WhatsApp's own unanswered-request limit). That is a statement "
                                "about those chats, NOT about the phone and NOT the end of your "
                                "history. %s messages recovered previously are intact. %s",
                                p, len(passd.get("silent_chats") or ()) or _PROBE_CHATS,
                                _PROBE_CHATS, f"{len(master):,}",
                                ("%d chat(s) the phone has ended are now recorded and will be "
                                 "skipped next run." % len(ended_chats)) if ended_chats else
                                "Re-run to continue; the queue order is updated each pass.")
                elif not master:
                    log.warning("pass %d came back empty — the phone answered none of the requests. "
                                "Stopping.", p)
                else:
                    log.info("converged — the phone served %d message(s) but %s < %d, so there is "
                             "little left to get at this depth. Stopping.", served,
                             "enriched" if refetch else "new", MIN_NEW)
                break
            _deepen_anchors(anchors_path, master, only=refetch_only,
                            start_reached=ended_chats, silent=chat_state["silent"])                     # go deeper next pass
    except KeyboardInterrupt:
        log.warning("interrupted — checkpointing %s recovered messages before exit.", f"{len(master):,}")
        _checkpoint(accum); _checkpoint(pass_out)
        if targets and master:
            log.info("writing the merged export with what was recovered before the interruption ...")
            try: _history_export(a, targets, history_file=pass_out)
            except Exception as e: log.error("could not write the merged export: %s", e)
        raise

    by = _checkpoint(pass_out); _checkpoint(accum)           # final full accumulated set -> both files
    AUDIT.artifact(pass_out, kind="recovered history (older than the browser cache)", records=len(master))
    AUDIT.artifact(accum, kind="history resume ledger (cumulative across runs)", records=len(master))
    if master and targets:
        log.info("──── appending %s recovered message(s) to the export ────", f"{len(master):,}")
        rc = _history_export(a, targets, history_file=pass_out)
        if rc:
            log.error("the recovered messages are safe in %s, but the merged export failed (%d). "
                      "Re-run with the same --out to try again; nothing has to be pulled twice.",
                      pass_out, rc)
            return rc
        if getattr(a, "fetch_media", False):
            for fmt, path in targets:
                if fmt != "sqlite": continue
                db = os.path.join(path, "msgstore.db")
                if not os.path.isfile(db):
                    log.warning("--fetch-media: no msgstore.db in %s to work from", path); continue
                log.info("--fetch-media: asking the CDN for media the browser never cached "
                         "(NETWORKED; a url whose signature has expired returns 403 and is skipped)")
                _sub("mediafetch.py", ["--db", db, "--cdn"] +
                     (["--profile", a.profile] if a.profile else []) +
                     (["--origin", a.origin] if a.origin else []))
        elif any(f == "sqlite" for f, _ in targets):
            log.info("media for the recovered messages is not downloaded: their mediaKeys ARE in "
                     "message_media, and --fetch-media (or scripts/mediafetch.py --cdn) will try the "
                     "CDN for the bytes.")
    if master:
        log.info("HISTORY DONE: recovered %s messages older than the cache, across %d chats -> %s",
                 f"{len(master):,}", len(by), pass_out)
        if not served_any:
            log.warning("NOTE: this run was served nothing new — every message above came from "
                        "earlier runs. Before reading that as throttling, note the client stops "
                        "after its first PROBE_CHATS=%s chats, so a run can ask a handful of chats "
                        "out of hundreds and report silence. Chats the phone has ended are skipped "
                        "and chats that stayed silent are asked last from now on (%s), which puts "
                        "other chats at the head of the queue for the next run.",
                        _PROBE_CHATS, os.path.basename(state_path))
        log.warning("NOTE: this is NOT necessarily everything. What you get is whatever your phone chose to "
                    "serve — it commonly returns only part of what it holds, and the rest may come on a later "
                    "run. Re-run `wawf history` to continue deeper from here (progress is saved and deduped); "
                    "a pass that adds nothing does not mean the older history is gone.")
        return 0
    # Nothing at all came back: explain WHY, so an empty result isn't read as a broken tool.
    log.warning("NOTHING RECOVERED — and this is usually NOT a fault in this tool. On-demand history is "
                "served by your PHONE (WhatsApp's servers only relay the request). Your phone answered none "
                "of the requests this run. That happens even with the phone online and connected: WhatsApp "
                "throttles these requests, and the exact reasons a phone silently declines are still under "
                "research. Everything up to this step (credentials, Signal state, anchors, the login) "
                "succeeded — only the phone's replies were missing.")
    log.warning("WHAT TO TRY: open WhatsApp on your phone and leave it on-screen on a stable network, close "
                "every web.whatsapp.com tab (a live web session fights this one for the same linked device), "
                "then run `wawf history` again. Nothing was lost — it resumes where it left off. Repeated "
                "attempts at different times are normal and often succeed where one did not.")
    return 1

def cmd_list_partitions(a):
    """Print every WhatsApp Web session in a Chromium profile: one line each, plus a JSON form for tools."""
    _require_source(a, "--list-partitions")
    if not _is_chromium(a.profile):
        log.error("--list-partitions applies to Chromium profiles (a Firefox profile has one session)")
        return 2
    sys.path.insert(0, os.path.join(HERE, "scripts"))
    import chromium_reader as cr
    cr.load_source(a.profile)
    rows = cr.ACQUISITION.get("partitions", [])
    print(f"{'layout':<20} {'account':<22} {'messages':>9}  root key  storage key")
    for r in rows:
        print(f"{r['layout']:<20} {(r.get('account') or '-'):<22} {r['messages']:>9}  "
              f"{'yes' if r['has_root_key'] else 'no ':<8}  {r['storage_key']}"
              f"{'   <- default' if r['storage_key'] == cr.ACQUISITION.get('selected') else ''}")
    print("WAWF_PARTITIONS_JSON " + json.dumps([{k: r.get(k) for k in ("layout", "account", "messages",
          "has_root_key", "storage_key")} for r in rows]))
    return 0

def cmd_sqlite(a):
    _require_source(a, "sqlite")                            # a profile (or --origin) is required; nothing is auto-detected
    extra = ["--out", a.out]
    if a.profile and _is_chromium(a.profile):
        extra += ["--profile", a.profile]          # Chromium (Chrome/Edge/Brave/Opera)
    else:
        origin = a.origin
        if not origin and a.profile:               # a Firefox profile dir -> derive its origin storage dir
            cand = os.path.join(a.profile, "storage/default/https+++web.whatsapp.com")
            if os.path.isdir(cand): origin = cand
        if origin: extra += ["--origin", origin]
    hf = getattr(a, "history_file", None)
    if hf and os.path.isfile(hf): extra += ["--history", hf]
    if not a.enc_static: extra += ["--metadata-only"]
    if a.profile and _is_chromium(a.profile):
        import chromium_reader as _cr
        _cr.release()          # the helper reads the parsed store from the run cache; don't hold two copies
    rc = _sub("export_sqlite.py", extra, secret_env={"WAWF_ENC_STATIC": a.enc_static})
    if rc == 0:
        # Same receipt as the text/JSON side, so a later --history run can name what it found here
        # instead of calling it an export of unknown composition.
        counts = {}
        try:
            import sqlite3 as _sq
            con = _sq.connect("file:%s?mode=ro" % os.path.join(a.out, "msgstore.db"), uri=True)
            counts["messages"] = con.execute("SELECT COUNT(*) FROM message").fetchone()[0]
            counts["chats"] = con.execute("SELECT COUNT(*) FROM chat").fetchone()[0]
            try:
                counts["recovered_from_phone"] = con.execute(
                    "SELECT COUNT(*) FROM message WHERE source<>'cache'").fetchone()[0]
            except Exception:
                pass
            con.close()
        except Exception as e:
            log.debug("could not count the exported database for the receipt: %s", e)
        _write_export_manifest(a.out, "cache+phone" if counts.get("recovered_from_phone") else "cache",
                               counts, ("msgstore.db", "wa.db"))
    return rc

def _win_utf8_console():
    """Windows consoles default to a legacy codepage that renders our em dashes / arrows / box characters as
    mojibake (e.g. `?`). Switch the console AND our stdio to UTF-8 for this run, restoring the codepage on
    exit so the user's shell is left as it was. No-op off Windows."""
    if sys.platform != "win32": return
    try:
        import ctypes, atexit
        k = ctypes.windll.kernel32
        old_out, old_in = k.GetConsoleOutputCP(), k.GetConsoleCP()
        if k.SetConsoleOutputCP(65001): atexit.register(k.SetConsoleOutputCP, old_out)
        if k.SetConsoleCP(65001): atexit.register(k.SetConsoleCP, old_in)
        for s in (sys.stdout, sys.stderr):
            try: s.reconfigure(encoding="utf-8")
            except Exception: pass
    except Exception: pass

def _given_stores_profile(idb, local_storage, media_cache):
    """A run-scoped folder holding only chromium_reader.PARTS_FILE, naming the given stores. Every reader
    resolves it to the real locations; nothing is copied, and the folder is removed when the run ends."""
    import tempfile, shutil, atexit
    d = tempfile.mkdtemp(prefix="wawf_given_")
    atexit.register(shutil.rmtree, d, True)
    with open(os.path.join(d, "wawf_parts.json"), "w", encoding="utf-8") as f:
        json.dump({"idb": [os.path.abspath(x) for x in idb], "local_storage": os.path.abspath(local_storage),
                   "media_cache": [os.path.abspath(x) for x in media_cache]}, f, indent=1)
    return d

def _own_console():
    """True when nothing but this program is attached to its console (it was double-clicked). A
    one-file build runs as two processes -- the bootloader and this one -- so for it two is alone; a
    shell it was started from would be a third."""
    if sys.platform != "win32": return False
    try:
        import ctypes
        buf = (ctypes.c_uint * 8)()
        return ctypes.windll.kernel32.GetConsoleProcessList(buf, 8) <= (2 if getattr(sys, "frozen", False) else 1)
    except Exception:
        return False

def main():
    _win_utf8_console()                                  # render em dashes / arrows / box chars, not mojibake
    # frozen dispatch: `<exe> _runpy <script.py> [args...]` runs a bundled helper in-process
    # (a onefile binary cannot exec a loose .py; the helper's own __main__ runs via runpy).
    if getattr(sys, "frozen", False) and len(sys.argv) >= 3 and sys.argv[1] == "_runpy":
        import runpy
        path = os.path.join(HERE, "scripts", sys.argv[2])
        sys.argv = [path] + sys.argv[3:]
        runpy.run_path(path, run_name="__main__")
        return 0
    # No arguments at all (a double-clicked .exe, or `wawf` typed alone): open the window instead.
    # Any argument keeps the command line exactly as it was. `--gui` asks for the window explicitly.
    if len(sys.argv) == 1 or sys.argv[1:] == ["--gui"]:
        # Double-clicked: Windows gave this process a console of its own, which would sit empty behind
        # the window (Windows Terminal ignores requests to hide it). Start the window detached, with no
        # console, and exit so this one closes. Run from a shell, the console is shared and stays.
        if len(sys.argv) == 1 and getattr(sys, "frozen", False) and _own_console():
            # PYINSTALLER_RESET_ENVIRONMENT: the new process must unpack its own copy rather than reuse
            # this one's, which is deleted the moment this process exits.
            subprocess.Popen([sys.executable, "--gui"], close_fds=True,
                             env=dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1"),
                             creationflags=0x00000008 | 0x00000200)   # DETACHED_PROCESS | NEW_PROCESS_GROUP
            return 0
        try:
            import wawf_gui
        except ImportError as e:                       # e.g. a Python without tkinter
            print(f"the window is unavailable here ({e}); run `wawf -h` for the command line", file=sys.stderr)
            return 2
        return wawf_gui.main()
    p = argparse.ArgumentParser(
        prog="wawf",
        description="WhatsApp Web Forensics (Firefox + Chromium). Point it at a browser profile and it "
                    "recovers the device credentials, captures the at-rest key, and decrypts your chats.",
        epilog=
        "WHAT IT DOES BY DEFAULT\n"
        "  wawf <PROFILE>        recover credentials -> capture the at-rest key (reconnect) -> decrypt.\n"
        "                        That is the whole job; there are no sub-commands to chain.\n"
        "\n"
        "OUTPUT  --out [FORMAT:]PATH   (repeatable; default: wawf_out as text + JSON)\n"
        "  --out D:\\case\\out                transcripts.txt + chats.json + identities.json\n"
        "  --out txt:D:\\case\\out            only transcripts.txt (senders named)\n"
        "  --out json:D:\\case\\out           chats.json + identities.json (structured)\n"
        "  --out sqlite:D:\\case\\db          Android-style msgstore.db + wa.db (open in any SQLite\n"
        "                                     viewer, or ingest with a WhatsApp forensic suite)\n"
        "  --out raw:D:\\case\\raw            every object store verbatim, decrypted in place\n"
        "  --out sqlite:D:\\case\\db --out txt:D:\\case\\out       write several formats at once\n"
        "  (FORMAT is one of txt, json, sqlite/db, raw. A plain path with no FORMAT: writes text+JSON.\n"
        "   A drive letter is never mistaken for a format, so D:\\case\\out works as you'd expect.)\n"
        "\n"
        "OPTIONAL EXTRAS\n"
        "  --key companion_enc_static.txt    already have the at-rest key? use it and skip the reconnect\n"
        "  --history             ALSO pull chat history OLDER than the browser cache from your\n"
        "                        phone, and append it to the export (networked, needs Node, takes\n"
        "                        hours; the phone must answer). With --out it decrypts the local\n"
        "                        store first, then appends what the phone returns -- one timeline\n"
        "                        per chat, written beside an earlier export, never over it.\n"
        "  --fetch-media         with --history --out sqlite:PATH, also ask the CDN for media the\n"
        "                        browser never cached (networked, slow, expired urls give 403)\n"
        "  --no-audit            do NOT write the chain-of-custody database (written by default)\n"
        "\n"
        "EXAMPLES\n"
        "  wawf \"" + _example_profile() + "\"\n"
        "  wawf \"" + _example_profile() + "\" --out sqlite:D:\\case\\db\n"
        "  wawf \"" + _example_profile() + "\" --key companion_enc_static.txt --out json:D:\\case\n"
        "\n"
        "PROFILE LOCATIONS ON THIS SYSTEM\n" + _profile_help() + "\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    p.add_argument("profile", nargs="?", metavar="PROFILE",
                   help="the browser profile folder to examine (required unless --origin is given). "
                        "Chromium: the folder containing 'IndexedDB'. Firefox: the profile folder. "
                        "See PROFILE LOCATIONS below. Never auto-detected.")
    p.add_argument("--origin", metavar="DIR",
                   help="Firefox web.whatsapp.com storage folder, instead of a profile folder")
    p.add_argument("--out", action="append", metavar="[FORMAT:]PATH",
                   help="where to write the results, repeatable. FORMAT is txt, json, sqlite/db "
                        "or raw (every store verbatim, decrypted in place); "
                        "a plain path writes text + JSON. Default: wawf_out. See OUTPUT below for examples.")
    p.add_argument("--raw-include-keys", action="store_true",
                   help="with --out raw: also dump signal-storage and wawc_db_enc. They hold the "
                        "account's Signal sessions, prekeys and the at-rest root key, so a dump that "
                        "includes them is key material and must not travel with a case.")
    p.add_argument("--key", metavar="FILE",
                   help="a companion_enc_static.txt captured earlier, to decrypt without touching the "
                        "network. Normally unnecessary: a copy left beside the output is picked up "
                        "automatically. A FILE rather than the key itself, so no secret reaches your "
                        "shell history, process list or command auditing.")
    p.add_argument("--offline", action="store_true",
                   help="never contact WhatsApp: decrypt with a key file if one is given or found, otherwise "
                        "export everything except message text")
    p.add_argument("--partition", metavar="WHICH",
                   help="when a profile holds more than one WhatsApp session, which one to examine: the "
                        "account number, the storage key, or the layout name shown by --list-partitions")
    g2 = p.add_argument_group("without a profile folder: point at the stores themselves")
    g2.add_argument("--idb", metavar="DIR", action="append",
                    help="a WhatsApp Web IndexedDB folder (https_web.whatsapp.com_0.indexeddb.leveldb, or "
                         "WebStorage/<n>/IndexedDB/indexeddb.leveldb), wherever it is; repeatable")
    g2.add_argument("--local-storage", metavar="DIR",
                    help="the profile's 'Local Storage/leveldb' folder (key salt, device keys, signed-in account)")
    g2.add_argument("--media-cache", metavar="DIR", action="append",
                    help="a cache folder to search for media (CacheStorage, Cache_Data, ...); repeatable")
    p.add_argument("--list-partitions", action="store_true",
                   help="list every WhatsApp Web session (storage partition) in the profile, then stop")
    p.add_argument("--creds", metavar="FILE",
                   help="an existing creds_in.json to reuse instead of recovering credentials again "
                        "(skips the minutes-long read of the browser storage). It must describe the "
                        "SAME device the profile holds: credentials exported before the browser "
                        "re-paired name a device that no longer exists and the login is refused -- "
                        "scripts/check_identity.py says which you have.")

    g = p.add_argument_group("optional actions (instead of the default decrypt job)")
    g.add_argument("--history", action="store_true",
                   help="pull chat history older than the browser cache from your phone. NETWORKED and "
                        "phone-dependent; pure Python (WAWF_HISTORY_ENGINE=node runs the Node client). "
                        "Results are saved and resume. "
                        "With --out, the local store is decrypted first and the recovered messages are "
                        "appended to it, so the export is one timeline per chat with every row saying "
                        "whether it came from the cache or the phone; it is written beside any export "
                        "already at that path rather than over it.")
    # The memory scan (--memory / --live / --memimage / --deep) is NOT exposed. The code is intact --
    # `cmd_memory` below, `scripts/wa_forensic.py`, and the key-from-RAM research behind them -- it is
    # the CLI surface that is withdrawn, because the mode could only validate candidates against a
    # FIREFOX store and there is no scenario yet where it beats the two routes that always work: a
    # normal run captures the key over the network, and `--key` decrypts offline with a key captured
    # earlier. Restoring it is these four add_argument lines plus the dispatch branch, both marked.
    g.add_argument("--queue", action="store_true",
                   help="record what WhatsApp's server is holding for this device (messages, group and "
                        "status updates, receipts, call offers received while the browser was closed), "
                        "decrypted with the browser's own keys. NETWORKED; nothing is acknowledged, so the "
                        "server keeps the queue for the browser, and nothing a contact can see is sent. "
                        "Written to <first --out>/server-queue/<time>/, and its messages are merged "
                        "into the export, each row marked source=server-queue.")
    g.add_argument("--install-node", action="store_true",
                   help="allow --history to INSTALL Node.js via winget if none is found. Not covered "
                        "by --yes, because it modifies this machine and asks for elevation; a "
                        "portable Node unzipped beside the tool, or WAWF_NODE, needs neither.")
    g.add_argument("--history-refetch", action="store_true",
                   help="with --history: re-ask for history already recovered instead of going "
                        "deeper, to fill in fields an earlier run did not capture (the group sender). "
                        "Finds nothing new by design and spends the same rate-limit budget.")
    g.add_argument("--fetch-media", action="store_true",
                   help="with --out sqlite:PATH: download, decrypt and verify the media the browser never "
                        "cached from WhatsApp's CDN, newest first. NETWORKED and can be large; a url whose "
                        "signature has expired is skipped. Without it the mediaKeys are still exported "
                        "and scripts/mediafetch.py --cdn can fetch later.")
    g.add_argument("--yes", action="store_true",
                   help="auto-confirm prompts that only affect this tool's own folder (such as "
                        "`npm install` in tools/reconnect). It does NOT authorise installing Node.js "
                        "system-wide -- that is --install-node.")

    g = p.add_argument_group("chain of custody")
    # NOTE: a plain flag, NOT nargs='?'. An optional-value option would swallow the PROFILE positional.
    # ON by default. A forensic tool's record of what it touched is not a feature to opt into: the
    # run that most needs the trail is the one where nobody thought to ask for it. Costs a file
    # beside the output and nothing else -- no network, no extra read of the evidence.
    g.add_argument("--no-audit", action="store_true",
                   help="do NOT write the audit database (it is written by default: every file "
                        "touched, key derivation, network request, artifact with its SHA-256, and "
                        "error, crash-safe, as wawf_audit.db beside the output)")
    g.add_argument("--audit-db", metavar="DB", help="path for the audit database (default: beside the output)")
    g.add_argument("--case-id", metavar="ID", help="case / exhibit number recorded in the audit database "
                                                    "(default: generated from the date)")
    g.add_argument("--examiner", metavar="NAME", help="who ran this, recorded with the case and with each run")
    g.add_argument("--case-notes", metavar="TEXT", help="free-text note recorded with the case")
    g.add_argument("--audit-secrets", action="store_true",
                   help="also store raw key material in the audit database (default: only SHA-256 "
                        "fingerprints plus derivation parameters, so the log is not a secret store)")

    g = p.add_argument_group("diagnostics")
    g.add_argument("-v", "--verbose", action="store_true", help="DEBUG logs + full tracebacks on error")
    g.add_argument("--log-file", metavar="FILE", help="mirror all logs (DEBUG) to this file")

    a = p.parse_args()
    if getattr(a, "offline", False) and getattr(a, "fetch_media", False):
        _usage("--offline and --fetch-media contradict each other: downloading media contacts WhatsApp's servers")
    if getattr(a, "media_cache", None):
        for d in a.media_cache:
            if not os.path.isdir(d): _usage("no such directory:\n  %s" % d)
        # read by mediacache in this process and in the helper subprocesses, for every engine
        os.environ["WAWF_MEDIA_CACHE"] = os.pathsep.join(os.path.abspath(d) for d in a.media_cache)
    if getattr(a, "idb", None) or getattr(a, "local_storage", None):
        if a.profile or a.origin:
            _usage("give either a profile folder (or Firefox --origin) or --idb/--local-storage, not both")
        if not (a.idb and a.local_storage):
            _usage("--idb and --local-storage are both needed: the messages are in the IndexedDB, and the "
                   "key salt and the signed-in account are in localStorage")
        for d in (a.idb or []) + [a.local_storage] + (a.media_cache or []):
            if not os.path.isdir(d): _usage("no such directory:\n  %s" % d)
        a.profile = _given_stores_profile(a.idb, a.local_storage, a.media_cache or [])
    # One version string for this run, inherited by the audit database (audit._tool_version reads
    # WAWF_VERSION) and by every helper process, so they cannot record different values.
    os.environ["WAWF_VERSION"] = _wawf_version()
    setup_logging(a.verbose, a.log_file)
    # Pick the action. The default IS the job: credentials -> key -> decrypt. --history and --memory are
    # the two alternative actions; everything else is an option on the default job.
    # (the memory-scan branch belonged here; see the note where its arguments were withdrawn)
    if getattr(a, "partition", None):
        os.environ["WAWF_PARTITION"] = a.partition       # helper subprocesses read the same session
    if getattr(a, "list_partitions", False):
        return cmd_list_partitions(a)
    if getattr(a, "queue", False) and a.history:
        _usage("--queue and --history are separate runs: run one, then the other")
    if getattr(a, "queue", False) and getattr(a, "offline", False):
        _usage("--queue signs in to WhatsApp's server, and --offline forbids going online")
    if getattr(a, "queue", False):
        def _decrypt_then_queue(a):
            # The queue first, so the export can fold it in: one timeline per chat, every row saying
            # whether it came from the browser's store or the server queue.
            rc = cmd_queue(a)
            if rc or not a.out: return rc            # with no --out: only the queue
            qf = getattr(a, "queue_export_file", None)
            if qf and os.path.isfile(qf) and not getattr(a, "history_file", None):
                a.history_file = qf
            return cmd_run(a)
        a.cmd, action = "decrypt+queue", _decrypt_then_queue
    elif a.history:
        a.cmd, action = "history", cmd_history
    else:
        a.cmd, action = "decrypt", cmd_run
    # Inputs are checked BEFORE a case database is opened. Every command here needs a profile and
    # valid --out formats, and with the audit on by default a mistyped path was leaving a
    # chain-of-custody file behind for a run that never started -- in the working directory, which
    # for anyone running from a clone is the repository.
    _require_source(a, "")
    for _spec in (a.out or []): _parse_out(_spec)
    global AUDIT
    if not getattr(a, "no_audit", False):            # the trail is written unless asked not to
        AUDIT = audit.open_db(_audit_db_path(a), case_id=getattr(a, "case_id", None),
                              record_secrets=getattr(a, "audit_secrets", False),
                              examiner=getattr(a, "examiner", None), notes=getattr(a, "case_notes", None))
        if AUDIT.enabled:
            AUDIT.start_run(a.cmd, sys.argv)
            # mirror EVERY log record (and any exc_info traceback) into the DB, so the trail is complete
            logging.getLogger().addHandler(AUDIT.logging_handler())
            log.info("audit: case %s  run %s  -> %s", AUDIT.case_id, AUDIT.run_id, AUDIT.path)
            if getattr(AUDIT, "case_id_conflict", None):
                log.warning("this audit database already belongs to case %s; --case-id %s was not applied "
                            "(one database is one case -- use another --audit-db for another case)",
                            AUDIT.case_id, AUDIT.case_id_conflict)
            if getattr(a, "examiner", None) or getattr(a, "case_notes", None):
                AUDIT.event("case details", category="case",
                            detail={"examiner": getattr(a, "examiner", None), "notes": getattr(a, "case_notes", None)})
            if AUDIT.record_secrets:
                log.warning("--audit-secrets: raw key material WILL be stored in %s — protect it accordingly.",
                            AUDIT.path)
    t0 = time.time()
    rc, status, err, tb = 0, "ok", None, None
    # Parsed-profile cache shared with helper subprocesses for this run only (see chromium_reader).
    import tempfile, shutil
    _cache_dir = tempfile.mkdtemp(prefix="wawf_src_")
    os.environ["WAWF_SOURCE_CACHE"] = _cache_dir
    try:
        rc = action(a)
        status = "ok" if not rc else "error"
    except SystemExit as e:
        log.error("%s", e); rc = int(e.code) if isinstance(e.code, int) else 1
        status, err = "error", e
    except KeyboardInterrupt:
        log.error("interrupted by user"); rc, status = 130, "interrupted"
    except FileNotFoundError as e:
        log.error("file not found: %s", e); (a.verbose and log.exception("traceback"))
        import traceback as _tb; rc, status, err, tb = 4, "error", e, _tb.format_exc()
    except Exception as e:
        log.error("%s: %s", type(e).__name__, e)
        log.exception("traceback") if a.verbose else log.error("(re-run with -v for the full traceback)")
        import traceback as _tb; rc, status, err, tb = 1, "error", e, _tb.format_exc()
    finally:
        shutil.rmtree(_cache_dir, ignore_errors=True)
        os.environ.pop("WAWF_SOURCE_CACHE", None)
        log.debug("elapsed %.1fs", time.time() - t0)
        # record the outcome even on failure: a 'running' status left behind means the process was killed
        AUDIT.end_run(rc or 0, status=status, error=err, tb=tb)
        AUDIT.close()
    return rc or 0

if __name__ == "__main__":
    sys.exit(main())
