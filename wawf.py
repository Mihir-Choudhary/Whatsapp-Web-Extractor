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

Output is chosen with --out [FORMAT:]PATH (repeatable; FORMAT = txt | json | sqlite/db). A plain path
writes transcripts.txt + chats.json; sqlite: writes an Android-style msgstore.db + wa.db. A Windows
drive letter is never mistaken for a FORMAT.

Two alternative actions replace the default job:
  --history                     pull chat history OLDER than the browser cache from the phone (Node)
  --memory (--live|--memimage)  hunt the at-rest key in RAM / swap / hibernation

Examples:
  wawf "C:\\Users\\<you>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
  wawf <PROFILE> --out sqlite:D:\\case\\db --out txt:D:\\case\\out
  wawf <PROFILE> --enc-static <b64> --out json:D:\\case --audit
"""
from __future__ import annotations
import argparse, sys, os, json, base64, logging, collections, datetime as dt, subprocess, time

HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # _MEIPASS when frozen (.exe)
sys.path.insert(0, os.path.join(HERE, "scripts")); sys.path.insert(0, HERE)
log = logging.getLogger("wawf")

import audit                                   # optional chain-of-custody DB (no-op unless --audit)
AUDIT = audit.NoAudit()                        # replaced in main() when --audit is given

def _evidence_paths(src):
    """The actual WhatsApp Web store inside a profile. Recording (and walking) a browser's ENTIRE profile is
    slow and misleading — most of it is unrelated cache, and the byte count would describe the browser, not
    the evidence. For Chromium that's the web.whatsapp.com IndexedDB (+ its external blob dir) and the
    localStorage LevelDB; a Firefox --origin dir already IS the store."""
    out = []
    idb = os.path.join(src, "IndexedDB")
    if os.path.isdir(idb):                                   # a Chromium profile dir
        for suf in ("_0.indexeddb.leveldb", "_0.indexeddb.blob"):
            p = os.path.join(idb, "https_web.whatsapp.com" + suf)
            if os.path.exists(p): out.append(p)
        lsd = os.path.join(src, "Local Storage", "leveldb")
        if os.path.isdir(lsd): out.append(lsd)
    return out or [src]

def _audit_evidence(src):
    """Record the evidence source: the profile/origin it came from, plus each WhatsApp store inside it with
    file count and total bytes."""
    if not src: return
    AUDIT.event("evidence source", category="acquire", detail={"profile_or_origin": src})
    for p in _evidence_paths(src):
        AUDIT.dir_read(p, purpose="WhatsApp Web store (evidence)")

def _audit_db_path(a):
    """The case DB lives WHERE THE OUTPUT GOES, so each case/output dir keeps its own history. --out may be
    a directory (decrypt/sqlite) or a file (creds/reconnect); commands without --out fall back to the CWD."""
    v = getattr(a, "audit_db", None)
    if v: return v                                          # explicit --audit-db <path>
    out = getattr(a, "out", None)
    if out:
        base = out if (os.path.isdir(out) or not os.path.splitext(out)[1]) else os.path.dirname(out)
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
        fh = logging.FileHandler(logfile); fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s"))
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

_OUT_FORMATS = ("txt", "json", "sqlite", "db")

def _parse_out(spec):
    """'--out FORMAT:PATH' -> (format, path); a bare path -> (None, path) meaning 'all text formats'.
    Only a KNOWN format counts as a prefix, so a Windows path like D:\\case\\out keeps its drive letter
    instead of being read as format 'D'."""
    if ":" in spec:
        head, rest = spec.split(":", 1)
        if head.lower() in _OUT_FORMATS and rest:
            return ("sqlite" if head.lower() in ("sqlite", "db") else head.lower()), rest
    return None, spec

def _out_workdir(path):
    """The folder an --out target lives in (the target itself when it names a folder)."""
    return path if (os.path.isdir(path) or not os.path.splitext(path)[1]) else (os.path.dirname(path) or ".")

def _require_source(a, cmd="<command>"):
    """Every data command needs an explicit profile (or Firefox --origin). Nothing is guessed: which
    profile gets examined is always the user's choice. Fail with the paths to look in, not a bare usage line."""
    if getattr(a, "profile", None) or getattr(a, "origin", None): return
    raise SystemExit("no profile given. Pass the browser profile directory to examine, or --origin for a "
                     "Firefox\nweb.whatsapp.com storage dir. Profiles are NOT auto-detected.\n\n"
                     "Profile locations on this system:\n" + _profile_help() +
                     "\n\nExample:\n  wawf " + cmd + " <profile-dir>")

def _require_session(ls, what="that profile"):
    """A browser can hold WhatsApp Web storage without being a logged-in session (site merely visited, or
    logged out). Say so plainly instead of dying with a KeyError deep inside the key derivation."""
    missing = [k for k in ("last-wid-md", "WAWebEncKeySalt", "WANoiseInfo") if k not in ls]
    if missing:
        raise SystemExit("%s has WhatsApp Web storage but is not a logged-in session (missing: %s). Log in to "
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
    engine, ls, root, msgs, meta = WD.load(getattr(a, "profile", None), getattr(a, "origin", None))
    log.info("engine=%s  messages=%d  root_key=%s  ls_keys=%d", engine, len(msgs), "yes" if root else "NO", len(ls))
    # what came OUT of the evidence source, and the on-disk root key that everything derives from
    AUDIT.event("loaded WhatsApp Web store", category="acquire",
                detail={"engine": engine, "source": src, "messages": len(msgs),
                        "localStorage_keys": len(ls), "stores": meta, "root_key_found": bool(root)})
    if root:
        AUDIT.crypto("recover", key=root, key_source="IndexedDB wawc_db_enc/keys (root key, non-extractable "
                     "CryptoKey serialized to disk)", input_desc=src,
                     detail={"engine": engine, "root_len": len(root)})
    if not root: raise SystemExit("root key not found in wawc_db_enc/keys (is this a WhatsApp Web profile?)")
    return WD, engine, ls, root, msgs, meta

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

    log.info("[1/3] recovering device credentials from the profile ...")
    creds_path = os.path.join(workdir, "creds_in.json")
    if cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=creds_path, _internal=True)):
        return 3

    key = a.enc_static
    if key:
        log.info("[2/3] using the companion_enc_static given with --enc-static (no reconnect needed)")
    else:
        log.info("[2/3] reconnecting as the linked device to capture companion_enc_static (NETWORKED) ...")
        keyfile = os.path.join(workdir, "companion_enc_static.txt")
        rc = cmd_reconnect(argparse.Namespace(profile=a.profile, origin=a.origin, creds=creds_path,
                                              out=keyfile, verbose=a.verbose))
        if rc:
            log.error("could not capture the at-rest key, so there is nothing to decrypt with. "
                      "Supply one with --enc-static, or recover it from memory with --memory.")
            return rc
        key = open(keyfile, encoding="utf-8").read().strip()

    log.info("[3/3] decrypting to %d output(s) ...", len(outs))
    for fmt, path in outs:
        if fmt == "sqlite":
            rc = cmd_sqlite(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key, out=path))
        else:
            rc = cmd_decrypt(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key,
                                                out=path, only=fmt))
        if rc: return rc
    return 0

def cmd_decrypt(a):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    WD, engine, ls, root, msgs, meta = _load_wa(a)
    _require_session(ls, getattr(a, "profile", None) or getattr(a, "origin", None))
    _summary(engine, ls, msgs, meta)
    salt_ws = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    sch = collections.Counter(m["scheme"] for m in msgs if m["data"])
    log.info("message schemes: %s", dict(sch))
    if not a.enc_static:
        log.info("no --enc-static: offline inventory only. Message TEXT needs companion_enc_static "
                 "(memory or reconnect). Media keys/metadata are already on disk.")
        return 0
    enc_static = base64.b64decode(a.enc_static)
    key = HKDF(algorithm=hashes.SHA256(), length=16, salt=enc_static, info=salt_ws).derive(root)
    # exactly what derived the message key, so an examiner can reproduce it: root (on disk) + server-only
    # companion_enc_static as HKDF salt + WAWebEncKeySalt as info -> AES-CBC-128
    AUDIT.crypto("derive", algorithm="AES-CBC-128", kdf="HKDF-SHA256 len=16", scheme="1 (final)",
                 key=key, key_source="HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt)",
                 salt=enc_static, salt_source="companion_enc_static (--enc-static; server-issued, never on disk)",
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
    chats = collections.defaultdict(list); ok = fail = 0
    for m in msgs:
        if not m["data"] or m["scheme"] != 1: continue   # scheme-1 only; skip scheme-0 (would be garbage)
        try: pt = WD.pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception as e: fail += 1; log.debug("decrypt fail %s: %s", m["id"][:24], e); continue
        chats[m["chat"]].append({"t": ts(m["t"]), "dir": "me" if m["from_me"] else "them",
                                 "type": m["type"], "sender": m["sender"], "text": " ".join(dict.fromkeys(WD.leaves(pt)))[:2000]})
        ok += 1
    for c in chats: chats[c].sort(key=lambda x: x["t"])
    only = getattr(a, "only", None)                      # 'txt' / 'json' from --out FORMAT:PATH; None = both
    if only != "txt":
        json.dump(chats, open(f"{a.out}/chats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    if only == "json":
        log.info("decrypted %d bodies (%d failed) -> %s/chats.json", ok, fail, a.out)
        AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=ok)
        return 0
    with open(f"{a.out}/transcripts.txt", "w", encoding="utf-8") as f:  # message text has emoji/non-Latin -> pin UTF-8 (Windows default is cp1252)
        for c, ml in sorted(chats.items(), key=lambda kv: -len(kv[1])):
            tm = [m for m in ml if m["text"]]
            if not tm: continue
            f.write(f"\n===== {c} ({len(ml)} msgs, {len(tm)} text) =====\n")
            for m in ml:
                if m["text"]: f.write(f"[{m['t']}] {m['dir']:>4}: {m['text']}\n")
    log.info("decrypted %d bodies (%d failed) -> %s/ (chats.json + transcripts.txt)", ok, fail, a.out)
    # outcome of the bulk decrypt + hashes of what was produced (so the exports are tamper-evident)
    AUDIT.crypto("decrypt", algorithm="AES-CBC-128", scheme="1 (final)", key=key,
                 input_desc="all scheme-1 msgRowOpaqueData bodies", records_in=ok + fail,
                 records_ok=ok, records_failed=fail, detail={"chats": len(chats)})
    AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=ok)
    AUDIT.artifact(f"{a.out}/transcripts.txt", kind="decrypted transcripts (text)", records=ok)
    return 0

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
        recs = None
        if profile and os.path.isdir(os.path.join(profile, "IndexedDB")):
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
                return None
            con = _sq.connect(f"file:{mm[0]}?mode=ro&immutable=1", uri=True)
            sid = _sidf(con, "user-prefs")
            if sid is None:
                return None
            recs = []
            for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
                try:
                    recs.append(_sc.loads(_unc(row)))
                except Exception:
                    continue
        for r in recs or []:
            if isinstance(r, dict) and str(r.get("key")) == "WARoutingInfo":
                v = r.get("value")
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
    elif a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")): ls, root, meta = BC.load_chromium(a.profile)
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

def _sub(script, extra):
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
    rc = subprocess.run(cmd, env=_env).returncode        # child appends to the same case DB
    AUDIT.event("helper subprocess exit rc=%s" % rc, level=("INFO" if rc == 0 else "ERROR"),
                category="subprocess", detail={"script": script, "rc": rc})
    return rc

def cmd_memory(a):
    extra = []
    if a.live: extra.append("--live")
    if a.memimage: extra += ["--memimage", a.memimage]
    if a.deep: extra.append("--deep")
    if a.enc_static: extra += ["--enc-static", a.enc_static]
    if a.origin: extra += ["--origin", a.origin]
    if a.yes: extra.append("--yes")
    return _sub("wa_forensic.py", extra)

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
        key = open(a.out, encoding="utf-8").read().strip()
        log.info("companion_enc_static captured (%d chars) -> %s", len(key), os.path.abspath(a.out))
        log.info("next:  wawf decrypt <profile> --enc-static %s --out out/", key)
    return rc

def _deepen_anchors(anchors_path, master):
    """Re-anchor each chat on the OLDEST message recovered so far and add all recovered ids to the
    on-disk set, so the next history pass continues further back instead of re-pulling the same window.

    Anchors are UPDATED IN PLACE rather than rebuilt. An anchor carries more than a timestamp: `chat`
    is the jid WhatsApp Web actually addresses (the historyChatId in its wire `@s.whatsapp.net` form,
    which is NOT the chat id), `chat_id` is the local chat id, and `more_on_primary` records whether
    the chat's endOfHistoryTransferType says the primary still holds older messages. Rebuilding an
    anchor from a recovered message threw all three away: it replaced the wire-form `chat` with
    whatever form the phone happened to return, so chats went back to being asked for by a jid the
    reference client never sends; it dropped `more_on_primary`, so chats build_anchors had excluded as
    unanswerable came back from pass 2 onward; and because the dict was keyed on that form, a chat
    whose returned jid differed from its anchor's got a SECOND anchor appended instead of being
    deepened -- re-requesting the window it had just finished.
    """
    a = json.load(open(anchors_path, encoding="utf-8"))
    ondisk = set(a["ondisk_ids"]); anchors = list(a["anchors"])
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
        x = idx.get(str(c))
        if x is None:                                      # a chat with no anchor: adopt it as-is
            x = {"chat": c, "chat_id": c, "more_on_primary": True}
            anchors.append(x); idx[str(c)] = x
        cur = deepest.get(id(x))
        if cur is None or ts < cur[1]:
            deepest[id(x)] = (x, ts, m["id"], bool(m.get("fromMe")))
    for x, ts, mid, fromme in deepest.values():            # mutate: every other field is preserved
        x["oldest_id"], x["oldest_ts"], x["oldest_fromMe"] = mid, ts, fromme
    # continue the chats we just went deeper on first, then the rest
    newanchors = [x for x in anchors if id(x) in deepest] + [x for x in anchors if id(x) not in deepest]
    tmp = anchors_path + ".tmp"                            # atomic write: a failed/interrupted write must not
    with open(tmp, "w", encoding="utf-8") as f: json.dump({"anchors": newanchors, "ondisk_ids": sorted(ondisk)}, f)  # corrupt
    os.replace(tmp, anchors_path)                          # the anchors.json the node client reads next pass

def _resume_master(accum, anchors_path, master):
    """Reload messages recovered on prior `wawf history` runs (from the accumulated ledger) into `master`
    and push the freshly-built anchors past them, so a new run continues older than prior runs instead of
    re-requesting the same window. Returns how many prior messages were reloaded (0 if none / on error)."""
    if not os.path.exists(accum): return 0
    try:
        for m in (json.load(open(accum, encoding="utf-8")).get("messages") or []):
            if m.get("id"): master[m["id"]] = m
        if master: _deepen_anchors(anchors_path, master)
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
    """A bundled Node (standalone .exe), else node(.exe) on PATH, else a known install location (a freshly
    winget-installed Node is not yet on this process's PATH). Returns the node path or None."""
    import shutil
    # standalone build: Node is packaged inside the .exe under node/ (the spec bundles the bare binary, but
    # accept bin/node too in case a whole Node dist is bundled instead).
    for b in ([os.path.join(HERE, "node", "node.exe")] if sys.platform == "win32"
              else [os.path.join(HERE, "node", "node"), os.path.join(HERE, "node", "bin", "node")]):
        if os.path.isfile(b): return b
    n = shutil.which("node")
    if n: return n
    for c in [r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe",
              os.path.expandvars(r"%LOCALAPPDATA%\Programs\nodejs\node.exe")]:
        if os.path.isfile(c): return c
    return None

def _ensure_node(assume_yes=False):
    """Return a path to node, offering to install Node.js if it's missing. None if unavailable."""
    node = _find_node()
    if node: return node
    if sys.platform != "win32":
        log.error("Node.js is required for history sync. Install it from https://nodejs.org and re-run."); return None
    if not _prompt_yes("history sync needs Node.js, which isn't installed. Install it now via winget?", assume_yes):
        log.error("Node.js is required — install it from https://nodejs.org, then re-run `wawf history`."); return None
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

def cmd_history(a):
    """On-demand history sync: pull messages OLDER than the browser cache from WhatsApp's servers, per
    chat, going back toward each chat's start — ITERATIVELY: each pass re-anchors on the oldest message
    recovered so far and pulls deeper, accumulating (deduped) until it converges. Recovers creds + Signal
    state + anchors (pure Python) then runs the Node/Baileys extractor. The Signal/E2E stack isn't ported
    to Python, so this needs Node + `npm install` in tools/reconnect: the .exe will use that folder if it
    sits next to the executable (e.g. the repo's dist/), but it is not bundled inside the .exe itself."""
    rec = _find_reconnect_dir()
    if not rec:
        log.error("history needs the Node client (tools/reconnect/history_extract.js), which is not bundled "
                  "in the .exe. Run wawf from the repo, or keep the .exe inside the repo (its dist/ folder is "
                  "fine) so tools/reconnect sits alongside it.")
        return 2
    node = _ensure_node(getattr(a, "yes", False))        # find Node, or offer to install it
    if not node: return 2
    node_dir = os.path.dirname(node)                     # make node/npm resolvable for this run's subprocesses
    if node_dir and node_dir not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = node_dir + os.pathsep + os.environ.get("PATH", "")
    if not _ensure_baileys(rec, node, getattr(a, "yes", False)): return 2   # find Baileys, or offer npm install
    # Where OUTPUTS (creds/state/anchors/recovered history) go. For a standalone .exe the Node client (rec)
    # lives inside the temp extraction dir, which is wiped on exit — so write outputs to a persistent folder
    # next to the executable instead, and keep the resume ledger there across runs.
    if getattr(sys, "frozen", False) and os.path.abspath(rec) == os.path.abspath(os.path.join(HERE, "tools", "reconnect")):
        work = _pick_work_dir()                          # exact match on the bundled client, not a prefix test
        log.info("history data dir: %s", work)
    else:
        work = rec                                       # from-source / repo-adjacent: outputs live in tools/reconnect
    # engine args shared by creds / signal-state / anchors
    _require_source(a, "history")                           # a profile (or --origin) is required; nothing is auto-detected
    if a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
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
    if _sub("check_identity.py", eng + ["--dir", work, "--quiet"]):
        log.error("the credentials just exported do not match the profile — refusing to run with them. "
                  "Run scripts/check_identity.py --profile <profile> --dir %s for the details.", work)
        return 3
    log.info("[3/4] building anchors from on-disk messages ...")
    if _sub("build_anchors.py", eng + ["--out", os.path.join(work, "anchors.json")]): return 3
    log.warning("[4/4] NETWORKED iterative history sync — logs in as your linked device and asks your phone, "
                "chat by chat, for messages older than the cache, re-anchoring deeper each pass until the "
                "phone's retained history is drained. Own account / authorized use only; this can take many "
                "minutes and repeated passes.")
    log.warning("HOW THIS WORKS / WHAT TO EXPECT: the messages come from your PHONE, not from WhatsApp's "
                "servers — the servers only relay the request. So this is NOT guaranteed to return anything: "
                "the phone often answers partially, and sometimes answers nothing at all EVEN WHEN it is "
                "online and connected. WhatsApp throttles these requests and the exact conditions under "
                "which a phone declines are still being researched, so an empty result is a known outcome, "
                "not necessarily a failure of this tool.")
    log.warning("FOR THE BEST CHANCE: open WhatsApp on your phone and leave it on-screen, keep it on a "
                "stable network, and close every web.whatsapp.com tab (a live web session competes with "
                "this one for the same linked device). Progress is saved after every pass, so re-running "
                "later simply continues deeper — an empty pass loses nothing.")
    log.warning("SIDE EFFECT ON THE DEVICE: your phone's replies are end-to-end encrypted to a Signal "
                "session, and the copy in the browser profile is a snapshot of a ratchet that keeps moving, "
                "so this renegotiates that session and then keeps its own copy (signal_runtime.json, next "
                "to the output — treat it as key material). The browser's stored session for this linked "
                "device therefore goes stale; WhatsApp Web re-establishes it by itself the next time you "
                "open it. Nothing on the phone or in the profile is modified.")
    log.warning("KEEP signal_runtime.json (and its .bak) WITH THE CASE — it is NOT a cache. It holds the "
                "only copy of the prekeys this tool published to WhatsApp's servers, which peers then "
                "encrypt to, and of ratchet state the phone has already moved past. Delete it and "
                "anything encrypted to those keys is permanently unreadable, even from the same profile. "
                "Every run also advances that shared state, so run deliberately, not repeatedly.")
    env = dict(os.environ, TOP="100000", COUNT="50", MAXPAGES="100000")   # every chat, page until exhausted
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
    n = _resume_master(accum, anchors_path, master)
    if n: log.info("resuming: %s messages recovered on prior runs — continuing older than those.", f"{n:,}")

    MIN_NEW, MAX_PASSES = 40, 25                             # stop when a pass adds < MIN_NEW; hard safety cap
    # Exit 7 from the Node client means its cooldown breaker stopped the pass: ten unanswered requests
    # inside WhatsApp's own 7200-second window. That is not a failure and must not be treated as one.
    # A sweep of a few hundred chats cannot fit inside one window, so the right response is to wait the
    # cooldown out and resume from the checkpoint -- which costs nothing, because every pass re-anchors
    # on the oldest message recovered so far. Set WAWF_COOLDOWN_SEC=0 to get the old behaviour of
    # stopping instead, and WAWF_MAX_COOLDOWNS to bound how long a run may sit waiting.
    COOLDOWN_RC = 7
    COOLDOWN = int(os.environ.get("WAWF_COOLDOWN_SEC", 7200))
    MAX_COOLDOWNS = int(os.environ.get("WAWF_MAX_COOLDOWNS", 6))
    cooldowns_used = 0
    try:
        for p in range(1, MAX_PASSES + 1):
            log.info("──── history pass %d ────", p)
            if os.path.exists(pass_out): os.remove(pass_out)   # else a node failure re-reads a stale pass as "new"
            ncmd = [node, os.path.join(rec, "history_extract.js")]
            AUDIT.event("history pass %d: launching Node extractor" % p, category="stage",
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
            new = 0
            for m in (passd.get("messages") or []):
                i = m.get("id")
                if i and i not in master: master[i] = m; new += 1
            by = _checkpoint(accum)                          # checkpoint the accumulated set every pass
            log.info("pass %d: +%d new  ·  total recovered: %d across %d chats", p, new, len(master), len(by))
            if rc == COOLDOWN_RC:
                _deepen_anchors(anchors_path, master)        # bank progress before the wait
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
            if new < MIN_NEW:
                if master:
                    log.info("converged — last pass added < %d new messages. Stopping.", MIN_NEW)
                else:                                        # never say "converged" when nothing ever arrived
                    log.warning("pass %d came back empty — the phone answered none of the requests. Stopping.", p)
                break
            _deepen_anchors(anchors_path, master)            # go deeper next pass
    except KeyboardInterrupt:
        log.warning("interrupted — checkpointing %s recovered messages before exit.", f"{len(master):,}")
        _checkpoint(accum); _checkpoint(pass_out); raise

    by = _checkpoint(pass_out); _checkpoint(accum)           # final full accumulated set -> both files
    AUDIT.artifact(pass_out, kind="recovered history (older than the browser cache)", records=len(master))
    AUDIT.artifact(accum, kind="history resume ledger (cumulative across runs)", records=len(master))
    if master:
        log.info("HISTORY DONE: recovered %s messages older than the cache, across %d chats -> %s",
                 f"{len(master):,}", len(by), pass_out)
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

def cmd_sqlite(a):
    _require_source(a, "sqlite")                            # a profile (or --origin) is required; nothing is auto-detected
    extra = ["--enc-static", a.enc_static, "--out", a.out]
    if a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
        extra += ["--profile", a.profile]          # Chromium (Chrome/Edge/Brave/Opera)
    else:
        origin = a.origin
        if not origin and a.profile:               # a Firefox profile dir -> derive its origin storage dir
            cand = os.path.join(a.profile, "storage/default/https+++web.whatsapp.com")
            if os.path.isdir(cand): origin = cand
        if origin: extra += ["--origin", origin]
    return _sub("export_sqlite.py", extra)

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
        "  --out D:\\case\\out                transcripts.txt AND chats.json in that folder\n"
        "  --out txt:D:\\case\\out            only transcripts.txt (readable transcripts)\n"
        "  --out json:D:\\case\\out           only chats.json (structured, per chat)\n"
        "  --out sqlite:D:\\case\\db          Android-style msgstore.db + wa.db (open in any SQLite\n"
        "                                     viewer, or ingest with a WhatsApp forensic suite)\n"
        "  --out sqlite:D:\\case\\db --out txt:D:\\case\\out       write several formats at once\n"
        "  (FORMAT is one of txt, json, sqlite/db. A plain path with no FORMAT: writes text + JSON.\n"
        "   A drive letter is never mistaken for a format, so D:\\case\\out works as you'd expect.)\n"
        "\n"
        "OPTIONAL EXTRAS\n"
        "  --enc-static <b64>    already have the at-rest key? use it and skip the reconnect\n"
        "  --history             instead of decrypting, pull chat history OLDER than the browser\n"
        "                        cache from your phone (networked, needs Node; phone must answer)\n"
        "  --memory --live       instead of reconnecting, hunt the key in RAM/swap/hibernation\n"
        "  --audit               write a chain-of-custody database beside the output\n"
        "\n"
        "EXAMPLES\n"
        "  wawf \"" + _example_profile() + "\"\n"
        "  wawf \"" + _example_profile() + "\" --out sqlite:D:\\case\\db\n"
        "  wawf \"" + _example_profile() + "\" --enc-static <b64> --out json:D:\\case --audit\n"
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
                   help="where to write the results, repeatable. FORMAT is txt, json or sqlite/db; "
                        "a plain path writes text + JSON. Default: wawf_out. See OUTPUT below for examples.")
    p.add_argument("--enc-static", metavar="B64",
                   help="the at-rest key (companion_enc_static, base64). Given this, the networked "
                        "reconnect is skipped entirely.")
    p.add_argument("--creds", metavar="FILE",
                   help="an existing creds_in.json to reuse instead of recovering credentials again")

    g = p.add_argument_group("optional actions (instead of the default decrypt job)")
    g.add_argument("--history", action="store_true",
                   help="pull chat history older than the browser cache from your phone. NETWORKED and "
                        "phone-dependent; needs Node (offers to install it). Results are saved and resume.")
    g.add_argument("--memory", action="store_true",
                   help="recover the at-rest key from volatile memory instead of reconnecting")
    g.add_argument("--live", action="store_true", help="with --memory: scan this machine's running browser (Linux, root)")
    g.add_argument("--memimage", metavar="FILE", help="with --memory: scan a RAM/swap/hibernation image file")
    g.add_argument("--deep", action="store_true", help="with --memory: slower, more exhaustive scan")
    g.add_argument("--yes", action="store_true",
                   help="auto-confirm prompts (installing Node for --history, scanning live memory)")

    g = p.add_argument_group("chain of custody")
    # NOTE: a plain flag, NOT nargs='?'. An optional-value option would swallow the PROFILE positional.
    g.add_argument("--audit", action="store_true",
                   help="record an audit database: every file touched, key derivation, network request, "
                        "artifact (with SHA-256) and error, crash-safe. One database per case, written "
                        "beside the output as wawf_audit.db.")
    g.add_argument("--audit-db", metavar="DB", help="path for the --audit database (default: beside the output)")
    g.add_argument("--audit-secrets", action="store_true",
                   help="with --audit, also store raw key material (default: only SHA-256 fingerprints "
                        "plus derivation parameters, so the log is not a secret store)")

    g = p.add_argument_group("diagnostics")
    g.add_argument("-v", "--verbose", action="store_true", help="DEBUG logs + full tracebacks on error")
    g.add_argument("--log-file", metavar="FILE", help="mirror all logs (DEBUG) to this file")

    a = p.parse_args()
    setup_logging(a.verbose, a.log_file)
    # Pick the action. The default IS the job: credentials -> key -> decrypt. --history and --memory are
    # the two alternative actions; everything else is an option on the default job.
    if a.memory or a.live or a.memimage:
        a.cmd, action = "memory", cmd_memory
    elif a.history:
        a.cmd, action = "history", cmd_history
    else:
        a.cmd, action = "decrypt", cmd_run
    global AUDIT
    if getattr(a, "audit", False) or getattr(a, "audit_db", None):   # --audit-db alone implies --audit
        AUDIT = audit.open_db(_audit_db_path(a), record_secrets=getattr(a, "audit_secrets", False))
        if AUDIT.enabled:
            AUDIT.start_run(a.cmd, sys.argv)
            # mirror EVERY log record (and any exc_info traceback) into the DB, so the trail is complete
            logging.getLogger().addHandler(AUDIT.logging_handler())
            log.info("audit: case %s  run %s  -> %s", AUDIT.case_id, AUDIT.run_id, AUDIT.path)
            if AUDIT.record_secrets:
                log.warning("--audit-secrets: raw key material WILL be stored in %s — protect it accordingly.",
                            AUDIT.path)
    t0 = time.time()
    rc, status, err, tb = 0, "ok", None, None
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
        log.debug("elapsed %.1fs", time.time() - t0)
        # record the outcome even on failure: a 'running' status left behind means the process was killed
        AUDIT.end_run(rc or 0, status=status, error=err, tb=tb)
        AUDIT.close()
    return rc or 0

if __name__ == "__main__":
    sys.exit(main())
