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
  --memory (--live|--memimage)  hunt the at-rest key in RAM / swap / hibernation

Examples:
  wawf "C:\\Users\\<you>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
  wawf <PROFILE> --out sqlite:D:\\case\\db --out txt:D:\\case\\out
  wawf <PROFILE> --key companion_enc_static.txt --out json:D:\\case --audit
"""
from __future__ import annotations
import argparse, sys, os, re, json, base64, logging, collections, datetime as dt, subprocess, time

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

_OUT_FORMATS = ("txt", "json", "sqlite", "db", "raw")

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
    engine, ls, root, msgs, meta, ids = WD.load(getattr(a, "profile", None), getattr(a, "origin", None))
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
    return WD, engine, ls, root, msgs, meta, ids

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
    if not key:
        log.info("[2/3] reconnecting as the linked device to capture the at-rest key (NETWORKED) ...")
        keyfile = os.path.join(workdir, KEY_FILENAME)
        rc = cmd_reconnect(argparse.Namespace(profile=a.profile, origin=a.origin, creds=creds_path,
                                              out=keyfile, verbose=a.verbose))
        if rc:
            log.error("could not capture the at-rest key, so there is nothing to decrypt with. "
                      "Point --key at a companion_enc_static.txt captured earlier, or recover the key from "
                      "memory with --memory.")
            return rc
        key = _read_key_file(keyfile)
        if not key:
            return 3
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
            if fmt == "sqlite":
                rc = cmd_sqlite(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k, out=path))
            elif fmt == "raw":
                rc = cmd_raw(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k, out=path,
                                                raw_include_keys=getattr(a, "raw_include_keys", False)))
            else:
                rc = cmd_decrypt(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=k,
                                                    out=path, only=fmt))
            if rc:
                return rc
        return 0

    if guessed:
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
    for fmt, path in outs:
        if fmt == "sqlite":
            rc = cmd_sqlite(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key, out=path))
        elif fmt == "raw":
            rc = cmd_raw(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key, out=path,
                                            raw_include_keys=getattr(a, "raw_include_keys", False)))
        else:
            rc = cmd_decrypt(argparse.Namespace(profile=a.profile, origin=a.origin, enc_static=key,
                                                out=path, only=fmt))
        if rc: return rc
    return 0

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
    b = None
    try:
        b = _ab(o)
    except Exception:
        b = None
    if b:
        return {"__bytes__": base64.b64encode(bytes(b)).decode(), "len": len(bytes(b))}
    return {"__repr__": repr(o)[:400]}


# Stores holding key material rather than evidence. A raw dump is meant to travel with a case, and
# these would turn it into a copy of the account's Signal keys and the at-rest root key.
_RAW_SKIP_DBS = ("signal-storage", "wawc_db_enc")


def cmd_raw(a):
    """--out raw:DIR -- decrypt, and change NOTHING else.

    Every other output reshapes: the text writer scrapes strings out of the decrypted protobuf with a
    heuristic walker, dedupes them and truncates at 2000 characters, so field identity and every
    non-string field are lost. This one emits each record as the browser stored it -- a JavaScript
    object, same field names, same "<Undefined>" markers, nothing renamed or dropped -- and ADDS the
    decrypted payload beside the original rather than in place of it:

        _wawf_plaintext_b64     the decrypted bytes verbatim, so the decryption can be re-checked
        _wawf_plaintext_fields  the same bytes as a schema-free protobuf field tree

    The encrypted msgRowOpaqueData stays exactly where it was, so the file remains a faithful image of
    the store plus a decryption, and never a substitute for it. One JSONL file per object store.
    """
    _require_source(a, "raw")
    if a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
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
            manifest.append({"database": db, "store": st, "file": safe + ".jsonl",
                             "records": n, "encrypted": enc, "decrypted": dec})
            AUDIT.artifact(path, kind=f"raw store dump ({db}/{st})", records=n)
    json.dump({"format": "wawf-raw/1", "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
               "profile": os.path.abspath(a.profile) if a.profile else None,
               "decryption": "AES-CBC-128, HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt)",
               "note": "records are verbatim as stored; _wawf_plaintext_* fields are ADDED, "
                       "msgRowOpaqueData is left untouched",
               "markers": {"__bytes__": "base64 of a binary value, with its length",
                           "__undefined__": "JavaScript undefined, which JSON cannot express and "
                                            "which is NOT the same as null",
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
    salt_ws = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    sch = collections.Counter(m["scheme"] for m in msgs if m["data"])
    log.info("message schemes: %s", dict(sch))
    if not a.enc_static:
        log.info("no at-rest key available: offline inventory only. Message TEXT needs companion_enc_static "
                 "(memory or reconnect). Media keys/metadata are already on disk.")
        return 0
    enc_static = base64.b64decode(a.enc_static)
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
    chats = collections.defaultdict(list); ok = fail = 0
    for m in msgs:
        if not m["data"] or m["scheme"] != 1: continue   # scheme-1 only; skip scheme-0 (would be garbage)
        # CBC consumes whole blocks: update() on a ciphertext that is not a multiple of 16 returns the
        # blocks it could and silently buffers the tail, so a truncated record decrypts to a SHORT
        # plaintext and is still counted as a success. Count it as what it is. None of the 22,121
        # bodies in the reference profile are misaligned; this is about the counts staying truthful
        # on a damaged store, which is exactly the case where they are what is being measured.
        if len(m["data"]) % 16:
            fail += 1; log.debug("misaligned body %s: %d bytes", m["id"][:24], len(m["data"])); continue
        try: pt = WD.pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception as e: fail += 1; log.debug("decrypt fail %s: %s", m["id"][:24], e); continue
        chats[m["chat"]].append(WD.msg_row(m, ts(m["t"]), pt, ids))
        ok += 1
    for c in chats: chats[c].sort(key=lambda x: x["t"])
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
    if only == "json":
        log.info("decrypted %d bodies (%d failed) -> %s/ (chats.json + identities.json)", ok, fail, a.out)
        AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=ok)
        return 0
    WD.write_transcripts(f"{a.out}/transcripts.txt", chats, ids)
    # name what was actually written: with --out txt:PATH the JSON side is skipped, and a log line
    # that lists files that are not there is a log line that gets believed
    wrote = "transcripts.txt" if only == "txt" else "chats.json + identities.json + transcripts.txt"
    log.info("decrypted %d bodies (%d failed) -> %s/ (%s)", ok, fail, a.out, wrote)
    # outcome of the bulk decrypt + hashes of what was produced (so the exports are tamper-evident)
    AUDIT.crypto("decrypt", algorithm="AES-CBC-128", scheme="1 (final)", key=key,
                 input_desc="all scheme-1 msgRowOpaqueData bodies", records_in=ok + fail,
                 records_ok=ok, records_failed=fail, detail={"chats": len(chats)})
    # only record artifacts that were actually produced: with --out txt:PATH there is no chats.json,
    # and a custody record asserting a file that does not exist is worse than no record
    if only != "txt":
        AUDIT.artifact(f"{a.out}/chats.json", kind="decrypted chats (JSON)", records=ok)
    AUDIT.artifact(f"{a.out}/transcripts.txt", kind="decrypted transcripts (text)", records=ok)
    return 0

def _wa_user_prefs(profile, origin):
    """Read WhatsApp Web's own `model-storage/user-prefs` key/value store off the profile.

    This is a different store from the one the credential export reads (`wawc/user`), and it holds
    the client's self-description: the build it runs, its edge routing, the feature list its phone
    advertised. Exception-safe by design -- every caller treats a missing value as "fall back to the
    old behaviour", so a profile shape we have not seen degrades instead of failing.
    """
    try:
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
    # The scan finds candidate keys in RAM and then VALIDATES each against ciphertext from the
    # profile -- and that reader is the Firefox one (`idb/*.sqlite`). Given a Chromium profile there
    # is nothing to validate against, and the child reported "Could not locate a Firefox WhatsApp
    # Web profile; pass --origin or --profile", which reads like the path was wrong when the real
    # answer is that this mode does not cover that engine. Said here, before spawning anything.
    if getattr(a, "profile", None) and not getattr(a, "origin", None) \
            and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
        log.error("the memory scan validates candidate keys against a FIREFOX WhatsApp Web store, "
                  "and that is a Chromium profile. Either point --origin at a Firefox "
                  "storage/default/https+++web.whatsapp.com folder, or just run `wawf <PROFILE>`, "
                  "which captures the key over the network instead.")
        return 2
    extra = []
    if a.live: extra.append("--live")
    if a.memimage: extra += ["--memimage", a.memimage]
    if a.deep: extra.append("--deep")
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
    log.warning("FOR THE BEST CHANCE: keep WhatsApp open on your phone with a stable network, and "
                "CLOSE every web.whatsapp.com tab -- a live web session competes for the same linked "
                "device. If a run comes back empty, do not immediately retry: that burns the failure "
                "budget and extends the quiet window. Run tools/reconnect/diag_onehistory.js instead, "
                "which sends ONE request and reports whether the server acknowledged it, so a throttle "
                "is distinguishable from a refusal.")
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
    extra = ["--out", a.out]
    if a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
        extra += ["--profile", a.profile]          # Chromium (Chrome/Edge/Brave/Opera)
    else:
        origin = a.origin
        if not origin and a.profile:               # a Firefox profile dir -> derive its origin storage dir
            cand = os.path.join(a.profile, "storage/default/https+++web.whatsapp.com")
            if os.path.isdir(cand): origin = cand
        if origin: extra += ["--origin", origin]
    return _sub("export_sqlite.py", extra, secret_env={"WAWF_ENC_STATIC": a.enc_static})

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
        "  --history             instead of decrypting, pull chat history OLDER than the browser\n"
        "                        cache from your phone (networked, needs Node; phone must answer)\n"
        "  --memory --live       instead of reconnecting, hunt the key in RAM/swap/hibernation\n"
        "  --audit               write a chain-of-custody database beside the output\n"
        "\n"
        "EXAMPLES\n"
        "  wawf \"" + _example_profile() + "\"\n"
        "  wawf \"" + _example_profile() + "\" --out sqlite:D:\\case\\db\n"
        "  wawf \"" + _example_profile() + "\" --key companion_enc_static.txt --out json:D:\\case --audit\n"
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
