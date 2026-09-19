#!/usr/bin/env python3
"""wawf — WhatsApp Web Forensics: one CLI for Firefox + Chromium (Chrome/Edge/Brave/Opera).

A single tool (PyInstaller-packageable to a .exe) that decrypts and exports WhatsApp Web from a
browser profile. Global -v/--verbose surfaces DEBUG logs and full tracebacks; --log-file mirrors
everything to a file.

Subcommands:
  decrypt   <profile|--origin> [--enc-static]  decrypt WhatsApp bodies (or offline inventory)
  creds     <profile|--origin> [--out]         recover reconnect creds (Noise key + account id)
  reconnect <profile|--origin|--creds>         log back in (pure-Python Noise) -> companion_enc_static
  history   <profile|--origin>                  pull ALL chat history older than the cache from WA (needs Node)
  memory    (--live|--memimage F) [--deep]     find companion_enc_static in RAM/swap/hiberfil/process
  sqlite    <profile|--origin> --enc-static    export decrypted chats to a SQLite DB (msgstore.db + wa.db)

Examples:
  wawf decrypt ~/.config/google-chrome/Default --enc-static <b64> --out out/ -v
  wawf decrypt --origin .../storage/default/https+++web.whatsapp.com --enc-static <b64>
"""
from __future__ import annotations
import argparse, sys, os, json, base64, logging, collections, datetime as dt, subprocess, time

HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # _MEIPASS when frozen (.exe)
sys.path.insert(0, os.path.join(HERE, "scripts")); sys.path.insert(0, HERE)
log = logging.getLogger("wawf")

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

# ---------------- subcommands ----------------
def _load_wa(a):
    WD, _ = _imp()
    if not getattr(a, "profile", None) and not getattr(a, "origin", None):
        raise SystemExit("pass a profile dir (Firefox/Chromium) or --origin <Firefox web.whatsapp.com dir>")
    engine, ls, root, msgs, meta = WD.load(getattr(a, "profile", None), getattr(a, "origin", None))
    log.info("engine=%s  messages=%d  root_key=%s  ls_keys=%d", engine, len(msgs), "yes" if root else "NO", len(ls))
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

def cmd_decrypt(a):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    WD, engine, ls, root, msgs, meta = _load_wa(a)
    _summary(engine, ls, msgs, meta)
    salt_ws = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    sch = collections.Counter(m["scheme"] for m in msgs if m["data"])
    log.info("message schemes: %s", dict(sch))
    if not a.enc_static:
        log.info("no --enc-static: offline inventory only. Message TEXT needs companion_enc_static "
                 "(memory or reconnect). Media keys/metadata are already on disk.")
        return 0
    key = HKDF(algorithm=hashes.SHA256(), length=16, salt=base64.b64decode(a.enc_static), info=salt_ws).derive(root)
    def strict(b): return bool(b) and len(b) % 16 == 0 and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]])*b[-1]
    refs = [m for m in msgs if m["data"] and m["scheme"] == 1][:40]; good = 0   # scheme-1 only
    for m in refs:
        try:
            if strict(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"])): good += 1
        except Exception as e: log.debug("ref decrypt error: %s", e)
    if refs and good < len(refs) * 0.5:
        log.error("companion_enc_static INVALID for this profile/device (%d/%d refs validate). Not writing garbage.", good, len(refs))
        return 3
    log.info("companion_enc_static VALIDATED (%d/%d reference messages)", good, len(refs))
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
    json.dump(chats, open(f"{a.out}/chats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    with open(f"{a.out}/transcripts.txt", "w", encoding="utf-8") as f:  # message text has emoji/non-Latin -> pin UTF-8 (Windows default is cp1252)
        for c, ml in sorted(chats.items(), key=lambda kv: -len(kv[1])):
            tm = [m for m in ml if m["text"]]
            if not tm: continue
            f.write(f"\n===== {c} ({len(ml)} msgs, {len(tm)} text) =====\n")
            for m in ml:
                if m["text"]: f.write(f"[{m['t']}] {m['dir']:>4}: {m['text']}\n")
    log.info("decrypted %d bodies (%d failed) -> %s/ (chats.json + transcripts.txt)", ok, fail, a.out)
    return 0

def cmd_creds(a):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    _, BC = _imp()
    if a.origin: ls, root, meta = BC.load_firefox(a.origin)
    elif a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")): ls, root, meta = BC.load_chromium(a.profile)
    elif a.profile: ls, root, meta = BC.load_firefox(os.path.join(a.profile, "storage/default/https+++web.whatsapp.com"))
    else: log.error("pass a profile or --origin"); return 2
    salt = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    K = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"\x00").derive(root)
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
    if not priv: log.error("could not recover/verify the Noise keypair"); return 3
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
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    abs_out = os.path.abspath(a.out)
    log.info("Noise keypair VERIFIED (X25519). reg_id=%s device=:%s account=%s -> %s",
             int(regid) if regid is not None else "?", dev, "present" if adv else "MISSING", abs_out)
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
    return subprocess.run(cmd).returncode

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
        if not a.profile and not a.origin:
            log.error("pass a profile or --origin (to recover creds), or --creds <existing creds_in.json>")
            return 2
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
        key = open(a.out).read().strip()
        log.info("companion_enc_static captured (%d chars) -> %s", len(key), os.path.abspath(a.out))
        log.info("next:  wawf decrypt <profile> --enc-static %s --out out/", key)
    return rc

def _deepen_anchors(anchors_path, master):
    """Re-anchor each chat on the OLDEST message recovered so far and add all recovered ids to the
    on-disk set, so the next history pass continues further back instead of re-pulling the same window."""
    a = json.load(open(anchors_path))
    ondisk = set(a["ondisk_ids"]); by = {x["chat"]: x for x in a["anchors"]}
    oldest = {}
    for m in master.values():
        if m.get("id"): ondisk.add(m["id"])
        c = m.get("chat"); ts = m.get("ts", 0)
        if not c or not m.get("id") or ts <= 0: continue   # ts<=0 (stubs) can't anchor fetchMessageHistory
        cur = oldest.get(c)
        if cur is None or ts < cur["oldest_ts"]:
            oldest[c] = {"chat": c, "oldest_id": m["id"], "oldest_ts": ts, "oldest_fromMe": bool(m.get("fromMe"))}
    for c, x in oldest.items(): by[c] = x
    # continue the chats we just went deeper on first, then the rest
    newanchors = list(oldest.values()) + [x for c, x in by.items() if c not in oldest]
    tmp = anchors_path + ".tmp"                            # atomic write: a failed/interrupted write must not
    with open(tmp, "w") as f: json.dump({"anchors": newanchors, "ondisk_ids": sorted(ondisk)}, f)  # corrupt
    os.replace(tmp, anchors_path)                          # the anchors.json the node client reads next pass

def _resume_master(accum, anchors_path, master):
    """Reload messages recovered on prior `wawf history` runs (from the accumulated ledger) into `master`
    and push the freshly-built anchors past them, so a new run continues older than prior runs instead of
    re-requesting the same window. Returns how many prior messages were reloaded (0 if none / on error)."""
    if not os.path.exists(accum): return 0
    try:
        for m in (json.load(open(accum)).get("messages") or []):
            if m.get("id"): master[m["id"]] = m
        if master: _deepen_anchors(anchors_path, master)
        return len(master)
    except Exception as e:
        log.warning("could not reload prior history (%s) — starting fresh.", e)
        return 0

def cmd_history(a):
    """On-demand history sync: pull messages OLDER than the browser cache from WhatsApp's servers, per
    chat, going back toward each chat's start — ITERATIVELY: each pass re-anchors on the oldest message
    recovered so far and pulls deeper, accumulating (deduped) until it converges. Recovers creds + Signal
    state + anchors (pure Python) then runs the Node/Baileys extractor. NEEDS Node + `npm install` in
    tools/reconnect — the Signal/E2E stack isn't ported to Python, so this isn't in the .exe."""
    import shutil
    rec = os.path.join(HERE, "tools", "reconnect")
    if getattr(sys, "frozen", False) or not os.path.isdir(rec):
        log.error("history sync needs the repo's Node client (tools/reconnect) — it is NOT in the .exe. "
                  "Clone the repo and run `wawf history` from source (with Node installed).")
        return 2
    if not shutil.which("node"):
        log.error("Node.js not found on PATH — install Node.js, then `cd tools/reconnect && npm install`."); return 2
    if not os.path.isdir(os.path.join(rec, "node_modules")):
        log.error("tools/reconnect/node_modules missing — run `cd tools/reconnect && npm install` once first."); return 2
    # engine args shared by creds / signal-state / anchors
    if a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")):
        eng = ["--profile", a.profile]
    else:
        origin = a.origin or (os.path.join(a.profile, "storage/default/https+++web.whatsapp.com") if a.profile else None)
        if not origin: log.error("pass a profile or --origin"); return 2
        eng = ["--origin", origin]
    log.info("[1/4] recovering reconnect creds ...")
    if cmd_creds(argparse.Namespace(profile=a.profile, origin=a.origin, out=os.path.join(rec, "creds_in.json"), _internal=True)):
        return 3
    log.info("[2/4] recovering Signal state (identity + prekeys) ...")
    if _sub("export_signal_state.py", eng + ["--out", os.path.join(rec, "signal_state.json")]): return 3
    log.info("[3/4] building anchors from on-disk messages ...")
    if _sub("build_anchors.py", eng + ["--out", os.path.join(rec, "anchors.json")]): return 3
    log.warning("[4/4] NETWORKED iterative history sync — logs in as your linked device and asks your phone, "
                "chat by chat, for messages older than the cache, re-anchoring deeper each pass until the "
                "phone's retained history is drained. Own account / authorized use only; this can take many "
                "minutes and repeated passes.")
    env = dict(os.environ, TOP="100000", COUNT="50", MAXPAGES="100000")   # every chat, page until exhausted
    anchors_path = os.path.join(rec, "anchors.json")
    pass_out = os.path.join(rec, "history_recovered.json")   # human-facing final output (full accumulated set)
    accum = os.path.join(rec, "history_all.json")            # resume ledger, accumulated across ALL runs
    master = {}                                              # msg id -> msg (dedup across passes AND runs)

    def _checkpoint(path):
        by = collections.Counter(m.get("chat") for m in master.values())
        tmp = path + ".tmp"                                  # atomic write: never leave a half-written file
        json.dump({"recovered_total": len(master), "new_not_on_disk": len(master),
                   "by_chat": dict(by), "messages": list(master.values())}, open(tmp, "w"))
        os.replace(tmp, path)
        return by

    # RESUME across separate `wawf history` runs: step [3/4] just rebuilt anchors.json fresh from what's on
    # disk (i.e. back at the browser-cache boundary), so reload everything recovered on prior runs and push
    # the anchors + on-disk id set past it — otherwise run 2 would re-request run 1's window and overwrite it.
    n = _resume_master(accum, anchors_path, master)
    if n: log.info("resuming: %s messages recovered on prior runs — continuing older than those.", f"{n:,}")

    MIN_NEW, MAX_PASSES = 40, 25                             # stop when a pass adds < MIN_NEW; hard safety cap
    got_output = False
    try:
        for p in range(1, MAX_PASSES + 1):
            log.info("──── history pass %d ────", p)
            if os.path.exists(pass_out): os.remove(pass_out)   # else a node failure re-reads a stale pass as "new"
            rc = subprocess.run(["node", "history_extract.js"], cwd=rec, env=env).returncode
            try: passd = json.load(open(pass_out))
            except Exception:
                log.error("pass %d produced no output (node exit=%s; connection failed / phone not serving) "
                          "— stopping.", p, rc); break
            got_output = True
            new = 0
            for m in (passd.get("messages") or []):
                i = m.get("id")
                if i and i not in master: master[i] = m; new += 1
            by = _checkpoint(accum)                          # checkpoint the accumulated set every pass
            log.info("pass %d: +%d new  ·  total recovered: %d across %d chats", p, new, len(master), len(by))
            if new < MIN_NEW:
                log.info("converged — last pass added < %d new messages. Stopping.", MIN_NEW); break
            _deepen_anchors(anchors_path, master)            # go deeper next pass
    except KeyboardInterrupt:
        log.warning("interrupted — checkpointing %s recovered messages before exit.", f"{len(master):,}")
        _checkpoint(accum); _checkpoint(pass_out); raise

    by = _checkpoint(pass_out); _checkpoint(accum)           # final full accumulated set -> both files
    log.info("HISTORY DONE: recovered %s messages older than the cache, across %d chats -> %s",
             f"{len(master):,}", len(by), pass_out)
    if not got_output and not master:
        log.error("no history recovered (phone not serving / connection failed). Retry when your phone is "
                  "online and active."); return 1
    return 0

def cmd_sqlite(a):
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

def main():
    # frozen dispatch: `<exe> _runpy <script.py> [args...]` runs a bundled helper in-process
    # (a onefile binary cannot exec a loose .py; the helper's own __main__ runs via runpy).
    if getattr(sys, "frozen", False) and len(sys.argv) >= 3 and sys.argv[1] == "_runpy":
        import runpy
        path = os.path.join(HERE, "scripts", sys.argv[2])
        sys.argv = [path] + sys.argv[3:]
        runpy.run_path(path, run_name="__main__")
        return 0
    p = argparse.ArgumentParser(prog="wawf", description="WhatsApp Web Forensics (Firefox + Chromium)")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG logs + full tracebacks on error")
    p.add_argument("--log-file", help="mirror all logs (DEBUG) to this file")
    sub = p.add_subparsers(dest="cmd", required=True)
    def prof_args(sp, origin=True):
        sp.add_argument("profile", nargs="?", help="browser profile dir (Firefox .default or Chromium Default)")
        if origin: sp.add_argument("--origin", help="Firefox web.whatsapp.com storage dir (alternative to profile)")
    _ENC = "companion_enc_static (base64) — the at-rest key; get it from `memory` or `reconnect`"
    s = sub.add_parser("decrypt", help="decrypt chats to transcripts.txt + chats.json (no key = offline inventory)",
                       description="Decrypt WhatsApp Web chats to transcripts.txt + chats.json. Without --enc-static "
                       "it prints an offline inventory (counts, date range, contacts) and decrypts no message text.")
    prof_args(s); s.add_argument("--enc-static", help=_ENC + " (omit for offline inventory only)")
    s.add_argument("--out", default="wa_decrypted", help="output dir for transcripts.txt + chats.json (default: wa_decrypted)")
    s.set_defaults(fn=cmd_decrypt)
    # when frozen (.exe) HERE is a temp extraction dir that's deleted on exit -> write creds to CWD instead
    _creds_out = "creds_in.json" if getattr(sys, "frozen", False) else os.path.join(HERE, "tools/reconnect/creds_in.json")
    s = sub.add_parser("creds", help="recover + verify reconnect credentials (Noise key + account identity)",
                       description="Recover and verify the reconnect credentials (Noise X25519 keypair + account "
                       "identity) from disk. Read-only; writes creds_in.json for `reconnect`/history. No message text.")
    prof_args(s); s.add_argument("--out", default=_creds_out, help="where to write creds_in.json")
    s.set_defaults(fn=cmd_creds)
    s = sub.add_parser("reconnect", help="log back in (pure-Python Noise) and capture companion_enc_static",
                       description="Log back in as the linked companion device via the pure-Python Noise handshake "
                       "and capture companion_enc_static. NETWORKED — own account / authorized use only.")
    prof_args(s); s.add_argument("--creds", help="existing creds_in.json (skip creds recovery)")
    s.add_argument("--out", default="companion_enc_static.txt", help="where to write the captured key (default: companion_enc_static.txt)")
    s.set_defaults(fn=cmd_reconnect)
    s = sub.add_parser("history", help="pull chat history older than the browser cache from your phone (needs Node)",
                       description="Iteratively pull messages older than the browser cache from WhatsApp's servers, "
                       "per chat, re-anchoring deeper each pass and accumulating (deduped) across passes AND separate "
                       "runs until it converges. NETWORKED; needs Node + tools/reconnect (npm install); not in the .exe.")
    prof_args(s); s.set_defaults(fn=cmd_history)
    s = sub.add_parser("memory", help="find companion_enc_static in RAM / swap / hibernation",
                       description="Recover companion_enc_static from volatile memory (live process, RAM/swap dump, or "
                       "hibernation file). Live scanning of another process's memory typically needs elevated privileges.")
    s.add_argument("--live", action="store_true", help="scan the running browser's memory on this machine")
    s.add_argument("--memimage", help="scan a memory image file (RAM dump / swap / hibernation) instead of live RAM")
    s.add_argument("--deep", action="store_true", help="slower, more exhaustive scan")
    s.add_argument("--enc-static", help="verify this candidate key against on-disk ciphertext instead of scanning")
    s.add_argument("--origin", help="Firefox web.whatsapp.com storage dir (to validate a found key)")
    s.add_argument("--yes", action="store_true", help="skip the confirmation prompt for scanning live memory")
    s.set_defaults(fn=cmd_memory)
    s = sub.add_parser("sqlite", help="export decrypted chats to Android msgstore.db + wa.db (needs key)",
                       description="Export decrypted chats to an Android-style SQLite database (msgstore.db + wa.db). "
                       "Requires --enc-static. Firefox (--origin) and Chromium (profile) both supported.")
    prof_args(s); s.add_argument("--enc-static", required=True, help=_ENC)
    s.add_argument("--out", default="wa_sqlite", help="output dir for msgstore.db + wa.db (default: wa_sqlite)")
    s.set_defaults(fn=cmd_sqlite)
    a = p.parse_args()
    setup_logging(a.verbose, a.log_file)
    t0 = time.time()
    try:
        rc = a.fn(a)
    except SystemExit as e:
        log.error("%s", e); return int(e.code) if isinstance(e.code, int) else 1
    except FileNotFoundError as e:
        log.error("file not found: %s", e); (a.verbose and log.exception("traceback")); return 4
    except Exception as e:
        log.error("%s: %s", type(e).__name__, e)
        log.exception("traceback") if a.verbose else log.error("(re-run with -v for the full traceback)")
        return 1
    finally:
        log.debug("elapsed %.1fs", time.time() - t0)
    return rc or 0

if __name__ == "__main__":
    sys.exit(main())
