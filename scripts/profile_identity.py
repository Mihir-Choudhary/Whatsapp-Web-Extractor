#!/usr/bin/env python3
"""profile_identity.py — what a browser profile folder says about itself, wherever it was copied to.

A profile handed over as a bare folder has lost its place in the browser's `User Data` directory, and
the folder name may have been changed. Its contents still say where it came from:

  * browser      — files only one browser writes (`Edge Profile.ico`, `EdgeCoupons`, `Google Profile.ico`,
                   Brave/Opera/Vivaldi preference keys), or Firefox's own files;
  * version      — the last browser version that wrote it (`Preferences`, Firefox `compatibility.ini`);
  * display name — `Preferences` → profile.name. This is the label in the browser's profile picker,
                   NOT the folder name (they differ: a "Profile 8" folder can be labelled "Profile 9");
  * original path — every Chromium LevelDB writes a `LOG` beside it whose lines carry the absolute path
                   the database was opened at ("Creating DB C:\\...\\User Data\\Profile 8\\Local Storage\\
                   leveldb ..."). The LOG's own position inside the profile is known, so removing that
                   suffix leaves the profile's original location: OS user, browser install, folder name.

Everything is read, nothing is written. Each finding names the files it came from.
"""
from __future__ import annotations
import collections, datetime as dt, json, os, re, sys

_CHROMIUM_MARKERS = (
    ("Microsoft Edge", ("Edge Profile.ico", "EdgeCoupons", "EdgeHubAppUsage", "EdgeSessions")),
    ("Google Chrome", ("Google Profile.ico", "Google Profile Picture.png")),
    ("Brave", ("brave_rewards", "BraveWallet")),
    ("Opera", ("Opera Add-ons Downloads",)),
    ("Vivaldi", ("Vivaldi Profile.ico", "VivaldiSessions")),
)
_PREF_KEYS = (("Microsoft Edge", "edge"), ("Brave", "brave"), ("Opera", "opera"), ("Vivaldi", "vivaldi"))
_LOG_LINE = re.compile(r"^(\d{4}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\S+\s+(.*)$")


def _filetime_us(v):
    """Chromium stores times as microseconds since 1601-01-01 UTC."""
    try:
        v = int(v)
        return (dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=v)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _original_paths(profile, max_logs=400):
    """[(original profile path, first LOG timestamp, LOG file)] recovered from LevelDB LOG lines."""
    found = []
    seen = 0
    for dirpath, _dirs, files in os.walk(profile):
        for name in files:
            if name not in ("LOG", "LOG.old"): continue
            seen += 1
            if seen > max_logs: break
            rel = os.path.relpath(dirpath, profile)
            if rel == ".": continue
            suffix = rel.replace("/", "\\").lower()
            try:
                with open(os.path.join(dirpath, name), "rb") as f:
                    text = f.read(256 * 1024).decode("utf-8", "replace")
            except OSError:
                continue
            for line in text.splitlines():
                m = _LOG_LINE.match(line)
                if not m: continue
                body = m.group(2)
                norm = body.replace("/", "\\")
                i = norm.lower().find("\\" + suffix)
                if i <= 0: continue
                # the absolute path starts at the last drive letter (or a separator after a space)
                starts = list(re.finditer(r"[A-Za-z]:\\|(?<!\S)\\", norm[:i]))
                if not starts: continue
                path = body[starts[-1].start():i]
                if path:
                    found.append((path, m.group(1), os.path.join(rel, name)))
                break                                   # first path-bearing line per LOG is enough
    return found


def _given_stores(profile):
    """For stores given on their own (no profile folder): where each one originally lived, from its LOG."""
    f = os.path.join(profile, "wawf_parts.json")
    if not os.path.isfile(f): return None
    with open(f, encoding="utf-8") as fh:
        given = json.load(fh)
    out = {"given_stores": {}}
    dirs = []
    try:
        import chromium_reader as cr
        dirs += [cr.resolve_idb(d) or d for d in given.get("idb") or []]
    except ImportError:
        dirs += list(given.get("idb") or [])
    ls = given.get("local_storage")
    if ls:
        dirs.append(os.path.join(ls, "leveldb") if os.path.isdir(os.path.join(ls, "leveldb")) else ls)
    for d in dirs:
        try:
            with open(os.path.join(d, "LOG"), "rb") as fh:
                text = fh.read(256 * 1024).decode("utf-8", "replace")
        except OSError:
            out["given_stores"][d] = None; continue
        # anchor on the store's own folder name ("indexeddb.leveldb", "leveldb", ...) and walk back to the
        # drive letter -- paths contain spaces ("User Data", "Local Storage"), so no token split works
        tail = "\\" + os.path.basename(os.path.normpath(d)).lower()
        hit = None
        for line in text.splitlines():
            low = line.replace("/", "\\").lower()
            i = low.find(tail)
            if i < 0: continue
            starts = list(re.finditer(r"[A-Za-z]:\\", low[:i]))
            if starts:
                hit = line[starts[-1].start():i + len(tail)]
                break
        out["given_stores"][d] = hit
        if hit and "original_path" not in out:
            prof = re.split(r"[\\/](?:IndexedDB|WebStorage|Local Storage)[\\/]", hit)[0]
            if prof != hit:
                out["original_path"] = prof
                out["original_folder_name"] = re.split(r"[\\/]", prof)[-1]
                m2 = re.match(r"^[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\]+)\\", prof)
                if m2: out["os_user"] = m2.group(1)
                for b, needle in (("Microsoft Edge", "\\microsoft\\edge\\"), ("Google Chrome", "\\google\\chrome\\"),
                                  ("Brave", "bravesoftware"), ("Opera", "opera software"), ("Vivaldi", "\\vivaldi\\")):
                    if needle in prof.lower():
                        out["browser"], out["browser_evidence"] = b, ["install path in the store's LOG"]
                        break
    return out


def identify(profile: str) -> dict:
    out = {"folder": os.path.abspath(profile)}
    if not os.path.isdir(profile):
        return out
    given = _given_stores(profile)
    if given is not None:
        out.update(given)
        return out
    names = set(os.listdir(profile))
    # a Firefox origin folder (storage/default/https+++web.whatsapp.com), given on its own (--origin)
    if "idb" in names and (".metadata-v2" in names or "ls" in names):
        out["browser"], out["browser_evidence"] = "Mozilla Firefox", ["origin storage folder (idb/, ls/)"]
        up = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(profile))))
        if os.path.isfile(os.path.join(up, "prefs.js")) or os.path.isfile(os.path.join(up, "compatibility.ini")):
            prof = identify(up)
            out.update({k: v for k, v in prof.items() if k != "folder"})
            out["profile_folder"] = up
        return out
    if "prefs.js" in names or "places.sqlite" in names:
        out["browser"] = "Mozilla Firefox"
        out["browser_evidence"] = sorted(names & {"prefs.js", "places.sqlite", "compatibility.ini"})
        try:
            with open(os.path.join(profile, "compatibility.ini"), encoding="utf-8", errors="replace") as f:
                ini = dict(l.strip().split("=", 1) for l in f if "=" in l)
            out["version"] = ini.get("LastVersion", "").split("_")[0] or None
            if ini.get("LastPlatformDir"): out["install_dir"] = ini["LastPlatformDir"]
        except OSError:
            pass
        try:
            with open(os.path.join(profile, "times.json"), encoding="utf-8") as f:
                t = json.load(f).get("created")
            if t: out["created_utc"] = dt.datetime.fromtimestamp(t / 1000, dt.timezone.utc).isoformat()
        except (OSError, ValueError, TypeError):
            pass
        # Firefox names a profile folder "<random>.<name>" and keeps the folder name inside it nowhere;
        # what survives a rename is the name part only if the folder was not renamed.
        return out
    prefs = {}
    try:
        with open(os.path.join(profile, "Preferences"), encoding="utf-8") as f:
            prefs = json.load(f)
    except (OSError, ValueError):
        pass
    browser, evidence = None, []
    for b, files in _CHROMIUM_MARKERS:
        hit = sorted(names & set(files))
        if hit:
            browser, evidence = b, hit
            break
    if not browser:
        for b, key in _PREF_KEYS:
            if key in prefs:
                browser, evidence = b, [f"Preferences: '{key}' settings"]
                break
    if not browser and ("Preferences" in names or "IndexedDB" in names or "WebStorage" in names):
        browser, evidence = "Chromium-based (unidentified)", ["Chromium profile layout"]
    if browser:
        out["browser"], out["browser_evidence"] = browser, evidence
    p = prefs.get("profile") or {}
    out["version"] = (prefs.get("extensions") or {}).get("last_chrome_version") or p.get("created_by_version")
    out["display_name"] = p.get("name")
    out["created_utc"] = _filetime_us(p.get("creation_time"))
    paths = _original_paths(profile)
    if paths:
        cnt = collections.Counter(x[0] for x in paths)
        best, n = cnt.most_common(1)[0]
        out["original_path"] = best
        out["original_folder_name"] = re.split(r"[\\/]", best.rstrip("\\/"))[-1]
        m = re.match(r"^[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\]+)\\", best) or \
            re.match(r"^/(?:home|Users)/([^/]+)/", best)
        if m: out["os_user"] = m.group(1)
        out["original_path_evidence"] = {"logs_agreeing": n, "logs_with_a_path": len(paths),
                                         "earliest_log_line": min(x[1] for x in paths if x[0] == best),
                                         "example_log": next(x[2] for x in paths if x[0] == best)}
        others = [k for k in cnt if k != best]
        if others: out["other_paths_seen"] = others[:5]
        b = browser_from_path(best)
        if b and (not out.get("browser") or out["browser"].startswith("Chromium-based")):
            out["browser"], out["browser_evidence"] = b, ["install path in LevelDB LOG lines"]
    return out


_PATH_BROWSERS = (("Microsoft Edge", (r"\microsoft\edge", "/microsoft-edge", "/microsoft edge")),
                  ("Google Chrome", (r"\google\chrome", "/google-chrome", "/google/chrome")),
                  ("Brave", ("bravesoftware",)), ("Vivaldi", ("vivaldi",)), ("Opera", ("opera software", "/opera")),
                  ("Chromium", ("\\chromium\\", "/chromium/")), ("Arc", ("\\arc\\", "/arc/")),
                  ("Yandex", ("yandex",)))

def browser_from_path(path):
    """The browser a profile path belongs to, by its install folder; None when unrecognised."""
    low = (path or "").lower()
    for name, needles in _PATH_BROWSERS:
        if any(n in low for n in needles):
            return name
    return None


def summary(info: dict) -> str:
    """One line for a log or a window."""
    parts = [info.get("browser") or "unknown browser"]
    if info.get("version"): parts[-1] += " " + info["version"]
    if info.get("original_path"):
        parts.append("originally " + info["original_path"])
    if info.get("display_name") and info.get("display_name") != info.get("original_folder_name"):
        parts.append(f"labelled '{info['display_name']}' in the browser")
    return ", ".join(parts)


def browser_running(profile):
    """True if the browser that owns this profile is running (it holds its lock), False if not, None if
    unknown. Chromium family: <User Data>/lockfile (Windows, held open) or SingletonLock (Linux/macOS,
    'host-pid' link). Firefox: parent.lock in the profile (Windows) or its 'lock' link."""
    cands = [os.path.join(os.path.dirname(os.path.abspath(profile)), n) for n in ("lockfile", "SingletonLock")]
    cands += [os.path.join(profile, n) for n in ("parent.lock", "lock")]
    for p in cands:
        if os.path.islink(p):                       # 'host-pid'
            try:
                host, pid = os.readlink(p).rsplit("-", 1); pid = int(pid)
            except (ValueError, OSError):
                return None
            # The pid only means something on the machine that wrote the lock: a profile copied from
            # another machine names a process of THAT machine. And on Windows os.kill(pid, 0) is not a
            # probe -- it terminates whatever process has that number.
            import socket
            if sys.platform == "win32" or host != socket.gethostname():
                return None
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                return True                         # it exists, under another user
            except OSError:
                return None
        if os.path.isfile(p) and sys.platform == "win32":
            try:
                open(p, "rb").close()
                return False
            except PermissionError:
                return True
            except OSError:
                return None
    return None


def _is_chromium_dir(path):
    """A Chromium profile folder: legacy IndexedDB, or the WebStorage bucket layout."""
    return bool(path) and (os.path.isdir(os.path.join(path, "IndexedDB")) or os.path.isdir(os.path.join(path, "WebStorage")))

def has_whatsapp_storage(d):
    """Cheap test (no store is read): does this profile folder hold WhatsApp Web storage?"""
    if os.path.isdir(os.path.join(d, "storage", "default", "https+++web.whatsapp.com")):
        return True
    idb = os.path.join(d, "IndexedDB")
    if os.path.isdir(idb) and any(n.startswith("https_web.whatsapp.com") for n in os.listdir(idb)):
        return True
    if os.path.isdir(os.path.join(d, "WebStorage")):
        try:
            import chromium_reader as _cr
            return bool(_cr._quota_buckets(d))
        except ImportError:
            return True       # the bucket index names each bucket's site
    return False

def nested_profiles(root, depth=4):
    """Profile folders with WhatsApp Web storage under `root`, at most `depth` levels down."""
    out = []
    for cur, dirs, _ in os.walk(root):
        rel = os.path.relpath(cur, root)
        level = 0 if rel == "." else rel.count(os.sep) + 1
        if level > depth:
            dirs[:] = []; continue
        if level and (_is_chromium_dir(cur) or os.path.isdir(os.path.join(cur, "storage", "default"))) \
                and has_whatsapp_storage(cur):
            out.append(os.path.normpath(cur)); dirs[:] = []          # do not descend into a profile
    return sorted(out)


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        i = identify(p)
        print(summary(i))
        print(json.dumps(i, indent=1))
