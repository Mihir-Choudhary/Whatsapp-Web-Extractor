#!/usr/bin/env python3
"""idbutil.py — shared Firefox IndexedDB helpers.

Firefox assigns object_store ids in creation order, so they are per-profile and MUST NOT be
hardcoded. Look stores up by name instead.
"""
import logging, os, shutil, sqlite3, tempfile
from urllib.parse import quote

def sqlite_uri(path):
    """`path` as a file: URI that SQLite opens on every platform.

    Percent-encoded: a '#', '?' or '%' in a folder name is URI syntax otherwise, and a raw path in a
    URI was cut there -- a folder named `Case #12` made the query run against a file that is not the
    evidence. And with an empty authority (file:///C:/..., file:////server/share/...), so a path on a
    network share opens too: pathlib's as_uri() names the server as the URI's host, which SQLite
    refuses ("invalid uri authority"), and a raw path was not found at all.
    """
    p = os.path.abspath(path)
    if os.sep == "\\":
        p = p.replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p                                    # C:/x -> /C:/x
    return "file://" + quote(p, safe="/:")

def open_private(path, mode="w", encoding="utf-8"):
    """Open `path` for writing with permissions for its owner only (0600 on Linux and macOS).

    For the files that are key material, not evidence: creds_in.json (the device's Noise private key),
    companion_enc_static.txt (the at-rest key), the Signal state and the app-state keys. A plain open()
    creates them with the umask's mode, 0644 on most systems -- readable by every user of a shared
    examination machine. A file that already exists is tightened too, since O_CREAT keeps its old mode.
    On Windows the mode only sets the read-only bit, which 0600 leaves clear.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return os.fdopen(fd, mode, encoding=None if "b" in mode else encoding)

def connect_ro(path):
    """Open one of the evidence's SQLite files without writing to it -- INCLUDING its write-ahead log.

    Firefox keeps IndexedDB and localStorage in WAL mode, so until a checkpoint the newest writes (on
    a profile copied from a running or crashed browser: the newest messages) exist only in
    `<file>-wal`. `immutable=1` ignores that file entirely -- measured: 5 rows in the log, 0 read.
    When a log is present, the file and its log are copied to a private temporary folder, read into
    memory, and the copy is deleted at once; the evidence itself is never opened for writing. (A
    plain `mode=ro` open is not an option: on a WAL database it creates -shm and -wal files beside
    the evidence.) If the copy cannot be made, the file is read as it is and the log says what that
    leaves out.
    """
    wal = path + "-wal"
    if os.path.isfile(wal) and os.path.getsize(wal) > 0:
        d = tempfile.mkdtemp(prefix="wawf_wal_")
        try:
            shutil.copyfile(path, os.path.join(d, "db"))
            shutil.copyfile(wal, os.path.join(d, "db-wal"))
            src = sqlite3.connect(os.path.join(d, "db"))
            try:
                mem = sqlite3.connect(":memory:")
                src.backup(mem)
            finally:
                src.close()
            return mem
        except (OSError, sqlite3.Error) as e:
            logging.getLogger("wawf.idb").warning(
                "%s: its write-ahead log could not be read (%s); rows that are only in the log are not "
                "included", path, e)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return sqlite3.connect(sqlite_uri(path) + "?mode=ro&immutable=1", uri=True)

def store_id(conn, name):
    """Return the object_store id for `name` in a Firefox IndexedDB .sqlite, or None if absent."""
    return {n: i for i, n in conn.execute("SELECT id,name FROM object_store")}.get(name)

def as_bytes(x):
    """Coerce an IndexedDB value to bytes across engines: raw bytes, latin-1 str (Firefox),
    list/tuple, {'__bytes'/'__bytes__'} wrappers, or a ccl Chromium CryptoKey (.key_data)."""
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, str): return x.encode('latin-1', 'ignore')
    if isinstance(x, (list, tuple)):
        try: return bytes(x)
        except Exception: return None
    if isinstance(x, dict):
        for k in ('__bytes', '__bytes__'):
            if k in x: return bytes(x[k])
    if hasattr(x, 'key_data'): return bytes(x.key_data)
    return None
