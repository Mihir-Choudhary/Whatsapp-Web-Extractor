#!/usr/bin/env python3
"""audit.py — optional chain-of-custody / audit database for wawf.

Enabled with `wawf --audit` (see wawf.py). When on, EVERY run of the tool appends to one SQLite DB that
lives next to the output, so an examiner can reconstruct exactly what the tool did: which files it opened,
what it took out of them, which key material derived what, which network requests went out, what artifacts
were produced (with hashes), and — if the tool crashed — the last thing it was doing plus the traceback.

Design notes that matter for forensics:
  * ONE DB PER CASE, never a global one. The DB is created in the output directory, so each case/output
    directory accumulates only its own history. Re-running appends a new `run` row to the same case DB.
  * CRASH-SAFE. Autocommit (isolation_level=None) + WAL + synchronous=FULL, so every row is durable the
    moment it is written. A hard crash or kill still leaves the log up to the last completed statement:
    the final `event` row tells you where it stopped, and `run.status` stays 'running' if it never finished.
  * MULTI-PROCESS. wawf shells out to helper scripts (export_sqlite, build_anchors, wa_reconnect, ...) and
    to node. Children pick the DB up from the WAWF_AUDIT_DB env var via from_env() and write to the same
    file; WAL + a busy timeout make that safe.
  * SECRETS. Key MATERIAL is recorded as a SHA-256 fingerprint plus the derivation parameters (KDF, salt
    source, info, lengths, scheme), never as the raw key. That is enough to prove which key produced which
    plaintext and to match a key you hold, without turning the audit log into a secret store. Pass
    record_secrets=True (wawf --audit-secrets) if your process genuinely requires the raw values.
  * A no-op object is returned when auditing is off, so call sites never need `if audit:` guards.
"""
from __future__ import annotations
import os, sys, json, sqlite3, hashlib, logging, datetime, platform, getpass, time

SCHEMA_VERSION = 1
ENV_DB, ENV_RUN, ENV_SECRETS = "WAWF_AUDIT_DB", "WAWF_AUDIT_RUN", "WAWF_AUDIT_SECRETS"

def _utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _js(x):
    if x is None: return None
    try: return json.dumps(x, default=str, ensure_ascii=False)
    except Exception: return json.dumps(str(x))

def sha256_file(path, cap=None):
    """SHA-256 of a file (evidence integrity). Returns (hexdigest, size) or (None, size) if unreadable."""
    h, n = hashlib.sha256(), 0
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b: break
                h.update(b); n += len(b)
                if cap and n > cap: return None, n          # too big to hash under the cap
        return h.hexdigest(), n
    except Exception:
        try: return None, os.path.getsize(path)
        except Exception: return None, None

def fp(data):
    """Fingerprint key/salt material: SHA-256 hex, truncated. Never the material itself."""
    if data is None: return None
    if isinstance(data, str): data = data.encode("utf-8", "replace")
    try: return hashlib.sha256(bytes(data)).hexdigest()
    except Exception: return None

_DDL = """
CREATE TABLE IF NOT EXISTS case_info(
  case_id TEXT, created_utc TEXT, tool TEXT, tool_version TEXT, schema_version INTEGER);
CREATE TABLE IF NOT EXISTS run(
  run_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, command TEXT, argv TEXT,
  started_utc TEXT, finished_utc TEXT, exit_code INTEGER, status TEXT,
  error_type TEXT, error_message TEXT, traceback TEXT,
  tool_version TEXT, frozen INTEGER, executable TEXT, python TEXT, platform TEXT,
  hostname TEXT, os_user TEXT, cwd TEXT, pid INTEGER, parent_run_id INTEGER);
CREATE TABLE IF NOT EXISTS event(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts_utc TEXT, elapsed_s REAL,
  level TEXT, category TEXT, logger TEXT, message TEXT, detail TEXT,
  module TEXT, lineno INTEGER, traceback TEXT);
CREATE TABLE IF NOT EXISTS file_access(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts_utc TEXT, action TEXT,
  path TEXT, purpose TEXT, present INTEGER, size INTEGER, mtime_utc TEXT,
  sha256 TEXT, records INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS crypto_op(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts_utc TEXT, op TEXT,
  algorithm TEXT, kdf TEXT, scheme TEXT, key_source TEXT, key_fp TEXT, key_len INTEGER,
  key_secret TEXT, salt_source TEXT, salt_fp TEXT, info TEXT,
  input_desc TEXT, records_in INTEGER, records_ok INTEGER, records_failed INTEGER,
  validated TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS network_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts_utc TEXT, direction TEXT,
  protocol TEXT, endpoint TEXT, kind TEXT, status TEXT, bytes INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS artifact(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts_utc TEXT, path TEXT, kind TEXT,
  size INTEGER, sha256 TEXT, records INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_event_run ON event(run_id, event_id);
CREATE INDEX IF NOT EXISTS ix_file_run  ON file_access(run_id);
"""


class NoAudit:
    """Returned when auditing is off: every method is a silent no-op, so call sites stay clean."""
    enabled = False
    run_id = None
    def __getattr__(self, _name):
        return lambda *a, **k: None
    def logging_handler(self): return None
    def child_env(self, env=None): return env if env is not None else dict(os.environ)
    def close(self, *a, **k): return None


class Audit:
    enabled = True

    def __init__(self, path, case_id=None, record_secrets=False, parent_run_id=None):
        self.path = os.path.abspath(path)
        self.record_secrets = bool(record_secrets)
        self._t0 = time.time()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        # autocommit + WAL + FULL sync: each row durable immediately so a crash keeps the trail
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=15.0)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=15000")
        self.db.executescript(_DDL)
        row = self.db.execute("SELECT case_id FROM case_info LIMIT 1").fetchone()
        if row:
            self.case_id = row[0]
        else:
            self.case_id = case_id or ("case-" + _utc().replace(":", "").replace("-", "")[:15])
            self.db.execute("INSERT INTO case_info(case_id,created_utc,tool,tool_version,schema_version)"
                            " VALUES(?,?,?,?,?)", (self.case_id, _utc(), "wawf", _tool_version(), SCHEMA_VERSION))
        self.run_id = None
        self.parent_run_id = parent_run_id

    # ---------- run lifecycle ----------
    def start_run(self, command, argv=None):
        cur = self.db.execute(
            "INSERT INTO run(case_id,command,argv,started_utc,status,tool_version,frozen,executable,python,"
            "platform,hostname,os_user,cwd,pid,parent_run_id) VALUES(?,?,?,?,'running',?,?,?,?,?,?,?,?,?,?)",
            (self.case_id, command, _js(list(argv or sys.argv)), _utc(), _tool_version(),
             1 if getattr(sys, "frozen", False) else 0, sys.executable, sys.version.split()[0],
             platform.platform(), platform.node(), _user(), os.getcwd(), os.getpid(), self.parent_run_id))
        self.run_id = cur.lastrowid
        return self.run_id

    def end_run(self, exit_code=0, status=None, error=None, tb=None):
        self.db.execute("UPDATE run SET finished_utc=?, exit_code=?, status=?, error_type=?, error_message=?,"
                        " traceback=? WHERE run_id=?",
                        (_utc(), exit_code, status or ("ok" if not exit_code else "error"),
                         type(error).__name__ if error else None, str(error) if error else None, tb, self.run_id))

    # ---------- the narrative ----------
    def event(self, message, level="INFO", category=None, detail=None, logger=None,
              module=None, lineno=None, tb=None):
        self.db.execute("INSERT INTO event(run_id,ts_utc,elapsed_s,level,category,logger,message,detail,"
                        "module,lineno,traceback) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (self.run_id, _utc(), round(time.time() - self._t0, 3), level, category, logger,
                         message, _js(detail), module, lineno, tb))

    # ---------- what was touched ----------
    def file_read(self, path, purpose=None, hash_it=False, records=None, detail=None, cap=None):
        return self._file("read", path, purpose, hash_it, records, detail, cap)

    def file_write(self, path, purpose=None, hash_it=True, records=None, detail=None, cap=None):
        return self._file("write", path, purpose, hash_it, records, detail, cap)

    def _file(self, action, path, purpose, hash_it, records, detail, cap):
        present, size, mtime, digest = 0, None, None, None
        try:
            st = os.stat(path); present, size = 1, st.st_size
            mtime = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if hash_it and os.path.isfile(path):
                digest, _ = sha256_file(path, cap)
        except Exception:
            pass
        self.db.execute("INSERT INTO file_access(run_id,ts_utc,action,path,purpose,present,size,mtime_utc,"
                        "sha256,records,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (self.run_id, _utc(), action, str(path), purpose, present, size, mtime,
                         digest, records, _js(detail)))
        return digest

    def dir_read(self, path, purpose=None, detail=None):
        """Record a directory as evidence: file count + total bytes (hashing a whole LevelDB is wasteful)."""
        n = tot = 0
        for dp, _d, fs in os.walk(path):
            for f in fs:
                n += 1
                try: tot += os.path.getsize(os.path.join(dp, f))
                except OSError: pass
        d = {"files": n, "bytes": tot}
        if detail: d.update(detail)
        self.db.execute("INSERT INTO file_access(run_id,ts_utc,action,path,purpose,present,size,records,detail)"
                        " VALUES(?,?,'read',?,?,?,?,?,?)",
                        (self.run_id, _utc(), str(path), purpose, 1 if os.path.isdir(path) else 0, tot, n, _js(d)))

    # ---------- what decrypted what ----------
    def crypto(self, op, algorithm=None, kdf=None, scheme=None, key=None, key_source=None,
               salt=None, salt_source=None, info=None, input_desc=None, records_in=None,
               records_ok=None, records_failed=None, validated=None, detail=None):
        self.db.execute("INSERT INTO crypto_op(run_id,ts_utc,op,algorithm,kdf,scheme,key_source,key_fp,"
                        "key_len,key_secret,salt_source,salt_fp,info,input_desc,records_in,records_ok,"
                        "records_failed,validated,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (self.run_id, _utc(), op, algorithm, kdf, scheme, key_source, fp(key),
                         (len(key) if key is not None else None),
                         (_b64(key) if (self.record_secrets and key is not None) else None),
                         salt_source, fp(salt), _txt(info), input_desc, records_in, records_ok,
                         records_failed, validated, _js(detail)))

    # ---------- what went over the wire ----------
    def net(self, direction, endpoint=None, kind=None, protocol=None, status=None, nbytes=None, detail=None):
        self.db.execute("INSERT INTO network_event(run_id,ts_utc,direction,protocol,endpoint,kind,status,"
                        "bytes,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                        (self.run_id, _utc(), direction, protocol, endpoint, kind, status, nbytes, _js(detail)))

    # ---------- what came out ----------
    def artifact(self, path, kind=None, records=None, hash_it=True, detail=None):
        digest, size = (None, None)
        if hash_it and os.path.isfile(path): digest, size = sha256_file(path)
        elif os.path.exists(path):
            try: size = os.path.getsize(path)
            except OSError: pass
        self.db.execute("INSERT INTO artifact(run_id,ts_utc,path,kind,size,sha256,records,detail)"
                        " VALUES(?,?,?,?,?,?,?,?)",
                        (self.run_id, _utc(), str(path), kind, size, digest, records, _js(detail)))
        return digest

    # ---------- plumbing ----------
    def logging_handler(self):
        """Mirror EVERY log record (including exc_info tracebacks) into `event`, so the audit trail contains
        the tool's own narrative without having to instrument each message by hand."""
        return _AuditHandler(self)

    def child_env(self, env=None):
        """Env for helper subprocesses so they append to this same case DB (see from_env())."""
        e = dict(os.environ if env is None else env)
        e[ENV_DB] = self.path
        e[ENV_RUN] = str(self.run_id or "")
        if self.record_secrets: e[ENV_SECRETS] = "1"
        return e

    def close(self):
        try: self.db.close()
        except Exception: pass


class _AuditHandler(logging.Handler):
    def __init__(self, aud):
        super().__init__(level=logging.DEBUG)
        self.aud = aud

    def emit(self, record):
        try:
            tb = None
            if record.exc_info:
                import traceback as _tb
                tb = "".join(_tb.format_exception(*record.exc_info))
            self.aud.event(record.getMessage(), level=record.levelname, category="log",
                           logger=record.name, module=record.module, lineno=record.lineno, tb=tb)
        except Exception:
            pass                                            # auditing must never break the tool


def _b64(x):
    import base64
    try: return base64.b64encode(bytes(x)).decode()
    except Exception: return None

def _txt(x):
    if x is None or isinstance(x, str): return x
    try: return bytes(x).decode("utf-8", "replace")
    except Exception: return str(x)

def _user():
    try: return getpass.getuser()
    except Exception: return None

def _tool_version():
    return os.environ.get("WAWF_VERSION") or "1.0"


def open_db(path, case_id=None, record_secrets=False, parent_run_id=None):
    """Open/create a case audit DB. Returns NoAudit() if it cannot be opened — auditing must never be the
    reason a forensic run fails."""
    try:
        return Audit(path, case_id=case_id, record_secrets=record_secrets, parent_run_id=parent_run_id)
    except Exception as e:
        sys.stderr.write("[audit] disabled (could not open %s: %s)\n" % (path, e))
        return NoAudit()


def from_env(command=None, start=True):
    """Used by helper scripts/subprocesses: attach to the case DB named by WAWF_AUDIT_DB, if any."""
    p = os.environ.get(ENV_DB)
    if not p: return NoAudit()
    parent = os.environ.get(ENV_RUN) or None
    try: parent = int(parent) if parent else None
    except ValueError: parent = None
    a = open_db(p, record_secrets=os.environ.get(ENV_SECRETS) == "1", parent_run_id=parent)
    if a.enabled and start:
        a.start_run(command or os.path.basename(sys.argv[0]))
    return a
