[← Back to the README](../README.md)

# Chain of custody (on by default)

The tool records everything it did into a SQLite **case database** beside the output. This is not
something to remember to switch on — the run that most needs the trail is the one where nobody
thought to ask for it — so it is written unless you pass `--no-audit`. It costs one file: no network,
no extra read of the evidence.

It is written into the output directory (one DB per case — never a single global log):

```bash
wawf <PROFILE> --out out/                               # -> out/wawf_audit.db
wawf <PROFILE> --out sqlite:db/                        # appends to db/wawf_audit.db
wawf <PROFILE> --out out/ --audit-db /cases/acme/custody.db     # or name the DB yourself
wawf <PROFILE> --out out/ --no-audit                   # write no case database at all
```

Re-running **appends** a new `run` row, so repeated passes over the same case — a decrypt, then a
`--history` sweep, then another output format — accumulate in one case history. Helper subprocesses and the Node history client write into the *same* DB.

| Table | What it records |
|---|---|
| `case_info` | case id, creation time, tool + schema version |
| `run` | one row per invocation: command, full argv, start/finish, exit code, status, error + traceback, host, OS user, pid, tool version, parent run |
| `event` | the ordered narrative — **every** log line (with tracebacks), plus stage breadcrumbs |
| `file_access` | which files/directories were opened, purpose, size, mtime, SHA-256, record counts |
| `crypto_op` | what decrypted what: algorithm, KDF, scheme, key **fingerprint**, salt source, info, records in/ok/failed, validation result |
| `network_event` | requests sent and responses received (e.g. each on-demand history page) |
| `artifact` | every output produced, with size, row count and **SHA-256** |

**Crash forensics.** The DB is autocommit + WAL + `synchronous=FULL`, so each row is durable the instant it's
written. If the tool dies, the last `event` row shows the stage it was in; a `run` still marked `running`
with no `finished_utc` means the process was killed rather than exiting. Handled failures record the
exception type, message and traceback.

**Secrets.** Key material is stored as a **SHA-256 fingerprint plus the derivation parameters** (KDF, salt
source, info, lengths, scheme) — enough to prove which key produced which plaintext, and to match a key you
hold, without turning the audit log into a secret store. Pass `--audit-secrets` if your process genuinely
requires the raw values. Message *content* is not duplicated into the DB; artifacts are referenced by hash.

---

[← Back to the README](../README.md)
