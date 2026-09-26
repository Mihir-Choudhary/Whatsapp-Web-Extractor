# WhatsApp Web Extractor

A forensic CLI that decrypts and exports **WhatsApp Web** from a browser's on-disk storage.
Works with **Firefox** and **Chromium** (Chrome / Edge / Brave / Opera), auto-detecting the engine
from the profile.

> Authorized use only — your own account or a lawful investigation with permission.

## Get it

### Windows — use the `.exe` (no Python needed)

Download **`wawf-windows-x64.exe`** from the [latest release](../../releases/latest), then run it from a terminal:

```powershell
wawf-windows-x64.exe <command> [options]
```

### Linux / macOS — run with Python

```bash
pip install -r requirements.txt          # cryptography, cramjam, websocket-client, ccl_chromium_reader
python3 wawf.py <command> [options]
```

<sub>(or install them by hand: `pip install cryptography cramjam websocket-client` and
`pip install "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"`)</sub>

(A prebuilt `wawf-linux-x64` binary is also on the [releases page](../../releases/latest), and you can
build your own binary for any OS with `pyinstaller wawf.spec` — see [BUILD.md](BUILD.md).)

## Use

**There are no sub-commands.** Point it at a browser profile and it does the whole job — recover the
device credentials, capture the at-rest key (reconnect), and decrypt:

```bash
wawf <PROFILE>
```

`<PROFILE>` is the browser profile folder (Chromium: the one containing `IndexedDB`; Firefox: the profile
folder, or `--origin` for its `web.whatsapp.com` storage folder). Nothing is auto-detected — which profile
gets examined is always your explicit choice. `wawf -h` prints the profile locations for your machine as
full, copy-pasteable paths.

### Choosing the output — `--out [FORMAT:]PATH`

Repeatable. `FORMAT` is `txt`, `json` or `sqlite`/`db`; a plain path writes text **and** JSON:

```bash
wawf <PROFILE> --out D:\case\out              # transcripts.txt AND chats.json
wawf <PROFILE> --out txt:D:\case\out          # only transcripts.txt
wawf <PROFILE> --out json:D:\case\out         # only chats.json
wawf <PROFILE> --out sqlite:D:\case\db        # Android msgstore.db + wa.db
wawf <PROFILE> --out sqlite:D:\case\db --out txt:D:\case\out    # several at once
```

A Windows drive letter is never mistaken for a `FORMAT`, so `D:\case\out` works as you'd expect.

### Options

| Option | What it does |
|---|---|
| `--enc-static B64` | You already have the at-rest key — use it and skip the networked reconnect. |
| `--origin DIR` | Firefox `web.whatsapp.com` storage folder instead of a profile folder. |
| `--history` | *Instead of decrypting:* pull chat history older than the browser cache from your phone, iteratively, resuming across runs. Needs Node (offers to install it); phone-side and rate-limited. |
| `--memory (--live \| --memimage FILE)` | *Instead of reconnecting:* find the key in RAM / swap / hibernation. `--live` is Linux-only (reads `/proc`, needs root); `--memimage` works anywhere. |
| `--audit` | Write a chain-of-custody database beside the output (see below). |
| `-v`, `--log-file FILE` | Full logs and tracebacks; mirror them to a file. |

## Chain of custody — `--audit` (optional)

Add `--audit` to any command and the tool records everything it did into a SQLite **case database**, written
into the output directory (one DB per case — never a single global log):

```bash
wawf decrypt <profile> --enc-static <b64> --out out/ --audit     # -> out/wawf_audit.db
wawf sqlite  <profile> --enc-static <b64> --out db/  --audit     # appends to db/wawf_audit.db
wawf decrypt <profile> --audit /cases/acme/custody.db            # or name the DB yourself
```

Re-running **appends** a new `run` row, so a whole workflow (`creds` → `reconnect` → `decrypt` → `sqlite`)
accumulates in one case history. Helper subprocesses and the Node history client write into the *same* DB.

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

## Workflow

Message **text** needs the `companion_enc_static` key (`--enc-static`), and that key is **never stored on
disk** — so the flow is always: *get the key, then decrypt.* `memory` and `reconnect` **produce** the key;
`decrypt` and `sqlite` **consume** it. Pick the path that matches your acquisition:

**A. You have memory** (live machine, RAM dump, swap, or hibernation file):

```bash
wawf memory --live                                  # Linux + root; on Windows/macOS use --memimage instead:
# wawf memory --memimage dump.raw --origin <web.whatsapp.com dir>
# -> prints companion_enc_static, then:
wawf decrypt <profile> --enc-static <b64> --out out/
```

**B. Disk only, but you can reach the network** (your own account / authorized investigation):

```bash
wawf reconnect <profile>                             # logs back in, writes companion_enc_static.txt
#   ^ networked: logs in as your linked device, registers activity — own account only
wawf decrypt <profile> --enc-static "$(cat companion_enc_static.txt)" --out out/
```

`reconnect` does the WhatsApp Noise handshake in **pure Python** — no Node required, and it runs from the
standalone `.exe`. (A Node/Baileys client under `tools/reconnect/` performs the same capture *plus* on-demand
history sync beyond the browser cache; it needs `npm install` and lives only in the source tree, not the `.exe`.)

**C. Disk only, no key** (never touch the account):

```bash
wawf decrypt <profile>          # offline inventory only: metadata + media keys, NO message text
```

Once you have the key, you can also export a full database instead of transcripts:

```bash
wawf sqlite <profile> --enc-static <b64> --out db/                        # Chromium: Chrome/Edge/Brave profile dir
wawf sqlite --origin <web.whatsapp.com dir> --enc-static <b64> --out db/   # Firefox: origin storage dir (+ cached Media/)
```

`memory` is the offline route to the key; `reconnect` is the networked route. `creds` just recovers the
reconnect credentials (it's implied by `reconnect`, or use it to feed the Node history client).

**Recovering history older than the cache.** A browser only ever holds the recent window WhatsApp
synced to it (e.g. tens of thousands of messages) — *not* your whole history. `wawf history <profile>`
logs back in and asks your phone, per chat, for messages **older** than what's on disk, paging backward
toward each chat's start:

```bash
wawf history <profile>                               # every chat, busiest first; needs Node + tools/reconnect
```

It runs **iteratively**: each pass re-anchors every chat on the oldest message recovered so far and pulls
deeper, accumulating (deduped) until a pass stops finding meaningfully more. Progress is checkpointed to
`tools/reconnect/history_all.json` after every pass, so it is **crash-safe and resumable** — re-running
`wawf history` continues from where the last run left off (older than everything already recovered) rather
than re-pulling the same window.

There is **no fixed 50K ceiling** — the limit is what your phone still retains. On-demand serving is
**phone-side and rate-limited**: your phone must be online/active and WhatsApp throttles it, so a pass may
return little while a later run (when the phone is more responsive) returns more — just run it again. It
needs Node + `cd tools/reconnect && npm install` (the Signal/E2E stack isn't ported to Python, so `history`
is **not** in the `.exe`).

**Examples** (Windows: swap `python3 wawf.py` for `wawf-windows-x64.exe`)

```bash
# Decrypt WhatsApp Web chats (needs companion_enc_static, from `memory` or a reconnect)
python3 wawf.py decrypt ~/.config/google-chrome/Default --enc-static <b64> --out out/ -v

# Firefox: point straight at the origin dir instead of a profile
python3 wawf.py decrypt --origin .../storage/default/https+++web.whatsapp.com --enc-static <b64>
```

`<profile>` is a browser profile directory:

- **Firefox** — `.../<name>.default` (or use `--origin` for its `web.whatsapp.com` storage dir)
- **Chromium** — `~/.config/google-chrome/Default`, `~/.config/microsoft-edge/Default`, etc.
  (Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default`)

`decrypt` validates the key against on-disk ciphertext and refuses to write garbage if it's wrong.
Exit codes: `0` ok · `1` error · `2` bad usage · `3` wrong key · `4` file not found.
