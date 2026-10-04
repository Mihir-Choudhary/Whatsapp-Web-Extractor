# WhatsApp Web Extractor

A forensic CLI that decrypts and exports **WhatsApp Web** from a browser's on-disk storage.
Works with **Firefox** and **Chromium** (Chrome / Edge / Brave / Opera), auto-detecting the engine
from the profile.

> Authorized use only — your own account or a lawful investigation with permission.

## Get it

### Windows — use the `.exe` (no Python needed)

Download **`wawf-windows-x64.exe`** from the [latest release](../../releases/latest), then run it from a terminal:

```powershell
wawf-windows-x64.exe <PROFILE> [options]
```

The binary is unsigned. On a machine with **Smart App Control** enabled, Windows may refuse to run it
with *"An Application Control policy has blocked this file"*. That block is reputation-based rather
than signature-based — it applies to a binary Windows has not seen before, and can clear by itself
after a while. Smart App Control **cannot be re-enabled once turned off**, so disabling it is a
one-way decision about the whole machine, not a workaround; running from Python instead avoids the
question entirely. See [BUILD.md](BUILD.md).

### Linux / macOS — run with Python

```bash
pip install -r requirements.txt          # cryptography, cramjam, websocket-client, ccl_chromium_reader
python3 wawf.py <PROFILE> [options]
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

Repeatable. `FORMAT` is `txt`, `json`, `sqlite`/`db` or `raw`; a plain path writes text **and** JSON.
A prefix that is not one of those is a typo rather than a path, and is rejected — `--out sqlit:D:\db`
used to be accepted silently and write text into a folder named after the mistake. A real path that
contains a colon can still be given as `./my:dir`.

```bash
wawf <PROFILE> --out D:\case\out              # transcripts.txt + chats.json + identities.json
wawf <PROFILE> --out txt:D:\case\out          # only transcripts.txt
wawf <PROFILE> --out json:D:\case\out         # only chats.json + identities.json
wawf <PROFILE> --out sqlite:D:\case\db        # Android msgstore.db + wa.db
wawf <PROFILE> --out raw:D:\case\raw          # every store verbatim, decrypted in place
wawf <PROFILE> --out sqlite:D:\case\db --out raw:D:\case\raw    # several at once
```

#### Who sent it

Every message names its sender. WhatsApp addresses one person three ways — `<phone>@c.us` (UI form),
`<phone>@s.whatsapp.net` (the same phone, wire form) and `<lid>@lid` (an account alias, which is what
recent messages actually carry) — so a transcript that printed the raw field would be unreadable, and
one that printed "me / them" would be unusable. Both are resolved against the examined profile's own
`contact` and `group-metadata` stores:

```
===== Weekend plans  [120363000000000000@g.us]  (group; 412 msgs, 377 with text) =====
  - Dev                       244358000000001@lid  919300000001@c.us
  - Riya                      133461000000002@lid  919300000002@c.us  (me)
[2026-07-03 00:50:37] ->                   Riya: I wanted to try golf at least once
[2026-07-03 00:51:02] <-                    Dev: next weekend?
[2026-07-03 00:51:40] <-                    Dev: (sticker)
                                           re: I wanted to try golf at least once
[2026-07-03 00:52:03] ->                   Riya: booking it
```

A name comes from the address book first, then the contact's own `pushname`, then their phone number,
and **when nothing is known the jid is printed unchanged** — a label is never invented, so
"unidentified" stays visibly different from "identified". Each chat header lists its senders with
every jid form they appear under, so any line can be traced back to an identifier.

A reply quotes the message it answers, and the quote is stored *inside* the reply. It is kept in its
own field rather than folded into the reply's text, because otherwise the transcript attributes one
person's words to another: on a 22,121-message store that affected 4,282 messages, and for 246 of
them — mostly sticker replies, which have no text of their own — the quoted message was the only
thing shown. In the transcript the quote appears under the reply as `re:`; a message that spans
lines is continued under `|`, so every line is attributable and no message content can sit where the
file's own structure does.

**Every message gets a line**, including the ones with no text of their own — caption-less media, a
revoked message, a call log — shown as the type the store recorded: `(sticker)`, `(image)`,
`(revoked)`. Omitting them hid 2,374 records of a 22,084-message export from the readable artifact,
and with them the `re:` quote on a sticker reply, which is exactly the case the own/quoted split
exists for. The chat header counts both: `N msgs, M with text`.

Bidi controls (`U+202E` and friends) are stripped on the way into the transcript, because they
re-order how a line renders and this file's whole premise is that every line is attributable.
`chats.json` keeps the characters the store held.

`chats.json` keeps `sender` exactly as stored and **adds** `sender_name`, `sender_lid`,
`sender_phone`, `sender_source`, `chat_name` and `quoted_text` beside it — nothing is replaced by an
interpretation of it. `identities.json` is the correlation table itself: jid ↔ lid ↔ phone ↔ name ↔ pushname, where
each label came from, which contacts are in the address book, plus group subjects, members, **past**
members and admins. That mapping is the one thing the browser holds and the wire format does not: a
lid-keyed contact record carries the matching `phoneNumber`, and on disk that is the only place the
lid→phone link exists.

The SQLite export carries the same correlation natively, in the Android shape a msgstore parser
expects (`message.sender_jid_row_id` → `jid`, `chat.jid_row_id` → `jid`, `jid` → `wa_contacts`), so
tools built for Android databases resolve senders from it without any extra work. Quoted text lands
in `message_quoted.text_data`, which is where such a parser looks for it.

#### Checking an export

```bash
python3 scripts/validate_export.py D:\case\out              # transcript + JSON
python3 scripts/validate_export.py D:\case\out D:\case\db   # ...and the database
```

Checks the artifacts against each other and against their own headers: that every sender resolves,
that the counts in each chat header match the lines beneath it and the records in `chats.json`, that
nothing is duplicated, that no message content sits where structure does, and that the Android
correlation chain resolves end to end. Useful after any change to the writers, or to satisfy
yourself that an export you were handed is internally consistent. It writes nothing.

#### `raw` — decrypt, and change nothing else

The other formats summarise. The text writer runs the decrypted payload through a heuristic string
scraper, which drops field identity, every non-string field and anything past 2000 characters.

`raw` writes one JSONL file per object store — typically **48 stores and ~70,000 records** — with each
record exactly as the browser stored it: same field names, same ordering, JavaScript `undefined`
preserved as a distinct marker (it is not the same as `null`). The decryption is **added beside** the
ciphertext rather than replacing it, so the file stays a faithful image of the store *plus* a
decryption:

| added field | what it holds |
|---|---|
| `_wawf_plaintext_b64` | the decrypted bytes verbatim, so the decryption can be re-verified independently |
| `_wawf_plaintext_fields` | the same bytes as a schema-free protobuf field tree, so you can see *which* field a string came from |

Because `raw` is an image of the store, it keeps **every** record the store holds, including
superseded versions of the same message — the browser's IndexedDB retains them and they are evidence
of edits and re-deliveries. The derived formats are per *message*, so they drop records that are
byte-for-byte identical to one already taken (25 ids, 37 records in the reference profile) and keep
any version that actually differs. So `raw` legitimately shows a few more records than `chats.json`
has rows; the difference is duplicates, not content.

A `_manifest.json` records per-store counts, the derivation used, and what every marker means. The key
is validated against 40 reference bodies before anything is written, so a wrong or stale key produces
a clear refusal instead of a complete-looking dump with nothing decrypted in it.

`signal-storage` and `wawc_db_enc` are **excluded by default** — they hold the account's Signal
sessions, prekeys and the at-rest root key, and a dump meant to travel with a case should not be key
material. `--raw-include-keys` overrides that.

A Windows drive letter is never mistaken for a `FORMAT`, so `D:\case\out` works as you'd expect.

### Options

| Option | What it does |
|---|---|
| `--key FILE` | A `companion_enc_static.txt` captured earlier — decrypt without touching the network. Usually unnecessary: a copy left beside the output is found automatically. A **file**, never the key itself, so no secret reaches your shell history, process list or command auditing. |
| `--origin DIR` | Firefox `web.whatsapp.com` storage folder instead of a profile folder. |
| `--raw-include-keys` | With `--out raw:` — also dump `signal-storage` and `wawc_db_enc`. Those are key material; a dump including them must not travel with a case. |
| `--history` | **Also** pull chat history older than the browser cache from your phone, iteratively, resuming across runs, and append it to the export. Needs Node (offers to install it). Phone-side and rate-limited — see below. |
| `--fetch-media` | With `--history --out sqlite:PATH`: after the pull, ask the CDN for media the browser never cached. Networked, and it downloads real bytes — a large account can be a lot of them. Urls whose signature has already expired are skipped without a request. |
| `--history-refetch` | With `--history`: re-ask for history already recovered, to fill in fields an earlier run did not capture (the group sender). Finds nothing new by design. |
| `--install-node` | Allow `--history` to install Node.js via winget when none is found. **Not** covered by `--yes`: it modifies the machine and asks for elevation. A portable Node unzipped beside the tool, or `WAWF_NODE` pointing at one, needs neither. |
| `--no-audit` | Do **not** write the chain-of-custody database. It is written by default (see below). |

Sender resolution is **reported, not assumed** — a run prints where every label came from, so the one
number that matters is visible:

```
senders identified: address-book=14,250  pushname=7,325  phone=543  unresolved=0
```

`unresolved` counts messages from jids the profile itself holds no name and no number for. On a
healthy profile it is zero; anything else is a gap in the evidence, not a gap in the tool.
| `-v`, `--log-file FILE` | Full logs and tracebacks; mirror them to a file. |

## Chain of custody (on by default)

The tool records everything it did into a SQLite **case database** beside the output. This is not
something to remember to switch on — the run that most needs the trail is the one where nobody
thought to ask for it — so it is written unless you pass `--no-audit`. It costs one file: no network,
no extra read of the evidence.

The database records everything it did, written
into the output directory (one DB per case — never a single global log):

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

## Where the key comes from

Message **text** is encrypted with a key derived from `companion_enc_static`, and that value is issued
by WhatsApp's servers and **never written to disk** by the browser. Two of the three inputs to the key
are in the profile; this one is not. So the question is always *where does the key come from* — and in
normal use you do not have to answer it, because `wawf <PROFILE>` captures it for you.

**A. Default — let it capture the key.** One command does credentials, key capture and decryption:

```bash
wawf <PROFILE> --out D:\case\out
```

The key capture is **networked**: it logs in as your linked device and registers activity on the
account. Own account or authorised investigation only. The captured key is written as
`companion_enc_static.txt` beside the output, and a later run finds it there and skips the network.

**B. Decrypt offline with a key you already hold.** Useful when you must not contact the account at
all, and it keeps working after the device has been revoked, because decryption is purely local:

```bash
wawf <PROFILE> --key companion_enc_static.txt --out D:\case\out
```

**C. From memory — not currently exposed.** Recovering the key from a RAM dump, swap or hibernation
file works, and the code for it is still in the repository (`scripts/wa_forensic.py`), but it could
only validate candidates against a **Firefox** store, which left no case where it beat route A or
route B. The command-line options were withdrawn rather than shipped half-covering; the note in
`wawf.py` says what restoring them needs.

**D. No key at all.** Still useful: metadata, contacts, timestamps, media keys — everything except
message text.

```bash
wawf <PROFILE> --out D:\case\out
#   ^ if key capture fails, it says so and writes the offline inventory
```

The key capture does the WhatsApp Noise handshake in **pure Python**, so it works from the standalone
binary with no Node required. The key is never printed and never passed to a subprocess on the command
line — it travels by file and by environment variable, because a secret in argv is readable from the
process list.

A wrong or stale key is **detected, not acted on**: every writer trial-decrypts reference ciphertext
first and refuses rather than producing garbage. If the key was one the tool found by itself, it
discards it and captures a fresh one; if you named it with `--key`, it reports the problem and stops
rather than silently reaching for the network.

## Recovering history older than the cache

A browser only ever holds the recent window WhatsApp synced to it (e.g. tens of thousands of messages) — *not* your whole history. `wawf <PROFILE> --history`
logs back in and asks your phone, per chat, for messages **older** than what's on disk, paging backward
toward each chat's start:

```bash
wawf <PROFILE> --history                             # pull only; results land in tools/reconnect
wawf <PROFILE> --history --out D:\case\run2          # ...and export the local store WITH them merged
wawf <PROFILE> --history --out sqlite:D:\case\run2 --fetch-media    # ...and try the CDN for their media
```

#### What `--history --out` produces

One dataset, not two files to reconcile. The local store is decrypted **first** — so a complete
export exists within minutes, before a pull that takes hours — and the recovered messages are
appended to it when the pull finishes (or when you interrupt it). Every row says which side it came
from:

| `source` | meaning |
|---|---|
| `cache` | the message was in the browser's own storage when the profile was examined |
| `phone` | the message was served by your phone during this run, over the network |

The timeline is shared; the provenance is not, which is why it is recorded per message rather than
per file. In the SQLite export the same distinction is the `message.source` column.

**An earlier export is never written over.** A history run produces a different dataset from a plain
one, so if the `--out` path already holds an export the new one is written beside it and the log says
what it found and where this one went:

```
D:\case\run1 already holds a cache export (2026-10-04 13:20, 22,084 messages). This run
produces the local store PLUS what the phone returns, which is a different dataset, so it is
written to D:\case\run1-history and the existing one is left untouched.
```

Each output folder carries a `wawf_export.json` receipt recording which of the two it is, when it was
made, and how many messages came from each side.

Two things worth knowing. `raw` is excluded on purpose: it is a verbatim image of what is *in* the
store, and a recovered message never was — the run says so rather than skipping it quietly. And
media for recovered messages is **not** downloaded by default: their `mediaKey`s are exported, so
`--fetch-media` (or `scripts/mediafetch.py --cdn` later) can fetch the bytes when you want them,
without adding CDN failures to an already long run.

A group message recovered from the phone carries its sender in the history protobuf
(`key.participant`, or `participant` on the message itself), and the sender's own display name in
`pushName`. Earlier versions of the extractor captured none of them, so messages banked by those
runs have no author and show as `(unknown)` — in the line and in the chat's participant legend, so
the file never claims to know who spoke when it does not.

There are two ways to fill those in. **Offline first**, if the chunks are there:

```bash
cd tools/reconnect && node rehydrate_history.js --dry-run   # what would change
cd tools/reconnect && node rehydrate_history.js             # apply it
```

A history chunk is the primary artifact — the phone uploaded it, the run downloaded it once, and its
CDN url expires within weeks — while everything in `history_recovered.json` is a *mapping* of it. So
runs keep every decrypted chunk in `history_chunks/`, and `rehydrate_history.js` re-reads them with
the current mapper, filling fields the run that downloaded them did not capture. No network, and it
only fills: a field the banked record already has is never overwritten.

Chunks are kept from 2026-10-04 onward. A ledger banked before that has none, so its missing senders
have to come from the phone:

```bash
wawf <PROFILE> --history --history-refetch --out D:\case\run3
```

That re-requests history you already have instead of going deeper, and asks **only the chats that
are missing something** — on this project's own ledger that was 20 group chats out of 249, a 92%
smaller request budget, which matters because the phone has to answer and WhatsApp rate-limits it.
It finds nothing new by design.

Where the profile cannot name a recovered sender at all, the name they chose for themselves is used
(`sender_source: history-pushname`) — better than a bare number, and still never a guess: the
address book wins where it has an entry.

It runs **iteratively**: each pass re-anchors every chat on the oldest message recovered so far and pulls
deeper, accumulating (deduped) until a pass stops finding meaningfully more. Progress is checkpointed to
`tools/reconnect/history_all.json` after every pass, so it is **crash-safe and resumable** — re-running
`wawf <PROFILE> --history` continues from where the last run left off (older than everything already
recovered) rather than re-pulling the same window.

**What has to be recovered for this to work.** The phone's answer comes back as a normal end-to-end
encrypted message, so authenticating as the linked device is not enough — the Signal state has to come
with it. `wawf` reads it straight out of the profile (`signal-storage`, where WhatsApp Web keeps the
ratchet state in plaintext) and translates it into the serialisation the Node Signal stack expects:
the identity keypair and registration id, the signed prekey, every one-time prekey, the **Double
Ratchet sessions** (including superseded ones, kept closed, so older messages still decrypt) and the
**group sender keys**. Without the sessions every inbound payload fails to decrypt and is discarded
before it can be recognised as a history reply — indistinguishable from "the phone never answered".

A ratchet is live state, though, not a file: the copy in the profile is a snapshot that the phone has
already moved past. So `wawf` renegotiates the session with your own device from a freshly fetched
prekey bundle, asks any sender it cannot read to re-encrypt (a retry receipt carrying our keys), and
**persists everything it learns** in `signal_runtime.json` beside the output, so the next run continues
from the live ratchet instead of the stale snapshot. That file is key material — protect it like the
credentials. Your browser's own stored session for this linked device goes stale as a result; WhatsApp
Web re-establishes it by itself the next time you open it. The profile and the phone are not modified.

There is **no fixed 50K ceiling** — the limit is what your phone still retains.

**How the rate limit works, and why you should not just retry.** WhatsApp throttles this, which the
server confirms (`wa_web_history_sync_dynamic_throttling`). The limit counts **failures, not
requests** — its counter resets on every success — so roughly ten *unanswered* requests inside two
hours puts the account quiet for two hours. The tool therefore paces itself: the delay doubles on each
unanswered request and eases back on each answered one, and when it does hit the limit it waits the
cooldown out and resumes from its checkpoint instead of giving up.

So **an empty pass is not a reason to run it again immediately** — that spends the failure budget and
extends the quiet window. Diagnose instead:

```bash
node tools/reconnect/diag_onehistory.js      # ONE request, every inbound stanza logged
```

It separates causes that otherwise look identical: no ack means the stanza was never accepted (not a
cooldown), an explicit error means refused with a readable reason, an ack then silence means throttled
or declined by the phone, and an ack then a notification means served.

**What to expect.** On a healthy device the server acks in ~0.3s and a chunk of up to 50 messages
arrives ~3s later. A first pass over a few hundred chats takes tens of minutes; draining a long
history runs for hours and will sit idle for two hours at a time when the limit trips. Progress is
checkpointed after every page, so stopping it costs nothing.

Needs Node + `cd tools/reconnect && npm install` — the Signal/E2E stack isn't ported to Python, so
`--history` is **not** in the standalone binary.

Node is looked for in the places it actually lives: beside the tool (a `node-v*/` folder or
`node/node.exe`), on `PATH`, in the standard install directories, in nvm / nvs / scoop / chocolatey /
winget, and wherever `WAWF_NODE` points. Unzipping the official portable build next to the tool is
the least invasive option on an examination machine — nothing is installed and nothing is elevated.

### Other diagnostics

```bash
node tools/reconnect/rehydrate_history.js --dry-run   # re-read kept chunks; what would change?
node tools/reconnect/diag_health.js    # 60s: CONNECT / REGISTERED / SERVED, reported separately
node tools/reconnect/diag_abprops.js   # which features the server has enabled for this client
python3 scripts/check_identity.py --profile <PROFILE> --dir tools/reconnect
```

`diag_health` matters because a **revoked** companion still completes the handshake and still reaches
"connected" — so connecting proves nothing. Its registration check is a USync device query against the
account, which is definitive rather than inferred from silence. Only a `REGISTERED` failure means the
device is gone.

`check_identity` answers a different question: when WhatsApp Web re-pairs, the account gets a new
device slot, registration id and Signal identity, and credentials exported before that describe a
device that no longer exists. `wawf <PROFILE>` re-exports every run and so self-heals; the `diag_*.js`
tools read whatever is on disk, so check first if you have been using them.

**Examples** (Windows: swap `python3 wawf.py` for `wawf-windows-x64.exe`)

```bash
# The whole job: recover credentials, capture the at-rest key, decrypt
python3 wawf.py ~/.config/google-chrome/Default --out out/ -v

# Firefox: point straight at the origin dir instead of a profile
python3 wawf.py --origin .../storage/default/https+++web.whatsapp.com --out out/

# Offline, with a key captured earlier, and a faithful dump plus a database
python3 wawf.py ~/.config/google-chrome/Default --key companion_enc_static.txt \
    --out raw:case/raw --out sqlite:case/db --audit
```

`<profile>` is a browser profile directory:

- **Firefox** — `.../<name>.default` (or use `--origin` for its `web.whatsapp.com` storage dir)
- **Chromium** — `~/.config/google-chrome/Default`, `~/.config/microsoft-edge/Default`, etc.
  (Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default`)

Every writer validates the key against on-disk ciphertext and refuses to write garbage if it is wrong.
Exit codes: `0` ok · `1` error · `2` bad usage · `3` wrong key · `4` file not found.

**Media.** Message media is recovered from the browser's own cache (Chromium simple-cache and
blockfile, Firefox CacheStorage and `cache2` — all four layouts verified byte-identical) and verified
against each message's `fileSha256`. Anything the browser never cached, or has since evicted, is not
on disk: those `mediaKey`s *are* exported in `message_media`, and `scripts/mediafetch.py --cdn` will
try the CDN. Note that a CDN url carries its own expiry — once it lapses every request is `403`, and
WhatsApp purges the object itself well before that, after which it returns `410` and the bytes are
gone server-side.
