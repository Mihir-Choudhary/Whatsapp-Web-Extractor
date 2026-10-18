# WhatsApp Web Extractor

A forensic CLI that decrypts and exports **WhatsApp Web** from a browser's on-disk storage.
Works with **Firefox** and **Chromium** (Chrome / Edge / Brave / Opera), auto-detecting the engine
from the profile.

> Authorized use only — your own account or a lawful investigation with permission.

> **Risk to the account.** The default run (to capture the key), `--queue` and `--history` sign in to
> WhatsApp as the account's linked device, using a client WhatsApp did not write; `--fetch-media`
> downloads from WhatsApp's CDN. That is against WhatsApp's Terms of Service, and WhatsApp has banned
> accounts for using unofficial clients. Each sign-in is recorded as activity on the account. If the
> account must not be put at risk, use `--offline` with a key captured earlier (`--key`), or without one
> to export everything except message text.

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

`--history` (pulling messages older than the browser cache from your phone) runs inside the `.exe`
too: the linked-device client and the Signal protocol are implemented in Python, so no Node.js is
needed. See [Recovering history](#recovering-history-older-than-the-cache).

### Linux / macOS — run with Python

```bash
pip install -r requirements.txt          # cryptography, cramjam, websocket-client, ccl_chromium_reader
python3 wawf.py <PROFILE> [options]
```

<sub>(or install them by hand: `pip install cryptography cramjam websocket-client` and
`pip install "git+https://github.com/cclgroupltd/ccl_chromium_reader.git@ef840de30221c4d65bc96d2f4d9057e9ef2f526d"`, the commit the tool is tested against)</sub>

(A prebuilt `wawf-linux-x64` binary is also on the [releases page](../../releases/latest), and you can
build your own binary for any OS with `pyinstaller wawf.spec` — see [BUILD.md](BUILD.md).)

## Use

**There are no sub-commands.** Point it at a browser profile and it does the whole job — recover the
device credentials, capture the at-rest key (reconnect), and decrypt:

```bash
wawf <PROFILE>
```

`<PROFILE>` is the browser profile folder (Chromium: `Default`, `Profile 1`, ...; Firefox: the profile
folder, or `--origin` for its `web.whatsapp.com` storage folder). Nothing is auto-detected — which profile
gets examined is always your explicit choice. `wawf -h` prints the profile locations for your machine as
full, copy-pasteable paths.

**Prefer a window?** Double-click `wawf-windows-x64.exe`, or run `wawf` with no arguments (`wawf --gui`
also works). It finds the profiles on the machine that hold WhatsApp Web — for any Chromium- or
Firefox-based browser — or takes a copied profile, or the stores on their own; then where to save and how
to get the key. Everything else the command line offers is under *Advanced options…*. The window shows
the exact command it will run, live, with a **Copy** button: every run from the window is an ordinary
command-line run, with the same audit trail, and can be repeated from a terminal or quoted in a report.

### Acquiring the profile

Close the browser completely first (on Windows also Edge's *Startup boost* / Chrome's *Continue running
background apps*), then copy the profile folder. A browser that is running keeps writing its LevelDB
stores, and a copy taken meanwhile is torn: tables come out zero-length or half-written, the write-ahead
log is cut mid-record, and IndexedDB can lose its own database and store names. On such a copy the tool
still reads everything that survived, names the stores by their record fields, and reports exactly what
could not be read — but what was lost is lost. A live copy can lose recent tables, including the key
store, and then nothing can be decrypted.

Current Chromium/Edge builds can keep WhatsApp Web under a *partitioned* storage key, in
`WebStorage/<n>/IndexedDB` with its own localStorage, instead of the classic
`IndexedDB/https_web.whatsapp.com_0.indexeddb.leveldb`. Every partition is found and recorded; the one
holding the signed-in session is examined. If a profile holds more than one signed-in WhatsApp account,
the run says so and `--partition` selects each in turn (`--list-partitions` shows them).

### No profile folder? Point at the stores

When only the stores were collected, pass them directly. They can be anywhere and renamed; their
relative layout no longer matters:

```bash
wawf --idb "E:\item7\IndexedDB" --local-storage "E:\item7\Local Storage" --out D:\case\out
wawf --idb "E:\item7\WebStorage\4\IndexedDB" --local-storage "E:\item7\Local Storage" --media-cache "E:\item7\WebStorage\4\CacheStorage" --offline --key key.txt --out D:\case\out
```

| What | Where it is in a Chromium profile | Needed for |
|---|---|---|
| `--idb` | `IndexedDB\https_web.whatsapp.com_0.indexeddb.leveldb`, or `WebStorage\<n>\IndexedDB\indexeddb.leveldb` | everything: messages, chats, contacts, groups, calls, the root key |
| `--local-storage` | `Local Storage\leveldb` | the key salt, the device keys and which account is signed in |
| `--media-cache` (optional) | `WebStorage\<n>\CacheStorage`, `Service Worker\CacheStorage`, `Cache\Cache_Data` | media WhatsApp Web had cached |

The folder itself or the one around it is accepted (`...\IndexedDB` for `--idb`, `Local Storage` for
`--local-storage`). For Firefox, `--origin` already takes the one folder that holds both
(`storage\default\https+++web.whatsapp.com`). The window offers the same choice under *Separate folders*.

### Where the profile came from

A profile folder can be copied anywhere and renamed, so the tool reads its origin from the folder's
own files and records it in the audit trail: the browser (files only that browser writes), the version
that last wrote it, the label the browser showed for it, and the **original path**. Every Chromium
LevelDB keeps a `LOG` whose lines carry the absolute path it was opened at, so:

```
profile: Microsoft Edge 154.0.4258.62, originally C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Profile 8, labelled 'Profile 9' in the browser
```

The label and the folder name are different things (the example is a real pair). Stores passed with
`--idb`/`--local-storage` are traced the same way, from their own `LOG` files.

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
[2026-07-03 00:50:37] ->                   Riya: We should try bowling sometime
[2026-07-03 00:51:02] <-                    Dev: next weekend?
[2026-07-03 00:51:40] <-                    Dev: (sticker)
                                           re: We should try bowling sometime
[2026-07-03 00:52:03] ->                   Riya: booking it
```

A name comes from the address book first, then the contact's own `pushname`, then their phone number,
and **when nothing is known the jid is printed unchanged** — a label is never invented, so
"unidentified" stays visibly different from "identified". Each chat header lists its senders with
every jid form they appear under, so any line can be traced back to an identifier.

A reply quotes the message it answers, and the quote is stored *inside* the reply. It is kept in its
own field rather than folded into the reply's text, because otherwise the transcript attributes one
person's words to another: in a typical store that affects thousands of messages, and for some of
them — mostly sticker replies, which have no text of their own — the quoted message was the only
thing shown. In the transcript the quote appears under the reply as `re:`; a message that spans
lines is continued under `|`, so every line is attributable and no message content can sit where the
file's own structure does.

**Every message gets a line**, including the ones with no text of their own — caption-less media, a
revoked message, a call log — shown as the type the store recorded: `(sticker)`, `(image)`,
`(revoked)`. A call says how it went: `(video call: Completed, 48m03s)`, and its `chats.json` row
carries `call` with `outcome`, `duration_s` and `video`. WhatsApp Web stores a call again as it
progresses (`Ongoing`, then how it ended); the export keeps one row per call, from the settled version.
Omitting them hid thousands of records of a typical export from the readable artifact,
and with them the `re:` quote on a sticker reply, which is exactly the case the own/quoted split
exists for. The chat header counts both: `N msgs, M with text`.

Bidi controls (`U+202E` and friends) are stripped on the way into the transcript, because they
re-order how a line renders and this file's whole premise is that every line is attributable.
`chats.json` keeps the characters the store held.

`chats.json` keeps `sender` exactly as stored and **adds** `sender_name`, `sender_lid`,
`sender_phone`, `sender_source`, `chat_name` and `quoted_text` beside it — nothing is replaced by an
interpretation of it. Every message in the store is written, including one whose body cannot be
turned into text: such a row has empty `text` and one extra field, `body_status` — `none` (no body
was stored, e.g. a message deleted by its sender), `other-scheme` (a body this key does not open), or
`failed`. One more kind of record is not a message at all: `receipt-only` is a message id and its
delivery state, with no time, no type and no body, which WhatsApp Web keeps when a receipt arrives
for a message it does not hold. It is kept as a row (`[time not recorded] … (receipt only: the message
itself is not in the store)` in the transcript), sits in its own `wawf_receipt_only` table in
`msgstore.db` rather than among the messages, and is replaced when `--history` recovers the message
itself. `identities.json` is the correlation table itself: jid ↔ lid ↔ phone ↔ name ↔ pushname, where
each label came from, which contacts are in the address book, plus group subjects, members, **past**
members and admins. That mapping is the one thing the browser holds and the wire format does not: a
lid-keyed contact record carries the matching `phoneNumber`, and on disk that is the only place the
lid→phone link exists. `contacts.csv` is the contact store for a spreadsheet: a value a spreadsheet
would run as a formula (one starting with `=`, `+`, `-` or `@` — names and *about* texts are typed by
the contacts themselves) is written with a leading `'`; `identities.json` and `wa.db` keep it exactly.

The SQLite export carries the same correlation natively, in the Android shape a msgstore parser
expects (`message.sender_jid_row_id` → `jid`, `chat.jid_row_id` → `jid`, `jid` → `wa_contacts`), so
tools built for Android databases resolve senders from it without any extra work. Quoted text lands
in `message_quoted.text_data`, which is where such a parser looks for it.

Media files are named after their message's row id (`Media/WhatsApp Web/<row id>.<ext>`), and an
export written again into the same folder numbers its rows afresh, so the files already there are
renamed to their messages' new row ids. A file whose message is not in the new export (another chat,
with `--chat`) is moved to `Media/previous-export/`, named after its message key, and not deleted:
a file downloaded from the CDN may not be downloadable a second time. The audit database records both.

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
scraper, which keeps every message's text whole but drops field identity and every non-string field.

`raw` writes one JSONL file per object store — typically **several dozen stores and tens of thousands of records** — with each
record exactly as the browser stored it: same field names, same ordering, JavaScript `undefined`
preserved as a distinct marker (it is not the same as `null`), and a JavaScript `Date` as its exact
milliseconds since 1970 UTC with the instant beside it. The decryption is **added beside** the
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
| `--offline` | Never contact WhatsApp. Decrypts with `--key` (or a key file found beside the output); with no key, exports **everything except message text** — chats, senders, timestamps, types, media keys and cached media, reactions, polls, calls, contacts, groups. |
| `--chat WHO` | Only this conversation: a contact or group name, a phone number with its country code, a lid or a jid; repeat for several. The export holds those chats only and `--history` asks the phone about those chats only — see [One conversation only](#one-conversation-only----chat). |
| `--partition WHICH` | When a profile holds more than one WhatsApp session: the account number, storage key or layout name to examine. |
| `--list-partitions` | List every WhatsApp session in the profile (account, messages, key present) and stop. |
| `--origin DIR` | Firefox `web.whatsapp.com` storage folder instead of a profile folder. |
| `--raw-include-keys` | With `--out raw:` — also dump `signal-storage` and `wawc_db_enc`. Those are key material; a dump including them must not travel with a case. |
| `--history` | **Also** pull chat history older than the browser cache from your phone, iteratively, resuming across runs, and append it to the export. Pure Python, no Node needed. Phone-side and rate-limited — see below. |
| `--queue` | After the export, record what WhatsApp's server is holding for this device, decrypted with the browser's own keys, into `<out>/server-queue/<time>/` (with `--chat`, beside it: `<out>-server-queue/<time>/`). Networked; acknowledges nothing, so the queue stays for the browser. See [Recording what the server is holding](#recording-what-the-server-is-holding----queue). |
| `--fetch-media` | With `--out sqlite:PATH` (with or without `--history`): download, decrypt and verify from the CDN the media the browser never cached, newest first. Networked, and it downloads real bytes — a large account can be a lot of them. Urls whose signature has already expired are skipped without a request. |
| `--history-refetch` | With `--history`: re-ask for history already recovered, to fill in fields an earlier run did not capture (the group sender). Finds nothing new by design. |
| `--install-node` | Only with the optional Node engine (`WAWF_HISTORY_ENGINE=node`): allow `--history` to install Node.js via winget when none is found. **Not** covered by `--yes`: it modifies the machine and asks for elevation. A portable Node unzipped beside the tool, or `WAWF_NODE` pointing at one, needs neither. |
| `--no-audit` | Do **not** write the chain-of-custody database. It is written by default (see below). |
| `-v`, `--log-file FILE` | Full logs and tracebacks; mirror them to a file. |
| `--version` | Print the version — the release, plus the git commit when run from a checkout — the same string the export receipts and the audit database record. |

Sender resolution is **reported, not assumed** — a run prints where every label came from, so the one
number that matters is visible:

```
senders identified: address-book=8,120  pushname=3,410  phone=212  unresolved=0
```

`unresolved` counts messages from jids the profile itself holds no name and no number for. On a
healthy profile it is zero; anything else is a gap in the evidence, not a gap in the tool.

### One conversation only — `--chat`

When an examination covers named conversations only, `--chat` keeps everything else out:

```
wawf <PROFILE> --chat "Book club" --chat +15555550101 --out D:\case\out
wawf <PROFILE> --chat 123456789012345@lid --history --out D:\case\out
```

- **A phone number, its lid and its jid are one person.** WhatsApp files newer chats under the lid and
  older ones under the number; both are found, whichever form is given. A number needs its country code.
- **A name is matched exactly** (case and spacing aside) against the address-book name, the contact's own
  name, a group's subject and the chat's name.
- **Never a guess.** A name or number that fits more than one chat, or none, stops the run (exit 2) and
  lists the candidates with their numbers; run again with one of those.
- **The chat must hold at least one message in the browser.** History is asked for as "older than this
  message", so a contact with no chat in the browser cannot be asked.
- **What is scoped:** chats.json, transcripts.txt and msgstore.db hold those chats only; identities.json,
  contacts.csv and wa.db the people in them; group membership the chosen groups only. The receipt
  (`wawf_export.json`) records the scope. `raw` is refused with `--chat`, because it is an image of the whole store.
- **What cannot be scoped:** signing in delivers whatever the server holds for the device. `--queue`
  and `--history` keep that, as received, outside the export folder — `--queue` beside it
  (`<out>-server-queue/`), `--history` in the device's folder — and say so when `--chat` is given; only
  the chosen chats' messages are merged into the export. On a profile with several sessions,
  `--partition` must name the one to search.

## What a browser holds — and what it does not

What WhatsApp Web keeps in a browser profile, compared with the phone it is linked to.

| | In the browser | Notes |
|---|---|---|
| **Messages** | about the last **90 days** per chat | the window is what the phone sends at link time; whole chats can be missing (the phone sends a selection of its active chats). `--history` asks the phone for more. |
| Message text | decrypted with the key from sign-in | view-once captions and messages WhatsApp Web recorded as `unknown` ("waiting for this message") have no content in the browser |
| Link previews, locations, polls (with options), events | yes, as separate fields and Android tables | decoded with WhatsApp Web's own schema for the message record |
| **Ticks** (sent / delivered / read / played) | yes, for every message sent from the account | in a group the state covers all members: two ticks only once everyone has it |
| Per-recipient receipts (who read it when) | **only** for messages whose *Message info* was opened in the browser | the phone keeps far more |
| **Calls** | the recent window only | outcome, duration, video, participants |
| **Contacts** | yes: name, pushname, lid ↔ phone number, username, *about* text, business names | `contacts.csv`, `identities.json`, `wa.db` |
| **Groups** | members, admins, past members with *left/removed* and when, subject, description, settings | the phone stores the owner as itself |
| Reactions, mentions, pins, labels, channels, blocklist | yes | |
| Albums, HD copies, motion photos | the links between them: albums and HD video copies in `message_association`, every link as the browser recorded it in `wawf_message_association` | the browser labels HD photo copies and motion photos alike, so those are not given an Android type; it keeps no media key for any HD copy (the HD file is only in the live server queue) |
| Statuses (stories) | **no** — not written to disk | status updates posted while the browser was closed are in the server queue: `--queue` records them, with media keys |
| Profile pictures | addresses and hashes only; the image only if still cached | |
| Media files | keys and hashes for all; the bytes only for what the browser cached (it caches some already decrypted) | `--fetch-media` downloads the rest while their links are valid |
| **View-once** photos and videos | a stub only: sender, time, message id, photo or video | WhatsApp does not send view-once content to linked devices. The stanza arrives as `<unavailable type="view_once"/>` with no ciphertext, WhatsApp Web stores it as a `view_once_unavailable_fanout` placeholder, and the phone does not answer a resend request for it. True whether or not the message was opened on the phone. The content exists only on the sending and receiving phones. |
| **What the server is holding** | not on disk until the browser next connects | `--queue` records it — see below |
| History before the link | not on disk | each history chunk is downloaded once and deleted from the server; a network log of the sync shows the downloads but cannot be decrypted after the fact (its keys never leave the browser's memory) |

Where the browser has less, that is the browser's content, not a reading gap: the
export says so in its counts and in `body_status`, rather than filling anything in.

## Chain of custody (on by default)

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

> **Two files in the (first) output folder are key material, not evidence.**
> `companion_enc_static.txt` decrypts the store, and `creds_in.json` holds the linked device's private
> Noise key and identity — enough to log in *as* that device. They are left there so a later run can
> reuse them (automatically, or with `--key` / `--creds`). Remove both before an export is copied,
> shared or attached to a report; everything else in the folder is safe to hand over. On Linux and
> macOS these files, and the Signal state a `--queue` or `--history` run keeps, are created readable
> by their owner only (mode 0600).

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
wawf <PROFILE> --offline --out D:\case\out
#   ^ never goes online; if key capture fails in a normal run, the same export is written
```

The key capture does the WhatsApp Noise handshake in **pure Python**, so it works from the standalone
binary with no Node required. The key is never printed and never passed to a subprocess on the command
line — it travels by file and by environment variable, because a secret in argv is readable from the
process list.

A wrong or stale key is **detected, not acted on**: every writer trial-decrypts reference ciphertext
first and refuses rather than producing garbage. If the key was one the tool found by itself, it
discards it and captures a fresh one; if you named it with `--key`, it reports the problem and stops
(exit 3) rather than silently reaching for the network. With `--offline` as well, it says so and writes
the export without message text instead, as it would with no key at all.

## Recording what the server is holding — `--queue`

While the browser session is closed, WhatsApp's server keeps for that device everything the account
receives and sends from its other devices: messages, group key handovers, status updates, channel posts,
receipts, call offers. The browser collects it the next time it connects. Until then it exists only on
the server — and a closed browser on a seized machine may never connect again.

```
wawf <profile> --out D:\case\out --queue
```

This exports the device's credentials and the browser's **own** Signal state
(identity, sessions, the group sender keys) into `<out>/server-queue/<time>/` (`<out>-server-queue/<time>/`, beside
the export rather than in it, with `--chat`), signs in as the device and
records every stanza the server delivers:

- `queue_journal.jsonl` — every stanza exactly as received (after transport decryption), each payload
  decrypted, written and synced to disk before anything else happens;
- `queue_messages.json` — one row per message: chat, group / 1:1 / status / channel / broadcast, sender
  (with device number and phone number), time, type, text, reactions and edits with the message they
  apply to, deletions, media keys (downloadable while the links are valid), and view-once stubs.
  Edits sent in WhatsApp's newer encrypted form are decrypted when the original message is in the same
  capture (its secret is the key, as in WhatsApp Web); otherwise the row says the original is missing;
- `queue_summary.json` — counts, and whether the server's end-of-queue marker was received.

The capture runs first, and the export then folds the queue's messages into each chat's timeline —
`chats.json`, `transcripts.txt` and `msgstore.db` — every row marked `source: server-queue` beside the
browser's own `cache` rows (deduplicated on the message id; the browser's copy wins). Reactions, edits and
deletions stay in `queue_messages.json`, which names the message each one acts on.

**Nothing is acknowledged.** An acknowledgement is what makes the server delete a stanza from the
device's queue, so the queue is left exactly where it was: the next client that connects as this device
— the browser included — receives it all again, and decrypts it with its own unchanged state. Nothing a
contact can see is sent either: no delivery or read receipts, no presence. It is still a sign-in, recorded
as activity on the account.

**Close WhatsApp Web in the browser first.** The server allows one connection per device and the newer
one replaces the other; if that happens the capture stops, says why, and exits with code 6.

Group messages whose key handover a *previous* client took without keeping are left encrypted (and on
the server); they are counted as `not decrypted`. View-once content is never in the queue (see the table
above).

`WAWF_QUEUE_ACK=saved` acknowledges what was saved and fully decrypted — never use it on evidence that
the browser should still receive. `--history` uses the same journal and the same default.

## Recovering history older than the cache

A browser only ever holds the recent window WhatsApp synced to it (e.g. tens of thousands of messages) — *not* your whole history. `wawf <PROFILE> --history`
logs back in and asks your phone, per chat, for messages **older** than what's on disk, paging backward
toward each chat's start:

```bash
wawf <PROFILE> --history                             # pull only; results land in the device's folder (below)
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
D:\case\run1 already holds a cache export (2026-01-15 09:30, 12,345 messages). This run
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
are missing something** — for example 15 group chats out of 200, a request budget over 90%
smaller, which matters because the phone has to answer and WhatsApp rate-limits it.
It finds nothing new by design.

Where the profile cannot name a recovered sender at all, the name they chose for themselves is used
(`sender_source: history-pushname`) — better than a bare number, and still never a guess: the
address book wins where it has an entry.

It runs **iteratively**: each pass re-anchors every chat on the oldest message recovered so far and pulls
deeper, accumulating (deduped) until a pass stops finding meaningfully more. Progress is checkpointed to
`history_all.json` after every pass, so it is **crash-safe and resumable** — re-running
`wawf <PROFILE> --history` continues from where the last run left off (older than everything already
recovered) rather than re-pulling the same window.

**One folder per linked device.** Everything a history run keeps — the credentials and Signal state it
signs in with, the resume ledger, the per-chat state, the kept chunks and what the server delivered —
is in `devices/<account>-<device>/` inside `tools/reconnect/` (run from a checkout) or inside
`wawf-history/` beside the `.exe`. So an examination of one account never resumes, asks for, or exports
another account's history. Files an earlier version left directly in that folder move into their
device's own folder on its next run.

**What has to be recovered for this to work.** The phone's answer comes back as a normal end-to-end
encrypted message, so authenticating as the linked device is not enough — the Signal state has to come
with it. `wawf` reads it straight out of the profile (`signal-storage`, where WhatsApp Web keeps the
ratchet state in plaintext) and translates it into the serialisation the Node Signal stack expects:
the identity keypair and registration id, the signed prekey, every one-time prekey, the **Double
Ratchet sessions** (including superseded ones, kept closed, so older messages still decrypt) and the
**group sender keys**. Without the sessions every inbound payload fails to decrypt and is discarded
before it can be recognised as a history reply — indistinguishable from "the phone never answered".

A ratchet is live state, though, not a file: the copy in the profile is a snapshot that the phone has
already moved past. When the phone cannot decrypt a request sent on that snapshot it says so (a retry
receipt), and `wawf` starts a new session from the phone's keys and sends the request again on it. The
optional Node engine also asks any sender it cannot read to re-encrypt (a retry receipt carrying our
keys); the default Python engine, the one in the `.exe`, does not, so a message it cannot decrypt stays
unread. Either engine **persists everything it learns** in `signal_runtime.py.json` (`signal_runtime.json` for the Node engine) in
the device's folder, so the next run continues
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
cd tools/reconnect/devices/<account>-<device>    # the device's folder: the tools read their inputs here
node ../../diag_onehistory.js                    # ONE request, every inbound stanza logged
```

It separates causes that otherwise look identical: no ack means the stanza was never accepted (not a
cooldown), an explicit error means refused with a readable reason, and an ack then a notification
means served. An ack then silence is NOT, by itself, the phone declining: the commonest cause was an
offline queue the client had not finished pulling (below), with the phone's answer queued behind it.

#### How a history run proceeds

1. **Drain the offline queue.** On login the server announces everything pending for the device
   (`offline_preview`) and delivers it only in batches the client asks for. The client keeps asking
   until the server says delivery is finished (`<ib><offline/>`) — as WhatsApp Web does — and only
   then sends a history request. Anything that arrives later, including the phone's answers, is
   queued behind that backlog, so asking before it is drained gets no answer while you are
   connected. (The Baileys library asks for one batch of 100 and stops; with a ~2,000-item backlog
   that was the whole reason history appeared to stop working.)
2. **Ask, chat by chat**, skipping chats the phone has said are finished and asking chats that have
   stayed silent last (`history_chat_state.json` in the device's folder remembers both across runs).
3. **Each answer** is downloaded, decrypted and kept in `history_chunks/`. The default client leaves
   the server's copy where it is; with `HIST_CHUNK_DELETE=1` (and by default in the Node engine) it is
   then deleted from the server, the way WhatsApp Web releases it. The log records when the phone
   produced it.
4. **Before disconnecting**, if a request went unanswered the client waits for late answers.
   Answers that arrive on a later connection are still banked.

**Side effect.** Draining receives everything pending for the device slot. The default client acknowledges
nothing (`WAWF_HISTORY_ACK=none`), so the server delivers it again to the browser the next time it
connects. The Node engine acknowledges what it receives; while it rides the browser profile's
registration (unless `pair.js` has been run), those items are not redelivered to the browser.

Settings (environment variables, all optional):

| variable | default | what it does |
|---|---|---|
| `SETTLE_MAX_MS` | 300000 | longest wait for the queue to finish draining before asking anyway |
| `POST_MARKER_MAX_MS` | 30000 | after draining, how long to wait for the backlog to finish processing |
| `PLACEHOLDER_BUDGET` | 50 | cap on resend requests sent to the phone for undecryptable items, per run |
| `OFFLINE_BATCH` / `OFFLINE_MAX_BATCHES` | 100 / 2000 | batch size requested, and the cap on requests |
| `LATE_WAIT_MS` | 300000 | how long to stay connected for late answers |
| `PROBE_CHATS` | 4 | stop after this many silent chats in a row at the start |
| `HIST_CHUNK_DELETE` | off | `1` deletes each history file from WhatsApp's server after reading it, as WhatsApp Web does (the Node engine deletes by default). Either way the tool keeps the encrypted file as served (`history_chunks/<sha>.enc`, re-verifiable against the `fileEncSha256` in `received_journal.jsonl`) and its decrypted protobuf (`<sha>.pb.gz`) |

**What to expect.** On a healthy device the server acks in ~0.3s and a chunk of up to 50 messages
arrives ~3s later. A first pass over a few hundred chats takes tens of minutes; draining a long
history runs for hours and will sit idle for two hours at a time when the limit trips. Progress is
checkpointed after every page, so stopping it costs nothing.

The default engine is `scripts/history_extract.py`: the Noise handshake, the binary stanza format, the
Signal 1:1 session (X3DH + Double Ratchet) and the history-sync protobufs are implemented in Python, so
`--history` works from the standalone binary with nothing else installed. It reads and writes the same
work folder, checkpoints and `history_recovered.json` as the Node client, so a sweep can be continued
with either. The Python Signal code is checked against libsignal-node by `scripts/selftest_signal.py`
(sessions and session records handed between the two implementations) and the stanza encoder against
Baileys by `scripts/selftest_binary.py`.

`WAWF_HISTORY_ENGINE=node` runs the original Node client instead (needs Node +
`cd tools/reconnect && npm install`). Node is looked for in the places it actually lives: beside the tool (a `node-v*/` folder or
`node/node.exe`), on `PATH`, in the standard install directories, in nvm / nvs / scoop / chocolatey /
winget, and wherever `WAWF_NODE` points. Unzipping the official portable build next to the tool is
the least invasive option on an examination machine — nothing is installed and nothing is elevated.

### Other diagnostics

```bash
node tools/reconnect/pair.js           # one-time: link the tool as its OWN device (needs the phone)
python3 scripts/check_identity.py --profile <PROFILE> --dir tools/reconnect/devices/<account>-<device>
cd tools/reconnect/devices/<account>-<device>   # the tools below read this device's files from here
node ../../rehydrate_history.js --dry-run       # re-read kept chunks; what would change?
node ../../diag_health.js    # 60s: CONNECT / REGISTERED / SERVED, reported separately
node ../../diag_abprops.js   # which features the server has enabled for this client
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
    --out raw:case/raw --out sqlite:case/db        # + case/raw/wawf_audit.db (audit is on by default)
```

`<profile>` is a browser profile directory:

- **Firefox** — `.../<name>.default` (or use `--origin` for its `web.whatsapp.com` storage dir)
- **Chromium** — `~/.config/google-chrome/Default`, `~/.config/microsoft-edge/Default`, etc.
  (Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default`)

Every writer validates the key against on-disk ciphertext and refuses to write garbage if it is wrong.
Exit codes: `0` ok · `1` error (with `--history`: nothing recovered, or nothing could be asked) · `2` bad
usage or a refused combination (also a profile, `--origin` or store folder that does not exist, and a
`--chat` that names no chat or several) · `3` wrong key or an unusable `--key` file (missing, empty, not a
key), or nothing for `--history` / `--queue` to work from (no usable device credentials; with `--chat`, no
message to anchor a request on) · `4` a file the run needs was not found (a `--creds` file, or one that
vanished mid-run) · `6` the server ended a `--queue` capture early · `130` interrupted.

**Media.** Message media is recovered from the browser's own cache (Chromium simple-cache and
blockfile, Firefox CacheStorage and `cache2` — all four layouts verified byte-identical) and verified
against each message's `fileSha256`. Anything the browser never cached, or has since evicted, is not
on disk: those `mediaKey`s *are* exported in `message_media`, and `scripts/mediafetch.py --cdn` will
try the CDN. Note that a CDN url carries its own expiry — once it lapses every request is `403`, and
WhatsApp purges the object itself well before that, after which it returns `410` and the bytes are
gone server-side.

## Known issues

- **Messages the `.exe` cannot decrypt stay unread.** During `--history` the default Python engine (the
  one in the `.exe` and the Linux binary) never asks a sender to re-encrypt a message it cannot
  decrypt. Each such message is kept as received in `received_journal.jsonl` and counted at the end of
  the pass, but its text is not recovered. The Node engine (`WAWF_HISTORY_ENGINE=node`) does ask, so
  the sender can send it again. In the other direction it is the opposite: when the *phone* cannot
  decrypt a history request, the Python engine sends it again on a new Signal session, while the Node
  engine starts the new session but does not send the request again.
- **The phone's signed prekey signature is not checked.** When the Python engine starts a new Signal
  session with the phone (after the phone asks for a request again), it uses the signed prekey from
  the phone's key bundle without verifying that key's signature. The bundle comes from WhatsApp's
  server over the authenticated connection; libsignal (the Node engine) does verify it.
