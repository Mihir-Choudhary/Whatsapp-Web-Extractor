[← Back to the README](../README.md)

# Running wawf

How to point it at the evidence, every option, and what the exit codes mean. For a first run, the [Quick start](../README.md#quick-start) is enough.

## Acquiring the profile

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

## No profile folder? Point at the stores

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

## Where the profile came from

A profile folder can be copied anywhere and renamed, so the tool reads its origin from the folder's
own files and records it in the audit trail: the browser (files only that browser writes), the version
that last wrote it, the label the browser showed for it, and the **original path**. Every Chromium
LevelDB keeps a `LOG` whose lines carry the absolute path it was opened at, so:

```
profile: Microsoft Edge 154.0.4258.62, originally C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Profile 8, labelled 'Profile 9' in the browser
```

The label and the folder name are different things. Stores passed with
`--idb`/`--local-storage` are traced the same way, from their own `LOG` files.

## Options

| Option | What it does |
|---|---|
| `--key FILE` | A `companion_enc_static.txt` captured earlier — decrypt without touching the network (see [Where the key comes from](key.md)). Usually unnecessary: a copy left beside the output is found automatically. A **file**, never the key itself, so no secret reaches your shell history, process list or command auditing. |
| `--offline` | Never contact WhatsApp. Decrypts with `--key` (or a key file found beside the output); with no key, exports **everything except message text** — chats, senders, timestamps, types, media keys and cached media, reactions, polls, calls, contacts, groups. |
| `--chat WHO` | Only this conversation: a contact or group name, a phone number with its country code, a lid or a jid; repeat for several. The export holds those chats only and `--history` asks the phone about those chats only — see [One conversation only](#one-conversation-only----chat). |
| `--partition WHICH` | When a profile holds more than one WhatsApp session: the account number, storage key or layout name to examine. |
| `--list-partitions` | List every WhatsApp session in the profile (account, messages, key present) and stop. |
| `--origin DIR` | Firefox `web.whatsapp.com` storage folder instead of a profile folder. |
| `--raw-include-keys` | With `--out raw:` — also dump `signal-storage` and `wawc_db_enc`. Those are key material; a dump including them must not travel with a case. |
| `--history` | **Also** pull chat history older than the browser cache from your phone, iteratively, resuming across runs, and append it to the export. Pure Python, no Node needed. Phone-side and rate-limited — see [Recovering older history](history.md). |
| `--queue` | After the export, record what WhatsApp's server is holding for this device, decrypted with the browser's own keys, into `<out>/server-queue/<time>/` (with `--chat`, beside it: `<out>-server-queue/<time>/`). Networked; acknowledges nothing, so the queue stays for the browser. See [Recording what the server is holding](server-queue.md). |
| `--fetch-media` | With `--out sqlite:PATH` (with or without `--history`): download, decrypt and verify from the CDN the media the browser never cached, newest first. Networked, and it downloads real bytes — a large account can be a lot of them. Urls whose signature has already expired are skipped without a request. |
| `--history-refetch` | With `--history`: re-ask for history already recovered, to fill in fields an earlier run did not capture (the group sender). Finds nothing new by design. |
| `--install-node` | Only with the optional Node engine (`WAWF_HISTORY_ENGINE=node`): allow `--history` to install Node.js via winget when none is found. **Not** covered by `--yes`: it modifies the machine and asks for elevation. A portable Node unzipped beside the tool, or `WAWF_NODE` pointing at one, needs neither. |
| `--no-audit` | Do **not** write the chain-of-custody database. It is written by default (see [Chain of custody](chain-of-custody.md)). |
| `-v`, `--log-file FILE` | Full logs and tracebacks; mirror them to a file. |
| `--version` | Print the version — the release, plus the git commit when run from a checkout — the same string the export receipts and the audit database record. |

Sender resolution is **reported, not assumed** — a run prints where every label came from, so the one
number that matters is visible:

```
senders identified: address-book=8,120  pushname=3,410  phone=212  unresolved=0
```

`unresolved` counts messages from jids the profile itself holds no name and no number for. On a
healthy profile it is zero; anything else is a gap in the evidence, not a gap in the tool.

## One conversation only — `--chat`

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

## Examples

On Windows, swap `python3 wawf.py` for `wawf-windows-x64.exe`.

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

---

[← Back to the README](../README.md)
