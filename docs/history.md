[← Back to the README](../README.md)

# Recovering history older than the cache

A browser only ever holds the recent window WhatsApp synced to it (e.g. tens of thousands of messages) — *not* your whole history. `wawf <PROFILE> --history`
logs back in and asks your phone, per chat, for messages **older** than what's on disk, paging backward
toward each chat's start:

```bash
wawf <PROFILE> --history                             # pull only; results land in the device's folder (below)
wawf <PROFILE> --history --out D:\case\run2          # ...and export the local store WITH them merged
wawf <PROFILE> --history --out sqlite:D:\case\run2 --fetch-media    # ...and try the CDN for their media
```

## What `--history --out` produces

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

## How a history run proceeds

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

## Other diagnostics

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

---

[← Back to the README](../README.md)
