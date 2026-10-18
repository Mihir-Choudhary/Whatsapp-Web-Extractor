[← Back to the README](../README.md)

# Output formats — `--out [FORMAT:]PATH`

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

## Who sent it

Every message names its sender. WhatsApp addresses one person three ways — `<phone>@c.us` (UI form),
`<phone>@s.whatsapp.net` (the same phone, wire form) and `<lid>@lid` (an account alias, which is what
recent messages actually carry) — so a transcript that printed the raw field would be unreadable, and
one that printed "me / them" would be unusable. Both are resolved against the examined profile's own
`contact` and `group-metadata` stores:

```
===== Weekend plans  [120363000000000000@g.us]  (group; 412 msgs, 377 with text) =====
  - Kai                       244358000000001@lid  919300000001@c.us
  - Riya                      133461000000002@lid  919300000002@c.us  (me)
[2026-07-03 00:50:37] ->                   Riya: We should try bowling sometime
[2026-07-03 00:51:02] <-                    Kai: next weekend?
[2026-07-03 00:51:40] <-                    Kai: (sticker)
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

## Checking an export

```bash
python3 scripts/validate_export.py D:\case\out              # transcript + JSON
python3 scripts/validate_export.py D:\case\out D:\case\db   # ...and the database
```

Checks the artifacts against each other and against their own headers: that every sender resolves,
that the counts in each chat header match the lines beneath it and the records in `chats.json`, that
nothing is duplicated, that no message content sits where structure does, and that the Android
correlation chain resolves end to end. Useful after any change to the writers, or to satisfy
yourself that an export you were handed is internally consistent. It writes nothing.

## `raw` — decrypt, and change nothing else

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
byte-for-byte identical to one already taken (a few dozen in a typical profile) and keep
any version that actually differs. So `raw` legitimately shows a few more records than `chats.json`
has rows; the difference is duplicates, not content.

A `_manifest.json` records per-store counts, the derivation used, and what every marker means. The key
is validated against 40 reference bodies before anything is written, so a wrong or stale key produces
a clear refusal instead of a complete-looking dump with nothing decrypted in it.

`signal-storage` and `wawc_db_enc` are **excluded by default** — they hold the account's Signal
sessions, prekeys and the at-rest root key, and a dump meant to travel with a case should not be key
material. `--raw-include-keys` overrides that.

A Windows drive letter is never mistaken for a `FORMAT`, so `D:\case\out` works as you'd expect.

## Media

Message media is recovered from the browser's own cache (Chromium simple-cache and
blockfile, Firefox CacheStorage and `cache2` — all four layouts verified byte-identical) and verified
against each message's `fileSha256`. Anything the browser never cached, or has since evicted, is not
on disk: those `mediaKey`s *are* exported in `message_media`, and `scripts/mediafetch.py --cdn` will
try the CDN. Note that a CDN url carries its own expiry — once it lapses every request is `403`, and
WhatsApp purges the object itself well before that, after which it returns `410` and the bytes are
gone server-side.

---

[← Back to the README](../README.md)
