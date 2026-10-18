[← Back to the README](../README.md)

# Recording what the server is holding — `--queue`

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
the server); they are counted as `not decrypted`. View-once content is never in the queue (see [What a browser holds](browser-contents.md)).

`WAWF_QUEUE_ACK=saved` acknowledges what was saved and fully decrypted — never use it on evidence that
the browser should still receive. `--history` uses the same journal and the same default.

---

[← Back to the README](../README.md)
