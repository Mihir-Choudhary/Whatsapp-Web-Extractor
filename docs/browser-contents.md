[← Back to the README](../README.md)

# What a browser holds — and what it does not

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
| **What the server is holding** | not on disk until the browser next connects | `--queue` records it — see [Recording what the server is holding](server-queue.md) |
| History before the link | not on disk | each history chunk is downloaded once and deleted from the server; a network log of the sync shows the downloads but cannot be decrypted after the fact (its keys never leave the browser's memory) |

Where the browser has less, that is the browser's content, not a reading gap: the
export says so in its counts and in `body_status`, rather than filling anything in.

---

[← Back to the README](../README.md)
