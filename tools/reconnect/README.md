# reconnect (Node/Baileys helpers)

Reconnect to WhatsApp using disk-recovered credentials.

> **For just the key, you don't need this Node client anymore.** `wawf <PROFILE>` does the
> WhatsApp Noise handshake in pure Python (no Node, no `npm install`) and runs from the standalone `.exe`.
> On-demand **history sync** (capability **2** below) is pure Python by default too
> (`scripts/history_extract.py`). This directory is the optional Node engine for it
> (`WAWF_HISTORY_ENGINE=node`), plus the `diag_*.js` diagnostics and `pair.js`.

## 1. Capture the decryption key (`companion_enc_static`) — *Node alternative to `wawf <PROFILE>`*

    npm install                                        # @whiskeysockets/baileys
    python3 ../../scripts/export_baileys_creds.py      # -> creds_in.json (gitignored)
    node reconnect.js                                  # LIVE: writes companion_enc_static.txt

## 2. Recover chat history the browser never cached (on-demand history sync)

> **The easy path is `wawf <PROFILE> --history`** — it recovers creds + Signal state + anchors and then
> drives the history client **iteratively** (re-anchoring deeper each pass, resuming across runs) for you,
> keeping each linked device's files in `devices/<account>-<device>/` here. The manual steps below run
> this Node client by hand, and need `npm install` here first.

A linked device can ask the phone for messages **older than** what it has cached. To decrypt the
phone's E2E responses you need the on-disk **Signal state** (device identity key + prekeys), which
`export_signal_state.py` recovers (the identity key is an AES-CTR-wrapped CryptoKey in
`signal-meta-store`; prekeys are plaintext). Works for Firefox (`--origin`) and Chromium (`--profile`).

    python3 ../../scripts/export_baileys_creds.py   --profile <chromium dir>   # creds_in.json
    python3 ../../scripts/export_signal_state.py     --profile <chromium dir>   # signal_state.json
    # build anchors.json (oldest cached message per chat + on-disk id set) — see STATE/BLOG for the snippet
    node history_extract.js                          # LIVE: paginates on-demand history per chat

`history_extract.js` loads the full Signal state into Baileys so E2E decrypts, then for each chat
repeatedly fetches older messages (re-anchoring on each page's oldest), downloads+decrypts each
`HistorySync` blob in-process (HKDF "WhatsApp History Keys" + AES-CBC + zlib), and writes the
recovered messages not already on disk to `history_recovered.json`. `fetch_history_blobs.py` does the
same download/decrypt/parse offline from captured notification params.

Env: `TOP` (chats), `COUNT` (per page), `MAXPAGES` (per chat).

**Proven:** recovered real messages absent from a Chrome profile (older than its cache), verified by
both media hashes. **Caveat:** on-demand serving is **phone-side and intermittent** — the primary phone
must be online/active, and WhatsApp appears to rate-limit it, so a run may return nothing and a later
run succeed. Anchoring on a chat's oldest cached message only yields data when the phone retains messages
older than that.

## Safety
`creds_in.json`, `signal_state.json`, `companion_enc_static.txt`, `anchors.json`, `history_*.json` are
all gitignored — they contain live account material (keys, identity, message content). This connects to
WhatsApp as your linked device: it registers device activity and may bump a live web session; **repeated
reconnects can get the device unlinked** (observed). Own account or authorized investigation only.
