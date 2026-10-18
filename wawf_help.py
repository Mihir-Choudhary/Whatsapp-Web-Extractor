"""Help text for the window: one short tip per control, one explanation per step, and a guide.

Kept apart from wawf_gui.py so the wording can be reviewed (and translated) without touching layout.
Every tip names the command-line option it sets, so what the window does can be repeated in a terminal.
"""

TIPS = {
    # step 1
    "profile_mode": "Point at a browser profile folder (Chrome/Edge/Brave/Opera/Vivaldi/… 'Default', 'Profile 1', "
                    "or a Firefox profile). A copied profile works; close the browser before copying it.",
    "stores_mode": "Use this when you have the WhatsApp stores but not the whole profile folder.\n"
                   "Command line: --idb / --local-storage / --media-cache (Firefox: --origin).",
    "profile_box": "Profiles on this computer that hold WhatsApp Web, from any Chromium- or Firefox-based "
                   "browser. Or type/paste a path, or use Browse.",
    "rescan": "Search this computer again for profiles holding WhatsApp Web.",
    "st_idb": "Chromium: the IndexedDB folder 'https_web.whatsapp.com_0.indexeddb.leveldb', or "
              "'WebStorage\\<n>\\IndexedDB' — or the folder around either.\n"
              "Firefox: 'storage\\default\\https+++web.whatsapp.com' (then Local Storage is not needed).\n"
              "Command line: --idb DIR (Firefox: --origin DIR).",
    "st_ls": "Chromium only: the profile's 'Local Storage' folder (or its 'leveldb'). It holds the key salt, "
             "the device keys and which account is signed in.\nCommand line: --local-storage DIR.",
    "st_cache": "Optional: a cache folder (CacheStorage, Cache_Data, Firefox cache2) to search for media "
                "WhatsApp Web had cached.\nCommand line: --media-cache DIR.",
    "account": "This profile holds more than one WhatsApp session -- for example an earlier login of a linked "
               "device and the one that replaced it. 'All sessions' exports each into its own folder; or pick one.\n"
               "Command line: (default: all) or --partition ACCOUNT:DEVICE.",
    # step 2
    "out": "Folder for everything this run writes: export\\ (chats), database\\ (SQLite), raw\\, the log and "
           "the chain-of-custody database. A new folder per case is best.",
    "fmt_text": "transcripts.txt (readable chats), chats.json (every message with all fields), "
                "identities.json (who is who: number ↔ lid ↔ name), contacts.csv.\nCommand line: --out DIR.",
    "fmt_sqlite": "msgstore.db + wa.db in the Android WhatsApp layout, for SQLite viewers and Android "
                  "WhatsApp tools (e.g. WAInsight), plus recovered media.\nCommand line: --out sqlite:DIR.",
    "fmt_raw": "Every IndexedDB store exactly as the browser kept it, one JSONL file per store, with the "
               "decryption added beside each record. For verification and research.\nCommand line: --out raw:DIR.",
    "fetch_media": "Download from WhatsApp's servers the photos/videos/documents the browser never cached, decrypt "
                   "them with each message's own key and verify their hash. Online; newest first; links that have "
                   "expired are skipped.\nCommand line: --fetch-media.",
    "history": "Sign in as the linked device and ask the phone for messages older than the browser's ~90 days, "
               "chat by chat. The phone must be reachable (it answers in the background, sometimes after "
               "minutes); a full sweep can take hours; recorded as account activity.\nCommand line: --history.",
    "queue": "While the browser is closed, WhatsApp's server holds for this device what the account receives "
             "(messages, group and status updates, receipts, call offers). This signs in as the device and "
             "records it all, decrypted with the browser's own keys, into server-queue\\ in the results folder "
             "(with 'Only these chats': beside the export, in a folder ending -server-queue\\, since it holds "
             "every chat). "
             "Nothing is acknowledged, so the server keeps it for the browser; nothing a contact can see is "
             "sent. View-once media is never sent to linked devices: only a placeholder is recorded. "
             "Close WhatsApp Web in the browser first: one connection per device, the newer one wins.\n"
             "Command line: --queue.",
    # step 3
    "key_online": "Message text is encrypted with a key WhatsApp gives the browser at sign-in. This signs in once "
                  "as the linked device to get it, and saves it as companion_enc_static.txt in the results "
                  "folder.\nCommand line: (default).",
    "key_file": "Use companion_enc_static.txt saved by an earlier run of this tool: decrypts without going "
                "online. Each linked device has its own key -- a profile with an earlier and a newer login needs "
                "one for each; choose several files (each session uses the one that opens it).\n"
                "Command line: --key FILE [--key FILE ...] --offline.",
    "key_offline": "Never contact WhatsApp. Without a key everything except message text is exported "
                   "(chats, senders, times, types, media, reactions, polls, calls, contacts, groups).\n"
                   "Command line: --offline.",
    "chat": "Export, and ask the phone about, these conversations only: a contact or group name, a phone "
            "number with its country code, a lid or a jid; separate several with ;. A name that fits more "
            "than one chat, or none, stops the run and lists the candidates.\nCommand line: --chat WHO "
            "[--chat WHO ...].",
    # step 4
    "case_id": "Case or exhibit number, stored in the chain-of-custody database.\nCommand line: --case-id ID.",
    "examiner": "Who ran this; stored with the case and with each run.\nCommand line: --examiner NAME.",
    "case_notes": "Free text stored with the case (item description, warrant, …).\nCommand line: --case-notes TEXT.",
    "audit_on": "wawf_audit.db records every step, every file read with its SHA-256, what was decrypted with "
                "which key (by fingerprint) and every output with its hash.",
    "audit_secrets": "Also store the raw key values in wawf_audit.db (normally only fingerprints). That database "
                     "then decrypts the evidence; protect it.\nCommand line: --audit-secrets.",
    "audit_off": "Write no chain-of-custody database.\nCommand line: --no-audit.",
    # advanced
    "refetch": "History: re-ask only the chats whose recovered messages lack a sender, instead of going "
               "further back.\nCommand line: --history-refetch.",
    "install_node": "Only for the optional Node history engine (WAWF_HISTORY_ENGINE=node): allow installing "
                    "Node.js with winget if none is found. The default engine needs no Node.\n"
                    "Command line: --install-node.",
    "raw_keys": "Also dump the Signal state and the key store into the raw dump. That dump is then key material; "
                "never share it.\nCommand line: --raw-include-keys.",
    "creds": "creds_in.json saved by an earlier run: reuse the device credentials instead of recovering them "
             "again.\nCommand line: --creds FILE.",
    "verbose": "Write full detail and tracebacks to the log.\nCommand line: -v.",
    "list_sessions": "Read the profile and list every WhatsApp session in it (account, messages, key present), "
                     "without exporting anything.\nCommand line: --list-partitions.",
    # bottom
    "cmd": "The exact command this window will run. Copy it to repeat the run in a terminal or to put it in a "
           "report.",
    "start": "Start the run. Reading a large profile takes several minutes before anything is written.",
}

STEPS = {
    "1": ("Browser data",
          "What to examine.\n\n"
          "• Profile folder — the browser's profile ('Default', 'Profile 1', …) or a copy of it. Close the browser "
          "before copying: a profile copied while the browser runs comes out damaged (the tool still reads what "
          "survived and reports what did not).\n\n"
          "• Separate folders — only the WhatsApp stores, wherever they are: the IndexedDB folder and the "
          "'Local Storage' folder (Chromium), or the 'https+++web.whatsapp.com' folder (Firefox).\n\n"
          "The tool works out the browser, its version and where the profile originally lived from the folder's "
          "own files, and records that."),
    "2": ("Save results to",
          "Where the results go and in which forms. Readable chats + JSON are for reading and scripting; the SQLite "
          "database follows the Android WhatsApp layout; the raw dump is the store itself plus its decryption.\n\n"
          "Optional, online: download media the browser never cached, recover history older than the "
          "browser's ~90 days from the phone, and record what WhatsApp's server is holding for the device.\n\n"
          "Only these chats: export (and ask the phone about) the named conversations only — a contact or group "
          "name, a phone number with its country code, a lid or a jid, several separated by ;. A name that fits "
          "more than one chat, or none, stops the run and lists the candidates."),
    "3": ("Message key",
          "WhatsApp Web encrypts message text with a key the server gives the browser at sign-in; the browser "
          "never writes that key to disk.\n\n"
          "• Get it from WhatsApp — signs in once as the linked device (online, recorded as activity on the "
          "account) and saves it as companion_enc_static.txt.\n"
          "• Use a saved key — that file from an earlier run; nothing goes online.\n"
          "• Don't go online — everything except message text.\n\n"
          "companion_enc_static.txt and creds_in.json in the results folder are key material: remove them before "
          "an export is shared."),
    "4": ("Case (chain of custody)",
          "The case number, examiner and notes are written to wawf_audit.db in the results folder, together with "
          "every step the tool took, every file it read (with SHA-256), what was decrypted with which key "
          "(fingerprint only) and every output with its hash. Running again into the same folder adds a run to the "
          "same case."),
}

GUIDE = """WhatsApp Web Extractor — how to use the window

QUICK START
 1. Browser data: pick the profile (or a copied profile folder, or the stores on their own).
 2. Save results to: choose a new folder for this case; keep "Readable chats + JSON" and "SQLite database".
 3. Message key: "Get it from WhatsApp" the first time; next time choose the saved key to stay offline.
 4. Case: fill in the case number and your name.
 Press Start. The log shows progress; "Open results folder" when it is done.

WHAT YOU GET (in the results folder)
 export\\transcripts.txt   every chat, readable, every line names its sender
 export\\chats.json        every message with all its fields (links, locations, polls, ticks, …)
 export\\identities.json   who is who: phone number ↔ lid ↔ name, groups and their members
 export\\contacts.csv      the contact list, opens in Excel
 database\\msgstore.db     Android WhatsApp layout (chats, messages, groups, calls, receipts, media)
 database\\wa.db           contacts in the Android layout;  database\\Media\\  recovered media
 wawf_audit.db            chain of custody;  wawf.log  the full log

WHAT A BROWSER HOLDS — AND WHAT IT DOES NOT
 • Messages: roughly the last 90 days per chat, as WhatsApp sent them when the browser was linked.
   Older history: tick "recover history … from the phone".
 • Ticks (sent / delivered / read / played) for messages sent from the account.
 • Who read a message when: only for messages whose "Message info" was opened in the browser.
 • Calls: the recent window only.  Statuses: not kept by WhatsApp Web.
 • Media: keys for everything; the files only if cached, or downloaded while their links are valid.

ONLINE OR NOT
 Nothing goes online unless you choose "Get it from WhatsApp", "download media", "recover history" or
 "record what WhatsApp's server is holding".
 Signing in uses a client WhatsApp did not write. That is against WhatsApp's Terms of Service, and
 WhatsApp has banned accounts for using unofficial clients. If the account must not be put at risk,
 use a saved key or don't go online.

KEY MATERIAL
 companion_enc_static.txt and creds_in.json (in the results folder), a raw dump with key material, and an
 audit database "including raw key values" can decrypt the evidence or sign in as the device. Keep them
 with the case; remove them before sharing an export.

THE COMMAND LINE
 Every run from this window is an ordinary command-line run: the box above Start shows it, and Copy puts it
 on the clipboard. "wawf -h" lists every option. Hover over any option here to see which one it sets.

Use only on accounts you own or are authorised to examine.
"""
