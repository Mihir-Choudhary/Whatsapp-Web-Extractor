[← Back to the README](../README.md)

# Where the key comes from

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

---

[← Back to the README](../README.md)
