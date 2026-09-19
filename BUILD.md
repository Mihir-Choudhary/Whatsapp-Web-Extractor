# Building `wawf` as a standalone CLI / `.exe`

`wawf.py` is a single-entry CLI that packages to one self-contained executable with
[PyInstaller](https://pyinstaller.org). No Python install is needed on the target machine.

## Prerequisites
```bash
pip install pyinstaller cryptography cramjam websocket-client
pip install "git+https://github.com/cclgroupltd/ccl_chromium_reader.git"   # Chromium/Chrome/Edge reader
```

## Build (onefile)
```bash
pyinstaller wawf.spec --noconfirm
```
Output:
- Linux / macOS: `dist/wawf`
- Windows:       `dist\wawf.exe`

Run it directly, e.g. `./dist/wawf decrypt <profile> --enc-static <b64> -v` or `dist\wawf.exe creds <profile>`.

> **Build on the OS you target.** PyInstaller does not cross-compile. To produce
> `wawf.exe`, run the same `pyinstaller wawf.spec` command on Windows (or in a Windows VM /
> CI runner). The spec file itself is OS-agnostic.

## What the spec bundles
- `ccl_chromium_reader` + `cramjam` (pure-python Snappy) + `websocket-client` via `collect_all` — the
  Chromium reader, Snappy, and the WebSocket client `reconnect` uses, all imported dynamically.
- All of `scripts/*.py` as data under `scripts/`. At runtime `wawf` inserts that dir on
  `sys.path`, so `chromium_reader`, `wa_decrypt`, `export_baileys_creds`, `wa_reconnect`
  (+ its `_wa_tokens` tables), `snappy_pure`, `sclone` import normally.
- `cryptography` submodules via `collect_submodules`.

The full **reconnect** (pure-Python WhatsApp Noise handshake → `companion_enc_static`) is therefore in
the `.exe` — no Node needed. The Node/Baileys client under `tools/reconnect/` is *not* bundled; it exists
only for the extra on-demand history-sync capability and needs its own `npm install`.

## Helper-script dispatch when frozen
`memory`, `sqlite`, and `reconnect` shell out to helper scripts that own their own argparse
(`wa_forensic.py`, `export_sqlite.py`, `wa_reconnect.py`). A onefile binary can't execute a loose `.py`, so
`wawf` re-execs itself with a hidden `_runpy` verb (`<exe> _runpy <script> [args…]`) and runs
the helper's `__main__` in-process via `runpy`. In dev mode it just runs
`python scripts/<script>` directly. This is transparent to the user.

## Verified (Linux onefile, PyInstaller 6.22.2, Python 3.14)
- `wawf --help`, subcommand help, clean argparse errors
- `decrypt` offline — root-key extraction for Firefox (51,577 msgs) and Chrome (23,481 msgs)
- `decrypt --enc-static <correct>` — validated 40/40, all bodies decrypted, 0 failed
- `decrypt --enc-static <wrong>`   — rejected (exit 3), no output written
- `creds` — Noise keypair X25519-verified, account identity recovered
- exit codes: 0 ok · 1 error · 2 usage · 3 wrong key · 4 file-not-found
