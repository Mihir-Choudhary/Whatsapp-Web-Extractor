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
- `decrypt` offline — root-key extraction on both Firefox and Chrome profiles (tens of thousands of msgs)
- `decrypt --enc-static <correct>` — key validated against on-disk ciphertext, all bodies decrypted, 0 failed
- `decrypt --enc-static <wrong>`   — rejected (exit 3), no output written
- `creds` — Noise keypair X25519-verified, account identity recovered
- `sqlite` — parse + key-validate pipeline, refuses a wrong key (exit 3), writes nothing on rejection
- frozen `.exe`: `_runpy` dispatch (`sqlite`/`memory`), `history` guard, `memory` EOF/platform handling
- exit codes: 0 ok · 1 error · 2 usage · 3 wrong key · 4 file-not-found

## Windows blocks the binary it just built

The exe is unsigned, and on a machine with **Smart App Control** enabled Windows refuses to run it:

```
Program 'wawf.exe' failed to run: An Application Control policy has blocked this file
```

This is reputation-based, not signature-based, so it hits a *freshly built* binary specifically.
Observed on one machine during a single session: two earlier builds ran fine while the newest was
blocked, with `(Get-MpComputerStatus).SmartAppControlState` reporting `On`. Nothing about the build
changed between them except that the last one had never been seen before.

It matters for distribution, not just for building: anyone downloading a release binary onto a Smart
App Control machine can hit the same thing, and the message does not mention the tool at all.

Ways round it, in the order worth trying:

* run from source instead (`pip install -r requirements.txt && python wawf.py ...`) -- no binary, no
  policy to satisfy, and in a forensic context arguably the better provenance anyway;
* check `SmartAppControlState`: once it is `On` it cannot be re-enabled after being turned off, so
  turning it off is a one-way decision about the whole machine and not one to make casually;
* sign the binary with a certificate the machine trusts, which is the only real fix for distribution.

A blocked launch is an OS policy decision and says nothing about whether the build is good: verify a
build by running it from source, or on a machine without the policy.
