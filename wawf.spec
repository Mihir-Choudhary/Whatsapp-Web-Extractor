# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the wawf unified CLI (onefile). Build:  pyinstaller wawf.spec
# Produces dist/wawf (Linux) or dist/wawf.exe (Windows). See BUILD.md for the Windows note.
import glob, os
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas, binaries, hiddenimports = [], [], []

# Third-party packages the helpers import dynamically (not visible to static analysis).
# websocket = websocket-client, used by wa_reconnect.py for the pure-Python Noise reconnect.
for pkg in ("ccl_chromium_reader", "cramjam", "websocket"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
hiddenimports += collect_submodules("cryptography")

# The helper scripts are bundled as DATA and executed through runpy, so PyInstaller never analyses
# their imports. A bare `import urllib` would be bundled; `import urllib.request` is not, and the
# frozen build then died with ModuleNotFoundError the moment it tried to reconnect -- which is the
# exe's DEFAULT job, so the binary could not capture its own at-rest key. Found by actually running
# the exe rather than the scripts. Checked across every bundled script: urllib.request is the only
# stdlib submodule in that position (wa_reconnect.py, mediafetch.py, fetch_history_blobs.py);
# urllib.error rides along with it and is named explicitly so it cannot be dropped either.
hiddenimports += ["urllib.request", "urllib.error"]

# Bundle every helper script as data so runpy + the runtime sys.path insert resolve them
# (chromium_reader, wa_decrypt, export_baileys_creds, wa_forensic, export_sqlite,
#  wa_reconnect + _wa_tokens, snappy_pure*, sclone, ...). They live under _MEIPASS/scripts at runtime.
datas += [(f, "scripts") for f in glob.glob("scripts/*.py")]
datas += [("assets/wawf.png", "assets")]          # window icon for the GUI

a = Analysis(
    ["wawf.py"],
    pathex=["scripts"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["PySide6", "PyQt5", "matplotlib", "numpy.testing"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="wawf",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    runtime_tmpdir=None, console=True, icon="assets/wawf.ico", disable_windowed_traceback=False,
)
