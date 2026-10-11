# -*- mode: python ; coding: utf-8 -*-
# STANDALONE build: like wawf.spec, but ALSO bundles Node.js + the tools/reconnect Baileys client, so
# `wawf history` works with NO external Node install. Produces one large single-file dist/wawf-standalone(.exe).
# (Trade-off: ~150 MB, and a onefile re-extracts its whole payload on every launch, so ALL commands start
#  slower. Prefer the lean wawf.spec for day-to-day use.)
#
# Point WAWF_NODE_EXE at a portable node(.exe) to bundle, then:
#   pyinstaller wawf-standalone.spec
import glob, os
from PyInstaller.utils.hooks import collect_all, collect_submodules
from PyInstaller.building.datastruct import Tree

datas, binaries, hiddenimports = [], [], []
for pkg in ("ccl_chromium_reader", "cramjam", "websocket"):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h
hiddenimports += collect_submodules("cryptography")
datas += [(f, "scripts") for f in glob.glob("scripts/*.py")]
datas += [("assets/wawf.png", "assets")]          # window icon for the GUI

# --- bundle Node.js (a single portable node executable) at node/node(.exe) ---
NODE_EXE = os.environ.get("WAWF_NODE_EXE")
if not NODE_EXE or not os.path.isfile(NODE_EXE):
    raise SystemExit("wawf-standalone.spec: set WAWF_NODE_EXE to the path of a portable node(.exe) to bundle")
datas += [(NODE_EXE, "node")]

# --- bundle the Node client (history_extract.js + reconnect.js + node_modules), minus secrets/outputs ---
recon = Tree("tools/reconnect", prefix="tools/reconnect",
             excludes=["creds_in.json", "signal_state.json", "signal_runtime.json",
                       "anchors.json", "notifs.json",
                       "history_*.json", "*.tmp", "*.log", "baileys.log"])

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
a.datas += recon
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="wawf-standalone",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    runtime_tmpdir=None, console=True, icon="assets/wawf.ico", disable_windowed_traceback=False,
)
