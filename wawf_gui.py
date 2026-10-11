"""wawf_gui.py — a small window in front of the wawf command line.

It builds the same command a user would type and runs it, streaming the output into the window, so
the GUI and the CLI cannot drift apart: every run is an ordinary CLI run, with the same audit trail.
Standard library only (tkinter).
"""
from __future__ import annotations
import os, sys, glob, queue, subprocess, threading, datetime as dt

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

HERE = os.path.dirname(os.path.abspath(__file__))

# palette: WhatsApp Web's own light theme -- panel grey, white cards, its text greys and greens
# (white on #008069 and #111B21 on #F0F2F5 both clear 4.5:1)
BG, CARD, FG, MUTED, BORDER = "#F0F2F5", "#FFFFFF", "#111B21", "#54656F", "#E9EDEF"
PRIMARY, ACTION, ACTION_HOVER, DANGER = "#008069", "#008069", "#006E5A", "#C0392B"
HEADER, LOG_BG, LOG_FG = "#00A884", "#0B141A", "#E9EDEF"
FONT = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_TITLE = ("Segoe UI Semibold", 15)
FONT_LABEL = ("Segoe UI Semibold", 10)
FONT_MONO = ("Consolas", 9)


# ---------------------------------------------------------------- profile discovery
def _browser_roots():
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        la = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        ad = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        chromium = [("Edge", os.path.join(la, "Microsoft", "Edge", "User Data")),
                    ("Chrome", os.path.join(la, "Google", "Chrome", "User Data")),
                    ("Brave", os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data")),
                    ("Vivaldi", os.path.join(la, "Vivaldi", "User Data")),
                    ("Opera", os.path.join(ad, "Opera Software"))]
        firefox = os.path.join(ad, "Mozilla", "Firefox", "Profiles")
    elif sys.platform == "darwin":
        a = os.path.join(home, "Library", "Application Support")
        chromium = [("Chrome", os.path.join(a, "Google", "Chrome")), ("Edge", os.path.join(a, "Microsoft Edge")),
                    ("Brave", os.path.join(a, "BraveSoftware", "Brave-Browser"))]
        firefox = os.path.join(a, "Firefox", "Profiles")
    else:
        c = os.path.join(home, ".config")
        chromium = [("Chrome", os.path.join(c, "google-chrome")), ("Edge", os.path.join(c, "microsoft-edge")),
                    ("Chromium", os.path.join(c, "chromium")), ("Brave", os.path.join(c, "BraveSoftware", "Brave-Browser"))]
        firefox = os.path.join(home, ".mozilla", "firefox")
    return chromium, firefox

def find_profiles():
    """[(label, path)] for every local browser profile that holds WhatsApp Web storage."""
    out = []
    chromium, firefox = _browser_roots()
    for name, root in chromium:
        for prof in sorted(glob.glob(os.path.join(root, "*"))):
            if not os.path.isdir(prof): continue
            legacy = os.path.join(prof, "IndexedDB", "https_web.whatsapp.com_0.indexeddb.leveldb")
            ls = os.path.join(prof, "Local Storage", "leveldb")
            has_ws = os.path.isdir(os.path.join(prof, "WebStorage"))
            if os.path.isdir(legacy) or (has_ws and os.path.isdir(ls) and _ls_mentions_wa(ls)):
                out.append((f"{name}  ·  {os.path.basename(prof)}", prof))
    for prof in sorted(glob.glob(os.path.join(firefox, "*"))):
        if os.path.isdir(os.path.join(prof, "storage", "default", "https+++web.whatsapp.com")):
            out.append((f"Firefox  ·  {os.path.basename(prof)}", prof))
    return out

def _ls_mentions_wa(ls_dir):
    """Cheap check (no parsing): does this profile's localStorage hold any web.whatsapp.com key?"""
    for f in glob.glob(os.path.join(ls_dir, "*.l*")):
        try:
            with open(f, "rb") as fh:
                if b"web.whatsapp.com" in fh.read(): return True
        except OSError:
            pass
    return False

def profile_summary(profile):
    """Browser, version and original location, read from the folder's own files (see profile_identity)."""
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import profile_identity as pi
        return pi.summary(pi.identify(profile))
    except Exception:
        return ""

def session_accounts(profile):
    """[(account, storage key)] of every signed-in WhatsApp session in a Chromium profile. Reads only
    localStorage (small), so it is fast enough to run when a profile is picked."""
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import chromium_reader as cr
        if not cr.is_chromium_profile(profile): return []
        out = []
        for sk, ls in cr.read_localstorage_all(profile).items():
            acct = cr._account(ls)
            if acct: out.append((acct, sk))
        cr.cleanup()
        return out
    except Exception:
        return []

# ---------------------------------------------------------------- drawn selection indicators
def _indicator(root, size, kind, on):
    """A check box or radio indicator drawn into a PhotoImage, anti-aliased by 4x4 supersampling.
    Themed ttk indicators ignore colours on Windows, and an indicator that does not show its state
    is worse than none -- so these are drawn: WhatsApp green filled with a white mark when on, a
    grey outline (3:1 against white) when off."""
    img = tk.PhotoImage(master=root, width=size, height=size)
    def rgb(h): return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))
    green, grey, white, card = rgb(ACTION), rgb("#8696A0"), (255, 255, 255), rgb(CARD)
    r = size / 2.0; stroke = max(1.5, size / 10)
    def colour(x, y):
        if kind == "radio":
            d = ((x - r) ** 2 + (y - r) ** 2) ** 0.5
            if d > r - 0.5: return None
            if not on: return grey if d > r - 0.5 - stroke else card
            if d > r - 0.5 - stroke: return green
            return green if d < r * 0.45 else white
        rad = size * 0.22; m = 0.5
        qx = min(max(x, m + rad), size - m - rad); qy = min(max(y, m + rad), size - m - rad)
        if ((x - qx) ** 2 + (y - qy) ** 2) ** 0.5 > rad: return None
        if not on:
            inner = rad - stroke
            px = min(max(x, m + stroke + inner), size - m - stroke - inner)
            py = min(max(y, m + stroke + inner), size - m - stroke - inner)
            return card if inner > 0 and ((x - px) ** 2 + (y - py) ** 2) ** 0.5 <= inner else grey
        # tick: two segments (0.24,0.52)->(0.42,0.70)->(0.76,0.32)
        def seg(ax, ay, bx, by):
            ax, ay, bx, by = ax * size, ay * size, bx * size, by * size
            t = max(0, min(1, ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)))
            return ((x - ax - t * (bx - ax)) ** 2 + (y - ay - t * (by - ay)) ** 2) ** 0.5
        w = size * 0.085
        return white if min(seg(.24, .52, .42, .70), seg(.42, .70, .76, .32)) < w else green
    rows = []
    for py in range(size):
        row = []
        for px in range(size):
            acc = [0, 0, 0]; hit = 0
            for sy in range(4):
                for sx in range(4):
                    c = colour(px + (sx + .5) / 4, py + (sy + .5) / 4)
                    if c is None: c = card
                    else: hit += 1
                    acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]
            row.append("#%02x%02x%02x" % tuple(v // 16 for v in acc))
        rows.append("{" + " ".join(row) + "}")
    img.put(" ".join(rows))
    return img


# ---------------------------------------------------------------- the window
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WhatsApp Web Extractor")
        try:
            self._icon = tk.PhotoImage(file=os.path.join(HERE, "assets", "wawf.png"))
            self.iconphoto(True, self._icon)
        except tk.TclError:
            pass
        self.configure(bg=BG)
        self.minsize(760, 640)
        self.proc = None
        self.q = queue.Queue()
        self._style()
        self._build()
        self.after(100, self._drain)
        self.after(50, self.refresh_profiles)

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, font=FONT)
        s.configure("Card.TFrame", background=CARD, relief="solid", borderwidth=1, bordercolor=BORDER)
        s.configure("Card.TLabel", background=CARD, foreground=FG, font=FONT)
        s.configure("Step.TLabel", background=CARD, foreground=PRIMARY, font=FONT_LABEL)
        s.configure("Help.TLabel", background=CARD, foreground=MUTED, font=FONT_SMALL)
        s.configure("Warn.TLabel", background=CARD, foreground=DANGER, font=FONT_SMALL)
        s.configure("Title.TLabel", background=BG, foreground=PRIMARY, font=FONT_TITLE)
        s.configure("Sub.TLabel", background=BG, foreground=MUTED, font=FONT_SMALL)
        s.configure("Status.TLabel", background=BG, foreground=MUTED, font=FONT)
        s.configure("Card.TCheckbutton", background=CARD, foreground=FG, font=FONT)
        s.configure("Card.TRadiobutton", background=CARD, foreground=FG, font=FONT)
        for st in ("Card.TCheckbutton", "Card.TRadiobutton"):
            s.map(st, background=[("active", CARD)],
                  indicatorcolor=[("selected", ACTION), ("!selected", CARD)],
                  indicatorforeground=[("selected", "#FFFFFF")])
        s.configure("TButton", padding=(12, 6))
        s.configure("Run.TButton", background=ACTION, foreground="#FFFFFF", font=FONT_LABEL, padding=(22, 9),
                    borderwidth=0, focusthickness=2, focuscolor="#FFFFFF")
        s.map("Run.TButton", background=[("disabled", "#94A3B8"), ("active", ACTION_HOVER)])
        s.configure("Stop.TButton", foreground=DANGER, padding=(16, 9))

    def _indicators(self):
        if getattr(self, "_ind", None): return self._ind
        try: scale = float(self.tk.call("tk", "scaling")) / 1.3333
        except Exception: scale = 1.0
        n = max(14, int(round(16 * scale)))
        self._ind = {(k, v): _indicator(self, n, k, v) for k in ("check", "radio") for v in (False, True)}
        return self._ind

    def _toggle(self, parent, text, variable, value=None, command=None):
        """A check box (value None) or radio button with a drawn indicator and a visible focus ring."""
        ind = self._indicators()
        kind = "check" if value is None else "radio"
        cls = tk.Checkbutton if value is None else tk.Radiobutton
        kw = dict(text=" " + text, variable=variable, image=ind[(kind, False)], selectimage=ind[(kind, True)],
                  compound="left", indicatoron=False, bd=0, relief="flat", offrelief="flat", overrelief="flat",
                  bg=CARD, activebackground=CARD, selectcolor=CARD, fg=FG, activeforeground=FG, font=FONT,
                  highlightthickness=1, highlightcolor=ACTION, highlightbackground=CARD, cursor="hand2",
                  padx=2, pady=2, anchor="w", takefocus=1)
        if value is not None: kw["value"] = value
        if command: kw["command"] = command
        return cls(parent, **kw)

    def _card(self, parent, step, title):
        f = ttk.Frame(parent, style="Card.TFrame", padding=(16, 12))
        f.pack(fill="x", pady=(0, 10))
        ttk.Label(f, text=f"{step}   {title}", style="Step.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        f.columnconfigure(0, weight=1)
        return f

    def _build(self):
        head = tk.Frame(self, bg=HEADER)
        head.pack(fill="x")
        inner = tk.Frame(head, bg=HEADER); inner.pack(fill="x", padx=20, pady=(14, 14))
        if getattr(self, "_icon", None):
            self._icon_small = self._icon.subsample(max(1, self._icon.width() // 40))
            tk.Label(inner, image=self._icon_small, bg=HEADER).pack(side="left", padx=(0, 12))
        txt = tk.Frame(inner, bg=HEADER); txt.pack(side="left", fill="x")
        tk.Label(txt, text="WhatsApp Web Extractor", bg=HEADER, fg="#FFFFFF", font=FONT_TITLE).pack(anchor="w")
        tk.Label(txt, text="Forensic export of WhatsApp Web from an acquired browser profile.  "
                           "Use only on accounts you own or are authorised to examine.",
                 bg=HEADER, fg="#FFFFFF", font=FONT_SMALL).pack(anchor="w")
        root = ttk.Frame(self, padding=(20, 14, 20, 16))
        root.pack(fill="both", expand=True)

        # 1 — source: a whole profile folder, or its stores given separately
        c = self._card(root, "1", "Browser data")
        self.src_mode = tk.StringVar(value="profile")
        modes = ttk.Frame(c, style="Card.TFrame", padding=0); modes.configure(borderwidth=0)
        modes.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self._toggle(modes, "Profile folder", self.src_mode, value="profile", command=self._src_mode).pack(side="left")
        self._toggle(modes, "Separate folders (no profile folder)", self.src_mode, value="stores",
                     command=self._src_mode).pack(side="left", padx=(18, 0))

        self.prof_frame = pf = ttk.Frame(c, style="Card.TFrame", padding=0); pf.configure(borderwidth=0)
        pf.grid(row=2, column=0, columnspan=3, sticky="ew"); pf.columnconfigure(0, weight=1)
        self.profile = tk.StringVar()
        self.profile_box = ttk.Combobox(pf, textvariable=self.profile, font=FONT)
        self.profile_box.grid(row=0, column=0, sticky="ew", pady=(8, 0))
        self.profile_box.bind("<<ComboboxSelected>>", self._picked)
        self.profile_box.bind("<FocusOut>", lambda e: self._check_profile())
        ttk.Button(pf, text="Browse…", command=self.pick_profile).grid(row=0, column=1, padx=(8, 0), pady=(8, 0))
        ttk.Button(pf, text="Rescan", command=self.refresh_profiles).grid(row=0, column=2, padx=(8, 0), pady=(8, 0))
        self.profile_help = ttk.Label(pf, style="Help.TLabel", wraplength=660, justify="left",
                                      text="Pick the acquired profile folder with Browse…  "
                                           "Profiles found on this computer are listed for convenience.")
        self.profile_help.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.acct_row = ttk.Frame(pf, style="Card.TFrame", padding=0); self.acct_row.configure(borderwidth=0)
        ttk.Label(self.acct_row, text="This profile has more than one WhatsApp account. Examine:",
                  style="Card.TLabel").pack(side="left")
        self.account = tk.StringVar()
        self.acct_box = ttk.Combobox(self.acct_row, textvariable=self.account, state="readonly", width=24, font=FONT)
        self.acct_box.pack(side="left", padx=(8, 0))
        self._accounts = []
        self._labels = {}

        self.stores_frame = sf = ttk.Frame(c, style="Card.TFrame", padding=0); sf.configure(borderwidth=0)
        sf.columnconfigure(1, weight=1)
        self.st_idb, self.st_ls, self.st_cache = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for i, (label, var, hint) in enumerate((
                ("IndexedDB folder", self.st_idb, "Chromium: …indexeddb.leveldb or the IndexedDB folder around it.  "
                                                  "Firefox: storage\\default\\https+++web.whatsapp.com"),
                ("Local Storage folder", self.st_ls, "Chromium: 'Local Storage' (or its 'leveldb').  Not needed for Firefox"),
                ("Media cache (optional)", self.st_cache, "CacheStorage / Cache_Data, to recover cached media"))):
            ttk.Label(sf, text=label, style="Card.TLabel").grid(row=2 * i, column=0, sticky="w", pady=(8, 0), padx=(0, 10))
            ttk.Entry(sf, textvariable=var, font=FONT).grid(row=2 * i, column=1, sticky="ew", pady=(8, 0))
            ttk.Button(sf, text="Browse…", command=lambda v=var, t=label: self._pick_dir(v, t)).grid(
                row=2 * i, column=2, padx=(8, 0), pady=(8, 0))
            ttk.Label(sf, text=hint, style="Help.TLabel").grid(row=2 * i + 1, column=1, sticky="w")

        # 2 — output
        c = self._card(root, "2", "Save results to")
        self.out = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Documents", "wawf-output",
                                                   dt.datetime.now().strftime("case-%Y%m%d-%H%M")))
        ttk.Entry(c, textvariable=self.out, font=FONT).grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(c, text="Browse…", command=self.pick_out).grid(row=1, column=1, padx=(8, 0), pady=(8, 0))
        fm = ttk.Frame(c, style="Card.TFrame", padding=0)
        fm.configure(borderwidth=0)
        fm.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self.fmt_text = tk.BooleanVar(value=True)
        self.fmt_sqlite = tk.BooleanVar(value=True)
        self.fmt_raw = tk.BooleanVar(value=False)
        self._toggle(fm, "Readable chats + JSON", self.fmt_text).pack(side="left")
        self._toggle(fm, "SQLite database (Android layout)", self.fmt_sqlite).pack(side="left", padx=(18, 0))
        self._toggle(fm, "Raw store dump", self.fmt_raw).pack(side="left", padx=(18, 0))
        self.fetch_media = tk.BooleanVar(value=False)
        self._toggle(c, "Also download media the browser did not cache, from WhatsApp's servers (online)",
                     self.fetch_media).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # 3 — key
        c = self._card(root, "3", "Message key")
        self.key_mode = tk.StringVar(value="online")
        self._toggle(c, "Get it from WhatsApp (signs in once as this linked device)", self.key_mode, value="online", command=self._key_mode).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        r = ttk.Frame(c, style="Card.TFrame", padding=0); r.configure(borderwidth=0)
        r.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(4, 0)); r.columnconfigure(1, weight=1)
        self._toggle(r, "Use a saved key (companion_enc_static.txt)", self.key_mode, value="file", command=self._key_mode).grid(row=0, column=0, sticky="w")
        self.key = tk.StringVar()
        self.key_entry = ttk.Entry(r, textvariable=self.key, font=FONT, state="disabled")
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.key_btn = ttk.Button(r, text="Browse…", command=self.pick_key, state="disabled")
        self.key_btn.grid(row=0, column=2, padx=(8, 0))
        self._toggle(c, "Don't go online (everything except message text)", self.key_mode, value="offline", command=self._key_mode).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Label(c, style="Help.TLabel", wraplength=660, justify="left",
                  text="Message text is encrypted with a key WhatsApp issues to the browser at sign-in and "
                       "never writes to disk. Getting it online signs in once as this linked device (recorded "
                       "as activity on the account) and saves it as companion_enc_static.txt in the results "
                       "folder; choose that file here on later runs to decrypt without going online.").grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # run row
        bar = ttk.Frame(root); bar.pack(fill="x", pady=(4, 8))
        self.run_btn = ttk.Button(bar, text="Start", style="Run.TButton", command=self.start)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", style="Stop.TButton", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.open_btn = ttk.Button(bar, text="Open results folder", command=self.open_out, state="disabled")
        self.open_btn.pack(side="right")
        self.status = ttk.Label(bar, text="Ready.", style="Status.TLabel")
        self.status.pack(side="left", padx=(16, 0))
        self.bar = ttk.Progressbar(root, mode="indeterminate")    # shown only while a run is going
        self._bar_after = bar

        # log
        lf = ttk.Frame(root); lf.pack(fill="both", expand=True, pady=(8, 0))
        self.log = tk.Text(lf, height=12, font=FONT_MONO, bg=LOG_BG, fg=LOG_FG, insertbackground=LOG_FG,
                           relief="flat", wrap="word", padx=10, pady=8, state="disabled")
        sb = ttk.Scrollbar(lf, command=self.log.yview); self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self.log.tag_configure("warn", foreground="#FBBF24")
        self.log.tag_configure("err", foreground="#F87171")
        self.log.tag_configure("ok", foreground="#25D366")
        self.bind("<Return>", lambda e: self.start() if str(self.run_btn["state"]) != "disabled" else None)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ----- actions
    def refresh_profiles(self):
        found = find_profiles()
        self._labels = {lbl: p for lbl, p in found}
        self.profile_box["values"] = [lbl for lbl, _ in found]
        if found and not self.profile.get():
            self.profile.set(found[0][0]); self._picked()
        if not found:
            self.profile_help.configure(text="No browser profile with WhatsApp Web was found on this computer. "
                                             "Use Browse… to pick a profile folder (or a copy of one).")

    def _profile_path(self):
        v = self.profile.get().strip()
        return self._labels.get(v, v)

    def _picked(self, _e=None):
        self._check_profile()

    def _check_profile(self):
        p = self._profile_path()
        if not p: return
        threading.Thread(target=lambda: self.q.put(("__accounts__", p, session_accounts(p))), daemon=True).start()
        threading.Thread(target=lambda: self.q.put(("__identity__", p, profile_summary(p))), daemon=True).start()
        self.profile_help.configure(style="Help.TLabel", text=p)

    def pick_profile(self):
        d = filedialog.askdirectory(title="Choose the browser profile folder (e.g. 'Default' or 'Profile 1')")
        if d: self.profile.set(os.path.normpath(d)); self._check_profile()

    def _src_mode(self):
        if self.src_mode.get() == "stores":
            self.prof_frame.grid_remove(); self.stores_frame.grid(row=2, column=0, columnspan=3, sticky="ew")
        else:
            self.stores_frame.grid_remove(); self.prof_frame.grid()

    def _pick_dir(self, var, title):
        d = filedialog.askdirectory(title=f"Choose the {title}")
        if d: var.set(os.path.normpath(d))

    def pick_out(self):
        d = filedialog.askdirectory(title="Choose where to save the results")
        if d: self.out.set(os.path.normpath(d))

    def pick_key(self):
        f = filedialog.askopenfilename(title="Choose companion_enc_static.txt saved by an earlier run",
                                       filetypes=[("Saved key", "companion_enc_static*.txt"), ("Text files", "*.txt"),
                                                  ("All files", "*.*")])
        if f: self.key.set(os.path.normpath(f))

    def _key_mode(self):
        st = "normal" if self.key_mode.get() == "file" else "disabled"
        self.key_entry.configure(state=st); self.key_btn.configure(state=st)

    def _command(self):
        out = self.out.get().strip()
        stores = self.src_mode.get() == "stores"
        if stores:
            idb, ls, cache = self.st_idb.get().strip(), self.st_ls.get().strip(), self.st_cache.get().strip()
            if not os.path.isdir(idb): raise ValueError("Choose the IndexedDB folder.")
            if cache and not os.path.isdir(cache): raise ValueError("The media cache folder does not exist.")
            firefox = os.path.isdir(os.path.join(idb, "idb")) and (
                os.path.isdir(os.path.join(idb, "ls")) or os.path.isfile(os.path.join(idb, ".metadata-v2")))
            if firefox:                     # Firefox keeps IndexedDB and localStorage in this one folder
                src = ["--origin", idb]
            else:
                if not os.path.isdir(ls): raise ValueError("Choose the Local Storage folder.")
                src = ["--idb", idb, "--local-storage", ls]
            src += ["--media-cache", cache] if cache else []
        else:
            prof = self._profile_path()
            if not prof or not os.path.isdir(prof):
                raise ValueError("Choose a browser profile folder that exists.")
            src = [prof]
        if not out:
            raise ValueError("Choose where to save the results.")
        if not (self.fmt_text.get() or self.fmt_sqlite.get() or self.fmt_raw.get()):
            raise ValueError("Tick at least one output.")
        if self.fetch_media.get() and self.key_mode.get() == "offline":
            raise ValueError("Downloading media goes online, and 'Don't go online' is chosen. "
                             "Untick the media download, or choose another key option.")
        if self.fetch_media.get() and not self.fmt_sqlite.get():
            raise ValueError("Downloading media needs the SQLite database output ticked.")
        if self.key_mode.get() == "file" and not os.path.isfile(self.key.get().strip()):
            raise ValueError("Choose the companion_enc_static.txt saved by an earlier run, or get the key from WhatsApp.")
        if getattr(sys, "frozen", False):
            cmd = [sys.executable]
        else:
            cmd = [sys.executable, "-u", os.path.join(HERE, "wawf.py")]
        cmd += src
        if self.fmt_text.get(): cmd += ["--out", os.path.join(out, "export")]
        if self.fmt_sqlite.get(): cmd += ["--out", "sqlite:" + os.path.join(out, "database")]
        if self.fmt_raw.get(): cmd += ["--out", "raw:" + os.path.join(out, "raw")]
        if self.key_mode.get() == "file":
            # a key file never needs the sign-in; stay offline unless media is to be downloaded
            cmd += ["--key", self.key.get().strip()] + ([] if self.fetch_media.get() else ["--offline"])
        if self.key_mode.get() == "offline": cmd += ["--offline"]
        if self.fetch_media.get(): cmd += ["--fetch-media"]
        if not stores and len(self._accounts) > 1 and self.account.get(): cmd += ["--partition", self.account.get()]
        cmd += ["--audit-db", os.path.join(out, "wawf_audit.db"), "--log-file", os.path.join(out, "wawf.log")]
        return cmd, out

    def start(self):
        try:
            cmd, out = self._command()
        except ValueError as e:
            messagebox.showwarning("WhatsApp Web Extractor", str(e)); return
        os.makedirs(out, exist_ok=True)
        self.out_dir = out
        self._clear(); self._append("$ " + " ".join(_q(c) for c in cmd) + "\n\n")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", WAWF_FROM_GUI="1",
                   PYINSTALLER_RESET_ENVIRONMENT="1")      # the run unpacks its own copy of the exe
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                         env=env, cwd=out, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as e:
            messagebox.showerror("WhatsApp Web Extractor", f"Could not start: {e}"); return
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()
        self.run_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.open_btn.configure(state="normal")
        self.status.configure(text="Working… reading a large profile takes several minutes.", foreground=MUTED)
        self.bar.pack(fill="x", after=self._bar_after); self.bar.start(12)

    def _pump(self, proc):
        for raw in iter(proc.stdout.readline, b""):
            self.q.put(raw.decode("utf-8", "replace"))
        self.q.put(("__exit__", proc.wait()))

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple) and item[0] == "__accounts__":
                    self._show_accounts(item[1], item[2])
                elif isinstance(item, tuple) and item[0] == "__identity__":
                    if item[1] == self._profile_path() and item[2]:
                        self.profile_help.configure(text=item[2] + "\n" + item[1])
                elif isinstance(item, tuple):
                    self._finished(item[1])
                else:
                    tag = "err" if " ERROR " in item else "warn" if " WARNING " in item else None
                    self._append(item, tag)
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _finished(self, rc):
        self.bar.stop(); self.bar.pack_forget()
        self.run_btn.configure(state="normal"); self.stop_btn.configure(state="disabled")
        if rc == 0:
            self.status.configure(text="Done.", foreground=ACTION)
            self._append("\nFinished.\n", "ok")
        else:
            self.status.configure(text=f"Stopped with an error (code {rc}). See the log above.", foreground=DANGER)
            self._append(f"\nExited with code {rc}.\n", "err")
        self.proc = None

    def _show_accounts(self, profile, accts):
        if profile != self._profile_path(): return          # the user has picked another profile since
        self._accounts = accts
        if len(accts) > 1:
            self.acct_box["values"] = [a for a, _ in accts]
            self.account.set(accts[0][0])
            self.acct_row.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        else:
            self.acct_row.grid_remove()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.status.configure(text="Stopping…")

    def open_out(self):
        d = getattr(self, "out_dir", None) or self.out.get()
        if d and os.path.isdir(d):
            if sys.platform == "win32": os.startfile(d)
            else: subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", d])

    def on_close(self):
        if self.proc and self.proc.poll() is None:
            if not messagebox.askyesno("WhatsApp Web Extractor", "A run is in progress. Stop it and close?"):
                return
            self.proc.terminate()
        self.destroy()

    def _clear(self):
        self.log.configure(state="normal"); self.log.delete("1.0", "end"); self.log.configure(state="disabled")

    def _append(self, text, tag=None):
        self.log.configure(state="normal"); self.log.insert("end", text, tag); self.log.see("end")
        self.log.configure(state="disabled")


def _q(s):
    return f'"{s}"' if " " in s else s

def hide_own_console():
    """Double-clicking a console .exe opens a console window that belongs to this process alone; hide it
    so the GUI is the only window. A console shared with a shell (the CLI case) is left alone."""
    if sys.platform != "win32": return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        buf = (ctypes.c_uint * 8)()
        if k.GetConsoleProcessList(buf, 8) <= (2 if getattr(sys, "frozen", False) else 1):
            hwnd = k.GetConsoleWindow()
            if hwnd: ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass

def main():
    hide_own_console()
    try:                                                    # its own taskbar entry and icon, not python's
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("wawf.extractor")
    except Exception:
        pass
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)      # crisp text on scaled displays
    except Exception:
        pass
    App().mainloop()
    return 0

if __name__ == "__main__":
    sys.exit(main())
