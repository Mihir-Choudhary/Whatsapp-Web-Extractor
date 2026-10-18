"""wawf_gui.py — a small window in front of the wawf command line.

It builds the same command a user would type and runs it, streaming the output into the window, so
the GUI and the CLI cannot drift apart: every run is an ordinary CLI run, with the same audit trail.
Standard library only (tkinter).
"""
from __future__ import annotations
import os, re, sys, glob, queue, shutil, subprocess, tempfile, threading, datetime as dt

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from wawf_help import TIPS, STEPS, GUIDE

# A log line starts with its level ("WARNING msg"; with -v, "<date> <time> WARNING name msg").
_LEVEL = re.compile(r"^(?:\d{4}-\d\d-\d\d [\d:,.]+ )?(ERROR|CRITICAL|WARNING)\b")
_PASS = re.compile(r"history pass (\d+)")

def _line_tag(line):
    """'err', 'warn' or None: the colour a line of the run's output gets in the log pane."""
    m = _LEVEL.match(line)
    return None if not m else "warn" if m.group(1) == "WARNING" else "err"


def _run_popen_kwargs():
    """How a run is started: no console window on Windows; elsewhere in a process group of its own, so
    Stop can reach the helpers it starts as well as the run itself."""
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {"start_new_session": True}


def _stop_tree(proc):
    """End a run and every helper process it started. Ending the run alone left its helpers running --
    on Linux and macOS a history or queue client went on signing in and asking the phone after Stop."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return
    import signal
    try:
        os.killpg(proc.pid, signal.SIGTERM)              # the run leads its own group (_run_popen_kwargs)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()


# which tip explains which toggle (matched on the start of its label)
_TOGGLE_TIPS = {"Profile folder": "profile_mode", "Separate folders": "stores_mode",
                "Readable chats": "fmt_text", "SQLite database": "fmt_sqlite", "Raw store dump": "fmt_raw",
                "Also download media": "fetch_media", "Also recover history": "history", "Also record what": "queue",
                "Get it from WhatsApp": "key_online", "Use saved key": "key_file", "Don't go online": "key_offline",
                "Record every step": "audit_on", "…including raw key values": "audit_secrets", "Don't record": "audit_off",
                "Only re-ask chats": "refetch", "Allow installing Node.js": "install_node",
                "Include key material": "raw_keys", "Detailed log": "verbose"}


class Tooltip:
    """Explanation shown when the pointer rests on a control (and while it has keyboard focus)."""
    def __init__(self, widget, text):
        self.w, self.text, self.tip, self.job = widget, text, None, None
        widget.bind("<Enter>", self._later, add="+"); widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<FocusIn>", self._later, add="+"); widget.bind("<FocusOut>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")
    def _later(self, _e=None):
        self._hide(); self.job = self.w.after(450, self._show)
    def _show(self):
        if self.tip or not self.w.winfo_viewable(): return
        x, y = self.w.winfo_rootx() + 12, self.w.winfo_rooty() + self.w.winfo_height() + 4
        self.tip = t = tk.Toplevel(self.w); t.wm_overrideredirect(True); t.wm_geometry(f"+{x}+{y}")
        tk.Label(t, text=self.text, justify="left", wraplength=460, bg="#111B21", fg="#FFFFFF",
                 font=("Segoe UI", 9), padx=10, pady=7).pack()
    def _hide(self, _e=None):
        if self.job: self.w.after_cancel(self.job); self.job = None
        if self.tip: self.tip.destroy(); self.tip = None

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
_SKIP = {"Cache", "Code Cache", "GPUCache", "Service Worker", "IndexedDB", "Local Storage", "WebStorage",
         "Extensions", "node_modules", "Packages", "Temp", "CrashDumps", "Crashpad", "ShaderCache", "storage",
         "cache2", "pip", "npm-cache", "Docker", "JetBrains"}

def _search_roots():
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [r for r in (os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA")) if r]
    if sys.platform == "darwin":
        return [os.path.join(home, "Library", "Application Support")]
    return [os.path.join(home, ".config"), os.path.join(home, ".mozilla"), os.path.join(home, "snap"),
            os.path.join(home, ".var", "app")]

def _wa_profile(d):
    """'chromium' / 'firefox' if folder `d` is a browser profile holding WhatsApp Web, else None.
    Decided by structure only, so any Chromium- or Firefox-based browser is found."""
    if os.path.isdir(os.path.join(d, "storage", "default", "https+++web.whatsapp.com")):
        return "firefox"
    if os.path.isdir(os.path.join(d, "IndexedDB", "https_web.whatsapp.com_0.indexeddb.leveldb")):
        return "chromium"
    ls = os.path.join(d, "Local Storage", "leveldb")
    if os.path.isdir(os.path.join(d, "WebStorage")) and os.path.isdir(ls) and _ls_mentions_wa(ls):
        return "chromium"
    return None

def _label(root, d):
    """'Microsoft Edge · Profile 8' style label from the path below the search root."""
    parts = [x for x in os.path.relpath(d, root).split(os.sep) if x not in ("User Data", "Profiles", "config")]
    name = parts[-1] if parts else d
    app = " ".join(parts[:-1][-2:]) or name
    return f"{app}  ·  {name}" if app != name else name

def find_profiles(max_depth=4):
    """[(label, path)] for every local browser profile holding WhatsApp Web, from any Chromium- or
    Firefox-based browser. Browser data roots are recognised by their own marker -- Chromium's
    `Local State` beside its profiles, Firefox's `profiles.ini` -- so only their profiles are tested."""
    out, seen = [], set()
    def consider(root, d):
        kind = _wa_profile(d)
        k = os.path.normcase(os.path.realpath(d))
        if kind and k not in seen:
            seen.add(k); out.append((_label(root, d), d))
    for root in _search_roots():
        if not os.path.isdir(root): continue
        stack = [(root, 0)]
        while stack:
            d, depth = stack.pop()
            try:
                names = {e.name: e for e in os.scandir(d)}
            except OSError:
                continue
            if "Local State" in names or "profiles.ini" in names:
                consider(root, d)                                    # e.g. Opera keeps its profile here
                for sub in ("", "Profiles"):
                    base = os.path.join(d, sub) if sub else d
                    try:
                        for e in os.scandir(base):
                            if e.is_dir(follow_symlinks=False): consider(root, e.path)
                    except OSError:
                        pass
                continue
            if depth >= max_depth: continue
            for n, e in names.items():
                if n not in _SKIP and e.is_dir(follow_symlinks=False):
                    stack.append((e.path, depth + 1))
    return sorted(out)

def _ls_mentions_wa(ls_dir):
    """Cheap check (no parsing): does this profile's localStorage hold any web.whatsapp.com key?"""
    for f in glob.glob(os.path.join(glob.escape(ls_dir), "*.l*")):
        try:
            with open(f, "rb") as fh:
                if b"web.whatsapp.com" in fh.read(): return True
        except OSError:
            pass
    return False

def _is_profile(p):
    return os.path.isdir(os.path.join(p, "IndexedDB")) or os.path.isdir(os.path.join(p, "WebStorage")) \
        or os.path.isdir(os.path.join(p, "storage", "default"))

def _nested(p):
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import profile_identity as pi
        return pi.nested_profiles(p)
    except Exception:
        return []

def profile_summary(profile):
    """Browser, version and original location, read from the folder's own files (see profile_identity)."""
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import profile_identity as pi
        text = pi.summary(pi.identify(profile))
        if pi.browser_running(profile):
            text = ("The browser is running on this profile: close it for a complete read. History recovery "
                    "and the server queue need it closed.\n") + text
        return text
    except Exception:
        return ""

ALL_SESSIONS = "All sessions (each in its own folder)"

def session_accounts(profile):
    """[(label, '<account>:<device>')] of every signed-in WhatsApp session in a Chromium profile, most
    recent login first. Reads only localStorage (small), so it is fast enough to run when a profile is picked."""
    try:
        sys.path.insert(0, os.path.join(HERE, "scripts"))
        import chromium_reader as cr
        if not cr.is_chromium_profile(profile): return []
        rows = []
        for sk, ls in cr.read_localstorage_all(profile).items():
            if cr._account(ls):
                rows.append({"account": cr._account(ls), "device": cr._device(ls), "wid": cr._wid(ls) or cr._account(ls)})
        cr.cleanup()
        rows.sort(key=lambda r: -(r["device"] or 0))
        labels = cr.session_labels(rows)
        return [("%s · device %s · %s" % (r["account"], r["device"] if r["device"] is not None else "?", labels[i]),
                 r["wid"]) for i, r in enumerate(rows)]
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
LOG_LINES, LOG_MIN_LINES = 12, 5        # the log's height during a run, and the least it shrinks to before one

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
        self.after(120, self._fit_screen)

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
        s.configure("Link.TButton", background=BG, foreground=PRIMARY, borderwidth=0, padding=(0, 2),
                    font=FONT_LABEL, focuscolor=PRIMARY)
        s.map("Link.TButton", background=[("active", BG)], foreground=[("active", ACTION_HOVER)])

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
        w = cls(parent, **kw)
        key = _TOGGLE_TIPS.get(text if not text.startswith("Also ") else text.split(" (")[0][:40])
        if key is None:
            key = next((k for lbl, k in _TOGGLE_TIPS.items() if text.startswith(lbl)), None)
        if key in TIPS: Tooltip(w, TIPS[key])
        return w

    def _card(self, parent, step, title):
        f = ttk.Frame(parent, style="Card.TFrame", padding=(16, 12))
        f.pack(fill="x", pady=(0, 10))
        head = ttk.Frame(f, style="Card.TFrame", padding=0); head.configure(borderwidth=0)
        head.grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(head, text=f"{step}   {title}", style="Step.TLabel").pack(side="left")
        if step in STEPS: self._info(head, STEPS[step][0], STEPS[step][1]).pack(side="left", padx=(8, 0))
        f.columnconfigure(0, weight=1)
        return f

    def _info(self, parent, title, text):
        """A small ⓘ: hover shows the explanation, click opens it in full."""
        b = tk.Label(parent, text="ⓘ", fg=PRIMARY, bg=CARD, font=("Segoe UI", 11), cursor="hand2", takefocus=1)
        b.bind("<Button-1>", lambda e: messagebox.showinfo(title, text, parent=self))
        b.bind("<Return>", lambda e: messagebox.showinfo(title, text, parent=self))
        Tooltip(b, text if len(text) < 400 else text[:380].rsplit(" ", 1)[0] + " …  (click for more)")
        return b

    def _tip(self, widget, key):
        if key in TIPS: Tooltip(widget, TIPS[key])
        return widget

    def show_help(self):
        if getattr(self, "_help", None) and self._help.winfo_exists():
            self._help.deiconify(); self._help.lift(); return
        self._help = h = tk.Toplevel(self); h.title("Help — WhatsApp Web Extractor"); h.configure(bg=BG)
        if getattr(self, "_icon", None): h.iconphoto(False, self._icon)
        t = tk.Text(h, wrap="word", font=("Segoe UI", 10), bg=CARD, fg=FG, relief="flat", padx=18, pady=14,
                    width=96, height=34)
        sb = ttk.Scrollbar(h, command=t.yview); t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); t.pack(fill="both", expand=True)
        t.tag_configure("h", font=("Segoe UI Semibold", 11), foreground=PRIMARY, spacing1=10)
        for line in GUIDE.splitlines():
            t.insert("end", line + "\n", "h" if line.isupper() and line.strip() else None)
        t.configure(state="disabled")

    def _build(self):
        head = tk.Frame(self, bg=HEADER)
        head.pack(fill="x")
        inner = tk.Frame(head, bg=HEADER); inner.pack(fill="x", padx=20, pady=(14, 14))
        if getattr(self, "_icon", None):
            self._icon_small = self._icon.subsample(max(1, self._icon.width() // 40))
            tk.Label(inner, image=self._icon_small, bg=HEADER).pack(side="left", padx=(0, 12))
        txt = tk.Frame(inner, bg=HEADER); txt.pack(side="left", fill="x")
        tk.Label(txt, text="WhatsApp Web Extractor", bg=HEADER, fg="#FFFFFF", font=FONT_TITLE).pack(anchor="w")
        hb = tk.Button(inner, text="Help", command=self.show_help, bg="#FFFFFF", fg=PRIMARY, relief="flat",
                       font=FONT_LABEL, padx=14, pady=4, cursor="hand2", activebackground="#E9EDEF")
        hb.pack(side="right")
        tk.Label(txt, text="Forensic export of WhatsApp Web from an acquired browser profile.  "
                           "Use only on accounts you own or are authorised to examine.",
                 bg=HEADER, fg="#FFFFFF", font=FONT_SMALL).pack(anchor="w")
        root = ttk.Frame(self, padding=(20, 14, 20, 16))
        root.pack(fill="both", expand=True)
        # Controls stay pinned at the bottom; the steps above them scroll, so no screen size can push
        # the Start button or the log out of the window.
        bottom = ttk.Frame(root); bottom.pack(side="bottom", fill="x")
        self._canvas = cv = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(root, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
        self._form = form = ttk.Frame(cv)
        win = cv.create_window((0, 0), window=form, anchor="nw")
        form.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfigure(win, width=e.width))
        def _wheel(e):
            if cv.winfo_height() < form.winfo_reqheight():
                cv.yview_scroll(int(-e.delta / 120) if e.delta else (1 if e.num == 5 else -1), "units")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            cv.bind_all(seq, lambda e, f=_wheel: f(e) if str(e.widget).startswith(str(cv)) else None)
        self._bottom = bottom

        # 1 — source: a whole profile folder, or its stores given separately
        c = self._card(form, "1", "Browser data")
        self.src_mode = tk.StringVar(value="profile")
        modes = ttk.Frame(c, style="Card.TFrame", padding=0); modes.configure(borderwidth=0)
        modes.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self._toggle(modes, "Profile folder", self.src_mode, value="profile", command=self._src_mode).pack(side="left")
        self._toggle(modes, "Separate folders (no profile folder)", self.src_mode, value="stores",
                     command=self._src_mode).pack(side="left", padx=(18, 0))

        self.prof_frame = pf = ttk.Frame(c, style="Card.TFrame", padding=0); pf.configure(borderwidth=0)
        pf.grid(row=2, column=0, columnspan=3, sticky="ew"); pf.columnconfigure(0, weight=1)
        self.profile = tk.StringVar()
        self.profile_box = ttk.Combobox(pf, textvariable=self.profile, font=FONT); self._tip(self.profile_box, "profile_box")
        self.profile_box.grid(row=0, column=0, sticky="ew", pady=(8, 0))
        self.profile_box.bind("<<ComboboxSelected>>", self._picked)
        self.profile_box.bind("<FocusOut>", lambda e: self._check_profile())
        ttk.Button(pf, text="Browse…", command=self.pick_profile).grid(row=0, column=1, padx=(8, 0), pady=(8, 0))
        self._tip(ttk.Button(pf, text="Rescan", command=self.refresh_profiles), "rescan").grid(row=0, column=2, padx=(8, 0), pady=(8, 0))
        self.profile_help = ttk.Label(pf, style="Help.TLabel", wraplength=880, justify="left",
                                      text="Pick the acquired profile folder with Browse…  "
                                           "Profiles found on this computer are listed for convenience.")
        self.profile_help.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.acct_row = ttk.Frame(pf, style="Card.TFrame", padding=0); self.acct_row.configure(borderwidth=0)
        ttk.Label(self.acct_row, text="This profile has more than one WhatsApp account. Examine:",
                  style="Card.TLabel").pack(side="left")
        self.account = tk.StringVar()
        self.acct_box = ttk.Combobox(self.acct_row, textvariable=self.account, state="readonly", width=52, font=FONT)
        self._tip(self.acct_box, "account")
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
            self._tip(ttk.Entry(sf, textvariable=var, font=FONT), ("st_idb", "st_ls", "st_cache")[i]).grid(
                row=2 * i, column=1, sticky="ew", pady=(8, 0))
            ttk.Button(sf, text="Browse…", command=lambda v=var, t=label: self._pick_dir(v, t)).grid(
                row=2 * i, column=2, padx=(8, 0), pady=(8, 0))
            ttk.Label(sf, text=hint, style="Help.TLabel").grid(row=2 * i + 1, column=1, sticky="w")

        # 2 — output
        c = self._card(form, "2", "Save results to")
        self.out = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Documents", "wawf-output",
                                                   dt.datetime.now().strftime("case-%Y%m%d-%H%M")))
        self._tip(ttk.Entry(c, textvariable=self.out, font=FONT), "out").grid(row=1, column=0, sticky="ew", pady=(8, 0))
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
        self.history = tk.BooleanVar(value=False)
        self._toggle(c, "Also recover history older than the browser's ~90 days, from the phone "
                        "(online; can take hours)",
                     self.history).grid(row=4, column=0, columnspan=3, sticky="w", pady=(2, 0))
        self.queue = tk.BooleanVar(value=False)
        self._toggle(c, "Also record what WhatsApp's server is holding for this device "
                        "(online; nothing is taken from it)",
                     self.queue).grid(row=5, column=0, columnspan=3, sticky="w", pady=(2, 0))
        sc = ttk.Frame(c, style="Card.TFrame", padding=0); sc.configure(borderwidth=0)
        sc.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0)); sc.columnconfigure(1, weight=1)
        ttk.Label(sc, text="Only these chats (optional)", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.chats = tk.StringVar()
        self._tip(ttk.Entry(sc, textvariable=self.chats, font=FONT), "chat").grid(row=0, column=1, sticky="ew")
        ttk.Label(sc, text="a name, phone number with country code, lid or jid; separate several with ;",
                  style="Help.TLabel").grid(row=1, column=1, sticky="w")

        # 3 — key
        c = self._card(form, "3", "Message key")
        self.key_mode = tk.StringVar(value="online")
        self._toggle(c, "Get it from WhatsApp (signs in once as this linked device)", self.key_mode, value="online", command=self._key_mode).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        r = ttk.Frame(c, style="Card.TFrame", padding=0); r.configure(borderwidth=0)
        r.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(4, 0)); r.columnconfigure(1, weight=1)
        self._toggle(r, "Use saved key(s) (one per linked device)", self.key_mode, value="file", command=self._key_mode).grid(row=0, column=0, sticky="w")
        self.key = tk.StringVar()
        self.key_entry = ttk.Entry(r, textvariable=self.key, font=FONT, state="disabled")
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.key_btn = ttk.Button(r, text="Browse…", command=self.pick_key, state="disabled")
        self.key_btn.grid(row=0, column=2, padx=(8, 0))
        self._toggle(c, "Don't go online (everything except message text)", self.key_mode, value="offline", command=self._key_mode).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Label(c, style="Help.TLabel", wraplength=880, justify="left",
                  text="Message text is encrypted with a key WhatsApp issues to the browser at sign-in and "
                       "never writes to disk. Getting it online signs in once as this linked device (recorded "
                       "as activity on the account) and saves it as companion_enc_static.txt in the results "
                       "folder; choose that file here on later runs to decrypt without going online.").grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # 4 — the case: recorded in the chain-of-custody database beside the results
        c4 = self._card(form, "4", "Case (chain of custody)")
        self.case_id, self.examiner, self.case_notes = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.audit_mode = tk.StringVar(value="on")
        row = ttk.Frame(c4, style="Card.TFrame", padding=0); row.configure(borderwidth=0)
        row.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0)); row.columnconfigure(1, weight=1); row.columnconfigure(3, weight=1)
        ttk.Label(row, text="Case / exhibit no.", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._tip(ttk.Entry(row, textvariable=self.case_id, font=FONT), "case_id").grid(row=0, column=1, sticky="ew")
        ttk.Label(row, text="Examiner", style="Card.TLabel").grid(row=0, column=2, sticky="w", padx=(16, 8))
        self._tip(ttk.Entry(row, textvariable=self.examiner, font=FONT), "examiner").grid(row=0, column=3, sticky="ew")
        ttk.Label(row, text="Notes", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
        self._tip(ttk.Entry(row, textvariable=self.case_notes, font=FONT), "case_notes").grid(row=1, column=1, columnspan=3, sticky="ew", pady=(6, 0))
        aud = ttk.Frame(c4, style="Card.TFrame", padding=0); aud.configure(borderwidth=0)
        aud.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self._toggle(aud, "Record every step and file hash (wawf_audit.db)", self.audit_mode, value="on").pack(side="left")
        self._toggle(aud, "…including raw key values", self.audit_mode, value="secrets").pack(side="left", padx=(14, 0))
        self._toggle(aud, "Don't record", self.audit_mode, value="off").pack(side="left", padx=(14, 0))

        # advanced options: everything else the command line offers, out of the way until asked for
        adv_head = ttk.Frame(bottom); adv_head.pack(fill="x", pady=(8, 6))
        self.adv_btn = ttk.Button(adv_head, text="Advanced options…", style="Link.TButton", command=self._toggle_adv)
        self.adv_btn.pack(side="left")
        self.adv_summary = ttk.Label(adv_head, text="", style="Sub.TLabel")
        self.adv_summary.pack(side="left", padx=(10, 0))
        self.adv = tk.Toplevel(self)                      # its own small window: the main one stays compact
        self.adv.withdraw(); self.adv.title("Advanced options"); self.adv.configure(bg=BG)
        self.adv.transient(self); self.adv.resizable(False, False)
        self.adv.protocol("WM_DELETE_WINDOW", self._toggle_adv)
        if getattr(self, "_icon", None): self.adv.iconphoto(False, self._icon)
        c = ttk.Frame(self.adv, style="Card.TFrame", padding=(16, 12)); c.pack(fill="both", expand=True, padx=12, pady=12)
        c.columnconfigure(1, weight=1)
        self.refetch, self.install_node = tk.BooleanVar(), tk.BooleanVar()
        self.raw_keys, self.verbose = tk.BooleanVar(), tk.BooleanVar()
        self.creds = tk.StringVar()
        ttk.Label(c, text="Older history from the phone (ticked in the main window):", style="Card.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w")
        sub = ttk.Frame(c, style="Card.TFrame", padding=(26, 0, 0, 0)); sub.configure(borderwidth=0)
        sub.grid(row=1, column=0, columnspan=3, sticky="w")
        self._toggle(sub, "Only re-ask chats whose senders are missing", self.refetch).pack(side="left")
        self._toggle(sub, "Allow installing Node.js (Node engine only)", self.install_node).pack(side="left", padx=(18, 0))
        self._toggle(c, "Include key material in the raw store dump (do not share that dump)",
                     self.raw_keys).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Label(c, text="Saved credentials (creds_in.json)", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self._tip(ttk.Entry(c, textvariable=self.creds, font=FONT), "creds").grid(row=3, column=1, sticky="ew", pady=(8, 0), padx=(10, 0))
        ttk.Button(c, text="Browse…", command=self.pick_creds).grid(row=3, column=2, padx=(8, 0), pady=(8, 0))
        self._toggle(c, "Detailed log (full tracebacks)", self.verbose).grid(row=5, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self._tip(ttk.Button(c, text="List the WhatsApp sessions in this profile", command=self.list_sessions),
                  "list_sessions").grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Button(c, text="Done", style="Run.TButton", command=self._toggle_adv).grid(row=7, column=2, sticky="e", pady=(12, 0))

        # the command line this window will run, always visible and copyable
        cl = ttk.Frame(bottom); cl.pack(fill="x", pady=(0, 6))
        ttk.Label(cl, text="Command line", style="Sub.TLabel").pack(side="left", padx=(0, 8))
        self.cmd_text = tk.StringVar()
        self._tip(ttk.Entry(cl, textvariable=self.cmd_text, state="readonly", font=FONT_MONO), "cmd").pack(
            side="left", fill="x", expand=True)
        ttk.Button(cl, text="Copy", command=self.copy_cmd).pack(side="left", padx=(8, 0))
        self.after(300, self._refresh_cmd)

        # run row
        bar = ttk.Frame(bottom); bar.pack(fill="x", pady=(4, 8))
        self._bar_row = bar
        self.run_btn = ttk.Button(bar, text="Start", style="Run.TButton", command=self.start)
        self.run_btn.pack(side="left"); self._tip(self.run_btn, "start")
        self.stop_btn = ttk.Button(bar, text="Stop", style="Stop.TButton", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.open_btn = ttk.Button(bar, text="Open results folder", command=self.open_out, state="disabled")
        self.open_btn.pack(side="right")
        self.status = ttk.Label(bar, text="Ready.", style="Status.TLabel")
        self.status.pack(side="left", padx=(16, 0))
        self.bar = ttk.Progressbar(bottom, mode="indeterminate")    # shown only while a run is going
        self._bar_after = bar

        # log
        lf = ttk.Frame(bottom); lf.pack(fill="both", expand=True, pady=(8, 0))
        self.log = tk.Text(lf, height=LOG_LINES, font=FONT_MONO, bg=LOG_BG, fg=LOG_FG, insertbackground=LOG_FG,
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
        self.profile_help.configure(text="Searching this computer for browser profiles with WhatsApp Web…")
        threading.Thread(target=lambda: self.q.put(("__profiles__", find_profiles())), daemon=True).start()

    def _show_profiles(self, found):
        self._labels = {lbl: p for lbl, p in found}
        self.profile_box["values"] = [lbl for lbl, _ in found]
        if found and not self.profile.get():
            self.profile.set(found[0][0]); self._picked()
        elif found:
            self._check_profile()
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
        if os.path.isdir(p) and not _is_profile(p):
            # the profile may be inside the chosen folder: use it when there is exactly one
            found = _nested(p)
            if len(found) == 1:
                self.profile.set(found[0]); p = found[0]
            elif len(found) > 1:
                self.profile_help.configure(style="Help.TLabel", text="This folder holds %d browser profiles with "
                                            "WhatsApp Web; pick one:\n  " % len(found) + "\n  ".join(found))
                self.profile_box["values"] = found
                self._accounts = []; self.acct_row.grid_remove()
                return
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

    def _fit_screen(self):
        """Show all the steps when the screen allows it; otherwise the steps scroll and the controls stay."""
        self.update_idletasks()
        avail = self.winfo_screenheight() - 90                 # leave room for a taskbar / dock
        fixed = self.winfo_reqheight() - self._canvas.winfo_reqheight()
        want = self._form.winfo_reqheight()
        # Before a run the log shrinks (down to LOG_MIN_LINES) until the steps through 3 ("Message key")
        # are in view; a run gives it LOG_LINES again. At 12 lines on a 1080-pixel screen step 3 was
        # cut off at the default size.
        cards = self._form.winfo_children()[:3]
        need = sum(c.winfo_reqheight() + 10 for c in cards)
        lines = LOG_LINES
        while lines > LOG_MIN_LINES and avail - fixed < min(want, need):
            lines -= 1; self.log.configure(height=lines); self.update_idletasks()
            fixed = self.winfo_reqheight() - self._canvas.winfo_reqheight()
        self._canvas.configure(height=max(200, min(want, avail - fixed)))
        self.update_idletasks()
        w, h = max(self._form.winfo_reqwidth() + 60, 760), min(self.winfo_reqheight(), avail)
        x = max(0, (self.winfo_screenwidth() - w) // 2)
        y = max(0, (avail - h) // 2)                           # placed inside the usable area, never under a taskbar
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(760, min(560, avail))

    def _refresh_cmd(self):
        try:
            cmd, _ = self._command()
            text = _cmdline(cmd)
        except ValueError as e:
            text = "(not ready: " + str(e) + ")"
        except Exception:
            text = ""
        if text != self.cmd_text.get(): self.cmd_text.set(text)
        summ = self._adv_text()
        if summ != self.adv_summary.cget("text"): self.adv_summary.configure(text=summ)
        self.after(400, self._refresh_cmd)

    def copy_cmd(self):
        t = self.cmd_text.get()
        if t and not t.startswith("(not ready"):
            self.clipboard_clear(); self.clipboard_append(t)
            self.status.configure(text="Command line copied.", foreground=MUTED)

    def _toggle_adv(self):
        if self.adv.winfo_viewable():
            self.adv.withdraw()
        else:
            self.adv.deiconify(); self.adv.lift(); self.adv.focus_set()

    def _adv_text(self):
        on = [t for v, t in ((self.refetch, "history: refetch only"),
                             (self.install_node, "may install Node.js"), (self.raw_keys, "key material in raw dump"),
                             (self.verbose, "detailed log")) if v.get()]
        if self.creds.get().strip(): on.append("saved credentials")
        return ("on: " + " · ".join(on)) if on else ""

    def pick_creds(self):
        f = filedialog.askopenfilename(title="Choose creds_in.json saved by an earlier run",
                                       filetypes=[("Credentials", "creds_in*.json"), ("JSON", "*.json"), ("All files", "*.*")])
        if f: self.creds.set(os.path.normpath(f))

    def list_sessions(self):
        try:
            src = self._source()
        except ValueError as e:
            messagebox.showwarning("WhatsApp Web Extractor", str(e)); return
        self._launch(self._exe() + src + ["--list-partitions"], None, "Reading the profile to list its sessions…")

    def pick_out(self):
        d = filedialog.askdirectory(title="Choose where to save the results")
        if d: self.out.set(os.path.normpath(d))

    def pick_key(self):
        fs = filedialog.askopenfilenames(title="Choose the saved key file(s) -- one per linked device",
                                         filetypes=[("Saved key", "companion_enc_static*.txt"), ("Text files", "*.txt"),
                                                    ("All files", "*.*")])
        if fs: self.key.set("; ".join(os.path.normpath(f) for f in fs))

    def _keys(self):
        return [k.strip() for k in self.key.get().split(";") if k.strip()]

    def _key_mode(self):
        st = "normal" if self.key_mode.get() == "file" else "disabled"
        self.key_entry.configure(state=st); self.key_btn.configure(state=st)

    def _exe(self):
        """How to run the command line: this very exe when frozen, else the script beside this file."""
        return [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-u", os.path.join(HERE, "wawf.py")]

    def _source(self):
        """The evidence arguments: a profile folder, Firefox --origin, or the stores given separately."""
        if self.src_mode.get() == "stores":
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
            return src + (["--media-cache", cache] if cache else [])
        prof = self._profile_path()
        if not prof or not os.path.isdir(prof):
            raise ValueError("Choose a browser profile folder that exists.")
        src = [prof]
        if len(self._accounts) > 1 and self.account.get() not in ("", ALL_SESSIONS):
            src += ["--partition", dict(self._accounts).get(self.account.get(), self.account.get())]
        return src

    def _command(self):
        out = self.out.get().strip()
        src = self._source()
        mode, fetch, hist = self.key_mode.get(), self.fetch_media.get(), self.history.get()
        queue = self.queue.get()
        if not out:
            raise ValueError("Choose where to save the results.")
        if not (self.fmt_text.get() or self.fmt_sqlite.get() or self.fmt_raw.get()):
            raise ValueError("Tick at least one output.")
        if (fetch or hist) and mode == "offline":
            raise ValueError("Downloading media and recovering history both go online, and 'Don't go online' "
                             "is chosen. Untick them, or choose another key option.")
        if queue and mode == "offline":
            raise ValueError("Recording the server queue goes online, and 'Don't go online' is chosen. "
                             "Untick it, or choose another key option.")
        if fetch and not self.fmt_sqlite.get():
            raise ValueError("Downloading media needs the SQLite database output ticked.")
        if hist and not (self.fmt_text.get() or self.fmt_sqlite.get()):
            raise ValueError("Recovered history is merged into the chats or database output; tick one of them.")
        if (self.refetch.get() or self.install_node.get()) and not hist:
            raise ValueError("'Only re-ask chats…' and 'Allow installing Node.js' belong to history recovery; "
                             "tick that too, or untick them.")
        chats = [x.strip() for x in self.chats.get().split(";") if x.strip()]
        if chats and self.fmt_raw.get():
            raise ValueError("The raw store dump is an image of the whole store and cannot hold some chats only; "
                             "untick it, or clear 'Only these chats'.")
        if self.raw_keys.get() and not self.fmt_raw.get():
            raise ValueError("'Include key material' applies to the raw store dump; tick that output too.")
        if mode == "file" and (not self._keys() or not all(os.path.isfile(k) for k in self._keys())):
            raise ValueError("Choose the companion_enc_static.txt saved by an earlier run, or get the key from WhatsApp.")
        creds = self.creds.get().strip()
        if creds and not os.path.isfile(creds):
            raise ValueError("The saved credentials file does not exist.")
        cmd = self._exe() + src
        if self.fmt_text.get(): cmd += ["--out", os.path.join(out, "export")]
        if self.fmt_sqlite.get(): cmd += ["--out", "sqlite:" + os.path.join(out, "database")]
        if self.fmt_raw.get(): cmd += ["--out", "raw:" + os.path.join(out, "raw")]
        if self.raw_keys.get(): cmd += ["--raw-include-keys"]
        for x in chats: cmd += ["--chat", x]
        if mode == "file":
            # a key file never needs the sign-in; stay offline unless something else must go online
            for k in self._keys():
                cmd += ["--key", k]
            cmd += [] if (fetch or hist or queue) else ["--offline"]
        if mode == "offline": cmd += ["--offline"]
        if creds: cmd += ["--creds", creds]
        if fetch: cmd += ["--fetch-media"]
        if queue: cmd += ["--queue"]
        if hist:
            cmd += ["--history", "--yes"]               # --yes: the window cannot answer a typed prompt
            if self.refetch.get(): cmd += ["--history-refetch"]
            if self.install_node.get(): cmd += ["--install-node"]
        if self.audit_mode.get() == "off":
            if self.case_id.get().strip() or self.examiner.get().strip() or self.case_notes.get().strip():
                raise ValueError("Case details are recorded in the chain-of-custody database; "
                                 "choose to record it, or clear the case fields.")
            cmd += ["--no-audit"]
        else:
            cmd += ["--audit-db", os.path.join(out, "wawf_audit.db")]
            if self.audit_mode.get() == "secrets": cmd += ["--audit-secrets"]
            for flag, var in (("--case-id", self.case_id), ("--examiner", self.examiner), ("--case-notes", self.case_notes)):
                if var.get().strip(): cmd += [flag, var.get().strip()]
        if self.verbose.get(): cmd += ["-v"]
        cmd += ["--log-file", os.path.join(out, "wawf.log")]
        return cmd, out

    def _running(self):
        try:
            sys.path.insert(0, os.path.join(HERE, "scripts"))
            import profile_identity as pi
            return bool(pi.browser_running(self._profile_path()))
        except Exception:
            return False

    def start(self):
        try:
            cmd, out = self._command()
        except ValueError as e:
            messagebox.showwarning("WhatsApp Web Extractor", str(e)); return
        if (self.queue.get() or self.history.get()) and self.src_mode.get() == "profile" and self._running():
            go = messagebox.askyesno(
                "The browser is open on this profile",
                "Recording the server queue and recovering history both need this browser closed:\n\n"
                "• while WhatsApp Web is open it receives everything itself, so the server holds nothing for "
                "this device;\n"
                "• the phone sends history to the device's open connection -- the browser -- not to this tool.\n\n"
                "Close the browser and press Start again to include them.\n\n"
                "Continue now without them? (the export, the key and the media download work with it open)")
            if not go:
                return
            self.queue.set(False); self.history.set(False)
            cmd, out = self._command()
        if self.history.get() and not messagebox.askyesno(
                "Recover history from the phone",
                "This signs in as the linked device and asks the phone for older messages, chat by chat. "
                "It can take hours, the phone must stay online, and it is recorded as activity on the account.\n\n"
                "Start it?"):
            return
        os.makedirs(out, exist_ok=True)
        self.out_dir = out
        self._launch(cmd, out, "Working… reading a large profile takes several minutes.")

    def _launch(self, cmd, cwd, status):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("WhatsApp Web Extractor", "A run is already in progress."); return
        self._clear(); self._append("$ " + _cmdline(cmd) + "\n\n")
        self._stopped, self._run_history = False, "--history" in cmd
        self.log.configure(height=LOG_LINES)            # a run's log matters more than the steps above it
        # The run and every helper it starts keep their temporary files (parsed copies of the store, which
        # hold key material) in a folder of their own, removed when the run ends: Stop ends the run
        # forcibly, so it never gets to clean up after itself.
        self._run_tmp = tempfile.mkdtemp(prefix="wawf_run_")
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", WAWF_FROM_GUI="1",
                   PYINSTALLER_RESET_ENVIRONMENT="1",      # the run unpacks its own copy of the exe
                   TMP=self._run_tmp, TEMP=self._run_tmp, TMPDIR=self._run_tmp)
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                         env=env, cwd=cwd or None, **_run_popen_kwargs())
        except OSError as e:
            self._remove_run_tmp()
            messagebox.showerror("WhatsApp Web Extractor", f"Could not start: {e}"); return
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()
        self.run_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.open_btn.configure(state="normal" if cwd else "disabled")
        self.status.configure(text=status, foreground=MUTED)
        self.bar.pack(fill="x", after=self._bar_after); self.bar.start(12)

    def _pump(self, proc):
        # the run's end is reported from the process itself: helper processes it started can keep the
        # output pipe open after it has exited
        def wait():
            self.q.put(("__exit__", proc.wait()))
        threading.Thread(target=wait, daemon=True).start()
        for raw in iter(proc.stdout.readline, b""):
            self.q.put(raw.decode("utf-8", "replace"))

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple) and item[0] == "__profiles__":
                    self._show_profiles(item[1])
                elif isinstance(item, tuple) and item[0] == "__accounts__":
                    self._show_accounts(item[1], item[2])
                elif isinstance(item, tuple) and item[0] == "__identity__":
                    if item[1] == self._profile_path() and item[2]:
                        self.profile_help.configure(text=item[2] + "\n" + item[1])
                elif isinstance(item, tuple):
                    if item[0] == "__exit__" and getattr(self, "_finished_proc", None) is self.proc:
                        continue                               # already reported
                    self._finished_proc = self.proc
                    self._finished(item[1])
                else:
                    self._append(item, _line_tag(item))
                    p = _PASS.search(item) if getattr(self, "_run_history", False) else None
                    if p and "────" in item and not getattr(self, "_stopped", False):
                        self.status.configure(text="Recovering history from the phone: pass %s. This can take "
                                                   "hours; Stop keeps what is recovered." % p.group(1), foreground=MUTED)
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _remove_run_tmp(self):
        d, self._run_tmp = getattr(self, "_run_tmp", None), None
        if d: shutil.rmtree(d, ignore_errors=True)

    def _finished(self, rc):
        self._remove_run_tmp()
        self.bar.stop(); self.bar.pack_forget()
        self.run_btn.configure(state="normal"); self.stop_btn.configure(state="disabled")
        if getattr(self, "_stopped", False):
            # ended by Stop: the exit code is the forced end, not an error of the run
            self.status.configure(text="Stopped.", foreground=MUTED)
            self._append("\nStopped.\n", "warn")
            if getattr(self, "_run_history", False):
                self._append("History the phone served before Stop is kept with this linked device's history "
                             "files, but was not added to this export. The next history run for this device "
                             "keeps it and adds it to that run's export.\n", "warn")
        elif rc == 0:
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
            self.acct_box["values"] = [ALL_SESSIONS] + [a for a, _ in accts]
            self.account.set(ALL_SESSIONS)
            self.acct_row.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        else:
            self.acct_row.grid_remove()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self._stopped = True
            _stop_tree(self.proc)                          # the run and every helper it started
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
            self.stop()
            try: self.proc.wait(timeout=10)
            except Exception: pass
            self._remove_run_tmp()
        self.destroy()

    def _clear(self):
        self.log.configure(state="normal"); self.log.delete("1.0", "end"); self.log.configure(state="disabled")

    def _append(self, text, tag=None):
        self.log.configure(state="normal"); self.log.insert("end", text, tag); self.log.see("end")
        self.log.configure(state="disabled")


def _cmdline(cmd):
    """The command exactly as a terminal on this platform would take it, to copy or put in a report."""
    if sys.platform == "win32":
        return subprocess.list2cmdline(cmd)
    import shlex
    return shlex.join(cmd)

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
