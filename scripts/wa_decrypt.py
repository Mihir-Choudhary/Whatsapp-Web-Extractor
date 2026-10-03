#!/usr/bin/env python3
"""wa_decrypt.py — browser-agnostic WhatsApp Web decryptor (Firefox + Chromium).

Loads the WhatsApp Web store from a Firefox OR Chromium profile, extracts the on-disk root key,
recovers the Noise device key (offline), and — given companion_enc_static — decrypts all message
bodies + exports readable transcripts. Same capability for both engines; only the storage reader differs.

  # auto-detect engine from the profile:
  python3 wa_decrypt.py --profile ~/.config/google-chrome/Default --enc-static <b64> --out out/
  python3 wa_decrypt.py --profile ~/snap/firefox/common/.mozilla/firefox/xxxx.default --enc-static <b64>
  # or point straight at a Firefox origin dir:
  python3 wa_decrypt.py --origin .../storage/default/https+++web.whatsapp.com --enc-static <b64>

Without --enc-static it still reports the offline inventory + recovers/verifies the Noise key.
"""
from __future__ import annotations
import argparse, os, sys, json, base64, glob, sqlite3, collections, datetime as dt, re, logging
import unicodedata                 # text filter: symbol/punctuation categories
log = logging.getLogger("wawf.decrypt")  # inherits wawf's handlers when imported; quiet standalone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id
import sclone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# ---------------- shared crypto / parse ----------------
def as_bytes(x):
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, (list, tuple)): return bytes(x)
    if isinstance(x, dict):
        for k in ("__bytes", "__bytes__"):
            if k in x: return bytes(x[k])
    return None
def pk7(b):
    if not b or len(b) % 16: return b
    p = b[-1]; return b[:-p] if 1 <= p <= 16 and b[-p:] == bytes([p])*p else b
def _varint(b, i):
    n = s = 0
    while True:
        x = b[i]; i += 1; n |= (x & 0x7f) << s; s += 7
        if not x & 0x80: break
    return n, i
# TEXT FILTER NOTE: this used to require any(c.isalpha()), i.e. at least one LETTER. That silently
# discarded every message without one: emoji-only replies, numbers, dates, prices, bare punctuation
# and @mention-only messages. Measured across a 22,121-message store, 767 messages lost their text to
# that single condition, 745 of them emoji. The printable-ratio test already rejects binary and the
# base64 test already rejects thumbnails, so the letter requirement did no work except lose evidence.
# Re-measured after relaxing it to alphanumeric-or-symbol-or-punctuation: 767 recovered, 0 lost.
#
# One narrowing on top of that: a string that is NOTHING BUT digits and 12 or more of them is an
# identifier -- a phone number, a jid user part, a message id -- not something a person typed, and
# `leaves()` collects every string in the tree so such a value would be concatenated into the
# transcript as if it were message content. Measured: that guard removes all 3 such strings in this
# store and loses 0 real messages, where requiring letters-or-emoji instead would have cost 239.
def leaves(buf, depth=0, out=None):
    if out is None: out = []
    i, n = 0, len(buf)
    while i < n:
        try:
            tag, i = _varint(buf, i); wt = tag & 7
            if wt == 0: _, i = _varint(buf, i)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            elif wt == 2:
                ln, i = _varint(buf, i); seg = buf[i:i+ln]; i += ln
                sub = []
                if len(seg) >= 2 and seg[0] in (0x08,0x0a,0x10,0x12,0x1a,0x22,0x2a):
                    try: leaves(seg, depth+1, sub)
                    except Exception: sub = []
                if sub: out += sub
                else:
                    try:
                        t = seg.decode("utf-8")
                        if t and t != "null" and sum(c.isprintable() for c in t) >= len(t)*0.9 \
                           and any(c.isalnum() or unicodedata.category(c)[0] in ('S','P') for c in t) and not (t.strip().isdigit() and len(t.strip()) >= 12) and not re.fullmatch(r'[A-Za-z0-9+/]{40,}={0,2}', t):
                            out.append(t)
                    except Exception: pass
            else: break
        except Exception: break
    return out

# ---------------- normalized source loaders ----------------
def _norm_msg(o):
    """Web message dict -> normalized fields the decryptor needs."""
    idv = o.get("id") or ""; parts = idv.split("_")
    op = o.get("msgRowOpaqueData") if isinstance(o.get("msgRowOpaqueData"), dict) else None
    iv = as_bytes(op.get("iv")) if op else None
    data = as_bytes(op.get("_data")) if op else None
    return {"id": idv, "chat": parts[1] if len(parts) > 1 else "?",
            "from_me": parts[0] == "true", "type": o.get("type"), "t": o.get("t") or 0,
            "sender": as_str(o.get("author")) or as_str(o.get("from")),
            "iv": iv, "data": data, "scheme": op.get("_scheme") if op else None}
def as_str(x):
    if isinstance(x, str): return x
    if isinstance(x, dict): return x.get("_serialized") or (f"{x.get('user')}@{x.get('server')}" if x.get("user") else None)
    return None

# ---------------- who is who ----------------
# A transcript that reads "me / them" is not evidence: the first question asked of a message is WHO
# sent it, and "them" cannot be cross-referenced against anything. Everything needed to answer it was
# already in the profile, in stores this loader read for a record count and then threw away.
#
# WhatsApp addresses one person in three ways, and the stores mix them freely:
#   <phone>@c.us             UI / legacy form           -- older messages' `from`, contact phoneNumber
#   <phone>@s.whatsapp.net   wire form of that phone    -- PN-keyed contact records
#   <lid>@lid                "linked id", an alias      -- every recent message's `author`
# any of which may carry a `:<device>` suffix. Collapsing those forms onto one key per person is the
# whole job: a message addressed one way will not find the contact record stored the other way.
_PN_SERVERS = ("c.us", "s.whatsapp.net")

def canon_jid(j):
    """One key per person: `:device` suffix dropped, phone-number servers folded onto `@c.us`."""
    s = j.strip() if isinstance(j, str) else ""
    if not s or "@" not in s: return s
    user, _, server = s.rpartition("@")
    return user.split(":")[0] + "@" + ("c.us" if server in _PN_SERVERS else server)

# Not people: WhatsApp's own pseudo-chats. They have no contact record and never will, so name them
# here rather than leaving a reader to wonder who "status@broadcast" is.
_PSEUDO = {"status@broadcast": "Status updates", "0@c.us": "WhatsApp"}

def _dedupe(records, key="id"):
    """Newest-first records, one per key. The Chromium reader deliberately yields superseded and
    deleted versions too (they are evidence), so the same contact appears several times; the first
    occurrence is the live one. Taking only that stops a stale record resurrecting an old name."""
    out, seen = [], set()
    for o in records or ():
        if not isinstance(o, dict): continue
        k = canon_jid(o.get(key))
        if not k or k in seen: continue
        seen.add(k); out.append(o)
    return out

def _txt(v):
    return v.strip() if isinstance(v, str) and v.strip() else None

class Identities:
    """jid/lid -> who that is, from `model-storage`'s own contact, group-metadata, chat and
    participant stores.

    The contact store holds TWO records per person -- one keyed by `@lid`, one by `@s.whatsapp.net` --
    and the name may be on either, so records are merged into one identity per person before being
    labelled. That merge is also what yields the lid<->phone correlation: the lid-keyed record carries
    the matching `phoneNumber`, and on disk that is the only place the mapping exists.

    Naming order is most-authoritative first: `name` is what the examined user saved in their own
    address book, `pushname` is what the contact chose to call themselves, and a phone number
    identifies without naming. When nothing is known the jid is returned unchanged -- a label is never
    invented, so "unidentified" stays visibly different from "identified".
    """
    def __init__(self, stores=None, ls=None):
        st = stores or {}
        self._id = {}      # canon jid -> identity dict (several keys share one object: that IS the merge)
        self._subject = {} # canon group jid -> subject, from group-metadata (authoritative)
        self._chat = {}    # canon chat jid -> WhatsApp's own display name, from the chat store
        self.groups = {}   # canon group jid -> membership as the client last saw it
        self.me = set()    # my own addresses, every form
        for o in _dedupe(st.get("contact")):
            jid, pn = canon_jid(o.get("id")), canon_jid(o.get("phoneNumber"))
            if not jid: continue
            ent = self._id.get(jid) or (self._id.get(pn) if pn else None) or {
                "lid": None, "pn": None, "name": None, "pushname": None, "addressbook": False}
            if jid.endswith("@lid"): ent["lid"] = ent["lid"] or jid
            elif jid.endswith("@c.us"): ent["pn"] = ent["pn"] or jid
            if pn: ent["pn"] = ent["pn"] or pn
            ent["name"] = ent["name"] or _txt(o.get("name")) or _txt(o.get("verifiedName"))
            ent["pushname"] = ent["pushname"] or _txt(o.get("pushname"))
            ent["addressbook"] = ent["addressbook"] or bool(o.get("isAddressBookContact"))
            for k in (jid, pn):
                if k: self._id[k] = ent
        for o in _dedupe(st.get("group-metadata")):            # authoritative group subject
            jid, subj = canon_jid(o.get("id")), _txt(o.get("subject"))
            if jid and subj: self._subject[jid] = subj
        # Kept separate from the subject rather than merged into it: for a group whose metadata is
        # absent (one that was left, or never synced) the chat store's name is the only name there is
        # and should be used -- but it is WhatsApp's own rendering, not the group's subject, and
        # source() has to be able to say which of the two a label came from.
        for o in _dedupe(st.get("chat")):
            jid, nm = canon_jid(o.get("id")), _txt(o.get("name"))
            if jid and nm: self._chat[jid] = nm
        for o in _dedupe(st.get("participant"), key="groupId"):
            jid = canon_jid(o.get("groupId"))
            if not jid: continue
            def lst(k, _o=o): return [canon_jid(x) for x in (_o.get(k) or ()) if isinstance(x, str)]
            self.groups[jid] = {"subject": self._subject.get(jid) or self._chat.get(jid),
                                "participants": lst("participants"),
                                "past_participants": lst("pastParticipants"),
                                "admins": lst("admins"), "super_admins": lst("superAdmins")}
        for k in ("last-wid-md", "WALid"):                     # my own phone form and lid form
            try: self.me.add(canon_jid(json.loads((ls or {}).get(k) or '""')))
            except Exception as e: log.debug("own jid from %s: %s", k, e)
        self.me.discard("")
        # ...and those two are one person, which the contact store does not always record: my lid
        # usually has a pushname record while my phone form has none. Linking them stops my own
        # outgoing messages resolving two different ways inside one transcript.
        mine = [self._id[j] for j in sorted(self.me) if j in self._id]
        ent = next((e for e in mine if e["name"] or e["pushname"]), None) or (mine[0] if mine else {
            "lid": None, "pn": None, "name": None, "pushname": None, "addressbook": False})
        for j in sorted(self.me):
            if j.endswith("@lid"): ent["lid"] = ent["lid"] or j
            else: ent["pn"] = ent["pn"] or j
            self._id[j] = ent

    def entry(self, jid):
        """The merged identity behind any form of a jid, or None."""
        return self._id.get(canon_jid(jid))

    def key(self, jid):
        """A stable key for the IDENTITY, not the address: every form of one person yields the same
        key. A participant list keyed on this has one row per person, where keying on the jid gives
        the same person twice -- once under their lid and once under their phone number."""
        cj = canon_jid(jid); e = self.entry(cj) or {}
        return e.get("lid") or e.get("pn") or cj

    def is_me(self, jid):
        return canon_jid(jid) in self.me

    # One order, used by both label() and source(), so the label and its stated provenance can never
    # disagree. A group is named by its subject and nothing else; a person is named by the examined
    # user's own address book first, because that is the name that identifies them TO THAT USER -- the
    # chat store's display name is WhatsApp's own rendering and only fills gaps.
    def _resolve(self, jid):
        """-> (label, source). The single decision; everything else formats it."""
        cj = canon_jid(jid)
        if not cj: return "(unknown)", "unresolved"
        if cj.endswith("@g.us"):
            if cj in self._subject: return self._subject[cj], "group-subject"
            if cj in self._chat: return self._chat[cj], "chat-name"
            return cj, "unresolved"
        e = self.entry(cj) or {}
        if e.get("name"): return e["name"], "address-book"
        if e.get("pushname"): return e["pushname"], "pushname"
        if cj in self._chat: return self._chat[cj], "chat-name"
        if cj in _PSEUDO: return _PSEUDO[cj], "system"
        pn = e.get("pn") or (cj if cj.endswith("@c.us") else None)
        if pn: return "+" + pn.split("@")[0], "phone"
        return cj, "unresolved"

    def source(self, jid):
        """Where a label came from, so coverage can be measured instead of assumed."""
        return self._resolve(jid)[1]

    def label(self, jid, mark_me=False):
        """What to print for a jid: a name, else a phone number, else the jid unchanged."""
        lab = self._resolve(jid)[0]
        return lab + " (me)" if mark_me and canon_jid(jid) in self.me else lab

    def row(self, jid):
        """Flat correlation record: what this jid is, and every other form of the same identity."""
        cj = canon_jid(jid); e = self.entry(cj) or {}
        return {"jid": cj, "lid": e.get("lid"), "phone": e.get("pn"), "name": e.get("name"),
                "pushname": e.get("pushname"), "address_book": bool(e.get("addressbook")),
                "label": self.label(cj), "source": self.source(cj), "is_me": cj in self.me}

    def table(self, jids):
        """The correlation table for the jids actually seen, plus group membership -- exported so an
        analyst can join on it rather than re-derive it from the stores."""
        rows = {}
        for j in jids:
            cj = canon_jid(j)
            if cj and cj not in rows: rows[cj] = self.row(cj)
        def members(ps): return [{"jid": p, "label": self.label(p, mark_me=True)} for p in ps]
        return {"_note": "identity correlation for this export. 'source' says where each label came "
                         "from; 'unresolved' means the profile knows no name and no number for that "
                         "jid, and the raw jid is used as the label.",
                "me": sorted(self.me),
                "identities": [rows[k] for k in sorted(rows)],
                "groups": {g: {"subject": v["subject"],
                               "participants": members(v["participants"]),
                               "past_participants": members(v["past_participants"]),
                               "admins": members(v["admins"]),
                               "super_admins": members(v["super_admins"])}
                           for g, v in sorted(self.groups.items())}}

    def coverage(self, jids):
        """{source: count} over the given jids -- what the logs report."""
        return collections.Counter(self.source(j) for j in jids)

# A decrypted body is protobuf, and `leaves()` deliberately collects EVERY string in the tree --
# which includes the sender's own jid, carried inside the message for addressing. That is metadata,
# not something a person typed, and now that the sender is resolved into its own column it is pure
# noise: measured over a 22,121-message store it was tacked onto the end of 6,218 lines.
#
# Dropped -- UNLESS it is the only string the body has. That is 424 messages here (393 image, 29
# video, 2 chat), where the address is all the text there is, and dropping it would turn a visible
# line into no line at all. So the filter can remove noise but can never remove a message.
_ADDRESS = re.compile(r"\+?\d{5,}(?::\d+)?@(?:lid|c\.us|s\.whatsapp\.net|g\.us|broadcast)\Z")

def message_text(pt, cap=2000):
    """The readable text of a decrypted body: every distinct string in it, addressing stripped."""
    lv = list(dict.fromkeys(leaves(pt)))
    keep = [x for x in lv if not _ADDRESS.match(x.strip())]
    return " ".join(keep or lv)[:cap]

def msg_row(m, when, text, ids):
    """One chats.json record. The identity fields are ADDITIVE: `sender` stays exactly as stored and
    the resolved name plus the lid/phone pair are added beside it, so nothing is replaced by an
    interpretation of it."""
    e = ids.entry(m.get("sender")) or {}
    return {"t": when, "dir": "me" if m["from_me"] else "them", "type": m["type"],
            "chat": m.get("chat"), "chat_name": ids.label(m.get("chat")),
            "sender": m.get("sender"), "sender_name": ids.label(m.get("sender")),
            "sender_lid": e.get("lid"), "sender_phone": e.get("pn"),
            "sender_source": ids.source(m.get("sender")), "text": text}

def write_transcripts(path, chats, ids):
    """transcripts.txt -- the artifact people actually read. Every line names its sender, and each
    chat header lists its senders with every jid form they appear under, so any line can be traced
    back to an identifier. `->` is outgoing, `<-` incoming."""
    with open(path, "w", encoding="utf-8") as f:   # emoji/non-Latin text -> pin UTF-8 (Windows is cp1252)
        f.write("# Names resolved from the examined profile's own contact/group stores: address-book\n"
                "# name, else WhatsApp pushname, else phone number, else the raw jid unchanged.\n"
                "# Each chat header lists its senders and their jid forms. '->' sent, '<-' received.\n")
        for c, ml in sorted(chats.items(), key=lambda kv: -len(kv[1])):
            tm = [m for m in ml if m["text"]]
            if not tm: continue
            kind = "group" if str(c).endswith("@g.us") else "1:1"
            f.write("\n===== %s  [%s]  (%s; %d msgs, %d text) =====\n"
                    % (ids.label(c), c, kind, len(ml), len(tm)))
            who = {}
            for m in ml:
                s = m.get("sender")
                if s and ids.key(s) not in who: who[ids.key(s)] = ids.row(ids.key(s))
            for cj, r in sorted(who.items(), key=lambda kv: (kv[1]["label"] or "").lower()):
                forms = "  ".join(x for x in (r["lid"], r["phone"]) if x and x != cj)
                f.write("  - %-26s %s%s%s\n" % (r["label"], cj, ("  " + forms) if forms else "",
                                                 "  (me)" if r["is_me"] else ""))
            for m in ml:
                if m["text"]:
                    f.write("[%s] %s %22s: %s\n" % (m["t"], "->" if m["dir"] == "me" else "<-",
                                                    m.get("sender_name") or m["dir"], m["text"]))

def load_firefox(origin):
    ls = {}
    lsp = os.path.join(origin, "ls/data.sqlite")
    if os.path.exists(lsp):
        c = sqlite3.connect(f"file:{lsp}?mode=ro&immutable=1", uri=True)
        for k, v, comp in c.execute("SELECT key,value,compression_type FROM data"):
            if comp:
                try: v = uncompress(v if isinstance(v, (bytes, bytearray)) else v.encode("latin-1"))
                except Exception: pass
            ls[k] = v.decode("utf-8","replace") if isinstance(v, (bytes, bytearray)) else v
        c.close()
    # root key from wawc_db_enc (marker extraction)
    root = None
    for sq in glob.glob(origin + "/idb/*wcanwec__bd*.sqlite"):
        conn = sqlite3.connect(f"file:{sq}?mode=ro&immutable=1", uri=True)
        kid = store_id(conn, "keys")                                  # by NAME; store ids are per-profile
        row = conn.execute("SELECT data FROM object_data WHERE object_store_id=?", (kid,)).fetchone() if kid else None
        if not row: continue
        d = uncompress(row[0])
        i = d.find(b"\x0a\x80\xff\xff")
        if i < 0: continue                                            # marker absent -> not this record; don't emit a bogus root
        j = d.find(b"\x00\x00\x00\x80\x00\x00\x00", i)
        if j < 0: continue                                            # inner marker absent -> don't slice a bogus root
        j += 7
        root = d[j:d.find(b"\x00"*8, j)]
    msgs = []
    meta = {"contact": 0, "group-metadata": 0, "chat": 0}
    stores = {}
    for sq in glob.glob(origin + "/idb/*meogdaerlo*.sqlite"):
        c = sqlite3.connect(f"file:{sq}?mode=ro&immutable=1", uri=True)
        sid = store_id(c, "message")
        if sid:
            skipped = 0
            for (d,) in c.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
                try: msgs.append(_norm_msg(sclone.loads(uncompress(d))))
                except Exception as e: skipped += 1; log.debug("firefox msg record skipped: %s", e)
            if skipped: log.debug("firefox: %d message record(s) failed to deserialize (of %d)", skipped, skipped + len(msgs))
        for n in _ID_STORES:                                  # who-is-who source records (small stores)
            stores[n] = _ff_store(c, n)
        for n in meta: meta[n] = len(stores.get(n, ()))       # counts for the terminal summary
        c.close()
    return ls, root, msgs, meta, stores

def load_chromium(profile):
    import chromium_reader as cr
    src = cr.load_source(profile); ls = src["localStorage"]; idb = src["idb"]
    root = None
    ck = idb.get("wawc_db_enc", {}).get("keys", [])
    if ck and isinstance(ck[0], dict) and hasattr(ck[0].get("key"), "key_data"):
        root = ck[0]["key"].key_data
    model = idb.get("model-storage", {})
    msgs = [_norm_msg(o) for o in model.get("message", []) if isinstance(o, dict)]
    meta = {n: sum(1 for o in model.get(n, []) if isinstance(o, dict)) for n in ("contact", "group-metadata", "chat")}
    stores = {n: [o for o in model.get(n, []) if isinstance(o, dict)] for n in _ID_STORES}
    return ls, root, msgs, meta, stores

# the stores that answer "who is this jid" -- small, and read by both engines
_ID_STORES = ("contact", "group-metadata", "chat", "participant")

def _ff_store(con, name):
    """Every record of one Firefox object store, looked up by NAME (store ids are per-profile)."""
    sid = store_id(con, name)
    if sid is None: return []
    out = []
    for (d,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
        try: out.append(sclone.loads(uncompress(d)))
        except Exception as e: log.debug("firefox %s record skipped: %s", name, e)
    return out

def load(profile=None, origin=None):
    """-> (engine, localStorage, root_key, messages, store_counts, Identities)"""
    if origin: engine, parts = "firefox", load_firefox(origin)
    elif os.path.isdir(os.path.join(profile, "IndexedDB")): engine, parts = "chromium", load_chromium(profile)
    else:
        cand = os.path.join(profile, "storage/default/https+++web.whatsapp.com")
        if not os.path.isdir(cand):
            raise SystemExit("Could not locate WhatsApp Web storage in that profile (pass --origin for Firefox).")
        engine, parts = "firefox", load_firefox(cand)
    ls, root, msgs, meta, stores = parts
    return engine, ls, root, msgs, meta, Identities(stores, ls)

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile"); ap.add_argument("--origin")
    ap.add_argument("--enc-static", default=None)
    ap.add_argument("--out", default="wa_decrypted")
    a = ap.parse_args()
    if not a.profile and not a.origin:
        ap.error("pass --profile <browser profile dir> or --origin <Firefox web.whatsapp.com dir>")
    engine, ls, root, msgs, meta, ids = load(a.profile, a.origin)
    print(f"[*] engine={engine}  messages={len(msgs)}  root_key={'yes' if root else 'NO'}  ls_keys={len(ls)}")
    if not root: raise SystemExit("root key not found (wawc_db_enc/keys)")
    salt_ws = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))

    # offline: recover + verify the Noise device key (preliminary-key CBC unwrap)
    try:
        prelim = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt_ws, info=b"\x00").derive(root)
        ni = json.loads(ls["WANoiseInfo"]); ivs = [base64.b64decode(x) for x in json.loads(ls["WANoiseInfoIv"])]
        def dc(b64, iv):
            pt = Cipher(algorithms.AES(prelim), modes.CBC(iv)).decryptor().update(base64.b64decode(b64)); p = pt[-1]
            return pt[:-p] if 1 <= p <= 16 and pt[-p:] == bytes([p])*p else pt
        ok = any(len(dc(ni["privKey"], ivs[p])) == 32 and
                 X25519PrivateKey.from_private_bytes(dc(ni["privKey"], ivs[p])).public_key().public_bytes_raw() == dc(ni["pubKey"], ivs[q])
                 for p in range(len(ivs)) for q in range(len(ivs)))   # WANoiseInfoIv may hold <4 IVs
        print(f"[+] Noise device key recovered offline + X25519-verified: {ok}")
    except Exception as e:
        print("[!] noise recovery skipped:", e)

    sch = collections.Counter(m["scheme"] for m in msgs if m["data"])
    print(f"[*] message schemes: {dict(sch)}")
    if not a.enc_static:
        print("[i] no --enc-static: offline inventory only. Message TEXT needs companion_enc_static "
              "(from memory or a reconnect). Media keys/metadata are already on disk.")
        return

    key = HKDF(algorithm=hashes.SHA256(), length=16, salt=base64.b64decode(a.enc_static), info=salt_ws).derive(root)

    # VALIDATE the salt/key against reference ciphertext (strict PKCS7) — a wrong companion_enc_static
    # must NOT be reported as success. Right key => ~100% valid padding; wrong key => ~0.4%.
    def strict_pk7(b): return bool(b) and len(b) % 16 == 0 and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]])*b[-1]
    refs = [m for m in msgs if m["data"] and m["scheme"] == 1][:40]   # only scheme-1 (the key we derive); scheme-0 would garbage-validate
    good = 0
    for m in refs:
        try:
            if strict_pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"])): good += 1
        except Exception: pass
    if refs and good < len(refs) * 0.5:
        print(f"[X] companion_enc_static is INVALID for this profile/device — only {good}/{len(refs)} "
              f"reference messages validate. Not writing garbage. (Wrong key, or wrong browser's salt.)")
        sys.exit(3)
    print(f"[+] companion_enc_static VALIDATED ({good}/{len(refs)} reference messages).")
    os.makedirs(a.out, exist_ok=True)
    def ts(v):
        try:
            v = float(v); v = v/1000 if v > 1e12 else v
            return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if 1e9 < v < 2e9 else ""
        except Exception: return ""
    chats = collections.defaultdict(list); ok = fail = 0
    for m in msgs:
        if not m["data"] or m["scheme"] != 1: continue   # only scheme-1 bodies match this key; skip (don't write garbage)
        if len(m["data"]) % 16: fail += 1; continue       # misaligned: see the note in wawf.py's cmd_decrypt
        try: pt = pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception: fail += 1; continue
        txt = message_text(pt)
        ok += 1
        chats[m["chat"]].append(msg_row(m, ts(m["t"]), txt, ids))
    print(f"[+] decrypted {ok} bodies ({fail} failed)  ->  {a.out}/")
    if ok and fail > ok:
        print("[!] most bodies failed to decrypt — companion_enc_static likely wrong for THIS profile/device.")
    for c in chats: chats[c].sort(key=lambda x: x["t"])
    json.dump(chats, open(f"{a.out}/chats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    seen = set(chats) | set(m["sender"] for ml in chats.values() for m in ml if m.get("sender"))
    json.dump(ids.table(seen), open(f"{a.out}/identities.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1, default=str)
    write_transcripts(f"{a.out}/transcripts.txt", chats, ids)
    cov = ids.coverage(s for ml in chats.values() for s in (m.get("sender") for m in ml) if s)
    print(f"[+] senders identified: " + "  ".join(f"{k}={v}" for k, v in cov.most_common()))
    print(f"    transcripts.txt + chats.json + identities.json written")

if __name__ == "__main__":
    main()
