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
import wa_opaque
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
# `str.isprintable()` is False for a newline, for a zero-width joiner, and for the tag characters a
# flag emoji is built from, so the 90%-printable test that rejects binary was also rejecting real
# messages: a reply containing a blank line, "Same pg <ZWJ emoji>", a lone shrug, the England flag.
# Measured over 22,121 bodies this recovers 12 strings and gives 3 messages back text they had none
# of; nothing containing an actual control character is admitted, because Cc stays excluded while
# the deliberate line breaks and the joiners/marks that are part of written text do not.
#
# This is the same failure as the one that cost 767 emoji-only messages their text -- that fix
# relaxed the "must contain a letter" rule and left this second gate in place behind it.
# Category Cf -- joiners, selectors AND the bidi controls -- is accepted here, because this test
# decides whether a string is text at all, and a bidi control is a text character: it occurs in
# legitimate Arabic and Hebrew writing. Rejecting a string over one would discard the whole message,
# which is worse than the problem -- measured, "see <RLO>this" is 8 printable of 9 and falls under
# the 90% threshold, so the message would lose its text entirely.
#
# What a bidi control must not do is reach a LINE-STRUCTURED artifact, where it re-orders the sender,
# the arrow and the text around each other in a file whose premise is that every line is
# attributable. That is the writer's job: `_printable_line` below removes them on the way into
# transcripts.txt, while chats.json keeps exactly what the store held.
_JOINERS = {0x200C, 0x200D, 0x2060}
def _textlike(c):
    o = ord(c)
    return (c.isprintable() or c in "\n\r\t" or o in _JOINERS
            or 0xE0020 <= o <= 0xE007F
            or unicodedata.category(c) in ("Cf", "Mn", "Me", "Mc")
            or _newer_than_tables(c))

def _newer_than_tables(c):
    """A code point this interpreter's Unicode database calls unassigned, that a newer standard may
    well have assigned. The build interpreter is Python 3.12 (Unicode 15.0); U+1FAE9 FACE WITH BAGS
    UNDER EYES arrived in Unicode 16, read as unassigned, failed the 90%-text test, and took the
    whole message with it -- measured: messages consisting of, or ending in, that emoji exported as
    empty. Surrogates and the permanent noncharacters are still refused."""
    o = ord(c)
    return (unicodedata.category(c) == "Cn" and o >= 0x2000
            and not (o & 0xFFFE) == 0xFFFE and not 0xFDD0 <= o <= 0xFDEF)

# Bidi and other explicit-formatting controls, stripped on the way into the LINE-ORIENTED file only.
# chats.json keeps the characters the store held; the transcript cannot, because they rewrite it.
_BIDI = {0x200E, 0x200F, 0x061C, 0x2066, 0x2067, 0x2068, 0x2069,
         0x202A, 0x202B, 0x202C, 0x202D, 0x202E}
def _printable_line(t):
    """Text safe to write into a line-structured artifact: no bidi reordering, no stray controls."""
    return "".join(c for c in str(t or "")
                   if ord(c) not in _BIDI and (c in "\n\t" or unicodedata.category(c)[0] != "C"
                                               or ord(c) in _JOINERS or 0xE0020 <= ord(c) <= 0xE007F))

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
                        if t and t != "null" and sum(_textlike(c) for c in t) >= len(t)*0.9 \
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
            "iv": iv, "data": data, "scheme": op.get("_scheme") if op else None,
            "filename": as_str(o.get("filename")),
            "view_once": bool(o.get("isViewOnce")),
            "ack": o.get("ack") if isinstance(o.get("ack"), int) else None}
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
    """A stored name, EXACTLY as saved -- or None when there is none.

    It used to return v.strip(), so a group whose subject was saved as "Book club " was exported
    as "Book club". JSON's contract is the value as stored; whitespace is only used to decide
    whether there is a name at all. (The transcript still collapses whitespace in a label, because a
    label there must fit on one line -- chats.json and identities.json keep it verbatim.)"""
    return v if isinstance(v, str) and v.strip() else None

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
        self.contact_records = [o for o in st.get("contact", []) if isinstance(o, dict)]   # verbatim, for contacts.csv
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
        # Names come from the live record only (above), because a superseded record can hold a name
        # the user has since deleted. The lid<->phone LINK is different: it is an identifier mapping,
        # it does not change, and losing it costs an identity. So it is harvested from every record,
        # including superseded ones -- a live record that omits `phoneNumber` no longer hides it.
        for o in st.get("contact") or ():
            if not isinstance(o, dict): continue
            jid, pn = canon_jid(o.get("id")), canon_jid(o.get("phoneNumber"))
            if not (jid and pn): continue
            ent = self._id.get(jid) or self._id.get(pn)
            if ent is None: continue                           # no identity to attach it to
            if jid.endswith("@lid"): ent["lid"] = ent["lid"] or jid
            ent["pn"] = ent["pn"] or pn
            self._id.setdefault(jid, ent); self._id.setdefault(pn, ent)
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
        # ...and `me` is the IDENTITY, not the two strings localStorage happened to hold. A profile
        # with `last-wid-md` but no `WALid` knows my phone form only, while my own messages are
        # authored by my lid -- so every outgoing message would fail `is_me` and be relabelled as
        # incoming, which is the exact defect the sender-driven direction was added to fix. Any form
        # the contact store ties to one of mine is mine too.
        for j in (ent.get("lid"), ent.get("pn")):
            if j: self.me.add(j)

    def learn_me(self, msgs, min_share=0.5):
        """Add my own address forms that the PROFILE did not name, taken from the messages.

        `last-wid-md` is on every logged-in profile; `WALid` is not guaranteed, and a profile can
        hold one of my forms while my own messages are authored by the other. Nothing then ties them
        together unless a contact record happens to, and every outgoing message would be attributed
        to the other party.

        The store already records authorship: the message id's `fromMe` flag. So the author of my
        outgoing messages IS me -- with one exception, group system events, where the flag means
        "recorded locally" and the author is whoever acted. A share threshold is what separates the
        two: my own lid accounts for essentially all flag-outgoing messages, while an actor on a
        system event accounts for a handful. Only ADDS forms; whatever localStorage said still
        stands, and a store whose flags are unusable simply teaches nothing.
        """
        c = collections.Counter(canon_jid(m.get("sender")) for m in msgs
                                if m.get("from_me") and m.get("sender"))
        c.pop("", None)
        total = sum(c.values())
        if not total: return set()
        learned = set()
        for form, n in c.items():
            if n / total >= min_share and form not in self.me:
                learned.add(form)
        for form in learned:
            ent = self._id.get(form)
            if ent is None:
                ent = next((self._id[j] for j in sorted(self.me) if j in self._id), None) or {
                    "lid": None, "pn": None, "name": None, "pushname": None, "addressbook": False}
                self._id[form] = ent
            if form.endswith("@lid"): ent["lid"] = ent["lid"] or form
            else: ent["pn"] = ent["pn"] or form
            self.me.add(form)
        if learned:
            log.info("own address form(s) not named by the profile, taken from message authorship: %d",
                     len(learned))
        return learned

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
        """Is this me, by IDENTITY. A form I have never seen still counts when it belongs to the same
        person as a form I have, which a literal set membership test cannot tell."""
        cj = canon_jid(jid)
        if cj in self.me: return True
        if not self.me: return False
        k = self.key(cj)
        return bool(k) and k in {self.key(x) for x in self.me}

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
        # The chat store names a CHAT, which is keyed by whichever form that chat uses -- so a name
        # attached to someone's phone form is invisible when the same person is reached by their lid.
        # Looked up across every form of the identity, or one person gets two labels in one export:
        # their chat-store name in chats.json (matched on the form the message used) and their phone
        # number in identities.json and the legend (matched on the identity key).
        for form in (cj, e.get("lid"), e.get("pn")):
            if form and form in self._chat: return self._chat[form], "chat-name"
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
        analyst can join on it rather than re-derive it from the stores.

        One row per PERSON, not per address: keying on the jid listed the same contact twice, once
        under their lid and once under their phone number, with both rows carrying the same name.
        The other forms are listed in `jids` so a lookup by any of them still lands on one row."""
        rows = {}
        for j in jids:
            cj = canon_jid(j)
            if not cj: continue
            k = self.key(cj)
            if k not in rows: rows[k] = dict(self.row(k), jids=[])
            if cj not in rows[k]["jids"]: rows[k]["jids"].append(cj)
        for r in rows.values(): r["jids"].sort()
        def members(ps): return [{"jid": p, "label": self.label(p, mark_me=True)} for p in ps]
        return {"_note": "Identity correlation for this export: one row per PERSON, with every "
                         "address form they appeared under in 'jids' (a phone number and a lid are "
                         "the same person). 'source' says where the label came from, and "
                         "'unresolved' means the profile knows no name and no number for that jid, "
                         "so the raw jid is used as the label rather than a guess.",
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
# Dropped unconditionally. It was once kept when it was the only string a body had, on the reasoning
# that it was "all the text there is" -- but that reasoning was about the WHOLE body, before own and
# quoted content were separated. Once they are, a body whose own content is nothing but addressing
# has no text, and 569 messages (397 image, 104 sticker, 31 video, 22 ptt, 11 album, 2 chat, 1 audio,
# 1 unknown) were printing their routing jid where their words would go. Re-measured across all
# 22,121 bodies: removing the exception drops a bare address in every one of those cases and loses
# nothing else -- zero messages lose anything that is not an address. The record itself is not lost
# either; it stays in chats.json with its type, and the transcript already omits messages with no
# text, which is what a media message without a caption is.
_ADDRESS = re.compile(r"\+?\d{5,}(?::\d+)?@(?:lid|c\.us|s\.whatsapp\.net|g\.us|broadcast)\Z")

# A decrypted body has TWO messages in it. Top-level field 1 is this message; top-level field 2 is
# the message it replies to, as the client stored the quote. Scraping the whole tree therefore put
# somebody else's words in this message's text column: measured on this store, 3,789 strings came
# from field 2, and 1,884 of them are verbatim the own-text of another message in the same chat (the
# rest quote messages older than the local cache, so there is nothing to match them against). The
# worst case was a sticker reply, which has no text of its own: 194 of them were displayed with the
# quoted message as if the sticker's sender had typed it.
#
# So the two are separated at the source. The quote is not discarded -- it is real evidence of what
# was replied to -- it is just no longer attributed to the wrong person.
def split_body(pt):
    """-> (own, quoted) byte segments of a decrypted body. Either may be None.

    Deliberately forgiving: anything unexpected falls back to (whole body, None), which is exactly
    the old behaviour, so an unfamiliar shape loses nothing."""
    own, quoted = [], None
    i, n = 0, len(pt)
    try:
        while i < n:
            tag, i = _varint(pt, i)
            f, wt = tag >> 3, tag & 7
            if wt == 2:
                ln, i = _varint(pt, i); seg = pt[i:i + ln]; i += ln
                # Field 2 is the quote, and only the first of it. EVERYTHING ELSE counts as this
                # message's own content -- including a repeated field 1 and any field this wrapper
                # has never been seen to carry. Keeping only field 1 would drop such content with no
                # counter and no log line, which is the failure this file keeps having to re-fix;
                # every body in the reference profile is exactly {1, 2}, so this costs nothing today
                # and loses nothing tomorrow.
                if f == 2 and quoted is None: quoted = seg
                else: own.append(seg)
            elif wt == 0: _, i = _varint(pt, i)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            else: return pt, None
    except Exception as e:
        log.debug("body split failed, scraping whole body: %s", e)
        return pt, None
    if not own and quoted is None:
        return pt, None          # parsed, but nothing recognised: scrape it all rather than lose it
    return (b"".join(own) or None), quoted   # own is None when the only content is a quote, and
                                             # saying so is the entire point

# A serialized message key, "<fromMe>_<chat>_<id>[_<participant>]". An encrypted edit's body holds
# the key of the message it edits, and it was exported as that message's TEXT -- the transcript
# showed the user "saying" true_6627..._3EB0FBE4... It is a reference, never something typed; the
# raw export keeps it.
_MSGKEY = re.compile(r"(?:true|false)_[^_\s]+@[a-z.]+_[0-9A-Fa-f]{16,}(?:_[^\s]+)?\Z")

def _primary_text(buf):
    """Field 1 of the body's own part, read verbatim -- the message's `body`.

    This is WhatsApp Web's internal record, not the protocol Message. Field 1 is its `body`
    property: the text of a text message, but for image / video / sticker messages the BASE64 JPEG
    THUMBNAIL ("/9j/4AAQ..."). `leaves()` guards against such blobs with a 12+ digit / 40+ base64 /
    90%-text test, and applied to a text message's own body those guards deleted real messages: a
    number someone sent ("1234567812345678", "919876543210"), a pasted hash, and -- with
    _newer_than_tables -- anything containing a new emoji. So: take field 1 verbatim unless it is an
    encoded image, which is decided by decoding it, not by its shape.
    (A first version also read field 6 as extendedTextMessage; this is not the Message schema, so
    that was unverified and is gone. Regression check over all 22,562 bodies: see STATE PHASE 43.)"""
    if not buf: return ""
    i, n = 0, len(buf)
    try:
        while i < n:
            tag, i = _varint(buf, i); f, wt = tag >> 3, tag & 7
            if wt == 2:
                ln, i = _varint(buf, i); seg = buf[i:i + ln]; i += ln
                if f == 1:
                    t = seg.decode("utf-8")
                    return "" if (not t.strip() or _is_encoded_image(t)) else t
            elif wt == 0: _, i = _varint(buf, i)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            else: break
    except Exception:
        pass                      # not readable field by field: the scraper still runs
    return ""

_IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG", b"RIFF", b"GIF8")
def _is_encoded_image(t):
    """True for a base64 string that decodes to an image (a stored thumbnail), not merely base64-shaped."""
    s = t.strip()
    if len(s) < 40 or not re.fullmatch(r"[A-Za-z0-9+/\r\n]+={0,2}", s): return False
    try:
        head = base64.b64decode(s[:64] + "=" * (-len(s[:64]) % 4))
    except Exception:
        return False
    return head.startswith(_IMAGE_MAGIC)

def _scrape(buf, cap):
    if not buf: return ""
    p = _primary_text(buf)
    # The address filter still applies to the primary text: a body that is only a jid is routing
    # data in these records, not something someone typed (pinned by selftest_identities).
    if p and (_ADDRESS.match(p.strip()) or _MSGKEY.match(p.strip())): p = ""
    # ...and a scraped fragment of the primary text is dropped, not appended. leaves() tries any
    # string starting with a byte that is also a protobuf tag ('*', '"', newline...) as nested
    # protobuf; a WhatsApp *bold* message parsed that way lost its first characters, which is the
    # copy the old export showed ("allet Update*" for "*Wallet Update*", 26 messages here).
    rest = [x for x in leaves(buf) if not _ADDRESS.match(x.strip()) and not _MSGKEY.match(x.strip())
            and not (p and x.strip() in p)]
    lv = list(dict.fromkeys(([p] if p else []) + rest))
    return " ".join(lv)[:cap]

def _schema_text(msg, cap=None):
    """The text of one decoded MsgOpaqueData: its `body`, or its `caption` when the body is not text.

    For media WhatsApp Web keeps a base64 JPEG thumbnail in `body` and the caption in `caption`; a
    link preview's title/description/url are separate fields and are NOT part of the text (they are
    exported as `link`). A body that is only an address or a message key is routing data."""
    if not msg: return ""
    body = msg.get("body") or ""
    if body and (not body.strip() or _is_encoded_image(body) or _ADDRESS.match(body.strip())
                 or _MSGKEY.match(body.strip())):
        body = ""
    # A poll or an event has no body; its question / name is what Android shows as the message text.
    t = body or msg.get("caption") or msg.get("pollName") or msg.get("eventName") or ""
    return t[:cap] if cap else t

def body_details(pt):
    """Structured parts of a body (link preview, location, poll, event...) or {} -- see wa_opaque.details."""
    row = wa_opaque.decode_row(pt) if pt else None
    return wa_opaque.details(row[0]) if row else {}

def texts(pt, cap=None):
    """-> (own text, quoted text) from ONE parse of the body.

    Decoded by WhatsApp Web's own schema (wa_opaque) when the body fits it, which keeps a link
    preview's title and description out of the text. A body that does not fit falls back to the
    schema-free reader below, so an unfamiliar shape still loses nothing.

    Both writers want both strings for every message, and calling `message_text` then `quoted_text`
    parsed each body twice and walked the tree twice -- 22,121 bodies in the hot loop of both
    exporters, for identical output.

    No length cap by default. JSON used to cut every message at 2,000 characters and SQLite at
    8,000, so a long forward or a pasted document lost its tail without a word -- 16 messages and
    3 quotes in the reference store, and the two exports disagreed about them."""
    row = wa_opaque.decode_row(pt) if pt else None
    if row is not None:
        return _schema_text(row[0], cap), _schema_text(row[1], cap)
    own, q = split_body(pt)
    return _scrape(own, cap), _scrape(q, cap)

def message_text(pt, cap=None):
    """This message's OWN text: every distinct string in its own content, addressing stripped."""
    return texts(pt, cap)[0]

def quoted_text(pt, cap=None):
    """The text of the message this one replies to, or "" -- kept apart, never merged into the above."""
    return texts(pt, cap)[1]

ACK_STATUS = {-1: "error", 0: "pending", 1: "sent", 2: "delivered", 3: "read", 4: "played"}
# entries that are not messages anyone sent: no delivery state applies, so none is written
_SYSTEM_TYPES = {"e2e_notification", "gp2", "notification_template", "notification", "pinned_message",
                 "protocol", "revoked", "ciphertext", "call_log", "message_history_notice"}

VIEW_ONCE_NOTE = ("view-once: WhatsApp sends the content only to the phones, never to linked devices; "
                  "the browser holds this record of it")

def msg_row(m, when, pt, ids):
    """One chats.json record, built from the decrypted body in one place so no writer can derive the
    text differently. The identity fields are ADDITIVE: `sender` stays exactly as stored and the
    resolved name plus the lid/phone pair are added beside it, so nothing is replaced by an
    interpretation of it. `text` is this message's own words; `quoted_text` is what it replied to."""
    e = ids.entry(m.get("sender")) or {}
    # Direction follows WHO SENT IT, not the stored `fromMe` flag, because on group system events the
    # two disagree: 20 records here are flagged outgoing while their actor is someone else (a group
    # subject change, an add, a remove), and reading those as messages I sent is simply wrong. The
    # flag is not lost -- `id` begins with "true_" or "false_" and is carried on every row.
    # ...but only when the profile actually told us who "me" is. On a profile missing `last-wid-md`
    # or `WALid` every message would otherwise read as incoming, which is worse than the flag.
    me = (ids.is_me(m.get("sender")) if (m.get("sender") and ids.me)
          else bool(m["from_me"]))      # is_me() compares identities, so either form of mine counts
    own, quoted = texts(pt)
    # WhatsApp Web stores a document's FILENAME in the caption field when it has no caption; a
    # "caption" equal to the filename is not something anyone wrote (the filename is its own field).
    if m.get("type") == "document" and own and own.strip() == (m.get("filename") or "").strip():
        own = ""
    det = body_details(pt)
    row = {"id": m.get("id"), "t": when, "dir": "me" if me else "them", "type": m["type"],
            "chat": m.get("chat"), "chat_name": ids.label(m.get("chat")),
            "sender": m.get("sender"), "sender_name": ids.label(m.get("sender")),
            "sender_lid": e.get("lid"), "sender_phone": e.get("pn"),
            "sender_source": ids.source(m.get("sender")),
            "text": own, "quoted_text": quoted,
            # Where this message came from. A cached message was in the browser's own storage when
            # the profile was examined; a recovered one was served by the phone during a `--history`
            # pull, over the network, at the time of the run. Same timeline, different provenance,
            # and an export that merges them has to say which is which.
            "source": "cache"}
    if m.get("filename"): row["filename"] = m["filename"]
    # WhatsApp does not send view-once content to linked devices: the browser keeps a record that the
    # message exists (sender, time, photo or video) and nothing else. Said here, so an empty row is not
    # read as a gap in the extraction.
    if m.get("view_once"):
        row["view_once"] = True
        row["content_note"] = VIEW_ONCE_NOTE
    # Delivery state of a message I sent, as WhatsApp Web last recorded it (the ticks).
    if m.get("from_me") and m.get("ack") in ACK_STATUS and (m["ack"] != 0 or m.get("type") not in _SYSTEM_TYPES):
        row["ack"] = m["ack"]; row["status"] = ACK_STATUS[m["ack"]]
    row.update(det)                     # link / location / poll / event / payment, only when present
    return row

# ONE cap for every place a label is written. Capping per call site (40 on a message line, 60 in the
# legend, 80 in a header) rendered the same person two different ways in one file and made a line
# impossible to match to its legend entry. Long enough for any real name -- the longest in the
# reference profile is 32 characters -- and short enough to keep a line readable.
_LABEL_MAX = 48

def _oneline(v, width=None):
    """A label flattened to one line, for a file whose structure is lines.

    A name or group subject is whatever the account holder typed, which can contain a newline or a
    tab -- and a label is written into the chat header, the participant legend and every message
    line, each of which must stay one line. Message TEXT is handled differently (it keeps its line
    breaks, continued under '|'); a label has no such affordance, so it is collapsed. Nothing is
    lost that identifies anyone: the raw jid sits beside it, and chats.json keeps the label verbatim.
    """
    t = " ".join(_printable_line(v).split())
    # A value cut to fit reads as the whole value unless something says otherwise, and in a
    # transcript that is a quiet claim about what somebody is called. Mark it; the full label is in
    # chats.json and identities.json.
    return (t[:width - 1] + "\u2026") if width and len(t) > width else t

# The phone returns a message as {chat, id, fromMe, participant, ts, text, type}: the stanza id
# alone rather than the composite the store uses, the wire jid rather than the form the store filed
# the chat under, and the protobuf field name rather than the store's type word. Normalised here so
# a recovered message and a cached one are the same kind of thing in the export.
_HIST_TYPE = {"conversation": "chat", "extendedtextmessage": "chat", "imagemessage": "image",
              "videomessage": "video", "audiomessage": "audio", "pttmessage": "ptt",
              "documentmessage": "document", "stickermessage": "sticker",
              "contactmessage": "vcard", "contactsarraymessage": "vcard",
              "locationmessage": "location", "livelocationmessage": "location",
              "reactionmessage": "reaction", "pollcreationmessage": "poll_creation",
              "protocolmessage": "protocol", "senderkeydistributionmessage": "e2e_notification"}

def hist_type(t):
    """The protobuf field name the phone used -> the type word the local store uses."""
    k = str(t or "").strip()
    if not k: return "unknown"
    # "?" is not "unknown": the history mapper writes it exactly when a record has NO message payload
    # (`w.message ? Object.keys(w.message)[0] : '?'`), i.e. a stub -- someone added, left, changed
    # the subject. As "unknown" those read as content of no known type, and in a merged export 23 of
    # them looked like outgoing messages sent by someone else. They are system events.
    if k == "?": return "notification"
    # Records banked before the mapper skipped metadata keys were typed by that key instead of their
    # content. The content is not recoverable from the ledger; say so rather than invent a type.
    if k == "messageContextInfo": return "unknown"
    lk = k.lower()
    if lk in _HIST_TYPE: return _HIST_TYPE[lk]
    return k[:-7].lower() if lk.endswith("message") else lk

def stanza_of(mid):
    """The stanza id inside a stored composite id (`false_<chat>_<stanza>[_<jid>]`), or the id itself.

    The two sides name a message differently: the store uses the composite, the phone returns only
    the stanza. The stanza is what they share, so it is what dedup has to compare -- and comparing
    the composites would fail anyway, because the chat jid inside them is not always the same form.
    """
    s = str(mid or "")
    parts = s.split("_")
    return parts[2] if len(parts) >= 3 else s

def hist_row(r, ids, when, chat_key=None):
    """One chats.json record from a message the PHONE served, in the same shape as a cached one."""
    chat = chat_key or canon_jid(r.get("chat")) or r.get("chat")
    fromme = bool(r.get("fromMe"))
    # In a group the sender is `participant`; in a 1:1 it is the chat itself, which is the same rule
    # the local store follows. For my own messages it is me.
    part = r.get("participant")
    if fromme:
        sender = (sorted(ids.me)[0] if ids.me else None)
        if part: sender = canon_jid(part)
    else:
        sender = canon_jid(part) if part else (None if str(chat).endswith("@g.us") else chat)
    e = (ids.entry(sender) or {}) if sender else {}
    me = ids.is_me(sender) if (sender and ids.me) else fromme
    # `pushName` is the name the sender chose for themselves, which the phone sends alongside the
    # message. It is used only where the profile has nothing better: with no jid at all it is the
    # only identification there is, and with a jid the profile cannot name it beats a bare number.
    # The address book still wins, as everywhere else.
    push = _txt(r.get("pushName"))
    src = ids.source(sender) if sender else None
    if sender and src != "unresolved":
        name, src = ids.label(sender), src
    elif push:
        name, src = push, "history-pushname"
    elif sender:
        name, src = ids.label(sender), src
    else:
        name, src = "(unknown)", "unresolved"
    return {"id": ("true" if fromme else "false") + "_" + str(chat) + "_" + str(r.get("id")),
            "t": when, "dir": "me" if me else "them", "type": hist_type(r.get("type")),
            "chat": chat, "chat_name": ids.label(chat),
            "sender": sender, "sender_name": name,
            "sender_lid": e.get("lid"), "sender_phone": e.get("pn"),
            "sender_source": src,
            "text": r.get("text") or "", "quoted_text": "",      # as sent: decrypt, change nothing
            "source": "phone"}

def bank_history(master, msgs):
    """Fold one pass's messages into the accumulated ledger. -> (new, enriched)

    The old rule was "if this id is not already banked, add it" -- which is right for counting what
    is NEW and wrong for everything else. A message banked by a run whose extractor did not capture
    the group sender could never gain one, even when a later pull served the same message again with
    it: the incoming copy was dropped whole. 29,864 messages in this project's own ledger have no
    sender for exactly that reason.

    So a banked record is now ENRICHED: fields it is missing are filled from the new copy, and
    fields it already has are left alone, because the older copy is the one the rest of the ledger
    (and the anchors) were built from. `False` and `0` are values, not absences.
    """
    EMPTY = (None, "", [], {})
    new = enriched = 0
    for m in msgs or ():
        i = m.get("id")
        if not i: continue
        cur = master.get(i)
        if cur is None:
            master[i] = m; new += 1; continue
        filled = False
        for k, v in m.items():
            if any(v is e for e in EMPTY) or v in ("",): continue
            if any(cur.get(k) is e for e in EMPTY) or cur.get(k) == "":
                cur[k] = v; filled = True
        if filled: enriched += 1
    return new, enriched

def bodyless_row(m, when, ids, status):
    """A message whose body could not be turned into text still EXISTS, and is written as a row.

    The text writers used to `continue` past any message without a decryptable body, so it vanished
    from chats.json and the transcript while msgstore.db -- which writes every message -- kept it.
    Measured: a message deleted by its sender ("revoked", body cleared) was in msgstore.db and in
    neither of the other two formats. A deletion marker is evidence. `status` says why there is no
    text: "none" (no body was stored), "other-scheme" (a body this key does not open), "failed"."""
    row = msg_row(m, when, b"", ids)
    row["body_status"] = status
    return row

def merge_history(chats, recovered, ids, ts):
    """Fold messages the phone served into an export built from the local store.

    Dedup is on the stanza id, and the CACHED copy wins: it was read from the device's own storage
    rather than reconstructed from what the phone chose to send back. A recovered chat arrives as a
    wire jid, which may not be the form the store filed that chat under -- `@s.whatsapp.net` where
    the store has `@lid` -- so it is mapped through the identity before being filed, or the same
    conversation would split into two chats in the output.

    Returns (added, skipped_already_present, chats_touched).
    """
    have = {stanza_of(m.get("id")) for ml in chats.values() for m in ml}
    bykey = {}                                  # identity key of a chat -> the key the store used
    for c in chats:
        bykey.setdefault(ids.key(c), c)
        bykey.setdefault(canon_jid(c), c)
    added = skipped = 0
    touched = set()
    for r in recovered or ():
        sid = str(r.get("id") or "")
        if not sid or not r.get("chat"):
            continue
        if sid in have:
            skipped += 1
            continue
        raw = canon_jid(r.get("chat"))
        key = bykey.get(ids.key(raw)) or bykey.get(raw) or raw
        chats.setdefault(key, []).append(hist_row(r, ids, ts(r.get("ts")), chat_key=key))
        have.add(sid); added += 1; touched.add(key)
    for c in touched:
        chats[c].sort(key=lambda x: x["t"])
    return added, skipped, touched

def _disambiguate(who):
    """{sender key: legend row} -> {sender key: label as printed in this chat}.

    Different people can share a display name -- one group here has five members called the same
    thing -- and a transcript line naming only that name cannot be attributed. Within a chat, each
    such label gets the last digits of that person's own number (or lid) appended, as many as it
    takes to tell them apart. Labels that are already unique are printed unchanged."""
    base = {k: _oneline(r["label"], _LABEL_MAX) for k, r in who.items() if r is not None}
    out = dict(base)
    groups = collections.defaultdict(list)
    for k, lab in base.items(): groups[lab].append(k)
    for lab, keys in groups.items():
        if len(keys) < 2: continue
        ids_ = {k: re.sub(r"\D", "", ((who[k].get("phone") or who[k].get("lid") or k) or "").split("@")[0])
                for k in keys}
        n = 4
        while n < 16 and len({ids_[k][-n:] for k in keys}) < len(keys): n += 2
        for k in keys:
            out[k] = "%s ·%s" % (lab, ids_[k][-n:] or "?")
    return out

CONTACT_COLUMNS = (("jid", "id"), ("phone_number", "phoneNumber"), ("name", "name"), ("short_name", "shortName"),
                   ("pushname", "pushname"), ("username", "username"), ("about", "textStatusString"),
                   ("about_updated", "textStatusLastUpdateTime"), ("in_address_book", "isAddressBookContact"),
                   ("type", "type"), ("display_name_lid", "displayNameLID"))

def write_contacts_csv(path, ids):
    """contacts.csv -- the `contact` store, one row per stored record, as stored. WhatsApp keeps a
    person under both their lid and their phone jid; `phone_number` on the lid row links the two."""
    import csv
    def v(x):
        if x is None or type(x).__name__ == "_Undefined": return ""
        if isinstance(x, bool): return "yes" if x else "no"
        return as_str(x) if not isinstance(x, (int, float)) else x
    seen = set()
    with open(path, "w", encoding="utf-8-sig", newline="") as f:      # BOM: Excel opens it as UTF-8
        w = csv.writer(f)
        w.writerow([c for c, _ in CONTACT_COLUMNS])
        n = 0
        for o in ids.contact_records:
            row = [v(o.get(src)) for _, src in CONTACT_COLUMNS]
            k = tuple(row)
            if k in seen: continue                 # superseded copies of an identical record
            seen.add(k); w.writerow(row); n += 1
    return n

def write_transcripts(path, chats, ids):
    """transcripts.txt -- the artifact people actually read. Every line names its sender, and each
    chat header lists its senders with every jid form they appear under, so any line can be traced
    back to an identifier. `->` is outgoing, `<-` incoming."""
    with open(path, "w", encoding="utf-8") as f:   # emoji/non-Latin text -> pin UTF-8 (Windows is cp1252)
        f.write("# Names resolved from the examined profile's own contact/group stores: address-book\n"
                "# name, else WhatsApp pushname, else phone number, else the raw jid unchanged.\n"
                "# Each chat header lists its senders and their jid forms. '->' sent, '<-' received.\n"
                "# A message that spans lines is continued under '|', and 're:' is the message being\n"
                "# replied to -- quoted by the client, written by whoever is named on that line.\n"
                "# '(image)', '(sticker)', '(revoked)' and the like are messages with no text of\n"
                "# their own, shown as the type the store recorded.\n")
        for c, ml in sorted(chats.items(), key=lambda kv: -len(kv[1])):
            tm = [m for m in ml if m["text"]]
            if not ml: continue
            kind = "group" if str(c).endswith("@g.us") else "1:1"
            f.write("\n===== %s  [%s]  (%s; %d msgs, %d with text) =====\n"
                    % (_oneline(ids.label(c), _LABEL_MAX), c, kind, len(ml), len(tm)))
            who = {}
            for m in ml:
                # A message with NO sender still gets a legend entry. Skipping it left the line
                # reading "(unknown)" with nothing in the legend to match it against -- in a file
                # whose promise is that every line's sender is listed above it. It happens for real:
                # a group message recovered from the phone before the extractor captured
                # `key.participant` has no author at all, and that absence is itself worth stating.
                k = ids.key(m["sender"]) if m.get("sender") else ""
                if k not in who: who[k] = ids.row(m["sender"]) if m.get("sender") else None
            disp = _disambiguate(who)
            for cj, r in sorted(who.items(), key=lambda kv: ((kv[1] or {}).get("label") or "~").lower()):
                if r is None:
                    f.write("  - %s  (no sender recorded in the message)\n" % "(unknown)".ljust(24))
                    continue
                forms = "  ".join(x for x in (r["lid"], r["phone"]) if x and x != cj)
                f.write("  - %s  %s%s%s\n" % (disp[cj].ljust(24), cj,
                                               ("  " + forms) if forms else "",
                                               "  (me)" if r["is_me"] else ""))
            for m in ml:
                # EVERY message gets a line. Skipping the ones with no text of their own dropped
                # 2,374 records from the readable artifact -- caption-less media, revoked messages,
                # call logs -- and with them the `re:` quote on a sticker reply, which is the one
                # case the own/quoted split was made for. A message with nothing to quote and nothing
                # to say is still a message that was sent at a time by a person, so it is shown as
                # its type in parentheses. Nothing is invented: `(image)` is the type the store
                # recorded, not a guess at content.
                body = m["text"] or ("(view-once %s: content only on the phones)" % (m.get("type") or "media")
                                     if m.get("view_once") else "(%s)" % (m.get("type") or "unknown"))
                # 3.7% of messages contain newlines, and writing them raw broke the one-line-per-
                # message structure this file promises: 2,394 continuation lines carried no
                # timestamp and no sender, and 29 of them began with '#', which is what this file
                # uses for its own header. Continuations are now indented under a '|' so every line
                # is attributable and no message content can be mistaken for structure.
                head = "[%s] %s %22s: " % (m["t"], "->" if m["dir"] == "me" else "<-",
                                           disp.get(ids.key(m["sender"]) if m.get("sender") else "")
                                           or _oneline(m.get("sender_name") or m["dir"], _LABEL_MAX))
                cont = " " * (len(head) - 2) + "| "
                lines = _printable_line(body).replace("\r\n", "\n").replace("\r", "\n").split("\n")
                f.write(head + lines[0] + "\n")
                for extra in lines[1:]:
                    f.write(cont + extra + "\n")
                q = _oneline(m.get("quoted_text"), 160)   # marked when cut; full text in chats.json
                if q:
                    f.write(" " * (len(head) - 6) + "re: " + q + "\n")

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
            msgs = _dedupe_msgs(msgs)                         # same reasoning as the Chromium path
        for n in _ID_STORES:                                  # who-is-who source records (small stores)
            stores[n] = _ff_store(c, n)
        for n in meta: meta[n] = len(stores.get(n, ()))       # counts for the terminal summary
        c.close()
    return ls, root, msgs, meta, stores

def _dedupe_msgs(msgs):
    """Drop records that are byte-for-byte the same message twice.

    The Chromium reader yields superseded versions as well as live ones, newest first, and that is
    deliberate -- an edited or re-delivered message is evidence. 25 ids in this store appear twice,
    and I first described those copies as byte-identical, which is wrong: they differ in `ack`,
    `pendingReadReceipt` and `hasReaction`. That is the message moving through its lifecycle, not a
    second message, and none of it is carried into an export.
    
    So the key is every field this normalisation KEEPS -- id, timestamp, direction, type, sender and
    the ciphertext itself. Two copies that differ only in delivery state collapse to the newest; a
    version whose text actually differs has different ciphertext, so it survives under the same id
    where it can be seen. Before this, the duplicates put 37 extra rows in chats.json, repeated
    lines in the transcript, and 37 duplicate `key_id`s in an export whose schema treats that column
    as unique.
    """
    out, seen = [], set()
    for m in msgs:
        k = (m.get("id"), m.get("t"), m.get("from_me"), m.get("type"), m.get("sender"),
             m.get("iv"), m.get("data"))
        if k in seen: continue
        seen.add(k); out.append(m)
    return out

def load_chromium(profile):
    import chromium_reader as cr
    src = cr.load_source(profile); ls = src["localStorage"]; idb = src["idb"]
    root = None
    ck = idb.get("wawc_db_enc", {}).get("keys", [])
    if ck and isinstance(ck[0], dict) and hasattr(ck[0].get("key"), "key_data"):
        root = ck[0]["key"].key_data
    model = idb.get("model-storage", {})
    msgs = _dedupe_msgs(_norm_msg(o) for o in model.get("message", []) if isinstance(o, dict))
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

def _is_chromium(path):
    import chromium_reader as cr
    return cr.is_chromium_profile(path)

def load(profile=None, origin=None):
    """-> (engine, localStorage, root_key, messages, store_counts, Identities)"""
    if origin: engine, parts = "firefox", load_firefox(origin)
    elif _is_chromium(profile): engine, parts = "chromium", load_chromium(profile)
    else:
        cand = os.path.join(profile, "storage/default/https+++web.whatsapp.com")
        if not os.path.isdir(cand):
            raise SystemExit("Could not locate WhatsApp Web storage in that profile (pass --origin for Firefox).")
        engine, parts = "firefox", load_firefox(cand)
    ls, root, msgs, meta, stores = parts
    ids = Identities(stores, ls)
    ids.learn_me(msgs)          # fill in any of my own address forms the profile did not name
    return engine, ls, root, msgs, meta, ids

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
    nobody = other = 0
    for m in msgs:
        if not m["data"]:                                  # no body stored: still a message (see bodyless_row)
            nobody += 1; chats[m["chat"]].append(bodyless_row(m, ts(m["t"]), ids, "none")); continue
        if m["scheme"] != 1:                               # a body this key does not open: never decrypt to garbage
            other += 1; chats[m["chat"]].append(bodyless_row(m, ts(m["t"]), ids, "other-scheme")); continue
        if len(m["data"]) % 16:                            # misaligned: see the note in wawf.py's cmd_decrypt
            fail += 1; chats[m["chat"]].append(bodyless_row(m, ts(m["t"]), ids, "failed")); continue
        try: pt = pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception:
            fail += 1; chats[m["chat"]].append(bodyless_row(m, ts(m["t"]), ids, "failed")); continue
        ok += 1
        chats[m["chat"]].append(msg_row(m, ts(m["t"]), pt, ids))
    if nobody or other:
        print(f"[+] {nobody} message(s) with no stored body and {other} with a body of another scheme "
              f"are written without text (body_status), not dropped")
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
