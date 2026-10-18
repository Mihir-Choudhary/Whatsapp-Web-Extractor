"""chat_scope.py — which chats a `--chat` names, without guessing.

An examination is often authorised for named conversations only. `--chat` takes a contact or group
name, a phone number, a lid or a jid, and this module turns each into the chats the profile holds for
it, using the profile's own identity table (wa_decrypt.Identities):

  * a jid (`...@s.whatsapp.net`, `...@c.us`, `...@lid`, `...@g.us`) or a bare number names ONE person
    or group. A phone number and a lid are the same person, so their 1:1 chat is found under either
    form (WhatsApp files newer chats under the lid);
  * a name is matched exactly (case and surrounding spaces ignored) against what the profile calls the
    chat: the address-book name, the contact's own pushname, a group's subject, the chat store's name.

Nothing is guessed. A name or number that fits more than one chat, or none, stops the run with the
candidates listed, and the examiner chooses by number, lid or jid. A chat must hold at least one
message in the browser: history is requested as "older than this message", and the export has
nothing else to scope.
"""
from __future__ import annotations
import collections, re

from wa_decrypt import canon_jid

_NUMBER = re.compile(r"\+?[\d\s\-().]+\Z")
# an address, not a name that happens to hold an '@' ("Mom @home" is a name)
_JID = re.compile(r"[^\s@]+@(?:s\.whatsapp\.net|c\.us|lid|g\.us|broadcast|newsletter)\Z", re.I)


class ScopeError(Exception):
    """A --chat value that names no chat, or more than one. The message lists the candidates."""


def _digits(s):
    return re.sub(r"\D", "", s or "")


def _norm(s):
    return " ".join((s or "").split()).casefold()


def _chats(ids, chat_counts):
    """{chat key: {"forms", "messages", "label", "names", "numbers"}}: one entry per person or group
    that has a chat, however many address forms its messages were filed under."""
    out = {}
    for cj, n in chat_counts.items():
        cj = canon_jid(cj)
        if not cj: continue
        k = ids.key(cj)
        c = out.setdefault(k, {"forms": set(), "messages": 0, "label": ids.label(cj), "names": set(),
                               "numbers": set()})
        c["forms"].add(cj); c["messages"] += n
    for k, c in out.items():
        e = ids.entry(k) or {}
        for form in [k] + sorted(c["forms"]) + [e.get("lid"), e.get("pn")]:
            if not form: continue
            c["forms"].add(canon_jid(form))
            if form.endswith(("@c.us", "@lid")): c["numbers"].add(form.split("@")[0])
        for nm in (e.get("name"), e.get("pushname"), ids._subject.get(k), c["label"],
                   *(ids._chat.get(f) for f in c["forms"])):
            if nm: c["names"].add(_norm(nm))
    return out


def _describe(k, c):
    nums = ", ".join(sorted(f for f in c["forms"] if f != c["label"]))
    return "  %-28s %s  (%d message%s)" % (c["label"], nums, c["messages"], "" if c["messages"] == 1 else "s")


def _fail(spec, why, cands, chats):
    lines = ["--chat %r: %s" % (spec, why)]
    if cands:
        lines.append("candidates (give one of its numbers, lid or jid instead):")
        lines += [_describe(k, chats[k]) for k in sorted(cands, key=lambda k: (-chats[k]["messages"], k))[:15]]
        if len(cands) > 15: lines.append("  ... and %d more" % (len(cands) - 15))
    raise ScopeError("\n".join(lines))


def resolve(specs, ids, chat_counts):
    """--chat values -> {chat key: {"label", "forms", "messages"}}. Raises ScopeError, naming the
    candidates, for a value that fits no chat or more than one. `chat_counts` maps each chat jid the
    store holds messages for to how many."""
    chats = _chats(ids, chat_counts)
    picked = {}
    for spec in specs:
        s = (spec or "").strip()
        if not s:
            raise ScopeError("--chat needs a name, a phone number, a lid or a jid")
        if _JID.match(s):
            want = ids.key(canon_jid(s))
            hits = [k for k in chats if k == want or canon_jid(s) in chats[k]["forms"]]
            if not hits:
                _fail(spec, "no chat with this address in the profile (a chat needs at least one message "
                            "in the browser)", [], chats)
        elif _NUMBER.match(s) and _digits(s):
            d = _digits(s)
            hits = [k for k, c in chats.items() if d in c["numbers"]]
            if not hits:                                 # a name made of digits ("2024") is still a name
                hits = [k for k, c in chats.items() if _norm(s) in c["names"]]
            if not hits:
                near = [k for k, c in chats.items() if len(d) >= 6 and any(n.endswith(d) for n in c["numbers"])]
                _fail(spec, "no chat with exactly this number (a phone number goes with its country code; "
                            "a chat needs at least one message in the browser)", near, chats)
        else:
            want = _norm(s)
            hits = [k for k, c in chats.items() if want in c["names"]]
            if not hits:
                near = [k for k, c in chats.items() if any(want in n for n in c["names"])]
                _fail(spec, "no chat is called exactly this" + (" -- did you mean one of these?" if near else
                            " (a chat needs at least one message in the browser)"), near, chats)
        if len(hits) > 1:
            _fail(spec, "fits %d chats; it must name one" % len(hits), hits, chats)
        k = hits[0]
        picked[k] = {"label": chats[k]["label"], "forms": sorted(chats[k]["forms"]),
                     "messages": chats[k]["messages"]}
    return picked


def forms(picked):
    """Every address form of the chosen chats, canonical (`:device` dropped, phone servers as @c.us)."""
    return sorted({f for c in picked.values() for f in c["forms"]})


def in_scope(jid, scope):
    """Is this chat jid one of the chosen chats? `scope` is forms(); None/empty means no --chat."""
    return not scope or canon_jid(jid) in scope


def chat_counts(msgs):
    """{chat jid: messages} from wa_decrypt's normalised messages."""
    return collections.Counter(m.get("chat") for m in msgs if m.get("chat"))
