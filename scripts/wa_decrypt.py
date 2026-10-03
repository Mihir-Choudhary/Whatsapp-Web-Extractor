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
    for sq in glob.glob(origin + "/idb/*meogdaerlo*.sqlite"):
        c = sqlite3.connect(f"file:{sq}?mode=ro&immutable=1", uri=True)
        sid = store_id(c, "message")
        if sid:
            skipped = 0
            for (d,) in c.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
                try: msgs.append(_norm_msg(sclone.loads(uncompress(d))))
                except Exception as e: skipped += 1; log.debug("firefox msg record skipped: %s", e)
            if skipped: log.debug("firefox: %d message record(s) failed to deserialize (of %d)", skipped, skipped + len(msgs))
        for n in meta:                                        # counts for the terminal summary (cheap: COUNT by store id)
            nsid = store_id(c, n)
            if nsid: meta[n] = c.execute("SELECT COUNT(*) FROM object_data WHERE object_store_id=?", (nsid,)).fetchone()[0]
        c.close()
    return ls, root, msgs, meta

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
    return ls, root, msgs, meta

def load(profile=None, origin=None):
    if origin: return ("firefox", *load_firefox(origin))
    # auto-detect
    if os.path.isdir(os.path.join(profile, "IndexedDB")):
        return ("chromium", *load_chromium(profile))
    for cand in (os.path.join(profile, "storage/default/https+++web.whatsapp.com"),):
        if os.path.isdir(cand): return ("firefox", *load_firefox(cand))
    raise SystemExit("Could not locate WhatsApp Web storage in that profile (pass --origin for Firefox).")

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile"); ap.add_argument("--origin")
    ap.add_argument("--enc-static", default=None)
    ap.add_argument("--out", default="wa_decrypted")
    a = ap.parse_args()
    if not a.profile and not a.origin:
        ap.error("pass --profile <browser profile dir> or --origin <Firefox web.whatsapp.com dir>")
    engine, ls, root, msgs, meta = load(a.profile, a.origin)
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
        try: pt = pk7(Cipher(algorithms.AES(key), modes.CBC(m["iv"])).decryptor().update(m["data"]))
        except Exception: fail += 1; continue
        txt = " ".join(dict.fromkeys(leaves(pt)))[:2000]
        ok += 1
        chats[m["chat"]].append({"t": ts(m["t"]), "dir": "me" if m["from_me"] else "them",
                                 "type": m["type"], "sender": m["sender"], "text": txt})
    print(f"[+] decrypted {ok} bodies ({fail} failed)  ->  {a.out}/")
    if ok and fail > ok:
        print("[!] most bodies failed to decrypt — companion_enc_static likely wrong for THIS profile/device.")
    for c in chats: chats[c].sort(key=lambda x: x["t"])
    json.dump(chats, open(f"{a.out}/chats.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    with open(f"{a.out}/transcripts.txt", "w", encoding="utf-8") as f:  # emoji/non-Latin text -> pin UTF-8 (Windows default is cp1252)
        for c, ml in sorted(chats.items(), key=lambda kv: -len(kv[1])):
            tm = [m for m in ml if m["text"]]
            if not tm: continue
            f.write(f"\n===== {c} ({len(ml)} msgs, {len(tm)} text) =====\n")
            for m in ml:
                if m["text"]: f.write(f"[{m['t']}] {m['dir']:>4}: {m['text']}\n")
    print(f"    transcripts.txt + chats.json written")

if __name__ == "__main__":
    main()
