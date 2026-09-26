#!/usr/bin/env python3
"""export_baileys_creds.py — recover WhatsApp device creds from a Firefox OR Chromium profile
for the reconnect client (tools/reconnect/reconnect.js). Decrypts the on-disk Noise key and
extracts the account identity, so we can log back in and capture a fresh companion_enc_static.

  python3 export_baileys_creds.py --profile ~/.config/google-chrome/Default        # Chromium
  python3 export_baileys_creds.py --origin  .../storage/default/https+++web.whatsapp.com  # Firefox
Writes tools/reconnect/creds_in.json.
"""
from __future__ import annotations
import argparse, os, sys, json, base64, glob, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id
import sclone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def as_bytes(x):
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, (list, tuple)): return bytes(x)
    if isinstance(x, dict):
        for k in ("__bytes", "__bytes__"):
            if k in x: return bytes(x[k])
    return None

# ---- engine-agnostic loader: returns (localStorage dict, root_ikm bytes, signal_meta [ {key,value} ]) ----
def load_firefox(origin):
    ls = {}
    c = sqlite3.connect(f"file:{origin}/ls/data.sqlite?mode=ro&immutable=1", uri=True)
    for k, v, comp in c.execute("SELECT key,value,compression_type FROM data"):
        if comp:
            try: v = uncompress(v if isinstance(v, (bytes, bytearray)) else v.encode("latin-1"))
            except Exception: pass
        ls[k] = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else v
    c.close()
    wc = glob.glob(origin + "/idb/*wcanwec__bd*.sqlite")
    if not wc: raise SystemExit("wawc_db_enc IndexedDB (*wcanwec__bd*) not found in " + origin)
    kc = sqlite3.connect(f"file:{wc[0]}?mode=ro&immutable=1", uri=True)
    kid = store_id(kc, "keys")                                    # by NAME; store ids are per-profile
    krow = kc.execute("SELECT data FROM object_data WHERE object_store_id=?", (kid,)).fetchone() if kid else None
    if not krow: raise SystemExit("root key store 'keys' not found/empty in wawc_db_enc")
    d = uncompress(krow[0])
    i = d.find(b"\x0a\x80\xff\xff")
    if i < 0: raise SystemExit("root-key marker not found in wawc_db_enc record")
    j = d.find(b"\x00\x00\x00\x80\x00\x00\x00", i)
    if j < 0: raise SystemExit("root-key inner marker not found in wawc_db_enc record")
    j += 7
    root = d[j:d.find(b"\x00"*8, j)]
    meta = []
    sg = glob.glob(origin + "/idb/*seigganraolt-s*.sqlite")
    sig = sqlite3.connect(f"file:{sg[0]}?mode=ro&immutable=1", uri=True) if sg else None
    sid = store_id(sig, "signal-meta-store") if sig else None
    if sig and sid:
        for (dd,) in sig.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try: meta.append(sclone.loads(uncompress(dd)))
            except Exception: pass
    return ls, root, meta

def load_chromium(profile):
    import chromium_reader as cr
    src = cr.load_source(profile); ls = src["localStorage"]; idb = src["idb"]
    root = idb["wawc_db_enc"]["keys"][0]["key"].key_data
    meta = [o for o in idb.get("signal-storage", {}).get("signal-meta-store", []) if isinstance(o, dict)]
    return ls, root, meta

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile"); ap.add_argument("--origin")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools/reconnect/creds_in.json"))
    a = ap.parse_args()
    if a.origin: engine, (ls, root, meta) = "firefox", load_firefox(a.origin)
    elif a.profile and os.path.isdir(os.path.join(a.profile, "IndexedDB")): engine, (ls, root, meta) = "chromium", load_chromium(a.profile)
    elif a.profile: engine, (ls, root, meta) = "firefox", load_firefox(os.path.join(a.profile, "storage/default/https+++web.whatsapp.com"))
    else: raise SystemExit("pass --profile or --origin")
    print(f"[*] engine={engine}")

    salt = base64.b64decode(json.loads(ls["WAWebEncKeySalt"]))
    KEY = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"\x00").derive(root)
    ni = json.loads(ls["WANoiseInfo"]); ivs = [base64.b64decode(x) for x in json.loads(ls["WANoiseInfoIv"])]
    def dec(b64, iv):
        pt = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor().update(base64.b64decode(b64)); p = pt[-1]
        return pt[:-p] if 1 <= p <= 16 and pt[-p:] == bytes([p])*p else pt
    priv = pub = None
    for pi in range(len(ivs)):                       # WANoiseInfoIv may hold fewer than 4 IVs
        for qi in range(len(ivs)):
            a1 = dec(ni["privKey"], ivs[pi]); b1 = dec(ni["pubKey"], ivs[qi])
            if len(a1) == 32 == len(b1):
                try:
                    if X25519PrivateKey.from_private_bytes(a1).public_key().public_bytes_raw() == b1: priv, pub = a1, b1
                except Exception: pass
    assert priv, "could not recover/verify Noise keypair"

    cert = None                                   # device certificate chain (from WANoiseInfo.certificateChainBuffer)
    if ni.get("certificateChainBuffer"):
        for iv in ivs:
            try:
                t = dec(ni["certificateChainBuffer"], iv)
                if t[:1] == b'{': cert = json.loads(t); break
            except Exception: pass

    adv = None; regid = None
    for o in meta:
        if o.get("key") == "adv_signed_identity":
            v = o["value"]
            adv = {k: base64.b64encode(as_bytes(v.get(k))).decode() for k in ("details","accountSignatureKey","accountSignature","deviceSignature") if as_bytes(v.get(k))}
        if o.get("key") == "signal_reg_id": regid = o.get("value")
    wid = json.loads(ls["last-wid-md"]); lid = json.loads(ls["WALid"])
    _ud = wid.split("@")[0].split(":"); user, dev = _ud[0], (_ud[1] if len(_ud) > 1 else "0")
    out = {"noise_priv": base64.b64encode(priv).decode(), "noise_pub": base64.b64encode(pub).decode(),
           "registrationId": int(regid) if regid is not None else None, "user": user, "device": int(dev),
           "me_id": f"{user}:{dev}@s.whatsapp.net", "lid": lid, "account": adv, "cert_chain": cert}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(out, open(a.out, "w", encoding="utf-8"), indent=1)
    print(f"[+] Noise keypair VERIFIED (X25519). reg_id={regid} device=:{dev}. wrote {a.out}")
    print(f"    account creds present: {list(adv.keys()) if adv else 'MISSING adv_signed_identity'}")

if __name__ == "__main__":
    main()
