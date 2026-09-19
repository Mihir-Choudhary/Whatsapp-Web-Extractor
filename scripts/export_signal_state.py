#!/usr/bin/env python3
"""export_signal_state.py — recover the full Signal protocol state from a Firefox WhatsApp Web
profile so a Baileys reconnect can DECRYPT (not just authenticate): device identity keypair,
registrationId, the current signed prekey, and all one-time prekeys.

The device identity keypair is stored in signal-meta-store under 'signal_static_privkey' /
'signal_static_pubkey' as a WebCrypto CryptoKey wrapper: {encKey:<AES-CTR key,16B>, value:<ct,32B>};
AES-CTR(key=encKey, IV=0) decrypts it. Prekeys/signed-prekeys are plaintext.

  python3 export_signal_state.py --origin <web.whatsapp.com dir> [--out signal_state.json]
"""
import argparse, os, sys, json, base64, glob, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id, as_bytes as ab   # shared byte-coercion helper
import sclone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
def b64(b): return base64.b64encode(b).decode()

def parse_static_cryptokey(d):
    """d = raw decompressed signal-meta-store record for signal_static_*; returns 32B plaintext key."""
    m = d.find(b'\x0a\x80\xff\xff')                     # SCTAG CryptoKey
    if m < 0: raise ValueError("no CryptoKey marker")
    li = d.find(b'\x10\x00\x00\x00', m)                 # AES key length = 16
    enckey = d[li+4:li+20]
    vi = d.find(b'\x1f\x00\xff\xff', li)                # SCTAG typed array (the ciphertext)
    ct = d[vi+12:vi+12+32]                              # 4B tag + 8B length, then 32B ct
    pt = Cipher(algorithms.AES(enckey), modes.CTR(b'\x00'*16)).decryptor().update(ct)
    return pt


def load_chromium_signal(profile):
    import chromium_reader as cr
    sig = cr.load_source(profile)["idb"].get("signal-storage", {})
    if not sig: raise SystemExit("signal-storage not found in Chromium profile")
    def get(store,key):
        for r in sig.get(store,[]):
            if isinstance(r,dict) and r.get('key')==key: return r.get('value')
        return None
    def dec_static(v):
        if v is None: return None
        enc=ab(v['encKey']); ct=ab(v['value'])
        return Cipher(algorithms.AES(enc), modes.CTR(b'\x00'*16)).decryptor().update(ct)
    id_priv=dec_static(get('signal-meta-store','signal_static_privkey'))
    if not id_priv: raise SystemExit("signal_static_privkey not found in Chromium signal-storage")
    id_pub =X25519PrivateKey.from_private_bytes(id_priv).public_key().public_bytes_raw()   # derive (authoritative)
    _stored=dec_static(get('signal-meta-store','signal_static_pubkey'))
    if _stored is not None and _stored!=id_pub: raise SystemExit("Chromium identity keypair mismatch (stored pubkey != derived)")
    reg=last=None
    for r in sig.get('signal-meta-store',[]):
        if not isinstance(r,dict): continue
        if r.get('key')=='signal_reg_id': reg=int(r['value'])
        if r.get('key')=='signal_last_spk_id': last=r['value']
    spks={}
    for r in sig.get('signed-prekey-store',[]):
        if not isinstance(r,dict) or 'keyId' not in r: continue
        kp=r.get('keyPair') or {}
        spks[r['keyId']]={"keyId":r['keyId'],"private":b64(ab(kp.get('privKey'))),"public":b64(ab(kp.get('pubKey'))),
                          "signature":b64(ab(r.get('signature'))) if r.get('signature') is not None else None}
    cur=spks.get(last) or (spks[max(spks)] if spks else None)
    if not cur: raise SystemExit("no signed prekey in Chromium signal-storage")
    prekeys={}
    for r in sig.get('prekey-store',[]):
        if not isinstance(r,dict) or 'keyId' not in r: continue
        kp=r.get('keyPair') or {}; pv,pu=ab(kp.get('privKey')),ab(kp.get('pubKey'))
        if pv and pu: prekeys[str(r['keyId'])]={"private":b64(pv),"public":b64(pu)}
    return {"registrationId":reg,"signedIdentityKey":{"private":b64(id_priv),"public":b64(id_pub)},
            "signedPreKey":cur,"preKeys":prekeys}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--origin"); ap.add_argument("--profile", help="Chromium profile dir")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools/reconnect/signal_state.json"))
    a = ap.parse_args()
    if a.profile:
        out = load_chromium_signal(a.profile)
        ip=base64.b64decode(out["signedIdentityKey"]["private"])
        if X25519PrivateKey.from_private_bytes(ip).public_key().public_bytes_raw()!=base64.b64decode(out["signedIdentityKey"]["public"]):
            raise SystemExit("identity keypair failed X25519 self-check")
        os.makedirs(os.path.dirname(a.out), exist_ok=True); json.dump(out, open(a.out,"w"))
        print(f"[+] (chromium) identity VERIFIED. regId={out['registrationId']} signedPreKey=id{out['signedPreKey']['keyId']} preKeys={len(out['preKeys'])} -> {a.out}")
        return
    o = a.origin
    if not o: raise SystemExit("pass --origin (Firefox) or --profile (Chromium)")
    sigp = glob.glob(o + "/idb/*seigganraolt-s*.sqlite")
    if not sigp: raise SystemExit("signal-storage IndexedDB not found in " + o)
    c = sqlite3.connect(f"file:{sigp[0]}?mode=ro&immutable=1", uri=True)
    def _sid(name):                                    # store ids are per-profile; look up by NAME, clean error
        i = store_id(c, name)
        if i is None: raise SystemExit(f"signal-storage store '{name}' not found in {o}")
        return i

    # meta: reg id, current signed-prekey id, identity keypair (CryptoKey records)
    reg_id = last_spk = None; id_priv = id_pub = None
    for (rr,) in c.execute(f"SELECT data FROM object_data WHERE object_store_id={_sid('signal-meta-store')}"):
        d = uncompress(rr)
        try: ob = sclone.loads(d)
        except Exception:
            if b'signal_static_privkey' in d: id_priv = parse_static_cryptokey(d)
            elif b'signal_static_pubkey' in d: id_pub = parse_static_cryptokey(d)
            continue
        if isinstance(ob, dict):
            if ob.get('key') == 'signal_reg_id': reg_id = ob.get('value')
            if ob.get('key') == 'signal_last_spk_id': last_spk = ob.get('value')
    if not id_priv: raise SystemExit("could not recover signal identity private (signal_static_privkey)")
    derived = X25519PrivateKey.from_private_bytes(id_priv).public_key().public_bytes_raw()
    if id_pub is not None and id_pub != derived:      # soft cross-check against the stored pubkey when present
        raise SystemExit("identity keypair mismatch (stored pubkey != derived)")
    id_pub = derived                                  # derived public is authoritative

    # signed prekeys
    spks = {}
    for (rr,) in c.execute(f"SELECT data FROM object_data WHERE object_store_id={_sid('signed-prekey-store')}"):
        ob = sclone.loads(uncompress(rr))
        if not isinstance(ob, dict) or 'keyId' not in ob: continue
        kp = ob.get('keyPair') or {}
        spks[ob['keyId']] = {"keyId": ob['keyId'],
            "private": b64(ab(kp.get('privKey'))), "public": b64(ab(kp.get('pubKey'))),
            "signature": b64(ab(ob.get('signature'))) if ob.get('signature') is not None else None}
    cur = spks.get(last_spk) or (spks[max(spks)] if spks else None)
    if not cur: raise SystemExit("no signed prekey found")

    # one-time prekeys
    prekeys = {}
    for (rr,) in c.execute(f"SELECT data FROM object_data WHERE object_store_id={_sid('prekey-store')}"):
        ob = sclone.loads(uncompress(rr))
        if not isinstance(ob, dict) or 'keyId' not in ob: continue
        kp = ob.get('keyPair') or {}
        pv, pu = ab(kp.get('privKey')), ab(kp.get('pubKey'))
        if pv and pu: prekeys[str(ob['keyId'])] = {"private": b64(pv), "public": b64(pu)}

    out = {"registrationId": int(reg_id) if reg_id is not None else None,
           "signedIdentityKey": {"private": b64(id_priv), "public": b64(id_pub)},
           "signedPreKey": cur, "preKeys": prekeys}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(out, open(a.out, "w"))
    print(f"[+] identity VERIFIED (X25519). regId={reg_id} signedPreKey=id{cur['keyId']} preKeys={len(prekeys)} -> {a.out}")

if __name__ == "__main__":
    main()
