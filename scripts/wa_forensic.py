#!/usr/bin/env python3
# WhatsApp Web (Firefox) forensic decryptor — does it all.
#   LIVE  : sudo python3 wa_forensic.py --live            (scan live Firefox RAM)
#   IMAGE : python3 wa_forensic.py --memimage dump.raw    (scan RAM/hiberfil/swap/core image)
#   KNOWN : python3 wa_forensic.py --enc-static <base64>  (you already have the salt)
# It asks for authorization, finds companion_enc_static by validating candidates against real
# ciphertext, then decrypts every message body and exports them.
import sqlite3, sys, os, re, base64, glob, argparse, struct, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from snappy_pure import uncompress
from idbutil import store_id
import sclone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:    import cramjam; SN = lambda b: bytes(cramjam.snappy.decompress_raw(b))
except Exception: SN = None

def find_profile():
    homes = [os.path.expanduser('~')]
    su = os.environ.get('SUDO_USER')                 # --live needs sudo; HOME is then /root, so also try the invoking user
    if su:
        try:
            import pwd; homes.append(pwd.getpwnam(su).pw_dir)
        except Exception: pass
    for h in homes:
        for p in glob.glob(h + '/.mozilla/firefox/*.default*') \
               + glob.glob(h + '/snap/firefox/common/.mozilla/firefox/*.default*'):
            if glob.glob(p + '/storage/default/https+++web.whatsapp.com'):
                return p
    return None

class Vault:
    def __init__(self, origin):
        self.origin = origin
        ro = lambda p: sqlite3.connect(f'file:{p}?mode=ro&immutable=1', uri=True)   # safe on live/locked profile
        self.ls   = ro(f'{origin}/ls/data.sqlite')
        def _idb(name):
            m = glob.glob(f'{origin}/idb/*{name}*.sqlite')
            if not m: raise SystemExit(f"IndexedDB *{name}* not found in {origin}")
            return ro(m[0])
        self.idb = _idb
        vr = self.ls.execute("SELECT value FROM data WHERE key='WAWebEncKeySalt'").fetchone()
        if not vr: raise SystemExit("WAWebEncKeySalt not found in localStorage (is this a WhatsApp Web profile?)")
        v = vr[0]
        self.info = base64.b64decode((v.decode() if isinstance(v,bytes) else v).strip('"'))     # HKDF info
        k = self.idb('wcanwec__bd')                                                              # wawc_db_enc
        kid = store_id(k, "keys")                                                                # by NAME; store ids are per-profile
        krow = k.execute("SELECT data FROM object_data WHERE object_store_id=?", (kid,)).fetchone() if kid else None
        if not krow: raise SystemExit("root key store 'keys' not found/empty in wawc_db_enc")
        d = uncompress(krow[0])
        i = d.find(b'\x0a\x80\xff\xff')
        if i < 0: raise SystemExit("root-key marker not found in wawc_db_enc record")
        j = d.find(b'\x00\x00\x00\x80\x00\x00\x00', i)
        if j < 0: raise SystemExit("root-key inner marker not found in wawc_db_enc record")
        j += 7
        self.ikm = d[j:d.find(b'\x00'*8, j)]                                                     # root key IKM
        self.msg = self.idb('meogdaerlo')                                                        # model-storage
        self.mid = store_id(self.msg, "message")                                                 # by NAME
        if not self.mid: raise SystemExit("message store not found in model-storage")
        self.refs = []                                                                           # scheme-1 reference ciphertexts
        for (row,) in self.msg.execute("SELECT data FROM object_data WHERE object_store_id=?", (self.mid,)):
            try: o = sclone.loads(uncompress(row))
            except Exception: continue
            op = o.get('msgRowOpaqueData')
            if isinstance(op, dict) and op.get('_scheme') == 1 and 'iv' in op and isinstance(op.get('_data'), dict):
                iv = op['iv']['__bytes'] if isinstance(op['iv'], dict) else op['iv']
                data = op['_data']['__bytes']
                if data and len(data) % 16 == 0:       # non-empty, block-aligned: matches the scheme-1 key derive() produces
                    self.refs.append((iv, data))
            if len(self.refs) >= 5: break
        if not self.refs:
            raise SystemExit("no scheme-1 reference ciphertexts in this profile; cannot validate a key against it")

    def derive(self, salt):
        return HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=self.info).derive(self.ikm)

    def valid_key(self, key):
        # refs are pre-filtered in __init__ to scheme-1, non-empty, block-aligned ciphertexts — the exact
        # population derive() targets — so the correct key decrypts EVERY one to valid PKCS7; a wrong key
        # fails the first ref fast. All-must-pass.
        if not self.refs: return False   # no reference ciphertext => cannot validate; never blindly pass
        for iv, data in self.refs:
            try: pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(data)
            except Exception: return False
            p = pt[-1]
            if not (1 <= p <= 16 and pt[-p:] == bytes([p]) * p): return False
        return True

B64 = re.compile(rb'[A-Za-z0-9+/]{16,96}={0,2}')
def scan_stream(read_chunks, vault):
    seen = set(); tested = 0
    for chunk in read_chunks:
        for m in B64.finditer(chunk):
            tok = m.group(0)
            if tok in seen: continue
            seen.add(tok)
            try: raw = base64.b64decode(tok + b'=' * (-len(tok) % 4))
            except Exception: continue
            if not (8 <= len(raw) <= 64): continue
            tested += 1
            try:
                if vault.valid_key(vault.derive(raw)):
                    return tok.decode(), raw
            except Exception: pass
    sys.stderr.write(f"[scan] tested {tested} unique candidates, no match in this source\n")
    return None, None

def scan_keys(read_chunks, vault, step=8):
    """Fallback: brute the raw 16-byte AES key directly from memory (non-extractable
    CryptoKey material is resident even though JS can't export it)."""
    tested = 0
    for chunk in read_chunks:
        for off in range(0, max(0, len(chunk) - 16), step):
            k = chunk[off:off+16]
            tested += 1
            try:
                if vault.valid_key(k):
                    return None, ('RAWKEY', k)
            except Exception: pass
    sys.stderr.write(f"[deep] tested {tested} key windows, no match in this source\n")
    return None, None

def read_file_chunks(path, size=8<<20, overlap=128):
    with open(path, 'rb') as f:
        prev = b''
        while True:
            b = f.read(size)
            if not b: break
            yield prev + b
            prev = b[-overlap:]

def read_proc_chunks(pid, overlap=128):
    maps = open(f'/proc/{pid}/maps').read()
    mem = open(f'/proc/{pid}/mem', 'rb', 0)
    prev = b''
    for line in maps.splitlines():
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+) r[w-]', line)
        if not m: continue
        a, b = int(m.group(1),16), int(m.group(2),16)
        if b - a > 512<<20: prev = b''; continue
        try:
            mem.seek(a); data = mem.read(b - a)
            yield prev + data                 # carry overlap so a key straddling a region boundary isn't missed
            prev = data[-overlap:]
        except Exception: prev = b''; continue

def firefox_pids():
    out = []
    for d in glob.glob('/proc/[0-9]*'):
        try:
            if b'firefox' in open(d + '/comm','rb').read(): out.append(int(d.split('/')[-1]))
        except Exception: pass
    return out

# ---- inner-plaintext parser (best effort; refined after first real body) ----
def pkcs7(b):
    p = b[-1]; return b[:-p] if b and 1 <= p <= 16 and b[-p:] == bytes([p])*p else b
def proto_strings(buf, depth=0, out=None):
    if out is None: out = []
    i = 0; n = len(buf)
    while i < n:
        try:
            tag = buf[i]; i += 1; field = tag >> 3; wt = tag & 7
            if wt == 0:
                while buf[i] & 0x80: i += 1
                i += 1
            elif wt == 2:
                ln = 0; sh = 0
                while True:
                    b = buf[i]; i += 1; ln |= (b & 0x7f) << sh; sh += 7
                    if not b & 0x80: break
                seg = buf[i:i+ln]; i += ln
                try:
                    s = seg.decode('utf-8')
                    if s and sum(c.isprintable() for c in s) >= len(s)*0.85 and len(s) >= 2:
                        out.append(s)
                except Exception:
                    if depth < 4: proto_strings(seg, depth+1, out)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            else: break
        except Exception: break
    return out

def decrypt_all(vault, key, outdir='analysis/bodies'):
    os.makedirs(outdir, exist_ok=True)
    import json, collections
    chats = collections.defaultdict(list); ok = fail = 0
    for (row,) in vault.msg.execute("SELECT data FROM object_data WHERE object_store_id=?", (vault.mid,)):
        try: o = sclone.loads(uncompress(row))
        except Exception: continue
        op = o.get('msgRowOpaqueData')
        if not (isinstance(op, dict) and 'iv' in op and isinstance(op.get('_data'), dict)): continue
        iv = op['iv']['__bytes'] if isinstance(op['iv'], dict) else op['iv']
        try: pt = pkcs7(Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(op['_data']['__bytes']))
        except Exception: fail += 1; continue
        inner = pt
        if SN:
            try: inner = SN(pt)
            except Exception: pass
        texts = proto_strings(inner)
        ok += 1
        idv = o.get('id') or ''
        chat = idv.split('_')[1] if isinstance(idv,str) and idv.count('_')>=2 else '?'
        chats[chat].append({'t':o.get('t'),'from':o.get('from'),'type':o.get('type'),'text':texts})
    json.dump({k:v for k,v in chats.items()}, open(f'{outdir}/chats.json','w', encoding='utf-8'), ensure_ascii=False, indent=1, default=str)  # UTF-8: text has emoji (Windows default is cp1252)
    print(f"[decrypt] {ok} bodies decrypted, {fail} failed -> {outdir}/chats.json ({len(chats)} chats)")
    return ok

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile'); ap.add_argument('--origin')
    ap.add_argument('--live', action='store_true')
    ap.add_argument('--memimage'); ap.add_argument('--enc-static')
    ap.add_argument('--deep', action='store_true', help='brute raw 16B key from memory (fallback if salt string absent)')
    ap.add_argument('--yes', action='store_true', help='skip authorization prompt')
    a = ap.parse_args()

    if not a.yes:
        try:
            r = input("AUTHORIZATION: Do you have explicit permission to analyze this WhatsApp account/system? [yes/no] ").strip().lower()
        except EOFError:                       # non-interactive stdin (piped / no TTY): don't crash with a traceback
            print("Aborting: the authorization prompt needs an interactive terminal. Re-run with --yes if you "
                  "have explicit permission to analyze this account/system."); sys.exit(1)
        if r not in ('y','yes'):
            print("Aborting: authorization not confirmed."); sys.exit(1)

    base = a.origin or a.profile or find_profile()
    if not base:
        print("Could not locate a Firefox WhatsApp Web profile; pass --origin or --profile."); sys.exit(2)
    origin = a.origin or (base + '/storage/default/https+++web.whatsapp.com')
    if not os.path.isdir(origin): print("WhatsApp origin not found:", origin); sys.exit(2)
    print("[*] origin:", origin)
    v = Vault(origin)
    print(f"[*] loaded root IKM ({len(v.ikm)}B), HKDF info ({len(v.info)}B), {len(v.refs)} reference ciphertexts")

    salt = None
    if a.enc_static:
        raw = base64.b64decode(a.enc_static)
        if v.valid_key(v.derive(raw)): salt = raw; print("[+] provided companion_enc_static VALIDATED")
        else: print("[-] provided companion_enc_static did NOT validate"); sys.exit(3)
    elif a.memimage:
        if not os.path.isfile(a.memimage):
            print(f"[-] memory image not found: {a.memimage}"); sys.exit(4)
        # for swap/pagefile/decompressed-hiberfil/RAM dumps: base64-salt scan, auto-fallback to raw-key
        print("[*] scanning memory image (swap/pagefile/hiberfil/RAM dump):", a.memimage)
        tok, salt = (None, None)
        if not a.deep:
            tok, salt = scan_stream(read_file_chunks(a.memimage), v)
            if salt: print("[+] FOUND companion_enc_static in image:", tok)
        if not salt:
            sys.stderr.write("[*] base64 salt not found -> deep raw-key scan\n")
            tok, salt = scan_keys(read_file_chunks(a.memimage), v)
            if salt: print("[+] FOUND raw message key in image:", salt)
    elif a.live:
        if not hasattr(os, 'geteuid') or not os.path.isdir('/proc'):   # live scan reads /proc/<pid>/mem (Linux-only)
            print("[-] --live memory scanning is Linux-only (it reads /proc/<pid>/mem). On Windows or macOS, "
                  "capture a RAM/swap/hibernation image and pass it with --memimage <file>, or use "
                  "`wawf reconnect` to obtain the key over the network."); sys.exit(4)
        if os.geteuid() != 0: print("[-] --live needs root (sudo) to read process memory"); sys.exit(4)
        _pt = '/proc/sys/kernel/yama/ptrace_scope'; _pt_old = None
        try: _pt_old = open(_pt).read().strip()      # save so we can restore — don't permanently weaken ptrace hardening
        except Exception: pass
        try: open(_pt, 'w').write('0')
        except Exception: pass
        try:
            for pid in firefox_pids():
                sys.stderr.write(f"[live] scanning pid {pid}\n")
                try:
                    tok, salt = (None, None)
                    if not a.deep: tok, salt = scan_stream(read_proc_chunks(pid), v)
                    if not salt:  tok, salt = scan_keys(read_proc_chunks(pid), v)
                except Exception as e: sys.stderr.write(f"  pid {pid}: {e}\n"); continue
                if salt: print(f"[+] FOUND key material in pid {pid}:", tok or salt); break
        finally:
            if _pt_old is not None:                  # restore original ptrace_scope
                try: open(_pt, 'w').write(_pt_old)
                except Exception: pass
    else:
        print("Pick a source: --live | --memimage <file> | --enc-static <b64>"); sys.exit(5)

    if not salt:
        print("[-] companion_enc_static not recovered from the given source.")
        print("    Dead disk alone cannot yield it; supply a RAM/hiberfil/swap image via --memimage,")
        print("    or capture it live. Metadata/media are already recoverable without it.")
        sys.exit(6)
    if isinstance(salt, tuple) and salt[0] == 'RAWKEY':
        key = salt[1]
    else:
        key = v.derive(salt)
    print("[+] AES-CBC-128 message key:", key.hex())
    decrypt_all(v, key)

if __name__ == '__main__':
    main()
