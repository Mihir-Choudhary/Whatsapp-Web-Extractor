#!/usr/bin/env python3
"""Disk-only (no companion key) recovery of cached WhatsApp Web media: decrypt the browser's
cached media blobs with the plaintext mediaKey stored on disk and verify each against its filehash.

  python3 scripts/mediarecover.py [<origin dir>] [<out dir>]
"""
import sys, os, base64, hashlib, glob, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress as unc_row
from idbutil import store_id, connect_ro
import sclone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try: import cramjam; _raw = cramjam.snappy.decompress_raw
except Exception: _raw = None

O   = sys.argv[1] if len(sys.argv) > 1 else 'evidence/origins/https+++web.whatsapp.com'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'analysis/media'

def unframe(data):
    if data[:4] != b'\xff\x06\x00\x00' or not _raw: return data   # framed-snappy needs cramjam
    out=bytearray(); p=10
    while p+4<=len(data):
        t=data[p]; ln=int.from_bytes(data[p+1:p+4],'little'); p+=4
        ch=data[p:p+ln]; p+=ln
        if t==0x00:
            try: out+=bytes(_raw(ch[4:]))
            except Exception: return bytes(out)   # last chunk may be cache-metadata garbage
        elif t==0x01: out+=ch[4:]
    return bytes(out)

_mm = glob.glob(glob.escape(O) + '/idb/*meogdaerlo*.sqlite')      # per-profile numeric prefix; never hardcode it
if not _mm: sys.exit(f"message-store IndexedDB (*meogdaerlo*) not found under {O}")
conm = connect_ro(_mm[0])
_msid = store_id(conm, 'message')                    # by NAME (per-profile), not a hardcoded id
if _msid is None: sys.exit("message store not found in model-storage")
byench={}
for (d,) in conm.execute("SELECT data FROM object_data WHERE object_store_id=?", (_msid,)):
    try: o=sclone.loads(unc_row(d))
    except Exception: continue
    if isinstance(o,dict) and o.get('encFilehash') and o.get('mediaKey'):
        byench[o['encFilehash']]=o

INFO={'image':b'WhatsApp Image Keys','video':b'WhatsApp Video Keys','audio':b'WhatsApp Audio Keys',
      'ptt':b'WhatsApp Audio Keys','document':b'WhatsApp Document Keys','sticker':b'WhatsApp Image Keys'}
EXT={'video/mp4':'mp4','image/jpeg':'jpg','image/webp':'webp','image/png':'png','application/pdf':'pdf',
     'audio/ogg; codecs=opus':'ogg','audio/mpeg':'mp3','application/zip':'zip'}
def dec_media(blob,mk,mt):
    exp=HKDF(algorithm=hashes.SHA256(),length=112,salt=b'\x00'*32,info=INFO.get(mt,b'WhatsApp Image Keys')).derive(base64.b64decode(mk))
    pt=Cipher(algorithms.AES(exp[16:48]),modes.CBC(exp[:16])).decryptor().update(blob[:-10])
    p=pt[-1]
    if 1<=p<=16 and pt[-p:]==bytes([p])*p: pt=pt[:-p]
    return pt

C = os.path.join(O, 'cache/morgue')                  # media cache lives under the origin dir
os.makedirs(OUT, exist_ok=True)
ok=0; scanned=0; bytype=collections.Counter()
for f in glob.glob(glob.escape(C)+"/*/*.final"):
    scanned+=1
    try: body=unframe(open(f,'rb').read())
    except Exception: continue
    o=byench.get(base64.b64encode(hashlib.sha256(body).digest()).decode())
    if not o: continue
    try:
        pt=dec_media(body,o['mediaKey'],o.get('type'))
        if base64.b64encode(hashlib.sha256(pt).digest()).decode()==o.get('filehash'):
            ext=EXT.get(o.get('mimetype'),'bin'); bytype[ext]+=1
            open(f'{OUT}/{o.get("rowId")}.{ext}','wb').write(pt); ok+=1
    except Exception: pass
print(f"scanned {scanned} cache files; media msgs indexed {len(byench)}; DECRYPTED+VERIFIED {ok}")
print("by type:", dict(bytype))
if _raw is None:
    print("[!] cramjam not installed — framed cache blobs could not be decompressed (some media skipped). pip install cramjam")
