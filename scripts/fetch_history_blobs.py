#!/usr/bin/env python3
"""fetch_history_blobs.py — download + decrypt WhatsApp on-demand history-sync blobs.

Given the historySyncNotification params (directPath, mediaKey, fileEncSha256, fileSha256) captured
from a reconnect, fetch the .enc blob from the media CDN, decrypt (HKDF 'WhatsApp History Keys' +
AES-CBC), gunzip, and parse the HistorySync protobuf to extract messages. This is how we obtain chat
history the browser never cached.
"""
import sys, json, base64, hashlib, gzip, zlib, urllib.request
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def download(directPath):
    url = "https://mmg.whatsapp.net" + directPath
    req = urllib.request.Request(url, headers={"User-Agent":"WhatsApp/2.3000.0","Origin":"https://web.whatsapp.com"})
    return urllib.request.urlopen(req, timeout=30).read()

def decrypt_blob(blob, mediaKey_b64):
    mk = base64.b64decode(mediaKey_b64)
    exp = HKDF(algorithm=hashes.SHA256(), length=112, salt=None, info=b"WhatsApp History Keys").derive(mk)
    iv, cipherKey = exp[0:16], exp[16:48]
    ct = blob[:-10]                                     # last 10 bytes = MAC
    pt = Cipher(algorithms.AES(cipherKey), modes.CBC(iv)).decryptor().update(ct)
    if pt:                                              # PKCS7 (guard empty)
        p = pt[-1]; pt = pt[:-p] if 1 <= p <= 16 else pt
    return pt

# ---- minimal protobuf reader ----
def rv(b,i):
    n=s=0
    while True:
        x=b[i]; i+=1; n|=(x&0x7f)<<s; s+=7
        if not x&0x80: break
    return n,i
def fields(b):
    """yield (field_no, wire_type, value) where value is bytes(len-delim)/int."""
    i=0;n=len(b)
    while i<n:
        tag,i=rv(b,i); f=tag>>3; wt=tag&7
        if wt==0: v,i=rv(b,i); yield f,0,v
        elif wt==2:
            ln,i=rv(b,i); yield f,2,b[i:i+ln]; i+=ln
        elif wt==5: yield f,5,b[i:i+4]; i+=4
        elif wt==1: yield f,1,b[i:i+8]; i+=8
        else: break

def parse_history(pt, ondisk):
    """HistorySync{2:Conversation}. Conversation{1:id,2:HistorySyncMsg}. HistorySyncMsg{1:WebMessageInfo}.
       WebMessageInfo{1:MessageKey,2:Message,3:ts}. MessageKey{1:remoteJid,2:fromMe,3:id}."""
    convs=0; msgs=0; new=0; samples=[]; newids=set()
    for f,wt,v in fields(pt):
        if f==2 and wt==2:  # conversation
            convs+=1; cid=None
            for cf,cwt,cv in fields(v):
                if cf==1 and cwt==2: cid=cv.decode('utf-8','replace')
                elif cf==2 and cwt==2:  # HistorySyncMsg
                    for hf,hwt,hv in fields(cv):
                        if hf==1 and hwt==2:  # WebMessageInfo
                            msgs+=1; mid=None; txt=None; frm=None; ts=None
                            for wf,wwt,wv in fields(hv):
                                if wf==1 and wwt==2:  # key
                                    for kf,kwt,kv in fields(wv):
                                        if kf==3 and kwt==2: mid=kv.decode('utf-8','replace')
                                        if kf==2 and kwt==0: frm=kv
                                elif wf==2 and wwt==2:  # message
                                    for mf,mwt,mv in fields(wv):
                                        if mf==1 and mwt==2:  # conversation (plain text)
                                            try: txt=mv.decode('utf-8')
                                            except: pass
                                        elif mf==6 and mwt==2:   # extendedTextMessage (proto field 6)
                                            for ef,ewt,ev in fields(mv):
                                                if ef==1 and ewt==2:
                                                    try: txt=ev.decode('utf-8')
                                                    except: pass
                                elif wf==3 and wwt==0: ts=wv
                            isnew = mid not in ondisk if mid else False
                            if isnew: new+=1; newids.add(mid)
                            if isnew and txt and len(samples)<8: samples.append((cid, ts, bool(frm), txt[:80]))
    return convs, msgs, new, samples, newids

def main():
    notifs=json.load(open(sys.argv[1]))
    ondisk=set(json.load(open(sys.argv[2]))["ondisk_ids"]) if len(sys.argv)>2 else set()
    tot_c=tot_m=tot_new=0; allsamp=[]; alln=set()
    for i,n in enumerate(notifs):
        try:
            blob=download(n["directPath"])
        except Exception as e:
            print(f"[{i}] download failed: {e}"); continue
        # ENFORCE integrity (forensic): when a hash is present it must match, else skip the blob.
        enc_have, sha_have = n.get("fileEncSha256"), n.get("fileSha256")
        if enc_have and base64.b64encode(hashlib.sha256(blob).digest()).decode()!=enc_have:
            print(f"[{i}] ENC-HASH MISMATCH -> skipped (corrupt download / tampering)"); continue
        pt=decrypt_blob(blob, n["mediaKey"])
        if sha_have and base64.b64encode(hashlib.sha256(pt).digest()).decode()!=sha_have:
            print(f"[{i}] PLAINTEXT-HASH MISMATCH -> skipped (wrong mediaKey / bad decrypt)"); continue
        try: raw=zlib.decompress(pt)
        except Exception:
            try: raw=gzip.decompress(pt)
            except Exception: raw=pt
        c,m,new,samp,nids=parse_history(raw, ondisk); alln.update(nids)
        tot_c+=c; tot_m+=m; tot_new+=new; allsamp+=samp
        vstat = "verified" if (enc_have and sha_have) else "UNVERIFIED(no hash in notif)"
        print(f"[{i}] blob {len(blob)}B {vstat} -> convs={c} msgs={m} NEW(not-on-disk)={new}")
    print(f"\nTOTAL: conversations={tot_c} messages={tot_m} NEW(not-on-disk)={tot_new}  UNIQUE-new-ids={len(alln)}")
    print("SAMPLE recovered messages NOT on disk (chat, ts, fromMe, text):")
    for s in allsamp[:8]: print("  ", s[0][:22], s[1], s[2], "|", s[3])

if __name__=="__main__": main()
