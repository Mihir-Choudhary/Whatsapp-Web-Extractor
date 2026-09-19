#!/usr/bin/env python3
"""Disk-only (no key needed) export of WhatsApp Web metadata to CSVs: contacts, chats, groups,
profile-pics, and full message-metadata. Works on any Firefox web.whatsapp.com storage dir.

  python3 scripts/extract_all.py [<origin dir>] [<out dir>]
"""
import sys, os, sqlite3, csv, glob, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id
import sclone

O   = sys.argv[1] if len(sys.argv) > 1 else 'evidence/origins/https+++web.whatsapp.com'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'analysis'
_mm = glob.glob(O + '/idb/*meogdaerlo*.sqlite')          # per-profile numeric prefix; never hardcode it
if not _mm: sys.exit(f"message-store IndexedDB (*meogdaerlo*) not found under {O}")
con = sqlite3.connect(f'file:{_mm[0]}?mode=ro&immutable=1', uri=True)
def sid(name):                                            # resolve object_store ids by NAME (per-profile)
    i = store_id(con, name)
    if i is None: sys.exit(f"object store '{name}' not found in model-storage")
    return i
def rows(name):
    for (d,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid(name),)):
        try: yield sclone.loads(uncompress(d))
        except Exception: continue
def ts(v):
    try:
        v = float(v)
        if v > 1e12: v /= 1000.0
        if 1e9 < v < 2e9: return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception: pass
    return ''
os.makedirs(OUT, exist_ok=True)

# CONTACTS
with open(f'{OUT}/contacts.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['id','phoneNumber','pushname','name','shortName','textStatus','isAddressBook','businessName'])
    n=0
    for o in rows('contact'):
        if not isinstance(o,dict):continue
        w.writerow([o.get('id',''),o.get('phoneNumber',''),o.get('pushname',''),o.get('name',''),o.get('shortName',''),
                    (o.get('textStatusString') or '')[:80],o.get('isAddressBookContact',''),o.get('verifiedName','')]);n+=1
    print('contacts.csv:',n)
# CHATS
with open(f'{OUT}/chats.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['id','name','lastActivity','archived','locked','muteExpiration','unreadCount'])
    n=0
    for o in rows('chat'):
        if not isinstance(o,dict):continue
        w.writerow([o.get('id',''),o.get('name',''),ts(o.get('t')),o.get('archive',''),o.get('isLocked',''),o.get('muteExpiration',''),o.get('unreadCount','')]);n+=1
    print('chats.csv:',n)
# GROUPS
with open(f'{OUT}/groups.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['id','subject','created','size','announce','restrict','description'])
    n=0
    for o in rows('group-metadata'):
        if not isinstance(o,dict):continue
        desc=o.get('desc') or ''
        w.writerow([o.get('id',''),o.get('subject',''),ts(o.get('creation')),o.get('size',''),o.get('announce',''),o.get('restrict',''),(desc if isinstance(desc,str) else '')[:120]]);n+=1
    print('groups.csv:',n)
# PROFILE PICS
with open(f'{OUT}/profile_pics.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['id','timestamp','eurl','fullDirectPath'])
    n=0
    for o in rows('profile-pic-thumb'):
        if not isinstance(o,dict):continue
        w.writerow([o.get('id',''),ts(o.get('timestamp')),o.get('eurl',''),o.get('fullDirectPath','')]);n+=1
    print('profile_pics.csv:',n)
# MESSAGE METADATA (full)
with open(f'{OUT}/messages_metadata.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['t','from','to','type','mimetype','size','filename','hasThumbnail','starred','ack','chatKey'])
    n=0
    for o in rows('message'):
        if not isinstance(o,dict):continue
        to=o.get('to'); to=to.get('_serialized') if isinstance(to,dict) else to
        idv=o.get('id') or ''
        chat=''
        if isinstance(idv,str) and idv.count('_')>=2:
            chat=idv.split('_')[1]
        w.writerow([ts(o.get('t')),o.get('from',''),to,o.get('type',''),o.get('mimetype',''),o.get('size',''),
                    o.get('filename','') or o.get('caption','') and '',bool(o.get('thumbnail')),o.get('isStarred',''),o.get('ack',''),chat]);n+=1
    print('messages_metadata.csv:',n)
