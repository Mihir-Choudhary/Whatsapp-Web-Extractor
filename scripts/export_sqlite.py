#!/usr/bin/env python3
"""export_sqlite.py — Export decrypted WhatsApp Web data to a SQLite database.

Produces <out>/{msgstore.db, wa.db, Media/} — decrypted chats, contacts, groups, media and
metadata in the standard Android WhatsApp schema. Requires companion_enc_static (from `reconnect`/`memory`).
Works on BOTH Firefox (--origin) and Chromium (--profile: Chrome/Edge/Brave/Opera).

  python3 scripts/export_sqlite.py --enc-static <b64> --origin <FF web.whatsapp.com dir> [--out DIR]
  python3 scripts/export_sqlite.py --enc-static <b64> --profile <Chromium profile dir>   [--out DIR]

(Firefox additionally decrypts on-disk cached media into Media/; on Chromium the media keys + metadata
are exported to message_media but the browser cache isn't decoded — recover media separately.)

(The Android schema is also ingestable by third-party suites such as akhil-dara/WAInsight.)
"""
import sqlite3, sys, os, base64, json, glob, hashlib, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id
import sclone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try: import cramjam; _sn = cramjam.snappy.decompress_raw
except Exception: _sn = None

def _find_origin():
    import glob as _g
    for p in _g.glob(os.path.expanduser('~/snap/firefox/common/.mozilla/firefox/*/storage/default/https+++web.whatsapp.com')) \
           + _g.glob(os.path.expanduser('~/.mozilla/firefox/*/storage/default/https+++web.whatsapp.com')):
        return p
    return None

_ap = argparse.ArgumentParser()
_ap.add_argument('--enc-static', required=True, help='companion_enc_static (base64), from reconnect/memory')
_ap.add_argument('--origin', default=None, help='Firefox web.whatsapp.com storage dir (auto-detected if omitted)')
_ap.add_argument('--profile', default=None, help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
_ap.add_argument('--out', default='wa_sqlite', help='output directory for the SQLite DB + Media')
_args = _ap.parse_args()
SALT = base64.b64decode(_args.enc_static)
OUT  = _args.out
# NOTE: output dirs are created only AFTER key validation passes (below), so a rejected
# run leaves nothing behind.

def as_bytes(x):                       # bytes across engines: Firefox {'__bytes':..}, CCL bytes, or a JS Array (tuple/list of ints)
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, (tuple, list)):
        try: return bytes(x)
        except (ValueError, TypeError): return None
    if isinstance(x, dict):
        for k in ('__bytes', '__bytes__'):
            if k in x: return bytes(x[k])
    return None

# ---- engine-aware loader: expose L(key), ROOT (raw root key) and store(name) for BOTH Firefox
#      (IndexedDB as SQLite + Snappy + Mozilla structured-clone) and Chromium (LevelDB + V8 via ccl).
#      Everything below this block is engine-agnostic (operates on the decoded WA object dicts).
_is_chromium = bool(_args.profile and os.path.isdir(os.path.join(_args.profile, 'IndexedDB')))
if _is_chromium:
    import chromium_reader as _cr
    _src = _cr.load_source(_args.profile)
    _LS = _src['localStorage']; _MODEL = _src['idb'].get('model-storage', {})
    def L(k): return _LS.get(k)
    _keys = _src['idb'].get('wawc_db_enc', {}).get('keys', [])   # CCL exposes the CryptoKey's raw bytes directly
    ROOT = _keys[0]['key'].key_data if (_keys and isinstance(_keys[0], dict)
                                        and hasattr(_keys[0].get('key'), 'key_data')) else None
    if not ROOT: print('ERROR: root key not recoverable from wawc_db_enc/keys (Chromium profile)'); sys.exit(2)
    if 'message' not in _MODEL: print("ERROR: 'message' store not found in Chromium model-storage"); sys.exit(2)
    def _clean(v):                     # CCL marks JS `undefined` with an _Undefined sentinel -> make it None
        if type(v).__name__ == '_Undefined': return None
        if isinstance(v, dict): return {k: _clean(x) for k, x in v.items()}
        if isinstance(v, list): return [_clean(x) for x in v]
        return v
    def store(name):
        for o in _MODEL.get(name, []):
            if isinstance(o, dict): yield _clean(o)
else:
    O = _args.origin or _find_origin()
    if not O or not os.path.isdir(O):
        print('ERROR: pass --origin <Firefox storage dir> or --profile <Chromium dir>; none found'); sys.exit(2)
    _ls = sqlite3.connect(f'file:{O}/ls/data.sqlite?mode=ro&immutable=1', uri=True)   # read-only: evidence integrity
    def L(k):
        r = _ls.execute("SELECT value FROM data WHERE key=?", (k,)).fetchone(); return r[0] if r else None
    _wc = glob.glob(f'{O}/idb/*wcanwec__bd*.sqlite')   # numeric prefix is per-profile; never hardcode it
    if not _wc: print('ERROR: wawc_db_enc IndexedDB (*wcanwec__bd*.sqlite) not found under', O); sys.exit(2)
    _conk = sqlite3.connect(f'file:{_wc[0]}?mode=ro&immutable=1', uri=True)
    _kid = store_id(_conk, "keys")                       # by NAME; store ids are per-profile
    _krow = _conk.execute("SELECT data FROM object_data WHERE object_store_id=?", (_kid,)).fetchone() if _kid else None
    if not _krow: print("ERROR: root key store 'keys' not found/empty in wawc_db_enc"); sys.exit(2)
    _d = uncompress(_krow[0])
    _i = _d.find(b'\x0a\x80\xff\xff')
    if _i < 0: print("ERROR: root-key marker not found in wawc_db_enc record"); sys.exit(2)
    _j = _d.find(b'\x00\x00\x00\x80\x00\x00\x00', _i)
    if _j < 0: print("ERROR: root-key inner marker not found in wawc_db_enc record"); sys.exit(2)
    _j += 7
    ROOT = _d[_j:_d.find(b'\x00'*8, _j)]
    _mm = glob.glob(f'{O}/idb/*meogdaerlo*.sqlite')    # message store; per-profile numeric prefix
    if not _mm: print('ERROR: message-store IndexedDB (*meogdaerlo*.sqlite) not found under', O); sys.exit(2)
    _conm = sqlite3.connect(f'file:{_mm[0]}?mode=ro&immutable=1', uri=True)
    if store_id(_conm, 'message') is None: print("ERROR: 'message' store not found in Firefox model-storage"); sys.exit(2)
    def store(name):                                   # resolve model-storage ids by NAME (per-profile); None -> nothing
        sid = store_id(_conm, name)
        if sid is None: return
        for (row,) in _conm.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try: yield sclone.loads(uncompress(row))
            except Exception: continue

_salt = L('WAWebEncKeySalt')
if _salt is None: print('ERROR: WAWebEncKeySalt not in localStorage — not a WhatsApp Web profile?'); sys.exit(2)
INFO = base64.b64decode(json.loads(_salt))
MSGKEY = HKDF(algorithm=hashes.SHA256(), length=16, salt=SALT, info=INFO).derive(ROOT)

def pk7(b):
    if not b or len(b) % 16: return b
    p = b[-1]; return b[:-p] if 1 <= p <= 16 and b[-p:] == bytes([p])*p else b
def rd_varint(b, i):
    n = s = 0
    while True:
        x = b[i]; i += 1; n |= (x & 0x7f) << s; s += 7
        if not x & 0x80: break
    return n, i
def leaves(buf, depth=0, out=None):
    if out is None: out = []
    i, n = 0, len(buf)
    while i < n:
        try:
            tag, i = rd_varint(buf, i); wt = tag & 7
            if wt == 0: _, i = rd_varint(buf, i)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            elif wt == 2:
                ln, i = rd_varint(buf, i); seg = buf[i:i+ln]; i += ln
                sub = []
                if len(seg) >= 2 and seg[0] in (0x08,0x0a,0x10,0x12,0x1a,0x22,0x2a):
                    try: leaves(seg, depth+1, sub)
                    except Exception: sub = []
                if sub: out += sub
                else:
                    try:
                        t = seg.decode('utf-8')
                        if t and t != 'null' and sum(c.isprintable() for c in t) >= len(t)*0.9 \
                           and any(c.isalpha() for c in t) and not re.fullmatch(r'[A-Za-z0-9+/]{40,}={0,2}', t):
                            out.append(t)
                    except Exception: pass
            else: break
        except Exception: break
    return out
def decrypt_body(op):
    if not isinstance(op, dict) or op.get('_scheme') != 1: return None   # MSGKEY is the scheme-1 key (scheme-0 -> garbage)
    iv = as_bytes(op.get('iv')); data = as_bytes(op.get('_data'))
    if not iv or not data: return None
    try: pt = pk7(Cipher(algorithms.AES(MSGKEY), modes.CBC(iv)).decryptor().update(data))
    except Exception: return None
    txt = leaves(pt)
    return ' '.join(dict.fromkeys(txt))[:8000] if txt else None

def ser(x):
    if isinstance(x, dict): return x.get('_serialized') or (f"{x.get('user')}@{x.get('server')}" if x.get('user') else None)
    return x
def norm_jid(x):
    x = ser(x)
    if not x: return None
    return x[:-5] + '@s.whatsapp.net' if x.endswith('@c.us') else x
def server_of(x): return x.split('@')[-1] if x and '@' in x else None

_jid_id = {}
def jid_id(raw):
    raw = norm_jid(raw)
    if not raw: return None
    if raw not in _jid_id: _jid_id[raw] = len(_jid_id) + 1
    return _jid_id[raw]
_wid = L('last-wid-md'); _lid = L('WALid')
if _wid is None or _lid is None:
    print("ERROR: last-wid-md / WALid missing in localStorage — not a logged-in WhatsApp Web profile?"); sys.exit(2)
OWNER_PHONE = json.loads(_wid).split(':')[0].split('@')[0] + '@s.whatsapp.net'
OWNER_USER  = OWNER_PHONE.split('@')[0]
OWNER_LID   = norm_jid(json.loads(_lid).split(':')[0] + '@lid')
OWNER_LID_USER = (OWNER_LID or '@').split('@')[0]
def is_owner(j):                                  # EXACT user-part match vs phone or LID (no substring false positives)
    u = (ser(j) or '@').split('@')[0]
    return bool(u) and (u == OWNER_USER or (OWNER_LID_USER and u == OWNER_LID_USER))
jid_id(OWNER_PHONE); jid_id(OWNER_LID)

MTYPE = {'chat':0,'image':1,'ptt':2,'audio':2,'video':3,'vcard':4,'location':5,'live_location':16,
         'gp2':7,'e2e_notification':7,'notification':7,'call_log':90,'document':9,'sticker':20,
         'poll_creation':66,'poll':66,'poll_vote':46,'gif':13,'album':99,'interactive':45,
         'revoked':0,'ciphertext':0,'status':116,'template':45,'rich_response':0,'unknown':0}
def ack_status(a): return {0:0,1:4,2:5,3:13,4:13}.get(a, 0)

# store() is defined per-engine in the loader above; reference model-storage object stores by NAME.
# Optional stores (reactions/message-info/poll-votes/pinned-messages) just yield nothing if absent.
MSG_SID, CONTACT_SID, GROUP_SID, CHAT_SID = 'message', 'contact', 'group-metadata', 'chat'
REACT_SID, MSGINFO_SID, POLLV_SID, PIN_SID = 'reactions', 'message-info', 'poll-votes', 'pinned-messages'

# Validate companion_enc_static against real ciphertext (strict PKCS7) BEFORE writing anything.
# A wrong/empty key would still yield correct metadata but garbage message TEXT and silently
# "succeed" — refuse that. Right key => ~100% valid padding; wrong key => ~0.4%.
def _strict_pk7(b): return bool(b) and len(b) % 16 == 0 and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]])*b[-1]
_refs, _good = [], 0
for _o in store(MSG_SID):
    if not isinstance(_o, dict): continue
    _op = _o.get('msgRowOpaqueData')
    if isinstance(_op, dict) and _op.get('_scheme') == 1:
        _iv = as_bytes(_op.get('iv')); _ct = as_bytes(_op.get('_data'))
        if _iv and _ct:
            _refs.append((_iv, _ct))
            if len(_refs) >= 40: break
for _iv, _ct in _refs:
    try:
        if _strict_pk7(Cipher(algorithms.AES(MSGKEY), modes.CBC(_iv)).decryptor().update(_ct)): _good += 1
    except Exception: pass
if _refs and _good < len(_refs) * 0.5:
    print(f"ERROR: companion_enc_static is INVALID for this profile/device — only {_good}/{len(_refs)} "
          f"reference message bodies validate. Refusing to write a garbage msgstore. (Wrong key, empty key, "
          f"or wrong browser's salt.)"); sys.exit(3)
print(f"[+] companion_enc_static VALIDATED ({_good}/{len(_refs)} reference bodies).")
os.makedirs(OUT, exist_ok=True); os.makedirs(f'{OUT}/Media/WhatsApp Web', exist_ok=True)

contacts = [o for o in store(CONTACT_SID) if isinstance(o, dict)]
groups   = {o['id']: o for o in store(GROUP_SID) if isinstance(o, dict) and o.get('id')}
chats    = {o['id']: o for o in store(CHAT_SID)  if isinstance(o, dict) and o.get('id')}

_chat_id = {}
def chat_rowid(jid):
    if jid not in _chat_id: _chat_id[jid] = len(_chat_id) + 1
    return _chat_id[jid]

# ---- parse messages ----
messages = []; call_objs = []            # capture call_log rows here to avoid a 2nd full message-store pass
for o in store(MSG_SID):
    if not isinstance(o, dict): continue
    if o.get('type') == 'call_log': call_objs.append(o)
    idv = o.get('id') or ''
    parts = idv.split('_')
    if len(parts) < 3: continue
    from_me = 1 if parts[0] == 'true' else 0
    chat_jid, key_id = parts[1], parts[2]
    sender_suffix = parts[3] if len(parts) > 3 else None
    is_group = chat_jid.endswith('@g.us')
    is_bcast = chat_jid.endswith('@broadcast')
    sender = OWNER_PHONE if from_me else (ser(o.get('author'))
             or (sender_suffix if sender_suffix and '@' in sender_suffix else None) or ser(o.get('from')))
    typ = o.get('type') or 'chat'
    t = o.get('t') or 0
    body = decrypt_body(o.get('msgRowOpaqueData')) if typ in (
        'chat','image','video','document','ptt','audio','interactive','template','rich_response','poll_creation') else None
    md = None
    if o.get('mediaKey') or o.get('directPath'):
        md = {'media_key': base64.b64decode(o['mediaKey']) if o.get('mediaKey') else None,
              'direct_path': o.get('directPath'), 'file_hash': o.get('filehash'), 'enc_file_hash': o.get('encFilehash'),
              'mime_type': o.get('mimetype'), 'file_length': o.get('size'), 'media_name': o.get('filename'),
              'caption': body if typ != 'chat' else None, 'width': o.get('width'), 'height': o.get('height'),
              'duration': o.get('duration'), 'type': typ,
              'media_key_ts': o.get('mediaKeyTimestamp'), 'message_url': o.get('deprecatedMms3Url')}
    th = o.get('thumbnail')
    ment = [ser(x) for x in (o.get('mentionedJidList') or []) if ser(x)]
    messages.append({
        'webid': idv, 'chat_jid': chat_jid, 'from_me': from_me, 'key_id': key_id,
        # received: sender = author/partner (groups+broadcast use author; 1:1 partner also fine)
        'sender_jid': None if (from_me or (not is_group and not is_bcast)) else sender,   # null sender for own + 1:1 received
        'timestamp': int(t)*1000 if t else 0, 'message_type': MTYPE.get(typ, 0), 'text_data': body,
        'status': ack_status(o.get('ack')), 'starred': 1 if o.get('star') or o.get('isStarred') else 0,
        'media': md, 'thumb': base64.b64decode(th) if isinstance(th, str) and th else None,
        'mentioned': ment, 'quoted_id': o.get('quotedStanzaID'), 'quoted_type': o.get('quotedType'),
    })
    jid_id(chat_jid); chat_rowid(chat_jid)
    if messages[-1]['sender_jid']: jid_id(messages[-1]['sender_jid'])
    for mj in ment: jid_id(mj)

for c in contacts:
    if c.get('id'): jid_id(c['id'])
    if c.get('phoneNumber'): jid_id(c['phoneNumber'])
for g in groups: jid_id(g)
for ch in chats: jid_id(ch); chat_rowid(ch)
print(f"parsed: {len(messages)} messages, {len(_jid_id)} jids, {len(_chat_id)} chats")

# ============ msgstore.db ============
mp = f'{OUT}/msgstore.db'
if os.path.exists(mp): os.remove(mp)
db = sqlite3.connect(mp)
db.executescript("""
CREATE TABLE jid(_id INTEGER PRIMARY KEY, user TEXT, server TEXT, agent INTEGER DEFAULT 0, device INTEGER DEFAULT 0, type INTEGER DEFAULT 0, raw_string TEXT);
CREATE TABLE jid_map(jid_row_id INTEGER, lid_row_id INTEGER);
CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT, created_timestamp INTEGER, sort_timestamp INTEGER, display_message_row_id INTEGER, archived INTEGER DEFAULT 0, account_jid_row_id INTEGER, participation_status INTEGER);
CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER, timestamp INTEGER, received_timestamp INTEGER, message_type INTEGER, text_data TEXT, status INTEGER, sort_id INTEGER, starred INTEGER DEFAULT 0, broadcast INTEGER DEFAULT 0);
CREATE TABLE message_media(_id INTEGER PRIMARY KEY, message_row_id INTEGER, chat_row_id INTEGER, file_path TEXT, file_size INTEGER, file_length INTEGER, mime_type TEXT, width INTEGER, height INTEGER, media_duration INTEGER, direct_path TEXT, file_hash TEXT, enc_file_hash TEXT, original_file_hash TEXT, media_key BLOB, media_key_timestamp INTEGER, message_url TEXT, media_caption TEXT, media_name TEXT);
CREATE TABLE message_thumbnail(message_row_id INTEGER, thumbnail BLOB);
CREATE TABLE message_album(message_row_id INTEGER, image_count INTEGER, video_count INTEGER, expected_image_count INTEGER, expected_video_count INTEGER);
CREATE TABLE message_association(child_message_row_id INTEGER, parent_message_row_id INTEGER, association_type INTEGER);
CREATE TABLE message_quoted(message_row_id INTEGER, key_id TEXT, text_data TEXT, message_type INTEGER, parent_message_chat_row_id INTEGER, chat_row_id INTEGER);
CREATE TABLE message_mentions(_id INTEGER PRIMARY KEY, message_row_id INTEGER, jid_row_id INTEGER);
CREATE TABLE message_add_on(_id INTEGER PRIMARY KEY, parent_message_row_id INTEGER, sender_jid_row_id INTEGER, from_me INTEGER, timestamp INTEGER, message_add_on_type INTEGER);
CREATE TABLE message_add_on_reaction(message_add_on_row_id INTEGER, reaction TEXT);
CREATE TABLE message_poll(message_row_id INTEGER, selectable_options_count INTEGER);
CREATE TABLE message_add_on_poll_vote(message_add_on_row_id INTEGER, sender_timestamp INTEGER);
CREATE TABLE receipt_user(message_row_id INTEGER, receipt_user_jid_row_id INTEGER, receipt_timestamp INTEGER, read_timestamp INTEGER, played_timestamp INTEGER);
CREATE TABLE message_link(_id INTEGER PRIMARY KEY, message_row_id INTEGER, link_index INTEGER);
CREATE TABLE message_add_on_pin_in_chat(message_add_on_row_id INTEGER, sender_timestamp INTEGER, expiry_duration_in_secs INTEGER, pin_in_chat_state INTEGER);
CREATE TABLE call_log(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, from_me INTEGER, timestamp INTEGER, video_call INTEGER, duration INTEGER, call_result INTEGER, bytes_transferred INTEGER, call_id TEXT, is_joinable_group_call INTEGER DEFAULT 0, group_jid_row_id INTEGER DEFAULT 0, call_type INTEGER DEFAULT 0, call_creator_device_jid_row_id INTEGER DEFAULT 0);
""")
_TYPE = {'s.whatsapp.net':0,'lid':18,'g.us':1,'newsletter':21,'bot':26,'broadcast':0}
for raw, rid in _jid_id.items():
    user = raw.split('@')[0]; srv = server_of(raw); dev = 0
    if ':' in user:
        u, dd = user.split(':', 1); user = u; dev = int(dd) if dd.isdigit() else 0
    ty = _TYPE.get(srv, 0)
    if dev > 0: ty = 17 if srv == 's.whatsapp.net' else (19 if srv == 'lid' else ty)
    db.execute("INSERT INTO jid(_id,user,server,agent,device,type,raw_string) VALUES(?,?,?,?,?,?,?)", (rid, user, srv, 0, dev, ty, raw))
for c in contacts:
    lid = c.get('id'); phone = c.get('phoneNumber')
    if lid and phone and str(lid).endswith('@lid'):
        db.execute("INSERT INTO jid_map(jid_row_id,lid_row_id) VALUES(?,?)", (jid_id(phone), jid_id(lid)))
owner_jid_row = jid_id(OWNER_PHONE)
for jraw, cid in _chat_id.items():
    ch = chats.get(jraw); g = groups.get(jraw)
    subject = (g.get('subject') if g else None) or (ch.get('name') if ch else None)
    created = g.get('creation') if g else None
    sort_ts = int((ch.get('t') if ch else 0) or 0)*1000
    archived = 1 if (ch and ch.get('archive')) else 0
    db.execute("INSERT INTO chat(_id,jid_row_id,subject,created_timestamp,sort_timestamp,archived,account_jid_row_id) VALUES(?,?,?,?,?,?,?)",
               (cid, jid_id(jraw), subject, int(created)*1000 if created else None, sort_ts, archived, owner_jid_row))

WEBID2ID = {}
mid = 0; ment_id = 0
for m in messages:
    mid += 1; WEBID2ID[m['webid']] = mid
    srow = jid_id(m['sender_jid']) if m['sender_jid'] else 0
    db.execute("""INSERT INTO message(_id,chat_row_id,from_me,key_id,sender_jid_row_id,timestamp,received_timestamp,message_type,text_data,status,sort_id,starred,broadcast)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (mid, chat_rowid(m['chat_jid']), m['from_me'], m['key_id'], srow, m['timestamp'], m['timestamp'],
                m['message_type'], m['text_data'], m['status'], mid, m['starred'], 1 if m['chat_jid'].endswith('@broadcast') else 0))
    md = m['media']
    if md:
        db.execute("""INSERT INTO message_media(message_row_id,chat_row_id,file_path,file_size,file_length,mime_type,width,height,media_duration,direct_path,file_hash,enc_file_hash,original_file_hash,media_key,media_key_timestamp,message_url,media_caption,media_name)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (mid, chat_rowid(m['chat_jid']), None, md['file_length'], md['file_length'], md['mime_type'], md['width'], md['height'],
                    int(md['duration'])*1000 if md.get('duration') else None, md['direct_path'], md['file_hash'],
                    md['enc_file_hash'], None, md['media_key'], md.get('media_key_ts'), md.get('message_url'), md['caption'], md['media_name']))
    if m['thumb']: db.execute("INSERT INTO message_thumbnail(message_row_id,thumbnail) VALUES(?,?)", (mid, m['thumb']))
    if m['quoted_id']:
        db.execute("INSERT INTO message_quoted(message_row_id,key_id,text_data,message_type,chat_row_id) VALUES(?,?,?,?,?)",
                   (mid, m['quoted_id'], None, m['quoted_type'], chat_rowid(m['chat_jid'])))
    for mj in m['mentioned']:
        r = jid_id(mj)
        if r: ment_id += 1; db.execute("INSERT INTO message_mentions(_id,message_row_id,jid_row_id) VALUES(?,?,?)", (ment_id, mid, r))
    if m['text_data']:
        for li, _u in enumerate(re.findall(r'https?://\S+', m['text_data'])):
            db.execute("INSERT INTO message_link(message_row_id,link_index) VALUES(?,?)", (mid, li))

# ---- reactions -> message_add_on (type 56) + message_add_on_reaction ----
addon_id = 0; rx = 0
for o in store(REACT_SID):
    if not isinstance(o, dict): continue
    pid = WEBID2ID.get(o.get('parentMsgKey'))
    if not pid: continue
    snd = ser(o.get('senderUserJid')); fm = 1 if is_owner(snd) else 0
    addon_id += 1
    db.execute("INSERT INTO message_add_on(_id,parent_message_row_id,sender_jid_row_id,from_me,timestamp,message_add_on_type) VALUES(?,?,?,?,?,56)",
               (addon_id, pid, jid_id(snd) or 0, fm, int(o.get('timestamp') or 0)))
    db.execute("INSERT INTO message_add_on_reaction(message_add_on_row_id,reaction) VALUES(?,?)", (addon_id, o.get('reactionText')))
    rx += 1

# ---- receipts -> receipt_user (outgoing per-recipient) ----
rc = 0
for o in store(MSGINFO_SID):
    if not isinstance(o, dict): continue
    pid = WEBID2ID.get(o.get('msgKey'))
    if not pid: continue
    rj = jid_id(ser(o.get('receiverUserJid')))
    if not rj: continue
    db.execute("INSERT INTO receipt_user(message_row_id,receipt_user_jid_row_id,receipt_timestamp,read_timestamp,played_timestamp) VALUES(?,?,?,?,?)",
               (pid, rj, o.get('delivery'), o.get('read'), o.get('played')))
    rc += 1

# ---- polls -> message_poll + votes (message_add_on type 2, poll_vote) ----
pl = 0
for m in messages:
    if m['message_type'] == 66:
        db.execute("INSERT INTO message_poll(message_row_id,selectable_options_count) VALUES(?,?)", (WEBID2ID[m['webid']], 1)); pl += 1
pv = 0
for o in store(POLLV_SID):
    if not isinstance(o, dict): continue
    pid = WEBID2ID.get(o.get('parentMsgKey'))
    if not pid: continue
    snd = ser(o.get('sender')); fm = 1 if is_owner(snd) else 0
    addon_id += 1
    db.execute("INSERT INTO message_add_on(_id,parent_message_row_id,sender_jid_row_id,from_me,timestamp,message_add_on_type) VALUES(?,?,?,?,?,2)",
               (addon_id, pid, jid_id(snd) or 0, fm, int(o.get('senderTimestampMs') or 0)))
    db.execute("INSERT INTO message_add_on_poll_vote(message_add_on_row_id,sender_timestamp) VALUES(?,?)", (addon_id, int(o.get('senderTimestampMs') or 0)))
    pv += 1

# ---- calls -> call_log (from call_log messages) ----
cl = 0
for o in call_objs:                      # already collected during the single parse pass above
    cl += 1
    frm = ser(o.get('from')); to = ser(o.get('to')); fm = 1 if is_owner(frm) else 0
    other = to if fm else frm
    db.execute("""INSERT INTO call_log(_id,jid_row_id,from_me,timestamp,video_call,duration,call_result,bytes_transferred,call_id,is_joinable_group_call)
                  VALUES(?,?,?,?,?,?,?,?,?,0)""",
               (cl, jid_id(other) or 0, fm, int(o.get('t') or 0)*1000, 1 if o.get('isVideoCall') else 0,
                o.get('duration') or 0, 5 if str(o.get('callOutcome') or '').lower() in ('accepted','answered') else 2, 0, o.get('id')))

# ---- pins -> message_add_on(type 79) + message_add_on_pin_in_chat ----
pn = 0
for o in store(PIN_SID):
    if not isinstance(o, dict): continue
    pid = WEBID2ID.get(o.get('parentMsgKey')) or WEBID2ID.get(o.get('msgKey'))
    if not pid: continue
    snd = ser(o.get('sender')); addon_id += 1
    db.execute("INSERT INTO message_add_on(_id,parent_message_row_id,sender_jid_row_id,from_me,timestamp,message_add_on_type) VALUES(?,?,?,?,?,79)",
               (addon_id, pid, jid_id(snd) or 0, 1 if is_owner(snd) else 0, int(o.get('senderTimestampMs') or 0)))
    db.execute("INSERT INTO message_add_on_pin_in_chat(message_add_on_row_id,sender_timestamp,expiry_duration_in_secs,pin_in_chat_state) VALUES(?,?,?,1)",
               (addon_id, int(o.get('senderTimestampMs') or 0), o.get('pinExpiryDuration'))); pn += 1

db.commit(); db.close()

# ============ wa.db ============
wp = f'{OUT}/wa.db'
if os.path.exists(wp): os.remove(wp)
wa = sqlite3.connect(wp)
wa.execute("CREATE TABLE wa_contacts(_id INTEGER PRIMARY KEY AUTOINCREMENT, jid TEXT UNIQUE, display_name TEXT, wa_name TEXT, given_name TEXT, family_name TEXT, status TEXT, number TEXT, is_whatsapp_user INTEGER DEFAULT 1)")
for c in contacts:
    for jraw in {norm_jid(c.get('id')), norm_jid(c.get('phoneNumber'))} - {None}:
        wa.execute("INSERT OR IGNORE INTO wa_contacts(jid,display_name,wa_name,given_name,status,number) VALUES(?,?,?,?,?,?)",
                   (jraw, c.get('name'), c.get('pushname'), c.get('shortName'), (c.get('textStatusString') or None), (c.get('phoneNumber') or '').split('@')[0]))
wa.commit(); wa.close()

# ============ decrypt cached media into Media/ + set file_path ============
INFOMAP = {'image':b'WhatsApp Image Keys','video':b'WhatsApp Video Keys','audio':b'WhatsApp Audio Keys','ptt':b'WhatsApp Audio Keys','document':b'WhatsApp Document Keys','sticker':b'WhatsApp Image Keys','gif':b'WhatsApp Video Keys'}
EXT = {'image/jpeg':'jpg','image/webp':'webp','image/png':'png','video/mp4':'mp4','application/pdf':'pdf','audio/ogg; codecs=opus':'ogg'}
def unframe(data):
    if data[:4] != b'\xff\x06\x00\x00' or not _sn: return data
    out = bytearray(); p = 10
    while p+4 <= len(data):
        ty = data[p]; ln = int.from_bytes(data[p+1:p+4],'little'); p += 4; ch = data[p:p+ln]; p += ln
        if ty == 0x00:
            try: out += bytes(_sn(ch[4:]))
            except Exception: break
        elif ty == 0x01: out += ch[4:]
        else: break
    return bytes(out)
# index cached .enc blobs by sha256 (Firefox on-disk origin cache; Chromium caches media elsewhere)
C = None if _is_chromium else f'{O}/cache/morgue'
byench = {}
for m in messages:
    if m['media'] and m['media'].get('enc_file_hash'): byench[m['media']['enc_file_hash']] = m
decrypted = 0
db = sqlite3.connect(mp)
for f in (glob.glob(C + '/*/*.final') if C else []):
    try: body = unframe(open(f,'rb').read())
    except Exception: continue
    h = base64.b64encode(hashlib.sha256(body).digest()).decode()
    m = byench.get(h)
    if not m: continue
    md = m['media']
    try:
        exp = HKDF(algorithm=hashes.SHA256(), length=112, salt=b'\x00'*32, info=INFOMAP.get(md['type'], b'WhatsApp Image Keys')).derive(md['media_key'])
        pt = Cipher(algorithms.AES(exp[16:48]), modes.CBC(exp[:16])).decryptor().update(body[:-10]); p = pt[-1]
        pt = pt[:-p] if 1 <= p <= 16 else pt
        if base64.b64encode(hashlib.sha256(pt).digest()).decode() != md['file_hash']: continue
        rid = WEBID2ID[m['webid']]; ext = EXT.get(md['mime_type'], 'bin')
        rel = f"Media/WhatsApp Web/{rid}.{ext}"
        open(f'{OUT}/{rel}', 'wb').write(pt)
        db.execute("UPDATE message_media SET file_path=? WHERE message_row_id=?", (rel, rid)); decrypted += 1
    except Exception: continue
db.commit(); db.close()
print(f"WROTE SQLite DB: {mp} + {wp}  (+ {OUT}/Media)")
print(f"  jids={len(_jid_id)} chats={len(_chat_id)} messages={mid} mentions={ment_id} reactions={rx} receipts={rc} polls={pl}/votes={pv} media_decrypted_to_disk={decrypted}")
# ---- human-readable summary ----
import datetime as _dt
_secs=[m['timestamp']/1000 for m in messages if m.get('timestamp') and 1e9 < m['timestamp']/1000 < 2e9]
def _d(t): return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime('%Y-%m-%d')
_cset=set(m['chat_jid'] for m in messages if m.get('chat_jid'))
_grp=sum(1 for c in _cset if c.endswith('@g.us')); _sent=sum(1 for m in messages if m.get('from_me'))
_media=sum(1 for m in messages if m.get('media'))
print('──────────── summary ────────────')
print(f'  messages    : {len(messages):,} total   ({_sent:,} sent / {len(messages)-_sent:,} received)')
print(f'  date range  : {(_d(min(_secs)) if _secs else "?")}  →  {(_d(max(_secs)) if _secs else "?")}')
print(f'  chats       : {len(_cset)}   ({len(_cset)-_grp} direct, {_grp} groups)')
print(f'  contacts    : {len(contacts):,}   ·   groups: {len(groups):,}   ·   chats(saved): {len(chats):,}')
print(f'  media msgs  : {_media:,}   ·   reactions: {rx:,}   ·   calls: {len(call_objs):,}')
print('─────────────────────────────────')
if _is_chromium:
    print("  [i] Chromium: on-disk cached-media decryption is skipped (Firefox-only), but media keys + "
          "metadata are in message_media — recover media with `mediarecover.py`/re-download, or export from Firefox.")
elif _sn is None:
    print("  [!] cramjam not installed — framed cached-media (.final) blobs were NOT decompressed; media_decrypted_to_disk may undercount. pip install cramjam")
print(f"  Standard Android WhatsApp schema — open with any SQLite viewer, or ingest with a suite like WAInsight"
      f" (run_ingest.py --db-path {OUT} --extra-db wa.db={OUT}/wa.db --media-path {OUT}/Media).")
