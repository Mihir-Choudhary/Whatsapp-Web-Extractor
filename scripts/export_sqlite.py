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
import sys as _sys
def _force_utf8_stdio():
    """Redirected/piped stdout defaults to the locale encoding, so a box-drawing character
    in a summary raises UnicodeEncodeError and takes the rest of the output with it."""
    for _s in (_sys.stdout, _sys.stderr):
        try: _s.reconfigure(encoding='utf-8', errors='replace')
        except Exception: pass
_force_utf8_stdio()
import sqlite3, sys, os, base64, json, glob, hashlib, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snappy_pure import uncompress
from idbutil import store_id, connect_ro, sqlite_uri
# ONE text builder for every export, so a message cannot read differently in two exports of the same
# evidence. (It used to be copied here, and when the filter was found to be dropping 767 messages the
# fix had to be made twice -- that is the failure mode this import exists to prevent.)
from wa_decrypt import texts as _message_texts, body_details as _body_details
from wa_decrypt import hist_type as _hist_type, stanza_of as _stanza_of, canon_jid as _canon_jid
from wa_decrypt import receipt_only as _receipt_only
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
_ap.add_argument('--metadata-only', action='store_true', help='no key: write everything except message text')
_ap.add_argument('--enc-static', help='companion_enc_static (base64). Prefer the WAWF_ENC_STATIC\n                     environment variable: a key on the command line is readable from the\n                     process list, which is the whole reason wawf passes it by environment.')
_ap.add_argument('--origin', default=None, help='Firefox web.whatsapp.com storage dir (auto-detected if omitted)')
_ap.add_argument('--profile', default=None, help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
_ap.add_argument('--out', default='wa_sqlite', help='output directory for the SQLite DB + Media')
_ap.add_argument('--history', default=None, metavar='FILE',
                 help='history_recovered.json from a `wawf --history` run: its messages are appended to the ones the store held, deduped on the stanza id, and marked source=phone')
_args = _ap.parse_args()
HISTORY_FILE = _args.history
# The key may arrive in the environment instead of argv -- wawf passes it that way on purpose, since a
# child's command line is readable from the process list and this is the one secret the browser never
# stored. argv still works for standalone use.
if not _args.enc_static:
    _args.enc_static = os.environ.get('WAWF_ENC_STATIC') or None
# Metadata only: no key, so no message text -- but every other field (chats, senders, timestamps,
# types, media keys, reactions, polls, calls, contacts, groups) is written. Asked for explicitly.
METADATA_ONLY = bool(_args.metadata_only or os.environ.get('WAWF_METADATA_ONLY'))
if not _args.enc_static and not METADATA_ONLY:
    raise SystemExit('ERROR: no companion_enc_static. Pass --enc-static <b64> or set WAWF_ENC_STATIC '
                     '(or --metadata-only to export everything except message text).')
if METADATA_ONLY: _args.enc_static = None
import audit                                   # appends to the SAME case DB as the parent (WAWF_AUDIT_DB)
A = audit.from_env("sqlite")
A.event("export_sqlite start", category="stage",
        detail={"profile": _args.profile, "origin": _args.origin, "out": _args.out})
SALT = base64.b64decode(_args.enc_static) if _args.enc_static else None
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

def as_text(x):
    """Coerce a value bound for a TEXT column to str. V8 stores Latin-1 ('one-byte') strings compactly and
    the Chromium reader hands those back as raw bytes — e.g. a pushname like b'S\\xe4m\\xea\\xear'. Inserting
    them unconverted makes SQLite put a BLOB in a TEXT column, which breaks consumers that expect text
    (they end up iterating bytes and getting ints). Try UTF-8, then Latin-1, which is lossless for
    one-byte strings; lossy replacement is a last resort so real names aren't mangled into U+FFFD."""
    if x is None or isinstance(x, str): return x
    if isinstance(x, (bytes, bytearray)):
        b = bytes(x)
        for enc in ('utf-8', 'latin-1'):
            try: return b.decode(enc)
            except UnicodeDecodeError: pass
        return b.decode('utf-8', 'replace')
    return str(x)

# ---- engine-aware loader: expose L(key), ROOT (raw root key) and store(name) for BOTH Firefox
#      (IndexedDB as SQLite + Snappy + Mozilla structured-clone) and Chromium (LevelDB + V8 via ccl).
#      Everything below this block is engine-agnostic (operates on the decoded WA object dicts).
import chromium_reader as _crd
_is_chromium = bool(_args.profile and _crd.is_chromium_profile(_args.profile))
if _is_chromium:
    import chromium_reader as _cr
    _src = _cr.load_source(_args.profile)
    _LS = _src['localStorage']; _MODEL = _src['idb'].get('model-storage', {})
    def L(k): return _LS.get(k)
    _keys = _src['idb'].get('wawc_db_enc', {}).get('keys', [])   # CCL exposes the CryptoKey's raw bytes directly
    ROOT = _keys[0]['key'].key_data if (_keys and isinstance(_keys[0], dict)
                                        and hasattr(_keys[0].get('key'), 'key_data')) else None
    if not ROOT and not METADATA_ONLY:
        print('ERROR: root key not recoverable from wawc_db_enc/keys (Chromium profile)'); sys.exit(2)
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
    _ls = connect_ro(f'{O}/ls/data.sqlite')   # read-only: evidence integrity
    def L(k):
        r = _ls.execute("SELECT value FROM data WHERE key=?", (k,)).fetchone(); return r[0] if r else None
    _wc = glob.glob(f'{glob.escape(O)}/idb/*wcanwec__bd*.sqlite')   # numeric prefix is per-profile; never hardcode it
    if not _wc: print('ERROR: wawc_db_enc IndexedDB (*wcanwec__bd*.sqlite) not found under', O); sys.exit(2)
    _conk = connect_ro(_wc[0])
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
    _mm = glob.glob(f'{glob.escape(O)}/idb/*meogdaerlo*.sqlite')    # message store; per-profile numeric prefix
    if not _mm: print('ERROR: message-store IndexedDB (*meogdaerlo*.sqlite) not found under', O); sys.exit(2)
    _conm = connect_ro(_mm[0])
    if store_id(_conm, 'message') is None: print("ERROR: 'message' store not found in Firefox model-storage"); sys.exit(2)
    def store(name):                                   # resolve model-storage ids by NAME (per-profile); None -> nothing
        sid = store_id(_conm, name)
        if sid is None: return
        for (row,) in _conm.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try: yield sclone.loads(uncompress(row))
            except Exception: continue

_salt = L('WAWebEncKeySalt')
if _salt is None and not METADATA_ONLY:
    print('ERROR: WAWebEncKeySalt not in localStorage — not a WhatsApp Web profile?'); sys.exit(2)
A.dir_read(_args.profile or O, purpose="WhatsApp Web browser storage (evidence source)")
if METADATA_ONLY:
    MSGKEY = None
    print("[i] metadata only: message text is not decrypted (no key was used).")
    A.event("metadata-only export: message bodies left encrypted", category="crypto")
else:
  INFO = base64.b64decode(json.loads(_salt))
  MSGKEY = HKDF(algorithm=hashes.SHA256(), length=16, salt=SALT, info=INFO).derive(ROOT)
  A.crypto("recover", key=ROOT, key_source="IndexedDB wawc_db_enc/keys (root key)",
         input_desc=(_args.profile or O), detail={"engine": "chromium" if _is_chromium else "firefox"})
  A.crypto("derive", algorithm="AES-CBC-128", kdf="HKDF-SHA256 len=16", scheme="1 (final)", key=MSGKEY,
         key_source="HKDF(root, salt=companion_enc_static, info=WAWebEncKeySalt)",
         salt=SALT, salt_source="companion_enc_static (--enc-static)", info="WAWebEncKeySalt (localStorage)",
         input_desc="msgRowOpaqueData._data (scheme 1)")

def pk7(b):
    if not b or len(b) % 16: return b
    p = b[-1]; return b[:-p] if 1 <= p <= 16 and b[-p:] == bytes([p])*p else b
def decrypt_body(op):
    """-> (own text, quoted text, structured parts). Texts may be None; parts is a dict (see wa_opaque)."""
    if MSGKEY is None: return (None, None, {})
    if not isinstance(op, dict) or op.get('_scheme') != 1: return (None, None, {})   # MSGKEY is the scheme-1 key (scheme-0 -> garbage)
    iv = as_bytes(op.get('iv')); data = as_bytes(op.get('_data'))
    if not iv or not data: return (None, None, {})
    if len(data) % 16: return (None, None, {})    # misaligned: CBC would decrypt part and drop the tail
    try: pt = pk7(Cipher(algorithms.AES(MSGKEY), modes.CBC(iv)).decryptor().update(data))
    except Exception: return (None, None, {})
    own, quoted = _message_texts(pt)            # one parse, both strings; never truncated
    return (own or None, quoted or None, _body_details(pt))

def ser(x):
    if isinstance(x, dict): return as_text(x.get('_serialized')) or (f"{as_text(x.get('user'))}@{as_text(x.get('server'))}" if x.get('user') else None)
    return as_text(x)                  # jids/ids can arrive as V8 one-byte bytes too -> always hand back str
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
if _wid is None:
    print("ERROR: last-wid-md missing in localStorage — not a logged-in WhatsApp Web profile?"); sys.exit(2)
# WALid is absent on profiles from before WhatsApp introduced LIDs; the owner is then known by number only
OWNER_PHONE = json.loads(_wid).split(':')[0].split('@')[0] + '@s.whatsapp.net'
OWNER_USER  = OWNER_PHONE.split('@')[0]
OWNER_LID   = norm_jid(json.loads(_lid).split(':')[0] + '@lid') if _lid else None
OWNER_LID_USER = (OWNER_LID or '@').split('@')[0]
def is_owner(j):                                  # EXACT user-part match vs phone or LID (no substring false positives)
    u = (ser(j) or '@').split('@')[0]
    return bool(u) and (u == OWNER_USER or (OWNER_LID_USER and u == OWNER_LID_USER))
jid_id(OWNER_PHONE); jid_id(OWNER_LID)

MTYPE = {'chat':0,'image':1,'ptt':2,'audio':2,'video':3,'vcard':4,'location':5,'live_location':16,
         'gp2':7,'e2e_notification':7,'notification':7,'call_log':90,'document':9,'sticker':20,
         'poll_creation':66,'poll':66,'poll_vote':46,'gif':13,'album':99,'interactive':45,
         # 15 = deleted ("revoked"), 7 = system, as in Android's msgstore. Mapping revoked to 0 made
         # 126 deletions in the reference store read as 126 blank text messages.
         'revoked':15,'notification_template':7,'protocol':7,'ciphertext':0,'status':116,'template':45,
         'rich_response':0,'unknown':0}
def ack_status(a, from_me=1):
    """WhatsApp Web `ack` -> Android message.status: 1 sent (one tick) -> 4, 2 delivered -> 5, 3 read -> 13,
    4 played -> 8.
    An outgoing record with no ack is a system/control entry, which Android stores as 6. Received
    messages carry no status of ours: 0."""
    if not from_me: return 0
    a = a if isinstance(a, int) else None
    return {1: 4, 2: 5, 3: 13, 4: 8}.get(a, 6)

# store() is defined per-engine in the loader above; reference model-storage object stores by NAME.
# Optional stores (reactions/message-info/poll-votes/pinned-messages) just yield nothing if absent.
MSG_SID, CONTACT_SID, GROUP_SID, CHAT_SID = 'message', 'contact', 'group-metadata', 'chat'
REACT_SID, MSGINFO_SID, POLLV_SID, PIN_SID = 'reactions', 'message-info', 'poll-votes', 'pinned-messages'

# Validate companion_enc_static against real ciphertext (strict PKCS7) BEFORE writing anything.
# A wrong/empty key would still yield correct metadata but garbage message TEXT and silently
# "succeed" — refuse that. Right key => ~100% valid padding; wrong key => ~0.4%.
def _strict_pk7(b): return bool(b) and len(b) % 16 == 0 and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]])*b[-1]
_refs, _good = [], 0
for _o in (store(MSG_SID) if MSGKEY else ()):
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
    A.crypto("verify", algorithm="AES-CBC-128", key=MSGKEY, validated="FAILED",
             input_desc="strict PKCS7 on reference bodies", records_in=len(_refs), records_ok=_good)
    A.end_run(3, status="error", error=RuntimeError("companion_enc_static INVALID (%d/%d)" % (_good, len(_refs))))
    print(f"{'[i]' if os.environ.get('WAWF_KEY_TRIAL') else 'ERROR:'} companion_enc_static is INVALID for this profile/device — only {_good}/{len(_refs)} "
          f"reference message bodies validate. Refusing to write a garbage msgstore. (Wrong key, empty key, "
          f"or wrong browser's salt.)"); sys.exit(3)
if MSGKEY:
    A.crypto("verify", algorithm="AES-CBC-128", key=MSGKEY, validated="OK",
             input_desc="strict PKCS7 on reference bodies", records_in=len(_refs), records_ok=_good)
    print(f"[+] companion_enc_static VALIDATED ({_good}/{len(_refs)} reference bodies).")
os.makedirs(OUT, exist_ok=True); os.makedirs(f'{OUT}/Media/WhatsApp Web', exist_ok=True)

contacts = [o for o in store(CONTACT_SID) if isinstance(o, dict)]
groups   = {o['id']: o for o in store(GROUP_SID) if isinstance(o, dict) and o.get('id')}
chats    = {o['id']: o for o in store(CHAT_SID)  if isinstance(o, dict) and o.get('id')}

# --chat (wawf sets WAWF_CHAT_SCOPE): only the chosen chats are written, and with them only the people,
# groups and records that belong to those chats -- not the whole address book.
SCOPE = set(json.loads(os.environ["WAWF_CHAT_SCOPE"])) if os.environ.get("WAWF_CHAT_SCOPE") else None
def _in_scope(j):
    return SCOPE is None or _canon_jid(ser(j) or '') in SCOPE

_chat_id = {}
def chat_rowid(jid):
    if jid not in _chat_id: _chat_id[jid] = len(_chat_id) + 1
    return _chat_id[jid]

# ---- parse messages ----
messages = []; call_objs = []            # capture call_log rows here to avoid a 2nd full message-store pass
_seen_msg = set()                        # exact-duplicate guard; see where it is used
_receipts = {}                           # (chat, from_me, key id) -> ack: records holding only a receipt
for o in store(MSG_SID):
    if not isinstance(o, dict): continue
    if SCOPE is not None:
        _p = (as_text(o.get('id')) or '').split('_')
        if len(_p) < 2 or not _in_scope(_p[1]): continue
    if o.get('type') == 'call_log': call_objs.append(o)
    idv = o.get('id') or ''
    parts = idv.split('_')
    if len(parts) < 3: continue
    from_me = 1 if parts[0] == 'true' else 0
    chat_jid, key_id = parts[1], parts[2]
    if _receipt_only(o):
        # an id and its delivery state, nothing else (see wa_decrypt.receipt_only): as a message row it
        # read as an empty text message dated 1970. It goes to wawf_receipt_only instead.
        _receipts.setdefault((chat_jid, from_me, key_id), o.get('ack') if isinstance(o.get('ack'), int) else None)
        continue
    sender_suffix = parts[3] if len(parts) > 3 else None
    is_group = chat_jid.endswith('@g.us')
    is_bcast = chat_jid.endswith('@broadcast')
    sender = OWNER_PHONE if from_me else (ser(o.get('author'))
             or (sender_suffix if sender_suffix and '@' in sender_suffix else None) or ser(o.get('from')))
    typ = o.get('type') or 'chat'
    t = o.get('t') or 0
    # `sticker` is in the list now: a sticker has no text of its own, but it can be a REPLY, and the
    # quote it carries is the only record of what it answered. Before the own/quoted split that quote
    # was mistaken for the sticker's own text, which is why stickers were kept out.
    # Every message that carries a body is decrypted, whatever its type -- the JSON export already
    # does this. The old allow-list silently dropped the text of types it did not name: a
    # template_button_reply ("Yes, I am interested") was in chats.json and empty in msgstore.db.
    body, quoted_body, det = decrypt_body(o.get('msgRowOpaqueData'))
    # WhatsApp Web stores a document's FILENAME in the caption field when it has no caption; the
    # filename is exported as media_name, and a caption equal to it is not something anyone wrote.
    if typ == 'document' and body and body.strip() == (as_text(o.get('filename')) or '').strip():
        body = None
    md = None
    if o.get('mediaKey') or o.get('directPath'):
        md = {'media_key': base64.b64decode(o['mediaKey']) if o.get('mediaKey') else None,
              'direct_path': as_text(o.get('directPath')), 'file_hash': as_text(o.get('filehash')),
              'enc_file_hash': as_text(o.get('encFilehash')),
              'mime_type': as_text(o.get('mimetype')), 'file_length': o.get('size'), 'media_name': as_text(o.get('filename')),
              'caption': body if typ != 'chat' else None, 'width': o.get('width'), 'height': o.get('height'),
              'duration': o.get('duration'), 'type': typ,
              'media_key_ts': o.get('mediaKeyTimestamp'), 'message_url': as_text(o.get('deprecatedMms3Url'))}
    th = o.get('thumbnail')
    ment = [ser(x) for x in (o.get('mentionedJidList') or []) if ser(x)]
    row = {
        'webid': idv, 'chat_jid': chat_jid, 'from_me': from_me, 'key_id': key_id,
        # received: sender = author/partner (groups+broadcast use author; 1:1 partner also fine)
        'sender_jid': None if (from_me or (not is_group and not is_bcast)) else sender,   # null sender for own + 1:1 received
        # view-once: Android's own types (42 photo, 43 video), so Android tools show it as view-once
        'timestamp': int(t)*1000 if t else 0,
        'message_type': ({'image': 42, 'video': 43}.get(typ, MTYPE.get(typ, 0)) if o.get('isViewOnce') else MTYPE.get(typ, 0)),
        'text_data': body,
        'status': ack_status(o.get('ack'), from_me), 'starred': 1 if o.get('star') or o.get('isStarred') else 0,
        'media': md, 'thumb': base64.b64decode(th) if isinstance(th, str) and th else None,
        'mentioned': ment, 'quoted_id': as_text(o.get('quotedStanzaID')), 'quoted_type': as_text(o.get('quotedType')),
        'quoted_text': quoted_body, 'source': 'cache', 'details': det,
    }
    # This store yields superseded record versions as well as live ones, so the same message can
    # arrive twice; 25 ids do here. Those copies are NOT byte-identical records -- they differ in
    # `ack`, `pendingReadReceipt` and `hasReaction` -- but delivery and read state is the message
    # moving through its lifecycle, not a second message, and the newest copy comes first, so taking
    # the first gives the current state.
    #
    # The key is therefore everything this row CARRIES except that volatile state: text, quote,
    # timestamp, sender, type, media, thumbnail, mentions, and the quoted link. Keying on a handful
    # of columns instead would have dropped a version that differs in its media key, its mentions or
    # its thumbnail, while the comment claimed such versions were kept. `status` and `starred` are
    # excluded deliberately: a message that was delivered, then read, then starred is one message.
    _k = json.dumps({k: v for k, v in row.items() if k not in ('status', 'starred')},
                    sort_keys=True, default=repr)
    if _k in _seen_msg: continue
    _seen_msg.add(_k)
    messages.append(row)
    jid_id(chat_jid); chat_rowid(chat_jid)
    if messages[-1]['sender_jid']: jid_id(messages[-1]['sender_jid'])
    for mj in ment: jid_id(mj)

# ---- messages the phone served, appended to the ones the store held -------------------------
# A `--history` run produces one dataset: the local store plus whatever the phone returned. They are
# appended here rather than written to a second database, because an examiner wants one timeline per
# chat -- and `message.source` says which side each row came from, since the provenance differs even
# though the timeline does not. Dedup is on the stanza id, and the stored copy always wins.
HIST = []
if HISTORY_FILE:
    try:
        with open(HISTORY_FILE, encoding='utf-8') as fh:
            HIST = (json.load(fh) or {}).get('messages') or []
    except Exception as e:
        print(f"[!] could not read recovered history from {HISTORY_FILE}: {e}")
        HIST = []
if HIST:
    have = {_stanza_of(m['webid']) for m in messages}
    # the form the store filed each chat under, so a wire jid folds onto it instead of splitting
    byform = {}
    for m in messages:
        byform.setdefault(_canon_jid(m['chat_jid']), m['chat_jid'])
        byform.setdefault(m['chat_jid'], m['chat_jid'])
    # ...and the phone-number form onto the LID form. The store files a 1:1 chat under the LID, while
    # history from the phone names it by phone number; canon_jid only normalises the phone-number
    # SERVER, so every such record opened a second chat. Measured on a merged export: 77 people's
    # conversations split in two in msgstore.db (359 chats with messages) while chats.json, which
    # resolves identities, had them as one (282). The contact record's phoneNumber is the link -- the
    # same pairs this script writes to jid_map.
    # A phone number can have more than one LID record (a stale one beside the current one); prefer
    # the LID the store actually filed a chat under, or the fold misses and the split survives.
    lid_of = {}
    for c in contacts:
        lid, phone = norm_jid(c.get('id')), norm_jid(c.get('phoneNumber'))
        if lid and phone and str(lid).endswith('@lid'):
            k = _canon_jid(phone)
            if k not in lid_of or (lid in byform and lid_of[k] not in byform):
                lid_of[k] = lid
    appended = outside = 0
    _hist_added = set()                           # stanza ids this merge appended
    for r in HIST:
        sid = str(r.get('id') or '')
        chat = r.get('chat')
        if chat and not _in_scope(chat): outside += 1; continue
        if not sid or not chat or sid in have: continue
        raw = _canon_jid(chat)
        cj = byform.get(raw) or byform.get(lid_of.get(raw)) or chat
        fromme = 1 if r.get('fromMe') else 0
        part = ser(r.get('participant'))
        is_group = str(cj).endswith('@g.us')
        sender = None if fromme else (part or (None if is_group else cj))
        typ = _hist_type(r.get('type'))
        messages.append({
            'webid': ('true' if fromme else 'false') + '_' + str(cj) + '_' + sid,
            'chat_jid': cj, 'from_me': fromme, 'key_id': sid,
            'sender_jid': norm_jid(sender) if sender else None,
            'timestamp': int(r.get('ts') or 0) * 1000, 'message_type': MTYPE.get(typ, 0),
            'text_data': (r.get('text') or None) if (r.get('text') or '').strip() else None,   # as sent
            'status': 0, 'starred': 0, 'media': None, 'thumb': None, 'mentioned': [],
            'quoted_id': None, 'quoted_type': None, 'quoted_text': None, 'source': r.get('source') or 'phone',
        })
        have.add(sid); appended += 1; _hist_added.add(sid)
        jid_id(cj); chat_rowid(cj)
        if sender: jid_id(norm_jid(sender))
    for k in [k for k in _receipts if k[2] in _hist_added]:
        del _receipts[k]                          # the phone served the message this receipt stood in for
    messages.sort(key=lambda m: (m['chat_jid'], m['timestamp']))
    _src = {}
    for r in HIST: _src[r.get('source') or 'phone'] = _src.get(r.get('source') or 'phone', 0) + 1
    _from = ' and '.join('%s (%d offered)' % ({'phone': 'the phone', 'server-queue': 'the server queue'}.get(k, k), v)
                         for k, v in _src.items()) or 'the phone'
    print(f"[+] merged: appended {appended} message(s) from {_from} "
          f"({len(HIST) - appended - outside} already in the store"
          + (f"; {outside} from chats outside --chat, left out" if outside else "") + ")")

if SCOPE is not None:
    # the chats themselves, and the people who appear in them (senders, mentions); a lid contact
    # record is kept when its phone number appears, and the other way round
    _ref = {_canon_jid(x) for m in messages for x in [m['chat_jid'], m.get('sender_jid')] + list(m.get('mentioned') or []) if x}
    _ref |= SCOPE
    contacts = [c for c in contacts if _canon_jid(ser(c.get('id')) or '') in _ref
                or _canon_jid(ser(c.get('phoneNumber')) or '') in _ref]
    groups = {k: v for k, v in groups.items() if _in_scope(k)}
    chats = {k: v for k, v in chats.items() if _in_scope(k)}
    print(f"--chat: {len(messages)} message(s) in the chosen chat(s); {len(contacts)} contact record(s) of the people in them")
for c in contacts:
    if c.get('id'): jid_id(c['id'])
    if c.get('phoneNumber'): jid_id(c['phoneNumber'])
for g in groups: jid_id(g)
for ch in chats: jid_id(ch); chat_rowid(ch)
print(f"parsed: {len(messages)} messages, {len(_jid_id)} jids, {len(_chat_id)} chats")

# ============ msgstore.db ============
mp = f'{OUT}/msgstore.db'
# Media files are named after the message's row id, and a database written again into this folder
# numbers its rows afresh -- `--history` writes it twice, the second time with the phone's messages
# merged in. The files of the previous export were left under their old numbers: unreferenced
# copies, named after rows that are now other messages. Remember which message each one belonged to,
# so they are renamed to the new numbers below (a file fetched from the CDN may not be fetchable twice).
_prev_media = {}
if os.path.exists(mp):
    try:
        _o = sqlite3.connect(sqlite_uri(mp) + "?mode=ro", uri=True)
        _prev_media = {(cj, fm, kid): fp for cj, fm, kid, fp in _o.execute(
            "SELECT j.raw_string, m.from_me, m.key_id, mm.file_path FROM message_media mm "
            "JOIN message m ON m._id=mm.message_row_id JOIN chat c ON c._id=m.chat_row_id "
            "JOIN jid j ON j._id=c.jid_row_id WHERE mm.file_path LIKE 'Media/WhatsApp Web/%'")}
        _o.close()
    except sqlite3.Error:
        _prev_media = {}
if os.path.exists(mp): os.remove(mp)
db = sqlite3.connect(mp)
db.executescript("""
CREATE TABLE jid(_id INTEGER PRIMARY KEY, user TEXT, server TEXT, agent INTEGER DEFAULT 0, device INTEGER DEFAULT 0, type INTEGER DEFAULT 0, raw_string TEXT);
CREATE TABLE jid_map(jid_row_id INTEGER, lid_row_id INTEGER);
CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT, created_timestamp INTEGER, sort_timestamp INTEGER, display_message_row_id INTEGER, archived INTEGER DEFAULT 0, account_jid_row_id INTEGER, participation_status INTEGER);
CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER, timestamp INTEGER, received_timestamp INTEGER, message_type INTEGER, text_data TEXT, status INTEGER, sort_id INTEGER, starred INTEGER DEFAULT 0, broadcast INTEGER DEFAULT 0, source TEXT DEFAULT 'cache');
CREATE TABLE message_media(_id INTEGER PRIMARY KEY, message_row_id INTEGER, chat_row_id INTEGER, file_path TEXT, file_size INTEGER, file_length INTEGER, mime_type TEXT, width INTEGER, height INTEGER, media_duration INTEGER, direct_path TEXT, file_hash TEXT, enc_file_hash TEXT, original_file_hash TEXT, media_key BLOB, media_key_timestamp INTEGER, message_url TEXT, media_caption TEXT, media_name TEXT);
CREATE TABLE message_thumbnail(message_row_id INTEGER, thumbnail BLOB);
CREATE TABLE message_album(message_row_id INTEGER, image_count INTEGER, video_count INTEGER, expected_image_count INTEGER, expected_video_count INTEGER);
CREATE TABLE message_association(child_message_row_id INTEGER, parent_message_row_id INTEGER, association_type INTEGER);
CREATE TABLE message_quoted(message_row_id INTEGER, key_id TEXT, text_data TEXT, message_type INTEGER, parent_message_chat_row_id INTEGER, chat_row_id INTEGER);
CREATE TABLE message_mentions(_id INTEGER PRIMARY KEY, message_row_id INTEGER, jid_row_id INTEGER);
CREATE TABLE message_add_on(_id INTEGER PRIMARY KEY, parent_message_row_id INTEGER, sender_jid_row_id INTEGER, from_me INTEGER, timestamp INTEGER, message_add_on_type INTEGER);
CREATE TABLE message_add_on_reaction(message_add_on_row_id INTEGER, reaction TEXT);
CREATE TABLE message_poll(message_row_id INTEGER, selectable_options_count INTEGER, poll_type INTEGER, end_time INTEGER, hide_participant_names INTEGER, allow_add_option INTEGER, correct_option_id INTEGER);
CREATE TABLE message_poll_option(_id INTEGER PRIMARY KEY, message_row_id INTEGER, option_name TEXT, option_hash TEXT, vote_total INTEGER);
CREATE TABLE message_text(message_row_id INTEGER, description TEXT, page_title TEXT, url TEXT);
CREATE TABLE message_location(message_row_id INTEGER, chat_row_id INTEGER, latitude REAL, longitude REAL, place_name TEXT, place_address TEXT, url TEXT, live_location_share_duration INTEGER);
CREATE TABLE message_event(message_row_id INTEGER, is_canceled INTEGER, name TEXT, description TEXT, location_latitude REAL, location_longitude REAL, location_name TEXT, location_address TEXT, join_link TEXT, start_time INTEGER, chat_row_id INTEGER, end_time INTEGER);
CREATE TABLE message_add_on_poll_vote(message_add_on_row_id INTEGER, sender_timestamp INTEGER);
CREATE TABLE receipt_user(message_row_id INTEGER, receipt_user_jid_row_id INTEGER, receipt_timestamp INTEGER, read_timestamp INTEGER, played_timestamp INTEGER);
CREATE TABLE message_link(_id INTEGER PRIMARY KEY, message_row_id INTEGER, link_index INTEGER);
CREATE TABLE message_add_on_pin_in_chat(message_add_on_row_id INTEGER, sender_timestamp INTEGER, expiry_duration_in_secs INTEGER, pin_in_chat_state INTEGER);
CREATE TABLE call_log(_id INTEGER PRIMARY KEY, jid_row_id INTEGER, from_me INTEGER, timestamp INTEGER, video_call INTEGER, duration INTEGER, call_result INTEGER, bytes_transferred INTEGER, call_id TEXT, is_joinable_group_call INTEGER DEFAULT 0, group_jid_row_id INTEGER DEFAULT 0, call_type INTEGER DEFAULT 0, call_creator_device_jid_row_id INTEGER DEFAULT 0);
""")
_TYPE = {'s.whatsapp.net':0,'lid':18,'g.us':1,'newsletter':21,'bot':26,'broadcast':0}
_jid_written = set()
def _flush_jids():
    """Write every jid handed a row id that has no `jid` row yet. Called again before the commit, so a
    reference created by a later section can never point at a row that does not exist."""
    for raw, rid in list(_jid_id.items()):
        if rid in _jid_written: continue
        user = raw.split('@')[0]; srv = server_of(raw); dev = 0
        if ':' in user:
            u, dd = user.split(':', 1); user = u; dev = int(dd) if dd.isdigit() else 0
        ty = _TYPE.get(srv, 0)
        if dev > 0: ty = 17 if srv == 's.whatsapp.net' else (19 if srv == 'lid' else ty)
        db.execute("INSERT INTO jid(_id,user,server,agent,device,type,raw_string) VALUES(?,?,?,?,?,?,?)", (rid, user, srv, 0, dev, ty, raw))
        _jid_written.add(rid)
_flush_jids()
for c in contacts:
    lid = c.get('id'); phone = c.get('phoneNumber')
    if lid and phone and str(lid).endswith('@lid'):
        db.execute("INSERT INTO jid_map(jid_row_id,lid_row_id) VALUES(?,?)", (jid_id(phone), jid_id(lid)))
CHATNAME = {}            # non-group chat display names, for wa_contacts to fall back on
owner_jid_row = jid_id(OWNER_PHONE)
for jraw, cid in _chat_id.items():
    ch = chats.get(jraw); g = groups.get(jraw)
    # Android keeps `chat.subject` for groups only -- a 1:1 chat's display name lives in wa_contacts,
    # and writing it here made the official "WhatsApp" account look like a group with a subject.
    # A non-group name is not discarded, though: it is handed to wa_contacts below, because dropping
    # it from `subject` without putting it anywhere would lose the only name a business account or
    # the "WhatsApp" account has.
    _nm = as_text((g.get('subject') if g else None) or (ch.get('name') if ch else None))
    if _nm and not str(jraw).endswith('@g.us'):
        CHATNAME[norm_jid(jraw)] = _nm
    subject = _nm if str(jraw).endswith('@g.us') else None
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
    db.execute("""INSERT INTO message(_id,chat_row_id,from_me,key_id,sender_jid_row_id,timestamp,received_timestamp,message_type,text_data,status,sort_id,starred,broadcast,source)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (mid, chat_rowid(m['chat_jid']), m['from_me'], m['key_id'], srow, m['timestamp'], m['timestamp'],
                m['message_type'], m['text_data'], m['status'], mid, m['starred'],
                1 if m['chat_jid'].endswith('@broadcast') else 0, m.get('source', 'cache')))
    md = m['media']
    if md:
        db.execute("""INSERT INTO message_media(message_row_id,chat_row_id,file_path,file_size,file_length,mime_type,width,height,media_duration,direct_path,file_hash,enc_file_hash,original_file_hash,media_key,media_key_timestamp,message_url,media_caption,media_name)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (mid, chat_rowid(m['chat_jid']), None, md['file_length'], md['file_length'], md['mime_type'], md['width'], md['height'],
                    int(md['duration'])*1000 if md.get('duration') else None, md['direct_path'], md['file_hash'],
                    md['enc_file_hash'], None, md['media_key'], md.get('media_key_ts'), md.get('message_url'), md['caption'], md['media_name']))
    if m['thumb']: db.execute("INSERT INTO message_thumbnail(message_row_id,thumbnail) VALUES(?,?)", (mid, m['thumb']))
    # text_data used to be written as NULL here while the quoted text was being concatenated into
    # the replying message's own text. It belongs in this column, which is where an Android parser
    # looks to render reply context.
    if m['quoted_id'] or m.get('quoted_text'):
        db.execute("INSERT INTO message_quoted(message_row_id,key_id,text_data,message_type,chat_row_id) VALUES(?,?,?,?,?)",
                   (mid, m['quoted_id'], m.get('quoted_text'), m['quoted_type'], chat_rowid(m['chat_jid'])))
    for mj in m['mentioned']:
        r = jid_id(mj)
        if r: ment_id += 1; db.execute("INSERT INTO message_mentions(_id,message_row_id,jid_row_id) VALUES(?,?,?)", (ment_id, mid, r))
    if m['text_data']:
        for li, _u in enumerate(re.findall(r'https?://\S+', m['text_data'])):
            db.execute("INSERT INTO message_link(message_row_id,link_index) VALUES(?,?)", (mid, li))
    det = m.get('details') or {}
    if det.get('link'):
        lk = det['link']
        db.execute("INSERT INTO message_text(message_row_id,description,page_title,url) VALUES(?,?,?,?)",
                   (mid, lk.get('description'), lk.get('title'), lk.get('url') or lk.get('client_url')))
    if det.get('location'):
        lc = det['location']
        db.execute("INSERT INTO message_location(message_row_id,chat_row_id,latitude,longitude,place_name,live_location_share_duration) VALUES(?,?,?,?,?,?)",
                   (mid, chat_rowid(m['chat_jid']), lc.get('lat'), lc.get('lng'), lc.get('name'), 1 if lc.get('live') else None))
    if det.get('event'):
        ev = det['event']; el = ev.get('location') or {}
        db.execute("INSERT INTO message_event(message_row_id,is_canceled,name,description,location_latitude,location_longitude,location_name,location_address,join_link,start_time,chat_row_id,end_time) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (mid, 1 if ev.get('canceled') else 0, ev.get('name'), ev.get('description'), el.get('degreesLatitude'),
                    el.get('degreesLongitude'), el.get('name'), el.get('address'), ev.get('join_link'),
                    (ev.get('start') or 0) * 1000 or None, chat_rowid(m['chat_jid']), (ev.get('end') or 0) * 1000 or None))

# ---- groups: current members (rank 0 member / 1 admin / 2 super-admin), past members, settings ----
# The `participant` store holds one record per group: member jids, admins, super-admins, and past
# members with when and how they left ("Left" or "Removed"). Android keeps the same facts in
# group_participant_user / group_past_participant_user; settings Android keeps across several wa.db
# tables are written to one wawf_group_settings table instead (named so it is not mistaken for one).
db.execute("CREATE TABLE group_participant_user(_id INTEGER PRIMARY KEY, group_jid_row_id INTEGER, user_jid_row_id INTEGER, rank INTEGER, pending INTEGER DEFAULT 0, add_timestamp INTEGER)")
db.execute("CREATE TABLE group_past_participant_user(_id INTEGER PRIMARY KEY, group_jid_row_id INTEGER, user_jid_row_id INTEGER, is_leave INTEGER, timestamp INTEGER)")
db.execute("""CREATE TABLE wawf_group_settings(group_jid_row_id INTEGER PRIMARY KEY, subject TEXT, subject_time INTEGER,
              owner_jid_row_id INTEGER, creation INTEGER, description TEXT, description_owner_jid_row_id INTEGER,
              description_time INTEGER, announce INTEGER, restrict INTEGER, member_add_mode TEXT,
              membership_approval_mode INTEGER, ephemeral_duration INTEGER, size INTEGER,
              parent_group_jid_row_id INTEGER, is_parent_group INTEGER, incomplete_participant_info INTEGER,
              suspended INTEGER, terminated INTEGER)""")
gpu = gpp = gs = 0
for o in store('participant'):
    if not isinstance(o, dict) or not o.get('groupId'): continue
    if not _in_scope(o['groupId']): continue
    grow = jid_id(ser(o['groupId']))
    if not grow: continue
    rank = {}
    for j in o.get('participants') or []: rank[ser(j)] = 0
    for j in o.get('admins') or []: rank[ser(j)] = 1
    for j in o.get('superAdmins') or []: rank[ser(j)] = 2
    for j, r in rank.items():
        u = jid_id(j)
        if not u: continue
        gpu += 1
        db.execute("INSERT INTO group_participant_user(_id,group_jid_row_id,user_jid_row_id,rank) VALUES(?,?,?,?)", (gpu, grow, u, r))
    for x in o.get('pastParticipants') or []:
        if not isinstance(x, dict): continue
        u = jid_id(ser(x.get('jid')))
        if not u: continue
        gpp += 1
        ts_ = x.get('leaveTs')
        db.execute("INSERT INTO group_past_participant_user(_id,group_jid_row_id,user_jid_row_id,is_leave,timestamp) VALUES(?,?,?,?,?)",
                   (gpp, grow, u, 1 if str(x.get('leaveReason')) == 'Left' else 0, int(float(ts_) * 1000) if ts_ else None))
for gid, g in groups.items():
    grow = jid_id(ser(gid))
    if not grow: continue
    def _b(v): return None if v is None else (1 if v else 0)
    def _ms(v):
        try: return int(float(v) * 1000) if v else None
        except (TypeError, ValueError): return None
    desc = g.get('desc')
    gs += 1
    db.execute("INSERT OR REPLACE INTO wawf_group_settings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (grow, as_text(g.get('subject')), _ms(g.get('subjectTime')), jid_id(ser(g.get('owner'))) or None,
                _ms(g.get('creation')), as_text(desc) if isinstance(desc, str) else None,
                jid_id(ser(g.get('descOwner'))) or None, _ms(g.get('descTime')), _b(g.get('announce')),
                _b(g.get('restrict')), as_text(g.get('memberAddMode')) if g.get('memberAddMode') is not None else None,
                _b(g.get('membershipApprovalMode')), g.get('ephemeralDuration'), g.get('size'),
                jid_id(ser(g.get('parentGroup'))) or None, _b(g.get('isParentGroup')),
                _b(g.get('hasIncompleteParticipantInformation')), _b(g.get('suspended')), _b(g.get('terminated'))))

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
    db.execute("INSERT INTO message_add_on_reaction(message_add_on_row_id,reaction) VALUES(?,?)", (addon_id, as_text(o.get('reactionText'))))
    rx += 1

# ---- message associations: album items, HD copies, motion photos -> message_association ----
# The browser labels associations MEDIA_ALBUM or UNKNOWN. MEDIA_ALBUM is Android's album item (2); UNKNOWN
# under a video parent is the video's HD copy (7); UNKNOWN under a photo parent is the photo's HD copy (12)
# or a motion photo (11), which the browser's records do not distinguish, so those -- and anything else --
# go only to wawf_message_association with the browser's label. WhatsApp Web keeps no media key for an HD
# or motion-photo child.
db.execute("""CREATE TABLE wawf_message_association(child_message_row_id INTEGER, parent_message_row_id INTEGER,
              child_key TEXT, parent_key TEXT, browser_association_type TEXT, meaning TEXT)""")
na = nwa = 0
for o in store('message-association'):
    if not isinstance(o, dict): continue
    ck, pk, bt = as_text(o.get('msgKey')), as_text(o.get('parentMsgKey')), as_text(o.get('associationType'))
    cid, pid = WEBID2ID.get(ck), WEBID2ID.get(pk)
    if SCOPE is not None and not (cid or pid): continue      # belongs to a chat outside --chat
    ptype = db.execute("SELECT message_type FROM message WHERE _id=?", (pid,)).fetchone() if pid else None
    ptype = ptype[0] if ptype else None
    if bt == 'MEDIA_ALBUM':
        atype, meaning = 2, 'album item'
    elif bt == 'UNKNOWN' and ptype in (3, 43):
        atype, meaning = 7, 'HD copy of a video (the browser keeps no media key for it)'
    elif bt == 'UNKNOWN' and ptype in (1, 42):
        atype, meaning = None, 'HD copy or motion photo of a photo (the browser does not record which; no media key kept)'
    else:
        atype, meaning = None, 'association %s' % bt
    db.execute("INSERT INTO wawf_message_association VALUES(?,?,?,?,?,?)", (cid, pid, ck, pk, bt, meaning))
    nwa += 1
    if atype and cid and pid:
        db.execute("INSERT INTO message_association(child_message_row_id,parent_message_row_id,association_type) VALUES(?,?,?)",
                   (cid, pid, atype))
        na += 1

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
pl = 0; popt = 0
for m in messages:
    pdet = (m.get('details') or {}).get('poll')
    if m['message_type'] == 66 or pdet:
        pdet = pdet or {}
        rid = WEBID2ID[m['webid']]
        db.execute("INSERT INTO message_poll(message_row_id,selectable_options_count,poll_type,end_time) VALUES(?,?,?,?)",
                   (rid, pdet.get('selectable'), 1 if pdet.get('type') == 'QUIZ' else 0 if pdet else None,
                    pdet.get('end_time'))); pl += 1
        votes = {v.get('option'): v.get('count') for v in pdet.get('votes') or []}
        for name in pdet.get('options') or []:
            popt += 1
            db.execute("INSERT INTO message_poll_option(_id,message_row_id,option_name,vote_total) VALUES(?,?,?,?)",
                       (popt, rid, name, votes.get(name)))
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
# A call is stored again as it progresses ('Ongoing', then 'Completed' with its length): keep one row
# per call, from the version that says how it ended.
def _call_rank(o):
    out = o.get('finalCallOutcome') or o.get('callOutcome')
    return (out not in (None, 'Ongoing'), o.get('callDuration') or 0)
_calls = {}
for o in call_objs:
    k = o.get('id')
    if k not in _calls or _call_rank(o) > _call_rank(_calls[k]): _calls[k] = o
# WhatsApp Web's outcome -> the call_result code this schema uses (5 connected, 2 not)
_CONNECTED = ('completed', 'acceptedelsewhere', 'accepted', 'answered')
cl = 0
for o in _calls.values():                # already collected during the single parse pass above
    cl += 1
    frm = ser(o.get('from')); to = ser(o.get('to')); fm = 1 if is_owner(frm) else 0
    other = to if fm else frm
    # a call placed in a group is the group's, not a 1:1 call with whoever started it: it was written
    # with no group at all, so it read as a direct call from that person
    _p = (as_text(o.get('id')) or '').split('_')
    grp = _p[1] if len(_p) > 1 and _p[1].endswith('@g.us') else None
    db.execute("""INSERT INTO call_log(_id,jid_row_id,from_me,timestamp,video_call,duration,call_result,bytes_transferred,call_id,is_joinable_group_call,group_jid_row_id,call_creator_device_jid_row_id)
                  VALUES(?,?,?,?,?,?,?,?,?,0,?,?)""",
               (cl, jid_id(other) or 0, fm, int(o.get('t') or 0)*1000, 1 if o.get('isVideoCall') else 0,
                int(o.get('callDuration') or o.get('duration') or 0),
                5 if str(o.get('finalCallOutcome') or o.get('callOutcome') or '').lower() in _CONNECTED else 2,
                0, as_text(o.get('id')), (jid_id(grp) or 0) if grp else 0,
                (jid_id(frm) or 0) if grp else 0))

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

# ---- records holding only a delivery receipt (no message) -> wawf_receipt_only ----
# Not message rows: Android's schema has no way to say "a receipt for a message this store does not
# hold" without inventing a type and a time. Named wawf_ so no parser takes it for an Android table.
db.execute("CREATE TABLE wawf_receipt_only(_id INTEGER PRIMARY KEY, chat_jid_row_id INTEGER, from_me INTEGER, "
           "key_id TEXT, ack INTEGER)")
for (cj, fm, kid), ack in _receipts.items():
    db.execute("INSERT INTO wawf_receipt_only(chat_jid_row_id,from_me,key_id,ack) VALUES(?,?,?,?)",
               (jid_id(cj) or 0, fm, kid, ack))
if _receipts:
    print(f"  [i] {len(_receipts)} record(s) hold only a delivery receipt (no time, no type, no body) for a "
          f"message the store does not hold: written to wawf_receipt_only, not as messages")

_flush_jids()
db.commit(); db.close()

# ============ wa.db ============
wp = f'{OUT}/wa.db'
if os.path.exists(wp): os.remove(wp)
wa = sqlite3.connect(wp)
wa.execute("CREATE TABLE wa_contacts(_id INTEGER PRIMARY KEY AUTOINCREMENT, jid TEXT UNIQUE, display_name TEXT, wa_name TEXT, given_name TEXT, family_name TEXT, status TEXT, number TEXT, is_whatsapp_user INTEGER DEFAULT 1)")
for c in contacts:
    for jraw in {norm_jid(c.get('id')), norm_jid(c.get('phoneNumber'))} - {None}:
        # the number: the record's phoneNumber, or -- on a record filed under the phone number itself,
        # which carries no phoneNumber field -- that jid's own user part (it left 1,400 rows blank)
        num = (ser(c.get('phoneNumber')) or (jraw if jraw.endswith('@s.whatsapp.net') else '')).split('@')[0]
        wa.execute("INSERT OR IGNORE INTO wa_contacts(jid,display_name,wa_name,given_name,status,number) VALUES(?,?,?,?,?,?)",
                   (jraw, as_text(c.get('name')), as_text(c.get('pushname')), as_text(c.get('shortName')),
                    as_text(c.get('textStatusString')) or None, num))
# A non-group chat's display name, for anyone the contact store does not cover: a business account,
# the official "WhatsApp" account, a chat whose contact record never synced. It used to ride in
# `chat.subject`, which is a group column in this schema -- moved here rather than dropped, because
# otherwise it is the only name those chats have and it would appear nowhere in either database.
# INSERT OR IGNORE, so a real contact record always wins; the UPDATE fills a blank display_name on
# a row that exists but has no name.
for jraw, nm in CHATNAME.items():
    if not jraw: continue
    wa.execute("INSERT OR IGNORE INTO wa_contacts(jid,display_name,number) VALUES(?,?,?)",
               (jraw, nm, jraw.split('@')[0] if jraw.endswith('@s.whatsapp.net') else ''))
    wa.execute("UPDATE wa_contacts SET display_name=? WHERE jid=? AND "
               "(display_name IS NULL OR display_name='')", (nm, jraw))
wa.commit(); wa.close()

# ============ media of a previous export in this folder: renamed to this export's row ids ============
if _prev_media:
    db = sqlite3.connect(mp)
    _now = {(cj, fm, kid): rid for rid, cj, fm, kid in db.execute(
        "SELECT m._id, j.raw_string, m.from_me, m.key_id FROM message m JOIN chat c ON c._id=m.chat_row_id "
        "JOIN jid j ON j._id=c.jid_row_id WHERE m._id IN (SELECT message_row_id FROM message_media)")}
    _stage = f'{OUT}/Media/WhatsApp Web/.relinking'
    os.makedirs(_stage, exist_ok=True)
    _moved = {}
    for k, fp in _prev_media.items():                # out of the way first: an old name can be a new one
        if os.path.isfile(f'{OUT}/{fp}'):
            _moved[k] = os.path.join(_stage, os.path.basename(fp))
            os.replace(f'{OUT}/{fp}', _moved[k])
    # A file whose message is not in this export (another chat, with --chat; another copy of the
    # profile) is set aside, never deleted: a file downloaded from the CDN may not be downloadable
    # again. It is named after its message key instead of a row id of a database that no longer
    # exists, so it cannot be mistaken for a message of this export.
    _aside_dir = f'{OUT}/Media/previous-export'
    _renamed, _aside = {}, {}
    for k, src in _moved.items():
        rid = _now.get(k)
        if rid:
            rel = f"Media/WhatsApp Web/{rid}{os.path.splitext(src)[1]}"
            os.replace(src, f'{OUT}/{rel}')
            db.execute("UPDATE message_media SET file_path=? WHERE message_row_id=?", (rel, rid))
            _renamed[_prev_media[k]] = rel
        else:
            os.makedirs(_aside_dir, exist_ok=True)
            cj, fm, kid = k
            name = re.sub(r'[^\w@.+-]', '_', f"{cj}_{fm}_{kid}") + os.path.splitext(src)[1]
            os.replace(src, os.path.join(_aside_dir, name))
            _aside[_prev_media[k]] = f"Media/previous-export/{name}"
    try: os.rmdir(_stage)
    except OSError: pass
    db.commit(); db.close()
    A.event("media of the previous export in this folder renamed to this export's row ids", category="stage",
            detail={"renamed": _renamed, "set_aside_not_in_this_export": _aside})
    print(f"  [i] media of the previous export in this folder: {len(_renamed)} file(s) renamed to this "
          f"export's row ids" + (f"; {len(_aside)} whose messages are not in this export set aside in "
                                 f"{_aside_dir} (not part of this export)" if _aside else ""))

# ============ decrypt cached media into Media/ + set file_path ============
# Browser-agnostic: mediacache walks every cache layout we know (Chromium simple-cache +
# blockfile, Firefox CacheStorage + cache2) under both the profile and, for Firefox, the origin.
# This block used to be gated `C = None if _is_chromium else ...`, so on ANY Chromium profile
# (Chrome/Edge/Brave/Opera) it silently recovered nothing while still creating an empty
# Media/WhatsApp Web folder -- the only hint being media_decrypted_to_disk=0 in the line below.
import mediacache
# One blob can belong to MANY messages -- a forwarded image or a re-sent sticker shares its
# ciphertext -- so index a LIST per hash. Keying one message per hash silently dropped the
# file_path of every other message that shared it.
byench = {}
byplain = {}       # WhatsApp Web also caches media it has already DECRYPTED; those match the plain hash
for m in messages:
    if m['media'] and m['media'].get('enc_file_hash'):
        byench.setdefault(m['media']['enc_file_hash'], []).append(m)
    if m['media'] and m['media'].get('file_hash'):
        byplain.setdefault(m['media']['file_hash'], []).append(m)
decrypted = blobs = plain_hits = 0
_written = set()                          # messages whose file is written: one file each, counted once
cached, _cst = mediacache.recover(set(byench) | set(byplain), _args.profile, O if not _is_chromium else None)
db = sqlite3.connect(mp)
for h, body in cached.items():
    wrote_any = False
    for m in byench.get(h, []) + byplain.get(h, []):
        md = m['media']
        rid = WEBID2ID[m['webid']]
        # The browser can hold a message's media twice -- the encrypted blob and an already decrypted
        # copy -- and each matched it: the same file was written twice and counted twice (3,135 "files"
        # reported, 2,424 on disk).
        if rid in _written: continue
        plain = h == md.get('file_hash')
        if plain:
            pt = body                     # cached already decrypted; recover() matched its SHA-256 exactly
        else:
            # the media TYPE (image/video/audio/document/sticker) picks the HKDF info string; fall back
            # to the mime when the record has no type word
            pt = mediacache.decrypt_media(body, md['media_key'], md.get('type') or md.get('mime_type'))
        if pt is None: continue
        if base64.b64encode(hashlib.sha256(pt).digest()).decode() != md['file_hash']: continue  # verified
        ext = mediacache.ext_for(md['mime_type'])
        rel = f"Media/WhatsApp Web/{rid}.{ext}"
        try: open(f'{OUT}/{rel}', 'wb').write(pt)
        except OSError: continue
        db.execute("UPDATE message_media SET file_path=? WHERE message_row_id=?", (rel, rid))
        decrypted += 1; wrote_any = True; _written.add(rid)
        if plain: plain_hits += 1
    blobs += 1 if wrote_any else 0
db.commit(); db.close()
if byench and not decrypted:
    print(f"  [i] media: {len(byench)} media message(s) have keys but none of their blobs are "
          f"in this browser's cache — wawf --fetch-media (or scripts/mediafetch.py --cdn) can download them")
elif decrypted:
    print(f"  [+] media: {decrypted} file(s) recovered from the browser's cache "
          f"({plain_hits} cached already decrypted, {decrypted - plain_hits} decrypted with their media key)")
print(f"WROTE SQLite DB: {mp} + {wp}  (+ {OUT}/Media)")
print(f"  groups={gs} group_members={gpu} past_members={gpp}")
print(f"  jids={len(_jid_id)} chats={len(_chat_id)} messages={mid} mentions={ment_id} reactions={rx} receipts={rc} polls={pl}/votes={pv} media_decrypted_to_disk={decrypted}")
if MSGKEY:
    A.crypto("decrypt", algorithm="AES-CBC-128", scheme="1 (final)", key=MSGKEY,
             input_desc="all scheme-1 message bodies", records_in=mid, records_ok=mid)
A.artifact(mp, kind="Android msgstore.db (decrypted messages)", records=mid)
A.artifact(wp, kind="Android wa.db (contacts)", records=len(contacts))
A.event("export_sqlite complete", category="stage",
        detail={"jids": len(_jid_id), "chats": len(_chat_id), "messages": mid, "mentions": ment_id,
                "reactions": rx, "receipts": rc, "polls": pl, "votes": pv, "media_written": decrypted,
                "receipt_only_records": len(_receipts),
                "associations": na, "associations_browser": nwa})
A.end_run(0, status="ok")
# ---- human-readable summary ----
import datetime as _dt
_secs=[m['timestamp']/1000 for m in messages if m.get('timestamp') and 1e9 < m['timestamp']/1000 < 2e9]
def _d(t): return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime('%Y-%m-%d')
_cset=set(m['chat_jid'] for m in messages if m.get('chat_jid'))
_grp=sum(1 for c in _cset if c.endswith('@g.us')); _sent=sum(1 for m in messages if m.get('from_me'))
_media=sum(1 for m in messages if m.get('media') and m.get('message_type') != 0)
_previews=sum(1 for m in messages if m.get('media') and m.get('message_type') == 0)   # link-preview images
print('──────────── summary ────────────')
print(f'  messages    : {len(messages):,} total   ({_sent:,} sent / {len(messages)-_sent:,} received)')
print(f'  date range  : {(_d(min(_secs)) if _secs else "?")}  →  {(_d(max(_secs)) if _secs else "?")}')
print(f'  chats       : {len(_cset)}   ({len(_cset)-_grp} direct, {_grp} groups)')
print(f'  contacts    : {len(contacts):,}   ·   groups: {len(groups):,}   ·   chats(saved): {len(chats):,}')
print(f'  media msgs  : {_media:,}' + (f' (+{_previews:,} link-preview images)' if _previews else '')
      + f'   ·   reactions: {rx:,}   ·   calls: {len(_calls):,}')
print(f'  associations: {na:,} albums / HD video copies linked   ·   {nwa:,} as the browser recorded them (wawf_message_association)')
print('─────────────────────────────────')
print(f"  media       : {decrypted:,} file(s) from {blobs:,} cached blob(s)"
      + (f"; {len(byench):,} distinct media object(s) have keys" if byench else ""))
if byench and decrypted < len(byench) and os.environ.get("WAWF_FETCH_MEDIA") == "1":
    print("  [i] the rest were never cached by the browser; they are downloaded from WhatsApp's servers next")
elif byench and decrypted < len(byench):
    print("  [i] the rest were never cached by the browser (or the cache has since been evicted). Their "
          "mediaKeys ARE in message_media — fetch them by adding --fetch-media to the wawf run, or with:")
    print(f"      python3 scripts/mediafetch.py --db {mp} --profile <profile> --cdn")
    print("      NOTE each media url carries a SIGNATURE with its own expiry (the oe= parameter). While "
          "it is valid the CDN serves the object — about a month on a typical profile; once it lapses "
          "every request is 403 and only a re-upload request can refresh it "
          "(tools/reconnect/diag_media_retry.js).")
if _sn is None:
    print("  [!] cramjam not installed — Firefox's framed CacheStorage blobs cannot be decompressed, so "
          "media may undercount on Firefox profiles. pip install cramjam")
print(f"  Standard Android WhatsApp schema — open with any SQLite viewer, or ingest with a suite like WAInsight"
      f" (run_ingest.py --db-path {OUT} --extra-db wa.db={OUT}/wa.db --media-path {OUT}/Media).")
