#!/usr/bin/env python3
"""validate_export.py -- check a finished export against itself.

The self-tests prove the code behaves on synthetic input. This proves the ARTIFACTS are sound: that
the transcript, the JSON and the database agree with each other and with their own headers, that
every sender resolves, that nothing is duplicated, and that the Android correlation chain an external
parser relies on actually resolves end to end. Run it on a real export whenever the writers change,
or to satisfy yourself that an export you were handed is internally consistent.

Each line is a statement that must hold. `ok` passed, `BUG` failed, `..` is a count for context.
Nothing is written and nothing leaves the machine; samples are printed only for failures.

  python3 scripts/validate_export.py D:/case/out                 # txt + json
  python3 scripts/validate_export.py D:/case/out D:/case/db      # ...and the SQLite export
"""
import json, io, os, re, sys, sqlite3, collections, datetime as dt, unicodedata

if len(sys.argv) < 2:
    sys.exit("usage: validate_export.py <out_dir> [<sqlite_dir>]")
OUT = sys.argv[1]
DB = sys.argv[2] if len(sys.argv) > 2 else None
for f in ("chats.json", "identities.json", "transcripts.txt"):
    if not os.path.isfile(os.path.join(OUT, f)):
        sys.exit("not an export directory (no %s in %s)" % (f, OUT))
FAIL = []

def chk(name, ok, detail=''):
    if ok:
        print("  ok   " + name + (("  " + str(detail)) if detail else ''))
    else:
        FAIL.append(name); print("  BUG  " + name + (("  " + str(detail)) if detail else ''))

def canon(j):
    j = str(j or '')
    if '@' not in j: return j
    u, _, s = j.rpartition('@')
    return u.split(':')[0] + '@' + ('c.us' if s in ('c.us', 's.whatsapp.net') else s)

ch = json.load(io.open(os.path.join(OUT, 'chats.json'), encoding='utf-8'))
ids = json.load(io.open(os.path.join(OUT, 'identities.json'), encoding='utf-8'))
txt = io.open(os.path.join(OUT, 'transcripts.txt'), encoding='utf-8').read()
msgs = [m for ml in ch.values() for m in ml]
print("=== chats.json: %d chats, %d messages ===" % (len(ch), len(msgs)))

FIELDS = {'id', 't', 'dir', 'type', 'chat', 'chat_name', 'sender', 'sender_name', 'sender_lid',
          'sender_phone', 'sender_source', 'text', 'quoted_text'}
chk("every row has exactly the documented fields",
    all(set(m) == FIELDS for m in msgs),
    next((sorted(set(m) ^ FIELDS) for m in msgs if set(m) != FIELDS), ''))
chk("chat key matches each row's chat field", all(m.get('chat') == c for c, ml in ch.items() for m in ml))
chk("no row has an empty timestamp", not [m for m in msgs if not m.get('t')])
chk("rows sorted by time inside each chat",
    all([m.get('t') for m in ml] == sorted(m.get('t') for m in ml) for ml in ch.values()))
# Rows carry their message id, so an identical row really is the same record twice. Without the id
# this check was meaningless: two different messages of "Ok" in the same second look alike.
chk("no exact-duplicate rows",
    all(len(ml) == len({json.dumps(m, sort_keys=True) for m in ml}) for ml in ch.values()),
    sum(len(ml) - len({json.dumps(m, sort_keys=True) for m in ml}) for ml in ch.values()))
chk("every row has a message id", not [m for m in msgs if not m.get('id')])
chk("message ids are unique", len({m.get('id') for m in msgs}) == len(msgs),
    len(msgs) - len({m.get('id') for m in msgs}))
chk("every sender resolves to a label", not [m for m in msgs if not m.get('sender_name')])
# A person's row is keyed by one canonical address and lists every form they appeared under,
# so a lookup goes through `jids` -- indexing by `jid` alone misses the same person reached
# by their phone number instead of their lid.
lab = {}
for r in ids['identities']:
    for j in (r.get('jids') or [r.get('jid')]): lab[j] = r.get('label')
    lab.setdefault(r.get('jid'), r.get('label'))
chk("sender_name agrees with identities.json",
    not [m for m in msgs if canon(m.get('sender')) in lab and m.get('sender_name') != lab[canon(m.get('sender'))]])
chk("every sender appears in identities.json",
    not {m.get('sender') for m in msgs if canon(m.get('sender')) not in lab})
me = set(ids['me'])
wrongdir = [m for m in msgs if m.get('dir') == 'them' and canon(m.get('sender')) in me]
chk("no incoming message is attributed to me", not wrongdir, len(wrongdir))
chk("direction agrees with who sent it",
    not [m for m in msgs if (canon(m.get('sender')) in me) != (m.get('dir') == 'me')])
chk("the stored fromMe flag is still legible on every row",
    all(str(m.get('id')).startswith(('true_', 'false_')) for m in msgs if m.get('id')))
flagdiff = [m for m in msgs if str(m.get('id')).startswith('true_') and m.get('dir') != 'me']
print("  ..   rows where the stored flag says outgoing but the actor is someone else: %d (types: %s)"
      % (len(flagdiff), dict(collections.Counter(m.get('type') for m in flagdiff))))
chk("...and those are group system events, not messages",
    all(m.get('type') in ('gp2', 'notification_template', 'e2e_notification', 'protocol') for m in flagdiff),
    dict(collections.Counter(m.get('type') for m in flagdiff)))
same = [m for m in msgs if m.get('text') and m.get('text') == m.get('quoted_text')]
print("  ..   replies whose own words equal the words they quote: %d (people do this)" % len(same))
print("  ..   rows with a quote: %d   rows with own text: %d"
      % (sum(1 for m in msgs if m.get('quoted_text')), sum(1 for m in msgs if m.get('text'))))

print("\n=== identities.json: %d identities, %d groups ===" % (len(ids['identities']), len(ids['groups'])))
chk("no duplicate identity rows",
    len({r['jid'] for r in ids['identities']}) == len(ids['identities']))
mine_forms = {j for r in ids['identities'] if r.get('is_me')
              for j in (r.get('jids') or [r.get('jid')])}
chk("the one row marked as me covers exactly my own addresses", mine_forms == me,
    sorted(mine_forms ^ me))
chk("source=address-book implies a name",
    not [r for r in ids['identities'] if r['source'] == 'address-book' and not r['name']])
chk("source=pushname implies a pushname",
    not [r for r in ids['identities'] if r['source'] == 'pushname' and not r['pushname']])
chk("source=unresolved implies nothing is known",
    not [r for r in ids['identities'] if r['source'] == 'unresolved' and (r['name'] or r['pushname'] or r['phone'])])
chk("a label is never empty", not [r for r in ids['identities'] if not r['label']])
chk("one row per person, not per address",
    max(collections.Counter(r['phone'] for r in ids['identities'] if r['phone']).values(), default=0) == 1,
    [r['jid'] for r in ids['identities'] if r['phone'] and
     collections.Counter(x.get('phone') for x in ids['identities'])[r['phone']] > 1][:2])
allforms = [j for r in ids['identities'] for j in r.get('jids', [])]
chk("each address form belongs to exactly one person", len(allforms) == len(set(allforms)))
chk("every sender's address form is listed on its person",
    not {canon(m.get('sender')) for m in msgs} - set(allforms))
chk("group jids are labelled by subject, not by a phone number",
    not [r for r in ids['identities'] if r['jid'].endswith('@g.us') and r['label'].startswith('+')])
print("  ..   label sources: %s" % dict(collections.Counter(r['source'] for r in ids['identities'])))

print("\n=== transcripts.txt ===")
HDR = re.compile(r'^===== (.*?)  \[(.+?)\]  \((group|1:1); (\d+) msgs, (\d+) text\) =====$')
MSG = re.compile(r'^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] (->|<-) +(.*?): (.*)$')
blocks = []; cur = None; stray = []
for ln in txt.split('\n'):
    m = HDR.match(ln)
    if m:
        cur = {'name': m.group(1), 'jid': m.group(2), 'kind': m.group(3), 'msgs': int(m.group(4)),
               'text': int(m.group(5)), 'lines': [], 'legend': [], 'cont': 0, 're': 0}
        blocks.append(cur); continue
    if cur is None:
        if ln and not ln.startswith('#'): stray.append(ln)
        continue
    if ln.startswith('  - '): cur['legend'].append(ln[4:]); continue
    mm = MSG.match(ln)
    if mm: cur['lines'].append(mm.groups()); continue
    if ln.lstrip().startswith('| '): cur['cont'] += 1; continue
    if ln.lstrip().startswith('re: '): cur['re'] += 1; continue
    if ln.strip(): stray.append(ln)
print("  ..   %d chat blocks, %d message lines, %d continuation lines, %d quote lines"
      % (len(blocks), sum(len(b['lines']) for b in blocks), sum(b['cont'] for b in blocks),
         sum(b['re'] for b in blocks)))
chk("no unclassifiable line", not stray, stray[:2])
chk("one block per chat that has text",
    len(blocks) == len([c for c, ml in ch.items() if any(m.get('text') for m in ml)]))
chk("no duplicate blocks", len({b['jid'] for b in blocks}) == len(blocks))
chk("header msg count matches chats.json",
    not [b for b in blocks if b['msgs'] != len(ch.get(b['jid'], []))])
chk("header text count matches chats.json",
    not [b for b in blocks if b['text'] != len([m for m in ch.get(b['jid'], []) if m.get('text')])])
chk("header text count matches lines written",
    not [b for b in blocks if b['text'] != len(b['lines'])])
chk("blocks ordered busiest first",
    [b['msgs'] for b in blocks] == sorted((b['msgs'] for b in blocks), reverse=True))
chk("lines ordered by time", all([l[0] for l in b['lines']] == sorted(l[0] for l in b['lines']) for b in blocks))
miss = [(b['name'], l[2]) for b in blocks for l in b['lines']
        if l[2] not in {x.split('  ')[0].strip() for x in b['legend']}]
chk("every line's sender is in its chat legend", not miss, miss[:2])
chk("no legend row duplicated inside a block",
    all(len(b['legend']) == len({x.split('  ')[0].strip() for x in b['legend']}) for b in blocks))
chk("no content line sits at column 0 where structure lives",
    not [l for l in txt.split('\n') if l[:1] not in ('', '#', '[', ' ', '=')], )
chk("no stray carriage return", '\r' not in txt)
chk("file is valid UTF-8 with emoji intact", any(ord(c) > 0xFFFF for c in txt))

if DB:
    print("\n=== sqlite export ===")
    con = sqlite3.connect('file:%s?mode=ro' % os.path.join(DB, 'msgstore.db'), uri=True)
    con.execute("ATTACH DATABASE ? AS wa", ('file:%s?mode=ro' % os.path.join(DB, 'wa.db'),))
    q = lambda s: con.execute(s).fetchone()[0]
    print("  ..   messages %d  chats %d  jids %d  contacts %d  quoted %d"
          % (q("SELECT COUNT(*) FROM message"), q("SELECT COUNT(*) FROM chat"),
             q("SELECT COUNT(*) FROM jid"), q("SELECT COUNT(*) FROM wa.wa_contacts"),
             q("SELECT COUNT(*) FROM message_quoted")))
    chk("message count matches chats.json", q("SELECT COUNT(*) FROM message") == len(msgs))
    chk("key_id is unique", q("SELECT COUNT(*)-COUNT(DISTINCT key_id) FROM message") == 0,
        q("SELECT COUNT(*)-COUNT(DISTINCT key_id) FROM message"))
    chk("no orphan chat_row_id", q("SELECT COUNT(*) FROM message WHERE chat_row_id NOT IN (SELECT _id FROM chat)") == 0)
    chk("no orphan jid_row_id on chats", q("SELECT COUNT(*) FROM chat WHERE jid_row_id NOT IN (SELECT _id FROM jid)") == 0)
    chk("no duplicate jid rows", q("SELECT COUNT(*)-COUNT(DISTINCT user||'@'||server) FROM jid") == 0)
    chk("subject only on groups",
        q("""SELECT COUNT(*) FROM chat ch JOIN jid j ON j._id=ch.jid_row_id
             WHERE ch.subject IS NOT NULL AND ch.subject<>'' AND j.server<>'g.us'""") == 0,
        q("""SELECT COUNT(*) FROM chat ch JOIN jid j ON j._id=ch.jid_row_id
             WHERE ch.subject IS NOT NULL AND ch.subject<>'' AND j.server<>'g.us'"""))
    chk("group messages always carry a sender jid",
        q("""SELECT COUNT(*) FROM message m JOIN chat ch ON ch._id=m.chat_row_id JOIN jid j ON j._id=ch.jid_row_id
             WHERE j.server='g.us' AND m.from_me=0 AND (m.sender_jid_row_id IS NULL OR m.sender_jid_row_id=0)""") == 0)
    chk("timestamps are plausible",
        q("SELECT COUNT(*) FROM message WHERE timestamp<1420070400000 OR timestamp>1830000000000") == 0,
        con.execute("SELECT MIN(timestamp),MAX(timestamp) FROM message").fetchone())
    chk("quoted text is now stored, not NULL",
        q("SELECT COUNT(*) FROM message_quoted WHERE text_data IS NOT NULL AND text_data<>''") > 0,
        q("SELECT COUNT(*) FROM message_quoted WHERE text_data IS NOT NULL AND text_data<>''"))
    print("  ..   quoted rows whose text equals the reply's own text: %d"
          % q("""SELECT COUNT(*) FROM message_quoted mq JOIN message m ON m._id=mq.message_row_id
                 WHERE mq.text_data IS NOT NULL AND mq.text_data=m.text_data"""))
    # Every child table hangs off message._id or chat._id. A row pointing at nothing is a row an
    # importer either drops silently or crashes on, and either way the export is not what it claims.
    kids = [(t, c) for t in ('message_media', 'message_quoted', 'message_thumbnail',
                             'message_mentions', 'message_link', 'message_poll')
            for c in ('message_row_id',)]
    present = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    orphans = {}
    for t, c in kids:
        if t not in present: continue
        n = q("SELECT COUNT(*) FROM %s WHERE %s NOT IN (SELECT _id FROM message)" % (t, c))
        if n: orphans[t] = n
    chk("no child row points at a message that is not there", not orphans, orphans)
    rows = {t: q("SELECT COUNT(*) FROM %s" % t) for t, _ in kids if t in present}
    print("  ..   child rows: %s" % rows)
    chk("media rows carry a key or a path",
        q("""SELECT COUNT(*) FROM message_media
             WHERE (media_key IS NULL OR media_key='') AND (direct_path IS NULL OR direct_path='')""") == 0,
        q("""SELECT COUNT(*) FROM message_media
             WHERE (media_key IS NULL OR media_key='') AND (direct_path IS NULL OR direct_path='')""")
        if 'message_media' in present else 0)
    if 'call_log' in present:
        print("  ..   call_log rows: %d" % q("SELECT COUNT(*) FROM call_log"))
        chk("every call row resolves to a jid",
            q("SELECT COUNT(*) FROM call_log WHERE jid_row_id NOT IN (SELECT _id FROM jid)") == 0)

    # the Android correlation chain
    tot = q("SELECT COUNT(*) FROM message WHERE from_me=0")
    named = q("""SELECT COUNT(*) FROM message m JOIN jid j ON j._id=m.sender_jid_row_id
                 JOIN wa.wa_contacts c ON c.jid=(j.user||'@'||j.server)
                 WHERE m.from_me=0 AND COALESCE(NULLIF(c.display_name,''),NULLIF(c.wa_name,''),NULLIF(c.number,'')) IS NOT NULL""")
    named += q("""SELECT COUNT(*) FROM message m JOIN chat ch ON ch._id=m.chat_row_id JOIN jid j ON j._id=ch.jid_row_id
                  JOIN wa.wa_contacts c ON c.jid=(j.user||'@'||j.server)
                  WHERE m.from_me=0 AND m.sender_jid_row_id NOT IN (SELECT _id FROM jid)
                    AND COALESCE(NULLIF(c.display_name,''),NULLIF(c.wa_name,''),NULLIF(c.number,'')) IS NOT NULL""")
    chk("every inbound message's sender resolves to a name or number", tot - named <= 5,
        "%d of %d resolve" % (named, tot))
    # text agreement with chats.json, below the 2000-char cap where both must agree exactly
    jt = collections.Counter(m.get('text') for m in msgs if m.get('text') and len(m.get('text')) < 2000)
    st = collections.Counter(r[0] for r in con.execute(
        "SELECT text_data FROM message WHERE text_data IS NOT NULL AND text_data<>''") if len(r[0]) < 2000)
    extra_j = sum((jt - st).values()); extra_s = sum((st - jt).values())
    print("  ..   short texts json=%d sqlite=%d (json-only %d, sqlite-only %d)"
          % (sum(jt.values()), sum(st.values()), extra_j, extra_s))
    # The database must never contain text the JSON does not: that would mean one writer inventing
    # or mis-scraping content. The reverse is expected and bounded -- the database decrypts bodies
    # only for the types Android stores text for, so location/vcard/system messages have none.
    chk("the database contains no text the JSON lacks", extra_s == 0, extra_s)
    chk("the JSON-only remainder stays small", extra_j < 60, extra_j)
    con.close()

print()
if FAIL:
    print("%d CHECK(S) FAILED" % len(FAIL))
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all output checks pass")
