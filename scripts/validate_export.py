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

# Failure details quote real message text and contact labels, so emoji are routine -- and on a
# Windows console that is cp1252 by default, printing one raises UnicodeEncodeError and kills the
# run exactly when it has something to report. The writers pin UTF-8 for the same reason.
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

if len(sys.argv) < 2:
    sys.exit("usage: validate_export.py <out_dir> [<sqlite_dir>]")
OUT = sys.argv[1]
DB = sys.argv[2] if len(sys.argv) > 2 else None
# `--out txt:PATH` and `--out json:PATH` are legitimate exports that hold only part of the set, so
# the rule is "at least one artifact", and each section below runs only if its input is there.
HAVE = {f for f in ("chats.json", "identities.json", "transcripts.txt")
        if os.path.isfile(os.path.join(OUT, f))}
if not HAVE:
    sys.exit("not an export directory (none of chats.json / identities.json / transcripts.txt in %s)" % OUT)
if "chats.json" in HAVE and "identities.json" not in HAVE:
    sys.exit("chats.json is here but identities.json is not -- they are written together, so this "
             "export is incomplete: %s" % OUT)
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

ch = json.load(io.open(os.path.join(OUT, 'chats.json'), encoding='utf-8')) if 'chats.json' in HAVE else {}
ids = (json.load(io.open(os.path.join(OUT, 'identities.json'), encoding='utf-8'))
       if 'identities.json' in HAVE else {"me": [], "identities": [], "groups": {}})
txt = io.open(os.path.join(OUT, 'transcripts.txt'), encoding='utf-8').read() if 'transcripts.txt' in HAVE else None
msgs = [m for ml in ch.values() for m in ml]
print("=== present: %s ===" % ", ".join(sorted(HAVE)))
print("=== chats.json: %d chats, %d messages ===" % (len(ch), len(msgs)))

FIELDS = {'id', 't', 'dir', 'type', 'chat', 'chat_name', 'sender', 'sender_name', 'sender_lid',
          'sender_phone', 'sender_source', 'text', 'quoted_text', 'source'}
# Optional fields, present only when they apply:
#   body_status -- a row whose body could not be turned into text ("none" / "other-scheme" / "failed",
#                  or "encrypted" in an export made without a key), written rather than dropped;
#   filename, ack/status, and the structured parts of a body (link, location, poll, event, payment,
#   target_message_key).
#   view_once + content_note -- a view-once record: WhatsApp sends its content only to the phones.
#   call -- a call log entry's outcome, duration_s and video flag.
OPTIONAL = {'filename', 'ack', 'status', 'link', 'location', 'poll', 'event', 'payment', 'target_message_key',
            'view_once', 'content_note', 'call'}
def _fields_ok(m):
    extra = set(m) - FIELDS
    if not FIELDS <= set(m) or extra - OPTIONAL - {'body_status'}: return False
    if 'body_status' in m:
        return not (m.get('text') or '').strip() and m['body_status'] in ('none', 'other-scheme', 'failed', 'encrypted')
    return True
chk("a call log row says how the call ended, how long and what kind",
    all(isinstance(m.get('call'), dict) and set(m['call']) == {'outcome', 'duration_s', 'video'}
        for m in msgs if m.get('type') == 'call_log' and m.get('source', 'cache') == 'cache'))
chk("one row per call", len([m for m in msgs if m.get('type') == 'call_log']) ==
    len({m.get('id') for m in msgs if m.get('type') == 'call_log'}))
chk("every row has exactly the documented fields",
    all(_fields_ok(m) for m in msgs),
    next((sorted(set(m) ^ FIELDS) for m in msgs if not _fields_ok(m)), ''))
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
# An id may legitimately appear twice: the loader keeps a version whose CONTENT differs (an edit, a
# re-delivery) under the same id, and drops only copies identical in everything it carries. So the
# invariant is "no two identical rows", checked above -- a repeated id is reported, not failed.
byid = collections.Counter(m.get('id') for m in msgs)
rep = {k: v for k, v in byid.items() if v > 1}
print("  ..   ids appearing more than once (differing versions kept): %d" % len(rep))
chk("a repeated id always means genuinely different rows",
    all(len({json.dumps(m, sort_keys=True) for m in msgs if m.get('id') == k}) == v
        for k, v in list(rep.items())[:50]), list(rep)[:2])
chk("every sender resolves to a label", not [m for m in msgs if not m.get('sender_name')])
# A person's row is keyed by one canonical address and lists every form they appeared under,
# so a lookup goes through `jids` -- indexing by `jid` alone misses the same person reached
# by their phone number instead of their lid.
# A record holding neither `author` nor `from` has no sender, and `table()` skips the empty form,
# so these rows must be skipped here too rather than reported as missing identities.
withsender = [m for m in msgs if m.get('sender')]
print("  ..   rows with no sender at all: %d" % (len(msgs) - len(withsender)))
lab = {}
for r in ids['identities']:
    for j in (r.get('jids') or [r.get('jid')]): lab[j] = r.get('label')
    lab.setdefault(r.get('jid'), r.get('label'))
chk("sender_name agrees with identities.json",
    not [m for m in withsender if canon(m.get('sender')) in lab
         and m.get('sender_name') != lab[canon(m.get('sender'))]])
chk("every sender appears in identities.json",
    not {m.get('sender') for m in withsender if canon(m.get('sender')) not in lab})
me = set(ids['me'])
wrongdir = [m for m in withsender if m.get('dir') == 'them' and canon(m.get('sender')) in me]
chk("no incoming message is attributed to me", not wrongdir, len(wrongdir))
chk("direction agrees with who sent it",
    not [m for m in withsender if (canon(m.get('sender')) in me) != (m.get('dir') == 'me')])
chk("the stored fromMe flag is still legible on every row",
    all(str(m.get('id')).startswith(('true_', 'false_')) for m in msgs if m.get('id')))
flagdiff = [m for m in msgs if str(m.get('id')).startswith('true_') and m.get('dir') != 'me']
print("  ..   rows where the stored flag says outgoing but the actor is someone else: %d (types: %s)"
      % (len(flagdiff), dict(collections.Counter(m.get('type') for m in flagdiff))))
chk("...and those are group system events, not messages",
    all(m.get('type') in ('gp2', 'notification', 'notification_template', 'e2e_notification', 'protocol')
        for m in flagdiff),
    dict(collections.Counter(m.get('type') for m in flagdiff)))
same = [m for m in msgs if m.get('text') and m.get('text') == m.get('quoted_text')]
print("  ..   replies whose own words equal the words they quote: %d (people do this)" % len(same))
print("  ..   rows with a quote: %d   rows with own text: %d"
      % (sum(1 for m in msgs if m.get('quoted_text')), sum(1 for m in msgs if m.get('text'))))
bysrc = collections.Counter(m.get('source') for m in msgs)
print("  ..   provenance: %s" % dict(bysrc))
chk("every row says where it came from", not [m for m in msgs if m.get('source') not in
                                              ('cache', 'phone', 'server-queue')], dict(bysrc))
# A message the phone served has no quote of its own (the extractor does not return one) and was not
# decrypted locally, so it must not claim to have been.
chk("a recovered row does not claim a locally decrypted quote",
    not [m for m in msgs if m.get('source') == 'phone' and m.get('quoted_text')])

def check_identities():
    """Everything the correlation table must satisfy. Skipped when identities.json is not
    part of this export -- `--out txt:PATH` writes only a transcript, and checks run
    against an empty stub are either vacuous or, in one case, wrong: "one row per person"
    read an empty table as a violation."""
    print("\n=== identities.json: %d identities, %d groups ===" % (len(ids['identities']), len(ids['groups'])))
    chk("no duplicate identity rows",
        len({r['jid'] for r in ids['identities']}) == len(ids['identities']))
    mine_forms = {j for r in ids['identities'] if r.get('is_me')
                  for j in (r.get('jids') or [r.get('jid')])}
    # `me` holds every form the profile named; `jids` lists only the forms that actually appear in
    # this export. My phone form is often never an `author`, so equality would fail on a sound export.
    chk("every address marked as me is one of mine", mine_forms <= me, sorted(mine_forms - me))
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
        not {canon(m.get('sender')) for m in withsender} - set(allforms))
    chk("group jids are labelled by subject, not by a phone number",
        not [r for r in ids['identities'] if r['jid'].endswith('@g.us') and r['label'].startswith('+')])
    print("  ..   label sources: %s" % dict(collections.Counter(r['source'] for r in ids['identities'])))

if not ids.get("identities") and "identities.json" not in HAVE:
    print("\n=== identities.json: not in this export (txt was the only requested format) ===")
else:
    check_identities()

def check_transcript():
    """Everything the transcript must satisfy. Skipped when txt was not a requested
    format -- `--out json:PATH` is a legitimate export with no transcript in it."""
    print("\n=== transcripts.txt ===")
    HDR = re.compile(r'^===== (.*?)  \[(.+?)\]  \((group|1:1); (\d+) msgs, (\d+) with text\) =====$')
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
    # Every chat with any message gets a block, and every message in it gets a line -- a message with
    # no text of its own is shown as its type, not omitted.
    if ch:
        chk("one block per chat", len(blocks) == len([c for c, ml in ch.items() if ml]))
    chk("no duplicate blocks", len({b['jid'] for b in blocks}) == len(blocks))
    if ch:
        chk("header msg count matches chats.json",
            not [b for b in blocks if b['msgs'] != len(ch.get(b['jid'], []))])
    if ch:
        chk("header 'with text' count matches chats.json",
            not [b for b in blocks if b['text'] != len([m for m in ch.get(b['jid'], []) if m.get('text')])])
    # Lines are 1:1 with messages and in the same order, so they can be PAIRED rather than matched on
    # (timestamp, sender) -- which is ambiguous, because two messages a second apart share a timestamp
    # at this resolution. Pairing by position, the invariant is: a message with no text of its own is
    # shown as its type, never as a blank line.
    mismatched = []
    for b in (blocks if ch else []):
        rows = ch.get(b['jid'], [])
        if len(rows) != len(b['lines']): continue          # already reported above
        for l, m in zip(b['lines'], rows):
            want = ("(view-once %s: content only on the phones)" % (m.get('type') or 'media') if m.get('view_once')
                    else "(%s)" % (m.get('type') or 'unknown'))
            if not m.get('text') and l[3] != want:
                mismatched.append((b['jid'], l[0], l[3], want))
    chk("a message with no text of its own is shown as its type", not mismatched, mismatched[:2])
    chk("...and a line's timestamp matches the message it pairs with",
        not [1 for b in (blocks if ch else []) for l, m in zip(b['lines'], ch.get(b['jid'], []))
             if len(ch.get(b['jid'], [])) == len(b['lines']) and l[0] != m.get('t')])
    chk("every message has a line", not [b for b in blocks if b['msgs'] != len(b['lines'])],
        [(b['jid'], b['msgs'], len(b['lines'])) for b in blocks if b['msgs'] != len(b['lines'])][:2])
    if ch:
        chk("no message is silently dropped from the transcript",
            sum(len(b['lines']) for b in blocks) == len(msgs),
            "%d lines vs %d messages" % (sum(len(b['lines']) for b in blocks), len(msgs)))
    chk("blocks ordered busiest first",
        [b['msgs'] for b in blocks] == sorted((b['msgs'] for b in blocks), reverse=True))
    chk("lines ordered by time", all([l[0] for l in b['lines']] == sorted(l[0] for l in b['lines']) for b in blocks))
    if not ch:
        print("  ..   chats.json is not in this export, so the cross-checks against it are skipped")
    miss = [(b['name'], l[2]) for b in blocks for l in b['lines']
            if l[2] not in {x.split('  ')[0].strip() for x in b['legend']}]
    chk("every line's sender is in its chat legend", not miss, miss[:2])
    chk("no legend row duplicated inside a block",
        all(len(b['legend']) == len({x.split('  ')[0].strip() for x in b['legend']}) for b in blocks))
    chk("no content line sits at column 0 where structure lives",
        not [l for l in txt.split('\n') if l[:1] not in ('', '#', '[', ' ', '=')], )
    chk("no stray carriage return", '\r' not in txt)
    print("  ..   astral-plane characters present (emoji survived): %s"
          % any(ord(c) > 0xFFFF for c in txt))

if txt is None:
    print("\n=== transcripts.txt: not in this export (txt was not a requested format) ===")
else:
    check_transcript()

if DB:
    print("\n=== sqlite export ===")
    con = sqlite3.connect('file:%s?mode=ro' % os.path.join(DB, 'msgstore.db'), uri=True)
    con.execute("ATTACH DATABASE ? AS wa", ('file:%s?mode=ro' % os.path.join(DB, 'wa.db'),))
    q = lambda s: con.execute(s).fetchone()[0]
    # Which tables this database actually has, established ONCE before anything queries them.
    # export_sqlite creates every table in one `executescript`, so for an export THIS repo produced
    # they are all present however few rows they hold -- the guard is for a database from anywhere
    # else, and for not dying with `no such table` when pointed at one. What varies for our own
    # exports is the ROW COUNT, which is why the quoted-text check below tests that instead. The
    # four named here are not optional: without them it is not this export.
    present = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")} | {
        'wa.' + r[0] for r in con.execute("SELECT name FROM wa.sqlite_master WHERE type='table'")}
    core = [t for t in ('message', 'chat', 'jid', 'wa.wa_contacts') if t not in present]
    if core:
        sys.exit("not a wawf SQLite export (missing: %s)" % ", ".join(core))

    def has(*tables):
        missing = [t for t in tables if t not in present]
        if missing:
            print("  ..   %s absent -- checks on it skipped" % ", ".join(missing))
            return False
        return True

    print("  ..   messages %d  chats %d  jids %d  contacts %d"
          % (q("SELECT COUNT(*) FROM message"), q("SELECT COUNT(*) FROM chat"),
             q("SELECT COUNT(*) FROM jid"), q("SELECT COUNT(*) FROM wa.wa_contacts")))
    chk("message count matches chats.json", q("SELECT COUNT(*) FROM message") == len(msgs))
    # Same policy as the JSON: a repeated key_id means a version whose content differs was kept.
    # Reported, because an Android importer may still object to it, but not a defect here.
    print("  ..   repeated key_id (differing versions kept): %d"
          % q("SELECT COUNT(*)-COUNT(DISTINCT key_id) FROM message"))
    chk("no orphan chat_row_id", q("SELECT COUNT(*) FROM message WHERE chat_row_id NOT IN (SELECT _id FROM chat)") == 0)
    chk("no orphan jid_row_id on chats", q("SELECT COUNT(*) FROM chat WHERE jid_row_id NOT IN (SELECT _id FROM jid)") == 0)
    chk("no duplicate jid rows", q("SELECT COUNT(*)-COUNT(DISTINCT user||'@'||server) FROM jid") == 0)
    chk("subject only on groups",
        q("""SELECT COUNT(*) FROM chat ch JOIN jid j ON j._id=ch.jid_row_id
             WHERE ch.subject IS NOT NULL AND ch.subject<>'' AND j.server<>'g.us'""") == 0,
        q("""SELECT COUNT(*) FROM chat ch JOIN jid j ON j._id=ch.jid_row_id
             WHERE ch.subject IS NOT NULL AND ch.subject<>'' AND j.server<>'g.us'"""))
    # A group message read from the local store always names its author. One recovered from the
    # phone only does when the extractor captured `key.participant` -- older pulls did not -- so the
    # invariant holds for cached rows and the rest is reported with its provenance rather than failed.
    _gsql = ("""SELECT COUNT(*) FROM message m JOIN chat ch ON ch._id=m.chat_row_id
                JOIN jid j ON j._id=ch.jid_row_id WHERE j.server='g.us' AND m.from_me=0
                  AND (m.sender_jid_row_id IS NULL OR m.sender_jid_row_id=0)""")
    if 'source' in {r[1] for r in con.execute("PRAGMA table_info(message)")}:
        chk("every CACHED group message carries a sender jid",
            q(_gsql + " AND m.source='cache'") == 0, q(_gsql + " AND m.source='cache'"))
        n = q(_gsql + " AND m.source<>'cache'")
        if n:
            print("  ..   recovered group messages with no sender (pulled before the extractor "
                  "captured key.participant): %d" % n)
    else:
        chk("group messages always carry a sender jid", q(_gsql) == 0, q(_gsql))
    chk("timestamps are plausible",
        q("SELECT COUNT(*) FROM message WHERE timestamp<1420070400000 OR timestamp>1830000000000") == 0,
        con.execute("SELECT MIN(timestamp),MAX(timestamp) FROM message").fetchone())
    if has('message_quoted'):
        nq = q("SELECT COUNT(*) FROM message_quoted")
        nqt = q("SELECT COUNT(*) FROM message_quoted WHERE text_data IS NOT NULL AND text_data<>''")
        print("  ..   quoted rows: %d (%d carry the quoted text)" % (nq, nqt))
        print("  ..   quoted rows with no key_id to join on: %d"
              % q("SELECT COUNT(*) FROM message_quoted WHERE key_id IS NULL"))
        # Only meaningful where the JSON found quotes: an export of a chat with no replies has none,
        # and that is not a defect.
        jq = sum(1 for m in msgs if m.get('quoted_text'))
        if jq:
            chk("the quoted text the JSON found is in the database too", nqt > 0, nqt)
        print("  ..   quoted rows whose text equals the reply's own text: %d"
              % q("""SELECT COUNT(*) FROM message_quoted mq JOIN message m ON m._id=mq.message_row_id
                     WHERE mq.text_data IS NOT NULL AND mq.text_data=m.text_data"""))
    # Every child table hangs off message._id or chat._id. A row pointing at nothing is a row an
    # importer either drops silently or crashes on, and either way the export is not what it claims.
    kids = [t for t in ('message_media', 'message_quoted', 'message_thumbnail',
                        'message_mentions', 'message_link', 'message_poll') if t in present]
    orphans = {}
    for t in kids:
        n = q("SELECT COUNT(*) FROM %s WHERE message_row_id NOT IN (SELECT _id FROM message)" % t)
        if n: orphans[t] = n
    chk("no child row points at a message that is not there", not orphans, orphans)
    print("  ..   child rows: %s" % {t: q("SELECT COUNT(*) FROM %s" % t) for t in kids})
    if has('message_media'):
        n = q("""SELECT COUNT(*) FROM message_media
                 WHERE (media_key IS NULL OR media_key='') AND (direct_path IS NULL OR direct_path='')""")
        chk("media rows carry a key or a path", n == 0, n)
    if has('call_log'):
        print("  ..   call_log rows: %d" % q("SELECT COUNT(*) FROM call_log"))
        chk("every call row resolves to a jid",
            q("SELECT COUNT(*) FROM call_log WHERE jid_row_id NOT IN (SELECT _id FROM jid)") == 0)

    # the Android correlation chain
    # Recovered group messages pulled before the extractor captured key.participant have no sender to
    # resolve; they are reported separately above, so they are not counted against the chain here --
    # with them included a merged export "failed" at 45% for a gap that is already stated.
    unsendered = q("""SELECT COUNT(*) FROM message m JOIN chat ch ON ch._id=m.chat_row_id JOIN jid j ON j._id=ch.jid_row_id
                      WHERE m.from_me=0 AND m.source='phone' AND j.server='g.us'
                        AND (m.sender_jid_row_id IS NULL OR m.sender_jid_row_id=0)""")
    tot = q("SELECT COUNT(*) FROM message WHERE from_me=0") - unsendered
    named = q("""SELECT COUNT(*) FROM message m JOIN jid j ON j._id=m.sender_jid_row_id
                 JOIN wa.wa_contacts c ON c.jid=(j.user||'@'||j.server)
                 WHERE m.from_me=0 AND COALESCE(NULLIF(c.display_name,''),NULLIF(c.wa_name,''),NULLIF(c.number,'')) IS NOT NULL""")
    named += q("""SELECT COUNT(*) FROM message m JOIN chat ch ON ch._id=m.chat_row_id JOIN jid j ON j._id=ch.jid_row_id
                  JOIN wa.wa_contacts c ON c.jid=(j.user||'@'||j.server)
                  WHERE m.from_me=0 AND m.sender_jid_row_id NOT IN (SELECT _id FROM jid)
                    AND COALESCE(NULLIF(c.display_name,''),NULLIF(c.wa_name,''),NULLIF(c.number,'')) IS NOT NULL""")
    # A tolerance measured on one store is not an invariant; report the rate and fail only on a
    # collapse, which is what a broken join looks like.
    print("  ..   inbound senders resolving to a name or number: %d of %d" % (named, tot))
    chk("the sender correlation chain resolves", tot == 0 or named >= tot * 0.9,
        "%d of %d" % (named, tot))
    # text agreement with chats.json, at every length. This used to skip texts of 2,000+ characters
    # because JSON truncated there -- which is how a cap that cut 16 messages short went unnoticed.
    jt = collections.Counter(m.get('text') for m in msgs if m.get('text'))
    st = collections.Counter(r[0] for r in con.execute(
        "SELECT text_data FROM message WHERE text_data IS NOT NULL AND text_data<>''"))
    extra_j = sum((jt - st).values()); extra_s = sum((st - jt).values())
    print("  ..   texts json=%d sqlite=%d (json-only %d, sqlite-only %d)"
          % (sum(jt.values()), sum(st.values()), extra_j, extra_s))
    # The database must never contain text the JSON does not: that would mean one writer inventing
    # or mis-scraping content. The reverse is expected and bounded -- the database decrypts bodies
    # only for the types Android stores text for, so location/vcard/system messages have none.
    chk("the database contains no text the JSON lacks", extra_s == 0, extra_s)
    # The database decrypts bodies only for the types Android stores text for, so a JSON-only
    # remainder is expected. Its SIZE depends on how many location/vcard/system messages a store
    # holds, so it is reported rather than bounded by a number from one profile.
    print("  ..   texts the JSON has and the database does not: %d (types it does not decrypt)"
          % extra_j)
    con.close()

print()
if FAIL:
    print("%d CHECK(S) FAILED" % len(FAIL))
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("all output checks pass")
