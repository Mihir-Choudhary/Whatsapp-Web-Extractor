#!/usr/bin/env python3
"""build_anchors.py — Build anchors.json for the on-demand history extractor (tools/reconnect/
history_extract.js). For every chat it records the OLDEST message currently on disk (the point to
page backwards from) plus the set of all on-disk message key-ids (so recovered messages already on
disk can be filtered out). Works on Firefox (--origin) and Chromium (--profile).

  python3 scripts/build_anchors.py --profile <Chromium ...Default>  [--out anchors.json]
  python3 scripts/build_anchors.py --origin  <FF web.whatsapp.com dir> [--out anchors.json]
"""
import sys, os, json, glob, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _iter_messages(profile, origin):
    """Yield WhatsApp message objects (dicts) from either engine."""
    if profile and os.path.isdir(os.path.join(profile, 'IndexedDB')):
        import chromium_reader as cr
        for o in cr.load_source(profile)['idb'].get('model-storage', {}).get('message', []):
            if isinstance(o, dict): yield o
    else:
        import sqlite3
        from snappy_pure import uncompress
        from idbutil import store_id
        import sclone
        if not origin or not os.path.isdir(origin):
            sys.exit('ERROR: pass --profile <Chromium dir> or --origin <Firefox storage dir>')
        mm = glob.glob(f'{origin}/idb/*meogdaerlo*.sqlite')
        if not mm: sys.exit(f'ERROR: message-store IndexedDB (*meogdaerlo*.sqlite) not found under {origin}')
        con = sqlite3.connect(f'file:{mm[0]}?mode=ro&immutable=1', uri=True)
        sid = store_id(con, 'message')
        if sid is None: sys.exit("ERROR: 'message' store not found in Firefox model-storage")
        for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try:
                o = sclone.loads(uncompress(row))
                if isinstance(o, dict): yield o
            except Exception: continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
    ap.add_argument('--origin', help='Firefox web.whatsapp.com storage dir')
    ap.add_argument('--out', default='anchors.json')
    a = ap.parse_args()

    per = {}          # chat -> {chat, oldest_id, oldest_ts, oldest_fromMe}
    ondisk = set()    # all on-disk message key-ids (parts[2] of the WA id)
    cnt = {}          # chat -> on-disk message count (to order busiest-first)
    for o in _iter_messages(a.profile, a.origin):
        idv = o.get('id') or ''
        parts = idv.split('_')
        if len(parts) < 3: continue
        from_me, chat, keyid = parts[0] == 'true', parts[1], parts[2]
        ondisk.add(keyid); cnt[chat] = cnt.get(chat, 0) + 1
        if not (chat.endswith('@s.whatsapp.net') or chat.endswith('@g.us') or chat.endswith('@lid')):
            continue                                   # only real conversational chats can be paged
        try: t = int(o.get('t'))
        except (TypeError, ValueError): continue
        cur = per.get(chat)
        if cur is None or t < cur['oldest_ts']:
            per[chat] = {'chat': chat, 'oldest_id': keyid, 'oldest_ts': t, 'oldest_fromMe': from_me}

    anchors = sorted(per.values(), key=lambda x: -cnt.get(x['chat'], 0))   # busiest chats first
    json.dump({'anchors': anchors, 'ondisk_ids': sorted(ondisk)}, open(a.out, 'w', encoding='utf-8'))
    print(f"[+] anchors.json: {len(anchors)} chats, {len(ondisk)} on-disk message ids -> {a.out}")


if __name__ == '__main__':
    main()
