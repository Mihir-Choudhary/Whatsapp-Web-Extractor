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


def _iter_chats(profile, origin):
    """Yield WhatsApp chat records (dicts) from either engine."""
    if profile and os.path.isdir(os.path.join(profile, 'IndexedDB')):
        import chromium_reader as cr
        for o in cr.load_source(profile)['idb'].get('model-storage', {}).get('chat', []):
            if isinstance(o, dict): yield o
    else:
        import sqlite3
        from snappy_pure import uncompress
        from idbutil import store_id
        import sclone
        mm = glob.glob(f'{origin}/idb/*meogdaerlo*.sqlite') if origin else []
        if not mm: return
        con = sqlite3.connect(f'file:{mm[0]}?mode=ro&immutable=1', uri=True)
        sid = store_id(con, 'chat')
        if sid is None: return
        for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try:
                o = sclone.loads(uncompress(row))
                if isinstance(o, dict): yield o
            except Exception: continue


def _history_jid_map(profile, origin):
    """chat id -> the jid WhatsApp Web actually puts in HistorySyncOnDemandRequest.chatJid.

    Read out of WhatsApp Web's own code: the request is built with

        const r = chatRecord.historyChatId != null ? createWid(chatRecord.historyChatId).toJid()
                                                   : CHAT_JID(chatId).toString();

    i.e. a chat carries a SEPARATE `historyChatId` for history purposes, and when it is set that is
    the jid the primary expects. On a LID-migrated account the chat id is `<lid>@lid` while
    historyChatId is the phone form `<number>@c.us`, so asking by chat id names a chat the phone
    cannot resolve and the request is simply never answered. Observed on a real profile: 134 of 310
    chats had a historyChatId and it differed from the chat id in every single case (all @lid -> @c.us).
    Group chats have none, which is why groups behaved differently from one-to-one chats throughout.
    """
    out = {}
    for c in _iter_chats(profile, origin):
        cid, hid = c.get('id'), c.get('historyChatId')
        if cid and hid and str(hid) != str(cid):
            out[str(cid)] = str(hid)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
    ap.add_argument('--origin', help='Firefox web.whatsapp.com storage dir')
    ap.add_argument('--out', default='anchors.json')
    a = ap.parse_args()

    histjid = _history_jid_map(a.profile, a.origin)

    per = {}          # chat id -> {chat, chat_id, oldest_id, oldest_ts, oldest_fromMe}
    ondisk = set()    # all on-disk message key-ids (parts[2] of the WA id)
    cnt = {}          # chat id -> on-disk message count (to order busiest-first)
    for o in _iter_messages(a.profile, a.origin):
        idv = o.get('id') or ''
        parts = idv.split('_')
        if len(parts) < 3: continue
        from_me, chat, keyid = parts[0] == 'true', parts[1], parts[2]
        ondisk.add(keyid); cnt[chat] = cnt.get(chat, 0) + 1
        # @c.us belongs here too: it is the phone form WhatsApp Web uses for history, and leaving it
        # out silently dropped those chats from the anchor list entirely.
        if not chat.endswith(('@s.whatsapp.net', '@g.us', '@lid', '@c.us')):
            continue                                   # only real conversational chats can be paged
        try: t = int(o.get('t'))
        except (TypeError, ValueError): continue
        cur = per.get(chat)
        if cur is None or t < cur['oldest_ts']:
            per[chat] = {'chat': histjid.get(chat, chat),   # what to ASK for
                         'chat_id': chat,                   # the local chat id, for reference
                         'oldest_id': keyid, 'oldest_ts': t, 'oldest_fromMe': from_me}

    anchors = sorted(per.values(), key=lambda x: -cnt.get(x['chat_id'], 0))   # busiest chats first
    json.dump({'anchors': anchors, 'ondisk_ids': sorted(ondisk)}, open(a.out, 'w', encoding='utf-8'))
    remapped = sum(1 for x in anchors if x['chat'] != x['chat_id'])
    print(f"[+] anchors.json: {len(anchors)} chats, {len(ondisk)} on-disk message ids -> {a.out}")
    print(f"    {remapped} chat(s) asked for by their historyChatId rather than their chat id "
          f"(this is what WhatsApp Web sends; asking by chat id goes unanswered)")


if __name__ == '__main__':
    main()
