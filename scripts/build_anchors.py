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
from wa_decrypt import receipt_only as _receipt_only


def _chromium(profile):
    """A Chromium source, by chromium_reader's one definition: a legacy IndexedDB folder, the WebStorage
    layout newer builds use, or stores given on their own (--idb/--local-storage). Testing for an
    `IndexedDB` folder alone sent the last two down the Firefox path, which then exited asking for
    --origin -- so --history stopped at its third step for them."""
    if not profile: return False
    import chromium_reader as cr
    return cr.is_chromium_profile(profile)


def _iter_messages(profile, origin):
    """Yield WhatsApp message objects (dicts) from either engine."""
    if _chromium(profile):
        import chromium_reader as cr
        for o in cr.load_source(profile)['idb'].get('model-storage', {}).get('message', []):
            if isinstance(o, dict): yield o
    else:
        from snappy_pure import uncompress
        from idbutil import store_id, connect_ro
        import sclone
        if not origin or not os.path.isdir(origin):
            sys.exit('ERROR: pass --profile <Chromium dir> or --origin <Firefox storage dir>')
        mm = glob.glob(f'{glob.escape(origin)}/idb/*meogdaerlo*.sqlite')
        if not mm: sys.exit(f'ERROR: message-store IndexedDB (*meogdaerlo*.sqlite) not found under {origin}')
        con = connect_ro(mm[0])
        sid = store_id(con, 'message')
        if sid is None: sys.exit("ERROR: 'message' store not found in Firefox model-storage")
        for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try:
                o = sclone.loads(uncompress(row))
                if isinstance(o, dict): yield o
            except Exception: continue


def _iter_chats(profile, origin):
    """Yield WhatsApp chat records (dicts) from either engine."""
    if _chromium(profile):
        import chromium_reader as cr
        for o in cr.load_source(profile)['idb'].get('model-storage', {}).get('chat', []):
            if isinstance(o, dict): yield o
    else:
        from snappy_pure import uncompress
        from idbutil import store_id, connect_ro
        import sclone
        mm = glob.glob(f'{glob.escape(origin)}/idb/*meogdaerlo*.sqlite') if origin else []
        if not mm: return
        con = connect_ro(mm[0])
        sid = store_id(con, 'chat')
        if sid is None: return
        for (row,) in con.execute("SELECT data FROM object_data WHERE object_store_id=?", (sid,)):
            try:
                o = sclone.loads(uncompress(row))
                if isinstance(o, dict): yield o
            except Exception: continue


def _to_jid(wid):
    """Wid.toJid() -- read out of WhatsApp Web's own Wid class:

        toString(t) { var r = (t.legacy && this.server === "c.us") ? "s.whatsapp.net" : this.server; ... }
        toJid()     { return this.toString({legacy: true}); }

    so a wid whose server is `c.us` serialises to `<user>@s.whatsapp.net` on the wire, and every
    other server passes through unchanged. `historyChatId` is stored in the `@c.us` form but the
    request carries `createWid(historyChatId).toJid()`, i.e. the `@s.whatsapp.net` form. Sending the
    stored `@c.us` form names a jid WhatsApp Web never sends.

    Confirmed independently against `history_initial_sync_boundry`, which WhatsApp Web keys with the
    same expression: of 132 chats carrying a historyChatId, the `@s.whatsapp.net` form matched a
    boundary key 132/132 and the raw `@c.us` form 0/132.
    """
    w = str(wid)
    return w.rsplit('@', 1)[0] + '@s.whatsapp.net' if w.endswith('@c.us') else w


# endOfHistoryTransferType -> does the primary still hold older messages for this chat?
# WAWebChatConstants.ConversationEndOfHistoryTransferModelPropType, and the truth table of
# WAWebHistorySyncUtils.primaryHasMoreMessagesReadyToLoad():
_MORE_ON_PRIMARY = {
    0: True,    # COMPLETE_BUT_MORE_MESSAGES_REMAIN_ON_PRIMARY
    1: False,   # COMPLETE_AND_NO_MORE_MESSAGE_REMAIN_ON_PRIMARY
    2: False,   # INCOMPLETE
    3: True,    # NOT_INCLUDED_IN_HIST_SYNC
    4: True,    # COMPLETE_ON_DEMAND_SYNC_BUT_MORE_MSG_REMAIN_ON_PRIMARY
    5: True,    # COMPLETE_ON_DEMAND_SYNC_WITH_MORE_MSG_ON_PRIMARY_BUT_NO_ACCESS
}


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
    out, more = {}, {}
    for c in _iter_chats(profile, origin):
        cid, hid = c.get('id'), c.get('historyChatId')
        if not cid:
            continue
        if hid and _to_jid(hid) != str(cid):
            out[str(cid)] = _to_jid(hid)         # the wire form, not the stored @c.us form
        more[str(cid)] = _MORE_ON_PRIMARY.get(c.get('endOfHistoryTransferType'), True)
    return out, more


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
    ap.add_argument('--origin', help='Firefox web.whatsapp.com storage dir')
    ap.add_argument('--out', default='anchors.json')
    ap.add_argument('--all-chats', action='store_true',
                    help="also page chats whose endOfHistoryTransferType says the primary holds "
                         "nothing older (WhatsApp Web would not ask for these)")
    a = ap.parse_args()

    histjid, more_on_primary = _history_jid_map(a.profile, a.origin)

    per = {}          # chat id -> {chat, chat_id, oldest_id, oldest_ts, oldest_fromMe}
    ondisk = set()    # all on-disk message key-ids (parts[2] of the WA id)
    cnt = {}          # chat id -> on-disk message count (to order busiest-first)
    for o in _iter_messages(a.profile, a.origin):
        idv = o.get('id') or ''
        parts = idv.split('_')
        if len(parts) < 3: continue
        from_me, chat, keyid = parts[0] == 'true', parts[1], parts[2]
        # A record holding only a delivery receipt is not the message (wa_decrypt.receipt_only). Counted
        # as on disk, it made both history clients throw away the copy the phone served for it.
        if _receipt_only(o): continue
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
                         'oldest_id': keyid, 'oldest_ts': t, 'oldest_fromMe': from_me,
                         'more_on_primary': more_on_primary.get(chat, True)}

    anchors = sorted(per.values(), key=lambda x: -cnt.get(x['chat_id'], 0))   # busiest chats first
    futile = [x for x in anchors if not x['more_on_primary']]
    if not a.all_chats:
        anchors = [x for x in anchors if x['more_on_primary']]
    json.dump({'anchors': anchors, 'ondisk_ids': sorted(ondisk)}, open(a.out, 'w', encoding='utf-8'))
    remapped = sum(1 for x in anchors if x['chat'] != x['chat_id'])
    print(f"[+] anchors.json: {len(anchors)} chats, {len(ondisk)} on-disk message ids -> {a.out}")
    print(f"    {remapped} chat(s) asked for by historyChatId in its wire form (@s.whatsapp.net) "
          f"rather than by chat id -- this is what WhatsApp Web sends")
    print(f"    {len(futile)} chat(s) {'kept (--all-chats)' if a.all_chats else 'dropped'}: the chat's "
          f"endOfHistoryTransferType says the primary holds nothing older, so a request for them "
          f"cannot be answered")


if __name__ == '__main__':
    main()
