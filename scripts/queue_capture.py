#!/usr/bin/env python3
"""queue_capture.py — record what WhatsApp's server is holding for the linked device, without taking it.

While a WhatsApp Web session is closed, the server queues for that device everything the account
receives and sends from other devices (messages, group key handovers, receipts, notifications). The
browser collects the queue the next time it connects; until then it exists only on the server.

This signs in as that device, asks for the queue, and writes every stanza to queue_journal.jsonl: the
stanza exactly as received (after transport decryption) and each payload decrypted with the device's
own Signal state, including group messages (sender keys). By default NOTHING is acknowledged, so the
server keeps the queue and delivers it again to the next client that connects as this device -- the
browser included. Nothing is sent that a contact can see: no receipts, no presence.

Inputs, in the working directory (as for history_extract.py): creds_in.json and signal_state.json, or
signal_runtime.py.json from an earlier run (its sessions and sender keys are newer and are preferred).

Outputs: queue_journal.jsonl (append-only, fsynced per stanza), queue_messages.json (readable: per
message chat, sender, time, type, text, media keys, HD/SD association), queue_summary.json.

Environment: WAWF_QUEUE_ACK=none|saved (default none), WAWF_QUEUE_MAX=seconds to wait (default 180).
Exit codes: 0 ok, 2 login rejected / bad inputs, 4 connection failed or inputs missing.

Networked; signs in as the device, so it is recorded as activity on the account. Own account / authorised
use only.
"""
from __future__ import annotations
import base64, json, os, queue, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wa_client as WC, wa_proto as WP, wa_binary as WB, wa_reconnect as WR

try: sys.stdout.reconfigure(encoding="utf-8", errors="replace"); sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
def say(*a): print(*a, file=sys.stderr, flush=True)

ACK = os.environ.get("WAWF_QUEUE_ACK", "none")
MAX_WAIT = int(os.environ.get("WAWF_QUEUE_MAX", "180"))
QUIET = 8                                    # seconds without a stanza after the end-of-queue marker

# media fields per media message type (WAProto numbering differs between types), for the readable output
_MEDIA_FIELDS = {
    "imageMessage": {1: "url", 2: "mimetype", 4: "fileSha256", 5: "fileLength", 6: "height", 7: "width",
                     8: "mediaKey", 9: "fileEncSha256", 11: "directPath", 12: "mediaKeyTimestamp"},
    "videoMessage": {1: "url", 2: "mimetype", 3: "fileSha256", 4: "fileLength", 6: "mediaKey", 9: "height",
                     10: "width", 11: "fileEncSha256", 13: "directPath", 14: "mediaKeyTimestamp"},
    "audioMessage": {1: "url", 2: "mimetype", 3: "fileSha256", 4: "fileLength", 7: "mediaKey",
                     8: "fileEncSha256", 9: "directPath", 10: "mediaKeyTimestamp"},
    "documentMessage": {1: "url", 2: "mimetype", 4: "fileSha256", 5: "fileLength", 7: "mediaKey",
                        9: "fileEncSha256", 10: "directPath", 11: "mediaKeyTimestamp"},
    "stickerMessage": {1: "url", 2: "fileSha256", 3: "fileEncSha256", 4: "mediaKey", 5: "mimetype", 6: "height",
                       7: "width", 8: "directPath", 9: "fileLength", 10: "mediaKeyTimestamp"},
}
_STR = {"url", "mimetype", "directPath"}
_MEDIA_TYPES = {3: "imageMessage", 7: "documentMessage", 8: "audioMessage", 9: "videoMessage", 26: "stickerMessage"}
_WRAPPERS = (37, 40, 53, 55, 58, 91)             # FutureProofMessage{message=1}: view once, ephemeral, edited, HD child...
_ASSOC = {1: ("associationType", "e"), 2: ("parentMessageKey", "m", WP.MESSAGE_KEY), 3: ("messageIndex", "u")}
_MSG_CTX = {10: ("messageAssociation", "m", _ASSOC)}
ASSOCIATION_TYPES = {1: "MEDIA_ALBUM", 5: "HD_VIDEO_DUAL_UPLOAD", 10: "HD_IMAGE_DUAL_UPLOAD", 12: "MOTION_PHOTO"}


def media_and_association(pt: bytes) -> dict:
    """From a Message protobuf: the media fields of a media message (also inside associatedChildMessage /
    other future-proof wrappers) and the HD/SD association, if any."""
    out = {}
    def walk(buf, depth=0):
        if depth > 3: return
        try: f = WP.decode(buf, {**{k: ("m%d" % k, "y") for k in _MEDIA_TYPES}, 35: ("ctx", "y"),
                                 **{k: ("w%d" % k, "y") for k in _WRAPPERS}})
        except Exception: return
        if f.get("ctx"):
            try:
                ctx = WP.decode(f["ctx"], _MSG_CTX).get("messageAssociation")
                if ctx:
                    out["association"] = {"type": ASSOCIATION_TYPES.get(ctx.get("associationType"), ctx.get("associationType")),
                                          "parent": ctx.get("parentMessageKey"), "index": ctx.get("messageIndex")}
            except Exception: pass
        for k, name in _MEDIA_TYPES.items():
            if f.get("m%d" % k):
                spec = {n: (x, "s" if x in _STR else ("u" if x in ("fileLength", "height", "width", "mediaKeyTimestamp") else "y"))
                        for n, x in _MEDIA_FIELDS[name].items()}
                d = WP.decode(f["m%d" % k], spec)
                out["media"] = {"kind": name, **{x: (base64.b64encode(v).decode() if isinstance(v, bytes) else v)
                                                 for x, v in d.items() if x != "_unknown"}}
                if "w91" in f or depth: out["media"]["wrapped"] = True
        for w in ["w%d" % k for k in _WRAPPERS]:
            if f.get(w):
                try: inner = WP.decode(f[w], {1: ("m", "y")}).get("m")
                except Exception: inner = None
                if inner: walk(inner, depth + 1)
    walk(pt)
    return out


def sender_device(jid):
    """Device number from a device jid 'user:N@server': 0 is the account's phone, any other number a linked
    device (web, desktop, tablet, second phone). Taken from the address, so it is a fact, not a guess."""
    user = (jid or "").split("@")[0]
    return int(user.split(":")[1]) if ":" in user and user.split(":")[1].isdigit() else 0

def id_style(mid):
    """The client family whose message-id format this is (as Baileys' getDevice reads it). A convention,
    not a guarantee: any client can choose any id."""
    import re
    mid = mid or ""
    if re.fullmatch(r"3A.{18}", mid): return "ios-style"
    if re.fullmatch(r"3E.{20}", mid): return "web-style"
    if re.fullmatch(r".{21}|.{32}", mid): return "android-style"
    if re.fullmatch(r"3F.*|.{18}", mid): return "desktop-style"
    return "unknown"

def _parts_from_stanza(r):
    """For journal lines written without decrypted parts: re-derive placeholders from the stanza bytes."""
    try: n = WR.decode_binary_node(base64.b64decode(r.get("stanza_b64") or ""))
    except Exception: return []
    return [{"enc": None, "unavailable": (c.get("attrs") or {}).get("type") or "unknown"}
            for c in (n.get("content") or []) if isinstance(c, dict) and c.get("tag") == "unavailable"]

def readable(journal_path: str) -> list:
    rows, seen = [], set()
    for line in open(journal_path, encoding="utf-8"):
        try: r = json.loads(line)
        except ValueError: continue
        if r.get("tag") != "message": continue
        a = r["attrs"]
        for p in (r.get("decrypted") or _parts_from_stanza(r)):
            key = (a.get("id"), a.get("participant") or a.get("from"), p.get("enc"))
            if key in seen: continue                             # the server re-delivers what is not acknowledged
            seen.add(key)
            row = {"id": a.get("id"), "chat": a.get("from"), "chat_kind": WC.chat_kind(a.get("from")),
                   "message_type_attr": a.get("type"), "sender": a.get("participant") or a.get("from"),
                   "recipient": a.get("recipient"), "push_name": a.get("notify"), "t": int(a.get("t") or 0),
                   "time_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(a.get("t") or 0))),
                   "category": a.get("category"), "enc": p.get("enc"),
                   "sender_device": sender_device(a.get("participant") or a.get("from")),
                   "sender_phone_number": a.get("sender_pn") or a.get("participant_pn"),
                   "id_style": id_style(a.get("id"))}
            if p.get("unavailable"):
                row.update(status="withheld from linked devices (%s)" % p["unavailable"], type=a.get("type"))
            elif p.get("error"):
                row.update(status="not decrypted", error=p["error"])
            else:
                pt = base64.b64decode(p["plaintext_b64"])
                msg = WP.decode(pt, WP.MESSAGE)
                row.update(status="decrypted", type=p.get("type"), text=WP.message_text(msg))
                row.update(media_and_association(pt))
            rows.append(row)
    rows.sort(key=lambda x: (x["t"], x["id"] or ""))
    return rows


def main():
    for f in ("creds_in.json",):
        if not os.path.isfile(f): say("[!] %s not found in %s" % (f, os.getcwd())); return 4
    state_file = next((f for f in ("signal_runtime.py.json", "signal_state.json") if os.path.isfile(f)), None)
    if not state_file: say("[!] no signal_state.json / signal_runtime.py.json in %s" % os.getcwd()); return 4
    creds = json.load(open("creds_in.json"))
    state = json.load(open(state_file))
    signal = WC.SignalState(state, os.path.abspath("signal_runtime.py.json"))
    say("[i] Signal state from %s: %d sessions, %d group sender keys" % (state_file, len(state.get("sessions") or {}),
                                                                         len(state.get("senderKeys") or {})))
    jpath = os.path.abspath("queue_journal.jsonl")
    c = WC.Client(creds, signal, log=lambda m: say("  " + m), journal=jpath, ack=ACK)
    say("[i] acknowledgements: %s" % ("NONE -- the server keeps the queue" if ACK == "none"
                                      else "after saving, for fully decrypted messages only"))
    try:
        c.connect()
    except ConnectionError as e:
        say("[x] login rejected:", e); return 2
    except Exception as e:
        say("[x] could not connect:", e); return 4
    started = time.time()
    offline_marker = None; last_in = time.time(); n_in = c.stats["in"]
    try:
        c.query(WB.node("iq", {"to": "s.whatsapp.net", "xmlns": "passive", "type": "set"}, [WB.node("active")]))
        c.send(WB.node("ib", {}, [WB.node("offline_batch", {"count": "100"})]))
        while time.time() - started < MAX_WAIT and not c.closed.is_set():
            try: ev = c.events.get(timeout=1.0)
            except queue.Empty: ev = None
            if c.stats["in"] != n_in: n_in, last_in = c.stats["in"], time.time()
            if ev and ev.get("tag") == "ib":
                for x in ev.get("content") or []:
                    if isinstance(x, dict) and x["tag"] == "offline":
                        offline_marker = dict(x.get("attrs") or {}); say("[i] end of queue marker: %s" % offline_marker)
            if ev is None and offline_marker is None and time.time() - last_in > 3:
                c.send(WB.node("ib", {}, [WB.node("offline_batch", {"count": "100"})]))
            if offline_marker is not None and time.time() - last_in > QUIET:
                break
    finally:
        c.close()
        while not c.messages.empty(): c.messages.get_nowait()
    rows = readable(jpath)
    json.dump(rows, open("queue_messages.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    summ = {"finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ack_policy": ACK,
            "end_of_queue_marker": offline_marker, "seconds": round(time.time() - started),
            "stats": c.stats, "tally": dict(c.tally),
            "messages": len(rows), "decrypted": sum(1 for r in rows if r["status"] == "decrypted"),
            "not_decrypted": sum(1 for r in rows if r["status"] != "decrypted")}
    json.dump(summ, open("queue_summary.json", "w", encoding="utf-8"), indent=1)
    say("[+] %d stanzas journalled (%d acknowledged); %d message parts, %d decrypted, %d not; queue end marker %s"
        % (c.stats["journalled"], c.stats["acked"], len(rows), summ["decrypted"], summ["not_decrypted"],
           "seen" if offline_marker is not None else "NOT seen"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
