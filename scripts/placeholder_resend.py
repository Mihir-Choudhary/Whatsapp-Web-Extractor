#!/usr/bin/env python3
"""placeholder_resend.py — ask the account's phone for messages the server delivered to the linked device
only as a placeholder.

Some messages reach a linked device as <unavailable/> with no content (view-once media is one case; the
server decides). WhatsApp's companion protocol has a request for exactly this: a peer message to the
account's own phone, PeerDataOperationRequest type PLACEHOLDER_MESSAGE_RESEND, naming the message keys.
The phone answers with PeerDataOperationRequestResponse carrying each message as WebMessageInfo bytes --
or does not answer, if it will not share that message. Nothing goes to the message's sender or its chat:
the request travels only between the account's own devices, so no tick or receipt changes.

Input, in the working directory: creds_in.json, signal_runtime.py.json (or signal_state.json) and
queue_messages.json from queue_capture.py (its rows with status "withheld from linked devices ...").
Output: placeholder_resend.json (per requested message: answered or not, the WebMessageInfo bytes as
base64, and the decoded type, text, media fields and HD/SD association), and resend_journal.jsonl
(every stanza received during the run, journalled before anything -- nothing is acknowledged).

Environment: WAWF_RESEND_WAIT=seconds to wait for the phone (default 60).
Networked; signs in as the device and sends one peer message to the account's phone. Own account /
authorised use only.
"""
from __future__ import annotations
import base64, json, os, queue, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wa_client as WC, wa_proto as WP, wa_binary as WB
import queue_capture as QC

try: sys.stdout.reconfigure(encoding="utf-8", errors="replace"); sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
def say(*a): print(*a, file=sys.stderr, flush=True)

WAIT = int(os.environ.get("WAWF_RESEND_WAIT", "60"))
WEB_MESSAGE_INFO_RAW = {1: ("key", "m", WP.MESSAGE_KEY), 2: ("message", "y"), 3: ("messageTimestamp", "u"),
                        19: ("pushName", "s")}


def main():
    for f in ("creds_in.json", "queue_messages.json"):
        if not os.path.isfile(f): say("[!] %s not found in %s" % (f, os.getcwd())); return 4
    rows = [r for r in json.load(open("queue_messages.json", encoding="utf-8")) if str(r.get("status", "")).startswith("withheld")]
    if not rows:
        say("[i] no withheld placeholders in queue_messages.json -- nothing to ask for"); return 0
    keys = []
    for r in rows:
        k = {"remoteJid": r["chat"], "fromMe": False, "id": r["id"]}
        if r.get("chat_kind") == "group" and r.get("sender"): k["participant"] = r["sender"]
        keys.append(k)
    state_file = next((f for f in ("signal_runtime.py.json", "signal_state.json") if os.path.isfile(f)), None)
    creds = json.load(open("creds_in.json")); state = json.load(open(state_file))
    signal = WC.SignalState(state, os.path.abspath("signal_runtime.py.json"))
    c = WC.Client(creds, signal, log=lambda m: say("  " + m), journal=os.path.abspath("resend_journal.jsonl"), ack="none")
    try:
        c.connect()
    except ConnectionError as e:
        say("[x]", e); return 2
    except Exception as e:
        say("[x] could not connect:", e); return 4
    own = (c.me_lid + "@lid") if c.me_lid else (c.me_pn + "@s.whatsapp.net")
    answers = {}
    try:
        c.query(WB.node("iq", {"to": "s.whatsapp.net", "xmlns": "passive", "type": "set"}, [WB.node("active")]))
        # let the queued backlog arrive first (it is journalled, not acknowledged); answers queue behind it
        t0 = time.time()
        while time.time() - t0 < 60:
            try: ev = c.events.get(timeout=1.5)
            except queue.Empty:
                c.send(WB.node("ib", {}, [WB.node("offline_batch", {"count": "100"})])); continue
            if ev["tag"] == "ib" and any(isinstance(x, dict) and x["tag"] == "offline" for x in (ev.get("content") or [])):
                break
        req = WP.encode({"protocolMessage": {"type": WP.PROTOCOL_TYPE_PDO_REQUEST, "peerDataOperationRequestMessage": {
            "peerDataOperationRequestType": 4,                       # PLACEHOLDER_MESSAGE_RESEND
            "placeholderMessageResendRequest": [{"messageKey": k} for k in keys]}}}, WP.MESSAGE)
        mid = c.send_peer(own, req, {"category": "peer", "push_priority": "high_force"})
        say("[i] asked the phone to resend %d placeholder message(s) (request %s); waiting up to %ds" % (len(keys), mid, WAIT))
        end = time.time() + WAIT
        while time.time() < end and len(answers) < len(keys) and not c.closed.is_set():
            try: m = c.messages.get(timeout=1.0)
            except queue.Empty: continue
            if not (m["from"].startswith(c.me_lid + "@") or m["from"].startswith(c.me_lid + ":")): continue
            pm = WP.unwrap(m["message"]).get("protocolMessage") or {}
            resp = pm.get("peerDataOperationRequestResponseMessage")
            if not resp: continue
            say("[i] phone answered (type %s, for request %s) with %d result(s)" % (resp.get("peerDataOperationRequestType"),
                resp.get("stanzaId"), len(resp.get("peerDataOperationResult") or [])))
            for res in resp.get("peerDataOperationResult") or []:
                b = (res.get("placeholderMessageResendResponse") or {}).get("webMessageInfoBytes")
                if not b: continue
                wmi = WP.decode(b, WEB_MESSAGE_INFO_RAW)
                k = wmi.get("key") or {}
                pt = wmi.get("message") or b""
                decoded = WP.decode(pt, WP.MESSAGE) if pt else {}
                answers[k.get("id")] = {"answered": True, "key": k, "timestamp": wmi.get("messageTimestamp"),
                                        "push_name": wmi.get("pushName"),
                                        "web_message_info_b64": base64.b64encode(b).decode(),
                                        "type": WP.message_type(decoded) if decoded else None,
                                        "text": WP.message_text(decoded) if decoded else None,
                                        **QC.media_and_association(pt)}
    finally:
        c.close()
    out = [answers.get(k["id"]) or {"answered": False, "key": k} for k in keys]
    json.dump(out, open("placeholder_resend.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    say("[+] %d of %d placeholder(s) returned by the phone; %d stanzas journalled, 0 acknowledged"
        % (sum(1 for o in out if o["answered"]), len(out), c.stats["journalled"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
