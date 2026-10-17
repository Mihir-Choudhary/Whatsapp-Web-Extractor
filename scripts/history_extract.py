#!/usr/bin/env python3
"""history_extract.py — on-demand history from the phone, in Python (no Node.js).

A drop-in for tools/reconnect/history_extract.js: the same inputs in the working directory
(creds_in.json, signal_state.json, anchors.json), the same output (history_recovered.json, checkpointed
after every page, plus the decrypted chunks in history_chunks/), the same progress lines, environment
knobs and exit codes, so wawf.py's multi-pass loop drives either one. It signs in as the linked device
(wa_client), drains the offline backlog first (answers queue behind it), then asks the account's own
phone, chat by chat, for messages older than each anchor, paging backward.

Exit: 0 done · 7 stopped by WhatsApp's own failure breaker (resume after the cooldown) · 2 login rejected
· 4 cannot connect / inputs missing · 5 creds and Signal state belong to different registrations.
Networked; own account / authorised use only.
"""
from __future__ import annotations
import base64, gzip, hashlib, json, os, queue, sys, time, urllib.parse, urllib.request, zlib

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import wa_client as WC, wa_proto as WP, wa_binary as WB
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

E = os.environ.get
TOP, COUNT, MAXPAGES = int(E("TOP", 5)), int(E("COUNT", 50)), int(E("MAXPAGES", 10))
REQ_TIMEOUT = int(E("REQ_TIMEOUT_MS", 10000)) / 1000
PROBE = int(E("PROBE_CHATS", 4))
FAIL_LIMIT, COOLDOWN = int(E("FAIL_LIMIT", 10)), int(E("COOLDOWN_SEC", 7200))
BASE_DELAY, MAX_DELAY = int(E("CHAT_DELAY_MS", 800)) / 1000, int(E("CHAT_DELAY_MAX_MS", 30000)) / 1000
LATE_WAIT = int(E("LATE_WAIT_MS", 300000)) / 1000
SETTLE_MAX = int(E("SETTLE_MAX_MS", 300000)) / 1000
# Off by default: the history file stays on WhatsApp's server as the phone left it (it expires there).
# WhatsApp Web deletes each one after reading it; HIST_CHUNK_DELETE=1 does the same.
CHUNK_DELETE = E("HIST_CHUNK_DELETE", "0") == "1"
CDN_HEADERS = {"accept": "*/*", "accept-language": "en-US,en;q=0.9", "origin": "https://web.whatsapp.com",
               "referer": "https://web.whatsapp.com/", "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors",
               "sec-fetch-dest": "empty",
               "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/154.0.0.0 Safari/537.36"}

def say(*a): print(*a, file=sys.stderr, flush=True)


def find(name):
    for c in (os.path.join(os.getcwd(), name), os.path.join(HERE, "..", "tools", "reconnect", name)):
        if os.path.isfile(c): return c
    return None


def fetch_blob(n):
    url = n.get("directPath") or ""
    target = "https://mmg.whatsapp.net" + url
    err = None
    for _ in range(3):
        try:
            return urllib.request.urlopen(urllib.request.Request(target, headers=CDN_HEADERS), timeout=20).read()
        except Exception as e:
            err = e; time.sleep(0.8)
    raise err


HISTORY_KEY_INFO = b"WhatsApp History Keys"

def history_mac_ok(blob, media_key):
    """The 10-byte HMAC-SHA256 (mac key = expanded[48:80], over iv + ciphertext) every WhatsApp media file
    carries -- checked before anything is decrypted."""
    import hmac as _hmac
    k = HKDF(algorithm=hashes.SHA256(), length=112, salt=b"\0" * 32, info=HISTORY_KEY_INFO).derive(media_key)
    return _hmac.compare_digest(_hmac.new(k[48:80], k[:16] + blob[:-10], hashlib.sha256).digest()[:10], blob[-10:])

def decrypt_history(blob, media_key):
    k = HKDF(algorithm=hashes.SHA256(), length=112, salt=b"\0" * 32, info=HISTORY_KEY_INFO).derive(media_key)
    d = Cipher(algorithms.AES(k[16:48]), modes.CBC(k[:16])).decryptor()
    pt = d.update(blob[:-10]) + d.finalize()
    pt = pt[:-pt[-1]]
    return zlib.decompress(pt), pt          # (HistorySync protobuf, the file before inflating = fileSha256)


def _undecoded(w):
    """Why this tool cannot read a history message, or None. Never a guess: a message whose content is a
    field this tool's schema does not name is reported as such, with its raw fields kept."""
    msg = w.get("message")
    if msg is None:
        return None                                   # a system event (stub), handled as one
    inner = WP.unwrap(msg)
    named = [k for k in inner if k not in ("messageContextInfo", "_unknown")]
    if named:
        return None
    unk = inner.get("_unknown") or []
    if unk:
        return {"reason": "message field(s) this tool does not decode", "fields": sorted({f for f, _, _ in unk}),
                "raw": [{"field": f, "b64": base64.b64encode(v if isinstance(v, (bytes, bytearray)) else b"").decode()}
                        for f, _, v in unk]}
    return {"reason": "empty message"}

def flatten(hs):
    out = []
    for conv in hs.get("conversations") or []:
        for hm in conv.get("messages") or []:
            w = hm.get("message") or {}
            k = w.get("key") or {}
            if not k.get("id"): continue
            row = {"chat": conv.get("id") or k.get("remoteJid"), "id": k["id"], "fromMe": bool(k.get("fromMe")),
                   "participant": k.get("participant") or w.get("participant"), "pushName": w.get("pushName"),
                   "ts": int(w.get("messageTimestamp") or 0), "text": WP.message_text(w.get("message")),
                   "type": WP.message_type(w.get("message"))}
            und = _undecoded(w)
            if und: row["undecoded"] = und
            out.append(row)
    return out


class Run:
    def __init__(self):
        self.creds = json.load(open(find("creds_in.json")))
        state_path = find("signal_state.json")
        self.state = json.load(open(state_path))
        self.anchors = json.load(open(find("anchors.json")))
        self.out = os.path.join(os.getcwd(), "history_recovered.json")
        self.chunkdir = os.path.join(os.getcwd(), "history_chunks")
        rt = os.path.join(os.getcwd(), "signal_runtime.py.json")
        # Continue from the ratchet this tool left last time, as long as it is the same registration:
        # the profile's snapshot is older than what a previous run already advanced.
        if os.path.isfile(rt):
            prev = json.load(open(rt))
            if prev.get("registrationId") == self.state.get("registrationId"):
                self.state = prev
        self.signal = WC.SignalState(self.state, rt)
        self.ondisk = set(self.anchors.get("ondisk_ids") or [])
        self.all = {}
        self.start_reached, self.silent, self.answered = set(), set(), set()
        self.anchor_chat = {}
        for a in self.anchors.get("anchors") or []:
            self.anchor_chat[str(a["chat"])] = str(a["chat"])
            if a.get("chat_id"): self.anchor_chat[str(a["chat_id"])] = str(a["chat"])
        self.pending = {}                       # request id -> list (filled when answered)
        self.our_ids, self.late_seen = set(), set()
        self.late = self.late_msgs = self.late_ours = 0
        self.kept = self.kept_bytes = self.released = self.release_failed = 0
        self.media_conn = None
        # what a chunk carries besides messages: chats (names, participants, settings), people who left
        # or were removed, call logs, status updates, name and number mappings -- accumulated across runs
        self.meta_path = os.path.join(os.getcwd(), "history_metadata.json")
        try: self.meta = json.load(open(self.meta_path, encoding="utf-8"))
        except Exception: self.meta = {}
        for k in ("conversations", "past_participants", "call_logs", "pushnames", "pn_lid", "status_messages"):
            self.meta.setdefault(k, {})
        self.undecoded = 0

    # -------------------------------------------------------------- output
    def write_out(self):
        arr = list(self.all.values()); nw = [m for m in arr if m["id"] not in self.ondisk]
        by = {}
        for m in nw: by[m["chat"]] = by.get(m["chat"], 0) + 1
        tmp = self.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"recovered_total": len(arr), "new_not_on_disk": len(nw), "by_chat": by,
                       "start_reached": sorted(self.start_reached), "silent_chats": sorted(self.silent),
                       "answered_chats": sorted(self.answered), "messages": nw}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.out)
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f: json.dump(self.meta, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.meta_path)
        return len(arr), len(nw), len(by)

    def note_metadata(self, hs):
        m = self.meta
        for conv in hs.get("conversations") or []:
            cid = conv.get("id")
            if not cid: continue
            rec = {k: conv.get(k) for k in ("name", "displayName", "description", "username", "pnJid", "lidJid",
                                            "archived", "pinned", "muteEndTime", "ephemeralExpiration")
                   if conv.get(k) not in (None, "", 0, False)}
            if conv.get("participant"):
                rec["participants"] = [{"jid": p.get("userJid"), "rank": {0: "member", 1: "admin", 2: "superadmin"}
                                        .get(p.get("rank") or 0, p.get("rank"))} for p in conv["participant"]]
            if rec: m["conversations"].setdefault(cid, {}).update(rec)
        for pp in hs.get("pastParticipants") or []:
            g = pp.get("groupJid")
            for x in pp.get("pastParticipants") or []:
                m["past_participants"].setdefault(g, {})[x.get("userJid")] = {
                    "left": {0: "left", 1: "removed"}.get(x.get("leaveReason") or 0), "ts": x.get("leaveTs")}
        for c in hs.get("callLogRecords") or []:
            cid = c.get("callId") or "%s-%s" % (c.get("callCreatorJid"), c.get("startTime"))
            m["call_logs"][cid] = {k: v for k, v in c.items() if k != "_unknown"}
        for p in hs.get("pushnames") or []:
            if p.get("id"): m["pushnames"][p["id"]] = p.get("pushname")
        for x in hs.get("phoneNumberToLidMappings") or []:
            if x.get("pnJid"): m["pn_lid"][x["pnJid"]] = x.get("lidJid")
        for w in hs.get("statusV3Messages") or []:
            k = w.get("key") or {}
            if k.get("id"):
                m["status_messages"][k["id"]] = {"from": k.get("participant") or k.get("remoteJid"),
                                                 "ts": w.get("messageTimestamp"), "type": WP.message_type(w.get("message")),
                                                 "text": WP.message_text(w.get("message"))}

    # -------------------------------------------------------------- chunks
    def keep_chunk(self, raw, enc=None):
        """Keep the decrypted HistorySync protobuf (<sha>.pb.gz) and, when it was downloaded, the encrypted
        file exactly as the CDN served it (<sha>.enc), which re-verifies against the fileEncSha256 the
        phone sent in its notification (in received_journal.jsonl)."""
        try:
            os.makedirs(self.chunkdir, exist_ok=True)
            base = os.path.join(self.chunkdir, hashlib.sha256(raw).hexdigest()[:32])
            if not os.path.exists(base + ".pb.gz"):
                data = gzip.compress(raw); open(base + ".pb.gz", "wb").write(data)
                self.kept += 1; self.kept_bytes += len(data)
            if enc is not None and not os.path.exists(base + ".enc"):
                open(base + ".enc", "wb").write(enc)
            return True
        except OSError as e:
            say("  chunk keep failed (not fatal):", e); return False

    def keep_chunk_record(self, raw, enc, n, origin, mac_ok):
        """<sha>.json beside the chunk: the key that opens <sha>.enc, how, and what was checked -- so the
        original, the key and the decrypted result are kept together and anyone can redo the decryption.
        KEY MATERIAL: it decrypts the chunk."""
        b64 = lambda v: base64.b64encode(v).decode() if isinstance(v, (bytes, bytearray)) else v
        try:
            base = os.path.join(self.chunkdir, hashlib.sha256(raw).hexdigest()[:32])
            rec = {
                "original": os.path.basename(base) + ".enc" if enc is not None else None,
                "inline": enc is None,                     # delivered inside the notification, not downloaded
                "decrypted": os.path.basename(base) + ".pb.gz",
                "media_key_b64": b64(n.get("mediaKey")),
                "key_derivation": "HKDF-SHA256(mediaKey, salt=32 zero bytes, info='WhatsApp History Keys', 112 bytes): "
                                  "iv=[0:16], aes_key=[16:48], mac_key=[48:80]; AES-256-CBC over enc[:-10], "
                                  "HMAC-SHA256(mac_key, iv+enc[:-10])[:10] == enc[-10:], PKCS7, then zlib inflate",
                "declared": {k: b64(n.get(k)) for k in ("fileEncSha256", "fileSha256", "fileLength", "directPath",
                                                        "syncType", "chunkOrder", "progress", "originalMessageId",
                                                        "peerDataRequestSessionId", "oldestMsgInChunkTimestampSec")
                             if n.get(k) is not None},
                "checked": {"enc_sha256": hashlib.sha256(enc).hexdigest() if enc is not None else None,
                            "enc_sha256_matches_declared": (hashlib.sha256(enc).digest() == n.get("fileEncSha256"))
                                                           if enc is not None and n.get("fileEncSha256") else None,
                            "mac_ok": mac_ok,
                            "plaintext_sha256_matches_declared": True if enc is not None and n.get("fileSha256") else None,
                            "decrypted_sha256": hashlib.sha256(raw).hexdigest(),
                            "decrypted_bytes": len(raw)},
                "delivered_by": {k: (origin or {}).get(k) for k in ("id", "from", "t", "category")} if origin else None,
                "received_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            with open(base + ".json", "w", encoding="utf-8") as f: json.dump(rec, f, indent=1)
        except OSError as e:
            say("  chunk record failed (not fatal):", e)

    def release_chunk(self, n):
        """Tell the CDN the chunk was consumed, as WhatsApp Web does after reading each one."""
        if not CHUNK_DELETE or not n.get("fileEncSha256") or not n.get("directPath"): return
        try:
            if self.media_conn is None or self.media_conn["expires"] < time.time():
                r = self.c.query(WB.node("iq", {"to": "s.whatsapp.net", "type": "set", "xmlns": "w:m"},
                                         [WB.node("media_conn")]))
                mc = next(x for x in r["content"] if isinstance(x, dict) and x["tag"] == "media_conn")
                hosts = [h["attrs"].get("hostname") for h in (mc.get("content") or []) if isinstance(h, dict) and h["tag"] == "host"]
                self.media_conn = {"auth": mc["attrs"]["auth"], "host": hosts[0] if hosts else "mmg.whatsapp.net",
                                   "expires": time.time() + int(mc["attrs"].get("ttl", 300)) - 30}
            b64url = lambda b: base64.b64encode(b).decode().replace("+", "-").replace("/", "_")
            h = b64url(n["fileEncSha256"])
            d_md = b64url(n["directPath"].encode()).rstrip("=")
            qs = "token=" + urllib.parse.quote(h, safe="") + "&d_md=" + d_md + "&auth=" + urllib.parse.quote(self.media_conn["auth"], safe="")
            req = urllib.request.Request("https://%s/mms/md-msg-hist/%s?%s" % (self.media_conn["host"], h, qs),
                                         method="DELETE", headers=CDN_HEADERS)
            code = urllib.request.urlopen(req, timeout=10).status
            if code == 200: self.released += 1
            else: self.release_failed += 1
        except Exception as e:
            self.release_failed += 1
            if self.release_failed <= 3: say("  chunk release failed:", e)

    # -------------------------------------------------------------- replies
    def note_conversations(self, convs):
        for conv in convs or []:
            cid = conv.get("id")
            if not cid: continue
            ids = [cid] + ([self.anchor_chat[cid]] if self.anchor_chat.get(cid) not in (None, cid) else [])
            for x in ids:
                self.answered.add(x); self.silent.discard(x)
                if int(conv.get("endOfHistoryTransferType") or 0) == 1: self.start_reached.add(x)

    def on_notification(self, n, origin=None):
        """Download, verify, decrypt, keep (original + key + decrypted), decode, bank, release.
        -> (session id, messages)"""
        blob = None; mac_ok = None
        if n.get("initialHistBootstrapInlinePayload"):
            p = n["initialHistBootstrapInlinePayload"]
            try: raw = zlib.decompress(p)
            except zlib.error: raw = p
        else:
            blob = fetch_blob(n)
            if n.get("fileEncSha256") and hashlib.sha256(blob).digest() != n["fileEncSha256"]:
                raise ValueError("history chunk hash mismatch")
            mac_ok = history_mac_ok(blob, n["mediaKey"])
            if not mac_ok:
                raise ValueError("history chunk MAC mismatch")
            raw, compressed = decrypt_history(blob, n["mediaKey"])
            if n.get("fileSha256") and hashlib.sha256(compressed).digest() != n["fileSha256"]:
                raise ValueError("history chunk plaintext hash mismatch")
        kept = self.keep_chunk(raw, blob)
        self.keep_chunk_record(raw, blob, n, origin, mac_ok)
        hs = WP.decode(raw, WP.HISTORY_SYNC)
        self.note_conversations(hs.get("conversations"))
        self.note_metadata(hs)
        msgs = flatten(hs)
        for m in msgs: self.all[m["id"]] = m
        und = sum(1 for m in msgs if m.get("undecoded"))
        if und:
            self.undecoded += und
            say("  [!] %d message(s) in this chunk are of a type this tool does not decode: kept raw "
                "(history_chunks/, and 'undecoded' in history_recovered.json), not interpreted" % und)
        if kept: self.release_chunk(n)
        return n.get("peerDataRequestSessionId"), msgs

    def pump(self, until):
        """Process inbound messages until `until()` is true or nothing arrives for a moment."""
        while not until():
            try: m = self.c.messages.get(timeout=0.5)
            except queue.Empty:
                if self.c.closed.is_set(): return
                continue
            pm = WP.unwrap(m["message"]).get("protocolMessage") or {}
            n = pm.get("historySyncNotification")
            # only the account's own devices send history; the phone may address us by its LID or by
            # its phone number, and creds without a LID have only the number to go by
            if not n or self.c.sender_kind(m["from"]) == "contact":
                continue
            try:
                sid, msgs = self.on_notification(n, m)
            except Exception as e:
                say("  history chunk failed:", e); continue
            if sid in self.pending:
                self.pending[sid].extend(msgs); self.pending[sid].append(None)     # None marks "answered"
            elif str(sid) not in self.late_seen:
                self.late_seen.add(str(sid)); self.late += 1; self.late_msgs += len(msgs)
                if str(sid) in self.our_ids: self.late_ours += 1
                self.write_out()

    def request_page(self, key, ts):
        req = WP.history_request(key["remoteJid"], key["id"], key["fromMe"], COUNT, ts)
        mid = self.c.send_peer(self.own, req, {"category": "peer", "push_priority": "high_force", "privacy_sensitive": "1"})
        self.our_ids.add(mid); self.pending[mid] = []
        deadline = time.time() + REQ_TIMEOUT
        self.pump(lambda: (self.pending[mid] and self.pending[mid][-1] is None) or time.time() > deadline)
        got = self.pending.pop(mid)
        if not got or got[-1] is not None: return None
        return got[:-1]

    # -------------------------------------------------------------- the run
    def main(self):
        if not self.creds.get("account"):
            say("[!] creds_in.json has no account (adv_signed_identity missing)"); return 2
        if self.creds.get("registrationId") and self.state.get("registrationId") and \
                int(self.creds["registrationId"]) != int(self.state["registrationId"]):
            say("[!] creds_in.json and signal_state.json belong to different registrations"); return 5
        askable = [a for a in self.anchors["anchors"] if a.get("more_on_primary") is not False]
        if len(askable) < len(self.anchors["anchors"]):
            say("[i] skipping %d chat(s) the primary has nothing older for" % (len(self.anchors["anchors"]) - len(askable)))
        targets = askable[:TOP]
        # everything the server delivers is journalled before anything is acknowledged; by default nothing is
        # (WAWF_HISTORY_ACK=saved acknowledges what was saved and decrypted) -- see wa_client
        self.c = WC.Client(self.creds, self.signal, log=lambda m: say("  " + m),
                           journal=os.path.join(os.getcwd(), "received_journal.jsonl"),
                           ack=os.environ.get("WAWF_HISTORY_ACK", "none"))
        try:
            self.c.connect()
        except ConnectionError as e:
            say("[x]", e); return 2
        except Exception as e:
            say("[x] could not connect:", e); return 4
        self.own = self.c.me_lid + "@lid" if self.c.me_lid else self.c.me_pn + "@s.whatsapp.net"
        say("[+] connected; asking the primary for history on %d chat(s)" % len(targets))
        self.c.query(WB.node("iq", {"to": "s.whatsapp.net", "xmlns": "passive", "type": "set"}, [WB.node("active")]))
        # answers queue behind the offline backlog: drain it before asking
        t0, done = time.time(), False
        self.c.send(WB.node("ib", {}, [WB.node("offline_batch", {"count": "100"})]))
        while time.time() - t0 < SETTLE_MAX and not done:
            try: ev = self.c.events.get(timeout=1.5)
            except queue.Empty:
                self.c.send(WB.node("ib", {}, [WB.node("offline_batch", {"count": "100"})])); continue
            if ev["tag"] == "ib" and any(isinstance(x, dict) and x["tag"] == "offline" for x in (ev.get("content") or [])):
                done = True
        self.pump(lambda: self.c.messages.empty())          # bank any late answers delivered in the backlog
        say("[i] offline backlog %s (%d stanzas, %d decrypted)" % ("drained" if done else "NOT fully drained",
                                                                    self.c.stats["in"], self.c.stats["decrypted"]))
        self.c.send(WB.node("presence", {"type": "available"}))
        fail = 0; first_fail = None; tripped = False; delay = BASE_DELAY
        probe_silent = probed = served = silent = 0
        for a in targets:
            key = {"remoteJid": a["chat"], "id": a["oldest_id"], "fromMe": bool(a.get("oldest_fromMe"))}
            ts, got = a["oldest_ts"], 0
            for pg in range(MAXPAGES):
                msgs = self.request_page(key, ts)
                if msgs is None:
                    say("  %s page%d: no response" % (a["chat"][:22], pg))
                    if pg == 0: probe_silent += 1; silent += 1; self.silent.add(a["chat"]); self.write_out()
                    now = time.time(); first_fail = first_fail or now
                    delay = min(MAX_DELAY, max(BASE_DELAY, delay * 2)); fail += 1
                    if fail >= FAIL_LIMIT and now - first_fail < COOLDOWN: tripped = True
                    break
                if pg == 0: served += 1; self.answered.add(a["chat"])
                fail, first_fail, delay = 0, None, max(BASE_DELAY, delay / 2)
                if not msgs:
                    ended = a["chat"] in self.start_reached or a.get("chat_id") in self.start_reached
                    say("  %s page%d: empty%s" % (a["chat"][:22], pg, " (the phone says nothing older remains)" if ended
                                                  else " (the phone says more remains)"))
                    self.write_out(); break
                got += len(msgs); msgs.sort(key=lambda m: m["ts"]); o = msgs[0]
                newc = sum(1 for m in msgs if m["id"] not in self.ondisk)
                self.write_out()
                say("  %s page%d: +%d (new %d) oldest=%s" % (a["chat"][:22], pg, len(msgs), newc,
                                                              time.strftime("%Y-%m-%d", time.gmtime(o["ts"]))))
                advanced = o["id"] != key["id"]
                key = {"remoteJid": a["chat"], "id": o["id"], "fromMe": o["fromMe"]}; ts = o["ts"]
                ended = a["chat"] in self.start_reached or a.get("chat_id") in self.start_reached
                if len(msgs) < COUNT and (ended or not advanced):
                    say("  %s: short page -> done (%d total)" % (a["chat"][:22], got)); break
                time.sleep(0.5)
            probed += 1
            if tripped:
                say("\n[!] %d unanswered requests inside the %ds window. WhatsApp Web stops here and goes quiet "
                    "for the cooldown, so we do the same." % (fail, COOLDOWN)); break
            if probed == PROBE and probe_silent == PROBE:
                say("\n[!] the first %d chats returned NOTHING -- stopping rather than grinding through %d chats."
                    % (PROBE, len(targets))); break
            if probed % 10 == 0 or probed == len(targets):
                say("  [%d/%d] served=%d silent=%d pace=%dms" % (probed, len(targets), served, silent, delay * 1000))
            time.sleep(delay)
        if LATE_WAIT > 0 and silent > 0 and not self.c.closed.is_set():
            say("[i] %d request(s) unanswered -- staying connected up to %ds for late answers" % (silent - self.late_ours, LATE_WAIT))
            end = time.time() + LATE_WAIT; seen = self.late_ours
            while time.time() < end and self.late_ours < silent and not self.c.closed.is_set():
                self.pump(lambda: True); time.sleep(1); self.pump(lambda: self.c.messages.empty())
                if self.late_ours != seen: seen = self.late_ours; end = max(end, time.time() + 60)
        if self.late:
            say("[*] %d reply(ies) arrived after their request had timed out, carrying %d message(s)" % (self.late, self.late_msgs))
        if self.kept:
            say("[*] kept %d decrypted history chunk(s), %.1f MiB, in %s" % (self.kept, self.kept_bytes / 1048576, self.chunkdir))
        if self.released or self.release_failed:
            say("[*] released %d consumed history chunk(s) back to the CDN%s" % (
                self.released, (", %d release(s) failed" % self.release_failed) if self.release_failed else ""))
        tot, nw, chats = self.write_out()
        say("\n[DONE] recovered=%d NEW(not-on-disk)=%d across %d chats -> %s" % (tot, nw, chats, self.out))
        mm = self.meta
        say("[i] also kept (history_metadata.json): %d chats' details (%d with participants), %d past participants, "
            "%d call logs, %d status updates, %d names" % (
                len(mm["conversations"]), sum(1 for v in mm["conversations"].values() if v.get("participants")),
                sum(len(v) for v in mm["past_participants"].values()), len(mm["call_logs"]),
                len(mm["status_messages"]), len(mm["pushnames"])))
        if self.undecoded:
            say("[!] %d recovered message(s) are of a type this tool does not decode -- kept raw, marked 'undecoded'"
                % self.undecoded)
        say("[i] received: " + ", ".join("%s=%d" % kv for kv in sorted(self.c.tally.items())))
        self.c.close()
        return 7 if tripped else 0


if __name__ == "__main__":
    for f in ("creds_in.json", "signal_state.json", "anchors.json"):
        if not find(f):
            say("[!] %s not found in %s" % (f, os.getcwd())); sys.exit(4)
    sys.exit(Run().main())
