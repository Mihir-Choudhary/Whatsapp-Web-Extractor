#!/usr/bin/env python3
"""Pure-Python WhatsApp Web reconnect: log back in as the already-linked companion device using the
disk-recovered Noise credentials, and capture `companion_enc_static` from the server's post-login
stanza. No Node/Baileys needed — this is a faithful port of the Baileys Noise handshake
(Noise_XX_25519_AESGCM_SHA256) far enough to read the `<success>`-era binary node that carries the key.

  python3 scripts/wa_reconnect.py --creds creds_in.json [--out companion_enc_static.txt]

Networked: this opens a real connection to WhatsApp and registers device activity. OWN ACCOUNT /
authorized investigation only. Exit: 0 captured · 2 login rejected (QR/failure) · 3 opened but no key ·
4 stream closed · 5 timeout · 6 bad input/creds.
"""
import sys, os, json, base64, struct, argparse, re, time, zlib, hashlib, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _wa_tokens import TAGS, SINGLE_BYTE_TOKENS, DOUBLE_BYTE_TOKENS

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

NOISE_MODE      = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0"   # exactly 32 bytes -> used as the initial hash verbatim
NOISE_WA_HEADER = bytes([87, 65, 6, 3])                     # "WA" + 6 + DICT_VERSION(3)
WS_URL          = "wss://web.whatsapp.com/ws/chat"
FALLBACK_VERSION = [2, 3000, 1043857760]
KEY_RE = re.compile(r"companion_enc_static|companion_enc|enc_static", re.I)


def _sha256(b):
    h = hashes.Hash(hashes.SHA256()); h.update(b); return h.finalize()

def _dh(priv32, pub32):   # X25519 (RFC 7748); matches libsignal.curve.calculateAgreement on the raw 32-byte keys
    return X25519PrivateKey.from_private_bytes(priv32).exchange(X25519PublicKey.from_public_bytes(pub32))


# ---------------- minimal protobuf ----------------
def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)

def _fld_len(num, data):                       # wire type 2 (length-delimited): bytes / string / sub-message
    return _varint((num << 3) | 2) + _varint(len(data)) + data

def _fld_var(num, val):                        # wire type 0 (varint): int / bool / enum
    return _varint((num << 3) | 0) + _varint(int(val))

def _pb_read(buf):                             # -> {field_num: [values]}, values are bytes (wt2) or int (wt0)
    out, i, n = {}, 0, len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        fnum, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _read_varint(buf, i)
        elif wt == 2:
            ln, i = _read_varint(buf, i); v = buf[i:i+ln]; i += ln
        elif wt == 1:
            v = buf[i:i+8]; i += 8
        elif wt == 5:
            v = buf[i:i+4]; i += 4
        else:
            raise ValueError("unsupported wire type %d" % wt)
        out.setdefault(fnum, []).append(v)
    return out

def _read_varint(buf, i):
    shift = res = 0
    while True:
        b = buf[i]; i += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80): return res, i
        shift += 7


def build_client_payload(user, device, version, country="US"):
    """The Baileys generateLoginNode ClientPayload for a passive companion login."""
    app_ver  = _fld_var(1, version[0]) + _fld_var(2, version[1]) + _fld_var(3, version[2])
    user_agent = (
        _fld_var(1, 14) +                       # platform = WEB
        _fld_len(2, app_ver) +                  # appVersion
        _fld_len(3, b"000") +                   # mcc
        _fld_len(4, b"000") +                   # mnc
        _fld_len(5, b"0.1") +                   # osVersion
        _fld_len(7, b"Desktop") +               # device
        _fld_len(8, b"0.1") +                   # osBuildNumber
        _fld_var(10, 0) +                       # releaseChannel = RELEASE
        _fld_len(11, b"en") +                   # localeLanguageIso6391
        _fld_len(12, country.encode())          # localeCountryIso31661Alpha2
    )
    web_info = _fld_var(4, 0)                    # webSubPlatform = WEB_BROWSER
    return (
        _fld_var(1, int(user)) +                 # username (phone)
        _fld_var(3, 0) +                         # passive = false
        _fld_len(5, user_agent) +                # userAgent
        _fld_len(6, web_info) +                  # webInfo
        _fld_var(12, 1) +                        # connectType = WIFI_UNKNOWN
        _fld_var(13, 1) +                        # connectReason = USER_ACTIVATED
        _fld_var(18, int(device)) +              # device
        _fld_var(33, 1)                          # pull = true
    )


# ---------------- Noise handshake (port of baileys Utils/noise-handler.js) ----------------
class Noise:
    def __init__(self, ephemeral_pub):
        self.hash = self.salt = self.enc = self.dec = NOISE_MODE   # 32-byte mode used directly as hash
        self.wc = self.rc = 0
        self.finished = False
        self._auth(NOISE_WA_HEADER)
        self._auth(ephemeral_pub)

    def _iv(self, counter):
        return b"\x00" * 8 + struct.pack(">I", counter)

    def _auth(self, data):
        if not self.finished:
            self.hash = _sha256(self.hash + data)

    def encrypt(self, pt):
        out = AESGCM(self.enc).encrypt(self._iv(self.wc), pt, self.hash)
        self.wc += 1
        self._auth(out)
        return out

    def decrypt(self, ct):
        iv = self._iv(self.rc if self.finished else self.wc)
        out = AESGCM(self.dec).decrypt(iv, ct, self.hash)
        if self.finished: self.rc += 1
        else: self.wc += 1
        self._auth(ct)
        return out

    def _hkdf(self, data):
        k = HKDF(algorithm=hashes.SHA256(), length=64, salt=self.salt, info=b"").derive(data)
        return k[:32], k[32:]

    def mix(self, data):
        w, r = self._hkdf(data)
        self.salt, self.enc, self.dec, self.rc, self.wc = w, r, r, 0, 0

    def finish(self):
        w, r = self._hkdf(b"")
        self.enc, self.dec, self.hash, self.rc, self.wc, self.finished = w, r, b"", 0, 0, True

    def process_handshake(self, sh_ephemeral, sh_static, sh_payload, noise_priv, noise_pub, ephem_priv):
        self._auth(sh_ephemeral)
        self.mix(_dh(ephem_priv, sh_ephemeral))
        dec_static = self.decrypt(sh_static)
        self.mix(_dh(ephem_priv, dec_static))
        self.decrypt(sh_payload)                 # server cert; we only decrypt to advance the hash (no verify)
        key_enc = self.encrypt(noise_pub)
        self.mix(_dh(noise_priv, sh_ephemeral))
        return key_enc

    def encode_frame(self, data, sent_intro):
        if self.finished:
            data = self.encrypt(data)
        intro = b"" if sent_intro else NOISE_WA_HEADER
        n = len(data)
        return intro + bytes([n >> 16]) + struct.pack(">H", n & 0xFFFF) + data


# ---------------- WA binary node decoder (port of WABinary/decode.js) ----------------
class NodeReader:
    def __init__(self, buf):
        self.b = buf; self.i = 0

    def _byte(self):
        v = self.b[self.i]; self.i += 1; return v

    def _bytes(self, n):
        v = self.b[self.i:self.i + n]; self.i += n; return bytes(v)

    def _int(self, n):
        v = 0
        for _ in range(n): v = (v << 8) | self._byte()
        return v

    def _int20(self):
        return ((self._byte() & 15) << 16) + (self._byte() << 8) + self._byte()

    def _list_size(self, tag):
        if tag == TAGS["LIST_EMPTY"]: return 0
        if tag == TAGS["LIST_8"]: return self._byte()
        if tag == TAGS["LIST_16"]: return self._int(2)
        raise ValueError("bad list tag %d" % tag)

    def _unpack_nibble(self, v):
        if 0 <= v <= 9: return ord("0") + v
        if v == 10: return ord("-")
        if v == 11: return ord(".")
        if v == 15: return 0            # '\0' padding for odd-length packed strings (trimmed in _packed8)
        raise ValueError("nibble %d" % v)

    def _unpack_hex(self, v):
        if 0 <= v < 16: return ord("0") + v if v < 10 else ord("A") + v - 10
        raise ValueError("hex %d" % v)

    def _packed8(self, tag):
        start = self._byte(); out = []
        for _ in range(start & 127):
            cur = self._byte()
            unpk = self._unpack_nibble if tag == TAGS["NIBBLE_8"] else self._unpack_hex
            out.append(chr(unpk((cur & 0xF0) >> 4))); out.append(chr(unpk(cur & 0x0F)))
        s = "".join(out)
        return s[:-1] if start >> 7 else s

    def _jid_pair(self):
        i = self._string(self._byte()); j = self._string(self._byte())
        if j: return (i or "") + "@" + j
        raise ValueError("bad jid pair")

    def _ad_jid(self):
        domain = self._byte(); device = self._byte(); user = self._string(self._byte())
        dom = "s.whatsapp.net" if domain in (0, 128) else "lid"
        return (("%s:%d" % (user, device)) if device else (user or "")) + "@" + dom

    def _string(self, tag):
        if 1 <= tag < len(SINGLE_BYTE_TOKENS):
            return SINGLE_BYTE_TOKENS[tag] or ""
        T = TAGS
        if tag in (T["DICTIONARY_0"], T["DICTIONARY_1"], T["DICTIONARY_2"], T["DICTIONARY_3"]):
            return DOUBLE_BYTE_TOKENS[tag - T["DICTIONARY_0"]][self._byte()]
        if tag == T["LIST_EMPTY"]: return ""
        if tag == T["BINARY_8"]:  return self._bytes(self._byte()).decode("utf-8", "replace")
        if tag == T["BINARY_20"]: return self._bytes(self._int20()).decode("utf-8", "replace")
        if tag == T["BINARY_32"]: return self._bytes(self._int(4)).decode("utf-8", "replace")
        if tag == T["JID_PAIR"]:  return self._jid_pair()
        if tag == T["AD_JID"]:    return self._ad_jid()
        if tag in (T["HEX_8"], T["NIBBLE_8"]): return self._packed8(tag)
        raise ValueError("bad string tag %d" % tag)

    def node(self):
        size = self._list_size(self._byte())
        header = self._string(self._byte())
        if not size or not header: raise ValueError("invalid node")
        attrs = {}
        for _ in range((size - 1) >> 1):
            k = self._string(self._byte()); v = self._string(self._byte()); attrs[k] = v
        content = None
        if size % 2 == 0:
            tag = self._byte()
            T = TAGS
            if tag in (T["LIST_EMPTY"], T["LIST_8"], T["LIST_16"]):
                content = [self.node() for _ in range(self._list_size(tag))]
            elif tag == T["BINARY_8"]:  content = self._bytes(self._byte())
            elif tag == T["BINARY_20"]: content = self._bytes(self._int20())
            elif tag == T["BINARY_32"]: content = self._bytes(self._int(4))
            else: content = self._string(tag)
        return {"tag": header, "attrs": attrs, "content": content}


def decode_binary_node(buf):
    if buf and (buf[0] & 2):
        buf = zlib.decompress(buf[1:])
    else:
        buf = buf[1:]
    return NodeReader(buf).node()


def audit_attrs(attrs, limit=6):
    """Stanza attributes for the audit trail, with key material replaced by its fingerprint.

    One of these attributes IS the at-rest key -- `companion_enc_static` arrives as an attribute of
    the post-login <success> stanza, which is the whole reason this script exists. Recording the
    stanza verbatim therefore wrote the key into the case database in plain base64, even though the
    crypto trail right beside it was carefully storing only a fingerprint, and even though the
    database is documented as "not a secret store" unless --audit-secrets is given. With the audit
    now on by default, every ordinary run did it.

    The fingerprint is kept rather than dropping the attribute: that the key arrived in THAT stanza,
    at that moment, is exactly what an examiner wants the trail to show -- and it can be checked
    against the key file without the trail holding the secret.
    """
    # `is not True` on purpose: when auditing is off, A is NoAudit, whose __getattr__ hands back a
    # lambda for every name -- so a plain truth test on an attribute it does not define reads as
    # "secrets allowed" and would defeat this. Only a real audit that was asked for secrets gets them.
    allow = getattr(A, "record_secrets", False) is True
    out = {}
    for k in list(attrs or {})[:limit]:
        v = attrs[k]
        if KEY_RE.search(k) and not allow:
            try:
                out[k] = "<redacted: sha256 %s>" % hashlib.sha256(base64.b64decode(v)).hexdigest()
            except Exception:
                out[k] = "<redacted>"
        else:
            out[k] = v
    return out

def scan_for_key(node, hits):
    if not isinstance(node, dict): return
    for k, v in (node.get("attrs") or {}).items():
        if KEY_RE.search(k): hits.append((k, v))
    c = node.get("content")
    if isinstance(c, list):
        for ch in c: scan_for_key(ch, hits)


# ---------------- frame pump + orchestration ----------------
def login_failure_reason(attrs):
    """<failure> at login -> what it means for the examination."""
    code = str((attrs or {}).get("reason") or "")
    if code == "401":
        return ("login refused (401): this linked device has been logged out -- removed from the account's "
                "linked devices, by the phone or by WhatsApp. The server holds nothing for it any more, and "
                "the browser's own session has ended too. What is on disk is unaffected: decrypt it offline "
                "with the key saved by an earlier run (--key ... --offline).")
    if code == "403":
        return "login refused (403): the account or this device is blocked from connecting"
    if code == "503":
        return "login refused (503): WhatsApp's server is unavailable; try again later"
    return "login refused (%s)" % (code or attrs)

def fetch_version():
    # same source Baileys' fetchLatestBaileysVersion uses; an outdated version -> server <failure 405>
    url = "https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/src/Defaults/baileys-version.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = json.load(urllib.request.urlopen(req, timeout=10))
        v = data.get("version")
        if isinstance(v, list) and len(v) == 3: return [int(x) for x in v]
    except Exception as e:
        print("[v] version fetch failed (%s); using fallback %s" % (e, FALLBACK_VERSION), file=sys.stderr)
    return list(FALLBACK_VERSION)


import audit                                    # appends to the case DB from --audit (no-op otherwise)
A = audit.NoAudit()                             # replaced in main()

def run(creds, out_path, timeout=30, log=lambda *a: None, print_key=False):
    import websocket   # websocket-client; imported here so import errors are actionable
    noise_priv = base64.b64decode(creds["noise_priv"])
    noise_pub  = base64.b64decode(creds["noise_pub"])
    if not creds.get("account"):
        print("[!] creds has no account (adv_signed_identity missing) — re-run `wawf creds`", file=sys.stderr)
        return 6
    user, device = creds["user"], int(creds.get("device") or 0)

    eph = X25519PrivateKey.generate()
    eph_priv = eph.private_bytes_raw()
    eph_pub  = eph.public_key().public_bytes_raw()
    noise = Noise(eph_pub)

    version = fetch_version()
    log("using WA version %s" % ".".join(map(str, version)))

    A.net("out", endpoint=WS_URL, protocol="websocket", kind="connect",
          detail={"wa_version": ".".join(map(str, version)), "device": device, "user_suffix": str(user)[-4:]})
    ws = websocket.create_connection(WS_URL, timeout=20,
                                     header=["Origin: https://web.whatsapp.com",
                                             "User-Agent: Mozilla/5.0"])
    A.net("in", endpoint=WS_URL, protocol="websocket", kind="connected", status="open")
    inbuf = bytearray()
    sent_intro = [False]

    def send_frame(data):
        ws.send_binary(noise.encode_frame(data, sent_intro[0])); sent_intro[0] = True

    def pull_frames():
        """Yield complete WA frames buffered so far (raw bytes pre-finish, decoded node post-finish)."""
        while len(inbuf) >= 3:
            size = (inbuf[0] << 16) | (inbuf[1] << 8) | inbuf[2]
            if len(inbuf) < size + 3: break
            frame = bytes(inbuf[3:size + 3]); del inbuf[:size + 3]
            if noise.finished:
                yield decode_binary_node(noise.decrypt(frame))
            else:
                yield frame

    try:
        # 1. ClientHello{ephemeral}
        send_frame(_fld_len(2, _fld_len(1, eph_pub)))
        # 2. wait for ServerHello
        server_hello = None
        ws.settimeout(20)
        while server_hello is None:
            inbuf.extend(ws.recv())
            for fr in pull_frames():
                server_hello = fr; break
        sh = _pb_read(server_hello).get(3, [None])[0]      # HandshakeMessage.serverHello (field 3)
        if not sh:
            print("[!] no serverHello in first frame", file=sys.stderr); return 4
        shf = _pb_read(sh)
        try:
            sh_eph, sh_static, sh_payload = shf[1][0], shf[2][0], shf[3][0]
        except (KeyError, IndexError):
            print("[!] malformed serverHello (missing ephemeral/static/payload field)", file=sys.stderr); return 4
        # 3. process handshake -> encrypted static key
        key_enc = noise.process_handshake(sh_eph, sh_static, sh_payload, noise_priv, noise_pub, eph_priv)
        # 4. ClientFinish{static, payload=login ClientPayload}
        payload_enc = noise.encrypt(build_client_payload(user, device, version))
        send_frame(_fld_len(4, _fld_len(1, key_enc) + _fld_len(2, payload_enc)))
        noise.finish()
        log("handshake complete; awaiting <success>")
        A.crypto("handshake", algorithm="Noise_XX_25519_AESGCM_SHA256",
                 key=noise_priv, key_source="disk-recovered Noise device private key (creds_in.json)",
                 validated="handshake completed", input_desc="WhatsApp Noise login",
                 detail={"wa_version": ".".join(map(str, version)), "device": device})
        A.net("out", endpoint=WS_URL, protocol="noise/websocket", kind="login ClientFinish",
              detail={"passive": False})
        # 5. read stanzas, scan for companion_enc_static
        captured = None
        deadline = time.time() + timeout
        while time.time() < deadline and captured is None:
            ws.settimeout(max(1.0, deadline - time.time()))
            try:
                inbuf.extend(ws.recv())
            except websocket.WebSocketTimeoutException:
                break
            except (websocket.WebSocketConnectionClosedException, ConnectionError):
                log("stream closed by server"); break
            for node in pull_frames():
                tag = node.get("tag")
                log("recv <%s> %s" % (tag, {k: node["attrs"][k] for k in list(node.get("attrs", {}))[:4]}))
                A.net("in", endpoint=WS_URL, protocol="noise/websocket", kind="stanza <%s>" % tag,
                      detail={"attrs": audit_attrs(node.get("attrs"))})
                hits = []; scan_for_key(node, hits)
                if hits:
                    captured = hits[0][1]
                    log("CAPTURED %s = %s" % (hits[0][0], captured))
                    # the server-issued at-rest key: fingerprint only unless --audit-secrets
                    A.crypto("receive", algorithm="companion_enc_static (server-issued)",
                             key=base64.b64decode(captured) if captured else None,
                             key_source="<%s> stanza attribute '%s' over the Noise session" % (tag, hits[0][0]),
                             validated="captured", input_desc="post-login stanza")
                    break
                if tag == "failure":
                    A.net("in", endpoint=WS_URL, protocol="noise/websocket", kind="stanza <failure>",
                          status="login rejected", detail={"attrs": node.get("attrs")})
                    print("[!] " + login_failure_reason(node.get("attrs")), file=sys.stderr)
                    A.end_run(2, status="error", error=RuntimeError("login rejected by server"))
                    return 2
                if tag in ("stream:error", "xmlstreamend"):
                    log("stream error/end")
                    A.end_run(4, status="error", error=RuntimeError("stream error/end <%s>" % tag)); return 4
        if captured:
            with open(out_path, "w") as f: f.write(captured)
            A.artifact(out_path, kind="companion_enc_static (at-rest key captured from the server)")
            # The key is NOT printed by default. It used to go to stdout unconditionally as a
            # scripting contract ("stdout = just the key"), which meant the one secret the browser
            # never writes to disk landed in the terminal, in scrollback and in anything capturing
            # output -- and wawf does not need it, because it reads the key back from the file above.
            # --print-key restores the old behaviour for anyone who was piping it.
            if print_key:
                print(captured)
            print("[+] companion_enc_static -> %s" % os.path.abspath(out_path), file=sys.stderr)
            return 0
        print("[!] connected but no companion_enc_static seen (timeout/closed)", file=sys.stderr)
        return 5
    finally:
        try: ws.close()
        except Exception: pass


def main():
    ap = argparse.ArgumentParser(description="pure-Python WhatsApp reconnect -> companion_enc_static")
    ap.add_argument("--creds", default="creds_in.json", help="creds_in.json from `wawf creds` (default: ./creds_in.json)")
    ap.add_argument("--out", default="companion_enc_static.txt", help="write the captured key here")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--print-key", action="store_true",
                    help="also write the captured key to stdout. Off by default: the key is the one "
                         "secret the browser never stores, and stdout ends up in scrollback and logs. "
                         "The key is always written to --out regardless.")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    global A
    A = audit.from_env("reconnect")
    log = (lambda *m: print("[ns]", *m, file=sys.stderr)) if a.verbose else (lambda *m: None)
    if not os.path.exists(a.creds):
        print("[!] creds file not found: %s — run `wawf creds <profile>` first" % a.creds, file=sys.stderr)
        A.end_run(6, status="error", error=RuntimeError("creds file not found: %s" % a.creds)); return 6
    A.file_read(a.creds, purpose="reconnect credentials (disk-recovered Noise keypair)", hash_it=True)
    creds = json.load(open(a.creds, encoding="utf-8"))
    try:
        import websocket  # noqa: F401
    except ImportError:
        print("[!] the 'websocket-client' package is required (pip install websocket-client)", file=sys.stderr)
        A.end_run(6, status="error", error=RuntimeError("websocket-client not installed")); return 6
    try:
        rc = run(creds, a.out, a.timeout, log, print_key=a.print_key)
    except Exception as e:
        import traceback as _tb
        A.end_run(1, status="error", error=e, tb=_tb.format_exc()); raise
    A.end_run(rc, status=("ok" if rc == 0 else "error"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
