#!/usr/bin/env python3
"""selftest_binary.py — the stanza encoder (wa_binary) against the decoder and against Baileys.

Always: every case round-trips through wa_reconnect's decoder. With Node and Baileys available (see
selftest_signal.py), every case is also encoded by Baileys' own encodeBinaryNode and must match byte for
byte.

Run:  python3 scripts/selftest_binary.py        (exit 0 = all cases pass)
"""
import os, sys, json, base64, shutil, subprocess, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import wa_binary as B, wa_reconnect as R
FAIL = []
def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: FAIL.append(name)
N = B.node
CASES = [
 N('iq', {'id': 'abc.123-4', 'to': 's.whatsapp.net', 'type': 'get', 'xmlns': 'encrypt'}, [N('count')]),
 N('iq', {'id': '1', 'to': 's.whatsapp.net', 'type': 'get', 'xmlns': 'encrypt'}, [N('key', {}, [N('user', {'jid': '123456789012345@lid'})])]),
 N('message', {'to': '123456789012345@lid', 'id': '3EB0A1B2C3D4E5F60718', 'type': 'text', 'category': 'peer', 'push_priority': 'high_force'},
   [N('enc', {'v': '2', 'type': 'pkmsg'}, bytes(range(256)) * 5), N('device-identity', {}, b'\x00' * 300)]),
 N('receipt', {'to': '919000000001:7@s.whatsapp.net', 'id': 'ABCDEF0123', 'type': 'peer_msg'}),
 N('receipt', {'to': '123456789012345:3@lid', 'id': 'ABCDEF0123', 'type': 'retry'}, [N('retry', {'count': '1', 'id': 'X', 't': '1791720490', 'v': '1'})]),
 N('ib', {}, [N('offline_batch', {'count': '100'})]),
 N('presence', {'type': 'available', 'name': 'Forensic Recovery 1.0'}),
 N('media', {'value': 'x' * 300}, b'y' * (1 << 20)),
 N('x', {'a': '-12.5', 'b': '00FF', 'c': 'abc@weird.server', 'd': 'odd1', 'e': '1234567', 'f': 'ab'}, 'plain content with spaces'),
 N('ack', {'id': 'ABC', 'class': 'message', 'to': '120363000000000000@g.us', 'participant': '12345@lid'}),
 N('iq', {'id': '2', 'xmlns': 'w:m', 'type': 'set', 'to': 's.whatsapp.net'}, [N('media_conn')]),
]
def norm(n):
    c = n['content']
    if isinstance(c, list): c = [norm(x) for x in c]
    elif isinstance(c, str): c = c.encode()
    elif isinstance(c, (bytes, bytearray)): c = bytes(c)
    return {'tag': n['tag'], 'attrs': {k: str(v) for k, v in n['attrs'].items()}, 'content': c}
print("round trip through the decoder")
check("every case decodes back to itself", all(norm(R.decode_binary_node(B.encode_binary_node(c))) == norm(c) for c in CASES))
mods = os.environ.get("WAWF_XTEST_NODE_MODULES") or os.path.join(os.path.dirname(HERE), "tools", "reconnect", "node_modules")
node = shutil.which("node") or (r"C:\Program Files\nodejs\node.exe" if os.path.isfile(r"C:\Program Files\nodejs\node.exe") else None)
harness = os.path.join(os.path.dirname(HERE), "tests", "crosscheck", "enc.js")
if node and os.path.isdir(os.path.join(mods, "@whiskeysockets", "baileys")):
    print("against Baileys' encodeBinaryNode")
    def tojs(n):
        c = n['content']
        if isinstance(c, (bytes, bytearray)): c = {'b64': base64.b64encode(c).decode()}
        elif isinstance(c, list): c = [tojs(x) for x in c]
        return {'tag': n['tag'], 'attrs': n['attrs'], 'content': c}
    d = tempfile.mkdtemp(); p = os.path.join(d, "cases.json"); json.dump([tojs(c) for c in CASES], open(p, "w"))
    try:
        out = json.loads(subprocess.run([node, harness, p], capture_output=True, text=True, check=True,
                                        env=dict(os.environ, NODE_PATH=mods)).stdout)
        check("%d stanzas byte-identical to Baileys" % len(CASES), out == [B.encode_binary_node(c).hex() for c in CASES])
    finally:
        shutil.rmtree(d, ignore_errors=True)
else:
    print("Baileys not available: byte-for-byte comparison skipped")
print()
if FAIL:
    print(f"{len(FAIL)} CASE(S) FAILED"); [print("  - " + f) for f in FAIL]; sys.exit(1)
print("all binary cases pass")
