#!/usr/bin/env python3
"""idbutil.py — shared Firefox IndexedDB helpers.

Firefox assigns object_store ids in creation order, so they are per-profile and MUST NOT be
hardcoded. Look stores up by name instead.
"""
def store_id(conn, name):
    """Return the object_store id for `name` in a Firefox IndexedDB .sqlite, or None if absent."""
    return {n: i for i, n in conn.execute("SELECT id,name FROM object_store")}.get(name)

def as_bytes(x):
    """Coerce an IndexedDB value to bytes across engines: raw bytes, latin-1 str (Firefox),
    list/tuple, {'__bytes'/'__bytes__'} wrappers, or a ccl Chromium CryptoKey (.key_data)."""
    if isinstance(x, (bytes, bytearray)): return bytes(x)
    if isinstance(x, str): return x.encode('latin-1', 'ignore')
    if isinstance(x, (list, tuple)):
        try: return bytes(x)
        except Exception: return None
    if isinstance(x, dict):
        for k in ('__bytes', '__bytes__'):
            if k in x: return bytes(x[k])
    if hasattr(x, 'key_data'): return bytes(x.key_data)
    return None
