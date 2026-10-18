#!/usr/bin/env python3
"""check_identity.py — do the exported credentials still describe the device this profile is on?

Why this exists
---------------
`creds_in.json` and `signal_state.json` are a SNAPSHOT of one companion registration. When WhatsApp
Web re-pairs — which is exactly what "reconnecting WhatsApp Web" does, and what happens by itself
when a linked device is revoked — the account gets a new device slot with a brand-new registrationId
and a brand-new Signal identity key. The exported files then describe a device that no longer exists.

Nothing about that is visible at runtime. A revoked companion still completes the Noise handshake and
still reaches Baileys' `open`, so the tool connects happily, asks every chat, receives nothing, and
the symptom — silence — is indistinguishable from throttling, from an exhausted chat, or from a phone
that is simply declining. Measured on a real profile: stored regId 10115 / device :43 against a live
profile on regId 11966 / device :44, with a different signedIdentityKey. That single fact accounts for
a long run of "history worked, then stopped, then worked again after I reopened WhatsApp Web":
reopening re-paired the browser, and re-exporting afterwards is what actually fixed it.

This is a pure READ of the profile and the two files — no network, nothing touched.

  python3 scripts/check_identity.py --profile <Chromium ...Default> [--dir tools/reconnect]
  python3 scripts/check_identity.py --origin  <FF web.whatsapp.com dir> [--dir .]

Exit 0 = the exports match the profile. Exit 1 = stale, re-export. Exit 2 = could not tell.
"""
import argparse, json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_red = lambda s: re.sub(r'\d{5,}', lambda m: m.group()[:4] + '*' * (len(m.group()) - 4), str(s))


def _load(path):
    try:
        with open(path, encoding='utf-8') as f:          # utf-8 explicitly: never the locale codepage
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[!] {os.path.basename(path)} is unreadable ({e})")
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', help='Chromium profile dir (Chrome/Edge/Brave .../Default)')
    ap.add_argument('--origin', help='Firefox web.whatsapp.com storage dir')
    ap.add_argument('--dir', default='.', help='where creds_in.json / signal_state.json live')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()

    creds = _load(os.path.join(a.dir, 'creds_in.json'))
    state = _load(os.path.join(a.dir, 'signal_state.json'))
    if creds is None or state is None:
        missing = [n for n, v in (('creds_in.json', creds), ('signal_state.json', state)) if v is None]
        print(f"[?] nothing to check: {', '.join(missing)} not present under {os.path.abspath(a.dir)}")
        return 2

    # 1. the two exports must agree with EACH OTHER. They are produced by separate steps, and `creds`
    #    is assembled from both, so a partial refresh yields one device's identity with another's
    #    registration -- which authenticates as nothing and cannot be diagnosed from the symptom.
    c_reg, s_reg = creds.get('registrationId'), state.get('registrationId')
    if c_reg is not None and s_reg is not None and int(c_reg) != int(s_reg):
        print(f"[x] STALE (inconsistent): creds_in.json says regId {c_reg} (device :{creds.get('device')}) "
              f"but signal_state.json says regId {s_reg}. One was refreshed without the other.")
        print("    FIX: re-export both from the same profile.")
        return 1

    # 2. and they must agree with the profile as it is NOW.
    eng = ['--profile', a.profile] if a.profile else (['--origin', a.origin] if a.origin else None)
    if not eng:
        print('[?] pass --profile or --origin to compare against the live profile '
              '(the two files agree with each other, which is all that can be checked without it)')
        return 2
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, 'fresh.json')
        # A onefile binary cannot exec a loose .py, so when frozen go through wawf's own `_runpy`
        # dispatch (the same route _sub uses) instead of naming the script by path.
        if getattr(sys, 'frozen', False):
            cmd = [sys.executable, '_runpy', 'export_signal_state.py', *eng, '--out', out]
        else:
            cmd = [sys.executable, os.path.join(HERE, 'export_signal_state.py'), *eng, '--out', out]
        env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUTF8='1')   # never the locale codepage
        r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=env)
        if r.returncode != 0 or not os.path.exists(out):
            print('[?] could not read the profile to compare '
                  f"({(r.stderr or r.stdout or '').strip().splitlines()[-1] if (r.stderr or r.stdout) else 'no output'})")
            return 2
        fresh = _load(out)
    if fresh is None:
        return 2

    f_reg = fresh.get('registrationId')
    old_id = (state.get('signedIdentityKey') or {}).get('public')
    new_id = (fresh.get('signedIdentityKey') or {}).get('public')
    same_reg = (s_reg is not None and f_reg is not None and int(s_reg) == int(f_reg))
    same_id = (old_id is not None and old_id == new_id)

    if same_reg and same_id:
        if not a.quiet:
            print(f"[+] exports are CURRENT: regId {f_reg}, device :{creds.get('device')} "
                  f"({_red(creds.get('me_id'))}), identity key matches the profile")
        return 0

    print("[x] STALE: the exported credentials describe a device the profile is no longer on.")
    print(f"      registrationId     exported {s_reg}  ->  profile {f_reg}"
          + ("   (same)" if same_reg else "   *** CHANGED ***"))
    print(f"      signedIdentityKey  {'same' if same_id else '*** CHANGED *** (a different Signal identity)'}")
    print(f"      exported device    :{creds.get('device')}  ({_red(creds.get('me_id'))})")
    print(f"      sessions           exported {len(state.get('sessions') or {})}  ->  profile {len(fresh.get('sessions') or {})}")
    print("    WhatsApp Web has re-paired since these were exported, so this registration is gone.")
    print("    Running --history with them authenticates as the dead device: it will connect, ask every")
    print("    chat, and get nothing back -- which looks exactly like throttling but is not.")
    print("    FIX: re-export. `wawf <PROFILE> --history` does this on every run; for the diag_*.js tools, re-run")
    print("    the creds export and scripts/export_signal_state.py first.")
    return 1


if __name__ == '__main__':
    sys.exit(main())
