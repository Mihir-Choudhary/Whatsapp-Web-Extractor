#!/usr/bin/env python3
"""signal_sessions.py — translate WhatsApp Web's Signal session / sender-key records into the
serialisation the Node `libsignal` (and Baileys' Group cipher) expect.

Why this exists
---------------
Recovering the identity key, registrationId and prekeys is enough to *authenticate* a reconnect,
but not to *decrypt*: every inbound E2E payload — including the `historySyncNotification` the phone
sends back for an on-demand history request — is encrypted to an existing Double Ratchet session.
Without the session store every inbound message fails with SessionError and is dropped before it
can be processed, which is exactly why `--history` returned nothing while the browser's own
"load older messages" button worked.

WhatsApp Web keeps these sessions in IndexedDB `signal-storage/session-store`, in PLAINTEXT (the
ratchet state is not wrapped by the at-rest key), so they can be read straight out of a profile.
Its serialisation differs from the `libsignal` npm package's, so the fields are remapped here.

Browser `session-store` record          ->  libsignal SessionRecord.serialize()
  address "<user>[:dev]@lid.0"              store key "<user>.<dev>"  (Baileys ProtocolAddress)
  remote.regId                              registrationId
  sendChain.ratchetKey.{serializedPubKey,   currentRatchet.ephemeralKeyPair.{pubKey,privKey}
                        privateKey}
  rootKey                                   currentRatchet.rootKey
  prevSendChainHighestIndex                 currentRatchet.previousCounter
  recvChains[-1].ratchetPubKey              currentRatchet.lastRemoteEphemeralKey
  aliceBaseKey                              indexInfo.baseKey  (also the _sessions map key)
  remote.pubKey                             indexInfo.remoteIdentityKey
  sendChain / recvChains[]                  _chains[<b64 ratchet pubkey>]
  initialExchangeInfo                       pendingPreKey
  prevSessions[]                            additional, closed, entries in the same _sessions map

Chain index convention: the browser stores `nextMsgIndex` (the index the NEXT message on that
chain will carry); libsignal stores `chainKey.counter` (the index of the LAST key derived), so
counter = nextMsgIndex - 1. Verified against libsignal's fillMessageKeys(), which derives
messageKeys[counter + 1] and is called with `chain.chainKey.counter + 1` when sending and with
`message.counter` when receiving.

No key material is logged by this module; it only re-encodes it.
"""
from __future__ import annotations
import base64, time
from idbutil import as_bytes as ab

# libsignal/src/base_key_type.js and chain_type.js
BASE_KEY_OURS, BASE_KEY_THEIRS = 1, 2
CHAIN_SENDING, CHAIN_RECEIVING = 1, 2
SESSION_RECORD_VERSION = "v1"


def _b64(b):
    return base64.b64encode(bytes(b)).decode()


def _i(v, default=0):
    """CCL hands back V8 numbers that can be floats ('2.0'); libsignal compares them as ints."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def signal_address(addr):
    """'133...:41@lid.0' -> '133....41'.

    Baileys addresses a session as `ProtocolAddress(user, device).toString()`, i.e. the jid's user
    part (server stripped) and the device from the ':NN' suffix. WhatsApp Web instead uses the
    whole jid as the id and a constant 0 device, so the trailing '.0' is NOT the device number.
    """
    s = str(addr or "")
    if "@" not in s:
        return None
    user = s.split("@", 1)[0]
    dev = 0
    if ":" in user:
        user, d = user.rsplit(":", 1)
        dev = _i(d)
    return f"{user}.{dev}" if user else None


def sender_key_name(name):
    """'<group>@g.us::<user>[:dev]@lid.0' -> '<group>@g.us::<user>::<dev>' (Baileys SenderKeyName).

    Split on the FIRST '::' — the group part can itself contain '@' ('status@broadcast').
    """
    s = str(name or "")
    if "::" not in s:
        return None
    group, sender = s.split("::", 1)
    user = sender.split("@", 1)[0]
    dev = 0
    if ":" in user:
        user, d = user.rsplit(":", 1)
        dev = _i(d)
    return f"{group}::{user}::{dev}" if group and user else None


def _chain(pub, chain_key, next_idx, chain_type):
    """One entry of libsignal's `_chains`, keyed by the base64 ratchet public key."""
    return _b64(pub), {
        "chainKey": {"counter": _i(next_idx) - 1, "key": _b64(chain_key)},
        "chainType": chain_type,
        # The browser's per-chain `unusedMsgKeys` hold full MessageKey structures (cipher key +
        # mac key + iv), not libsignal's single 32-byte seed, so they are not portable. They were
        # empty in every observed record; skipped rather than mistranslated.
        "messageKeys": {},
    }


def _entry(reg_id, ratchet_pub, ratchet_priv, root_key, prev_counter, last_remote,
           base_key, base_key_type, remote_identity, chains, closed, used, pending=None):
    e = {
        "registrationId": _i(reg_id),
        "currentRatchet": {
            "ephemeralKeyPair": {"pubKey": _b64(ratchet_pub), "privKey": _b64(ratchet_priv)},
            "lastRemoteEphemeralKey": _b64(last_remote),
            "previousCounter": _i(prev_counter),
            "rootKey": _b64(root_key),
        },
        "indexInfo": {
            "baseKey": _b64(base_key),
            "baseKeyType": base_key_type,
            "closed": closed,
            "used": used,
            "created": used,
            "remoteIdentityKey": _b64(remote_identity),
        },
        "_chains": chains,
    }
    if pending:
        e["pendingPreKey"] = pending
    return e


def convert_current(sess):
    """The live session object (`session-store` record -> `session`). Returns an entry or None."""
    if not isinstance(sess, dict):
        return None
    sc = sess.get("sendChain") or {}
    rk = sc.get("ratchetKey") or {}
    pub, priv = ab(rk.get("serializedPubKey")), ab(rk.get("privateKey"))
    root = ab(sess.get("rootKey"))
    remote = sess.get("remote") or {}
    rid = ab(remote.get("pubKey"))
    base = ab(sess.get("aliceBaseKey"))
    if not (pub and priv and root and rid and base):
        return None

    chains = {}
    ck = ab(sc.get("chainKey"))
    if ck:
        k, v = _chain(pub, ck, sc.get("nextMsgIndex"), CHAIN_SENDING)
        chains[k] = v
    last_remote = None
    for rc in (sess.get("recvChains") or []):
        if not isinstance(rc, dict):
            continue
        rpub, rck = ab(rc.get("ratchetPubKey")), ab(rc.get("chainKey"))
        if not (rpub and rck):
            continue
        k, v = _chain(rpub, rck, rc.get("nextMsgIndex"), CHAIN_RECEIVING)
        chains[k] = v
        last_remote = rpub          # newest chain last; only used to back-fill skipped message
                                    # keys when the ratchet steps
    # lastRemoteEphemeralKey must be a Buffer for libsignal. If we have never received on this
    # session, any non-matching key is harmless: maybeStepRatchet simply finds no previous chain.
    if last_remote is None:
        last_remote = rid

    # WhatsApp Web keeps `initialExchangeInfo` only while our own PreKeyWhisperMessage is still
    # unanswered, which is precisely libsignal's `pendingPreKey` — and it exists only when WE were
    # the initiator, so it also tells us the base key stored here is ours.
    ie = sess.get("initialExchangeInfo")
    pending = None
    bkt = BASE_KEY_THEIRS
    if isinstance(ie, dict):
        lp = ab(ie.get("localOneTimePubKey"))
        if lp:
            pending = {"signedKeyId": _i(ie.get("remoteSignedId")),
                       "baseKey": _b64(lp),
                       "preKeyId": _i(ie.get("remoteOneTimeId"))}
            bkt = BASE_KEY_OURS

    now = int(time.time() * 1000)
    return _entry(remote.get("regId"), pub, priv, root, sess.get("prevSendChainHighestIndex"),
                  last_remote, base, bkt, rid, chains, -1, now, pending)


def convert_previous(ps, closed_ms, used_ms):
    """An entry of `prevSessions`, which uses WhatsApp's older SessionStructure-style field names
    (senderChain / receiverChains / chainKey.index) rather than the live object's."""
    if not isinstance(ps, dict):
        return None
    sc = ps.get("senderChain") or {}
    pub, priv = ab(sc.get("senderRatchetKey")), ab(sc.get("senderRatchetKeyPrivate"))
    root = ab(ps.get("rootKey"))
    rid = ab(ps.get("remoteIdentityPublic"))
    base = ab(ps.get("aliceBaseKey"))
    if not (pub and priv and root and rid and base):
        return None

    chains = {}
    ck = sc.get("chainKey") or {}
    ckk = ab(ck.get("key"))
    if ckk:
        k, v = _chain(pub, ckk, ck.get("index"), CHAIN_SENDING)
        chains[k] = v
    last_remote = None
    for rc in (ps.get("receiverChains") or []):
        if not isinstance(rc, dict):
            continue
        rpub = ab(rc.get("senderRatchetKey"))
        rck = rc.get("chainKey") or {}
        rckk = ab(rck.get("key"))
        if not (rpub and rckk):
            continue
        k, v = _chain(rpub, rckk, rck.get("index"), CHAIN_RECEIVING)
        chains[k] = v
        last_remote = rpub
    if last_remote is None:
        last_remote = rid

    return _entry(ps.get("remoteRegistrationId"), pub, priv, root, ps.get("previousCounter"),
                  last_remote, base, BASE_KEY_THEIRS, rid, chains, closed_ms, used_ms)


def build_sessions(records, warn=None):
    """`session-store` records -> {"<user>.<dev>": <SessionRecord.serialize() shape>}.

    A LevelDB object store keeps older versions of a record alongside the live one and we read
    them all (an overwritten session is evidence), so the same address can appear several times.
    `records` MUST therefore be newest-first, which is what chromium_reader.read_indexeddb
    guarantees by ordering on `is_live` + `ldb_seq_no`; the Firefox path has one row per key.

    Ordering matters for correctness, not just tidiness: a DH ratchet step resets both chains'
    message indices to zero, so the current state can look "less advanced" than the copy it
    replaced. Picking by contents rather than by write order selects a stale root key and every
    inbound message then fails with Bad MAC.

    Superseded states are kept as CLOSED entries so messages encrypted under an older ratchet
    still decrypt; libsignal's getOpenSession() returns the first entry that is not closed, so
    exactly one entry per address — the live one — is left open.
    """
    by_addr, skipped = {}, 0
    for r in records or []:
        if not isinstance(r, dict):
            continue
        addr = signal_address(r.get("address"))
        sess = r.get("session")
        if not addr or not isinstance(sess, dict):
            skipped += 1
            continue
        by_addr.setdefault(addr, []).append(sess)

    out, stale, now = {}, 0, int(time.time() * 1000)
    for addr, versions in by_addr.items():
        stale += len(versions) - 1
        entries, age = {}, 0
        for vi, sess in enumerate(reversed(versions)):      # oldest first: the live copy lands last
            live = (vi == len(versions) - 1)
            for ps in (sess.get("prevSessions") or []):
                age += 1
                e = convert_previous(ps, closed_ms=now - age * 1000, used_ms=now - age * 1000)
                if e:
                    entries[e["indexInfo"]["baseKey"]] = e
            cur = convert_current(sess)
            if cur:
                if not live:                                # an overwritten copy of this session
                    age += 1
                    cur["indexInfo"]["closed"] = cur["indexInfo"]["used"] = now - age * 1000
                    cur["indexInfo"]["created"] = cur["indexInfo"]["used"]
                entries[cur["indexInfo"]["baseKey"]] = cur  # live state wins a base-key collision
        if entries:
            out[addr] = {"_sessions": entries, "version": SESSION_RECORD_VERSION}
        else:
            skipped += len(versions)
    if warn:
        if skipped:
            warn(f"{skipped} session record(s) could not be translated and were skipped")
        if stale:
            warn(f"{stale} superseded session record(s) found in the store; kept as closed sessions")
    return out


def build_sender_keys(records, warn=None):
    """`senderkey-store` records -> {"<group>::<user>::<dev>": [SenderKeyState structure, ...]}.

    Baileys' SenderChainKey.iteration has the same "next index" meaning as the browser's
    nextMsgIndex (group_cipher derives up to the requested iteration, then stores getNext()), so
    unlike the 1:1 chains it maps across unshifted.
    """
    merged, skipped = {}, 0        # name -> {senderKeyId: state}
    for r in records or []:
        if not isinstance(r, dict):
            continue
        name = sender_key_name(r.get("senderKeyName"))
        states = ((r.get("senderKey") or {}).get("senderKeyStates")) or []
        if not name:
            skipped += 1
            continue
        got = False
        for st in states:
            if not isinstance(st, dict):
                continue
            ckw = st.get("senderKeyChainKey") or {}
            seed, pubk = ab(ckw.get("chainKey")), ab(st.get("senderSigningKeyPublic"))
            if not (seed and pubk):
                continue
            signing = {"public": _b64(pubk)}
            privk = ab(st.get("senderSigningKeyPrivate"))
            if privk:
                signing["private"] = _b64(privk)
            key_id = _i(st.get("senderKeyId"))
            state = {
                "senderKeyId": key_id,
                "senderChainKey": {"iteration": _i(ckw.get("nextMsgIndex")), "seed": _b64(seed)},
                "senderSigningKey": signing,
                "senderMessageKeys": [],
            }
            # Same dedup problem as sessions: superseded copies of a record are still in the store.
            # Keep the furthest-advanced chain per key id — an older chain key cannot ratchet
            # forward to reach a newer one's position without the intervening derivations.
            prev = merged.setdefault(name, {}).get(key_id)
            if prev is None or state["senderChainKey"]["iteration"] > prev["senderChainKey"]["iteration"]:
                merged[name][key_id] = state
            got = True
        if not got:
            skipped += 1
    out = {n: list(states.values()) for n, states in merged.items() if states}
    if skipped and warn:
        warn(f"{skipped} sender-key record(s) could not be translated and were skipped")
    return out
