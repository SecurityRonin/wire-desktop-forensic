#!/usr/bin/env python3
"""Independent-oracle driver for the wire-desktop ccl differential test.

Reads the SAME Chromium IndexedDB-over-LevelDB store our reader consumes
(``…​.indexeddb.leveldb``) with the third-party
`cclgroupltd/ccl_chromium_reader <https://github.com/cclgroupltd/ccl_chromium_reader>`_
and emits its decoded view on stdout for the Rust harness
(``tests/differential_ccl.rs``) to reconcile against ``wire_desktop_core::read_store``.

Two independent implementations of the hard part — the LevelDB key coding plus
the Blink/V8 ``SerializedScriptValue`` value decode — agreeing on the same bytes
is the tier-1 evidence. The Wire *schema* field mapping (which JSON field is the
"sender", where the message body lives) is shared documented knowledge, applied
here to ccl's own independent decode exactly as ``wire-desktop-core`` applies it
to its own decode; the byte-level decode is what is being cross-checked.

Point ``CCL_WIRE_ORACLE`` at a Python interpreter that can import ccl (add the
clone to ``PYTHONPATH``):

    PYTHONPATH=/path/to/ccl_chromium_reader CCL_WIRE_ORACLE=$(which python3) \
        cargo test -p wire-desktop-core --test differential_ccl

Output is a hex-encoded, tab-separated line stream (hex sidesteps every
delimiter/encoding hazard in decoded values):

    REC\t<hex store>\t<hex key>\t<hex kind>              # one per live record
    FIELD\t<hex store>\t<hex key>\t<hex field>\t<hex value>  # one per interpreted field
    ENC\t<hex store>\t<hex key>                          # record body is opaque/encrypted

Only *live* records are emitted (``iterate_records(live_only=True)``); the Rust
side reconciles the same live (non-tombstone) view.
"""

import pathlib
import sys

from ccl_chromium_reader import ccl_chromium_indexeddb as idb

# Wire Dexie object store -> forensic role. Mirrors
# WireRecordKind::from_store_name in wire-desktop-core (shared documented Wire
# schema knowledge, not decode logic).
_KIND = {
    "conversations": "conversation",
    "events": "event",
    "users": "user",
    "clients": "client",
}

# Documented ciphertext-marker fields (mirrors is_encrypted_payload).
_CIPHER_MARKERS = ("cipher_text", "cipherText", "otr", "encrypted")


def _hex(s: str) -> str:
    return s.encode("utf-8").hex()


def _scalar_text(x):
    """Render a scalar leaf to text; None for containers/binary.

    Mirrors wire-desktop-core's `as_text`: only String/number/bool leaves have a
    text form; dict/bytes/list/None do not.
    """
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, str):
        return x
    if isinstance(x, int):
        return str(x)
    if isinstance(x, float):
        # Match Rust's f64 Display for integral values (e.g. 2.0 -> "2").
        return str(int(x)) if x.is_integer() else repr(x)
    return None


def _message_text(v):
    """Cleartext body: data.content/data.text, then top-level content/text.

    Mirrors wire-desktop-core's `message_text`.
    """
    if isinstance(v, dict):
        data = v.get("data")
        if isinstance(data, dict):
            for f in ("content", "text"):
                if f in data:
                    t = _scalar_text(data[f])
                    if t is not None:
                        return t
        for f in ("content", "text"):
            if f in v:
                t = _scalar_text(v[f])
                if t is not None:
                    return t
    return None


def _is_encrypted(v):
    """Opaque/ciphered body with no cleartext. Mirrors is_encrypted_payload.

    ccl decodes a Blink ArrayBuffer to `bytes`.
    """
    if isinstance(v, (bytes, bytearray)):
        return True
    if not isinstance(v, dict):
        return False
    data = v.get("data")
    if isinstance(data, (bytes, bytearray)):
        return True
    for m in _CIPHER_MARKERS:
        if m in v:
            return True
        if isinstance(data, dict) and m in data:
            return True
    return False


def _key_text(key) -> str:
    """Render an IdbKey to the same text form as wire-desktop-core::render_key.

    This minted store keys everything with strings; other shapes fall back to a
    stable str() so a divergence fails loud rather than silently.
    """
    val = getattr(key, "value", key)
    if isinstance(val, str):
        return val
    if isinstance(val, (bytes, bytearray)):
        return "0x" + val.hex()
    return str(val)


def _fields_for(kind, v):
    """Interpreted scalar fields, mirroring wire-desktop-core's per-role fill_*.

    Returns an ordered list of (field_name, value) that our WireRecord surfaces
    as `Some`. Only known kinds extract fields (Unknown stores stay bare).
    """
    out = []
    if not isinstance(v, dict):
        return out
    if kind == "conversation":
        cid = _scalar_text(v.get("id"))
        if cid is not None:
            out.append(("id", cid))
            out.append(("conversation", cid))  # fill_conversation sets conversation = id
        name = _scalar_text(v.get("name"))
        if name is not None:
            out.append(("name", name))
    elif kind == "event":
        eid = _scalar_text(v.get("id"))
        if eid is not None:
            out.append(("id", eid))
        conv = _scalar_text(v.get("conversation"))
        if conv is not None:
            out.append(("conversation", conv))
        sender = v.get("from", v.get("sender"))
        sender = _scalar_text(sender)
        if sender is not None:
            out.append(("sender", sender))
        time = _scalar_text(v.get("time"))
        if time is not None:
            out.append(("time", time))
        mt = _scalar_text(v.get("type"))
        if mt is not None:
            out.append(("message_type", mt))
        text = _message_text(v)
        if text is not None:
            out.append(("text", text))
    elif kind == "user":
        uid = _scalar_text(v.get("id"))
        if uid is not None:
            out.append(("id", uid))
        name = _scalar_text(v.get("name"))
        if name is not None:
            out.append(("name", name))
    elif kind == "client":
        cid = _scalar_text(v.get("id"))
        if cid is not None:
            out.append(("id", cid))
        name = v.get("model", v.get("class", v.get("label")))
        name = _scalar_text(name)
        if name is not None:
            out.append(("name", name))
    return out


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: ccl_oracle.py <indexeddb-leveldb-dir>\n")
        return 2
    store_dir = pathlib.Path(argv[1])
    if not store_dir.is_dir():
        sys.stderr.write(f"not a directory: {store_dir}\n")
        return 2

    wdb = idb.WrappedIndexDB(store_dir)
    out = []
    for dbid in wdb.database_ids:
        db = wdb[dbid.dbid_no]
        for store_name in db.object_store_names:
            store = db.get_object_store_by_name(store_name)
            kind = _KIND.get(store_name, "unknown")
            for rec in store.iterate_records(live_only=True):
                key = _key_text(rec.key)
                out.append(f"REC\t{_hex(store_name)}\t{_hex(key)}\t{_hex(kind)}")
                for fname, fval in _fields_for(kind, rec.value):
                    out.append(
                        f"FIELD\t{_hex(store_name)}\t{_hex(key)}\t{_hex(fname)}\t{_hex(fval)}"
                    )
                # Encryption classification only applies to the events store,
                # matching wire-desktop-core (fill_event is the only caller).
                if kind == "event" and _is_encrypted(rec.value):
                    out.append(f"ENC\t{_hex(store_name)}\t{_hex(key)}")

    sys.stdout.write("\n".join(out))
    if out:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
