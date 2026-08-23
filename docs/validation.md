# Validation — wire-desktop-forensic

## Summary

The reader is validated against a **real Chromium-authored** IndexedDB store
(the bytes are produced by Google Chrome's Blink/LevelDB stack, a genuine
external encoder), minted on the host in Wire's documented Dexie schema. This is
a **tier-2** oracle: the *bytes* are external, but the *scenario* is
self-constructed, so it can miss real-Wire-app quirks. **No real Wire message
corpus was publicly available.** The self-authored unit fixtures (records built
at the reader-output seam) are **tier-3** structural checks layered under it.

## Oracle selection — the honesty rule, resolved in order

1. **App installed on this host?** No — there is no
   `~/Library/Application Support/Wire` (nor `~/.config/Wire`) on the build host,
   so no real user store could be copied.
2. **Public third-party sample?** None found. Research turned up no purpose-built,
   downloadable Wire IndexedDB forensic sample. The closest public
   Electron-messenger LevelDB corpus — [`lxndrblz/forensicsim`](https://github.com/lxndrblz/forensicsim)
   — is **Microsoft Teams**, a *different* Dexie schema, so it is not a valid Wire
   oracle. (Wire schema reference: hunjison, *Forensic Analysis of Wire Messenger
   in Windows OS* — <https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS>.)
3. **Mint a real underlying Chromium store.** Chosen. Headless Google Chrome was
   driven to open an IndexedDB database, create the Wire Dexie object stores
   (`conversations`, `events`, `users`, `clients`, `keys`), and write one record
   into each — a cleartext message (`data.content`), an encrypted message whose
   `data` is an `ArrayBuffer` (opaque Proteus-style body), a user, a client, a
   conversation with a name, and an `otr_key` record. The resulting
   `…indexeddb.leveldb` directory is committed under
   `tests/data/wire-indexeddb/` and read back through
   `chromium-storage-indexeddb` in `core/tests/oracle_minted.rs`.

**Reported validation tier: T2** for the minted-store correctness assertions,
**T1** for the differential below. The bytes are Chromium/Blink-authored (not
self-encoded); the Wire-schema scenario was constructed by us, but the decode is
independently cross-checked against a third-party reader.

## Differential against ccl_chromium_reader (tier 1)

The Chromium IndexedDB-over-LevelDB decode our reader consumes is reconciled,
record-for-record, against the independent third-party reader
[`cclgroupltd/ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chromium_reader)
reading the **same** committed minted store. Two independent implementations of
the hard part — the LevelDB key coding scheme plus the Blink/V8
`SerializedScriptValue` value deserialization — agreeing on the same bytes is
tier-1 evidence: the answer key is authored by someone else, not by us. (The
Wire *schema* field mapping — which JSON field is the sender, where the message
body lives — is shared documented knowledge applied to each side's own decode;
the byte-level decode is what the differential cross-checks.)

`core/tests/differential_ccl.rs` decodes the store with
`read_store`, shells out to `tests/ccl_oracle.py` (which drives ccl's
`ccl_chromium_indexeddb` over the identical directory), and asserts three sets
match exactly: the live `(store, key, kind)` records, every interpreted
`(store, key, field, value)`, and the encrypted-record set. On the committed
minted store all three reconcile (6 records: `conversations`/`events`/`users`/
`clients`/`keys`, the `meet at 9` cleartext body, and the `ArrayBuffer` event
classified encrypted by both).

It is **env-gated on `CCL_WIRE_ORACLE`** (a Python interpreter that can
`from ccl_chromium_reader import ccl_chromium_indexeddb`, with the clone on
`PYTHONPATH`); unset ⇒ clean skip, so CI without the oracle stays green. Set
`CCL_WIRE_DIR` to point the differential at a different Chromium IndexedDB store.

```bash
PYTHONPATH=/path/to/ccl_chromium_reader CCL_WIRE_ORACLE=$(which python3) \
    cargo test -p wire-desktop-core --test differential_ccl
```

## What the tier-2 oracle checks

Reconciled against the known writes:

- All four Wire object stores enumerate with the correct role.
- The cleartext body `meet at 9` is recovered from a real Blink V8 blob, with its
  sender (`user-alice`) and time.
- The `ArrayBuffer`-bodied message is classified `Encrypted` with no fabricated
  text; `decrypted_text()` returns `WireError::EncryptedPayloadUnrecoverable`.
- The conversation name `Incident Ops` resolves.
- The `otr_key` record is present.

The mint recipe (verbatim commands + the origin caveat) is in
`tests/data/README.md`.

## Tier-3 structural fixtures (under the oracle)

`core/tests/*.rs` and the in-module unit tests build
`IndexedDbRecord`s at the reader-output seam to exercise each record type,
encryption classification, the timeline, and the analyzer. These are
self-authored fixtures *and* expected answers — legitimate, fast, deterministic
regression scaffolding for detection/interpretation behavior, but not an
independent oracle. They sit **below** the tier-2 minted store.

## Panic-free evidence

- `#![forbid(unsafe_code)]`; `clippy::unwrap_used` / `expect_used` denied in
  production.
- Two `cargo-fuzz` targets (`fuzz_interpret_records`, `fuzz_forensic`) over
  arbitrary bytes; smoke-run locally at 20,000 runs each with no crash, and CI
  runs 100k/target on nightly. Invariant: never panic.

## What would upgrade this further

- **Real Wire corpus:** a real Wire desktop profile captured from an actual
  installation (or a published third-party DFIR sample with ground truth) would
  upgrade the *scenario* from self-constructed to real, running the same ccl
  differential over genuine Wire app output rather than a minted store.
- **A second independent oracle:** Google's
  [`dfindexeddb`](https://github.com/google/dfindexeddb) over the same bytes,
  reconciled the same way, would add a second cross-check alongside ccl.

The current, honestly-labelled evidence is a **tier-1 differential** against
`ccl_chromium_reader` (independent decoder, same bytes) over a tier-2
Chromium-authored minted store, plus tier-3 structural fixtures under it.
