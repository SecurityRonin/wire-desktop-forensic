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
   `chromium-storage-indexeddb` in `wire-desktop-core/tests/oracle_minted.rs`.

**Reported validation tier: T2.** The bytes are Chromium/Blink-authored (not
self-encoded), but the Wire-schema scenario was constructed by us.

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

`wire-desktop-core/tests/*.rs` and the in-module unit tests build
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

## What would upgrade this

- **Tier-1:** a real Wire desktop profile captured from an actual installation
  (or a published third-party DFIR sample with ground truth). Reconcile the
  interpreted records against an independent parser — `ccl_chrome_indexeddb` or
  Google's [`dfindexeddb`](https://github.com/google/dfindexeddb) — over the same
  store, and compare object-store contents record-for-record.
- **Cross-tool differential:** run `dfindexeddb` on the committed minted store and
  reconcile its record dump against this reader's output (an independent oracle
  over the same bytes), even before a real corpus is available.

Neither is claimed today; the current, honestly-labelled evidence is tier-2 over
Chromium-authored bytes plus tier-3 structural fixtures.
