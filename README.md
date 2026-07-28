# wire-desktop-forensic

[![Crates.io core](https://img.shields.io/crates/v/wire-desktop-core.svg?label=wire-desktop-core)](https://crates.io/crates/wire-desktop-core)
[![Crates.io forensic](https://img.shields.io/crates/v/wire-desktop-forensic.svg?label=wire-desktop-forensic)](https://crates.io/crates/wire-desktop-forensic)
[![Docs.rs](https://img.shields.io/docsrs/wire-desktop-core?label=docs.rs)](https://docs.rs/wire-desktop-core)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/wire-desktop-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/wire-desktop-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20line-brightgreen.svg)](docs/validation.md)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![input-fuzzed](https://img.shields.io/badge/input-fuzzed-success.svg)](fuzz)
[![Security advisories: clean](https://img.shields.io/badge/advisories-clean-success.svg)](deny.toml)

**Read a Wire desktop chat store the way an investigator needs it — typed records and a timeline out of the Chromium IndexedDB, with encrypted message bodies flagged honestly instead of faked.**

Wire desktop is an Electron wrapper over the Wire web client; all of its evidence
lives in one Chromium IndexedDB store
(`IndexedDB/https_app.wire.com_0.indexeddb.leveldb`), laid out as Dexie object
stores. This suite sits on top of the fleet's Chromium IndexedDB reader and turns
those generic records into Wire conversations, events, users, and clients — and
tells you which message bodies you can read and which you cannot.

## Above the fold

```rust
use wire_desktop_core::read_profile;
use wire_desktop_forensic::audit_store;

// Point at a Wire profile directory (Electron userData, e.g.
// ~/Library/Application Support/Wire) — the store path is resolved from the
// forensicnomicon Wire spec, not hardcoded here.
let store = read_profile(std::path::Path::new("/evidence/Wire"))?;

for f in audit_store(&store) {
    println!("[{:?}] {} — {}", f.severity, f.code, f.note);
}
// [Some(Low)]  WIRE-MESSAGE-CLEARTEXT                 — a cleartext message body was recovered …
// [Some(Info)] WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE   — client-side (Proteus) encrypted; key not in OS Safe Storage …
// [Some(Medium)] WIRE-RECORD-DELETED-RESIDUAL         — a deleted Wire record survives as a LevelDB tombstone …
# Ok::<(), wire_desktop_core::WireError>(())
```

## The two crates

| Crate | Role |
|---|---|
| **`wire-desktop-core`** | Reader — interprets the IndexedDB Dexie stores into typed [`WireRecord`]s (`conversation` / `event` / `user` / `client`) + a chronological timeline. No findings. |
| **`wire-desktop-forensic`** | Analyzer — audits an interpreted store into canonical `forensicnomicon::report::Finding`s. |

It reads through the Wave-2 [`chromium-storage-indexeddb`](https://github.com/SecurityRonin/chromium-storage-forensic)
reader (LevelDB key coding + Blink V8 value decode) and reuses the Wire spec from
[`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) — it owns no
LevelDB or path knowledge of its own.

## Anomaly codes

| Code | Severity | Category | Meaning |
|---|---|---|---|
| `WIRE-MESSAGE-CLEARTEXT` | Low | Residue | a cleartext message body was recovered from the store |
| `WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE` | Info | Provenance | a message body is client-side (Proteus) encrypted; the key is not in the OS Safe Storage, so plaintext is unrecoverable |
| `WIRE-RECORD-DELETED-RESIDUAL` | Medium | Residue | a tombstoned (deleted) Wire record survives in the LevelDB and was recovered |
| `WIRE-OTR-KEY-PRESENT` | High | Threat | the Wire `otr_key` (attachment key) is present in the IndexedDB — recoverable key material (MITRE T1552) |

## Encrypted content — honest, not fabricated

Wire encrypts message content client-side (Proteus). That key is **not** stored in
the Chromium OS Safe Storage (unlike Chrome cookie keys or Signal's key), so it is
**not recoverable from this artifact**. Encrypted bodies are surfaced as
`PayloadState::Encrypted` with their cleartext metadata (conversation, sender,
time) intact; asking for the plaintext returns a typed
`WireError::EncryptedPayloadUnrecoverable` — never plausible-but-wrong bytes. The
crate performs no decryption and ships no placeholder crypto.

## Trust, but verify

- **Fuzzed** — two `cargo-fuzz` targets (`fuzz_interpret_records`, `fuzz_forensic`)
  drive the interpreter and the full audit pipeline over arbitrary input; the
  invariant is *never panic*.
- **Panic-free by lint** — `#![forbid(unsafe_code)]`, `clippy::unwrap_used` /
  `expect_used` denied in production code, bounds-checked value handling.
- **Validated against real Chromium-authored bytes** — the reader is exercised
  against a real IndexedDB store minted by Google Chrome in Wire's documented
  Dexie schema (tier-2). See [docs/validation.md](docs/validation.md) for the
  honest tier discussion and what would upgrade it.

---

[Privacy Policy](https://securityronin.github.io/wire-desktop-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/wire-desktop-forensic/terms/) · © 2026 Security Ronin Ltd
