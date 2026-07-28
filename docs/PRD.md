# Purpose & Scope — wire-desktop-forensic

A library repo (reader + analyzer), so this is the lighter **Purpose & Scope**
document (per ADR-0015 / ADR-0003), not a full product PRD.

## Purpose

Give a DFIR analyst the readable content of a Wire desktop chat store, and an
honest account of what cannot be read. Wire desktop keeps all evidence in one
Chromium IndexedDB store; a generic IndexedDB dump is a wall of Dexie records
with V8-serialized values. This suite turns that into typed Wire records
(conversations, events, users, clients) plus a timeline, and audits them for the
observations that matter in an investigation.

## In scope

- Interpret the Wire Dexie object stores (`conversations`, `events`, `users`,
  `clients`, and any others as `Unknown`) into typed records.
- Recover cleartext message bodies and all cleartext metadata (conversation,
  sender, event time, event type, names).
- Surface recovered **deleted** records (LevelDB tombstones) and **encrypted**
  message payloads (marked unrecoverable, with metadata intact).
- Emit canonical `forensicnomicon` findings (cleartext recovered, encrypted
  unrecoverable, deleted residual, `otr_key` present).
- Build a chronological timeline of event records.

## Out of scope (and why)

- **Decrypting message content.** Wire's Proteus message key is not in the
  Chromium OS Safe Storage and is not recoverable from this artifact. The crate
  performs no decryption and ships no placeholder crypto — an encrypted body is
  reported as unrecoverable, never fabricated. (If a key were ever recoverable
  from another artifact, decryption would belong in a separate, key-injecting
  layer, not here.)
- **Reading the raw LevelDB / decoding V8 values.** That is the Wave-2
  `chromium-storage-indexeddb` reader's job; this crate consumes its output.
- **Locating the profile on a disk image / mounting containers.** Callers pass a
  directory (or a profile base dir); container/VFS access is upstream.
- **Attachment decryption.** The `otr_key` (attachment key) is *reported as
  present* (recoverable key material); using it to decrypt attachment blobs is a
  separate capability.

## Users

- DFIR analysts triaging a Wire desktop profile pulled from an endpoint.
- Fleet orchestration (Issen) aggregating Wire findings alongside other analyzers.

## Success

A single `read_profile(base)` → `audit_store(...)` call yields the recoverable
Wire conversation content and a truthful list of what is encrypted/deleted, with
no fabricated plaintext and no panic on a malformed store.
