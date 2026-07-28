# ADR-0002: Interpret over the Wave-2 IndexedDB reader, not raw LevelDB

## Status
Accepted.

## Context
Wire's evidence is a Chromium IndexedDB-over-LevelDB store. Decoding that store
(the LevelDB key-coding scheme, tombstone recovery, and the Blink
`SerializedScriptValue` V8 values) is a solved, medium-agnostic problem already
owned by the Wave-2 crate `chromium-storage-indexeddb`. The PARSER-tier rule
(CLAUDE.md / ADR-0016) is that a parser depends on FOUNDATION and accepts already-
decoded input; it never re-implements a container/storage reader.

## Decision
`wire-desktop-core` consumes `chromium_storage_indexeddb::IndexedDbRecord`
(via `read_dir` / the decoded slice) and interprets it. It owns **no** LevelDB,
V8, or key-coding code. The Wire profile path and encryption posture come from
`forensicnomicon_core::messenger_desktop` (the `"Wire"` spec) — never re-hardcoded
here; `read_profile` resolves the store's relative path from that spec.

## Consequences
- One place fixes a LevelDB/V8 decode bug (the Wave-2 reader), and this crate
  inherits it.
- The interpretation seam is `IndexedDbRecord`, which makes the Wire mapping
  unit-testable without minting a LevelDB store for every case.
- The Wire object-store *names* (Dexie `conversations`/`events`/…) are the one
  piece of Wire-specific schema knowledge this crate adds, sourced from the
  published Wire forensics writeup.
