# ADR-0003: Encrypted message payloads fail loud, never fabricate plaintext

## Status
Accepted.

## Context
Wire encrypts message content client-side (Proteus). Unlike Chrome cookie keys or
Signal's SQLCipher key, **Wire's message key is not stored in the Chromium OS Safe
Storage** — it is not recoverable from this artifact. A forensic reader that
emitted plausible-but-wrong "plaintext" for such a record would fabricate
evidence: the single worst failure class (CLAUDE.md — Robustness / crypto). Many
event values in a real store are opaque (Proteus ciphertext), so this is the
common case, not an edge.

## Decision
- The reader classifies a message body it cannot read as
  `PayloadState::Encrypted { scheme: "Proteus", reason }`, keeping its cleartext
  metadata (conversation, sender, time, type) intact.
- `WireRecord::decrypted_text()` returns `Ok(body)` only for a cleartext payload;
  for an encrypted one it returns the typed
  `WireError::EncryptedPayloadUnrecoverable`, and for an upstream-undecodable V8
  blob `WireError::UndecodedValue`. It **never** returns fabricated bytes.
- The crate performs **no** decryption and depends on **no** crypto crate. There
  is no placeholder/XOR/"minimal" cipher — there is nothing to get wrong.
- The analyzer emits `WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE` (Info) so the
  encrypted-but-present message is visible in the report as an evidentiary limit,
  not silently dropped.

## Consequences
- An analyst always knows which bodies are readable and which are not, and never
  sees invented content.
- If a Wire message key ever becomes recoverable from another artifact,
  decryption belongs in a separate key-injecting layer above this reader — not by
  weakening this refusal.
- Detection of the `otr_key` (the *attachment* key, which *is* stored in the
  IndexedDB in cleartext per the Wire writeup) is reported as present key material
  (`WIRE-OTR-KEY-PRESENT`); using it to decrypt attachment blobs is out of scope
  here.
