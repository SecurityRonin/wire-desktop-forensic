//! Forensic anomaly analysis for **Wire desktop** IndexedDB artifacts, layered on
//! the [`wire_desktop_core`] reader.
//!
//! The reader interprets the Chromium IndexedDB Dexie stores into typed
//! [`wire_desktop_core::WireRecord`]s; this crate inspects an interpreted
//! [`wire_desktop_core::WireStore`] and reports observations as canonical
//! [`forensicnomicon::report::Finding`]s, so Wire findings aggregate alongside
//! every other `SecurityRonin` analyzer.
//!
//! | Code | Category | Meaning |
//! |---|---|---|
//! | `WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE` | Provenance | a message body is client-side (Proteus) encrypted; the key is not in the OS Safe Storage, so plaintext is unrecoverable |
//! | `WIRE-MESSAGE-CLEARTEXT` | Residue | a cleartext message body was recovered from the store |
//! | `WIRE-RECORD-DELETED-RESIDUAL` | Residue | a tombstoned (deleted) Wire record survives in the LevelDB and was recovered |
//! | `WIRE-OTR-KEY-PRESENT` | Threat | the Wire `otr_key` (attachment key) is present in the IndexedDB — recoverable key material |
//!
//! Findings are observations, never legal conclusions.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::Finding;
use wire_desktop_core::WireStore;

/// Analyzer name, recorded on every finding's [`forensicnomicon::report::Source`].
pub const ANALYZER: &str = "wire-desktop-forensic";

/// Audit an interpreted Wire store, returning a canonical [`Finding`] for each
/// observation.
#[must_use]
pub fn audit_store(store: &WireStore) -> Vec<Finding> {
    // Scaffold: filled in by the analyzer TDD cycle.
    let _ = store;
    Vec::new()
}
