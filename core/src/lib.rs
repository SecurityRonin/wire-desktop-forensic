//! **Wire desktop** (Electron) messenger reader.
//!
//! Wire desktop is an Electron wrapper over the Wire web client; all of its
//! evidence lives in the Chromium **IndexedDB** store
//! (`IndexedDB/https_app.wire.com_0.indexeddb.leveldb`), organised as Dexie
//! object stores. This crate sits on top of the Wave-2 reader
//! [`chromium_storage_indexeddb`]: it takes the generic decoded IndexedDB
//! records and interprets them into typed Wire records
//! ([`WireRecord`]) and a chronological [`timeline`].
//!
//! It is a **reader**, not an analyzer — it exposes structure and records and
//! emits no findings (those live in `wire-desktop-forensic`).
//!
//! # Where the bytes are
//!
//! The profile path and the app's encryption posture come from the fleet
//! KNOWLEDGE leaf [`forensicnomicon_core::messenger_desktop`] (spec `"Wire"`) —
//! this crate never re-hardcodes them. [`read_profile`] resolves the IndexedDB
//! store under a Wire profile base directory using that spec.
//!
//! # Encrypted content — fail loud, never fabricate
//!
//! Wire encrypts message content client-side (Proteus). That key is **not** in
//! the Chromium OS Safe Storage, so it is not recoverable from this artifact.
//! Encrypted message bodies are surfaced as [`PayloadState::Encrypted`] with
//! their cleartext metadata (conversation, sender, time) intact; asking for the
//! plaintext returns a typed [`WireError::EncryptedPayloadUnrecoverable`] rather
//! than plausible-but-wrong bytes.
//!
//! References: hunjison, *Forensic Analysis of Wire Messenger in Windows OS*
//! (the `https_app.wire.com_0.indexeddb.leveldb` store + the `otr_key`).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod record;
mod timeline;

pub use error::WireError;
pub use record::{
    interpret_records, ObjectStoreSummary, PayloadState, WireRecord, WireRecordKind, WireStore,
};
pub use timeline::{timeline, TimelineEntry};

use forensicnomicon_core::messenger_desktop::{self, MessengerSpec, StoreRole};
use std::path::{Path, PathBuf};

/// The Wire desktop artifact spec from the fleet KNOWLEDGE leaf.
#[must_use]
pub fn wire_spec() -> Option<&'static MessengerSpec> {
    messenger_desktop::spec("Wire")
}

/// Read and interpret a Wire IndexedDB store directory
/// (`…/https_app.wire.com_0.indexeddb.leveldb`).
///
/// Reads every record (including tombstones) via [`chromium_storage_indexeddb`]
/// and interprets them into a [`WireStore`].
pub fn read_store(dir: &Path) -> Result<WireStore, WireError> {
    let records = chromium_storage_indexeddb::read_dir(dir).map_err(|e| WireError::Read {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    Ok(interpret_records(&records))
}

/// Read a Wire IndexedDB store from a **profile base directory** by resolving the
/// store's relative path from the forensicnomicon Wire spec (never a hardcoded
/// path here).
///
/// `base` is the Electron `userData` directory for Wire (e.g.
/// `~/Library/Application Support/Wire`). Returns
/// [`WireError::StoreNotFound`] when the resolved store directory is absent.
pub fn read_profile(base: &Path) -> Result<WireStore, WireError> {
    // forensicnomicon-core always ships the Wire spec; the None arm is a
    // defensive guard for a future catalog that drops it (cov:unreachable).
    let spec = wire_spec().ok_or_else(|| WireError::StoreNotFound {
        base: base.display().to_string(),            // cov:unreachable
        relative: "<Wire spec missing>".to_string(), // cov:unreachable
    })?; // cov:unreachable
    let relative = spec
        .store(StoreRole::Messages)
        .map_or("IndexedDB", |s| s.relative_path);
    let dir: PathBuf = base.join(relative);
    if !dir.is_dir() {
        return Err(WireError::StoreNotFound {
            base: base.display().to_string(),
            relative: relative.to_string(),
        });
    }
    read_store(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_spec_resolves_from_knowledge_leaf() {
        let spec = wire_spec().expect("Wire spec present in forensicnomicon-core");
        assert_eq!(spec.app, "Wire");
        // The Messages store path is the IndexedDB LevelDB directory.
        let msgs = spec.store(StoreRole::Messages).expect("messages store");
        assert!(msgs.relative_path.contains(".indexeddb.leveldb"));
    }

    #[test]
    fn read_profile_fails_loud_when_store_absent() {
        let tmp = std::env::temp_dir().join("wire-desktop-core-nonexistent-profile-xyz");
        let err = read_profile(&tmp).expect_err("absent store must fail loud");
        assert!(matches!(err, WireError::StoreNotFound { .. }));
        assert!(err.to_string().contains(".indexeddb.leveldb"));
    }

    #[test]
    fn read_profile_reads_a_store_at_the_spec_relative_path() {
        // Lay out a profile whose Messages-store relative path (from the Wire
        // spec) contains the committed minted store, and read it end to end.
        let spec = wire_spec().expect("spec");
        let relative = spec
            .store(StoreRole::Messages)
            .expect("messages")
            .relative_path;

        let base = std::env::temp_dir().join(format!("wire-profile-{}", std::process::id()));
        let dest = base.join(relative);
        std::fs::create_dir_all(&dest).expect("mkdir profile store");
        let src = std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/data/wire-indexeddb/http_127.0.0.1_8731.indexeddb.leveldb"
        ));
        for entry in std::fs::read_dir(&src).expect("read fixture dir") {
            let entry = entry.expect("entry");
            std::fs::copy(entry.path(), dest.join(entry.file_name())).expect("copy fixture file");
        }

        let store = read_profile(&base).expect("read_profile happy path");
        assert!(store
            .records
            .iter()
            .any(|r| r.text.as_deref() == Some("meet at 9")));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn read_store_surfaces_reader_errors() {
        let missing = std::env::temp_dir().join("wire-desktop-core-no-such-store-dir");
        let err = read_store(&missing).expect_err("missing dir must error");
        assert!(matches!(err, WireError::Read { .. }));
        assert!(err.to_string().contains("no-such-store-dir"));
    }
}
