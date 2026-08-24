//! Tier-2 oracle test over a REAL Chromium-authored IndexedDB store minted in
//! Wire's documented Dexie schema by driving headless Google Chrome. The store
//! directory is committed under `tests/data/wire-indexeddb/`, so this runs
//! deterministically in CI; set `WIRE_MINTED_DIR` to point at a freshly minted
//! store instead.
//!
//! Honest tier: tier-2 (the *bytes* are Chromium-authored — a genuine external
//! encoder — but the Wire-schema *scenario* is self-constructed, so it can miss
//! real-Wire-app quirks). No real Wire message corpus was publicly available;
//! see docs/validation.md for the mint recipe and what would upgrade this.

use wire_desktop_core::{read_store, WireRecordKind};

fn minted_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var_os("WIRE_MINTED_DIR") {
        return std::path::PathBuf::from(d);
    }
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/wire-indexeddb/http_127.0.0.1_8731.indexeddb.leveldb"
    ))
}

#[test]
fn reads_real_minted_wire_schema_store() {
    let dir = minted_dir();
    let store = read_store(&dir).expect("read minted store");

    eprintln!("object stores: {:?}", store.object_stores);
    for r in &store.records {
        eprintln!(
            "  [{}] {} kind={:?} conv={:?} sender={:?} time={:?} text={:?} enc={}",
            r.store,
            r.primary_key,
            r.kind,
            r.conversation,
            r.sender,
            r.time,
            r.text,
            r.is_encrypted()
        );
    }

    // Ground truth from the mint: the four Wire stores are present.
    let names: Vec<&str> = store
        .object_stores
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    for expected in ["conversations", "events", "users", "clients"] {
        assert!(
            names.contains(&expected),
            "missing store {expected}: {names:?}"
        );
    }

    // The cleartext message body was recovered from a real Chromium V8 blob.
    let clear = store
        .events()
        .find(|e| e.text.as_deref() == Some("meet at 9"))
        .expect("cleartext event 'meet at 9'");
    assert_eq!(clear.conversation.as_deref(), Some("conv-1"));
    assert_eq!(clear.sender.as_deref(), Some("user-alice"));

    // The ArrayBuffer-bodied message is marked encrypted/unrecoverable.
    assert!(
        store.encrypted_events().next().is_some(),
        "expected at least one encrypted event"
    );

    // otr_key material surfaced.
    assert!(
        store
            .records
            .iter()
            .any(|r| r.primary_key.contains("otr_key")),
        "expected otr_key record"
    );

    // A conversation name resolved.
    assert!(store.records.iter().any(
        |r| r.kind == WireRecordKind::Conversation && r.name.as_deref() == Some("Incident Ops")
    ));
}
