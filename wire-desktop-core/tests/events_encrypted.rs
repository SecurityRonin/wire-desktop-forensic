//! Encrypted event-record interpretation — surface metadata, FAIL LOUD on the
//! body. Wire encrypts message content client-side (Proteus); its key is not in
//! the Chromium OS Safe Storage, so the plaintext is unrecoverable.

mod common;

use chromium_storage_indexeddb::V8Value;
use common::{obj, record, s};
use wire_desktop_core::{interpret_records, PayloadState, WireError};

fn encrypted_event() -> Vec<chromium_storage_indexeddb::IndexedDbRecord> {
    vec![record(
        "events",
        "conv-1@ev-enc",
        obj(vec![
            ("conversation", s("conv-1")),
            ("from", s("user-bob")),
            ("time", s("2026-01-02T03:05:00.000Z")),
            ("type", s("conversation.otr-message-add")),
            // Opaque Proteus ciphertext — no cleartext content.
            ("data", V8Value::ArrayBuffer(vec![0xde, 0xad, 0xbe, 0xef])),
        ]),
    )]
}

#[test]
fn encrypted_body_is_marked_unrecoverable_but_metadata_survives() {
    let store = interpret_records(&encrypted_event());
    let ev = store.events().next().expect("event");

    // Metadata is cleartext and recovered.
    assert_eq!(ev.conversation.as_deref(), Some("conv-1"));
    assert_eq!(ev.sender.as_deref(), Some("user-bob"));
    assert_eq!(ev.time.as_deref(), Some("2026-01-02T03:05:00.000Z"));

    // Body is encrypted and has no cleartext.
    assert!(ev.is_encrypted());
    assert_eq!(ev.text, None);
    match &ev.payload {
        PayloadState::Encrypted { scheme, .. } => assert_eq!(*scheme, "Proteus"),
        other => panic!("expected Encrypted payload, got {other:?}"),
    }
}

#[test]
fn decrypted_text_fails_loud_and_never_fabricates() {
    let store = interpret_records(&encrypted_event());
    let ev = store.events().next().expect("event");
    match ev.decrypted_text() {
        Err(WireError::EncryptedPayloadUnrecoverable) => {}
        other => panic!("expected a loud EncryptedPayloadUnrecoverable error, got {other:?}"),
    }
}

#[test]
fn cipher_marker_field_also_classifies_as_encrypted() {
    let recs = vec![record(
        "events",
        "conv-1@ev-c",
        obj(vec![
            ("conversation", s("conv-1")),
            ("type", s("conversation.message-add")),
            ("data", obj(vec![("cipher_text", s("b64=="))])),
        ]),
    )];
    let store = interpret_records(&recs);
    assert!(store.encrypted_events().next().is_some());
}
