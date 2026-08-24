//! Cleartext event-record interpretation (object store `events`).

mod common;

use common::{obj, record, s};
use wire_desktop_core::{interpret_records, PayloadState, WireRecordKind};

#[test]
fn extracts_event_metadata_and_cleartext_body() {
    let recs = vec![record(
        "events",
        "conv-1@ev-1",
        obj(vec![
            ("id", s("ev-1")),
            ("conversation", s("conv-1")),
            ("from", s("user-alice")),
            ("time", s("2026-01-02T03:04:05.000Z")),
            ("type", s("conversation.message-add")),
            ("data", obj(vec![("content", s("meet at 9"))])),
        ]),
    )];

    let store = interpret_records(&recs);
    let ev = store
        .records
        .iter()
        .find(|r| r.kind == WireRecordKind::Event)
        .expect("an event record");

    assert_eq!(ev.id.as_deref(), Some("ev-1"));
    assert_eq!(ev.conversation.as_deref(), Some("conv-1"));
    assert_eq!(ev.sender.as_deref(), Some("user-alice"));
    assert_eq!(ev.time.as_deref(), Some("2026-01-02T03:04:05.000Z"));
    assert_eq!(ev.message_type.as_deref(), Some("conversation.message-add"));
    assert_eq!(ev.text.as_deref(), Some("meet at 9"));
    assert_eq!(ev.payload, PayloadState::Cleartext);
    assert!(!ev.is_encrypted());
    // A cleartext body is returned verbatim (no fabrication needed).
    assert_eq!(ev.decrypted_text().unwrap(), "meet at 9");
}

#[test]
fn top_level_text_field_is_also_recovered() {
    let recs = vec![record(
        "events",
        "conv-1@ev-2",
        obj(vec![
            ("conversation", s("conv-1")),
            ("type", s("conversation.message-add")),
            ("text", s("top-level body")),
        ]),
    )];
    let store = interpret_records(&recs);
    let ev = store.events().next().expect("event");
    assert_eq!(ev.text.as_deref(), Some("top-level body"));
}
