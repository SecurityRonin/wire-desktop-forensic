//! Store-structure interpretation: object-store enumeration + record passthrough.

mod common;

use common::{deleted_record, obj, record, s, undecoded_record};
use wire_desktop_core::{interpret_records, PayloadState, WireRecordKind, WireStore};

fn sample() -> Vec<chromium_storage_indexeddb::IndexedDbRecord> {
    vec![
        record(
            "conversations",
            "conv-1",
            obj(vec![("id", s("conv-1")), ("name", s("Ops"))]),
        ),
        record(
            "events",
            "conv-1@1",
            obj(vec![
                ("conversation", s("conv-1")),
                ("type", s("conversation.message-add")),
            ]),
        ),
        deleted_record(
            "events",
            "conv-1@2",
            obj(vec![("conversation", s("conv-1"))]),
        ),
        record("users", "user-1", obj(vec![("id", s("user-1"))])),
        record("clients", "client-1", obj(vec![("id", s("client-1"))])),
        undecoded_record("events", "conv-1@3", "truncated blob"),
    ]
}

#[test]
fn enumerates_object_stores_with_roles_and_counts() {
    let store: WireStore = interpret_records(&sample());

    let names: Vec<&str> = store
        .object_stores
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    assert!(names.contains(&"conversations"));
    assert!(names.contains(&"events"));
    assert!(names.contains(&"users"));
    assert!(names.contains(&"clients"));

    let events = store
        .object_stores
        .iter()
        .find(|o| o.name == "events")
        .expect("events summary");
    assert_eq!(events.kind, WireRecordKind::Event);
    assert_eq!(events.records, 3);
    assert_eq!(events.deleted, 1);

    let convs = store
        .object_stores
        .iter()
        .find(|o| o.name == "conversations")
        .expect("conversations summary");
    assert_eq!(convs.kind, WireRecordKind::Conversation);
    assert_eq!(convs.records, 1);
}

#[test]
fn passes_every_record_through_with_store_key_and_flags() {
    let store = interpret_records(&sample());
    assert_eq!(store.records.len(), 6);

    let deleted = store
        .records
        .iter()
        .find(|r| r.primary_key == "conv-1@2")
        .unwrap();
    assert_eq!(deleted.store, "events");
    assert_eq!(deleted.kind, WireRecordKind::Event);
    assert!(deleted.deleted);

    let undecoded = store
        .records
        .iter()
        .find(|r| r.primary_key == "conv-1@3")
        .unwrap();
    assert!(matches!(undecoded.payload, PayloadState::Undecoded { .. }));
}
