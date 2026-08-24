//! Timeline reconstruction over event records.

mod common;

use chromium_storage_indexeddb::V8Value;
use common::{obj, record, s};
use wire_desktop_core::{interpret_records, timeline, PayloadState};

#[test]
fn orders_events_by_time_and_keeps_encrypted_entries() {
    let recs = vec![
        record(
            "events",
            "e-late",
            obj(vec![
                ("conversation", s("c1")),
                ("time", s("2026-01-02T10:00:00.000Z")),
                ("type", s("conversation.message-add")),
                ("data", obj(vec![("content", s("second"))])),
            ]),
        ),
        record(
            "events",
            "e-early",
            obj(vec![
                ("conversation", s("c1")),
                ("time", s("2026-01-02T09:00:00.000Z")),
                ("type", s("conversation.otr-message-add")),
                ("data", V8Value::ArrayBuffer(vec![1, 2, 3])),
            ]),
        ),
        // No time — excluded from the timeline.
        record(
            "events",
            "e-notime",
            obj(vec![("conversation", s("c1")), ("type", s("system"))]),
        ),
        // Non-event record — excluded.
        record("users", "u1", obj(vec![("id", s("u1"))])),
    ];

    let store = interpret_records(&recs);
    let tl = timeline(&store);

    assert_eq!(tl.len(), 2, "only the two timestamped events");
    assert_eq!(tl[0].time, "2026-01-02T09:00:00.000Z");
    assert_eq!(tl[1].time, "2026-01-02T10:00:00.000Z");

    // The earliest is the encrypted one — it stays on the timeline, body marked.
    assert!(matches!(tl[0].payload, PayloadState::Encrypted { .. }));
    assert_eq!(tl[1].payload, PayloadState::Cleartext);
}
