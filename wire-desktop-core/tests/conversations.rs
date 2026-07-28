//! Conversation-record interpretation (object store `conversations`).

mod common;

use common::{obj, record, s};
use wire_desktop_core::{interpret_records, WireRecordKind};

#[test]
fn extracts_conversation_id_and_name() {
    let recs = vec![record(
        "conversations",
        "conv-1",
        obj(vec![
            ("id", s("conv-1")),
            ("name", s("Incident Ops")),
            ("type", s("group")),
        ]),
    )];

    let store = interpret_records(&recs);
    let conv = store
        .records
        .iter()
        .find(|r| r.kind == WireRecordKind::Conversation)
        .expect("a conversation record");

    assert_eq!(conv.id.as_deref(), Some("conv-1"));
    assert_eq!(conv.conversation.as_deref(), Some("conv-1"));
    assert_eq!(conv.name.as_deref(), Some("Incident Ops"));
}
