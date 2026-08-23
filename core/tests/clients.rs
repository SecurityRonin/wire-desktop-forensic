//! Client/device-record interpretation (object store `clients`).

mod common;

use common::{obj, record, s};
use wire_desktop_core::{interpret_records, WireRecordKind};

#[test]
fn extracts_client_id_and_device_label() {
    let recs = vec![record(
        "clients",
        "client-7f",
        obj(vec![
            ("id", s("7f3a")),
            ("class", s("desktop")),
            ("model", s("Wire for macOS")),
        ]),
    )];

    let store = interpret_records(&recs);
    let client = store
        .records
        .iter()
        .find(|r| r.kind == WireRecordKind::Client)
        .expect("a client record");

    assert_eq!(client.id.as_deref(), Some("7f3a"));
    // The device label prefers the model, falling back to the class.
    assert_eq!(client.name.as_deref(), Some("Wire for macOS"));
}

#[test]
fn falls_back_to_class_when_no_model() {
    let recs = vec![record(
        "clients",
        "client-01",
        obj(vec![("id", s("01")), ("class", s("desktop"))]),
    )];
    let store = interpret_records(&recs);
    let client = store
        .records
        .iter()
        .find(|r| r.kind == WireRecordKind::Client)
        .unwrap();
    assert_eq!(client.name.as_deref(), Some("desktop"));
}
