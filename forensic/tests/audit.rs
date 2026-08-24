//! Analyzer: audit an interpreted Wire store into forensicnomicon findings.

mod common;

use chromium_storage_indexeddb::V8Value;
use common::{deleted_record, obj, record, s};
use forensicnomicon::report::{Category, Severity};
use wire_desktop_core::interpret_records;
use wire_desktop_forensic::audit_store;

fn store() -> wire_desktop_core::WireStore {
    interpret_records(&[
        // Cleartext message.
        record(
            "events",
            "c1@ev-clear",
            obj(vec![
                ("conversation", s("c1")),
                ("from", s("alice")),
                ("time", s("2026-01-02T09:00:00.000Z")),
                ("type", s("conversation.message-add")),
                ("data", obj(vec![("content", s("hello"))])),
            ]),
        ),
        // Encrypted message (Proteus; unrecoverable).
        record(
            "events",
            "c1@ev-enc",
            obj(vec![
                ("conversation", s("c1")),
                ("time", s("2026-01-02T09:01:00.000Z")),
                ("type", s("conversation.otr-message-add")),
                ("data", V8Value::ArrayBuffer(vec![0xde, 0xad])),
            ]),
        ),
        // Recovered deletion tombstone.
        deleted_record("events", "c1@ev-del", obj(vec![("conversation", s("c1"))])),
        // Exposed attachment key material (documented Wire otr_key).
        record("keys", "otr_key", obj(vec![("id", s("otr_key"))])),
    ])
}

fn has(findings: &[forensicnomicon::report::Finding], code: &str) -> bool {
    findings.iter().any(|f| f.code == code)
}

#[test]
fn flags_encrypted_payload_as_info_provenance() {
    let f = audit_store(&store());
    let enc = f
        .iter()
        .find(|x| x.code == "WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE")
        .expect("encrypted-payload finding");
    assert_eq!(enc.severity, Some(Severity::Info));
    assert_eq!(enc.category, Category::Provenance);
    assert!(enc.note.to_lowercase().contains("unrecoverable"));
}

#[test]
fn recovers_cleartext_message_as_residue() {
    let f = audit_store(&store());
    let c = f
        .iter()
        .find(|x| x.code == "WIRE-MESSAGE-CLEARTEXT")
        .expect("cleartext finding");
    assert_eq!(c.severity, Some(Severity::Low));
    assert_eq!(c.category, Category::Residue);
}

#[test]
fn flags_recovered_deleted_record() {
    let f = audit_store(&store());
    let d = f
        .iter()
        .find(|x| x.code == "WIRE-RECORD-DELETED-RESIDUAL")
        .expect("deleted-record finding");
    assert_eq!(d.severity, Some(Severity::Medium));
    assert_eq!(d.category, Category::Residue);
}

#[test]
fn flags_present_otr_key_material() {
    let f = audit_store(&store());
    let k = f
        .iter()
        .find(|x| x.code == "WIRE-OTR-KEY-PRESENT")
        .expect("otr-key finding");
    assert_eq!(k.severity, Some(Severity::High));
    assert_eq!(k.category, Category::Threat);
    // Every finding names the producing analyzer.
    assert_eq!(k.source.analyzer, wire_desktop_forensic::ANALYZER);
}

#[test]
fn encrypted_event_without_conversation_or_time_still_flags() {
    // Exercises the empty-evidence path (no conversation, no time).
    let recs = vec![record(
        "events",
        "ev-bare",
        obj(vec![
            ("type", s("conversation.otr-message-add")),
            ("data", V8Value::ArrayBuffer(vec![0x00])),
        ]),
    )];
    let f = audit_store(&interpret_records(&recs));
    let enc = f
        .iter()
        .find(|x| x.code == "WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE")
        .expect("encrypted finding");
    assert!(enc.evidence.is_empty());
}

#[test]
fn clean_store_yields_no_findings_of_note() {
    let empty = interpret_records(&[record("users", "u1", obj(vec![("id", s("u1"))]))]);
    let f = audit_store(&empty);
    assert!(!has(&f, "WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE"));
    assert!(!has(&f, "WIRE-RECORD-DELETED-RESIDUAL"));
    assert!(!has(&f, "WIRE-OTR-KEY-PRESENT"));
}
