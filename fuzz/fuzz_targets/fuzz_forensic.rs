#![no_main]
//! Fuzz the full interpret -> audit pipeline. Invariant: never panic.
//!
//! Reuses the record synthesis from `fuzz_interpret_records` and additionally
//! drives the analyzer (`audit_store`) so the finding builders (severity,
//! category, evidence, MITRE) stay panic-free on arbitrary input.

use chromium_storage_indexeddb::{IdbKey, IndexedDbRecord, RecordValue, V8Value};
use libfuzzer_sys::fuzz_target;

const STORES: [&str; 6] = ["conversations", "events", "users", "clients", "keys", ""];

fn synth_records(data: &[u8]) -> Vec<IndexedDbRecord> {
    let sel = data.first().copied().unwrap_or(0);
    let store = STORES[sel as usize % STORES.len()];
    let text = String::from_utf8_lossy(data)
        .chars()
        .take(64)
        .collect::<String>();

    let body = if data.len() % 3 == 0 {
        V8Value::ArrayBuffer(data.to_vec())
    } else {
        V8Value::Object(vec![("content".to_string(), V8Value::String(text.clone()))])
    };
    let value = RecordValue::V8(V8Value::Object(vec![
        ("conversation".to_string(), V8Value::String(text.clone())),
        ("from".to_string(), V8Value::String(text.clone())),
        ("time".to_string(), V8Value::String(text.clone())),
        (
            "type".to_string(),
            V8Value::String("conversation.message-add".to_string()),
        ),
        ("data".to_string(), body),
    ]));

    vec![IndexedDbRecord {
        database_id: 1,
        object_store_id: 1,
        database: None,
        object_store: Some(store.to_string()),
        key: IdbKey::String(text),
        value,
        seq: u64::from(sel),
        deleted: sel % 2 == 0,
    }]
}

fuzz_target!(|data: &[u8]| {
    let store = wire_desktop_core::interpret_records(&synth_records(data));
    let _ = wire_desktop_core::timeline(&store);
    let _ = wire_desktop_forensic::audit_store(&store);
});
