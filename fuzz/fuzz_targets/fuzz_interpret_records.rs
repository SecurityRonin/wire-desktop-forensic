#![no_main]
//! Fuzz the Wire IndexedDB-record interpreter. Invariant: never panic.
//!
//! Builds decoded IndexedDB records with arbitrary keys, store names, and V8
//! object shapes (including opaque ArrayBuffer bodies) from the fuzz bytes, then
//! drives `interpret_records`, the timeline, and every record's `decrypted_text`
//! — the field extraction, encryption classification, key rendering, and sort
//! must all stay panic-free and bounds-checked.

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

    let key = match sel % 4 {
        0 => IdbKey::String(text.clone()),
        1 => IdbKey::Binary(data.to_vec()),
        2 => IdbKey::Array(vec![IdbKey::String(text.clone()), IdbKey::Number(1.0)]),
        _ => IdbKey::Invalid(data.to_vec()),
    };

    let body = if data.len() % 3 == 0 {
        // Opaque (encrypted-looking) body.
        V8Value::ArrayBuffer(data.to_vec())
    } else {
        V8Value::Object(vec![("content".to_string(), V8Value::String(text.clone()))])
    };
    let value = RecordValue::V8(V8Value::Object(vec![
        ("id".to_string(), V8Value::String(text.clone())),
        ("conversation".to_string(), V8Value::String(text.clone())),
        ("from".to_string(), V8Value::String(text.clone())),
        ("time".to_string(), V8Value::String(text.clone())),
        (
            "type".to_string(),
            V8Value::String("conversation.message-add".to_string()),
        ),
        ("name".to_string(), V8Value::String(text)),
        ("data".to_string(), body),
    ]));

    let undecoded = IndexedDbRecord {
        database_id: 1,
        object_store_id: 1,
        database: None,
        object_store: Some(store.to_string()),
        key: IdbKey::String("otr_key".to_string()),
        value: RecordValue::Undecoded {
            raw: data.to_vec(),
            error: "fuzz".to_string(),
        },
        seq: u64::from(sel),
        deleted: sel % 2 == 0,
    };

    vec![
        IndexedDbRecord {
            database_id: 1,
            object_store_id: 1,
            database: None,
            object_store: Some(store.to_string()),
            key,
            value,
            seq: u64::from(sel),
            deleted: sel % 2 == 0,
        },
        undecoded,
    ]
}

fuzz_target!(|data: &[u8]| {
    let recs = synth_records(data);
    let store = wire_desktop_core::interpret_records(&recs);
    let _ = wire_desktop_core::timeline(&store);
    for r in &store.records {
        let _ = r.decrypted_text();
        let _ = r.is_encrypted();
    }
});
