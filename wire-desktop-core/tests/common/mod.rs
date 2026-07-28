//! Shared fixture builders for the Wire reader tests.
//!
//! These build [`IndexedDbRecord`]s at the reader-output seam — the exact type
//! `wire-desktop-core` consumes. The V8 object shapes mirror Wire's Dexie schema
//! (object stores `conversations` / `events` / `users` / `clients`) as
//! documented by hunjison, *Forensic Analysis of Wire Messenger in Windows OS*.
//! This is a self-authored (tier-3) fixture set; see docs/validation.md.
#![allow(dead_code)]

use chromium_storage_indexeddb::{IdbKey, IndexedDbRecord, RecordValue, V8Value};

/// A V8 string value.
pub fn s(v: &str) -> V8Value {
    V8Value::String(v.to_string())
}

/// A V8 object value from `(key, value)` pairs (insertion order preserved).
pub fn obj(fields: Vec<(&str, V8Value)>) -> V8Value {
    V8Value::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// A decoded IndexedDB record in object store `store` with string primary key
/// `key` and a decoded V8 `value`.
pub fn record(store: &str, key: &str, value: V8Value) -> IndexedDbRecord {
    IndexedDbRecord {
        database_id: 1,
        object_store_id: 1,
        database: Some("wire".to_string()),
        object_store: Some(store.to_string()),
        key: IdbKey::String(key.to_string()),
        value: RecordValue::V8(value),
        seq: 1,
        deleted: false,
    }
}

/// Like [`record`], but flagged as a recovered deletion tombstone.
pub fn deleted_record(store: &str, key: &str, value: V8Value) -> IndexedDbRecord {
    let mut r = record(store, key, value);
    r.deleted = true;
    r
}

/// A record whose value failed to decode upstream (raw + error retained).
pub fn undecoded_record(store: &str, key: &str, error: &str) -> IndexedDbRecord {
    let mut r = record(store, key, V8Value::Null);
    r.value = RecordValue::Undecoded {
        raw: vec![0xff, 0xff],
        error: error.to_string(),
    };
    r
}
