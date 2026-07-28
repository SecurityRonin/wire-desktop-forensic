//! Typed Wire records and the interpretation of IndexedDB records into them.
//!
//! Wire desktop is an Electron wrapper over the Wire web client; all evidence
//! lives in the Chromium IndexedDB (`https_app.wire.com_0.indexeddb.leveldb`),
//! organised as Dexie object stores. This module maps each generic
//! [`IndexedDbRecord`] (already decoded by [`chromium_storage_indexeddb`]) onto a
//! typed [`WireRecord`] by the object-store it came from.
//!
//! The object-store names are Wire web-client schema knowledge (Dexie stores
//! `conversations`, `events`, `users`, `clients`); the profile path and the
//! encryption posture come from the fleet KNOWLEDGE leaf
//! [`forensicnomicon_core::messenger_desktop`].
//!
//! # Encrypted content
//!
//! Message bodies are frequently client-side encrypted (Proteus). Wire's message
//! key is **not** stored in the Chromium OS Safe Storage, so it is not
//! recoverable from this artifact. An encrypted payload is surfaced as
//! [`PayloadState::Encrypted`] with its cleartext metadata (conversation,
//! sender, time) intact; asking for its plaintext fails loud (see
//! [`WireRecord::decrypted_text`]) rather than fabricating bytes.

use crate::error::WireError;
use chromium_storage_indexeddb::{IdbKey, IndexedDbRecord, RecordValue, V8Value};

/// Which Wire object store a record came from — the Dexie store name mapped to a
/// forensic role.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireRecordKind {
    /// `conversations` — conversation/group metadata.
    Conversation,
    /// `events` — message and system events (the chat log).
    Event,
    /// `users` — the contact roster.
    User,
    /// `clients` — registered devices/clients.
    Client,
    /// An object store this reader does not map to a Wire role.
    Unknown,
}

impl WireRecordKind {
    /// Map a Dexie object-store name to its Wire role.
    #[must_use]
    pub fn from_store_name(name: &str) -> WireRecordKind {
        match name {
            "conversations" => WireRecordKind::Conversation,
            "events" => WireRecordKind::Event,
            "users" => WireRecordKind::User,
            "clients" => WireRecordKind::Client,
            _ => WireRecordKind::Unknown,
        }
    }

    /// A stable label for the kind.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            WireRecordKind::Conversation => "conversation",
            WireRecordKind::Event => "event",
            WireRecordKind::User => "user",
            WireRecordKind::Client => "client",
            WireRecordKind::Unknown => "unknown",
        }
    }
}

/// The recoverability state of a record's content.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadState {
    /// The content is in cleartext (metadata records, or a message whose body
    /// was extractable).
    Cleartext,
    /// The content is client-side encrypted and its key is not recoverable from
    /// this artifact.
    Encrypted {
        /// The encryption scheme (Wire uses Proteus for message content).
        scheme: &'static str,
        /// Why the plaintext is unrecoverable.
        reason: &'static str,
    },
    /// The value could not be decoded from its Blink/V8 blob upstream.
    Undecoded {
        /// The upstream decode error, verbatim.
        error: String,
    },
}

/// One interpreted Wire record.
///
/// Fields absent from the source record stay `None`; only fields the record
/// actually carries are populated. `#[non_exhaustive]` so new fields do not
/// break consumers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct WireRecord {
    /// The object-store name the record came from.
    pub store: String,
    /// The Wire role of the store.
    pub kind: WireRecordKind,
    /// The record's primary key, rendered as text.
    pub primary_key: String,
    /// The record's own `id` field, if present.
    pub id: Option<String>,
    /// The conversation id the record belongs to, if present.
    pub conversation: Option<String>,
    /// The sender/author (`from`) of an event, if present.
    pub sender: Option<String>,
    /// The event/record timestamp as stored (ISO-8601 string), if present.
    pub time: Option<String>,
    /// The Wire event `type` (e.g. `conversation.message-add`), if present.
    pub message_type: Option<String>,
    /// A human name — conversation name, user display name, or device model.
    pub name: Option<String>,
    /// The cleartext message body, when one was recoverable.
    pub text: Option<String>,
    /// Whether the content is cleartext, encrypted, or undecodable.
    pub payload: PayloadState,
    /// LevelDB sequence number (write ordering).
    pub seq: u64,
    /// `true` if this record is a deletion tombstone recovered from the store.
    pub deleted: bool,
}

impl WireRecord {
    /// The recoverable plaintext of this record's message body.
    ///
    /// Returns the cleartext body for a [`PayloadState::Cleartext`] record.
    /// For an encrypted or undecodable payload it **fails loud** with a typed
    /// error — it never fabricates plaintext.
    pub fn decrypted_text(&self) -> Result<&str, WireError> {
        match &self.payload {
            PayloadState::Cleartext => Ok(self.text.as_deref().unwrap_or("")),
            PayloadState::Encrypted { .. } => Err(WireError::EncryptedPayloadUnrecoverable),
            PayloadState::Undecoded { error } => Err(WireError::UndecodedValue(error.clone())),
        }
    }

    /// Whether this record's content is client-side encrypted and unrecoverable.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self.payload, PayloadState::Encrypted { .. })
    }
}

/// Interpret a slice of decoded IndexedDB records into a typed [`WireStore`].
#[must_use]
pub fn interpret_records(records: &[IndexedDbRecord]) -> WireStore {
    // Scaffold: interpretation is filled in per record type (TDD cycles).
    let _ = records;
    WireStore::default()
}

/// The interpreted Wire store: a per-object-store summary plus every record.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WireStore {
    /// One summary per named object store found.
    pub object_stores: Vec<ObjectStoreSummary>,
    /// Every interpreted record, in source order.
    pub records: Vec<WireRecord>,
}

impl WireStore {
    /// Records belonging to `store`.
    pub fn records_in<'a>(&'a self, store: &'a str) -> impl Iterator<Item = &'a WireRecord> {
        self.records.iter().filter(move |r| r.store == store)
    }

    /// All message/system event records.
    pub fn events(&self) -> impl Iterator<Item = &WireRecord> {
        self.records
            .iter()
            .filter(|r| r.kind == WireRecordKind::Event)
    }

    /// Event records whose content is client-side encrypted (unrecoverable).
    pub fn encrypted_events(&self) -> impl Iterator<Item = &WireRecord> {
        self.events().filter(|r| r.is_encrypted())
    }
}

/// A per-object-store roll-up.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStoreSummary {
    /// The Dexie object-store name.
    pub name: String,
    /// Its Wire role.
    pub kind: WireRecordKind,
    /// How many records it holds (live + tombstoned).
    pub records: usize,
    /// How many of those records carry an encrypted, unrecoverable payload.
    pub encrypted_payloads: usize,
    /// How many are deletion tombstones.
    pub deleted: usize,
}

// ─── value helpers (shared by the per-store fill_* handlers) ─────────────────

/// Render an [`IdbKey`] to a stable text form for the record's `primary_key`.
#[allow(dead_code)]
pub(crate) fn render_key(key: &IdbKey) -> String {
    match key {
        IdbKey::String(s) => s.clone(),
        IdbKey::Number(n) | IdbKey::Date(n) => n.to_string(),
        IdbKey::Binary(b) => format!("0x{}", hex(b)),
        IdbKey::Array(items) => {
            let parts: Vec<String> = items.iter().map(render_key).collect();
            format!("[{}]", parts.join(","))
        }
        IdbKey::Null => "null".to_string(),
        IdbKey::Min => "min".to_string(),
        IdbKey::Invalid(b) => format!("invalid:0x{}", hex(b)),
    }
}

#[allow(dead_code)]
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// A record value that decoded to a V8 object; `None` for non-objects.
#[allow(dead_code)]
pub(crate) fn obj_field<'a>(v: &'a V8Value, key: &str) -> Option<&'a V8Value> {
    match v {
        V8Value::Object(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, val)| val),
        _ => None,
    }
}

/// Render a scalar V8 value to text; `None` for containers/binary.
#[allow(dead_code)]
pub(crate) fn as_text(v: &V8Value) -> Option<String> {
    match v {
        V8Value::String(s) | V8Value::StringObject(s) | V8Value::BigInt(s) => Some(s.clone()),
        V8Value::Int(i) => Some(i.to_string()),
        V8Value::Double(d) | V8Value::Date(d) | V8Value::NumberObject(d) => Some(d.to_string()),
        V8Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The decode-state of a record value, independent of its object-store role.
#[allow(dead_code)]
pub(crate) fn base_payload(value: &RecordValue) -> PayloadState {
    match value {
        RecordValue::V8(_) => PayloadState::Cleartext,
        RecordValue::Undecoded { error, .. } => PayloadState::Undecoded {
            error: error.clone(),
        },
    }
}
