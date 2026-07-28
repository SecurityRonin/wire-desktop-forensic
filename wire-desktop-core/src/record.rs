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
///
/// Every record is passed through as a [`WireRecord`] (store, role, primary key,
/// sequence, tombstone flag, and decode-state payload); per-store field
/// extraction is applied by the `fill_*` handlers. A per-object-store summary is
/// rolled up alongside.
#[must_use]
pub fn interpret_records(records: &[IndexedDbRecord]) -> WireStore {
    let mut out = Vec::with_capacity(records.len());
    let mut summaries: Vec<ObjectStoreSummary> = Vec::new();

    for r in records {
        let store = r.object_store.as_deref().unwrap_or("");
        let wr = interpret_one(store, r);

        if !store.is_empty() {
            let enc = usize::from(wr.is_encrypted());
            let del = usize::from(wr.deleted);
            match summaries.iter_mut().find(|s| s.name == store) {
                Some(sum) => {
                    sum.records += 1;
                    sum.encrypted_payloads += enc;
                    sum.deleted += del;
                }
                None => summaries.push(ObjectStoreSummary {
                    name: store.to_string(),
                    kind: wr.kind,
                    records: 1,
                    encrypted_payloads: enc,
                    deleted: del,
                }),
            }
        }
        out.push(wr);
    }

    WireStore {
        object_stores: summaries,
        records: out,
    }
}

/// Interpret one decoded IndexedDB record into a [`WireRecord`].
///
/// Builds the base record (store, role, primary key, seq, tombstone flag,
/// decode-state payload) then dispatches to the per-store field extractor.
fn interpret_one(store: &str, r: &IndexedDbRecord) -> WireRecord {
    let kind = WireRecordKind::from_store_name(store);
    let mut wr = WireRecord {
        store: store.to_string(),
        kind,
        primary_key: render_key(&r.key),
        id: None,
        conversation: None,
        sender: None,
        time: None,
        message_type: None,
        name: None,
        text: None,
        payload: base_payload(&r.value),
        seq: r.seq,
        deleted: r.deleted,
    };

    if let RecordValue::V8(v) = &r.value {
        match kind {
            WireRecordKind::Conversation => fill_conversation(&mut wr, v),
            WireRecordKind::Event => fill_event(&mut wr, v),
            WireRecordKind::User => fill_user(&mut wr, v),
            WireRecordKind::Client => fill_client(&mut wr, v),
            WireRecordKind::Unknown => {}
        }
    }

    wr
}

/// Extract conversation metadata: the conversation id (its own `id`) and the
/// display `name`.
fn fill_conversation(wr: &mut WireRecord, v: &V8Value) {
    wr.id = obj_field(v, "id").and_then(as_text);
    wr.conversation = wr.id.clone();
    wr.name = obj_field(v, "name").and_then(as_text);
}

/// Extract event metadata (conversation, sender, time, type) and, when the body
/// is in cleartext, the message text. Encrypted-payload classification is added
/// by the encrypted-event cycle.
fn fill_event(wr: &mut WireRecord, v: &V8Value) {
    wr.id = obj_field(v, "id").and_then(as_text);
    wr.conversation = obj_field(v, "conversation").and_then(as_text);
    wr.sender = obj_field(v, "from")
        .or_else(|| obj_field(v, "sender"))
        .and_then(as_text);
    wr.time = obj_field(v, "time").and_then(as_text);
    wr.message_type = obj_field(v, "type").and_then(as_text);

    if let Some(text) = message_text(v) {
        wr.text = Some(text);
        wr.payload = PayloadState::Cleartext;
    } else if is_encrypted_payload(v) {
        // Wire message content is Proteus-encrypted client-side; its key is not
        // in the Chromium OS Safe Storage, so we mark it unrecoverable rather
        // than fabricate plaintext.
        wr.payload = PayloadState::Encrypted {
            scheme: "Proteus",
            reason: "Wire message key is not held in the Chromium OS Safe Storage",
        };
    }
}

/// Whether an event value carries an opaque/ciphered body with no cleartext.
///
/// General structural rule (not tied to any one fixture): a top-level or nested
/// `data` [`V8Value::ArrayBuffer`], or a documented ciphertext-marker field
/// (`cipher_text` / `cipherText` / `otr` / `encrypted`) at the top level or
/// under `data`.
fn is_encrypted_payload(v: &V8Value) -> bool {
    const CIPHER_MARKERS: [&str; 4] = ["cipher_text", "cipherText", "otr", "encrypted"];

    if matches!(v, V8Value::ArrayBuffer(_)) {
        return true;
    }
    let data = obj_field(v, "data");
    if matches!(data, Some(V8Value::ArrayBuffer(_))) {
        return true;
    }
    CIPHER_MARKERS
        .iter()
        .any(|m| obj_field(v, m).is_some() || data.is_some_and(|d| obj_field(d, m).is_some()))
}

/// Extract a cleartext message body from an event value: the `content`/`text`
/// field of the nested `data` object, or a top-level `content`/`text` field.
/// Returns `None` when no cleartext body is present (e.g. an encrypted or a
/// pure-system event).
fn message_text(v: &V8Value) -> Option<String> {
    if let Some(data) = obj_field(v, "data") {
        if let Some(t) = obj_field(data, "content")
            .or_else(|| obj_field(data, "text"))
            .and_then(as_text)
        {
            return Some(t);
        }
    }
    obj_field(v, "content")
        .or_else(|| obj_field(v, "text"))
        .and_then(as_text)
}

/// Extract user metadata: the user `id` and the display `name`.
fn fill_user(wr: &mut WireRecord, v: &V8Value) {
    wr.id = obj_field(v, "id").and_then(as_text);
    wr.name = obj_field(v, "name").and_then(as_text);
}

/// Extract client/device metadata: the client `id` and a device label (the
/// `model`, falling back to the `class` or `label`).
fn fill_client(wr: &mut WireRecord, v: &V8Value) {
    wr.id = obj_field(v, "id").and_then(as_text);
    wr.name = obj_field(v, "model")
        .or_else(|| obj_field(v, "class"))
        .or_else(|| obj_field(v, "label"))
        .and_then(as_text);
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
