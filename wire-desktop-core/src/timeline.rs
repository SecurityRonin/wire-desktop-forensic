//! A chronological view of the Wire event records.
//!
//! Only [`WireRecordKind::Event`] records with a parseable `time` participate.
//! Entries carry the cleartext metadata and the payload state, so an encrypted
//! message still appears on the timeline (with its body marked unrecoverable)
//! rather than vanishing.

use crate::record::{PayloadState, WireRecord, WireRecordKind, WireStore};

/// One entry in the reconstructed Wire timeline.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    /// The event time as stored (ISO-8601 string).
    pub time: String,
    /// The conversation the event belongs to.
    pub conversation: Option<String>,
    /// The sender/author.
    pub sender: Option<String>,
    /// The Wire event type.
    pub message_type: Option<String>,
    /// Whether the body is cleartext, encrypted, or undecodable.
    pub payload: PayloadState,
    /// `true` if this event is a recovered deletion tombstone.
    pub deleted: bool,
}

/// Build the chronological timeline of event records from an interpreted store.
///
/// Events are ordered by their stored `time` (ISO-8601 strings sort
/// lexicographically in chronological order); an event with no `time` is omitted.
#[must_use]
pub fn timeline(store: &WireStore) -> Vec<TimelineEntry> {
    let mut entries: Vec<TimelineEntry> = store
        .records
        .iter()
        .filter(|r| r.kind == WireRecordKind::Event)
        .filter_map(entry_for)
        .collect();
    entries.sort_by(|a, b| a.time.cmp(&b.time));
    entries
}

/// Build a timeline entry for an event record, or `None` when it has no `time`.
fn entry_for(r: &WireRecord) -> Option<TimelineEntry> {
    let time = r.time.clone()?;
    Some(TimelineEntry {
        time,
        conversation: r.conversation.clone(),
        sender: r.sender.clone(),
        message_type: r.message_type.clone(),
        payload: r.payload.clone(),
        deleted: r.deleted,
    })
}
