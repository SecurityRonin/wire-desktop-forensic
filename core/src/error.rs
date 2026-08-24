//! Typed errors for the Wire reader.
//!
//! The load-bearing one is [`WireError::EncryptedPayloadUnrecoverable`]: Wire
//! encrypts message content client-side (Proteus), and that key is **not** held
//! in the Chromium OS Safe Storage (unlike Signal/Chrome cookie keys). So when a
//! caller asks for the plaintext of an encrypted payload we **fail loud** with a
//! typed error rather than fabricate plausible-but-wrong bytes.

use thiserror::Error;

/// An error interpreting a Wire desktop IndexedDB store.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum WireError {
    /// The underlying IndexedDB/LevelDB store could not be read.
    #[error("failed to read Wire IndexedDB store at {path}: {detail}")]
    Read {
        /// The directory that failed to read.
        path: String,
        /// The underlying reader's error, verbatim.
        detail: String,
    },

    /// A Wire profile base directory did not contain the expected IndexedDB store.
    #[error("Wire profile at {base} has no IndexedDB store at the expected path {relative}")]
    StoreNotFound {
        /// The profile base directory searched.
        base: String,
        /// The store path (from the forensicnomicon Wire spec) that was expected.
        relative: String,
    },

    /// The caller asked for the plaintext of a client-side-encrypted payload.
    ///
    /// Wire's message key is not recoverable from this artifact, so the reader
    /// refuses rather than fabricate plaintext. Surface the record's cleartext
    /// metadata (conversation, sender, time) instead.
    #[error(
        "message payload is client-side (Proteus) encrypted; Wire's message key is NOT held in \
         the Chromium OS Safe Storage, so the plaintext is unrecoverable from this artifact"
    )]
    EncryptedPayloadUnrecoverable,

    /// The record value could not be decoded from its Blink/V8 structured-clone
    /// blob upstream; its raw bytes were retained but no plaintext exists.
    #[error("record value could not be decoded from its Blink/V8 blob: {0}")]
    UndecodedValue(String),
}
