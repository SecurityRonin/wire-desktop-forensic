//! Forensic anomaly analysis for **Wire desktop** IndexedDB artifacts, layered on
//! the [`wire_desktop_core`] reader.
//!
//! The reader interprets the Chromium IndexedDB Dexie stores into typed
//! [`wire_desktop_core::WireRecord`]s; this crate inspects an interpreted
//! [`wire_desktop_core::WireStore`] and reports observations as canonical
//! [`forensicnomicon::report::Finding`]s, so Wire findings aggregate alongside
//! every other `SecurityRonin` analyzer.
//!
//! | Code | Category | Meaning |
//! |---|---|---|
//! | `WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE` | Provenance | a message body is client-side (Proteus) encrypted; the key is not in the OS Safe Storage, so plaintext is unrecoverable |
//! | `WIRE-MESSAGE-CLEARTEXT` | Residue | a cleartext message body was recovered from the store |
//! | `WIRE-RECORD-DELETED-RESIDUAL` | Residue | a tombstoned (deleted) Wire record survives in the LevelDB and was recovered |
//! | `WIRE-OTR-KEY-PRESENT` | Threat | the Wire `otr_key` (attachment key) is present in the IndexedDB — recoverable key material |
//!
//! Findings are observations, never legal conclusions.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Category, Evidence, Finding, Location, Severity, Source};
use wire_desktop_core::{PayloadState, WireRecord, WireStore};

/// Analyzer name, recorded on every finding's [`forensicnomicon::report::Source`].
pub const ANALYZER: &str = "wire-desktop-forensic";

/// The documented Wire attachment-decryption key name (hunjison, *Forensic
/// Analysis of Wire Messenger in Windows OS*). Its presence in the IndexedDB is
/// recoverable key material — the domain's documented literal, not a fixture
/// special-case.
const OTR_KEY_NAME: &str = "otr_key";

/// A Wire IndexedDB observation, with the offending evidence attached.
///
/// The reader keeps its typed record output; this analyzer keeps its typed
/// anomaly kind (domain knowledge) and converts to canonical findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A message body is client-side (Proteus) encrypted and its key is not
    /// recoverable from this artifact.
    EncryptedMessage {
        /// The conversation the message belongs to.
        conversation: Option<String>,
        /// The message time, if known.
        time: Option<String>,
    },
    /// A cleartext message body was recovered from the store.
    CleartextMessage {
        /// The conversation the message belongs to.
        conversation: Option<String>,
        /// The sender, if known.
        sender: Option<String>,
        /// The message time, if known.
        time: Option<String>,
    },
    /// A deletion tombstone survived in the LevelDB and was recovered.
    DeletedRecord {
        /// The object store it came from.
        store: String,
        /// Its primary key.
        primary_key: String,
    },
    /// The Wire `otr_key` (attachment key) is present in the IndexedDB.
    OtrKeyPresent {
        /// The object store it came from.
        store: String,
        /// Its primary key.
        primary_key: String,
    },
}

impl AnomalyKind {
    /// Stable, scheme-prefixed machine code (a published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::EncryptedMessage { .. } => "WIRE-MESSAGE-ENCRYPTED-UNRECOVERABLE",
            AnomalyKind::CleartextMessage { .. } => "WIRE-MESSAGE-CLEARTEXT",
            AnomalyKind::DeletedRecord { .. } => "WIRE-RECORD-DELETED-RESIDUAL",
            AnomalyKind::OtrKeyPresent { .. } => "WIRE-OTR-KEY-PRESENT",
        }
    }

    /// Canonical severity for the observation.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::EncryptedMessage { .. } => Severity::Info,
            AnomalyKind::CleartextMessage { .. } => Severity::Low,
            AnomalyKind::DeletedRecord { .. } => Severity::Medium,
            AnomalyKind::OtrKeyPresent { .. } => Severity::High,
        }
    }

    /// Analytical lens for the observation.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::EncryptedMessage { .. } => Category::Provenance,
            AnomalyKind::CleartextMessage { .. } | AnomalyKind::DeletedRecord { .. } => {
                Category::Residue
            }
            AnomalyKind::OtrKeyPresent { .. } => Category::Threat,
        }
    }

    /// Human-readable, consistent-with note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::EncryptedMessage { conversation, .. } => format!(
                "a message in conversation {} is client-side (Proteus) encrypted; Wire's message \
                 key is not held in the Chromium OS Safe Storage, so the plaintext is \
                 unrecoverable from this artifact",
                conversation.as_deref().unwrap_or("<unknown>")
            ),
            AnomalyKind::CleartextMessage { conversation, .. } => format!(
                "a cleartext message body was recovered from conversation {} in the Wire IndexedDB",
                conversation.as_deref().unwrap_or("<unknown>")
            ),
            AnomalyKind::DeletedRecord { store, primary_key } => format!(
                "a deleted Wire record ({store}/{primary_key}) survives as a LevelDB tombstone and \
                 was recovered — consistent with residual data after deletion"
            ),
            AnomalyKind::OtrKeyPresent { store, primary_key } => format!(
                "the Wire otr_key attachment key is present in the IndexedDB ({store}/{primary_key}) \
                 — consistent with recoverable attachment-decryption key material"
            ),
        }
    }

    /// MITRE ATT&CK techniques this observation is consistent with.
    #[must_use]
    fn mitre(&self) -> &'static [&'static str] {
        match self {
            // Unsecured Credentials — key material recoverable from local storage.
            AnomalyKind::OtrKeyPresent { .. } => &["T1552"],
            _ => &[],
        }
    }

    /// Evidence rows for the observation.
    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::EncryptedMessage { conversation, time }
            | AnomalyKind::CleartextMessage {
                conversation, time, ..
            } => {
                let mut ev = Vec::new();
                if let Some(c) = conversation {
                    ev.push(Evidence {
                        field: "conversation".to_string(),
                        value: c.clone(),
                        location: None,
                    });
                }
                if let Some(t) = time {
                    ev.push(Evidence {
                        field: "time".to_string(),
                        value: t.clone(),
                        location: None,
                    });
                }
                ev
            }
            AnomalyKind::DeletedRecord { store, primary_key }
            | AnomalyKind::OtrKeyPresent { store, primary_key } => vec![Evidence {
                field: "record".to_string(),
                value: format!("{store}/{primary_key}"),
                location: Some(Location::Key(primary_key.clone())),
            }],
        }
    }

    /// Convert this observation into a canonical [`Finding`].
    fn to_finding(&self, source: Source) -> Finding {
        let mut builder = Finding::observation(self.severity(), self.category(), self.code())
            .note(self.note())
            .source(source);
        for ev in self.evidence() {
            builder = builder.evidence_item(ev);
        }
        for technique in self.mitre() {
            builder = builder.mitre(*technique);
        }
        builder.build()
    }
}

/// Build the [`Source`] stamped on every finding.
fn source() -> Source {
    Source {
        analyzer: ANALYZER.to_string(),
        scope: "IndexedDB".to_string(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

/// Classify one record into the observations it warrants.
fn observe(record: &WireRecord) -> Vec<AnomalyKind> {
    let mut out = Vec::new();

    if record.deleted {
        out.push(AnomalyKind::DeletedRecord {
            store: record.store.clone(),
            primary_key: record.primary_key.clone(),
        });
    }

    if record
        .primary_key
        .to_ascii_lowercase()
        .contains(OTR_KEY_NAME)
    {
        out.push(AnomalyKind::OtrKeyPresent {
            store: record.store.clone(),
            primary_key: record.primary_key.clone(),
        });
    }

    match &record.payload {
        PayloadState::Encrypted { .. } => out.push(AnomalyKind::EncryptedMessage {
            conversation: record.conversation.clone(),
            time: record.time.clone(),
        }),
        PayloadState::Cleartext if record.text.is_some() => {
            out.push(AnomalyKind::CleartextMessage {
                conversation: record.conversation.clone(),
                sender: record.sender.clone(),
                time: record.time.clone(),
            });
        }
        _ => {}
    }

    out
}

/// Audit an interpreted Wire store, returning a canonical [`Finding`] for each
/// observation.
#[must_use]
pub fn audit_store(store: &WireStore) -> Vec<Finding> {
    let src = source();
    store
        .records
        .iter()
        .flat_map(observe)
        .map(|a| a.to_finding(src.clone()))
        .collect()
}
