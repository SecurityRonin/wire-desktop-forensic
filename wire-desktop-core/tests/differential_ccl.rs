//! Tier-1 **differential** validation against the independent Python oracle
//! [`cclgroupltd/ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chromium_reader).
//!
//! Where `oracle_minted.rs` asserts our decode against the *documented* writes
//! of the minted store (construction-derived ground truth, tier 2), this test
//! reconciles our [`read_store`] output against a **separate, third-party
//! re-implementation** reading the *same* on-disk bytes. Agreement of two
//! independent LevelDB-key + Blink/V8-value decoders on the same Chromium
//! IndexedDB store is tier-1 evidence: the answer key is authored by someone
//! else, not by us.
//!
//! The independence being cross-checked is the **byte-level decode** (the
//! LevelDB coding scheme and the V8 `SerializedScriptValue` deserialization —
//! the hard part). The Wire *schema* field mapping (which JSON field is the
//! sender, where the message body lives) is shared documented knowledge applied
//! to each side's own decode, exactly as the leveldb-forensic differential
//! applies the same "live view" rule to each side.
//!
//! ## Gating (skips cleanly unless the oracle is present)
//! * `CCL_WIRE_ORACLE` — path to a Python interpreter that can
//!   `from ccl_chromium_reader import ccl_chromium_indexeddb` (add the clone to
//!   `PYTHONPATH`). Unset ⇒ skip.
//! * `CCL_WIRE_DIR` — optional override pointing at a different Chromium
//!   IndexedDB store directory. Defaults to the committed minted fixture, so the
//!   differential runs against real Chromium-authored bytes with zero setup once
//!   the oracle is available.
//!
//! When `CCL_WIRE_ORACLE` is set we fail loud on any oracle error (a broken
//! interpreter is a bootstrap failure, never a silent skip). Absence of the env
//! var is the only clean-skip path.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use wire_desktop_core::{read_store, WireRecord};

/// The committed minted-store fixture directory (workspace-root relative).
fn default_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/wire-indexeddb/http_127.0.0.1_8731.indexeddb.leveldb")
}

/// The bundled Python oracle driver (this test's private companion).
fn oracle_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ccl_oracle.py")
}

/// Decode hex to bytes.
fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex from oracle: {s:?}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex from oracle"))
        .collect()
}

fn unhex_str(s: &str) -> String {
    String::from_utf8(unhex(s)).expect("oracle emits UTF-8 hex")
}

/// What both decoders are reconciled on.
#[derive(Default, PartialEq, Eq)]
struct Sets {
    /// `(store, primary_key, kind)` for every live record.
    records: BTreeSet<(String, String, String)>,
    /// `(store, primary_key, field_name, value)` for every interpreted field.
    fields: BTreeSet<(String, String, String, String)>,
    /// `(store, primary_key)` of every record classified as encrypted/opaque.
    encrypted: BTreeSet<(String, String)>,
}

/// Run the ccl oracle over `dir` and parse its hex-line output into [`Sets`].
fn oracle_sets(python: &str, dir: &Path) -> Sets {
    let out = Command::new(python)
        .arg(oracle_script())
        .arg(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to launch ccl oracle {python:?}: {e}"));
    assert!(
        out.status.success(),
        "ccl oracle exited {:?}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("oracle stdout is UTF-8");
    let mut sets = Sets::default();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        match f.next() {
            Some("REC") => {
                let store = unhex_str(f.next().expect("REC store"));
                let key = unhex_str(f.next().expect("REC key"));
                let kind = unhex_str(f.next().expect("REC kind"));
                sets.records.insert((store, key, kind));
            }
            Some("FIELD") => {
                let store = unhex_str(f.next().expect("FIELD store"));
                let key = unhex_str(f.next().expect("FIELD key"));
                let name = unhex_str(f.next().expect("FIELD name"));
                let value = unhex_str(f.next().expect("FIELD value"));
                sets.fields.insert((store, key, name, value));
            }
            Some("ENC") => {
                let store = unhex_str(f.next().expect("ENC store"));
                let key = unhex_str(f.next().expect("ENC key"));
                sets.encrypted.insert((store, key));
            }
            other => panic!("unrecognised oracle line tag {other:?} in {line:?}"),
        }
    }
    sets
}

/// Project our record stream onto the same live view the oracle emits: every
/// non-tombstone record, decomposed into the record identity, its interpreted
/// scalar fields, and its encryption classification.
fn our_sets(recs: &[WireRecord]) -> Sets {
    let mut sets = Sets::default();
    for r in recs.iter().filter(|r| !r.deleted) {
        let store = r.store.clone();
        let key = r.primary_key.clone();
        sets.records
            .insert((store.clone(), key.clone(), r.kind.as_str().to_string()));

        let mut field = |name: &str, val: &Option<String>| {
            if let Some(v) = val {
                sets.fields
                    .insert((store.clone(), key.clone(), name.to_string(), v.clone()));
            }
        };
        field("id", &r.id);
        field("conversation", &r.conversation);
        field("sender", &r.sender);
        field("time", &r.time);
        field("message_type", &r.message_type);
        field("name", &r.name);
        field("text", &r.text);

        if r.is_encrypted() {
            sets.encrypted.insert((store, key));
        }
    }
    sets
}

#[test]
fn differential_matches_ccl_chromium_reader() {
    let Ok(python) = std::env::var("CCL_WIRE_ORACLE") else {
        eprintln!(
            "skipping ccl differential: set CCL_WIRE_ORACLE to a Python \
             interpreter that can `from ccl_chromium_reader import \
             ccl_chromium_indexeddb` (add the clone to PYTHONPATH)"
        );
        return;
    };
    if python.trim().is_empty() {
        eprintln!("skipping ccl differential: CCL_WIRE_ORACLE is empty");
        return;
    }

    let dir = std::env::var_os("CCL_WIRE_DIR").map_or_else(default_fixture_dir, PathBuf::from);
    assert!(
        dir.is_dir(),
        "CCL_WIRE_DIR / fixture is not a directory: {}",
        dir.display()
    );

    let ours = our_sets(
        &read_store(&dir)
            .expect("our reader decodes the store")
            .records,
    );
    let theirs = oracle_sets(&python, &dir);

    // Real bytes must carry records, or the differential proves nothing (guards
    // against pointing at an empty/wrong directory).
    assert!(
        !theirs.records.is_empty(),
        "ccl oracle found no records in {} — wrong directory?",
        dir.display()
    );

    assert_eq!(
        ours.records,
        theirs.records,
        "live (store, key, kind) record sets diverge from ccl_chromium_reader\n\
         ours-only:   {:?}\n\
         theirs-only: {:?}",
        ours.records.difference(&theirs.records).collect::<Vec<_>>(),
        theirs.records.difference(&ours.records).collect::<Vec<_>>(),
    );

    assert_eq!(
        ours.fields,
        theirs.fields,
        "interpreted (store, key, field, value) sets diverge from ccl_chromium_reader\n\
         ours-only:   {:?}\n\
         theirs-only: {:?}",
        ours.fields.difference(&theirs.fields).collect::<Vec<_>>(),
        theirs.fields.difference(&ours.fields).collect::<Vec<_>>(),
    );

    assert_eq!(
        ours.encrypted,
        theirs.encrypted,
        "encrypted-record sets diverge from ccl_chromium_reader\n\
         ours-only:   {:?}\n\
         theirs-only: {:?}",
        ours.encrypted
            .difference(&theirs.encrypted)
            .collect::<Vec<_>>(),
        theirs
            .encrypted
            .difference(&ours.encrypted)
            .collect::<Vec<_>>(),
    );
}
