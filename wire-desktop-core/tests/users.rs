//! User-record interpretation (object store `users`).

mod common;

use common::{obj, record, s};
use wire_desktop_core::{interpret_records, WireRecordKind};

#[test]
fn extracts_user_id_and_display_name() {
    let recs = vec![record(
        "users",
        "user-alice",
        obj(vec![
            ("id", s("user-alice")),
            ("name", s("Alice Example")),
            ("handle", s("alice")),
        ]),
    )];

    let store = interpret_records(&recs);
    let user = store
        .records
        .iter()
        .find(|r| r.kind == WireRecordKind::User)
        .expect("a user record");

    assert_eq!(user.id.as_deref(), Some("user-alice"));
    assert_eq!(user.name.as_deref(), Some("Alice Example"));
}
