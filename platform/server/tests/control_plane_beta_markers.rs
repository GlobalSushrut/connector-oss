//! Static markers for **AGOS_UI_CONTROL_PLANE_REMEDIATION.md** — “mid above control beta”.
//! These tests do not start HTTP servers; they guard honesty defaults in source.

use std::path::PathBuf;

fn read_books_rs() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/services/books.rs");
    std::fs::read_to_string(&p).expect("read books.rs")
}

#[test]
fn books_api_meta_defaults_do_not_claim_reconciled() {
    let s = read_books_rs();
    assert!(
        s.contains("reconciliation_status: \"UNVERIFIED\".to_string()"),
        "ApiMeta defaults must be UNVERIFIED (not RECONCILED)"
    );
    assert!(
        s.contains("AUDIT_COUNTS_ALIGNED"),
        "System position integrity should use explicit AUDIT_COUNTS_ALIGNED label"
    );
    assert!(
        !s.contains("reconciliation_status: \"RECONCILED\".to_string()"),
        "books.rs must not hardcode meta reconciliation_status RECONCILED"
    );
}

#[test]
fn books_close_session_does_not_invent_trust_at_close() {
    let s = read_books_rs();
    assert!(
        s.contains("trust_at_close: 0"),
        "close_session must not fabricate a high trust_at_close score"
    );
}
