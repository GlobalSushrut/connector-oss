//! Same architecture invariants, read only from this crate (no dependency on tracetramp test cwd).
//! Run: `cargo test -p witnessctl --test architecture_claims`

const ROUTES: &str = include_str!("../src/routes.rs");
const CAPTURE: &str = include_str!("../src/capture.rs");
const PROXY: &str = include_str!("../src/proxy.rs");
const COMPLIANCE: &str = include_str!("../src/compliance.rs");
const EXPORT: &str = include_str!("../src/export.rs");

#[test]
fn handoff_route_inserts_payload_table() {
    assert!(ROUTES.contains("INSERT INTO witness_tracetramp_handoffs"));
}

#[test]
fn capture_sql_links_tracetramp_ids() {
    assert!(CAPTURE.contains("tracetramp_trace_id") && CAPTURE.contains("tracetramp_request_id"));
}

#[test]
fn proxy_pipeline_calls_ingest_after_forward() {
    assert!(PROXY.contains("ingest_with_route_attestation"));
}

#[test]
fn compliance_queries_captures_by_session() {
    assert!(COMPLIANCE.contains("FROM witness_captures WHERE session_id"));
}

#[test]
fn export_session_includes_decision_digest_column() {
    assert!(EXPORT.contains("decision_digest"));
}
