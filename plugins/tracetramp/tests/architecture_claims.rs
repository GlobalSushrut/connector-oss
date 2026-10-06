//! Static verification of architecture claims about TraceTramp (and cross-crate WitnessCtl files).
//! Run: `cargo test -p tracetramp --test architecture_claims`

const CONTROL: &str = include_str!("../src/control.rs");
const VIEW: &str = include_str!("../src/view.rs");
const GATEWAY: &str = include_str!("../src/gateway.rs");
const CAGE: &str = include_str!("../src/cage.rs");
const CONFIG_RS: &str = include_str!("../src/config.rs");
const TRACE_PROJECTION: &str = include_str!("../src/trace_projection.rs");
const RESOLVER: &str = include_str!("../src/resolver.rs");
const CONNECTOR: &str = include_str!("../src/connector.rs");
const WITNESS_ROUTES: &str = include_str!("../../witnessctl/src/routes.rs");
const WITNESS_CAPTURE: &str = include_str!("../../witnessctl/src/capture.rs");
const WITNESS_PROXY: &str = include_str!("../../witnessctl/src/proxy.rs");
const WITNESS_COMPLIANCE: &str = include_str!("../../witnessctl/src/compliance.rs");
const MIG_TRACE_LEDGER: &str = include_str!("../migrations/20260503160000_trace_events_ledger_guard.sql");
const DECISION_ENVELOPE: &str = include_str!("../src/decision_envelope.rs");

#[test]
fn claim_trace_events_append_only_migration_present() {
    assert!(
        MIG_TRACE_LEDGER.contains("tracetramp_trace_events_ledger_guard"),
        "ledger guard migration must define the trigger function"
    );
    assert!(
        MIG_TRACE_LEDGER.contains("DELETE forbidden"),
        "append-only ledger must forbid DELETE on trace_events"
    );
    assert!(
        MIG_TRACE_LEDGER.contains("immutable columns cannot change"),
        "ledger guard must forbid mutating core trace_events columns"
    );
}

#[test]
fn claim_decision_envelope_declares_ledger_contract() {
    assert!(
        DECISION_ENVELOPE.contains("LEDGER_CONTRACT") && DECISION_ENVELOPE.contains("ledger_contract"),
        "decision envelope must expose ledger_contract for exports / SIEM"
    );
}

#[test]
fn claim_view_pipeline_does_not_insert_trace_events() {
    assert!(
        !VIEW.contains("INSERT INTO trace_events"),
        "view.rs must not persist trace_events (TUI/admin traces come from control pipeline only)"
    );
}

#[test]
fn claim_control_pipeline_inserts_trace_events() {
    assert!(
        CONTROL.contains("INSERT INTO trace_events"),
        "control.rs must INSERT trace_events for TUI/admin aggregation"
    );
}

#[test]
fn claim_resolver_hardcodes_control_mode_in_lab_path() {
    assert!(
        RESOLVER.contains("default_mode: RequestMode::Control"),
        "resolve_tenant currently always returns Control (tenant DB default_mode unused here)"
    );
}

#[test]
fn claim_gateway_routes_view_vs_control() {
    assert!(
        GATEWAY.contains("RequestMode::View") && GATEWAY.contains("view::handle_request"),
        "gateway routes View mode to view::handle_request"
    );
    assert!(
        GATEWAY.contains("RequestMode::Control") && GATEWAY.contains("control::handle_request"),
        "gateway routes Control mode to control::handle_request"
    );
}

#[test]
fn claim_gateway_gates_optional_view_on_config() {
    assert!(
        GATEWAY.contains("allow_view_pipeline") && GATEWAY.contains("effective_request_mode"),
        "gateway must gate optional View pipeline on config + effective_request_mode"
    );
}

#[test]
fn claim_trace_projection_used_by_decision_and_enforcement() {
    assert!(
        TRACE_PROJECTION.contains("cumulative_action_trace_entries")
            && TRACE_PROJECTION.contains("cumulative_block_flags"),
        "trace_projection must expose cumulative action_trace and block_flags"
    );
    assert!(
        GATEWAY.contains("action_trace_cumulative") && GATEWAY.contains("trace_projection::"),
        "gateway decision + enforcement endpoints must embed trace_projection"
    );
}

#[test]
fn claim_provider_exhaustion_records_trace_before_503() {
    let marker = CONTROL
        .find("All provider fallbacks exhausted")
        .expect("provider exhaustion marker");
    let tail = &CONTROL[marker..];
    assert!(
        tail.contains("record_event") && tail.contains("provider_unavailable"),
        "provider chain exhaustion must record_event before 503"
    );
}

#[test]
fn claim_control_has_documented_enforcement_hooks() {
    for needle in [
        "check_operation_block",
        "check_quarantine",
        "classify_default_hitl_hold",
        "check_policy",
        "check_budget",
        "inspect_request_pii",
        "proxy_with_fallback",
        "persist_decision_tree",
        "witness_tracetramp_handoff",
        "HDR_TRACE_TRAMP_LANES",
        "control,observe",
    ] {
        assert!(
            CONTROL.contains(needle),
            "control.rs missing expected hook: {needle}"
        );
    }
}

#[test]
fn claim_view_persists_decision_tree_but_not_trace_events() {
    assert!(
        VIEW.contains("persist_decision_tree"),
        "view pipeline persists decision_trees"
    );
    assert!(
        !VIEW.contains("INSERT INTO trace_events"),
        "view must not insert trace_events"
    );
}

#[test]
fn claim_high_risk_event_is_recorded_but_request_not_short_circuited_before_route() {
    let start = CONTROL
        .find("// Step 4: Risk scoring")
        .expect("Step 4 marker");
    let end = CONTROL
        .find("// Step 5: Route selection")
        .expect("Step 5 marker");
    let slice = &CONTROL[start..end];
    assert!(
        slice.contains("risk_score >= 0.7") && slice.contains("RiskScored"),
        "RiskScored step must exist"
    );
    assert!(
        !slice.contains("return Ok("),
        "Between RiskScored and RouteSelected there must be no early HTTP return — high risk is logged as Block in trace_events but the request continues"
    );
}

#[test]
fn claim_response_preview_patch_targets_response_released_row() {
    assert!(
        CONTROL.contains("UPDATE trace_events SET metadata = metadata || $1::jsonb")
            && CONTROL.contains("ResponseReleased"),
        "response_preview backfill must target ResponseReleased trace_events row"
    );
}

#[test]
fn claim_connector_posts_tracetramp_handoff_url() {
    assert!(
        CONNECTOR.contains("/api/v1/integrations/tracetramp/handoff"),
        "ConnectorClient must POST TraceTramp handoff to WitnessCtl integration path"
    );
}

#[test]
fn claim_witnessctl_handoff_inserts_row() {
    assert!(
        WITNESS_ROUTES.contains("INSERT INTO witness_tracetramp_handoffs"),
        "tracetramp_handoff must insert witness_tracetramp_handoffs"
    );
    assert!(
        WITNESS_ROUTES.contains("tracetramp_by_trace"),
        "by-trace lookup route must exist"
    );
}

#[test]
fn claim_witnessctl_capture_stores_tracetramp_correlation_columns() {
    assert!(
        WITNESS_CAPTURE.contains("tracetramp_trace_id") && WITNESS_CAPTURE.contains("tracetramp_request_id"),
        "witness_captures insert must include TraceTramp correlation columns"
    );
}

#[test]
fn claim_witnessctl_proxy_chains_forward_then_capture() {
    assert!(
        WITNESS_PROXY.contains("proxy_and_capture") && WITNESS_PROXY.contains("ingest_with_route_attestation"),
        "ProxyEngine must forward then run capture ingest"
    );
}

#[test]
fn claim_witnessctl_compliance_reads_captures_for_session() {
    assert!(
        WITNESS_COMPLIANCE.contains("FROM witness_captures WHERE session_id"),
        "ComplianceEngine must aggregate witness_captures per session"
    );
}

#[test]
fn claim_cage_address_hex_validation() {
    assert!(
        CAGE.contains("validate_cage_sha_address") && CAGE.contains("is_ascii_hexdigit"),
        "cage.rs must validate SHA-style hex addresses"
    );
    assert!(
        GATEWAY.contains("crate::cage::validate_cage_sha_address"),
        "gateway cage proxy must call cage validation"
    );
}

#[test]
fn claim_redis_optional_config() {
    assert!(
        CONFIG_RS.contains("redis_url: Option<String>") && CONFIG_RS.contains("fn redis_enabled"),
        "TraceTramp config must support optional Redis (postgres-only prod)"
    );
}

#[test]
fn claim_provider_circuit_breaker_present() {
    assert!(
        CONTROL.contains("is_provider_circuit_open") && CONTROL.contains("Opening circuit for provider"),
        "control pipeline must implement provider circuit breaker"
    );
}

#[test]
fn claim_witnessctl_admin_dashboard() {
    assert!(
        WITNESS_ROUTES.contains("/admin/dashboard") && WITNESS_ROUTES.contains("admin-ui/dashboard.html"),
        "WitnessCtl must serve operator dashboard"
    );
}

#[test]
fn claim_witnessctl_custody_quorum_module() {
    const CUSTODY_NODE: &str = include_str!("../../witnessctl/src/custody_node.rs");
    const CUSTODY: &str = include_str!("../../witnessctl/src/custody.rs");
    assert!(
        CUSTODY_NODE.contains("verify_quorum") && CUSTODY_NODE.contains("CustodyProof"),
        "custody_node must implement quorum verification"
    );
    assert!(
        CUSTODY.contains("replicate_url") && CUSTODY.contains("store_custody_proof"),
        "custody worker must use replicate protocol and persist proofs"
    );
}

#[test]
fn claim_witnessctl_witness_bundle_format() {
    const BUNDLE_FILE: &str = include_str!("../../witnessctl/src/bundle_file.rs");
    const SESSION: &str = include_str!("../../witnessctl/src/session.rs");
    assert!(
        BUNDLE_FILE.contains(".witness") && BUNDLE_FILE.contains(".witness.json"),
        "bundle_file must define .witness paths and metadata sidecar"
    );
    assert!(
        SESSION.contains("bundle_file::write_bundle_artifacts"),
        "seal must materialize .witness bundles"
    );
}
