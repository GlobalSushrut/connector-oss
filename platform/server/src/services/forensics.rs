//! Forensics aggregate — IIA chain, rollups, package, CFNI honesty (operator surface).

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::honesty::operator_envelope, services::agents::caller, services::kernel_host,
    state::SharedState,
};

fn auth_ok(headers: &HeaderMap) -> bool {
    caller(headers).is_some()
}

#[derive(Debug, Deserialize)]
pub struct AgentWindowQuery {
    pub agent_pid: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

fn window(q: &AgentWindowQuery) -> (Option<i64>, Option<i64>) {
    (q.from.or(q.from_ms), q.to.or(q.to_ms))
}

/// `GET /api/v1/forensics/status`
pub async fn get_forensics_status(State(state): State<SharedState>) -> Json<Value> {
    let causal_count = crate::substrate::causal::causal_envelope_count(state.as_ref());
    let latest_env = crate::substrate::causal::latest_envelope_id(state.as_ref());
    let knot_nodes = crate::substrate::knot_rebuild::knot_node_count(&state);
    let kernel_packets = {
        let k = state.kernel.lock().unwrap();
        k.packet_count()
    };
    let isolation = *state.isolation_runtime.read().unwrap();
    let mode = *state.runtime_mode.read().unwrap();
    let effective_plugin_backend =
        crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label();

    let (contract_count, rollup_count, join_count, universal_count, receipt_agents) = {
        let es = state.engine_store.lock().unwrap();
        let contracts = es
            .folder_keys(
                crate::kernel::compliance_contract::COMPLIANCE_CONTRACT_FOLDER,
                None,
            )
            .unwrap_or_default()
            .len();
        let rollups = es
            .folder_keys(crate::kernel::forensic_rollups::ROLLUP_FOLDER, None)
            .unwrap_or_default()
            .len();
        let joins = es
            .folder_keys(crate::kernel::forensic_rollups::JOIN_FOLDER, None)
            .unwrap_or_default()
            .len();
        let universals = es
            .folder_keys(
                crate::kernel::agent_identity_envelope::FORENSIC_UNIVERSAL_FOLDER,
                None,
            )
            .unwrap_or_default()
            .len();
        let receipt_idx = es
            .folder_keys(crate::kernel::forensics::IIA_RECEIPT_INDEX, None)
            .unwrap_or_default()
            .len();
        (contracts, rollups, joins, universals, receipt_idx)
    };

    Json(operator_envelope(json!({
        "schema": "forensics_status.v2",
        "iia": {
            "compliance_contracts": contract_count,
            "intelligence_receipt_agents": receipt_agents,
            "universal_envelopes": universal_count,
            "rollup_buckets": rollup_count,
            "correlation_joins": join_count,
            "apis": {
                "compliance_contract": "GET /api/v1/agents/:pid/compliance-contract",
                "universal": "GET /api/v1/agents/:pid/forensic/universal",
                "rollups": "GET /api/v1/forensics/rollups/:agent",
                "chain": "GET /api/v1/forensics/chain?agent_pid=",
                "package": "GET /api/v1/forensics/package?agent_pid=",
                "court_readiness": "GET /api/v1/forensics/court-readiness?agent_pid=",
                "witnessctl_join": "GET /api/v1/forensics/witnessctl-join?session_id=",
            },
            "signing": {
                "node_pubkey_hex": state.signing_key.public_key_hex(),
                "note": "Court tier only after forensic package rules (B26) — see court-readiness",
            },
        },
        "causal": {
            "envelope_count": causal_count,
            "latest_envelope_id": latest_env,
            "chain_head_key": crate::substrate::causal::CAUSAL_ENVELOPE_FOLDER,
        },
        "cfni": {
            "enabled": crate::substrate::cfni::cfni_enabled(),
            "enforce_production": crate::substrate::cfni::cfni_enforce_production(),
            "header": connector_trust::CFNI_HEADER,
            "fni_flow_id_field": "fni_flow_id",
            "join": "correlate TT/WC captures + moments by fni_flow_id + moment_id",
        },
        "transit": {
            "principal_header": crate::substrate::outbound::PRINCIPAL_CONTEXT_HEADER,
            "data_plane_note": "LLM/tool egress uses gateway admission + CFNI; mgmt plane is TT/WC proxy only",
        },
        "memory_graph": {
            "knot_node_count": knot_nodes,
            "kernel_packet_count": kernel_packets,
            "rebuild_on_boot": true,
        },
        "isolation": {
            "declared_runtime": isolation.as_str(),
            "runtime_mode": mode.as_str(),
            "effective_plugin_backend_env": effective_plugin_backend,
            "fail_closed_boot": true,
            "downgrade_env": "CONNECTOR_ALLOW_ISOLATION_DOWNGRADE",
            "namespace_deny_events": "forensic_rollup_bucket_v2.memory_trace.cross_agent_attempts_denied",
        },
        "moments": {
            "count": crate::services::moment::moment_count(state.as_ref()),
            "moment_id_field": "moment_id",
            "di_audit_middle_field": "DiAuditMiddleEvent.moment_id",
        },
        "object_fabric": {
            "count": crate::services::object_fabric::object_count(&state),
            "storage_backend": "fs_cas",
            "honesty": "CAS blobs under data_dir/object_fabric_cas; storage_backend=fs_cas when put succeeds",
        },
        "timeline": {
            "causal_envelopes": causal_count,
            "moments": crate::services::moment::moment_count(state.as_ref()),
            "artifact_log": crate::substrate::artifact_log::artifact_log_count(state.as_ref()),
            "artifact_log_record_ids": crate::substrate::artifact_log::recent_artifact_record_ids(
                state.as_ref(),
                8,
            ),
            "handoff_pending": crate::substrate::handoff_queue::handoff_queue_stats(state.as_ref())
                .get("pending")
                .cloned()
                .unwrap_or(json!(0)),
            "iia_rollup_buckets": rollup_count,
            "verified": false,
            "verified_note": "Never decorative — verified only after independent recompute / package verify",
        },
        "artifact_log": {
            "count": crate::substrate::artifact_log::artifact_log_count(state.as_ref()),
            "record_ids": crate::substrate::artifact_log::recent_artifact_record_ids(state.as_ref(), 8),
            "folder": crate::substrate::artifact_log::ARTIFACT_LOG_FOLDER,
            "honesty": "Ids from engine_store artifact_log_v2; cite in forensics UI — not a second SoT",
        },
        "fni_verify": {
            "status": if crate::substrate::cfni::cfni_enabled() {
                "cfni_enabled_verify_per_capture"
            } else {
                "cfni_disabled"
            },
            "honesty": "TT/WC store fni_verify_status=unverified at ingest; GET WC /captures/:id/fni-verify + TT /admin/traces/:id/fni-verify run CFNI verify when CONNECTOR_CFNI_SECRET available — never decorative verified",
            "witnessctl": "GET /api/v1/captures/:id + /api/v1/captures/:id/fni-verify",
            "tracetramp": "GET /admin/traces/:trace_id/fni-verify",
        },
        "sgke": {
            "gate": "substrate::sgke_gate",
            "deny_reason": crate::substrate::sgke_gate::REASON_HIGH_I_MISSING_H,
            "high_i_threshold": crate::substrate::sgke_gate::SGKE_HIGH_I_THRESHOLD,
        },
        "projections": {
            "tracetramp_artifact_log": crate::substrate::projection::projection_record_count(state.as_ref()),
            "cnp_edge_artifact_log": crate::substrate::cnp_edge::cnp_edge_count(state.as_ref()),
        },
        "handoff_queue": crate::substrate::handoff_queue::handoff_queue_stats(state.as_ref()),
        "flow_lease": crate::substrate::flow_lease::lease_snapshot(state.as_ref()),
        "egress": {
            "api": "/api/v1/runtime/egress/status",
            "kernel_host_enforce": kernel_host::kernel_enforce_enabled(),
        },
    })))
}

/// GET /api/v1/forensics/rollups/:agent?from=&to=
pub async fn get_forensics_rollups(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent): Path<String>,
    Query(q): Query<AgentWindowQuery>,
) -> Json<Value> {
    if !auth_ok(&headers)
        && !crate::kernel::agent_identity_envelope::agent_self_access(&headers, &agent)
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let (from, to) = window(&q);
    let rollups = crate::kernel::forensic_rollups::list_rollups(state.as_ref(), &agent, from, to);
    Json(json!({
        "ok": true,
        "schema": connector_trust::FORENSIC_ROLLUP_SCHEMA,
        "agent_pid": agent,
        "from_ms": from,
        "to_ms": to,
        "count": rollups.len(),
        "rollups": rollups,
    }))
}

/// GET /api/v1/forensics/chain?agent_pid=
pub async fn get_forensics_chain(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentWindowQuery>,
) -> Json<Value> {
    let Some(agent_pid) = q.agent_pid.as_deref() else {
        return Json(json!({"ok": false, "error": "agent_pid_required"}));
    };
    if !auth_ok(&headers)
        && !crate::kernel::agent_identity_envelope::agent_self_access(&headers, agent_pid)
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let (from, to) = window(&q);
    let joins = crate::kernel::forensic_rollups::list_joins(state.as_ref(), agent_pid);
    let joins: Vec<_> = joins
        .into_iter()
        .filter(|j| {
            if let Some(f) = from {
                if j.issued_at_ms < f {
                    return false;
                }
            }
            if let Some(t) = to {
                if j.issued_at_ms > t {
                    return false;
                }
            }
            true
        })
        .collect();
    let receipts = crate::kernel::forensics::export_receipt_chain(state.as_ref(), agent_pid);
    Json(json!({
        "ok": true,
        "schema": connector_trust::FORENSIC_CORRELATION_SCHEMA,
        "agent_pid": agent_pid,
        "iia_chain_head": crate::kernel::forensics::chain_head_for_agent(state.as_ref(), agent_pid),
        "four_id": crate::kernel::forensics::four_id_linkage(state.as_ref(), agent_pid),
        "join_count": joins.len(),
        "joins": joins,
        "intelligence_receipt_count": receipts.len(),
        "intelligence_receipts": receipts,
    }))
}

/// GET /api/v1/forensics/package?agent_pid=&from=&to=
pub async fn get_forensics_package(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AgentWindowQuery>,
) -> Json<Value> {
    let Some(agent_pid) = q.agent_pid.as_deref() else {
        return Json(json!({"ok": false, "error": "agent_pid_required"}));
    };
    if !auth_ok(&headers)
        && !crate::kernel::agent_identity_envelope::agent_self_access(&headers, agent_pid)
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let (from, to) = window(&q);
    match crate::kernel::forensic_package::build_package(state.as_ref(), agent_pid, from, to) {
        Ok(pkg) => Json(pkg),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

#[derive(Debug, Deserialize)]
pub struct CourtReadinessQuery {
    pub agent_pid: String,
}

/// GET /api/v1/forensics/court-readiness?agent_pid= — DI-5 honesty checklist (never claims soak Done).
pub async fn get_court_readiness(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<CourtReadinessQuery>,
) -> Json<Value> {
    if !auth_ok(&headers)
        && !crate::kernel::agent_identity_envelope::agent_self_access(&headers, &q.agent_pid)
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let pid = q.agent_pid.as_str();
    let mut missing: Vec<String> = Vec::new();

    let setup = crate::kernel::agent_identity_envelope::load_setup(state.as_ref(), pid);
    let forensic_profile = setup
        .as_ref()
        .map(|s| format!("{:?}", s.forensic_profile).to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".into());
    let wc_required = setup
        .as_ref()
        .map(|s| {
            s.forensic_profile
                .evidence_policy()
                .witnessctl_session_required
        })
        .unwrap_or(false);

    let package = crate::kernel::forensic_package::build_package(state.as_ref(), pid, None, None);
    let (package_ok, package_court_ok, signing_tier, stubs, receipt_count, wc_session_from_pkg) =
        match &package {
            Ok(pkg) => {
                let tier = pkg
                    .pointer("/manifest/signing_tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hmac_lab")
                    .to_string();
                let stubs = pkg
                    .pointer("/manifest/honesty/stubs_in_window")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let court = tier.eq_ignore_ascii_case("ed25519_court")
                    || tier.eq_ignore_ascii_case("Ed25519Court");
                let receipts = pkg
                    .pointer("/manifest/receipt_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let sid = pkg
                    .pointer("/manifest/witnessctl_session_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if !court {
                    missing.push("package_not_court_tier".into());
                }
                if !stubs.is_empty() {
                    missing.push("stubs_in_window".into());
                }
                (true, court, tier, stubs, receipts, sid)
            }
            Err(e) => {
                missing.push(format!("package_build_failed:{e}"));
                (false, false, "hmac_lab".into(), Vec::new(), 0u64, None)
            }
        };

    let alignment = crate::kernel::witnessctl_align::load_alignment(state.as_ref(), pid);
    let wc_status = alignment
        .as_ref()
        .and_then(|a| a.get("status").and_then(|x| x.as_str()))
        .unwrap_or("missing")
        .to_string();
    let wc_session_id = alignment
        .as_ref()
        .and_then(|a| a.get("session_id").and_then(|x| x.as_str()))
        .map(|s| s.to_string())
        .or(wc_session_from_pkg);
    let wc_ok = if !wc_required {
        true
    } else {
        let has_session = wc_session_id
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let status_ok = matches!(wc_status.as_str(), "opened" | "aligned" | "open" | "bound");
        if !has_session {
            missing.push("wc_session_required".into());
        } else if !status_ok {
            missing.push(format!("wc_alignment_status:{wc_status}"));
        }
        has_session && status_ok
    };

    let cfni_enabled = crate::substrate::cfni::cfni_enabled();
    let cfni_secret = crate::substrate::cfni::cfni_secret_configured();
    let cfni_enforce = crate::substrate::cfni::cfni_enforce_production();
    if !cfni_enabled {
        missing.push("cfni_disabled".into());
    }
    if !cfni_secret {
        missing.push("cfni_secret_unset".into());
    }

    let lab_body = crate::services::settings_llms::get_lab_mode_body();
    let lab_mode = lab_body
        .get("lab_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if lab_mode {
        missing.push("lab_mode_on".into());
    }

    let profile_court_capable = matches!(forensic_profile.as_str(), "court" | "hipaa" | "soc2");
    if !profile_court_capable {
        missing.push("forensic_profile_not_court_capable".into());
    }

    let llm_stub = matches!(
        std::env::var("CONNECTOR_LLM_STUB")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    );
    if llm_stub {
        missing.push("llm_stub_on".into());
    }

    let live_court_e2e_ready = package_court_ok
        && wc_ok
        && cfni_enabled
        && cfni_secret
        && profile_court_capable
        && !lab_mode
        && !llm_stub;
    if live_court_e2e_ready {
        // Ready checklist ≠ CD-9 human/counsel sign-off.
    } else if missing.is_empty() {
        missing.push("live_court_incomplete".into());
    }

    let checklist = json!([
        {
            "id": "CD-1",
            "ok": !lab_mode,
            "fix": "connectorctl harden ; CONNECTOR_PRESET=production"
        },
        {
            "id": "CD-2",
            "ok": cfni_enabled && cfni_secret,
            "fix": "export CONNECTOR_CFNI_SECRET=… ; unset CONNECTOR_CFNI_DISABLE"
        },
        {
            "id": "CD-3",
            "ok": profile_court_capable && wc_ok,
            "fix": "CONNECTOR_WITNESSCTL_MANAGEMENT_URL + ADMIN_TOKEN ; re-activate"
        },
        {
            "id": "CD-4",
            "ok": profile_court_capable,
            "fix": "POST /agents/:pid/setup forensic_profile=court then activate"
        },
        {
            "id": "CD-5",
            "ok": !llm_stub && stubs.is_empty(),
            "fix": "unset CONNECTOR_LLM_STUB ; connectorctl llm link …"
        },
        {
            "id": "CD-6",
            "ok": package_court_ok,
            "fix": "node Ed25519 key must sign receipts; generate work; rebuild package"
        },
        {
            "id": "CD-7",
            "ok": live_court_e2e_ready,
            "fix": "connectorctl iia court --agent-pid … --save-package ; iia verify-export"
        }
    ]);

    Json(json!({
        "ok": true,
        "schema": "connector.forensics.court_readiness.v2",
        "agent_pid": pid,
        "ready": live_court_e2e_ready,
        "live_court_e2e_ready": live_court_e2e_ready,
        "defensible": live_court_e2e_ready,
        "missing": missing,
        "checklist": checklist,
        "forensic_profile": forensic_profile,
        "lab_mode": lab_mode,
        "lab": lab_body,
        "package": {
            "build_ok": package_ok,
            "package_court_ok": package_court_ok,
            "signing_tier": signing_tier,
            "receipt_count": receipt_count,
            "stubs_in_window": stubs,
        },
        "witnessctl": {
            "required": wc_required,
            "session_id": wc_session_id,
            "alignment_status": wc_status,
            "ok": wc_ok,
        },
        "cfni": {
            "enabled": cfni_enabled,
            "secret_configured": cfni_secret,
            "enforce": cfni_enforce,
            "ok": cfni_enabled && cfni_secret,
        },
        "verify_hint": "connectorctl iia court --agent-pid PID --save-package export.json && connectorctl iia verify-export --file export.json",
        "package_hint": format!("GET /api/v1/forensics/package?agent_pid={pid}"),
        "follow": "COURT_DEFENSIBLE_CHECKLIST.md",
        "honesty": "ready=true is CD-1…CD-7 on this pid. CD-8 custody + CD-9 human/counsel sign-off are still required to market court-grade.",
    }))
}

#[derive(Debug, Deserialize)]
pub struct WitnessctlJoinQuery {
    pub session_id: String,
}

/// GET /api/v1/forensics/witnessctl-join?session_id=
pub async fn get_witnessctl_join(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<WitnessctlJoinQuery>,
) -> Json<Value> {
    if !auth_ok(&headers) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let join =
        crate::kernel::forensic_rollups::witnessctl_export_join(state.as_ref(), &q.session_id);
    Json(json!({
        "ok": true,
        "join": join,
        "witnessctl_export": format!("/plugins/witnessctl/sessions/{}/export", q.session_id),
    }))
}
