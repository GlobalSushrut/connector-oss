//! CDMI — Chaotic Distributed Matrix Intelligence isolation.
//!
//! Untrusted intelligence touching hardware-capable nodes: on continuity break or
//! tamper, revoke all quanta, quarantine the agent, and cut egress (fail-closed).

use connector_trust::ContinuityStateV2;
use serde_json::{json, Value};

use crate::kernel::{agent_principal, continuity, docklock};
use crate::quanta_polar;
use crate::state::{PlatformState, SharedState};

const MATRIX_META_FOLDER: &str = "agent_meta";

/// Hardware-capable matrix cells require signed ERM + top isolation grade.
pub fn matrix_hw_enforce_enabled() -> bool {
    docklock::ring1_enforce_enabled()
        || crate::substrate::cage_security::prodish_isolation_enforced()
        || env_flag("CONNECTOR_MATRIX_HW_ENFORCE")
        || env_flag("CONNECTOR_IIA_RING1_STRICT")
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Agent is under matrix egress isolation (continuity break / tamper / operator hold).
pub fn agent_egress_isolated(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    es.folder_get(MATRIX_META_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|m| m.get("egress_isolated").and_then(|v| v.as_bool()))
        .unwrap_or(false)
}

/// Full matrix reaction: revoke quanta → quarantine → egress isolate → host cut → audit.
pub fn react_on_continuity_break(state: &SharedState, api_pid: &str, reason: &str) {
    let revoked = quanta_polar::revoke_all_quanta_for_agent(state.as_ref(), api_pid);
    crate::services::admission::matrix_security_isolate(state, api_pid, reason);
    match crate::kernel::matrix_host_egress::apply_matrix_host_egress_cut(api_pid, reason) {
        Ok(cut) => {
            stamp_host_egress_meta(
                state.as_ref(),
                api_pid,
                &cut.backend,
                &cut.detail,
                cut.applied,
                &cut.intelligence_mark,
            );
            if !cut.applied && matrix_hw_enforce_enabled() {
                tracing::error!(
                    agent_pid = %api_pid,
                    detail = %cut.detail,
                    "CDMI intelligence host egress cut not applied under HW enforce"
                );
            }
        }
        Err(e) => {
            stamp_host_egress_meta(state.as_ref(), api_pid, "failed", &e, false, "");
            tracing::error!(
                agent_pid = %api_pid,
                error = %e,
                "CDMI intelligence host egress cut FAILED (fail-closed stamp recorded)"
            );
        }
    }
    stamp_matrix_event(state.as_ref(), api_pid, reason, revoked);
    tracing::warn!(
        agent_pid = %api_pid,
        reason = %reason,
        quanta_revoked = revoked,
        "CDMI matrix isolation engaged"
    );
}

fn stamp_host_egress_meta(
    state: &PlatformState,
    api_pid: &str,
    backend: &str,
    detail: &str,
    applied: bool,
    intelligence_mark: &str,
) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let existing = es
        .folder_get(MATRIX_META_FOLDER, api_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": api_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    meta.insert("host_egress_cut_applied".into(), json!(applied));
    meta.insert("host_egress_cut_backend".into(), json!(backend));
    meta.insert("host_egress_cut_detail".into(), json!(detail));
    meta.insert("intelligence_egress_mark".into(), json!(intelligence_mark));
    meta.insert("execution_plane".into(), json!("intelligence"));
    let _ = es.folder_put(MATRIX_META_FOLDER, api_pid, &serde_json::Value::Object(meta));
}

/// PlatformState-only path for lab hooks without SharedState handle.
pub fn react_on_continuity_break_platform(state: &PlatformState, api_pid: &str, reason: &str) {
    let revoked = quanta_polar::revoke_all_quanta_for_agent(state, api_pid);
    stamp_egress_isolated_meta(state, api_pid, reason);
    match crate::kernel::matrix_host_egress::apply_matrix_host_egress_cut(api_pid, reason) {
        Ok(cut) => stamp_host_egress_meta(
            state,
            api_pid,
            &cut.backend,
            &cut.detail,
            cut.applied,
            &cut.intelligence_mark,
        ),
        Err(e) => stamp_host_egress_meta(state, api_pid, "failed", &e, false, ""),
    }
    stamp_matrix_event(state, api_pid, reason, revoked);
}

/// Operator / CVR lifecycle: cut egress for one agent (PlatformState path).
pub fn isolate_agent_egress(state: &PlatformState, agent_pid: &str) -> Value {
    stamp_egress_isolated_meta(state, agent_pid, "cvr_lifecycle_quarantine_or_stop");
    match crate::kernel::matrix_host_egress::apply_matrix_host_egress_cut(
        agent_pid,
        "cvr_lifecycle",
    ) {
        Ok(cut) => {
            stamp_host_egress_meta(
                state,
                agent_pid,
                &cut.backend,
                &cut.detail,
                cut.applied,
                &cut.intelligence_mark,
            );
            json!({
                "ok": cut.applied || !matrix_hw_enforce_enabled(),
                "applied": cut.applied,
                "backend": cut.backend,
                "detail": cut.detail,
            })
        }
        Err(e) => {
            stamp_host_egress_meta(state, agent_pid, "failed", &e, false, "");
            json!({
                "ok": !matrix_hw_enforce_enabled(),
                "applied": false,
                "error": e,
                "honesty": if matrix_hw_enforce_enabled() {
                    "HW enforce on — cut failure is fail-closed"
                } else {
                    "Soft stamp only — matrix tools unavailable"
                },
            })
        }
    }
}

fn stamp_egress_isolated_meta(state: &PlatformState, api_pid: &str, reason: &str) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let existing = es
        .folder_get(MATRIX_META_FOLDER, api_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": api_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();
    meta.insert("quarantined".into(), serde_json::json!(true));
    meta.insert("quarantine_reason".into(), serde_json::json!(reason));
    meta.insert("egress_isolated".into(), serde_json::json!(true));
    meta.insert("matrix_isolation_reason".into(), serde_json::json!(reason));
    meta.insert("matrix_isolated_at".into(), serde_json::json!(now));
    meta.insert("cdmi_posture".into(), serde_json::json!("egress_isolated"));
    meta.insert("paused".into(), serde_json::json!(true));
    let _ = es.folder_put(MATRIX_META_FOLDER, api_pid, &serde_json::Value::Object(meta));
}

fn stamp_matrix_event(state: &PlatformState, api_pid: &str, reason: &str, revoked: usize) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let key = format!("matrix_{}", chrono::Utc::now().timestamp_millis());
    let _ = es.folder_put(
        "matrix_isolation_audit",
        &key,
        &json!({
            "schema": "connector.matrix.isolation.v1",
            "agent_pid": api_pid,
            "reason": reason,
            "quanta_revoked": revoked,
            "egress_isolated": true,
            "at_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
}

/// Before hardware-touching effects: signed ERM + cage grade must be honest.
pub fn assert_hardware_reality_bound(state: &PlatformState) -> Result<(), String> {
    if !matrix_hw_enforce_enabled() {
        return Ok(());
    }
    let erm = continuity::mint_execution_reality_manifest(state);
    if erm.signature.is_none() {
        return Err("erm_unsigned".into());
    }
    if let Err(e) = crate::substrate::cage_security::assert_cage_isolation_grade(state) {
        return Err(e.into());
    }
    Ok(())
}

pub fn status_for_agent(state: &PlatformState, agent_pid: &str) -> serde_json::Value {
    let continuity = agent_principal::load_continuity(state, agent_pid);
    let isolated = agent_egress_isolated(state, agent_pid);
    let hw_enforce = matrix_hw_enforce_enabled();
    let cage = crate::substrate::cage_security::cage_security_status(state);
    let mark = crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(agent_pid);
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    json!({
        "schema": "connector.matrix.isolation.status.v1",
        "agent_pid": agent_pid,
        "principal_id": principal_id,
        "intelligence_mark": mark,
        "cdmi_posture": if isolated { "egress_isolated" } else { "nominal" },
        "egress_isolated": isolated,
        "continuity_state": continuity.as_ref().map(|c| format!("{:?}", c.state)),
        "continuity_broken": continuity
            .as_ref()
            .map(|c| c.state == ContinuityStateV2::Broken)
            .unwrap_or(false),
        "matrix_hw_enforce": hw_enforce,
        "ring1_enforce": docklock::ring1_enforce_enabled(),
        "cage_security": cage,
        "hardware_reality_bound": assert_hardware_reality_bound(state).is_ok(),
        "threat_model": "chaotic_intelligence_untrusted_hardware_capable_node",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_hw_follows_ring1_or_prodish() {
        std::env::remove_var("CONNECTOR_MATRIX_HW_ENFORCE");
        std::env::remove_var("CONNECTOR_IIA_RING1");
        std::env::remove_var("CONNECTOR_ENV");
        assert!(!matrix_hw_enforce_enabled() || docklock::ring1_enforce_enabled());
    }
}
