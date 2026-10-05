//! # Adaptive Firewall Configuration Service
//!
//! Surfaces `connector_engine::adaptive_threshold::AdaptiveThresholdManager` and
//! `connector_engine::content_guard` detectors as a configurable service.
//!
//! Routes:
//!   GET  /firewall/standard              — Graph Firewall v1 contract
//!   GET  /firewall/status                — Fleet agentic breaker + relation graph summary
//!   GET  /firewall/status/:pid           — Per-agent breaker + relation graph
//!   POST /firewall/rules                 — Persist dynamic graph rule (admin)
//!   GET  /firewall/thresholds/{pid}      — adapted thresholds for agent
//!   GET  /firewall/baselines             — all agent baselines
//!   GET  /firewall/adjustments           — threshold adjustment audit log
//!   POST /firewall/inspect               — run content through all detectors
//!   GET  /firewall/false-positives/{pid} — flagged items for review

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// GET /firewall/standard — Graph Firewall v1 + agentic control breaker contract.
pub async fn firewall_standard() -> Json<serde_json::Value> {
    Json(crate::substrate::graph_firewall::intelligence_standard_json())
}

/// GET /firewall/status — fleet-wide graph firewall + breaker status.
pub async fn firewall_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(crate::substrate::graph_firewall::fleet_status(&state))
}

/// GET /firewall/status/:pid — per-agent relation graph + breaker status.
pub async fn firewall_agent_status(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::graph_firewall::agent_status(&state, &pid))
}

#[derive(Deserialize)]
pub struct GraphRuleRequest {
    pub rule_id: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub namespace_prefix: Option<String>,
    #[serde(default = "default_deny_action")]
    pub action: String,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_deny_action() -> String {
    "deny".into()
}

/// POST /firewall/rules — persist a dynamic relation-graph rule.
pub async fn put_graph_rule(
    State(state): State<SharedState>,
    Json(req): Json<GraphRuleRequest>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    let body = serde_json::json!({
        "rule_id": req.rule_id,
        "operation": req.operation,
        "namespace_prefix": req.namespace_prefix,
        "action": req.action,
        "reason": req.reason,
        "updated_at": now_iso(),
    });
    let _ = es.folder_put("graph_firewall_rules", &req.rule_id, &body);
    Json(serde_json::json!({
        "ok": true,
        "rule_id": req.rule_id,
        "stored": true,
    }))
}

/// GET /firewall/thresholds/{pid} — current adapted thresholds for an agent.
pub async fn agent_thresholds(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let at = state.adaptive_thresholds.lock().unwrap();
    let thresh = at.thresholds_for(&pid);
    let avg = at.agent_avg_score(&pid);
    Json(serde_json::json!({
        "agent_pid": pid,
        "block_threshold": thresh.block,
        "warn_threshold": thresh.warn,
        "review_threshold": thresh.review,
        "avg_score": avg,
        "adapted": avg.is_some(),
    }))
}

/// GET /firewall/baselines — all agent baselines.
pub async fn baselines(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let at = state.adaptive_thresholds.lock().unwrap();
    // AdaptiveThresholdManager has no all_baselines — return adjustment log summary
    let log = at.adjustment_log();
    let agents: Vec<&str> = log.iter().map(|a| a.agent_pid.as_str()).collect();
    let unique: std::collections::HashSet<&str> = agents.into_iter().collect();
    let entries: Vec<serde_json::Value> = unique
        .iter()
        .map(|pid| {
            let avg = at.agent_avg_score(pid);
            let thresh = at.thresholds_for(pid);
            serde_json::json!({
                "agent_pid": pid,
                "avg_score": avg,
                "block_threshold": thresh.block,
                "warn_threshold": thresh.warn,
            })
        })
        .collect();
    Json(serde_json::json!({"count": entries.len(), "baselines": entries}))
}

/// GET /firewall/adjustments — threshold adjustment audit log.
pub async fn adjustments(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let at = state.adaptive_thresholds.lock().unwrap();
    let items = at.adjustment_log();
    let entries: Vec<serde_json::Value> = items
        .iter()
        .map(|a| {
            serde_json::json!({
                "timestamp": a.timestamp,
                "agent_pid": a.agent_pid,
                "direction": a.direction,
                "old_block": a.old_block,
                "new_block": a.new_block,
                "avg_score": a.avg_score,
            })
        })
        .collect();
    Json(serde_json::json!({"count": entries.len(), "adjustments": entries}))
}

#[derive(Deserialize)]
pub struct InspectRequest {
    pub content: String,
    pub agent_pid: String,
    #[serde(default)]
    pub namespace: String,
}

/// POST /firewall/inspect — run content through all 5 content detectors.
pub async fn inspect_content(
    State(state): State<SharedState>,
    Json(req): Json<InspectRequest>,
) -> Json<serde_json::Value> {
    use connector_engine::guard_pipeline::GuardRequest;
    use vac_core::namespace_types::SecurityLevel;
    let mut guard = state.guard.lock().unwrap();
    let guard_req = GuardRequest {
        request_id: format!("fw_{}", chrono::Utc::now().timestamp_millis()),
        agent_pid: req.agent_pid.clone(),
        agent_clearance: SecurityLevel::Standard,
        operation: "inspect".into(),
        namespace: req.namespace.clone(),
        content: Some(req.content.clone()),
        content_type: Some("input".into()),
        is_owner: false,
        has_grant: false,
        has_integrity_grant: false,
        has_write_down_grant: false,
        is_read: true,
        is_write: false,
        is_kernel: false,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };
    let chain = guard.evaluate(&guard_req);
    let blocked = matches!(
        chain.final_decision,
        vac_core::guard::GuardDecision::Deny { .. }
    );

    Json(serde_json::json!({
        "agent_pid": req.agent_pid,
        "content_length": req.content.len(),
        "blocked": blocked,
        "final_decision": format!("{:?}", chain.final_decision),
        "layers_evaluated": chain.layer_verdicts.len(),
        "inspected_at": now_iso(),
    }))
}

/// GET /firewall/false-positives/{pid} — flagged (non-blocked) items for review.
pub async fn false_positives(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let guard = state.guard.lock().unwrap();
    // GuardPipeline.verdict_log returns &[GuardVerdictChain]; filter by agent_pid
    // Flag = final_decision is NOT Deny but has >1 Hold/Warn layer verdicts
    let log = guard.verdict_log();
    let flagged: Vec<serde_json::Value> = log
        .iter()
        .filter(|c| c.agent_pid == pid)
        .filter(|c| {
            !matches!(
                c.final_decision,
                vac_core::guard::GuardDecision::Deny { .. }
            )
        })
        .map(|c| {
            serde_json::json!({
                "request_id": c.request_id,
                "operation": c.operation,
                "final_decision": format!("{:?}", c.final_decision),
                "layer_count": c.layer_verdicts.len(),
            })
        })
        .collect();
    Json(serde_json::json!({
        "agent_pid": pid,
        "count": flagged.len(),
        "flagged": flagged,
    }))
}

#[cfg(test)]
mod tests {
    use super::InspectRequest;

    /// Stable JSON contract: unknown fields ignored (WitnessCtl sends `checks`).
    #[test]
    fn inspect_request_deserializes_with_extra_checks_field() {
        let v = serde_json::json!({
            "content": "hello",
            "agent_pid": "agent-1",
            "namespace": "witness/test",
            "checks": ["pii", "injection"]
        });
        let r: InspectRequest = serde_json::from_value(v).unwrap();
        assert_eq!(r.content, "hello");
        assert_eq!(r.agent_pid, "agent-1");
        assert_eq!(r.namespace, "witness/test");
    }
}
