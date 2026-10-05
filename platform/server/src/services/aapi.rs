//! AAPI — Action Authorization Plane (P0 gap exposure)
//!
//! Exposes the full ActionEngine:
//! - UCAN-style capability issue / delegate / revoke / verify
//! - Per-agent resource budgets (create / consume / check)
//! - Dynamic policy CRUD
//! - Regulatory templates (HIPAA, Financial)
//! - Tool authorization
//! - Interaction log
//! - Enterprise default-deny toggle

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::aapi::{ComplianceConfig, PolicyEffect, PolicyRule};
use serde::Deserialize;

fn effect_from_str(s: &str) -> PolicyEffect {
    match s {
        "deny" => PolicyEffect::Deny,
        "require_approval" => PolicyEffect::RequireApproval,
        _ => PolicyEffect::Allow,
    }
}

// ── UCAN Capability Issue ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct IssueCapabilityRequest {
    pub issuer: String,
    pub subject: String,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl_hours: u64,
}
fn default_ttl() -> u64 {
    24
}

/// POST /aapi/capabilities/issue
pub async fn issue_capability(
    State(state): State<SharedState>,
    Json(req): Json<IssueCapabilityRequest>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let cap = aapi.issue_capability(
        &req.issuer,
        &req.subject,
        req.actions,
        req.resources,
        req.ttl_hours,
    );
    Json(serde_json::json!({
        "ok": true,
        "token_id": cap.token_id,
        "issuer": cap.issuer,
        "subject": cap.subject,
        "actions": cap.actions,
        "resources": cap.resources,
        "issued_at": cap.issued_at,
        "expires_at": cap.expires_at,
        "ttl_hours": req.ttl_hours,
        "valid": cap.is_valid(),
    }))
}

// ── UCAN Capability Delegate ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DelegateCapabilityRequest {
    pub parent_token_id: String,
    pub new_subject: String,
    #[serde(default)]
    pub remove_actions: Vec<String>,
}

/// POST /aapi/capabilities/delegate
pub async fn delegate_capability(
    State(state): State<SharedState>,
    Json(req): Json<DelegateCapabilityRequest>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let remove: Vec<&str> = req.remove_actions.iter().map(|s| s.as_str()).collect();
    match aapi.delegate_capability(&req.parent_token_id, &req.new_subject, &remove) {
        Some(cap) => Json(serde_json::json!({
            "ok": true,
            "token_id": cap.token_id,
            "parent_token_id": req.parent_token_id,
            "subject": cap.subject,
            "actions": cap.actions,
            "resources": cap.resources,
            "expires_at": cap.expires_at,
            "valid": cap.is_valid(),
            "note": "Attenuated delegation — cannot grant more than parent",
        })),
        None => Json(serde_json::json!({
            "ok": false,
            "error": "Parent token not found or expired",
            "parent_token_id": req.parent_token_id,
        })),
    }
}

// ── UCAN Capability Revoke ────────────────────────────────────────────────────

/// DELETE /aapi/capabilities/:token_id
pub async fn revoke_capability(
    State(state): State<SharedState>,
    Path(token_id): Path<String>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    aapi.revoke_capability(&token_id);
    Json(serde_json::json!({
        "ok": true,
        "token_id": token_id,
        "revoked": true,
    }))
}

// ── UCAN Capability Verify ────────────────────────────────────────────────────

/// GET /aapi/capabilities/:token_id/verify
pub async fn verify_capability(
    State(state): State<SharedState>,
    Path(token_id): Path<String>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    match aapi.verify_capability(&token_id) {
        Some(valid) => Json(serde_json::json!({
            "token_id": token_id,
            "valid": valid,
            "exists": true,
        })),
        None => Json(serde_json::json!({
            "token_id": token_id,
            "valid": false,
            "exists": false,
            "error": "Token not found",
        })),
    }
}

/// GET /aapi/capabilities
pub async fn list_capabilities(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    Json(serde_json::json!({
        "count": aapi.capability_count(),
        "note": "Use GET /aapi/capabilities/:token_id/verify to check individual tokens",
    }))
}

// ── Budget Management ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateBudgetRequest {
    pub agent_pid: String,
    pub resource: String,
    pub limit: f64,
}

/// POST /aapi/budgets
pub async fn create_budget(
    State(state): State<SharedState>,
    Json(req): Json<CreateBudgetRequest>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    aapi.create_budget(&req.agent_pid, &req.resource, req.limit);
    let tracker = aapi
        .list_budgets()
        .into_iter()
        .find(|b| b.agent_pid == req.agent_pid && b.resource == req.resource)
        .cloned();
    drop(aapi);
    if let Some(t) = tracker {
        crate::substrate::aapi_effect_field::persist_budget(state.as_ref(), &t);
    }
    Json(serde_json::json!({
        "ok": true,
        "agent_pid": req.agent_pid,
        "resource": req.resource,
        "limit": req.limit,
        "remaining": req.limit,
        "durable": true,
    }))
}

/// GET /aapi/budgets/:agent_pid/:resource
pub async fn get_budget(
    State(state): State<SharedState>,
    Path((agent_pid, resource)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let remaining = aapi.check_budget(&agent_pid, &resource);
    let exhausted = remaining <= 0.0 && remaining != f64::MAX;
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "resource": resource,
        "remaining": if remaining == f64::MAX { serde_json::Value::String("unlimited".into()) } else { serde_json::json!(remaining) },
        "exhausted": exhausted,
        "has_budget": remaining != f64::MAX,
    }))
}

#[derive(Deserialize)]
pub struct ConsumeBudgetRequest {
    pub agent_pid: String,
    pub resource: String,
    pub amount: f64,
}

/// POST /aapi/budgets/consume
pub async fn consume_budget(
    State(state): State<SharedState>,
    Json(req): Json<ConsumeBudgetRequest>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let ok = aapi.consume_budget(&req.agent_pid, &req.resource, req.amount);
    let remaining = aapi.check_budget(&req.agent_pid, &req.resource);
    let tracker = aapi
        .list_budgets()
        .into_iter()
        .find(|b| b.agent_pid == req.agent_pid && b.resource == req.resource)
        .cloned();
    drop(aapi);
    if let Some(t) = tracker {
        crate::substrate::aapi_effect_field::persist_budget(state.as_ref(), &t);
    }
    Json(serde_json::json!({
        "ok": ok,
        "agent_pid": req.agent_pid,
        "resource": req.resource,
        "consumed": req.amount,
        "remaining": remaining,
        "denied_reason": if !ok { Some("budget_exhausted") } else { None::<&str> },
    }))
}

// ── BCR reserve-execute-commit (A12 / S17) ─────────────────────────────────────

#[derive(Deserialize)]
pub struct BcrReserveRequest {
    pub agent_pid: String,
    pub resource: String,
    pub amount: f64,
    pub idempotency_key: String,
    #[serde(default)]
    pub action_digest: Option<String>,
}

/// POST /aapi/budgets/reserve
pub async fn bcr_reserve(
    State(state): State<SharedState>,
    Json(req): Json<BcrReserveRequest>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::aapi_effect_field::bcr_reserve(
        &state,
        &req.agent_pid,
        &req.resource,
        req.amount,
        &req.idempotency_key,
        req.action_digest.as_deref(),
    ))
}

#[derive(Deserialize)]
pub struct BcrReservationIdRequest {
    pub reservation_id: String,
}

/// POST /aapi/budgets/commit
pub async fn bcr_commit(
    State(state): State<SharedState>,
    Json(req): Json<BcrReservationIdRequest>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::aapi_effect_field::bcr_commit(
        &state,
        &req.reservation_id,
    ))
}

/// POST /aapi/budgets/release
pub async fn bcr_release(
    State(state): State<SharedState>,
    Json(req): Json<BcrReservationIdRequest>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::aapi_effect_field::bcr_release(
        &state,
        &req.reservation_id,
    ))
}

#[derive(Deserialize)]
pub struct RegisterInverseRequest {
    pub agent_pid: String,
    pub action_digest: String,
    pub inverse_intent: String,
}

/// POST /aapi/inverse/register
pub async fn register_inverse(
    State(state): State<SharedState>,
    Json(req): Json<RegisterInverseRequest>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::aapi_effect_field::register_inverse(
        state.as_ref(),
        &req.agent_pid,
        &req.action_digest,
        &req.inverse_intent,
    ))
}

#[derive(Deserialize)]
pub struct CompensateRequest {
    pub agent_pid: String,
    pub original_invocation_id: String,
}

/// POST /aapi/compensate
pub async fn compensate(
    State(state): State<SharedState>,
    Json(req): Json<CompensateRequest>,
) -> Json<serde_json::Value> {
    Json(crate::substrate::aapi_effect_field::compensate(
        &state,
        &req.agent_pid,
        &req.original_invocation_id,
    ))
}

/// GET /aapi/ledger/:agent_pid — durable action ledger (S16).
pub async fn get_durable_ledger(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let actions = crate::substrate::aapi_effect_field::list_durable_actions(
        state.as_ref(),
        &agent_pid,
        100,
    );
    Json(serde_json::json!({
        "ok": true,
        "agent_pid": agent_pid,
        "count": actions.len(),
        "actions": actions,
        "effect_field": crate::substrate::aapi_effect_field::posture_json(),
    }))
}

// ── Dynamic Policy CRUD ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddPolicyRequest {
    pub id: String,
    pub name: String,
    pub rules: Vec<PolicyRuleInput>,
}

#[derive(Deserialize)]
pub struct PolicyRuleInput {
    pub effect: String,
    pub action_pattern: String,
    #[serde(default)]
    pub resource_pattern: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub priority: i32,
}

/// POST /aapi/policies
pub async fn add_policy(
    State(state): State<SharedState>,
    Json(req): Json<AddPolicyRequest>,
) -> Json<serde_json::Value> {
    let rules: Vec<PolicyRule> = req
        .rules
        .iter()
        .map(|r| PolicyRule {
            effect: effect_from_str(&r.effect),
            action_pattern: r.action_pattern.clone(),
            resource_pattern: r.resource_pattern.clone(),
            roles: r.roles.clone(),
            priority: r.priority,
        })
        .collect();
    let mut aapi = state.aapi.lock().unwrap();
    aapi.add_policy(&req.id, &req.name, rules);
    Json(serde_json::json!({
        "ok": true,
        "id": req.id,
        "name": req.name,
        "rule_count": req.rules.len(),
        "total_policies": aapi.policy_count(),
    }))
}

/// DELETE /aapi/policies/:id
pub async fn remove_policy(
    State(state): State<SharedState>,
    Path(policy_id): Path<String>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let before = aapi.policy_count();
    aapi.remove_policy(&policy_id);
    let after = aapi.policy_count();
    Json(serde_json::json!({
        "ok": true,
        "id": policy_id,
        "removed": before > after,
        "remaining_policies": after,
    }))
}

/// POST /aapi/policies/evaluate
pub async fn evaluate_policy(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let resource = req.get("resource").and_then(|v| v.as_str()).unwrap_or("");
    let role = req.get("role").and_then(|v| v.as_str());
    let aapi = state.aapi.lock().unwrap();
    let decision = aapi.evaluate_policy(action, resource, role);
    Json(serde_json::json!({
        "allowed": decision.allowed,
        "effect": decision.effect,
        "reason": decision.reason,
        "matched_rule": decision.matched_rule,
        "requires_approval": decision.requires_approval,
    }))
}

// ── Regulatory Templates ──────────────────────────────────────────────────────

/// POST /aapi/policies/hipaa  (S10: idempotent — safe to call multiple times)
pub async fn apply_hipaa_policy(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let before = aapi.policy_count();
    aapi.add_hipaa_policy();
    let after = aapi.policy_count();
    let already_applied = after == before;
    Json(serde_json::json!({
        "ok": true,
        "policy_id": "hipaa",
        "name": "HIPAA Guard",
        "already_applied": already_applied,
        "rules_applied": [
            "Deny *.delete on ehr:* resources",
            "RequireApproval ehr.update_* operations",
            "Allow ehr.read_* for doctor/nurse roles",
        ],
        "total_policies": after,
    }))
}

/// POST /aapi/policies/financial  (S10: idempotent — safe to call multiple times)
pub async fn apply_financial_policy(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let before = aapi.policy_count();
    aapi.add_financial_policy();
    let after = aapi.policy_count();
    let already_applied = after == before;
    Json(serde_json::json!({
        "ok": true,
        "policy_id": "financial",
        "name": "Financial Guard",
        "already_applied": already_applied,
        "rules_applied": [
            "RequireApproval trade.* operations",
            "Deny *.delete on ledger:* resources",
            "Allow report.read_* operations",
        ],
        "total_policies": after,
    }))
}

// ── Tool Authorization ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthorizeToolRequest {
    pub agent_pid: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub role: Option<String>,
}

/// POST /aapi/tools/authorize
pub async fn authorize_tool(
    State(state): State<SharedState>,
    Json(req): Json<AuthorizeToolRequest>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let decision = aapi.authorize_tool(
        &req.agent_pid,
        &req.action,
        &req.resource,
        req.role.as_deref(),
    );
    Json(serde_json::json!({
        "allowed": decision.allowed,
        "effect": decision.effect,
        "reason": decision.reason,
        "matched_rule": decision.matched_rule,
        "requires_approval": decision.requires_approval,
        "agent_pid": req.agent_pid,
        "action": req.action,
        "resource": req.resource,
    }))
}

/// POST /aapi/tools/register
pub async fn register_tool_aapi(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let description = req
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if name.is_empty() {
        return Json(serde_json::json!({ "ok": false, "error": "name required" }));
    }
    let mut aapi = state.aapi.lock().unwrap();
    aapi.register_tool(name, description);
    Json(serde_json::json!({
        "ok": true,
        "name": name,
        "capability_issued": format!("tool.{}", name),
        "resource": format!("tool://{}", name),
        "audit_logged": true,
    }))
}

// ── Interaction Log ───────────────────────────────────────────────────────────

/// GET /aapi/interactions
pub async fn list_interactions(
    State(state): State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<InteractionQuery>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let interactions: Vec<serde_json::Value> = aapi
        .list_interactions(q.agent_pid.as_deref())
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id,
                "agent_pid": i.agent_pid,
                "type": i.itype,
                "target": i.target,
                "operation": i.operation,
                "status": i.status,
                "duration_ms": i.duration_ms,
                "tokens": i.tokens,
                "cost_usd": i.cost_usd,
                "timestamp": i.timestamp,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": interactions.len(),
        "agent_pid_filter": q.agent_pid,
        "interactions": interactions,
    }))
}

#[derive(Deserialize)]
pub struct InteractionQuery {
    pub agent_pid: Option<String>,
}

#[derive(Deserialize)]
pub struct LogInteractionRequest {
    pub agent_pid: String,
    pub itype: String,
    pub target: String,
    pub operation: String,
    pub status: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub tokens: Option<u64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
}

/// POST /aapi/interactions
pub async fn log_interaction(
    State(state): State<SharedState>,
    Json(req): Json<LogInteractionRequest>,
) -> Json<serde_json::Value> {
    let mut aapi = state.aapi.lock().unwrap();
    let entry = aapi.log_interaction(
        &req.agent_pid,
        &req.itype,
        &req.target,
        &req.operation,
        &req.status,
        req.duration_ms,
        req.tokens,
        req.cost_usd,
    );
    Json(serde_json::json!({
        "ok": true,
        "id": entry.id,
        "timestamp": entry.timestamp,
    }))
}

// ── Compliance Config ─────────────────────────────────────────────────────────

/// POST /aapi/compliance
pub async fn set_compliance(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let regulations: Vec<String> = req
        .get("regulations")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let data_classification = req
        .get("data_classification")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let retention_days = req
        .get("retention_days")
        .and_then(|v| v.as_u64())
        .unwrap_or(90);
    let requires_human_review = req
        .get("requires_human_review")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut aapi = state.aapi.lock().unwrap();
    aapi.set_compliance(ComplianceConfig {
        regulations: regulations.clone(),
        data_classification: data_classification.clone(),
        retention_days,
        requires_human_review,
    });
    Json(serde_json::json!({
        "ok": true,
        "regulations": regulations,
        "data_classification": data_classification,
        "retention_days": retention_days,
        "requires_human_review": requires_human_review,
    }))
}
