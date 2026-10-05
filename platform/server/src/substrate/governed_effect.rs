//! Unified governed effect admission — GovernedRequestV2 + IA augmentations.
//!
//! All mutating agent effects (LLM, tools, memory, MCP, pipelines) should route
//! through this module. It layers character drift, entropy radius, and contract
//! stack checks before legacy `admission::check`, then mints `CapabilityGrantV2`.

use axum::http::HeaderMap;
use connector_trust::{
    AdmissionTicketV2, CapabilityGrantV2, ContinuityStateV2, GovernedRequestV2,
    PrincipalContextV2,
};
use connector_trust::principal::AuthSourceV2;
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::kernel::docklock;
use crate::services::admission::{self, AdmissionOp, AdmissionRequest, AdmissionTicket};
use crate::state::SharedState;

pub const EFFECT_GRANTS_FOLDER: &str = "effect_grants";
pub const SCHEMA: &str = "governed_effect.v1";

#[derive(Debug, Clone)]
pub struct GovernedEffectResult {
    pub ticket: AdmissionTicket,
    pub ticket_v2: AdmissionTicketV2,
    pub grant: CapabilityGrantV2,
}

fn resolve_quantum(headers: Option<&HeaderMap>, explicit: Option<&str>) -> Option<String> {
    if let Some(q) = explicit.filter(|s| !s.is_empty()) {
        return Some(q.to_string());
    }
    headers
        .and_then(|h| docklock::extract_quantum_id(h))
        .or_else(|| crate::kernel::ring1_context::resolve_quantum_id(None))
}

fn synthetic_workload_principal(agent_pid: &str) -> PrincipalContextV2 {
    PrincipalContextV2 {
        subject: format!("agent:{agent_pid}"),
        email: String::new(),
        role: "workload".into(),
        permissions: Vec::new(),
        tenant_id: None,
        jti: None,
        token_type: "workload".into(),
        instance_id: None,
        auth_source: AuthSourceV2::Synthetic,
        contract_version: 2,
    }
}

fn content_digest(content: Option<&str>) -> Option<String> {
    content.map(|c| hex::encode(Sha256::digest(c.as_bytes())))
}

/// Build a normalized v2 governed request from an admission op.
pub fn build_governed_request(
    agent_pid: &str,
    namespace: &str,
    operation: &AdmissionOp,
    content: Option<&str>,
    principal: Option<PrincipalContextV2>,
) -> GovernedRequestV2 {
    let principal = principal.unwrap_or_else(|| synthetic_workload_principal(agent_pid));
    GovernedRequestV2 {
        principal,
        tenant_id: None,
        workload_id: Some(agent_pid.to_string()),
        session_id: None,
        agent_pid: Some(agent_pid.to_string()),
        action: operation.slug().to_string(),
        resource: operation.resource(),
        namespace: Some(namespace.to_string()),
        policy_revision: None,
        content_digest: content_digest(content),
        contract_version: 2,
    }
}

fn contract_stack_for_op(op: &AdmissionOp) -> (&'static str, String) {
    match op {
        AdmissionOp::LlmChat => ("llm.chat", "llm.chat".into()),
        AdmissionOp::MemoryWrite => ("memory.write", "memory.write".into()),
        AdmissionOp::MemoryRead { namespace } => {
            ("memory.read", format!("memory.read:{namespace}"))
        }
        AdmissionOp::ToolDispatch { tool_id } => ("tool.dispatch", tool_id.clone()),
        AdmissionOp::PipelineStep { pipeline_id, step } => {
            ("pipeline.step", format!("pipeline:{pipeline_id}:step:{step}"))
        }
        AdmissionOp::McpCall { tool_name } => ("mcp.call", tool_name.clone()),
        AdmissionOp::ConpCommand { capability_id, .. } => {
            ("conp.command", capability_id.clone())
        }
    }
}

/// Character drift gate — deny when continuity record is Broken under hardening.
fn enforce_character_drift(state: &SharedState, api_pid: &str) -> Result<(), ConnectorError> {
    if !crate::kernel::agent_principal::intelligence_hardening_on() {
        return Ok(());
    }
    if let Some(record) = crate::kernel::agent_principal::load_continuity(state.as_ref(), api_pid) {
        if record.state == ContinuityStateV2::Broken {
            let reason = record
                .break_reason
                .unwrap_or_else(|| "continuity_broken".into());
            return Err(
                ConnectorError::new(
                    DenialReason::PolicyDenied,
                    format!("character drift detected: {reason}"),
                )
                .with_denied_resource("agent.continuity")
                .with_hint("Re-attest agent identity or unquarantine after HITL review"),
            );
        }
    }
    Ok(())
}

/// Entropy radius — deny when agent entropy exceeds configured bound under hardening.
fn enforce_entropy_radius(state: &SharedState, api_pid: &str) -> Result<(), ConnectorError> {
    if !crate::kernel::agent_principal::intelligence_hardening_on() {
        return Ok(());
    }
    let max = std::env::var("CONNECTOR_ENTROPY_RADIUS_MAX")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(1.0);
    // Prefer live Knot/entropic SoT; folder meta is fallback only.
    let live = crate::substrate::kecs_sot::resolve_kecs(state.as_ref(), api_pid);
    if live > max {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("entropy_radius live kecs={live:.3} > max={max}"),
        )
        .with_denied_resource("agent.entropy")
        .with_hint("Lower KECS disorder or raise CONNECTOR_ENTROPY_RADIUS_MAX"));
    }
    let meta_score = {
        let es = state.engine_store.lock().map_err(|_| {
            ConnectorError::new(DenialReason::InternalError, "engine_store lock")
        })?;
        es.folder_get("agent_meta", api_pid)
            .ok()
            .flatten()
            .and_then(|meta| {
                meta.get("entropy_radius")
                    .or_else(|| meta.get("kecs_score"))
                    .and_then(|v| v.as_f64())
            })
    };
    if let Some(score) = meta_score {
        if score > max {
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                format!("entropy radius exceeded: {score:.4} > bound {max:.4}"),
            )
            .with_denied_resource("agent.entropy")
            .with_hint("Reduce reasoning diversity or raise CONNECTOR_ENTROPY_RADIUS_MAX after review"));
        }
    }
    Ok(())
}

/// Contract stack — charter capabilities must cover the requested effect.
fn enforce_contract_stack(
    state: &SharedState,
    api_pid: &str,
    op: &AdmissionOp,
) -> Result<(), ConnectorError> {
    let (action, target) = contract_stack_for_op(op);
    crate::kernel::agent_principal::require_contract_action(state.as_ref(), api_pid, action, &target)
        .map_err(|e| {
            ConnectorError::new(DenialReason::PolicyDenied, e)
                .with_denied_resource(op.resource())
        })
}

fn mint_effect_grant(
    state: &SharedState,
    req: &GovernedRequestV2,
    op: &AdmissionOp,
) -> CapabilityGrantV2 {
    let grant_id = format!("egr_{}", uuid::Uuid::new_v4().simple());
    let now = chrono::Utc::now().timestamp();
    let grant = CapabilityGrantV2 {
        grant_id: grant_id.clone(),
        principal_id: req.principal.subject.clone(),
        tenant_id: req.tenant_id.clone(),
        workload_id: req.workload_id.clone(),
        action: op.slug().to_string(),
        resource: op.resource(),
        audience: Some("connector-platform".into()),
        expires_at: now + 300,
        policy_revision: req.policy_revision,
        revoked: false,
        contract_version: 2,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            EFFECT_GRANTS_FOLDER,
            &grant_id,
            &serde_json::to_value(&grant).unwrap_or_default(),
        );
    }
    grant
}

/// Full governed effect pipeline: IA augmentations → admission → capability grant.
pub fn evaluate_governed_effect(
    state: &SharedState,
    req: &GovernedRequestV2,
    admission: &AdmissionRequest<'_>,
) -> Result<GovernedEffectResult, ConnectorError> {
    let api_pid = req.agent_pid.as_deref().unwrap_or(admission.agent_pid);
    // Unbypassable LLM lane — cannot skip broker to avoid 409/499.
    match &admission.operation {
        crate::services::admission::AdmissionOp::LlmChat
        | crate::services::admission::AdmissionOp::ToolDispatch { .. }
        | crate::services::admission::AdmissionOp::McpCall { .. } => {
            crate::substrate::llm_broker_gate::assert_llm_lane(state, api_pid)?;
        }
        _ => {}
    }
    if crate::substrate::atomic_revoke::is_agent_authority_revoked(state, api_pid) {
        return Err(ConnectorError::policy_denied("effect", "authority_revoked")
            .with_hint("Agent authority revoked — re-admit after clearance"));
    }
    if let Err(v) =
        crate::substrate::sandbox_unbypassable::assert_sandbox_unbypassable(state, api_pid)
    {
        let msg = v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("sandbox_unbypassable");
        let code = v
            .get("denial_reason")
            .and_then(|x| x.as_str())
            .unwrap_or("sandbox_unbypassable");
        return Err(ConnectorError::policy_denied("effect", code).with_hint(msg));
    }
    // P2-T03/T04: bind cgroup/ns identity + principal attribution (best-effort record).
    let _ = crate::kernel::agent_cgroup::bind_agent_process_tree(state, api_pid, api_pid);
    if crate::substrate::probabilistic_llm::distrust_enforced() {
        if let Err(e) = enforce_character_drift(state, api_pid) {
            return Err(crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                api_pid,
                "character",
                &e.human_readable,
            ));
        }
        if let Err(e) = enforce_entropy_radius(state, api_pid) {
            return Err(crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                api_pid,
                "parameters",
                &e.human_readable,
            ));
        }
        if let Err(e) = enforce_contract_stack(state, api_pid, &admission.operation) {
            return Err(crate::substrate::probabilistic_llm::require_human_for_rule(
                state,
                api_pid,
                "knowledge",
                &e.human_readable,
            ));
        }
    } else {
        enforce_character_drift(state, api_pid)?;
        enforce_entropy_radius(state, api_pid)?;
        enforce_contract_stack(state, api_pid, &admission.operation)?;
    }
    crate::substrate::identity_stack::enforce(
        state,
        api_pid,
        admission.namespace,
        &admission.operation,
    )?;
    if crate::substrate::probabilistic_llm::distrust_enforced() {
        let missing = crate::substrate::probabilistic_llm::augmentation_pillars(state, api_pid);
        if !missing.is_empty() {
            return Err(
                crate::substrate::probabilistic_llm::require_human_for_rule(
                    state,
                    api_pid,
                    "identity_memory_character_knowledge_hitl_parameters",
                    &format!("missing Connector pillars: {}", missing.join(", ")),
                ),
            );
        }
    }
    {
        let addr = crate::substrate::identity_stack::action_address(
            &admission.operation,
            admission.namespace,
        );
        let caged = crate::kernel::address_cage::classify_address(&addr, api_pid);
        let tool = crate::kernel::address_contracts::tool_from_op(&admission.operation);
        crate::kernel::address_contracts::enforce_for_effect(
            state,
            api_pid,
            &caged.address,
            &tool,
        )?;
    }

    let ticket = admission::check(state, admission)?;
    let ticket_v2 = ticket.to_v2();
    let grant = mint_effect_grant(state, req, &admission.operation);

    // Under broker mode, non-talk effects need a live opaque LLM context token
    // (minted on prior talk, stored as active:{pid}). Without it the shared model
    // has no agent binding and cannot act.
    if crate::substrate::llm_context_broker::broker_enforced()
        && !matches!(admission.operation, AdmissionOp::LlmChat)
    {
        let active_tok = crate::substrate::llm_context_broker::active_token_id(state, api_pid);
        crate::substrate::llm_context_broker::assert_live_for_agent(
            state,
            api_pid,
            active_tok.as_deref(),
        )?;
    }

    Ok(GovernedEffectResult {
        ticket,
        ticket_v2,
        grant,
    })
}

/// Convenience entry for handlers — builds GovernedRequestV2 + AdmissionRequest.
pub fn evaluate_effect(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    operation: AdmissionOp,
    content: Option<&str>,
) -> Result<GovernedEffectResult, ConnectorError> {
    evaluate_effect_with_principal(
        state,
        headers,
        agent_pid,
        namespace,
        operation,
        content,
        None,
        None,
    )
}

pub fn evaluate_effect_with_principal(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    operation: AdmissionOp,
    content: Option<&str>,
    principal: Option<PrincipalContextV2>,
    explicit_quantum: Option<&str>,
) -> Result<GovernedEffectResult, ConnectorError> {
    let quantum = resolve_quantum(headers, explicit_quantum);
    let governed = build_governed_request(agent_pid, namespace, &operation, content, principal);
    let admission = AdmissionRequest {
        agent_pid,
        namespace,
        operation,
        content,
        execution_quantum_id: quantum.as_deref(),
    };
    evaluate_governed_effect(state, &governed, &admission)
}

/// Map governed denial to JSON (admission_gate compatibility).
pub fn denial_json(err: &ConnectorError) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": if err.hint.as_deref().unwrap_or("").contains("hitl_required") {
            "hitl_required"
        } else {
            "admission_denied"
        },
        "message": err.human_readable,
        "denial_reason": err.denial_reason.slug(),
        "hint": err.hint,
        "example_fix": err.example_fix,
        "denied_resource": err.denied_resource,
        "docklock_ring1": docklock::ring1_enforce_enabled(),
        "governed_effect": SCHEMA,
        "identity_stack": SCHEMA,
    })
}

pub fn posture_json() -> serde_json::Value {
    serde_json::json!({
        "schema": SCHEMA,
        "honesty": "All mutating effects route through governed_effect (identity stack + address DAC + character drift + entropy radius + contract stack + admission + CapabilityGrantV2).",
        "identity_stack": crate::substrate::identity_stack::posture_json(),
        "address_dac": crate::kernel::address_contracts::posture_json(),
        "character_drift": "ContinuityStateV2::Broken denies under intelligence hardening",
        "entropy_radius": "agent_meta entropy_radius/kecs_score vs CONNECTOR_ENTROPY_RADIUS_MAX",
        "contract_stack": "require_contract_action before admission::check",
        "grant_folder": EFFECT_GRANTS_FOLDER,
        "grant_ttl_secs": 300,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_mapping_covers_ops() {
        let (a, t) = contract_stack_for_op(&AdmissionOp::LlmChat);
        assert_eq!(a, "llm.chat");
        assert_eq!(t, "llm.chat");
        let (a, _) = contract_stack_for_op(&AdmissionOp::ToolDispatch {
            tool_id: "b:t".into(),
        });
        assert_eq!(a, "tool.dispatch");
    }

    #[test]
    fn build_request_sets_action_resource() {
        let req = build_governed_request(
            "agent_1",
            "m/test",
            &AdmissionOp::MemoryWrite,
            Some("hello"),
            None,
        );
        assert_eq!(req.action, "memory.write");
        assert_eq!(req.resource, "memory.write");
        assert!(req.content_digest.is_some());
    }
}
