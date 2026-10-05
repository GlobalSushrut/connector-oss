//! Connector stance: the LLM is probabilistic. It is not trusted to augment
//! itself. Connector remains the source of identity, memory, character,
//! knowledge, HITL, and parameters.
//!
//! - Bypass of a Connector rule → **quarantine** + human retrieval (unquarantine HITL).
//! - Failure of identity / memory / character / knowledge / HITL / parameters →
//!   **human approval is mandatory**; the model cannot continue autonomously.

use serde_json::{json, Value};

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;

pub const SCHEMA: &str = "connector.probabilistic_llm.v1";

/// The 13 Connector parameters the LLM must follow. Miss any → HTTP 499.
///
/// 1–7 = Agent Packet DNA genome · 8–13 = agentic / talk pillars.
pub const THE_13: [&str; 13] = [
    "principal_id",
    "agent_pid",
    "character_hash",
    "contract_hash",
    "quantum_id",
    "flow_lease_id",
    "effect_digest",
    "who_am_i",
    "principal",
    "character",
    "last_memory",
    "knowledge_contract",
    "rules_hitl",
];

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

/// Master switch — production default via connector_profile.
/// Lab may leave this unset so denials stay denials without auto-quarantine.
pub fn distrust_enforced() -> bool {
    env_flag("CONNECTOR_LLM_DISTRUST")
}

#[derive(Debug, Clone, Copy)]
pub enum DenialClass {
    /// Tried to go around Connector (raw tool, forged ticket, ungoverned path).
    Bypass,
    /// Failed a Connector-owned rule the model must follow.
    Rule,
}

/// Bypass classes that always quarantine when distrust is on.
pub fn is_bypass_reason(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("bypass")
        || r.contains("forged")
        || r.contains("handshake_required")
        || r.contains("handshake_revoked")
        || r.contains("in_process_effect")
        || r.contains("raw_network")
        || r.contains("direct_mcp")
        || r.contains("ticket_replay")
        || r.contains("effect_exclusivity")
        || r.contains("sdk_bypass")
}

/// Quarantine the intelligence. Human must retrieve it via unquarantine HITL.
///
/// Response shape for LLM/clients: **HTTP 499** —
/// `sorry, you are not allowed — need human approval`.
pub fn quarantine_for_bypass(
    state: &SharedState,
    agent_pid: &str,
    kind: &str,
    detail: &str,
) -> Value {
    let reason = format!("llm_bypass:{kind}: {detail}");
    crate::services::admission::operator_quarantine_agent(
        state,
        agent_pid,
        &reason,
        "probabilistic_llm_guard",
    );
    tracing::error!(
        agent_pid = %agent_pid,
        kind = %kind,
        "LLM bypass attempt — quarantined until human retrieval (HTTP 499 to model)"
    );
    json!({
        "ok": false,
        "status": 499,
        "message": "sorry, you are not allowed — need human approval",
        "error": "llm_quarantined_bypass",
        "denial_reason": "llm_bypass_quarantine",
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "bypass_kind": kind,
        "human_approval": true,
        "detail": detail,
        "retrieval": format!("POST /api/v1/agents/{agent_pid}/unquarantine after reviewing HITL"),
        "philosophy": "The LLM is probabilistic. Connector does not believe it is ready for unaugmented autonomy.",
    })
}

/// Quarantine + return ConnectorError that maps to HTTP 499 for talk/gateway paths.
pub fn quarantine_499(
    state: &SharedState,
    agent_pid: &str,
    kind: &str,
    detail: &str,
) -> ConnectorError {
    let _ = quarantine_for_bypass(state, agent_pid, kind, detail);
    ConnectorError::llm_quarantined_need_approval(agent_pid, kind, detail)
}

/// Rule failure: model may not proceed. HTTP **499** — you are not allowed.
pub fn require_human_for_rule(
    state: &SharedState,
    agent_pid: &str,
    domain: &str,
    detail: &str,
) -> ConnectorError {
    let digest_src = format!("rule_fail|{agent_pid}|{domain}|{detail}");
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(digest_src.as_bytes()))
    };
    let request_id = crate::services::agents::hitl_submit_bound(
        agent_pid,
        &format!("rule.{domain}"),
        &format!(
            "Connector rule '{domain}' failed: {detail}. LLM is probabilistic — human approval is required to continue."
        ),
        &digest,
        Some(json!({
            "schema": SCHEMA,
            "domain": domain,
            "detail": detail,
            "stance": "llm_not_trusted_for_augmentation",
            "http_status": 499,
            "message": "you are not allowed",
            "the_13": THE_13,
        })),
        Some(SCHEMA.into()),
        None,
        Some(state),
    );
    ConnectorError::llm_not_allowed(domain, detail)
        .with_hint(format!(
            "sorry, you are not allowed — need human approval — hitl_required request_id={request_id} POST /api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
        ))
}

/// Classify an error slug and apply quarantine (bypass) or HITL (rule).
pub fn apply_denial(
    state: &SharedState,
    agent_pid: &str,
    class: DenialClass,
    kind: &str,
    detail: &str,
) -> Value {
    if !distrust_enforced() {
        return json!({
            "ok": false,
            "error": kind,
            "message": detail,
            "schema": SCHEMA,
            "distrust": false,
        });
    }
    match class {
        DenialClass::Bypass => quarantine_for_bypass(state, agent_pid, kind, detail),
        DenialClass::Rule => {
            let err = require_human_for_rule(state, agent_pid, kind, detail);
            json!({
                "ok": false,
                "status": 499,
                "message": "sorry, you are not allowed — need human approval",
                "error": "llm_not_allowed",
                "denial_reason": err.denial_reason.slug(),
                "human_readable": err.human_readable,
                "hint": err.hint,
                "human_approval": true,
                "schema": SCHEMA,
                "domain": kind,
                "the_13": THE_13,
            })
        }
    }
}

/// Pillars the LLM must follow. Any miss → HITL, not autonomous continue.
pub fn augmentation_pillars(state: &SharedState, agent_pid: &str) -> Vec<String> {
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(state, agent_pid);
    }
    let mut missing = Vec::new();
    let snap = crate::substrate::identity_stack::inspect(
        state,
        agent_pid,
        &format!("gateway/{agent_pid}"),
        &crate::services::admission::AdmissionOp::LlmChat,
    );
    missing.extend(snap.missing);

    let contract = crate::kernel::agent_principal::load_contract(state.as_ref(), agent_pid);
    if contract.is_none() {
        missing.push("identity_contract_parameters".into());
    }
    if crate::kernel::agent_principal::load_principal(state.as_ref(), agent_pid).is_none() {
        missing.push("connector_identity_principal".into());
    }
    if let Some(c) = contract {
        if c.purpose.is_empty() {
            missing.push("character_purpose".into());
        }
        if c.capabilities.is_empty() {
            missing.push("knowledge_capabilities".into());
        }
    }
    // Playground Talk: after lane mint, drop identity-stack pillars that are still
    // warming (first packet race). Principal/contract gaps still surface.
    if crate::services::playground::is_playground_mode() {
        missing.retain(|m| {
            !matches!(
                m.as_str(),
                "last_memory"
                    | "address_relation_identity_graph"
                    | "address_rules_contract"
                    | "address_hitl_contract"
                    | "identity_character"
            )
        });
    }
    missing.sort();
    missing.dedup();
    missing
}

pub fn status() -> Value {
    json!({
        "schema": SCHEMA,
        "distrust_enforced": distrust_enforced(),
        "stance": "LLM is probabilistic. Connector does not believe it is ready for unaugmented autonomy.",
        "bypass": "quarantine + human retrieval (unquarantine HITL)",
        "rule_failure": "HTTP 499 — sorry, you are not allowed — need human approval",
        "http_status_on_rule_fail": 499,
        "message_on_rule_fail": "sorry, you are not allowed — need human approval",
        "on_quarantine": "HTTP 499 + human_approval — same surface as rule fail",
        "the_13": THE_13,
        "pillars": [
            "connector_identity",
            "memory",
            "character",
            "knowledge",
            "hitl",
            "parameters",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_reasons_detected() {
        assert!(is_bypass_reason("forged_ticket"));
        assert!(is_bypass_reason("handshake_required"));
        assert!(is_bypass_reason("in_process_effect_path"));
        assert!(!is_bypass_reason("budget_exceeded"));
    }
}
