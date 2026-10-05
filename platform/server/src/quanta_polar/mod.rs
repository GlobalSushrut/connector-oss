//! QPR — Quanta/Polar Ring: CPO → ExecutionQuantum (Gate 2).

use connector_trust::{
    sign_json_ed25519, verify_signed_payload_v2, CognitiveProposalV2, ContinuityStateV2,
    ExecutionQuantumV2, IIA_SCHEMA,
};
use sha2::{Digest, Sha256};

use crate::kernel::agent_principal;
use crate::state::PlatformState;

pub const IIA_QUANTUM_FOLDER: &str = "execution_quantum_v2";

pub const QUANTUM_TTL_SECS: i64 = 90;

#[derive(Debug, serde::Deserialize)]
pub struct QprIntentRequest {
    pub agent_pid: String,
    pub cpo_id: String,
}

pub fn qpr_enforce_enabled() -> bool {
    // Leaf QPR flag OR full Ring-1 (ring1 itself uses leaf flags only — no recursion).
    matches!(
        std::env::var("CONNECTOR_IIA_QPR_ENFORCE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) || crate::kernel::docklock::ring1_enforce_enabled()
}

pub fn polarize_cpo(
    state: &PlatformState,
    req: &QprIntentRequest,
) -> Result<ExecutionQuantumV2, serde_json::Value> {
    let contract = agent_principal::load_contract(state, &req.agent_pid).ok_or_else(|| {
        serde_json::json!({"error": "contract_not_found"})
    })?;
    let continuity = agent_principal::load_continuity(state, &req.agent_pid).ok_or_else(|| {
        serde_json::json!({"error": "continuity_not_found"})
    })?;
    if continuity.state == ContinuityStateV2::Broken {
        return Err(serde_json::json!({
            "error": "qpr_denied",
            "denial_reason": "continuity_broken",
        }));
    }

    let cpo: CognitiveProposalV2 = {
        let es = state.engine_store.lock().unwrap();
        let v = es
            .folder_get(crate::intelligence_admission::IIA_CPO_FOLDER, &req.cpo_id)
            .ok()
            .flatten()
            .ok_or_else(|| serde_json::json!({"error": "cpo_not_found"}))?;
        serde_json::from_value(v).map_err(|_| serde_json::json!({"error": "cpo_corrupt"}))?
    };

    if !contract_allows_action(&contract, &cpo.proposed_action, &cpo.proposed_target) {
        return Err(serde_json::json!({
            "error": "qpr_denied",
            "denial_reason": "out_of_contract",
            "proposed_action": cpo.proposed_action,
            "proposed_target": cpo.proposed_target,
        }));
    }

    if cpo
        .context_slices
        .iter()
        .any(|s| matches!(s.class, connector_trust::ContextClassV2::Untrusted))
        && cpo.proposed_target.contains("finance")
    {
        return Err(serde_json::json!({
            "error": "qpr_denied",
            "denial_reason": "untrusted_context_privileged_target",
        }));
    }

    let now = chrono::Utc::now().timestamp_millis();
    let nonce = hex::encode(Sha256::digest(
        format!("{}|{}|{}", req.cpo_id, now, uuid::Uuid::new_v4()).as_bytes(),
    ));
    let quantum_id = format!("q_{}", &nonce[..16]);

    let mut quantum = ExecutionQuantumV2 {
        schema: IIA_SCHEMA.into(),
        quantum_id: quantum_id.clone(),
        cpo_id: cpo.cpo_id.clone(),
        principal_id: cpo.principal_id.clone(),
        contract_digest_sha256: contract.contract_digest_sha256.clone(),
        action: cpo.proposed_action.clone(),
        target: cpo.proposed_target.clone(),
        nonce,
        issued_at_ms: now,
        expires_at_ms: now + QUANTUM_TTL_SECS * 1000,
        single_use: true,
        consumed: false,
        signature: None,
    };

    // B27: node-sign quantum (never ephemeral court theater).
    if let Ok(sig) = sign_json_ed25519(state.signing_key.ed25519(), &quantum) {
        quantum.signature = Some(sig);
    } else if qpr_enforce_enabled() {
        return Err(serde_json::json!({
            "error": "qpr_denied",
            "denial_reason": "quantum_unsigned",
            "message": "Node could not sign execution quantum",
        }));
    }

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(IIA_QUANTUM_FOLDER, &quantum_id, &serde_json::to_value(&quantum).unwrap());

    Ok(quantum)
}

/// Capability must cover the proposed action — `"read"` alone does **not** allow all ops.
pub fn contract_allows_action(
    contract: &connector_trust::AgentContractV2,
    action: &str,
    target: &str,
) -> bool {
    let action_l = action.to_ascii_lowercase();
    let target_l = target.to_ascii_lowercase();
    if contract
        .denied_operations
        .iter()
        .any(|d| {
            let d = d.to_ascii_lowercase();
            action_l.contains(&d) || target_l.contains(&d)
        })
    {
        return false;
    }
    if contract.capabilities.is_empty() {
        // Empty allowlist = deny (fail-closed). Operators must grant capabilities.
        return false;
    }
    contract
        .capabilities
        .iter()
        .any(|c| capability_covers(c, &action_l, &target_l))
}

fn capability_covers(cap: &str, action: &str, target: &str) -> bool {
    let c = cap.to_ascii_lowercase();
    if c == "*" || c == "any" {
        return true;
    }
    if action.contains(&c) || target.contains(&c) {
        return true;
    }
    match c.as_str() {
        "read" => {
            action.contains("read")
                || action.contains("recall")
                || action.contains("get")
                || action.contains("list")
                || action.contains("query")
                || action == "llm.chat"
                || action.contains("chat")
                || action.contains("cognize")
        }
        "write" => {
            action.contains("write")
                || action.contains("put")
                || action.contains("ingest")
                || action.contains("memory")
        }
        "llm" | "chat" => {
            action.contains("chat")
                || action.contains("llm")
                || action.contains("cognize")
                || action.contains("complete")
        }
        "tool" => {
            action.contains("tool")
                || action.contains("dispatch")
                || action.contains("mcp")
                || action.contains("exec")
        }
        "network" | "egress" => {
            action.contains("network")
                || action.contains("egress")
                || action.contains("http")
                || action.contains("fetch")
                || action.contains("a2a")
                || action.contains("signal")
                || action.contains("fabric")
        }
        "a2a" | "fabric" | "multiagent" | "signal" | "council" => {
            action.contains("a2a")
                || action.contains("fabric")
                || action.contains("signal")
                || action.contains("multiagent")
                || action.contains("dispatch")
                || action.contains("council")
        }
        "share" | "knowledge" => {
            action.contains("share")
                || action.contains("knowledge")
                || action.contains("ingest")
                || action.contains("memory")
                || action.contains("council")
        }
        "shell" => action.contains("shell") || action.contains("bypass"),
        _ => false,
    }
}

pub fn load_quantum(state: &PlatformState, quantum_id: &str) -> Option<ExecutionQuantumV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_QUANTUM_FOLDER, quantum_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn consume_quantum(state: &PlatformState, quantum_id: &str) -> Result<(), serde_json::Value> {
    let now = chrono::Utc::now().timestamp_millis();
    let node_pk = state.signing_key.public_key_hex();
    let mut es = state.engine_store.lock().unwrap();
    let v = es
        .folder_get(IIA_QUANTUM_FOLDER, quantum_id)
        .ok()
        .flatten()
        .ok_or_else(|| serde_json::json!({"error": "quantum_not_found"}))?;
    let mut q: ExecutionQuantumV2 = serde_json::from_value(v).map_err(|_| {
        serde_json::json!({"error": "quantum_corrupt"})
    })?;
    if q.consumed {
        return Err(serde_json::json!({"error": "quantum_replay", "denial_reason": "consumed"}));
    }
    if now > q.expires_at_ms {
        return Err(serde_json::json!({"error": "quantum_expired"}));
    }
    // B27: when QPR enforce on, signature must verify and match this node's pubkey.
    if qpr_enforce_enabled() {
        let Some(ref sig) = q.signature else {
            return Err(serde_json::json!({
                "error": "quantum_unsigned",
                "denial_reason": "missing_signature",
            }));
        };
        if sig.public_key_hex != node_pk {
            return Err(serde_json::json!({
                "error": "quantum_foreign_signer",
                "denial_reason": "not_node_signed",
            }));
        }
        // verify against unsigned body (signature field None for digest)
        let mut unsigned = q.clone();
        unsigned.signature = None;
        if !verify_signed_payload_v2(&unsigned, sig) {
            return Err(serde_json::json!({
                "error": "quantum_bad_signature",
                "denial_reason": "signature_invalid",
            }));
        }
    }
    q.consumed = true;
    let _ = es.folder_put(
        IIA_QUANTUM_FOLDER,
        quantum_id,
        &serde_json::to_value(&q).unwrap(),
    );
    Ok(())
}

pub fn require_quantum_header(
    state: &PlatformState,
    agent_pid: &str,
    quantum_id: Option<&str>,
) -> Result<(), serde_json::Value> {
    if !qpr_enforce_enabled() {
        return Ok(());
    }
    let Some(qid) = quantum_id else {
        return Err(serde_json::json!({
            "error": "qpr_required",
            "message": "CONNECTOR_IIA_QPR_ENFORCE=1 requires X-Connector-Execution-Quantum",
        }));
    };
    let q = load_quantum(state, qid).ok_or_else(|| {
        serde_json::json!({"error": "quantum_not_found"})
    })?;
    let principal = agent_principal::load_principal(state, agent_pid).ok_or_else(|| {
        serde_json::json!({"error": "principal_not_found"})
    })?;
    if q.principal_id != principal.principal_id {
        return Err(serde_json::json!({"error": "quantum_principal_mismatch"}));
    }
    consume_quantum(state, qid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::{AgentContractV2, IIA_SCHEMA};

    fn contract_with(caps: &[&str], denied: &[&str]) -> AgentContractV2 {
        AgentContractV2 {
            schema: IIA_SCHEMA.into(),
            agent_id: "cnktr:agent:t".into(),
            issuer: "i".into(),
            purpose: vec![],
            capabilities: caps.iter().map(|s| (*s).into()).collect(),
            denied_operations: denied.iter().map(|s| (*s).into()).collect(),
            filesystem_read: vec![],
            filesystem_write: vec![],
            network_allow: vec![],
            network_default: "deny".into(),
            receipt_required: true,
            contract_digest_sha256: "x".into(),
            contract_version: 2,
        }
    }

    #[test]
    fn read_capability_does_not_allow_shell() {
        let c = contract_with(&["read"], &[]);
        assert!(contract_allows_action(&c, "llm.chat", "/x"));
        assert!(!contract_allows_action(&c, "ambient_shell", "/bin/sh"));
        assert!(!contract_allows_action(&c, "tool.dispatch", "curl"));
    }

    #[test]
    fn empty_capabilities_deny() {
        let c = contract_with(&[], &[]);
        assert!(!contract_allows_action(&c, "llm.chat", "/x"));
    }

    #[test]
    fn denied_operations_win() {
        let c = contract_with(&["*"], &["ambient_shell"]);
        assert!(!contract_allows_action(&c, "ambient_shell", "x"));
    }

    #[test]
    fn qpr_enforce_all_flags_off_no_recurse() {
        let _ = qpr_enforce_enabled();
    }
}

/// Revoke all unconsumed quanta for an agent principal (continuity break / matrix isolation).
pub fn revoke_all_quanta_for_agent(state: &PlatformState, api_pid: &str) -> usize {
    let Some(principal) = agent_principal::load_principal(state, api_pid) else {
        return 0;
    };
    let Ok(mut es) = state.engine_store.lock() else {
        return 0;
    };
    let keys = es
        .folder_keys(IIA_QUANTUM_FOLDER, None)
        .unwrap_or_default();
    let mut revoked = 0usize;
    for key in keys {
        let Some(v) = es.folder_get(IIA_QUANTUM_FOLDER, &key).ok().flatten() else {
            continue;
        };
        let Ok(mut q) = serde_json::from_value::<ExecutionQuantumV2>(v) else {
            continue;
        };
        if q.principal_id != principal.principal_id || q.consumed {
            continue;
        }
        q.consumed = true;
        if es
            .folder_put(IIA_QUANTUM_FOLDER, &key, &serde_json::to_value(&q).unwrap())
            .is_ok()
        {
            revoked += 1;
        }
    }
    revoked
}
