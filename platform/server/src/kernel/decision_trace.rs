//! TG-5 — Decision traces (hash-chained) ≠ logs.
//!
//! Every gateway Allow/Ask/Block and fabric terminal transition appends a
//! `DecisionTraceV1` for court-shaped forensic packages.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::kernel::agent_principal;
use crate::state::PlatformState;

pub const TRACE_SCHEMA: &str = "connector.decision.trace.v1";
pub const TRACE_FOLDER: &str = "iia_decision_traces";
pub const TRACE_HEAD_FOLDER: &str = "iia_decision_trace_heads";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTraceV1 {
    pub schema: String,
    pub trace_id: String,
    pub agent_pid: String,
    pub principal_id: Option<String>,
    pub prev_hash: String,
    pub record_hash: String,
    pub gateway: String,
    pub policy_version: String,
    pub action_digest: Option<String>,
    pub approval_resolution_id: Option<String>,
    pub model_ref: Option<String>,
    #[serde(default)]
    pub rag_context_hashes: Vec<String>,
    pub outcome: String,
    pub at_ms: i64,
    /// NP-5: CONP / protocol evidence (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnp_message_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TraceAppendOpts {
    pub gateway: String,
    pub action_digest: Option<String>,
    pub approval_resolution_id: Option<String>,
    pub model_ref: Option<String>,
    pub rag_context_hashes: Vec<String>,
    pub outcome: String,
    pub policy_version: Option<String>,
    pub message_type: Option<String>,
    pub capability_id: Option<String>,
    pub cnp_message_id: Option<String>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn load_head(state: &PlatformState, agent_pid: &str) -> String {
    let Ok(es) = state.engine_store.lock() else {
        return "genesis".into();
    };
    es.folder_get(TRACE_HEAD_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("head").and_then(|h| h.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "genesis".into())
}

fn compute_record_hash(t: &DecisionTraceV1) -> String {
    // Hash without record_hash field (set after).
    let material = json!({
        "schema": t.schema,
        "trace_id": t.trace_id,
        "agent_pid": t.agent_pid,
        "principal_id": t.principal_id,
        "prev_hash": t.prev_hash,
        "gateway": t.gateway,
        "policy_version": t.policy_version,
        "action_digest": t.action_digest,
        "approval_resolution_id": t.approval_resolution_id,
        "model_ref": t.model_ref,
        "rag_context_hashes": t.rag_context_hashes,
        "outcome": t.outcome,
        "at_ms": t.at_ms,
        "message_type": t.message_type,
        "capability_id": t.capability_id,
        "cnp_message_id": t.cnp_message_id,
    });
    let bytes = serde_json::to_vec(&crate::kernel::action_binding::canonical_json(&material))
        .unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

pub fn append_trace(state: &PlatformState, agent_pid: &str, opts: TraceAppendOpts) -> DecisionTraceV1 {
    append_trace_result(state, agent_pid, opts).unwrap_or_else(|_| DecisionTraceV1 {
        schema: TRACE_SCHEMA.into(),
        trace_id: "dt_persist_failed".into(),
        agent_pid: agent_pid.into(),
        principal_id: None,
        prev_hash: "unavailable".into(),
        record_hash: "unavailable".into(),
        gateway: "persist_failed".into(),
        policy_version: "none".into(),
        action_digest: None,
        approval_resolution_id: None,
        model_ref: None,
        rag_context_hashes: vec![],
        outcome: "trace_persist_failed".into(),
        at_ms: now_ms(),
        message_type: None,
        capability_id: None,
        cnp_message_id: None,
    })
}

pub fn append_trace_result(
    state: &PlatformState,
    agent_pid: &str,
    opts: TraceAppendOpts,
) -> Result<DecisionTraceV1, String> {
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    let policy_version = opts.policy_version.unwrap_or_else(|| {
        agent_principal::load_contract(state, agent_pid)
            .map(|c| c.contract_version.to_string())
            .unwrap_or_else(|| "none".into())
    });
    let prev = load_head(state, agent_pid);
    let mut trace = DecisionTraceV1 {
        schema: TRACE_SCHEMA.into(),
        trace_id: format!("dt_{}", Uuid::new_v4()),
        agent_pid: agent_pid.into(),
        principal_id,
        prev_hash: prev,
        record_hash: String::new(),
        gateway: opts.gateway,
        policy_version,
        action_digest: opts.action_digest,
        approval_resolution_id: opts.approval_resolution_id,
        model_ref: opts.model_ref,
        rag_context_hashes: opts.rag_context_hashes,
        outcome: opts.outcome,
        at_ms: now_ms(),
        message_type: opts.message_type,
        capability_id: opts.capability_id,
        cnp_message_id: opts.cnp_message_id,
    };
    // Never attribute to gateway-* fake principal
    if trace
        .principal_id
        .as_deref()
        .map(|p| p.starts_with("gateway-") || p.starts_with("gateway_"))
        .unwrap_or(false)
    {
        trace.principal_id = None;
    }
    trace.record_hash = compute_record_hash(&trace);

    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store_lock:{e}"))?;
    let v = serde_json::to_value(&trace).map_err(|e| e.to_string())?;
    es.folder_put(TRACE_FOLDER, &trace.trace_id, &v)
        .map_err(|e| format!("trace_put:{e}"))?;
    es.folder_put(
        TRACE_HEAD_FOLDER,
        agent_pid,
        &json!({
            "head": trace.record_hash,
            "trace_id": trace.trace_id,
            "at_ms": trace.at_ms,
        }),
    )
    .map_err(|e| format!("trace_head_put:{e}"))?;
    Ok(trace)
}

pub fn list_traces(
    state: &PlatformState,
    agent_pid: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Vec<DecisionTraceV1> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let keys = es.folder_keys(TRACE_FOLDER, None).unwrap_or_default();
    let from = from_ms.unwrap_or(0);
    let to = to_ms.unwrap_or(i64::MAX);
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(TRACE_FOLDER, &k) {
            if let Ok(t) = serde_json::from_value::<DecisionTraceV1>(v) {
                if t.agent_pid == agent_pid && t.at_ms >= from && t.at_ms <= to {
                    out.push(t);
                }
            }
        }
    }
    out.sort_by_key(|t| t.at_ms);
    out
}

/// Verify hash chain for an agent (or provided slice). Fail-closed on break.
pub fn verify_trace_chain(traces: &[DecisionTraceV1]) -> Result<(), String> {
    let mut prev = "genesis".to_string();
    for t in traces {
        if t.prev_hash != prev {
            return Err(format!(
                "trace_chain_break: {} expected prev={} got={}",
                t.trace_id, prev, t.prev_hash
            ));
        }
        let mut check = t.clone();
        check.record_hash.clear();
        let expect = compute_record_hash(&check);
        if expect != t.record_hash {
            return Err(format!("trace_hash_mismatch: {}", t.trace_id));
        }
        if t.principal_id
            .as_deref()
            .map(|p| p.starts_with("gateway-") || p.starts_with("gateway_"))
            .unwrap_or(false)
        {
            return Err(format!("gateway_attribution_forbidden: {}", t.trace_id));
        }
        prev = t.record_hash.clone();
    }
    Ok(())
}

pub fn traces_json(traces: &[DecisionTraceV1]) -> Value {
    json!({
        "schema": "connector.decision.traces.bundle.v1",
        "count": traces.len(),
        "chain_ok": verify_trace_chain(traces).is_ok(),
        "traces": traces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_links() {
        let mut a = DecisionTraceV1 {
            schema: TRACE_SCHEMA.into(),
            trace_id: "dt_a".into(),
            agent_pid: "agent_1".into(),
            principal_id: Some("cnktr:agent:1".into()),
            prev_hash: "genesis".into(),
            record_hash: String::new(),
            gateway: "allow".into(),
            policy_version: "1".into(),
            action_digest: Some("aa".into()),
            approval_resolution_id: None,
            model_ref: None,
            rag_context_hashes: vec![],
            outcome: "ok".into(),
            at_ms: 1,
            message_type: None,
            capability_id: None,
            cnp_message_id: None,
        };
        a.record_hash = compute_record_hash(&a);
        let mut b = a.clone();
        b.trace_id = "dt_b".into();
        b.prev_hash = a.record_hash.clone();
        b.outcome = "next".into();
        b.at_ms = 2;
        b.record_hash = String::new();
        b.record_hash = compute_record_hash(&b);
        assert!(verify_trace_chain(&[a.clone(), b.clone()]).is_ok());
        b.prev_hash = "wrong".into();
        b.record_hash = String::new();
        b.record_hash = compute_record_hash(&b);
        assert!(verify_trace_chain(&[a, b]).is_err());
    }
}
