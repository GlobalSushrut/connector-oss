//! Temporal state ledger — bitemporal claims; old truth stays historical.

use connector_trust::{StateClaim, TrustTier, STATE_CLAIM_SCHEMA};
use serde_json::Value;

use crate::state::PlatformState;

use super::trust_firewall;
use super::{now_ms, FOLDER_CLAIMS};

fn claim_key(agent_pid: &str, claim_id: &str) -> String {
    format!("{agent_pid}:{claim_id}")
}

fn current_key(agent_pid: &str, subject: &str, predicate: &str) -> String {
    format!("current:{agent_pid}:{subject}:{predicate}")
}

/// Append a claim. If it supersedes an active claim, close the old valid_until.
pub fn put_claim(
    state: &PlatformState,
    agent_pid: &str,
    claim_id: &str,
    subject: &str,
    predicate: &str,
    value: Value,
    source: &str,
    trust: TrustTier,
    evidence_cids: Vec<String>,
    supersedes: Option<&str>,
    confidence: f32,
) -> Result<StateClaim, String> {
    let now = now_ms();
    if let Some(old_id) = supersedes {
        deactivate(state, agent_pid, old_id, now)?;
    } else if let Some(active_id) = active_claim_id(state, agent_pid, subject, predicate) {
        // Same subject/predicate without explicit supersede → close prior.
        deactivate(state, agent_pid, &active_id, now)?;
    }

    let envelope = trust_firewall::bind_envelope(
        claim_id,
        agent_pid,
        source,
        trust,
        "committed",
        evidence_cids.clone(),
        None,
        None,
        Some(now),
        None,
    );

    let claim = StateClaim {
        schema: STATE_CLAIM_SCHEMA.into(),
        claim_id: claim_id.into(),
        agent_pid: agent_pid.into(),
        subject: subject.into(),
        predicate: predicate.into(),
        value,
        valid_from_ms: now,
        valid_until_ms: None,
        observed_at_ms: now,
        source: source.into(),
        supersedes: supersedes.map(|s| s.to_string()),
        confidence,
        evidence_cids,
        envelope,
        active: true,
    };

    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(&claim).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_CLAIMS, &claim_key(agent_pid, claim_id), &val)
        .map_err(|e| format!("put claim: {e}"))?;
    es.folder_put(
        FOLDER_CLAIMS,
        &current_key(agent_pid, subject, predicate),
        &serde_json::json!({ "claim_id": claim_id }),
    )
    .map_err(|e| format!("put current: {e}"))?;
    Ok(claim)
}

fn deactivate(
    state: &PlatformState,
    agent_pid: &str,
    claim_id: &str,
    until_ms: i64,
) -> Result<(), String> {
    let key = claim_key(agent_pid, claim_id);
    let mut claim: StateClaim = {
        let es = state
            .engine_store
            .lock()
            .map_err(|e| format!("engine_store lock: {e}"))?;
        let v = es
            .folder_get(FOLDER_CLAIMS, &key)
            .ok()
            .flatten()
            .ok_or_else(|| format!("claim_not_found:{claim_id}"))?;
        serde_json::from_value(v).map_err(|e| format!("parse claim: {e}"))?
    };
    claim.active = false;
    claim.valid_until_ms = Some(until_ms);
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(&claim).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_CLAIMS, &key, &val)
        .map_err(|e| format!("put deactivated: {e}"))?;
    Ok(())
}

fn active_claim_id(state: &PlatformState, agent_pid: &str, subject: &str, predicate: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(FOLDER_CLAIMS, &current_key(agent_pid, subject, predicate))
        .ok()
        .flatten()
        .and_then(|v| v.get("claim_id").and_then(|c| c.as_str()).map(|s| s.to_string()))
}

pub fn load_claim(state: &PlatformState, agent_pid: &str, claim_id: &str) -> Option<StateClaim> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER_CLAIMS, &claim_key(agent_pid, claim_id))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

/// Presently valid claim for subject/predicate at `at_ms` (gates cognition).
pub fn current_at(
    state: &PlatformState,
    agent_pid: &str,
    subject: &str,
    predicate: &str,
    at_ms: i64,
) -> Option<StateClaim> {
    let id = active_claim_id(state, agent_pid, subject, predicate)?;
    let claim = load_claim(state, agent_pid, &id)?;
    if claim.is_active_at(at_ms) {
        Some(claim)
    } else {
        None
    }
}

/// List claim CIDs that are active for this agent (for eligibility scan).
pub fn list_active_claim_ids(state: &PlatformState, agent_pid: &str) -> Vec<String> {
    let keys = super::store_scans::scan_claim_keys(state, agent_pid);
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(FOLDER_CLAIMS, &k) {
            if let Ok(c) = serde_json::from_value::<StateClaim>(v) {
                if c.active {
                    out.push(c.claim_id);
                }
            }
        }
    }
    out
}
