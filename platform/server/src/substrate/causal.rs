//! Causal envelope append store — one lineage record per governed admission pass.

use connector_trust::CausalEnvelopeV2;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::state::{PlatformState, SharedState};

type HmacSha256 = Hmac<Sha256>;

pub const CAUSAL_ENVELOPE_FOLDER: &str = "causal_envelopes_v2";
const PREVIOUS_MAC_KEY: &str = "causal_chain_head";

/// Record a causal envelope after successful admission.
pub fn record_admission_envelope(
    state: &SharedState,
    principal_id: &str,
    tenant_id: Option<&str>,
    agent_pid: &str,
    session_id: Option<&str>,
    action: &str,
    resource: &str,
    admission_ticket_id: &str,
    policy_revision: Option<u64>,
) -> CausalEnvelopeV2 {
    let now = chrono::Utc::now().timestamp_millis();
    let envelope_id = format!("env_{}", uuid::Uuid::new_v4().simple());
    let previous_mac = read_chain_head(state);
    let mut env = CausalEnvelopeV2 {
        envelope_id: envelope_id.clone(),
        principal_id: principal_id.to_string(),
        tenant_id: tenant_id.map(str::to_string),
        workload_id: Some(agent_pid.to_string()),
        session_id: session_id.map(str::to_string),
        delegation_chain: vec![],
        action: action.to_string(),
        resource: resource.to_string(),
        policy_revision,
        decision: "allow".to_string(),
        admission_ticket_id: Some(admission_ticket_id.to_string()),
        input_digest: None,
        output_digest: None,
        side_effects: vec![],
        previous_mac: previous_mac.clone(),
        integrity_mac: None,
        occurred_at_ms: now,
        contract_version: 2,
    };
    env.integrity_mac = Some(compute_integrity_mac(&env));
    persist_envelope(state, &env);
    write_chain_head(state, env.integrity_mac.as_deref().unwrap_or(&envelope_id));
    env
}

fn causal_mac_key() -> Vec<u8> {
    if let Ok(s) = std::env::var("CONNECTOR_CAUSAL_HMAC_KEY") {
        let t = s.trim();
        if !t.is_empty() {
            return t.as_bytes().to_vec();
        }
    }
    if let Ok(s) = std::env::var("CONNECTOR_AUDIT_HMAC_KEY") {
        let t = s.trim();
        if !t.is_empty() {
            return t.as_bytes().to_vec();
        }
    }
    b"connector-causal-hmac-dev-only".to_vec()
}

/// Keyed HMAC over canonical envelope fields (excludes integrity_mac itself).
fn compute_integrity_mac(env: &CausalEnvelopeV2) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        env.envelope_id,
        env.principal_id,
        env.tenant_id.as_deref().unwrap_or(""),
        env.workload_id.as_deref().unwrap_or(""),
        env.session_id.as_deref().unwrap_or(""),
        env.action,
        env.resource,
        env.decision,
        env.admission_ticket_id.as_deref().unwrap_or(""),
        env.previous_mac.as_deref().unwrap_or(""),
    );
    let mut mac = HmacSha256::new_from_slice(&causal_mac_key())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"connector-causal-hmac-fallback").expect("hmac"));
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a persisted envelope's integrity_mac (U5.2).
pub fn verify_integrity_mac(env: &CausalEnvelopeV2) -> bool {
    let Some(claimed) = env.integrity_mac.as_deref() else {
        return false;
    };
    let expected = compute_integrity_mac(env);
    expected == claimed
}

fn persist_envelope(state: &SharedState, env: &CausalEnvelopeV2) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        CAUSAL_ENVELOPE_FOLDER,
        &env.envelope_id,
        &serde_json::to_value(env).unwrap_or_default(),
    );
}

fn read_chain_head(state: &SharedState) -> Option<String> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(CAUSAL_ENVELOPE_FOLDER, PREVIOUS_MAC_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(str::to_string))
}

fn write_chain_head(state: &SharedState, mac: &str) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        CAUSAL_ENVELOPE_FOLDER,
        PREVIOUS_MAC_KEY,
        &serde_json::Value::String(mac.to_string()),
    );
}

pub fn causal_envelope_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(CAUSAL_ENVELOPE_FOLDER, None)
        .map(|keys| keys.iter().filter(|k| *k != PREVIOUS_MAC_KEY).count())
        .unwrap_or(0)
}

pub fn latest_envelope_id(state: &PlatformState) -> Option<String> {
    let es = state.engine_store.lock().unwrap();
    let mut keys = es.folder_keys(CAUSAL_ENVELOPE_FOLDER, None).unwrap_or_default();
    keys.retain(|k| k != PREVIOUS_MAC_KEY);
    keys.sort();
    keys.pop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_mac_is_keyed_and_verifies() {
        std::env::set_var("CONNECTOR_CAUSAL_HMAC_KEY", "test-causal-key");
        let env = CausalEnvelopeV2 {
            envelope_id: "env_test".into(),
            principal_id: "p1".into(),
            tenant_id: Some("t1".into()),
            workload_id: Some("a1".into()),
            session_id: None,
            delegation_chain: vec![],
            action: "memory.write".into(),
            resource: "ns/default".into(),
            policy_revision: None,
            decision: "allow".into(),
            admission_ticket_id: Some("tk1".into()),
            input_digest: None,
            output_digest: None,
            side_effects: vec![],
            previous_mac: None,
            integrity_mac: None,
            occurred_at_ms: 1,
            contract_version: 2,
        };
        let mut with_mac = env.clone();
        with_mac.integrity_mac = Some(compute_integrity_mac(&env));
        assert!(verify_integrity_mac(&with_mac));
        with_mac.action = "tampered".into();
        assert!(!verify_integrity_mac(&with_mac));
        std::env::remove_var("CONNECTOR_CAUSAL_HMAC_KEY");
    }
}
