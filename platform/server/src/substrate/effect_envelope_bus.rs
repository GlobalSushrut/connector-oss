//! EffectEnvelope mint/attach for tool and CONP paths (Seven Pillars §5).
//! Also mints Agent Packet DNA (seven genome params) for network-bound effects.

use connector_trust::{AgentPacketDnaV1, EffectEnvelopeV1, EFFECT_ENVELOPE_SCHEMA};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::kernel::action_binding::ActionBinding;
use crate::state::PlatformState;

type HmacSha256 = Hmac<Sha256>;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signing_key_bytes() -> Vec<u8> {
    for key in [
        "CONNECTOR_EFFECT_AUTHZ_HMAC",
        "CONNECTOR_AUDIT_HMAC_SECRET",
        "CONNECTOR_AUDIT_HMAC_KEY",
    ] {
        if let Ok(s) = std::env::var(key) {
            if !s.trim().is_empty() {
                return s.into_bytes();
            }
        }
    }
    if crate::connector_profile::is_productionish_env() {
        panic!(
            "effect envelope: CONNECTOR_EFFECT_AUTHZ_HMAC (or CONNECTOR_AUDIT_HMAC_KEY) required under productionish env"
        );
    }
    tracing::warn!("effect envelope: using lab-only HMAC key");
    b"connector-effect-envelope-dev".to_vec()
}

fn sign(digest: &str) -> String {
    let key = signing_key_bytes();
    let mut mac = HmacSha256::new_from_slice(&key)
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(digest.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build a signed EffectEnvelope from an ActionBinding + optional authz/flow/mission ids.
pub fn mint_for_tool(
    state: &PlatformState,
    binding: &ActionBinding,
    authorization_digest: Option<String>,
    flow_lease_id: Option<String>,
    quantum_id: Option<String>,
    mission_id: Option<String>,
    ttl_secs: u64,
) -> EffectEnvelopeV1 {
    let now = now_unix();
    let principal = binding
        .principal_id
        .clone()
        .unwrap_or_else(|| format!("agent:{}", binding.agent_pid));
    let mut env = EffectEnvelopeV1 {
        schema: EFFECT_ENVELOPE_SCHEMA.into(),
        principal_id: principal,
        agent_pid: binding.agent_pid.clone(),
        workload_id: None,
        contract_hash: binding.contract_digest.clone(),
        grant_id: None,
        address: binding.target.resource.clone(),
        operation: binding.operation.clone(),
        parameter_digest: EffectEnvelopeV1::parameter_digest_of(&binding.parameters),
        quantum_id,
        flow_lease_id,
        authorization_digest,
        nonce: Uuid::new_v4().to_string(),
        issued_at_unix: now,
        expires_at_unix: now.saturating_add(ttl_secs.max(30)),
        causal_id: None,
        mission_id,
        signer_key_id: "node-hmac-v1".into(),
        digest_hex: String::new(),
        signature: String::new(),
    };
    env.digest_hex = env.compute_digest_hex();
    env.signature = sign(&env.digest_hex);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "effect_envelope_v1",
            &env.nonce,
            &serde_json::to_value(&env).unwrap_or_default(),
        );
    }
    env
}

/// Mint packet DNA alongside an effect envelope (agent genome for the wire hop).
pub fn mint_dna_for_tool(
    state: &PlatformState,
    binding: &ActionBinding,
    flow_lease_id: Option<&str>,
    quantum_id: Option<&str>,
    ttl_ms: i64,
) -> Result<AgentPacketDnaV1, String> {
    let payload = serde_json::json!({
        "address": binding.target.resource,
        "operation": binding.operation,
        "parameters": binding.parameters,
    });
    crate::substrate::packet_dna::mint_for_agent(
        state,
        &binding.agent_pid,
        &binding.operation,
        &binding.target.resource,
        &binding.parameters,
        &payload,
        quantum_id,
        flow_lease_id,
        ttl_ms,
    )
}

pub fn verify_envelope(env: &EffectEnvelopeV1) -> Result<(), String> {
    if !env.digest_matches() {
        return Err("effect_envelope_digest_mismatch".into());
    }
    if env.is_expired(now_unix()) {
        return Err("effect_envelope_expired".into());
    }
    if sign(&env.digest_hex) != env.signature {
        return Err("effect_envelope_signature_invalid".into());
    }
    Ok(())
}
