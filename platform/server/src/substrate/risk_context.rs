//! RiskContextEnvelope — minimal signed risk capsule for LTL.
//! Exposes affordances/obligations without leaking full policy internals.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;
use crate::substrate::affordance_envelope;
use crate::substrate::rgo;

pub const RISK_SCHEMA: &str = "connector.risk_context.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContextEnvelope {
    pub schema: String,
    pub agent_pid: String,
    pub autonomy_tier: u8,
    pub allowed_ops_hint: Vec<String>,
    pub obligations: Vec<String>,
    pub max_reversibility: String,
    pub digest_hex: String,
    pub signature: String,
    pub expires_at_ms: i64,
}

type HmacSha256 = Hmac<Sha256>;

fn secret() -> Vec<u8> {
    std::env::var("CONNECTOR_AUDIT_HMAC_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_CNP_HMAC"))
        .unwrap_or_else(|_| "connector-risk-dev".into())
        .into_bytes()
}

/// Mint a short-lived risk capsule for the proposer (LTL).
pub fn mint(state: &PlatformState, agent_pid: &str, ttl_ms: i64) -> RiskContextEnvelope {
    let env = affordance_envelope::compile(state, agent_pid);
    let autonomy_tier = rgo::autonomy_tier();
    let allowed_ops_hint: Vec<String> = env
        .slots
        .iter()
        .take(12)
        .map(|s| format!("{}:{}", s.address, s.ops.join("|")))
        .collect();
    let obligations = vec![
        "no_raw_policy_leak".into(),
        "every_effect_needs_action_binding".into(),
        "reasoning_content_is_transport_only".into(),
    ];
    let max_reversibility = if autonomy_tier <= 2 { "R2" } else { "R3" }.to_string();
    let expires_at_ms = chrono::Utc::now().timestamp_millis() + ttl_ms.max(5_000);
    let preimage = json!({
        "agent_pid": agent_pid,
        "autonomy_tier": autonomy_tier,
        "allowed_ops_hint": allowed_ops_hint,
        "obligations": obligations,
        "max_reversibility": max_reversibility,
        "expires_at_ms": expires_at_ms,
    });
    let bytes = serde_json::to_vec(&preimage).unwrap_or_default();
    let digest_hex = format!("{:x}", Sha256::digest(&bytes));
    let mut mac = HmacSha256::new_from_slice(&secret())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(digest_hex.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    RiskContextEnvelope {
        schema: RISK_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        autonomy_tier,
        allowed_ops_hint,
        obligations,
        max_reversibility,
        digest_hex,
        signature,
        expires_at_ms,
    }
}

pub fn verify(env: &RiskContextEnvelope) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    if now > env.expires_at_ms {
        return Err("risk_context_expired".into());
    }
    let preimage = json!({
        "agent_pid": env.agent_pid,
        "autonomy_tier": env.autonomy_tier,
        "allowed_ops_hint": env.allowed_ops_hint,
        "obligations": env.obligations,
        "max_reversibility": env.max_reversibility,
        "expires_at_ms": env.expires_at_ms,
    });
    let bytes = serde_json::to_vec(&preimage).unwrap_or_default();
    let digest_hex = format!("{:x}", Sha256::digest(&bytes));
    if digest_hex != env.digest_hex {
        return Err("risk_context_digest_mismatch".into());
    }
    let mut mac = HmacSha256::new_from_slice(&secret())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(digest_hex.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected != env.signature {
        return Err("risk_context_signature_mismatch".into());
    }
    Ok(())
}

pub fn to_json(e: &RiskContextEnvelope) -> Value {
    serde_json::to_value(e).unwrap_or(json!({ "ok": false }))
}
