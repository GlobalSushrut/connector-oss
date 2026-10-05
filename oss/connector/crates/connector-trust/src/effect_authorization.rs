//! EffectAuthorizationV1 — exact-action cryptographic authorization (Seven Pillars §3).
//!
//! An address/effect adapter accepts an action only when it can verify a current
//! authorization artifact that binds principal, target, operation, parameters,
//! policy, and approval state.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EFFECT_AUTHORIZATION_SCHEMA: &str = "connector.effect_authorization.v1";

/// Canonical exact-action authorization object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectAuthorizationV1 {
    pub schema: String,
    pub principal_id: String,
    pub node_id: String,
    pub agent_pid: String,
    /// Target address / resource identity.
    pub address: String,
    /// Operation / tool / method.
    pub operation: String,
    /// Canonical JSON of parameters (already normalized).
    pub parameters_canonical: serde_json::Value,
    pub character_hash: Option<String>,
    pub contract_hash: Option<String>,
    pub policy_version: String,
    pub grant_id: Option<String>,
    pub hitl_approval_ref: Option<String>,
    pub nonce: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub quantum_id: Option<String>,
    pub signer_key_id: String,
    /// Hex SHA-256 digest of the unsigned payload (preimage without `signature`).
    pub digest_hex: String,
    /// Hex signature over `digest_hex` bytes (HMAC or Ed25519 hex, profile-dependent).
    pub signature: String,
}

fn sort_json(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(child) = map.get(k) {
                    out.insert(k.clone(), sort_json(child));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json).collect())
        }
        other => other.clone(),
    }
}

impl EffectAuthorizationV1 {
    /// Build unsigned digest preimage (signature field omitted / empty).
    pub fn unsigned_preimage(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": EFFECT_AUTHORIZATION_SCHEMA,
            "principal_id": self.principal_id,
            "node_id": self.node_id,
            "agent_pid": self.agent_pid,
            "address": self.address,
            "operation": self.operation,
            "parameters_canonical": sort_json(&self.parameters_canonical),
            "character_hash": self.character_hash,
            "contract_hash": self.contract_hash,
            "policy_version": self.policy_version,
            "grant_id": self.grant_id,
            "hitl_approval_ref": self.hitl_approval_ref,
            "nonce": self.nonce,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "quantum_id": self.quantum_id,
            "signer_key_id": self.signer_key_id,
        })
    }

    pub fn compute_digest_hex(&self) -> String {
        let v = sort_json(&self.unsigned_preimage());
        let bytes = serde_json::to_vec(&v).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at_unix
    }

    /// True when digest matches recomputed preimage (tamper check before signature verify).
    pub fn digest_matches(&self) -> bool {
        self.digest_hex == self.compute_digest_hex()
    }
}

/// Mint a digest for an ActionBinding-compatible payload (projection helper).
pub fn digest_hex_for_params(
    principal_id: &str,
    agent_pid: &str,
    address: &str,
    operation: &str,
    parameters: &serde_json::Value,
    policy_version: &str,
) -> String {
    let v = sort_json(&serde_json::json!({
        "schema": EFFECT_AUTHORIZATION_SCHEMA,
        "principal_id": principal_id,
        "agent_pid": agent_pid,
        "address": address,
        "operation": operation,
        "parameters_canonical": parameters,
        "policy_version": policy_version,
    }));
    let bytes = serde_json::to_vec(&v).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_change_changes_digest() {
        let mut a = EffectAuthorizationV1 {
            schema: EFFECT_AUTHORIZATION_SCHEMA.into(),
            principal_id: "p1".into(),
            node_id: "n1".into(),
            agent_pid: "a1".into(),
            address: "http://example.com".into(),
            operation: "tool.invoke".into(),
            parameters_canonical: serde_json::json!({"x": 1}),
            character_hash: None,
            contract_hash: None,
            policy_version: "1".into(),
            grant_id: None,
            hitl_approval_ref: None,
            nonce: "n".into(),
            issued_at_unix: 1,
            expires_at_unix: 100,
            quantum_id: None,
            signer_key_id: "k".into(),
            digest_hex: String::new(),
            signature: String::new(),
        };
        a.digest_hex = a.compute_digest_hex();
        let d1 = a.digest_hex.clone();
        a.parameters_canonical = serde_json::json!({"x": 2});
        assert_ne!(d1, a.compute_digest_hex());
    }
}
