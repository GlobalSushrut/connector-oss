//! EffectEnvelopeV1 — internal governed effect transport (Seven Pillars §5).
//!
//! Agents submit structured effect requests; trusted adapters serialize to
//! external protocols only after authority exists.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EFFECT_ENVELOPE_SCHEMA: &str = "connector.effect_envelope.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectEnvelopeV1 {
    pub schema: String,
    pub principal_id: String,
    pub agent_pid: String,
    pub workload_id: Option<String>,
    pub contract_hash: Option<String>,
    pub grant_id: Option<String>,
    pub address: String,
    pub operation: String,
    /// Digest of canonical parameters (hex SHA-256).
    pub parameter_digest: String,
    pub quantum_id: Option<String>,
    pub flow_lease_id: Option<String>,
    /// Embedded or referenced EffectAuthorization digest.
    pub authorization_digest: Option<String>,
    pub nonce: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub causal_id: Option<String>,
    pub mission_id: Option<String>,
    pub signer_key_id: String,
    pub digest_hex: String,
    pub signature: String,
}

impl EffectEnvelopeV1 {
    pub fn unsigned_preimage(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": EFFECT_ENVELOPE_SCHEMA,
            "principal_id": self.principal_id,
            "agent_pid": self.agent_pid,
            "workload_id": self.workload_id,
            "contract_hash": self.contract_hash,
            "grant_id": self.grant_id,
            "address": self.address,
            "operation": self.operation,
            "parameter_digest": self.parameter_digest,
            "quantum_id": self.quantum_id,
            "flow_lease_id": self.flow_lease_id,
            "authorization_digest": self.authorization_digest,
            "nonce": self.nonce,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "causal_id": self.causal_id,
            "mission_id": self.mission_id,
            "signer_key_id": self.signer_key_id,
        })
    }

    pub fn compute_digest_hex(&self) -> String {
        let bytes = serde_json::to_vec(&self.unsigned_preimage()).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub fn digest_matches(&self) -> bool {
        self.digest_hex == self.compute_digest_hex()
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expires_at_unix
    }

    pub fn parameter_digest_of(parameters: &serde_json::Value) -> String {
        let canon = match parameters {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    if let Some(c) = map.get(k) {
                        out.insert(k.clone(), c.clone());
                    }
                }
                serde_json::Value::Object(out)
            }
            other => other.clone(),
        };
        let bytes = serde_json::to_vec(&canon).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_digest_stable() {
        let mut e = EffectEnvelopeV1 {
            schema: EFFECT_ENVELOPE_SCHEMA.into(),
            principal_id: "p".into(),
            agent_pid: "a".into(),
            workload_id: None,
            contract_hash: None,
            grant_id: None,
            address: "mcp:tool".into(),
            operation: "call".into(),
            parameter_digest: "abc".into(),
            quantum_id: None,
            flow_lease_id: None,
            authorization_digest: None,
            nonce: "1".into(),
            issued_at_unix: 1,
            expires_at_unix: 99,
            causal_id: None,
            mission_id: None,
            signer_key_id: "k".into(),
            digest_hex: String::new(),
            signature: String::new(),
        };
        e.digest_hex = e.compute_digest_hex();
        assert!(e.digest_matches());
    }
}
