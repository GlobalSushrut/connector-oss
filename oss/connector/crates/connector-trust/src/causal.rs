//! Canonical causal envelope — one lineage for every governed effect.

use serde::{Deserialize, Serialize};

/// Complete causal record for a governed decision and its effects.
///
/// Sprint 1 lands the schema; R3 wires keyed audit and independent verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CausalEnvelopeV2 {
    pub envelope_id: String,
    /// Initiating principal subject.
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub delegation_chain: Vec<String>,
    pub action: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    /// `allow` | `deny` | `break_glass`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    #[serde(default)]
    pub side_effects: Vec<String>,
    /// Previous envelope / audit after_hash for chaining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_mac: Option<String>,
    /// Integrity tag over this envelope (HMAC or hash hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_mac: Option<String>,
    /// Unix epoch milliseconds.
    pub occurred_at_ms: i64,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}
