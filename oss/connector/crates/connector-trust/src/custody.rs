//! Portable custody receipt for independent verification.

use serde::{Deserialize, Serialize};

/// Externally verifiable custody / proof receipt.
///
/// Must not claim validity unless an independent verifier recomputes checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyReceiptV2 {
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Inclusive event / audit range start id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_range_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_range_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(default)]
    pub artifact_digests: Vec<String>,
    /// Signature bytes (hex) when signed; absent means unsigned export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Explicit verification status — never default to valid.
    pub verification_status: CustodyVerificationStatus,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustodyVerificationStatus {
    /// Schema exported; integrity not yet checked.
    Unverified,
    /// Independent verifier recomputed and passed.
    Verified,
    /// Independent verifier recomputed and failed.
    Failed,
    /// Signature or chain missing required material.
    Incomplete,
}
