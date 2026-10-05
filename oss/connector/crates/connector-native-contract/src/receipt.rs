//! Edge receipts for observed / enforced operations.

use serde::{Deserialize, Serialize};

use crate::posture::EnforcementPosture;
use crate::semantic::{SemanticConfidence, SemanticProvenance};
use crate::surface::TargetRef;

/// Edge receipt capturing enforcement and evidence for an operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeReceipt {
    pub operation_id: String,
    pub intelligence_uid: String,
    pub workload_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_uid: Option<String>,
    pub semantic_confidence: SemanticConfidence,
    pub semantic_provenance: SemanticProvenance,
    pub enforcement_posture: EnforcementPosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<TargetRef>,
    /// Observed locator digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_locators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_loss_digest: Option<String>,
    pub contract_ref: String,
    pub contract_revision: u64,
    pub grant_ref: String,
    pub authority_revision: u64,
    /// PATE verdict (`allow` | `deny` | `hitl` | …).
    pub pate_verdict: String,
    pub execution_state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    pub issued_at_ms: i64,
}
