//! Semantic Virtualization Fabric (SVF) contracts — projection + disclosure, not authority.
//! Docs: platform/docs/arch/CONNECTOR_SVF.md
//!
//! Honesty: these types do **not** replace PATE, WorldGrant, DIM, ARC, or AffordanceEnvelope.
//! SVF requests views and destination-bound release; PDP remains ActionBinding + NF³ + PATE.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SVF_SCHEMA: &str = "connector.svf.v1";
pub const AGENTIC_OBJECT_SCHEMA: &str = "connector.svf.agentic_object.v1";
pub const SEMANTIC_HANDLE_SCHEMA: &str = "connector.svf.semantic_handle.v1";
pub const CONTEXT_MANIFEST_SCHEMA: &str = "connector.svf.context_manifest.v1";
pub const PROJECTION_SCHEMA: &str = "connector.svf.projection.v1";
pub const DISCLOSURE_GRANT_SCHEMA: &str = "connector.svf.disclosure_grant.v1";
pub const DISCLOSURE_RECEIPT_SCHEMA: &str = "connector.svf.disclosure_receipt.v1";
pub const SEMANTIC_CONTRACT_SCHEMA: &str = "connector.svf.semantic_contract.v1";
pub const RESOLVE_REQUEST_SCHEMA: &str = "connector.svf.resolve_request.v1";
pub const RESOLVE_RESULT_SCHEMA: &str = "connector.svf.resolve_result.v1";
pub const MATERIALIZATION_REQUEST_SCHEMA: &str = "connector.svf.materialization_request.v1";
pub const EFFECT_RECEIPT_SCHEMA: &str = "connector.svf.effect_receipt.v1";
pub const DERIVED_KNOWLEDGE_SCHEMA: &str = "connector.svf.derived_knowledge.v1";
pub const SVF_EPOCH_SCHEMA: &str = "connector.svf.epoch.v1";
pub const TASK_REQUEST_ENVELOPE_SCHEMA: &str = "connector.svf.task_request_envelope.v1";
pub const BROKER_DECISION_SCHEMA: &str = "connector.svf.broker_decision.v1";
pub const OBSERVATION_REMASK_SCHEMA: &str = "connector.svf.observation_remask.v1";

/// Progressive disclosure levels S0–S5 (minimum sufficient view).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureLevel {
    /// S0 — existence / type stub only
    S0Stub,
    /// S1 — safe labels / non-sensitive fields
    S1Labels,
    /// S2 — structured schema without secrets
    S2Schema,
    /// S3 — purpose-bound partial values
    S3Partial,
    /// S4 — full logical content (still no standing credentials)
    S4FullLogical,
    /// S5 — materialize-bound (CDP / action-broker only; never model plane)
    S5Materialize,
}

impl DisclosureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S0Stub => "S0_stub",
            Self::S1Labels => "S1_labels",
            Self::S2Schema => "S2_schema",
            Self::S3Partial => "S3_partial",
            Self::S4FullLogical => "S4_full_logical",
            Self::S5Materialize => "S5_materialize",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::S0Stub => 0,
            Self::S1Labels => 1,
            Self::S2Schema => 2,
            Self::S3Partial => 3,
            Self::S4FullLogical => 4,
            Self::S5Materialize => 5,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "s0" | "s0_stub" | "stub" => Some(Self::S0Stub),
            "s1" | "s1_labels" | "labels" => Some(Self::S1Labels),
            "s2" | "s2_schema" | "schema" => Some(Self::S2Schema),
            "s3" | "s3_partial" | "partial" => Some(Self::S3Partial),
            "s4" | "s4_full_logical" | "full" | "full_logical" => Some(Self::S4FullLogical),
            "s5" | "s5_materialize" | "materialize" => Some(Self::S5Materialize),
            _ => None,
        }
    }

    /// Levels at or above this require a purpose string + AutonomyGateway.
    pub fn requires_purpose(self) -> bool {
        self.rank() >= Self::S2Schema.rank()
    }

    /// S5 is CDP-only — never released onto the model plane via EXPAND.
    pub fn model_plane_forbidden(self) -> bool {
        matches!(self, Self::S5Materialize)
    }
}

/// How CDP injects secrets after Admit (never into guest env as standing keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializeMode {
    /// Connector/MCP bridge holds the secret and performs the action.
    ActionBroker,
    /// Short-TTL proxy credential minted for one admitted effect.
    EphemeralProxyToken,
}

/// Structured broker / SVF decision for DAL recoverability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerDecisionCode {
    Allow,
    Ask,
    Block,
    Redo,
    Quarantine,
    ExpandDenied,
    WorldGrantDenied,
    EpochMismatch,
    ResidualSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SvfEpoch {
    pub schema: String,
    pub broker_epoch: u64,
    pub iac_epoch: u64,
    pub policy_epoch: u64,
}

impl SvfEpoch {
    pub fn new(broker_epoch: u64, iac_epoch: u64, policy_epoch: u64) -> Self {
        Self {
            schema: SVF_EPOCH_SCHEMA.to_string(),
            broker_epoch,
            iac_epoch,
            policy_epoch,
        }
    }
}

/// Semantic identity — not a grant, not a WorldGrant pore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticHandle {
    pub schema: String,
    /// Dual-format: `{{obj:type.id}}` and/or opaque `⟦conn:…⟧`.
    pub handle: String,
    pub object_type: String,
    pub object_id: String,
    pub agent_vid: String,
    pub disclosure_ceiling: DisclosureLevel,
    pub broker_epoch: u64,
}

impl SemanticHandle {
    pub fn format_obj(object_type: &str, object_id: &str) -> String {
        format!("{{{{obj:{object_type}.{object_id}}}}}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextFragment {
    pub fragment_id: String,
    pub class: String,
    pub disclosure_level: DisclosureLevel,
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fade_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextManifest {
    pub schema: String,
    pub object_id: String,
    pub fragments: Vec<ContextFragment>,
}

/// First-class semantic object (VAC/Knot-backed identity).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgenticObject {
    pub schema: String,
    pub object_id: String,
    pub object_type: String,
    pub agent_vid: String,
    pub handle: SemanticHandle,
    pub manifest: ContextManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knot_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_packet_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Projection {
    pub schema: String,
    pub object_id: String,
    pub level: DisclosureLevel,
    pub view_text: String,
    pub broker_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisclosureGrant {
    pub schema: String,
    pub grant_id: String,
    pub object_id: String,
    pub max_level: DisclosureLevel,
    pub purpose: String,
    pub agent_vid: String,
    pub expires_at_ms: Option<i64>,
    pub broker_epoch: u64,
}

/// What was shown / released to which sink — forensic honesty, not court binder alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisclosureReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub agent_vid: String,
    pub object_refs: Vec<String>,
    pub level: DisclosureLevel,
    pub sink: String,
    pub purpose: String,
    pub broker_epoch: u64,
    pub issued_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pate_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticContract {
    pub schema: String,
    pub contract_id: String,
    pub agent_vid: String,
    pub allowed_object_types: Vec<String>,
    pub default_ceiling: DisclosureLevel,
    pub require_purpose_above: DisclosureLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolveRequest {
    pub schema: String,
    pub handle: String,
    pub agent_vid: String,
    pub purpose: String,
    pub broker_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolveResult {
    pub schema: String,
    pub handle: String,
    pub resolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_grant_pore: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaterializationRequest {
    pub schema: String,
    pub handle: String,
    pub agent_vid: String,
    pub mode: MaterializeMode,
    pub pate_task_id: String,
    pub action_digest: String,
    pub sink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub pate_task_id: String,
    pub materialized: bool,
    pub mode: MaterializeMode,
    pub issued_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DerivedKnowledge {
    pub schema: String,
    pub derived_id: String,
    pub agent_vid: String,
    pub source_object_ids: Vec<String>,
    pub claim: String,
    pub epistemic_class: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskRequestEnvelope {
    pub schema: String,
    pub agent_vid: String,
    pub semantic_intent_digest: String,
    pub opaque_args: Value,
    pub purpose: String,
    pub broker_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_refs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrokerDecision {
    pub schema: String,
    pub code: BrokerDecisionCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redo_hints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservationRemaskReport {
    pub schema: String,
    pub agent_vid: String,
    pub tokens_minted: u32,
    pub residual_redacted: bool,
    pub broker_epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_rank_orders() {
        assert!(DisclosureLevel::S0Stub.rank() < DisclosureLevel::S5Materialize.rank());
    }

    #[test]
    fn handle_format() {
        assert_eq!(
            SemanticHandle::format_obj("email", "inbox-1"),
            "{{obj:email.inbox-1}}"
        );
    }
}
