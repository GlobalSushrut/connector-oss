//! Production agent memory contracts — MEMORY / EVIDENCE / FORENSICS separation.
//! Docs: platform/docs/arch/CONNECTOR_AGENT_MEMORY.md

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context_rollup::{FadeState, ProofLevel};

pub const AGENT_MEMORY_SCHEMA: &str = "connector.agent_memory.v1";
pub const EVIDENCE_RECORD_SCHEMA: &str = "connector.evidence_record.v1";
pub const AMC_SCHEMA: &str = "connector.agent_memory_capsule.v1";
pub const DECISION_MEMORY_SCHEMA: &str = "connector.decision_memory.v1";
pub const MOMENT_PROOF_SCHEMA: &str = "connector.moment_proof.v1";
pub const CONTEXT_TRANSITION_SCHEMA: &str = "connector.context_transition.v1";
pub const CHECKPOINT_SCHEMA: &str = "connector.context_checkpoint.v1";
pub const CONTEXT_DELTA_SCHEMA: &str = "connector.context_delta.v1";
pub const MEMORY_POINT_SCHEMA: &str = "connector.memory_point.v1";

/// Five epistemic classes (E0–E4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicClass {
    Authoritative,
    Observed,
    Derived,
    Inferred,
    Predicted,
}

impl EpistemicClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "E0_authoritative",
            Self::Observed => "E1_observed",
            Self::Derived => "E2_derived",
            Self::Inferred => "E3_inferred",
            Self::Predicted => "E4_predicted",
        }
    }
}

/// 40-byte transport reference to committed context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextReference {
    pub context_root: String,
    pub epoch: u64,
}

impl ContextReference {
    pub fn digest_hex(content: &[u8]) -> String {
        format!("{:x}", Sha256::digest(content))
    }
}

/// Append-only cold evidence index entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub schema: String,
    pub evidence_id: String,
    pub source_id: String,
    pub agent_vid: String,
    pub event_time_ms: i64,
    pub ingest_time_ms: i64,
    pub content_hash: String,
    pub schema_hash: String,
    pub previous_event_hash: Option<String>,
    pub raw_location: String,
    pub epistemic_class: EpistemicClass,
    pub signature_status: String,
    #[serde(default = "default_fade_state")]
    pub fade_state: FadeState,
    #[serde(default = "default_proof_level")]
    pub proof_level: ProofLevel,
    #[serde(default)]
    pub bytes: u64,
}

fn default_fade_state() -> FadeState {
    FadeState::F0Full
}

fn default_proof_level() -> ProofLevel {
    ProofLevel::P0Full
}

/// Hot runtime capsule (8–64 KB target).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentMemoryCapsule {
    pub schema: String,
    pub agent_vid: String,
    pub execution_epoch: u64,
    pub context_epoch: u64,
    pub memory_root: String,
    pub authority_root: String,
    pub evidence_root: String,
    pub current_goal: Option<String>,
    pub current_plan: Option<String>,
    pub critical_facts: Vec<String>,
    pub commitments: Vec<String>,
    pub unresolved: Vec<String>,
    pub recent_decisions: Vec<String>,
    pub recent_actions: Vec<String>,
    pub entropy: f32,
    pub volatility: f32,
    pub confidence: f32,
    pub autonomous_radius: f32,
    pub previous_capsule_root: Option<String>,
    pub context_ref: ContextReference,
}

/// Decision memory — store decisions, not transcripts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionMemory {
    pub schema: String,
    pub decision_id: String,
    pub subject: String,
    pub before_state: String,
    pub trigger: String,
    pub after_state: String,
    pub reason: String,
    pub authority_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub confidence: f32,
    pub consequence: String,
    pub context_epoch: u64,
    pub epistemic_class: EpistemicClass,
}

/// 3D context matrix point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryPoint {
    pub schema: String,
    pub point_id: String,
    pub time_ms: i64,
    pub entity: String,
    pub consequence: String,
    pub state: String,
    pub confidence: f32,
    pub entropy: f32,
    pub volatility: f32,
    pub evidence_ref: String,
    pub context_epoch: u64,
    pub epistemic_class: EpistemicClass,
    #[serde(default = "default_proof_level")]
    pub proof_level: ProofLevel,
    #[serde(default = "default_fade_state")]
    pub fade_state: FadeState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextDelta {
    pub schema: String,
    pub delta_id: String,
    pub agent_vid: String,
    pub seq: u64,
    pub path: String,
    pub before: Option<String>,
    pub after: String,
    pub context_epoch: u64,
    pub at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextCheckpoint {
    pub schema: String,
    pub checkpoint_id: String,
    pub agent_vid: String,
    pub execution_id: String,
    pub epoch: u64,
    pub context_root: String,
    pub evidence_root: String,
    pub policy_root: String,
    pub authority_root: String,
    pub previous_checkpoint: Option<String>,
    pub timestamp_ms: i64,
    pub node_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextTransition {
    pub schema: String,
    pub transition_id: String,
    pub agent_vid: String,
    pub previous_context_root: String,
    pub evidence_delta_root: String,
    pub owner_delta_root: String,
    pub world_delta_root: String,
    pub agent_delta_root: String,
    pub reducer_version: String,
    pub policy_version: String,
    pub next_context_root: String,
    pub timestamp_ms: i64,
    pub node_signature: Option<String>,
}

/// Forensic entry point (1–4 KB target).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MomentProof {
    pub schema: String,
    pub moment_id: String,
    pub timestamp_ms: i64,
    pub agent_vid: String,
    pub execution_id: String,
    pub previous_context_root: String,
    pub current_context_root: String,
    pub authority_root: String,
    pub owner_context_root: String,
    pub agent_self_root: String,
    pub world_root: String,
    pub policy_root: String,
    pub evidence_root: String,
    pub trigger: String,
    pub proposed_action: String,
    pub connector_decision: String,
    pub actual_effect: String,
    pub transition_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub epistemic_summary: Value,
    pub node_signature: Option<String>,
    #[serde(default = "default_proof_level")]
    pub proof_level_at_creation: ProofLevel,
    #[serde(default = "default_proof_level")]
    pub current_proof_level: ProofLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skeleton_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTierTarget {
    EvidenceOnly,
    Warm,
    Hot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_ref_roundtrip() {
        let r = ContextReference {
            context_root: "abc".into(),
            epoch: 91882,
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: ContextReference = serde_json::from_str(&j).unwrap();
        assert_eq!(back.epoch, 91882);
    }
}
