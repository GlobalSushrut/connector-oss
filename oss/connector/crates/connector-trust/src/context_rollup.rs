//! Context Rollup System — fade states, proof levels, tombstones, rollups.
//! Docs: platform/docs/arch/CONNECTOR_CONTEXT_ROLLUP.md
//!
//! Core principle: **Fade information, never fade consequence.**

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FADE_STATE_SCHEMA: &str = "connector.fade_state.v1";
pub const PROOF_LEVEL_SCHEMA: &str = "connector.proof_level.v1";
pub const FADE_LOCK_SCHEMA: &str = "connector.fade_lock.v1";
pub const FADE_POLICY_SCHEMA: &str = "connector.fade_policy.v1";
pub const EVIDENCE_TOMBSTONE_SCHEMA: &str = "connector.evidence_tombstone.v1";
pub const CONTEXT_ROLLUP_SCHEMA: &str = "connector.context_rollup.v1";
pub const CAUSAL_SKELETON_SCHEMA: &str = "connector.causal_memory_skeleton.v1";
pub const DECISION_ROLLUP_SCHEMA: &str = "connector.decision_rollup.v1";
pub const SESSION_ROLLUP_SCHEMA: &str = "connector.session_rollup.v1";
pub const DAILY_ROLLUP_SCHEMA: &str = "connector.daily_agent_rollup.v1";
pub const ROLLUP_BUDGET_SCHEMA: &str = "connector.agent_rollup_budget.v1";
pub const ROLLUP_METRICS_SCHEMA: &str = "connector.rollup_metrics.v1";

/// Four evidence fading states (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FadeState {
    /// F0 — complete raw source retained
    F0Full,
    /// F1 — distilled excerpts + hashes
    F1Distilled,
    /// F2 — decision-level memory only
    F2Decision,
    /// F3 — causal skeleton + tombstone
    F3Skeleton,
}

impl FadeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::F0Full => "F0_full",
            Self::F1Distilled => "F1_distilled",
            Self::F2Decision => "F2_decision",
            Self::F3Skeleton => "F3_skeleton",
        }
    }

    pub fn next(self) -> Option<Self> {
        match self {
            Self::F0Full => Some(Self::F1Distilled),
            Self::F1Distilled => Some(Self::F2Decision),
            Self::F2Decision => Some(Self::F3Skeleton),
            Self::F3Skeleton => None,
        }
    }
}

/// Proof resolution levels for TraceTramp (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLevel {
    /// P0 — raw source reconstructable
    P0Full,
    /// P1 — distilled excerpts available
    P1Distilled,
    /// P2 — DecisionMemory + MomentProof
    P2Contextual,
    /// P3 — hash + tombstone commitment only
    P3Commitment,
}

impl ProofLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P0Full => "P0_full",
            Self::P1Distilled => "P1_distilled",
            Self::P2Contextual => "P2_contextual",
            Self::P3Commitment => "P3_commitment",
        }
    }

    pub fn tracetramp_symbol(self) -> &'static str {
        match self {
            Self::P0Full => "●",
            Self::P1Distilled => "◉",
            Self::P2Contextual => "○",
            Self::P3Commitment => "·",
        }
    }

    pub fn for_fade_state(state: FadeState) -> Self {
        match state {
            FadeState::F0Full => Self::P0Full,
            FadeState::F1Distilled => Self::P1Distilled,
            FadeState::F2Decision => Self::P2Contextual,
            FadeState::F3Skeleton => Self::P3Commitment,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FadeLock {
    pub schema: String,
    pub evidence_id: String,
    pub agent_vid: String,
    pub reason: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub policy_ref: Option<String>,
}

/// Evidence class for scoped retention (§15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Telemetry,
    Research,
    OwnerInstruction,
    FinancialAction,
    Security,
    Default,
}

impl EvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Telemetry => "telemetry",
            Self::Research => "research",
            Self::OwnerInstruction => "owner_instructions",
            Self::FinancialAction => "financial_actions",
            Self::Security => "security",
            Self::Default => "default",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "telemetry" | "status" => Self::Telemetry,
            "research" | "search" | "web" => Self::Research,
            "owner" | "owner_instructions" | "instruction" => Self::OwnerInstruction,
            "financial" | "financial_actions" | "purchase" => Self::FinancialAction,
            "security" | "incident" => Self::Security,
            _ => Self::Default,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FadePolicy {
    pub schema: String,
    pub policy_id: String,
    /// Age in ms before F0→F1 for low-risk data
    pub f0_to_f1_ms: i64,
    pub f1_to_f2_ms: i64,
    pub f2_to_f3_ms: i64,
    /// Consequence multiplier (higher = slower fade)
    pub consequence_slow_factor: f32,
    /// Optional scope: agent | tenant | namespace | evidence_class
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<EvidenceClass>,
    /// Hard floor — never fade below this proof level
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_proof_level: Option<ProofLevel>,
    /// Regulatory / legal hold — block all fade
    #[serde(default)]
    pub legal_retention: bool,
}

impl Default for FadePolicy {
    fn default() -> Self {
        Self {
            schema: FADE_POLICY_SCHEMA.into(),
            policy_id: "STANDARD".into(),
            f0_to_f1_ms: 7 * 86_400_000,
            f1_to_f2_ms: 30 * 86_400_000,
            f2_to_f3_ms: 180 * 86_400_000,
            consequence_slow_factor: 2.0,
            scope_kind: None,
            scope_id: None,
            evidence_class: None,
            minimum_proof_level: None,
            legal_retention: false,
        }
    }
}

impl FadePolicy {
    pub fn for_class(class: EvidenceClass) -> Self {
        let day = 86_400_000i64;
        match class {
            EvidenceClass::Telemetry => Self {
                policy_id: "TELEMETRY".into(),
                f0_to_f1_ms: day,
                f1_to_f2_ms: 7 * day,
                f2_to_f3_ms: 7 * day,
                evidence_class: Some(class),
                consequence_slow_factor: 0.5,
                ..Default::default()
            },
            EvidenceClass::Research => Self {
                policy_id: "RESEARCH".into(),
                f0_to_f1_ms: 7 * day,
                f1_to_f2_ms: 30 * day,
                f2_to_f3_ms: 90 * day,
                evidence_class: Some(class),
                ..Default::default()
            },
            EvidenceClass::OwnerInstruction => Self {
                policy_id: "OWNER_INSTRUCTION".into(),
                f0_to_f1_ms: 30 * day,
                f1_to_f2_ms: i64::MAX / 4,
                f2_to_f3_ms: i64::MAX / 4,
                evidence_class: Some(class),
                minimum_proof_level: Some(ProofLevel::P1Distilled),
                consequence_slow_factor: 4.0,
                ..Default::default()
            },
            EvidenceClass::FinancialAction => Self {
                policy_id: "FINANCIAL_7Y".into(),
                f0_to_f1_ms: 7 * 365 * day,
                f1_to_f2_ms: 7 * 365 * day,
                f2_to_f3_ms: 7 * 365 * day,
                evidence_class: Some(class),
                legal_retention: true,
                minimum_proof_level: Some(ProofLevel::P0Full),
                consequence_slow_factor: 10.0,
                ..Default::default()
            },
            EvidenceClass::Security => Self {
                policy_id: "SECURITY".into(),
                f0_to_f1_ms: 180 * day,
                f1_to_f2_ms: 365 * day,
                f2_to_f3_ms: 2 * 365 * day,
                evidence_class: Some(class),
                minimum_proof_level: Some(ProofLevel::P2Contextual),
                consequence_slow_factor: 5.0,
                ..Default::default()
            },
            EvidenceClass::Default => Self::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceTombstone {
    pub schema: String,
    pub evidence_id: String,
    pub agent_vid: String,
    pub original_hash: String,
    pub source_id: String,
    pub event_time_ms: i64,
    pub ingest_time_ms: i64,
    pub original_size_bytes: u64,
    pub fade_time_ms: i64,
    pub fade_policy: String,
    pub previous_proof_level: ProofLevel,
    pub final_proof_level: ProofLevel,
    pub retained_context_refs: Vec<String>,
    pub retained_decision_refs: Vec<String>,
    pub retained_moment_refs: Vec<String>,
    pub deletion_reason: String,
    pub node_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextRollup {
    pub schema: String,
    pub rollup_id: String,
    pub agent_vid: String,
    pub context_range_start_ms: i64,
    pub context_range_end_ms: i64,
    pub source_evidence_root: String,
    pub retained_evidence_root: String,
    pub decision_refs: Vec<String>,
    pub moment_refs: Vec<String>,
    pub action_refs: Vec<String>,
    pub previous_proof_level: ProofLevel,
    pub new_proof_level: ProofLevel,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub fade_policy: String,
    pub faded_objects: Vec<String>,
    pub retained_objects: Vec<String>,
    pub created_at_ms: i64,
    pub node_signature: Option<String>,
}

/// Irreducible causal structure (§8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CausalMemorySkeleton {
    pub schema: String,
    pub skeleton_id: String,
    pub moment_id: String,
    pub agent_vid: String,
    pub before: String,
    pub trigger: String,
    pub authority: String,
    pub material_evidence: Vec<String>,
    pub derivation: Option<String>,
    pub decision: String,
    pub action: String,
    pub outcome: String,
    pub proof_level: ProofLevel,
    pub context_epoch: u64,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionRollup {
    pub schema: String,
    pub decision_id: String,
    pub agent_vid: String,
    pub before_context: String,
    pub trigger: String,
    pub decisive_evidence: Vec<String>,
    pub authority: Option<String>,
    pub reasoning_summary: String,
    pub after_context: String,
    pub action: String,
    pub outcome: String,
    pub corrections: Vec<String>,
    pub moment_ref: Option<String>,
    pub proof_level: ProofLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRollup {
    pub schema: String,
    pub session_id: String,
    pub agent_vid: String,
    pub start_context_root: String,
    pub end_context_root: String,
    pub goals_started: Vec<String>,
    pub goals_completed: Vec<String>,
    pub decisions: Vec<String>,
    pub actions: Vec<String>,
    pub unresolved: Vec<String>,
    pub evidence_root: String,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DailyAgentRollup {
    pub schema: String,
    pub day: String,
    pub agent_vid: String,
    pub worked_on: Vec<String>,
    pub decisions: Vec<String>,
    pub changes: Vec<String>,
    pub commitments: Vec<String>,
    pub external_actions: Vec<String>,
    pub failures: Vec<String>,
    pub unresolved: Vec<String>,
    pub key_moments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentRollupBudget {
    pub schema: String,
    pub agent_vid: String,
    pub hot_memory_max_bytes: u64,
    pub warm_memory_max_bytes: u64,
    pub full_evidence_budget_bytes: u64,
    pub distilled_evidence_budget_bytes: u64,
    pub minimum_proof_level: ProofLevel,
    pub checkpoint_interval_ms: i64,
    pub storage_pressure_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RollupMetrics {
    pub schema: String,
    pub agent_vid: String,
    pub raw_bytes: u64,
    pub distilled_bytes: u64,
    pub decision_bytes: u64,
    pub skeleton_bytes: u64,
    pub bytes_faded_total: u64,
    pub bytes_preserved_by_lock: u64,
    pub f0_count: u64,
    pub f1_count: u64,
    pub f2_count: u64,
    pub f3_count: u64,
    pub p0_moments: u64,
    pub p1_moments: u64,
    pub p2_moments: u64,
    pub p3_moments: u64,
    pub rehydration_count: u64,
    pub fade_denied_count: u64,
    pub health: String,
}

impl RollupMetrics {
    pub fn new(agent_vid: &str) -> Self {
        Self {
            schema: ROLLUP_METRICS_SCHEMA.into(),
            agent_vid: agent_vid.into(),
            health: "HEALTHY".into(),
            ..Default::default()
        }
    }
}

/// TraceTramp-facing rollup explain payload (§65).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RollupExplain {
    pub schema: String,
    pub evidence_id: String,
    pub fade_state: FadeState,
    pub proof_level: ProofLevel,
    pub fade_score: f32,
    pub fade_eligible: bool,
    pub fade_denied_reason: Option<String>,
    pub causal_ref_count: u64,
    pub decision_ref_count: u64,
    pub tracetramp_display: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fade_state_progression() {
        assert_eq!(FadeState::F0Full.next(), Some(FadeState::F1Distilled));
        assert_eq!(FadeState::F3Skeleton.next(), None);
    }

    #[test]
    fn proof_level_for_fade_state() {
        assert_eq!(
            ProofLevel::for_fade_state(FadeState::F2Decision),
            ProofLevel::P2Contextual
        );
    }
}
