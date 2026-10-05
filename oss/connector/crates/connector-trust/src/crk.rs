//! Cognitive Range Kernel (CRK) / RangeGuard contracts.
//!
//! Owns: MEMORY → WHAT MAY INFLUENCE THIS MOMENT.
//! Does **not** authorize world effects (PATE / WorldGrant remain PDP).
//! Distinct from SVF `ContextManifest` (disclosure fragments).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Schemas ──────────────────────────────────────────────────────────────────

pub const MEMORY_ENVELOPE_SCHEMA: &str = "connector.crk.memory_envelope.v1";
pub const STATE_CLAIM_SCHEMA: &str = "connector.crk.state_claim.v1";
pub const PROCEDURE_CAPSULE_SCHEMA: &str = "connector.crk.procedure_capsule.v1";
pub const MEMORY_RELATION_SCHEMA: &str = "connector.crk.memory_relation.v1";
pub const MOMENT_RANGE_SCHEMA: &str = "connector.crk.moment_range.v1";
pub const INFLUENCE_MANIFEST_SCHEMA: &str = "connector.crk.influence_manifest.v1";
pub const MEMORY_COMMIT_SCHEMA: &str = "connector.crk.memory_commit.v1";
pub const CONTEXT_FRAME_SCHEMA: &str = "connector.crk.context_frame.v1";
pub const CONTEXT_TRANSFER_SCHEMA: &str = "connector.crk.context_transfer.v1";
pub const RECALL_SESSION_SCHEMA: &str = "connector.crk.recall_session.v1";
pub const ACTION_CUE_SCHEMA: &str = "connector.crk.action_cue.v1";
pub const MEMORY_SEQUENCE_DNA_SCHEMA: &str = "connector.crk.memory_sequence_dna.v1";
pub const MEMORY_SEQUENCE_DNA_LEN: usize = 7;

/// Memory node kind stamp — **type matters** in activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDnaType {
    State,
    Procedure,
    Evidence,
    Relation,
    Conflict,
    OpenWork,
    Index,
}

impl MemoryDnaType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Procedure => "procedure",
            Self::Evidence => "evidence",
            Self::Relation => "relation",
            Self::Conflict => "conflict",
            Self::OpenWork => "open_work",
            Self::Index => "index",
        }
    }

    /// Cover priority (lower = hotter / must-include first).
    pub fn cover_priority(self) -> u8 {
        match self {
            Self::Procedure => 0,
            Self::State => 1,
            Self::Conflict => 2,
            Self::OpenWork => 3,
            Self::Evidence => 4,
            Self::Relation => 5,
            Self::Index => 6,
        }
    }
}

/// Seven-slot sequencing stamp for memory nodes (parallel to AgentPacketDnaV1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemorySequenceDnaV1 {
    pub schema: String,
    /// 1 — agent identity scope
    pub agent_dna: String,
    /// 2 — type stamp
    pub type_dna: MemoryDnaType,
    /// 3 — content address
    pub cid: String,
    /// 4 — canonical payload digest
    pub data_digest: String,
    /// 5 — cue/binding sequence (action/skill/params)
    pub var_digest: String,
    /// 6 — projection / pagination locus
    pub index_key: String,
    /// 7 — sealed MemoryCommit root
    pub auth_root: String,
    /// Canonical digest over the seven slots
    pub sequence_digest: String,
}

impl MemorySequenceDnaV1 {
    pub fn mint(
        agent_dna: impl Into<String>,
        type_dna: MemoryDnaType,
        cid: impl Into<String>,
        data_digest: impl Into<String>,
        var_digest: impl Into<String>,
        index_key: impl Into<String>,
        auth_root: impl Into<String>,
    ) -> Self {
        let mut dna = Self {
            schema: MEMORY_SEQUENCE_DNA_SCHEMA.into(),
            agent_dna: agent_dna.into(),
            type_dna,
            cid: cid.into(),
            data_digest: data_digest.into(),
            var_digest: var_digest.into(),
            index_key: index_key.into(),
            auth_root: auth_root.into(),
            sequence_digest: String::new(),
        };
        dna.sequence_digest = dna.compute_digest();
        dna
    }

    pub fn compute_digest(&self) -> String {
        let material = serde_json::json!({
            "agent_dna": self.agent_dna,
            "type_dna": self.type_dna.as_str(),
            "cid": self.cid,
            "data_digest": self.data_digest,
            "var_digest": self.var_digest,
            "index_key": self.index_key,
            "auth_root": self.auth_root,
        });
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&material).unwrap_or_default())
        )
    }

    pub fn verify_digest(&self) -> bool {
        self.sequence_digest == self.compute_digest()
    }

    pub fn as_seven(&self) -> [&str; MEMORY_SEQUENCE_DNA_LEN] {
        [
            self.agent_dna.as_str(),
            self.type_dna.as_str(),
            self.cid.as_str(),
            self.data_digest.as_str(),
            self.var_digest.as_str(),
            self.index_key.as_str(),
            self.auth_root.as_str(),
        ]
    }
}

// ── Trust lattice (origin/authority — parallel to EpistemicClass E0–E4) ───────

/// Origin/authority trust floor. Transform may **lower**, never raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// T0 — External / untrusted (web, user text, unproven tool)
    T0External,
    /// T1 — Observed (sensor/tool raw, not verified)
    T1Observed,
    /// T2 — Source-bound (signed / namespace-scoped source)
    T2SourceBound,
    /// T3 — Environment/tool verified (Admit + receipt)
    T3EnvVerified,
    /// T4 — Operator/contract verified
    T4OperatorVerified,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::T0External => "T0_external",
            Self::T1Observed => "T1_observed",
            Self::T2SourceBound => "T2_source_bound",
            Self::T3EnvVerified => "T3_env_verified",
            Self::T4OperatorVerified => "T4_operator_verified",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::T0External => 0,
            Self::T1Observed => 1,
            Self::T2SourceBound => 2,
            Self::T3EnvVerified => 3,
            Self::T4OperatorVerified => 4,
        }
    }

    /// Transformation may reduce authority, never increase.
    pub fn attenuate(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }

    /// True if `derived` illegally raised trust above `parent`.
    pub fn promotion_violation(parent: Self, derived: Self) -> bool {
        derived.rank() > parent.rank()
    }
}

// ── CRK readiness (never Allow/Deny) ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrkState {
    Ready,
    Ambiguous,
    Stale,
    Untrusted,
    Insufficient,
}

impl CrkState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Ambiguous => "AMBIGUOUS",
            Self::Stale => "STALE",
            Self::Untrusted => "UNTRUSTED",
            Self::Insufficient => "INSUFFICIENT",
        }
    }
}

// ── Memory envelope (non-removable) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryEnvelope {
    pub schema: String,
    pub cid: String,
    pub agent_pid: String,
    pub origin: String,
    pub origin_authority: TrustTier,
    pub created_at_ms: i64,
    pub observed_at_ms: i64,
    pub verification_state: String,
    #[serde(default)]
    pub evidence_cids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_ms: Option<i64>,
    pub lineage_digest: String,
}

impl MemoryEnvelope {
    pub fn digest(&self) -> String {
        let material = serde_json::json!({
            "cid": self.cid,
            "agent_pid": self.agent_pid,
            "origin": self.origin,
            "origin_authority": self.origin_authority,
            "created_at_ms": self.created_at_ms,
            "observed_at_ms": self.observed_at_ms,
            "verification_state": self.verification_state,
            "evidence_cids": self.evidence_cids,
            "world_scope": self.world_scope,
            "skill_scope": self.skill_scope,
            "valid_from_ms": self.valid_from_ms,
            "valid_until_ms": self.valid_until_ms,
        });
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&material).unwrap_or_default())
        )
    }
}

// ── State claim (bitemporal) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateClaim {
    pub schema: String,
    pub claim_id: String,
    pub agent_pid: String,
    pub subject: String,
    pub predicate: String,
    pub value: serde_json::Value,
    pub valid_from_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_ms: Option<i64>,
    pub observed_at_ms: i64,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    pub confidence: f32,
    #[serde(default)]
    pub evidence_cids: Vec<String>,
    pub envelope: MemoryEnvelope,
    /// Presently active for cognition when valid_until is None or in the future.
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

impl StateClaim {
    /// Presently eligible for cognition at `at_ms` (requires active + validity window).
    pub fn is_active_at(&self, at_ms: i64) -> bool {
        if !self.active {
            return false;
        }
        self.was_valid_at(at_ms)
    }

    /// Historical truth: validity window only (old claims stay reconstructable).
    pub fn was_valid_at(&self, at_ms: i64) -> bool {
        if at_ms < self.valid_from_ms {
            return false;
        }
        match self.valid_until_ms {
            Some(until) => at_ms < until,
            None => true,
        }
    }
}

// ── Procedure capsule ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcedureStep {
    pub step_id: String,
    pub kind: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_or_capability: Option<String>,
    #[serde(default)]
    pub required_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedProcedureCapsule {
    pub schema: String,
    pub procedure_id: String,
    pub skill_id: String,
    pub procedure_version: String,
    pub agent_pid: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub steps: Vec<ProcedureStep>,
    #[serde(default)]
    pub required_evidence: Vec<String>,
    #[serde(default)]
    pub verification_points: Vec<String>,
    #[serde(default)]
    pub exit_conditions: Vec<String>,
    pub provenance: String,
    #[serde(default)]
    pub successful_runs: u64,
    #[serde(default)]
    pub failure_modes: Vec<String>,
    pub envelope: MemoryEnvelope,
}

// ── Memory relation ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRelationKind {
    Next,
    Requires,
    Refines,
    Forbids,
    Derives,
    Conflicts,
    Supersedes,
    Causal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryRelation {
    pub schema: String,
    pub relation_id: String,
    pub agent_pid: String,
    pub from_cid: String,
    pub to_cid: String,
    pub kind: MemoryRelationKind,
    #[serde(default)]
    pub weight: f64,
    pub envelope: MemoryEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_type: Option<MemoryDnaType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_type: Option<MemoryDnaType>,
}

/// Whether relation kind may connect these endpoint types (activation gate).
pub fn relation_type_pairing_ok(
    kind: MemoryRelationKind,
    from: MemoryDnaType,
    to: MemoryDnaType,
) -> bool {
    use MemoryDnaType::*;
    use MemoryRelationKind::*;
    match kind {
        Requires => matches!(
            (from, to),
            (Procedure, State)
                | (Procedure, Evidence)
                | (State, Evidence)
                | (OpenWork, State)
                | (OpenWork, Procedure)
        ),
        Next => {
            matches!(
                (from, to),
                (Procedure, Procedure) | (State, State) | (OpenWork, OpenWork)
            )
        }
        Causal | Derives | Refines => {
            from != Index && to != Index && from != Conflict && to != Conflict
        }
        Conflicts | Forbids => matches!((from, to), (State, State) | (Evidence, Evidence)),
        Supersedes => matches!((from, to), (State, State) | (Procedure, Procedure)),
    }
}

// ── Action cue + MomentRange ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionCueEnvelope {
    pub schema: String,
    pub agent_pid: String,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_skill: Option<String>,
    pub phase: String,
    pub action_digest: String,
    #[serde(default)]
    pub risk: String,
    pub token_budget: u64,
    #[serde(default)]
    pub max_range_cover: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MomentRange {
    pub schema: String,
    pub moment_range_id: String,
    pub agent_pid: String,
    pub action_digest: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_skill: Option<String>,
    pub context_cids: Vec<String>,
    pub range_generation: u64,
    pub token_budget: u64,
    pub state: CrkState,
    #[serde(default)]
    pub unresolved_conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_id: Option<String>,
    pub created_at_ms: i64,
}

// ── Context frame (usable form) ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFrameKind {
    State,
    Procedure,
    Evidence,
    Conflict,
    OpenWork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderPolicy {
    Full,
    Compact,
    Reference,
    Omit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextFrame {
    pub schema: String,
    pub frame_id: String,
    pub kind: ContextFrameKind,
    pub canonical_cids: Vec<String>,
    pub content_digest: String,
    pub provenance_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_at_ms: Option<i64>,
    pub trust_floor: TrustTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_scope: Option<String>,
    pub priority: u32,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    pub token_cost: u32,
    pub machine_payload: serde_json::Value,
    pub render_policy: RenderPolicy,
}

// ── Influence manifest (≠ SVF ContextManifest) ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InfluenceManifest {
    pub schema: String,
    pub manifest_id: String,
    pub agent_pid: String,
    pub generation: u64,
    pub action_digest: String,
    pub moment_range_id: String,
    pub hot_cids: Vec<String>,
    pub cold_index_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_version: Option<String>,
    #[serde(default)]
    pub state_claim_ids: Vec<String>,
    #[serde(default)]
    pub excluded_conflicts: Vec<String>,
    pub provenance_root: String,
    pub temporal_snapshot_ms: i64,
    pub selector_version: String,
    pub range_contract_hash: String,
    /// Honesty: proves selection + exposure binding, not internal model causality.
    pub honesty: String,
}

impl Default for InfluenceManifest {
    fn default() -> Self {
        Self {
            schema: INFLUENCE_MANIFEST_SCHEMA.into(),
            manifest_id: String::new(),
            agent_pid: String::new(),
            generation: 0,
            action_digest: String::new(),
            moment_range_id: String::new(),
            hot_cids: Vec::new(),
            cold_index_digest: String::new(),
            procedure_id: None,
            procedure_version: None,
            state_claim_ids: Vec::new(),
            excluded_conflicts: Vec::new(),
            provenance_root: String::new(),
            temporal_snapshot_ms: 0,
            selector_version: "crk.selector.v1".into(),
            range_contract_hash: String::new(),
            honesty: "exposure_and_influence_bound — not mechanistic model causality".into(),
        }
    }
}

// ── Memory commit (atomic visibility) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryCommit {
    pub schema: String,
    pub commit_id: String,
    pub agent_pid: String,
    pub authoritative_packet_cids: Vec<String>,
    #[serde(default)]
    pub envelope_cids: Vec<String>,
    #[serde(default)]
    pub claim_cids: Vec<String>,
    #[serde(default)]
    pub relation_cids: Vec<String>,
    #[serde(default)]
    pub affected_projection_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_previous_root: Option<String>,
    pub resulting_root: String,
    pub source_support_digest: String,
    pub committed_at_ms: i64,
    /// When false, commit must not become visible to readers.
    pub sealed: bool,
}

// ── Context transfer envelope (broker binding) ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextTransferEnvelope {
    pub schema: String,
    pub transfer_id: String,
    pub tenant_id: String,
    pub agent_pid: String,
    pub broker_generation: u64,
    pub identity_generation: u64,
    pub memory_root: String,
    pub read_set_epoch: u64,
    pub moment_range_id: String,
    pub influence_manifest_cid: String,
    pub ordered_frame_ids: Vec<String>,
    pub ordered_frame_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_id: Option<String>,
    pub exact_render_digest: String,
    pub renderer_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    pub declared_token_count: u64,
    pub provider_token_limit: u64,
    pub truncation_policy: String,
    pub expires_at_ms: i64,
}

impl ContextTransferEnvelope {
    pub fn transfer_digest(&self) -> String {
        let material = serde_json::json!({
            "transfer_id": self.transfer_id,
            "agent_pid": self.agent_pid,
            "broker_generation": self.broker_generation,
            "memory_root": self.memory_root,
            "moment_range_id": self.moment_range_id,
            "influence_manifest_cid": self.influence_manifest_cid,
            "ordered_frame_digests": self.ordered_frame_digests,
            "exact_render_digest": self.exact_render_digest,
            "renderer_version": self.renderer_version,
        });
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&material).unwrap_or_default())
        )
    }
}

// ── Continuity rollup (not recursive summaries) ──────────────────────────────

pub const CONTINUITY_ROLLUP_SCHEMA: &str = "connector.crk.continuity_rollup.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContinuityRollup {
    pub schema: String,
    pub agent_pid: String,
    pub memory_root: String,
    #[serde(default)]
    pub current_claim_ids: Vec<String>,
    #[serde(default)]
    pub procedure_ids: Vec<String>,
    #[serde(default)]
    pub open_work_cids: Vec<String>,
    pub cold_evidence_digest: String,
    pub trust_floor: TrustTier,
    pub rolled_at_ms: i64,
    pub honesty: String,
}

// ── Recall session ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecallSession {
    pub schema: String,
    pub session_id: String,
    pub agent_pid: String,
    pub cue_digest: String,
    pub pinned_memory_root: String,
    pub pinned_read_set_epoch: u64,
    #[serde(default)]
    pub query_plan: Vec<String>,
    #[serde(default)]
    pub visited_node_ids: Vec<String>,
    #[serde(default)]
    pub candidate_cids: Vec<String>,
    #[serde(default)]
    pub exclusion_reasons: Vec<String>,
    pub remaining_budget: u64,
    pub round: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_never_promotes() {
        assert!(TrustTier::promotion_violation(
            TrustTier::T0External,
            TrustTier::T3EnvVerified
        ));
        assert!(!TrustTier::promotion_violation(
            TrustTier::T3EnvVerified,
            TrustTier::T1Observed
        ));
        assert_eq!(
            TrustTier::T3EnvVerified.attenuate(TrustTier::T0External),
            TrustTier::T0External
        );
        assert_eq!(
            TrustTier::T1Observed.attenuate(TrustTier::T4OperatorVerified),
            TrustTier::T1Observed
        );
    }

    #[test]
    fn state_claim_active_window() {
        let env = MemoryEnvelope {
            schema: MEMORY_ENVELOPE_SCHEMA.into(),
            cid: "c1".into(),
            agent_pid: "a".into(),
            origin: "tool".into(),
            origin_authority: TrustTier::T3EnvVerified,
            created_at_ms: 1000,
            observed_at_ms: 1000,
            verification_state: "verified".into(),
            evidence_cids: vec![],
            world_scope: None,
            skill_scope: None,
            valid_from_ms: Some(1000),
            valid_until_ms: Some(2000),
            lineage_digest: "ld".into(),
        };
        let claim = StateClaim {
            schema: STATE_CLAIM_SCHEMA.into(),
            claim_id: "cl1".into(),
            agent_pid: "a".into(),
            subject: "account".into(),
            predicate: "status".into(),
            value: serde_json::json!("active"),
            valid_from_ms: 1000,
            valid_until_ms: Some(2000),
            observed_at_ms: 1000,
            source: "tool".into(),
            supersedes: None,
            confidence: 0.9,
            evidence_cids: vec![],
            envelope: env,
            active: true,
        };
        assert!(claim.is_active_at(1500));
        assert!(!claim.is_active_at(2000));
        assert!(!claim.is_active_at(500));
        let mut historical = claim.clone();
        historical.active = false;
        assert!(!historical.is_active_at(1500));
        assert!(historical.was_valid_at(1500));
        assert!(!historical.was_valid_at(2000));
    }

    #[test]
    fn crk_state_never_allow() {
        // Compile-time documentation: CrkState has no Allow variant.
        let s = CrkState::Ready;
        assert_eq!(s.as_str(), "READY");
        assert_ne!(s.as_str(), "ALLOW");
    }
}
