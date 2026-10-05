//! Agent Identity — cryptographic DID anchor, VC chain, expertise records,
//! memory series index, and procedural pattern store.
//!
//! Implements the Layer 1-2 foundations of the Identity Trachea (Section 11
//! of ece_arch.md):
//!   Layer 1 — Memory Series: episodic series index + provenance retention
//!   Layer 2 — Default Identity: AgentDID (Ed25519) + VerifiableCredential chain
//!
//! Research basis:
//!   W3C DID 1.0 (2022), W3C VC 2.0 (2025)
//!   arxiv:2511.02841 "AI Agents with Decentralized Identifiers and VCs"
//!   arxiv:2512.12856 MaRS provenance-closed antimatroid retention

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// AgentDID — Layer 2 Default Identity anchor
// =============================================================================

/// Decentralized Identifier for an agent.
///
/// Format: `did:connector:<agent_pid>:<namespace_root>:<genesis_cid>`
///
/// Properties:
/// - Ledger-anchored via Connector's audit CID chain
/// - Self-sovereign: only the agent's Ed25519 key can update its DID doc
/// - Tamper-evident: any identity modification creates a new genesis_cid
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDID {
    /// Kernel-assigned PID (immutable for agent lifetime)
    pub agent_pid: String,
    /// Agent's home namespace root (e.g. "/k/ehr/allergy")
    pub namespace_root: String,
    /// CID of the AgentControlBlock at registration time
    pub genesis_cid: String,
    /// Ed25519 public key (base64url-encoded)
    pub public_key: String,
    /// Timestamp of DID creation (ms epoch)
    pub created_at: i64,
    /// Timestamp of last DID document update (ms epoch)
    pub updated_at: i64,
}

impl AgentDID {
    /// Construct a new AgentDID at agent registration time.
    pub fn new(agent_pid: String, namespace_root: String, genesis_cid: String, public_key: String, created_at: i64) -> Self {
        Self {
            agent_pid,
            namespace_root,
            genesis_cid,
            public_key,
            created_at,
            updated_at: created_at,
        }
    }

    /// Canonical DID string representation.
    ///
    /// `did:connector:<agent_pid>:<namespace_root_hash>:<genesis_cid>`
    pub fn to_did_string(&self) -> String {
        let ns_slug = self.namespace_root.replace('/', "_").trim_matches('_').to_string();
        format!("did:connector:{}:{}:{}", self.agent_pid, ns_slug, &self.genesis_cid[..16.min(self.genesis_cid.len())])
    }
}

// =============================================================================
// VerifiableCredential — grows with the agent as it earns trust
// =============================================================================

/// Type of verifiable credential issued to an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum VCType {
    /// Issued at registration by the orchestrator
    Genesis,
    /// Issued when a CapabilityGrant is awarded
    Capability,
    /// Issued when KECS exceeds the expertise threshold
    Expertise,
    /// Issued after W clean executions with no probation
    Behavior,
}

/// A single Verifiable Credential in the agent's chain.
///
/// Each VC is signed by a kernel-native source (orchestrator DID, capability
/// registry, TrustComputer) — never by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// VC type
    pub vc_type: VCType,
    /// Subject DID (the agent this VC describes)
    pub subject_did: String,
    /// Issuer DID
    pub issuer_did: String,
    /// Claims as key-value pairs
    pub claims: HashMap<String, serde_json::Value>,
    /// Issue timestamp (ms epoch)
    pub issued_at: i64,
    /// Expiry timestamp (None = no expiry)
    pub expires_at: Option<i64>,
    /// HMAC signature over (subject_did + issuer_did + claims_hash + issued_at)
    /// using the issuer's kernel signing key
    pub signature: String,
    /// CID of the audit entry that triggered this VC issuance
    pub evidence_cid: Option<String>,
}

impl VerifiableCredential {
    /// Create a new VC with the given claims. Signature must be filled in
    /// by the issuing authority before the VC is considered valid.
    pub fn new(
        vc_type: VCType,
        subject_did: String,
        issuer_did: String,
        claims: HashMap<String, serde_json::Value>,
        issued_at: i64,
    ) -> Self {
        Self {
            vc_type,
            subject_did,
            issuer_did,
            claims,
            issued_at,
            expires_at: None,
            signature: String::new(),
            evidence_cid: None,
        }
    }

    /// Returns true if the VC has not expired relative to `now_ms`.
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        match self.expires_at {
            Some(exp) => now_ms <= exp,
            None => true,
        }
    }
}

/// The agent's growing chain of Verifiable Credentials.
///
/// Starts at genesis and accumulates capability, expertise, and behavior VCs
/// as the agent earns trust through verified execution.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VCChain {
    /// Genesis VC (always present after registration)
    pub genesis: Option<VerifiableCredential>,
    /// Capability VCs (one per CapabilityGrant awarded)
    pub capability_vcs: Vec<VerifiableCredential>,
    /// Expertise VCs (one per namespace where KECS ≥ θ_expert)
    pub expertise_vcs: Vec<VerifiableCredential>,
    /// Behavior VCs (issued after W clean execution windows)
    pub behavior_vcs: Vec<VerifiableCredential>,
}

impl VCChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of VCs in the chain (a proxy for "how established" this agent is).
    pub fn len(&self) -> usize {
        self.genesis.is_some() as usize
            + self.capability_vcs.len()
            + self.expertise_vcs.len()
            + self.behavior_vcs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the most recently issued VC type, or None if chain is empty.
    pub fn latest_vc_type(&self) -> Option<VCType> {
        // Check in reverse chronological priority
        if !self.behavior_vcs.is_empty() {
            return Some(VCType::Behavior);
        }
        if !self.expertise_vcs.is_empty() {
            return Some(VCType::Expertise);
        }
        if !self.capability_vcs.is_empty() {
            return Some(VCType::Capability);
        }
        if self.genesis.is_some() {
            return Some(VCType::Genesis);
        }
        None
    }

    /// Add a VC to the appropriate chain slot.
    pub fn add(&mut self, vc: VerifiableCredential) {
        match vc.vc_type {
            VCType::Genesis => self.genesis = Some(vc),
            VCType::Capability => self.capability_vcs.push(vc),
            VCType::Expertise => self.expertise_vcs.push(vc),
            VCType::Behavior => self.behavior_vcs.push(vc),
        }
    }

    /// Collect all active (non-expired) VCs at `now_ms`.
    pub fn active_vcs(&self, now_ms: i64) -> Vec<&VerifiableCredential> {
        let mut out = Vec::new();
        if let Some(ref g) = self.genesis {
            if g.is_valid_at(now_ms) { out.push(g); }
        }
        for vc in &self.capability_vcs {
            if vc.is_valid_at(now_ms) { out.push(vc); }
        }
        for vc in &self.expertise_vcs {
            if vc.is_valid_at(now_ms) { out.push(vc); }
        }
        for vc in &self.behavior_vcs {
            if vc.is_valid_at(now_ms) { out.push(vc); }
        }
        out
    }
}

// =============================================================================
// AgentExpertiseRecord — per-namespace KECS state (Section 10)
// =============================================================================

/// Execution outcome categories for Rényi entropy computation.
///
/// Maps to the 6-class outcome distribution Ω used in KECS S_renyi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Success,
    Failed,
    RolledBack,
    DeniedPolicy,
    DeniedMac,
    Pending,
}

/// Per-namespace expertise record — stores the rolling signals needed to
/// compute the KECS (KnotEngine Confidence Score) for agent A in namespace N.
///
/// Updated on every execution completion and every KnotEngine ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentExpertiseRecord {
    /// Namespace this record applies to
    pub namespace: String,

    // --- KECS component scores (cached, recomputed incrementally) ---
    /// K_vn: Von Neumann graph entropy confidence [0,1]
    pub k_vn: f64,
    /// S_renyi: Rényi-2 execution stability [0,1]
    pub s_renyi: f64,
    /// K_topo: Topological mixing confidence [0,1]
    pub k_topo: f64,
    /// KECS composite score [0,1]
    pub kecs: f64,

    // --- Raw counters for incremental updates ---
    /// Total verified executions (n_exec — the "n" in KECS)
    pub exec_count: u64,
    /// Rolling window of last W=50 outcome counts (indexed by ExecutionOutcome)
    pub outcome_window: HashMap<ExecutionOutcome, u32>,
    /// Window size W (default 50)
    pub window_size: u32,
    /// Historical baseline outcome distribution (full history)
    pub baseline_dist: HashMap<ExecutionOutcome, f64>,
    /// Current KL divergence vs baseline (regression detector)
    pub kl_divergence: f64,

    // --- Probation state ---
    /// Whether agent is in probation for this namespace
    pub in_probation: bool,
    /// Number of consecutive clean windows since probation start
    pub clean_windows_since_probation: u32,

    // --- Timestamps ---
    pub first_exec_at: i64,
    pub last_exec_at: i64,
    pub last_updated_at: i64,
}

impl AgentExpertiseRecord {
    pub fn new(namespace: String, now_ms: i64) -> Self {
        Self {
            namespace,
            k_vn: 0.0,
            s_renyi: 0.0,
            k_topo: 0.0,
            kecs: 0.0,
            exec_count: 0,
            outcome_window: HashMap::new(),
            window_size: 50,
            baseline_dist: HashMap::new(),
            kl_divergence: 0.0,
            in_probation: false,
            clean_windows_since_probation: 0,
            first_exec_at: now_ms,
            last_exec_at: now_ms,
            last_updated_at: now_ms,
        }
    }

    /// Record a new execution outcome in the rolling window.
    pub fn record_outcome(&mut self, outcome: ExecutionOutcome, now_ms: i64) {
        self.exec_count += 1;
        self.last_exec_at = now_ms;
        self.last_updated_at = now_ms;
        *self.outcome_window.entry(outcome.clone()).or_insert(0) += 1;

        // Trim window to W entries (approximate — track total window count)
        let total_in_window: u32 = self.outcome_window.values().sum();
        if total_in_window > self.window_size {
            // Proportionally reduce oldest entries (approximate sliding window)
            let excess = total_in_window - self.window_size;
            let mut remaining = excess;
            for count in self.outcome_window.values_mut() {
                if remaining == 0 { break; }
                let remove = remaining.min(*count);
                *count -= remove;
                remaining -= remove;
            }
            self.outcome_window.retain(|_, v| *v > 0);
        }

        // Update baseline (exponential moving average, α=0.05)
        let alpha = 0.05_f64;
        let total: u32 = self.outcome_window.values().sum();
        if total > 0 {
            let p_current = *self.outcome_window.get(&outcome).unwrap_or(&0) as f64 / total as f64;
            let baseline_entry = self.baseline_dist.entry(outcome).or_insert(p_current);
            *baseline_entry = (1.0 - alpha) * *baseline_entry + alpha * p_current;
        }
    }

    /// Convert current outcome_window to probability distribution.
    pub fn current_outcome_dist(&self) -> HashMap<ExecutionOutcome, f64> {
        let total: u32 = self.outcome_window.values().sum();
        if total == 0 {
            return HashMap::new();
        }
        self.outcome_window.iter()
            .map(|(k, &v)| (k.clone(), v as f64 / total as f64))
            .collect()
    }

    /// KECS as a 0-20 point score for TrustDimensions.
    pub fn kecs_points(&self) -> u32 {
        if self.in_probation {
            return 0;
        }
        (self.kecs * 20.0).round().min(20.0) as u32
    }
}

// =============================================================================
// MemorySeriesIndex — Layer 1 episodic series tracking (Section 11.2)
// =============================================================================

/// Index of the agent's episodic memory series for a namespace.
///
/// Tracks the ordered series of verified execution windows, budget utilization,
/// and the provenance DAG structure for antimatroid retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySeriesIndex {
    /// Namespace this series covers
    pub namespace: String,
    /// Ordered window sequence numbers in the episodic series
    pub window_sns: Vec<u64>,
    /// Number of verified Tool packets in this series (= n_exec for KECS)
    pub verified_packet_count: u64,
    /// Estimated token cost of retained packets
    pub budget_used_tokens: u64,
    /// Configured token budget B
    pub budget_limit_tokens: u64,
    /// Number of episodic packets evicted (consolidated into semantic)
    pub consolidated_count: u64,
    /// Timestamp of first packet in series
    pub series_start_ms: i64,
    /// Timestamp of most recent packet in series
    pub series_end_ms: i64,
}

impl MemorySeriesIndex {
    pub fn new(namespace: String, budget_limit_tokens: u64) -> Self {
        Self {
            namespace,
            window_sns: Vec::new(),
            verified_packet_count: 0,
            budget_used_tokens: 0,
            budget_limit_tokens,
            consolidated_count: 0,
            series_start_ms: 0,
            series_end_ms: 0,
        }
    }

    /// Record a new verified execution window in the series.
    pub fn record_window(&mut self, window_sn: u64, packet_token_cost: u64, ts_ms: i64) {
        if !self.window_sns.contains(&window_sn) {
            self.window_sns.push(window_sn);
        }
        self.verified_packet_count += 1;
        self.budget_used_tokens += packet_token_cost;
        if self.series_start_ms == 0 { self.series_start_ms = ts_ms; }
        self.series_end_ms = ts_ms.max(self.series_end_ms);
    }

    /// Mark packets as consolidated (evicted from episodic series).
    pub fn mark_consolidated(&mut self, count: u64, freed_tokens: u64) {
        self.consolidated_count += count;
        self.budget_used_tokens = self.budget_used_tokens.saturating_sub(freed_tokens);
    }

    /// Budget utilization ratio [0,1].
    pub fn budget_utilization(&self) -> f64 {
        if self.budget_limit_tokens == 0 { return 0.0; }
        (self.budget_used_tokens as f64 / self.budget_limit_tokens as f64).min(1.0)
    }

    /// Time span of the series in milliseconds.
    pub fn time_span_ms(&self) -> i64 {
        (self.series_end_ms - self.series_start_ms).max(0)
    }
}

// =============================================================================
// ProcedureRecord — Layer 1 procedural crystallization (Section 11.2.4)
// =============================================================================

/// A crystallized procedural pattern — a verified, sealed execution template
/// that the agent has repeated successfully enough to be pre-authorized.
///
/// Trigger: same (namespace, action_type, precondition_signature) seen ≥ k times
///          with success_rate ≥ γ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureRecord {
    /// Hash of (namespace + action_type + precondition_signature)
    pub pattern_hash: String,
    /// Human-readable label for this pattern
    pub pattern_label: String,
    /// Namespace this procedure applies to
    pub namespace: String,
    /// Action type string (e.g. "ehr.update_allergy")
    pub action_type: String,
    /// Number of times this pattern executed successfully
    pub success_count: u32,
    /// Total executions of this pattern (including failures)
    pub total_count: u32,
    /// CID of the sealed MemPacket recording this procedure
    pub sealed_cid: Option<String>,
    /// Whether this procedure is currently pre-authorized
    pub pre_authorized: bool,
    /// Timestamp when crystallization was triggered
    pub crystallized_at: i64,
    /// Timestamp of last execution of this pattern
    pub last_executed_at: i64,
}

impl ProcedureRecord {
    pub fn new(
        pattern_hash: String,
        pattern_label: String,
        namespace: String,
        action_type: String,
        now_ms: i64,
    ) -> Self {
        Self {
            pattern_hash,
            pattern_label,
            namespace,
            action_type,
            success_count: 0,
            total_count: 0,
            sealed_cid: None,
            pre_authorized: false,
            crystallized_at: now_ms,
            last_executed_at: now_ms,
        }
    }

    /// Current success rate for this pattern [0,1].
    pub fn success_rate(&self) -> f64 {
        if self.total_count == 0 { return 0.0; }
        self.success_count as f64 / self.total_count as f64
    }

    /// Check if this pattern meets the crystallization threshold.
    /// Default: k=10 executions, γ=0.90 success rate.
    pub fn meets_crystallization_threshold(&self, k: u32, gamma: f64) -> bool {
        self.total_count >= k && self.success_rate() >= gamma
    }
}

// =============================================================================
// AgentIdentityState — the full per-agent identity bundle
// =============================================================================

/// Complete identity state for a single agent.
///
/// Stored per agent in the kernel's AgentControlBlock extension.
/// Sealed into the audit CID chain at the end of each execution window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentityState {
    /// Agent PID this identity belongs to
    pub agent_pid: String,
    /// Layer 2: Cryptographic DID anchor
    pub did: AgentDID,
    /// Layer 2: Verifiable credential chain
    pub vc_chain: VCChain,
    /// Layer 1: Per-namespace memory series indices
    pub memory_series: HashMap<String, MemorySeriesIndex>,
    /// Layer 1: Per-namespace expertise records (for KECS)
    pub expertise: HashMap<String, AgentExpertiseRecord>,
    /// Layer 1: Crystallized procedural patterns
    pub procedures: Vec<ProcedureRecord>,
    /// Timestamp of last full identity state update
    pub last_updated_at: i64,
}

impl AgentIdentityState {
    pub fn new(agent_pid: String, did: AgentDID, now_ms: i64) -> Self {
        Self {
            agent_pid,
            did,
            vc_chain: VCChain::new(),
            memory_series: HashMap::new(),
            expertise: HashMap::new(),
            procedures: Vec::new(),
            last_updated_at: now_ms,
        }
    }

    /// Get or create an expertise record for the given namespace.
    pub fn expertise_for(&mut self, namespace: &str, now_ms: i64) -> &mut AgentExpertiseRecord {
        self.expertise
            .entry(namespace.to_string())
            .or_insert_with(|| AgentExpertiseRecord::new(namespace.to_string(), now_ms))
    }

    /// Get or create a memory series index for the given namespace.
    pub fn series_for(&mut self, namespace: &str, budget_limit: u64) -> &mut MemorySeriesIndex {
        self.memory_series
            .entry(namespace.to_string())
            .or_insert_with(|| MemorySeriesIndex::new(namespace.to_string(), budget_limit))
    }

    /// Total VCs earned across all chains.
    pub fn total_vcs(&self) -> usize {
        self.vc_chain.len()
    }

    /// Highest KECS score across all namespaces.
    pub fn max_kecs(&self) -> f64 {
        self.expertise.values().map(|e| e.kecs).fold(0.0_f64, f64::max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_did_format() {
        let did = AgentDID::new(
            "agent-001".to_string(),
            "/k/ehr/allergy".to_string(),
            "bafy2bzacea...".to_string(),
            "ed25519_pubkey".to_string(),
            1_700_000_000_000,
        );
        let s = did.to_did_string();
        assert!(s.starts_with("did:connector:agent-001:"));
        assert!(s.contains("k_ehr_allergy"));
    }

    #[test]
    fn test_vc_chain_growth() {
        let mut chain = VCChain::new();
        assert!(chain.is_empty());

        let genesis_vc = VerifiableCredential::new(
            VCType::Genesis,
            "did:connector:agent-001:...".to_string(),
            "did:connector:orchestrator:...".to_string(),
            HashMap::new(),
            1_700_000_000_000,
        );
        chain.add(genesis_vc);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.latest_vc_type(), Some(VCType::Genesis));
    }

    #[test]
    fn test_expertise_record_outcome_tracking() {
        let mut rec = AgentExpertiseRecord::new("/k/ehr".to_string(), 0);
        for _ in 0..45 {
            rec.record_outcome(ExecutionOutcome::Success, 1_000);
        }
        for _ in 0..5 {
            rec.record_outcome(ExecutionOutcome::Failed, 1_001);
        }
        assert_eq!(rec.exec_count, 50);
        let dist = rec.current_outcome_dist();
        let p_success = dist.get(&ExecutionOutcome::Success).copied().unwrap_or(0.0);
        assert!(p_success > 0.8);
    }

    #[test]
    fn test_procedure_crystallization() {
        let mut proc = ProcedureRecord::new(
            "hash_abc".to_string(),
            "ehr.update_allergy".to_string(),
            "/k/ehr".to_string(),
            "ehr.update_allergy".to_string(),
            0,
        );
        proc.total_count = 10;
        proc.success_count = 10;
        assert!(proc.meets_crystallization_threshold(10, 0.90));
        assert!(proc.meets_crystallization_threshold(10, 0.95)); // 1.0 >= 0.95 → true
        assert!(!proc.meets_crystallization_threshold(11, 0.90)); // total_count=10 < 11 → false
    }

    #[test]
    fn test_memory_series_budget() {
        let mut idx = MemorySeriesIndex::new("/k/ehr".to_string(), 32_000);
        idx.record_window(1, 500, 1_000);
        idx.record_window(2, 500, 2_000);
        assert_eq!(idx.budget_used_tokens, 1_000);
        assert!((idx.budget_utilization() - 1000.0 / 32_000.0).abs() < 1e-9);
    }
}
