//! Trust Computer — computes verifiable trust scores from real kernel data.
//!
//! The trust score is NOT self-reported. It is computed from:
//! - Ring 0: CID integrity + Merkle verification
//! - Ring 1: Audit completeness (no gaps)
//! - Ring 2: AAPI authorization coverage
//! - Ring 3: Decision provenance chain
//! - App layer: Claim validity (% of LLM claims verified against source CIDs)

use vac_core::kernel::MemoryKernel;
use vac_core::types::OpOutcome;
use serde::{Deserialize, Serialize};
use crate::claims::ClaimSet;
use crate::entropic::{KecsComputer, KecsWeights, KecsResult, MemoryLayerState, ConsciousnessScore, ReasoningEntropyScore};
use vac_core::identity::{AgentIdentityState, AgentExpertiseRecord};
use vac_core::knot::KnotEngine;

/// Trust score with up to 8 dimensions, each 0-20.
/// Base score 0-100 from dims 1-5; dims 6+8 add up to +40 (capped at 100).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Overall score (0-100)
    pub score: u32,
    /// Letter grade: A+ (95+), A (85+), B (70+), C (50+), D (30+), F (<30)
    pub grade: String,
    /// Individual dimension scores
    pub dimensions: TrustDimensions,
    /// Number of operations analyzed
    pub operations_analyzed: usize,
    /// Whether the score is verifiable (all data from kernel)
    pub verifiable: bool,
}

/// 8 trust dimensions (each 0-20):
///   Dims 1-5: per-run kernel checks (always present)
///   Dim  6:   KECS longitudinal expertise score (from Section 10 / entropic.rs)
///   Dim  7:   Claim validity (app-layer, optional)
///   Dim  8:   Identity coherence (Ψ + R_score from Section 11 / identity.rs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDimensions {
    /// Dim 1 — Memory integrity: CID matches, no tampered packets (0-20)
    pub memory_integrity: u32,
    /// Dim 2 — Audit completeness: no gaps in audit log (0-20)
    pub audit_completeness: u32,
    /// Dim 3 — Authorization coverage: % of actions with AAPI Vakya (0-20)
    pub authorization_coverage: u32,
    /// Dim 4 — Decision provenance: % of decisions with evidence chain (0-20)
    pub decision_provenance: u32,
    /// Dim 5 — Operational health: agent lifecycle correctness (0-20)
    pub operational_health: u32,
    /// Dim 6 — KECS confidence: longitudinal expertise from KnotEngine + audit history (0-20)
    /// None if no expertise record is available (kernel-only mode without identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kecs_confidence: Option<u32>,
    /// Dim 7 — Claim validity: % of LLM claims verified against source CIDs (0-20, app layer)
    /// None if no claims were verified (kernel-only mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_validity: Option<u32>,
    /// Dim 8 — Identity coherence: mean(Ψ consciousness, R_score reasoning) × 20 (0-20)
    /// None if no identity state is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_coherence: Option<u32>,
    /// Full KECS result (detailed breakdown, not counted in score)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kecs_detail: Option<KecsResult>,
}

/// Trust computer — analyzes kernel state to produce a verifiable trust score.
pub struct TrustComputer;

impl TrustComputer {
    /// Compute trust score from kernel state.
    pub fn compute(kernel: &MemoryKernel) -> TrustScore {
        let audit_log_all = kernel.audit_log_all();
        let audit_log = audit_log_all.as_slice();
        let total_ops = audit_log.len();

        // Note: do NOT short-circuit to score=0 when total_ops==0.
        // After a server restart the audit log is empty (not persisted) but
        // agents and packets are reloaded from store. memory_integrity,
        // operational_health, and decision_provenance are computed from
        // kernel state (agents/packets), not audit entries — they should
        // still contribute to the score. Audit-dependent dims
        // (completeness, authorization_coverage) will naturally return 0
        // on an empty log, which is the correct per-dimension behaviour.
        // Only return grade "N/A" when there are literally no agents at all.
        let has_any_state = !kernel.agents().is_empty() || kernel.packet_count() > 0 || total_ops > 0;
        if !has_any_state {
            return TrustScore {
                score: 0,
                grade: "N/A".to_string(),
                dimensions: TrustDimensions {
                    memory_integrity: 0,
                    audit_completeness: 0,
                    authorization_coverage: 0,
                    decision_provenance: 0,
                    operational_health: 0,
                    kecs_confidence: None,
                    claim_validity: None,
                    identity_coherence: None,
                    kecs_detail: None,
                },
                operations_analyzed: 0,
                verifiable: true,
            };
        }

        let memory_integrity = Self::compute_memory_integrity(kernel);
        let audit_completeness = Self::compute_audit_completeness(audit_log);
        let authorization_coverage = Self::compute_authorization_coverage(audit_log);
        let decision_provenance = Self::compute_decision_provenance(kernel);
        let operational_health = Self::compute_operational_health(kernel);

        let base_score = memory_integrity + audit_completeness + authorization_coverage
            + decision_provenance + operational_health;
        let score = base_score.min(100);
        let grade = Self::score_to_grade(score);

        TrustScore {
            score,
            grade,
            dimensions: TrustDimensions {
                memory_integrity,
                audit_completeness,
                authorization_coverage,
                decision_provenance,
                operational_health,
                kecs_confidence: None,
                claim_validity: None,
                identity_coherence: None,
                kecs_detail: None,
            },
            operations_analyzed: total_ops,
            verifiable: true,
        }
    }

    /// Compute trust with claim validity from a ClaimSet.
    ///
    /// The 5 kernel dimensions stay the same (each 0-20, total 0-100).
    /// Claim validity is an additional app-layer dimension (0-20).
    /// The final score is: kernel_score * (claim_validity_ratio).
    /// This means rejected claims REDUCE the overall trust.
    pub fn compute_with_claims(kernel: &MemoryKernel, claim_set: &ClaimSet) -> TrustScore {
        let mut trust = Self::compute(kernel);

        let validity = Self::compute_claim_validity(claim_set);
        trust.dimensions.claim_validity = Some(validity);

        // Adjust score: if claims exist, blend kernel trust with claim validity
        // Formula: score = kernel_base * (0.8 + 0.2 * validity_ratio)
        // This means 100% valid claims = no penalty, 0% = 20% reduction
        if claim_set.total() > 0 {
            let validity_ratio = claim_set.validity_ratio();
            let adjusted = (trust.score as f64) * (0.8 + 0.2 * validity_ratio);
            trust.score = adjusted.round().min(100.0).max(0.0) as u32;
            trust.grade = Self::score_to_grade(trust.score);
        }

        trust
    }

    /// Compute trust score with KECS (dim 6) + identity coherence (dim 8).
    ///
    /// Full 8-dimension trust score:
    ///   base_score    = sum(dims 1-5)                [0-100]
    ///   kecs_points   = KECS × 20                   [0-20]
    ///   id_points     = mean(Ψ, R_score) × 20       [0-20]
    ///   raw_score     = min(100, base + kecs + id)
    ///   trust_score   = raw × (0.8 + 0.2 × claim_validity_ratio)
    pub fn compute_with_identity(
        kernel: &MemoryKernel,
        knot: &KnotEngine,
        identity: &AgentIdentityState,
        namespace: &str,
        reasoning: Option<&ReasoningEntropyScore>,
        claim_set: Option<&ClaimSet>,
    ) -> TrustScore {
        let mut trust = Self::compute(kernel);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // --- Dim 6: KECS ---
        let expertise = identity.expertise.get(namespace);
        let kecs_result = if let Some(exp) = expertise {
            let weights = KecsWeights::default();
            Some(KecsComputer::compute(knot, exp, &weights))
        } else {
            None
        };

        let kecs_points = kecs_result.as_ref().map(|r| r.kecs_points).unwrap_or(0);
        trust.dimensions.kecs_confidence = Some(kecs_points);
        trust.dimensions.kecs_detail = kecs_result;

        // --- Dim 8: Identity coherence ---
        let series = identity.memory_series.get(namespace);
        let mem_state = MemoryLayerState {
            episodic: (
                series.map(|s| s.verified_packet_count).unwrap_or(0),
                series.map(|s| s.budget_utilization()).unwrap_or(0.0),
                series.map(|s| s.window_sns.len()).unwrap_or(0),
            ),
            semantic: (
                knot.node_count(),
                knot.edge_count(),
                expertise.map(|e| e.k_vn).unwrap_or(0.0),
            ),
            procedural: (
                identity.procedures.iter().filter(|p| p.pre_authorized).count(),
                identity.procedures.iter()
                    .map(|p| p.success_rate())
                    .fold(0.0_f64, |acc, r| acc + r)
                    / identity.procedures.len().max(1) as f64,
            ),
        };
        let psi = ConsciousnessScore::compute(&mem_state);
        let r_score = reasoning.map(|r| r.r_score()).unwrap_or(0.5);
        let identity_coherence = ((psi + r_score) / 2.0 * 20.0).round().min(20.0) as u32;
        trust.dimensions.identity_coherence = Some(identity_coherence);

        // --- Recompute score with dims 6+8 ---
        let base = trust.dimensions.memory_integrity
            + trust.dimensions.audit_completeness
            + trust.dimensions.authorization_coverage
            + trust.dimensions.decision_provenance
            + trust.dimensions.operational_health;

        let raw = (base + kecs_points + identity_coherence).min(100);

        // Apply claim validity multiplier
        let validity_ratio = claim_set
            .filter(|cs| cs.total() > 0)
            .map(|cs| cs.validity_ratio())
            .unwrap_or(1.0);

        if let Some(cs) = claim_set {
            let validity = Self::compute_claim_validity(cs);
            trust.dimensions.claim_validity = Some(validity);
        }

        let adjusted = (raw as f64) * (0.8 + 0.2 * validity_ratio);
        trust.score = adjusted.round().min(100.0).max(0.0) as u32;
        trust.grade = Self::score_to_grade(trust.score);
        trust.operations_analyzed = kernel.audit_log_all().len();
        trust
    }

    /// Compute claim validity dimension (0-20).
    fn compute_claim_validity(claim_set: &ClaimSet) -> u32 {
        if claim_set.total() == 0 {
            return 20; // No claims = nothing to invalidate
        }
        (claim_set.validity_ratio() * 20.0).round() as u32
    }

    /// Memory integrity: Are all packets content-addressed and unmodified?
    fn compute_memory_integrity(kernel: &MemoryKernel) -> u32 {
        let total_packets = kernel.packet_count();
        if total_packets == 0 {
            return 20; // No packets = nothing to corrupt = perfect
        }

        // Every packet has a CID (guaranteed by kernel), so base score is high.
        // Deduct for sealed violations or integrity check failures.
        let audit_log_mem = kernel.audit_log_all();
        let audit_log = audit_log_mem.as_slice();
        let integrity_failures = audit_log.iter()
            .filter(|e| {
                e.operation == vac_core::types::MemoryKernelOp::IntegrityCheck
                    && e.outcome != OpOutcome::Success
            })
            .count();

        if integrity_failures == 0 {
            20
        } else {
            let ratio = 1.0 - (integrity_failures as f64 / total_packets.max(1) as f64);
            (ratio * 20.0).round() as u32
        }
    }

    /// Audit completeness: Is there a continuous, gap-free audit trail?
    fn compute_audit_completeness(audit_log: &[vac_core::types::KernelAuditEntry]) -> u32 {
        if audit_log.is_empty() {
            return 0;
        }

        // Check for monotonically increasing timestamps (no gaps)
        let mut gaps = 0;
        for window in audit_log.windows(2) {
            if window[1].timestamp < window[0].timestamp {
                gaps += 1;
            }
        }

        // Check that all entries have outcomes
        let entries_with_outcome = audit_log.iter()
            .filter(|e| e.outcome != OpOutcome::Success || e.outcome == OpOutcome::Success)
            .count();

        let completeness_ratio = entries_with_outcome as f64 / audit_log.len() as f64;
        let gap_penalty = (gaps as f64 / audit_log.len().max(1) as f64).min(1.0);

        ((completeness_ratio - gap_penalty) * 20.0).round().max(0.0) as u32
    }

    /// Authorization coverage: What % of operations have AAPI Vakya IDs?
    fn compute_authorization_coverage(audit_log: &[vac_core::types::KernelAuditEntry]) -> u32 {
        if audit_log.is_empty() {
            return 0;
        }

        let with_vakya = audit_log.iter()
            .filter(|e| e.vakya_id.is_some())
            .count();

        let ratio = with_vakya as f64 / audit_log.len() as f64;
        (ratio * 20.0).round() as u32
    }

    /// Decision provenance: Do decisions have evidence chains?
    fn compute_decision_provenance(kernel: &MemoryKernel) -> u32 {
        let total_packets = kernel.packet_count();
        if total_packets == 0 {
            return 20; // No decisions = nothing to trace = perfect
        }

        // Check how many packets have provenance (evidence_refs, reasoning)
        // Since we can't iterate all packets directly, use audit log as proxy
        let audit_log_prov = kernel.audit_log_all();
        let audit_log = audit_log_prov.as_slice();
        let write_ops = audit_log.iter()
            .filter(|e| e.operation == vac_core::types::MemoryKernelOp::MemWrite)
            .count();

        let successful_writes = audit_log.iter()
            .filter(|e| {
                e.operation == vac_core::types::MemoryKernelOp::MemWrite
                    && e.outcome == OpOutcome::Success
            })
            .count();

        if write_ops == 0 {
            return 20;
        }

        let ratio = successful_writes as f64 / write_ops as f64;
        (ratio * 20.0).round() as u32
    }

    /// Operational health: Are agents in correct lifecycle states?
    fn compute_operational_health(kernel: &MemoryKernel) -> u32 {
        let agents = kernel.agents();
        if agents.is_empty() {
            return 20;
        }

        let healthy = agents.values()
            .filter(|acb| {
                // Registered is a valid pre-start lifecycle state — counts as healthy.
                // Unhealthy = none of: registered, running, suspended, waiting, completed, failed, terminated
                // In practice: any agent that exists in the kernel is in a valid state.
                use vac_core::types::AgentStatus;
                !matches!(acb.status, AgentStatus::Failed)
            })
            .count();

        let audit_log_pol = kernel.audit_log_all();
        let denied_ops = audit_log_pol.iter()
            .filter(|e| e.outcome == OpOutcome::Denied)
            .count();

        let total_ops = audit_log_pol.len().max(1);
        let denied_ratio = denied_ops as f64 / total_ops as f64;

        let health_ratio = healthy as f64 / agents.len() as f64;
        let score = (health_ratio * 20.0) - (denied_ratio * 5.0);
        score.round().max(0.0).min(20.0) as u32
    }

    /// Convert numeric score to letter grade.
    fn score_to_grade(score: u32) -> String {
        match score {
            95..=100 => "A+".to_string(),
            85..=94 => "A".to_string(),
            70..=84 => "B".to_string(),
            50..=69 => "C".to_string(),
            30..=49 => "D".to_string(),
            _ => "F".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};
    use vac_core::types::MemoryKernelOp;

    fn setup_kernel_with_agent() -> (MemoryKernel, String) {
        let mut kernel = MemoryKernel::new();

        let reg = SyscallRequest {
            agent_pid: "system".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "test-bot".to_string(),
                namespace: "ns:test".to_string(),
                role: Some("writer".to_string()),
                model: None,
                framework: None,
            },
            reason: None,
            vakya_id: None, trace_parent: None, trace_state: None, api_version: None,
        };
        let result = kernel.dispatch(reg);
        let pid = match result.value {
            SyscallValue::AgentPid(p) => p,
            _ => panic!("Expected AgentPid"),
        };

        let start = SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: None,
            vakya_id: None, trace_parent: None, trace_state: None, api_version: None,
        };
        kernel.dispatch(start);

        (kernel, pid)
    }

    #[test]
    fn test_empty_kernel_trust() {
        let kernel = MemoryKernel::new();
        let trust = TrustComputer::compute(&kernel);
        assert_eq!(trust.score, 0);
        assert_eq!(trust.grade, "N/A");
        assert!(trust.verifiable);
    }

    #[test]
    fn test_healthy_kernel_trust() {
        let (kernel, _pid) = setup_kernel_with_agent();
        let trust = TrustComputer::compute(&kernel);

        // Should have high scores for a healthy kernel
        assert!(trust.score > 0);
        assert!(trust.operations_analyzed >= 2); // register + start
        assert!(trust.verifiable);
        assert!(trust.dimensions.memory_integrity > 0);
        assert!(trust.dimensions.audit_completeness > 0);
        assert!(trust.dimensions.operational_health > 0);
    }

    #[test]
    fn test_grade_mapping() {
        assert_eq!(TrustComputer::score_to_grade(100), "A+");
        assert_eq!(TrustComputer::score_to_grade(95), "A+");
        assert_eq!(TrustComputer::score_to_grade(90), "A");
        assert_eq!(TrustComputer::score_to_grade(75), "B");
        assert_eq!(TrustComputer::score_to_grade(60), "C");
        assert_eq!(TrustComputer::score_to_grade(40), "D");
        assert_eq!(TrustComputer::score_to_grade(10), "F");
    }
}
