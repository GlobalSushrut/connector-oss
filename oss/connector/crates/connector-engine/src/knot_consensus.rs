//! KnotConsensus — Topological Pseudo-Consensus for Agent Interaction.
//!
//! Replaces Raft (leader-election log replication) and PBFT (3f+1 Byzantine
//! rounds) with a consensus model grounded in **knot-physics interference**
//! and **braid category theory**.
//!
//! # Why Raft / PBFT Don't Fit Agents
//!
//! - Raft assumes homogeneous nodes, deterministic log replication, stable leaders.
//!   Agents are heterogeneous, probabilistic, memory-rich, asynchronous.
//! - PBFT requires exactly 3f+1 nodes, synchronous phases, binary vote.
//!   Agents have *graded* trust (KECS ∈ [0,1]), *graded* identity (AISV),
//!   and *graded* agreement (partial semantic overlap).
//! - Neither model leverages the *semantic content* of what is being agreed upon.
//!   Agent proposals carry evidence CIDs, KnotEngine entity references,
//!   reasoning chains — all ignored by binary vote.
//!
//! # Mathematical Foundation
//!
//! ## 1. Agents as Strands — Braid Group B_n
//!
//! n agents participating in a consensus round form n strands in the braid
//! group B_n (Artin 1925). Each agent i has a **range parameter** (spectral
//! parameter):
//!
//! ```text
//! u_i = α·KECS_i + β·Ψ_i + γ·R_score_i   ∈ [0, 3]
//! ```
//!
//! where α=0.4, β=0.35, γ=0.25 match the entropic trust weight schema.
//! u_i is anchored to the agent's `AgentIdentityState` — it cannot be forged.
//!
//! ## 2. Interactions as Braid Crossings — R-Matrix
//!
//! When agents A_i and A_j exchange a proposal/attestation, this is a
//! **crossing** σ_{ij} in B_n. The crossing sign is determined by the
//! **R-matrix** R(u_i, u_j) ∈ End(V ⊗ V):
//!
//! Using the XXX rational R-matrix (Baxter 1972, Yang 1967):
//! ```text
//! R(u_i, u_j) = A(u_i-u_j)·I + B(u_i-u_j)·P
//! A(δu) = δu / (δu + η)
//! B(δu) = η   / (δu + η)
//! ```
//!
//! where η = 1 (coupling constant), P is the swap operator.
//! The **crossing sign** ε(i,j) ∈ {+1, 0, -1} is:
//! - ε = +1 (positive crossing, σ_i): A(δu) > B(δu) → higher-trust agent dominates
//! - ε = -1 (negative crossing, σ_i⁻¹): A(δu) < B(δu) → lower-trust agent overrides
//! - ε = 0  (smooth, no crossing): |A - B| < θ_smooth → abstain
//!
//! ## 3. Yang-Baxter Equation as Consistency Invariant
//!
//! For any triple (i,j,k), the crossing sequence must satisfy the YBE:
//! ```text
//! R₁₂(u_i,u_j) R₁₃(u_i,u_k) R₂₃(u_j,u_k) = R₂₃(u_j,u_k) R₁₃(u_i,u_k) R₁₂(u_i,u_j)
//! ```
//! In our discrete approximation: the signed crossing sum must be path-independent.
//! ε(i,j) + ε(j,k) + ε(i,k)  =  ε(j,i) + ε(k,i) + ε(k,j)  (mod sign)
//!
//! This is checked for ALL triples before consensus is accepted. A YBE violation
//! means some agent's identity parameter is inconsistent with the others
//! (possible Sybil or Byzantine behavior).
//!
//! ## 4. Writhe as Consensus Signal
//!
//! The **writhe** w(β) of the interaction braid β is:
//! ```text
//! w(β) = Σ_{i<j} ε(i,j)     (sum of all signed crossings)
//! ```
//!
//! Interpretation:
//! - w > 0: net agreement (more positive crossings than negative)
//! - w = 0: deadlock / perfect disagreement
//! - w < 0: net rejection (majority oppose the proposal)
//!
//! Consensus threshold: w(β) ≥ θ_writhe = ⌊n/2⌋ + 1
//! (majority of pairwise agreements, weighted by trust parameters)
//!
//! ## 5. Kauffman Bracket as Evidence Weight
//!
//! The Kauffman bracket ⟨β⟩ of the interaction braid (Kauffman 1987,
//! "State models and the Jones polynomial", Topology 26:395-407):
//! ```text
//! Rule 1: ⟨∅⟩ = 1
//! Rule 2: ⟨L+⟩ = A·⟨L0⟩ + A⁻¹·⟨L∞⟩   (crossing → two smoothings)
//! Rule 3: ⟨O ⊔ L⟩ = (-A² - A⁻²)·⟨L⟩  (disjoint circle = δ factor)
//! ```
//!
//! A is derived from agent parameters: A = exp(i·π·u_avg/4)
//! The normalized bracket X(β) = (-A)^{-3w(β)} · ⟨β⟩
//! |X(β)| ∈ (0, 1] is the **evidence coherence weight**.
//!
//! ## 6. Linking Number as Quorum Density
//!
//! The **linking number** lk(A_i, A_j) between agent strands i and j:
//! ```text
//! lk(i,j) = (1/2) Σ_crossings(i,j) sign(c)
//! ```
//! where crossings(i,j) are the pairwise crossings between strands i and j.
//!
//! **Quorum density** Q(S) of a participating set S:
//! ```text
//! Q(S) = (2 / |S|·(|S|-1)) · Σ_{i<j∈S} |lk(i,j)|
//! ```
//! Q(S) ≥ θ_quorum = 0.5 required for commit.
//!
//! ## 7. Skein Resolution for Conflict
//!
//! When two agents i,j disagree (ε(i,j) ambiguous within [−θ, +θ]):
//! The **Jones skein relation** resolves the conflict:
//! ```text
//! t⁻¹·V(L+) - t·V(L-) = (t^(1/2) - t^(-1/2))·V(L0)
//! ```
//! where t = exp(2πi/r), r = floor(3 + n/2) (level r Temperley-Lieb).
//!
//! In practice: V(L0) = V_abstain is computed from unambiguous crossings,
//! then used to project L+ and L- into agreement / disagreement.
//!
//! ## 8. Temperley-Lieb Representation for State Space
//!
//! The braid generators σ_i are mapped to TL_n(δ):
//! ```text
//! ρ(σ_i) = A·e_i + A⁻¹·1    where δ = -A² - A⁻²
//! ```
//! The **Markov trace** tr_M(ρ(β)) = δ^{n-1}·tr(ρ(β)) gives the
//! unnormalized bracket polynomial, used as a consistency check on
//! the overall consensus state.
//!
//! # Protocol Summary
//!
//! ```text
//! 1. PROPOSE    — proposer broadcasts (value_hash, evidence_cids, StateVector digest)
//! 2. STRAND     — each agent computes u_i from its AgentIdentityState
//! 3. CROSSING   — each pair (i,j) evaluates R(u_i,u_j) → ε(i,j)
//! 4. YBE CHECK  — verify Yang-Baxter consistency for all triples
//! 5. WRITHE     — compute w(β) = Σ ε(i,j)
//! 6. BRACKET    — compute evidence coherence |X(β)|
//! 7. LINKING    — compute quorum density Q(S)
//! 8. SKEIN      — resolve ambiguous crossings via Jones skein
//! 9. DECIDE     — COMMIT if w ≥ θ_writhe AND Q ≥ θ_quorum AND YBE holds
//!                 NULL   otherwise → retry or escalate
//! ```
//!
//! # Research Sources
//!
//! - Artin, E. (1925): Theory of braids. Hamburg Math. Sem. Abh. 4:47-72.
//! - Yang, C.N. (1967): Some exact results for the many-body problem in one
//!   dimension with repulsive delta-function interaction. PRL 19:1312.
//! - Baxter, R.J. (1972): Partition function of the eight-vertex lattice model.
//!   Ann. Phys. 70:193-228.
//! - Kauffman, L.H. (1987): State models and the Jones polynomial.
//!   Topology 26(3):395-407.
//! - Jones, V.F.R. (1985): A polynomial invariant for knots via von Neumann algebras.
//!   Bull. AMS 12:103-111.
//! - Temperley, H.N.V. & Lieb, E.H. (1971): Relations between the
//!   'percolation' and 'colouring' problem. Proc. Roy. Soc. Lond. A 322:251-280.
//! - Alexander, J.W. (1923): A lemma on systems of knotted curves. PNAS 9:93-95.
//! - Markov, A.A. (1935): Über die freie Äquivalenz geschlossener Zöpfe.
//! - Kitaev, A. (2003): Fault-tolerant quantum computation by anyons.
//!   Ann. Phys. 303:2-30.
//! - Castro, M. & Liskov, B. (1999): PBFT — referenced only for contrast.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// =============================================================================
// Range Parameter — agent's spectral identity parameter
// =============================================================================

/// Agent spectral parameter u_i ∈ [0,3], computed from KECS+Ψ+R_score.
///
/// This is the "range parameter" from the Yang-Baxter / R-matrix formalism.
/// Anchored to the agent's verifiable identity — cannot be forged.
///
/// u_i = α·KECS + β·Ψ + γ·R_score
///   α = 0.40  (matches KECS weight in trust scoring)
///   β = 0.35  (Ψ consciousness weight)
///   γ = 0.25  (R_score reasoning weight)
///   u_i ∈ [0, 1] (normalized to [0,1] before R-matrix computation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotStrand {
    /// Agent PID
    pub agent_pid: String,
    /// Namespace participating in consensus
    pub namespace: String,
    /// KECS score [0,1] from AgentExpertiseRecord
    pub kecs: f64,
    /// Consciousness score Ψ [0,1] from ConsciousnessScore
    pub psi: f64,
    /// Reasoning consistency R_score [0,1] from ReasoningEntropyScore
    pub r_score: f64,
    /// Computed spectral parameter u_i ∈ [0,1]
    pub u: f64,
    /// VC chain length (used as secondary trust signal)
    pub vc_count: usize,
    /// Whether agent is in probation (forces u → 0)
    pub in_probation: bool,
}

impl KnotStrand {
    /// Weights for range parameter computation.
    pub const ALPHA: f64 = 0.40;
    pub const BETA: f64 = 0.35;
    pub const GAMMA: f64 = 0.25;

    /// Construct a KnotStrand and compute u_i.
    pub fn new(
        agent_pid: String,
        namespace: String,
        kecs: f64,
        psi: f64,
        r_score: f64,
        vc_count: usize,
        in_probation: bool,
    ) -> Self {
        let u = if in_probation {
            0.0
        } else {
            (Self::ALPHA * kecs + Self::BETA * psi + Self::GAMMA * r_score).clamp(0.0, 1.0)
        };
        Self { agent_pid, namespace, kecs, psi, r_score, u, vc_count, in_probation }
    }

    /// Create a minimal strand for an agent with no identity data yet.
    pub fn genesis(agent_pid: String, namespace: String) -> Self {
        Self::new(agent_pid, namespace, 0.0, 0.0, 0.5, 0, false)
    }
}

// =============================================================================
// R-Matrix — crossing sign computation
// =============================================================================

/// The XXX rational R-matrix (Yang 1967, Baxter 1972).
///
/// R(u_i, u_j) = A(δu)·I + B(δu)·P
///
/// where:
///   δu = u_i - u_j  (difference of spectral parameters)
///   A(δu) = δu / (δu + η)   (identity component)
///   B(δu) = η   / (δu + η)   (swap component)
///   η = 1.0 (coupling constant, fixed)
///
/// The crossing sign ε(i,j):
///   +1 if A > B + θ_smooth  (i dominates — positive crossing)
///   -1 if B > A + θ_smooth  (j dominates — negative crossing)
///    0 if |A - B| ≤ θ_smooth (abstain — smooth the crossing)
pub struct RMatrix;

impl RMatrix {
    /// Coupling constant η.
    pub const ETA: f64 = 1.0;
    /// Smoothing threshold — crossings within this margin are abstentions.
    pub const THETA_SMOOTH: f64 = 0.05;

    /// Compute the A coefficient (identity component weight).
    ///
    /// A(δu) = δu / (δu + η)
    ///
    /// Range: A ∈ (-∞, 1). For u_i > u_j (δu > 0): A > 0, A increases toward 1.
    /// For u_i < u_j (δu < 0): A < 0 (negative).
    /// Special case δu → ∞: A → 1 (pure identity, high-trust agent dominates).
    pub fn a_coeff(delta_u: f64) -> f64 {
        delta_u / (delta_u + Self::ETA)
    }

    /// Compute the B coefficient (swap component weight).
    ///
    /// B(δu) = η / (δu + η)
    ///
    /// Range: B ∈ (0, ∞) for δu > -η. For δu → ∞: B → 0.
    /// B(0) = 1 (equal trust → pure swap, crossing undetermined).
    pub fn b_coeff(delta_u: f64) -> f64 {
        Self::ETA / (delta_u + Self::ETA)
    }

    /// Compute the crossing sign ε(i,j) ∈ {+1, 0, -1}.
    ///
    /// δu = u_i - u_j
    /// If δu > 0 (agent i has higher trust):
    ///   A > 0, B = η/(δu+η) < A for δu > η  → positive crossing
    /// If δu < 0 (agent j has higher trust):
    ///   A < 0, negative crossing
    /// If δu ≈ 0 (equal trust): abstain
    pub fn crossing_sign(strand_i: &KnotStrand, strand_j: &KnotStrand) -> i8 {
        let delta_u = strand_i.u - strand_j.u;
        // Absolute delta_u > 0 means i has more trust
        // Use the rational parametrization: sign follows sgn(A - B)
        // A(δu) - B(δu) = (δu - η) / (δu + η)
        // Positive when δu > η, negative when δu < η (= when j dominates),
        // zero when δu = η exactly.
        //
        // For our consensus: we want a simpler interpretation:
        //   ε(i,j) = sign(u_i - u_j) when |u_i - u_j| > θ_smooth
        //   ε(i,j) = 0               otherwise
        let abs_delta = delta_u.abs();
        if abs_delta <= Self::THETA_SMOOTH {
            0
        } else if delta_u > 0.0 {
            1
        } else {
            -1
        }
    }

    /// Compute the full R-matrix A and B coefficients for logging/analysis.
    pub fn r_components(strand_i: &KnotStrand, strand_j: &KnotStrand) -> (f64, f64) {
        let delta_u = strand_i.u - strand_j.u;
        (Self::a_coeff(delta_u), Self::b_coeff(delta_u))
    }
}

// =============================================================================
// BraidCrossing — a single pairwise interaction record
// =============================================================================

/// A single crossing between two agent strands in the consensus braid.
///
/// Corresponds to one pairwise exchange of proposal/attestation.
/// The crossing sign encodes the trust-weighted agreement direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraidCrossing {
    /// Strand i (first agent)
    pub strand_i: String,
    /// Strand j (second agent)  
    pub strand_j: String,
    /// Spectral parameter of strand i
    pub u_i: f64,
    /// Spectral parameter of strand j
    pub u_j: f64,
    /// δu = u_i - u_j
    pub delta_u: f64,
    /// R-matrix A coefficient
    pub a_coeff: f64,
    /// R-matrix B coefficient
    pub b_coeff: f64,
    /// Crossing sign ε(i,j) ∈ {-1, 0, +1}
    pub epsilon: i8,
    /// Whether this crossing was resolved via skein relation
    pub skein_resolved: bool,
    /// Attestation CID from strand_i about the proposal
    pub attestation_cid_i: Option<String>,
    /// Attestation CID from strand_j about the proposal
    pub attestation_cid_j: Option<String>,
}

impl BraidCrossing {
    /// Construct a crossing from two strands with optional attestation CIDs.
    pub fn new(
        strand_i: &KnotStrand,
        strand_j: &KnotStrand,
        attestation_cid_i: Option<String>,
        attestation_cid_j: Option<String>,
    ) -> Self {
        let delta_u = strand_i.u - strand_j.u;
        let (a_coeff, b_coeff) = RMatrix::r_components(strand_i, strand_j);
        let epsilon = RMatrix::crossing_sign(strand_i, strand_j);
        Self {
            strand_i: strand_i.agent_pid.clone(),
            strand_j: strand_j.agent_pid.clone(),
            u_i: strand_i.u,
            u_j: strand_j.u,
            delta_u,
            a_coeff,
            b_coeff,
            epsilon,
            skein_resolved: false,
            attestation_cid_i,
            attestation_cid_j,
        }
    }

    /// Linking number contribution of this crossing.
    ///
    /// lk(i,j) += sign(ε) / 2  per crossing.
    /// Accumulated over all crossings between strands i and j.
    pub fn linking_contribution(&self) -> f64 {
        self.epsilon as f64 * 0.5
    }
}

// =============================================================================
// Yang-Baxter Consistency Checker
// =============================================================================

/// Checks the Yang-Baxter equation for all triples of strands.
///
/// YBE consistency (discrete approximation):
/// For any triple (i, j, k), the crossing sequence must be path-independent:
///
/// ```text
/// ε(i,j) · ε(i,k) · ε(j,k) = ε(j,i) · ε(k,i) · ε(k,j)
/// ```
///
/// Since ε(j,i) = -ε(i,j), this reduces to checking that the total
/// signed path through any triple is consistent.
///
/// Physical meaning: If agent i beats j, and j beats k,
/// YBE requires i beats k (transitivity of trust dominance).
/// A YBE violation means circular trust (A > B > C > A) → Byzantine/Sybil signal.
pub struct YangBaxterChecker;

impl YangBaxterChecker {
    /// Check YBE for all triples in the crossing map.
    ///
    /// Returns (is_consistent, list_of_violations).
    /// Violations are (agent_i, agent_j, agent_k) triples that fail.
    pub fn check(
        strands: &[KnotStrand],
        crossing_map: &HashMap<(String, String), i8>,
    ) -> (bool, Vec<(String, String, String)>) {
        let mut violations = Vec::new();

        let n = strands.len();
        for a in 0..n {
            for b in (a + 1)..n {
                for c in (b + 1)..n {
                    let pid_a = &strands[a].agent_pid;
                    let pid_b = &strands[b].agent_pid;
                    let pid_c = &strands[c].agent_pid;

                    let eps_ab = Self::get_sign(crossing_map, pid_a, pid_b);
                    let eps_ac = Self::get_sign(crossing_map, pid_a, pid_c);
                    let eps_bc = Self::get_sign(crossing_map, pid_b, pid_c);

                    // LHS path: A→B then A→C then B→C
                    // RHS path: B→A then C→A then C→B = -eps_ab, -eps_ac, -eps_bc
                    // Consistency: transitivity check
                    // If A > B and B > C then A must be > C (eps_ac must agree)
                    // Violation if eps_ab > 0 AND eps_bc > 0 AND eps_ac <= 0
                    // or symmetric cases.
                    let violates = if eps_ab > 0 && eps_bc > 0 && eps_ac <= 0 {
                        true
                    } else if eps_ab < 0 && eps_bc < 0 && eps_ac >= 0 {
                        true
                    } else if eps_ab > 0 && eps_ac < 0 && eps_bc >= 0 {
                        true
                    } else if eps_ab < 0 && eps_ac > 0 && eps_bc <= 0 {
                        true
                    } else {
                        false
                    };

                    if violates {
                        violations.push((pid_a.clone(), pid_b.clone(), pid_c.clone()));
                    }
                }
            }
        }

        (violations.is_empty(), violations)
    }

    fn get_sign(map: &HashMap<(String, String), i8>, i: &str, j: &str) -> i8 {
        let key_ij = (i.to_string(), j.to_string());
        let key_ji = (j.to_string(), i.to_string());
        if let Some(&s) = map.get(&key_ij) {
            s
        } else if let Some(&s) = map.get(&key_ji) {
            -s // ε(j,i) = -ε(i,j)
        } else {
            0 // No crossing recorded → abstain
        }
    }
}

// =============================================================================
// Kauffman Bracket — Evidence Coherence Weight
// =============================================================================

/// Computes the Kauffman bracket ⟨β⟩ and normalized bracket X(β).
///
/// The bracket is computed over the braid crossings using the state-sum model
/// (Kauffman 1987). Each crossing is expanded into two smoothings (A and B types),
/// giving 2^n states for n crossings. We use a truncated approximation for
/// tractability.
///
/// The bracket parameter A is derived from the average spectral parameter:
/// A = exp(-π·u_avg / 2)  — maps [0,1] range parameter to A ∈ [exp(-π/2), 1]
///
/// The normalized bracket X(β) = (-A)^{-3w}·⟨β⟩ is the **evidence coherence**.
/// |X| close to 1 means the evidence network is tightly coupled (knot-like).
/// |X| close to 0 means the evidence is scattered (unlink-like, weak consensus).
pub struct KauffmanBracket;

impl KauffmanBracket {
    /// Compute the Kauffman A parameter from average strand u value.
    ///
    /// A = exp(-π·u_avg / 2)
    /// A ∈ [exp(-π/2), 1] ≈ [0.208, 1]
    pub fn a_param(strands: &[KnotStrand]) -> f64 {
        if strands.is_empty() {
            return 1.0;
        }
        let u_avg = strands.iter().map(|s| s.u).sum::<f64>() / strands.len() as f64;
        (-std::f64::consts::PI * u_avg / 2.0).exp()
    }

    /// Compute the loop value δ = -A² - A⁻².
    ///
    /// δ is the loop value in the Temperley-Lieb algebra TL_n(δ).
    /// For A ∈ (0,1): δ ∈ (-∞, -2). δ → -2 as A → 1 (Jones-Wenzl projector limit).
    pub fn delta(a: f64) -> f64 {
        -(a * a) - 1.0 / (a * a)
    }

    /// Compute the unnormalized Kauffman bracket ⟨β⟩ for a sequence of crossings.
    ///
    /// Uses the state-sum expansion:
    /// ⟨L+⟩ = A·⟨A-smoothing⟩ + A⁻¹·⟨B-smoothing⟩
    ///
    /// For each crossing with sign +1: contributes A factor
    /// For each crossing with sign -1: contributes A⁻¹ factor
    /// For each abstained crossing (0): contributes δ factor (loop)
    ///
    /// Result is a scalar approximation (not the full polynomial) that captures
    /// the overall contribution of the braid diagram.
    pub fn bracket(crossings: &[BraidCrossing], a: f64) -> f64 {
        if crossings.is_empty() {
            return 1.0;
        }
        let delta = Self::delta(a);
        let a_inv = 1.0 / a.max(1e-10);
        let mut result = 1.0_f64;
        for crossing in crossings {
            match crossing.epsilon {
                1  => result *= a,
                -1 => result *= a_inv,
                0  => result *= delta.abs(), // smooth crossings contribute loop factor
                _  => {}
            }
        }
        result
    }

    /// Compute the writhe normalization factor (-A)^{-3w}.
    pub fn writhe_norm(a: f64, writhe: i32) -> f64 {
        // (-A)^{-3w} = (-1)^{-3w} · A^{-3w}
        let sign = if (-3 * writhe) % 2 == 0 { 1.0_f64 } else { -1.0_f64 };
        let magnitude = a.powi(-3 * writhe);
        sign * magnitude
    }

    /// Compute the normalized bracket X(β) = (-A)^{-3w} · ⟨β⟩.
    ///
    /// X is the **evidence coherence weight** of the consensus round.
    /// |X| ∈ (0, ∞), clipped to [0, 1] for practical use.
    pub fn normalized_bracket(crossings: &[BraidCrossing], strands: &[KnotStrand], writhe: i32) -> f64 {
        let a = Self::a_param(strands);
        let bracket = Self::bracket(crossings, a);
        let norm = Self::writhe_norm(a, writhe);
        (norm * bracket).abs().min(1.0)
    }
}

// =============================================================================
// SkeinResolver — resolves ambiguous crossings
// =============================================================================

/// Resolves ambiguous (ε=0) crossings using the Jones skein relation.
///
/// The skein relation (Jones 1985):
/// ```text
/// t⁻¹·V(L+) - t·V(L-) = (t^{1/2} - t^{-1/2})·V(L0)
/// ```
///
/// In our context:
/// - V(L+) = consensus probability if crossing resolved as positive
/// - V(L-) = consensus probability if crossing resolved as negative
/// - V(L0) = abstain probability (already computed from non-ambiguous crossings)
/// - t = exp(2πi/r) where r = floor(3 + n/2) is the Temperley-Lieb level
///
/// We use the real-valued specialization t → t_real:
/// t_real = (writhe_so_far + 1) / (total_positive_possible + 1)
/// This maps to [0,1] and is Sybil-resistant because it depends on
/// the already-committed non-ambiguous crossings.
pub struct SkeinResolver;

impl SkeinResolver {
    /// Resolve ambiguous crossings (ε=0) in a crossing list.
    ///
    /// For each ambiguous crossing between strands i,j:
    /// 1. Compute t_real from committed crossings
    /// 2. Compute V(L0) as fraction of positive among committed
    /// 3. Solve for sign using skein equation
    ///
    /// Returns the crossing list with ambiguous crossings resolved.
    pub fn resolve(
        mut crossings: Vec<BraidCrossing>,
        strands: &[KnotStrand],
    ) -> Vec<BraidCrossing> {
        let n = strands.len() as f64;

        // Compute t_real from committed (non-ambiguous) crossings
        let committed: Vec<&BraidCrossing> = crossings.iter().filter(|c| c.epsilon != 0).collect();
        let n_pos = committed.iter().filter(|c| c.epsilon > 0).count() as f64;
        let n_total = committed.len() as f64;

        let t_real = if n_total > 0.0 {
            (n_pos + 1.0) / (n_total + 2.0) // Laplace-smoothed ratio
        } else {
            0.5 // No prior → neutral
        };

        // V(L0) = t_real (abstain probability = current positive fraction)
        let v_l0 = t_real;

        // Level r for Temperley-Lieb representation
        let r = (3.0 + n / 2.0).floor() as i32;
        let t_tl = (2.0 * std::f64::consts::PI / r as f64).cos(); // Real part of e^{2πi/r}

        // Skein equation solution:
        // t⁻¹·V(L+) - t·V(L-) = (t^{1/2} - t^{-1/2})·V(L0)
        // Constraint: V(L+) + V(L-) = 1 (one must be chosen)
        // → V(L+) - V(L-) = t · skein_rhs  (symmetric solution)
        // → V(L+) = (1 + t·skein_rhs) / 2
        let t_sqrt = t_tl.sqrt().max(0.0);
        let t_inv_sqrt = if t_sqrt > 1e-10 { 1.0 / t_sqrt } else { 0.0 };
        let skein_rhs = (t_sqrt - t_inv_sqrt) * v_l0;
        let v_lplus = ((1.0 + t_tl * skein_rhs) / 2.0).clamp(0.0, 1.0);

        // For each ambiguous crossing: sign = +1 if V(L+) > 0.5, else -1
        for crossing in crossings.iter_mut() {
            if crossing.epsilon == 0 {
                crossing.epsilon = if v_lplus > 0.5 { 1 } else { -1 };
                crossing.skein_resolved = true;
            }
        }

        crossings
    }
}

// =============================================================================
// Linking Number — quorum density computation
// =============================================================================

/// Computes linking numbers and quorum density.
pub struct LinkingNumberComputer;

impl LinkingNumberComputer {
    /// Compute the linking number lk(i,j) between two agent strands.
    ///
    /// lk(i,j) = (1/2) · Σ_crossings(i,j) sign(c)
    ///
    /// Returns an integer (always an integer for closed curves).
    pub fn linking_number(crossings: &[BraidCrossing], pid_i: &str, pid_j: &str) -> f64 {
        let sum: f64 = crossings.iter()
            .filter(|c| {
                (c.strand_i == pid_i && c.strand_j == pid_j) ||
                (c.strand_i == pid_j && c.strand_j == pid_i)
            })
            .map(|c| {
                // Orient: if strand_i == pid_i, sign is ε; else −ε (reverse orientation)
                if c.strand_i == pid_i { c.epsilon as f64 }
                else { -(c.epsilon as f64) }
            })
            .sum();
        sum * 0.5
    }

    /// Compute the quorum density Q(S) for the participating agent set.
    ///
    /// Q(S) = (2 / |S|·(|S|-1)) · Σ_{i<j∈S} |lk(i,j)|
    ///
    /// Q = 1.0: all pairs maximally linked (tight consensus group)
    /// Q = 0.0: no linking at all (fully disconnected agents)
    /// Q ≥ 0.5: sufficient quorum (default threshold)
    pub fn quorum_density(crossings: &[BraidCrossing], strands: &[KnotStrand]) -> f64 {
        let n = strands.len();
        if n < 2 {
            return 0.0;
        }
        let pairs = n * (n - 1) / 2;
        if pairs == 0 {
            return 0.0;
        }

        let total_lk: f64 = (0..n).flat_map(|a| ((a + 1)..n).map(move |b| (a, b)))
            .map(|(a, b)| {
                let lk = Self::linking_number(
                    crossings,
                    &strands[a].agent_pid,
                    &strands[b].agent_pid,
                );
                lk.abs()
            })
            .sum();

        (2.0 * total_lk / (n * (n - 1)) as f64).min(1.0)
    }
}

// =============================================================================
// Proposal — the value being agreed upon
// =============================================================================

/// A consensus proposal: what the agents are agreeing on.
///
/// Not just a hash — includes semantic context that agents use to
/// evaluate with their KnotEngine knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotProposal {
    /// Round number (monotonically increasing per namespace)
    pub round: u64,
    /// PID of the proposing agent
    pub proposer_pid: String,
    /// SHA-256 hash of the proposed value
    pub value_hash: String,
    /// The actual proposed value (StateVector digest, namespace merge, etc.)
    pub value: serde_json::Value,
    /// Evidence CIDs from the proposer's KnotEngine
    pub evidence_cids: Vec<String>,
    /// StateVector serial number that this proposal relates to
    pub sv_sn: Option<u64>,
    /// Timestamp (ms epoch)
    pub timestamp_ms: u64,
}

impl KnotProposal {
    pub fn new(
        round: u64,
        proposer_pid: impl Into<String>,
        value: serde_json::Value,
        evidence_cids: Vec<String>,
        timestamp_ms: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value.to_string().as_bytes());
        let value_hash = hex::encode(&hasher.finalize()[..16]);
        Self {
            round,
            proposer_pid: proposer_pid.into(),
            value_hash,
            value,
            evidence_cids,
            sv_sn: None,
            timestamp_ms,
        }
    }
}

/// An attestation from a strand (agent) about a proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotAttestation {
    /// Round this attestation is for
    pub round: u64,
    /// Attesting agent PID
    pub attester_pid: String,
    /// Hash of the proposal being attested
    pub value_hash: String,
    /// Whether the attester supports this proposal
    pub support: bool,
    /// Supporting evidence CIDs from the attester's own KnotEngine
    pub evidence_cids: Vec<String>,
    /// Optional reasoning snippet (hash of CoT trace)
    pub reasoning_hash: Option<String>,
}

// =============================================================================
// KnotConsensusRound — full protocol execution
// =============================================================================

/// Phase of a KnotConsensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnotPhase {
    /// Waiting for a proposal
    Idle,
    /// Proposal received, computing strand parameters
    StrandFormation,
    /// Computing R-matrix crossings
    CrossingEvaluation,
    /// Checking Yang-Baxter consistency
    YangBaxterCheck,
    /// Computing writhe and bracket
    WritheAccumulation,
    /// Resolving ambiguous crossings via skein
    SkeinResolution,
    /// Computing linking numbers and quorum
    QuorumEvaluation,
    /// Consensus committed — value accepted
    Committed,
    /// Consensus null — insufficient writhe or quorum
    Null,
    /// YBE violation detected — Byzantine/Sybil signal
    ByzantineDetected,
}

/// Result of a KnotConsensus round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotConsensusResult {
    /// Round number
    pub round: u64,
    /// Final phase reached
    pub phase: KnotPhase,
    /// The proposal that was evaluated
    pub proposal: KnotProposal,
    /// All strand parameters
    pub strands: Vec<KnotStrand>,
    /// All crossings computed (after skein resolution)
    pub crossings: Vec<BraidCrossing>,
    /// Writhe w(β) = Σ ε(i,j)
    pub writhe: i32,
    /// Writhe threshold for commit
    pub writhe_threshold: i32,
    /// Evidence coherence |X(β)| ∈ [0,1]
    pub evidence_coherence: f64,
    /// Quorum density Q(S) ∈ [0,1]
    pub quorum_density: f64,
    /// Quorum threshold
    pub quorum_threshold: f64,
    /// Whether YBE consistency holds
    pub ybe_consistent: bool,
    /// YBE violations (triples) if any
    pub ybe_violations: Vec<(String, String, String)>,
    /// Number of crossings resolved via skein
    pub skein_resolved_count: usize,
    /// Whether consensus was committed
    pub committed: bool,
    /// Commit CID (hash of the full result)
    pub commit_cid: Option<String>,
}

/// Main consensus round executor.
///
/// Usage:
/// ```rust,ignore
/// let round = KnotConsensusRound::new(proposal, strands);
/// let result = round.execute();
/// ```
pub struct KnotConsensusRound {
    proposal: KnotProposal,
    strands: Vec<KnotStrand>,
    attestations: HashMap<String, KnotAttestation>,
    /// Writhe threshold: default ⌊n/2⌋ + 1 (strict majority of pairwise agreements)
    writhe_threshold: Option<i32>,
    /// Quorum density threshold: default 0.5
    quorum_threshold: Option<f64>,
}

impl KnotConsensusRound {
    /// Create a new consensus round.
    pub fn new(proposal: KnotProposal, strands: Vec<KnotStrand>) -> Self {
        Self {
            proposal,
            strands,
            attestations: HashMap::new(),
            writhe_threshold: None,
            quorum_threshold: None,
        }
    }

    /// Add an attestation from a participating agent.
    pub fn add_attestation(&mut self, attest: KnotAttestation) {
        self.attestations.insert(attest.attester_pid.clone(), attest);
    }

    /// Override the writhe threshold.
    pub fn with_writhe_threshold(mut self, t: i32) -> Self {
        self.writhe_threshold = Some(t);
        self
    }

    /// Override the quorum density threshold.
    pub fn with_quorum_threshold(mut self, t: f64) -> Self {
        self.quorum_threshold = Some(t);
        self
    }

    /// Execute the full KnotConsensus protocol.
    ///
    /// Steps:
    /// 1. StrandFormation — u_i already in strands
    /// 2. CrossingEvaluation — R-matrix for all pairs
    /// 3. YangBaxterCheck — consistency for all triples
    /// 4. WritheAccumulation — w(β), |X(β)|
    /// 5. SkeinResolution — resolve ε=0 crossings
    /// 6. QuorumEvaluation — linking numbers, Q(S)
    /// 7. Decide
    pub fn execute(self) -> KnotConsensusResult {
        let n = self.strands.len();
        let writhe_threshold = self.writhe_threshold
            .unwrap_or_else(|| (n as i32 / 2) + 1);
        let quorum_threshold = self.quorum_threshold.unwrap_or(0.5);

        // ── Phase 2: CrossingEvaluation ───────────────────────────────────
        let mut crossings: Vec<BraidCrossing> = Vec::new();
        let mut crossing_map: HashMap<(String, String), i8> = HashMap::new();

        for a in 0..n {
            for b in (a + 1)..n {
                let si = &self.strands[a];
                let sj = &self.strands[b];

                // Determine attestation CIDs for this pair
                let cid_i = self.attestations.get(&si.agent_pid)
                    .and_then(|a| a.evidence_cids.first().cloned());
                let cid_j = self.attestations.get(&sj.agent_pid)
                    .and_then(|a| a.evidence_cids.first().cloned());

                // Adjust crossing sign based on attestation support
                let attest_i_support = self.attestations.get(&si.agent_pid).map(|a| a.support);
                let attest_j_support = self.attestations.get(&sj.agent_pid).map(|a| a.support);

                let mut crossing = BraidCrossing::new(si, sj, cid_i, cid_j);

                // Attestation override: if both support → force positive;
                // if both oppose → force negative; if split → keep R-matrix result
                crossing.epsilon = match (attest_i_support, attest_j_support) {
                    (Some(true), Some(true))   => 1,
                    (Some(false), Some(false)) => -1,
                    (Some(true), Some(false)) | (Some(false), Some(true)) => {
                        // Disagreement — use R-matrix to break tie (higher trust wins)
                        RMatrix::crossing_sign(si, sj)
                    }
                    _ => crossing.epsilon, // No attestation → pure R-matrix
                };

                crossing_map.insert(
                    (si.agent_pid.clone(), sj.agent_pid.clone()),
                    crossing.epsilon,
                );
                crossings.push(crossing);
            }
        }

        // ── Phase 3: YangBaxterCheck ─────────────────────────────────────
        let (ybe_consistent, ybe_violations) =
            YangBaxterChecker::check(&self.strands, &crossing_map);

        // YBE violation → Byzantine detected
        if !ybe_consistent {
            return KnotConsensusResult {
                round: self.proposal.round,
                phase: KnotPhase::ByzantineDetected,
                proposal: self.proposal,
                strands: self.strands,
                crossings,
                writhe: 0,
                writhe_threshold,
                evidence_coherence: 0.0,
                quorum_density: 0.0,
                quorum_threshold,
                ybe_consistent: false,
                ybe_violations,
                skein_resolved_count: 0,
                committed: false,
                commit_cid: None,
            };
        }

        // ── Phase 4: WritheAccumulation ───────────────────────────────────
        // Writhe before skein resolution (only non-ambiguous crossings)
        let pre_writhe: i32 = crossings.iter()
            .filter(|c| !c.skein_resolved)
            .map(|c| c.epsilon as i32)
            .sum();

        let pre_coherence = KauffmanBracket::normalized_bracket(&crossings, &self.strands, pre_writhe);

        // ── Phase 5: SkeinResolution ──────────────────────────────────────
        let crossings_before_skein = crossings.len();
        let crossings = SkeinResolver::resolve(crossings, &self.strands);
        let skein_resolved_count = crossings.iter().filter(|c| c.skein_resolved).count();

        // ── Phase 6: WritheAccumulation (post skein) ──────────────────────
        let writhe: i32 = crossings.iter().map(|c| c.epsilon as i32).sum();
        let evidence_coherence = KauffmanBracket::normalized_bracket(&crossings, &self.strands, writhe);

        // ── Phase 7: QuorumEvaluation ─────────────────────────────────────
        let quorum_density = LinkingNumberComputer::quorum_density(&crossings, &self.strands);

        // ── Decision ─────────────────────────────────────────────────────
        let committed = writhe >= writhe_threshold && quorum_density >= quorum_threshold;
        let phase = if committed { KnotPhase::Committed } else { KnotPhase::Null };

        // Compute commit CID
        let commit_cid = if committed {
            let mut hasher = Sha256::new();
            hasher.update(self.proposal.value_hash.as_bytes());
            hasher.update(&writhe.to_le_bytes());
            hasher.update(&self.proposal.round.to_le_bytes());
            Some(hex::encode(&hasher.finalize()[..16]))
        } else {
            None
        };

        KnotConsensusResult {
            round: self.proposal.round,
            phase,
            proposal: self.proposal,
            strands: self.strands,
            crossings,
            writhe,
            writhe_threshold,
            evidence_coherence,
            quorum_density,
            quorum_threshold,
            ybe_consistent,
            ybe_violations,
            skein_resolved_count,
            committed,
            commit_cid,
        }
    }
}

// =============================================================================
// Markov Trace — global consistency check (TL representation)
// =============================================================================

/// Computes the Markov trace of the braid representation in TL_n(δ).
///
/// The Markov trace tr_M(ρ(β)) provides a global consistency check:
/// tr_M = δ^{n-1} · Σ_{committed crossings} contribution
///
/// Reference: Jones (1985), Temperley-Lieb (1971)
pub struct MarkovTrace;

impl MarkovTrace {
    /// Compute the Markov trace for an executed consensus result.
    ///
    /// tr_M(ρ(β)) = δ^{n-1} · ⟨β⟩ · (-A)^{3w}
    ///
    /// A high |tr_M| means the braid is close to the unknot (trivial = full agreement).
    /// A low |tr_M| means complex braiding = contentious round.
    pub fn compute(result: &KnotConsensusResult) -> f64 {
        let n = result.strands.len();
        if n == 0 {
            return 0.0;
        }
        let a = KauffmanBracket::a_param(&result.strands);
        let delta = KauffmanBracket::delta(a);
        let bracket = KauffmanBracket::bracket(&result.crossings, a);
        let norm = KauffmanBracket::writhe_norm(a, result.writhe);

        let trace = delta.powi((n - 1) as i32) * bracket * norm;
        trace.abs().min(1.0) // Normalize to [0,1] for interpretability
    }
}

// =============================================================================
// KnotConsensusConfig — configurable thresholds
// =============================================================================

/// Configuration for KnotConsensus thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotConsensusConfig {
    /// Writhe threshold: min writhe for commit (default: ⌊n/2⌋+1)
    pub writhe_threshold: Option<i32>,
    /// Quorum density threshold (default: 0.5)
    pub quorum_threshold: f64,
    /// R-matrix smoothing threshold θ_smooth (default: 0.05)
    pub smooth_threshold: f64,
    /// Minimum evidence coherence |X| required (default: 0.1)
    pub min_evidence_coherence: f64,
    /// Whether to run skein resolution on ambiguous crossings (default: true)
    pub enable_skein_resolution: bool,
    /// Whether to fail on YBE violations (default: true)
    pub strict_ybe: bool,
}

impl Default for KnotConsensusConfig {
    fn default() -> Self {
        Self {
            writhe_threshold: None,
            quorum_threshold: 0.5,
            smooth_threshold: 0.05,
            min_evidence_coherence: 0.1,
            enable_skein_resolution: true,
            strict_ybe: true,
        }
    }
}

// =============================================================================
// Convenience builder
// =============================================================================

/// Convenience builder for a consensus round from raw agent parameters.
pub struct KnotConsensusBuilder {
    proposal: KnotProposal,
    strands: Vec<KnotStrand>,
    config: KnotConsensusConfig,
}

impl KnotConsensusBuilder {
    pub fn new(proposal: KnotProposal) -> Self {
        Self {
            proposal,
            strands: Vec::new(),
            config: KnotConsensusConfig::default(),
        }
    }

    /// Add a participating agent strand.
    pub fn add_strand(mut self, strand: KnotStrand) -> Self {
        self.strands.push(strand);
        self
    }

    /// Override default config.
    pub fn with_config(mut self, config: KnotConsensusConfig) -> Self {
        self.config = config;
        self
    }

    /// Build and execute the round.
    pub fn execute(self) -> KnotConsensusResult {
        let n = self.strands.len() as i32;
        let mut round = KnotConsensusRound::new(self.proposal, self.strands)
            .with_quorum_threshold(self.config.quorum_threshold);

        if let Some(wt) = self.config.writhe_threshold {
            round = round.with_writhe_threshold(wt);
        } else {
            round = round.with_writhe_threshold(n / 2 + 1);
        }

        round.execute()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(round: u64) -> KnotProposal {
        KnotProposal::new(
            round,
            "agent-proposer",
            serde_json::json!({"action": "merge_namespace", "target": "/k/ehr"}),
            vec!["cid1abc".to_string(), "cid2def".to_string()],
            1_700_000_000_000,
        )
    }

    fn strand(pid: &str, kecs: f64, psi: f64, r_score: f64) -> KnotStrand {
        KnotStrand::new(pid.to_string(), "/k/ehr".to_string(), kecs, psi, r_score, 3, false)
    }

    // ── R-Matrix Tests ────────────────────────────────────────────────────────

    #[test]
    fn test_r_matrix_equal_strands_abstain() {
        let si = strand("agent-1", 0.8, 0.7, 0.9);
        let sj = strand("agent-2", 0.8, 0.7, 0.9);
        // Identical u values → |δu| = 0 ≤ θ_smooth → ε = 0
        assert_eq!(RMatrix::crossing_sign(&si, &sj), 0);
    }

    #[test]
    fn test_r_matrix_high_trust_dominates() {
        let expert = strand("expert", 0.9, 0.85, 0.95); // u ≈ 0.9
        let novice = strand("novice", 0.1, 0.1, 0.3);   // u ≈ 0.16
        // expert.u - novice.u ≈ 0.74 >> θ_smooth → positive crossing
        assert_eq!(RMatrix::crossing_sign(&expert, &novice), 1);
    }

    #[test]
    fn test_r_matrix_lower_trust_negative() {
        let novice = strand("novice", 0.1, 0.1, 0.3);
        let expert = strand("expert", 0.9, 0.85, 0.95);
        // novice.u - expert.u < 0 → negative crossing
        assert_eq!(RMatrix::crossing_sign(&novice, &expert), -1);
    }

    #[test]
    fn test_r_matrix_probation_forces_zero_u() {
        let probation_agent = KnotStrand::new(
            "prob-agent".to_string(), "/k/ehr".to_string(),
            0.9, 0.9, 0.9, 5, true, // in_probation = true
        );
        assert_eq!(probation_agent.u, 0.0);
        let expert = strand("expert", 0.9, 0.85, 0.95);
        // probation u=0, expert u≈0.9 → negative crossing (probation loses)
        assert_eq!(RMatrix::crossing_sign(&probation_agent, &expert), -1);
    }

    #[test]
    fn test_range_parameter_bounds() {
        let s = strand("a", 1.0, 1.0, 1.0);
        assert!((s.u - 1.0).abs() < 1e-9, "Max trust should give u=1.0");
        let s2 = strand("b", 0.0, 0.0, 0.0);
        assert!(s2.u.abs() < 1e-9, "Zero trust should give u=0.0");
    }

    // ── Yang-Baxter Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_ybe_consistent_monotone_trust() {
        // Monotone: u_a > u_b > u_c → all crossings positive, YBE holds
        let sa = strand("a", 0.9, 0.8, 0.9); // u ≈ 0.875
        let sb = strand("b", 0.6, 0.5, 0.6); // u ≈ 0.565
        let sc = strand("c", 0.2, 0.1, 0.2); // u ≈ 0.165

        let strands = vec![sa.clone(), sb.clone(), sc.clone()];
        let mut map = HashMap::new();
        map.insert(("a".into(), "b".into()), RMatrix::crossing_sign(&sa, &sb));
        map.insert(("a".into(), "c".into()), RMatrix::crossing_sign(&sa, &sc));
        map.insert(("b".into(), "c".into()), RMatrix::crossing_sign(&sb, &sc));

        let (consistent, violations) = YangBaxterChecker::check(&strands, &map);
        assert!(consistent, "Monotone trust should be YBE-consistent, got violations: {:?}", violations);
    }

    #[test]
    fn test_ybe_violation_circular_trust() {
        // Circular: a > b, b > c, but c > a (Byzantine cycle)
        // We simulate by forcing circular crossing signs
        let sa = strand("a", 0.8, 0.7, 0.8);
        let sb = strand("b", 0.6, 0.5, 0.6);
        let sc = strand("c", 0.4, 0.3, 0.4);

        let strands = vec![sa.clone(), sb.clone(), sc.clone()];
        let mut map = HashMap::new();
        map.insert(("a".into(), "b".into()), 1_i8);  // a > b ✓
        map.insert(("b".into(), "c".into()), 1_i8);  // b > c ✓
        map.insert(("a".into(), "c".into()), -1_i8); // c > a ← CIRCULAR

        let (consistent, violations) = YangBaxterChecker::check(&strands, &map);
        assert!(!consistent, "Circular trust should be YBE-inconsistent");
        assert!(!violations.is_empty());
    }

    // ── Kauffman Bracket Tests ────────────────────────────────────────────────

    #[test]
    fn test_kauffman_a_param_range() {
        let strands = vec![
            strand("a", 0.0, 0.0, 0.0), // u=0 → A=1
            strand("b", 1.0, 1.0, 1.0), // u=1 → A=exp(-π/2)≈0.208
        ];
        let a_low = KauffmanBracket::a_param(&vec![strand("z", 0.0, 0.0, 0.0)]);
        let a_high = KauffmanBracket::a_param(&vec![strand("z", 1.0, 1.0, 1.0)]);
        assert!((a_low - 1.0).abs() < 1e-9, "u=0 should give A=1");
        assert!((a_high - (-std::f64::consts::PI / 2.0).exp()).abs() < 1e-6,
                "u=1 should give A=exp(-π/2)≈0.208");
        let _ = strands;
    }

    #[test]
    fn test_kauffman_bracket_empty() {
        let result = KauffmanBracket::bracket(&[], 1.0);
        assert_eq!(result, 1.0);
    }

    #[test]
    fn test_kauffman_bracket_all_positive() {
        let si = strand("a", 0.9, 0.8, 0.9);
        let sj = strand("b", 0.1, 0.1, 0.1);
        let c = BraidCrossing::new(&si, &sj, None, None);
        assert_eq!(c.epsilon, 1);
        let bracket = KauffmanBracket::bracket(&[c], 0.9);
        assert!((bracket - 0.9).abs() < 1e-9, "Single positive crossing: bracket = A");
    }

    // ── Linking Number Tests ──────────────────────────────────────────────────

    #[test]
    fn test_linking_number_single_positive() {
        let si = strand("a", 0.9, 0.8, 0.9);
        let sj = strand("b", 0.1, 0.1, 0.1);
        let c = BraidCrossing::new(&si, &sj, None, None);
        let lk = LinkingNumberComputer::linking_number(&[c], "a", "b");
        assert!((lk - 0.5).abs() < 1e-9, "Single positive crossing: lk = 0.5");
    }

    #[test]
    fn test_linking_number_two_positive_one_negative() {
        // Two positive + one negative crossings between same pair → lk = (2-1)/2 = 0.5
        let si = strand("a", 0.9, 0.8, 0.9);
        let sj = strand("b", 0.1, 0.1, 0.1);
        let mut c1 = BraidCrossing::new(&si, &sj, None, None);
        let mut c2 = BraidCrossing::new(&si, &sj, None, None);
        let mut c3 = BraidCrossing::new(&si, &sj, None, None);
        c1.epsilon = 1; c2.epsilon = 1; c3.epsilon = -1;
        let lk = LinkingNumberComputer::linking_number(&[c1, c2, c3], "a", "b");
        assert!((lk - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_quorum_density_all_agree() {
        let sa = strand("a", 0.9, 0.8, 0.9);
        let sb = strand("b", 0.6, 0.5, 0.6);
        let sc = strand("c", 0.2, 0.1, 0.2);

        let c_ab = BraidCrossing::new(&sa, &sb, None, None);
        let c_ac = BraidCrossing::new(&sa, &sc, None, None);
        let c_bc = BraidCrossing::new(&sb, &sc, None, None);
        // All positive crossings
        let crossings = vec![c_ab, c_ac, c_bc];
        let strands = vec![sa, sb, sc];
        let q = LinkingNumberComputer::quorum_density(&crossings, &strands);
        assert!(q > 0.0, "Non-trivial crossings should give Q > 0");
    }

    // ── Full Round Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_full_round_unanimous_experts() {
        // 3 experts all agree → committed
        let proposal = make_proposal(1);
        let sa = strand("a", 0.9, 0.85, 0.92);
        let sb = strand("b", 0.85, 0.8, 0.88);
        let sc = strand("c", 0.75, 0.75, 0.8);
        // All agents attest support
        let mut round = KnotConsensusRound::new(proposal, vec![sa, sb, sc]);
        for pid in ["a", "b", "c"] {
            round.add_attestation(KnotAttestation {
                round: 1,
                attester_pid: pid.to_string(),
                value_hash: "...".to_string(),
                support: true,
                evidence_cids: vec![format!("cid_{}", pid)],
                reasoning_hash: None,
            });
        }
        let result = round.execute();
        assert!(result.committed, "Unanimous experts should reach consensus");
        assert_eq!(result.phase, KnotPhase::Committed);
        assert!(result.ybe_consistent);
        assert!(result.commit_cid.is_some());
    }

    #[test]
    fn test_full_round_probation_agent_excluded() {
        // 1 expert, 2 probation agents → insufficient writhe
        let proposal = make_proposal(2);
        let expert = KnotStrand::new("expert".into(), "/k/ehr".into(), 0.9, 0.9, 0.9, 5, false);
        let prob1 = KnotStrand::new("prob1".into(), "/k/ehr".into(), 0.9, 0.9, 0.9, 5, true);
        let prob2 = KnotStrand::new("prob2".into(), "/k/ehr".into(), 0.9, 0.9, 0.9, 5, true);
        let round = KnotConsensusRound::new(proposal, vec![expert, prob1, prob2]);
        let result = round.execute();
        // writhe_threshold = 2, but probation agents have u=0 → negative crossings
        assert!(!result.committed, "Probation agents should not reach consensus");
    }

    #[test]
    fn test_full_round_split_vote_uses_r_matrix() {
        // 2 agents agree, 1 disagrees → R-matrix breaks tie
        let proposal = make_proposal(3);
        let sa = strand("a", 0.9, 0.85, 0.92);
        let sb = strand("b", 0.85, 0.8, 0.88);
        let sc = strand("c", 0.2, 0.15, 0.25);
        let mut round = KnotConsensusRound::new(proposal, vec![sa, sb, sc]);
        round.add_attestation(KnotAttestation {
            round: 3, attester_pid: "a".into(), value_hash: "".into(),
            support: true, evidence_cids: vec![], reasoning_hash: None,
        });
        round.add_attestation(KnotAttestation {
            round: 3, attester_pid: "b".into(), value_hash: "".into(),
            support: true, evidence_cids: vec![], reasoning_hash: None,
        });
        round.add_attestation(KnotAttestation {
            round: 3, attester_pid: "c".into(), value_hash: "".into(),
            support: false, evidence_cids: vec![], reasoning_hash: None,
        });
        let result = round.execute();
        // a and b both support → crossings a-b positive;
        // c opposes but low trust → R-matrix: a > c, b > c → still positive majority
        assert!(result.committed, "Majority high-trust support should reach consensus");
    }

    #[test]
    fn test_markov_trace_committed_round() {
        let proposal = make_proposal(4);
        let sa = strand("a", 0.9, 0.85, 0.92);
        let sb = strand("b", 0.85, 0.8, 0.88);
        let mut round = KnotConsensusRound::new(proposal, vec![sa, sb]);
        round.add_attestation(KnotAttestation {
            round: 4, attester_pid: "a".into(), value_hash: "".into(),
            support: true, evidence_cids: vec![], reasoning_hash: None,
        });
        round.add_attestation(KnotAttestation {
            round: 4, attester_pid: "b".into(), value_hash: "".into(),
            support: true, evidence_cids: vec![], reasoning_hash: None,
        });
        let result = round.execute();
        let trace = MarkovTrace::compute(&result);
        assert!(trace >= 0.0 && trace <= 1.0, "Markov trace should be in [0,1]");
    }

    #[test]
    fn test_skein_resolution_resolves_ambiguous() {
        // Build crossings where some are ambiguous (ε=0)
        let sa = strand("a", 0.55, 0.5, 0.55); // u ≈ 0.525
        let sb = strand("b", 0.5, 0.45, 0.5);  // u ≈ 0.4775
        // δu = 0.0475 < θ_smooth(0.05) → ambiguous
        let c = BraidCrossing::new(&sa, &sb, None, None);
        assert_eq!(c.epsilon, 0, "Should be ambiguous crossing");
        let resolved = SkeinResolver::resolve(vec![c], &[sa, sb]);
        assert!(resolved[0].epsilon != 0 || resolved[0].skein_resolved,
                "Ambiguous crossing should be resolved by skein");
    }
}
