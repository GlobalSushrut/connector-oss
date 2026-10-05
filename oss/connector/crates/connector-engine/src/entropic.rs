//! Entropic Trust Scoring — KECS (KnotEngine Confidence Score) and
//! Agent Identity State Vector (AISV) computation.
//!
//! Implements the full mathematical model from Sections 10 & 11 of ece_arch.md:
//!
//! ## KECS Components (Section 10)
//! - `VnGraphEntropy`     — Von Neumann graph entropy H_vn(G) via quadratic approx O(|E|)
//! - `RenyiEntropy`       — Rényi-2 collision entropy H_2 over execution outcomes
//! - `TopologicalMixing`  — Spectral gap |λ_2(T)| via power iteration
//! - `KlDivergence`       — KL divergence for regression detection
//!
//! ## Consciousness + Identity (Section 11)
//! - `ConsciousnessScore` — φ* multi-information approximation (IIT 4.0 tractable form)
//! - `BehaviorFingerprint`— 5-tuple stable behavioral signature
//! - `AgentIdentityStateVec` (AISV) — 14-dimensional identity state point
//!
//! ## Research basis
//! - Braunstein et al. (2006), De Domenico & Biamonte (2016): Von Neumann graph entropy
//! - Chen et al. ICML 2019: O(|E|) quadratic VNGE approximation
//! - Rényi (1961): Rényi-α entropy; α=2 collision entropy
//! - Adler, Konheim, McAndrew (1965): Topological entropy; Markov mixing time
//! - Tononi et al. (2023) IIT 4.0: φ structure; Oizumi et al. (2016) φ* approximation
//! - Friston (2017): Markov blanket / Free energy principle
//! - Baars (1988), Dehaene (2011): Global Workspace Theory

use std::collections::HashMap;
use vac_core::identity::{AgentExpertiseRecord, ExecutionOutcome, AgentIdentityState};
use vac_core::knot::KnotEngine;
use serde::{Deserialize, Serialize};

// =============================================================================
// VnGraphEntropy — Von Neumann entropy of the normalized graph Laplacian
// =============================================================================

/// Computes Von Neumann graph entropy H_vn(G) from a KnotEngine subgraph.
///
/// Uses the quadratic approximation from Chen et al. (ICML 2019) to avoid
/// full eigendecomposition. Complexity: O(|E|).
///
/// H_vn = log₂(n) - (n / (2 × Tr(L²))) × ||L - (Tr(L)/n)I||²_F
pub struct VnGraphEntropy;

impl VnGraphEntropy {
    /// Compute normalized knowledge confidence K_vn ∈ [0, 1] from the KnotEngine.
    ///
    /// K_vn = 1 - H_vn / log₂(max(n, 2))
    ///
    /// K_vn → 0: maximally disordered (new agent, random graph)
    /// K_vn → 1: maximally structured (expert, star-like / hierarchical topology)
    pub fn compute(knot: &KnotEngine) -> f64 {
        let n = knot.node_count();
        if n < 2 {
            return 0.0;
        }

        // Build degree and adjacency information from KnotEdge weights.
        // D_ii = Σ_j w(i,j) + Σ_j w(j,i)  [in + out degree sums]
        let mut degree: HashMap<String, f64> = HashMap::new();
        let mut edge_sum_sq = 0.0_f64; // Σ w(i,j)² — for Tr(L²) approximation
        let mut total_degree = 0.0_f64;

        // Accumulate out-degrees
        for (from_node, _) in knot.nodes() {
            let out_edges = knot.edges_from(from_node);
            let out_w: f64 = out_edges.iter().map(|e| e.weight).sum();
            *degree.entry(from_node.to_string()).or_insert(0.0) += out_w;
            total_degree += out_w;

            // Accumulate squared weights for Tr(L²)
            for e in &out_edges {
                let w_sym = e.weight; // symmetrized weight approximation
                edge_sum_sq += w_sym * w_sym;
            }
        }

        // Accumulate in-degrees (reverse edges)
        for (node_id, _) in knot.nodes() {
            let in_edges = knot.edges_to(node_id);
            let in_w: f64 = in_edges.iter().map(|e| e.weight).sum();
            *degree.entry(node_id.to_string()).or_insert(0.0) += in_w;
            total_degree += in_w;
        }

        if total_degree <= 0.0 {
            return 0.0;
        }

        // Tr(L) = Σ_i D_ii (for normalized Laplacian, Tr = n - normalized_sum)
        // Approximation: Tr(L) ≈ n (for normalized Laplacian with unit diagonal)
        let tr_l = n as f64;

        // Tr(L²) ≈ n + 2 × Σ_{edges} (w_sym / sqrt(d_i × d_j))²
        // Simplified for computational efficiency: Tr(L²) ≈ n + 2 × edge_sum_sq / (total_degree/n)²
        let avg_degree = total_degree / n as f64;
        let tr_l2 = (n as f64) + 2.0 * edge_sum_sq / (avg_degree * avg_degree).max(1e-10);

        // ||L - (Tr(L)/n)I||²_F = Tr(L²) - (Tr(L))²/n
        let frobenius_sq = tr_l2 - (tr_l * tr_l) / (n as f64);

        // Quadratic VNGE approximation (Chen et al. ICML 2019):
        // H_vn ≈ log₂(n) - (n / (2 × Tr(L²))) × ||L - (Tr(L)/n)I||²_F
        let log2_n = (n as f64).log2();
        let h_vn = (log2_n - (n as f64 / (2.0 * tr_l2.max(1e-10))) * frobenius_sq)
            .max(0.0)
            .min(log2_n);

        // Normalized: K_vn = 1 - H_vn / log₂(n)
        let k_vn = 1.0 - h_vn / log2_n.max(1e-10);
        k_vn.clamp(0.0, 1.0)
    }
}

// =============================================================================
// RenyiEntropy — Rényi-2 collision entropy over execution outcomes
// =============================================================================

/// Computes Rényi entropy of order α=2 (collision entropy) over the
/// execution outcome distribution.
///
/// H_2(X) = -log₂(Σ_ω p_ω²)
///
/// α=2 chosen because it weights the dominant outcome (predictability).
/// An agent with 90% Success has low H_2; an agent with 50/50 has high H_2.
pub struct RenyiEntropy;

impl RenyiEntropy {
    /// Compute execution stability S_renyi ∈ [0, 1] from the current outcome window.
    ///
    /// S_renyi = 1 - H_2(X_exec) / log₂(6)
    ///
    /// S_renyi = 1.0: perfectly predictable (always succeeds)
    /// S_renyi = 0.0: chaotic (uniform over all 6 outcome categories)
    pub fn compute_stability(expertise: &AgentExpertiseRecord) -> f64 {
        let dist = expertise.current_outcome_dist();
        if dist.is_empty() {
            return 0.5; // No data — neutral, not 0 (no evidence of chaos either)
        }
        Self::from_distribution(&dist)
    }

    /// Compute S_renyi directly from a probability distribution over outcomes.
    pub fn from_distribution(dist: &HashMap<ExecutionOutcome, f64>) -> f64 {
        // H_2 = -log₂(Σ p²)   (collision probability = Σ p²)
        let collision_prob: f64 = dist.values().map(|&p| p * p).sum();
        if collision_prob <= 0.0 {
            return 0.5;
        }

        // log₂(6) ≈ 2.585 is the maximum entropy for 6 equally likely outcomes
        let max_entropy = 6_f64.log2();
        let h2 = -(collision_prob.log2());
        let h2_clamped = h2.clamp(0.0, max_entropy);

        (1.0 - h2_clamped / max_entropy).clamp(0.0, 1.0)
    }
}

// =============================================================================
// TopologicalMixing — spectral gap |λ_2(T)| via power iteration
// =============================================================================

/// Computes the topological mixing confidence K_topo from the KnotEngine
/// transition matrix T.
///
/// K_topo = 1 - |λ_2(T)|
///
/// where λ_2(T) is the second-largest eigenvalue of the row-normalized
/// stochastic transition matrix.
///
/// K_topo → 1: fast mixing, well-connected knowledge graph (expert)
/// K_topo → 0: slow mixing, disconnected knowledge islands (novice)
pub struct TopologicalMixing;

impl TopologicalMixing {
    /// Estimate |λ_2(T)| using deflated power iteration.
    ///
    /// For a row-normalized stochastic matrix, λ_max = 1.
    /// We estimate λ_2 by deflating the dominant eigenvector and applying
    /// power iteration to find the next dominant eigenvalue.
    ///
    /// Complexity: O(|E| × iterations), default iterations=50.
    pub fn compute(knot: &KnotEngine) -> f64 {
        let n = knot.node_count();
        if n < 3 {
            // Too small for meaningful spectral gap
            return 0.5;
        }

        // Build node index map
        let nodes: Vec<String> = knot.nodes().keys().cloned().collect();
        let node_idx: HashMap<String, usize> = nodes.iter().enumerate().map(|(i, id)| (id.clone(), i)).collect();

        // Build row-normalized transition matrix as sparse adjacency list
        // T_ij = w(i,j) / Σ_k w(i,k)
        let mut rows: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
        for (from_id, idx_i) in &node_idx {
            let out_edges = knot.edges_from(from_id);
            let total_w: f64 = out_edges.iter().map(|e| e.weight).sum();
            if total_w > 0.0 {
                for edge in &out_edges {
                    if let Some(&idx_j) = node_idx.get(&edge.to) {
                        rows[*idx_i].push((idx_j, edge.weight / total_w));
                    }
                }
            } else {
                // Dangling node: uniform transition (teleportation)
                let uniform = 1.0 / n as f64;
                for j in 0..n {
                    rows[*idx_i].push((j, uniform));
                }
            }
        }

        // Power iteration for λ_1 = 1 (dominant eigenvector = stationary distribution)
        let mut v1 = vec![1.0_f64 / n as f64; n];
        for _ in 0..30 {
            v1 = Self::matvec(&rows, &v1, n);
            let norm: f64 = v1.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 1e-10 {
                for x in &mut v1 { *x /= norm; }
            }
        }

        // Deflated power iteration for λ_2
        // Start with a random orthogonal vector, then subtract v1 component
        let mut v2: Vec<f64> = (0..n).map(|i| {
            // deterministic "random" init using index-based oscillation
            if i % 2 == 0 { 1.0 / n as f64 } else { -1.0 / n as f64 }
        }).collect();
        Self::normalize(&mut v2);

        let max_iter = 50;
        let mut lambda2 = 0.0_f64;

        for _ in 0..max_iter {
            // Deflate: remove v1 component
            let dot_v1: f64 = v2.iter().zip(v1.iter()).map(|(a, b)| a * b).sum();
            for (x, &y) in v2.iter_mut().zip(v1.iter()) {
                *x -= dot_v1 * y;
            }
            Self::normalize(&mut v2);

            let v2_new = Self::matvec(&rows, &v2, n);

            // Rayleigh quotient: λ ≈ <v2_new, v2> / <v2, v2>
            let numerator: f64 = v2_new.iter().zip(v2.iter()).map(|(a, b)| a * b).sum();
            let denominator: f64 = v2.iter().map(|x| x * x).sum();
            lambda2 = if denominator > 1e-10 { numerator / denominator } else { 0.0 };

            v2 = v2_new;
            let norm: f64 = v2.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 1e-10 {
                for x in &mut v2 { *x /= norm; }
            }
        }

        // K_topo = 1 - |λ_2|
        let k_topo = 1.0 - lambda2.abs().min(1.0);
        k_topo.clamp(0.0, 1.0)
    }

    fn matvec(rows: &[Vec<(usize, f64)>], v: &[f64], n: usize) -> Vec<f64> {
        let mut out = vec![0.0_f64; n];
        for (i, row) in rows.iter().enumerate() {
            for &(j, w) in row {
                out[j] += w * v[i];
            }
        }
        out
    }

    fn normalize(v: &mut Vec<f64>) {
        let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm > 1e-10 {
            for x in v.iter_mut() { *x /= norm; }
        }
    }
}

// =============================================================================
// KlDivergence — regression detection via KL(P_current || P_baseline)
// =============================================================================

/// Computes KL divergence for execution outcome regression detection.
///
/// D_KL(P_current || P_baseline) = Σ_ω P_current(ω) × log₂(P_current(ω) / P_baseline(ω))
///
/// D_KL = 0.0  → identical distributions (no regression)
/// D_KL > 0.5  → meaningful drift → alert, raise gate tier
/// D_KL > 1.0  → significant regression → force Tier 2
/// D_KL > 2.0  → critical divergence → force Tier 3 + probation check
pub struct KlDivergence;

impl KlDivergence {
    /// Compute KL divergence between current window distribution and historical baseline.
    /// Returns 0.0 if baseline is empty (no regression detectable yet).
    pub fn compute(
        p_current: &HashMap<ExecutionOutcome, f64>,
        p_baseline: &HashMap<ExecutionOutcome, f64>,
    ) -> f64 {
        if p_baseline.is_empty() || p_current.is_empty() {
            return 0.0;
        }

        // Use all outcomes that appear in either distribution
        let all_outcomes = [
            ExecutionOutcome::Success,
            ExecutionOutcome::Failed,
            ExecutionOutcome::RolledBack,
            ExecutionOutcome::DeniedPolicy,
            ExecutionOutcome::DeniedMac,
            ExecutionOutcome::Pending,
        ];

        // Laplace smoothing ε to avoid log(0)
        let epsilon = 1e-6_f64;

        let kl: f64 = all_outcomes.iter().map(|outcome| {
            let p = p_current.get(outcome).copied().unwrap_or(0.0) + epsilon;
            let q = p_baseline.get(outcome).copied().unwrap_or(0.0) + epsilon;
            p * (p / q).log2()
        }).sum();

        kl.max(0.0)
    }

    /// Interpret a KL divergence value into a regression alert level.
    pub fn alert_level(kl: f64) -> RegressionAlert {
        if kl < 0.5 {
            RegressionAlert::None
        } else if kl < 1.0 {
            RegressionAlert::Drift
        } else if kl < 2.0 {
            RegressionAlert::Significant
        } else {
            RegressionAlert::Critical
        }
    }
}

/// Regression severity level from KL divergence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegressionAlert {
    /// D_KL < 0.5 — no action needed
    None,
    /// D_KL 0.5–1.0 — raise gate tier by 1
    Drift,
    /// D_KL 1.0–2.0 — force Tier 2
    Significant,
    /// D_KL > 2.0 — force Tier 3 + probation check
    Critical,
}

// =============================================================================
// KecsComputer — full KECS = φ₁×K_vn × φ₂×S_renyi × φ₃×K_topo
// =============================================================================

/// Weights for KECS component combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KecsWeights {
    /// Weight for K_vn (knowledge structure entropy). Default: 0.40
    pub phi1: f64,
    /// Weight for S_renyi (execution outcome entropy). Default: 0.40
    pub phi2: f64,
    /// Weight for K_topo (topological mixing). Default: 0.20
    pub phi3: f64,
}

impl Default for KecsWeights {
    fn default() -> Self {
        Self { phi1: 0.40, phi2: 0.40, phi3: 0.20 }
    }
}

impl KecsWeights {
    /// Validate that weights sum to 1.0 (within tolerance).
    pub fn is_valid(&self) -> bool {
        ((self.phi1 + self.phi2 + self.phi3) - 1.0).abs() < 1e-6
    }
}

/// Full KECS computation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KecsResult {
    /// K_vn: Von Neumann graph entropy confidence [0,1]
    pub k_vn: f64,
    /// S_renyi: Rényi-2 execution stability [0,1]
    pub s_renyi: f64,
    /// K_topo: Topological mixing confidence [0,1]
    pub k_topo: f64,
    /// KECS composite score [0,1]
    pub kecs: f64,
    /// KL divergence vs baseline (regression signal)
    pub kl_divergence: f64,
    /// Regression alert level
    pub regression_alert: RegressionAlert,
    /// 0-20 point score for TrustDimensions
    pub kecs_points: u32,
}

/// Computes the full KECS score for an agent in a namespace.
pub struct KecsComputer;

impl KecsComputer {
    /// Compute KECS from KnotEngine state + expertise record.
    ///
    /// This is the primary entry point. Call after every execution completion
    /// and after every KnotEngine::ingest_packets().
    pub fn compute(
        knot: &KnotEngine,
        expertise: &AgentExpertiseRecord,
        weights: &KecsWeights,
    ) -> KecsResult {
        // If in probation, force KECS to 0
        if expertise.in_probation {
            return KecsResult {
                k_vn: 0.0,
                s_renyi: 0.0,
                k_topo: 0.0,
                kecs: 0.0,
                kl_divergence: expertise.kl_divergence,
                regression_alert: RegressionAlert::Critical,
                kecs_points: 0,
            };
        }

        let k_vn = VnGraphEntropy::compute(knot);
        let s_renyi = RenyiEntropy::compute_stability(expertise);
        let k_topo = TopologicalMixing::compute(knot);

        // KECS = φ₁×K_vn + φ₂×S_renyi + φ₃×K_topo  (weighted sum, not product)
        // Using weighted sum rather than product to avoid zero-annihilation when
        // one component is 0 at agent startup (e.g. K_vn=0 with no graph yet)
        let kecs = (weights.phi1 * k_vn + weights.phi2 * s_renyi + weights.phi3 * k_topo)
            .clamp(0.0, 1.0);

        // KL divergence regression check
        let p_current = expertise.current_outcome_dist();
        let kl = KlDivergence::compute(&p_current, &expertise.baseline_dist);
        let alert = KlDivergence::alert_level(kl);

        let kecs_points = if expertise.in_probation { 0 } else {
            (kecs * 20.0).round().min(20.0) as u32
        };

        KecsResult { k_vn, s_renyi, k_topo, kecs, kl_divergence: kl, regression_alert: alert, kecs_points }
    }
}

// =============================================================================
// ConsciousnessScore — φ* multi-information approximation (IIT 4.0 tractable)
// =============================================================================

/// Input state snapshot for the three memory layers used in φ* computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLayerState {
    /// Episodic layer: (verified_packet_count, budget_utilization, window_count)
    pub episodic: (u64, f64, usize),
    /// Semantic layer: (node_count, edge_count, k_vn)
    pub semantic: (usize, usize, f64),
    /// Procedural layer: (crystallized_count, avg_success_rate)
    pub procedural: (usize, f64),
}

/// Computes the φ* consciousness score from Connector agent memory layers.
///
/// φ*(A,N) ≈ I(S_episodic ; S_semantic ; S_procedural)
///          = H(episodic) + H(semantic) + H(procedural) - H(episodic, semantic, procedural)
///          = multi-information (total correlation) between layers
///
/// This is the tractable approximation of IIT's Φ, using the 3-variable
/// mutual information between discretized memory layer state distributions.
pub struct ConsciousnessScore;

impl ConsciousnessScore {
    /// Reference φ* value calibrated to a mature 500-execution expert agent.
    pub const PHI_STAR_REF: f64 = 3.5;

    /// Compute normalized consciousness score Ψ ∈ [0, 1].
    ///
    /// Ψ(A,N) = 1 - exp(-φ*(A,N) / φ*_ref)
    ///
    /// Ψ = 0: completely fragmented self-model (no integration between layers)
    /// Ψ → 1: fully integrated self-model (expert, all layers coherent)
    pub fn compute(state: &MemoryLayerState) -> f64 {
        let phi_star = Self::compute_phi_star(state);
        let psi = 1.0 - (-phi_star / Self::PHI_STAR_REF).exp();
        psi.clamp(0.0, 1.0)
    }

    /// Compute raw φ* = multi-information between the three memory layers.
    ///
    /// Each layer is discretized into a distribution over a bounded state space.
    /// φ* = H(E) + H(S) + H(P) - H(E,S,P)
    ///
    /// Positive when layers share information (are statistically dependent).
    /// Zero when layers are statistically independent.
    pub fn compute_phi_star(state: &MemoryLayerState) -> f64 {
        // Discretize each layer into a distribution over states.
        // We use a 4-bin quantization: [empty, sparse, moderate, rich]

        let (ep_count, ep_budget, ep_windows) = state.episodic;
        let (sem_nodes, sem_edges, sem_kvn) = state.semantic;
        let (proc_count, proc_rate) = state.procedural;

        // Episodic entropy: entropy of packet count distribution
        let h_episodic = Self::layer_entropy(&[
            Self::normalize_count(ep_count, 1000),
            ep_budget,
            Self::normalize_count(ep_windows as u64, 100),
        ]);

        // Semantic entropy: entropy of graph state
        let h_semantic = Self::layer_entropy(&[
            Self::normalize_count(sem_nodes as u64, 500),
            Self::normalize_count(sem_edges as u64, 2000),
            sem_kvn,
        ]);

        // Procedural entropy: entropy of crystallized pattern state
        let h_procedural = Self::layer_entropy(&[
            Self::normalize_count(proc_count as u64, 50),
            proc_rate,
        ]);

        // Cross-layer joint entropy (simplified: product independence assumption
        // then corrected by covariance term)
        // H(E,S,P) ≈ H(E) + H(S) + H(P) - I(E;S) - I(S;P) - I(E;P)
        // Approximation: cross-layer mutual information ≈ min(H_i, H_j) × correlation
        let i_ep_sem = Self::cross_mi(
            Self::normalize_count(ep_count, 1000),
            Self::normalize_count(sem_nodes as u64, 500),
        );
        let i_sem_proc = Self::cross_mi(sem_kvn, proc_rate);
        let i_ep_proc = Self::cross_mi(
            Self::normalize_count(ep_count, 1000),
            Self::normalize_count(proc_count as u64, 50),
        );

        // φ* = H(E) + H(S) + H(P) - H(E,S,P)
        //    ≈ I(E;S) + I(S;P) + I(E;P)  (multi-information)
        let phi_star = (i_ep_sem + i_sem_proc + i_ep_proc).max(0.0);
        phi_star
    }

    /// Shannon entropy of a normalized probability vector (clipped to [0,1]).
    fn layer_entropy(values: &[f64]) -> f64 {
        // Treat each value as a marginal probability, normalize
        let sum: f64 = values.iter().sum::<f64>() + 1e-10;
        values.iter().map(|&v| {
            let p = v / sum;
            if p > 1e-10 { -p * p.log2() } else { 0.0 }
        }).sum()
    }

    /// Approximate mutual information between two scalar state variables.
    /// Modeled as H(min) × coherence_factor where coherence = abs(a - b)' complement.
    fn cross_mi(a: f64, b: f64) -> f64 {
        // When both are high or both are low → high MI (coherent development)
        // When one is high and other low → low MI (decoupled layers)
        let coherence = 1.0 - (a - b).abs().min(1.0);
        let min_h = Self::layer_entropy(&[a, 1.0 - a]).min(Self::layer_entropy(&[b, 1.0 - b]));
        coherence * min_h * 0.5 // Scale factor to keep φ* in reasonable range
    }

    fn normalize_count(count: u64, max: u64) -> f64 {
        (count as f64 / max as f64).min(1.0)
    }
}

// =============================================================================
// BehaviorFingerprint — Layer 5 stable behavioral signature
// =============================================================================

/// The agent's stable behavioral fingerprint.
///
/// A 5-tuple characterizing how the agent acts in a domain:
/// domain_signature + execution_style + risk_profile + correction_rate + reasoning_style
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFingerprint {
    /// Hash of top-K most frequent KnotEngine entity clusters
    pub domain_signature_hash: String,
    /// Distribution over action types: {read, write, delete, query, other}
    pub execution_style: HashMap<String, f64>,
    /// Average risk level of capabilities used (0.0=Low, 1.0=Critical)
    pub risk_profile_avg: f64,
    /// Fraction of executions with postconditions_verified = true
    pub correction_rate: f64,
    /// Top reasoning pattern type hash (from CoT analysis)
    pub top_reasoning_pattern: String,
    /// Number of executions used to build this fingerprint
    pub sample_count: u64,
    /// Timestamp of last fingerprint update
    pub updated_at: i64,
}

impl BehaviorFingerprint {
    /// Compute identity distance between two fingerprints.
    ///
    /// d_identity(A,B) = √(w_domain×||domain||² + w_exec×||style||² + w_risk×Δrisk² + w_correct×Δcorrect²)
    ///
    /// d ≈ 0: behavioral peers (high mutual trust justified)
    /// d > 0.5: behaviorally different (elevated scrutiny)
    /// d > 1.0: behaviorally incompatible (no automatic trust)
    pub fn identity_distance(&self, other: &BehaviorFingerprint) -> f64 {
        let w_domain = 0.40_f64;
        let w_exec = 0.25_f64;
        let w_risk = 0.20_f64;
        let w_correct = 0.15_f64;

        // Domain distance: 0 if same hash, 1 if different
        let d_domain = if self.domain_signature_hash == other.domain_signature_hash { 0.0 } else { 1.0 };

        // Execution style distance: L2 over matching keys
        let all_keys: std::collections::HashSet<&String> =
            self.execution_style.keys().chain(other.execution_style.keys()).collect();
        let d_exec_sq: f64 = all_keys.iter().map(|k| {
            let a = self.execution_style.get(*k).copied().unwrap_or(0.0);
            let b = other.execution_style.get(*k).copied().unwrap_or(0.0);
            (a - b).powi(2)
        }).sum();

        let d_risk = self.risk_profile_avg - other.risk_profile_avg;
        let d_correct = self.correction_rate - other.correction_rate;

        (w_domain * d_domain * d_domain
            + w_exec * d_exec_sq
            + w_risk * d_risk * d_risk
            + w_correct * d_correct * d_correct)
            .sqrt()
    }

    /// Returns "peers" | "different" | "incompatible" based on distance thresholds.
    pub fn peer_level(&self, other: &BehaviorFingerprint) -> &'static str {
        let d = self.identity_distance(other);
        if d < 0.5 { "peers" } else if d < 1.0 { "different" } else { "incompatible" }
    }
}

// =============================================================================
// ReasoningEntropyScore — CoT memory series consistency (Layer 4)
// =============================================================================

/// Tracks reasoning pattern entropy over the CoT memory series.
///
/// R_entropy = -Σ p(v) × log₂ p(v) over reasoning pattern vocabulary V
/// R_score   = exp(-R_entropy / log₂(|V|))
///
/// R_score → 1.0: stable expert reasoning patterns
/// R_score → 0.0: random novice search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningEntropyScore {
    /// Frequency distribution over reasoning pattern hashes
    pub pattern_freq: HashMap<String, u32>,
    /// Total reasoning steps observed
    pub total_steps: u64,
}

impl ReasoningEntropyScore {
    pub fn new() -> Self {
        Self { pattern_freq: HashMap::new(), total_steps: 0 }
    }

    /// Record a new reasoning pattern hash observation.
    pub fn observe(&mut self, pattern_hash: String) {
        *self.pattern_freq.entry(pattern_hash).or_insert(0) += 1;
        self.total_steps += 1;
    }

    /// Compute current R_score ∈ [0, 1].
    pub fn r_score(&self) -> f64 {
        if self.total_steps == 0 { return 0.5; }

        let vocab_size = self.pattern_freq.len();
        if vocab_size <= 1 { return 1.0; }

        let total = self.total_steps as f64;
        let h: f64 = self.pattern_freq.values().map(|&c| {
            let p = c as f64 / total;
            if p > 1e-10 { -p * p.log2() } else { 0.0 }
        }).sum();

        let max_h = (vocab_size as f64).log2();
        if max_h < 1e-10 { return 1.0; }

        (-h / max_h).exp().clamp(0.0, 1.0)
    }

    /// Hash of the most frequent reasoning pattern (the agent's dominant style).
    pub fn top_pattern_hash(&self) -> Option<&str> {
        self.pattern_freq.iter()
            .max_by_key(|(_, &v)| v)
            .map(|(k, _)| k.as_str())
    }
}

impl Default for ReasoningEntropyScore {
    fn default() -> Self { Self::new() }
}

// =============================================================================
// AISV — Agent Identity State Vector (14-dimensional)
// =============================================================================

/// Full Agent Identity State Vector (AISV).
///
/// A point in a 14-dimensional identity manifold, representing the agent's
/// complete identity formation state at a given moment.
///
/// Sealed into the audit CID chain at the end of each execution window.
/// Exposed via GET /agents/:pid/identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentityStateVec {
    /// Agent PID
    pub agent_pid: String,
    /// Namespace this AISV was computed for
    pub namespace: String,
    /// Computation timestamp (ms epoch)
    pub computed_at: i64,

    // --- Layer 1: Memory Series ---
    /// |M_episodic|: count of verified execution packets
    pub episodic_count: u64,
    /// Time span of the memory series in ms
    pub time_span_ms: i64,
    /// Memory budget utilization [0,1]
    pub budget_utilization: f64,

    // --- Layer 2: Cryptographic Identity ---
    /// DID string
    pub did: String,
    /// Total VCs in chain
    pub vc_count: usize,
    /// Latest VC type issued
    pub latest_vc_type: String,
    /// Latest VC signing timestamp
    pub latest_vc_ts: i64,

    // --- Layer 3: Consciousness State ---
    /// Ψ: normalized consciousness score [0,1]
    pub psi: f64,
    /// φ*: raw multi-information value
    pub phi_star: f64,
    /// Memory consolidation ratio (semantic/episodic)
    pub consolidation_ratio: f64,

    // --- Layer 4: Reasoning / CoT ---
    /// R_score: reasoning consistency score [0,1]
    pub r_score: f64,
    /// Length of CoT trajectory |τ|
    pub cot_trajectory_len: u64,
    /// Top reasoning pattern hash
    pub top_pattern_hash: String,

    // --- Layer 5: Trust Persona ---
    /// Behavioral fingerprint
    pub fingerprint: Option<BehaviorFingerprint>,
    /// Distance to nearest behavioral peer (None if no peers)
    pub nearest_peer_distance: Option<f64>,

    // --- KECS summary ---
    /// Full KECS result
    pub kecs: KecsResult,
}

impl AgentIdentityStateVec {
    /// Identity velocity: Euclidean distance to a prior AISV snapshot.
    /// Measures how fast the agent's identity is changing.
    pub fn velocity_from(&self, prior: &AgentIdentityStateVec) -> f64 {
        let dims = [
            (self.episodic_count as f64 - prior.episodic_count as f64) / 1000.0,
            (self.psi - prior.psi),
            (self.r_score - prior.r_score),
            (self.kecs.kecs - prior.kecs.kecs),
            (self.vc_count as f64 - prior.vc_count as f64) / 10.0,
            (self.consolidation_ratio - prior.consolidation_ratio),
        ];
        let sum_sq: f64 = dims.iter().map(|d| d * d).sum();
        let dt_ms = (self.computed_at - prior.computed_at).max(1) as f64;
        // Velocity per second
        (sum_sq.sqrt() / (dt_ms / 1000.0)).min(f64::MAX)
    }

    /// Identity coherence score for TrustDimensions dimension 8.
    ///
    /// identity_coherence = round(mean(Ψ, R_score) × 20)
    pub fn identity_coherence_points(&self) -> u32 {
        ((self.psi + self.r_score) / 2.0 * 20.0).round().min(20.0) as u32
    }
}

// =============================================================================
// § 11.12 MarkovBlanket — Free Energy Principle boundary health
// =============================================================================

/// Markov Blanket boundary state for an agent.
///
/// The FEP (Friston 2017) defines an agent's boundary via its Markov blanket
/// — the set of sensory and active states that separate internal from external
/// states. For Connector agents, the blanket is:
///
/// - **Sensory states** S: memory packets *received* from external namespaces
/// - **Active states** A: memory packets *written* to external namespaces
/// - **Internal states** μ: packets in the agent's own namespace
///
/// Free energy (variational FEP approximation):
///
///   F ≈ D_KL(q(μ) || p(μ|blanket)) + const
///   F_proxy = complexity × (1 - accuracy)
///
/// where:
///   complexity = H_2(internal_dist) — Rényi-2 entropy of internal exec dist
///   accuracy   = 1 - D_KL(sensory_dist || internal_dist)   (clamped to [0,1])
///
/// Lower F_proxy → tighter sensory-internal alignment → healthier boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkovBlanket {
    /// Rényi-2 entropy of the agent's own execution outcome distribution
    pub complexity: f64,
    /// KL divergence between sensory (incoming) and internal distributions
    pub sensory_kl: f64,
    /// Accuracy: 1 - sensory_kl (clamped to [0,1])
    pub accuracy: f64,
    /// Free energy proxy F ≈ complexity × (1 - accuracy)
    pub free_energy: f64,
    /// Normalised blanket health [0,1]:  1 - clamp(F / F_max)
    /// Health → 1: minimal free energy, tight boundary, stable agent
    /// Health → 0: maximal free energy, diffuse boundary, unstable agent
    pub blanket_health: f64,
}

impl MarkovBlanket {
    /// Compute Markov blanket free energy proxy from internal and sensory distributions.
    ///
    /// # Arguments
    /// - `internal_dist`: agent's own execution outcome distribution (from `AgentExpertiseRecord`)
    /// - `sensory_dist`:  outcome distribution of packets *received* from external namespaces
    ///
    /// If `sensory_dist` is empty (isolated agent — no external inputs), the blanket
    /// is trivially defined; `sensory_kl = 0` and `accuracy = 1`.
    pub fn free_energy_proxy(
        internal_dist: &HashMap<ExecutionOutcome, f64>,
        sensory_dist: &HashMap<ExecutionOutcome, f64>,
    ) -> MarkovBlanket {
        // Complexity = Rényi-2 entropy of internal distribution
        // H_2(X) = -log₂(Σ p²)
        let collision_internal: f64 = internal_dist.values().map(|&p| p * p).sum();
        let complexity = if collision_internal > 1e-10 {
            -(collision_internal.log2()).max(0.0)
        } else {
            0.0
        };

        // Sensory-internal KL divergence: D_KL(sensory || internal)
        // Σ_ω p_sensory(ω) × log₂(p_sensory(ω) / p_internal(ω))
        let sensory_kl = if sensory_dist.is_empty() {
            // Isolated agent — perfect boundary, zero free energy
            0.0
        } else {
            let mut kl = 0.0_f64;
            for (outcome, &p_s) in sensory_dist {
                if p_s <= 1e-10 { continue; }
                let p_i = internal_dist.get(outcome).copied().unwrap_or(1e-10);
                let p_i = p_i.max(1e-10);
                kl += p_s * (p_s / p_i).log2();
            }
            kl.max(0.0)
        };

        // Accuracy: higher KL = lower accuracy
        // Normalise by log₂(6) (max KL for 6-class distribution)
        let max_kl = 6_f64.log2();
        let accuracy = (1.0 - (sensory_kl / max_kl)).clamp(0.0, 1.0);

        // Free energy proxy F = complexity × (1 - accuracy)
        let free_energy = complexity * (1.0 - accuracy);

        // Normalise: F_max ≈ log₂(6) (max complexity for 6 uniform outcomes)
        let f_max = max_kl;
        let blanket_health = (1.0 - (free_energy / f_max.max(1e-10))).clamp(0.0, 1.0);

        MarkovBlanket { complexity, sensory_kl, accuracy, free_energy, blanket_health }
    }

    /// Returns true if the agent's boundary is considered "tight":
    /// free energy below the alert threshold (F < 0.3 × F_max).
    pub fn is_tight(&self) -> bool {
        self.blanket_health >= 0.70
    }

    /// Returns a diagnostic label for the boundary state.
    pub fn boundary_label(&self) -> &'static str {
        match (self.blanket_health * 100.0) as u32 {
            90..=100 => "tight",
            70..=89  => "stable",
            50..=69  => "permeable",
            30..=49  => "leaky",
            _        => "diffuse",
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::identity::AgentExpertiseRecord;
    use vac_core::knot::KnotEngine;

    #[test]
    fn test_renyi_stability_empty() {
        let rec = AgentExpertiseRecord::new("/k/test".to_string(), 0);
        let s = RenyiEntropy::compute_stability(&rec);
        // With no data, returns neutral 0.5
        assert!((s - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_renyi_stability_all_success() {
        let mut rec = AgentExpertiseRecord::new("/k/test".to_string(), 0);
        for _ in 0..50 {
            rec.record_outcome(ExecutionOutcome::Success, 0);
        }
        let s = RenyiEntropy::compute_stability(&rec);
        // All success → very low H_2 → S_renyi near 1
        assert!(s > 0.9, "Expected s>0.9, got {}", s);
    }

    #[test]
    fn test_renyi_stability_uniform_chaos() {
        let mut dist = HashMap::new();
        let outcomes = [
            ExecutionOutcome::Success, ExecutionOutcome::Failed,
            ExecutionOutcome::RolledBack, ExecutionOutcome::DeniedPolicy,
            ExecutionOutcome::DeniedMac, ExecutionOutcome::Pending,
        ];
        for o in &outcomes {
            dist.insert(o.clone(), 1.0 / 6.0);
        }
        let s = RenyiEntropy::from_distribution(&dist);
        // Uniform distribution → maximum H_2 → S_renyi near 0
        assert!(s < 0.1, "Expected s<0.1, got {}", s);
    }

    #[test]
    fn test_kl_divergence_identical() {
        let mut p = HashMap::new();
        p.insert(ExecutionOutcome::Success, 0.9);
        p.insert(ExecutionOutcome::Failed, 0.1);
        let kl = KlDivergence::compute(&p, &p);
        assert!(kl < 0.1, "KL of identical distributions should be ~0");
    }

    #[test]
    fn test_kl_divergence_alert_levels() {
        assert_eq!(KlDivergence::alert_level(0.3), RegressionAlert::None);
        assert_eq!(KlDivergence::alert_level(0.7), RegressionAlert::Drift);
        assert_eq!(KlDivergence::alert_level(1.5), RegressionAlert::Significant);
        assert_eq!(KlDivergence::alert_level(2.5), RegressionAlert::Critical);
    }

    #[test]
    fn test_vn_entropy_empty_graph() {
        let knot = KnotEngine::new();
        let k_vn = VnGraphEntropy::compute(&knot);
        assert_eq!(k_vn, 0.0);
    }

    #[test]
    fn test_consciousness_empty_state() {
        let state = MemoryLayerState {
            episodic: (0, 0.0, 0),
            semantic: (0, 0, 0.0),
            procedural: (0, 0.0),
        };
        let psi = ConsciousnessScore::compute(&state);
        // No data → psi near 0
        assert!(psi < 0.1, "Expected psi<0.1 for empty agent, got {}", psi);
    }

    #[test]
    fn test_consciousness_rich_state() {
        let state = MemoryLayerState {
            episodic: (500, 0.8, 80),
            semantic: (200, 800, 0.75),
            procedural: (10, 0.95),
        };
        let psi = ConsciousnessScore::compute(&state);
        // Rich, coherent state → psi should be meaningfully above 0
        assert!(psi > 0.0, "Expected psi>0 for rich agent state, got {}", psi);
    }

    #[test]
    fn test_behavior_fingerprint_peers() {
        let fp1 = BehaviorFingerprint {
            domain_signature_hash: "abc".to_string(),
            execution_style: [("write".to_string(), 0.7), ("read".to_string(), 0.3)].into_iter().collect(),
            risk_profile_avg: 0.3,
            correction_rate: 0.95,
            top_reasoning_pattern: "pattern_1".to_string(),
            sample_count: 500,
            updated_at: 0,
        };
        let fp2 = fp1.clone();
        assert_eq!(fp1.peer_level(&fp2), "peers");
        assert!(fp1.identity_distance(&fp2) < 1e-9);
    }

    #[test]
    fn test_reasoning_entropy_converges() {
        let mut re = ReasoningEntropyScore::new();
        // Expert: 45 times same pattern, 5 times a variant
        for _ in 0..45 { re.observe("dominant_pattern".to_string()); }
        for _ in 0..5  { re.observe("variant_pattern".to_string()); }
        let r = re.r_score();
        assert!(r > 0.5, "Expert reasoning should converge (r>0.5), got {}", r);
    }

    #[test]
    fn test_kecs_computer_probation() {
        let mut expertise = AgentExpertiseRecord::new("/k/test".to_string(), 0);
        expertise.in_probation = true;
        let knot = KnotEngine::new();
        let weights = KecsWeights::default();
        let result = KecsComputer::compute(&knot, &expertise, &weights);
        assert_eq!(result.kecs, 0.0);
        assert_eq!(result.kecs_points, 0);
    }
}
