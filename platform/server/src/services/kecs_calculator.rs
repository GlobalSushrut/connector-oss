//! KECS Calculator — Real KECS Score Computation
//!
//! Computes KECS (Knowledge Entropy Consensus Score) from actual agent metrics:
//! - K_vn: Knowledge graph von Neumann entropy (quantum-inspired)
//! - S_renyi: Rényi entropy of agent's reasoning patterns
//! - K_topo: Topological complexity of knowledge structures
//!
//! KECS = 0.4*K_vn + 0.4*S_renyi + 0.2*K_topo

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::f64::consts::E;

/// KECS Components
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KecsComponents {
    /// von Neumann entropy component (quantum-inspired knowledge disorder)
    pub k_vn: f64,
    /// Rényi entropy component (reasoning diversity)
    pub s_renyi: f64,
    /// Topological complexity (knowledge structure)
    pub k_topo: f64,
    /// Final composite score
    pub kecs: f64,
}

impl KecsComponents {
    /// Calculate composite KECS score
    pub fn calculate(k_vn: f64, s_renyi: f64, k_topo: f64) -> Self {
        // Normalize inputs to [0, 1] range
        let k_vn_norm = k_vn.clamp(0.0, 1.0);
        let s_renyi_norm = s_renyi.clamp(0.0, 1.0);
        let k_topo_norm = k_topo.clamp(0.0, 1.0);

        // Weighted composite (as per VAC paper)
        let kecs = 0.4 * k_vn_norm + 0.4 * s_renyi_norm + 0.2 * k_topo_norm;

        Self {
            k_vn: k_vn_norm,
            s_renyi: s_renyi_norm,
            k_topo: k_topo_norm,
            kecs,
        }
    }

    /// Maturity level based on KECS
    pub fn maturity_level(&self) -> &'static str {
        match self.kecs {
            s if s >= 0.85 => "expert",
            s if s >= 0.70 => "proficient",
            s if s >= 0.55 => "competent",
            s if s >= 0.40 => "developing",
            _ => "novice",
        }
    }
}

/// Entropy calculations for KECS
pub struct EntropyCalculator;

impl EntropyCalculator {
    /// Shannon entropy: H(X) = -Σ p(x) log₂ p(x)
    pub fn shannon(probabilities: &[f64]) -> f64 {
        probabilities
            .iter()
            .filter(|&&p| p > 0.0)
            .map(|&p| -p * p.log2())
            .sum()
    }

    /// Rényi entropy of order α: H_α(X) = (1/(1-α)) log₂(Σ p(x)^α)
    pub fn renyi(probabilities: &[f64], alpha: f64) -> f64 {
        if alpha == 1.0 {
            return Self::shannon(probabilities);
        }

        let sum_p_alpha: f64 = probabilities.iter().map(|&p| p.powf(alpha)).sum();

        (1.0 / (1.0 - alpha)) * sum_p_alpha.log2()
    }

    /// von Neumann entropy for density matrix eigenvalues
    /// S = -Tr(ρ log ρ) = -Σ λᵢ log λᵢ
    pub fn von_neumann(eigenvalues: &[f64]) -> f64 {
        eigenvalues
            .iter()
            .filter(|&&λ| λ > 1e-10) // Avoid log(0)
            .map(|&λ| -λ * λ.ln())
            .sum()
    }

    /// Calculate spectral entropy from agent's packet distribution
    pub fn spectral_entropy(packet_counts: &[usize]) -> f64 {
        let total: usize = packet_counts.iter().sum();
        if total == 0 {
            return 0.0;
        }

        let probabilities: Vec<f64> = packet_counts
            .iter()
            .map(|&count| count as f64 / total as f64)
            .collect();

        Self::shannon(&probabilities)
    }
}

/// Complex spectral parameters for Knot consensus
/// ψ = re^{iθ} where r ∈ [0,1] and θ ∈ [0, 2π]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ComplexSpectral {
    /// Real part: amplitude/magnitude
    pub re: f64,
    /// Imaginary part: phase
    pub im: f64,
}

impl ComplexSpectral {
    /// Create from polar coordinates (r, θ)
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }

    /// Magnitude |ψ| = √(re² + im²)
    pub fn magnitude(&self) -> f64 {
        (self.re.powi(2) + self.im.powi(2)).sqrt()
    }

    /// Phase θ = atan2(im, re)
    pub fn phase(&self) -> f64 {
        self.im.atan2(self.re)
    }

    /// Normalize to unit magnitude
    pub fn normalize(&mut self) {
        let mag = self.magnitude();
        if mag > 0.0 {
            self.re /= mag;
            self.im /= mag;
        }
    }

    /// Compute ψ* (complex conjugate)
    pub fn conjugate(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    /// Inner product ⟨ψ₁|ψ₂⟩ = ψ₁* · ψ₂
    pub fn inner_product(a: &ComplexSpectral, b: &ComplexSpectral) -> ComplexSpectral {
        let a_conj = a.conjugate();
        ComplexSpectral {
            re: a_conj.re * b.re - a_conj.im * b.im,
            im: a_conj.re * b.im + a_conj.im * b.re,
        }
    }
}

/// Real KECS calculator based on actual agent metrics
pub struct KecsCalculator {
    /// History of calculations for trend analysis
    calculation_history: HashMap<String, Vec<KecsComponents>>,
    /// Maximum history size per agent
    max_history: usize,
}

impl KecsCalculator {
    pub fn new(max_history: usize) -> Self {
        Self {
            calculation_history: HashMap::new(),
            max_history,
        }
    }

    /// Calculate KECS from real agent metrics
    pub fn calculate_kecs(
        &mut self,
        agent_pid: &str,
        packet_count: usize,
        operation_count: usize,
        success_rate: f64,
        memory_packets: usize,
        graph_connections: usize,
    ) -> KecsComponents {
        // K_vn: von Neumann entropy based on memory packet distribution
        // Higher entropy = more diverse knowledge = higher score
        let k_vn = if memory_packets > 0 {
            // Simulate density matrix eigenvalues from packet distribution
            let eigenvalues = vec![
                (packet_count as f64 / memory_packets as f64).min(1.0),
                (operation_count as f64 / memory_packets as f64).min(1.0),
                success_rate,
            ];
            // Normalize to probability distribution
            let sum: f64 = eigenvalues.iter().sum();
            let normalized: Vec<f64> = eigenvalues.iter().map(|&x| x / sum).collect();
            EntropyCalculator::von_neumann(&normalized)
        } else {
            0.5 // Default for new agents
        };

        // S_renyi: Rényi entropy of agent's operation patterns
        // Higher diversity = higher entropy = higher score
        let s_renyi = if operation_count > 0 {
            let op_dist = vec![success_rate, 1.0 - success_rate];
            EntropyCalculator::renyi(&op_dist, 2.0) // Order-2 Rényi entropy
        } else {
            0.5
        };

        // K_topo: Topological complexity from graph connections
        // More connections = higher complexity = higher score
        let k_topo = if graph_connections > 0 {
            let connection_density = (graph_connections as f64 / 100.0).min(1.0);
            let complexity = connection_density * (1.0 + (graph_connections as f64).ln() / 10.0);
            complexity.min(1.0)
        } else {
            0.3
        };

        let components = KecsComponents::calculate(k_vn, s_renyi, k_topo);

        // Store in history
        let history = self
            .calculation_history
            .entry(agent_pid.to_string())
            .or_insert_with(Vec::new);
        history.push(components);
        if history.len() > self.max_history {
            history.remove(0);
        }

        components
    }

    /// Get trend (improving, stable, declining)
    pub fn get_trend(&self, agent_pid: &str) -> Option<&'static str> {
        let history = self.calculation_history.get(agent_pid)?;
        if history.len() < 3 {
            return Some("insufficient_data");
        }

        let recent: f64 = history.iter().rev().take(3).map(|c| c.kecs).sum::<f64>() / 3.0;
        let older: f64 = history
            .iter()
            .rev()
            .skip(3)
            .take(3)
            .map(|c| c.kecs)
            .sum::<f64>()
            / 3.0;

        if recent > older + 0.05 {
            Some("improving")
        } else if recent < older - 0.05 {
            Some("declining")
        } else {
            Some("stable")
        }
    }

    /// Get historical average
    pub fn historical_average(&self, agent_pid: &str) -> Option<f64> {
        let history = self.calculation_history.get(agent_pid)?;
        if history.is_empty() {
            return None;
        }
        Some(history.iter().map(|c| c.kecs).sum::<f64>() / history.len() as f64)
    }
}

/// Knot consensus spectral parameters
/// Each agent gets a spectral parameter u_i = kecs + i·entropy
pub fn calculate_spectral_parameters(kecs: f64, entropy: f64) -> ComplexSpectral {
    // u_i ∈ [0,1] + i·[0,1]
    ComplexSpectral {
        re: kecs.clamp(0.0, 1.0),
        im: entropy.clamp(0.0, 1.0),
    }
}

/// Calculate R-matrix crossing weight for Knot consensus
/// Based on Yang-Baxter equation with spectral parameters
pub fn r_matrix_weight(u_i: &ComplexSpectral, u_j: &ComplexSpectral) -> f64 {
    // Simplified R-matrix: weight based on spectral difference
    let diff = ComplexSpectral {
        re: u_i.re - u_j.re,
        im: u_i.im - u_j.im,
    };

    // Weight decreases with spectral distance
    // R(u) ∝ 1 / (1 + |u_i - u_j|²)
    let distance_sq = diff.re.powi(2) + diff.im.powi(2);
    1.0 / (1.0 + distance_sq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        // Fair coin: max entropy = 1.0
        let fair_coin = vec![0.5, 0.5];
        assert!((EntropyCalculator::shannon(&fair_coin) - 1.0).abs() < 0.01);

        // Biased coin: lower entropy
        let biased = vec![0.9, 0.1];
        assert!(EntropyCalculator::shannon(&biased) < 0.5);

        // Certain event: zero entropy
        let certain = vec![1.0, 0.0];
        assert_eq!(EntropyCalculator::shannon(&certain), 0.0);
    }

    #[test]
    fn test_renyi_entropy() {
        let uniform = vec![0.25, 0.25, 0.25, 0.25];
        let renyi_2 = EntropyCalculator::renyi(&uniform, 2.0);
        // For uniform distribution, Rényi-2 = log₂(n) = 2.0
        assert!((renyi_2 - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_von_neumann_entropy() {
        // Pure state: zero entropy
        let pure = vec![1.0, 0.0, 0.0];
        assert_eq!(EntropyCalculator::von_neumann(&pure), 0.0);

        // Maximally mixed 2-state: ln(2)
        let mixed = vec![0.5, 0.5];
        let entropy = EntropyCalculator::von_neumann(&mixed);
        assert!((entropy - 0.693).abs() < 0.01);
    }

    #[test]
    fn test_complex_spectral() {
        let psi = ComplexSpectral::from_polar(1.0, std::f64::consts::PI / 4.0);
        // 45° angle: re = im = √2/2 ≈ 0.707
        assert!((psi.re - 0.707).abs() < 0.01);
        assert!((psi.im - 0.707).abs() < 0.01);
        assert!((psi.magnitude() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_kecs_calculation() {
        let mut calc = KecsCalculator::new(10);

        let kecs = calc.calculate_kecs(
            "agent-1", 100, // packet_count
            50,  // operation_count
            0.9, // success_rate
            200, // memory_packets
            10,  // graph_connections
        );

        // Check all components in valid range
        assert!(kecs.k_vn >= 0.0 && kecs.k_vn <= 1.0);
        assert!(kecs.s_renyi >= 0.0 && kecs.s_renyi <= 1.0);
        assert!(kecs.k_topo >= 0.0 && kecs.k_topo <= 1.0);
        assert!(kecs.kecs >= 0.0 && kecs.kecs <= 1.0);

        // Higher success should give higher KECS
        let kecs_low_success = calc.calculate_kecs("agent-2", 100, 50, 0.5, 200, 10);

        assert!(kecs.kecs > kecs_low_success.kecs);
    }

    #[test]
    fn test_r_matrix_weight() {
        let u1 = ComplexSpectral { re: 0.8, im: 0.3 };
        let u2 = ComplexSpectral { re: 0.9, im: 0.4 };

        let weight = r_matrix_weight(&u1, &u2);

        // Weight should be positive and ≤ 1
        assert!(weight > 0.0 && weight <= 1.0);

        // Same spectral parameters should give weight = 1
        let weight_same = r_matrix_weight(&u1, &u1);
        assert!((weight_same - 1.0).abs() < 0.01);
    }
}
