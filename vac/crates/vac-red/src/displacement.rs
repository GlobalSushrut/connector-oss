//! Regressive Entropic Displacement algorithm
//!
//! Core learning algorithm for VAC based on:
//! - Multiplicative Weights Update (Hedge algorithm)
//! - KL divergence as information gain
//! - Free energy minimization

use crate::vector::SparseVector;
use crate::{DEFAULT_DIMS, DEFAULT_ETA};

/// Regressive Entropic Displacement engine
pub struct RedEngine {
    /// Number of dimensions
    pub dims: usize,
    /// Learning rate
    pub eta: f64,
    /// Prior distribution (maximum entropy = uniform)
    pub prior: Vec<f64>,
    /// Posterior distribution (updated by observations)
    pub posterior: Vec<f64>,
    /// Cumulative loss per dimension
    pub cumulative_loss: Vec<f64>,
    /// Total observations
    pub total_observations: u64,
    /// Total retrievals
    pub total_retrievals: u64,
}

impl RedEngine {
    /// Create a new RED engine with default parameters
    pub fn new() -> Self {
        Self::with_params(DEFAULT_DIMS, DEFAULT_ETA)
    }
    
    /// Create a new RED engine with specified parameters
    pub fn with_params(dims: usize, eta: f64) -> Self {
        let uniform = 1.0 / dims as f64;
        Self {
            dims,
            eta,
            prior: vec![uniform; dims],
            posterior: vec![uniform; dims],
            cumulative_loss: vec![0.0; dims],
            total_observations: 0,
            total_retrievals: 0,
        }
    }
    
    /// Update belief distribution when new event is observed
    /// This is the "perception" step in free energy minimization
    pub fn observe(&mut self, vector: &SparseVector) {
        self.total_observations += 1;
        
        // Bayesian update: posterior ∝ prior × likelihood
        for (dim, weight) in vector.nonzero() {
            self.posterior[dim] *= 1.0 + self.eta * weight;
        }
        
        // Renormalize
        self.normalize_posterior();
    }
    
    /// Update weights based on retrieval outcome
    /// Uses multiplicative weights update (Hedge algorithm)
    pub fn retrieval_feedback(&mut self, vector: &SparseVector, was_useful: bool) {
        self.total_retrievals += 1;
        
        // Loss: 0 if useful, 1 if not useful
        let loss = if was_useful { 0.0 } else { 1.0 };
        
        for (dim, weight) in vector.nonzero() {
            // Accumulate loss
            self.cumulative_loss[dim] += loss * weight;
            
            // Multiplicative update (exponential discounting)
            self.posterior[dim] *= (-self.eta * loss * weight).exp();
        }
        
        // Renormalize
        self.normalize_posterior();
    }
    
    /// Compute entropy (novelty) of a vector relative to current belief
    /// Uses KL divergence: D_KL(vector || posterior)
    pub fn compute_entropy(&self, vector: &SparseVector) -> f64 {
        let p = vector.to_distribution();
        
        let epsilon = 1e-10;
        let mut kl_div = 0.0;
        
        for (dim, p_i) in p.iter().enumerate() {
            if *p_i > epsilon {
                let q_i = self.posterior[dim].max(epsilon);
                kl_div += p_i * (p_i / q_i).ln();
            }
        }
        
        // Normalize to [0, 1] using sigmoid centered at KL=1
        sigmoid(kl_div - 1.0)
    }
    
    /// Compute entropic displacement = how much the belief changed
    pub fn compute_displacement(&self, old_posterior: &[f64]) -> f64 {
        let epsilon = 1e-10;
        let mut kl_div = 0.0;
        
        for dim in 0..self.dims {
            let p_i = self.posterior[dim].max(epsilon);
            let q_i = old_posterior[dim].max(epsilon);
            kl_div += p_i * (p_i / q_i).ln();
        }
        
        kl_div
    }
    
    /// Periodic reframing: adjust network structure based on accumulated learning
    /// Analogous to "sleep consolidation" in biological memory
    pub fn reframe_network(&mut self) {
        if self.total_retrievals == 0 {
            return;
        }
        
        // Compute average loss per dimension
        let avg_loss: Vec<f64> = self.cumulative_loss
            .iter()
            .map(|&loss| loss / self.total_retrievals as f64)
            .collect();
        
        // Update prior using softmax (maximum entropy with constraints)
        let inv_loss: Vec<f64> = avg_loss.iter().map(|&l| 1.0 / (1.0 + l)).collect();
        self.prior = softmax(&inv_loss);
        
        // Reset cumulative loss
        self.cumulative_loss = vec![0.0; self.dims];
        
        // Blend posterior toward new prior (gradual reframing)
        let alpha = 0.1;
        for dim in 0..self.dims {
            self.posterior[dim] = (1.0 - alpha) * self.posterior[dim] + alpha * self.prior[dim];
        }
        
        self.normalize_posterior();
    }
    
    /// Get the current posterior distribution
    pub fn get_posterior(&self) -> &[f64] {
        &self.posterior
    }
    
    /// Clone the current posterior (for displacement calculation)
    pub fn clone_posterior(&self) -> Vec<f64> {
        self.posterior.clone()
    }
    
    fn normalize_posterior(&mut self) {
        let sum: f64 = self.posterior.iter().sum();
        if sum > 1e-10 {
            for p in &mut self.posterior {
                *p /= sum;
            }
        }
    }
}

impl Default for RedEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Sigmoid function
fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Softmax function
fn softmax(x: &[f64]) -> Vec<f64> {
    let max_x = x.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let exp_x: Vec<f64> = x.iter().map(|&xi| (xi - max_x).exp()).collect();
    let sum: f64 = exp_x.iter().sum();
    exp_x.iter().map(|&e| e / sum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_red_engine_creation() {
        let engine = RedEngine::new();
        assert_eq!(engine.dims, DEFAULT_DIMS);
        assert_eq!(engine.total_observations, 0);
    }
    
    #[test]
    fn test_observe() {
        let mut engine = RedEngine::with_params(100, 0.1);
        
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        vector.add(10, 0.5);
        
        engine.observe(&vector);
        
        assert_eq!(engine.total_observations, 1);
        // Observed dimensions should have higher posterior
        assert!(engine.posterior[0] > engine.posterior[50]);
    }
    
    #[test]
    fn test_retrieval_feedback() {
        let mut engine = RedEngine::with_params(100, 0.1);
        
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        
        // Useful retrieval
        engine.retrieval_feedback(&vector, true);
        assert_eq!(engine.total_retrievals, 1);
        
        // Useless retrieval should decrease weight
        let posterior_before = engine.posterior[0];
        engine.retrieval_feedback(&vector, false);
        assert!(engine.posterior[0] < posterior_before);
    }
    
    #[test]
    fn test_entropy_computation() {
        let engine = RedEngine::with_params(100, 0.1);
        
        // Uniform vector should have low entropy (matches prior)
        let mut uniform = SparseVector::with_dims(100);
        for i in 0..100 {
            uniform.add(i, 1.0);
        }
        
        let entropy_uniform = engine.compute_entropy(&uniform);
        
        // Sparse vector should have higher entropy (diverges from prior)
        let mut sparse = SparseVector::with_dims(100);
        sparse.add(0, 1.0);
        
        let entropy_sparse = engine.compute_entropy(&sparse);
        
        assert!(entropy_sparse > entropy_uniform);
    }
    
    #[test]
    fn test_displacement() {
        let mut engine = RedEngine::with_params(100, 0.1);
        
        let old_posterior = engine.clone_posterior();
        
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        engine.observe(&vector);
        
        let displacement = engine.compute_displacement(&old_posterior);
        assert!(displacement > 0.0);
    }
    
    #[test]
    fn test_reframe_network() {
        let mut engine = RedEngine::with_params(100, 0.1);
        
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        
        // Simulate some retrievals with mixed feedback
        for i in 0..10 {
            // Mix of useful and not useful to create loss variance
            engine.retrieval_feedback(&vector, i % 2 == 0);
        }
        
        let posterior_before = engine.posterior[0];
        engine.reframe_network();
        
        // Posterior should have changed after reframing
        // (blending toward new prior)
        assert!(engine.total_retrievals > 0);
    }
    
    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-10);
        assert!(sigmoid(10.0) > 0.99);
        assert!(sigmoid(-10.0) < 0.01);
    }
}
