//! Entropy computation for VAC
//!
//! Combines multiple entropy signals into a single score.

use crate::displacement::RedEngine;
use crate::vector::SparseVector;

/// Compute the combined entropy score for an event
pub fn compute_entropy(
    red: &RedEngine,
    vector: &SparseVector,
    conflict_count: usize,
    time_since_similar_secs: f64,
) -> f64 {
    // 1. Entropic novelty via KL divergence
    let novelty = red.compute_entropy(vector);
    
    // 2. Contradiction score from ClaimBundle matching
    let conflict_score = (conflict_count as f64 / 3.0).min(1.0);
    
    // 3. Temporal novelty (exponential decay over 24h)
    let temporal_novelty = 1.0 - (-time_since_similar_secs / (24.0 * 3600.0)).exp();
    
    // 4. Combine using weighted sum (maximum entropy principle)
    let weights = [0.4, 0.3, 0.3];
    let components = [novelty, conflict_score, temporal_novelty];
    
    weights.iter().zip(components.iter()).map(|(w, c)| w * c).sum()
}

/// Entropy context for tracking state
pub struct EntropyContext {
    pub red_engine: RedEngine,
    pub displacement_log: Vec<(String, f64)>,
}

impl EntropyContext {
    pub fn new() -> Self {
        Self {
            red_engine: RedEngine::new(),
            displacement_log: Vec::new(),
        }
    }
    
    /// Compute entropy and update the RED engine
    pub fn compute_and_update(
        &mut self,
        event_cid: &str,
        vector: &SparseVector,
        conflict_count: usize,
        time_since_similar_secs: f64,
    ) -> f64 {
        // Clone posterior before update
        let old_posterior = self.red_engine.clone_posterior();
        
        // Compute entropy
        let entropy = compute_entropy(
            &self.red_engine,
            vector,
            conflict_count,
            time_since_similar_secs,
        );
        
        // Update RED engine
        self.red_engine.observe(vector);
        
        // Compute and log displacement
        let displacement = self.red_engine.compute_displacement(&old_posterior);
        self.displacement_log.push((event_cid.to_string(), displacement));
        
        entropy
    }
    
    /// Provide retrieval feedback
    pub fn feedback(&mut self, vector: &SparseVector, was_useful: bool) {
        self.red_engine.retrieval_feedback(vector, was_useful);
    }
    
    /// Trigger network reframing (consolidation)
    pub fn reframe(&mut self) {
        self.red_engine.reframe_network();
    }
}

impl Default for EntropyContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compute_entropy() {
        let red = RedEngine::with_params(100, 0.1);
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        
        let entropy = compute_entropy(&red, &vector, 0, 0.0);
        
        // Should be in [0, 1]
        assert!(entropy >= 0.0);
        assert!(entropy <= 1.0);
    }
    
    #[test]
    fn test_entropy_context() {
        let mut ctx = EntropyContext::new();
        
        let mut vector = SparseVector::with_dims(65536);
        vector.add(0, 1.0);
        
        let entropy = ctx.compute_and_update("cid1", &vector, 0, 0.0);
        
        assert!(entropy >= 0.0);
        assert_eq!(ctx.displacement_log.len(), 1);
    }
    
    #[test]
    fn test_conflict_increases_entropy() {
        let red = RedEngine::with_params(100, 0.1);
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        
        let entropy_no_conflict = compute_entropy(&red, &vector, 0, 0.0);
        let entropy_with_conflict = compute_entropy(&red, &vector, 3, 0.0);
        
        assert!(entropy_with_conflict > entropy_no_conflict);
    }
    
    #[test]
    fn test_time_increases_entropy() {
        let red = RedEngine::with_params(100, 0.1);
        let mut vector = SparseVector::with_dims(100);
        vector.add(0, 1.0);
        
        let entropy_recent = compute_entropy(&red, &vector, 0, 0.0);
        let entropy_old = compute_entropy(&red, &vector, 0, 86400.0); // 24 hours
        
        assert!(entropy_old > entropy_recent);
    }
}
