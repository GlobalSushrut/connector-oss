//! Sparse vector implementation for RED
//!
//! Feature vectors are sparse vectors in R^d where d = 65536.
//! Dimensions are hash buckets for entities, predicates, and n-grams.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::DEFAULT_DIMS;

/// A sparse vector for feature representation
#[derive(Debug, Clone, Default)]
pub struct SparseVector {
    /// Number of dimensions
    pub dims: usize,
    /// Non-zero entries: dimension -> value
    pub entries: BTreeMap<usize, f64>,
}

impl SparseVector {
    /// Create a new sparse vector with default dimensions
    pub fn new() -> Self {
        Self::with_dims(DEFAULT_DIMS)
    }
    
    /// Create a new sparse vector with specified dimensions
    pub fn with_dims(dims: usize) -> Self {
        Self {
            dims,
            entries: BTreeMap::new(),
        }
    }
    
    /// Add a value to a dimension
    pub fn add(&mut self, dim: usize, value: f64) {
        let entry = self.entries.entry(dim).or_insert(0.0);
        *entry += value;
    }
    
    /// Set a dimension value
    pub fn set(&mut self, dim: usize, value: f64) {
        if value.abs() < 1e-10 {
            self.entries.remove(&dim);
        } else {
            self.entries.insert(dim, value);
        }
    }
    
    /// Get a dimension value
    pub fn get(&self, dim: usize) -> f64 {
        self.entries.get(&dim).copied().unwrap_or(0.0)
    }
    
    /// Get non-zero entries
    pub fn nonzero(&self) -> impl Iterator<Item = (usize, f64)> + '_ {
        self.entries.iter().map(|(&dim, &val)| (dim, val))
    }
    
    /// Number of non-zero entries
    pub fn nnz(&self) -> usize {
        self.entries.len()
    }
    
    /// L2 norm
    pub fn norm(&self) -> f64 {
        self.entries.values().map(|v| v * v).sum::<f64>().sqrt()
    }
    
    /// L1 norm (sum of absolute values)
    pub fn l1_norm(&self) -> f64 {
        self.entries.values().map(|v| v.abs()).sum()
    }
    
    /// Normalize to unit L2 norm
    pub fn normalize(&mut self) {
        let norm = self.norm();
        if norm > 1e-10 {
            for val in self.entries.values_mut() {
                *val /= norm;
            }
        }
    }
    
    /// Convert to probability distribution (normalize to sum to 1)
    pub fn to_distribution(&self) -> Vec<f64> {
        let mut dist = vec![0.0; self.dims];
        let sum: f64 = self.entries.values().sum();
        
        if sum > 1e-10 {
            for (&dim, &val) in &self.entries {
                dist[dim] = val / sum;
            }
        }
        
        dist
    }
    
    /// Dot product with another sparse vector
    pub fn dot(&self, other: &SparseVector) -> f64 {
        let mut result = 0.0;
        
        // Iterate over the smaller vector
        let (smaller, larger) = if self.nnz() < other.nnz() {
            (&self.entries, &other.entries)
        } else {
            (&other.entries, &self.entries)
        };
        
        for (&dim, &val) in smaller {
            if let Some(&other_val) = larger.get(&dim) {
                result += val * other_val;
            }
        }
        
        result
    }
    
    /// Cosine similarity with another sparse vector
    pub fn cosine_similarity(&self, other: &SparseVector) -> f64 {
        let dot = self.dot(other);
        let norm_product = self.norm() * other.norm();
        
        if norm_product > 1e-10 {
            dot / norm_product
        } else {
            0.0
        }
    }
}

/// Hash a string to a dimension
pub fn hash_to_dim(s: &str, dims: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    (hasher.finish() as usize) % dims
}

/// Extract n-grams from text
pub fn extract_ngrams(text: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < n {
        return vec![text.to_string()];
    }
    
    chars.windows(n)
        .map(|w| w.iter().collect())
        .collect()
}

/// Encode an event into a sparse vector
pub fn encode_event(
    entities: &[String],
    predicates: &[String],
    text: &str,
    dims: usize,
) -> SparseVector {
    let mut vector = SparseVector::with_dims(dims);
    
    // Entity features (highest weight)
    for entity in entities {
        let dim = hash_to_dim(entity, dims);
        vector.add(dim, 2.0);
    }
    
    // Predicate features
    for predicate in predicates {
        let dim = hash_to_dim(predicate, dims);
        vector.add(dim, 1.5);
    }
    
    // N-gram features (lexical)
    for ngram in extract_ngrams(text, 3) {
        let dim = hash_to_dim(&ngram, dims);
        vector.add(dim, 0.5);
    }
    
    vector.normalize();
    vector
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sparse_vector_basic() {
        let mut v = SparseVector::new();
        v.add(0, 1.0);
        v.add(100, 2.0);
        
        assert_eq!(v.get(0), 1.0);
        assert_eq!(v.get(100), 2.0);
        assert_eq!(v.get(50), 0.0);
        assert_eq!(v.nnz(), 2);
    }
    
    #[test]
    fn test_normalize() {
        let mut v = SparseVector::with_dims(100);
        v.add(0, 3.0);
        v.add(1, 4.0);
        
        v.normalize();
        
        // Should be unit norm (3-4-5 triangle)
        assert!((v.norm() - 1.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_cosine_similarity() {
        let mut v1 = SparseVector::with_dims(100);
        v1.add(0, 1.0);
        v1.add(1, 0.0);
        
        let mut v2 = SparseVector::with_dims(100);
        v2.add(0, 1.0);
        v2.add(1, 0.0);
        
        // Same vector should have similarity 1
        assert!((v1.cosine_similarity(&v2) - 1.0).abs() < 1e-10);
        
        // Orthogonal vectors should have similarity 0
        let mut v3 = SparseVector::with_dims(100);
        v3.add(2, 1.0);
        
        assert!(v1.cosine_similarity(&v3).abs() < 1e-10);
    }
    
    #[test]
    fn test_hash_deterministic() {
        let dim1 = hash_to_dim("test_entity", 65536);
        let dim2 = hash_to_dim("test_entity", 65536);
        assert_eq!(dim1, dim2);
    }
    
    #[test]
    fn test_ngrams() {
        let ngrams = extract_ngrams("hello", 3);
        assert_eq!(ngrams, vec!["hel", "ell", "llo"]);
    }
    
    #[test]
    fn test_encode_event() {
        let entities = vec!["user:alice".to_string()];
        let predicates = vec!["preference:food".to_string()];
        let text = "I like pizza";
        
        let vector = encode_event(&entities, &predicates, text, 65536);
        
        assert!(vector.nnz() > 0);
        assert!((vector.norm() - 1.0).abs() < 1e-10);
    }
}
