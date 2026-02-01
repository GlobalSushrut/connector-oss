//! Boundary detection for content-defined chunking
//!
//! Uses rolling hash to determine chunk boundaries in a history-independent way.

use sha2::{Sha256, Digest};

use crate::{BOUNDARY_THRESHOLD, DEFAULT_Q};

/// Check if a key is a boundary key (starts a new chunk)
/// 
/// A key is a boundary if: hash(key) < BOUNDARY_THRESHOLD
/// This gives approximately 1/Q probability of being a boundary.
pub fn is_boundary(key: &[u8]) -> bool {
    let hash = hash_key(key);
    hash < BOUNDARY_THRESHOLD
}

/// Hash a key to a u32 for boundary detection
fn hash_key(key: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    
    // Take first 4 bytes as u32
    u32::from_be_bytes([result[0], result[1], result[2], result[3]])
}

/// Compute the boundary probability for a given Q
pub fn boundary_probability(q: usize) -> f64 {
    1.0 / q as f64
}

/// Expected chunk size for a given Q
pub fn expected_chunk_size(q: usize) -> usize {
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_boundary_deterministic() {
        let key = b"test_key";
        let is_b1 = is_boundary(key);
        let is_b2 = is_boundary(key);
        assert_eq!(is_b1, is_b2);
    }
    
    #[test]
    fn test_boundary_distribution() {
        // Test that approximately 1/Q keys are boundaries
        let mut boundary_count = 0;
        let total = 10000;
        
        for i in 0..total {
            let key = format!("key_{}", i);
            if is_boundary(key.as_bytes()) {
                boundary_count += 1;
            }
        }
        
        let ratio = boundary_count as f64 / total as f64;
        let expected = 1.0 / DEFAULT_Q as f64;
        
        // Should be within 50% of expected (statistical test)
        assert!(ratio > expected * 0.5);
        assert!(ratio < expected * 1.5);
    }
}
