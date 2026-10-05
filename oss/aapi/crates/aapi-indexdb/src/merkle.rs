//! Merkle tree implementation for transparency logs

use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// In-memory Merkle tree for append-only logs
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes
    leaves: Vec<String>,
    /// Cached internal nodes: (level, index) -> hash
    nodes: HashMap<(usize, usize), String>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            nodes: HashMap::new(),
        }
    }

    /// Append a new leaf and return its index
    pub fn append(&mut self, data: &str) -> usize {
        let leaf_hash = self.hash_leaf(data.as_bytes());
        let index = self.leaves.len();
        self.leaves.push(leaf_hash);
        
        // Invalidate cached nodes (simple approach - rebuild on demand)
        self.nodes.clear();
        
        index
    }

    /// Get the number of leaves
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the root hash
    pub fn root(&self) -> Option<String> {
        if self.leaves.is_empty() {
            return None;
        }
        
        if self.leaves.len() == 1 {
            return Some(self.leaves[0].clone());
        }

        Some(self.compute_root(&self.leaves))
    }

    /// Get a leaf hash by index
    pub fn get_leaf(&self, index: usize) -> Option<&String> {
        self.leaves.get(index)
    }

    /// Get an inclusion proof for a leaf
    pub fn get_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[leaf_index].clone();
        let path = self.compute_proof_path(leaf_index);
        
        Some(MerkleProof {
            leaf_hash,
            leaf_index,
            path,
        })
    }

    /// Verify an inclusion proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let root = match self.root() {
            Some(r) => r,
            None => return false,
        };

        let computed_root = self.compute_root_from_proof(proof);
        computed_root == root
    }

    /// Hash a leaf (with 0x00 prefix to distinguish from internal nodes)
    fn hash_leaf(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&[0x00]); // Leaf prefix
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Hash an internal node (with 0x01 prefix)
    fn hash_internal(&self, left: &str, right: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&[0x01]); // Internal node prefix
        hasher.update(hex::decode(left).unwrap_or_default());
        hasher.update(hex::decode(right).unwrap_or_default());
        hex::encode(hasher.finalize())
    }

    /// Compute the root hash from leaves
    fn compute_root(&self, leaves: &[String]) -> String {
        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        let mut current_level: Vec<String> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;

            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    let hash = self.hash_internal(&current_level[i], &current_level[i + 1]);
                    next_level.push(hash);
                    i += 2;
                } else {
                    // Odd node: promote to next level
                    next_level.push(current_level[i].clone());
                    i += 1;
                }
            }

            current_level = next_level;
        }

        current_level[0].clone()
    }

    /// Compute the proof path for a leaf
    fn compute_proof_path(&self, leaf_index: usize) -> Vec<(String, bool)> {
        let mut path = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut index = leaf_index;

        while current_level.len() > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            
            if sibling_index < current_level.len() {
                let is_right = index % 2 == 0;
                path.push((current_level[sibling_index].clone(), is_right));
            }

            // Move to next level
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    let hash = self.hash_internal(&current_level[i], &current_level[i + 1]);
                    next_level.push(hash);
                    i += 2;
                } else {
                    next_level.push(current_level[i].clone());
                    i += 1;
                }
            }

            current_level = next_level;
            index /= 2;
        }

        path
    }

    /// Compute root from a proof
    fn compute_root_from_proof(&self, proof: &MerkleProof) -> String {
        let mut current = proof.leaf_hash.clone();

        for (sibling, is_right) in &proof.path {
            if *is_right {
                current = self.hash_internal(&current, sibling);
            } else {
                current = self.hash_internal(sibling, &current);
            }
        }

        current
    }

    /// Get a consistency proof between two tree sizes
    pub fn get_consistency_proof(&self, first_size: usize, second_size: usize) -> Option<ConsistencyProof> {
        if first_size > second_size || second_size > self.leaves.len() {
            return None;
        }

        if first_size == 0 {
            return Some(ConsistencyProof {
                first_size,
                second_size,
                proof_hashes: vec![],
            });
        }

        let first_root = self.compute_root(&self.leaves[..first_size]);
        let second_root = self.compute_root(&self.leaves[..second_size]);

        // Simplified consistency proof - just include the roots
        // A full implementation would include the minimal set of nodes
        Some(ConsistencyProof {
            first_size,
            second_size,
            proof_hashes: vec![first_root, second_root],
        })
    }
}

/// Merkle inclusion proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Hash of the leaf
    pub leaf_hash: String,
    /// Index of the leaf
    pub leaf_index: usize,
    /// Proof path: (sibling_hash, is_sibling_on_right)
    pub path: Vec<(String, bool)>,
}

impl MerkleProof {
    /// Verify the proof against a known root
    pub fn verify(&self, expected_root: &str) -> bool {
        let tree = MerkleTree::new();
        let computed = tree.compute_root_from_proof(self);
        computed == expected_root
    }
}

/// Consistency proof between two tree states
#[derive(Debug, Clone)]
pub struct ConsistencyProof {
    pub first_size: usize,
    pub second_size: usize,
    pub proof_hashes: Vec<String>,
}

/// Signed tree head for checkpointing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedTreeHead {
    /// Tree size (number of leaves)
    pub tree_size: u64,
    /// Root hash
    pub root_hash: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Signature over (tree_size || root_hash || timestamp)
    pub signature: Option<String>,
    /// Key ID used for signing
    pub key_id: Option<String>,
}

impl SignedTreeHead {
    /// Create a new unsigned tree head
    pub fn new(tree_size: u64, root_hash: String) -> Self {
        Self {
            tree_size,
            root_hash,
            timestamp: chrono::Utc::now(),
            signature: None,
            key_id: None,
        }
    }

    /// Get the bytes to sign
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.tree_size.to_be_bytes());
        bytes.extend_from_slice(self.root_hash.as_bytes());
        bytes.extend_from_slice(&self.timestamp.timestamp().to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.size(), 0);
        assert!(tree.root().is_none());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        let index = tree.append("hello");
        
        assert_eq!(index, 0);
        assert_eq!(tree.size(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleTree::new();
        tree.append("leaf1");
        tree.append("leaf2");
        tree.append("leaf3");
        
        assert_eq!(tree.size(), 3);
        
        let root = tree.root().unwrap();
        assert!(!root.is_empty());
    }

    #[test]
    fn test_root_changes_on_append() {
        let mut tree = MerkleTree::new();
        tree.append("leaf1");
        let root1 = tree.root().unwrap();
        
        tree.append("leaf2");
        let root2 = tree.root().unwrap();
        
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_inclusion_proof() {
        let mut tree = MerkleTree::new();
        tree.append("leaf0");
        tree.append("leaf1");
        tree.append("leaf2");
        tree.append("leaf3");
        
        let proof = tree.get_proof(1).unwrap();
        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_proof_for_all_leaves() {
        let mut tree = MerkleTree::new();
        for i in 0..8 {
            tree.append(&format!("leaf{}", i));
        }
        
        for i in 0..8 {
            let proof = tree.get_proof(i).unwrap();
            assert!(tree.verify_proof(&proof), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = MerkleTree::new();
        tree.append("leaf0");
        tree.append("leaf1");
        
        let mut proof = tree.get_proof(0).unwrap();
        proof.leaf_hash = "tampered".to_string();
        
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_consistency_proof() {
        let mut tree = MerkleTree::new();
        tree.append("leaf0");
        tree.append("leaf1");
        
        let proof = tree.get_consistency_proof(1, 2);
        assert!(proof.is_some());
        
        let proof = proof.unwrap();
        assert_eq!(proof.first_size, 1);
        assert_eq!(proof.second_size, 2);
    }

    #[test]
    fn test_deterministic_hashing() {
        let mut tree1 = MerkleTree::new();
        let mut tree2 = MerkleTree::new();
        
        tree1.append("data");
        tree2.append("data");
        
        assert_eq!(tree1.root(), tree2.root());
    }
}
