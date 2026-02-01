//! Merkle proof structures and verification for Prolly trees

use cid::Cid;
use serde::{Deserialize, Serialize};

use vac_core::{sha256, VacResult};

use crate::node::ProllyNode;

/// A membership proof for a key in a Prolly tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProllyProof {
    /// The key being proved
    pub key: Vec<u8>,
    /// The value CID
    pub value_cid: Cid,
    /// The full leaf node containing the key
    pub leaf_node: ProllyNode,
    /// Path from leaf to root
    pub path: Vec<ProofStep>,
    /// Expected root hash
    pub root_hash: [u8; 32],
}

/// A step in the proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// Level in the tree
    pub level: u8,
    /// Hash of the node at this level
    pub node_hash: [u8; 32],
    /// Hashes of sibling nodes (left-to-right, excluding current)
    pub sibling_hashes: Vec<[u8; 32]>,
    /// Position of node_hash among siblings
    pub position: u16,
}

impl ProllyProof {
    /// Verify the proof
    pub fn verify(&self) -> VacResult<bool> {
        // 1. Verify key exists in leaf node
        if !self.leaf_node.keys.iter().any(|k| k == &self.key) {
            return Ok(false);
        }
        
        // 2. Verify value matches
        let key_index = self.leaf_node.keys.iter().position(|k| k == &self.key);
        match key_index {
            Some(idx) if self.leaf_node.values[idx] == self.value_cid => {}
            _ => return Ok(false),
        }
        
        // 3. Verify leaf node hash
        let mut leaf_clone = self.leaf_node.clone();
        let leaf_hash = leaf_clone.hash();
        
        // 4. Walk up the path, recomputing parent hashes
        let mut current_hash = leaf_hash;
        
        for step in &self.path {
            // Insert current hash at correct position among siblings
            let mut all_children: Vec<[u8; 32]> = step.sibling_hashes.clone();
            all_children.insert(step.position as usize, current_hash);
            
            // Recompute parent hash: H(level || child_hash_0 || child_hash_1 || ...)
            let mut parent_data = vec![step.level];
            for child_hash in &all_children {
                parent_data.extend_from_slice(child_hash);
            }
            current_hash = sha256(&parent_data);
        }
        
        // 5. Final hash should match root
        Ok(current_hash == self.root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_structure() {
        let proof = ProllyProof {
            key: b"test_key".to_vec(),
            value_cid: Cid::default(),
            leaf_node: ProllyNode::new_leaf(
                vec![b"test_key".to_vec()],
                vec![Cid::default()],
            ),
            path: vec![],
            root_hash: [0u8; 32],
        };
        
        assert_eq!(proof.key, b"test_key".to_vec());
    }
}
