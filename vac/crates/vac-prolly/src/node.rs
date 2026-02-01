//! Prolly tree node implementation

use cid::Cid;
use serde::{Deserialize, Serialize};
use vac_core::{compute_prolly_node_hash, ContentAddressable, VacResult};

/// A node in the Prolly tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProllyNode {
    /// Level in the tree (0 = leaf, >0 = internal)
    pub level: u8,
    /// Sorted keys
    pub keys: Vec<Vec<u8>>,
    /// Values (CIDs to data for leaves, CIDs to child nodes for internal)
    pub values: Vec<Cid>,
    /// Cached node hash
    #[serde(skip)]
    cached_hash: Option<[u8; 32]>,
}

impl ProllyNode {
    /// Create a new leaf node
    pub fn new_leaf(keys: Vec<Vec<u8>>, values: Vec<Cid>) -> Self {
        assert_eq!(keys.len(), values.len(), "keys and values must have same length");
        Self {
            level: 0,
            keys,
            values,
            cached_hash: None,
        }
    }
    
    /// Create a new internal node
    pub fn new_internal(level: u8, keys: Vec<Vec<u8>>, children: Vec<Cid>) -> Self {
        assert!(level > 0, "internal nodes must have level > 0");
        assert_eq!(keys.len(), children.len(), "keys and children must have same length");
        Self {
            level,
            keys,
            values: children,
            cached_hash: None,
        }
    }
    
    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
    
    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    
    /// Compute the node hash
    pub fn hash(&mut self) -> [u8; 32] {
        if let Some(hash) = self.cached_hash {
            return hash;
        }
        
        let hash = compute_prolly_node_hash(self.level, &self.keys, &self.values);
        self.cached_hash = Some(hash);
        hash
    }
    
    /// Get value for a key (binary search)
    pub fn get(&self, key: &[u8]) -> Option<&Cid> {
        match self.keys.binary_search_by(|k| k.as_slice().cmp(key)) {
            Ok(idx) => Some(&self.values[idx]),
            Err(_) => None,
        }
    }
    
    /// Find the child index for a key (for internal nodes)
    pub fn find_child_index(&self, key: &[u8]) -> usize {
        match self.keys.binary_search_by(|k| k.as_slice().cmp(key)) {
            Ok(idx) => idx,
            Err(idx) => {
                if idx == 0 {
                    0
                } else {
                    idx - 1
                }
            }
        }
    }
    
    /// Insert a key-value pair (returns new node, doesn't mutate)
    pub fn insert(&self, key: Vec<u8>, value: Cid) -> Self {
        let mut keys = self.keys.clone();
        let mut values = self.values.clone();
        
        match keys.binary_search_by(|k| k.as_slice().cmp(&key)) {
            Ok(idx) => {
                // Key exists, update value
                values[idx] = value;
            }
            Err(idx) => {
                // Insert at position
                keys.insert(idx, key);
                values.insert(idx, value);
            }
        }
        
        Self {
            level: self.level,
            keys,
            values,
            cached_hash: None,
        }
    }
    
    /// Remove a key (returns new node, doesn't mutate)
    pub fn remove(&self, key: &[u8]) -> Option<Self> {
        match self.keys.binary_search_by(|k| k.as_slice().cmp(key)) {
            Ok(idx) => {
                let mut keys = self.keys.clone();
                let mut values = self.values.clone();
                keys.remove(idx);
                values.remove(idx);
                
                Some(Self {
                    level: self.level,
                    keys,
                    values,
                    cached_hash: None,
                })
            }
            Err(_) => None, // Key not found
        }
    }
    
    /// Split node at boundary keys
    pub fn split_at_boundaries(&self) -> Vec<Self> {
        use crate::boundary::is_boundary;
        
        if self.is_empty() {
            return vec![];
        }
        
        let mut chunks = Vec::new();
        let mut current_keys = Vec::new();
        let mut current_values = Vec::new();
        
        for (i, key) in self.keys.iter().enumerate() {
            // If this key is a boundary and we have accumulated entries, start new chunk
            if is_boundary(key) && !current_keys.is_empty() {
                chunks.push(Self {
                    level: self.level,
                    keys: std::mem::take(&mut current_keys),
                    values: std::mem::take(&mut current_values),
                    cached_hash: None,
                });
            }
            
            current_keys.push(key.clone());
            current_values.push(self.values[i].clone());
        }
        
        // Don't forget the last chunk
        if !current_keys.is_empty() {
            chunks.push(Self {
                level: self.level,
                keys: current_keys,
                values: current_values,
                cached_hash: None,
            });
        }
        
        chunks
    }
}

impl ContentAddressable for ProllyNode {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_leaf_node() {
        let keys = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let values = vec![Cid::default(), Cid::default(), Cid::default()];
        
        let node = ProllyNode::new_leaf(keys, values);
        
        assert!(node.is_leaf());
        assert_eq!(node.len(), 3);
    }
    
    #[test]
    fn test_get() {
        let keys = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let values = vec![Cid::default(), Cid::default(), Cid::default()];
        
        let node = ProllyNode::new_leaf(keys, values);
        
        assert!(node.get(b"a").is_some());
        assert!(node.get(b"b").is_some());
        assert!(node.get(b"d").is_none());
    }
    
    #[test]
    fn test_insert() {
        let keys = vec![b"a".to_vec(), b"c".to_vec()];
        let values = vec![Cid::default(), Cid::default()];
        
        let node = ProllyNode::new_leaf(keys, values);
        let node2 = node.insert(b"b".to_vec(), Cid::default());
        
        assert_eq!(node2.len(), 3);
        assert!(node2.get(b"b").is_some());
    }
    
    #[test]
    fn test_remove() {
        let keys = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let values = vec![Cid::default(), Cid::default(), Cid::default()];
        
        let node = ProllyNode::new_leaf(keys, values);
        let node2 = node.remove(b"b").unwrap();
        
        assert_eq!(node2.len(), 2);
        assert!(node2.get(b"b").is_none());
    }
    
    #[test]
    fn test_hash_deterministic() {
        let keys = vec![b"a".to_vec(), b"b".to_vec()];
        let values = vec![Cid::default(), Cid::default()];
        
        let mut node1 = ProllyNode::new_leaf(keys.clone(), values.clone());
        let mut node2 = ProllyNode::new_leaf(keys, values);
        
        assert_eq!(node1.hash(), node2.hash());
    }
}
