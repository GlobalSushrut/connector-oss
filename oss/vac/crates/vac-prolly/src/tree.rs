//! Prolly tree implementation
//!
//! A history-independent Merkle tree with content-defined chunking.

use async_trait::async_trait;
use cid::Cid;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::future::Future;

use vac_core::{VacError, VacResult};

use crate::node::ProllyNode;
use crate::proof::{ProllyProof, ProofStep};

/// Trait for node storage
#[async_trait]
pub trait NodeStore: Send + Sync {
    /// Get a node by CID
    async fn get(&self, cid: &Cid) -> VacResult<ProllyNode>;
    
    /// Put a node, returns its CID
    async fn put(&self, node: &ProllyNode) -> VacResult<Cid>;
    
    /// Check if a node exists
    async fn contains(&self, cid: &Cid) -> bool;
}

/// In-memory node store for testing
#[derive(Default)]
pub struct MemoryNodeStore {
    nodes: std::sync::RwLock<BTreeMap<Cid, ProllyNode>>,
}

#[async_trait]
impl NodeStore for MemoryNodeStore {
    async fn get(&self, cid: &Cid) -> VacResult<ProllyNode> {
        self.nodes
            .read()
            .unwrap()
            .get(cid)
            .cloned()
            .ok_or_else(|| VacError::NotFound(format!("Node not found: {}", cid)))
    }
    
    async fn put(&self, node: &ProllyNode) -> VacResult<Cid> {
        use vac_core::ContentAddressable;
        let cid = node.cid()?;
        self.nodes.write().unwrap().insert(cid.clone(), node.clone());
        Ok(cid)
    }
    
    async fn contains(&self, cid: &Cid) -> bool {
        self.nodes.read().unwrap().contains_key(cid)
    }
}

/// Prolly tree
pub struct ProllyTree<S: NodeStore> {
    store: S,
    root: Option<Cid>,
}

impl<S: NodeStore> ProllyTree<S> {
    /// Create a new empty tree
    pub fn new(store: S) -> Self {
        Self { store, root: None }
    }
    
    /// Create a tree with an existing root
    pub fn with_root(store: S, root: Cid) -> Self {
        Self { store, root: Some(root) }
    }
    
    /// Get the root CID
    pub fn root(&self) -> Option<&Cid> {
        self.root.as_ref()
    }
    
    /// Get a value by key (iterative to avoid async recursion)
    pub async fn get(&self, key: &[u8]) -> VacResult<Option<Cid>> {
        let mut current_cid = match &self.root {
            Some(cid) => cid.clone(),
            None => return Ok(None),
        };
        
        loop {
            let node = self.store.get(&current_cid).await?;
            
            if node.is_leaf() {
                return Ok(node.get(key).cloned());
            } else {
                let child_idx = node.find_child_index(key);
                if child_idx < node.values.len() {
                    current_cid = node.values[child_idx].clone();
                } else {
                    return Ok(None);
                }
            }
        }
    }
    
    /// Insert a key-value pair (simplified for v0.1 - single leaf)
    pub async fn insert(&mut self, key: Vec<u8>, value: Cid) -> VacResult<()> {
        let new_root = match &self.root {
            Some(root_cid) => {
                // For v0.1, we only support single-leaf trees
                self.insert_into_leaf(root_cid, key, value).await?
            }
            None => {
                // Create new leaf node
                let node = ProllyNode::new_leaf(vec![key], vec![value]);
                self.store.put(&node).await?
            }
        };
        
        self.root = Some(new_root);
        Ok(())
    }
    
    /// Insert into leaf (simplified - no tree balancing for v0.1)
    async fn insert_into_leaf(&self, node_cid: &Cid, key: Vec<u8>, value: Cid) -> VacResult<Cid> {
        let node = self.store.get(node_cid).await?;
        let new_node = node.insert(key, value);
        self.store.put(&new_node).await
    }
    
    /// Generate a membership proof for a key
    pub async fn prove(&self, key: &[u8]) -> VacResult<Option<ProllyProof>> {
        let root_cid = match &self.root {
            Some(cid) => cid,
            None => return Ok(None),
        };
        
        let root_node = self.store.get(root_cid).await?;
        let mut root_node_clone = root_node.clone();
        let root_hash = root_node_clone.hash();
        
        match self.prove_iterative(key).await? {
            Some((leaf_node, value_cid, path)) => {
                Ok(Some(ProllyProof {
                    key: key.to_vec(),
                    value_cid,
                    leaf_node,
                    path,
                    root_hash,
                }))
            }
            None => Ok(None),
        }
    }
    
    /// Prove key existence (iterative)
    async fn prove_iterative(
        &self,
        key: &[u8],
    ) -> VacResult<Option<(ProllyNode, Cid, Vec<ProofStep>)>> {
        let mut current_cid = match &self.root {
            Some(cid) => cid.clone(),
            None => return Ok(None),
        };
        
        let mut path = Vec::new();
        
        loop {
            let node = self.store.get(&current_cid).await?;
            let mut node_clone = node.clone();
            
            if node.is_leaf() {
                // Check if key exists
                match node.clone().get(key) {
                    Some(value_cid) => return Ok(Some((node, value_cid.clone(), path))),
                    None => return Ok(None),
                }
            } else {
                let child_idx = node.find_child_index(key);
                
                // Collect sibling hashes
                let mut sibling_hashes = Vec::new();
                for (i, child_cid) in node.values.iter().enumerate() {
                    if i != child_idx {
                        let mut child = self.store.get(child_cid).await?;
                        sibling_hashes.push(child.hash());
                    }
                }
                
                // Add proof step
                path.push(ProofStep {
                    level: node.level,
                    node_hash: node_clone.hash(),
                    sibling_hashes,
                    position: child_idx as u16,
                });
                
                // Move to child
                current_cid = node.values[child_idx].clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_empty_tree() {
        let store = MemoryNodeStore::default();
        let tree = ProllyTree::new(store);
        
        assert!(tree.root().is_none());
        assert!(tree.get(b"key").await.unwrap().is_none());
    }
    
    #[tokio::test]
    async fn test_insert_and_get() {
        let store = MemoryNodeStore::default();
        let mut tree = ProllyTree::new(store);
        
        let value = Cid::default();
        tree.insert(b"key1".to_vec(), value.clone()).await.unwrap();
        
        assert!(tree.root().is_some());
        assert_eq!(tree.get(b"key1").await.unwrap(), Some(value));
        assert!(tree.get(b"key2").await.unwrap().is_none());
    }
    
    #[tokio::test]
    async fn test_multiple_inserts() {
        let store = MemoryNodeStore::default();
        let mut tree = ProllyTree::new(store);
        
        for i in 0..100 {
            let key = format!("key_{:03}", i);
            tree.insert(key.into_bytes(), Cid::default()).await.unwrap();
        }
        
        // Verify all keys exist
        for i in 0..100 {
            let key = format!("key_{:03}", i);
            assert!(tree.get(key.as_bytes()).await.unwrap().is_some());
        }
    }
    
    #[tokio::test]
    async fn test_proof_generation() {
        let store = MemoryNodeStore::default();
        let mut tree = ProllyTree::new(store);
        
        tree.insert(b"key1".to_vec(), Cid::default()).await.unwrap();
        tree.insert(b"key2".to_vec(), Cid::default()).await.unwrap();
        
        let proof = tree.prove(b"key1").await.unwrap();
        assert!(proof.is_some());
        
        let proof = tree.prove(b"nonexistent").await.unwrap();
        assert!(proof.is_none());
    }
}
