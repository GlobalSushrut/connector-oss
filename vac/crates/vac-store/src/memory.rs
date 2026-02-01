//! In-memory content store implementation

use async_trait::async_trait;
use cid::Cid;
use cid::multihash::Multihash;
use dashmap::DashMap;

use vac_core::{VacError, VacResult, sha256};

use crate::cas::ContentStore;

/// DAG-CBOR multicodec code
const DAG_CBOR_CODE: u64 = 0x71;

/// SHA2-256 multihash code
const SHA256_CODE: u64 = 0x12;

/// In-memory content store for testing and development
#[derive(Default)]
pub struct MemoryStore {
    data: DashMap<Cid, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
        }
    }
    
    /// Get the number of stored objects
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get all CIDs
    pub fn cids(&self) -> Vec<Cid> {
        self.data.iter().map(|r| r.key().clone()).collect()
    }
}

#[async_trait]
impl ContentStore for MemoryStore {
    async fn get_bytes(&self, cid: &Cid) -> VacResult<Vec<u8>> {
        self.data
            .get(cid)
            .map(|r| r.value().clone())
            .ok_or_else(|| VacError::NotFound(format!("CID not found: {}", cid)))
    }
    
    async fn put_bytes(&self, bytes: &[u8]) -> VacResult<Cid> {
        let hash_bytes = sha256(bytes);
        let mh = Multihash::<64>::wrap(SHA256_CODE, &hash_bytes)
            .map_err(|e| VacError::CidError(e.to_string()))?;
        let cid = Cid::new_v1(DAG_CBOR_CODE, mh);
        self.data.insert(cid.clone(), bytes.to_vec());
        Ok(cid)
    }
    
    async fn contains(&self, cid: &Cid) -> bool {
        self.data.contains_key(cid)
    }
    
    async fn delete(&self, cid: &Cid) -> VacResult<()> {
        self.data.remove(cid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_store_basic() {
        let store = MemoryStore::new();
        
        let data = b"hello world";
        let cid = store.put_bytes(data).await.unwrap();
        
        assert!(store.contains(&cid).await);
        assert_eq!(store.len(), 1);
        
        let retrieved = store.get_bytes(&cid).await.unwrap();
        assert_eq!(retrieved, data);
    }
    
    #[tokio::test]
    async fn test_memory_store_delete() {
        let store = MemoryStore::new();
        
        let data = b"hello world";
        let cid = store.put_bytes(data).await.unwrap();
        
        assert!(store.contains(&cid).await);
        
        store.delete(&cid).await.unwrap();
        
        assert!(!store.contains(&cid).await);
    }
    
    #[tokio::test]
    async fn test_memory_store_not_found() {
        let store = MemoryStore::new();
        let fake_cid = Cid::default();
        
        let result = store.get_bytes(&fake_cid).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_content_addressable() {
        let store = MemoryStore::new();
        
        // Same content should produce same CID
        let data = b"hello world";
        let cid1 = store.put_bytes(data).await.unwrap();
        let cid2 = store.put_bytes(data).await.unwrap();
        
        assert_eq!(cid1, cid2);
        assert_eq!(store.len(), 1); // Only one entry
    }
}
