//! Content Addressable Store trait

use async_trait::async_trait;
use cid::Cid;

use vac_core::{ContentAddressable, VacResult};

/// Trait for content-addressable storage
#[async_trait]
pub trait ContentStore: Send + Sync {
    /// Get raw bytes by CID
    async fn get_bytes(&self, cid: &Cid) -> VacResult<Vec<u8>>;
    
    /// Put raw bytes, returns CID
    async fn put_bytes(&self, bytes: &[u8]) -> VacResult<Cid>;
    
    /// Check if CID exists
    async fn contains(&self, cid: &Cid) -> bool;
    
    /// Delete by CID (for garbage collection)
    async fn delete(&self, cid: &Cid) -> VacResult<()>;
    
    /// Get an object by CID
    async fn get<T: ContentAddressable + Send>(&self, cid: &Cid) -> VacResult<T> {
        let bytes = self.get_bytes(cid).await?;
        T::from_bytes(&bytes)
    }
    
    /// Put an object, returns CID
    async fn put<T: ContentAddressable + Sync>(&self, obj: &T) -> VacResult<Cid> {
        let bytes = obj.to_bytes()?;
        self.put_bytes(&bytes).await
    }
}
