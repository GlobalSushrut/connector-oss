//! Sync protocol implementation
//!
//! Block-verified sync as specified in arch.md §19.1

use async_trait::async_trait;
use cid::Cid;

use vac_core::{BlockHeader, VacError, VacResult, VaultPatch};
use vac_crypto::verify_block_signature;

/// Sync result
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub transferred_blocks: usize,
    pub transferred_objects: usize,
}

/// Sync error
#[derive(Debug, Clone)]
pub enum SyncError {
    InvalidSignature { block_no: u64 },
    PrevHashMismatch { block_no: u64 },
    BlockHashMismatch { block_no: u64 },
    MissingBlock { block_no: u64 },
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::InvalidSignature { block_no } => {
                write!(f, "Invalid signature on block {}", block_no)
            }
            SyncError::PrevHashMismatch { block_no } => {
                write!(f, "Block {} prev_hash mismatch", block_no)
            }
            SyncError::BlockHashMismatch { block_no } => {
                write!(f, "Block {} hash mismatch", block_no)
            }
            SyncError::MissingBlock { block_no } => {
                write!(f, "Missing block {}", block_no)
            }
        }
    }
}

impl std::error::Error for SyncError {}

/// Trait for a syncable vault
#[async_trait]
pub trait SyncableVault: Send + Sync {
    /// Get the head block
    async fn get_head_block(&self) -> VacResult<BlockHeader>;
    
    /// Get a block by number
    async fn get_block(&self, block_no: u64) -> VacResult<BlockHeader>;
    
    /// Get blocks in a range (inclusive)
    async fn get_block_range(&self, from: u64, to: u64) -> VacResult<Vec<BlockHeader>>;
    
    /// Get a patch by CID
    async fn get_patch(&self, cid: &Cid) -> VacResult<VaultPatch>;
    
    /// Get an object by CID
    async fn get_object(&self, cid: &Cid) -> VacResult<Vec<u8>>;
    
    /// Put an object
    async fn put_object(&self, bytes: &[u8]) -> VacResult<Cid>;
    
    /// Put a block
    async fn put_block(&self, block: &BlockHeader) -> VacResult<()>;
    
    /// Set the head to a block hash
    async fn set_head(&self, block_hash: [u8; 32]) -> VacResult<()>;
}

/// Verify a block's signature and hash
pub fn verify_block(block: &BlockHeader, expected_prev_hash: &[u8; 32]) -> Result<(), SyncError> {
    // 1. Verify prev_hash chain
    if &block.prev_block_hash != expected_prev_hash {
        return Err(SyncError::PrevHashMismatch { block_no: block.block_no });
    }
    
    // 2. Verify all signatures
    let block_message = compute_block_message(block);
    for sig in &block.signatures {
        match verify_block_signature(sig, &block_message) {
            Ok(true) => {}
            _ => return Err(SyncError::InvalidSignature { block_no: block.block_no }),
        }
    }
    
    // 3. Verify block_hash computation
    let computed_hash = vac_core::compute_block_hash(
        block.block_no,
        &block.prev_block_hash,
        block.ts,
        &block.links.patch,
        &block.links.manifest,
        &block.signatures,
    ).map_err(|_| SyncError::BlockHashMismatch { block_no: block.block_no })?;
    
    if computed_hash != block.block_hash {
        return Err(SyncError::BlockHashMismatch { block_no: block.block_no });
    }
    
    Ok(())
}

/// Compute the message to sign for a block (everything except signatures)
fn compute_block_message(block: &BlockHeader) -> Vec<u8> {
    // Serialize block data without signatures
    let mut data = Vec::new();
    data.extend_from_slice(&block.block_no.to_be_bytes());
    data.extend_from_slice(&block.prev_block_hash);
    data.extend_from_slice(&block.ts.to_be_bytes());
    data.extend_from_slice(&block.links.patch.to_bytes());
    data.extend_from_slice(&block.links.manifest.to_bytes());
    data
}

/// Find common ancestor block between two vaults
pub async fn find_common_ancestor<S: SyncableVault, T: SyncableVault>(
    source: &S,
    target: &T,
) -> VacResult<BlockHeader> {
    let source_head = source.get_head_block().await?;
    let target_head = target.get_head_block().await?;
    
    // Walk back from both heads to find common ancestor
    let mut source_block = source_head;
    let mut target_block = target_head;
    
    // Simple algorithm: walk back the longer chain first
    while source_block.block_no > target_block.block_no {
        if source_block.block_no == 0 {
            break;
        }
        source_block = source.get_block(source_block.block_no - 1).await?;
    }
    
    while target_block.block_no > source_block.block_no {
        if target_block.block_no == 0 {
            break;
        }
        target_block = target.get_block(target_block.block_no - 1).await?;
    }
    
    // Now walk back both until we find matching hashes
    while source_block.block_hash != target_block.block_hash {
        if source_block.block_no == 0 || target_block.block_no == 0 {
            // No common ancestor (shouldn't happen in practice)
            return Err(VacError::InvalidState("No common ancestor found".into()));
        }
        source_block = source.get_block(source_block.block_no - 1).await?;
        target_block = target.get_block(target_block.block_no - 1).await?;
    }
    
    Ok(source_block)
}

/// Sync target vault to match source vault
pub async fn sync<S: SyncableVault, T: SyncableVault>(
    source: &S,
    target: &T,
) -> Result<SyncResult, SyncError> {
    let source_head = source.get_head_block().await
        .map_err(|_| SyncError::MissingBlock { block_no: 0 })?;
    let target_head = target.get_head_block().await
        .map_err(|_| SyncError::MissingBlock { block_no: 0 })?;
    
    // Already in sync
    if source_head.block_hash == target_head.block_hash {
        return Ok(SyncResult {
            transferred_blocks: 0,
            transferred_objects: 0,
        });
    }
    
    // Find common ancestor
    let ancestor = find_common_ancestor(source, target).await
        .map_err(|_| SyncError::MissingBlock { block_no: 0 })?;
    
    // Get blocks from ancestor to source head
    let blocks = source.get_block_range(ancestor.block_no + 1, source_head.block_no).await
        .map_err(|_| SyncError::MissingBlock { block_no: ancestor.block_no + 1 })?;
    
    // Transfer and verify each block IN ORDER
    let mut prev_hash = ancestor.block_hash;
    let mut total_objects = 0;
    
    for block in &blocks {
        // Verify block
        verify_block(block, &prev_hash)?;
        
        // Fetch and store objects referenced by this block's patch
        let patch = source.get_patch(&block.links.patch).await
            .map_err(|_| SyncError::MissingBlock { block_no: block.block_no })?;
        
        for cid in &patch.added_cids {
            let obj = source.get_object(cid).await
                .map_err(|_| SyncError::MissingBlock { block_no: block.block_no })?;
            target.put_object(&obj).await
                .map_err(|_| SyncError::MissingBlock { block_no: block.block_no })?;
            total_objects += 1;
        }
        
        // Store the verified block
        target.put_block(block).await
            .map_err(|_| SyncError::MissingBlock { block_no: block.block_no })?;
        
        prev_hash = block.block_hash;
    }
    
    // Update target head to last verified block
    if let Some(last_block) = blocks.last() {
        target.set_head(last_block.block_hash).await
            .map_err(|_| SyncError::MissingBlock { block_no: last_block.block_no })?;
    }
    
    Ok(SyncResult {
        transferred_blocks: blocks.len(),
        transferred_objects: total_objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sync_error_display() {
        let err = SyncError::InvalidSignature { block_no: 42 };
        assert!(err.to_string().contains("42"));
    }
}
