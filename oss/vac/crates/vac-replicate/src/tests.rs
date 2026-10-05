//! Tests for vac-replicate.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::error::ReplicateError;
use crate::merkle_sync::{MerkleSync, SyncSchedulerConfig};
use crate::peer::{PeerInfo, PeerRegistry};

use async_trait::async_trait;
use cid::Cid;
use std::collections::HashMap;
use std::sync::Mutex;
use vac_core::{BlockHeader, BlockLinks, VacError, VacResult, VaultPatch};
use vac_sync::protocol::SyncableVault;

// ---------------------------------------------------------------------------
// Mock SyncableVault for testing
// ---------------------------------------------------------------------------

struct MockVault {
    blocks: Mutex<HashMap<u64, BlockHeader>>,
    head_block_no: Mutex<u64>,
}

impl MockVault {
    fn new() -> Self {
        // Create a genesis block
        let genesis = make_block(0, [0u8; 32]);
        let mut blocks = HashMap::new();
        blocks.insert(0, genesis);
        Self {
            blocks: Mutex::new(blocks),
            head_block_no: Mutex::new(0),
        }
    }

    fn with_blocks(count: u64) -> Self {
        let vault = Self::new();
        {
            let mut blocks = vault.blocks.lock().unwrap();
            let mut prev_hash = blocks.get(&0).unwrap().block_hash;
            for i in 1..count {
                let block = make_block(i, prev_hash);
                prev_hash = block.block_hash;
                blocks.insert(i, block);
            }
        }
        *vault.head_block_no.lock().unwrap() = count - 1;
        vault
    }
}

fn make_block(block_no: u64, prev_hash: [u8; 32]) -> BlockHeader {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(block_no.to_be_bytes());
    hasher.update(prev_hash);
    let result = hasher.finalize();
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&result);

    // Create a dummy CID for patch/manifest links
    let dummy_cid = Cid::default();

    BlockHeader {
        type_: "block".to_string(),
        version: 1,
        block_no,
        prev_block_hash: prev_hash,
        block_hash,
        ts: chrono::Utc::now().timestamp(),
        links: BlockLinks {
            patch: dummy_cid,
            manifest: dummy_cid,
        },
        signatures: vec![],
        metadata: BTreeMap::new(),
    }
}

#[async_trait]
impl SyncableVault for MockVault {
    async fn get_head_block(&self) -> VacResult<BlockHeader> {
        let head_no = *self.head_block_no.lock().unwrap();
        let blocks = self.blocks.lock().unwrap();
        blocks
            .get(&head_no)
            .cloned()
            .ok_or_else(|| VacError::InvalidState("No head block".into()))
    }

    async fn get_block(&self, block_no: u64) -> VacResult<BlockHeader> {
        let blocks = self.blocks.lock().unwrap();
        blocks
            .get(&block_no)
            .cloned()
            .ok_or_else(|| VacError::InvalidState(format!("Block {} not found", block_no)))
    }

    async fn get_block_range(&self, from: u64, to: u64) -> VacResult<Vec<BlockHeader>> {
        let blocks = self.blocks.lock().unwrap();
        let mut result = Vec::new();
        for i in from..=to {
            if let Some(b) = blocks.get(&i) {
                result.push(b.clone());
            }
        }
        Ok(result)
    }

    async fn get_patch(&self, _cid: &Cid) -> VacResult<VaultPatch> {
        Ok(VaultPatch {
            type_: "patch".to_string(),
            version: 1,
            parent_block_hash: [0u8; 32],
            added_cids: vec![],
            removed_refs: vec![],
            updated_roots: BTreeMap::new(),
            links: BTreeMap::new(),
            metadata: BTreeMap::new(),
        })
    }

    async fn get_object(&self, _cid: &Cid) -> VacResult<Vec<u8>> {
        Ok(vec![])
    }

    async fn put_object(&self, _bytes: &[u8]) -> VacResult<Cid> {
        Ok(Cid::default())
    }

    async fn put_block(&self, block: &BlockHeader) -> VacResult<()> {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.insert(block.block_no, block.clone());
        Ok(())
    }

    async fn set_head(&self, _block_hash: [u8; 32]) -> VacResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PeerInfo tests
// ---------------------------------------------------------------------------

#[test]
fn test_peer_info_creation() {
    let peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![1, 2, 3]);
    assert_eq!(peer.cell_id, "cell-1");
    assert_eq!(peer.endpoint, "http://cell-1:4222");
    assert_eq!(peer.public_key, vec![1, 2, 3]);
    assert_eq!(peer.last_merkle_root, [0u8; 32]);
    assert_eq!(peer.last_block_no, 0);
    assert_eq!(peer.sync_count, 0);
    assert_eq!(peer.failed_sync_count, 0);
    assert!(peer.heartbeat_age().is_none());
    assert!(peer.is_stale(Duration::from_secs(30)));
}

#[test]
fn test_peer_heartbeat_update() {
    let mut peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    let root = [42u8; 32];
    peer.update_heartbeat(root, 10);
    assert_eq!(peer.last_merkle_root, root);
    assert_eq!(peer.last_block_no, 10);
    assert!(peer.heartbeat_age().is_some());
    assert!(!peer.is_stale(Duration::from_secs(30)));
}

#[test]
fn test_peer_sync_tracking() {
    let mut peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    assert!(peer.sync_age().is_none());

    peer.record_sync_success();
    assert_eq!(peer.sync_count, 1);
    assert!(peer.sync_age().is_some());

    peer.record_sync_failure();
    assert_eq!(peer.failed_sync_count, 1);
    assert_eq!(peer.sync_count, 1);
}

// ---------------------------------------------------------------------------
// PeerRegistry tests
// ---------------------------------------------------------------------------

#[test]
fn test_peer_registry_register_and_get() {
    let mut registry = PeerRegistry::new();
    let peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    registry.register(peer).unwrap();

    assert_eq!(registry.count(), 1);
    assert!(registry.get("cell-1").is_some());
    assert!(registry.get("cell-2").is_none());
}

#[test]
fn test_peer_registry_duplicate_register() {
    let mut registry = PeerRegistry::new();
    let peer1 = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    let peer2 = PeerInfo::new("cell-1", "http://cell-1:4223", vec![]);
    registry.register(peer1).unwrap();

    let result = registry.register(peer2);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ReplicateError::PeerAlreadyRegistered(_)
    ));
}

#[test]
fn test_peer_registry_upsert() {
    let mut registry = PeerRegistry::new();
    let peer1 = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    registry.upsert(peer1);
    assert_eq!(registry.get("cell-1").unwrap().endpoint, "http://cell-1:4222");

    let peer2 = PeerInfo::new("cell-1", "http://cell-1:9999", vec![]);
    registry.upsert(peer2);
    assert_eq!(registry.get("cell-1").unwrap().endpoint, "http://cell-1:9999");
    assert_eq!(registry.count(), 1);
}

#[test]
fn test_peer_registry_remove() {
    let mut registry = PeerRegistry::new();
    registry.upsert(PeerInfo::new("cell-1", "http://cell-1:4222", vec![]));
    registry.upsert(PeerInfo::new("cell-2", "http://cell-2:4222", vec![]));
    assert_eq!(registry.count(), 2);

    let removed = registry.remove("cell-1");
    assert!(removed.is_some());
    assert_eq!(registry.count(), 1);
    assert!(registry.get("cell-1").is_none());
}

#[test]
fn test_peer_registry_stale_peers() {
    let mut registry = PeerRegistry::new();
    let local_root = [1u8; 32];

    let mut peer1 = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    peer1.last_merkle_root = local_root; // in sync
    registry.upsert(peer1);

    let mut peer2 = PeerInfo::new("cell-2", "http://cell-2:4222", vec![]);
    peer2.last_merkle_root = [2u8; 32]; // out of sync
    registry.upsert(peer2);

    let stale = registry.stale_peers(&local_root);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].cell_id, "cell-2");
}

// ---------------------------------------------------------------------------
// MerkleSync tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_merkle_sync_add_peer() {
    let vault = std::sync::Arc::new(MockVault::new());
    let sync = MerkleSync::new(vault);

    let peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    sync.add_peer(peer).await.unwrap();

    let peers = sync.peers().read().await;
    assert_eq!(peers.count(), 1);
}

#[tokio::test]
async fn test_merkle_sync_check_all_peers() {
    let vault = std::sync::Arc::new(MockVault::new());
    let sync = MerkleSync::new(vault);

    let local_root = [10u8; 32];
    sync.set_local_merkle_root(local_root).await;

    // Peer in sync
    let mut peer1 = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    peer1.last_merkle_root = local_root;
    sync.add_peer(peer1).await.unwrap();

    // Peer out of sync
    let mut peer2 = PeerInfo::new("cell-2", "http://cell-2:4222", vec![]);
    peer2.last_merkle_root = [20u8; 32];
    sync.add_peer(peer2).await.unwrap();

    let statuses = sync.check_all_peers().await;
    assert_eq!(statuses.len(), 2);

    let in_sync_count = statuses.iter().filter(|s| s.in_sync).count();
    let out_of_sync_count = statuses.iter().filter(|s| !s.in_sync).count();
    assert_eq!(in_sync_count, 1);
    assert_eq!(out_of_sync_count, 1);
}

#[tokio::test]
async fn test_merkle_sync_handle_heartbeat() {
    let vault = std::sync::Arc::new(MockVault::new());
    let sync = MerkleSync::new(vault);

    let peer = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    sync.add_peer(peer).await.unwrap();

    let new_root = [99u8; 32];
    sync.handle_heartbeat("cell-1", new_root, 42).await;

    let peers = sync.peers().read().await;
    let p = peers.get("cell-1").unwrap();
    assert_eq!(p.last_merkle_root, new_root);
    assert_eq!(p.last_block_no, 42);
    assert!(p.heartbeat_age().is_some());
}

#[tokio::test]
async fn test_merkle_sync_out_of_sync_peers() {
    let vault = std::sync::Arc::new(MockVault::new());
    let sync = MerkleSync::new(vault);

    let local_root = [10u8; 32];
    sync.set_local_merkle_root(local_root).await;

    let mut p1 = PeerInfo::new("cell-1", "http://cell-1:4222", vec![]);
    p1.last_merkle_root = local_root;
    sync.add_peer(p1).await.unwrap();

    let mut p2 = PeerInfo::new("cell-2", "http://cell-2:4222", vec![]);
    p2.last_merkle_root = [20u8; 32];
    sync.add_peer(p2).await.unwrap();

    let oos = sync.out_of_sync_peers().await;
    assert_eq!(oos.len(), 1);
    assert_eq!(oos[0], "cell-2");
}

#[test]
fn test_compute_merkle_root_empty() {
    let root = MerkleSync::<MockVault>::compute_merkle_root(&[]);
    assert_eq!(root, [0u8; 32]);
}

#[test]
fn test_compute_merkle_root_deterministic() {
    let cids = vec!["bafyrei_abc".to_string(), "bafyrei_xyz".to_string()];
    let root1 = MerkleSync::<MockVault>::compute_merkle_root(&cids);
    let root2 = MerkleSync::<MockVault>::compute_merkle_root(&cids);
    assert_eq!(root1, root2);
    assert_ne!(root1, [0u8; 32]);
}

#[test]
fn test_compute_merkle_root_order_matters() {
    let cids_a = vec!["bafyrei_abc".to_string(), "bafyrei_xyz".to_string()];
    let cids_b = vec!["bafyrei_xyz".to_string(), "bafyrei_abc".to_string()];
    let root_a = MerkleSync::<MockVault>::compute_merkle_root(&cids_a);
    let root_b = MerkleSync::<MockVault>::compute_merkle_root(&cids_b);
    assert_ne!(root_a, root_b);
}

#[test]
fn test_sync_scheduler_config_default() {
    let config = SyncSchedulerConfig::default();
    assert_eq!(config.sync_interval, Duration::from_secs(30));
    assert_eq!(config.heartbeat_timeout, Duration::from_secs(90));
    assert_eq!(config.max_concurrent_syncs, 3);
}
