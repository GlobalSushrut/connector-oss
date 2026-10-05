//! Merkle sync engine — periodic peer comparison and catch-up replication.
//!
//! Wraps `vac_sync::sync()` with peer management, scheduling, and
//! Merkle root comparison to detect stale peers.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Sha256, Digest};
use tokio::sync::RwLock;
use tracing::debug;

use vac_sync::protocol::{SyncableVault, SyncResult};

use crate::error::{ReplicateError, ReplicateResult};
use crate::peer::{PeerInfo, PeerRegistry};

/// Result of comparing Merkle roots with all peers.
#[derive(Debug, Clone)]
pub struct PeerSyncStatus {
    pub cell_id: String,
    pub in_sync: bool,
    pub local_root_hex: String,
    pub remote_root_hex: String,
}

/// Result of a sync cycle across all peers.
#[derive(Debug, Clone, Default)]
pub struct SyncCycleResult {
    pub peers_checked: usize,
    pub peers_in_sync: usize,
    pub peers_synced: usize,
    pub peers_failed: usize,
    pub total_blocks_transferred: usize,
    pub total_objects_transferred: usize,
}

/// Merkle sync engine that manages peer comparison and catch-up replication.
///
/// Generic over `S: SyncableVault` — the local vault implementation.
pub struct MerkleSync<S: SyncableVault> {
    local: Arc<S>,
    peers: Arc<RwLock<PeerRegistry>>,
    local_merkle_root: Arc<RwLock<[u8; 32]>>,
}

impl<S: SyncableVault> MerkleSync<S> {
    pub fn new(local: Arc<S>) -> Self {
        Self {
            local,
            peers: Arc::new(RwLock::new(PeerRegistry::new())),
            local_merkle_root: Arc::new(RwLock::new([0u8; 32])),
        }
    }

    /// Get a reference to the peer registry.
    pub fn peers(&self) -> &Arc<RwLock<PeerRegistry>> {
        &self.peers
    }

    /// Update the local Merkle root (called after local writes).
    pub async fn set_local_merkle_root(&self, root: [u8; 32]) {
        *self.local_merkle_root.write().await = root;
    }

    /// Get the current local Merkle root.
    pub async fn local_merkle_root(&self) -> [u8; 32] {
        *self.local_merkle_root.read().await
    }

    /// Register a new peer.
    pub async fn add_peer(&self, peer: PeerInfo) -> ReplicateResult<()> {
        self.peers.write().await.register(peer)
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, cell_id: &str) -> Option<PeerInfo> {
        self.peers.write().await.remove(cell_id)
    }

    /// Compare Merkle roots with all peers. Returns status for each peer.
    pub async fn check_all_peers(&self) -> Vec<PeerSyncStatus> {
        let local_root = *self.local_merkle_root.read().await;
        let local_hex = hex::encode(local_root);
        let peers = self.peers.read().await;

        peers
            .all()
            .map(|p| {
                let remote_hex = hex::encode(p.last_merkle_root);
                let in_sync = p.last_merkle_root == local_root;
                PeerSyncStatus {
                    cell_id: p.cell_id.clone(),
                    in_sync,
                    local_root_hex: local_hex.clone(),
                    remote_root_hex: remote_hex,
                }
            })
            .collect()
    }

    /// Sync with a specific peer using `vac_sync::sync()`.
    ///
    /// `peer_vault` is the remote vault accessor (could be over network).
    pub async fn sync_with_peer<T: SyncableVault>(
        &self,
        peer_cell_id: &str,
        peer_vault: &T,
    ) -> ReplicateResult<SyncResult> {
        // Check peer exists
        {
            let peers = self.peers.read().await;
            if peers.get(peer_cell_id).is_none() {
                return Err(ReplicateError::PeerNotFound(peer_cell_id.to_string()));
            }
        }

        debug!(peer = %peer_cell_id, "Starting sync with peer");

        // Delegate to vac_sync::sync() — block-verified replication
        let result = vac_sync::sync(peer_vault, self.local.as_ref())
            .await
            .map_err(|e| ReplicateError::SyncFailed {
                peer_id: peer_cell_id.to_string(),
                reason: e.to_string(),
            })?;

        // Update peer stats
        {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(peer_cell_id) {
                peer.record_sync_success();
                debug!(
                    peer = %peer_cell_id,
                    blocks = result.transferred_blocks,
                    objects = result.transferred_objects,
                    "Sync completed"
                );
            }
        }

        Ok(result)
    }

    /// Handle a heartbeat from a remote peer — update their Merkle root.
    pub async fn handle_heartbeat(
        &self,
        cell_id: &str,
        merkle_root: [u8; 32],
        block_no: u64,
    ) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(cell_id) {
            peer.update_heartbeat(merkle_root, block_no);
            debug!(
                peer = %cell_id,
                block_no = block_no,
                root = %hex::encode(merkle_root),
                "Heartbeat received"
            );
        } else {
            debug!(peer = %cell_id, "Heartbeat from unknown peer, ignoring");
        }
    }

    /// Get peers that are out of sync (Merkle root differs from local).
    pub async fn out_of_sync_peers(&self) -> Vec<String> {
        let local_root = *self.local_merkle_root.read().await;
        let peers = self.peers.read().await;
        peers
            .stale_peers(&local_root)
            .iter()
            .map(|p| p.cell_id.clone())
            .collect()
    }

    /// Get peers that haven't sent a heartbeat within `timeout`.
    pub async fn dead_peers(&self, timeout: Duration) -> Vec<String> {
        let peers = self.peers.read().await;
        peers
            .dead_peers(timeout)
            .iter()
            .map(|p| p.cell_id.clone())
            .collect()
    }

    /// Compute a Merkle root from a set of CID strings.
    /// Uses SHA-256 binary tree hashing.
    pub fn compute_merkle_root(cids: &[String]) -> [u8; 32] {
        if cids.is_empty() {
            return [0u8; 32];
        }

        // Hash each CID string
        let mut hashes: Vec<[u8; 32]> = cids
            .iter()
            .map(|cid| {
                let mut hasher = Sha256::new();
                hasher.update(cid.as_bytes());
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            })
            .collect();

        // Binary tree reduction
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    // Odd node: hash with itself
                    hasher.update(&chunk[0]);
                }
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                next_level.push(hash);
            }
            hashes = next_level;
        }

        hashes[0]
    }
}

/// Configuration for the sync scheduler.
#[derive(Debug, Clone)]
pub struct SyncSchedulerConfig {
    /// Interval between sync cycles.
    pub sync_interval: Duration,
    /// Timeout for considering a peer dead.
    pub heartbeat_timeout: Duration,
    /// Maximum concurrent syncs.
    pub max_concurrent_syncs: usize,
}

impl Default for SyncSchedulerConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
            max_concurrent_syncs: 3,
        }
    }
}
