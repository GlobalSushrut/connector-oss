//! Peer management for replication.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{ReplicateError, ReplicateResult};

/// Information about a remote peer cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub cell_id: String,
    pub endpoint: String,
    pub public_key: Vec<u8>,
    pub last_merkle_root: [u8; 32],
    pub last_block_no: u64,
    #[serde(skip)]
    last_heartbeat: Option<Instant>,
    #[serde(skip)]
    last_sync: Option<Instant>,
    pub sync_count: u64,
    pub failed_sync_count: u64,
}

impl PeerInfo {
    pub fn new(cell_id: &str, endpoint: &str, public_key: Vec<u8>) -> Self {
        Self {
            cell_id: cell_id.to_string(),
            endpoint: endpoint.to_string(),
            public_key,
            last_merkle_root: [0u8; 32],
            last_block_no: 0,
            last_heartbeat: None,
            last_sync: None,
            sync_count: 0,
            failed_sync_count: 0,
        }
    }

    /// Update from a heartbeat event.
    pub fn update_heartbeat(&mut self, merkle_root: [u8; 32], block_no: u64) {
        self.last_merkle_root = merkle_root;
        self.last_block_no = block_no;
        self.last_heartbeat = Some(Instant::now());
    }

    /// Record a successful sync.
    pub fn record_sync_success(&mut self) {
        self.last_sync = Some(Instant::now());
        self.sync_count += 1;
    }

    /// Record a failed sync.
    pub fn record_sync_failure(&mut self) {
        self.failed_sync_count += 1;
    }

    /// Duration since last heartbeat. None if never received.
    pub fn heartbeat_age(&self) -> Option<Duration> {
        self.last_heartbeat.map(|t| t.elapsed())
    }

    /// Duration since last sync. None if never synced.
    pub fn sync_age(&self) -> Option<Duration> {
        self.last_sync.map(|t| t.elapsed())
    }

    /// Whether this peer is considered stale (no heartbeat for `timeout`).
    pub fn is_stale(&self, timeout: Duration) -> bool {
        match self.last_heartbeat {
            Some(t) => t.elapsed() > timeout,
            None => true,
        }
    }
}

/// Registry of known peers.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: HashMap<String, PeerInfo>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Register a new peer. Errors if already registered.
    pub fn register(&mut self, peer: PeerInfo) -> ReplicateResult<()> {
        if self.peers.contains_key(&peer.cell_id) {
            return Err(ReplicateError::PeerAlreadyRegistered(peer.cell_id));
        }
        self.peers.insert(peer.cell_id.clone(), peer);
        Ok(())
    }

    /// Register or update a peer (upsert).
    pub fn upsert(&mut self, peer: PeerInfo) {
        self.peers.insert(peer.cell_id.clone(), peer);
    }

    /// Remove a peer.
    pub fn remove(&mut self, cell_id: &str) -> Option<PeerInfo> {
        self.peers.remove(cell_id)
    }

    /// Get a peer by cell_id.
    pub fn get(&self, cell_id: &str) -> Option<&PeerInfo> {
        self.peers.get(cell_id)
    }

    /// Get a mutable peer by cell_id.
    pub fn get_mut(&mut self, cell_id: &str) -> Option<&mut PeerInfo> {
        self.peers.get_mut(cell_id)
    }

    /// Number of registered peers.
    pub fn count(&self) -> usize {
        self.peers.len()
    }

    /// All peers.
    pub fn all(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// All mutable peers.
    pub fn all_mut(&mut self) -> impl Iterator<Item = &mut PeerInfo> {
        self.peers.values_mut()
    }

    /// Peers whose Merkle root differs from `local_root`.
    pub fn stale_peers(&self, local_root: &[u8; 32]) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| &p.last_merkle_root != local_root)
            .collect()
    }

    /// Peers that haven't sent a heartbeat within `timeout`.
    pub fn dead_peers(&self, timeout: Duration) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.is_stale(timeout))
            .collect()
    }
}
