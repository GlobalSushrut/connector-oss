//! Cell — the distribution unit.
//!
//! A Cell wraps a kernel identity (cell_id, keypair) with a monotonic
//! sequence counter and Merkle root tracking. It is the unit of
//! distribution in the cluster.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Status of a cell in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellStatus {
    Starting,
    Ready,
    Syncing,
    Degraded,
    ShuttingDown,
}

impl std::fmt::Display for CellStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Starting => write!(f, "starting"),
            Self::Ready => write!(f, "ready"),
            Self::Syncing => write!(f, "syncing"),
            Self::Degraded => write!(f, "degraded"),
            Self::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

/// A Cell is the distribution unit in the cluster.
///
/// Each cell has:
/// - A unique `cell_id`
/// - A monotonic sequence counter for ordering events
/// - A Merkle root tracking the current state
/// - A status indicating readiness
pub struct Cell {
    /// Unique identifier for this cell
    pub cell_id: String,
    /// Monotonic sequence counter — incremented on every write
    pub seq: AtomicU64,
    /// Current Merkle root of this cell's store
    pub merkle_root: Arc<RwLock<[u8; 32]>>,
    /// Cell status
    pub status: Arc<RwLock<CellStatus>>,
    /// Timestamp when this cell was created
    pub created_at: i64,
    /// Ed25519 signing key for this cell (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key for this cell (public)
    verifying_key: VerifyingKey,
}

impl Cell {
    /// Create a new cell with the given ID and a fresh Ed25519 keypair.
    pub fn new(cell_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            cell_id: cell_id.into(),
            seq: AtomicU64::new(0),
            merkle_root: Arc::new(RwLock::new([0u8; 32])),
            status: Arc::new(RwLock::new(CellStatus::Starting)),
            created_at: chrono::Utc::now().timestamp_millis(),
            signing_key,
            verifying_key,
        }
    }

    /// Create a cell with a specific keypair (for testing or key restoration).
    pub fn with_keypair(cell_id: impl Into<String>, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            cell_id: cell_id.into(),
            seq: AtomicU64::new(0),
            merkle_root: Arc::new(RwLock::new([0u8; 32])),
            status: Arc::new(RwLock::new(CellStatus::Starting)),
            created_at: chrono::Utc::now().timestamp_millis(),
            signing_key,
            verifying_key,
        }
    }

    /// Get this cell's public verifying key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get this cell's signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the next sequence number (atomically increments).
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the current sequence number without incrementing.
    pub fn current_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    /// Set the cell status.
    pub async fn set_status(&self, status: CellStatus) {
        *self.status.write().await = status;
    }

    /// Get the cell status.
    pub async fn get_status(&self) -> CellStatus {
        *self.status.read().await
    }

    /// Update the Merkle root.
    pub async fn set_merkle_root(&self, root: [u8; 32]) {
        *self.merkle_root.write().await = root;
    }

    /// Get the current Merkle root.
    pub async fn get_merkle_root(&self) -> [u8; 32] {
        *self.merkle_root.read().await
    }

    /// Mark the cell as ready.
    pub async fn mark_ready(&self) {
        self.set_status(CellStatus::Ready).await;
    }
}
