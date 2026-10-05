//! Error types for vac-replicate.

use thiserror::Error;

/// Errors from the replication layer.
#[derive(Debug, Error)]
pub enum ReplicateError {
    #[error("Sync failed with peer {peer_id}: {reason}")]
    SyncFailed { peer_id: String, reason: String },

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Merkle root mismatch for peer {peer_id}: local={local_hex}, remote={remote_hex}")]
    MerkleRootMismatch {
        peer_id: String,
        local_hex: String,
        remote_hex: String,
    },

    #[error("Bus error: {0}")]
    Bus(String),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Peer already registered: {0}")]
    PeerAlreadyRegistered(String),

    #[error("Scheduler already running")]
    SchedulerAlreadyRunning,
}

pub type ReplicateResult<T> = Result<T, ReplicateError>;
