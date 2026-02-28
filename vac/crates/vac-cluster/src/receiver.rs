//! Replication receiver — background task that applies events from other cells.
//!
//! Runs as a `tokio::spawn` task, subscribes to the cluster replication topic,
//! and applies incoming events to the local store.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use vac_bus::{EventBus, ReplicationOp};
use vac_core::store::KernelStore;
use vac_core::types::KernelAuditEntry;

use crate::cell::Cell;
use crate::error::ClusterError;

/// Registry of known peer public keys for signature verification.
///
/// Maps cell_id → Ed25519 VerifyingKey. Only events from registered peers
/// with valid signatures are accepted.
#[derive(Clone, Default)]
pub struct PeerRegistry {
    peers: HashMap<String, VerifyingKey>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self { peers: HashMap::new() }
    }

    /// Register a peer's public key.
    pub fn register(&mut self, cell_id: impl Into<String>, key: VerifyingKey) {
        self.peers.insert(cell_id.into(), key);
    }

    /// Look up a peer's public key.
    pub fn get(&self, cell_id: &str) -> Option<&VerifyingKey> {
        self.peers.get(cell_id)
    }

    /// Number of registered peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Statistics for the replication receiver.
#[derive(Debug, Default, Clone)]
pub struct ReceiverStats {
    /// Total events received
    pub events_received: u64,
    /// Events applied successfully
    pub events_applied: u64,
    /// Events skipped (own events)
    pub events_skipped_self: u64,
    /// Events rejected (CID mismatch, bad signature, etc.)
    pub events_rejected: u64,
}

/// Start the replication receiver loop (no signature verification).
///
/// This subscribes to the given topic on the bus and applies incoming
/// replication events to the local store. Events from this cell are skipped.
///
/// Returns a handle to the spawned task and shared stats.
pub async fn start_replication_loop<S, B>(
    local_store: Arc<Mutex<S>>,
    bus: Arc<B>,
    cell: Arc<Cell>,
    topic: &str,
) -> Result<(tokio::task::JoinHandle<()>, Arc<Mutex<ReceiverStats>>), ClusterError>
where
    S: KernelStore + Send + 'static,
    B: EventBus,
{
    start_replication_loop_inner(local_store, bus, cell, topic, None).await
}

/// Start the replication receiver loop **with** Ed25519 signature verification.
///
/// Every event from a remote cell must:
/// 1. Have a non-empty signature
/// 2. Come from a cell registered in the `PeerRegistry`
/// 3. Pass Ed25519 verification against that cell's public key
///
/// Events that fail any check are rejected and counted in `events_rejected`.
pub async fn start_verified_replication_loop<S, B>(
    local_store: Arc<Mutex<S>>,
    bus: Arc<B>,
    cell: Arc<Cell>,
    topic: &str,
    peers: PeerRegistry,
) -> Result<(tokio::task::JoinHandle<()>, Arc<Mutex<ReceiverStats>>), ClusterError>
where
    S: KernelStore + Send + 'static,
    B: EventBus,
{
    start_replication_loop_inner(local_store, bus, cell, topic, Some(peers)).await
}

/// Inner implementation shared by both verified and unverified loops.
async fn start_replication_loop_inner<S, B>(
    local_store: Arc<Mutex<S>>,
    bus: Arc<B>,
    cell: Arc<Cell>,
    topic: &str,
    peers: Option<PeerRegistry>,
) -> Result<(tokio::task::JoinHandle<()>, Arc<Mutex<ReceiverStats>>), ClusterError>
where
    S: KernelStore + Send + 'static,
    B: EventBus,
{
    let mut rx = bus.subscribe(topic).await?;
    let stats = Arc::new(Mutex::new(ReceiverStats::default()));
    let stats_clone = stats.clone();
    let cell_id = cell.cell_id.clone();
    let topic_owned = topic.to_string();

    let handle = tokio::spawn(async move {
        info!(cell_id = %cell_id, topic = %topic_owned, "Replication receiver started");

        while let Some(event) = rx.recv().await {
            let mut stats = stats_clone.lock().await;
            stats.events_received += 1;

            // Skip our own events
            if event.cell_id == cell_id {
                stats.events_skipped_self += 1;
                continue;
            }

            // === Signature verification (if PeerRegistry provided) ===
            if let Some(ref registry) = peers {
                // 1. Must be signed
                if !event.is_signed() {
                    stats.events_rejected += 1;
                    warn!(
                        from_cell = %event.cell_id,
                        seq = event.seq,
                        "Rejected unsigned event"
                    );
                    continue;
                }
                // 2. Must be from a known peer
                let peer_key = match registry.get(&event.cell_id) {
                    Some(k) => k,
                    None => {
                        stats.events_rejected += 1;
                        warn!(
                            from_cell = %event.cell_id,
                            seq = event.seq,
                            "Rejected event from unknown peer"
                        );
                        continue;
                    }
                };
                // 3. Signature must be valid
                if let Err(reason) = event.verify(peer_key) {
                    stats.events_rejected += 1;
                    warn!(
                        from_cell = %event.cell_id,
                        seq = event.seq,
                        reason = %reason,
                        "Rejected event with invalid signature"
                    );
                    continue;
                }
            }

            debug!(
                from_cell = %event.cell_id,
                seq = event.seq,
                op = %event.op.op_type(),
                "Received replication event"
            );

            // Apply the event to local store
            let mut store = local_store.lock().await;
            match apply_op(&mut *store, &event.op) {
                Ok(()) => {
                    stats.events_applied += 1;
                    debug!(
                        from_cell = %event.cell_id,
                        seq = event.seq,
                        op = %event.op.op_type(),
                        "Applied replication event"
                    );
                }
                Err(e) => {
                    stats.events_rejected += 1;
                    warn!(
                        from_cell = %event.cell_id,
                        seq = event.seq,
                        op = %event.op.op_type(),
                        error = %e,
                        "Failed to apply replication event"
                    );
                }
            }
        }

        info!(cell_id = %cell_id, "Replication receiver stopped");
    });

    Ok((handle, stats))
}

/// Apply a single replication operation to the local store.
fn apply_op<S: KernelStore>(store: &mut S, op: &ReplicationOp) -> Result<(), ClusterError> {
    match op {
        ReplicationOp::PacketWrite {
            packet_cbor,
            packet_cid,
            ..
        } => {
            // Deserialize the packet
            let packet: vac_core::types::MemPacket =
                serde_json::from_slice(packet_cbor).map_err(|e| {
                    ClusterError::Serialization(format!("Failed to decode packet: {}", e))
                })?;

            // Verify CID matches content (tamper detection)
            let actual_cid = packet.index.packet_cid.to_string();
            if actual_cid != *packet_cid {
                return Err(ClusterError::CidMismatch {
                    expected: packet_cid.clone(),
                    actual: actual_cid,
                });
            }

            store
                .store_packet(&packet)
                .map_err(|e| ClusterError::Store(e.message))?;
            Ok(())
        }

        ReplicationOp::PacketSeal { cids } => {
            // Sealing is a local operation — we just log it
            debug!(cids = ?cids, "Received seal notification");
            Ok(())
        }

        ReplicationOp::PacketEvict { cids } => {
            for cid_str in cids {
                if let Ok(cid) = cid_str.parse::<cid::Cid>() {
                    store
                        .delete_packet(&cid)
                        .map_err(|e| ClusterError::Store(e.message))?;
                }
            }
            Ok(())
        }

        ReplicationOp::TierChange { cid, new_tier } => {
            debug!(cid = %cid, new_tier = %new_tier, "Tier change notification");
            // Tier changes are applied when the packet is next loaded
            Ok(())
        }

        ReplicationOp::AgentRegister {
            pid,
            name,
            namespace,
        } => {
            debug!(pid = %pid, name = %name, namespace = %namespace, "Agent registered on remote cell");
            // We don't replicate full ACBs — just track that the agent exists
            // The VakyaRouter will use this for routing decisions
            Ok(())
        }

        ReplicationOp::AuditEntry { entry_cbor } => {
            let entry: KernelAuditEntry =
                serde_json::from_slice(entry_cbor).map_err(|e| {
                    ClusterError::Serialization(format!("Failed to decode audit entry: {}", e))
                })?;
            store
                .store_audit_entry(&entry)
                .map_err(|e| ClusterError::Store(e.message))?;
            Ok(())
        }

        ReplicationOp::BlockCommit { block_cbor } => {
            debug!(size = block_cbor.len(), "Block commit received");
            // Block commits are handled by vac-replicate (Merkle sync layer)
            Ok(())
        }

        ReplicationOp::Heartbeat { .. } => {
            // Heartbeats are handled by the health monitor, not the store
            Ok(())
        }

        // AAPI ops are handled by the AAPI layer (ClusterGateway), not here
        ReplicationOp::VakyaForward { .. }
        | ReplicationOp::VakyaReply { .. }
        | ReplicationOp::VakyaRollback { .. }
        | ReplicationOp::PolicyUpdate { .. }
        | ReplicationOp::AdapterAnnounce { .. }
        | ReplicationOp::AdapterDeregister { .. }
        | ReplicationOp::ApprovalRequest { .. }
        | ReplicationOp::ApprovalResponse { .. } => {
            debug!(op = %op.op_type(), "AAPI op — handled by ClusterGateway");
            Ok(())
        }

        ReplicationOp::SignalDeliver { .. } => {
            debug!(op = %op.op_type(), "Signal delivery — handled by kernel signal dispatch");
            Ok(())
        }
    }
}
