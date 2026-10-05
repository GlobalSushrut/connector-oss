//! ClusterKernelStore — THE KEY COMPONENT.
//!
//! Implements `KernelStore` by delegating to a local store for all operations,
//! and additionally replicating write operations via the event bus.
//!
//! - ALL reads: local only (fast, <1ms)
//! - ALL writes: local + replicate (fast + async fire-and-forget)
//!
//! The kernel doesn't know it's distributed. This is the VFS trick.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cid::Cid;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use vac_bus::{EventBus, ReplicationEvent, ReplicationOp};
use vac_core::audit_export::ScittReceipt;
use vac_core::interference::{InterferenceEdge, StateVector};
use vac_core::range_window::RangeWindow;
use vac_core::store::{KernelStore, StoreResult};
use vac_core::types::*;

use crate::cell::Cell;

/// Bounded replication channel capacity (Gap 3 fix, infra.md §3).
///
/// 8192 ops × ~200 bytes = 1.6MB max memory pressure (bounded, predictable).
/// At 100K ops/sec: ~82ms burst buffer before backpressure fires.
const REPLICATION_CHANNEL_CAPACITY: usize = 8_192;

/// Prometheus-style counter: incremented when replication channel is full.
/// Exported via GET /metrics as `vac_replication_backpressure_total`.
static REPLICATION_BACKPRESSURE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Returns the total replication backpressure events since process start.
pub fn replication_backpressure_total() -> u64 {
    REPLICATION_BACKPRESSURE_TOTAL.load(Ordering::Relaxed)
}

/// A `KernelStore` that replicates writes to the cluster via an event bus.
///
/// Generic over:
/// - `S`: Any local `KernelStore` backend (InMemory, Prolly, IndexDB)
/// - `B`: Any `EventBus` implementation (InProcessBus, NatsBus)
///
/// ## Replication design (Gap 3 fix)
///
/// Old design: one `handle.spawn` per write → unbounded task spawn → OOM under load.
/// New design: bounded `mpsc::Sender<ReplicationOp>` (capacity 8192) + single
/// background worker that drains the channel, signs events, and publishes with retry.
///
/// On `TrySendError::Full`: increment counter, log warn — never silently drop.
pub struct ClusterKernelStore<S: KernelStore, B: EventBus> {
    /// The local store — all reads and writes go here first
    local: S,
    /// Bounded replication sender (capacity 8192)
    replication_tx: mpsc::Sender<ReplicationOp>,
    /// Cell identity (kept for seq number and signing, accessed by background worker)
    cell: Arc<Cell>,
    /// Tokio handle for async bridging (KernelStore is sync)
    handle: Handle,
    /// Phantom — B is used in `new()` to spawn the worker; not stored directly.
    _bus: std::marker::PhantomData<B>,
}

impl<S: KernelStore + Send + 'static, B: EventBus + Send + Sync + 'static> ClusterKernelStore<S, B> {
    /// Create a new ClusterKernelStore.
    ///
    /// Spawns a single background `replication_worker` task that drains the
    /// bounded channel, signs each event, and publishes it to the bus with retry.
    pub fn new(local: S, bus: Arc<B>, cell: Arc<Cell>, topic: impl Into<String>) -> Self {
        let handle = Handle::current();
        let topic = topic.into();

        let (replication_tx, mut replication_rx) = mpsc::channel::<ReplicationOp>(REPLICATION_CHANNEL_CAPACITY);

        // Spawn the single background worker — one task, not one-per-write
        let worker_bus = bus.clone();
        let worker_cell = cell.clone();
        let worker_topic = topic.clone();

        handle.spawn(async move {
            while let Some(op) = replication_rx.recv().await {
                let seq = worker_cell.next_seq();
                let mut event = ReplicationEvent::new(worker_cell.cell_id.clone(), seq, op);
                event.sign(worker_cell.signing_key());

                debug!(
                    cell = %worker_cell.cell_id,
                    seq = seq,
                    op = %event.op.op_type(),
                    "Replication worker publishing"
                );

                // Retry once on transient failure
                if let Err(e) = worker_bus.publish(&worker_topic, &event).await {
                    warn!(error = %e, "Replication publish failed, retrying once");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    if let Err(e2) = worker_bus.publish(&worker_topic, &event).await {
                        warn!(error = %e2, "Replication publish retry failed — event lost");
                    }
                }
            }
            debug!("Replication worker stopped (channel closed)");
        });

        Self {
            local,
            replication_tx,
            cell,
            handle,
            _bus: std::marker::PhantomData,
        }
    }

    /// Enqueue a replication op on the bounded channel.
    ///
    /// On `Full`: increments backpressure counter and logs — never panics,
    /// never silently drops without counting.
    fn replicate(&self, op: ReplicationOp) {
        match self.replication_tx.try_send(op) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(dropped_op)) => {
                REPLICATION_BACKPRESSURE_TOTAL.fetch_add(1, Ordering::Relaxed);
                warn!(
                    cell = %self.cell.cell_id,
                    backpressure_total = REPLICATION_BACKPRESSURE_TOTAL.load(Ordering::Relaxed),
                    op = %dropped_op.op_type(),
                    "Replication channel full — op dropped. Consider increasing REPLICATION_CHANNEL_CAPACITY or checking NATS health."
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(cell = %self.cell.cell_id, "Replication channel closed");
            }
        }
    }

    /// Get a reference to the local store.
    pub fn local(&self) -> &S {
        &self.local
    }

    /// Get a mutable reference to the local store.
    pub fn local_mut(&mut self) -> &mut S {
        &mut self.local
    }

    /// Get the cell reference.
    pub fn cell(&self) -> &Arc<Cell> {
        &self.cell
    }
}

// =============================================================================
// KernelStore implementation — delegate reads to local, writes to local + channel
// =============================================================================

impl<S: KernelStore + Send + 'static, B: EventBus + Send + Sync + 'static> KernelStore for ClusterKernelStore<S, B> {
    // ── Packets ──────────────────────────────────────────────────────

    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        // 1. Write locally (sync, fast)
        self.local.store_packet(packet)?;

        // 2. Replicate (async, fire-and-forget)
        let cbor = serde_json::to_vec(packet).unwrap_or_default();
        let cid_str = packet.index.packet_cid.to_string();
        let ns = packet.namespace.clone().unwrap_or_default();
        self.replicate(ReplicationOp::PacketWrite {
            namespace: ns,
            packet_cbor: cbor,
            packet_cid: cid_str,
        });

        Ok(())
    }

    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>> {
        self.local.load_packet(cid)
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        self.local.load_packets_by_namespace(namespace)
    }

    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()> {
        self.local.delete_packet(cid)?;
        self.replicate(ReplicationOp::PacketEvict {
            cids: vec![cid.to_string()],
        });
        Ok(())
    }

    // ── RangeWindows ─────────────────────────────────────────────────

    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()> {
        self.local.store_window(window)
        // Windows are derived from packets — no separate replication needed.
        // Remote cells will build their own windows from replicated packets.
    }

    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>> {
        self.local.load_window(namespace, sn)
    }

    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>> {
        self.local.load_windows(namespace)
    }

    // ── StateVectors ─────────────────────────────────────────────────

    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> {
        self.local.store_state_vector(sv)
        // StateVectors are derived from packets — no separate replication.
    }

    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>> {
        self.local.load_state_vector(agent_pid, sn)
    }

    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>> {
        self.local.load_state_vectors(agent_pid)
    }

    // ── InterferenceEdges ────────────────────────────────────────────

    fn store_interference_edge(&mut self, ie: &InterferenceEdge) -> StoreResult<()> {
        self.local.store_interference_edge(ie)
        // Derived data — no separate replication.
    }

    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<InterferenceEdge>> {
        self.local.load_interference_edges(agent_pid)
    }

    // ── Audit ────────────────────────────────────────────────────────

    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()> {
        self.local.store_audit_entry(entry)?;
        let cbor = serde_json::to_vec(entry).unwrap_or_default();
        self.replicate(ReplicationOp::AuditEntry { entry_cbor: cbor });
        Ok(())
    }

    fn load_audit_entries(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> StoreResult<Vec<KernelAuditEntry>> {
        self.local.load_audit_entries(from_ms, to_ms)
    }

    fn load_audit_entries_by_agent(
        &self,
        agent_pid: &str,
        limit: usize,
    ) -> StoreResult<Vec<KernelAuditEntry>> {
        self.local.load_audit_entries_by_agent(agent_pid, limit)
    }

    // ── SCITT Receipts ───────────────────────────────────────────────

    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()> {
        self.local.store_scitt_receipt(receipt)
        // SCITT receipts are replicated via the federation layer, not here.
    }

    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>> {
        self.local.load_scitt_receipt(statement_id)
    }

    // ── Agents ───────────────────────────────────────────────────────

    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> {
        self.local.store_agent(acb)?;
        self.replicate(ReplicationOp::AgentRegister {
            pid: acb.agent_pid.clone(),
            name: acb.agent_name.clone(),
            namespace: acb.namespace.clone(),
        });
        Ok(())
    }

    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> {
        self.local.load_agent(pid)
    }

    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> {
        self.local.load_all_agents()
    }

    // ── Sessions ─────────────────────────────────────────────────────

    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()> {
        self.local.store_session(session)
        // Sessions are local to the cell that created them.
        // Cross-cell session access goes through the gateway.
    }

    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>> {
        self.local.load_session(session_id)
    }

    // ── Ports ────────────────────────────────────────────────────────

    fn store_port(&mut self, port: &Port) -> StoreResult<()> {
        self.local.store_port(port)
        // Ports are local to the cell. Cross-cell ports use the bus directly.
    }

    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>> {
        self.local.load_port(port_id)
    }

    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>> {
        self.local.load_ports_by_owner(owner_pid)
    }

    // ── Execution Policies ───────────────────────────────────────────

    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()> {
        self.local.store_execution_policy(policy)
        // Policies are replicated via the FederatedPolicyEngine (AAPI layer).
    }

    fn load_execution_policy(
        &self,
        role: &AgentRole,
    ) -> StoreResult<Option<ExecutionPolicy>> {
        self.local.load_execution_policy(role)
    }

    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> {
        self.local.load_all_policies()
    }

    // ── Delegation Chains ────────────────────────────────────────────

    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()> {
        self.local.store_delegation_chain(chain)
        // Delegation chains are verified on receipt, not replicated.
    }

    fn load_delegation_chain(
        &self,
        chain_cid: &str,
    ) -> StoreResult<Option<DelegationChain>> {
        self.local.load_delegation_chain(chain_cid)
    }

    fn load_delegation_chains_by_subject(
        &self,
        subject: &str,
    ) -> StoreResult<Vec<DelegationChain>> {
        self.local.load_delegation_chains_by_subject(subject)
    }

    // ── WAL (local only — WAL is per-cell) ──────────────────────────

    fn store_wal(&mut self, namespace: &str, entries: &[vac_core::range_window::WalEntry]) -> StoreResult<()> {
        self.local.store_wal(namespace, entries)
    }

    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<vac_core::range_window::WalEntry>> {
        self.local.load_wal(namespace)
    }

    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()> {
        self.local.clear_wal(namespace)
    }

    // ── Bulk loaders ────────────────────────────────────────────────

    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> {
        self.local.load_all_sessions()
    }

    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        self.local.load_all_packets()
    }
}
