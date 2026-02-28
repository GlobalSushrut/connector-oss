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

use cid::Cid;
use tokio::runtime::Handle;
use tracing::{debug, warn};

use vac_bus::{EventBus, ReplicationEvent, ReplicationOp};
use vac_core::audit_export::ScittReceipt;
use vac_core::interference::{InterferenceEdge, StateVector};
use vac_core::range_window::RangeWindow;
use vac_core::store::{KernelStore, StoreResult};
use vac_core::types::*;

use crate::cell::Cell;

/// A `KernelStore` that replicates writes to the cluster via an event bus.
///
/// Generic over:
/// - `S`: Any local `KernelStore` backend (InMemory, Prolly, IndexDB)
/// - `B`: Any `EventBus` implementation (InProcessBus, NatsBus)
pub struct ClusterKernelStore<S: KernelStore, B: EventBus> {
    /// The local store — all reads and writes go here first
    local: S,
    /// The event bus for replication
    bus: Arc<B>,
    /// Cell identity for signing events
    cell: Arc<Cell>,
    /// Topic prefix for replication events
    topic: String,
    /// Tokio handle for async bridging (KernelStore is sync)
    handle: Handle,
}

impl<S: KernelStore, B: EventBus> ClusterKernelStore<S, B> {
    /// Create a new ClusterKernelStore.
    ///
    /// - `local`: The underlying local store
    /// - `bus`: The event bus for replication
    /// - `cell`: The cell identity
    /// - `topic`: The replication topic (e.g., "cluster.replication")
    pub fn new(local: S, bus: Arc<B>, cell: Arc<Cell>, topic: impl Into<String>) -> Self {
        Self {
            local,
            bus,
            cell,
            topic: topic.into(),
            handle: Handle::current(),
        }
    }

    /// Fire-and-forget replication of a write operation.
    ///
    /// This is async but called from sync context via `block_on`.
    /// The actual publish is fast (in-process: clone + send).
    fn replicate(&self, op: ReplicationOp) {
        let seq = self.cell.next_seq();
        let mut event = ReplicationEvent::new(self.cell.cell_id.clone(), seq, op);

        // Sign the event with this cell's Ed25519 key
        event.sign(self.cell.signing_key());

        let bus = self.bus.clone();
        let topic = self.topic.clone();

        debug!(
            cell = %self.cell.cell_id,
            seq = seq,
            op = %event.op.op_type(),
            "Replicating (signed)"
        );

        // Spawn the publish as a background task — don't block the sync store
        self.handle.spawn(async move {
            if let Err(e) = bus.publish(&topic, &event).await {
                warn!(error = %e, "Replication publish failed");
            }
        });
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

    /// Get the bus reference.
    pub fn bus(&self) -> &Arc<B> {
        &self.bus
    }
}

// =============================================================================
// KernelStore implementation — delegate reads to local, writes to local + bus
// =============================================================================

impl<S: KernelStore, B: EventBus> KernelStore for ClusterKernelStore<S, B> {
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
