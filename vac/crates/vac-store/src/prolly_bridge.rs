//! Prolly Tree Bridge — connects the `KernelStore` trait to `vac-prolly::ProllyTree`.
//!
//! Provides `ProllyKernelStore`, an implementation of `KernelStore` that
//! persists MemPackets, RangeWindows, StateVectors, and audit entries
//! into a Prolly tree for content-addressed, history-independent storage.
//!
//! The Prolly tree is async; this bridge uses `tokio::runtime::Handle`
//! to block on async operations within the synchronous `KernelStore` trait.

use std::sync::Arc;

use cid::Cid;
use tokio::runtime::Handle;
use tokio::sync::RwLock;

use vac_core::audit_export::ScittReceipt;
use vac_core::interference::InterferenceEdge as IEdge;
use vac_core::interference::StateVector;
use vac_core::range_window::RangeWindow;
use vac_core::store::{KernelStore, StoreError, StoreResult};
use vac_core::types::*;

use vac_prolly::tree::{MemoryNodeStore, ProllyTree};

use crate::cas::ContentStore;
use crate::memory::MemoryStore;

// =============================================================================
// ProllyKernelStore
// =============================================================================

/// A `KernelStore` implementation backed by a Prolly tree + CAS.
///
/// - MemPackets are serialized to CBOR and stored in the CAS (content-addressed).
/// - Prolly tree keys index packets by namespace/type/time for range queries.
/// - RangeWindows, StateVectors, and audit entries are stored in the CAS
///   and indexed by structured Prolly keys.
pub struct ProllyKernelStore {
    /// Content-addressable store for raw bytes
    cas: Arc<MemoryStore>,
    /// Prolly tree for packet indexing
    packet_tree: Arc<RwLock<ProllyTree<MemoryNodeStore>>>,
    /// Tokio runtime handle for blocking on async ops
    handle: Handle,
    /// Fallback in-memory store for types not yet in Prolly
    /// (agents, sessions, audit — these are small and rarely queried by range)
    fallback: vac_core::store::InMemoryKernelStore,
}

impl ProllyKernelStore {
    /// Create a new ProllyKernelStore with in-memory backends.
    ///
    /// In production, the CAS and NodeStore would be backed by disk/network.
    pub fn new(handle: Handle) -> Self {
        let cas = Arc::new(MemoryStore::new());
        let node_store = MemoryNodeStore::default();
        let packet_tree = Arc::new(RwLock::new(ProllyTree::new(node_store)));

        Self {
            cas,
            packet_tree,
            handle,
            fallback: vac_core::store::InMemoryKernelStore::new(),
        }
    }

    /// Get the CAS for direct access (e.g., for bulk operations)
    pub fn cas(&self) -> &Arc<MemoryStore> {
        &self.cas
    }

    /// Get the Prolly tree root CID
    pub fn prolly_root(&self) -> Option<Cid> {
        let tree = self.block_on_safe(self.packet_tree.read());
        tree.root().cloned()
    }

    /// Serialize a value to JSON bytes for CAS storage
    fn serialize<T: serde::Serialize>(value: &T) -> StoreResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|e| StoreError {
            message: format!("Serialization error: {}", e),
        })
    }

    /// Deserialize JSON bytes from CAS
    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StoreResult<T> {
        serde_json::from_slice(bytes).map_err(|e| StoreError {
            message: format!("Deserialization error: {}", e),
        })
    }

    /// Run an async block synchronously, safe even when called from within a tokio runtime.
    fn block_on_safe<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(f))
    }

    /// Store bytes in CAS and return the CID
    fn cas_put(&self, bytes: &[u8]) -> StoreResult<Cid> {
        self.block_on_safe(self.cas.put_bytes(bytes))
            .map_err(|e| StoreError {
                message: format!("CAS put error: {}", e),
            })
    }

    /// Load bytes from CAS by CID
    fn cas_get(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        match self.block_on_safe(self.cas.get_bytes(cid)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None),
        }
    }

    /// Insert a key-value pair into the Prolly tree
    fn prolly_insert(&self, key: Vec<u8>, value_cid: Cid) -> StoreResult<()> {
        let tree = self.packet_tree.clone();
        self.block_on_safe(async {
            let mut t = tree.write().await;
            t.insert(key, value_cid).await.map_err(|e| StoreError {
                message: format!("Prolly insert error: {}", e),
            })
        })
    }

    /// Lookup a value CID in the Prolly tree by key
    fn prolly_get(&self, key: &[u8]) -> StoreResult<Option<Cid>> {
        let tree = self.packet_tree.clone();
        self.block_on_safe(async {
            let t = tree.read().await;
            t.get(key).await.map_err(|e| StoreError {
                message: format!("Prolly get error: {}", e),
            })
        })
    }
}

impl KernelStore for ProllyKernelStore {
    // --- Packets: stored in CAS + indexed in Prolly tree ---
    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        let bytes = Self::serialize(packet)?;
        let cas_cid = self.cas_put(&bytes)?;

        // Build Prolly key for indexing
        let ns = packet.namespace.clone().unwrap_or_default();
        let key = vac_core::store::build_packet_prolly_key(
            "pkt",
            &ns,
            &packet.content.packet_type,
            packet.index.ts,
            &packet.index.packet_cid,
        );

        self.prolly_insert(key, cas_cid)?;

        // Also store in fallback for namespace queries (Prolly range scan not yet implemented)
        self.fallback.store_packet(packet)
    }

    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>> {
        // Try fallback first (faster for in-memory)
        self.fallback.load_packet(cid)
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        self.fallback.load_packets_by_namespace(namespace)
    }

    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()> {
        // Delete from CAS
        let _ = self.block_on_safe(self.cas.delete(cid));
        // Delete from fallback
        self.fallback.delete_packet(cid)
    }

    // --- RangeWindows: stored in CAS + indexed in Prolly ---
    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()> {
        let bytes = Self::serialize(window)?;
        let cas_cid = self.cas_put(&bytes)?;

        let key = vac_core::store::build_window_prolly_key("rw", &window.namespace, window.sn);
        self.prolly_insert(key, cas_cid)?;

        self.fallback.store_window(window)
    }

    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>> {
        // Try Prolly tree first
        let key = vac_core::store::build_window_prolly_key("rw", namespace, sn);
        if let Some(cas_cid) = self.prolly_get(&key)? {
            if let Some(bytes) = self.cas_get(&cas_cid)? {
                return Ok(Some(Self::deserialize(&bytes)?));
            }
        }
        // Fallback
        self.fallback.load_window(namespace, sn)
    }

    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>> {
        self.fallback.load_windows(namespace)
    }

    // --- StateVectors: stored in CAS + indexed in Prolly ---
    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> {
        let bytes = Self::serialize(sv)?;
        let cas_cid = self.cas_put(&bytes)?;

        let key = vac_core::store::build_sv_prolly_key("sv", &sv.agent_pid, sv.sn);
        self.prolly_insert(key, cas_cid)?;

        self.fallback.store_state_vector(sv)
    }

    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>> {
        let key = vac_core::store::build_sv_prolly_key("sv", agent_pid, sn);
        if let Some(cas_cid) = self.prolly_get(&key)? {
            if let Some(bytes) = self.cas_get(&cas_cid)? {
                return Ok(Some(Self::deserialize(&bytes)?));
            }
        }
        self.fallback.load_state_vector(agent_pid, sn)
    }

    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>> {
        self.fallback.load_state_vectors(agent_pid)
    }

    // --- Delegate remaining to fallback (small data, no range queries needed) ---
    fn store_interference_edge(&mut self, ie: &IEdge) -> StoreResult<()> {
        self.fallback.store_interference_edge(ie)
    }

    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<IEdge>> {
        self.fallback.load_interference_edges(agent_pid)
    }

    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()> {
        self.fallback.store_audit_entry(entry)
    }

    fn load_audit_entries(&self, from_ms: i64, to_ms: i64) -> StoreResult<Vec<KernelAuditEntry>> {
        self.fallback.load_audit_entries(from_ms, to_ms)
    }

    fn load_audit_entries_by_agent(&self, agent_pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>> {
        self.fallback.load_audit_entries_by_agent(agent_pid, limit)
    }

    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()> {
        self.fallback.store_scitt_receipt(receipt)
    }

    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>> {
        self.fallback.load_scitt_receipt(statement_id)
    }

    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> {
        self.fallback.store_agent(acb)
    }

    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> {
        self.fallback.load_agent(pid)
    }

    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> {
        self.fallback.load_all_agents()
    }

    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()> {
        self.fallback.store_session(session)
    }

    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>> {
        self.fallback.load_session(session_id)
    }

    // --- Ports (delegated to fallback) ---
    fn store_port(&mut self, port: &Port) -> StoreResult<()> {
        self.fallback.store_port(port)
    }
    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>> {
        self.fallback.load_port(port_id)
    }
    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>> {
        self.fallback.load_ports_by_owner(owner_pid)
    }

    // --- Execution Policies (delegated to fallback) ---
    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()> {
        self.fallback.store_execution_policy(policy)
    }
    fn load_execution_policy(&self, role: &AgentRole) -> StoreResult<Option<ExecutionPolicy>> {
        self.fallback.load_execution_policy(role)
    }
    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> {
        self.fallback.load_all_policies()
    }

    // --- Delegation Chains (delegated to fallback) ---
    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()> {
        self.fallback.store_delegation_chain(chain)
    }
    fn load_delegation_chain(&self, chain_cid: &str) -> StoreResult<Option<DelegationChain>> {
        self.fallback.load_delegation_chain(chain_cid)
    }
    fn load_delegation_chains_by_subject(&self, subject: &str) -> StoreResult<Vec<DelegationChain>> {
        self.fallback.load_delegation_chains_by_subject(subject)
    }

    // --- WAL (delegated to fallback) ---
    fn store_wal(&mut self, namespace: &str, entries: &[vac_core::range_window::WalEntry]) -> StoreResult<()> {
        self.fallback.store_wal(namespace, entries)
    }
    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<vac_core::range_window::WalEntry>> {
        self.fallback.load_wal(namespace)
    }
    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()> {
        self.fallback.clear_wal(namespace)
    }

    // --- Bulk loaders (delegated to fallback) ---
    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> {
        self.fallback.load_all_sessions()
    }
    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        self.fallback.load_all_packets()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_source() -> Source {
        Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkTest".to_string(),
        }
    }

    fn make_packet(entities: &[&str], ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"test": true}),
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            ts,
        )
        .with_entities(entities.iter().map(|s| s.to_string()).collect())
        .with_namespace("ns:test".to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prolly_store_packet() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);

        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();

        // Load back
        let loaded = store.load_packet(&cid).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().content.entities, vec!["alice".to_string()]);

        // CAS should have content
        assert!(store.cas().len() > 0);

        // Prolly tree should have a root
        assert!(store.prolly_root().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prolly_store_window() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);

        let window = RangeWindow {
            sn: 0,
            page_code: "ns:test/000000".to_string(),
            event_time_start: 1000,
            event_time_end: 3000,
            ingest_time: 4000,
            leaf_cids: vec![],
            token_count: 100,
            packet_count: 3,
            rw_root: [0u8; 32],
            prev_rw_root: [0u8; 32],
            tree_size: 3,
            boundary_reason: vac_core::range_window::BoundaryReason::PacketLimit,
            namespace: "ns:test".to_string(),
            agent_pid: "pid:001".to_string(),
            session_id: None,
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            sealed: true,
            entities: vec!["alice".to_string()],
        };

        store.store_window(&window).unwrap();

        // Load via Prolly tree path
        let loaded = store.load_window("ns:test", 0).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().packet_count, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prolly_store_state_vector() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);

        let sv = StateVector {
            sn: 0,
            agent_pid: "pid:001".to_string(),
            namespace: "ns:test".to_string(),
            entities: BTreeMap::new(),
            intents: vec![],
            decisions: vec![],
            contradictions: vec![],
            observations: vec![],
            summary: None,
            source_packet_count: 5,
            source_token_count: 200,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 1000,
        };

        store.store_state_vector(&sv).unwrap();

        // Load via Prolly tree path
        let loaded = store.load_state_vector("pid:001", 0).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().source_packet_count, 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prolly_delete_packet() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);

        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_some());

        store.delete_packet(&cid).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_prolly_namespace_query() {
        let handle = Handle::current();
        let mut store = ProllyKernelStore::new(handle);

        store.store_packet(&make_packet(&["alice"], 1000)).unwrap();
        store.store_packet(&make_packet(&["bob"], 2000)).unwrap();

        let packets = store.load_packets_by_namespace("ns:test").unwrap();
        assert_eq!(packets.len(), 2);
    }
}
