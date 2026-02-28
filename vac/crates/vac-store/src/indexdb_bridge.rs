//! IndexDB Bridge — connects the `KernelStore` trait to a persistent database backend.
//!
//! Provides:
//! - `AsyncPersistenceBackend`: an async trait that any database (SQLite, Postgres, etc.)
//!   can implement to serve as a kernel persistence layer.
//! - `IndexDbKernelStore`: a `KernelStore` implementation that delegates to an
//!   `AsyncPersistenceBackend` using `block_in_place` for sync→async bridging.
//!
//! The `aapi-indexdb` crate (or any other DB crate) can implement
//! `AsyncPersistenceBackend` to plug into the kernel.

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use tokio::runtime::Handle;
use tokio::sync::RwLock;

use vac_core::audit_export::ScittReceipt;
use vac_core::interference::InterferenceEdge as IEdge;
use vac_core::interference::StateVector;
use vac_core::range_window::RangeWindow;
use vac_core::store::{KernelStore, StoreError, StoreResult};
use vac_core::types::*;

// =============================================================================
// AsyncPersistenceBackend trait
// =============================================================================

/// Error type for async persistence operations
#[derive(Debug, Clone)]
pub struct PersistenceError {
    pub message: String,
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PersistenceError: {}", self.message)
    }
}

impl std::error::Error for PersistenceError {}

pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Async persistence backend trait.
///
/// Any database (SQLite via sqlx, Postgres, etc.) can implement this trait
/// to serve as a kernel persistence layer. The `IndexDbKernelStore` wraps
/// this trait for synchronous `KernelStore` usage.
///
/// All data is passed as JSON bytes to keep the trait database-agnostic.
/// The implementor is responsible for schema management and indexing.
#[async_trait]
pub trait AsyncPersistenceBackend: Send + Sync {
    // --- Generic key-value operations ---
    /// Store a JSON-serialized record by (table, key)
    async fn put(&self, table: &str, key: &str, value: &[u8]) -> PersistenceResult<()>;

    /// Load a JSON-serialized record by (table, key)
    async fn get(&self, table: &str, key: &str) -> PersistenceResult<Option<Vec<u8>>>;

    /// Delete a record by (table, key)
    async fn delete(&self, table: &str, key: &str) -> PersistenceResult<()>;

    /// List all records in a table matching a key prefix
    async fn list_by_prefix(&self, table: &str, prefix: &str) -> PersistenceResult<Vec<Vec<u8>>>;

    /// List records in a table matching a key range [from, to]
    async fn list_by_range(&self, table: &str, from: &str, to: &str) -> PersistenceResult<Vec<Vec<u8>>>;

    /// Get the count of records in a table
    async fn count(&self, table: &str) -> PersistenceResult<u64>;
}

// =============================================================================
// InMemoryPersistenceBackend — for testing
// =============================================================================

/// In-memory implementation of `AsyncPersistenceBackend` using a BTreeMap.
/// Suitable for testing the IndexDB bridge without a real database.
#[derive(Default)]
pub struct InMemoryPersistenceBackend {
    data: std::sync::Mutex<std::collections::BTreeMap<(String, String), Vec<u8>>>,
}

impl InMemoryPersistenceBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AsyncPersistenceBackend for InMemoryPersistenceBackend {
    async fn put(&self, table: &str, key: &str, value: &[u8]) -> PersistenceResult<()> {
        let mut data = self.data.lock().unwrap();
        data.insert((table.to_string(), key.to_string()), value.to_vec());
        Ok(())
    }

    async fn get(&self, table: &str, key: &str) -> PersistenceResult<Option<Vec<u8>>> {
        let data = self.data.lock().unwrap();
        Ok(data.get(&(table.to_string(), key.to_string())).cloned())
    }

    async fn delete(&self, table: &str, key: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().unwrap();
        data.remove(&(table.to_string(), key.to_string()));
        Ok(())
    }

    async fn list_by_prefix(&self, table: &str, prefix: &str) -> PersistenceResult<Vec<Vec<u8>>> {
        let data = self.data.lock().unwrap();
        let table = table.to_string();
        let results: Vec<Vec<u8>> = data
            .iter()
            .filter(|((t, k), _)| t == &table && k.starts_with(prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(results)
    }

    async fn list_by_range(&self, table: &str, from: &str, to: &str) -> PersistenceResult<Vec<Vec<u8>>> {
        let data = self.data.lock().unwrap();
        let table_str = table.to_string();
        let from_key = (table_str.clone(), from.to_string());
        let to_key = (table_str.clone(), to.to_string());
        let results: Vec<Vec<u8>> = data
            .range(from_key..=to_key)
            .filter(|((t, _), _)| t == &table_str)
            .map(|(_, v)| v.clone())
            .collect();
        Ok(results)
    }

    async fn count(&self, table: &str) -> PersistenceResult<u64> {
        let data = self.data.lock().unwrap();
        let table = table.to_string();
        Ok(data.keys().filter(|(t, _)| t == &table).count() as u64)
    }
}

// =============================================================================
// IndexDbKernelStore
// =============================================================================

/// Table names used by the IndexDB bridge
pub mod tables {
    pub const PACKETS: &str = "kernel_packets";
    pub const WINDOWS: &str = "kernel_windows";
    pub const STATE_VECTORS: &str = "kernel_state_vectors";
    pub const INTERFERENCE_EDGES: &str = "kernel_interference_edges";
    pub const AUDIT_ENTRIES: &str = "kernel_audit_entries";
    pub const SCITT_RECEIPTS: &str = "kernel_scitt_receipts";
    pub const AGENTS: &str = "kernel_agents";
    pub const SESSIONS: &str = "kernel_sessions";
    pub const PORTS: &str = "kernel_ports";
    pub const EXECUTION_POLICIES: &str = "kernel_execution_policies";
    pub const DELEGATION_CHAINS: &str = "kernel_delegation_chains";
    pub const WAL: &str = "kernel_wal";
}

/// A `KernelStore` implementation backed by an `AsyncPersistenceBackend`.
///
/// This bridges the synchronous `KernelStore` trait to any async database
/// backend. Data is serialized to JSON for storage.
pub struct IndexDbKernelStore {
    backend: Arc<dyn AsyncPersistenceBackend>,
    handle: Handle,
}

impl IndexDbKernelStore {
    pub fn new(backend: Arc<dyn AsyncPersistenceBackend>, handle: Handle) -> Self {
        Self { backend, handle }
    }

    fn block_on_safe<F: std::future::Future>(&self, f: F) -> F::Output {
        tokio::task::block_in_place(|| self.handle.block_on(f))
    }

    fn serialize<T: serde::Serialize>(value: &T) -> StoreResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|e| StoreError {
            message: format!("Serialization error: {}", e),
        })
    }

    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StoreResult<T> {
        serde_json::from_slice(bytes).map_err(|e| StoreError {
            message: format!("Deserialization error: {}", e),
        })
    }

    fn map_err(e: PersistenceError) -> StoreError {
        StoreError {
            message: format!("Persistence backend: {}", e.message),
        }
    }
}

impl KernelStore for IndexDbKernelStore {
    // --- Packets ---
    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        let bytes = Self::serialize(packet)?;
        let key = packet.index.packet_cid.to_string();
        self.block_on_safe(self.backend.put(tables::PACKETS, &key, &bytes))
            .map_err(Self::map_err)?;

        // Also store under namespace prefix for namespace queries
        let ns = packet.namespace.clone().unwrap_or_default();
        let ns_key = format!("ns:{}:{}:{}", ns, packet.index.ts, key);
        self.block_on_safe(self.backend.put(tables::PACKETS, &ns_key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>> {
        let key = cid.to_string();
        match self.block_on_safe(self.backend.get(tables::PACKETS, &key)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        let prefix = format!("ns:{}:", namespace);
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::PACKETS, &prefix))
            .map_err(Self::map_err)?;
        results.iter().map(|b| Self::deserialize(b)).collect()
    }

    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()> {
        let key = cid.to_string();
        self.block_on_safe(self.backend.delete(tables::PACKETS, &key))
            .map_err(Self::map_err)
    }

    // --- RangeWindows ---
    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()> {
        let bytes = Self::serialize(window)?;
        let key = format!("{}/{:010}", window.namespace, window.sn);
        self.block_on_safe(self.backend.put(tables::WINDOWS, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>> {
        let key = format!("{}/{:010}", namespace, sn);
        match self.block_on_safe(self.backend.get(tables::WINDOWS, &key)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>> {
        let prefix = format!("{}/", namespace);
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::WINDOWS, &prefix))
            .map_err(Self::map_err)?;
        results.iter().map(|b| Self::deserialize(b)).collect()
    }

    // --- StateVectors ---
    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> {
        let bytes = Self::serialize(sv)?;
        let key = format!("{}/{:010}", sv.agent_pid, sv.sn);
        self.block_on_safe(self.backend.put(tables::STATE_VECTORS, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>> {
        let key = format!("{}/{:010}", agent_pid, sn);
        match self.block_on_safe(self.backend.get(tables::STATE_VECTORS, &key)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>> {
        let prefix = format!("{}/", agent_pid);
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::STATE_VECTORS, &prefix))
            .map_err(Self::map_err)?;
        results.iter().map(|b| Self::deserialize(b)).collect()
    }

    // --- InterferenceEdges ---
    fn store_interference_edge(&mut self, ie: &IEdge) -> StoreResult<()> {
        let bytes = Self::serialize(ie)?;
        // D2 FIX: Key by agent_pid so load_interference_edges(agent_pid) can find them
        let key = format!("{}:{:010}:{:010}", ie.agent_pid, ie.from_sn, ie.to_sn);
        self.block_on_safe(self.backend.put(tables::INTERFERENCE_EDGES, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<IEdge>> {
        let prefix = format!("{}:", agent_pid);
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::INTERFERENCE_EDGES, &prefix))
            .map_err(Self::map_err)?;
        results.iter().map(|b| Self::deserialize(b)).collect()
    }

    // --- Audit ---
    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()> {
        let bytes = Self::serialize(entry)?;
        let key = format!("{}/{:020}", entry.agent_pid, entry.timestamp);
        self.block_on_safe(self.backend.put(tables::AUDIT_ENTRIES, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_audit_entries(&self, from_ms: i64, to_ms: i64) -> StoreResult<Vec<KernelAuditEntry>> {
        // Use range query with timestamp-based keys
        // We need to scan all agents, so use a broad range
        let from_key = format!("{:020}", from_ms);
        let to_key = format!("{:020}", to_ms);
        // For simplicity, list all and filter by timestamp
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::AUDIT_ENTRIES, ""))
            .map_err(Self::map_err)?;
        let mut entries: Vec<KernelAuditEntry> = results
            .iter()
            .filter_map(|b| Self::deserialize(b).ok())
            .filter(|e: &KernelAuditEntry| e.timestamp >= from_ms && e.timestamp <= to_ms)
            .collect();
        entries.sort_by_key(|e| e.timestamp);
        Ok(entries)
    }

    fn load_audit_entries_by_agent(&self, agent_pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>> {
        let prefix = format!("{}/", agent_pid);
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::AUDIT_ENTRIES, &prefix))
            .map_err(Self::map_err)?;
        results
            .iter()
            .take(limit)
            .map(|b| Self::deserialize(b))
            .collect()
    }

    // --- SCITT Receipts ---
    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()> {
        let bytes = Self::serialize(receipt)?;
        self.block_on_safe(self.backend.put(tables::SCITT_RECEIPTS, &receipt.statement_id, &bytes))
            .map_err(Self::map_err)
    }

    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>> {
        match self.block_on_safe(self.backend.get(tables::SCITT_RECEIPTS, statement_id)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    // --- Agents ---
    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> {
        let bytes = Self::serialize(acb)?;
        self.block_on_safe(self.backend.put(tables::AGENTS, &acb.agent_pid, &bytes))
            .map_err(Self::map_err)
    }

    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> {
        match self.block_on_safe(self.backend.get(tables::AGENTS, pid)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> {
        let results = self
            .block_on_safe(self.backend.list_by_prefix(tables::AGENTS, ""))
            .map_err(Self::map_err)?;
        results.iter().map(|b| Self::deserialize(b)).collect()
    }

    // --- Sessions ---
    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()> {
        let bytes = Self::serialize(session)?;
        self.block_on_safe(self.backend.put(tables::SESSIONS, &session.session_id, &bytes))
            .map_err(Self::map_err)
    }

    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>> {
        match self.block_on_safe(self.backend.get(tables::SESSIONS, session_id)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    // --- Ports ---
    fn store_port(&mut self, port: &Port) -> StoreResult<()> {
        let bytes = Self::serialize(port)?;
        self.block_on_safe(self.backend.put(tables::PORTS, &port.port_id, &bytes))
            .map_err(Self::map_err)
    }

    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>> {
        match self.block_on_safe(self.backend.get(tables::PORTS, port_id)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>> {
        let prefix = format!("owner:{}", owner_pid);
        match self.block_on_safe(self.backend.list_by_prefix(tables::PORTS, &prefix)) {
            Ok(entries) => {
                let mut ports = Vec::new();
                for bytes in entries {
                    ports.push(Self::deserialize(&bytes)?);
                }
                Ok(ports)
            }
            Err(e) => Err(Self::map_err(e)),
        }
    }

    // --- Execution Policies ---
    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()> {
        let bytes = Self::serialize(policy)?;
        let key = format!("{:?}", policy.role);
        self.block_on_safe(self.backend.put(tables::EXECUTION_POLICIES, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_execution_policy(&self, role: &AgentRole) -> StoreResult<Option<ExecutionPolicy>> {
        let key = format!("{:?}", role);
        match self.block_on_safe(self.backend.get(tables::EXECUTION_POLICIES, &key)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> {
        match self.block_on_safe(self.backend.list_by_prefix(tables::EXECUTION_POLICIES, "")) {
            Ok(entries) => {
                let mut policies = Vec::new();
                for bytes in entries {
                    policies.push(Self::deserialize(&bytes)?);
                }
                Ok(policies)
            }
            Err(e) => Err(Self::map_err(e)),
        }
    }

    // --- Delegation Chains ---
    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()> {
        let bytes = Self::serialize(chain)?;
        self.block_on_safe(self.backend.put(tables::DELEGATION_CHAINS, &chain.chain_cid, &bytes))
            .map_err(Self::map_err)
    }

    fn load_delegation_chain(&self, chain_cid: &str) -> StoreResult<Option<DelegationChain>> {
        match self.block_on_safe(self.backend.get(tables::DELEGATION_CHAINS, chain_cid)) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_delegation_chains_by_subject(&self, subject: &str) -> StoreResult<Vec<DelegationChain>> {
        let prefix = format!("subj:{}", subject);
        match self.block_on_safe(self.backend.list_by_prefix(tables::DELEGATION_CHAINS, &prefix)) {
            Ok(entries) => {
                let mut chains = Vec::new();
                for bytes in entries {
                    chains.push(Self::deserialize(&bytes)?);
                }
                Ok(chains)
            }
            Err(e) => Err(Self::map_err(e)),
        }
    }

    // --- WAL ---
    fn store_wal(&mut self, namespace: &str, entries: &[vac_core::range_window::WalEntry]) -> StoreResult<()> {
        let key = format!("wal:{}", namespace);
        let bytes = Self::serialize(&entries.to_vec())?;
        self.block_on_safe(self.backend.put(tables::WAL, &key, &bytes))
            .map_err(Self::map_err)
    }

    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<vac_core::range_window::WalEntry>> {
        let key = format!("wal:{}", namespace);
        match self.block_on_safe(self.backend.get(tables::WAL, &key)) {
            Ok(Some(bytes)) => Ok(Self::deserialize(&bytes)?),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()> {
        let key = format!("wal:{}", namespace);
        self.block_on_safe(self.backend.delete(tables::WAL, &key))
            .map_err(Self::map_err)
    }

    // --- Bulk loaders ---
    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> {
        match self.block_on_safe(self.backend.list_by_prefix(tables::SESSIONS, "")) {
            Ok(entries) => {
                let mut sessions = Vec::new();
                for bytes in entries {
                    sessions.push(Self::deserialize(&bytes)?);
                }
                Ok(sessions)
            }
            Err(e) => Err(Self::map_err(e)),
        }
    }

    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        match self.block_on_safe(self.backend.list_by_prefix(tables::PACKETS, "")) {
            Ok(entries) => {
                let mut packets = Vec::new();
                for bytes in entries {
                    packets.push(Self::deserialize(&bytes)?);
                }
                Ok(packets)
            }
            Err(e) => Err(Self::map_err(e)),
        }
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
    async fn test_indexdb_store_and_load_packet() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();

        let loaded = store.load_packet(&cid).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().content.entities, vec!["alice".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_namespace_query() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        store.store_packet(&make_packet(&["alice"], 1000)).unwrap();
        store.store_packet(&make_packet(&["bob"], 2000)).unwrap();

        let packets = store.load_packets_by_namespace("ns:test").unwrap();
        assert_eq!(packets.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_delete_packet() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_some());

        store.delete_packet(&cid).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_store_and_load_window() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

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

        let loaded = store.load_window("ns:test", 0).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().packet_count, 3);

        let all = store.load_windows("ns:test").unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_store_and_load_state_vector() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

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

        let loaded = store.load_state_vector("pid:001", 0).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().source_packet_count, 5);

        let all = store.load_state_vectors("pid:001").unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_store_and_load_agent() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        let acb = AgentControlBlock {
            agent_pid: "pid:001".to_string(),
            agent_name: "bot".to_string(),
            agent_role: None,
            status: AgentStatus::Running,
            priority: 5,
            namespace: "ns:test".to_string(),
            memory_region: MemoryRegion::new("ns:test".to_string()),
            active_sessions: Vec::new(),
            total_packets: 0,
            total_tokens_consumed: 0,
            total_cost_usd: 0.0,
            capabilities: Vec::new(),
            readable_namespaces: Vec::new(),
            writable_namespaces: Vec::new(),
            allowed_tools: Vec::new(),
            model: None,
            framework: None,
            parent_pid: None,
            child_pids: Vec::new(),
            registered_at: 1000,
            last_active_at: 2000,
            terminated_at: None,
            termination_reason: None,
            phase: AgentPhase::default(),
            role: AgentRole::default(),
            namespace_mounts: Vec::new(),
            tool_bindings: Vec::new(),
            signal_handlers: Vec::new(),
            pending_signals: Vec::new(),
            agent_priority: AgentPriority::default(),
            token_budget: None,
        };

        store.store_agent(&acb).unwrap();

        let loaded = store.load_agent("pid:001").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().agent_name, "bot");

        let all = store.load_all_agents().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_store_and_load_session() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        let session = SessionEnvelope {
            type_: "session".to_string(),
            version: 1,
            session_id: "sess:001".to_string(),
            agent_id: "pid:001".to_string(),
            namespace: "ns:test".to_string(),
            label: Some("test session".to_string()),
            started_at: 1000,
            ended_at: None,
            packet_cids: Vec::new(),
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            compression: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            summary: None,
            summary_cid: None,
            total_tokens: 0,
            metadata: BTreeMap::new(),
        };

        store.store_session(&session).unwrap();

        let loaded = store.load_session("sess:001").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().label, Some("test session".to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_store_and_load_audit() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());
        let handle = Handle::current();
        let mut store = IndexDbKernelStore::new(backend, handle);

        let entry = KernelAuditEntry {
            audit_id: "a001".into(),
            timestamp: 1000,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:001".into(),
            target: Some("cid:x".into()),
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: Some(100),
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
            natural_language: None,
            business_impact: None,
            remediation_hint: None,
            causal_chain: Vec::new(),
            severity: TelemetrySeverity::default(),
            gen_ai_attrs: None,
        };

        store.store_audit_entry(&entry).unwrap();

        let loaded = store.load_audit_entries(0, 2000).unwrap();
        assert_eq!(loaded.len(), 1);

        let by_agent = store.load_audit_entries_by_agent("pid:001", 10).unwrap();
        assert_eq!(by_agent.len(), 1);

        let empty = store.load_audit_entries(5000, 6000).unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_backend_count() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());

        backend.put("test", "key1", b"value1").await.unwrap();
        backend.put("test", "key2", b"value2").await.unwrap();

        assert_eq!(backend.count("test").await.unwrap(), 2);
        assert_eq!(backend.count("other").await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_indexdb_backend_range_query() {
        let backend = Arc::new(InMemoryPersistenceBackend::new());

        backend.put("test", "a/001", b"first").await.unwrap();
        backend.put("test", "a/002", b"second").await.unwrap();
        backend.put("test", "a/003", b"third").await.unwrap();
        backend.put("test", "b/001", b"other").await.unwrap();

        let results = backend.list_by_range("test", "a/001", "a/002").await.unwrap();
        assert_eq!(results.len(), 2);

        let prefix_results = backend.list_by_prefix("test", "a/").await.unwrap();
        assert_eq!(prefix_results.len(), 3);
    }
}
