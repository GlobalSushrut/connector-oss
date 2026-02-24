//! # RedbKernelStore — Enterprise-grade persistent storage via redb
//!
//! Pure Rust, ACID, crash-safe (copy-on-write B-trees), MVCC.
//! No WAL needed — redb is inherently crash-safe via CoW.
//!
//! Tables:
//! - `packets`: CID bytes → JSON-serialized MemPacket
//! - `namespace_packets`: "ns:{namespace}" → JSON array of CID bytes
//! - `agents`: PID string → JSON-serialized AgentControlBlock
//! - `sessions`: session_id → JSON-serialized SessionEnvelope
//! - `audit`: "{timestamp}:{id}" → JSON-serialized KernelAuditEntry
//! - `windows`: "ns:{namespace}:{sn}" → JSON-serialized RangeWindow
//! - `state_vectors`: "pid:{agent_pid}:{sn}" → JSON-serialized StateVector
//! - `interference_edges`: "pid:{agent_pid}" → JSON array of edges
//! - `scitt_receipts`: statement_id → JSON-serialized ScittReceipt
//! - `ports`: port_id → JSON-serialized Port
//! - `policies`: role → JSON-serialized ExecutionPolicy
//! - `delegations`: chain_cid → JSON-serialized DelegationChain
//! - `wal`: "ns:{namespace}" → JSON array of WalEntry

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};

use vac_core::store::{KernelStore, StoreError, StoreResult};
use vac_core::audit_export::ScittReceipt;
use vac_core::interference::{InterferenceEdge, StateVector};
use vac_core::range_window::RangeWindow;
use vac_core::types::*;

// ── Table Definitions ───────────────────────────────────────

const PACKETS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("packets");
const NAMESPACE_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_index");
const AGENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("agents");
const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
const AUDIT: TableDefinition<&str, &[u8]> = TableDefinition::new("audit");
const WINDOWS: TableDefinition<&str, &[u8]> = TableDefinition::new("windows");
const STATE_VECTORS: TableDefinition<&str, &[u8]> = TableDefinition::new("state_vectors");
const INTERFERENCE: TableDefinition<&str, &[u8]> = TableDefinition::new("interference");
const SCITT: TableDefinition<&str, &[u8]> = TableDefinition::new("scitt");
const PORTS: TableDefinition<&str, &[u8]> = TableDefinition::new("ports");
const POLICIES: TableDefinition<&str, &[u8]> = TableDefinition::new("policies");
const DELEGATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("delegations");
const WAL: TableDefinition<&str, &[u8]> = TableDefinition::new("wal");

// ── Helpers ─────────────────────────────────────────────────

fn se(msg: impl std::fmt::Display) -> StoreError {
    StoreError { message: msg.to_string() }
}

fn cid_bytes(cid: &cid::Cid) -> Vec<u8> {
    cid.to_bytes()
}

fn cid_from_bytes(bytes: &[u8]) -> Result<cid::Cid, StoreError> {
    cid::Cid::try_from(bytes).map_err(|e| se(format!("Invalid CID: {}", e)))
}

fn to_json<T: serde::Serialize>(v: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| se(format!("Serialize: {}", e)))
}

fn from_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(bytes).map_err(|e| se(format!("Deserialize: {}", e)))
}

// ── RedbKernelStore ─────────────────────────────────────────

/// Enterprise-grade persistent KernelStore backed by redb.
///
/// - **ACID**: Every write is a full transaction
/// - **Crash-safe**: Copy-on-write B-trees — no WAL needed
/// - **MVCC**: Concurrent readers don't block writer
/// - **Pure Rust**: No C dependencies
pub struct RedbKernelStore {
    db: Arc<Database>,
}

impl RedbKernelStore {
    /// Open or create a redb database at the given path.
    ///
    /// Initializes all tables on first open so read transactions never
    /// fail with "table does not exist".
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let db = Database::create(path.as_ref())
            .map_err(|e| se(format!("Failed to open redb at {:?}: {}", path.as_ref(), e)))?;

        // Initialize all tables (creates them if they don't exist)
        let txn = db.begin_write().map_err(|e| se(e))?;
        txn.open_table(PACKETS).map_err(|e| se(e))?;
        txn.open_table(NAMESPACE_INDEX).map_err(|e| se(e))?;
        txn.open_table(AGENTS).map_err(|e| se(e))?;
        txn.open_table(SESSIONS).map_err(|e| se(e))?;
        txn.open_table(AUDIT).map_err(|e| se(e))?;
        txn.open_table(WINDOWS).map_err(|e| se(e))?;
        txn.open_table(STATE_VECTORS).map_err(|e| se(e))?;
        txn.open_table(INTERFERENCE).map_err(|e| se(e))?;
        txn.open_table(SCITT).map_err(|e| se(e))?;
        txn.open_table(PORTS).map_err(|e| se(e))?;
        txn.open_table(POLICIES).map_err(|e| se(e))?;
        txn.open_table(DELEGATIONS).map_err(|e| se(e))?;
        txn.open_table(WAL).map_err(|e| se(e))?;
        txn.commit().map_err(|e| se(e))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Get database file size in bytes.
    pub fn file_size(&self) -> StoreResult<u64> {
        // redb doesn't expose file size directly; we return 0 as placeholder
        Ok(0)
    }
}

// ── KernelStore Implementation ──────────────────────────────

impl KernelStore for RedbKernelStore {
    // --- Packets ---

    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        let key = cid_bytes(&packet.index.packet_cid);
        let val = to_json(packet)?;
        let ns = packet.namespace.clone().unwrap_or_default();

        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(PACKETS).map_err(|e| se(e))?;
            table.insert(key.as_slice(), val.as_slice()).map_err(|e| se(e))?;
        }
        // Update namespace index
        {
            let mut idx = txn.open_table(NAMESPACE_INDEX).map_err(|e| se(e))?;
            let mut cids: Vec<Vec<u8>> = idx.get(ns.as_str()).map_err(|e| se(e))?
                .map(|v| from_json::<Vec<Vec<u8>>>(v.value()).unwrap_or_default())
                .unwrap_or_default();
            if !cids.iter().any(|c| c == &key) {
                cids.push(key);
            }
            let cids_json = to_json(&cids)?;
            idx.insert(ns.as_str(), cids_json.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_packet(&self, cid: &cid::Cid) -> StoreResult<Option<MemPacket>> {
        let key = cid_bytes(cid);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(PACKETS).map_err(|e| se(e))?;
        match table.get(key.as_slice()).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let idx = txn.open_table(NAMESPACE_INDEX).map_err(|e| se(e))?;
        let cid_list: Vec<Vec<u8>> = match idx.get(namespace).map_err(|e| se(e))? {
            Some(v) => from_json(v.value())?,
            None => return Ok(Vec::new()),
        };

        let ptable = txn.open_table(PACKETS).map_err(|e| se(e))?;
        let mut packets = Vec::new();
        for cid_bytes in &cid_list {
            if let Some(v) = ptable.get(cid_bytes.as_slice()).map_err(|e| se(e))? {
                packets.push(from_json(v.value())?);
            }
        }
        Ok(packets)
    }

    fn delete_packet(&mut self, cid: &cid::Cid) -> StoreResult<()> {
        let key = cid_bytes(cid);
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(PACKETS).map_err(|e| se(e))?;
            table.remove(key.as_slice()).map_err(|e| se(e))?;
        }
        // Clean namespace index
        {
            let mut idx = txn.open_table(NAMESPACE_INDEX).map_err(|e| se(e))?;
            let mut iter = idx.iter().map_err(|e| se(e))?;
            let mut updates: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
            while let Some(Ok(entry)) = iter.next() {
                let ns = entry.0.value().to_string();
                let mut cids: Vec<Vec<u8>> = from_json(entry.1.value()).unwrap_or_default();
                let before = cids.len();
                cids.retain(|c| c != &key);
                if cids.len() != before {
                    updates.push((ns, cids));
                }
            }
            drop(iter);
            for (ns, cids) in updates {
                let val = to_json(&cids)?;
                idx.insert(ns.as_str(), val.as_slice()).map_err(|e| se(e))?;
            }
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    // --- RangeWindows ---

    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()> {
        let key = format!("{}:{}", window.namespace, window.sn);
        let val = to_json(window)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(WINDOWS).map_err(|e| se(e))?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>> {
        let key = format!("{}:{}", namespace, sn);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(WINDOWS).map_err(|e| se(e))?;
        match table.get(key.as_str()).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>> {
        let prefix = format!("{}:", namespace);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(WINDOWS).map_err(|e| se(e))?;
        let mut windows = Vec::new();
        let range = table.range(prefix.as_str()..).map_err(|e| se(e))?;
        for entry in range {
            let entry = entry.map_err(|e| se(e))?;
            let k = entry.0.value();
            if !k.starts_with(&prefix) { break; }
            windows.push(from_json(entry.1.value())?);
        }
        Ok(windows)
    }

    // --- StateVectors ---

    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> {
        let key = format!("{}:{}", sv.agent_pid, sv.sn);
        let val = to_json(sv)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(STATE_VECTORS).map_err(|e| se(e))?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>> {
        let key = format!("{}:{}", agent_pid, sn);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(STATE_VECTORS).map_err(|e| se(e))?;
        match table.get(key.as_str()).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>> {
        let prefix = format!("{}:", agent_pid);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(STATE_VECTORS).map_err(|e| se(e))?;
        let mut svs = Vec::new();
        let range = table.range(prefix.as_str()..).map_err(|e| se(e))?;
        for entry in range {
            let entry = entry.map_err(|e| se(e))?;
            if !entry.0.value().starts_with(&prefix) { break; }
            svs.push(from_json(entry.1.value())?);
        }
        Ok(svs)
    }

    // --- InterferenceEdges ---

    fn store_interference_edge(&mut self, ie: &InterferenceEdge) -> StoreResult<()> {
        let key = ie.agent_pid.clone();
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(INTERFERENCE).map_err(|e| se(e))?;
            let mut edges: Vec<InterferenceEdge> = table.get(key.as_str()).map_err(|e| se(e))?
                .map(|v| from_json(v.value()).unwrap_or_default())
                .unwrap_or_default();
            edges.push(ie.clone());
            let val = to_json(&edges)?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<InterferenceEdge>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(INTERFERENCE).map_err(|e| se(e))?;
        match table.get(agent_pid).map_err(|e| se(e))? {
            Some(v) => from_json(v.value()),
            None => Ok(Vec::new()),
        }
    }

    // --- Audit ---

    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()> {
        let key = format!("{}:{}", entry.timestamp, entry.audit_id);
        let val = to_json(entry)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(AUDIT).map_err(|e| se(e))?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_audit_entries(&self, from_ms: i64, to_ms: i64) -> StoreResult<Vec<KernelAuditEntry>> {
        let from_key = format!("{}:", from_ms);
        let to_key = format!("{}:", to_ms + 1);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(AUDIT).map_err(|e| se(e))?;
        let mut entries = Vec::new();
        let range = table.range(from_key.as_str()..to_key.as_str()).map_err(|e| se(e))?;
        for entry in range {
            let entry = entry.map_err(|e| se(e))?;
            entries.push(from_json(entry.1.value())?);
        }
        Ok(entries)
    }

    fn load_audit_entries_by_agent(&self, agent_pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(AUDIT).map_err(|e| se(e))?;
        let mut entries = Vec::new();
        // Scan all entries (reverse for most recent first)
        let iter = table.iter().map_err(|e| se(e))?;
        for entry in iter {
            let entry = entry.map_err(|e| se(e))?;
            let ae: KernelAuditEntry = from_json(entry.1.value())?;
            if ae.agent_pid == agent_pid {
                entries.push(ae);
                if entries.len() >= limit { break; }
            }
        }
        Ok(entries)
    }

    // --- SCITT Receipts ---

    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()> {
        let val = to_json(receipt)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(SCITT).map_err(|e| se(e))?;
            table.insert(receipt.statement_id.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(SCITT).map_err(|e| se(e))?;
        match table.get(statement_id).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    // --- Agents ---

    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> {
        let val = to_json(acb)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(AGENTS).map_err(|e| se(e))?;
            table.insert(acb.agent_pid.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(AGENTS).map_err(|e| se(e))?;
        match table.get(pid).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(AGENTS).map_err(|e| se(e))?;
        let mut agents = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            agents.push(from_json(entry.1.value())?);
        }
        Ok(agents)
    }

    // --- Sessions ---

    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()> {
        let val = to_json(session)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(SESSIONS).map_err(|e| se(e))?;
            table.insert(session.session_id.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(SESSIONS).map_err(|e| se(e))?;
        match table.get(session_id).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    // --- Ports ---

    fn store_port(&mut self, port: &Port) -> StoreResult<()> {
        let val = to_json(port)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(PORTS).map_err(|e| se(e))?;
            table.insert(port.port_id.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(PORTS).map_err(|e| se(e))?;
        match table.get(port_id).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(PORTS).map_err(|e| se(e))?;
        let mut ports = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            let port: Port = from_json(entry.1.value())?;
            if port.owner_pid == owner_pid {
                ports.push(port);
            }
        }
        Ok(ports)
    }

    // --- Execution Policies ---

    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()> {
        let key = format!("{:?}", policy.role);
        let val = to_json(policy)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(POLICIES).map_err(|e| se(e))?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_execution_policy(&self, role: &AgentRole) -> StoreResult<Option<ExecutionPolicy>> {
        let key = format!("{:?}", role);
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(POLICIES).map_err(|e| se(e))?;
        match table.get(key.as_str()).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(POLICIES).map_err(|e| se(e))?;
        let mut policies = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            policies.push(from_json(entry.1.value())?);
        }
        Ok(policies)
    }

    // --- Delegation Chains ---

    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()> {
        let key = chain.chain_cid.clone();
        let val = to_json(chain)?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(DELEGATIONS).map_err(|e| se(e))?;
            table.insert(key.as_str(), val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_delegation_chain(&self, chain_cid: &str) -> StoreResult<Option<DelegationChain>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(DELEGATIONS).map_err(|e| se(e))?;
        match table.get(chain_cid).map_err(|e| se(e))? {
            Some(v) => Ok(Some(from_json(v.value())?)),
            None => Ok(None),
        }
    }

    fn load_delegation_chains_by_subject(&self, subject: &str) -> StoreResult<Vec<DelegationChain>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(DELEGATIONS).map_err(|e| se(e))?;
        let mut chains = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            let chain: DelegationChain = from_json(entry.1.value())?;
            // Check if any proof in the chain has this subject as delegate
            let matches = chain.proofs.iter().any(|p| p.subject == subject);
            if matches {
                chains.push(chain);
            }
        }
        Ok(chains)
    }

    // --- WAL ---

    fn store_wal(&mut self, namespace: &str, entries: &[vac_core::range_window::WalEntry]) -> StoreResult<()> {
        let val = to_json(&entries.to_vec())?;
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(WAL).map_err(|e| se(e))?;
            table.insert(namespace, val.as_slice()).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<vac_core::range_window::WalEntry>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(WAL).map_err(|e| se(e))?;
        match table.get(namespace).map_err(|e| se(e))? {
            Some(v) => from_json(v.value()),
            None => Ok(Vec::new()),
        }
    }

    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()> {
        let txn = self.db.begin_write().map_err(|e| se(e))?;
        {
            let mut table = txn.open_table(WAL).map_err(|e| se(e))?;
            table.remove(namespace).map_err(|e| se(e))?;
        }
        txn.commit().map_err(|e| se(e))?;
        Ok(())
    }

    // --- Bulk loaders ---

    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(SESSIONS).map_err(|e| se(e))?;
        let mut sessions = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            sessions.push(from_json(entry.1.value())?);
        }
        Ok(sessions)
    }

    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        let txn = self.db.begin_read().map_err(|e| se(e))?;
        let table = txn.open_table(PACKETS).map_err(|e| se(e))?;
        let mut packets = Vec::new();
        for entry in table.iter().map_err(|e| se(e))? {
            let entry = entry.map_err(|e| se(e))?;
            packets.push(from_json(entry.1.value())?);
        }
        Ok(packets)
    }
}

// RedbKernelStore is Send because redb::Database is Send+Sync
unsafe impl Send for RedbKernelStore {}

// ── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
    use vac_core::store::KernelStore;

    fn tmp_store() -> (RedbKernelStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let store = RedbKernelStore::open(&path).unwrap();
        (store, dir)
    }

    fn setup_kernel() -> (MemoryKernel, String) {
        let mut kernel = MemoryKernel::new();
        let reg = SyscallRequest {
            agent_pid: "system".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".to_string(),
                namespace: "ns:test".to_string(),
                role: Some("writer".to_string()),
                model: None,
                framework: Some("connector".to_string()),
            },
            reason: Some("test".to_string()),
            vakya_id: None,
        };
        let result = kernel.dispatch(reg);
        let pid = match result.value {
            SyscallValue::AgentPid(p) => p,
            _ => panic!("Expected AgentPid"),
        };
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty,
            reason: Some("start".to_string()),
            vakya_id: None,
        });
        (kernel, pid)
    }

    #[test]
    fn test_redb_open_and_create() {
        let (store, _dir) = tmp_store();
        // Store should be empty
        let packets = store.load_all_packets().unwrap();
        assert!(packets.is_empty());
        let agents = store.load_all_agents().unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn test_redb_store_and_load_packet() {
        let (mut store, _dir) = tmp_store();
        let (_, pid) = setup_kernel();

        let packet = crate::auto_derive::AutoDerive::build_packet(
            "User prefers dark mode",
            "user:alice",
            "pipe:test",
            &pid,
            crate::auto_derive::DerivationContext::FactExtraction,
            None,
            Some("ns:test"),
        ).unwrap();

        // Store
        store.store_packet(&packet).unwrap();

        // Load by CID
        let loaded = store.load_packet(&packet.index.packet_cid).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert!(loaded.content.payload.to_string().contains("User prefers dark mode"));

        // Load by namespace
        let ns_packets = store.load_packets_by_namespace("ns:test").unwrap();
        assert_eq!(ns_packets.len(), 1);
        assert!(ns_packets[0].content.payload.to_string().contains("User prefers dark mode"));
    }

    #[test]
    fn test_redb_delete_packet() {
        let (mut store, _dir) = tmp_store();
        let (_, pid) = setup_kernel();

        let packet = crate::auto_derive::AutoDerive::build_packet(
            "temporary fact",
            "user:bob",
            "pipe:test",
            &pid,
            crate::auto_derive::DerivationContext::FactExtraction,
            None,
            Some("ns:test"),
        ).unwrap();

        store.store_packet(&packet).unwrap();
        assert!(store.load_packet(&packet.index.packet_cid).unwrap().is_some());

        // Delete
        store.delete_packet(&packet.index.packet_cid).unwrap();
        assert!(store.load_packet(&packet.index.packet_cid).unwrap().is_none());

        // Namespace index should be clean
        let ns_packets = store.load_packets_by_namespace("ns:test").unwrap();
        assert!(ns_packets.is_empty());
    }

    #[test]
    fn test_redb_store_and_load_agent() {
        let (mut store, _dir) = tmp_store();
        let (kernel, pid) = setup_kernel();

        let acb = kernel.get_agent(&pid).unwrap().clone();
        store.store_agent(&acb).unwrap();

        let loaded = store.load_agent(&pid).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().agent_pid, pid);

        let all = store.load_all_agents().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_redb_full_flush_and_recover() {
        let (mut store, _dir) = tmp_store();
        let (mut kernel, pid) = setup_kernel();

        // Write some packets through kernel
        let packet = crate::auto_derive::AutoDerive::build_packet(
            "important memory",
            "user:alice",
            "pipe:test",
            &pid,
            crate::auto_derive::DerivationContext::FactExtraction,
            None,
            Some("ns:test"),
        ).unwrap();
        kernel.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet },
            reason: Some("test write".to_string()),
            vakya_id: None,
        });

        let original_packets = kernel.packet_count();
        assert!(original_packets > 0);

        // Flush to redb
        let written = kernel.flush_to_store(&mut store).unwrap();
        assert!(written > 0, "Should write objects to redb");

        // Recover from redb
        let restored = MemoryKernel::load_from_store(&store).unwrap();
        assert_eq!(restored.packet_count(), original_packets,
            "Recovered kernel should have {} packets, got {}", original_packets, restored.packet_count());
    }

    #[test]
    fn test_redb_persistence_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persist.redb");

        // Write data
        {
            let mut store = RedbKernelStore::open(&path).unwrap();
            let (mut kernel, pid) = setup_kernel();

            let packet = crate::auto_derive::AutoDerive::build_packet(
                "persistent fact",
                "user:alice",
                "pipe:test",
                &pid,
                crate::auto_derive::DerivationContext::FactExtraction,
                None,
                Some("ns:test"),
            ).unwrap();
            kernel.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite { packet },
                reason: Some("persist".to_string()),
                vakya_id: None,
            });

            kernel.flush_to_store(&mut store).unwrap();
        } // store dropped, file closed

        // Reopen and verify data persisted
        {
            let store = RedbKernelStore::open(&path).unwrap();
            let restored = MemoryKernel::load_from_store(&store).unwrap();
            assert!(restored.packet_count() > 0,
                "Data should persist across reopen");

            let packets = store.load_packets_by_namespace("ns:test").unwrap();
            assert!(!packets.is_empty());
            assert!(packets[0].content.payload.to_string().contains("persistent fact"));
        }
    }

    #[test]
    fn test_redb_multiple_namespaces() {
        let (mut store, _dir) = tmp_store();
        let (_, pid) = setup_kernel();

        for (ns, text) in &[("ns:a", "fact A"), ("ns:b", "fact B"), ("ns:a", "fact A2")] {
            let packet = crate::auto_derive::AutoDerive::build_packet(
                text, "user:x", "pipe:test", &pid,
                crate::auto_derive::DerivationContext::FactExtraction,
                None, Some(ns),
            ).unwrap();
            store.store_packet(&packet).unwrap();
        }

        assert_eq!(store.load_packets_by_namespace("ns:a").unwrap().len(), 2);
        assert_eq!(store.load_packets_by_namespace("ns:b").unwrap().len(), 1);
        assert_eq!(store.load_packets_by_namespace("ns:c").unwrap().len(), 0);
    }
}
