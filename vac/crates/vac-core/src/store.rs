//! Storage abstraction for the Memory Kernel.
//!
//! Defines `KernelStore` — a trait that the `AgentRuntime` uses to persist
//! and retrieve kernel state. Provides:
//! - `InMemoryKernelStore`: HashMap-based (default, already used by kernel)
//! - Bridge types for Prolly tree (`ProllyBridge`) and IndexDB (`IndexDbBridge`)
//!
//! The trait is synchronous because the kernel dispatch loop is synchronous.
//! Async backends (Prolly, IndexDB) are wrapped with blocking adapters.
//!
//! Design: The kernel remains the source of truth for in-flight state.
//! The store is used for:
//! 1. Persisting committed RangeWindows
//! 2. Persisting StateVectors and InterferenceEdges
//! 3. Persisting sealed packets for long-term storage
//! 4. Loading historical state on startup

use std::collections::{BTreeMap, HashMap};

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::audit_export::ScittReceipt;
use crate::interference::InterferenceEdge as IEdge;
use crate::interference::StateVector;
use crate::range_window::RangeWindow;
use crate::types::*;

// =============================================================================
// KernelStore trait
// =============================================================================

/// Error type for store operations
#[derive(Debug, Clone)]
pub struct StoreError {
    pub message: String,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreError: {}", self.message)
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// The storage trait for kernel persistence.
///
/// All methods are synchronous. Async backends should use
/// `tokio::runtime::Handle::current().block_on()` or similar.
pub trait KernelStore {
    // --- Packets ---
    /// Persist a MemPacket
    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()>;
    /// Load a MemPacket by CID
    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>>;
    /// Load packets by namespace
    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>>;
    /// Delete a packet (for GC)
    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()>;

    // --- RangeWindows ---
    /// Persist a committed RangeWindow
    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()>;
    /// Load a RangeWindow by (namespace, sn)
    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>>;
    /// Load all windows for a namespace, ordered by sn
    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>>;

    // --- StateVectors ---
    /// Persist a StateVector
    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()>;
    /// Load a StateVector by (agent_pid, sn)
    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>>;
    /// Load all StateVectors for an agent, ordered by sn
    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>>;

    // --- InterferenceEdges ---
    /// Persist an InterferenceEdge
    fn store_interference_edge(&mut self, ie: &IEdge) -> StoreResult<()>;
    /// Load all InterferenceEdges for an agent, ordered by from_sn
    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<IEdge>>;

    // --- Audit ---
    /// Persist a KernelAuditEntry
    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()>;
    /// Load audit entries in a time range
    fn load_audit_entries(&self, from_ms: i64, to_ms: i64) -> StoreResult<Vec<KernelAuditEntry>>;
    /// Load audit entries for an agent
    fn load_audit_entries_by_agent(&self, agent_pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>>;

    // --- SCITT Receipts ---
    /// Persist a SCITT receipt
    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()>;
    /// Load a SCITT receipt by statement_id
    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>>;

    // --- Agents ---
    /// Persist an AgentControlBlock
    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()>;
    /// Load an AgentControlBlock by PID
    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>>;
    /// Load all agents
    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>>;

    // --- Sessions ---
    /// Persist a SessionEnvelope
    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()>;
    /// Load a SessionEnvelope by ID
    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>>;

    // --- Ports (Phase 9e) ---
    /// Persist a Port
    fn store_port(&mut self, port: &Port) -> StoreResult<()>;
    /// Load a Port by ID
    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>>;
    /// Load all ports owned by an agent
    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>>;

    // --- Execution Policies (Phase 9e) ---
    /// Persist an ExecutionPolicy
    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()>;
    /// Load an ExecutionPolicy by role
    fn load_execution_policy(&self, role: &AgentRole) -> StoreResult<Option<ExecutionPolicy>>;
    /// Load all execution policies
    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>>;

    // --- Delegation Chains (Phase 9e) ---
    /// Persist a DelegationChain
    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()>;
    /// Load a DelegationChain by CID
    fn load_delegation_chain(&self, chain_cid: &str) -> StoreResult<Option<DelegationChain>>;
    /// Load all delegation chains for a subject
    fn load_delegation_chains_by_subject(&self, subject: &str) -> StoreResult<Vec<DelegationChain>>;

    // --- WAL (Tier 1 Hardening) ---
    /// Persist WAL entries for crash recovery
    fn store_wal(&mut self, namespace: &str, entries: &[crate::range_window::WalEntry]) -> StoreResult<()>;
    /// Load WAL entries for a namespace (for replay after crash)
    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<crate::range_window::WalEntry>>;
    /// Clear WAL for a namespace (after successful commit)
    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()>;

    // --- Bulk loaders (Tier 1 Hardening) ---
    /// Load all sessions
    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>>;
    /// Load all packets (for kernel reconstruction)
    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>>;
}

// =============================================================================
// InMemoryKernelStore — HashMap-based implementation
// =============================================================================

/// In-memory store using HashMaps. This is the default backend.
/// Suitable for testing, single-process agents, and short-lived sessions.
#[derive(Default)]
pub struct InMemoryKernelStore {
    packets: HashMap<Cid, MemPacket>,
    namespace_packets: HashMap<String, Vec<Cid>>,
    windows: BTreeMap<(String, u64), RangeWindow>,
    state_vectors: BTreeMap<(String, u64), StateVector>,
    interference_edges: HashMap<String, Vec<IEdge>>,
    audit_entries: Vec<KernelAuditEntry>,
    scitt_receipts: HashMap<String, ScittReceipt>,
    agents: HashMap<String, AgentControlBlock>,
    sessions: HashMap<String, SessionEnvelope>,
    ports: HashMap<String, Port>,
    execution_policies: HashMap<String, ExecutionPolicy>,
    delegation_chains: HashMap<String, DelegationChain>,
    wal_entries: HashMap<String, Vec<crate::range_window::WalEntry>>,
}

impl InMemoryKernelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total stored object count (for diagnostics)
    pub fn total_objects(&self) -> usize {
        self.packets.len()
            + self.windows.len()
            + self.state_vectors.len()
            + self.audit_entries.len()
            + self.scitt_receipts.len()
            + self.agents.len()
            + self.sessions.len()
            + self.ports.len()
            + self.execution_policies.len()
            + self.delegation_chains.len()
    }
}

impl KernelStore for InMemoryKernelStore {
    // --- Packets ---
    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        let cid = packet.index.packet_cid.clone();
        let ns = packet.namespace.clone().unwrap_or_default();
        self.namespace_packets.entry(ns).or_default().push(cid.clone());
        self.packets.insert(cid, packet.clone());
        Ok(())
    }

    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>> {
        Ok(self.packets.get(cid).cloned())
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        let cids = self.namespace_packets.get(namespace);
        match cids {
            Some(cids) => Ok(cids.iter().filter_map(|c| self.packets.get(c).cloned()).collect()),
            None => Ok(Vec::new()),
        }
    }

    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()> {
        self.packets.remove(cid);
        for cids in self.namespace_packets.values_mut() {
            cids.retain(|c| c != cid);
        }
        Ok(())
    }

    // --- RangeWindows ---
    fn store_window(&mut self, window: &RangeWindow) -> StoreResult<()> {
        self.windows.insert((window.namespace.clone(), window.sn), window.clone());
        Ok(())
    }

    fn load_window(&self, namespace: &str, sn: u64) -> StoreResult<Option<RangeWindow>> {
        Ok(self.windows.get(&(namespace.to_string(), sn)).cloned())
    }

    fn load_windows(&self, namespace: &str) -> StoreResult<Vec<RangeWindow>> {
        Ok(self.windows
            .range((namespace.to_string(), 0)..=(namespace.to_string(), u64::MAX))
            .map(|(_, w)| w.clone())
            .collect())
    }

    // --- StateVectors ---
    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> {
        self.state_vectors.insert((sv.agent_pid.clone(), sv.sn), sv.clone());
        Ok(())
    }

    fn load_state_vector(&self, agent_pid: &str, sn: u64) -> StoreResult<Option<StateVector>> {
        Ok(self.state_vectors.get(&(agent_pid.to_string(), sn)).cloned())
    }

    fn load_state_vectors(&self, agent_pid: &str) -> StoreResult<Vec<StateVector>> {
        Ok(self.state_vectors
            .range((agent_pid.to_string(), 0)..=(agent_pid.to_string(), u64::MAX))
            .map(|(_, sv)| sv.clone())
            .collect())
    }

    // --- InterferenceEdges ---
    fn store_interference_edge(&mut self, ie: &IEdge) -> StoreResult<()> {
        // D2 FIX: Store under agent_pid key so load_interference_edges(agent_pid) works.
        // Previously stored under "ie:{from_sn}:{to_sn}" which never matched the load key.
        let key = ie.agent_pid.clone();
        self.interference_edges.entry(key).or_default().push(ie.clone());
        Ok(())
    }

    fn load_interference_edges(&self, agent_pid: &str) -> StoreResult<Vec<IEdge>> {
        Ok(self.interference_edges.get(agent_pid).cloned().unwrap_or_default())
    }

    // --- Audit ---
    fn store_audit_entry(&mut self, entry: &KernelAuditEntry) -> StoreResult<()> {
        self.audit_entries.push(entry.clone());
        Ok(())
    }

    fn load_audit_entries(&self, from_ms: i64, to_ms: i64) -> StoreResult<Vec<KernelAuditEntry>> {
        Ok(self.audit_entries
            .iter()
            .filter(|e| e.timestamp >= from_ms && e.timestamp <= to_ms)
            .cloned()
            .collect())
    }

    fn load_audit_entries_by_agent(&self, agent_pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>> {
        // D9 FIX: Return newest entries first (rev iterator), not oldest.
        // Audit queries almost always want the most recent entries.
        let mut entries: Vec<KernelAuditEntry> = self.audit_entries
            .iter()
            .rev()
            .filter(|e| e.agent_pid == agent_pid)
            .take(limit)
            .cloned()
            .collect();
        entries.reverse(); // Restore chronological order within the result
        Ok(entries)
    }

    // --- SCITT Receipts ---
    fn store_scitt_receipt(&mut self, receipt: &ScittReceipt) -> StoreResult<()> {
        self.scitt_receipts.insert(receipt.statement_id.clone(), receipt.clone());
        Ok(())
    }

    fn load_scitt_receipt(&self, statement_id: &str) -> StoreResult<Option<ScittReceipt>> {
        Ok(self.scitt_receipts.get(statement_id).cloned())
    }

    // --- Agents ---
    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> {
        self.agents.insert(acb.agent_pid.clone(), acb.clone());
        Ok(())
    }

    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> {
        Ok(self.agents.get(pid).cloned())
    }

    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> {
        Ok(self.agents.values().cloned().collect())
    }

    // --- Sessions ---
    fn store_session(&mut self, session: &SessionEnvelope) -> StoreResult<()> {
        self.sessions.insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    fn load_session(&self, session_id: &str) -> StoreResult<Option<SessionEnvelope>> {
        Ok(self.sessions.get(session_id).cloned())
    }

    // --- Ports ---
    fn store_port(&mut self, port: &Port) -> StoreResult<()> {
        self.ports.insert(port.port_id.clone(), port.clone());
        Ok(())
    }

    fn load_port(&self, port_id: &str) -> StoreResult<Option<Port>> {
        Ok(self.ports.get(port_id).cloned())
    }

    fn load_ports_by_owner(&self, owner_pid: &str) -> StoreResult<Vec<Port>> {
        Ok(self.ports.values().filter(|p| p.owner_pid == owner_pid).cloned().collect())
    }

    // --- Execution Policies ---
    fn store_execution_policy(&mut self, policy: &ExecutionPolicy) -> StoreResult<()> {
        let key = format!("{:?}", policy.role);
        self.execution_policies.insert(key, policy.clone());
        Ok(())
    }

    fn load_execution_policy(&self, role: &AgentRole) -> StoreResult<Option<ExecutionPolicy>> {
        let key = format!("{:?}", role);
        Ok(self.execution_policies.get(&key).cloned())
    }

    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> {
        Ok(self.execution_policies.values().cloned().collect())
    }

    // --- Delegation Chains ---
    fn store_delegation_chain(&mut self, chain: &DelegationChain) -> StoreResult<()> {
        self.delegation_chains.insert(chain.chain_cid.clone(), chain.clone());
        Ok(())
    }

    fn load_delegation_chain(&self, chain_cid: &str) -> StoreResult<Option<DelegationChain>> {
        Ok(self.delegation_chains.get(chain_cid).cloned())
    }

    fn load_delegation_chains_by_subject(&self, subject: &str) -> StoreResult<Vec<DelegationChain>> {
        Ok(self.delegation_chains.values()
            .filter(|c| c.proofs.last().map(|p| p.subject.as_str()) == Some(subject))
            .cloned()
            .collect())
    }

    // --- WAL ---
    fn store_wal(&mut self, namespace: &str, entries: &[crate::range_window::WalEntry]) -> StoreResult<()> {
        self.wal_entries.insert(namespace.to_string(), entries.to_vec());
        Ok(())
    }

    fn load_wal(&self, namespace: &str) -> StoreResult<Vec<crate::range_window::WalEntry>> {
        Ok(self.wal_entries.get(namespace).cloned().unwrap_or_default())
    }

    fn clear_wal(&mut self, namespace: &str) -> StoreResult<()> {
        self.wal_entries.remove(namespace);
        Ok(())
    }

    // --- Bulk loaders ---
    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> {
        Ok(self.sessions.values().cloned().collect())
    }

    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        Ok(self.packets.values().cloned().collect())
    }
}

// =============================================================================
// ProllyBridge — adapter for Prolly tree storage
// =============================================================================

/// Configuration for connecting to a Prolly tree backend.
///
/// The Prolly tree stores MemPackets indexed by structured keys
/// (namespace/type/timestamp/cid) for efficient range queries.
/// This bridge wraps the async `ProllyTree<NodeStore>` for synchronous use.
#[derive(Debug, Clone)]
pub struct ProllyConfig {
    /// Key prefix for packet storage
    pub packet_prefix: String,
    /// Key prefix for window storage
    pub window_prefix: String,
    /// Key prefix for state vector storage
    pub sv_prefix: String,
}

impl Default for ProllyConfig {
    fn default() -> Self {
        Self {
            packet_prefix: "pkt".to_string(),
            window_prefix: "rw".to_string(),
            sv_prefix: "sv".to_string(),
        }
    }
}

/// Build a Prolly tree key for a MemPacket.
///
/// Format: `{prefix}/{namespace}/{packet_type}/{timestamp}/{cid}`
/// This enables efficient range scans by namespace, type, and time.
pub fn build_packet_prolly_key(
    prefix: &str,
    namespace: &str,
    packet_type: &PacketType,
    timestamp: i64,
    cid: &Cid,
) -> Vec<u8> {
    format!("{}/{}/{}/{:020}/{}", prefix, namespace, packet_type, timestamp, cid)
        .into_bytes()
}

/// Build a Prolly tree key for a RangeWindow.
///
/// Format: `{prefix}/{namespace}/{sn:010}`
pub fn build_window_prolly_key(prefix: &str, namespace: &str, sn: u64) -> Vec<u8> {
    format!("{}/{}/{:010}", prefix, namespace, sn).into_bytes()
}

/// Build a Prolly tree key for a StateVector.
///
/// Format: `{prefix}/{agent_pid}/{sn:010}`
pub fn build_sv_prolly_key(prefix: &str, agent_pid: &str, sn: u64) -> Vec<u8> {
    format!("{}/{}/{:010}", prefix, agent_pid, sn).into_bytes()
}

// =============================================================================
// Tier 3: Encryption at rest — EncryptedStore wrapper
// =============================================================================

/// HMAC-SHA256 for audit log signing and encryption key derivation.
/// Uses the existing `sha2` crate — no new dependencies.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    // HMAC: H((K ^ opad) || H((K ^ ipad) || message))
    let mut k = [0u8; 64];
    if key.len() <= 64 {
        k[..key.len()].copy_from_slice(key);
    } else {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let h: [u8; 32] = hasher.finalize().into();
        k[..32].copy_from_slice(&h);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

/// Derive a keystream block from a key and counter using SHA256.
fn derive_keystream(key: &[u8; 32], counter: u64) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(&counter.to_le_bytes());
    hasher.finalize().into()
}

/// XOR-based stream cipher using SHA256-CTR mode.
/// Encrypts/decrypts data in-place using a 256-bit key.
pub fn xor_cipher(key: &[u8; 32], data: &mut [u8]) {
    let mut counter = 0u64;
    let mut offset = 0;
    while offset < data.len() {
        let block = derive_keystream(key, counter);
        let remaining = data.len() - offset;
        let chunk = remaining.min(32);
        for i in 0..chunk {
            data[offset + i] ^= block[i];
        }
        offset += chunk;
        counter += 1;
    }
}

/// An encrypting wrapper around any `KernelStore`.
///
/// Tier 3: All data is encrypted before writing to the inner store and
/// decrypted after reading. Uses SHA256-CTR stream cipher (symmetric).
/// The key must be 32 bytes (256 bits).
///
/// For production use, replace with AES-256-GCM (requires `aes-gcm` crate).
/// This implementation provides confidentiality without authentication —
/// use HMAC verification on audit entries for tamper detection.
pub struct EncryptedStore<S: KernelStore> {
    inner: S,
    key: [u8; 32],
}

impl<S: KernelStore> EncryptedStore<S> {
    /// Create a new encrypted store wrapper.
    pub fn new(inner: S, key: [u8; 32]) -> Self {
        Self { inner, key }
    }

    /// Get a reference to the inner store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut encrypted = data.to_vec();
        xor_cipher(&self.key, &mut encrypted);
        encrypted
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        // XOR cipher is symmetric — encrypt == decrypt
        self.encrypt(data)
    }

    fn encrypt_packet(&self, packet: &MemPacket) -> MemPacket {
        let mut p = packet.clone();
        // Encrypt the payload (the sensitive content)
        let payload_bytes = serde_json::to_vec(&p.content.payload).unwrap_or_default();
        let encrypted = self.encrypt(&payload_bytes);
        p.content.payload = serde_json::json!({
            "__encrypted": true,
            "__data": crate::types::hex_encode(&encrypted),
        });
        p
    }

    fn decrypt_packet(&self, packet: &MemPacket) -> MemPacket {
        let mut p = packet.clone();
        if let Some(true) = p.content.payload.get("__encrypted").and_then(|v| v.as_bool()) {
            if let Some(hex_data) = p.content.payload.get("__data").and_then(|v| v.as_str()) {
                if let Ok(encrypted_bytes) = crate::types::hex_decode(hex_data) {
                    let decrypted = self.decrypt(&encrypted_bytes);
                    if let Ok(original) = serde_json::from_slice(&decrypted) {
                        p.content.payload = original;
                    }
                }
            }
        }
        p
    }
}

impl<S: KernelStore> KernelStore for EncryptedStore<S> {
    fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
        let encrypted = self.encrypt_packet(packet);
        self.inner.store_packet(&encrypted)
    }

    fn load_packet(&self, cid: &Cid) -> StoreResult<Option<MemPacket>> {
        match self.inner.load_packet(cid)? {
            Some(p) => Ok(Some(self.decrypt_packet(&p))),
            None => Ok(None),
        }
    }

    fn load_packets_by_namespace(&self, namespace: &str) -> StoreResult<Vec<MemPacket>> {
        let packets = self.inner.load_packets_by_namespace(namespace)?;
        Ok(packets.iter().map(|p| self.decrypt_packet(p)).collect())
    }

    fn delete_packet(&mut self, cid: &Cid) -> StoreResult<()> {
        self.inner.delete_packet(cid)
    }

    // Delegate non-sensitive operations directly
    fn store_window(&mut self, w: &RangeWindow) -> StoreResult<()> { self.inner.store_window(w) }
    fn load_window(&self, ns: &str, sn: u64) -> StoreResult<Option<RangeWindow>> { self.inner.load_window(ns, sn) }
    fn load_windows(&self, ns: &str) -> StoreResult<Vec<RangeWindow>> { self.inner.load_windows(ns) }
    fn store_state_vector(&mut self, sv: &StateVector) -> StoreResult<()> { self.inner.store_state_vector(sv) }
    fn load_state_vector(&self, pid: &str, sn: u64) -> StoreResult<Option<StateVector>> { self.inner.load_state_vector(pid, sn) }
    fn load_state_vectors(&self, pid: &str) -> StoreResult<Vec<StateVector>> { self.inner.load_state_vectors(pid) }
    fn store_interference_edge(&mut self, ie: &IEdge) -> StoreResult<()> { self.inner.store_interference_edge(ie) }
    fn load_interference_edges(&self, pid: &str) -> StoreResult<Vec<IEdge>> { self.inner.load_interference_edges(pid) }
    fn store_audit_entry(&mut self, e: &KernelAuditEntry) -> StoreResult<()> { self.inner.store_audit_entry(e) }
    fn load_audit_entries(&self, from: i64, to: i64) -> StoreResult<Vec<KernelAuditEntry>> { self.inner.load_audit_entries(from, to) }
    fn load_audit_entries_by_agent(&self, pid: &str, limit: usize) -> StoreResult<Vec<KernelAuditEntry>> { self.inner.load_audit_entries_by_agent(pid, limit) }
    fn store_scitt_receipt(&mut self, r: &ScittReceipt) -> StoreResult<()> { self.inner.store_scitt_receipt(r) }
    fn load_scitt_receipt(&self, id: &str) -> StoreResult<Option<ScittReceipt>> { self.inner.load_scitt_receipt(id) }
    fn store_agent(&mut self, acb: &AgentControlBlock) -> StoreResult<()> { self.inner.store_agent(acb) }
    fn load_agent(&self, pid: &str) -> StoreResult<Option<AgentControlBlock>> { self.inner.load_agent(pid) }
    fn load_all_agents(&self) -> StoreResult<Vec<AgentControlBlock>> { self.inner.load_all_agents() }
    fn store_session(&mut self, s: &SessionEnvelope) -> StoreResult<()> { self.inner.store_session(s) }
    fn load_session(&self, id: &str) -> StoreResult<Option<SessionEnvelope>> { self.inner.load_session(id) }
    fn store_port(&mut self, p: &Port) -> StoreResult<()> { self.inner.store_port(p) }
    fn load_port(&self, id: &str) -> StoreResult<Option<Port>> { self.inner.load_port(id) }
    fn load_ports_by_owner(&self, pid: &str) -> StoreResult<Vec<Port>> { self.inner.load_ports_by_owner(pid) }
    fn store_execution_policy(&mut self, p: &ExecutionPolicy) -> StoreResult<()> { self.inner.store_execution_policy(p) }
    fn load_execution_policy(&self, r: &AgentRole) -> StoreResult<Option<ExecutionPolicy>> { self.inner.load_execution_policy(r) }
    fn load_all_policies(&self) -> StoreResult<Vec<ExecutionPolicy>> { self.inner.load_all_policies() }
    fn store_delegation_chain(&mut self, c: &DelegationChain) -> StoreResult<()> { self.inner.store_delegation_chain(c) }
    fn load_delegation_chain(&self, id: &str) -> StoreResult<Option<DelegationChain>> { self.inner.load_delegation_chain(id) }
    fn load_delegation_chains_by_subject(&self, s: &str) -> StoreResult<Vec<DelegationChain>> { self.inner.load_delegation_chains_by_subject(s) }
    fn store_wal(&mut self, ns: &str, entries: &[crate::range_window::WalEntry]) -> StoreResult<()> { self.inner.store_wal(ns, entries) }
    fn load_wal(&self, ns: &str) -> StoreResult<Vec<crate::range_window::WalEntry>> { self.inner.load_wal(ns) }
    fn clear_wal(&mut self, ns: &str) -> StoreResult<()> { self.inner.clear_wal(ns) }
    fn load_all_sessions(&self) -> StoreResult<Vec<SessionEnvelope>> { self.inner.load_all_sessions() }
    fn load_all_packets(&self) -> StoreResult<Vec<MemPacket>> {
        let packets = self.inner.load_all_packets()?;
        Ok(packets.iter().map(|p| self.decrypt_packet(p)).collect())
    }
}

// =============================================================================
// Tier 3: Audit log HMAC signing for tamper detection
// =============================================================================

/// Compute an HMAC-SHA256 signature for a KernelAuditEntry.
///
/// The signature covers: audit_id, timestamp, operation, agent_pid, outcome.
/// This creates a chain where each entry's HMAC includes the previous entry's
/// HMAC, forming a hash chain that detects any insertion, deletion, or modification.
pub fn sign_audit_entry(entry: &KernelAuditEntry, key: &[u8; 32], prev_hmac: &[u8; 32]) -> [u8; 32] {
    let canonical = format!(
        "{}|{}|{:?}|{}|{:?}|{}",
        entry.audit_id,
        entry.timestamp,
        entry.operation,
        entry.agent_pid,
        entry.outcome,
        hex::encode(prev_hmac),
    );
    hmac_sha256(key, canonical.as_bytes())
}

/// Verify an audit log chain — each entry's HMAC must match the recomputed value.
///
/// Returns a list of (index, error_message) for any entries that fail verification.
pub fn verify_audit_chain(
    entries: &[KernelAuditEntry],
    key: &[u8; 32],
    hmacs: &[[u8; 32]],
) -> Vec<(usize, String)> {
    let mut errors = Vec::new();
    if entries.len() != hmacs.len() {
        errors.push((0, format!("Entry count {} != HMAC count {}", entries.len(), hmacs.len())));
        return errors;
    }

    let mut prev_hmac = [0u8; 32];
    for (i, entry) in entries.iter().enumerate() {
        let expected = sign_audit_entry(entry, key, &prev_hmac);
        if expected != hmacs[i] {
            errors.push((i, format!("Audit entry {} HMAC mismatch at index {}", entry.audit_id, i)));
        }
        prev_hmac = hmacs[i];
    }

    errors
}

// hex module for HMAC chain (minimal, no extra dep)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// =============================================================================
// Snapshot / Restore — serialize entire kernel state
// =============================================================================

/// A serializable snapshot of the entire kernel + runtime state.
/// Used for checkpointing, backup, and migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSnapshot {
    /// Snapshot version
    pub version: u32,
    /// When this snapshot was taken
    pub created_at: i64,
    /// All agents
    pub agents: Vec<AgentControlBlock>,
    /// All sessions
    pub sessions: Vec<SessionEnvelope>,
    /// All committed windows (namespace, sn, window)
    pub windows: Vec<RangeWindow>,
    /// All state vectors
    pub state_vectors: Vec<StateVector>,
    /// Audit entry count (entries themselves may be too large to snapshot)
    pub audit_entry_count: u64,
    /// Total packet count
    pub packet_count: u64,
}

impl KernelSnapshot {
    /// Create a snapshot from an InMemoryKernelStore
    pub fn from_store(store: &InMemoryKernelStore) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            version: 1,
            created_at: now,
            agents: store.agents.values().cloned().collect(),
            sessions: store.sessions.values().cloned().collect(),
            windows: store.windows.values().cloned().collect(),
            state_vectors: store.state_vectors.values().cloned().collect(),
            audit_entry_count: store.audit_entries.len() as u64,
            packet_count: store.packets.len() as u64,
        }
    }

    /// Restore into an InMemoryKernelStore
    pub fn restore(&self) -> InMemoryKernelStore {
        let mut store = InMemoryKernelStore::new();

        for acb in &self.agents {
            store.agents.insert(acb.agent_pid.clone(), acb.clone());
        }

        for session in &self.sessions {
            store.sessions.insert(session.session_id.clone(), session.clone());
        }

        for window in &self.windows {
            store.windows.insert((window.namespace.clone(), window.sn), window.clone());
        }

        for sv in &self.state_vectors {
            store.state_vectors.insert((sv.agent_pid.clone(), sv.sn), sv.clone());
        }

        store
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_store_and_load_packet() {
        let mut store = InMemoryKernelStore::new();
        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();

        let loaded = store.load_packet(&cid).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().content.entities, vec!["alice".to_string()]);
    }

    #[test]
    fn test_load_packets_by_namespace() {
        let mut store = InMemoryKernelStore::new();

        store.store_packet(&make_packet(&["alice"], 1000)).unwrap();
        store.store_packet(&make_packet(&["bob"], 2000)).unwrap();

        let packets = store.load_packets_by_namespace("ns:test").unwrap();
        assert_eq!(packets.len(), 2);

        let empty = store.load_packets_by_namespace("ns:other").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_delete_packet() {
        let mut store = InMemoryKernelStore::new();
        let packet = make_packet(&["alice"], 1000);
        let cid = packet.index.packet_cid.clone();

        store.store_packet(&packet).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_some());

        store.delete_packet(&cid).unwrap();
        assert!(store.load_packet(&cid).unwrap().is_none());
    }

    #[test]
    fn test_store_and_load_window() {
        let mut store = InMemoryKernelStore::new();

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
            boundary_reason: crate::range_window::BoundaryReason::PacketLimit,
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

    #[test]
    fn test_store_and_load_audit() {
        let mut store = InMemoryKernelStore::new();

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
            severity: TelemetrySeverity::Info,
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

    #[test]
    fn test_store_and_load_agent() {
        let mut store = InMemoryKernelStore::new();

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
            agent_priority: AgentPriority::Normal,
            token_budget: None,
        };

        store.store_agent(&acb).unwrap();

        let loaded = store.load_agent("pid:001").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().agent_name, "bot");

        let all = store.load_all_agents().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_store_and_load_session() {
        let mut store = InMemoryKernelStore::new();

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

    #[test]
    fn test_prolly_key_builders() {
        let cid = Cid::default();

        let pkt_key = build_packet_prolly_key("pkt", "ns:test", &PacketType::Extraction, 1000, &cid);
        let key_str = String::from_utf8(pkt_key).unwrap();
        assert!(key_str.starts_with("pkt/ns:test/extraction/"));
        assert!(key_str.contains("00000000000000001000"));

        let rw_key = build_window_prolly_key("rw", "ns:test", 42);
        let key_str = String::from_utf8(rw_key).unwrap();
        assert_eq!(key_str, "rw/ns:test/0000000042");

        let sv_key = build_sv_prolly_key("sv", "pid:001", 7);
        let key_str = String::from_utf8(sv_key).unwrap();
        assert_eq!(key_str, "sv/pid:001/0000000007");
    }

    #[test]
    fn test_kernel_snapshot_roundtrip() {
        let mut store = InMemoryKernelStore::new();

        // Populate store
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
            agent_priority: AgentPriority::Normal,
            token_budget: None,
        };
        store.store_agent(&acb).unwrap();

        let session = SessionEnvelope {
            type_: "session".to_string(),
            version: 1,
            session_id: "sess:001".to_string(),
            agent_id: "pid:001".to_string(),
            namespace: "ns:test".to_string(),
            label: Some("test".to_string()),
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

        // Snapshot
        let snapshot = KernelSnapshot::from_store(&store);
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.agents.len(), 1);
        assert_eq!(snapshot.sessions.len(), 1);

        // Serialize → deserialize
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored_snapshot: KernelSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored_snapshot.agents.len(), 1);

        // Restore into new store
        let restored_store = restored_snapshot.restore();
        assert!(restored_store.load_agent("pid:001").unwrap().is_some());
        assert!(restored_store.load_session("sess:001").unwrap().is_some());
    }

    #[test]
    fn test_total_objects() {
        let mut store = InMemoryKernelStore::new();
        assert_eq!(store.total_objects(), 0);

        store.store_packet(&make_packet(&["alice"], 1000)).unwrap();
        assert!(store.total_objects() > 0);
    }

    #[test]
    fn test_tier3_encrypted_store_roundtrip() {
        // Tier 3: EncryptedStore must encrypt payloads and decrypt on read
        let inner = InMemoryKernelStore::new();
        let key = [0xABu8; 32];
        let mut enc_store = EncryptedStore::new(inner, key);

        let original_payload = serde_json::json!({"diagnosis": "flu", "patient": "P001"});
        let packet = MemPacket::new(
            PacketType::Extraction,
            original_payload.clone(),
            Cid::default(),
            "subject:enc".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            1000,
        ).with_namespace("ns:enc".to_string());
        let cid = packet.index.packet_cid.clone();

        enc_store.store_packet(&packet).unwrap();

        // Inner store should have encrypted payload (not the original)
        let raw = enc_store.inner().load_packet(&cid).unwrap().unwrap();
        assert!(raw.content.payload.get("__encrypted").is_some(),
            "Tier3: Inner store must have encrypted payload marker");
        assert_ne!(raw.content.payload, original_payload,
            "Tier3: Inner store payload must NOT be plaintext");

        // Reading through EncryptedStore should decrypt
        let decrypted = enc_store.load_packet(&cid).unwrap().unwrap();
        assert_eq!(decrypted.content.payload, original_payload,
            "Tier3: Decrypted payload must match original");

        // load_packets_by_namespace should also decrypt
        let ns_packets = enc_store.load_packets_by_namespace("ns:enc").unwrap();
        assert_eq!(ns_packets.len(), 1);
        assert_eq!(ns_packets[0].content.payload, original_payload);
    }

    #[test]
    fn test_tier3_wrong_key_fails_decrypt() {
        // Tier 3: Wrong key must not produce correct plaintext
        let inner = InMemoryKernelStore::new();
        let key = [0xABu8; 32];
        let mut enc_store = EncryptedStore::new(inner, key);

        let original = serde_json::json!({"secret": "data"});
        let packet = MemPacket::new(
            PacketType::Extraction,
            original.clone(),
            Cid::default(),
            "subject:wrongkey".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            2000,
        ).with_namespace("ns:wrongkey".to_string());
        let cid = packet.index.packet_cid.clone();

        enc_store.store_packet(&packet).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = [0xCDu8; 32];
        let wrong_store = EncryptedStore::new(InMemoryKernelStore::new(), wrong_key);
        // Load the raw encrypted packet from the original inner store
        let raw = enc_store.inner().load_packet(&cid).unwrap().unwrap();
        let bad_decrypt = wrong_store.decrypt_packet(&raw);
        // The decrypted payload should NOT match original (garbled or still encrypted)
        assert_ne!(bad_decrypt.content.payload, original,
            "Tier3: Wrong key must not produce correct plaintext");
    }

    #[test]
    fn test_tier3_audit_hmac_chain() {
        // Tier 3: Audit HMAC chain must verify valid entries and detect tampering
        let key = [0x42u8; 32];

        let entries: Vec<KernelAuditEntry> = (0..5).map(|i| KernelAuditEntry {
            audit_id: format!("audit:{:04}", i),
            timestamp: 1000 + i as i64,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:000001".to_string(),
            target: None,
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: None,
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
            natural_language: None,
            business_impact: None,
            remediation_hint: None,
            causal_chain: Vec::new(),
            severity: TelemetrySeverity::Info,
            gen_ai_attrs: None,
        }).collect();

        // Sign the chain
        let mut hmacs = Vec::new();
        let mut prev = [0u8; 32];
        for entry in &entries {
            let h = sign_audit_entry(entry, &key, &prev);
            hmacs.push(h);
            prev = h;
        }

        // Verify valid chain
        let errors = verify_audit_chain(&entries, &key, &hmacs);
        assert!(errors.is_empty(), "Tier3: Valid audit chain must verify, got: {:?}", errors);

        // Tamper with an entry
        let mut tampered = entries.clone();
        tampered[2].agent_pid = "pid:HACKER".to_string();
        let errors = verify_audit_chain(&tampered, &key, &hmacs);
        assert!(!errors.is_empty(), "Tier3: Tampered audit chain must fail verification");
        assert!(errors.iter().any(|(i, _)| *i == 2), "Tier3: Tampered entry at index 2 must be detected");
    }

    #[test]
    fn test_tier3_audit_hmac_detects_deletion() {
        // Tier 3: Deleting an entry from the chain must break verification
        let key = [0x99u8; 32];

        let entries: Vec<KernelAuditEntry> = (0..3).map(|i| KernelAuditEntry {
            audit_id: format!("audit:{:04}", i),
            timestamp: 1000 + i as i64,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:000001".to_string(),
            target: None,
            outcome: OpOutcome::Success,
            reason: None,
            error: None,
            duration_us: None,
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
            natural_language: None,
            business_impact: None,
            remediation_hint: None,
            causal_chain: Vec::new(),
            severity: TelemetrySeverity::Info,
            gen_ai_attrs: None,
        }).collect();

        let mut hmacs = Vec::new();
        let mut prev = [0u8; 32];
        for entry in &entries {
            let h = sign_audit_entry(entry, &key, &prev);
            hmacs.push(h);
            prev = h;
        }

        // Delete middle entry
        let shortened_entries = vec![entries[0].clone(), entries[2].clone()];
        let shortened_hmacs = vec![hmacs[0], hmacs[2]];
        let errors = verify_audit_chain(&shortened_entries, &key, &shortened_hmacs);
        assert!(!errors.is_empty(), "Tier3: Deleted entry must break chain verification");
    }
}
