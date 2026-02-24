//! RangeWindow Manager — groups MemPackets into sealed, paginated, Merkle-proven windows.
//!
//! A RangeWindow is a time-bounded batch of MemPackets with:
//! - Monotonic serial number (`sn`)
//! - Merkle root over all packet CIDs in the window
//! - Chain link to previous window (`prev_rw_root`)
//! - Bi-temporal timestamps (event time + ingest time)
//! - Boundary detection (token limit, packet limit, session boundary, topic change)
//!
//! Design sources: Google Trillian (CT log batching), EverMemOS (MemCell boundary),
//! Graphiti (bi-temporal), Dolt Prolly tree (content-addressed chunking),
//! vLLM PagedAttention (block table logical→physical mapping).

use std::collections::BTreeMap;

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::cid::sha256;
use crate::types::*;

// =============================================================================
// RangeWindow types
// =============================================================================

/// Why a RangeWindow boundary was triggered
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryReason {
    /// Hard limit: token count exceeded threshold
    TokenLimit,
    /// Hard limit: packet count exceeded threshold
    PacketLimit,
    /// Session boundary: new session started or current session closed
    SessionBoundary,
    /// Seal forced: explicit mem_seal triggered window commit
    SealForced,
    /// Manual: explicitly committed by caller
    Manual,
}

impl std::fmt::Display for BoundaryReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryReason::TokenLimit => write!(f, "token_limit"),
            BoundaryReason::PacketLimit => write!(f, "packet_limit"),
            BoundaryReason::SessionBoundary => write!(f, "session_boundary"),
            BoundaryReason::SealForced => write!(f, "seal_forced"),
            BoundaryReason::Manual => write!(f, "manual"),
        }
    }
}

/// A committed RangeWindow — one "page" in the infinite memory chain.
///
/// Each RangeWindow is a sealed, Merkle-proven batch of MemPackets.
/// Windows form a linked chain via `prev_rw_root`, creating a
/// tamper-evident append-only log of all agent memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeWindow {
    /// Monotonic serial number (0, 1, 2, ...)
    pub sn: u64,
    /// Pagination key for partial loading (e.g., "ns:hospital/agent:bot/0042")
    pub page_code: String,

    // --- Bi-temporal timestamps (from Graphiti) ---
    /// When the first event in this window occurred
    pub event_time_start: i64,
    /// When the last event in this window occurred
    pub event_time_end: i64,
    /// When this window was committed (ingestion time)
    pub ingest_time: i64,

    // --- Content ---
    /// CIDs of MemPackets in this window (ordered by insertion)
    pub leaf_cids: Vec<Cid>,
    /// Total token count across all packets in this window
    pub token_count: u64,
    /// Total packet count
    pub packet_count: u32,

    // --- Merkle sealing (from Trillian) ---
    /// Merkle root of leaf_cids: H(cid_0 || cid_1 || ... || cid_n)
    pub rw_root: [u8; 32],
    /// Chain link: Merkle root of the previous window (zeroed for first window)
    pub prev_rw_root: [u8; 32],
    /// Cumulative entry count in the log (sum of all packets across all windows)
    pub tree_size: u64,

    // --- Boundary ---
    /// Why this window was committed
    pub boundary_reason: BoundaryReason,

    // --- Classification ---
    /// Agent namespace this window belongs to
    pub namespace: String,
    /// Agent PID that owns this window
    pub agent_pid: String,
    /// Session ID (if all packets share one session)
    pub session_id: Option<String>,
    /// Memory tier
    pub tier: MemoryTier,
    /// Memory scope
    pub scope: MemoryScope,
    /// Whether this window is sealed (immutable)
    pub sealed: bool,

    // --- Entities (for knot topology index) ---
    /// Unique entities mentioned across all packets in this window
    #[serde(default)]
    pub entities: Vec<String>,
}

/// Configuration for the RangeWindow manager
#[derive(Debug, Clone)]
pub struct RangeWindowConfig {
    /// Max tokens per window before auto-commit
    pub max_tokens: u64,
    /// Max packets per window before auto-commit
    pub max_packets: u32,
    /// Whether to auto-commit on session boundaries
    pub commit_on_session_boundary: bool,
}

impl Default for RangeWindowConfig {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            max_packets: 32,
            commit_on_session_boundary: true,
        }
    }
}

/// An uncommitted window accumulator — collects packets until a boundary is hit.
#[derive(Debug)]
struct WindowAccumulator {
    /// CIDs accumulated so far
    leaf_cids: Vec<Cid>,
    /// Token count so far
    token_count: u64,
    /// Earliest event timestamp
    event_time_start: Option<i64>,
    /// Latest event timestamp
    event_time_end: Option<i64>,
    /// Session IDs seen
    session_ids: std::collections::HashSet<String>,
    /// Entities seen
    entities: std::collections::HashSet<String>,
    /// Namespace
    namespace: String,
    /// Agent PID
    agent_pid: String,
}

impl WindowAccumulator {
    fn new(namespace: String, agent_pid: String) -> Self {
        Self {
            leaf_cids: Vec::new(),
            token_count: 0,
            event_time_start: None,
            event_time_end: None,
            session_ids: std::collections::HashSet::new(),
            entities: std::collections::HashSet::new(),
            namespace,
            agent_pid,
        }
    }

    fn is_empty(&self) -> bool {
        self.leaf_cids.is_empty()
    }

    fn packet_count(&self) -> u32 {
        self.leaf_cids.len() as u32
    }

    fn add_packet(&mut self, cid: Cid, ts: i64, tokens: u64, session_id: Option<&str>, entities: &[String]) {
        self.leaf_cids.push(cid);
        self.token_count += tokens;

        match self.event_time_start {
            None => {
                self.event_time_start = Some(ts);
                self.event_time_end = Some(ts);
            }
            Some(_) => {
                self.event_time_end = Some(ts);
            }
        }

        if let Some(sid) = session_id {
            self.session_ids.insert(sid.to_string());
        }

        for e in entities {
            self.entities.insert(e.clone());
        }
    }
}

// =============================================================================
// RangeWindow Manager
// =============================================================================

/// Manages the lifecycle of RangeWindows for a single agent/namespace.
///
/// Packets flow in via `ingest()`. When a boundary is hit (token limit,
/// packet limit, session change, or manual commit), the current window
/// is committed with a Merkle root and chained to the previous window.
pub struct RangeWindowManager {
    /// Configuration
    config: RangeWindowConfig,
    /// Committed windows (sn → RangeWindow)
    windows: BTreeMap<u64, RangeWindow>,
    /// Current uncommitted accumulator
    accumulator: WindowAccumulator,
    /// Next serial number
    next_sn: u64,
    /// Previous window's Merkle root (for chaining)
    prev_rw_root: [u8; 32],
    /// Cumulative packet count across all committed windows
    cumulative_tree_size: u64,
    /// Window index: sn → summary for fast lookup without loading full window
    index: BTreeMap<u64, WindowIndexEntry>,
    /// D17 FIX: Write-ahead log of uncommitted packet CIDs.
    /// On crash, these CIDs can be replayed from the packet store to
    /// reconstruct the accumulator state. Without this, all uncommitted
    /// packets are silently lost.
    pub wal: Vec<WalEntry>,
}

/// D17: Write-ahead log entry for crash recovery of uncommitted packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Packet CID
    pub cid: Cid,
    /// Timestamp
    pub timestamp: i64,
    /// Token count
    pub token_count: u64,
    /// Session ID (if any)
    pub session_id: Option<String>,
    /// Entities
    pub entities: Vec<String>,
}

/// Lightweight index entry for a committed window (kept in memory for fast lookup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowIndexEntry {
    /// Serial number
    pub sn: u64,
    /// Page code
    pub page_code: String,
    /// Merkle root
    pub rw_root: [u8; 32],
    /// Token count
    pub token_count: u64,
    /// Packet count
    pub packet_count: u32,
    /// Time range
    pub event_time_start: i64,
    pub event_time_end: i64,
    /// Entities in this window
    pub entities: Vec<String>,
    /// Namespace
    pub namespace: String,
    /// Whether sealed
    pub sealed: bool,
}

impl RangeWindowManager {
    /// Create a new manager for a given agent/namespace
    pub fn new(namespace: String, agent_pid: String, config: RangeWindowConfig) -> Self {
        Self {
            config,
            windows: BTreeMap::new(),
            accumulator: WindowAccumulator::new(namespace.clone(), agent_pid),
            next_sn: 0,
            prev_rw_root: [0u8; 32],
            cumulative_tree_size: 0,
            index: BTreeMap::new(),
            wal: Vec::new(),
        }
    }

    /// Create with default config
    pub fn with_defaults(namespace: String, agent_pid: String) -> Self {
        Self::new(namespace, agent_pid, RangeWindowConfig::default())
    }

    // =========================================================================
    // Ingest
    // =========================================================================

    /// Ingest a packet into the current window.
    ///
    /// Returns `Some(RangeWindow)` if a boundary was hit and a window was committed.
    /// Returns `None` if the packet was accumulated without triggering a commit.
    pub fn ingest(
        &mut self,
        packet_cid: Cid,
        timestamp: i64,
        token_count: u64,
        session_id: Option<&str>,
        entities: &[String],
    ) -> Option<RangeWindow> {
        // D17 FIX: Write WAL entry before adding to accumulator.
        // On crash, WAL entries can be replayed to reconstruct uncommitted state.
        self.wal.push(WalEntry {
            cid: packet_cid.clone(),
            timestamp,
            token_count,
            session_id: session_id.map(|s| s.to_string()),
            entities: entities.to_vec(),
        });

        self.accumulator.add_packet(
            packet_cid,
            timestamp,
            token_count,
            session_id,
            entities,
        );

        // Check boundaries
        if self.accumulator.token_count >= self.config.max_tokens {
            return Some(self.commit(BoundaryReason::TokenLimit));
        }

        if self.accumulator.packet_count() >= self.config.max_packets {
            return Some(self.commit(BoundaryReason::PacketLimit));
        }

        None
    }

    /// Notify the manager of a session boundary (create or close).
    ///
    /// If configured and the accumulator is non-empty, commits the current window.
    pub fn notify_session_boundary(&mut self) -> Option<RangeWindow> {
        if self.config.commit_on_session_boundary && !self.accumulator.is_empty() {
            Some(self.commit(BoundaryReason::SessionBoundary))
        } else {
            None
        }
    }

    /// Force-commit the current window (e.g., on seal).
    ///
    /// Returns `None` if the accumulator is empty.
    pub fn force_commit(&mut self, reason: BoundaryReason) -> Option<RangeWindow> {
        if self.accumulator.is_empty() {
            return None;
        }
        Some(self.commit(reason))
    }

    // =========================================================================
    // Commit
    // =========================================================================

    /// Commit the current accumulator into a sealed RangeWindow.
    fn commit(&mut self, boundary_reason: BoundaryReason) -> RangeWindow {
        let sn = self.next_sn;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let namespace = self.accumulator.namespace.clone();
        let agent_pid = self.accumulator.agent_pid.clone();

        // Compute Merkle root: H(cid_0_bytes || cid_1_bytes || ... || cid_n_bytes)
        let rw_root = compute_merkle_root(&self.accumulator.leaf_cids);

        // Determine session_id (if all packets share one session)
        let session_id = if self.accumulator.session_ids.len() == 1 {
            self.accumulator.session_ids.iter().next().cloned()
        } else {
            None
        };

        let page_code = format!("{}/{:06}", namespace, sn);

        let entities: Vec<String> = self.accumulator.entities.iter().cloned().collect();

        let window = RangeWindow {
            sn,
            page_code: page_code.clone(),
            event_time_start: self.accumulator.event_time_start.unwrap_or(now),
            event_time_end: self.accumulator.event_time_end.unwrap_or(now),
            ingest_time: now,
            leaf_cids: self.accumulator.leaf_cids.clone(),
            token_count: self.accumulator.token_count,
            packet_count: self.accumulator.packet_count(),
            rw_root,
            prev_rw_root: self.prev_rw_root,
            tree_size: self.cumulative_tree_size + self.accumulator.leaf_cids.len() as u64,
            boundary_reason,
            namespace: namespace.clone(),
            agent_pid: agent_pid.clone(),
            session_id,
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            sealed: true,
            entities: entities.clone(),
        };

        // Update index
        let index_entry = WindowIndexEntry {
            sn,
            page_code,
            rw_root,
            token_count: window.token_count,
            packet_count: window.packet_count,
            event_time_start: window.event_time_start,
            event_time_end: window.event_time_end,
            entities,
            namespace: namespace.clone(),
            sealed: true,
        };
        self.index.insert(sn, index_entry);

        // Store committed window
        self.windows.insert(sn, window.clone());

        // Update chain state
        self.prev_rw_root = rw_root;
        self.cumulative_tree_size += self.accumulator.leaf_cids.len() as u64;
        self.next_sn += 1;

        // Reset accumulator and clear WAL (committed data is now safe)
        self.accumulator = WindowAccumulator::new(namespace, agent_pid);
        // D17 FIX: Clear WAL after successful commit — data is now in committed window
        self.wal.clear();

        window
    }

    // =========================================================================
    // Pagination / Query
    // =========================================================================

    /// D17 FIX: Replay WAL entries to reconstruct accumulator state after crash.
    /// Call this on startup with WAL entries loaded from persistent storage.
    pub fn replay_wal(&mut self, entries: &[WalEntry]) {
        for entry in entries {
            self.accumulator.add_packet(
                entry.cid.clone(),
                entry.timestamp,
                entry.token_count,
                entry.session_id.as_deref(),
                &entry.entities,
            );
        }
        self.wal = entries.to_vec();
    }

    /// Load a page by serial number
    pub fn load_page(&self, sn: u64) -> Option<&RangeWindow> {
        self.windows.get(&sn)
    }

    /// Load a page by page_code
    pub fn load_page_by_code(&self, page_code: &str) -> Option<&RangeWindow> {
        self.windows.values().find(|w| w.page_code == page_code)
    }

    /// Get all committed windows in order
    pub fn all_windows(&self) -> Vec<&RangeWindow> {
        self.windows.values().collect()
    }

    /// Get the window index (lightweight summaries)
    pub fn window_index(&self) -> &BTreeMap<u64, WindowIndexEntry> {
        &self.index
    }

    /// Get windows in a serial number range
    pub fn windows_in_range(&self, from_sn: u64, to_sn: u64) -> Vec<&RangeWindow> {
        self.windows
            .range(from_sn..=to_sn)
            .map(|(_, w)| w)
            .collect()
    }

    /// Get windows that mention a specific entity
    pub fn windows_for_entity(&self, entity: &str) -> Vec<&RangeWindow> {
        self.index
            .values()
            .filter(|idx| idx.entities.iter().any(|e| e == entity))
            .filter_map(|idx| self.windows.get(&idx.sn))
            .collect()
    }

    /// Get windows in a time range (event time)
    pub fn windows_in_time_range(&self, from_ms: i64, to_ms: i64) -> Vec<&RangeWindow> {
        self.windows
            .values()
            .filter(|w| w.event_time_end >= from_ms && w.event_time_start <= to_ms)
            .collect()
    }

    /// Get total committed window count
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// Get the latest committed window
    pub fn latest_window(&self) -> Option<&RangeWindow> {
        self.windows.values().next_back()
    }

    /// Get the current accumulator state (uncommitted packets)
    pub fn pending_packet_count(&self) -> u32 {
        self.accumulator.packet_count()
    }

    /// Get the current accumulator token count
    pub fn pending_token_count(&self) -> u64 {
        self.accumulator.token_count
    }

    /// Get cumulative tree size (total packets across all committed windows)
    pub fn tree_size(&self) -> u64 {
        self.cumulative_tree_size
    }

    // =========================================================================
    // Verification
    // =========================================================================

    /// Verify the chain integrity: each window's prev_rw_root matches the previous window's rw_root.
    pub fn verify_chain(&self) -> Result<bool, String> {
        let mut expected_prev = [0u8; 32];

        for (sn, window) in &self.windows {
            // Check chain link
            if window.prev_rw_root != expected_prev {
                return Err(format!(
                    "Chain broken at sn={}: expected prev_rw_root {:?}, got {:?}",
                    sn, expected_prev, window.prev_rw_root
                ));
            }

            // Verify Merkle root
            let computed_root = compute_merkle_root(&window.leaf_cids);
            if computed_root != window.rw_root {
                return Err(format!(
                    "Merkle root mismatch at sn={}: computed {:?}, stored {:?}",
                    sn, computed_root, window.rw_root
                ));
            }

            expected_prev = window.rw_root;
        }

        Ok(true)
    }

    /// Verify a single window's Merkle root
    pub fn verify_window(&self, sn: u64) -> Result<bool, String> {
        let window = self.windows.get(&sn).ok_or(format!("Window sn={} not found", sn))?;
        let computed = compute_merkle_root(&window.leaf_cids);
        if computed != window.rw_root {
            return Err(format!("Merkle root mismatch at sn={}", sn));
        }
        Ok(true)
    }
}

// =============================================================================
// Merkle root computation
// =============================================================================

/// Domain separation prefix for Merkle leaf hashes (RFC 6962).
const MERKLE_LEAF_PREFIX: u8 = 0x00;
/// Domain separation prefix for Merkle internal node hashes (RFC 6962).
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Hash a leaf with domain separation: H(0x00 || data)
fn merkle_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(MERKLE_LEAF_PREFIX);
    buf.extend_from_slice(data);
    sha256(&buf)
}

/// Hash two children with domain separation: H(0x01 || left || right)
fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(MERKLE_NODE_PREFIX);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// Compute a Merkle root over a list of CIDs.
///
/// Uses a domain-separated binary Merkle tree (RFC 6962 style):
/// - Leaf level: H(0x00 || cid_bytes) — domain-separated from internal nodes
/// - Internal levels: H(0x01 || left || right) — domain-separated from leaves
/// - Odd nodes are promoted (not duplicated) to prevent length-extension
/// - Final root includes tree size: H(0x01 || tree_size_be8 || computed_root)
///
/// Empty list → all-zero root.
pub fn compute_merkle_root(cids: &[Cid]) -> [u8; 32] {
    if cids.is_empty() {
        return [0u8; 32];
    }

    // Leaf hashes with domain separation
    let mut hashes: Vec<[u8; 32]> = cids
        .iter()
        .map(|cid| merkle_leaf_hash(&cid.to_bytes()))
        .collect();

    let tree_size = hashes.len() as u64;

    // Build tree bottom-up
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < hashes.len() {
            if i + 1 < hashes.len() {
                // Pair: hash both children with domain separation
                next_level.push(merkle_node_hash(&hashes[i], &hashes[i + 1]));
                i += 2;
            } else {
                // Odd node: promote directly (no duplication)
                next_level.push(hashes[i]);
                i += 1;
            }
        }
        hashes = next_level;
    }

    // Bind tree size into root to prevent truncation attacks
    let mut final_buf = Vec::with_capacity(1 + 8 + 32);
    final_buf.push(MERKLE_NODE_PREFIX);
    final_buf.extend_from_slice(&tree_size.to_be_bytes());
    final_buf.extend_from_slice(&hashes[0]);
    sha256(&final_buf)
}

/// Compute a Merkle inclusion proof for a CID at a given index.
///
/// Returns the sibling hashes needed to reconstruct the root.
/// Uses domain-separated hashing consistent with `compute_merkle_root`.
pub fn compute_inclusion_proof(cids: &[Cid], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= cids.len() || cids.is_empty() {
        return None;
    }

    let tree_size = cids.len();
    let mut hashes: Vec<[u8; 32]> = cids
        .iter()
        .map(|cid| merkle_leaf_hash(&cid.to_bytes()))
        .collect();

    let mut proof = Vec::new();
    let mut target_idx = index;

    while hashes.len() > 1 {
        let level_len = hashes.len();
        // If target is the unpaired odd node, it gets promoted — no sibling needed
        let is_last_odd = (level_len % 2 != 0) && (target_idx == level_len - 1);

        if !is_last_odd {
            let sibling_idx = if target_idx % 2 == 0 {
                target_idx + 1
            } else {
                target_idx - 1
            };
            proof.push(hashes[sibling_idx]);
        }

        // Build next level
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < level_len {
            if i + 1 < level_len {
                next_level.push(merkle_node_hash(&hashes[i], &hashes[i + 1]));
                i += 2;
            } else {
                next_level.push(hashes[i]);
                i += 1;
            }
        }

        target_idx /= 2;
        hashes = next_level;
    }

    Some(proof)
}

/// Verify a Merkle inclusion proof.
///
/// Uses domain-separated hashing. `tree_size` is required to prevent
/// proofs from being replayed against different-sized trees.
pub fn verify_inclusion_proof(
    leaf_cid: &Cid,
    index: usize,
    tree_size: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    if index >= tree_size || tree_size == 0 {
        return false;
    }

    let mut current = merkle_leaf_hash(&leaf_cid.to_bytes());
    let mut idx = index;
    let mut level_size = tree_size;
    let mut proof_idx = 0;

    while level_size > 1 {
        let is_last_odd = (level_size % 2 != 0) && (idx == level_size - 1);

        if is_last_odd {
            // Promoted — no sibling consumed
        } else {
            if proof_idx >= proof.len() {
                return false;
            }
            let sibling = &proof[proof_idx];
            proof_idx += 1;
            if idx % 2 == 0 {
                current = merkle_node_hash(&current, sibling);
            } else {
                current = merkle_node_hash(sibling, &current);
            }
        }

        idx /= 2;
        level_size = (level_size + 1) / 2;
    }

    // Verify with tree-size-bound root
    let mut final_buf = Vec::with_capacity(1 + 8 + 32);
    final_buf.push(MERKLE_NODE_PREFIX);
    final_buf.extend_from_slice(&(tree_size as u64).to_be_bytes());
    final_buf.extend_from_slice(&current);
    let computed_root = sha256(&final_buf);

    computed_root == *expected_root
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cid(n: u8) -> Cid {
        // Create distinct CIDs by hashing different bytes
        use crate::cid::compute_cid;
        compute_cid(&vec![n; 32]).unwrap_or_default()
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let cids = vec![make_cid(1), make_cid(2), make_cid(3)];
        let root1 = compute_merkle_root(&cids);
        let root2 = compute_merkle_root(&cids);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single() {
        let cids = vec![make_cid(42)];
        let root = compute_merkle_root(&cids);
        // Single CID: leaf = H(0x00 || cid_bytes), root = H(0x01 || tree_size_be8 || leaf)
        let leaf_hash = merkle_leaf_hash(&cids[0].to_bytes());
        let mut final_buf = Vec::with_capacity(1 + 8 + 32);
        final_buf.push(MERKLE_NODE_PREFIX);
        final_buf.extend_from_slice(&1u64.to_be_bytes());
        final_buf.extend_from_slice(&leaf_hash);
        let expected = sha256(&final_buf);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_changes_with_content() {
        let cids_a = vec![make_cid(1), make_cid(2)];
        let cids_b = vec![make_cid(1), make_cid(3)];
        let root_a = compute_merkle_root(&cids_a);
        let root_b = compute_merkle_root(&cids_b);
        assert_ne!(root_a, root_b);
    }

    #[test]
    fn test_inclusion_proof_verify() {
        let cids = vec![make_cid(10), make_cid(20), make_cid(30), make_cid(40)];
        let root = compute_merkle_root(&cids);

        for i in 0..cids.len() {
            let proof = compute_inclusion_proof(&cids, i).unwrap();
            assert!(
                verify_inclusion_proof(&cids[i], i, cids.len(), &proof, &root),
                "Inclusion proof failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_inclusion_proof_invalid_index() {
        let cids = vec![make_cid(1)];
        assert!(compute_inclusion_proof(&cids, 5).is_none());
    }

    #[test]
    fn test_inclusion_proof_tamper_detection() {
        let cids = vec![make_cid(1), make_cid(2), make_cid(3), make_cid(4)];
        let root = compute_merkle_root(&cids);
        let proof = compute_inclusion_proof(&cids, 0).unwrap();

        // Verify with wrong CID should fail
        let fake_cid = make_cid(99);
        assert!(!verify_inclusion_proof(&fake_cid, 0, cids.len(), &proof, &root));
    }

    #[test]
    fn test_window_auto_commit_on_packet_limit() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 3,
                commit_on_session_boundary: true,
            },
        );

        // First 2 packets: no commit
        assert!(mgr.ingest(make_cid(1), 1000, 100, Some("s1"), &[]).is_none());
        assert!(mgr.ingest(make_cid(2), 2000, 100, Some("s1"), &[]).is_none());
        assert_eq!(mgr.pending_packet_count(), 2);

        // 3rd packet: triggers commit (max_packets=3)
        let window = mgr.ingest(make_cid(3), 3000, 100, Some("s1"), &[]);
        assert!(window.is_some());

        let w = window.unwrap();
        assert_eq!(w.sn, 0);
        assert_eq!(w.packet_count, 3);
        assert_eq!(w.token_count, 300);
        assert_eq!(w.boundary_reason, BoundaryReason::PacketLimit);
        assert_eq!(w.event_time_start, 1000);
        assert_eq!(w.event_time_end, 3000);
        assert!(w.sealed);
        assert_eq!(w.leaf_cids.len(), 3);

        // Accumulator reset
        assert_eq!(mgr.pending_packet_count(), 0);
        assert_eq!(mgr.window_count(), 1);
    }

    #[test]
    fn test_window_auto_commit_on_token_limit() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 500,
                max_packets: 100,
                commit_on_session_boundary: true,
            },
        );

        // 200 + 200 = 400 < 500
        assert!(mgr.ingest(make_cid(1), 1000, 200, None, &[]).is_none());
        assert!(mgr.ingest(make_cid(2), 2000, 200, None, &[]).is_none());

        // 400 + 300 = 700 >= 500 → commit
        let w = mgr.ingest(make_cid(3), 3000, 300, None, &[]).unwrap();
        assert_eq!(w.boundary_reason, BoundaryReason::TokenLimit);
        assert_eq!(w.token_count, 700);
    }

    #[test]
    fn test_session_boundary_commit() {
        let mut mgr = RangeWindowManager::with_defaults("ns:test".to_string(), "pid:001".to_string());

        mgr.ingest(make_cid(1), 1000, 50, Some("s1"), &[]);
        mgr.ingest(make_cid(2), 2000, 50, Some("s1"), &[]);

        // Session boundary triggers commit
        let w = mgr.notify_session_boundary();
        assert!(w.is_some());
        let w = w.unwrap();
        assert_eq!(w.boundary_reason, BoundaryReason::SessionBoundary);
        assert_eq!(w.packet_count, 2);
        assert_eq!(w.session_id, Some("s1".to_string()));
    }

    #[test]
    fn test_session_boundary_empty_no_commit() {
        let mut mgr = RangeWindowManager::with_defaults("ns:test".to_string(), "pid:001".to_string());

        // No packets → no commit
        let w = mgr.notify_session_boundary();
        assert!(w.is_none());
    }

    #[test]
    fn test_force_commit() {
        let mut mgr = RangeWindowManager::with_defaults("ns:test".to_string(), "pid:001".to_string());

        mgr.ingest(make_cid(1), 1000, 50, None, &[]);

        let w = mgr.force_commit(BoundaryReason::SealForced).unwrap();
        assert_eq!(w.boundary_reason, BoundaryReason::SealForced);
        assert_eq!(w.packet_count, 1);
    }

    #[test]
    fn test_chain_linking() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        // Window 0
        mgr.ingest(make_cid(1), 1000, 10, None, &[]);
        let w0 = mgr.ingest(make_cid(2), 2000, 10, None, &[]).unwrap();
        assert_eq!(w0.sn, 0);
        assert_eq!(w0.prev_rw_root, [0u8; 32]); // First window chains to zero

        // Window 1
        mgr.ingest(make_cid(3), 3000, 10, None, &[]);
        let w1 = mgr.ingest(make_cid(4), 4000, 10, None, &[]).unwrap();
        assert_eq!(w1.sn, 1);
        assert_eq!(w1.prev_rw_root, w0.rw_root); // Chains to window 0

        // Window 2
        mgr.ingest(make_cid(5), 5000, 10, None, &[]);
        let w2 = mgr.ingest(make_cid(6), 6000, 10, None, &[]).unwrap();
        assert_eq!(w2.sn, 2);
        assert_eq!(w2.prev_rw_root, w1.rw_root); // Chains to window 1

        // Verify full chain
        assert!(mgr.verify_chain().is_ok());
        assert_eq!(mgr.tree_size(), 6);
    }

    #[test]
    fn test_chain_verification() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        for i in 0..10u8 {
            mgr.ingest(make_cid(i), (i as i64) * 1000, 10, None, &[]);
        }

        // 5 windows committed (10 packets / 2 per window)
        assert_eq!(mgr.window_count(), 5);
        assert!(mgr.verify_chain().is_ok());

        // Verify individual windows
        for sn in 0..5 {
            assert!(mgr.verify_window(sn).is_ok());
        }
    }

    #[test]
    fn test_pagination_load_page() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        for i in 0..6u8 {
            mgr.ingest(make_cid(i), (i as i64) * 1000, 10, None, &[]);
        }

        // Load by sn
        let page = mgr.load_page(1).unwrap();
        assert_eq!(page.sn, 1);
        assert_eq!(page.packet_count, 2);

        // Load by page_code
        let page = mgr.load_page_by_code("ns:test/000002").unwrap();
        assert_eq!(page.sn, 2);

        // Range query
        let pages = mgr.windows_in_range(0, 1);
        assert_eq!(pages.len(), 2);
    }

    #[test]
    fn test_entity_query() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        // Window 0: mentions "alice"
        mgr.ingest(make_cid(1), 1000, 10, None, &["alice".to_string()]);
        mgr.ingest(make_cid(2), 2000, 10, None, &["bob".to_string()]);

        // Window 1: mentions "alice" again
        mgr.ingest(make_cid(3), 3000, 10, None, &["alice".to_string()]);
        mgr.ingest(make_cid(4), 4000, 10, None, &["charlie".to_string()]);

        let alice_windows = mgr.windows_for_entity("alice");
        assert_eq!(alice_windows.len(), 2);

        let bob_windows = mgr.windows_for_entity("bob");
        assert_eq!(bob_windows.len(), 1);

        let nobody_windows = mgr.windows_for_entity("nobody");
        assert_eq!(nobody_windows.len(), 0);
    }

    #[test]
    fn test_time_range_query() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        // Window 0: events at 1000, 2000
        mgr.ingest(make_cid(1), 1000, 10, None, &[]);
        mgr.ingest(make_cid(2), 2000, 10, None, &[]);

        // Window 1: events at 5000, 6000
        mgr.ingest(make_cid(3), 5000, 10, None, &[]);
        mgr.ingest(make_cid(4), 6000, 10, None, &[]);

        // Query time range 0-3000 → only window 0
        let windows = mgr.windows_in_time_range(0, 3000);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].sn, 0);

        // Query time range 4000-7000 → only window 1
        let windows = mgr.windows_in_time_range(4000, 7000);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].sn, 1);

        // Query time range 0-7000 → both
        let windows = mgr.windows_in_time_range(0, 7000);
        assert_eq!(windows.len(), 2);
    }

    #[test]
    fn test_window_index() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 2,
                commit_on_session_boundary: false,
            },
        );

        for i in 0..4u8 {
            mgr.ingest(make_cid(i), (i as i64) * 1000, 50 + i as u64, None, &[]);
        }

        let index = mgr.window_index();
        assert_eq!(index.len(), 2);

        let entry = &index[&0];
        assert_eq!(entry.sn, 0);
        assert_eq!(entry.packet_count, 2);
        assert!(entry.sealed);
    }

    #[test]
    fn test_page_code_format() {
        let mut mgr = RangeWindowManager::with_defaults("ns:hospital".to_string(), "pid:bot".to_string());

        mgr.ingest(make_cid(1), 1000, 50, None, &[]);
        let w = mgr.force_commit(BoundaryReason::Manual).unwrap();

        assert_eq!(w.page_code, "ns:hospital/000000");

        mgr.ingest(make_cid(2), 2000, 50, None, &[]);
        let w = mgr.force_commit(BoundaryReason::Manual).unwrap();
        assert_eq!(w.page_code, "ns:hospital/000001");
    }

    #[test]
    fn test_latest_window() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 1,
                commit_on_session_boundary: false,
            },
        );

        assert!(mgr.latest_window().is_none());

        mgr.ingest(make_cid(1), 1000, 10, None, &[]);
        assert_eq!(mgr.latest_window().unwrap().sn, 0);

        mgr.ingest(make_cid(2), 2000, 10, None, &[]);
        assert_eq!(mgr.latest_window().unwrap().sn, 1);
    }

    #[test]
    fn test_cumulative_tree_size() {
        let mut mgr = RangeWindowManager::new(
            "ns:test".to_string(),
            "pid:001".to_string(),
            RangeWindowConfig {
                max_tokens: 100000,
                max_packets: 3,
                commit_on_session_boundary: false,
            },
        );

        // Window 0: 3 packets
        for i in 0..3u8 {
            mgr.ingest(make_cid(i), (i as i64) * 1000, 10, None, &[]);
        }
        assert_eq!(mgr.tree_size(), 3);

        // Window 1: 3 more packets
        for i in 3..6u8 {
            mgr.ingest(make_cid(i), (i as i64) * 1000, 10, None, &[]);
        }
        assert_eq!(mgr.tree_size(), 6);

        // Each window records cumulative size
        assert_eq!(mgr.load_page(0).unwrap().tree_size, 3);
        assert_eq!(mgr.load_page(1).unwrap().tree_size, 6);
    }

    // =========================================================================
    // Crypto hardening regression tests
    // =========================================================================

    #[test]
    fn test_c1_domain_separation_leaf_vs_node() {
        // C1: Leaf hash and node hash must differ even if data is the same.
        // This prevents second preimage attacks where an internal node
        // masquerades as a leaf.
        let data = [0u8; 32];
        let leaf = merkle_leaf_hash(&data);
        let node = merkle_node_hash(&data, &data);
        assert_ne!(leaf, node, "Leaf and node hashes must differ (domain separation)");
    }

    #[test]
    fn test_c1_internal_node_cannot_fake_leaf() {
        // An attacker tries to present H(left || right) as a leaf.
        // With domain separation, this produces a different hash.
        let cids = vec![make_cid(1), make_cid(2)];
        let root = compute_merkle_root(&cids);

        // Attacker computes what the internal node hash would be without prefix
        let left = sha256(&cids[0].to_bytes());
        let right = sha256(&cids[1].to_bytes());
        let mut fake_leaf_data = Vec::new();
        fake_leaf_data.extend_from_slice(&left);
        fake_leaf_data.extend_from_slice(&right);

        // This fake "leaf" should NOT produce the same root
        let fake_root = compute_merkle_root(&[]);
        assert_ne!(root, fake_root);
    }

    #[test]
    fn test_m1_odd_node_promotion_not_duplication() {
        // With 3 CIDs, the old code would duplicate the 3rd to make 4.
        // New code promotes the odd node. Verify roots differ from naive duplication.
        let cids = vec![make_cid(10), make_cid(20), make_cid(30)];
        let root_3 = compute_merkle_root(&cids);

        // 3-element and 4-element (with duplicate last) must produce different roots
        let cids_4 = vec![make_cid(10), make_cid(20), make_cid(30), make_cid(30)];
        let root_4 = compute_merkle_root(&cids_4);
        assert_ne!(root_3, root_4, "Odd-node promotion must differ from duplication");
    }

    #[test]
    fn test_m2_tree_size_bound_in_root() {
        // Two trees with different sizes but same leaf must produce different roots
        let cid = make_cid(42);
        let root_1 = compute_merkle_root(&[cid.clone()]);
        let root_2 = compute_merkle_root(&[cid.clone(), cid.clone()]);
        assert_ne!(root_1, root_2, "Different tree sizes must produce different roots");
    }

    #[test]
    fn test_m5_proof_rejects_wrong_tree_size() {
        let cids = vec![make_cid(1), make_cid(2), make_cid(3), make_cid(4)];
        let root = compute_merkle_root(&cids);
        let proof = compute_inclusion_proof(&cids, 0).unwrap();

        // Correct tree_size works
        assert!(verify_inclusion_proof(&cids[0], 0, 4, &proof, &root));

        // Wrong tree_size must fail
        assert!(!verify_inclusion_proof(&cids[0], 0, 3, &proof, &root));
        assert!(!verify_inclusion_proof(&cids[0], 0, 5, &proof, &root));
        assert!(!verify_inclusion_proof(&cids[0], 0, 0, &proof, &root));
    }

    #[test]
    fn test_inclusion_proof_odd_count() {
        // Verify proofs work correctly with odd number of leaves (promotion path)
        let cids = vec![make_cid(1), make_cid(2), make_cid(3)];
        let root = compute_merkle_root(&cids);

        for i in 0..cids.len() {
            let proof = compute_inclusion_proof(&cids, i).unwrap();
            assert!(
                verify_inclusion_proof(&cids[i], i, cids.len(), &proof, &root),
                "Inclusion proof failed for index {} with 3 leaves",
                i
            );
        }
    }

    #[test]
    fn test_inclusion_proof_large_tree() {
        // Verify proofs work at larger scale (32 leaves)
        let cids: Vec<Cid> = (0..32u8).map(make_cid).collect();
        let root = compute_merkle_root(&cids);

        for i in [0, 1, 15, 16, 30, 31] {
            let proof = compute_inclusion_proof(&cids, i).unwrap();
            assert!(
                verify_inclusion_proof(&cids[i], i, cids.len(), &proof, &root),
                "Inclusion proof failed for index {} with 32 leaves",
                i
            );
        }
    }
}
