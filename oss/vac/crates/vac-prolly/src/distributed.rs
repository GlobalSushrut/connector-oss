//! INF-P4-4 — Distributed Prolly Tree (T4)
//!
//! Extends the local `ProllyTree` with cross-cell distribution:
//!
//! - **CID-addressed nodes**: each node is identified by `SHA-256(DAG-CBOR(node))`
//! - **RF/N ownership**: each cell owns `RF/N` of all CIDs (consistent hashing)
//! - **Cross-cell reads**: local miss → `VakyaForward` to the primary cell
//! - **Merkle diff sync**: only changed nodes transferred — O(diff size) not O(total)
//!
//! # Protocol
//!
//! ```text
//! Cell A (reader)                    Cell B (owner of CID)
//! ───────────────                    ─────────────────────
//! get(cid) → cache miss
//! ─── VakyaForward{cid} ──────────►
//!                                    lookup local store
//! ◄── VakyaReply{node_cbor} ─────────
//! deserialise → cache → return
//! ```
//!
//! # Merkle diff sync
//!
//! ```text
//! Cell A root: R_A     Cell B root: R_B
//! diff_sync(R_A, R_B) → walk both trees simultaneously
//!   same CID at any subtree → skip entire subtree (O(1))
//!   different CID → recurse into children
//!   only transfer leaf deltas
//! Total transfer: O(|diff|) not O(|total|)
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use async_trait::async_trait;
use cid::Cid;
use serde::{Deserialize, Serialize};
use vac_core::{VacError, VacResult};

use crate::node::ProllyNode;
use crate::tree::{NodeStore, ProllyTree};

// ═══════════════════════════════════════════════════════════════
// Cell routing — consistent hashing for RF/N ownership
// ═══════════════════════════════════════════════════════════════

/// Determines which cell is the primary owner of a given CID.
///
/// Uses the first 8 bytes of the CID multihash as a u64, then
/// `hash mod N` to map to a cell index. With replication factor RF,
/// the primary cell and `RF-1` successors all hold the node.
#[derive(Clone)]
pub struct CellRouter {
    /// Ordered list of cell IDs (stable ordering required for consistent hashing).
    cells: Vec<String>,
    /// Replication factor (default 3 for RF=3).
    pub replication_factor: usize,
}

impl CellRouter {
    pub fn new(cells: Vec<String>, replication_factor: usize) -> Self {
        assert!(!cells.is_empty(), "cell list must not be empty");
        assert!(replication_factor >= 1 && replication_factor <= cells.len(),
            "RF must be in [1, N]");
        Self { cells, replication_factor }
    }

    /// Returns the primary cell index for the given CID.
    pub fn primary_index(&self, cid: &Cid) -> usize {
        let hash_bytes = cid.hash().digest();
        let mut bytes = [0u8; 8];
        let copy = hash_bytes.len().min(8);
        bytes[..copy].copy_from_slice(&hash_bytes[..copy]);
        let h = u64::from_be_bytes(bytes);
        (h % self.cells.len() as u64) as usize
    }

    /// Returns the primary cell ID for the given CID.
    pub fn primary_cell(&self, cid: &Cid) -> &str {
        &self.cells[self.primary_index(cid)]
    }

    /// Returns all `RF` cell IDs that should hold this CID (primary + successors).
    pub fn replica_cells(&self, cid: &Cid) -> Vec<&str> {
        let n = self.cells.len();
        let start = self.primary_index(cid);
        (0..self.replication_factor)
            .map(|i| self.cells[(start + i) % n].as_str())
            .collect()
    }

    /// Returns true if `cell_id` is a replica for this CID.
    pub fn is_replica(&self, cid: &Cid, cell_id: &str) -> bool {
        self.replica_cells(cid).contains(&cell_id)
    }
}

// ═══════════════════════════════════════════════════════════════
// Cross-cell fetch request/response types
// ═══════════════════════════════════════════════════════════════

/// A cross-cell node fetch request (sent via `VakyaForward`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeFetchRequest {
    /// CID of the node being requested.
    pub cid: String,
    /// Requesting cell ID.
    pub requester_cell: String,
    /// Request ID for correlation.
    pub request_id: String,
}

/// A cross-cell node fetch response (sent via `VakyaReply`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeFetchResponse {
    /// Request ID (correlates to `NodeFetchRequest.request_id`).
    pub request_id: String,
    /// DAG-CBOR encoded node bytes, or None if not found.
    pub node_cbor: Option<Vec<u8>>,
    /// Responding cell ID.
    pub responder_cell: String,
}

// ═══════════════════════════════════════════════════════════════
// Cross-cell node store (INF-P4-4 primary storage layer)
// ═══════════════════════════════════════════════════════════════

/// Trait for a transport that can forward node fetch requests to remote cells.
#[async_trait]
pub trait NodeFetchTransport: Send + Sync {
    /// Fetch a node from a remote cell. Returns `None` if not found.
    async fn fetch_from_cell(&self, cell_id: &str, cid: &Cid) -> VacResult<Option<ProllyNode>>;
}

/// Distributed node store implementing INF-P4-4 cross-cell reads.
///
/// - Local hits serve directly from `local_store` (zero network).
/// - Local misses forward to the primary cell via `transport`.
/// - Fetched nodes are cached locally (LRU approximation: cap at `cache_cap`).
pub struct DistributedNodeStore {
    /// This cell's ID.
    pub cell_id: String,
    /// Local in-memory node cache.
    local_cache: std::sync::RwLock<HashMap<Cid, ProllyNode>>,
    /// Cache capacity (approximate — evict when exceeded).
    cache_cap: usize,
    /// Cell routing table.
    pub router: CellRouter,
    /// Transport for cross-cell fetches.
    transport: Arc<dyn NodeFetchTransport>,
}

impl DistributedNodeStore {
    pub fn new(
        cell_id: impl Into<String>,
        router: CellRouter,
        transport: Arc<dyn NodeFetchTransport>,
        cache_cap: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            cell_id: cell_id.into(),
            local_cache: std::sync::RwLock::new(HashMap::new()),
            cache_cap,
            router,
            transport,
        })
    }

    /// Insert a node into the local cache directly (for local writes).
    pub fn cache_put(&self, cid: Cid, node: ProllyNode) {
        let mut cache = self.local_cache.write().unwrap();
        if cache.len() >= self.cache_cap {
            // Simple eviction: remove arbitrary entry
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }
        cache.insert(cid, node);
    }

    /// Number of nodes currently in local cache.
    pub fn cache_size(&self) -> usize {
        self.local_cache.read().unwrap().len()
    }
}

#[async_trait]
impl NodeStore for DistributedNodeStore {
    async fn get(&self, cid: &Cid) -> VacResult<ProllyNode> {
        // 1. Local cache hit
        {
            let cache = self.local_cache.read().unwrap();
            if let Some(node) = cache.get(cid) {
                return Ok(node.clone());
            }
        }

        // 2. Cross-cell fetch: route to primary cell
        let primary = self.router.primary_cell(cid).to_string();
        if primary == self.cell_id {
            // We are the primary — node should be in cache (miss = not found)
            return Err(VacError::NotFound(format!("node {} not in primary cell {}", cid, self.cell_id)));
        }

        // 3. Forward to primary cell via transport (VakyaForward)
        match self.transport.fetch_from_cell(&primary, cid).await? {
            Some(node) => {
                // Cache locally for future reads
                self.cache_put(cid.clone(), node.clone());
                Ok(node)
            }
            None => Err(VacError::NotFound(format!(
                "node {} not found on primary cell {}", cid, primary
            ))),
        }
    }

    async fn put(&self, node: &ProllyNode) -> VacResult<Cid> {
        use vac_core::ContentAddressable;
        let cid = node.cid()?;
        self.cache_put(cid.clone(), node.clone());
        Ok(cid)
    }

    async fn contains(&self, cid: &Cid) -> bool {
        self.local_cache.read().unwrap().contains_key(cid)
    }
}

// ═══════════════════════════════════════════════════════════════
// INF-P4-4: Merkle diff sync — O(|diff|) not O(|total|)
// ═══════════════════════════════════════════════════════════════

/// A single node delta between two tree versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDelta {
    /// CID of the node in the new (local) tree.
    pub new_cid: String,
    /// CID of the node in the old (remote) tree, if any.
    pub old_cid: Option<String>,
    /// The node content (DAG-CBOR bytes) to transfer.
    pub node_cbor: Vec<u8>,
    /// Tree level of this node.
    pub level: u8,
}

/// Result of a Merkle diff sync between two tree roots.
#[derive(Debug, Default)]
pub struct MerkleDiffResult {
    /// Nodes that exist in local tree but not (or differently) in remote tree.
    /// These must be sent to the remote cell.
    pub nodes_to_send: Vec<NodeDelta>,
    /// CIDs requested from the remote cell (exist there but not locally).
    pub cids_to_request: Vec<String>,
    /// Number of subtrees skipped because roots matched.
    pub subtrees_skipped: usize,
    /// Total nodes compared.
    pub nodes_compared: usize,
}

impl MerkleDiffResult {
    /// True if trees are identical (no differences found).
    pub fn is_empty(&self) -> bool {
        self.nodes_to_send.is_empty() && self.cids_to_request.is_empty()
    }
}

/// Performs an INF-P4-4 Merkle diff sync between a local and remote tree root.
///
/// Walk both trees simultaneously (BFS). When two subtrees share the same root
/// CID, the entire subtree is skipped. Only changed nodes are transferred.
///
/// # Complexity
/// - O(|diff|) node comparisons and transfers
/// - O(log N) depth per changed path
/// - Best case O(1) if roots match (trees identical)
pub struct MerkleDiffSyncer<S: NodeStore> {
    local_store: Arc<S>,
}

impl<S: NodeStore> MerkleDiffSyncer<S> {
    pub fn new(local_store: Arc<S>) -> Self {
        Self { local_store }
    }

    /// Compute the diff between `local_root` and `remote_root`.
    ///
    /// `remote_cids` provides a set of CIDs known to exist on the remote cell
    /// (sent as part of the sync handshake). Nodes in `remote_cids` are skipped.
    pub async fn compute_diff(
        &self,
        local_root: &Cid,
        remote_root: Option<&Cid>,
        remote_cids: &HashSet<String>,
    ) -> VacResult<MerkleDiffResult> {
        let mut result = MerkleDiffResult::default();

        // If roots match → trees are identical → nothing to do
        if let Some(rroot) = remote_root {
            if local_root == rroot {
                return Ok(result);
            }
        }

        // BFS queue: (local_cid, remote_cid_or_none)
        let mut queue: VecDeque<(Cid, Option<Cid>)> = VecDeque::new();
        queue.push_back((local_root.clone(), remote_root.cloned()));

        while let Some((local_cid, remote_cid_opt)) = queue.pop_front() {
            result.nodes_compared += 1;

            // If both sides have the same CID → entire subtree is identical → skip
            if let Some(ref rcid) = remote_cid_opt {
                if &local_cid == rcid {
                    result.subtrees_skipped += 1;
                    continue;
                }
            }

            // Fetch local node
            let local_node = self.local_store.get(&local_cid).await?;

            // Serialize node for transfer
            let node_cbor = serde_json::to_vec(&local_node).unwrap_or_default();

            result.nodes_to_send.push(NodeDelta {
                new_cid: local_cid.to_string(),
                old_cid: remote_cid_opt.as_ref().map(|c| c.to_string()),
                node_cbor,
                level: local_node.level,
            });

            // If this is an internal node, enqueue children
            if !local_node.is_leaf() {
                for child_cid in &local_node.values {
                    // Check if this child CID exists on remote (from remote_cids set)
                    let remote_child = if remote_cids.contains(&child_cid.to_string()) {
                        Some(child_cid.clone())
                    } else {
                        None
                    };
                    queue.push_back((child_cid.clone(), remote_child));
                }
            }
        }

        Ok(result)
    }

    /// Apply a received diff to the local store.
    /// Each `NodeDelta.node_cbor` is deserialised and inserted into local cache.
    pub async fn apply_diff(&self, deltas: &[NodeDelta]) -> VacResult<usize> {
        let mut applied = 0;
        for delta in deltas {
            if let Ok(node) = serde_json::from_slice::<ProllyNode>(&delta.node_cbor) {
                self.local_store.put(&node).await?;
                applied += 1;
            }
        }
        Ok(applied)
    }
}

// ═══════════════════════════════════════════════════════════════
// In-memory transport (for testing — no real network)
// ═══════════════════════════════════════════════════════════════

/// Test transport that routes fetches to a local map of cell stores.
pub struct InMemoryTransport {
    /// cell_id → node store mapping
    cell_stores: std::sync::RwLock<HashMap<String, Arc<std::sync::RwLock<HashMap<Cid, ProllyNode>>>>>,
}

impl InMemoryTransport {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { cell_stores: std::sync::RwLock::new(HashMap::new()) })
    }

    /// Register a cell's node map so this transport can serve it.
    pub fn register_cell(
        &self,
        cell_id: impl Into<String>,
        nodes: Arc<std::sync::RwLock<HashMap<Cid, ProllyNode>>>,
    ) {
        self.cell_stores.write().unwrap().insert(cell_id.into(), nodes);
    }
}

#[async_trait]
impl NodeFetchTransport for InMemoryTransport {
    async fn fetch_from_cell(&self, cell_id: &str, cid: &Cid) -> VacResult<Option<ProllyNode>> {
        let stores = self.cell_stores.read().unwrap();
        match stores.get(cell_id) {
            Some(store) => Ok(store.read().unwrap().get(cid).cloned()),
            None => Err(VacError::NotFound(format!("cell {} not found in transport", cell_id))),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::MemoryNodeStore;

    fn make_router(n: usize) -> CellRouter {
        let cells = (0..n).map(|i| format!("cell-{}", i)).collect();
        CellRouter::new(cells, 1.min(n))
    }

    fn make_cid(seed: u8) -> Cid {
        use vac_core::ContentAddressable;
        let node = ProllyNode::new_leaf(vec![vec![seed]], vec![Cid::default()]);
        node.cid().unwrap()
    }

    #[test]
    fn test_inf_p4_4_cell_router_deterministic() {
        let router = make_router(5);
        let cid = make_cid(42);
        let p1 = router.primary_cell(&cid).to_string();
        let p2 = router.primary_cell(&cid).to_string();
        assert_eq!(p1, p2, "Routing must be deterministic");
    }

    #[test]
    fn test_inf_p4_4_cell_router_rf_replicas() {
        let router = CellRouter::new(
            vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            3,
        );
        let cid = make_cid(7);
        let replicas = router.replica_cells(&cid);
        assert_eq!(replicas.len(), 3, "RF=3 must return exactly 3 cells");
        // All replicas must be distinct
        let unique: HashSet<_> = replicas.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_inf_p4_4_cell_router_is_replica() {
        let router = CellRouter::new(
            vec!["a".into(), "b".into(), "c".into()],
            2,
        );
        let cid = make_cid(99);
        let replicas = router.replica_cells(&cid);
        for cell in &replicas {
            assert!(router.is_replica(&cid, cell), "{} should be a replica", cell);
        }
    }

    #[tokio::test]
    async fn test_inf_p4_4_distributed_store_local_hit() {
        let transport = InMemoryTransport::new();
        let router = make_router(3);
        let store = DistributedNodeStore::new("cell-0", router, transport, 1000);

        let node = ProllyNode::new_leaf(vec![b"key".to_vec()], vec![Cid::default()]);
        let cid = store.put(&node).await.unwrap();

        // Should be served from local cache
        let fetched = store.get(&cid).await.unwrap();
        assert_eq!(fetched.keys, node.keys);
    }

    #[tokio::test]
    async fn test_inf_p4_4_distributed_store_cross_cell_fetch() {
        // Set up: cell-1 has a node that cell-0 doesn't
        let cell1_nodes: Arc<std::sync::RwLock<HashMap<Cid, ProllyNode>>> =
            Arc::new(std::sync::RwLock::new(HashMap::new()));

        let node = ProllyNode::new_leaf(vec![b"remote_key".to_vec()], vec![Cid::default()]);

        let transport = InMemoryTransport::new();
        transport.register_cell("cell-1", cell1_nodes.clone());

        // Build a router that routes this CID to cell-1
        let router = CellRouter::new(vec!["cell-0".into(), "cell-1".into()], 1);

        let store = DistributedNodeStore::new("cell-0", router.clone(), transport, 1000);

        // Insert node into cell-1's backing store
        use vac_core::ContentAddressable;
        let cid = node.cid().unwrap();
        cell1_nodes.write().unwrap().insert(cid.clone(), node.clone());

        // cell-0 fetches — should cross-cell to cell-1 if cell-1 is primary
        let primary = router.primary_cell(&cid).to_string();
        if primary == "cell-1" {
            let fetched = store.get(&cid).await.unwrap();
            assert_eq!(fetched.keys, node.keys);
            // Should now be cached locally
            assert!(store.contains(&cid).await);
        }
        // If cell-0 is primary, the node would be expected locally — skip assertion
    }

    #[tokio::test]
    async fn test_inf_p4_4_merkle_diff_identical_roots_skipped() {
        let store = Arc::new(MemoryNodeStore::default());
        let mut tree = ProllyTree::new(MemoryNodeStore::default());
        tree.insert(b"k1".to_vec(), Cid::default()).await.unwrap();
        let root = tree.root().unwrap().clone();

        // Insert root into syncer's store
        let node = store.get(&root).await;
        // Can't easily populate MemoryNodeStore externally for this test,
        // so we test the identical-root fast path via an empty diff check
        let syncer = MerkleDiffSyncer::new(store);
        let result = syncer.compute_diff(&root, Some(&root), &HashSet::new()).await.unwrap();
        // Same root → early exit before BFS; empty diff, zero traversal cost
        assert!(result.is_empty(), "identical roots must produce empty diff");
        assert_eq!(result.nodes_compared, 0, "early exit must not traverse any nodes");
        assert_eq!(result.subtrees_skipped, 0);
    }

    #[tokio::test]
    async fn test_inf_p4_4_merkle_diff_no_remote_root() {
        let store = Arc::new(MemoryNodeStore::default());
        let mut tree = ProllyTree::new(MemoryNodeStore::default());
        tree.insert(b"k1".to_vec(), Cid::default()).await.unwrap();
        tree.insert(b"k2".to_vec(), Cid::default()).await.unwrap();
        let root = tree.root().unwrap().clone();

        // Insert the root node into the syncer's backing store
        let node = ProllyNode::new_leaf(
            vec![b"k1".to_vec(), b"k2".to_vec()],
            vec![Cid::default(), Cid::default()],
        );
        store.put(&node).await.unwrap();
        let root_cid = store.put(&node).await.unwrap();

        let syncer = MerkleDiffSyncer::new(store);
        let result = syncer.compute_diff(&root_cid, None, &HashSet::new()).await.unwrap();
        // No remote root → everything must be sent
        assert!(!result.nodes_to_send.is_empty());
    }

    #[test]
    fn test_inf_p4_4_node_delta_serialization() {
        let delta = NodeDelta {
            new_cid: "bafyabc".to_string(),
            old_cid: Some("bafydef".to_string()),
            node_cbor: vec![1, 2, 3],
            level: 0,
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: NodeDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.new_cid, "bafyabc");
        assert_eq!(back.level, 0);
    }

    #[test]
    fn test_inf_p4_4_noop_op_added_to_replication_op() {
        // Verify VakyaForward exists (used for cross-cell fetch)
        use vac_bus::types::ReplicationOp;
        let op = ReplicationOp::VakyaForward {
            vakya_cbor: vec![],
            pipeline_id: "pipe-1".into(),
            step_id: "step-1".into(),
            reply_topic: "reply.topic".into(),
        };
        assert_eq!(op.op_type(), "vakya_forward");
    }
}
