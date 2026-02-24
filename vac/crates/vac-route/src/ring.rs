//! Consistent hash ring with virtual nodes.
//!
//! Each cell gets `vnodes_per_cell` virtual nodes distributed around the ring.
//! Lookup finds the first node >= the hash of the key (clockwise walk).
//! Adding/removing a cell only affects ~1/N of the key space.

use std::collections::{BTreeMap, HashSet};

use sha2::{Sha256, Digest};

/// Default number of virtual nodes per cell.
pub const DEFAULT_VNODES_PER_CELL: usize = 150;

/// A consistent hash ring mapping keys to cell IDs.
///
/// Uses SHA-256 truncated to u64 for ring positions.
/// Each cell gets `vnodes_per_cell` virtual nodes for even distribution.
#[derive(Debug, Clone)]
pub struct ConsistentHashRing {
    ring: BTreeMap<u64, String>,
    vnodes_per_cell: usize,
    cells: HashSet<String>,
}

impl ConsistentHashRing {
    /// Create a new empty ring with the default vnode count.
    pub fn new() -> Self {
        Self {
            ring: BTreeMap::new(),
            vnodes_per_cell: DEFAULT_VNODES_PER_CELL,
            cells: HashSet::new(),
        }
    }

    /// Create a new ring with a custom vnode count.
    pub fn with_vnodes(vnodes_per_cell: usize) -> Self {
        Self {
            ring: BTreeMap::new(),
            vnodes_per_cell,
            cells: HashSet::new(),
        }
    }

    /// Add a cell to the ring. Returns false if already present.
    pub fn add_cell(&mut self, cell_id: &str) -> bool {
        if !self.cells.insert(cell_id.to_string()) {
            return false;
        }
        for i in 0..self.vnodes_per_cell {
            let vnode_key = format!("{}:{}", cell_id, i);
            let hash = Self::hash_key(&vnode_key);
            self.ring.insert(hash, cell_id.to_string());
        }
        true
    }

    /// Remove a cell from the ring. Returns false if not present.
    pub fn remove_cell(&mut self, cell_id: &str) -> bool {
        if !self.cells.remove(cell_id) {
            return false;
        }
        for i in 0..self.vnodes_per_cell {
            let vnode_key = format!("{}:{}", cell_id, i);
            let hash = Self::hash_key(&vnode_key);
            self.ring.remove(&hash);
        }
        true
    }

    /// Look up which cell owns the given key.
    /// Returns None if the ring is empty.
    pub fn get_node(&self, key: &str) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let hash = Self::hash_key(key);
        // Walk clockwise: find first node >= hash
        if let Some((_pos, cell_id)) = self.ring.range(hash..).next() {
            return Some(cell_id.as_str());
        }
        // Wrap around to the first node in the ring
        self.ring.values().next().map(|s| s.as_str())
    }

    /// Get the N closest cells for a key (for replication).
    /// Returns up to `n` distinct cell IDs.
    pub fn get_n_nodes(&self, key: &str, n: usize) -> Vec<&str> {
        if self.ring.is_empty() || n == 0 {
            return vec![];
        }

        let hash = Self::hash_key(key);
        let mut result: Vec<&str> = Vec::new();
        let mut seen = HashSet::new();

        // Walk clockwise from hash
        for (_pos, cell_id) in self.ring.range(hash..) {
            if seen.insert(cell_id.as_str()) {
                result.push(cell_id.as_str());
                if result.len() >= n {
                    return result;
                }
            }
        }

        // Wrap around from the beginning
        for (_pos, cell_id) in self.ring.iter() {
            if seen.insert(cell_id.as_str()) {
                result.push(cell_id.as_str());
                if result.len() >= n {
                    return result;
                }
            }
        }

        result
    }

    /// Number of cells in the ring.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Number of virtual nodes in the ring.
    pub fn vnode_count(&self) -> usize {
        self.ring.len()
    }

    /// Check if a cell is in the ring.
    pub fn has_cell(&self, cell_id: &str) -> bool {
        self.cells.contains(cell_id)
    }

    /// All cell IDs in the ring.
    pub fn cell_ids(&self) -> impl Iterator<Item = &str> {
        self.cells.iter().map(|s| s.as_str())
    }

    /// Hash a key to a u64 ring position using SHA-256.
    fn hash_key(key: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        // Take first 8 bytes as u64
        u64::from_be_bytes([
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
        ])
    }
}

impl Default for ConsistentHashRing {
    fn default() -> Self {
        Self::new()
    }
}
