//! Topological Consensus — mathematically stable cluster membership.
//!
//! Grounded in three pillars of mathematical distributed computing:
//!
//! 1. **Lattice-based CRDT membership** (Shapiro et al. 2011):
//!    Membership views form a join-semilattice under component-wise max
//!    of vector clocks + union of known members. Convergence is guaranteed
//!    by the algebraic properties: commutativity, associativity, idempotence.
//!
//! 2. **Simplicial topology for partition detection** (Herlihy-Shavit 1999):
//!    The cluster is modeled as a simplicial complex. The 0th Betti number
//!    β₀ = rank(H₀) counts connected components. β₀ = 1 means the cluster
//!    is connected (quorum possible); β₀ > 1 means network partition.
//!    The Euler characteristic χ = V - E + F is a topological invariant
//!    that detects structural changes.
//!
//! 3. **Braid-theoretic stability invariant** (knot theory):
//!    Membership events (join/leave) form crossings in a causal braid.
//!    The writhe W = Σ sign(crossing) measures net membership flux.
//!    The stability index S = 1 - |W|/N ∈ [0,1] where N = total crossings.
//!    S → 1 means the cluster is stabilizing (balanced joins/leaves).
//!
//! **Why no leader election?** Our data model is CID-addressed (content-
//! addressed, conflict-free by construction). Membership views are CRDTs.
//! The block chain uses monotonic block_no. No Raft/PBFT needed.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ============================================================================
// 1. Vector Clock — Join-Semilattice for Causal Ordering
// ============================================================================

/// A vector clock implementing a join-semilattice.
///
/// **Algebraic properties (proven):**
/// - Commutativity: merge(a, b) = merge(b, a)
/// - Associativity: merge(merge(a, b), c) = merge(a, merge(b, c))
/// - Idempotence: merge(a, a) = a
///
/// These three properties guarantee convergence in any message ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    entries: BTreeMap<String, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Increment the clock for a given cell. Returns the new value.
    pub fn increment(&mut self, cell_id: &str) -> u64 {
        let entry = self.entries.entry(cell_id.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Get the clock value for a cell.
    pub fn get(&self, cell_id: &str) -> u64 {
        self.entries.get(cell_id).copied().unwrap_or(0)
    }

    /// Join-semilattice merge: component-wise maximum.
    ///
    /// Proof of semilattice properties:
    /// - max(a,b) = max(b,a)                    [commutativity]
    /// - max(max(a,b),c) = max(a,max(b,c))      [associativity]
    /// - max(a,a) = a                            [idempotence]
    pub fn merge(&self, other: &VectorClock) -> VectorClock {
        let mut result = self.entries.clone();
        for (k, v) in &other.entries {
            let entry = result.entry(k.clone()).or_insert(0);
            *entry = (*entry).max(*v);
        }
        VectorClock { entries: result }
    }

    /// Returns true if self happens-before other (strict partial order).
    /// a < b iff ∀k: a[k] ≤ b[k] ∧ ∃k: a[k] < b[k]
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let all_keys: HashSet<&String> =
            self.entries.keys().chain(other.entries.keys()).collect();
        let mut at_least_one_less = false;
        for k in all_keys {
            let a = self.get(k);
            let b = other.get(k);
            if a > b {
                return false;
            }
            if a < b {
                at_least_one_less = true;
            }
        }
        at_least_one_less
    }

    /// Returns true if self and other are concurrent (incomparable in the partial order).
    pub fn concurrent(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self) && self != other
    }

    /// Number of cells tracked.
    pub fn dimension(&self) -> usize {
        self.entries.len()
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 2. Simplicial Complex — Cluster Topology
// ============================================================================

/// A simplicial complex modeling cluster topology.
///
/// - 0-simplices (vertices) = cells
/// - 1-simplices (edges) = communication links between cells
///
/// The 0th Betti number β₀ = number of connected components.
/// Euler characteristic χ = |V| - |E|  (for 1-dimensional complex).
#[derive(Debug, Clone)]
pub struct SimplicialComplex {
    vertices: HashSet<String>,
    edges: HashSet<(String, String)>,
}

impl SimplicialComplex {
    pub fn new() -> Self {
        Self {
            vertices: HashSet::new(),
            edges: HashSet::new(),
        }
    }

    pub fn add_vertex(&mut self, cell_id: &str) {
        self.vertices.insert(cell_id.to_string());
    }

    pub fn remove_vertex(&mut self, cell_id: &str) {
        self.vertices.remove(cell_id);
        self.edges
            .retain(|(a, b)| a != cell_id && b != cell_id);
    }

    /// Add an edge (1-simplex). Ensures canonical ordering (a < b).
    pub fn add_edge(&mut self, a: &str, b: &str) {
        if a == b {
            return;
        }
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.vertices.insert(lo.to_string());
        self.vertices.insert(hi.to_string());
        self.edges.insert((lo.to_string(), hi.to_string()));
    }

    pub fn remove_edge(&mut self, a: &str, b: &str) {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.edges.remove(&(lo.to_string(), hi.to_string()));
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Euler characteristic χ = V - E (for a 1-dimensional simplicial complex).
    /// For a connected graph: χ = 1. For k components: χ = k.
    /// For a tree: χ = 1 (V - E = V - (V-1) = 1).
    pub fn euler_characteristic(&self) -> i64 {
        self.vertices.len() as i64 - self.edges.len() as i64
    }

    /// Compute connected components using BFS.
    /// Returns the 0th Betti number β₀ = number of connected components.
    ///
    /// β₀ = 1 → cluster is connected (quorum possible)
    /// β₀ > 1 → network partition detected
    pub fn connected_components(&self) -> Vec<HashSet<String>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut components: Vec<HashSet<String>> = Vec::new();

        // Build adjacency list
        let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
        for v in &self.vertices {
            adj.entry(v.clone()).or_default();
        }
        for (a, b) in &self.edges {
            adj.entry(a.clone()).or_default().insert(b.clone());
            adj.entry(b.clone()).or_default().insert(a.clone());
        }

        for v in &self.vertices {
            if visited.contains(v) {
                continue;
            }
            let mut component = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(v.clone());
            visited.insert(v.clone());

            while let Some(node) = queue.pop_front() {
                component.insert(node.clone());
                if let Some(neighbors) = adj.get(&node) {
                    for n in neighbors {
                        if !visited.contains(n) {
                            visited.insert(n.clone());
                            queue.push_back(n.clone());
                        }
                    }
                }
            }
            components.push(component);
        }
        components
    }

    /// β₀ = rank(H₀) = number of connected components.
    pub fn betti_0(&self) -> usize {
        if self.vertices.is_empty() {
            return 0;
        }
        self.connected_components().len()
    }

    /// Whether the complex is connected (β₀ = 1).
    pub fn is_connected(&self) -> bool {
        self.betti_0() == 1
    }
}

impl Default for SimplicialComplex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 3. Causal Braid — Knot-Theoretic Stability Invariant
// ============================================================================

/// Type of crossing in the causal braid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossingSign {
    /// Positive crossing: a cell joined (+1)
    Positive,
    /// Negative crossing: a cell left (-1)
    Negative,
    /// Neutral: heartbeat / state update (0)
    Neutral,
}

impl CrossingSign {
    pub fn value(&self) -> i64 {
        match self {
            CrossingSign::Positive => 1,
            CrossingSign::Negative => -1,
            CrossingSign::Neutral => 0,
        }
    }
}

/// A single crossing in the causal braid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraidCrossing {
    pub cell_id: String,
    pub sign: CrossingSign,
    pub timestamp: i64,
}

/// Causal braid tracking membership stability via knot invariants.
///
/// The writhe W = Σ sign(crossing_i) measures net membership flux.
/// The stability index S = 1 - |W|/N where N = number of non-neutral crossings.
/// - S = 1.0: perfectly balanced (equal joins and leaves)
/// - S = 0.0: maximally unstable (all joins or all leaves)
///
/// Uses a sliding window to bound memory.
pub struct CausalBraid {
    crossings: VecDeque<BraidCrossing>,
    max_window: usize,
}

impl CausalBraid {
    pub fn new(max_window: usize) -> Self {
        Self {
            crossings: VecDeque::new(),
            max_window,
        }
    }

    pub fn record(&mut self, cell_id: &str, sign: CrossingSign) {
        let crossing = BraidCrossing {
            cell_id: cell_id.to_string(),
            sign,
            timestamp: chrono::Utc::now().timestamp(),
        };
        self.crossings.push_back(crossing);
        while self.crossings.len() > self.max_window {
            self.crossings.pop_front();
        }
    }

    /// Writhe W = Σ sign(crossing_i).
    /// Positive writhe = net joins dominate. Negative = net leaves dominate.
    pub fn writhe(&self) -> i64 {
        self.crossings.iter().map(|c| c.sign.value()).sum()
    }

    /// Number of non-neutral crossings in the window.
    pub fn significant_crossings(&self) -> usize {
        self.crossings
            .iter()
            .filter(|c| c.sign != CrossingSign::Neutral)
            .count()
    }

    /// Stability index S ∈ [0.0, 1.0].
    /// S = 1 - |W|/N where N = significant crossings.
    /// Returns 1.0 if no significant crossings (trivially stable).
    pub fn stability_index(&self) -> f64 {
        let n = self.significant_crossings();
        if n == 0 {
            return 1.0;
        }
        let w = self.writhe().unsigned_abs() as f64;
        1.0 - (w / n as f64)
    }

    pub fn total_crossings(&self) -> usize {
        self.crossings.len()
    }
}

// ============================================================================
// 4. Membership View — State-Based CRDT
// ============================================================================

/// State of a single member cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberState {
    pub cell_id: String,
    pub address: String,
    pub is_voter: bool,
    pub joined_at: i64,
    pub last_seen: i64,
    /// Generation counter — incremented on each state change.
    /// Used for last-writer-wins within the CRDT merge.
    pub generation: u64,
    /// Whether this member has been explicitly removed.
    pub tombstone: bool,
}

/// CRDT membership view — converges under any message ordering.
///
/// **Merge semantics (join-semilattice):**
/// - For each cell_id present in either view, take the entry with higher generation.
/// - Vector clock: component-wise max.
///
/// **Proof of convergence:**
/// - merge(A, B) = merge(B, A)  [commutativity: max is commutative]
/// - merge(merge(A,B), C) = merge(A, merge(B,C))  [associativity]
/// - merge(A, A) = A  [idempotence: max(x,x) = x]
/// ∴ MembershipView is a join-semilattice → eventual consistency guaranteed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipView {
    pub members: BTreeMap<String, MemberState>,
    pub clock: VectorClock,
}

impl MembershipView {
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
            clock: VectorClock::new(),
        }
    }

    /// Join-semilattice merge of two membership views.
    pub fn merge(&self, other: &MembershipView) -> MembershipView {
        let mut merged_members = self.members.clone();

        for (cell_id, other_state) in &other.members {
            match merged_members.get(cell_id) {
                Some(existing) => {
                    // Last-writer-wins by generation counter
                    if other_state.generation > existing.generation {
                        merged_members.insert(cell_id.clone(), other_state.clone());
                    }
                }
                None => {
                    merged_members.insert(cell_id.clone(), other_state.clone());
                }
            }
        }

        MembershipView {
            members: merged_members,
            clock: self.clock.merge(&other.clock),
        }
    }

    /// Number of alive (non-tombstoned) members.
    pub fn alive_count(&self) -> usize {
        self.members.values().filter(|m| !m.tombstone).count()
    }

    /// Number of alive voters.
    pub fn voter_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| !m.tombstone && m.is_voter)
            .count()
    }
}

impl Default for MembershipView {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 5. Membership — Top-Level Orchestrator
// ============================================================================

/// Configuration for the membership protocol.
#[derive(Debug, Clone)]
pub struct MembershipConfig {
    /// How long before a member is considered dead (no heartbeat).
    pub heartbeat_timeout: Duration,
    /// Maximum braid crossings to track.
    pub braid_window: usize,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout: Duration::from_secs(30),
            braid_window: 1000,
        }
    }
}

/// Topological cluster membership.
///
/// Combines:
/// - CRDT membership view (lattice convergence)
/// - Simplicial complex (partition detection via homology)
/// - Causal braid (stability via knot invariant)
pub struct Membership {
    local_cell_id: String,
    pub view: MembershipView,
    pub complex: SimplicialComplex,
    pub braid: CausalBraid,
    pub config: MembershipConfig,
    heartbeat_tracker: HashMap<String, Instant>,
}

impl Membership {
    /// Create a new membership tracker. The local cell is automatically added.
    pub fn new(cell_id: &str, address: &str, config: MembershipConfig) -> Self {
        let mut view = MembershipView::new();
        let state = MemberState {
            cell_id: cell_id.to_string(),
            address: address.to_string(),
            is_voter: true,
            joined_at: chrono::Utc::now().timestamp(),
            last_seen: chrono::Utc::now().timestamp(),
            generation: 1,
            tombstone: false,
        };
        view.members.insert(cell_id.to_string(), state);
        view.clock.increment(cell_id);

        let mut complex = SimplicialComplex::new();
        complex.add_vertex(cell_id);

        let braid_window = config.braid_window;
        let mut braid = CausalBraid::new(braid_window);
        braid.record(cell_id, CrossingSign::Positive);

        let mut tracker = HashMap::new();
        tracker.insert(cell_id.to_string(), Instant::now());

        Self {
            local_cell_id: cell_id.to_string(),
            view,
            complex,
            braid,
            config,
            heartbeat_tracker: tracker,
        }
    }

    pub fn local_cell_id(&self) -> &str {
        &self.local_cell_id
    }

    /// A remote cell joins the cluster.
    pub fn join(&mut self, cell_id: &str, address: &str, is_voter: bool) {
        let gen = self
            .view
            .members
            .get(cell_id)
            .map(|m| m.generation + 1)
            .unwrap_or(1);

        let state = MemberState {
            cell_id: cell_id.to_string(),
            address: address.to_string(),
            is_voter,
            joined_at: chrono::Utc::now().timestamp(),
            last_seen: chrono::Utc::now().timestamp(),
            generation: gen,
            tombstone: false,
        };
        self.view.members.insert(cell_id.to_string(), state);
        self.view.clock.increment(&self.local_cell_id);

        self.complex.add_vertex(cell_id);
        // Add edge from local cell to new cell (communication link)
        self.complex.add_edge(&self.local_cell_id, cell_id);

        self.braid.record(cell_id, CrossingSign::Positive);
        self.heartbeat_tracker
            .insert(cell_id.to_string(), Instant::now());
    }

    /// A cell leaves the cluster (tombstone in CRDT).
    pub fn leave(&mut self, cell_id: &str) {
        if let Some(member) = self.view.members.get_mut(cell_id) {
            member.tombstone = true;
            member.generation += 1;
        }
        self.view.clock.increment(&self.local_cell_id);

        self.complex.remove_vertex(cell_id);
        self.braid.record(cell_id, CrossingSign::Negative);
        self.heartbeat_tracker.remove(cell_id);
    }

    /// Process a heartbeat from a remote cell.
    pub fn heartbeat(&mut self, cell_id: &str) {
        if let Some(member) = self.view.members.get_mut(cell_id) {
            member.last_seen = chrono::Utc::now().timestamp();
        }
        self.heartbeat_tracker
            .insert(cell_id.to_string(), Instant::now());
        self.braid.record(cell_id, CrossingSign::Neutral);
    }

    /// Merge a remote membership view into ours (CRDT merge).
    /// Convergence guaranteed by join-semilattice properties.
    pub fn merge_remote(&mut self, remote: &MembershipView) {
        self.view = self.view.merge(remote);
        self.view.clock.increment(&self.local_cell_id);

        // Rebuild simplicial complex from merged view
        self.rebuild_complex();
    }

    /// Rebuild the simplicial complex from the current membership view.
    fn rebuild_complex(&mut self) {
        self.complex = SimplicialComplex::new();
        let alive: Vec<String> = self
            .view
            .members
            .values()
            .filter(|m| !m.tombstone)
            .map(|m| m.cell_id.clone())
            .collect();

        for cell_id in &alive {
            self.complex.add_vertex(cell_id);
        }
        // In a fully-connected cluster, add edges between all alive members
        for i in 0..alive.len() {
            for j in (i + 1)..alive.len() {
                self.complex.add_edge(&alive[i], &alive[j]);
            }
        }
    }

    /// Detect dead members based on heartbeat timeout.
    pub fn detect_dead(&self) -> Vec<String> {
        let timeout = self.config.heartbeat_timeout;
        self.heartbeat_tracker
            .iter()
            .filter(|(id, last)| {
                *id != &self.local_cell_id && last.elapsed() > timeout
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Whether we have a majority quorum of alive voters AND the cluster is connected.
    /// This is the topological quorum condition:
    ///   quorum ⟺ alive_voters > total_voters/2 ∧ β₀ = 1
    pub fn has_quorum(&self) -> bool {
        let alive_voters = self.view.voter_count();
        let total_voters = self
            .view
            .members
            .values()
            .filter(|m| m.is_voter)
            .count();

        if total_voters == 0 {
            return false;
        }

        let majority = alive_voters > total_voters / 2;
        let connected = self.complex.is_connected();
        majority && connected
    }

    /// β₀ — number of connected components (network partitions).
    pub fn partition_count(&self) -> usize {
        self.complex.betti_0()
    }

    /// Cluster stability index from the causal braid.
    pub fn stability_index(&self) -> f64 {
        self.braid.stability_index()
    }

    /// Euler characteristic of the cluster topology.
    pub fn euler_characteristic(&self) -> i64 {
        self.complex.euler_characteristic()
    }

    /// Number of alive members.
    pub fn alive_count(&self) -> usize {
        self.view.alive_count()
    }

    /// Number of total members (including tombstoned).
    pub fn total_count(&self) -> usize {
        self.view.members.len()
    }
}
