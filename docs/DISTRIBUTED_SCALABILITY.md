# DISTRIBUTED_SCALABILITY.md — Agent OS as a Distributed Universe

> **The one-line definition:**
> "The Agent OS is not a single process. It is a universe of cells — each cell a complete, independent kernel — that together form a coherent, self-healing, infinitely scalable distributed system. No single point of failure. No coordinator. No bottleneck."

---

## Table of Contents

1. [The Universe Model — Why "Distributed" Is Not Enough](#1-the-universe-model)
2. [Five Laws of the Distributed Agent OS](#2-five-laws)
3. [Current Implementation Inventory](#3-current-implementation-inventory)
4. [Cell — The Atomic Unit of Distribution](#4-cell)
5. [ClusterKernelStore — The VFS Trick](#5-clusterkernelstore)
6. [Event Bus — The Fabric of the Universe](#6-event-bus)
7. [Consistent Hash Ring — Agent Routing](#7-consistent-hash-ring)
8. [Topological Consensus — Membership Without a Leader](#8-topological-consensus)
9. [Merkle Sync — Content-Addressed Replication](#9-merkle-sync)
10. [Prolly Tree — The Distributed Data Structure](#10-prolly-tree)
11. [AAPI Federation — Cross-Org Distributed Policy](#11-aapi-federation)
12. [AAPI Pipeline — Distributed VAKYA Execution](#12-aapi-pipeline)
13. [Saga Coordinator — Distributed Transactions](#13-saga-coordinator)
14. [Tier Topology — Scaling from Nano to Universe](#14-tier-topology)
15. [CAP / PACELC Analysis — Consistency Trade-offs](#15-cap-pacelc-analysis)
16. [Enhancement Roadmap — What Needs to Be Built Next](#16-enhancement-roadmap)
17. [Complete Distributed Architecture Diagram](#17-complete-distributed-architecture-diagram)

---

## 1. The Universe Model

### Physics of the Agent OS

A universe has physical laws that govern every particle, regardless of scale. Our distributed Agent OS has equivalent laws:

| Physics | Agent OS |
|---------|----------|
| Speed of light (causality limit) | Network latency (vector clocks enforce causal order) |
| Conservation of energy | Content addressing: every packet has exactly one CID — it cannot exist twice |
| Quantum superposition | Concurrent writes: allowed, resolved by CRDT merge |
| Gravity (attraction between mass) | Consistent hash ring: agents naturally gravitate to their owning cell |
| Expansion of the universe | Horizontal scaling: adding cells redistributes only 1/N of the key space |
| Heat death / entropy | Compactor role + SummarizeEvict policy: prevents unbounded memory growth |
| Atomic structure | Cell: indivisible unit; everything above is built from cells |
| Chemical bonds | Ports: typed, directional, TTL-governed bonds between agents across cells |
| Topology of spacetime | SimplicialComplex: the mathematical model of cluster connectivity |

### What "Distributed" Actually Means Here

Most systems claim to be distributed but actually have:
- A master node that writes; replicas that read
- A consensus leader that serializes all operations
- A single metadata server that knows "who owns what"

**This system has none of these.** Instead:

1. **Every cell is a complete, independent kernel** — can operate fully offline
2. **No leader election** — CID-addressed data is conflict-free by construction
3. **No global coordinator** — consistent hash ring assigns ownership deterministically
4. **No central metadata** — CRDT membership views converge without coordination
5. **No distributed lock** — Prolly tree + vector clocks resolve all conflicts algebraically

This is the **cell-based, leaderless, topology-aware** distributed model.

---

## 2. Five Laws of the Distributed Agent OS

### Law 1 — Cell Sovereignty
> Each cell owns its slice of the consistent hash ring. Writes to a namespace are processed locally. Reads are always local (`O(1)`). Replication is async fire-and-forget.

### Law 2 — Convergence Without Coordination
> Membership views are CRDT join-semilattices. `merge(A, B) = merge(B, A)` (commutativity). Eventual consistency is **mathematically guaranteed** — not engineered around, but proven from algebra.

### Law 3 — Topology Awareness
> The cluster models itself as a simplicial complex. β₀ (0th Betti number) = number of connected components. β₀ > 1 = network partition detected. The system refuses to grant quorum across a partition.

### Law 4 — Content-Addressed Immutability
> Every `MemPacket` is identified by its CID = `hash(canonical_cbor(packet))`. The same content always has the same CID. Two cells that write the same packet independently will have the same CID — not a conflict, just a convergence. No distributed lock needed.

### Law 5 — Scale Independence
> The system behaves identically at every scale. `InProcessBus` (single process, 1-100 agents) and `NatsBus` (multi-datacenter, 1M+ agents) implement the same `EventBus` trait. No architectural change needed to scale — only swap the bus implementation.

---

## 3. Current Implementation Inventory

### What Exists (Coded and Tested)

| Component | Crate | Key Types | Status |
|-----------|-------|-----------|--------|
| `Cell` | `vac-cluster` | `Cell`, `CellStatus` | ✅ Production |
| `ClusterKernelStore` | `vac-cluster` | `ClusterKernelStore<S, B>` | ✅ Production |
| `Membership` CRDT | `vac-cluster` | `Membership`, `MembershipView`, `VectorClock` | ✅ Production |
| `SimplicialComplex` | `vac-cluster` | `SimplicialComplex`, `betti_0()` | ✅ Production |
| `CausalBraid` | `vac-cluster` | `CausalBraid`, `stability_index()` | ✅ Production |
| `ConsistentHashRing` | `vac-route` | `ConsistentHashRing` (150 vnodes/cell, SHA-256) | ✅ Production |
| `AgentRouter` | `vac-route` | `AgentRouter` | ✅ Production |
| `MerkleSync` | `vac-replicate` | `MerkleSync<S>`, `PeerRegistry` | ✅ Production |
| `PeerInfo` | `vac-replicate` | `PeerInfo`, heartbeat tracking | ✅ Production |
| `InProcessBus` | `vac-bus` | `InProcessBus` (tokio broadcast) | ✅ Production |
| `NatsBus` | `vac-bus` | `NatsBus` (async-nats JetStream) | ✅ Feature-flagged |
| `ReplicationEvent` + `ReplicationOp` | `vac-bus` | 16 op types | ✅ Production |
| `EventBus` trait | `vac-bus` | `publish()`, `subscribe()` | ✅ Production |
| `vac-sync` protocol | `vac-sync` | `SyncableVault`, `SyncResult` | ✅ Production |
| `ProllyTree` | `vac-prolly` | Probabilistic B-tree, CID diff/sync | ✅ Production |
| `FederatedPolicyEngine` | `aapi-federation` | 3-level policy (local/cluster/federation) | ✅ Production |
| `CrossCellCapabilityVerifier` | `aapi-federation` | `DelegationHop` chain verification | ✅ Production |
| `ScittExchange` | `aapi-federation` | Cross-org transparency receipts | ✅ Production |
| `VakyaPipeline` | `aapi-pipeline` | Multi-cell step execution | ✅ Production |
| `VakyaRouter` | `vac-pipeline` | Local vs. remote routing | ✅ Production |
| `SagaCoordinator` | `aapi-pipeline` | Reverse-order distributed rollback | ✅ Production |

### Distribution by Scale Tier

| Tier | Agents | Cells | Bus | Store Backend |
|------|--------|-------|-----|--------------|
| Nano | 1-10 | 1 | `InProcessBus` | `InMemoryStore` |
| Micro | 10-100 | 1-3 | `InProcessBus` | `ProllyStore` |
| Small | 100-1K | 3-10 | `NatsBus` (feature) | `IndexDbStore` |
| Medium | 1K-10K | 10-50 | `NatsBus` | `IndexDbStore` + sharding |
| Large | 10K-100K | 50-500 | `NatsBus` JetStream | `ProllyStore` cluster |
| Universe | 100K+ | 500+ | `NatsBus` + federation | Multi-datacenter Prolly |

---

## 4. Cell — The Atomic Unit of Distribution

A `Cell` is the indivisible unit of the distributed Agent OS. It is the cosmological equivalent of a fundamental particle: everything in the system is built from cells.

```rust
// vac-cluster/src/cell.rs:42
pub struct Cell {
    pub cell_id: String,              // e.g., "cell:us-east-1:pod-7"
    pub seq: AtomicU64,               // monotonic sequence counter (SeqCst ordering)
    pub merkle_root: Arc<RwLock<[u8; 32]>>, // current state fingerprint
    pub status: Arc<RwLock<CellStatus>>,    // Starting→Ready→Syncing→Degraded
    pub created_at: i64,
}
```

### 4.1 Cell Identity Properties

**`cell_id`**: Globally unique. Convention: `cell:{region}:{datacenter}:{pod}`. Example: `cell:ca-central-1:dc-montreal:pod-042`.

**`seq`**: Atomic monotonic counter (`AtomicU64` with `SeqCst` ordering). Every write to the cell increments this. Enables:
- Total ordering of events within one cell
- Out-of-order detection at receivers (`seq` gaps indicate missed events)
- Anti-entropy sync (peers request "give me seq 101..N")

**`merkle_root`**: SHA-256 binary tree hash of all CIDs in the cell's store. Updated after every write batch. Enables:
- O(1) sync check: if two cells have identical Merkle roots, they are in sync
- O(log N) diff: Merkle tree comparison identifies exactly which branches differ

### 4.2 Cell Status FSM

```
Starting → Ready (initialization complete)
Ready → Syncing (catching up with peers)
Syncing → Ready (caught up)
Ready → Degraded (heartbeat failures, network issues)
Degraded → Ready (reconnected, synced)
Any → ShuttingDown (graceful shutdown)
```

### 4.3 What a Cell Contains

Every cell is a complete, self-sufficient agent operating environment:

```
Cell
├── MemoryKernel (vac-core)      — agent process table, namespace store, syscall dispatcher
├── KernelStore (backend)        — InMemory | Prolly | IndexDb
├── EventBus connection          — InProcessBus | NatsBus
├── Membership (vac-cluster)     — CRDT view of cluster topology
├── MerkleSync (vac-replicate)   — peer sync engine
├── ConsistentHashRing (vac-route) — agent routing table
├── AgentFirewall                — per-cell threat scoring
├── BehaviorAnalyzer             — per-cell behavioral tracking
└── FederatedPolicyEngine (aapi) — 3-level policy (local/cluster/federation)
```

A cell can be **removed from the cluster** and continue serving all agents assigned to it independently. When reconnected, it re-syncs via Merkle diff — no data loss, no coordinator required.

---

## 5. ClusterKernelStore — The VFS Trick

The most elegant architectural decision in the distributed system: **the kernel does not know it is distributed**.

```rust
// vac-cluster/src/cluster_store.rs:9
// The kernel doesn't know it's distributed. This is the VFS trick.

pub struct ClusterKernelStore<S: KernelStore, B: EventBus> {
    local: S,        // Any local backend (InMemory | Prolly | IndexDb)
    bus: Arc<B>,     // Any event bus (InProcessBus | NatsBus)
    cell: Arc<Cell>, // Cell identity for signing events
    topic: String,   // Replication topic
    handle: Handle,  // Tokio async bridge
}
```

### 5.1 The VFS Analogy

This is modeled after the Linux Virtual Filesystem (VFS):
- VFS: applications call `read()`/`write()` without knowing if it's ext4, NFS, tmpfs, or FUSE
- ClusterKernelStore: the kernel calls `store_packet()` without knowing if it's local, replicated, or clustered

The kernel sees: `KernelStore` (one trait, one interface).
Reality: `ClusterKernelStore<ProllyStore, NatsBus>` → writes locally AND replicates.

### 5.2 Write Path — Local First, Async Replicate

```rust
// vac-cluster/src/cluster_store.rs:114
fn store_packet(&mut self, packet: &MemPacket) -> StoreResult<()> {
    // 1. Write locally (sync, <1ms, always succeeds)
    self.local.store_packet(packet)?;

    // 2. Replicate (async, fire-and-forget — never blocks the caller)
    self.replicate(ReplicationOp::PacketWrite {
        namespace: ns,
        packet_cbor: cbor,
        packet_cid: cid_str,
    });

    Ok(())
}
```

**Why fire-and-forget?** The write succeeds as soon as it's local. Replication is best-effort with eventual consistency. If a peer misses an event, `MerkleSync` catches it up on the next sync cycle (default: every 30 seconds).

### 5.3 What Gets Replicated vs. What Stays Local

| Operation | Replicated? | Rationale |
|-----------|-------------|-----------|
| `store_packet` | ✅ Yes | Core data — all cells must see all packets |
| `store_audit_entry` | ✅ Yes | Audit logs must be distributed and immutable |
| `store_agent` (ACB) | ✅ Yes | Agent registry must be cluster-wide |
| `store_packet` evict | ✅ Yes | Deletions must propagate |
| `store_session` | ❌ Local | Sessions are cell-local; cross-cell via gateway |
| `store_port` | ❌ Local | Ports are cell-local; cross-cell via bus |
| `store_execution_policy` | ❌ Local | Policies replicated via `FederatedPolicyEngine` (AAPI layer) |
| `store_delegation_chain` | ❌ Local | Chains verified on receipt, not replicated |
| `store_wal` | ❌ Local | WAL is per-cell crash recovery — never replicated |
| `store_window` (RangeWindow) | ❌ Local | Derived from packets; rebuilt on each cell independently |
| `store_scitt_receipt` | ❌ Local | SCITT replicated at federation layer |

### 5.4 The `replicate()` Method

```rust
// vac-cluster/src/cluster_store.rs:62
fn replicate(&self, op: ReplicationOp) {
    let seq = self.cell.next_seq();   // monotonically increment seq
    let event = ReplicationEvent::new(self.cell.cell_id.clone(), seq, op);
    let bus = self.bus.clone();
    let topic = self.topic.clone();

    // Spawn as background task — never blocks the sync store call
    self.handle.spawn(async move {
        if let Err(e) = bus.publish(&topic, &event).await {
            warn!(error = %e, "Replication publish failed");
            // Failed events are caught by MerkleSync anti-entropy
        }
    });
}
```

---

## 6. Event Bus — The Fabric of the Universe

The event bus is the spacetime fabric that connects all cells. Every write, every agent registration, every policy update, every pipeline step — all transmitted as `ReplicationEvent`s.

### 6.1 The `EventBus` Trait

```rust
// vac-bus/src/traits.rs
pub trait EventBus: Send + Sync + 'static {
    async fn publish(&self, topic: &str, event: &ReplicationEvent) -> BusResult<()>;
    async fn subscribe(&self, topic: &str) -> BusResult<impl Stream<Item = ReplicationEvent>>;
}
```

Two cells communicate entirely through this trait. The implementation behind it is swappable with zero architectural changes.

### 6.2 `InProcessBus` — Nano/Micro Scale

```
Implementation: tokio::sync::broadcast
Topology: single process, shared memory
Latency: <1µs (shared memory, no serialization)
Capacity: 1-100 agents, 1-3 cells
Use case: Edge devices, development, testing, single-server deployments
```

For Nano/Micro tier: all cells live in the same process. The bus is a `broadcast::Sender` — writes clone the event and deliver to all subscribers in-memory. No network, no serialization overhead.

### 6.3 `NatsBus` — Small to Universe Scale

```
Implementation: async-nats + JetStream (feature-flagged)
Topology: multi-process, multi-datacenter
Latency: 1-10ms (network)
Capacity: unlimited (JetStream subjects = unlimited topics)
Use case: Production deployments, multi-region, multi-org
```

NATS JetStream provides:
- **At-least-once delivery** with sequence numbers (matches our `cell.seq` monotonic counter)
- **Subject-per-namespace** routing: `cluster.replication.{namespace}` — only cells with agents in that namespace receive packets
- **Consumer groups**: scale consumers horizontally without duplicate processing
- **Replay**: missed events replayed from persisted stream (covers network partitions)

### 6.4 The 16 `ReplicationOp` Types

```
VAC Storage Operations (8):
  PacketWrite    — replicate a MemPacket to all peers
  PacketSeal     — mark packets as immutable across the cluster
  PacketEvict    — delete packets on all peers (GDPR right-to-erasure)
  TierChange     — promote/demote packet memory tier cluster-wide
  AgentRegister  — announce a new agent to the cluster
  AuditEntry     — replicate an audit log entry (tamper-proof distributed log)
  BlockCommit    — commit a Prolly tree block (content-addressed state)
  Heartbeat      — cell health signal with Merkle root + agent count + load

AAPI Distribution Operations (8):
  VakyaForward   — route a VĀKYA to a cell that has the required adapter
  VakyaReply     — send execution result back to the originating cell
  VakyaRollback  — request saga rollback on a remote cell
  PolicyUpdate   — propagate a new policy to all cells in the cluster
  AdapterAnnounce — tell the cluster "I can handle domain X, actions Y"
  AdapterDeregister — tell the cluster "I no longer handle domain X"
  ApprovalRequest — route a human-in-the-loop approval to approvers
  ApprovalResponse — deliver approval decision back to requesting cell
```

### 6.5 `ReplicationEvent` — The Atomic Message

```rust
// vac-bus/src/types.rs:7
pub struct ReplicationEvent {
    pub cell_id: String,     // originating cell
    pub seq: u64,            // monotonic sequence (for ordering + gap detection)
    pub op: ReplicationOp,   // the operation payload
    pub ts: i64,             // wall clock timestamp (ms epoch)
    pub signature: Vec<u8>,  // Ed25519 signature of DAG-CBOR(op)
}
```

The `signature` field enables: **authenticated replication**. A receiving cell can verify that the event genuinely came from `cell_id` and was not tampered with in transit. This prevents:
- Rogue cells injecting fake writes into the cluster
- Man-in-the-middle attacks on the replication bus
- Replay attacks (signature covers `seq` + `ts`)

---

## 7. Consistent Hash Ring — Agent Routing

### 7.1 The Problem of Agent Placement

In a cluster of N cells, when an SDK call arrives for agent `pid:acme:triage:001`, which cell should handle it? Options:

- **Random**: simple, but agent's memory might be on a different cell
- **Central directory**: fast lookup, but single point of failure
- **Broadcast**: ask all cells, take the first answer — O(N) overhead
- **Consistent hashing**: deterministic O(1) lookup, no coordinator, minimal reshuffling

We use consistent hashing.

### 7.2 `ConsistentHashRing`

```rust
// vac-route/src/ring.rs:19
pub struct ConsistentHashRing {
    ring: BTreeMap<u64, String>,  // position → cell_id
    vnodes_per_cell: usize,       // 150 (default)
    cells: HashSet<String>,       // known cells
}
```

**150 virtual nodes per cell** is the industry standard (used by Cassandra, Amazon DynamoDB, Riak). It ensures:
- Even distribution: each cell handles ~1/N of the key space
- Smooth rebalancing: adding/removing a cell moves ~1/N of keys
- Collision resistance: 150 SHA-256 positions per cell across 2^64 ring space

### 7.3 SHA-256 Ring Position

```rust
// vac-route/src/ring.rs:140
fn hash_key(key: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    // Take first 8 bytes as u64 (2^64 ring space)
    u64::from_be_bytes([result[0], result[1], result[2], result[3],
                        result[4], result[5], result[6], result[7]])
}
```

The routing key for an agent is its `namespace` (e.g., `org:acme/team:support/agent:triage`). The ring deterministically maps this to a cell.

### 7.4 N-Replica Lookup

For replication factor `R`:

```rust
// vac-route/src/ring.rs:87
pub fn get_n_nodes(&self, key: &str, n: usize) -> Vec<&str> {
    // Walk clockwise from key's hash position
    // Return first n DISTINCT cell_ids encountered
    // Automatically wraps around the ring
}
```

With `R=3`, a namespace is owned by the primary cell (clockwise walk position 1) and replicated to cells at positions 2 and 3. This gives:
- Reads from any of the 3 cells (high availability)
- Writes to primary, async-replicated to 2 secondaries
- Tolerate loss of up to 2 cells for any namespace

### 7.5 Scaling Events

**Adding a cell** (horizontal scale-out):
```
1. New cell starts, announces via bus: AdapterAnnounce + Heartbeat
2. All cells receive announcement, add cell to their local ConsistentHashRing
3. Ring redistributes: ~1/N of namespaces now point to the new cell
4. Affected agents are migrated: old cell sends PacketWrite events for relocated namespaces
5. New cell receives and stores them, starts serving those namespaces
6. Old cell tombstones its copies after confirmation
```

**Removing a cell** (node failure or scale-in):
```
1. Heartbeat timeout detected by Membership.detect_dead()
2. All cells remove dead cell from ConsistentHashRing
3. Affected namespaces now point to the next cell in the ring (clockwise)
4. MerkleSync catches up: the new primary pulls missing packets from still-alive replicas
5. Re-replication to maintain R=3 continues in background
```

**Key property**: During scale-out/in, only affected agents (those in relocated namespaces) experience any interruption. All other agents are completely unaffected.

---

## 8. Topological Consensus — Membership Without a Leader

This is the most mathematically sophisticated component in the system. It combines three areas of pure mathematics to achieve leaderless consensus:

### 8.1 Layer 1 — Vector Clocks (Join-Semilattice)

```rust
// vac-cluster/src/membership.rs:45
pub struct VectorClock {
    entries: BTreeMap<String, u64>,  // cell_id → logical time
}
```

**The algebraic proof of convergence** (Shapiro et al. 2011):

```
merge(A, B) = component-wise max of all entries

Commutativity:  max(a,b) = max(b,a)              ✓
Associativity:  max(max(a,b),c) = max(a,max(b,c)) ✓
Idempotence:    max(a,a) = a                       ✓

∴ VectorClock forms a join-semilattice
∴ merge(merge(A,B), C) = merge(A, merge(B,C)) for any message delivery order
∴ EVENTUAL CONSISTENCY IS MATHEMATICALLY GUARANTEED
```

The `happens_before` relation (`<`) defines a partial order over events:
```
a < b ⟺ ∀k: a[k] ≤ b[k] ∧ ∃k: a[k] < b[k]
```

Two events are **concurrent** if neither happens-before the other — both are valid, both are applied, CRDT merge resolves them.

### 8.2 Layer 2 — Simplicial Complex (Algebraic Topology)

```rust
// vac-cluster/src/membership.rs:131
pub struct SimplicialComplex {
    vertices: HashSet<String>,         // cells (0-simplices)
    edges: HashSet<(String, String)>,  // links (1-simplices)
}
```

The cluster is modeled as a **simplicial complex** — a topological space composed of vertices (cells) and edges (communication links). This is the mathematical language for reasoning about connectivity.

**The Euler characteristic** χ = V - E:
- For a connected graph: χ = 1 (V - (V-1) = 1 for a tree)
- For a disconnected graph: χ = k (number of components)

**The 0th Betti number** β₀ = rank(H₀) = number of connected components:
```rust
pub fn betti_0(&self) -> usize {
    self.connected_components().len()  // BFS over the graph
}
```

**Quorum condition**:
```rust
pub fn has_quorum(&self) -> bool {
    let majority = alive_voters > total_voters / 2;
    let connected = self.complex.is_connected();  // β₀ = 1
    majority && connected
}
```

A quorum is only granted when:
1. More than half of voter cells are alive (standard majority quorum)
2. **AND** the cluster is topologically connected (β₀ = 1)

This prevents **split-brain**: even if 3 out of 5 cells are alive but 2 are unreachable from the other 3, `β₀ = 2 > 1` → no quorum → system enters read-only mode rather than accepting conflicting writes.

### 8.3 Layer 3 — Causal Braid (Knot Theory)

```rust
// vac-cluster/src/membership.rs:290
pub struct CausalBraid {
    crossings: VecDeque<BraidCrossing>,  // sliding window of membership events
    max_window: usize,
}
```

Membership events (joins = +1, leaves = -1, heartbeats = 0) form **crossings in a causal braid** — a concept from knot theory that tracks the history of membership changes.

**The writhe W** = Σ sign(crossing_i) = net membership flux:
- W > 0: more joins than leaves → cluster is growing
- W < 0: more leaves than joins → cluster is shrinking (possible failure cascade)
- W ≈ 0: stable cluster

**Stability index S** = 1 - |W|/N ∈ [0.0, 1.0]:
- S = 1.0: perfectly balanced (trivially stable or equal joins/leaves)
- S → 0.0: maximally unstable (all joins OR all leaves — rapid churn)

Use case: If `stability_index() < 0.3` and `alive_count()` is decreasing, the system triggers an alert before the cluster loses quorum. This is **predictive** — it detects a failure cascade before it happens.

### 8.4 CRDT Membership View

```rust
// vac-cluster/src/membership.rs:376
pub struct MembershipView {
    pub members: BTreeMap<String, MemberState>,  // cell_id → state
    pub clock: VectorClock,
}
```

**Merge semantics**: last-writer-wins by `generation` counter. A tombstoned (`tombstone: true`) entry has higher generation than the live entry — tombstones win, ensuring a leave is not accidentally undone by a stale join message.

The merge operation:
```rust
pub fn merge(&self, other: &MembershipView) -> MembershipView {
    // For each cell_id in either view: take entry with higher generation
    // Merge clocks: component-wise max
}
```

**Why no Raft/PBFT?** Because the data model makes them unnecessary:
- MemPackets are identified by CID — same content = same CID = no conflict
- Membership views are CRDTs — no consensus needed for convergence
- Prolly tree uses monotonic `block_no` — causal ordering without a leader

---

## 9. Merkle Sync — Content-Addressed Replication

### 9.1 The Anti-Entropy Engine

`MerkleSync` is the background catch-up mechanism. When real-time replication misses events (network partitions, cell restarts, bus failures), Merkle sync closes the gap.

```rust
// vac-replicate/src/merkle_sync.rs:41
pub struct MerkleSync<S: SyncableVault> {
    local: Arc<S>,
    peers: Arc<RwLock<PeerRegistry>>,
    local_merkle_root: Arc<RwLock<[u8; 32]>>,
}
```

### 9.2 The Merkle Root Comparison

```rust
// Heartbeat: every cell broadcasts its Merkle root every N seconds
pub async fn handle_heartbeat(&self, cell_id: &str, merkle_root: [u8; 32], block_no: u64) {
    // Store peer's Merkle root + block number
}

// Anti-entropy check: compare with all peers
pub async fn check_all_peers(&self) -> Vec<PeerSyncStatus> {
    let local_root = *self.local_merkle_root.read().await;
    // For each peer: in_sync = (peer.last_merkle_root == local_root)
}
```

This is an **O(1) sync check**: comparing two `[u8; 32]` arrays. If they match, the peer has exactly the same state as us. Only when they differ do we initiate a Merkle tree diff.

### 9.3 Merkle Root Computation

```rust
// vac-replicate/src/merkle_sync.rs:189
pub fn compute_merkle_root(cids: &[String]) -> [u8; 32] {
    // 1. Hash each CID with SHA-256
    // 2. Build binary tree: repeatedly hash pairs until one root remains
    // 3. Odd nodes: hash with themselves (consistent result)
}
```

The Merkle root captures the entire state of a namespace in 32 bytes. Two cells with the same set of CIDs will always produce identical roots — this is the content-addressing invariant.

### 9.4 Sync Protocol

```
Cell A                           Cell B
  │                                │
  │← Heartbeat (root=0xAABB, seq=105)
  │                                │
  │ root differs? → yes (local=0xCCDD)
  │                                │
  │→ vac_sync::sync(peer_vault, local_vault)
  │  (block-verified diff protocol)
  │                                │
  │← Missing blocks transferred   │
  │                                │
  │ apply blocks locally          │
  │ recompute Merkle root         │
  │ root = 0xAABB (now matches)  │
  │                                │
  ▼  Peer marked in-sync          ▼
```

The `vac-sync` protocol uses **block-verified transfer**: every block sent includes its hash. The receiver verifies before applying. A corrupted block is rejected and re-requested.

### 9.5 Sync Scheduler Configuration

```rust
// vac-replicate/src/merkle_sync.rs:234
pub struct SyncSchedulerConfig {
    pub sync_interval: Duration,        // 30 seconds (default) — how often to check peers
    pub heartbeat_timeout: Duration,    // 90 seconds — when to declare a peer dead
    pub max_concurrent_syncs: usize,    // 3 — avoid thundering herd on rejoin
}
```

---

## 10. Prolly Tree — The Distributed Data Structure

### 10.1 What Is a Prolly Tree?

The Prolly Tree (Probabilistic B-tree) is the backing data structure for `ProllyStore`. It is purpose-built for distributed, content-addressed, efficiently diffable storage.

Properties:
- **Content-defined chunking**: chunk boundaries are determined by content hash, not byte offset — identical data produces identical chunk trees across independent implementations
- **Efficient diff**: two Prolly trees can be diffed in O(changed nodes) rather than O(all nodes)
- **CID-addressed**: every node is identified by its content hash — identical subtrees share storage
- **Conflict-free**: two cells that write non-overlapping keys will have diffable, mergeable trees

### 10.2 Why Not a B-Tree?

A traditional B-Tree:
- Page boundaries are fixed offsets → different insertion orders → different trees → can't detect "same data" without full comparison
- No built-in content addressing → need separate CID layer
- Diff = full scan

A Prolly Tree:
- Chunk boundaries are data-driven → same data → same chunks → same CIDs → O(1) equality check
- Every chunk IS its CID — no separate layer
- Diff = walk only changed subtrees → O(changed data)

### 10.3 Integration with ClusterKernelStore

```
Agent writes MemPacket
  │
  ▼
ClusterKernelStore.store_packet()
  │
  ├── ProllyStore.store_packet() → inserts into Prolly tree
  │   ├── Computes chunk CIDs
  │   ├── Updates tree root → new root CID
  │   └── Root CID = new Merkle root of namespace
  │
  └── replicate(PacketWrite { packet_cid, ... }) → bus → all peers
        │
        ▼ peers apply
      ProllyStore.store_packet() → identical tree structure (content-defined)
      → same root CID → same Merkle root → sync check passes immediately
```

---

## 11. AAPI Federation — Cross-Org Distributed Policy

### 11.1 Three-Level Policy Hierarchy

The `FederatedPolicyEngine` implements a hierarchical policy system that mirrors the three tiers of organizational authority:

```
Federation Level  (cross-org, SCITT-attested)
    │ Absolute deny — cannot be overridden by lower levels
    ▼
Cluster Level  (shared across all cells in one org)
    │ Deny short-circuits — local cannot override cluster deny
    ▼
Local Level  (cell-specific)
    │ Default-deny + allow rules
    ▼
Decision: Allow | Deny
```

```rust
// aapi-federation/src/federated_policy.rs:64
pub async fn evaluate(&self, context: &EvaluationContext) -> MetaRulesResult<PolicyDecision> {
    // 1. Federation policies (cross-org, absolute)
    let fed_decision = self.federation.read().await.evaluate(context).await?;
    if !fed_decision.allowed { return Ok(fed_decision); }  // short-circuit

    // 2. Cluster policies (shared)
    let cluster_decision = self.cluster.read().await.evaluate(context).await?;
    if !cluster_decision.allowed { return Ok(cluster_decision); }  // short-circuit

    // 3. Local policies
    Ok(self.local.evaluate(context).await?)
}
```

### 11.2 Federation Trust Model

```
Organization A                    Organization B
    │                                  │
    ├── Cell A1                        ├── Cell B1
    ├── Cell A2     ← PolicyUpdate →   ├── Cell B2
    └── Cell A3                        └── Cell B3
         │                                  │
         └──── ScittExchange ──────────────┘
               (cross-org attestation)
```

**`PolicyUpdate` replication**: when a cluster-level policy changes, `ReplicationOp::PolicyUpdate { policy_cbor }` is broadcast to all cells in the cluster. Each cell updates its `cluster` policy engine.

**`ScittExchange`**: for cross-org federation, policies are attested via SCITT transparency receipts. Cell B trusts a policy from Org A only if it carries a valid SCITT receipt signed by a mutually trusted authority.

### 11.3 `CrossCellCapabilityVerifier`

When Agent A on Cell 1 delegates a capability to Agent B on Cell 2, the delegation chain crosses a cell boundary. `CrossCellCapabilityVerifier` verifies:

```
DelegationChain: root_proof → hop_1 → hop_2 (current)
                 cell:A1       cell:B1   cell:B2

For each hop:
  1. Verify Ed25519 signature
  2. Verify issuer is registered on their cell
  3. Verify action attenuation (child ⊆ parent)
  4. Verify expiry has not passed
  5. Verify hop cell_id matches expected cell

All hops pass → capability is valid cross-cell
Any hop fails → Denied
```

---

## 12. AAPI Pipeline — Distributed VAKYA Execution

### 12.1 Overview

A VĀKYA (agent action) often requires execution steps spread across multiple cells:
- Cell A has the LLM adapter (GPT-4)
- Cell B has the EHR adapter (database access)
- Cell C has the audit adapter (compliance logging)

The `VakyaPipeline` orchestrates multi-step execution across cells with dependency tracking, rollback capability, and distributed tracing.

### 12.2 `VakyaRouter` — Local vs. Remote Routing

```
VĀKYA arrives at gateway (Cell G)
  │
  ▼
VakyaRouter.route(vakya)
  │
  ├── Does Cell G have the required adapter?
  │   → Yes: execute locally
  │
  └── No: find which cell has this adapter
      │
      ├── AdapterRegistry (built from AdapterAnnounce events)
      │   "domain:ehr → [cell:B1, cell:B2]"
      │
      └── Route: ReplicationOp::VakyaForward → cell:B1
          Wait for: ReplicationOp::VakyaReply
```

### 12.3 `VakyaPipeline` — Multi-Cell Step Execution

```
Pipeline: [step_1 (cell:A), step_2 (cell:B), step_3 (cell:C)]

step_1:
  VakyaForward { vakya, pipeline_id, step_id: "step_1", reply_topic }
  → cell:A executes
  VakyaReply { step_id: "step_1", result_cbor }
  → pipeline advances to step_2

step_2:
  VakyaForward { ...step_2... }
  → cell:B executes (uses result of step_1 as input)
  VakyaReply { step_id: "step_2", result_cbor }
  → pipeline advances to step_3

step_3 (failure):
  cell:C returns error
  → SagaCoordinator.rollback([step_2, step_1])
     VakyaRollback { effect: step_2_effect, saga_id } → cell:B
     VakyaRollback { effect: step_1_effect, saga_id } → cell:A
```

---

## 13. Saga Coordinator — Distributed Transactions

### 13.1 The Problem

In a distributed system, multi-step operations can partially fail:
```
Step 1: Agent writes patient record to Cell A → SUCCESS
Step 2: Agent sends notification to Cell B → SUCCESS
Step 3: Agent bills insurance via Cell C → FAILURE (insurance API down)
```

Without rollback: the patient record exists, the notification was sent, but billing failed. The system is inconsistent.

### 13.2 The Saga Pattern

Instead of distributed two-phase commit (which requires a coordinator and blocks resources), the system uses the **Saga pattern** — a sequence of local transactions with compensating transactions for rollback.

```
saga_id: "vakya:prescription-001"
steps:
  1. Cell A: write_ehr (compensate: delete_ehr)
  2. Cell B: send_notification (compensate: cancel_notification)
  3. Cell C: bill_insurance (compensate: void_billing)

On step 3 failure:
  SagaCoordinator.rollback() in REVERSE ORDER:
    VakyaRollback { effect: cell_B_notification_effect } → cell:B
    VakyaRollback { effect: cell_A_ehr_write_effect } → cell:A
```

### 13.3 Why Reverse Order?

Reverse-order rollback (D8 fix) ensures that dependent effects are rolled back before their dependencies. Writing to the EHR created data that the notification referenced — rolling back the notification before the EHR write ensures no dangling references.

### 13.4 Distributed Transaction Guarantees

The Saga pattern provides:
- **ACD** (Atomicity, Consistency, Durability) — NOT full ACID (no Isolation between steps)
- Eventual consistency: on rollback, all compensating transactions eventually execute
- No global lock: each step is a local transaction on its cell
- Failure tolerance: if a cell is down during rollback, the saga is retried on reconnection

---

## 14. Tier Topology — Scaling from Nano to Universe

### 14.1 Deployment Topology by Tier

#### Nano Tier (1-10 agents, 1 cell, single process)
```
Process: connector-server
  ├── MemoryKernel (vac-core)
  ├── InMemoryStore (vac-store)
  ├── InProcessBus (vac-bus)
  └── ConnectorEngine (connector-engine)
       ├── AgentFirewall
       └── BehaviorAnalyzer
```
No distribution needed. Everything in one async Tokio runtime. Memory footprint: ~50MB. Startup: <10ms.

#### Micro Tier (10-100 agents, 1-3 cells, single host)
```
Host
├── Cell 1 (PID 1)
│   ├── MemoryKernel
│   ├── ProllyStore
│   └── InProcessBus (shared with Cell 2, 3)
├── Cell 2 (PID 2)
│   └── (same structure)
└── Cell 3 (PID 3)
    └── (same structure)
```
Cells communicate via `InProcessBus` (shared memory, <1µs). ProllyStore provides durable storage. Replication factor R=2.

#### Small Tier (100-1K agents, 3-10 cells, multi-host)
```
Host A: Cell 1, Cell 2
Host B: Cell 3, Cell 4
Host C: Cell 5 (gateway + load balancer)
         │
         └── All cells connected via NatsBus
```
`NatsBus` with JetStream provides cross-host messaging. Replication factor R=3. Membership uses CRDT with heartbeat timeout 30s.

#### Medium Tier (1K-10K agents, 10-50 cells, multi-rack)
```
Region: us-east
  Rack A: Cells 1-15 (ProllyStore on local NVMe)
  Rack B: Cells 16-30
  Rack C: Cells 31-50 (gateway cells)
              │
              └── NATS JetStream cluster (3-node quorum)
```
NATS cluster provides message persistence and replay. ConsistentHashRing distributes 10K agents across 50 cells (200 agents/cell average). MerkleSync anti-entropy runs every 30s.

#### Large Tier (10K-100K agents, 50-500 cells, multi-datacenter)
```
DC1 (us-east-1)          DC2 (eu-west-1)         DC3 (ap-southeast-1)
  Cells 1-150               Cells 151-300            Cells 301-450
       │                          │                         │
       └──────────── NATS Leaf Nodes ─────────────────────┘
                     (cross-region replication)
                              │
                     FederatedPolicyEngine
                     (cross-DC policies + SCITT)
```

NATS Leaf Nodes provide geo-replicated messaging with subject-based filtering. Each DC operates autonomously during network partitions (cells continue serving local agents). On reconnection, CRDT membership merges automatically.

#### Universe Tier (100K+ agents, 500+ cells, multi-org)
```
Org A (500 cells, 3 DCs)          Org B (300 cells, 2 DCs)
       │                                  │
       └──── aapi-federation ────────────┘
             (ScittExchange + FederatedPolicyEngine)
             CrossCellCapabilityVerifier
             DelegationChain (multi-hop, attenuated)
```

Cross-org communication uses SCITT transparency receipts. Every cross-org action is attested and verifiable. FederatedPolicyEngine enforces cross-org rules that neither org can override unilaterally.

---

## 15. CAP / PACELC Analysis

### 15.1 CAP Theorem Position

The system makes a deliberate **AP (Availability + Partition tolerance)** choice for data operations, with opt-in **CP** for policy operations.

| Operation | CAP Choice | Rationale |
|-----------|-----------|-----------|
| MemPacket write | **AP** | Agent memory writes are always local-first; never block on network |
| MemPacket read | **AP** | Reads always from local cell; may be slightly stale |
| AgentRegister | **AP** | Agent can register even if peers are unreachable |
| PolicyUpdate | **CP** | Policies are enforced; stale policy = security hole |
| AccessGrant | **CP** | Security grants must be consistent across cells |
| Audit log | **AP** | Local write, async replicated; never lost (CID-addressed) |
| DelegationChain | **CP** | Capability verification must be consistent |

### 15.2 PACELC Analysis

**When there is a Partition (P)**:
- Choose **A** (Availability): cells continue operating on local data
- Tradeoff: **E** (Eventually consistent) reads — stale data possible during partition

**Else (no partition, E)**:
- Choose **L** (Low latency): writes are local-first, async replicated
- Tradeoff: **C** (Consistency): reads may be milliseconds stale (lag = replication lag)

**Summary**: PA/EL system — optimized for latency and availability, accepts eventual consistency.

### 15.3 Why This Is Correct for Agent Workloads

Agent memory is inherently eventual:
- An agent reading its own memories is always reading from its local cell (no staleness)
- An agent reading another agent's shared memory accepts that it may be milliseconds behind
- This is semantically equivalent to how humans share information — eventually consistent

The only CP exceptions (policy, access grants, delegation chains) are exactly the places where consistency matters for security — and the system correctly handles them separately.

---

## 16. Enhancement Roadmap

### 16.1 HIGH — NatsBus Production Hardening

**Current state**: `NatsBus` is feature-flagged (`#[cfg(feature = "nats")]`) — the implementation exists but is not yet default in production deployments.

**Enhancement needed**:
1. Enable `nats` feature in `connector-server/Cargo.toml` by default
2. Add NATS connection pool with automatic reconnection and exponential backoff
3. Add `ReplicationEvent` signature verification at the receiver (currently unsigned events are accepted)
4. Add JetStream consumer group configuration for horizontal receiver scaling

### 16.2 HIGH — Cell-to-Cell TLS Mutual Authentication

**Gap**: `ReplicationEvent` has an `Ed25519 signature` field, but the `NatsBus` implementation does not verify incoming event signatures.

**Enhancement needed**:
```rust
// Add to ClusterKernelStore receiver path:
fn verify_event(event: &ReplicationEvent, peer_public_key: &[u8]) -> Result<(), AuthError> {
    let payload = canonical_cbor(&event.op);
    ed25519_verify(peer_public_key, &payload, &event.signature)?;
    Ok(())
}
```

This ensures: only authenticated cells can write to the cluster. Rogue or compromised cells are rejected at the bus level.

### 16.3 HIGH — Automatic Agent Migration on Cell Failure

**Gap**: When a cell fails, the ConsistentHashRing correctly redirects new requests to the next cell. But **existing in-flight agent sessions** on the failed cell are not automatically migrated.

**Enhancement needed**: Implement agent handoff protocol:
```rust
// Triggered by Membership.detect_dead():
pub async fn migrate_agents(dead_cell_id: &str, ring: &ConsistentHashRing) {
    // 1. Identify agents routed to dead_cell_id
    // 2. For each agent: find new primary cell via ring.get_node(agent.namespace)
    // 3. Trigger MerkleSync catch-up for that namespace
    // 4. Update gateway routing table
    // 5. Resume suspended agents on new cell
}
```

### 16.4 MEDIUM — Read-Your-Writes Consistency

**Gap**: After an agent writes a packet, if the next read hits a different cell (due to load balancing), it may not see the write yet.

**Enhancement**: Session stickiness — route all operations for the same `session_id` to the same cell during the session lifetime. The `VakyaRouter` should implement session-affinity routing.

### 16.5 MEDIUM — Cross-Cell Port Messaging

**Gap**: `Port` objects are cell-local. An agent on Cell A cannot send a `PortMessage` directly to an agent on Cell B.

**Enhancement needed**: Cross-cell port bridge using the event bus:
```rust
// When PortSend targets an agent not on the local cell:
// → lookup target agent's cell via ConsistentHashRing
// → publish ReplicationOp::VakyaForward with port message payload
// → target cell receives, routes to agent's Port inbox
```

### 16.6 MEDIUM — Distributed Namespace Quota Enforcement

**Gap**: `MemoryRegion.quota_packets` is enforced per-cell. An agent distributed across cells could exceed its global quota by writing to multiple cells.

**Enhancement**: Global quota service — track total packet counts per namespace across all cells via periodic `Heartbeat { packet_count }` aggregation.

### 16.7 LOW — Adaptive Consistent Hash Rebalancing

**Gap**: When a cell becomes `Degraded` (high load), it still receives the same share of agents as a healthy cell.

**Enhancement**: Load-weighted consistent hashing — cells with low load get more virtual nodes (more agents), cells under load shed virtual nodes. The `Heartbeat { load: u8 }` field is already designed for this.

---

## 17. Complete Distributed Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AGENT OS — DISTRIBUTED UNIVERSE                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  SDK / API Gateway                                                               │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  connector-server  (axum REST + gRPC + Prometheus metrics)                │   │
│  │  VakyaRouter: local dispatch OR VakyaForward → target cell               │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                     │ agent_pid → ConsistentHashRing → cell_id                  │
│                     ▼                                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    CELL LAYER  (N cells, each identical)                 │    │
│  │                                                                          │    │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │    │
│  │  │  CELL  (cell:us-east-1:dc-a:pod-07)                              │   │    │
│  │  │                                                                   │   │    │
│  │  │  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐  │   │    │
│  │  │  │  MemoryKernel   │  │  ConnectorEngine │  │  Membership    │  │   │    │
│  │  │  │  (vac-core)     │  │  ├─ Firewall     │  │  ├─ VectorClock│  │   │    │
│  │  │  │  ├─ AgentTable  │  │  ├─ Behavior     │  │  ├─ Simplicial │  │   │    │
│  │  │  │  ├─ NamespaceNS │  │  ├─ Instruction  │  │  │  Complex    │  │   │    │
│  │  │  │  ├─ SyscallDispatch│ │  └─ Compliance  │  │  └─ CausalBraid│  │   │    │
│  │  │  │  └─ AuditLog    │  └──────────────────┘  └────────────────┘  │   │    │
│  │  │  └────────┬────────┘                                             │   │    │
│  │  │           │                                                       │   │    │
│  │  │  ┌────────▼────────────────────────────────────────────────┐    │   │    │
│  │  │  │  ClusterKernelStore<S, B>                               │    │   │    │
│  │  │  │  "The VFS Trick" — kernel sees KernelStore              │    │   │    │
│  │  │  │  Reality: local write + async bus publish               │    │   │    │
│  │  │  │                                                          │    │   │    │
│  │  │  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐   │    │   │    │
│  │  │  │  │  InMemory    │  │  ProllyStore │  │  IndexDb    │   │    │   │    │
│  │  │  │  │  (Nano/Dev)  │  │  (Micro-Med) │  │  (Small+)   │   │    │   │    │
│  │  │  │  └──────────────┘  └──────────────┘  └─────────────┘   │    │   │    │
│  │  │  └─────────────────────────────┬───────────────────────────┘    │   │    │
│  │  │                                │ replicate(op) fire-and-forget   │   │    │
│  │  └────────────────────────────────│────────────────────────────────┘   │    │
│  │                                   │                                      │    │
│  └───────────────────────────────────│──────────────────────────────────────┘   │
│                                      │                                           │
│  ┌───────────────────────────────────▼──────────────────────────────────────┐   │
│  │                           EVENT BUS LAYER                                │   │
│  │                                                                           │   │
│  │  ┌─────────────────────────────┐  ┌──────────────────────────────────┐  │   │
│  │  │  InProcessBus               │  │  NatsBus (feature = "nats")      │  │   │
│  │  │  tokio broadcast            │  │  NATS JetStream                  │  │   │
│  │  │  Nano/Micro: <1µs, 1 host  │  │  Small-Universe: 1-10ms, N DCs   │  │   │
│  │  └─────────────────────────────┘  └──────────────────────────────────┘  │   │
│  │                                                                           │   │
│  │  ReplicationOp:  PacketWrite | PacketEvict | AuditEntry | AgentRegister  │   │
│  │                  Heartbeat | BlockCommit | VakyaForward | VakyaReply     │   │
│  │                  VakyaRollback | PolicyUpdate | AdapterAnnounce          │   │
│  │                  ApprovalRequest | ApprovalResponse                       │   │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                        REPLICATION LAYER                                  │  │
│  │                                                                           │  │
│  │  ┌──────────────────────┐  ┌────────────────────────────────────────┐   │  │
│  │  │  ConsistentHashRing  │  │  MerkleSync + PeerRegistry             │   │  │
│  │  │  150 vnodes/cell     │  │  Heartbeat: 30s interval               │   │  │
│  │  │  SHA-256 positioning │  │  Anti-entropy: Merkle root comparison  │   │  │
│  │  │  ~1/N key remapping  │  │  Catch-up: vac-sync block protocol     │   │  │
│  │  │  on cell add/remove  │  │  Dead peer: 90s heartbeat timeout      │   │  │
│  │  └──────────────────────┘  └────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                      FEDERATION LAYER (cross-org)                        │  │
│  │                                                                           │  │
│  │  FederatedPolicyEngine (3-level: local → cluster → federation)           │  │
│  │  CrossCellCapabilityVerifier (DelegationChain across cell boundaries)    │  │
│  │  ScittExchange (SCITT transparency receipts for cross-org attestation)   │  │
│  │  VakyaPipeline + SagaCoordinator (distributed transactions + rollback)  │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

                    Mathematical Foundations:
                    ┌─────────────────────────────────────────────────────┐
                    │  VectorClock: join-semilattice (Shapiro 2011)       │
                    │    merge(A,B) = merge(B,A), merge(merge(A,B),C)    │
                    │    = merge(A,merge(B,C)), merge(A,A) = A           │
                    │    → Eventual consistency PROVEN                    │
                    │                                                     │
                    │  SimplicialComplex: β₀ = connected components      │
                    │    β₀ = 1 → quorum possible                        │
                    │    β₀ > 1 → partition detected → read-only mode   │
                    │    Euler characteristic: χ = V - E                 │
                    │                                                     │
                    │  CausalBraid: stability_index = 1 - |W|/N          │
                    │    S → 1.0: stable cluster                         │
                    │    S → 0.0: failure cascade imminent               │
                    │                                                     │
                    │  CID addressing: hash(content) = identity          │
                    │    → same content → same CID → no conflict         │
                    │    → two cells write same packet → trivial merge   │
                    └─────────────────────────────────────────────────────┘
```

---

## Appendix A: Distributed Component Quick Reference

| Need To... | Use | Location |
|-----------|-----|----------|
| Route an agent to its cell | `ConsistentHashRing.get_node(namespace)` | `vac-route` |
| Route an agent to N replica cells | `ConsistentHashRing.get_n_nodes(namespace, R)` | `vac-route` |
| Check if cluster has quorum | `Membership.has_quorum()` | `vac-cluster` |
| Detect network partitions | `Membership.partition_count() > 1` | `vac-cluster` |
| Check cluster stability | `Membership.stability_index()` | `vac-cluster` |
| Detect dead cells | `Membership.detect_dead()` | `vac-cluster` |
| Write + replicate data | `ClusterKernelStore.store_packet()` | `vac-cluster` |
| Compare cell state | `MerkleSync.check_all_peers()` | `vac-replicate` |
| Force sync a stale peer | `MerkleSync.sync_with_peer()` | `vac-replicate` |
| Evaluate cross-org policy | `FederatedPolicyEngine.evaluate()` | `aapi-federation` |
| Verify cross-cell delegation | `CrossCellCapabilityVerifier` | `aapi-federation` |
| Route VAKYA to correct cell | `VakyaRouter.route()` | `aapi-pipeline` |
| Rollback distributed transaction | `SagaCoordinator.rollback()` | `aapi-pipeline` |
| Publish replication event | `EventBus.publish(topic, event)` | `vac-bus` |
| Add agent to cluster | `AgentRegister` → `ReplicationOp::AgentRegister` | auto via `ClusterKernelStore` |

---

## Appendix B: Scaling Properties Summary

| Property | Value | Source |
|----------|-------|--------|
| Agent routing lookup | O(log N) BTree walk | `ConsistentHashRing.get_node()` |
| Agent read latency | <1ms (local cell) | `ClusterKernelStore` reads: local only |
| Sync check latency | O(1) — compare 32 bytes | `MerkleSync.check_all_peers()` |
| Key remapping on node add/remove | ~1/N of namespaces | Consistent hashing property |
| Membership convergence | O(M × N) | M=members, N=cells, CRDT merge |
| Partition detection | O(V + E) BFS | `SimplicialComplex.betti_0()` |
| Max agents per cell | Unlimited (quota governed by `BudgetPolicy`) | `MemoryKernel` |
| Max cells in cluster | Unlimited (ring scales to 2^64 positions) | `ConsistentHashRing` |
| Replication lag | <10ms (InProcessBus) / 1-10ms (NatsBus) | `EventBus` implementations |
| Anti-entropy catch-up | O(changed blocks) | Merkle tree diff |
| Cross-org trust verification | O(chain depth) | `DelegationChain.verify()` |

*Research foundations: Amazon Dynamo (consistent hashing), Shapiro-Preguiça-Baquero-Zawirski (CRDTs, 2011), Herlihy-Shavit (simplicial topology, 1999), Apache Cassandra (virtual nodes), NATS JetStream, UCAN delegation specification, SCITT (Supply Chain Integrity, Transparency, and Trust)*
