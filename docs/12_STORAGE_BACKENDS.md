# Storage Backends

> KernelStore trait, all backends, redb, EncryptedStore, cluster
> Source: `vac/crates/vac-core/src/store.rs`, `vac/crates/vac-store/`, `connector/crates/connector-engine/src/redb_store.rs`

---

## KernelStore Trait

All storage is abstracted behind `KernelStore`. The kernel never knows which backend is in use.

```rust
pub trait KernelStore {
    fn store_packet(&mut self, packet: &MemPacket) -> Result<(), String>;
    fn load_packet(&self, cid: &Cid) -> Result<Option<MemPacket>, String>;
    fn delete_packet(&mut self, cid: &Cid) -> Result<bool, String>;
    fn load_packets_by_namespace(&self, ns: &str) -> Result<Vec<MemPacket>, String>;
    fn store_session(&mut self, session: &SessionEnvelope) -> Result<(), String>;
    fn load_session(&self, id: &str) -> Result<Option<SessionEnvelope>, String>;
    fn store_agent(&mut self, agent: &AgentControlBlock) -> Result<(), String>;
    fn load_agent(&self, pid: &str) -> Result<Option<AgentControlBlock>, String>;
    fn store_audit(&mut self, entry: &KernelAuditEntry) -> Result<(), String>;
    fn load_audit_range(&self, from: u64, to: u64) -> Result<Vec<KernelAuditEntry>, String>;
    fn store_window(&mut self, window: &RangeWindow) -> Result<(), String>;
    fn total_objects(&self) -> usize;
    // WAL methods
    fn store_wal(&mut self, entry: &WalEntry) -> Result<(), String>;
    fn load_wal(&self) -> Result<Vec<WalEntry>, String>;
    fn clear_wal(&mut self) -> Result<(), String>;
    // Port, ExecutionPolicy, DelegationChain methods
    fn store_port(&mut self, port: &Port) -> Result<(), String>;
    fn load_port(&self, id: &str) -> Result<Option<Port>, String>;
}
```

---

## Backend Comparison

| Backend | Crate | URI | Persistence | Notes |
|---------|-------|-----|-------------|-------|
| `InMemoryKernelStore` | `vac-core` | `memory://` | No | Tests, ephemeral agents |
| `RedbKernelStore` | `connector-engine` | `redb:<path>` or `*.redb` | Yes | **Default persistent backend** |
| `ProllyKernelStore` | `vac-store` | `prolly:<path>` | Yes | Merkle-verifiable, content-addressed |
| `IndexDbKernelStore` | `vac-store` | any `AsyncPersistenceBackend` | Yes | Generic async DB interface |
| `EncryptedStore<S>` | `vac-core` | wraps any store | Inherits inner | SHA256-CTR encryption |
| `ClusterKernelStore` | `vac-cluster` | `connector://cluster:<host>` | Yes + replicated | Raft + NATS |

---

## RedbKernelStore (Default)

**redb** is the default persistent backend: pure Rust, ACID, crash-safe CoW B-trees, MVCC.

```rust
// connector-engine/src/redb_store.rs
pub struct RedbKernelStore {
    db: redb::Database,
}
```

**13 tables**:

| Table | Key | Value |
|-------|-----|-------|
| `packets` | CID bytes | JSON(MemPacket) |
| `namespace_index` | `ns:{ns}:{ts}:{cid}` | CID bytes |
| `agents` | agent_pid | JSON(AgentControlBlock) |
| `sessions` | session_id | JSON(SessionEnvelope) |
| `audit` | audit_id | JSON(KernelAuditEntry) |
| `windows` | window_sn | JSON(RangeWindow) |
| `state_vectors` | entity_id | JSON(StateVector) |
| `interference` | edge_id | JSON(InterferenceEdge) |
| `scitt` | receipt_id | JSON(ScittReceipt) |
| `ports` | port_id | JSON(Port) |
| `policies` | policy_id | JSON(ExecutionPolicy) |
| `delegations` | chain_id | JSON(DelegationChain) |
| `wal` | seq | JSON(WalEntry) |

All tables are initialized on `open()` to prevent "table does not exist" errors on first read.

**Storage URI selection**:
```rust
Connector::new()
    .storage("redb:./data.redb")  // explicit redb
    .storage("./data.redb")       // auto-detect .redb extension
    .storage("memory")            // in-memory (default if no storage set)
    .storage("prolly:./data")     // Prolly tree
```

---

## InMemoryKernelStore

```rust
pub struct InMemoryKernelStore {
    packets:   HashMap<Cid, MemPacket>,
    agents:    HashMap<String, AgentControlBlock>,
    sessions:  HashMap<String, SessionEnvelope>,
    audit:     Vec<KernelAuditEntry>,
    // ...
}
```

Default when no storage URI is specified. Used in all tests and ephemeral pipelines.

---

## EncryptedStore

```rust
pub struct EncryptedStore<S: KernelStore> {
    inner: S,
    key:   [u8; 32],
}

impl<S: KernelStore> EncryptedStore<S> {
    pub fn new(inner: S, key: [u8; 32]) -> Self
}
```

**Cipher**: SHA256-CTR stream cipher using the existing `sha2` crate — no new dependencies.

**Wire format**: `{"__encrypted": true, "__data": "<hex-ciphertext>"}`

**Transparent**: kernel code sees no difference — reads decrypt automatically, writes encrypt automatically.

---

## ProllyKernelStore

```rust
// vac-store/src/prolly_bridge.rs
pub struct ProllyKernelStore {
    tree: ProllyTree<MemoryNodeStore>,
}
```

Uses `block_in_place` for sync→async bridging. Requires `flavor = "multi_thread"` tokio runtime in tests.

Namespace packet keys include timestamp to avoid CID collisions:
```
ns:{namespace}:{timestamp_ms}:{cid}
```

---

## IndexDbKernelStore

```rust
// vac-store/src/indexdb_bridge.rs
pub trait AsyncPersistenceBackend: Send + Sync {
    async fn put(&self, table: &str, key: &str, value: &[u8]) -> Result<(), String>;
    async fn get(&self, table: &str, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn delete(&self, table: &str, key: &str) -> Result<bool, String>;
    async fn list_by_prefix(&self, table: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, String>;
    async fn list_by_range(&self, table: &str, start: &str, end: &str) -> Result<Vec<(String, Vec<u8>)>, String>;
    async fn count(&self, table: &str) -> Result<usize, String>;
}

pub struct IndexDbKernelStore<B: AsyncPersistenceBackend> {
    backend: Arc<B>,
}
```

`InMemoryPersistenceBackend` (BTreeMap-based) is provided for testing. Any async DB (SQLite, Postgres, etc.) can implement `AsyncPersistenceBackend`.

---

## ClusterKernelStore

```rust
// vac-cluster/src/cluster_store.rs
pub struct ClusterKernelStore<S: KernelStore, B: EventBus> {
    local:  S,
    bus:    B,
    cell_id: String,
}
```

**Write path**: write to local store (sync, fast) + publish `ReplicationEvent` to bus (async, background).

**Read path**: read from local store only (fast). Merkle root verification for freshness.

**ReplicationOp variants**: `PacketWrite | PacketSeal | PacketEvict | TierChange | AgentRegister | AuditEntry | BlockCommit | Heartbeat | VakyaForward | VakyaReply | VakyaRollback | PolicyUpdate | AdapterAnnounce | AdapterDeregister | ApprovalRequest | ApprovalResponse`

---

## Persistence API

```rust
// Flush kernel state to store (atomic — rolls back on failure)
kernel.flush_to_store(&mut store) -> Result<(), String>

// Reconstruct kernel from persisted checkpoint
MemoryKernel::load_from_store(&store) -> Result<MemoryKernel, String>

// Compact: prune old audit entries beyond retention window
kernel.compact_store(&mut store, retention_days: u64) -> Result<usize, String>
```
