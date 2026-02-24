# Merkle and Prolly Tree

> Prolly tree structure, Merkle proofs, block/manifest hashing
> Source: `vac/crates/vac-prolly/`, `vac/crates/vac-core/src/cid.rs`

---

## Prolly Tree

A **Prolly tree** (Probabilistic B-tree) is a history-independent Merkle tree with content-defined chunking. It provides:

- **O(log n)** insert, lookup, delete
- **Merkle inclusion proofs** — prove a key exists without revealing others
- **Deterministic structure** — same keys always produce the same tree shape
- **Efficient diff** — compare two trees by comparing root CIDs; only changed subtrees differ

```rust
// vac-prolly/src/tree.rs
pub struct ProllyTree<S: NodeStore> {
    store: S,
    root:  Option<Cid>,
}

pub trait NodeStore: Send + Sync {
    async fn get(&self, cid: &Cid)      -> VacResult<ProllyNode>;
    async fn put(&self, node: &ProllyNode) -> VacResult<Cid>;
    async fn contains(&self, cid: &Cid) -> bool;
}
```

---

## ProllyNode

```rust
// vac-core/src/types.rs — ProllyNode (§25.9)
pub struct ProllyNode {
    pub type_:     String,   // "prolly_node"
    pub version:   u32,
    pub level:     u8,       // 0 = leaf, >0 = internal
    pub keys:      Vec<Vec<u8>>,
    pub values:    Vec<Cid>,
    pub node_hash: [u8; 32], // domain-separated hash of level+keys+values
}
```

**Node hash formula**:
```
H("vac.prolly.v1" || level || num_keys(u16 BE) ||
  key_0_len(u16 BE) || key_0 || ... ||
  value_0_cid_bytes || ...)
```

---

## Merkle Proof

```rust
// vac-prolly/src/proof.rs
pub struct ProllyProof {
    pub steps: Vec<ProofStep>,
}

pub struct ProofStep {
    pub level:     u8,
    pub key_index: usize,
    pub siblings:  Vec<Cid>,
}
```

Verify inclusion: walk from leaf to root, recomputing node hashes at each level. If the recomputed root CID matches the known root, the key is proven to exist.

---

## Storage Backends for Prolly

```rust
// vac-store/src/prolly_bridge.rs
pub struct ProllyKernelStore {
    tree: ProllyTree<MemoryNodeStore>,
    // Uses block_in_place for sync→async bridging
    // Requires multi_thread tokio runtime
}
```

Namespace packet keys include timestamp to avoid CID collisions:
```
ns:{namespace}:{timestamp_ms}:{cid}
```

---

## Block Chain (Attestation)

The kernel produces signed `BlockHeader` objects that chain together all state changes:

```rust
// vac-core/src/types.rs — BlockHeader (§10.3)
pub struct BlockHeader {
    pub block_no:        u64,
    pub prev_block_hash: [u8; 32],  // links to previous block
    pub ts:              i64,
    pub links: BlockLinks {
        pub patch:    Cid,           // VaultPatch — what changed
        pub manifest: Cid,           // ManifestRoot — full state summary
    },
    pub signatures:  Vec<Signature>, // Ed25519 signatures
    pub block_hash:  [u8; 32],       // H("vac.block.v1" || ...)
}
```

**VaultPatch** records what changed in this block:
```rust
pub struct VaultPatch {
    pub parent_block_hash: [u8; 32],
    pub added_cids:        Vec<Cid>,
    pub removed_refs:      Vec<Cid>,
    pub updated_roots:     BTreeMap<String, [u8; 32]>,
}
```

---

## ManifestRoot

Per-block root summary — a single hash that commits to the entire state:

```rust
pub struct ManifestRoot {
    pub block_no:           u64,
    pub chapter_index_root: [u8; 32],
    pub snaptree_roots:     BTreeMap<String, [u8; 32]>,
    pub pcnn_basis_root:    [u8; 32],
    pub pcnn_mpn_root:      [u8; 32],
    pub pcnn_ie_root:       [u8; 32],
    pub body_cas_root:      [u8; 32],
    pub policy_root:        [u8; 32],
    pub revocation_root:    [u8; 32],
    pub manifest_hash:      [u8; 32],
}
```

---

## Replication via Merkle Sync

`vac-replicate` uses the Prolly tree root CID for efficient sync:

1. Compare root CIDs between peers — if equal, no sync needed
2. Walk the tree to find divergent subtrees
3. Transfer only the changed nodes
4. Verify each received node's hash before accepting

CID-addressed data is **conflict-free by construction** — same content always has the same CID, so concurrent writes to different keys never conflict.
