# CID and DAG-CBOR

> CIDv1 computation, DAG-CBOR encoding, Prolly key format
> Source: `vac/crates/vac-core/src/cid.rs`

---

## CIDv1 Computation

Every `MemPacket` and every VAC object gets a **CIDv1** — a self-describing content address.

```
CIDv1 = CID(codec=DAG_CBOR(0x71), multihash=SHA2-256(0x12, 32_bytes))

Steps:
  1. Serialize object to DAG-CBOR bytes using ciborium::into_writer()
  2. SHA2-256 hash the bytes → [u8; 32]
  3. Wrap in Multihash: Multihash::wrap(SHA256_CODE=0x12, &hash_bytes)
  4. Create CIDv1: Cid::new_v1(DAG_CBOR_CODE=0x71, multihash)
```

**Rust implementation** (`vac-core/src/cid.rs`):

```rust
const DAG_CBOR_CODE: u64 = 0x71;
const SHA256_CODE:   u64 = 0x12;

pub fn compute_cid<T: Serialize>(obj: &T) -> VacResult<Cid> {
    let bytes    = to_dag_cbor(obj)?;          // ciborium serialization
    let hash     = sha256(&bytes);             // [u8; 32]
    let mh       = Multihash::<64>::wrap(SHA256_CODE, &hash)?;
    Ok(Cid::new_v1(DAG_CBOR_CODE, mh))
}

pub fn to_dag_cbor<T: Serialize>(obj: &T) -> VacResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(obj, &mut bytes)?;
    Ok(bytes)
}
```

**Guarantee**: Same content → same CID, always. Change one byte → different CID → tamper detected.

---

## Domain-Separated Hashing

To prevent cross-context hash collisions, domain separation is used for structural hashes:

```rust
// H(domain || data)
pub fn sha256_domain(domain: &[u8], data: &[u8]) -> [u8; 32]

// Used for:
sha256_domain(b"vac.prolly.v1",   &node_data)   // Prolly node hash
sha256_domain(b"vac.block.v1",    &block_data)  // BlockHeader hash
sha256_domain(b"vac.manifest.v1", &manifest)    // ManifestRoot hash
```

---

## Block Hash

```rust
// H("vac.block.v1" || block_no || prev_block_hash || ts || patch_cid || manifest_cid || signatures)
pub fn compute_block_hash(
    block_no:       u64,
    prev_block_hash: &[u8; 32],
    ts:             i64,
    patch_cid:      &Cid,
    manifest_cid:   &Cid,
    signatures:     &[Signature],
) -> VacResult<[u8; 32]>
```

---

## Manifest Hash

```rust
// H("vac.manifest.v1" || block_no || chapter_index_root || snaptree_roots ||
//   pcnn_basis_root || pcnn_mpn_root || pcnn_ie_root || body_cas_root ||
//   policy_root || revocation_root)
pub fn compute_manifest_hash(...) -> VacResult<[u8; 32]>
```

---

## Prolly Tree Key Format

Packets are stored in the Prolly tree under structured keys that enable efficient range queries:

```
Format: {packet_type}/{subject_id}/{predicate}/{cid_short}

Examples:
  extraction/patient:P-44291/allergy/bafy2bzace7f3a
  action/patient:P-44291/ehr.update_allergy/bafy2bzace9a20
  llm_raw/patient:P-44291/deepseek/bafy2bzace04bb
  decision/user:alice/approve_action/bafy2bzace1234
```

**Properties**:
- All packets for a subject are adjacent → efficient range query by subject
- All packets of a type are adjacent → efficient type query
- Tree root CID changes when ANY packet changes → tamper detection
- Keys sort by type first (lexicographic), then subject, then predicate

```rust
pub fn build_prolly_key(
    packet_type: &str,
    subject_id:  &str,
    predicate:   &str,
    cid:         &Cid,
) -> Vec<u8>

pub fn parse_prolly_key(key: &[u8]) -> Option<(&str, &str, &str, &str)>
// Returns (packet_type, subject_id, predicate, cid_short)
```

---

## Determinism Test

```rust
// Same inputs always produce the same CID:
let cid1 = compute_cid(&packet_with_same_content).unwrap();
let cid2 = compute_cid(&packet_with_same_content).unwrap();
assert_eq!(cid1, cid2);  // always true

// CID version and codec are always correct:
assert_eq!(cid.version(), cid::Version::V1);
assert_eq!(cid.codec(),   DAG_CBOR_CODE);  // 0x71
```
