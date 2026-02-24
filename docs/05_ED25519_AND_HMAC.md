# Ed25519 and HMAC

> Ed25519 signing, HMAC-SHA256 audit chain, EncryptedStore
> Source: `vac/crates/vac-crypto/`, `vac/crates/vac-core/src/store.rs`

---

## Ed25519 Signing

Used for packet signing, VAKYA token signing, cell identity, and capability delegation chains.

```rust
// vac-crypto crate
pub fn ed25519_keygen() -> (PublicKey, SecretKey)
pub fn ed25519_sign(secret: &SecretKey, message: &[u8]) -> Signature
pub fn ed25519_verify(public: &PublicKey, message: &[u8], sig: &Signature) -> bool
```

**Signature type** (stored in `BlockHeader.signatures` and VAKYA tokens):
```rust
pub struct Signature {
    pub public_key: String,   // hex-encoded Ed25519 public key
    pub signature:  Vec<u8>,  // 64-byte Ed25519 signature
}
```

**Where Ed25519 is used**:
- `BlockHeader.signatures` — signs each attestation block
- AAPI VAKYA tokens — every action authorization is signed
- `aapi-crypto` capability tokens — UCAN-compatible delegation
- `vac-cluster` cell identity — each cell has an Ed25519 keypair
- `CrossCellCapabilityVerifier` — verifies delegation hop chains

---

## HMAC-SHA256 Audit Chain

The kernel audit log is HMAC-chained — every entry includes the HMAC of the previous entry, making deletion, insertion, or reordering cryptographically detectable.

```rust
// vac-core/src/store.rs
pub fn sign_audit_entry(
    entry:     &KernelAuditEntry,
    key:       &[u8; 32],
    prev_hmac: &[u8; 32],
) -> [u8; 32]
// Returns: HMAC-SHA256(key, prev_hmac || entry_bytes)

pub fn verify_audit_chain(
    entries: &[KernelAuditEntry],
    key:     &[u8; 32],
    hmacs:   &[[u8; 32]],
) -> Vec<(usize, String)>
// Returns: list of (index, error_message) for any broken links
```

**Chain formula**:
```
hmac[0] = HMAC-SHA256(key, [0u8; 32] || entry[0])
hmac[i] = HMAC-SHA256(key, hmac[i-1] || entry[i])
```

**What it detects**:
- Modification of any entry → HMAC mismatch at that index
- Deletion of an entry → all subsequent HMACs break
- Insertion of a fake entry → breaks the chain at insertion point
- Reordering of entries → breaks the chain

**Implementation**: Pure SHA2 — no new dependencies beyond the existing `sha2` crate.

---

## EncryptedStore

Wraps any `KernelStore` with transparent payload encryption:

```rust
// vac-core/src/store.rs
pub struct EncryptedStore<S: KernelStore> {
    inner: S,
    key:   [u8; 32],  // 256-bit encryption key
}

impl<S: KernelStore> EncryptedStore<S> {
    pub fn new(inner: S, key: [u8; 32]) -> Self
}
```

**Cipher**: SHA256-CTR stream cipher (no new dependencies — uses existing `sha2` crate).

**On write**: payload serialized → encrypted → stored as:
```json
{"__encrypted": true, "__data": "<hex-encoded-ciphertext>"}
```

**On read**: `{"__encrypted": true}` detected → decrypted → deserialized transparently.

**Usage**:
```rust
let key: [u8; 32] = /* 256-bit key */;
let store = EncryptedStore::new(InMemoryKernelStore::new(), key);
// All writes encrypted, all reads decrypted — kernel sees no difference
```

---

## SCITT Receipts

The `DispatcherSecurity.scitt = true` flag enables SCITT (Supply Chain Integrity, Transparency and Trust) receipt anchoring for every packet write. SCITT receipts provide cross-organization attestation that a packet existed at a specific time.

Implemented in `aapi-federation` via `ScittExchange`.

---

## Security Config

```rust
// connector-api/src/security.rs
pub struct SecurityConfig {
    pub signing:              Option<SigningAlgorithm>,  // Ed25519
    pub scitt:                bool,
    pub data_classification:  Option<String>,  // PHI | PII | confidential | internal | public
    pub jurisdiction:         Option<String>,  // US | EU | UK | CA | AU
    pub retention_days:       u64,
    pub key_rotation_days:    u64,
    pub audit_export:         Option<String>,  // json | csv | otel
    pub max_delegation_depth: u8,              // default: 3
    pub require_mfa:          bool,
    pub ip_allowlist:         Vec<String>,
}

pub enum SigningAlgorithm { Ed25519 }
```
