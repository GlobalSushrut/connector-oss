<div align="center">

# VAC — Vault Attestation Chain

**The First Verifiable Memory System for AI Agents**

[![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue.svg)](https://github.com/GlobalSushrut/vac/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)

[Documentation](docs/) • [Demo](demo/) • [Contributing](CONTRIBUTING.md) • [Changelog](CHANGELOG.md)

</div>

---

## Why VAC?

Current AI memory systems (Mem0, MemGPT, Zep) store memories but **can't prove them**. VAC adds cryptographic verifiability:

| Feature | Mem0 | MemGPT | Zep | **VAC** |
|---------|------|--------|-----|---------|
| Content-Addressed (CID) | ❌ | ❌ | ❌ | ✅ |
| Cryptographic Proofs | ❌ | ❌ | ❌ | ✅ |
| Non-ML Learning | ❌ | ❌ | ❌ | ✅ |
| Offline-First Sync | ❌ | ❌ | ❌ | ✅ |
| Provenance Chain | ❌ | ❌ | partial | ✅ |

## Key Features

- **🔐 Verifiable** — Every memory has a CID (content hash). Merkle proofs. Ed25519 signatures.
- **🔗 Provenance** — Trace any claim back to its source conversation.
- **⚡ Non-ML Learning** — RED engine learns from retrieval feedback using information theory.
- **📴 Offline-First** — Works without cloud. Deterministic DAG sync.
- **🗄️ No External DB** — Embedded Prolly tree storage. No Neo4j/Pinecone required.

## Architecture

```
VAC = CAS + Prolly Tree + Attested Blocks + ManifestRoot + ClaimBundle + UCAN + Vector Network
```

See [preplanning/arch.md](../preplanning/arch.md) for the complete specification.

## Project Structure

```
vac/
├── Cargo.toml              # Rust workspace
├── crates/
│   ├── vac-core/           # Core types (Event, ClaimBundle, Block, etc.)
│   ├── vac-prolly/         # Prolly tree implementation
│   ├── vac-red/            # Regressive Entropic Displacement engine
│   ├── vac-crypto/         # Ed25519 signatures, DID keys
│   ├── vac-store/          # Content-addressable storage
│   ├── vac-sync/           # Block-verified sync protocol
│   └── vac-wasm/           # WebAssembly bindings
├── packages/
│   └── vac-sdk/            # TypeScript SDK
└── README.md
```

## Quick Start

### Rust

```bash
cd vac

# Build all crates
cargo build

# Run tests
cargo test

# Build WASM
cargo build -p vac-wasm --target wasm32-unknown-unknown
```

### TypeScript

```bash
cd vac/packages/vac-sdk

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Usage

### TypeScript SDK

```typescript
import { createVault, Vault } from '@vac/sdk';

// Create a vault
const vault = createVault({
  vaultId: 'my-vault',
  ownerId: 'did:key:z6Mk...',
});

// Create an event
const event = vault.createEvent('User said: I prefer vegetarian food', {
  entities: ['user:alice'],
  tags: ['preference', 'food'],
});

// Create a claim
const claim = vault.createClaim('user:alice', 'preference:food', 'vegetarian', {
  confidence: 0.95,
});

// Commit to a new block
const block = await vault.commit();
console.log(`Block ${block.block_no} committed`);

// Provide retrieval feedback (for RED learning)
vault.feedback(['user:alice'], 'vegetarian food', true);
```

### Rust

```rust
use vac_core::{Event, Source, SourceKind};
use vac_red::{RedEngine, SparseVector, encode_event};

// Create an event
let source = Source {
    kind: SourceKind::User,
    principal_id: "did:key:z6Mk...".to_string(),
};
let event = Event::new(timestamp, payload_cid, source);

// Compute entropy using RED
let mut red = RedEngine::new();
let vector = encode_event(&entities, &predicates, &text, 65536);
let entropy = red.compute_entropy(&vector);

// Update RED on observation
red.observe(&vector);
```

## Core Concepts

### Regressive Entropic Displacement (RED)

RED is a non-ML learning system based on information-theoretic principles:

1. **Maximum Entropy Principle** — Start with uniform prior (maximum ignorance)
2. **KL Divergence** — Measure information gain when beliefs change
3. **Multiplicative Weights** — Exponentially discount features that lead to useless retrievals
4. **Network Reframing** — Periodic consolidation (like sleep)

```
Entropy = 0.4 × novelty + 0.3 × conflict_score + 0.3 × temporal_novelty
```

### Prolly Tree

History-independent Merkle tree with content-defined chunking:

- **Branching factor Q = 32**
- **Boundary detection** via hash threshold
- **O(log n)** lookup, insert, delete
- **Efficient diff/sync** via Merkle proofs

### Block-Verified Sync

Sync protocol that verifies blocks in order:

1. Find common ancestor block
2. Transfer blocks from ancestor to source head
3. Verify each block's signature + prev_hash chain
4. Store objects referenced by each block's patch
5. Update head to last verified block

## Crate Overview

| Crate | Description |
|-------|-------------|
| `vac-core` | Core types, CID computation, DAG-CBOR codec |
| `vac-prolly` | Prolly tree with boundary detection, proofs |
| `vac-red` | Sparse vectors, RED engine, entropy computation |
| `vac-crypto` | Ed25519 keypairs, DID keys, signing |
| `vac-store` | ContentStore trait, MemoryStore |
| `vac-sync` | SyncableVault trait, block verification |
| `vac-wasm` | WASM bindings for browser/Node.js |

## Dependencies

### Rust

- `libipld` — IPLD/DAG-CBOR
- `cid`, `multihash` — Content addressing
- `ed25519-dalek` — Signatures
- `sprs` — Sparse matrices for RED
- `tokio` — Async runtime

### TypeScript

- `@ipld/dag-cbor` — DAG-CBOR codec
- `multiformats` — CID computation
- `@noble/ed25519` — Signatures
- `@noble/hashes` — SHA256

## Status

**v0.1.0-alpha** — Early preview release

- ✅ Core functionality works
- ✅ Basic documentation
- ✅ Demo application
- ⚠️ API may change
- ⚠️ Not recommended for production yet

See [CHANGELOG.md](CHANGELOG.md) for version history and [roadmap](docs/OSS_LAUNCH_RESEARCH.md#33-roadmap-to-v10).

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — See [LICENSE](LICENSE)

## References

- [Architecture Specification](../preplanning/arch.md)
- [Research Synthesis](docs/RESEARCH_SYNTHESIS.md) — Competitor analysis
- Jaynes (1957) — Maximum Entropy Principle
- Friston (2010) — Free Energy Principle
- Littlestone & Warmuth (1994) — Multiplicative Weights
- DoltHub (2022) — Prolly Trees

---

<div align="center">

**VAC** — Memory you can prove.

[⭐ Star us on GitHub](https://github.com/GlobalSushrut/vac)

</div>
