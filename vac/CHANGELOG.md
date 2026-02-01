# Changelog

All notable changes to VAC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial planning for v0.2.0 features

---

## [0.1.0-alpha] - 2026-02-01

### Added

#### Core (Rust)
- **vac-core**: Core types, error handling, DAG-CBOR codec, CID computation
- **vac-store**: Content-addressable storage with memory backend
- **vac-prolly**: Prolly tree implementation for history-independent indexing
- **vac-red**: Regressive Entropic Displacement (RED) engine for non-ML learning
- **vac-crypto**: Ed25519 key generation and signing
- **vac-sync**: DAG synchronization protocol
- **vac-wasm**: WebAssembly bindings for browser/Node.js

#### TypeScript SDK
- `@vac/sdk`: TypeScript SDK with full type definitions
  - CID computation and verification
  - DAG-CBOR encoding/decoding
  - Memory store implementation
  - RED engine bindings
  - Vault API for agent integration
  - LangChain memory adapter

#### Documentation
- Architecture specification (`arch.md`)
- Research synthesis on AI agent memory systems
- Claim extraction documentation
- OSS launch research and strategy

#### Demo
- Interactive demo application (React + Vite + TailwindCSS)
- Production architecture diagram
- Competitor comparison
- Live claim extraction simulation

### Technical Details

- **Content Addressing**: CIDv1 with SHA-256 and DAG-CBOR multicodec
- **Signatures**: Ed25519 for block attestation
- **Storage**: Prolly trees with Q=32 boundary detection
- **Learning**: Information-theoretic RED engine (no ML required)

### Known Limitations

- Demo uses regex for claim extraction (production uses LLM)
- Single-leaf Prolly tree operations (full balancing in v0.2)
- Memory-only storage backend (persistent backends in v0.2)

---

## Roadmap

### [0.2.0-alpha] - Planned

- LangChain integration
- SQLite storage backend
- Improved RED engine with decay
- Full Prolly tree balancing

### [0.3.0-beta] - Planned

- Production testing
- Performance optimization
- API stabilization
- WASM size optimization

### [1.0.0] - Planned

- Stable API
- Production-ready
- Full documentation
- Multiple storage backends

---

## Version History

| Version | Date | Status |
|---------|------|--------|
| 0.1.0-alpha | 2026-02-01 | Current |

---

[Unreleased]: https://github.com/GlobalSushrut/vac/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/GlobalSushrut/vac/releases/tag/v0.1.0-alpha
