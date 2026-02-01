<div align="center">

# Connector — AI Agent Infrastructure

**Secure, Verifiable, Accountable AI Agent Systems**

[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)

</div>

---

## Overview

**Connector** is a suite of open-source tools for building trustworthy AI agent systems. It consists of two complementary projects:

| Project | Purpose | Status |
|---------|---------|--------|
| **[AAPI](#aapi---agentic-action-protocol-interface)** | Secure, auditable agent actions | v0.1.0 |
| **[VAC](#vac---vault-attestation-chain)** | Verifiable agent memory | v0.1.0-alpha |

Together, they provide the complete infrastructure for AI agents that are:
- **Accountable** — Every action is authorized, logged, and auditable
- **Verifiable** — Every memory has cryptographic proof
- **Trustworthy** — Full provenance from intent to execution

---

## The Problem

AI agents are becoming autonomous — booking flights, executing code, managing data. But current systems lack:

| Gap | Risk | Solution |
|-----|------|----------|
| No action accountability | Agent does something wrong, who's responsible? | **AAPI** — Signed action envelopes |
| No memory verification | Agent claims "you told me X", can you prove it? | **VAC** — Content-addressed memory |
| No audit trail | Compliance asks what the agent did, no answer | **AAPI + VAC** — Complete transparency |

---

## AAPI — Agentic Action Protocol Interface

**The accountability layer for AI agent actions.**

When AI agents perform actions—booking flights, executing code, calling APIs—AAPI provides:

- **Authorization** — What can the agent do?
- **Audit** — What did the agent do?
- **Attribution** — Who is responsible?
- **Rollback** — Can we undo mistakes?

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AAPI Gateway                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  MetaRules  │  │   Crypto    │  │      IndexDB        │  │
│  │   Engine    │  │  (Ed25519)  │  │  (Transparency Log) │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                       Adapters                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   File   │  │   HTTP   │  │ Database │  │  Custom  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Key Concepts

**VĀKYA** (Sanskrit for "sentence") — The request envelope capturing complete action semantics:

| Slot | Name | Meaning | Example |
|------|------|---------|---------|
| V1 | **Kartā** | WHO is acting | `user:alice`, `agent:assistant` |
| V2 | **Karma** | WHAT is acted upon | `file:/data/report.txt` |
| V3 | **Kriyā** | The ACTION | `file.read`, `http.post` |
| V7 | **Adhikaraṇa** | UNDER WHAT AUTHORITY | Capability token, TTL |

### Crates

| Crate | Description |
|-------|-------------|
| `aapi-core` | VĀKYA schema, validation |
| `aapi-crypto` | Ed25519 signing, capability tokens |
| `aapi-indexdb` | Append-only transparency log |
| `aapi-gateway` | HTTP server with REST API |
| `aapi-adapters` | File, HTTP, custom adapters |
| `aapi-metarules` | Policy engine for authorization |
| `aapi-sdk` | Client library |
| `aapi-cli` | Command-line interface |

### Quick Start

```bash
cd aapi

# Build
cargo build --release

# Start gateway
cargo run --bin aapi -- serve

# Submit an action
cargo run --bin aapi -- submit \
  --actor "user:alice" \
  --resource "file:/data/report.txt" \
  --action "file.read"
```

📚 [Full AAPI Documentation](aapi/README.md)

---

## VAC — Vault Attestation Chain

**The first verifiable memory system for AI agents.**

Current AI memory systems (Mem0, MemGPT, Zep) store memories but can't prove them. VAC adds cryptographic verifiability:

| Feature | Mem0 | MemGPT | Zep | **VAC** |
|---------|------|--------|-----|---------|
| Content-Addressed (CID) | ❌ | ❌ | ❌ | ✅ |
| Cryptographic Proofs | ❌ | ❌ | ❌ | ✅ |
| Non-ML Learning | ❌ | ❌ | ❌ | ✅ |
| Offline-First Sync | ❌ | ❌ | ❌ | ✅ |
| Provenance Chain | ❌ | ❌ | partial | ✅ |

### Key Features

- **🔐 Verifiable** — Every memory has a CID (content hash). Merkle proofs. Ed25519 signatures.
- **🔗 Provenance** — Trace any claim back to its source conversation.
- **⚡ Non-ML Learning** — RED engine learns using information theory, not neural networks.
- **📴 Offline-First** — Works without cloud. Deterministic DAG sync.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VAC Memory Layer                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  CID Store  │  │ Prolly Tree │  │     RED Engine      │  │
│  │  (Content)  │  │  (Merkle)   │  │   (Non-ML Learn)    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Attestation Log                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Block → Block → Block  (Ed25519 signed commits)     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Description |
|-------|-------------|
| `vac-core` | Core types, CID computation, DAG-CBOR |
| `vac-prolly` | Prolly tree with Merkle proofs |
| `vac-red` | RED engine (non-ML learning) |
| `vac-crypto` | Ed25519 signatures |
| `vac-store` | Content-addressable storage |
| `vac-sync` | DAG synchronization |
| `vac-wasm` | WebAssembly bindings |

### TypeScript SDK

```typescript
import { createVault } from '@vac/sdk';

const vault = createVault({ vaultId: 'my-vault' });

// Store a memory
const event = vault.createEvent('User said: I prefer vegetarian food');

// Extract a claim with provenance
const claim = vault.createClaim('user', 'preference:food', 'vegetarian', {
  confidence: 0.95,
  evidence: event.cid,  // Links to source!
});

// Commit to signed block
await vault.commit();
```

📚 [Full VAC Documentation](vac/README.md)

---

## How They Work Together

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User: "Book me a flight to NYC"                               │
│                           │                                     │
│                           ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    VAC Memory                           │   │
│   │  • Store conversation event (CID: bafy2bzace...)        │   │
│   │  • Extract claim: user.destination = "NYC"              │   │
│   │  • Link evidence to source event                        │   │
│   └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│                           ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    AAPI Action                          │   │
│   │  • Create VĀKYA: actor=agent, action=flight.book        │   │
│   │  • Check authorization (MetaRules)                      │   │
│   │  • Sign with Ed25519                                    │   │
│   │  • Log to IndexDB (transparency)                        │   │
│   │  • Execute via adapter                                  │   │
│   └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│                           ▼                                     │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    VAC Memory                           │   │
│   │  • Store action result event                            │   │
│   │  • Extract claim: booking.confirmed = true              │   │
│   │  • Commit to signed block                               │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Result**: Complete audit trail from user intent → memory → action → result, all cryptographically verifiable.

---

## Repository Structure

```
connector-oss/
├── README.md           # This file
├── LICENSE             # Apache 2.0
├── CONTRIBUTING.md     # Contribution guidelines
│
├── aapi/               # AAPI - Action Protocol
│   ├── crates/         # Rust crates
│   ├── sdks/           # Python SDK
│   └── README.md
│
└── vac/                # VAC - Memory System
    ├── crates/         # Rust crates
    ├── packages/       # TypeScript SDK
    ├── demo/           # Interactive demo
    └── README.md
```

---

## Getting Started

### Prerequisites

- **Rust** 1.75+ 
- **Node.js** 18+ (for VAC TypeScript SDK)
- **SQLite** (for AAPI development)

### Build Everything

```bash
# Clone
git clone https://github.com/GlobalSushrut/connector-oss.git
cd connector-oss

# Build AAPI
cd aapi && cargo build && cd ..

# Build VAC
cd vac && cargo build && cd ..

# Build VAC TypeScript SDK
cd vac/packages/vac-sdk && npm install && npm run build && cd ../../..

# Run VAC demo
cd vac/demo && npm install && npm run dev
```

---

## Use Cases

### 1. Regulated Industries (Healthcare, Finance)

**Problem**: AI agent makes a recommendation, regulator asks "why?"

**Solution**:
- **VAC**: Prove what the agent knew and when it learned it
- **AAPI**: Show exactly what actions were taken and who authorized them

### 2. Multi-Agent Systems

**Problem**: Multiple agents collaborate, something goes wrong

**Solution**:
- **VAC**: Shared memory with deterministic sync
- **AAPI**: Clear attribution of which agent did what

### 3. Enterprise AI Assistants

**Problem**: Assistant accesses sensitive data, need audit trail

**Solution**:
- **AAPI**: Every data access is authorized and logged
- **VAC**: Memory of what was accessed and why

---

## Roadmap

### AAPI

| Version | Features |
|---------|----------|
| v0.1 ✅ | Core VĀKYA, Ed25519, IndexDB, Gateway, Adapters |
| v0.2 | PostgreSQL, gRPC, MCP bridge |
| v1.0 | SCITT integration, multi-party approval |

### VAC

| Version | Features |
|---------|----------|
| v0.1-alpha ✅ | Core types, Prolly tree, RED engine, TypeScript SDK |
| v0.2-alpha | LangChain integration, SQLite backend |
| v0.3-beta | Production testing, API stabilization |
| v1.0 | Stable API, full documentation |

---

## Contributing

We welcome contributions to both projects! See:
- [AAPI Contributing Guide](aapi/CONTRIBUTING.md)
- [VAC Contributing Guide](vac/CONTRIBUTING.md)

## License

Apache License 2.0 — See [LICENSE](LICENSE)

---

<div align="center">

**Connector** — Trustworthy AI Agent Infrastructure

[⭐ Star us on GitHub](https://github.com/GlobalSushrut/connector-oss)

**AAPI** — Actions you can audit | **VAC** — Memory you can prove

</div>
