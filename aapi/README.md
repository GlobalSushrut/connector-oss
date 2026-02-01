# AAPI - Agentic Action Protocol Interface

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

**AAPI** is an enterprise-grade protocol for secure, auditable, and accountable AI agent actions. It provides the missing accountability layer between AI intent and real-world execution.

## 🎯 What is AAPI?

When AI agents perform actions—booking flights, executing code, managing files, calling APIs—there's currently no standard way to:

- **Authorize** what an agent can do
- **Audit** what an agent did
- **Attribute** responsibility for agent actions
- **Rollback** agent mistakes

AAPI solves this with a structured protocol based on the **VĀKYA** (Sanskrit for "sentence/statement") request envelope that captures the complete semantics of any action.

## 🏗️ Architecture

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

## 📦 Crates

| Crate | Description |
|-------|-------------|
| `aapi-core` | VĀKYA schema, Sandhi canonicalization, validation |
| `aapi-crypto` | Ed25519 signing, capability tokens, DSSE envelopes |
| `aapi-indexdb` | Append-only evidence log with Merkle proofs |
| `aapi-gateway` | HTTP server with REST API |
| `aapi-adapters` | File, HTTP, and custom action adapters |
| `aapi-metarules` | Policy engine for authorization |
| `aapi-sdk` | Client library for applications |
| `aapi-cli` | Command-line interface |

### Python SDK

Located in `sdks/python/`, the Python SDK provides:
- Pydantic models for VĀKYA
- HTTP Client
- Ed25519 Signing
- **LangChain Tool** integration

```bash
pip install sdks/python
```

## 🚀 Quick Start

### Prerequisites

- Rust 1.75 or later
- SQLite (for development) or PostgreSQL (for production)

### Build

```bash
# Clone the repository
git clone https://github.com/aapi-protocol/aapi.git
cd aapi

# Build all crates
cargo build --release

# Run tests
cargo test
```

### Start the Gateway

```bash
# Start with default settings (SQLite, port 8080)
cargo run --bin aapi -- serve

# Or with custom settings
cargo run --bin aapi -- serve --host 0.0.0.0 --port 8080 --database sqlite:aapi.db
```

### Submit a VĀKYA

```bash
# Using the CLI
cargo run --bin aapi -- submit \
  --actor "user:alice" \
  --resource "file:/data/report.txt" \
  --action "file.read"

# Or using curl
curl -X POST http://localhost:8080/v1/vakya \
  -H "Content-Type: application/json" \
  -d '{
    "vakya": {
      "vakya_version": {"major": 0, "minor": 1, "patch": 0},
      "vakya_id": "test-123",
      "v1_karta": {"pid": "user:alice", "actor_type": "human"},
      "v2_karma": {"rid": "file:/data/report.txt"},
      "v3_kriya": {"action": "file.read"},
      "v7_adhikarana": {"cap": {"cap_ref": "cap:default"}},
      "body_type": {"name": "generic", "version": {"major": 0, "minor": 1, "patch": 0}},
      "body": {},
      "meta": {"created_at": "2024-01-01T00:00:00Z"}
    }
  }'
```

### Check Health

```bash
cargo run --bin aapi -- health
# ✓ Gateway Status: healthy
#   Gateway ID: abc-123
#   Version: 0.1.0
```

## 📖 The VĀKYA Envelope

VĀKYA is based on the 7 Vibhakti (Sanskrit grammatical cases):

| Slot | Name | Meaning | Example |
|------|------|---------|---------|
| V1 | **Kartā** | WHO is acting | `user:alice`, `agent:assistant` |
| V2 | **Karma** | WHAT is acted upon | `file:/data/report.txt` |
| V3 | **Kriyā** | The ACTION | `file.read`, `http.post` |
| V4 | **Karaṇa** | BY WHAT MEANS | `via: http`, `adapter: file` |
| V5 | **Sampradāna** | FOR WHOM | Recipient of the action |
| V6 | **Apādāna** | FROM WHERE | Source of data |
| V7 | **Adhikaraṇa** | UNDER WHAT AUTHORITY | Capability token, TTL, budgets |

## 🔐 Security Features

- **Ed25519 Signatures**: Every VĀKYA is signed for non-repudiation
- **Capability Tokens**: Macaroon-style tokens with caveats for fine-grained authorization
- **Merkle Transparency Log**: Append-only IndexDB with inclusion proofs
- **DSSE Envelopes**: Dead Simple Signing Envelope for payload type binding
- **Policy Engine**: MetaRules for declarative authorization policies

## 🔍 Transparency & Audit

Every action is logged to IndexDB with:

- **VĀKYA Record**: The complete request with signature
- **Effect Record**: Before/after state capture
- **Receipt (PRAMĀṆA)**: Execution result with timing

Query the transparency log:

```bash
# Get Merkle root
cargo run --bin aapi -- merkle root --tree-type vakya

# Get inclusion proof
cargo run --bin aapi -- merkle proof --tree-type vakya --index 0
```

## 🛠️ Extending AAPI

### Custom Adapter

```rust
use aapi_adapters::{Adapter, ExecutionContext, ExecutionResult};
use async_trait::async_trait;

pub struct MyAdapter;

#[async_trait]
impl Adapter for MyAdapter {
    fn domain(&self) -> &str { "myservice" }
    fn version(&self) -> &str { "1.0.0" }
    fn supported_actions(&self) -> Vec<&str> {
        vec!["myservice.action1", "myservice.action2"]
    }

    async fn execute(&self, vakya: &Vakya, ctx: &ExecutionContext) 
        -> AdapterResult<ExecutionResult> 
    {
        // Your implementation here
    }
}
```

### Custom Policy Rule

```rust
use aapi_metarules::{Rule, Condition, Operator, RuleEffect};

let rule = Rule::deny("block-sensitive", "Block Sensitive Resources")
    .with_condition(Condition::resource(Operator::Contains, "/sensitive/"))
    .with_priority(100);
```

## 📚 Documentation

- [Architecture Document](preplanning/archecture.md)
- [Research Summary](preplanning/resherch.md)
- [Engineering Blueprint](preplanning/engineering.md)
- [Why AAPI?](preplanning/why_aapi.md)

## 🗺️ Roadmap

### v0.1 (Current)
- [x] Core VĀKYA schema and validation
- [x] Ed25519 signing and verification
- [x] Capability tokens with caveats
- [x] SQLite-backed IndexDB
- [x] HTTP Gateway with REST API
- [x] File and HTTP adapters
- [x] MetaRules policy engine
- [x] CLI and SDK

### v0.2 (Planned)
- [ ] PostgreSQL backend for IndexDB
- [ ] gRPC API
- [ ] MCP (Model Context Protocol) bridge
- [ ] Approval workflow UI
- [ ] OpenTelemetry integration

### v1.0 (Future)
- [ ] SCITT integration
- [ ] Multi-party approval
- [ ] Federated capability delegation
- [ ] Compliance report generation

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct.

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

AAPI draws inspiration from:
- [SPIFFE](https://spiffe.io/) for workload identity
- [Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/) for capability tokens
- [Certificate Transparency](https://certificate.transparency.dev/) for transparency logs
- [in-toto](https://in-toto.io/) for attestation frameworks
- [DSSE](https://github.com/secure-systems-lab/dsse) for signing envelopes
