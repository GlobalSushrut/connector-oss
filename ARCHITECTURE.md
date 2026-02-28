# Connector OSS — Architecture

> Tamper-proof memory, chain-of-custody, and OS-grade runtime for AI agents.
> 28 crates · 61 engine modules · 11 protocol layers · 7 protocol bridges · 5 surface layers · 1,857 tests

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER INTERFACES                                │
│  Python FFI (~140 fn)  │  NAPI-RS (26 native methods)                   │
│  TypeScript SDK (~35 methods, native-first + HTTP fallback)             │
│  connector-server (38 REST routes)  │  YAML config (7 levels)           │
└───────┬───────────┬───────────┬──────────────┬──────────────────────────┘
        │           │           │              │
┌───────▼───────────▼───────────▼──────────────▼──────────────────────────┐
│                      connector-api (Connector)                          │
│  ConnectorBuilder → Connector → Agent/Pipeline → PipelineOutput         │
│  from_config() wires 21 phases (A–U) → all 3 tiers into runtime        │
└───────┬─────────────────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────────┐
│               connector-engine (DualDispatcher) — 61 modules            │
│                                                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────┐  │
│  │ Ring 1:      │ │ Ring 2:      │ │ Ring 3:      │ │ Ring 4:       │  │
│  │ Memory &     │ │ Action &     │ │ Security &   │ │ Distributed & │  │
│  │ Knowledge    │ │ Orchestration│ │ Compliance   │ │ Scalability   │  │
│  │              │ │              │ │              │ │               │  │
│  │ MemoryKernel │ │ ActionEngine │ │ Firewall     │ │ BftConsensus  │  │
│  │ KnotEngine   │ │ PolicyEngine │ │ GuardPipelin │ │ CrossCellPort │  │
│  │ RagEngine    │ │ ToolRegistry │ │ Watchdog     │ │ NoiseChannel  │  │
│  │ BindingEng   │ │ Orchestrator │ │ SecretStore  │ │ GatewayBridge │  │
│  │ ContextMgr   │ │ Negotiation  │ │ FipsCrypto   │ │ SagaBridge    │  │
│  │ EngineStore  │ │ Escrow       │ │ PostQuantum  │ │ Discovery     │  │
│  │ StorageZone  │ │ DynPricer    │ │ InjectionDet │ │ CircuitBrkr   │  │
│  │ Claims       │ │ SagaBridge   │ │ FormalVerify │ │ Reputation    │  │
│  │ Knowledge    │ │ AgentIndex   │ │ Compliance   │ │ AdaptiveRoutr │  │
│  │ Memory       │ │ ServiceContr │ │ ContentGuard │ │ SessionSticky │  │
│  │              │ │              │ │              │ │ GlobalQuota   │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └───────────────┘  │
└───────┬─────────────────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────────┐
│              connector-protocol (CP/1.0) — 11 modules                   │
│  Identity │ Channel │ Consensus │ Routing │ Capability │ Intent         │
│  Attestation │ Safety │ Telemetry │ Envelope │ Error                    │
│  120 capabilities × 12 categories × 7 entity classes                    │
└───────┬─────────────────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────────┐
│                    vac (Kernel + Distributed)                            │
│  vac-core: MemoryKernel, MemPacket, KnotEngine, AuditEntry, Syscalls   │
│  vac-cluster → vac-bus + vac-route (cluster orchestration)              │
│  vac-replicate → vac-sync + vac-crypto (state replication)              │
│  vac-sync → vac-prolly + vac-store (CAS merkle sync)                   │
│  vac-crypto (Ed25519, HMAC-SHA256) │ vac-store (persistent KV)         │
└───────┬─────────────────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────────┐
│                    aapi (Action Authorization)                          │
│  aapi-core (VĀKYA model) │ aapi-gateway (HTTP gateway)                  │
│  aapi-federation (cross-org trust) │ aapi-pipeline (saga rollback)      │
│  aapi-crypto (signatures) │ aapi-indexdb (capability index)             │
│  aapi-metarules (governance) │ aapi-adapters │ aapi-sdk │ aapi-cli      │
└───────┬─────────────────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────────┐
│                        Storage Backends                                 │
│  InMemory │ Redb (ACID embedded) │ SQLite (engine store) │ Prolly (CAS)│
└─────────────────────────────────────────────────────────────────────────┘
```

## 28 Crates — 3 Workspaces

| Workspace | Crates | Tests | Purpose |
|-----------|--------|-------|---------|
| **connector/** | connector-api, connector-engine (61 modules), connector-protocol (11 modules), connector-protocols (7 bridges), connector-caps, connector-server | 1,194 | API, engine, protocol, HTTP server |
| **vac/** | vac-core, vac-ffi, vac-bus, vac-cluster, vac-replicate, vac-sync, vac-route, vac-crypto, vac-store, vac-prolly, vac-red, vac-wasm | 492 | Kernel, FFI, distributed infra |
| **aapi/** | aapi-core, aapi-cli, aapi-adapters, aapi-crypto, aapi-federation, aapi-gateway, aapi-indexdb, aapi-metarules, aapi-pipeline, aapi-sdk | 171 | Action authorization, federation |

**Total: 28 crates · 1,857 tests · 0 failures**

## Config System (3-Tier Design)

| Tier | Philosophy | Example |
|------|-----------|---------|
| **Tier 1: Required** | Must provide | `provider`, `model`, `api_key` |
| **Tier 2: Defaults** | Smart defaults if omitted | `max_tokens: 4096`, `temperature: 0.7`, `storage: memory` |
| **Tier 3: Optional-Revoke** | **Absent = OFF, Present = ON** | `cluster`, `swarm`, `streaming`, `mcp`, `watchdog`, `crypto`, `consensus`, `observability`, `tracing`, `negotiation`, `formal_verify` |

YAML examples: `level0_hello` → `level7_full_stack` (7 progressive configs).

## REST API (38 Routes)

### Core
| Method | Path | Description |
|--------|------|-------------|
| POST | `/run` | Run single agent |
| POST | `/pipeline` | Run multi-agent pipeline |
| POST | `/config/parse` | Parse YAML config |

### Memory & Knowledge
| Method | Path | Description |
|--------|------|-------------|
| POST | `/remember` | Write memory packet |
| GET | `/memories/:ns` | List packets in namespace |
| POST | `/knowledge/ingest` | Ingest namespace → knowledge graph |
| POST | `/knowledge/query` | RAG retrieval |

### Agents & Audit
| Method | Path | Description |
|--------|------|-------------|
| GET | `/agents` | List registered agents |
| GET | `/audit` | Tail audit log |

### Tools
| Method | Path | Description |
|--------|------|-------------|
| POST | `/tools/register` | Register a tool |
| POST | `/tools/call` | Call a tool |

### Custom Folders (OS mkdir model)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/folders/create` | Create namespaced folder |
| POST | `/folders/put` | Write key-value |
| POST | `/folders/get` | Read key-value |
| GET | `/folders/list` | List all folders |

### Trust, Perception, Cognitive, Logic
| Method | Path | Description |
|--------|------|-------------|
| GET | `/trust` | Kernel trust breakdown per agent |
| POST | `/perceive` | Run perception on namespace |
| POST | `/cognitive/cycle` | Run cognitive cycle |
| POST | `/logic/plan` | Create reasoning plan |

### Sessions
| Method | Path | Description |
|--------|------|-------------|
| POST | `/sessions/create` | Create session envelope |
| POST | `/sessions/close` | Close session |

### Search, Policies, Grounding, Secrets
| Method | Path | Description |
|--------|------|-------------|
| POST | `/search` | Search packets by namespace/session |
| POST | `/policies/evaluate` | Evaluate policy rule |
| GET | `/grounding/:cat/:term` | Grounding table lookup |
| POST | `/secrets/store` | Store secret with TTL |

### Connector Protocol (CP/1.0) — 7-Layer Stack
| Method | Path | Description |
|--------|------|-------------|
| GET | `/protocol/info` | Full protocol layer summary (7 layers, 120 caps, safety) |
| POST | `/protocol/identity/register` | Register entity identity (DICE/SPIFFE/DID) |
| GET | `/protocol/capabilities` | List all 120 capabilities across 12 categories |
| POST | `/protocol/capability/check` | Check entity class → capability permission |
| POST | `/protocol/safety/estop` | Emergency stop (ambient — cannot be denied) |
| POST | `/protocol/intent` | AI agent intent decomposition + execution waves |
| POST | `/protocol/consensus/propose` | HotStuff BFT consensus proposal |
| POST | `/protocol/attestation/verify` | DICE/SPDM firmware attestation verification |
| GET | `/protocol/telemetry/streams` | Telemetry stream info |
| GET | `/protocol/routing/info` | Content-addressed routing strategies |

### Infrastructure
| Method | Path | Description |
|--------|------|-------------|
| GET | `/db/stats` | Engine + kernel statistics |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |

## 61 Engine Components — Complete Reference

All 61 modules are `pub mod` in `connector-engine/src/lib.rs`, compiled into every build.
The DualDispatcher imports **46** of them directly for runtime orchestration.

### Ring 1 — Memory & Knowledge (11 modules)
| # | Module | Component | Scalability Role | Exposed via |
|---|--------|-----------|-----------------|-------------|
| 1 | `memory.rs` | **MemoryKernel** | Per-cell kernel, replicated via vac-replicate | FFI, NAPI, SDK, Server |
| 2 | `knowledge.rs` | **KnotEngine** | Entity graph, federated merge via vac-sync | FFI, NAPI, SDK, Server |
| 3 | `rag.rs` | **RagEngine** | Token-budgeted retrieval, sharded per namespace | FFI, NAPI, SDK, Server |
| 4 | `binding.rs` | **BindingEngine** | Multi-pass cognitive cycles | FFI (cognitive_cycle) |
| 5 | `context_manager.rs` | **ContextManager** | Per-agent token budgets, cross-cell context | Internal |
| 6 | `engine_store.rs` | **EngineStore** (trait + InMemory + SQLite) | Pluggable backends, zone-partitioned | FFI, NAPI, SDK, Server |
| 7 | `storage_zone.rs` | **StorageZone** | Cell-scoped mount points (`/cell:{id}/audit/`) | FFI, Server |
| 8 | `claims.rs` | **ClaimSet** | Verifiable claims with evidence refs | FFI (verify_claims) |
| 9 | `memory_format.rs` | **ConnectorMemory** | Structured memory format for export | Internal |
| 10 | `redb_store.rs` | **RedbKernelStore** | ACID embedded persistence | `storage: redb:path` |
| 11 | `sqlite_store.rs` | **SqliteEngineStore** | WAL-mode SQL persistence | `storage: sqlite:path` |

### Ring 2 — Action & Orchestration (11 modules)
| # | Module | Component | Scalability Role | Exposed via |
|---|--------|-----------|-----------------|-------------|
| 12 | `aapi.rs` | **ActionEngine** | VĀKYA execution with budget enforcement | FFI, Server |
| 13 | `policy_engine.rs` | **PolicyEngine** | Deny/allow rules, cross-cell policy sync | FFI, Server, SDK |
| 14 | `tool_def.rs` | **ToolRegistry** | Shared tool definitions across fleet | FFI, Server |
| 15 | `orchestrator.rs` | **Orchestrator** | DAG task execution, multi-agent pipelines | Internal |
| 16 | `negotiation.rs` | **NegotiationEngine** | Agent-to-agent contract formation | Config (negotiation:) |
| 17 | `escrow.rs` | **EscrowManager** | Trustless payment locks, saga-coordinated | Internal |
| 18 | `pricing.rs` | **DynamicPricer** | Supply/demand service pricing | Internal |
| 19 | `agent_index.rs` | **AgentIndex** | Capability-based agent directory | Internal |
| 20 | `service_contract.rs` | **ServiceContract** | SLA enforcement, cross-cell contracts | Internal |
| 21 | `saga_bridge.rs` | **SagaBridge** | Distributed pipeline rollback (AAPI) | Internal |
| 22 | `auto_vakya.rs` | **AutoVakya** | Automatic VĀKYA operation generation | Automatic |

### Ring 3 — Security & Compliance (14 modules)
| # | Module | Component | Scalability Role | Exposed via |
|---|--------|-----------|-----------------|-------------|
| 23 | `firewall.rs` | **AgentFirewall** | Non-bypassable boundary, per-cell | Automatic |
| 24 | `guard_pipeline.rs` | **GuardPipeline** | 5-layer gate: MAC→Policy→Content→Rate→Audit | Automatic |
| 25 | `behavior.rs` | **BehaviorAnalyzer** | Anomaly detection, drift scoring | Automatic |
| 26 | `secret_store.rs` | **SecretStore** | Opaque handles, TTL, auto-redact in audit | Server (/secrets/store) |
| 27 | `semantic_injection.rs` | **InjectionDetector** | Prompt injection defense | Automatic |
| 28 | `watchdog.rs` | **SystemWatchdog** | Heartbeat monitor, deadline enforcement | Config (watchdog:) |
| 29 | `fips_crypto.rs` | **CryptoModuleRegistry** | Pluggable FIPS-compliant modules | Config (crypto:) |
| 30 | `post_quantum.rs` | **HybridSigner** | ML-DSA-65 + Ed25519 dual signing | Internal |
| 31 | `instruction.rs` | **InstructionPlane** | Schema validation, non-bypassable | Automatic |
| 32 | `compliance.rs` | **ComplianceEngine** | HIPAA/SOC2/GDPR/EU AI Act/DoD | Config (comply:) |
| 33 | `content_guard.rs` | **ContentGuard** | PII detection, topic blocking, token limits | Automatic |
| 34 | `formal_verify.rs` | **FormalVerifier** | Invariant checking, state machine proofs | Config (formal_verify:) |
| 35 | `firewall_events.rs` | **FirewallEvents** | Audit trail for all firewall decisions | Internal |
| 36 | `adaptive_threshold.rs` | **AdaptiveThreshold** | Dynamic security thresholds | Internal |

### Ring 4 — Distributed & Scalability (14 modules)
| # | Module | Component | Scalability Role | Exposed via |
|---|--------|-----------|-----------------|-------------|
| 37 | `bft_consensus.rs` | **BftConsensus** | PBFT 4-phase: Propose→PreVote→PreCommit→Commit | Config (consensus:) |
| 38 | `cross_cell_port.rs` | **CrossCellPort** | Cell-to-cell namespace bridge | Config (cluster:) |
| 39 | `noise_channel.rs` | **NoiseChannelManager** | Noise_IK encrypted agent-to-agent channels | Internal |
| 40 | `gateway_bridge.rs` | **GatewayBridge** | AAPI Gateway → Engine → Kernel bridge | Internal |
| 41 | `discovery.rs` | **IntentDiscovery** | Intent-based agent matching (Akash-style) | Internal |
| 42 | `circuit_breaker.rs` | **CircuitBreaker** | Fault isolation for distributed calls | Internal |
| 43 | `session_stickiness.rs` | **SessionRouter** | Affinity routing for multi-node | Internal |
| 44 | `adaptive_router.rs` | **AdaptiveRouter** | Workload-aware LLM routing | Internal |
| 45 | `reputation.rs` | **ReputationEngine** | EigenTrust distributed scoring | Internal |
| 46 | `global_quota.rs` | **GlobalQuotaTracker** | Cross-node rate limiting | Internal |
| 47 | `llm_router.rs` | **LlmRouter** | Multi-provider failover + load balance | Automatic |
| 48 | `llm.rs` | **LlmConfig** | Provider config (OpenAI/Anthropic/DeepSeek/Custom) | Config (connector:) |
| 49 | `checkpoint.rs` | **CheckpointManager** | Write-through persistence snapshots | Automatic |
| 50 | `kernel_ops.rs` | **KernelOps** | Syscall dispatch bridge | Internal |

### Cross-Cutting (11 modules)
| # | Module | Component | Scalability Role | Exposed via |
|---|--------|-----------|-----------------|-------------|
| 51 | `perception.rs` | **PerceptionEngine** | Namespace observation, multi-modal | FFI, Server (/perceive) |
| 52 | `judgment.rs` | **JudgmentEngine** | Trust scoring, quality assessment | FFI |
| 53 | `logic.rs` | **LogicEngine** | Reasoning chains, plan generation | FFI, Server (/logic/plan) |
| 54 | `grounding.rs` | **GroundingTable** | Term→definition lookup | FFI, Server (/grounding) |
| 55 | `trace.rs` | **TraceEngine** | Distributed tracing spans | Config (tracing_config:) |
| 56 | `output.rs` | **PipelineOutput** | Trust-scored result envelope | All surfaces |
| 57 | `dispatcher.rs` | **DualDispatcher** | Core orchestrator (46 internal imports) | All surfaces |
| 58 | `auto_derive.rs` | **AutoDerive** | Automatic packet derivation | Automatic |
| 59 | `error.rs` | **EngineError** | Typed error hierarchy | All surfaces |
| 60 | `l6_integration.rs` | **L6Integration** | Level 6 distributed config tests | Tests |
| 61 | `stability_test.rs` | **StabilityTests** | Cross-component stability suite | Tests |

## Distributed Architecture & Scalability

### Cell-Based Topology

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Cell: us-east-1 │     │  Cell: eu-west-1 │     │  Cell: ap-se-1   │
│                  │     │                  │     │                  │
│  MemoryKernel    │◄───►│  MemoryKernel    │◄───►│  MemoryKernel    │
│  EngineStore     │     │  EngineStore     │     │  EngineStore     │
│  AgentFleet      │     │  AgentFleet      │     │  AgentFleet      │
│                  │     │                  │     │                  │
│ ┌──────────────┐ │     │ ┌──────────────┐ │     │ ┌──────────────┐ │
│ │ CrossCellPort│─┼─────┼─│ CrossCellPort│─┼─────┼─│ CrossCellPort│ │
│ │ NoiseChannel │ │     │ │ NoiseChannel │ │     │ │ NoiseChannel │ │
│ │ BftConsensus │─┼─────┼─│ BftConsensus │─┼─────┼─│ BftConsensus │ │
│ └──────────────┘ │     │ └──────────────┘ │     │ └──────────────┘ │
└──────────────────┘     └──────────────────┘     └──────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │   Federation Layer (AAPI)   │
                    │  aapi-federation            │
                    │  aapi-gateway               │
                    │  SCITT attestation exchange  │
                    └────────────────────────────┘
```

### Scalability Components — How They Interlink

| Component | What It Does | Depends On | Enables |
|-----------|-------------|-----------|---------|
| **vac-cluster** | Multi-node cluster orchestration | vac-core, vac-bus, vac-route | Cell membership, leader election |
| **vac-replicate** | State replication across nodes | vac-core, vac-sync, vac-bus, vac-crypto | Consistent kernel state across cells |
| **vac-sync** | CAS merkle-tree sync protocol | vac-core, vac-prolly, vac-store, vac-crypto | Efficient delta replication |
| **vac-bus** | Message bus abstraction | — | Transport for cluster + replicate |
| **vac-route** | Content-addressed routing | — | Namespace → cell routing |
| **vac-crypto** | Ed25519 + HMAC-SHA256 | vac-core | Signed replication, attestation |
| **vac-prolly** | Prolly tree (content-addressed) | vac-core | Deterministic merkle sync |
| **vac-store** | Persistent KV backend | vac-core, vac-prolly | Durable cell storage |
| **BftConsensus** | PBFT 4-phase agreement | Transport via vac-bus | Cell state transitions |
| **CrossCellPort** | Namespace bridge between cells | ClusterConfig | Cross-cell memory access |
| **NoiseChannel** | Noise_IK encrypted channels | — | Secure agent-to-agent comms |
| **GatewayBridge** | AAPI Gateway → Engine | — | External API integration |
| **SagaBridge** | Distributed pipeline rollback | aapi-pipeline | Multi-step failure recovery |
| **Discovery** | Intent-based agent matching | AgentIndex | Capability-aware routing |
| **CircuitBreaker** | Fault isolation | — | Graceful degradation |
| **SessionStickiness** | Affinity routing | — | Stateful session routing |
| **AdaptiveRouter** | Workload-aware LLM routing | LlmRouter | Load-balanced LLM calls |
| **Reputation** | EigenTrust scoring | — | Trust-weighted agent selection |
| **GlobalQuota** | Cross-node rate limiting | — | Fleet-wide resource control |
| **aapi-federation** | Cross-org trust + metarules | aapi-core, aapi-metarules | Multi-organization agents |
| **aapi-gateway** | HTTP VĀKYA gateway | aapi-core, aapi-crypto, aapi-indexdb | External action authorization |
| **aapi-pipeline** | Saga-coordinated pipelines | aapi-core, aapi-adapters | Rollback-safe multi-step |

### Dependency Chain (bottom-up)

```
vac-prolly ──────► vac-store ──────► vac-sync ──────► vac-replicate
     │                 │                 │                   │
     └────► vac-core ◄─┘                 │                   │
                │                        │                   │
                ├───► vac-crypto ◄───────┘───────────────────┘
                │
                ├───► vac-bus ──────► vac-cluster
                │                        │
                └───► vac-route ─────────┘

connector-engine ──► connector-api ──► connector-protocol
       │                    │
       ├──► vac-core        ├──► connector-protocols (ANP, A2A, ACP)
       │                    │
       └──► connector-server (38 REST routes)
                │
                └──► connector-napi (NAPI-RS, 26 methods)

aapi-core ──► aapi-crypto ──► aapi-federation
   │              │
   ├──► aapi-gateway (HTTP)
   ├──► aapi-pipeline (saga rollback)
   ├──► aapi-indexdb (capability index)
   └──► aapi-metarules (governance)
```

### Config-to-Runtime Wiring (21 Phases)

`from_config()` maps every YAML section to a real runtime effect:

| Phase | Config Section | Runtime Effect |
|-------|---------------|----------------|
| A | `knowledge:` | Seed facts injected into system prompt |
| B | `agents[].budget:` | Budget enforcement in ActionEngine |
| B | `policies:` | Deny/allow rules in PolicyEngine |
| C | `firewall:` | PII detection, topic blocking, token limits |
| D | `memory:` | Kernel MemoryRegion preset (fast/long/deep/infinite) |
| E | `judgment:` | Trust scoring thresholds |
| F | `cognitive:` | Multi-pass reasoning depth |
| G | `router.retry:` | LLM retry count |
| H | `perception:` | Observation pipeline config |
| I | `tools:` | Tool definitions registered in engine |
| J | `streaming:` | SSE/WebSocket/gRPC chunked output |
| K | `cluster:` | Multi-node mode (standalone/cluster/federated) |
| L | `swarm:` | Agent fleet (pool size, A2A, load balancing, saga) |
| M | `mcp:` | Model Context Protocol servers |
| N | `server:` | HTTP address/port overrides |
| O | `watchdog:` | Heartbeat + deadline enforcement |
| P | `crypto:` | FIPS mode, key rotation, HSM |
| Q | `consensus:` | BFT protocol (PBFT/Raft/Gossip) |
| R | `observability:` | Prometheus/OTLP metrics export |
| S | `tracing_config:` | Distributed tracing (Jaeger/Zipkin) |
| T | `negotiation:` | Agent contract formation rules |
| U | `formal_verify:` | State machine invariant checking |

### Connector Protocol (CP/1.0) — 7-Layer Stack

| Layer | Module | Purpose | Entity Classes |
|-------|--------|---------|---------------|
| 1 | `identity.rs` | DID-based identity (DICE/SPIFFE/SelfSigned) | Agent, Machine, Device, Service, Sensor, Actuator, Composite |
| 2 | `channel.rs` | Noise_IK encrypted channels | All |
| 3 | `consensus.rs` | BFT state agreement | All |
| 4 | `routing.rs` | Content-addressed routing | All |
| 5 | `capability.rs` | 120 capabilities × 12 categories | Per entity class |
| 6 | `intent.rs` | Goal decomposition + execution waves | Agent, Service |
| 7 | `attestation.rs` | DICE/SPDM firmware verification | Machine, Device, Sensor, Actuator |
| — | `safety.rs` | Emergency stop (ambient, cannot be denied) | All |
| — | `telemetry.rs` | Structured telemetry streams | All |
| — | `envelope.rs` | Signed protocol envelopes | All |

### 5 Surface Layers — All Interlinked

| Surface | Method Count | Transport | Native Rust? | Distributed? |
|---------|-------------|-----------|-------------|-------------|
| **connector-server** | 38 REST routes | HTTP (Axum) | ✅ | Shared kernel (Mutex), cell-aware |
| **vac-ffi** (Python) | ~140 fn | PyO3 FFI | ✅ | In-process kernel + engine store |
| **connector-napi** (Node.js) | 26 methods | NAPI-RS native addon | ✅ | In-process kernel + engine store |
| **TypeScript SDK** | ~35 async methods | NAPI native-first, HTTP fallback | ✅ / HTTP | Both modes |
| **YAML Config** | 21 config phases | File parse → runtime | ✅ | All distributed configs wired |

## User Interfaces

### Python FFI (vac-ffi) — ~80 methods
```python
from connector_oss import Connector

c = Connector("deepseek", "deepseek-chat", api_key)
# OR
c = Connector.from_config("connector.yaml")

# Agent
r = c.agent("bot", "You are helpful").run("Hello", user="alice")

# Memory
c.write_packet(pid, "Patient has fever", "user:nurse", "pipe:er")
c.memory_write(pid, "text", "Fever noted", "user:nurse", "ns:er")
packets = c.search_namespace("ns:er", limit=10)

# Knowledge
c.knowledge_ingest("ns:er")
ctx = c.rag_retrieve(pid, "ns:er", entities=["fever"], max_facts=10)

# Cognitive
report = c.cognitive_cycle(pid, "ns:er", "Diagnose patient")

# Custom Folders
c.create_agent_folder("nurse", "notes", "Patient notes")
c.folder_put("agent:nurse/notes", "p123", '{"bp": "140/90"}')
val = c.folder_get("agent:nurse/notes", "p123")

# Policies & Capabilities
c.add_hipaa_policy()
cap = c.issue_capability("admin", "nurse", ["read", "write"], ["patient:*"], ttl_hours=24)
```

### TypeScript SDK — ~35 methods (NAPI-RS native Rust bindings)

The TypeScript SDK calls Rust directly via NAPI-RS native Node.js addon.
**No HTTP server required** when native addon is built. Falls back to HTTP if not.

```
sdks/typescript/
├── native/              ← NAPI-RS Rust crate (connector-napi)
│   ├── Cargo.toml       ← depends on connector-api, connector-engine, connector-protocol, vac-core
│   ├── build.rs
│   └── src/lib.rs       ← #[napi] exported NativeConnector struct (~30 methods)
├── src/
│   ├── connector.ts     ← native-first, HTTP fallback per method
│   ├── agent.ts
│   ├── pipeline.ts
│   ├── types.ts
│   └── index.ts
└── package.json         ← build:native → napi build, build:ts → tsc
```

```typescript
import { Connector, isNativeAvailable } from 'connector_oss'

console.log('native:', isNativeAvailable()) // true if .node addon built

// Native mode — calls Rust engine directly (no server needed)
const c = new Connector({ llm: 'deepseek:deepseek-chat', apiKey: process.env.KEY })
// OR from YAML (parsed by Rust config loader)
const c2 = Connector.fromConfig('connector.yaml')

console.log(c.isNative) // true

// Memory & Knowledge — calls Rust MemoryKernel directly
await c.remember('pid:bot', 'Patient data', 'alice')
const mems = await c.memories('ns:er')
await c.knowledgeIngest('ns:er')

// Sessions, Search, Folders — all native Rust
const sess = await c.sessionCreate('pid:bot', 'ns:er', 'ER Visit')
await c.sessionClose('pid:bot', sess.session_id)
const results = await c.search({ namespace: 'ns:er', limit: 10 })
await c.folderCreate('agent:nurse/notes', 'agent', 'nurse', 'Patient notes')
await c.folderPut('agent:nurse/notes', 'p123', { bp: '140/90' })

// Connector Protocol (CP/1.0) — direct Rust protocol engine
const info = await c.protocolInfo()           // 7-layer summary
const caps = await c.protocolCapabilities()   // 120 capabilities × 12 categories
await c.protocolIdentityRegister('robot-1', 'machine')
await c.protocolEstop('operator', 'safety violation', 'global')
await c.protocolIntent('planner', 'mill bracket', { coordination: 'parallel' })

// Trust & Cognitive
const trust = await c.trust()
const stats = await c.dbStats()
```

## Data Flow

```
User Input
    │
    ▼
┌─ ConnectorBuilder ─────────────────────────────────────┐
│  .llm()  .compliance()  .storage()  .cell()            │
│  .from_config()  → parses YAML → wires all 3 tiers     │
└────────────────────┬────────────────────────────────────┘
                     │  .build()
                     ▼
┌─ Connector ────────────────────────────────────────────┐
│  .agent("name", "instructions").run("input", "user")   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─ DualDispatcher ───────────────────────────────────────┐
│  1. register_actor() → kernel AgentRegister + Start     │
│  2. Firewall check → non-bypassable boundary            │
│  3. Guard pipeline → MAC + Policy + Content + Rate      │
│  4. remember() → write MemPacket to kernel              │
│  5. RAG retrieve → inject knowledge context             │
│  6. LLM Router → call provider (with fallbacks)         │
│  7. recall() → verify + audit trail                     │
│  8. Output → PipelineOutput with trust score            │
└─────────────────────────────────────────────────────────┘
```

## Storage Architecture

```
/cell:{cell_id}/
├── kernel/          # MemPackets, agents, sessions (Redb/InMemory)
├── audit/           # Audit entries (append-only)
├── knowledge/       # KnotEngine entity graph
├── tools/           # Tool definitions
├── policies/        # Policy rules
├── folders/         # Custom agent/tool folders (SQLite)
│   ├── agent:nurse/notes/
│   ├── agent:doctor/diagnoses/
│   └── tool:search/cache/
├── secrets/         # Opaque handles, TTL, kernel-only
├── checkpoints/     # Write-through persistence
└── escrow/          # Trustless payment locks
```

## Protocol Bridges (connector-protocols)

| Protocol | Standard | Status |
|----------|----------|--------|
| **ANP** | W3C DID + Ed25519 | ✅ Built |
| **A2A** | Google Agent-to-Agent | ✅ Built |
| **ACP** | IBM/LF Agent Communication | ✅ Built |
| **MCP** | Model Context Protocol | ✅ Config parsed |
| **SCITT** | Supply Chain Integrity | ✅ Built (connector-protocol) |

## Where Connector-OSS Fits — Technical Positioning

Connector-OSS is **not a container runtime**. It is a **kernel + control-plane + SDK platform** for agent execution with verifiable memory and security policy enforcement.

### Comparison Table: Docker vs Kubernetes vs Istio vs Vault vs OPA vs Connector

| Primitive | Docker | Kubernetes | Istio/Envoy | Vault | OPA | **Connector-OSS** |
|-----------|--------|-----------|-------------|-------|-----|-------------------|
| **Process isolation** | ✅ cgroups + namespaces | Delegates to runtime | — | — | — | ⚠️ Logical (cells + agent namespaces, not OS-level) |
| **Image packaging** | ✅ OCI layers | Pod specs | — | — | — | — |
| **Resource limits** | ✅ cgroups (CPU/mem) | Resource quotas | — | — | — | ✅ GlobalQuota, ContextManager (token budgets), budget enforcement |
| **Lifecycle mgmt** | ✅ create/start/stop | Pod lifecycle | — | — | — | ✅ AgentRegister → AgentStart → AgentTerminate (syscall API) |
| **Namespace isolation** | ✅ Linux namespaces | K8s namespaces | — | — | — | ✅ `/cell:{id}/` storage zones, per-agent memory namespaces |
| **Scheduling** | — | ✅ kube-scheduler | — | — | — | ✅ Orchestrator (DAG), AdaptiveRouter, SessionStickiness |
| **Service discovery** | — | ✅ DNS + endpoints | ✅ | — | — | ✅ IntentDiscovery (capability-based, Akash-style) |
| **Multi-node cluster** | Docker Swarm | ✅ etcd + control plane | — | ✅ HA | — | ✅ vac-cluster + vac-replicate + BftConsensus |
| **Federation** | — | Multi-cluster | Mesh federation | — | — | ✅ aapi-federation + SCITT attestation exchange |
| **Traffic routing** | — | Ingress/Service | ✅ Envoy filters | — | — | ✅ CrossCellPort, AdaptiveRouter, content-addressed routing |
| **mTLS / encryption** | — | — | ✅ Envoy mTLS | ✅ PKI | — | ✅ Noise_IK channels, Ed25519, post-quantum ML-DSA-65 |
| **Policy enforcement** | seccomp/AppArmor | RBAC + PSP | ✅ AuthZ filters | ✅ ACL | ✅ Rego | ✅ GuardPipeline (5-layer), PolicyEngine, Firewall (non-bypassable) |
| **Secret management** | Docker secrets | K8s secrets | — | ✅ Core feature | — | ✅ SecretStore (opaque handles, TTL, auto-redact) |
| **Audit trail** | Audit events | Audit log | Access log | ✅ Audit | Decision log | ✅ Append-only, Ed25519-signed, SCITT receipts |
| **Compliance** | — | — | — | — | Policy-as-code | ✅ HIPAA/SOC2/GDPR/EU AI Act/DoD built-in |
| **Telemetry** | Stats API | Metrics API | ✅ Prometheus/Zipkin | — | — | ✅ Prometheus metrics, distributed tracing, telemetry streams |
| **Circuit breaker** | — | — | ✅ Envoy | — | — | ✅ CircuitBreakerManager |
| **Saga / rollback** | — | — | — | — | — | ✅ SagaBridge (distributed pipeline rollback) |
| **Memory integrity** | — | — | — | — | — | ✅ **Core feature**: tamper-proof MemPackets, CID-addressed, kernel-verified |
| **Knowledge graph** | — | — | — | — | — | ✅ **Core feature**: KnotEngine, RAG retrieval, entity binding |
| **Trust scoring** | — | — | — | — | — | ✅ **Core feature**: JudgmentEngine, ReputationEngine (EigenTrust) |
| **Agent protocol** | — | — | — | — | — | ✅ **Core feature**: CP/1.0 (7 layers, 120 caps, identity, attestation) |

### What Connector-OSS IS

```
┌─────────────────────────────────────────────────────────────────┐
│                    Connector-OSS = 3 things                     │
│                                                                 │
│  1. KERNEL    — OS-grade runtime for agent state + trust        │
│     vac-core: syscalls, audit, namespaces, cells, crypto        │
│     connector-engine: firewall, policy, watchdog, routing       │
│     /cell:{id}/... layout = OS-like filesystem for agent state  │
│                                                                 │
│  2. CONTROL PLANE — multi-cell orchestration for agent fleets   │
│     Cells, cross-cell ports, discovery, global quota            │
│     BFT consensus, reputation, routing, saga rollback           │
│     aapi-federation + metarules = cross-org governance          │
│                                                                 │
│  3. ENFORCEMENT MESH — service-mesh-grade policy + telemetry    │
│     GuardPipeline: MAC → Policy → Content → Rate → Audit       │
│     Non-bypassable firewall, capability auth, protocol layer    │
│     Noise channels, Ed25519/PQ signing, SCITT attestation       │
└─────────────────────────────────────────────────────────────────┘
```

### What Connector-OSS is NOT

- **Not a container runtime** — no OCI images, no cgroups, no filesystem mounts, no process isolation
- **Not a process scheduler** — no device drivers, no init system
- **Not replacing Docker/K8s** — runs *inside* Docker, orchestrated *by* K8s

### The Correct 1-Line Positioning

| Audience | Positioning |
|----------|------------|
| **Kernel** | "OS-grade runtime that makes agent memory/actions verifiable and policy-enforced" |
| **Control-plane** | "Control-plane for agent cells: trust, routing, federation, rollback" |
| **Mesh** | "Service-mesh-style enforcement + telemetry layer for agent execution" |
| **Infra** | "HashiCorp Vault + OPA + agent runtime — combined as SDKs + server + config" |
| **Git analogy** | "Git for memory evidence + policy gateway + multi-cell runtime" |

### Maturity Stage

| Layer | Status |
|-------|--------|
| ✅ Platform foundation | 28 crates, 61 engine modules, 1,857 tests |
| ✅ SDK + server surfaces | Python FFI (~140 fn), NAPI-RS (26 methods), TypeScript SDK (~35 methods), REST (38 routes) |
| ✅ Policy/security/telemetry | 5-layer guard, firewall, compliance, watchdog, tracing, metrics |
| ✅ Protocol system | CP/1.0 (7 layers, 120 caps, identity, channel, consensus, routing, attestation) |
| ✅ Distributed infra | Cells, cluster, replicate, sync, BFT consensus, federation, saga |
| ⚠️ Not in scope | OS-level process isolation, OCI packaging, device drivers, init system |

## Security Model

- **Bell-LaPadula** (confidentiality) + **Biba** (integrity) MAC labels on every packet
- **5-layer guard pipeline**: MAC → Policy → Content → Rate → Audit
- **Non-bypassable firewall**: PII detection, topic blocking, token limits
- **Ed25519 signing** on all audit entries (optional SCITT receipts)
- **Post-quantum ready**: Hybrid ML-DSA-65 + Ed25519 signer
- **Semantic injection detection**: Advanced prompt injection defense
- **Noise Protocol channels**: Encrypted agent-to-agent communication
- **FIPS crypto registry**: Pluggable cryptographic modules
- **Secret store**: Opaque handles with TTL, automatic redaction in audit

## Install & Run

### Install from Package Managers (recommended)

```bash
# ── Python (PyPI) ──
pip install connector-oss

# ── TypeScript / Node.js (npm) ──
npm install @connector-oss/connector

# ── Docker (server with 38 REST routes) ──
docker run -p 8080:8080 -e DEEPSEEK_API_KEY=sk-... globalsushrut/connector-oss

# ── Docker Compose (with SQLite persistence) ──
export DEEPSEEK_API_KEY=sk-...
docker compose up
```

### Build from Source

```bash
# ── Build all (28 crates) ──
cd connector && cargo build       # API + engine + server + protocol
cd vac && cargo build             # Kernel + distributed + FFI
cd aapi && cargo build            # Action authorization + federation

# ── Test all (1,857 tests) ──
cd connector && cargo test        # 1,194 tests
cd vac && cargo test              # 492 tests
cd aapi && cargo test             # 171 tests

# ── Run server (38 routes) ──
DEEPSEEK_API_KEY=sk-... cargo run -p connector-server

# With distributed config
CONNECTOR_ENGINE_STORAGE=sqlite:./data.db \
CONNECTOR_CELL_ID=cell_us_east_1 \
cargo run -p connector-server

# ── Python FFI (~140 fn) ──
cd sdks/python && pip install maturin && maturin develop --release
python -c "from connector_oss import Connector; print('ready')"

# ── TypeScript SDK (NAPI-RS native) ──
cd sdks/typescript && npm install && npm run build
node -e "const {Connector,isNativeAvailable}=require('./dist'); console.log('native:',isNativeAvailable())"

# ── Docker build ──
docker build -t connector-oss .
```

### Packaging & CI

| Package | Registry | Install command | CI Workflow |
|---------|----------|----------------|-------------|
| **connector-oss** | PyPI | `pip install connector-oss` | `.github/workflows/publish-pypi.yml` |
| **@connector-oss/connector** | npm | `npm install @connector-oss/connector` | `.github/workflows/publish-npm.yml` |
| **globalsushrut/connector-oss** | Docker Hub + GHCR | `docker run globalsushrut/connector-oss` | `.github/workflows/publish-docker.yml` |

All publish workflows trigger on `git tag v*` and build for multiple platforms:
- **Python**: Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64)
- **npm**: Same 5 platforms + Linux musl (x86_64, aarch64)
- **Docker**: linux/amd64 (scratch image, ~8MB, 0 CVEs)

See [QUICKSTART.md](QUICKSTART.md) for a 5-minute copy-paste guide.
