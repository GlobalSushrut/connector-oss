# Connector OSS — Documentation Index

> 29 topic documents covering every layer of the system, from cryptographic foundations to deployment.

---

## System Overview

| # | File | Topic |
|---|------|-------|
| 1 | [01_INDEX.md](01_INDEX.md) | This index |
| 2 | [02_SYSTEM_OVERVIEW.md](02_SYSTEM_OVERVIEW.md) | 4-ring architecture, request lifecycle, design invariants |

---

## Ring 0 — Cryptographic Foundation

| # | File | Topic |
|---|------|-------|
| 3 | [03_CID_AND_DAG_CBOR.md](03_CID_AND_DAG_CBOR.md) | CIDv1 computation, DAG-CBOR encoding, Prolly key format |
| 4 | [04_MERKLE_AND_PROLLY.md](04_MERKLE_AND_PROLLY.md) | Prolly tree, Merkle proofs, block/manifest hashing |
| 5 | [05_ED25519_AND_HMAC.md](05_ED25519_AND_HMAC.md) | Ed25519 signing, HMAC-SHA256 audit chain, EncryptedStore |

---

## Ring 1 — VAC Memory Kernel

| # | File | Topic |
|---|------|-------|
| 6 | [06_MEMORY_KERNEL.md](06_MEMORY_KERNEL.md) | MemoryKernel internals, syscall dispatch, agent lifecycle |
| 7 | [07_MEMPACKET.md](07_MEMPACKET.md) | MemPacket 3-plane model, PacketType enum, all fields |
| 8 | [08_SYSCALLS.md](08_SYSCALLS.md) | Complete SyscallPayload variants, SyscallResult, OpOutcome |
| 9 | [09_NAMESPACE_ISOLATION.md](09_NAMESPACE_ISOLATION.md) | Namespace ACLs, AccessGrant/Revoke, port system |
| 10 | [10_AUDIT_CHAIN.md](10_AUDIT_CHAIN.md) | KernelAuditEntry, HMAC chain, integrity check, overflow |
| 11 | [11_SESSIONS_AND_CONTEXTS.md](11_SESSIONS_AND_CONTEXTS.md) | SessionEnvelope, ContextSnapshot, compression |
| 12 | [12_STORAGE_BACKENDS.md](12_STORAGE_BACKENDS.md) | KernelStore trait, all backends, redb, EncryptedStore, cluster |
| 13 | [13_KNOT_ENGINE.md](13_KNOT_ENGINE.md) | KnotEngine, KnotNode/Edge, 4-way retrieval, RRF fusion |
| 14 | [14_INTERFERENCE_ENGINE.md](14_INTERFERENCE_ENGINE.md) | StateVector, InterferenceEdge, compaction, contradiction |

---

## Ring 2 — AAPI Action Kernel

| # | File | Topic |
|---|------|-------|
| 15 | [15_VAKYA_GRAMMAR.md](15_VAKYA_GRAMMAR.md) | 8 slots, 15 verbs, VAKYA structure, CID-linked tokens |
| 16 | [16_AAPI_POLICY.md](16_AAPI_POLICY.md) | PolicyRule, MetaRules engine, BudgetTracker, IssuedCapability |
| 17 | [17_AAPI_PIPELINE.md](17_AAPI_PIPELINE.md) | VakyaPipeline, SagaCoordinator, rollback, federation |

---

## Ring 3 — connector-engine

| # | File | Topic |
|---|------|-------|
| 18 | [18_DUAL_DISPATCHER.md](18_DUAL_DISPATCHER.md) | DualDispatcher, Firewall, InstructionPlane, BehaviorAnalyzer |
| 19 | [19_COGNITIVE_LOOP.md](19_COGNITIVE_LOOP.md) | BindingEngine, 5 phases: Perceive→Retrieve→Reason→Reflect→Act |
| 20 | [20_KNOWLEDGE_ENGINE.md](20_KNOWLEDGE_ENGINE.md) | KnowledgeEngine, ingest, retrieve, compile, contradictions |
| 21 | [21_TRUST_COMPUTER.md](21_TRUST_COMPUTER.md) | 5-dimension trust score, grades, kernel-derived verification |
| 22 | [22_COMPLIANCE_ENGINE.md](22_COMPLIANCE_ENGINE.md) | Standards, Evidence types, ComplianceReport, all 7 frameworks |
| 23 | [23_LLM_ROUTER.md](23_LLM_ROUTER.md) | LlmRouter, retry, fallback, circuit breaker, cost tracking |

---

## Ring 4 — connector-api & SDK

| # | File | Topic |
|---|------|-------|
| 24 | [24_CONNECTOR_API.md](24_CONNECTOR_API.md) | Connector, AgentBuilder, PipelineBuilder, 4 progressive layers |
| 25 | [25_YAML_CONFIG.md](25_YAML_CONFIG.md) | ConnectorConfig, 3-tier design, all fields, env-var interpolation |
| 26 | [26_PIPELINE_OUTPUT.md](26_PIPELINE_OUTPUT.md) | PipelineOutput, PipelineOutputExt, Provenance, ObservationEvent |
| 27 | [27_PYTHON_SDK.md](27_PYTHON_SDK.md) | vac-ffi PyO3 bindings, Connector/AgentHandle classes |
| 28 | [28_TYPESCRIPT_SDK.md](28_TYPESCRIPT_SDK.md) | connector-server REST API, TypeScript SDK, fromConfig |

---

## Operations

| # | File | Topic |
|---|------|-------|
| 29 | [29_SECURITY_MODEL.md](29_SECURITY_MODEL.md) | SecurityConfig, signing, SCITT, classification, MFA, delegation |
| 30 | [30_DEPLOYMENT.md](30_DEPLOYMENT.md) | Build, Docker, connector-server, Prometheus metrics, scaling |

---

## Dictionaries & Quickstart

> These 5 documents are designed to be self-sufficient — enough to build any system from a simple chatbot to military-grade infrastructure without reading anything else.

| # | File | Topic |
|---|------|-------|
| 31 | [31_YAML_DICTIONARY.md](31_YAML_DICTIONARY.md) | Every YAML key in plain English — what it does, values, defaults, examples |
| 32 | [32_CODE_DICTIONARY_PYTHON.md](32_CODE_DICTIONARY_PYTHON.md) | Python patterns — 3-line agent to military grade, every method explained |
| 33 | [33_CODE_DICTIONARY_RUST.md](33_CODE_DICTIONARY_RUST.md) | Rust patterns — builder API, expert config, raw kernel syscalls |
| 34 | [34_CODE_DICTIONARY_TYPESCRIPT.md](34_CODE_DICTIONARY_TYPESCRIPT.md) | TypeScript patterns — REST API, SDK, pipeline, all use cases |
| 35 | [35_QUICKSTART.md](35_QUICKSTART.md) | 5-minute quickstart — 9 paths from zero to any use case |

---

## Quick Reference

```
vac/crates/
  vac-core/src/
    kernel.rs          → MemoryKernel, SyscallRequest, SyscallPayload
    types.rs           → MemPacket, PacketType, Event, ClaimBundle, BlockHeader
    cid.rs             → compute_cid(), DAG-CBOR, Prolly key builders
    knot.rs            → KnotEngine, KnotNode, KnotEdge, RRF
    interference.rs    → StateVector, InterferenceEdge, compaction
    audit_export.rs    → audit export helpers
    store.rs           → KernelStore trait, InMemoryKernelStore, EncryptedStore
  vac-prolly/src/
    tree.rs            → ProllyTree, NodeStore trait
    proof.rs           → ProllyProof, ProofStep
  vac-store/src/
    prolly_bridge.rs   → ProllyKernelStore
    indexdb_bridge.rs  → IndexDbKernelStore, AsyncPersistenceBackend
  vac-cluster/src/
    cluster_store.rs   → ClusterKernelStore
  vac-ffi/src/lib.rs   → PyO3 Connector, AgentHandle

aapi/crates/
  aapi-core/           → VAKYA grammar
  aapi-crypto/         → Ed25519, capability tokens
  aapi-indexdb/        → append-only log
  aapi-gateway/        → HTTP server
  aapi-metarules/      → policy engine
  aapi-pipeline/       → VakyaPipeline, SagaCoordinator
  aapi-federation/     → FederatedPolicyEngine, ScittExchange

connector/crates/
  connector-engine/src/
    dispatcher.rs      → DualDispatcher, ActorConfig, DispatcherSecurity
    binding.rs         → BindingEngine, CognitivePhase, CycleSummary
    knowledge.rs       → KnowledgeEngine, IngestResult, CompiledKnowledge
    logic.rs           → LogicEngine, Plan, PlanStep, ReasoningChain
    perception.rs      → PerceptionEngine, Observation, PerceivedContext
    trust.rs           → TrustComputer, TrustScore, TrustDimensions
    compliance.rs      → ComplianceVerifier, Standard, Evidence, ComplianceReport
    llm_router.rs      → LlmRouter, RetryConfig, CircuitBreakerConfig
    firewall.rs        → AgentFirewall, ThreatScorer, Verdict, Signal
    behavior.rs        → BehaviorAnalyzer, BehaviorConfig
    checkpoint.rs      → CheckpointManager, CheckpointConfig
    kernel_ops.rs      → KernelOps, KernelStats, AgentInfo, AuditEntry
    redb_store.rs      → RedbKernelStore (13 tables)
    aapi.rs            → ActionEngine, PolicyRule, BudgetTracker, IssuedCapability
    claims.rs          → Claim, ClaimVerifier, SupportLevel, VerificationResult
    grounding.rs       → GroundingTable, CodeEntry
    judgment.rs        → JudgmentEngine, JudgmentResult
    llm.rs             → LlmClient, LlmConfig, ChatMessage
    output.rs          → PipelineOutput, OutputBuilder, Provenance, ObservationEvent
    trace.rs           → Trace, Span, SpanType, TraceSummary
  connector-api/src/
    connector.rs       → Connector, ConnectorBuilder
    agent.rs           → AgentBuilder, OutputGuard, PipelineOutputExt
    pipeline.rs        → Pipeline, PipelineBuilder, NodeBuilder
    config.rs          → ConnectorConfig, GlobalConfig, 3-tier design
    security.rs        → SecurityConfig, SigningAlgorithm
    observe.rs         → TrustBadge, compliance/replay/xray/audit helpers
  connector-server/src/
    main.rs            → axum server, CONNECTOR_ADDR env var
    routes.rs          → POST /run, POST /pipeline, POST /config/parse, GET /health
    metrics.rs         → 9 Prometheus metrics
```
