# System Overview

> 4-ring architecture, request lifecycle, design invariants

---

## The 4-Ring Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Language Bindings                                                           │
│  Python: vac-ffi (PyO3)  →  Connector, AgentHandle, PipelineOutput         │
│  TypeScript: REST client  →  connector-server (axum, port 8080)             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 4 — connector-api                                                      │
│  Connector · AgentBuilder · PipelineBuilder · SecurityConfig                │
│  PipelineOutputExt: trust() · comply() · replay() · xray() · audit()       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 3 — connector-engine                                                   │
│  DualDispatcher · BindingEngine · KnowledgeEngine · LogicEngine             │
│  PerceptionEngine · TrustComputer · ComplianceVerifier · LlmRouter          │
│  Firewall · BehaviorAnalyzer · CheckpointManager · KernelOps                │
│  AutoDerive · AutoVakya · ClaimVerifier · GroundingTable · JudgmentEngine   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 1 — VAC Memory Kernel     │  Ring 2 — AAPI Action Kernel              │
│  vac-core: MemoryKernel         │  aapi-core:       VAKYA grammar            │
│            SyscallRequest       │  aapi-crypto:     Ed25519 + capability     │
│            MemPacket (3-plane)  │  aapi-indexdb:    append-only log          │
│            KernelAuditEntry     │  aapi-gateway:    HTTP server              │
│            KnotEngine           │  aapi-metarules:  policy engine            │
│            InterferenceEngine   │  aapi-pipeline:   saga pipelines           │
│  vac-prolly: Prolly tree        │  aapi-federation: cross-cell policy        │
│  vac-store:  KernelStore trait  │  aapi-adapters:   file/http/db             │
│  vac-crypto: SHA2-256/Ed25519   │  aapi-sdk / aapi-cli                       │
│  vac-cluster: multi-node cells  │                                            │
│  vac-bus / vac-route / vac-sync │                                            │
│  vac-replicate / vac-red        │                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 0 — Cryptographic Foundation                                           │
│  CIDv1 (DAG-CBOR + SHA2-256) · Ed25519 · HMAC-SHA256 · Prolly Merkle       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Full Request Lifecycle

```
agent.run("Patient: chest pain, BP 158/95", "user:alice")
  │
  ├─ [Ring 4] connector-api builds AgentRequest
  │
  ├─ [Ring 3] DualDispatcher.run_agent()
  │    │
  │    ├─ Firewall.evaluate(input)
  │    │    → ThreatScorer: injection=0.05, exfil=0.00 → score=0.02 → Allow
  │    │
  │    ├─ InstructionPlane.validate(instructions)
  │    │    → source=user, schema=chat.send → ok
  │    │
  │    ├─ [Ring 1] MemoryKernel.dispatch(AgentRegister "triage")
  │    │    → pid:000001 assigned
  │    │    → audit #1: AgentRegister, Success, 42µs
  │    │
  │    ├─ [Ring 1] MemoryKernel.dispatch(AgentStart pid:000001)
  │    │    → audit #2: AgentStart, Success, 18µs
  │    │
  │    ├─ [Ring 1] MemoryKernel.dispatch(MemWrite input_packet)
  │    │    → CID = bafyreihgvk... (SHA2-256 of DAG-CBOR bytes)
  │    │    → stored in ns:triage
  │    │    → audit #3: MemWrite, Success, 187µs
  │    │
  │    ├─ [Ring 2] AutoVakya.build(pid:000001, "run", "pipe:er")
  │    │    → IssuedCapability { token_id: vk_8f7a2d, expires_at: +5min }
  │    │
  │    ├─ LlmRouter.call(provider=deepseek, model=deepseek-chat)
  │    │    → HTTP POST api.deepseek.com/chat/completions
  │    │    → response: "Urgency 1. Differentials: ACS (I21.3)..."
  │    │
  │    ├─ BehaviorAnalyzer.record(pid:000001, latency=1.2s, tokens=312)
  │    │    → sliding window: no anomaly
  │    │
  │    ├─ [Ring 1] MemoryKernel.dispatch(MemWrite response_packet)
  │    │    → CID = bafyreigima...
  │    │    → audit #4: MemWrite, Success, 232µs
  │    │
  │    └─ TrustComputer.compute(kernel)
  │         → memory_integrity=20, audit_completeness=20,
  │           authorization_coverage=20, decision_provenance=20, health=20
  │         → total=100, grade=A+
  │
  └─ PipelineOutput {
       text:        "Urgency 1. Differentials: ACS (I21.3)...",
       trust:       100,
       trust_grade: "A+",
       cid:         "bafyreigima...",
       trace_id:    "pipe:triage",
       ok:          true,
       verified:    true,
       warnings:    [],
       provenance:  { kernel_verified: 4, total: 4, trust_percentage: 100 }
     }
```

---

## Workspaces

| Workspace | Path | Crates |
|-----------|------|--------|
| VAC | `vac/` | 12 crates — vac-core, vac-prolly, vac-store, vac-crypto, vac-bus, vac-cluster, vac-replicate, vac-route, vac-sync, vac-red, vac-ffi, vac-wasm |
| AAPI | `aapi/` | 10 crates — aapi-core, aapi-crypto, aapi-indexdb, aapi-gateway, aapi-metarules, aapi-pipeline, aapi-federation, aapi-adapters, aapi-sdk, aapi-cli |
| Connector | `connector/` | 3 crates — connector-engine, connector-api, connector-server |

---

## Design Invariants

1. **Every syscall produces an audit entry** — enforced at `MemoryKernel::dispatch()`, not the SDK layer.
2. **CID is computed before storage** — if stored content doesn't match CID, tampering is detected immediately.
3. **Namespace isolation is kernel-enforced** — no SDK bypass possible; `AccessGrant` is a syscall.
4. **Trust score is kernel-derived** — computed from real audit data, not self-reported configuration flags.
5. **Storage is a trait** — `KernelStore` means the kernel works identically across all backends.
6. **Firewall is non-bypassable** — embedded in `DualDispatcher`; every operation passes through before hitting either kernel.
7. **VAKYA wraps every action** — no action without an authorization token; `AutoVakya` builds it automatically.
8. **Audit log is HMAC-chained** — deletion, insertion, or reordering of entries is cryptographically detectable.
