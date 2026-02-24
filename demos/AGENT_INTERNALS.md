# Agent System Internals

How a single `agent.run("input")` call flows through all 7 components — from SDK surface to VAC kernel and back.

---

## System Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  SDK Surface  (Python vac-ffi / TypeScript REST)                            │
│                                                                             │
│   c = Connector.from_config("hospital.yaml")                                │
│   agent = c.agent("triage", "You are an ER nurse...")                       │
│   result = agent.run("Patient: chest pain...")                              │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │  AgentRequest { input, user, instructions }
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  connector-api  (Ring 3 — Public API)                                       │
│                                                                             │
│  • Connector::run_agent() — entry point                                     │
│  • Loads YAML config (3-tier: mandatory / default / optional-revoke)        │
│  • Builds DualDispatcher with shared MemoryKernel                           │
│  • Returns PipelineOutput { text, trust, cid, trace, ... }                  │
└────────────────────────────┬────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  [1] DualDispatcher  (connector-engine/dispatcher.rs)                       │
│                                                                             │
│  The central router. Every operation passes through here.                   │
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │  Firewall    │    │  Behavior    │    │  Checkpoint  │                  │
│  │  (pre-check) │───▶│  Analyzer   │───▶│  Manager     │                  │
│  └──────────────┘    └──────────────┘    └──────────────┘                  │
│         │                                       │                          │
│         ▼                                       ▼                          │
│  ┌──────────────────────────┐   ┌───────────────────────────┐              │
│  │  VAC Memory Kernel       │   │  AAPI Action Engine       │              │
│  │  (Ring 1)                │   │  (Ring 2)                 │              │
│  └──────────────────────────┘   └───────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## The 7 Components

### [1] DualDispatcher
**File:** `connector-engine/src/dispatcher.rs`

The backbone. Routes every operation to the correct kernel and cross-links results.

```
Operation arrives
      │
      ├─▶ [Firewall] — threat score → Allow / Warn / Review / Block
      │
      ├─▶ [InstructionPlane] — validate instruction source + integrity
      │
      ├─▶ [BehaviorAnalyzer] — sliding window anomaly detection
      │
      ├─▶ [CheckpointManager] — save/restore agent state at decision points
      │
      ├─▶ VAC MemoryKernel.dispatch(SyscallRequest) — memory ops
      │
      └─▶ AAPI ActionEngine — policy evaluation + capability issuance
```

**Key types:**
- `ActorConfig` — per-agent allowed/denied tools, data, approval gates
- `DispatcherSecurity` — PHI/PII classification, retention, Ed25519 signing, SCITT
- `DualDispatcher<'k>` — owns or borrows the shared `MemoryKernel`

---

### [2] VAC Memory Kernel  (Ring 1)
**Crate:** `vac/crates/vac-core`

The tamper-evident memory substrate. All data is content-addressed.

```
SyscallRequest { agent_pid, operation, payload, reason, vakya_id }
      │
      ▼
MemoryKernel.dispatch()
      │
      ├─▶ AgentRegister / AgentStart / AgentTerminate
      │       → assigns PID, creates isolated namespace ns:<name>
      │
      ├─▶ MemWrite { packet }
      │       → CID = SHA3-256(DAG-CBOR(packet))
      │       → stored in namespace, appended to audit log
      │
      ├─▶ MemRead { cid }
      │       → checks agent has read grant for owning namespace
      │       → returns content or DENIED
      │
      ├─▶ AccessGrant { namespace, grantee_pid }
      │       → adds grantee to namespace ACL
      │
      └─▶ IntegrityCheck
              → verifies all CIDs match stored content (Merkle)

SyscallResponse { value: SyscallValue, outcome: OpOutcome, audit_entry }
```

**Every op produces an `AuditEntry`** — agent_pid, operation, outcome, duration_µs, HMAC-linked to previous entry. The chain is tamper-evident.

**Namespace isolation:** each agent owns exactly one namespace. Cross-reads require an explicit `AccessGrant` from the owning agent. No implicit sharing.

---

### [3] AAPI Action Engine  (Ring 2)
**File:** `connector-engine/src/aapi.rs`

Policy-based authorization for every action an agent takes.

```
ActionEngine
  │
  ├─▶ PolicyRule { effect, action_pattern, resource_pattern, roles, priority }
  │       → Allow / Deny / RequireApproval
  │
  ├─▶ BudgetTracker { agent_pid, resource, limit, used }
  │       → rate-limits token spend, API calls, tool invocations
  │
  ├─▶ IssuedCapability { token_id, agent_pid, action, resource, expires_at }
  │       → OCAP-style delegation — agent can sub-delegate with depth limit
  │
  └─▶ ComplianceConfig { frameworks: [HIPAA, SOC2, GDPR], classification, retention }
          → applied to every packet written to VAC kernel
```

**Vakya** — every AAPI action is wrapped in a `Vakya` (Sanskrit: "utterance") — a signed, CID-linked authorization token. No action without a Vakya.

---

### [4] Firewall
**File:** `connector-engine/src/firewall.rs`

Non-bypassable. Embedded in DualDispatcher — every operation passes through before hitting either kernel.

```
Input signals → ThreatScorer (weighted ML-like) → scalar score → Verdict

Signals:
  • prompt_injection_patterns   weight=0.35
  • data_exfiltration_patterns  weight=0.30
  • privilege_escalation        weight=0.20
  • jailbreak_patterns          weight=0.25
  • tool_abuse                  weight=0.15
  • anomalous_volume            weight=0.10

Verdict:
  Allow  (score < 0.3)
  Warn   (0.3–0.5)   → logged, continues
  Review (0.5–0.7)   → flagged for human review
  Block  (> 0.7)     → operation rejected, audit entry written
```

Research basis: MAESTRO 7-layer (CSA 2025), OWASP LLM Top 10 (2025), EU AI Act Art.9.

---

### [5] BindingEngine — Cognitive Loop
**File:** `connector-engine/src/binding.rs`

The top-level orchestrator for agentic pipelines. Runs the **observe → think → act** cycle.

```
                    ┌─────────────────────────────────┐
                    │         BindingEngine            │
                    │                                  │
  raw input ──────▶ │  Phase 1: PERCEIVE               │
                    │    PerceptionEngine.observe()    │
                    │    → CID-backed observation      │
                    │    → entity extraction           │
                    │    → claim verification          │
                    │    → quality score (0-100)       │
                    │                                  │
                    │  Phase 2: RETRIEVE               │
                    │    KnowledgeEngine.retrieve()    │
                    │    → 4-way retrieval + RRF       │
                    │    → KnotEngine graph query      │
                    │    → InterferenceEngine check    │
                    │                                  │
                    │  Phase 3: REASON                 │
                    │    LogicEngine.plan()            │
                    │    → goal decomposition          │
                    │    → step execution              │
                    │    → each step CID-linked        │
                    │                                  │
                    │  Phase 4: REFLECT                │
                    │    LogicEngine.reflect()         │
                    │    → quality evaluation          │
                    │    → contradiction detection     │
                    │    → reconsider if needed        │
                    │                                  │
                    │  Phase 5: ACT                    │
                    │    KnowledgeEngine.compile()     │
                    │    → cache reasoning as memory   │
                    │    → write decision CID to VAC   │
                    └─────────────────────────────────┘
                                    │
                              CycleSummary
                    { observation_cid, decision_cid,
                      facts_retrieved, reasoning_steps,
                      quality_score, contradiction_detected }
```

---

### [6] KnowledgeEngine
**File:** `connector-engine/src/knowledge.rs`

Wraps: RAG + KnotEngine (graph) + InterferenceEngine (contradiction detection).

```
KnowledgeEngine
  │
  ├─▶ ingest(observations)
  │       → upsert entities + edges into KnotEngine graph
  │       → compute StateVector (quantum-inspired interference)
  │       → detect contradictions vs. previous state
  │       → returns IngestResult { entities_upserted, interference_score }
  │
  ├─▶ retrieve(query, budget_tokens)
  │       → 4-way retrieval:
  │           1. Semantic (embedding similarity)
  │           2. Keyword (BM25-style)
  │           3. Graph (KnotEngine.query — entity hops)
  │           4. Temporal (recency-weighted)
  │       → RRF (Reciprocal Rank Fusion) to merge results
  │       → token-budget trimming
  │       → returns RetrievedFact[] with provenance CIDs
  │
  ├─▶ compile(reasoning_chain)
  │       → serialize ReasoningChain as CompiledKnowledge
  │       → write to VAC kernel with CID
  │       → available for future retrieval (avoids re-reasoning)
  │
  └─▶ contradictions()
          → compare current StateVector vs. previous
          → returns ContradictionReport { conflicts, severity }
```

---

### [7] TrustComputer
**File:** `connector-engine/src/trust.rs`

Trust is **not self-reported**. It is computed from real kernel data across 5 dimensions.

```
TrustComputer.compute(kernel: &MemoryKernel) → TrustScore

5 Dimensions (each 0–20, total 0–100):

  ┌─────────────────────────┬──────┬──────────────────────────────────────────┐
  │ Dimension               │ Max  │ Source                                   │
  ├─────────────────────────┼──────┼──────────────────────────────────────────┤
  │ memory_integrity        │  20  │ Ring 0: CID re-hash matches stored hash  │
  │ audit_completeness      │  20  │ Ring 1: no gaps in HMAC-linked audit log │
  │ authorization_coverage  │  20  │ Ring 2: % ops with valid AAPI Vakya      │
  │ decision_provenance     │  20  │ Ring 3: % decisions with evidence CIDs   │
  │ operational_health      │  20  │ App: agent lifecycle correctness         │
  ├─────────────────────────┼──────┼──────────────────────────────────────────┤
  │ TOTAL                   │ 100  │                                          │
  └─────────────────────────┴──────┴──────────────────────────────────────────┘

  Optional 6th dimension (app layer):
  │ claim_validity          │  20  │ % LLM claims verified against source CID │

Grades: A+ (95+)  A (85+)  B (70+)  C (50+)  D (30+)  F (<30)
```

---

## Full Request Lifecycle

```
agent.run("Patient: chest pain, BP 158/95...")
         │
         │  1. connector-api builds AgentRequest
         │
         ▼
  DualDispatcher.run_agent()
         │
         │  2. Firewall.evaluate(input)
         │     → ThreatScorer: injection=0.0, exfil=0.0 → Allow
         │
         │  3. InstructionPlane.validate(instructions)
         │     → source=user:nurse, integrity=ok
         │
         │  4. VAC: AgentRegister("triage") → pid:000001
         │     VAC: AgentStart(pid:000001)
         │     VAC: MemWrite(input) → CID=bafyrei...  [audit #1]
         │
         │  5. AAPI: AutoVakya.build(pid:000001, "run", "pipe:er")
         │     → IssuedCapability { token_id, expires_at=+5min }
         │
         │  6. LlmRouter.call(provider=deepseek, model=deepseek-chat)
         │     → HTTP POST api.deepseek.com/chat/completions
         │     → response: "Urgency 1. Differentials: ACS (I21.3)..."
         │
         │  7. BehaviorAnalyzer.record(pid:000001, latency, tokens)
         │     → sliding window: no anomaly
         │
         │  8. VAC: MemWrite(response) → CID=bafyrei...  [audit #2]
         │
         │  9. TrustComputer.compute(kernel)
         │     → memory_integrity=20, audit_completeness=20,
         │        authz=0 (no cross-agent), provenance=20, health=20
         │     → total=80, grade=B
         │
         │  10. Trace.build() → SpanTree { input_span, llm_span, output_span }
         │
         ▼
  PipelineOutput {
    text:        "Urgency 1. Differentials: ACS (I21.3)...",
    trust:       80,
    trust_grade: "B",
    cid:         "bafyrei...",
    trace_id:    "pipe:triage",
    ok:          true,
    verified:    true,
    warnings:    [],
    provenance:  { kernel_verified: 2, total: 2, trust_percentage: 100 }
  }
```

---

## Component Dependency Graph

```
connector-api (Ring 3)
    └── connector-engine
            ├── DualDispatcher ──────────────────────────────────────┐
            │       ├── Firewall                                     │
            │       ├── InstructionPlane                             │
            │       ├── BehaviorAnalyzer                             │
            │       ├── CheckpointManager                            │
            │       ├── LlmRouter ──▶ DeepSeek / OpenAI / Anthropic  │
            │       └── AutoVakya ──▶ AAPI ActionEngine              │
            │                                                        │
            ├── BindingEngine (cognitive loop)                       │
            │       ├── PerceptionEngine                             │
            │       │       ├── MemoryCoordinator ──▶ VAC Kernel     │
            │       │       ├── GroundingTable (ICD-10, RxNorm, ...)  │
            │       │       ├── ClaimVerifier                        │
            │       │       └── JudgmentEngine                       │
            │       ├── KnowledgeEngine                              │
            │       │       ├── RagEngine (4-way + RRF)              │
            │       │       ├── KnotEngine (entity graph)            │
            │       │       └── InterferenceEngine (contradictions)  │
            │       └── LogicEngine                                  │
            │               ├── Plan { steps[], CID-linked }         │
            │               ├── ReasoningChain                       │
            │               └── Reflection + Reconsideration         │
            │                                                        │
            ├── TrustComputer (5-dim, kernel-derived)                │
            ├── KernelOps (list_agents, audit_tail, export_json)     │
            └── ComplianceEngine (HIPAA/SOC2/GDPR policy)            │
                                                                     │
VAC Memory Kernel (Ring 1) ◀──────────────────────────────────────────┘
    ├── vac-core    — MemoryKernel, SyscallRequest, AuditLog
    ├── vac-crypto  — Ed25519 signing, SHA3-256 CID
    ├── vac-store   — redb persistent storage
    ├── vac-prolly  — Prolly tree (content-addressed B-tree)
    ├── vac-cluster — multi-node coordination
    ├── vac-bus     — internal event bus
    ├── vac-route   — packet routing
    ├── vac-sync    — cross-node sync
    └── vac-replicate — replication protocol
```

---

## Namespace Isolation Model

```
Kernel Memory
  │
  ├── ns:triage      [owner: pid:000001]  ← only triage can write
  │     ├── CID bafyrei...  (patient case)
  │     └── CID bafyrei...  (triage assessment)
  │
  ├── ns:diagnosis   [owner: pid:000002]  ← only diagnosis can write
  │     ├── CID bafyrei...  (diagnosis response)
  │     └── CID bafyrei...  (investigation plan)
  │
  ├── ns:treatment   [owner: pid:000003]
  │     └── CID bafyrei...  (treatment plan)
  │
  └── ns:audit       [owner: pid:000004]
        └── (empty — reads from all via grants)

Cross-read requires explicit AccessGrant:
  grant_access(pid_triage, "ns:triage", pid_diagnosis)
  → diagnosis can now read ns:triage CIDs
  → audit entry written: [Success] AccessGrant agent=pid:000001

Without grant:
  try_read(pid_diagnosis, triage_cid)
  → "DENIED: Agent pid:000002 lacks read access to ns:triage"
  → audit entry written: [Denied] MemRead agent=pid:000002
```

---

## Audit Chain (Tamper-Evident)

Every kernel operation appends an `AuditEntry`:

```
AuditEntry {
  audit_id:    "audit:000017",
  agent_pid:   "pid:000001",
  operation:   "MemWrite",
  outcome:     Success,
  duration_us: 187,
  prev_hmac:   "sha256:a3f9...",   ← HMAC of previous entry
  entry_hmac:  "sha256:b7c2...",   ← HMAC of this entry
}
```

The chain: `entry_hmac = HMAC(prev_hmac || operation || outcome || agent_pid)`

Tampering with any entry breaks all subsequent HMACs. `integrity_check()` verifies the full chain in O(n).

---

## YAML Config → Runtime Mapping

```yaml
# hospital.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}      # env-var interpolated by Rust loader
```

```
ConnectorConfig
  └── GlobalConfig { provider, model, api_key }
          │
          ▼
  Connector::from_config()
          │
          ├── LlmRouter::new(LlmConfig { provider=deepseek, model=deepseek-chat })
          ├── MemoryKernel::new()  (shared across all agents)
          ├── ActionEngine::new()
          └── DualDispatcher::new(kernel, llm_router, action_engine)
```

3-tier config precedence:
1. **Mandatory** — `connector.provider`, `connector.model` (required, no default)
2. **Default** — `connector.signing`, `connector.retention_days` (sensible defaults)
3. **Optional-revoke** — `firewall`, `behavior`, `checkpoint` (off by default, opt-in)
