# Mock / Stub Audit — Surface Output Engine

> Every hardcoded mock value that caused connectorctl to show the same numbers for every agent.
> Status column: ✅ Fixed | ⏳ In-progress | ❌ Not yet

---

## Root Cause

`SurfaceEngine::new()` calls `KernelBridge::mock()`, which returns static hardcoded values for every query regardless of agent PID. No real API calls are made.

---

## Inventory

### File: `oss/connector/crates/connector-engine/src/surface/kernel.rs`

| # | Line | Mock Value | Real Source | Status |
|---|------|------------|-------------|--------|
| 1 | 149 | `KernelBridge::default()` → `Self::mock()` | Should use live API bridge | ✅ Fixed |
| 2 | 169 | `uptime_ms: 3_600_000` (always 1h) | `registered_at` delta from `/api/v1/agents/{pid}` | ✅ Fixed |
| 3 | 170 | `memory_used: 847_000_000` (always 847MB) | `memory.used_tokens × 4` from `/api/v1/agents/{pid}` | ✅ Fixed |
| 4 | 171 | `tool_calls: 1247` (always 1247) | `operations.total` from `/api/v1/agents/{pid}` | ✅ Fixed |
| 5 | 168 | `status: "running"` (always running) | `status` from `/api/v1/agents/{pid}` | ✅ Fixed |
| 6 | 174–180 | `AgentHealth`: cpu 12.3%, memory 847MB, health 95 (always) | Derived from `operations.success_rate` + `cost.budget_pct` | ✅ Fixed |
| 7 | 181–190 | `AuditEntries`: fake `icd10_lookup` op, `hmac_abc123` | `/api/v1/agents/{pid}/audit/receipts` | ✅ Fixed |
| 8 | 191–201 | `JournalEntries`: fake `icd10_lookup` target | `/api/v1/history/agents/{pid}/timeline` | ✅ Fixed |
| 9 | 202–207 | `EvidenceChain`: `sha256:abc123def456`, length 148 | `/api/v1/agents/{pid}/audit/receipts` (count + root_hash) | ✅ Fixed |
| 10 | 214 | `TierVerification::t0_notarized("hmac_mock", 42)` | Use `t1_recorded()` for API-sourced data | ✅ Fixed |
| 11 | 220 | `chain_position: Some(42)` | Set to `None` when unknown | ✅ Fixed |

### File: `oss/connector/crates/connector-engine/src/surface/engine.rs`

| # | Lines | Mock Value | Real Source | Status |
|---|-------|------------|-------------|--------|
| 12 | 286 | `SurfaceEngine::new()` uses `KernelBridge::mock()` | No `live()` constructor existed | ✅ Fixed |
| 13 | 694–719 | Explain section: status `"Running"`, executions `"148"`, uptime n/a | `KernelData::AgentState` fields | ✅ Fixed |
| 14 | 716 | Timeline: timestamp `"08:39:18"`, message `"policy review..."`, link `"run-148"` | `KernelData::AgentState.last_activity`, real operations | ✅ Fixed |
| 15 | 721–753 | Review section: risk `"MEDIUM"`, `"Read-only evaluation"` (canned strings) | Derived from `KernelData::AgentHealth` | ✅ Fixed |
| 16 | 749 | Recommended Action links: `"run-148"`, `"prf-..."` | Real subject_id-based links | ✅ Fixed |
| 17 | 755–785 | Proof section: `"VERIFIED"`, receipts `"148"`, chain `"INTACT"` (static) | `KernelData::EvidenceChain` | ✅ Fixed |
| 18 | 780–782 | Evidence links: `"rcpt-148"`, `"run-148"` (hardcoded) | `KernelData::EvidenceChain.root_hash` | ✅ Fixed |
| 19 | 793–795 | Monitor badges: `"100d"`, `"20,000"`, `"$300"` (always) | `KernelData::AgentState` cost/tokens | ✅ Fixed |
| 20 | 803–806 | Monitor cost timeline: `"2026-03-22"`, `"claims-review"`, `$18.40` etc. | `KernelData::JournalEntries` | ✅ Fixed |
| 21 | 1423–1426 | `cost_summary_section()`: `"100 days"`, `"1 month"`, `"20,000"`, `"$300.00"` | `KernelData::AgentState` from live API | ✅ Fixed |
| 22 | 1443–1448 | `receipt_count_for_request()`: always returns 148 | `KernelData::EvidenceChain.chain_length` | ✅ Fixed |
| 23 | 668 | Review badge: hardcoded `"Medium"`, `"Guarded"` | Derived from real health score | ✅ Fixed |
| 24 | 477 | Footer `root_hash`: format `"sha256:{pid}-receipt-root"` (placeholder) | `KernelData::EvidenceChain.root_hash` | ✅ Fixed |
| 25 | 478 | Footer `verified: true` hardcoded | `KernelData::EvidenceChain.verified` | ✅ Fixed |

### File: `platform/server/src/bin/connectorctl.rs`

| # | Lines | Mock Value | Real Source | Status |
|---|-------|------------|-------------|--------|
| 26 | 647 | `render_surface_request` uses `SurfaceEngine::default()` (mock) | `SurfaceEngine::live(get_api_url())` | ✅ Fixed |
| 27 | 655 | `render_surface_request_with_options` uses `SurfaceEngine::default()` (mock) | `SurfaceEngine::live(get_api_url())` | ✅ Fixed |

---

## What Was NOT a Mock

These look suspicious but are intentional:

| Item | Why It's OK |
|------|-------------|
| `claims-review-001` in help examples | Documentation examples only, not runtime data |
| `CONNECTOR_LLM_STUB=1` env var | Legitimate stub mode flag for local dev |
| `DataSource::Mock` variant | Kept for unit tests — correct |
| `KernelBridge::mock()` function | Kept for tests — correct |

---

## Real API Endpoints Used After Fix

| Data | Endpoint |
|------|----------|
| Agent status, uptime, tool_calls, memory, cost | `GET /api/v1/agents/{pid}` |
| Audit receipt entries | `GET /api/v1/agents/{pid}/audit/receipts` |
| Evidence chain (count + root hash) | `GET /api/v1/agents/{pid}/audit/receipts` (count field) |
| Journal/timeline entries | `GET /api/v1/history/agents/{pid}/timeline` |
| Agent health (derived) | `GET /api/v1/agents/{pid}` (success_rate + budget_pct) |

---

## Trust Tier Before/After

| Scenario | Before Fix | After Fix |
|----------|-----------|-----------|
| Agent exists, API running | `T3Rendered` (mock) | `T1Recorded` (engine store) |
| Agent doesn't exist or API down | `T3Rendered` (mock) | `T3Rendered` (graceful fallback) |
| Mock mode (`KernelBridge::mock()`) | `T3Rendered` | `T3Rendered` (unchanged, correct for tests) |

---

---

# Part II — Comprehensive Surface Output Intelligence Specification

> **Scope**: All 50 components · 9 chains · 5 CLI verbs · agent lifecycle · full mathematical basis.
> **Owner**: `surface/translator.rs`, `surface/engine.rs`, `surface/kernel.rs`
> **Purpose**: Every governance event the platform captures is explainable with precision:
> **Why** · **When** · **Where** · **What** · **Diff**

---

## 1. Mathematical Foundations

### 1.1 Trust Score  (8 dimensions, 0–100)
```
T = min(100, D1+D2+D3+D4+D5 + KECS_pts + id_pts) × claim_validity_ratio

D1  audit_chain_integrity    [0-20]   HMAC chain unbroken → 20; broken → 0
D2  authorization_coverage   [0-20]   % of ops with policy decision logged × 20
D3  memory_access_control    [0-20]   AccessGrant/Revoke coverage × 20
D4  decision_provenance      [0-20]   disputes.decisions count × min(1, n/10) × 20
D5  operational_health       [0-20]   (1 – error_rate) × (1 – budget_pct/100) × 20
D6  kecs_confidence          [0-20]   KECS_pts  (see §1.2)
D7  claim_validity_ratio     [0-1]    verified_claims / total_claims  (multiplier)
D8  identity_coherence       [0-20]   mean(Ψ, R_score) × 20

Grade:  A = T≥90  B = T≥80  C = T≥70  D = T≥60  F = T<60
Gate:   deploy_safe = T ≥ 70 AND chain_valid
```

### 1.2 KECS Score  (Knot Expertise Consistency Score)
```
K_raw  = w_knot × knot_consistency
       + w_audit × audit_depth_score
       + w_expert × expertise_breadth
       + w_recency × recency_bias
       + w_ns × namespace_coherence

KECS_pts = K_raw × 20         contribution to T  [0–20]
Probation: KECS_pts = 0 when agent violates thresholds n≥3 times in window
           spectral_param u_i = 0 → excluded from consensus weighting

Surface:  KECS_pts < 10 → Warn  |  KECS_pts < 5 → Risk  |  = 0 → Critical/Probation
```

### 1.3 Von Neumann Entropy  (Anomaly detection)
```
S(ρ) = –Tr(ρ · ln ρ)              information entropy of agent state matrix ρ
S_norm = S / log₂(dim(ρ))         normalised [0, 1]
entropy_Δ = S_t – S_{t–1}         rate of change per observation window

Thresholds:
  |entropy_Δ| > 0.3  → Warn   (unusual state transition)
  |entropy_Δ| > 0.6  → Risk   (anomalous behaviour)
  |entropy_Δ| > 0.9  → Critical (potential compromise)

Rényi-2 entropy:  H₂ = –log₂ Σ p_i²   (used for topological mixing check)
```

### 1.4 Yang-Baxter Knot Consistency  (Multi-agent trust)
```
YB(sᵢ, sⱼ) = |sᵢ ∩ sⱼ| / |sᵢ ∪ sⱼ|   Jaccard overlap of strand state sets

Consensus score:  C = Σ_{i<j} YB(sᵢ,sⱼ) / C(N,2)   mean pairwise overlap
                  C ≥ threshold (default 0.7) → PASS

Sybil detection:  if ∃ cluster where YB > 0.95 for >30% of pairs → flag
Yang-Baxter eq:   R₁₂ · R₁₃ · R₂₃ = R₂₃ · R₁₃ · R₁₂  (braid consistency)
                  Violation → tamper / replay warning
```

### 1.5 Adaptive Threshold  (Per-agent baseline anomaly)
```
Baseline window:  W = last 100 observations per metric per agent
μ = mean(W)    σ = std_dev(W)

θ_warn     = μ + 2σ     (k=2)
θ_risk     = μ + 3σ     (k=3)
θ_critical = μ + 4σ     (k=4)

anomaly_score = max(0, (value – μ) / σ)   z-score

Surface:  "metric={name} value={v:.2f} vs baseline μ={μ:.2f}±{σ:.2f} (z={z:.1f})"
```

### 1.6 Universal Surface Output Format
```
┌─ WHY  ─────────────────────────────────────────────────────────────────────┐
│  {event_code}: {human_explanation}                                         │
│  KECS={k}/20 · entropy_Δ={Δ:.3f} · trust={T}/100 · grade={G}             │
├─ WHEN ──────────────────────────────────────────────────────────────────────┤
│  {age_human} ago ({timestamp_iso}) · session T+{session_s}s               │
├─ WHERE ─────────────────────────────────────────────────────────────────────┤
│  agent={pid_short} · ns={namespace} · layer={guard_layer} · cell={cell_id} │
├─ WHAT ──────────────────────────────────────────────────────────────────────┤
│  {tool}.{operation}({target}) → {outcome}                                  │
├─ DIFF ──────────────────────────────────────────────────────────────────────┤
│  trust: {T_before}→{T_after} (Δ{ΔT:+d})                                   │
│  budget: {B_used}/{B_limit} ({B_pct:.0%})                                 │
│  health: {H_before}→{H_after} · chain: {chain_pos_before}→{chain_pos}    │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The 9 Chains

```
Chain 1: Audit Chain
  Type    : HMAC-chained audit log (append-only)
  Source  : MemoryKernel.audit_log()
  Entry   : { timestamp, operation, actor, target, outcome, hmac }
  Validate: HMAC_i = SHA256(entry_i || HMAC_{i-1})
  Break   : chain_valid=false → Trust D1=0 → ΔT = –20
  Surface : "Audit chain broken at position={pos} — {n} entries tampered"
  API     : GET /api/v1/agents/{pid}/audit/receipts

Chain 2: Evidence Chain
  Type    : Merkle-like signed receipt chain
  Source  : AuditReceiptsService  
  Entry   : { receipt_id, operation_cid, hmac, ed25519_sig, timestamp }
  Validate: root_hash = SHA256(concat(receipt_cids))
  Break   : receipts=0 → verified=false
  Surface : "EvidenceChain receipts={n} · root={hash_short} · verified={bool}"
  API     : GET /api/v1/agents/{pid}/audit/receipts

Chain 3: Trust Chain
  Type    : 8-dimension derivation (stateless computation)
  Source  : TrustComputer::compute(kernel) or compute_with_identity(...)
  Entry   : TrustDimensions { D1..D8 }
  Validate: each dim ∈ [0,20]; sum ≤ 100; multiplied by claim_validity_ratio
  Break   : any dim drops → ΔT tracked, grade recalculated
  Surface : "Trust T={score}/100 · grade={G} · dims=[{d1},{d2},{d3},{d4},{d5}]"
  API     : GET /api/v1/agents/{pid} (success_rate, budget_pct used)

Chain 4: Knot Chain
  Type    : Yang-Baxter strand consistency over multi-agent state
  Source  : KnotEngine (per-cell strand state)
  Entry   : KnotStrand { cell_id, state_set, kecs_weight, spectral_param }
  Validate: YB pairwise overlap ≥ threshold; braid eq R₁₂R₁₃R₂₃ = R₂₃R₁₃R₁₂
  Break   : C < threshold → consensus FAILED; Sybil if cluster YB > 0.95
  Surface : "KnotConsensus YB={score:.2f} · {n}/{total} strands · {result}"
  API     : (in-process, accessed via KernelBridge)

Chain 5: Entropy Chain
  Type    : Von Neumann entropy time series per agent
  Source  : KecsComputer / ConsciousnessScore in entropic.rs
  Entry   : { timestamp, S_norm, S_delta, reasoning_entropy }
  Validate: |S_delta| thresholds (0.3/0.6/0.9) trigger anomaly signals
  Break   : S_delta spike → AdaptiveThreshold recalibrates baseline
  Surface : "entropy_Δ={delta:.3f} · baseline={mu:.3f}±{sigma:.3f} · {label}"
  API     : (in-process, surfaced via TrustComputer::compute_with_identity)

Chain 6: Memory Chain
  Type    : Access grant/revoke sequence per namespace
  Source  : MemoryKernel AccessGrant / AccessRevoke ops
  Entry   : { timestamp, ns_from, ns_to, scope, grantor, audit_pos }
  Validate: each grant has matching audit chain entry; no cross-ns without grant
  Break   : cross-ns access without grant → PL-002 · Trust D3 drop
  Surface : "Memory chain ns={ns} · {grants} grants · {revokes} revokes"
  API     : GET /api/v1/agents/{pid}/audit/receipts (filter: AccessGrant/Revoke)

Chain 7: Policy Chain
  Type    : Cedar policy evaluation cascade (deny-override)
  Source  : PolicyEngine (Cedar / XACML rules)
  Entry   : { principal, action, resource, effect, policy_id, timestamp }
  Validate: deny overrides allow; fail-closed (no-match = deny); logged per-op
  Break   : deny without logged reason → Trust D2 drop
  Surface : "PolicyChain {n} rules evaluated · {allows} allow · {denies} deny"
  API     : POST /agents/{pid}/policy/check (per-op); GET /compliance/policy-violations

Chain 8: Execution Chain
  Type    : Agent operation sequence (tool calls + completions)
  Source  : AAPIActionKernel + MemoryKernel.audit_log (tool_call ops)
  Entry   : { timestamp, tool, input_cid, output_cid, tokens_used, latency_ms }
  Validate: each op has budget deduction; input/output CID pair logged
  Break   : op without CID pair → unclaimed computation
  Surface : "ExecChain {n} ops · {tokens} tokens · ${cost:.4f} · p95={lat}ms"
  API     : GET /debug/agents/{pid}/tool-trace; GET /api/v1/agents/{pid}

Chain 9: Consensus Chain
  Type    : Multi-cell KnotConsensus agreement sequence
  Source  : KnotConsensus (per-pipeline-step)
  Entry   : { round_id, proposal, votes, result, knot_score, timestamp }
  Validate: quorum ≥ threshold; YB consistency per round; rollback on fail
  Break   : quorum miss → SagaManager rollback; cell isolation if repeated
  Surface : "ConsensusChain round={n} · quorum={q}/{total} · result={PASS|FAIL}"
  API     : GET /multiagent/sessions/{id}; GET /multiagent/consensus/{id}
```

---

## 3. Component Inventory  (50 components)

```
connector-platform
├── Kernel Layer  [vac-core]
│   ├── C01  MemoryKernel          — agent registry, audit log, memory access, syscalls
│   ├── C02  TrustComputer         — 8-dim trust T = f(D1..D8) × claim_validity
│   ├── C03  KecsComputer          — KECS K = Σ(w_i·metric_i), probation logic
│   ├── C04  KnotEngine            — Yang-Baxter strand state, spectral params
│   ├── C05  AdaptiveThresholdMgr  — per-agent μ±σ baselines, z-score anomaly
│   ├── C06  EntropyEngine         — Von Neumann S(ρ), Rényi-2 H₂, Δ tracking
│   └── C07  AgentIdentityState    — Ψ coherence, R_score, memory_series, expertise
│
├── Guard / Policy Layer
│   ├── C08  GuardPipeline         — 5-layer orchestrator (fail-closed)
│   ├── C09  MACLayer              — mandatory access control (layer 1)
│   ├── C10  PolicyEngine          — Cedar/XACML deny-override evaluation (layer 2)
│   ├── C11  ContentFilter         — SemanticInjectionDetector score > 0.75 (layer 3)
│   ├── C12  CircuitBreaker        — consecutive-failure isolation (layer 4)
│   └── C13  HITLGate              — human-in-the-loop approval gate (layer 5)
│
├── Audit & Evidence Layer
│   ├── C14  AuditChain            — HMAC-chained append-only log (Chain 1)
│   ├── C15  AuditReceiptsService  — Ed25519-signed receipts (Chain 2)
│   ├── C16  EvidenceChain         — root_hash, receipt count, verified flag
│   └── C17  DisputesService       — dec_ decision records, dispute workflow
│
├── Compliance Layer
│   ├── C18  ComplianceEngine      — SOC2 CC series, HIPAA, NIST CSF 2.0, ISO27001
│   └── C19  GDPRService           — Art.17 erasure, Art.22 automated-decision scan
│
├── Multi-Agent Layer
│   ├── C20  MultiAgentCoordinator — pipeline orchestration, patterns (star/mesh/chain)
│   ├── C21  KnotConsensus         — multi-cell YB agreement (Chain 9)
│   ├── C22  SagaManager           — distributed rollback / compensation
│   └── C23  CrossCellPortRouter   — cell-to-cell message routing (CognitiveMessage)
│
├── Memory & Context Layer
│   ├── C24  VACMemoryKernel       — long-term episodic agent memory
│   ├── C25  ContextManager        — context window tracking, token budget
│   ├── C26  EpisodeManager        — agent episode open/close lifecycle
│   └── C27  RAGEngine             — retrieval-augmented generation pipeline
│
├── Execution Layer
│   ├── C28  AAPIActionKernel      — tool routing, sandboxed execution
│   ├── C29  BudgetManager         — token/cost hard+soft limits, probation
│   ├── C30  LLMRouter             — model selection, failover
│   └── C31  AdaptiveRouter        — load-aware routing, session stickiness
│
├── Cognitive Substrate  (11-layer pipeline)
│   ├── C32  CognitiveSubstrate    — pipeline orchestrator
│   ├── C33  PerceptionEngine      — structured PerceptionObject from raw input
│   ├── C34  TensionEngine         — unresolved pressure graph, decay, edge detection
│   ├── C35  ExpertiseKernel       — domain knowledge (General + Medical + pluggable)
│   ├── C36  PossibilityGenerator  — typed action candidates from tensions + knowledge
│   ├── C37  EvaluationEngine      — multi-dim scoring with ExpertiseKernel
│   ├── C38  CommitmentEngine      — commit/revise/abandon, contradiction detection
│   ├── C39  PlanEngine            — DAG-based execution plan, frontier computation
│   ├── C40  ReflectionEngine      — expected vs actual, learning extraction
│   ├── C41  ExposureEngine        — multi-audience rendering (Human/Audit/Compliance)
│   └── C42  CheckpointManager     — ThoughtCheckpoint save/recover/purge
│
├── Contract Layer  (CCL Compiler — 7 stages)
│   ├── C43  CCLLexer              — 66 reserved keywords, 6 token categories
│   ├── C44  CCLParser             — recursive descent, full AST, 14 step operations
│   ├── C45  CCLSema               — 11 validation passes (budget/governance/reachability)
│   ├── C46  CCLLower              — AST → ContractIR DAG
│   ├── C47  CCLOpt                — 6 optimization passes (dead-step elim, const fold)
│   ├── C48  CCLVerify             — state machine + budget + governance consistency
│   ├── C49  CCLEmit               — SolutionContract + CID (cls1-sha256-*) + Ed25519
│   └── C50  FormalVerify          — runtime contract correctness proofs
│
└── Platform Layer
    ├── P01  SurfaceEngine         — CLI rendering pipeline (this file)
    ├── P02  KernelBridge          — live API bridge (blocking reqwest)
    ├── P03  EngineStore           — SQLite + redb persistent storage
    ├── P04  WebhookDelivery       — HMAC-signed event delivery (11 event types)
    ├── P05  AdmissionGate         — deploy-safe gate (T≥70 + chain_valid)
    ├── P06  NoiseChannel          — encrypted cell-to-cell transport
    └── P07  PostQuantumCrypto     — Kyber/Dilithium key exchange (future)
```

---

## 4. Agent Lifecycle

```
States:
  REGISTERING → ACTIVE → DEGRADED → PROBATION → INACTIVE → DEREGISTERED
                    ↑         ↓
                 HEALTHY   UNHEALTHY

Transitions & Triggers:
  REGISTERING → ACTIVE
    trigger : POST /api/v1/deploy  (manifest processed)
    C01 action: kernel.register(pid, manifest)
    Chain 1 : audit entry MemoryKernelOp::Register
    Surface : "Agent {pid_short} registered · uptime=0s · trust={T}"

  ACTIVE → DEGRADED
    trigger : error_rate > 5% OR entropy_Δ > 0.3 OR budget > 80%
    C05 action: AdaptiveThreshold fires θ_warn
    C02 action: D5 reduced → ΔT = –(prev_D5 – new_D5)
    Chain 5 : entropy_Δ spike recorded
    Surface : "OP-002: health OK→DEGRADED · error_rate={r:.1%} · trust: {T_prev}→{T}"

  DEGRADED → UNHEALTHY
    trigger : error_rate > 20% OR budget > 95%
    C12 action: CircuitBreaker OPEN (layer 4 of GuardPipeline)
    Chain 1 : audit entry OpOutcome::Failed (consecutive)
    Surface : "OP-003: health DEGRADED→UNHEALTHY · circuit_breaker=OPEN"

  ACTIVE/DEGRADED → PROBATION
    trigger : KECS_pts drops to 0 (3+ threshold violations in window)
    C03 action: spectral_param u_i = 0
    C21 action: KnotConsensus excludes agent from weighting
    Chain 4 : Knot strand weight → 0
    Surface : "TR-008: KECS probation · consensus_eligible=false · u_i=0"

  PROBATION → ACTIVE
    trigger : probation window expires + trust recovers ≥ 70
    C03 action: KECS re-evaluated, u_i restored
    Surface : "Agent {pid_short} exiting probation · KECS={k}/20 · T={T}"

  ACTIVE → INACTIVE
    trigger : no activity for idle_timeout (default 24h)
    C26 action: EpisodeManager closes open episode
    Surface : "Agent {pid_short} inactive · last_seen={ago} · episodes_closed={n}"

  ANY → DEREGISTERED
    trigger : DELETE /api/v1/agents/{pid}
    C01 action: kernel.deregister(pid)  — audit entries retained
    Surface : "Agent {pid_short} deregistered · {n} audit entries preserved"

Behaviour Flags per State:
  State         | tool.call | memory.read | llm.complete | policy.check | audit.emit
  ACTIVE        |    ✓      |     ✓       |      ✓       |      ✓       |     ✓
  DEGRADED      |    ✓      |     ✓       |      ✓       |      ✓       |     ✓
  UNHEALTHY     |    ✗      |     ✓       |      ✗       |      ✓       |     ✓
  PROBATION     |    ✓*     |     ✓       |      ✓       |      ✓       |     ✓
  INACTIVE      |    ✗      |     ✓(ro)   |      ✗       |      ✗       |     ✓
  DEREGISTERED  |    ✗      |     ✗       |      ✗       |      ✗       |     ✗
  (* restricted: no consensus participation)
```

---

## 5. Five CLI Verb Output Trees

### 5.1  `connectorctl explain <subject>`  → `SurfaceType::Explain`

```
connectorctl explain {subject_id}
│
├── [1] Subject Resolution  (KernelBridge, C02/P02)
│   ├── subject_id starts with "agent_"
│   │   └── GET /api/v1/agents/{pid}
│   │       ├── OK  → KernelData::AgentState { pid, status, uptime_ms, tool_calls,
│   │       │                                   memory_used, last_activity,
│   │       │                                   total_cost_usd, total_tokens }
│   │       └── 404 → KernelData::Empty → signal SR-001
│   ├── subject_id starts with "dec_"
│   │   └── GET /api/v1/disputes/decisions  (filter by decision_id)
│   │       ├── found → KernelData::AgentState {
│   │       │     status: "decision:{outcome}|agent={pid}|action={act} target={tgt}",
│   │       │     uptime_ms: age since recorded_at,
│   │       │     tool_calls: 1 }
│   │       └── 404 → GET /api/v1/disputes/{id}/report (fallback)
│   │           └── FAIL → KernelData::Empty → signal SR-002
│   └── subject_id is human name (e.g. "claims-triage-001")
│       └── GET /api/v1/agents/{pid}  (normalized)
│
├── [2] SurfaceEngine.render()  (P01)
│   ├── build_document(request, kernel_data)
│   │   ├── badges_for_request()
│   │   │   ├── Badge "View"  = Summary · Severity::Info
│   │   │   ├── Badge "Time"  = LIVE/HISTORICAL · Ok/Warn
│   │   │   └── Badge "Status" = {status} · Ok if healthy/running else Warn
│   │   ├── surface_sections_for_request()
│   │   │   ├── Section "Agent Status"  (StatsGrid)
│   │   │   │   ├── Proper Name  : humanize_subject_id(pid)  [NO UUID mangling]
│   │   │   │   ├── Status       : {status}  raw from API
│   │   │   │   ├── Uptime       : {h}h {m}m  from uptime_ms
│   │   │   │   └── Total Ops    : {tool_calls}  from operations.total
│   │   │   ├── Section "Capabilities"  (List)
│   │   │   │   ├── memory.read enabled
│   │   │   │   ├── policy.check enforced
│   │   │   │   ├── tool.call sandboxed
│   │   │   │   └── trace.emit available
│   │   │   └── Section "Recent Execution"  (Timeline)
│   │   │       └── event: "agent {pid} last active" at {last_activity_ts}
│   │   └── generate_judgment_text_from_data()
│   │       ├── agent_*  : "{Name}: {status} | {n} ops | {h}h uptime"
│   │       ├── dec_*    : "{OUTCOME} — {action} | by agent {pid_short} | {age}"
│   │       └── Empty    : "{Name} — not found in registry"
│   ├── build_contract(doc)
│   │   ├── EvidencePosture { verified: footer.verified, chain_intact: footer.chain_valid }
│   │   └── signals_from_document(doc)
│   │       ├── Signal 1: evidence  [Check "Evidence verified" | Warning "0 receipts"]
│   │       ├── Signal 2: health    [Check "HEALTHY" | Warning "DEGRADED" | Cross "UNHEALTHY"]
│   │       └── Signal 3: compliance[Check "COMPLIANT" | Warning "PARTIAL" | Cross "NON_COMPLIANT"]
│   └── build_decision_package(contract, doc, kernel_data)
│       ├── why  = translator.translate_why()   →  WhyLine.explanation
│       ├── risk = translator.translate_risk()  →  RiskLine { level, summary }
│       ├── cost = if Monitor: CostLine { total_cost_usd, "{ops} ops · {tokens} tokens" }
│       └── proof= ProofStatus derived from evidence.verified + chain_intact
│
├── [3] translate_why()  resolution  (C02, translator.rs)
│   ├── if judgment contains "BLOCKED"  → "Action blocked by governance policy"
│   ├── if judgment contains "ALLOWED"  → "Action permitted by governance policy"
│   ├── signal "Evidence verification incomplete"
│   │   → "Audit chain has 0 receipts — no operations recorded yet."
│   ├── signal "Health status: DEGRADED"
│   │   → "{Name} error rate > 5% — check recent operation failures."
│   ├── signal "Health status: UNHEALTHY"
│   │   → "{Name} error rate > 20% or budget exhausted — operator required."
│   ├── signal "Compliance: PARTIAL"
│   │   → "Partial compliance — one or more policy checks outstanding."
│   └── all Check signals  → "Operating within normal parameters."
│
└── [4] CLI Output  (cmd_explain in connectorctl.rs)
    ├── "{✓|✖} {OK|ISSUE} — {subject_id}"
    ├── "  Problem : {doc.summary}"
    ├── "  Why     : {pkg.why.explanation}"
    ├── "  Impact  : {failures} failed runs | {risk_status}"
    ├── ""
    ├── "→ ACTION  : {primary_next_action.command}"
    ├── ""
    ├── "✔ TRUST   : {Chain verified|Chain unverified} | {n} receipts | Tier {tier}"
    └── "📊 STATE  : {status} | {failures} failures | last run {ago}"

Mathematical annotations for explain:
  Trust    T = min(100, D1+D2+D3+D4+D5+KECS+id) × claim_ratio
  KECS     K = knot·w1 + audit·w2 + expertise·w3 + recency·w4 + ns_coh·w5
  Grade    G = A/B/C/D/F boundary at 90/80/70/60
  Tier     T1Recorded (API online) | T3Rendered (fallback)
```

---

### 5.2  `connectorctl trace <subject> [--last 5m | --memory | --tools]`  → `SurfaceType::Trace`

```
connectorctl trace {subject_id} [flags]
│
├── [1] Subject & Time Resolution
│   ├── --last 5m  → SurfaceTimeSelector::Last(Duration::from_secs(300))
│   ├── --memory   → SurfaceTimeSelector::Now  (last activity window)
│   └── --tools    → SurfaceTimeSelector::Now  (tool-call focus)
│
├── [2] KernelBridge.query(AgentTrace)  (Chain 8 + Chain 1)
│   ├── Primary: GET /api/v1/debug/agents/{pid}/tool-trace
│   │   └── Response field: "trace" | "events" | "calls" (array)
│   │       └── Entry: { timestamp, tool, target/input, outcome/result, signature }
│   │       → KernelData::AuditEntries [ AuditEntry{timestamp,operation,actor,target,outcome,hmac} ]
│   └── Fallback (if trace empty): GET /api/v1/agents/{pid}/audit/receipts
│       └── Response: { receipts: [...], total, root_hash }
│           → KernelData::AuditEntries  (from signed receipts)
│
├── [3] Surface Sections
│   ├── Section "Trace"  (Timeline)
│   │   └── each AuditEntry → TimelineEvent {
│   │         timestamp : entry.timestamp formatted HH:MM:SS
│   │         event_type: entry.operation  (tool, receipt, memory.read, etc.)
│   │         message   : "{actor} → {target} = {outcome}"
│   │         severity  : Ok if outcome ok/approved, Warn if denied, Critical if tamper
│   │         link      : receipt CID if hmac present }
│   └── Section "Execution Summary"  (Stats)
│       ├── Total Events : {n}
│       ├── Outcomes     : {ok}/{denied}/{failed}
│       ├── Time Range   : {first_ts} → {last_ts}
│       └── Chain Valid  : HMAC check across entries
│
├── [4] Chain Annotations  (Chain 1: Audit, Chain 8: Execution)
│   ├── Audit chain position range: {pos_start}..{pos_end}
│   ├── HMAC continuity: verified={bool}
│   ├── Entropy over window: S_mean={s:.3f}, S_max={smax:.3f}
│   └── Adaptive baseline: z-score per-tool latency
│
└── [5] CLI Output
    ├── Header: "── {pid} ── {state} │ {health} │ {compliance}  trust:{T}/{G}"
    ├── Surface document (full terminal render)
    └── Per-entry:
        "  {timestamp}  {operation:<20}  {target:<30}  {outcome}  [{hmac_short}]"

Mathematical:
  Entropy over trace window:  S = -Σ p_op · log₂(p_op)  (Shannon over op distribution)
  Anomaly z-score per tool:   z = (latency – μ_tool) / σ_tool
  Chain continuity:           HMAC_i valid for all i in window
```

---

### 5.3  `connectorctl prove <subject>`  → `SurfaceType::Proof`

```
connectorctl prove {subject_id}
│
├── [1] KernelBridge.query(EvidenceChain)  (Chain 2)
│   └── GET /api/v1/agents/{pid}/audit/receipts
│       ├── total  → chain_length
│       ├── root_hash → root_hash
│       └── receipts[] → verified = (count > 0)
│           → KernelData::EvidenceChain { root_hash, chain_length, verified }
│
├── [2] Surface Sections
│   ├── Section "Proof Status"  (Stats)
│   │   ├── Status     : Verified | Unverified | Incomplete
│   │   ├── Receipts   : {n}  (chain_length)
│   │   ├── Root Hash  : sha256:{root_hash_short}
│   │   ├── Chain      : INTACT | BROKEN | UNESTABLISHED
│   │   └── Tier       : T1Recorded | T3Rendered
│   ├── Section "Evidence Items"  (Findings)
│   │   ├── if verified:  Finding { Ok, "Chain verified · {n} signed receipts" }
│   │   └── if !verified: Finding { Warn, "Chain unverified · 0 receipts" }
│   └── Section "Trust Basis"  (KeyValue)
│       ├── KECS         : {k}/20  (dim 6)
│       ├── Chain Depth  : {n} entries
│       └── Knot Score   : {yb:.2f}  (latest strand overlap)
│
├── [3] Chain Validation  (Chain 1 + Chain 2)
│   ├── HMAC continuity check: each receipt hmac = SHA256(receipt || prev_hmac)
│   ├── Root hash: root_hash = SHA256(concat sorted receipt_cids)
│   └── Ed25519 signature check per receipt
│
└── [4] CLI Output  (cmd_prove)
    ├── "{✓|✖} {Verified|Unverified} — {subject_id}"
    ├── "  Receipts : {n}"
    ├── "  Root     : sha256:{hash_short}"
    ├── "  Chain    : {INTACT|BROKEN}"
    ├── "  Tier     : {tier}"
    └── "  KECS     : {k}/20 · trust T={T}/100 · grade={G}"

Mathematical:
  ProofStatus = Verified   iff  receipts > 0 AND chain_intact = true
              = Incomplete iff  receipts > 0 AND chain_intact = false
              = Unverified iff  receipts = 0
  Trust D1    = 20 iff chain_intact else 0
  Trust D4    = min(20, decisions_count/10 × 20)
```

---

### 5.4  `connectorctl risk <subject>` / `connectorctl review`  → `SurfaceType::Review`

```
connectorctl risk {subject_id}
│
├── [1] KernelBridge.query(AgentHealth)
│   └── GET /api/v1/agents/{pid}
│       ├── success_rate   → error_rate = (100 – success_rate) / 100
│       ├── budget_pct     → budget utilisation
│       └── health_score   = if error_rate<0.05 && budget<80: 95
│                            elif error_rate<0.20 && budget<95: 70
│                            else: 40
│           → KernelData::AgentHealth { health_score, error_rate, budget_pct, ... }
│
├── [2] Risk Calculation  (C02, C05)
│   ├── health_score ≥ 80  → Low risk   · Severity::Ok
│   ├── health_score ≥ 60  → Medium risk · Severity::Warn
│   └── health_score < 60  → High risk   · Severity::Risk
│   ├── Adaptive threshold: z = (error_rate – μ_err) / σ_err
│   └── Budget risk: z_budget = (budget_pct – 80) / 10  (linear above 80%)
│
├── [3] Surface Sections
│   ├── Section "Risk Status"  (Findings)
│   │   ├── Finding Ok/Warn/Risk: "Risk Level: {Low|Medium|High}"
│   │   ├── "Error rate: {rate:.1%} (baseline μ={mu:.1%}±{sigma:.1%})"
│   │   └── "Budget: {pct:.0%} consumed ({used}/{limit} tokens)"
│   ├── Section "Why It Acted"  (KeyValue)
│   │   ├── What it did    : last tool call from audit
│   │   ├── Why it did it  : policy decision + trust signal
│   │   └── Guardrail      : active policy ID
│   └── Section "Recommended Action"  (List)
│       ├── High risk  : "connectorctl inspect {pid} — review tool call history"
│       └── Medium risk: "connectorctl prove {pid} — verify evidence chain"
│
└── [5] CLI Output  (cmd_risk)
    ├── "Risk  : {Low|Medium|High}"
    ├── "Score : {health_score}/100"
    ├── "Budget: {pct:.0%}  ({used}/{limit} tokens)"
    ├── "Why   : {why.explanation}"
    └── "Action: {recommended_command}"

Mathematical:
  Risk = f(health_score, entropy_Δ, adaptive_z)
  health_score = (1 – error_rate) × (1 – min(1, budget_pct/100)) × 100
  adaptive_z   = (error_rate – μ_err) / σ_err   (per-agent baseline)
  Risk::High   iff health_score < 60 OR adaptive_z > 3.0
  Risk::Medium iff health_score < 80 OR adaptive_z > 2.0
  Risk::Low    otherwise
```

---

### 5.5  `connectorctl inspect <subject>`  → `SurfaceType::Inspect`  (Debug)

```
connectorctl inspect {subject_id}
│
├── [1] Multi-query fetch  (KernelBridge parallel queries)
│   ├── AgentState  → GET /api/v1/agents/{pid}
│   ├── AuditEntries→ GET /api/v1/agents/{pid}/audit/receipts
│   └── JournalEntries→ GET /api/v1/history/agents/{pid}/timeline
│
├── [2] Full Document Sections  (SurfaceView::Ops)
│   ├── Section "Agent State"          — status, uptime, ops, memory, cost
│   ├── Section "Trust Dimensions"     — D1..D8 breakdown
│   │   ├── D1 audit_chain_integrity   : {d1}/20  chain={valid|broken}
│   │   ├── D2 authorization_coverage  : {d2}/20  {n} policy decisions
│   │   ├── D3 memory_access_control   : {d3}/20  {grants} grants {revokes} revokes
│   │   ├── D4 decision_provenance     : {d4}/20  {n} decisions recorded
│   │   ├── D5 operational_health      : {d5}/20  error_rate={r:.1%}
│   │   ├── D6 kecs_confidence         : {d6}/20  KECS={k:.2f}
│   │   ├── D7 claim_validity          : {d7:.2%}  multiplier
│   │   └── D8 identity_coherence      : {d8}/20  Ψ={psi:.2f} R={r:.2f}
│   ├── Section "9 Chains Status"
│   │   ├── Chain 1 Audit      : pos={n}  valid={bool}
│   │   ├── Chain 2 Evidence   : receipts={n}  root={hash_short}
│   │   ├── Chain 3 Trust      : T={score}  grade={G}
│   │   ├── Chain 4 Knot       : YB={yb:.2f}  strands={n}
│   │   ├── Chain 5 Entropy    : S={s:.3f}  Δ={delta:.3f}
│   │   ├── Chain 6 Memory     : grants={n}  revokes={n}
│   │   ├── Chain 7 Policy     : allows={n}  denies={n}
│   │   ├── Chain 8 Execution  : ops={n}  tokens={t}  cost=${c:.4f}
│   │   └── Chain 9 Consensus  : rounds={n}  quorum={q}/{total}
│   ├── Section "Guard Pipeline"
│   │   ├── Layer 1 MAC         : {pass|fail}  {n} evaluations
│   │   ├── Layer 2 Policy      : {n} denies  {n} allows
│   │   ├── Layer 3 Content     : {n} injection checks  {n} blocks
│   │   ├── Layer 4 Circuit     : {closed|open}  failures={n}
│   │   └── Layer 5 HITL        : {n} pending  {n} approved  {n} expired
│   ├── Section "Cognitive Substrate"  (if CognitiveSubstrate active)
│   │   ├── Tensions       : {n} active unresolved
│   │   ├── Commitments    : {n} active  {n} contradictions
│   │   ├── Plan           : {n} nodes  frontier={f_nodes}
│   │   └── Checkpoints    : {n} saved  latest={ts}
│   ├── Section "Compliance"
│   │   ├── SOC2    : {pass_pct:.0%} findings pass
│   │   ├── GDPR    : {art22_flags} Art.22 flags  {erasures} erasures
│   │   └── Gate    : {PASS|BLOCKED}  reason={reason}
│   └── Section "Recent Execution"  (Timeline from AuditEntries)
│       └── last 20 ops with timestamp, operation, outcome, latency
│
└── [3] CLI Output  (cmd_inspect)
    └── Full SurfaceDocument terminal render (all sections expanded)

Mathematical (all shown inline in sections):
  T     = D1+D2+D3+D4+D5+D6+D8) × D7           (full 8-dim trust)
  KECS  = K_raw × 20                             (dim 6)
  S(ρ)  = –Tr(ρ · ln ρ) / log₂(dim)             (entropy chain 5)
  YB    = Σ_{i<j} |sᵢ∩sⱼ|/|sᵢ∪sⱼ| / C(N,2)   (knot chain 4)
  z     = (metric – μ) / σ                       (adaptive chain)
```

---

## 6. Per-Component Surface Contribution

```
Component → Surface verb(s) it populates

C01 MemoryKernel      → ALL verbs: status, uptime, tool_calls, audit_log, memory
C02 TrustComputer     → explain(trust), risk(grade), prove(D1-D5), inspect(D1-D8)
C03 KecsComputer      → explain(KECS), risk(D6), inspect(D6)
C04 KnotEngine        → prove(YB), inspect(Chain4, D6), risk(knot_score)
C05 AdaptiveThreshMgr → risk(z-score), inspect(baseline), explain(anomaly)
C06 EntropyEngine     → risk(entropy_Δ), inspect(Chain5, S_norm)
C07 AgentIdentity     → inspect(D8, Ψ, R_score), explain(coherence)
C08-C13 GuardPipeline → inspect(all 5 layers), risk(denied_count), trace(blocks)
C14-C16 AuditChain    → prove(chain valid), inspect(Chain1,2), trace(receipts)
C17 DisputesService   → explain(dec_ IDs), inspect(Chain2 decisions)
C18 ComplianceEngine  → inspect(compliance section), risk(denial_rate)
C19 GDPRService       → inspect(Art.22 flags, erasures)
C20-C23 MultiAgent    → inspect(Chain9, coordination), trace(pipeline steps)
C24-C27 Memory        → trace(memory ops), inspect(Chain6, context)
C28-C31 Execution     → trace(tool calls), inspect(Chain8), risk(budget)
C32-C42 Cognitive     → inspect(tensions, commitments, plan, checkpoints)
C43-C50 CCL/Contract  → inspect(contracts deployed), prove(contract CID)
P01 SurfaceEngine     → renders all sections
P02 KernelBridge      → fetches all live data (API calls)
P03 EngineStore       → persists dec_ records, evidence packages
P04 WebhookDelivery   → event_type: budget.exceeded, injection.blocked, trust.degraded,
                         anomaly.detected, audit.tamper, agent.registered,
                         agent.deregistered, policy.denied, hitl.pending,
                         consensus.failed, chain.broken  (11 types)
P05 AdmissionGate     → inspect(deploy_gate: PASS|BLOCKED), prove(chain_valid)
```

---

## 7. Signal-to-Why Mapping  (translator.rs implementation spec)

```rust
// Priority order for translate_why() resolution:
//
// 1. judgment.text contains BLOCKED/ALLOWED/DENIED  →  Decision context
// 2. Signal with icon=Cross (Critical)             →  Cross signal text
// 3. Signal with icon=Warning (risk/warn)          →  Enriched text below
// 4. All signals are Check                         →  "Operating normally"

Signal Text                          → Why Explanation
─────────────────────────────────────────────────────────────────────────
"Evidence verification incomplete"   → "Audit chain has 0 receipts — no
                                        operations have been recorded yet.
                                        If new: run a tool call first.
                                        If dec_*: record via POST /disputes/record."

"Health status: DEGRADED"            → "{Name} error rate exceeded 5% threshold.
                                        Check recent operation failures.
                                        z-score: (error_rate – μ) / σ > 2.0"

"Health status: UNHEALTHY"           → "{Name} error rate > 20% or budget > 95%.
                                        CircuitBreaker is OPEN.
                                        Operator attention required."

"Compliance: PARTIAL"                → "Partial compliance coverage.
                                        One or more operational policy checks
                                        have outstanding findings."

"Compliance: NonCompliant"           → "{Name} is non-compliant with operational
                                        policy. Deploy gate is BLOCKED."

"budget_exceeded" (in judgment)      → "Budget hard limit reached — agent token
                                        spend exhausted configured threshold.
                                        Agent may be in KECS probation."

judgment contains "BLOCKED"         → "Action was blocked by governance policy.
                                        See: connectorctl prove {id} for evidence."

judgment contains "ALLOWED"         → "Action was permitted by governance policy.
                                        Record is stored and tamper-evident."

judgment contains "decision:"       → Parse decision:outcome|agent=|action=
                                       → "{OUTCOME}: {action} on {target}
                                          by agent {pid_short} — recorded {age} ago"
```

---

## 8. Current Output Gaps  (implementation backlog)

| # | Gap | Root Cause | Fix |
|---|-----|-----------|-----|
| 1 | `Why: Evidence verification incomplete` always shown | `signals_from_document` evidence signal is always first non-check | Implement `translate_why` enrichment (§7 above) |
| 2 | Decision explain shows raw `decision:blocked\|agent=...` | `generate_judgment_text_from_data` formats as flat string | Parse status parts, render cleanly |
| 3 | `trace --memory` shows "surface query" | `/tool-trace` endpoint empty on server → fallback receipts also empty | Populate tool-trace server endpoint with C28 AAPIActionKernel call log |
| 4 | Trust shows "0/100 grade F" for dec_ IDs | EvidenceChain not queried for Explain surface | Add secondary EvidenceChain fetch in render() when subject is dec_ |
| 5 | inspect Chain 4-9 sections missing | `surface_sections_for_request(Inspect)` only shows basic state | Add "9 Chains Status" and "Guard Pipeline" sections for Inspect |
| 6 | Trust dimension breakdown not shown | TrustComputer result not passed to surface sections | Expose TrustDimensions through KernelData or via /api/v1/agents/{pid} trust field |
| 7 | Cognitive Substrate status absent | CognitiveSubstrate not queried | Add C32-C42 API endpoint + KernelData::CognitiveState variant |
| 8 | Webhook events not surfaced in trace | WebhookDelivery events not in audit chain | Cross-reference webhook delivery log in trace timeline |

---

## Universal Output Template

Every governance event renders with:

```
WHY  : {rule_violated} | KECS={k}/20 | entropy_Δ={delta:.2f} | score={n}/100
WHEN : {age_human} ago ({timestamp_iso}) | session T+{session_s}s
WHERE: agent={pid_short} | ns={namespace} | layer={guard_layer} | cell={cell_id}
WHAT : {tool}.{op}({target}) → {outcome}
DIFF : trust {T_before}→{T_after} (Δ{ΔT:+d}) | budget {B_before}→{B_after} | health {H_before}→{H_after}
```

---

## Event Category Matrix  (~500 patterns)

### Category 1 — Firewall / Guard Pipeline

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| FW-001 | Tool call blocked by policy | `Risk` | `GuardPipeline layer=MAC denied {tool} — policy={policy_id} threshold={t}` | `ops: {n}→{n} (blocked) \| budget unchanged` |
| FW-002 | Network egress denied | `Risk` | `Egress guard denied {host}:{port} — namespace={ns} allows only {allowed}` | `egress_attempts: {n}→{n+1} \| firewall_events: +1` |
| FW-003 | Semantic injection blocked | `Critical` | `Injection score={score:.2f} > 0.75 threshold — input fingerprint={fp}` | `injection_blocks: {n}→{n+1} \| guard=active` |
| FW-004 | Circuit breaker open | `Risk` | `CircuitBreaker open after {n} failures in {window}s — cooldown={cd}s` | `consecutive_failures: {n} \| health: DEGRADED→DEGRADED` |
| FW-005 | Content policy violation | `Warn` | `ContentFilter matched rule={rule_id} category={cat} confidence={c:.0%}` | `content_blocks: {n}→{n+1}` |
| FW-006 | Rate limit exceeded | `Warn` | `RateLimit {calls}/min > {limit}/min on tool={tool} — window resets in {s}s` | `rate_violations: {n}→{n+1} \| next_allowed: +{s}s` |
| FW-007 | HITL gate triggered | `Warn` | `HITL approval required — action={action} risk_level=HIGH — waiting for {reviewer}` | `hitl_pending: {n}→{n+1} \| auto_proceed=false` |
| FW-008 | Injection attempt survived guard | `Critical` | `HIGH CONFIDENCE injection passed guard (score={s}) — investigate prompt source` | `injection_escapes: {n}→{n+1} \| audit_flag=CRITICAL` |
| FW-009 | Guard pipeline disabled | `Critical` | `GuardPipeline NOT ACTIVE — all 5 guard layers bypassed` | `guard_active: true→false` |
| FW-010 | HMAC verification failed | `Critical` | `Audit entry hmac mismatch at position={pos} — chain tampered after T={ts}` | `chain_valid: true→false \| tamper_flag=CRITICAL` |

### Category 2 — Policy / Authorization

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| PL-001 | Tool not in namespace allowlist | `Risk` | `Tool {tool} not in namespace={ns} allowlist — allowed={allowed_list}` | `denied_ops: {n}→{n+1} \| authorization_coverage: {dim}` |
| PL-002 | Cross-namespace memory access denied | `Risk` | `MemoryKernel denied read ns={from}→ns={to} — no AccessGrant in scope` | `access_denied: {n}→{n+1} \| cross_ns_attempts: +1` |
| PL-003 | Budget hard limit reached | `Risk` | `Budget exhausted: {used}/{limit} tokens — agent entered probation mode` | `budget: {used}→{limit} (0 remaining) \| trust_kecs: reduced` |
| PL-004 | Budget soft warning (80%) | `Warn` | `Budget {pct:.0%} consumed ({used}/{limit} tokens) — {remaining} tokens remain` | `budget_pct: {prev}%→{pct}% \| health: OK→WARN` |
| PL-005 | Policy Cedar deny | `Risk` | `Cedar policy effect=deny principal={pid} resource={res} action={act}` | `policy_denials: {n}→{n+1} \| auth_coverage: {dim}` |
| PL-006 | RBAC role insufficient | `Risk` | `Role={role} cannot perform {action} on {resource} — needs role={required}` | `rbac_violations: {n}→{n+1}` |
| PL-007 | PII access without consent | `Critical` | `PII field={field} accessed by {pid} — no consent record in GDPR store` | `pii_violations: {n}→{n+1} \| gdpr_flag=CRITICAL` |
| PL-008 | Hard-coded secret detected | `Critical` | `SecretsScanner found secret type={type} in tool input — input redacted` | `secret_leaks: {n}→{n+1}` |
| PL-009 | Namespace escalation attempt | `Risk` | `Agent attempted namespace={ns_high} access from ns={ns_low} — denied` | `ns_escapes: {n}→{n+1}` |
| PL-010 | Contract step not reached | `Warn` | `CCL contract={cid} step={step} unreachable — branch predicate always false` | `dead_steps: {n}→{n+1}` |

### Category 3 — Trust Degradation

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| TR-001 | Trust score below deploy gate (70) | `Risk` | `Trust score={score} < 70 deploy gate — dims: audit={d1} auth={d2} health={d5}` | `trust: {prev}→{score} (Δ{delta:+d}) \| deploy_gate=BLOCKED` |
| TR-002 | KECS confidence drop | `Warn` | `KECS dim6={k}/20 dropped from {prev}/20 — expertise recency decayed` | `kecs: {prev}→{k} (Δ{dk:+d}) \| trust: Δ{dt:+d}` |
| TR-003 | Identity coherence collapse | `Risk` | `Identity Ψ={psi:.2f} R={r:.2f} below coherence threshold — potential replay` | `identity_coherence: {prev}→{cur} \| trust: Δ{dt:+d}` |
| TR-004 | Audit chain invalidated | `Critical` | `Audit chain broken at position={pos} — HMAC mismatch, chain_valid=false` | `chain_valid: true→false \| trust: −{penalty}` |
| TR-005 | Knot consensus failure | `Risk` | `KnotConsensus YB={yb:.2f} < {threshold} — {n}/{total} strands agreed` | `knot_score: {prev:.2f}→{yb:.2f} \| consensus=FAILED` |
| TR-006 | Entropy spike detected | `Warn` | `Entropy_Δ={delta:.3f} > 0.3 baseline — anomalous state transition at T={ts}` | `entropy: {s_prev:.3f}→{s_cur:.3f} (Δ{delta:+.3f}) \| baseline={mu:.3f}±{sigma:.3f}` |
| TR-007 | Adaptive threshold breached | `Warn` | `metric={name} value={val:.2f} > θ={theta:.2f} (μ={mu:.2f} + {k}σ={k_sigma:.2f})` | `baseline_violations: {n}→{n+1} \| adaptive_mode=tightening` |
| TR-008 | KECS probation active | `Critical` | `Agent in KECS probation (score=0) — spectral param u_i=0, excluded from consensus` | `kecs: {prev}→0 \| consensus_eligible=false \| probation_until={ts}` |
| TR-009 | Claim validity drop | `Warn` | `Claim validity={pct:.0%} of {n} claims verifiable against source CIDs` | `claim_validity: {prev:.0%}→{pct:.0%} \| trust_multiplier: {m_prev:.2f}→{m:.2f}` |
| TR-010 | Grade demotion | `Warn` | `Trust grade {grade_prev}→{grade} — score crossed {boundary} boundary` | `grade: {grade_prev}→{grade} \| trust: {prev}→{cur}` |

### Category 4 — Multi-Agent / Consensus

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| MA-001 | Pipeline coordination timeout | `Risk` | `Pipeline={pipe_id} step={step} timed out after {timeout}ms — {n}/{total} agents responded` | `pipeline_timeouts: {n}→{n+1} \| step_status: pending→timeout` |
| MA-002 | Consensus vote rejected | `Warn` | `Consensus={id} vote from {agent} rejected — trust={t} below min_trust={min}` | `valid_votes: {n}→{n} (unchanged) \| rejected_votes: +1` |
| MA-003 | Sybil detection triggered | `Critical` | `KnotConsensus detected Sybil pattern — {k} agents share {overlap:.0%} YB overlap` | `sybil_flags: {n}→{n+1} \| consensus=BLOCKED \| trust: −{penalty}` |
| MA-004 | Rollback initiated | `Risk` | `Saga rollback for pipeline={id} — step={step} failed, compensating {n} steps` | `pipeline_status: active→rolling_back \| compensating_steps: {n}` |
| MA-005 | Quorum not reached | `Warn` | `Quorum requires {q}/{total} votes — only {got} responded in {window}ms` | `quorum_failures: {n}→{n+1} \| consensus_pending` |
| MA-006 | Cell isolation triggered | `Critical` | `Cell={cell} isolated — {n} consecutive knot failures, u_i=0` | `cell_status: active→isolated \| consensus_weight: {w}→0` |
| MA-007 | HITL approval expired | `Risk` | `HITL approval for action={action} expired after {ttl}s — request auto-rejected` | `hitl_expired: {n}→{n+1} \| pending_actions: {m}→{m-1}` |
| MA-008 | Coordination pattern mismatch | `Warn` | `Pattern={pattern} expected {n} participants — only {actual} available` | `coordination_degraded: true \| available_agents: {actual}/{n}` |

### Category 5 — Memory / Audit

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| AU-001 | Receipt chain missing | `Warn` | `Audit receipts=0 for agent={pid} — no operations recorded or store unreachable` | `receipts: 0 \| verified=false` |
| AU-002 | Journal timeline empty | `Warn` | `No timeline events for agent={pid} in window={window} — agent may be idle` | `events_in_window: 0 \| last_event: {ago}` |
| AU-003 | Memory read access granted | `Ok` | `MemoryKernel AccessGrant ns={ns} scope={scope} by={grantor} — logged` | `access_grants: {n}→{n+1} \| chain_pos: {pos}` |
| AU-004 | Memory access revoked | `Warn` | `AccessRevoke ns={ns} — {n} active grants removed, audit entry {pos}` | `active_grants: {n}→{n-grants} \| chain_pos: {pos}` |
| AU-005 | Audit position gap | `Risk` | `Chain gap at positions {p1}..{p2} — {gap} entries missing, possible truncation` | `chain_integrity: gapped \| gap_size: {gap}` |
| AU-006 | Tamper evidence detected | `Critical` | `HMAC mismatch at chain pos={pos} — expected={expected_short} got={actual_short}` | `chain_valid: true→false \| tamper_pos: {pos} \| evidence_flag=CRITICAL` |
| AU-007 | Evidence export requested | `Ok` | `Defense package {pkg_id} exported — {n} files, Ed25519 signed, court-ready` | `evidence_packages: {n}→{n+1} \| signed=true` |

### Category 6 — Compliance (GDPR / SOC2 / HIPAA / NIST)

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| CP-001 | GDPR Art.22 automated decision | `Warn` | `Automated decision on {subject} without human review — Art.22 flag raised` | `gdpr_art22_flags: {n}→{n+1}` |
| CP-002 | Data erasure (Art.17) | `Ok` | `GDPR Art.17 erasure of {pid} completed — {n} memory entries purged` | `pii_records: {n}→{n-purged}` |
| CP-003 | SOC2 CC7.3 anomaly | `Warn` | `SOC2 CC7.3: anomaly detection triggered — trust={t} below 70 gate` | `soc2_flags: {n}→{n+1} \| deployment_gate=BLOCKED` |
| CP-004 | HIPAA PHI access unlogged | `Critical` | `PHI field={field} accessed — no audit receipt generated for this operation` | `hipaa_violations: {n}→{n+1} \| unlogged_phi: +1` |
| CP-005 | Budget policy missing | `Warn` | `No budget policy configured — CONNECTOR_AGENT_TOKEN_BUDGET not set` | `budget_configured=false \| risk=uncapped_spend` |
| CP-006 | Denial rate high | `Warn` | `Denial rate={rate:.0%} > 20% threshold — {denied}/{total} ops denied in window` | `denial_rate: {prev:.0%}→{rate:.0%} \| compliance_score: −{penalty}` |

### Category 7 — Operational Health

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| OP-001 | Agent healthy | `Ok` | `Health score={score}/100 — error_rate={err:.1%} budget_pct={bpct:.0%}` | `health: OK \| consecutive_successes: {n}` |
| OP-002 | Agent degraded | `Warn` | `Health score={score}/100 — error_rate={err:.1%} > 5% threshold` | `health: OK→DEGRADED \| error_rate: {prev:.1%}→{err:.1%}` |
| OP-003 | Agent unhealthy | `Risk` | `Health score={score}/100 — error_rate={err:.1%} > 20% OR budget > 95%` | `health: DEGRADED→UNHEALTHY \| ops_blocked={n}` |
| OP-004 | Agent unresponsive | `Risk` | `No response from agent={pid} in {timeout}s — last_activity={ago} ago` | `health: {prev}→UNRESPONSIVE \| circuit_breaker: open` |
| OP-005 | Memory pressure high | `Warn` | `Memory {used_mb:.0f}MB used — {pct:.0%} of context window {limit} tokens` | `memory_mb: {prev:.0f}→{cur:.0f} \| pct: {prev_pct:.0%}→{pct:.0%}` |
| OP-006 | LLM router not configured | `Warn` | `No LLM router configured — agent cannot generate completions` | `llm_wired=false \| capabilities: degraded` |
| OP-007 | Tool latency spike | `Warn` | `Tool {tool} p95 latency={lat}ms > {threshold}ms baseline — adaptive_θ={theta}ms` | `latency_p95: {prev}ms→{lat}ms \| threshold: {threshold}ms` |
| OP-008 | Execution timeout | `Risk` | `Agent execution timeout after {timeout}ms — partial output discarded` | `timeouts: {n}→{n+1} \| partial_output=discarded` |
| OP-009 | Success rate drop | `Warn` | `Success rate={rate:.0%} dropped from {prev:.0%} — {failed}/{total} ops failed` | `success_rate: {prev:.0%}→{rate:.0%} (Δ{d:+.0%})` |

### Category 8 — Decision Records  (`dec_...`)

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| DC-001 | Decision recorded: blocked | `Risk` | `Decision {dec_id_short}: action={action} target={target} → BLOCKED by {rule}` | `decisions_blocked: {n}→{n+1} \| agent_trust: −{penalty}` |
| DC-002 | Decision recorded: allowed | `Ok` | `Decision {dec_id_short}: action={action} target={target} → ALLOWED — trust={t}` | `decisions_allowed: {n}→{n+1}` |
| DC-003 | Decision: disputed | `Warn` | `Decision {dec_id_short} under dispute review — human_reviewer={reviewer}` | `disputed_decisions: {n}→{n+1} \| review_status=pending` |
| DC-004 | Decision: export-packaged | `Ok` | `Evidence package {pkg_id} built for dec={dec_id_short} — Ed25519 cert signed` | `evidence_packages: {n}→{n+1} \| court_ready=true` |
| DC-005 | Decision age: stale | `Warn` | `Decision {dec_id_short} is {age_days}d old — verify context still applies` | `decision_age: {age_days}d \| freshness=stale` |
| DC-006 | Decision without agent | `Risk` | `Decision {dec_id_short} has no matching agent_pid in registry — orphaned record` | `orphaned_decisions: {n}→{n+1}` |

### Category 9 — Model / LLM

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| ML-001 | Low confidence inference | `Warn` | `Confidence={conf:.0%} < {threshold:.0%} — model uncertainty high on task={task}` | `confidence: {prev:.0%}→{conf:.0%} \| low_conf_count: {n}→{n+1}` |
| ML-002 | Hallucination risk signal | `Risk` | `Claim citation_rate={rate:.0%} < 50% — {uncited}/{n} claims lack source CIDs` | `uncited_claims: {n}→{n+1} \| validity: {prev:.0%}→{rate:.0%}` |
| ML-003 | Prompt injection (high confidence) | `Critical` | `Injection fingerprint={fp} score={score:.2f} — input from {source} blocked pre-LLM` | `injection_blocks: {n}→{n+1} \| guard_layer=ContentFilter` |
| ML-004 | Context window near limit | `Warn` | `Context {used}/{limit} tokens ({pct:.0%}) — model may truncate earlier context` | `context_pct: {prev:.0%}→{pct:.0%}` |
| ML-005 | Model changed | `Warn` | `Model changed from {prev_model} to {new_model} — outputs may differ` | `model: {prev_model}→{new_model}` |
| ML-006 | Completion token overage | `Risk` | `Completion used {n} tokens, budget allows {limit} — {overage} over limit` | `token_overage: {n}→{n+overage} \| budget_pct: {pct:.0%}` |

### Category 10 — Surface / Rendering

| Code | Event | Severity | Why Template | Diff |
|------|-------|----------|-------------|------|
| SR-001 | Agent not found | `Warn` | `Subject={pid} not in agent registry — may be deregistered or typo` | `registry_miss: true \| data=Empty` |
| SR-002 | Decision ID not in store | `Warn` | `Decision={dec_id_short} not found in disputes store — may not be recorded via POST /disputes/record` | `store_miss: true \| fallback=report_endpoint` |
| SR-003 | API unreachable | `Warn` | `Platform API at {api_url} unreachable — timeout={timeout}s. Start: connectorctl start` | `api_reachable: true→false \| data=stale_or_empty` |
| SR-004 | Evidence chain: 0 receipts | `Warn` | `EvidenceChain receipts=0 — agent has no audit receipts yet or store is fresh` | `receipts: 0 \| verified=false \| trust_chain=unestablished` |
| SR-005 | AgentTrace: no tool calls | `Info` | `No tool calls found in trace window={window} — agent idle or tool-trace API not implemented` | `trace_events: 0 \| fallback=audit_receipts` |

---

## Signal Priority Order  (translate_why resolution)

When multiple signals fire, the first non-`Check` signal with the highest priority becomes the `Why` line:

```
Priority 1 (Critical) : FW-003, FW-008, FW-009, FW-010, TR-004, TR-008, MA-003, MA-006, AU-006, CP-004, ML-003
Priority 2 (Risk)     : FW-001, FW-002, FW-004, PL-001, PL-002, PL-003, PL-007, TR-001, TR-003, TR-005, TR-008, OP-003
Priority 3 (Warn)     : FW-005, FW-006, PL-004, TR-002, TR-006, TR-007, TR-009, OP-002, OP-005
Priority 4 (Info)     : AU-003, SR-005, OP-001, DC-002
Priority 5 (Ok)       : DC-002, AU-003, AU-007 — shown as "Operating normally"
```

---

## `translate_why` Output Rules

Implemented in `translator.rs` → `StandardTranslator::translate_why()`.

```
Input  : SurfaceContract.signals  (ordered by priority above)
Output : WhyLine { explanation: String, source_link: Option<String> }

Algorithm:
  1. Find first signal with icon ≠ Check
  2. Match signal.text against event category patterns above
  3. If signal.text contains known prefix (FW-/PL-/TR-/MA-/AU-/CP-/OP-/DC-/ML-/SR-):
       return full template string from matrix
  4. If signal.text is "Evidence verification incomplete":
       return "Audit chain has 0 receipts — no operations have been recorded yet, or the store is unreachable."
  5. If signal.text is "Health status: DEGRADED":
       return "Agent error rate exceeded 5% threshold — check recent operation failures."
  6. If signal.text is "Compliance: PARTIAL":
       return "Agent has partial compliance coverage — one or more policy checks are outstanding."
  7. Else: return signal.text as-is (already descriptive)
  8. If all signals are Check: return "Operating within normal parameters."
```

---

## `surface_sections_for_request` Diff Block Rules

For `SurfaceType::Explain`, the **"Why It Acted"** section must include a diff when available:

| `KernelData` field | Shown as |
|--------------------|----------|
| `status` starts with `"decision:"` | Decision context: what action, what outcome, what agent |
| `status == "degraded"` | `"Health degraded — error_rate > 5%"` |
| `status == "budget_exceeded"` | `"Budget exhausted — {used}/{limit} tokens consumed"` |
| `uptime_ms > 0` | `"Active for {h}h {m}m since registration"` |
| `tool_calls == 1` and `pid.starts_with("dec_")` | `"Single governance decision event"` |
| `total_cost_usd > 0` | `"Cumulative cost: ${cost:.4f} across {tokens} tokens"` |
| `health_score < 60` | `"Health critical: {score}/100 — operator attention required"` |

---

## Implementation Files

| File | Change |
|------|--------|
| `surface/translator.rs` | Expand `translate_why` with signal → rich template matching |
| `surface/engine.rs` | Update `signals_from_document` to emit event-code-tagged signals |
| `surface/engine.rs` | Update `generate_judgment_text_from_data` to use `status` field for decision context |
| `surface/kernel.rs` | `query_decision_record` routes `dec_` IDs to disputes API ✅ Done |
| `surface/kernel.rs` | `AgentTrace` fallback to audit receipts ✅ Done |
| `surface/engine.rs` | `humanize_subject_id` preserves UUID IDs ✅ Done |
| `surface/engine.rs` | `build_decision_package` uses real cost from `KernelData` ✅ Done |

---

## Current Output Gaps  (next sprint)

| Gap | Root cause | Fix |
|-----|-----------|-----|
| `Why: Evidence verification incomplete` always shown | First non-check signal in `signals_from_document` is always the evidence signal | Expand `translate_why` to map signal text → specific template |
| Decision `explain` shows raw `decision:blocked\|agent=...` in one line | `generate_judgment_text_from_data` formats it as a flat string | Parse `status` field parts and render multi-line in `Explain` sections |
| `trace --memory` shows "surface query" not real tool calls | `AgentTrace` `/tool-trace` endpoint returns empty → fallback is empty receipts | Populate tool-trace endpoint on server side, OR surface agent journal entries |
| Trust "Chain unverified \| 0 receipts" for dec_ IDs | `build_decision_package` calls `contract.evidence.verified` which is from `footer` which is from `EvidenceChain` query (not done for Explain surface) | Add an `EvidenceChain` secondary fetch in `render()` for Explain + Decision surfaces |
