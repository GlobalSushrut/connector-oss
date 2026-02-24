# Cognitive Loop

> BindingEngine, 5 phases: Perceive→Retrieve→Reason→Reflect→Act
> Source: `connector/crates/connector-engine/src/binding.rs`, `perception.rs`, `logic.rs`

---

## BindingEngine

The top-level coordinator for agentic pipelines. Manages the observe → think → act cognitive loop with full CID provenance on every phase output.

```rust
// connector-engine/src/binding.rs
pub struct BindingEngine {
    perception: PerceptionEngine,
    knowledge:  KnowledgeEngine,
    logic:      LogicEngine,
    config:     BindingConfig,
}

pub struct BindingConfig {
    pub max_cycles:          u32,    // default: 3 (reflect can trigger re-cycle)
    pub quality_threshold:   f32,    // default: 0.7 (below → reflect triggers reconsider)
    pub token_budget:        usize,  // default: 8192
    pub enable_reflection:   bool,   // default: true
}
```

---

## CognitivePhase

```rust
pub enum CognitivePhase {
    Idle,
    Perceiving,
    Retrieving,
    Reasoning,
    Reflecting,
    Acting,
    Complete,
}
```

---

## CycleSummary

```rust
pub struct CycleSummary {
    pub cycle_number:    u32,
    pub phase_reached:   CognitivePhase,
    pub observation_cid: Option<Cid>,
    pub context_cid:     Option<Cid>,
    pub plan_cid:        Option<Cid>,
    pub output_cid:      Option<Cid>,
    pub quality_score:   f32,
    pub reconsidered:    bool,
    pub warnings:        Vec<String>,
    pub duration_ms:     u64,
}
```

---

## Phase 1: PERCEIVE

```rust
// connector-engine/src/perception.rs
pub struct PerceptionEngine {
    memory:    MemoryCoordinator,
    grounding: GroundingTable,
    claims:    ClaimVerifier,
    judgment:  JudgmentEngine,
    trace:     TraceBuilder,
}

pub fn observe(
    &mut self,
    input:     &str,
    agent_pid: &str,
    config:    &ObservationConfig,
) -> Observation
```

**`Observation` output**:
```rust
pub struct Observation {
    pub cid:           Cid,           // CID of this observation
    pub input_cid:     Cid,           // CID of raw input packet
    pub entities:      Vec<String>,   // extracted named entities
    pub claims:        Vec<Claim>,    // structured claims from input
    pub grounded:      Vec<GroundedClaim>, // claims with domain codes
    pub quality_score: f32,           // 0.0–1.0 (JudgmentEngine)
    pub warnings:      Vec<String>,
    pub timestamp:     i64,
}
```

### ClaimVerifier

```rust
// connector-engine/src/claims.rs
pub struct Claim {
    pub text:         String,
    pub quote:        String,         // exact quote from source
    pub support:      SupportLevel,   // Explicit | Implied | Absent
    pub code:         Option<String>, // domain code (ICD-10, etc.)
}

pub enum SupportLevel {
    Explicit,  // quote found verbatim in source
    Implied,   // paraphrase, needs review
    Absent,    // not supported by source
}

// Verification logic:
// Explicit + quote found in source → Confirmed
// Explicit + quote NOT found       → Rejected (hallucinated evidence)
// Implied                          → NeedsReview
// Absent                           → Rejected
// code.is_some()                   → required for Confirmed
```

### GroundingTable

```rust
// connector-engine/src/grounding.rs
// JSON format: {"category": {"term": {"code": "...", "desc": "...", "system": "..."}}}
// Example:
// {"diagnosis": {"chest_pain": {"code": "R07.9", "desc": "Chest pain, unspecified", "system": "icd10"}}}

pub struct GroundingTable {
    entries: HashMap<String, HashMap<String, CodeEntry>>,
}

pub struct CodeEntry {
    pub code:   String,
    pub desc:   String,
    pub system: String,  // "icd10" | "cpt" | "rxnorm" | "unknown"
}
```

### JudgmentEngine

```rust
// connector-engine/src/judgment.rs
pub struct JudgmentEngine {
    config: JudgmentConfig,
}

pub struct JudgmentConfig {
    pub min_claim_confidence:  f32,   // default: 0.6
    pub require_grounding:     bool,  // default: false
    pub penalize_absent_claims: bool, // default: true
}

pub struct JudgmentResult {
    pub quality_score: f32,    // 0.0–1.0
    pub passed:        bool,
    pub reasons:       Vec<String>,
}
```

---

## Phase 2: RETRIEVE

```rust
// connector-engine/src/perception.rs
pub fn perceive(
    &self,
    observation: &Observation,
    token_budget: usize,
) -> PerceivedContext
```

**`PerceivedContext` output**:
```rust
pub struct PerceivedContext {
    pub cid:           Cid,
    pub packets:       Vec<MemPacket>,   // retrieved from kernel
    pub total_tokens:  usize,
    pub strategies:    Vec<String>,      // which retrieval strategies fired
    pub rrf_scores:    Vec<f64>,
    pub warnings:      Vec<String>,
}
```

Internally calls `KnowledgeEngine.retrieve()` which runs 4-way retrieval via `KnotEngine` + `RagEngine` + temporal + keyword, fused with RRF.

---

## Phase 3: REASON

```rust
// connector-engine/src/logic.rs
pub struct LogicEngine {
    config: LogicConfig,
}

pub fn plan(
    &self,
    goal:    &str,
    context: &PerceivedContext,
    llm:     &LlmRouter,
) -> Plan
```

**`Plan` structure**:
```rust
pub struct Plan {
    pub plan_id:  String,
    pub plan_cid: Cid,           // CID of this plan
    pub goal:     String,
    pub steps:    Vec<PlanStep>,
    pub created_at: i64,
}

pub struct PlanStep {
    pub step_id:      String,
    pub description:  String,
    pub tool_id:      Option<String>,
    pub action:       Option<String>,
    pub status:       StepStatus,
    pub result_cid:   Option<Cid>,    // CID of step result packet
    pub evidence_cids: Vec<Cid>,      // supporting evidence
    pub reasoning:    Option<String>,
}

pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
    Reconsidered,  // set by Phase 4 (Reflect)
}
```

---

## Phase 4: REFLECT

```rust
pub fn reflect(
    &self,
    plan:        &Plan,
    observation: &Observation,
) -> ReflectionResult

pub struct ReflectionResult {
    pub quality_score:    f32,
    pub passed:           bool,
    pub reconsidered_steps: Vec<String>,  // step_ids marked Reconsidered
    pub warnings:         Vec<String>,
    pub should_recycle:   bool,  // true → BindingEngine runs another cycle
}
```

If `quality_score < config.quality_threshold` and `cycle_number < max_cycles`:
- Steps with low confidence are marked `StepStatus::Reconsidered`
- `should_recycle = true` → BindingEngine starts Phase 1 again with updated context

---

## Phase 5: ACT

```rust
// connector-engine/src/knowledge.rs
pub fn compile(
    &mut self,
    plan:        &Plan,
    observation: &Observation,
) -> CompiledKnowledge
```

**`CompiledKnowledge`**:
```rust
pub struct CompiledKnowledge {
    pub cid:          Cid,           // CID of compiled result
    pub summary:      String,        // human-readable summary
    pub key_facts:    Vec<String>,   // extracted key facts
    pub entity_updates: Vec<String>, // entities updated in KnotEngine
    pub packet_cid:   Cid,           // CID of stored Extraction packet
}
```

The compiled knowledge is stored as an `Extraction` `MemPacket` in the kernel — reusable in future cycles without re-running the LLM.

---

## ReasoningChain

```rust
pub struct ReasoningChain {
    pub chain_id:     String,
    pub chain_cid:    Cid,
    pub steps:        Vec<ReasoningStep>,
    pub conclusion:   String,
    pub confidence:   f32,
    pub evidence_cids: Vec<Cid>,
}
```

The `ReasoningChain` is the final output of the cognitive loop — a CID-linked, evidence-backed chain from input to conclusion.
