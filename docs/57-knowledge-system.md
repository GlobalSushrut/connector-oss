# 57 — Knowledge System: The `/k/` Namespace and Knowledge Forms

> The knowledge system is what separates a governed AI system from a chatbot with a system prompt. `/k/` holds curated, auditable, expert-reviewed knowledge. Every fact has a source. Every claim is traceable. The LLM reasons from documented evidence — not from training weights that cannot be inspected.

---

## Why a Separate Knowledge System

A standard RAG system retrieves text chunks and injects them into an LLM prompt. The chunks are text. Their provenance is a filename. Their reliability is unknown. Their relationship to other chunks is implicit.

Connector's knowledge system is different:

| Standard RAG | Connector Knowledge System |
|---|---|
| Text chunks | Typed `KnowledgeForm` objects |
| Filename provenance | `agent_pid`, `timestamp`, `confidence`, `source_cid` |
| Unknown reliability | Confidence score + contradiction detection |
| No relationships | Structural and causal forms capture relationships |
| No versioning | `AppendOnly` namespace — old versions preserved |
| No audit | Every read and write journaled |
| No contradiction detection | `KnowledgeEngine.ingest()` detects conflicts |

---

## The 8 Knowledge Forms

Every piece of knowledge in `/k/` is typed as one of 8 `KnowledgeForm` variants. The type determines how the knowledge is stored, retrieved, and used in reasoning.

### 1. Factual

A verified observation or measurement.

```rust
KnowledgeForm::Factual {
    content: String,       // "Troponin I > 0.04 ng/mL indicates myocardial injury"
    confidence: f32,       // 0.97 — evidence quality score
    source: Option<String>, // "ACC/AHA 2023 Guidelines §3.2"
    verified_at: Timestamp,
}
```

**Used for:** Medical facts, scientific measurements, regulatory definitions, verified historical records.  
**Retrieval:** Highest priority in 4-way retrieval — if a factual form answers the query, it is returned first.

### 2. Procedural

A step-by-step method with preconditions and postconditions.

```rust
KnowledgeForm::Procedural {
    name: String,          // "cardiac-risk-assessment"
    steps: Vec<String>,    // ["1. Check troponin", "2. Assess ECG", ...]
    preconditions: Vec<String>,  // ["patient present", "labs available"]
    postconditions: Vec<String>, // ["risk level determined", "escalation decision made"]
    estimated_duration: Option<Duration>,
}
```

**Used for:** Clinical protocols, deployment procedures, compliance workflows, onboarding checklists.  
**Impact on reasoning:** When an agent encounters a task matching a `Procedural` form, the cognitive substrate generates a `CognitivePlan` aligned with the procedure's steps — structured execution, not freeform generation.

### 3. Structural

Relationships between entities — the knowledge graph.

```rust
KnowledgeForm::Structural {
    entities: Vec<String>,   // ["aspirin", "warfarin", "bleeding-risk"]
    relations: Vec<(String, String, String)>, // ("aspirin", "interacts-with", "warfarin")
    graph_type: String,      // "drug-interaction-graph"
}
```

**Used for:** Drug interaction graphs, organizational hierarchies, legal entity relationships, system dependency maps.  
**Retrieval:** Queried by entity or relation type. Returns the subgraph relevant to the query.

### 4. Causal

Cause → effect relationships with probability.

```rust
KnowledgeForm::Causal {
    cause: String,         // "elevated troponin"
    effect: String,        // "myocardial injury likely"
    probability: f32,      // 0.87
    conditions: Vec<String>, // ["in absence of renal failure"]
    evidence_cid: Option<String>, // Points to supporting factual forms
}
```

**Used for:** Diagnostic reasoning, risk factor analysis, incident root cause, regulatory causation chains.  
**Impact on reasoning:** The `tension.rs` engine uses causal forms to detect tensions — when the observed state contradicts an expected causal chain, it generates reasoning pressure.

### 5. Analogical

Pattern mapping between domains — "this is like that."

```rust
KnowledgeForm::Analogical {
    source_domain: String,   // "antibiotic resistance"
    target_domain: String,   // "AI model adversarial robustness"
    mapping: Vec<(String, String)>, // [("bacteria mutation", "adversarial input"), ...]
    confidence: f32,
}
```

**Used for:** Cross-domain transfer, novel problem solving, educational explanations, regulatory interpretation across jurisdictions.

### 6. Counterfactual

What would have happened under different conditions.

```rust
KnowledgeForm::Counterfactual {
    actual_scenario: String,     // "Patient received aspirin"
    alternative_scenario: String, // "Patient did not receive aspirin"
    actual_outcome: String,      // "Symptoms resolved in 48h"
    predicted_alternative: String, // "Likely prolonged ischemic event"
    confidence: f32,
    evidence_cid: Option<String>,
}
```

**Used for:** Clinical decision support (what if we had acted earlier?), compliance analysis (what if policy X had been applied?), incident retrospectives.

### 7. Temporal

Time-ordered knowledge with validity windows.

```rust
KnowledgeForm::Temporal {
    content: String,        // "Drug X dosing guideline"
    valid_from: Timestamp,
    valid_until: Option<Timestamp>, // null = still valid
    supersedes: Option<String>,     // CID of previous version
    event_type: String,             // "guideline_update"
}
```

**Used for:** Regulatory guidelines with expiry dates, drug formularies, policy versions, time-limited permissions.  
**Critical property:** The retrieval system checks `valid_until` before returning temporal forms. An expired guideline is not returned — the agent cannot accidentally reason from outdated knowledge.

### 8. Normative

Rules with enforcement levels — what agents MUST, SHOULD, and MUST NOT do.

```rust
KnowledgeForm::Normative {
    rule: String,           // "PHI must not be included in LLM context"
    enforcement: NormativeEnforcement,
    regulation_source: Option<String>, // "HIPAA §164.502(b)"
    applies_to: Vec<String>, // ["all-agents", "namespace:/p/"]
}

pub enum NormativeEnforcement {
    Mandatory,    // MUST — hard block if violated
    Recommended,  // SHOULD — soft warning
    Prohibited,   // MUST NOT — hard block
    Advisory,     // MAY — informational
}
```

**Impact:** `Mandatory` and `Prohibited` normative forms are enforced by the firewall (Ring 3) and the policy engine (Ring 5). The knowledge system feeds directly into governance enforcement.

---

## The Knowledge Engine

`knowledge.rs` implements the `KnowledgeEngine` — the system that manages the lifecycle of all knowledge in `/k/`.

### Ingest

```rust
let result: IngestResult = engine.ingest(observations, namespace, kernel).await?;
```

Ingestion:
1. Parses observations into `KnowledgeForm` types
2. Checks for contradictions with existing knowledge
3. Computes growth events (what was derived from interference)
4. Assigns CIDs to new packets
5. Writes to `/k/` namespace
6. Extends the namespace chain
7. Returns `IngestResult` with contradiction report

### Contradiction Detection

When two `Factual` forms conflict, or a new `Causal` form contradicts an existing one, `ingest()` produces a `ContradictionReport`:

```rust
pub struct ContradictionReport {
    pub new_form_cid: String,
    pub conflicting_form_cid: String,
    pub contradiction_type: ContradictionType,
    pub resolution: ContradictionResolution,
    pub confidence_delta: f32,  // How much certainty was lost
}
```

Resolution options: `PreferNewer`, `PreferHigherConfidence`, `RequireHumanReview`, `FlagAndKeepBoth`.

Contradictions in `/k/` are a signal that domain knowledge is in dispute — the HITL queue is used for high-stakes contradictions (medical, legal, financial).

### Retrieve: 4-Way Retrieval with RRF Fusion

Retrieval uses four strategies simultaneously, then fuses results with Reciprocal Rank Fusion (RRF):

```
Query: "cardiac risk assessment for patient with elevated troponin"

Strategy 1: Semantic similarity (embedding cosine)
  → Factual: "Troponin > 0.04 indicates injury" (score: 0.91)
  → Procedural: "cardiac-risk-assessment" (score: 0.87)

Strategy 2: Keyword match
  → Factual: "troponin threshold" (score: 0.85)

Strategy 3: Knowledge form type preference
  → Procedural forms preferred for action queries (score boost)

Strategy 4: Recency and validity
  → Temporal forms checked: only valid-now forms returned

RRF Fusion → ranked list → token budget applied → context returned
```

The token budget ensures that knowledge retrieval does not consume the entire LLM context window — the most relevant forms are selected to fit the budget.

### Compile: Cached Reasoning Packets

For expensive reasoning chains that are reused frequently, `compile()` produces a `CompiledKnowledge` packet:

```rust
pub struct CompiledKnowledge {
    pub cid: String,         // CID of the compiled packet
    pub query_signature: String, // Hash of the query that produced it
    pub result: String,      // The cached reasoning
    pub source_cids: Vec<String>, // What knowledge forms were used
    pub compiled_at: Timestamp,
    pub confidence: f32,
}
```

Compiled knowledge is invalidated when any of its `source_cids` are updated. This prevents stale cached reasoning from being used after the underlying knowledge changes.

---

## Knowledge Seeds

`ThoughtSeed` and `KnowledgeSeed` in `cognitive/types.rs` pre-populate an agent's knowledge at creation time:

```rust
pub struct ThoughtSeed {
    pub domain: String,       // "medical-cardiology"
    pub knowledge: Vec<KnowledgeForm>,
    pub priorities: Vec<String>,  // What this agent cares about most
    pub expertise_level: f32, // 0.0 = novice, 1.0 = expert
}
```

Seeds are loaded from `/k/` namespace paths declared in the agent manifest. An agent seeded with `["/k/medical/cardiology/", "/k/medical/pharmacology/"]` starts with comprehensive medical knowledge already in its cognitive context — before the first patient query arrives.

---

## Knowledge Growth Events

Every time the Knowledge Engine detects interference between existing knowledge and new observations, it records a `GrowthEvent`:

```rust
pub struct GrowthEvent {
    pub trigger_cid: String,     // What new observation triggered growth
    pub interfering_cid: String, // What existing knowledge interfered
    pub derived_forms: Vec<KnowledgeForm>, // What new knowledge was derived
    pub growth_type: GrowthType, // Expansion, Refinement, Contradiction, Synthesis
    pub timestamp: Timestamp,
}
```

Growth events are the audit trail of how knowledge evolved. A compliance officer can ask: "how did this agent come to know that patient X has drug allergy Y?" and trace the complete knowledge provenance chain.

---

## Hyperbolic Embeddings in the Chain Tree

`chain_tree.rs` uses hyperbolic space (Poincaré disk model) for knowledge embedding. Why hyperbolic?

Standard embedding spaces (Euclidean) distort hierarchical relationships — things that are conceptually close in a hierarchy appear far apart in vector space. Knowledge is deeply hierarchical: `cardiac-symptoms` → `chest-pain` → `ischemic-pain` → `STEMI`.

Hyperbolic space preserves hierarchical structure exponentially better than Euclidean space. The `HyperbolicPoint` in `chain_tree.rs` stores the Poincaré disk coordinates of each knowledge node. Memory recall using hyperbolic nearest-neighbor search finds related knowledge along the hierarchy — not just semantically similar text.

```bash
$ connectorctl show agent ag_a3f7b2 --knowledge-stats
  knowledge_namespace:  /k/medical/cardiology/
  total_forms:          4,127
  factual:              2,891
  procedural:            412
  causal:                389
  structural:            201
  normative:             234
  compiled_cache:         89 packets
  contradiction_count:     7 (6 resolved, 1 pending HITL)
  last_growth_event:    2026-04-13T22:41:12Z
```
