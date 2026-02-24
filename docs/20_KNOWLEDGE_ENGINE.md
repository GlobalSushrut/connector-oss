# Knowledge Engine

> KnowledgeEngine, ingest, retrieve, compile, contradictions
> Source: `connector/crates/connector-engine/src/knowledge.rs`

---

## Purpose

The `KnowledgeEngine` manages knowledge growth, retrieval, and compilation. It wraps three sub-systems:

- **RagEngine** — vector-based semantic retrieval
- **KnotEngine** — entity graph retrieval (see `13_KNOT_ENGINE.md`)
- **InterferenceEngine** — contradiction detection and StateVector compaction

The key distinction: **Memory ≠ Knowledge**. Memory is raw packets in the kernel. Knowledge is structured, contradiction-checked, retrievable understanding built from those packets.

---

## KnowledgeEngine Structure

```rust
pub struct KnowledgeEngine {
    knot:         KnotEngine,
    rag:          RagEngine,
    interference: InterferenceEngine,
    config:       KnowledgeConfig,
}

pub struct KnowledgeConfig {
    pub token_budget:          usize,   // default: 8192
    pub max_retrieval_results: usize,   // default: 20
    pub contradiction_threshold: f64,  // default: 0.7
    pub enable_graph:          bool,   // default: true
    pub enable_semantic:       bool,   // default: true (requires vector store)
    pub enable_temporal:       bool,   // default: true
    pub enable_keyword:        bool,   // default: true
}
```

---

## ingest()

Adds an observation to the knowledge base:

```rust
pub fn ingest(
    &mut self,
    observation: &Observation,
    packets:     &[MemPacket],
) -> IngestResult
```

**What it does**:
1. Extracts entities from `observation.entities` → upserts `KnotNode` entries
2. Infers relationships from co-occurring entities → upserts `KnotEdge` entries
3. Runs `InterferenceEngine.detect_contradiction()` against existing knowledge
4. If contradiction detected: creates `ContradictionRecord`, sets `interference_score`
5. Adds packets to `RagEngine` index (if semantic enabled)

**`IngestResult`**:
```rust
pub struct IngestResult {
    pub entities_upserted:      usize,
    pub edges_upserted:         usize,
    pub total_entities:         usize,
    pub contradiction_detected: bool,
    pub interference_score:     f64,   // 0.0 = no conflict, 1.0 = full contradiction
    pub warnings:               Vec<String>,
}
```

---

## retrieve()

4-way parallel retrieval with RRF fusion:

```rust
pub fn retrieve(
    &self,
    observation:  &Observation,
    kernel:       &MemoryKernel,
    token_budget: usize,
) -> PerceivedContext
```

**4 strategies run in parallel**:

```
Strategy 1: Temporal
  → MemoryQuery { since_ts: now-24h, until_ts: now, limit: 50 }
  → kernel.dispatch(Query { query })
  → returns packets sorted by timestamp desc

Strategy 2: Entity/Graph
  → KnotQuery { entity_ids: observation.entities, max_hops: 2 }
  → KnotEngine.query(knot_query, packets, budget)
  → returns packets linked to entities + their graph neighbors

Strategy 3: Keyword
  → Match observation.entities + tags against packet.content.tags + entities
  → Returns packets with any matching tag or entity

Strategy 4: Semantic
  → RagEngine.search(observation.input_text, top_k=20)
  → Returns packets by embedding similarity
  → (empty if no vector store configured)
```

**RRF fusion**: All 4 result lists merged, scored, deduplicated, trimmed to `token_budget`.

---

## compile()

Caches a reasoning chain as reusable semantic memory:

```rust
pub fn compile(
    &mut self,
    plan:        &Plan,
    observation: &Observation,
) -> CompiledKnowledge
```

**What it does**:
1. Extracts key facts from `plan.steps` (completed steps with `result_cid`)
2. Updates `KnotEngine` with new entities/edges from the plan
3. Writes an `Extraction` `MemPacket` to the kernel with the compiled summary
4. Returns `CompiledKnowledge` with the packet CID

**`CompiledKnowledge`**:
```rust
pub struct CompiledKnowledge {
    pub cid:             Cid,
    pub summary:         String,
    pub key_facts:       Vec<String>,
    pub entity_updates:  Vec<String>,
    pub packet_cid:      Cid,   // CID of stored Extraction packet in kernel
}
```

The compiled knowledge packet is reused in future cycles — the LLM doesn't need to re-derive the same conclusions.

---

## KnowledgeSeed

Pre-loads domain knowledge before any agent runs:

```rust
pub struct KnowledgeSeed {
    pub domain:   String,         // "healthcare", "finance", "legal"
    pub entities: Vec<KnotNode>,
    pub edges:    Vec<KnotEdge>,
    pub facts:    Vec<String>,
}

pub fn seed(&mut self, seed: KnowledgeSeed) -> IngestResult
```

Used in `connector.yaml`:
```yaml
knowledge:
  domain: healthcare
  seed_file: ./knowledge/icd10_common.json
```

---

## GrowthEvent

Tracks how the knowledge base grows over time:

```rust
pub struct GrowthEvent {
    pub timestamp:    i64,
    pub event_type:   GrowthEventType,
    pub entity_count: usize,
    pub edge_count:   usize,
    pub packet_count: usize,
}

pub enum GrowthEventType {
    Ingest,
    Compile,
    Seed,
    Contradiction,
    Eviction,
}
```

---

## RagEngine

```rust
pub struct RagEngine {
    // Vector store integration (optional)
    // If no vector store configured: semantic search returns empty
    // Supports: in-memory (default), Pinecone, Qdrant, Chroma (via adapters)
}

impl RagEngine {
    pub fn index(&mut self, packet: &MemPacket, embedding: Vec<f32>)
    pub fn search(&self, query: &str, top_k: usize) -> Vec<(Cid, f32)>
    // Returns: (packet_cid, similarity_score) pairs
}
```

---

## Contradiction Handling

When `IngestResult.contradiction_detected = true`:

1. `ContradictionRecord` added to current `StateVector`
2. `Contradiction` `MemPacket` written to kernel:
   - `content.packet_type = PacketType::Contradiction`
   - `provenance.evidence_refs = [cid_a, cid_b]`
   - `provenance.supersedes = cid_a` (older conflicting packet)
3. `LogicEngine.reflect()` sees contradiction → marks affected `PlanStep` as `Reconsidered`
4. `BindingEngine` may trigger another cycle with updated context

**Example**:
```
Packet A (from session 1): "Patient has no known allergies"
Packet B (from session 2): "Patient allergic to Penicillin"
→ InterferenceEdge { kind: Contradict, from: cid_A, to: cid_B }
→ Contradiction packet written
→ Warning: "Contradiction detected: allergy status conflict"
→ JudgmentEngine penalizes quality_score
```
