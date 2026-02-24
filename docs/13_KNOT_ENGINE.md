# Knot Engine

> KnotEngine, KnotNode/Edge, 4-way retrieval, RRF fusion
> Source: `vac/crates/vac-core/src/knot.rs`

---

## Purpose

The `KnotEngine` is a typed entity knowledge graph built into `vac-core`. It maintains entities and relationships extracted from `MemPacket` content, enabling structured retrieval beyond simple keyword search.

Design sources: Graphiti (temporal knowledge graph), Microsoft GraphRAG (community detection), Zep (bi-temporal + graph), LightRAG (dual-level), vLLM PagedAttention (token-budget packing).

---

## KnotNode

```rust
pub struct KnotNode {
    pub entity_id:    String,                          // "patient:P-001", "drug:penicillin"
    pub entity_type:  Option<String>,                  // "person", "medication", "organization"
    pub attributes:   BTreeMap<String, serde_json::Value>,
    pub tags:         Vec<String>,                     // for keyword search
    pub first_seen:   i64,                             // Unix ms
    pub last_seen:    i64,
    pub mention_count: u64,
    pub window_sns:   Vec<u64>,                        // RangeWindow serial numbers
    pub source_cids:  Vec<Cid>,                        // packets that contributed
}
```

---

## KnotEdge

```rust
pub struct KnotEdge {
    pub from:         String,   // source entity_id
    pub to:           String,   // target entity_id
    pub relation:     String,   // "allergic_to", "prescribed", "works_at", "has_condition"
    pub weight:       f64,      // edge strength (higher = stronger)
    pub evidence_cids: Vec<Cid>,
    pub created_at:   i64,
    pub last_updated: i64,
}
```

---

## KnotQuery

```rust
pub struct KnotQuery {
    pub entity_ids:   Vec<String>,   // start from these entities
    pub relations:    Vec<String>,   // filter by relation type
    pub max_hops:     usize,         // graph traversal depth
    pub since_ts:     Option<i64>,
    pub until_ts:     Option<i64>,
    pub limit:        Option<usize>,
}
```

---

## 4-Way Retrieval

`KnotEngine` implements 4 parallel retrieval strategies, fused with RRF:

```
1. Temporal  — by time range (RangeWindow pagination)
               → packets in [since_ts, until_ts] window

2. Entity/Graph — by entity relationships
               → start from seed entities, traverse KnotEdge hops
               → up to max_hops depth

3. Keyword   — by tag/entity string matching
               → exact and prefix match on tags + entity_ids

4. Semantic  — by embedding similarity
               → placeholder for vector store integration
               → currently returns empty (vector store optional)
```

---

## Reciprocal Rank Fusion (RRF)

Results from all 4 strategies are merged using RRF:

```
RRF score for document d = Σ 1 / (k + rank_i(d))
  where k = 60 (standard constant)
  and rank_i(d) = rank of d in retrieval strategy i
```

Documents appearing in multiple strategies get boosted scores. Final list is sorted by RRF score descending.

---

## Token Budget Packing

After RRF fusion, results are trimmed to fit a token budget:

```rust
pub struct FusedResult {
    pub packets:         Vec<MemPacket>,
    pub total_tokens:    usize,
    pub budget_used:     usize,
    pub budget_limit:    usize,
    pub strategies_used: Vec<String>,
    pub rrf_scores:      Vec<f64>,
}
```

Packets are added in RRF score order until `budget_used >= budget_limit`. This ensures the LLM context window is never exceeded.

---

## KnotEngine API

```rust
impl KnotEngine {
    pub fn new() -> Self

    // Upsert entity
    pub fn upsert_node(&mut self, node: KnotNode)

    // Upsert relationship
    pub fn upsert_edge(&mut self, edge: KnotEdge)

    // Get entity by ID
    pub fn get_node(&self, entity_id: &str) -> Option<&KnotNode>

    // Get all edges from an entity
    pub fn edges_from(&self, entity_id: &str) -> Vec<&KnotEdge>

    // 4-way retrieval with RRF fusion
    pub fn query(
        &self,
        query:        &KnotQuery,
        packets:      &HashMap<Cid, MemPacket>,
        token_budget: usize,
    ) -> FusedResult

    // Entity count
    pub fn node_count(&self) -> usize

    // Edge count
    pub fn edge_count(&self) -> usize
}
```

---

## Integration with KnowledgeEngine

`connector-engine/src/knowledge.rs` wraps `KnotEngine` with higher-level operations:

```rust
pub struct KnowledgeEngine {
    knot:          KnotEngine,
    rag:           RagEngine,
    interference:  InterferenceEngine,
}

// ingest() → upserts entities + edges into KnotEngine
// retrieve() → calls KnotEngine.query() as one of 4 strategies
// compile() → caches ReasoningChain as CompiledKnowledge packet
```

The `IngestResult` reports:
```rust
pub struct IngestResult {
    pub entities_upserted:       usize,
    pub edges_upserted:          usize,
    pub total_entities:          usize,
    pub contradiction_detected:  bool,
    pub interference_score:      f64,  // 0.0 = no conflict, higher = more conflict
    pub warnings:                Vec<String>,
}
```
