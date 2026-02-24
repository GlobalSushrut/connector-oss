# Interference Engine

> StateVector, InterferenceEdge, compaction, contradiction
> Source: `vac/crates/vac-core/src/interference.rs`

---

## Purpose

The `InterferenceEngine` extracts structured meaning from raw `MemPacket` streams into `StateVector` snapshots, then computes `InterferenceEdge` deltas between consecutive windows. This enables **infinite memory through compaction**: raw packets → StateVector + InterferenceEdge chains → raw packets can be evicted.

Design sources: CRDT delta state vectors, Hindsight CARA reflect, EverMemOS engram lifecycle, Event Sourcing snapshots.

---

## StateVector

A snapshot of everything the agent knows about a set of entities at a point in time:

```rust
pub struct StateVector {
    pub window_sn:   u64,                    // RangeWindow serial number
    pub timestamp:   i64,
    pub entities:    HashMap<String, EntityState>,
    pub intents:     Vec<Intent>,
    pub decisions:   Vec<DecisionRecord>,
    pub contradictions: Vec<ContradictionRecord>,
    pub observations: Vec<ObservationRecord>,
    pub sv_cid:      Option<Cid>,            // CID of this StateVector
}
```

### EntityState

```rust
pub struct EntityState {
    pub entity_id:    String,                // "patient:P-001", "user:alice"
    pub attributes:   BTreeMap<String, serde_json::Value>,
    pub last_seen:    i64,
    pub mention_count: u64,
    pub source_cids:  Vec<Cid>,             // packets that contributed
}
```

### Intent

```rust
pub struct Intent {
    pub intent_id:   String,
    pub description: String,
    pub open:        bool,
    pub created_at:  i64,
    pub resolved_at: Option<i64>,
    pub evidence_cids: Vec<Cid>,
}
```

### DecisionRecord

```rust
pub struct DecisionRecord {
    pub description: String,
    pub reasoning:   Option<String>,
    pub outcome:     Option<String>,
    pub decided_at:  i64,
    pub evidence_cids: Vec<Cid>,
}
```

### ContradictionRecord

```rust
pub struct ContradictionRecord {
    pub description:  String,
    pub cid_a:        Cid,    // first conflicting packet
    pub cid_b:        Cid,    // second conflicting packet
    pub detected_at:  i64,
    pub resolved:     bool,
    pub resolution:   Option<String>,
}
```

---

## InterferenceEdge

Represents the delta between two consecutive StateVectors — what changed:

```rust
// vac-core/src/types.rs — InterferenceEdge (§25.10)
pub struct InterferenceEdge {
    pub type_:      String,   // "interference_edge"
    pub version:    u32,
    pub kind:       IeKind,
    pub strength:   f32,      // 0.0–1.0
    pub created_ts: i64,
    pub links: IeLinks {
        pub from: Cid,        // CID of earlier StateVector
        pub to:   Cid,        // CID of later StateVector
    },
}

pub enum IeKind {
    Reinforce,   // new evidence strengthens an existing belief
    Contradict,  // new evidence conflicts with an existing belief
    Refine,      // new evidence narrows/clarifies an existing belief
    Alias,       // two entities are discovered to be the same
}
```

---

## Compaction Flow

```
Window N packets:
  [Input, LlmRaw, Extraction, Decision, ToolCall, ToolResult]
         ↓
  InterferenceEngine.extract_state_vector(packets)
         ↓
  StateVector_N { entities, intents, decisions, contradictions }
         ↓ (compute CID → sv_cid_N)
         ↓
  InterferenceEngine.compute_edge(sv_N-1, sv_N)
         ↓
  InterferenceEdge { kind=Reinforce|Contradict|Refine|Alias, from=sv_cid_N-1, to=sv_cid_N }
         ↓
  Store StateVector_N + InterferenceEdge in kernel
  Evict raw Window N packets (MemEvict)
         ↓
  Memory footprint: O(windows) instead of O(packets)
```

---

## Contradiction Detection

When `IeKind::Contradict` is detected:

1. A `ContradictionRecord` is added to the new `StateVector`
2. A `Contradiction` `MemPacket` is written to the kernel
3. The `ProvenancePlane.supersedes` field on the new packet points to the conflicting CID
4. `KnowledgeEngine.ingest()` reports `contradiction_detected: true` in `IngestResult`
5. `LogicEngine.reflect()` can trigger reconsideration of the current plan

---

## InterferenceEngine API

```rust
impl InterferenceEngine {
    pub fn new() -> Self

    // Extract StateVector from a batch of packets
    pub fn extract_state_vector(
        &self,
        packets:   &[MemPacket],
        window_sn: u64,
        timestamp: i64,
    ) -> StateVector

    // Compute delta between two StateVectors
    pub fn compute_edge(
        &self,
        prev: &StateVector,
        next: &StateVector,
    ) -> InterferenceEdge

    // Check if two packets contradict each other
    pub fn detect_contradiction(
        &self,
        a: &MemPacket,
        b: &MemPacket,
    ) -> Option<ContradictionRecord>
}
```

---

## RangeWindow

`RangeWindow` is the time-windowed pagination unit that organizes packets before StateVector extraction:

```rust
pub struct RangeWindow {
    pub sn:           u64,           // serial number (monotonically increasing)
    pub t_min:        i64,
    pub t_max:        i64,
    pub packet_count: u32,
    pub rw_root:      [u8; 32],      // Merkle root of packets in this window
    pub prev_rw_root: [u8; 32],      // links to previous window (chain)
    pub sv_cid:       Option<Cid>,   // CID of extracted StateVector
}
```

`verify_window_chain()` walks the chain verifying `rw_root` and `prev_rw_root` linkage — any gap or modification is detected.
