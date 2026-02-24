# MemPacket

> MemPacket 3-plane model, PacketType enum, all fields
> Source: `vac/crates/vac-core/src/types.rs`

---

## The 3-Plane Model

Every agent artifact is stored as a `MemPacket` — a content-addressed envelope with three orthogonal planes:

```
MemPacket
  ├── ContentPlane    — WHAT happened
  ├── ProvenancePlane — WHERE it came from
  └── AuthorityPlane  — WHO authorized it
```

---

## ContentPlane

```rust
pub struct ContentPlane {
    pub packet_type:    PacketType,       // classifies the artifact
    pub payload:        serde_json::Value, // the actual data (JSON)
    pub payload_cid:    Cid,              // CID of the payload content
    pub schema_version: String,
    pub encoding:       String,           // default: "json"
    pub entities:       Vec<String>,      // named entities referenced
    pub tags:           Vec<String>,      // classification tags
    pub chapter_hint:   Option<String>,   // session/chapter grouping hint
}
```

---

## PacketType

```rust
pub enum PacketType {
    Input,        // raw user/sensor input
    LlmRaw,       // full LLM generation output
    Extraction,   // structured facts extracted from LLM output
    Decision,     // agent decision with reasoning
    ToolCall,     // tool invocation with parameters
    ToolResult,   // tool response/result
    Action,       // authorized VAKYA action (AAPI envelope)
    Feedback,     // human correction/approval/feedback
    Contradiction,// detected conflict between facts
    StateChange,  // before/after state transition
}
// Display: lowercase snake_case (e.g., PacketType::LlmRaw → "llm_raw")
```

---

## ProvenancePlane

```rust
pub struct ProvenancePlane {
    pub source:       Source,         // { kind: SourceKind, principal_id: DID }
    pub trust_tier:   u8,             // 3=self/verified, 2=tool, 1=user, 0=untrusted
    pub evidence_refs: Vec<Cid>,      // CIDs of supporting evidence packets
    pub confidence:   Option<f32>,    // 0.0–1.0
    pub epistemic:    Epistemic,      // Observed | Inferred | Verified | Retracted
    pub supersedes:   Option<Cid>,    // CID of packet this one replaces
    pub reasoning:    Option<String>, // human-readable reasoning chain
    pub domain_code:  Option<String>, // e.g., ICD-10 "I21.3", RxNorm "723"
}

pub struct Source {
    pub kind:         SourceKind,
    pub principal_id: String,  // DID (e.g., "did:key:z6Mk...")
}

pub enum SourceKind {
    SelfSource,  // agent itself
    User,        // human user
    Tool,        // tool/function call
    Web,         // web retrieval
    Untrusted,   // unverified external source
}

pub enum Epistemic {
    Observed,   // directly seen/measured
    Inferred,   // derived from other facts
    Verified,   // cryptographically verified
    Retracted,  // previously asserted, now withdrawn
}
```

---

## AuthorityPlane

```rust
pub struct AuthorityPlane {
    pub vakya_id:    Option<String>, // AAPI VAKYA token ID that authorized this
    pub actor:       Option<String>, // who authorized
    pub capability:  Option<String>, // capability reference used
    pub namespace:   String,         // owning namespace (ns:<agent_name>)
    pub session_id:  Option<String>, // session this belongs to
    pub subject_id:  String,         // user/patient/entity this is about
    pub pipeline_id: String,         // pipeline that produced this
    pub timestamp:   i64,            // Unix milliseconds
}
```

---

## MemPacket Constructor

```rust
impl MemPacket {
    pub fn new(
        packet_type: PacketType,
        payload:     serde_json::Value,
        payload_cid: Cid,
        subject_id:  String,
        pipeline_id: String,
        source:      Source,
        timestamp:   i64,
    ) -> Self
}
```

---

## CID Determinism

```rust
// Same content always produces the same CID:
let cid1 = compute_cid(&packet_a).unwrap();
let cid2 = compute_cid(&packet_b).unwrap(); // same fields as packet_a
assert_eq!(cid1, cid2);  // guaranteed
```

---

## Supporting Types

### Event (raw input atom)
```rust
pub struct Event {
    pub type_:           String,     // "event"
    pub version:         u32,
    pub ts:              i64,
    pub chapter_hint:    Option<String>,
    pub actors:          Vec<String>,
    pub tags:            Vec<String>,
    pub entities:        Vec<String>,
    pub payload_ref:     Cid,
    pub feature_sketch:  Vec<u8>,
    pub entropy:         f32,
    pub importance:      f32,
    pub score_components: ScoreComponents { salience, recency, connectivity },
    pub source:          Source,
    pub trust_tier:      u8,
    pub verification:    Option<Verification>,
    pub links:           BTreeMap<String, Cid>,
    pub metadata:        BTreeMap<String, Value>,
}
```

### ClaimBundle (structured assertion)
```rust
pub struct ClaimBundle {
    pub subject_id:     String,
    pub predicate_key:  String,
    pub value:          serde_json::Value,
    pub value_type:     String,   // "string" | "number" | "bool" | "json"
    pub units:          Option<String>,
    pub epistemic:      Epistemic,
    pub asserted_ts:    i64,
    pub valid_ts_range: Option<ValidityRange { from, to }>,
    pub confidence:     Option<f32>,
    pub evidence_refs:  Vec<Cid>,
    pub supersedes:     Option<Cid>,
    pub source:         Source,
    pub trust_tier:     u8,
}
```

### InterferenceEdge (§25.10)
```rust
pub struct InterferenceEdge {
    pub kind:       IeKind,  // Reinforce | Contradict | Refine | Alias
    pub strength:   f32,
    pub created_ts: i64,
    pub links: IeLinks { pub from: Cid, pub to: Cid },
}
```
