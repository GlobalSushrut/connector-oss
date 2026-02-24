# Sessions and Contexts

> SessionEnvelope, ContextSnapshot, compression
> Source: `vac/crates/vac-core/src/types.rs`, `vac/crates/vac-core/src/kernel.rs`

---

## SessionEnvelope

A session groups related packets under a logical conversation or task boundary.

```rust
pub struct SessionEnvelope {
    pub type_:            String,           // "session"
    pub version:          u32,
    pub session_id:       String,
    pub agent_pid:        String,
    pub namespace:        String,
    pub label:            Option<String>,
    pub parent_session_id: Option<String>,  // for nested sessions
    pub child_session_ids: Vec<String>,
    pub started_at:       i64,
    pub ended_at:         Option<i64>,
    pub is_active:        bool,
    pub total_tokens:     u64,
    pub summary:          Option<String>,   // set after SessionCompress
    pub summary_cid:      Option<Cid>,      // CID of compressed summary
    pub metadata:         BTreeMap<String, serde_json::Value>,
}
```

---

## Session Lifecycle

```
SessionCreate(session_id, label, parent_session_id)
    → creates SessionEnvelope
    → audit: SessionCreate, Success
    → returns SyscallValue::SessionId(session_id)

(agent writes packets with session_id in AuthorityPlane)
(session_index[session_id] grows with each MemWrite)

SessionCompress(session_id, algorithm, summary)
    → sets session.summary = summary
    → stores summary as new packet → summary_cid
    → audit: SessionCompress, Success

SessionClose(session_id)
    → sets session.ended_at = now
    → sets session.is_active = false
    → audit: SessionClose, Success
```

---

## ContextSnapshot

Captures the full execution context of an agent at a point in time:

```rust
pub struct ExecutionContext {
    pub agent_pid:        String,
    pub session_id:       Option<String>,
    pub pipeline_id:      String,
    pub active_packets:   Vec<Cid>,        // packets in working memory
    pub token_count:      u64,
    pub tool_calls:       Vec<String>,     // tool IDs called this session
    pub decisions:        Vec<String>,     // decision CIDs made this session
    pub timestamp:        i64,
    pub session_snapshot: Option<Cid>,     // CID of compressed session summary
}
```

**ContextSnapshot syscall**:
```rust
SyscallPayload::ContextSnapshot { session_id, pipeline_id }
// → serializes ExecutionContext to DAG-CBOR
// → computes CID
// → stores in context_snapshots HashMap
// → returns SyscallValue::Cid(snapshot_cid)
```

**ContextRestore syscall**:
```rust
SyscallPayload::ContextRestore { snapshot_cid }
// → retrieves ExecutionContext from context_snapshots
// → returns SyscallValue::Context(Box<ExecutionContext>)
```

---

## SessionInfo (KernelOps view)

```rust
pub struct SessionInfo {
    pub session_id:  String,
    pub agent_id:    String,
    pub namespace:   String,
    pub label:       Option<String>,
    pub packet_count: usize,
    pub total_tokens: u64,
    pub started_at:  i64,
    pub ended_at:    Option<i64>,
    pub is_active:   bool,
    pub tier:        String,
}
```

---

## Nested Sessions

Sessions can be nested via `parent_session_id`. This enables hierarchical task decomposition:

```
session:pipeline-001 (parent)
  ├── session:triage-001 (child — triage agent)
  ├── session:diagnosis-001 (child — diagnosis agent)
  └── session:treatment-001 (child — treatment agent)
```

Each child session has its own packet index and token count. The parent session aggregates.

---

## Session Compression

When a session grows large, `SessionCompress` replaces raw packets with a summary:

```rust
SyscallPayload::SessionCompress {
    session_id: "session:triage-001".to_string(),
    algorithm:  "extractive".to_string(),
    summary:    "Patient John Doe, 45M, chest pain onset 2h ago, BP 158/95...".to_string(),
}
// → summary stored as new Extraction packet
// → summary_cid set on SessionEnvelope
// → original packets remain (not deleted — use MemEvict to free space)
```

This enables **infinite memory** through compaction: raw packets → compressed summary → raw packets evicted.
