# Syscalls

> Complete SyscallPayload variants, SyscallResult, OpOutcome
> Source: `vac/crates/vac-core/src/kernel.rs`

---

## Complete SyscallPayload Variants

| Variant | Key Fields | Returns |
|---------|-----------|---------|
| `Empty` | — | None |
| `AgentRegister` | agent_name, namespace, role, model, framework | AgentPid |
| `MemWrite` | packet: MemPacket | Cid |
| `MemRead` | packet_cid: Cid | Packet |
| `TierChange` | packet_cid, new_tier: MemoryTier | None |
| `MemEvict` | cids: Vec\<Cid\>, max_evict: u64 | Count |
| `MemSeal` | cids: Vec\<Cid\> | None |
| `MemClear` | — | None |
| `MemAlloc` | quota_packets, quota_tokens, quota_bytes, eviction_policy | None |
| `SessionCreate` | session_id, label, parent_session_id | SessionId |
| `SessionClose` | session_id | None |
| `SessionCompress` | session_id, algorithm, summary | None |
| `ContextSnapshot` | session_id, pipeline_id | Cid |
| `ContextRestore` | snapshot_cid: Cid | Context |
| `AccessGrant` | target_namespace, grantee_pid, read: bool, write: bool | None |
| `AccessRevoke` | target_namespace, grantee_pid | None |
| `AccessCheck` | target_namespace, operation: "read"\|"write" | Bool |
| `Query` | query: MemoryQuery | Packets |
| `PortCreate` | port_type, direction, allowed_packet_types, allowed_actions, max_delegation_depth, ttl_ms | None |
| `PortBind` | port_id, target_pid | None |
| `PortSend` | port_id, message: PortMessage | None |
| `PortReceive` | port_id | Packet |
| `PortClose` | port_id | None |
| `PortDelegate` | port_id, delegate_to, allowed_actions | None |
| `AgentTerminate` | target_pid: Option\<String\>, reason | None |
| `IntegrityCheck` | — | Bool |
| `GarbageCollect` | — | Count |
| `IndexRebuild` | — | None |
| `ToolDispatch` | tool_id, action, request: Value | Packet |

---

## MemoryKernelOp Enum

```rust
pub enum MemoryKernelOp {
    AgentRegister,
    AgentStart,
    AgentSuspend,
    AgentResume,
    AgentTerminate,
    MemWrite,
    MemRead,
    TierChange,
    MemEvict,
    MemSeal,
    MemClear,
    MemAlloc,
    SessionCreate,
    SessionClose,
    SessionCompress,
    ContextSnapshot,
    ContextRestore,
    AccessGrant,
    AccessRevoke,
    AccessCheck,
    Query,
    PortCreate,
    PortBind,
    PortSend,
    PortReceive,
    PortClose,
    PortDelegate,
    IntegrityCheck,
    GarbageCollect,
    IndexRebuild,
    ToolDispatch,
}
```

---

## OpOutcome

```rust
pub enum OpOutcome {
    Success,
    Denied,   // access control rejection
    Failed,   // operational failure
}
```

---

## SyscallValue

```rust
pub enum SyscallValue {
    None,
    Cid(Cid),                      // MemWrite, ContextSnapshot
    Packet(Box<MemPacket>),         // MemRead, PortReceive, ToolDispatch
    Packets(Vec<MemPacket>),        // Query
    AgentPid(String),               // AgentRegister → "pid:000001"
    SessionId(String),              // SessionCreate
    Bool(bool),                     // AccessCheck, IntegrityCheck
    Count(u64),                     // MemEvict, GarbageCollect
    Context(Box<ExecutionContext>),  // ContextRestore
    Error(String),                  // operation-specific error detail
}
```

---

## MemoryTier

```rust
pub enum MemoryTier {
    Hot,      // active working memory, fast access
    Warm,     // recent episodic, moderate access
    Cold,     // long-term semantic, slow access
    Archive,  // compliance retention, rarely accessed
}
```

---

## EvictionPolicy

```rust
pub enum EvictionPolicy {
    Lru,       // least recently used
    Lfu,       // least frequently used
    TierBased, // evict cold/archive first
    Manual,    // only explicit MemEvict calls
}
```

---

## PortType and PortDirection

```rust
pub enum PortType {
    MemoryShare,       // share memory packets between agents
    ToolDelegate,      // delegate tool access
    EventStream,       // one-way event stream
    RequestResponse,   // synchronous request/response
    Broadcast,         // one-to-many
    Pipeline,          // ordered pipeline stage
}

pub enum PortDirection {
    Inbound,
    Outbound,
    Bidirectional,
}
```

---

## MemoryQuery

```rust
pub struct MemoryQuery {
    pub namespace:    Option<String>,
    pub session_id:   Option<String>,
    pub packet_types: Vec<PacketType>,
    pub tags:         Vec<String>,
    pub entities:     Vec<String>,
    pub since_ts:     Option<i64>,
    pub until_ts:     Option<i64>,
    pub limit:        Option<usize>,
    pub subject_id:   Option<String>,
}
```

---

## Example: Full Agent Write Cycle

```rust
// 1. Register agent
let reg = kernel.dispatch(SyscallRequest {
    agent_pid: "system".to_string(),
    operation: MemoryKernelOp::AgentRegister,
    payload: SyscallPayload::AgentRegister {
        agent_name: "triage".to_string(),
        namespace:  "ns:triage".to_string(),
        role:       Some("agent".to_string()),
        model:      Some("deepseek-chat".to_string()),
        framework:  Some("connector".to_string()),
    },
    reason:   Some("Agent 'triage' registration".to_string()),
    vakya_id: None,
});
let pid = match reg.value { SyscallValue::AgentPid(p) => p, _ => panic!() };

// 2. Start agent
kernel.dispatch(SyscallRequest {
    agent_pid: pid.clone(),
    operation: MemoryKernelOp::AgentStart,
    payload:   SyscallPayload::Empty,
    reason:    None,
    vakya_id:  None,
});

// 3. Write packet
let result = kernel.dispatch(SyscallRequest {
    agent_pid: pid.clone(),
    operation: MemoryKernelOp::MemWrite,
    payload:   SyscallPayload::MemWrite { packet },
    reason:    Some("Store LLM response".to_string()),
    vakya_id:  Some("vk_8f7a2d".to_string()),
});
let cid = match result.value { SyscallValue::Cid(c) => c, _ => panic!() };
// result.audit_entry is always populated
```
