# Memory Kernel

> MemoryKernel internals, syscall dispatch, agent lifecycle
> Source: `vac/crates/vac-core/src/kernel.rs`

---

## MemoryKernel Internal State

```rust
pub struct MemoryKernel {
    // Agent registry
    agents:             HashMap<String, AgentControlBlock>,
    next_pid:           u64,                    // pid:000001, pid:000002, ...

    // Memory
    packets:            HashMap<Cid, MemPacket>,
    sealed_cids:        HashSet<Cid>,
    namespace_index:    HashMap<String, Vec<Cid>>,  // ns → [cid, ...]
    session_index:      HashMap<String, Vec<Cid>>,  // session_id → [cid, ...]

    // Sessions & contexts
    sessions:           HashMap<String, SessionEnvelope>,
    contexts:           HashMap<String, ExecutionContext>,
    context_snapshots:  HashMap<Cid, ExecutionContext>,

    // Audit
    audit_log:          Vec<KernelAuditEntry>,  // bounded ring buffer, max 100_000
    audit_log_max:      usize,
    audit_overflow:     Vec<KernelAuditEntry>,  // evicted entries pending flush
    audit_overflow_count: u64,
    audit_chain_hash:   Option<String>,         // HMAC chain head
    next_audit_id:      u64,

    // Access control
    access_grants:      HashMap<(String, String), (bool, bool)>,  // (grantee_pid, ns) → (read, write)

    // Ports (Phase 8 hardening)
    ports:              HashMap<String, Port>,
    port_buffers:       HashMap<String, Vec<PortMessage>>,
    next_port_id:       u64,

    // Execution policies & delegation
    execution_policies: HashMap<String, ExecutionPolicy>,
    delegation_chains:  HashMap<String, DelegationChain>,

    // Rate limiting
    rate_limit_windows: HashMap<(String, String), (u32, u32, i64, i64)>,
    // (agent_pid, op_name) → (count_this_second, count_this_minute, second_start_ms, minute_start_ms)
}
```

---

## Syscall Dispatch

Every operation goes through `MemoryKernel::dispatch()`:

```rust
pub fn dispatch(&mut self, req: SyscallRequest) -> SyscallResult {
    // 1. Validate the request (agent exists, operation allowed)
    // 2. Execute the operation
    // 3. Create KernelAuditEntry
    // 4. Append to audit_log (evict oldest if at max)
    // 5. Return SyscallResult { outcome, audit_entry, value }
}
```

**SyscallRequest**:
```rust
pub struct SyscallRequest {
    pub agent_pid:  String,           // "pid:000001" or "system"
    pub operation:  MemoryKernelOp,   // enum variant
    pub payload:    SyscallPayload,   // operation-specific data
    pub reason:     Option<String>,   // human-readable reason for audit
    pub vakya_id:   Option<String>,   // AAPI authorization token ID
}
```

**SyscallResult**:
```rust
pub struct SyscallResult {
    pub outcome:     OpOutcome,         // Success | Denied | Failed
    pub audit_entry: KernelAuditEntry,  // always produced
    pub value:       SyscallValue,      // operation-specific return
}

pub enum SyscallValue {
    None,
    Cid(Cid),                    // MemWrite, ContextSnapshot
    Packet(Box<MemPacket>),      // MemRead
    Packets(Vec<MemPacket>),     // Query
    AgentPid(String),            // AgentRegister
    SessionId(String),           // SessionCreate
    Bool(bool),                  // AccessCheck, IntegrityCheck
    Count(u64),                  // MemEvict, GarbageCollect
    Context(Box<ExecutionContext>), // ContextRestore
    Error(String),               // operation-specific error
}
```

---

## Agent Lifecycle

```
AgentRegister(name, namespace, role, model, framework)
    → assigns pid:NNNNNN
    → creates AgentControlBlock
    → initializes namespace_index[ns] = []
    → audit: AgentRegister, Success

AgentStart(pid)
    → sets ACB.status = Active
    → audit: AgentStart, Success

(agent runs — MemWrite, MemRead, ToolDispatch, etc.)

AgentTerminate(pid, reason)
    → sets ACB.status = Terminated
    → records termination_reason + terminated_at
    → audit: AgentTerminate, Success
```

**AgentControlBlock**:
```rust
pub struct AgentControlBlock {
    pub agent_pid:          String,
    pub agent_name:         String,
    pub namespace:          String,
    pub role:               Option<String>,
    pub model:              Option<String>,
    pub framework:          Option<String>,
    pub status:             AgentStatus,  // Registered | Active | Suspended | Terminated
    pub registered_at:      i64,
    pub terminated_at:      Option<i64>,
    pub termination_reason: Option<String>,
    pub total_packets:      u64,
    pub total_tokens:       u64,
    pub total_cost_usd:     f64,
    pub memory_used_packets: u64,
    pub memory_quota_packets: u64,
    pub active_sessions:    usize,
    pub last_active_at:     i64,
    pub phase:              String,
}
```

---

## PID Format

```
pid:000001   (6-digit zero-padded counter, starts at 1)
pid:000002
...
```

The `"system"` PID is used for kernel-internal operations (AgentRegister called by DualDispatcher).

---

## Audit Log Bounds

- **Max entries**: 100,000 (`audit_log_max`)
- **Overflow**: When full, oldest entries are moved to `audit_overflow` (pending flush to persistent store)
- **Overflow count**: `audit_overflow_count` tracks total evicted entries
- **Chain**: `audit_chain_hash` holds the HMAC of the most recent entry

---

## Integrity Check

```rust
// SyscallPayload::IntegrityCheck
// Verifies:
//   1. All CIDs in packets HashMap match recomputed CIDs
//   2. session_index consistency (all session CIDs exist in packets)
//   3. No duplicate CIDs in namespace_index
// Returns: SyscallValue::Bool(all_ok)
```

---

## Rate Limiting

Per `(agent_pid, operation)` pair, the kernel tracks:
- Count this second + second window start
- Count this minute + minute window start

`ExecutionPolicy` defines per-agent limits. Exceeding limits returns `OpOutcome::Denied`.

---

## Persistence

`MemoryKernel::flush_to_store(store)` — atomic flush:
1. Write all packets to store
2. Write all agents, sessions, audit entries
3. Roll back written packets on any failure

`MemoryKernel::load_from_store(store)` — reconstruct kernel from persisted checkpoint:
- Restores agents, sessions, packets, namespace_index, session_index

`verify_window_chain()` — walks RangeWindow Merkle chain, verifies `rw_root` and `prev_rw_root` linkage.
