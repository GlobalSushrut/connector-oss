# Namespace Isolation

> Namespace ACLs, AccessGrant/Revoke, port system
> Source: `vac/crates/vac-core/src/kernel.rs`

---

## Model

Each agent owns exactly one namespace: `ns:<agent_name>`. The kernel enforces:

- **Write**: only the owning agent can write to its namespace
- **Read**: only the owning agent can read its namespace — unless an `AccessGrant` exists
- **No implicit sharing**: agents are isolated by default

```
Kernel Memory
  ├── ns:triage      [owner: pid:000001]
  │     ├── CID bafyrei...  (input packet)
  │     └── CID bafyrei...  (LLM response)
  │
  ├── ns:diagnosis   [owner: pid:000002]
  │     └── CID bafyrei...  (diagnosis response)
  │
  ├── ns:treatment   [owner: pid:000003]
  │     └── CID bafyrei...  (treatment plan)
  │
  └── ns:audit       [owner: pid:000004]
        └── (reads from others via explicit grants)
```

---

## AccessGrant

```rust
// Grant read access from ns:triage to pid:000002 (diagnosis agent)
kernel.dispatch(SyscallRequest {
    agent_pid: "pid:000001",  // must be the namespace owner
    operation: MemoryKernelOp::AccessGrant,
    payload: SyscallPayload::AccessGrant {
        target_namespace: "ns:triage".to_string(),
        grantee_pid:      "pid:000002".to_string(),
        read:  true,
        write: false,
    },
    reason:   Some("Allow diagnosis to read triage data".to_string()),
    vakya_id: None,
});
// → audit: AccessGrant, Success
```

**Storage**: `access_grants: HashMap<(grantee_pid, namespace), (read, write)>`

---

## AccessRevoke

```rust
kernel.dispatch(SyscallRequest {
    agent_pid: "pid:000001",
    operation: MemoryKernelOp::AccessRevoke,
    payload: SyscallPayload::AccessRevoke {
        target_namespace: "ns:triage".to_string(),
        grantee_pid:      "pid:000002".to_string(),
    },
    ..
});
// → audit: AccessRevoke, Success
// → (pid:000002, ns:triage) removed from access_grants
```

---

## AccessCheck

```rust
let result = kernel.dispatch(SyscallRequest {
    agent_pid: "pid:000002",
    operation: MemoryKernelOp::AccessCheck,
    payload: SyscallPayload::AccessCheck {
        target_namespace: "ns:triage".to_string(),
        operation: "read".to_string(),
    },
    ..
});
// SyscallValue::Bool(true)  — if grant exists
// SyscallValue::Bool(false) — if no grant
```

---

## What Happens Without a Grant

```
pid:000002 tries to read CID from ns:triage (no grant):
  → MemRead returns OpOutcome::Denied
  → audit: MemRead, Denied, "Agent pid:000002 lacks read access to ns:triage"
  → SyscallValue::Error("Agent pid:000002 lacks read access to ns:triage")
```

This is logged in the audit trail as a `Denied` entry — visible in `audit_tail()` output.

---

## Port System

Ports provide typed, capability-controlled communication channels between agents.

### PortCreate

```rust
SyscallPayload::PortCreate {
    port_type:             PortType,       // MemoryShare | ToolDelegate | EventStream |
                                           // RequestResponse | Broadcast | Pipeline
    direction:             PortDirection,  // Inbound | Outbound | Bidirectional
    allowed_packet_types:  Vec<PacketType>,
    allowed_actions:       Vec<String>,
    max_delegation_depth:  u8,
    ttl_ms:                Option<u64>,
}
```

### PortBind

Connects a port to a target agent:
```rust
SyscallPayload::PortBind { port_id, target_pid }
```

### PortDelegate

Sub-delegates a port capability with attenuation (can only restrict, never expand):
```rust
SyscallPayload::PortDelegate {
    port_id:         String,
    delegate_to:     String,       // target agent PID
    allowed_actions: Vec<String>,  // subset of original allowed_actions
}
```

`max_delegation_depth` prevents unbounded delegation chains. Default: 3.

---

## Execution Policies

Per-agent execution policies control rate limits and budget:

```rust
pub struct ExecutionPolicy {
    pub role:                  String,
    pub max_ops_per_second:    u32,
    pub max_ops_per_minute:    u32,
    pub max_memory_packets:    u64,
    pub max_token_budget:      u64,
    pub allowed_operations:    Vec<MemoryKernelOp>,
    pub denied_operations:     Vec<MemoryKernelOp>,
}
```

---

## Delegation Chains

```rust
pub struct DelegationChain {
    pub chain_id:    String,
    pub hops:        Vec<DelegationHop>,
    pub root_issuer: String,
    pub depth:       u8,
}

pub struct DelegationHop {
    pub from:        String,   // delegating agent PID
    pub to:          String,   // receiving agent PID
    pub capability:  String,
    pub signature:   Vec<u8>,  // Ed25519 signature
    pub issued_at:   i64,
    pub expires_at:  Option<i64>,
}
```

Cross-cell capability verification (`aapi-federation::CrossCellCapabilityVerifier`) walks the full `DelegationHop` chain and verifies each Ed25519 signature.
