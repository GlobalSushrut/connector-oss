# SECURITY_ISOLATION.md — Agent Namespace, Filesystem Isolation & Execution Logic System

> **The one-line definition:**
> "Every agent sees only what it owns or has been explicitly granted. No ambient authority. No namespace leakage. Every access is checked, logged, and auditable."

---

## Table of Contents

1. [Design Philosophy — Why Isolation Is Not Optional](#1-design-philosophy)
2. [Current Implementation Inventory](#2-current-implementation-inventory)
3. [Namespace Architecture — Agent Memory Isolation](#3-namespace-architecture)
4. [Filesystem Isolation — NamespaceMount + MountFilter](#4-filesystem-isolation)
5. [Agent Control Block — The Process Control Block](#5-agent-control-block)
6. [Memory Region — Quota + Protection Flags](#6-memory-region)
7. [Execution Logic System (ELS) — Phase FSM + Role Policies](#7-execution-logic-system)
8. [Tool Isolation — ToolBinding + Default-Deny](#8-tool-isolation)
9. [Delegation Chain — Cryptographic Access Attenuation](#9-delegation-chain)
10. [Port System — Typed Inter-Agent Channels](#10-port-system)
11. [Access Grant/Revoke Lifecycle](#11-access-grant-revoke-lifecycle)
12. [Instruction Plane — Schema-Validated Entry Gate](#12-instruction-plane)
13. [Enhancement Roadmap — What Needs to Be Built Next](#13-enhancement-roadmap)
14. [Integration Map — How All Layers Connect](#14-integration-map)

---

## 1. Design Philosophy

### Why Isolation Is Not Optional

In a multi-agent system — especially one operating in regulated domains (healthcare, finance, legal) — memory isolation is not a performance optimization. It is a **legal and safety requirement**.

Without isolation:
- Agent A can read Agent B's patient records
- A compromised agent can overwrite audit logs
- A tool call can write to any namespace it knows about
- One agent's memory leak becomes all agents' data breach

The isolation model in this system is modeled after real OS kernel design:

| OS Concept | Agent OS Equivalent |
|-----------|---------------------|
| Process address space | Agent namespace (isolated MemPacket store) |
| Page table | Namespace mount table (`namespace_mounts: Vec<NamespaceMount>`) |
| Page protection flags | `MemoryProtection { read, write, execute, share, evict }` |
| Process Control Block | `AgentControlBlock` |
| seccomp-bpf filter | `ExecutionPolicy` (role-based syscall allowlist + phase FSM) |
| Linux bind mounts | `NamespaceMount { source, mount_point, mode, filters }` |
| User groups / RBAC | `AgentRole` (Reader, Writer, Admin, ToolAgent, Auditor, Compactor) |
| Capability objects (Fuchsia) | `CapabilityToken` (UCAN-style delegation, see TOOL_ARCH.md) |

### The Three Isolation Invariants

**Invariant 1 — Namespace Sovereignty**:
> An agent's namespace is exclusively owned. No agent can write to another agent's namespace without an explicit `AccessGrant` syscall issued by the owner.

**Invariant 2 — Default Deny**:
> Every access check fails closed. If the kernel cannot find an explicit grant, mount, or ownership match → `OpOutcome::Denied`. There is no fallback to permissive.

**Invariant 3 — Audit Everything**:
> Every access decision — success AND denial — produces a `KernelAuditEntry`. Denied accesses are logged with reason. The audit log is append-only and cannot be modified by any agent.

---

## 2. Current Implementation Inventory

### What Exists (Coded and Tested)

| Component | Location | Tests | Status |
|-----------|----------|-------|--------|
| `AgentNamespace` | `vac-core/src/types.rs:1169` | — | ✅ Production |
| `AgentControlBlock` | `vac-core/src/types.rs:1254` | 15 Phase 9i tests | ✅ Production |
| `MemoryRegion` + `MemoryProtection` | `vac-core/src/types.rs:1382` | kernel tests | ✅ Production |
| `NamespaceMount` + `MountMode` + `MountFilter` | `vac-core/src/types.rs:1680` | Phase 9a tests | ✅ Production |
| `ToolBinding` + default-deny | `vac-core/src/types.rs:1734` | Phase 9b tests | ✅ Production |
| `ExecutionPolicy` + `AgentPhase` FSM | `vac-core/src/types.rs:1505` | Phase 9d tests | ✅ Production |
| `AgentRole` (6 roles) | `vac-core/src/types.rs:1551` | Phase 9d tests | ✅ Production |
| `RateLimit` + `BudgetPolicy` | `vac-core/src/types.rs:1592` | rate limit tests | ✅ Production |
| `DelegationChain` + `DelegationProof` | `vac-core/src/types.rs` | Phase 9g tests | ✅ Production |
| `AccessGrant`/`AccessRevoke` syscalls | `vac-core/src/kernel.rs:2048` | kernel tests | ✅ Production |
| Mount enforcement in `MemWrite` | `vac-core/src/kernel.rs:983` | Phase 9a tests | ✅ Production |
| Mount enforcement + filter in `MemRead` | `vac-core/src/kernel.rs:1169` | Phase 9a tests | ✅ Production |
| `check_mount_access` helper | `vac-core/src/kernel.rs:2684` | — | ✅ Production |
| `packet_passes_mount_filters` | `vac-core/src/kernel.rs:2696` | Phase 9a tests | ✅ Production |
| `check_tool_binding` (glob matching) | `vac-core/src/kernel.rs:2744` | Phase 9b tests | ✅ Production |
| `InstructionPlane` (schema validation) | `connector-engine/src/instruction.rs` | 12+ tests | ✅ Production |
| Port system (`Port`, `PortBind`, etc.) | `vac-core/src/kernel.rs` | Phase 8 tests | ✅ Production |
| KernelStore for Port/Policy/Chain | `vac-core/src/store.rs` | Phase 9e tests | ✅ Production |

### What Needs Enhancement (see §13)

| Gap | Impact | Priority |
|-----|--------|----------|
| No namespace path canonicalization | Path traversal (`../../admin`) possible in mount source | High |
| No cross-agent namespace leak detection at kernel level | Firewall handles it, kernel doesn't | High |
| No time-to-live (TTL) enforcement on `AccessGrant` | Grants are permanent once issued | Medium |
| Mount write path missing quota debit | Write via ReadWrite mount doesn't charge grantee's quota | Medium |
| No `MountMode::Execute` enforcement in ToolDispatch | Execute mode is defined but not checked in tool dispatch | Medium |
| `DelegationChain.verify()` only checks action patterns | Doesn't verify resource pattern attenuation | Medium |
| No namespace hierarchy enforcement | Parent namespace doesn't auto-restrict child namespace | Low |

---

## 3. Namespace Architecture

### 3.1 Namespace ID Format

Every namespace is identified by a hierarchical path:

```
org:{org_id}/team:{team_id}/agent:{agent_name}
```

Examples:
```
org:acme/team:support/agent:triage
org:hospital-a/dept:cardiology/agent:dr-smith
ns:pipeline-001/agent:summarizer
```

### 3.2 Namespace Hierarchy

```
org:acme/                              ← Organization root (Admin only)
├── team:support/                      ← Team namespace
│   ├── agent:triage/                  ← Agent A's private namespace
│   ├── agent:specialist/              ← Agent B's private namespace
│   └── shared/knowledge/              ← Shared read-only knowledge base
├── team:billing/
│   ├── agent:invoice-processor/
│   └── shared/invoices/
└── shared/global-policies/            ← Org-wide read-only
```

**Key rule**: An agent registered to `org:acme/team:support/agent:triage` owns only that namespace. Anything above or beside it requires an explicit `AccessGrant` or `NamespaceMount`.

### 3.3 `AgentNamespace` Type

```rust
// vac-core/src/types.rs:1169
pub struct AgentNamespace {
    pub namespace_id: String,           // e.g., "org:acme/team:support/agent:triage"
    pub agent_id: String,               // owning agent ID
    pub parent_namespace: Option<String>, // hierarchical parent
    pub readable_namespaces: Vec<String>, // explicit read grants
    pub writable_namespaces: Vec<String>, // explicit write grants
    pub quota_max_packets: u64,         // 0 = unlimited
    pub current_packet_count: u64,
    pub created_at: i64,
}
```

### 3.4 Namespace Access Matrix

At any point, an agent can access a namespace if ONE of the following is true:

```
Access Decision = (
    packet_ns == acb.namespace                           // own namespace
    || acb.writable_namespaces.contains(packet_ns)      // explicit write grant
    || acb.readable_namespaces.contains(packet_ns)      // explicit read grant
    || access_grants.get((agent_pid, packet_ns))         // kernel-issued grant
    || check_mount_access(acb, packet_ns) != None        // mount table
)
```

**All other cases → `OpOutcome::Denied`**

---

## 4. Filesystem Isolation

### 4.1 `NamespaceMount` — The Bind Mount Abstraction

Analogous to Linux `mount --bind /source /mountpoint`, a `NamespaceMount` makes a foreign namespace visible to an agent at a declared `mount_point`, with controlled access:

```rust
// vac-core/src/types.rs:1684
pub struct NamespaceMount {
    pub source: String,        // Real namespace path (e.g., "org:acme/shared/knowledge")
    pub mount_point: String,   // Agent's view path (e.g., "/shared/knowledge")
    pub mode: MountMode,       // ReadOnly | ReadWrite | Execute | Sealed
    pub filters: Vec<MountFilter>, // Restricts which packets are visible
}
```

### 4.2 `MountMode` — Four Access Levels

```rust
pub enum MountMode {
    ReadOnly,   // agent can read packets; cannot write
    ReadWrite,  // agent can read and write packets
    Execute,    // agent can invoke tools bound in this namespace (not read/write packets)
    Sealed,     // read-only + integrity verified on every packet access
}
```

**Enforcement** (implemented in `vac-core/src/kernel.rs`):

| Operation | ReadOnly | ReadWrite | Execute | Sealed |
|-----------|----------|-----------|---------|--------|
| `MemRead` | ✅ Allow | ✅ Allow | ❌ Deny | ✅ Allow + verify |
| `MemWrite` | ❌ Deny | ✅ Allow | ❌ Deny | ❌ Deny |
| `ToolDispatch` | ❌ Deny | ❌ Deny | ✅ Allow | ❌ Deny |

Code path for write enforcement:
```rust
// vac-core/src/kernel.rs:1016-1043
let has_legacy_access = packet_ns == acb.namespace || acb.writable_namespaces.contains(&packet_ns);
let has_mount_access = matches!(
    Self::check_mount_access(acb, &packet_ns),
    Some(MountMode::ReadWrite)   // ReadOnly mount does NOT grant write
);
if !has_legacy_access && !has_mount_access {
    return SyscallResult { outcome: OpOutcome::Denied, ... }
}
```

### 4.3 `MountFilter` — Fine-Grained Visibility Control

A mount can restrict which packets are visible even when access mode is allowed:

```rust
// vac-core/src/types.rs:1712
pub struct MountFilter {
    pub packet_types: Option<Vec<PacketType>>, // Only show Extraction, Decision, etc.
    pub time_range: Option<(i64, i64)>,        // Only show packets in time window
    pub entity_filter: Option<Vec<String>>,    // Only show packets mentioning these entities
    pub tier_filter: Option<Vec<MemoryTier>>,  // Only show Nano/Micro/Small tier packets
    pub max_packets: Option<u64>,              // Cap visibility at N packets
}
```

**Example — Healthcare agent sees only relevant patient packets:**

```rust
NamespaceMount {
    source: "org:hospital/shared/patient-records",
    mount_point: "/shared/patients",
    mode: MountMode::ReadOnly,
    filters: vec![
        MountFilter {
            packet_types: Some(vec![PacketType::Extraction]),
            entity_filter: Some(vec!["patient:P-847".to_string()]),  // only this patient
            time_range: Some((session_start, session_end)),            // only this session
            tier_filter: None,
            max_packets: Some(500),
        }
    ]
}
```

### 4.4 Filter Evaluation Logic

```rust
// vac-core/src/kernel.rs:2696
fn packet_passes_mount_filters(packet: &MemPacket, mount: &NamespaceMount) -> bool {
    for filter in &mount.filters {
        // PacketType filter: packet type must be in the allowlist
        if let Some(ref types) = filter.packet_types {
            if !types.contains(&packet.content.packet_type) { return false; }
        }
        // TimeRange filter: packet timestamp must be in [from, to]
        if let Some((from, to)) = filter.time_range {
            let ts = packet.index.ts;
            if ts < from || ts > to { return false; }
        }
        // Entity filter: at least one declared entity must match (glob-aware)
        if let Some(ref entities) = filter.entity_filter {
            let has_match = entities.iter().any(|ef| {
                if ef.ends_with('*') {
                    packet.content.entities.iter().any(|pe| pe.starts_with(&ef[..ef.len()-1]))
                } else {
                    packet.content.entities.contains(ef)
                }
            });
            if !has_match && !packet.content.entities.is_empty() { return false; }
        }
        // Tier filter: packet memory tier must be in the allowlist
        if let Some(ref tiers) = filter.tier_filter {
            if !tiers.contains(&packet.tier) { return false; }
        }
    }
    true
}
```

### 4.5 Mount Lookup Algorithm

```
check_mount_access(acb, target_namespace):
  for mount in acb.namespace_mounts:
    if target_namespace == mount.source
    OR target_namespace.starts_with(mount.source + "/"):
      return Some(mount.mode)
  return None   ← no mount covers this namespace
```

This means mounts are **prefix-based** — mounting `org:acme/shared` automatically covers `org:acme/shared/knowledge`, `org:acme/shared/policies`, etc.

---

## 5. Agent Control Block

The `AgentControlBlock` (ACB) is the central per-agent data structure in the kernel. Every agent registered via `AgentRegister` syscall gets one. It is the Agent OS equivalent of Linux's `task_struct` / Windows `EPROCESS`.

```rust
// vac-core/src/types.rs:1254
pub struct AgentControlBlock {
    // ── Identity ────────────────────────────────────────────────────
    pub agent_pid: String,           // e.g., "pid:acme:triage:001"
    pub agent_name: String,          // human-readable
    pub agent_role: Option<String>,  // e.g., "clinical-triage"
    pub status: AgentStatus,         // lifecycle state

    // ── Memory Isolation ────────────────────────────────────────────
    pub namespace: String,           // agent's owned namespace
    pub memory_region: MemoryRegion, // quota + protection flags
    pub readable_namespaces: Vec<String>,  // explicit read grants
    pub writable_namespaces: Vec<String>,  // explicit write grants

    // ── Capability Control ──────────────────────────────────────────
    pub capabilities: Vec<String>,   // AAPI capability refs held
    pub allowed_tools: Vec<String>,  // deprecated (replaced by tool_bindings)

    // ── Phase 8 Kernel Hardening ────────────────────────────────────
    pub phase: AgentPhase,           // FSM state: Registered→Active→Suspended...
    pub role: AgentRole,             // Reader|Writer|Admin|ToolAgent|Auditor|Compactor
    pub namespace_mounts: Vec<NamespaceMount>, // mount table (bind mounts)
    pub tool_bindings: Vec<ToolBinding>,       // capability-scoped tool access
    ...
}
```

### 5.1 Agent Lifecycle (Status FSM)

```
Registered ─→ Running ─→ Suspended ─→ Running (resume)
                │               │
                └─→ Waiting ────┘
                │
                ├─→ Completed  (normal exit)
                ├─→ Failed     (error exit)
                └─→ Terminated (kernel/operator killed)
```

### 5.2 Agent Phase FSM (ExecutionPolicy enforcement)

The `AgentPhase` is separate from `AgentStatus` — it controls which syscalls are VALID at any moment:

```
Registered: only AgentStart allowed
Active:     MemWrite, MemRead, SessionCreate, ContextSave/Load, ToolDispatch, PortCreate/Send/Receive
Suspended:  only AgentResume or AgentTerminate allowed
ReadOnly:   only MemRead, AccessCheck, IntegrityCheck (auditor/sealed mode)
Terminating: only AgentTerminate allowed
```

---

## 6. Memory Region

Every agent's ACB contains a `MemoryRegion` — the allocated "virtual address space" for that agent's memory.

```rust
// vac-core/src/types.rs:1386
pub struct MemoryRegion {
    pub namespace: String,
    pub quota_packets: u64,     // max MemPackets (0 = unlimited)
    pub quota_tokens: u64,      // max LLM tokens (0 = unlimited)
    pub quota_bytes: u64,       // max storage bytes (0 = unlimited)
    pub used_packets: u64,      // current packet count
    pub used_tokens: u64,       // current token count
    pub used_bytes: u64,        // current byte usage
    pub protection: MemoryProtection,
    pub eviction_policy: EvictionPolicy,
    pub sealed: bool,           // if true, no further writes allowed
}
```

### 6.1 `MemoryProtection` Flags

```rust
// vac-core/src/types.rs:1448
pub struct MemoryProtection {
    pub read: bool,              // can read packets from this region
    pub write: bool,             // can write new packets
    pub execute: bool,           // can execute tool calls using data from this region
    pub share: bool,             // can share packets to other agents (via Port)
    pub evict: bool,             // can delete/evict packets (LRU, GC, etc.)
    pub requires_approval: bool, // every write needs human approval
}
```

Default: `read=true, write=true, execute=true, share=false, evict=true, requires_approval=false`

### 6.2 Eviction Policies

| Policy | When to Use | Behavior |
|--------|-------------|----------|
| `Lru` | General agents | Evict least-recently-accessed packets first |
| `Fifo` | Streaming agents | Evict in creation order (sliding window) |
| `Ttl` | Session-scoped agents | Evict packets older than TTL |
| `Priority` | Trust-tiered systems | Evict lowest-trust-tier packets first |
| `SummarizeEvict` | Long-running agents | Compress + summarize before eviction (MemGPT pattern) |
| `Never` | Compliance/audit agents | Fail on quota exceeded — never silently lose data |

### 6.3 Quota Enforcement

```rust
// vac-core/src/kernel.rs:1046-1082
// Check region capacity
if !acb.memory_region.has_capacity() {
    return SyscallResult { outcome: OpOutcome::Denied, ... "Region at capacity" }
}
// Check write protection
if !acb.memory_region.protection.write {
    return SyscallResult { outcome: OpOutcome::Denied, ... "Write-protected" }
}
```

---

## 7. Execution Logic System (ELS)

### 7.1 Overview

The ELS is the kernel's equivalent of Linux `seccomp-bpf` — a per-role policy that defines which syscalls are allowed, under what rate limits, with what budget constraints, and what phase transitions are valid.

### 7.2 `AgentRole` — Six Default Roles

```rust
// vac-core/src/types.rs:1555
pub enum AgentRole {
    Reader,    // Read-only: only MemRead, AccessCheck, IntegrityCheck
    Writer,    // Default: MemRead + MemWrite + Session ops
    Admin,     // Full access to all syscalls
    ToolAgent, // Reader + Writer + ToolDispatch, rate-limited
    Auditor,   // ReadOnly mode: MemRead + audit exports
    Compactor, // Memory management: GC, evict, promote, demote
    Custom(String), // Explicit allowlist
}
```

### 7.3 `ExecutionPolicy` — Per-Role Syscall Policy

```rust
// vac-core/src/types.rs:1650
pub struct ExecutionPolicy {
    pub role: AgentRole,
    pub allowed_ops: Vec<MemoryKernelOp>,    // syscall whitelist
    pub phase_transitions: Vec<PhaseTransition>, // valid FSM transitions
    pub rate_limits: BTreeMap<String, RateLimit>, // per-op rate limits
    pub budget: BudgetPolicy,
}
```

### 7.4 Predefined Role Policies (Phase 9d)

**Reader Role**:
```
allowed_ops: [MemRead, AccessCheck, IntegrityCheck, AgentStart, AgentTerminate]
rate_limits: { MemRead: 1000/min }
budget: { max_packets_per_minute: 0, enforce: false }
```

**Writer Role** (default):
```
allowed_ops: [MemRead, MemWrite, SessionCreate, SessionEnd, ContextSave,
              ContextLoad, AgentStart, AgentSuspend, AgentResume, AgentTerminate]
rate_limits: { MemWrite: 500/min, MemRead: 1000/min }
budget: { max_packets_per_minute: 500, enforce: true }
```

**Admin Role**:
```
allowed_ops: ALL
rate_limits: { default: 10000/min }
budget: { enforce: false }
```

**ToolAgent Role**:
```
allowed_ops: [MemRead, MemWrite, ToolDispatch, SessionCreate, SessionEnd,
              PortCreate, PortBind, PortSend, PortReceive]
rate_limits: { ToolDispatch: 60/min, MemWrite: 200/min }
budget: { max_tool_calls_per_session: 100, enforce: true }
```

**Auditor Role** (read-only):
```
allowed_ops: [MemRead, AccessCheck, IntegrityCheck]
phase_constraint: ReadOnly phase only
rate_limits: { MemRead: 10000/min }
```

**Compactor Role**:
```
allowed_ops: [MemRead, MemEvict, GarbageCollect, ContextSave]
rate_limits: { MemEvict: 1000/min }
```

### 7.5 `RateLimit` + `BudgetPolicy`

```rust
pub struct RateLimit {
    pub max_per_second: u32,   // token bucket fill rate
    pub max_per_minute: u32,   // rolling window limit
    pub max_burst: u32,        // burst headroom above steady-state
}

pub struct BudgetPolicy {
    pub max_tokens_per_session: u64,      // LLM token cap
    pub max_cost_per_session_usd: f64,    // spend cap
    pub max_packets_per_minute: u32,      // write throughput cap
    pub max_tool_calls_per_session: u32,  // tool call cap
    pub enforce: bool,                    // if false: warn-only mode
}
```

---

## 8. Tool Isolation

### 8.1 Default-Deny Tool Model

The tool system uses **default-deny**: an agent cannot call ANY tool unless there is an explicit `ToolBinding` in its ACB that covers:
1. The `tool_id` (exact match or glob)
2. The `action` being performed (exact match or glob)
3. The `resource` being accessed (exact match or glob)

```rust
// vac-core/src/kernel.rs:2744
fn check_tool_binding(acb: &AgentControlBlock, tool_id: &str, action: &str) -> bool {
    acb.tool_bindings.iter().any(|b| {
        let tool_match = if b.tool_id == tool_id { true }
            else if b.tool_id.ends_with('*') {
                tool_id.starts_with(&b.tool_id[..b.tool_id.len()-1])
            } else { false };
        if !tool_match { return false; }
        if b.allowed_actions.is_empty() { return true; } // no action restriction
        b.allowed_actions.iter().any(|a| {
            a == "*" || a == action ||
            (a.ends_with('*') && action.starts_with(&a[..a.len()-1]))
        })
    })
}
```

### 8.2 `ToolBinding` Structure

```rust
// vac-core/src/types.rs:1739
pub struct ToolBinding {
    pub tool_id: String,              // "ehr.read_patient" or "ehr.*"
    pub namespace_path: String,       // where this tool is "mounted": "/tools/ehr"
    pub allowed_actions: Vec<String>, // ["ehr.read_*"] — glob-matched
    pub allowed_resources: Vec<String>,// ["patient:*"] — glob-matched
    pub rate_limit: Option<RateLimit>,// per-tool rate limit (overrides role default)
    pub data_classification: String,  // "phi", "pii", "public", "internal"
    pub requires_approval: bool,      // if true → human must approve each call
}
```

### 8.3 Tool Dispatch Flow

```
agent calls ToolDispatch syscall
  │
  ▼
kernel.check_tool_binding(acb, tool_id, action)
  ├── No binding found → OpOutcome::Denied (default-deny)
  └── Binding found → continue
        │
        ▼
  Check requires_approval
  ├── true → OpOutcome::Skipped (waiting for HITL)
  └── false → execute
        │
        ▼
  Rate limit check (per binding rate_limit or role default)
  ├── Exceeded → OpOutcome::Denied
  └── OK → OpOutcome::Success + dispatch
```

### 8.4 Example Tool Bindings — Hospital Agent

```rust
// Triage agent: can read any patient record, can't write
ToolBinding {
    tool_id: "ehr.read_*",
    namespace_path: "/tools/ehr/read",
    allowed_actions: vec!["ehr.read_vitals", "ehr.read_history", "ehr.read_allergy"],
    allowed_resources: vec!["patient:*"],
    rate_limit: Some(RateLimit { max_per_second: 10, max_per_minute: 100, max_burst: 5 }),
    data_classification: "phi".to_string(),
    requires_approval: false,
}

// Prescription agent: requires human approval on every write
ToolBinding {
    tool_id: "ehr.write_prescription",
    namespace_path: "/tools/ehr/write",
    allowed_actions: vec!["ehr.write_prescription"],
    allowed_resources: vec!["patient:*"],
    rate_limit: Some(RateLimit { max_per_second: 1, max_per_minute: 10, max_burst: 1 }),
    data_classification: "phi".to_string(),
    requires_approval: true,  // EVERY prescription needs doctor approval
}
```

---

## 9. Delegation Chain

### 9.1 UCAN-Style Cryptographic Delegation

The `DelegationChain` implements UCAN-style capability delegation where:
- Each proof in the chain is signed with Ed25519
- Child delegations can only NARROW (attenuate) capabilities, never AMPLIFY
- The chain must be verified before any delegated access is permitted

```rust
pub struct DelegationChain {
    pub proofs: Vec<DelegationProof>,
    pub chain_cid: String,    // CID of the whole chain
}

pub struct DelegationProof {
    pub proof_cid: String,
    pub issuer: String,             // "user:alice" or "agent:triage"
    pub subject: String,            // "agent:specialist"
    pub allowed_actions: Vec<String>, // ["ehr.read_*"] — glob patterns
    pub allowed_resources: Vec<String>,
    pub expires_at: i64,             // Unix ms
    pub parent_proof_cid: Option<String>,
    pub signature: Option<String>,   // Ed25519 over canonical JSON (ex. signature field)
    pub issued_at: i64,
    pub revoked: bool,
}
```

### 9.2 Attenuation Verification

The kernel enforces attenuation: a child proof cannot grant actions not covered by the parent:

```rust
// If child says "ehr.write_allergy" but parent only allowed "ehr.read_*"
// → chain.verify(now) returns Err("not covered by parent")
```

Test (Phase 9g):
```rust
// vac-core/src/kernel.rs:5087
fn test_delegation_chain_attenuation_violation() {
    // Parent allows: ["ehr.read_*"]
    // Child attempts: ["ehr.write_allergy"] ← not covered
    let result = chain.verify(now);
    assert!(result.unwrap_err().contains("not covered by parent"));
}
```

### 9.3 Ed25519 Signing

```rust
// DelegationChain::sign_proof() and verify_signatures()
// Signs canonical JSON excluding the signature field
// Uses ed25519-dalek + rand (added to vac-core Cargo.toml in Phase 9g)
```

---

## 10. Port System

### 10.1 Typed Inter-Agent Communication Channels

Ports are the agent OS equivalent of Unix domain sockets or named pipes — they provide isolated, typed, permission-controlled channels between agents.

```rust
pub struct Port {
    pub port_id: String,
    pub port_type: PortType,              // Pipeline | Broadcast | Unicast | Control
    pub owner_pid: String,                // who created this port
    pub bound_pids: Vec<String>,          // who can receive on this port
    pub direction: PortDirection,         // Inbound | Outbound | Bidirectional
    pub allowed_packet_types: Vec<PacketType>, // only these packet types can transit
    pub allowed_actions: Vec<String>,     // only these actions can be performed
    pub max_delegation_depth: u8,         // how deep the delegation chain can go
    pub expires_at: Option<i64>,          // TTL for the port
    pub closed: bool,
}
```

### 10.2 Port Lifecycle

```
PortCreate (owner) → PortBind (bind target agent) → PortSend (owner or bound) → PortReceive (bound agent)
                  → PortDelegate (attenuated sub-delegation) → PortClose (owner)
```

### 10.3 Port Expiry Enforcement (Phase 9c)

Every `PortSend`, `PortReceive`, `PortBind` operation checks TTL:

```rust
if let Some(expires_at) = port.expires_at {
    if Self::now_ms() > expires_at && !port.closed {
        port.closed = true;
        return SyscallResult { outcome: OpOutcome::Denied, ... "Port expired" }
    }
}
```

### 10.4 Why Ports Not Shared Memory

Shared memory (allowing agents to directly read/write each other's namespaces) creates ambient authority. Ports force **explicit, typed, audited data transfer**:

- Every message through a port is a `PortMessage` — logged in the audit trail
- Port constraints (`allowed_packet_types`, `allowed_actions`) are enforced at kernel level
- Delegation depth limits prevent unbounded capability chains

---

## 11. Access Grant/Revoke Lifecycle

### 11.1 `AccessGrant` Syscall

The only way for Agent A to gain access to Agent B's namespace is via the `AccessGrant` syscall — which ONLY Agent B (the namespace owner) can issue:

```
Agent B (owner) issues: AccessGrant {
    target_namespace: "ns:B",
    grantee_pid: "pid:A",
    read: true,
    write: false,    // read-only grant
}

kernel validates:
  acb_B.namespace == "ns:B" OR acb_B.writable_namespaces.contains("ns:B")
  → if passes: stores grant, updates acb_A.readable_namespaces
  → if fails: OpOutcome::Denied "Only namespace owner can grant access"
```

Code: `vac-core/src/kernel.rs:2048-2130`

### 11.2 `AccessRevoke` Syscall

Grants can be revoked at any time by the owner:

```
Agent B issues: AccessRevoke { target_namespace: "ns:B", grantee_pid: "pid:A" }

kernel:
  removes grant from access_grants HashMap
  removes "ns:B" from acb_A.readable_namespaces + writable_namespaces
```

Code: `vac-core/src/kernel.rs:2132-2186`

### 11.3 Enhancement Needed: Grant TTL

Currently grants are permanent. Enhancement (see §13): add `expires_at: Option<i64>` to `AccessGrant` payload so grants automatically expire.

---

## 12. Instruction Plane

The `InstructionPlane` sits BETWEEN the firewall and the kernel dispatcher. It validates every instruction against a registered schema before it reaches the kernel.

```
External Input → AgentFirewall (injection check) → InstructionPlane (schema) → DualDispatcher → Kernel
```

### 12.1 Four-Layer Gate

Every instruction passes through 4 checks in order:

```
1. Action unknown? → BLOCKED (UnknownAction)
2. Source type not allowed? → BLOCKED (SourceBlocked)
3. Actor's role not in allowed_roles? → BLOCKED (RoleDenied)
4. Required params missing? → BLOCKED (MissingParam)
4. Param type mismatch? → BLOCKED (TypeMismatch)
5. Unknown param (strict mode)? → BLOCKED (UnknownParam)
```

Only after all 5 pass → `ValidationResult::valid = true`

### 12.2 SourceConstraint

```rust
pub enum SourceConstraint {
    RegisteredOnly,                          // only actors registered via register_actor()
    AllowExternal { client_ids: Vec<String> }, // specific external clients allowed
    SystemOnly,                               // kernel-generated only
    Any,                                      // no restriction (dangerous)
}
```

### 12.3 Standard Schema Set (10 Schemas)

| Action | Domain | Verb | Roles | Source |
|--------|--------|------|-------|--------|
| `memory.write` | memory | write | writer, admin | RegisteredOnly |
| `memory.read` | memory | read | reader, writer, admin, auditor | RegisteredOnly |
| `memory.seal` | memory | seal | admin | RegisteredOnly |
| `knowledge.query` | knowledge | query | reader, writer, admin | RegisteredOnly |
| `knowledge.ingest` | knowledge | ingest | writer, admin | RegisteredOnly |
| `knowledge.seed` | knowledge | seed | admin | RegisteredOnly |
| `chat.send` | chat | send | writer, admin | RegisteredOnly |
| `chat.receive` | chat | receive | reader, writer, admin | RegisteredOnly |
| `tool.call` | tool | call | writer, admin, tool_agent | RegisteredOnly |
| `tool.register` | tool | register | admin | RegisteredOnly |

---

## 13. Enhancement Roadmap

### 13.1 High Priority — Namespace Path Security

**Gap**: No canonicalization of namespace paths. An attacker could craft:
`source: "org:acme/team:support/../../billing/invoices"` — traversal attack.

**Fix needed** in `NamespaceMount` validation:
```rust
fn canonicalize_namespace_path(path: &str) -> Result<String, IsolationError> {
    // 1. Reject any component containing ".."
    if path.split('/').any(|c| c == "..") {
        return Err(IsolationError::PathTraversal(path.to_string()));
    }
    // 2. Normalize multiple slashes
    // 3. Validate format: org:{id}/team:{id}/agent:{id}
    Ok(path.to_string())
}
```

### 13.2 High Priority — AccessGrant TTL

**Gap**: Grants are permanent. A compromised agent's grant lives forever.

**Fix needed** in `SyscallPayload::AccessGrant`:
```rust
// Add to AccessGrant payload:
pub expires_at: Option<i64>,   // None = permanent (current behavior preserved)
```

And in `handle_mem_read` / `handle_mem_write`:
```rust
// Check grant TTL
if let Some((read, write, expires_at)) = access_grants.get((agent_pid, ns)) {
    if let Some(exp) = expires_at {
        if now_ms() > exp { return Err("Grant expired"); }
    }
}
```

### 13.3 Medium Priority — Execute Mode in ToolDispatch

**Gap**: `MountMode::Execute` is defined but `handle_tool_dispatch` doesn't check it.

**Fix needed** in `handle_tool_dispatch`:
```rust
// Before check_tool_binding, also check: does the agent have an Execute mount
// for the tool's namespace_path?
let has_execute_mount = Self::check_mount_access(acb, &binding.namespace_path)
    == Some(MountMode::Execute);
```

### 13.4 Medium Priority — Quota Debit for Mount Writes

**Gap**: When Agent A writes to namespace B via a `ReadWrite` mount, the packet count is debited to Agent B's quota but Agent A's quota is not checked.

**Fix needed**: Debit both grantee and source agent quotas on cross-namespace writes.

### 13.5 Medium Priority — Resource Pattern Attenuation in DelegationChain

**Gap**: `DelegationChain.verify()` checks action glob patterns but does NOT verify resource pattern attenuation.

**Fix needed**:
```rust
// Child's allowed_resources must be subset/narrowing of parent's
fn resources_attenuate(parent: &[String], child: &[String]) -> bool {
    child.iter().all(|cr| {
        parent.iter().any(|pr| glob_covers(pr, cr))
    })
}
```

### 13.6 Low Priority — Namespace Hierarchy Auto-Restriction

**Gap**: An agent registered to `org:acme/team:support/agent:triage` can be granted access to `org:acme/team:billing/invoices` — a cross-team grant that an org-level policy should be able to prevent.

**Fix needed**: `OrgPolicy` struct that sets maximum cross-team grant permissions. Add org-level policy check to `handle_access_grant`.

---

## 14. Integration Map

How all isolation layers connect in a memory write operation:

```
Agent calls remember("patient data", ...)
  │
  ▼ connector-engine/src/dispatcher.rs:312
AgentFirewall.score_memory_write(content, agent_pid, owned_ns)
  ├── injection check → Block if score >= 0.8
  ├── PII check → Warn if PII detected
  ├── cross_boundary check → Block if namespace doesn't belong to agent
  └── Allow → continue
  │
  ▼
BehaviorAnalyzer.record_action(agent_pid, "memory.write", bytes)
  ├── frequency check → Alert if too many writes
  ├── data volume check → Alert if exfiltration pattern
  └── baseline deviation check → Alert if drift detected
  │
  ▼
InstructionPlane.validate(Instruction { action: "memory.write", ... })
  ├── schema check → Block if no "memory.write" schema registered
  ├── source check → Block if external source
  ├── role check → Block if role ∉ [writer, admin]
  └── param type check → Block if "content" not string
  │
  ▼
DualDispatcher → kernel.dispatch(SyscallRequest { MemWrite, ... })
  │
  ▼ vac-core/src/kernel.rs:983
MemoryKernel.handle_mem_write()
  ├── ExecutionPolicy check → Is MemWrite in allowed_ops for this role?
  ├── AgentPhase check → Is agent in Active phase?
  ├── Namespace ownership check:
  │   ├── Own namespace? → Allow
  │   ├── In writable_namespaces? → Allow
  │   ├── ReadWrite mount covers target? → Allow
  │   └── None of above → OpOutcome::Denied (audit entry written)
  ├── MemoryRegion.has_capacity()? → Deny if sealed or over quota
  ├── MemoryProtection.write? → Deny if write-protected
  ├── MemoryProtection.requires_approval? → Defer if HITL required
  │
  ▼ Success path
Compute CID(packet)                     ← content-addressed
Store packet in namespace_index
Debit acb.memory_region.used_packets
Write KernelAuditEntry                  ← immutable audit record
  │
  ▼
Return SyscallResult { Success, packet_cid }
  │
  ▼ connector-engine
connector-engine links packet to AAPI ActionRecord
connector-engine updates ExecutionContract (see TOOL_ARCH.md)
```

Every step is independently tested. Every denial is independently audited. No step can be bypassed.

---

## Appendix A: Isolation Check Cheatsheet

| Scenario | Check | Code Location |
|----------|-------|--------------|
| Agent writes to own namespace | `packet_ns == acb.namespace` | `kernel.rs:1019` |
| Agent writes via explicit grant | `acb.writable_namespaces.contains(ns)` | `kernel.rs:1019` |
| Agent writes via mount | `check_mount_access == ReadWrite` | `kernel.rs:1020` |
| Agent reads via mount + filter | `packet_passes_mount_filters(packet, mount)` | `kernel.rs:2696` |
| Agent calls tool | `check_tool_binding(acb, tool_id, action)` | `kernel.rs:2744` |
| Agent reads with grant | `access_grants.get((agent_pid, ns))` | `kernel.rs:1220` |
| Agent issues cross-namespace grant | `acb.namespace == target_namespace` | `kernel.rs:2081` |
| Delegation attenuation | `child_actions ⊆ parent_actions` | `types.rs` (DelegationChain) |
| Phase FSM violation | `allowed_ops.contains(op)` | `kernel.rs` (ELS) |
| Rate limit exceeded | rolling window count vs max | `kernel.rs` |
| Memory quota exceeded | `acb.memory_region.has_capacity()` | `kernel.rs:1046` |
| Instruction schema missing | `schemas.get(action) == None` | `instruction.rs:367` |
| External source on internal schema | `source.is_external() + RegisteredOnly` | `instruction.rs:385` |

*Research sources: seL4 capability model, Fuchsia Zircon component framework, Linux namespace isolation, AIOS kernel architecture (COLM 2025), UCAN delegation spec, OWASP Agentic AI Top 10, NIST AI RMF*
