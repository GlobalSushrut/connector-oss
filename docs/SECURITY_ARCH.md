# SECURITY_ARCH.md — Security & Isolation as One System

> **"Every agent sees only what it owns or has been explicitly granted. Every access is checked, logged, and auditable. No ambient authority. No bypass."**

---

## The 12 Security Components

| # | Component | Purpose | Location |
|---|-----------|---------|----------|
| 1 | **AgentNamespace** | Isolated memory space per agent | `vac-core/types.rs` |
| 2 | **AgentControlBlock (ACB)** | Per-agent process control block (Linux `task_struct`) | `vac-core/types.rs` |
| 3 | **MemoryRegion** | Quota + protection flags per agent | `vac-core/types.rs` |
| 4 | **NamespaceMount** | Controlled cross-namespace visibility (Linux `bind mount`) | `vac-core/types.rs` |
| 5 | **ExecutionPolicy + AgentPhase** | Role-based syscall allowlist + phase FSM (Linux `seccomp`) | `vac-core/types.rs` |
| 6 | **ToolBinding** | Default-deny capability-scoped tool access | `vac-core/types.rs` |
| 7 | **DelegationChain** | UCAN-style cryptographic access attenuation (Ed25519) | `vac-core/types.rs` |
| 8 | **AccessGrant / AccessRevoke** | Explicit namespace sharing between agents | `vac-core/kernel.rs` |
| 9 | **Port System** | Typed, audited inter-agent communication channels | `vac-core/kernel.rs` |
| 10 | **AgentFirewall** | Weighted threat scorer (MAESTRO 7-layer, OWASP LLM Top 10) | `connector-engine/firewall.rs` |
| 11 | **BehaviorAnalyzer** | Runtime anomaly detection (6 algorithms) | `connector-engine/firewall.rs` |
| 12 | **InstructionPlane** | Schema-validated entry gate (default-deny) | `connector-engine/instruction.rs` |

---

## How They Work Together — The 4-Layer Security Gate

Every operation passes through **4 gates in order**. All must pass. Any denial stops the operation.

```
External Input (SDK call, protocol bridge, agent request)
  │
  ▼ GATE 1 — AgentFirewall [10]
  │
  ├── injection_score(text) → 18 lexical patterns + semantic (future)
  ├── pii_score(text) → SSN, CC, MRN, Email, Phone + 5 more (future)
  ├── cross_boundary_check(namespace, agent_pid)
  ├── rate_pressure(calls_per_minute)
  ├── anomaly_score(from BehaviorAnalyzer [11])
  │
  │   Weighted sum = Σ(signal × weight)
  │   < 0.30 → Allow
  │   0.30-0.60 → Warn (log, continue)
  │   0.60-0.80 → Review (flag for human)
  │   > 0.80 → Block
  │   injection >= 0.5 + block_injection_by_default → Block
  │
  ▼ GATE 2 — BehaviorAnalyzer [11]
  │
  ├── record_action(agent_pid, action, bytes)
  ├── frequency check → spike above baseline?
  ├── data_volume check → exfiltration pattern? (>10MB/window)
  ├── tool_diversity check → scope drift? (>10 unique tools)
  ├── error_rate check → probing? (>30% errors)
  ├── behavioral_drift → deviation from established baseline?
  │
  ▼ GATE 3 — InstructionPlane [12]
  │
  ├── Action known? → Block if UnknownAction
  ├── Source type allowed? → Block if SourceBlocked
  ├── Actor role in allowed_roles? → Block if RoleDenied
  ├── Required params present? → Block if MissingParam
  ├── Param types correct? → Block if TypeMismatch
  │
  │   10 standard schemas: memory.write, memory.read, memory.seal,
  │   knowledge.query, knowledge.ingest, knowledge.seed,
  │   chat.send, chat.receive, tool.call, tool.register
  │
  ▼ GATE 4 — MemoryKernel (Execution Logic System)
  │
  ├── ExecutionPolicy [5]: Is this op in allowed_ops for agent's role?
  ├── AgentPhase [5]: Is agent in correct phase for this op?
  ├── Namespace check [1]: Does agent own target namespace?
  │   ├── Own namespace? → Allow
  │   ├── In writable_namespaces? → Allow
  │   ├── AccessGrant [8] exists? → Allow (check TTL)
  │   ├── NamespaceMount [4] covers target? → Allow (check mode)
  │   └── None → Denied
  ├── MemoryRegion [3]: Has capacity? Write-protected? Sealed?
  ├── ToolBinding [6]: Tool allowed? Action allowed? Resource allowed?
  │
  ▼ SUCCESS → Execute + Audit
  │
  Compute CID(packet)
  Store in namespace_index
  Debit quota
  Write KernelAuditEntry (immutable, HMAC-chained)
```

---

## Component Deep Dive

### 1. AgentNamespace — Isolated Memory Space

```
Namespace format: org:{id}/team:{id}/agent:{name}

org:acme/                           ← Org root (Admin only)
├── team:support/
│   ├── agent:triage/               ← Agent A's private namespace
│   ├── agent:specialist/           ← Agent B's private namespace
│   └── shared/knowledge/           ← Shared read-only
├── team:billing/
│   └── agent:invoice-processor/
└── shared/global-policies/         ← Org-wide read-only

RULE: Agent owns ONLY its namespace. Everything else requires explicit grant.
```

### 2. AgentControlBlock — The Process Control Block

```
ACB (one per agent)
├── Identity
│   ├── agent_pid: "pid:acme:triage:001"
│   ├── agent_name, agent_role
│   └── status: Running | Suspended | Completed | Failed | Terminated
│
├── Memory Isolation
│   ├── namespace: "org:acme/team:support/agent:triage"  (owned)
│   ├── memory_region: MemoryRegion [3]
│   ├── readable_namespaces: Vec<String>   (explicit read grants)
│   └── writable_namespaces: Vec<String>   (explicit write grants)
│
├── Capability Control
│   ├── namespace_mounts: Vec<NamespaceMount> [4]   (bind mounts)
│   ├── tool_bindings: Vec<ToolBinding> [6]         (default-deny tools)
│   └── delegation_chains: Vec<DelegationChain> [7] (crypto access)
│
└── Execution Control
    ├── phase: AgentPhase [5]   (Registered → Active → Suspended → ...)
    ├── role: AgentRole [5]     (Reader | Writer | Admin | ToolAgent | Auditor | Compactor)
    └── pending_signals: Vec<AgentSignal>
```

### 3. MemoryRegion — Quota + Protection

```
MemoryRegion
├── Quotas (0 = unlimited)
│   ├── quota_packets: u64    max MemPackets
│   ├── quota_tokens: u64     max LLM tokens
│   ├── quota_bytes: u64      max storage bytes
│   └── used_*: u64           current usage (debited on every write)
│
├── Protection Flags
│   ├── read: bool            can read packets
│   ├── write: bool           can write packets
│   ├── execute: bool         can execute tool calls
│   ├── share: bool           can share via Port
│   ├── evict: bool           can delete/GC packets
│   └── requires_approval: bool  every write needs HITL
│
├── Eviction Policy
│   Lru | Fifo | Ttl | Priority | SummarizeEvict | Never
│
└── sealed: bool              if true, no further writes ever
```

### 4. NamespaceMount — Controlled Cross-Namespace Access

```
NamespaceMount {
    source: "org:hospital/shared/patient-records",   ← real namespace
    mount_point: "/shared/patients",                  ← agent's view
    mode: ReadOnly | ReadWrite | Execute | Sealed,
    filters: [MountFilter {
        packet_types: [Extraction],        ← only these types visible
        entity_filter: ["patient:P-847"],  ← only this patient
        time_range: (session_start, end),  ← only this session
        max_packets: 500                   ← cap visibility
    }]
}

Enforcement:
  ReadOnly  → MemRead: ✅  MemWrite: ❌  ToolDispatch: ❌
  ReadWrite → MemRead: ✅  MemWrite: ✅  ToolDispatch: ❌
  Execute   → MemRead: ❌  MemWrite: ❌  ToolDispatch: ✅
  Sealed    → MemRead: ✅ (+ integrity verify)  MemWrite: ❌
```

### 5. ExecutionPolicy + AgentPhase — Syscall Control

```
6 Roles → 6 Policies:

Reader:    [MemRead, AccessCheck, IntegrityCheck]           rate: 1000/min
Writer:    [MemRead, MemWrite, Session*, Context*, Start]   rate: 500/min
Admin:     ALL operations                                    rate: 10000/min
ToolAgent: [MemRead, MemWrite, ToolDispatch, Port*]         rate: 60 tools/min
Auditor:   [MemRead, AccessCheck, IntegrityCheck]           ReadOnly phase only
Compactor: [MemRead, MemEvict, GarbageCollect]              rate: 1000/min

Phase FSM:
  Registered → only AgentStart
  Active     → all role-allowed ops
  Suspended  → only AgentResume or AgentTerminate
  ReadOnly   → only MemRead, AccessCheck, IntegrityCheck
  Terminating → only AgentTerminate
```

### 6. ToolBinding — Default-Deny

```
RULE: Agent cannot call ANY tool unless explicit ToolBinding exists.

ToolBinding {
    tool_id: "ehr.read_*",                      ← glob match
    namespace_path: "/tools/ehr/read",
    allowed_actions: ["ehr.read_vitals", "ehr.read_history"],
    allowed_resources: ["patient:*"],            ← glob match
    rate_limit: { 10/sec, 100/min, burst: 5 },
    data_classification: "phi",
    requires_approval: false
}

Check: tool_id match? → action match? → resource match? → rate OK?
Any NO → OpOutcome::Denied
```

### 7. DelegationChain — Cryptographic Attenuation

```
DelegationChain.proofs = [
    DelegationProof {
        issuer: "user:alice",
        subject: "agent:triage",
        allowed_actions: ["ehr.read_*", "ehr.write_*"],
        allowed_resources: ["patient:*"],
        signature: Ed25519(canonical_json),
        expires_at: ...
    },
    DelegationProof {
        issuer: "agent:triage",
        subject: "agent:specialist",
        allowed_actions: ["ehr.read_vitals"],        ← NARROWED
        allowed_resources: ["patient:P-847"],         ← NARROWED
        parent_proof_cid: proof_0.cid,
        signature: Ed25519(canonical_json)
    }
]

RULE: child.allowed_actions ⊆ parent.allowed_actions (attenuation only)
VERIFY: walk chain backwards, check each signature + attenuation
```

### 8. AccessGrant / AccessRevoke

```
Agent B (owner of "ns:B") issues:
  AccessGrant { target_namespace: "ns:B", grantee_pid: "pid:A", read: true, write: false }

Kernel validates: acb_B.namespace == "ns:B" (only owner can grant)
  → stores grant
  → updates acb_A.readable_namespaces

Agent B revokes:
  AccessRevoke { target_namespace: "ns:B", grantee_pid: "pid:A" }
  → removes grant + removes from acb_A's lists

Enhancement (Phase 1): expires_at TTL on grants
```

### 9. Port System — Typed Inter-Agent Channels

```
Port {
    port_id, port_type: Pipeline | Broadcast | Unicast | Control,
    owner_pid,
    bound_pids: Vec<String>,
    direction: Inbound | Outbound | Bidirectional,
    allowed_packet_types: Vec<PacketType>,
    allowed_actions: Vec<String>,
    max_delegation_depth: u8,
    expires_at: Option<i64>,
    closed: bool
}

Lifecycle:
  PortCreate → PortBind → PortSend → PortReceive → PortClose
                         → PortDelegate (attenuated sub-delegation)

WHY NOT shared memory?
  Shared memory = ambient authority.
  Ports = explicit, typed, audited, TTL-governed, delegation-bounded.
```

### 10. AgentFirewall — Weighted Threat Scorer

```
6 signal weights (configurable):
  injection:      0.35   (18 lexical patterns + encoding tricks)
  pii:            0.20   (5 types now, 10 types Phase 4)
  anomaly:        0.15   (from BehaviorAnalyzer)
  policy:         0.15   (role/phase violations)
  rate_pressure:  0.10   (calls/min vs limit)
  cross_boundary: 0.05   (namespace ownership)

3 config profiles:
  default()  → warn: 0.30, review: 0.60, block: 0.80
  strict()   → warn: 0.20, review: 0.40, block: 0.60
  hipaa()    → strict + pii weight doubled to 0.40

MAESTRO coverage: 4/7 layers active, 3 roadmap
OWASP LLM coverage: 8/10 covered, 2 roadmap
```

### 11. BehaviorAnalyzer — Runtime Anomaly Detection

```
6 detection algorithms:
  1. Frequency spike     — actions/window > max_actions_per_window (100)
  2. Data exfiltration   — bytes/window > max_data_volume (10MB)
  3. Scope drift         — unique tools > max_tool_diversity (10)
  4. Error probing       — error_rate > max_error_rate (30%)
  5. Behavioral drift    — deviation from baseline > anomaly_threshold (2.0×)
  6. Escalation attempt  — explicit escalation tracking

Baseline established after 20 actions.
Window: 60 seconds sliding.
Risk score per agent: aggregated from all 6 signals.
```

### 12. InstructionPlane — Schema-Validated Entry Gate

```
Every instruction passes 5 checks:
  1. Action known?        → UnknownAction
  2. Source type allowed?  → SourceBlocked
  3. Actor role allowed?   → RoleDenied
  4. Required params?      → MissingParam
  5. Param types correct?  → TypeMismatch

10 standard schemas registered:
  memory.write/read/seal, knowledge.query/ingest/seed,
  chat.send/receive, tool.call/register

SourceConstraint:
  RegisteredOnly → only actors registered via register_actor()
  AllowExternal  → specific external client IDs
  SystemOnly     → kernel-generated only
  Any            → no restriction (dangerous)
```

---

## The 3 Invariants

**Invariant 1 — Namespace Sovereignty**
> An agent's namespace is exclusively owned. No agent can write to another's namespace without an explicit AccessGrant issued by the owner.

**Invariant 2 — Default Deny**
> Every access check fails closed. No explicit grant, mount, or ownership match → `OpOutcome::Denied`.

**Invariant 3 — Audit Everything**
> Every access decision — success AND denial — produces a `KernelAuditEntry`. Append-only. Cannot be modified by any agent.

---

## Complete Security Pipeline — Memory Write

```
Agent calls: remember("patient data for P-847", namespace="org:acme/...")
  │
  ▼ [10] AgentFirewall
  injection_score = 0.02 (clean)
  pii_score = 0.33 (MRN "P-847" detected)
  cross_boundary = 0.0 (own namespace)
  weighted_sum = 0.04 → Allow
  │
  ▼ [11] BehaviorAnalyzer
  record_action("pid:agent-001", "memory.write", 156 bytes)
  47 actions < 100 max → OK
  4.7MB < 10MB → OK
  deviation 0.3× < 2.0× → OK
  │
  ▼ [12] InstructionPlane
  "memory.write" → schema found ✓
  source = Internal → registered ✓
  role = "writer" ∈ ["writer", "admin"] ✓
  params: { content: String ✓ } ✓
  │
  ▼ [5] ExecutionPolicy
  MemWrite ∈ Writer.allowed_ops ✓
  AgentPhase::Active ✓
  │
  ▼ [1][4][8] Namespace Check
  target = "org:acme/team:support/agent:triage"
  acb.namespace == target → own namespace ✓
  │
  ▼ [3] MemoryRegion
  has_capacity() = true ✓
  protection.write = true ✓
  requires_approval = false ✓
  │
  ▼ SUCCESS
  CID = hash(cbor(packet))
  Store in namespace_index
  used_packets += 1
  KernelAuditEntry { op: MemWrite, outcome: Success, cid: "bafyreib..." }
```

---

## Threat Coverage Matrix

| Threat | Detection | Component |
|--------|-----------|-----------|
| Direct prompt injection | 18 lexical patterns | Firewall [10] |
| Indirect prompt injection | memory_poisoning signal | Firewall [10] |
| System prompt extraction | Pattern match | Firewall [10] |
| PII in input/output/memory | 5 types (10 Phase 4) | Firewall [10] |
| Cross-agent contamination | cross_boundary signal | Firewall [10] + Analyzer [11] |
| Excessive tool use | scope_drift check | Analyzer [11] |
| Rate abuse / DoS | rate_pressure signal | Firewall [10] |
| Privilege escalation | escalation_attempt | Analyzer [11] |
| Behavioral drift | baseline deviation | Analyzer [11] |
| Data exfiltration | volume check | Analyzer [11] |
| Unknown action injection | UnknownAction | InstructionPlane [12] |
| Unregistered actor | UnregisteredActor | InstructionPlane [12] |
| Role escalation | RoleDenied | InstructionPlane [12] |
| Namespace traversal (../../) | Path canonicalization (Phase 1) | Kernel |
| Expired grant abuse | TTL enforcement (Phase 1) | Kernel |

---

## Compliance Coverage

| Framework | Automated Check | Key Requirements |
|-----------|----------------|------------------|
| **HIPAA §164.312** | `verify_hipaa()` | PII/PHI scanning, audit trails, access control |
| **SOC 2 Type II** | `verify_soc2()` | Audit integrity, monitoring, rate limiting |
| **GDPR Article 17** | `verify_gdpr()` | Right to erasure, data classification, retention |
| **EU AI Act Article 9** | `verify_eu_ai_act()` | Risk monitoring, human oversight, audit trail |
| **OWASP LLM Top 10** | AgentFirewall | 8/10 covered (2 roadmap) |
| **CSA MAESTRO** | ThreatScore tagging | 4/7 layers (3 roadmap) |
| **NIST AI RMF** | BehaviorAnalyzer | GOVERN/MAP/MEASURE/MANAGE |

---

## OS Analogy Reference

| OS Concept | Agent OS Component | # |
|-----------|-------------------|---|
| Process address space | AgentNamespace | 1 |
| `task_struct` / PCB | AgentControlBlock | 2 |
| Page protection (rwx) | MemoryRegion.protection | 3 |
| `mount --bind` | NamespaceMount | 4 |
| `seccomp-bpf` | ExecutionPolicy | 5 |
| Default-deny caps (Fuchsia) | ToolBinding | 6 |
| `sudo` + PAM delegation | DelegationChain | 7 |
| Unix domain sockets | Port system | 9 |
| `iptables` / `nftables` | AgentFirewall | 10 |
| `auditd` + `falco` | BehaviorAnalyzer | 11 |
| Syscall filter | InstructionPlane | 12 |

---

*12 components. 4 gates. 3 invariants. Every access checked. Every denial logged. No bypass possible.*
