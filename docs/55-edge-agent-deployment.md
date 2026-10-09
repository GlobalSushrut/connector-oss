# 55 — Edge Agent Deployment and CDN-Style Distribution

> **Status: Built and operational. Not required today.**  
> The sandbox model (`sandbox.rs`), traffic manager, transport layer, and distributed scheduler ship in the codebase today. You do not need edge deployment for a single-region system. You need it when latency to a central node is unacceptable, when data sovereignty requires local processing, or when you are building governed AI into devices, gateways, or regional points of presence — the same reasons CDNs exist.

---

## The CDN Analogy

A CDN (Content Delivery Network) solves one problem: the speed of light. Moving data from a central origin to users at the edge — close to where requests originate — eliminates the latency of round-trips across continents.

The governance analog is identical. Moving a governed AI agent to the edge — close to the data, the user, and the decision point — eliminates:

- Latency from sending every request to a central Connector node
- Data sovereignty violations from sending local data across borders
- Single-point-of-failure risk from a centralized governance node
- Bandwidth costs from streaming large contexts to a distant node

But a CDN just caches content. A Connector edge agent runs full governed AI inference with a complete governance contract, a local audit trail, and cryptographic proof of every decision — while staying synchronized with the origin network.

---

## The Edge Agent Model

An edge-deployed Connector agent is not a stripped-down version of a full agent. It is a full governed agent running in a sandboxed environment with **attenuated capabilities** — it can only do what the deployed contract explicitly permits.

The attenuation is the key insight. Rather than building a special "edge agent" with reduced features, Connector simply deploys a full agent with a contract that declares what capabilities are available at the edge. The agent itself enforces the boundary.

```
Origin Connector Network          Edge Connector Node
──────────────────────            ──────────────────────────────────
Full memory kernel       ──────►  Attenuated memory (local cache)
Full tool allowlist      ──────►  Edge-permitted tools only
Full audit journal       ◄──────  Local journal → sync to origin
CLS contract registry    ──────►  Deployed contract (by CID)
Full governance engine   ──────►  Same governance engine, same contract
HITL queue               ◄──────  HITL requests escalated to origin
Proof generation         ◄──────  Proof requests forwarded to origin
```

The edge node runs the full 9-ring architecture. All nine rings operate locally. What changes is the **scope** of what each ring can access — defined entirely by the CCL contract deployed to that edge.

---

## Sandboxing: The IsolationLevel Model

Every edge agent runs in a sandbox. `sandbox.rs` defines the isolation model:

```rust
pub enum IsolationLevel {
    None,       // Development only — no isolation
    Process,    // OS process isolation (separate PID namespace)
    Container,  // Container isolation (namespaces + cgroups)
    VM,         // Hardware-level VM isolation
    Hardware,   // Trusted Execution Environment (TEE) — SGX, TrustZone
}
```

For edge deployments:

| Deployment type | Isolation level |
|-----------------|-----------------|
| Developer laptop / local testing | `Process` |
| Edge server in a colocation facility | `Container` |
| Hospital on-premise device | `VM` |
| Medical wearable or IoT gateway | `Hardware` (TEE) |
| Regulated financial terminal | `Hardware` (TEE) |

### Resource Limits

Every edge agent has declared resource limits enforced by the sandbox:

```rust
pub struct ResourceLimits {
    pub max_memory_bytes: u64,       // Total memory the agent may use
    pub max_cpu_percent: f32,        // CPU ceiling (enforced by cgroup)
    pub max_tokens_per_minute: u32,  // LLM budget at the edge
    pub max_disk_bytes: u64,         // Local storage limit
    pub max_network_bytes_per_sec: u64, // Bandwidth limit
    pub max_concurrent_requests: u32,   // Request concurrency limit
}
```

These limits are declared in the CCL contract. The sandbox enforces them in hardware/OS primitives. The contract cannot be tricked into exceeding them — the enforcement is below the software layer.

### Capability Attenuation

```rust
pub struct SandboxCapability {
    pub capability_type: CapabilityType,
    pub granted: bool,
    pub scope: Option<String>,   // e.g., namespace restriction
    pub expires_at: Option<Timestamp>,
}

pub enum CapabilityType {
    MemoryRead,
    MemoryWrite,
    ToolCall,
    NetworkEgress,
    AuditWrite,
    HitlEscalate,
    ProofRequest,
    AgentDelegate,
}
```

An edge agent deployed for local patient intake might have:
```
MemoryRead:     granted, scope: /p/local-clinic/intake/
MemoryWrite:    granted, scope: /p/local-clinic/intake/
ToolCall:       granted, scope: [schedule_appointment, lookup_provider]
NetworkEgress:  granted, scope: origin-connector-node only
AuditWrite:     granted (local + sync to origin)
HitlEscalate:   granted (escalates to origin HITL queue)
ProofRequest:   NOT GRANTED (forwarded to origin)
AgentDelegate:  NOT GRANTED
```

This edge agent can do exactly what the intake workflow requires. It cannot call arbitrary tools, read other patients' records, delegate to other agents, or generate proofs without origin involvement. Even if the edge device is physically compromised, the attenuated capability set limits the blast radius.

---

## What Runs Locally vs. What Goes to Origin

Not everything can or should run at the edge. The split:

### Runs Locally at the Edge

| Component | Why local |
|-----------|-----------|
| Guard pipeline (Ring 3) | Zero-latency rejection of bad inputs |
| Memory read (in-scope namespace) | Low latency recall of local facts |
| LLM inference (if model is local) | Eliminate round-trip for inference |
| Policy evaluation (Ring 5) | Local decision-making without origin |
| Local audit journal | Fast journal writes, synced to origin |
| Tool dispatch (attenuated set) | Local tools (schedule, lookup) |
| Governed chat | Full governed inference locally |

### Forwarded to Origin

| Component | Why origin |
|-----------|-----------|
| Memory reads outside local scope | Data sovereignty — PHI stays at origin |
| HITL escalations | Human reviewers are at origin |
| Proof generation | Requires full journal chain across all cells |
| Trust score updates | Network-wide reputation |
| Contract registry | Single source of truth for contract CIDs |
| Cross-agent routing | Full topology discovery at origin |
| Memory writes to shared namespaces | Consistency requires origin coordination |

The `traffic_manager.rs` in the distributed subsystem handles this routing automatically. The edge agent does not need to know which calls go local and which go to origin — the CCL contract declares it, and the runtime enforces it.

---

## The Audit Trail: Local → Sync → Origin

Every decision at the edge produces a journal entry. The local journal at the edge node is HMAC-chained — consistent with the origin journal format. Sync works as follows:

```
Edge Journal:                    Origin Journal:
seq=1 edge_boot                  seq=1000 edge_registered
seq=2 memory_write               seq=1001 ← seq=2 (synced)
seq=3 decision                   seq=1002 ← seq=3 (synced)
seq=4 tool_call                  seq=1003 ← seq=4 (synced)
seq=5 network_partition          ─────────────────────────
seq=6 decision (offline)         [sync pending]
seq=7 memory_write (offline)     [sync pending]
seq=8 network_restored           seq=1004 ← seq=6 (synced in order)
                                 seq=1005 ← seq=7 (synced in order)
                                 seq=1006 ← seq=8 (synced)
```

**Critical property:** The HMAC chain is never broken. During a network partition, the edge agent continues operating locally. Its local journal is valid and self-consistent. When connectivity restores, the synced entries are inserted in sequence order at the origin. Any auditor can reconstruct the complete timeline — including what happened during the outage — from the combined journal.

A governed edge agent that was offline for three days is not an auditing gap. It is three days of locally-chained journal entries, synced and provable.

---

## Violation Detection and Response

`SandboxViolation` records any attempt by the edge agent to exceed its capability boundary:

```rust
pub struct SandboxViolation {
    pub violation_type: ViolationType,
    pub attempted_action: String,
    pub blocked: bool,
    pub timestamp: Timestamp,
}

pub enum ViolationType {
    CapabilityExceeded,     // Tried to call a tool not in capability set
    ResourceLimitExceeded,  // Tried to use more memory/CPU than allowed
    NamespaceViolation,     // Tried to read outside scoped namespace
    NetworkPolicyViolation, // Tried to contact unauthorized endpoint
    BudgetExceeded,         // Tried to exceed token/cost budget
}

pub enum ViolationAction {
    Block,           // Block the action, continue running
    BlockAndAlert,   // Block + send alert to origin
    BlockAndHalt,    // Block + halt the edge agent
    BlockAndEscalate, // Block + HITL escalation to origin
}
```

Violations are journaled locally and synced to origin immediately (even before the full journal sync). An edge agent that is being actively exploited triggers `BlockAndAlert` or `BlockAndHalt` — the origin network knows within milliseconds.

---

## Deployment: The Edge Agent Manifest

Deploying an edge agent requires an agent manifest that declares the edge-specific configuration:

```yaml
agent:
  name: intake-agent-clinic-47
  contract_cid: cls1-sha256-a3f7b2c8d9e1f5a2  # Immutable by CID

edge:
  isolation: container
  origin_node: https://connector.hospital-a.internal:8443
  sync_interval_seconds: 30
  offline_allowed: true
  max_offline_hours: 72

resources:
  max_memory_bytes: 512MB
  max_cpu_percent: 25.0
  max_tokens_per_minute: 1000
  max_disk_bytes: 2GB

capabilities:
  memory_read:
    scope: /p/clinic-47/intake/
  memory_write:
    scope: /p/clinic-47/intake/
  tools:
    - schedule_appointment
    - lookup_provider
    - check_availability
  network_egress:
    allowed_hosts: [origin-connector-node]

governance_tags: [hipaa, minimum-necessary, edge-attenuated]
```

This manifest is compiled into the CCL contract at deploy time. The contract CID covers the manifest parameters. You cannot deploy the same `cls1-sha256-*` CID with different edge settings — a settings change produces a new CID.

---

## The Future: Governed AI at the Edge, Everywhere

The CDN analogy extends fully:

| CDN | Connector Edge Network |
|-----|----------------------|
| Content cached at edge PoPs | Governed agents deployed at edge nodes |
| Origin serves cache misses | Origin handles proof, HITL, cross-scope queries |
| Cache invalidation | Contract CID update — old CID agents drain, new ones activate |
| Regional routing | Trust-based routing to nearest compliant edge |
| DDoS protection at edge | Firewall pipeline runs locally, rejects bad inputs before origin |
| Analytics | Every decision journaled and queryable |

The end state: a network of governed AI nodes at every meaningful point of presence — hospital intake desks, financial terminals, IoT gateways, enterprise edge servers, regional cloud PoPs. Each node runs attenuated governed agents. Each agent's behavior is defined by an immutable CID-addressed contract. Every decision is locally fast, regionally auditable, and globally provable.

Governed AI at the edge is not a product feature. It is the infrastructure layer that makes governed AI viable in the real world — where data has gravity, regulations have borders, and latency has consequences.
