# LINUX_REVOLUTION.md — From Unix Revolution to Linux Revolution of AI Infrastructure

> **The inflection point, stated plainly:**
> "Unix gave us processes, files, pipes, and permissions. Linux industrialized them into a planetary-scale operating substrate. The Agent OS is at the Unix stage right now. This document defines what the Linux revolution requires."

---

## Table of Contents

1. [The Analogy That Defines the Moment](#1-the-analogy)
2. [What Unix Gave Computing — And What Linux Added](#2-unix-vs-linux)
3. [Where the Agent OS Stands Today (Honest Audit)](#3-honest-audit)
4. [The 12 Missing Primitives — What Linux Revolution Requires](#4-twelve-missing-primitives)
   - [P1 — LLM Scheduler: Preemption, Fairness, Token Budgets](#p1-llm-scheduler)
   - [P2 — Context Manager: Snapshots, Swapping, Compression](#p2-context-manager)
   - [P3 — Signal System: Async Inter-Agent Events](#p3-signal-system)
   - [P4 — Agent Identity & Discovery: DID + Agent Card](#p4-agent-identity)
   - [P5 — Protocol Bridge: MCP / A2A / ACP / ANP Native Support](#p5-protocol-bridge)
   - [P6 — GPU / Compute Resource Manager](#p6-gpu-compute)
   - [P7 — Semantic Telemetry: LLM-Readable Observability](#p7-semantic-telemetry)
   - [P8 — Agent Payment Protocol (AP2)](#p8-agent-payment)
   - [P9 — eBPF-Style Kernel Extension Points](#p9-kernel-extensions)
   - [P10 — Adaptive Scheduler: Workload-Aware Execution](#p10-adaptive-scheduler)
   - [P11 — Cross-Org Agent Marketplace + Discovery](#p11-agent-marketplace)
   - [P12 — Self-Healing Infrastructure: Agents That Fix Their Own OS](#p12-self-healing)
5. [What Already Exists (Do Not Rebuild)](#5-what-already-exists)
6. [Protocol Landscape: MCP, A2A, ACP, ANP, AP2](#6-protocol-landscape)
7. [The Linux Revolution Roadmap — Phased Build Plan](#7-phased-roadmap)
8. [Architecture: The Complete Agent OS Stack Post-Revolution](#8-complete-stack)
9. [Research Foundations](#9-research-foundations)

---

## 1. The Analogy

### Unix Era (1969–1991): Invention of Primitives

Unix invented the concepts that define modern computing:
- **Process** — isolated unit of execution with an address space
- **File** — uniform abstraction over everything (disk, pipe, device, socket)
- **Pipe** — composable single-direction data flow between processes
- **Permission bits** — rwx model for access control
- **Signal** — async notification from kernel to process

These were profound inventions. But Unix was: single-machine, single-user-minded, not networked at scale, not multi-tenant, and required expert operators. Every deployment was hand-crafted.

### Linux Era (1991–present): Industrialization of Primitives

Linux took Unix primitives and made them:
- **Preemptible** — the scheduler could interrupt any process; fairness was enforced
- **Namespaced** — processes got isolated views of the filesystem, network, PID space
- **Containerized** — cgroups + namespaces = lightweight VMs; Docker built on this
- **Orchestrated** — Kubernetes turned Linux primitives into a planetary-scale control plane
- **Observable** — `/proc`, `/sys`, eBPF, perf — kernel became introspectable at zero cost
- **Extensible** — eBPF let userspace safely inject logic into kernel paths without forking

The Linux revolution was not new ideas. It was the **operationalization, industrialization, and standardization** of Unix ideas at planetary scale.

### The Agent OS Today

The Agent OS (this codebase) has done the Unix work:
- ✅ **Process**: `AgentControlBlock` — per-agent isolated execution context
- ✅ **File**: `NamespaceMount` — uniform namespace abstraction over agent memory
- ✅ **Pipe**: `Port` system — typed inter-agent message channels
- ✅ **Permissions**: `ExecutionPolicy` + `ToolBinding` + `DelegationChain`
- ✅ **Signal**: Partial — `ReplicationOp::ApprovalRequest` exists, but no general signal system
- ✅ **Scheduler**: None — no preemption, no token fairness, no LLM-aware scheduling

**We are at Unix 1975.** The Linux 1991 moment requires 12 new primitives.

---

## 2. Unix vs. Linux — The Exact Mapping to Agent OS

| Unix Primitive | Linux Addition | Agent OS Unix Stage | Agent OS Linux Need |
|---------------|----------------|--------------------|--------------------|
| Process (single CPU) | Preemptive scheduler, SMP, cgroups | `AgentControlBlock`, `AgentPhase` | **LLM Scheduler** with token fairness (P1) |
| File (disk only) | VFS: NFS, tmpfs, proc, sysfs, FUSE | `NamespaceMount`, `KernelStore` VFS trick | **FUSE-equiv**: pluggable memory backends (partial) |
| Pipe (local, blocking) | Unix domain sockets, epoll, io_uring | `Port` system (local only) | **Async signal bus**: non-blocking inter-agent events (P3) |
| Single machine | TCP/IP stack, networking in kernel | `ClusterKernelStore`, `NatsBus` | **Protocol bridge**: MCP/A2A/ANP native (P5) |
| Manual login | `/etc/passwd`, PAM, LDAP, Kerberos | `DelegationChain`, Ed25519 | **DID-based identity + discovery** (P4) |
| `strace`, `gdb` | `perf`, `eBPF`, `/proc`, cgroups metrics | `KernelAuditEntry`, `BehaviorAnalyzer` | **Semantic telemetry** (P7) |
| Static binaries | `ld.so`, modules, eBPF kernel extensions | Fixed syscall table | **Runtime kernel extension** via hooks (P9) |
| CPU time sharing | GPU drivers, CUDA, VRAM scheduling | `LlmConfig`, multi-provider | **GPU/token compute resource manager** (P6) |
| No memory swap | Swap space, NUMA, huge pages | `EvictionPolicy`, tier system | **Context swap**: LLM state snapshots (P2) |
| Single org | NFS, LDAP, Kerberos, domain trust | `FederatedPolicyEngine`, SCITT | **Agent marketplace + cross-org discovery** (P11) |
| Manual recovery | `systemd`, watchdog, `journald`, cron | Partial saga rollback | **Self-healing infrastructure** (P12) |
| No payment | N/A (Linux predates e-commerce) | N/A | **Agent Payment Protocol** (P8) |

---

## 3. Honest Audit — Where the Agent OS Stands Today

### What We Have Built (Unix Tier — Solid)

| Component | Crate | Maturity | Unix Analog |
|-----------|-------|----------|-------------|
| Agent process model | `vac-core/kernel.rs` | ✅ Production | `fork()`/`exec()` |
| Namespace isolation | `vac-core/types.rs` | ✅ Production | `chroot` + mount namespaces |
| Mount system | `NamespaceMount` | ✅ Production | `mount(2)` |
| Permission model | `ExecutionPolicy` + `ToolBinding` | ✅ Production | `chmod`/`chown` |
| Delegation chain | `DelegationChain` Ed25519 | ✅ Production | `sudo` + `PAM` |
| Audit log | `KernelAuditEntry` + SCITT | ✅ Production | `auditd` |
| Consistent hash routing | `vac-route` | ✅ Production | `ip route` |
| CRDT membership | `vac-cluster/membership.rs` | ✅ Production | ARP table + routing |
| Distributed store | `ClusterKernelStore` | ✅ Production | NFS + VFS |
| Merkle replication | `vac-replicate` | ✅ Production | `rsync` |
| Event bus | `vac-bus` (InProcess + NATS) | ✅ Production | Unix pipes + sockets |
| Policy engine | `aapi-metarules` | ✅ Production | `iptables`/`nftables` |
| Security firewall | `connector-engine/firewall.rs` | ✅ Production | `seccomp` |
| Behavior analysis | `connector-engine/behavior.rs` | ✅ Production | `auditd` + `falco` |
| LLM multi-provider | `connector-engine/llm.rs` | ✅ Production | device drivers |
| LLM circuit breaker | `connector-engine/llm_router.rs` | ✅ Production | kernel I/O retry |
| Instruction plane | `connector-engine/instruction.rs` | ✅ Production | `seccomp` syscall filter |
| Saga/rollback | `aapi-pipeline/saga.rs` | ✅ Production | `journald` + transaction |
| Federation | `aapi-federation` | ✅ Production | Kerberos cross-realm |
| VAKYA pipeline | `aapi-pipeline` | ✅ Production | `make` DAG execution |
| Perception engine | `connector-engine/perception.rs` | ✅ Production | sensor abstraction |
| Port system (local) | `vac-core/types.rs` Port | ✅ Production | Unix domain socket |

### What Is Missing (Linux Tier — Not Yet Built)

| Missing Primitive | Linux Analog | Impact | Priority |
|-----------------|-------------|--------|----------|
| LLM Scheduler | CFS/EEVDF + cgroups | Critical — no token fairness, starvation possible | P0 |
| Context Manager | `swapd`, KSM, huge pages | High — no LLM state snapshot/resume | P1 |
| Signal system | `kill(2)`, `signalfd`, `sigaction` | High — no async agent interrupts | P1 |
| Agent identity (DID) | `/etc/passwd` + Kerberos | High — no cross-org agent discovery | P1 |
| Protocol bridge (MCP/A2A) | network device driver | High — no external ecosystem interop | P1 |
| GPU/token quota | `cpuacct` cgroup + CUDA MPS | High — no resource fairness | P2 |
| Semantic telemetry | `eBPF` + `perf` | Medium — logs not LLM-readable | P2 |
| Agent Payment (AP2) | (no Unix analog) | Medium — no economic primitives | P2 |
| Kernel extension hooks | `eBPF` kernel modules | Medium — kernel is not extensible | P3 |
| Adaptive scheduler | `sched_ext` eBPF schedulers | Medium — no workload-aware dispatch | P3 |
| Agent marketplace | `apt`/`yum` + DNS-SD | Low-Medium — no agent discovery | P3 |
| Self-healing infra | `systemd` + watchdog | Medium — failure recovery is manual | P3 |

---

## 4. The 12 Missing Primitives

---

### P1 — LLM Scheduler: Preemption, Fairness, Token Budgets

**The problem**: The current system has zero LLM scheduling. When 50 agents all request LLM inference simultaneously, they race for the same provider endpoints. The first agent to send wins. Later agents starve. High-priority agents get no preference. There is no token budget enforcement at the kernel level.

**What Linux did**: The Completely Fair Scheduler (CFS) replaced O(1) scheduler in 2.6.23. It modeled "virtual runtime" — each process gets its fair share of CPU proportional to its weight. No process starves. Linux 6.12 added `sched_ext` — eBPF-programmable schedulers that let user space define scheduling policy without kernel recompilation.

**What the Agent OS needs**:

```rust
// NEW: vac-core/src/scheduler.rs
pub struct LlmScheduler {
    queues: HashMap<AgentPriority, VecDeque<LlmRequest>>,
    token_budgets: HashMap<String, TokenBudget>,   // agent_pid → budget
    virtual_runtime: HashMap<String, f64>,          // agent_pid → vruntime (CFS model)
    active_requests: HashMap<String, LlmRequest>,  // in-flight requests
}

pub struct TokenBudget {
    pub agent_pid: String,
    pub daily_limit: u64,       // max tokens per day
    pub hourly_limit: u64,      // max tokens per hour
    pub burst_limit: u64,       // max tokens in a single request
    pub used_today: u64,
    pub used_this_hour: u64,
    pub cost_center: String,    // for FinOps attribution
}

pub enum AgentPriority {
    RealTime,    // weight 100 — never preempted
    High,        // weight 10
    Normal,      // weight 1 (default)
    Background,  // weight 0.1 — preempted first
    Idle,        // weight 0.01 — runs only when no other work
}

pub enum SchedulingPolicy {
    Fifo,          // arrival order (current implicit behavior)
    RoundRobin,    // time-sliced — preempt long-running LLM calls
    Cfs,           // weighted virtual runtime (Linux CFS model)
    Custom(Box<dyn SchedulerPlugin>),  // eBPF-style custom policy
}
```

**Integration points**:
- `AgentControlBlock` gets a `priority: AgentPriority` and `token_budget: Option<TokenBudget>` field
- `DualDispatcher.gate_llm_call()` — new firewall equivalent for LLM calls; checks budget before forwarding to `LlmRouter`
- `ClusterKernelStore` replicates `TokenBudget` usage across cells so cross-cell agents share one budget

**Research grounding**: AIOS paper (2403.16971) §3.3 implements FIFO + Round Robin. Google's SchedCP framework (arXiv:2509.01245) shows eBPF-programmable schedulers outperforming static policies by 1.79× on kernel compilation. The `sched_ext` framework in Linux 6.12 is the direct model.

---

### P2 — Context Manager: LLM State Snapshots, Swapping, Compression

**The problem**: When an LLM request is preempted (long-running, or interrupted by higher-priority agent), its partial generation state is lost. The request must restart from scratch. This wastes compute and token budget proportional to the work already done.

**What Linux did**: Virtual memory with swap. A process's address space pages can be evicted to disk when RAM is full, then paged back in on demand. The process never knows it was swapped.

**What the Agent OS needs**:

```rust
// NEW: connector-engine/src/context_manager.rs
pub struct ContextSnapshot {
    pub agent_pid: String,
    pub request_id: String,
    pub snapshot_type: SnapshotType,
    pub partial_output: String,          // decoded tokens so far
    pub beam_state: Option<Vec<u8>>,     // logits-based: beam search state (closed-source LLMs skip)
    pub messages_so_far: Vec<ChatMessage>,
    pub tokens_consumed: u32,
    pub created_at: i64,
    pub cid: String,                     // content-addressed, storable in VAC namespace
}

pub enum SnapshotType {
    TextBased,    // closed-source LLMs (GPT-4, Claude) — save decoded text only
    LogitsBased,  // open-source LLMs (Llama, Mistral) — save beam search tree
}

pub struct ContextManager {
    active_snapshots: HashMap<String, ContextSnapshot>,   // request_id → snapshot
    namespace: String,   // store snapshots in VAC namespace "sys:context:snapshots"
}

impl ContextManager {
    // Preempt an in-flight LLM request — save state to VAC
    pub async fn snapshot(&self, request_id: &str) -> ContextSnapshot;
    // Resume a preempted request from its snapshot
    pub async fn restore(&self, snapshot: &ContextSnapshot) -> LlmRequest;
    // Compress a snapshot (reduce token cost of re-injection)
    pub async fn compress(&self, snapshot: &ContextSnapshot) -> ContextSnapshot;
    // Evict old snapshots from RAM to kernel store
    pub async fn evict_to_store(&self, snapshot: ContextSnapshot);
}
```

**Key design**: Snapshots are CID-addressed and stored in a dedicated VAC namespace (`sys:context:snapshots`). This means:
- They survive cell restarts (persistent across crashes)
- They can be replicated to peer cells (preempted work can resume on any cell)
- They are auditable (the SCITT audit trail covers context switches)

**Integration**: `LlmScheduler` calls `ContextManager.snapshot()` when preempting. The AIOS paper's `logits-based` snapshot achieves finer-grained resume than text-only, but requires open-source model access.

---

### P3 — Signal System: Async Inter-Agent Events

**The problem**: Unix `kill(2)` allows one process to asynchronously interrupt another with a typed signal (SIGTERM, SIGINT, SIGUSR1). The receiving process can register a handler or use the default. This is the foundation of all async process coordination. The Agent OS has **no equivalent**. The `ApprovalRequest` `ReplicationOp` is a manual workaround, not a general signal primitive.

**What the Agent OS needs**:

```rust
// NEW: vac-core/src/signal.rs
pub enum AgentSignal {
    // System signals (like POSIX)
    Terminate,       // SIGTERM — graceful shutdown request
    Kill,            // SIGKILL — immediate termination, no handler
    Suspend,         // SIGSTOP — pause execution (transition to Suspended phase)
    Resume,          // SIGCONT — resume from Suspended
    Interrupt,       // SIGINT — interrupt current operation
    // Agent-specific signals
    TokenBudgetWarning { remaining: u64 },    // approaching budget limit
    TokenBudgetExhausted,                     // hard stop — budget depleted
    MemoryPressure { used_pct: u8 },          // namespace filling up
    SecurityAlert { threat_score: f64 },      // firewall detected threat
    PeerDown { cell_id: String },             // a peer cell has failed
    PolicyUpdated { policy_id: String },      // a policy affecting this agent changed
    ApprovalGranted { approval_id: String },  // human approved a pending operation
    ApprovalDenied  { approval_id: String },  // human denied a pending operation
    // User-defined (SIGUSR1/SIGUSR2 equivalent)
    Custom { name: String, payload: Vec<u8> },
}

pub struct SignalHandler {
    pub signal: AgentSignal,
    pub action: SignalAction,
}

pub enum SignalAction {
    Ignore,
    Default,                    // apply kernel default behavior
    Custom(Box<dyn Fn(AgentSignal) + Send + Sync>),
}

// New syscall: SyscallPayload::SendSignal { target_pid: String, signal: AgentSignal }
// New syscall: SyscallPayload::RegisterSignalHandler { signal_type: String, action: SignalAction }
```

**Integration**:
- `AgentControlBlock` gets `signal_handlers: HashMap<String, SignalAction>`
- `LlmScheduler` sends `TokenBudgetWarning` / `TokenBudgetExhausted` to agents
- `MemoryKernel` sends `MemoryPressure` when `MemoryRegion.used_pct > 80`
- `AgentFirewall` sends `SecurityAlert` on high-threat-score events
- `Membership.detect_dead()` sends `PeerDown` to all affected agents

**Why this is the Linux moment**: Without signals, agents cannot react to async system events. They must poll. Polling at scale burns compute, increases latency, and makes self-healing impossible.

---

### P4 — Agent Identity & Discovery: Decentralized Identity (DID)

**The problem**: An agent on Cell A has no standard way to discover that an agent on Cell B exists, what capabilities it has, or whether it is trustworthy. Agents are currently identified by `agent_pid` strings — opaque to any external system.

**The ecosystem standard**: W3C Decentralized Identifiers (DID) + **Agent Card** (Google A2A spec). An Agent Card is a JSON-LD document describing an agent's identity, capabilities, supported protocols, and authentication requirements. It is the `/.well-known/agent.json` of the agent ecosystem.

**What the Agent OS needs**:

```rust
// NEW: aapi-federation/src/identity.rs
pub struct AgentCard {
    // W3C DID — globally unique, self-sovereign identity
    pub did: String,                    // e.g., "did:connector:cell-us-east:agent:triage-001"
    pub name: String,
    pub description: String,
    pub version: String,
    pub capabilities: Vec<AgentCapability>,
    pub supported_protocols: Vec<String>,  // ["mcp", "a2a", "acp"]
    pub authentication: Vec<AuthMethod>,
    pub service_endpoints: Vec<ServiceEndpoint>,
    pub public_key: Vec<u8>,           // Ed25519 public key
    pub scitt_receipt: Option<String>, // transparency attestation
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

pub struct AgentCapability {
    pub domain: String,         // e.g., "healthcare.triage"
    pub actions: Vec<String>,   // e.g., ["read_ehr", "write_note", "order_test"]
    pub data_types: Vec<String>,
    pub rate_limits: Option<RateLimit>,
}

// NEW: Agent Card registry — stored in VAC namespace "sys:registry:agents"
pub struct AgentRegistry {
    kernel: Arc<MemoryKernel>,
}

impl AgentRegistry {
    pub async fn register(&self, card: AgentCard) -> CID;
    pub async fn lookup_by_did(&self, did: &str) -> Option<AgentCard>;
    pub async fn discover_by_capability(&self, domain: &str, action: &str) -> Vec<AgentCard>;
    pub async fn verify_card(&self, card: &AgentCard) -> bool; // Ed25519 + SCITT
}
```

**The `/.well-known/agent.json` endpoint** — every `connector-server` should serve its agents' cards at this URL, enabling cross-org discovery without a central registry.

**Research grounding**: Google A2A spec requires Agent Cards. ANP (Agent Network Protocol) uses W3C DIDs for decentralized identity. The survey (arXiv:2505.02279) identifies "no universal agent identity system" as the #1 interoperability gap.

---

### P5 — Protocol Bridge: MCP / A2A / ACP / ANP Native Support

**The problem**: The agent ecosystem has four emerging interoperability protocols. The Agent OS currently speaks none of them natively. Every adapter must implement its own translation layer.

**The four protocols** (from arXiv:2505.02279):

| Protocol | Sponsor | Purpose | Transport | Trust Model |
|----------|---------|---------|-----------|-------------|
| **MCP** (Model Context Protocol) | Anthropic | Tool/context delivery to LLMs | JSON-RPC 2.0 over stdio/SSE | Single org |
| **A2A** (Agent-to-Agent) | Google | Enterprise agent collaboration | HTTP/SSE multimodal | Multi-org, mutual auth |
| **ACP** (Agent Communication Protocol) | IBM/Linux Foundation | Async RESTful inter-agent | REST + async | Vendor-neutral |
| **ANP** (Agent Network Protocol) | Open | Open internet agent mesh | HTTP + W3C DID | Decentralized |
| **AP2** (Agent Payment Protocol) | Google | Agent financial transactions | HTTPS + cryptographic mandates | Cross-bank |

**What the Agent OS needs**:

```rust
// NEW: connector/crates/connector-protocols/src/

// MCP Bridge — expose VAC namespaces + ToolBindings as MCP servers
pub struct McpBridge {
    dispatcher: Arc<DualDispatcher>,
}
impl McpBridge {
    // Translate MCP tool calls → SyscallPayload::ToolDispatch
    // Translate MCP resource reads → SyscallPayload::MemRead
    // Expose VAC namespace as MCP "resource" with content-addressed CIDs
    pub async fn serve_mcp(&self, bind: &str) -> Result<(), McpError>;
}

// A2A Bridge — serve Agent Cards + handle task delegation
pub struct A2ABridge {
    registry: Arc<AgentRegistry>,
    dispatcher: Arc<DualDispatcher>,
}
impl A2ABridge {
    // Serve /.well-known/agent.json
    pub async fn serve_agent_card(&self, agent_pid: &str) -> AgentCard;
    // Receive A2A task from external agent → route to VakyaRouter
    pub async fn receive_task(&self, task: A2ATask) -> A2ATaskResult;
    // Delegate A2A task to external agent
    pub async fn delegate_task(&self, card: &AgentCard, task: A2ATask) -> A2ATaskResult;
}

// ACP Bridge — Linux Foundation's REST-based async protocol
pub struct AcpBridge {
    // RESTful endpoints for inter-agent async messaging
    // Maps ACP messages → ReplicationOp::VakyaForward/Reply
}

// ANP Bridge — open internet + W3C DID
pub struct AnpBridge {
    did_resolver: Arc<DidResolver>,
    // Encrypted agent-to-agent HTTP with DID-based authentication
}
```

**Integration with existing infrastructure**:
- MCP Bridge wraps existing `ToolBinding` system — no new security model needed
- A2A Bridge uses existing `DelegationChain` for cross-org trust verification
- ACP Bridge maps directly to `ReplicationOp::VakyaForward`/`VakyaReply`
- All bridges feed events through existing `AgentFirewall` — zero trust gap

---

### P6 — GPU / Compute Resource Manager

**The problem**: GPUs are the scarcest resource in AI infrastructure. The current system treats LLM providers as black boxes — no visibility into GPU utilization, VRAM usage, or inference latency distribution. From Jimmy Song (2026): "GPU utilization remains below 30-40% in many environments while costs continue to rise."

**What the Agent OS needs**:

```rust
// NEW: vac-core/src/compute.rs
pub struct ComputeResource {
    pub resource_id: String,
    pub resource_type: ComputeType,
    pub total_capacity: ComputeCapacity,
    pub allocated: ComputeCapacity,
    pub reserved: ComputeCapacity,
}

pub enum ComputeType {
    GpuVram { device: String, vram_gb: f32 },      // local GPU
    CloudInference { provider: String, model: String, tpm: u64 }, // tokens/min
    LocalInference { engine: String, tokens_per_sec: u32 },       // ollama, vllm
    CpuInference { threads: u8 },
}

pub struct ComputeCapacity {
    pub tokens_per_minute: u64,    // throughput
    pub max_context_tokens: u32,   // context window
    pub max_concurrent: u8,        // parallel requests
    pub cost_per_1k_tokens: f64,   // FinOps
}

// NEW: Token budget cgroup equivalent
pub struct ComputeCgroup {
    pub name: String,           // e.g., "team:healthcare", "agent:triage"
    pub token_quota_daily: u64,
    pub token_quota_hourly: u64,
    pub compute_weight: f32,    // CFS-style weight (default 1.0)
    pub cost_center: String,    // for billing attribution
    pub children: Vec<String>,  // nested cgroups (team → agent → request)
}

pub struct ComputeManager {
    resources: Vec<ComputeResource>,
    cgroups: HashMap<String, ComputeCgroup>,
    usage: HashMap<String, ComputeUsage>, // CID-addressed usage records
}
```

**The FinOps layer**: Every LLM call records `(agent_pid, model, input_tokens, output_tokens, cost_usd, latency_ms)` as a `KernelAuditEntry`. The `ComputeCgroup` hierarchy allows attribution by org → team → agent → request. This is the direct analog of `cpuacct` cgroup accounting.

---

### P7 — Semantic Telemetry: LLM-Readable Observability

**The problem**: Current audit logs (`KernelAuditEntry`) are machine-readable but not LLM-readable. An agent cannot read its own telemetry to self-diagnose. From CIO.com: "Instead of `Error 500: null pointer exception`, semantic telemetry provides: `Error: The procurement agent failed because the vendor ID field was null, preventing a valid match.`"

**What the Agent OS needs**:

```rust
// ENHANCEMENT: vac-core/src/audit_export.rs
pub struct SemanticAuditEntry {
    pub base: KernelAuditEntry,
    // NEW FIELDS:
    pub natural_language: String,          // LLM-readable description of what happened
    pub business_impact: Option<String>,   // "Patient record not updated — requires manual review"
    pub remediation_hint: Option<String>,  // "Retry with namespace write permission"
    pub causal_chain: Vec<String>,         // CIDs of preceding events that caused this
    pub tags: Vec<String>,                 // structured searchable tags
    pub severity: TelemetrySeverity,
}

pub enum TelemetrySeverity { Debug, Info, Warn, Error, Critical, Fatal }

// NEW: vac-core/src/telemetry.rs
pub struct SemanticTelemetryEngine {
    templates: HashMap<KernelOp, TelemetryTemplate>,
}

pub struct TelemetryTemplate {
    pub natural_language_fn: Box<dyn Fn(&KernelAuditEntry) -> String>,
    pub impact_fn: Box<dyn Fn(&KernelAuditEntry) -> Option<String>>,
    pub remediation_fn: Box<dyn Fn(&KernelAuditEntry) -> Option<String>>,
}

// Example template for MemWrite failure:
// natural_language: "Agent {agent_pid} attempted to write {bytes} bytes to namespace {ns} but was blocked: {reason}"
// impact: "Memory update failed — agent state may be inconsistent"
// remediation: "Check namespace ownership and mount permissions in AgentControlBlock"
```

**OpenTelemetry semantic conventions**: Emit structured spans with `gen_ai.*` attributes (the emerging OTel AI semantic conventions):
```
gen_ai.system = "connector-os"
gen_ai.operation.name = "memory_write" | "tool_call" | "llm_inference"
gen_ai.agent.id = agent_pid
gen_ai.token.usage.input = N
gen_ai.token.usage.output = N
gen_ai.request.model = "gpt-4o"
connector.threat_score = 0.15
connector.namespace = "org:acme/team:support"
```

---

### P8 — Agent Payment Protocol (AP2)

**The problem**: Agents increasingly need to complete financial transactions (purchase APIs, pay for compute, transact on behalf of users). There is no cryptographic payment primitive in the system. Without it, agents either get full account access (dangerous) or require human confirmation for every transaction (slow).

**Google AP2 model** — three credential types:
- **Cart Mandate** (user present): agent assembles cart, user signs before money moves
- **Intent Mandate** (preapproval): user pre-signs a scoped budget for a future action
- **Payment Mandate**: cryptographic proof to payment networks that agent acted within mandate

**What the Agent OS needs**:

```rust
// NEW: aapi-federation/src/payment.rs
pub struct PaymentMandate {
    pub mandate_id: String,
    pub issuer_did: String,           // the human/org issuing the mandate
    pub agent_did: String,            // the agent authorized to spend
    pub mandate_type: MandateType,
    pub max_amount: f64,
    pub currency: String,
    pub merchant_constraints: Option<Vec<String>>,  // only these merchants
    pub category_constraints: Option<Vec<String>>,  // only these categories
    pub expires_at: i64,
    pub signature: Vec<u8>,           // Ed25519 signature from issuer
    pub scitt_receipt: Option<String>,// transparency attestation
}

pub enum MandateType {
    CartMandate { session_ttl_ms: u64 },    // user present
    IntentMandate { trigger: String },       // "buy X when Y happens"
    PaymentMandate { authorized_amount: f64 },
}

// New syscall: SyscallPayload::PaymentRequest { mandate_id: String, amount: f64, merchant: String }
// Firewall intercepts: checks mandate validity, amount within bounds, merchant allowed
// SCITT receipt issued for every transaction
```

**Integration with DelegationChain**: `PaymentMandate` IS a `DelegationChain` with financial attenuation. The issuer delegates payment authority to the agent with `max_amount` attenuation — exactly the UCAN delegation model already in the system.

---

### P9 — eBPF-Style Kernel Extension Points

**The problem**: The kernel syscall table is fixed at compile time. Adding new behavior (custom scheduling, custom audit sinks, custom security rules) requires modifying and recompiling the kernel. Linux solved this with eBPF: safe, verifiable programs loaded at runtime that hook into kernel paths.

**What the Agent OS needs**:

```rust
// NEW: vac-core/src/extensions.rs
pub trait KernelExtension: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn hooks(&self) -> Vec<KernelHook>;
}

pub enum KernelHook {
    PreSyscall(Box<dyn Fn(&SyscallPayload, &AgentControlBlock) -> HookDecision + Send + Sync>),
    PostSyscall(Box<dyn Fn(&SyscallPayload, &KernelSyscallResult) + Send + Sync>),
    OnAgentRegister(Box<dyn Fn(&AgentControlBlock) + Send + Sync>),
    OnAgentTerminate(Box<dyn Fn(&str) + Send + Sync>),  // agent_pid
    OnMemWrite(Box<dyn Fn(&MemPacket) -> HookDecision + Send + Sync>),
    OnAuditEntry(Box<dyn Fn(&KernelAuditEntry) + Send + Sync>),
    OnThreatDetected(Box<dyn Fn(&ThreatScore) + Send + Sync>),
    OnTokenBudgetExhausted(Box<dyn Fn(&str, u64) + Send + Sync>), // agent_pid, tokens_used
}

pub enum HookDecision { Allow, Deny(String), Modify(SyscallPayload) }

// Extension registry — loaded at kernel startup, not recompile-time
pub struct ExtensionRegistry {
    extensions: Vec<Box<dyn KernelExtension>>,
}
```

**Safety guarantee** (eBPF analog): Extensions are verified at load time:
- No access to kernel internal state (only the provided hook arguments)
- Bounded execution: hooks must complete within 1ms or are killed
- No blocking I/O in hooks

**Use cases this enables**:
- Custom compliance auditors (HIPAA exporter that hooks `OnAuditEntry`)
- Domain-specific schedulers that hook `PreSyscall` to re-prioritize
- Custom PII detectors that hook `OnMemWrite`
- External SIEM integration that hooks `OnThreatDetected`

---

### P10 — Adaptive Scheduler: Workload-Aware Execution

**Research grounding**: SchedCP (arXiv:2509.01245) showed that LLM-driven `sched_ext` eBPF schedulers can achieve **1.79× performance on kernel compilation**, **2.11× P99 latency improvement**, and **13× cost reduction** over static schedulers by understanding workload semantics.

**The problem**: The current `VakyaRouter` makes routing decisions based on adapter availability only. It does not consider: cell load, inference latency, token cost, agent priority, deadline, or workload type.

**What the Agent OS needs**:

```rust
// ENHANCEMENT: aapi-pipeline/src/router.rs
pub struct AdaptiveVakyaRouter {
    ring: Arc<ConsistentHashRing>,
    workload_profiles: HashMap<String, WorkloadProfile>,
    cell_metrics: Arc<RwLock<HashMap<String, CellMetrics>>>,
    policy: SchedulingPolicy,
}

pub struct WorkloadProfile {
    pub workload_type: WorkloadType,
    pub avg_tokens: u32,
    pub avg_latency_ms: u64,
    pub priority: AgentPriority,
    pub deadline_ms: Option<u64>,
}

pub enum WorkloadType {
    Interactive,   // low latency critical (chat UI) — prefer fast cells, fast models
    Batch,         // throughput critical (bulk processing) — pack many into one cell
    Background,    // neither — run in idle slots
    Realtime,      // deadline-critical — preempt background work
}

pub struct CellMetrics {
    pub cell_id: String,
    pub active_agents: u32,
    pub queue_depth: u32,
    pub avg_inference_latency_ms: u64,
    pub token_throughput: u64,     // tokens/sec
    pub load: u8,                  // 0-100%
}
```

**Scheduling decisions**:
- `Interactive` workload → route to cell with lowest `avg_inference_latency_ms`
- `Batch` workload → route to cell with highest `token_throughput`
- `Realtime` → signal all lower-priority agents with `Suspend`; execute immediately
- `Background` → delay until cell `load < 50%`

---

### P11 — Cross-Org Agent Marketplace + Discovery

**The problem**: There is no `apt-get` for agents. An agent needs a capability ("translate medical records from Spanish to English") — there is no standard way to discover, verify, and delegate to an agent that has this capability, whether inside or outside the org.

**The ecosystem approach**: Agent Card + DNS-SD (`_agent._tcp.SRV` records) + a signed capability index stored in the VAC federation namespace.

**What the Agent OS needs**:

```rust
// NEW: aapi-federation/src/marketplace.rs
pub struct AgentMarketplace {
    local_registry: Arc<AgentRegistry>,
    federation_index: Arc<FederatedIndex>,
    trust_verifier: Arc<CrossCellCapabilityVerifier>,
}

pub struct AgentListing {
    pub card: AgentCard,
    pub provider_org: String,
    pub pricing: Option<AgentPricing>,
    pub health: AgentHealth,
    pub reviews: Vec<AgentReview>,     // usage attestations from other agents
    pub scitt_receipt: String,         // transparency attestation
}

pub struct AgentPricing {
    pub model: PricingModel,
    pub rate: f64,
    pub currency: String,
}

pub enum PricingModel {
    Free,
    PerCall { price_per_call: f64 },
    PerToken { price_per_1k: f64 },
    Subscription { price_monthly: f64 },
}

impl AgentMarketplace {
    // Discover agents by capability (local registry first, then federation)
    pub async fn discover(&self, capability: &str) -> Vec<AgentListing>;
    // Verify an agent card before delegating
    pub async fn verify_and_install(&self, listing: &AgentListing) -> DelegationChain;
    // DNS-SD: discover agents on local network
    pub async fn discover_local_network(&self) -> Vec<AgentCard>;
}
```

---

### P12 — Self-Healing Infrastructure: Agents That Fix Their Own OS

**The problem**: When a cell fails, the current system detects it (Membership) and redistributes traffic (ConsistentHashRing), but the healing is entirely passive — it relies on external operators to restart failed cells, repair database inconsistencies, or recover from cascading failures.

Linux analog: `systemd` watchdog, automatic service restart, `fsck` on boot, `smartd` for predictive disk failure.

**What the Agent OS needs**:

```rust
// NEW: connector-engine/src/watchdog.rs
pub struct SystemWatchdog {
    kernel: Arc<MemoryKernel>,
    behavior: Arc<BehaviorAnalyzer>,
    membership: Arc<Membership>,
    signal_bus: Arc<dyn EventBus>,
    rules: Vec<WatchdogRule>,
}

pub struct WatchdogRule {
    pub name: String,
    pub condition: WatchdogCondition,
    pub action: WatchdogAction,
    pub cooldown: Duration,   // don't trigger again within this window
}

pub enum WatchdogCondition {
    CellHeartbeatMissed { cell_id: String, timeout: Duration },
    AgentErrorRateHigh { agent_pid: String, threshold: f32 },
    TokenBudgetExhausted { agent_pid: String },
    MemoryQuotaExceeded { namespace: String, pct: u8 },
    ClusterPartitionDetected { min_betti_0: usize },
    StabilityIndexLow { threshold: f64 },
    ThreatScoreElevated { agent_pid: String, threshold: f64 },
    Custom(Box<dyn Fn(&WatchdogState) -> bool + Send + Sync>),
}

pub enum WatchdogAction {
    RestartAgent { agent_pid: String },
    SuspendAgent { agent_pid: String },
    EvictToTier { namespace: String, tier: MemoryTier },
    TriggerMerkleSync { cell_id: String },
    SendSignal { target_pid: String, signal: AgentSignal },
    NotifyHuman { message: String, channels: Vec<String> },
    ExecuteVakya { vakya: Vakya },    // self-healing via VAKYA pipeline
    Custom(Box<dyn Fn() + Send + Sync>),
}
```

**The deepest capability**: `WatchdogAction::ExecuteVakya` allows the OS to self-heal using its own agent execution engine. An agent CAN be the repair script. This is the Linux revolution equivalent: the OS can reconfigure itself at runtime using the same primitives it provides to applications.

---

## 5. What Already Exists (Do Not Rebuild)

These are the foundations the 12 primitives build on. Do **not** reimplement:

| Existing Component | Powers These New Primitives |
|-------------------|-----------------------------|
| `AgentControlBlock` (PCB) | P1 (add priority + budget fields), P3 (add signal handlers) |
| `DelegationChain` Ed25519 | P4 (DID = delegation chain with `did:` URI), P8 (mandate = attenuated delegation) |
| `ExecutionPolicy` + `BudgetPolicy` | P1 (extend with token quotas), P6 (extend with compute cgroups) |
| `ReplicationOp` enum | P3 (add `SignalDeliver` op type) |
| `ToolBinding` default-deny | P5 (MCP bridge wraps existing ToolBindings) |
| `FederatedPolicyEngine` | P4 (federation-level agent registry), P11 (marketplace trust) |
| `KernelAuditEntry` + SCITT | P7 (add `natural_language` + `business_impact` fields) |
| `AgentFirewall` | P5 (all protocol bridges feed through existing firewall) |
| `BehaviorAnalyzer` | P10 (workload profiles derive from behavior baselines) |
| `ClusterKernelStore` VFS trick | P6 (compute usage stored in VAC namespace) |
| `ConsistentHashRing` | P10 (adaptive routing extends ring with load metrics) |
| `CausalBraid` stability index | P12 (watchdog condition: `StabilityIndexLow`) |
| `SagaCoordinator` | P12 (self-healing rollback uses saga machinery) |
| `Port` system | P3 (signals delivered via typed ports) |
| `vac-crypto` | P4 (DID key material), P8 (mandate signatures) |

---

## 6. Protocol Landscape: MCP, A2A, ACP, ANP, AP2

### Current State (February 2026)

| Protocol | Status | Key Gap vs. Agent OS |
|----------|--------|---------------------|
| **MCP** (Anthropic) | ✅ W3C spec, widely deployed | Agent OS has no MCP server; ToolBindings not exposed as MCP tools |
| **A2A** (Google) | ✅ Open spec, growing adoption | Agent OS has no Agent Card endpoint; no `/.well-known/agent.json` |
| **ACP** (IBM/LF) | 🟡 Early, Linux Foundation | Close to `ReplicationOp::VakyaForward` — thin bridge needed |
| **ANP** | 🟡 Early, open community | Requires W3C DID support (new) |
| **AP2** (Google) | 🟡 Early, limited deployment | Requires `PaymentMandate` type (new), maps to `DelegationChain` |
| **AG-UI** | 🟡 Draft | Agent-User interaction standard — UI layer, not OS concern |

### Why the Agent OS Has a Structural Advantage

All four protocols require:
1. **Agent identity** → Agent OS has Ed25519 keypairs per cell, easily extended to DID
2. **Content-addressed state** → Agent OS has CIDs natively; MCP resources map to CIDs
3. **Delegation/attenuation** → Agent OS has UCAN-style `DelegationChain` natively
4. **Audit trail** → Agent OS has `KernelAuditEntry` + SCITT natively
5. **Policy engine** → Agent OS has `FederatedPolicyEngine` natively

The Agent OS is the only agentic infrastructure in the world where all five protocol prerequisites are **already built**. The bridges are thin.

---

## 7. The Linux Revolution Roadmap — Phased Build Plan

### Phase L1 — The Foundation (Months 1-2)
*Make the OS self-aware*

```
L1.1  Signal System (P3)
      - Add AgentSignal enum to vac-core/src/signal.rs
      - New SyscallPayload::SendSignal + RegisterSignalHandler
      - AgentControlBlock.signal_handlers field
      - Deliver signals via ReplicationOp::SignalDeliver (new op)
      - 15 tests: signal delivery, handler registration, default actions

L1.2  Semantic Telemetry (P7)
      - Extend KernelAuditEntry with natural_language + business_impact fields
      - SemanticTelemetryEngine with templates for all 20 kernel ops
      - OpenTelemetry gen_ai.* attributes on all spans
      - 10 tests: template rendering, OTel attribute emission
```

### Phase L2 — Compute Fairness (Months 2-3)
*Stop agent starvation*

```
L2.1  Token Budget System (partial P1 + P6)
      - TokenBudget struct in vac-core/src/types.rs
      - AgentControlBlock.token_budget field
      - DualDispatcher.gate_llm_call() — budget check before LlmRouter
      - KernelAuditEntry records token usage per LLM call
      - Signals: TokenBudgetWarning at 80%, TokenBudgetExhausted at 100%
      - 10 tests

L2.2  LLM Scheduler — FIFO + Round Robin (P1 core)
      - vac-core/src/scheduler.rs: LlmScheduler with FIFO + RR policies
      - AgentPriority enum + AgentControlBlock.priority field
      - Queue management: per-priority VecDeque
      - 10 tests: scheduling fairness, priority ordering

L2.3  ComputeCgroup (P6)
      - Hierarchical token accounting: org → team → agent
      - FinOps: cost_per_1k attribution to cost_center
      - Stored as SemanticAuditEntry in VAC namespace "sys:compute:usage"
      - 8 tests
```

### Phase L3 — Identity & Protocols (Months 3-4)
*Connect to the ecosystem*

```
L3.1  Agent DID + Agent Card (P4)
      - aapi-federation/src/identity.rs: AgentCard + AgentRegistry
      - DID generation: "did:connector:{cell_id}:{agent_pid}"
      - AgentRegistry stored in VAC namespace "sys:registry:agents"
      - connector-server: GET /.well-known/agent.json endpoint
      - 12 tests

L3.2  MCP Bridge (P5 — Phase 1)
      - connector/crates/connector-protocols/src/mcp.rs
      - Expose ToolBindings as MCP tools
      - Expose VAC namespaces as MCP resources (CID-addressed)
      - AgentFirewall gates all MCP calls
      - 15 tests

L3.3  A2A Bridge (P5 — Phase 2)
      - connector/crates/connector-protocols/src/a2a.rs
      - Agent Card serving + task receive/delegate
      - DelegationChain verification for cross-org tasks
      - 15 tests
```

### Phase L4 — Context & Self-Healing (Months 4-5)
*Make the OS resilient*

```
L4.1  Context Manager (P2)
      - connector-engine/src/context_manager.rs
      - TextBased snapshots for closed-source LLMs
      - Snapshots stored in VAC namespace "sys:context:snapshots"
      - LlmScheduler.preempt() → ContextManager.snapshot()
      - 10 tests

L4.2  System Watchdog (P12)
      - connector-engine/src/watchdog.rs
      - 8 WatchdogCondition types
      - 8 WatchdogAction types including ExecuteVakya
      - Default rules: cell down, memory pressure, error rate
      - 12 tests

L4.3  Adaptive Router (P10)
      - WorkloadProfile + CellMetrics in AdaptiveVakyaRouter
      - Route interactive→low-latency, batch→high-throughput
      - Cell metrics from Heartbeat { load } field (already exists)
      - 10 tests
```

### Phase L5 — Economic Primitives + Marketplace (Months 5-6)
*Enable the agent economy*

```
L5.1  Agent Payment Protocol (P8)
      - aapi-federation/src/payment.rs: PaymentMandate
      - Maps to DelegationChain with financial attenuation
      - SCITT receipt on every transaction
      - AgentFirewall gates: amount ≤ mandate.max_amount
      - 10 tests

L5.2  Agent Marketplace (P11)
      - aapi-federation/src/marketplace.rs: AgentMarketplace
      - AgentListing + AgentPricing structs
      - Local registry first, federation fallback
      - DNS-SD discovery for local network agents
      - 10 tests

L5.3  Kernel Extension Hooks (P9)
      - vac-core/src/extensions.rs: KernelExtension trait
      - 8 KernelHook types
      - ExtensionRegistry loaded at kernel startup
      - Safety verification: bounded execution, no kernel state access
      - 10 tests
```

---

## 8. Architecture: The Complete Agent OS Stack Post-Revolution

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    AGENT OS — LINUX REVOLUTION COMPLETE STACK                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│  AGENT MARKETPLACE & ECONOMY LAYER  (Phase L5)                                   │
│  ┌────────────────┐ ┌────────────────┐ ┌─────────────────────────────────────┐  │
│  │ AgentMarketplace│ │ PaymentMandate │ │ AgentCard + DID Registry            │  │
│  │ (apt for agents)│ │ (AP2 protocol) │ │ /.well-known/agent.json             │  │
│  └────────────────┘ └────────────────┘ └─────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  PROTOCOL BRIDGE LAYER  (Phase L3)                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ MCP      │  │ A2A      │  │ ACP      │  │ ANP      │  │ AG-UI            │  │
│  │ Bridge   │  │ Bridge   │  │ Bridge   │  │ Bridge   │  │ (future)         │  │
│  │ (Anthropic)│ │(Google) │  │ (Linux F)│  │ (Open)   │  │                  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────────────┘  │
│       └─────────────┴──────────────┴──────────────┘                             │
│                      ALL bridges feed through AgentFirewall                      │
├──────────────────────────────────────────────────────────────────────────────────┤
│  SELF-HEALING & OBSERVABILITY LAYER  (Phase L4)                                  │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────────┐  │
│  │ SystemWatchdog       │  │ SemanticTelemetry     │  │ ContextManager        │  │
│  │ 8 conditions         │  │ LLM-readable logs     │  │ Snapshot + Resume     │  │
│  │ 8 actions            │  │ OTel gen_ai.* attrs   │  │ TextBased + Logits    │  │
│  │ ExecuteVakya self-fix│  │ business_impact field │  │ CID-addressed in VAC  │  │
│  └──────────────────────┘  └──────────────────────┘  └───────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  COMPUTE FAIRNESS LAYER  (Phase L2)                                              │
│  ┌─────────────────────────────┐  ┌──────────────────────────────────────────┐  │
│  │ LlmScheduler                │  │ ComputeCgroup + TokenBudget              │  │
│  │ FIFO | RoundRobin | CFS     │  │ org → team → agent → request hierarchy  │  │
│  │ Preemption + context swap   │  │ FinOps: cost attribution per CID         │  │
│  │ AgentPriority: 5 levels     │  │ Signals: BudgetWarning + Exhausted       │  │
│  └─────────────────────────────┘  └──────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  SIGNAL SYSTEM  (Phase L1)                                                       │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ AgentSignal: Terminate | Kill | Suspend | Resume | Interrupt               │  │
│  │            + TokenBudgetWarning | MemoryPressure | SecurityAlert           │  │
│  │            + PeerDown | PolicyUpdated | ApprovalGranted | Custom           │  │
│  │ Delivery: ReplicationOp::SignalDeliver (new) over EventBus                 │  │
│  │ Handlers: AgentControlBlock.signal_handlers                                │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  KERNEL EXTENSION LAYER  (Phase L5)                                              │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ KernelExtension trait: PreSyscall | PostSyscall | OnMemWrite               │  │
│  │                       OnAuditEntry | OnThreatDetected | OnTokenExhausted  │  │
│  │ Safety: bounded execution (1ms), no kernel state access                    │  │
│  │ Uses: custom compliance, domain-specific schedulers, SIEM integrations     │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  EXISTING UNIX TIER (Already Built — Do Not Rebuild)                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Memory   │ │ Security │ │ Cluster  │ │ AAPI     │ │ LLM      │ │ Audit   │ │
│  │ Kernel   │ │ Firewall │ │ (CRDT +  │ │ Pipeline │ │ Router   │ │ (SCITT) │ │
│  │ (vac-core│ │ Behavior │ │ Ring +   │ │ Saga     │ │ Circuit  │ │         │ │
│  │ PCB)     │ │ Analyzer │ │ Merkle)  │ │ VakyaFwd │ │ Breaker) │ │         │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘

The Delta: Unix Tier (built) → Linux Revolution (6 phases, 12 primitives)
           ↑ What we have now          ↑ What this document specifies
```

---

## 9. Research Foundations

| Source | Finding Applied |
|--------|-----------------|
| **AIOS: LLM Agent Operating System** (arXiv:2403.16971v5) | LLM Core as CPU, Scheduler (FIFO+RR), Context Manager (text+logit snapshots), Memory Manager (LRU-K eviction), Tool Manager conflicts → P1, P2, P3 |
| **Towards Agentic OS** (arXiv:2509.01245v4, Google+CMU 2025) | SchedCP: safety-first kernel interfaces, eBPF-programmable schedulers, 1.79×/2.11× gains, 13× cost reduction → P1, P9, P10 |
| **AI 2026: Infrastructure** (Jimmy Song, 2026) | GPU utilization 30-40%, scheduling/isolation/quota primitive, agents are distributed systems, control plane needed → P6, P10, P12 |
| **Agentic Infrastructure Overhaul** (CIO.com, 2026) | Semantic telemetry, async/event-driven APIs, agent-readable logs → P7 |
| **Agent Interoperability Protocols Survey** (arXiv:2505.02279v1) | MCP/A2A/ACP/ANP gaps: no unified identity, no cross-org discovery, no standard context delivery → P4, P5 |
| **AI Agent Protocols Guide** (GetStream.io, 2026) | AP2 mandate types (Cart/Intent/Payment), role separation, cryptographic mandates → P8 |
| **Linux CFS/EEVDF, sched_ext** (kernel.org, Linux 6.12) | Virtual runtime fairness, eBPF scheduler safety, preemption model → P1, P9 |
| **W3C DID Specification** (W3C, 2022) | Decentralized identifier format, key material, resolution → P4, P5 |
| **UCAN Spec** (Fission.codes) | Capability attenuation, delegation chains — already implemented, extended for P8 |
| **NIST AI RMF** (2023) | Govern/Map/Measure/Manage framework — semantic telemetry enables all four → P7 |

---

*The Unix revolution gave us the primitives. The Linux revolution industrialized them. We have built the Unix tier. This document is the Linux revolution plan.*
