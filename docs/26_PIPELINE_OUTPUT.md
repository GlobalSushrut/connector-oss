# Pipeline Output

> PipelineOutput, PipelineOutputExt, Provenance, ObservationEvent
> Source: `connector/crates/connector-engine/src/output.rs`, `connector-api/src/observe.rs`

---

## PipelineOutput

The return type of every `agent.run()` and `pipeline.run()` call:

```rust
pub struct PipelineOutput {
    // Core result
    pub text:        String,          // LLM response text
    pub ok:          bool,            // true if no errors
    pub verified:    bool,            // true if all events are kernel-verified

    // Trust
    pub trust:       u32,             // 0–100
    pub trust_grade: String,          // A+ | A | B | C | D | F

    // Provenance
    pub cid:         String,          // CID of the response packet
    pub trace_id:    String,          // pipeline trace ID

    // Observability
    pub trace:       Trace,           // full span tree
    pub events:      Vec<ObservationEvent>,
    pub warnings:    Vec<String>,
    pub errors:      Vec<String>,

    // AAPI summary
    pub aapi:        AapiSummary,

    // Memory summary
    pub memory:      MemorySummary,

    // Provenance summary
    pub provenance:  ProvenanceSummary,
}
```

---

## AapiSummary

```rust
pub struct AapiSummary {
    pub actions_authorized: u32,
    pub actions_denied:     u32,
    pub capabilities_issued: u32,
    pub budget_tokens_used:  u64,
    pub budget_cost_usd:     f64,
}
```

---

## MemorySummary

```rust
pub struct MemorySummary {
    pub packets_written: u32,
    pub packets_read:    u32,
    pub namespaces_used: Vec<String>,
    pub total_tokens:    u64,
}
```

---

## ProvenanceSummary

```rust
pub struct ProvenanceSummary {
    pub kernel_verified:   u32,   // events sourced from kernel audit
    pub llm_unverified:    u32,   // events from LLM (not kernel-verified)
    pub derived:           u32,   // events derived from kernel data
    pub user:              u32,   // events from user input
    pub total:             u32,
    pub trust_percentage:  f64,   // kernel_verified / total * 100
}
```

---

## Provenance

Every field in `PipelineOutput` is tagged with its source:

```rust
pub enum Provenance {
    Kernel,   // from real kernel audit log — trusted
    Llm,      // from LLM response — not cryptographically verified
    Derived,  // computed from kernel data — trusted
    User,     // from user input — not verified
}

pub struct Verified<T> {
    pub value:    T,
    pub source:   Provenance,
    pub cid:      Option<Cid>,  // evidence CID (if Kernel or Derived)
}

impl<T> Verified<T> {
    pub fn kernel(value: T) -> Self
    pub fn kernel_with_cid(value: T, cid: Cid) -> Self
    pub fn llm(value: T) -> Self
    pub fn derived(value: T) -> Self
    pub fn user(value: T) -> Self
    pub fn is_trusted(&self) -> bool  // true for Kernel and Derived
}
```

---

## ObservationEvent

Structured event stream from the kernel audit log:

```rust
pub struct ObservationEvent {
    pub event_type: String,       // "memory_stored" | "tool_called" | "access_granted" |
                                  // "access_denied" | "firewall_blocked" | "anomaly_detected"
    pub severity:   EventSeverity,
    pub message:    String,       // human-readable
    pub agent:      String,       // agent PID or name
    pub cid:        Option<String>, // evidence CID
    pub source:     Provenance,   // always Kernel for audit-derived events
    pub timestamp_ms: i64,
}

pub enum EventSeverity {
    Info,
    Warning,
    Error,
}
```

---

## PipelineOutputExt Methods

```rust
pub trait PipelineOutputExt {
    // Trust score (computed from kernel data)
    fn trust(&self) -> TrustScore;

    // Compliance report (evidence-based)
    fn comply(&self, framework: &str) -> ComplianceReport;
    // framework: "hipaa" | "soc2" | "gdpr" | "eu_ai_act" | "nist_ai_rmf" | "owasp_llm" | "maestro"

    // Time travel — reconstruct agent state at timestamp
    fn replay(&self, timestamp: &str) -> ReplaySnapshot;
    // timestamp: ISO 8601, e.g., "2025-02-21T09:30:00Z"

    // Decision X-Ray — why did the agent respond this way?
    fn xray(&self) -> XRayResult;

    // Audit trail
    fn audit(&self) -> AuditSummary;

    // Export formats
    fn to_json(&self) -> String;           // machine-parseable JSON with provenance tags
    fn to_otel(&self) -> String;           // OTLP-compatible resource_spans
    fn to_llm_summary(&self) -> String;    // LLM-friendly structured JSON

    // Zero-fake check
    fn all_observations_verified(&self) -> bool;
    // true if all events have source=Kernel

    // Provenance breakdown
    fn provenance_summary(&self) -> ProvenanceSummary;

    // Filter events by severity
    fn events_by_severity(&self, severity: EventSeverity) -> Vec<&ObservationEvent>;
}
```

---

## ReplaySnapshot

```rust
pub struct ReplaySnapshot {
    pub timestamp:    String,
    pub packets:      Vec<MemPacket>,   // packets that existed at that time
    pub agent_states: Vec<AgentInfo>,
    pub audit_window: Vec<AuditEntry>,
    pub snapshot_cid: String,
}
```

---

## XRayResult

```rust
pub struct XRayResult {
    pub response_text:    String,
    pub memories_used:    Vec<MemPacket>,   // packets injected into LLM context
    pub tools_called:     Vec<String>,
    pub reasoning_chain:  Option<ReasoningChain>,
    pub evidence_cids:    Vec<String>,
    pub quality_score:    f32,
    pub trust_score:      u32,
}
```

---

## Display Output

```
╔══════════════════════════════════════════════════════════╗
║  Connector Pipeline Output                               ║
║  Status: ✅ OK  |  Trust: 87/100 (A)  |  Verified: ✅   ║
╠══════════════════════════════════════════════════════════╣
║  Response [source: llm]                                  ║
║  Urgency 1. Differentials: ACS (I21.3), NSTEMI...       ║
╠══════════════════════════════════════════════════════════╣
║  Dashboard (all kernel-verified)                         ║
║  Memory: 4 packets written  |  Auth: 4 VAKYA tokens     ║
║  Compliance: HIPAA ✅  SOC2 ✅                           ║
╠══════════════════════════════════════════════════════════╣
║  Provenance: 4/4 events kernel-verified (zero-fake: ✅)  ║
║  Trace: 6 spans  |  ID: pipe:er:a3f8c1                  ║
╚══════════════════════════════════════════════════════════╝
```

---

## Trace

```rust
pub struct Trace {
    pub trace_id:  String,
    pub spans:     Vec<Span>,
    pub started_at: i64,
    pub ended_at:  Option<i64>,
    pub duration_ms: u64,
}

pub struct Span {
    pub span_id:   String,
    pub parent_id: Option<String>,
    pub name:      String,
    pub span_type: SpanType,
    pub status:    SpanStatus,
    pub started_at: i64,
    pub ended_at:  Option<i64>,
    pub duration_ms: u64,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

pub enum SpanType {
    Pipeline, Agent, LlmCall, ToolCall, MemoryRead, MemoryWrite,
    KernelOp, FirewallCheck, PolicyEval, Compliance,
}

pub enum SpanStatus { Ok, Error, Timeout }
```

---

## PipelineStatus

```rust
pub enum PipelineStatus {
    Success,
    PartialSuccess { warnings: Vec<String> },
    Failed { errors: Vec<String> },
    Blocked { reason: String },    // firewall or policy block
    BudgetExceeded { detail: String },
}
```
