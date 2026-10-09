# 52 — Glue: The Unified Developer Surface

> **Status: Stub executor — not a shipping integration surface.**  
> Grammar / CNP handles exist in `connector-glue/`. Under `CONNECTOR_ENV=production` or defense-strict, the stub executor is **fail-closed** unless `CONNECTOR_GLUE_ALLOW_STUB=1` (lab break-glass). Operator honesty: **“Glue stub blocked in prod”** on `GET /api/v1/substrate/status` → `glue`. Prefer HTTP / `agos-sdk` for real integrations until Glue graduates.

---

## The Problem with SDKs

Every platform builds an SDK. SDKs create wrappers. Wrappers drift.

The Python SDK wraps the HTTP API. The TypeScript SDK wraps the Python SDK's semantics, imperfectly. The Go client is community-maintained and three months behind. Each wrapper adds a translation layer where governance context can be lost, audit metadata can be dropped, and policy intent can be misinterpreted.

More fundamentally: SDKs are imperative. They tell the system *how* to do something. Governance is declarative — it describes *what rules* apply, not how to execute them.

Glue is the answer to this problem. Glue is not a wrapper. Glue is a semantic surface: a language for expressing governed intent that compiles to correct execution regardless of which caller, which language, or which integration point is used.

---

## The Glue Grammar

Glue has three grammatical primitives: **verbs**, **nouns**, and **selectors**.

### Verbs — What to do

```rust
pub enum Verb {
    Run,        // Execute a governed task
    Remember,   // Write to governed memory
    Recall,     // Read from governed memory  
    Search,     // Semantic search with governance
    List,       // List governed resources
    Show,       // Surface a governed view
    Audit,      // Retrieve audit trail
    Verify,     // Cryptographic verification
    Print,      // Render to operator surface
    Inspect,    // Self-inspection (agent calling about itself)
}
```

### Nouns — What to act on

```
agent       memory      knowledge   tool
policy      session     protocol    pipeline
surface     contract    namespace   receipt
```

### Selectors — Scope and context

```
--in namespace      scope to memory namespace
--under policy      apply named policy
--as role           render as Developer/Operator/Auditor/Executive
--since time        time-bounded query
--for agent         target specific agent
--with audit        thread audit context through
```

---

## The Glue API (Rust)

The `Glue` struct in `connector-glue/src/lib.rs` exposes the full grammar as a fluent builder API:

```rust
use connector_glue::Glue;

let glue = Glue::new();

// Run a governed task
let result = glue
    .run("Summarize patient cardiac history")
    .for_agent("med-agent-01")
    .in_namespace("/p/hospital-a/patients/")
    .under_policy("hipaa-minimum-necessary")
    .with_audit()
    .execute()
    .await?;

// Write to governed memory
let cid = glue
    .remember("Patient had troponin elevation on 2026-04-12")
    .in_namespace("/p/hospital-a/patients/p_001/")
    .as_fact()
    .execute()
    .await?;

// Retrieve with governance context
let facts = glue
    .recall("cardiac risk factors")
    .for_agent("med-agent-01")
    .in_namespace("/p/hospital-a/")
    .top(10)
    .execute()
    .await?;

// Audit a decision
let trail = glue
    .audit("dec_a3f7b2c8d9e1f5a2")
    .since("2026-04-01")
    .as_role(Role::Auditor)
    .execute()
    .await?;

// Cryptographic verification
let proof = glue
    .verify("agent med-agent-01")
    .claim("data_minimization")
    .execute()
    .await?;
```

Every method on `Glue` returns a builder. Every builder has `.execute()`. Every execution is audited, journals a `decision_id`, and returns a typed result with `audit_cid`.

---

## CNP: The Connector Native Protocol

CNP (Connector Native Protocol) is the underlying wire protocol that Glue compiles to. While HTTP/REST is the external API, CNP is optimized for:

- Low-latency agent-to-agent communication
- Binary framing over TCP or Unix sockets
- Session multiplexing (many governed interactions over one connection)
- Streaming audit events
- Capability negotiation

The `connector-glue/` crate exposes CNP through typed handles:

```rust
// Open a governed session
let session = glue.session()
    .with_agent("med-agent-01")
    .with_namespace("/p/hospital-a/")
    .open()
    .await?;

// Agent-to-agent protocol
let protocol_handle = glue.protocol(ProtocolContract {
    source_agent: "coordinator",
    target_agent: "specialist",
    allowed_verbs: vec![Verb::Run, Verb::Recall],
    max_turns: 5,
});

// CNP port: typed communication channel
let port = glue.cnp_port(CnpPortContract {
    name: "query-channel",
    direction: Direction::Bidirectional,
    message_type: MessageType::GovernedQuery,
});

// CNP capability negotiation
let capability = glue.cnp_capability(CnpCapabilityContract {
    required: vec!["memory_read", "tool_call"],
    offered: vec!["audit_read"],
    trust_level: TrustLevel::Verified,
});

// CNP message with governance context
let response = glue.cnp_message(CnpMessageContract {
    to: "specialist-agent",
    content: query,
    governance_cid: "cls1-sha256-a3f7b2",
    audit_thread: current_audit_thread,
}).send().await?;
```

---

## Glue Runtime: Session, Intent, Audit Threading

`runtime.rs` manages the lifecycle of a Glue session:

**Session state** — Glue tracks what has happened in the current session: what was written to memory, what tools were called, what decisions were recorded. This enables compound operations where a later step can reference what an earlier step did.

**Intent tracking** — Every Glue operation has a declared intent. The runtime uses this to:
- Validate that the operation is coherent with the session's governance context
- Provide richer narration in audit trails ("agent recalled 3 cardiac facts before summarizing")
- Enable the HITL system to present meaningful context to human reviewers

**Audit threading** — Every Glue operation in a session shares an audit thread ID. This means that a complex multi-step workflow (recall → reason → write → surface) appears as a single coherent audit entry, not five unrelated journal entries. Forensic reconstruction becomes trivial.

```rust
let thread = glue.session().start_audit_thread("patient-qa-workflow");

let facts = glue.recall("cardiac history").in_thread(&thread).execute().await?;
let summary = glue.run("summarize").with_context(facts).in_thread(&thread).execute().await?;
let _ = glue.remember(summary).in_thread(&thread).execute().await?;

let audit = thread.close().generate_proof().await?;
// One proof covers the entire workflow, not three separate proofs
```

---

## Glue for Other Languages

Glue's grammar is language-agnostic. The Rust implementation is the reference. Bindings for other languages compile to the same CNP wire protocol and produce identical governance behavior.

**Python (via the Python SDK today, Glue bindings planned):**
```python
from connector import Glue

glue = Glue()
result = (glue
    .run("Summarize cardiac history")
    .for_agent("med-agent-01")
    .under_policy("hipaa-minimum-necessary")
    .execute())
```

**TypeScript (planned):**
```typescript
const result = await glue
  .run("Summarize cardiac history")
  .forAgent("med-agent-01")
  .underPolicy("hipaa-minimum-necessary")
  .execute();
```

**Go (planned):**
```go
result, err := glue.
    Run("Summarize cardiac history").
    ForAgent("med-agent-01").
    UnderPolicy("hipaa-minimum-necessary").
    Execute(ctx)
```

All three compile to the same CNP message. All three produce the same audit trail. The governance is not in the language binding — it is in the CLS contract and the Connector node.

---

## Why Glue and Not Just HTTP

| Concern | Raw HTTP | Glue |
|---------|----------|------|
| Audit threading | Manual, error-prone | Automatic |
| Policy application | Must be specified per call | Inherited from session |
| Error semantics | HTTP status codes + JSON | Typed `GlueError` with governance context |
| Agent-to-agent comms | HTTP round-trips | CNP multiplexed sessions |
| Multi-step workflows | Stateless, you track state | Stateful, Glue tracks |
| Compliance reporting | Assemble manually | `thread.generate_proof()` |
| Language consistency | Different wrappers, different bugs | One grammar, one behavior |

---

## The Future: Glue as the Standard Interface for Governed AI

The long-term role of Glue is as the standard interface for calling governed AI agents — the way REST is the standard interface for web services today.

Any system that wants to interact with a Connector-governed agent would use Glue. The agent might be running on a node in your data center, in a partner's cloud, or at the edge. The caller might be a Python script, a Go microservice, a Rust binary, or a bash pipeline. Glue provides one grammar that works everywhere, compiles to CNP, and produces identical governance and audit behavior regardless of caller.

Glue is not about making Connector easier to use. It is about making governed AI interoperable.
