# Code Dictionary — Rust

> Every Rust pattern explained: what to write, what it does, what you get back.
> Covers 3-line agent → builder API → expert config → raw kernel syscalls.

---

## How to Read This Dictionary

Each entry shows:
1. **The code** — exact, copy-pasteable
2. **What it does** — plain English
3. **What you get back** — exact return type and fields
4. **When to use it** — the right scenario

---

## Setup

```toml
# Cargo.toml
[dependencies]
connector-api = { path = "connector/crates/connector-api" }
```

```rust
use connector_api::{Connector, ConnectorResult};
```

---

## Pattern 1 — Hello World (3 lines)

```rust
let c = Connector::new()
    .llm("deepseek", "deepseek-chat", "sk-...")
    .build();

let out = c.agent("bot")
    .instructions("You are a helpful assistant.")
    .run("What is 2+2?", "user:alice")?;

println!("{}", out.text);
println!("Trust: {}/{} ({})", out.trust, 100, out.trust_grade);
```

**What you get back:**
```rust
out.text          // String — LLM response
out.trust         // u32 — 0-100
out.trust_grade   // String — "A+" | "A" | "B" | "C" | "D" | "F"
out.ok            // bool
out.verified      // bool
out.cid           // String — CID of response packet
out.trace_id      // String
out.warnings      // Vec<String>
out.errors        // Vec<String>
```

**When to use:** Any simple chatbot, internal tool, proof of concept.

---

## Pattern 2 — Load from YAML

```rust
use connector_api::Connector;

let c = Connector::from_config("connector.yaml")?;
// Reads file, interpolates ${ENV_VAR}, validates all fields
// Raises ConfigError if required field missing or env var not set

let out = c.agent("bot")
    .instructions("You are helpful.")
    .run("Hello!", "user:alice")?;
```

**When to use:** All production code. Never hardcode API keys.

---

## Pattern 3 — Builder Pattern (Intermediate)

```rust
use connector_api::{Connector, SecurityConfig, SigningAlgorithm};

let c = Connector::new()
    .llm("deepseek", "deepseek-chat", &api_key)
    .storage("redb:./data/agent.redb")
    .compliance(&["hipaa", "soc2"])
    .security(SecurityConfig {
        signing: Some(SigningAlgorithm::Ed25519),
        data_classification: Some("PHI".to_string()),
        jurisdiction: Some("US".to_string()),
        retention_days: 2555,
        ..Default::default()
    })
    .build();
```

**When to use:** Production agents where you need explicit security settings.

---

## Pattern 4 — Agent with Tools

```rust
let out = c.agent("doctor")
    .instructions("Diagnose patients based on symptoms and vitals.")
    .role("tool_agent")
    .allow_tools(&["read_ehr", "write_diagnosis"])
    .require_approval(&["prescribe_medication"])
    .memory_from(&["triage"])   // read triage agent's namespace
    .run("Diagnose patient P-001", "patient:P-001")?;

// Check if any tools were called
println!("Steps: {:?}", out.steps);
println!("Events: {}", out.event_count);
```

**What `.memory_from()` does:** Creates `AccessGrant` syscalls at run time so this agent can read the `triage` namespace. Without this, reading `ns:triage` returns `OpOutcome::Denied`.

**What `.require_approval()` does:** Any call to `prescribe_medication` suspends and waits for human approval before executing.

---

## Pattern 5 — Multi-Agent Pipeline (n8n-Simple API)

```rust
use connector_api::{Connector, Action};

let pipeline = Connector::pipeline("er_pipeline")
    .llm("deepseek", "deepseek-chat", &api_key)
    .compliance(&["hipaa"])
    .node("triage", "Classify patients by urgency 1-5", |n| n
        .can(Action::new("classify_patient"))
        .role("writer")
    )
    .node("doctor", "Diagnose and prescribe treatment", |n| n
        .can(Action::new("read_ehr"))
        .can(Action::new("prescribe_medication").needs_approval())
        .role("tool_agent")
    )
    .node("pharmacist", "Verify and dispense medication", |n| n
        .can(Action::new("dispense_medication").needs_approval())
    )
    .route("triage -> doctor -> pharmacist")
    // ^ auto-wires memory_from: doctor reads triage, pharmacist reads triage+doctor
    .hipaa("US", 2555)
    .build();

let out = pipeline.run("Patient: 45M, chest pain 2h, BP 158/95", "patient:P-001")?;
println!("{}", out.text);
println!("Trust: {}/100 ({})", out.trust, out.trust_grade);
```

**What `.route()` does:** Auto-wires `memory_from` between connected agents — no manual `AccessGrant` needed.

**What `.hipaa()` does:** Sets `comply=["hipaa"]`, `data_classification=PHI`, `jurisdiction=US`, `retention_days=2555`, `signing=true` in one call.

---

## Pattern 6 — Expert Security Config

```rust
use connector_api::{
    Connector, SecurityConfig, SigningAlgorithm,
    FirewallConfig, BehaviorConfig,
};
use connector_engine::firewall::FirewallPreset;

let c = Connector::new()
    .llm("deepseek", "deepseek-chat", &api_key)
    .storage("redb:./data/hospital.redb")
    .security(SecurityConfig {
        signing:             Some(SigningAlgorithm::Ed25519),
        scitt:               true,
        data_classification: Some("PHI".to_string()),
        jurisdiction:        Some("US".to_string()),
        retention_days:      2555,
        require_mfa:         true,
        max_delegation_depth: 3,
        key_rotation_days:   90,
        audit_export:        Some("otel".to_string()),
        ..Default::default()
    })
    .firewall(FirewallConfig::preset(FirewallPreset::Hipaa))
    .behavior(BehaviorConfig {
        window_ms:              60_000,
        anomaly_threshold:      0.7,
        max_actions_per_window: 100,
        ..Default::default()
    })
    .build();
```

---

## Pattern 7 — Observability

```rust
use connector_api::PipelineOutputExt;

let out = pipeline.run("message", "user:alice")?;

// Trust score (kernel-derived, not self-reported)
let trust = out.trust();
println!("Score: {}/100 ({})", trust.score, trust.grade);
println!("Memory integrity:       {}/20", trust.dimensions.memory_integrity);
println!("Audit completeness:     {}/20", trust.dimensions.audit_completeness);
println!("Authorization coverage: {}/20", trust.dimensions.authorization_coverage);
println!("Decision provenance:    {}/20", trust.dimensions.decision_provenance);
println!("Operational health:     {}/20", trust.dimensions.operational_health);

// Compliance report (evidence-based)
let hipaa = out.comply("hipaa");
println!("HIPAA: {:.1}/100 ({})", hipaa.score, hipaa.grade);
for control in &hipaa.controls {
    println!("  {} [{}] {}", 
        control.control_id,
        if control.satisfied { "✅" } else { "❌" },
        control.description
    );
}

// Export formats
let json_str  = out.to_json();     // machine-readable with provenance tags
let otel_str  = out.to_otel();     // OTLP spans
let llm_str   = out.to_llm_summary(); // feed to another LLM

// Zero-fake check
let all_verified = out.all_observations_verified();
println!("Zero-fake: {}", if all_verified { "✅" } else { "⚠️" });

// Provenance breakdown
let prov = out.provenance_summary();
println!("Kernel-verified: {}/{} ({:.1}%)",
    prov.kernel_verified, prov.total, prov.trust_percentage);
```

---

## Pattern 8 — Raw Kernel Access (Layer 3)

```rust
use connector_api::Connector;
use connector_engine::kernel_ops::KernelOps;

let c = Connector::new()
    .llm("deepseek", "deepseek-chat", &api_key)
    .build();

// Get kernel ops handle
let ops = c.kernel_ops();

// List all agents
let agents = ops.list_agents();
for agent in &agents {
    println!("Agent: {} ({})", agent.name, agent.pid);
    println!("  Packets: {}", agent.packet_count);
    println!("  Status:  {}", agent.status);
}

// Get audit tail
let audit = ops.audit_tail(20);
for entry in &audit {
    println!("[{:8}] {:20} {}µs  {}",
        entry.outcome,
        entry.operation,
        entry.duration_us,
        entry.target_cid.as_deref().unwrap_or("-")
    );
}

// Export full kernel state as JSON
let json = ops.export_json(50);
println!("{}", json);

// Integrity check
let (ok, errors) = ops.integrity_check();
println!("Integrity: {} ({} errors)", if ok { "PASS" } else { "FAIL" }, errors);
```

---

## Pattern 9 — Direct Kernel Syscalls (Layer 3 — Advanced)

```rust
use vac_core::{
    MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue,
    MemoryKernelOp, MemPacket, PacketType, Source, SourceKind,
    ContentPlane, ProvenancePlane, AuthorityPlane, Epistemic,
};
use vac_core::cid::compute_cid;

// Build a kernel directly
let mut kernel = MemoryKernel::new();

// Register an agent
let reg = kernel.dispatch(SyscallRequest {
    agent_pid: "system".to_string(),
    operation: MemoryKernelOp::AgentRegister,
    payload: SyscallPayload::AgentRegister {
        agent_name: "analyst".to_string(),
        namespace:  "ns:analyst".to_string(),
        role:       Some("writer".to_string()),
        model:      Some("deepseek-chat".to_string()),
        framework:  Some("connector".to_string()),
    },
    reason:   Some("Register analyst agent".to_string()),
    vakya_id: None,
});
let pid = match reg.value {
    SyscallValue::AgentPid(p) => p,
    _ => panic!("Expected AgentPid"),
};
println!("Agent PID: {}", pid);   // "pid:000001"

// Start the agent
kernel.dispatch(SyscallRequest {
    agent_pid: pid.clone(),
    operation: MemoryKernelOp::AgentStart,
    payload:   SyscallPayload::Empty,
    reason:    None,
    vakya_id:  None,
});

// Build a packet manually
let payload = serde_json::json!({
    "text": "Patient allergic to Penicillin",
    "entity": "patient:P-001"
});
let payload_cid = compute_cid(&payload).unwrap();

let packet = MemPacket {
    content: ContentPlane {
        packet_type:    PacketType::Extraction,
        payload:        payload,
        payload_cid:    payload_cid,
        schema_version: "1.0".to_string(),
        encoding:       "json".to_string(),
        entities:       vec!["patient:P-001".to_string(), "penicillin".to_string()],
        tags:           vec!["allergy".to_string(), "PHI".to_string()],
        chapter_hint:   None,
    },
    provenance: ProvenancePlane {
        source:       Source { kind: SourceKind::Tool, principal_id: "ehr-system".to_string() },
        trust_tier:   2,
        evidence_refs: vec![],
        confidence:   Some(0.99),
        epistemic:    Epistemic::Verified,
        supersedes:   None,
        reasoning:    Some("Extracted from EHR allergy list".to_string()),
        domain_code:  Some("Z88.0".to_string()),  // ICD-10: Allergy to penicillin
    },
    authority: AuthorityPlane {
        vakya_id:    None,
        actor:       Some(pid.clone()),
        capability:  None,
        namespace:   "ns:analyst".to_string(),
        session_id:  None,
        subject_id:  "patient:P-001".to_string(),
        pipeline_id: "pipeline:ehr-ingest".to_string(),
        timestamp:   chrono::Utc::now().timestamp_millis(),
    },
};

// Write the packet
let write = kernel.dispatch(SyscallRequest {
    agent_pid: pid.clone(),
    operation: MemoryKernelOp::MemWrite,
    payload:   SyscallPayload::MemWrite { packet },
    reason:    Some("Store allergy from EHR".to_string()),
    vakya_id:  None,
});
let cid = match write.value {
    SyscallValue::Cid(c) => c,
    _ => panic!("Expected Cid"),
};
println!("Stored CID: {}", cid);
println!("Audit: {:?}", write.audit_entry.outcome);
```

**When to use:** Kernel plugin development, custom storage backends, testing kernel behavior directly.

---

## Pattern 10 — Persistent Storage

```rust
use connector_api::Connector;

// Create connector with persistent storage
let c = Connector::new()
    .llm("deepseek", "deepseek-chat", &api_key)
    .storage("redb:./data/agent.redb")
    .build();

// Run some agents...
let out = c.agent("bot").instructions("...").run("Hello", "user:alice")?;

// Save kernel state to disk
c.save()?;
println!("Saved {} packets", c.packet_count());

// --- Later, in a new process ---

let c2 = Connector::new()
    .llm("deepseek", "deepseek-chat", &api_key)
    .storage("redb:./data/agent.redb")
    .build();

// Restore from disk
c2.load()?;
println!("Restored {} packets", c2.packet_count());
// All agents, sessions, packets, and audit trail are back
```

---

## Pattern 11 — Encrypted Storage

```rust
use vac_core::store::{EncryptedStore, InMemoryKernelStore};

// 256-bit encryption key (store this securely — in HSM or env var)
let key: [u8; 32] = [/* your 32-byte key */];

// Wrap any store with encryption
let encrypted_store = EncryptedStore::new(
    InMemoryKernelStore::new(),
    key,
);
// All writes encrypted, all reads decrypted — kernel sees no difference
// Payloads stored as {"__encrypted": true, "__data": "<hex>"}
```

---

## Pattern 12 — Compliance Report (Rust)

```rust
use connector_api::PipelineOutputExt;
use connector_engine::compliance::Standard;

let out = pipeline.run("Assess patient risk", "patient:P-001")?;

// HIPAA report
let hipaa = out.comply("hipaa");
println!("HIPAA Score: {:.0}/100 ({})", hipaa.score, hipaa.grade);
// hipaa.grade: "PASS" | "PARTIAL" | "FAIL"

// SOC2 report
let soc2 = out.comply("soc2");

// EU AI Act report
let eu_ai = out.comply("eu_ai_act");

// All controls with evidence
for control in &hipaa.controls {
    println!("  {} [{}] evidence={:?}",
        control.control_id,
        if control.satisfied { "PASS" } else { "FAIL" },
        control.evidence_type
    );
}
```

---

## Pattern 13 — Replay (Time Travel)

```rust
use connector_api::PipelineOutputExt;

let out = pipeline.run("Diagnose patient", "patient:P-001")?;

// Replay agent state at a past timestamp
let snapshot = out.replay("2025-02-21T09:30:00Z");
println!("Packets at that time: {}", snapshot.packets.len());
println!("Agent states: {:?}", snapshot.agent_states);

// X-Ray — why did the agent respond this way?
let xray = out.xray();
println!("Memories used: {}", xray.memories_used.len());
println!("Tools called:  {:?}", xray.tools_called);
println!("Quality score: {:.2}", xray.quality_score);
if let Some(chain) = &xray.reasoning_chain {
    println!("Reasoning: {}", chain.conclusion);
}
```

---

## Pattern 14 — DoD Military Grade

```rust
use connector_api::{Connector, SecurityConfig, SigningAlgorithm, FirewallConfig};
use connector_engine::firewall::FirewallPreset;

let c = Connector::new()
    .llm("ollama", "llama3.2", "local")   // air-gapped, local model
    .storage("redb:./data/classified.redb")
    .compliance(&["dod"])
    .security(SecurityConfig {
        signing:              Some(SigningAlgorithm::Ed25519),
        scitt:                true,
        data_classification:  Some("TOP_SECRET".to_string()),
        jurisdiction:         Some("US".to_string()),
        retention_days:       3650,
        require_mfa:          true,
        max_delegation_depth: 1,   // no delegation
        key_rotation_days:    30,
        audit_export:         Some("json".to_string()),
        ..Default::default()
    })
    .firewall(FirewallConfig {
        preset: Some(FirewallPreset::Strict),
        block_injection_by_default: true,
        max_calls_per_minute: 5,
        ..Default::default()
    })
    .build();

let out = c.agent("intel_analyst")
    .instructions("Analyze intelligence. Cite all sources. Never speculate.")
    .role("writer")
    .run("Analyze SIGINT report #7734", "operator:ID-7734")?;

// Hard gates before using output
assert!(out.verified, "Output not kernel-verified");
assert!(out.trust >= 90, "Trust score {} below threshold", out.trust);
assert!(out.ok, "Agent failed: {:?}", out.errors);

// Chain-of-custody
println!("CID: {}", out.cid);   // immutable proof of this output
println!("Trust: {}/100 ({})", out.trust, out.trust_grade);
```

---

## Complete Type Reference

### ConnectorBuilder methods
```rust
Connector::new() -> ConnectorBuilder
.llm(provider, model, api_key) -> Self
.storage(uri) -> Self           // "memory://" | "redb:path" | "*.redb"
.compliance(frameworks) -> Self // &["hipaa", "soc2", ...]
.security(SecurityConfig) -> Self
.firewall(FirewallConfig) -> Self
.behavior(BehaviorConfig) -> Self
.build() -> Connector
Connector::from_config(path) -> ConnectorResult<Connector>
Connector::pipeline(name) -> PipelineBuilder
```

### AgentBuilder methods
```rust
c.agent(name) -> AgentBuilder
.instructions(text) -> Self
.role(role) -> Self             // "writer" | "reader" | "tool_agent" | "supervisor"
.allow_tools(tools) -> Self
.require_approval(tools) -> Self
.memory_from(namespaces) -> Self
.action(Action) -> Self
.run(message, user_id) -> ConnectorResult<PipelineOutput>
.remember(text, user_id) -> ConnectorResult<String>  // returns CID
.recall(query, user_id) -> ConnectorResult<Vec<MemPacket>>
```

### PipelineBuilder methods (n8n-Simple)
```rust
Connector::pipeline(name) -> PipelineBuilder
.llm(provider, model, api_key) -> Self
.compliance(frameworks) -> Self
.node(name, desc, |n| n.can(action)) -> Self
.route("a -> b -> c") -> Self
.hipaa(jurisdiction, retention_days) -> Self
.soc2() -> Self
.gdpr(retention_days) -> Self
.dod() -> Self
.signed() -> Self
.build() -> Pipeline
pipeline.run(message, user_id) -> ConnectorResult<PipelineOutput>
```

### ConnectorError variants
```rust
ConnectorError::KernelError(String)
ConnectorError::LlmError(String)
ConnectorError::StorageError(String)
ConnectorError::ConfigError(String)
ConnectorError::FirewallBlocked(String)
ConnectorError::BudgetExceeded(String)
ConnectorError::PolicyDenied(String)
ConnectorError::NotFound(String)
```
