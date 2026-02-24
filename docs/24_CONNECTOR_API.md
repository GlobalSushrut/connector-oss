# Connector API

> Connector, AgentBuilder, PipelineBuilder, 4 progressive layers
> Source: `connector/crates/connector-api/src/`

---

## 4 Progressive Layers

```
Layer 0 — 3-line agent (anyone):
  let c = Connector::new()
      .llm("deepseek", "deepseek-chat", "sk-...")
      .build();
  let out = c.agent("bot")
      .instructions("You are helpful")
      .run("Hello!", "user:alice")?;

Layer 1 — Builder pattern (intermediate):
  Connector::pipeline("hospital")
      .llm("deepseek", "deepseek-chat", "sk-...")
      .memory("redb:./hospital.redb")
      .compliance(&["hipaa"])
      .node("triage", "Classify patients", |n| n.can(classify_action))
      .node("doctor", "Diagnose and treat", |n| n.can(diagnose_action).can(prescribe_action))
      .route("triage -> doctor -> pharmacist")
      .hipaa("US", 2555)
      .build()

Layer 2 — Expert configuration (security engineers):
  .security(|s| s
      .signing(Ed25519)
      .scitt(true)
      .classification("PHI")
      .jurisdiction("US")
      .retention_days(2555)
  )
  .firewall(|f| f.preset("hipaa").block_injection(true))
  .behavior(|b| b.window_ms(60_000).anomaly_threshold(0.7))

Layer 3 — Raw kernel access (kernel developers):
  let ops = c.kernel_ops();
  ops.list_agents()
  ops.audit_tail(50)
  ops.export_json(100)
  ops.integrity_check()
```

---

## Connector

```rust
// connector-api/src/connector.rs
pub struct Connector {
    pub(crate) llm_config:    Option<LlmConfig>,
    pub(crate) memory_config: Option<MemoryConfig>,
    pub(crate) compliance:    Vec<String>,
    pub(crate) security:      SecurityConfig,
    pub(crate) kernel:        Arc<RwLock<MemoryKernel>>,  // shared across all agents
    pub(crate) store:         Arc<Mutex<Box<dyn KernelStore + Send>>>,
    pub(crate) storage_uri:   Option<String>,
}
```

**Shared kernel**: All agents created from the same `Connector` share the same `MemoryKernel` via `Arc<RwLock<>>`. Reads (packet_count, audit, trust) are concurrent; writes (run, remember, recall) are exclusive.

```rust
impl Connector {
    pub fn new() -> ConnectorBuilder
    pub fn pipeline(name: &str) -> PipelineBuilder
    pub fn agent(&self, name: &str) -> AgentBuilder
    pub fn llm_config(&self) -> Option<&LlmConfig>
    pub fn compliance(&self) -> &[String]
    pub fn security(&self) -> &SecurityConfig
    pub fn packet_count(&self) -> usize
    pub fn audit_count(&self) -> usize
    pub fn save(&self) -> Result<(), String>   // flush kernel to store
    pub fn load(&mut self) -> Result<(), String> // restore from store
}
```

---

## ConnectorBuilder

```rust
pub struct ConnectorBuilder {
    llm_config:    Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance:    Vec<String>,
    security:      SecurityConfig,
    storage_uri:   Option<String>,
}

impl ConnectorBuilder {
    pub fn llm(self, provider: &str, model: &str, api_key: &str) -> Self
    pub fn memory(self, uri: &str) -> Self          // alias for storage()
    pub fn storage(self, uri: &str) -> Self         // "memory" | "redb:path" | "*.redb"
    pub fn compliance(self, frameworks: &[&str]) -> Self
    pub fn security(self, config: SecurityConfig) -> Self
    pub fn build(self) -> Connector
}
```

---

## AgentBuilder

```rust
// connector-api/src/agent.rs
pub struct AgentBuilder<'c> {
    name:             String,
    connector:        &'c Connector,
    instructions:     Option<String>,
    allowed_tools:    Vec<String>,
    require_approval: Vec<String>,
    memory_from:      Vec<String>,
    role:             String,
    actions:          Vec<Action>,
}

impl<'c> AgentBuilder<'c> {
    pub fn instructions(self, text: &str) -> Self
    pub fn role(self, role: &str) -> Self
    pub fn allow_tools(self, tools: &[&str]) -> Self
    pub fn require_approval(self, tools: &[&str]) -> Self
    pub fn memory_from(self, namespaces: &[&str]) -> Self
    pub fn action(self, action: Action) -> Self
    pub fn actions(self, actions: Vec<Action>) -> Self

    // Execute
    pub fn run(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput>
    pub fn remember(self, text: &str, user_id: &str) -> ConnectorResult<String>  // returns CID
    pub fn recall(self, query: &str, user_id: &str) -> ConnectorResult<Vec<MemPacket>>
}
```

---

## PipelineBuilder

```rust
// connector-api/src/pipeline.rs
pub struct PipelineBuilder {
    name:          String,
    llm_config:    Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance:    Vec<String>,
    security:      SecurityConfig,
    actors:        Vec<ActorDef>,
    flow:          Option<FlowDef>,
    data:          DataConfig,
    output_guards: Vec<OutputGuard>,
    rate_limit:    Option<u32>,
    budget_tokens: Option<u64>,
    budget_cost:   Option<f64>,
}
```

### n8n-Simple API (new)

```rust
// .node() — agent IS a node
.node("triage", "Classify patients by urgency", |n| n
    .can(classify_action)
    .role("writer")
)

// .route() — one-line flow, auto-wires memory_from
.route("triage -> doctor -> pharmacist")
// equivalent to:
// .flow(|f| f.start("triage").then("doctor").then("pharmacist"))
// + doctor.memory_from(["triage"])
// + pharmacist.memory_from(["triage", "doctor"])

// Compliance shorthands
.hipaa("US", 2555)   // sets comply=["hipaa"], classification=PHI, jurisdiction=US, retention_days=2555
.soc2()              // adds "soc2" to comply list
.gdpr(1825)          // sets comply=["gdpr"], classification=PII, jurisdiction=EU, retention_days=1825
.dod()               // sets comply=["dod"], classification=TOP_SECRET, jurisdiction=US, signing=Ed25519, require_mfa=true
.signed()            // Ed25519 + SCITT audit trail
```

### NodeBuilder

```rust
pub struct NodeBuilder {
    name:             String,
    description:      String,
    actions:          Vec<Action>,
    role:             Option<String>,
    denied_data:      Vec<String>,
}

impl NodeBuilder {
    pub fn can(self, action: Action) -> Self
    // Auto-wires from Action:
    //   action.name → allowed_tools
    //   action.needs_approval() → require_approval
    //   action.data_classification → allowed_data

    pub fn role(self, role: &str) -> Self
    pub fn deny_data(self, classification: &str) -> Self
}
```

### Old verbose API (still works)

```rust
.actor("triage", |a| a
    .instructions("Classify patients")
    .role("writer")
    .allow_tools(&["classify"])
)
.actor("doctor", |a| a
    .role("tool_agent")
    .allow_tools(&["read_ehr", "write_notes"])
    .require_approval(&["write_notes"])
    .memory_from(&["triage"])
)
.flow(|f| f.start("triage").then("doctor"))
```

---

## PipelineOutputExt

```rust
// connector-api/src/agent.rs
pub trait PipelineOutputExt {
    fn trust(&self) -> TrustScore;
    fn comply(&self, framework: &str) -> ComplianceReport;
    fn replay(&self, timestamp: &str) -> ReplaySnapshot;
    fn xray(&self) -> XRayResult;
    fn audit(&self) -> AuditSummary;
    fn to_json(&self) -> String;
    fn to_otel(&self) -> String;
    fn to_llm_summary(&self) -> String;
}
```

---

## OutputGuard

Post-processing validators applied to every `PipelineOutput`:

```rust
pub struct OutputGuard {
    pub name:      String,
    pub check:     Box<dyn Fn(&PipelineOutput) -> GuardResult>,
}

pub enum GuardResult {
    Pass,
    Warn(String),
    Block(String),
}
```

---

## ConnectorResult / ConnectorError

```rust
pub type ConnectorResult<T> = Result<T, ConnectorError>;

pub enum ConnectorError {
    KernelError(String),
    LlmError(String),
    StorageError(String),
    ConfigError(String),
    FirewallBlocked(String),
    BudgetExceeded(String),
    PolicyDenied(String),
    NotFound(String),
}
```
