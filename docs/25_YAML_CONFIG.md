# YAML Config

> ConnectorConfig, 3-tier design, all fields, env-var interpolation
> Source: `connector/crates/connector-api/src/config.rs`

---

## 3-Tier Design

```
Tier 1 — MANDATORY:
  connector.provider, connector.model, connector.api_key
  Runtime error if absent (or env var not set).

Tier 2 — DEFAULT (omit = safe defaults apply):
  All other connector.* fields, security, firewall, behavior,
  checkpoint, memory, judgment, router.

Tier 3 — OPTIONAL-REVOKE (absent = feature OFF, present = feature ON):
  cluster, swarm, streaming, mcp, server, perception,
  cognitive, tracing_config, observability.
  Setting these fields activates the capability; removing them disables it.
```

---

## Full ConnectorConfig

```rust
pub struct ConnectorConfig {
    // Tier 1+2: Core
    pub connector: GlobalConfig,
    pub agents:    HashMap<String, AgentConfig>,
    pub pipelines: HashMap<String, PipelineConfig>,
    pub tools:     HashMap<String, ToolConfig>,
    pub policies:  HashMap<String, PolicyConfig>,

    // Tier 2: Optional with defaults
    pub knowledge: Option<KnowledgeConfig>,
    pub rag:       Option<RagConfig>,
    pub memory:    Option<MemoryManagementConfig>,
    pub judgment:  Option<JudgmentConfig>,

    // Tier 3: Optional-Revoke
    pub cluster:        Option<ClusterConfig>,
    pub swarm:          Option<SwarmConfig>,
    pub streaming:      Option<StreamingConfig>,
    pub mcp:            Option<McpConfig>,
    pub server:         Option<ServerConfig>,
    pub perception:     Option<PerceptionConfig>,
    pub cognitive:      Option<CognitiveConfig>,
    pub tracing_config: Option<TracingConfig>,
    pub observability:  Option<ObservabilityConfig>,
}
```

---

## GlobalConfig (connector:)

```yaml
connector:
  # Tier 1 — MANDATORY
  provider: deepseek                    # LLM provider
  model: deepseek-chat                  # model name
  api_key: ${DEEPSEEK_API_KEY}          # env-var interpolated

  # LLM options
  endpoint: https://api.deepseek.com    # custom base URL (optional)
  max_tokens: 4096
  temperature: 0.7
  system_prompt: "You are a helpful assistant."

  # Fallbacks (tried in order if primary fails)
  fallbacks:
    - provider: openai
      model: gpt-4o-mini
      api_key: ${OPENAI_API_KEY}

  # Router
  router:
    retry:
      max_retries: 3
      base_delay_ms: 500
      max_delay_ms: 10000
    circuit_breaker:
      failure_threshold: 5
      cooldown_secs: 30

  # Storage
  storage: redb:./data.redb             # memory:// | redb:<path> | prolly:<path>

  # Compliance
  comply: [hipaa, soc2]                 # hipaa | soc2 | gdpr | eu_ai_act | dod

  # Sub-configs (Tier 2)
  security:
    signing: true                       # Ed25519 packet signing
    scitt: false                        # SCITT receipt anchoring
    key_rotation_days: 90
    data_classification: PHI            # PHI | PII | confidential | internal | public
    jurisdiction: US                    # US | EU | UK | CA | AU
    retention_days: 2555
    require_mfa: false
    max_delegation_depth: 3
    ip_allowlist: []
    audit_export: json                  # json | csv | otel

  firewall:
    preset: hipaa                       # default | strict | hipaa
    block_injection: true
    injection_threshold: 0.3
    pii_types: [ssn, credit_card, email, phone, dob, medical_record]
    pii_threshold: 0.5
    blocked_tools: []
    max_calls_per_minute: 60
    max_input_length: 32768
    weights:
      injection: 0.35
      pii: 0.30
      anomaly: 0.20
      policy_violation: 0.25
      rate_pressure: 0.15
      boundary_crossing: 0.10
    thresholds:
      warn: 0.3
      review: 0.6
      block: 0.8

  behavior:
    window_ms: 60000
    baseline_sample_size: 100
    anomaly_threshold: 0.7
    max_actions_per_window: 100
    max_tool_diversity: 20
    max_error_rate: 0.3
    max_data_volume: 10485760           # 10MB in bytes
    detect_contamination: true

  checkpoint:
    write_through: true
    wal_enabled: true
    auto_checkpoint_threshold: 1000     # flush every N writes
```

---

## AgentConfig (agents:)

```yaml
agents:
  triage:
    instructions: "Classify patients by urgency level 1-5."
    role: writer
    model: deepseek-chat                # overrides connector.model
    tools: [classify_patient, lookup_vitals]
    require_approval: []
    memory_from: []
    namespace: ns:triage                # default: ns:<agent_name>

  doctor:
    instructions: "Diagnose based on triage data."
    role: tool_agent
    tools: [read_ehr, write_diagnosis, prescribe_medication]
    require_approval: [prescribe_medication]
    memory_from: [ns:triage]
```

---

## PipelineConfig (pipelines:)

```yaml
pipelines:
  er_pipeline:
    comply: [hipaa]
    security:
      signing: true
      data_classification: PHI
    actors: [triage, doctor, pharmacist]
    flow: "triage -> doctor -> pharmacist"
    budget_tokens: 50000
    budget_cost_usd: 0.50
    rate_limit: 10                      # max 10 concurrent runs
```

---

## ToolConfig (tools:)

```yaml
tools:
  classify_patient:
    description: "Classify patient urgency 1-5"
    parameters:
      symptoms: {type: string, required: true}
      vitals: {type: object, required: false}
    requires_approval: false
    data_classification: PHI

  prescribe_medication:
    description: "Write a prescription"
    parameters:
      medication: {type: string, required: true}
      dosage: {type: string, required: true}
      patient_id: {type: string, required: true}
    requires_approval: true             # always requires human approval
    data_classification: PHI
```

---

## PolicyConfig (policies:)

```yaml
policies:
  hipaa_policy:
    rules:
      - effect: allow
        action: "memory.*"
        resource: "ns:*"
        roles: [writer, reader, tool_agent]
        priority: 10
      - effect: require_approval
        action: "tool.call"
        resource: "tool:prescribe_*"
        roles: [doctor_ai]
        priority: 20
      - effect: deny
        action: "*"
        resource: "ns:audit"
        roles: [untrusted]
        priority: 100
```

---

## Tier 3 Optional Configs

```yaml
# Cluster (absent = single-node mode)
cluster:
  nodes: [node1:4222, node2:4222, node3:4222]
  cell_id: cell-001
  replication_factor: 2

# Streaming (absent = batch mode)
streaming:
  enabled: true
  buffer_size: 1000
  flush_interval_ms: 100

# MCP (absent = no MCP server)
mcp:
  enabled: true
  port: 3000

# Observability (absent = no external metrics)
observability:
  prometheus_port: 9090
  otel_endpoint: http://localhost:4317
  log_level: info
```

---

## Env-Var Interpolation

All string values support `${VAR_NAME}` syntax. Interpolation is performed by the Rust loader **before** deserialization:

```yaml
connector:
  api_key: ${DEEPSEEK_API_KEY}          # required — error if not set
  endpoint: ${DEEPSEEK_ENDPOINT:-https://api.deepseek.com}  # with default
```

**Error message when missing**:
```
Missing environment variables referenced in config:
  DEEPSEEK_API_KEY (referenced in connector.api_key)

Tip: copy .env.example to .env and fill in the values
```

---

## Loading from File

```rust
// Rust
let c = Connector::from_config("connector.yaml")?;

// Python (vac-ffi)
c = Connector.from_config("connector.yaml")

// TypeScript (REST)
const c = await Connector.fromConfig("connector.yaml");
// → POST /config/parse with file contents
// → returns parsed config + validation errors
```

---

## Validation Errors

```rust
pub enum ConfigError {
    FileNotFound { path: String, detail: String },
    ParseError(String),        // YAML syntax error
    MissingEnvVars(String),    // unset ${VAR} references
    ValidationError { section: String, message: String },
}
```
