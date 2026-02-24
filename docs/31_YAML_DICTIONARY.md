# YAML Dictionary

> Every YAML key explained in plain English — what it does, what values it accepts, what happens if you omit it, and a real example for each.

---

## How to Read This Dictionary

Each entry follows this format:

```
KEY
  What it does:   plain English explanation
  Type:           string | bool | int | list | object
  Default:        what happens if you leave it out
  Values:         accepted values (if constrained)
  Effect:         what changes in the system when set
  Example:        minimal working YAML snippet
```

---

## Top-Level Sections

```yaml
connector:   # global LLM + storage + security settings
agents:      # named agents with instructions and tools
pipelines:   # multi-agent flows
tools:       # tool definitions
policies:    # authorization rules
knowledge:   # knowledge base settings
rag:         # vector retrieval settings
memory:      # memory management settings
judgment:    # output quality settings
cluster:     # multi-node settings (Tier 3 — absent = OFF)
streaming:   # streaming output (Tier 3 — absent = OFF)
mcp:         # MCP server (Tier 3 — absent = OFF)
server:      # HTTP server settings (Tier 3 — absent = OFF)
observability: # metrics + tracing (Tier 3 — absent = OFF)
```

---

## connector: — Global Settings

---

### connector.provider

```
What it does:   Which LLM company to call
Type:           string
Default:        REQUIRED — error if missing
Values:         deepseek | openai | anthropic | ollama | groq | any OpenAI-compatible
Effect:         Sets the primary LLM for all agents unless overridden per-agent
```
```yaml
connector:
  provider: deepseek
```

---

### connector.model

```
What it does:   Which specific model to use
Type:           string
Default:        REQUIRED — error if missing
Values:         deepseek-chat | deepseek-reasoner | gpt-4o | gpt-4o-mini |
                claude-3.5-sonnet | claude-3-haiku | llama3.2 | mixtral-8x7b | ...
Effect:         Passed directly to the LLM API as the model parameter
```
```yaml
connector:
  model: deepseek-chat
```

---

### connector.api_key

```
What it does:   Authentication key for the LLM provider
Type:           string (use ${ENV_VAR} — never hardcode)
Default:        REQUIRED — error if missing
Effect:         Sent as Bearer token in LLM API requests
```
```yaml
connector:
  api_key: ${DEEPSEEK_API_KEY}
```

---

### connector.endpoint

```
What it does:   Override the LLM API base URL
Type:           string (URL)
Default:        Provider default (e.g., https://api.deepseek.com)
Effect:         Use any OpenAI-compatible API — local Ollama, Azure OpenAI, etc.
```
```yaml
connector:
  provider: ollama
  model: llama3.2
  endpoint: http://localhost:11434
  api_key: ollama   # Ollama ignores this but field is required
```

---

### connector.max_tokens

```
What it does:   Maximum tokens the LLM can generate per response
Type:           int
Default:        Provider default (usually 4096)
Values:         1 – 128000 (depends on model)
Effect:         Caps LLM output length — prevents runaway generation costs
```
```yaml
connector:
  max_tokens: 2048
```

---

### connector.temperature

```
What it does:   Controls LLM randomness/creativity
Type:           float
Default:        0.7
Values:         0.0 (deterministic) – 2.0 (very random)
Effect:         0.0 = same answer every time; 1.0 = creative; use 0.0 for medical/legal
```
```yaml
connector:
  temperature: 0.0   # deterministic — good for compliance use cases
```

---

### connector.system_prompt

```
What it does:   Default system prompt prepended to every agent conversation
Type:           string
Default:        none
Effect:         Sets baseline behavior for all agents unless overridden per-agent
```
```yaml
connector:
  system_prompt: "You are a precise medical assistant. Always cite evidence."
```

---

### connector.storage

```
What it does:   Where to persist kernel memory (packets, agents, audit log)
Type:           string (URI)
Default:        memory:// (in-memory, lost on restart)
Values:         memory://          — ephemeral, tests only
                redb:./data.redb   — persistent file (recommended for production)
                ./data.redb        — auto-detected by .redb extension
                prolly:./data      — Merkle-verifiable tree
Effect:         memory:// = nothing survives restart
                redb:path = ACID-safe, survives crash, queryable
```
```yaml
connector:
  storage: redb:./data/agent.redb
```

---

### connector.comply

```
What it does:   Compliance frameworks to enforce — not just report, but actively enforce
Type:           list of strings
Default:        [] (no compliance enforcement)
Values:         hipaa | soc2 | gdpr | eu_ai_act | nist_ai_rmf | owasp_llm | maestro | dod
Effect:         Activates framework-specific controls in the firewall and policy engine
                hipaa  → PHI detection, audit trail, access controls
                soc2   → availability monitoring, change management
                gdpr   → PII detection, right-to-erasure, retention limits
                eu_ai_act → human oversight gates, risk assessment
                dod    → TOP_SECRET classification, MFA, Ed25519, max_delegation_depth=1
```
```yaml
connector:
  comply: [hipaa, soc2]
```

---

### connector.fallbacks

```
What it does:   Backup LLM providers tried in order if the primary fails
Type:           list of objects
Default:        [] (no fallback — primary failure = error)
Effect:         Automatic failover: primary fails → try fallback[0] → fallback[1] → ...
                Each fallback can have its own provider/model/api_key/endpoint
```
```yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  fallbacks:
    - provider: openai
      model: gpt-4o-mini
      api_key: ${OPENAI_API_KEY}
    - provider: ollama
      model: llama3.2
      endpoint: http://localhost:11434
```

---

### connector.router

```
What it does:   Controls retry and circuit breaker behavior for LLM calls
Type:           object
Default:        retry(3 attempts, 500ms base) + circuit_breaker(5 failures, 30s cooldown)
```
```yaml
connector:
  router:
    retry:
      max_retries: 3          # attempts before giving up on one provider
      base_delay_ms: 500      # wait 500ms, then 1000ms, then 2000ms (exponential)
      max_delay_ms: 10000     # cap at 10 seconds
    circuit_breaker:
      failure_threshold: 5    # trip after 5 consecutive failures
      cooldown_secs: 30       # wait 30s before trying again
```

---

## connector.security: — Security Settings

---

### connector.security.signing

```
What it does:   Cryptographically sign every memory packet with Ed25519
Type:           bool
Default:        false
Effect:         true  → every MemPacket gets an Ed25519 signature
                       tampered packets detected on read
                false → no signing (development only)
```
```yaml
connector:
  security:
    signing: true
```

---

### connector.security.scitt

```
What it does:   Anchor every packet write to a SCITT transparency log
Type:           bool
Default:        false
Effect:         Cross-organization proof that a packet existed at a specific time
                Required for: supply chain compliance, cross-org audit
```
```yaml
connector:
  security:
    scitt: true
```

---

### connector.security.data_classification

```
What it does:   Tag all data with a sensitivity level
Type:           string
Default:        none
Values:         PHI | PII | confidential | internal | public
Effect:         PHI        → HIPAA controls + medical PII detection
                PII        → GDPR controls + personal data detection
                confidential → SOC2 controls
                internal   → standard access controls
                public     → minimal controls
```
```yaml
connector:
  security:
    data_classification: PHI
```

---

### connector.security.jurisdiction

```
What it does:   Geographic jurisdiction for compliance enforcement
Type:           string
Default:        none
Values:         US | EU | UK | CA | AU
Effect:         US → HIPAA, SOC2, NIST AI RMF activated
                EU → GDPR, EU AI Act activated
                UK → UK GDPR activated
```
```yaml
connector:
  security:
    jurisdiction: US
```

---

### connector.security.retention_days

```
What it does:   How long to keep memory packets before they can be purged
Type:           int (days)
Default:        0 (keep forever)
Values:         any positive integer
Effect:         HIPAA requires 6 years = 2190 days
                GDPR "storage limitation" — set to your legal requirement
                compact_store() removes entries older than this
```
```yaml
connector:
  security:
    retention_days: 2555   # 7 years (HIPAA requirement)
```

---

### connector.security.require_mfa

```
What it does:   Require multi-factor authentication for approval-gated actions
Type:           bool
Default:        false
Effect:         true → RequireApproval actions block until MFA token verified
                Use for: financial transactions, medical prescriptions, military ops
```
```yaml
connector:
  security:
    require_mfa: true
```

---

### connector.security.max_delegation_depth

```
What it does:   Maximum hops in an agent delegation chain
Type:           int
Default:        3
Values:         1 (no delegation) – 10
Effect:         1 → Agent A cannot delegate to Agent B at all
                3 → A → B → C → D (3 hops max)
                DoD grade: set to 1
```
```yaml
connector:
  security:
    max_delegation_depth: 1   # DoD: no delegation allowed
```

---

### connector.security.audit_export

```
What it does:   Format for exporting the audit trail
Type:           string
Default:        json
Values:         json | csv | otel
Effect:         json → full kernel snapshot with all fields
                csv  → flat table (audit_id, timestamp, operation, outcome, agent, cid)
                otel → OTLP-compatible spans for OpenTelemetry ingestion
```
```yaml
connector:
  security:
    audit_export: otel
```

---

## connector.firewall: — Firewall Settings

---

### connector.firewall.preset

```
What it does:   Apply a named security preset (overrides individual fields)
Type:           string
Default:        default
Values:         default | strict | hipaa
Effect:         default → block_injection=true, standard thresholds
                strict  → lower thresholds, more PII types, tighter limits
                hipaa   → medical PII types (SSN, DOB, medical_record), strict thresholds
                Individual fields override the preset on top of it.
```
```yaml
connector:
  firewall:
    preset: hipaa
```

---

### connector.firewall.block_injection

```
What it does:   Block prompt injection attempts
Type:           bool
Default:        true
Effect:         true  → inputs with injection patterns (ignore previous instructions, etc.)
                        are blocked before reaching the LLM
                false → injection attempts pass through (development only)
```
```yaml
connector:
  firewall:
    block_injection: true
```

---

### connector.firewall.pii_types

```
What it does:   Which PII patterns to detect and flag
Type:           list of strings
Default:        [] (no PII detection unless preset sets it)
Values:         ssn | credit_card | email | phone | dob | medical_record
Effect:         Detected PII in output → firewall warning or block (per pii_threshold)
```
```yaml
connector:
  firewall:
    pii_types: [ssn, credit_card, medical_record]
    pii_threshold: 0.5   # block if PII signal score > 0.5
```

---

### connector.firewall.max_calls_per_minute

```
What it does:   Rate limit — maximum LLM calls per agent per minute
Type:           int
Default:        60
Effect:         Exceeding limit → OpOutcome::Denied + audit entry
                Prevents runaway agents and cost explosions
```
```yaml
connector:
  firewall:
    max_calls_per_minute: 10   # conservative for production
```

---

### connector.firewall.blocked_tools

```
What it does:   Tools that are always blocked regardless of agent config
Type:           list of strings (tool IDs)
Default:        []
Effect:         Even if an agent has a tool in allowed_tools, if it's in blocked_tools
                it will always be denied. Use for emergency tool disabling.
```
```yaml
connector:
  firewall:
    blocked_tools: [delete_patient_record, wire_transfer]
```

---

### connector.firewall.weights / thresholds

```
What it does:   Fine-tune how each threat signal contributes to the overall threat score
Type:           object
Default:        injection=0.35, pii=0.30, anomaly=0.20, policy_violation=0.25,
                rate_pressure=0.15, boundary_crossing=0.10
                warn=0.3, review=0.6, block=0.8
Effect:         threat_score = sum(signal_value * weight)
                score >= warn    → add warning to output
                score >= review  → flag for human review
                score >= block   → block the operation
```
```yaml
connector:
  firewall:
    weights:
      injection: 0.5         # increase injection sensitivity
      pii: 0.4
    thresholds:
      warn: 0.2              # warn earlier
      block: 0.7             # block earlier
```

---

## connector.behavior: — Behavioral Analysis

---

### connector.behavior.anomaly_threshold

```
What it does:   Sensitivity for detecting abnormal agent behavior
Type:           float
Default:        0.7
Values:         0.0 (flag everything) – 1.0 (never flag)
Effect:         Compares current window to baseline behavior
                Low value → very sensitive (many warnings)
                High value → only flags extreme anomalies
```
```yaml
connector:
  behavior:
    anomaly_threshold: 0.8   # only flag clear anomalies
    window_ms: 60000         # 1-minute sliding window
    max_actions_per_window: 50
```

---

## connector.checkpoint: — Persistence

---

### connector.checkpoint.write_through

```
What it does:   Persist every packet to storage immediately on write
Type:           bool
Default:        true
Effect:         true  → every MemWrite also writes to disk (slower, crash-safe)
                false → batch writes (faster, risk of data loss on crash)
```
```yaml
connector:
  checkpoint:
    write_through: true
    wal_enabled: true              # Write-Ahead Log for crash recovery
    auto_checkpoint_threshold: 500 # flush every 500 writes
```

---

## agents: — Agent Definitions

---

### agents.<name>

```
What it does:   Define a named agent with its own instructions, tools, and permissions
Type:           object
Default:        inherits connector.provider/model/api_key
Effect:         Creates an AgentControlBlock in the kernel with namespace ns:<name>
```
```yaml
agents:
  triage:
    instructions: "Classify patients by urgency level 1-5. Be concise."
    role: writer              # writer | reader | tool_agent | supervisor
    model: deepseek-chat      # override global model for this agent
    tools: [classify_patient, lookup_vitals]
    require_approval: []      # tools requiring human approval before execution
    memory_from: []           # namespaces this agent can read from
```

---

### agents.<name>.role

```
What it does:   Sets the agent's permission level in the kernel
Type:           string
Default:        writer
Values:         writer      → can write + read own namespace
                reader      → can only read (no writes)
                tool_agent  → can call tools + write results
                supervisor  → can read all namespaces (requires explicit grants)
Effect:         Enforced by InstructionPlane — operations outside role are blocked
```
```yaml
agents:
  audit_agent:
    role: reader   # can only read, never write
```

---

### agents.<name>.memory_from

```
What it does:   Namespaces this agent is allowed to read from
Type:           list of strings (namespace names)
Default:        [] (only own namespace)
Effect:         Automatically creates AccessGrant syscalls at pipeline start
                doctor reading from triage = doctor sees triage's packets
```
```yaml
agents:
  doctor:
    memory_from: [triage, labs]   # doctor reads triage + lab results
```

---

### agents.<name>.require_approval

```
What it does:   Tools that require human approval before execution
Type:           list of strings (tool IDs)
Default:        []
Effect:         Tool call is suspended → ApprovalRequest event published
                Human approves → tool executes
                Human rejects → PolicyDecision { allowed: false }
```
```yaml
agents:
  doctor:
    require_approval: [prescribe_medication, order_surgery]
```

---

## pipelines: — Multi-Agent Flows

---

### pipelines.<name>.flow

```
What it does:   Define the execution order of agents as a simple string
Type:           string (arrow notation)
Default:        none (single agent)
Effect:         "triage -> doctor -> pharmacist" means:
                1. triage runs first
                2. doctor runs second (auto-gets read access to triage memory)
                3. pharmacist runs third (auto-gets read access to triage + doctor)
                Memory flows automatically — no manual AccessGrant needed
```
```yaml
pipelines:
  er_pipeline:
    flow: "triage -> doctor -> pharmacist"
    comply: [hipaa]
```

---

### pipelines.<name>.budget_tokens

```
What it does:   Maximum total tokens for the entire pipeline run
Type:           int
Default:        unlimited
Effect:         Sum of all agent token usage across the pipeline
                Exceeding → BudgetExceeded error, pipeline stops
```
```yaml
pipelines:
  er_pipeline:
    budget_tokens: 50000
    budget_cost_usd: 0.50   # also cap by cost
```

---

## tools: — Tool Definitions

---

### tools.<name>

```
What it does:   Define a callable tool with typed parameters
Type:           object
Effect:         Registered in InstructionPlane — agents can call it via tool.call verb
                Requires VAKYA authorization for every call
```
```yaml
tools:
  classify_patient:
    description: "Classify patient urgency 1-5 based on symptoms and vitals"
    parameters:
      symptoms:
        type: string
        required: true
        description: "Patient's reported symptoms"
      vitals:
        type: object
        required: false
        description: "BP, HR, SpO2, temperature"
    requires_approval: false
    data_classification: PHI
```

---

## policies: — Authorization Rules

---

### policies.<name>.rules

```
What it does:   Define allow/deny/require_approval rules for actions
Type:           list of rule objects
Effect:         Evaluated in priority order (highest first)
                First matching rule wins
                Federation Deny is absolute — overrides all local Allow rules
```
```yaml
policies:
  hospital_policy:
    rules:
      - effect: allow
        action: "memory.*"          # glob: matches memory.write, memory.read, etc.
        resource: "ns:*"            # glob: matches any namespace
        roles: [writer, tool_agent]
        priority: 10

      - effect: require_approval
        action: "tool.call"
        resource: "tool:prescribe_*" # matches prescribe_medication, prescribe_controlled
        roles: [doctor_ai]
        priority: 20

      - effect: deny
        action: "*"                 # all actions
        resource: "ns:audit"        # audit namespace is read-only
        roles: [untrusted]
        priority: 100
```

---

## Tier 3 — Optional Features (absent = OFF)

---

### cluster:

```
What it does:   Enable multi-node distributed deployment
Type:           object
Default:        absent = single-node mode
Effect:         Present → ClusterKernelStore activated
                          Raft consensus for membership
                          NATS JetStream for replication
                          CID-addressed conflict-free replication
```
```yaml
cluster:
  nodes: [node1:4222, node2:4222, node3:4222]
  cell_id: cell-hospital-001
  replication_factor: 2   # write to 2 nodes before confirming
```

---

### observability:

```
What it does:   Enable external metrics and tracing export
Type:           object
Default:        absent = internal only (GET /metrics still works)
Effect:         prometheus_port → expose Prometheus metrics on separate port
                otel_endpoint   → export spans to OpenTelemetry collector
```
```yaml
observability:
  prometheus_port: 9090
  otel_endpoint: http://otel-collector:4317
  log_level: info   # trace | debug | info | warn | error
```

---

## Complete Examples by Use Case

### Minimal (development)
```yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
```

### Production (single agent)
```yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/agent.redb
  security:
    signing: true
    data_classification: internal
  firewall:
    preset: default
  checkpoint:
    write_through: true
```

### Healthcare (HIPAA)
```yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/hospital.redb
  comply: [hipaa, soc2]
  security:
    signing: true
    data_classification: PHI
    jurisdiction: US
    retention_days: 2555
    require_mfa: true
  firewall:
    preset: hipaa
agents:
  triage:
    instructions: "Classify patients by urgency 1-5."
    role: writer
    tools: [classify_patient]
  doctor:
    instructions: "Diagnose based on triage data."
    role: tool_agent
    memory_from: [triage]
    require_approval: [prescribe_medication]
pipelines:
  er:
    flow: "triage -> doctor"
    comply: [hipaa]
    budget_tokens: 50000
```

### Finance (SOC2 + GDPR)
```yaml
connector:
  provider: openai
  model: gpt-4o
  api_key: ${OPENAI_API_KEY}
  storage: redb:./data/finance.redb
  comply: [soc2, gdpr]
  security:
    signing: true
    scitt: true
    data_classification: PII
    jurisdiction: EU
    retention_days: 1825
    require_mfa: true
    max_delegation_depth: 2
  firewall:
    preset: strict
    pii_types: [ssn, credit_card, email]
    max_calls_per_minute: 20
```

### Military (DoD grade)
```yaml
connector:
  provider: ollama
  model: llama3.2
  api_key: local
  endpoint: http://localhost:11434   # air-gapped, no external calls
  storage: redb:./data/classified.redb
  comply: [dod]
  security:
    signing: true
    scitt: true
    data_classification: TOP_SECRET
    jurisdiction: US
    retention_days: 3650
    require_mfa: true
    max_delegation_depth: 1
    key_rotation_days: 30
  firewall:
    preset: strict
    block_injection: true
    max_calls_per_minute: 5
    weights:
      injection: 0.8
      boundary_crossing: 0.9
    thresholds:
      warn: 0.1
      block: 0.4
  behavior:
    anomaly_threshold: 0.3
    max_actions_per_window: 10
  checkpoint:
    write_through: true
    wal_enabled: true
```
