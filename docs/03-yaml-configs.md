# 03 — YAML Configuration

> Complete reference for every YAML configuration file Connector reads.

---

## Configuration Files Overview

| File | Purpose | Hot-reload |
|---|---|---|
| `connector.yaml` | Node configuration — the primary config | No (restart required) |
| `agent.yaml` | Agent manifest — per-agent settings | Yes |
| `policies/*.yaml` | Policy rule definitions | Yes |
| `namespaces.yaml` | Namespace declarations and access controls | No |
| `tools.yaml` | Tool allowlist and schema | Yes |
| `.connector/witnessctl.yaml` | witnessctl plugin policy | Yes |
| `devguard.yaml` | DevGuard plugin policy | Yes |

---

## `connector.yaml` — Node Configuration

### Minimal Configuration

```yaml
node:
  id: my-connector-node
  env: development

api:
  host: 0.0.0.0
  port: 9091
  api_key: "your-api-key-here"

storage:
  path: ./data
  journal_retention_days: 90

llm:
  default_provider: openai
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"
      model: gpt-4o
```

### Standard Configuration

```yaml
node:
  id: connector-prod-01
  env: production
  log_level: info
  keypair_path: /etc/connector/keys/node.ed25519

api:
  host: 0.0.0.0
  port: 9091
  tls:
    enabled: true
    cert: /etc/connector/tls/cert.pem
    key: /etc/connector/tls/key.pem
  auth:
    api_key: "${CONNECTOR_API_KEY}"
    token_expiry_seconds: 86400
  rate_limit:
    requests_per_minute: 1000
    burst: 100

storage:
  path: /var/lib/connector
  journal_retention_days: 365
  memory_tier_hot_mb: 512
  memory_tier_warm_mb: 4096
  backup:
    enabled: true
    interval_hours: 6
    path: /var/backups/connector

llm:
  default_provider: openai
  timeout_seconds: 30
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"
      model: gpt-4o
      max_tokens: 4096
    anthropic:
      api_key: "${ANTHROPIC_API_KEY}"
      model: claude-3-5-sonnet-20241022
    ollama:
      base_url: http://localhost:11434
      model: llama3.2

firewall:
  enabled: true
  fail_closed: true
  injection_threshold: 0.7
  pii_detection: true
  budget_enforcement: true
  behavioral_drift: true

governance:
  hitl_timeout_seconds: 3600
  default_confidence_threshold: 0.8
  audit_all_decisions: true

compliance:
  frameworks:
    - hipaa
    - soc2_type2
    - gdpr
  report_format: json

plugins:
  - path: plugins/devguard
  - path: plugins/witnessctl
```

### Production Configuration (Full)

```yaml
node:
  id: "${NODE_ID}"
  env: production
  log_level: warn
  keypair_path: "${KMS_KEYPAIR_PATH}"
  binary_attestation: true

api:
  host: 0.0.0.0
  port: 9091
  tls:
    enabled: true
    cert: "${TLS_CERT_PATH}"
    key: "${TLS_KEY_PATH}"
    client_ca: "${CLIENT_CA_PATH}"    # mTLS
  auth:
    api_key: "${CONNECTOR_API_KEY}"
    allow_agent_pid_auth: true
  cors:
    origins: ["https://app.yourdomain.com"]
  rate_limit:
    requests_per_minute: 5000

storage:
  path: "${STORAGE_PATH}"
  journal_retention_days: 2190        # 6 years (HIPAA)
  encryption_at_rest: true
  kms_key_id: "${KMS_KEY_ID}"

secrets:
  provider: aws_secrets_manager       # or: vault, gcp_secret_manager
  region: us-east-1

cluster:
  enabled: true
  discovery: dns
  peers:
    - connector-02.internal:9091
    - connector-03.internal:9091
  consensus: raft
```

---

## `agent.yaml` — Agent Manifest

```yaml
# agent.yaml — defines a governed agent
name: medical-summarizer
description: "Summarize patient records with HIPAA controls"
role: medical_assistant
clearance: 3

# Memory namespace bindings
memory:
  private_ns: /p/patients          # PHI — never reaches LLM
  working_ns: /m/medical-summarizer
  knowledge_ns: /k/medical

# Tool allowlist — only these tools may be called
tools:
  allowed:
    - name: read_patient_record
      namespace_required: /p/patients
    - name: write_summary
      namespace_required: /m/medical-summarizer
  deny_all_others: true

# Budget constraints
budget:
  max_tokens_per_session: 100000
  max_cost_usd_per_session: 5.00
  max_duration_seconds: 300

# Policy bindings
policies:
  - hipaa_minimum_necessary
  - phi_no_llm_exposure
  - hitl_on_treatment_recommendation

# CCL contract (optional — inline or path)
contract: |
  contract MedicalSummarizer {
    intent: "Summarize patient records with minimum necessary access"
    memory {
      read  /p/patients/{{ patient_id }}
      write /m/medical-summarizer/summaries
    }
    governance {
      require confidence > 0.85
      tag hipaa
    }
  }

# LLM settings for this agent
llm:
  model: gpt-4o
  temperature: 0.1
  system_prompt_path: prompts/medical_system.txt
```

---

## `policies/*.yaml` — Policy Rules

```yaml
# policies/hipaa_minimum_necessary.yaml
name: hipaa_minimum_necessary
description: "Enforce HIPAA minimum necessary principle"
version: "1.0"
regulations: [hipaa]

rules:
  - id: phi_namespace_isolation
    description: "PHI in /p/ namespace must never reach LLM context"
    condition:
      namespace_starts_with: "/p/"
      target: llm_context
    action: deny
    severity: critical
    audit: true

  - id: phi_access_logging
    description: "All /p/ namespace reads must be logged"
    condition:
      operation: read
      namespace_starts_with: "/p/"
    action: allow
    side_effects:
      - audit_with_tag: hipaa
      - record_decision: true

  - id: minimum_necessary_check
    description: "Agent may only read fields declared in manifest"
    condition:
      operation: read
      fields_not_in: "{{ agent.declared_fields }}"
    action: deny
    severity: high
```

```yaml
# policies/pii_guard.yaml
name: pii_guard
description: "Detect and handle PII in all content"
version: "1.0"
regulations: [gdpr, hipaa]

rules:
  - id: pii_in_llm_output
    description: "Block PII from appearing in LLM outputs"
    condition:
      pii_detected: true
      location: llm_output
    action: redact_and_allow
    audit: true

  - id: pii_in_tool_call
    description: "Block PII from tool call arguments"
    condition:
      pii_detected: true
      location: tool_args
      pii_type: [ssn, credit_card, phi]
    action: deny
    severity: critical
```

---

## `namespaces.yaml` — Namespace Declarations

```yaml
namespaces:
  - path: /p/
    label: private_phi
    security_level: 5              # highest
    integrity_level: 5
    llm_access: deny               # never reaches LLM
    encryption: required
    audit: all_operations
    retention_days: 2190

  - path: /m/
    label: agent_memory
    security_level: 3
    integrity_level: 3
    llm_access: allow
    audit: write_operations
    retention_days: 90

  - path: /k/
    label: knowledge
    security_level: 2
    integrity_level: 4
    llm_access: allow_read_only
    audit: on_change
    retention_days: 3650

  - path: /s/
    label: system
    security_level: 5
    integrity_level: 5
    llm_access: deny
    agent_access: deny
    audit: all_operations
```

---

## `tools.yaml` — Tool Allowlist

```yaml
# tools.yaml — governed tool registry
tools:
  - name: filesystem_read
    description: "Read a file from the filesystem"
    parameters:
      path:
        type: string
        pattern: "^/allowed/paths/.*"   # path restriction
    allowed_namespaces: [/m/, /k/]
    required_clearance: 2
    audit: true
    schema_validation: strict

  - name: database_query
    description: "Execute a read-only database query"
    parameters:
      query:
        type: string
        max_length: 2000
      table:
        type: string
        enum: [public_records, summaries]  # table allowlist
    allowed_namespaces: [/m/]
    required_clearance: 3
    audit: true
    dry_run_available: true

  - name: http_request
    description: "Make an outbound HTTP request"
    parameters:
      url:
        type: string
        allowed_hosts: ["api.approved-domain.com"]
      method:
        type: string
        enum: [GET, POST]
    required_clearance: 3
    rate_limit: 100_per_minute
    audit: true
```

---

## Hot-Reload Behavior

Fields that can be changed without node restart:

```bash
connectorctl reload policies      # reload policies/*.yaml
connectorctl reload tools         # reload tools.yaml
connectorctl reload agent <pid>   # reload agent.yaml for one agent
```

Fields requiring restart:
- `node.id`, `node.keypair_path`
- `api.port`, `api.tls.*`
- `storage.path`, `storage.encryption_at_rest`
- `cluster.*`

---

## Environment Variable Substitution

Any value in YAML can reference an environment variable:

```yaml
api_key: "${CONNECTOR_API_KEY}"          # required — fails if not set
api_key: "${CONNECTOR_API_KEY:-dev-key}" # optional — fallback to dev-key
```

---

## Next Steps

- **[04 — Python SDK](04-python-sdk.md)** — call the API from Python
- **[05 — CCL Contracts](05-ccl-contracts.md)** — write governance contracts
- **[25 — External Deployment](25-infra-external.md)** — production YAML patterns
