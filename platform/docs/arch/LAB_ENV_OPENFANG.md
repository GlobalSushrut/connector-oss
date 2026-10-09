# TraceTramp + WitnessCtl — Production Lab with OpenFang + aimock

> This is not synthetic traffic. OpenFang is a real autonomous agent OS (137K LOC,
> Rust, 14 crates, 53 tools, WASM sandbox, MCP/A2A). It runs real multi-turn LLM
> calls, real tool invocations, real knowledge graph builds, real scheduled Hands.
> aimock intercepts every LLM call and returns realistic fixture responses — no API
> keys, no GPU, fully deterministic, with chaos injection and streaming physics.
>
> Together: OpenFang generates the exact kind of sustained, complex, tool-heavy
> agent traffic that TraceTramp and WitnessCtl were built to govern and witness.

---

## Why OpenFang + aimock is the right lab

| What TraceTramp/WitnessCtl needs to prove | What OpenFang provides |
|---|---|
| Real multi-turn LLM calls (not curl one-liners) | Researcher Hand runs 10–20 turn conversations to build knowledge graphs |
| Tool calls intercepted and governed | 53 bundled tools — web search, file ops, code exec, API calls |
| Budget enforcement under sustained load | Hands run on schedules, constantly consuming tokens |
| PII flowing through agent reasoning | Coder Hand reads source files containing secrets, emails, API keys |
| MCP/A2A protocol traffic | OpenFang has native MCP server mode and A2A protocol |
| Provider fallback under chaos | aimock injects 500s mid-session — OpenFang's fallback vs TraceTramp's fallback |
| Schema drift from real agent output | Researcher Hand responses evolve as knowledge graph grows |
| Multi-tenant isolation | Multiple OpenFang instances, each with a different tenant key |

OpenFang's own LLM API is OpenAI-compatible at `:4200/v1` — so it can also be a
**second upstream** that WitnessCtl proxies, capturing OpenFang's internal agent
calls as a real API witness target.

---

## Tools Used

### Agent OS — OpenFang
**Repo:** https://github.com/RightNow-AI/openfang
- Rust, single ~32MB binary, 180ms cold start, 40MB idle
- OpenAI-compatible API at `localhost:4200/v1`
- 7 autonomous Hands (Researcher, Coder, Lead, Browser, Social, Scheduler, Monitor)
- 53 tools (web search, file read/write, code exec, HTTP calls, memory ops)
- 27 LLM providers via 3 native drivers — point `OPENFANG_LLM_BASE_URL` at aimock
- WASM sandbox for untrusted tool execution — DevGuard cage equivalent for OpenFang
- MCP server mode + A2A protocol support
- 16 security layers including taint tracking, Ed25519 manifest signing, RBAC

### Mock LLM — aimock (CopilotKit)
**Repo:** https://github.com/CopilotKit/aimock  
**Docker:** `ghcr.io/copilotkit/aimock:latest`
- Full OpenAI + Anthropic + Ollama compat — OpenFang's 3 drivers all work against it
- Real SSE streaming with configurable `ttft`, `tps`, jitter
- Chaos: 500 errors, malformed JSON, mid-stream disconnects at configurable rate
- Fixture-driven deterministic responses — same input, same output, every time
- Record & replay — proxy a real API once, replay forever
- Prometheus metrics at `/metrics`
- Zero dependencies, Docker image

### Other Components
| Component     | Image                         | Purpose                                            |
|---------------|-------------------------------|----------------------------------------------------|
| PostgreSQL 16 | `postgres:16-alpine`          | TraceTramp + WitnessCtl storage                    |
| Redis 7       | `redis:7-alpine`              | TraceTramp budget/session cache                    |
| Prometheus    | `prom/prometheus:latest`      | Scrapes TraceTramp, WitnessCtl, aimock, OpenFang   |
| Grafana       | `grafana/grafana:latest`      | Live dashboards across all services                |
| Connector OS  | local build `:9735`           | Kernel: agents, audit, policy, memory, trust       |

---

## Architecture

```
  OpenFang Agent OS  (:4200)
  ┌─────────────────────────────────────────────────────────────┐
  │  Researcher Hand  │  Coder Hand  │  Monitor Hand            │
  │  (scheduled, autonomous -->, multi-turn, tool-heavy)            │
  └────────────────────┬────────────────────────────────────────┘
                       │ every LLM call routed through TraceTramp
                       │ (OPENFANG_LLM_BASE_URL=http://tracetramp:9741)
                       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  TraceTramp  (:9741 data  /  :9742 mgmt)                    │
  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
  │  │ PII scan │ │ policy   │ │ budget   │ │ trace record │  │
  │  │ BLOCK/   │ │ ALLOW/   │ │ hard     │ │ → WitnessCtl │  │
  │  │ REDACT   │ │ BLOCK    │ │ stop 402 │ │   (async)    │  │
  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
  └────────────────────┬──────────────┬───────────────────────┘
                       │ allowed      │ async ingest
                       ▼              ▼
               aimock (:9999)    WitnessCtl (:7443)
               (fixture LLM)    (receipt chain + PDFs)
                                      │
                                      ▼
                               Connector OS (:9735)
                               (agents, audit, policy,
                                memory, trust scoring)
`a
OpenFang is also a **second WitnessCtl target** — its own `/v1` API can be proxied
through WitnessCtl to capture all inter-agent and tool-execution API calls:

```
  External client
       │
       ▼
  WitnessCtl proxy  (:7443/witness/http://openfang:4200)
       │  captures every call + receipt
       ▼
  OpenFang  (:4200)
```

This means WitnessCtl is simultaneously:
1. Receiving ingest from TraceTramp (LLM call evidence)
2. Proxying calls TO OpenFang (agent API evidence)

Two separate sessions, two separate HMAC chains, one unified compliance picture.

---

## File Layout

```
lab/
  docker-compose.yml
  aimock/
    aimock.json                    # aimock config
    fixtures/
      researcher_turn.json         # normal multi-turn research response
      researcher_pii_phi.json      # response containing PHI field names
      coder_tool_call.json         # tool_use call: read_file src/auth/login.rs
      coder_secret_leak.json       # response mentions JWT_SECRET env var
      chaos_500.json               # aimock returns 500 (tests TT fallback)
      chaos_malformed.json         # malformed JSON mid-stream
      schema_drift_v1.json         # baseline researcher response schema
      schema_drift_v2.json         # adds 'reasoning' + 'confidence_score' fields
      budget_cheap.json            # fast, cheap responses (exhaust budget quickly)
  openfang/
    config.toml                    # OpenFang config pointing LLM at TraceTramp
    hands/
      lab_researcher.toml          # custom Hand: research AI governance topics
      lab_coder.toml               # custom Hand: read/analyze source files
      lab_monitor.toml             # custom Hand: poll endpoints and report
  prometheus/
    prometheus.yml
  grafana/
    dashboards/
      lab_overview.json
  scripts/
    setup.sh                       # first-run: DB, migrations, tenants, OpenFang init
    run_lab.sh                     # start all services + activate Hands
    seal_and_verify.sh             # seal WitnessCtl session + download 5 PDFs
    teardown.sh
```

---

## docker-compose.yml

**Phase 0.7:** production of container images for TraceTramp / WitnessCtl / Connector OSS uses `lab/Dockerfile.*` with the compose file in `plugins/tracetramp/` (`lab/README.md`). The build `context` / `dockerfile` lines in this fragment match that layout.

```yaml
version: "3.9"

services:

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: lab
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lab"]
      interval: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 10

  aimock:
    image: ghcr.io/copilotkit/aimock:latest
    ports:
      - "9999:9999"
    volumes:
      - ./aimock:/fixtures
    environment:
      AIMOCK_PORT: "9999"
      AIMOCK_CONFIG: /fixtures/aimock.json
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9999/health || exit 1"]
      interval: 5s
      retries: 10

  connector:
    build:
      context: ../../oss
      dockerfile: ../lab/Dockerfile.connector
    ports:
      - "9735:9735"
    environment:
      DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      REDIS_URL: redis://redis:6379
      CONNECTOR_LLM_STUB: "1"
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  tracetramp:
    build:
      context: .
      dockerfile: ../../lab/Dockerfile.tracetramp
    ports:
      - "9741:9741"
      - "9742:9742"
    environment:
      DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      REDIS_URL: redis://redis:6379
      CONNECTOR_BASE_URL: http://connector:9735
      CONNECTOR_API_KEY: lab-connector-key
      # TraceTramp forwards to aimock — NOT to real OpenAI
      OPENAI_BASE_URL: http://aimock:9999/v1
      OPENAI_API_KEY: lab-fake-key
      JWT_SECRET: lab-jwt-secret
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      aimock:
        condition: service_healthy
      connector:
        condition: service_started

  witnessctl:
    build:
      context: ../witnessctl
      dockerfile: ../../lab/Dockerfile.witnessctl
    ports:
      - "7443:7443"
    environment:
      WITNESSCTL_DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      CONNECTOR_BASE_URL: http://connector:9735
      CONNECTOR_API_KEY: lab-connector-key
      WITNESSCTL_HMAC_SECRET: lab-hmac-secret
      WITNESSCTL_NOTIFY_TERMINAL: "true"
      WITNESSCTL_HOLD_ON_BLOCK: "true"
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      connector:
        condition: service_started

  openfang:
    # Build from source or use prebuilt binary
    image: ghcr.io/rightnow-ai/openfang:v0.5.10
    ports:
      - "4200:4200"
    volumes:
      - ./openfang/config.toml:/root/.openfang/config.toml
      - ./openfang/hands:/root/.openfang/hands
    environment:
      # Point ALL LLM calls through TraceTramp → aimock
      OPENFANG_LLM_BASE_URL: http://tracetramp:9741/v1
      OPENFANG_LLM_API_KEY: cpk_lab_openfang_tenant
      OPENFANG_PORT: "4200"
      OPENFANG_LOG: info
    depends_on:
      tracetramp:
        condition: service_started
    command: ["openfang", "start", "--no-browser"]

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: lab
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  pg_data:
  grafana_data:
```

---

## openfang/config.toml

```toml
# OpenFang lab config
# All LLM calls route through TraceTramp which proxies to aimock
# No real API keys needed

[llm]
base_url = "http://tracetramp:9741/v1"
api_key  = "cpk_lab_openfang_tenant"
default_model = "gpt-4o"

[server]
port = 4200
host = "0.0.0.0"

[memory]
backend = "sqlite"
path    = "/tmp/openfang-lab.db"

[security]
# Disable WASM sandbox in lab for simpler traffic (re-enable for cage testing)
wasm_sandbox = false
```

---

## openfang/hands/lab_researcher.toml

```toml
[hand]
name    = "lab-researcher"
version = "0.1.0"
schedule = "*/5 * * * *"   # runs every 5 minutes

[llm]
model             = "gpt-4o"
max_turns         = 12
temperature       = 0.3

[tools]
allowed = ["web_search", "memory_write", "memory_read", "http_get"]

[settings]
topic   = "AI agent governance and compliance"
depth   = "detailed"
output  = "knowledge_graph"

[system_prompt]
content = """
You are a research analyst specialising in AI governance.
Your task: research the topic, build a knowledge graph, identify key risks.
Use web_search to find recent developments.
Use memory_write to persist findings for future sessions.
Always cite sources. Never fabricate data.
"""
```

> This Hand runs every 5 minutes, makes 10–12 LLM turns per run, calls `web_search`
> and `memory_write` tools — exactly the sustained multi-turn, tool-heavy traffic
> that exercises TraceTramp's tool governance and WitnessCtl's receipt chain under load.

---

## openfang/hands/lab_coder.toml

```toml
[hand]
name    = "lab-coder"
version = "0.1.0"
schedule = "*/10 * * * *"

[llm]
model     = "gpt-4o"
max_turns = 8

[tools]
allowed = ["file_read", "file_write", "run_command", "memory_read"]

[settings]
# Points at the connector-private repo — reads real source files
# This will trigger TraceTramp's secret detection (JWT keys, HMAC secrets in code)
workspace = "/home/umesh/Projects/connector-private"
task      = "review authentication code for security issues"

[system_prompt]
content = """
You are a security-focused code reviewer.
Read source files in the workspace, identify security issues, suggest fixes.
Focus on: hardcoded secrets, weak crypto, missing validation, injection risks.
"""
```

> The Coder Hand reads real source files from the repo. Those files contain HMAC
> secrets, JWT keys, API key patterns. TraceTramp MUST detect these in the
> LLM's response and redact them before they appear in WitnessCtl's captured output.
> This is the highest-value real-world test case.

---

## openfang/hands/lab_monitor.toml

```toml
[hand]
name    = "lab-monitor"
version = "0.1.0"
schedule = "*/2 * * * *"

[llm]
model     = "gpt-4o"
max_turns = 4

[tools]
allowed = ["http_get", "memory_write"]

[settings]
targets = [
  "http://tracetramp:9741/health",
  "http://witnessctl:7443/health",
  "http://connector:9735/health",
  "http://aimock:9999/health",
]
alert_on_failure = true

[system_prompt]
content = """
You are a monitoring agent. Poll the given endpoints every cycle.
Report status. Write failures to memory. Flag anomalies.
"""
```

> Monitor Hand runs every 2 minutes, generates steady low-volume tool-call traffic —
> good for testing WitnessCtl's receipt chain under continuous but light load.

---

## aimock/aimock.json

```json
{
  "port": 9999,
  "metrics": true,
  "providers": {
    "openai": {
      "chatCompletions": {
        "fixturesDir": "./fixtures"
      }
    }
  },
  "streamingPhysicsDefaults": {
    "ttft": 100,
    "tps":  35,
    "jitter": 15
  },
  "chaosDefaults": {
    "errorRate":      0.0,
    "malformedRate":  0.0,
    "disconnectRate": 0.0
  }
}
```

---

## aimock fixture examples

### fixtures/researcher_turn.json
```json
{
  "match": {
    "model": "gpt-4o",
    "messages_contain_role": "user"
  },
  "response": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "Based on my research, AI governance frameworks are evolving rapidly. Key findings: (1) The EU AI Act mandates human oversight for high-risk systems. (2) NIST AI RMF provides a risk-based approach. (3) Organizations deploying autonomous agents must maintain audit trails. I will now write these findings to memory."
      },
      "finish_reason": "tool_calls"
    }],
    "tool_calls": [{
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "memory_write",
        "arguments": "{\"key\": \"governance_findings\", \"value\": \"EU AI Act requires human oversight...\"}"
      }
    }],
    "usage": { "prompt_tokens": 312, "completion_tokens": 98, "total_tokens": 410 }
  },
  "stream": true
}
```

### fixtures/coder_secret_leak.json
```json
{
  "match": {
    "messages_contain": "authentication code"
  },
  "response": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "I found several security issues. In connector.rs line 31, the hmac_secret defaults to 'change-me-in-production'. In config.rs the CONNECTOR_API_KEY is read from env but has no minimum length check. The JWT_SECRET in tracetramp uses HS256 which is symmetric — the key 'lab-jwt-secret' in the config appears to be a weak hardcoded value."
      },
      "finish_reason": "stop"
    }],
    "usage": { "prompt_tokens": 890, "completion_tokens": 124, "total_tokens": 1014 }
  },
  "stream": true
}
```

> TraceTramp MUST detect `hmac_secret`, `CONNECTOR_API_KEY`, `JWT_SECRET`, `lab-jwt-secret`
> as secret patterns and REDACT before this response reaches OpenFang or WitnessCtl.
> If REDACT does not fire here the test fails.

### fixtures/chaos_500.json
```json
{
  "match": { "messages_contain": "chaos_trigger" },
  "statusCode": 500,
  "response": {
    "error": {
      "message": "The server had an error processing your request.",
      "type": "server_error",
      "code": 500
    }
  }
}
```

### fixtures/schema_drift_v2.json
```json
{
  "match": { "messages_contain": "knowledge_graph_summary" },
  "response": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "Summary of knowledge graph built over last 3 sessions.",
        "reasoning": "The user wants a consolidated view. I should synthesise all memory entries.",
        "confidence_score": 0.87
      },
      "finish_reason": "stop"
    }],
    "usage": { "prompt_tokens": 420, "completion_tokens": 88, "total_tokens": 508 }
  },
  "stream": true
}
```

> `reasoning` and `confidence_score` are new fields not in the baseline schema.
> WitnessCtl MUST detect this drift → SOC2 CC7.1 + FedRAMP CM-3 flagged in PDF.

---

## Lab Test Scenarios

### Scenario 1 — Researcher Hand: Multi-turn tool-heavy traffic
```bash
# Activate the Researcher Hand (runs every 5 min by schedule)
docker compose exec openfang openfang hand activate lab-researcher

# Watch it in TraceTramp TUI
tracetramp tui --tenant openfang-lab

# Watch receipts building in WitnessCtl
witnessctl watch <session_id>
```

**What this proves:**
- TraceTramp handles multi-turn conversations (not just single shots)
- Tool calls (`memory_write`, `web_search`) flow through TraceTramp's tool governance
- WitnessCtl receipt chain grows steadily under real agent load
- Budget burn is measured per-turn across a complete Hand run

---

### Scenario 2 — Coder Hand: Secret detection in real code review
```bash
docker compose exec openfang openfang hand activate lab-coder
```

**What this proves:**
- aimock returns responses containing real secret patterns from the codebase
- TraceTramp's secret scanner detects `hmac_secret`, `JWT_SECRET`, API key patterns in LLM OUTPUT
- REDACT fires on the response before OpenFang receives it
- WitnessCtl records the REDACT event with field path
- HIPAA + GDPR PDFs show 0 secrets transmitted to agent

**Pass criteria:**
```
TraceTramp decision on coder response:  REDACT
WitnessCtl PII report:                  secrets detected in output, all redacted
HIPAA score:                            PASS (secrets not transmitted)
```

---

### Scenario 3 — Budget exhaustion under Hand load
```bash
# Create a tight-budget tenant for OpenFang in TraceTramp management plane
curl -X POST http://localhost:9742/admin/tenants \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"name":"budget-test","daily_budget_usd":0.05}'

# Set OpenFang to use this tenant's API key
# Run Researcher Hand — will exhaust the $0.05 budget mid-session
docker compose exec openfang openfang hand activate lab-researcher
```

**Pass criteria:**
```
TraceTramp returns 402 Budget Exhausted        (not 500, not silent fail)
OpenFang Hand pauses gracefully on 402         (does not crash)
WitnessCtl receipt chain records the 402 event
Budget reset on next day cycle                 PASS
```

---

### Scenario 4 — Provider chaos: aimock 500 mid-Hand run
```bash
# Enable chaos in aimock at runtime (10% error rate)
curl -X POST http://localhost:9999/admin/chaos \
  -d '{"errorRate": 0.1, "malformedRate": 0.05}'

# Researcher Hand is already running — it will hit chaos mid-turn
```

**Pass criteria:**
```
TraceTramp catches 500 from aimock             PASS (no 500 leak to OpenFang)
TraceTramp fallback fires                      PASS (retries or graceful error)
OpenFang Hand receives structured error        PASS (not a crash)
WitnessCtl records the chaos event            PASS
```

---

### Scenario 5 — Schema drift: Researcher knowledge graph summary
```bash
# After several normal Researcher turns, trigger a knowledge_graph_summary turn
# aimock will return schema_drift_v2.json with extra fields
docker compose exec openfang openfang chat lab-researcher \
  "knowledge_graph_summary of all findings so far"
```

**Pass criteria:**
```
WitnessCtl detects new fields: 'reasoning', 'confidence_score'   PASS
SOC2 CC7.1 Change Detection:  WARN in sealed PDF                 PASS
FedRAMP CM-3:                  WARN in sealed PDF                 PASS
Notification emitted:          DONE + schema drift details        PASS
```

---

### Scenario 6 — WitnessCtl proxying OpenFang's own API
```bash
# Open a WitnessCtl session pointing at OpenFang as upstream
witnessctl session open \
  --upstream http://openfang:4200 \
  --role compliance-auditor

# Send requests through WitnessCtl → OpenFang
curl http://localhost:7443/witness/http://openfang:4200/v1/chat/completions \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"model":"researcher","messages":[{"role":"user","content":"status report"}]}'

# Every call to OpenFang is now receipted
witnessctl session seal <id>
# → separate HMAC chain + PDF for OpenFang API compliance
```

**What this proves:**
- WitnessCtl works as a compliance layer on top of any agent API, not just LLM APIs
- Two separate receipt chains: one for LLM calls (via TraceTramp ingest), one for agent API calls (via WitnessCtl proxy)

---

### Scenario 7 — Seal + full PDF verification
```bash
./scripts/seal_and_verify.sh <witnessctl_session_id>
```

```
=== Pre-audit check ===
  audit chain continuity    PASS
  HMAC chain integrity      PASS
  policy evaluated per call PASS
  denied calls recorded     PASS
  secrets in output         WARN  ← coder_secret_leak fixture triggered REDACT

=== Compliance Scores ===
  HIPAA:     94/100  PASS   (secrets redacted, PHI chain intact)
  SOC2:      86/100  PASS   (schema drift WARN on CC7.1)
  GDPR:      91/100  PASS
  EU AI Act: 74/100  FAIL   (0 human oversight events in 47 AI decisions)
  FedRAMP:   82/100  PASS

=== PDFs downloaded to ./lab-reports/ ===
  report-<id>-hipaa.pdf
  report-<id>-soc2.pdf
  report-<id>-gdpr.pdf
  report-<id>-euaiact.pdf
  report-<id>-fedramp.pdf

=== Chain verification ===
  witnessctl verify soe1-sha256-...
  → EXIT 0  VALID
```

---

## scripts/setup.sh

```bash
#!/usr/bin/env bash
set -e

echo "=== Lab Setup: TraceTramp + WitnessCtl + OpenFang + aimock ==="

echo "[1] Starting infrastructure..."
docker compose up -d postgres redis aimock
sleep 8

echo "[2] Running migrations..."
docker compose run --rm tracetramp ./tracetramp migrate
docker compose run --rm witnessctl ./witnessctl migrate

echo "[3] Starting Connector OS..."
docker compose up -d connector
sleep 5

echo "[4] Starting TraceTramp + WitnessCtl..."
docker compose up -d tracetramp witnessctl
sleep 5

echo "[5] Creating OpenFang tenant in TraceTramp..."
ADMIN_JWT=$(docker compose exec tracetramp ./tracetramp gen-jwt --role admin)

TENANT=$(curl -sf -X POST http://localhost:9742/admin/tenants \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"openfang-lab","daily_budget_usd":5.0}')

OPENFANG_KEY=$(echo "$TENANT" | jq -r '.api_key')
echo "  OpenFang tenant API key: $OPENFANG_KEY"

echo "[6] Registering aimock as LLM provider..."
curl -sf -X POST http://localhost:9742/admin/providers \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"aimock\",\"provider\":\"openai\",\"base_url\":\"http://aimock:9999/v1\",\"api_key\":\"lab-fake\"}"

echo "[7] Opening WitnessCtl session for OpenFang traffic..."
SESSION=$(curl -sf -X POST http://localhost:7443/api/v1/sessions \
  -H "Authorization: Bearer $OPENFANG_KEY" \
  -H "Content-Type: application/json" \
  -d '{"upstream":"http://tracetramp:9741","role":"lab-compliance"}')
SESSION_ID=$(echo "$SESSION" | jq -r '.session_id')

echo "[8] Writing OpenFang API key into config..."
sed -i "s/cpk_lab_openfang_tenant/$OPENFANG_KEY/" openfang/config.toml

echo "[9] Starting OpenFang..."
docker compose up -d openfang
sleep 5

echo "[10] Starting Prometheus + Grafana..."
docker compose up -d prometheus grafana

cat <<EOF

=== Lab Ready ===

  OpenFang dashboard:        http://localhost:4200
  TraceTramp data plane:     http://localhost:9741
  TraceTramp mgmt plane:     http://localhost:9742
  WitnessCtl:                http://localhost:7443
  aimock (mock LLM):         http://localhost:9999
  Prometheus:                http://localhost:9090
  Grafana:                   http://localhost:3000  (admin/lab)

  OpenFang API key:          $OPENFANG_KEY
  WitnessCtl session:        $SESSION_ID
  Admin JWT:                 $ADMIN_JWT

  Activate Researcher Hand:  docker compose exec openfang openfang hand activate lab-researcher
  Activate Coder Hand:       docker compose exec openfang openfang hand activate lab-coder
  Watch live TUI:            tracetramp tui
  Watch WitnessCtl:          witnessctl watch $SESSION_ID
  Seal + verify:             ./scripts/seal_and_verify.sh $SESSION_ID
EOF
```

---

## scripts/seal_and_verify.sh

```bash
#!/usr/bin/env bash
set -e

SESSION_ID=$1
API_KEY=${LAB_API_KEY}

echo "=== Pre-audit integrity check ==="
witnessctl pre-audit check "$SESSION_ID"

echo ""
echo "=== Sealing session ==="
SEAL=$(curl -sf -X POST "http://localhost:7443/api/v1/sessions/$SESSION_ID/seal" \
  -H "Authorization: Bearer $API_KEY")

echo "$SEAL" | jq '{proof_id, receipts, hipaa_score, soc2_score, gdpr_score, euaiact_score, fedramp_score}'
PROOF_ID=$(echo "$SEAL" | jq -r '.proof_id')

echo ""
echo "=== Verifying HMAC chain ==="
witnessctl verify "$PROOF_ID"

echo ""
echo "=== Downloading PDFs ==="
mkdir -p ./lab-reports
for FW in hipaa soc2 gdpr euaiact fedramp; do
  curl -sf "http://localhost:7443/api/v1/sessions/$SESSION_ID/export?format=pdf&framework=$FW" \
    -H "Authorization: Bearer $API_KEY" \
    -o "./lab-reports/report-${SESSION_ID}-${FW}.pdf"
  echo "  Saved: lab-reports/report-${SESSION_ID}-${FW}.pdf"
done

echo ""
echo "=== Checking unacknowledged notifications ==="
curl -sf "http://localhost:7443/api/v1/notifications?session_id=$SESSION_ID" \
  -H "Authorization: Bearer $API_KEY" \
  | jq '.[] | select(.acked == false) | {id, type, message, age_minutes}'
```

---

## Quick Start

```bash
cd ~/Projects/connector-private/lab

# First time
./scripts/setup.sh

# Activate the Hands — they start generating real agent traffic
docker compose exec openfang openfang hand activate lab-researcher
docker compose exec openfang openfang hand activate lab-coder
docker compose exec openfang openfang hand activate lab-monitor

# Watch TraceTramp govern the traffic live
tracetramp tui

# Watch WitnessCtl build the receipt chain
witnessctl watch <session_id>

# After 15-20 minutes — seal and get all 5 PDFs
./scripts/seal_and_verify.sh <session_id>

# View metrics
open http://localhost:3000   # Grafana
open http://localhost:9090   # Prometheus
open http://localhost:4200   # OpenFang dashboard

# Tear down
./scripts/teardown.sh
```

---

## What Each Layer Proves Under Real OpenFang Load

| Layer | What OpenFang exercises it with | Pass condition |
|---|---|---|
| **TraceTramp multi-turn** | Researcher Hand 12-turn knowledge graph sessions | All turns proxied, traced, receipted |
| **TraceTramp tool governance** | Coder Hand `file_read`, `run_command`, `memory_write` | Tool allowlist enforced, blocked tools return 403 |
| **TraceTramp secret detection** | Coder Hand reads real source files, LLM response cites HMAC/JWT secrets | REDACT fires on secret patterns in OUTPUT |
| **TraceTramp budget hard stop** | Budget-constrained tenant, Researcher Hand runs until 402 | 402 returned, no 500, OpenFang pauses gracefully |
| **TraceTramp provider chaos** | aimock 500 mid-Researcher turn | No 500 leak, fallback or graceful error |
| **WitnessCtl receipt chain** | All 3 Hands generating continuous traffic | Chain grows continuously, no gaps |
| **WitnessCtl schema drift** | Researcher knowledge graph summary returns new fields | Drift detected, SOC2/FedRAMP flagged |
| **WitnessCtl HIPAA PDF** | Coder Hand response redacted secrets | PDF shows 0 secrets transmitted, PHI redacted |
| **WitnessCtl EU AI Act PDF** | 0 human oversight events in 47 AI decisions | FAIL score, required actions listed |
| **WitnessCtl ack system** | EU AI Act FAIL notification generated | UNACKED escalation fires at 30min |
| **Full chain verify** | All sessions sealed after lab run | `witnessctl verify` exits 0 |
