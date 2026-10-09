# Relay — Deep Architecture: How It Works at OpenFaaS Level

> **This document explains, component by component, exactly how Relay works internally — benchmarked against OpenFaaS's production architecture — then shows where Relay goes further at every layer.**

---

## 1. OpenFaaS: How It Actually Works (Research)

Understanding OpenFaaS precisely is the baseline. Relay must match every capability and exceed every limitation.

### 1.1 OpenFaaS Component Stack

```
┌──────────────────────────────────────────────────────┐
│  CLIENT (faas-cli / HTTP / SDK)                      │
└──────────────────────┬───────────────────────────────┘
                       │ HTTP POST /function/NAME
┌──────────────────────▼───────────────────────────────┐
│  GATEWAY (openfaas/faas-netes)                       │
│  - REST API: deploy, invoke, list, scale             │
│  - Prometheus metrics scrape                         │
│  - Auto-scale trigger (RPS / inflight threshold)     │
│  - Basic auth / OIDC (Pro tier)                      │
│  - Routes: /function/NAME  →  sync invoke            │
│            /async-function/NAME  →  NATS queue       │
└──────────────────────┬───────────────────────────────┘
          sync         │                  async
    ┌─────────────────┤           ┌──────▼──────────────┐
    │                 │           │  NATS / Queue Worker │
    │                 │           │  - dequeue + invoke  │
    │                 │           │  - retry N times     │
    │                 │           │  - webhook callback  │
    │                 │           └──────────────────────┘
┌───▼─────────────────────────────────────────────────┐
│  FUNCTION POD (Kubernetes Deployment)               │
│  ┌─────────────────────────────────────────────┐    │
│  │  of-watchdog (sidecar process, port 8080)   │    │
│  │  - Receives request from Gateway            │    │
│  │  - Modes:                                   │    │
│  │    · http: forward to function HTTP server  │    │
│  │    · stdio: fork process per request        │    │
│  │    · streaming: SSE support                 │    │
│  │  - Health check endpoint (/healthz)         │    │
│  │  - Timeout enforcement                      │    │
│  │  - max_inflight concurrency control         │    │
│  └────────────────────┬────────────────────────┘    │
│                       │                             │
│  ┌────────────────────▼────────────────────────┐    │
│  │  FUNCTION PROCESS (your code)               │    │
│  │  - Any language                             │    │
│  │  - HTTP handler on port 3000 (http mode)    │    │
│  │  - stdin/stdout (stdio mode)                │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────┐
│  Prometheus (metrics) + Container Registry          │
│  + Kubernetes (pod lifecycle + scaling)             │
└─────────────────────────────────────────────────────┘
```

### 1.2 OpenFaaS Request Lifecycle (Synchronous)

```
Step 1:  Client → POST http://gateway:8080/function/my-fn  { body }
Step 2:  Gateway authenticates (basic auth or OIDC JWT)
Step 3:  Gateway looks up K8s Service for "my-fn"
Step 4:  Gateway forwards request → Pod:8080 (watchdog)
Step 5:  Watchdog checks max_inflight counter
Step 6:  Watchdog forwards to function process (http: localhost:3000, stdio: fork)
Step 7:  Function processes, returns response
Step 8:  Watchdog returns response → Gateway → Client
Step 9:  Prometheus scrapes /metrics on Gateway
```

**Latency overhead**: ~5–15ms (Gateway auth + K8s DNS lookup + watchdog forward)

### 1.3 OpenFaaS Invocation Modes

| Mode | How it works | Best for |
|---|---|---|
| **http** | of-watchdog keeps function process warm; forwards HTTP to localhost:3000 | Long-running, stateful, ML models |
| **stdio** | of-watchdog forks a new process per request, pipes stdin/stdout | Simple scripts, CLIs, max isolation |
| **streaming** | SSE/chunked response support | Long output, progressive results |
| **async** | Gateway enqueues to NATS; queue-worker dequeues + invokes | Fire-and-forget, batch, background |

### 1.4 OpenFaaS: What It Does NOT Have

This is the gap Relay fills:

| Missing in OpenFaaS | Impact |
|---|---|
| **No LLM awareness** | Can run an agent container, but has no concept of tokens, models, or prompts |
| **No memory injection** | Functions are stateless; no persistent agent context between calls |
| **No MCP tool injection** | No tool registry; each function must wire its own tools |
| **No agent identity** | No DID, no sponsor chain, no passport |
| **No per-call budget gates** | Can rate-limit by RPS, but no token/cost budget enforcement |
| **No audit with semantic content** | Prometheus metrics only; no prompt/response audit log |
| **No PII/PHI redaction** | No content inspection at the gateway layer |
| **No policy-as-code for LLMs** | No model allow/deny lists, no instruction injection |
| **No cross-function governance** | Each function is isolated; no org-level policy |
| **Kubernetes required for prod** | Heavyweight; faasd for edge is limited |

---

## 2. Relay: Full Architecture (OpenFaaS Standard + Connector Runtime)

Relay takes every concept from OpenFaaS — Gateway, Watchdog, function lifecycle, async queue, auto-scale — and rebuilds them with **agent-native intelligence** powered by the Connector kernel.

### 2.1 Full Component Map

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT                                        │
│  faas-cli equivalent: relay CLI / Python SDK / TypeScript SDK / HTTP       │
│                                                                            │
│  relay register --name fn --uri http://localhost:3000                      │
│  relay invoke fn --input '{"query": "hello"}'                              │
│  POST http://relay:8087/api/v1/functions/fn/invoke  { body }               │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────────┐
│                         RELAY GATEWAY (port 8087)                          │
│                      ← Axum HTTP server, same pattern as all plugins →     │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Function Registry                                                  │   │
│  │  - Postgres: relay_functions (name, uri, port, policy, status)     │   │
│  │  - Health check loop (30s ping to each registered URI)             │   │
│  │  - Live status: healthy / degraded / unreachable                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Relay Watchdog  (equivalent to of-watchdog — built into proxy)    │   │
│  │                                                                     │   │
│  │  On every invoke:                                                   │   │
│  │  1. Auth check      → Connector RBAC (API key + role)              │   │
│  │  2. Admission gate  → Connector pre-flight (injection, firewall)   │   │
│  │  3. Budget check    → Connector metering (tokens/cost remaining)   │   │
│  │  4. Memory inject   → Connector memory kernel (agent context)      │   │
│  │  5. Tool inject     → Connector MCP (filtered tool list)           │   │
│  │  6. Prompt inject   → Prepend instructions to system prompt        │   │
│  │  7. Identity attach → AgentPassport DID in request headers         │   │
│  │  8. Forward         → reqwest HTTP POST to registered URI          │   │
│  │  9. Response audit  → Connector audit log + TraceTramp OTEL        │   │
│  │  10. PII scrub      → Connector HIPAA controls on response         │   │
│  │  11. Cost record    → Connector metering + LedgerLens              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Async Queue (equiv. NATS in OpenFaaS)                             │   │
│  │  - POST /functions/:name/invoke?async=true                        │   │
│  │  - Tokio task queue (in-process) → Postgres job table             │   │
│  │  - Retry with exponential backoff (N attempts, configurable)      │   │
│  │  - Webhook callback on completion / failure                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Auto-suspend / Auto-resume                                        │   │
│  │  - Connector agent lifecycle: suspend, quarantine, terminate       │   │
│  │  - Budget exceeded → auto-suspend + notify                        │   │
│  │  - Incident created → auto-quarantine (via AgentPassport)         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │ HTTP only — no shared memory
┌────────────────────────────────────▼───────────────────────────────────────┐
│                         CONNECTOR KERNEL                                   │
│                                                                            │
│  ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌─────────────────────────┐  │
│  │ LLM Proxy │ │ Admission    │ │ Memory   │ │ MCP Server (30+ tools)  │  │
│  │ :9091/v1  │ │ Gate         │ │ Kernel   │ │ exec, file, git, search │  │
│  └───────────┘ └──────────────┘ └──────────┘ └─────────────────────────┘  │
│  ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌─────────────────────────┐  │
│  │ RBAC +    │ │ Budget Gate  │ │ Audit    │ │ Secret Store + PHI      │  │
│  │ API Keys  │ │ (hard limits)│ │ Log (CID)│ │ Redaction               │  │
│  └───────────┘ └──────────────┘ └──────────┘ └─────────────────────────┘  │
│  ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌─────────────────────────┐  │
│  │ A2A       │ │ UCAN         │ │ Signal   │ │ Self-Heal Candidates     │  │
│  │ Channels  │ │ Capabilities │ │ Handlers │ │ + Circuit Breaker        │  │
│  └───────────┘ └──────────────┘ └──────────┘ └─────────────────────────┘  │
└────────────────────────────────────┬───────────────────────────────────────┘
              ↕                      │                          ↕
┌─────────────▼──────────┐ ┌────────▼───────────┐ ┌───────────▼────────────┐
│  AgentPassport         │ │  LedgerLens         │ │  TraceTramp            │
│  - DID per function    │ │  - Cost per fn/org  │ │  - OTEL trace per call │
│  - Reputation score    │ │  - Budget reports   │ │  - Flamegraph / spans  │
│  - Revocation cascade  │ │  - Anomaly alerts   │ │  - Latency breakdown   │
└────────────────────────┘ └─────────────────────┘ └────────────────────────┘
                                     │
┌────────────────────────────────────▼───────────────────────────────────────┐
│                        YOUR FUNCTION (unchanged)                           │
│                                                                            │
│   Python / TypeScript / Go / Rust / Shell / Any HTTP service               │
│   Running anywhere: localhost:3000, k8s pod, Lambda, VM, Docker, EC2       │
│   Zero code changes required                                               │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Request Lifecycle — Step by Step

### 3.1 Synchronous Invocation (full detail)

```
CLIENT
  POST http://relay:8087/api/v1/functions/customer-support/invoke
  Headers: X-API-Key: cpk_live_...
  Body: { "query": "I need a refund" }
  │
  ▼
RELAY GATEWAY — middleware stack (sequential, <5ms total overhead)
  │
  ├─ [1] Auth middleware
  │       → X-API-Key → Connector RBAC API
  │       → GET /auth/verify?key=cpk_live_...
  │       → Returns: { role: "agent", org_id: "acme", budget_remaining: "$4.23" }
  │       → REJECT if: key invalid / role insufficient / function suspended
  │
  ├─ [2] Load function definition
  │       → SELECT * FROM relay_functions WHERE name='customer-support' AND status='healthy'
  │       → Load: uri, policy_json, instructions
  │       → REJECT if: function not found / status=suspended / health=unreachable
  │
  ├─ [3] Admission gate
  │       → POST /admission/check  { content: req.body, function: "customer-support" }
  │       → Connector checks: prompt injection, content firewall, PII in input
  │       → Returns: ALLOW / DENY / REDACT
  │       → If REDACT: apply redactions to body before forwarding
  │       → If DENY: return 403 with reason
  │
  ├─ [4] Budget gate
  │       → POST /metering/check { function: "customer-support", org: "acme" }
  │       → Connector checks: per_call_tokens remaining, per_day_usd remaining
  │       → If exceeded: return 429 with { budget_exhausted: true, resets_at: "..." }
  │
  ├─ [5] Memory injection
  │       → GET /memory/agent?did=did:connector:agent:customer-support&limit=5
  │       → Returns: last 5 memory entries for this agent
  │       → Appended to request as: X-Relay-Memory-Context: base64(json)
  │       → Function can read this header to get persistent context
  │
  ├─ [6] Tool injection
  │       → GET /mcp/tools?allowed=[memory_read,memory_write,web_search]
  │       → Returns: filtered tool definitions from Connector MCP
  │       → Appended to request as: X-Relay-Tools: base64(json)
  │       → If function calls OpenAI with function_calling, Relay can auto-attach these
  │
  ├─ [7] Instruction injection (system prompt)
  │       → If request body contains "messages" array (OpenAI format):
  │           Find system message → prepend policy.instructions
  │           If no system message: inject one with instructions
  │       → This happens transparently — function code sees the enriched prompt
  │
  ├─ [8] Identity header
  │       → GET /agentpassport/did?name=customer-support
  │       → Append: X-Agent-DID: did:connector:agent:customer-support-uuid
  │       → Function can use this to sign its own responses
  │
  ▼
FORWARD
  → reqwest HTTP POST to function URI: http://localhost:3000/run
  → Forward: body (with injected instructions if OpenAI format)
  → Forward: all X-Relay-* headers
  → Timeout: policy.timeout_secs (default: 30)
  │
  ▼
FUNCTION RUNS (your code, unchanged)
  → Calls OpenAI:
      OPENAI_BASE_URL=http://relay:8087/llm/v1   ← Relay intercepts this too
      (Relay→Connector gateway→actual LLM)
  → Or calls any tool, database, API
  → Returns: { "result": "...", "memory_update": {...} }
  │
  ▼
RELAY — RESPONSE PROCESSING
  │
  ├─ [9] PII scrub on response
  │       → POST /hipaa/scrub { content: response.body }
  │       → Redact SSN, credit cards, emails, phone numbers per policy
  │
  ├─ [10] Memory update
  │       → If response contains "memory_update" key:
  │           POST /memory/agent { did: ..., entries: response.memory_update }
  │           Connector memory kernel persists this
  │
  ├─ [11] Audit log
  │       → POST /audit/log {
  │             function: "customer-support",
  │             input_hash: sha256(request_body),
  │             output_hash: sha256(response_body),
  │             tokens_in: 350, tokens_out: 120,   ← from LLM proxy headers
  │             cost_usd: 0.0042,
  │             latency_ms: 1240,
  │             actor_did: "did:connector:user:...",
  │             audit_cid: chain_cid(prev_cid, payload)
  │           }
  │
  ├─ [12] TraceTramp OTEL span close
  │       → Report span: name="relay.invoke.customer-support"
  │             attributes: model, tokens, latency, status, function_uri
  │
  ├─ [13] LedgerLens cost attribution
  │       → POST /costs { function: "customer-support", cost_usd: 0.0042, model: "gpt-4o-mini" }
  │
  └─ [14] Return to client
          HTTP 200 { "result": "...", "trace_id": "...", "audit_cid": "..." }
          Latency overhead: ~8–15ms (all Connector calls are localhost or same-cluster)
```

### 3.2 Asynchronous Invocation

```
CLIENT
  POST /api/v1/functions/batch-processor/invoke?async=true
  Headers: X-Callback-URL: https://my-app.com/webhook/result
  Body: { "file": "s3://bucket/data.csv" }
  │
  ▼
RELAY
  → Run [1]-[4] (auth, policy, admission, budget) synchronously
  → Enqueue job to relay_async_jobs table:
      { id: uuid, function: "batch-processor", body: ..., callback_url: ..., status: "queued" }
  → Return immediately: HTTP 202 Accepted { "job_id": "...", "status": "queued" }
  │
  (background Tokio task)
  │
  ▼
ASYNC WORKER
  → Dequeue job
  → Run [5]-[14] (memory inject → forward → audit → cost)
  → On success: POST callback_url { "job_id": "...", "result": "...", "status": "done" }
  → On failure: retry (exponential backoff, max 3 attempts)
  → On final failure: POST callback_url { "status": "failed", "error": "...", "attempts": 3 }
  → Update relay_async_jobs: status = done/failed
```

### 3.3 LLM Proxy Sub-path

Your function calls OpenAI. If `OPENAI_BASE_URL` points at Relay:

```
FUNCTION CODE
  openai.chat.completions.create(model="gpt-4o-mini", messages=[...])
  → POST http://relay:8087/llm/v1/chat/completions  { model, messages }
  │
  ▼
RELAY LLM PROXY
  → Reads X-Agent-DID from request context
  → Routes to Connector gateway: POST http://connector:9091/v1/chat/completions
  → Connector: auth, admission gate, PHI redaction, model routing, cost tracking
  → Connector → actual LLM provider (OpenAI, Anthropic, Ollama)
  → Connector returns response + X-Tokens-In / X-Tokens-Out / X-Cost-USD headers
  → Relay reads cost headers → stores in relay_invocations for attribution
  → Returns response to function
```

This means **every LLM call from every function is governed** — even if the function doesn't know about Relay beyond its `OPENAI_BASE_URL`.

---

## 4. The Relay Watchdog vs OpenFaaS of-watchdog

| Concept | OpenFaaS of-watchdog | Relay Watchdog |
|---|---|---|
| **What it is** | Sidecar process inside each container | Built into Relay Gateway (no sidecar needed) |
| **Deployment** | Must ship watchdog binary IN your container | Function runs anywhere — no binary required |
| **Warm process** | `http` mode: keeps process warm between calls | Function is always warm — it's your own server |
| **Health check** | `/healthz` in watchdog | Relay health-check loop pings your URI every 30s |
| **Concurrency control** | `max_inflight` env var | `policy.max_concurrent` in relay.yaml |
| **Timeout** | `read_timeout` / `write_timeout` env vars | `policy.timeout_secs` in relay.yaml |
| **Auth** | Basic auth / OIDC at gateway | Connector RBAC (API key, JWT, SSO) at gateway |
| **Content awareness** | None — binary pipe | Full LLM content awareness (prompts, tokens) |
| **Memory** | None — stateless | Connector memory kernel (persistent agent context) |
| **Tool injection** | None — function wires own tools | Connector MCP (30+ tools, policy-filtered) |
| **Budget** | None | Connector budget gate (tokens + USD hard limits) |
| **Audit** | None (Prometheus RPS metrics only) | Connector CID-chained audit log (every call) |
| **PII redaction** | None | Connector HIPAA controls |
| **Identity** | None | AgentPassport DID per function |

**The key difference**: OpenFaaS watchdog is a **process manager**. Relay watchdog is an **agent runtime** — it understands what the function IS doing, not just that it ran.

---

## 5. relay.yaml Specification (Full)

The OpenFaaS equivalent is `stack.yaml`. Relay's is `relay.yaml`.

```yaml
# relay.yaml — full specification
version: "1"

# Global defaults (inherited by all functions unless overridden)
defaults:
  timeout_secs: 30
  max_concurrent: 10
  retry:
    max_attempts: 3
    backoff: exponential       # linear | exponential | none
    backoff_base_ms: 500
  budget:
    per_day_usd: 10.00
    on_exceed: suspend          # suspend | deny | notify
  pii_redact: true
  audit: true

functions:
  # ── Minimal definition (same friction as OpenFaaS minimal stack.yaml) ───────
  - name: hello-world
    uri: http://localhost:3000/run

  # ── Full definition (enterprise-grade) ──────────────────────────────────────
  - name: customer-support
    uri: http://customer-support-svc:3000/run
    description: "Tier-1 customer support agent"
    version: "2.1"

    # Invocation
    timeout_secs: 45
    max_concurrent: 20
    modes:
      sync: true               # POST /functions/customer-support/invoke
      async: true              # POST /functions/customer-support/invoke?async=true
      scheduled: "0 9 * * MON-FRI"   # Cron trigger (optional)

    # Policy — compiled to Connector RBAC + admission gate
    policy:
      require_role: [agent, senior, admin]
      allowed_models:
        - gpt-4o-mini
        - claude-haiku-3-5
      deny_models:
        - gpt-4o               # Too expensive for support tier
      budget:
        per_call_tokens: 2000
        per_call_usd: 0.01
        per_day_usd: 50.00
        on_exceed: deny
      tools:
        allow: [memory_read, memory_write, web_search, crm_lookup]
        deny:  [exec, git_commit, file_write, file_delete]
      content:
        pii_redact: true
        hipaa: false
        injection_detection: true
        hallucination_guard: false

    # Instructions — injected into system prompt on every call
    instructions: |
      You are a customer support assistant for Acme Corp.
      Be concise, empathetic, and solution-focused.
      Never reveal internal pricing, system names, or employee details.
      Always escalate billing disputes to tier-2 by saying:
      "I'm connecting you with our billing specialist."
      Maximum response length: 3 sentences.

    # Memory — Connector memory kernel configuration
    memory:
      enabled: true
      scope: per_user          # per_user | per_function | per_org | global
      max_entries: 10
      ttl_hours: 72

    # Identity — AgentPassport auto-registration
    identity:
      sponsor_email: platform-eng@acme.com
      sponsor_legal_entity: "Acme Corp"
      auto_register: true
      credential_types:
        - CapabilityCredential
        - ComplianceCredential

    # Health check
    health:
      path: /health
      interval_secs: 30
      timeout_ms: 2000
      failure_threshold: 3     # mark unhealthy after 3 failures

    # Retry
    retry:
      max_attempts: 2
      backoff: exponential
      retry_on: [502, 503, 504, timeout]

    # Webhook (async mode callback)
    webhook:
      on_success: https://my-app.com/webhooks/relay/success
      on_failure: https://my-app.com/webhooks/relay/failure
      hmac_secret: ${RELAY_WEBHOOK_SECRET}

    # Observability
    tracing:
      provider: tracetramp     # or: otel | none
      sample_rate: 1.0
    cost_attribution:
      provider: ledgerlens
      dimension: team          # team | user | role | function
      label: "support-tier-1"

    metadata:
      team: customer-success
      env: production
      cost_center: CS-001
```

**Compare to OpenFaaS stack.yaml**:

```yaml
# OpenFaaS stack.yaml — for contrast
version: 1.0
provider:
  name: openfaas
  gateway: http://127.0.0.1:8080

functions:
  customer-support:
    lang: python3-http
    handler: ./customer-support
    image: registry/customer-support:latest
    environment:
      max_inflight: 20
      read_timeout: 45s
    labels:
      com.openfaas.scale.max: "10"
```

OpenFaaS stack.yaml configures **container deployment**.
Relay relay.yaml configures **agent runtime behaviour**.

---

## 6. Invocation Modes: Relay vs OpenFaaS

### 6.1 Sync (both have this)

```bash
# OpenFaaS
curl http://gateway:8080/function/customer-support -d '{"query": "help"}'

# Relay — identical UX
curl http://relay:8087/api/v1/functions/customer-support/invoke -d '{"query": "help"}' \
  -H "X-API-Key: cpk_live_..."
```

### 6.2 Async (both have this — Relay adds audit + budget)

```bash
# OpenFaaS
curl http://gateway:8080/async-function/batch-job -d '{"file": "data.csv"}'
# Returns: 202 Accepted (no call ID, no webhook guarantee)

# Relay
curl http://relay:8087/api/v1/functions/batch-job/invoke?async=true \
  -H "X-Callback-URL: https://myapp.com/done" \
  -d '{"file": "s3://bucket/data.csv"}'
# Returns: 202 Accepted { "job_id": "uuid", "status": "queued", "budget_remaining": "$8.20" }
# Callback fires: { "job_id": "uuid", "result": "...", "cost_usd": 0.23, "audit_cid": "cid:..." }
```

### 6.3 Scheduled (OpenFaaS Pro only — Relay: built-in)

```yaml
# relay.yaml
- name: daily-report
  uri: http://report-agent:3000/run
  modes:
    scheduled: "0 8 * * *"    # Every day at 8am UTC
  instructions: "Generate the daily cost summary report."
```

```bash
# Relay — no extra setup, schedule runs inside Relay's tokio scheduler
relay logs daily-report --tail 10
# Shows: scheduled runs, cost per run, last result
```

### 6.4 Event-triggered (Relay: Connector signals)

```yaml
# relay.yaml
- name: incident-responder
  uri: http://oncall-agent:3000/run
  modes:
    events:
      - source: connector.signals
        filter: "event_type == 'budget_breach' OR event_type == 'security_incident'"
```

Any Connector signal (budget breach, anomaly, quarantine event) can trigger a Relay function automatically — with full audit and context injection.

### 6.5 Direct LLM call (Relay unique — OpenFaaS has no concept)

```bash
# Your function doesn't need to be running at all
# Relay can invoke a "virtual function" that is just an instruction set + LLM call

curl http://relay:8087/api/v1/invoke -d '{
  "instructions": "You are a data validator. Return only JSON.",
  "input": { "data": "..." },
  "model": "gpt-4o-mini",
  "budget": { "max_tokens": 500 }
}'
# Relay handles: instruction injection → Connector LLM proxy → budget gate → audit → return
```

This is pure Relay — no function registration, no container, no code. Just policy + instruction + Connector runtime.

---

## 7. Where Relay Goes Beyond OpenFaaS

| Layer | OpenFaaS | Relay |
|---|---|---|
| **Runtime awareness** | HTTP in / HTTP out | Understands: prompts, tokens, models, memory, tools |
| **Identity per function** | None | AgentPassport DID auto-registered on `relay register` |
| **Persistent memory** | None (stateless) | Connector memory kernel (scope: user/function/org) |
| **Tool injection** | None (manual wiring) | Connector MCP (30+ tools, filtered by policy) |
| **Instruction injection** | None | System prompt prepended at gateway layer |
| **Budget enforcement** | None | Hard token + USD gates, per call + per day |
| **Content inspection** | None | Admission gate: injection, hallucination, PII |
| **Compliance** | None | HIPAA PHI redaction, SOC 2 audit trail, CID chain |
| **Auto-quarantine** | Manual K8s kill | Connector lifecycle: suspend / quarantine / terminate |
| **Cross-function governance** | None | org-level policy in relay.yaml + Connector RBAC |
| **Cost attribution** | None | LedgerLens: per function, per team, per role |
| **Tracing** | Prometheus RPS only | TraceTramp OTEL: per-call spans, token attribution |
| **Federation** | None | AgentPassport: cross-org function verification |
| **No container required** | Requires Docker/K8s | Function can be localhost:3000, a VM, Lambda, anything |
| **Async audit** | No audit | Job table + Connector audit on every async job |
| **Event triggers** | Kafka/SQS (Pro only) | Connector signals (any event type, free tier) |

---

## 8. What Gets Built (Implementation Map)

### 8.1 Database Schema

```sql
-- relay_functions: the function registry (equiv. K8s Deployment in OpenFaaS)
CREATE TABLE relay_functions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL UNIQUE,
    uri             TEXT NOT NULL,
    description     TEXT,
    version         TEXT NOT NULL DEFAULT '1.0',
    policy_json     JSONB NOT NULL DEFAULT '{}',
    instructions    TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','healthy','degraded','unreachable','suspended')),
    connector_pid   TEXT,           -- linked ConnectorOS process ID
    passport_did    TEXT,           -- AgentPassport DID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- relay_invocations: every call, fully attributed (equiv. Prometheus in OpenFaaS + audit)
CREATE TABLE relay_invocations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id     UUID NOT NULL REFERENCES relay_functions(id),
    function_name   TEXT NOT NULL,
    caller_id       TEXT,           -- API key owner / user DID
    caller_role     TEXT,
    mode            TEXT NOT NULL DEFAULT 'sync' CHECK (mode IN ('sync','async','scheduled','event')),
    input_hash      TEXT,           -- SHA-256 of input (not raw input — privacy)
    output_hash     TEXT,           -- SHA-256 of output
    model_used      TEXT,
    tokens_in       INT,
    tokens_out      INT,
    cost_usd        NUMERIC(10,6),
    latency_ms      INT,
    status          TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success','error','timeout','denied','budget_exceeded')),
    error_message   TEXT,
    audit_cid       TEXT,           -- CID-chained entry
    trace_id        TEXT,           -- TraceTramp span ID
    invoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- relay_async_jobs: async invocation queue (equiv. NATS in OpenFaaS)
CREATE TABLE relay_async_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id     UUID NOT NULL REFERENCES relay_functions(id),
    function_name   TEXT NOT NULL,
    body            JSONB NOT NULL,
    callback_url    TEXT,
    hmac_secret_ref TEXT,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','running','done','failed','cancelled')),
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    next_attempt_at TIMESTAMPTZ,
    result_json     JSONB,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- relay_health_checks: function health history
CREATE TABLE relay_health_checks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id     UUID NOT NULL REFERENCES relay_functions(id),
    status          TEXT NOT NULL CHECK (status IN ('healthy','degraded','unreachable')),
    latency_ms      INT,
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- relay_policies: versioned policy history per function
CREATE TABLE relay_policies (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id     UUID NOT NULL REFERENCES relay_functions(id),
    policy_json     JSONB NOT NULL,
    instructions    TEXT,
    version         INT NOT NULL DEFAULT 1,
    active          BOOL NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 8.2 Source Modules

```
plugins/relay/src/
├── main.rs           — startup, dual-port (API:8087 + Prometheus:9093)
│                       background tasks: health-check loop, async job worker
├── types.rs          — FunctionDef, InvocationRecord, PolicyConfig, AsyncJob
├── error.rs          — AppError (CISO-grade, no internal leakage)
├── registry.rs       — CRUD for relay_functions + health-check loop
├── proxy.rs          — core: auth→admission→budget→memory→tools→inject→forward→audit
├── policy.rs         — relay.yaml parser, policy compiler → Connector config
├── instructions.rs   — system prompt injection (OpenAI and Anthropic format)
├── memory.rs         — Connector memory kernel bridge (read + write per call)
├── tools.rs          — Connector MCP bridge (filtered tool list injection)
├── queue.rs          — async job enqueue/dequeue worker (Tokio task)
├── scheduler.rs      — cron + Connector event trigger loop
├── identity.rs       — AgentPassport auto-registration on function register
├── connector.rs      — ConnectorClient: RBAC, budget, audit, MCP, memory, signals
├── tracing.rs        — TraceTramp OTEL span open/close per invocation
├── cost.rs           — LedgerLens cost attribution per invocation
└── routes.rs         — 14 API endpoints + LLM proxy sub-path
```

### 8.3 API Surface

| Method | Endpoint | OpenFaaS equivalent | What it does |
|---|---|---|---|
| `POST` | `/api/v1/functions` | `POST /system/functions` | Register a function |
| `GET` | `/api/v1/functions` | `GET /system/functions` | List all + health |
| `GET` | `/api/v1/functions/:name` | `GET /system/function/:name` | Detail + live stats |
| `PUT` | `/api/v1/functions/:name` | `PUT /system/functions` | Update policy/instructions |
| `DELETE` | `/api/v1/functions/:name` | `DELETE /system/functions` | Deregister |
| `POST` | `/api/v1/functions/:name/invoke` | `POST /function/:name` | Sync invoke |
| `POST` | `/api/v1/functions/:name/invoke?async=true` | `POST /async-function/:name` | Async invoke |
| `GET` | `/api/v1/functions/:name/jobs` | *(none)* | List async jobs |
| `GET` | `/api/v1/functions/:name/logs` | *(none — Prometheus only)* | Invocation audit log |
| `GET` | `/api/v1/functions/:name/stats` | *(none — Prometheus only)* | Cost, latency, error rate |
| `POST` | `/api/v1/functions/:name/suspend` | *(manual K8s scale to 0)* | Suspend via Connector |
| `POST` | `/api/v1/functions/:name/resume` | *(manual K8s scale up)* | Resume |
| `POST` | `/api/v1/invoke` | *(none)* | Raw invoke (no registration needed) |
| `POST` | `/llm/v1/chat/completions` | *(none)* | LLM proxy sub-path (Connector gateway) |
| `GET` | `/health` | `GET /healthz` | DB + Connector health |

### 8.4 Background Tasks

```
Task 1: Health Check Loop (every 30s)
  → For each function in relay_functions WHERE status != 'suspended':
      GET function.uri + health.path  (timeout: health.timeout_ms)
      → healthy: update status='healthy', record latency
      → timeout / 5xx: increment failure_count
      → failure_count >= threshold: status='degraded' / 'unreachable'
      → notify via Connector signal if status changes

Task 2: Async Job Worker (always running, Tokio task)
  → SELECT * FROM relay_async_jobs WHERE status='queued' AND next_attempt_at <= NOW()
  → For each job: run full proxy pipeline
  → On success: update status='done', fire callback webhook
  → On failure: increment attempts, set next_attempt_at (exponential backoff)
  → On max_attempts reached: status='failed', fire failure callback

Task 3: Scheduled Trigger Loop (every 60s tick)
  → Parse scheduled cron expressions from relay_functions
  → Fire invoke for functions whose next_run <= NOW()
  → Update next_run after firing

Task 4: Connector Signal Listener (poll every 30s)
  → GET /tools/signals/pending
  → Match signals to relay_functions event triggers
  → Fire invoke for matching functions
```

---

## 9. The Relay CLI (equiv. faas-cli)

```bash
# Register — relay.yaml or inline
relay register -f relay.yaml
relay register --name hello --uri http://localhost:3000/run

# Invoke
relay invoke customer-support --input '{"query":"I need a refund"}' --wait
relay invoke batch-processor  --input @payload.json --async

# Inspect
relay list                          # all functions + health status
relay status customer-support       # health, stats, recent calls
relay logs customer-support --tail 20
relay stats customer-support --since 24h

# Policy
relay policy get customer-support   # show current policy
relay policy set customer-support -f updated-policy.yaml  # update without restart
relay policy diff customer-support  # show diff from last version

# Lifecycle
relay suspend customer-support --reason "security review"
relay resume customer-support

# Attestation (via AgentPassport)
relay export customer-support --format json   # signed attestation pack
relay export customer-support --format text   # procurement-grade report

# Import from other frameworks
relay import langgraph  my_graph.py  --name "rag-pipeline"
relay import crewai     my_crew.py   --name "research-crew"
relay import openai-sdk my_agents.py --name "customer-flow"
```

---

## 10. Performance

OpenFaaS gateway adds ~5–15ms latency per call (K8s DNS + watchdog forward).

Relay adds ~8–15ms per call:

| Step | Time |
|---|---|
| Auth (Connector RBAC, cached JWT) | ~2ms |
| Policy + registry lookup (Postgres, indexed) | ~1ms |
| Admission gate (in-memory, Connector) | ~2ms |
| Budget check (Connector, cached per window) | ~1ms |
| Memory inject (Connector, async prefetch) | ~2ms |
| Tool list inject (cached, invalidated on policy change) | ~0ms |
| Instruction inject (in-process string op) | ~0ms |
| Forward (reqwest to function URI) | ~1ms (same cluster) |
| Audit log (async, non-blocking) | ~0ms on critical path |
| **Total overhead** | **~8–15ms** |

Cache strategy: RBAC decisions cached for 60s per key. Budget windows cached per function per 5min. Tool lists cached until policy version changes. Memory context prefetched on first call, invalidated on memory_update.

---

## 11. Deployment

```bash
# Minimal (no Kubernetes required — unlike OpenFaaS)
docker run -p 8087:8087 -p 9093:9093 \
  -e DATABASE_URL=postgres://... \
  -e CONNECTOR_URL=http://connector:9091 \
  -e RELAY_API_KEY=change-me \
  connector/relay:latest

# Register any function — running anywhere
relay register --name my-agent --uri http://my-service:3000/run

# Done. No container build. No K8s manifest. No Dockerfile.
```

**OpenFaaS requires**:
1. Kubernetes cluster
2. Helm chart deploy
3. Container registry
4. `faas-cli build` (Dockerfile per function)
5. `faas-cli push` (publish to registry)
6. `faas-cli deploy` (K8s Deployment + Service)

**Relay requires**:
1. Docker run (one container)
2. `relay register --uri http://your-existing-service`

If your function is already running (a Docker container, a VM, a Lambda, a localhost server) — Relay registers it in one command. No rebuild, no push, no manifest.

---

> **Relay: OpenFaaS for AI agents. Minus Kubernetes. Plus memory, tools, identity, governance, and the full Connector runtime.**
