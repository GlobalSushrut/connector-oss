# TraceTramp: What It Is and How to Use It

## What It Is

TraceTramp is an **AI runtime proxy** that sits between your application and any LLM provider. Every request passes through it. Every decision it makes is recorded. Nothing is hidden, nothing is sampled — every prompt, every response, every action is captured in a tamper-evident chain.

It runs in two modes:

| Mode | What It Does |
|------|-------------|
| **View** | Observe and record — trace every request, explain every decision, prove integrity, attribute cost |
| **Control** | Enforce at runtime — block requests, redact PII, enforce budgets, require human approval |

Both modes share the same proxy. The difference is whether the proxy acts on policy or just records it.

## Architecture

TraceTramp exposes two servers:

- **Data Plane** (`:9091`) — receives LLM API calls, runs the View or Control pipeline, proxies to the provider
- **Management Plane** (`:9092`) — admin API for tenants, providers, RBAC, budgets, policies, compliance exports

Every request through the Data Plane results in a **Decision Tree** stored in Postgres — a full record of what was received, what policy said, which provider was used, what came back, what it cost, and a cryptographic receipt from the Connector kernel.

## Integration: One Line of Code

Your existing code does not change except for the base URL:

```python
# Before
client = OpenAI(api_key="sk-...")

# After
client = OpenAI(
    api_key="tt_live_xxx",       # your TraceTramp API key
    base_url="http://localhost:9091/v1"
)
```

Any OpenAI-compatible SDK works. Python, TypeScript, Go, Ruby — all work without modification.

## What Gets Recorded

For every request, TraceTramp records:

1. **Raw input** — the exact messages the user sent
2. **Policy outcome** — allowed, blocked, rerouted, or flagged
3. **Provider selected** — which model was actually called and why
4. **Raw output** — the exact response from the provider
5. **Derived action** — what the LLM's response means (tool call, refund, escalation, etc.)
6. **Cost** — exact tokens and USD cost attributed to tenant, app, and actor
7. **Receipt** — a CID-chained cryptographic hash from the Connector kernel

## API Reference

### Chat Completions (OpenAI-compatible)
```
POST /v1/chat/completions
POST /v1/responses
```

### Evidence Queries
```
GET /trace/{trace_id}          — full timeline of all steps in a request
GET /decision/{trace_id}       — the decision tree for a request
GET /explain/{request_id}      — human-readable explanation of each decision
GET /prove/{request_id}        — cryptographic proof: hashes, receipt CID, tamper check
GET /cost/{request_id}         — cost breakdown with token attribution
GET /compliance/export         — regulator-ready CSV or JSON export
```

### Workflow and Agent APIs
```
POST /v1/workflows              — create a workflow definition
GET  /v1/workflows              — list workflows
POST /v1/workflows/{id}/run    — execute a workflow
POST /v1/workflows/{id}/trigger — trigger via webhook event
GET  /v1/runs/{run_id}         — get run status
POST /v1/runs/{run_id}/cancel  — cancel a running workflow

POST /v1/agents/run            — start an agent with tools + model
POST /v1/agents/{id}/continue  — continue a paused agent

POST /v1/tools/invoke          — invoke a tool by name
POST /v1/tools/{name}/invoke   — invoke a specific tool
POST /v1/tools/batch           — invoke multiple tools in parallel

POST /v1/functions/{name}/call  — call a function (OpenFaaS / Lambda / Docker)
POST /v1/functions/{name}/async — async function call with job ID
```

### Management API (`:9092`)
```
# Tenants
GET/POST       /admin/tenants
GET/PUT/DELETE /admin/tenants/{id}

# Providers
GET/POST       /admin/providers
GET/PUT/DELETE /admin/providers/{id}

# RBAC
GET/POST       /admin/roles
POST           /admin/roles/{id}/assign
GET/POST       /admin/users

# Policy and Budget
GET/POST       /admin/policies
GET/POST       /admin/budgets

# Approvals
GET            /admin/approvals
POST           /admin/approvals/{id}/approve
POST           /admin/approvals/{id}/reject

# Logging and Compliance
GET/POST       /admin/log-destinations
GET/POST       /admin/compliance/exports
```

## Running It

### Prerequisites

- Rust (for building from source)
- PostgreSQL
- Redis
- Connector instance running

### Start

```bash
cd plugins/tracetramp

# Start Postgres and Redis
docker-compose up -d postgres redis

# Run database migrations
cargo sqlx migrate run

# Set environment
cp .env.example .env
# Fill in: database URL, redis URL, connector URL, API keys

# Run
cargo run
```

### Key Environment Variables

```bash
TRACETRAMP_DATA_PLANE_PORT=9091
TRACETRAMP_MANAGEMENT_PLANE_PORT=9092
TRACETRAMP_DATABASE_URL=postgres://user:pass@localhost/tracetramp
TRACETRAMP_REDIS_URL=redis://localhost:6379
TRACETRAMP_CONNECTOR_BASE_URL=http://localhost:8080
TRACETRAMP_CONNECTOR_API_KEY=cpk_live_xxx
TRACETRAMP_CONTROL_MODE_ENABLED=true

OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AZURE_OPENAI_API_KEY=...
OLLAMA_BASE_URL=http://localhost:11434
```

## What a Request Looks Like End to End

```
Client App
  │
  │ POST /v1/chat/completions {"model": "gpt-4o", "messages": [...]}
  ▼
TraceTramp Data Plane (:9091)
  1. Authenticate API key → resolve tenant and actor
  2. Check policy via Connector → allow / block / redact / reroute
  3. If Control mode: enforce budget, check tool permissions, redact PII
  4. Select provider and model (routing policy or explicit)
  5. Call provider (OpenAI / Anthropic / Azure / Ollama)
  6. Record Decision Tree in Postgres
  7. Calculate and store cost
  8. Issue receipt via Connector (CID-chained hash)
  9. Return response with X-Trace-Id and X-Receipt-CID headers
  │
  ▼
Client App receives response + trace metadata
```

## Example Decision Tree Output

```
GET /decision/550e8400-e29b-41d4-a716-446655440000

{
  "trace_id": "550e8400-...",
  "tenant_id": "acme-corp",
  "actor_id": "support-agent-1",
  "final_outcome": "tool_invocation",
  "total_cost_usd": 0.00415,
  "receipt_cid": "bafybei9a2f...",
  "nodes": [
    {
      "id": "node-0",
      "node_type": "intent_recognition",
      "model": "gpt-4o",
      "provider": "openai",
      "input_text": "I want a refund for order 12345",
      "output_text": "I'll look up that order for you right now.",
      "action_taken": "tool_invocation",
      "tokens_in": 45,
      "tokens_out": 18,
      "cost_usd": 0.00063,
      "latency_ms": 412,
      "policy_checks": [
        {"policy": "refund_policy", "outcome": "alert", "reason": "refund keyword detected"}
      ]
    }
  ]
}
```

## When to Use TraceTramp

**Use it when any of these are true:**

- You need to prove what your AI told a user
- You have compliance requirements (SOC 2, GDPR, HIPAA, SEC, FINRA)
- You are running multi-tenant AI and need isolated audit trails
- You need cost visibility and budget enforcement per team or project
- You are running agentic workflows with tool calls
- You use more than one LLM provider
- A human needs to approve sensitive AI actions before they execute

**Don't use it when:**

- You are prototyping with a single provider and zero compliance requirements
- Your latency budget is under 50ms end to end (proxy adds ~20-50ms)
- You are a solo developer with no production workloads

## Decision Matrix

| Requirement | Use TraceTramp | Skip It |
|-------------|---------------|---------|
| Multiple LLM providers | Yes | Single provider only |
| Compliance audit trail | Yes | Internal tools only |
| Budget / cost control | Yes | No spend limits needed |
| Tool / agent workflows | Yes | Single LLM calls only |
| Multi-tenant isolation | Yes | Single tenant |
| PII protection | Yes | No sensitive data |
| Human approval gates | Yes | Full automation OK |
