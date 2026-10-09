# AgentLoop — Cloudflare for the Agentic Web

> **The global agent mesh. DNS, proxy, workers, and observability — for the infrastructure layer of AI.**
>
> One network. Every agent. Powered by ConnectorOS.

---

## The Problem Nobody Has Infrastructure For

AI agents in 2026 are where microservices were in 2015: powerful in isolation, fragile at scale.

When enterprises try to connect agents together today:

| Problem | Reality |
|---|---|
| **Hardcoded endpoints** | Agent A calls `http://10.0.1.44:8080` — breaks on every deploy, every scale event, every region migration |
| **No service discovery** | When Agent B moves hosts, every caller must be updated manually |
| **No health-aware routing** | Dead agent instances still receive traffic; callers get 500s |
| **No policy at the hop** | Security teams have zero visibility into what agents are calling each other |
| **No standard protocol** | Agent A calls B over HTTP, C calls D over a custom socket, E uses gRPC |
| **No edge compute** | Logic that should run near the data runs in a central server |
| **No address space** | There is no `agent://` — every agent is just an IP address |

This is exactly the problem Cloudflare solved for the web in 2010. The exact same gap exists in the agentic stack today — and no one has built infrastructure for it.

---

## What AgentLoop Is

**AgentLoop is Cloudflare for AI agents.**

It is the network infrastructure layer between AI agents — providing the same primitives Cloudflare provides for HTTP traffic, rebuilt natively for the semantics of agent workloads.

```
# Before AgentLoop — agents hardcode each other:
response = requests.post("http://10.0.1.44:8080/run", payload)

# After AgentLoop — agents route through the mesh:
response = agentloop.call("agent://summarizer.v2.acme", payload)
# → DNS resolution → policy check → proxy → target agent → receipt
```

That one-line change gives every caller, immediately, with zero changes to the target agent:

- **Global routing** — agent moves host? DNS record updates, callers don't notice
- **Health-aware failover** — dead endpoint removed from routing table in seconds
- **Policy enforcement** — Conductor cage policies checked at every hop
- **Cryptographic receipts** — HMAC-chained, CID-linked — tamper-evident audit trail
- **Cost + latency tracking** — per-hop token cost, response time, status
- **Full replay capability** — any call can be deterministically replayed from the recorded hop

---

## The Four Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                        AgentLoop                                  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 4 — Observability (Design · Ship · Debug · Optimize)  │ │
│  │  Prompt registry · Experiments · Replay · Fleet SLOs        │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 3 — Agent Workers (Edge Compute)                      │ │
│  │  Stateless functions · MCP-native · event-triggered          │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 2 — Agent Mesh (Proxy + Routing)                      │ │
│  │  Policy at every hop · circuit breaking · health-aware LB    │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 1 — Agent DNS (Discovery + Registry)                  │ │
│  │  agent:// address space · AgentCard · version routing        │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────┐
│                    ConnectorOS (Kernel)                           │
│  CID chains · policy · UCAN auth · receipts · history · billing  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Agent DNS

### What it is

AgentLoop introduces the `agent://` address space — a hierarchical, version-aware namespace for AI agents. Every agent gets a **Fully Qualified Agent Name (FQAN)**:

```
agent://summarizer.v2.medical-team.acme-corp
    └── name:    summarizer
    └── version: v2 (or: latest, stable, canary)
    └── team:    medical-team
    └── org:     acme-corp
```

Resolving a FQAN returns an **AgentCard** — a structured JSON document (A2A protocol compatible) containing:
- Live endpoint URLs with current health status
- Supported input/output schemas
- MCP capabilities (tools this agent exposes)
- Required authentication (API key, UCAN capability)
- Rate limits, cost estimates, SLO commitments

### Version routing policies

| Call | What happens |
|---|---|
| `agent://summarizer.latest` | Routes to highest version with `approved` status |
| `agent://summarizer.stable` | Routes to latest version tagged `stable` |
| `agent://summarizer.v3` | Pinned to exactly v3 — 404 if not registered |
| `agent://summarizer.canary` | Routes X% to canary, remainder to stable |
| `agent://summarizer.blue` | Blue/green: switch entire fleet with one command |

### Registering an agent

```bash
curl -X POST https://mesh.agentloop.net/api/v1/dns/register \
  -H "X-AgentLoop-Api-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "summarizer",
    "version_label": "v2",
    "team":          "medical",
    "org":           "acme-corp",
    "endpoint_url":  "http://10.0.1.44:8080",
    "region":        "us-east-1",
    "routing_policy":"round_robin"
  }'

# Response:
# {
#   "dns_record": { "fqan": "summarizer.v2.medical.acme-corp", ... },
#   "endpoint":   { "id": "uuid", "health_status": "unknown", ... }
# }
```

### Resolving an agent

```bash
curl https://mesh.agentloop.net/api/v1/dns/resolve/summarizer.v2.medical.acme-corp

# Returns the full AgentCard:
# {
#   "fqan":        "summarizer.v2.medical.acme-corp",
#   "endpoints":   [{ "url": "http://10.0.1.44:8080", "health_status": "healthy", ... }],
#   "capabilities": { "input_formats": ["text", "pdf"], ... },
#   "ttl_secs":    30
# }
```

### DNS TTL cache

Resolution results are cached in-process using a DashMap keyed by FQAN, with per-record TTLs. A background `health_sweeper` task probes degraded/unhealthy endpoints every 15 seconds and evicts stale cache entries — the mesh always routes to fresh, healthy instances.

---

## Layer 2 — Agent Mesh

### What it is

Every agent-to-agent call routes through the mesh proxy. This is the service mesh model — but without sidecar complexity, because agents already have an HTTP API surface.

```
Agent A  →  agentloop.call("agent://summarizer.v2.acme", payload)
              │
              ▼  AgentLoop Mesh Proxy
              ├── 1. Circuit breaker check (per FQAN, atomic)
              ├── 2. Resolve DNS → healthy endpoint
              ├── 3. Load cage policy (from Conductor)
              ├── 4. Evaluate policy — DENY or ALLOW
              ├── 5. Route to healthy instance (weighted LB)
              ├── 6. Forward request with timeout budget
              ├── 7. Record hop: latency, status, tokens, cost
              ├── 8. HMAC-chain receipt (CID-linked)
              └── 9. Return response + receipt to Agent A
```

### Per-hop features

| Feature | What it does |
|---|---|
| **Circuit breaker** | Per-FQAN atomic counter; opens after N failures, half-opens after cooldown |
| **Weighted routing** | `60% → v2, 40% → v3` for zero-downtime migration |
| **Health-aware failover** | Unhealthy endpoints removed from routing table within one sweep cycle |
| **Policy enforcement** | Conductor cage policies checked before every forward |
| **Canary traffic splitting** | DNS-level canary weight shifts traffic without touching agent code |
| **HMAC-chained receipts** | Every hop produces a cryptographic receipt linked to the previous hop |
| **Context propagation** | `X-Request-ID` and CID chain forwarded across every hop |
| **Deny audit** | DENIED calls are still recorded with reason, for security investigation |

### Making a proxied call

```bash
curl -X POST https://mesh.agentloop.net/api/v1/mesh/call \
  -H "X-AgentLoop-Api-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "callee_fqan":     "agent://summarizer.v2.medical.acme-corp",
    "caller_agent_id": "uuid-of-calling-agent",
    "method":          "POST",
    "payload":         { "text": "Patient notes from 2026-04-19..." }
  }'

# Response:
# {
#   "hop_id":       "uuid",
#   "fqan":         "summarizer.v2.medical.acme-corp",
#   "verdict":      "allow",
#   "status_code":  200,
#   "response":     { "summary": "..." },
#   "latency_ms":   142,
#   "receipt_hmac": "a3f7c2..."
# }
```

### Verifying a hop chain

```bash
# Verify the HMAC chain of receipts from a hop back to genesis
curl https://mesh.agentloop.net/api/v1/mesh/hops/{hop_id}/verify

# {
#   "valid":       true,
#   "chain_depth": 4,
#   "message":     "Chain intact from hop 4 to genesis"
# }
```

---

## Layer 3 — Agent Workers

### What they are

Agent Workers are **stateless, event-driven compute units** that run at the mesh edge — like Cloudflare Workers but for agent workloads. They execute a single task and return a result. No server required.

### Worker types

| Type | Trigger | Concrete example |
|---|---|---|
| **Request** | Incoming mesh request | Validate + transform input before forwarding to summarizer |
| **Response** | Outgoing mesh response | Redact PII from response before returning to caller |
| **Event** | Agent system event | Notify Slack when SLO breach detected |
| **Schedule** | Cron expression | Run nightly regression test suite at 02:00 UTC |
| **A2A** | A2A capability call | Expose a tool via MCP protocol without a full agent server |
| **Tunnel** | Incoming tunnel connection | Bridge private agent behind firewall into public mesh |

### Registering a worker

```bash
curl -X POST https://mesh.agentloop.net/api/v1/workers \
  -H "X-AgentLoop-Api-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "pii-redactor",
    "worker_type":   "response",
    "agent_id":      "uuid-of-summarizer-agent",
    "handler_url":   "https://workers.acme.internal/pii-redact",
    "trigger_config": { "path_pattern": "/api/v1/mesh/call" },
    "mcp_capabilities": [{ "name": "redact", "description": "Redact PII from text" }]
  }'
```

Workers auto-register in DNS as `agent://pii-redactor.workers.acme-corp` — callable by any other agent in the mesh immediately.

### Invoking a worker directly

```bash
curl -X POST https://mesh.agentloop.net/api/v1/workers/{id}/invoke \
  -d '{ "input": { "text": "Call patient John Doe at 555-1234" } }'

# { "invocation_id": "uuid", "status": "completed", "latency_ms": 38 }
```

---

## Layer 4 — Observability

Because every agent call routes through the mesh, observability is **zero-config** — no SDK required, no manual instrumentation, no code changes.

### Design — Prompt lifecycle

Register, version, lint, and approve every prompt your agents use.

```bash
# Create a prompt
curl -X POST https://mesh.agentloop.net/api/v1/prompts \
  -d '{ "name": "medical-summarizer-v2", "system_prompt": "You are a medical...", "author": "dr-smith" }'

# Approve a version for production
curl -X POST https://mesh.agentloop.net/api/v1/prompts/{id}/versions/{vid}/approve \
  -d '{ "approved": true, "reviewer": "dr-jones", "reason": "Validated on 50 patient cases" }'
```

**Outcome:** every prompt change is versioned, reviewed, and linked to the runs that used it. Rollback to any previous version in one API call.

### Ship — A/B experiments

Run traffic experiments between prompt versions, model configs, or agent versions.

```bash
curl -X POST https://mesh.agentloop.net/api/v1/experiments \
  -d '{
    "name":                   "gpt4o-vs-claude3",
    "variant_control_id":     "uuid-of-control-prompt",
    "variant_treatment_id":   "uuid-of-treatment-prompt",
    "traffic_split_pct":      20,
    "significance_threshold": 0.95,
    "auto_promote":           true
  }'
```

**Outcome:** statistically valid promotion decisions. Treatment auto-promotes when p-value crosses threshold. Canary traffic split is enforced at the DNS layer — no code changes to agents.

### Debug — Timeline + Replay

Every run is a replayable timeline.

```bash
# View a run's step-by-step timeline
curl https://mesh.agentloop.net/api/v1/agents/{id}/timeline?limit=20

# Diff two runs (find first divergence)
curl -X POST https://mesh.agentloop.net/api/v1/runs/diff \
  -d '{ "left_run_id": "uuid-A", "right_run_id": "uuid-B" }'

# Start a deterministic replay from a specific step
curl -X POST https://mesh.agentloop.net/api/v1/replays \
  -d '{ "source_run_id": "uuid", "substitutions": { "model": "gpt-4o" } }'
```

**Outcome:** root-cause broken runs in minutes, not hours. Replay with different inputs or models without re-running the entire pipeline.

### Optimize — Fleet intelligence

Set SLOs, detect drift, and receive actionable recommendations.

```bash
# Define an SLO
curl -X POST https://mesh.agentloop.net/api/v1/agents/{id}/slos \
  -d '{ "name": "p95-latency", "metric": "latency_ms_p95", "threshold": 2000, "window_hours": 24 }'

# Run drift detection
curl -X POST https://mesh.agentloop.net/api/v1/agents/{id}/drift/detect

# View fleet summary (all agents, health, cost, SLO status)
curl https://mesh.agentloop.net/api/v1/fleet
```

**Outcome:** know before customers do when an agent is degrading. Receive specific recommendations (model downgrade, prompt trim, endpoint migration) with projected cost savings.

---

## Agent Tunnel — Private Connectivity

For enterprises with private agents that cannot be publicly exposed:

```
Private cloud                    AgentLoop mesh
┌─────────────────┐              ┌────────────────────────────────┐
│  Agent-B        │◄─────────────│  Tunnel endpoint               │
│  (no public IP, │              │  agent://agent-b.private.acme  │
│   behind NAT,   │──────────────│  Persistent outbound conn      │
│   behind FW)    │              │                                │
└─────────────────┘              └────────────────────────────────┘
```

Agent-B establishes an outbound connection to AgentLoop. The mesh routes `agent://agent-b.private.acme` traffic inward — no firewall rule changes, no public IP, no VPN. Identical to `cloudflared` but for agent workloads.

```bash
# Register a tunnel
curl -X POST https://mesh.agentloop.net/api/v1/agents/{id}/tunnels \
  -d '{ "name": "prod-private", "private_addr": "http://localhost:8080", "public_fqan": "agent-b.private.acme" }'

# Returns a secret token; the agent establishes the outbound connection using this token
```

---

## ConnectorOS Integration

AgentLoop does not re-implement policy, receipts, CID chains, or billing. ConnectorOS provides all of these as the kernel. AgentLoop is the **network** on top of the **OS**:

| AgentLoop layer | ConnectorOS primitive used |
|---|---|
| DNS resolution | Agent registry + identity |
| Mesh routing | Policy engine + cage rules |
| Hop receipts | CID-chained history + HMAC receipts |
| Worker admission | Admission gate + content firewall |
| Tunnel auth | UCAN capability verification |
| Cost tracking | Billing + token metering |

Every decision AgentLoop makes is backed by ConnectorOS. There is no separate policy engine.

---

## Full API Reference

### Agent DNS

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/dns/register` | Register an agent endpoint in the mesh |
| `GET`  | `/api/v1/dns/resolve/:fqan` | Resolve FQAN → AgentCard + healthy endpoints |
| `GET`  | `/api/v1/dns/records` | List all DNS records (paginated) |
| `DELETE` | `/api/v1/dns/records/:fqan` | Deregister (soft-disable) a record |

### Agent Mesh

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/mesh/call` | Proxy a call through the mesh |
| `GET`  | `/api/v1/mesh/hops` | List hop log (paginated, filterable) |
| `GET`  | `/api/v1/mesh/hops/:id/verify` | Verify HMAC receipt chain |
| `GET`  | `/api/v1/mesh/circuit-breakers` | Current circuit breaker states |

### Agent Workers

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/workers` | Register a worker |
| `GET`  | `/api/v1/workers` | List workers |
| `GET`  | `/api/v1/workers/:id` | Get worker detail |
| `POST` | `/api/v1/workers/:id/invoke` | Invoke a worker directly |
| `GET`  | `/api/v1/workers/:id/mcp` | Get MCP capability manifest |
| `GET`  | `/api/v1/workers/:id/invocations` | Invocation history |

### Agents (core entity)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/agents` | Create an agent |
| `GET`  | `/api/v1/agents` | List agents |
| `GET`  | `/api/v1/agents/:id` | Get agent detail |
| `GET`  | `/api/v1/agents/:id/timeline` | Run timeline |
| `POST` | `/api/v1/agents/:id/sync` | Sync history from ConnectorOS |
| `GET`  | `/api/v1/agents/:id/slos` | List SLOs |
| `POST` | `/api/v1/agents/:id/slos` | Create SLO |
| `POST` | `/api/v1/agents/:id/slos/evaluate` | Evaluate all SLOs now |
| `GET`  | `/api/v1/agents/:id/drift` | List drift events |
| `POST` | `/api/v1/agents/:id/drift/detect` | Run drift detection |

### Debug

| Method | Path | Description |
|---|---|---|
| `GET`  | `/api/v1/runs/:id` | Run detail |
| `POST` | `/api/v1/runs/diff` | Diff two runs |
| `POST` | `/api/v1/replays` | Start a replay |
| `GET`  | `/api/v1/replays/:id` | Get replay status |

### Design

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/prompts` | Create prompt |
| `GET`  | `/api/v1/prompts` | List prompts |
| `GET`  | `/api/v1/prompts/:id` | Get prompt detail |
| `POST` | `/api/v1/prompts/:id/versions` | Add version |
| `POST` | `/api/v1/prompts/:id/versions/:vid/approve` | Approve/reject version |
| `POST` | `/api/v1/datasets` | Create golden dataset |

### Ship

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/experiments` | Create experiment |
| `GET`  | `/api/v1/experiments` | List experiments |
| `GET`  | `/api/v1/experiments/:id` | Get experiment |
| `POST` | `/api/v1/experiments/:id/start` | Start traffic split |
| `POST` | `/api/v1/experiments/:id/pause` | Pause |
| `POST` | `/api/v1/experiments/:id/promote` | Promote winner |
| `POST` | `/api/v1/experiments/:id/rollback` | Rollback |
| `POST` | `/api/v1/experiments/:id/metrics` | Refresh significance |

### Optimize

| Method | Path | Description |
|---|---|---|
| `GET`  | `/api/v1/fleet` | Fleet summary (all agents) |
| `GET`  | `/api/v1/recommendations` | List open recommendations |
| `POST` | `/api/v1/recommendations/:id/apply` | Apply a recommendation |
| `POST` | `/api/v1/recommendations/:id/dismiss` | Dismiss a recommendation |

### System

| Method | Path | Description |
|---|---|---|
| `GET`  | `/health` | Service health |
| `GET`  | `/readyz` | Readiness probe (checks DB) |
| `GET`  | `/metrics` | Prometheus metrics (port 9090) |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL connection string (required) |
| `CONNECTOR_URL` | — | ConnectorOS base URL (required) |
| `CONNECTOR_API_KEY` | — | ConnectorOS API key |
| `AGENTLOOP_API_KEY` | — | API key for this service (blank = disabled) |
| `AGENTLOOP_HMAC_KEY` | `agentloop-hmac-default` | Key for HMAC receipt chaining |
| `PORT` | `8084` | API server port |
| `METRICS_PORT` | `9090` | Prometheus metrics port |
| `CORS_ALLOW_ORIGIN` | `*` | CORS allowed origin |
| `BODY_LIMIT_MB` | `4` | Request body limit in MB |
| `REQUEST_TIMEOUT_SECS` | `60` | Per-request timeout |
| `DB_MAX_CONNECTIONS` | `20` | PgPool max connections |
| `DB_MIN_CONNECTIONS` | `2` | PgPool min connections |
| `DNS_HEALTH_SWEEP_SECS` | `15` | DNS health sweep interval |
| `MESH_CB_THRESHOLD` | `5` | Circuit breaker failure threshold per FQAN |
| `MESH_CB_COOLDOWN_MS` | `30000` | Circuit breaker cooldown in ms |

---

## Prometheus Metrics

| Metric | Type | Labels |
|---|---|---|
| `agentloop_requests_total` | Counter | `method`, `path`, `status` |
| `agentloop_request_duration_ms` | Histogram | `method`, `path`, `status` |
| `agentloop_errors_total` | Counter | `code`, `status` |
| `agentloop_auth_failures_total` | Counter | — |
| `agentloop_dns_registrations_total` | Counter | — |
| `agentloop_dns_cache_hits_total` | Counter | — |
| `agentloop_dns_cache_misses_total` | Counter | — |
| `agentloop_dns_cache_size` | Gauge | — |
| `agentloop_endpoint_health_updates_total` | Counter | `result` |
| `agentloop_mesh_calls_total` | Counter | `fqan` |
| `agentloop_mesh_call_duration_ms` | Histogram | `fqan`, `verdict` |
| `agentloop_mesh_circuit_open_total` | Counter | `fqan` |
| `agentloop_mesh_errors_total` | Counter | `fqan` |

---

## Pricing

Not seat-based. Infrastructure-based — like Cloudflare.

| Tier | Price | Included |
|---|---|---|
| **Free** | $0/mo | 3 agents · 10K mesh calls/mo · 1 worker · Debug read-only |
| **Starter** | $49/mo | 20 agents · 500K mesh calls/mo · 10 workers · full Debug |
| **Team** | $299/mo | Unlimited agents · 5M calls/mo · unlimited workers · Design + Ship |
| **Platform** | $999/mo | All modules · private mesh node · Tunnel · SLAs |
| **Enterprise** | Custom | On-prem mesh · custom DNS zone · SOC2 · dedicated support |

Usage-based overage: **$0.10 per 10K mesh calls** above plan limit.
