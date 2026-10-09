# Conductor — Market Position & Capability Guide

> **Updated:** Cage + Proxy added — OS-level sandbox enforcement and action call interception.

## The Problem Nobody Has Solved

AI agents can talk. They can reason. But they can't **govern themselves across multi-step workflows**.

Today, when an enterprise deploys a multi-agent pipeline:

- There is no way to **pause a workflow** mid-execution for human sign-off before a high-risk step
- There is no way to **prove** which agent produced which output, in which order, with what cost
- There is no way to **replay a failed step** without re-running the entire pipeline from scratch
- There is no way to **enforce a gate** before promoting a pipeline version to production
- There is no policy-backed mechanism to **abort a run** that exceeds budget or violates schema contracts
- There is no **sandbox** preventing an agent from calling arbitrary hosts, file paths, or executing subprocesses outside the declared pipeline contract

Current tools don't solve this:

| Tool | What It Provides | What It Misses |
|------|-----------------|----------------|
| LangGraph | DAG-based agent orchestration | No persistence, no audit, no human approval gates |
| Prefect / Airflow | Workflow scheduling | Built for data pipelines, not AI agents |
| Temporal | Durable execution | No LLM/agent-native governance or HITL |
| LangSmith | Observability traces | Read-only, no control plane, no enforcement |
| Custom orchestration | Ad-hoc Celery/Redis loops | No governance, audit, or replay built-in |
| **All of the above** | — | **None can cage agents at the OS level, intercept and receipt every action call, or verify a tamper-evident chain of all outbound agent activity** |

None of these give you a **tamper-evident chain of custody** across an entire multi-agent run. None enforce human-in-the-loop at the workflow level. None produce receipts an auditor can verify. And none can **cage what an agent is allowed to do at the OS level** — which hosts it can call, which ports it can open, what paths it can read, how much memory and CPU it can consume.

This is the gap Conductor fills.

---

## What Conductor Does

Conductor is a **governed multi-agent orchestration engine** built on Connector. It runs as a production-grade Axum HTTP service backed by Postgres, with full Connector API integration for execution, governance, and audit.

### Pipeline Lifecycle

You define a pipeline as a YAML file — a named, versioned sequence of agent steps with input/output schemas, budgets, and HITL flags. Conductor:

1. **Parses and validates** the YAML against schema
2. **SHA-256 fingerprints** the compiled pipeline definition — identical pipelines get the same fingerprint; version drift is always detected
3. **Registers** the definition with the Connector multiagent kernel
4. **Versions** every mutation — you always know exactly what YAML produced which run

```yaml
name: triage-and-summarise
steps:
  - name: triage
    agent_id: triage-v2
    input_schema: { ... }
    output_schema: { ... }
    require_approval: true
  - name: summarise
    agent_id: summariser-v1
    budget_tokens: 4000
    budget_usd: 0.05
```

### Run Execution

When a run starts, Conductor:

- Creates a `conductor_runs` record with `pending` status
- Submits the pipeline to the Connector multiagent execution kernel
- Polls step-by-step completion at 2-second intervals
- Validates each step's output against its declared JSON schema
- Tracks per-step token and USD cost, accumulating against the run's budget envelope
- Pauses the run automatically when a step is flagged `require_approval: true`
- Transitions run status: `pending → running → paused | completed | failed | aborted`

### Human-in-the-Loop (HITL)

When a step requires approval, Conductor:

1. Creates a `conductor_approvals` record with `pending` status
2. Sets the run to `paused`
3. Exposes the approval via `GET /api/v1/approvals`
4. Waits — indefinitely, or until the configured TTL expires
5. On `POST /api/v1/approvals/:id` with `approved: true/false`:
   - **Approved** → resumes the run from the paused step, signals Connector to continue
   - **Rejected** → fails the run with the reviewer's reason recorded
6. Stale approvals (past TTL) are auto-expired by the background scheduler sweep

This is not a workaround — it is a first-class workflow control. No other orchestrator ties human approval to actual execution hold.

### Replay Without Re-Running

When a step fails:

```
POST /api/v1/runs/:id/replay/:step
{ "new_inputs": { ... } }
```

Conductor:
- Creates a **new run** linked to the original via `parent_run_id`
- Re-executes from the specified step index, with new or inherited inputs
- Records the replay lineage so you always know which run was retried from where

### Receipt Chain & Audit Proof

Every completed run can produce a **CID-chained receipt bundle**:

```
GET /api/v1/runs/:id/receipt-chain
```

For each step:
- SHA-256 hash the step output JSON
- Derive a content identifier (CID): `bafy<first 32 hex chars of hash>`
- Chain all step CIDs into a root CID covering the entire run

The result is a **tamper-evident chain of custody** — if any step output changes after the fact, the root CID no longer matches. This is the same integrity guarantee used in IPFS/content-addressed storage, without requiring a distributed network.

This bundle also includes the Connector-side CID chain (from `/pipeline/:run_id/cid-chain`), providing a **dual-layer receipt**: Conductor's local chain and Connector's kernel chain must agree.

### Gate Policies

Before promoting a pipeline version to production, Conductor evaluates **gate policies**:

| Gate Type | What It Checks |
|-----------|----------------|
| `regression_test` | Calls Connector's regression detection API — did this version regress vs. baseline? |
| `budget_variance` | Did actual cost deviate from expected by more than X%? Blocks promotion if over threshold |
| `approval_count` | Requires a minimum number of HITL approvals in recent runs before promotion is allowed |

```
GET /api/v1/runs/:id/gate
```

Returns `pass: true/false` with per-gate verdicts and reasons.

### Cage — OS-Level Sandbox

Every pipeline can have a **cage policy** — a declarative contract that defines the exact allowed envelope for every action API call made by agents during a run. The cage is enforced at three layers:

**Layer 1 — Network policy** (checked by the proxy on every call):
- `allow_network: false` — no outbound HTTP/gRPC whatsoever
- `allowed_hosts` — only these hosts may be called (supports `*.example.com` wildcards)
- `blocked_hosts` — always denied, even if in the allowlist
- `allowed_ports` — if set, only these ports are reachable

**Layer 2 — Action type policy**:
- `allowed_action_types` — allowlist of categories: `http`, `sql`, `file`, `subprocess`, `tool`
- `blocked_action_types` — explicit deny regardless of allowlist

**Layer 3 — OS resource limits** (applied if agents run as subprocesses):
- `max_cpu_ms` → `RLIMIT_CPU` via `setrlimit(2)`
- `max_memory_bytes` → `RLIMIT_AS` (virtual address space)
- `max_file_size_bytes` → `RLIMIT_FSIZE`
- `max_open_files` → `RLIMIT_NOFILE`
- `max_processes` → `RLIMIT_NPROC`
- `syscall_policy` label (`default` / `strict` / `permissive`) for seccomp integration
- cgroup v2 scopes (`memory.max`, `cpu.max`, `pids.max`) written to `/sys/fs/cgroup/conductor-<run>-step<N>.scope`

**Enforcement modes**:
- `enforce` — hard deny; request is blocked with 403, intercept recorded
- `audit` — policy violation is logged but the call is allowed through (migration/testing mode)
- `disabled` — cage off; all calls pass

```
POST /api/v1/cages
{
  "pipeline_id": "...",
  "allow_network": true,
  "allowed_hosts": ["api.openai.com", "*.internal.corp"],
  "blocked_hosts": ["169.254.169.254"],
  "allowed_ports": [443],
  "allowed_action_types": ["http", "tool"],
  "max_memory_bytes": 268435456,
  "max_cpu_ms": 30000,
  "syscall_policy": "strict",
  "enforcement": "enforce"
}
```

> The AWS metadata endpoint (`169.254.169.254`) is a common SSRF target. Blocking it by default in the cage prevents agents from exfiltrating IAM credentials.

### Cage Proxy — Action Interception

Agents route all outbound calls through the **cage proxy** instead of calling upstreams directly. This is the enforcement point:

```
Agent → POST /api/v1/proxy/action
        {
          "action_type": "http",
          "method": "POST",
          "url": "https://api.openai.com/v1/chat/completions",
          "headers": { "Authorization": "Bearer sk-..." },
          "body": "...",
          "run_id": "<uuid>",
          "step_index": 2,
          "agent_id": "summariser-v1"
        }
```

For every call the proxy:
1. Resolves `run_id → pipeline_id` to load the cage policy
2. Evaluates network, type, and path rules against the cage
3. **DENY** → returns 403 immediately; writes an intercept record
4. **ALLOW/AUDIT** → forwards the request to the upstream target
5. Computes SHA-256 hashes of the request and response bodies (never stores raw content)
6. Writes an **HMAC-SHA256 chained intercept record** — each intercept is chained to the previous one for this run, forming a tamper-evident proxy receipt chain
7. Returns the upstream response plus `{ verdict, intercept_id, receipt_hmac, latency_ms }`

The intercept chain can be verified at any time:
```
GET /api/v1/proxy/intercepts/:run_id/verify
→ { "chain_valid": true, "total_intercepts": 7, "broken_at_index": null }
```

### Cron + Webhook Scheduling

Conductor has a built-in trigger engine. Schedules are stored in Postgres, not in memory — they survive restarts.

- **Cron schedules**: standard cron expressions (`*/5 * * * *`), evaluated every 30 seconds by the background tick loop
- **Webhook schedules**: unique token-authenticated URLs (`/api/v1/webhooks/trigger/:token`) — external systems trigger runs by POST

```
POST /api/v1/schedules
{
  "pipeline_id": "...",
  "name": "nightly-batch",
  "trigger_type": "cron",
  "cron_expr": "0 2 * * *"
}
```

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                          Conductor (Axum)                              │
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌─────────────┐  │
│  │ pipeline │ │  runner  │ │   hitl   │ │  gate   │ │  scheduler  │  │
│  │  CRUD    │ │  poll    │ │ approval │ │ promote │ │ cron+webhook│  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ └──────┬──────┘  │
│       │             │             │             │             │         │
│  ┌────▼─────────────▼─────────────▼─────────────▼─────────────▼─────┐  │
│  │                         ConnectorClient                           │  │
│  │      retry(3)+jitter · circuit breaker · X-Request-ID            │  │
│  └──────────────────────────────────┬────────────────────────────────┘  │
│                                      │                                  │
│  ┌──────────────────────────────────▼─────────────────────────────┐   │
│  │                       Postgres (sqlx)                           │   │
│  │  pipelines · runs · steps · approvals · gates · schedules      │   │
│  │  cages · proxy_intercepts                                       │   │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    Cage Proxy  (/api/v1/proxy/action)           │   │
│  │                                                                  │   │
│  │  Agent call → load cage policy → evaluate rules                 │   │
│  │    ├─ DENY  → 403 + intercept record                            │   │
│  │    └─ ALLOW → forward to upstream → capture hash → HMAC chain  │   │
│  │                                                                  │   │
│  │  OS enforcement (subprocess mode):                              │   │
│  │    setrlimit(CPU/AS/FSIZE/NOFILE/NPROC)                        │   │
│  │    cgroup v2 memory.max · cpu.max · pids.max                   │   │
│  └────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
                                      │
                          ┌──────────▼──────────┐
                          │  Connector Kernel    │
                          │  multiagent/pipeline │
                          │  /tools/a2a          │
                          │  /pipeline/gate      │
                          │  /history/regression │
                          └──────────────────────┘
```

---

## Enterprise Readiness

| Capability | Implementation |
|------------|----------------|
| **Retry logic** | 3-attempt exponential backoff with ±20% jitter on all Connector calls |
| **Circuit breaker** | Opens after 5 consecutive failures, half-opens after 30s cooldown |
| **Connection pooling** | PgPool: 2–20 connections, acquire timeout 5s, max lifetime 30min |
| **Graceful shutdown** | CTRL+C and SIGTERM both drain in-flight requests cleanly |
| **API authentication** | `X-Conductor-API-Key` or `Authorization: Bearer` on all `/api/*` routes |
| **Request tracing** | `X-Request-ID` injected/echoed on every request; propagated to Connector |
| **Structured logging** | JSON log lines via `tracing` + `tracing-subscriber` with env-filter |
| **Compression** | gzip/brotli response compression via `tower-http` |
| **Body size limit** | 4MB default, env-tunable via `BODY_LIMIT_MB` |
| **CORS** | Env-controlled `CORS_ALLOW_ORIGIN`; restrictive by default |
| **Pagination** | `limit`/`offset` on all list endpoints (pipelines, runs, schedules, approvals) |
| **Input validation** | 422 on empty YAML, invalid cron, missing reviewer, invalid trigger type |
| **HTTP status codes** | 201 on create, 404 on not found, 409 on conflict, 422 on validation, 503 on circuit-open |
| **Release binary** | `panic = "abort"`, `strip = true`, `lto = true`, `codegen-units = 1` |
| **Cage sandbox** | Per-pipeline OS-level policy: network allowlist/blocklist, action type control, path restrictions |
| **OS rlimits** | `setrlimit(2)` for CPU, AS, FSIZE, NOFILE, NPROC applied per subprocess |
| **cgroup v2** | `memory.max`, `cpu.max`, `pids.max` written to `/sys/fs/cgroup/conductor-<run>-stepN.scope` |
| **Proxy interception** | Every agent action call is intercepted, cage-checked, forwarded, and receipted |
| **HMAC receipt chain** | Every proxy intercept is HMAC-SHA256 chained to the previous — tamper-evident |
| **Body hashing only** | Proxy never stores raw request/response bodies — SHA-256 hashes only |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | required | Postgres connection string |
| `CONNECTOR_URL` | `http://localhost:9091` | Connector kernel base URL |
| `CONNECTOR_API_KEY` | `conductor_key` | API key for Connector authentication |
| `CONNECTOR_TIMEOUT_SECS` | `30` | Per-request timeout for Connector calls |
| `CONNECTOR_MAX_RETRIES` | `3` | Maximum retry attempts on 5xx/network errors |
| `CONNECTOR_CIRCUIT_THRESHOLD` | `5` | Consecutive failures before circuit opens |
| `CONNECTOR_CIRCUIT_COOLDOWN_SECS` | `30` | Seconds before circuit half-opens |
| `PORT` | `8083` | HTTP listen port |
| `DB_MAX_CONNECTIONS` | `20` | Postgres pool max connections |
| `DB_MIN_CONNECTIONS` | `2` | Postgres pool min connections |
| `BODY_LIMIT_MB` | `4` | Maximum request body size in megabytes |
| `CORS_ALLOW_ORIGIN` | `*` (permissive) | Restrict to specific origin in production |
| `RUST_LOG` | `conductor=info` | Log level filter |
| `CONDUCTOR_HMAC_KEY` | (internal default) | HMAC-SHA256 key for proxy receipt chaining — **must be set in production** |

---

## API Surface (27 endpoints)

### Pipelines
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/pipelines` | Upload YAML, parse, fingerprint, register with Connector |
| `GET` | `/api/v1/pipelines` | List active pipelines with pagination |
| `GET` | `/api/v1/pipelines/:id` | Get pipeline by ID |
| `DELETE` | `/api/v1/pipelines/:id` | Archive pipeline (soft delete) |
| `POST` | `/api/v1/pipelines/:id/run` | Start a run with input JSON |

### Runs
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/runs` | List runs, filter by pipeline or status, paginated |
| `GET` | `/api/v1/runs/:id` | Live run detail: status + all steps + pending approvals |
| `POST` | `/api/v1/runs/:id/pause` | Pause a running run |
| `POST` | `/api/v1/runs/:id/resume` | Resume a paused run |
| `POST` | `/api/v1/runs/:id/abort` | Abort a run (terminal state) |
| `POST` | `/api/v1/runs/:id/replay/:step` | Replay from step N with optional new inputs |
| `GET` | `/api/v1/runs/:id/receipt-chain` | CID-chained tamper-evident proof bundle |
| `GET` | `/api/v1/runs/:id/gate` | Evaluate gate policies for run promotion |

### Approvals (HITL)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/approvals` | List all pending approvals across all runs |
| `POST` | `/api/v1/approvals/:id` | Approve or reject with reviewer name and reason |

### Schedules
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/schedules` | Create cron or webhook schedule |
| `GET` | `/api/v1/schedules` | List schedules |
| `DELETE` | `/api/v1/schedules/:id` | Delete schedule |
| `POST` | `/api/v1/webhooks/trigger/:token` | Webhook-triggered run (token-authenticated) |

### Cage (Sandbox Policy)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/cages` | Create or update cage policy for a pipeline |
| `GET` | `/api/v1/cages/:pipeline_id` | Get the cage policy for a pipeline |
| `DELETE` | `/api/v1/cages/:pipeline_id` | Remove cage policy |

### Cage Proxy (Action Interception)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/proxy/action` | Agent action call — cage-checked, forwarded, HMAC-receipted |
| `GET` | `/api/v1/proxy/intercepts/:run_id` | List all intercepted calls for a run |
| `GET` | `/api/v1/proxy/intercepts/:run_id/verify` | Verify HMAC chain integrity across all intercepts |

### Health
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | DB + Connector health check |
| `GET` | `/healthz` | Kubernetes liveness probe alias |

---

## Phase 2 Roadmap

### Cage & Proxy (next tier of OS enforcement)

- **seccomp BPF filter generation** — the `syscall_policy` label (`default` / `strict` / `permissive`) is stored today but not yet compiled into a kernel-level BPF filter. Phase 2 generates a `seccomp(2)` filter from the label and loads it into the subprocess before exec, preventing even root-escalated syscalls outside the allowed set. Strict mode allows only: `read`, `write`, `open`, `close`, `exit`, `futex`, `mmap`, `brk`.

- **Network namespace isolation** — subprocess agents can be spawned inside a dedicated Linux network namespace (`unshare(CLONE_NEWNET)`) with only a veth pair connected to the cage proxy. All outbound traffic is forced through the proxy regardless of what the agent code tries to call directly. This closes the bypass path where a compromised agent binary calls `connect(2)` directly instead of using the action API.

- **Cage policy inheritance** — define an org-wide default cage and override per-pipeline. Today each pipeline has its own isolated cage or no cage. Inheritance means: org default → pipeline override → step-level override. A strict org default can block all `subprocess` and `file` actions globally, with individual pipelines opting in to specific exceptions.

- **Proxy action replay** — after a call is denied by the cage, operators can update the cage policy and replay the denied intercept without re-running the entire pipeline. The replay re-evaluates the cage against the new policy, re-forwards if now allowed, and links the replay record to the original denied intercept for full audit lineage.

### Observability & Operations

- **Prometheus `/metrics` endpoint** — run counts, step latency histograms, budget consumption rates, cage deny rates by pipeline and action type, circuit breaker state gauge
- **WebSocket streaming** — live step completion events pushed to clients during a run (`GET /api/v1/runs/:id/stream`)
- **OpenTelemetry export** — span export to external collector; `X-Request-ID` becomes the trace root
- **PDF/CSV audit export** — regulator-ready run report including all steps, HITL decisions, gate verdicts, and proxy intercept summary

### Auth & Multi-tenancy

- **JWT per-user RBAC** — replace single shared API key with per-user JWTs; roles: `operator` (read), `engineer` (write), `admin` (delete + cage config)
- **Redis pub/sub** — multi-instance HITL notification so approval events fan out to all Conductor nodes without polling

### Deployment

- **Kubernetes Helm chart** — with PodDisruptionBudget, HPA, and liveness/readiness probes wired to `/healthz`
- **Docker Compose** — single-command local stack: Conductor + Postgres + Connector kernel
