# Conductor — Current Status

## Build
- **Status:** ✅ Compiles cleanly (0 errors, 0 warnings)
- **LOC:** ~3,300 lines of Rust across 12 source files
- **Stubs:** Zero `todo!()`, `unimplemented!()`, `NOT_IMPLEMENTED`, or `FIXME` in codebase
- **SQL queries:** All dynamic `sqlx::query()` — no compile-time `DATABASE_URL` dependency
- **Cage + Proxy:** Added — OS-level sandbox policy enforcement and action call interception with HMAC receipt chain

## Modules

| File | Lines | Purpose |
|------|-------|--------|
| `runner.rs` | ~483 | Pipeline execution engine — start, poll, pause, resume, abort, replay, budget enforcement, schema validation |
| `types.rs` | ~361 | Pipeline, Run, Step, Approval, Schedule, Gate, all request/response types |
| `routes.rs` | ~424 | 25 HTTP route handlers with typed errors, pagination, input validation, cage CRUD |
| `connector.rs` | ~464 | ConnectorClient — retry, circuit breaker, request-ID, connection pooling |
| `cage.rs` | ~490 | Cage policy — OS-level sandbox evaluation, rlimit application, cgroup v2 writes, DB CRUD |
| `proxy.rs` | ~360 | Action proxy — cage evaluation, forward, SHA-256 body hashing, HMAC chain, intercept log |
| `pipeline.rs` | ~200 | YAML parse/validate, compile to Connector format, SHA-256 fingerprint, DB CRUD |
| `hitl.rs` | ~230 | Approval queue — create, resolve, expire stale, pause/resume run lifecycle |
| `gate.rs` | ~230 | Gate evaluation — regression_test, budget_variance, approval_count |
| `scheduler.rs` | ~156 | Cron tick loop (30s), webhook token generation, HITL expiry sweep |
| `main.rs` | ~206 | Server bootstrap — pool config, graceful shutdown, middleware stack, CORS |
| `error.rs` | ~125 | Typed `AppError` — 8 variants, correct HTTP codes, structured logging |
| `middleware.rs` | ~100 | request-id injection, API key auth, per-request structured tracing |

## API Endpoints (all implemented, zero stubs)

### Pipelines
- ✅ `POST /api/v1/pipelines` — Parse YAML, SHA-256 fingerprint, validate schema, register with Connector, store versioned
- ✅ `GET /api/v1/pipelines` — List active pipelines with `limit`/`offset` pagination
- ✅ `GET /api/v1/pipelines/:id` — Fetch single pipeline by UUID (404 if not found)
- ✅ `DELETE /api/v1/pipelines/:id` — Archive pipeline (soft delete, 404 guard)
- ✅ `POST /api/v1/pipelines/:id/run` — Start run with inputs, YAML re-parsed, submitted to Connector

### Runs
- ✅ `GET /api/v1/runs` — Filter by `pipeline_id` and/or `status`, paginated
- ✅ `GET /api/v1/runs/:id` — Live detail: run + all steps + pending HITL approvals
- ✅ `POST /api/v1/runs/:id/pause` — Pause a running run (404 guard)
- ✅ `POST /api/v1/runs/:id/resume` — Resume paused run, signal Connector (409 if not paused)
- ✅ `POST /api/v1/runs/:id/abort` — Abort run permanently (404 guard)
- ✅ `POST /api/v1/runs/:id/replay/:step` — Replay from step N with optional new inputs, new run linked to parent
- ✅ `GET /api/v1/runs/:id/receipt-chain` — CID-chained proof bundle (local + Connector dual-layer)
- ✅ `GET /api/v1/runs/:id/gate` — Evaluate all gate policies for promotion decision

### Approvals (HITL)
- ✅ `GET /api/v1/approvals` — List all pending approvals across all runs
- ✅ `POST /api/v1/approvals/:id` — Approve or reject (requires `reviewer`, 422 if blank; 409 if already resolved)

### Schedules
- ✅ `POST /api/v1/schedules` — Create cron or webhook schedule (422 on invalid `trigger_type` or missing `cron_expr`)
- ✅ `GET /api/v1/schedules` — List all schedules
- ✅ `DELETE /api/v1/schedules/:id` — Delete schedule (404 guard)
- ✅ `POST /api/v1/webhooks/trigger/:token` — Token-authenticated webhook trigger (404 on invalid/disabled token)

### Cage (Sandbox Policy)
- ✅ `POST /api/v1/cages` — Create or update cage policy for a pipeline; verifies pipeline exists (404 guard); upsert on conflict
- ✅ `GET /api/v1/cages/:pipeline_id` — Get cage policy (404 if none configured)
- ✅ `DELETE /api/v1/cages/:pipeline_id` — Remove cage policy (404 guard)

### Cage Proxy (Action Interception)
- ✅ `POST /api/v1/proxy/action` — Intercept, cage-evaluate, forward, HMAC-chain, record intercept
- ✅ `GET /api/v1/proxy/intercepts/:run_id` — Full intercept log for a run (ordered by time)
- ✅ `GET /api/v1/proxy/intercepts/:run_id/verify` — Verify HMAC chain; returns `chain_valid`, `total_intercepts`, `broken_at_index`

### Health
- ✅ `GET /health` — Real DB ping + Connector health check + circuit breaker status
- ✅ `GET /healthz` — Kubernetes liveness alias

## Connector Integration (all real HTTP calls)

| Connector API | Used By | Purpose |
|---------------|---------|---------|
| `POST /multiagent/pipeline` | runner.rs | Submit pipeline run for execution |
| `GET /pipeline/:id/steps` | runner.rs | Poll step completion during run |
| `POST /pipeline/:id/replay-from-step/:n` | runner.rs | Replay run from specific step |
| `GET /pipeline/:id/cid-chain` | routes.rs | Fetch Connector-side CID chain for receipt bundle |
| `POST /pipeline/definitions` | pipeline.rs | Register pipeline definition with Connector |
| `POST /multiagent/pipelines/:id/approve-step/:n` | hitl.rs | Signal Connector to continue approved step |
| `GET /pipeline/:id/gate` | gate.rs | Connector gate status |
| `POST /history/regression-detect` | gate.rs | Regression test gate evaluation |
| `GET /health` | routes.rs | Connector health check |

## Database Schema

**`001_initial.sql`** (6 tables) + **`002_cage_proxy.sql`** (2 tables) = 8 tables total:

| Table | Purpose |
|-------|---------|
| `conductor_pipelines` | Versioned pipeline definitions with YAML source, compiled JSON, SHA-256 fingerprint |
| `conductor_runs` | Run lifecycle, status, inputs/outputs, budget tracking (tokens + USD), replay lineage |
| `conductor_steps` | Per-step status, input/output JSON, schema validation result, cost, timing |
| `conductor_approvals` | HITL approval records — step, run, reviewer, decision, TTL, reason |
| `conductor_gates` | Gate policy definitions per pipeline — type, config, required flag |
| `conductor_schedules` | Cron and webhook trigger schedules with next_run_at tracking |
| `conductor_cages` | OS-level sandbox policy per pipeline — network, type, path, rlimit, syscall, enforcement mode |
| `conductor_proxy_intercepts` | Append-only intercept log — SHA-256 hashes of req/resp bodies, HMAC chain, verdict, latency |

Key indexes:
- `idx_conductor_steps_run_step` — UNIQUE on `(run_id, step_index)` for upsert support
- `idx_conductor_cages_pipeline` — UNIQUE on `pipeline_id` (one cage per pipeline)
- `idx_conductor_proxy_run` — on `run_id` for intercept log queries
- `idx_conductor_proxy_verdict` — on `cage_verdict` for deny-rate analytics
- `idx_conductor_proxy_time` — on `intercepted_at DESC` for ordered log retrieval
- Status indexes on runs, steps, and approvals for fast filter queries
- Timestamp indexes on runs and schedules for ordering and cron polling

## Enterprise Features

| Feature | Status |
|---------|-------|
| Retry with exponential backoff + jitter | ✅ 3 attempts, 100ms base, ±20% jitter |
| Circuit breaker (lock-free atomic state) | ✅ Opens at 5 failures, cooldown 30s |
| PgPool with acquire/idle/lifetime timeouts | ✅ Env-tunable via `DB_MAX_CONNECTIONS` etc. |
| Graceful shutdown (CTRL+C + SIGTERM) | ✅ `with_graceful_shutdown` on `axum::serve` |
| API key authentication middleware | ✅ `X-Conductor-API-Key` or `Authorization: Bearer` |
| X-Request-ID propagation | ✅ Injected on every request, echoed in response, forwarded to Connector |
| Structured JSON logging | ✅ `tracing-subscriber` with `.json()` layer |
| Response compression | ✅ gzip + brotli via `tower-http CompressionLayer` |
| Request body size limit | ✅ 4MB default, `BODY_LIMIT_MB` env override |
| CORS env-controlled | ✅ `CORS_ALLOW_ORIGIN` — permissive only if unset or `*` |
| Typed HTTP errors (not all-500) | ✅ 400/404/409/422/503/500 from `AppError` enum |
| Pagination on all list endpoints | ✅ `limit`/`offset` query params |
| Input validation before DB hits | ✅ Empty YAML, blank reviewer, invalid trigger type → 422 |
| Release binary hardening | ✅ `panic=abort`, `strip=true`, `lto=true`, `codegen-units=1` |
| **Cage sandbox policy** | ✅ Per-pipeline: network allowlist/blocklist, port control, action type allow/deny, path restrictions |
| **OS rlimits** | ✅ `setrlimit(2)` for `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_NPROC` (Linux) |
| **cgroup v2 limits** | ✅ `memory.max`, `cpu.max`, `pids.max` written to `/sys/fs/cgroup/conductor-<run>-stepN.scope` (Linux) |
| **Cage enforcement modes** | ✅ `enforce` (403 deny), `audit` (log+allow), `disabled` (passthrough) |
| **Action proxy** | ✅ Single `POST /api/v1/proxy/action` entry-point for all agent outbound calls |
| **Proxy forwarding** | ✅ Real HTTP forward; strips Conductor internal headers, preserves caller headers |
| **Body hashing only** | ✅ SHA-256 hashes of request+response bodies stored — raw content never persisted |
| **HMAC-SHA256 receipt chain** | ✅ Each intercept chained to previous via HMAC — tamper-evident, verifiable at any time |
| **Chain verification endpoint** | ✅ `GET /proxy/intercepts/:run_id/verify` returns `chain_valid`, `broken_at_index` |

## What's Not Done (Phase 2)

- [ ] WebSocket streaming for live run step events
- [ ] Redis pub/sub for multi-instance HITL notification
- [ ] Prometheus metrics endpoint (`/metrics`) — run counts, step latency, budget histograms, cage deny rates
- [ ] PDF/CSV run audit export
- [ ] JWT-based per-user RBAC (current auth is single shared API key)
- [ ] Kubernetes Helm chart
- [ ] Docker Compose deployment file
- [ ] OpenTelemetry span export to external collector
- [ ] seccomp BPF filter generation from `syscall_policy` label (currently stored, not yet applied as kernel filter)
- [ ] Network namespace isolation for subprocess agents (Linux `unshare(CLONE_NEWNET)`)
- [ ] Cage policy inheritance — default org-wide cage overridden per pipeline
- [ ] Proxy action replay — re-run a denied intercept after cage policy update

## How Conductor Fits in the Connector Stack

| Plugin | What It Governs |
|--------|----------------|
| TraceTramp | **Inbound** — LLM calls, reasoning decisions, prompt/response capture |
| WitnessCtl | **Outbound** — API calls made by AI agents, receipt chains, schema drift |
| **Conductor** | **Orchestration** — Multi-agent workflow sequencing, HITL gates, budget control, replay, scheduling |
| DevGuard | **Security** — Code change governance, vulnerability policy |

Together, TraceTramp + WitnessCtl + Conductor create an unbroken chain of custody:

```
User request
  → TraceTramp (LLM call captured + governed)
    → Conductor (multi-step workflow orchestrated + gated)
      → WitnessCtl (outbound API calls captured + proved)
        → Tamper-evident receipt chain across the entire system
```
