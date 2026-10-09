# TraceTramp + WitnessCtl — Production (Connector OS)

Canonical engineering plan: [`platform/deploy/PRODUCTION_READINESS_PLAN.md`](../platform/deploy/PRODUCTION_READINESS_PLAN.md).

This runbook covers **what ships today** on a Connector node and how to verify it.

## Architecture

| Plugin | Role | Connector integration |
|--------|------|------------------------|
| **TraceTramp** | Runtime control — policy, budgets, HITL, trace ledger | Cage proxy `/plugin/tracetramp/…`, management proxy `/api/v1/plugins/tracetramp/…` |
| **WitnessCtl** | Evidence — capture, receipts, seal, compliance | Cage proxy, management `/api/v1/plugins/witnessctl/…`, handoff ingest |

TraceTramp posts enforcement events to WitnessCtl:

`POST {witness}/api/v1/integrations/tracetramp/handoff` with shared `TRACETRAMP_WITNESS_HANDOFF_SECRET` / `WITNESSCTL_TRACETRAMP_HANDOFF_SECRET`.

## Environment (operator)

| Variable | Purpose |
|----------|---------|
| `CONNECTOR_TRACETRAMP_MANAGEMENT_URL` | TraceTramp management plane (lab default host `19742`) |
| `CONNECTOR_TRACETRAMP_ADMIN_TOKEN` | Admin bearer (minted at first boot if unset) |
| `CONNECTOR_WITNESSCTL_MANAGEMENT_URL` | WitnessCtl management (lab default `17443`) |
| `CONNECTOR_WITNESSCTL_ADMIN_TOKEN` | WitnessCtl admin bearer |
| `TRACETRAMP_WITNESS_HANDOFF_BASE_URL` | TraceTramp → WitnessCtl base (set in lab compose) |
| `TRACETRAMP_WITNESS_HANDOFF_SECRET` | Must match WitnessCtl handoff secret |

TraceTramp **PostgreSQL-only** mode: omit `TRACETRAMP_REDIS_URL` or set `off`. Approvals use `approval_queue` in Postgres.

## Verify

```bash
# Lab + Connector (Docker)
make one-green-start-smoke

# With server on :9091 and management URLs for lab ports
CONNECTOR_PORT=19202 CONNECTOR_PLUGIN_LAB_AUTO_START=0 \
  CONNECTOR_TRACETRAMP_MANAGEMENT_URL=http://127.0.0.1:19742 \
  CONNECTOR_WITNESSCTL_MANAGEMENT_URL=http://127.0.0.1:17443 \
  make story-qa-smoke

# TT/WC production probes (management health, readiness, optional handoff)
make tt-wc-prod-smoke
make cage-tt-load-smoke   # concurrent cage-proof + cage health (plan Phase 2 lite)
```

## Phase 1 deliverables (plan ↔ code)

| Plan item | Status |
|-----------|--------|
| Redis optional | TraceTramp starts without Redis; doctor warns only |
| Web dashboard | `GET /admin/dashboard` on management plane |
| Witness handoff | TraceTramp `witness_tracetramp_handoff` + WitnessCtl route |
| Offline bundle verify | `witnessctl verify-bundle` (WitnessCtl CLI) |
| Connector Service Map green | `plugins/status` + `one-green-start-smoke` |

## Phase 2 deliverables (partial)

| Plan item | Status |
|-----------|--------|
| Cage SHA validation | `src/cage.rs` — hex-only addresses on `/cage/:sha/*` |
| Cage load probe | `make cage-tt-load-smoke` (bash); `make k6-cage-load` (k6 script) |
| Provider circuit breaker | `control.rs` / `view.rs` — open after consecutive failures |
| WitnessCtl dashboard | `GET /admin/dashboard` |

## Phase 1 evidence (WitnessCtl)

| Plan item | Status |
|-----------|--------|
| `.witness` bundle | Seal writes `{session}-{ts}.witness` + `.witnessctl` + `.witness.json` |
| Offline verify | `witnessctl-verify` binary; `witnessctl verify-bundle` accepts all three |
| Smoke | `make witness-bundle-smoke` |

Env: `WITNESSCTL_BUNDLE_DIR` (default `./witness-evidence`), `WITNESSCTL_HMAC_SECRET`.

## Phase 2 custody + tenancy

| Plan item | Status |
|-----------|--------|
| Custody node protocol | `POST /api/v1/custody/replicate` + `witnessctl-node` binary |
| Quorum verify | `custody_node::verify_quorum` + `witness_custody_proofs` table |
| TraceTramp tenancy | `src/tenancy.rs` + `make audit-tracetramp-tenancy` |

```bash
make custody-quorum-smoke
make audit-tracetramp-tenancy
make helm-lint-smoke
make tt-wc-prod-gate    # all TT/WC smokes + helm lint
```

## Phase 4 packaging (Helm)

| Chart | Path |
|-------|------|
| TraceTramp | [`platform/deploy/helm/tracetramp`](../platform/deploy/helm/tracetramp) — `redis.enabled: false` default |
| WitnessCtl | [`platform/deploy/helm/witnessctl`](../platform/deploy/helm/witnessctl) |
| Connector | [`platform/deploy/helm/connector`](../platform/deploy/helm/connector) |

See [`platform/deploy/helm/README.md`](../platform/deploy/helm/README.md).

Later phases (3-node geo replication at scale, signed tarballs per plugin, SOC2 pen test) remain in the plan; track in [`PRODUCTION_READINESS_CHECKLIST.md`](../PRODUCTION_READINESS_CHECKLIST.md).
