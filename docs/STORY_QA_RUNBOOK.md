# Story QA runbook (Jordan / Sam / Riley)

Automated acceptance: `make story-qa-smoke` (requires a running node).

## Prerequisites

```bash
make start
# or
CONNECTOR_PORT=19096 make one-green-start-smoke
export CONNECTOR_TEST_URL=http://127.0.0.1:9091
```

## A.2 Jordan — gateway + Service Map

| Step | Check |
|------|--------|
| Apps hub | `GET /api/v1/apps` returns `apps[]` |
| TraceTramp | `GET /api/v1/plugins/status` → `plugins.tracetramp.status_badge` = `healthy` when lab is up |
| Cage | `GET /api/v1/plugins/cage-proof` → `"ok":true` |
| Scoped keys | Dashboard **Settings → API keys** or `POST /api/v1/auth/api-keys` |

## A.3 Sam — WitnessCtl

| Step | Check |
|------|--------|
| Status | `GET /api/v1/plugins/witnessctl/status` |
| Lab | `CONNECTOR_WITNESSCTL_MANAGEMENT_URL` + Docker witnessctl service |

## A.4 Riley — workflows

| Step | Check |
|------|--------|
| Register | `POST /api/v1/workflows` with reference template `cls_source` |
| Enable | `POST …/lifecycle` COMPILED → STAGED → ENABLED |
| CNP | ENABLE response includes `cnp_dispatch.dispatch_token` (`cpk_wf_*`) |
| Dry-run | `POST …/dry-run` returns `dry_run.cnp_replay` with `cnp_bus_registration` when enabled |

## Sign-off template

```
Story QA — version ______ date ______
Jordan: PASS / FAIL  notes: ___
Sam:    PASS / FAIL  notes: ___
Riley:  PASS / FAIL  notes: ___
```
