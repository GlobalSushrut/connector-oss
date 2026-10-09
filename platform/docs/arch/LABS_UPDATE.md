# Labs Update — Advanced Production LabDB for TraceTramp + WitnessCtl

> Goal: build a production-standard lab that continuously exercises TraceTramp and
> WitnessCtl with realistic autonomous-agent traffic, real OpenFang workflows, and
> a database-backed response/output generator. This should test product behavior,
> not just demo flows.

This update extends the existing lab docs:

- `platform/docs/arch/LAB_ENV.md` — base TraceTramp + WitnessCtl + aimock lab.
- `platform/docs/arch/LAB_ENV_OPENFANG.md` — OpenFang-driven autonomous agent lab.

The missing piece is an **Advanced LabDB**: a Postgres-backed scenario and output
generator that creates random but controlled agentic inputs, tool outputs,
PII/secrets, schema drift, policy violations, budget burn, and compliance evidence.

---

## Why We Need LabDB

Fixture-only labs are good for deterministic smoke tests, but production systems
fail under variety:

- Agents produce different output shapes over time.
- Tool calls include nested JSON, partial failures, retries, and stale context.
- PII and secrets appear in prompts, tool responses, model output, and memory.
- Multi-tenant traffic creates isolation, budget, and correlation pressure.
- Evidence systems need long-running session chains, not one-off captures.

LabDB gives us both:

- **Randomness** for production-like diversity.
- **Seeds** for reproducible failures.

Every generated interaction should be traceable by:

- `scenario_id`
- `run_id`
- `tenant_id`
- `agent_id`
- `trace_id`
- `request_id`
- `witness_session_id`

---

## Advanced Lab Architecture

```text
                           ┌────────────────────────────┐
                           │ Advanced LabDB (Postgres)  │
                           │ scenarios, seeds, outputs  │
                           └─────────────┬──────────────┘
                                         │
                                         ▼
┌──────────────┐     prompts/tools   ┌──────────────┐
│ lab-runner   │────────────────────►│ OpenFang     │
│ generator    │                     │ real Hands   │
└──────┬───────┘                     └──────┬───────┘
       │                                    │ OpenAI-compatible LLM calls
       │                                    ▼
       │                           ┌────────────────┐
       │                           │ TraceTramp     │
       │                           │ enforce/cost   │
       │                           └──────┬─────────┘
       │                                  │ allowed calls
       │                                  ▼
       │                           ┌────────────────┐
       │                           │ aimock/lab-llm │
       │                           │ DB-backed      │
       │                           └────────────────┘
       │
       │ async evidence/correlation
       ▼
┌────────────────┐
│ WitnessCtl     │
│ seal/verify    │
└────────────────┘
```

OpenFang remains the real autonomous agent source. LabDB controls the scenario
inputs and expected outputs. aimock, or a small `lab-llm` shim, reads from LabDB
to generate OpenAI-compatible responses.

---

## Components

### 1. LabDB

Postgres database used by the lab runner and response generator.

Responsibilities:

- Store scenario definitions and seeds.
- Generate random prompts, tool results, and agent memory events.
- Track expected TraceTramp decisions: `allow`, `block`, `redact`, `hold`.
- Track expected WitnessCtl evidence outcomes: PII hit, schema drift, receipt,
  seal, custody queue, compliance report.
- Persist every generated input/output for replay.

### 2. Lab Runner

Small service or CLI, likely Python first for speed.

Responsibilities:

- Create tenants and WitnessCtl sessions.
- Activate OpenFang Hands.
- Feed generated tasks into OpenFang.
- Trigger chaos windows.
- Seal sessions and verify evidence bundles.
- Produce a run summary with pass/fail conditions.

### 3. DB-backed Lab LLM

Two implementation options:

- **Option A: aimock adapter**: pre-generate fixtures from LabDB into aimock
  fixture files before each run.
- **Option B: `lab-llm` shim**: a tiny OpenAI-compatible HTTP server that reads
  LabDB rows at request time and returns generated responses.

Recommended: start with **Option A** for speed, then move to **Option B** when
we need runtime randomness and stateful multi-turn behavior.

### 4. OpenFang Workloads

Use real OpenFang Hands as the agent workload:

- Researcher Hand: long-running research, memory writes, citations, summaries.
- Coder Hand: code review over real source files, secrets, tool outputs.
- Monitor Hand: endpoint polling, anomaly detection, incident reports.
- Compliance Hand: reads prior outputs and prepares evidence narratives.

Every OpenFang LLM call routes through TraceTramp:

```text
OPENFANG_LLM_BASE_URL=http://tracetramp:9741/v1
OPENFANG_LLM_API_KEY=<TraceTramp tenant key>
```

WitnessCtl also proxies OpenFang's own API for a second evidence chain.

---

## LabDB Schema Draft

```sql
CREATE TABLE lab_runs (
    id              UUID PRIMARY KEY,
    seed            BIGINT NOT NULL,
    profile         TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE lab_scenarios (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    category        TEXT NOT NULL,
    weight          INT NOT NULL DEFAULT 1,
    config          JSONB NOT NULL,
    expected        JSONB NOT NULL
);

CREATE TABLE lab_agents (
    id              UUID PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES lab_runs(id),
    tenant_id       TEXT NOT NULL,
    openfang_hand   TEXT NOT NULL,
    trace_key       TEXT NOT NULL,
    witness_session UUID,
    config          JSONB NOT NULL
);

CREATE TABLE lab_events (
    id              UUID PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES lab_runs(id),
    scenario_id     UUID REFERENCES lab_scenarios(id),
    agent_id        UUID REFERENCES lab_agents(id),
    trace_id        TEXT,
    request_id      TEXT,
    event_type      TEXT NOT NULL,
    input_payload   JSONB NOT NULL,
    output_payload  JSONB,
    expected        JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lab_response_templates (
    id              UUID PRIMARY KEY,
    scenario_id     UUID NOT NULL REFERENCES lab_scenarios(id),
    model           TEXT NOT NULL DEFAULT 'gpt-4o',
    match_rules     JSONB NOT NULL,
    response_shape  JSONB NOT NULL,
    pii_profile     TEXT,
    secret_profile  TEXT,
    chaos_profile   TEXT,
    schema_version  INT NOT NULL DEFAULT 1
);
```

---

## Scenario Catalog

### P0 Product Scenarios

| Scenario | What LabDB Generates | Expected TraceTramp | Expected WitnessCtl |
|---|---|---|---|
| Clean multi-turn | 10-20 turn OpenFang research run | allow, cost tracked, trace persisted | receipt chain continuous |
| PII prompt injection | SSN, email, PHI, card, MRN | block or redact | PII rows + compliance evidence |
| Secret leak in output | JWT/HMAC/API-key-like strings from code review | redact output | redacted preview recorded |
| Budget exhaustion | high-token outputs under low budget tenant | 402, no 500 | capture shows denied/budget event |
| Provider chaos | 500, timeout, malformed JSON, stream disconnect | graceful error/fallback | event/capture preserved |
| Schema drift | response adds `reasoning`, `confidence_score`, nested tool metadata | allow or hold by policy | drift marked in captures/report |
| Multi-tenant isolation | same scenario across 3 tenants | no cross-tenant leakage | separate sessions/chains |
| Async handoff | TraceTramp emits handoff events | request not blocked by handoff | `by-trace` returns handoff + capture |
| Seal/verify | long session then seal | enforcement packet export works | `.witnessctl` bundle verifies |

### Production Stress Scenarios

| Scenario | Load Shape | Pass Condition |
|---|---|---|
| Sustained agent day | 4 OpenFang Hands, 2 hours | no memory leak, no chain gaps |
| Burst incident | 100 requests/min for 5 min | p95 acceptable, no raw 500s |
| Tenant swarm | 25 tenants, mixed scenarios | budgets and policies isolated |
| Evidence backlog | custody/webhook failures injected | retries + dead-letter visible |
| Long stream | slow streaming with mid-stream PII | TraceTramp detects/handles safely |

---

## Expected Output Artifacts

Each advanced lab run should write:

```text
lab-runs/<run_id>/
  summary.json
  tracetramp/
    enforcement-packets/
    decisions.jsonl
    costs.json
  witnessctl/
    sessions.json
    evidence-bundles/
    verification.json
    reports/
      soc2.pdf
      hipaa.pdf
      gdpr.pdf
  openfang/
    hand-runs.jsonl
    tool-calls.jsonl
  replay/
    labdb-seed.txt
    generated-fixtures/
```

`summary.json` should be machine-readable:

```json
{
  "run_id": "uuid",
  "seed": 1700000001,
  "profile": "production-standard",
  "passed": true,
  "trace_count": 430,
  "witness_capture_count": 430,
  "sealed_sessions": 8,
  "failed_expectations": [],
  "checks": {
    "no_raw_500_to_agent": true,
    "pii_redacted": true,
    "budget_hard_stop": true,
    "witness_chain_valid": true,
    "trace_witness_correlation": true
  }
}
```

---

## Compose Additions

Add services on top of the current premium lab compose:

```yaml
services:
  labdb:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: advanced_lab
    ports:
      - "16432:5432"
    volumes:
      - labdb-data:/var/lib/postgresql/data
      - ./advanced-lab/migrations:/docker-entrypoint-initdb.d:ro

  lab-runner:
    build:
      context: ./advanced-lab/runner
    environment:
      LABDB_URL: postgres://lab:lab@labdb:5432/advanced_lab
      TRACETRAMP_DATA_URL: http://tracetramp:9741
      TRACETRAMP_ADMIN_URL: http://tracetramp:9742
      WITNESSCTL_URL: http://witnessctl:7443
      OPENFANG_URL: http://openfang:4200
    depends_on:
      labdb:
        condition: service_started
      tracetramp:
        condition: service_healthy
      witnessctl:
        condition: service_healthy

  lab-llm:
    build:
      context: ./advanced-lab/lab-llm
    environment:
      LABDB_URL: postgres://lab:lab@labdb:5432/advanced_lab
    ports:
      - "19999:9999"
```

Then route TraceTramp provider config to:

```text
OPENAI_BASE_URL=http://lab-llm:9999/v1
```

For the first implementation, `lab-llm` can be replaced by aimock fixtures
generated from LabDB.

---

## Implementation Plan

### Phase 1 — Design + Seeded Generator

- Add `advanced-lab/migrations/001_labdb.sql`.
- Add `advanced-lab/runner/generate.py`.
- Generate deterministic prompt/output rows from a seed.
- Export aimock-compatible fixtures from LabDB.
- Run one OpenFang Hand through TraceTramp.

Acceptance:

- Same seed produces identical fixtures.
- Different seed produces different PII/secrets/schema variants.
- TraceTramp and WitnessCtl both record `trace_id`/`request_id`.

### Phase 2 — Full OpenFang Integration

- Add OpenFang Hand profiles for researcher, coder, monitor, compliance.
- Create TraceTramp tenants per Hand.
- Open WitnessCtl sessions per Hand.
- Correlate TraceTramp handoffs with WitnessCtl captures by trace.

Acceptance:

- `GET /api/v1/integrations/tracetramp/by-trace/:trace_id` returns both handoff
  and capture rows for generated events.
- At least one session seals and verifies successfully.

### Phase 3 — Production Profiles

Add profiles:

- `smoke`: 5 minutes, 1 tenant, 1 Hand.
- `demo`: 20 minutes, 3 tenants, researcher + coder + monitor.
- `prod-standard`: 2 hours, 25 tenants, chaos, custody/webhook retries.
- `soak`: 8 hours, long-running chains and budget rollover.

Acceptance:

- Lab runner emits `summary.json`.
- Exit code non-zero on failed product expectations.
- Reports and evidence bundles are written under `lab-runs/<run_id>/`.

### Phase 4 — CI Gate

- Run `smoke` profile in CI.
- Run `demo` profile nightly.
- Keep `prod-standard` as a manual release gate.

Acceptance:

- CI blocks if PII redaction, budget stop, evidence seal, chain verify, or
  TraceTramp/WitnessCtl correlation fails.

---

## Pass/Fail Contract

The advanced lab should fail the run if any of these happen:

- TraceTramp returns raw 500 to OpenFang for expected provider chaos.
- PII or secrets configured as `must_redact` reach OpenFang unredacted.
- Budget exhaustion returns anything other than 402 or configured policy result.
- WitnessCtl cannot seal a session after successful traffic.
- WitnessCtl verification reports broken chain or head mismatch.
- TraceTramp handoff exists but WitnessCtl cannot correlate it by trace ID.
- Tenant A traffic appears in Tenant B evidence or costs.
- Compliance reports omit evidence rows for captures that triggered findings.

---

## Directory Proposal

```text
advanced-lab/
  README.md
  docker-compose.override.yml
  migrations/
    001_labdb.sql
  runner/
    pyproject.toml
    lab_runner/
      __init__.py
      cli.py
      db.py
      generator.py
      openfang.py
      tracetramp.py
      witnessctl.py
      expectations.py
  lab-llm/
    pyproject.toml
    lab_llm/
      server.py
      openai_compat.py
      response_builder.py
  openfang/
    hands/
      researcher.toml
      coder.toml
      monitor.toml
      compliance.toml
  outputs/
    .gitkeep
```

This should live beside the product lab assets, not inside either plugin, because
it tests the combined product surface:

```text
plugins/tracetramp/          # product
plugins/witnessctl/          # product
advanced-lab/                # production-standard test lab
platform/docs/arch/          # architecture docs
```

---

## Immediate Next Step

**Implemented (repo root `advanced-lab/`):** LabDB + `lab-llm` OpenAI shim, Compose merge file, Docker smoke runner, TraceTramp gateway honors `x-trace-id` / `x-request-id` for correlation with WitnessCtl + handoffs. See `advanced-lab/README.md`.

Remaining from the original slice:

1. Seeded fixture exporter from LabDB → aimock (optional; `lab-llm` already reads DB).
2. OpenFang Hands + scheduled load (see `LAB_ENV_OPENFANG.md`).
3. Seal + verify step inside the runner (optional hard gate).
4. Long-running production profiles (`demo`, `prod-standard`, `soak`).
