# Conductor — Implementation Plan

> **LangGraph with enterprise guardrails that won't break in prod.**

**Governed multi-agent orchestration platform** — built on Connector.

---

## 1. The Problem (validated 2026 signal)

Multi-agent is in production — and it's breaking.

Validated signals:
- **Documented wall**: teams start on CrewAI for velocity → hit scale limits at 6–12 months → painful rewrite to LangGraph (*"Multiple teams report hitting this wall … requiring painful rewrites to LangGraph"* — Medium 2025 framework landscape review)
- **Protocol explosion**: MCP + ACP + A2A (Google, 50+ company backing) + ANP — every framework speaks a different dialect
- **Governance gap in every framework**: LangGraph has no built-in audit. CrewAI has no HITL. AutoGen has no policy engine. OpenAI Agents SDK has no deterministic replay. Anthropic Agent SDK has no budget enforcement.
- **Enterprise reality**: teams bolt on homegrown logging + approvals + budget caps around LangGraph/CrewAI. Every company rebuilds the same plumbing badly.
- **Gartner 2026**: 40% of enterprise applications will embed AI agents; most will be multi-agent.

Today's frustrations:
- Pipeline fails at step 4 of 7 — no way to resume from step 4
- Agent A calls Agent B with bad data — no type check, no schema validation
- A long-running pipeline exceeds budget — no automatic pause
- A compliance team asks "what did the pipeline do last Tuesday?" — logs are incomplete
- A multi-agent system misbehaves — no policy gate, no quarantine, no kill switch
- Engineering team wants to add HITL approval on sensitive steps — requires framework fork

**Frameworks solve composition. Conductor solves production.**

---

## 2. The Product

Conductor is a multi-agent orchestration platform designed from day one for enterprise production:

- **Declarative pipelines** — YAML/Python DSL defining agents, edges, conditions
- **Visual designer** — build pipelines in a graph UI, export as code
- **Built-in policy gates** — enforce at every edge without custom code
- **Native HITL approval** — mark any step as requiring human sign-off
- **Per-step budget** — hard caps with auto-pause or auto-downgrade
- **Per-step receipts** — every step CID-chained, cryptographically auditable
- **Type-safe edges** — JSON Schema contracts between agents, validated at runtime
- **Deterministic replay** — re-run any pipeline from any step
- **A2A channels** — built-in agent-to-agent messaging with ACL
- **Pre-deploy diff** — see what changes before shipping a new pipeline version
- **Gate policies** — promote/deny pipeline versions based on test gates
- **Self-healing** — auto-retry, auto-rollback, auto-quarantine on regression
- **Framework adapters** — import LangGraph / CrewAI / AutoGen pipelines
- **MCP/A2A compatible** — speaks standard protocols

---

## 3. Connector Capability Audit (~85% done)

Connector has the richest multi-agent primitives of any platform — mostly unsurfaced.

| Capability | Connector Endpoint | Status |
|---|---|---|
| Pipeline run | `POST /multiagent/pipeline` | ✅ |
| Pipeline trace | `GET /multiagent/trace/:pipe_name` | ✅ |
| Cross-agent map | `GET /multiagent/map` | ✅ |
| Grant access | `POST /multiagent/grant` | ✅ |
| Revoke access | `POST /multiagent/revoke` | ✅ |
| List ports | `GET /multiagent/ports` | ✅ |
| HITL approve step | `POST /multiagent/pipelines/:id/approve-step/:step` | ✅ |
| Mesh knowledge plane | `GET /multiagent/mesh/knowledge-plane` | ✅ |
| Pipeline steps | `GET /pipeline/:id/steps` | ✅ |
| Pipeline integrity | `GET /pipeline/:id/integrity` | ✅ |
| Pipeline CID chain | `GET /pipeline/:id/cid-chain` | ✅ |
| Pipeline gate | `GET /pipeline/:id/gate` | ✅ |
| Pre-deploy diff | `POST /pipeline/pre-deploy-diff` | ✅ |
| Pipeline definitions | `POST/GET /pipeline/definitions` | ✅ |
| Validate run | `GET /pipeline/definitions/:id/validate-run/:run` | ✅ |
| Pipeline artifacts | `POST/GET /pipeline/:id/artifacts` | ✅ |
| Replay from step | `POST /pipeline/:id/replay-from-step/:n` | ✅ |
| Gate policies | `POST/GET /pipeline/gate-policies` | ✅ |
| KECS auto-suspend sweep | `POST /pipeline/kecs-suspend-sweep` | ✅ |
| A2A open channel | `POST /tools/a2a/open` | ✅ |
| A2A send | `POST /tools/a2a/:id/send` | ✅ |
| Agent DIDs + cards | `/tools/agents/:pid/did`, `/card` | ✅ |
| Tool approval queue | `/tools/approvals/*` | ✅ |
| Scoped tool bindings | `/tools/bindings/scoped` | ✅ |
| Circuit breaker | `/tools/bridges/:id/circuit-breaker` | ✅ |
| Signal handlers | `/tools/signals/handlers` | ✅ |
| Agent economy / escrow | AAPI budgets + negotiation | ✅ |
| Self-heal candidates | `/insights/self-heal-candidates` | ✅ |
| Regression detect | `/history/regression-detect` | ✅ |

**What's new (~15%)**: declarative pipeline DSL, visual designer UI, framework adapters (LangGraph/CrewAI/AutoGen import), schedule/trigger engine, pipeline template library, SDK packages, real-time execution viewer.

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────┐
│            Conductor UI (browser + CLI)              │
│  Designer · Run Viewer · Templates · Gates ·         │
│  Approvals · Schedules · Versioning · Debugger       │
└──────────────────────────┬───────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────┐
│           Conductor API Service                      │
│  /pipelines · /runs · /approvals · /schedules ·      │
│  /templates · /import · /gates · /channels           │
└──────────────────────────┬───────────────────────────┘
                           │ HTTP only
┌──────────────────────────▼───────────────────────────┐
│               CONNECTOR (kernel)                     │
│  multiagent · pipeline · A2A · agents · tools ·      │
│  budgets · audit · CID chain · self-heal             │
└──────────────────────────────────────────────────────┘
```

### Pipeline model

```yaml
# pipeline.yaml
name: customer_onboarding
version: v3
agents:
  - id: intake
    role: classifier
    model: gpt-4o-mini
    budget: { per_run: 500_tokens }
  - id: enricher
    role: data_enrichment
    tools: [crm_lookup, linkedin_search]
    budget: { per_run: 2000_tokens }
  - id: drafter
    role: email_author
    model: claude-sonnet-4
    budget: { per_run: 3000_tokens }

edges:
  - from: intake
    to: enricher
    when: "result.category == 'qualified'"
    schema: { $ref: "schemas/qualified_lead.json" }
  - from: enricher
    to: drafter
    schema: { $ref: "schemas/enriched_lead.json" }
    hitl: { required_if: "result.tier == 'enterprise'", reviewers: [sales_lead] }

gates:
  - on_version_promote:
      require: [regression_test_pass, budget_within_10pct, gate_policy_default]

budget:
  total_per_run: 10_000_tokens
  total_per_day: 5_000_000_tokens
  on_exceed: pause_and_notify
```

Compiled into Connector pipeline definitions + gate policies + multiagent grants.

---

## 5. Core Features

### 5.1 Pipeline Designer
- Drag-and-drop graph builder (React Flow)
- Node types: agent, tool, condition, HITL gate, A2A channel, subpipeline
- Inline schema editor for edges
- Budget + policy editor per node
- Live validation as you draw
- Export as YAML or Python DSL

### 5.2 Declarative DSL (YAML + Python)
- Version controlled
- Diff-friendly
- Reviewable in PRs
- Compiled to Connector pipeline definitions

### 5.3 Real-time Run Viewer
- Live graph execution with nodes turning green/yellow/red
- Step detail panel: inputs, outputs, tool calls, cost, latency
- Pause, resume, abort, replay-from-here
- Step breakpoints
- Variable inspection at each edge

### 5.4 HITL Approval (native)
- Mark any edge with `hitl: { reviewers: [...] }`
- Runtime pauses execution, notifies reviewers (Slack, email, UI)
- Reviewer approves/rejects with reason
- Fully audited, cryptographically signed

### 5.5 Per-step Budget
- Token / cost / latency budgets at node or edge level
- Enforcement: pause / downgrade / deny / alert
- Budget rollup: pipeline-level → org-level
- Integrates with LedgerLens for attribution

### 5.6 Schema-validated Edges
- Every edge declares JSON Schema for its payload
- Runtime validates incoming data, rejects malformed
- Catches agent hallucinations at the type boundary
- Generates TypeScript/Python types from schemas

### 5.7 Deterministic Replay
- Any pipeline run can be replayed from any step
- Uses Connector's CID-chained artifacts
- Substitute inputs, models, prompts for "what-if" replay
- Regression test harness built on replay

### 5.8 Gate Policies (CI/CD for pipelines)
- Pipeline versions promoted only if gate checks pass
- Gate types: regression test, budget variance, approval count, compliance scan
- Rollback on gate failure
- Git-integrated: PR triggers gate evaluation

### 5.9 Schedules + Triggers
- Cron schedules
- Webhook triggers
- Event triggers (from Connector signals)
- Agent-initiated triggers (A2A)
- Conditional triggers

### 5.10 Framework Adapters
Import existing work — no rewrite:
- `conductor import langgraph <file.py>` — imports state graph as pipeline
- `conductor import crewai <file.py>` — imports crew as pipeline
- `conductor import autogen <file.py>` — imports group chat as pipeline
- `conductor import openai-sdk <file.py>` — imports agents SDK
- Imported pipelines gain: policy gates, HITL, budget, receipts, replay — without code changes

### 5.11 Template Library
- Curated templates for common patterns:
  - Classifier → enricher → drafter
  - Retrieval → synthesis → critique
  - Plan → execute → verify
  - Research → report → review
  - Support triage → resolver → escalator
- Each template ships with: default policies, budgets, schemas, HITL points
- One-click instantiation

### 5.12 A2A Channels (native)
- Agents communicate over governed channels
- ACL: who can open, send, receive
- Rate limits, message schemas, audit per channel
- Works cross-tenant (with AgentPassport verification)

### 5.13 Self-Healing
- Auto-retry with backoff
- Auto-rollback on regression detection
- Auto-quarantine misbehaving agents
- Auto-route around failing tools (circuit breaker)
- All actions audited and reversible

### 5.14 MCP + A2A Protocol Support
- Pipelines can consume any MCP server as a tool node
- Pipelines can expose themselves as MCP servers
- Full A2A protocol compatibility for cross-platform orchestration
- AgentPassport integration for verifying external agents

### 5.15 SDK
- Python SDK: `conductor-py`
- TypeScript SDK: `conductor-ts`
- Go SDK: `conductor-go`
- Embed pipelines in applications with one import

---

## 6. New Endpoints (thin product layer)

| Endpoint | Purpose | Connector calls behind |
|---|---|---|
| `POST /pipelines` | Create/update pipeline | `/pipeline/definitions` |
| `GET /pipelines` | List + version history | `/pipeline/definitions` |
| `POST /pipelines/:id/run` | Execute | `/multiagent/pipeline` |
| `GET /runs/:id` | Run detail w/ live updates | `/pipeline/:id/steps` + `trace` |
| `POST /runs/:id/pause` | Pause run | `/pipeline/kecs-suspend-sweep` scoped |
| `POST /runs/:id/resume` | Resume from step | `/pipeline/:id/replay-from-step` |
| `POST /runs/:id/abort` | Abort run | agent kill + cleanup |
| `POST /import/:framework` | Import LG/CrewAI/AutoGen | new (parser) |
| `GET /templates` | Template library | new (Postgres) |
| `POST /schedules` | Cron/event schedules | new + Connector signals |
| `POST /channels/:id` | Open A2A channel | `/tools/a2a/open` |
| `POST /gates/evaluate/:run_id` | Run gate checks | `/pipeline/gate-policies` |
| `POST /validate` | Validate pipeline YAML | schema check + Connector validation |

---

## 7. Build Order

### Phase 1 — Declarative core + Run viewer (week 1-4)
- YAML DSL + compiler to Connector pipelines
- Python SDK
- CLI (`conductor run / pause / resume / replay`)
- Real-time run viewer UI
- Step detail panel
- Basic HITL approval flow

**Ships: usable orchestrator. Pilot with teams rebuilding off LangGraph.**

### Phase 2 — Designer + Templates (week 5-8)
- Visual designer (React Flow based)
- Schema editor
- Template library (5 starter patterns)
- Export as YAML
- Schedule + webhook triggers

**Ships: no-code option. Team tier launches.**

### Phase 3 — Framework import + Gates (week 9-12)
- LangGraph adapter
- CrewAI adapter
- AutoGen adapter
- Gate policies + promote/rollback
- Pre-deploy diff UI
- Regression test harness

**Ships: land-and-migrate play. Enterprise conversations start.**

### Phase 4 — A2A + MCP + Self-heal (week 13-16)
- Native A2A channel management UI
- MCP server exposure for pipelines
- AgentPassport integration (verify external agents)
- Self-heal configuration UI
- Auto-rollback triggers
- TypeScript + Go SDKs

**Total: 16 weeks / 2 engineers.**

---

## 8. Competitive Position

| Feature | Conductor | LangGraph | CrewAI | AutoGen | OpenAI Agents SDK | Anthropic Agent SDK |
|---|---|---|---|---|---|---|
| Declarative DSL | ✅ | partial | ✅ | ○ | ○ | ○ |
| Visual designer | ✅ | partial (Studio) | ○ | ○ | ○ | ○ |
| **Built-in audit** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Per-step receipts (CID-chained)** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Native HITL approval** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Per-step budget enforcement** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Policy gates at every edge** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Schema-validated edges** | ✅ | partial | partial | ○ | ○ | ○ |
| **Deterministic replay from any step** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Pre-deploy diff + gates** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Self-heal / auto-rollback** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Framework import** | ✅ | N/A | ○ | ○ | ○ | ○ |
| MCP / A2A protocol support | ✅ | partial | partial | partial | ✅ | ✅ |
| Visual run monitoring | ✅ | partial | ○ | ○ | ○ | ○ |
| **Self-hosted + on-prem** | ✅ | partial | partial | ✅ | ○ | ○ |

**Positioning vs each**:
- **LangGraph**: They give you control primitives. We give you production. Import your LangGraph, keep writing code, gain audit/HITL/budget/replay for free.
- **CrewAI**: They're the fast-prototype framework. We're the fast-prototype that also ships to production.
- **AutoGen**: Research-grade. We're enterprise-grade.
- **OpenAI/Anthropic Agent SDKs**: Vendor-locked. We're provider-neutral + on-prem capable.

**Moat**: Connector kernel. Competitors would need to rebuild pipeline CID chains, per-step receipts, policy binding, A2A governance, and self-heal to match. That's 2+ years of platform work.

---

## 9. Pricing

| Tier | Price | Includes |
|---|---|---|
| Free | $0 | 3 pipelines, 100 runs/mo, DSL + CLI, basic viewer |
| Pro | $99/mo | 25 pipelines, 10K runs/mo, designer, HITL, templates |
| Team | $499/mo | Unlimited pipelines, gate policies, framework import, schedules, SDKs |
| Enterprise | Custom (typ. $2k-$15k/mo) | On-prem, SSO, A2A federation, self-heal UI, SLA |

**Expansion**: land via free tier (developers experimenting) → Pro (team using HITL + templates) → Team (pipelines going to prod with gates + framework imports) → Enterprise (multi-tenant, regulated).

---

## 10. Go-To-Market

### Buyer
- **Primary**: Platform Engineering Lead / Director of AI Engineering
- **Secondary**: CTO / VP Engineering (concerned with production reliability)
- **Champion**: Senior engineer about to rewrite CrewAI → LangGraph

### Wedge
**"Import your LangGraph. Keep your code. Gain production."**

Demo script:
1. Customer uploads their existing LangGraph file
2. `conductor import langgraph pipeline.py`
3. Same pipeline now runs with: per-step receipts, HITL gates, budget caps, replay, audit
4. Show them a failing run replayed deterministically from step 4
5. Show Slack notification for an HITL approval on a high-risk step
6. Contract in 4 weeks

### Channel
- Engineering-led: GitHub presence, HN launch, dev.to + Medium articles
- Open-source the SDK + DSL parser (adoption driver)
- Integration partnerships:
  - LangGraph / LangChain (co-exist, import)
  - CrewAI (import + co-market)
  - Anthropic / OpenAI (agent SDK interop)
- Conference talks: AI Engineer Summit, RAGathon, MLOps conferences
- Cloud marketplace listings

---

## 11. Positioning

> **Conductor is multi-agent orchestration built for production. Declarative pipelines, visual designer, per-step receipts, native HITL, budget enforcement, deterministic replay, and framework imports — all on a kernel designed for governance from day one.**

> **Orchestrate anything. Govern everything.**

---

---

## 13. Production Implementation Plan (Current Sprint)

### What Conductor IS (concrete, not abstract)

An Axum HTTP server — same shape as WitnessCtl and TraceTramp — that:
1. Accepts pipeline YAML from users, stores + validates + compiles it
2. Executes pipelines by calling Connector's multiagent/pipeline APIs
3. Tracks step state, budget, and receipts in Postgres
4. Pauses runs for HITL approval and resumes on sign-off
5. Fires cron/webhook/event triggers
6. Evaluates gate policies before version promotion

**It is NOT a framework.** It is a production control plane that sits on top of Connector.

### End-to-End Workflow (the product story)

```
User writes pipeline.yaml
    │
    ▼
POST /api/v1/pipelines
    → Parse + validate YAML
    → Compile to Connector pipeline definition
    → Store in DB (conductor_pipelines)
    → Register agents in Connector
    │
    ▼
POST /api/v1/pipelines/:id/run  { inputs: {...} }
    → Create run record (conductor_runs)
    → Call Connector POST /multiagent/pipeline
    → Poll Connector GET /pipeline/:id/steps every 2s
    → For each step completion:
        → Store in conductor_steps
        → Check budget → pause if exceeded
        → Check HITL flag → pause for approval if required
        → Validate output schema → reject if malformed
    │
    ├── HITL gate hit
    │     POST /api/v1/runs/:id/approve-step/:step { approved: true, reason }
    │     → Store approval in conductor_approvals
    │     → Call Connector POST /multiagent/pipelines/:id/approve-step/:step
    │     → Run continues
    │
    ├── Budget exceeded
    │     → Auto-pause, notify via webhook
    │     → User calls POST /api/v1/runs/:id/resume or abort
    │
    └── Run completes
          → CID-chained receipt from Connector
          → Store final state, cost totals
          → Gate policy evaluation if version pinned
          GET /api/v1/runs/:id/receipt-chain → proof bundle

Deterministic replay:
    POST /api/v1/runs/:id/replay/:step_number { new_inputs? }
    → Calls Connector POST /pipeline/:id/replay-from-step/:n
    → New run record linked to parent

Schedule trigger:
    POST /api/v1/schedules { pipeline_id, cron: "0 9 * * MON" }
    → Scheduler loop fires POST /api/v1/pipelines/:id/run at cron time
```

### Modules (build order)

| # | File | Purpose |
|---|------|---------|
| 1 | `Cargo.toml` | cron + serde_yaml added |
| 2 | `migrations/` | 6 DB tables |
| 3 | `types.rs` | Pipeline, Step, Run, Approval, Schedule, Gate, Budget |
| 4 | `connector.rs` | ConnectorClient for all multiagent/pipeline/A2A APIs |
| 5 | `pipeline.rs` | YAML parse, validate, compile to Connector definition, version |
| 6 | `runner.rs` | Execute pipeline, poll steps, budget check, schema check |
| 7 | `hitl.rs` | Approval queue — pause step, notify, approve/reject, resume |
| 8 | `gate.rs` | Gate policy evaluation (regression, budget variance, approval count) |
| 9 | `scheduler.rs` | Cron + webhook trigger loop |
| 10 | `routes.rs` | Full API surface |
| 11 | `main.rs` | Server bootstrap |

### DB Schema

```sql
conductor_pipelines   — id, name, version, yaml, compiled_json, status, fingerprint, created_at
conductor_runs        — id, pipeline_id, connector_run_id, status, inputs, budget_used_tokens, started_at, ended_at
conductor_steps       — id, run_id, step_name, agent_id, status, input_json, output_json, cost_tokens, started_at, ended_at
conductor_approvals   — id, run_id, step_id, required_if, reviewers, status, reviewer, reason, requested_at, resolved_at
conductor_schedules   — id, pipeline_id, cron_expr, trigger_type, webhook_url, last_run, next_run, enabled, created_at
conductor_gates       — id, pipeline_id, gate_type, config_json, required, created_at
```

### API Surface (15 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/pipelines` | Create/update pipeline (YAML body) |
| GET | `/api/v1/pipelines` | List pipelines with version history |
| GET | `/api/v1/pipelines/:id` | Get pipeline + effective config |
| DELETE | `/api/v1/pipelines/:id` | Archive pipeline |
| POST | `/api/v1/pipelines/:id/run` | Start a run with inputs |
| GET | `/api/v1/runs` | List runs (filterable by pipeline, status) |
| GET | `/api/v1/runs/:id` | Live run detail — steps, budget, status |
| POST | `/api/v1/runs/:id/pause` | Pause in-progress run |
| POST | `/api/v1/runs/:id/resume` | Resume paused run |
| POST | `/api/v1/runs/:id/abort` | Abort run |
| POST | `/api/v1/runs/:id/replay/:step` | Replay from step N |
| GET | `/api/v1/runs/:id/receipt-chain` | CID-chained proof bundle |
| GET | `/api/v1/approvals` | List pending approvals |
| POST | `/api/v1/approvals/:id` | Approve or reject |
| POST | `/api/v1/schedules` | Create cron/webhook schedule |
| GET | `/api/v1/schedules` | List schedules |
| DELETE | `/api/v1/schedules/:id` | Delete schedule |
| GET | `/health` | DB + Connector health check |

### Final Outcome (what ships)

A **production-grade binary** (`conductor`) that:
- Runs any YAML-defined multi-agent pipeline
- Provides HITL approval gates on any step
- Enforces per-step token/cost budgets
- Validates schema contracts between agents
- Gives deterministic replay from any failed step
- Produces CID-chained cryptographic proof of every run
- Fires cron + webhook scheduled runs
- Evaluates gate policies before version promotion
- Is 0 stubs, 0 placeholders, builds with 0 errors

**Who buys it:** Platform Engineering Lead / Director of AI Engineering who has a working LangGraph/CrewAI prototype that keeps breaking in prod and needs: audit, HITL, budget enforcement, and replay.

**Wedge pitch:** "Import your existing pipeline. Same code. Gain: HITL approval on sensitive steps, per-step budget caps, deterministic replay when it fails at step 4, and a signed cryptographic receipt chain for compliance."

## 12. Strategic Value in Connector Portfolio

Conductor is the **orchestration layer** that amplifies every other Connector product:

- **DevGuard** — coding agents can orchestrate tasks via Conductor with governance intact
- **TraceTramp** — Conductor runs flow through TraceTramp for full runtime enforcement
- **AgentLoop** — Conductor pipelines are versioned, tested, replayed, optimized via AgentLoop
- **LedgerLens** — per-step costs in Conductor attribute directly into LedgerLens dimensions
- **AgentPassport** — Conductor verifies external agents in A2A edges via AgentPassport

Full portfolio becomes:

```
Connector (kernel)
├── Identity:     AgentPassport
├── Code layer:   DevGuard
├── Runtime:      TraceTramp
├── Orchestration: Conductor
├── Lifecycle:    AgentLoop
└── Cost:         LedgerLens
```

Six products. Zero overlap. Six distinct buyer personas. One kernel. Platform network effect compounds with each new module shipped.
