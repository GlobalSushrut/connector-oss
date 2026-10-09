# TraceTramp — Implementation Plan

> **See everything. Control what matters. Prove what happened.**

Proxy-native tracer + execution controller built on Connector.

---

## 0. Stack Model

```
Customer Product:  TraceTramp   (sellable surface)
Runtime Kernel:    Connector    (hidden engine)
```

TraceTramp NEVER duplicates Connector. It wraps, surfaces, and extends.

---

## 1. Connector Capability Audit — What's Already Built

| Domain | Done | Key Assets in Connector |
|---|---|---|
| LLM Gateway/Proxy | 90% | OpenAI + Anthropic endpoints, streaming, multi-provider routing, fallback |
| Auth + RBAC | 80% | JWT, API keys, SSO/OIDC (Okta/Google/Azure/GitHub), roles, 2FA |
| Admission Gate | 85% | Deny-by-default, quarantine, injection detection, content firewall |
| Budget + Billing | 95% | Per-token metering, tier limits, Stripe, overage, agent cost tracking |
| Audit + Provenance | 70% | Action log, audit trail, CID chains, dispute log, defense packages, GDPR Art.22 |
| UCAN + Policy | 85% | Capabilities, dynamic policies, HIPAA/Financial templates, compliance |
| Agent Lifecycle | 95% | Register/start/stop/pause/quarantine, clearance, trust, HITL approval |
| MCP + Tools | 90% | Register/invoke, approval queue, scoped bindings, circuit breaker |
| Memory Kernel | 90% | Sessions, packets, knowledge graph, RAG, cross-agent search |
| DevGuard | 80% | File/exec/git/secret policy, risk scoring, OS-level cage |
| Monitoring | 85% | Cost dashboard, anomaly detection, SLOs, capacity forecast, Grafana export |
| Dashboard UI | 60% | Leptos-based, needs TraceTramp-specific screens |

**~75% of TraceTramp's runtime already exists.** Build scope is product surfaces.

---

## 2. What's NEW — Real Build Scope

### A. Data Plane (~20% new)
- **trace_id propagation** — carry through full lifecycle
- **RuntimeExecutionRequest** canonical schema (normalize all formats)
- **Tenant Resolver** — multi-tenant context per request
- **New endpoints**: `/v1/responses`, `/v1/workflows/submit`, `/v1/tools/invoke`, `/v1/agents/run`

### B. Evidence Plane (~60% new — killer differentiator)
- **Trace recorder** — structured timeline from runtime events
- **Explain builder** — human-readable reasoning for every decision
- **Prove builder** — integrity chain from receipts + CID hashes
- **Cost collector** — per-request/session/workflow/tenant surfaces
- **Statement builder** — workflow-level summary document
- **Evidence API**: `/trace/<id>`, `/explain/<id>`, `/prove/<id>`, `/cost/<id>`, `/workflow/<id>/statement`

### C. Management Plane (~40% new)
- **Multi-tenant isolation** — tenant CRUD, per-tenant keys/policy
- **Provider config UI** — self-service LLM setup
- **Logging destinations** — S3, ELK, Splunk, webhook, SIEM
- **Compliance export** — SOC 2 / HIPAA / GDPR evidence packs
- **Dashboard screens** — timeline, detail, approvals, cost, compliance

### D. Control Pipeline (~30% new)
- **Policy Controller** — customer YAML → Connector rules
- **Risk Controller** — PHI/PII, side-effects, anomaly scoring
- **Routing Controller** — model/provider by policy + budget + risk
- **Approval Controller** — queue, notify, pause/resume, webhook
- **Output Guard** — leakage/hallucination/compliance before release
- **Action Guard** — side-effect governance (email, CRM, API)

### E. CLI
- `tracetramp status/trace/explain/prove/cost/workflow`
- `tracetramp approvals list/approve/reject`
- `tracetramp tenant show` / `tracetramp doctor`

---

## 3. Three-Plane Architecture

```
  MANAGEMENT PLANE (:9092)
  ┌─────────────────────────────────────────────────┐
  │ Tenants · Providers · RBAC · Budgets · Policies │
  │ Logging · Approvals · Compliance · Dashboard    │
  └──────────────────────┬──────────────────────────┘
                         │ config
  DATA PLANE (:9091)     ▼
  ┌─────────────────────────────────────────────────┐
  │ Gateway → Resolver → Normalizer                 │
  │    ↓                                            │
  │ [View Pipeline]        [Control Pipeline]       │
  │  trace/explain/prove    policy/risk/routing     │
  │  cost/statement         tool/memory/output/     │
  │                         action guards/approval  │
  │    ↓                                            │
  │ Connector Bridge Layer                          │
  └──────────────────────┬──────────────────────────┘
                         │
  CONNECTOR RUNTIME      ▼
  ┌─────────────────────────────────────────────────┐
  │ Enforcement · Receipts · Audit · Memory · Tools │
  │ Budget · Policy execution · UCAN               │
  └──────────────────────┬──────────────────────────┘
                         │
  ADAPTERS               ▼
  ┌─────────────────────────────────────────────────┐
  │ OpenAI · Anthropic · Ollama · Custom · Tools    │
  └─────────────────────────────────────────────────┘
```

---

## 4. Runtime Event Model

```
request.received → identity.resolved → policy.checked → risk.scored →
route.selected → memory.requested → memory.allowed|blocked →
tool.requested → tool.allowed|blocked → approval.requested →
approval.resolved → provider.called → response.received →
output.checked → output.redacted|blocked → action.executed →
response.released → cost.recorded → receipt.issued
```

- **View Mode**: events = observability records (flight recorder)
- **Control Mode**: events = enforcement checkpoints

---

## 5. Canonical Request Schema

```rust
struct RuntimeExecutionRequest {
    request_id: String,
    trace_id: String,
    tenant_id: String,
    app_id: String,
    environment: String,
    workflow_id: Option<String>,
    session_id: Option<String>,
    actor_id: String,
    actor_role: String,
    request_mode: Mode,          // View | Control
    model_intent: String,
    input_payload: serde_json::Value,
    tools_requested: Vec<String>,
    memory_scope: Option<String>,
    action_targets: Vec<String>,
    output_mode: OutputMode,     // Text | Stream | Structured
    budget_context: BudgetContext,
    compliance_tags: Vec<String>,
    execution_profile: String,
}
```

Every incoming format (OpenAI, Anthropic, workflow, tool, agent) normalizes into this.

---

## 6. Data Storage

| Store | Purpose | Status |
|---|---|---|
| Postgres | Tenants, workflows, request metadata, policies, approvals, audit indexes | New |
| Redis | Sessions, approval queues, rate limits, policy cache | New |
| Object storage | Evidence packs, trace snapshots, compliance exports | New (S3/minio) |
| Connector engine store | Receipts, proof artifacts, execution proofs, audit chain | ✅ Exists |
| Customer SIEM | Configurable log shipping | New (webhook/S3 adapter) |

---

## 7. Core Services — Mapping to Connector

### 7.1 API Gateway Service (extends existing)

Already built: `/v1/chat/completions`, `/v1/messages`, auth, rate limit, injection.

New:
- trace_id assignment on every request
- tenant_id resolution from API key prefix
- mode resolution (View vs Control) from tenant config
- forward to Resolver → Normalizer chain
- New routes: `/v1/responses`, `/v1/workflows/submit`, `/v1/tools/invoke`, `/v1/agents/run`

### 7.2 Identity + Tenant Resolver

Maps API key → full governance context.

Already built: auth, RBAC, agent_pid resolution, UCAN capabilities.

New: multi-tenant isolation layer, per-tenant config bundles.

```
cpk_live_abc123 → tenant:acme → actor:john@acme → role:senior_dev
  → policy_bundle:acme_default → budget:acme_team_a
  → providers:[openai,anthropic] → mode:control
```

### 7.3 View Pipeline (Trace / Explain / Prove / Cost / Statement)

| Component | New? | Maps to Connector |
|---|---|---|
| Trace recorder | Mostly new | Extends actionlog + audit |
| Explain builder | New | Reads admission/policy decisions, formats for humans |
| Prove builder | Extends | CID chain + receipts exist, needs unified surface |
| Cost collector | Extends | billing.record_llm_gateway_usage exists, needs per-request surface |
| Statement builder | New | Aggregates trace + cost + decisions at workflow level |

### 7.4 Control Pipeline

**Policy Controller** — Connector has admission gate, UCAN, DevGuard. New: customer YAML compiler.

**Risk Controller** — Connector has injection detection, anomaly detection, trust scores. New: PHI/PII scoring, side-effect classification.

**Routing Controller** — Connector has LlmRouter with fallback, adaptive routing. New: policy-driven model selection, budget-aware downgrade.

**Approval Controller** — Connector has HITL gate, tool approvals. New: queue service, webhook continuation, reviewer notification.

### 7.5 Guard Services

| Guard | What it does | Connector Foundation |
|---|---|---|
| Tool Guard | Control tool invocation | MCP invoke + scoped bindings + circuit breaker |
| Memory Guard | Control context access | Memory kernel + sessions + access revoke |
| Output Guard | Check response before release | Content firewall + grounding |
| Action Guard | Govern side-effects | New (wraps external API calls) |

### 7.6 Connector Bridge Layer

Thin translation — the critical boundary:
- Translate RuntimeExecutionRequest → Connector syscalls
- Send decisions → admission gate
- Receive receipts, audit artifacts, budget data
- Never duplicate — always delegate to Connector

### 7.7 Evidence API

| Endpoint | What it returns |
|---|---|
| `GET /trace/<request_id>` | Ordered event timeline |
| `GET /explain/<request_id>` | Decision reasoning (allow/block/route/why) |
| `GET /prove/<request_id>` | Receipt chain + integrity hashes + tamper status |
| `GET /cost/<request_id>` | Token breakdown, model cost, total |
| `GET /workflow/<id>/statement` | Full workflow summary |

### 7.8 Admin Plane

| API | Purpose | Connector Foundation |
|---|---|---|
| `/admin/tenants` | Tenant CRUD | New |
| `/admin/providers` | LLM provider config | Extends gateway config |
| `/admin/policies` | Policy management | Extends UCAN + dynamic policies |
| `/admin/rbac` | Role management | Extends auth/rbac |
| `/admin/budgets` | Budget setup | Extends billing tiers |
| `/admin/logging` | Log destination config | New |
| `/admin/approvals` | Approval reviewer setup | Extends HITL |
| `/admin/compliance` | Compliance config | Extends AAPI compliance |

---

## 8. Request Lifecycle (production flow)

```
Step 1: POST /v1/chat/completions → Gateway authenticates, assigns request_id + trace_id
Step 2: Resolver fetches tenant, actor, workflow, policies, budget, providers
Step 3: Normalizer builds RuntimeExecutionRequest
Step 4: Mode fork:
        View Mode → record, observe, trace, cost, evidence
        Control Mode → policy check, risk score, route, guards, approval
Step 5: Connector Bridge → enforcement, receipts, cost accounting, memory/tool governance
Step 6: Provider call → model endpoint / local model / tool / external API
Step 7: Output Guard → leakage, compliance, certainty, release eligibility
Step 8: Response released to client
Step 9: Evidence immediately queryable: /trace, /explain, /prove, /cost, /statement
```

---

## 9. Security Architecture

### Mental model (OS-level thinking)
- requests = processes
- tools = syscalls
- memory = address space
- budgets = quotas
- policies = kernel rules
- receipts = kernel journal

### Minimum guarantees
- Tenant isolation (no cross-tenant data leak)
- Provider key isolation (per-tenant encrypted storage)
- No bypass around Connector (all paths go through bridge)
- Policy before provider call in Control Mode
- Tool actions always governed
- Memory access always bounded
- Output checked before release in Control Mode
- Every execution step receipted
- Approval actions authenticated and logged
- Audit/export access RBAC-gated

---

## 10. RBAC — Two Layers

### A. Management Plane RBAC (who manages the system)
- platform admin
- tenant admin
- operator
- reviewer
- auditor
- read-only

### B. Runtime Execution RBAC (who causes what AI behavior)
- which app → which models
- which actor role → which workflows
- which workflows → which tools/actions
- which roles → can approve
- which roles → can export evidence

---

## 11. Policy Architecture

### Policy domains
- provider, model, workflow, actor/role, tool, memory, output, region, budget, approval, compliance

### Policy outcomes
- allow
- allow with transform
- route to approved provider
- downgrade model
- require reviewer approval
- redact output
- block request
- block tool action

### Customer-friendly format
```yaml
# tracetramp-policy.yaml
tenant: acme
mode: control
rules:
  - scope: model
    allow: [gpt-4o, claude-sonnet-4-20250514]
    block: [gpt-4-32k]  # too expensive
  - scope: tool
    require_approval: [send_email, update_crm, deploy_*]
  - scope: output
    redact: [ssn, credit_card, api_key]
  - scope: budget
    daily_limit: 50_000_tokens
    monthly_limit: 1_000_000_tokens
    on_exceed: downgrade_to_mini
  - scope: workflow
    phi_workflows: [patient_*, claims_*]
    phi_provider: azure_hipaa_endpoint
```

Compiles into Connector runtime rules (UCAN + admission + DevGuard).

---

## 12. Evidence Architecture (biggest differentiator)

### Trace
Human-readable ordered execution record.

### Explain
Human-readable reasoning: why allow/block, why this route, why approval needed, why this model.

### Prove
Integrity evidence: request hash, policy hash, chain status, receipt count, tamper status.

### Statement
Workflow-level summary: what happened, what attempted, what blocked, what approved, what released, total cost.

### Example: `/explain/req_abc123`
```json
{
  "request_id": "req_abc123",
  "decisions": [
    {
      "step": "policy.checked",
      "result": "allow",
      "reason": "Actor role 'senior_dev' has access to model 'gpt-4o' in tenant 'acme'",
      "policy_ref": "pol_acme_default_v3"
    },
    {
      "step": "risk.scored",
      "result": "medium",
      "reason": "Request contains pattern matching PHI regex, flagged for output guard",
      "score": 0.62
    },
    {
      "step": "output.checked",
      "result": "redacted",
      "reason": "SSN pattern detected in response, redacted per policy rule output.redact.ssn",
      "fields_redacted": 1
    }
  ]
}
```

---

## 13. Dashboard Screens

| Screen | Shows |
|---|---|
| **Tenant Overview** | Total requests, active workflows, daily cost, blocked actions, pending approvals |
| **Live Request Timeline** | Incoming requests, routed models, status, latency, cost, mode |
| **Request Detail** | Full trace, explain panel, prove panel, receipts, output decision, policy hits |
| **Approval Queue** | Pending items, action type, risk level, requester, approve/reject |
| **Cost Center** | Cost by model/workflow/team, budget status, anomalies |
| **Compliance Export** | Evidence pack generation, statement export, policy/export history |
| **Provider Health** | Upstream status, latency, error rates, routing distribution |

---

## 14. CLI

```
tracetramp status                         # system health
tracetramp trace <request_id>             # show trace timeline
tracetramp explain <request_id>           # show decision reasoning
tracetramp prove <request_id>             # show integrity proof
tracetramp cost <request_id>              # show cost breakdown
tracetramp workflow statement <wf_id>     # workflow summary
tracetramp approvals list                 # pending approvals
tracetramp approvals approve <id>         # approve action
tracetramp approvals reject <id>          # reject action
tracetramp tenant show <tenant>           # tenant overview
tracetramp doctor                         # diagnose setup issues
```

---

## 15. Module Tree

```
tracetramp/
├── gateway/          # HTTP ingress, streaming, auth, error normalization
├── resolver/         # tenant, actor, workflow, budget, provider resolution
├── normalizer/       # request schema, provider mapping, canonical model
├── view/             # trace_recorder, explain_builder, prove_builder, cost_collector, statement
├── control/          # policy_controller, risk_controller, routing_controller, approval_controller
├── guards/           # tool_guard, memory_guard, output_guard, action_guard
├── connector_bridge/ # runtime_client, receipt_adapter, evidence_adapter, policy_binding
├── evidence_api/     # trace, explain, prove, cost, workflow_statement endpoints
├── admin/            # tenants, providers, rbac, budgets, policies, logging, compliance
├── approvals/        # queue, notifications, review_actions
├── dashboard/        # overview, request_detail, approvals, cost_center, compliance_exports
├── storage/          # postgres, redis, object_store, caches
├── adapters/         # openai, anthropic, ollama, custom_provider, tool_adapters
└── cli/              # status, trace, explain, prove, cost, approvals, tenant, doctor
```

---

## 16. Deployment Models

### A. Pilot (1 VM / 1 cluster)
- All services colocated
- Connector node + Redis + Postgres
- Self-hosted pilots, fast demos, low cost

### B. Managed SaaS
- Load balancer → multiple gateway instances
- Separate services for resolver, view, control, approval, evidence, admin
- Connector runtime pool, Redis cluster, Postgres primary/replica
- Multi-tenant, better isolation

### C. Regulated Isolated (healthcare/fintech)
- Per-tenant: dedicated gateway, control plane, Connector runtime, database, evidence store
- Private network routing
- Strictest audit/compliance boundaries

---

## 17. Budget + Cost Engine

### Responsibilities
- Input/output token counting (per request)
- Model cost calculation (per provider pricing)
- Request cost, session cost, workflow cost
- Tenant daily/monthly spend tracking
- Per-user/team cost attribution

### Enforcement
- Hard stop (deny request)
- Soft warning (log + allow)
- Model-specific caps
- Tenant-level caps
- Workflow-specific caps
- on_exceed: downgrade_to_mini | deny | alert_only

### Connector foundation
- `billing::record_llm_gateway_usage()` — already tracks tokens, cost, model
- `billing::check_limits()` — already enforces tier limits
- `GET /agents/:pid/cost` — already provides per-agent cost
- `GET /monitor/cost-dashboard` — already exists
- Need: per-tenant aggregation, per-workflow roll-up, budget policy compilation

---

## 18. Build Order

### Phase 1 — View Mode MVP (weeks 1-3)

Gets you first pilots. Low-friction adoption.

| Task | Effort | Depends on |
|---|---|---|
| trace_id propagation through gateway | 2 days | — |
| RuntimeExecutionRequest schema | 2 days | — |
| Tenant resolver (API key → tenant → config) | 3 days | Postgres migration |
| Postgres schema + migration | 2 days | — |
| Trace recorder service | 3 days | trace_id, event model |
| Explain builder service | 3 days | admission decisions |
| Prove builder service | 2 days | CID chain + receipts |
| Cost collector (per-request surface) | 2 days | billing hooks |
| Evidence API (5 endpoints) | 3 days | view pipeline |
| Admin: provider config | 2 days | tenant model |
| Connector bridge layer | 3 days | — |
| Provider adapters (extend existing) | 2 days | — |

**Total: ~27 dev-days (~3 weeks for 1-2 engineers)**

### Phase 2 — Light Control (weeks 4-5)

Gets you governance. First enterprise conversations.

| Task | Effort |
|---|---|
| Policy controller + YAML compiler | 4 days |
| Routing controller (policy-driven model selection) | 3 days |
| Budget enforcement (hard/soft limits) | 2 days |
| Basic RBAC (management plane) | 3 days |
| Model allow/block rules | 1 day |
| Output guard basics (redaction) | 3 days |

**Total: ~16 dev-days (~2 weeks)**

### Phase 3 — Full Control Mode (weeks 6-8)

True execution control. Enterprise moat.

| Task | Effort |
|---|---|
| Tool guard | 3 days |
| Memory guard | 3 days |
| Action guard (side-effect governance) | 4 days |
| Approval controller + queue (Redis) | 4 days |
| Reviewer notification (webhook/email) | 2 days |
| Risk controller (PHI/PII scoring) | 3 days |
| Workflow-level policy depth | 3 days |

**Total: ~22 dev-days (~3 weeks)**

### Phase 4 — Enterprise Hardening (weeks 9-12)

Ship to regulated customers.

| Task | Effort |
|---|---|
| Dashboard UI (7 screens) | 10 days |
| Multi-tenant scale testing | 3 days |
| Compliance export (SOC 2, HIPAA, GDPR packs) | 5 days |
| Regulated deployment mode (tenant isolation) | 5 days |
| Log shipping (S3, Splunk, webhook) | 3 days |
| CLI (12 commands) | 4 days |
| Docker packaging | 2 days |
| Documentation + onboarding guide | 3 days |

**Total: ~35 dev-days (~4 weeks)**

### Total estimate: ~100 dev-days (12 weeks / 2 engineers)

---

## 19. Risk + Mitigation

| Risk | Mitigation |
|---|---|
| Latency overhead | Gateway adds <10ms (in-memory, no external calls in hot path) |
| Postgres dependency | Start with Connector engine store, migrate to Postgres incrementally |
| Multi-tenant complexity | Phase 1 = single-tenant, Phase 3 = multi-tenant |
| Dashboard build time | Use existing Leptos stack, share components with Connector dashboard |
| Control Mode adoption friction | View Mode first (zero enforcement), Control Mode opt-in per tenant |

---

## 20. Competitive Position

| Feature | TraceTramp | LiteLLM | Helicone | Portkey | MintMCP |
|---|---|---|---|---|---|
| OpenAI/Anthropic proxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Trace (structured timeline)** | ✅ | ○ | ○ | ○ | ○ |
| **Explain (decision reasoning)** | ✅ | ○ | ○ | ○ | ○ |
| **Prove (integrity chain)** | ✅ | ○ | ○ | ○ | ○ |
| **Control Mode (enforcement)** | ✅ | ○ | ○ | ○ | ○ |
| Policy engine | ✅ | ○ | ○ | ○ | partial |
| File/exec/git governance | ✅ | ○ | ○ | ○ | ○ |
| Agent quarantine | ✅ | ○ | ○ | ○ | ○ |
| Approval workflows | ✅ | ○ | ○ | ○ | partial |
| OS-level cage | ✅ | ○ | ○ | ○ | ○ |
| HIPAA/SOC2 built-in | ✅ | ○ | ○ | ○ | ○ |
| Budget hard gates | ✅ | ○ | ○ | ○ | ○ |
| Compliance evidence export | ✅ | ○ | partial | ○ | partial |
| Self-hosted | ✅ | ✅ | ✅ | ✅ | ○ |
| Memory kernel | ✅ | ○ | ○ | ○ | ○ |

**Moat**: Two-mode model. View Mode for adoption, Control Mode for lock-in. Evidence Plane for compliance premium.

---

## 21. Final Positioning

> **TraceTramp is a production-grade proxy-native tracing and execution control plane for AI systems. In View Mode it records, explains, and proves what workflows do. In Control Mode it governs execution with policy, approvals, budgets, and OS-level certainty.**

> **See everything. Control what matters. Prove what happened.**
