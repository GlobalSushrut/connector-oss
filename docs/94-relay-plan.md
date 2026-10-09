# Relay — Plan, Strategy & Enterprise Design

> **Relay is the zero-framework agent runtime.**
> Point any function, script, or service at a URL. Relay attaches LLM routing, memory, tools, governance, tracing, cost tracking, and compliance — without a single library import.

---

## 1. The Name

**Relay** — a relay receives a signal and re-transmits it with switching, amplification, and control added. That is exactly what this does: your logic comes in, Connector's full runtime capability is added, and the enriched signal goes out.

> "Drop LangChain. Drop LangSmith. Drop OpenFaaS. Point your agent at Relay."

Portfolio slot:

```
Connector (kernel)
├── Identity:      AgentPassport
├── Code layer:    DevGuard
├── Runtime:       TraceTramp
├── Orchestration: Conductor
├── Lifecycle:     AgentLoop
├── Cost:          LedgerLens
├── Audit:         WitnessCtl
└── Runtime Proxy: Relay          ← This
```

---

## 2. The Problem — Why This Slot Exists

### 2.1 The Real Landscape (researched, April 2026)

Four distinct categories of tools exist today. None of them is a governed agent runtime.

#### Category A — Framework/Orchestration (require code restructuring)

| Tool | Language | What it is | Core gap |
|---|---|---|---|
| **LangChain** | Python | Tool chains, prompt management, LLM wrappers | No governance, no RBAC, no budget, no audit. Code dependency — rewrite to move off. |
| **LangGraph** | Python | Stateful multi-agent graph primitives | No HITL, no budget enforcement, no compliance. You build the plumbing. |
| **LangSmith** | Python | Observability layer for LangChain only | Only sees LangChain calls. Your custom agent is invisible. Doesn't enforce anything. |
| **CrewAI** | Python | Role-based agent crews | No schema validation, no replay, no policy gates. Hits scale wall at 6–12 months. |
| **AutoGen** | Python | Research-grade multi-agent conversations | Not production-grade. No budget, no HITL, no determinism. |
| **LangServe** | Python | Serve LangChain chains as HTTP APIs | LangChain-only. No governance at the HTTP layer. |

#### Category B — Function Runtime (language-agnostic, but LLM-blind)

| Tool | Language | What it is | Core gap |
|---|---|---|---|
| **OpenFaaS** | Go | Serverless function runtime on Kubernetes | No concept of LLM, tokens, memory, tools, or agents. Watchdog is a process manager, not an agent runtime. Requires Docker + K8s + container build per function. |

#### Category C — Personal Agent Assistants (single-user, no enterprise)

| Tool | Stars (Apr 2026) | What it is | Core gap |
|---|---|---|---|
| **OpenClaw** | 250K+ | Personal AI assistant — gateway daemon, 50+ integrations (WhatsApp, Telegram, Slack, Discord, iMessage, Gmail, GitHub, Spotify, Hue, browser). TypeScript, Node 24. Skills marketplace (ClawHub). | Single-user by design. Local gateway (`port 18789`). No RBAC, no multi-tenant, no enterprise audit, no budget gates. Cold start: 5.98 seconds. Memory: 394 MB idle. No production governance. |
| **OpenFang** | Rust, 14 crates, 137K LOC | Open-source Agent OS in Rust. Pre-built "Hands" (autonomous capability packages). 40 channel adapters, 53 tools, WASM sandbox, 27 LLM providers, 16 security layers, OpenAI-compatible API. Single binary ~32MB. Cold start: 180ms. Memory: 40MB idle. Has migration tool from OpenClaw + LangChain. | Personal/prosumer target. No enterprise RBAC, no org-level policy, no compliance (HIPAA/SOC2), no cryptographic audit chain, no AgentPassport identity, no cost attribution by team/role. No integration with existing enterprise SSO. Hands are pre-built; you can't register your own existing HTTP service as a governed function. |

#### Category D — Academic OS (not production)

| Tool | What it is | Core gap |
|---|---|---|
| **AIOS** (agiresearch) | LLM Agent Operating System — academic research project. Kernel abstracts LLM, memory, storage, tool scheduling. Python. Experimental Rust rewrite (aios-rs) — trait definitions only. Cerebrum SDK for agent development. 4 deployment modes (local kernel → remote kernel). | Research paper (COLM 2025). No production hardening. No RBAC, no billing, no compliance, no enterprise auth. Rust rewrite is "trait definitions and minimal placeholder implementations" — not feature-complete. Cannot run your existing HTTP service as an agent. |

### 2.2 What Every Category Gets Wrong

```
Category A (LangChain family):  You must restructure your code around the framework.
                                Migration = full rewrite. Framework is the product.

Category B (OpenFaaS):          Language-agnostic ✅ but LLM-blind.
                                Knows your function ran. Has no idea what it did.
                                No tokens, no prompts, no memory, no agent lifecycle.

Category C (OpenClaw/OpenFang): Rich feature set for personal use.
                                Not designed for multi-tenant enterprise.
                                No RBAC, no compliance, no org-level policy.
                                OpenFang's Hands are pre-built packages —
                                you cannot register your own existing service.

Category D (AIOS):              Academic design. Rust rewrite is stubs.
                                Cannot run in production today.
```

### 2.3 The Hidden Costs Teams Actually Pay

- **Migration hell**: LangChain → LangGraph rewrites documented at 6–12 months wall
- **Observability gap**: LangSmith only sees LangChain; OpenFang/OpenClaw are invisible to enterprise monitoring
- **No production controls**: cold start 2.5–6 seconds on Python frameworks; OpenFang 180ms but still personal-use
- **No portability**: LangChain code doesn't work with CrewAI; OpenFang Hands don't accept your existing HTTP service
- **Governance vacuum**: OpenClaw (250K stars, most popular) has **zero enterprise governance** — no RBAC, no audit, no budget
- **Vendor lock**: LangSmith is OpenAI-adjacent; AIOS is research-only; OpenFang is pre-1.0, breaking changes between minors

### 2.4 The ConnectorOS Insight

ConnectorOS already IS a production-grade agent runtime. It has:

- OpenAI-compatible LLM proxy (drop-in for any SDK)
- Multi-provider LLM routing with fallback
- Admission gate (injection detection, content firewall)
- RBAC + API keys + SSO
- Per-agent cost tracking + budget gates
- MCP server (30+ tools: memory, exec, file, search, git)
- A2A channels (agent-to-agent communication)
- CID-chained audit log
- UCAN capability delegation
- Secret store + PHI sanitization
- Agent lifecycle (register, suspend, quarantine, terminate)
- Signal handlers + circuit breakers
- Self-heal candidates + regression detection

**Nobody has surfaced this as "bring your own logic, we're your runtime."**

Relay makes that surface explicit.

---

## 3. What Relay Is

### 3.1 The Core Idea

```
Before Relay:
  Your agent code → LangChain → LangSmith → custom retry → DIY governance → LLM

After Relay:
  Your agent code → Relay (URI + port)
                    ├── LLM routing          (Connector gateway)
                    ├── Memory               (Connector memory kernel)
                    ├── Tools                (Connector MCP server)
                    ├── Governance           (Connector admission gate + RBAC)
                    ├── Tracing              (Connector audit log + TraceTramp)
                    ├── Cost tracking        (Connector ledger + LedgerLens)
                    ├── Identity             (AgentPassport)
                    └── Orchestration        (Conductor, if multi-step)
```

### 3.2 The Setup

Three steps to get full Connector runtime capability on any existing agent:

```bash
# Step 1: Register your function/agent endpoint
relay register \
  --name "customer-support-agent" \
  --uri  http://localhost:3000/run \
  --port 3000

# Step 2: Set environment (your existing code, unchanged)
export OPENAI_BASE_URL=http://relay:9091/v1
export OPENAI_API_KEY=cpk_live_...
export RELAY_MCP_URL=http://relay:9091/mcp

# Step 3: Done. Your agent now has:
# - full audit trail
# - RBAC + budget gates
# - memory + tools injected
# - tracing + observability
# - cryptographic identity (AgentPassport DID)
```

### 3.3 What "Zero Orchestration" Means

Relay doesn't impose a framework. It doesn't require you to subclass anything, import a library, or restructure your code.

You write your logic in **any language, any framework, any shape**:

```python
# Python function — no LangChain, no decorators
def run(inputs: dict) -> dict:
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": inputs["query"]}]
    )
    return {"result": response.choices[0].message.content}
```

```typescript
// TypeScript HTTP handler — no LangChain, no SDK
app.post("/run", async (req, res) => {
  const result = await callOpenAI(req.body.query);
  res.json({ result });
});
```

```bash
# Shell script — yes, even this
curl http://relay:9091/v1/chat/completions -d '{"messages": [...]}'
```

All you do: point `OPENAI_BASE_URL` at Relay. That single change gives you everything.

---

## 4. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     RELAY (thin layer)                             │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Function Registry                                           │  │
│  │  - register(name, uri, port, policy, instructions)          │  │
│  │  - list(), get(), deregister()                              │  │
│  │  - health-check loop                                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Invocation Proxy                                            │  │
│  │  POST /relay/invoke/:name  →  forward to registered URI      │  │
│  │  - inject: memory context (from Connector memory kernel)    │  │
│  │  - inject: MCP tool list (Connector MCP server)             │  │
│  │  - inject: agent identity (AgentPassport DID)               │  │
│  │  - enforce: RBAC + budget gate (Connector admission gate)   │  │
│  │  - trace: every call → Connector audit log + TraceTramp     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Policy + Instructions Layer                                 │  │
│  │  - per-function policies (relay.yaml)                       │  │
│  │  - system prompt injection (instructions prepended to calls)│  │
│  │  - tool allow/deny lists per function                       │  │
│  │  - budget per function, per org, per role                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │ HTTP only
┌──────────────────────────────────▼─────────────────────────────────┐
│                      CONNECTOR (kernel)                            │
│  LLM proxy · Admission gate · Audit · Memory · MCP · RBAC         │
│  Budget gate · A2A · Agent lifecycle · UCAN · Secret store         │
└────────────────────────────────────────────────────────────────────┘
```

### 4.1 relay.yaml — the full setup

```yaml
# relay.yaml — register any function as a governed agent
version: "1"

functions:
  - name: customer-support
    uri: http://localhost:3000/run
    description: "Handles tier-1 customer queries"

    # Policy (maps to ConnectorOS RBAC + DevGuard policy)
    policy:
      allowed_models: [gpt-4o-mini, claude-haiku-3-5]
      budget:
        per_call_tokens: 2000
        per_day_usd: 5.00
        on_exceed: deny
      tools: [memory_read, memory_write, web_search]
      deny_tools: [exec, git_commit, file_write]
      require_role: [agent, senior]
      hipaa: false
      pii_redact: true

    # Instructions (prepended to every system prompt)
    instructions: |
      You are a customer support assistant. Be concise.
      Never mention internal system names or pricing.
      Always escalate billing issues to tier-2.

    # Identity (links to AgentPassport)
    identity:
      sponsor_email: eng-lead@acme.com
      auto_register_passport: true

    # Health check
    health:
      path: /health
      interval_secs: 30

  - name: code-reviewer
    uri: http://code-agent:8000/review
    policy:
      allowed_models: [claude-sonnet-4, gpt-4o]
      budget:
        per_call_tokens: 8000
        per_day_usd: 20.00
      tools: [memory_read, file_read]
      deny_tools: [exec, file_write, git_commit]
    instructions: |
      You review code for security vulnerabilities and code quality.
      Flag any hardcoded secrets immediately.
```

---

## 5. What ConnectorOS Provides (~90% Already Built)

| Capability | Connector Endpoint | Relay uses it for |
|---|---|---|
| LLM proxy | `POST /v1/chat/completions` | Every LLM call from registered functions |
| Anthropic proxy | `POST /v1/messages` | Claude-using functions |
| LLM routing | Connector router | Model selection, fallback |
| Admission gate | Connector pre-flight | Injection detection, content firewall |
| RBAC + API keys | Connector auth | Per-function key, per-role policy |
| Budget gate | Connector metering | Per-function, per-org hard limits |
| Memory kernel | Connector memory API | Inject persistent context per agent |
| MCP server | Connector MCP | Tool injection (30+ tools available) |
| A2A channels | `/tools/a2a/*` | Inter-function messaging |
| Audit log | Connector audit | Every invocation, every LLM call |
| PHI sanitization | HIPAA controls | Auto-redact from any function's output |
| Secret store | Connector secrets | Inject secrets safely into function calls |
| Agent lifecycle | Connector lifecycle | Suspend, quarantine, terminate a function |
| UCAN capabilities | `/aapi/capabilities/*` | Fine-grained function-level capabilities |
| AgentPassport | AgentPassport plugin | DID + reputation per registered function |
| TraceTramp | TraceTramp plugin | OTEL trace per invocation |
| LedgerLens | LedgerLens plugin | Cost attribution per function |

**What Relay builds new (~10%)**:
- `relay.yaml` parser + compiler
- Function Registry (Postgres table + health-check loop)
- Invocation proxy (HTTP reverse proxy with context injection)
- Instructions injection (system prompt prepend at proxy layer)
- CLI (`relay register`, `relay invoke`, `relay logs`, `relay status`)
- SDK wrappers (Python, TypeScript) for typed invocation

---

## 6. Feature Set (Relay vs Real Competitors — Researched)

| Feature | **Relay** | OpenFang | OpenClaw | AIOS | OpenFaaS | LangChain |
|---|---|---|---|---|---|---|
| **Any language/framework** | ✅ | Rust-only internal | TS only (Node) | Python | ✅ | Python only |
| **Zero import required** | ✅ | ❌ use their SDK | ❌ npm install | ❌ pip install | ✅ | ❌ pip install |
| **Register existing HTTP service** | ✅ | ❌ use Hands only | ❌ skills only | ❌ | ✅ | ❌ |
| **No container build required** | ✅ | ✅ single binary | ✅ npm global | ❌ | ❌ Docker required | ✅ |
| **Multi-tenant enterprise RBAC** | ✅ | ❌ single user | ❌ single user | ❌ | ✅ (basic auth) | ○ |
| **SSO / OIDC (Okta, Azure AD)** | ✅ | ❌ | ❌ | ❌ | ✅ (Pro tier) | ○ |
| **Per-function budget gates (USD)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **LLM routing + fallback** | ✅ | ✅ (27 providers) | ✅ (multi model) | ✅ | ❌ | ✅ |
| **Memory injection (persistent)** | ✅ | ✅ SQLite + vector | ✅ sessions | ✅ kernel | ❌ | partial |
| **53+ tool injection (MCP)** | ✅ | ✅ 53 tools | ✅ 50+ integrations | ✅ tool manager | ❌ | ✅ manual |
| **CID-chained cryptographic audit** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **HIPAA / SOC 2 compliance** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **PII / PHI redaction** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Agent identity (DID + passport)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Auto-quarantine on incident** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Policy-as-code (YAML)** | ✅ relay.yaml | ✅ HAND.toml | ✅ openclaw.json | ❌ | partial stack.yaml | ❌ |
| **System prompt injection at proxy** | ✅ | ✅ SKILL.md | ✅ SOUL.md | ❌ | ❌ | manual |
| **Cold start** | ~8ms overhead | 180ms | 5.98s | N/A (Python) | 2.5s (LangGraph) | 3s+ |
| **Idle memory** | ~40MB (Rust) | 40MB (Rust) | 394MB (Node) | 180MB+ (Python) | 180MB (K8s) | 180MB |
| **Production hardened** | ✅ | ⚠️ pre-1.0 | ✅ | ❌ academic | ✅ | ✅ |
| **Self-hosted / on-prem** | ✅ | ✅ | ✅ | partial | ✅ | ✅ |
| **Cost attribution per team/role** | ✅ LedgerLens | ❌ | ❌ | ❌ | ❌ | ❌ |
| **OTEL traces per invocation** | ✅ TraceTramp | ❌ | ❌ | ❌ | ❌ | partial |
| **40+ messaging channel adapters** | via MCP | ✅ 40 channels | ✅ 50+ channels | ❌ | ❌ | ❌ |

---

## 7. The "How It Beats Them" Story

### vs OpenFang (the closest technical competitor)

> **"OpenFang is a great personal agent OS. Relay is the enterprise agent runtime."**

OpenFang is impressive: 14 Rust crates, 137K LOC, 53 tools, 40 channel adapters, 27 LLM providers, 7 autonomous Hands, single 32MB binary, 180ms cold start. Built-in Ed25519 signing. WASM sandbox. Real engineering.

But OpenFang is built for **one person, one machine**:
- No org-level RBAC — no concept of teams, roles, or multi-tenancy
- No enterprise SSO (Okta, Azure AD, Google Workspace)
- No per-function budget gates in USD — you can't say "support-agent: max $50/day"
- No CID-chained cryptographic audit trail — no proof that any specific call happened
- No HIPAA/SOC 2 — no PII redaction, no compliance export
- No agent identity (DID) — nothing that procurement can verify
- Pre-1.0 — breaking changes between minor versions; they say "pin to a specific commit for production"
- **The Hands model is incompatible with Relay's model**: Hands are pre-built autonomous capability packages you activate. You cannot take your existing Python API and register it as a governed Hand. Relay's core value is "bring your existing HTTP service."

For a startup founder running personal automations: OpenFang.
For an enterprise with 50 agent services, compliance requirements, and a CISO: Relay.

### vs OpenClaw (250K GitHub stars — the most popular)

> **"OpenClaw solved personal AI. Relay solves enterprise AI."**

OpenClaw is the fastest-growing open-source AI project ever — 250K stars in ~60 days (Jan 2026). 50+ integrations, multi-channel inbox (WhatsApp, Telegram, Slack, Discord, iMessage, Gmail, GitHub, Spotify, Hue, browser). Skills marketplace (ClawHub). TypeScript, Node 24.

But it is explicitly **a personal assistant, not a platform**:
- 394MB idle memory (Node.js) — 10× OpenFang, not suitable for fleet deployment
- 5.98 second cold start — the slowest in the benchmark
- DM pairing model is designed for one user — not an org of 500 engineers
- No RBAC, no multi-tenant, no enterprise audit
- `openclaw gateway --port 18789` — single daemon on your machine
- Its security model is: "DMs from unknown senders get a pairing code" — appropriate for personal use, not for API security
- No budget gates — it will spend whatever your API key allows

OpenClaw's 250K stars prove the **demand** for easy agent deployment. Relay is the answer for when that agent needs to run in an enterprise.

### vs AIOS (academic — the original "agent OS" paper)

> **"AIOS defined the vision. Relay is the production version."**

AIOS (agiresearch, published COLM 2025) introduced the concept of treating LLM as an OS kernel — with modules for LLM core, memory manager, context manager, storage manager, tool manager, agent scheduler. The framing is exactly right.

But AIOS is an **academic research system**:
- Python — 180MB+ idle, no production hardening
- Rust rewrite (`aios-rs/`) is "trait definitions and minimal placeholder implementations" — not runnable
- No RBAC, no billing, no compliance, no enterprise auth
- 4 deployment modes defined in docs — only Mode 1 and 2 implemented
- No HIPAA, no audit trail, no budget enforcement
- You cannot take your existing HTTP service and "register" it — you must build against their SDK

AIOS proved the kernel architecture is correct. Connector built it in production Rust 2 years ago. Relay surfaces it.

### vs OpenFaaS (function runtime)

> **"OpenFaaS runs functions. Relay runs agent functions — memory, tools, governance included."**

OpenFaaS requires: Kubernetes + Helm + container registry + `faas-cli build` + `faas-cli push` + `faas-cli deploy`. A Dockerfile per function. Every function gets an `of-watchdog` sidecar baked in.

OpenFaaS tracks: RPS, concurrency, Prometheus metrics.

Relay requires: `relay register --uri http://your-existing-service`. Your existing service, untouched.

Relay tracks: every prompt, every token, every cost, every PII redaction, cryptographically signed per call.

OpenFaaS's watchdog is a **process manager**. Relay's proxy is an **agent runtime**.

### vs LangChain / LangGraph

> **"LangChain is a code dependency. Relay is an infrastructure choice."**

- LangChain: restructure code around `LLMChain`, `AgentExecutor`, `ToolNode`. Moving off = full rewrite.
- Relay: `export OPENAI_BASE_URL=http://relay:9091/v1`. Moving off = change one env var.

LangGraph gives you control primitives for complex pipelines. For the 80% of agent calls that are "user says X, agent does Y, done" — LangGraph is over-engineering. Relay is exactly right. For the 20% that need explicit graph orchestration — use Relay-registered functions as steps inside Conductor.

### vs LangSmith

> **"LangSmith only sees LangChain. Relay sees everything."**

LangSmith observes LangChain only. Your FastAPI agent, your Go service, your TypeScript function — invisible.

Relay observes every function regardless of language because they all call LLMs through the same proxy. No instrumentation required.

---

## 8. What It Produces for Each Buyer

### Developer
```
Before: pip install langchain langsmith openai + 200 lines of boilerplate
After:  export OPENAI_BASE_URL=http://relay:9091/v1 && python my_agent.py
```

### Platform Engineering
```
One relay.yaml manages all agent functions.
Policy changes are a YAML diff. No code deployments.
Budget exceeded? One line in relay.yaml. Deployed in 10 seconds.
```

### CISO
```
Every agent call: logged, attributed, signed.
PII redacted before it hits any LLM.
Every function has a DID. Instant revocation.
SOC 2 evidence: generated from the audit log, not manually collected.
```

### CFO
```
Every dollar attributed to a specific function, team, and user.
Budget gates prevent surprise bills.
Savings report generated weekly.
```

---

## 9. Architecture — What Gets Built

### 9.1 Relay Plugin (Axum HTTP server, same pattern as LedgerLens/WitnessCtl)

```
plugins/relay/
├── Cargo.toml
├── migrations/
│   └── 001_initial.sql
├── src/
│   ├── main.rs           — startup, background tasks, dual-port
│   ├── types.rs          — FunctionDef, InvocationRecord, PolicyConfig
│   ├── error.rs          — AppError, CISO-grade codes
│   ├── registry.rs       — register, deregister, list, health-check loop
│   ├── proxy.rs          — HTTP reverse proxy with context injection
│   ├── instructions.rs   — system prompt injection at proxy layer
│   ├── policy.rs         — relay.yaml parser, policy enforcement
│   ├── memory.rs         — Connector memory kernel bridge
│   ├── tools.rs          — MCP tool injection per function
│   ├── identity.rs       — AgentPassport auto-registration
│   ├── tracing.rs        — TraceTramp + Connector audit forwarding
│   ├── connector.rs      — ConnectorClient (RBAC, budget, audit, MCP)
│   └── routes.rs         — 12 API endpoints
└── .env.example
```

### 9.2 Database Schema

```sql
relay_functions     — id, name, uri, port, policy_json, instructions, status, health_status, did
relay_invocations   — id, function_id, caller_id, input_hash, output_hash, model_used,
                       tokens_in, tokens_out, cost_usd, latency_ms, audit_cid, invoked_at
relay_policies      — id, function_id, policy_json, version, active, created_at
relay_health_checks — id, function_id, status, latency_ms, checked_at
```

### 9.3 API Endpoints (12)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/functions` | Register a function (relay.yaml or JSON body) |
| `GET` | `/api/v1/functions` | List registered functions + health status |
| `GET` | `/api/v1/functions/:name` | Get function detail + live stats |
| `PUT` | `/api/v1/functions/:name` | Update policy/instructions without restart |
| `DELETE` | `/api/v1/functions/:name` | Deregister |
| `POST` | `/api/v1/functions/:name/invoke` | Invoke a registered function |
| `POST` | `/api/v1/invoke` | Raw invocation (pass URI directly, one-shot) |
| `GET` | `/api/v1/functions/:name/logs` | Last N invocation logs |
| `GET` | `/api/v1/functions/:name/stats` | Cost, latency, error rate |
| `POST` | `/api/v1/functions/:name/suspend` | Suspend (Connector quarantine) |
| `POST` | `/api/v1/functions/:name/resume` | Resume |
| `GET` | `/health` | DB + Connector health check |

### 9.4 CLI (`relay`)

```bash
relay register --name my-agent --uri http://localhost:3000/run --policy ./relay.yaml
relay invoke my-agent --input '{"query": "hello"}'
relay logs my-agent --tail 50
relay status                     # all functions + health
relay stats my-agent             # cost, latency, call count
relay suspend my-agent --reason "security review"
relay resume my-agent
relay export my-agent --format json   # Attestation pack via AgentPassport
```

---

## 10. Build Order (3 Phases)

### Phase 1 — Core Proxy (weeks 1-3)

**What ships**: Register a function. Invoke it. Every call routes through Connector (LLM proxy + audit).

- `relay.yaml` parser
- `relay_functions` table + registry endpoints
- Basic HTTP reverse proxy (reqwest forwarding to registered URI)
- Connector LLM proxy bridge (swap OPENAI_BASE_URL at proxy time)
- Invocation log in `relay_invocations`
- Health check loop
- `POST /functions`, `GET /functions`, `POST /functions/:name/invoke`
- CLI: `register`, `invoke`, `status`

**Value**: Replace LangSmith observability immediately. Any existing agent gets an audit trail.

### Phase 2 — Policy + Instructions (weeks 4-6)

**What ships**: Full `relay.yaml` policy compiler. Instructions injection. Budget gates. Tool allow/deny.

- `relay.yaml` full spec (policy, instructions, identity, budget, tools)
- Policy compiler → Connector RBAC + admission gate config
- System prompt injection at proxy layer
- Tool injection (Connector MCP tool list filtered by policy)
- Memory context injection (Connector memory kernel)
- Budget enforcement (delegate to Connector budget gate)
- PII/secret redaction bridge (Connector HIPAA controls)
- CLI: `logs`, `stats`, `suspend`, `resume`

**Value**: Replace LangChain's agent executor + LangSmith + manual policy. One YAML file controls everything.

### Phase 3 — Identity + Ecosystem (weeks 7-9)

**What ships**: Every registered function gets a DID (AgentPassport auto-registration). TraceTramp OTEL traces. LedgerLens cost attribution. SDK packages.

- AgentPassport auto-registration on `relay register`
- TraceTramp OTEL trace per invocation
- LedgerLens cost attribution per function/org/role
- Raw invocation endpoint (`POST /invoke` — no pre-registration needed)
- Attestation export via AgentPassport (`relay export`)
- Python SDK (`relay-py`): `relay.invoke("my-agent", inputs)` with typed responses
- TypeScript SDK (`relay-ts`)
- CLI: `export`

**Value**: Full Connector portfolio integration. Demo: "register a function, get identity, audit, cost tracking, and compliance in one command."

---

## 11. Competitive Position Summary

### What Relay learns from each competitor

| Competitor | What they got right | What Relay takes from them |
|---|---|---|
| **OpenFang** | Rust binary, HAND.toml manifest, SKILL.md injection, 53 tools | relay.yaml manifest, SKILL-like instructions injection, Connector MCP tool injection |
| **OpenClaw** | Gateway daemon model, skills marketplace, multi-channel routing | relay register as local daemon, policy marketplace (relay.yaml templates) |
| **AIOS** | Kernel architecture — LLM/memory/storage/tool as OS primitives | Connector is already this kernel; Relay exposes it via HTTP proxy |
| **OpenFaaS** | Language-agnostic HTTP function runtime, health-check loop, async queue | relay register accepts any HTTP URI; built-in health loop and async job queue |
| **LangChain** | Rich tool ecosystem, broad adoption | Import from LangChain via `relay import langchain` (Phase 3) |

### What Relay replaces (per buyer)

| Buyer Pain | Tool they use today | Why it fails them | Relay replacement |
|---|---|---|---|
| "I need LLM routing + fallback" | LiteLLM | No governance, no RBAC | Relay (Connector gateway) |
| "I need observability" | LangSmith | LangChain-only, no enterprise audit | Relay (Connector audit + TraceTramp) |
| "I need to run agent functions" | OpenFaaS | LLM-blind, Kubernetes required | Relay (function registry + proxy, no K8s) |
| "I want personal automation" | OpenClaw | No enterprise RBAC or audit | Relay (multi-tenant, governed) |
| "I want autonomous agents" | OpenFang | Pre-1.0, personal use, no compliance | Relay (production-grade, HIPAA, DID) |
| "I want an agent OS" | AIOS | Academic/research, not runnable in prod | Relay (production Rust, 2+ years deployed) |
| "I need agent memory" | LangChain memory / Mem0 | No governance, no cross-function scope | Relay (Connector memory kernel) |
| "I need cost visibility" | Custom dashboards | Manual, per-team silos | Relay (LedgerLens) |
| "I need compliance logging" | Custom + Datadog | Not agent-aware, no CID chain | Relay (Connector audit + WitnessCtl) |
| "I need to enforce budget" | Nothing — surprise bills | No enforcement primitive | Relay (Connector budget gate, hard limits) |

### The moat

OpenFang (the closest technical competitor) has 14 crates and 137K LOC of Rust. Impressive. But rebuilding what Connector already has — RBAC, budget gates, CID-chained audit, HIPAA controls, UCAN delegation, AgentPassport identity, A2A channels, and circuit breakers — would take 2+ years.

And even if they rebuilt it all: they would still need to find customers, build compliance certifications, and acquire the SSO integrations (Okta, Azure AD, Google Workspace) that enterprises require on day one.

---

## 12. Pricing

| Tier | Price | Includes |
|---|---|---|
| **Free** | $0 | 3 functions, 10K invocations/mo, basic audit, community support |
| **Pro** | $79/mo | 25 functions, 500K invocations/mo, full policy engine, memory injection, CLI |
| **Team** | $399/mo | Unlimited functions, budget gates, PII redaction, HIPAA, identity (DID), SDKs |
| **Enterprise** | Custom | On-prem, SSO, LedgerLens + TraceTramp integration, SLA, attestation packs |

**Expansion model**: land via Free (developer tries relay register in 2 minutes) → Pro (team adopts for production agents) → Team (compliance team asks for HIPAA + audit) → Enterprise (CISO asks for identity + attestation).

---

## 13. Go-To-Market

### Buyer personas

| Persona | Pain they have | What Relay says |
|---|---|---|
| **Developer** | Too many libraries; agents break in prod | "One env var. No library. Full runtime." |
| **Platform Engineer** | Managing N agent frameworks across M teams | "One relay.yaml per function. One control plane." |
| **CISO** | No visibility into what agents call, access, output | "Every call logged, attributed, and signed. PII never leaves clean." |
| **CFO** | Surprise $40K LLM bills | "Hard budget gates per function. Surprise bills eliminated." |

### Wedge play

**Target**: developer who built an agent in Python/FastAPI/TypeScript and has it "mostly working" but is now asked by their manager to add:
1. Observability ("what is it doing?")
2. Budget control ("how much is it spending?")
3. Compliance ("can we audit it for SOC 2?")

Their current plan: add LangSmith, write custom cost tracking, manually build audit log.

Relay's answer: change one line (`OPENAI_BASE_URL`). Done.

### Demo script

```
1. Show a Python agent calling OpenAI directly — no visibility
2. relay register --name demo-agent --uri http://localhost:3000 --policy relay.yaml
3. export OPENAI_BASE_URL=http://relay:9091/v1
4. Run same agent — zero code change
5. Show: audit log, cost dashboard, PII redacted, policy enforced
6. suspend demo-agent → agent calls return 403 instantly
7. Show relay.yaml — 20 lines replaced LangChain + LangSmith + custom cost tracking
8. "What did you just replace?" — pull up the stack diagram
```

---

## 14. Strategic Value in Connector Portfolio

Relay is the **lowest-friction entry point** in the entire portfolio.

- **AgentPassport**: every Relay function auto-gets a DID and sponsor chain
- **TraceTramp**: every invocation gets an OTEL trace
- **LedgerLens**: every function's cost is attributed and dashboarded
- **WitnessCtl**: every invocation is in the immutable audit log
- **Conductor**: complex multi-step pipelines can call Relay-registered functions as steps
- **DevGuard**: coding agents (Windsurf, Cursor) use Relay as their governed LLM proxy

The network effect: each new Relay function registered **increases** the value of AgentPassport (more agents with identity), TraceTramp (more runtime data), and LedgerLens (more cost attribution data).

---

## 15. One-Line Positioning by Audience

| Audience | One line |
|---|---|
| **Developer** | "Point your agent at a URL. Get LangChain + LangSmith capabilities without installing either." |
| **Platform Eng** | "One YAML file governs every agent function in your org. No framework sprawl." |
| **CISO** | "Every agent call is logged, attributed, and signed. PII never reaches any LLM unredacted." |
| **CFO** | "Hard budget gates on every function. Surprise AI bills become predictable costs." |
| **Investor** | "Relay replaces a 5-library dependency stack with a single environment variable. The moat is the Connector runtime — 2+ years of kernel work no framework competitor can replicate." |

---

> **Relay: Zero framework. Full runtime. One URL change.**
