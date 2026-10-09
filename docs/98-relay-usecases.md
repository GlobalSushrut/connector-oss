# Relay — What It Does, What You Get, Why It Wins

> Zero framework. Zero rewrite. Point your code at a URL — production-grade agent runtime attached.

---

## What Relay Does (Plain English)

Relay is the runtime layer for agent functions. You have code that calls an LLM — a Python script, a Go HTTP handler, a Node function, a Rust service. You want it to be a governed, observable, memory-equipped, cost-tracked enterprise agent. Today you'd need to pick a framework (LangChain, CrewAI), restructure your code around it, wire in observability (LangSmith), wire in memory (Mem0), wire in cost tracking (Helicone), wire in governance (something you probably just skip) — and then maintain all of that.

Relay's answer: don't. Register your endpoint. Change two environment variables. You're done.

Relay is the **missing runtime surface of ConnectorOS** — the thing that says "bring your existing logic, we'll be your runtime." No imports. No restructuring. No framework lock-in.

---

## What Relay Can Do — Full Capability Map

### 1. Zero-Framework Agent Registration

Register any HTTP endpoint as a governed agent function. Relay doesn't care what language it's written in, what framework it uses, or what shape the handler takes.

```bash
# Register a Python Flask function
relay register --name "support-agent" --uri http://localhost:5000/run

# Register a Go HTTP handler
relay register --name "code-reviewer" --uri http://localhost:8080/review

# Register a Node.js Express route
relay register --name "data-extractor" --uri http://localhost:3000/extract

# Register a Rust Axum handler
relay register --name "risk-scorer" --uri http://localhost:9000/score
```

**What you get immediately after registration:**
- Agent gets a Connector-issued DID (`did:connector:relay/support-agent`) via AgentPassport
- LLM traffic routed through Connector gateway — full audit, admission gate, budget enforcement
- MCP tools available: file, exec, memory, git, search — no SDK install
- Prometheus metrics: latency, error rate, token usage, cost per invocation
- Replay-safe invocation IDs for every call

**The output of registration:**
```json
{
  "agent_did": "did:connector:relay/support-agent",
  "relay_url": "http://relay:9091/fn/support-agent",
  "mcp_url":   "http://relay:9091/mcp",
  "llm_url":   "http://relay:9091/v1",
  "api_key":   "cpk_live_relay_..."
}
```

Set two env vars in your existing code. Ship.

---

### 2. Full LLM Runtime — No Config Required

Relay injects Connector's entire LLM runtime into your function via the gateway URL. Your code calls `openai.chat.completions.create()` — Relay intercepts every call and attaches:

| What Relay adds | What it does |
|---|---|
| **Multi-provider routing** | If OpenAI is down, falls back to Anthropic, Ollama, Azure — automatically |
| **Admission gate** | Every prompt checked for injection, PII, secret leakage before it leaves your infra |
| **Budget gate** | Function exceeds its token budget? Call is blocked. No $50K surprise bills. |
| **Secret redaction** | `.env` values, API keys in prompts stripped before hitting the LLM |
| **RBAC enforcement** | Agent's role determines which models it can access |
| **Semantic cache** | Identical or near-identical prompts return cached responses — cost drops 30–60% |
| **Audit trail** | Every prompt, every response, every model, every token — logged and signed |

**What you get:**
- Zero code change — your existing `openai.Client(base_url=...)` just works
- `OPENAI_BASE_URL=http://relay:9091/v1` — one line, full Connector runtime
- Every LLM call has a `call_cid` — content-addressed, tamper-evident audit entry
- Real-time cost dashboard in LedgerLens — per function, per team, per model

---

### 3. Memory Injection — No Mem0, No SDK

Relay connects your function to the Connector memory kernel (or Engram if deployed). Your function writes and reads memory via MCP tool calls — no separate memory service to provision.

```python
# Your agent code — unchanged structure
response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a support agent."},
        {"role": "user",   "content": user_message},
    ],
    tools=[{
        "type": "function",
        "function": {
            "name": "mcp__memory__recall",
            "description": "Recall relevant memory facts",
            "parameters": {"type": "object", "properties": {
                "query": {"type": "string"},
                "top_k": {"type": "integer"}
            }}
        }
    }]
)
```

The `mcp__memory__recall` tool call goes through `http://relay:9091/mcp` — Relay routes it to the memory kernel, returns grounded facts, logs the access.

**What you get:**
- Persistent memory across sessions — no session state in your code
- Hybrid recall: semantic + BM25 + entity linking
- Memory namespace isolation — your function's memory stays in its own namespace
- If Engram is deployed: entropy scoring, dehallucination grounding, CoT Anchor — all available via MCP
- Every memory access audited via WitnessCtl

---

### 4. Tool Runtime — 30+ MCP Tools, Zero Install

Relay exposes Connector's full MCP server to your function at `http://relay:9091/mcp`. Your function gets every tool with no import, no library, no config.

| Tool category | Examples |
|---|---|
| **Memory** | `memory__recall`, `memory__write`, `memory__ground` |
| **File** | `file__read`, `file__write`, `file__list` (policy-gated) |
| **Exec** | `exec__run` (policy-gated, risk-scored, admission-checked) |
| **Git** | `git__commit`, `git__diff`, `git__branch` (branch protection enforced) |
| **Search** | `search__web`, `search__docs` |
| **Agent** | `agent__signal`, `agent__spawn`, `agent__message` |
| **Audit** | `witness__record`, `witness__verify` |

Every tool call goes through the admission gate. High-risk calls (`exec__run` in production) are gated behind RBAC. Sensitive calls create WitnessCtl receipts automatically.

**What you get:**
- Your function has the full Connector toolset without shipping a single dependency
- Every tool call is governed — the tool can't be misused outside its policy scope
- Tools are available in any language that can make an HTTP call — Go, Rust, Python, TypeScript, Java, all the same

---

### 5. Tracing + Observability — Full Execution Graph

Every Relay invocation is a TraceTramp trace. The execution graph captures:

- Function start / end + duration
- Every LLM call with prompt hash, tokens, model, cost
- Every tool call with input, output, latency
- Every memory read/write with CIDs
- Every governance decision (ALLOW / DENY / HOLD)
- Every retry, fallback, error

**What you get:**
- Full execution graph in OpenTelemetry format — ship to Jaeger, Grafana, Datadog, any OTEL collector
- `trace_cid`: content-addressed trace — the trace itself is tamper-evident
- Replay: given a trace CID, re-run the invocation deterministically for debugging
- Anomaly detection: TraceTramp flags when function behavior deviates from baseline

```
relay trace show --id trace-sha256-3a4b...

Invocation: support-agent / 2026-04-19T23:41:02Z
├── LLM call: gpt-4o          42ms   1,243 tokens  $0.004   ALLOWED
├── Tool:    memory__recall    8ms    5 facts        —       ALLOWED
├── LLM call: gpt-4o          61ms   892 tokens     $0.003   ALLOWED
├── Tool:    mcp__file__read   3ms    2.4KB          —       HOLD → APPROVED
└── Response returned         114ms total            $0.007
```

---

### 6. Cost Tracking + Budget Gates — Per Function, Per Team

Every Relay function gets a LedgerLens cost entry. Every token, every tool call, every model — attributed to the function, the team, the developer.

**What you get:**
- Real-time cost dashboard: `support-agent` spent $4.20 today across 312 invocations
- Hard budget gates: function exceeds daily budget → LLM calls blocked, alert fired
- Cost anomaly alerts: "support-agent just spent 3x its rolling average in 10 minutes"
- Charge-back: per-team cost reports for internal billing
- Model cost optimization: Relay shows "80% of your calls could use `gpt-4o-mini` with the same quality score"

---

### 7. Governance + RBAC — Policy Without Rewriting

Relay enforces Connector's RBAC + DevGuard policy on every invocation. Your function runs under a role. The role determines what it can do.

```yaml
# relay.yaml — the only config you write
functions:
  - name: support-agent
    role: support-eng
    budget_daily_usd: 20.0
    allowed_models: [gpt-4o, gpt-4o-mini]
    tools:
      memory: [recall, write]
      file: []        # no file access
      exec: []        # no exec access

  - name: infra-agent
    role: platform-eng
    budget_daily_usd: 100.0
    allowed_models: [gpt-4o]
    tools:
      memory: [recall, write, ground]
      file: [read]
      exec: [run]     # exec allowed, gated by DevGuard risk score
    require_approval_above_risk: 70
```

**What you get:**
- `support-agent` literally cannot call `exec__run` — the admission gate blocks it, logs the attempt
- `infra-agent` exec calls above risk score 70 go to HITL approval queue
- New developer joins, their function inherits the role's limits — no per-function config needed
- SOC 2 evidence: every governance decision logged with reason code and policy version

---

### 8. Cryptographic Identity — Every Function Has a DID

Relay registers every function with AgentPassport on first deployment. The function gets a W3C DID and an HMAC-signed audit chain entry for every invocation.

**What you get:**
- `agent_did: did:connector:relay/support-agent` — verifiable identity, portable across systems
- Every invocation signed: `invocation_cid: inv-sha256-...` — you can prove what ran when
- Reputation score: functions that consistently pass governance thresholds build reputation
- Federation: share your function's DID with another Relay instance — cross-org agent collaboration

---

### 9. Multi-Function Orchestration — Without a Framework

Relay functions can signal each other via Conductor without any orchestration framework.

```bash
# Function A completes, triggers function B
relay signal --from support-agent --to escalation-agent --payload '{"ticket_id": "T-1234"}'
```

**What you get:**
- No LangGraph. No CrewAI. No AutoGen. No class inheritance, no graph definition.
- Event-driven function composition — functions are decoupled, signals are async
- Full trace across the signal boundary — the trace graph spans both functions
- Conductor handles retries, timeouts, failure routing

---

## Concrete Use Cases

### Enterprise Support Team (SaaS, 200 devs)
**Problem:** Team built a support agent in Python. Works fine in dev. In production: no idea what prompts it sends, no cost visibility, no way to prove to the CISO it doesn't leak customer data.

**With Relay:**
- `relay register --name support-agent --uri http://support:5000/run` — one command
- Change one env var in the existing code: `OPENAI_BASE_URL=http://relay:9091/v1`
- Immediately: every prompt audited, PII scrubbed before it leaves the cluster, LLM cost attributed to the support team's budget, full OTEL traces in Grafana
- Code: **unchanged**

**Output:** SOC 2 audit evidence ready in 48 hours. Team lead can see every LLM call in the dashboard. CISO approves the agent for customer-facing use.

---

### DevOps Automation Agent (Infra Team)
**Problem:** Infra team wrote a Go agent that reads Terraform plans and proposes changes. It works but sometimes proposes destroying production resources. No human-in-the-loop. No rollback.

**With Relay:**
- `relay register --name infra-agent --uri http://infra-agent:8080/plan`
- `relay.yaml`: `require_approval_above_risk: 70`, `exec: [run]`
- Every plan proposal scored by DevGuard risk engine
- Risk > 70 (touching `*.prod.*` Terraform resources): automatic HOLD → approval queue in Slack
- Risk < 70 (adding a read-only IAM role): ALLOW, logged, continues
- Full trace CID written to WitnessCtl for every plan

**Output:** Infra automation runs autonomously for 85% of changes. High-risk changes get human eyes. Zero production incidents from agent proposals.

---

### Polyglot Engineering Org (Go + Python + Rust + TypeScript)
**Problem:** 4 teams, 4 languages, each building agents. Each team is evaluating different memory stores, different observability tools, different governance approaches. No consistency, no cross-team visibility.

**With Relay:**
- Each team registers their endpoint — language doesn't matter
- All four get the same `OPENAI_BASE_URL` and `MCP_URL` — same Connector runtime
- All four appear in the same LedgerLens cost dashboard, same TraceTramp observability, same WitnessCtl audit store
- Memory is shared across teams via Engram knowledge sharing gates — legal agent's knowledge shared read-only with compliance agent

**Output:** One governance plane for four tech stacks. CTOs get one dashboard, one audit trail, one cost report. Teams keep their code exactly as-is.

---

### Regulated Financial Services (Compliance-Critical)
**Problem:** Fintech company wants to deploy an AI agent that reads client portfolios and drafts risk summaries. Legal says no until they can prove: (a) the model doesn't hallucinate numbers, (b) every draft is traceable to source data, (c) audit trail exists for every generation.

**With Relay + Engram:**
- Register the portfolio agent with `role: compliance` — no file write, no exec, memory read-only for `/k/portfolios/`
- Engram dehallucination chain: every claim in the draft checked against portfolio data before it's returned
- WitnessCtl: every draft has an immutable `invocation_cid` and `proof_cid` (grounding proof)
- HIPAA namespace: client PII stays in `/p/` namespace — never appears in LLM context

**Output:** Legal approves. Every draft is traceable. Regulators ask "what did the AI know when it wrote this?" — answered in seconds with a CID.

---

### AI-Native Startup (Moving Fast, Don't Want Lock-In)
**Problem:** Startup building fast. Used LangChain to prototype. Now 18 months in, it's a mess — LangChain version pinned at 0.1, upgrading breaks everything, LangSmith costs $800/mo, the CEO is asking why the AI costs are $40K/month with no breakdown.

**With Relay:**
- Wrap the LangChain chain in a single HTTP handler (one function, one `POST /run`)
- Register with Relay — all the LangChain internals are invisible to Relay
- Immediately: cost breakdown per agent, per model, per team — in LedgerLens
- LangChain stays as internal implementation detail — Relay is the governed surface
- When the team is ready to drop LangChain: swap the handler internals, Relay registration unchanged

**Output:** Cost visibility in day 1. Lock-in eliminated progressively. No big-bang rewrite.

---

## Why Use Relay Instead of Competitors

### vs LangChain / LangGraph

| | LangChain / LangGraph | Relay |
|---|---|---|
| **Adoption** | Full rewrite required — your logic restructured around their graph primitives | Zero rewrite — register your existing endpoint |
| **Language** | Python only | Any language with an HTTP server |
| **Governance** | None built-in — you build it or skip it | RBAC, budget gates, admission gate, HITL — all from `relay.yaml` |
| **Observability** | LangSmith — only sees LangChain calls, $800/mo | TraceTramp — all calls, all languages, self-hosted free |
| **Migration path** | Locked in. LangChain → LangGraph documented at 6–12 months | No migration ever needed — your code is the logic, Relay is the runtime |
| **Memory** | `ConversationBufferMemory` dies with the process | Persistent, namespace-isolated, entropy-scored memory via Engram |
| **Audit trail** | None | Cryptographic, CID-addressed, SOC 2 ready |

**LangChain made framework the product. Relay makes your code the product.**

---

### vs OpenFaaS

OpenFaaS is an excellent serverless function runtime. It is completely LLM-blind.

| | OpenFaaS | Relay |
|---|---|---|
| **LLM routing** | None — you wire it yourself | Multi-provider, fallback, semantic cache |
| **Token budgets** | None | Hard per-function budget gates |
| **Memory** | None | Connector memory kernel / Engram |
| **Governance** | None | RBAC, DevGuard policy, admission gate |
| **Audit** | Basic invocation logs | Cryptographic full-trace, WitnessCtl receipts |
| **Agent identity** | None | AgentPassport DID per function |
| **Setup overhead** | Docker + K8s + container build per function | HTTP endpoint + one `relay register` command |

OpenFaaS answers "did my function run?" Relay answers "what did my agent do, is it allowed, what did it cost, and can I prove it?"

---

### vs OpenClaw (250K stars)

OpenClaw is the most popular personal agent assistant today. It's a personal tool.

| | OpenClaw | Relay |
|---|---|---|
| **Multi-tenancy** | Single user | Full org hierarchy, teams, roles |
| **RBAC** | None | Per-function roles, per-model access |
| **Enterprise auth** | None | SSO/OIDC (Okta, Google, Azure AD) |
| **Budget control** | None | Per-function daily/monthly budget gates |
| **Audit trail** | None | Cryptographic, compliance-ready |
| **Cold start** | 5.98 seconds | <50ms (no container spin-up) |
| **Your own service** | Can't register existing HTTP services | First-class — any HTTP endpoint |
| **HIPAA / SOC 2** | None | Built-in PHI firewall, compliance controls |

**OpenClaw for your personal AI. Relay for your company's AI.**

---

### vs OpenFang (Rust, 137K LOC)

OpenFang is the most technically impressive personal agent OS. It's also personal-use.

| | OpenFang | Relay |
|---|---|---|
| **Register your own service** | Hands are pre-built packages only — can't register your existing HTTP service | First-class — any language, any HTTP endpoint |
| **Enterprise RBAC** | None | Full role-based access per function |
| **Org-level policy** | None | DevGuard policy (`relay.yaml`), per-team rules |
| **Compliance** | None | HIPAA, SOC 2, cryptographic audit |
| **Your existing code** | Must repackage as a Hand | Unchanged — two env vars |
| **Memory governance** | Basic | Engram: entropy, dehallucination, CoT Anchor |
| **Stability** | Pre-1.0, breaking changes between minors | Connector kernel in production Rust 2+ years |

**OpenFang is impressive engineering. Relay is what enterprises actually need.**

---

### vs CrewAI / AutoGen

Both require you to define agents as Python classes, import their SDK, and structure your code around their primitives.

- **CrewAI** hits a wall at 6–12 months in production: no budget control, no RBAC, no determinism
- **AutoGen** is research-grade: no budget enforcement, no HITL, no compliance

Neither can govern a function written in Go. Neither has a compliance audit trail. Neither has persistent memory with entropy management. Both disappear when you restart the process.

**These tools help you build agents. Relay helps you run them in production.**

---

### vs Helicone / LangSmith (Observability-only)

Helicone and LangSmith observe LLM calls. They do not govern them.

- Helicone sees the prompt and response. It cannot block a call, enforce a budget, redact a secret, or approve a high-risk action.
- LangSmith only sees LangChain calls. A Go service calling OpenAI directly is invisible.
- Neither has memory, tools, identity, or compliance controls.

**Observability is one feature. Relay is the runtime.**

---

## The One-Line Summary for Every Buyer

| Buyer | What they tell their team |
|---|---|
| **Developer** | "Register your endpoint, set two env vars — you get LLM routing, memory, tools, tracing, cost tracking. Your code doesn't change." |
| **Engineering Manager** | "Every agent in every language on one governance plane. One dashboard. One cost report." |
| **Platform Engineer** | "No framework migrations. No LangChain lock-in. Swap the runtime, keep the logic." |
| **CISO** | "Every agent function has a DID, every invocation has a signed receipt, every high-risk call requires approval. That's your SOC 2 evidence." |
| **CTO** | "We dropped LangChain, LangSmith, Helicone, and three internal libraries. Relay replaced all of them. Bill went from $40K to $12K because we can finally see where tokens go." |
