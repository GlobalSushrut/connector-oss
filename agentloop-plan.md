# AgentLoop — Cloudflare for the Agentic Web

> **The global agent mesh. DNS, proxy, workers, and observability — for the infrastructure layer of AI.**

One network. Every agent. Powered by ConnectorOS.

---

## 0. The New Vision (supersedes previous framing)

The previous framing (PromptForge + ReplayLab + FleetHelm) described the **observability layer**. That is still valid — it becomes Layer 4 (Optimize) of AgentLoop. But the deeper product is the **infrastructure layer** beneath it.

**AgentLoop is to AI agents what Cloudflare is to the web.**

Cloudflare solved: "every web request needs routing, protection, caching, and compute — at global scale, with one line of config." AgentLoop solves: "every agent call needs routing, policy enforcement, discovery, and auditability — at global scale, with one line of config."

```
# Before AgentLoop — agents hardcode each other:
response = requests.post("http://10.0.1.44:8080/run", ...)

# After AgentLoop — agents route through the mesh:
response = agentloop.call("agent://summarizer.v2.acme", ...)
# → DNS resolution → policy check → proxy → target agent → receipt
```

That one-line change gives you: global routing, health-aware failover, policy enforcement at every hop, cryptographic receipts, cost tracking, and full observability. No code changes to the agents themselves.

---

## 1. The Problem Nobody Has Infrastructure For

AI agents in 2026 are where microservices were in 2015:

- Agents **hardcode endpoints** to each other — coupling that breaks on every deploy
- No **service discovery**: when agent-B moves hosts, agent-A breaks
- No **health-aware routing**: failed agents still receive traffic
- No **policy at every hop**: security teams have zero visibility into agent-to-agent calls
- No **standard protocol**: A calls B by HTTP, C calls D by custom socket, E uses gRPC
- No **edge compute**: logic that should run near the data runs in a central server
- **No DNS for agents**: there is no `agent://` address space

This is exactly the problem Cloudflare solved for the web in 2010 — and the exact gap in the agentic infrastructure stack today.

---

## 2. What AgentLoop Is

**AgentLoop is the Cloudflare for the agentic web.**

It is the network infrastructure layer between AI agents — providing the same primitives Cloudflare provides for HTTP traffic, rebuilt natively for the semantics of agent workloads.

| Cloudflare (web) | AgentLoop (agents) |
|---|---|
| Anycast DNS | **Agent DNS** — `agent://name.version.team` resolves to live endpoint + capabilities |
| Edge Proxy (reverse proxy) | **Agent Proxy** — all agent traffic routes through the mesh |
| Cloudflare Workers | **Agent Workers** — stateless edge compute triggered by agent events |
| Tunnel (cloudflared) | **Agent Tunnel** — connect private agents without opening firewall ports |
| Zero Trust / Access | **Agent Identity + mTLS** — mutual auth, UCAN capability delegation between agents |
| Load Balancer | **Agent Router** — health-aware routing, weighted traffic, failover |
| WAF | **Agent Policy Engine** — Conductor cage policies enforced at every mesh hop |
| R2 / KV / D1 | **Agent Context Store** — shared KV, embeddings cache, artifact storage |
| Analytics Engine | **Agent Telemetry** — per-hop latency, cost, error rate, token usage |
| CDN / Cache | **Context Cache** — avoid redundant LLM calls for identical agent context |

Powered by ConnectorOS as the control plane / kernel underneath every layer.

---

## 3. The Four Infrastructure Layers

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
│  │  Stateless functions · MCP-native · triggered by events      │ │
│  │  Deploy in seconds · appear in DNS automatically             │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 2 — Agent Mesh (Proxy + Routing)                      │ │
│  │  Policy at every hop · mTLS · circuit breaking · retries     │ │
│  │  Health checks · weighted routing · canary shifting          │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Layer 1 — Agent DNS (Discovery + Registry)                  │ │
│  │  agent:// address space · AgentCard serving · version routing│ │
│  │  A2A protocol · MCP endpoint registration · DID support      │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ HTTP only
┌──────────────────────────────────▼───────────────────────────────┐
│                    ConnectorOS (Kernel)                           │
│  CID chains · policy · UCAN auth · receipts · history · billing  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Layer 1 — Agent DNS

### The Problem
Agents today call each other by IP or hostname. This is equivalent to web browsers using IP addresses instead of domain names. It breaks on every deploy, every scale event, every region migration.

### The Solution: `agent://` address space

AgentLoop introduces a hierarchical, version-aware agent address namespace:

```
agent://summarizer.v2.medical-team.acme-corp
    └── name: summarizer
    └── version: v2 (or: latest, stable, canary)
    └── team: medical-team
    └── org: acme-corp (or: *.agentloop.net for SaaS)
```

**Resolution returns an AgentCard** — a structured JSON document (A2A protocol compatible) that describes:
- Live endpoint URL(s) with health status
- Supported input/output schemas
- MCP capabilities (what tools this agent exposes)
- Required authentication (API key, UCAN capability)
- Rate limits and cost estimates
- SLO commitments

### Version Routing Policies

| Policy | What happens |
|---|---|
| `agent://name.latest` | Routes to highest version with `approved` status |
| `agent://name.stable` | Routes to latest version tagged `stable` |
| `agent://name.v3`     | Routes to exactly version 3, returns 404 if not registered |
| `agent://name.canary` | Routes X% of traffic to treatment, rest to control |
| `agent://name.blue`   | Blue/green: switch entire traffic with one command |

### Protocols Supported
- **A2A (Agent-to-Agent)** — Google-led open standard; AgentCard is the A2A capability manifest
- **MCP (Model Context Protocol)** — agents registered in AgentLoop DNS can expose MCP tools natively
- **DID (W3C Decentralized Identifiers)** — optional cryptographic identity anchoring
- **Plain HTTP** — any agent callable by HTTP can register; no SDK required

---

## 5. Layer 2 — Agent Mesh (Proxy + Routing)

### What it is
Every agent-to-agent call routes through the mesh proxy instead of directly. This is the Envoy/Istio model — but without the sidecar complexity, because agents already have an API surface.

```
Agent A  →  agentloop.call("agent://summarizer.v2.acme", payload)
              │
              ▼  AgentLoop Mesh Proxy
              ├── 1. Resolve DNS → endpoint
              ├── 2. Load cage policy (from Conductor)
              ├── 3. Evaluate policy — DENY or ALLOW
              ├── 4. mTLS + UCAN capability check
              ├── 5. Route to healthy instance (weighted LB)
              ├── 6. Retry on 5xx (3 attempts, exponential backoff)
              ├── 7. Record hop: latency, status, tokens, cost
              ├── 8. HMAC-chain receipt (CID-linked)
              └── 9. Return response to Agent A
```

### Features at every hop
- **Circuit breaking** — opens after N consecutive failures, half-opens after cooldown
- **Mutual TLS** — agent identity verified on both sides of every call
- **UCAN capability check** — Agent A must possess a valid delegated capability to call Agent B
- **Cage policy enforcement** — Conductor cage policies checked before forwarding
- **Weighted routing** — `60% → v2, 40% → v3` for gradual migration
- **Health-aware failover** — dead instances removed from routing table within seconds
- **Context propagation** — `X-Agent-Request-ID` and `X-CID-Chain` forwarded across hops

### The Decentralized Architecture
"Decentralized" in AgentLoop means **operationally distributed, not blockchain**:
- Mesh proxy nodes can run anywhere — cloud, on-prem, edge
- Agents join the mesh by registering with any node; registration propagates to all nodes
- No single mesh node is a SPOF — routing tables are eventually-consistent across nodes
- An enterprise can run a private mesh that peers with the global AgentLoop network
- Like Cloudflare's anycast — the mesh routes to the nearest healthy proxy automatically

---

## 6. Layer 3 — Agent Workers

### What they are
Agent Workers are **stateless, event-driven compute units** that run at the mesh edge — like Cloudflare Workers but for agent workloads. They execute a single task, return a result, and disappear.

### Why they matter
Current agent infrastructure requires a full server per agent. Workers let you:
- Deploy a new agent capability in seconds (one function, no server)
- Run logic before requests reach the target agent (pre-processing, auth, transformation)
- Handle agent-triggered events (webhooks, schedule triggers, A2A events)
- Expose MCP tools without standing up a full agent server

### Worker types

| Type | Trigger | Example |
|---|---|---|
| **Request Worker** | Incoming mesh request | Validate + transform input before forwarding |
| **Response Worker** | Outgoing mesh response | Redact PII before returning to caller |
| **Event Worker** | Agent event (drift, SLO breach, new run) | Notify Slack on SLO breach |
| **Schedule Worker** | Cron expression | Nightly cost report, daily regression test |
| **A2A Worker** | A2A capability call from another agent | Expose a tool via the MCP protocol |
| **Tunnel Worker** | Incoming tunnel connection | Bridge a private agent into the mesh |

### Worker runtime
- Workers are stored as JSON-serialized configs with a callable HTTP endpoint or inline script reference
- Invocations are logged with latency, status, and output hash
- Workers register in DNS automatically — `agent://worker-name.workers.team`
- Workers can call other agents through the mesh (they are themselves mesh participants)

---

## 7. Agent Tunnel

For enterprises with private agents that cannot be exposed publicly:

```
Private cloud          AgentLoop mesh
┌─────────────┐        ┌─────────────────────────────┐
│ Agent-B     │←───────│  Tunnel endpoint             │
│ (no public  │        │  agent://agent-b.private.acme│
│  IP, behind │        │                              │
│  firewall)  │────────│  Persistent outbound conn    │
└─────────────┘        └─────────────────────────────┘
```

Agent-B establishes an outbound tunnel connection to AgentLoop. The mesh then routes `agent://agent-b.private.acme` traffic through the tunnel — no firewall rules, no public IPs, no VPN. Like `cloudflared` but for agents.

---

## 8. Layer 4 — Observability (Design · Ship · Debug · Optimize)

The original AgentLoop plan (PromptForge + ReplayLab + FleetHelm) is fully preserved as the observability and lifecycle management layer. Because every agent call now routes through the mesh, observability is automatic — no SDK instrumentation required.

| Module | What it provides |
|---|---|
| **Design** | Prompt registry, versioning, lint, approval workflow, golden datasets |
| **Ship** | A/B experiments, statistical significance, auto-promote, canary rollout, rollback |
| **Debug** | Timeline, run detail, run-vs-run diff, deterministic replay, first-divergence highlighter |
| **Optimize** | Fleet view, SLOs, drift detection, rightsizing recommendations, cost forecast, savings tracker |

**The mesh makes observability zero-config.** Every call through the proxy is already captured. No agent code changes, no SDK, no manual instrumentation. Layer 4 is just a UI over what the mesh already records.

---

## 9. The Simple Use Case

> "Register your agents. They call each other by name. You see everything."

```bash
# 1. Register an agent (one-time):
curl -X POST https://mesh.agentloop.net/api/v1/dns/register \
  -d '{ "name": "summarizer", "version": "v2", "team": "medical", "endpoint": "http://10.0.1.44:8080" }'

# 2. Call it from any other agent:
agentloop.call("agent://summarizer.v2.medical", { "text": "..." })

# 3. That's it. You now have:
# ✓ DNS-based discovery (no hardcoded IPs)
# ✓ Policy enforcement (cage policies from Conductor)
# ✓ Health-aware routing (automatic failover)
# ✓ HMAC-chained receipt (tamper-evident audit)
# ✓ Cost + latency tracking (per hop)
# ✓ Full replay capability (Debug module)
```

---

## 10. ConnectorOS as the Kernel

AgentLoop does not re-implement policy, receipts, CID chains, or billing. ConnectorOS provides all of this. AgentLoop is the **network layer** on top of the **OS layer**:

```
AgentLoop (network)       ConnectorOS (OS / kernel)
──────────────────        ──────────────────────────
DNS resolution      ←──── Agent registry + identity
Mesh routing        ←──── Policy engine + cage rules
Worker invocations  ←──── Admission gate + content firewall
Tunnel auth         ←──── UCAN capability verification
Hop receipts        ←──── CID-chained history + HMAC receipts
Cost tracking       ←──── Billing + token metering
```

Every decision AgentLoop makes is backed by ConnectorOS primitives. There is no separate policy engine — it delegates to Conductor/ConnectorOS at every step.

---

## 11. Build Order (Revised)

### Phase 0 — Agent DNS + Registry (weeks 1-2)
The address space. Everything else depends on this.
- `al_agent_endpoints` table — multiple live endpoints per agent
- `al_dns_records` table — name resolution + version policies
- `POST /api/v1/dns/register` — register an agent endpoint
- `GET /api/v1/dns/resolve/:name` — resolve to live endpoints + AgentCard
- `GET /api/v1/dns/lookup/:name` — full AgentCard with capabilities

**Ships: agents can register and discover each other.**

### Phase 1 — Agent Mesh Proxy (weeks 3-5)
The routing engine.
- `POST /api/v1/mesh/call` — proxy a call through the mesh
- Policy check (Conductor cage), mTLS, weighted routing, health checks
- Per-hop receipt + HMAC chain
- Circuit breaker per target

**Ships: all agent traffic routes through AgentLoop with policy + receipts.**

### Phase 2 — Agent Workers (weeks 6-8)
Edge compute.
- `al_workers` table — worker definitions + triggers
- `POST /api/v1/workers` — register a worker
- Worker invocation engine (request/response/event/schedule types)
- Workers register in DNS automatically

**Ships: agents deploy logic at the edge without a server.**

### Phase 3 — Debug module (weeks 9-11)
Observability wedge.
- Timeline, run detail, diff, replay (already coded)
- Wired to mesh hop logs — zero-config, automatic

**Ships: first paying customers — "show me my broken run."**

### Phase 4 — Design + Ship modules (weeks 12-16)
Prompt lifecycle.
- Prompt registry, versions, lint, approval (already coded)
- Experiments, A/B, canary (already coded)
- Ship's canary connects to DNS layer — canary traffic split is a DNS policy

**Ships: full prompt lifecycle. Enterprise conversations start.**

### Phase 5 — Optimize + Tunnel (weeks 17-22)
Fleet intelligence + private connectivity.
- SLOs, drift, recommendations, savings (already coded)
- Agent Tunnel for private deployment
- Cross-module provenance (prompt → run → fleet)

**Ships: full platform. Infrastructure + observability unified.**

---

## 12. Competitive Positioning

| Capability | AgentLoop | LangSmith | Istio/Envoy | Cloudflare | AWS App Mesh |
|---|---|---|---|---|---|
| Agent DNS (`agent://`) | ✅ | ○ | ○ | ○ | ○ |
| A2A protocol support | ✅ | ○ | ○ | ○ | ○ |
| Agent mesh proxy | ✅ | ○ | partial (HTTP only) | ○ | partial |
| Policy at every hop (cage) | ✅ | ○ | partial (authz only) | partial | ○ |
| Agent Workers (edge compute) | ✅ | ○ | ○ | ✅ (web only) | ○ |
| Agent Tunnel (private) | ✅ | ○ | ○ | ✅ (web only) | partial |
| CID-chained receipts | ✅ | ○ | ○ | ○ | ○ |
| Deterministic replay | ✅ | partial | ○ | ○ | ○ |
| Prompt registry + experiments | ✅ | ✅ | ○ | ○ | ○ |
| ConnectorOS kernel integration | ✅ | ○ | ○ | ○ | ○ |
| Self-hosted + on-prem mesh | ✅ | partial | ✅ | ○ | partial |

**The gap**: Cloudflare doesn't understand agents. Istio doesn't understand LLMs. LangSmith doesn't do routing or DNS. Nobody provides the full stack: DNS + Mesh + Workers + Observability, agent-native, cryptographically receipted.

---

## 13. Pricing — Infrastructure Model

Not seat-based. Infrastructure-based — like Cloudflare.

| Tier | Price | What's included |
|---|---|---|
| **Free** | $0 | 3 agents, 10K mesh calls/mo, 1 worker, Debug read-only |
| **Starter** | $49/mo | 20 agents, 500K mesh calls/mo, 10 workers, full Debug |
| **Team** | $299/mo | Unlimited agents, 5M calls/mo, unlimited workers, Design + Ship |
| **Platform** | $999/mo | All modules, private mesh node, Tunnel, SLAs |
| **Enterprise** | Custom | On-prem mesh, custom DNS zone, SOC2, dedicated support |

**Usage-based overage**: $0.10 per 10K mesh calls above plan. Aligns incentives — we grow when customers grow.

---

## 14. The Moat (Three Layers)

1. **Kernel moat** — CID chains, UCAN auth, policy receipts from ConnectorOS. No competitor can replicate without rebuilding years of ConnectorOS infrastructure.

2. **Network moat** — once agents are registered in AgentLoop DNS, ripping it out means renaming every `agent://` call across every codebase. Like migrating off DNS. Nobody does that.

3. **Data moat** — every hop through the mesh builds the most complete dataset of agent behavior ever assembled. Drift detection, rightsizing, anomaly detection — they all improve as more agents route through the network. Network effects compound.

---

## 15. One-Line Positioning

> **AgentLoop is Cloudflare for AI agents. Register. Route. Enforce. Observe. On one mesh, with one line of config.**
