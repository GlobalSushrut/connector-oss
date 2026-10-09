# Connector + DevGuard: Enterprise AI Agent Governance Platform

## Executive Summary

**The Problem**: Nobody can audit what their AI coding agents are doing. Enterprises have 10–50+ developers running Windsurf, Cursor, Claude Code, Copilot, and custom agentic workflows with zero visibility into decisions made, code generated, commands executed, or data accessed. This is **shadow AI at the code layer** — the most dangerous place it can exist.

**Market proof**:
- AI Governance market: **$2.2B in 2025 → $11B by 2036** (15.8% CAGR) — [Future Market Insights]
- Gartner: **40% of enterprise apps will feature AI agents by end of 2026** (up from <5% in 2025)
- **37% of organizations** already adjusting security strategy due to AI threats — [Netwrix 2025]
- $4.4B in AI-related compliance failures in 2025 alone
- SOC 2, HIPAA, GDPR all **require audit trails of AI agent actions** — no current tool provides this for coding agents

**The Product**: Connector as an **API proxy + management plane** that sits between every coding agent (Windsurf, Cursor, Claude Code, Aider, custom) and their LLM providers. Teams configure their own LLM keys, RBAC, and logging. Connector intercepts every LLM call, enforces policy, creates the audit trail, and provides a governance dashboard.

**Unique differentiator**: Not just observability (Helicone does that). Not just routing (LiteLLM does that). Connector provides **physical enforcement** — agents literally cannot bypass policy because all LLM traffic flows through Connector.

---

## 1. Internal Research: What Connector Already Has

### 1.1 Existing Capabilities (production-ready)

| Capability | Status | Location |
|---|---|---|
| **OpenAI-compatible gateway** | ✅ Live | `POST /v1/chat/completions` — drop-in replacement for any OpenAI SDK |
| **Anthropic Messages API** | ✅ Live | `POST /v1/messages` — Claude Code integration |
| **LLM router** | ✅ Live | Multi-provider routing (OpenAI, Anthropic, Ollama, custom) |
| **Admission gate** | ✅ Live | Pre-execution security: quarantine, injection detection, content firewall |
| **Auth + RBAC** | ✅ Live | JWT auth, API keys, SSO/OIDC (Okta, Google, Azure AD, GitHub), role-based access |
| **Billing + metering** | ✅ Live | Per-token usage tracking, tier limits (Community/Pro/Team/Enterprise), Stripe |
| **Audit log** | ✅ Live | Every LLM call logged with tokens, cost, model, agent, timestamp |
| **Agent cost ledger** | ✅ Live | Per-agent running total: cost, tokens, calls, model breakdown |
| **MCP server** | ✅ Live | Full MCP protocol with 30+ tools (memory, exec, file, DevGuard) |
| **Secret store** | ✅ Live | Encrypted secret management, key rotation |
| **Content firewall** | ✅ Live | Injection detection, hallucination safety, grounding |
| **HIPAA/SOC2 controls** | ✅ Live | PHI sanitization, compliance logging, BAA support |
| **Agent lifecycle** | ✅ Live | Register, start, suspend, quarantine, terminate |
| **Webhooks** | ✅ Live | Event delivery with retry, dedup, templates |
| **Payment (Stripe)** | ✅ Live | Checkout, portal, metered billing |
| **Dashboard UI** | ✅ Live | Leptos-based management plane |
| **UCAN capabilities** | ✅ Live | Issue, delegate, revoke, verify fine-grained capabilities |

### 1.2 DevGuard (application on top of Connector)

| Capability | Status |
|---|---|
| Policy engine (devguard.yaml) | ✅ Role-based file/exec/git/secret/budget rules |
| Risk scoring (0–100) | ✅ File, command, git, secret risk assessment |
| Enforcement verdicts | ✅ ALLOW, DENY, HOLD, NEEDS_APPROVAL |
| Session management | ✅ Per-agent governed sessions with role binding |
| Server-side gateway enforcement | ✅ Wired into OpenAI, Anthropic, MCP dispatch paths |
| OS-level cage | ✅ File watchdog, git hooks, chmod, exec wrapper |
| Adapters | ✅ Windsurf, Cursor, Claude Code, Aider, generic |
| Audit trail | ✅ Every file/exec/git/secret action logged |
| Approval engine | ✅ HITL approval flow for sensitive operations |

### 1.3 Architecture (correct separation)

```
┌──────────────────────────────────────────────────────────┐
│  Connector OS (standalone, no DevGuard dependency)       │
│  ┌─────────┐ ┌──────────┐ ┌───────┐ ┌───────────────┐  │
│  │ Gateway  │ │ Admission│ │ Audit │ │ Auth + RBAC   │  │
│  │ (LLM    │ │ Gate     │ │ Log   │ │ SSO, API keys │  │
│  │  proxy) │ │          │ │       │ │               │  │
│  └─────────┘ └──────────┘ └───────┘ └───────────────┘  │
│  ┌─────────┐ ┌──────────┐ ┌───────┐ ┌───────────────┐  │
│  │ Billing │ │ MCP Srv  │ │Firewall│ │ Memory Kernel │  │
│  └─────────┘ └──────────┘ └───────┘ └───────────────┘  │
└──────────────────────────────────────────────────────────┘
        ↑ HTTP API only — no linking
┌──────────────────────────────────────────────────────────┐
│  DevGuard (application, policy engine)                   │
│  ┌─────────┐ ┌──────────┐ ┌───────┐ ┌───────────────┐  │
│  │ Policy  │ │ Risk     │ │ Cage  │ │ Adapters      │  │
│  │ Engine  │ │ Engine   │ │ (OS)  │ │ (Windsurf etc)│  │
│  └─────────┘ └──────────┘ └───────┘ └───────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Market Analysis: The Pain

### 2.1 The Shadow AI Problem

Every enterprise has developers using coding agents (Windsurf, Cursor, Claude Code) with **zero governance**:

- **No audit trail**: CTOs cannot answer "what code did the AI write last Tuesday?"
- **No RBAC**: An intern's agent has the same access as a principal engineer's
- **No cost control**: Teams discover $50K LLM bills with no accountability
- **No compliance**: SOC 2 auditors ask for AI decision logs — nothing exists
- **No secret protection**: Agents can read `.env`, API keys, credentials
- **No policy**: Any agent can modify production configs, Terraform, Dockerfiles

### 2.2 Competitive Landscape

| Product | What they do | What they DON'T do |
|---|---|---|
| **LiteLLM** | Multi-provider routing, unified API | No RBAC, no file/exec governance, no agent awareness |
| **Helicone** | LLM observability, cost tracking | No enforcement, no policy, no coding agent control |
| **Portkey** | Routing + fallback + cost tracking | No file/exec audit, no RBAC, no agent governance |
| **MintMCP** | MCP gateway + LLM proxy | Focused on MCP servers, not coding agent policy enforcement |
| **TrueFoundry** | Full MLOps platform + gateway | Heavy, focused on model deployment, not coding agent governance |
| **Kong AI** | API gateway with AI plugins | Generic API gateway, not agent-aware |

**Gap in the market**: Nobody provides **coding agent governance** — the combination of:
1. LLM proxy with audit trail
2. File/exec/git policy enforcement
3. Role-based access control per agent
4. Secret protection
5. Cost control per developer/role
6. OS-level cage (physical enforcement)

### 2.3 Target Customers

| Segment | Pain | Willingness to pay |
|---|---|---|
| **Enterprise engineering teams** (500+ devs) | Compliance, audit, shadow AI | $299-999/mo per team |
| **Regulated industries** (fintech, healthtech) | HIPAA, SOC 2, GDPR | $999-5000/mo |
| **Security-conscious startups** (Series A+) | IP protection, cost control | $49-299/mo |
| **AI-native companies** | Agent fleet management | $299-999/mo |
| **Government/defense** | Classification, clearance-based access | Custom enterprise |

---

## 3. Product Plan: Connector as Enterprise AI Agent Proxy

### 3.1 The Entry Point

The **single setup change** for any team:

```bash
# Before (unmonitored):
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://api.openai.com/v1

# After (fully governed):
export OPENAI_API_KEY=cpk_live_...     # Connector-issued key
export OPENAI_BASE_URL=http://connector:9091/v1  # Connector proxy
```

That's it. Every OpenAI/Anthropic SDK, every coding agent (Windsurf, Cursor, Claude Code, Aider) — they all support `base_url` override. One environment variable change gives the enterprise:
- Full audit trail of every LLM call
- RBAC enforcement
- Cost tracking per developer/team
- Secret redaction
- Injection detection
- Budget gates

### 3.2 Two-Port Architecture

| Port | Purpose | Users |
|---|---|---|
| **`:9091`** (API Gateway) | LLM proxy + MCP server + agent traffic | Coding agents (Windsurf, Cursor, etc.) |
| **`:9092`** (Management Plane) | Dashboard, config, RBAC, audit viewer, billing | Team leads, security, CTO |

### 3.3 User Workflow

```
1. Admin deploys Connector (Docker / binary / cloud)
2. Admin opens Management Plane (:9092)
   → Configures upstream LLM providers (OpenAI, Anthropic, Ollama, Azure)
   → Sets up RBAC roles (intern, dev, senior, lead, admin)
   → Configures DevGuard policy (devguard.yaml)
   → Generates API keys per developer (cpk_live_...)
   → Sets logging destination (S3, Elasticsearch, local)
3. Developers update their environment:
   → OPENAI_API_BASE=http://connector:9091/v1
   → OPENAI_API_KEY=cpk_live_<their-key>
4. Everything flows through Connector:
   → Every LLM call → audited, policy-checked, cost-tracked
   → Every tool call (MCP) → file/exec policy enforced
   → Every secret → redacted before reaching LLM
   → Every budget limit → enforced at the proxy
```

### 3.4 Feature Roadmap

#### Phase 1: Core Proxy (weeks 1–2) — MOSTLY DONE
- [x] OpenAI-compatible gateway (`/v1/chat/completions`)
- [x] Anthropic Messages API (`/v1/messages`)
- [x] LLM routing (multi-provider, fallback)
- [x] Auth + API keys
- [x] Audit log (every call)
- [x] Cost tracking per agent/user
- [x] Admission gate (injection, quarantine)
- [x] HIPAA/SOC2 controls
- [ ] Management plane UI for LLM provider config (partial — needs self-service)
- [ ] Per-developer API key management UI
- [ ] Logging destination config (S3, ELK, etc.)

#### Phase 2: Agent Governance (weeks 3–4) — IN PROGRESS
- [x] DevGuard policy engine (devguard.yaml)
- [x] Server-side enforcement in gateway
- [x] Server-side enforcement in MCP dispatch
- [x] File/exec/git/secret policy
- [x] Risk scoring
- [x] OS-level cage (watchdog, git hooks, chmod)
- [ ] Per-developer role assignment in management UI
- [ ] Real-time agent activity dashboard
- [ ] Alert rules (notify on DENY, cost threshold, anomaly)

#### Phase 3: Enterprise (weeks 5–8)
- [ ] SSO/SAML integration for developer onboarding
- [ ] Team/organization hierarchy
- [ ] Compliance report export (SOC 2, HIPAA, ISO 27001)
- [ ] Custom model endpoint management (Ollama, vLLM, Azure)
- [ ] Log shipping to customer infrastructure (S3, Splunk, Datadog)
- [ ] Terraform provider for policy-as-code
- [ ] GitHub Actions integration (CI/CD policy gates)
- [ ] Multi-cell deployment (regional)

#### Phase 4: Scale (weeks 9–12)
- [ ] High-availability clustering
- [ ] SDK for custom agent integration
- [ ] Marketplace for policy templates
- [ ] AI-powered anomaly detection in agent behavior
- [ ] Token budget optimization recommendations
- [ ] Automated compliance evidence collection

---

## 4. Pricing Strategy

| Tier | Price | Includes |
|---|---|---|
| **Community** | Free | 3 agents, 10K tokens/day, 30-day audit retention, single user |
| **Pro** | $49/mo | 20 agents, 500K tokens/mo, 1-year audit, cost dashboard |
| **Team** | $299/mo | Unlimited agents, 5M tokens/mo, RBAC, HIPAA BAA, SSO, webhook alerts |
| **Enterprise** | Custom | Unlimited everything, on-prem, SOC 2 report, dedicated support, SLA |

Revenue model: **usage-based metered billing** (base + per-1K tokens above plan) via Stripe — already built.

---

## 5. Go-to-Market

### 5.1 Positioning

> **"The control plane for AI coding agents."**
>
> Connector gives CTOs complete visibility and control over every AI agent in their engineering org. One environment variable change. Full audit trail. Enforceable policy. No code changes.

### 5.2 Key Messages

1. **For CTOs/CISOs**: "Know exactly what every AI coding agent does. SOC 2 audit-ready in minutes."
2. **For Engineering Managers**: "Control costs. $50K surprise LLM bills become $5K governed spend."
3. **For Security Teams**: "No more shadow AI. Every prompt, every tool call, every file access — logged and governed."
4. **For Developers**: "Keep using Windsurf/Cursor/Claude. Just change one env var. Same workflow, full protection."

### 5.3 Distribution

1. **Self-serve**: `curl -sSL install.connector.ai | bash` → Docker container, immediate value
2. **GitHub/HN launch**: Open-source core proxy, enterprise features paid
3. **Integrations**: Windsurf Extension, Cursor plugin, VS Code extension
4. **Partner**: Cloud marketplace (AWS, GCP, Azure)

---

## 6. Technical Differentiators vs Competition

| Feature | Connector | LiteLLM | Helicone | Portkey | MintMCP |
|---|---|---|---|---|---|
| OpenAI-compatible proxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| Anthropic proxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| Multi-provider routing | ✅ | ✅ | ○ | ✅ | ○ |
| File/exec policy enforcement | ✅ | ○ | ○ | ○ | ○ |
| RBAC per developer/role | ✅ | ○ | ○ | ○ | ○ |
| Secret redaction in prompts | ✅ | ○ | ○ | ○ | ○ |
| Git branch protection | ✅ | ○ | ○ | ○ | ○ |
| OS-level cage (physical) | ✅ | ○ | ○ | ○ | ○ |
| Injection detection | ✅ | ○ | ○ | ○ | ○ |
| Agent quarantine (auto) | ✅ | ○ | ○ | ○ | ○ |
| HIPAA/SOC2 controls | ✅ | ○ | ○ | ○ | ○ |
| MCP server governance | ✅ | ○ | ○ | ○ | ✅ |
| Cost tracking per agent | ✅ | ✅ | ✅ | ✅ | ○ |
| Budget gates (hard limit) | ✅ | ○ | ○ | ○ | ○ |
| Audit export (compliance) | ✅ | ○ | ✅ | ○ | ✅ |
| Self-hosted / on-prem | ✅ | ✅ | ✅ | ✅ | ○ |
| Memory kernel (agent state) | ✅ | ○ | ○ | ○ | ○ |
| Agent economy (escrow/pricing) | ✅ | ○ | ○ | ○ | ○ |

**Connector's moat**: It's not just a proxy. It's an **operating system for AI agents** with memory, governance, economy, and compliance built in. Competitors would need to rebuild years of infrastructure to match.

---

## 7. Risk & Mitigation

| Risk | Mitigation |
|---|---|
| Latency overhead | Gateway adds <10ms (in-memory admission, no external calls) |
| Provider lock-in | Standard OpenAI/Anthropic API format — zero vendor lock-in |
| Adoption friction | One env var change. No code changes. Works with existing tools. |
| Open-source competition | LiteLLM is routing-only. No governance = no enterprise sale. |
| Compliance complexity | Templates (HIPAA, SOC 2, Financial) built-in. Not from scratch. |

---

## 8. Immediate Next Steps

1. **Harden management plane UI** — self-service LLM provider config, API key generation, role assignment
2. **Package Docker image** — `docker run -p 9091:9091 -p 9092:9092 connector/platform`
3. **Write onboarding guide** — 5-minute setup for Windsurf/Cursor/Claude Code teams
4. **Build compliance report export** — SOC 2 evidence package from audit log
5. **Launch on GitHub** — open-source core proxy, enterprise features gated
6. **Produce demo video** — "From unmonitored to fully governed in 60 seconds"
