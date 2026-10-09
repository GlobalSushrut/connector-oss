# TraceTramp vs Alternatives

## The Core Question

Before comparing tools, establish what you actually need:

1. Do you need **compliance evidence** — audit trails an auditor will accept?
2. Do you need **policy enforcement** — blocking or redacting requests at runtime?
3. Do you need **workflow orchestration** — multi-step agents with state?
4. Do you need **multi-provider routing** — switching models based on cost or policy?

If the answer to all four is no, TraceTramp is not the right tool. If any are yes, read on.

---

## Side-by-Side Comparison

| Capability | TraceTramp | LiteLLM | Helicone | Portkey | LangChain | Kong AI | Direct SDK |
|-----------|-----------|---------|---------|---------|-----------|---------|-----------|
| Multi-provider routing | ✅ | ✅ | ❌ | ✅ | ✅ | ⚠️ | ❌ |
| Decision tree recording | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Tamper-evident receipts | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Runtime policy enforcement | ✅ | ⚠️ | ❌ | ⚠️ | ❌ | ⚠️ | ❌ |
| PII redaction at proxy | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Budget enforcement | ✅ | ✅ | ⚠️ | ✅ | ❌ | ❌ | ❌ |
| RBAC per tenant | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| Workflow / DAG orchestration | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Human-in-the-loop approvals | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ |
| OpenFaaS / Lambda / Docker functions | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ |
| Compliance export (CSV / JSON) | ✅ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| OpenAI-compatible API | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| 1-line integration | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | n/a |
| Managed SaaS option | ❌ (roadmap) | ✅ | ✅ | ✅ | ❌ | ✅ | n/a |
| Cost | Free + infra | Free + infra | $500–2K/mo | $300–1.5K/mo | Free | Free + license | Free |

---

## LiteLLM

**Best for:** Quickly routing across 100+ providers with minimal setup.

**What it does well:**
- OpenAI-compatible proxy for almost every model
- Basic rate limiting and budget tracking
- Fallback routing when a provider fails
- Free and open source

**Where it falls short:**
- No decision tree — you know a call was made but not what decision it represented
- No tamper-evident evidence — logs are mutable
- No runtime policy enforcement — no blocking, no redaction at the proxy level
- No workflow engine
- No RBAC per tenant with real enforcement

**Choose LiteLLM if:** You need multi-provider routing fast and have no compliance requirements.

**Choose TraceTramp over LiteLLM if:** You need audit trails, policy enforcement, or workflow orchestration.

---

## Helicone

**Best for:** Analytics dashboards and prompt management for OpenAI-based products.

**What it does well:**
- Clean observability UI out of the box
- Prompt template management
- Cost dashboards
- Managed SaaS (zero infrastructure)

**Where it falls short:**
- OpenAI-only (or limited multi-provider)
- No tamper-evident evidence — logs live in their cloud, mutable
- No policy enforcement at runtime
- No workflow engine
- No multi-tenancy with RBAC
- No compliance export in auditor-acceptable format
- Data residency is a concern for regulated industries

**Choose Helicone if:** You want quick dashboards for an OpenAI-based product and have no compliance or enforcement requirements.

**Choose TraceTramp over Helicone if:** You have data residency requirements, compliance audits, multi-tenant isolation, or need runtime enforcement.

---

## Portkey

**Best for:** Production AI gateway with semantic caching and guardrails.

**What it does well:**
- Solid multi-provider routing and fallbacks
- Semantic caching (reduce duplicate LLM costs)
- Basic guardrails (content filtering)
- Managed SaaS

**Where it falls short:**
- Guardrails are basic — not full policy engine with RBAC
- No decision tree recording — observes calls but not the decision chain
- No tamper-evident evidence
- No workflow / agent orchestration
- On-premise not available (or limited)

**Choose Portkey if:** You want managed infrastructure, semantic caching, and basic guardrails without operational overhead.

**Choose TraceTramp over Portkey if:** You need self-hosted, compliance-grade evidence, RBAC with real enforcement, or workflow orchestration.

---

## LangChain / LangGraph

**Best for:** Building Python-based agents quickly with a rich ecosystem of integrations.

**What it does well:**
- Extremely broad integration ecosystem
- Agent and chain abstractions
- LangGraph for DAG-based workflows
- LangSmith for tracing (LangChain-specific)

**Where it falls short:**
- Framework-specific — only captures calls made through LangChain
- Not a proxy — requires code changes to integrate
- LangSmith traces are mutable, not tamper-evident
- No runtime enforcement (policy, budget, RBAC)
- Language-locked (Python/JS)

**Choose LangChain if:** You are building in Python, want rapid agent prototyping, and compliance is not a requirement.

**Choose TraceTramp alongside LangChain if:** You want to capture LangChain calls in a framework-agnostic, tamper-evident audit trail with policy enforcement.

---

## Kong AI Gateway

**Best for:** Enterprises already running Kong as their API gateway who want AI capabilities bolted on.

**What it does well:**
- Battle-tested gateway infrastructure
- Large plugin ecosystem
- Rate limiting, authentication, load balancing
- Enterprise support

**Where it falls short:**
- AI features are plugins on top of a general-purpose gateway, not purpose-built
- No decision tree recording
- No tamper-evident evidence
- No workflow engine
- Expensive at enterprise tier
- AI-specific features lag dedicated tools

**Choose Kong if:** You are deep in Kong already and want to add light AI governance without a new system.

**Choose TraceTramp over Kong if:** You need purpose-built AI observability, decision recording, or compliance evidence.

---

## Cloud AI Gateways (AWS / Azure / GCP)

**Best for:** Enterprises already committed to one cloud vendor who want managed AI governance.

**What it does well:**
- Native integration with cloud services (IAM, CloudWatch, etc.)
- Managed infrastructure
- Compliance certifications (FedRAMP, HIPAA BAA, etc.)

**Where it falls short:**
- Vendor lock-in — policies, logs, and evidence are in one cloud
- No portable tamper-evident evidence format
- No cross-cloud routing
- Limited customization of what is recorded
- No workflow orchestration native to the gateway

**Choose a cloud gateway if:** You are single-cloud and want managed infrastructure with no portability requirements.

**Choose TraceTramp over cloud gateways if:** You are multi-cloud, need portable audit evidence, or need custom policy enforcement.

---

## Direct SDK

**Best for:** Prototyping and simple single-provider applications.

**What it does well:**
- Lowest possible latency
- Simplest setup — no infrastructure
- Full control

**Where it falls short:**
- Zero governance — no policy, no budgets, no audit trail
- Provider-specific — switching requires code changes
- No observability across calls

**Choose direct SDK if:** You are prototyping, solo developer, single provider, no production requirements.

---

## Decision Tree

```
Do you need compliance-grade audit evidence?
├── YES → Do you need runtime enforcement (policy/budget/PII)?
│   ├── YES → TraceTramp
│   └── NO  → TraceTramp (View mode only)
└── NO  → Do you need multi-provider routing?
    ├── YES → Do you need workflow orchestration?
    │   ├── YES → TraceTramp or LangGraph + LiteLLM
    │   └── NO  → LiteLLM or Portkey
    └── NO  → Direct SDK
```

---

## Migration to TraceTramp

### From Direct SDK

1. Deploy TraceTramp (Docker or binary)
2. Run migrations (`cargo sqlx migrate run`)
3. Change `base_url` in your client to `http://your-host:9091/v1`
4. Change `api_key` to your TraceTramp key
5. Done — all existing calls now have decision trees

### From LiteLLM

1. Deploy TraceTramp alongside LiteLLM
2. Point clients at TraceTramp instead of LiteLLM
3. Configure providers in TraceTramp admin API
4. Migrate budget and routing rules to TraceTramp policies

### From LangChain

1. Keep LangChain for agent logic and chain composition
2. Change the LLM client inside LangChain to point at TraceTramp
3. All LLM calls now flow through TraceTramp and get recorded
4. Add workflow definitions to TraceTramp if you want cross-framework orchestration

---

## When TraceTramp Is the Right Choice

- You need to answer "what exactly did the AI decide and why" for a specific request
- Auditors or regulators will review your AI interactions
- You run multi-tenant AI and each tenant has isolated compliance requirements
- You need to enforce budgets, block content, or redact PII at the proxy level
- You need human approval before certain AI actions execute
- You use more than one LLM provider and want unified governance across all of them

## When TraceTramp Is Not the Right Choice

- You are building a proof of concept with a single provider
- Your team is 1-2 engineers with no compliance requirements
- You need managed SaaS with no operational overhead (use Helicone or Portkey)
- Your latency budget is under 50ms (proxy adds ~20-50ms)
