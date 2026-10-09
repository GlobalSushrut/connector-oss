# TraceTramp: Market Position and Competitive Moat

## The Problem Nobody Has Solved

Companies are deploying AI agents into production. These agents talk to customers, execute code, call APIs, access databases, and make decisions that carry legal and financial weight.

When something goes wrong — or when a regulator asks — nobody can answer:

- "What exactly did the AI tell that user?"
- "Why did the agent approve that $50,000 transaction?"
- "Who authorized this tool call?"
- "Prove the AI's decision was compliant with policy X."
- "Show me the full reasoning chain for workflow Y on Tuesday at 2pm."

Current tools don't solve this:

| Tool | What It Captures | What It Misses |
|------|-----------------|----------------|
| Datadog APM | Latency, error rates | No decision content |
| LangSmith | LangChain-specific traces | Framework-locked, mutable |
| Helicone | Request/response logs | No policy chain, no evidence integrity |
| CloudWatch | Infrastructure metrics | No AI-specific context |
| Custom logging | Whatever you coded | Inconsistent, manually maintained |

None of these produce evidence that an auditor can verify for integrity. None enforce policy at the decision point. None build a chain across multi-step workflows.

This is the gap TraceTramp fills.

## The Core Product: Decision Tree Recording

Every AI request that passes through TraceTramp produces a **Decision Tree** — a structured, cryptographically-anchored record of:

1. The raw input (exact prompt, messages, context)
2. The policy outcome (allowed, blocked, rerouted, flagged)
3. The provider and model selected and why
4. The raw output (exact LLM response)
5. The derived action (what the response actually did — tool call, refund, escalation, content generated)
6. Cost attribution (tokens in/out, USD cost, per-tenant)
7. A receipt from the Connector kernel — a CID-chained hash linking each decision to the previous

The Decision Tree is stored in Postgres. It is queryable by trace ID. It can be exported for compliance. The receipt chain means any tampering is detectable.

This is what auditors want. This is what TraceTramp provides. No competitor does this.

## The Moat: Five Things Nobody Else Has

### 1. Raw Decision Recording, Not Just Call Logging

Competitors record that a call was made and how many tokens were used. TraceTramp records what decision was represented by that call — the input, the output, the action derived from the output, and the policy context that governed it.

The difference: a log says "GPT-4 was called at 2pm." A decision tree says "User asked X, AI said Y, which triggered action Z, policy outcome was Allow, cost was $0.004."

### 2. Decision Chain Across Multi-Step Workflows

A single LLM call is rarely a single business decision. Agents chain calls together. Workflows have steps that depend on previous outputs. TraceTramp links these into a chain — the full reasoning trace from first input to final action, across as many steps as the workflow has.

This is what makes compliance possible for agentic systems. You need to see the whole chain, not isolated calls.

### 3. Cryptographic Evidence Integrity

Logs are mutable. TraceTramp's receipts are not. Every decision tree is hashed. The hash is submitted to the Connector kernel, which issues a CID-chained receipt. Any modification to the recorded data breaks the hash chain.

When an auditor asks "how do I know this wasn't changed after the fact," the answer is: "Check the receipt CID. The hash is verifiable."

### 4. Runtime Policy Enforcement, Not Post-Hoc Analysis

Most observability tools watch what happened and report on it. TraceTramp's Control mode acts before the LLM call is made:

- Blocks requests that violate policy
- Redacts PII before the prompt reaches the provider
- Enforces budget limits in real time
- Holds requests for human approval before executing

This means non-compliant requests never reach the LLM. The audit trail shows enforcement, not just observation.

### 5. Zero-Change Integration

The proxy accepts the OpenAI API format. Changing one line — the `base_url` — is the entire integration. Every existing SDK, every existing agent, every existing LangChain/LlamaIndex/AutoGen workflow works without code changes.

This lowers adoption friction to near zero.

## Why Customers Can't Build This Themselves

The components required to build what TraceTramp provides:

- **CID-chained receipt generation** — cryptographic hashing with a verifiable chain, requires a separate kernel (Connector)
- **Universal LLM proxy** — handle OpenAI, Anthropic, Azure, Ollama, Bedrock, Vertex with format normalization
- **Policy engine** — runtime evaluation of typed policies (content filter, tool permission, PII, rate limit) with RBAC
- **PII detection and tokenization** — multi-pattern regex engine with reversible token substitution
- **Decision extraction** — parsing raw LLM output to derive the action it represents
- **Multi-backend function execution** — OpenFaaS, AWS Lambda, Docker Engine API, WASM
- **Tiered storage** — hot/warm/cold with rollups, compression, retention management
- **Multi-tenant RBAC** — full role management with per-request permission enforcement

Realistic engineering estimate to build equivalent from scratch:
- **Team size:** 8-12 engineers
- **Timeline:** 12-18 months
- **Cost:** $2-5M in engineering time

Deploying TraceTramp takes days. Building the equivalent takes over a year.

## Who Needs This

### Tier 1: Regulated Industries

**Financial Services** (banks, trading firms, fintech)
- Regulators (SEC, FINRA, FCA) require audit trails of customer-facing AI interactions
- Current pain: manual audit prep takes weeks, auditors reject incomplete logs
- One enforcement action covers years of TraceTramp costs

**Healthcare** (insurers, telemedicine, EHR vendors)
- HIPAA requires audit capability for AI clinical decisions
- PII redaction is mandatory before prompts leave the organization
- A single HIPAA violation can exceed $1.5M

**Legal Tech** (law firms, compliance software vendors)
- Attorney-client privilege creates documentation requirements for AI interactions
- Provenance of AI-generated legal content is a liability issue

### Tier 2: High-Volume AI Deployments

**Customer support at scale**
- AI agents make commitments — refunds, replacements, escalations
- Without a decision trail, you cannot audit what was promised to whom

**Code generation platforms**
- Liability for AI-generated vulnerabilities requires provenance
- Copyright concerns require proof of what training data influenced outputs

**Multi-tenant SaaS**
- Enterprise customers require per-tenant compliance exports
- Currently costs 15-20% of engineering time to build custom per-customer logging

### Tier 3: Enterprise IT Governance

Large enterprises deploying AI internally without visibility into what teams are doing with it. Shadow AI usage, uncontrolled spend, no audit capability.

## Architecture: The Proxy Moat

The proxy architecture has a strategic advantage beyond low integration friction:

Once TraceTramp's decision tree format is accepted by a customer's auditors and embedded in their compliance workflows, switching costs become significant:

- All historical evidence is in TraceTramp's format
- Auditors have been trained on and approved that format
- Compliance processes are built around the format
- Migrating would require reformatting years of records and retraining auditors

This is the same dynamic that made Splunk the log format standard and Datadog the metrics format standard. **TraceTramp is positioned to become the standard format for AI decision evidence.**

## Scalability Architecture

TraceTramp is designed for growth from single-instance to enterprise scale:

### Tiered Storage

| Tier | Storage | Retention | Query Latency | Use Case |
|------|---------|-----------|---------------|----------|
| Hot | Redis + Postgres | 7 days | < 100ms | Real-time debugging, active audits |
| Warm | Postgres partitioned | 7–90 days | 1–5 seconds | Compliance reports, recent reviews |
| Cold | S3 + Parquet | 90 days – 7 years | Seconds to minutes | Regulatory audits, legal discovery |

### Scale Points

- Single instance: 10K req/sec sustained
- With async Kafka write buffer: 100K req/sec
- Horizontal scaling: 1M+ req/sec (10 instances behind load balancer)
- Postgres Citus for horizontal sharding when hot tier exceeds single-node capacity

## Go-To-Market Trigger Events

These are the moments when a prospect becomes a buyer:

- Upcoming SOC 2 Type II audit and no AI evidence capability
- HIPAA compliance review with AI systems in scope
- A publicized AI incident at a peer company (the "that could be us" moment)
- Board-level directive to govern AI usage
- A regulator requesting AI interaction logs that cannot be produced
- Engineering team spending significant time building custom per-customer logging

## Pricing Framework

**Starter — $5K/month**
- Up to 1M decisions/month
- 3 providers
- 30-day retention
- Core evidence APIs

**Professional — $25K/month**
- Up to 50M decisions/month
- Unlimited providers
- 1-year retention
- Full policy engine
- Workflow orchestration
- RBAC

**Enterprise — $100K–500K/year**
- Unlimited decisions
- On-premise or dedicated cloud deployment
- 7-year retention for regulatory requirements
- Custom policies
- SSO / SAML
- White-glove onboarding
- 99.99% SLA

**Compliance Add-ons**
- FINRA/SEC templates: +$50K
- HIPAA BAA and templates: +$50K
- FedRAMP documentation: +$100K

## The Position in One Line

**TraceTramp is the only AI proxy that records every decision in a tamper-evident chain — the exact prompt, the exact response, the exact action — in a format auditors accept.**

Everything else logs calls. TraceTramp records decisions.
