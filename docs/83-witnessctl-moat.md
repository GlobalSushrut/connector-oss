# WitnessCtl — Market Position & Moat

## The Problem

Every AI system in production makes outbound API calls. Nobody can prove what happened.

- **Compliance officers** can't audit AI-driven API interactions because logs are incomplete, mutable, and lack cryptographic proof
- **Security teams** can't detect when AI agents leak PII through API calls or get manipulated via prompt injection into calling unauthorized endpoints
- **Engineering leads** can't explain to regulators why an AI agent called a specific API, what data it sent, or whether the response was tampered with

Current tools (DataDog, Langfuse, Helicone) log LLM calls. None of them capture, govern, and prove **outbound API interactions** with tamper-evident receipts.

## The Moat

### 1. HMAC-Chained Receipts
Every API call produces a receipt chained to the previous one via HMAC-SHA256. Break one link, the entire chain fails verification. This is the same principle as blockchain — without the overhead.

**Competitive barrier:** Nobody else chains receipts. Logs are append-only at best, mutable at worst. Auditors reject mutable logs.

### 2. Dual-Layer Governance
Connector's admission gate + firewall run on every call before it reaches the upstream. This isn't logging-after-the-fact — it's enforcement-before-the-fact.

**Competitive barrier:** API gateways (Kong, AWS API Gateway) enforce policies but don't produce compliance-grade evidence. Observability tools produce evidence but don't enforce policies. WitnessCtl does both in one pass.

### 3. Schema Drift Detection
WitnessCtl infers the JSON schema of every API endpoint it sees. When the upstream changes shape (new fields, removed fields, type changes), it flags drift automatically.

**Competitive barrier:** Nobody else tracks API contract drift in the context of AI agent interactions. This is uniquely valuable when AI agents call dozens of APIs whose schemas evolve independently.

### 4. Multi-Framework Compliance
HIPAA, SOC2, GDPR, EU AI Act — evaluated per-session with specific control mappings. Not a generic "compliance score" but article-level control results.

**Competitive barrier:** Compliance tools evaluate your infrastructure. WitnessCtl evaluates your AI's actual API behavior against specific regulatory controls, with evidence for each.

### 5. Connector Integration
WitnessCtl isn't standalone. It registers agents with Connector, uses Connector's firewall, policy engine, audit chain, and proof generation. The evidence it produces is verifiable against Connector's kernel-level receipts.

**Competitive barrier:** Standalone tools produce isolated evidence. WitnessCtl's evidence is part of the Connector ecosystem — verifiable end-to-end from LLM decision (TraceTramp) through API action (WitnessCtl) to kernel proof (Connector).

## Target Customers

### Tier 1: Healthcare AI (HIPAA)
- **Who:** Companies deploying AI agents that interact with EHR systems, insurance APIs, patient data
- **Pain:** HIPAA auditors require proof of every PHI touchpoint. AI agents make dynamic API calls that traditional audit tools can't track.
- **Why WitnessCtl:** Tamper-evident receipts + PII detection + HIPAA control mapping = auditors accept the evidence.

### Tier 2: Financial Services AI (SOC2)
- **Who:** Fintech and banks using AI agents for transaction processing, fraud detection, customer service
- **Pain:** SOC2 requires change management controls. AI agents calling APIs with drifting schemas is a control gap.
- **Why WitnessCtl:** Schema drift detection + admission gate + SOC2 control mapping.

### Tier 3: Enterprise AI Platforms (GDPR/EU-AI-Act)
- **Who:** European companies deploying AI systems that interact with customer data via APIs
- **Pain:** EU AI Act requires risk management, transparency, and human oversight for high-risk AI. API calls are the highest-risk surface.
- **Why WitnessCtl:** Article-level compliance + human oversight via admission hold + full transparency chain.

## Pricing

| Tier | Price | Includes |
|------|-------|----------|
| Starter | $500/mo | 10K API calls/mo, 1 framework, 7-day retention |
| Business | $2,000/mo | 100K calls/mo, all frameworks, 90-day retention, CSV export |
| Enterprise | $5,000/mo | Unlimited calls, all frameworks, unlimited retention, PDF export, SSO, custom controls |

## Why This Wins

1. **Narrow wedge:** Outbound API governance for AI — nobody owns this category yet
2. **Clear buyer:** Compliance officer who needs to pass an audit, not an engineer who wants better logging
3. **Unavoidable:** Once you deploy AI agents that call external APIs in a regulated industry, you need this or you fail your audit
4. **Defensible:** HMAC receipt chains can't be retrofitted into logging tools. Schema drift detection requires sustained investment. Connector integration compounds over time.
5. **Expandable:** Same architecture scales from 1K to 1B+ calls/sec via tiered storage rollups (hot PostgreSQL → warm compressed → cold S3 archive)
