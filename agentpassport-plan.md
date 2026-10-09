# AgentPassport — Implementation Plan

> **Every AI agent has an identity. Verify it. Sponsor it. Hold it accountable.**

**Know Your Agent (KYA) and agent identity platform** — built on Connector.

---

## 1. The Problem (validated 2026 signal)

"Who is responsible when an autonomous agent acts?" is no longer theoretical.

Validated signals:
- **Mastercard open-sourced** the Agent Pay Acceptance Framework (Google, Fiserv signed on) — cryptographic proof that a specific agent, sponsored by a specific human, executed a specific action
- **ERC-8004 "Trustless Agents"** standard — agent identity registry, on-chain reputation, ZK-proof validation, slashing for misbehavior
- **HID Global**: *"Most enterprises lack a unified method for discovering, verifying and governing agent identities."*
- **Bessemer Venture Partners**: *"Securing AI agents is the defining cybersecurity challenge of 2026."*
- **Gartner**: 40% of enterprise applications will embed AI agents by end of 2026 — and procurement is starting to demand agent identity attestation before vendor onboarding
- Fortune 500 RFPs now include: *"How is your AI agent's identity verified? What is its accountability chain?"*

Today's enterprise reality:
- Procurement can't tell the difference between a vetted agent and a random script calling OpenAI
- Security teams can't verify which agents are running, who deployed them, or what they're allowed to do
- When an agent misbehaves, **nobody can prove who is liable** (dev? deployer? vendor?)
- There is no **agent resume** — no way to check an agent's prior behavior before trusting it
- Multi-vendor agent ecosystems fail at the trust boundary

---

## 2. The Product

AgentPassport gives every enterprise a platform to **register, verify, and govern the identity of every AI agent** interacting with their systems — internal or third-party.

Core capabilities:

- **Cryptographic identity** — every agent gets a DID with signed attributes
- **Human sponsorship linkage** — Agent → Verified User → Legal Entity (liability chain)
- **Verifiable credentials** — third-party attestations (capability, compliance, provenance)
- **Reputation registry** — portable behavior score across deployments
- **Attestation workflow** — approval flows before an agent is "production-trusted"
- **Procurement-grade reports** — PDF/JSON attestation packs for vendor onboarding
- **Revocation** — instantly revoke an agent's identity with cascading effect
- **Verification API** — `POST /verify` for any counterparty to check an agent
- **Cross-org federation** — trust another org's passport with one-click policy
- **Audit chain** — every identity event cryptographically logged

---

## 3. Connector Capability Audit (~80% done)

| Capability | Connector Endpoint | Status |
|---|---|---|
| Agent DID | `GET /tools/agents/:pid/did` | ✅ |
| Agent card (A2A) | `GET /tools/agents/:pid/card` | ✅ |
| UCAN capability issue | `POST /aapi/capabilities/issue` | ✅ |
| UCAN delegate | `POST /aapi/capabilities/delegate` | ✅ |
| UCAN revoke | `POST /aapi/capabilities/revoke` | ✅ |
| UCAN verify | `POST /aapi/capabilities/verify` | ✅ |
| Trust live | `GET /monitor/trust` | ✅ |
| Trust trend | `GET /monitor/trust-trend` | ✅ |
| Trust override | `POST /agents/:pid/trust` | ✅ |
| Clearance levels | `POST /agents/:pid/clearance` | ✅ |
| Agent lifecycle | Register, start, quarantine, terminate | ✅ |
| Interaction log | `GET /aapi/interactions` | ✅ |
| CID audit chain | Engine store, chained receipts | ✅ |
| Defense package | `GET /disputes/:id/defense-package` | ✅ |
| Provenance chain | `GET /disputes/provenance/:cid` | ✅ |
| Regulation templates | `GET /disputes/regulation-template/:framework` | ✅ |
| Dynamic policies | `POST /aapi/policies` | ✅ |
| Auth / SSO / OIDC | Full auth stack | ✅ |

**What's new (~20%)**: sponsor linkage workflow, verifiable credentials issuer/verifier (W3C VC), reputation registry, attestation PDF generator, procurement export packs, federation UI, external /verify API, ERC-8004 compatibility adapter.

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────┐
│         AgentPassport UI (browser + CLI)             │
│  Agent Directory · Attestations · Reputation ·       │
│  Sponsorship · Federation · Verify · Audit           │
└──────────────────────────┬───────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────┐
│          AgentPassport API Service                   │
│  /agents · /did · /credentials · /sponsors ·         │
│  /reputation · /verify · /revoke · /federation       │
└──────────────────────────┬───────────────────────────┘
                           │ HTTP only
┌──────────────────────────▼───────────────────────────┐
│               CONNECTOR (kernel)                     │
│  DIDs · agent cards · UCAN · trust · audit · CID     │
└──────────────────────────────────────────────────────┘
                           │ optional
┌──────────────────────────▼───────────────────────────┐
│    External standards (optional integrations)        │
│  W3C VCs · ERC-8004 · Mastercard Agent Pay · OIDC    │
└──────────────────────────────────────────────────────┘
```

### Identity model

Every agent passport contains:

```
AgentPassport {
  did: "did:connector:agent:abc123",
  sponsor: {
    user_did: "did:connector:user:jane@acme",
    legal_entity: "Acme Corp (EIN: 12-3456789)",
    signature: Ed25519(...)
  },
  credentials: [
    { type: "CapabilityCredential", issuer: "acme_security", capability: "read_crm", expires: ... },
    { type: "ComplianceCredential", issuer: "acme_compliance", framework: "internal_ai_policy_v3", ... },
    { type: "ProvenanceCredential", issuer: "connector_platform", model: "gpt-4o", prompt_hash: "..." }
  ],
  reputation: {
    total_interactions: 142318,
    trust_score: 0.94,
    violations: 0,
    last_incident: null,
    score_trend: [ ... 90-day series ... ]
  },
  revoked: false,
  audit_cid: "bafybeig..."
}
```

All signed. All CID-chained. All verifiable offline.

---

## 5. Core Features

### 5.1 Agent Directory
- Every agent in your org: internal + third-party
- Filter by: sponsor, status, trust score, credentials, clearance, last active
- Bulk actions: attest, revoke, update policy, assign sponsor

### 5.2 Registration Flow
1. Developer registers agent (CLI or UI)
2. System mints DID + agent card
3. Sponsor (human) required: approves registration with 2FA
4. Policy attached (what this agent is allowed to do)
5. Initial credentials issued
6. Passport activated, verifiable externally

### 5.3 Sponsor Linkage
- Every agent requires a human sponsor
- Sponsor must be a verified user (SSO + 2FA)
- Legal entity attested via admin (links to Tax ID / company record)
- Chain: `agent_did → sponsor_user_did → legal_entity_did`
- Liability chain baked into every attestation output

### 5.4 Verifiable Credentials (W3C VC)
- Issuers can be any user/team/external party
- Credential types:
  - **CapabilityCredential** — what the agent is allowed to do
  - **ComplianceCredential** — compliance framework attestation
  - **ProvenanceCredential** — model + prompt version + training data attestation
  - **IdentityCredential** — legal entity binding
- All signed, verifiable offline, revocable
- Expiration + auto-renewal flows

### 5.5 Reputation Registry
- Portable reputation score (0-1) per agent
- Aggregated from Connector trust score + violation history + uptime
- 90-day trend
- Global decay on violations (cannot "reset" by redeploying)
- Option to publish to external registry (ERC-8004 compatible export)

### 5.6 Verification API
External counterparties hit one endpoint:

```
POST /verify
{
  "did": "did:connector:agent:abc123",
  "required_credentials": ["CapabilityCredential:read_crm"],
  "min_trust_score": 0.8
}

→ 200 OK
{
  "verified": true,
  "passport": { ... },
  "verified_at": "2026-04-17T12:00:00Z",
  "proof": "ed25519_sig:..."
}
```

Can be called by: another agent (A2A), another org, a compliance auditor, a procurement system.

### 5.7 Attestation Export Packs
For procurement / third-party risk / compliance:
- PDF: "Agent Passport Report" — full identity + sponsor + credentials + reputation
- JSON: machine-readable attestation for API-driven procurement
- Signed by AgentPassport instance for tamper evidence
- Bundles audit chain proofs

### 5.8 Revocation
- One-click revoke: disables DID, invalidates all VCs, propagates to federation peers
- Cascading: revoke a sponsor → revoke all their agents
- Revocation reason + audit logged on-chain
- CRL (Certificate Revocation List) queryable by external verifiers

### 5.9 Federation
- Trust another AgentPassport instance (e.g., vendor's passport)
- Import their agents with inherited verification
- Scoped: "trust Acme's agents only for /read_* capabilities"
- Auto-revoke if peer revokes upstream

### 5.10 Incident Response
When an agent violates policy:
- Auto-quarantine via Connector
- Reputation score decremented (bounded algorithm)
- Sponsor notified
- Incident report generated
- If severe: sponsor-wide freeze until review

### 5.11 ERC-8004 Compatibility (optional)
- Export/import ERC-8004 agent tokens
- On-chain anchoring of passport hashes
- Interop with agent-commerce ecosystems (for customers that need it)

### 5.12 Mastercard Agent Pay Compatibility (optional)
- Export passport in Mastercard's Agent Pay format
- Enables AgentPassport-issued agents to transact on Mastercard network

---

## 6. New Endpoints (thin layer)

| Endpoint | Purpose | Connector calls behind |
|---|---|---|
| `POST /agents/register` | Registration workflow | `/agents` + sponsor check |
| `POST /sponsors/verify` | Verify human sponsor | auth + 2FA |
| `GET /passport/:did` | Full passport | DID + agent card + VCs + reputation |
| `POST /credentials/issue` | Issue W3C VC | New (crypto signer) |
| `POST /credentials/verify` | Verify VC | New (crypto) |
| `POST /credentials/revoke` | Revoke VC | New + CRL |
| `POST /verify` | External verification | aggregate above |
| `POST /revoke/:did` | Revoke agent | `/agents/:pid/terminate` + cascade |
| `GET /reputation/:did` | Reputation + trend | `/monitor/trust*` + violations |
| `GET /attestation/:did/export` | PDF/JSON attestation | aggregate |
| `POST /federation/peers` | Register peer instance | new |
| `POST /federation/import/:peer` | Import peer agents | federation API |
| `GET /erc8004/:did` | ERC-8004 export | adapter |
| `GET /mastercard/:did` | Agent Pay format | adapter |

---

## 7. Build Order

### Phase 1 — Identity core (week 1-4)
- Agent directory + registration flow
- Sponsor linkage + 2FA gate
- DID issuance (using Connector's existing DIDs)
- Basic passport view
- Revocation flow

**Ships: baseline KYA for internal agents.**

### Phase 2 — Credentials + Verification (week 5-8)
- W3C VC issuer
- VC verifier (library + API)
- `/verify` external API
- Attestation PDF generator
- Procurement-grade JSON export

**Ships: third-party verification. Pilot with procurement teams.**

### Phase 3 — Reputation + Federation (week 9-12)
- Reputation registry with decay algorithm
- Cross-incident tracking
- Federation peer registration
- Peer trust import with scoping
- Revocation cascade

**Ships: multi-org / vendor trust. Enterprise tier launches.**

### Phase 4 — Standards compatibility (week 13-16)
- ERC-8004 export/import
- Mastercard Agent Pay format
- On-chain anchoring (optional, opt-in)
- OIDC agent identity flow
- CLI (`agentpassport register / verify / revoke`)

**Total: 16 weeks / 1-2 engineers**

---

## 8. Competitive Position

| Capability | AgentPassport | Strata Identity | Mastercard Agent Pay | ChainUp | HID Global | Okta |
|---|---|---|---|---|---|---|
| Agent DID issuance | ✅ | partial | ✅ | ✅ | partial | ○ |
| **Human sponsor linkage** | ✅ | partial | ✅ | ✅ | ✅ | ○ |
| **W3C Verifiable Credentials** | ✅ | ○ | partial | ○ | ✅ | ○ |
| **Reputation registry** | ✅ | ○ | ✅ | ✅ | ○ | ○ |
| **External /verify API** | ✅ | partial | ✅ | partial | partial | partial |
| **Procurement-grade export** | ✅ | ○ | ○ | ○ | ○ | ○ |
| **Revocation w/ cascade** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Runtime integration** (with enforcement) | ✅ | partial | partial | ○ | ○ | ✅ |
| **CID-chained audit** | ✅ | ○ | partial | ✅ | ○ | ○ |
| ERC-8004 compatible | ✅ | ○ | partial | ✅ | ○ | ○ |
| Mastercard compatible | ✅ | ○ | ✅ | ○ | ○ | ○ |
| Federation | ✅ | ✅ | partial | partial | ✅ | ✅ |
| **Self-hosted** | ✅ | ✅ | ○ | partial | ✅ | partial |
| **Agent-native runtime** | ✅ | ○ | ○ | ○ | ○ | ○ |

**Positioning**:
- vs **Strata Identity**: They're enterprise SSO for humans, doing agents as afterthought. We're agent-native with runtime integration (Connector kernel).
- vs **Mastercard Agent Pay**: They solve payments-rails only. We solve the full enterprise KYA stack, with Mastercard as one supported output format.
- vs **ChainUp**: They're crypto/blockchain-native. We're enterprise-native with crypto as optional layer.
- vs **HID Global**: They're PKI for devices/humans. We're agent-native with lifecycle + reputation.
- vs **Okta**: They're humans + devices. Agents are wedge they don't own yet.

**Moat**: Runtime integration. AgentPassport isn't just identity metadata — it's enforced at every Connector call. Competitors issue certificates; AgentPassport issues + polices + audits + reputes.

---

## 9. Pricing

| Tier | Price | Includes |
|---|---|---|
| Starter | $99/mo | 25 agents, basic passport, internal verification |
| Team | $499/mo | 250 agents, W3C VCs, /verify API, PDF attestations |
| Business | $1,999/mo | Unlimited agents, reputation, federation, compliance exports |
| Enterprise | Custom (typ. $5k-$25k/mo) | On-prem, SSO, ERC-8004 + Mastercard, SLA, legal entity attestation |

**Enterprise deals justify via**:
- Security budget: pre-approved for agent risk management
- Procurement budget: vendor onboarding acceleration
- Compliance budget: audit-ready third-party attestation
- Legal budget: liability chain for AI incidents

---

## 10. Go-To-Market

### Buyer
- **Primary**: CISO / Head of Security. 2026 mandate to govern agent identity.
- **Secondary**: VP Procurement. Needs to verify third-party AI before onboarding.
- **Tertiary**: Chief Compliance Officer / GC. Liability chain clarity.
- **Champion**: Security engineer fighting shadow AI.

### Wedge
"You just onboarded a new SaaS vendor. They said their AI is safe. **Prove it.**"

Demo: point their vendor's agent at our `/verify` endpoint → show real-time passport verification including sponsor, capabilities, reputation, compliance attestations.

### Channel
- Security conferences (RSA, Black Hat, Gartner Security Summit)
- CISO peer networks
- Procurement tech councils
- Integration partnerships:
  - Okta / Azure AD (human SSO → agent sponsorship)
  - ServiceNow (GRC workflow)
  - OneTrust / Drata (compliance automation)
- Cloud marketplace listings (AWS, Azure, GCP)
- Open-source core verifier library (adoption driver)

---

## 11. Positioning

> **AgentPassport is Know Your Agent for the enterprise. Register every AI agent with a cryptographic identity. Link it to a verified human sponsor. Issue credentials. Track reputation. Verify external agents in real time. Revoke with one click.**

> **No passport, no action.**

---

## 12. Strategic Value in Connector Portfolio

AgentPassport is the **identity layer** that every other Connector product benefits from:

- **DevGuard** uses AgentPassport to verify coding agents per policy
- **TraceTramp** uses AgentPassport to enforce identity at proxy ingress
- **AgentLoop** uses AgentPassport to scope who can edit/ship/approve prompts
- **LedgerLens** uses AgentPassport to attribute spend to verified sponsors
- **Conductor** (future) uses AgentPassport for trust in multi-agent pipelines

This makes AgentPassport both a **standalone product** and the **identity substrate** for the entire Connector portfolio — classic platform network effect.
