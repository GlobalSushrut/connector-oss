# AgentPassport — Strategy, Outcome Clarity & Enterprise Design

> **AgentPassport is Auth0 for AI agents. Not humans. Agents.**
> Every AI agent gets a cryptographic identity, a verified human owner, a behavior reputation, and a passport that any system — internal or external — can verify in one API call.

---

## 1. The Question You Must Answer First

### Why do we need this if ConnectorOS already has DIDs, UCAN, trust scoring, and auth?

**ConnectorOS manages identity for agents YOU own.**

AgentPassport answers a different question: **how does anyone ELSE trust an agent they didn't build?**

```
ConnectorOS kernel answers:
  "Is this agent allowed to call this endpoint?"       ← internal enforcement

AgentPassport answers:
  "Can I trust this agent that just knocked on my door?" ← external verification
```

The gap is the trust boundary between organizations, systems, and counterparties.

A vendor says: "Our AI agent will access your ERP system."
Procurement asks: "Prove it. Who built it? Who is liable if it misbehaves? What is it allowed to do? Has it ever violated policy anywhere? Show me the credential."

Today, there is no answer to that question. AgentPassport is the answer.

---

## 2. What We're Actually Selling

Stop thinking about features. There are **three purchases** happening:

### Purchase 1 — The CISO buys "no more shadow agents" ($2,000–$25,000/mo)

**The problem they have today**: They don't know how many AI agents are running in their organization. Some were deployed by contractors. Some are third-party SaaS features that turned on by default. Security can't enumerate them, can't verify what they're doing, and can't prove governance to auditors.

**What they buy**: An agent directory with cryptographic proof of every agent's identity, owner, capabilities, and behavior history. When the auditor asks "what AI agents touched our customer data?", the answer is a signed report, not a scramble.

**The metric they care about**: Time to produce an audit-ready agent inventory — from weeks to minutes.

---

### Purchase 2 — Procurement buys "vendor AI due diligence" ($500–$5,000/mo)

**The problem they have today**: Every SaaS vendor now includes AI. The SOC2 report doesn't mention the AI agent at all. The vendor's "AI trust center" is a marketing page. There's no standardized way to assess whether a vendor's AI agent meets their risk thresholds before onboarding.

**What they buy**: The ability to hit `POST /verify` against any vendor's AgentPassport and get a machine-readable trust score, capability list, compliance attestations, and sponsor identity — in seconds. Vendor onboarding that used to take 3 weeks of back-and-forth takes 3 minutes.

**The metric they care about**: Time and cost of third-party AI agent due diligence.

---

### Purchase 3 — The enterprise platform team buys "agent identity substrate" ($5,000–$50,000/mo)

**The problem they have today**: They're building a multi-agent platform. Agent A calls Agent B which calls Agent C. Each hop requires a trust decision. They're reinventing JWT-like tokens for agents, writing custom trust logic, and managing it differently across 12 teams.

**What they buy**: A platform that issues agent identity tokens, enforces trust policies at every hop, and provides a single revocation surface. When an agent is compromised, one revocation cascades through the entire system — no hunting down which tokens to invalidate.

**The metric they care about**: Engineering hours spent on agent identity plumbing vs. product work.

---

## 3. What Already Exists vs. What We Build

### Already in ConnectorOS kernel (we call it, we don't rebuild it)

| Capability | Connector endpoint | What it gives us |
|---|---|---|
| Agent DID issuance | `GET /tools/agents/:pid/did` | Every agent has a DID from day 1 |
| Agent card (A2A) | `GET /tools/agents/:pid/card` | Machine-readable capability declaration |
| UCAN issue/delegate/revoke/verify | `/aapi/capabilities/*` | Fine-grained capability tokens, delegatable |
| Trust score live | `GET /monitor/trust` | Behavioral reputation, updated in real time |
| Trust trend (90d) | `GET /monitor/trust-trend` | Reputation history for procurement reports |
| Trust override | `POST /agents/:pid/trust` | Admin-force trust level changes |
| Clearance levels | `POST /agents/:pid/clearance` | Tiered access control for sensitive resources |
| Agent lifecycle | register, start, quarantine, terminate | Full lifecycle with events |
| CID audit chain | internal engine | Tamper-evident, CID-linked event chain |
| Defense package | `GET /disputes/:id/defense-package` | Pre-built audit pack for incidents |
| Provenance chain | `GET /disputes/provenance/:cid` | Full call chain traceable from any event |
| Dynamic policies | `POST /aapi/policies` | Runtime policy enforcement |
| Auth / SSO / OIDC | full auth stack | Human identity already solved |
| Interaction log | `GET /aapi/interactions` | Full call history per agent |

**That is ~80% of what AgentPassport needs. The kernel already exists.**

### What AgentPassport adds (the 20% that creates the product)

| New capability | Why it doesn't exist in ConnectorOS | What it enables |
|---|---|---|
| **Sponsor linkage workflow** | ConnectorOS knows agent DIDs but not human liability chains | Procurement: "Who is legally responsible?" |
| **W3C Verifiable Credentials** | ConnectorOS has UCAN (capability tokens) but not W3C VC standard | Interop with external verifiers, standards compliance |
| **External `/verify` API** | ConnectorOS enforces internally, has no public-facing verification gateway | Third parties can verify your agents before trusting them |
| **Reputation registry** | ConnectorOS has trust score but no portable, cross-deployment reputation | "This agent was well-behaved at Acme — trust it at Contoso" |
| **Attestation PDF/JSON export** | No procurement-grade report generation | Vendor onboarding, auditor handoffs |
| **Federation** | ConnectorOS manages one org's agents; no cross-org trust mesh | "Import Acme's agents as trusted" |
| **Certificate Revocation List** | ConnectorOS revokes internally; external verifiers need a queryable CRL | External systems can check revocation without calling our API |
| **ERC-8004 / Mastercard adapter** | External standards not yet implemented | Commerce network interop, future-proofing |

---

## 4. The Auth0 Analogy — Where It Holds and Where It Breaks

### Where AgentPassport IS Auth0 for agents

| Auth0 for humans | AgentPassport for agents |
|---|---|
| User signs up → gets user_id | Agent registers → gets DID |
| Assign user to roles/groups | Assign agent to capabilities/clearances |
| Issue JWT token | Issue UCAN capability token |
| SSO: "this Google user = this system user" | Sponsor linkage: "this agent = this human + this legal entity" |
| OIDC discovery endpoint | AgentPassport `/verify` endpoint |
| User is blocked → token invalid | Agent revoked → DID invalidated, CRL updated |
| Multi-tenant: one Auth0, many apps | Federation: one AgentPassport, many orgs |
| Auth0 Management API | AgentPassport admin API |
| Auth0 Rules/Actions | AgentPassport policy engine (via ConnectorOS) |

### Where AgentPassport goes BEYOND Auth0

Auth0 answers: "Who is this user? Are they allowed in?"
Auth0 does NOT answer:
- "Has this identity behaved well historically?" → **Reputation registry**
- "Who is legally liable for this identity's actions?" → **Sponsor linkage**
- "Can this identity prove it was trained on compliant data?" → **Provenance credential**
- "What did this identity do to the auditor's satisfaction?" → **CID audit chain + defense package**
- "Can I trust this identity that comes from a different organization?" → **Federation**
- "Does this identity's reputation follow it across deployments?" → **Portable reputation**

This is where Auth0 ends and AgentPassport begins. Auth0 was designed for humans behind browsers. Agents are autonomous, persistent, multi-tenanted, and legally consequential in ways that human SSO never had to handle.

---

## 5. Enterprise Design — The System That Challenges Auth0 in the AI Domain

### 5.1 Identity Model

```
AgentPassport {
  // Core identity (from ConnectorOS)
  did:         "did:connector:agent:abc123",
  agent_card:  { name, version, capabilities[], endpoints[] },
  
  // Sponsor chain (NEW — this is what ConnectorOS doesn't have)
  sponsor: {
    user_did:      "did:connector:user:jane@acme.com",
    legal_entity:  "Acme Corp",
    jurisdiction:  "US-DE",
    liability_sig: Ed25519(sponsor_did + agent_did + timestamp),
    verified_at:   "2026-04-17T00:00:00Z",
    expires_at:    "2027-04-17T00:00:00Z",
  },
  
  // Verifiable credentials (W3C VC — NEW)
  credentials: [
    CapabilityCredential  { capability: "read_crm", issuer, expires, sig },
    ComplianceCredential  { framework: "SOC2", scope: "data_handling", sig },
    ProvenanceCredential  { model: "gpt-4o", training_data_attestation, sig },
    IdentityCredential    { legal_entity_did, jurisdiction, tax_id_hash, sig },
  ],
  
  // Reputation (from ConnectorOS trust + NEW portable registry)
  reputation: {
    trust_score:          0.94,
    total_interactions:   142318,
    violations:           0,
    incident_count:       0,
    score_trend_90d:      [ ... ],
    cross_org_references: 3,      // Used and vouched for at 3 other orgs
  },
  
  // Audit chain (from ConnectorOS CID engine)
  audit_cid:   "bafybeig...",     // CID of latest audit chain entry
  revoked:     false,
  revoked_at:  null,
  revocation_reason: null,
}
```

All fields are signed. The passport is verifiable offline using the issuer's public key. The CID chain means any field tampering is detectable.

---

### 5.2 The Five Flows (what the product actually does day-to-day)

#### Flow 1: Agent Registration
```
Developer                    AgentPassport              ConnectorOS
    │                             │                          │
    ├── POST /agents/register ───►│                          │
    │   { name, capabilities,     │                          │
    │     sponsor_email }         │                          │
    │                             ├── mint DID ─────────────►│
    │                             │◄─ did:connector:abc123 ──┤
    │                             │                          │
    │                             ├── email sponsor ─────────►
    │                             │   "Approve this agent"   
    │                             │                          │
    │             Sponsor clicks approve (2FA required)      │
    │                             │                          │
    │                             ├── sign sponsorship chain  │
    │                             ├── issue initial VCs ─────►│
    │                             ├── activate passport       │
    │◄── passport: { did, ... } ──┤                          │
    
Result: agent has DID + sponsor chain + initial credentials
        externally verifiable from this moment
```

#### Flow 2: External Verification (the B2B use case)
```
Vendor                    Enterprise (buyer)         AgentPassport
    │                          │                          │
    │  "Our agent wants        │                          │
    │   to access your ERP"    │                          │
    │─────────────────────────►│                          │
    │                          │                          │
    │                          ├── POST /verify ─────────►│
    │                          │   { did: "did:...",       │
    │                          │     require_credentials:  │
    │                          │     ["SOC2","CapCRM"],    │
    │                          │     min_trust: 0.8 }      │
    │                          │                          │
    │                          │◄── verified: true ───────┤
    │                          │    passport: { ... }      │
    │                          │    proof: ed25519_sig     │
    │                          │                          │
    │◄── "Access granted" ─────┤                          │
    
3 seconds. No emails. No PDF review. Machine-readable trust decision.
```

#### Flow 3: Budget Breach → Sponsor Accountability
```
AgentPassport          ConnectorOS (LedgerLens)     Sponsor (human)
    │                          │                          │
    │◄── budget_breach event ──┤                          │
    │    { agent_did, amount }  │                          │
    │                          │                          │
    ├── lookup sponsor chain   │                          │
    ├── decrement reputation   │                          │
    ├── notify sponsor ────────────────────────────────► │
    │   "Your agent breached   │                          │
    │    $5K budget limit"     │                          │
    │                          │                          │
    │   Sponsor doesn't respond within 4h                 │
    │                          │                          │
    ├── auto-quarantine via ConnectorOS ──────────────────►
    ├── update passport: status=quarantined
    ├── CRL updated: agent's credentials suspended
    
External verifiers calling /verify now get: verified: false
```

#### Flow 4: Vendor Onboarding (replaces 3-week due diligence)
```
Procurement team hits:
  GET /attestation/{vendor_agent_did}/export?format=pdf

Gets back a signed PDF containing:
  ✅ Agent DID + creation date
  ✅ Sponsor: Jane Smith, Acme Corp, US-DE jurisdiction, liability signature
  ✅ Credentials: SOC2 Type II (issued by Drata), CRM Read (issued by Acme Security)
  ✅ Reputation: 0.94 trust score, 142,318 interactions, 0 violations, 3 org references
  ✅ Audit chain: CID bafybeig... (verifiable against ConnectorOS)
  ✅ Signature: AgentPassport instance sign, timestamp, hash of above
  
Vendor onboarding: 3 weeks → 3 minutes.
```

#### Flow 5: Incident Response
```
Agent makes unauthorized DB access attempt
  │
  ├── ConnectorOS DENY verdict
  ├── Incident created + CID logged
  ├── AgentPassport notified
  │
  ├── Reputation decrement: 0.94 → 0.71 (violation weight applied)
  ├── Sponsor notified: "Your agent attempted unauthorized access"
  ├── Incident report generated
  │
  If 3 violations within 30 days:
  ├── Auto-revoke: DID invalidated
  ├── CRL updated
  ├── All VCs revoked (cascade)
  ├── All federation peers notified
  ├── Audit package generated for legal
  
Agent cannot operate anywhere that checks the CRL.
```

---

### 5.3 Database Schema

```sql
-- Core passport
CREATE TABLE ap_agents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    did             TEXT UNIQUE NOT NULL,          -- did:connector:agent:...
    name            TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '1.0',
    org_id          UUID NOT NULL,
    agent_card      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending', -- pending|active|suspended|quarantined|revoked
    trust_score     NUMERIC(5,4) DEFAULT 1.0,
    total_interactions BIGINT DEFAULT 0,
    violation_count INT DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT,
    audit_cid       TEXT
);

-- Human sponsor chain
CREATE TABLE ap_sponsors (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES ap_agents(id),
    user_did        TEXT NOT NULL,
    user_email      TEXT NOT NULL,
    legal_entity    TEXT NOT NULL,
    jurisdiction    TEXT,
    liability_sig   TEXT NOT NULL,   -- Ed25519(agent_did + user_did + timestamp)
    verified_at     TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- W3C Verifiable Credentials
CREATE TABLE ap_credentials (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES ap_agents(id),
    credential_type TEXT NOT NULL,   -- CapabilityCredential|ComplianceCredential|ProvenanceCredential|IdentityCredential
    issuer_did      TEXT NOT NULL,
    issuer_name     TEXT NOT NULL,
    subject         JSONB NOT NULL,  -- credential-specific payload
    proof           TEXT NOT NULL,   -- Ed25519 signature
    issued_at       TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revocation_reason TEXT,
    vc_json         JSONB NOT NULL   -- full W3C VC JSON
);

-- Reputation registry (portable across deployments)
CREATE TABLE ap_reputation_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_did       TEXT NOT NULL,
    event_type      TEXT NOT NULL,   -- interaction|violation|commendation|federation_reference
    delta           NUMERIC(5,4) NOT NULL, -- score change (+/-)
    reason          TEXT,
    evidence_cid    TEXT,
    source_org_id   UUID,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Federation peers
CREATE TABLE ap_federation_peers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    peer_name       TEXT NOT NULL,
    peer_url        TEXT NOT NULL,
    trust_scope     JSONB NOT NULL DEFAULT '{}',  -- capability filters
    auto_trust      BOOL NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'pending',
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Certificate Revocation List
CREATE TABLE ap_crl (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    did             TEXT NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT,
    revoked_by      TEXT NOT NULL,
    published_crl_hash TEXT   -- for external verifiers to detect CRL freshness
);

-- Verification log (immutable)
CREATE TABLE ap_verification_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_did       TEXT NOT NULL,
    verifier_id     TEXT,           -- who verified (org, IP, or anonymous)
    required_credentials JSONB,
    min_trust_score NUMERIC(5,4),
    result          BOOL NOT NULL,
    failure_reason  TEXT,
    proof_sig       TEXT,
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Incidents
CREATE TABLE ap_incidents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES ap_agents(id),
    incident_type   TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'medium',
    description     TEXT NOT NULL,
    evidence_cid    TEXT,
    reputation_delta NUMERIC(5,4),
    sponsor_notified_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    auto_action     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log (append-only, never updated)
CREATE TABLE ap_audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type     TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    action          TEXT NOT NULL,
    actor_did       TEXT,
    payload         JSONB NOT NULL DEFAULT '{}',
    prev_cid        TEXT,
    this_cid        TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### 5.4 API Surface (the 14 endpoints that matter)

```
POST   /api/v1/agents/register           Register agent, initiate sponsor approval
GET    /api/v1/agents                    List all agents (directory)
GET    /api/v1/agents/:did               Agent detail + status
DELETE /api/v1/agents/:did/revoke        Revoke with reason, cascade

GET    /api/v1/passport/:did             Full passport: DID + sponsor + VCs + reputation
POST   /api/v1/verify                    External verification endpoint (public-facing)
GET    /api/v1/crl                       Certificate Revocation List (public, cacheable)

POST   /api/v1/credentials/issue         Issue W3C VC to an agent
POST   /api/v1/credentials/:id/revoke    Revoke specific credential

GET    /api/v1/reputation/:did           Reputation score + 90d trend + events
POST   /api/v1/sponsors/approve/:token   Sponsor approval (from email link)

GET    /api/v1/attestation/:did/export   PDF or JSON attestation pack (signed)

POST   /api/v1/federation/peers          Register federation peer
GET    /api/v1/federation/peers/:id/sync Import peer's agents

GET    /api/v1/incidents                 All incidents, filterable
GET    /api/v1/audit                     Audit log, filterable by entity/actor/action
```

The `/verify` and `/crl` endpoints are **public-facing** — no auth required. This is intentional: external verifiers must be able to check agent credentials without needing an account. This is the OIDC discovery pattern. It's what makes federation work.

---

### 5.5 The Verification Protocol

The single most important endpoint. Design it to be called from:
- Another AI agent (A2A trust check)
- A procurement automation script
- A compliance auditor's tool
- Another organization's AgentPassport instance (federation)
- A Mastercard Agent Pay gateway

```
POST /api/v1/verify
Authorization: Bearer (optional — anonymous verification allowed against public data)

{
  "did": "did:connector:agent:abc123",
  
  // What the verifier requires (all optional — flexible trust policy)
  "required_credentials":  ["ComplianceCredential:SOC2", "CapabilityCredential:read_crm"],
  "min_trust_score":       0.8,
  "require_active_sponsor":true,
  "max_violations":        0,
  "issued_after":          "2026-01-01"
}

→ 200 OK
{
  "verified":       true,
  "agent_did":      "did:connector:agent:abc123",
  "agent_name":     "billing-agent-v2",
  "trust_score":    0.94,
  "sponsor": {
    "name":         "Jane Smith",
    "legal_entity": "Acme Corp",
    "jurisdiction": "US-DE",
    "verified":     true
  },
  "credentials_verified": ["ComplianceCredential:SOC2", "CapabilityCredential:read_crm"],
  "violations":     0,
  "verified_at":    "2026-04-19T21:00:00Z",
  "expires_in_sec": 300,
  "proof": {
    "type":      "Ed25519Signature2020",
    "created":   "2026-04-19T21:00:00Z",
    "verificationMethod": "did:connector:agentpassport:instance#key-1",
    "signature": "z58DAdFfa9SkqZMVPxAQpic..."
  }
}

→ 200 OK (not verified)
{
  "verified":       false,
  "reason":         "trust_score_below_threshold",
  "trust_score":    0.61,
  "threshold":      0.80,
  "agent_did":      "did:connector:agent:xyz789",
  "verified_at":    "2026-04-19T21:00:00Z",
  "proof":          { ... }   ← signed even on failure, for audit
}
```

The proof is signed by the AgentPassport instance regardless of pass/fail. This means:
- The verifier can prove to a third party that verification happened
- The agent owner cannot dispute that verification was performed
- Compliance audit: "on this date, at this time, this agent passed/failed this verification"

---

### 5.6 Reputation Algorithm

Reputation is the moat. It cannot be gamed by redeploying.

```
Initial score: 1.0

Events that decrement:
  Minor violation (policy warning):        -0.02
  Moderate violation (policy deny):        -0.05
  Severe violation (unauthorized access):  -0.15
  Budget breach:                           -0.03
  Sponsor revocation:                      -0.30
  Security incident:                       -0.25

Events that increment:
  1,000 clean interactions:                +0.01 (capped at 1.0)
  Compliance credential issued:            +0.02
  Federation reference (another org):      +0.03
  Sponsor renewal:                         +0.01

Decay rules:
  Violations older than 180 days decay 50% per year
  Score cannot be reset by re-registration (DID is permanent)
  Minimum floor: 0.0 (cannot go negative)
  Recovery from 0.0 requires manual sponsor review + approval

Cross-deployment portability:
  When an org imports an agent via federation, they see the full reputation history
  They can choose to accept it, reject it, or apply their own floor
  "I'll trust any agent with score >= 0.7 from Acme" is a valid federation policy
```

---

### 5.7 How It Integrates With the ConnectorOS Portfolio

```
                    ┌─────────────────────────────────┐
                    │        AgentPassport             │
                    │   (identity + trust layer)       │
                    └──────────────┬──────────────────┘
                                   │ provides identity to
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
   ┌──────▼──────┐        ┌────────▼────────┐     ┌────────▼────────┐
   │  DevGuard   │        │   AgentLoop     │     │  LedgerLens     │
   │             │        │                 │     │                 │
   │ "Is this    │        │ "Is this agent  │     │ "Which sponsor  │
   │  agent      │        │  allowed on     │     │  is accountable │
   │  allowed to │        │  this mesh      │     │  for this       │
   │  edit this  │        │  route?"        │     │  $47K bill?"    │
   │  file?"     │        │                 │     │                 │
   └─────────────┘        └─────────────────┘     └─────────────────┘
          │                        │                        │
          └────────────────────────┼────────────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │          ConnectorOS             │
                    │      (enforcement kernel)        │
                    └─────────────────────────────────┘
```

Without AgentPassport: DevGuard, AgentLoop, and LedgerLens each have a local concept of "which agent is this" — but they're siloed.

With AgentPassport: every plugin asks the same question — "what does the passport say?" — and gets the same answer. One revocation propagates everywhere. One reputation event is visible everywhere. One sponsor is accountable for everything.

**AgentPassport is the identity bus for the entire ConnectorOS portfolio.**

---

## 6. Why This Beats Auth0 in the AI Domain

Auth0's actual product is: "Issue a JWT after a user authenticates. Put roles in it."

For humans behind browsers, that's sufficient. For AI agents, it fails on six dimensions:

| Dimension | Auth0 | AgentPassport |
|---|---|---|
| **Identity persistence** | User exists while account exists | Agent DID is permanent — reputation follows even after redeploy |
| **Liability chain** | No concept of "who is responsible for this user" | Sponsor chain baked in — legal entity, signature, jurisdiction |
| **Behavioral reputation** | No. JWT is issued based on credentials, not behavior | Trust score built from actual behavior across all deployments |
| **Third-party verification** | OIDC discovery lets others verify the token issuer, not the identity's behavior | `/verify` returns trust score, credentials, violations, sponsor chain |
| **Cross-org portability** | User federation via SAML/OIDC — well established | Agent federation: import trusted agents from other orgs with scoped policies |
| **Revocation with cascade** | Token expiry or revocation endpoint | Revoke DID → all credentials revoked → all federation peers notified → CRL updated → future verifications fail |
| **Standards compliance** | OAuth2 / OIDC — human-oriented | W3C VC + UCAN + DID + ERC-8004 + Mastercard Agent Pay — agent-native |
| **Audit chain** | Access logs only | CID-chained, tamper-evident audit of every identity event |
| **Compliance export** | API logs | Signed PDF/JSON attestation pack ready for vendor onboarding or auditors |

Auth0 cannot add these without becoming a different product. These aren't features — they're architectural decisions. Agents are not users. Treating them like users produces a credential system that fails at the first enterprise procurement question.

---

## 7. Build Phases — 16 Weeks to Auth0-Challenge

### Phase 1 — Identity core (weeks 1–4)
**Deliverable: "Every agent has a passport."**

- `POST /agents/register` → DID minting via ConnectorOS, sponsor email
- Sponsor approval flow (email link + 2FA, signs liability chain)
- Agent directory: list, filter, status
- Basic passport view: DID + sponsor + status
- Revocation: one click, CRL updated, cascade to ConnectorOS
- `GET /crl` — public endpoint, cacheable

**Who buys Phase 1**: Security teams who need an agent inventory now.

---

### Phase 2 — Credentials + External Verification (weeks 5–8)
**Deliverable: "Any external party can verify our agents in 3 seconds."**

- W3C VC issuer (CapabilityCredential, ComplianceCredential, ProvenanceCredential)
- VC verifier (library + API)
- `POST /verify` — public-facing, signed responses
- Attestation export: PDF + JSON (signed by AgentPassport instance)
- Basic incident tracking (link to ConnectorOS violations)

**Who buys Phase 2**: Procurement teams with vendor AI due diligence requirements. This is the deal-closer for enterprises being asked by their customers to prove their AI is safe.

---

### Phase 3 — Reputation + Federation (weeks 9–12)
**Deliverable: "Trust is portable. Revocation is instant everywhere."**

- Full reputation registry with decay algorithm
- Cross-incident tracking (violations follow the DID, not the deployment)
- Federation peer registration + scoped trust policies
- Revocation cascade to federation peers
- `GET /reputation/:did` — 90d trend, event log
- Cross-org agent import with inherited (or overridden) trust

**Who buys Phase 3**: Platform teams building multi-agent products who need a shared trust substrate. Enterprise deals where the buyer manages dozens of vendors.

---

### Phase 4 — Standards + CLI (weeks 13–16)
**Deliverable: "Compatible with every AI commerce and compliance standard."**

- ERC-8004 export/import adapter
- Mastercard Agent Pay format export
- On-chain anchoring (optional, opt-in via env flag)
- OIDC agent identity flow (for systems that speak OIDC)
- CLI: `agentpassport register / verify / revoke / export`
- Grafana dashboard for reputation + verification metrics

**Who buys Phase 4**: Fintech (Mastercard interop), crypto-native companies (ERC-8004), and regulated industries that need OIDC compatibility in their existing IAM stack.

---

## 8. Pricing

| Tier | Price | What you get |
|---|---|---|
| **Starter** | $99/mo | 25 agents, passport directory, basic credentials, internal verification |
| **Team** | $499/mo | 250 agents, W3C VCs, `/verify` API, PDF attestations, incident tracking |
| **Business** | $1,999/mo | Unlimited agents, reputation registry, federation (3 peers), compliance exports |
| **Enterprise** | $5K–$25K/mo | On-prem, ERC-8004 + Mastercard, unlimited federation, SLA, legal entity attestation, dedicated support |

**Enterprise budget owners**:
- Security: agent risk management line item
- Procurement: vendor onboarding automation (replaces consultant hours)
- Compliance: SOC2/ISO27001 evidence generation
- Legal: liability chain documentation for AI incidents

---

## 9. The One-Line Pitch Per Audience

| Audience | Pitch |
|---|---|
| **CISO** | "Know exactly which AI agents are running in your org, who owns them, and prove it to auditors in 3 minutes instead of 3 weeks." |
| **VP Procurement** | "Stop accepting a vendor's word that their AI is safe. Verify any agent's identity, capabilities, and behavior history with one API call." |
| **Platform engineer** | "Stop reinventing agent identity tokens. AgentPassport is the identity layer — issue, verify, revoke, federate. One service. All your agents." |
| **CFO** | "When your AI agent causes an incident, AgentPassport answers who is liable. Right now, nobody can answer that question." |
| **Compliance officer** | "HMAC-signed, CID-chained audit records of every agent identity event. SOC2 and EU AI Act evidence, produced automatically." |
| **Investor** | "Auth0 reached $6.5B by owning human identity for the web. AgentPassport owns agent identity for the AI era — a larger, faster-growing, and more legally consequential problem." |
