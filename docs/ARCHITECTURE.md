# AI Agent Architecture with Connector (VAC + AAPI)

This document shows how VAC and AAPI integrate into a standard AI agent architecture to provide verifiable memory and accountable actions.

---

## 1. Traditional AI Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRADITIONAL AI AGENT                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                      USER / APPLICATION                         │      │
│    └─────────────────────────────┬───────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                    AGENT FRAMEWORK                              │      │
│    │              (LangChain / LlamaIndex / AutoGPT)                 │      │
│    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │      │
│    │  │ Agent Loop   │  │   Prompts    │  │   Tool Orchestrator  │   │      │
│    │  └──────────────┘  └──────────────┘  └──────────────────────┘   │      │
│    └─────────────────────────────┬───────────────────────────────────┘      │
│                                  │                                          │
│              ┌───────────────────┼───────────────────┐                      │
│              │                   │                   │                      │
│              ▼                   ▼                   ▼                      │
│    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐           │
│    │       LLM        │ │     MEMORY       │ │      TOOLS       │           │
│    │  (GPT-4/Claude)  │ │  (Vector DB)     │ │  (APIs/Actions)  │           │
│    │                  │ │                  │ │                  │           │
│    │  • Reasoning     │ │  • Pinecone      │ │  • HTTP calls    │           │
│    │  • Generation    │ │  • Chroma        │ │  • File ops      │           │
│    │  • Extraction    │ │  • Mem0          │ │  • DB queries    │           │
│    └──────────────────┘ └──────────────────┘ └──────────────────┘           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                              ⚠️ PROBLEMS ⚠️

    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │  NO PROVENANCE  │  │  NO AUDIT TRAIL │  │ NO AUTHORIZATION│
    │                 │  │                 │  │                 │
    │ Can't prove     │  │ Can't trace     │  │ Agent can do    │
    │ when/where      │  │ what agent did  │  │ anything with   │
    │ memory learned  │  │ or why          │  │ no oversight    │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## 2. AI Agent Architecture with Connector (VAC + AAPI)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AI AGENT WITH CONNECTOR                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                      USER / APPLICATION                         │      │
│    └─────────────────────────────┬───────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │                    AGENT FRAMEWORK                              │      │
│    │              (LangChain / LlamaIndex / AutoGPT)                 │      │
│    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │      │
│    │  │ Agent Loop   │  │   Prompts    │  │   Tool Orchestrator  │   │      │
│    │  └──────────────┘  └──────────────┘  └──────────────────────┘   │      │
│    └─────────────────────────────┬───────────────────────────────────┘      │
│                                  │                                          │
│              ┌───────────────────┼───────────────────┐                      │
│              │                   │                   │                      │
│              ▼                   ▼                   ▼                      │
│    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐           │
│    │       LLM        │ │                  │ │                  │           │
│    │  (GPT-4/Claude)  │ │                  │ │                  │           │
│    │                  │ │                  │ │                  │           │
│    │  • Reasoning     │ │                  │ │                  │           │
│    │  • Generation    │ │                  │ │                  │           │
│    │  • Extraction    │ │                  │ │                  │           │
│    └──────────────────┘ │                  │ │                  │           │
│                         │                  │ │                  │           │
│    ╔══════════════════╗ │ ╔══════════════╗ │ │ ╔══════════════╗ │           │
│    ║   VAC MEMORY     ║ │ ║     VAC      ║ │ │ ║    AAPI      ║ │           │
│    ║   (Verifiable)   ║◄┼─║   Claims     ║ │ │ ║   Gateway    ║ │           │
│    ║                  ║ │ ║              ║ │ │ ║              ║ │           │
│    ║ • CID-addressed  ║ │ ║ • Extracted  ║ │ │ ║ • Authorize  ║ │           │
│    ║ • Merkle proofs  ║ │ ║ • Provenance ║ │ │ ║ • Sign       ║ │           │
│    ║ • Signed blocks  ║ │ ║ • Supersede  ║ │ │ ║ • Log        ║ │           │
│    ║ • RED learning   ║ │ ║              ║ │ │ ║ • Execute    ║ │           │
│    ╚══════════════════╝ │ ╚══════════════╝ │ │ ╚══════════════╝ │           │
│              │          │        │         │ │        │         │           │
│              │          │        │         │ │        ▼         │           │
│              │          │        │         │ │ ┌──────────────┐ │           │
│              │          │        │         │ │ │    TOOLS     │ │           │
│              │          │        │         │ │ │  (Adapters)  │ │           │
│              │          │        │         │ │ │              │ │           │
│              │          │        │         │ │ │ • File       │ │           │
│              │          │        │         │ │ │ • HTTP       │ │           │
│              │          │        │         │ │ │ • Database   │ │           │
│              │          │        │         │ │ │ • Custom     │ │           │
│              │          │        │         │ │ └──────────────┘ │           │
│              │          │        │         │ │        │         │           │
│              ▼          │        ▼         │ │        ▼         │           │
│    ╔══════════════════════════════════════════════════════════╗ │           │
│    ║              TRANSPARENCY & AUDIT LAYER                  ║ │           │
│    ║  ┌────────────────────┐  ┌────────────────────────────┐  ║ │           │
│    ║  │  VAC Attestation   │  │    AAPI IndexDB            │  ║ │           │
│    ║  │  Log (Memory)      │  │    (Actions)               │  ║ │           │
│    ║  │                    │  │                            │  ║ │           │
│    ║  │  • Event CIDs      │  │  • VĀKYA records           │  ║ │           │
│    ║  │  • Claim CIDs      │  │  • Effect records          │  ║ │           │
│    ║  │  • Block headers   │  │  • Receipts (PRAMĀṆA)      │  ║ │           │
│    ║  │  • Ed25519 sigs    │  │  • Merkle proofs           │  ║ │           │
│    ║  └────────────────────┘  └────────────────────────────┘  ║ │           │
│    ╚══════════════════════════════════════════════════════════╝ │           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                              ✅ SOLUTIONS ✅

    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │  VAC PROVENANCE │  │  FULL AUDIT     │  │ AAPI AUTHZ      │
    │                 │  │  TRAIL          │  │                 │
    │ Every memory    │  │ Every action    │  │ Every action    │
    │ has CID +       │  │ logged with     │  │ authorized by   │
    │ evidence link   │  │ Merkle proof    │  │ capability      │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## 3. Detailed Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE DATA FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  USER: "Book me a flight to NYC next Friday"                                │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 1: VAC - Store Input Event                                   │      │
│  │                                                                   │      │
│  │   Event {                                                         │      │
│  │     content: "Book me a flight to NYC next Friday"                │      │
│  │     cid: "bafy2bzace7x8k..."                                      │      │
│  │     timestamp: 2026-02-01T12:00:00Z                               │      │
│  │     source: { kind: "user", principal: "did:key:z6Mk..." }        │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   → Stored in Prolly Tree with Merkle proof                       │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 2: LLM - Extract Claims                                      │      │
│  │                                                                   │      │
│  │   LLM extracts structured claims:                                 │      │
│  │   • user.destination = "NYC"                                      │      │
│  │   • user.travel_date = "next Friday"                              │      │
│  │   • user.intent = "book_flight"                                   │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 3: VAC - Store Claims with Provenance                        │      │
│  │                                                                   │      │
│  │   ClaimBundle {                                                   │      │
│  │     subject: "user"                                               │      │
│  │     predicate: "destination"                                      │      │
│  │     value: "NYC"                                                  │      │
│  │     confidence: 0.95                                              │      │
│  │     evidence_cid: "bafy2bzace7x8k..."  ← Links to source event!  │      │
│  │     cid: "bafy2bzacewq9m..."                                      │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   → Claim CID computed from content                               │      │
│  │   → Evidence links to original event                              │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 4: AAPI - Create & Authorize Action                          │      │
│  │                                                                   │      │
│  │   VĀKYA {                                                         │      │
│  │     v1_karta: { pid: "agent:assistant", type: "ai_agent" }        │      │
│  │     v2_karma: { rid: "flight:search" }                            │      │
│  │     v3_kriya: { action: "flight.search" }                         │      │
│  │     v7_adhikarana: {                                              │      │
│  │       cap: { ref: "cap:user-alice-flights" }                      │      │
│  │       ttl: 3600                                                   │      │
│  │       budget: { max_cost: 1000 }                                  │      │
│  │     }                                                             │      │
│  │     body: { destination: "NYC", date: "2026-02-07" }              │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   → MetaRules engine checks authorization                         │      │
│  │   → Ed25519 signature applied                                     │      │
│  │   → Logged to IndexDB with Merkle proof                           │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 5: AAPI - Execute via Adapter                                │      │
│  │                                                                   │      │
│  │   HTTP Adapter executes:                                          │      │
│  │   POST https://api.flights.com/search                             │      │
│  │   { destination: "NYC", date: "2026-02-07" }                      │      │
│  │                                                                   │      │
│  │   Effect Record {                                                 │      │
│  │     before_state: null                                            │      │
│  │     after_state: { flights: [...] }                               │      │
│  │     vakya_id: "vakya-123"                                         │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   Receipt (PRAMĀṆA) {                                             │      │
│  │     status: "success"                                             │      │
│  │     duration_ms: 450                                              │      │
│  │     result: { flights: [...] }                                    │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   → All logged to IndexDB                                         │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │ STEP 6: VAC - Store Result & Commit Block                         │      │
│  │                                                                   │      │
│  │   Event {                                                         │      │
│  │     content: "Found 5 flights to NYC..."                          │      │
│  │     cid: "bafy2bzacepq7n..."                                      │      │
│  │     source: { kind: "agent", principal: "agent:assistant" }       │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   Block {                                                         │      │
│  │     block_no: 42                                                  │      │
│  │     prev_block: "bafy2bzace..."                                   │      │
│  │     events_root: "bafy2bzace..."  ← Merkle root of events        │      │
│  │     claims_root: "bafy2bzace..."  ← Merkle root of claims        │      │
│  │     signature: "ed25519:..."                                      │      │
│  │   }                                                               │      │
│  │                                                                   │      │
│  │   → Committed to attestation log                                  │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. What Connector Brings to the Architecture

### 4.1 VAC — Verifiable Memory

| Capability | Traditional | With VAC |
|------------|-------------|----------|
| **Storage** | Vector DB (row IDs) | Content-addressed (CID) |
| **Verification** | Trust the system | Cryptographic proof |
| **Provenance** | None | Evidence chain to source |
| **Contradictions** | Overwrite/lose | Superseding chain (audit) |
| **Learning** | Requires LLM | RED engine (no ML) |
| **Sync** | Server-dependent | Offline-first DAG |

**Key Benefits:**

1. **Prove What Was Learned**
   - Every memory has a unique CID computed from content
   - Can verify memory hasn't been tampered with
   - Merkle proofs for efficient verification

2. **Trace to Source**
   - Every claim links to evidence (source event CID)
   - Can answer "when did the agent learn this?"
   - Full provenance chain for compliance

3. **Handle Contradictions**
   - "I'm vegetarian" then "I love steak"
   - Both remain in chain (audit trail)
   - New claim supersedes old (latest is active)

4. **Learn Without ML**
   - RED engine uses information theory
   - Adjusts importance from retrieval feedback
   - No LLM API calls for learning

### 4.2 AAPI — Accountable Actions

| Capability | Traditional | With AAPI |
|------------|-------------|-----------|
| **Authorization** | None or basic | Capability tokens with caveats |
| **Audit** | Application logs | Merkle transparency log |
| **Attribution** | Unclear | Signed VĀKYA envelopes |
| **Rollback** | Manual | Effect records (before/after) |
| **Policy** | Hardcoded | Declarative MetaRules |

**Key Benefits:**

1. **Authorize Before Execute**
   - Capability tokens define what agent can do
   - Caveats for fine-grained control (TTL, budget, scope)
   - MetaRules engine for policy enforcement

2. **Sign Every Action**
   - Ed25519 signatures on VĀKYA envelopes
   - Non-repudiation: can prove who did what
   - DSSE format for payload type binding

3. **Log Everything**
   - Append-only IndexDB with Merkle proofs
   - VĀKYA (request) + Effect (state change) + Receipt (result)
   - Inclusion proofs for any record

4. **Enable Rollback**
   - Effect records capture before/after state
   - Can reconstruct what changed
   - Supports undo operations

### 4.3 Combined Benefits

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CONNECTOR BENEFITS MATRIX                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   QUESTION                    │  TRADITIONAL  │  WITH CONNECTOR             │
│   ─────────────────────────────────────────────────────────────────────     │
│                                                                             │
│   "What does the agent know?" │  Query DB     │  VAC: List claims with CIDs │
│                               │  (trust it)   │  (verify any claim)         │
│                                                                             │
│   "When did it learn that?"   │  Unknown      │  VAC: Evidence CID →        │
│                               │               │  source event timestamp     │
│                                                                             │
│   "Can the agent do this?"    │  Maybe check  │  AAPI: Capability token     │
│                               │  permissions  │  with caveats               │
│                                                                             │
│   "What did the agent do?"    │  App logs     │  AAPI: IndexDB with         │
│                               │  (incomplete) │  Merkle proofs              │
│                                                                             │
│   "Who authorized it?"        │  Unclear      │  AAPI: Signed VĀKYA         │
│                               │               │  with capability ref        │
│                                                                             │
│   "Can we undo this?"         │  Maybe        │  AAPI: Effect record        │
│                               │               │  with before/after state    │
│                                                                             │
│   "Is this compliant?"        │  Manual audit │  VAC + AAPI: Full chain     │
│                               │               │  from intent to execution   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Use Case Examples

### 5.1 Healthcare AI Assistant

**Scenario**: AI assistant helps doctors with patient information.

```
Patient says: "I'm allergic to penicillin"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ VAC stores:                                                     │
│   Event CID: bafy2bzace...                                      │
│   Claim: patient.allergy = "penicillin" (confidence: 0.95)      │
│   Evidence: links to event CID                                  │
│   Block: signed, timestamped                                    │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
Later, doctor asks: "Does this patient have any allergies?"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ VAC retrieves:                                                  │
│   Claim: patient.allergy = "penicillin"                         │
│   Provenance: Learned on 2026-02-01 from patient statement      │
│   Proof: Merkle proof available                                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
Regulator asks: "Prove the system knew about the allergy"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ VAC provides:                                                   │
│   • Claim CID (content hash)                                    │
│   • Evidence CID (source event)                                 │
│   • Block signature (timestamp proof)                           │
│   • Merkle inclusion proof                                      │
│                                                                 │
│ CRYPTOGRAPHIC PROOF that the system knew, when it learned,      │
│ and from whom.                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Financial AI Agent

**Scenario**: AI agent executes trades on behalf of user.

```
User says: "Buy 100 shares of AAPL if it drops below $150"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ VAC stores intent:                                              │
│   Event: "Buy 100 shares of AAPL if it drops below $150"        │
│   Claim: user.order = { symbol: AAPL, qty: 100, limit: 150 }    │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
Price drops to $149.50, agent acts:
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ AAPI authorizes and executes:                                   │
│                                                                 │
│   VĀKYA {                                                       │
│     actor: agent:trading-bot                                    │
│     action: trade.buy                                           │
│     resource: stock:AAPL                                        │
│     capability: cap:user-alice-trading                          │
│       caveats: { max_value: $20000, symbols: [AAPL, GOOGL] }    │
│     body: { qty: 100, price: 149.50 }                           │
│   }                                                             │
│                                                                 │
│   → Signed with Ed25519                                         │
│   → Logged to IndexDB                                           │
│   → Executed via broker adapter                                 │
│                                                                 │
│   Effect: { before: { cash: $50000 }, after: { cash: $35050 } } │
│   Receipt: { status: success, order_id: "ORD-123" }             │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
Compliance audit: "Show all trades and authorizations"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ AAPI + VAC provide:                                             │
│                                                                 │
│   1. User intent (VAC event with CID)                           │
│   2. Extracted order (VAC claim with evidence link)             │
│   3. Authorization (AAPI capability token)                      │
│   4. Execution request (AAPI signed VĀKYA)                      │
│   5. State change (AAPI effect record)                          │
│   6. Result (AAPI receipt with Merkle proof)                    │
│                                                                 │
│ COMPLETE AUDIT TRAIL from user intent to trade execution.       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Summary

### What Connector Adds

| Layer | Component | What It Provides |
|-------|-----------|------------------|
| **Memory** | VAC | Verifiable, provenance-tracked, non-ML learning |
| **Actions** | AAPI | Authorized, signed, logged, auditable |
| **Transparency** | Both | Merkle proofs, cryptographic verification |

### The New Guarantees

1. **Verifiability**: Every memory and action can be cryptographically verified
2. **Provenance**: Complete chain from user intent to system action
3. **Accountability**: Clear attribution of who did what and why
4. **Auditability**: Compliance-ready logs with inclusion proofs
5. **Reversibility**: Effect records enable understanding and rollback

### One Sentence

> **Connector (VAC + AAPI) transforms AI agents from black boxes into transparent, accountable systems where every memory can be proven and every action can be audited.**
