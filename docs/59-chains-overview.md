# 59 — The 9 Chains: System Overview

> Connector's governance guarantees are implemented as nine distinct chain structures. A chain is a sequence of cryptographically-linked nodes where each node references its predecessor. Breaking a chain is detectable. Extending a chain requires authorization. Reading a chain produces a complete, ordered, tamper-evident history.

---

## What a Chain Is

A chain in Connector is not a metaphor. It is a data structure:

```
Node N:
  id:        <content address of this node>
  prev_id:   <content address of previous node>
  prev_hmac: <HMAC of previous node's content>
  hmac:      <HMAC(content + prev_hmac)>
  content:   <the actual data>
  timestamp: <when this node was written>
```

Three properties hold for every chain:

1. **Tamper-evident:** Any modification to any historical node changes its HMAC, which breaks the chain at that point. The break is detectable by anyone with the chain head.

2. **Append-only in practice:** While the data structure allows arbitrary modification, the system never modifies historical nodes. New data is always appended.

3. **Independently verifiable:** Given any chain head, a third party with no access to Connector can verify the chain's integrity using only SHA-256 and HMAC-SHA256.

---

## The 9 Chains at a Glance

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PROOF CHAIN (Chain 8)                           │
│          Root attestation tree — anchors all other chains               │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ contains or references
        ┌──────────────────────┼──────────────────────────┐
        │                      │                          │
        ▼                      ▼                          ▼
┌───────────────┐    ┌───────────────┐    ┌──────────────────────────────┐
│  AUDIT CHAIN  │    │ MEMORY CHAIN  │    │   DEHALLUCINATION CHAIN      │
│   (Chain 1)   │    │  (Chain 2)    │    │        (Chain 3)             │
│ HMAC journal  │    │ CID-linked    │    │ LLM outputs → source memory  │
│ every event   │    │ writes per    │    │ grounding validation nodes   │
│               │    │ namespace     │    │                              │
└───────────────┘    └───────────────┘    └──────────────────────────────┘

┌───────────────┐    ┌───────────────┐    ┌──────────────────────────────┐
│  COMPLIANCE   │    │  GOVERNANCE   │    │    EXECUTION CHAIN           │
│   CHAIN       │    │  CHAIN        │    │       (Chain 6)              │
│  (Chain 4)    │    │  (Chain 5)    │    │ Tool receipts, action ledger │
│ Regulation-   │    │ CCL contract  │    │                              │
│ tagged ledger │    │ step log      │    │                              │
└───────────────┘    └───────────────┘    └──────────────────────────────┘

┌───────────────┐    ┌───────────────┐
│  TRUST CHAIN  │    │  ISOLATION    │
│  (Chain 7)    │    │  CHAIN        │
│ Reputation    │    │  (Chain 9)    │
│ score history │    │ Namespace     │
│               │    │ access log    │
└───────────────┘    └───────────────┘
```

---

## Chain Descriptions

### Chain 1 — Audit Chain
**Location:** `services/books.rs`  
**What it records:** Every event in the system — memory writes, LLM calls, tool dispatches, policy decisions, HITL events, node boots, agent starts/stops.  
**Linking mechanism:** HMAC-SHA256 where each entry's HMAC is computed using the previous entry's HMAC as the key.  
**Verification command:** `connectorctl prove agent <pid>` → reports `t0_chain_verified: true/false`  
**Breaks if:** Any historical entry is modified or deleted.

### Chain 2 — Memory Chain
**Location:** `services/namespace_isolation.rs`  
**What it records:** Every write to every namespace. One chain per namespace.  
**Linking mechanism:** `chain_hash` field — HMAC of namespace access event + previous chain hash.  
**Verification command:** `connectorctl inspect <pid>` → `chain_verified` field  
**Breaks if:** A write occurs outside the normal pipeline, bypassing chain extension.

### Chain 3 — Dehallucination Chain
**Location:** `services/chain_tree.rs` (`ChainNodeType::Dehallucination`)  
**What it records:** Every LLM output linked to the memory packets that verify it. Unverifiable claims are recorded with no supporting links.  
**Linking mechanism:** `DehallData` — `source_cids: Vec<String>` linking output to evidence.  
**Verification command:** `connectorctl explain <decision_id>` → shows grounding sources  
**Breaks if:** An LLM output reaches the surface without a dehallucination check.

### Chain 4 — Compliance Chain
**Location:** `services/compliance.rs`  
**What it records:** Every governance decision tagged with one or more regulation identifiers (`hipaa`, `soc2`, `gdpr`, `eu-ai-act`).  
**Linking mechanism:** Sequential `decision_id` references with regulation tags.  
**Verification command:** `POST /api/v1/compliance/export?regulation=hipaa` → full HIPAA evidence bundle  
**Breaks if:** A regulated action occurs without a compliance chain entry.

### Chain 5 — Governance Chain
**Location:** `connector-engine/src/cls/executor.rs`  
**What it records:** Every CCL contract step executed — step name, contract CID, input, output, state transition.  
**Linking mechanism:** Execution step sequence with contract CID binding.  
**Verification command:** `connectorctl explain <decision_id>` → shows CCL step path  
**Breaks if:** An agent executes a step not declared in its contract.

### Chain 6 — Execution Chain
**Location:** `services/audit_receipts.rs`  
**What it records:** Every tool dispatch — tool name, parameters, result, agent PID, timestamp, receipt CID.  
**Linking mechanism:** `verify_receipt_chain()` — receipts reference previous receipt CID.  
**Verification command:** `connectorctl prove agent <pid>` → `receipt_count` + chain integrity  
**Breaks if:** A tool is called without producing a receipt, or a receipt is modified.

### Chain 7 — Trust Chain
**Location:** `connector-engine/src/reputation.rs`  
**What it records:** Every trust score update for every agent — interaction type, delta, new score, timestamp, validator.  
**Linking mechanism:** Sequential trust score history per agent.  
**Verification command:** `connectorctl review agent <pid>` → trust history  
**Breaks if:** A trust score is modified without a corresponding chain entry.

### Chain 8 — Proof Chain
**Location:** `services/proof_chain.rs`  
**What it records:** Hierarchical attestation tree — `Leaf` (raw evidence), `Aggregate` (rollup), `CrossReference` (link to other chains), `Temporal` (time-bounded proof).  
**Linking mechanism:** `ProofChainTree` with parent-child node relationships. Merkle structure for efficient partial verification.  
**Verification command:** `connectorctl prove agent <pid>` → generates and returns proof bundle  
**Breaks if:** Any referenced chain (1–7 or 9) has broken integrity.

### Chain 9 — Isolation Chain
**Location:** `services/namespace_isolation.rs` (`IsolationChain`)  
**What it records:** Every access to every namespace — authorized and unauthorized. The security perimeter audit.  
**Linking mechanism:** `ChainLink` with `chain_hash` — each access extends the namespace's isolation chain.  
**Verification command:** `connectorctl inspect <pid>` → `namespace_violations`, `chain_hash`  
**Breaks if:** A namespace is accessed through a path that bypasses the isolation engine.

---

## How the 9 Chains Relate

The chains are not independent. They cross-reference each other:

```
A single governed chat interaction produces entries in:

Chain 1 (Audit):       "llm_call event" with seq=1247
Chain 2 (Memory):      "context read from /m/" with chain_hash=abc
Chain 3 (Dehall):      "output grounded against 3 memory packets"
Chain 4 (Compliance):  "hipaa-tagged decision" decision_id=dec_a3f7
Chain 5 (Governance):  "CCL step chat_respond executed" contract=cls1-...
Chain 6 (Execution):   (no tool calls in this interaction)
Chain 7 (Trust):       "trust_score +0.002 for grounded output"
Chain 8 (Proof):       new Leaf node referencing all above
Chain 9 (Isolation):   "read /m/session/ authorized" chain_hash=def
```

When you call `generate_proof` for this agent, the Proof Chain assembles a bundle that includes or references all 9 chain entries for this interaction. The bundle is self-contained: a third party can verify it without any access to the live Connector node.

---

## The `connectorctl chain` Command

```bash
# Analyze the full chain for an agent
$ connectorctl chain analyze ag_a3f7b2

  Audit Chain:        ✓ intact  (seq 1-1247, 0 gaps)
  Memory Chain:       ✓ intact  (3 namespaces, 0 breaks)
  Dehallucination:    ✓ intact  (412 outputs, 412 grounded)
  Compliance Chain:   ✓ intact  (89 HIPAA entries, 12 SOC2)
  Governance Chain:   ✓ intact  (1247 steps, 0 policy violations)
  Execution Chain:    ✓ intact  (203 receipts, 0 gaps)
  Trust Chain:        ✓ intact  (current score: 0.94)
  Proof Chain:        ✓ intact  (root: soe1-sha256-d4e8f1)
  Isolation Chain:    ⚠ 2 unauthorized attempts (blocked)

# Diff two points in time
$ connectorctl chain diff ag_a3f7b2 --from 2026-04-01 --to 2026-04-14

  +1,247 audit entries
  +412 dehallucination validations
  +89 HIPAA compliance records
  +2 isolation violation attempts (both blocked)
  Trust score change: 0.87 → 0.94
```

---

## Generating the Unified Proof Bundle

`POST /api/v1/proof/generate` traverses all 9 chains and produces a single JSON proof bundle:

```json
{
  "agent_pid": "ag_a3f7b2",
  "generated_at": "2026-04-14T00:21:00Z",
  "proof_root": "soe1-sha256-d4e8f1a3b2c9",
  "chains": {
    "audit": { "verified": true, "entries": 1247, "head_hmac": "..." },
    "memory": { "verified": true, "namespaces": 3, "breaks": 0 },
    "dehallucination": { "verified": true, "outputs": 412, "grounded": 412 },
    "compliance": { "verified": true, "hipaa": 89, "soc2": 12 },
    "governance": { "verified": true, "steps": 1247, "violations": 0 },
    "execution": { "verified": true, "receipts": 203, "gaps": 0 },
    "trust": { "current_score": 0.94, "delta_30d": "+0.07" },
    "proof": { "root_cid": "soe1-sha256-d4e8f1", "depth": 4 },
    "isolation": { "intact": true, "violations_blocked": 2 }
  },
  "signature": "<Ed25519 signature of proof bundle>",
  "verifiable_without_connector": true
}
```

The bundle is signed by the node's Ed25519 keypair. Any verifier who trusts the node's public key can verify the bundle offline.
