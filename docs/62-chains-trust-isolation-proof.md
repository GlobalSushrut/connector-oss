# 62 — Chains 7–9: Trust, Isolation, and Proof

> Deep documentation of the final three chains: the reputation score history, the namespace security perimeter audit, and the hierarchical proof tree that anchors everything.

---

## Chain 7 — The Trust Chain

**Implementation:** `connector-engine/src/reputation.rs`  
**API:** `GET /api/v1/agents/:pid` → `trust_score`  
**CLI:** `connectorctl review agent <pid>` → trust history

### What It Records

The Trust Chain is the complete, auditable history of how every agent's trust score evolved. An agent's trust score is not a static rating — it is a live measurement that updates with every verified interaction. The Trust Chain records every update: what happened, what changed, and who validated it.

Trust cannot be claimed. It can only be earned and observed.

### Trust Score Updates

Trust scores run from 0.0 (untrusted) to 1.0 (fully trusted). An agent starts with the trust level of the node that created it (typically 0.5–0.7 for a new node). From there, it goes up or down based on behavior:

**Trust increases from:**

| Interaction | Delta | Reason |
|------------|-------|--------|
| Grounded LLM output (score ≥ 0.90) | +0.003 | Output matches documented evidence |
| Correct HITL escalation | +0.005 | Agent correctly identified need for human review |
| Clean audit chain (no breaks) | +0.001/day | Consistent, unbroken operation |
| Successful proof generation | +0.002 | Full chain integrity verified |
| Peer agent validation | +0.004 | Another agent validated this agent's output |
| Schema-valid tool calls | +0.001 | All tool calls passed schema validation |

**Trust decreases from:**

| Event | Delta | Reason |
|-------|-------|--------|
| Ungrounded LLM output | -0.010 | Claim without evidence |
| Policy violation | -0.025 | Attempted action outside contract |
| Namespace violation attempt | -0.020 | Tried to access unauthorized namespace |
| Budget overrun attempt | -0.015 | Tried to exceed declared limits |
| Schema validation failure | -0.008 | Invalid tool call parameters |
| Audit chain gap | -0.050 | Break in audit integrity |
| HITL override required | -0.010 | Human had to intervene unexpectedly |

### Trust Chain Node Schema

```rust
pub struct TrustChainNode {
    pub node_id: String,
    pub agent_pid: String,
    pub score_before: f32,
    pub score_after: f32,
    pub delta: f32,
    pub trigger_type: TrustTrigger,
    pub trigger_cid: String,    // CID of the event that triggered this update
    pub validator: String,      // What validated this (system, peer agent, human)
    pub timestamp: String,
    pub prev_node_cid: String,
    pub node_cid: String,
}

pub enum TrustTrigger {
    GroundedOutput,
    UngroundedOutput,
    PolicyViolation,
    NamespaceViolation,
    CleanAudit,
    PeerValidation,
    HumanValidation,
    BudgetViolation,
    SchemaFailure,
    ChainGap,
}
```

### Trust-Based Routing

The Trust Chain feeds directly into the Agent DNS system (Chapter 54). When an agent queries the network for a specialist to delegate to, agents with higher trust scores are preferred. A malfunction — a series of ungrounded outputs, a policy violation — reduces the trust score, which reduces routing preference, which reduces the blast radius of a failing agent automatically.

```
Agent A (trust: 0.94) ──► receives routing preference
Agent B (trust: 0.61) ──► receives lower routing weight
Agent C (trust: 0.23) ──► receives no routing (below threshold)
```

The network self-heals through the trust system. No operator intervention required.

### Reading the Trust Chain

```bash
$ connectorctl review agent ag_a3f7b2

  trust_score:       0.94  (↑ from 0.87 over 30 days)
  trust_history:
    2026-04-14: +0.003  grounded_output (89/89 grounded this day)
    2026-04-13: +0.002  proof_verified
    2026-04-12: -0.010  ungrounded_output (1 claim without evidence, blocked)
    2026-04-12: +0.005  hitl_correct_escalation
    2026-04-11: +0.003  grounded_output
    ...
  total_interactions:  1,247
  grounding_rate:      99.9%  (1,246 / 1,247 grounded)
  violation_rate:      0.00%  (0 policy violations)
  chain_verified:      true
```

---

## Chain 8 — The Proof Chain

**Implementation:** `platform/server/src/services/proof_chain.rs`  
**API:** `POST /api/v1/proof/generate`, `POST /api/v1/compliance/verify`  
**CLI:** `connectorctl prove agent <pid>`

### What It Is

The Proof Chain is the root that anchors all other chains. It is a hierarchical attestation tree — a `ProofChainTree` — where every node either contains evidence directly (`Leaf`) or references and summarizes other nodes (`Aggregate`, `CrossReference`, `Temporal`).

When you call `generate_proof`, the Proof Chain assembles a bundle that contains or references all 8 other chains for the specified agent and time range. The bundle is self-contained and independently verifiable.

### ProofChainTree Node Types

```rust
pub enum ProofNodeType {
    Leaf,            // Raw evidence (a single journal entry, receipt, or chain node)
    Aggregate,       // Rollup of multiple leaf nodes
    CrossReference,  // Link to a node in another chain
    Temporal,        // Time-bounded proof (valid_from, valid_until)
}

pub struct ProofNode {
    pub node_id: String,
    pub node_type: ProofNodeType,
    pub content: ProofContent,
    pub children: Vec<String>,    // Child node IDs (for Aggregate)
    pub cross_ref: Option<String>, // Referenced node CID (for CrossReference)
    pub parent: Option<String>,
    pub timestamp: String,
    pub signature: Signature,     // Ed25519 signature
    pub compression: Option<CompressionInfo>,
    pub storage_tier: StorageTier,
}

pub struct ProofContent {
    pub data: serde_json::Value,   // The actual evidence or summary
    pub content_cid: String,       // CID of the content
    pub source_chain: String,      // Which of the 9 chains this came from
    pub actor: String,             // Who produced this evidence
    pub tags: Vec<String>,         // Regulation tags, event types
}
```

### Building a Proof Bundle

When `generate_proof` is called for agent `ag_a3f7b2`, the ProofChainTree is built as:

```
Root (Aggregate)
├── Audit Chain Summary (Aggregate)
│   ├── seq=1..500 (Temporal — first half, archived)
│   └── seq=501..1247 (Temporal — recent, hot storage)
├── Memory Chain Summary (Aggregate)
│   ├── /p/ namespace (CrossReference → IsolationChain)
│   ├── /m/ namespace (CrossReference → IsolationChain)
│   └── /k/ namespace (CrossReference → IsolationChain)
├── Dehallucination Summary (Aggregate)
│   └── 412 outputs: 412 grounded, 0 blocked (Aggregate)
├── Compliance Summary (Aggregate)
│   ├── HIPAA chain (CrossReference)
│   └── EU-AI-Act chain (CrossReference)
├── Governance Summary (Aggregate)
│   └── 1247 steps, 0 violations (Aggregate)
├── Execution Summary (Aggregate)
│   └── 203 receipts, chain verified (Aggregate)
├── Trust Chain Summary (Leaf)
│   └── current_score=0.94, history verified
└── Isolation Summary (Aggregate)
    └── all_chains_intact: true, violations_blocked: 2
```

The total bundle is a single JSON document with a Merkle root CID. Verification requires only SHA-256 and HMAC-SHA256 — no Connector installation needed.

### Storage Tiers: Long-Term Proof Retention

```rust
pub enum StorageTier {
    Hot,    // < 30 days — redb, in-memory+disk, instant access
    Warm,   // 30–365 days — SQLite, on-disk, fast access
    Cold,   // > 365 days — compressed archive, slow access but verifiable
}
```

Old proof nodes move to cold storage but remain verifiable. The Merkle structure ensures that a cold node can be verified by knowing its CID — you don't need to load all its siblings, just the path from root to the node.

**Delta Compression:** `compress_delta()` stores only the difference between two consecutive proof states rather than the full state. For long-running agents, this dramatically reduces storage while maintaining full verifiability.

**Merkle Pruning:** `compress_merkle_prune()` removes intermediate nodes while preserving the Merkle root and enough leaves to verify any path. An auditor can verify a specific claim without downloading the entire proof tree.

**Sparse Index:** `create_sparse_index()` creates an index at regular intervals (e.g., every 100 nodes) so that traversal of long chains is O(log n) rather than O(n).

---

## Chain 9 — The Isolation Chain

**Implementation:** `platform/server/src/services/namespace_isolation.rs`  
**Structures:** `IsolationChain`, `ChainLink`, `IsolationSummary`  
**CLI:** `connectorctl inspect <pid>` → isolation summary

### What It Records

The Isolation Chain is the namespace security perimeter audit. Every access to every namespace — read, write, delete, search — produces a chain link. Unauthorized attempts are recorded with `authorized: false` and trigger the configured containment action.

The Isolation Chain answers: "Has any data ever crossed a namespace boundary it wasn't supposed to?"

### IsolationChain Structure (from namespace_isolation.rs)

```rust
pub struct IsolationChain {
    pub namespace_id: String,    // e.g., "/p/hospital-a/patients/"
    pub trust_chain: Vec<ChainLink>,
    pub chain_hash: String,      // Current chain head — HMAC of all links
    pub chain_broken: bool,      // True if a break was detected
}

pub struct ChainLink {
    pub agent_pid: String,
    pub operation: AccessOperation,  // Read, Write, Delete, Search, Export, AdminOverride
    pub namespace: String,
    pub timestamp: Timestamp,
    pub chain_hash: String,    // HMAC(this link | prev chain_hash)
    pub authorized: bool,
    pub policy_matched: Option<String>, // Which policy rule authorized this
}
```

### Chain Break Handling

`handle_chain_breach()` is called when the isolation chain is broken. A break means either:
1. A write occurred outside the normal pipeline (bypassing chain extension)
2. An existing chain link was modified
3. A data race produced inconsistent chain state

Action sequence on breach:
```
Chain break detected in /p/hospital-a/
    │
    ├─► IsolationStatus::Breached (namespace locked)
    ├─► Alert: chain_breach event in Audit Chain (Chain 1)
    ├─► Alert: compliance chain entry with flag SECURITY_INCIDENT
    ├─► HITL escalation: requires operator review to unlock
    └─► Trust score delta: -0.050 for agent in breach context
```

### verify_all_chains()

```rust
pub fn verify_all_chains(&mut self) -> Vec<(String, bool)> {
    // Returns: [(namespace_id, chain_intact), ...]
}

pub struct IsolationSummary {
    pub intact_chains: usize,        // Namespaces with intact chains
    pub broken_chains: usize,        // Namespaces with breaks
    pub total_entries: usize,        // Total access events
    pub unauthorized_attempts: usize, // Blocked access attempts
    pub authorized_entries: usize,   // Normal authorized accesses
}
```

### Namespace Isolation in the Proof Bundle

The Isolation Chain is the last chain included in the Proof Bundle because it is the outermost boundary — if the isolation chain is intact across all namespaces, no data leaked. If it has breaks, the proof bundle must include the break details and the remediation actions.

```bash
$ connectorctl prove agent ag_a3f7b2

  === PROOF BUNDLE ===
  agent:          ag_a3f7b2
  proof_root:     soe1-sha256-d4e8f1a3b2
  
  [1] Audit Chain        ✓  1,247 entries  no breaks
  [2] Memory Chain       ✓  3 namespaces   no breaks
  [3] Dehallucination    ✓  412 outputs    412 grounded
  [4] Compliance         ✓  89 HIPAA       12 SOC2
  [5] Governance         ✓  1,247 steps    0 violations
  [6] Execution          ✓  203 receipts   no gaps
  [7] Trust              ✓  score=0.94     delta=+0.07/30d
  [8] Proof Chain        ✓  root verified  merkle_depth=4
  [9] Isolation          ✓  intact         2 attempts blocked

  ALL 9 CHAINS VERIFIED
  bundle_cid:     soe1-sha256-d4e8f1a3b2c9e1f5
  signature:      <Ed25519>
  verifiable_offline: true
```

---

## The 9 Chains Together: Why This Architecture

Each chain serves a distinct purpose. Together they cover every dimension of governance:

| Dimension | Chain | Question Answered |
|-----------|-------|------------------|
| What happened | 1 (Audit) | Complete event history |
| What was written | 2 (Memory) | Data provenance |
| Was it true | 3 (Dehall) | Grounding verification |
| Was it legal | 4 (Compliance) | Regulatory compliance |
| Was it authorized | 5 (Governance) | Contract enforcement |
| What did it do | 6 (Execution) | Action ledger |
| Should we trust it | 7 (Trust) | Behavioral reputation |
| Can we prove it | 8 (Proof) | Cryptographic attestation |
| Did anything leak | 9 (Isolation) | Boundary integrity |

No single chain answers all questions. No question goes unanswered. The 9 chains together make the governance claim total: every interaction, in every dimension, is documented and provable.
