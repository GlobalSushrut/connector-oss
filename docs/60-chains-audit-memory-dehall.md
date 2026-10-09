# 60 — Chains 1–3: Audit, Memory, and Dehallucination

> Deep documentation of the first three chains: the primary event journal, the namespace write ledger, and the grounding validation system that makes hallucination detectable and provable.

---

## Chain 1 — The Audit Chain

**Implementation:** `platform/server/src/services/books.rs`  
**API:** `GET /api/v1/books/journal`, `GET /api/v1/books/position`  
**CLI:** `connectorctl prove agent <pid>`, `connectorctl trace agent <pid> --last 5m`

### Structure

The Audit Chain is the primary HMAC-linked journal. Every significant system event produces an entry. The chain is the single source of truth for what happened, when it happened, and who caused it.

```rust
// Journal entry schema
pub struct JournalEntry {
    pub seq: u64,              // Monotonically increasing sequence number
    pub cid: String,           // Content address of this entry: mem1-sha256-*
    pub prev_hmac: String,     // HMAC of the previous entry's content
    pub hmac: String,          // HMAC(this content | prev_hmac)
    pub event_type: EventType,
    pub agent_pid: Option<String>,
    pub namespace: Option<String>,
    pub payload: serde_json::Value,
    pub timestamp: String,
    pub audit_cid: String,     // Present on every mutating operation response
}
```

### Event Types Recorded

| Event Type | Trigger | Key Payload Fields |
|-----------|---------|-------------------|
| `agent_created` | `POST /api/v1/agents` | `agent_pid`, `contract_cid`, `namespace` |
| `agent_started` | `POST /api/v1/agents/:pid/start` | `agent_pid`, `boot_time` |
| `memory_write` | Any namespace write | `cid`, `namespace`, `packet_type` |
| `llm_call` | Governed chat | `model`, `tokens_in`, `tokens_out`, `context_namespaces` |
| `tool_dispatch` | Tool execution | `tool_name`, `params_hash`, `receipt_cid` |
| `decision_recorded` | `POST /api/v1/decisions` | `decision_id`, `outcome`, `regulations` |
| `firewall_block` | Guard pipeline denial | `denial_reason`, `injection_score`, `layer` |
| `hitl_queued` | HITL escalation | `hitl_id`, `reason`, `confidence` |
| `hitl_resolved` | Human review | `hitl_id`, `reviewer`, `decision` |
| `chain_verified` | `generate_proof` | `chain_integrity`, `entry_count` |
| `cell_migration` | Agent migration | `source_cell`, `dest_cell`, `memory_snapshot_cid` |
| `policy_violation` | CCL contract breach | `step`, `violation_type`, `blocked` |

### HMAC Chain Verification

The chain is verified by recomputing every HMAC from the chain head backwards:

```python
def verify_audit_chain(entries):
    """
    Given a list of journal entries in sequence order,
    verify the HMAC chain is unbroken.
    """
    import hmac, hashlib, json

    for i, entry in enumerate(entries[1:], 1):
        prev = entries[i-1]

        # Recompute: HMAC(current content | prev_hmac)
        expected_hmac = hmac.new(
            prev['hmac'].encode(),
            json.dumps(entry['payload'], sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        if expected_hmac != entry['hmac']:
            print(f"CHAIN BREAK at seq={entry['seq']}")
            return False

    return True
```

### The Causal Chain Within the Audit Chain

`books.rs` also records a `causal_chain` — a set of `CausalRef` entries within each journal entry that point to other entries that caused this one:

```rust
pub struct CausalRef {
    pub seq: u64,          // Sequence number of the cause
    pub cid: String,       // CID of the cause entry
    pub relation: String,  // "triggered_by", "response_to", "escalated_from"
}
```

This means the audit chain is not just a chronological list — it is a directed acyclic graph of causation. A compliance officer can ask: "What sequence of events led to this HITL escalation?" and trace the causal path through the journal.

### Reading the Audit Chain

```bash
# Last 5 minutes of audit events for an agent
$ connectorctl trace agent ag_a3f7b2 --last 5m

  seq=1243 [2026-04-14T00:18:01Z] memory_write        /m/session/ cid=mem1-sha256-a3f
  seq=1244 [2026-04-14T00:18:02Z] llm_call            tokens=412  grounded=true
  seq=1245 [2026-04-14T00:18:02Z] decision_recorded   dec_a3f7b2  outcome=allowed
  seq=1246 [2026-04-14T00:18:03Z] tool_dispatch       search      receipt=rcp_d4e8
  seq=1247 [2026-04-14T00:18:04Z] chain_verified      t0=true     entries=1247

# Full position (chain head)
$ GET /api/v1/books/position
  { "seq": 1247, "cid": "mem1-sha256-d4e8f1...", "hmac": "abc123..." }
```

---

## Chain 2 — The Memory Chain

**Implementation:** `platform/server/src/services/namespace_isolation.rs`  
**Structures:** `IsolationChain`, `ChainLink`, `NamespaceNode`  
**CLI:** `connectorctl inspect <pid>` → `chain_verified`, `namespace_violations`

### What It Records

The Memory Chain is not one chain — it is one chain per namespace. Every write to `/p/`, `/m/`, `/k/`, and `/s/` extends that namespace's chain. This means:

- The `/p/hospital-a/` chain records every PHI access in that namespace
- The `/m/agent-01/` chain records every memory write by agent-01
- A break in any namespace chain means something wrote to that namespace outside the normal pipeline

### Chain Structure

```rust
pub struct IsolationChain {
    pub namespace_id: String,
    pub trust_chain: Vec<ChainLink>,
    pub chain_hash: String,     // Current chain head
    pub chain_broken: bool,     // Alert flag
}

pub struct ChainLink {
    pub agent_pid: String,
    pub operation: AccessOperation,  // Read, Write, Delete, Search
    pub timestamp: Timestamp,
    pub chain_hash: String,    // HMAC(this link content | prev chain_hash)
    pub authorized: bool,      // Was this access authorized?
}

pub enum AccessOperation {
    Read,
    Write,
    Delete,
    Search,
    Export,
    AdminOverride,
}
```

### Chain Integrity Verification

```rust
// Verify all namespace chains simultaneously
let summary: IsolationSummary = isolation.verify_all_chains();

pub struct IsolationSummary {
    pub intact_chains: usize,    // Number of namespace chains that are intact
    pub broken_chains: usize,    // Number that have breaks
    pub total_entries: usize,    // Total access events across all chains
    pub unauthorized_attempts: usize,
}
```

### Leak Detection

`namespace_isolation.rs` also implements `LeakDetection` — watching for patterns that indicate data is crossing namespace boundaries without authorization:

```rust
pub struct LeakDetection {
    pub detected: bool,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub severity: LeakSeverity,
    pub evidence_cid: String,
}

pub enum LeakSeverity {
    Low,       // Potential false positive
    Medium,    // Suspicious pattern
    High,      // Likely leak
    Critical,  // Confirmed cross-namespace data exposure
}
```

A `Critical` leak detection triggers `IsolationStatus::Breached` on the namespace and initiates `handle_chain_breach()` — halting access to the namespace until an operator reviews and resets.

---

## Chain 3 — The Dehallucination Chain

**Implementation:** `platform/server/src/services/chain_tree.rs`  
**Node type:** `ChainNodeType::Dehallucination` with `DehallData`  
**CLI:** `connectorctl explain <decision_id>` → grounding sources

### The Hallucination Problem

An LLM can generate plausible-sounding text that is factually wrong. In governed AI systems, this is not just inaccurate — it is a governance failure. If a medical AI system tells a clinician that a drug dose is safe when it is not, and that claim was not grounded in documented evidence, every layer of the governance system has failed.

The Dehallucination Chain is the structural solution. It does not prevent the LLM from generating ungrounded text — that is impossible. It makes ungrounded text **detectable, blocked, and provable**.

### How It Works

After every LLM response, the grounding verification system (`grounding.rs`) runs:

1. **Extract claims:** Parse the LLM response into discrete claims
2. **Match to memory:** For each claim, search `/k/` and `/m/` for supporting evidence
3. **Score grounding:** Each claim receives a grounding score (0.0–1.0)
4. **Create chain nodes:** One `Dehallucination` chain node per claim

```rust
pub struct DehallData {
    pub claim_text: String,          // The LLM's claim
    pub grounding_score: f32,        // 0.0 = no evidence, 1.0 = fully grounded
    pub source_cids: Vec<String>,    // Memory packet CIDs that support the claim
    pub source_namespaces: Vec<String>, // Where the evidence came from
    pub verification_method: String, // "semantic_match", "exact_match", "causal_trace"
    pub grounded: bool,              // true if grounding_score >= threshold
}
```

### Chain Node Structure

```
Dehallucination Chain for one LLM response:

Node 1: Memory recall — /k/medical/cardiology/
  └── type: Memory
  └── kecs_score: 0.91
  └── content_cid: mem1-sha256-a3f7

Node 2: Memory recall — /m/session/patient-context/
  └── type: Memory
  └── kecs_score: 0.87
  └── content_cid: mem1-sha256-b4c8

Node 3: LLM claim — "Troponin elevation indicates cardiac injury"
  └── type: Dehallucination
  └── dehall_data.source_cids: [mem1-sha256-a3f7, mem1-sha256-b4c8]
  └── dehall_data.grounding_score: 0.94
  └── dehall_data.grounded: true    ← PASSES

Node 4: LLM claim — "Patient's condition is stable"
  └── type: Dehallucination
  └── dehall_data.source_cids: []   ← NO EVIDENCE
  └── dehall_data.grounding_score: 0.12
  └── dehall_data.grounded: false   ← FAILS
```

### What Happens When Grounding Fails

A grounding failure (score below threshold, no supporting CIDs) triggers one of three outcomes based on the CCL contract's governance block:

| Governance setting | Result |
|-------------------|--------|
| `on_hallucination: block` | Claim is removed from response, replaced with "I don't have evidence for this" |
| `on_hallucination: flag` | Claim is included but flagged with `[UNVERIFIED]` marker |
| `on_hallucination: hitl` | Response is held, queued for human review before surfacing |

The governance chain (Chain 5) records which action was taken and why.

### Connector Refuses to Fabricate

The canonical Connector behavior for an ungroundable claim:

```
LLM says: "The patient's last medication was aspirin 81mg daily"
                          ↓
Dehallucination check: Search /k/ and /m/ for aspirin + this patient
                          ↓
Result: No matching packets found (score: 0.08)
                          ↓
Governance: contract says on_hallucination: block
                          ↓
Response to user: "I don't have documented information about this
                   patient's current medications. Please check the
                   medication records directly."
                          ↓
Dehallucination chain node: BLOCKED, source_cids: [], grounded: false
Audit chain entry: hallucination_blocked, seq=1248
```

This is the "Connector said 'I don't know'" behavior from Demo 4 Phase 3 — implemented structurally, not through prompt engineering, and proven through the dehallucination chain.

### Verifying the Dehallucination Chain

```bash
$ connectorctl explain dec_a3f7b2c8

  decision_id:   dec_a3f7b2c8
  type:          llm_response
  outcome:       allowed
  claims_total:  7
  claims_grounded: 7
  claims_blocked:  0
  grounding_sources:
    - mem1-sha256-a3f7  (/k/medical/cardiology/guidelines/)  score=0.94
    - mem1-sha256-b4c8  (/m/session/patient-context/)         score=0.87
    - mem1-sha256-c9d2  (/k/medical/pharmacology/drug-db/)    score=0.91
  dehall_chain_cid:  chain1-sha256-d4e8f1...
  chain_verified:    true
```
