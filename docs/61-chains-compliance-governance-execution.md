# 61 — Chains 4–6: Compliance, Governance, and Execution

> Deep documentation of chains four through six: the regulation-tagged decision ledger, the CCL contract enforcement record, and the tool dispatch receipt chain.

---

## Chain 4 — The Compliance Chain

**Implementation:** `platform/server/src/services/compliance.rs`  
**API:** `GET /api/v1/decisions`, `POST /api/v1/compliance/export`  
**CLI:** `connectorctl review agent <pid>` → compliance tags

### What It Records

Every governance decision that carries one or more regulation tags is added to the compliance chain. The compliance chain is the machine-readable regulatory ledger — the artifact that a compliance officer or regulator receives when they ask: "Prove this system is compliant."

It is separate from the Audit Chain (Chain 1) because:
- The Audit Chain records everything — compliance chain records only regulation-tagged events
- The Compliance Chain is queryable by regulation (`?regulation=hipaa`) — the Audit Chain is not filtered
- The Compliance Chain is the primary export artifact for regulatory submissions — the Audit Chain is the forensic tool

### Compliance Chain Node Schema

```rust
pub struct ComplianceChainNode {
    pub node_id: String,         // Unique ID for this compliance record
    pub decision_id: String,     // Links to the governance decision
    pub regulation_tags: Vec<String>, // ["hipaa", "soc2-tsc3", "eu-ai-act-art13"]
    pub agent_pid: String,
    pub action: String,          // What the agent did
    pub outcome: String,         // "allowed", "blocked", "escalated"
    pub rationale: String,       // Why this outcome
    pub phi_involved: bool,      // Was PHI part of this decision?
    pub llm_involved: bool,      // Was an LLM call part of this decision?
    pub hitl_required: bool,     // Was human review required?
    pub hitl_reviewer: Option<String>,
    pub timestamp: String,
    pub audit_cid: String,       // Links to Audit Chain (Chain 1) entry
    pub prev_node_cid: String,   // Chain linking
    pub node_cid: String,        // CID of this node
}
```

### Tagging Regulation Events

Regulation tags are applied at three levels:

**1. CCL contract level** — The contract declares what regulations apply to all its executions:
```ccl
governance {
    regulations = ["hipaa", "minimum-necessary"]
    hitl_threshold = 0.70
    audit_required = true
}
```

**2. Decision level** — Specific decisions can carry additional tags:
```python
platform.record_decision(
    agent_pid=pid,
    action="patient_data_access",
    outcome="allowed",
    regulation_tags=["hipaa", "soc2-tsc4"]
)
```

**3. Firewall level** — The guard pipeline adds tags when certain patterns trigger:
- PHI detection → adds `hipaa` tag automatically
- High-risk tool call → adds `soc2-tsc3` tag
- Cross-border data → adds `gdpr-cross-border` tag

### Querying the Compliance Chain

```bash
# All HIPAA events for last 30 days
$ GET /api/v1/decisions?regulation=hipaa&since=2026-03-14
  Returns: 89 compliance chain nodes, paginated

# Export for SOC 2 Type II assessment
$ POST /api/v1/compliance/export
  { "framework": "soc2", "period": "2026-Q1", "format": "json" }
  Returns: Complete evidence bundle with chain verification proof

# Summary view
$ connectorctl review agent ag_a3f7b2
  compliance_tags:
    hipaa:        89 events  (89 allowed, 0 blocked)
    soc2-tsc3:    47 events  (processing integrity)
    eu-ai-act:    89 events  (all chat interactions tagged)
  hitl_events:    3          (3 escalated, 3 resolved by reviewer)
  violations:     0
```

### The Compliance Chain as Evidence

The compliance chain is designed to be submitted directly to a compliance officer or auditor. Each node:
- Is content-addressed (CID-based) — the auditor can verify they received the unmodified chain
- References the Audit Chain (Chain 1) for full event detail
- Is signed by the node's Ed25519 keypair
- Is self-contained — verifiable without running Connector

---

## Chain 5 — The Governance Chain

**Implementation:** `connector-engine/src/cls/executor.rs`  
**API:** `GET /api/v1/decisions/:id` → CCL step detail  
**CLI:** `connectorctl explain <decision_id>` → full governance trace

### What It Records

The Governance Chain is the CCL contract execution record. Every step that the CLS executor runs produces a governance chain node. The chain is the machine-readable proof that the agent followed its contract — not just that the contract was deployed, but that every specific action was governed by a specific contract step.

This is the critical distinction: having a governance policy and actually enforcing it are different. The Governance Chain proves enforcement.

### Governance Chain Node Schema

```rust
pub struct GovernanceChainNode {
    pub step_id: String,          // Unique step execution ID
    pub contract_cid: String,     // cls1-sha256-* — which contract governed this
    pub step_name: String,        // Name from CCL contract
    pub step_type: StepOpType,    // Call, Write, Read, Emit, Branch, Require, etc.
    pub input_hash: String,       // Hash of step inputs (not content, for privacy)
    pub output_hash: String,      // Hash of step outputs
    pub state_before: String,     // CCL state machine state before step
    pub state_after: String,      // CCL state machine state after step
    pub predicate_result: bool,   // Did the predicate/guard pass?
    pub policy_applied: Vec<String>, // Active policy rules at this step
    pub budget_consumed: BudgetDelta, // Tokens/cost consumed by this step
    pub timestamp: String,
    pub audit_cid: String,        // Links to Audit Chain entry
    pub prev_step_cid: String,    // Chain link
    pub step_cid: String,
}
```

### Step Operations Recorded

Every CCL `StepOp` produces a governance chain node:

| StepOp | What it records |
|--------|----------------|
| `call` | Tool dispatch authorization, schema validation result |
| `write` | Memory write authorization, namespace check |
| `read` | Memory read authorization, namespace check |
| `emit` | Event emission record |
| `branch` | Which branch was taken and why (predicate result) |
| `require` | Guard condition result — pass or fail |
| `check_budget` | Budget status at this step |
| `await_hitl` | HITL queue entry, reviewer decision |

### Divergence Detection

The Governance Chain enables divergence detection — comparing what the agent actually did against what the contract said it should do:

```
Contract declares:
  Step 3: call tool="search" with params matching schema_v2

Governance Chain records:
  Step 3: call tool="search" with params NOT matching schema_v2
                  ↓
  Divergence detected: schema_v2 violation
  Action: block step, record policy_violation in Audit Chain
  Alert: governance_chain_divergence event
```

A divergence means the agent is behaving outside its contract — which means either the contract is wrong, the agent is malfunctioning, or the system has been compromised. Any of these is worth knowing immediately.

### Reading the Governance Chain

```bash
$ connectorctl explain dec_a3f7b2

  decision_id:     dec_a3f7b2
  contract_cid:    cls1-sha256-d4e8f1a3b2
  steps_executed:  4

  Step 1: require    context_available=true    ✓ PASSED
  Step 2: read       /m/session/patient/       ✓ authorized
  Step 3: call       search (schema_v2)        ✓ validated
  Step 4: write      /m/session/result/        ✓ authorized

  state_path:      idle → reading → processing → complete
  budget_consumed: 412 tokens ($0.0012)
  policy_applied:  [hipaa-minimum-necessary, budget-1000-tokens]
  governance_verified: true
  contract_followed: true
```

---

## Chain 6 — The Execution Chain

**Implementation:** `platform/server/src/services/audit_receipts.rs`  
**API:** `GET /api/v1/receipts`, `GET /api/v1/receipts/:id`  
**CLI:** `connectorctl prove agent <pid>` → `receipt_count`

### What It Records

Every tool dispatch — every real-world action the agent takes — produces a signed execution receipt. Receipts chain: each receipt references the previous receipt's CID for that agent. The Execution Chain is the action ledger: what the agent actually did in the world, in order, with cryptographic proof.

The distinction between the Governance Chain (what the contract authorized) and the Execution Chain (what actually happened) is important. In a correctly functioning system, they match. Any gap between them is a finding.

### Execution Receipt Schema

```rust
pub struct ExecutionReceipt {
    pub receipt_id: String,       // Unique receipt identifier
    pub receipt_cid: String,      // CID of this receipt: rcp-sha256-*
    pub prev_receipt_cid: String, // Chain link — previous receipt for this agent
    pub agent_pid: String,
    pub tool_name: String,        // Which tool was called
    pub params_hash: String,      // SHA-256 of parameters (not raw params, for privacy)
    pub params_schema: String,    // Schema version that validated the params
    pub result_hash: String,      // SHA-256 of result
    pub execution_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    pub governance_step_cid: String, // Links to Governance Chain node that authorized this
    pub audit_cid: String,           // Links to Audit Chain entry
    pub timestamp: String,
    pub node_signature: String,   // Ed25519 signature from the node keypair
}
```

### Chain Verification

```rust
pub async fn verify_receipt_chain(
    agent_pid: &str,
    start_receipt: &str,
) -> Result<ChainVerificationResult, Error>
```

Verification walks the chain from the latest receipt back to the declared start, confirming that every receipt's `prev_receipt_cid` matches the previous receipt's `receipt_cid`. A gap in the chain means a tool was called without producing a receipt — a governance failure.

### Real-World Examples

```
Execution Chain for deploy workflow:

rcp_001: tool=backup_config       params_hash=a3f7  ✓ success  3.2s
rcp_002: tool=update_config       params_hash=b4c8  ✓ success  1.1s
rcp_003: tool=validate_config     params_hash=c9d2  ✓ success  0.4s
rcp_004: tool=restart_service     params_hash=d4e8  ✓ success  8.7s
rcp_005: tool=check_health        params_hash=e5f9  ✓ success  0.2s

Chain verified: 5 receipts, 0 gaps, all signed
Total execution time: 13.6s
```

### Using Receipts for Determinism Proof

Two identical intents produce the same execution plan → the same sequence of receipts → the same ordered set of tool calls. The Execution Chain is the observable proof of determinism:

```bash
# Run 1 receipt chain
rcp_a01 → rcp_a02 → rcp_a03 → rcp_a04 → rcp_a05

# Run 2 receipt chain
rcp_b01 → rcp_b02 → rcp_b03 → rcp_b04 → rcp_b05

# Compare execution plans
$ connectorctl determinism verify \
    --receipts-1 rcp_a01..rcp_a05 \
    --receipts-2 rcp_b01..rcp_b05

  tool_sequence_match:   true
  params_schema_match:   true
  execution_order_match: true
  determinism_verified:  TRUE
```

This is what Demo 6's "killer moment" shows — and the Execution Chain is the technical foundation that makes it provable.
