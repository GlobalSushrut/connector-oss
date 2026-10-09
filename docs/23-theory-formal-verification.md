# 23 — Formal Verification and Determinism Proofs

> How Connector makes governance claims mathematically verifiable.

---

## `formal_verify.rs` — The Verification Engine

Connector's formal verifier applies before deployment and at runtime. It operates on the CCL IR (intermediate representation) after compilation.

---

## The 11-Pass CCL Semantic Validator

Every compiled CCL contract passes through 11 semantic analysis passes:

### Pass 1: Name Resolution
Verify all referenced tools, namespaces, events, and states are declared. Undefined references = compile error.

### Pass 2: Tool Validation
Every `call <tool>` must reference a tool in `tools.yaml` or the node's tool registry. Undeclared tool calls are rejected.

### Pass 3: Memory Namespace Validation
Every `read` and `write` in the `memory` block must reference a declared namespace. Namespace patterns are validated against the node's namespace registry.

### Pass 4: State Machine Validation
- Initial state must be declared
- Every state must be reachable from initial
- Every transition must have a trigger event
- No state may have ambiguous transitions (same event → two different targets)

### Pass 5: Event Handler Validation
Every event referenced in `state` transitions must have a handler in the `events` block. Unhandled events = compile error.

### Pass 6: Branch Exhaustiveness
Every `branch` statement must cover all possible outcomes. If a branch has `confidence > 0.85` and `confidence <= 0.85 → emit low_confidence`, both arms must be handled.

### Pass 7: Type Checking
Template variables (`{{ input.patient_id }}`) must match declared types. Predicate comparisons must be type-compatible.

### Pass 8: Reachability Analysis
Dead code detection — any step that can never be reached is flagged as a warning or error (configurable).

### Pass 9: Termination Proof
Every execution path must terminate. The verifier checks for:
- Loops with a bounded iteration count (`loop N { ... }`)
- No unbounded recursion (CCL does not support recursion — verified at parse time)
- Every event handler must reach a terminal state or emit a progress event

### Pass 10: Budget Analysis
Static analysis of maximum possible token/cost consumption. If the maximum exceeds the declared budget, the contract is rejected.

### Pass 11: Regulation Tag Verification
Every action that touches a regulated namespace (`/p/`, PHI fields) must carry an appropriate regulation tag (`hipaa`, `gdpr`). Missing tags are compile errors.

---

## Determinism Proof

**Claim:** Given the same intent and the same memory state, the CLS executor always produces the same execution plan with the same cryptographic hash.

**Proof sketch:**

1. Intent is serialized to canonical CBOR → deterministic bytes → deterministic hash
2. Memory recall uses a deterministic ordering (by CID, ascending)
3. CCL execution is a pure function over (intent, memory state, contract) — no external randomness
4. The resulting execution plan is serialized to canonical CBOR → same content → same hash

**Verification:**
```python
import hashlib, json, cbor2

intent = {"task": "summarize", "patient_id": "p001"}
plan   = execute_ccl_contract(contract_cid, intent, memory_state)

plan_bytes = cbor2.dumps(plan, canonical=True)
plan_hash  = hashlib.sha256(plan_bytes).hexdigest()

# Running again with same inputs produces same plan_hash
```

---

## Policy Consistency Checking

Before policies are deployed, `formal_verify.rs` checks for contradictions:

```
Policy A: rule_1 — IF namespace=/p/ THEN allow (clearance >= 5)
Policy B: rule_2 — IF agent=medical-agent THEN allow /p/patients
```

These rules may conflict for agents with clearance < 5. The verifier detects the conflict and reports:
```
CONFLICT: rule_1 and rule_2 produce different verdicts for:
  agent: medical-agent, clearance: 3, namespace: /p/patients
  rule_1 → DENY (clearance < 5)
  rule_2 → ALLOW (agent match)
  Resolution: rule_1 takes priority (higher severity)
```

---

## CCL Operational Semantics

Formal semantics for key step operations:

### `require(predicate)`
```
Semantics:
  if eval(predicate, state) = false
  then raise PolicyViolation(predicate)
  else continue
```

### `write(ns, content)`
```
Semantics:
  pre:  agent.has_write_access(ns) = true
        firewall.inspect(content) = Allow
  post: memory[ns] = memory[ns] ∪ {CID(content) → content}
        journal.append(MemoryDeposit{ns, cid})
```

### `await_hitl(timeout)`
```
Semantics:
  emit HITLRequest(agent, reason, timeout)
  suspend execution
  on_approve: resume
  on_deny:    raise HITLDenied
  on_timeout: apply contract.on_timeout policy
```

---

## Model Checking for State Machine Completeness

The CCL state machine is modeled as a finite automaton. The verifier checks:

1. **Completeness:** Every input event has a defined handler in every state
2. **Determinism:** No state has two transitions triggered by the same event
3. **Safety:** No state transition leads to an "unsafe" state (defined by policy)
4. **Liveness:** From every state, the machine can eventually reach a terminal state

---

## Running Formal Verification

```bash
# Verify a CCL contract
connectorctl verify contract my_contract.ccl

# Verify a policy file
connectorctl verify policy policies/hipaa_minimum_necessary.yaml

# Verify consistency across all loaded policies
connectorctl verify policies --all

# Check execution plan determinism
connectorctl verify determinism --agent <pid> --intent '{"task": "summarize"}'
```

---

## Formal Verification Report

```bash
connectorctl prove agent <pid>   # includes formal verification results
```

```json
{
  "executive_summary": {
    "grade":              "A",
    "invariants_passed":  "5/6",
    "verdict":            "Invariant violations detected — review required",
    "agent_health_score": 85
  },
  "invariants": [
    {"name": "namespace_isolation",  "status": "passed"},
    {"name": "chain_integrity",      "status": "passed"},
    {"name": "pii_containment",      "status": "passed"},
    {"name": "budget_bounds",        "status": "passed"},
    {"name": "termination",          "status": "passed"},
    {"name": "policy_consistency",   "status": "warning",
     "detail": "2 rules with overlapping conditions"}
  ]
}
```

---

## Next Steps

- **[16 — Ring 5: Policy and Governance](16-ring-5-policy-governance.md)**
- **[05 — CCL Contracts](05-ccl-contracts.md)**
- **[51 — CLS System](51-cls-system.md)**
