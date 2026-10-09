# 16 — Ring 5: Policy and Governance Engine

> CCL execution, decision recording, HITL, and regulation tagging.

---

## Overview

Ring 5 is the governance heart of Connector. Every agent action is evaluated against:
1. Active **policy rules** (`policies/*.yaml`)
2. The agent's **CCL contract** (if deployed)
3. **Budget limits**
4. **HITL queue** (if human review is required)

Every evaluation produces a **decision record** in the ledger.

---

## Policy Rule Evaluation

Policies are loaded from `policies/*.yaml` and compiled at boot. Rules are evaluated in priority order. First matching rule wins.

```yaml
# Policy evaluation order:
# 1. Deny rules (highest priority)
# 2. Allow-with-conditions rules
# 3. Allow rules
# 4. Default: deny (fail closed)
```

### Runtime Evaluation Flow

```
Incoming Action (e.g., mem_read /p/patients/p001)
    │
    ▼ Load active policies for this agent
    │
    ▼ Evaluate each rule in priority order
    │
    ▼ First match: apply action (allow / deny / redact / hitl)
    │
    ▼ No match: DENY (default)
    │
    ▼ Record decision in ledger (ring 8)
```

---

## CCL Contract Execution

When an agent has a deployed CCL contract, Ring 5 runs the CLS executor:

```
Agent Action
    │
    ▼ CLS executor checks: is this action in the contract?
    │
    ▼ Is the current state machine state valid for this step?
    │
    ▼ Do all require predicates pass?
    │
    ▼ Execute step operation
    │
    ▼ Record governance chain node
```

**Divergence detection:** If an agent tries to take a step not in its contract, the CLS executor blocks it and records a policy violation.

---

## Decision Recording (`record_decision`)

Every governance outcome — whether from policy evaluation, CCL execution, or firewall — produces a decision record.

```python
decision = p.record_decision(
    agent_pid=pid,
    action="summarize.patient_record",
    target="/p/patients/p001",
    outcome="allow_minimum_necessary",
    model_name="gpt-4o",
    rationale="Attending physician access, treatment purpose",
    confidence=0.95,
    evidence_cids=["mem1-sha256-abc..."],
    regulations=["hipaa", "soc2"]
)
```

**Response (top-level — no `.data` wrapper):**
```json
{
  "decision_id":          "dec_uuid...",
  "action":               "summarize.patient_record",
  "agent_pid":            "agent_abc123",
  "outcome":              "allow_minimum_necessary",
  "confidence":           0.95,
  "regulations":          ["hipaa", "soc2"],
  "audit_chain_verified": true,
  "immutable":            true,
  "content_hash":         "sha256:...",
  "signature":            "ed25519:...",
  "trust_grade":          "A",
  "public_key_hex":       "34d0bdcb..."
}
```

**Key properties:**
- `immutable: true` — cannot be modified after creation
- `audit_chain_verified` — confirms the HMAC chain is intact
- `signature` — Ed25519-signed by node keypair

---

## HITL (Human-in-the-Loop) Queue

When a policy rule or CCL contract requires human review, execution pauses and a HITL request is enqueued.

### Triggering HITL

Via CCL:
```ccl
events {
  on confidence_low {
    await_hitl {
      timeout: 3600
      reason: "Confidence below threshold — human review required"
    }
  }
}
```

Via policy rule:
```yaml
- id: treatment_recommendation_hitl
  condition:
    action: recommend_treatment
    agent_role: medical_assistant
  action: hitl
  timeout_seconds: 3600
  approvers: ["medical-officer"]
```

### Managing HITL Queue

```python
# Check pending
pending = p.list_hitl_pending(pid)
for req in pending["requests"]:
    print(f"Request {req['request_id']}: {req['reason']}")

# Approve
p.hitl_approve(pid, req["request_id"])

# Deny
p.hitl_deny(pid, req["request_id"])
```

### HITL Timeout

If no human responds within the timeout:
- CCL `on_timeout: deny` → action is denied, decision recorded
- CCL `on_timeout: allow` → action proceeds (rare — use only for low-risk)
- Default: deny

---

## Budget Governance

Budget enforcement at Ring 5:

```python
# Current budget status
cost = p.get_agent_cost(pid)
# {
#   "total_tokens_consumed": 4500,
#   "total_cost_usd": 0.012,
#   "budget_tokens": 100000,
#   "budget_pct": 4.5,
#   "budget_status": "ok"   # ok | warning | exceeded
# }
```

When budget is exceeded:
1. New LLM calls and tool calls are blocked
2. Decision record: `"budget_exceeded"` outcome
3. HITL request (if configured) or automatic deny

---

## Regulation Tags

Every decision can carry regulation tags. These populate the compliance chain:

```python
p.record_decision(pid, action, target, outcome,
                  regulations=["hipaa", "soc2", "gdpr", "eu_ai_act"])
```

Tags are queryable:
```python
# Get all HIPAA-tagged decisions
report = p.get_regulation_report("hipaa")
```

---

## Formal Verification (`formal_verify.rs`)

Policy consistency checking before deployment:

- Detects contradictions between policy rules
- Verifies CCL contract termination
- Checks state machine completeness
- Validates predicate types

Run verification:
```bash
connectorctl verify policy policies/hipaa_minimum_necessary.yaml
connectorctl verify contract contracts/medical_agent.ccl
```

---

## Policy Check API

```python
result = p.policy_check(pid, "mem_read", "/p/patients/p001")
# {
#   "verdict": "DENY",
#   "reason": "namespace_isolation: /p/ access requires clearance 5",
#   "enforcement": "kernel_policy"
# }
```

---

## Next Steps

- **[17 — Ring 6: Reasoning](17-ring-6-reasoning-llm.md)**
- **[30 — API: Governance](30-api-governance.md)**
- **[36 — Tutorial: CCL Workflows](36-tutorial-ccl-workflows.md)**
