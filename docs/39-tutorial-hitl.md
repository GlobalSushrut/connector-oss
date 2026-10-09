# 39 — Tutorial: Human-in-the-Loop (HITL)

> Add human review gates to governed agent workflows.

---

## When to Use HITL

| Situation | Why HITL |
|---|---|
| Confidence below threshold | Agent is uncertain — human decides |
| High-value irreversible action | Deploy, delete, send — require approval |
| Regulated domain | Medical treatment recommendation, legal advice |
| Policy ambiguity | Two rules conflict — escalate to human |
| Novel input | No precedent in memory — human judgment needed |

---

## Step 1 — Register an Agent with HITL Policy

```python
import sys, json, time
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

agent = p.register_agent("hitl-demo", "HITL demonstration agent", 3)
pid = agent["pid"]
ns  = agent["namespace"]
print(f"Agent: {pid}")
```

---

## Step 2 — Triggering HITL via Low Confidence

The most common trigger: confidence below threshold.

```python
# Simulate: agent has low confidence in its answer
question  = "Should we administer 500mg or 1000mg of the medication?"
confidence = 0.62   # below 0.85 threshold

# Agent records the uncertain decision and escalates
escalation = p.record_decision(pid,
    "medical.dosage_recommendation",
    question[:60],
    "escalated_to_hitl",
    rationale=f"Confidence {confidence:.0%} below threshold 0.85 — human review required",
    confidence=confidence,
    regulations=["hipaa"])

print(f"Escalation recorded: {escalation['decision_id']}")

# Write the pending recommendation to memory for human to review
p.write_memory(pid,
    json.dumps({
        "question":        question,
        "agent_reasoning": "Model suggests 500mg based on standard protocol, "
                           "but patient weight is above average.",
        "confidence":      confidence,
        "escalation_id":   escalation["decision_id"],
        "requires_review": True
    }),
    ptype="hitl_pending",
    memory_type="working",
    tags=["hitl", "medical", "pending_review"])
```

---

## Step 3 — Poll the HITL Queue

```python
pending = p.list_hitl_pending(pid)
print(f"\nPending HITL requests: {pending.get('count', 0)}")

for req in pending.get("requests", []):
    print(f"\nRequest: {req['request_id']}")
    print(f"  Reason:   {req.get('reason', 'N/A')}")
    print(f"  Created:  {req.get('created_at', 'N/A')}")
    print(f"  Timeout:  {req.get('timeout_at', 'N/A')}")
```

---

## Step 4 — Simulating the Human Review (Approval)

In production, a human reviewer would visit a dashboard. In this tutorial, we simulate it:

```python
if pending.get("count", 0) > 0:
    req_id = pending["requests"][0]["request_id"]

    # Simulate human approves
    result = p.hitl_approve(pid, req_id)
    print(f"\nHITL approved: {result}")

    # Record the human decision
    p.record_decision(pid,
        "hitl.human_review",
        req_id,
        "approved_by_human",
        rationale="Attending physician approved 500mg — standard protocol applies",
        confidence=1.0,
        regulations=["hipaa"])

    # Agent can now proceed
    print("Agent may proceed with the approved action")
```

---

## Step 5 — Handling HITL Timeout

When no human responds before the timeout:

```python
# Check if any requests timed out
journal = p.get_books_journal(limit=20)
timeouts = [e for e in journal.get("entries", [])
            if "timeout" in str(e.get("action", "")).lower()]

for t in timeouts:
    print(f"Timeout: {t['action']} → {t['outcome']}")
    # Record policy enforcement for timeout
    p.record_decision(pid,
        "hitl.timeout",
        t.get("action", "unknown"),
        "denied_by_timeout",
        rationale="No human response within timeout — action denied per policy",
        confidence=1.0)
```

---

## Step 6 — Denial Flow

```python
# Simulate HITL denial
if pending.get("count", 0) > 0:
    req_id = pending["requests"][0]["request_id"]

    result = p.hitl_deny(pid, req_id)
    print(f"HITL denied: {result}")

    # Record the denial
    p.record_decision(pid,
        "hitl.human_review",
        req_id,
        "denied_by_human",
        rationale="Reviewer: insufficient clinical context — request more information",
        confidence=1.0,
        regulations=["hipaa"])

    # Agent should abort this path and notify
    print("Action denied — agent must abort this task")
```

---

## HITL in a CCL Contract

```ccl
events {
  on analysis_complete {
    branch {
      confidence > 0.85 → emit summary_approved
      confidence <= 0.85 → emit low_confidence
    }
  }

  on low_confidence {
    # Write review request to memory
    write /m/{{ agent_pid }}/hitl_queue {
      content:    "Low confidence summary requires review",
      confidence: {{ confidence }},
      data:       {{ step.output }}
    }

    # Pause execution and wait for human
    await_hitl {
      timeout:  3600          # 1 hour
      reason:   "Confidence {{ confidence }} below threshold 0.85"
      on_approve: emit summary_approved
      on_deny:    emit task_aborted
      on_timeout: emit task_aborted
    }
  }
}
```

---

## Step 7 — HITL Audit Trail

Every HITL event is audited:

```bash
connectorctl trace agent <pid> --decisions

# Output includes:
# [seq]  DecisionRecorded   escalated_to_hitl
# [seq]  HITLRequested      pending
# [seq]  DecisionRecorded   approved_by_human / denied_by_human
```

```python
# Generate proof that includes HITL decisions
proof = p.generate_proof(pid, title="hitl_audit")
print(f"Proof with HITL decisions: {proof['proof_id']}")
```

---

## Production HITL Integration

In production, connect the HITL queue to a review dashboard:

```python
import threading, time

def hitl_monitor(pid, poll_interval_seconds=30):
    """Background thread that monitors HITL queue and notifies reviewers."""
    while True:
        pending = p.list_hitl_pending(pid)
        if pending.get("count", 0) > 0:
            for req in pending["requests"]:
                notify_reviewer(req)   # send email/Slack/webhook
        time.sleep(poll_interval_seconds)

def notify_reviewer(req):
    # Your notification logic here
    print(f"[NOTIFY] Review required: {req['request_id']}")
    print(f"         Reason: {req.get('reason')}")
    print(f"         Timeout: {req.get('timeout_at')}")
    # POST to Slack, send email, create Jira ticket, etc.
```

---

## Next Steps

- **[16 — Ring 5: Policy and Governance](16-ring-5-policy-governance.md)**
- **[30 — API: Governance](30-api-governance.md)**
- **[40 — Tutorial: HIPAA System](40-tutorial-compliance.md)**
