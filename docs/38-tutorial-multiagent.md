# 38 — Tutorial: Multi-Agent Systems

> Build a coordinator-specialist-validator triad with governed delegation.

---

## What You'll Build

Three governed agents:
- **Coordinator** — receives tasks, routes to specialists
- **Specialist** — performs domain work
- **Validator** — checks specialist output against policy

---

## Step 1 — Register All Three Agents

```python
import sys, json, time
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

coordinator = p.register_agent("ma-coordinator", "Routes tasks to specialists", 3)
specialist  = p.register_agent("ma-specialist",  "Domain specialist", 3)
validator   = p.register_agent("ma-validator",   "Output policy validator", 3)

c_pid = coordinator["pid"]
s_pid = specialist["pid"]
v_pid = validator["pid"]

print(f"Coordinator: {c_pid}")
print(f"Specialist:  {s_pid}")
print(f"Validator:   {v_pid}")
```

---

## Step 2 — Coordinator Receives and Routes a Task

```python
task = {
    "type":    "research_query",
    "topic":   "renewable energy storage",
    "context": "technology briefing for executives"
}

# Coordinator: policy check before delegating
check = p.policy_check(c_pid, "delegate.task", s_pid)
print(f"Policy verdict: {check['verdict']}")

# Record delegation
delegation = p.record_decision(c_pid,
    "delegate.task",
    s_pid,
    "authorized",
    rationale=f"Routing '{task['type']}' to specialist",
    confidence=0.95)

delegation_id = delegation["decision_id"]
print(f"Delegation ID: {delegation_id}")

# Write task to shared memory
p.write_memory(c_pid,
    json.dumps({
        "delegation_id": delegation_id,
        "from":          c_pid,
        "to":            s_pid,
        "task":          task,
        "expires_at":    time.time() + 1800
    }),
    ptype="delegation",
    memory_type="working",
    tags=["delegation", f"to:{s_pid}"])
```

---

## Step 3 — Specialist Performs Work

```python
# Specialist checks firewall before processing
fw = p.firewall_inspect(s_pid, json.dumps(task), f"m/{s_pid}")
assert not fw["blocked"], f"Task blocked: {fw['final_decision']}"

# Specialist invokes governed LLM
response = p.invoke_chat(s_pid,
    f"m/{s_pid}",
    f"Write a 3-paragraph briefing on: {task['topic']}",
    system="You are a specialist researcher. Be concise and accurate.")

specialist_output = response["choices"][0]["message"]["content"]
specialist_cid    = response.get("audit_cid")

print(f"\nSpecialist output ({len(specialist_output)} chars):")
print(f"  {specialist_output[:100]}...")
print(f"  Audit CID: {specialist_cid}")

# Record specialist completion
p.record_decision(s_pid,
    "task.completed",
    delegation_id,
    "delivered",
    rationale=f"Research briefing generated, {len(specialist_output)} chars",
    confidence=0.90)

# Write output for validator to inspect
p.write_memory(s_pid,
    json.dumps({"output": specialist_output, "task": task,
                "delegation_id": delegation_id}),
    ptype="specialist_output",
    memory_type="evidence",
    tags=["output", f"delegation:{delegation_id}"])
```

---

## Step 4 — Validator Checks the Output

```python
# Validator: firewall inspect the specialist output
fw_validate = p.firewall_inspect(v_pid, specialist_output, f"m/{v_pid}")

pii_found    = fw_validate.get("pii_detected", False)
inj_score    = fw_validate.get("injection_score", 0)
policy_clean = not fw_validate.get("blocked", False)

# Validator records verdict
verdict = "approved" if (policy_clean and not pii_found and inj_score < 0.3) \
          else "rejected"

validation_decision = p.record_decision(v_pid,
    "validate.specialist_output",
    s_pid,
    verdict,
    rationale=(
        f"policy_clean={policy_clean}, "
        f"pii_detected={pii_found}, "
        f"injection_score={inj_score:.2f}"
    ),
    confidence=0.95 if verdict == "approved" else 0.99)

print(f"\nValidator verdict: {verdict}")
print(f"  Validation decision: {validation_decision['decision_id']}")
```

---

## Step 5 — Coordinator Surfaces the Result

```python
if verdict == "approved":
    # Coordinator records final delivery
    p.record_decision(c_pid,
        "surface.result",
        "executive_briefing",
        "delivered",
        evidence_cids=[specialist_cid],
        rationale=f"Validated by {v_pid}, delegation {delegation_id}",
        confidence=0.95)

    # Write final output
    p.write_memory(c_pid,
        json.dumps({
            "final_output":     specialist_output,
            "validated_by":     v_pid,
            "delegation_id":    delegation_id,
            "delivered_at":     time.time()
        }),
        ptype="final_output",
        memory_type="evidence",
        tags=["final", "validated"])

    print(f"\n✓ Task complete — output validated and delivered")
else:
    p.record_decision(c_pid,
        "surface.result",
        "executive_briefing",
        "blocked_by_validator",
        rationale=f"Validator rejected output: {validation_decision['decision_id']}")
    print(f"\n✗ Task blocked — validator rejected output")
```

---

## Step 6 — Generate a Multi-Agent Proof

```python
# Generate proof for each agent
for label, apid in [("coordinator", c_pid), ("specialist", s_pid), ("validator", v_pid)]:
    proof = p.generate_proof(apid, title=f"multiagent_{label}")
    print(f"{label}: proof_id={proof['proof_id']}")
```

---

## Step 7 — Verify Namespace Isolation

```python
# Confirm that coordinator cannot read specialist's private memory
isolation_check = p.test_mac_enforcement(c_pid, f"m/{s_pid}/private")
assert isolation_check["verdict"] == "DENY", "Isolation failure!"
print(f"✓ Namespace isolation enforced")
```

---

## Step 8 — Trace the Full Delegation Chain

```bash
connectorctl trace agent <coordinator_pid> --decisions
# Shows: delegate.task → surface.result

connectorctl trace agent <specialist_pid> --decisions
# Shows: task.completed

connectorctl trace agent <validator_pid> --decisions
# Shows: validate.specialist_output → approved/rejected
```

---

## Consensus Pattern (3-Agent Voting)

```python
def consensus_vote(agent_pids: list, proposal: str) -> str:
    votes = {}
    for apid in agent_pids:
        fw   = p.firewall_inspect(apid, proposal, f"m/{apid}")
        vote = "reject" if fw["blocked"] or fw["injection_score"] > 0.5 else "accept"
        votes[apid] = vote
        p.record_decision(apid, "consensus.vote", proposal[:60], vote,
                          confidence=0.9)

    accept_count = sum(1 for v in votes.values() if v == "accept")
    result = "accept" if accept_count > len(agent_pids) / 2 else "reject"

    # Record consensus outcome at coordinator
    p.record_decision(c_pid, "consensus.result", proposal[:60], result,
                      rationale=f"{accept_count}/{len(agent_pids)} voted accept",
                      confidence=accept_count / len(agent_pids))
    return result

result = consensus_vote([c_pid, s_pid, v_pid], "Deploy new model version")
print(f"Consensus result: {result}")
```

---

## Next Steps

- **[10 — Multi-Agent Workflows](10-workflows-multiagent.md)**
- **[39 — Tutorial: HITL](39-tutorial-hitl.md)**
- **[48 — Builder: Agent Roles](48-builder-agent-roles.md)**
