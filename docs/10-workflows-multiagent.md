# 10 — Multi-Agent Coordination Workflows

> 25 workflow patterns for agent networks.

---

## MA-01: Agent Delegation Chain with Proof-of-Authority

**Rings:** 1, 5, 8 | **Tags:** all

A coordinator agent delegates to a specialist, with a cryptographic proof-of-authority at each hop.

```python
def delegate_to_specialist(coordinator_pid, specialist_pid, task, ns):
    # 1. Record delegation from coordinator
    dec = p.record_decision(coordinator_pid,
        "delegate.to_specialist",
        specialist_pid,
        "authorized",
        rationale=f"Task: {task['type']} requires specialist capability",
        confidence=0.95)

    delegation_id = dec["decision_id"]

    # 2. Write delegation token to shared namespace
    p.write_memory(coordinator_pid, json.dumps({
        "delegation_id": delegation_id,
        "from": coordinator_pid,
        "to": specialist_pid,
        "task": task,
        "authority": "coordinator",
        "expires_at": now_plus(minutes=30)
    }), memory_type="working", tags=["delegation"])

    # 3. Specialist reads and accepts delegation
    mem = p.recall_memory(f"m/shared/delegations", limit=5)
    # specialist verifies delegation_id is valid before proceeding

    return delegation_id
```

---

## MA-02: Consensus Voting Workflow

Three agents vote on a decision — majority wins.

```python
def consensus_vote(agents: list, proposal: str, ns: str) -> dict:
    votes = {}
    for agent_pid in agents:
        # Each agent independently evaluates
        fw = p.firewall_inspect(agent_pid, proposal, ns)
        vote = "reject" if fw.get("blocked") else "accept"
        votes[agent_pid] = vote

        p.record_decision(agent_pid, "consensus.vote",
                          proposal[:60], vote,
                          rationale=f"Agent {agent_pid} vote: {vote}")

    accept_count = sum(1 for v in votes.values() if v == "accept")
    majority     = "accept" if accept_count > len(agents) / 2 else "reject"

    # Record consensus outcome
    p.record_decision(agents[0], "consensus.result",
                      proposal[:60], majority,
                      rationale=f"{accept_count}/{len(agents)} voted accept",
                      confidence=accept_count / len(agents))
    return {"outcome": majority, "votes": votes}
```

---

## MA-03: Parallel Agent Fan-Out

```python
import concurrent.futures

def parallel_fanout(coordinator_pid, specialist_pids: list, task: dict):
    results = {}

    def run_specialist(spec_pid):
        p.record_decision(spec_pid, "fanout.task_received",
                          coordinator_pid, "accepted")
        result = process_task(spec_pid, task)
        p.record_decision(spec_pid, "fanout.task_complete",
                          coordinator_pid, "delivered")
        return spec_pid, result

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(specialist_pids)) as ex:
        futures = [ex.submit(run_specialist, pid) for pid in specialist_pids]
        for f in concurrent.futures.as_completed(futures):
            spec_pid, result = f.result()
            results[spec_pid] = result

    # Aggregate
    p.record_decision(coordinator_pid, "fanout.aggregated",
                      str(len(results)), "completed")
    return results
```

---

## MA-04: Specialist Agent Routing

```python
ROUTING_TABLE = {
    "cardiology": "agent_cardiology_specialist",
    "oncology":   "agent_oncology_specialist",
    "neurology":  "agent_neurology_specialist",
    "general":    "agent_general_practitioner"
}

def route_to_specialist(coordinator_pid, query: str) -> str:
    # LLM-based routing decision — governed
    response = p.invoke_chat(coordinator_pid,
        f"m/{coordinator_pid}",
        f"Which specialty handles: '{query}'? Reply with ONE word: "
        f"{', '.join(ROUTING_TABLE.keys())}")

    specialty = response.get("choices", [{}])[0] \
                        .get("message", {}).get("content", "general").strip().lower()
    specialist_pid = ROUTING_TABLE.get(specialty, ROUTING_TABLE["general"])

    p.record_decision(coordinator_pid, "routing.specialist_selected",
                      specialist_pid, "routed",
                      rationale=f"Query '{query[:40]}' → {specialty}")
    return specialist_pid
```

---

## MA-05: Agent-to-Agent Memory Share

```python
# Agent A writes to shared namespace
p.write_memory(agent_a_pid,
    json.dumps({"findings": findings, "source": "agent_a"}),
    memory_type="working",
    tags=["shared", f"for:{agent_b_pid}"])

# Agent B reads from shared namespace
# (namespace fencing must permit agent_b to read shared/)
shared_mem = p.recall_memory("m/shared", limit=10, memory_type="working")
findings = [json.loads(pkt["content"]) for pkt in shared_mem["packets"]
            if agent_b_pid in pkt.get("tags", [])]
```

---

## MA-06: Conflict Resolution between Agents

```python
def resolve_conflict(coordinator_pid, agent_a_decision, agent_b_decision):
    # Detect conflict
    if agent_a_decision["outcome"] == agent_b_decision["outcome"]:
        return agent_a_decision  # no conflict

    # Use LLM arbitration with governed chat
    arbitration_prompt = (
        f"Two agents disagree:\n"
        f"Agent A: {agent_a_decision['rationale']}\n"
        f"Agent B: {agent_b_decision['rationale']}\n"
        f"Which is correct? Reply with: A or B, then one sentence explanation."
    )
    response = p.invoke_chat(coordinator_pid, f"m/{coordinator_pid}/arbitration",
                             arbitration_prompt)
    winner = response["choices"][0]["message"]["content"][0].upper()  # "A" or "B"

    chosen = agent_a_decision if winner == "A" else agent_b_decision
    p.record_decision(coordinator_pid, "conflict.resolved",
                      "agent_disagreement", f"chose_{winner.lower()}",
                      rationale=response["choices"][0]["message"]["content"])
    return chosen
```

---

## MA-07: HITL Escalation Network

```python
def escalate_to_human(agent_pid, reason: str, data: dict):
    # Write to HITL-accessible namespace
    p.write_memory(agent_pid, json.dumps({
        "reason": reason,
        "data": data,
        "requires_human_decision": True,
        "urgency": "high"
    }), memory_type="working", tags=["hitl_pending"])

    p.record_decision(agent_pid, "hitl.escalated",
                      "human_review_queue", "pending",
                      rationale=reason, confidence=0.0)

    # Poll for human response
    for _ in range(36):   # 36 × 10s = 6 minutes
        pending = p.list_hitl_pending(agent_pid)
        if pending.get("count", 0) == 0:
            break
        time.sleep(10)

    return p.recall_memory(f"m/{agent_pid}/hitl_response", limit=1)
```

---

## MA-08: Peer Agent Trust Negotiation

```python
def negotiate_trust(initiator_pid, peer_pid):
    # Initiator presents credentials
    initiator_proof = p.generate_proof(initiator_pid, title="trust_credentials")

    # Write credentials to shared space
    p.write_memory(initiator_pid, json.dumps({
        "proof_id": initiator_proof.get("proof_id"),
        "requesting_trust_from": peer_pid,
        "capabilities": ["read_shared", "write_shared"]
    }), memory_type="working", tags=["trust_negotiation"])

    # Peer evaluates (in real system, triggered by event)
    p.record_decision(peer_pid, "trust.evaluated",
                      initiator_pid, "trusted",
                      rationale="Proof verified, capabilities within policy",
                      confidence=0.9)
```

---

## MA-10: Coordinator-Specialist-Validator Triad

Full three-agent pattern used in Demo 3/6:

```python
# Coordinator: routes and orchestrates
coordinator = p.register_agent("coordinator", "Routes tasks to specialists", 3)
c_pid = coordinator["pid"]

# Specialist: domain expert
specialist = p.register_agent("specialist", "Medical domain specialist", 3)
s_pid = specialist["pid"]

# Validator: checks specialist output against policy
validator = p.register_agent("validator", "Output policy validator", 3)
v_pid = validator["pid"]

# Workflow:
# 1. Coordinator receives task
dec_route = p.record_decision(c_pid, "route.task", s_pid, "delegated")

# 2. Specialist processes
response = p.invoke_chat(s_pid, f"m/{s_pid}", task_prompt)
specialist_output = response["choices"][0]["message"]["content"]

# 3. Validator checks
fw = p.firewall_inspect(v_pid, specialist_output, f"m/{v_pid}")
verdict = "approved" if not fw.get("blocked") else "rejected"
p.record_decision(v_pid, "validate.specialist_output", s_pid, verdict)

# 4. Coordinator surfaces result (only if approved)
if verdict == "approved":
    p.record_decision(c_pid, "surface.result", "output", "delivered")
```

---

## MA-12: Namespace Fencing in Multi-Agent

```python
# Prove that agents cannot read each other's private namespaces
agents = [a_pid, b_pid, c_pid]
for reader in agents:
    for writer in agents:
        if reader != writer:
            result = p.test_mac_enforcement(reader, f"m/{writer}/private")
            assert result["verdict"] == "DENY", \
                f"ISOLATION FAILURE: {reader} can read {writer}'s namespace"
print("✓ All namespace fences verified")
```

---

## MA-21: Agent Quorum Decision

```python
def quorum_decision(agent_pids: list, proposal: str, quorum: float = 0.67) -> bool:
    votes = [consensus_vote([pid], proposal, "m/shared")[outcome]
             for pid in agent_pids]
    accept_rate = votes.count("accept") / len(votes)
    passed = accept_rate >= quorum

    # Record quorum result
    p.record_decision(agent_pids[0], "quorum.result", proposal[:60],
                      "passed" if passed else "failed",
                      rationale=f"Accept rate: {accept_rate:.0%} (quorum: {quorum:.0%})",
                      confidence=accept_rate)
    return passed
```

---

## Multi-Agent Architecture Diagram

```
                    COORDINATOR (pid:C)
                    /       |       \
                   /        |        \
              SPEC-A    SPEC-B    SPEC-C
             (pid:A)   (pid:B)   (pid:C)
                   \        |        /
                    \       |       /
                     VALIDATOR (pid:V)
                          |
                     SURFACE OUTPUT

Namespace topology:
  /m/coordinator/     ← Coordinator private
  /m/specialist-a/    ← Spec-A private
  /m/shared/          ← Read: all; Write: Coordinator, Specialists
  /m/validator/       ← Validator private
  All fenced by Ring 4 MAC enforcement
```

---

## Next Steps

- **[11 — Architecture Overview](11-architecture-overview.md)**
- **[38 — Tutorial: Multi-Agent](38-tutorial-multiagent.md)**
- **[54 — Agent DNS Discovery](54-agent-dns-discovery.md)**
