# 09 — DevOps and Deterministic Execution Workflows

> 25 workflow patterns for infrastructure automation.

---

## DO-01: Governed Deployment Pipeline

**Rings:** 5, 7, 8 | **Tags:** soc2

```python
def governed_deploy(pid, service, version, environment):
    # Step 1: Policy gate
    check = p.policy_check(pid, "deploy", f"{service}:{version}:{environment}")
    if check["verdict"] != "ALLOW":
        raise RuntimeError(f"Deploy denied: {check['reason']}")

    # Step 2: Pre-deploy validation
    p.record_decision(pid, "deploy.validate", f"{service}@{version}",
                      "started", regulations=["soc2"])

    # Step 3: Dry-run first
    dry = p.mcp_invoke_tool("ops-bridge", "deploy",
                            pid, {"service": service, "version": version,
                                  "env": environment, "dry_run": True})

    if dry.get("errors"):
        p.record_decision(pid, "deploy.dry_run", service, "aborted",
                          rationale=f"Dry-run errors: {dry['errors']}")
        raise RuntimeError(f"Dry-run failed: {dry['errors']}")

    # Step 4: Execute deploy
    p.record_decision(pid, "deploy.execute", service, "executing")
    result = p.mcp_invoke_tool("ops-bridge", "deploy",
                               pid, {"service": service, "version": version,
                                     "env": environment})

    # Step 5: Seal proof
    proof = p.generate_proof(pid, title=f"deploy_{service}_{version}")
    return {"deployed": True, "proof_id": proof["proof_id"]}
```

---

## DO-02: Dependency-Ordered Multi-Step Workflow

```ccl
contract DependencyOrdered {
  intent: "Execute steps in declared dependency order"

  state {
    initial: waiting_deps
    waiting_deps -> step_a   on: deps_satisfied
    step_a       -> step_b   on: step_a_done
    step_b       -> step_c   on: step_b_done
    step_c       -> complete on: all_done
  }

  events {
    on step_a {
      require step_a_preconditions_met
      call run_step_a()
      emit step_a_done
    }
    on step_b {
      require step_a_completed   # enforced — cannot skip
      call run_step_b()
      emit step_b_done
    }
  }
}
```

---

## DO-03: Hash-Verified Deterministic Execution

**Key property:** Same intent → same execution plan → same hash.

```python
import hashlib, json

def deterministic_execute(pid, intent: dict) -> dict:
    # Canonical serialization
    intent_str  = json.dumps(intent, sort_keys=True)
    intent_hash = hashlib.sha256(intent_str.encode()).hexdigest()

    # Record intent with hash
    p.record_decision(pid, "execution.intent", intent_hash,
                      "accepted", regulations=["soc2"],
                      rationale=f"Deterministic execution: {intent_hash[:16]}")

    # Execute
    result = execute_plan(pid, intent)

    # Record result with hash
    result_str  = json.dumps(result, sort_keys=True)
    result_hash = hashlib.sha256(result_str.encode()).hexdigest()

    p.record_decision(pid, "execution.complete", intent_hash,
                      "completed",
                      rationale=f"Result hash: {result_hash[:16]}")

    return {"intent_hash": intent_hash, "result_hash": result_hash,
            "result": result}
```

---

## DO-04: Rollback on Failure with Audit

```python
def with_rollback(pid, action_fn, rollback_fn, action_name):
    # Record attempt
    p.record_decision(pid, f"{action_name}.start",
                      action_name, "attempting")
    try:
        result = action_fn()
        p.record_decision(pid, f"{action_name}.success",
                          action_name, "completed")
        return result
    except Exception as exc:
        # Record failure
        p.record_decision(pid, f"{action_name}.failure",
                          action_name, "failed",
                          rationale=str(exc))
        # Execute rollback
        p.record_decision(pid, f"{action_name}.rollback",
                          action_name, "rolling_back")
        rollback_fn()
        p.record_decision(pid, f"{action_name}.rollback_complete",
                          action_name, "rolled_back")
        raise
```

---

## DO-05: Cost-Bounded Compute Job

```python
def cost_bounded_job(pid, job_fn, max_usd=1.00):
    # Check budget before starting
    cost = p.get_agent_cost(pid)
    if cost.get("total_cost_usd", 0) >= max_usd:
        p.record_decision(pid, "job.budget_exceeded",
                          "compute_job", "denied",
                          rationale=f"Budget ${max_usd} already consumed")
        raise BudgetError(f"Budget exceeded: ${cost['total_cost_usd']:.4f}")

    result = job_fn()

    # Post-job cost check
    cost_after = p.get_agent_cost(pid)
    p.record_decision(pid, "job.complete", "compute_job",
                      "completed",
                      rationale=f"Cost: ${cost_after['total_cost_usd']:.4f}")
    return result
```

---

## DO-06: Schema-Validated API Call

```python
import jsonschema

def schema_validated_call(pid, url, payload, schema):
    # Validate schema before call
    try:
        jsonschema.validate(payload, schema)
    except jsonschema.ValidationError as e:
        p.record_decision(pid, "api.schema_violation", url,
                          "denied", rationale=str(e))
        raise

    # Firewall inspect
    fw = p.firewall_inspect(pid, json.dumps(payload), ns)
    if fw.get("blocked"):
        raise RuntimeError(f"Firewall blocked: {fw['final_decision']}")

    # Record and execute
    p.record_decision(pid, "api.call", url, "allow")
    return requests.post(url, json=payload)
```

---

## DO-07: Canary Release Governance

```python
def canary_release(pid, service, new_version, canary_pct=5):
    # Policy gate for canary
    check = p.policy_check(pid, "canary_release", service)
    assert check["verdict"] == "ALLOW"

    # Deploy canary
    p.record_decision(pid, "canary.deploy", service,
                      "started", rationale=f"{canary_pct}% traffic to {new_version}")

    deploy_canary(service, new_version, canary_pct)

    # Monitor for N minutes
    errors = monitor_canary(service, new_version, duration_minutes=10)

    if errors > 0.01:  # > 1% error rate
        p.record_decision(pid, "canary.rollback", service,
                          "rolling_back", rationale=f"Error rate: {errors:.2%}")
        rollback_canary(service)
    else:
        p.record_decision(pid, "canary.promote", service,
                          "promoting", rationale=f"Error rate: {errors:.2%}")
        promote_canary(service, new_version)
```

---

## DO-08: Infrastructure Drift Detection

```python
def detect_infra_drift(pid, expected_state: dict, actual_state: dict):
    drift = {}
    for resource, expected in expected_state.items():
        actual = actual_state.get(resource)
        if actual != expected:
            drift[resource] = {"expected": expected, "actual": actual}

    if drift:
        p.record_decision(pid, "infra.drift_detected",
                          json.dumps(list(drift.keys())),
                          "alert", regulations=["soc2"],
                          rationale=f"Drift in {len(drift)} resources",
                          confidence=1.0)

        # Write drift to memory for LLM analysis
        p.write_memory(pid, json.dumps({"drift": drift}),
                       ptype="infra_drift", memory_type="evidence")

    return drift
```

---

## DO-09: Execution Replay and Forensic Reconstruction

```python
def replay_session(pid, from_seq: int, to_seq: int):
    """Replay all tool calls in a session from the journal."""
    journal = p.get_books_journal(limit=1000)
    entries = [e for e in journal["entries"]
               if from_seq <= e.get("seq_no", 0) <= to_seq]

    replay_log = []
    for entry in entries:
        if entry.get("action") and "tool" in str(entry["action"]).lower():
            replay_log.append({
                "seq": entry["seq_no"],
                "action": entry["action"],
                "outcome": entry["outcome"],
                "replayed_at": now_iso()
            })

    p.record_decision(pid, "forensic.replay_complete",
                      f"seq:{from_seq}-{to_seq}",
                      "completed",
                      rationale=f"Replayed {len(replay_log)} tool calls")
    return replay_log
```

---

## DO-12: Dry-Run Before Execute

```python
def safe_execute(pid, tool, params):
    # 1. Dry-run
    dry = p.mcp_invoke_tool("ops-bridge", tool, pid,
                            {**params, "dry_run": True})
    if dry.get("error"):
        raise RuntimeError(f"Dry-run failed: {dry['error']}")

    p.record_decision(pid, f"{tool}.dry_run", tool,
                      "passed", rationale=str(dry.get("plan", "")))

    # 2. Execute
    result = p.mcp_invoke_tool("ops-bridge", tool, pid, params)
    p.record_decision(pid, f"{tool}.execute", tool, "completed")
    return result
```

---

## DO-17: Execution Proof for CI/CD Gate

```python
# In CI/CD pipeline — gate on proof verification
def cicd_proof_gate(pid) -> bool:
    proof = p.generate_proof(pid, title="cicd_gate")
    verify = p.get_verify_report()

    summary = verify.get("executive_summary", {})
    grade   = summary.get("grade", "F")
    passed  = grade in ("A", "B")

    print(f"Governance grade: {grade}")
    print(f"Proof ID: {proof.get('proof_id')}")
    print(f"Gate: {'PASS' if passed else 'FAIL'}")

    return passed

# Use in CI:
# if not cicd_proof_gate(pid):
#     sys.exit(1)
```

---

## DO-25: Automated Rollback Decision

```python
def auto_rollback_policy(pid, service, metrics):
    """Automatically decide whether to rollback based on metrics."""
    should_rollback = (
        metrics.get("error_rate", 0) > 0.05 or
        metrics.get("p99_latency_ms", 0) > 2000 or
        metrics.get("availability", 1.0) < 0.999
    )

    outcome = "rollback" if should_rollback else "continue"
    p.record_decision(pid, "deployment.auto_decision", service,
                      outcome, regulations=["soc2"],
                      rationale=(
                          f"error_rate={metrics.get('error_rate',0):.2%}, "
                          f"p99={metrics.get('p99_latency_ms',0)}ms, "
                          f"avail={metrics.get('availability',1):.4f}"
                      ), confidence=0.95)
    return should_rollback
```

---

## Execution Safety Matrix

| Risk Level | Pattern | Gate |
|---|---|---|
| Low | DO-06 Schema validation | Pre-call only |
| Medium | DO-12 Dry-run | Dry-run + execute |
| High | DO-01 Full pipeline | Policy + dry-run + HITL |
| Critical | DO-04 + DO-13 Saga | Two-phase commit + rollback |

---

## Next Steps

- **[10 — Multi-Agent Workflows](10-workflows-multiagent.md)**
- **[18 — Ring 7: Tool Execution](18-ring-7-tool-execution.md)**
- **[47 — Builder: Real Execution Control](47-builder-real-execution-control.md)**
