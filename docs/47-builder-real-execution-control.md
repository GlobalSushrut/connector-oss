# 47 — Builder: Real Execution Control

> Govern deterministic tool execution, saga patterns, and infrastructure automation.

---

## The Core Principle

Real execution control means: **the agent can only do what is explicitly declared, and every execution is cryptographically receipted.**

```
Declared intent (CCL contract)
    │
    ▼ Ring 5: Policy check — is this in the contract?
    │
    ▼ Ring 7: Schema validation — are args valid?
    │
    ▼ Budget check — is there capacity?
    │
    ▼ Execute
    │
    ▼ Receipt generated (signed, chained)
    │
    ▼ Evidence stored
    │
    ▼ Journal entry
```

---

## Step 1: Define What Can Execute

```yaml
# tools.yaml — execution allowlist
tools:
  - name: restart_service
    description: "Restart a named systemd service"
    parameters:
      service:
        type: string
        enum: [nginx, connector, api-server]   # ONLY these services
    required: [service]
    required_clearance: 4
    audit: true
    dry_run_available: true

  - name: run_migration
    description: "Run a named database migration"
    parameters:
      migration_name:
        type: string
        pattern: "^[a-z0-9_]{5,50}$"         # strict pattern
      environment:
        type: string
        enum: [staging, production]
    required: [migration_name, environment]
    required_clearance: 4
    audit: true
    dry_run_available: true
    requires_hitl:
      environment: production                  # HITL required for production
```

---

## Step 2: Dry-Run Before Execute

```python
def safe_execute(pid, tool, params, bridge="ops-bridge"):
    """Always dry-run before actual execution."""

    # 1. Dry-run
    dry = p.mcp_invoke_tool(bridge, tool, pid,
                            tool_input={**params, "dry_run": True})

    if dry.get("error"):
        p.record_decision(pid, f"{tool}.dry_run_failed", tool,
                          "aborted", rationale=dry["error"])
        raise RuntimeError(f"Dry-run failed: {dry['error']}")

    plan = dry.get("plan", [])
    p.record_decision(pid, f"{tool}.dry_run_passed", tool,
                      "plan_approved",
                      rationale=f"Plan: {'; '.join(plan[:3])}")

    # 2. Execute
    p.record_decision(pid, f"{tool}.execute_start", tool, "executing")
    result = p.mcp_invoke_tool(bridge, tool, pid, tool_input=params)

    outcome = "completed" if not result.get("error") else "failed"
    p.record_decision(pid, f"{tool}.execute_done", tool, outcome,
                      rationale=str(result.get("error") or "Success"))

    return result
```

---

## Step 3: Saga with Compensation

For multi-step operations where partial failure must be reversed:

```python
class Saga:
    """Execute a sequence of steps with compensating actions for rollback."""

    def __init__(self, pid: str):
        self.pid         = pid
        self.steps       = []
        self.completed   = []

    def add_step(self, name: str, execute_fn, compensate_fn):
        self.steps.append({
            "name": name,
            "execute":    execute_fn,
            "compensate": compensate_fn
        })
        return self

    def run(self) -> dict:
        for step in self.steps:
            p.record_decision(self.pid, f"saga.step.{step['name']}",
                              "saga", "executing")
            try:
                result = step["execute"]()
                self.completed.append(step)
                p.record_decision(self.pid, f"saga.step.{step['name']}",
                                  "saga", "completed")
            except Exception as exc:
                p.record_decision(self.pid, f"saga.step.{step['name']}",
                                  "saga", "failed",
                                  rationale=str(exc))
                self._rollback()
                return {"ok": False, "failed_at": step["name"], "error": str(exc)}

        return {"ok": True, "completed_steps": [s["name"] for s in self.completed]}

    def _rollback(self):
        for step in reversed(self.completed):
            p.record_decision(self.pid, f"saga.compensate.{step['name']}",
                              "saga", "compensating")
            try:
                step["compensate"]()
                p.record_decision(self.pid, f"saga.compensate.{step['name']}",
                                  "saga", "compensated")
            except Exception as exc:
                p.record_decision(self.pid, f"saga.compensate.{step['name']}",
                                  "saga", "compensation_failed",
                                  rationale=str(exc))


# Usage
saga = Saga(pid)
saga.add_step("backup_db",
    execute_fn    = lambda: run_backup(),
    compensate_fn = lambda: delete_backup()
).add_step("run_migration",
    execute_fn    = lambda: run_migration("add_users_table", "production"),
    compensate_fn = lambda: rollback_migration("add_users_table")
).add_step("restart_api",
    execute_fn    = lambda: restart_service("api-server"),
    compensate_fn = lambda: restart_service("api-server")  # restart again
)

result = saga.run()
print(f"Saga result: {result}")
```

---

## Step 4: Two-Phase Commit

```python
def two_phase_commit(pid, prepare_fn, commit_fn, rollback_fn):
    """
    Phase 1: Prepare — check all preconditions, acquire locks
    Phase 2: Commit  — execute, only if prepare succeeded
    """
    # Phase 1: Prepare
    p.record_decision(pid, "tpc.prepare", "two_phase_commit", "started")
    try:
        prepare_result = prepare_fn()
        if not prepare_result.get("ok"):
            p.record_decision(pid, "tpc.prepare", "two_phase_commit",
                              "aborted", rationale=prepare_result.get("reason"))
            return {"ok": False, "phase": "prepare", "reason": prepare_result["reason"]}
    except Exception as exc:
        p.record_decision(pid, "tpc.prepare", "two_phase_commit", "failed",
                          rationale=str(exc))
        return {"ok": False, "phase": "prepare", "error": str(exc)}

    p.record_decision(pid, "tpc.prepare", "two_phase_commit", "succeeded")

    # Phase 2: Commit
    p.record_decision(pid, "tpc.commit", "two_phase_commit", "started")
    try:
        result = commit_fn()
        p.record_decision(pid, "tpc.commit", "two_phase_commit", "completed")
        return {"ok": True, "result": result}
    except Exception as exc:
        p.record_decision(pid, "tpc.commit", "two_phase_commit", "failed",
                          rationale=str(exc))
        p.record_decision(pid, "tpc.rollback", "two_phase_commit", "started")
        rollback_fn()
        p.record_decision(pid, "tpc.rollback", "two_phase_commit", "completed")
        return {"ok": False, "phase": "commit", "rolled_back": True}
```

---

## Step 5: Execution Replay

Replay any session from its journal:

```python
def replay_execution(pid: str, from_seq: int, to_seq: int) -> list:
    """Replay tool calls from a journal range."""
    journal  = p.get_books_journal(limit=1000)
    entries  = [e for e in journal["entries"]
                if from_seq <= e.get("seq_no", 0) <= to_seq
                and "tool" in str(e.get("action", "")).lower()]

    replay_log = []
    for entry in entries:
        # Record that we are replaying
        p.record_decision(pid,
            f"replay.{entry['action']}",
            f"seq:{entry['seq_no']}",
            "replayed",
            rationale=f"Forensic replay of seq {entry['seq_no']}")
        replay_log.append({
            "original_seq": entry["seq_no"],
            "action":       entry["action"],
            "outcome":      entry["outcome"],
            "replayed_at":  now_iso()
        })

    return replay_log
```

---

## Idempotency Pattern

```python
import hashlib, json

_executed_hashes = set()

def idempotent_execute(pid, tool, params, bridge="ops-bridge"):
    """Only execute if this exact (tool, params) combination hasn't run yet."""
    intent_hash = hashlib.sha256(
        json.dumps({"tool": tool, "params": params}, sort_keys=True).encode()
    ).hexdigest()

    if intent_hash in _executed_hashes:
        p.record_decision(pid, f"{tool}.idempotent_skip", tool,
                          "skipped", rationale=f"Already executed: {intent_hash[:16]}")
        return {"ok": True, "skipped": True, "hash": intent_hash}

    result = p.mcp_invoke_tool(bridge, tool, pid, tool_input=params)
    _executed_hashes.add(intent_hash)
    return {**result, "hash": intent_hash}
```

---

## Execution Proof for CI/CD Gate

```python
def governance_ci_gate(pid: str, min_grade: str = "B") -> bool:
    """CI/CD gate: pass only if governance grade is sufficient."""
    grades = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}

    proof  = p.generate_proof(pid, title="cicd_gate")
    verify = p.get_verify_report()

    summary = verify.get("executive_summary", {})
    grade   = summary.get("grade", "F")
    passed  = grades.get(grade, 0) >= grades.get(min_grade, 3)

    p.record_decision(pid, "cicd.gate", "governance_check",
                      "passed" if passed else "failed",
                      rationale=f"Grade: {grade}, required: {min_grade}",
                      confidence=1.0)

    print(f"CI/CD gate: grade={grade} required={min_grade} → {'PASS' if passed else 'FAIL'}")
    return passed
```

---

## Next Steps

- **[18 — Ring 7: Tool Execution](18-ring-7-tool-execution.md)**
- **[42 — Builder: Tool Bridge](42-builder-tool-bridge.md)**
- **[48 — Builder: Agent Roles](48-builder-agent-roles.md)**
