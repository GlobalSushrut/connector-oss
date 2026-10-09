# 18 — Ring 7: Tool Execution

> Governed tool dispatch — schema validation, allowlist enforcement, receipts.

---

## Overview

Ring 7 controls what tools an agent can call and under what conditions. Every tool dispatch:
1. Checks the agent's tool allowlist
2. Validates arguments against JSON Schema
3. Checks namespace policy for the tool's scope
4. Verifies budget has not been exceeded
5. Executes the tool call
6. Generates a signed execution receipt
7. Chains the receipt (each receipt references the previous)

---

## Tool Bridge and MCP Integration

Connector wraps MCP (Model Context Protocol) servers to enforce governance on every tool call:

```
Agent → Ring 7 → Tool Bridge → MCP Server → Tool Execution
                 ↑
          Schema validation
          Allowlist check
          Budget check
          Receipt generation
```

### Register a Tool Bridge

```python
p.mcp_register_bridge(
    bridge_id="filesystem-bridge",
    url="http://localhost:8080/mcp",
    tools=["read_file", "write_file", "list_dir"]
)
```

### Invoke a Tool

```python
result = p.mcp_invoke_tool(
    bridge_id="filesystem-bridge",
    tool="read_file",
    agent_pid=pid,
    tool_input={"path": "/allowed/paths/readme.txt"}
)
```

---

## Tool Schema Validation

Every tool has a JSON Schema declaration. Arguments are validated **before** dispatch:

```yaml
# Tool schema in tools.yaml
- name: read_file
  parameters:
    path:
      type: string
      pattern: "^/allowed/paths/.*"    # path restriction
      description: "File path to read"
  required: [path]
  returns:
    type: string
```

```python
# This call will be blocked — path violates schema
result = p.mcp_invoke_tool("fs-bridge", "read_file", pid,
                           {"path": "/etc/passwd"})
# Error: "path does not match pattern '^/allowed/paths/.*'"
```

---

## Tool Allowlist Enforcement

An agent can only call tools declared in its manifest or policy:

```yaml
# agent.yaml
tools:
  allowed:
    - name: read_patient_record
    - name: write_summary
  deny_all_others: true    # everything else is blocked
```

```python
# Attempting to call an unallowed tool
result = p.mcp_invoke_tool("bridge", "delete_database", pid, {})
# Blocked: "Tool 'delete_database' not in agent allowlist"
```

---

## Execution Receipts

Every tool dispatch generates a signed receipt:

```json
{
  "receipt_id":   "rec_uuid...",
  "tool":         "read_patient_record",
  "bridge_id":    "medical-bridge",
  "agent_pid":    "agent_abc123",
  "input_hash":   "sha256:...",
  "output_hash":  "sha256:...",
  "prev_receipt": "rec_previous...",   // chain link
  "timestamp":    "2026-04-16T09:00:00Z",
  "signature":    "ed25519:...",
  "audit_cid":    "mem1-sha256-..."
}
```

**Receipt chain:** Each receipt references the previous receipt's ID. A break in the chain indicates a missing or tampered tool call.

---

## Deterministic Execution

Same intent → same execution plan → same hash.

```python
import hashlib, json

# The execution plan is derived deterministically from the intent
intent = {"task": "summarize_patient", "patient_id": "p001", "fields": ["diagnosis", "medications"]}
intent_str  = json.dumps(intent, sort_keys=True)
intent_hash = hashlib.sha256(intent_str.encode()).hexdigest()

# Executing the same intent twice produces the same receipt chain
# (given the same memory state)
```

---

## Saga Pattern (`saga_bridge.rs`)

For multi-step operations with rollback capability:

```python
# Define a saga
saga = {
    "steps": [
        {"tool": "backup_database",     "args": {...}},
        {"tool": "run_migration",       "args": {...}, "compensate": "rollback_migration"},
        {"tool": "restart_service",     "args": {...}, "compensate": "restore_service"}
    ]
}

# Execute — if any step fails, compensating steps run in reverse
result = p.mcp_invoke_tool("ops-bridge", "execute_saga", pid,
                           tool_input=saga)
```

---

## Tool Escalation Prevention

Namespace policy prevents tools from accessing data outside their declared scope:

```python
# Tool registered with namespace: /m/my-agent
# Attempting to access /p/patients via the tool → blocked at Ring 5
result = p.mcp_invoke_tool("bridge", "read_file", pid,
                           {"path": "/p/patients/secret.json"})
# Error: "Tool namespace violation: /p/ requires clearance 5"
```

---

## Dry-Run Mode

Most tools support dry-run for validation before execution:

```python
result = p.mcp_invoke_tool("ops-bridge", "deploy", pid,
                           {"service": "api", "version": "1.2.0", "dry_run": True})
# Returns execution plan without actually deploying
# {
#   "plan": ["stop old container", "pull new image", "start new container"],
#   "estimated_downtime_seconds": 12,
#   "risks": [],
#   "dry_run": true
# }
```

---

## `formal_verify.rs` — Execution Plan Verification

Before a multi-step execution plan runs, `formal_verify.rs` checks:
- Every step is reachable from the initial state
- No step can produce an illegal state transition
- The plan terminates (no infinite loops)
- Budget is sufficient for all steps

---

## Execution Receipt Chain Verification

```python
receipts = p.list_audit_receipts(pid, limit=50)
# Verify receipt chain integrity
prev_id = None
for receipt in receipts.get("receipts", []):
    if prev_id and receipt.get("prev_receipt") != prev_id:
        print(f"CHAIN BREAK at receipt {receipt['receipt_id']}")
    prev_id = receipt["receipt_id"]
```

---

## Tool Dispatch Receipt in CLI

```bash
connectorctl trace agent <pid> --tools    # show tool dispatch receipts
connectorctl explain <receipt_id>         # detail for one receipt
```

---

## Next Steps

- **[19 — Ring 8 and 9: Audit and Surface](19-ring-8-9-audit-surface.md)**
- **[World cage — pores, vendor cut, browser world](WORLD_CAGE_AND_BROWSER.md)**
- **[42 — Builder: Tool Bridge](42-builder-tool-bridge.md)**
- **[47 — Builder: Real Execution Control](47-builder-real-execution-control.md)**
