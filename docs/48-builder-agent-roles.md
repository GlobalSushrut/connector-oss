# 48 — Builder: Agent Roles and Clearance Levels

> Design role hierarchies, clearance levels, and agent capability scopes.

---

## Clearance Levels

Clearance determines what namespaces and tools an agent can access:

| Level | Name | Can Access |
|---|---|---|
| 1 | Observer | `/k/` read-only, no tools |
| 2 | Worker | `/m/` read/write, `/k/` read, basic tools |
| 3 | Standard | `/m/` read/write, `/k/` read, most tools |
| 4 | Privileged | Adds `/s/` read, admin tools |
| 5 | Admin | Full access including `/p/`, system tools |

```python
# Clearance 3 — standard agent (most common)
agent = p.register_agent("my-agent", "Standard agent", clearance=3)

# Clearance 4 — operations agent that can restart services
ops_agent = p.register_agent("ops-agent", "Operations agent", clearance=4)

# Clearance 5 — medical data custodian (PHI access required)
phi_agent = p.register_agent("phi-custodian", "PHI data custodian", clearance=5)
```

---

## Role Types

Roles bind to policy rule conditions:

| Role | Policy Bindings | Typical Use |
|---|---|---|
| `observer` | Read-only access, no tools | Monitoring, reporting |
| `worker` | Standard operations | Most business agents |
| `medical_assistant` | HIPAA rules active | Clinical AI |
| `operations` | DevOps tools allowed | Infrastructure automation |
| `compliance_officer` | Audit-only access | Compliance review |
| `coordinator` | Can delegate to other agents | Multi-agent orchestration |
| `specialist` | Domain-specific tools | Expert sub-agents |
| `validator` | Output validation only | Quality assurance |

---

## Role-Policy Binding

```yaml
# policies/role_bindings.yaml
name: role_bindings

rules:
  - id: medical_phi_access
    description: "Medical assistants can read patient data for treatment"
    condition:
      agent_role: medical_assistant
      clearance_gte: 3
    action: allow
    namespace_allow: [/p/patients/, /k/medical/]
    regulations: [hipaa]

  - id: ops_tools
    description: "Operations agents can restart services"
    condition:
      agent_role: operations
      clearance_gte: 4
    action: allow
    tools_allow: [restart_service, run_migration, deploy_service]
    regulations: [soc2]

  - id: coordinator_delegation
    description: "Coordinators can delegate to specialist agents"
    condition:
      agent_role: coordinator
    action: allow
    operations_allow: [delegate.task, consensus.vote, route.task]
```

---

## Building a Role Hierarchy

```python
def create_agent_hierarchy():
    """Create a three-tier agent hierarchy."""

    # Tier 1: Coordinator (strategic decisions)
    coordinator = p.register_agent(
        "research-coordinator",
        "Coordinates research tasks and routes to specialists",
        clearance=3
    )

    # Tier 2: Specialists (domain expertise)
    specialists = {
        "medical":   p.register_agent("medical-specialist",   "Medical domain expert", 3),
        "legal":     p.register_agent("legal-specialist",     "Legal domain expert",   3),
        "technical": p.register_agent("technical-specialist", "Technical expert",      3),
    }

    # Tier 3: Validators (output QA)
    validator = p.register_agent(
        "output-validator",
        "Validates specialist outputs for policy compliance",
        clearance=3
    )

    return {
        "coordinator": coordinator,
        "specialists": specialists,
        "validator":   validator
    }
```

---

## Dynamic Capability Scoping

Restrict an agent's capabilities for specific tasks:

```python
def scoped_agent_for_task(pid: str, task_type: str) -> dict:
    """
    Return a context dict that scopes what the agent can do for this task.
    The scoping is enforced by policy rules, not by the caller.
    """
    TASK_SCOPES = {
        "summarize":  {"max_tokens": 5000,  "tools": [],                   "namespaces": ["/m/", "/k/"]},
        "deploy":     {"max_tokens": 10000, "tools": ["deploy_service"],   "namespaces": ["/m/"]},
        "audit":      {"max_tokens": 2000,  "tools": [],                   "namespaces": ["/m/", "/k/"], "read_only": True},
        "phi_access": {"max_tokens": 5000,  "tools": ["read_patient_record"], "namespaces": ["/p/", "/m/", "/k/"]},
    }

    scope = TASK_SCOPES.get(task_type, TASK_SCOPES["summarize"])

    # Record the scope selection
    p.record_decision(pid, f"agent.scoped_for.{task_type}",
                      pid, "scoped",
                      rationale=f"Task scope: tokens={scope['max_tokens']}, "
                                f"tools={scope['tools']}")

    return {"pid": pid, "task_type": task_type, "scope": scope}
```

---

## Agent Trust Score (`kecs_score`)

Connector computes a trust score for each agent:

```
KECS = 0.4 × K_vn + 0.4 × S_renyi + 0.2 × K_topo
```

Where:
- `K_vn` — von Neumann entropy of the agent's decision distribution
- `S_renyi` — Rényi entropy (measures diversity of actions)
- `K_topo` — topological entropy (coherence of the agent's behavior)

Score maps to grade:

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A | Highly trusted, consistent behavior |
| 75–89  | B | Trusted, minor concerns |
| 60–74  | C | Moderate trust, review recommended |
| 45–59  | D | Low trust, investigation needed |
| 0–44   | F | Untrusted, quarantine candidate |

```python
agent = p.get_agent(pid)
kecs  = agent.get("kecs", {})
score = kecs.get("k_vn", 0) * 0.4 + kecs.get("s_renyi", 0) * 0.4 + kecs.get("k_topo", 0) * 0.2
print(f"Trust score: {score:.1f}")
```

---

## Quarantine and Recovery

When an agent violates policy:

```python
# Check if quarantined
agent = p.get_agent(pid)
if agent.get("status") == "quarantined":
    print(f"Agent {pid} is quarantined")

    # Review what triggered quarantine
    violations = p.get_policy_violations()
    for v in violations.get("violations", []):
        if v.get("agent_pid") == pid:
            print(f"Violation: {v['action']} → {v['outcome']}")

    # After review, unquarantine
    p.unquarantine_agent(pid)
    p.record_decision(pid, "agent.unquarantined", pid,
                      "released_after_review",
                      rationale="Reviewed violations, cleared for operation",
                      regulations=["soc2"])
```

---

## Agent Lifecycle State Machine

```
          register()
              │
              ▼
           IDLE ──────── start() ──────► ACTIVE
                │                           │
                │                    policy_violation()
                │                           │
                │                           ▼
                │                      QUARANTINED
                │                           │
                │                    unquarantine()
                │                           │
                │                           ▼
                └── kill() ──────────► STOPPING
                                           │
                                           ▼
                                        STOPPED
```

---

## Next Steps

- **[49 — Builder: DevGuard Plugin](49-builder-devguard.md)**
- **[10 — Multi-Agent Workflows](10-workflows-multiagent.md)**
- **[38 — Tutorial: Multi-Agent](38-tutorial-multiagent.md)**
