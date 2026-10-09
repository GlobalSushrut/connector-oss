# 05 — CCL Contracts

> The Connector Contract Language — grammar, semantics, and deployment.

---

## What is CCL?

CCL (Connector Contract Language) is the governance specification language for Connector agents. A CCL contract defines:

- What an agent **intends** to do
- What **memory** it may read and write
- What **tools** it may call
- What **state transitions** are valid
- What **events** trigger what responses
- What **governance rules** apply (HITL, budget, regulations)

A compiled contract is addressed by CID (`cls1-sha256-*`), signed with Ed25519, and deployed to a live node. Once deployed, the agent **cannot take actions outside the contract** — the CLS executor enforces it at runtime.

---

## Grammar Overview

```
contract <Name> {
  intent:     "<natural language description>"

  memory { ... }
  tools  { ... }
  state  { ... }
  events { ... }
  governance { ... }
  budget { ... }
}
```

---

## Block Types

### `intent`

```ccl
intent: "Summarize patient records with minimum necessary access"
```

Plain text. Used in governance reports and SOE surfaces. Required.

---

### `memory`

Declares which namespaces the agent may read and write.

```ccl
memory {
  read  /p/patients/{{ patient_id }}   # template variable
  read  /k/medical/protocols
  write /m/summarizer/output
  write /m/summarizer/session
}
```

Any memory operation outside declared namespaces is denied at Ring 4.

---

### `tools`

```ccl
tools {
  allow read_patient_record {
    require namespace: /p/patients
    require clearance: 3
  }
  allow write_summary {
    require namespace: /m/summarizer
  }
  deny *                              # deny everything else
}
```

---

### `state`

Defines a finite state machine for the agent's execution flow.

```ccl
state {
  initial: idle

  idle -> reading     on: task_received
  reading -> analysis on: records_loaded
  analysis -> writing on: summary_ready
  analysis -> review  on: confidence_low     # confidence < threshold
  review -> writing   on: human_approved
  review -> idle      on: human_denied
  writing -> idle     on: output_written
}
```

---

### `events`

Event handlers that trigger actions.

```ccl
events {
  on task_received {
    call read_patient_record(patient_id: {{ input.patient_id }})
    emit records_loaded
  }

  on records_loaded {
    call invoke_llm(
      prompt: "Summarize this patient history: {{ memory.patient_record }}"
      namespace: /m/summarizer/session
    )
    emit summary_ready
  }

  on confidence_low {
    emit hitl_required
    await hitl
  }
}
```

---

### `governance`

```ccl
governance {
  require confidence > 0.85
  require namespace_clean: /p/patients    # no PHI in LLM context

  on_violation: deny_and_audit

  tag hipaa
  tag soc2

  hitl {
    trigger: confidence < 0.7
    timeout: 3600
    approvers: ["medical-officer@hospital.com"]
    on_timeout: deny
  }
}
```

---

### `budget`

```ccl
budget {
  max_tokens:   100000
  max_cost_usd: 5.00
  max_duration: 300s

  on_exceed: deny_new_steps    # or: alert_and_continue
}
```

---

## Step Operations (14 built-ins)

| Operation | Description |
|---|---|
| `call <tool>(args)` | Invoke a governed tool |
| `write <ns> <content>` | Write to a memory namespace |
| `read <ns>` | Read from a memory namespace |
| `emit <event>` | Emit an event to the state machine |
| `branch <condition>` | Conditional branch |
| `require <predicate>` | Assert a condition — fails contract if false |
| `check_budget` | Verify budget is not exceeded |
| `await_hitl` | Pause for human review |
| `invoke_llm <prompt>` | Governed LLM call |
| `record_decision <action> <outcome>` | Write to governance ledger |
| `seal` | Seal a proof bundle for this step |
| `defer <step>` | Defer execution of a step |
| `loop <N> { ... }` | Bounded iteration |
| `parallel { ... }` | Parallel step execution |

---

## Predicate Syntax

```ccl
# Comparison
confidence > 0.85
cost_usd < 5.00
token_count <= 100000

# Logical
confidence > 0.85 and namespace_clean: /p/
tool == "read_patient_record" or tool == "write_summary"
not pii_detected

# Namespace predicates
namespace_clean: /p/patients        # no data from this namespace in LLM context
namespace_writable: /m/output       # agent has write access
namespace_readable: /k/medical      # agent has read access

# Regulation predicates
regulation_tagged: hipaa
all_decisions_recorded: true
chain_verified: true
```

---

## Type System

```ccl
# Primitive types
string, int, float, bool, bytes

# Namespace reference
ns: /p/patients

# Template variable (resolved at runtime)
{{ input.patient_id }}
{{ memory.records }}
{{ step.output }}
{{ context.timestamp }}
```

---

## Compile Pipeline

```
Source (.ccl)
    │
    ▼ 1. Lex — tokenize CCL source
    ▼ 2. Parse — build AST
    ▼ 3. Sema — 11-pass semantic analysis:
    │     pass 1: name resolution
    │     pass 2: tool validation
    │     pass 3: memory namespace validation
    │     pass 4: state machine validation
    │     pass 5: event handler validation
    │     pass 6: branch exhaustiveness
    │     pass 7: type checking
    │     pass 8: reachability analysis
    │     pass 9: termination proof
    │     pass 10: budget analysis
    │     pass 11: regulation tag verification
    ▼ 4. Lower — AST → IR
    ▼ 5. Optimize — dead step elimination, constant folding
    ▼ 6. Verify — formal verification of IR
    ▼ 7. Emit — serialized IR + Ed25519 signature
    │
    ▼
Compiled Contract (cls1-sha256-*)
```

### Compiling via Python SDK

```python
source = """
contract MyAgent {
  intent: "Do a governed thing"
  memory { write /m/my-agent/output }
  governance { tag soc2 }
}
"""
result = p.compile_cls_contract(source)
cid = result["cid"]      # cls1-sha256-...
```

---

## CID Addressing

Every compiled contract gets a content-addressed identifier:

```
cls1-sha256-3a4b5c6d7e8f...
```

The CID is derived from the canonical serialization of the compiled IR. Changing a single character in the contract changes the CID. A deployed contract is **immutable** — you deploy a new version with a new CID.

---

## Deploying a Contract

```python
# Compile
result = p.compile_cls_contract(source)
cid = result["cid"]

# Deploy to agent
p.deploy_contract(pid, cid)

# Verify deployment
agent = p.get_agent(pid)
assert agent["contract_cid"] == cid
```

---

## Contract Versioning

```ccl
contract MedicalSummarizer {
  version: "2.1.0"
  supersedes: "cls1-sha256-previous..."

  intent: "Improved summarization with PHI field detection"
  # ...
}
```

Hot-swap a running contract:
```bash
connectorctl deploy contract <new-cid> --agent <pid> --verify
```

---

## Example: Complete Medical Contract

```ccl
contract HIPAAMedicalSummarizer {
  version: "1.0.0"
  intent: "Summarize patient records with HIPAA minimum necessary access"

  memory {
    read  /p/patients/{{ input.patient_id }}
    read  /k/medical/icd10_codes
    write /m/summarizer/{{ session_id }}/output
    write /m/summarizer/{{ session_id }}/audit
  }

  tools {
    allow read_patient_record {
      require namespace: /p/patients
      require clearance: 3
    }
    allow write_summary
    deny *
  }

  state {
    initial: idle
    idle     -> reading   on: task_start
    reading  -> analysis  on: records_loaded
    analysis -> output    on: summary_approved
    analysis -> review    on: confidence_low
    review   -> output    on: human_approved
    review   -> idle      on: human_denied
    output   -> idle      on: complete
  }

  events {
    on task_start {
      read /p/patients/{{ input.patient_id }}
      emit records_loaded
    }
    on records_loaded {
      require namespace_clean: /p/patients
      invoke_llm {
        prompt: "Summarize the clinical history. Do not include contact information."
        namespace: /m/summarizer/{{ session_id }}
      }
      branch {
        confidence > 0.85 -> emit summary_approved
        confidence <= 0.85 -> emit confidence_low
      }
    }
    on confidence_low {
      await_hitl {
        timeout: 3600
        reason: "Confidence below threshold — human review required"
      }
    }
  }

  governance {
    require chain_verified: true
    require namespace_clean: /p/patients
    tag hipaa
    on_violation: deny_and_audit
  }

  budget {
    max_tokens:   50000
    max_cost_usd: 2.00
    max_duration: 120s
    on_exceed: deny_new_steps
  }
}
```

---

## Next Steps

- **[16 — Ring 5: Policy and Governance](16-ring-5-policy-governance.md)** — how CCL is executed
- **[23 — Formal Verification](23-theory-formal-verification.md)** — the 11-pass verifier
- **[36 — Tutorial: Writing CCL Contracts](36-tutorial-ccl-workflows.md)** — hands-on walkthrough
- **[45 — Builder: Extending CCL](45-builder-ccl-extensions.md)** — custom operations
