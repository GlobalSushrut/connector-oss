# 36 — Tutorial: Writing CCL Workflows

> Write, compile, deploy, and test a CCL contract end-to-end.

---

## What You'll Build

A CCL contract for a clinical note summarizer that:
- Reads PHI from `/p/` namespace
- Never exposes PHI to the LLM
- Requires human review if confidence < 0.85
- Tags every decision with `hipaa`
- Stays within a 50,000 token budget

---

## Step 1 — Start with the Intent

Before writing CCL, articulate the intent in one sentence:

> "Summarize patient clinical notes with minimum necessary PHI access, requiring human review for low-confidence outputs."

This becomes the `intent` field — it appears verbatim in compliance reports.

---

## Step 2 — Declare Memory Access

```ccl
memory {
  read  /p/patients/{{ patient_id }}      # PHI source — never forwarded to LLM
  read  /k/medical/icd10_codes           # Knowledge — safe for LLM
  write /m/summarizer/{{ session_id }}/output
  write /m/summarizer/{{ session_id }}/audit
}
```

**Rules:**
- `read /p/...` — PHI can be read by the agent but the governance layer enforces it never enters LLM context
- `write /m/...` — working output namespace
- Template variables `{{ ... }}` are resolved at runtime from the call inputs

---

## Step 3 — Declare Tools

```ccl
tools {
  allow read_patient_record {
    require namespace: /p/patients
    require clearance: 3
  }
  allow write_summary {
    require namespace: /m/summarizer
  }
  deny *    # deny everything not explicitly allowed
}
```

---

## Step 4 — Model the State Machine

Draw it first, then write it:

```
idle → reading → analysis → output → done
                    ↓
                 review (if confidence_low)
                    ↓
              output (if approved) or idle (if denied)
```

```ccl
state {
  initial: idle
  idle     → reading   on: task_start
  reading  → analysis  on: records_loaded
  analysis → output    on: summary_approved
  analysis → review    on: confidence_low
  review   → output    on: human_approved
  review   → idle      on: human_denied
  output   → done      on: summary_written
}
```

---

## Step 5 — Write Event Handlers

```ccl
events {
  on task_start {
    read /p/patients/{{ input.patient_id }}
    emit records_loaded
  }

  on records_loaded {
    require namespace_clean: /p/patients
    invoke_llm {
      prompt:    "Summarize the clinical history. Omit all contact information."
      namespace: /m/summarizer/{{ input.session_id }}
    }
    branch {
      confidence > 0.85  → emit summary_approved
      confidence <= 0.85 → emit confidence_low
    }
  }

  on confidence_low {
    await_hitl {
      timeout: 3600
      reason:  "Confidence {{ confidence }} below threshold 0.85"
    }
  }

  on summary_approved {
    write /m/summarizer/{{ input.session_id }}/output
    record_decision {
      action:      "summarize.patient_record"
      outcome:     "allow_minimum_necessary"
      regulations: [hipaa]
    }
    emit summary_written
  }
}
```

---

## Step 6 — Add Governance Block

```ccl
governance {
  require chain_verified: true
  require namespace_clean: /p/patients   # PHI must not appear in LLM context
  tag hipaa
  on_violation: deny_and_audit
}
```

---

## Step 7 — Add Budget

```ccl
budget {
  max_tokens:   50000
  max_cost_usd: 2.00
  max_duration: 120s
  on_exceed:    deny_new_steps
}
```

---

## Complete Contract

```ccl
contract ClinicalNoteSummarizer {
  version: "1.0.0"
  intent:  "Summarize patient clinical notes with minimum necessary PHI access"

  memory {
    read  /p/patients/{{ patient_id }}
    read  /k/medical/icd10_codes
    write /m/summarizer/{{ session_id }}/output
    write /m/summarizer/{{ session_id }}/audit
  }

  tools {
    allow read_patient_record { require namespace: /p/patients }
    allow write_summary       { require namespace: /m/summarizer }
    deny *
  }

  state {
    initial: idle
    idle     → reading   on: task_start
    reading  → analysis  on: records_loaded
    analysis → output    on: summary_approved
    analysis → review    on: confidence_low
    review   → output    on: human_approved
    review   → idle      on: human_denied
    output   → done      on: summary_written
  }

  events {
    on task_start {
      read /p/patients/{{ input.patient_id }}
      emit records_loaded
    }
    on records_loaded {
      require namespace_clean: /p/patients
      invoke_llm {
        prompt:    "Summarize clinical history. Omit all contact information."
        namespace: /m/summarizer/{{ input.session_id }}
      }
      branch {
        confidence > 0.85  → emit summary_approved
        confidence <= 0.85 → emit confidence_low
      }
    }
    on confidence_low {
      await_hitl { timeout: 3600 }
    }
    on summary_approved {
      write /m/summarizer/{{ input.session_id }}/output
      record_decision {
        action: "summarize.patient_record"
        outcome: "allow_minimum_necessary"
        regulations: [hipaa]
      }
      emit summary_written
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
    on_exceed:    deny_new_steps
  }
}
```

---

## Step 8 — Compile

```python
with open("contracts/clinical_summarizer.ccl") as f:
    source = f.read()

result = p.compile_cls_contract(source)
print(f"CID: {result['cid']}")
print(f"Passes: {result['semantic_passes']}")
```

Or via CLI:
```bash
connectorctl contracts compile contracts/clinical_summarizer.ccl
# Output: cls1-sha256-3a4b5c...
```

Common compile errors and fixes:

| Error | Fix |
|---|---|
| `Undefined tool: write_summary` | Add tool to `tools.yaml` |
| `Unreachable state: review` | Check state transitions |
| `Branch not exhaustive` | Add else branch |
| `Regulation tag required for /p/ access` | Add `tag hipaa` to governance block |

---

## Step 9 — Deploy

```python
cid = result["cid"]
p.deploy_contract(pid, cid)

# Verify
agent = p.get_agent(pid)
assert agent["contract_cid"] == cid
print(f"Contract deployed: {cid}")
```

```bash
connectorctl deploy contract cls1-sha256-... --agent <pid> --verify
```

---

## Step 10 — Test the Deployed Contract

```python
# 1. Trigger task_start event
response = p.invoke_chat(pid, ns,
    f"Summarize patient p001 notes",
    system="You are a clinical summarizer.")

# 2. If confidence is low, a HITL request will be created
pending = p.list_hitl_pending(pid)
if pending["count"] > 0:
    print(f"HITL pending: {pending['requests'][0]['reason']}")
    p.hitl_approve(pid, pending["requests"][0]["request_id"])

# 3. Check output
output = p.recall_memory(f"m/summarizer/{session_id}/output", limit=1)
```

---

## Debugging Contracts

```bash
# See contract IR (intermediate representation)
connectorctl contracts inspect cls1-sha256-...

# Trace contract execution
connectorctl trace agent <pid> --decisions

# Check for violations
connectorctl compliance violations
```

---

## Next Steps

- **[05 — CCL Contracts](05-ccl-contracts.md)** — full grammar reference
- **[37 — Tutorial: Audit Proof](37-tutorial-audit-proof.md)**
- **[45 — Builder: Extending CCL](45-builder-ccl-extensions.md)**
