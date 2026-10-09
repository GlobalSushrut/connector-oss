# 45 — Builder: Extending CCL

> Custom step operations, predicates, and domain-specific contract libraries.

---

## Custom Step Operations

Beyond the 14 built-in CCL operations, you can register custom operations:

```rust
// In a plugin (Rust):
// plugins/my_plugin/src/steps.rs

use connector_engine::ccl::StepOp;

pub struct DrugInteractionCheck;

impl StepOp for DrugInteractionCheck {
    fn name(&self) -> &str { "check_drug_interactions" }
    fn description(&self) -> &str {
        "Check for known drug interactions in the agent's medication list"
    }

    fn execute(&self, ctx: &mut StepContext) -> StepResult {
        let medications = ctx.memory_recall("/m/medications")?;
        let new_drug    = ctx.get_input("new_drug")?;

        let interactions = check_interactions(medications, new_drug);
        if !interactions.is_empty() {
            ctx.emit_event("drug_interaction_detected");
            ctx.write_memory("/m/alerts/interactions", interactions);
            return StepResult::block("Drug interaction detected");
        }
        StepResult::ok()
    }
}
```

Register in `plugin.yaml`:
```yaml
custom_ccl_ops:
  - name: check_drug_interactions
    module: my_plugin::steps::DrugInteractionCheck
    inputs: [new_drug]
    outputs: [interactions]
    regulations: [hipaa]
```

---

## Custom Predicates

Add domain-specific predicates to CCL governance blocks:

```rust
// plugins/medical/src/predicates.rs

use connector_engine::ccl::Predicate;

pub struct PhiInContext;

impl Predicate for PhiInContext {
    fn name(&self) -> &str { "phi_in_context" }

    fn evaluate(&self, ctx: &PredicateContext) -> bool {
        // Check if any LLM context packet comes from /p/ namespace
        ctx.llm_context_packets()
           .iter()
           .any(|pkt| pkt.namespace.starts_with("/p/"))
    }
}
```

Use in CCL:
```ccl
governance {
  require not phi_in_context      # custom predicate
  require namespace_clean: /p/    # built-in predicate
  tag hipaa
}
```

---

## Contract Libraries

Build reusable CCL modules for your domain:

```ccl
// libs/hipaa_base.ccl
module HIPAABase {
  // Reusable governance block for any HIPAA agent
  governance_template {
    require chain_verified: true
    require namespace_clean: /p/
    require not phi_in_context
    tag hipaa
    on_violation: deny_and_audit
  }

  // Reusable budget for clinical agents
  budget_template {
    max_tokens:   100000
    max_cost_usd: 5.00
    on_exceed:    deny_new_steps
  }
}
```

Import in a contract:
```ccl
import HIPAABase from "libs/hipaa_base.ccl"

contract ClinicalAgent {
  intent: "..."
  use HIPAABase.governance_template
  use HIPAABase.budget_template
  // ... rest of contract
}
```

---

## Macro Expansion

CCL supports macro-style repetition:

```ccl
// Without macro — verbose
events {
  on step_1_done { call tool_a() ; emit step_2 }
  on step_2_done { call tool_b() ; emit step_3 }
  on step_3_done { call tool_c() ; emit step_4 }
}

// With macro — concise
events {
  for step in [1, 2, 3] {
    on step_{{ step }}_done {
      call tool_{{ step }}()
      emit step_{{ step + 1 }}
    }
  }
}
```

---

## Contract Composition

Compose contracts from smaller contracts:

```ccl
contract DataPipeline {
  intent: "Multi-step data processing pipeline"

  // Include sub-contracts as phases
  phase extract {
    import ExtractContract from "contracts/extract.ccl"
    bind input.source_ns to /p/raw_data
  }

  phase transform {
    import TransformContract from "contracts/transform.ccl"
    bind input.input_ns  to /m/raw
    bind input.output_ns to /m/transformed
    require: extract.complete
  }

  phase load {
    import LoadContract from "contracts/load.ccl"
    bind input.source_ns to /m/transformed
    require: transform.complete
  }
}
```

---

## CCL Contract Testing

Write tests alongside contracts:

```ccl
// contracts/medical_agent_test.ccl
test_suite MedicalAgentTests {

  test phi_not_in_llm_context {
    given:
      memory /p/patients/test { "name": "Test Patient", "dx": "Diabetes" }
    when:
      trigger task_start { patient_id: "test" }
    then:
      assert namespace_clean: /p/
      assert llm_context_does_not_contain: "Test Patient"
      assert decision_recorded: "summarize.patient_record"
  }

  test confidence_triggers_hitl {
    given:
      llm_confidence: 0.60
    when:
      trigger records_loaded
    then:
      assert state == review
      assert hitl_pending: true
  }

  test budget_limit {
    given:
      tokens_consumed: 49000
    when:
      trigger invoke_llm { tokens: 2000 }
    then:
      assert blocked_by_budget: true
  }
}
```

Run tests:
```bash
connectorctl test contract contracts/medical_agent.ccl
```

---

## CCL Lint and Format

```bash
# Lint
connectorctl lint contract contracts/medical_agent.ccl
# Outputs: warnings about unreachable states, missing regulation tags, etc.

# Format
connectorctl fmt contract contracts/medical_agent.ccl
# Formats CCL source according to standard style
```

---

## Next Steps

- **[05 — CCL Contracts](05-ccl-contracts.md)**
- **[23 — Formal Verification](23-theory-formal-verification.md)**
- **[46 — Builder: RAG Patterns](46-builder-rag-retrieval.md)**
