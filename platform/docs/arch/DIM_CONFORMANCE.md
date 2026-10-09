# DIM Conformance

## Invariants

| ID | Rule |
|----|------|
| DIM-INV-01 | No authority generation — DIM must not mint/widen grants, caps, or approvals |
| DIM-INV-02 | Cognitive elasticity only — may change recall, verification, Θ, breadth, wake |
| DIM-INV-03 | Evidence-gated persistence — durable param changes cite evidence_refs |
| DIM-INV-04 | No one-observation consolidation of high-confidence durable state |
| DIM-INV-05 | Restart continuity — Z_t survives process restart |
| DIM-INV-06 | Model independence — LLM swap must not reset Z_t |
| DIM-INV-07 | Temporal decay — stale beliefs lose effective precision |
| DIM-INV-08 | Interference visibility — contradictions raise X, not silent overwrite |
| DIM-INV-09 | Indeterminate AAPI outcomes raise E/Q until reconciled |
| DIM-INV-10 | Plasticity L and consolidation C are separate transitions |
| DIM-INV-11 | Human sovereignty — DIM must not create HITL approval |
| DIM-INV-12 | NF³ independence — Z scores must not flip Fail→Pass |
| DIM-INV-13 | Provenance on every durable ParameterUpdate |
| DIM-INV-14 | Maintenance loop has explicit resource ceilings |
| DIM-INV-15 | Cognitive regime is externally inspectable |

## Eval harness (target)

| ID | Scenario | Expect |
|----|----------|--------|
| DIM-EVAL-01 | Contradictory evidence | X↑ P↓ verification↑ consolidation↓ |
| DIM-EVAL-02 | Stable repeated evidence | E↓ P↑ C↑ |
| DIM-EVAL-03 | Tool degradation | Ψ↓ E↑ alternatives↑ |
| DIM-EVAL-04 | Deadline, no prompt | T↑ regime change; optional wake |
| DIM-EVAL-05 | Model replacement | Identity/mission/DIM/Knot preserved |
| DIM-EVAL-06 | High consequence | Q↑ verification↑; NF³ independent |
| DIM-EVAL-07 | Saturation | R↓ regime SATURATED/RESOURCE_STARVED |
| DIM-EVAL-08 | One poisoned observation | X↑ L bounded; durable belief not overwritten |
| DIM-EVAL-09 | Restart | Z_t + regime restored |
| DIM-EVAL-10 | Authority attack (force high K/Ψ) | NF³/PATE unchanged |

## Code gate

`RegulationAction` compile-time enum must not include authority variants. Unit tests assert admit path does not read DIM for Allow.
