# RGO — Reversibility-Graded Oversight

RGO sits after static contracts / ActionBinding and before PATE commit.

## Classes

| Class | Meaning | Typical oversight (tier 2–3) |
|-------|---------|------------------------------|
| R0 | Read-only | Autonomous |
| R1 | Reversible | Autonomous |
| R2 | External reversible | Hotl / HitlDigest |
| R3 | Irreversible | HitlDigest (never Autonomous on unknown) |

CONP `RiskLevel` maps via `ReversibilityClass::from_cp`. Emergency stop remains ambient Allow in ActionBinding/PATE.

## NF³

Invariant verdicts are categorical. Cognition / correction hints never flip Fail→Pass.

## Affordance envelope

Compiled from AgentContract, WorldGrant, Knot-21 shadow hint. May **shrink** consequence; never expands static authority. Each substitute on the fallback ladder requires a **new** ActionBinding digest.
