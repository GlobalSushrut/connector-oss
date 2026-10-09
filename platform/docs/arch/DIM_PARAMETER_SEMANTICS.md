# DIM Parameter Semantics

Persistent dynamic intelligence state `Z_t` (15 coordinates + diagnostics).  
Values are **condition** metrics in `[0, 1]` unless noted — never permissions.

## Coordinates

| Sym | Name | Meaning | v0 estimate sources |
|-----|------|---------|---------------------|
| K | Coherence | Belief/mission/identity consistency | BeliefSnapshot coverage, DAL phase, contract present |
| E | Prediction error | Predicted vs observed mismatch | AAPI outcome vs expected; Knot mismatch |
| P | Precision | Confidence in evidence/beliefs | Trust × freshness × source reliability |
| H | Cognitive entropy | Disorder across hypotheses/actions | KECS disorder / EGCM disorder |
| M | Metastability | Useful reconfiguration without chaos | Inverse of (H×E) clamped |
| L | Plasticity | Willingness to revise models | Novelty × (1−Q) × evidence_strength |
| C | Consolidation | Strength of verified persistence | Recent consolidated packet rate |
| X | Interference | Memory/goal/evidence conflict | Contradiction / IE pressure |
| A | Affordance density | Density of useful candidate transitions | AffordanceEnvelope slot count (normalized) |
| Ψ | Empowerment | Reliable influence on desired futures | Tool success EMA, grant readiness |
| R | Resource potential | Compute/context/budget/tools | Trajectory budget remaining + token headroom |
| G | Goal tension | Distance to desired outcomes | Mission incompleteness / frontier size |
| T | Temporal pressure | Deadlines, staleness, wait | Deadline / freshness / commitment urgency |
| Q | Consequence pressure | Cost of being wrong | RGO class × irreversibility × uncertainty |
| S | Self-continuity | Match to durable worldline | Identity + journal + Knot present after restart |

## Diagnostics

| Field | Meaning |
|-------|---------|
| `Θ` cognitive_temperature | Exploration vs exploitation (never authority) |
| `Φ_I` homeodynamic_potential | Distance outside viability bands |
| `regime` | CognitiveRegime classification |
| `evidence_refs` | CIDs / receipt ids backing this snapshot |

## Viability bands

Each `Z_i` has `[lo, hi]` (allostatic). Defaults in code; enterprise profiles may override via `dynamic_intelligence` config (future). Crossing bands raises `Φ_I` and triggers regulation — **not** deny.

## Persistence

Folder: `dim_state` keyed by `agent_pid`. Schema: `connector.dim.state.v1`.
