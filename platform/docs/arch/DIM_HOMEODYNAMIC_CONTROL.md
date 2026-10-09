# DIM Homeodynamic Control

## Potential

```
Φ_I = Σ_i w_i · D(Z_i, [l_i, u_i])
```

Low Φ → healthy · Moderate → regulate cognition · High → contract/verify/pause · Critical → escalate human coupling.

## Maintenance loop (deterministic)

1. Sample observers (Knot, AAPI, mission, resources, time)
2. Estimate `Z_t`
3. Compute `Φ_I` and regime
4. Choose bounded `RegulationAction` `u_h` (min Φ + cost)
5. Apply micro-regulation (no authority change)
6. Persist journal entry; repeat

LLMs are invoked only when a transition needs generative cognition — not every tick.

## Allowed RegulationAction

`IncreaseRecallRadius` · `DecreaseRecallRadius` · `IncreaseVerification` · `DecreaseCandidateBreadth` · `IncreaseCandidateBreadth` · `PauseConsolidation` · `ResumeConsolidation` · `RefreshWorldEvidence` · `ReduceToolParallelism` · `IncreaseCounterfactualDepth` · `WakeCognition` · `EnterWaiting` · `IncreaseHumanCoupling`

## Forbidden (never in enum)

`GrantCapability` · `WidenWorldGrant` · `OverrideNF3` · `CreateApproval`

## Cognitive temperature

`Θ` rises with E, H, X and falls with K, P. It widens candidates / verification — **never** grants.

## Multi-timescale

| Loop | Examples |
|------|----------|
| Fast | H, R, Θ, temporary P, Q |
| Medium | A, X, Ψ, T, G |
| Slow | C, durable priors, causal edges |

## CIP / DAL

CIP executive and DAL run state are **consumers** of DIM regulation (breadth, stop, wake). DIM owns Z_t; DAL owns mission lineage CIDs.
