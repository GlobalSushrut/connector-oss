# Connector Context Rollup System

Production data fading, memory consolidation, causal skeletons, and long-term agent accountability.

**Core principle:** Fade information, never fade consequence.

## Problem

Hot/warm/cold memory tiers bound *active* context growth. Long-lived agents still accumulate cold evidence at rates that can exceed **86 GB/day** at scale. Connector needs progressive conversion:

```text
INGEST → CONSOLIDATE → ROLL UP → FADE → RETAIN CAUSAL MEMORY
```

## Enable

```bash
export CONNECTOR_AGENT_MEMORY=1      # required base plane
export CONNECTOR_CONTEXT_ROLLUP=1    # rollup engine (also on with agent memory)
# Optional destructive raw removal after tombstone:
export CONNECTOR_ROLLUP_DELETE_RAW=1
```

## Four fade states (F0–F3)

| State | Retained | Purpose |
|-------|----------|---------|
| **F0 FULL** | Raw payload + hashes | Maximum reconstruction |
| **F1 DISTILLED** | Excerpts, normalized facts, source hash | Material state impact |
| **F2 DECISION** | `DecisionMemory` fields | Operational memory |
| **F3 SKELETON** | `CausalMemorySkeleton` + tombstone | Long-term lineage |

## Four proof levels (P0–P3) — TraceTramp honesty

| Level | Symbol | Operator sees |
|-------|--------|---------------|
| **P0 FULL** | ● | Raw source reconstructable |
| **P1 DISTILLED** | ◉ | Critical excerpts available |
| **P2 CONTEXTUAL** | ○ | Decision + moment, not all raw |
| **P3 COMMITMENT** | · | Hash + tombstone only |

`MomentProof` carries `proof_level_at_creation` and `current_proof_level` so TraceTramp can show aging honestly.

## Fade score

```
score = w_t·T + w_s·S + w_c·C + w_a·A + w_r·R + w_u·U + w_h·H + epistemic_penalty
```

High score → eligible to fade. FadeLock, E0 authority, unresolved dependencies → **FADE DENY**.

Thresholds: T1=0.15 (F0→F1), T2=0.45 (→F2), T3=0.75 (→F3).

## Rollup pipeline

```text
RAW EVENT → hash + EvidenceRecord (F0)
         → context delta + promotion
         → agent decision / action
         → MomentProof + CausalMemorySkeleton
         → rollup eligibility engine
              ├── preserve (FadeLock / E0 / dependency)
              ├── distill (F0→F1)
              ├── decision-only (F1→F2)
              └── skeleton (F2→F3 + EvidenceTombstone)
         → TraceTramp (proof level display)
```

## Fail-closed rule

Before permanent fade (F3):

- No FadeLock
- Retention policy permits
- No unresolved action dependency
- Decisive facts persisted in DecisionMemory / skeleton
- Source hash retained
- Tombstone written
- Proof downgrade recorded in `ContextRollup`

If any check fails: **DO NOT DELETE RAW DATA**.

## Schemas (`connector-trust/context_rollup.rs`)

- `FadeState`, `ProofLevel`, `FadeLock`, `FadePolicy`
- `EvidenceTombstone`, `ContextRollup`
- `CausalMemorySkeleton`, `DecisionRollup`, `SessionRollup`, `DailyAgentRollup`
- `AgentRollupBudget`, `RollupMetrics`, `RollupExplain`

## Operator API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/rollup/posture` | Rollup status |
| GET | `/api/v1/rollup/:agent_vid/metrics` | F0–F3 / P0–P3 counts |
| GET/PUT | `/api/v1/rollup/:agent_vid/policy` | Per-agent FadePolicy |
| GET | `/api/v1/rollup/:agent_vid/explain/:evidence_id` | Why fade allowed/denied |
| POST | `/api/v1/rollup/:agent_vid/aging-pass` | Run eligibility pass |
| POST | `/api/v1/rollup/:agent_vid/scheduled-pass` | Minute + daily + aging |
| POST | `/api/v1/rollup/:agent_vid/rehydrate/:evidence_id` | Restore from archive |
| POST | `/api/v1/rollup/:agent_vid/lock/:evidence_id` | FadeLock |
| GET | `/api/v1/rollup/tombstone/:evidence_id` | Tombstone lookup |
| POST | `/api/v1/rollup/demo/c0c10` | C0–C10 aging acceptance |
| GET | `/api/v1/forensics/moments/:agent_vid` | Moment index + proof symbols |

## CLI

```bash
connectorctl rollup posture
connectorctl rollup metrics --agent AGT-...
connectorctl rollup explain --agent AGT-... --evidence E-...
connectorctl rollup aging-pass --agent AGT-... --limit 50
connectorctl rollup scheduled-pass --agent AGT-...
connectorctl rollup rehydrate --agent AGT-... --evidence E-...
connectorctl rollup demo
connectorctl moment show --id M-...   # includes tracetramp proof view
```

## TraceTramp integration

`GET /api/v1/forensics/moment/:id/proof` returns:

- `moment` — full `MomentProof`
- `tracetramp` — proof symbol, reconstruction flags, causal skeleton
- `chain_verified` — evidence hash chain status

TraceTramp admin:

- `GET /admin/moments/:agent_vid` — moment index with ●◉○· legend
- `GET /admin/moments/proof/:moment_id` — display envelope
- `GET /admin/rollup/:agent_vid/explain/:evidence_id` — fade explain

Example display fields:

- Evidence Resolution: P2 CONTEXTUAL
- Original raw report: FADED
- Decision reconstruction: AVAILABLE
- Exact original pages: NOT AVAILABLE

## Retention classes (§15)

| Class | Preset | Notes |
|-------|--------|-------|
| telemetry | fast F0→F3 | noise |
| research | 7d / 30d | default research |
| owner_instructions | slow, min P1 | E0-like |
| financial_actions | legal hold 7y | never fade |
| security | slow, min P2 | incidents |
## What must survive (normally F2/F3 persistent)

Owner authority change, policy change, delegation, revocation, human override, agent commitment, consequential decision, external action, denied action, security event, correction, high-risk contradiction, material failure, legal hold.

## What may fade aggressively

Duplicate telemetry, status polls, unchanged API responses, intermediate search pages, low-value model chatter, superseded noncritical state.

## Related

- [CONNECTOR_AGENT_MEMORY.md](./CONNECTOR_AGENT_MEMORY.md) — MEMORY / EVIDENCE / FORENSICS planes
- Full spec: `.cursor/plans/agent_memory_architecture_0d3c9741.plan.md` Section B
