# Connector Agent Memory Architecture

Production agent memory separates three planes:

| Plane | Role | Hot budget | Storage |
|-------|------|------------|---------|
| **MEMORY** | Runtime context for LLM/tool steps | 8–64 KB (`AgentMemoryCapsule`) | Engine store folder `agent_memory_capsule` |
| **EVIDENCE** | Append-only cold index of writes | unbounded (hash chain) | `agent_memory_evidence_chain` + `agent_memory_evidence_index` |
| **FORENSICS** | Moment-level proof export | 1–4 KB (`MomentProof`) | `agent_memory_moments` |

## Enable

```bash
export CONNECTOR_AGENT_MEMORY=1
# Optional hard cap enforcement (refuse oversized capsules):
export CONNECTOR_AGENT_MEMORY_HARDEN=1
```

Also enabled when `CONNECTOR_AUGMENTED_ENV=1` (augmented production posture).

## Schemas (`connector-trust`)

- `EvidenceRecord` — hash-linked cold evidence index (E0–E4 epistemic class)
- `AgentMemoryCapsule` — bounded hot runtime capsule with `ContextReference`
- `DecisionMemory` — decisions, not transcripts
- `MemoryPoint` — 3D context matrix point (time × entity × consequence)
- `ContextDelta` / `ContextCheckpoint` / `ContextTransition` — reconstructable context lineage
- `MomentProof` — forensic entry point for a single moment

## Write path (MemWrite)

On successful `MemWrite` when agent memory is enabled:

1. Append `EvidenceRecord` to per-agent hash chain
2. Append `ContextDelta` and bump `context_epoch` / `context_root`
3. Promote high-score facts to `MemoryPoint` (warm/hot tiers via promotion score P_m)
4. Checkpoint when delta count, time, or consequential trigger thresholds hit

## Talk path (gateway)

Before LLM dispatch, build/inject `AgentMemoryCapsule` as a system block tagged
`[connector.agent_memory_capsule]`. Harden mode rejects capsules over 64 KB.

## PATE (ATU)

When enabled, `AugmentedTaskUnit.context_ref` carries the committed `ContextReference`
(epoch + context_root) at mint time.

## Operator API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/agent-memory/posture` | Plane status + flags |
| GET | `/api/v1/agent-memory/capsule/:agent_vid` | Current AMC |
| GET | `/api/v1/forensics/moment/:moment_id/proof` | MomentProof + chain verify |

## CLI

```bash
connectorctl moment posture
connectorctl moment show --id M-...
```

## Promotion score

```
P_m = 0.30·authority + 0.25·consequence + 0.20·recency + 0.15·confidence + 0.10·volatility
```

- `P_m ≥ 0.75` → hot (AMC)
- `P_m ≥ 0.45` → warm (`MemoryPoint`)
- else → evidence-only

## Related

- VAC MemPacket kernel (`oss/vac/crates/vac-core`) — packet SoT
- ARC / COPG — agency graph; checkpoint delta storage
- **Context Rollup** — [CONNECTOR_CONTEXT_ROLLUP.md](./CONNECTOR_CONTEXT_ROLLUP.md) — F0–F3 fade, P0–P3 proof levels
- TraceTramp / WitnessCtl — moment-first forensics UI

Full specification: `.cursor/plans/agent_memory_architecture_0d3c9741.plan.md`
