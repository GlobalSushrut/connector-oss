# Connector Semantic Virtualization Fabric (SVF)

SVF is the **semantic projection + labeling + view compilation** slice of Connector
capability §15 (Data Tokenization). It is **not** a second OS and does **not**
replace PATE, WorldGrant, DIM, ARC, AffordanceEnvelope, or effect exclusivity.

| Plane | Owns | Does not own |
|-------|------|--------------|
| **PROJECT / EXPAND** | Minimum sufficient model view (S0–S5) | Allow verdict |
| **RESOLVE** | Private topology / credential binding lookup | Lease mint |
| **MATERIALIZE** | Last-hop CDP inject / action-broker | Guest cage policy |
| **DisclosureReceipt** | What was shown to which sink | Court binder alone |

## Phase 1b — CDP + remask

- Materialize via `svf::materialize_after_admit` (ActionBroker default; WorldGrant when `CONNECTOR_SVF=1` and vault refs present)
- Quarantine freezes CDP (`assert_cdp_thawed`)
- Tool results remasked via `svf::remask_observation` before next LLM

## Phase 2 — SEMANTICIZE + PROJECT

- MemPacket entities + Knot nodes → `svf_agentic_objects` store
- Dual-format handles `{{obj:type.id}}` + `⟦conn:obj:…⟧`
- Talk injects `[connector.svf.projection]` beside agentic_context

## Phase 7 — Ops / CLI / TraceTramp / REACH

- Status: `substrate.status.svf` already beside arc/agent_memory/rollup
- CLI: `connectorctl svf posture|objects|stubs|grants|derived|receipts|fade-sync`
- CLI: `connectorctl dal posture|start|show`
- Receipts: `GET /api/v1/svf/receipts/:agent` — disclosure vs effect
- TraceTramp: `svf_honesty` on MomentProof — disclosure (EXPAND) ≠ materialize (CDP)
- REACH: A10b–A10g gated in [CONNECTOR_REACH_CHECKLIST.md](./CONNECTOR_REACH_CHECKLIST.md)

## Phase 6 — Memory / rollup / graph

- Object relations via COPG `svf_*` (+ optional Knot mirror); belief field stays cognitive
- `POST /svf/derived` → evidence E2 + MomentProof + lineage edges
- Fade bind: EvidenceMeta F0–F3 / P0–P3 → `ContextFragment.fade_state` (hooked from rollup)

## Phase 5 — DAL owns the turn

- `POST /api/v1/dal/start` — stamp live `broker_epoch` + `SvfEpoch`
- `POST /api/v1/dal/:run_id/turn` — PROJECT → proposals → `agent_loop` → LTL stitch
- CIP `should_inhibit_effect` + exclusivity asserted before Act
- Ring-1: proposals only; Talk never auto-dispatches; tools keep the sandwich

## Phase 4 — RESOLVE / MATERIALIZE / OBSERVE

- `POST /api/v1/svf/resolve` — private binding lookup (no lease mint)
- `POST /api/v1/svf/materialize` — PATE + lease + RESOLVE + ActionBroker CDP (no world effect alone)
- Tool results: remask → MemPacket ToolResult + COPG `svf_observe` + re-SEMANTICIZE
- MomentProof via existing `pate::complete_augmented_task`

## Phase 3 — EXPAND + progressive tools

- `POST /api/v1/svf/expand` — purpose-bound S0–S4; S5 denied on model plane (`BrokerDecision`)
- `DisclosureGrant` ceilings; quarantine freezes grants/CDP
- MCP tool stubs S0→S2 via `GET /api/v1/svf/tools/stubs/:agent_vid`
- Talk injects S0 tool stub names beside projection

## Enable

```bash
export CONNECTOR_SVF=1
# Also follows CONNECTOR_AUGMENTED_ENV / unbypassable LLM lane when those are on.
```

## Authority honesty

- **PDP** = ActionBinding + NF³ + PATE (Admit digest over **opaque** handles)
- **CDP** = `credential_proxy` **after** Admit (+ WorldGrant pore)
- AffordanceEnvelope **shrinks only** — SVF may label reachable surface, never widen it
- DIM / Knot / “usefulness” **never** flip Fail→Pass

## Correct sandwich (Rings 6–7)

```text
REAL INPUT
  → SEMANTICIZE / tokenize+seal
  → residual scan (fail-closed leftovers; never redact-first wipe)
  → PROJECT → LLM
  → validate opaque egress
  → PDP: pate.admit_* (opaque digest)
  → ARC lease (when CONNECTOR_ARC_LEASE=1)
  → expand_after_admit + CDP materialize
  → Ring 7 effect
  → OBSERVE remask → VAC / COPG / MomentProof
```

**Never:** redact-first tokenizable secrets · expand-before-Admit under IFC · secrets in guest env · SVF mint Allow.

## Schemas (`connector-trust`)

- `AgenticObject` / `SemanticHandle` (`{{obj:type.id}}` + `⟦conn:…⟧`)
- `ContextManifest` / `Projection` / `DisclosureLevel` S0–S5
- `DisclosureGrant` / `DisclosureReceipt`
- `ResolveRequest`/`Result` · `MaterializationRequest`/`EffectReceipt`
- `SvfEpoch` (broker · iac · policy) · `TaskRequestEnvelope` · `BrokerDecision`
- `DerivedKnowledge` · `ObservationRemaskReport`

## Live insert points

| Path | Module | SVF role |
|------|--------|----------|
| Talk | `services/gateway.rs` | tokenize/seal before residual redact; PROJECT inject |
| Broker | `llm_broker_gate` | `egress_validate` → (Admit) → `expand_after_admit` |
| Tools | `services/tools.rs` | opaque Admit → CDP ActionBroker → remask observation |
| SEMANTICIZE | `substrate/svf/semanticize` | MemPacket + Knot → object store |
| PROJECT | `substrate/svf/project` | S0/S1 Talk block `[connector.svf.projection]` |
| IFC D3 | `arc/ifc` | detok only post-Admit when `CONNECTOR_ARC_IFC=1` |

## Operator API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/svf/posture` | Plane status + flags |
| GET | `/api/v1/svf/objects/:agent_vid` | SEMANTICIZE + list AgenticObjects |
| POST | `/api/v1/svf/expand` | Purpose-bound EXPAND (S0–S4) |
| POST | `/api/v1/svf/resolve` | Private binding + WorldGrant pore lookup |
| POST | `/api/v1/svf/materialize` | Admit + lease + RESOLVE + CDP |
| POST | `/api/v1/dal/start` | Start DAL run (live broker_epoch) |
| POST | `/api/v1/dal/:run_id/turn` | Governed turn (proposals → tools) |
| GET | `/api/v1/dal/:run_id` | Run snapshot + CIP |
| POST | `/api/v1/svf/relations` | Object↔object COPG edge |
| GET | `/api/v1/svf/relations/:agent_vid/:object_id` | List related objects |
| POST | `/api/v1/svf/derived` | DerivedKnowledge → evidence + MomentProof |
| GET | `/api/v1/svf/derived/:agent_vid` | List derived |
| POST | `/api/v1/svf/fade/sync/:agent_vid` | Sync fragment fade from rollup |
| POST | `/api/v1/svf/grants` | Mint DisclosureGrant |
| GET | `/api/v1/svf/grants/:agent_vid` | List grants |
| GET | `/api/v1/svf/tools/stubs/:agent_vid` | Progressive MCP stubs |
| GET | `/api/v1/svf/receipts/:agent_vid` | Disclosure + effect receipts |
| CLI | `connectorctl svf …` | Operator posture / objects / stubs / grants |
| CLI | `connectorctl dal …` | DAL start / show / posture |

## Related

- [CONNECTOR_FULL_ARCHITECTURE.md](./CONNECTOR_FULL_ARCHITECTURE.md) Part VI / XV
- [CONNECTOR_CAPABILITY_STANDARD.md](./CONNECTOR_CAPABILITY_STANDARD.md) §13 · §15
- [CONNECTOR_REACH_CHECKLIST.md](./CONNECTOR_REACH_CHECKLIST.md) A10b–A10g
- [EFFECT_EXCLUSIVITY.md](./EFFECT_EXCLUSIVITY.md)
- [LLM_TOKENIZATION_PLANE.md](./LLM_TOKENIZATION_PLANE.md)
- [CONNECTOR_AGENT_MEMORY.md](./CONNECTOR_AGENT_MEMORY.md) · [CONNECTOR_CONTEXT_ROLLUP.md](./CONNECTOR_CONTEXT_ROLLUP.md)
- [CONNECTOR_ARC.md](./CONNECTOR_ARC.md) · [CONNECTOR_SDB_RUNTIME.md](./CONNECTOR_SDB_RUNTIME.md)

Plan: `.cursor/plans/semantic_virtualization_fabric_219c84ec.plan.md`
