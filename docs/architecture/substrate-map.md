# Substrate Map — Ten Constitutional Primitives

Maps each Connector OS constitutional primitive to **existing** crates and modules.
Workflows (TraceTramp, WitnessCtl, DevGuard) must compose these mechanisms; they must not reimplement them with hidden bypasses.

Authority: [docs/00-constitutional-preamble.md](../00-constitutional-preamble.md).
Shared contracts: `oss/connector/crates/connector-trust`.

| Primitive | Primary implementation | Supporting modules | Workflow duplication / gaps |
|---|---|---|---|
| **Identity** | `platform/server/src/auth/core.rs` (`Claims`, JWT verify) | `oss/connector/crates/connector-protocol/src/identity.rs`; `connector-trust::PrincipalContextV2` | TraceTramp/WitnessCtl mint local sessions; must consume platform principal |
| **Authority** | `platform/server/src/auth/rbac.rs` | `oss/connector/crates/connector-caps`; `connector-trust::CapabilityGrantV2`; plugin hub grants | Ambient admin tokens in plugins |
| **Memory** | VAC kernel (`oss/vac/crates/vac-core`) | `memory.rs`, `memory_vector_box.rs` (`MemoryVectorBox` super_key+identity_key); Knot / relational | Play via `/memory/vector-box` + `/memory/data-context` |
| **Execution** | `platform/server/src/services/admission.rs` | `substrate/graph_firewall.rs` (relation-graph rules + agentic breaker), `admission_gate.rs`, guard pipeline, multiagent orchestration | Step 1.6 graph firewall → Step 2 guard; `/infra/orchestrator` = DAG planner only |
| **Isolation** | `platform/plugin-runtime/` | cage_security grade gates, microvm/docker fail-closed | Prod requires microvm/docker; subprocess break-glass only |
| **Naming / communication** | CNP / `connector-glue` / `connector-protocol` routing | plugin proxies, service discovery | Cage names not cryptographically bound to API keys |
| **Resources** | Admission + agent quotas / budgets | `agents.rs` tenant caps, billing token counters | Budgets not always atomic with admission |
| **Causality / audit** | VAC `make_audit` / `verify_audit_chain` | actionlog services | Kernel chain is hash-linked (not keyed HMAC despite comments) |
| **Proof / custody** | `platform/server/src/services/proof.rs` | WitnessCtl `receipt.rs`; `CustodyReceiptV2` | Several proof endpoints historically hardcode validity |
| **Lifecycle** | VAC kernel `AgentRegister/Start/Terminate` | `substrate/agent_progeny.rs` — kernel `parent_pid`/`child_pids` tree, cascade terminate; `GET /api/v1/agents/sot-status` | `agent_lifecycle::AgentRegistry` is orphaned; product SoT = `services::agents` + kernel ACB (`dual_registry=false`) |

## Trust contract crate

| Type | Role |
|---|---|
| `PrincipalContextV2` | Verified identity inserted by auth middleware |
| `CapabilityGrantV2` | Scoped, expiring grants |
| `GovernedRequestV2` | Normalized admission input |
| `AdmissionTicketV2` | Gate approval (lifted from `AdmissionTicket`) |
| `CausalEnvelopeV2` | Canonical lineage schema (wired in R3) |
| `CustodyReceiptV2` | Portable receipt with explicit verification status |
| `ForensicFlowIdentityV2` | CFNI flow stamp (`x-connector-flow-id`); mesh relay verify on egress routes |
| `PrincipalContextV2` outbound | `x-connector-principal-context` on TT/WC/cage proxy (`substrate/outbound.rs`) |
| `UsageEventV2` | Immutable usage SoT for books projections |
| `ArtifactLogRecordV2` | Append-only artifact log entries |

Platform wiring: `platform/server/src/substrate/` · operator APIs: `platform/server/src/operator/`.

Backend track (no UI): [BACKEND_TOP_GRADE_TRACK.md](../../BACKEND_TOP_GRADE_TRACK.md)

Machine-readable inventory: [route-security-inventory.json](./route-security-inventory.json).  
Admission effect → gate matrix: [admission-matrix.md](./admission-matrix.md).

## Claim honesty

- Audit chain integrity is **keyed HMAC-SHA256** (`CONNECTOR_AUDIT_HMAC_KEY`) with recompute verification in `vac-core` (`make_audit` / `verify_audit_chain` / `sign_audit_entry`). Production / defense-strict must set a real key — the lab default material is rejected at boot.
- Residual audit gaps: HMAC canonicalization still covers a narrow field set (id/ts/op/pid/outcome); full envelope MAC + external anchoring remain follow-ups.
- Proof `"verified": true` must only appear after independent recomputation. `generate_proof` persists artifacts as **unverified** until recompute passes.
- Open auth / synthetic principals are **non-production** and must remain loopback-bound under defense-strict.
- **Doctrine (coders):** MemPackets / ArtifactLog / UsageEvent are SoT; TraceTramp / WitnessCtl / Postgres are projections; Knot rebuilds from packets; HA / automatic failover is **not** product SoT (single-node).

## Tool report & maturity path

- Capability + forensics/WF placement: [IMP_1000.md](../../IMP_1000.md)
- Final user outcomes: [FINAL_OUTCOME.md](../../FINAL_OUTCOME.md)
- Chaos → universal DI substrate: [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](../../CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md)
- 30-iteration Core/Backend/UI checklist: [MATURITY_CHECKLIST_30.md](../../MATURITY_CHECKLIST_30.md)
- 21-segment maturity + coding upgrade plan: [MATURITY_21_SEGMENTS.md](../../MATURITY_21_SEGMENTS.md) · [MATURITY_21_UPGRADE_PLAN.md](../../MATURITY_21_UPGRADE_PLAN.md)
- Coder doctrine (SoT rules): [doctrine-coders.md](./doctrine-coders.md)
- WF projection adapters (TT/WC): [wf-projection-adapters.md](./wf-projection-adapters.md)
- Operator UI makeover (page-by-page): [UI_MAKEOVER_PLAN.md](../../UI_MAKEOVER_PLAN.md)
