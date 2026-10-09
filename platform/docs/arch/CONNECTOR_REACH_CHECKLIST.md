# Connector — Reach Checklist

**Purpose:** Ordered checklist to reach the [capability standard](CONNECTOR_CAPABILITY_STANDARD.md) as **Connector software**: engineer envelope made real (tools · env · isolation · monitoring · proof) with E/A/S pass and the five invariants.  
**Pass rule:** Same as [FINAL_OUTCOMES](CONNECTOR_FINAL_OUTCOMES.md) — capability + honesty, not “100% secure.”  
**How to use:** Work top→bottom. Mark `[x]` only when **verify hint** passes on a real node (playground or harden as stated). Update [Appendix A](CONNECTOR_CAPABILITY_STANDARD.md#appendix-a--engineered-standard-map-what-already-exists) when a row flips Partial→Engineered.

### Current standing (read this first)

| In scope for “standard reached” | Out of scope (do not treat as finish line) |
|---------------------------------|--------------------------------------------|
| Posture honesty, effect exclusivity, engineer profiles, DIM/Knot/AAPI effect-field, proof export, membrane gates | **Compliance demos**, BANKING/HEALTH “profile compile” showcases, claiming org is “compliant,” certification theater |
| E1–E8 · A1–A28 · S1–S28 verify | Mapping Connector into every GRC framework as a product milestone |
| Five invariants + CI anti-claims | `services/compliance.rs` HIPAA/SOC2/EU-AI-Act **report UIs** as proof the substrate standard is done |

Existing `/api/v1/compliance/*` routes are **optional org/GRC tooling** already in the tree. They are **not** the Connector capability standard. Standard §§26–30 only require: evidence/proof the org can map themselves — delivered by worldline export + digests/receipts, not by a “compliance demo.”

**Real augmented env (not lab):** set `CONNECTOR_AUGMENTED_ENV=1` — see [CONNECTOR_AUGMENTED_ENV.md](CONNECTOR_AUGMENTED_ENV.md).  
**Operational spine:** [CONNECTOR_OPERATIONAL_SOFTWARE.md](CONNECTOR_OPERATIONAL_SOFTWARE.md) — Talk/tools/start/recall/spend on live paths.  
**Target agency plane:** [CONNECTOR_ARC.md](CONNECTOR_ARC.md) · implement via [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md) (Phases A–H). Not a finish-line for E/A/S; deepens L3–L5 on the same spine.

**Legend**

| Mark | Meaning |
|------|---------|
| `[x]` | Surface exists; verify once on your deploy |
| `[~]` | Partial — code exists; must harden / productize / prove |
| `[ ]` | Still open against the standard |
| `[LAB]` | Honest LAB / host-unavailable — Engineered for honesty, not for apply |

---

## Phase 0 — Docs & honesty spine (must stay green)

- [x] Parent SoT: `CONNECTOR_CAPABILITY_STANDARD.md`
- [x] Promise: `CONNECTOR_PRODUCT_PROMISE.md` (no absolute-security claim)
- [x] Outcomes: `CONNECTOR_FINAL_OUTCOMES.md` (E / A / S)
- [x] Companions: DIM · AAPI · Knot docs
- [x] `ARCHITECTURE.md` links standard + promise + outcomes + operational software
- [x] CI: `bash scripts/audit-product-promise.sh` in repo-hygiene
- [x] Release notes / UI / docs audited against **Anti-claims** (FINAL_OUTCOMES) via `audit-product-promise.sh`

**Verify:** `bash scripts/audit-product-promise.sh` → PASSED

---

## Phase 1 — Engineer freedom (E1–E8)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | E1 | Profile continuum + LAB/applied visible | `GET /api/v1/product/promise` + `/substrate/status` → `lab_mode` / `applied_truth` |
| [x] | E2 | Compose limits independently (contract, grant, tier, budget, tokenize, DIM bands) | `CONNECTOR_DIM_BANDS_JSON` + `dim::bands` · `/substrate/status` → `dim_bands` |
| [x] | E3 | Isolation tier choice; report applied | Soft + **KVM Effective**: `artifacts/cvr-acceptance/cvr-kvm-acceptance.json` → `effective_claim=true` |
| [x] | E4 | DIM regulate without changing NF³ | `POST /dim/:pid/regulate` → `authority: unchanged` |
| [x] | E5 | Proof export | `GET /proof/export/:agent_pid` digests/receipts/DIM/ledger/**packet_dna** |
| [x] | E6 | Monitor without CoT | `GET /operator/pulse` → denials + spend + HITL + DIM (no CoT) |
| [x] | E7 | Lab honesty when gates off | Soft-fail labeled LAB; never “production-ready” |
| [x] | E8 | Escape hatches named + audited | `/substrate/status` → `escape_hatches` · audit script |

**Phase 1 exit:** E1–E8 verified on playground **and** harden refuse-start demo when a mandatory gate is missing.

---

## Phase 2 — Identity & membrane (A1–A8, §3–4, §13–14)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | A1 | Bound identity; no ambient LLM effects | `enforce_real_agent_talk` + `CONNECTOR_GATEWAY_BAN_ANON` (pilot/harden) |
| [x] | A2 | Contract floor | `require_contract_action` on tool.dispatch under harden |
| [x] | A3 | Cage soft-fail loud | `soft_fail_lab` on landlock applied_truth; not green “applied” |
| [x] | A4 | Memory namespace `m/{pid}` | New agent packets only in own ns |
| [x] | A5 | WorldGrant pores | `CONNECTOR_WORLD_GRANTS_FAIL_CLOSED` + world_gateway admit |
| [x] | A6 | Packet DNA on outbound | `mint_require_and_log` on tools + CONP when `CONNECTOR_PACKET_DNA_REQUIRE` |
| [x] | A7 | Continuity Broken → egress cut | matrix + governed_effect deny; HW cut LAB if tools absent |
| [x] | A8 | Charter change re-individuates | `demote_after_charter_change` → SetupReady + quanta revoked |

**Phase 2 exit:** Harden profile checklist: identity ✓ contract ✓ WorldGrant ✓ ActionBinding ✓ — unmet → **START REFUSED** (§16 honesty).

---

## Phase 3 — Tokenization, budgets, blast (A9–A14, §15, §17)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | A9 | Ingress tokenize/seal | Pilot: `CONNECTOR_LLM_DATA_TOKENIZE=1` + broker |
| [x] | A10 | Detokenize only on admitted effects | `egress_validate_opaque` → `pate.admit_*` → `expand_after_admit` (IFC D3) |
| [x] | A10b | SVF progressive disclosure receipts | `CONNECTOR_SVF=1` · `DisclosureReceipt` on expand · [CONNECTOR_SVF.md](./CONNECTOR_SVF.md) |
| [x] | A10c | SVF EXPAND S0–S4 + tool stubs | `POST /svf/expand` · grants · `GET /svf/tools/stubs/:agent` |
| [x] | A10d | SVF status posture | `/substrate/status` → `svf.enabled` · `GET /svf/posture` |
| [x] | A10e | `connectorctl svf` | `connectorctl svf posture|objects|stubs` |
| [x] | A10f | TraceTramp disclosure≠materialize | MomentProof `tracetramp.svf_honesty` |
| [x] | A10g | Materialize ≠ world effect alone | `POST /svf/materialize` honesty + EffectReceipt |
| [x] | A11 | Budget exhaustion stops spend | Talk/API refuse via `ops_runtime::spend_tokens` BCR |
| [x] | A12 | BCR reserve→commit; overspend refuse | `/aapi/budgets/*` **and** live Talk/Anthropic paths |
| [x] | A13 | Trajectory caps | Exhausted trajectory blocks further effects |
| [x] | A14 | Playground session reap + agent cap | Cap hit → registration denied |

**Phase 3 exit:** One demo agent with capital/orders/time envelope (standard §17 example shape).

---

## Phase 4 — Cognition (A15–A20, §6–11, DIM/Knot)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | A15 | Persistent DIM Z_t | Restart → `GET /dim/:pid` same revision family |
| [x] | A16 | DIM regulates cognition only | Authority-attack: high K/Ψ → NF³ unchanged |
| [x] | A17 | Durable memory + recall | Restart → `/memory/retrieve/:pid` hits |
| [x] | A18 | Interference on contradiction | `/knot/:pid/interference` after contradict |
| [x] | A19 | Idle wake without new prompt | `/dim/:pid/wake/evaluate` under pressure |
| [x] | A20 | Model-replaceable mind | `PATCH /agents/:pid` → `set_model_ref` · `scripts/smoke-model-swap.sh` |

| Done | S | Task | Verify |
|------|---|------|--------|
| [x] | S6–S8 | DIM inspect / refresh / regulate | APIs return operator_view |
| [x] | S9 | Idle wake | wake folder + pending API |
| [x] | S10 | Authority-attack automated | `audit-authority-attack.sh` + dim unit test |
| [x] | S11–S13 | Recall + ReadSet + interference | memory_retrieval + knot_belief_field |
| [x] | S14 | Non-destructive consolidate | `POST /memory/consolidate` → `non_destructive: true` |
| [x] | S15 | Selective foresight | `/knot/:pid/foresight` |

**Phase 4 exit:** DIM-EVAL authority-attack in CI; A20 e2e green.

---

## Phase 5 — Effects & accountability (A21–A28, §18–19, AAPI S16–S20)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | A21 | Digest-bound HITL | `hitl_binding_tests::digest_a_cannot_execute_as_digest_b` |
| [x] | A22 | Proportional autonomy R0/R1 vs R3 | `harden_suite_r0_r1_r3` · R3 → HitlDigest |
| [~] | A23 | Receipt every admitted effect | Durable ledger + mission step exist; a PATE completion does not yet append an IntelligenceReceiptV2 for every effect |
| [~] | A24 | Compensation when inverse registered | Compensation receipt is recorded; the inverse still needs a PATE-admitted execution |
| [x]/[LAB] | A25 | CONP without SIL theater | Lab echo labeled; DNA on CONP when required; partner HAL = LAB |
| [x] | A26 | Narrowed child + paired receipts | progeny link + proof export progeny/links |
| [x] | A27 | Operator stop/inspect without CoT | `POST /agents/:pid/operator-stop` → regime/Φ only |
| [x] | A28 | No self-authorization (CI) | `audit-authority-attack.sh` + dim test |

| Done | S | Task | Verify |
|------|---|------|--------|
| [x] | S16 | Durable AAPI ledger | `/aapi/ledger/:pid` + boot hydrate |
| [x] | S17 | BCR spend | reserve/commit/release |
| [x] | S18 | Idempotent retry | BCR idempotency key on `spend_tokens` |
| [~] | S19 | Compensate | Receipt recorded; inverse execution through the governed spine is still open |
| [x] | S20 | CONP DNA honesty | DNA mint on CONP when required |

**Phase 5 exit:** Ungated mutating HTTP paths inventoried → closed or labeled LAB (effect exclusivity S24).

---

## Phase 6 — Isolation & profiles (§16, E3, playground/pilot/harden)

| Done | Task | Verify |
|------|------|--------|
| [x] | Report **Requested / Applied / Effective** on posture | `harden_posture` / `product_promise.posture.harden_triad` |
| [x] | Harden: missing mandatory primitive → **START_REFUSED** | `assert_harden_ready_for_start`; set `CONNECTOR_AUGMENTED_ENV=1` |
| [x] | Playground UI shows **LAB / PLAYGROUND** | Operator `LabModeBanner` + `/substrate/status` `lab_banner` |
| [x] | Pilot profile preset (grants+budgets+selective tokenize) | `CONNECTOR_PRESET=pilot` |
| [x] | Harden / augmented env enablement | [CONNECTOR_AUGMENTED_ENV.md](CONNECTOR_AUGMENTED_ENV.md) |
| [x] | T2 Landlock / T3 DockLock applied_truth | `membrane_posture.isolation_tiers` |
| [x] | T4 microVM path for tool plane when profile requires | **Effective** authorized when `cvr-kvm-acceptance.json` has `status=PASS` + `effective_claim=true` (Firecracker start/pause/resume/stop on `/dev/kvm`) |

**Phase 6 exit:** `CONNECTOR_AUGMENTED_ENV=1` node refuses start when gates unmet; playground never silently claims harden.

**Live ops:** Talk stream + Anthropic + MCP tools + agent_loop call `ops_runtime::preflight_agent_effect` (same START_REFUSED gate as agent start). See [CONNECTOR_OPERATIONAL_SOFTWARE.md](CONNECTOR_OPERATIONAL_SOFTWARE.md).

---

## Phase 7 — Knowledge, charter, capability SoT (§4–5, §12)

| Done | Task | Verify |
|------|------|--------|
| [x] | Charter as first-class (not prompt-only) | Version + `demote_after_charter_change` |
| [x] | Knowledge boundary policy SoT (permit/auth/prohibit sources) | `/knowledge/:pid/boundary` + retrieve filter + **tool admit `assert_knowledge_may_justify`** |
| [x] | Capability discovery ≠ authorization | Tool list without grant still denied via PATE/contract |

**Phase 7 exit:** Knowledge + charter + capability rules are enforceable under harden — not a regulated-industry demo.

---

## Phase 8 — Worldline & ops (S1–S5, S21–S28)

| Done | ID | Task | Verify |
|------|-----|------|--------|
| [x] | S1 | register → Talk | Force-pid path + anon ban |
| [x] | S2 | Mission journal | Steps persist |
| [x] | S3 | Model swap mid-mission | `set_model_ref` + smoke script |
| [x] | S4 | Process restart | Knot rebuild + AAPI hydrate + DIM load |
| [x] | S5 | Fabric child | Narrowed child via progeny; export links |
| [x] | S21–S23 | R0/R1 proportional; R3 fail-closed; NF³ categorical | `scripts/harden-rgo-suite.sh` |
| [~] | S24 | Effect exclusivity audit | Audit script and start gate exist; microVM, MCP handle, A2A send, native, and inbound CNP paths are not yet one spine |
| [x] | S25 | Health under load | Existing health endpoints |
| [x] | S26 | Operator view | Unified `/operator/pulse` v2 |
| [x] | S27 | Poison / degrade response | `POST /dim/:pid/poison` → verification↑, authority unchanged |
| [x] | S28 | CI on promise + outcomes | `audit-product-promise.sh` |

**Phase 8 exit:** Target is one worldline for one mission: identity → authority → digest → receipt. Current explain can still attach the latest agent ATU and the latest agent trace, so two tasks on one agent can cross-link.

---

## Phase 9 — Proof packaging (reconstructible worldline)

Connector standard needs **proof of what was admitted/executed**, not a compliance product demo.

| Done | Task | Verify |
|------|------|--------|
| [x] | Proof export API | `/proof/export/:pid` |
| [x] | Export includes mission window + DNA + HITL | proof_export: mission_steps, hitl, knowledge_boundary, **packet_dna**, integrity |
| [x] | CLI: worldline / proof export | `connectorctl worldline export --agent <pid> [--mission] [--out]` |
| [x] | Hashed (or signed) manifest in export | `integrity.digest_hex` sha256 on export |
| [x] | No “certified / compliant AI” language in product | `audit-product-promise.sh` anti-claim grep |

**Phase 9 exit:** Export exists. Reconstructing one exact effect still needs the receipt, ATU, mission, and trace to share one task key. That join is partial.  
(Org GRC mapping, if any, is **their** use of that export — not a Connector milestone.)

---

## Phase ARC — Agency plane (deepens L3–L5; not E/A/S finish line)

Implements [CONNECTOR_ARC.md](CONNECTOR_ARC.md) via [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md). Soft default; harden via `CONNECTOR_ARC_*`.

| Done | Task | Verify |
|------|------|--------|
| [x] | Phases A–H coded (vocab → memory) | `cargo test -p connector-server arc::` |
| [x] | Governor on PATE Talk/tool/CONP | `CONNECTOR_ARC_GOVERNOR=1` → RESERVED tx |
| [x] | Lease sinks: tool / Talk / CONP | `CONNECTOR_ARC_LEASE=1` → NoLease⇒NoEffect |
| [~] | Durable worldline + tx | `CONNECTOR_ARC_STORE=copg` → `arc.redb` (COPG); jsonl Soft fallback |
| [x] | Proof export includes ARC graph | `/proof/export/:pid` → `arc_worldline` + `arc_agency` |
| [x] | CLI surfaces ARC in worldline export | `connectorctl worldline export --agent <pid>` |
| [~] | Effective A facets | C/G/D/I/T/Q/P Enforced; N Observed honest |
| [~] | A-VSOCK + F4 bypass | Codec + inventory; live wire / closed bypass LAB |
| [ ] | U1–U5 on augmented node | Operator: `CONNECTOR_AUGMENTED_ENV=1` + ARC flags |

**Phase ARC exit (Soft):** Four primitives + lease on inventoried sinks + reconstruct + honest Effective A meet.  
**Not exit:** claiming all Observed facets gone, live A-VSOCK as boundary, or U1–U5 without node verify.

---

## Suggested work order (shortest path to “standard reached”)

1. ~~Harden refuse-start~~ ✓  
2. ~~Effect exclusivity audit CI~~ ✓  
3. ~~Authority-attack CI~~ ✓  
4. ~~HITL digest mutation test~~ ✓  
5. ~~Knowledge boundary SoT~~ ✓  
6. ~~DIM bands + playground/pilot/harden presets~~ ✓  
7. ~~Proof CLI + integrity manifest~~ ✓  

Remaining operator verify: run `audit-product-promise.sh`, `harden-rgo-suite.sh`, and one `CONNECTOR_AUGMENTED_ENV=1` refuse-start on your node.

Do **not** schedule “compliance profile compile” or industry demos as the path to the standard.

---

## Definition of “we reached the requirement”

All of the following are true:

1. Appendix A has **no Gap** rows; Partial rows are either Engineered or explicitly **LAB-only** with posture labels.  
2. E1–E8, A1–A28, S1–S28 each have a recorded verify result (pass on playground and/or harden as specified).  
3. Five invariants demonstrable: no self-auth · exclusivity · posture honesty · engineer freedom · reconstructible worldline.  
4. `audit-product-promise.sh` green in CI.  
5. Anti-claims hold in docs + UI + release notes.

**Standing:** Soft LAB + **KVM Effective** for Firecracker MicroCell (this host green). Partner-attested HAL remains `[LAB]` until partner attach. Re-run `CONNECTOR_KVM_REQUIRED=1 make cvr-kvm-acceptance` after VMM/asset changes.
