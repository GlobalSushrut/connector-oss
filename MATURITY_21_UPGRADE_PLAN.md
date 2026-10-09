# Connector OS — 21-Segment Upgrade Plan & Coding Checklist

**Baseline:** [MATURITY_21_SEGMENTS.md](MATURITY_21_SEGMENTS.md) (2026-08-04)  
**North star:** [FINAL_REACH.md](FINAL_REACH.md) (**AIOS → L5 global mesh coding queue**) · [FINAL_OUTCOME.md](FINAL_OUTCOME.md) · Grade B gate: [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md) · Grade C detail: [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md)  
**Note:** U8.4 Option A (defer vac-cluster) is **superseded for L5** by FINAL_REACH **P8** (Option B: wire vac-cluster + real peer mTLS + custody quorum). Keep honesty APIs false until P8/P9 soak.  
**Backend already done track:** [BACKEND_TOP_GRADE_TRACK.md](BACKEND_TOP_GRADE_TRACK.md) (T0–T7) — do **not** re-litigate closed T-items; close residual gaps below.

---

## How to use (coding rules)

1. Work **phases in order** (U0 → U8). Inside a phase, items may parallelize if they do not share the same hot path.
2. Mark `[x]` only when **Verify** passes on the working tree (test command or manual step listed).
3. Every PR that closes an item must:
   - name the segment(s) in the PR body (`Seg 3`, `Seg 11`, …);
   - update the scoreboard row in `MATURITY_21_SEGMENTS.md` if a lens score changed;
   - bump the honesty tag in `IMP_1000.md` if maturity moved (Partial → Shipped-gaps, etc.).
4. **Do not** claim HA / multi-node SoT until U8 explicitly wires and proves it.
5. Prefer fail-closed defaults over new surface area.
6. After each phase: run `make doctor` (or the phase’s gate) before starting the next.
7. **Low RAM:** never `cargo test -p connector-platform` on ≤16 GiB laptops — see `docs/LOW_MEMORY_DEV.md`. Prefer `bash platform/scripts/check-reference-templates-light.sh` and CI for full compiles.

**Legend**

| Tag | Meaning |
|-----|---------|
| `Core` | `oss/vac`, `connector-trust`, `connector-caps`, `connector-kerneld` |
| `Backend` | `platform/server`, plugins, hub/runtime |
| `UI` | `platform/ui-leptos/dashboard` (and TT/WC admin if named) |
| `Ops` | deploy, Makefile, CI, docs honesty |

---

## Progress tracker

| Phase | Theme | Segments | Status | Date |
|-------|--------|----------|--------|------|
| U0 | Honesty & doctrine lock | 1, 11, 21 | ☑ | 2026-08-04 |
| U1 | Secrets, auth, admission universality | 5, 6, 14 | ☑ | 2026-08-04 |
| U2 | Memory durability & Moment exit | 2, 3, 11 | ☑ | 2026-08-04 |
| U3 | Knowledge ingest + graph honesty | 4 | ☑ | 2026-08-04 |
| U4 | Isolation fail-closed defaults | 7, 16 | ☑ | 2026-08-04 |
| U5 | Protocols, CFNI, usage meters | 8, 11, 14, 17 | ☑ | 2026-08-04 |
| U6 | CLS / workflows / WF-as-projection | 15, 17 | ☑ | 2026-08-04 |
| U7 | Operator UI + concurrency hygiene | 10, 12, 13, 18 | ☑ | 2026-08-04 |
| U8 | Package proof + HA decision | 9, 19, 20, 21 | ☑ code / ☐ human Final GO | 2026-08-04 |

**Exit:** All U0–U7 `[x]` + Production Final GO (clean VM) + scoreboard lenses improved where claimed. U8-HA is optional and must not block single-node ship.

---

## U0 — Honesty & doctrine lock

**Goal:** Docs and checklists match code so coding work is not double-counted or overclaimed.

### U0.1 Align trust / audit honesty

- [x] **Ops:** Update `docs/architecture/substrate-map.md` claim honesty to match keyed audit HMAC + recompute in `vac-core` (`make_audit` / `verify_audit_chain` / `sign_audit_entry`).
- [x] **Ops:** Patch stale lines in `CONNECTOR_OS_CODE_REALITY_AND_SECURITY_REPORT.md` that still claim unkeyed SHA-256-only audit and fake `verified: true` on proof generate (code already returns unverified).
- [x] **Ops:** Doctrine + hardening docs updated; I-01/I-02 tracker notes via `docs/architecture/doctrine-coders.md`.
- **Verify:** Honesty docs no longer claim unkeyed-only audit or decorative `verified: true` on generate_proof.

### U0.2 Segment scoreboard hygiene

- [x] **Ops:** Add “Last coded” date note at top of `MATURITY_21_SEGMENTS.md`.
- [x] **Ops:** Link this file from `ARCHITECTURE.md` (maturity docs line).
- **Verify:** Both files cross-link; no contradictory “Production-ready” claims on Early/Partial segments.

### U0.3 Doctrine one-pager for coders

- [x] **Ops:** Confirm single doctrine: **MemPackets / ArtifactLog / UsageEvent are SoT; TT/WC/Postgres are projections; Knot rebuilds from packets; HA is not product SoT.** → `docs/architecture/doctrine-coders.md`
- [x] **Backend:** Doctrine forbids Postgres-as-SoT without ADR (documented for reviewers).
- **Verify:** Doctrine doc linked from substrate-map; maps to Maturity I-01.

**Phase gate:** `make doctor` green.

---

## U1 — Secrets, auth, admission universality

**Goal:** No silent trust; no effect path without admission; no mock runners on hot paths.

### U1.1 Fail-closed secrets (Seg 2, 7, 11)

- [x] **Core/Backend:** Refuse boot in production / defense-strict if `CONNECTOR_AUDIT_HMAC_KEY` unset/invalid (`connector_profile::validate_production_secrets_fail_closed`).
- [x] **Backend:** Cage / CFNI: no JWT/dev fallback under prodish (`cage_security`, `cfni`); require dedicated secrets at boot.
- [x] **Backend:** Document required env keys in `docs/PRODUCTION_HARDENING.md`.
- **Verify:** `production_secrets_require_audit_cfni_cage_keys` unit test.

### U1.2 Caps runners honesty (Seg 5)

- [x] **Core:** Gate `HttpRunner` / `StoreRunner` mock bodies behind `CONNECTOR_CAPS_ALLOW_MOCK=1` or `cfg(test)`.
- [x] **Backend:** Production boot rejects `CONNECTOR_CAPS_ALLOW_MOCK`.
- **Verify:** `cargo test -p connector-caps --lib runner`; secrets unit test.

### U1.3 Protocol-gateway key trust (Seg 5, 8, 14)

- [x] **Backend:** `X-API-Key` path calls `auth::validate_api_key` (no prefix-only trust) in `protocol_gateway/mod.rs`.
- **Verify:** Invalid key → 401 (middleware path).

### U1.4 Admission on remaining effect routes (Seg 6, 4, 14)

- [x] **Backend:** Knowledge ingest + tools MCP already call admission (confirmed); matrix lists them.
- [x] **Backend:** No new bypass introduced; substrate status exposes quota/admission honesty.
- **Verify:** Existing admission matrix coverage; knowledge/tools paths gated.

### U1.5 Dual quota stack decision (Seg 6, 13)

- [x] **Backend:** SoT documented: `services::agents` + VAC kernel caps; `crate::agents::*` + `agent_resource_manager` deprecated.
- [x] **Backend:** `#[deprecated]` on unwired modules; `/substrate/status` reports `quota_sot`.
- **Verify:** Grep + status field; no double-enforce on register.

**Phase gate:** platform tests for admission matrix + prod secret boot test green.

---

## U2 — Memory durability & Moment exit

**Goal:** Crash does not silently lose agent memory; Moment recall is real enough for operators.

### U2.1 MemWrite durability defaults (Seg 2, 3) — maps I-03

- [x] **Backend:** Production presets set `CONNECTOR_MEMWRITE_SYNC_FLUSH=1` when unset; write-through already defaults on for `CONNECTOR_ENV=production`.
- [x] **Backend:** Durability snapshot on `/substrate/status` (existing + honesty note).
- [x] **UI:** Monitor Overview/Load shows last durable flush + wal_status from `/substrate/status`.
- **Verify:** `production_preset_sets_memwrite_and_cfni_enforce`; `ci_beta_gate` includes `durability-kill-soak.sh`.

### U2.2 Audit overflow + knot rebuild proof (Seg 2, 3, 11) — maps I-04

- [x] **Backend:** Boot knot rebuild already wired (Backend T3); status/durability surfaces remain.
- [x] **Backend:** Audit overflow persist path from Backend T3 — keep soak in release gate.
- [x] **UI:** Memory topic empty-state explains Knot rebuild vs no data (`topic_panels`).
- **Verify:** Restart after writes → Knot non-empty (existing path).

### U2.3 Moment recall hydrate (Seg 3) — maps I-12

- [x] **Backend:** `recall_moment` hydrates Object Fabric by `object_ref`/`content_hash` with budgets + `truncated` honesty.
- [x] **Backend:** Enforce byte/part budget; return partial + honesty fields when truncated.
- [x] **UI:** Memory drawer hints moment recall API + truncated honesty via substrate/status.
- **Verify:** API returns `truncated` / `hydrate_errors` fields.

### U2.4 Multimodal MemWrite parts (Seg 3) — maps I-11

- [x] **Backend:** `WriteRequest.parts` + Object Fabric materialization on `/memory/write` (no inline `data_b64` on packet).
- [x] **Backend:** Unit tests for part descriptor shape + packet embed.
- **Verify:** `memory_part_input_strips_to_object_ref_shape` + `make_packet_embeds_parts_*`.

### U2.5 ArtifactLog append universality (Seg 11) — maps I-13

- [x] **Backend:** LLM completion already appends UsageEvent + ArtifactLog + Moment (`billing.rs`).
- [x] **Backend:** ArtifactLog folder SoT; TT/WC remain projections (doctrine).
- **Verify:** After LLM call, ArtifactLog has row (existing Backend T5 path).

**Phase gate:** memwrite soak + moment recall test + substrate status shows durable lag.

---

## U3 — Knowledge ingest + graph honesty

**Goal:** Knowledge plane is admitted, rebuildable, and not overclaimed as a mesh.

### U3.1 Admit knowledge ingest (Seg 4, 6)

- [x] **Backend:** Knowledge ingest already calls `admission::check(MemoryWrite)` before mutate.
- [x] **Backend:** Admission gate remains on ingest path (no bypass added).
- **Verify:** Matrix lists knowledge ingest; unauthenticated mutate denied by router auth + admission.

### U3.2 Index durability honesty (Seg 4)

- [x] **Backend:** `/substrate/status` reports `knowledge.index_mode=in_process` + honesty (Knot rebuilds from packets).
- [x] **UI:** Memory topic empty-state covers index/Knot rebuild honesty.
- **Verify:** Status API honesty fields present.

### U3.3 Poisoning / injection gate (Seg 4) — maps I-19 basic

- [x] **Backend:** Admission + injection detection already on knowledge ingest via shared MemoryWrite gate.
- [x] **Backend:** advanced-lab attack YAMLs exist; optional nightly wiring remains ops (U8.2).
- **Verify:** Admission deny on injection-shaped content (existing gate).

### U3.4 Marketing / IMP honesty (Seg 4, 9)

- [x] **Ops:** `IMP_1000.md` states semantic/hybrid recall is **single-node only**.
- **Verify:** No “distributed semantic fabric” claim without U8 wiring.

**Phase gate:** knowledge ingest admission tests green; IMP wording updated.

---

## U4 — Isolation fail-closed defaults

**Goal:** Production cannot silently run subprocess cages or weak secrets.

### U4.1 Grade gates (Seg 7, 16)

- [x] **Backend:** Production presets force `microvm`; subprocess break-glass only via `CONNECTOR_ALLOW_SUBPROCESS_ISOLATION` under prodish (`cage_security`).
- [x] **Backend:** `/substrate/status` shows isolation + subprocess_break_glass + prodish_enforced.
- [x] **UI:** Plugin light consoles + Monitor Load show isolation grade badge from `/substrate/status`.
- **Verify:** Status fields; existing isolation grade gates.

### U4.2 Egress enforce (Seg 7, 14)

- [x] **Backend:** MCP egress allowlist + CFNI mesh verify already in Backend T4; secrets fail-closed added.
- [x] **Backend:** Defense-strict / production harden path documented.
- **Verify:** Existing egress_policy + CFNI tests.

### U4.3 Plugin hub / reference stubs (Seg 16)

- [x] **Backend/Ops:** `KNOWN_PLUGINS` = TT/WC/DG only; reference plugins remain stubs by design.
- [x] **Backend:** Hub/cpkg signature path already shipped (IMP).
- **Verify:** Deferred plugins not in default enable list.

### U4.4 Kerneld / flow lease (Seg 6, 7) — maps I-21 residual

- [x] **Backend:** `/substrate/status` reports `kerneld.status` (`absent|configured|socket_present`).
- [x] **Ops:** Production hardening table documents secrets + isolation; kerneld optional honesty.
- **Verify:** Status honesty field.

**Phase gate:** `make prod-dogfood-smoke` (or equivalent) with microVM/docker preset.

---

## U5 — Protocols, CFNI, usage meters

**Goal:** Forensic transit and honest meters on the paths operators actually use.

### U5.1 CFNI enforce coverage (Seg 1, 8, 11, 17) — maps I-16/I-17

- [x] **Backend:** Production presets set `CONNECTOR_CFNI_ENFORCE=1` when unset.
- [x] **Backend:** Mint/verify paths already on gateway + TT/WC/cage + MCP (Backend T4); dedicated CFNI secret required in prod.
- [x] **Backend:** Mesh relay reject when enforce on (existing).
- **Verify:** Preset unit test; CFNI suite.

### U5.2 Causal envelope keyed integrity (Seg 1, 11)

- [x] **Core/Backend:** Causal `integrity_mac` is keyed HMAC (`CONNECTOR_CAUSAL_HMAC_KEY` or audit key).
- [x] **Backend:** `verify_integrity_mac` + unit test for tamper reject.
- **Verify:** `integrity_mac_is_keyed_and_verifies`.

### U5.3 UsageEvent completeness (Seg 14, 17) — maps I-05/I-07

- [x] **Backend:** UsageEvent on LLM completion **and** stream finalize (gateway already meters streams).
- [x] **Backend:** TT stream/view emit `token_source` + `cost_status` (`unavailable` ≠ $0) in `plugins/tracetramp/src/view.rs`.
- [x] **UI:** Books usage-first copy + costs section already usage-led.
- **Verify:** Gateway stream path sets `token_source`; Books API never invents $0 (Backend T1).

### U5.4 CNP / glue stub containment (Seg 8, 15)

- [x] **Backend:** `connector-glue` stub executor refused under production / defense-strict unless `CONNECTOR_GLUE_ALLOW_STUB=1`.
- [x] **Backend:** CNP `establish_mtls` fails closed without `CONNECTOR_CNP_ALLOW_MTLS_STUB`; stub marks `mutual_auth=false`.
- **Verify:** `cnp::stack::security::tests::establish_mtls_*` (3 tests).

### U5.5 Internal DNS honesty (Seg 8)

- [x] **Backend/Ops:** `/substrate/status` `dns.mode=in_process` + honesty string.
- [x] **UI:** Monitor durability section shows Cage DNS mode.
- **Verify:** Status reports `dns.mode=in_process`.

**Phase gate:** CFNI enforce tests + usage stream test + books honesty smoke.

---

## U6 — CLS / workflows / WF-as-projection

**Goal:** Workflows enable for real; TT/WC never become a second kernel.

### U6.1 CLS enable path (Seg 15)

- [x] **Backend:** ENABLE → CNP bus registration + CLS activation (`workflow_runtime`).
- [x] **Backend:** Dry-run returns `cnp_correlated_events` + `cnp_bus_registration` (full replay still KNOWN_LIMITATIONS).
- [x] **UI:** Setup / apps list workflows; enable via existing workflow APIs.
- **Verify:** Enable sample CCL → list shows ENABLED; dry-run returns correlation ids.

### U6.2 TT/WC as projections (Seg 17) — maps I-14

- [x] **Backend/Ops:** `docs/architecture/wf-projection-adapters.md` — Postgres as projection.
- [x] **Backend:** Doctrine prefers CFNI `flow_id` join.
- [x] **UI:** `OpForensicsPanel` shows flow_id + moment + ArtifactLog alongside TT/WC ids.
- **Verify:** Forensics panel + projection doc.

### U6.3 Deferred plugins freeze (Seg 17)

- [x] **Ops:** Doctrine + IMP: deferred plugins named; not co-equal kernels.
- [x] **Backend:** `plugin_matrix::KNOWN_PLUGINS` = only `devguard`, `tracetramp`, `witnessctl`.
- **Verify:** Fresh enable list cannot silently include deferred ids.

### U6.4 Sample new-WF contract (Seg 15, 16) — maps I-26

- [x] **Backend:** `substrate_memory_moment` reference template (MemWrite → Moment → Usage → ArtifactLog; `institutions: []`).
- [x] **Docs:** `docs/agos/workflow-builder-contract.md` + `PLUGIN_CONTRACT.md` pointer.
- **Verify (laptop):** `bash platform/scripts/check-reference-templates-light.sh`  
- **Verify (CI / ≥32 GiB):** `all_bundled_templates_compile`

**Phase gate:** `make story-qa-smoke` or workflow enable smoke + forensics join smoke.

---

## U7 — Operator UI + concurrency hygiene

**Goal:** Operators see truth; kernel hot path does not melt under parallel agents.

### U7.1 Memory / Moment / Vector Box UI (Seg 3, 18) — maps I-25

- [x] **UI:** Memory topic empty-states + substrate durability panel (knot / flush / wal).
- [x] **UI:** Books / Monitor avoid decorative verified / fake $0 (unavailable honesty).
- **Verify:** Monitor + Books + Memory drawer copy.

### U7.2 Forensics unification (Seg 11, 17, 18) — maps I-24

- [x] **UI:** `OpForensicsPanel` unifies substrate + TT + WC ids with shared `flow_id`.
- **Verify:** Dev gallery / forensics panel renders flow_id row.

### U7.3 Mutex / concurrency hygiene (Seg 10, 12)

- [x] **Backend:** Documented acceptable contention on `/substrate/status` `concurrency` (Mutex, not sharded).
- [x] **Backend:** Background notification escalator already drops locks before further work (BUG-033 fix).
- **Verify:** Status concurrency honesty field.

### U7.4 Orphaned agent lifecycle cleanup (Seg 13)

- [x] **Backend:** `agent_lifecycle` already marked deprecated; `agents::*` + `agent_resource_manager` deprecated this pass.
- [x] **Backend:** Single SoT: VAC kernel ACB + progeny (documented on status `quota_sot`).
- **Verify:** HTTP register path uses `services::agents` only.

### U7.5 Catalog “app ls” direction (Seg 12, 18)

- [x] **Backend:** `GET /api/v1/apps` unified catalog already shipped (`apps_catalog.rs`).
- [x] **UI:** Setup canvas loads institutions from `/apps?kind=plugin` (+ plugins/status fallback).
- **Verify:** `/apps` returns plugins + workflows.

**Phase gate:** UI build + multiagent soak + catalog API smoke.

---

## U8 — Package proof + HA decision

**Goal:** Ship single-node with proof; decide HA explicitly (wire or defer).

### U8.1 Packaging Final GO (Seg 20, 21)

- [ ] **Ops:** Clean VM: unpack tarball → `connectorctl start` → doctor → one-green-start (**manual**).
- [x] **Ops:** Signed release path documented (`docs/SIGNED_RELEASE.md` + PRODUCTION_HARDENING link).
- [ ] **Ops:** Story QA + lab video checkboxes in `PRODUCTION_READINESS_CHECKLIST.md` (**manual**).
- **Verify:** Final GO section items checked on clean VM.

### U8.2 CI evidence (Seg 21)

- [x] **Ops:** `ci_beta_gate` already runs durability-kill-soak; advanced-lab remains optional nightly.
- [x] **Ops:** `make prod-readiness-gate` is the engineering gate (run on release branch).
- **Verify:** `platform/scripts/ci_beta_gate.sh` + `durability-kill-soak.sh`.

### U8.3 Vendor plane scope (Seg 19)

- [x] **Ops:** ARCHITECTURE + doctrine: vendor license/portal/playground **out of** customer node bar.
- [x] **Ops:** Portal/playground remains deploy-specific.
- **Verify:** ARCHITECTURE customer vs vendor table.

### U8.4 HA decision gate (Seg 9) — pick **one**

**Option A — Defer (default, recommended for ship):**

- [x] **Ops:** Status API + docs: `automatic_failover: false`; HA doc honesty; substrate status `ha.product_sot=single_node`.
- [x] **Backend:** Option A was interim (single-node U8); **L5 / FINAL_REACH P8 = Option B** — wire `vac-cluster` + fix peer TLS (tracked there, not re-closed here).
- **Verify:** Scoreboard Seg 9 stays Early; IMP honest.

**Option B — Wire minimal cell (only if product requires):**

- [ ] **Backend:** Depend on `vac-cluster` / cell transport; remove `SkipServerVerification` for peer TLS.
- [ ] **Backend:** Prove leader election + one failover soak; update HA doc.
- [ ] **Ops:** Bump Seg 9 lenses only after soak.
- **Verify:** Two-node soak doc + automated test.

**Phase gate:** Production Final GO (A) or HA soak report (B).

---

## Per-PR coding checklist (copy into PR body)

```markdown
## Maturity PR
- [ ] Phase / item ID: Ux.y
- [ ] Segments touched: 
- [ ] Lens impact: Isolation / Distribution / Parallel / Memory / Knowledge (circle)
- [ ] Fail-closed by default? (yes/n/a)
- [ ] Honesty: IMP_1000 / MATURITY_21_SEGMENTS updated if grade/score changed
- [ ] Verify command(s):
- [ ] No Postgres-as-SoT for memory/usage without projection ADR
- [ ] No decorative `verified: true` / fake $0
```

---

## Suggested coding order (first 10 PRs)

| PR | Item | Why first |
|----|------|-----------|
| 1 | U0.1–U0.2 | Stop lying to yourself in docs |
| 2 | U1.1 secrets fail-closed | Prod safety |
| 3 | U1.4 admission on knowledge + MCP | Close bypasses |
| 4 | U1.2–U1.3 caps/gateway trust | Stop mock success |
| 5 | U2.1 memwrite prod defaults | Memory lens |
| 6 | U2.3 moment recall hydrate | Unblock I-12 |
| 7 | U4.1 isolation grade gates | Isolation lens |
| 8 | U5.1 CFNI enforce in prod preset | Forensics |
| 9 | U5.3 usage stream honesty | Books truth |
| 10 | U6.1–U6.2 CLS enable + WF projection | Product story |

Then continue U3 → U7 → U8 packaging.

---

## Mapping to other checklists

| This plan | Other doc |
|-----------|-----------|
| U0 | Maturity I-01, I-28 |
| U1 | Backend T1–T2 residuals; route inventory |
| U2 | Maturity I-03, I-04, I-11–I-13; Backend T3 |
| U3 | Maturity I-19–I-20 |
| U4 | Backend T6; Maturity I-21 |
| U5 | Maturity I-05–I-08, I-15–I-18; Backend T4–T5 |
| U6 | Maturity I-14, I-26; Production workflows section |
| U7 | Maturity I-06, I-24–I-25, I-29 |
| U8 | Production Final GO; Maturity I-27, I-30 |

---

## Definition of done (upgrade program)

- [x] Phases **U0–U7** complete with Verify evidence (code + unit tests).
- [x] `MATURITY_21_SEGMENTS.md` scoreboard updated (no Early segment claimed as Production-ready).
- [x] `IMP_1000.md` tags match code (knowledge single-node honesty).
- [ ] `make prod-readiness-gate` green on release machine (**operator run**).
- [ ] Production Final GO on clean VM (U8.1) — see `docs/FINAL_GO_RUNBOOK.md` (**human**).
- [x] HA explicitly deferred (U8.4-A).

**Code path for this upgrade plan is complete.** Remaining boxes are operator/human Final GO only.
