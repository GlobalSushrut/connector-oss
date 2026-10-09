# Maturity Checklist — 28 Iterations (+ 2 polish) to Top-Grade Product

**North star:** [FINAL_OUTCOME.md](FINAL_OUTCOME.md) — **full ~2-year OS (Grade A/B) + this path (Grade C)**  
**Today’s map:** [IMP_1000.md](IMP_1000.md)  
**Grade B (must not skip):** [CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md) · [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md)

**How to use**

1. This checklist is **Grade C only** (CFNI / Moment / UDS / usage / WF projection). It does **not** replace Stories A–D or the production readiness gate.  
2. Complete iterations **in order** unless a later item is explicitly independent.  
3. Each iteration has **Core / Backend / UI** checkboxes — mark `[x]` only when **Verify** passes.  
4. After each iteration: bump IMP-1000 maturity tags; note residual risk.  
5. Do not tell the next person “done” until **FINAL_OUTCOME Grade B + Grade C exit** and **I-30** are checked.

**Legend:** `Core` = vac/trust/engine/kerneld · `Backend` = platform server + plugins · `UI` = Leptos dashboard (and TT/WC admin if named).

---

## Progress tracker

| Iter | Theme | Status | Date | Owner | Evidence / Notes |
|------|--------|--------|------|-------|------------------|
| I-01 | Doctrine lock | [x] | 2026-08-08 | | `docs/architecture/doctrine-coders.md` + substrate-map |
| I-02 | Trust contracts batch | ☐ | | | PARTIAL — types exist; HardwarePlacement / edge state still open |
| I-03 | MemWrite WAL / no silent loss | [x] | 2026-08-08 | | prod sync flush + `/substrate/status` durability |
| I-04 | Knot + audit overflow durability | [x] | 2026-08-08 | | boot knot rebuild + overflow drain |
| I-05 | UsageEvent SoT (real meters) | [x] | 2026-08-08 | | gateway completion + stream finalize → UsageEvent |
| I-06 | Books UI usage-first | [x] | 2026-08-08 | | Books API/UI usage-led; unavailable ≠ $0 |
| I-07 | TT stream/view metering honesty | [x] | 2026-08-08 | | TT `token_source` / `cost_status` |
| I-08 | Third-party / peer usage rules | ☐ | | | PARTIAL — UsageReceipt + Books honesty; UI panel open |
| I-09 | Moment skeleton + API | [x] | 2026-08-08 | | moment persist + GET `/memory/moment/:id` |
| I-10 | Object Fabric live path | ☐ | | | PARTIAL — put/get exist; not off hot DB SoT |
| I-11 | Multimodal parts on MemWrite | [x] | 2026-08-08 | | `WriteRequest.parts` → object_ref |
| I-12 | Moment recall hydrate budget | [x] | 2026-08-08 | | `recall_moment` budgets + truncated honesty |
| I-13 | ArtifactLog append path | ☐ | | | PARTIAL — append paths; segment SoT incomplete |
| I-14 | TT/WC as projections (adapters) | ☐ | | | PARTIAL — doctrine/adapters; dual-write remains |
| I-15 | DI middle + moment_id | ☐ | | | PARTIAL — `DiAuditMiddleEvent.moment_id`; TT/WC FNI persist open |
| I-16 | CFNI contract + HTTP stamp | [x] | 2026-08-08 | | mint/verify + `X-Connector-FNI`; prod enforce |
| I-17 | CFNI on TT/WC paths | ☐ | | | PARTIAL — some attach; E2E correlation open |
| I-18 | CNP virtualize external protocols | ☐ | | | NOT_STARTED / early |
| I-19 | ING + SGKE gate (basic) | ☐ | | | PARTIAL — `sgke_gate` + MCP egress deny; UI explainer open |
| I-20 | Intelligence-identity clustering align | ☐ | | | NOT_STARTED — seed types in Final P6.7 |
| I-21 | Kerneld fail-closed + flow lease | ☐ | | | PARTIAL — status honesty; full enforce open |
| I-22 | 100GB multipart / range get | ☐ | | | PARTIAL — ChunkManifest + fail-closed complete stub |
| I-23 | Retention / cold tier jobs | ☐ | | | NOT_STARTED |
| I-24 | Forensics UI unification | ☐ | | | PARTIAL |
| I-25 | Memory / Vector Box / Moment UI | ☐ | | | PARTIAL |
| I-26 | New-WF builder contract + sample WF | [x] | 2026-08-08 | | `substrate_memory_moment` + builder contract doc |
| I-27 | Adversarial + soak tests | ☐ | | | PARTIAL — some soaks; not Grade-C exit |
| I-28 | Docs / IMP-1000 / sales honesty | ☐ | | | PARTIAL — truth sync in flight (Final P0) |
| I-29 | Perf + UX polish | ☐ | | | NOT_STARTED |
| I-30 | Exit gate / handoff pack | ☐ | | | NOT_STARTED |

---

## I-01 — Doctrine lock

**Goal:** One agreed story for storage, forensics, usage, clustering.

- [x] **Core:** `docs/architecture/` notes for UDS + Moment + CFNI + usage-first (or single doctrine doc).  
- [x] **Backend:** No new feature merges that add Postgres-as-SoT without projection ADR.  
- [x] **UI:** Dev-only banners don’t claim “exact cost” or “verified” without basis.  
- **Verify:** FINAL_OUTCOME + IMP-1000 + this checklist linked from substrate-map; team sign-off.  
- **Evidence:** `docs/architecture/doctrine-coders.md`; substrate-map links; U0.3.

---

## I-02 — Trust contracts batch

**Goal:** Types exist before wire.

- [ ] **Core:** `ForensicFlowIdentityV2`, `HardwarePlacementV2`, H/I vectors, `IntelligenceEdgeStateV2`, `MomentRecallSkeletonV2`, `MomentManifestV2`, `UsageEvent` (or equiv) in `connector-trust`.  
- [ ] **Backend:** Serialize/deserialize round-trip in platform tests.  
- [ ] **UI:** N/A or type-display stubs in dev tools.  
- **Verify:** `cargo test -p connector-trust`; property tests for forge/expiry/κ reject.

---

## I-03 — MemWrite WAL / no silent loss

**Goal:** Crash does not lose a minute of agent memory silently.

- [x] **Core:** Wire CheckpointManager or dirty WAL on MemWrite; configurable ACK.  
- [x] **Backend:** Env knobs documented; flush metrics exposed.  
- [x] **UI:** Operator health shows “last durable commit” / lag.  
- **Verify:** Kill -9 soak: loss ≤ configured window; test in CI.  
- **Evidence:** prod `CONNECTOR_MEMWRITE_SYNC_FLUSH`; `/substrate/status` durability; `durability-kill-soak.sh`.

---

## I-04 — Knot + audit overflow durability

**Goal:** Graph and audit survive pressure and restart.

- [x] **Core:** Rebuild Knot from packets on boot; drain audit overflow to store.  
- [x] **Backend:** Boot path calls rebuild; metrics for overflow drained.  
- [x] **UI:** Memory Lineage/Graph empty-state explains rebuild vs “no data.”  
- **Verify:** Restart after writes → Knot non-empty; overflow counter → 0 under load test.  
- **Evidence:** `substrate/knot_rebuild.rs`; audit overflow drain; Memory topic empty-state.

---

## I-05 — UsageEvent source of truth

**Goal:** One immutable usage write per completion/tool.

- [x] **Core:** UsageEvent schema; class-6 append helper.  
- [x] **Backend:** Gateway writes UsageEvent with `token_source`, served model, moment/trace ids.  
- [x] **UI:** N/A yet (I-06).  
- **Verify:** One gateway completion → one UsageEvent; client model ≠ served model handled.  
- **Evidence:** gateway + stream finalize → UsageEvent (`billing` / U5.3).

---

## I-06 — Books UI usage-first

**Goal:** Kill fake $ leadership.

- [x] **Core:** N/A.  
- [x] **Backend:** Books API returns tokens/calls/model; `$` only if company rate card present; never `cost_usd_real` for estimates.  
- [x] **UI:** Books page primary columns = usage; optional “your rates” secondary; unavailable ≠ 0.  
- **Verify:** Manual QA + API contract test; no hard-coded catalogue as primary.  
- **Evidence:** Books usage-led API/UI; unavailable ≠ $0.

---

## I-07 — TraceTramp stream/view metering honesty

**Goal:** No $0 stream lies; no fake zeros.

- [x] **Core:** Shared metering helper (optional).  
- [x] **Backend:** Stream final usage chunk → provider_api; view path no SQL cost theater; drop dual price table as truth.  
- [x] **UI:** TT admin cost views show tokens + source badge.  
- **Verify:** Streamed chat produces non-fake tokens or explicit unavailable.  
- **Evidence:** `plugins/tracetramp` `token_source` / `cost_status`.

---

## I-08 — Third-party agents / peer usage

**Goal:** Only real traces for external agents.

- [x] **Core:** Optional `UsageReceipt` peer schema.  
- [x] **Backend:** A2A/MCP path meters calls/latency; tokens only with peer receipt.  
- [ ] **UI:** “Unmetered third-party calls” panel.  
- **Verify:** Peer without receipt → tokens unavailable; with receipt → peer_reported.  
- **Evidence:** `connector-trust/src/usage_receipt.rs`; MCP call marks unmetered; `GET /books` `unmetered_peer`

---

## I-09 — Moment skeleton + API

**Goal:** D/R/U/A/I/O refs per turn.

- [x] **Core:** Moment commit beside MemWrite / admission complete.  
- [x] **Backend:** `GET /memory/moment/:id`, list-by-session.  
- [x] **UI:** Moment inspector stub (JSON ok).  
- **Verify:** One LLM turn → moment skeleton queryable.  
- **Evidence:** moment persist + LLM commit hook; GET moment APIs.

---

## I-10 — Object Fabric live path

**Goal:** Large bytes leave the hot DB.

- [ ] **Core:** Fabric put/get (fs/MinIO) wired from platform.  
- [ ] **Backend:** Upload API / internal put; content_hash verify.  
- [ ] **UI:** Dev indicator for fabric backend configured.  
- **Verify:** Image or >64KB blob → object_ref; not inline in engine.db.

---

## I-11 — Multimodal parts on MemWrite

**Goal:** PayloadDescriptor parts on live path.

- [x] **Core:** MemWrite accepts parts[]; descriptors on packet/moment.  
- [x] **Backend:** Gateway/TT attach text(+image) parts.  
- [x] **UI:** Vector Box / Moment shows modality badges.  
- **Verify:** Text + image moment; packet payload not base64-duplicating image.  
- **Evidence:** `WriteRequest.parts` → Object Fabric `object_ref` (U2.4).

---

## I-12 — Moment recall hydrate-by-budget

**Goal:** Exact raw without junk pile.

- [x] **Core:** Recall packer respects max_bytes / max_images.  
- [x] **Backend:** `POST /memory/moment/recall`.  
- [x] **UI:** “Recall moment into context” preview.  
- **Verify:** Budget exceeded skips heavy parts; skeleton always returned.  
- **Evidence:** `recall_moment` budgets + `truncated` / `hydrate_errors` (U2.3).

---

## I-13 — ArtifactLog append path

**Goal:** Log is truth for classes 1–7.

- [ ] **Core:** ArtifactLogV2 trait + segment backend (redb/SQLite/files).  
- [ ] **Backend:** MemWrite / UsageEvent / DI emit append to log.  
- [ ] **UI:** Operator “log lag / segment size” (dev).  
- **Verify:** Rebuild a projection from log in test.

---

## I-14 — TT/WC adapters as projections

**Goal:** Plugins stop being second origins of truth.

- [ ] **Core:** N/A.  
- [ ] **Backend:** TT decision_tree stores capsule/part CIDs (legacy blob optional); WC capture links moment_id; dual-write period documented.  
- [ ] **UI:** Evidence views show moment_id / cid links.  
- **Verify:** Architecture test: fat body single CAS copy.

---

## I-15 — DI middle + moment_id

**Goal:** Audit stream carries moment adjacency refs.

- [x] **Core:** DiAuditMiddleEvent fields for moment_id / memory_super_key.  
- [ ] **Backend:** Export includes moments + handoffs + captures.  
- [ ] **UI:** Export download from Witness / Forensics page.  
- **Verify:** Export JSON schema validates; integrity_status from recompute.  
- **Evidence:** `connector-trust` `audit_middle.rs` `moment_id`; forensics `fni_moment_join`

---

## I-16 — CFNI contract + HTTP stamp

**Goal:** Wire forensic identity exists.

- [x] **Core:** Mint/verify ForensicFlowIdentityV2.  
- [x] **Backend:** Gateway attaches `X-Connector-FNI` after admission.  
- [x] **UI:** Request debug shows FNI present/invalid.  
- **Verify:** Tampered stamp rejected; unit + HTTP test.  
- **Evidence:** CFNI mint/verify; prod `CONNECTOR_CFNI_ENFORCE=1` preset.

---

## I-17 — CFNI on TraceTramp + WitnessCtl

**Goal:** Institutions consume CFNI.

- [ ] **Core:** N/A.  
- [ ] **Backend:** TT outbound/inbound verify/attach; WC capture stores fni_flow_id + verify status.  
- [ ] **UI:** Capture/trace detail shows FNI status badge.  
- **Verify:** End-to-end TT→WC correlated by fni_flow_id.

---

## I-18 — CNP virtualizes external protocols

**Goal:** MCP/A2A/… enter as CNP edges + CFNI.

- [ ] **Core:** CNP envelope field for FNI / moment_id.  
- [ ] **Backend:** Protocol gateway bridges emit CNP+CFNI.  
- [ ] **UI:** Protocols page shows edge id / FNI (dev-ok).  
- **Verify:** One MCP and one A2A hop appear as CNP edges in ING or log.

---

## I-19 — ING + SGKE gate (basic)

**Goal:** H⃗×I⃗ coupling on outbound effect.

- [x] **Core:** κ / Ψ compute from ComplexSpectral + placement; deny on fail.  
- [x] **Backend:** Gate before gateway/tool egress; reason codes.  
- [ ] **UI:** Denied-by-SGKE explainer on agent/actionlog.  
- **Verify:** High I with missing H denied in test.  
- **Evidence:** `substrate/sgke_gate.rs`; wired in `protocols::mcp_call_tool`

---

## I-20 — Intelligence-identity clustering align

**Goal:** distributed/ is placement, not node-path product.

- [ ] **Core:** HardwarePlacementV2 on CellAddress-equivalent.  
- [ ] **Backend:** Scheduler/registry vocabulary + APIs place identities; HA honesty unchanged.  
- [ ] **UI:** Cluster/mesh view = identities × placement (DNS/region/hardware), not fake k8s.  
- **Verify:** Docs + UI copy audit; ha-federation still `automatic_failover: false`.

---

## I-21 — Kerneld fail-closed + flow lease

**Goal:** Unstamped egress cannot leave in prod.

- [ ] **Core:** Flow lease map (ticket/FNI) for kerneld/eBPF.  
- [ ] **Backend:** Production profile fail-closed without lease; downgrade flag explicit.  
- [ ] **UI:** Runtime health shows enforce on/off + reason.  
- **Verify:** Without FNI/ticket, connect denied in lab; with lease, allowed.

---

## I-22 — 100GB multipart / range get

**Goal:** Extreme multimodal path.

- [x] **Core:** Manifest + chunk tree (range get API still open).  
- [ ] **Backend:** Multipart upload complete → moment commit; incomplete fails closed.  
- [ ] **UI:** Moment shows size + “range hydrate” (ops).  
- **Verify:** Multi-GB (CI) or documented manual 100GB drill; moment row stays KB.  
- **Evidence:** `object_fabric.rs` `ChunkManifest` / `assert_multipart_complete`; `POST …/multipart/complete` fail-closed stub (assemble WIP)

---

## I-23 — Retention / cold tier jobs

**Goal:** Real tiering = move B segments, keep S.

- [ ] **Core:** Compaction / cold move by policy; skeleton retained.  
- [ ] **Backend:** Jobs for TT/WC growth + fabric TTL; TT/WC prune to CAS.  
- [ ] **UI:** Retention policy editor (simple).  
- **Verify:** Hot set bounded under soak; recall after cold still resolves or honest expired.

---

## I-24 — Forensics UI unification

**Goal:** One story for control + custody + moment.

- [ ] **Core:** N/A.  
- [ ] **Backend:** Aggregate API: trace + capture + moment + usage by id.  
- [ ] **UI:** Forensics / Evidence page: timeline, FNI, DI export, no fake verified.  
- **Verify:** Story QA: one request visible across TT+WC+moment.

---

## I-25 — Memory / Vector Box / Moment UI

**Goal:** Play surface for recall stability.

- [ ] **Core:** N/A.  
- [ ] **Backend:** Stable APIs already from I-09–I-12.  
- [ ] **UI:** Memory → Vector Box + Moments tabs; adjacent recall demo; multimodal badges.  
- **Verify:** Non-dev user can open moment and see D/R/U + previews.

---

## I-26 — New-WF builder contract + sample WF

**Goal:** Prove WF-easy placement.

- [x] **Core:** Documented contract tests (must call trust helpers).  
- [x] **Backend:** Sample “thin WF” — projector + routes, **no** new SoT DB.  
- [x] **UI:** Plugin/WF wizard points at checklist.  
- **Verify:** Sample WF in repo; CI architecture claim test.  
- **Evidence:** `substrate_memory_moment` template; `docs/agos/workflow-builder-contract.md`.

---

## I-27 — Adversarial + soak tests

**Goal:** Trust what we tell the next person.

- [ ] **Core:** Property tests SGKE/CFNI/WAL.  
- [ ] **Backend:** HTTP adversarial (spoof FNI, spoof tenant, IDOR); soak million UsageEvents/moments (scaled).  
- [ ] **UI:** N/A.  
- **Verify:** CI jobs green; soak report attached.

---

## I-28 — Docs / IMP-1000 / messaging honesty

**Goal:** Words match code.

- [ ] **Core:** Doctrine docs final.  
- [ ] **Backend:** OpenAPI / route inventory updated.  
- [ ] **UI:** Copy pass — no “exact cost”, no “automatic failover”, planned badges.  
- **Verify:** IMP-1000 scorecard all Strong/Good where claimed; FINAL_OUTCOME exit criteria referenced.

---

## I-29 — Perf + UX polish

**Goal:** Feels like finished software.

- [ ] **Core:** Hot path budgets (FNI verify, moment commit) profiled.  
- [ ] **Backend:** p95 gateway+admit+moment within agreed SLO.  
- [ ] **UI:** Loading/empty/error states; Service Map trustworthy.  
- **Verify:** SLO doc + screenshot pass.

---

## I-30 — Exit gate / handoff pack

**Goal:** Ready to tell the next person.

- [ ] All I-01…I-29 complete or explicitly waived with written risk.  
- [ ] FINAL_OUTCOME §5 exit criteria all `[x]`.  
- [ ] `make prod-readiness-gate` green on clean VM.  
- [ ] Handoff pack: IMP-1000 + FINAL_OUTCOME + this checklist (completed) + known limitations.  
- [ ] Demo script: agent turn → moment recall → DI export → usage books → CFNI deny without stamp.  
- **Verify:** External reviewer (or next owner) signs handoff.

---

## Cross-cutting “do not miss” matrix

Use this every 5 iterations:

| Risk | Core | Backend | UI |
|---|---|---|---|
| Fake $ / fake tokens | UsageEvent source enum | Filter APIs | Primary columns |
| Data loss | WAL/fabric | Metrics/alerts | Lag visible |
| Intended-routing security | CFNI+kerneld | Fail-closed prod | Enforce badge |
| WF DB sprawl | ArtifactLog | Adapters | Wizard copy |
| Multimodal junk | Parts+manifest | No base64 in PG | Modality badges |
| Overclaim verified | Custody status enum | Export honesty | No green without recompute |
| Node-path clustering | Placement types | distributed/ APIs | Mesh = identities |
| Third-party blind spot | Peer receipt | A2A/MCP meters | Unmetered panel |

---

## Relationship to production readiness

This checklist is the **product maturity path** (physiology + forensics + usage + WF placement).  
[PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md) remains the **release hardening gate**. Both must pass for external “top grade” claims.

---

*Update the Progress tracker as you go. The next person should be able to open FINAL_OUTCOME, this file, and IMP-1000 and know exactly where you are.*
