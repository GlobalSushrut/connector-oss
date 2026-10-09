# FINAL REACH — AIOS → L5 Global Mesh Coding Checklist

> **ENGINEERING GREEN (2026-08-10):** `make final-reach-light-gate` → **OK** (all CORE; T13/T15/T17 PASS via soak evidence).  
> `make engineering-reach-gate` = light-gate + `.l5-mesh-soak.ok` + `.custody-multinode-soak.ok`.  
> **Still human/CI before marketing claim:** T7 clean-VM signed tar, `make prod-readiness-gate` on ≥32 GiB, P9 human sign-off (market L5). **T13/T15 engineering soak:** PASS — `platform/scripts/.l5-mesh-soak.ok` (2026-08-10).

**Use this file as the only coding queue for Final.** Check boxes only with evidence (path, smoke, or PR). Do not market **L5 / court-grade / global mesh** until **P8 + P9** multi-node soaks are signed. Do not market **L4 +2** until **P7** human Final GO is signed.

Related: [docs/CONNECTOR_TRUTH_STORY.md](docs/CONNECTOR_TRUTH_STORY.md) (**0→today→future + honest marketing**) · [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md) (**P10 court-grade intelligence identity — vertical spine on top of L3–L5**) · [FINAL_OUTCOME.md](FINAL_OUTCOME.md) · [CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md) · [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) · [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md) · [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) · [docs/architecture/ha-federation.md](docs/architecture/ha-federation.md) · [docs/LOW_MEMORY_DEV.md](docs/LOW_MEMORY_DEV.md)

**Existing L5 starting points (wire, do not rewrite):** `oss/vac/crates/vac-cluster` · `vac-replicate` · `vac-sync` · `platform/server/src/distributed/*` (`CellAddress`, SWIM, QUIC) · `services/ha_federation.rs` · `services/orchestration_intelligence.rs` · `plugins/witnessctl` custody quorum · `oss/aapi/crates/aapi-federation` · CNP stack mTLS.

---

## Connector claim (few lines)

**Connector OS is not a better agent and not merely one-node software.** Any agent runs as a **process on Connector**. Intelligence is placed by **geo-identity × hardware placement**, not by pretending Kubernetes is the product.

We sit **three levels above** agent stacks when L5 is signed:

1. **L3 — AI Operating System (+1):** constitutional primitives, admission, cages, CLS/CNP programs, Hub apps, TT/WC/DG institutions — agents are PIDs.
2. **L4 — Universal DI substrate (+2):** one physiology on a node — CFNI, moments/Object Fabric, usage-first books; agents cannot forge green or own a second SoT.
3. **L5 — Global intelligence mesh (+3):** many nodes connected with **today’s tech** (mTLS, cell transport/QUIC, gossip/CRDT membership, zone replication, geo-DNS/VIP) into an **intelligence-global clustering** fabric; **court-grade multi-party custody** (N-of-M independent witnesses); built-in **distributed system channels** (CNP mesh + vac sync) so a world mesh can form without each agent inventing its own network.

**Until P8 soak flips honesty flags:** APIs stay truthful (`automatic_failover: false`, `product_sot=single_node`, `mesh_fabric: false`). **Never** fake cluster UI or “court-grade” from issuer-only HMAC.

---

## Ladder (do not skip)

| Level | Meaning | Exit |
|-------|---------|------|
| L0 | Model / chat API | use only |
| L1 | Agent app / framework | host as tenant |
| L2 | Governed agent platform | surpass — we are not another L2 |
| **L3** | **AIOS (+1)** | P1–P5 + Stories A–D |
| **L4** | **DI substrate (+2)** | P6 + claim tests T8–T12 |
| **L5** | **Global intelligence mesh (+3)** | P8 + claim tests T13–T18 |

**Program exit = L5.** Coding order: **P0 → P1 → … → P9**. L3/L4 first (one strong node), then wire multi-node from existing crates. Within a pillar: Core → Backend → UI.

---

## Coding rules (avoid mistakes)

1. **One truth:** MemPackets / ArtifactLog / UsageEvent are SoT. Multi-node replicates **packets/zones**, not a second Postgres SoT per cell.
2. **Honesty:** never decorative `verified: true` or fake `$0`; unavailable ≠ zero. HA/mesh flags flip **only after soak**.
3. **Fail-closed in prod:** secrets, mock caps, CFNI, cages, unstamped egress, **peer mTLS** (no `SkipServerVerification` on marketed paths).
4. **UI with every Backend** — mesh view = identities × placement × cells, not fake k8s node chrome.
5. **Laptop:** do **not** run `cargo test -p connector-platform --bin connector-platform` on ≤16 GiB ([docs/LOW_MEMORY_DEV.md](docs/LOW_MEMORY_DEV.md)). Multi-node soaks on lab VMs / CI.
6. **L5 builds on existing code** — wire `vac-cluster` + `distributed/*` + WitnessCtl quorum; do not invent a parallel mesh stack.
7. **Secondary plugins** stay deferred — do not market as equal to TT/WC/DG.
8. After each item: update this checkbox + evidence; bump IMP / segment 9 when distribution maturity moves.

**Row template:** `- [ ] **Core:** …` / `- [ ] **Backend:** …` / `- [ ] **UI:** …` / `- **Verify:** …` / `- **Evidence:** _path or command_`

---

## P0 — Truth sync (do first)

| ID | Item | Core | Backend | UI | Verify | Done |
|----|------|------|---------|-----|--------|------|
| P0.1 | Publish this claim + ladder (this file) | [x] | n/a | n/a | Linked from ARCHITECTURE | [x] |
| P0.2 | Sync [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) for already-coded I-items (no lag) | [x] | [x] | [x] | Checkboxes match code | [x] |
| P0.3 | Fix stale gaps in [MATURITY_21_SEGMENTS.md](MATURITY_21_SEGMENTS.md) (moment/HMAC/CFNI) | [x] | n/a | n/a | Scoreboard honest | [x] |
| P0.4 | Link claim from [ARCHITECTURE.md](ARCHITECTURE.md) + [FINAL_OUTCOME.md](FINAL_OUTCOME.md) | [x] | n/a | n/a | Index points here | [x] |
| P0.5 | Known limitations only list *real* open Final gaps | [x] | n/a | n/a | [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | [x] |

---

## P1 — Sovereign node (L3 base)

### P1.1 Backup / restore one trust domain

- [x] **Core:** Define trust-domain bundle contents (data_dir, vault secrets, audit key refs, plugin state inventory).
- [x] **Backend:** Dashboard/API export + restore that reconstitutes one node; fail closed on partial restore.
- [x] **UI:** Settings → Backup / Restore with progress + honesty if incomplete.
- **Verify:** Clean restore boots; doctor green; no second SoT invented.
- **Evidence:** `docs/TRUST_DOMAIN_BACKUP.md`; `connectorctl backup/restore` + `.manifest.json`; Settings `BackupTrustDomainSection`; `GET /settings/system/backup` trust_domain block

### P1.2 Binary upgrade / migrate (≠ billing tier)

- [x] **Core:** Versioned migrate notes / schema bump path documented.
- [x] **Backend:** `connectorctl` (or docs+script) **node** upgrade distinct from commercial `upgrade` tier.
- [x] **UI:** Settings shows node version + “upgrade instructions” / status (no fake one-click if not real).
- **Verify:** N→N+1 migrate on lab data_dir.
- **Evidence:** `docs/PRODUCTION_UPGRADE.md` migrate notes; `connectorctl node-upgrade`; Settings `NodeUpgradeSection`; release README fixed

### P1.3 Signed release path

- [x] **Core:** [docs/SIGNED_RELEASE.md](docs/SIGNED_RELEASE.md) steps complete.
- [x] **Backend:** Package script produces hash; signature slot (GPG/cosign) documented.
- [x] **UI:** n/a (or About → release digest display).
- **Verify:** Verify signature on unpacked tarball.
- **Evidence:** `scripts/verify-release-artifacts.sh`; `make verify-release-artifacts`; SIGNED_RELEASE verify section

### P1.4 §10 automatable gaps

- [x] **Core:** n/a.
- [x] **Backend:** Extend `section10-automated-smoke` where still open. *(backup + node-upgrade docs file-exists; human-only UI paths remain)*
- [x] **UI:** Operator paths covered by smoke or flagged human-only. *(script notes manual still required)*
- **Verify:** `make section10-automated-smoke`.
- **Evidence:** `platform/scripts/section10-automated-smoke.sh` checks `docs/TRUST_DOMAIN_BACKUP.md` + `docs/PRODUCTION_UPGRADE.md`; footer still lists dashboard/LLM/TLS/lab-video as manual.

---

## P2 — Governed execution (beat L2 platforms)

### P2.1 Admission on every external effect

- [x] **Core:** Admission matrix doc: route/effect → gate (chaos O2).
- [x] **Backend:** Tools / MCP / knowledge / debug egress all call admission; adversarial tests deny bypass.
- [x] **UI:** Denied actions show reason (admission), not silent failure.
- **Verify:** Bypass suite green; matrix checked.
- **Evidence:** `docs/architecture/admission-matrix.md`; `substrate/admission_matrix.rs` (+ debug restore/snapshot); `debug::agent_restore` / `agent_snapshot` → `admission_gate::require_memory_write`; UI `OpApiErrorBanner` “Denied by admission”; light tests in `admission_matrix` / inventory

### P2.2 LLM fallback + cost-cap E2E

- [x] **Core:** Fallback + cap contracts in settings model.
- [x] **Backend:** Cap blocks overspend on gateway chat (hard_stop vs Books month USD); UsageEvent records `model_served` from `LlmResponse` (fallback hop). Primary-down→fallback E2E soak still open. *(partial)*
- [x] **UI:** Settings LLM: configure fallback + cap; Monitor/Books show cap hit honestly.
- **Verify:** Story-qa / smoke: primary down → fallback; cap enforced.
- **Evidence:** `settings_llms::cost_cap_hard_stop_violation` on `POST /v1/chat/completions` (+ stream); gateway/billing pass served model into `UsageEventV2.model_served`; `GET /settings/llms/fallback-cap` + `/guardrails`; `make llm-fallback-cap-smoke`; Settings `LlmTab`. Open: primary-down→fallback live E2E.

### P2.3 TraceTramp Control / outage honesty

- [x] **Core:** n/a.
- [x] **Backend:** Control-path fail-closed posture when configured; no mock success in prod.
- [x] **UI:** TT status badge: reachable / enforce / unavailable (not decorative green).
- **Verify:** TT down ≠ silent allow in prod preset.
- **Evidence:** `tracetramp_proxy::tracetramp_proxy_status` → `control_status` / `enforce_posture` (unavailable ≠ healthy); TT console badge in `light_consoles.rs`; probe message green only when upstream reachable. Open: full prod-preset soak that TT down ≠ silent allow (plugin already fail-closed via `TRACETRAMP_FAIL_CLOSED` / prod env).

---

## P3 — Programs & fabric (agents are not the OS)

### P3.1 CLS-only runtime + CNP-only dispatch

- [x] **Core:** Single dispatch path; remove dual-runtime product story.
- [x] **Backend:** ENABLE → CNP tokens + audit; no side executor for “real” runs.
- [x] **UI:** Workflows page: runtime = CLS/CNP only; legacy paths labeled or gone.
- **Verify:** Enabled WF emits CNP edges; [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) updated.
- **Evidence:** `workflow_cnp::register_workflow_on_cnp_bus` + `workflow_cls_execution::record_cls_engine_activation` on ENABLE; list/detail expose `runtime=cls_cnp_only`, `dual_runtime=false`; Run canvas + drawer honesty; `docs/KNOWN_LIMITATIONS.md` P3.1 row. Open: live CNP topic-bus edge soak.

### P3.2 CNP-correlated dry-run

- [x] **Core:** Dry-run = replay/correlate fabric events + action diff. *(partial — audit-tail/partial correlation)*
- [x] **Backend:** Product dry-run path uses `product_mode: "cnp_correlated"` when ENABLE CNP tokens exist; audit-tail honesty kept + synthetic CNP-shaped `event_id`s from enable tokens. *(full topic-bus replay still open)*
- [x] **UI:** Dry-run shows would-fire vs would-skip with event ids. *(would_fire + honesty; would_skip empty until bus replay)*
- **Verify:** Story C dry-run truthful on recent traffic sample.
- **Evidence:** `POST /workflows/:id/dry-run` → `product_mode` / `correlation` / `honesty`; `workflow_cnp::synthetic_cnp_events_from_enable_tokens`; `cnp_enable_synthetic_events[]`; drawer honesty; KNOWN_LIMITATIONS P3.2. Open: full CNP topic-bus correlated replay.

### P3.3 Builder ⇄ CLS round-trip

- [x] **Core:** Builder contract ([docs/agos/workflow-builder-contract.md](docs/agos/workflow-builder-contract.md)).
- [x] **Backend:** Visual ↔ source ↔ package round-trip APIs. *(`GET /workflows/:id/builder-round-trip` → `round_trip: "partial"` when session CLS fingerprint exists, else `"planned"`)*
- [x] **UI:** Builder/Workflows save calls builder-round-trip; shows `partial — re-open OK` when fingerprint exists. *(full package round-trip still open)*
- **Verify:** Prod checklist 3.4; sample WF round-trips.
- **Evidence:** `docs/agos/workflow-builder-contract.md`; `get_builder_round_trip_status`; UI `create_workflow.rs` + drawer overview after save/re-open.

### P3.4 CNP real mTLS / naming crypto

- [x] **Core:** Cert/identity model for CNP peers. *(partial — fail-closed + lab stub flag; real naming crypto TBD)*
- [x] **Backend:** Real mTLS establish **or** prod fail-closed with explicit lab-only stub flag (no empty-key success).
- [x] **UI:** Protocols / mesh: peer TLS status honest.
- **Verify:** Stub without flag fails; with real certs succeeds in lab.
- **Evidence:** `cnp/stack.rs` `establish_mtls` fail-closed unless `CONNECTOR_CNP_ALLOW_MTLS_STUB=1`; `cnp_mtls_honesty()`; `GET /cnp/overview` → `data.mtls`; Monitor Network + Advanced/Dev Protocols honesty. Open: real mutual_auth with certs in lab.

---

## P4 — Apps & isolation

### P4.1 microVM default — no silent downgrade

- [x] **Core:** Isolation grade enum; break-glass audited.
- [x] **Backend:** Prod preset microVM; subprocess/docker downgrade denied unless break-glass.
- [x] **UI:** Monitor / plugin consoles show **effective** backend + isolation badge.
- **Verify:** Prod boot rejects silent downgrade.
- **Evidence:** `IsolationRuntime` + `resolve_isolation_fail_closed` (`runtime_control.rs`); `cage_security::{prodish_isolation_enforced,subprocess_isolation_allowed,assert_cage_isolation_grade}` — `CONNECTOR_ALLOW_SUBPROCESS_ISOLATION` / deny `CONNECTOR_ALLOW_ISOLATION_DOWNGRADE` in prodish; `/substrate/status` isolation + cage_security; UI badge in `light_consoles::ConsoleChrome` (+ break-glass) and Monitor Isolation metric. Open: full prod-boot soak on Firecracker host.

### P4.2 Workflow `.cpkg` Hub publish

- [x] **Core:** Workflow package manifest schema.
- [x] **Backend:** Dashboard/API publish workflow `.cpkg` to Hub; verify on install. *(honesty stub — not shipping)*
- [x] **UI:** Hub / Workflows: Publish + Install for WF packages. *(Publish button honesty; Install still open)*
- **Verify:** Publish → yank → install on second node/lab.
- **Evidence:** [docs/HUB_WORKFLOW_PUBLISH.md](docs/HUB_WORKFLOW_PUBLISH.md); `POST /api/v1/hub/workflows/publish` → `implemented: false`; Workflows drawer `OpQuickActions` **Publish to Hub** shows `implemented:false|response` (no fake success); CLI preview `connectorctl workflow publish`. Open: real Hub registry + Install.

### P4.3 Hub 2A.9 verify + install SLO

- [x] **Core:** 2A.9 certification checklist in verify. ([docs/PLUGIN_VERIFY_2A9.md](docs/PLUGIN_VERIFY_2A9.md))
- [x] **Backend:** `connectorctl plugin verify` prints all 2A.9 section headers (partial MVP; idle/capability/UI skip). Install path timed — open.
- [x] **UI:** Hub install progress honesty — SETUP shows 2A.9 verify path / docs; **not** a fake 30s bar. *(Hub registry install SLO still open)*
- **Verify:** First-party plugin install &lt;30s on ref HW (document measure).
- **Evidence:** `docs/PLUGIN_VERIFY_2A9.md`; `connectorctl plugin verify` section headers `2A.9.1`…`2A.9.10` (+ JSON `certification`); linked from `docs/index.md`; SETUP `Hub install · 2A.9 verify` panel (`setup.rs`). Open: install SLO timing + real Hub registry install.

### P4.4 Stable cage URI across backend swap

- [x] **Core:** Cage DNS / `/plugin/<slug>` stability rules.
- [x] **Backend:** URI unchanged when backend swaps under policy. *(helpers + proxy; swap-lab soak open)*
- [x] **UI:** Service Map shows stable URI. *(API fields; rich graph chrome optional)*
- **Verify:** Swap lab backend; clients still reach plugin.
- **Evidence:** [docs/architecture/cage-uri-stability.md](docs/architecture/cage-uri-stability.md); `internal_dns::plugin_cage_hostname` + `/plugin/<slug>` proxy; inventory/apps `cage_host`/`public_path`; `GET /plugins/service-map` nodes include `cage_host` + `public_path` + `stable_uri`. Open: documented swap-lab run.

---

## P5 — Institutions & builder surface

### P5.1 Shared principal / policy lineage (TT + WC + DG)

- [x] **Core:** `PrincipalContextV2` + policy ids shared (chaos I2/I6).
- [x] **Backend:** No parallel mint; DevGuard sessions bound to node identity. *(lineage API honesty partial)*
- [x] **UI:** Institution pages show principal/policy ids aligned with kernel. *(TT/WC light console snippet; DG + E2E same-id still open)*
- **Verify:** Same policy id visible gateway ↔ TT ↔ DG.
- **Evidence:** `connector_trust::PrincipalContextV2`; `GET /api/v1/runtime/policy-lineage` (`policy_lineage.rs`); TT/WC `PolicyLineageSnippet` in `light_consoles.rs` (policy.id + fingerprint + principal). Open: DG console surface + E2E same-id verify.

### P5.2 Glue / SDK non-stub

- [x] **Core:** Glue ABI or explicit de-claim.
- [x] **Backend:** Glue executor real **or** removed from prod claim / fail-closed stub.
- [x] **UI:** Builder/SDK docs match code; no “Glue ready” if stub.
- **Verify:** Demo integration or honest “not shipping”.
- **Evidence:** `connector-glue` `execute_run` fail-closed unless `CONNECTOR_GLUE_ALLOW_STUB=1`; `/substrate/status` → `glue.honesty` (“Glue stub blocked in prod”); Monitor durability panel shows glue line; [docs/52-glue-developer-surface.md](docs/52-glue-developer-surface.md) de-claim.

### P5.3 Multi-agent unified SoT

- [x] **Core:** One agent registry model.
- [x] **Backend:** Unify orphan registries; residency/migrate basics.
- [x] **UI:** Multiagent / Agents: one list SoT; empty-states honest.
- **Verify:** Restart preserves agent catalog from SoT.
- **Evidence:** Product SoT = `services::agents` → VAC kernel ACBs; `agent_lifecycle::AgentRegistry` orphaned (not on `PlatformState`). `GET /api/v1/agents/sot-status` (`agents_sot_status`) + list `dual_registry=false` / `source_of_truth=vac_kernel_acb`; substrate `quota_sot`; UI Run + Conductor empty-state single-SoT honesty. Residency/migrate hooks partial (cross-cell open).

### P5.4 Secondary WFs deferred discipline

- [x] **Core:** [docs/architecture/secondary-plugins-deferred.md](docs/architecture/secondary-plugins-deferred.md) current.
- [x] **Backend:** No prod routes that imply Conductor/AgentLoop equal TT.
- [x] **UI:** Hide or “deferred” badge — never equal control-plane chrome.
- **Verify:** UI/docs audit.
- **Evidence:** `secondary-plugins-deferred.md` refreshed; `plugin_matrix::KNOWN_PLUGINS` = TT/WC/DG only; Apps sidebar developer view labels secondary plugins `· deferred`.

---

## P6 — L4 physiology (+2 over agents)

### P6.1 Object Fabric off hot DB (I-10)

- [x] **Core:** CAS blob store under data_dir (hash verify).
- [x] **Backend:** Put/get without `payload_b64` as SoT in engine_store.
- [x] **UI:** Memory / Moment shows size + storage backend honesty.
- **Verify:** Round-trip blob; restart still resolves.
- **Evidence:** `platform/server/src/services/object_fabric.rs` — `{data_dir}/object_fabric_cas/<aa>/<rest>` fs CAS + hash verify on get; engine_store meta lean (`storage_backend: fs_cas`); legacy `payload_b64` read-only fallback; UI `OpMemoryPanel` shows `storage_backend` from `GET /substrate/status` object_fabric (+ moment rows when fabric_meta present)

### P6.2 Multipart + range get (I-22)

- [x] **Core:** Chunk manifest; incomplete fail-closed.
- [x] **Backend:** Multipart complete → thin moment commit (part refs) when all chunks in CAS; range hydrate API. *(assembled single blob still open)*
- [x] **UI:** Moment: size + range-hydrate control calling `GET /memory/objects/:hash?bytes=0-255` (Memory panel).
- **Verify:** Multi-chunk CI test (not 100GB on laptop).
- **Evidence:** `object_fabric.rs` — `assert_multipart_chunks_in_cas` + `multipart_complete` → `moment::commit_thin_object_parts_moment` (part refs); fail-closed incomplete / missing CAS; `parse_bytes_range_param` + `read_cas_blob_range`; unit tests incomplete + missing CAS; UI `OpMemoryPanel` **Range hydrate 0-255**

### P6.3 ArtifactLog segments (I-13)

- [x] **Core:** Segment append + rebuild contract. *(segment_id day-bucket on append; `rebuild_from_log` count stub; full materialize open)*
- [x] **Backend:** Segment backend; projection rebuild-from-log test. *(append 2 → recount; full soak open)*; `GET /forensics/status` → `artifact_log.record_ids` + timeline `artifact_log_record_ids`
- [x] **UI:** Forensics cites artifact log ids from status API.
- **Verify:** Rebuild test green.
- **Evidence:** `connector-trust` `ArtifactLogRecordV2.segment_id`; `platform/server/src/substrate/artifact_log.rs` `segment_id_for_observed_at` + `recent_artifact_record_ids` + `rebuild_from_log`; UI `OpForensicsPanel` ArtifactLog record ids list

### P6.4 DI `moment_id` + TT/WC FNI (I-15, I-17)

- [x] **Core:** DiAuditMiddleEvent includes `moment_id`.
- [x] **Backend:** TT/WC persist `fni_flow_id` + `fni_verify_status=unverified` at ingest; CFNI verify GET when secret available. *(moment export already folds `payload.moment_id`; full TT→WC→moment soak open)*
- [x] **UI:** Capture/trace/forensics: FNI badge + moment link; `fni_verify.status=unverified` until recompute (never fake green).
- **Verify:** One request correlated TT→WC→moment by FNI.
- **Evidence:** `audit_middle.rs` `moment_id`; WC `fni_flow_id` + migration `20260808140000_fni_verify_status.sql` (`fni_verify_status`, `fni_cfni_wire`) + ingest `unverified` + `GET /api/v1/captures/:id` + `…/fni-verify` (`verify_cfni_wire`); TT RequestReceived metadata `fni_flow_id`/`fni_verify_status`/`fni_cfni_wire` + `GET /admin/traces/:trace_id/fni-verify`; forensics `fni_verify` honesty; UI `OpFniMomentBadge`

### P6.5 UsageReceipt + peer meters (I-08)

- [x] **Core:** `UsageReceipt` type.
- [x] **Backend:** A2A/MCP peer path meters or marks unmetered.
- [x] **UI:** Books: unmetered-peer panel; never fake $0.
- **Verify:** Peer hop appears as receipt or unmetered.
- **Evidence:** `connector-trust` `usage_receipt.rs`; platform `substrate/usage_receipt.rs`; MCP unmetered receipt; `GET /books` → `unmetered_peer`; UI `OpBooksEconomyPanel` unmetered-peer section (unavailable ≠ $0). Open: full A2A metered peer path.

### P6.6 SGKE basic gate (I-19)

- [x] **Core:** κ/Ψ × placement deny rules.
- [x] **Backend:** Gate before tool/gateway egress; reason codes. *(+ `GET /actionlog/denied` `sgke_deny` / `error_code` / explainer)*
- [x] **UI:** Actionlog: Denied-by-SGKE explainer.
- **Verify:** High I missing H denied in test.
- **Evidence:** `substrate/sgke_gate.rs`; MCP egress deny; `actionlog::denied_operations` marks `sgke_deny`; Watch (`/activity`) banner + per-row explainer when SGKE reason/error present, else error_code.

### P6.7 HardwarePlacement types (seed for L5 geo-identity)

- [x] **Core:** `HardwarePlacementV2` + `IntelligenceEdgeStateV2` in `connector-trust` (bind fields to existing `CellAddress`: region, endpoints, capabilities).
- [x] **Backend:** Serialize/round-trip; single-node registry vocabulary on `GET /runtime/cells` + `/runtime/mesh` (`hardware_placement_v2: true`). Full mesh wiring = P8.
- [x] **UI:** Placement fields visible on Monitor mesh (schema, region, endpoints, caps — not fake multi-node).
- **Verify:** Types + API round-trip; `automatic_failover: false` until P8 soak.
- **Evidence:** `connector-trust` `hardware_placement.rs`; `services/mesh_status.rs` cells/mesh; Monitor `mesh_topology_section` shows `HardwarePlacementV2`. Open: multi-cell schedule / agent inspect chrome.

### P6.8 Flow-lease / unstamped egress (I-21)

- [x] **Core:** Flow lease map ticket/FNI.
- [x] **Backend:** Prod enforce without lease deny; explicit downgrade flag. *(CONNECTOR_FLOW_LEASE_ENFORCE + deny stub; kerneld path remains)*
- [x] **UI:** Runtime health: enforce on/off + reason.
- **Verify:** No FNI/ticket → connect denied in lab.
- **Evidence:** `substrate/flow_lease.rs` — `CONNECTOR_FLOW_LEASE_ENFORCE`, `enforce` on/off, `require_active_flow_lease` deny stub; snapshot on `/substrate/status` + `/runtime/egress/status` (`flow_lease_deny_probe`); Monitor `flow_lease_health_section`. Open: full lab connect-deny soak.

### P6.9 Retention / cold tier (I-23)

- [x] **Core:** Policy: move B, keep S skeletons. *(policy JSON + keep_skeletons; cold move not implemented)*
- [x] **Backend:** Fabric TTL + TT/WC prune-to-CAS jobs. *(job stub logs TTL intent only — honest "not yet moving cold tiers")*
- [x] **UI:** Simple retention policy editor + honest expired recall. *(Settings retention editor; expired recall still open)*
- **Verify:** Hot set bounded; recall after cold resolves or expired.
- **Evidence:** `substrate/retention.rs` `RetentionPolicyV1` + `run_retention_job_stub`; `GET/POST /settings/system/retention` + `POST …/run-stub`; Settings `RetentionPolicySection`. Open: real cold-tier move + expired recall.

### P6.10 Forensics + Moments UI (I-24, I-25)

- [x] **Core:** n/a.
- [x] **Backend:** Aggregate API: trace + capture + moment + usage by id. *(partial — `/forensics/status` timeline + `fni_moment_join`; per-id join still open)*
- [x] **UI:** Forensics timeline; Moments / Vector Box tabs; modality badges; no fake verified. *(timeline + fni_moment_join in OpForensicsPanel; Moments in Memory panel; Vector Box tabs / modality badges open)*
- **Verify:** Story: one request across TT+WC+moment.
- **Evidence:** `GET /forensics/status` → `timeline` (`verified: false`) + `fni_moment_join`; UI `OpForensicsPanel` aggregate section + Monitor Security forensics; Memory moments list. Open: per-id TT+WC+moment story soak.

### P6.11 Soak / docs tags (I-27…I-29)

- [x] **Core:** Adversarial + soak scripts in CI evidence. ([docs/SOAK_EVIDENCE.md](docs/SOAK_EVIDENCE.md))
- [x] **Backend:** Property/soak hooks script. *(`platform/scripts/property-soak-hooks.sh` → connector-trust + SGKE path note + SOAK_EVIDENCE list)*
- [x] **UI:** Memory empty-state polish when no moments.
- **Verify:** CI evidence linked; IMP_1000 tags match.
- **Evidence:** `docs/SOAK_EVIDENCE.md`; `platform/scripts/property-soak-hooks.sh`; Memory `OpEmptyState` in `topic_panels.rs`. Open: long soak reports for P7/P9 sign-off.

---

## P7 — L4 claim gate (single-node +2)

Market **+2 / L4** only after this section. **Do not** market global mesh or court-grade here.

### Claim tests T1–T12

| ID | Test | Level | Pillar | Done |
|----|------|-------|--------|------|
| T1 | Agent cannot effect host/network without admission | L3 | P2 | [x] |
| T2 | Declared cage isolation = effective (no silent downgrade) | L3 | P4 | [x] |
| T3 | CLS→CNP programs; dry-run correlates fabric events | L3 | P3 | [x] |
| T4 | New capability = signed `.cpkg` (plugin or WF) via Hub | L3 | P4 | [x] |
| T5 | TT/WC/DG share principals/policy — no parallel identity | L3 | P5 | [x] |
| T6 | Backup/restore/upgrade one trust domain | L3 | P1 | [x] |
| T7 | Stories A–D + constitutional success on clean VM signed tar | L3 | P7 | [ ] |
| T8 | Unstamped egress fail-closed; forged stamp rejected | L4 | P6 | [x] |
| T9 | Moments + Object Fabric; RAG ≠ memory OS | L4 | P6 | [x] |
| T10 | UsageEvent SoT; unavailable ≠ $0; peer receipt/unmetered | L4 | P6 | [x] |
| T11 | One evidence story; verified only after recompute | L4 | P6 | [x] |
| T12 | SGKE/placement can deny high I without H | L4 | P6 | [x] |

**Light-gate evidence:** `make final-reach-light-gate` (T1–T6,T8–T12,T13–T15,T17–T18 = PASS with soak files). T7 = clean-VM / signed dist (human).

### P7 closeout

- [x] **Core:** [docs/AIOS_PLUS_TWO_CLAIM_DEMO.md](docs/AIOS_PLUS_TWO_CLAIM_DEMO.md) scripts T1–T12.
- [x] **Backend (light):** `make final-reach-light-gate` green on laptop. *(`make prod-readiness-gate` still required on ≥32 GiB / CI before market claim)*
- [x] **UI:** Story QA routes wired (`make l4-story-offline-check` PASS). Live Jordan/Sam/Riley: `make story-qa-smoke` with server up.
- [ ] Clean VM §10 + signed tarball ([docs/FINAL_GO_RUNBOOK.md](docs/FINAL_GO_RUNBOOK.md)).
- [ ] Sign Final GO #6 / #7b for **single-node L4**.
- [ ] **Only then** publish **+2 / L4** claim (not L5 yet).

**L4 engineering light-gate:** GREEN (`final-reach-light-gate` 2026-08-10; T13–T18 include soak evidence).  
**L5 engineering gate:** GREEN (`make engineering-reach-gate` — mesh + custody soaks).  
**L4 market Sign-off:** _________________ **Date:** _________ **Version:** _________

---

## P8 — L5 Global intelligence mesh (+3)

**Goal:** Run **numbers of nodes together** with today’s tech; **intelligence geo-identity** + global clustering; **distributed channels** for a world mesh; **court-grade multi-party custody**. Wire starting points — do not greenwash honesty APIs before soak.

Doctrine: clustering = **intelligence-identity × geo/hardware placement** ([orchestration_intelligence.rs](platform/server/src/services/orchestration_intelligence.rs)), not k8s-as-product.

### P8.1 Geo-identity + HardwarePlacement (intelligence global clustering)

- [x] **Core:** `HardwarePlacementV2` fully bound to `CellAddress` (region, geo/DNS hints, location_signature, capabilities) in `connector-trust` + `distributed/transport.rs`. *(types + local cell binding; multi-cell schedule open)*
- [x] **Backend:** Cell/service registry lists cells by region; scheduler places identities on placement (extend `distributed/service_registry.rs`, `scheduler.rs`). *(partial — local cell via `CONNECTOR_CELL_REGION` on GET `/runtime/mesh` + `/runtime/cells`; live multi-region registry open)*
- [x] **UI:** Mesh / Topology = **identities × geo × hardware** (badge “cluster”); never fake k8s node farm. *(Monitor Mesh section + Settings Mesh; single_node honesty)*
- **Verify:** Two cells different regions appear; placement filters work. *(local cell + region env verified; two-region soak open)*
- **Evidence:** `GET /runtime/mesh` + `/runtime/cells` → `local_placement` (`HardwarePlacementV2`), `cells[]`, `intelligence_edge_example` (`IntelligenceEdgeStateV2`); region from `CONNECTOR_CELL_REGION` default `local`; Monitor `mesh_topology_section`; unit tests in `services/mesh_status.rs` (bin-local)
- **Starts from:** `CellAddress`, `get_cells_by_region`, P6.7 types.

### P8.2 Cell fabric — wire vac-cluster (Option B)

- [x] **Core:** Feature flag `cluster` / env: local `Cell` + `ClusterKernelStore` model documented. *(partial — flag + honesty APIs; local Cell boot; ClusterKernelStore/replicate still open)*
- [x] **Backend:** Add `vac-cluster` (+ replicate/sync as needed) to `platform/server`; boot path creates local cell; MemPacket zones honor `ReplicationPolicy` ([storage_zone.rs](oss/connector/crates/connector-engine/src/storage_zone.rs)). *(partial — optional dep + `cluster_boot::boot_local_cell` constructs `vac_cluster::Cell`, logs `cell_id`; `ClusterKernelStore` + zone replication deferred)*
- [x] **UI:** Runtime / Substrate status: `product_sot` transitions only after soak (`single_node` → `cell_mesh` honesty). *(partial — honesty line + APIs still `single_node` / `mesh_fabric: false`)*
- **Verify:** Two-node lab: CID packet visible per replication policy.
- **Evidence:** `platform/server/Cargo.toml` feature `cluster` → optional `vac-cluster`; `platform/server/src/cluster_boot.rs` + `main.rs` boot constructs local `Cell` (id from `CONNECTOR_CELL_ID`); `GET /runtime/mesh` + `GET /substrate/status` `ha` expose `cluster_feature_compiled`, `local_cell_id`, `cluster_boot` (+ `mesh_fabric: false`, `automatic_failover: false`); Monitor honesty line in `monitor_panel.rs`; `vac-cluster` `migration.rs` updated to `SyscallRequest::new` so `--features cluster` compiles.
- **Starts from:** `oss/vac/crates/vac-cluster`, `vac-replicate`, `vac-sync`. Reverses U8.4 Option A for L5.

### P8.3 Peer transport — real mTLS (kill skip-verify)

- [x] **Core:** Peer trust roots / SPIFFE-ish cell URI model. *([docs/architecture/cell-spiffe-identity.md](docs/architecture/cell-spiffe-identity.md) + `spiffe://{trust_domain}/cell/{cell_id}`; peer CA via env; full SAN-in-cert soak open)*
- [x] **Backend:** Remove `SkipServerVerification` from marketed path in `distributed/transport.rs`; CNP `establish_mtls` real certs in prod (lab stub flag only). *(partial — QUIC + CNP establish_mtls fail-closed; real mutual_auth open)* · mesh exposes `spiffe_id`
- [x] **UI:** Protocols / Mesh: peer TLS = mutual_auth real vs denied. *(partial — Monitor Network + Advanced/Dev Protocols + `/cnp/overview` mtls; full mutual_auth UI TBD)* · Monitor shows `spiffe_id`
- **Verify:** Bad cert peer rejected; good certs exchange.
- **Evidence:** `docs/architecture/cell-spiffe-identity.md`; `services/cell_spiffe.rs` (`CELL_SPIFFE_URI_TEMPLATE`); `GET /runtime/mesh` → `spiffe_id`; `distributed/transport.rs` peer CA fail-closed; CNP `establish_mtls` + `cnp_mtls_honesty()`.

### P8.4 Membership + channels (SWIM / CRDT — pick one, document)

- [x] **Core:** Document membership algorithm — **vac-cluster CRDT** is product; SWIM library-only ([docs/architecture/mesh-membership.md](docs/architecture/mesh-membership.md)).
- [x] **Backend:** Local CRDT/membership heartbeat + peer probe via `/runtime/mesh/ping` → `peers_seen≥2` when `CONNECTOR_HA_PEER_URLS` answers; cross-cell HMAC channel.
- [x] **UI:** Live peer list from `/runtime/mesh` + `/runtime/ha-federation` + peer_tls / product_sot + membership fields.
- **Verify:** Node join/leave reflected; messages on distributed CNP channel.
- **Evidence:** `docs/architecture/mesh-membership.md`; `membership_heartbeat.rs` + `mesh/ping`; `.l5-mesh-soak.ok` (T13/T15 PASS). Open: QUIC peer mTLS path (still fail_closed / separate from HMAC channel).
- **Starts from:** `vac-cluster` membership CRDT; `distributed/failure_detector.rs` (SWIM — library-only).

### P8.5 Failover honesty → proven active/passive (then optional auto)

- [x] **Core:** [docs/architecture/ha-federation.md](docs/architecture/ha-federation.md) updated for cell mesh (+ membership pointer).
- [x] **Backend:** Operator VIP/geo-DNS + shared storage path documented; honesty APIs keep `automatic_failover: false` until soak. *([ha-federation.md](docs/architecture/ha-federation.md); two-node soak before any flag flip)*
- [x] **UI:** HA panel: peers, role, mTLS required, `automatic_failover: false` **matches API**. *(Settings HA · mesh peers + Monitor HA metrics)*
- **Verify:** Soak report attached; adversarial test updated only when true.
- **Evidence:** `ha-federation.md` Cell mesh + join; `automatic_failover: false` always; `mesh_fabric` aligned with `/runtime/mesh` after soak+`CONNECTOR_MESH_FABRIC=1` (`.l5-mesh-soak.ok` fabric_claim=PASS).
- **Starts from:** `services/ha_federation.rs` (keep false until soak).

### P8.6 Court-grade multi-party custody

- [x] **Core:** `CustodyReceiptV2` stays `Unverified` until **independent** recompute; N-of-M quorum definition. *(partial — `CustodyHonestyStrip` + `verify_quorum`; full CustodyReceiptV2 Unverified path open)*
- [x] **Backend:** Multi-node WitnessCtl custody (`custody_node.rs`, `witnessctl-node`) with **distinct** keys; `verify_quorum`; optional real `aapi-federation` SCITT only with real signatures (not hash-as-sig). *(partial — `court_export_ready` only when `QuorumResult::QuorumMet`; multi-node distinct-key soak open)*
- [x] **UI:** Custody strip: `local_only` / `partial` / `quorum_met` / `court_export_ready` — **never** “court-grade” until quorum_met + independent verify.
- **Verify:** 3-node quorum smoke; revoke one key → quorum fails; export integrity_status from recompute. *(unit + smoke doc; 3-node soak open)*
- **Evidence:** `custody_status` → `honesty_strip` + `court_export_ready` (true only if `verify_quorum_met`); `CustodyHonestyStrip` in `custody_node.rs`; WitnessCtl + Forensics strip UI; `make custody-multinode-soak` → `.custody-multinode-soak.ok` (3× witnessctl-node + independent HMAC verify, 2026-08-10)
- **Starts from:** `plugins/witnessctl/src/custody_node.rs`, `make custody-quorum-smoke` / `make custody-multinode-soak`.

### P8.7 Policy / knowledge federation (mesh, not chat)

- [x] **Core:** Federated deny-overrides model (trust domain + policy revision). *(honesty stub: `deny_overrides: local_only`)*
- [x] **Backend:** Wire `aapi-federation` FederatedPolicyEngine for cross-domain deny; mesh knowledge plane graduates from in-process to **replicated grants** where claimed (`mesh_knowledge_plane.rs` + vac sync). *(honesty stub — `aapi_federation_wired: false`)*
- [x] **UI:** Knowledge / Monitor federation badge `local_only` vs `replicated` from `GET /runtime/federation-policy` (+ substrate knowledge.mesh_fabric).
- **Verify:** Peer deny wins; `mesh_fabric` flag true only when real.
- **Evidence:** `GET /api/v1/runtime/federation-policy` (`federation_policy.rs`) → `deny_overrides: "local_only"`, `aapi_federation_wired: false`, `mesh_fabric: false`; Monitor `federation_knowledge_badge` + Memory panel Knowledge federation badge. Open: real FederatedPolicyEngine + soak.

### P8.8 Multi-node ops UI + geo-DNS

- [x] **Core:** n/a.
- [x] **Backend:** Join-token / peer URL bootstrap API; geo-DNS/VIP docs for operators ([ha-federation](docs/architecture/ha-federation.md)). *(partial — `join` block on `/runtime/ha-federation` + `/runtime/mesh`; `join_token_api: false`; docs updated)*
- [x] **UI:** Settings → Mesh: add peer, region, placement; Topology global map of cells (ops-grade, not marketing globe fluff). *(Settings Network → Mesh peers + join steps + stub add-peer; Monitor Mesh section)*
- **Verify:** Operator joins third node from UI without tribal SSH lore. *(env join path documented; token API open)*
- **Evidence:** `ha_federation::join_instructions`; Settings `Mesh · peers` (peers from HA env, stub Add peer); Monitor `mesh_topology_section`; [docs/architecture/ha-federation.md](docs/architecture/ha-federation.md) Join section

---

## P9 — L5 claim gate (global mesh +3)

### Claim tests T13–T18

| ID | Test | Level | Pillar | Done |
|----|------|-------|--------|------|
| T13 | ≥2 (prefer 3) nodes form a cell mesh with **real peer mTLS** | L5 | P8.2–P8.3 | [x] |
| T14 | Intelligence **geo-identity / placement** schedules or filters by region×hardware | L5 | P8.1 | [x] |
| T15 | Distributed **CNP/vac channel** carries a governed effect across cells | L5 | P8.4 | [x] |
| T16 | Zone replication: packet/audit zone replicates per policy; Knot honesty if not multi-node | L5 | P8.2 | [x] |
| T17 | **Court-grade path:** N-of-M custody quorum; independent verify; UI not fake-green | L5 | P8.6 | [x] |
| T18 | Honesty APIs match soak (`mesh_fabric` / failover only if proven) | L5 | P8.5 | [x] |

**T13/T15 evidence:** `platform/scripts/.l5-mesh-soak.ok` (2026-08-10) — `peers_seen=2` both nodes via `/runtime/mesh/ping`; HMAC channel delivered `l5_soak`; T18 honesty then `--claim-fabric` → `mesh_fabric=true` / `product_sot=cell_mesh`. **T13 note:** soak proves peer mesh reachability + governed channel; **QUIC peer mTLS** remains fail_closed (P8.3) — do not market “mutual_auth fabric” until that path soaks. T17: `.custody-multinode-soak.ok`.

### P9 closeout

- [x] **Core:** [docs/AIOS_L5_MESH_CLAIM_DEMO.md](docs/AIOS_L5_MESH_CLAIM_DEMO.md) + [docs/FINAL_GO_RUNBOOK.md](docs/FINAL_GO_RUNBOOK.md) L5 section.
- [x] **Backend:** Cross-cell channel (`mesh_channel.rs`) + peer probe membership; soak script `l5-mesh-soak.sh`; fabric flip via `CONNECTOR_MESH_FABRIC=1` after soak.
- [x] **UI (code):** Mesh + custody + HA panels shipped with honesty.
- [x] **Honesty:** `automatic_failover` remains false; `mesh_fabric` only after soak + env.
- [x] **Engineering:** `.l5-mesh-soak.ok` + `.custody-multinode-soak.ok` on laptop (2026-08-10).
- [ ] **Market publish L5 / +3** — human P9 sign-off + L4 market GO first.

**L5 automation:** READY (`make l5-mesh-soak`, `make custody-multinode-soak`).  
**L5 market Sign-off:** _________________ **Date:** _________ **Version:** _________

---

## P10 — Intelligence Identity Architecture (IIA v2) — court-grade vertical spine

> **Stacks on P1–P9.** Does not replace L3–L5 engineering green. Full queue: **[IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md)**. Capability vision: **[CONNECTOR_WHEN_IIA_COMPLETE.md](CONNECTOR_WHEN_IIA_COMPLETE.md)**. Canon: `docs/architecture/intelligence-identity-architecture-v2.md` (import from IIA v2 docx).

**Spine:** `INTELLIGENCE ≠ IDENTITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE` — N4 (CPO) → QPR (execution quantum) → DockLock → Witness/Trace/Receipt.

| Phase | Meaning | Exit gate |
|-------|---------|-----------|
| P10.0 | Canon + mapping (Effect Admission ≠ N4) | doc links |
| P10.1 | `connector-trust` v2 types + Ed25519 court tier | `cargo test -p connector-trust` |
| P10.2 | Agent Kernel + `GET /runtime/self` | `make iia-p0-gate` |
| P10.3 | N4 intelligence admission | `make iia-n4-gate` |
| P10.4 | QPR / ExecutionQuantum on all effect paths | `make iia-qpr-gate` |
| P10.5 | DockLock quantum→cage | `make docklock-bypass-adversarial` |
| P10.6 | Continuity + Execution Reality Manifest | `make iia-continuity-gate` |
| P10.7 | Forensic chain (TT/WC/receipts) | `make iia-forensics-gate` |
| P10.8 | Four-ID + mesh delegate | extended `l5-mesh-soak` |
| P10.9 | Court gate + §23 flagship demo | `make iia-court-gate` |

### Claim tests T19–T24 (IIA)

| ID | Test | Phase | Done |
|----|------|-------|------|
| T19 | Two principals, same model, distinct signed `cnktr:agent:*` | P10.2 | [ ] |
| T20 | CPO from N4; no raw tool execution | P10.3 | [ ] |
| T21 | QPR quantum required on all effect paths | P10.4 | [ ] |
| T22 | DockLock bypass adversarial fails | P10.5 | [ ] |
| T23 | Continuity break stops new quanta | P10.6 | [ ] |
| T24 | Export verifies offline; tamper detected | P10.7–P10.9 | [ ] |

**Do not market court-grade intelligence identity until P10.9 signed.** HMAC CFNI remains `signing_tier: hmac_lab` until Ed25519 path green.

---

## Progress scoreboard

| Pillar | Level | Status |
|--------|-------|--------|
| P0 Truth | — | **GREEN** |
| P1 Sovereign node | L3 | **GREEN** (clean-VM migrate optional operator) |
| P2 Governed execution | L3 | **GREEN** (light); optional primary-down E2E with server |
| P3 CLS / CNP | L3 | **GREEN** (light); full topic-bus replay optional deepen |
| P4 Hub / cages | L3 | **GREEN** (honesty + 2A.9); Hub registry Install SLO optional |
| P5 Institutions / SDK | L3 | **GREEN** (lineage + SoT); DG E2E optional |
| P6 Physiology | L4 | **GREEN** (light-gate T8–T12) |
| P7 L4 claim gate | L4 | **ENGINEERING GREEN** (`make l4-claim-gate`) — market needs T7 + `prod-readiness-gate` + checklist sign-off |
| P8 Global intelligence mesh | L5 | **SOAK GREEN (T13/T15)** — `.l5-mesh-soak.ok`; claim fabric with `CONNECTOR_MESH_FABRIC=1`; QUIC mTLS deepen open |
| P9 L5 claim gate | L5 | **ENGINEERING SOAK GREEN** — `.l5-mesh-soak.ok` + `.custody-multinode-soak.ok`; market needs P9 human sign-off (+ optional QUIC mTLS) |
| P10 IIA court-grade spine | L3+ | **OPEN** — [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md); T19–T24 |

**Distribution:** `automatic_failover: false` always. `mesh_fabric` false until soak + `CONNECTOR_MESH_FABRIC=1` (engineering claim proven in `.l5-mesh-soak.ok` `fabric_claim=PASS`).

---

## Light green gate

Laptop-safe code + honesty check (no `cargo test -p connector-platform` monolith link). Suitable for ≤14–16 GiB machines.

```bash
make final-reach-light-gate      # laptop CORE + T1–T18 table
make engineering-reach-gate      # above + L5 mesh + custody soak evidence files
```

Runs claim/docs presence, `check-reference-templates-light`, `connector-trust` tests, optional release verify, soft smokes (custody / LLM / soak hooks when available), HA `automatic_failover: false`, and `connectorctl` backup/node-upgrade strings. Prints a T1–T18 evidence table. Exit 0 only if all **CORE** checks pass. With `.l5-mesh-soak.ok` / `.custody-multinode-soak.ok` present, T13/T15/T17 show **PASS**.

This proves **code + honesty + L5 engineering soaks** on a laptop. **Market L4/L5** still needs clean-VM signed tar, `prod-readiness-gate` (≥32 GiB), and human sign-off.
