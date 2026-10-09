# Universal Operator Backend Checklist

**Status:** Pre-implementation — single source of truth for backend work **before** shell UI coding.  
**North star:** [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) (L3 APIs feed L2 manifests feed L1 shell).  
**Substrate:** [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) · [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md)

**One sentence:** Ship three universal registries — **workflow surface**, **institution capabilities**, **edge plane** — plus honest aggregate read APIs for RUN · WATCH · FIX · SETUP, on top of fail-closed substrate gates (P0–P1 minimum).

---

## 0. Laws (backend)

1. **One read path per concern** — UI never merges five endpoints for one card; server merges.
2. **Manifests are data, not code** — `operator_surface.v1`, `institution_capability.v1`, `edge_record.v1` in JSON; Rust only validates + merges.
3. **Institutions register, shell consumes** — TT/WC/DG extend `workflow-contract`, not bespoke routes in the dashboard.
4. **Truth or absent** — APIs return `null` / omit fields when unknown; never `0`, `$0.00`, or `verified: true` without verify.
5. **Extend before invent** — wire existing proxies (`custom_domains`, `internal_dns`, `plugins/status`, `actionlog`) into CEP; do not fork storage.
6. **No UI coding until B-EXIT** — see §8.

---

## 1. What exists today (audit)

Mark `[x]` only when verified in code + route inventory.

### 1.1 Workflow runtime

| Item | Route / module | Status |
|------|----------------|--------|
| List workflows | `GET /api/v1/workflows` → `workflow_runtime::list_workflows` | ☐ |
| Workflow detail | `GET /api/v1/workflows/:id` | ☐ |
| Lifecycle | `POST /api/v1/workflows/:id/lifecycle` | ☐ |
| Dry-run + reports | `POST …/dry-run`, `GET …/dry-runs`, `GET …/dry-runs/:run_id` | ☐ |
| Reference templates | `GET /api/v1/workflows/reference-templates` | ☐ |
| Template install | `POST /api/v1/workflows/reference/:id/install` | ☐ |
| Catalog sync | `GET/POST /api/v1/workflows/catalog[/sync]` → `workflow_catalog_sync.rs` | ☐ |
| Plugin workflow contract | `GET /plugins/workflow-contracts`, `POST /plugins/:id/workflow-contract` (actions/events only) | ☐ |
| **Operator surface** | `GET /workflows/:id/surface` | **missing** |
| **Capabilities resolve** | `GET /workflows/:id/capabilities` | **missing** |

### 1.2 Institutions & plugins

| Item | Route / module | Status |
|------|----------------|--------|
| Plugin status aggregate | `GET /api/v1/plugins/status` → `plugins_status.rs` | ☐ |
| Cage proof | `GET /api/v1/plugins/cage-proof` → `cage_proof.rs` | ☐ |
| TraceTramp proxy | `tracetramp_proxy.rs` | ☐ |
| WitnessCtl proxy + export | `witnessctl_proxy.rs`, `GET /plugins/witnessctl/sessions/:id/export` | ☐ |
| DevGuard hooks + connect | `devguard_proxy.rs`, `POST /devguard/connect` | ☐ |
| Cage proxy | `plugin_cage_proxy.rs` | ☐ |
| **Capability registry** | `GET /operator/capabilities` | **missing** |

### 1.3 Edge & networking

| Item | Route / module | Status |
|------|----------------|--------|
| Custom domains CRUD | `GET/POST /settings/networking/custom-domains` → `custom_domain_routing.rs` | ☐ |
| Internal DNS (cage) | `internal_dns/mod.rs` | ☐ |
| Host-based routing middleware | `custom_domain_routing` | ☐ |
| Gateway `/v1` | `gateway.rs`, `anthropic_gateway.rs` | ☐ |
| **Edge plane merge** | `GET /operator/edge/plane` | **missing** |
| **Edge write unify** | `POST /operator/edge/records` | **missing** |

### 1.4 Operator aggregates (shell feeds)

| Item | Route / module | Status |
|------|----------------|--------|
| Action log / denied | `GET /actionlog/*` | ☐ |
| Tool approvals | `GET /tools/approvals/pending` | ☐ |
| Monitor health | `GET /monitor/health` | ☐ |
| Books / costs | `GET /books/costs`, `/books/live` | ☐ |
| Proof / compliance export | `GET /proof/*`, `/compliance/report/pdf` | ☐ |
| Report center | `GET /reports/center` | ☐ |
| Unified health | `unified_health.rs` (partial) | ☐ |
| **Pulse summary** | `GET /operator/pulse` | **missing** |
| **WATCH stream** | `GET /operator/watch/events` (or documented client merge) | **missing** |
| **FIX queue** | `GET /operator/fix/queue` (or documented client merge) | ☐ optional |

### 1.5 Trust substrate (blocks honest backend)

| Item | Location | Status |
|------|----------|--------|
| `PrincipalContextV2` | `connector-trust` | ☐ types exist |
| `AdmissionTicketV2` | `connector-trust` + `admission.rs` | ☐ wired on all mutating effects |
| `ForensicFlowIdentityV2` | `connector-trust` | **missing** |
| Route admission matrix CI | `docs/architecture/route-security-inventory.json` + `scripts/audit-route-admission-inventory.py` | ☑ 19 wired effect paths (100% declared) |
| Tenant from verified token only | `middleware/tenant.rs` | ☐ P0 |
| WC session ownership / TT mgmt auth | proxies | ☐ P0 |

---

## 2. Three universal registries (build these first)

Detail schemas: [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) · [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md) · [UI_CONNECTOR_EDGE_PLANE.md](UI_CONNECTOR_EDGE_PLANE.md)

### 2.1 Registry A — `operator_surface.v1` (per workflow)

**Storage keys (proposed):**

- `operator_surfaces/{workflow_id}` — attached manifest
- Catalog sidecar: `{name}.operator.json` beside `{name}.ccl` / `{name}.workflow.json`
- Bundled: `platform/server/resources/workflow_templates/*.operator.json`

**Merge order (later wins where explicit):**

1. Default synthesizer (from `WorkflowRecord` + CLS metadata)
2. Reference template embedded manifest (if from template install)
3. Catalog `*.operator.json` / `.workflow.json` `operator_surface` block
4. `PUT /workflows/:id/surface` admin override
5. Plugin `workflow-contract` → fold `actions`/`events` into `actions[]` / `signals[]`

| ID | Backend task | File targets | Verify |
|----|--------------|--------------|--------|
| **B-W0** | Rust types + JSON schema for `operator_surface.v1` | new `platform/server/src/operator/surface.rs`, `schemas/operator_surface.v1.json` | serde round-trip test |
| **B-W1** | `default_surface(workflow_id)` synthesizer | `workflow_runtime.rs` or `operator/surface_merge.rs` | WF with no manifest returns valid surface |
| **B-W2** | Catalog ingest `*.operator.json` | `workflow_catalog_sync.rs` | drop file → stored + sync report lists it |
| **B-W3** | `GET /workflows/:id/surface` | `router.rs`, `operator/surface.rs` | HITL template merges TT+WC institutions |
| **B-W4** | `GET /workflows/surfaces?ids=` batch | same | RUN list ≤2 requests |
| **B-W5** | `PUT /workflows/:id/surface` (admin) | same | round-trip PUT → GET |
| **B-W6** | Ship manifests for 3 reference templates | `resources/workflow_templates/*.operator.json` | install HITL → surface has fix_rules + panels |
| **B-W7** | `GET /operator/panel-types` | `operator/surface.rs` | documents kv, summary, chips, event_list, table, approval_queue |
| **B-W8** | `connectorctl workflow lint-surface` | `bin/connectorctl.rs` | CI fails invalid manifest |

### 2.2 Registry B — `institution_capability.v1` (per plugin/kernel)

**Storage:** extend `plugin_workflow_contracts/{plugin_id}` or new folder `institution_capabilities/{id}`.

| ID | Backend task | File targets | Verify |
|----|--------------|--------------|--------|
| **B-K0** | Schema + types `institution_capability.v1` | `operator/capability.rs`, `schemas/institution_capability.v1.json` | archetype enum: witness \| enforcer \| actor |
| **B-K1** | Static seed: kernel, witnessctl, tracetramp, devguard | `operator/capability_seed.rs` | WC has `evidence.export`; DG has `connect.tool` only |
| **B-K2** | Plugin registration extends caps at enable | `register_plugin_workflow_contract` or new POST | plugin registers without UI fork |
| **B-K3** | `GET /operator/capabilities` | `router.rs` | lists all institutions + caps + bind templates |
| **B-K4** | `GET /workflows/:id/capabilities` | merge surface.institutions ∩ registry ∩ install state | DG-only WF has no PDF export cap |
| **B-K5** | Capability execute proxy helper (optional v1) | `operator/capability_exec.rs` | palette can POST execute with bind context |
| **B-K6** | Truth tests: no cap → 404 not empty stub | integration tests | `export pdf` on DG-only → explicit unavailable |

**Real capability map (v1 truth):**

| Institution | perform | export | forensics |
|-------------|---------|--------|-----------|
| witnessctl | — | session export (pdf, json, di_audit_middle) | custody.status |
| tracetramp | approve/trace actions | compliance.export | trace.list |
| devguard | connect.tool, profile.local | **none** | — |
| kernel | — | audit.export, compliance.pdf, report.center | proof.merkle |

### 2.3 Registry C — `edge_record.v1` (node-wide)

**v1 strategy:** read-merge existing stores; unified write delegates to `custom_domains` + future bind store.

| ID | Backend task | File targets | Verify |
|----|--------------|--------------|--------|
| **B-E0** | Types + schema `edge_record.v1` | `operator/edge.rs` | record kinds: HOST_ALIAS, INSTITUTION_ROUTE, GATEWAY_ROUTE, CAGE_INTERNAL, WORKFLOW_ROUTE, AGENT_ROUTE |
| **B-E1** | `GET /operator/edge/plane` merge | `operator/edge_merge.rs` | TT+WC hosts + `*.cnktros` + public URL in one JSON |
| **B-E2** | `GET /operator/edge/records`, `GET /operator/edge/dns-hints` | same | DNS hint strings for SETUP |
| **B-E3** | `POST /operator/edge/records` → custom_domains | `custom_domain_routing.rs` | create alias → appears in plane |
| **B-E4** | `DELETE /operator/edge/records/:id` | same | remove alias |
| **B-E5** | `POST /operator/edge/records/:id/prove` → cage_proof | `cage_proof.rs` | prove returns pass/fail + detail |
| **B-E6** | `GET /workflows/:id/edge`, `GET /agents/:pid/edge` | filter plane by bind | drawer tab has bindings only |
| **B-E7** | `require_cfni` policy field (stub until CFNI ships) | edge schema only | honest `supported: false` until P3 |

**Merge sources for E1:**

- `settings_system/custom_domains`
- `internal_dns` table
- `plugins/status` upstream URLs
- `cage_proof` last result
- env: `CONNECTOR_PUBLIC_URL`, gateway listen port

---

## 3. Shell aggregate APIs (RUN · WATCH · FIX · SETUP)

UI can client-merge initially; server merge is preferred for honesty and performance.

| ID | Endpoint | Purpose | Implementation notes |
|----|----------|---------|------------------------|
| **B-S0** | `GET /operator/pulse` | Pulse bar: running, needs-you, idle, node health | Merge `workflows` state + `fix/queue` count + `monitor/health` |
| **B-S1** | `GET /operator/fix/queue` | FIX inbox | Merge `actionlog/denied`, `tools/approvals/pending`, surface `fix_rules` evaluation, TT approvals if wired |
| **B-S2** | `GET /operator/watch/events` | WATCH stream | Merge `actionlog/actions` + health ticks + workflow events; cursor pagination |
| **B-S3** | `GET /operator/setup/summary` | SETUP landing | `plugins/status` + edge plane summary + license/secrets hints |
| **B-S4** | Response honesty envelope | All `/operator/*` | `unknown_fields`, `stale_at`, `source` per subsection |

**Alternative (documented):** If B-S1/S2 slip, publish `UI_PAGE_DESIGN.md` client merge recipe and keep v1 pulse server-side only.

---

## 4. Substrate gates (backend-only minimum before B-EXIT)

From [CHAOS checklist](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) — **backend scope** for universal operator APIs.

### Phase B-P0 — Stop bleeding (parallel with B-W0)

| ID | Task | Closes chaos | Verify |
|----|------|--------------|--------|
| B-P0-1 | Tenant never from unverified header | I1 | adversarial HTTP test |
| B-P0-2 | Open-auth / lab presets loopback-bound | I5 | prod profile smoke |
| B-P0-3 | WitnessCtl session IDOR closed | X6 | cross-session export → 403 |
| B-P0-4 | TT management auth attached on mgmt routes | X5 | unauthenticated mgmt → 401 |
| B-P0-5 | Remove fake `verified` from API payloads | U1 | grep API responses |
| B-P0-6 | Books/costs: unavailable ≠ `0` | M3, U2 | `GET /books/costs` contract test |

### Phase B-P1 — One identity envelope (before capability execute)

| ID | Task | Closes chaos | Verify |
|----|------|--------------|--------|
| B-P1-1 | Admission on all mutating `/operator/*` writes | O2, T4 | route matrix CI |
| B-P1-2 | Plugin proxies consume `PrincipalContextV2` | O6, I2 | TT/WC handoff carries principal |
| B-P1-3 | No ambient god token as default in prod profile | I4 | env preset test |
| B-P1-4 | Cage DNS name ≠ authorization | I3 | Host header spoof test |

### Phase B-P2 — Data honesty (parallel, not blocking B-EXIT)

| ID | Task | Maps to |
|----|------|---------|
| B-P2-1 | MemWrite WAL / flush metrics | I-03, S2 |
| B-P2-2 | UsageEvent SoT for `/books/live` | I-05, M1 |
| B-P2-3 | ArtifactLog append path | I-13, S1 |

### Phase B-P3 — CFNI (after B-EXIT, links to E7)

| ID | Task | Maps to |
|----|------|---------|
| B-P3-1 | `ForensicFlowIdentityV2` in connector-trust | I-16 |
| B-P3-2 | Stamp gateway + TT + WC | I-17 |
| B-P3-3 | `edge_record.policy.require_cfni` enforced | N1 |

---

## 5. Module layout (new code)

```text
platform/server/src/
  operator/
    mod.rs
    surface.rs          # B-W0–W7
    surface_merge.rs    # default + catalog + contract merge
    capability.rs       # B-K0–K4
    capability_seed.rs  # WC/TT/DG/kernel truth table
    edge.rs             # B-E0–E7
    edge_merge.rs       # custom_domains + internal_dns + status
    pulse.rs            # B-S0
    fix_queue.rs        # B-S1
    watch_events.rs     # B-S2
    setup_summary.rs    # B-S3
    honesty.rs          # unknown/null helpers for operator JSON
  schemas/
    operator_surface.v1.json
    institution_capability.v1.json
    edge_record.v1.json
```

**Touch existing:**

- `router.rs` — mount `/api/v1/operator/*`, `/api/v1/workflows/:id/surface`
- `workflow_catalog_sync.rs` — ingest operator JSON
- `workflow_runtime.rs` — surface storage helpers
- `custom_domain_routing.rs` — edge write delegate
- `services/mod.rs` — `pub mod operator`

---

## 6. Execution order

```text
B-P0 (parallel) ─────────────────────────────────────────┐
                                                          │
B-W0 → B-W1 → B-W2 → B-W3 → B-W4 → B-W6 → B-W8           │
         │                                                │
B-K0 → B-K1 → B-K3 → B-K4                                ├──► B-EXIT
         │                                                │
B-E0 → B-E1 → B-E2 → B-E3 → B-E5                         │
         │                                                │
B-S0 (needs W3 surface list + fix count) ────────────────┘

B-P1 (before B-K5 execute + edge writes in prod)
B-P2 / B-P3 (ongoing substrate — do not block shell v1)
```

**First coding PR (recommended):** `B-W0` + `B-W1` + `B-W3` + `B-K0` + `B-K1` + `B-K3` + types only for edge.

**Second PR:** `B-W2`, `B-W6`, `B-E0`, `B-E1`, `B-S0`.

**Third PR:** `B-E3`–`E5`, `B-S1`, `B-W8` CLI lint.

---

## 7. Verification gates (per phase)

### Gate G1 — Surface

- [ ] `GET /workflows/:id/surface` for unknown id → 404
- [ ] Workflow with no manifest → default surface with `schema: operator_surface.v1`
- [ ] HITL installed → `institutions: ["tracetramp","witnessctl"]` on surface
- [ ] Catalog drop `foo.operator.json` → sync → surface persisted

### Gate G2 — Capabilities

- [ ] `GET /operator/capabilities` includes kernel + 3 institutions
- [ ] `GET /workflows/:id/capabilities` for PII template → devguard perform, no wc export unless WC installed
- [ ] Missing plugin → capability `available: false`, not omitted silently

### Gate G3 — Edge

- [ ] `GET /operator/edge/plane` lists custom domain + internal cage host for enabled TT
- [ ] POST edge record → readable in plane + in `custom-domains` GET
- [ ] prove → calls cage_proof, returns structured result

### Gate G4 — Pulse / honesty

- [ ] `GET /operator/pulse` with zero workflows → idle count honest, not fake health
- [ ] No `$0.00` or `100%` in operator aggregate when data missing
- [ ] All `/operator/*` responses include `generated_at`

### Gate G5 — Substrate (P0)

- [ ] Adversarial tenant header test green
- [ ] WC export other tenant/session → denied

---

## 8. B-EXIT — start UI coding when

All required:

- [ ] **G1** surface merge live (`B-W3` + `B-W1`)
- [ ] **G2** capability registry live (`B-K3` + `B-K4`)
- [ ] **G3** edge plane read live (`B-E1`)
- [ ] **G4** pulse API live (`B-S0`)
- [ ] **G5** P0 backend items closed (`B-P0-1` … `B-P0-6`)
- [ ] Reference template operator manifests shipped (`B-W6`)
- [ ] `connectorctl workflow lint-surface` in CI (`B-W8`)

Optional for v1 UI (can client-merge):

- [ ] `B-S1` fix queue server merge
- [ ] `B-S2` watch events server merge
- [ ] `B-E3` edge write unify
- [ ] `B-P1` full admission matrix

---

## 9. Progress tracker

| Track | IDs | Status | Date | Notes |
|-------|-----|--------|------|-------|
| Substrate P0 | B-P0-* | ☐ | | |
| Surface | B-W0–W8 | ☐ in progress | | B-W0–W7 first PR landed |
| Capabilities | B-K0–K6 | ☐ in progress | | B-K0–K4 landed |
| Edge plane | B-E0–E7 | ☐ in progress | | B-E0–E1 read landed |
| Shell aggregates | B-S0–S4 | ☐ in progress | | B-S0 landed |
| Substrate P1 | B-P1-* | ☐ | | |
| **B-EXIT** | §8 | ☐ | | |

---

## 10. Relationship to other docs

| Document | Role |
|----------|------|
| **This file** | **Backend execution checklist** — code before UI |
| [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) | UI phases (start after B-EXIT) |
| [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) | Surface schema detail |
| [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md) | Capability schema + archetypes |
| [UI_CONNECTOR_EDGE_PLANE.md](UI_CONNECTOR_EDGE_PLANE.md) | Edge record detail |
| [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md) | Per-topic API field maps (drawer) |
| [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) | Why P0–P5 exist |
| [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) | Grade C iterations → B-P2/P3 |

---

## 11. One sentence for the next implementer

> Build **merge APIs** for workflow surface, institution capabilities, and edge plane; seed **truthful** TT/WC/DG capability tables; add **pulse**; close **P0** — then the universal shell renders from data with zero workflow-specific Rust in the dashboard.

---

*Update §9 as items close. Do not start `platform/ui-leptos` shell components until B-EXIT.*
