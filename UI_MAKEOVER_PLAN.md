# Operator UI Plan (v3.1 — Universal Shell + Substrate Alignment)

**Status:** Ready to implement shell — backend B-EXIT gate largely closed ([BACKEND_TOP_GRADE_TRACK.md](BACKEND_TOP_GRADE_TRACK.md) T0–T5).  
**Target UI:** `platform/ui-leptos/dashboard` (`connector-ui`) — node operator surface only.  
**Not in scope:** portal `www` · vendor `admin`.

**One sentence:** Build a **Universal Operator Shell** (RUN · WATCH · FIX · SETUP) with a **Universal Workflow Surface** (one renderer, manifest per workflow) — **grounded in kernel substrate** (progeny tree, graph firewall, orchestration intelligence) — so operators run intelligence without learning our page map, and workflow #500 needs zero UI code.

**v3.1 change:** Backend now ships real control-plane primitives (not philosophical stubs). UI must **read substrate APIs**, not invent parallel lifecycle/firewall/orchestration state. See §12.

**Greenfield rebuild:** Delete legacy 81-page sprawl; build **Op* library first** — see **[UI_GREENFIELD_BUILD_PLAN.md](UI_GREENFIELD_BUILD_PLAN.md)** (38 primitives → 11 cards → 16 overlays → 10 shell surfaces). Reference mock: CONNECTOR OS RUN view (pulse + rail + workflow cards + stream + drawer).

---

## Document map (read in this order)

| Doc | Role |
|-----|------|
| **[UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md)** | Global shell — vibe, anatomy, four modes, Pulse Bar, drawer |
| **[UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md)** | **Phase E** — Charter Studio, Talk, RUN/WATCH, TT/WC |
| **[BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md)** | Hardcoded/incomplete IIA backend (B1–B22) to finish with UI |
| **[UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md)** | Manifest-driven workflows — TT/WC/DG as institutions, not pages |
| **[UI_GREENFIELD_BUILD_PLAN.md](UI_GREENFIELD_BUILD_PLAN.md)** | **Delete → 38 primitives → 11 cards → 16 overlays → 10 surfaces** — execution order |
| **[UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md)** | **Cards, bars, toasts, palette, popups** — universal `Op*` library |
| **[platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md)** | **Leptos/WASM only** — build pipeline, loader patches, do-not-break rules |
| **[UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md)** | **Export, audit, forensics, perform** — capability registry + evidence objects |
| **[UI_CONNECTOR_EDGE_PLANE.md](UI_CONNECTOR_EDGE_PLANE.md)** | **Edge routing plane** — DNS-like records, proxies, gateway, WF/agent binds |
| **[UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md)** | Data contracts — APIs per object/drawer topic |
| **[BACKEND_UNIVERSAL_CHECKLIST.md](BACKEND_UNIVERSAL_CHECKLIST.md)** | **Backend first** — registries, merge APIs, B-EXIT gate before UI code |
| **This file** | Phases, checklist, disposition, file targets |

**Related product docs:** [FINAL_OUTCOME.md](FINAL_OUTCOME.md) · [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) §1.6 · [IMP_1000.md](IMP_1000.md)

---

## 1. Architecture (three layers)

```text
┌─────────────────────────────────────────────────────────────┐
│ L1  OPERATOR SHELL + UOCS (fixed Rust/Leptos — ships once)   │
│     OpPulseBar · OpModeRail · OpCard · OpPalette · OpDrawer  │
│     RUN · WATCH · FIX · SETUP                                │
└──────────────────────────┬──────────────────────────────────┘
                           │ reads
┌──────────────────────────▼──────────────────────────────────┐
│ L2  OPERATOR SURFACE MANIFEST (per workflow — JSON data)      │
│     operator_surface.v1 — signals · actions · panels · fix    │
│     institutions[] · console_links[] (TT/WC/DG)               │
└──────────────────────────┬──────────────────────────────────┘
                           │ calls
┌──────────────────────────▼──────────────────────────────────┐
│ L3  EXISTING APIs (no UI forks)                             │
│     /workflows/* · /plugins/status · /actionlog/* · /books  │
└─────────────────────────────────────────────────────────────┘
```

**Laws:**
1. Shell code never branches on `workflow_id` or plugin name.
2. Institutions register **capabilities** (export, perform, forensics) — UI renders the intersection. See [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md).
3. Institutions are **chips + SETUP install + capability menus**, not sidebar products.
4. Old routes remain as **deep links into shell state** (redirects), not separate products.
5. Unknown data → `—` (H1–H10).
6. **Leptos/WASM only** — no parallel JS SPA; preserve WASM loader pipeline. See [platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md).

---

## 2. What the operator sees (not a page list)

### 2.1 Shell (replaces sidebar IA)

```text
PULSE BAR (always)
  ● N running   ⚠ N needs you   ○ N idle   │ node name ● health   ⌘K

MODE RAIL (4 icons)
  ▶ RUN      workflow cards — default landing
  ◎ WATCH    unified event stream
  ⚠ FIX      inbox — badge only when queue > 0
  ⚙ SETUP    install institutions + node config

DRAWER (right, on demand)
  workflow · agent · event · issue · receipt · memory · cost · trust
```

**No:** Home page, More menu, 6-item sidebar, per-workflow pages, per-plugin nav items.

### 2.2 RUN mode = universal workflow cards

Every workflow (CLS, template, catalog drop, custom) renders from **`GET /workflows/:id/surface`**:

```text
┌─────────────────────────────┐
│ HITL Approve and Audit      │
│ Capture → seal → human gate │
│ [TT●] [WC●]  last run: 2m   │
│ [ Dry-run ]                 │
└─────────────────────────────┘
```

Drawer: manifest `panels[]` + `actions[]` + optional T1 `console_links` (TraceTramp console →).

Details: [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md)

### 2.3 Institutions (TT · WC · DG) — different backends, same UI verbs

| Institution | Archetype | Has export PDF? | Primary universal verb |
|-------------|-----------|-----------------|------------------------|
| **WitnessCtl** | witness | yes — session dossier, DI audit | **export**, prove, custody |
| **TraceTramp** | enforcer | yes — compliance CSV/PDF | **export**, trace, approve |
| **DevGuard** | actor | **no** | **act** (connect, scan) |

Same components: `OpExportMenu`, `OpActionButton`, `OpForensicsPanel` — **visibility from capability registry**, not per-plugin pages.

Full model: [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md)

| Role | UI placement |
|------|----------------|
| **Install** | SETUP mode — setup wizards (keep existing) |
| **Health** | Chips on workflow cards — `GET /plugins/status` |
| **Power console** | T1 — drawer footer link or ⌘K; **not** daily nav |
| **FIX items** | Universal issue cards (approvals, denials) — same renderer |

### 2.4 Drawer topics (old “pages” become objects)

Reach via ⌘K **GO** or FIX/RUN context — **not** sidebar:

| Topic | Opens from | Primary APIs |
|-------|------------|--------------|
| Memory | ⌘K, agent drawer | `/memory/*` |
| Trust / exports | ⌘K, FIX item | `/monitor/trust`, `/reports/center`, `/proof/*` |
| Cost & usage | ⌘K, Pulse lazy | `/books/costs`, `/billing/usage`, `/substrate/usage` |
| Safety | ⌘K, FIX item | `/safety/*`, **`/firewall/standard`**, **`/firewall/status`** |
| Agents | RUN strip, WATCH row | `/agents/*`, **`/agents/progeny/tree`**, **`/agents/:pid/progeny`** |
| Agent tree | agent drawer, ⌘K GO | **`GET /agents/progeny/tree`** — kernel `parent_pid`/`child_pids` SoT |
| Conductor | workflow drawer, SETUP | **`/multiagent/intelligence/standard`**, pipeline `intelligence_chain[]` |
| Substrate | developer drawer | **`/substrate/status`**, **`/substrate/admission/matrix`**, **`/forensics/status`** |
| Monitor detail | WATCH strip | `/monitor/health`, `/monitor/anomalies` |

Full data map: [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md)

---

## 3. Design principles

| # | Principle |
|---|-----------|
| P1 | **Four verbs** — RUN · WATCH · FIX · SETUP |
| P2 | **Pulse Bar is home** — 2-second glance; no Overview page |
| P3 | **One renderer, infinite workflows** — `operator_surface.v1` |
| P4 | **Canvas + drawer** — no full-page hops for detail |
| P5 | **⌘K does work** — run, dry-run, approve, export |
| P6 | **Institutions ≠ nav items** — TT/WC/DG are dependencies |
| P7 | **Truthful UI** — H1–H10 (§7) |
| P8 | **T0 default, T1 optional** — 90% never open plugin consoles |
| P9 | **Same shell** — playground, self-host, prod |
| P10 | **Custom WF = manifest + CCL** — zero UI PR |

---

## 4. Route disposition

### 4.1 Shell modes (new primary UX)

| Mode | Absorbs (conceptually) | Default route |
|------|------------------------|---------------|
| **RUN** | `/workflows`, `/`, workflow templates | `/run` or `/workflows` → shell RUN |
| **WATCH** | `/activity`, `/actionlog`, `/history` | `/watch` |
| **FIX** | denied queue, approvals, report-ready | `/fix` |
| **SETUP** | `/apps`, `/settings`, install wizards, **Edge plane** | `/setup` |

### 4.2 REMOVE from nav (redirect 90 days)

| Route | Redirect |
|-------|----------|
| `/insights` | RUN (pulse) |
| `/economy` | hidden |
| `/marketplace` | SETUP |
| `/topology-center` | drawer topic or advanced |
| `/multiagent` | SETUP → **Conductor drawer** (mesh grants + pipeline intelligence); not daily nav |
| `/verify`, `/grounding`, `/firewall`, `/disputes` | drawer Safety topic |
| `/report-center` | drawer Trust topic |
| `/orchestrator` | drawer Infra topic |
| `/pipeline` | workflow drawer Integrity panel |
| `/context` | agent drawer |
| `/cls-catalog`, `/cls-builder`, `/cls-packages`, `/cls-execution/*` | RUN drawer / SETUP author |
| `/plugins`, `/plugins/marketplace` | SETUP |
| stub “coming soon” landings | hide |

### 4.3 KEEP as routes (deep links → shell + drawer)

| Route | Shell behavior |
|-------|----------------|
| `/workflows/:id` | RUN + drawer |
| `/agents/:pid` | RUN strip or drawer |
| `/plugins/tracetramp`, `/witnessctl`, `/devguard` | T1 consoles (SETUP/drawer link) |
| `/books`, `/trust`, `/memory`, `/safety`, `/monitor` | ⌘K GO → drawer topic |
| `/billing`, `/license`, `/secrets`, `/webhooks` | SETUP sections |
| `/debug`, `/tools`, `/protocols`, `/infra`, `/service-map` | Advanced / developer view |

---

## 5. Backend contracts to add

| Endpoint | Phase | Purpose | Backend status |
|----------|-------|---------|----------------|
| `GET /workflows/:id/surface` | W2 | Merged `operator_surface.v1` | ☑ shipped |
| `GET /workflows/surfaces` | W2 | Batch for RUN list | partial — use per-id or batch when added |
| `PUT /workflows/:id/surface` | W2 | Admin attach manifest | ☑ shipped |
| `*.operator.json` catalog ingest | W1 | Extend `workflow_catalog_sync` | ☑ shipped |
| `GET /operator/watch/events` | S3+ | Unified WATCH stream | ☑ shipped (client may still merge) |
| `GET /operator/fix/queue` | S4+ | Unified FIX inbox | ☑ shipped |
| `GET /operator/pulse` | S0 | Pulse Bar aggregate | ☑ shipped |
| `GET /operator/capabilities` | K2 | Institution capability registry | ☑ shipped |
| `GET /workflows/:id/capabilities` | K2 | Resolved caps for workflow + run context | check router — may need wiring |
| `GET /operator/edge/plane` | E0 | Merged edge records + health + DNS hints | ☑ shipped |
| `POST /operator/edge/records` | E2 | Unified edge write | ☑ shipped |
| **`GET /agents/progeny/tree`** | D1 | Kernel progeny forest for agent drawer | ☑ shipped |
| **`GET /agents/lifecycle/standard`** | D1 | Lifecycle contract (kernel SoT) | ☑ shipped |
| **`GET /firewall/standard`** | D2 | Graph firewall + breaker contract | ☑ shipped |
| **`GET /multiagent/intelligence/standard`** | W4 | Orchestration intelligence contract | ☑ shipped |

Schema: [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) §4.2 · Capabilities: [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md)

---

## 6. Unified execution phases

Execute in order. **Do not skip shell (S) for page polish (U).**

### Track A — Honesty (parallel, 1–2 days)

| ID | Task | Verify |
|----|------|--------|
| **U0** | `fmt_unknown`, `VerifiedBadge` shared components | grep no `$0.00` on primary path |
| **U0** | Kill 100% default, fake verified, `agent-1` | Insights hidden |
| **U0** | Fix dead links `/cost` → drawer cost, `/policies` → memory | CI link check |

### Track B — Universal Workflow Surface (server + renderer)

| ID | Task | Verify |
|----|------|--------|
| **W0** | `operator_surface.v1` schema + default synthesizer | workflow with no manifest still renders |
| **W1** | Catalog ingest `*.operator.json` / extend `.workflow.json` | drop file → surface stored |
| **W2** | `GET /workflows/:id/surface`, optional batch | merge template plugins → institutions |
| **W3** | Universal RUN **card** renderer (signals, chips, primary action) | 3 reference templates on cards |
| **W4** | Universal **drawer** panel renderer (kv, summary, chips, event_list, table) | dry-run summary human-first |
| **W5** | Ship manifests for HITL, PII, incident templates | TT/WC/DG chips without bespoke code |
| **W6** | FIX queue reads manifest `fix_rules` | blocked WF → FIX card |
| **W7** | Demote TT/WC/DG from sidebar → SETUP + `console_links` | daily path never requires T1 |
| **W8** | `connectorctl workflow lint-surface` | CI validates manifests |

### Track C — Operator Shell (chrome + modes)

| ID | Task | Verify |
|----|------|--------|
| **S0** | Pulse Bar — running / needs-you / idle / health | 2-second test |
| **S1** | Mode rail RUN · WATCH · FIX · SETUP + route mapping | old URLs redirect |
| **S2** | RUN canvas hosts W3 card grid (not legacy table) | install + dry-run from RUN |
| **S3** | WATCH unified stream (merge actionlog + health ticks) | no Activity tabs default |
| **S4** | FIX queue + badge on rail (hidden when empty) | inbox zero UX |
| **S5** | Command palette actions (run, dry-run, approve, GO topics) | ⌘K runs workflow |
| **S6** | SETUP calm layout (institutions + node settings) | TT install < 3 clicks |
| **S7** | Context drawer framework (object types) | click card → drawer, no route hop |
| **S8** | Visual language pass — no tables/JSON on RUN first paint | napkin explainable |

### Track D — Drawer topics & legacy retirement

| ID | Task | Verify |
|----|------|--------|
| **D1** | Memory · Trust · Cost · Safety as drawer topics | ⌘K GO works |
| **D2** | Merge Safety hubs (firewall, formal, grounding, disputes) | one drawer topic |
| **D3** | Merge Trust exports (report-center, compliance entry) | H3 badges |
| **D4** | Cost drawer — usage meters first | Billing = invoices only |
| **D5** | Retire legacy nav registry entries | no More menu |
| **D6** | Grade C drawer panels when APIs exist (Moments, UsageEvent, CFNI) | no premature “shipped” |

### Track E — Universal components (UOCS)

| ID | Task | Verify |
|----|------|--------|
| **C0** | `OpPulseBar`, `OpAlertBar`, `OpHealthDot` | 2-second pulse test |
| **C1** | `OpCard` base + workflow/issue/event variants | manifest drives layout |
| **C2** | `OpSignal`, `OpInstitutionChip` | TT/WC/DG chips on cards |
| **C3** | `OpEventRow` virtualized WATCH stream | smooth 1k+ events |
| **C4** | `OpDrawer` + panel renderer (`kv`, summary, table, …) | no JSON on first paint |
| **C5** | `OpResultSheet`, `OpConfirm` | dry-run human summary popup |
| **C6** | `OpPalette` 2.0 — execute actions, not just navigate | ⌘K dry-run works |
| **N1** | `OpNotifyCenter` + bell + `OpNotifyCard` | layered notifications |
| **N2** | Manifest `notifications[]` → toast/center | WF-driven alerts |
| **C7** | Visual tokens + reduced motion pass | modern control-plane feel |

Detail: [UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md)

### Track F — Capabilities, evidence & forensics

| ID | Task | Verify |
|----|------|--------|
| **K0** | `institution_capability.v1` schema | types + doc |
| **K1** | WC, TT, DG register real capabilities (export vs perform) | registry truthful |
| **K2** | `GET /operator/capabilities`, `/workflows/:id/capabilities` | bind context |
| **K3** | `OpArtifact` + `OpArtifactCard` + `OpArtifactList` | PDF = one artifact kind |
| **K4** | `OpExportMenu` — capability-gated | no PDF on DG-only WF |
| **K5** | `OpActionButton` for `perform` (DevGuard connect) | actor archetype |
| **K6** | `OpForensicsPanel` — custody, trace, proof sections | HITL vs PII templates |
| **K7** | Manifest `evidence[]`, `perform[]`, `forensics[]` on surface | custom WF composes |
| **K8** | Drawer templates by archetype mix | same components, different order |
| **K9** | Palette export/audit commands | executes capability |
| **K10** | Hide missing caps — no grey fake exports | honesty |

Detail: [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md)

### Track G — Connector Edge Plane (CEP)

| ID | Task | Verify |
|----|------|--------|
| **E0** | `edge_record.v1` schema + `GET /operator/edge/plane` merge | one read API |
| **E1** | SETUP Edge table — `OpEdgeRecordRow`, DNS hints, prove | TT+WC hosts in one table |
| **E2** | Write records → custom_domains + bindings | guided form not JSON |
| **E3** | Workflow/agent edge tab in drawer | bind filter works |
| **E4** | TLS/DNS automation (optional) | ACME or CF worker |
| **E5** | CFNI `require_cfni` on edge policies | fail-closed transit |

Detail: [UI_CONNECTOR_EDGE_PLANE.md](UI_CONNECTOR_EDGE_PLANE.md)

### Recommended order

```text
U0 ──┬──► W0 → W1 → W2 → W3 → W4 → W5
     │
     ├──► C0 → C1 → C2 (with W3/W5)
     │
     └──► S0 → S1 → S2 (uses W3+C1) → S3 (C3) → S4 (C1 issue) → S5 (C6) → S6 → S7 (C4) → S8 (C7)
                    │
                    └──► W6 → W7 → W8
                              │
                              └──► N1 → N2 → D1 → D2 → D3 → D4 → D5 → D6
```

**Backend gate:** [BACKEND_TOP_GRADE_TRACK.md](BACKEND_TOP_GRADE_TRACK.md) T0–T5 ☑ — **shell UI coding may proceed** (operator registries + substrate primitives shipped). Remaining backend gaps (adversarial CI green, plugin handoff) do not block shell S0–S4.

**First code milestone:** UI `U0` + `C0` + `S0` (Pulse uses `GET /operator/pulse`), then `S2` + `W3` card renderer.

---

## 12. Backend substrate → UI mapping (v3.1 rethink)

The backend is no longer “APIs waiting for UI.” Three **kernel-level primitives** must appear in the shell **without new pages**:

### 12.1 Agent progeny (lifecycle SoT)

| Backend | UI surface | Rule |
|---------|------------|------|
| `GET /agents/progeny/tree` | Agent drawer — **tree view** (not flat table) | Parent/child from kernel ACB only |
| `GET /agents/:pid/progeny` | Agent drawer header — depth, children count | Terminate shows **cascade warning** |
| `POST /agents` + `parent_pid` | Create/clone flows | Optional parent picker from live tree |
| `DELETE /agents/:pid` → `terminated_subtree` | Confirm dialog | List affected descendants |
| `GET /agents/lifecycle/standard` | Developer panel only | Documents `not_this` — no fake registry |

**Do not:** Render `agent_lifecycle::AgentRegistry` or engine_store-only parent links. **Do not:** Flat `/agents` list as primary — RUN/WATCH show rows; detail is tree.

### 12.2 Graph firewall (top enforcement layer)

| Backend | UI surface | Rule |
|---------|------------|------|
| `GET /firewall/standard` | Safety drawer — contract blurb | Relation graph + breaker semantics |
| `GET /firewall/status` | Safety drawer — fleet summary | Tripped breakers, rule counts |
| `GET /firewall/status/:pid` | Agent drawer — **Enforcement** panel | Per-agent graph + breaker state |
| `POST /firewall/rules` | Safety drawer — admin only | Dynamic rule write |
| Admission denials (Step 1.6) | WATCH + FIX | Link deny row → agent enforcement panel |
| Legacy `/firewall/baselines` | Developer ▾ tab only | Subordinate to graph firewall |

**Do not:** “No threats” on empty baselines. **Do not:** Separate `/firewall` nav page — Safety drawer topic only.

### 12.3 Orchestration intelligence (control plane vs leaves)

| Backend | UI surface | Rule |
|---------|------------|------|
| `GET /multiagent/intelligence/standard` | Conductor drawer + developer | k8s-analog: control plane schedules waves |
| Pipeline run `intelligence_chain[]` | Workflow drawer — **Run detail** | Wave index, merge strategy, fingerprints |
| `orchestration_waves[]` in pipeline result | Same panel | Parallel vs single wave — human labels |
| `POST /multiagent/pipeline/run` | RUN card dry-run / run | Not a standalone `/multiagent` product |
| `/infra/orchestrator` | Infra drawer | DAG planner only — **not** LLM execution |

**Do not:** JSON dump page (`pages/multiagent.rs` today). **Do not:** Claim orchestrator runs agents — pipeline does.

### 12.4 Operator aggregates (shell feeds)

| API | Shell consumer |
|-----|----------------|
| `GET /operator/pulse` | OpPulseBar — running / needs-you / idle / health |
| `GET /operator/fix/queue` | FIX mode + rail badge |
| `GET /operator/watch/events` | WATCH stream (or merge with actionlog client-side) |
| `GET /substrate/status` | SETUP → Substrate health strip (developer) |
| `GET /forensics/status` | Trust drawer — forensic readiness |

### 12.5 What changes in execution order

```text
OLD: Wait B-EXIT → build shell
NEW: S0 (pulse) + C0 + U0 in parallel with W3 (cards) — substrate drawers D1–D2 early

Priority shift:
  1. Pulse + four modes (S0–S1)
  2. RUN cards from /workflows/:id/surface (W3)
  3. Agent drawer with progeny tree (D1) — replaces flat agents page IA
  4. Safety drawer with graph firewall (D2) — merge old firewall tabs
  5. Workflow run panel with intelligence_chain (W4 extension)
  6. Retire multiagent.rs JSON page → Conductor drawer
```

---

## 7. Honesty rules (H1–H10)

| Rule | Implementation |
|------|----------------|
| **H1** | Unknown → `—`, never `$0.00` |
| **H2** | Empty → “No data yet”, never `100%` healthy |
| **H3** | Verified only after verify API |
| **H4** | Live agent picker — no `agent-1` |
| **H5** | Usage meters primary; USD labeled estimated |
| **H6** | No “coming soon” primary CTA |
| **H7** | stub_mode labeled **Lab** |
| **H8** | Labels match content |
| **H9** | No dead routes |
| **H10** | JSON/API paths — developer drawer only |

---

## 8. Master checklist

| # | Item | Phase |
|---|------|-------|
| 1 | Universal Operator Shell doc agreed | ✓ |
| 2 | Universal Workflow Surface doc agreed | ✓ |
| 3 | Pulse Bar live + honest | S0 |
| 4 | Four modes replace sidebar IA | S1 |
| 5 | `operator_surface.v1` on server | W0–W2 |
| 6 | Universal card + drawer renderer | W3–W4, S2, S7 |
| 7 | TT/WC/DG as institution chips, not nav | W5, W7 |
| 8 | FIX queue + hidden when empty | S4, W6 |
| 9 | WATCH single stream | S3 |
| 10 | ⌘K executes actions | S5 |
| 11 | Custom WF without UI PR | W1, W8 |
| 12 | H1–H10 on RUN/WATCH/FIX first paint | U0, S8 |
| 13 | Legacy routes redirect | S1, D5 |
| 14 | T1 consoles reachable, not required | W7 |
| 15 | Playground inherits same shell | S9 |
| 16 | Story QA: run WF in 30s, no CLS training | S2+W3 |
| 17 | Workflow #500 test (manifest only) | W8 |
| 18 | CHAOS checklist UI items mapped | D6 |
| 19 | UOCS `Op*` library — cards, palette, notifications | C0–C7, N1–N2 |
| 20 | Custom WF uses OpCard + manifest only | C1, W8 |
| 21 | Capability registry — export/audit/forensics/perform | K0–K10 |
| 22 | DG perform vs WC export — same UI, different caps | K4, K5 |
| 23 | Edge plane — one record table for TT/WC/DG/gateway/WF | E0–E3 |
| 24 | Kernel progeny tree in agent drawer (not flat fleet) | D1, §12.1 |
| 25 | Graph firewall in Safety drawer (not legacy baselines page) | D2, §12.2 |
| 26 | Pipeline `intelligence_chain` in workflow run drawer | W4, §12.3 |
| 27 | Retire `multiagent.rs` JSON dump → Conductor drawer | §12.3, §4.2 |
| 28 | Leptos/WASM pipeline unchanged — shell in Rust only | §9.1, UI_LEPTOS_WASM_STACK |

---

## 9. File targets

| Area | Files |
|------|--------|
| **Shell** | new `components/operator/` — `pulse_bar.rs`, `mode_rail.rs`, `op_card.rs`, `drawer.rs`, `palette.rs` |
| **UOCS** | `operator/op_signal.rs`, `institution_chip.rs`, `event_row.rs`, `notify_center.rs`, `result_sheet.rs` |
| **Layout** | `components/ui/app_shell.rs`, `components/layout.rs` |
| **RUN renderer** | new `components/workflow_card.rs`, `surface_drawer.rs`, `panel_renderer.rs` |
| **Workflows page** | `pages/workflows.rs` → thin wrapper over RUN canvas or replace |
| **WATCH** | refactor `pages/actionlog.rs` → stream component |
| **SETUP** | `pages/apps.rs`, `pages/settings.rs` |
| **Server surface** | `platform/server/src/services/workflow_runtime.rs`, `workflow_catalog_sync.rs` |
| **Routes** | `routes.rs`, `lib.rs`, `routing/authenticated.rs` |
| **Honesty** | `components/honesty.rs` or `utils/fmt.rs` |
| **Palette** | search modal → action executor |
| **Manifests** | `platform/server/resources/workflow_templates/*.operator.json` |
| **Agents drawer** | `components/operator/agent_tree.rs`, `progeny_panel.rs` — `GET /agents/progeny/tree` |
| **Safety drawer** | `components/operator/graph_firewall_panel.rs` — `/firewall/status` |
| **Conductor drawer** | replace `pages/multiagent.rs` with drawer topic — intelligence standard + mesh grants |
| **WASM / build** | [platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md) — Leptos only; preserve `patch_wasm_init.py` |

---

## 9.1 Tech stack guardrails (Leptos / WASM)

All shell work ships in **`platform/ui-leptos/dashboard`** (Rust → WASM). Do not introduce a parallel JavaScript SPA.

| Do | Don't |
|----|-------|
| Add `Op*` components as `.rs` + Tailwind | React/Vue/Svelte or Vite for operator UI |
| `make dev-dashboard` / `build-playground` | Hand-edit `dist/` or skip `patch_wasm_init.py` |
| Keep `hydrate()` async (`spawn_local` in `lib.rs`) | Heavy sync work in `#[wasm_bindgen(start)]` |
| `#[lazy_route]` for heavy new pages | Unbounded growth of initial wasm chunk |
| Rebuild `dist/` before `connector-platform` embed | Assume `cargo build` alone refreshes UI |

**Canonical:** [platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md) — boot splash, split loader, cache bust, wasm-opt off, `CONNECTOR_UI_DIR`.

---

## 10. Success criteria (v3)

1. **2-second test:** Pulse shows running, needs-you, health — no click.
2. **30-second test:** New operator installs starter workflow and dry-runs — never hears “CLS.”
3. **Universal test:** Add workflow via catalog manifest only — card appears, **no UI commit**.
4. **Institution test:** HITL card shows TT+WC chips; daily path never opens T1 consoles.
5. **FIX test:** Badge hidden when queue empty; amber card when blocked.
6. **Napkin test:** “RUN · WATCH · FIX · SETUP — workflows are cards, everything else is drawer or ⌘K.”
7. **Honesty test:** No fake `$0`, `100%`, or Verified on RUN/WATCH/FIX.
8. **Scale test:** Workflow #500 uses same panel types as workflow #1.
9. **Substrate test:** Terminate parent agent shows cascade children from kernel tree; graph firewall deny in WATCH links to agent enforcement panel.

---

## 11. What we are NOT building

- Smaller dashboard with 15 sidebar items  
- New page per workflow or per plugin  
- Home + Workflows + Activity as three products  
- TraceTramp / WitnessCtl / DevGuard as daily nav siblings  
- Tab sprawl inside RUN (templates/author → SETUP drawer or ⌘K)  
- UI that requires updating when a custom workflow ships  
- **Parallel lifecycle registries** — kernel progeny is the only agent tree  
- **Standalone Multiagent / Firewall / Orchestrator pages** — drawer topics only  
- **JavaScript/React operator frontend** — Leptos/WASM only; see [UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md)

---

*v3.1 adds §12 substrate alignment on top of v3. Execute: U0 + C0 + S0 first, then W3 + agent progeny drawer (D1). Detail: [UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md) · [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) · [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md).*
