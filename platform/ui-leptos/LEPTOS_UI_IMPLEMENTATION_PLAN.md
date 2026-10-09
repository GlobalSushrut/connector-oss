# Leptos Dashboard UI — Implementation Plan

Companion to `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` (the diagnostic).
This document is the **execution plan**: phases, dependencies, PR
groupings, server endpoints, build changes, acceptance gates.

If you are about to write code, read this. If you want to know *why*, read
the audit.

---

## 0. Headline

| | |
|---|---|
| Total in-scope rows | **~68** (P0: 17, P1: 27, P2: 24, drawn from `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §10 + §10b + §10c) |
| Phases | **8** (Phase 0 — Phase 7) |
| Estimated effort | 4–6 weeks · 1 engineer; 2–3 weeks · 2 engineers in parallel after Phase 1 |
| New top-level dashboard files | ~22 |
| Changed dashboard files | ~30 |
| New server endpoints | **7** (see §10) |
| Build outputs | Goes from **1** Leptos build → **2** (`--features=playground` and `--features=self-deploy`) |
| Routes net change | **+5** new routes (`/setup`, `/install`, `/activity`, plus 6 plugin stubs minus the 4 CLS pages folded into Workflows hub) |

### Phase summary

```
Phase 0 — Stop the bleeding              1–2 d   no deps        ship visible bug fixes
Phase 1 — Foundation primitives          3–5 d   needs Phase 0  shared signals + components
Phase 2 — IA / sidebar rewrite           5–7 d   needs Phase 1  47-page sidebar → 4 sections
Phase 3 — Products as headlines          4–6 d   needs Phase 1  9 plugins + 3 reference wf
Phase 4 — Onboarding wizards             5–7 d   needs Phase 1  wizard system + 8 wizards
Phase 5 — Dual-distribution UX           4–6 d   needs Phase 1+3 Playground vs self-deploy split
Phase 6 — Overview & tab density         6–8 d   needs Phase 1+2 page-level simplification
Phase 7 — Polish, a11y, mobile, telemetry 4–6 d  any time        cleanup pass
```

### Critical path

```
Phase 0 ─▶ Phase 1 ─▶ Phase 2 ─▶ Phase 6
                  ├─▶ Phase 3 ─▶ Phase 5
                  ├─▶ Phase 4
                  └─▶ Phase 7  (any time)
```

Phase 1 is the single chokepoint. After it merges, Phases 2, 3, 4, 5 can
run in parallel on separate branches; Phase 6 needs Phase 2's header
slimming done first; Phase 7 is opportunistic.

### Suggested branch / PR strategy

- One long-lived branch per phase: `feat/ui-phase-{N}-{slug}`.
- Each phase ships as **3–8 smaller PRs** into its phase branch (one per
  logical unit). When the phase is acceptance-gate-green, the phase
  branch merges to `main`.
- Phase branches rebase on `main` weekly; conflicts within
  `dashboard/src/components/layout.rs` are inevitable across phases —
  Phase 2 owns the canonical version of that file during its window.

---

## 1. Phase 0 — Stop the bleeding (1–2 days)

**Goal:** Land the visible bugs the operator explicitly called out in 24
hours. Get rid of the awkward header, kill the dev-bypass footgun, remove
"Phase 3.11" leakage. No new architecture, just deletions + small
patches.

**Rows included:** P0-1, P0-2, P0-3, P0-4, P0-5, P0-6, P0-11.

**Dependencies:** none.

### 1.1 PRs

| # | PR title | Rows | Files |
|---|---|---|---|
| 0.1 | `ui(header): replace inline StatusBanner with compact Live pill; make first-fetch neutral` | P0-1 | `components/layout.rs`, `components/status_banner.rs`, new `components/live_dot_pill.rs`, new `components/system_health_card.rs` |
| 0.2 | `ui(security): gate dev-bypass behind build flag; remove data-dev=1 from index.html` | P0-2 | `index.html`, `pages/login.rs`, `main.rs`, `Trunk.toml` |
| 0.3 | `ui(header): wire Sign-Out menu item; remove dead handler` | P0-3 | `components/layout.rs` L1179–1182 |
| 0.4 | `ui(overview): remove fake 100% progress bars in System Resources` | P0-4 | `pages/overview.rs` L645–675 |
| 0.5 | `ui(sidebar): drop hard-coded /cls-execution/pkg-basic-tool-agent sample id` | P0-5 | `components/layout.rs` L53 |
| 0.6 | `ui(copy): strip raw API paths from primary copy on Memory / Overview / OperatorShell / Notifications popup` | P0-6 | `pages/overview.rs`, `pages/memory.rs` L55–68, `pages/operator_shell.rs` L29–36, `components/layout.rs` notifications popup |
| 0.7 | `ui(copy): strip "Phase 3.11" / "Phase 3 control plane" labels from workflow surfaces` | P0-11 | `pages/workflows.rs`, `pages/cls_catalog.rs`, `pages/cls_packages.rs` |

### 1.2 New files in Phase 0

```
platform/ui-leptos/dashboard/src/components/live_dot_pill.rs
platform/ui-leptos/dashboard/src/components/system_health_card.rs
```

### 1.3 Acceptance gate

- Header is 56 px on first paint, never wraps, never flashes red during
  cold-fetch.
- `index.html` ships with no `data-dev` attribute. Dev-bypass only
  appears when `cargo build --features=dev-bypass` is used.
- Sign-Out from header dropdown logs the user out.
- "Phase 3.11" appears in zero operator-facing copy (`rg -i "Phase 3"
  platform/ui-leptos/dashboard/src/pages/` returns nothing).
- No raw `/api/v1/` path is rendered as `<p>` body text on Overview,
  Memory, OperatorShell, or the notifications popup.

### 1.4 Manual verification script

```bash
# 1. Visual sanity
cd platform/ui-leptos/dashboard && trunk serve --release
# Open http://localhost:8080, confirm:
#   - header bar height stable across loads
#   - no red "UNAVAILABLE" flash
#   - no "Phase 3" or "Phase 3.11" strings anywhere
#   - profile dropdown → Sign Out logs out

# 2. Security check
rg "data-dev" platform/ui-leptos/dashboard/    # must return nothing in committed files
rg "dev_bypass|Dev Bypass" platform/ui-leptos/dashboard/src/pages/login.rs
#   must be gated by #[cfg(feature="dev-bypass")] or equivalent runtime guard

# 3. Copy hygiene
rg "/api/v1/" platform/ui-leptos/dashboard/src/pages/ | rg -v "title=|tooltip=|comment|//"
#   should be empty
```

---

## 2. Phase 1 — Foundation primitives (3–5 days)

**Goal:** Land the shared signals, components, and build infrastructure
that every later phase consumes. This is the single chokepoint — most of
the rest of the work parallelises after this.

**Rows included:** P0-12, P1-8, P1-18, plus three new shared primitives
not previously enumerated (empty-state, route registry, request store).

**Dependencies:** Phase 0 merged.

### 2.1 Components & signals to land

| Module | Purpose | Consumed by |
|---|---|---|
| `dashboard/src/deployment.rs` | `DeploymentMode { Playground, SelfHosted }`, `DeploymentInfo` struct, signal + provider. Fetches `GET /api/v1/deployment/info` once on `App` mount + every 60 s. | Phases 2, 3, 4, 5 (every mode-gated branch) |
| `dashboard/src/routes.rs` | Central route registry — single `Vec<RouteDescriptor>` consumed by `main.rs` Routes block, sidebar nav, and SearchModal. End of hard-coded item drift. | Phase 2 (sidebar + search) |
| `dashboard/src/components/wizard.rs` | `Wizard` component + `WizardStep` primitive. localStorage-resumable. | Phase 4 (all wizards) |
| `dashboard/src/components/empty_state.rs` | One opinionated empty-state pattern: icon + headline + sub + primary action. | Phases 3, 6, 7 |
| `dashboard/src/components/page_title.rs` | Sets `document.title = "{title} · Connector"` on mount. | Every page touched in any phase |
| `dashboard/src/request_store.rs` (refactor of existing fetches) | Single LocalResource per shared endpoint (`/monitor/health`, `/notifications`, `/agents`) keyed by an explicit reload signal — removes the "read `pathname.get()` to force refetch" hack. | Phase 0 already removed half; Phase 1 finishes the centralisation |

### 2.2 Server endpoints introduced

```
GET  /api/v1/deployment/info
```

Response shape:

```json
{
  "mode": "playground" | "self_hosted",
  "edition": "community" | "enterprise" | "playground",
  "public_url": "https://try.cnktros.com",
  "version": "0.5.2",
  "session_expires_at": "2026-05-25T10:30:00Z",   // playground only
  "license_tier": "enterprise",                    // self-hosted only
  "license_status": "active",                      // self-hosted only
  "feature_flags": { "wizards_enabled": true, "playground_telemetry": true }
}
```

Mapped from `CONNECTOR_PRESET` server-side (already set by both Compose
files).

### 2.3 Build infrastructure (P1-18)

Two Leptos build profiles in `dashboard/Cargo.toml`:

```toml
[features]
default = ["self-deploy"]
self-deploy = []                  # strips playground-only code paths
playground = []                   # strips self-deploy-only code paths
dev-bypass = []                   # opt-in dev override (used by 0.2)
```

Two `Trunk.toml` configs (`Trunk.playground.toml`, default `Trunk.toml`
for self-deploy) writing to `dist/playground/` and `dist/self-deploy/`.

`platform/ui-leptos/Makefile` targets:

```make
build-self-deploy:
	cd dashboard && trunk build --release --features=self-deploy
build-playground:
	cd dashboard && TRUNK_CONFIG=Trunk.playground.toml trunk build --release --features=playground
build-all: build-self-deploy build-playground
```

CI: matrix on `{self-deploy, playground}` + lint pass on both. Add
`#[cfg_attr(not(feature = "playground"), allow(dead_code))]` lints to
catch divergence.

### 2.4 PRs

| # | PR title | Rows |
|---|---|---|
| 1.1 | `ui(deployment): add DeploymentMode signal, server endpoint, App-level provider` | P0-12 |
| 1.2 | `ui(build): split Leptos build into --features={playground,self-deploy} profiles` | P1-18 |
| 1.3 | `ui(routes): central route registry consumed by Router, sidebar, SearchModal` | (new) — unblocks P1-1, P1-6 |
| 1.4 | `ui(components): Wizard primitive + WizardStep + localStorage resume state` | P1-8 (foundation only — no wizards yet) |
| 1.5 | `ui(components): EmptyState component + PageTitle helper + request store refactor` | (new) — unblocks Phases 3, 6, 7 |

### 2.5 Acceptance gate

- `GET /api/v1/deployment/info` returns valid JSON in both Playground and
  Self-deploy modes. The dashboard reads it on boot and exposes
  `use_context::<DeploymentInfo>()`.
- `make -C platform/ui-leptos build-all` succeeds and produces **two**
  distinct `dist/` folders. Bundles differ in size (playground should be
  smaller because self-deploy-only code is stripped).
- A `<Wizard>` test page renders with 3 toy steps, navigates forward/
  back, persists step + form state to localStorage, and resumes on page
  reload.
- `<EmptyState>` is used by at least one page; every other page touched
  in later phases adopts it.
- Every page sets its `document.title` on mount (tabs in the browser
  show distinct titles).

---

## 3. Phase 2 — IA / sidebar rewrite (5–7 days)

**Goal:** Collapse the 47-page, 7-section sidebar into the 4-section
shape from `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §9.1. Wire mode-gating so
the sidebar adapts to Playground vs Self-deploy. Surface all 9 marketed
plugins. Replace the static SearchModal index with a generated one.

**Rows included:** P1-1, P1-2, P1-4, P1-6, P0-9, P0-15, P0-17, P1-16,
P1-17, P1-25, P2-18, P2-19.

**Dependencies:** Phase 1 (`deployment.rs`, `routes.rs`, route registry).

### 3.1 What gets done

1. Rewrite `components/layout.rs::nav_sections()` to read from
   `routes.rs::REGISTRY`. Group into 4 top-level sections (`Overview`,
   `Build`, `Trust`, `Settings`) + a `More…` expandable group.
2. Add 6 new sidebar entries (Conductor, AgentLoop, LedgerLens,
   AgentPassport, Relay, Engram) under Build → Apps. Disabled state for
   `enabled_in_deployment=false` (same UX as existing
   `SidebarPluginNavItem`).
3. Merge `Operations / Action Log + History` into a single `/activity`
   page (P1-1 implies, formalise here).
4. Delete `OperatorShell` page and its `/command-center` route; fold the
   worklist into `Overview` as a top section (P1-4).
5. Generate `SearchModal` items from the route registry + live agents +
   plugins + reference workflows (P1-6, P1-16). Bind global `⌘K`
   handler in `App` (P1-16).
6. Mode-gated sidebar (P0-15): Playground hides Billing/License/Settings
   → Custom Domains/Webhooks/Secrets. The mode-gating logic is one
   `filter()` over `REGISTRY`.
7. Mode-gated routes (P0-17): in Playground build,
   `/billing`/`/license`/`/secrets`/`/webhooks`/`/settings/custom-domains`
   render a single "Install on your own infra" card (this card is reused
   in Phase 5).
8. Edition pill in sidebar footer (P1-25): `Community v0.5.2 ·
   Enterprise v0.5.2 · Try Me · 47m left`.
9. Brand unification (P2-18): pick "Connector" everywhere customer-
   facing; update sidebar logo, page titles, Apps Hub intro.
10. Eliminate hardcoded `pkg-basic-tool-agent` from `workflows.rs` L152
    and `cls_packages.rs` L43 (P2-19); replace with "first installed
    package" lookup via the registry.
11. Single source for product catalog (P1-17): the 9 plugins live in
    `platform/products/catalog.json` (or `oss/connector/.../products.rs`)
    consumed by **both** the dashboard sidebar **and** the marketing
    site's `Nav.tsx`.

### 3.2 Server endpoints introduced

Optional but recommended:

```
GET  /api/v1/products            # serves products/catalog.json
```

Otherwise both consumers (`dashboard/src/routes.rs`,
`platform/docs/landing-page/web/src/components/Nav.tsx`) import the
checked-in JSON via build step.

### 3.3 PRs

| # | PR title | Rows |
|---|---|---|
| 2.1 | `ui(catalog): products/catalog.json + GET /products endpoint; consume from sidebar` | P1-17 |
| 2.2 | `ui(sidebar): 4-section IA with More… expandable group; consume route registry` | P1-1, P1-2 |
| 2.3 | `ui(sidebar): surface all 9 marketed plugins; disabled state by deployment` | P0-9 |
| 2.4 | `ui(sidebar): mode-gated visibility (Playground hides admin surfaces) + edition pill` | P0-15, P1-25 |
| 2.5 | `ui(activity): merge /actionlog + /history into /activity` | P1-1 partial |
| 2.6 | `ui(overview): fold /command-center worklist into Overview; delete OperatorShell` | P1-4 |
| 2.7 | `ui(search): generated SearchModal index + global ⌘K palette` | P1-6, P1-16 |
| 2.8 | `ui(routing): Playground hides /billing /license /secrets /webhooks /settings/custom-domains` | P0-17 |
| 2.9 | `ui(brand): "Connector" unified across logo, page titles, Apps Hub copy` | P2-18 |
| 2.10 | `ui(cls): remove hardcoded pkg-basic-tool-agent from workflows.rs + cls_packages.rs` | P2-19 |

### 3.4 Acceptance gate

- Sidebar renders **≤ 10 visible items** in 4 sections + "More…" expander.
- All 9 plugins appear (DG, TT, WC, Conductor, AgentLoop, LedgerLens,
  AgentPassport, Relay, Engram).
- `⌘K` opens a search modal whose results include current routes, the 3
  reference workflows, installed plugins, and live agents.
- In a Playground build, `/billing` renders the install card; in a
  Self-deploy build, it renders the real billing UI.
- Sidebar footer shows the edition pill matching the active build.
- `rg "pkg-basic-tool-agent" platform/ui-leptos/dashboard/src/` returns
  zero results.

---

## 4. Phase 3 — Products as headlines (4–6 days)

**Goal:** Lead the Apps experience with the pre-built workflows + 9
plugins. Replace the developer-jargon empty states. Stub the 6 currently-
invisible plugin pages so the marketed product line is whole.

**Rows included:** P0-7, P0-8, P0-10, P1-13, P1-14.

**Dependencies:** Phase 1 (EmptyState, routes registry).

### 4.1 What gets done

1. Rewrite `pages/apps.rs` to the §13.4-A layout: **Featured · Pre-built
   Workflows · All Plugins (9) · Example Integrations · Custom**.
2. Implement `install_reference_workflow(id)` — one-click POST
   `/workflows` with the shipped CCL source (no Builder hop). Wire to
   the `[ Install ]` button on each template card. Server endpoint may
   already exist as `POST /workflows`; if not, lightweight wrapper at
   `POST /workflows/reference/{id}/install` is acceptable.
3. Workflows page empty-state rewrite: replace the "POST
   /api/v1/workflows" copy with the 3-template `[ Install ]` CTA from
   §13.4-D. Use the EmptyState component from Phase 1.
4. Featured slot on Overview (P1-13): small card above the Worklist row;
   dismissable via `localStorage["featured_dismissed"]`; reappears when
   server reports `featured_updated_at` newer than last visit.
5. Six new plugin stub pages (P1-14):
   `pages/plugins/{conductor,agentloop,ledgerlens,agentpassport,relay,
   engram}.rs`. Each is a minimal page with: hero, 1-paragraph
   description from the marketing megamenu, "Set up" button (no-op
   in Phase 3 — Phase 4 wires the wizard), routes registered, sidebar
   entries already in Phase 2.

### 4.2 Server endpoints introduced

```
POST /api/v1/workflows/reference/{id}/install     # P0-8 thin wrapper
```

(Optionally inferred from existing `POST /workflows` + pre-loaded
template source — server side decides.)

### 4.3 PRs

| # | PR title | Rows |
|---|---|---|
| 3.1 | `ui(apps): rewrite Apps Hub layout — Featured/Pre-built/All Plugins/Examples/Custom` | P0-7 |
| 3.2 | `ui(workflows): one-click install for reference templates + empty-state rewrite` | P0-8, P0-10 |
| 3.3 | `ui(overview): Featured slot card (dismissable, server-pushed updates)` | P1-13 |
| 3.4 | `ui(plugins): stub pages for Conductor/AgentLoop/LedgerLens/AgentPassport/Relay/Engram` | P1-14 |

### 4.4 Acceptance gate

- A fresh Self-deploy node shows the 3 reference workflows on `/apps`,
  each with a working `[ Install ]` button.
- Clicking `[ Install ]` POSTs to the workflow endpoint and navigates to
  `/workflows/{id}`.
- The Workflows page never shows raw API paths in its empty-state.
- Each of the 6 new plugin pages is reachable from the sidebar and from
  `⌘K`.

---

## 5. Phase 4 — Onboarding wizards (5–7 days)

**Goal:** Ship the multi-step wizard system end-to-end. Mirror the TUI
wizards from `TUI_WIZARDS_MASTER_PLAN.md` in the web dashboard so the
product feel is consistent. Add the `/setup` hub. Make the first-run
experience real.

**Rows included:** P1-9, P1-10, P1-11, P1-12.

**Dependencies:** Phase 1 (Wizard primitive), Phase 3 (install-reference-
workflow exists for P1-11).

### 5.1 Wizards to ship

| Wizard | Page | Source / inspiration | Steps |
|---|---|---|---|
| **First-run** | `/setup` (default for fresh nodes) | TUI shared boot + capability handshake | Welcome → Connector connection → workspace detect → license activation (self-deploy only) → first plugin → invite teammate (optional) → done |
| **Connect a tool** | `/setup/connect-tool` | promote `pages/connect_landing.rs` into wizard | Pick tool (Cursor/Windsurf/Claude Code/Kiro/Generic) → get Base URL + token → copy snippet → first request verification |
| **Install a workflow** | `/setup/install-workflow/{template_id}` | new | Pick template → preview CLS → choose namespace + agent binding → confirm → land on `/workflows/{id}` |
| **DevGuard** | `/plugins/devguard/setup` | TUI plan §"DevGuard Wizard Modules A–E" | Protection targeting → enforcement layers → agent integration → policy authoring → verification |
| **TraceTramp** | `/plugins/tracetramp/setup` | TUI plan §"TraceTramp Modules A–E" | Runtime profile → provider chain → budget → policy route → memory/evidence |
| **WitnessCtl** | `/plugins/witnessctl/setup` | TUI plan §"WitnessCtl Modules A–E" | Evidence sources → integrity chain → compliance profile → PII handling → report delivery |
| **Create first agent** | modal in `/agents` | promote existing modal to step-wizard | Name+namespace → role → model → token budget → review → create |
| **First budget** | `/billing/setup-budget` | new | Scope (tenant/team/agent) → token cap → cost cap → alert thresholds → action |

### 5.2 `/setup` hub

New page `pages/setup.rs`:

- Lists all wizards with completion state (icons: ✓ done, ◐ resume, ○
  not started).
- Each wizard reads its own `wizard:<id>` localStorage state to compute
  status.
- Suggested "next wizard" hint based on which steps are unmet.

Default route for fresh nodes — `App::on_mount`, when
`agents.len() == 0 && workflows.len() == 0 && !wizard_completed("first_run")`,
redirect to `/setup` (with skip link).

### 5.3 PRs

| # | PR title | Rows |
|---|---|---|
| 4.1 | `ui(setup): /setup hub page + first-run guard in App` | P1-9 partial |
| 4.2 | `ui(wizard): first-run wizard (Connector connection → first plugin → invite)` | P1-9 |
| 4.3 | `ui(wizard): connect-a-tool wizard — promote /connect into shell` | P1-10 |
| 4.4 | `ui(wizard): install-a-workflow wizard (template preview → bind → confirm)` | P1-11 |
| 4.5 | `ui(wizard): DevGuard setup wizard (Modules A–E from TUI plan)` | P1-12 |
| 4.6 | `ui(wizard): TraceTramp setup wizard (Modules A–E)` | P1-12 |
| 4.7 | `ui(wizard): WitnessCtl setup wizard (Modules A–E)` | P1-12 |
| 4.8 | `ui(agents): promote Create modal to step wizard` | P1-12 spillover |
| 4.9 | `ui(billing): first-budget wizard` | P1-12 spillover |

### 5.4 Server endpoints introduced

```
GET  /api/v1/setup/state           # what's done, what's next
POST /api/v1/setup/dismiss         # mark wizard dismissed (server-side persistence optional; localStorage is OK)
```

For Self-deploy: each wizard's `Finish` step calls existing product
endpoints (`POST /workflows`, `POST /agents`, etc.), not a new orchestration
endpoint. Wizards are pure UI.

### 5.5 Acceptance gate

- A fresh Self-deploy node redirects sign-in → `/setup` → first-run
  wizard.
- Each of the 8 wizards renders, advances, validates, and lands on the
  product page on completion.
- Closing the browser mid-wizard, reopening → resumes at the same step
  with form state intact.
- `/setup` hub shows accurate completion state per wizard.
- DevGuard / TraceTramp / WitnessCtl wizards' module structure matches
  `TUI_WIZARDS_MASTER_PLAN.md` (the web and TUI flows are interchangeable
  to the operator).

---

## 6. Phase 5 — Dual-distribution UX (4–6 days)

**Goal:** Make Playground feel like a 90-minute demo; make Self-deploy
feel like production. Implement every row in §10c that depends on
`DeploymentInfo`.

**Rows included:** P0-13, P0-14, P0-16, P1-19, P1-20, P1-21, P1-22, P1-23,
P1-24, P1-26, P1-27.

**Dependencies:** Phase 1 (deployment.rs + build features), Phase 3
(reference workflow install).

### 6.1 Playground side

1. **Countdown pill in header** (P0-13). Replace `<LiveDotPill/>` with
   `<CountdownPill expires_at=... />` when `mode == Playground`. Renders
   `● Live · expires in 47m 12s`, amber under 10 m, red under 2 m. Click
   opens session-end modal.
2. **Session-end modal** (P0-14). Triggered at `expires_at − 60 s`.
   Three buttons: Extend (signup), Download install.sh + my-session.tar.gz,
   End session. After expiry → friendly "Session ended" page with
   conversion CTAs (not a 401 redirect).
3. **Dev-bypass off in Playground** (P0-16). Even if `dev-bypass` build
   flag is set, when `mode == Playground` the bypass UI is hidden and
   `dev_bypass()` short-circuits to error.
4. **Pre-install + sample data** (P1-19). Server-side: when a playground
   session starts, install all 3 reference workflows and start sample-
   data generators. UI: empty-state never shown in Playground.
5. **Guided tour** (P1-20). Replace the first-run wizard in Playground
   mode with a 4-step × 30 s tour: PII redaction → incident routing →
   HITL approval → "Install on your infra ↓". Reuses the Wizard
   primitive with `tour` styling and shorter copy.
6. **`/install` page** (P1-21). Renders install commands (curl, Docker,
   Helm), "Download my-session.tar.gz" button, pricing tiers, portal
   signup CTA. Persistent footer "Take this home →" links here.
7. **"Save this session" tar export** (P1-22). `GET /api/v1/playground/
   session/export` returns a `.tar.gz`. Downloaded by `/install` and the
   30 m-remaining banner.
8. **Caps as visible meters** (P1-24). `Agents 2 / 5 · Tokens 12k / 100k`
   row on Overview, sticky in header at ≥ 80 %.
9. **Telemetry funnel** (P2-20 brought forward if Playground is the
   release-priority audience). `session_start`,
   `workflow_installed`, `first_receipt`, `install_clicked`,
   `signup_clicked`.

### 6.2 Self-deploy side

1. **Mode-aware copy** (P1-26) on `/billing`, `/license`,
   `/settings/custom-domains`, `/secrets`, `/webhooks`. These are *hidden*
   in Playground per Phase 2; here we make them *real* in Self-deploy.
2. **Update toast** (P1-27). Poll `releases.connector.dev/latest.json`.
   Toast on Overview when newer version exists.
3. **Import from playground session** (P1-23). `POST /api/v1/import/
   playground-session` accepts the tarball uploaded during first-run
   wizard, pre-fills wizard state (plugins, workflows, agents).

### 6.3 Server endpoints introduced

```
GET  /api/v1/playground/session/export       # P1-22
POST /api/v1/import/playground-session       # P1-23
POST /api/v1/telemetry/playground            # P2-20
GET  releases.connector.dev/latest.json      # static (P1-27)
```

Plus a server-side behaviour change for `POST /playground/session` to
install the 3 reference workflows + start sample-data generators on the
new session (P1-19).

### 6.4 PRs

| # | PR title | Rows |
|---|---|---|
| 5.1 | `ui(playground): countdown pill in header; session-end modal at T-60s` | P0-13, P0-14 |
| 5.2 | `ui(playground): hard-disable dev-bypass when mode=Playground` | P0-16 |
| 5.3 | `server(playground): pre-install 3 reference workflows + sample-data generators` | P1-19 |
| 5.4 | `ui(playground): 4-step guided tour replaces first-run wizard` | P1-20 |
| 5.5 | `ui(install): /install page (commands + download tarball + pricing CTA)` | P1-21 |
| 5.6 | `server(playground): GET /playground/session/export — config snapshot tar.gz` | P1-22 |
| 5.7 | `ui(playground): caps as visible meters on Overview + header at ≥80%` | P1-24 |
| 5.8 | `ui(self-deploy): mode-aware copy on /billing /license /secrets /webhooks /custom-domains` | P1-26 |
| 5.9 | `ui(self-deploy): "Update available" toast` | P1-27 |
| 5.10 | `ui(self-deploy): import-playground-session step in first-run wizard` | P1-23 |

### 6.5 Acceptance gate

- Playground build: header shows live countdown; at 89 min countdown
  reads `● Live · expires in 1m 00s`; at 90 min the session-end modal is
  mounted; closing it shows the conversion page (not a 401 login
  redirect).
- Playground build: clicking "Download install.sh + my session" produces
  a `connector-trial-{tenant}.tar.gz` containing `connector.yaml`, the
  installed workflows, and the receipts.
- Self-deploy build with the tarball above placed in
  `/var/lib/connector/import/`: first-run wizard offers "Import from
  playground session?" and pre-fills the plugin + workflow choices.
- Self-deploy build: `/billing` renders the real billing UI; in
  Playground build the same URL renders the install card.
- Dev-bypass UI is invisible in any Playground build regardless of build
  flag.

---

## 7. Phase 6 — Overview & per-page tab density (6–8 days)

**Goal:** Apply the tab-cap rule (≤ 4 tabs per page) across all dense
pages. Collapse Overview to "skinny + expander". Implement the
recommendations engine.

**Rows included:** P1-3, P1-5, P1-15.

**Dependencies:** Phase 2 (header slimmed, OperatorShell removed),
Phase 3 (reference workflows landed for empty-state).

### 7.1 Per-page tab refactors

| Page | Tabs today | Tabs target |
|---|---:|---|
| `memory.rs` | 10 | **Browse / Write / Audit** (3) |
| `agents.rs` | 11 | **Overview / Activity / Trust & Compliance / Lifecycle** (4) |
| `monitor.rs` | 10 | **Health / Cost / Anomalies / Forecast** (4) |
| `compliance.rs` | 7 | **Scorecard / Findings / Frameworks** (3) — frameworks is a dropdown inside |
| `trust.rs` | 6 | **Score / Receipts / Proofs** (3) |
| `debug.rs` | 7 | **Sessions / Tracing / Failures** (3) |
| `protocols.rs` | 6 tabs | single list with protocol pill on each row (0 tabs) |
| `tools.rs` | 5 | **Bridges / Invoke / Approvals** (3) |
| `pipeline.rs` | 5 | **Gate / Steps / Definitions** (3) |
| `infra.rs` | 5 | **Topology / Vault / Quota** (3) |

For pages going 7→3 or 11→4, the cut tabs become **sub-sections inside
their new parent tab**, with their own filter chips. We are reorganising,
not deleting features.

### 7.2 Overview rewrite (P1-3)

`pages/overview.rs` goes from 12 first-paint resources → 3:

```rust
let surface  = LocalResource::new(|| surface_client::overview_system());
let agents   = LocalResource::new(|| api::get_value("/agents"));
let activity = LocalResource::new(|| api::get_value("/actionlog/actions?limit=20"));
```

Page composition (top → bottom):

1. Worklist (3 cells: Open incidents, Pending approvals, Trust score) —
   from `surface`.
2. Active Agents table + Live Activity feed — from `agents`, `activity`.
3. `<details>` expander "Show cost details" — loads cost dashboard +
   books on demand.
4. `<details>` expander "Show LLM gateway info" — loads gateway info on
   demand.

Delete: Operator Actions toolbar, Spend provenance essay, the 4-column
hero row (folded into the Worklist).

### 7.3 Recommended next steps engine (P1-15)

Server: `GET /api/v1/setup/recommendations` returns up to 3 suggestions
computed from current state:

```json
{
  "recommendations": [
    {"id":"install_workflow","title":"Install a pre-built workflow","cta_path":"/apps#pre-built"},
    {"id":"create_agent","title":"Create your first agent","cta_path":"/agents?new=1"},
    {"id":"set_budget","title":"Set a budget","cta_path":"/billing/setup-budget"}
  ]
}
```

Rendered on Overview under "Suggested next steps". Dismissed/snoozed per
user (localStorage; or server-side once an auth model is decided).

### 7.4 PRs

| # | PR title | Rows |
|---|---|---|
| 6.1 | `ui(memory): 10 → 3 tabs; remove API endpoint dump card` | P1-5 |
| 6.2 | `ui(agents): 11 → 4 tabs` | P1-5 |
| 6.3 | `ui(monitor): 10 → 4 tabs` | P1-5 |
| 6.4 | `ui(compliance): 7 → 3 tabs; frameworks dropdown` | P1-5 |
| 6.5 | `ui(trust): 6 → 3 tabs` | P1-5 |
| 6.6 | `ui(debug): 7 → 3 tabs; "Developer view" toggle in Settings` | P1-5, P2-9 |
| 6.7 | `ui(protocols): replace tabs with single connection list` | P1-5 |
| 6.8 | `ui(tools|pipeline|infra): 5 → 3 tabs each` | P1-5 |
| 6.9 | `ui(overview): collapse to skinny + expanders; cut 12→3 first-paint resources` | P1-3 |
| 6.10 | `ui(overview): recommendations engine + server endpoint` | P1-15 |

### 7.5 Acceptance gate

- `rg "enum Tab" platform/ui-leptos/dashboard/src/pages/ | awk -F '{' '{print NF-1}' | sort -nr | head -1` shows max 4.
- Overview fetches ≤ 3 resources on first paint (measured via DevTools
  network tab on a fresh node).
- Overview fits in a 1440 × 900 viewport without scroll on a fresh node.
- The Recommendations panel renders 1–3 cards on a non-fresh node;
  hidden on a fully-onboarded node.

---

## 8. Phase 7 — Polish, a11y, mobile, telemetry (4–6 days)

**Goal:** The cleanup pass. Mostly mechanical edits. Can be done in
parallel with other phases by a second engineer.

**Rows included:** P2-1, P2-2, P2-3, P2-4, P2-5, P2-6, P2-7, P2-8, P2-9,
P2-10, P2-11, P2-12, P2-13, P2-14, P2-15, P2-16, P2-17, P2-21, P2-22,
P2-23, P2-24.

**Dependencies:** every other phase (run last or in parallel).

### 8.1 Buckets

| Bucket | Rows | Notes |
|---|---|---|
| **Visual / design system** | P2-4 (6-token palette) · P2-5 (single loading treatment) · P2-17 (EmptyState everywhere) · P2-18 (brand — done in Phase 2) | One PR per bucket; cosmetics-only |
| **Accessibility** | P2-6 (a11y pass: aria-label, contrast, role=status on LiveDotPill) | Pair with the colour palette PR |
| **Re-style /trial + /connect** | P2-1 (trial → Tailwind) · P2-2 (connect inside shell) | Mechanical; ~1 day |
| **Performance** | P2-7 (eliminate double-fetch on every nav — partially done in Phase 1 request_store) | Audit; small fixes |
| **Mobile** | P2-10 (drawer sidebar ≤ md; lg fallback for xl: grid) | 1–2 days, biggest item in Phase 7 |
| **Terminology + titles** | P2-8 (unify "Agents"/"Activity"/"Trust") · P2-12 (per-page document titles) | Mechanical |
| **Developer-view toggle** | P2-9 (hide JSON dumps in Memory/Verify/Debug behind a Settings flag) | One PR |
| **Tier awareness** | P2-13 (entitlements signal + "Upgrade" pill) | One PR + a mapping table |
| **What's new** | P2-11 (release-notes toast) | Static fetch |
| **Sample data run** | P2-14 (run-with-sample-data button on pre-built workflows) | Server endpoint + UI button |
| **Recent / favorites** | P2-15 (sidebar Recent group + star to pin) | localStorage only |
| **Invite teammate** | P2-16 (invite wizard inside dashboard) | New wizard |
| **Misc Playground polish** | P2-21 (Take-this-home CTA) · P2-22 (Update footer) · P2-23 (launchd/systemd snippets on /install) · P2-24 (connector.yaml editor) | Mostly small |
| **Cleanup** | P2-3 (decide settings_custom_domains.rs — register or delete) | One PR |

### 8.2 PRs

12–15 small PRs; the larger ones are:

- 7.1 `ui(theme): 6-token colour palette + lint rule`
- 7.2 `ui(a11y): aria-label sweep + contrast bumps + LiveDotPill role=status`
- 7.3 `ui(mobile): drawer sidebar ≤ md; lg fallback for xl: grids`
- 7.4 `ui(trial+connect): restyle to Tailwind + bring inside shell`
- 7.5 `ui(entitlements): entitlements signal + Upgrade pill on gated controls`
- 7.6 `ui(devtools): hide JSON dumps behind Settings → Developer view flag`
- 7.7 `ui(release-notes): What's new toast`
- 7.8 `ui(sidebar): Recent group + Star to pin`
- 7.9 `ui(invite): invite-teammate wizard inside dashboard`

### 8.3 Acceptance gate

- No raw Tailwind colour names (`indigo-*`, `purple-*`, etc.) in any
  page touched after this phase. Only `brand`, `success`, `warn`,
  `danger`, `info`, `muted`.
- WCAG AA contrast check passes on at least 90 % of text.
- Sidebar collapses to drawer on `md:` and below; no horizontal scroll
  on any page at iPad widths.
- All pages set `document.title`.
- `/trial` and `/connect` are visually consistent with the rest of the
  app.

---

## 9. Server endpoints — full inventory

All new endpoints across all phases, owned by the
`oss/connector/crates/connector-server` crate. Each ships behind the
existing route gating in `routes.rs`.

| # | Endpoint | Phase | Why | Auth |
|---|---|---|---|---|
| 1 | `GET  /api/v1/deployment/info` | 1 | Mode + edition + license + countdown for the UI | Bearer (any operator) |
| 2 | `GET  /api/v1/products` | 2 | Single source for the 9-plugin catalog | Public (or operator+) |
| 3 | `POST /api/v1/workflows/reference/{id}/install` | 3 | One-click install of shipped CCL templates | operator+ |
| 4 | `GET  /api/v1/setup/state` | 4 | Wizard completion lookup | Bearer |
| 5 | `POST /api/v1/setup/dismiss` | 4 | Mark wizard skipped/done (optional, localStorage acceptable interim) | Bearer |
| 6 | `GET  /api/v1/setup/recommendations` | 6 | Suggested next steps engine | Bearer |
| 7 | `GET  /api/v1/playground/session/export` | 5 | Tarball of current playground session | playground-session-bearer |
| 8 | `POST /api/v1/import/playground-session` | 5 | Restore on self-deploy node | first-run/admin |
| 9 | `POST /api/v1/telemetry/playground` | 5 (or 7) | Anonymous funnel | none (CSRF-token gated) |

Total: **9** new endpoints, all small. None replaces an existing
endpoint; the surface only grows.

---

## 10. Shared primitives map

Phase 1 introduces these and the rest of the codebase consumes them.
Use this as a guard against drift / duplication.

| Primitive | Path | Phases that consume it |
|---|---|---|
| `DeploymentMode`, `DeploymentInfo` signal | `dashboard/src/deployment.rs` | 2, 3, 4, 5 |
| Route registry (`REGISTRY: Vec<RouteDescriptor>`) | `dashboard/src/routes.rs` | 2 (Router + sidebar), 2 (SearchModal), 6 (Recommendations CTAs) |
| `Wizard` + `WizardStep` | `dashboard/src/components/wizard.rs` | 4 (all 8 wizards), 5 (guided tour) |
| `EmptyState` | `dashboard/src/components/empty_state.rs` | 3 (workflows empty), 6 (every list page), 7 (cleanup) |
| `PageTitle` | `dashboard/src/components/page_title.rs` | every page in 2–7 |
| `LiveDotPill`, `CountdownPill` | `dashboard/src/components/{live_dot_pill,countdown_pill}.rs` | 0, 5 |
| `SystemHealthCard` | `dashboard/src/components/system_health_card.rs` | 0 (Overview, Monitor) |
| `Entitlements` signal | `dashboard/src/entitlements.rs` (Phase 7) | gated pages across the app |
| `recommendations` resource | `dashboard/src/recommendations.rs` (Phase 6) | Overview, possibly `/setup` |

---

## 11. Build & CI changes

### 11.1 Feature flags (already designed in Phase 1)

```toml
# platform/ui-leptos/dashboard/Cargo.toml
[features]
default     = ["self-deploy"]
self-deploy = []
playground  = []
dev-bypass  = []
```

Rules of thumb when authoring:

- `#[cfg(feature = "playground")]` for code that should *only* compile
  into the playground bundle (e.g., countdown pill, `/install` page).
- `#[cfg(feature = "self-deploy")]` for code that should *only* compile
  into the self-deploy bundle (e.g., license activation, custom-domain
  editor, `connector.yaml` editor).
- Use `mode.get() == DeploymentMode::Playground` at runtime when the code
  is *shared* but behaves differently (e.g., sidebar item filter).
- Use `#[cfg_attr(not(feature = "..."), allow(dead_code))]` when sharing
  helpers across both.

### 11.2 Build outputs

```
platform/ui-leptos/dashboard/dist/self-deploy/    ← shipped in tarball under /ui/
platform/ui-leptos/dashboard/dist/playground/     ← copied into Dockerfile.playground.unified
```

### 11.3 CI matrix

- `cargo check` × `{self-deploy, playground, dev-bypass + self-deploy}`
- `trunk build --release` × `{self-deploy, playground}`
- `cargo clippy` × matrix (deny warnings)
- `cargo test --workspace` (one-shot)
- Optional: lighthouse run against `dist/self-deploy/` and
  `dist/playground/` to catch a11y / perf regressions.

### 11.4 Release pipeline impact

- Existing `install.sh` already serves `connector-platform-{ver}-{arch}.
  tar.gz` from `releases.connector.dev`. We need to add `/ui/` from
  `dist/self-deploy/` into the tar.
- `Dockerfile.playground.unified` needs its `COPY` step updated to pull
  from `dist/playground/` not from a default trunk output.

---

## 12. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Phase 2's sidebar rewrite has merge conflicts with parallel Phase 3/4/5 work in the same `layout.rs` | High | Medium | Phase 2 owns `layout.rs` exclusively during its window; other phases use feature branches that rebase weekly. |
| `GET /deployment/info` lands later than the UI consumers | Medium | High | Phase 1 ships the **endpoint first**, then the client code (PR 1.1 contains both server + client). |
| `--features=playground` build accidentally includes a self-deploy panel | High | Medium (perf), High (security if dev-bypass leaks) | CI fails if `rg "feature.*self-deploy" dist/playground/` finds matches; manual review on every PR touching `#[cfg(feature=...)]`. |
| Wizard primitive too generic / too rigid | Medium | High (forces ugly workarounds) | Build it against PR 4.2 (first-run) **first** so the API is validated by a real use, then 4.3+ adopt it. |
| Server work blocks UI work | Medium | Medium | Stub endpoints with hardcoded JSON in dev so UI can land without waiting. Use `dev_seed_*` env vars on the server. |
| 47 pages → 14 — operators with bookmarks 404 | Medium | Low | All 46 routes stay valid forever. Reorg, never delete routes. Old deep links redirect inside `App`. |
| Playground telemetry crosses into Self-deploy | Low | High (privacy) | `#[cfg(feature = "playground")]` on the entire telemetry module; CI lint blocks any non-cfg-gated POST to `/telemetry/...`. |
| Sample-data generators leak across playground sessions | Medium | Medium | Per-session namespace already enforced server-side (`CONNECTOR_PLAYGROUND_*` env). Audit `/playground/session.rs` during PR 5.3. |
| First-run wizard breaks for existing self-deploy operators who don't want it | Low | Low | Always show "Skip and explore" link; respect `localStorage["onboarding_completed"]` set on first sign-in. |

---

## 13. Rollout, migration, and instrumentation

### 13.1 Staged rollout per phase

Each phase merges to `main`. The release pipeline ships both bundles.
Rollback = revert phase branch + redeploy previous tarball + previous
Fly.io image.

### 13.2 Migration of operator state

- All wizard state lives in localStorage with `wizard:<id>` keys. No
  server schema change for Phase 4.
- The 6 hidden-page redirects in Playground build are pure UI — server
  routes still work.
- The `/command-center` route delete in Phase 2 leaves a redirect to `/`
  in `App`'s 404 handler to catch bookmarks. Same for `/cls-execution/
  pkg-basic-tool-agent` deep link → `/workflows`.

### 13.3 Instrument the migration itself

Add four counters to telemetry (or `actionlog`):

- `ui.phase.{N}.shipped_at` (manual annotation per release tag).
- `ui.wizard.{id}.started`, `…completed`, `…dismissed` (anon counter).
- `ui.playground.session.export.downloaded` (P1-22 conversion proxy).
- `ui.playground.session.import.invoked` (P1-23 conversion confirmation).

These let you read the conversion funnel on the next platform refresh.

---

## 14. Tracking matrix — every audit row → phase → PR

The shorthand below is the canonical "what goes where" map. If a row is
not in this table, it's not in scope.

### 14.1 P0 rows

| Row | Title (audit) | Phase | PR |
|---|---|---|---|
| P0-1 | Slim header / replace StatusBanner | 0 | 0.1 |
| P0-2 | Fix dev-bypass leakage | 0 | 0.2 |
| P0-3 | Fix dead Sign-Out button | 0 | 0.3 |
| P0-4 | Remove fake progress bars | 0 | 0.4 |
| P0-5 | Drop hardcoded /cls-execution sample id (sidebar) | 0 | 0.5 |
| P0-6 | Stop raw API paths as primary copy | 0 | 0.6 |
| P0-7 | Lead /apps with pre-built workflows | 3 | 3.1 |
| P0-8 | One-click install for 3 reference workflows | 3 | 3.2 |
| P0-9 | Surface all 9 marketed plugins in sidebar | 2 | 2.3 |
| P0-10 | Workflows empty-state rewrite | 3 | 3.2 |
| P0-11 | Strip "Phase 3.11" / "Phase 3 control plane" labels | 0 | 0.7 |
| P0-12 | Deployment-mode signal + endpoint | 1 | 1.1 |
| P0-13 | 90-min countdown pill in header | 5 | 5.1 |
| P0-14 | Session-end modal at T-60s | 5 | 5.1 |
| P0-15 | Mode-gated sidebar | 2 | 2.4 |
| P0-16 | Hard-disable dev-bypass in Playground | 5 | 5.2 |
| P0-17 | Route gating for /trial /connect by mode | 2 | 2.8 |

### 14.2 P1 rows

| Row | Title | Phase | PR |
|---|---|---|---|
| P1-1 | New 4-section sidebar | 2 | 2.2 |
| P1-2 | Remove sidebar duplication | 2 | 2.2 |
| P1-3 | Collapse Overview to skinny + expander | 6 | 6.9 |
| P1-4 | Merge /command-center into / | 2 | 2.6 |
| P1-5 | Cap tab counts at 4 across pages | 6 | 6.1–6.8 |
| P1-6 | Generated SearchModal index | 2 | 2.7 |
| P1-7 | In-shell onboarding (welcome card + tooltips) | 4 | 4.1 |
| P1-8 | Wizard primitive + /setup hub | 1 + 4 | 1.4 (primitive) + 4.1 (hub) |
| P1-9 | First-run wizard | 4 | 4.2 |
| P1-10 | Connect-a-tool wizard | 4 | 4.3 |
| P1-11 | Install-a-workflow wizard | 4 | 4.4 |
| P1-12 | DevGuard/TraceTramp/WitnessCtl setup wizards | 4 | 4.5–4.7 |
| P1-13 | Featured slot on Overview | 3 | 3.3 |
| P1-14 | Stub pages for 6 invisible plugins | 3 | 3.4 |
| P1-15 | Recommended next steps engine | 6 | 6.10 |
| P1-16 | Global ⌘K palette | 2 | 2.7 |
| P1-17 | Single source for product catalog | 2 | 2.1 |
| P1-18 | Two Leptos build profiles | 1 | 1.2 |
| P1-19 | Pre-install + sample data in Playground | 5 | 5.3 |
| P1-20 | Guided tour in Playground first-run | 5 | 5.4 |
| P1-21 | /install page (Playground) | 5 | 5.5 |
| P1-22 | Session tar export | 5 | 5.6 |
| P1-23 | Import-playground-session step in first-run | 5 | 5.10 |
| P1-24 | Caps as visible meters in Playground | 5 | 5.7 |
| P1-25 | Edition pill in sidebar footer | 2 | 2.4 |
| P1-26 | Mode-aware copy on 5 admin-adjacent pages | 5 | 5.8 |
| P1-27 | Self-deploy "Update available" toast | 5 | 5.9 |

### 14.3 P2 rows

| Row | Title | Phase | PR |
|---|---|---|---|
| P2-1 | Restyle /trial to Tailwind | 7 | 7.4 |
| P2-2 | Bring /connect inside the shell | 7 | 7.4 |
| P2-3 | Decide settings_custom_domains.rs | 7 | misc |
| P2-4 | 6-token colour palette | 7 | 7.1 |
| P2-5 | Single loading treatment | 7 | misc |
| P2-6 | A11y pass | 7 | 7.2 |
| P2-7 | Stop double-fetching on every nav | 1 + 7 | 1.5 (request_store) + audit |
| P2-8 | Glossary/terminology unification | 7 | misc |
| P2-9 | Developer-view toggle | 6 | 6.6 |
| P2-10 | Mobile / responsive sweep | 7 | 7.3 |
| P2-11 | "What's new" toast | 7 | 7.7 |
| P2-12 | Per-page document title | 1 + 7 | 1.5 (helper) + audit |
| P2-13 | Entitlement-aware UI | 7 | 7.5 |
| P2-14 | Run-with-sample-data on pre-built workflows | 7 | misc |
| P2-15 | Recent / Favorites sidebar | 7 | 7.8 |
| P2-16 | Invite-a-teammate wizard | 7 | 7.9 |
| P2-17 | Empty-state component everywhere | 1 + 7 | 1.5 + audit |
| P2-18 | Brand-name unification | 2 | 2.9 |
| P2-19 | Eliminate remaining pkg-basic-tool-agent hardcodes | 2 | 2.10 |
| P2-20 | Playground telemetry funnel | 5 | 5 (sub-PR) |
| P2-21 | Playground "Take this home →" CTA | 5 | 5.5 |
| P2-22 | Self-deploy Update footer button | 5 | 5.9 |
| P2-23 | systemd/launchd snippets on /install | 5 | 5.5 |
| P2-24 | connector.yaml editor (self-deploy) | 7 | misc |

---

## 15. Definition of done (full programme)

This effort is "complete" when:

1. **The audit's §11 + §11b acceptance criteria all pass** on both
   builds.
2. **Both bundles compile** from `main` (`make build-all`).
3. **Sidebar has 4 sections + "More…"** and never exceeds 10 visible
   items at any width.
4. **All 9 marketed plugins** appear in the dashboard sidebar with
   dedicated pages, even if some pages are stubs.
5. **All 3 reference workflows** have a one-click `[ Install ]` action
   reachable from `/apps` in ≤ 2 clicks from sign-in.
6. **`/setup` wizard hub** is the default landing for a fresh node, and
   covers 8 distinct wizards.
7. **Playground build** ships a 90-min countdown, never shows
   billing/license/secrets, exports session as tar, and has working
   conversion CTAs.
8. **Self-deploy build** ships full admin surfaces, real license
   activation, "Update available" toast, and optional import of a
   playground session.
9. **No tab strip exceeds 4 tabs** on any page in `dashboard/src/pages/`.
10. **Zero raw API paths** appear as `<p>` body copy on any operator-
    facing page.
11. **The product catalog** (`platform/products/catalog.json`) is the
    single source of truth consumed by both the marketing site and the
    dashboard sidebar.
12. **CI matrix** runs both feature builds + clippy + tests on every PR.

When all twelve are green, the project is shipped. The audit document
becomes historical reference; this plan becomes the changelog.

---

## 16. Quick-start for the next engineer

The shortest "what do I do tomorrow morning" sequence:

1. Read `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §0 and §10/§10b/§10c.
2. Read this file's §1 (Phase 0).
3. Create branch `feat/ui-phase-0-bleeding`.
4. Work the 7 PRs in §1.1 in order. Each is small. Aim to merge Phase 0
   in two days.
5. Move to Phase 1 (`feat/ui-phase-1-foundation`). PR 1.1
   (`deployment.rs` + endpoint) goes first.
6. After Phase 1 merges, open three parallel branches for Phases 2, 3,
   4. Phase 5 starts when Phases 1 + 3 merge. Phase 6 starts when Phases
   1 + 2 merge. Phase 7 is opportunistic throughout.

Where to find shared things:

- Audit findings & justification → `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md`.
- The TUI wizard module shapes you'll mirror in Phase 4 →
  `TUI_WIZARDS_MASTER_PLAN.md`.
- The marketing-side product list (9 plugins) →
  `platform/docs/landing-page/web/src/components/Nav.tsx`.
- The shipped reference workflow CCL sources →
  `platform/server/resources/workflow_templates/`.
- The two existing deploys (Try-Me / self-deploy) →
  `platform/deploy/{fly.playground.toml, install.sh}` etc.
- This plan supersedes any phase ordering implied in the audit.

*End of plan.*
