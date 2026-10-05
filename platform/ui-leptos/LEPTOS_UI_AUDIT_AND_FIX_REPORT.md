# Leptos Dashboard UI — Operator Audit & Fix Report

Scope: `platform/ui-leptos/dashboard/` (the operator-facing Leptos app).
The `admin/` and `www/` apps are out of scope for this report, except where the
dashboard duplicates their concerns.

This report is written from the perspective of a **first-time operator** opening
the dashboard on day 0 of a real deployment. Every finding cites the file and
component it lives in. Section 10 is the prioritized fix list to execute.

---

## 0. Executive summary

The dashboard works, but it shows its age. It has been growing surface-area for
~12 months and now exposes more product than any single operator needs on day 1
— *while simultaneously hiding the things customers actually paid for*.

The shortest possible diagnosis:

| Smell | Today | Target |
|---|---:|---:|
| Page modules under `pages/` | **49** | ~14 |
| Top-level sidebar entries (incl. plugins) | **~46** | ~10 (+ "More") |
| Sidebar sections | **7** + Apps | 4 |
| Largest tab-set on a single page (`monitor.rs`) | **10 tabs** | ≤ 4 |
| Same for `memory.rs` | **10 tabs** | ≤ 4 |
| Same for `agents.rs` | **11 tabs** | ≤ 4 |
| API resources fetched on `/` (Overview) | **12** | 3 + lazy |
| Things stuffed into the 56 px header strip | **6 widgets** | 2 |
| **Marketed plugins surfaced in sidebar** | **3 of 9** | 9 of 9 |
| **Pre-built workflow templates featured anywhere prominent** | **0 of 3** | 3 of 3 on `/apps` |
| **Setup wizards in the web app** | **0** | 8+ (§14) |
| Onboarding screens for a fresh node | **0 in-app** (only `/trial`, `/connect` standalone) | first-run wizard + per-product wizards |
| Distinct "command center / overview" surfaces | **3** (`/`, `/command-center`, `surfaces/overview`) | 1 |
| Hard-coded `pkg-basic-tool-agent` references on a fresh node | **3 places** (sidebar, workflows, packages) | 0 |
| **Distinct UX for Playground (90-min) vs self-deploy tar** | **0** — same WASM bundle served by both | runtime `DeploymentMode` branch + two `--features` builds (§16) |
| **Trial → production "import session" path** | **none** | tarball export + first-run wizard import (§16.6) |

There are also concrete UI bugs (an unscoped dev-bypass banner on the login
screen, a raw "UNAVAILABLE" pill that hijacks the header on every cold start,
internal API paths and "Phase 3.11" milestone labels printed as primary copy
on operator pages, a dead Sign-Out button in the profile dropdown). The fix
plan in §10 + §10b addresses these alongside the structural cleanup.

The report is structured top-to-bottom as: diagnosis (§1–§8), proposed shape
(§9), fix plan (§10), acceptance criteria (§11), appendix (§12), then two
expansions added after operator review:

**Round 2 — products & wizards**

- §13 — **Core selling products & pre-built workflows must be in main
  highlights** (the 9-vs-3 plugin gap, 3 shipped templates buried).
- §14 — **Full onboarding wizards** (mirroring the existing
  `TUI_WIZARDS_MASTER_PLAN.md`).
- §15 — **Other gaps** discovered in the second pass.
- §10b — additions to the prioritized fix plan.
- §12b — product / wizard inventory.

**Round 3 — dual distribution (Try-Me vs tar self-deploy)**

- §16 — **Two distributions, one codebase.** The 90-minute hosted Try-Me
  (`try.cnktros.com`, `CONNECTOR_PRESET=playground`) and the self-deploy
  tarball (`curl install.sh \| bash`, the real adv software for production
  customers) must intentionally diverge in UX while sharing a single
  Leptos source tree. Build-time features + a runtime `DeploymentMode`
  signal split a long table of surfaces (sidebar, header, billing,
  secrets, onboarding, conversion CTAs) cleanly between the two.
- §10c — additions to the prioritized fix plan for the split.
- §11b — extra acceptance criteria covering both editions.
- §12c — full distribution matrix + file delta for the dual-build work.

---

## 1. The header — what the operator sees first

> User complaint: *"in header there is a available/unavailable banner that its
> total off, looks awkward."*

Confirmed and worse than reported. `components/layout.rs` `Header` (lines
~931–1197) currently renders, inside a single 56 px (`h-14`) sticky strip:

1. The page title (`<h1>`).
2. The full **`StatusBanner`** (`components/status_banner.rs`), which is a
   *3–4 row block*: pulsing dot, `LIVE`/`DEGRADED`/`UNAVAILABLE` uppercase pill,
   `monitor/health` font‑mono provenance, a 2‑line wrapping message, an
   "Updated …" line, and a row of `detail_chips` (Trust, Audit, Agents, Gov,
   Deploy). It's designed to be a side-panel widget but is forcibly squeezed
   into the header by the surrounding `max-w-sm` flex container — so on most
   widths it wraps and pushes the header to ~70 px on first paint, then snaps
   back when health resolves. That snap-and-truncate is the "awkward" feeling.
3. A **search button** that opens a modal whose item list is hard-coded
   (`SearchModal`, lines 1201–1361) and already drifts from the real route table.
4. A **notifications bell** with a 460 px-wide popup that fetches
   `/notifications` again on every navigation (`pathname.get()` is read inside
   the resource just to invalidate it).
5. A **`HeaderSubsystemStrip`** (lines 559–669) with three dots — API / Ledger /
   Mem — which *re-uses the same `/monitor/health` resource* as the banner.
   So the same signal is encoded twice: once as a giant banner with chips, once
   as three dots.
6. A profile chip with a dropdown that links to `/settings`, `/billing`,
   `/license` and a fake "Sign Out" `<button>` that has no `on:click` handler
   (real sign-out only happens from the sidebar; the dropdown button does
   nothing — bug).

On `Unavailable`, all of the above flips into red simultaneously: red banner +
red API dot. That doubled red — plus the fact that "Unavailable" is the
*default* state during the first fetch — is what makes the header read as
broken every time the page loads.

### Fix (Section 10, P0-1)

- Replace the in-header `StatusBanner` with a **compact pill** ("● Live ·
  monitor 12s ago") that links to `/monitor`. Move the full banner — message,
  chips, provenance — into a **`SystemHealthCard`** that lives on `Overview`
  and `Monitor`, where wrapping is fine.
- Make the default state during the first fetch a neutral `Checking` (zinc),
  not red `Unavailable`. The current map `live_state_from_monitor_status`
  falls through to `Unavailable` for any unknown string — that is wrong while
  the response is in flight.
- Delete `HeaderSubsystemStrip` from the header. Keep the three-dot mini-strip
  on the `/monitor` page only.
- Wire the "Sign Out" item in the profile dropdown to actually call `logout()`,
  or remove it.
- Stop reading `pathname.get()` inside the notifications/health resources just
  to force a refetch — use a `SystemResource` with a manual reload trigger.

The header should reduce to: `Title · LiveDot · Search · Bell · Profile`.

---

## 2. Navigation & information architecture — the 47-page sidebar

`components/layout.rs::nav_sections()` currently emits 7 sections with these
items (transcribed verbatim):

- **Operations**: Command Center, Overview, Agents, Memory, Monitor, Action
  Log, Books, History
- **Intelligence**: Prompts, Experiments, Insights, Notebook, Pipeline
- **Apps & Workflows**: Apps Hub, Workflows, CLS Catalog, CLS Builder, CLS
  Packages, **CLS Execution → `/cls-execution/pkg-basic-tool-agent`** (a
  hard-coded sample package id pinned as a sidebar entry — bug)
- **Trust & Safety**: Trust, Compliance, Safety (formal), Runtime Enforcement,
  Report Center, Firewall, Disputes
- **Infrastructure**: Tools, Protocols, Multi-Agent, Topology Center, Service
  Map, Infra, Orchestrator, Secrets, Grounding, Context
- **Platform**: Webhooks, Notifications, Economy, Marketplace, Verify (fleet),
  Debug
- **Settings**: Billing, License, Settings

Then below that, `PluginsNavSection` adds: Apps Hub (again), All Plugins,
DevGuard, TraceTramp, WitnessCtl, Service Map (again).

Problems by inspection:

| # | Problem | Evidence |
|---|---|---|
| 2.1 | **"Command Center" and "Overview" both at the top of Operations** point at conceptually overlapping pages (`/command-center` = `OperatorShell`, `/` = `Overview`). They re-use the same `surface_client::overview_system` + same `<SurfaceSummary/SurfaceOps/...>` components. | `main.rs` L100, L141; `overview.rs` L65–80; `operator_shell.rs` L25–73 |
| 2.2 | **"Apps Hub" appears twice** — once in "Apps & Workflows" and once in `PluginsNavSection`. "Service Map" appears twice (Infrastructure + plugins). "Marketplace" page exists alongside a separate `/plugins/marketplace` route. | `layout.rs` L48, L152, L75, L207; `main.rs` L153 |
| 2.3 | **CLS is shattered into 4 separate top-level entries** (Catalog, Builder, Packages, Execution) for what is one feature. | `layout.rs` L50–53 |
| 2.4 | **CLS Execution sidebar link is hard-coded to a sample package id** (`/cls-execution/pkg-basic-tool-agent`). On a fresh node this 404s or shows a non-existent run. | `layout.rs` L53 |
| 2.5 | **Trust + Compliance + Safety (formal) + Runtime Enforcement + Report Center + Firewall + Disputes** are 7 separate top-level entries that all answer one question: "is the system behaving safely?" | `layout.rs` L57–67 |
| 2.6 | **Topology Center, Service Map, and Infra** are three entries that all describe the platform topology. Same for **Grounding + Context + Multi-Agent + Orchestrator + Tools + Protocols** all under Infrastructure. | `layout.rs` L70–81 |
| 2.7 | **`settings_custom_domains.rs` (474 lines)** has no route registered in `main.rs` and no sidebar link. It's dead code or reachable only via deep-link from `Settings` (TBD). | `pages/mod.rs` L35; absent from `main.rs` |
| 2.8 | The sidebar is **non-collapsible by section** — once expanded (240 px), the operator must scroll to see Settings. There is no "Pin" / "Recent" / "Frequent" affordance. | `layout.rs` L826–852 |
| 2.9 | `Books` lives under **Operations** but is a finance/accounting surface. `Webhooks` and `Notifications` live under **Platform** but a first-time operator looks for them under **Settings**. Mental-model mismatch. | `layout.rs` |
| 2.10 | The hard-coded `SearchModal` item list (35 entries) is the only "go to" affordance, and it has already drifted from the real routes (e.g. no entries for `/command-center`, `/cls-*`, `/books`, `/apps`, `/runtime-enforcement`, `/topology-center`, `/service-map`, `/report-center`, plugins). | `layout.rs` L1205–1250 vs `main.rs` L100–154 |

### Proposed new IA (see §9 for details)

Four sections, never more than six items each:

```
Overview     →  /            (one page, dense-light)
Agents       →  /agents      (existing, simplified tabs)
Memory       →  /memory      (existing, simplified tabs)
Activity     →  /activity    (Action log + History merged)
Trust        →  /trust       (Trust + Compliance + Safety + Disputes folded as tabs)
Workflows    →  /workflows   (Workflows + CLS Catalog/Builder/Packages/Execution folded)
Apps         →  /apps        (Plugins + Marketplace + DevGuard/TraceTramp/WitnessCtl)
Monitor      →  /monitor     (Monitor + Service Map + Topology + Infra folded)
Settings     →  /settings    (Billing + License + Webhooks + Notifications + Secrets + Domains)
More…        →  expandable     (Notebook, Pipeline, Experiments, Prompts, Insights,
                                Economy, Verify, Debug, Orchestrator, Books, Grounding, Context)
```

Everything in "More…" stays *reachable*, but it leaves the daily eye-line.

---

## 3. Overview page — too many endpoints, too many narratives

`pages/overview.rs` is 686 lines and fetches **12 separate resources** on first
paint (`surface`, `trust`, `health`, `cost`, `books_ledger`, `license`,
`agents`, `activity`, `gateway`, `incidents`, `approvals`, `compliance`,
`proof`). It then renders:

1. A "Plugins & isolation" hint bar with two inline links.
2. A 6-panel surface package (Summary / Ops / Identity / Trust / Evidence /
   Exec) — these are the same panels that `OperatorShell` re-renders at
   `/command-center`. (`overview.rs` L65–80, `operator_shell.rs` L58–69.)
3. A 4-column "top row": Active Incidents, Pending Approvals, Proof Activity,
   Compliance score.
4. An "Operator Actions" toolbar with 5 buttons (Compliance, Tools, Command
   Center, State snapshot, Action log).
5. A 4-column "hero" row: Trust Gauge, Platform Status (which embeds an
   LLM-gateway sub-card showing routed provider/model/router/stub), License
   tier + a placeholder progress bar with literal text *"Live from license
   backend"* (string, not data), Spend snapshot.
6. A "Spend provenance" card whose body literally explains the two cost
   backends to the operator: *"Kernel (A): GET /api/v1/monitor/cost-dashboard
   — kernel_agent_control_block_runtime_totals, scope … Books (B): GET
   /api/v1/books/costs?period=month — JWT-scoped billing_usage_events …"*
   That is **internal architecture leaking onto the landing page**.
7. A 6-card cost metrics row (Kernel $, Books $, Kernel tokens, Books tokens,
   Agents filtered, LLM calls node) duplicating signal from the hero row.
8. An Active Agents table + a Live Activity feed (good — keep these).
9. A "System Resources" row with four progress bars that are all
   hard-coded to `width: 100%` regardless of actual data (look at
   `overview.rs` L646–675). That's a visual lie.

### Findings

- 3.1 — **Two overview pages.** `/` (Overview) and `/command-center`
  (OperatorShell) render the same canonical surface package and overlap ~70%.
  Decide one. Recommend: keep `/` as the *single* daily landing; demote
  OperatorShell to an embedded "Worklist" tab inside Overview, or delete it.
- 3.2 — **Stop printing API paths as primary copy.** Operators don't need to
  read `GET /api/v1/monitor/cost-dashboard` in the body of the landing page.
  Move those to `title=` tooltips on a small `?` icon, or to the `/debug` page.
- 3.3 — **The "Spend provenance" essay** does not belong on Overview at all.
  It's a footnote for finance/ops once they've already understood Books.
  Move it to `/books` (or `/settings/usage`).
- 3.4 — **Fake progress bars.** Each `System Resources` cell unconditionally
  paints `width: 100%`. Either bind the bar to real data or remove the bars
  and keep the four key/value rows.
- 3.5 — **No empty-state.** A fresh node with no agents, no activity, no
  incidents looks identical to a broken node — em-dashes everywhere. Add a
  first-run state (see §5).
- 3.6 — **The "Operator Actions" toolbar duplicates the sidebar.**
  Compliance, Tools, Command Center, Action log are all one click in the
  sidebar already.

### Target Overview composition (skinny)

```
┌─ Header: title  · Live dot  · Search · Bell · Profile ────────┐
│
│ [ Welcome card ] (first run only — see §5)
│
│ [ Worklist (3 cells) :  Open incidents · Pending approvals ·
│                         Trust score                          ]
│
│ [ Active Agents table ]   [ Live Activity feed ]
│
│ [ "Spend this month: $X · Trust grade B+ · 4 plugins · 12 agents" ]
│
│ ↓ "Show more details" expander → cost cards, gateway info, etc.
└────────────────────────────────────────────────────────────────┘
```

Fetch budget on first paint: `surface_client::overview_system` (1 call),
`/agents` (1), `/actionlog/actions?limit=20` (1). Everything else lazy on tab
or expander.

---

## 4. Per-page tab explosion

Tab counts from `pages/*.rs::enum Tab`:

| Page | Tabs | Worst-tab-named offender |
|---|---:|---|
| `agents.rs` | **11** | `Sandbox`, `ContractApps`, `Lifecycle` next to `Overview` |
| `memory.rs` | **10** | `AgentOs`, `Inspector`, `Isolation`, `Lineage`, `Proof`, `Export` |
| `monitor.rs` | **10** | `Anomalies`, `Budget`, `Cost`, `Signals`, `Slos`, `Storage`, `Forecast` |
| `debug.rs` | 7 | mixed |
| `compliance.rs` | 7 | `GdPr`, `EuAiAct`, `Hipaa` all as siblings of `Findings` |
| `trust.rs` | 6 | `Scitt`, `Merkle` as primary tabs |
| `protocols.rs` | 6 | `Cnp`, `Mcp`, `A2A`, `Acp`, `Anp`, `Ap2` (acronyms-only) |
| `tools.rs` | 5 | mixed |
| `pipeline.rs` | 5 | mixed |
| `infra.rs` | 5 | mixed |
| `verify.rs` | 4 | mixed |
| `books.rs` | 4 | mixed |
| `safety.rs` | 3 | mixed |
| `notifications.rs` | 3 | mixed |
| `billing.rs` | 3 | mixed |

11 tabs on one page is a navigation system, not a tab strip. Operators are
forced to memorize what each tab does because the labels are nouns from the
backend (`AgentOs`, `ContractApps`, `Scitt`, `Merkle`, `Cnp`, `Ap2`) not verbs
from the operator's job ("inspect", "approve", "investigate").

### Per-page fix sketches

- **`memory.rs` (10 → 3 tabs).** Collapse to **Browse / Write / Audit**.
  Browse = current `AgentOs` + `Graph` + `Timeline` + `AgentTree`. Write =
  current `Write` + `Inspector`. Audit = current `Lineage` + `Isolation` +
  `Proof` + `Export`. Also: **remove the API-endpoint dump** in the top card
  (L55–68) — that 7-bullet list of `POST /api/v1/memory/write`,
  `GET /api/v1/memory/recall/...` etc. is developer reference docs, not
  operator UX. Move to `?` tooltips and to `docs/`.
- **`agents.rs` (11 → 4 tabs).** Collapse to **Overview / Activity / Trust &
  Compliance / Lifecycle**. Existing `Runtime`+`Sandbox`+`Tools`+`Memory`
  belong under Activity; `Trust`+`Compliance` merge; `Trace`+`Reports`+
  `ContractApps` go under Lifecycle.
- **`monitor.rs` (10 → 4 tabs).** **Health / Cost / Anomalies / Forecast**.
  `Llm`+`Tools`+`Signals`+`Slos`+`Storage` become sub-sections inside Health.
  `Budget` merges into Cost.
- **`compliance.rs` (7 → 3 tabs).** **Scorecard / Findings / Frameworks**.
  GDPR / EU-AI-Act / HIPAA become items in a single dropdown inside the
  Frameworks tab. (Frameworks proliferate — you can't have one top-tab per
  framework or you'll need 12 tabs by year-end.)
- **`protocols.rs` (6 → 1 page).** Operators shouldn't have to know the
  protocol acronyms. Replace tabs with a single connection list ("MCP server
  · A2A peer · CNP listener") with the protocol shown as a chip on each row.
- **`trust.rs` (6 → 3 tabs).** **Score / Receipts / Proofs**. `Scitt` and
  `Merkle` are implementation details — fold them into Proofs.

Rule of thumb to write down in `AGENTS.md`: **no page may have more than 4
top-level tabs**. If you need more, add a second filter/control row inside
the tab body, not another tab.

---

## 5. Onboarding — what exists today, what's missing

What exists:

- `/trial` (`pages/trial.rs`) — a standalone email-gated 90-min playground
  flow that issues an API key and three plugin endpoints. **Uses raw inline
  `style="…"` instead of Tailwind**, which makes it visually disconnected
  from the rest of the app and bypasses the design system.
- `/connect` (`pages/connect_landing.rs`) — a "DevGuard Playground" flow
  letting the user pick a tool (Cursor/Windsurf/Claude Code/Generic) and get
  a Base URL + token.

What's missing — the actual gap a first-time operator hits:

1. **No first-run wizard** inside the authenticated shell. The moment they
   sign in (or hit `Dev Bypass`), they land on the 9-section Overview with
   em-dashes everywhere and 47 sidebar links, with zero context about what
   to do next.
2. **No tour / "what is this view?" affordances.** No `?` icons, no "Show me
   how" buttons, no annotated empty states.
3. **No deployment-state detection.** The UI does not know "this node has
   never had an agent" vs "this node had 200 agents but they're all paused"
   — both render identically.
4. **`/trial` and `/connect` are not linked from the dashboard.** They are
   marketing-adjacent flows reachable only by URL.

### Recommended onboarding flow (post-auth, in-shell)

Add a new component `components/onboarding.rs` that:

1. On Overview, when `agents.len() == 0 && action_log.len() == 0`, replaces
   the page body with a **Welcome card**:
   - 3 numbered steps: (1) Connect your first tool → links to `/apps`,
     (2) Create your first agent → opens a modal, (3) Run a workflow →
     `/workflows`. Each step shows ✓ once detected.
   - "Skip and explore" link that sets `localStorage["onboarding_dismissed"]`
     so the welcome card doesn't reappear.
2. **Inline "what does this do?" cards** on every page's first visit (track
   per-page in localStorage), one sentence + a docs link. Auto-dismiss on
   second visit.
3. **Connect/Trial entry surfaced inside the shell.** Add a sidebar entry
   "Connect a tool" (`/connect`) under Apps for first-time operators —
   currently you can only get there by URL.
4. **Restyle `/trial`** to use the same Tailwind tokens as the rest of the
   app (`page-wrapper`, `card`, `btn-primary`). Inline `style=""` should not
   exist in this codebase.

### Empty-state pattern

Replace the current "—" everywhere with: small icon + one-line explanation
+ primary action button. Example for Overview → Active Agents:

> *No agents yet.*
> *Agents are the running workloads governed by this node.*
> **[ Create agent ]   [ Read the docs ]**

---

## 6. Legacy / dead / duplicated surfaces

A non-exhaustive list of debris from earlier iterations that has accreted in
`pages/`:

| Surface | Status | Recommendation |
|---|---|---|
| `pages/operator_shell.rs` (`/command-center`) | Duplicates Overview + adds raw JSON `<details>`. First paragraph is literally API endpoint documentation. | Delete or fold into Overview as a "Worklist" tab. |
| `pages/settings_custom_domains.rs` | 474 lines, no route in `main.rs`, no sidebar entry. | Either register the route (`/settings/custom-domains`) and link from Settings, or delete. |
| Hard-coded CLS Execution link `/cls-execution/pkg-basic-tool-agent` | Sidebar pins one example package id. | Drop the sidebar entry; reach Execution from inside CLS Catalog/Packages rows. |
| `connect_landing.rs` (`/connect`) | Operator-relevant tool-connect flow that lives outside the shell with its own custom header. | Re-skin to live inside the standard `<Header>`+sidebar shell so operators don't lose context. |
| `trial.rs` (`/trial`) | Inline `style=""` everywhere, not Tailwind. | Restyle to design system; ship as one of two entry points to a single "Welcome / Connect" flow. |
| `SearchModal` items list (`layout.rs` L1205–1250) | Hard-coded, already drifts from `main.rs` route table. | Generate from a single `routes::REGISTRY` source so they stay in sync; or query the backend for searchable entities (agents, plugins, runs). |
| `PluginsNavSection` duplicates "Apps Hub" + "Service Map" entries from `nav_sections()`. | Visible duplication in sidebar. | Pick one section; show plugin items as a nested group under "Apps". |
| `Overview` "Operator Actions" toolbar | Buttons that duplicate sidebar links. | Delete. |
| `Overview` "Spend provenance" essay | Internal architecture exposition. | Move to `/books` or `/settings/usage`; replace with one-line summary. |
| `Memory` top card with 7 raw API endpoints | Reference doc in operator UI. | Move to docs site / `?` tooltip per tab. |
| `Overview` "System Resources" fake progress bars | Hard-coded `width: 100%`. | Bind to data or remove. |
| Sign-out button in profile dropdown | No `on:click` handler — visually present but inert. | Wire to `logout()` or remove (sign-out exists in sidebar). |

---

## 7. Login & dev-bypass leakage

`pages/login.rs` plus `index.html`:

- 7.1 — **Login screen leads with a yellow `Dev bypass is always available`
  warning banner (L56–69) above the form.** A first-time real operator sees
  a warning before they see the input. Move below the form, or behind a
  collapsed "Developer options".
- 7.2 — **`index.html` ships `data-dev="1"` on `<html>`.** `main.rs` L57–69
  reads this attribute and **silently auto-bypasses auth** when set. That
  attribute is *checked into the repo*. If a release pipeline forgets to
  swap `index.html` → `index.release.html`, every signed-in user is
  super_admin. This is a footgun. Fix: invert the default so dev mode must
  be explicitly opted-in via a build flag, not the HTML.
- 7.3 — The "Dev Bypass — Skip Auth" full-width amber button at the bottom
  of the login screen is present in every build. Hide it behind the same
  flag.
- 7.4 — Login form has **no error recovery hint** when the key is rejected
  beyond the literal API message. Add: "Get a new key from the portal →"
  shortcut on 401.

---

## 8. Cross-cutting cosmetic & consistency issues

- 8.1 — **Internal API paths shown as primary copy.** Found on:
  Memory (top card 7 bullets), OperatorShell (top paragraph), Overview
  ("Spend provenance"), notifications popup (`GET /api/v1/notifications`
  shown next to "Notifications" headline). Move all of these to tooltips
  or `/debug`.
- 8.2 — **Inline `style=""` attributes.** `pages/trial.rs` uses raw inline
  CSS throughout — colors `#3ecf8e`, `#6366f1`, `#f59e0b` hardcoded. Every
  other page uses Tailwind. Unify.
- 8.3 — **Mixed colour vocabularies.** Indigo + purple + emerald + amber +
  rose + sky + violet + fuchsia + orange all appear as accent colours. The
  notifications row alone uses six (`notif_severity_pill_class`). Define a
  6-token palette (`brand`, `success`, `warn`, `danger`, `info`, `muted`)
  and forbid arbitrary Tailwind colour names in new code.
- 8.4 — **Inconsistent terminology.** "Active Agents" (Overview) vs "Fleet /
  worklist (agents)" (OperatorShell) vs "Agents" (sidebar). "Compliance" vs
  "Trust & Safety" vs "Safety (formal)". "Action Log" vs "Activity" vs
  "Timeline". Pick one name per concept.
- 8.5 — **`pretty_json` and `details/summary` JSON dumps** appear on many
  pages (OperatorShell, Memory, Verify, Debug). These are dev affordances
  bleeding into operator pages. Hide behind a single feature flag
  ("Developer view") in Settings.
- 8.6 — **Skeleton vs spinner vs em-dash** are inconsistent loading
  treatments across pages. Pick one — recommend `Skeleton` for tables and
  `<PageLoading/>` for sections.
- 8.7 — **No mobile/narrow-width treatment.** Sidebar is always 240 px /
  64 px collapsed; many pages set `xl:grid-cols-3` which fails to single
  column gracefully on tablets. Mobile is a P2, but operators on the field
  use iPads.
- 8.8 — **Accessibility.** Most icon-only buttons have `title=` but no
  `aria-label`. Most `<button>` colour-contrast pairs (e.g. `text-zinc-500`
  on `bg-zinc-900`) fail WCAG AA. The pulsing red `Unavailable` dot has no
  text alternative — screen readers get nothing.
- 8.9 — **Re-fetch on every navigation.** `Header` reads `pathname.get()`
  inside both the `/monitor/health` and `/notifications` resources purely
  to invalidate them on navigation. That means every link click fires two
  background requests on top of the page's own resources. Use a single
  store-level resource updated by an explicit signal.

---

## 9. Proposed new IA + onboarding (concrete)

### 9.1 Sidebar (final shape)

```
┌─ "C" Connector · Agent OS                      « ─┐
│
│   ⚪ OVERVIEW
│   ────────────
│   ◾ Overview                   /
│   ◾ Agents                     /agents
│   ◾ Memory                     /memory
│   ◾ Activity                   /activity      (= action log + history)
│
│   ⚪ TRUST
│   ────────────
│   ◾ Trust                      /trust         (Score + Receipts + Proofs)
│   ◾ Compliance                 /compliance    (Scorecard + Findings + Frameworks)
│   ◾ Safety & Firewall          /safety        (Invariants + Rules + Disputes)
│
│   ⚪ BUILD
│   ────────────
│   ◾ Workflows                  /workflows     (Workflows + CLS suite)
│   ◾ Apps                       /apps          (Plugins + Marketplace + Connect)
│   ◾ Monitor                    /monitor       (Health + Cost + Anomalies + Topology)
│
│   ⚪ SETTINGS
│   ────────────
│   ◾ Billing                    /billing
│   ◾ License                    /license
│   ◾ Settings                   /settings      (incl. Webhooks, Notifications,
│                                                 Secrets, Custom Domains)
│   ◾ More…                      ⌃ expandable   (Notebook, Pipeline, Experiments,
│                                                 Prompts, Insights, Economy,
│                                                 Verify, Debug, Orchestrator,
│                                                 Books, Grounding, Context,
│                                                 Multi-Agent, Protocols, Tools,
│                                                 Service Map, Topology Center,
│                                                 Runtime Enforcement, Report
│                                                 Center, Infra)
│
└─ user · ⏻ sign out ────────────────────────────────┘
```

10 visible items, the rest one click away in **More…**. The rule is *every
existing route still works* — we are reorganizing, not deleting.

### 9.2 Onboarding flow

Triggered when `localStorage["onboarding_completed"] != "1"`:

1. **Welcome card** on Overview (replaces body, sidebar still visible):
   - "Welcome to Connector. Three steps to get governed AI running."
   - Step 1 — *Connect a tool* (link → `/apps`, ✓ when `gateway/status`
     reports at least 1 routed call in the last hour)
   - Step 2 — *Create an agent* (opens existing agents/Create modal, ✓ when
     `GET /agents` returns ≥ 1)
   - Step 3 — *See a receipt* (link → `/trust`, ✓ when at least 1 receipt
     exists)
   - "Skip and explore" link in the corner.

2. **Per-page first-visit tooltips** (one-shot, tracked per page in
   localStorage): a small card pinned under the page header explaining what
   the page is for in one sentence + a docs link.

3. **`/connect` and `/trial` come inside the shell** (not standalone). Add
   to the Apps page as the first cards. Restyle `/trial` to Tailwind.

### 9.3 Header (final shape)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Overview       ● Live · 12s ago       [⌘K Search]  [🔔 3]  [👤 Umesh ▾] │
└─────────────────────────────────────────────────────────────────────────┘
```

- The Live dot is a clickable pill — opens a small popover with the same
  info that's currently splattered across the in-header banner (message,
  chips, provenance).
- Clicking it navigates to `/monitor`. Hovering shows last 5 health checks.
- Bell shows numeric badge for unread; popover keeps current design but
  trimmed (no second `GET /api/v1/notifications` echo in the header).
- Search is single-key (`⌘K` / `Ctrl+K`) — bind a global keydown handler in
  `App` (`main.rs`).

---

## 10. Prioritized fix plan (do these in order)

Each row names the file(s) to touch and what to delete vs change.

### P0 — Ship-blockers / awkward visuals the user explicitly called out

| # | Title | Files | Action |
|---|---|---|---|
| P0-1 | **Slim the header.** Replace `StatusBanner` inside `<Header>` with a `LiveDotPill` component. Delete `HeaderSubsystemStrip` from header. Make first-fetch state neutral (`Checking`), not red `Unavailable`. | `components/layout.rs` L931–1197, `components/status_banner.rs` | Create `components/live_dot_pill.rs`. Move `StatusBanner` to `components/system_health_card.rs` (used by Overview/Monitor only). |
| P0-2 | **Fix dev-bypass leakage.** Remove `data-dev="1"` from `index.html`; gate the bypass on a Trunk env var. Remove the amber warning banner from above the login form; move "Developer options" below the form, collapsed. | `index.html`, `pages/login.rs` | One-shot edit. |
| P0-3 | **Fix dead Sign-Out button** in profile dropdown. Wire to `logout()` or remove. | `components/layout.rs` L1179–1182 | One-line fix. |
| P0-4 | **Remove fake progress bars.** Overview "System Resources" four bars all `width: 100%`. Either bind or remove. | `pages/overview.rs` L645–675 | Delete bars, keep key/value rows. |
| P0-5 | **Drop hard-coded CLS Execution sample id** from sidebar. | `components/layout.rs` L53 | Delete that NavItem or replace with `/cls-catalog` deep-link. |
| P0-6 | **Stop printing raw API paths as primary copy.** | `pages/overview.rs` (Spend provenance), `pages/memory.rs` L55–68, `pages/operator_shell.rs` L29–36, header notifications popup | Move to `title=` tooltips. |

### P1 — Reduce surface area & rebuild IA (the main user complaint)

| # | Title | Files | Action |
|---|---|---|---|
| P1-1 | **New 4-section sidebar** (per §9.1) with "More…" expandable group. | `components/layout.rs::nav_sections()` | Rewrite. Keep all routes alive; only re-section. |
| P1-2 | **Remove sidebar duplication.** Apps Hub × 2, Service Map × 2, Marketplace × 2. | `components/layout.rs` L48, L75, L152, L207, L89 | Pick one location each. |
| P1-3 | **Collapse Overview to "skinny + expander"** (per §3). Cut from 12 resources to 3 on first paint. Delete the "Operator Actions" toolbar and the "Spend provenance" essay. Move cost details behind `<details>` "Show more". | `pages/overview.rs` | Major rewrite — pull surface components into a small `<OverviewSkinny/>` + `<OverviewMore/>`. |
| P1-4 | **Merge `/command-center` into `/`.** Demote `OperatorShell` to `<WorklistTab/>` inside Overview, or delete entirely. Remove its sidebar entry. | `pages/operator_shell.rs`, `main.rs` L141, `components/layout.rs` L25 | Decide → consolidate. |
| P1-5 | **Cap tab counts at 4** on every page. Apply to `memory.rs` (10 → 3), `agents.rs` (11 → 4), `monitor.rs` (10 → 4), `compliance.rs` (7 → 3), `trust.rs` (6 → 3), `debug.rs` (7 → 3), `protocols.rs` (6 → 0; replace with list). | `pages/{memory,agents,monitor,compliance,trust,debug,protocols}.rs` | Refactor tab enums per §4. |
| P1-6 | **Generated SearchModal index.** Build the index from `main.rs` routes and live agents/plugins, not from a hard-coded 35-item list. | `components/layout.rs::SearchModal`, new `routes.rs` registry | One-time + maintainable. |
| P1-7 | **In-shell onboarding.** Welcome card on Overview when fresh; per-page first-visit tooltips. | new `components/onboarding.rs`; touch `pages/overview.rs` | See §9.2. |

### P2 — Polish & consistency

| # | Title | Files | Action |
|---|---|---|---|
| P2-1 | **Restyle `/trial` to Tailwind.** Remove all inline `style=""` attributes; reuse `page-wrapper`, `card`, `btn-primary`, etc. | `pages/trial.rs` | Mechanical rewrite. |
| P2-2 | **Bring `/connect` inside the shell** (header + sidebar). | `pages/connect_landing.rs` | Wrap in standard layout. |
| P2-3 | **Decide on `settings_custom_domains.rs`** — register or delete. | `pages/settings_custom_domains.rs`, `main.rs` | If kept, add `<Route path="/settings/custom-domains">` and a link from Settings. |
| P2-4 | **Define a 6-token colour palette** (`brand`, `success`, `warn`, `danger`, `info`, `muted`) in `input.css`. Forbid raw `text-{indigo,purple,emerald,...}-*` in new code via a CSS lint rule. | `input.css`, `AGENTS.md` | Add lint section to AGENTS.md. |
| P2-5 | **Single loading treatment.** `<PageLoading/>` for whole sections, `<Skeleton/>` for tables. Audit and standardise. | most `pages/*.rs` | Mechanical. |
| P2-6 | **A11y pass.** `aria-label` on icon-only buttons; bump zinc-500-on-zinc-900 contrast to zinc-400; add `role="status"` + `aria-live="polite"` to the LiveDotPill; provide text alt for the pulsing dot. | `components/layout.rs`, `status_banner.rs` | Per-file fixes. |
| P2-7 | **Stop double-fetching `/monitor/health` and `/notifications`** on every navigation. Use a single store-level resource with an explicit reload signal. | `components/layout.rs` L938–945 | One refactor. |
| P2-8 | **Glossary / terminology unification.** "Agents" everywhere; "Activity" everywhere; "Trust" not "Safety (formal)". | `components/layout.rs`, all page titles | Mechanical. |
| P2-9 | **Move all developer JSON dumps behind a "Developer view" toggle** in Settings (localStorage flag). Hides `<details>JSON</details>` blocks in OperatorShell, Memory, Verify, Debug. | `pages/settings.rs`, several others | One flag + conditional rendering. |
| P2-10 | **Mobile sweep.** Audit every `xl:grid-cols-3` for graceful fallback; sidebar becomes drawer ≤ md. | `components/layout.rs`, several pages | Time-boxed. |

---

## 11. Acceptance criteria

A first-time operator opening the dashboard on a fresh node should:

1. See a calm header with one status indicator, not a wrapping red banner.
2. See a sidebar with **≤ 10 visible items** organised under **≤ 4** headings.
3. Land on an Overview that fits in one viewport on a 1440×900 laptop and
   shows them what to do next when nothing exists yet.
4. Be able to click ≤ 3 times from sign-in to "connect a tool / create an
   agent / view a receipt".
5. Never see a raw API path (`GET /api/v1/...`) as primary body copy on any
   page reachable from the sidebar.
6. See no "DEV BYPASS" controls unless the build was explicitly compiled
   with the dev flag.

When all P0 + P1 items in §10 are merged, these are met.

---

## 12. Appendix — useful inventory tables

### A. Routes registered in `main.rs` (one per line)

```
/login                          /connect                         /trial
/                               /agents                          /memory
/monitor                        /compliance                      /debug
/tools                          /protocols                       /safety
/infra                          /actionlog                       /history
/pipeline                       /trust                           /disputes
/insights                       /experiments                     /prompts
/notebook                       /multiagent                      /notifications
/webhooks                       /grounding                       /economy
/marketplace                    /runtime-enforcement[/:sandbox_id]
/topology-center                /service-map
/report-center[/:receipt_id]    /apps                            /workflows
/cls-catalog[/:id]              /cls-builder                     /cls-packages[/:id]
/cls-execution/:id[/:run_id]    /context                         /command-center
/firewall                       /orchestrator                    /verify
/secrets                        /billing                         /license
/settings                       /books                           /plugins
/plugins/devguard               /plugins/tracetramp              /plugins/witnessctl
/plugins/marketplace
```

Total: 46 distinct route paths. None of them goes away in this proposal —
they are re-organised under the new IA so most are reached via "More…" or via
the consolidated parent pages.

### B. Tab inventory (verbatim from `enum Tab` declarations)

```
agents       (11)  Overview, Runtime, Sandbox, Memory, Tools, Trace, Trust,
                   Compliance, Lifecycle, ContractApps, Reports
memory       (10)  AgentOs, Write, Graph, Timeline, AgentTree, Inspector,
                   Isolation, Lineage, Proof, Export
monitor      (10)  Health, Llm, Anomalies, Budget, Cost, Tools, Signals,
                   Slos, Storage, Forecast
debug         (7)  Sessions, Trace, Reasoning, ToolTrace, Memory, Diff,
                   Failures
compliance    (7)  Scorecard, DataTruth, Findings, GdPr, EuAiAct, Hipaa,
                   Reports
trust         (6)  Score, ReportCenter, ProofIndex, Receipts, Scitt, Merkle
protocols     (6)  Cnp, Mcp, A2A, Acp, Anp, Ap2
tools         (5)  Bridges, Invoke, Approvals, Signals, Cgroups
infra         (5)  Consensus, Reputation, Vault, Quota, Orchestrator
pipeline      (5)  Gate, Steps, Integrity, CidChain, Definitions
books         (4)  Position, Journal, Costs, Reconcile
verify        (4)  Formal, Summary, Violations, Snapshot
safety        (3)  Invariants, Claims, Grounding
notifications (3)  Active, History, Schedule
billing       (3)  Usage, Entitlements, Invoices
license       (3)  Status, Machine, Heartbeat
experiments   (3)  List, Datasets, Actions
firewall      (3)  Baselines, Adjustments, FalsePositives
webhooks      (2)  Endpoints, Events
orchestrator  (2)  DagPipelines, Sagas
marketplace   (4)  Index, Rankings, Contracts, Discover
```

Total tabs across the app: **108**. Target after P1-5: ~50.

### C. Largest page files (lines of code)

```
1046  compliance.rs
 871  workflows.rs
 794  cls_builder.rs
 692  agents.rs
 686  overview.rs
 660  memory.rs
 658  books.rs
 634  settings.rs
 486  actionlog.rs
 474  settings_custom_domains.rs   ← orphan, see §6
 437  cls_packages.rs
 406  apps.rs
 370  operator_shell.rs            ← merge candidate, see §3.1
 368  connect_landing.rs
 360  runtime_enforcement.rs
```

Pages over ~500 lines are the right targets for tab-collapsing in P1-5.

---

## 13. Core selling products & pre-made workflows must be in main highlights

> User feedback round 2: *"make sure all per made workflows are core selling
> products it should be in main highlights."*

This is a real, concrete gap, not a rephrasing of §3. The dashboard currently
treats the **shipped products** like they were random feature pages rather
than the things customers actually pay for.

### 13.1 Mismatch: 9 marketed plugins vs 3 surfaced in dashboard

The marketing site (`platform/docs/landing-page/web/src/components/Nav.tsx`
lines 4–14) advertises **9 plugins** as products with megamenu cards:

```
DevGuard       — Policy & secret enforcement
TraceTramp     — Full execution tracing
Conductor      — Multi-agent orchestration
AgentLoop      — Agent lifecycle management
LedgerLens     — Cost & budget control
WitnessCtl     — Cryptographic audit receipts
AgentPassport  — Agent identity (DID)
Relay          — Zero-framework runtime
Engram         — Enterprise memory
```

All 9 exist under `plugins/` and have first-party crates. The dashboard
sidebar (`components/layout.rs::PluginsNavSection`) surfaces only **3** of
them — DevGuard, TraceTramp, WitnessCtl. The other six (Conductor,
AgentLoop, LedgerLens, AgentPassport, Relay, Engram) are reachable only via
the generic `/plugins` hub list, with no dedicated card on the home page and
no headline treatment.

A first-time operator who saw the marketing site and bought the platform
opens the dashboard and finds 1/3 of the product line missing from the
sidebar.

### 13.2 Pre-made workflows: shipped but buried

`platform/server/resources/workflow_templates/` contains **three production-
ready CCL workflow templates**:

```
pii_redaction_pipeline.ccl     ← PII detection + redact + audit
incident_slack_jira.ccl        ← Alert → Slack → open Jira ticket
hitl_approve_audit.ccl         ← Human-in-the-loop approval + receipt
```

These are *the* shipped pre-made workflows — the equivalent of "templates"
in any SaaS product. They are served via `GET /api/v1/workflows/reference-
templates` and consumed by `pages/cls_catalog.rs` lines 41–80, which renders
them as a small inner card grid inside a card titled "Reference workflow
templates (Phase 3.11)" — the phrase **"Phase 3.11"** is then printed to
operators as primary copy.

The reference templates also exist under `examples/agos-reference-plugins/`
as full plugin crates:

```
acme-datadog-forwarder/        ← forwards events to Datadog
acme-jira-bridge/              ← creates Jira issues from receipts
acme-slack-notifier/           ← posts incidents to Slack
```

None of these six pre-made artifacts (3 CCL workflows + 3 reference plugins)
are surfaced on `/`, `/apps`, or anywhere a first-time operator looks first.
They are reachable as follows:

| Asset | Current reach (clicks from sign-in) |
|---|---|
| `pii_redaction_pipeline.ccl` | Sidebar → CLS Catalog → scroll → "Open in Builder" → Builder → compile → Packages → Register (5+) |
| `acme-slack-notifier` | Sidebar → All Plugins → scroll to plugin (3+) — *if* it's even installed |
| 6 marketed plugins (Conductor etc.) | Sidebar → All Plugins → scroll (3) |

A "core selling product" that takes five clicks to reach is not a core
selling product — it is a footnote.

### 13.3 The "Workflows" page actively hides the pre-mades

`pages/workflows.rs` (871 lines, second-largest) opens with:

> *"Phase 3 control plane. Registered workflows use the CLS engine + CNP
> dispatch contract. Use Builder and Packages for authoring; dry-run and
> lifecycle transitions are handled here."*

That sentence is for an internal engineer, not for a customer. There is no
"Try one of our pre-built workflows" call-to-action, no template card grid,
no empty-state hero — when the workflow list is empty, the page literally
tells the user: *"No workflows registered yet. Create CLS source in the
Builder, then register under Packages or POST /api/v1/workflows"*. That is
asking the customer to author a workflow before showing them the **three
shipped ones** they already own.

The hard-coded button `<a href="/cls-execution/pkg-basic-tool-agent">` on
line 152 of `workflows.rs` is the same broken pin as in the sidebar (P0-5)
— a sample package id is treated as the canonical entry point.

### 13.4 Fix — restructure Apps + Overview to lead with products

**13-A. `/apps` (`pages/apps.rs`) becomes a real product gallery.**

Replace the current three-section layout (Dev Apps / Server Apps / Workflows)
with a **two-level layout**:

```
┌─ Apps & Workflows ─────────────────────────────────────────────────────┐
│                                                                        │
│  ★ FEATURED                                                            │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐         │
│  │ DevGuard        │ │ TraceTramp      │ │ WitnessCtl      │         │
│  │ Enforce policy  │ │ Trace every call│ │ Cryptographic   │         │
│  │ on AI tools     │ │ to your LLMs    │ │ audit receipts  │         │
│  │ [ Set up → ]    │ │ [ Set up → ]    │ │ [ Set up → ]    │         │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘         │
│                                                                        │
│  PRE-BUILT WORKFLOWS — drop-in templates                               │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐         │
│  │ PII Redaction   │ │ Incident →      │ │ Human-in-loop   │         │
│  │ Pipeline        │ │ Slack + Jira    │ │ approval audit  │         │
│  │ [ Install → ]   │ │ [ Install → ]   │ │ [ Install → ]   │         │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘         │
│                                                                        │
│  ALL PLUGINS (9)                                                       │
│  Conductor · AgentLoop · LedgerLens · AgentPassport · Relay · Engram  │
│  · DevGuard · TraceTramp · WitnessCtl                                  │
│                                                                        │
│  EXAMPLE INTEGRATIONS                                                  │
│  acme-slack-notifier · acme-jira-bridge · acme-datadog-forwarder       │
│                                                                        │
│  CUSTOM — build your own                                               │
│  [ Open CLS Builder → ]                                                │
└────────────────────────────────────────────────────────────────────────┘
```

The three Featured plugins are configurable (`featured_plugins` in
`connector.yaml` or a server response field), so deployments can re-rank.
The Pre-built Workflows row pulls directly from
`/api/v1/workflows/reference-templates` and surfaces "Install" — a one-click
shortcut that does `POST /workflows` with the shipped CLS source under the
hood, no Builder detour.

**13-B. Overview gets a "What can you do here?" headline card** (first-run
only, then dismissable):

```
┌─ Get started — try a pre-built workflow ─────────────────────────┐
│  PII Redaction · Incident→Slack+Jira · HITL approval audit       │
│  [ Browse all → /apps ]                                          │
└───────────────────────────────────────────────────────────────────┘
```

Dismissed once `localStorage["featured_dismissed"] = "1"` OR once the
operator has installed any workflow. It also re-appears with a "What's new"
slot when the server reports a `featured_updated_at` newer than the user's
last visit.

**13-C. Sidebar adds the missing 6 plugin entries** under Apps so customers
who paid for "Engram" or "LedgerLens" don't have to hunt:

```
Apps & Workflows
  Featured
  Workflows  (pre-built + your own)
  DevGuard       TraceTramp       WitnessCtl
  Conductor      AgentLoop        LedgerLens
  AgentPassport  Relay            Engram
  All plugins…
```

If `enabled_in_deployment == false` for any plugin, keep the entry visible
but disabled with a "Not enabled in this deployment" tooltip (same pattern
the existing `SidebarPluginNavItem` already uses for DG/TT/WC).

**13-D. Workflow empty-state replaces "POST /api/v1/workflows" copy** with:

```
┌─────────────────────────────────────────────────────────────────┐
│  You have no workflows installed yet.                           │
│                                                                  │
│  Start with one of our pre-built workflows:                     │
│  • PII Redaction Pipeline      [ Install ]                      │
│  • Incident → Slack + Jira     [ Install ]                      │
│  • Human-in-the-loop approval  [ Install ]                      │
│                                                                  │
│  Or [ author your own in the Builder → ]                        │
└─────────────────────────────────────────────────────────────────┘
```

**13-E. Drop "Phase 3 control plane" / "Phase 3.11" labels.** They are
internal milestone names that leaked into product copy. Replace with one
sentence of customer-facing language ("Workflows are reusable, governed
pipelines you can install or author yourself.").

---

## 14. Onboarding — full multi-step wizards (the missing piece)

> User feedback round 2: *"we should have unboarding wizards and all also"*

Section 5 of this report described a welcome card + per-page tooltips. That
is the *bare minimum*. The right shape is a **proper multi-step wizard
system**, mirroring (and partially sharing source with) the existing TUI
wizard plan in `TUI_WIZARDS_MASTER_PLAN.md` at the repo root.

### 14.1 Wizards that should exist in the web dashboard

The TUI plan already defines, in detail, three product wizards plus a
shared boot/unlock flow. The web dashboard should ship the **same wizards**
so an operator who used the TUI yesterday recognises the flow today.

| Wizard | Trigger | What it does | Source already exists in |
|---|---|---|---|
| **First-run setup** | Fresh node, no agents, no workflows | Connect API → workspace detect → pick first plugin to enable → invite teammates | TUI_WIZARDS_MASTER_PLAN.md §"Shared Boot and Unlock" |
| **Connect a tool** | Click "Connect tool" on Apps Hub | Pick Cursor / Windsurf / Claude Code / Kiro / Generic → copy Base URL + token → see live first request | already partially in `pages/connect_landing.rs` — promote into wizard |
| **Install a pre-built workflow** | Click "Install" on a template card | Pick template → preview CLS → choose namespace/agent binding → confirm → land on `/workflows/:id` | NEW |
| **Create your first agent** | Empty-state on `/agents` | Name + namespace → choose role (writer/reviewer/operator) → choose model → set token budget → register | exists as a modal in `pages/agents.rs`, needs promotion to step-wizard with explanations |
| **DevGuard setup** | First time on `/plugins/devguard` | Protection targeting → enforcement layers → tool adapter → policy authoring → dry-run verify | TUI_WIZARDS_MASTER_PLAN.md §"DevGuard Wizard Modules A–E" — port the *same modules* |
| **TraceTramp setup** | First time on `/plugins/tracetramp` | Runtime profile → provider chain → budget/usage → policy route → memory/evidence | TUI_WIZARDS_MASTER_PLAN.md §"TraceTramp Wizard Modules A–E" |
| **WitnessCtl setup** | First time on `/plugins/witnessctl` | Evidence sources → integrity chain → compliance profile (SOC2/HIPAA/GDPR/EU-AI-Act) → PII handling → report delivery | TUI_WIZARDS_MASTER_PLAN.md §"WitnessCtl Wizard Modules A–E" |
| **Set up first budget** | First time on `/billing` or LedgerLens | Pick scope (tenant/team/agent) → token cap → cost cap → alert thresholds → action (warn/throttle/reject) | NEW |
| **Author your first compliance report** | First time on `/compliance` Reports tab | Pick framework → scope → date range → preview → generate → download | from WitnessCtl wizard Module E |

Each wizard is **dismissable** but **resumable** — if the operator quits
halfway, the next visit shows "Resume *Connect a tool* — step 2 of 4 →".

### 14.2 Wizard component primitive (one piece of code, many wizards)

Add `components/wizard.rs`:

```rust
pub struct WizardStep {
    pub id: &'static str,
    pub title: &'static str,
    pub subtitle: &'static str,
    pub body: ViewFn,                 // step body content
    pub can_advance: Box<dyn Fn() -> bool>,  // validation
    pub on_complete: Option<Box<dyn Fn()>>,  // mutation
}

#[component]
pub fn Wizard(
    id: &'static str,                 // localStorage key for resume state
    steps: Vec<WizardStep>,
    on_finish: Callback<()>,
) -> impl IntoView { … }
```

Layout fixed: top progress strip with numbered dots, left optional sidebar
with step list (when ≥ 4 steps), right "Cancel · Back · Next · Finish".
Persistence: write `wizard:<id>` to localStorage with current step + field
values. Resume on next mount.

### 14.3 Wizard hub

Add a dedicated page `/setup` (and a sidebar entry: **`Setup wizards`**
under Settings) that lists all wizards and their state:

```
Setup Wizards
─────────────
✓ Connector connection          Completed · 2 days ago
✓ Connect Cursor                Completed · 2 days ago
○ Install pre-built workflow    Not started      [ Start → ]
◐ DevGuard setup                Resume · step 3 of 5  [ Resume → ]
○ TraceTramp setup              Not started      [ Start → ]
○ WitnessCtl setup              Not started      [ Start → ]
○ First budget                  Not started      [ Start → ]
○ First compliance report       Not started      [ Start → ]
```

This is the operator's "what should I do next" lookup — equivalent to the
TUI's command palette but for guided flows.

### 14.4 First-run guard

On `App` mount in `main.rs`, after `fetch_me`, check
`GET /api/v1/setup/state` (new endpoint, or derived from existing — empty
`agents` + empty `workflows` + missing operator preference flag). If
"never run setup", redirect to `/setup` instead of `/`. Skip-able with
"Take me to the dashboard anyway" link.

### 14.5 Per-page nudges

Independent of full wizards, every page that has natural setup state should
show a one-line **nudge banner** when the operator hasn't completed the
relevant wizard:

> *DevGuard is not configured for this workspace. Take 2 minutes to set up
> enforcement. **[ Start setup ]**  [ Dismiss ]*

Stored in localStorage per `(page, wizard_id)`.

---

## 15. Other gaps I missed (round 2 corrections)

> User feedback: *"few more work i see not written in docs"*

The following items were not in the original report and belong in the fix
plan. They are reflected in the §10 P0/P1/P2 deltas at the bottom of this
section.

### 15.1 Marketing/dashboard product list is out of sync

- 9 plugins advertised on the marketing site → 3 surfaced in the dashboard
  sidebar (§13.1). The dashboard must read its product list from the same
  source the marketing site reads from — either a shared
  `plugins.catalog.json` checked into the repo, or `GET /api/v1/products`
  on the server. Today they will drift again the next time someone ships a
  new plugin.

### 15.2 "Try Me" / "Dive In" path is not wired into the in-app shell

- Marketing CTA: *Try Me → `playgroundUrl`*, *Dive In → `portalSignupUrl`*.
- In-app: `/trial` (own custom HTML) and `/connect` (DevGuard playground)
  are not linked from each other and not from the marketing footer.
- After signing up via portal the operator lands somewhere unspecified —
  there is no canonical post-signup landing inside the dashboard.

Fix: define one **post-signup entry path** (`/welcome` → first-run wizard),
and link it from the marketing "Dive In" CTA, from `/trial` "Continue to
your dashboard", and from email templates.

### 15.3 Customer-paid features hidden behind generic pages

- `LedgerLens` (cost & budget) is a paid product, but the dashboard exposes
  cost & budget under **Monitor → Cost** and **Billing → Usage** with no
  branding/wayfinding back to the LedgerLens product page. A customer who
  paid for LedgerLens has no idea they're already using it.
- Same for `AgentPassport` (agent identity / DID) — *no* current page in
  the dashboard for agent DIDs. The product exists in `plugins/` but has no
  UI.
- Same for `Engram` (enterprise memory) — the `/memory` page is the *generic*
  memory plane and does not flag when Engram features are in use.
- Same for `Relay` (zero-framework runtime) — no UI surface.
- Same for `Conductor` (multi-agent orchestration) — `/multiagent` exists
  but does not say "powered by Conductor" or link to the Conductor product
  page.

Fix: each plugin page (`/plugins/<slug>`) needs to exist for **all 9**
plugins, with a consistent template (overview / setup wizard / usage /
config / receipts). Generic pages should show a small *"You're using
LedgerLens here. **[ About LedgerLens → ]**"* badge.

### 15.4 No "What's new" / changelog surface inside the dashboard

There is a `CHANGELOG.md` at the repo root but no UI to surface releases to
operators. Add a dismissable "What's new in v0.x.y" toast or modal that
reads from `GET /api/v1/release-notes` (or a static `release_notes.json`
shipped with the release).

### 15.5 No "Recommended next steps" engine

After a fresh node is set up, the dashboard has no notion of "what should I
do next?". Recommended:

1. Compute a small set of suggestions server-side from current state
   (`no_workflow_installed` → suggest pre-built; `agents>0 && no_budget` →
   suggest budget setup; `compliance_findings>0` → suggest report).
2. Render top 3 on Overview under "Suggested next steps".
3. Mark dismissed/snoozed per user.

### 15.6 Discoverability of advanced surfaces

After the IA collapse (§9.1), 30+ surfaces move under "More…". Without a
**command palette** (`⌘K`) that searches *routes + pre-built workflows +
plugins + agents + receipts*, these will be unreachable. The current
`SearchModal` is hard-coded and only knows page names (§2.10).

Make `⌘K` first-class: bind it globally in `main.rs::App`, replace the
in-header search button with the same handler, and expand the index to
include:

- All registered routes (auto-generated)
- All pre-built workflow templates (`GET /workflows/reference-templates`)
- All installed plugins (`GET /plugins/status`)
- Live agents (`GET /agents`)
- Recent receipts (`GET /reports/center?limit=20`)
- Wizards (`/setup` items)

### 15.7 No tier / entitlement awareness in UI

The license page reads tier and entitlements, but **no other page reflects
them**. A free-tier user sees the same UI as enterprise, and clicks
features that 403/disable silently. Fix: a single `entitlements` signal in
`App` that hides or grays gated controls with a "Upgrade to unlock" pill
that links to the portal.

### 15.8 Notifications surface vs Incidents surface conflicts

- Header bell → `/notifications` (alerting feed)
- Overview top row → "Active Incidents" (from `/compliance/policy-violations`)
- Compliance tab → "Findings"
- Action log → ad-hoc denial entries

These are four lenses on overlapping data. Either unify under one
`/activity` superset (preferred) or define crisp ownership: bell = ops
alerts, /compliance = framework findings, /activity = chronological log.
Today an operator does not know where to look first when something breaks.

### 15.9 No "Connect a teammate" / multi-user invite flow

The Settings page (`pages/settings.rs`, 634 lines) does not include a user
invite flow. The `admin/` Leptos app has `pages/customers.rs` for that, but
operators inside `dashboard/` can't invite a teammate. Add an "Invite
operator" wizard (one of the items in §14.1).

### 15.10 No mobile/tablet shell at all

Already mentioned in §8.7. Re-emphasising: every public marketing page
works on mobile; the dashboard does not even attempt to. iPad-on-the-floor
is a realistic operator use case for incident response. Drawer-style
sidebar on `md:` and below; everything `xl:` should have an `lg:` fallback.

### 15.11 No "Connector OS" branding consistency

The dashboard says "Connector · Agent OS" in the sidebar logo. The Apps
page says "Connector OS · App Substrate". The marketing site uses just
"Connector". TUI docs say "Connector Platform". Pick one customer-facing
name and use it everywhere.

### 15.12 Pre-made products have no demo data / playground mode

When an operator installs a pre-built workflow on a fresh node, the
workflow runs against an empty system — no sample events to redact, no
incidents to forward to Slack, nothing to approve. Each pre-built workflow
should ship with a **"Run with sample data"** button that synthesizes a few
events and shows the workflow processing them, so the operator sees what
the product does *before* wiring up real sources.

### 15.13 No "Recent" / "Favorites" on the sidebar

With 30+ items in "More…", the operator's daily 5 should be one click.
Track navigation history in localStorage; show "Recent" group at the top of
the sidebar, and a star icon next to every page to pin to "Favorites".

### 15.14 Per-page `<h1>` / `<title>` are inconsistent

Browser tab is always "Connector Platform" (`index.html` line 6). Every
page should set `document.title = "<page> · Connector"` so operators with
many tabs can find the right one. Trivial fix, big QoL win.

### 15.15 No empty-state for "all the things"

Eight + pages render em-dashes when empty (overview, agents, memory,
trust, compliance, monitor, history, action log). Define one **empty
state component** with icon + one-line explanation + primary action, used
everywhere a list is empty.

### 15.16 Hard-coded "pkg-basic-tool-agent" appears in *three* places

- Sidebar: `components/layout.rs` line 53.
- Workflows page button: `pages/workflows.rs` line 152.
- ClsPackages default detail fetch: `pages/cls_packages.rs` line 43.

Pick one canonical "default sample package id" — or, preferably, query the
server for "first installed package" and use that. Today, a fresh node
404s on all three.

---

## 10b. Additions to the prioritized fix plan (round 2)

These rows are added to the §10 plan. Numbering continues from §10.

### P0 — round 2

| # | Title | Files | Action |
|---|---|---|---|
| P0-7 | **Lead with pre-built workflows on `/apps`.** Implement §13.4-A (Featured + Pre-built Workflows + All Plugins + Examples). Drop "Phase 3.11" label. | `pages/apps.rs`, `pages/workflows.rs`, `pages/cls_catalog.rs` | Replace the current 3-section card layout. |
| P0-8 | **One-click install** for the 3 shipped reference workflows. Each template card on `/apps` gets `[ Install ]` that POSTs `/workflows` with the CCL source, no Builder hop. | `pages/apps.rs`, `pages/workflows.rs` empty-state | New `install_reference_workflow(id)` helper. |
| P0-9 | **Surface all 9 marketed plugins in the sidebar** (Conductor, AgentLoop, LedgerLens, AgentPassport, Relay, Engram added). Disabled state for `enabled_in_deployment=false`. | `components/layout.rs::PluginsNavSection` | Extend the existing 3 to 9 entries. |
| P0-10 | **Workflows empty-state rewrite** — replace "POST /api/v1/workflows" copy with the §13.4-D pre-built CTA. | `pages/workflows.rs` L183–190 | Copy + buttons. |
| P0-11 | **Strip every "Phase 3"/"Phase 3.11"/"Phase 3 control plane" label** from operator-facing copy. | `pages/workflows.rs`, `pages/cls_catalog.rs`, `pages/cls_packages.rs` | Find/replace. |

### P1 — round 2

| # | Title | Files | Action |
|---|---|---|---|
| P1-8 | **`components/wizard.rs` primitive + `/setup` hub.** Implement §14.2 + §14.3. Track per-wizard state in localStorage. | new `components/wizard.rs`, new `pages/setup.rs`, route in `main.rs` | Ships the foundation; individual wizards land separately. |
| P1-9 | **First-run wizard** (Connector connection → workspace detect → first plugin → invite teammate). Triggered by `App` when `setup_state` says "fresh". | new `pages/wizards/first_run.rs` | Borrow shape from TUI plan §"Shared Boot and Unlock". |
| P1-10 | **Connect-a-tool wizard.** Promote `pages/connect_landing.rs` from a standalone page into a wizard step set inside the shell. | `pages/connect_landing.rs`, `pages/wizards/connect_tool.rs` | Re-skin existing flow. |
| P1-11 | **Install-a-workflow wizard.** New flow: pick template → preview CLS → choose binding (agent/namespace/env) → confirm. | new `pages/wizards/install_workflow.rs` | Replaces the manual builder-compile-register loop. |
| P1-12 | **Plugin setup wizards (DevGuard / TraceTramp / WitnessCtl).** Port the modules A–E defined in `TUI_WIZARDS_MASTER_PLAN.md` into the web wizard primitive. | new `pages/wizards/{devguard,tracetramp,witnessctl}.rs` | Mirror module structure. |
| P1-13 | **Featured slot on Overview** (§13.4-B). Dismissable, re-appears on `featured_updated_at` change. | `pages/overview.rs` | Small card above the Worklist row. |
| P1-14 | **Stub plugin pages for the 6 currently-invisible marketed plugins** (Conductor, AgentLoop, LedgerLens, AgentPassport, Relay, Engram). Each one: hero, overview text, "Set up" wizard hook, route registered. | new `pages/plugins/{conductor,agentloop,ledgerlens,agentpassport,relay,engram}.rs` | 6 minimal pages now; full UI follows feature-by-feature. |
| P1-15 | **Recommended next steps engine.** `GET /api/v1/setup/recommendations` server-side; top-3 shown on Overview, dismissable per-step. | new endpoint + new `components/recommendations.rs` | Hook to Overview. |
| P1-16 | **Global `⌘K` palette** with dynamic index (routes + reference workflows + plugins + agents + receipts). Replace static `SearchModal` items. | `components/layout.rs::SearchModal`, `main.rs::App` | Keydown handler + indexer. |
| P1-17 | **Single source for the product catalog.** `connector-products.json` (or `GET /api/v1/products`) consumed by both marketing site (`Nav.tsx`) and dashboard sidebar. | new shared JSON, `components/layout.rs`, `platform/docs/landing-page/web/src/components/Nav.tsx` | Stop drift. |

### P2 — round 2

| # | Title | Files | Action |
|---|---|---|---|
| P2-11 | **"What's new" toast.** Reads `GET /api/v1/release-notes` (or static), shows once per release per user. | new `components/whats_new.rs` | Hook in `App`. |
| P2-12 | **Per-page document title.** `document.title = "<page> · Connector"` set on each page mount. | every `pages/*.rs` | Mechanical. |
| P2-13 | **Entitlement-aware UI.** Global `entitlements` signal in `App`; gated controls show "Upgrade" pill linking to portal. | `auth.rs`, `App`, every page that uses gated routes | Per-feature mapping table. |
| P2-14 | **"Run with sample data" on each pre-built workflow** install confirmation. | `pages/wizards/install_workflow.rs`, server endpoint `POST /workflows/:id/sample-run` | New endpoint + UI. |
| P2-15 | **Recent / Favorites sidebar group.** localStorage-tracked recents; star button on each page. | `components/layout.rs` | Local-only. |
| P2-16 | **Invite-a-teammate wizard.** Add user-invite flow inside `dashboard/` (currently only admin app). | `pages/settings.rs`, new `pages/wizards/invite_operator.rs` | Server endpoint already exists in admin. |
| P2-17 | **Empty-state component** + apply to 8 list pages. | new `components/empty_state.rs` | Mechanical. |
| P2-18 | **Brand-name unification.** Pick one customer-facing name (recommend "Connector"). | `components/layout.rs` sidebar logo, `pages/apps.rs` intro, all `<Header title=…>` strings | Mechanical. |
| P2-19 | **Eliminate hard-coded `pkg-basic-tool-agent`** in three locations (sidebar removed in P0-5; this finishes the job). | `pages/workflows.rs` L152, `pages/cls_packages.rs` L43 | Replace with "first installed package" lookup. |

---

## 12b. Appendix — product & wizard inventory (round 2)

### D. Marketed plugins vs dashboard surface

| Plugin | Marketed (Nav.tsx) | Sidebar entry | Dedicated page | Wizard | Source folder |
|---|:---:|:---:|:---:|:---:|---|
| DevGuard | ✓ | ✓ | `/plugins/devguard` | TUI only — port to web | `plugins/devguard/` |
| TraceTramp | ✓ | ✓ | `/plugins/tracetramp` | TUI only — port to web | `plugins/tracetramp/` |
| WitnessCtl | ✓ | ✓ | `/plugins/witnessctl` | TUI only — port to web | `plugins/witnessctl/` |
| Conductor | ✓ | **✗** | partially `/multiagent` | — | `plugins/conductor/` |
| AgentLoop | ✓ | **✗** | — | — | `plugins/agentloop/` |
| LedgerLens | ✓ | **✗** | partially `/monitor`+`/billing` | — | `plugins/ledgerlens/` |
| AgentPassport | ✓ | **✗** | — | — | `plugins/agentpassport/` |
| Relay | ✓ | **✗** | — | — | `plugins/relay/` |
| Engram | ✓ | **✗** | partially `/memory` | — | `plugins/engram/` |

Six of nine marketed plugins have **no dedicated page and no sidebar entry**.
P0-9 + P1-14 close this gap.

### E. Pre-built workflow templates shipped with the product

```
platform/server/resources/workflow_templates/pii_redaction_pipeline.ccl
platform/server/resources/workflow_templates/incident_slack_jira.ccl
platform/server/resources/workflow_templates/hitl_approve_audit.ccl
```

Served by `GET /api/v1/workflows/reference-templates`. Currently rendered
only by `pages/cls_catalog.rs` inside an internal-jargon card. P0-7 promotes
these to the Apps headline; P1-11 builds the install wizard.

### F. Example reference plugins shipped as runnable code

```
examples/agos-reference-plugins/acme-datadog-forwarder/
examples/agos-reference-plugins/acme-jira-bridge/
examples/agos-reference-plugins/acme-slack-notifier/
```

Currently zero dashboard surface. P0-7 adds the "Example Integrations" row
on Apps.

### G. Wizards: TUI plan vs web dashboard delivery

| Wizard | TUI plan | Web dashboard today | Web dashboard target |
|---|:---:|:---:|:---:|
| Connector connection / unlock | ✓ | none | P1-9 first-run wizard |
| Workspace detection | ✓ | none | P1-9 step |
| Capability handshake (license/tier) | ✓ | partial (license page) | P1-9 step |
| DevGuard A–E | ✓ | none | P1-12 |
| TraceTramp A–E | ✓ | none | P1-12 |
| WitnessCtl A–E | ✓ | none | P1-12 |
| Install pre-built workflow | — | none | P1-11 (new) |
| Connect a tool (Cursor/Windsurf/…) | — | partial (`/connect`) | P1-10 promote |
| Create first agent | — | partial (modal in `/agents`) | promote to wizard |
| First budget | — | none | P1-12 budget extension |
| First compliance report | — | none | from WitnessCtl Module E |
| Invite teammate | — | admin app only | P2-16 |

---

## 16. Two distributions, one codebase — Try-Me vs self-deploy

> User feedback round 3: *"make sure 90 min is there we are deploying it but
> we also need software that will be created tar and it will be real adv
> software which ppl use with real things self deploy as its real user flow
> it follow of prod so there is 1 we will deploy in try me 1 is tar and
> there will be a slight distribution and ux diff intentional."*

### 16.1 What already exists (don't rebuild)

Both distributions are already wired at infrastructure level. The dashboard
just hasn't caught up to them yet.

**Hosted Try-Me ("Try Me" CTA on marketing site):**

| File | What it does |
|---|---|
| `platform/deploy/Dockerfile.playground` + `.runtime` + `.unified` | Builds a playground-preset image |
| `platform/deploy/docker-compose.playground.yml` | One-command playground node |
| `platform/deploy/fly.playground.toml` | Fly.io deploy of `try.cnktros.com` |
| `platform/deploy/supervisord.playground.conf` | Multi-process orchestration |

Key environment variables, all already set in `fly.playground.toml`:

```
CONNECTOR_PRESET                       = "playground"
CONNECTOR_PLAYGROUND_SESSION_TTL_SECS  = "5400"   ← 90 minutes
CONNECTOR_PLAYGROUND_MAX_SESSIONS      = "50"
CONNECTOR_PLAYGROUND_MAX_AGENTS        = "5"
CONNECTOR_PLAYGROUND_TOKEN_BUDGET      = "100000"
CONNECTOR_ULTIMATE_FREE                = "1"
CONNECTOR_PUBLIC_URL                   = "https://try.cnktros.com"
```

`POST /api/v1/playground/session` returns `{api_key, tenant_id, expires_at,
node.public_url}` — the contract `pages/trial.rs` (L62–69) already
consumes. **The 90-minute trial stays.** Nothing in the fix plan removes
or shortens it. It is the first product impression and the lowest-friction
on-ramp.

**Self-deploy tar ("Dive In" CTA on marketing site):**

| File | What it does |
|---|---|
| `platform/deploy/install.sh` (447 lines) | `curl ‑fsSL .../install.sh \| bash` — production installer with systemd hardening |
| `platform/deploy/docker-compose.control-plane.yml` | Compose self-deploy |
| `platform/deploy/helm/{tracetramp,witnessctl}/` | Kubernetes Helm charts |
| `platform/deploy/CONTROL_PLANE_DEPLOYMENT_PLAN.md` (403 lines) | Production runbook |
| `platform/deploy/PRODUCTION_READINESS_PLAN.md` | Hardening checklist |
| `platform/deploy/macos/com.connector.node.plist` | macOS launchd unit |

This installs the **same binary** (`connector-platform`) as the playground,
just without the `CONNECTOR_PRESET=playground` env. License activation
talks to `CONNECTOR_LICENSE_SERVER` (default `https://license.connector.dev`).
Customer data lives at `/var/lib/connector`, license data at
`/var/lib/connector-license`, both owned by a dedicated `connector` service
user. This **is** the "real adv software which ppl use with real things"
— it is production-shaped from line 1 of `install.sh`.

### 16.2 The dashboard problem

`platform/ui-leptos/dashboard/` (and the `index.html` it ships with) is
**identical** between the two distributions today. The same WASM bundle is
served by `try.cnktros.com` and by a customer's `/var/lib/connector/ui`.
That means:

- A playground visitor sees the same 47-page sidebar a paying enterprise
  customer sees — including `Billing`, `License`, `Settings → Custom
  Domains`, `Webhooks`, `Secrets`, `Admin`-adjacent things they cannot
  actually use.
- A playground visitor's session expires at 90 min but the dashboard never
  warns them, never shows a countdown, never converts them. The
  `expires_at` is stashed into `LocalStorage` by `trial.rs` L267–268 and
  then forgotten.
- A real self-deployed customer sees "Try free trial" copy on `/trial` and
  "Playground live" badges on `/connect`, which are confusing in their own
  production environment.
- The dev-bypass leak (P0-2) ships to both. A misconfigured `index.html`
  on `try.cnktros.com` would silently make every visitor a `super_admin`.

This is a single-binary product with two intentional personas, and the UI
is unaware of the persona.

### 16.3 The single signal that fixes it

Add **one** runtime mode signal that the entire dashboard branches on:

```rust
// platform/ui-leptos/dashboard/src/deployment.rs
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub enum DeploymentMode {
    /// Hosted multi-tenant 90-min trial node (try.cnktros.com etc.).
    Playground,
    /// Customer-owned self-deployed installation (tar / install.sh / helm).
    #[default]
    SelfHosted,
}

#[derive(Clone, Default, Debug)]
pub struct DeploymentInfo {
    pub mode: DeploymentMode,
    pub public_url: String,
    pub session_expires_at: Option<String>,   // only Playground
    pub session_remaining_secs: Option<i64>,  // only Playground
    pub edition: &'static str,                // "community" | "enterprise"
    pub license_tier: Option<String>,         // only SelfHosted
}
```

Source of truth: `GET /api/v1/deployment/info` (new endpoint, derived from
`CONNECTOR_PRESET` server-side). Cached for the session, refreshed every
60 s by `App` in `main.rs`. Exposed as a `provide_context::<RwSignal
<DeploymentInfo>>` so any component can read it.

Every UX divergence below is gated by `mode.get()`.

### 16.4 Intentional UX differences (side-by-side)

| Surface | **Playground (90-min Try Me)** | **Self-deploy tar** |
|---|---|---|
| **Brand chrome** | Sidebar logo: "Connector · **Try Me**". Footer: "Hosted playground · 90-min session". Accent colour: emerald (matches marketing "Try Me" button). | Sidebar logo: "Connector · *(node name)*". Accent: indigo. |
| **Header pill** | `● Live · expires in 47m 12s` countdown — pulses amber under 10m, red under 2m. Clicking opens "Convert this session" modal (see below). | `● Live · monitor 12s ago` (the slim pill from P0-1). |
| **First-run** | Skip the full wizard. Drop the visitor into a **guided tour** of `/apps` with the 3 reference workflows pre-installed and pre-loaded with **synthetic sample data** (P2-14). 4 steps, 30 seconds each: see PII redaction → see incident routing → see HITL approval → "Want this on your own infra? Install ↓". | The full first-run wizard (§14, P1-9): Connector connection → workspace detect → license activation → first plugin → invite teammate. |
| **Sidebar** | The 4-section sidebar (§9.1) trimmed to the bits a 90-min visitor can use: **Overview · Agents · Workflows · Apps · Activity** — that's 5 items. Everything else (Billing, License, Settings, Webhooks, Secrets, Custom Domains, all admin-adjacent) is **hidden entirely**. | The full 4-section sidebar (§9.1) with all 9 marketed plugins (P0-9), Settings, Billing, License, full "More…". |
| **Pre-built workflows** | All 3 reference templates **pre-installed and pre-running with sample data**. The operator never sees an empty state. | Templates are **available** but not pre-installed (the visitor's own data goes into them). One-click install per P0-7/P0-8. |
| **Featured slot on Overview** | A glowing "**Hosted demo — your session ends in 47m**" card top-row, with "Save this session → install on your infra" CTA linking to the tarball download. | A standard "Get started" Featured card (§13.4-B) with "What's new in v0.x.y" toast (P2-11). |
| **Agent / token caps** | Hard-coded by the server (`MAX_AGENTS=5`, `TOKEN_BUDGET=100k`). UI shows them as visible meters on Overview: `Agents 2 / 5  ·  Tokens 12k / 100k`. | License entitlements (§15.7) drive caps. Meters show real license limits. |
| **Real secrets / domains** | `/secrets`, `/settings/custom-domains`, `/webhooks` are **hidden** or replaced with "Available in self-deploy → install" placeholder. | Full editing. |
| **Billing & License pages** | Replaced by a single **"Install on your own infrastructure"** page (downloads, install commands, pricing table, signup CTA). | Real billing + license UI. |
| **Dev-bypass / "Skip Auth"** | **Never shown** regardless of build flag — guarded by `mode == SelfHosted && build_flag(dev)`. (Fixes a security footgun.) | Behind `--dev` build flag only (P0-2). |
| **`/connect` and `/trial`** | `/trial` is the entry point. `/connect` lives inside the shell as a wizard step. | Both are **hidden** — operators don't need them. |
| **"Save your work" prompts** | At 30 min remaining: persistent banner *"Your session expires in 30 minutes. Download your config / receipts / install tarball to continue."* | n/a |
| **Session-end behaviour** | At `expires_at - 60s`: fullscreen modal *"Your 90 minutes are almost up. Pick one: [ Extend (sign up) ] [ Download install.sh + your trial config ] [ End session ]"*. After expiry: a friendly "Session ended" page with three conversion CTAs, **not** a 401 redirect to login. | n/a |
| **API path leakage (P0-6)** | Stripped harder — playground visitors don't need to see `GET /api/v1/...` at all. | Hidden by default; exposed inside `/debug` and "Developer view" toggle (P2-9). |
| **Onboarding wizards (§14.1)** | Limited set: only "Connect a tool" (because that's the demo). All product-setup wizards (DevGuard/TraceTramp/WitnessCtl/Budget/Compliance) replaced with a *"Try this on your own deploy →"* card. | Full wizard catalog. |
| **`SearchModal` / `⌘K` (P1-16) index** | Limited to playground-accessible surfaces. | Full index. |
| **Telemetry** | Stronger product-analytics events (anonymous funnel: session start → workflow install → time-to-first-receipt → conversion CTA). | Opt-in only. |
| **Footer** | Marketing footer: "Like what you see? **[ Install on your infra ]** · **[ Talk to us ]**". | "Connector vX.Y.Z · License: Enterprise · Updated 3 days ago · **[ Update ]**". |

The general rule: **the same Leptos crate compiles once**; everything
above is a runtime branch on `DeploymentMode`. There is no fork.

### 16.5 What the tar release actually contains

The tarball customers download from `releases.connector.dev/{version}/` is
already structured by `install.sh` to fetch:

```
connector-platform-{version}-{arch}.tar.gz
├── bin/
│   ├── connector-platform        # main daemon
│   ├── connector-license-server  # local license
│   ├── connectorctl              # CLI
│   └── plugins/
│       ├── devguard, tracetramp, witnessctl
│       └── conductor, agentloop, ledgerlens, agentpassport, relay, engram
├── ui/                           # this Leptos build (dashboard + admin)
├── workflow_templates/           # the 3 .ccl reference workflows
├── examples/                     # acme-* reference plugins
├── systemd/                      # service units
├── connector.yaml.example        # default config
└── INSTALL.md                    # quickstart
```

Two changes the UI plan needs to coordinate with:

1. **The Leptos build flag** that hardens the tar build:
   - `--features=self-deploy` is the default — strips playground-only code
     paths from the WASM bundle (smaller binary, less attack surface), and
     forbids reading `?playground=1` from URL.
   - `--features=playground` is what `Dockerfile.playground` uses — strips
     self-deploy-only code paths (license activation modal, custom-domain
     editor, etc.) and forces `DeploymentMode::Playground` at boot,
     ignoring server response (defence-in-depth).
2. **A "Download install.sh" / "Download the tarball" UX inside the
   playground** (the inverse of "Try Me"). Every Playground-mode page has
   a persistent "Take this home →" CTA in the footer/header. Clicking
   opens `/install` which renders:
   - The exact `curl ‑fsSL .../install.sh \| bash` line
   - The Docker/Helm alternatives
   - A "Download your current session as YAML" button (config snapshot)
   - The license/pricing tiers

### 16.6 The trial → tar conversion flow (real user flow it follows of prod)

This is the bridge the user explicitly asked about. The shape:

```
┌─ Marketing site ───────────────────────────────────────────────────┐
│                                                                    │
│   ┌─[ Try Me ]──────────┐         ┌─[ Dive In ]──────────────────┐ │
│   │ try.cnktros.com     │         │ portal.connector.dev/signup  │ │
│   │ 90-min playground   │         │ Tier picker + install.sh     │ │
│   └─────────┬───────────┘         └─────────────┬────────────────┘ │
└─────────────│───────────────────────────────────│──────────────────┘
              │                                   │
              ▼                                   ▼
   ┌─ POST /playground/session ──┐     ┌─ Portal signup ─────────────┐
   │   90-min countdown starts   │     │ Issues license key + cpk_*  │
   │   3 reference workflows     │     │ Email: install.sh URL + key │
   │     pre-installed +         │     └────────┬────────────────────┘
   │     sample data running     │              │
   └────────────┬────────────────┘              │
                │                               │
                │  "Take this home →"            │
                │  (any time in 90 min)         │
                ▼                               ▼
   ┌─ /install (Playground only) ───────────────────────────────────┐
   │  • curl install.sh                                              │
   │  • docker compose                                               │
   │  • helm install                                                 │
   │  • [ Download my-session.tar.gz ]   ← config + receipts so far  │
   │  • Pricing tiers + [ Sign up for a license → portal ]           │
   └────────────────────────┬────────────────────────────────────────┘
                            │
                            ▼
   ┌─ Customer's own infra ──────────────────────────────────────────┐
   │  $ curl -fsSL install.sh | bash                                 │
   │  $ connectorctl license activate cpk_***                        │
   │  $ systemctl start connector-platform                           │
   │                                                                  │
   │  Browse to https://node.example.com → first-run wizard (§14)    │
   │  Optional: drop my-session.tar.gz into /var/lib/connector       │
   │  → first-run wizard offers "Import from playground session?"    │
   └─────────────────────────────────────────────────────────────────┘
```

The "Import from playground session" step is the **only** new server
endpoint (`POST /api/v1/import/playground-session`) — it reads the
downloaded YAML and pre-fills the first-run wizard with the customer's
plugin choices, workflow installs, and any agent definitions they made
during their 90 minutes. That makes the trial→prod transition feel
**continuous**, not a restart.

### 16.7 Edition / tier signalling (works for both modes)

`DeploymentInfo.edition` is a static string baked into the binary at
release time:

```
"community"   — self-deploy, single tenant, free, capped
"enterprise"  — self-deploy, full features, licensed
"playground"  — hosted, 90-min, capped
```

The dashboard sidebar footer renders this as a small pill:

```
Community · v0.5.2   ← free self-deploy
Enterprise · v0.5.2  ← paid self-deploy
Try Me · 47m left    ← playground
```

This is the **at-a-glance "where am I?"** signal that's currently missing.

---

## 10c. Additions to the prioritized fix plan (round 3)

These rows are added to §10 + §10b. Numbering continues.

### P0 — round 3

| # | Title | Files | Action |
|---|---|---|---|
| P0-12 | **Deployment-mode signal.** Server: `GET /api/v1/deployment/info` returning `{mode, public_url, session_expires_at, edition, license_tier}`. Client: new `dashboard/src/deployment.rs`, refreshed every 60s, exposed via `provide_context`. | server: `oss/connector/crates/connector-server/src/routes.rs`; client: new `deployment.rs`, hook in `main.rs::App` | Foundation for every other row in this section. |
| P0-13 | **90-min countdown pill in header (Playground mode).** Replaces the standard Live pill with `● Live · expires in 47m 12s`. Amber under 10m, red under 2m, opens conversion modal on click. | `components/layout.rs::Header`, new `components/countdown_pill.rs` | Read `session_remaining_secs` from `DeploymentInfo`. |
| P0-14 | **Session-end modal at `expires_at − 60s`.** Three buttons: Extend (signup), Download install.sh + my-session.tar.gz, End session. | new `components/session_end_modal.rs`, mounted in `App` | One global modal; only mounts in Playground. |
| P0-15 | **Mode-gated sidebar.** Playground hides Billing, License, Settings → Custom Domains, Webhooks, Secrets, Admin links. SelfHosted shows them. | `components/layout.rs::nav_sections()` | Filter on `mode`. |
| P0-16 | **Hide dev-bypass in Playground unconditionally.** Even if `data-dev="1"` somehow leaks (P0-2), Playground must never bypass auth. | `pages/login.rs`, `main.rs::App` | `mode == Playground && bypass → false`. |
| P0-17 | **`/trial` and `/connect` accessibility by mode.** Playground: `/trial` is the entry, `/connect` lives inside the shell. SelfHosted: both hidden from sidebar and search index; deep-links 404 with a friendly redirect to `/setup`. | `main.rs` routing, `components/layout.rs::SearchModal` | Mode-aware route registration. |

### P1 — round 3

| # | Title | Files | Action |
|---|---|---|---|
| P1-18 | **Two Leptos build profiles.** `--features=playground` and `--features=self-deploy` in `dashboard/Cargo.toml`. Strip the unused branch at compile time; force `DeploymentMode` constant in each. | `dashboard/Cargo.toml`, `dashboard/src/deployment.rs`, `platform/ui-leptos/Makefile`, `Trunk.toml` | Two `dist/` outputs from one source tree. |
| P1-19 | **Pre-install + sample-data for the 3 reference workflows in Playground.** Server: when `CONNECTOR_PRESET=playground` and a new session starts, install all 3 templates and start the sample-data generators. UI: empty-state never shown in Playground. | `oss/connector/crates/connector-server/src/playground.rs` (or new), `pages/workflows.rs` | Pairs with P0-8 and P2-14. |
| P1-20 | **Guided tour in Playground first-run** (instead of the full wizard). 4 steps × 30s each: PII redaction → incident routing → HITL approval → "Install on your own infra ↓". | new `pages/playground_tour.rs`, `App::first_run` redirect | Reuse the wizard primitive (P1-8) but mode-branched. |
| P1-21 | **`/install` page (Playground only).** Renders install commands, Docker/Helm alternatives, "Download my-session.tar.gz" config-snapshot button, pricing tiers, portal signup CTA. | new `pages/install.rs`, route, persistent footer link in Playground | Single page; sources commands from `DeploymentInfo.public_url` + license server. |
| P1-22 | **"Save this session" tar export.** `GET /api/v1/playground/session/export` returns a `.tar.gz` with `connector.yaml`, installed workflows, agent definitions, receipts so far. Trigger from `/install` and the 30m-remaining banner. | server: `oss/connector/crates/connector-server/src/playground.rs`; client: `pages/install.rs` | Single-shot zip. |
| P1-23 | **"Import from playground session" step in self-deploy first-run wizard.** `POST /api/v1/import/playground-session` accepts the tar, pre-fills wizard state. | server: new endpoint; client: `pages/wizards/first_run.rs` (P1-9) | The trial→prod continuity bridge. |
| P1-24 | **Caps as visible meters in Playground.** `Agents 2 / 5 · Tokens 12k / 100k` row on Overview, sticky in header at ≥ 80% utilisation. | `pages/overview.rs`, `components/layout.rs::Header` | Read from `DeploymentInfo` and `/playground/status`. |
| P1-25 | **Edition pill in sidebar footer.** `Community v0.5.2` / `Enterprise v0.5.2` / `Try Me · 47m left`. | `components/layout.rs` sidebar footer | Read from `DeploymentInfo.edition`. |
| P1-26 | **Mode-aware copy on `/billing` + `/license` + `/settings/custom-domains` + `/secrets` + `/webhooks`.** In Playground, swap each with a single "Install on your own infra to use this" card linking to `/install`. | the 5 pages above | Top-level conditional. |
| P1-27 | **Self-deploy "Update available" toast** (Self-deploy only). Polls `releases.connector.dev/latest.json`; toast on Overview when a newer version is published. | new `components/update_toast.rs` | Mode-gated. |

### P2 — round 3

| # | Title | Files | Action |
|---|---|---|---|
| P2-20 | **Telemetry funnel events (Playground only).** `session_start`, `workflow_installed`, `first_receipt`, `install_clicked`, `signup_clicked`. POST to `/api/v1/telemetry/playground` (anonymous). | new `components/telemetry.rs`, hook in `App` | Opt-out via query string. |
| P2-21 | **Playground "Take this home →" persistent CTA** in header (right of countdown) and Overview footer. Links to `/install`. | `components/layout.rs::Header` | Mode-gated. |
| P2-22 | **Self-deploy "Update" footer button** (next to version pill) when a newer release exists. Pairs with P1-27. | sidebar footer | Mode-gated. |
| P2-23 | **macOS launchd / Linux systemd integration in `/install`.** When in Playground, show the exact unit files (`com.connector.node.plist`, `connector-platform.service`) so power users can deploy in five minutes. | `pages/install.rs` | Static content from `platform/deploy/`. |
| P2-24 | **`connector.yaml` editor** (Self-deploy only) under Settings. Read/write the local config file via a kernel-gated API. | new `pages/settings_config.rs`, server endpoint | Behind a build flag — risky surface, must be authenticated and audit-logged. |

---

## 11b. Acceptance criteria (round 3)

Adds to §11:

7. A Playground visitor can see the **session countdown** at all times, is
   never shown billing/license/secrets/domains/webhooks UI, and can
   download an installer + session config any time during the 90 minutes.

8. A self-deploy operator never sees "Try free trial" or "Playground live"
   copy, sees real license/billing/secrets surfaces, and on a fresh node
   can complete the first-run wizard (optionally importing a playground
   session) in under five minutes.

9. The exact same Leptos source tree compiles to **two distinct binaries**
   (`--features=playground` and `--features=self-deploy`) and neither
   binary contains the other's code paths.

10. The `/install` page in Playground shows real, copy-paste-able
    installation commands for the **current platform version** of the
    backend it's talking to.

11. A visitor who imports their playground session into a self-deployed
    node sees their workflows, agents, and pinned receipts already in the
    new dashboard before they finish the first-run wizard.

---

## 12c. Appendix — distribution matrix (round 3)

### H. Side-by-side build matrix

| Aspect | Playground | Self-deploy (tar) |
|---|---|---|
| Build target | `Dockerfile.playground.unified` | `install.sh` + `connector-platform-{ver}-{arch}.tar.gz` |
| Hosted at | `try.cnktros.com` (Fly.io) | Customer's own infra |
| Tenancy | Multi-tenant (50 concurrent sessions) | Single tenant (the customer's org) |
| Session TTL | 5400 s (90 min, env-configurable) | None — persistent |
| Agent cap | 5 (env) | License-driven |
| Token budget | 100k (env) | License-driven |
| LLM | Stub by default, optional real with spend cap | Customer's keys |
| Persistence | Per-session namespace, dropped at TTL | `/var/lib/connector` durable |
| Auth | Anonymous trial sessions (`cpk_*` issued by `/playground/session`) | API keys, OAuth, license-tied JWTs |
| License server | Bypassed (`CONNECTOR_ULTIMATE_FREE=1`) | `https://license.connector.dev` (or self-hosted) |
| Plugins available | All 9, sandboxed | All 9, license-tier-gated |
| Dashboard build | `dashboard --features=playground` | `dashboard --features=self-deploy` |
| Dev-bypass | **Never** | Only with `--dev` build flag |
| Reference workflows | Pre-installed with sample data | Available, opt-in install |
| Custom domains / secrets / webhooks | Hidden | Available |
| Billing / License pages | Replaced by `/install` | Real |
| First experience | Guided tour (4 steps × 30s) | First-run wizard (§14) |
| Conversion CTA | Persistent "Take this home →" | n/a |
| Telemetry | Anonymous funnel | Opt-in |

### I. Files that the dual-distribution work touches

```
NEW
  platform/ui-leptos/dashboard/src/deployment.rs              ← mode signal (P0-12)
  platform/ui-leptos/dashboard/src/components/countdown_pill.rs   (P0-13)
  platform/ui-leptos/dashboard/src/components/session_end_modal.rs (P0-14)
  platform/ui-leptos/dashboard/src/pages/install.rs           ← Playground "/install" (P1-21)
  platform/ui-leptos/dashboard/src/pages/playground_tour.rs   ← guided tour (P1-20)
  platform/ui-leptos/dashboard/src/components/update_toast.rs ← Self-deploy update (P1-27)

CHANGED
  platform/ui-leptos/dashboard/Cargo.toml                     ← features (P1-18)
  platform/ui-leptos/dashboard/Trunk.toml                     ← per-feature output
  platform/ui-leptos/Makefile                                 ← two build targets
  platform/ui-leptos/dashboard/src/main.rs                    ← App reads DeploymentInfo
  platform/ui-leptos/dashboard/src/components/layout.rs       ← mode-gated sidebar + edition pill
  platform/ui-leptos/dashboard/src/pages/{billing,license,secrets,webhooks,settings_custom_domains}.rs
  platform/ui-leptos/dashboard/src/pages/overview.rs          ← Playground caps meter
  platform/ui-leptos/dashboard/src/pages/login.rs             ← dev-bypass guard

SERVER (new endpoints)
  GET  /api/v1/deployment/info                                ← mode + edition (P0-12)
  GET  /api/v1/playground/session/export                      ← tar.gz (P1-22)
  POST /api/v1/import/playground-session                      ← restore on prod (P1-23)
  POST /api/v1/telemetry/playground                           ← funnel (P2-20)
```

---

*End of report.*
