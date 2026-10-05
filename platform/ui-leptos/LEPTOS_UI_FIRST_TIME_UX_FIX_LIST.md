# Leptos UI — First-Time Customer UX Fix List & Implementation Guide

**Audience:** Engineers (and AI coding agents) fixing the operator dashboard for a **first-time user** who has never heard of Connector, WitnessCtl, TraceTramp, or DevGuard.

**Scope:** `platform/ui-leptos/dashboard/` (authenticated app + `/trial`, `/connect`, setup wizards).

---

## 1. Perspectives

### A. The Solution Architect Perspective
From a systems and architecture standpoint, the current UX issues stem from technical debt and missing abstractions:
1. **Routing State is Implicit:** Product choices made in `/trial` or wizards aren't captured centrally. We hard-redirect via `window.location.set_href("/plugins/{id}")` rather than writing state (e.g. `localStorage::set("preferred_product", id)`) and delegating navigation to a single source of truth.
2. **Layout Abstraction Leak:** The `AppShell` design system primitive (`components/ui/app_shell.rs`) was built to solve overlap and scrolling bugs safely using CSS flex/grid and `min-h-0`, but the root `<ParentRoute>` in `main.rs` still uses an ad-hoc `<div class="relative flex h-screen overflow-hidden">` wrapper that fights the child components.
3. **Over-fetching & Eager Rendering:** Pages like `compliance.rs` load 7+ `LocalResource` APIs on mount, even for hidden tabs. 
4. **Scattered Onboarding State:** The "first-run" guard in `setup.rs` checks for `wizard:first-run:completed`, but playground users finish `wizard:playground-tour:completed`, causing infinite redirect loops on the root `/` route.

### B. The First-Time User Perspective
From a psychological standpoint, the current UX causes immediate cognitive overload:
1. **"I want a solution, not a headache":** A user signs up for TraceTramp. They are dumped into a dense 3-column dashboard with sticky sidebars, a "static folder tree metaphor", and raw JSON dumps (e.g., `witness_captures` or API health outputs). 
2. **Where am I?** There is no friendly "Overview" or home page that acknowledges their existence. They don't know what the 9 plugins in the sidebar are (6 are disabled stubs!).
3. **No gentle guidance:** There are no "tap to learn more" coachmarks or tutorial cards, only full-page, multi-step wizards that feel like chores.

---

## 2. Target First-Time Journey (North Star)

```mermaid
flowchart TD
  A[Land: /trial or /login] --> B{Authenticated?}
  B -->|No| A
  B -->|Yes| C[Overview / Product hub]
  C --> D{Chose a product?}
  D -->|No| E[Tutorial cards + Apps hub CTA]
  D -->|Yes| F[Overview with Your product: X strip]
  F --> G[Optional: /plugins/X/setup wizard]
  G --> H[/plugins/X dashboard]
  E --> I[/apps pick product]
  I --> F
```

**UX Rules:**
1. **First authenticated screen = Overview (`/`)**, not a plugin dashboard.
2. **Product choice is remembered** (`preferred_product = witnessctl | tracetramp | devguard`) and reflected in Overview copy.
3. **No raw JSON** for default users (`data-developer="0"`). Wrap JSON in `<details class="dev-only">`.

---

## 3. Actionable Implementation Steps

Work top-to-bottom. Each task is scoped for an engineer/agent to execute in one PR.

### Phase 1: Fix Redirects & Routing State (P0)

**Task 1.1: Create `routing/post_auth.rs`**
- **Action:** Create `dashboard/src/routing/post_auth.rs`.
- **Code:** Add helpers `get_preferred_product() -> Option<String>`, `set_preferred_product(id: &str)`, and `navigate_to_overview_with_preference(navigate: impl Fn, id: &str)`.

**Task 1.2: Patch `/trial` and Setup Wizards**
- **Action:** In `trial.rs` (L299-L327) and `plugins/setup/{witnessctl,tracetramp,devguard}.rs`, replace `window.location.set_href("/plugins/{id}")`.
- **Code:** Call `set_preferred_product(id)` and navigate to **`/`** (Overview) instead.

**Task 1.3: Fix the First-Run Guard Loop**
- **Action:** In `dashboard/src/pages/setup.rs` (`install_first_run_guard`).
- **Code:** Modify the guard condition to check if **EITHER** `wizard_status("first-run").is_done()` **OR** `wizard_status("playground-tour").is_done()`. If either is true, `return true;` (skip redirect).

### Phase 2: Create the "Start Here" Overview Experience (P1)

**Task 2.1: Add "Preferred Product" Banner to Overview**
- **Action:** Edit `dashboard/src/pages/overview.rs`.
- **Code:** Read `get_preferred_product()`. If it exists (e.g., `tracetramp`), render a `ui::Banner` at the top: *"Welcome! You are exploring TraceTramp."* with a primary `Button` linking to `/plugins/tracetramp`.

**Task 2.2: Implement Tutorial Cards (`ui/tutorial.rs`)**
- **Action:** Create `dashboard/src/components/tutorial/mod.rs`, `tutorial_card.rs`, and `tutorial_dialog.rs`.
- **Code:** Build a `TutorialCard` primitive using `ui::Card`. When clicked, it opens a `ui::Dialog` with 3-5 plain-language bullet points. Store `tutorial:dismissed:{id}` in `localStorage`.
- **Wiring:** Add these cards to `overview.rs` (e.g., "What is Connector?") and `apps.rs` (e.g., "Pick your product").

**Task 2.3: Handle Zero-Agents Empty State**
- **Action:** In `overview.rs`.
- **Code:** If the `agents` API returns empty, hide the `FeaturedSlot` and `RecommendationsPanel`. Render a massive `ui::EmptyState` hero: "Connect your first tool" linking to `/setup/connect-tool`.

### Phase 3: De-Clutter Plugin Dashboards (P1)

**Task 3.1: Hide Raw JSON (No Developer View)**
- **Action:** Edit `witnessctl_dashboard.rs`, `devguard_dashboard.rs`, and `compliance.rs`.
- **Code:** Wrap any `<pre class="notebook-output">` that dumps JSON inside a `<details class="dev-only">` block with a summary like "Show Technical Details". Or render conditionally `Show when=use_developer_view()`.

**Task 3.2: Simplify WitnessCtl Layout**
- **Action:** Edit `witnessctl_dashboard.rs`.
- **Code:** Remove the 3-column `xl:grid-cols-[13rem_1fr_16rem]` with `xl:sticky` side columns. Make it a single main column. Move the "folder tree metaphor" into a `<details>` or a Drawer.

**Task 3.3: Hide "Coming Soon" Sidebar Stubs**
- **Action:** Edit `dashboard/src/components/layout.rs` (Sidebar).
- **Code:** For the 6 stub plugins (Conductor, AgentLoop, etc.), hide them from the primary sidebar unless `use_developer_view()` is true. They should only be discovered via `/apps`.

**Task 3.4: Lazy Load Compliance Tabs**
- **Action:** Edit `dashboard/src/pages/compliance.rs`.
- **Code:** Refactor the 7+ `LocalResource` calls so they only initialize/fetch when their specific tab is active. Default the view strictly to the "Scorecard" tab.

**Task 3.5: Add Tutorial Wizards to Dense API Pages**
- **Action:** Edit `compliance.rs`, `witnessctl_dashboard.rs`, and `tracetramp_dashboard.rs` (the pages that load multiple API resources).
- **Code:** Add a `TutorialCard` that links to a multi-step `TutorialDialog` wizard. This should show up prominently after the APIs load, explaining the data (e.g., "How to read this Scorecard", "What is the HITL queue?") in 3-5 plain English steps.

### Phase 4: Structural Layout Safety (P2)

**Task 4.1: Migrate to `AppShell`**
- **Action:** Edit `dashboard/src/main.rs`.
- **Code:** Replace the `<div class="relative flex h-screen overflow-hidden...">` with `<AppShell sidebar=... topbar=...>`. Make sure the `main-content` area leverages the CSS definitions in `components/ui/app_shell.rs` to guarantee `min-h-0` scrolling (preventing sticky elements from overlapping content).

**Task 4.2: Consolidate Tab Bar CSS**
- **Action:** Edit `dashboard/input.css` and the plugin dashboards.
- **Code:** Ensure all plugin dashboards wrap their content in `.plugin-dashboard` so the `.tab-bar` negative margins don't create double-borders or overlaps with the content panels below.

**Task 4.3: Header Responsive Collapse**
- **Action:** Edit `dashboard/src/components/layout.rs` (Header).
- **Code:** Collapse secondary header widgets (capacity meters, star pin) behind a "···" dropdown on small screens (`sm` breakpoint).

---

*Follow these steps sequentially to resolve the cognitive overwhelm, layout overlap, and missing onboarding flows. Validate each step by logging in as a fresh user via `/trial` on a small laptop screen (1280x800).*