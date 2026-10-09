# UI Greenfield Build Plan — Primitives First

**Status:** Master execution plan for dashboard rebuild.  
**Stack:** Leptos 0.8 CSR → WASM only — [platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md)  
**Visual north star:** CONNECTOR OS shell (Pulse + RUN/WATCH/FIX/SETUP + workflow cards + live stream + right drawer) — reference mock in repo assets; adapt to real APIs, not pixel-perfect copy.

**One sentence:** **Delete the 81-page sprawl**, build **~38 primitives → ~11 cards → ~16 overlays → ~10 shell surfaces**, stay light via lazy routes + drawer (not pages).

**Parent:** [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) · [UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md) · [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md)

---

## 0. Build order (strict)

```text
Phase A  Scaffold + tokens + honesty utils          ✓
Phase B  38 Op* primitives (atoms/molecules)         ✓
Phase C  11 composite cards + 8 button/menu patterns ✓
Phase D  16 overlays (drawer, palette, sheets, modals) ✓ (stubs + wired drawer/palette)
Phase E  10 shell surfaces (modes, not 81 pages)     ✓ (run/watch/fix/setup/dev/console/404 + auth)
Phase F  Wire APIs + delete legacy pages/components  ✓ (sidebar gone; demoted pages deleted)
```

**Do not** build pages before Phase B–D exist. **Do not** delete `api.rs`, `auth.rs`, `lib.rs::hydrate()`, or `patch_wasm_init.py`.

---

## 1. What the reference image maps to

| Image region | Our component(s) | Mode |
|--------------|-------------------|------|
| Top: CONNECTOR OS + sine PULSE + running/needs-you/idle + health + ⌘K | `OpPulseBar`, `OpPulseWave`, `OpStatChip`, `OpHealthDot`, `OpEnvBadge` | global |
| Left rail: RUN / WATCH / FIX / SETUP | `OpModeRail`, `OpModeButton` | global |
| RUN header + filters + grid | `OpModeHeader`, `OpFilterTabs`, `OpSearchField`, `OpViewToggle` | RUN |
| Workflow tiles (accent rail, sparkline, RUN/FIX) | `OpWorkflowCard` (variant of `OpCard`) | RUN |
| Bottom live stream table | `OpEventStream`, `OpEventRow` | WATCH strip / WATCH mode |
| Right drawer: tabs, error hero, sparklines, quick actions, object grid | `OpDrawer`, `OpDrawerTabs`, `OpErrorHero`, `OpSparklineGrid`, `OpObjectGrid` | drawer |
| Dark glass + semantic glow | `op_tokens.rs` (CSS vars / Tailwind tokens) | global |

---

## 2. What we delete (Phase F — not until replacements exist)

### 2.1 Keep (never delete)

| Path | Why |
|------|-----|
| `src/api.rs`, `src/auth.rs`, `src/request_store.rs` | API + session |
| `src/lib.rs` (`hydrate`, router skeleton) | WASM entry |
| `src/deployment.rs`, `src/entitlements.rs` | Boot gates |
| `index.html`, `scripts/patch_wasm_init.py` | WASM loader |
| `src/routing/lazy_routes.rs` | Code split |
| `src/pages/login.rs`, `src/pages/trial.rs`, `src/pages/connect_landing.rs` | Auth entry |
| `src/components/error_boundary.rs` | Safety |

### 2.2 Delete (~81 page modules → ~10 shell surfaces)

All current `src/pages/*.rs` except login/trial/connect — replaced by:

| # | Shell surface | Route | Replaces (examples) |
|---|---------------|-------|---------------------|
| 1 | **RunCanvas** | `/`, `/run`, `/workflows` | workflows, overview, home, cls_* |
| 2 | **WatchCanvas** | `/watch`, `/activity` | actionlog, history |
| 3 | **FixCanvas** | `/fix` | disputes, report-center queue slices |
| 4 | **SetupCanvas** | `/setup`, `/apps`, `/settings` | apps, settings, install wizards |
| 5 | **LoginSurface** | `/login` | login (keep, restyle) |
| 6 | **TrialSurface** | `/trial` | trial (keep) |
| 7 | **ConnectSurface** | `/connect` | connect_landing |
| 8 | **PluginConsole** (T1 lazy) | `/plugins/:id` | TT/WC/DG dashboards — one lazy console |
| 9 | **AdvancedDev** (lazy) | `/debug`, `/tools` | debug, protocols, infra — one dev hub |
| 10 | **NotFound** | `/*` | 404 |

Everything else → **drawer topic** or **redirect** (see [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) §4.2).

### 2.3 Delete legacy components (~58 files → `components/operator/`)

Remove after Op* parity:

- `components/cards.rs`, `layout.rs`, `sidebar_personal.rs`, `system_health_card.rs`
- `components/surface/*` (replaced by drawer panel renderer)
- `components/tutorial/*` (optional — move to SETUP help drawer later)
- Duplicate `ui/empty_state.rs` vs `empty_state.rs` — consolidate into `OpEmptyState`

**Keep and wrap:** `components/ui/button.rs`, `dialog.rs`, `badge.rs` — migrate into `OpButton`, `OpDialog` or delete when Op* ships.

---

## 3. Phase B — 38 primitives (`components/operator/primitives/`)

Finite set. New visual need → extend variant, not new file (unless ≥3 uses).

### 3.1 Tokens & layout (6)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P01 | `OpTokens` | `tokens.rs` | CSS vars: bg, surface, border, glow, semantic colors |
| P02 | `OpSurface` | `surface.rs` | Glass panel wrapper (`backdrop-blur`, border, radius) |
| P03 | `OpStack` | `stack.rs` | V/H flex gaps — consistent spacing scale |
| P04 | `OpGrid` | `grid.rs` | Responsive card grid (RUN canvas) |
| P05 | `OpScrollArea` | `scroll_area.rs` | Overflow + thin scrollbar |
| P06 | `OpDivider` | `divider.rs` | Horizontal/vertical separator |

### 3.2 Typography & honesty (5)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P07 | `OpText` | `text.rs` | title, subtitle, caption, mono variants |
| P08 | `OpFmtUnknown` | `fmt.rs` | H1: null → `—` |
| P09 | `OpVerifiedBadge` | `verified_badge.rs` | H3: only after verify API |
| P10 | `OpTimeAgo` | `time_ago.rs` | Relative time + absolute tooltip |
| P11 | `OpTruncMono` | `trunc_mono.rs` | CID, pid, run_id ellipsis |

### 3.3 Status & indicators (8)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P12 | `OpHealthDot` | `health_dot.rs` | ok/degraded/down/unknown |
| P13 | `OpStatChip` | `stat_chip.rs` | running / needs-you / idle counts |
| P14 | `OpStatePill` | `state_pill.rs` | ENABLED, PAUSED, blocked |
| P15 | `OpDecisionPill` | `decision_pill.rs` | allow / deny / skip |
| P16 | `OpSignal` | `signal.rs` | manifest metric chip |
| P17 | `OpInstitutionChip` | `institution_chip.rs` | TT/WC/DG dot + label |
| P18 | `OpLiveDot` | `live_dot.rs` | pulsing live indicator |
| P19 | `OpPulseWave` | `pulse_wave.rs` | decorative sine / activity line in Pulse Bar |

### 3.4 Inputs & controls (9)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P20 | `OpButton` | `button.rs` | primary, secondary, ghost, danger, sizes |
| P21 | `OpIconButton` | `icon_button.rs` | ⋮ menu, close, pin |
| P22 | `OpKbd` | `kbd.rs` | ⌘K hint |
| P23 | `OpSearchField` | `search_field.rs` | RUN/WATCH filter |
| P24 | `OpTextField` | `text_field.rs` | forms in SETUP |
| P25 | `OpSelect` | `select.rs` | agent picker, env |
| P26 | `OpSwitch` | `switch.rs` | toggles |
| P27 | `OpFilterTabs` | `filter_tabs.rs` | All / Running / Needs you / Idle |
| P28 | `OpViewToggle` | `view_toggle.rs` | grid / list (optional) |

### 3.5 Chrome & navigation (6)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P29 | `OpModeRail` | `mode_rail.rs` | 4 icons, FIX badge |
| P30 | `OpModeButton` | `mode_button.rs` | active glow (image: green RUN) |
| P31 | `OpPulseBar` | `pulse_bar.rs` | composes P13–P19 + env + bell |
| P32 | `OpAlertBar` | `alert_bar.rs` | single system banner |
| P33 | `OpNotifyBell` | `notify_bell.rs` | unread count |
| P34 | `OpEnvBadge` | `env_badge.rs` | `prod-eu-1` style node label |

### 3.6 Feedback & loading (4)

| ID | Component | File | Notes |
|----|-----------|------|-------|
| P35 | `OpSpinner` | `spinner.rs` | boot + inline |
| P36 | `OpSkeleton` | `skeleton.rs` | card/row placeholders |
| P37 | `OpEmptyState` | `empty_state.rs` | icon + title + CTA |
| P38 | `OpProgress` | `progress.rs` | dry-run / export progress |

**Total: 38 primitives**

---

## 4. Phase C — 11 composite cards + patterns

Built from primitives only. Manifest-driven where noted.

| ID | Component | Variant / use | Image match |
|----|-----------|---------------|-------------|
| C01 | `OpCard` | base: accent rail, title, slots, menu | all tiles |
| C02 | `OpWorkflowCard` | `OpCard` variant=workflow | RUN grid cards |
| C03 | `OpIssueCard` | variant=issue | FIX amber card |
| C04 | `OpEventRow` | stream row (not full card) | WATCH table rows |
| C05 | `OpAgentCard` | variant=agent | drawer object grid |
| C06 | `OpMetricCard` | variant=metric | sidebar sparkline block |
| C07 | `OpMetricRow` | 4-up KPI row | Last run / health impact |
| C08 | `OpInstitutionCard` | SETUP install tile | apps grid |
| C09 | `OpObjectTile` | small 2×2 grid cell | Agents/Secrets/Connections/Receipts |
| C10 | `OpReceiptCard` | Trust export row | receipts list |
| C11 | `OpUsageMeter` | token/call bar | cost drawer |

### Button / menu patterns (8 — not separate pages)

| ID | Pattern | Component |
|----|---------|-----------|
| B01 | Primary CTA | `OpButton` variant=primary |
| B02 | RUN / FIX footer CTA | `OpCardFooterActions` |
| B03 | Overflow ⋮ menu | `OpDropdownMenu` |
| B04 | Quick actions row | `OpQuickActions` (drawer) |
| B05 | Destructive confirm trigger | `OpButton` variant=danger |
| B06 | Link-style action | `OpButton` variant=ghost |
| B07 | Loading button | `OpButton` + `OpSpinner` |
| B08 | Palette action row | `OpPaletteItem` |

---

## 5. Phase D — 16 overlays & popups

| ID | Component | Type | Trigger |
|----|-----------|------|---------|
| O01 | `OpDrawer` | right panel shell | card click, ⌘K GO |
| O02 | `OpDrawerTabs` | Overview / Runs / Objects / Receipts | inside drawer |
| O03 | `OpDrawerPanel` | manifest `panels[]` renderer | kv, table, sparkline |
| O04 | `OpErrorHero` | “What’s wrong” + Fix now | FIX / drawer |
| O05 | `OpPalette` | ⌘K command surface | global |
| O06 | `OpConfirm` | yes/no destructive | terminate subtree |
| O07 | `OpResultSheet` | dry-run human summary | after RUN |
| O08 | `OpToast` | ephemeral | actions |
| O09 | `OpNotifyCenter` | bell dropdown / side sheet | P33 |
| O10 | `OpModal` | centered dialog | rare forms |
| O11 | `OpSheet` | bottom sheet (mobile) | optional |
| O12 | `OpExportMenu` | capability-gated PDF/CSV | Trust |
| O13 | `OpAgentTree` | progeny tree panel | agent drawer |
| O14 | `OpSparklineGrid` | 4 mini charts | drawer overview |
| O15 | `OpForensicsPanel` | custody/trace sections | Trust |
| O16 | `OpSessionEndModal` | playground session end | keep behavior, restyle |

**Total: 16 overlays** (expand to 20 only if manifest needs `OpWizard` steps — use one `OpWizard` with steps[], not 4 modals).

---

## 6. Phase E — 10 shell surfaces (light “pages”)

Each surface = **one lazy route** + composes chrome + canvas. Detail = drawer, not routes.

```text
┌─────────────────────────────────────────────────────────────────┐
│ OpPulseBar                                                       │
├────┬──────────────────────────────────────────────┬─────────────┤
│Rail│  RunCanvas | WatchCanvas | FixCanvas | Setup │ OpDrawer    │
│    │  (filters + OpGrid of OpWorkflowCards)         │ (on demand) │
│    │  + optional Watch strip at bottom of RUN       │             │
└────┴──────────────────────────────────────────────┴─────────────┘
```

| Surface | Lazy | Initial WASM chunk |
|---------|------|-------------------|
| LoginSurface | no (minimal) | auth only |
| RunCanvas | yes | shell + cards |
| WatchCanvas | yes | stream |
| FixCanvas | yes | issue cards |
| SetupCanvas | yes | institutions + settings sections |
| PluginConsole | yes | per-plugin chunk |
| AdvancedDev | yes | debug hub |
| TrialSurface | separate crate | unchanged |
| ConnectSurface | tiny | unchanged |
| NotFound | inline | tiny |

**Target:** initial load **< trial + shell + RunCanvas** — not 81 pages compiled in.

---

## 7. File layout (new tree)

```text
platform/ui-leptos/dashboard/src/
  components/
    operator/
      mod.rs
      tokens.rs              # P01 — import in input.css @layer
      primitives/              # P02–P38
        mod.rs
        button.rs
        ...
      cards/                   # C01–C11
        mod.rs
        workflow_card.rs
        ...
      overlays/                # O01–O16
        mod.rs
        drawer.rs
        palette.rs
        ...
      shell/                   # composes chrome
        mod.rs
        app_shell.rs           # Pulse + Rail + outlet + drawer host
        pulse_bar.rs
        mode_rail.rs
    honesty.rs                 # P08–P09 helpers
  surfaces/                    # replaces pages/ (10 files)
    mod.rs
    run.rs
    watch.rs
    fix.rs
    setup.rs
    login.rs                   # thin — or keep pages/login.rs
    plugin_console.rs
    advanced_dev.rs
    not_found.rs
  pages/                       # DELETE in Phase F (keep login/trial until moved)
```

---

## 8. Visual tokens (from reference — Tailwind)

Add to `dashboard/input.css` `@layer components`:

| Token | Value (starting point) |
|-------|------------------------|
| `--op-bg` | `#080c14` (deep navy) |
| `--op-surface` | zinc-900/40 + backdrop-blur |
| `--op-border` | zinc-800/60 |
| `--op-glow-running` | emerald-500/20 box-shadow |
| `--op-glow-attention` | amber-500/20 |
| `--op-glow-idle` | zinc-700/10 |
| `--op-accent-rail-w` | 3px |
| `--op-pulse-h` | 40px |
| `--op-rail-w` | 48px |

Semantic colors only on status — not decorative rainbow.

---

## 9. Execution checklist

### Wave 1 — Scaffold (1–2 days)

- [x] `components/operator/mod.rs` + `tokens.rs` + `primitives/mod.rs`
- [x] `surfaces/mod.rs` stub; `AppShell` renders Pulse + Rail + empty outlet
- [x] `lib.rs` router: `/run`, `/watch`, `/fix`, `/setup`, `/dev/components` + `/` → `/run`
- [x] Storybook-style **dev page** `/dev/components` listing Op* primitives

### Wave 2 — Primitives P01–P20 (3–4 days)

- [x] Tokens, surfaces, typography, first buttons
- [x] `GET /operator/pulse` wired to `OpPulseBar` (honest counts)

### Wave 3 — Primitives P21–P38 + chrome (3–4 days)

- [x] Mode rail, filters, health, skeletons
- [x] Match reference image top bar + left rail

### Wave 4 — Cards C01–C11 (3–4 days)

- [x] `OpWorkflowCard` + card click → drawer (`GET /workflows/:id/surface`)
- [x] `OpEventRow` + `GET /operator/watch/events`
- [x] `OpIssueCard` + `GET /operator/fix/queue`
- [x] Remaining cards: Agent, Metric, Institution, ObjectTile, Receipt, UsageMeter

### Wave 5 — Overlays O01–O16 (4–5 days)

- [x] Drawer + tabs + error hero + palette (⌘K)
- [x] Confirm, Modal, ResultSheet, Toast, Sheet, ExportMenu, AgentTree, Forensics, NotifyCenter
- [ ] Wire dry-run POST → ResultSheet (action plumbing)
- [ ] SessionEndModal restyle onto OpModal (keep behavior)

### Wave 6 — Surfaces + delete legacy (5–7 days)

- [x] Run/Watch/Fix/Setup canvases (v1) + `/dev/components` + `/dev` + `/console/:id`
- [x] Redirects: all demoted legacy routes → RUN/WATCH/FIX/SETUP/DEV
- [x] Delete ParentRoute sidebar shell from router
- [x] Delete demoted `pages/*` from build (keep login/trial/connect + install + wizards + TT/WC/DG)
- [x] Dry-run POST → `OpResultSheet` from drawer quick actions
- [ ] Optional: delete unused legacy `components/layout` Sidebar (dead code)
- [ ] `cargo leptos build --split` size check vs 8.9MB baseline

---

## 10. WASM lightness rules

1. **Lazy route every surface** except login shell.
2. **Drawer content lazy** — fetch panel data on open, not at boot.
3. **No `LocalResource` storms** — use `request_store` for pulse/health/agents.
4. **Sparklines:** lightweight canvas or SVG in Rust — no chart npm.
5. **Plugin consoles:** one `PluginConsole` route, lazy load plugin view by id.
6. **Do not** import all surfaces in `lib.rs` — use `#[lazy_route]` pattern in `routing/lazy_routes.rs`.

---

## 11. Success criteria

1. **Component test:** `/dev/components` shows all 38 primitives with variants.
2. **Image parity:** RUN view recognizable vs reference (pulse, rail, cards, stream strip, drawer).
3. **Count test:** ≤10 surface routes in router; everything else drawer or redirect.
4. **Size test:** playground split build initial chunk materially smaller than old monolith.
5. **Honesty test:** H1–H10 on RUN/WATCH/FIX first paint.
6. **WASM test:** boot splash → app with no loader regression ([UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md)).

---

## 12. What we are NOT doing

- Rebuilding in JavaScript/React
- 81 pages with copy-paste cards
- Per-workflow custom Leptos components
- Deleting WASM loader scripts before new UI works
- Big-bang delete day 1 without scaffold replacing login + run

---

*Reference mock: user-provided CONNECTOR OS dashboard (Aug 2026). Execute Wave 1 immediately; delete legacy only in Wave 6.*
