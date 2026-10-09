# Universal Operator Component System (UOCS)

**Purpose:** One library of **cards, bars, popups, and notifications** that powers the shell, every workflow (including custom), and every institution — **no per-workflow UI components**.

**Parent docs:** [UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md) · [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) · [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md)

**Vibe:** Light · smart · modern · mission-control — advanced without clutter.

---

## 1. Design law

```text
┌────────────────────────────────────────────────────────────────┐
│  FIXED COMPONENTS (Rust/Leptos — ship once)                     │
│  OpCard · OpBar · OpToast · OpDrawer · OpPalette · OpChip …    │
└────────────────────────────┬───────────────────────────────────┘
                             │ composed by
┌────────────────────────────▼───────────────────────────────────┐
│  MANIFEST DATA (per workflow / per rule — JSON)                 │
│  card.variant · signals · actions · notifications · overlays    │
└────────────────────────────┬───────────────────────────────────┘
                             │ never
                             ▼
                    custom React/Leptos per workflow ✗
```

| Law | Meaning |
|-----|---------|
| **C1** | Every visual pattern is an `Op*` component with a `variant` + `props` schema |
| **C2** | Custom workflows only supply **data** — never new component types in app code |
| **C3** | New visual need → add **one** `Op*` primitive used by all workflows |
| **C4** | Notifications are **layered** (toast → bar → center → FIX) — same payload shape |
| **C5** | Search/palette **executes** — not just navigates |
| **C6** | Heavy content lazy; first paint **light** (skeleton → hydrate) |

---

## 2. Global chrome (always on screen)

### 2.1 Pulse Bar `OpPulseBar`

The permanent heartbeat. Replaces logo strip + scattered banners.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ ● 2 running  │  ⚠ 1 needs you  │  ○ 5 idle  │  prod-eu-1 ● ok  │  ⌘K  🔔 │
└──────────────────────────────────────────────────────────────────────────┘
     ↑ click→RUN      ↑ click→FIX              ↑ node      health   palette  bell
```

| Segment | Component | Data | Interaction |
|---------|-----------|------|-------------|
| Running | `OpStatChip` variant=running | `GET /workflows` count active | → RUN filtered |
| Needs you | `OpStatChip` variant=attention | FIX queue length | → FIX mode |
| Idle | `OpStatChip` variant=idle | workflows idle | → RUN filtered |
| Node | `OpNodeBadge` | identity from health/settings | tooltip |
| Health | `OpHealthDot` | `GET /monitor/health` | tooltip degraded reasons |
| ⌘K | `OpKbd` | — | open palette |
| Bell | `OpNotifyBell` | unread count | open notification center drawer |

**Style:** 40px height, monospace numbers, semantic color only on chips (emerald/amber/zinc).

---

### 2.2 Alert Bar `OpAlertBar` (below Pulse — optional)

Persistent **system-level** messages. One line. Dismissible.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ ⚠ License expires in 7 days · stub_mode active (Lab) · [Dismiss] [Setup] │
└──────────────────────────────────────────────────────────────────────────┘
```

| Source | Priority | Example |
|--------|----------|---------|
| `GET /license/status` | high | expiry |
| `GET /gateway/status` stub_mode | medium | Lab banner (H7) |
| `GET /monitor/health` degraded | high | component down |
| Server `system_alerts[]` (future) | configurable | maintenance |

**Rules:** Max **one** bar visible; queue others in notification center. Never stack 3 banners.

---

### 2.3 Mode Rail `OpModeRail`

48px icon column. Badge on FIX only.

```text
  ▶   RUN
  ◎   WATCH
  ⚠₃  FIX      ← badge = queue count; hidden when 0
  ⚙   SETUP
```

---

## 3. Universal card system `OpCard`

Single base component. **Variant** + **slots** from manifest.

### 3.1 Base anatomy

```text
┌─ OpCard ─────────────────────────────────────────┐
│ [accent rail]  TITLE                    [menu ⋮]  │
│                subtitle · meta row                  │
│                ┌ signal ┐ ┌ signal ┐ ┌ chips ┐    │
│                [primary CTA]  [secondary]           │
└──────────────────────────────────────────────────┘
```

| Slot | Purpose |
|------|---------|
| `accent` | left 3px bar: running=emerald, attention=amber, denied=red, idle=zinc |
| `title` / `subtitle` | human text from manifest `display` |
| `signals` | up to 3 `OpSignal` pills |
| `chips` | `OpInstitutionChip[]` or tags |
| `actions` | max 2 visible + overflow menu |
| `menu` | drawer open, pin, copy id |

### 3.2 Card variants (finite set)

| `variant` | Used in | Manifest key |
|-----------|---------|--------------|
| `workflow` | RUN canvas | default workflow card |
| `issue` | FIX queue | `fix_rules` → issue card |
| `event` | WATCH stream | normalized event |
| `approval` | FIX queue | pending HITL |
| `agent` | RUN strip, search | agent summary |
| `metric` | drawer, SETUP | single KPI |
| `metric_row` | drawer | row of KPIs |
| `receipt` | Trust drawer | export/receipt |
| `moment` | Memory drawer | moment play |
| `usage` | Cost drawer | token/call meter |
| `institution` | SETUP | plugin install card |
| `skeleton` | loading | placeholder |

**Custom workflow #500:** uses `workflow` variant + manifest fields — **not** a new variant unless ≥3 workflows need it.

### 3.3 `OpSignal` (card metrics)

```text
  last run 2m    ·    blocked    ·    v3
```

| `format` | Renders |
|----------|---------|
| `time_ago` | relative time |
| `boolean_badge` | yes/no/— |
| `number` | formatted count |
| `state_pill` | ENABLED / PAUSED |
| `text` | plain string |
| `unknown` | **—** (H1) |

From manifest `signals[]` — see [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md).

### 3.4 `OpInstitutionChip`

```text
  [TT ●]  [WC ●]  [DG ○]
```

| Dot | Meaning |
|-----|---------|
| ● green | `enabled_in_deployment` + healthy |
| ● amber | degraded |
| ○ grey | not installed |
| — hidden | not in workflow manifest `institutions[]` |

Data: `GET /plugins/status` only.

---

## 4. Stream & list components (WATCH / FIX)

### 4.1 `OpEventRow` (WATCH)

Compact, scannable — not a table.

```text
  12:04:02   allow   agent-abc   mem.write        ns:research
  12:03:58   deny    agent-def   tool.invoke      [Fix →]
```

| Field | Source |
|-------|--------|
| time | `ts` → `time_ago` on hover |
| decision pill | allow/deny/info |
| actor | agent_pid or workflow_id |
| action | verb |
| resource | truncated mono |
| CTA | deny only → FIX |

**Smart:** virtualized list (10k events); pause stream toggle; new events slide in (respect `prefers-reduced-motion`).

### 4.2 `OpIssueCard` (FIX)

Same `OpCard` variant=`issue`. **Inbox semantics.**

```text
┌─ ⚠ billing-sync-wf blocked ──────────────────────┐
│ policy budget exceeded · agent-def · 5m ago         │
│ [ Open workflow ]  [ View denial ]  [ Dismiss ]   │
└───────────────────────────────────────────────────┘
```

Actions from manifest `fix_rules[].actions` or global FIX action registry.

### 4.3 `OpApprovalCard` (FIX / notifications)

Reuse existing HITL pattern — universalized:

```text
┌─ Approval required ────────────────────────────────┐
│ tool.invoke · bridge:mcp-slack · agent-abc          │
│ [ Approve ]  [ Deny ]  [ Details ]                  │
└────────────────────────────────────────────────────┘
```

Data: `GET /tools/approvals/pending`, TT approvals API — **same card**, different `source` field.

---

## 5. Notification system (four layers)

One payload shape `OpNotification`:

```json
{
  "id": "n_abc",
  "level": "info|success|warning|error|attention",
  "title": "Dry-run complete",
  "body": "research-agent-wf · ok=true · 12 events",
  "source": { "kind": "workflow", "id": "research-agent-wf" },
  "actions": [{ "id": "open", "label": "Open", "href": "/workflows/research-agent-wf" }],
  "persistent": false,
  "created_at_ms": 1730000000000
}
```

### 5.1 Layer map

| Layer | Component | TTL | Use |
|-------|-----------|-----|-----|
| **L1 Toast** | `OpToast` / existing `Toaster` | 4–8s | action feedback ("Dry-run started") |
| **L2 Alert bar** | `OpAlertBar` | until dismiss | license, stub_mode, degraded |
| **L3 Notification center** | `OpNotifyCenter` drawer | until read | history, approvals, exports ready |
| **L4 FIX badge** | `OpModeRail` badge | until resolved | needs-you count |

```text
         L2 Alert bar (0-1 line)
┌────────────────────────────────────────┐
│ L1 Toast stack (bottom-right)          │
│   ✓ Workflow enabled                   │
│   ⚠ Dry-run had 1 warning              │
└────────────────────────────────────────┘

  Bell → L3 Notification center
  ⚠ FIX badge → L4 queue
```

### 5.2 Workflow-driven notifications (manifest)

Extend `operator_surface.v1`:

```json
"notifications": [
  {
    "on": "action_complete",
    "action_id": "dry_run",
    "level": "success",
    "title_template": "Dry-run complete",
    "body_template": "{workflow_id} · ok={ok}"
  },
  {
    "on": "fix_rule_match",
    "fix_rule_id": "policy_denied",
    "level": "attention",
    "title_template": "Workflow blocked",
    "persistent": true
  }
]
```

Shell renders — workflow author never writes toast code.

### 5.3 `OpNotifyCard` (inside center)

```text
┌─ ● Dry-run complete ──────────────── 2m ago ─┐
│ research-agent-wf · ok=true · 12 events       │
│ [ Open ]                              [ ✓ ]   │
└───────────────────────────────────────────────┘
```

Mark read · action buttons · swipe dismiss on mobile.

**Data today:** `GET /notifications` + action toasts from API responses. **Future:** `GET /notifications/feed` unified.

---

## 6. Popups & overlays (universal)

| Component | Role | Max size |
|-----------|------|----------|
| `OpDrawer` | primary detail (workflow, agent, topic) | 480px right |
| `OpDialog` | confirm, destructive, short forms | 480px center |
| `OpSheet` | mobile full-height drawer | 100% |
| `OpPopover` | quick actions on card menu | auto |
| `OpTooltip` | hints only | — |

### 6.1 Drawer sections `OpDrawerSection`

Manifest `panels[]` map to sections:

| `panel.type` | Component |
|--------------|-----------|
| `kv` | `OpKeyValueList` |
| `summary_text` | `OpSummaryBlock` |
| `metric` / `metric_row` | `OpMetric` / `OpMetricRow` |
| `event_list` | `OpEventRow` list |
| `table` | `OpDataTable` (compact) |
| `institution_chips` | chip row |
| `timeline` | `OpTimeline` |
| `approval_queue` | `OpApprovalCard` list |
| `json` | `OpJsonBlock` (developer only) |

### 6.2 Confirm dialog `OpConfirm`

Universal destructive guard:

```text
  Pause workflow "research-agent-wf"?
  Running agents may be interrupted.

  [ Cancel ]  [ Pause ]
```

Triggered by manifest actions with `"confirm": true`.

### 6.3 Action result popup `OpResultSheet`

After dry-run / export — human summary first:

```text
┌─ Dry-run result ─────────────────────────────────┐
│ ok=true · blueprint_ops=3 · events=12            │
│ cls: basic_tool_agent · 4 blocks                 │
│ [ Copy run id ]  [ Open in WATCH ]               │
│ [ Developer ▾ JSON ]                           │
└──────────────────────────────────────────────────┘
```

Uses existing `workflow_dry_run_summary_text` logic — **universal for all workflows**.

---

## 7. Command palette 2.0 `OpPalette`

Upgrade from page-only search to **operator command center**.

### 7.1 Layout

```text
┌─ ⌘K ─────────────────────────────────────────────────────────────┐
│ 🔍  run research · deny · approve · memory · cost                 │
├──────────────────────────────────────────────────────────────────┤
│ SUGGESTED                                                         │
│   ▶ Dry-run research-agent-wf                          RUN         │
│   ◎ Show denied events last hour                       WATCH       │
│   ⚠ 1 issue needs you                                  FIX         │
├──────────────────────────────────────────────────────────────────┤
│ WORKFLOWS                                                         │
│   research-agent-wf · HITL Approve and Audit                     │
├──────────────────────────────────────────────────────────────────┤
│ AGENTS · PLUGINS · GO TOPICS                                      │
└──────────────────────────────────────────────────────────────────┘
```

### 7.2 Command kinds

| Kind | Prefix / trigger | Executes |
|------|------------------|----------|
| **RUN** | `run`, `dry-run`, `pause` + workflow name | `POST` manifest action |
| **WATCH** | `show`, `tail`, `denied` | switch mode + filter |
| **FIX** | `approve`, `deny`, `unblock` | approval APIs |
| **GO** | `memory`, `trust`, `cost`, `safety` | open drawer topic |
| **SETUP** | `install`, `settings` | SETUP mode |
| **NAV** | fallback | deep link into shell state |

### 7.3 Smart features

| Feature | Behavior |
|---------|----------|
| **Fuzzy match** | workflows, agents, plugins, commands |
| **Recents** | last 5 commands (localStorage) |
| **Contextual** | on FIX mode, surface fix actions first |
| **Execute in place** | dry-run without leaving palette (show `OpResultSheet`) |
| **Keyboard** | ↑↓ navigate, ↵ execute, esc close |
| **Empty** | show SUGGESTED + onboarding hints |

### 7.4 Data sources

| Row type | API |
|----------|-----|
| Workflows | `GET /workflows` + surface titles |
| Agents | shared `GET /agents` |
| Plugins | catalog + `GET /plugins/status` |
| Actions | manifest `actions[]` aggregated server-side (future `GET /operator/commands`) |
| Pages | route registry (fallback NAV only) |

---

## 8. Smart & light behaviors

| Behavior | Component / pattern |
|----------|---------------------|
| **Skeleton first paint** | `OpCard` variant=skeleton, `OpPulseBar` shimmer |
| **Lazy drawer** | fetch panel APIs only when drawer opens |
| **Optimistic UI** | card state updates on action click, revert on error |
| **Virtualized streams** | WATCH list — window 50 rows |
| **Debounced search** | palette 150ms |
| **Reduced motion** | no slide animations; instant toast |
| **Honest empty** | `OpEmpty` with one CTA — never fake metrics |
| **Batch surface** | `GET /workflows/surfaces` — one round trip for RUN |
| **Stale-while-revalidate** | show cached cards, refresh quietly |
| **Connection dot** | subtle offline indicator in Pulse |

---

## 9. Visual tokens (modern operator)

| Token | Value | Use |
|-------|-------|-----|
| `--op-bg` | zinc-950 | canvas |
| `--op-surface` | zinc-900/80 | cards |
| `--op-border` | zinc-800/60 | borders |
| `--op-text` | zinc-100 | titles |
| `--op-muted` | zinc-500 | meta |
| `--op-run` | emerald-500 | running, allow |
| `--op-attention` | amber-500 | needs you, warning |
| `--op-deny` | red-500 | denied, error |
| `--op-action` | indigo-600 | primary button (one per card) |
| Radius | 12px cards, 8px chips | consistent |
| Font | UI sans + mono for ids | |
| Density | 16px card padding, 8px gap | light not cramped |

**No:** gradient marketing cards, 3D shadows, multiple primary buttons per card.

---

## 10. Manifest extensions (custom WF without UI PR)

Add to `operator_surface.v1`:

```json
{
  "card": {
    "variant": "workflow",
    "accent_from": "attention|state",
    "max_signals": 3
  },
  "notifications": [ /* §5.2 */ ],
  "overlays": {
    "on_action_complete": { "type": "result_sheet", "action_id": "dry_run" },
    "on_primary_click": { "type": "drawer" }
  },
  "palette_hints": [
    "dry-run {workflow_id}",
    "show denied for {workflow_id}"
  ]
}
```

| Field | Effect |
|-------|--------|
| `card.variant` | which `OpCard` layout |
| `notifications[]` | toast/center rules |
| `overlays` | drawer vs dialog vs result sheet |
| `palette_hints[]` | suggested ⌘K strings |

---

## 11. Component inventory (build list)

### 11.1 Chrome

| Component | File (proposed) | Phase |
|-----------|-----------------|-------|
| `OpPulseBar` | `operator/pulse_bar.rs` | S0 |
| `OpAlertBar` | `operator/alert_bar.rs` | S0 |
| `OpModeRail` | `operator/mode_rail.rs` | S1 |
| `OpHealthDot` | `operator/health_dot.rs` | S0 |
| `OpNotifyBell` | `operator/notify_bell.rs` | N1 |

### 11.2 Cards & streams

| Component | File | Phase |
|-----------|------|-------|
| `OpCard` | `operator/op_card.rs` | W3 |
| `OpSignal` | `operator/op_signal.rs` | W3 |
| `OpInstitutionChip` | `operator/institution_chip.rs` | W5 |
| `OpEventRow` | `operator/event_row.rs` | S3 |
| `OpIssueCard` | `operator/issue_card.rs` | S4 |
| `OpApprovalCard` | refactor `actions.rs` | S4 |
| `OpEmpty` | extend `empty_state.rs` | W3 |
| `OpSkeleton` | extend `skeleton.rs` | S0 |

### 11.3 Notifications

| Component | File | Phase |
|-----------|------|-------|
| `OpToast` | unify `toaster.rs` | U0 |
| `OpNotifyCenter` | `operator/notify_center.rs` | N1 |
| `OpNotifyCard` | `operator/notify_card.rs` | N1 |
| `OpResultSheet` | `operator/result_sheet.rs` | W4 |

### 11.4 Overlays

| Component | File | Phase |
|-----------|------|-------|
| `OpDrawer` | `operator/drawer.rs` | S7 |
| `OpDrawerSection` | `operator/drawer_section.rs` | W4 |
| `OpDialog` | extend `ui/dialog.rs` | S7 |
| `OpConfirm` | `operator/confirm.rs` | W4 |
| `OpPalette` | refactor `layout.rs` SearchModal | S5 |

### 11.5 Panel renderers (drawer)

| Component | Maps from `panel.type` |
|-----------|------------------------|
| `OpKeyValueList` | `kv` |
| `OpSummaryBlock` | `summary_text` |
| `OpMetric` / `OpMetricRow` | `metric` / `metric_row` |
| `OpDataTable` | `table` |
| `OpTimeline` | `timeline` |
| `OpJsonBlock` | `json` |

---

## 12. Execution phases (component track)

| ID | Deliverable | Depends |
|----|-------------|---------|
| **U0** | Unify toast + `fmt_unknown` + honest chips | — |
| **C0** | `OpPulseBar` + `OpAlertBar` + `OpHealthDot` | S0 |
| **C1** | `OpCard` base + variants workflow/issue/event | W3 |
| **C2** | `OpSignal` + `OpInstitutionChip` | W5 |
| **C3** | `OpEventRow` virtualized stream | S3 |
| **C4** | `OpDrawer` + `OpDrawerSection` panel renderer | S7, W4 |
| **C5** | `OpResultSheet` + `OpConfirm` | W4 |
| **C6** | `OpPalette` 2.0 (execute actions) | S5 |
| **N1** | `OpNotifyCenter` + `OpNotifyCard` + bell | notifications API |
| **N2** | Manifest `notifications[]` wiring | W2 |
| **C7** | Visual token pass + reduced motion | S8 |
| **C8** | Storybook / wizard-demo page for all `Op*` variants | docs |

**Parallel start:** `U0` + `C0` + `OpCard` skeleton (`C1` partial).

---

## 13. Success criteria

1. **Card test:** HITL, PII, custom catalog WF — same `OpCard`, different manifest.
2. **Notification test:** dry-run → toast + optional center entry — no page code.
3. **Palette test:** `⌘K` → "dry-run research" → executes POST → result sheet.
4. **Light test:** RUN first paint ≤3 API calls (workflows + surfaces batch + health).
5. **FIX test:** approval appears as `OpApprovalCard` in FIX and notification center.
6. **Modern test:** operator says "feels like a control plane" not "admin website."
7. **Scale test:** 100 workflow cards scroll smoothly (virtualize or paginate).

---

## 14. Wireframe — full shell with components

```text
┌─ OpPulseBar ─────────────────────────────────────────────────────────────┐
│ ● 2 running │ ⚠ 1 needs you │ ○ 5 idle │ prod-eu-1 ● ok │ ⌘K │ 🔔₁      │
├─ OpAlertBar (optional) ──────────────────────────────────────────────────┤
│ ⚠ stub_mode (Lab) — estimates not production billing        [Dismiss]    │
├────┬─────────────────────────────────────────────────────────────────────┤
│ Op │  RUN CANVAS                                                          │
│Mode│  ┌─ OpCard workflow ─────────┐  ┌─ OpCard workflow ─────────┐       │
│Rail│  │ HITL Approve…            │  │ PII Redaction…           │       │
│    │  │ [TT●][WC●]  last run 2m  │  │ [DG●]  paused            │       │
│ ▶  │  │ [ Dry-run ]              │  │ [ Dry-run ]              │       │
│ ◎  │  └──────────────────────────┘  └──────────────────────────┘       │
│ ⚠₁ │                                                                    │
│ ⚙  │  ┌─ OpCard workflow attention ─────────────────────────────┐      │
│    │  │ ⚠ billing-sync blocked · [ See why ] [ Dry-run ]        │      │
│    │  └─────────────────────────────────────────────────────────┘      │
├────┴─────────────────────────────────────────────────────────────────────┤
│ OpToast: ✓ Dry-run complete                                    [×]       │
└──────────────────────────────────────────────────────────────────────────┘

  OpDrawer (on card click)          OpPalette (⌘K)
  ┌──────────────────────┐           ┌─────────────────────────┐
  │ OpDrawerSection kv │           │ 🔍 dry-run research…    │
  │ OpSummaryBlock       │           │ SUGGESTED · WORKFLOWS   │
  │ OpInstitutionChip    │           │ [execute on ↵]          │
  │ [Dry-run][Pause]     │           └─────────────────────────┘
  └──────────────────────┘
```

---

*UOCS is the visual and interaction layer for the Universal Operator Shell. Build `Op*` primitives once; manifests and FIX/WATCH/RUN modes compose them forever.*
