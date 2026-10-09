# Universal Operator Shell (UOS)

**The standard Connector should set:** not a dashboard of features — a **global shell** for an **execution system**: open the node, **work through a real agent** (Talk / effects under quantum), with calm instruments for what just ran and what’s blocked.

**Supersedes:** sidebar-with-30-pages mental model. [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) = master plan. **Product gravity (IIA Phase E):** [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md) §0 — execution-first; ATC is the instrument strip, not the identity. [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md) = API/data per drawer. [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) = workflow cards.

---

## 1. What operators should feel (the vibe)

| Feel | Not this |
|------|----------|
| **Execution cockpit** — Talk/act as a bound principal | Feature catalog / admin panel |
| **Instruments on the glass** — pulse, denies, continuity (secondary) | **Only** air-traffic radar with no agent workbench |
| **Mission when needed** — what's blocked, what executed | "Explore our 40 modules" |
| **One breath** — open app → in an agent context or one clear pick | Hunt through More… |
| **Trust through restraint** — show less, mean more | Raw JSON and API paths as UI |
| **Universal** — same shell for playground, self-host, prod | Different nav per deployment |

> **Note:** Early drafts used “air-traffic control” to kill page sprawl. That metaphor **over-rotated** the UI into a control plane. Connector’s backend is an execution spine (identity → quantum → DockLock → receipt). UI must match: **execute first, supervise second**.

**One-sentence promise:**  
*Open Connector → enter an agent → Talk/execute → see effects & fix blocks. No map required.*

**Operator mantra (design north star):**  
**RUN (execute) · WATCH (recorder) · FIX · SETUP** — four verbs, not forty pages.

---

## 2. Why the current plan still isn't enough

The v2 makeover cut pages from ~40 to ~15. That's housekeeping, not a standard.

| Still wrong | Why it fails the vibe |
|-------------|----------------------|
| Sidebar lists "pages" | Teaches product structure, not operator job |
| Home + Workflows + Agents + Activity + Apps | Five doors for one job (run work) |
| "More" for Memory, Trust, Cost… | Archaeology — universal shells don't hide the job |
| Tabs inside tabs (Workflows 5 tabs, Trust 4…) | Cognitive stack, not one canvas |
| Each concern = full page navigation | Context loss; feels like a website |
| No persistent live strip | Operator can't feel pulse without clicking |
| Command palette = page search | Should be **action** search (run, block, export) |

**Target:** An operator who has never seen Connector can sit down and run a workflow in 30 seconds **without learning what CLS means**.

---

## 3. Universal Operator Shell — anatomy

Five layers. Same on every node, every deployment.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ PULSE BAR — always live, always honest                                       │
│ ● 2 running   ⚠ 1 needs you   ○ 5 idle   │  Node: prod-eu-1   healthy   ⌘K  │
├────┬────────────────────────────────────────────────────────────────────────┤
│    │ CONTEXT LINE — one sentence, plain English                              │
│ R  │ "Research workflow blocked by policy · last run 4m ago"                  │
│ U  ├────────────────────────────────────────────────────────────────────────┤
│ N  │                                                                         │
│    │ CANVAS — one primary surface per mode (no page sprawl)                  │
│ W  │                                                                         │
│ A  │   [ the thing you came to do — big, calm, obvious ]                     │
│ T  │                                                                         │
│ C  │                                                                         │
│ H  │                                                                         │
│    │                                                                         │
│ F  ├────────────────────────────────────────────────────────────────────────┤
│ I  │ STRIP (optional) — agents · recent events · meters (glance, not tables) │
│ X  │                                                                         │
├────┴────────────────────────────────────────────────────────────────────────┤
│ DRAWER (right, on demand) — detail without losing canvas                     │
└─────────────────────────────────────────────────────────────────────────────┘

MODE RAIL (left, 48px, icons only):
  ▶ RUN      default · workflows + run actions
  ◎ WATCH    live stream + health
  ⚠ FIX      badge only when queue non-empty
  ⚙ SETUP    install + node config (rare)
```

### 3.1 Pulse Bar (the heartbeat)

**Always visible. Never fake.**

| Segment | Data | Display |
|---------|------|---------|
| Running | `GET /workflows` where `state=active` | `● N running` or hidden if 0 |
| Needs you | denied + blocked WFs + pending approvals | `⚠ N needs you` — **click → FIX mode** |
| Idle | workflows not active | `○ N idle` — muted |
| Node | `GET /monitor/health` + identity | name + ok/degraded/down dot |
| Command | — | `⌘K` — primary navigation |

No logo marketing strip. No tutorial banner on every paint. Pulse Bar **is** the home screen.

### 3.2 Mode Rail (four verbs)

| Mode | Icon | Operator question | Canvas shows |
|------|------|-------------------|--------------|
| **RUN** | ▶ | What should I run? | Workflow deck — cards, not tables |
| **WATCH** | ◎ | What is happening? | Unified live stream |
| **FIX** | ⚠ | What is broken / blocked? | Issue queue (only lit when N>0) |
| **SETUP** | ⚙ | What do I install / configure? | Apps + node settings |

**No fifth mode.** Memory, Trust, Cost, Safety, Monitor, Debug are **not nav items** — they open from drawer, command palette, or FIX queue items.

### 3.3 Canvas (one surface per mode)

Rules:
- **One primary layout** per mode — no tab bar on first paint
- Secondary detail → **drawer**, not route change
- Max **one** optional chip row (e.g. All | Running | Blocked) — never 11 tabs

### 3.4 Context Drawer (right)

Click any object (workflow, agent, event, receipt) → drawer slides in.

| Drawer section | Content |
|----------------|---------|
| Header | Object name + status pill |
| Summary | Human sentences (dry-run summary, not JSON) |
| Actions | 1–3 buttons max |
| Proof / audit | Link row → opens Trust drawer or export |
| Developer ▾ | Raw JSON + API path |

**Routes become deep links into shell state:**  
`/workflows/research-agent` = RUN mode + workflow selected + drawer open.  
Not a separate "page product."

### 3.5 Command Palette (⌘K) — the real nav

Universal shells are keyboard-first. Palette groups:

```text
RUN     run workflow …    dry-run …    pause …
WATCH   show denied       show agent …   tail activity
FIX     unblock …         approve …      export receipt …
GO      memory …          cost …         trust …         (go to drawer topic)
SETUP   install TraceTramp    settings secrets
```

Palette **does** things (`POST /workflows/:id/dry-run`), not just `router.push`.

---

## 4. Mode designs (how each mode looks & what data feeds it)

### 4.1 RUN mode (80% of operator time)

> **Universal workflows:** RUN does not branch per workflow type. Every card is rendered from **`operator_surface.v1`** manifest via `GET /workflows/:id/surface`. See [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md).

**Vibe:** Spotify queue meets launch control — pick something, hit play.

```text
┌─ PULSE: ● 2 running  ⚠ 1 needs you ─────────────────────────────────────────┐
│ CONTEXT: Pick a workflow to run or resume.                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ + Install starter ]                              filter: All ▾  🔍       │
│                                                                             │
│  ┌─────────────────────────────┐  ┌─────────────────────────────┐          │
│  │ ● research-agent-wf         │  │ ○ support-triage-wf         │          │
│  │   active · 2m ago           │  │   paused · 1d ago           │          │
│  │                             │  │                             │          │
│  │   [ ▶ RUN ]    [ dry-run ]  │  │   [ ▶ RUN ]    [ dry-run ]  │          │
│  └─────────────────────────────┘  └─────────────────────────────┘          │
│                                                                             │
│  ┌─────────────────────────────┐                                           │
│  │ ⚠ billing-sync-wf           │  ← amber border = needs you               │
│  │   blocked · policy budget   │     click → FIX item pre-selected         │
│  │   [ see why ]  [ dry-run ]  │                                           │
│  └─────────────────────────────┘                                           │
│                                                                             │
│ STRIP: Agents ●3 running · last event: allow mem.write 12s ago  [Watch →]  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data:**

| UI | API | Notes |
|----|-----|-------|
| Workflow cards | `GET /workflows` | Card = `workflow_id`, `state`, `last_dry_run_recorded_at` |
| Blocked styling | `GET /actionlog/denied` correlated | Amber ≠ fake error |
| ▶ RUN | `POST /workflows/:id/dry-run` or lifecycle | Toast + card pulse |
| Install starter | `GET /workflows/reference-templates` + `POST /workflows` | Empty canvas CTA |
| Agent strip | `GET /agents` + `GET /actionlog/actions?limit=1` | Glance only |

**Drawer (workflow selected):**  
`GET /workflows/:id` → summary text → [Run] [Pause] [Versions] [Author] as drawer sections, not tabs.

**What dies:** separate Home page, CLS Catalog/Builder nav, workflow table with 12 columns.

---

### 4.2 WATCH mode (15% — "what's happening")

**Vibe:** Single tail -f for the node. Not six Activity tabs.

```text
┌─ PULSE ─────────────────────────────────────────────────────────────────────┐
│ CONTEXT: Live activity on this node.                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  filter: [All] [Denied] [Agents▾]                    pause stream ⏸        │
│                                                                             │
│  12:04:02  allow   agent-abc   mem.write      ns:research                   │
│  12:03:58  deny    agent-def   tool.invoke    policy:budget    [Fix →]     │
│  12:03:41  allow   workflow    dry-run.complete  research-agent-wf          │
│  12:03:12  info    system      health.ok                                    │
│                                                                             │
│  ─── load more ───                                                          │
│                                                                             │
│ STRIP: Health ● ok · Anomalies: 0 · LLM gateway: live  [details ▾]         │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data:** merge streams (client-side or future `GET /watch/stream`):

| Source | API |
|--------|-----|
| Actions | `GET /actionlog/actions` |
| Denied | `GET /actionlog/denied` |
| Health ticks | `GET /monitor/health` (poll 30s) |
| Workflow events | dry-run completions from workflows |

**Denied row → FIX:** click `[Fix →]` switches mode to FIX with that item focused.

**Advanced (collapsed):** tool audit, kernel audit, export JSONL — not default WATCH.

---

### 4.3 FIX mode (5% — only when needed)

**Vibe:** Inbox zero for operators. **FIX icon hidden when queue empty.**

```text
┌─ PULSE: ⚠ 3 needs you ──────────────────────────────────────────────────────┐
│ CONTEXT: 3 things need a decision.                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. billing-sync-wf blocked                                                 │
│     policy budget exceeded · agent-def · 5m ago                              │
│     [ Open workflow ]  [ View denial ]  [ Adjust budget → Setup ]           │
│                                                                             │
│  2. Pending tool approval                                                   │
│     bridge:mcp-slack · tool:post_message                                    │
│     [ Approve ]  [ Deny ]                                                   │
│                                                                             │
│  3. Trust export requested                                                  │
│     SOC2 pack · ready                                                       │
│     [ Download ]                                                            │
│                                                                             │
│  When queue empty: "Nothing needs you." → auto-return suggestion to RUN     │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data — FIX queue builder:**

| Queue item type | Source APIs |
|-----------------|-------------|
| Blocked workflow | `GET /actionlog/denied` + `GET /workflows` |
| Pending approval | `GET /tools/approvals/pending` |
| Trust/compliance ready | `GET /reports/center` |
| Anomaly | `GET /monitor/anomalies` |
| Firewall FP | `GET /firewall/false-positives/:pid` (when agent known) |

**One card per issue. Three actions max.** No formal verify UI on first paint.

Memory, Safety, Trust full surfaces open **from FIX item** or **⌘K GO**, not sidebar.

---

### 4.4 SETUP mode (rare — intentional boredom)

**Vibe:** App store back room. Install institutions, tune node, leave.

```text
┌─ SETUP ─────────────────────────────────────────────────────────────────────┐
│                                                                               │
│  INSTITUTIONS (install once)                                                  │
│  [TraceTramp] [WitnessCtl] [DevGuard]   ← real wizards only                   │
│                                                                               │
│  NODE                                                                           │
│  LLM routing · Secrets · License · Webhooks · Billing invoices                  │
│                                                                               │
│  (no marketing cards · no "coming soon" · Deferred = grey, not clickable)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data:** `GET /plugins/status`, `GET /settings/*`, `GET /billing/invoices` — same as today, calmer layout.

---

## 5. Objects, not pages

Universal standard = **stable object model** in the shell.

| Object | Opens from | Drawer shows | Deep link |
|--------|------------|--------------|-----------|
| **Workflow** | RUN card | run, versions, author | `/w/:id` |
| **Agent** | RUN strip, WATCH row | start/stop, memory link | `/a/:pid` |
| **Event** | WATCH stream | denial reason, trace | `/e/:id` |
| **Issue** | FIX queue | resolution actions | `/fix/:id` |
| **Receipt** | FIX or ⌘K | verify, download | `/r/:id` |
| **Moment** | ⌘K GO memory | vector-box play | `/m/:cid` |
| **Usage** | ⌘K GO cost | meters, period | `/cost` |
| **Plugin** | SETUP | setup wizard / dashboard | `/p/:slug` |

Pages in the old sense become **drawer topics** or **palette destinations**.

---

## 6. Visual language (global standard)

### 6.1 Density & typography

| Rule | Spec |
|------|------|
| Hero numbers | `2 running`, `1 needs you` — 24–32px semibold |
| Body | 14px, zinc-300, max 60ch line length |
| Labels | 11px uppercase tracking, zinc-500 |
| Tables | **Banned** on RUN and WATCH first paint — cards and stream only |
| JSON | Developer drawer only |

### 6.2 Color = meaning (sparingly)

| Token | Meaning |
|-------|---------|
| `emerald` | running / allow / healthy |
| `amber` | needs you / degraded / estimated |
| `red` | denied / down / failed |
| `zinc` | idle / unknown / — |
| `indigo` | primary action button only |

No gradient marketing cards. No "Featured" ribbons in RUN mode.

### 6.3 Motion

| Event | Motion |
|-------|--------|
| Workflow running | subtle pulse on card border (2s loop) |
| New WATCH event | slide-in from top, fade old |
| FIX badge | dot on ⚠ icon when queue > 0 |
| Drawer | 200ms slide, no full page transition |

### 6.4 Empty states (honest, one CTA)

| Mode | Empty copy | CTA |
|------|------------|-----|
| RUN | "No workflows yet." | [Install starter workflow] |
| WATCH | "Quiet node. No events yet." | [Run a workflow] |
| FIX | "Nothing needs you." | (hide FIX badge) |
| SETUP | "Node is ready." | [Install TraceTramp] optional |

Never: "100% healthy", `$0.00`, fake green verified.

---

## 7. What happens to old routes

Routes stay for bookmarks/API parity. Shell **absorbs** them.

| Old route | Shell behavior |
|-----------|----------------|
| `/` | Redirect → RUN (or SETUP if first-run) |
| `/workflows` | RUN mode |
| `/workflows/:id` | RUN + drawer |
| `/activity`, `/actionlog` | WATCH mode |
| `/agents`, `/agents/:pid` | RUN strip or drawer |
| `/apps` | SETUP mode |
| `/settings`, `/secrets`, `/billing` | SETUP sections |
| `/memory`, `/trust`, `/books`, `/safety`, `/monitor` | ⌘K GO → drawer topic (no sidebar) |
| `/plugins/tracetramp` | SETUP institution or full-screen plugin (TT is heavy — exception) |
| Removed pages | Redirect per UI_MAKEOVER_PLAN |

**TraceTramp / WitnessCtl / DevGuard** may keep full dashboards (institution consoles) but entry is always SETUP → institution, not sidebar clutter.

---

## 8. Comparison — dashboard vs universal shell

| Dimension | Dashboard (v2 plan) | Universal Operator Shell |
|-----------|---------------------|---------------------------|
| Nav | 6 + More + Settings | 4 modes + ⌘K |
| Home | Separate page | Pulse Bar |
| Workflows | Page with 5 tabs | RUN canvas + drawer |
| Activity | 6-tab page | WATCH stream |
| Blocked items | Hunt across pages | FIX queue |
| Memory/Trust/Cost | Secondary nav | Objects / palette |
| First paint | Pick a page | See pulse + RUN cards |
| Training time | "Learn our IA" | "Press Run" |
| Feels like | Internal admin tool | **OS for intelligence** |

---

## 9. Implementation phases (shell-first)

| Phase | Deliverable | Verify |
|-------|-------------|--------|
| **S0** | Pulse Bar + honest data | 2-second glance test |
| **S1** | Mode rail (4 modes) + route mapping | Old URLs still work |
| **S2** | RUN canvas (workflow cards) + drawer | Run without visiting old /workflows table |
| **S3** | WATCH unified stream | No default Activity tabs |
| **S4** | FIX queue builder | Badge clears when queue empty |
| **S5** | Command palette actions | Run/dry-run from ⌘K |
| **S6** | SETUP calm layout | Install TT in <3 clicks |
| **S7** | Drawer topics (memory, trust, cost) | ⌘K GO opens drawer, not page sprawl |
| **S8** | Visual language pass | No tables/JSON on RUN first paint |

**Do S0–S4 before any new Grade C UI.** Substrate features surface as drawer topics, not new sidebar items.

---

## 10. Success — "universal standard" test

1. **2-second test:** Operator sees running count, needs-you count, health — no click.
2. **30-second test:** New operator installs starter workflow and dry-runs it — never hears "CLS."
3. **Zero More menu:** Everything reachable via mode, drawer, or ⌘K — not sidebar archaeology.
4. **FIX hides when empty:** No anxiety chrome when node is fine.
5. **Same shell** playground + self-host — only SETUP differs (license/billing).
6. **Explain on a napkin:** four verbs, pulse bar, cards, stream, inbox.

---

## 11. File targets (when building shell)

| Piece | Files |
|-------|--------|
| Shell layout | `components/ui/app_shell.rs`, new `operator_shell.rs` |
| Pulse Bar | new `components/pulse_bar.rs` |
| Mode rail | `routes.rs` → mode enum; `layout.rs` |
| RUN canvas | refactor `pages/workflows.rs` → card deck |
| WATCH stream | refactor `pages/actionlog.rs` |
| FIX queue | new `components/fix_queue.rs` |
| Drawer | new `components/context_drawer.rs` |
| Command palette | extend search modal → actions |
| Router | `lib.rs` — shell parent route, deep links |

---

*This is the global shell standard. [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) defines how unlimited workflows (incl. TT/WC/DG) render without per-workflow UI. [UI_PAGE_DESIGN.md](UI_PAGE_DESIGN.md) remains the per-object data contract. Build the shell first; pages become drawers.*
