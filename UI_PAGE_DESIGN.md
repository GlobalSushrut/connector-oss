# Operator UI — Page-by-Page Design Spec

**Status:** Data contract layer for v3.1 shell. Pages are **drawer topics** and **deep links**, not the primary IA.

**v3.1 note:** Backend substrate is shipped ([BACKEND_TOP_GRADE_TRACK.md](BACKEND_TOP_GRADE_TRACK.md) T5). Agent lifecycle, graph firewall, and orchestration intelligence are **kernel-authoritative** — UI reads substrate APIs; see [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) §12.

**Read first:** [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) · [UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md) · [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) · [UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md) (Op* cards, notifications, palette) · **[platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md)** (Leptos/WASM — not JS)

**Implementation stack:** Operator UI = **Leptos 0.8 CSR → WebAssembly** in `platform/ui-leptos/dashboard`. New shell components are Rust (`.rs`), styled with Tailwind. Do not add a JavaScript SPA or change the WASM loader without reading the WASM stack doc.

### Leptos / WASM constraints (do not regress)

| Constraint | Detail |
|------------|--------|
| Framework | Leptos 0.8 CSR, `wasm32-unknown-unknown` |
| API client | `gloo-net` in `dashboard/src/api.rs` |
| Boot | `#root` splash in `index.html`; `lib.rs::hydrate()` async mount |
| Playground release | `cargo leptos build --split` + `patch_wasm_init.py` |
| Embed | `connector-platform` `include_dir!` from `dashboard/dist/` or `CONNECTOR_UI_DIR` |
| Sacred files | `patch_wasm_init.py`, `data-no-wasm-opt`, no double `hydrate()` |

Full pipeline: [platform/ui-leptos/UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md).

**Greenfield build:** [UI_GREENFIELD_BUILD_PLAN.md](UI_GREENFIELD_BUILD_PLAN.md) — 38 primitives, 11 cards, 16 overlays, 10 surfaces (not 81 pages).

**How to read each page section:**
- **Who** — how often operators use it
- **Looks like** — ASCII wireframe of the target design (not current chaos)
- **Data map** — every visible block → endpoint → fields → display rule
- **Actions** — buttons the operator can click
- **Empty state** — what shows when there is no data
- **Honesty** — fake-data traps to avoid

---

## Index

| # | Page | Route | Nav tier |
|---|------|-------|----------|
| 0 | [Global shell](#0-global-shell) | — | — |
| 1 | [Workflows](#1-workflows) | `/workflows` | Primary |
| 2 | [Home](#2-home) | `/` | Primary |
| 3 | [Agents](#3-agents) | `/agents` | Primary |
| 4 | [Activity](#4-activity) | `/activity` | Primary |
| 5 | [Apps](#5-apps) | `/apps` | Primary |
| 6 | [Settings](#6-settings) | `/settings` | Primary |
| 7 | [Memory](#7-memory) | `/memory` | Secondary |
| 8 | [Trust](#8-trust) | `/trust` | Secondary |
| 9 | [Cost & usage](#9-cost--usage) | `/books` | Secondary |
| 10 | [Safety](#10-safety) | `/safety` | Secondary |
| 11 | [Monitor](#11-monitor) | `/monitor` | Secondary |
| 12 | [Billing](#12-billing) | `/billing` | Settings |
| 13 | [License](#13-license) | `/license` | Settings |
| 14 | [Secrets](#14-secrets) | `/secrets` | Settings |
| 15 | [Webhooks](#15-webhooks) | `/webhooks` | Settings |
| 16 | [Notifications](#16-notifications) | `/notifications` | Settings |
| 17 | [Tools](#17-tools) | `/tools` | Advanced |
| 18 | [Protocols](#18-protocols) | `/protocols` | Advanced |
| 19 | [Service Map](#19-service-map) | `/service-map` | Advanced |
| 20 | [Infra](#20-infra) | `/infra` | Advanced |
| 21 | [Runtime enforcement](#21-runtime-enforcement) | `/runtime-enforcement` | Advanced |
| 22 | [Debug](#22-debug) | `/debug` | Advanced |
| 23 | [Notebook](#23-notebook) | `/notebook` | Advanced |
| 24 | [TraceTramp dashboard](#24-tracetramp-dashboard) | `/plugins/tracetramp` | Plugin |
| 25 | [WitnessCtl dashboard](#25-witnessctl-dashboard) | `/plugins/witnessctl` | Plugin |
| 26 | [DevGuard dashboard](#26-devguard-dashboard) | `/plugins/devguard` | Plugin |
| 27 | [Setup & onboarding](#27-setup--onboarding) | `/setup/*`, `/install` | Flow |
| 28 | [Control plane substrate](#28-control-plane-substrate) | drawer topics | Drawer |
| 29 | [Conductor (multi-agent)](#29-conductor-multi-agent) | `/multiagent` → drawer | SETUP / drawer |

**Removed pages** (redirect only — no design): Insights, Economy, Marketplace, Topology Center, Verify, Grounding, Disputes, Report Center, Orchestrator (infra DAG only in drawer), Pipeline, Context, CLS Catalog/Builder/Packages/Execution as standalone routes, Plugins Hub, Plugin Marketplace.

**Demoted to drawer** (not removed): Multiagent → §29 Conductor drawer · Firewall → §10 Safety (graph firewall) · Agents fleet → §3 tree + RUN/WATCH rows.

---

## 0. Global shell

**Who:** Every session.  
**Post-login landing:** RUN mode — `/run` or `/workflows` if workflows exist; SETUP onboarding if empty.

### Looks like (v3.1 target — replaces sidebar below)

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ PULSE  ● 2 running  ⚠ 1 needs you  ○ 4 idle  │ node-1 ● ok  │  ⌘K  [user]│
├────┬─────────────────────────────────────────────────────────────────────┤
│ ▶  │  RUN — workflow cards (from GET /workflows/:id/surface)             │
│ ◎  │  ┌─────────────────────┐  ┌─────────────────────┐                     │
│ ⚠  │  │ HITL Approve        │  │ Research loop       │  …                │
│ ⚙  │  │ [TT●][WC●] 2m ago   │  │ [Dry-run]           │                     │
│    │  └─────────────────────┘  └─────────────────────┘                     │
│    │  [Drawer →]  workflow · agent tree · safety · conductor               │
└────┴─────────────────────────────────────────────────────────────────────┘
```

Pulse data: `GET /operator/pulse` · FIX badge: `GET /operator/fix/queue` · WATCH: `GET /operator/watch/events`

### Legacy reference (current dashboard — to retire)

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ [logo] Connector OS          [⌘K Search pages & agents]    [●] [user ▾]  │
├──────────────┬───────────────────────────────────────────────────────────┤
│ WORK         │  Breadcrumb: Workflows › research-agent-wf                │
│ ● Workflows  │  ─────────────────────────────────────────────────────  │
│   Home       │  <page content>                                           │
│   Agents     │                                                           │
│   Activity   │                                                           │
│   Apps       │                                                           │
│ MORE ▾       │                                                           │
│   Memory     │                                                           │
│   Trust      │                                                           │
│   Cost       │                                                           │
│   Safety     │                                                           │
│   Monitor    │                                                           │
│ Settings     │                                                           │
└──────────────┴───────────────────────────────────────────────────────────┘
```

### Data map

| UI block | API | Fields | Display |
|----------|-----|--------|---------|
| Header health dot | `GET /monitor/health` (shared store) | `status`: ok/degraded/down | Green/amber/red; hidden if error |
| Notifications badge | `GET /notifications` (shared) | unread count | Number or hidden |
| User menu | auth session | role, email | Show Admin badge if elevated |
| Search modal | route registry | path, label | No dead links (H9) |
| Developer toggle | localStorage | — | Shows `[Developer ▾]` panels site-wide |

### Honesty
- Health dot never green when `/monitor/health` failed or empty.
- Search must not list removed routes without redirect target.

---

## 1. Workflows

**Route:** `/workflows` · **Nav:** Primary (default)  
**Who:** Daily — primary operator surface.

**Purpose:** Run, pause, dry-run, and author CLS workflows without leaving one page.

### Looks like — main (Run tab)

```text
┌─ Workflows ──────────────────────────────────────────────────────────────┐
│ Run your automations.                                                      │
├────────────────────────────────────────────────────────────────────────────┤
│ [Run] [Templates] [Author] [Packages] [Integrity]     🔍 filter    [↻]    │
├──────────────────┬─────────────────────────────────────────────────────────┤
│ FILTER           │  research-agent-wf                                      │
│ All │ Running │  │  ─────────────────────────────────────────────────────  │
│ Idle │ Attention│  package: basic_tool_agent  state: ● active              │
│                  │  version: v1  fingerprint: abc123…  bytes: 4.2k          │
│ ┌──────────────┐ │  last dry-run: 2m ago · dr_7f3a…                        │
│ │● research    │ │                                                         │
│ │○ support     │ │  [▶ Run]  [Dry-run]  [Pause]  [Resume]  [Versions ▾]   │
│ │⚠ billing     │ │                                                         │
│ │○ ref-basic   │ │  ┌─ Last dry-run ─────────────────────────────────────┐ │
│ └──────────────┘ │  │ ok=true · blueprint_ops=3 · events=12              │ │
│                  │  │ cls: basic_tool_agent · 4 blocks · cid bafy…       │ │
│                  │  └────────────────────────────────────────────────────┘ │
│                  │  [Developer ▾] GET /workflows/:id JSON                   │
└──────────────────┴─────────────────────────────────────────────────────────┘
```

### Looks like — Templates tab

```text
┌─ Templates ────────────────────────────────────────────────────────────────┐
│ Starter workflows you can install in one click.                              │
├────────────────────────────────────────────────────────────────────────────┤
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐               │
│ │ basic_tool_agent│ │ research_loop   │ │ approval_gate   │               │
│ │ Tool + MCP demo │ │ Multi-step RAG  │ │ HITL pattern    │               │
│ │ [Install]       │ │ [Install]       │ │ [Install]       │               │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘               │
└────────────────────────────────────────────────────────────────────────────┘
```

### Looks like — Author tab

```text
┌─ Author ───────────────────────────────────────────────────────────────────┐
│ CCL source editor · compile before save.                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ workflow_id [________]  package_id [________]  [Load template ▾]          │
│ ┌─ CCL source ─────────────────────────────────────────────────────────┐  │
│ │ contract basic_tool_agent { ... }                                     │  │
│ └───────────────────────────────────────────────────────────────────────┘  │
│ [Compile]  [Save version]  [Save as new workflow]                          │
│ Compile result: ok · 4 blocks · contract_cid bafy…  (or error message)    │
│ Plugin actions: list from GET /plugins/workflow-contracts                  │
└────────────────────────────────────────────────────────────────────────────┘
```

### Looks like — Packages tab

```text
┌─ Packages ───────────────────────────────────────────────────────────────┐
│ Registered CLS packages · bind to agents/nodes.                            │
├────────────────────────────────────────────────────────────────────────────┤
│ package_id          version   state      bound agents                      │
│ pkg-research        v3        active     agent-a, agent-b                  │
│ [Register] [Install] [Bind] [Activate] [View execution →]                  │
└────────────────────────────────────────────────────────────────────────────┘
```

### Looks like — Integrity tab

```text
┌─ Integrity (pipeline) ─────────────────────────────────────────────────────┐
│ CID chain and gate status for selected workflow's pipeline.                  │
├────────────────────────────────────────────────────────────────────────────┤
│ pipeline_id: [picker from GET /pipeline/definitions]                       │
│ Gate: pass/fail/—   Steps: N   Integrity hash: …   CID chain: …           │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map — Run tab

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Workflow list | `GET /workflows` | `workflows[].workflow_id`, `package_id`, `version`, `state`, `last_dry_run_id`, `last_dry_run_recorded_at` | Sort Attention first |
| Status buckets | derived from list + `GET /actionlog/denied` | blocked workflow ids | Count badges; `—` if unknown |
| Selected detail | `GET /workflows/:id` | `workflow.state`, `cls_source_fingerprint`, `cls_source_byte_len`, `version_log_len`, `last_dry_run_*` | Human summary line first |
| Dry-run button | `POST /workflows/:id/dry-run` | `ok`, `dry_run.run_id`, `events_replayed`, `dispatched_actions[]`, `cls_compile` | `workflow_dry_run_summary_text()` |
| Dry-run history | `GET /workflows/:id/dry-runs` | `dry_runs[]` | Table: run_id, recorded_at |
| Dry-run detail | `GET /workflows/:id/dry-runs/:run_id` | full replay envelope | Developer panel only |
| Versions | `GET /workflows/:id/versions` | version log | List + diff hint |
| New version | `POST /workflows/:id/versions` | body: cls_source | Flash success |
| Lifecycle | `POST /workflows/:id/lifecycle` | `{ "state": "active"|"paused"|… }` | Button reflects current state |
| **RUN card (shell)** | `GET /workflows/:id/surface` | `signals`, `actions`, `institutions`, `panels` | OpCard renderer — not Run tab table |
| **Pipeline run** | `POST /multiagent/pipeline/run` | `intelligence_chain[]`, `orchestration_waves[]` | Drawer: wave timeline, merge strategy |
| Intelligence contract | `GET /multiagent/intelligence/standard` | control plane vs leaves | Developer blurb in run drawer |

### Data map — Templates tab

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Template cards | `GET /workflows/reference-templates` | `id`, `title`, `description`, `cls_source` | Card per template |
| Install | `POST /workflows` | `{ workflow_id: "ref-{id}", package_id, version, cls_source }` | Redirect to `/workflows/:id` |

### Data map — Author tab

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Templates dropdown | `GET /workflows/reference-templates`, `GET /contracts/templates` | `cls_source` | Load into editor |
| Plugin contracts | `GET /plugins/workflow-contracts` | action list | Sidebar reference |
| Compile | `POST /cls/compile` | `ok`, `block_count`, `contract_cid`, `error` | Show errors inline |
| Save | `POST /workflows` or `POST /workflows/:id/versions` | — | Flash + refresh list |

### Data map — Packages tab

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Package list | `GET /cls/packages` | `package_id`, `version`, state | Table |
| Package detail | `GET /cls/packages/:id` | bind info, lifecycle | Detail drawer |
| Register | `POST /cls/packages` | `package_id`, `version` | — |
| Install | `POST /cls/packages/:id/install` | — | — |
| Bind | `POST /cls/packages/:id/bind` | `agent`, `node`, `environment` | Agent picker |
| Lifecycle | `POST /cls/packages/:id/lifecycle` | `action` | — |
| Execution | `GET /cls/packages/:id/execution` | runs, explain, risk | Link from package row |

### Data map — Integrity tab

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Definitions | `GET /pipeline/definitions` | pipeline ids | Picker |
| Gate | `GET /pipeline/:id/gate` | pass/fail | No pass on empty |
| Steps | `GET /pipeline/:id/steps` | step list | — |
| Integrity | `GET /pipeline/:id/integrity` | hash | — |
| CID chain | `GET /pipeline/:id/cid-chain` | chain[] | Monospace |

### Actions
- **Run** / **Dry-run** / **Pause** / **Resume** — lifecycle + dry-run POSTs
- **Install template** — POST /workflows
- **Compile** / **Save** — Author tab
- **Bind package** — Packages tab with live agent picker

### Empty state
```text
No workflows yet.
Install a starter template to run your first automation.
[Install basic_tool_agent]  [Browse all templates]
```
No links to removed `/cls-catalog` routes.

### Honesty
- Empty list ≠ "all healthy"
- Dry-run errors shown as text, not silent JSON
- `state` from API only; no invented "running" spinner

---

## 2. Home

**Route:** `/` · **Nav:** Primary  
**Who:** Daily glance; first-run landing when no workflows exist.

### Looks like

```text
┌─ Home ─────────────────────────────────────────────────────────────────────┐
│ What's happening on this node.                                               │
├────────────────────────────────────────────────────────────────────────────┤
│ NEEDS YOU                                                                    │
│ ┌──────────────┬──────────────┬──────────────┬──────────────────────────┐  │
│ │ Workflows    │ Approvals    │ Trust        │ Incidents                │  │
│ │ 1 attention  │ 2 pending    │ 82 (score)   │ 0 open                   │  │
│ │ → Workflows  │ → Activity   │ → Trust      │ —                        │  │
│ └──────────────┴──────────────┴──────────────┴──────────────────────────┘  │
│                                                                              │
│ MY WORKFLOWS (quick run)                    RECENT ACTIVITY                  │
│ [▶ research-agent] [▶ support-triage]     allow · agent-x · 2m ago         │
│ [See all →]                                 deny · agent-y · 5m ago          │
│                                             [See all → Activity]             │
│                                                                              │
│ ACTIVE AGENTS (3)                           ▼ Show cost details (lazy)       │
│ agent-a · running · 12m ago                 ▼ Show LLM gateway (lazy)        │
│ agent-b · idle                              ▼ Show recommendations (if any)  │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Needs-you: workflows | `GET /workflows` + `GET /actionlog/denied` | attention count | Link to Workflows filtered |
| Needs-you: approvals | `GET /surfaces/overview/system` | `pending_approvals` | `—` if missing |
| Needs-you: trust | `GET /surfaces/overview/system` | `trust_score` | `—` not `0` |
| Needs-you: incidents | `GET /surfaces/overview/system` | `open_incidents` | `—` if missing |
| My workflows row | `GET /workflows` (top 5) | `workflow_id`, `state` | Quick dry-run button |
| Recent activity | `GET /actionlog/actions?limit=20` | `action`, `agent_pid`, `decision`, `ts` | `time_ago_str` |
| Active agents | shared `GET /agents` | `pid`, `status`, `last_seen` | Max 5 rows |
| Cost (lazy) | `GET /monitor/cost-dashboard`, `GET /books/costs?period=month` | tokens, calls, `usd_estimate` | Label USD as **estimated**; `—` if null |
| Gateway (lazy) | `GET /gateway/status` | providers, stub_mode | **Lab** banner if stub_mode |
| Recommendations | recommendations component | list | Hidden when empty |

### Actions
- Click worklist cells → navigate
- Quick **▶** on workflow → `POST /workflows/:id/dry-run` with toast
- Expand lazy sections

### Empty state
First-run: tutorial row + CTA "Install your first workflow → Apps"

### Honesty
- Never `unwrap_or(0.0)` for cost
- Trust score `—` when surface unavailable (amber banner, not fake 0)

---

## 3. Agents

**Route:** `/agents` (deep link) · **Shell:** RUN/WATCH rows + **drawer with progeny tree**  
**Who:** Several times per week — fleet management, not deep debugging.

**v3.1:** Kernel `parent_pid` / `child_pids` is the only tree. Flat list is a **collapsed forest** view; detail opens tree panel.

### Looks like — fleet list (RUN/WATCH or `/agents` redirect)

```text
┌─ Agents (forest roots) ────────────────────────────────────────────────────┐
│ Kernel progeny · GET /agents/progeny/tree                    [+ Create]     │
├────────────────────────────────────────────────────────────────────────────┤
│ FILTER: All │ Running │ Stopped                    🔍 search                 │
├────────────────────────────────────────────────────────────────────────────┤
│ NAME              PID           STATE      CHILDREN  MODEL         LAST       │
│ Research Agent    agent-abc     ● running  2 ↳       gpt-4.1       2m ago     │
│ Support Bot       agent-def     ○ stopped  0         claude-3      2d ago     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Looks like — agent detail (drawer, tree panel)

```text
┌─ Research Agent (agent-abc) ─────────────────────────────────────────────────┐
│ ● running · namespace m/research · model gpt-4.1 · depth 1 · 2 children      │
├────────────────────────────────────────────────────────────────────────────┤
│ PROGENY (kernel SoT)                                                          │
│   └─ agent-child-a  ● running                                                │
│   └─ agent-child-b  ○ waiting                                                │
│ GET /agents/:pid/progeny                                                       │
│                                                                               │
│ [Start] [Stop] [Terminate subtree…]  ← cascade confirm uses terminated_subtree │
│                                                                               │
│ ENFORCEMENT (graph firewall)                                                  │
│ Breaker: closed · rules: 5 active · parent quarantine: no                     │
│ GET /firewall/status/:pid                                                      │
│                                                                               │
│ SUMMARY                                                                       │
│ Memory packets: 142    Tool card: 3 tools    Cost: — (see Cost & usage)      │
│ Last activity: allow mem.write · 2m ago → WATCH                              │
│                                                                               │
│ QUICK LINKS                                                                   │
│ [Memory] [Workflows bound] [WATCH filtered] [Context snapshots]              │
│                                                                               │
│ [Developer ▾] lifecycle/standard · verify JSON · raw ACB                     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map — fleet

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Progeny forest | `GET /agents/progeny/tree` | `roots[]`, `nodes[].children`, `depth` | Tree or indented list; kernel SoT |
| Agent list (fallback) | shared `GET /agents` | `pid`, `name`, `status`, `model`, `last_active` | Merge with tree for roots only |
| Create agent | `POST /agents` | + optional `parent_pid` | Parent picker from tree |
| Clone | `POST /agents/:pid/clone` | `child_pid`, `kernel_pid`, `parent_kernel_pid` | Links into progeny tree |

### Data map — detail

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Progeny subtree | `GET /agents/:pid/progeny` | `children`, `depth`, `parent_pid` | Expandable tree |
| Lifecycle contract | `GET /agents/lifecycle/standard` | `kernel_status_map`, `not_this` | Developer only |
| Graph firewall | `GET /firewall/status/:pid` | breaker, rules, quarantine | Enforcement panel |
| Agent record | `GET /agents/:pid` | status, namespace, model, lifecycle | Header |
| Terminate | `DELETE /agents/:pid` | `terminated_subtree[]` | Confirm cascade |
| Lifecycle | `POST /agents/:pid/{start,stop,…}` | — | Buttons |
| Memory stats | `GET /agents/:pid/memory/stats` | packet counts | Number or `—` |
| Memory preview | `GET /agents/:pid/memory` | recent packets | Collapsed |
| Cost | `GET /agents/:pid/cost` | usage meters | `—` not `$0`; link to Cost page |
| Activity | `GET /agents/:pid/activity` | recent actions | 5 rows + link |
| Timeline | `GET /history/agents/:pid/timeline?limit=50` | events | Developer only |
| Tool card | `GET /tools/agents/:pid/card` | tools[] | Developer only |
| Verify | `GET /agents/:pid/verify` | verify result | Developer only |
| Compliance | `GET /compliance/policy-violations` | violations for pid | Developer only |
| Context snapshots | `GET /context/:pid/snapshots` | snapshot list | Expandable; empty = "No snapshots" |

### Actions
- Create, Start, Stop, Restart
- Navigate to Memory / Workflows / Activity with query filter

### Empty state
"No agents yet. Create one or install a workflow that spawns an agent."

### Honesty
- No hardcoded `agent-1`
- Cost `—` when endpoint empty
- **No fake parent/child** — only show links present in `GET /agents/progeny/tree`
- Terminate always warns when `terminated_subtree` length > 1

---

## 4. Activity

**Route:** `/activity` (aliases: `/actionlog`, `/history`) · **Nav:** Primary  
**Who:** Daily — "what happened" and "what was blocked."

### Looks like

```text
┌─ Activity ─────────────────────────────────────────────────────────────────┐
│ Audit trail for this node.                                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ [Actions] [Denied]     Advanced ▾                                            │
├────────────────────────────────────────────────────────────────────────────┤
│ TIME          AGENT        ACTION           DECISION    RESOURCE             │
│ 2m ago        agent-abc    mem.write        allow       ns:research          │
│ 5m ago        agent-def    tool.invoke      deny        policy:budget        │
│                                                                              │
│ Export: [Download JSONL]  → GET /actionlog/export/jsonl                      │
└────────────────────────────────────────────────────────────────────────────┘

Advanced ▾ opens:
  Interactions · Tool audit · Access matrix · Kernel audit
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Actions | `GET /actionlog/actions` | `ts`, `agent_pid`, `action`, `decision`, `resource` | Default tab |
| Denied | `GET /actionlog/denied` | same shape | Highlight deny rows |
| Interactions | `GET /actionlog/interactions` | conversation turns | Advanced |
| Tool audit | `GET /actionlog/tool-audit` | tool calls | Advanced |
| Access matrix | `GET /actionlog/access-matrix` | matrix | Advanced |
| Kernel audit | `GET /history/audit` | kernel events | Advanced |
| Export link | `GET /actionlog/export/jsonl` | file | Button, not a page |

### Actions
- Filter by agent (query param)
- Export JSONL / OTEL (links in footer)

### Empty state
"No actions recorded yet. Run a workflow or agent to generate activity."

### Honesty
- Empty ≠ "all secure"

---

## 5. Apps

**Route:** `/apps` · **Nav:** Primary  
**Who:** Weekly — install TraceTramp, WitnessCtl, DevGuard, workflow templates.

### Looks like

```text
┌─ Apps ─────────────────────────────────────────────────────────────────────┐
│ Install plugins and starter workflows.                                       │
├────────────────────────────────────────────────────────────────────────────┤
│ FEATURED INSTITUTIONS                                                        │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                          │
│ │ TraceTramp   │ │ WitnessCtl   │ │ DevGuard     │                          │
│ │ LLM proxy    │ │ Evidence     │ │ Dev connect  │                          │
│ │ [Set up →]   │ │ [Set up →]   │ │ [Set up →]   │                          │
│ └──────────────┘ └──────────────┘ └──────────────┘                          │
│                                                                              │
│ STARTER WORKFLOWS                                                            │
│ ┌─────────────────┐  [Install] → POST /workflows → /workflows/:id          │
│                                                                              │
│ ALL PLUGINS                                                                  │
│ name · enabled_in_deployment · [Open] · [Deferred] badge if not shipped     │
│                                                                              │
│ INSTALLED (collapsed)                                                        │
│ GET /apps live state — developer disclosure only                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Featured plugins | static catalog + `GET /plugins/status` | `enabled_in_deployment` | Real setup links only |
| Templates | `GET /workflows/reference-templates` | `id`, `title`, `cls_source` | Install → POST /workflows |
| All plugins | catalog + `GET /plugins/status` | per-plugin status | Deferred badge if stub |
| Installed apps | `GET /apps` | live state | Behind disclosure |
| Plugin path | `GET /plugins/status` | health | Status dot on card |

### Actions
- **Set up** → `/plugins/{slug}/setup` or dashboard
- **Install** template → POST /workflows → redirect Workflows
- **Open** installed plugin dashboard

### Empty state
"Install TraceTramp to govern LLM traffic" (single CTA, not 3 fake marketplaces)

### Honesty
- No "coming soon" primary CTA (H6)
- Links to `/books` not `/cost`; memory → `/memory` not `/policies`

---

## 6. Settings

**Route:** `/settings` · **Nav:** Primary  
**Who:** Rare — admin / platform setup.

### Looks like

```text
┌─ Settings ─────────────────────────────────────────────────────────────────┐
│ Node configuration.                                                          │
├────────────────────────────────────────────────────────────────────────────┤
│ [Node] [LLM routing] [System] [Admin ▾]                                      │
├────────────────────────────────────────────────────────────────────────────┤
│ NODE                                                                         │
│ Runtime mode: [strict ▾]   [Save]  → POST /runtime/mode                      │
│                                                                              │
│ LLM ROUTING (forms, not raw JSON default)                                    │
│ Providers · Rules · Overrides · Guardrails · Privacy tags                    │
│ GET/POST /settings/llms/*                                                    │
│                                                                              │
│ SYSTEM                                                                       │
│ Networking · Identity · Backup · Telemetry · License summary                 │
│ GET/POST /settings/system/*                                                  │
│                                                                              │
│ ADMIN (elevated role only)                                                   │
│ Pilots: create · extend · scope  → POST /admin/pilots/*                      │
│                                                                              │
│ Quick links: [Secrets] [Webhooks] [Notifications] [Billing] [License]        │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Section | GET | POST | Notes |
|---------|-----|------|-------|
| Runtime mode | `/runtime/mode` | `/runtime/mode` | — |
| LLM providers | `/settings/llms/providers` | same | Form preferred over JSON textarea |
| Routing rules | `/settings/llms/routing-rules` | same | — |
| Overrides | `/settings/llms/overrides` | same | — |
| Guardrails | `/settings/llms/guardrails` | same | — |
| Privacy tags | `/settings/llms/privacy-tags` | same | — |
| Charts | `/settings/llms/charts` | — | Read-only |
| System networking | `/settings/system/networking` | `/settings/system/networking` | — |
| System identity | `/settings/system/identity` | same | — |
| Backup | `/settings/system/backup` | same | — |
| Telemetry | `/settings/system/telemetry` | same | — |
| License summary | `/settings/system/license` | same | Link to /license |
| Pilots | `/admin/pilots` | `/admin/pilots`, extend, scope | Admin+ only |

### Honesty
- Pilot admin behind role banner
- JSON textareas only in Developer view

---

## 7. Memory

**Route:** `/memory` · **Nav:** Secondary  
**Who:** Weekly — recall, write, inspect moments.

### Looks like

```text
┌─ Memory ───────────────────────────────────────────────────────────────────┐
│ Agent memory — browse, write, and replay moments.                            │
├────────────────────────────────────────────────────────────────────────────┤
│ [Browse] [Write] [Moments]                                                   │
├────────────────────────────────────────────────────────────────────────────┤
│ BROWSE                                                                       │
│ Agent: [picker from GET /memory/agents ▾]                                    │
│ ┌─ Sessions ─────────────┐  ┌─ Semantic search ─────────────────────────┐ │
│ │ GET /memory/sessions/  │  │ query [____] [Search]                     │ │
│ │ list                   │  │ GET /memory/semantic-search?q=            │ │
│ └────────────────────────┘  └───────────────────────────────────────────┘ │
│ Tree: GET /agents/:pid/memory/tree (when agent selected)                   │
│                                                                              │
│ WRITE                                                                        │
│ namespace [____]  content [________________]  [Write]                        │
│ POST /memory/write                                                           │
│                                                                              │
│ MOMENTS (Grade C — when API ships)                                           │
│ identity_key [____]  CID [____]  [Play]                                      │
│ GET /memory/vector-box · GET /memory/vector-box/:cid                         │
│ super_key · identity_key · timestamp · hydrate budget                      │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Agent list | `GET /memory/agents` | agent pids | Picker |
| Plane overview | `GET /memory/plane/overview` | stats | Summary card |
| Sessions | `GET /memory/sessions/list` | sessions[] | Timeline |
| Memory tree | `GET /agents/:pid/memory/tree` | tree | Per agent |
| Semantic search | `GET /memory/semantic-search?q=` | hits[] | Results list |
| Write | `POST /memory/write` | namespace, content | Flash |
| Recall | `GET /memory/recall/:ns` | packets | On demand |
| Knowledge query | `POST /memory/knowledge/query` | facts[] | Advanced |
| Vector box list | `GET /memory/vector-box` | boxes[] | Moments tab |
| Vector box play | `GET /memory/vector-box/:cid` | `play.super_key`, `play.identity_key`, planes | Play surface card |
| Graph (advanced) | `GET /memory/graph/entities` | entities | Developer only |
| Stale analysis (advanced) | `GET /memory/stale-analysis` | stale packets | Developer only |

### Actions
- Write memory, search, play moment
- Link to Trust for proof export (no duplicate Proof tab)

### Empty state
"No memory for this agent yet. Write a packet or run a workflow that uses memory."

### Honesty
- Hide tabs whose APIs return "not exposed"
- Graph/lineage not in primary Browse path

---

## 8. Trust

**Route:** `/trust` · **Nav:** Secondary  
**Who:** Rare — audit, compliance export, proof verification.

### Looks like

```text
┌─ Trust ────────────────────────────────────────────────────────────────────┐
│ Trust scores, receipts, and exports.                                         │
├────────────────────────────────────────────────────────────────────────────┤
│ [Score] [Receipts] [Exports] [Compliance]                                    │
├────────────────────────────────────────────────────────────────────────────┤
│ SCORE                                                                        │
│ Trust score: 82   (from GET /monitor/trust)                                  │
│ Trend/sparkline if present · — if unavailable                                │
│                                                                              │
│ RECEIPTS                                                                     │
│ receipt_id · agent · framework · verified: Pending|Verified|Failed           │
│ GET /reports/center · GET /proof/list                                        │
│                                                                              │
│ EXPORTS (ex-Report Center)                                                   │
│ report type · status · [Download]                                            │
│ Verified badge ONLY after GET /proof/merkle-proof/:cid or verify endpoint    │
│                                                                              │
│ COMPLIANCE → links to full Compliance view (nested)                          │
│                                                                              │
│ Merkle lookup: CID [____] [Verify]  GET /proof/merkle-proof/:cid             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Score | `GET /monitor/trust` | score, components | `trust_color()`; `—` if null |
| Receipts | `GET /reports/center` | receipts[] | Table |
| Proof index | `GET /proof/list` | proofs[] | Table |
| Merkle verify | `GET /proof/merkle-proof/:cid` | proof chain | VerifiedBadge (H3) |
| SCITT | `GET /proof/scitt-receipt/:cid` | receipt | Advanced |
| Exports | `GET /reports/center` | reports[], `verified` | No green without verify |
| Per-agent receipts | `GET /agents/:pid/audit/receipts` | receipts | Link from agent |

### Honesty
- **H3:** `verified` bool → Pending unless verify API succeeded
- No "Verified" from `unwrap_or(false)`

---

## 9. Cost & usage

**Route:** `/books` (label: **Cost & usage**) · **Nav:** Secondary  
**Who:** Weekly — finance/ops checking spend drivers.

### Looks like

```text
┌─ Cost & usage ─────────────────────────────────────────────────────────────┐
│ Fundamental usage meters — tokens, calls, models. USD is estimated.          │
├────────────────────────────────────────────────────────────────────────────┤
│ [Usage] [Journal] [Balance]                                                  │
├────────────────────────────────────────────────────────────────────────────┤
│ USAGE (primary)                                                              │
│ Period: [today ▾] [month] [all]   GET /books/costs?period=                   │
│ ┌────────────┬────────────┬────────────┬────────────┐                        │
│ │ Tokens     │ API calls  │ Models     │ Agents     │                        │
│ │ 1.2M       │ 4,521      │ 3 active   │ 5          │                        │
│ └────────────┴────────────┴────────────┴────────────┘                        │
│ Per-model table: model · tokens · calls · source badge · usd_est (~)         │
│ Also: GET /billing/usage for quota context                                   │
│                                                                              │
│ JOURNAL                                                                      │
│ GET /books/journal?limit=100 — searchable ledger                             │
│                                                                              │
│ BALANCE                                                                      │
│ GET /books/balance · GET /books (position)                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Usage meters | `GET /books/costs?period=` | tokens, calls, by_model[] | **Primary headline** |
| Billing usage | `GET /billing/usage` | quota, events | Secondary |
| Journal | `GET /books/journal?limit=100` | entries[] | Search/filter |
| Position | `GET /books` | `data` | System position |
| Balance | `GET /books/balance` | balance | `—` if null |

### Honesty
- **H1/H5:** USD labeled `~estimated`; meters are primary
- `token_source` badge when provider-reported vs inferred

---

## 10. Safety

**Route:** `/safety` (deep link) · **Shell:** FIX item + ⌘K GO → **Safety drawer topic**  
**Who:** Rare — security review, breaker triage, disputes.

**v3.1:** Graph Firewall v1 is the **top enforcement layer** (relation graph + agentic breaker). Legacy baselines are developer-only.

### Looks like

```text
┌─ Safety (drawer) ──────────────────────────────────────────────────────────┐
│ Graph firewall · formal · grounding · disputes                               │
├────────────────────────────────────────────────────────────────────────────┤
│ GRAPH FIREWALL (primary)                                                     │
│ Fleet: GET /firewall/status — tripped: 0 · agents monitored: 12              │
│ Contract: GET /firewall/standard (relation graph + breaker semantics)        │
│ Per-agent: picker → GET /firewall/status/:pid                                │
│ Admin: POST /firewall/rules (dynamic rules)                                  │
│                                                                              │
│ OVERVIEW                                                                     │
│ Formal invariants: GET /safety/formal/verify                                 │
│ Status: configured / not configured / N violations                           │
│                                                                              │
│ FORMAL / GROUNDING / DISPUTES (collapsed sections — same as before)          │
│                                                                              │
│ [Developer ▾] baselines · adjustments · false-positives (legacy sub-layer)   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab / section | API | Key fields | Display rule |
|---------------|-----|------------|--------------|
| Graph firewall fleet | `GET /firewall/status` | tripped, rule_count, agents | Empty ≠ secure |
| Graph firewall contract | `GET /firewall/standard` | built-in rules, breaker | Developer blurb |
| Per-agent enforcement | `GET /firewall/status/:pid` | breaker_state, graph_edges | Link from WATCH deny |
| Dynamic rules | `POST /firewall/rules` | rule_id, action | Admin only |
| Overview | `GET /safety/formal/verify` | invariants[] | Empty = "not configured" |
| Claims | `POST /safety/claims/verify` | claim result | Form |
| Firewall baselines (legacy) | `GET /firewall/baselines` | rules[] | Developer ▾ only |
| Firewall FP (legacy) | `GET /firewall/false-positives/:pid` | fps[] | Developer ▾ |
| Formal verify | `GET /safety/formal/verify` | results | No "all passed" on empty |
| Formal report | `GET /safety/formal/report` | summary | — |
| Violations | `GET /safety/formal/violations` | list | — |
| Grounding stats | `GET /grounding/stats` | categories | `—` not 0 categories |
| Grounding tables | `GET /grounding/tables` | tables[] | — |
| Disputes | `GET /disputes/decisions` | decisions[] | No template confidence 0.95 |

### Honesty
- **H4:** live agent picker everywhere
- Empty graph firewall status ≠ "no threats"
- Denied operations in WATCH should deep-link to `/firewall/status/:pid` when graph rule fired

---

## 11. Monitor

**Route:** `/monitor` · **Nav:** Secondary  
**Who:** Rare — health checks, anomaly review.

### Looks like

```text
┌─ Monitor ──────────────────────────────────────────────────────────────────┐
│ Node health and anomalies. Cost → Cost & usage.                              │
├────────────────────────────────────────────────────────────────────────────┤
│ [Health] [Anomalies]                                                         │
├────────────────────────────────────────────────────────────────────────────┤
│ HEALTH                                                                       │
│ Status: ok/degraded/down  GET /monitor/health (shared)                        │
│ Sub-panels (collapsed): Tools · Signals · SLOs · Storage                     │
│   GET /monitor/tools · /signals · /slos · /storage/layout                      │
│                                                                              │
│ ANOMALIES                                                                    │
│ GET /monitor/anomalies — table of anomalies                                  │
│                                                                              │
│ Link: "LLM metrics & cost → Cost & usage"                                    │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Health | shared `GET /monitor/health` | `status`, components | Header + shared store |
| LLM | `GET /monitor/llm` | model stats | Link out to Cost |
| Anomalies | `GET /monitor/anomalies` | anomalies[] | Default secondary tab |
| Tools | `GET /monitor/tools` | — | Advanced chip |
| Signals | `GET /monitor/signals` | — | Advanced |
| SLOs | `GET /monitor/slos` | — | Advanced |
| Storage | `GET /monitor/storage/layout` | — | Advanced |
| Cost (removed from nav) | `GET /monitor/cost-dashboard` | totals | Redirect to /books |
| Budget | `GET /monitor/budget-alerts` | alerts | Link to Cost |
| Forecast | `GET /monitor/forecast` | — | Link to Cost |

### Honesty
- Cost tab removed from Monitor nav; no `$0` totals here

---

## 12. Billing

**Route:** `/billing` · **Nav:** Settings  
**Who:** Monthly — invoices and entitlements.

### Looks like

```text
┌─ Billing ──────────────────────────────────────────────────────────────────┐
│ Invoices and plan entitlements. Usage meters → Cost & usage.                 │
├────────────────────────────────────────────────────────────────────────────┤
│ [Entitlements] [Invoices]                                                    │
│ GET /billing/entitlements                                                    │
│ GET /billing/invoices                                                        │
│ (usage tab removed — see /books)                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Tab | API | Key fields | Display rule |
|-----|-----|------------|--------------|
| Entitlements | `GET /billing/entitlements` | plan, limits | — |
| Invoices | `GET /billing/invoices` | invoices[] | PDF links if present |
| ~~Usage~~ | ~~`GET /billing/usage`~~ | moved to Cost page | — |

### Honesty
- Overage estimates labeled **estimated**, not headline

---

## 13. License

**Route:** `/license` · **Nav:** Settings  
**Who:** Rare.

### Looks like

```text
┌─ License ──────────────────────────────────────────────────────────────────┐
│ License status for this node.                                                │
├────────────────────────────────────────────────────────────────────────────┤
│ Status · machine id · heartbeat · expiry                                     │
│ GET /license/status · /license/machine · /license/heartbeat                │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Secrets

**Route:** `/secrets` · **Nav:** Settings (also linked from Settings)  
**Who:** Rare — admin.

### Data map

| Block | API |
|-------|-----|
| Secrets list | `GET /settings/secrets` |
| Master key options | `GET /settings/secrets/master-key/options` |
| Vault status | `GET /infra/vault/status` |
| Audit log | `GET /secrets/audit` |

### Looks like
Form-based secret management; vault stats as secondary card. No duplicate Infra vault UI.

---

## 15. Webhooks

**Route:** `/webhooks` · **Nav:** Settings  

### Data map
- `GET /webhooks` — endpoint list
- `GET /webhooks/events` — delivery log
- `POST /webhooks` — create

### Looks like
Table of endpoints + event delivery log. Empty = "No webhooks configured."

---

## 16. Notifications

**Route:** `/notifications` · **Nav:** Settings  

### Data map
- `GET /notifications` — alert list (also shared in header)

---

## 17. Tools

**Route:** `/tools` · **Nav:** Advanced  
**Who:** Rare — MCP bridges and approvals.

### Looks like

```text
[Bridges] [Approvals]     Advanced ▾: Signals · Cgroups
GET /tools/mcp/bridges
GET /tools/approvals/pending
POST /tools/mcp/invoke (developer only)
GET /tools/cgroups · GET /tools/signals/handlers
```

### Honesty
- Cgroup cost `—` not `$0.00`

---

## 18. Protocols

**Route:** `/protocols` · **Nav:** Advanced  

### Data map

| Block | API |
|-------|-----|
| CNP overview | `GET /cnp/overview` |
| MCP tools | `GET /protocols/mcp/tools` |
| A2A card | `GET /protocols/a2a/card` |
| Invoke (dev) | `POST /protocols/mcp/handle`, `/a2a/tasks`, `/acp/messages`, etc. |

### Looks like
Connection status list first; invoke JSON panels behind Developer.

---

## 19. Service Map

**Route:** `/service-map` · **Nav:** Advanced  

### Data map
- `GET /plugins/status` — plugin health matrix
- `GET /plugins/service-map` — graph data (service_map_graph component)

### Looks like
Graph + table of cages/plugins/ingress. Empty = "No platform topology reported" not fake green.

---

## 20. Infra

**Route:** `/infra` · **Nav:** Advanced  

### Looks like

```text
[Topology] [Consensus] [Quota] [Orchestrator]
GET /infra/consensus/status
GET /infra/reputation/scores
GET /infra/quota
GET /infra/orchestrator · /infra/orchestrator/sagas
(Vault tab removed → Settings/Secrets)
```

### Honesty
- Empty consensus = "no cluster" not zeros as scores

---

## 21. Runtime enforcement

**Route:** `/runtime-enforcement` · **Nav:** Advanced  

### Data map
- `GET /runtime/enforcement` — event list
- `GET /runtime/enforcement/:sandbox_id` — detail
- `GET /monitor/cgroups` — cgroup metrics

### Looks like
Table of sandbox events; detail drawer. Cost fields `—` not `0.0/0.0`.

---

## 22. Debug

**Route:** `/debug` · **Nav:** Advanced (developer view default off)  

### Data map
- `GET /debug/sessions`, `/debug/sessions/:id`
- `GET /debug/failure-clusters`
- `GET /agents` (for picker)
- `GET /debug/diff?pid_a=&pid_b=`

---

## 23. Notebook

**Route:** `/notebook` · **Nav:** Advanced  

### Data map
- `GET /notebook/kernel`, `/notebook/snippets`
- `POST /notebook/execute`

---

## 24. TraceTramp dashboard

**Route:** `/plugins/tracetramp` · **Nav:** Plugin (from Apps)  
**Who:** Daily for teams using TT institution.

### Looks like

```text
┌─ TraceTramp ───────────────────────────────────────────────────────────────┐
│ LLM proxy · policy · approvals · traces                                      │
├────────────────────────────────────────────────────────────────────────────┤
│ [Overview] [Traces] [Policies] [Approvals] [Blocks] [Quarantine]             │
├────────────────────────────────────────────────────────────────────────────┤
│ Stats cards: requests · blocked · PII hits                                   │
│ Burn rate: labeled "estimated" not exact $/min                                 │
│ Trace table: GET /plugins/tracetramp/admin/traces?limit=40                   │
│ Policy editor · approval queue · operation blocks                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| Block | API |
|-------|-----|
| Hub status | `GET /plugins/status` |
| Plugin status | `GET /plugins/tracetramp/status` |
| Stats | `GET /plugins/tracetramp/admin/stats` |
| Approvals | `GET /plugins/tracetramp/admin/approvals?status=pending` |
| Blocks | `GET /plugins/tracetramp/admin/operation-blocks` |
| Traces | `GET /plugins/tracetramp/admin/traces?limit=40` |
| Policies | `GET /plugins/tracetramp/admin/policies` |
| Quarantine | `GET /plugins/tracetramp/admin/quarantine` |

---

## 25. WitnessCtl dashboard

**Route:** `/plugins/witnessctl` · **Nav:** Plugin  

### Data map

| Block | API |
|-------|-----|
| Health | `GET /plugins/witnessctl/health` |
| Sessions | `GET /plugins/witnessctl/sessions` |
| Per-session compliance | `GET /plugins/witnessctl/compliance/:sid` |
| HITL | `GET /plugins/witnessctl/compliance/:sid/hitl` |
| Custody | `GET /plugins/witnessctl/custody/:sid/status` |
| Pentest decisions | `GET /plugins/witnessctl/pentest/:sid/decisions` |

### Looks like
Session list → session detail with custody/compliance tabs. Real operator UI — keep, simplify JSON defaults.

---

## 26. DevGuard dashboard

**Route:** `/plugins/devguard` · **Nav:** Plugin  

### Data map

| Block | API |
|-------|-----|
| Connect info | `GET /devguard/connect/info` |
| Connect | `POST /devguard/connect` |
| Local profile | `GET/POST /plugins/devguard/local-profile` |
| Extension status | `GET /plugins/devguard/extension/status` |
| Plugin status | `GET /plugins/status` |

### Looks like
Connect tool wizard + local profile editor + extension status.

---

## 27. Setup & onboarding

**Routes:** `/setup/*`, `/install`, `/connect`, `/trial` (playground), plugin `/plugins/*/setup`

### Flow

```text
First login (no workflows):
  Home → tutorial → Apps → Install template OR Set up TT
  → POST /workflows or plugin setup
  → land on /workflows/:id

Playground install:
  /install → GET /playground/session/export → migration bundle

Wizards:
  /agents/create — POST /agents
  /setup/budget, /setup/connect-tool, etc.
```

### Data map

| Wizard | API |
|--------|-----|
| Create agent | `POST /agents` |
| Install workflow | `POST /workflows` from template |
| TT setup | plugin setup routes |
| Playground export | `GET /playground/session/export` |

---

## 28. Control plane substrate

**Shell:** SETUP strip (developer) + Trust drawer footer · **Not a nav page**

**Who:** Operators debugging enforcement; developers validating B-EXIT gates.

### Looks like (drawer / developer panel)

```text
┌─ Substrate health ───────────────────────────────────────────────────────────┐
│ GET /substrate/status — WAL, knot, memwrite, usage_event                     │
│ GET /forensics/status — CFNI, handoff, artifact log readiness              │
│ GET /substrate/admission/matrix — route × admission coverage               │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Substrate status | `GET /substrate/status` | durability, knot, metering | `—` when field absent |
| Forensics readiness | `GET /forensics/status` | cfni, handoff, artifacts | No fake "ready" |
| Admission matrix | `GET /substrate/admission/matrix` | routes[], gated | Developer only |
| Operator pulse | `GET /operator/pulse` | workflows.running, needs_you | Same as Pulse Bar |
| FIX queue | `GET /operator/fix/queue` | items[], count | FIX mode source |
| WATCH events | `GET /operator/watch/events` | unified stream | WATCH mode source |

### Honesty
- Substrate panels never green when endpoint 404/empty
- Admission matrix is informational — not a "security score"

---

## 29. Conductor (multi-agent)

**Route:** `/multiagent` → redirect to SETUP or open **Conductor drawer**  
**Who:** Occasional — mesh grants, pipeline authoring context; not daily ops.

**Replaces:** `pages/multiagent.rs` JSON dump with structured drawer.

### Looks like

```text
┌─ Conductor ──────────────────────────────────────────────────────────────────┐
│ Mesh knowledge plane · grants · pipeline intelligence (not infra DAG)        │
├────────────────────────────────────────────────────────────────────────────┤
│ INTELLIGENCE MODEL                                                           │
│ GET /multiagent/intelligence/standard — control plane schedules waves;     │
│ intelligence leaves execute in parallel; `intelligence_chain[]` on run.      │
│                                                                              │
│ MESH                                                                         │
│ GET /multiagent/mesh/knowledge-plane — namespaces, knot, grants              │
│ Grant: POST /multiagent/mesh/grant · Revoke: POST …/revoke                   │
│                                                                              │
│ PIPELINE (link to workflow)                                                  │
│ Run: POST /multiagent/pipeline/run — progeny_parent chains across waves      │
│ Infra DAG (separate): GET /infra/orchestrator — planner only, not LLM        │
│                                                                              │
│ [Developer ▾] /multiagent/map · /multiagent/ports raw JSON                   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Data map

| UI block | API | Key fields | Display rule |
|----------|-----|------------|--------------|
| Intelligence standard | `GET /multiagent/intelligence/standard` | waves, merge, not_this | Header contract |
| Mesh plane | `GET /multiagent/mesh/knowledge-plane` | knot, grants, edges | Summary cards — not raw JSON default |
| Grants | `POST /multiagent/mesh/grant` | grantor, grantee, namespace | Form with agent pickers |
| Pipeline run | `POST /multiagent/pipeline/run` | intelligence_chain, waves | Link from workflow drawer |
| Agent map | `GET /multiagent/map` | fleet graph | Developer ▾ |
| Ports | `GET /multiagent/ports` | protocol ports | Developer ▾ |

### Honesty
- Do not conflate `/infra/orchestrator` (DAG) with pipeline LLM execution
- Show progeny linkage when pipeline spawns child agents (`parent_pid` in register)

---

## Cross-page components (shared)

| Component | Used on | Behavior |
|-----------|---------|----------|
| `AgentPicker` | Agents, Safety, Memory, Workflows bind | `GET /agents` |
| `AgentTree` | Agent drawer, terminate confirm | `GET /agents/progeny/tree`, `GET /agents/:pid/progeny` |
| `GraphFirewallPanel` | Safety drawer, agent drawer | `GET /firewall/status`, `GET /firewall/status/:pid` |
| `IntelligenceChainTimeline` | Workflow run drawer | pipeline result `intelligence_chain[]` |
| `fmt_unknown()` | All numeric displays | null → `—` |

**Build / runtime:** All components above are **Leptos Rust** compiled to WASM — not React/Vue. Release builds use Trunk (self-deploy) or `cargo leptos build --split` + `patch_wasm_init.py` (playground). See [UI_LEPTOS_WASM_STACK.md](platform/ui-leptos/UI_LEPTOS_WASM_STACK.md).
| `VerifiedBadge` | Trust, Exports | H3 |
| `FlashMsg` | All action pages | toast feedback |
| `ApiErrorBanner` | All fetch pages | honest error |
| `PageLoading` | Suspense boundaries | skeleton |
| shared `request_store` | Home, Monitor, Agents | dedupe health/agents/notifications |

---

## Page → API quick reference

| Page / topic | Primary GET endpoints |
|--------------|----------------------|
| RUN / Workflows | `/workflows`, `/workflows/:id/surface`, `/workflows/:id`, `/operator/pulse` |
| Pulse / FIX / WATCH | `/operator/pulse`, `/operator/fix/queue`, `/operator/watch/events` |
| Agents | `/agents/progeny/tree`, `/agents`, `/agents/:pid/progeny`, `/firewall/status/:pid` |
| Activity | `/actionlog/actions`, `/actionlog/denied`, `/operator/watch/events` |
| Apps | `/apps`, `/plugins/status`, `/workflows/reference-templates` |
| Memory | `/memory/agents`, `/memory/sessions/list`, `/memory/vector-box` |
| Trust | `/monitor/trust`, `/reports/center`, `/proof/list` |
| Cost | `/books/costs`, `/books/journal`, `/billing/usage` |
| Safety | `/firewall/standard`, `/firewall/status`, `/safety/formal/*` |
| Conductor | `/multiagent/intelligence/standard`, `/multiagent/mesh/knowledge-plane` |
| Substrate | `/substrate/status`, `/forensics/status`, `/substrate/admission/matrix` |
| Monitor | `/monitor/health`, `/monitor/anomalies` |
| Settings | `/settings/llms/*`, `/operator/edge/plane`, `/runtime/mode` |
| TraceTramp | `/plugins/tracetramp/admin/*` |
| WitnessCtl | `/plugins/witnessctl/sessions`, `/plugins/witnessctl/compliance/:sid` |
| DevGuard | `/devguard/connect/info`, `/plugins/devguard/local-profile` |

---

*v3.1 data contracts — substrate-aligned. Build target: [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) §12 + tracks S0–D6.*
