# Universal Workflow Surface

**Problem:** TraceTramp, WitnessCtl, and DevGuard each have bespoke dashboard pages today. Custom workflows will multiply. **Building a new UI per workflow does not scale** and is not a universal operator standard.

**Answer:** One **shell renderer** + one **Operator Surface manifest** per workflow. The UI never branches on `if workflow == "tracetramp"`. It renders whatever the manifest declares.

**Parent:** [UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md) · [UI_UNIVERSAL_CAPABILITIES.md](UI_UNIVERSAL_CAPABILITIES.md) (export/audit/forensics) · [UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md)

---

## 1. Core idea

```text
┌─────────────────────────────────────────────────────────────────┐
│  OPERATOR SHELL (fixed code — never per workflow)                 │
│  Pulse · RUN cards · WATCH stream · FIX queue · Drawer chrome     │
└────────────────────────────┬────────────────────────────────────┘
                             │ reads
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  OPERATOR SURFACE MANIFEST (per workflow — declarative JSON)    │
│  display · signals · actions · panels · fix_rules · institutions  │
└────────────────────────────┬────────────────────────────────────┘
                             │ calls
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  EXISTING APIs (CLS runtime · plugins · actionlog · dry-run)    │
└─────────────────────────────────────────────────────────────────┘
```

**Rule:** Adding workflow #500 requires **zero UI PRs** — only a manifest (+ CCL source) dropped in catalog or registered via API.

---

## 2. What is a "workflow" in the UI?

Everything the operator **runs** is one **Workflow object** in RUN mode:

| Kind | Example | UI treatment |
|------|---------|--------------|
| **CLS workflow** | `research-agent-wf` | Universal card + manifest |
| **Reference template** | `hitl_approve_audit` | Same — install → becomes workflow |
| **Catalog drop** | `custom/foo.ccl` + sidecar | Auto-sync → same card |
| **Institution bundle** | TT+WC pipeline workflow | Card shows institution **chips**, not separate nav |

TraceTramp, WitnessCtl, DevGuard are **not workflows** in the nav sense — they are **institutions** (plugins) that workflows **use**. The operator runs *"HITL Approve-and-Audit"*, not *"TraceTramp page"*.

### Institution vs workflow

```text
WORKFLOW (what you RUN)          INSTITUTIONS (what it USES)
─────────────────────────        ───────────────────────────
hitl-approve-audit               [TT] [WC]
pii-redaction-pipeline           [DG] [gateway]
my-custom-etl-wf                 [slack] [jira]
ref-basic_tool_agent             (none)
```

Institution health comes from `GET /plugins/status` — shown as small chips on the card, not a separate product entry per plugin.

---

## 3. Three UI tiers (only one is default)

| Tier | Code | When | Operator sees |
|------|------|------|---------------|
| **T0 Universal** | Shell renderer | **Always default** | Card + drawer from manifest |
| **T1 Institution console** | Optional heavy UI | Power users, ⌘K "open TraceTramp console" | Full plugin dashboard (existing TT/WC/DG pages) |
| **T2 Author** | CLS editor | SETUP / developer | CCL compile — not daily ops |

**90% of operators never leave T0.**  
TT/WC/DG dashboards become **T1 escape hatches** linked from drawer footer: *"Open TraceTramp console →"* — not sidebar siblings to every workflow.

---

## 4. Operator Surface manifest

### 4.1 Where it lives

| Source | Path / API |
|--------|------------|
| Catalog sidecar (extend today) | `{name}.ccl` + `{name}.workflow.json` |
| Bundled templates | embedded in `GET /workflows/reference-templates` |
| Runtime registration | `POST /workflows/:id/operator-surface` (new) |
| Plugin merge | `GET /plugins/workflow-contracts` actions/events folded in |
| **Resolved surface (UI reads one place)** | **`GET /workflows/:id/surface`** (new, server merges) |

Today catalog sync already reads `.workflow.json` sidecars (`workflow_id`, `package_id`, `version`). **Extend sidecar with `operator` block** or add `*.operator.json` sibling.

### 4.2 Schema `operator_surface.v1`

```json
{
  "schema": "operator_surface.v1",
  "workflow_id": "hitl-approve-audit",
  "display": {
    "title": "HITL Approve and Audit",
    "subtitle": "Capture → seal → human gate",
    "category": "trust",
    "icon": "shield-check"
  },
  "institutions": ["tracetramp", "witnessctl"],
  "lifecycle": {
    "primary_action": "dry_run",
    "run_label": "Dry-run",
    "enable_label": "Enable"
  },
  "signals": [
    {
      "id": "last_run",
      "label": "Last run",
      "source": "workflow",
      "path": "last_dry_run_recorded_at",
      "format": "time_ago"
    },
    {
      "id": "blocked",
      "label": "Blocked",
      "source": "fix_queue",
      "filter": { "workflow_id": "$self" },
      "format": "boolean_badge"
    }
  ],
  "actions": [
    {
      "id": "dry_run",
      "label": "Dry-run",
      "method": "POST",
      "path": "/workflows/{workflow_id}/dry-run",
      "body": {},
      "when_states": ["ENABLED", "STAGED", "COMPILED", "PAUSED"]
    },
    {
      "id": "enable",
      "label": "Enable",
      "method": "POST",
      "path": "/workflows/{workflow_id}/lifecycle",
      "body": { "state": "ENABLED" },
      "when_states": ["STAGED", "PAUSED"]
    },
    {
      "id": "pause",
      "label": "Pause",
      "method": "POST",
      "path": "/workflows/{workflow_id}/lifecycle",
      "body": { "state": "PAUSED" },
      "when_states": ["ENABLED"]
    }
  ],
  "panels": [
    {
      "id": "summary",
      "title": "Summary",
      "type": "kv",
      "source": "workflow",
      "fields": [
        { "label": "Package", "path": "package_id" },
        { "label": "State", "path": "state" },
        { "label": "Version", "path": "version" }
      ]
    },
    {
      "id": "last_dry_run",
      "title": "Last dry-run",
      "type": "summary_text",
      "source": "api",
      "path": "/workflows/{workflow_id}/dry-runs",
      "summary_fn": "workflow_dry_run_summary"
    },
    {
      "id": "institution_health",
      "title": "Institutions",
      "type": "institution_chips",
      "source": "plugins_status",
      "plugin_ids": ["tracetramp", "witnessctl"]
    },
    {
      "id": "recent_events",
      "title": "Recent activity",
      "type": "event_list",
      "source": "api",
      "path": "/actionlog/actions",
      "query": { "workflow_id": "{workflow_id}", "limit": "10" }
    }
  ],
  "fix_rules": [
    {
      "id": "policy_denied",
      "when": { "source": "actionlog_denied", "match": { "workflow_id": "$self" } },
      "title": "Workflow blocked by policy",
      "actions": ["view_denial", "open_workflow"]
    }
  ],
  "console_links": [
    {
      "institution": "tracetramp",
      "label": "TraceTramp console",
      "path": "/plugins/tracetramp",
      "tier": 1
    },
    {
      "institution": "witnessctl",
      "label": "WitnessCtl console",
      "path": "/plugins/witnessctl",
      "tier": 1
    }
  ]
}
```

### 4.3 Panel types (finite set — universal renderer)

| `type` | Renders | No custom code per workflow |
|--------|---------|----------------------------|
| `kv` | Key-value rows from JSON paths | ✓ |
| `summary_text` | Human sentence block (server or client template) | ✓ |
| `metric` | Single number + label | ✓ |
| `metric_row` | Row of metrics | ✓ |
| `event_list` | WATCH-style rows | ✓ |
| `table` | Generic table from array path | ✓ |
| `institution_chips` | Plugin status dots from `/plugins/status` | ✓ |
| `timeline` | Version log / dry-run history | ✓ |
| `approval_queue` | Pending items from path | ✓ |
| `json` | Developer drawer only | ✓ |

**New workflow need?** Compose existing panel types. Only add a new `type` when **many** workflows need it (quarterly, not per WF).

### 4.4 Action executor (universal)

Shell executes manifest actions without hardcoding:

```text
POST {path} with {body} + path params substituted
→ toast from response.ok / response.error
→ refresh workflow signals
→ if response opens FIX item, bump FIX badge
```

Primary button on card = `lifecycle.primary_action` → first matching `actions[]` entry for current state.

---

## 5. How RUN mode renders any workflow

### 5.1 List (cards)

```text
For each item in GET /workflows:
  surface = GET /workflows/:id/surface  (or default_surface if missing)
  card.title     = surface.display.title || workflow_id
  card.subtitle  = surface.display.subtitle || package_id
  card.state     = workflow.state → universal state pill
  card.chips     = surface.institutions → plugins/status health
  card.signals   = evaluate surface.signals[] (max 3 on card)
  card.primary   = resolve primary_action for current state
  card.attention = any fix_rule matched → amber border
```

### 5.2 Drawer (detail)

```text
Open drawer(workflow_id):
  render surface.panels[] in order
  render surface.actions[] as button row (state-filtered)
  footer: surface.console_links[] (T1 only, small links)
  developer: GET /workflows/:id raw JSON
```

### 5.3 Default surface (no manifest)

When no manifest exists — **still works**, never blank:

```json
{
  "schema": "operator_surface.v1",
  "display": { "title": "{workflow_id}", "subtitle": "{package_id}" },
  "lifecycle": { "primary_action": "dry_run" },
  "actions": [ /* standard dry-run, enable, pause from kernel */ ],
  "panels": [
    { "type": "kv", "fields": ["state", "version", "last_dry_run_recorded_at"] },
    { "type": "timeline", "source": "dry_runs" }
  ]
}
```

Server synthesizes this from `WorkflowRecord` + kernel transitions. **Custom manifest overrides/extends defaults.**

---

## 6. TraceTramp · WitnessCtl · DevGuard (concrete)

### Today (wrong)

```text
Sidebar: Workflows | Apps | … | TraceTramp | WitnessCtl | DevGuard
→ Operator thinks these are 3 products + workflows
→ Each new institution = new sidebar item + new dashboard crate page
```

### Universal (target)

```text
RUN: one card per workflow
  "HITL Approve and Audit"  [TT●] [WC●]  [Dry-run]
  "PII Redaction Pipeline"  [DG●] [gw●]  [Dry-run]

Drawer for HITL:
  Summary · Last dry-run · Institutions (TT up, WC up) · Recent events
  [Dry-run] [Enable] [Pause]
  ─── optional ───
  Open TraceTramp console →   Open WitnessCtl console →

SETUP: install institutions once
  TraceTramp [Set up]   WitnessCtl [Set up]   DevGuard [Set up]
  (same wizards as today — T1 entry points)
```

| Institution | Role in universal UI | T1 console (optional) |
|-------------|----------------------|------------------------|
| **TraceTramp** | Chip on cards that list `"tracetramp"` in manifest; FIX items for TT blocks/approvals | `/plugins/tracetramp` |
| **WitnessCtl** | Chip + custody/export panels via manifest `event_list` / `api` panels | `/plugins/witnessctl` |
| **DevGuard** | Chip on dev-facing workflows; FIX for connect/policy denials | `/plugins/devguard` |

**Workflow templates already declare plugins:**

```json
// GET /workflows/reference-templates
{ "id": "hitl_approve_audit", "plugins": ["tracetramp", "witnessctl"], ... }
```

Manifest generator can **bootstrap** `institutions[]` and `console_links[]` from template `plugins[]` until authors customize.

### FIX queue (institution-aware, still universal)

FIX builder merges **global rules** + **per-workflow fix_rules**:

| Source | FIX item (universal card) |
|--------|---------------------------|
| `GET /actionlog/denied` | "Workflow X blocked" → drawer |
| `GET /tools/approvals/pending` | "Tool approval pending" → approve action |
| `GET /plugins/tracetramp/admin/approvals` | Same renderer, `type: approval_queue` panel |
| Manifest `fix_rules` | Custom title/actions |

Same FIX card UI for all — only manifest changes copy and buttons.

---

## 7. Custom workflows (future scale)

### Author drops files in catalog

```text
data/workflows/catalog/
  my-etl.ccl
  my-etl.workflow.json       # workflow_id, package_id, version
  my-etl.operator.json       # operator_surface.v1 (optional)
```

Catalog sync (`workflow_catalog_sync`) already watches `*.ccl`. **Extend to ingest `*.operator.json`** and store beside workflow record.

### Author publishes to fleet

```text
POST /workflows/catalog/sync
GET /workflows/catalog        # status
```

UI RUN mode refetches list — new cards appear. **No deploy.**

### Community / marketplace workflow pack

A `.cpkg` or bundle contains:

- `workflow.ccl`
- `operator.surface.json`
- optional `fix_rules` / `panels` referencing institution APIs

Install = register workflow + surface in one transaction.

---

## 8. WATCH & FIX stay workflow-agnostic

### WATCH stream

Events normalized to **Event object**:

```json
{
  "ts", "kind", "workflow_id", "agent_pid", "decision", "summary", "deep_link"
}
```

Sources: actionlog, dry-run completions, plugin webhooks (future).  
**No per-workflow stream UI** — filter chips: All | Denied | Workflow▾.

### FIX queue

Items normalized to **Issue object**:

```json
{
  "issue_id", "severity", "title", "subtitle", "workflow_id", "actions": [...]
}
```

Built from global scanners + manifest `fix_rules`.  
Click issue → drawer with workflow surface focused on resolution panels.

---

## 9. API additions (small, high leverage)

| Endpoint | Purpose |
|----------|---------|
| `GET /workflows/:id/surface` | Merged manifest (sidecar + template + defaults + plugin contracts) |
| `PUT /workflows/:id/surface` | Admin: attach/update operator manifest |
| `GET /workflows/surfaces` | Optional batch for RUN list (avoid N+1) |
| `GET /operator/panel-types` | Schema registry for authoring tools |
| `POST /workflows/catalog/sync` | Already exists — extend to pick up operator JSON |

**UI calls only `/workflows`, `/workflows/:id/surface`, and action paths from manifest** — never workflow-specific routes in shell code.

---

## 10. What we stop building

| Stop | Replace with |
|------|--------------|
| New sidebar item per plugin | Institution chip + SETUP install |
| New dashboard page per workflow type | Manifest `panels[]` |
| CLS Catalog / Builder as RUN nav | Author in SETUP; operators stay in RUN |
| Hardcoded links TT → WC in UI | `console_links[]` in manifest |
| `if plugin == "tracetramp"` in shell | `institution_chips` panel type |
| Per-template empty states in Rust | `display.subtitle` in manifest |

Keep T1 consoles (TT/WC/DG dashboards) as **optional power tools** — maintain separately, but they are **not** the universal operator path.

---

## 11. Implementation phases

| Phase | Deliverable |
|-------|-------------|
| **W0** | `operator_surface.v1` schema doc + default surface synthesizer on server |
| **W1** | Extend `*.workflow.json` / `*.operator.json` catalog ingest |
| **W2** | `GET /workflows/:id/surface` merge endpoint |
| **W3** | Shell: universal RUN card renderer (signals + primary action) |
| **W4** | Shell: universal drawer panel renderer (kv, summary, chips, event_list) |
| **W5** | Bootstrap manifests for 3 reference templates (HITL, PII, incident) |
| **W6** | FIX queue reads `fix_rules` from surfaces |
| **W7** | Demote TT/WC/DG from nav → SETUP + drawer `console_links` |
| **W8** | Authoring: validate manifest in CI (`connectorctl workflow lint-surface`) |

**Order:** W0–W4 before any new plugin dashboard work.

---

## 12. Success test (universal + practical)

1. Drop a new `*.ccl` + `*.operator.json` in catalog → card appears in RUN **without UI commit**.
2. HITL template shows TT+WC chips **without** TraceTramp-specific card code.
3. Operator completes daily job using **only RUN + drawer** — never opens T1 console.
4. Workflow #100 uses same 10 panel types as workflow #1.
5. Adding institution #20 = plugin registers status + manifest references it — **no new shell mode**.

---

## 13. One diagram (mental model)

```mermaid
flowchart TB
  subgraph shell [Operator Shell - fixed]
    RUN[RUN cards]
    DRAWER[Context drawer]
    WATCH[WATCH stream]
    FIX[FIX queue]
  end

  subgraph manifests [Per workflow - data only]
    M1[hitl.operator.json]
    M2[pii.operator.json]
    M3[custom.operator.json]
  end

  subgraph institutions [Plugins - not nav items]
    TT[TraceTramp]
    WC[WitnessCtl]
    DG[DevGuard]
    NX[Future plugin N]
  end

  subgraph apis [Existing APIs]
    WF[/workflows/*]
    PL[/plugins/status]
    AL[/actionlog/*]
  end

  M1 --> RUN
  M2 --> RUN
  M3 --> RUN
  RUN --> DRAWER
  manifests --> DRAWER
  DRAWER --> apis
  RUN --> PL
  TT -.-> PL
  WC -.-> PL
  DG -.-> PL
  NX -.-> PL
  FIX --> manifests
  WATCH --> AL
```

---

*Universal means: **one renderer, infinite workflows**. Institutions are dependencies, not duplicate products. TT/WC/DG stay as setup targets and optional consoles — the operator's daily world is workflow cards driven by manifest.*
