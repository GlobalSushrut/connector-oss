# Universal Capabilities, Evidence & Forensics

**Problem:** WitnessCtl exports PDF and DI audit packs. TraceTramp exports compliance CSV/PDF and shows traces. DevGuard **performs actions** (connect IDE, scan) — it does not ship session dossiers. Custom workflows will mix these differently. **We cannot use one institution UI or hide real differences** — but we also cannot build a new page per plugin.

**Answer:** Separate **what the operator always sees** (universal evidence objects & verbs) from **what each backend registers** (capability registry). UI renders the **intersection** — only show export PDF when `witnessctl.evidence.export` is available for this context.

**Parent:** [UI_UNIVERSAL_WORKFLOW_SURFACE.md](UI_UNIVERSAL_WORKFLOW_SURFACE.md) · [UI_OPERATOR_COMPONENT_SYSTEM.md](UI_OPERATOR_COMPONENT_SYSTEM.md) · [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md)

---

## 1. Core model

```text
┌─────────────────────────────────────────────────────────────────┐
│ UNIVERSAL OPERATOR VERBS (fixed — same labels everywhere)        │
│  run · watch · fix · prove · export · audit · forensics · act    │
└────────────────────────────┬────────────────────────────────────┘
                             │ gated by
┌────────────────────────────▼────────────────────────────────────┐
│ CAPABILITY REGISTRY (per institution / plugin — data)             │
│  witnessctl.evidence.export · tracetramp.compliance.export        │
│  devguard.connect · devguard.scan · kernel.actionlog.export       │
└────────────────────────────┬────────────────────────────────────┘
                             │ composed by
┌────────────────────────────▼────────────────────────────────────┐
│ WORKFLOW MANIFEST (per workflow — which caps matter here)         │
│  institutions[{id, role, bind}] · evidence[] · actions[]        │
└─────────────────────────────────────────────────────────────────┘
```

**UI rule:** Same `OpExportMenu`, `OpArtifactCard`, `OpForensicsPanel`, `OpActionButton` — **visibility and targets** come from resolved capabilities, not `if plugin == "witnessctl"`.

---

## 2. Institution archetypes (semantic, not separate UIs)

Archetypes describe **how an institution behaves**, not which page to build.

| Archetype | Institutions | Operator mental model | Primary verbs |
|-----------|--------------|----------------------|---------------|
| **witness** | WitnessCtl | "Seal and prove what happened" | export, custody, prove |
| **enforcer** | TraceTramp | "Gate traffic and record decisions" | trace, block, approve, compliance export |
| **actor** | DevGuard | "Do something on the dev machine" | connect, scan, configure |
| **bridge** | slack, jira, MCP tools | "Call external system" | invoke, notify |
| **kernel** | Connector core | "Node truth" | audit log, memory, merkle proof |

A workflow manifest assigns **roles**:

```json
"institutions": [
  { "id": "witnessctl", "role": "witness" },
  { "id": "tracetramp", "role": "enforcer" },
  { "id": "devguard", "role": "actor" }
]
```

**HITL template:** witness + enforcer → drawer shows export + trace panels.  
**PII template:** actor + enforcer → drawer shows connect/scan + compliance export.  
**Custom WF #500:** manifest picks roles → UI composes automatically.

---

## 3. Capability registry (backend truth)

Each plugin (or kernel module) registers **capabilities** at enable time. Extends today's `POST /plugins/:id/workflow-contract`.

### 3.1 Capability record `institution_capability.v1`

```json
{
  "schema": "institution_capability.v1",
  "institution_id": "witnessctl",
  "archetype": "witness",
  "capabilities": [
    {
      "id": "evidence.export",
      "kind": "export",
      "label": "Export session evidence",
      "formats": ["pdf", "json", "csv", "markdown", "di_audit_middle"],
      "method": "GET",
      "path": "/plugins/witnessctl/sessions/{session_id}/export",
      "query": { "format": "{format}" },
      "requires": { "session_id": "string" },
      "produces": "artifact"
    },
    {
      "id": "compliance.report",
      "kind": "export",
      "label": "Framework report",
      "formats": ["pdf"],
      "method": "GET",
      "path": "/plugins/witnessctl/sessions/{session_id}/report",
      "query": { "framework": "{framework}", "format": "pdf" },
      "requires": { "session_id": "string", "framework": "string" }
    },
    {
      "id": "custody.status",
      "kind": "forensics",
      "label": "Custody chain",
      "method": "GET",
      "path": "/plugins/witnessctl/custody/{session_id}/status",
      "requires": { "session_id": "string" },
      "produces": "kv"
    }
  ]
}
```

### 3.2 Real backends today (ground truth)

| Institution | Capability id | API (today) | Formats / output |
|-------------|---------------|-------------|------------------|
| **witnessctl** | `evidence.export` | `GET /plugins/witnessctl/sessions/:id/export` | pdf, json, csv, md, di_audit_middle |
| **witnessctl** | `compliance.report` | WC report endpoint (proxied) | pdf per framework |
| **witnessctl** | `custody.status` | `GET /plugins/witnessctl/custody/:id/status` | custody kv |
| **witnessctl** | `session.list` | `GET /plugins/witnessctl/sessions` | session picker |
| **tracetramp** | `compliance.export` | TT `GET /v1/compliance/export` (via plugin) | csv, json, html, pdf |
| **tracetramp** | `trace.list` | `GET /plugins/tracetramp/admin/traces` | trace table |
| **tracetramp** | `policy.manage` | TT admin policies | block/approve actions |
| **tracetramp** | `approval.queue` | `GET .../admin/approvals` | HITL cards |
| **devguard** | `connect.tool` | `POST /devguard/connect` | perform — no PDF |
| **devguard** | `profile.local` | `GET/POST /plugins/devguard/local-profile` | config kv |
| **devguard** | `extension.status` | `GET .../extension/status` | status kv |
| **kernel** | `audit.export` | `GET /actionlog/export/jsonl`, `/otel`, `/cloudevents` | jsonl, otel |
| **kernel** | `proof.merkle` | `GET /proof/merkle-proof/:cid` | proof object |
| **kernel** | `compliance.pdf` | `GET /compliance/report/pdf`, `/brief/pdf` | pdf |
| **kernel** | `report.center` | `GET /reports/center` | receipt list |
| **kernel** | `cls.execution.export` | `GET /cls/packages/:id/execution/export` | run report |

**DevGuard has no `evidence.export`** — UI must not show PDF export on DG-only workflows.

### 3.3 Aggregated API (new)

```text
GET /operator/capabilities                    # all institutions + caps
GET /operator/capabilities?institution=witnessctl
GET /workflows/:id/capabilities             # manifest institutions ∩ registry ∩ runtime context
```

Server resolves **bind** variables (`session_id`, `trace_id`, `workflow_id`) from workflow run context.

---

## 4. Universal evidence objects (what UI shows)

Regardless of backend, produced outputs normalize to **`OpArtifact`**:

```json
{
  "artifact_id": "art_abc",
  "kind": "export|receipt|proof|trace_bundle|audit_pack",
  "title": "WitnessCtl session export",
  "format": "pdf",
  "mime": "application/pdf",
  "size_bytes": 124000,
  "sha256": "abc…",
  "produced_at_ms": 1730000000000,
  "source": {
    "institution_id": "witnessctl",
    "capability_id": "evidence.export",
    "session_id": "sess_xyz"
  },
  "download": {
    "method": "GET",
    "path": "/plugins/witnessctl/sessions/sess_xyz/export?format=pdf"
  },
  "verify": {
    "available": true,
    "path": "/proof/merkle-proof/{cid}"
  }
}
```

| Universal component | Renders |
|---------------------|---------|
| `OpArtifactCard` | any artifact — title, format badge, size, hash snippet, [Download] [Verify] |
| `OpArtifactList` | drawer section — list of artifacts for workflow/session |
| `OpExportMenu` | dropdown of **available** export capabilities (formats as sub-items) |
| `OpProofStrip` | verify state: Pending / Verified / Failed (H3) |
| `OpForensicsPanel` | custody + trace + CFNI lineage when caps exist |
| `OpAuditStream` | filtered actionlog — always available (kernel) |

**PDF is one `format` on an artifact**, not a separate WitnessCtl page pattern.

---

## 5. Universal verbs → UI components

| Verb | Component | Always available? | Gated by |
|------|-----------|-------------------|----------|
| **run** | `OpCard` primary CTA | per workflow | workflow lifecycle |
| **watch** | `OpEventRow` | yes | kernel actionlog |
| **fix** | `OpIssueCard` | when queue > 0 | fix rules |
| **export** | `OpExportMenu` | **no** | `kind: export` capability + context |
| **audit** | `OpAuditStream` + export jsonl/otel | yes (kernel) | role |
| **prove** | `OpProofStrip` + merkle lookup | when proof exists | kernel/proof |
| **forensics** | `OpForensicsPanel` | **no** | `kind: forensics` capability |
| **act** | `OpActionButton` | **no** | `kind: perform` capability (DevGuard) |

### 5.1 `OpExportMenu` (universal)

One menu everywhere — contents from resolved capabilities:

```text
Export ▾
  ├─ Session evidence (PDF)          ← witnessctl.evidence.export
  ├─ DI audit middle (JSON)          ← witnessctl.evidence.export format
  ├─ Compliance report (PDF)         ← tracetramp.compliance.export
  ├─ Audit log (JSONL)               ← kernel.audit.export
  ├─ Compliance brief (PDF)          ← kernel.compliance.pdf
  └─ (empty → menu hidden, not grey fake items)
```

**Rules:**
- Only show items whose `requires` context is satisfied (`session_id` present, etc.)
- Missing renderer (no chromium) → honest error toast, not fake download
- Long exports → `OpNotifyCard` persistent + progress (future)

### 5.2 `OpActionButton` (actor archetype — DevGuard)

For **perform** capabilities, not export:

```text
[ Connect Cursor ]   [ Scan workspace ]   [ Copy env snippet ]
```

```json
{
  "id": "connect.tool",
  "kind": "perform",
  "label": "Connect IDE",
  "method": "POST",
  "path": "/devguard/connect",
  "body_schema": { "tool": "string", "role": "string", "workspace": "string" },
  "ui": "form_compact"
}
```

Same `OpActionButton` for future actor plugins — form fields from `body_schema`.

### 5.3 `OpForensicsPanel` (when backends provide lineage)

Composable sections — each section optional:

| Section | Capability | Data |
|---------|------------|------|
| Custody chain | `witnessctl.custody.status` | HMAC chain, seal state |
| Trace timeline | `tracetramp.trace.list` | trace_id correlated events |
| Decision log | kernel | actionlog denied + TT decisions |
| CFNI stamp | kernel (Grade C) | forensic flow identity |
| Merkle proof | `kernel.proof.merkle` | cid → proof |

**If workflow has no forensics caps** → section omitted, not "empty = safe".

---

## 6. Workflow manifest extensions

Add to `operator_surface.v1`:

```json
{
  "institutions": [
    {
      "id": "witnessctl",
      "role": "witness",
      "bind": { "session_id": "$run.session_id" }
    },
    {
      "id": "tracetramp",
      "role": "enforcer",
      "bind": { "trace_id": "$run.trace_id", "tenant_id": "$run.tenant_id" }
    },
    {
      "id": "devguard",
      "role": "actor",
      "bind": { "workspace": "$agent.workspace" }
    }
  ],
  "operator_verbs": {
    "primary": "dry_run",
    "secondary": ["export", "audit"],
    "hidden": ["forensics"]
  },
  "evidence": [
    {
      "capability": "witnessctl.evidence.export",
      "label": "Session evidence",
      "default_format": "pdf",
      "show_in": ["drawer", "palette", "fix_complete"]
    },
    {
      "capability": "tracetramp.compliance.export",
      "label": "Compliance export",
      "default_format": "csv",
      "show_in": ["drawer"]
    },
    {
      "capability": "kernel.audit.export",
      "label": "Audit log",
      "default_format": "jsonl",
      "show_in": ["drawer", "palette"]
    }
  ],
  "perform": [
    {
      "capability": "devguard.connect.tool",
      "label": "Connect IDE",
      "show_in": ["drawer", "setup"]
    }
  ],
  "forensics": [
    {
      "capability": "witnessctl.custody.status",
      "panel": "custody_chain"
    },
    {
      "capability": "tracetramp.trace.list",
      "panel": "trace_timeline",
      "filter": { "trace_id": "$run.trace_id" }
    }
  ],
  "artifacts": {
    "list_path": "/reports/center",
    "filter": { "workflow_id": "$self" }
  }
}
```

| Field | Purpose |
|-------|---------|
| `institutions[].role` | archetype → default drawer layout template |
| `institutions[].bind` | how to fill `{session_id}` etc. from run context |
| `evidence[]` | which export caps to surface for **this** workflow |
| `perform[]` | actor buttons (DevGuard) |
| `forensics[]` | which forensic panels appear |
| `operator_verbs.hidden` | suppress forensics on simple WFs |

**Custom workflow** only lists what it uses — UI stays minimal.

---

## 7. Drawer layout by archetype mix (templates, not code forks)

Server picks a **drawer template** from institution role set:

| Roles present | Default drawer sections (in order) |
|---------------|-----------------------------------|
| any | Summary · Actions · Audit stream |
| + enforcer | Trace / decisions · Compliance export |
| + witness | Artifacts · Export menu · Custody forensics |
| + actor | Perform actions · Local profile status |
| + bridge | Last invocations (from actionlog) |

```text
HITL (witness + enforcer):
  Summary → Actions → Artifacts → Export ▾ → Custody → Trace → Audit

PII (actor + enforcer):
  Summary → Actions → [Connect IDE] [Scan] → Compliance export → Audit

Simple CLS (kernel only):
  Summary → Actions → Dry-run history → Audit export
```

Template is **data** (`drawer_template: "witness_enforcer"`) — overridable per manifest `panels[]`.

---

## 8. Example: three institutions, one universal UI

### WitnessCtl workflow moment (export)

```text
Operator clicks Export ▾ → Session evidence (PDF)
  → GET /plugins/witnessctl/sessions/{id}/export?format=pdf
  → OpArtifactCard appears in drawer + OpToast success
  → OpProofStrip: Pending until verify
```

### TraceTramp moment (no session dossier)

```text
Operator clicks Export ▾ → Compliance CSV
  → TT compliance export API
  → OpArtifactCard (format=csv)
No "Session evidence PDF" — capability not registered
```

### DevGuard moment (act, not export)

```text
Drawer shows [ Connect Cursor ] [ View extension status ]
No Export menu (no export capability)
Audit stream still available (kernel — workflow touched node)
```

### Custom workflow (slack + jira bridge)

```text
manifest institutions: [{id:"slack",role:"bridge"},{id:"jira",role:"bridge"}]
Drawer: Summary → Actions → Audit (invoke events only)
Export: kernel audit jsonl only
```

---

## 9. FIX queue & notifications (evidence-aware)

Universal FIX cards can include export CTAs when capability + context ready:

```json
{
  "fix_rule_id": "export_ready",
  "when": { "artifact": { "kind": "export", "status": "ready" } },
  "title": "Evidence pack ready",
  "actions": [
    { "capability": "witnessctl.evidence.export", "format": "pdf", "label": "Download PDF" }
  ]
}
```

Same `OpIssueCard` — action executes capability, not custom WC code.

---

## 10. T1 institution consoles (still allowed)

Heavy plugin UIs (WitnessCtl PDF viewer, TT policy editor) remain **T1** — linked from:

- `console_links[]` in manifest
- `OpExportMenu` → "Open advanced export…" when `tier: 1` on capability

**T0 universal path** covers 90%: export download + artifact card + audit stream.  
**T1** for multi-framework report picker, TT quarantine admin, etc.

---

## 11. Implementation phases

| ID | Task | Verify |
|----|------|--------|
| **K0** | `institution_capability.v1` schema | doc + types |
| **K1** | Plugin registration extends workflow-contract with capabilities | WC, TT, DG register truthfully |
| **K2** | `GET /operator/capabilities` + `GET /workflows/:id/capabilities` | resolve bind context |
| **K3** | `OpArtifact` + `OpArtifactCard` + `OpArtifactList` | any export → same card |
| **K4** | `OpExportMenu` — capability-driven, context-gated | DG workflow has no PDF item |
| **K5** | `OpActionButton` + compact forms — perform caps | DevGuard connect |
| **K6** | `OpForensicsPanel` sections — custody, trace, proof | HITL shows WC+TT sections |
| **K7** | Manifest `evidence[]`, `perform[]`, `forensics[]` on surface merge | custom WF composes |
| **K8** | Drawer templates by archetype mix | HITL vs PII layout differs, same components |
| **K9** | Palette: `export pdf for session`, `audit jsonl` | executes capability |
| **K10** | Honest missing-capability UX — hide, don't disable grey | H1 for exports |

**Depends on:** W2 (`GET /workflows/:id/surface`), C4 (drawer), C6 (palette).

---

## 12. Laws (capability universality)

| # | Law |
|---|-----|
| **K1** | Export, audit, forensics, and act are **verbs** — same UI components |
| **K2** | Backends register **capabilities** — UI never hardcodes institution menus |
| **K3** | Workflow manifest selects **which caps matter** for this automation |
| **K4** | Missing capability → **hidden**, not fake button |
| **K5** | All exports become **`OpArtifact`** — PDF is a format, not a page type |
| **K6** | Actor (DevGuard) uses **`perform`** kind — not forced into export UX |
| **K7** | Kernel audit/proof always available — workflow doesn't own audit |
| **K8** | T1 consoles optional — T0 must complete export/download without them |

---

## 13. Success test

1. HITL workflow drawer: export PDF + DI audit + custody + trace — **one** `OpExportMenu`, no WC-specific layout code in shell.
2. DevGuard-only workflow: **no** export menu; connect/scan buttons present.
3. Custom catalog WF with only `kernel` institutions: audit jsonl export only.
4. Add fictional plugin with `evidence.export` + `perform` caps → UI works without shell PR.
5. Operator never sees greyed "PDF export" on workflows that cannot produce PDF.

---

*Capabilities are the contract between heterogeneous backends and a universal operator UI. Workflows declare intent; institutions declare ability; the shell renders intersection.*
