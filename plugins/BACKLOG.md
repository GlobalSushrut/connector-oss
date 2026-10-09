# TraceTramp + WitnessCtl - Product Backlog & Competitive Roadmap

> Deep-dive code audit + web research + competitive analysis, Apr 27 2026.  
> Format: checkbox checklist. Mark `[x]` when done.  
> P0 = existential | P1 = demo-blocker | P2 = pre-revenue | P3 = polish/differentiator  
> Every item is grounded in actual code locations confirmed by source reading.

---

## Part 0 - Product Moat: Two Separate $1000 Products
 show traces, calls, costs, and timelines, but those screens are not the product. The product is control an
### Non-Negotiable Positioning

TraceTramp and WitnessCtl are **not observability or debugging tools**. They may show traces, calls, costs, and timelines, but those screens are not the product. The product is control and proof.

| Product | Category we own | Buyer pays because | Not because |
|---|---|---|---|
| **TraceTramp** | Runtime enforcement and agent execution governance | It blocks, holds, routes, approves, and explains high-risk LLM/tool execution before damage happens | It tunes prompts |
| **WitnessCtl** | API witness, custody, and compliance evidence | It produces independently verifiable proof packets, custody records, and auditor-ready evidence | It logs API requests |

### The $1000 Experience Bar

Someone should feel comfortable paying today when the product does these things on first contact:

- [ ] **One command, no shame** - first run creates sane local secrets, starts the right services, prints the exact URL/key/snippets, and never dumps the user into env-var archaeology.
- [ ] **Trust visible in 10 seconds** - every screen says what is protected, what is blocked, what is pending, what is sealed, and what still needs setup.
- [x] **Action in the same place as evidence** - approve, reject, quarantine, seal, export, verify, and open the generated artifact without leaving the product.
- [ ] **No fake zeros or blank cells** - no `"-"` provider cells, `$0.0000` budget lies, static setup wizard text, or API-hint panels pretending to be workflows.
- [ ] **Auditor/operator confidence** - every important action leaves a human-readable reason plus machine-verifiable evidence.

### TraceTramp Standalone Product

TraceTramp is the **inline runtime control plane** for AI agents and LLM traffic.

It competes in budget conversations against gateways and tracing vendors because buyers already know those categories. But TraceTramp's product category is different: **it is the policy enforcement layer in the hot path**.

| Buyer question | TraceTramp answer |
|---|---|
| Can this agent call this model/tool right now? | Allow, block, redact, hold, or route before the call leaves |
| Who approved this risky action? | HITL queue with reviewer, reason, timestamp, and decision trail |
| Why was this blocked? | Decision tree, policy verdicts, budget verdicts, and clean human reason |
| Can a developer bypass the SDK? | Cage proxy mode makes the governed route the path |
| Can I run it in my own environment? | Self-hosted data/control plane with Connector OS integration |

TraceTramp surfaces traces only to explain enforcement. A trace without a decision is not enough for this product.

### WitnessCtl Standalone Product

WitnessCtl is the **evidence and custody plane** for API and AI interactions.

It competes against governance evidence tools, GRC exports, and cryptographic audit products. It is not an LLM troubleshooting dashboard. A capture is valuable only when it can become defensible proof.

| Buyer question | WitnessCtl answer |
|---|---|
| Can we prove what happened? | HMAC receipt chain, verification endpoint, CLI verify, custody checkpoints |
| Can an auditor consume it? | PDF/CSV/JSON exports with framework control mapping |
| Can we preserve evidence? | Seal, bundle, custody queue, quorum status, WORM/legal-hold roadmap |
| Can we handle sensitive sessions? | Lock, quarantine, redact, HITL review, PII preview |
| Can the proof survive outside the app? | Signed `.witnessctl` bundle and independent verification roadmap |

WitnessCtl surfaces request history only to prove custody, compliance, and reviewer decisions.

### Integration Without Product Confusion

```
Agent/app
  -> TraceTramp: enforce live execution decision
  -> WitnessCtl: preserve evidence and custody proof
```

- TraceTramp owns synchronous enforcement: route, policy, budget, PII action, HITL hold, quarantine.
- WitnessCtl owns asynchronous proof: receipts, chain verification, compliance mapping, signed bundle, custody replication.
- Connector OS owns shared identity, tenancy, policy primitives, budgets, receipts, and plugin lifecycle.

### Competitive Reality, Apr 2026

Modern gateways now claim routing, fallbacks, virtual keys, budgets, guardrails, PII redaction, RBAC, and compliance language. Modern tracing platforms have strong timelines, evals, prompt workflows, and cost analytics. We should not pretend they are empty.

TraceTramp wins only if it becomes a **fail-closed enforcement product**:

- [ ] **TT-MOAT-01** - Cage route is the default path, not an optional demo path.
- [x] **TT-MOAT-02** - HITL approvals are persisted, actionable, and visible in the TUI.
- [ ] **TT-MOAT-03** - Decision trees are real stored artifacts, not in-memory logs.
- [ ] **TT-MOAT-04** - Management APIs are authenticated and tenant-safe.
- [ ] **TT-MOAT-05** - Every block has a clean reason, policy source, and replay reference.

WitnessCtl wins only if it becomes a **proof product**:

- [x] **WC-MOAT-01** - Chain verification badge is visible everywhere evidence is shown.
- [ ] **WC-MOAT-02** - Seal writes an actual evidence bundle, not only DB metadata.
- [ ] **WC-MOAT-03** - Compliance exports map controls to captured evidence.
- [x] **WC-MOAT-04** - Custody/quorum status is visible in the TUI and export manifest.
- [ ] **WC-MOAT-05** - Evidence can be verified without trusting the live server UI.

---

## Part 1 - TraceTramp Target Outcomes

TraceTramp's target user is an AI platform/security operator who needs to govern live agent execution without rewriting every agent framework. The premium moment is: **drop one cage URL into the app and immediately see enforceable decisions, holds, budgets, and quarantines.**

| # | Outcome | Status | Where blocked |
|---|---|---|---|
| 1 | `tracetramp` starts into a governed local lab: Connector detection, DB/migrations, default tenant/provider/key, cage URL, TUI | [ ] | `tracetramp/src/main.rs` defaults to `run_server()`, missing full first-run orchestration |
| 2 | Cage URL is the normal integration path: `OPENAI_BASE_URL=http://host:9741/cage/<sha>` | [ ] | No `ANY /cage/:sha_address/*path` route in `tracetramp/src/main.rs` / `control.rs` |
| 3 | Every request has an enforceable decision: allow, block, redact, hold, route, or quarantine | [ ] | Core hot path exists in `control.rs`; HITL/hold/quarantine are incomplete |
| 4 | Operator sees **why enforcement happened**, not raw Rust debug strings | [x] | `tracetramp/src/tui.rs` normalizes decision strings and shows cleaned block reason text. |
| 5 | Decision tree is a first-class artifact for every high-risk call | [ ] | `decision_trees` SQL exists; `gateway.rs::get_decision_tree` is a stub; `view.rs` only logs trees |
| 6 | Pending approvals are real rows with reviewer actions and expiry | [x] | `tracetramp/src/admin.rs` now serves real `approval_queue` rows and resolve endpoints. |
| 7 | TUI can approve, reject, quarantine, and inspect tool args in place | [ ] | Approve/reject/quarantine are now wired in `tui.rs`; tool-arg inspection still needs dedicated rendering. |
| 8 | Budget enforcement is hard and visible: per tenant/key/model, rolling burn, projected monthly spend | [ ] | `cost_records`, `hourly_rollups`, `daily_rollups` are unused; control-path metadata lacks full cost |
| 9 | Active calls shows true in-flight concurrency, not an inferred recent-row count | [x] | `AppState.active_calls` with entry/exit guard is now wired in `tracetramp/src/control.rs` + surfaced in TUI stats. |
| 10 | Provider/model/token/cost cells are never blank for completed calls | [x] | `InteractionRecord` + admin responses now include `provider/model/decision_reason`, and TUI renders them. |
| 11 | Management plane is secure by default | [ ] | `auth.rs` helpers exist but `admin::create_router` does not apply admin/tenant auth |
| 12 | Provider setup happens in the product UI, not by curl spelunking | [ ] | Provider CRUD exists in `admin.rs`; no TUI form |
| 13 | Policy edits happen in the product UI with validation and dry-run preview | [ ] | Policy CRUD exists in `admin.rs`; no TUI editor |
| 14 | Quarantine freezes an agent/tenant immediately with a visible reason banner | [ ] | No quarantine route/check in `admin.rs` / `control.rs` |
| 15 | Financial/tool HITL workflow works end to end: refund/transfer/delete is held, reviewed, released/rejected | [ ] | Tool validation exists in `control.rs`; no persistent HITL queue |
| 16 | Decision replay is controlled, audited, and explicit | [ ] | No replay table/API/CLI yet |
| 17 | Export gives an operator packet: decision tree, policy verdicts, budget verdicts, request metadata, reviewer actions | [ ] | Current TUI export is view-oriented, not enforcement-packet oriented |
| 18 | `tracetramp doctor` proves production readiness: ports, DB, Redis, Connector, auth, cage route, migrations, pricing tables | [ ] | `run_doctor()` exists but needs deeper checks |
| 19 | TUI has a premium command surface: `?` help, command palette, mouse select, split inspector | [ ] | Mostly footer hints and fixed panels |
| 20 | No dependency failure looks like product failure | [ ] | Connector calls have some graceful degradation; startup and identity paths still need hardening |

---

## Part 2 - WitnessCtl Target Outcomes

WitnessCtl's target user is a compliance, platform, or security team that needs proof they can hand to an auditor, regulator, customer, or legal team. The premium moment is: **open a session, proxy calls, seal it, verify it, and export a signed evidence bundle that stands on its own.**

| # | Outcome | Status | Where blocked |
|---|---|---|---|
| 1 | `witnessctl` starts into a usable witness session with proxy URL, TUI, secret, framework defaults, and export path | [ ] | `run_setup()` can write secret; `Config::from_env()` still hard-fails on insecure default |
| 2 | Published proxy URL always matches actual host/port/base URL | [ ] | `session.rs::open_session` hardcodes `http://localhost:7443/witness/{id}` |
| 3 | Proxy capture path works out of the box | [x] | Routes include `/witness/:session_id/*path` in `routes.rs` |
| 4 | Chain verification is visible as a trust strip: `[CHAIN OK]`, `[BROKEN]`, pending custody count | [x] | `witnessctl/src/tui.rs` now fetches verify status and renders chain trust strip in both Live and History selection context. |
| 5 | Seal creates a real local/exportable artifact, not only a DB status | [ ] | `session.rs` stores `bundle_path`; no evidence file is materialized there |
| 6 | Compliance export maps framework controls to concrete captures and receipts | [ ] | `compliance.rs` has framework logic; export lacks control-to-evidence mapping |
| 7 | `internal/compliance_map.yaml` is the canonical source or is generated from Rust | [ ] | YAML spec and `compliance.rs` can drift |
| 8 | Report download saves to user-visible path and opens it | [x] | `witnessctl/src/tui.rs` now writes report/batch artifacts to `~/Downloads`, opens via `xdg-open`, and tracks path/hash/time in UI. |
| 9 | TUI compliance wizard is guided: framework, time range, session set, format, destination | [ ] | Wizard/report panels exist but are mostly static |
| 10 | HITL queue displays actual pending rows and actions | [x] | `tui.rs` renders queue rows and supports approve/reject/escalate actions against HITL APIs. |
| 11 | HITL enterprise gating is clear instead of looking broken on free tier | [x] | HITL panel surfaces API error context/tier-required failures as explicit status/toast messaging. |
| 12 | Quarantine freezes a session with reason, actor, timestamp, and export evidence | [x] | Added `/api/v1/sessions/:id/quarantine|unquarantine`, policy quarantine event metadata, reviewer action evidence, and TUI `z/Z` actions. |
| 13 | Lock/unlock sessions from TUI and API | [x] | Added `/api/v1/sessions/:id/lock|unlock`, TUI `l/u` actions, and proxy enforcement for locked sessions. |
| 14 | Custody/quorum status is visible in TUI and export manifest | [x] | `tui.rs` shows custody strip with quorum achieved/target; batch manifest includes custody block |
| 15 | Per-capture and per-session cost is real | [x] | `capture.rs` now computes/stores `witness_captures.cost_usd` and increments session `cost_usd` totals on ingest. |
| 16 | PII preview shows original vs redacted and exact field/type | [x] | `witness_pii_hits` now stores original/redacted previews; TUI inspector renders structured rows with field/type/action and before/after values. |
| 17 | Session switcher is built in | [x] | TUI now has in-app session switcher modal (`g`) with “all sessions” and per-session selection that updates active capture filter. |
| 18 | Upstream target can be changed through the product | [x] | Added `/api/v1/sessions/:id/upstream` plus TUI upstream editor modal (`e`) with inline edit/apply and reviewer action evidence. |
| 19 | Webhook/SIEM/GRC export exists for PII, quarantine, seal, HITL, broken chain | [x] | Added `webhook.rs` queue worker + retry/dead-letter pipeline and event enqueue on seal/quarantine/lock/upstream/HITL actions. |
| 20 | Evidence can be verified without trusting the UI | [ ] | CLI/API verify exist; signed standalone bundle still missing |

---

## Part 3 - Product Boundaries and Handoff

### TraceTramp Owns

- Runtime route governance.
- Provider/model routing.
- Policy and budget enforcement before execution.
- PII block/redact decisions in the hot path.
- Tool validation and high-risk HITL hold.
- Quarantine of live agents/tenants.
- Decision trees and operator action trails.

### WitnessCtl Owns

- Capture sessions.
- HMAC receipt chains.
- Chain verification and tamper detection.
- Compliance control mapping.
- Session seal, lock, custody, and signed evidence bundle.
- PII evidence preview and redaction review.
- Auditor, SIEM, GRC, and legal export.

### Integration Contract

```
AI agent
  -> TraceTramp cage URL
  -> allow/block/redact/hold decision
  -> async event/evidence handoff
  -> WitnessCtl session/capture/receipt/export
```

- [x] **INT-01** - TraceTramp forwards enforcement events to WitnessCtl without blocking the user request.
  - _Files: `tracetramp/src/connector.rs::witness_tracetramp_handoff`; `tracetramp/src/control.rs` / `tracetramp/src/view.rs` (spawned handoffs)._
- [x] **INT-02** - WitnessCtl accepts TraceTramp enforcement context as evidence metadata.
  - _Files: `witnessctl/src/routes.rs` (`POST /api/v1/integrations/tracetramp/handoff`), `witnessctl/migrations/20260427000012_tracetramp_integration.sql`._
- [x] **INT-03** - Shared IDs link TraceTramp decision packet to WitnessCtl evidence packet.
  - _Files: `witnessctl/src/capture.rs` (`x-trace-id` / `x-request-id` → `witness_captures`, receipt payload); correlation `GET /api/v1/integrations/tracetramp/by-trace/:trace_id`._
- [x] **INT-04** - Product UI keeps ownership separate: TraceTramp says "enforced"; WitnessCtl says "sealed/verified".
  - _Files: `tracetramp/src/tui.rs`, `witnessctl/src/tui.rs` (title strip, help overlay, controls, evidence panel copy)._

---

## Part 4 - Zero-Friction Startup Architecture

> Research findings from: Supabase CLI, Stripe CLI, fly.io, k9s, lazydocker, Warp, Temporal, Portkey, LiteLLM, Helicone. Copy the startup polish, not the product category.

### How the Best Tools Do It

| Tool | Startup experience | What we copy |
|------|-------------------|--------------|
| **Supabase** | `supabase start` -> auto-creates DB, auto-generates JWT/anon key/service_role key, prints all credentials in a box | Auto-generate all secrets, print credential box on first start |
| **Stripe CLI** | `stripe login` -> opens browser, auto-configures API key, zero manual env vars | `CONNECTOR_KEY` as a local shared key when Connector OS is present |
| **fly.io** | `fly launch` -> detects project type, writes `fly.toml`, deploys | `tracetramp init` detects existing providers, writes config, starts |
| **Langfuse** | `docker compose up` -> one command, all services, web UI at localhost:3000 | Copy the zero-friction setup, not the product positioning |
| **k9s** | `k9s` -> auto-detects kubeconfig, zero config, TUI immediately shows live data | TUI auto-launches, auto-detects Connector, shows live data immediately |
| **lazydocker** | `lazydocker` -> auto-detects Docker, zero config, TUI shows containers | Zero-config TUI that just works with whatever is running |
| **Microsoft AGT** | `pip install agent-governance-toolkit[full]` + `agt doctor` | `tracetramp doctor` + `witnessctl doctor` as pre-flight health checks |
| **Temporal** | HITL workflow: `interrupt` -> pending -> `resolve` -> continue | HITL financial workflow built into proxy, not just SDK |
| **Warp** | Agent mode: natural language -> action, zero friction | TUI actions: `c` compliance, `q` quarantine, `a` approve; one key per action |

### TraceTramp Target First Run

```bash
$ tracetramp

  ==============================================================
  TraceTramp v0.1 - Runtime Enforcement for AI Agents

  [ok] Connector OS detected at localhost:9091
  [ok] Database connected (tracetramp)
  [ok] Redis connected
  [ok] Secrets auto-generated (first run - saved to .env)
  [ok] Default tenant created: openfang-lab
  [ok] Default provider registered: aimock

  API Key:     cpk_lab_a3f8b2c1d4e5...
  Cage URL:    http://localhost:9741/cage/a3f8b2c1
  Management:  http://localhost:9742
  TUI:         launched in separate window

  Python: client = TraceTrampClient("http://localhost:9741/cage/a3f8b2c1")
  curl:   export OPENAI_BASE_URL=http://localhost:9741
          export OPENAI_API_KEY=cpk_lab_a3f8b2c1d4e5...
  ==============================================================
```

### WitnessCtl Target First Run

```bash
$ witnessctl

  ==============================================================
  WitnessCtl v0.1 - Verifiable API Evidence

  Session:     wit_20260427_lab
  Proxy URL:   http://localhost:7443/witness/wit_20260427_lab
  Chain:       CHAIN OK (seq=0)
  Custody:     local quorum pending
  Export dir:  ~/Downloads/witnessctl

  Next:
    1. Point your API client at the proxy URL.
    2. Press c for compliance export.
    3. Press s to seal and produce a .witnessctl bundle.
  ==============================================================
```

### Startup Flow (what needs to be coded)

```
tracetramp or witnessctl invoked

1. Load .env - if missing, create with sensible defaults

2. Auto-generate secrets if not set:
   - TRACETRAMP_JWT_SECRET  -> openssl-rand-hex(32)
   - WITNESSCTL_HMAC_SECRET -> wctl_<uuid>_<uuid>
   - CONNECTOR_KEY          -> conn_lab_<rand-hex(20)>
   Write to .env. Print warning. Never hard-fail in dev.

3. Single key: CONNECTOR_KEY works for both tools when Connector OS is present
   (aliases: TRACETRAMP_CONNECTOR_API_KEY, CONNECTOR_API_KEY)

4. Detect Connector OS at localhost:9091
   - If reachable -> continue
   - If not -> try to spawn from CONNECTOR_BIN or well-known path
   - If cannot spawn -> warn + continue in degraded mode
   - NEVER hard-fail because Connector is down

5. Wait for Connector health (up to 30s) if it was just spawned

6. Ensure DB exists (auto-create if not)
   Ensure migrations applied (auto-repair checksum if env flag set)

7. Create default tenant + provider + API key if none exist
   (idempotent - skip if already created)

8. Start data plane + management plane listeners

9. Auto-launch TUI in detached terminal (unless TRACETRAMP_NO_TUI=1)
   - No interactive prompts (no prompt_requested_agents)
   - Default to 3 agents / dev-free tier

10. Print product-specific credential/proof box with copy-paste snippets
```

---

## TraceTramp Backlog - Runtime Enforcement Product

### P0 - Existential

- [x] **TT-P0-01** - Cage proxy path is the default paid experience: `ANY /cage/:sha_address/*path` resolves tenant/provider and runs full enforcement.
  - _Files: `tracetramp/src/main.rs`, `tracetramp/src/control.rs`, `tracetramp/src/admin.rs`._
- [x] **TT-P0-02** - Persist real decision trees for high-risk calls and return them from `GET /decision/:trace_id`.
  - _Files: `tracetramp/migrations/20240101000004_decision_trees.sql`, `tracetramp/src/gateway.rs::get_decision_tree`, `tracetramp/src/view.rs`._
- [x] **TT-P0-03** - Replace approval stubs with durable approval rows and TUI actions.
  - _Files: `tracetramp/src/admin.rs::list_approvals`, `tracetramp/src/control.rs`, `tracetramp/src/tui.rs`._
- [x] **TT-P0-04** - Secure management plane by default.
  - _Files: `tracetramp/src/auth.rs`, `tracetramp/src/admin.rs::create_router`._
- [x] **TT-P0-05** - No blank/fake enforcement data in the TUI: provider, model, cost, tokens, latency, policy source, decision reason.
  - _Files: `tracetramp/src/control.rs`, `tracetramp/src/connector.rs::InteractionRecord`, `tracetramp/src/tui.rs`._
- [x] **TT-P0-06** - Financial/tool HITL workflow: `refund`, `transfer`, `delete`, prod write, and publish actions hold by default.
  - _Files: `tracetramp/src/control.rs`, `tracetramp/src/admin.rs`, `tracetramp/src/tui.rs`._

---

### P1 - Demo Blockers

- [x] **TT-P1-01** - `tracetramp` with no args runs the premium local path: setup, serve, TUI, credential box.
  - _File: `tracetramp/src/main.rs`._
- [x] **TT-P1-02** - Auto-generate `TRACETRAMP_JWT_SECRET` in dev/local and save it safely.
  - _File: `tracetramp/src/main.rs`, `Config::from_env` path._
- [x] **TT-P1-03** - Remove blocking interactive agent prompts from detached startup.
  - _File: `tracetramp/src/main.rs::prompt_requested_agents`._
- [x] **TT-P1-04** - Auto-launch TUI from server/default path with `--no-tui` escape hatch.
  - _File: `tracetramp/src/main.rs`._
- [x] **TT-P1-05** - Clean decision reason parsing: `Block { reason: "x" }` becomes `BLOCKED: x`.
  - _File: `tracetramp/src/tui.rs`._
- [x] **TT-P1-06** - Control path records full metadata at `ResponseReleased` and `CostRecorded`.
  - _File: `tracetramp/src/control.rs::record_event` call sites._
- [x] **TT-P1-07** - Active call counter increments/decrements on real request entry/exit.
  - _Files: `tracetramp/src/main.rs::AppState`, `tracetramp/src/control.rs`._
- [x] **TT-P1-08** - `tracetramp doctor` includes auth, cage route, migrations, Redis, DB, Connector, and port checks.
  - _File: `tracetramp/src/main.rs::run_doctor`._
- [x] **TT-P1-09** - Witness ingest URL no longer posts to Connector OS by default.
  - _File: `tracetramp/src/connector.rs::ingest_witness_event`; source shows port replacement toward `:7443/api/v1/ingest`._

### P2 - Pre-Revenue

- [x] **TT-P2-01** - Provider config form in TUI with masked key entry and validation.
  - _Files: `tracetramp/src/admin.rs`, `tracetramp/src/tui.rs`._
- [x] **TT-P2-02** - Policy editor in TUI with dry-run against a sample request.
  - _Files: `tracetramp/src/admin.rs`, `tracetramp/src/tui.rs`._
- [x] **TT-P2-03** - Quarantine agent/tenant API and hot-path check.
  - _Files: `tracetramp/src/admin.rs`, `tracetramp/src/control.rs`._
- [x] **TT-P2-04** - Populate `cost_records` and rollups, or remove dead schema.
  - _Files: `tracetramp/migrations/20240101000001_init.sql`, `tracetramp/migrations/20240101000005_rollup_tables.sql`._
- [x] **TT-P2-05** - Python drop-in client for cage URL.
  - _New: `plugins/tracetramp-client-py/`._
- [x] **TT-P2-06** - Node drop-in client for cage URL.
  - _New: `plugins/tracetramp-client-node/`._
- [x] **TT-P2-07** - Enforcement packet export: decision tree, policy verdicts, budget verdicts, reviewer actions.
  - _Files: `tracetramp/src/tui.rs`, `tracetramp/src/gateway.rs`._

### P3 - Premium Differentiators

- [x] **TT-P3-01** - Command palette: approve, reject, quarantine, provider, policy, replay.
  - _File: `tracetramp/src/tui.rs`._
- [x] **TT-P3-02** - Decision diff: compare two model/provider decisions and policy paths.
  - _Files: `tracetramp/src/gateway.rs`, `tracetramp/src/tui.rs`._
- [x] **TT-P3-03** - Cost forecast and anomaly detection from real rollups.
  - _Files: `tracetramp/src/admin.rs`, rollup tables._
- [x] **TT-P3-04** - OWASP Agentic Top 10 policy coverage panel.
  - _File: `tracetramp/src/tui.rs`._
- [x] **TT-P3-05** - Terminal polish: split inspector, mouse selection, help overlay, gauges, sparklines.
  - _File: `tracetramp/src/tui.rs`._

---

## WitnessCtl Backlog - Evidence and Custody Product

### P0 - Existential

- [x] **WC-P0-01** - Chain verification trust strip in TUI using existing verify API.
  - _Files: `witnessctl/src/routes.rs::verify_session`, `witnessctl/src/main.rs::run_cli_verify`, `witnessctl/src/tui.rs`._
- [x] **WC-P0-02** - Seal writes a real `.witnessctl` evidence bundle with captures, receipts, verification result, report manifest, and signature metadata.
  - _Files: `witnessctl/src/session.rs::materialize_witness_bundle`, `witnessctl/src/receipt.rs::verify_chain`._
- [x] **WC-P0-03** - Compliance report maps controls to concrete evidence rows.
  - _Files: `witnessctl/src/export.rs::build_markdown_report` (framework verdicts + capture table samples), `witnessctl/src/compliance.rs`._
- [x] **WC-P0-04** - Published proxy URL uses configured host/port/base URL.
  - _File: `witnessctl/src/session.rs::open_session`._
- [x] **WC-P0-05** - Session quarantine and lock/unlock are real API/TUI actions.
  - _Files: `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs`, `witnessctl/src/session.rs`._

### P1 - Demo Blockers

- [x] **WC-P1-01** - Auto-generate `WITNESSCTL_HMAC_SECRET` for local/dev start and save it.
  - _Files: `witnessctl/src/main.rs::run_setup`, `witnessctl/src/config.rs::from_env`._
- [x] **WC-P1-02** - Compliance/report wizard in TUI: framework, format, batch toggle; export to default downloads dir; `xdg-open` after write. Scope is the selected session (no separate time-range picker).
  - _Files: `witnessctl/src/tui.rs` (report overlay + `export_report_action` / `export_report_batch_action`), `witnessctl/src/routes.rs::report_session`._
- [x] **WC-P1-03** - Report export in TUI writes to `~/Downloads` or configured export dir.
  - _Files: `witnessctl/src/tui.rs::export_report_action`, `witnessctl/src/main.rs::run_cli_export`._
- [x] **WC-P1-04** - HITL panel fetches and renders actual queue items with approve/reject/escalate actions.
  - _Files: `witnessctl/src/routes.rs` (`list_hitl_queue`, `resolve_hitl_item`), `witnessctl/src/tui.rs`._
- [x] **WC-P1-05** - Tier-gated APIs show clear product messaging in TUI.
  - _Files: `witnessctl/src/config.rs::is_enterprise_tier`, `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs` (e.g. custody-degraded export confirm, enterprise errors)._
- [x] **WC-P1-06** - PII inspector shows original, redacted, type, field, and reviewer action.
  - _File: `witnessctl/src/tui.rs` (inspector reads `witness_pii_hits` previews + `action`)._
- [x] **WC-P1-07** - `witnessctl doctor` command exists.
  - _File: `witnessctl/src/main.rs::run_doctor`; remaining work is depth/parity, not existence._
- [x] **WC-P1-08** - Chain verification exists outside the TUI.
  - _Files: `witnessctl/src/routes.rs::verify_session`, `witnessctl/src/main.rs::run_cli_verify`._

### P2 - Pre-Revenue

- [x] **WC-P2-01** - Custody/quorum status panel and export manifest section.
  - _Files: `witnessctl/src/custody.rs`, `witnessctl/src/routes.rs::get_custody_status`, `witnessctl/src/tui.rs`._
- [x] **WC-P2-02** - Populate `witness_captures.cost_usd` and session totals.
  - _Files: `witnessctl/src/capture.rs`, `witnessctl/src/session.rs`, core migration._
- [x] **WC-P2-03** - Session switcher and session list on TUI launch without `--session-id`.
  - _File: `witnessctl/src/tui.rs`._
- [x] **WC-P2-04** - Upstream editor for existing or new sessions.
  - _Files: `witnessctl/src/session.rs`, `witnessctl/src/tui.rs`._
- [x] **WC-P2-05** - Webhook/SIEM/GRC delivery queue with retries and dead-letter state.
  - _New: `witnessctl/src/webhook.rs`; routes/config integration._
- [x] **WC-P2-06** - Canonicalize compliance controls: YAML source generates Rust mapping, or Rust exports canonical YAML.
  - _Files: `witnessctl/internal/compliance_map.yaml`, `witnessctl/internal/compliance_map.generated.yaml`, `witnessctl/src/compliance.rs`, `witnessctl/src/main.rs`._

### P3 - Premium Differentiators

- [x] **WC-P3-01** - Signed evidence bundle with independent verifier command.
  - _Files: `witnessctl/src/main.rs`, `witnessctl/src/session.rs`, `witnessctl/src/receipt.rs`._
- [x] **WC-P3-02** - Legal hold and WORM storage profile.
  - _Files: `witnessctl/src/config.rs`, `witnessctl/src/custody.rs`, `witnessctl/src/export.rs`, `witnessctl/src/routes.rs`._
- [x] **WC-P3-03** - Popeye mode: scan all sessions for broken chains, unsealed sessions, stale HITL, PII leaks, custody failures.
  - _Files: `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs`._
- [x] **WC-P3-04** - Evidence packet viewer: control map, receipts, custody checkpoints, reviewer actions, export history.
  - _File: `witnessctl/src/tui.rs`._
- [x] **WC-P3-05** - Terminal polish: help overlay, split inspector, mouse selection, trust badges, export progress.
  - _File: `witnessctl/src/tui.rs`._

---

## Shared Setup and Reliability Backlog

- [x] **SETUP-01** - `CONNECTOR_KEY` is a shared local alias for both products where Connector OS is present.
  - _Files: both config/main paths._
- [x] **SETUP-02** - Connector OS detection/spawn is graceful and never hides the product's own local mode.
  - _Files: `tracetramp/src/main.rs`, `witnessctl/src/connector.rs`._
- [x] **SETUP-03** - Docker Compose starts Connector OS, Postgres, Redis, TraceTramp, and WitnessCtl with non-conflicting ports and healthchecks.
  - _Files: `lab/docker-compose.premium-lab.yml`, `plugins/tracetramp/docker-compose-init/`, `lab/Dockerfile.connector` (OSS Connector build context `oss/`)._
- [x] **SETUP-04** - Migration checksum repair is opt-in and clearly messaged.
  - _Files: `tracetramp/src/storage.rs` (migrations + repair), `tracetramp/src/main.rs` (`doctor` hints)._
- [x] **SETUP-05** - Agent registration reuses existing identity and does not burn lab cap slots on every restart.
  - _Files: `witnessctl/src/session.rs` (stable agent names), `witnessctl/src/connector.rs` (exact-name reuse only)._

---

## Source-Confirmed Corrections and Bugs

### TraceTramp

| ID | Status | File/symbol | Finding |
|---|---|---|---|
| TT-BUG-01 | [x] | `tracetramp/src/tui.rs`, `tracetramp/src/connector.rs::InteractionRecord` | Resolved: `model`/`provider` fields are carried through and rendered in TUI interaction rows. |
| TT-BUG-02 | [x] | `tracetramp/src/control.rs` | Resolved: hot path metadata now records provider/model/tokens/cost/latency/reason across key steps. |
| TT-BUG-03 | [x] | `tracetramp/src/gateway.rs::get_decision_tree` | Resolved: `/decision/:trace_id` reads persisted `decision_trees.tree_data` and returns real artifacts. |
| TT-BUG-04 | [x] | `tracetramp/src/admin.rs::list_approvals` | Resolved: approvals are backed by `approval_queue` with approve/reject/quarantine actions. |
| TT-BUG-05 | [x] | `tracetramp/src/auth.rs`, `tracetramp/src/admin.rs` | Resolved: admin router is guarded and insecure dev bypass now requires explicit `TRACETRAMP_ALLOW_INSECURE_ADMIN=1`. |
| TT-BUG-06 | [x] | `tracetramp/migrations/20240101000001_init.sql`, `20240101000005_rollup_tables.sql` | Resolved: control-path writes now populate `cost_records` and upsert hourly/daily rollups. |
| TT-BUG-07 | [x] | `tracetramp/src/main.rs::AppState`, `tracetramp/src/control.rs` | Resolved: active-call counter is managed via request-lifecycle guard and shown in admin/TUI. |
| TT-BUG-08 | [x] | `tracetramp/src/main.rs` | Resolved: startup now emits a credential box with local API key + cage URL/env exports. |
| TT-BUG-09 | [x] | `tracetramp/src/connector.rs::witness_tracetramp_handoff` | Witness handoff uses `POST …/integrations/tracetramp/handoff` with shared secret (not legacy ingest URL). |

### WitnessCtl

| ID | Status | File/symbol | Finding |
|---|---|---|---|
| WC-BUG-01 | [x] | `witnessctl/src/session.rs::open_session` | Resolved: `proxy_url` now honors `WITNESSCTL_BASE_URL` (or `WITNESSCTL_PUBLIC_HOST` + `WITNESSCTL_PORT`) instead of hardcoded localhost. |
| WC-BUG-02 | [x] | `witnessctl/src/tui.rs` | Resolved: TUI now shows chain trust strip using verify API in both primary views. |
| WC-BUG-03 | [x] | `witnessctl/src/session.rs` | Resolved: seal materializes a `.witnessctl` bundle and persists `bundle_path`. |
| WC-BUG-04 | [x] | `witnessctl/src/capture.rs` | Resolved: ingest now writes per-capture cost and updates session cumulative cost. |
| WC-BUG-05 | [x] | `witnessctl/src/tui.rs` | Resolved: HITL panel now shows actionable queue rows with resolve actions. |
| WC-BUG-06 | [x] | `witnessctl/src/config.rs::is_enterprise_tier`, `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs` | Resolved: enterprise gating and degraded-custody export policy blocks are surfaced with explicit UI messaging/confirmation flow. |
| WC-BUG-07 | [x] | `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs`, `witnessctl/src/session.rs` | Resolved lock/unlock and quarantine action surface with API + TUI controls, reviewer action evidence, and proxy blocking for locked/quarantined sessions. |
| WC-BUG-08 | [x] | `witnessctl/src/custody.rs`, `witnessctl/src/tui.rs` | Custody/quorum badge is now visible in TUI with quorum achieved/target metrics. |
| WC-BUG-09 | [x] | `witnessctl/src/main.rs::run_doctor` | WitnessCtl already has a doctor command; backlog should track parity/depth only. |
| WC-BUG-10 | [x] | `witnessctl/src/routes.rs::verify_session`, `witnessctl/src/main.rs::run_cli_verify` | Chain verification exists outside the TUI. |
| WC-BUG-11 | [x] | `witnessctl/src/capture.rs`, `witnessctl/src/tui.rs`, `witnessctl/migrations/20260427000010_pii_preview_columns.sql` | Resolved: PII inspector now shows exact field/type/action with original vs redacted preview. |

---

## Recommended Sprint Order

### Immediate Next Steps (Execution Queue)

1. - [x] **NEXT-01 (TraceTramp P0/P2)** - Enforce management-plane auth and tenant scoping for approvals/interactions APIs.
   - _Files: `tracetramp/src/admin.rs`, `tracetramp/src/auth.rs`._
2. - [x] **NEXT-02 (TraceTramp P2)** - Add quarantine hot-path enforcement (blocked-at-source) beyond approval status update.
   - _Files: `tracetramp/src/control.rs`, `tracetramp/src/admin.rs`, `tracetramp/src/tui.rs`._
3. - [x] **NEXT-03 (WitnessCtl P0)** - Implement real `.witnessctl` bundle materialization on seal (captures + receipts + verify snapshot + signature metadata).
   - _Files: `witnessctl/src/session.rs`, `witnessctl/src/export.rs`, `witnessctl/src/receipt.rs`._
4. - [x] **NEXT-04 (WitnessCtl P1/P2)** - Replace HITL count-only panel with actionable queue rows + resolve actions + tier messaging.
   - _Files: `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs`, `witnessctl/src/config.rs`._
5. - [x] **NEXT-05 (WitnessCtl P2)** - Add custody/quorum strip and export-manifest section in TUI.
   - _Files: `witnessctl/src/custody.rs`, `witnessctl/src/routes.rs`, `witnessctl/src/tui.rs`._

### TraceTramp Track

1. - [x] **TT Sprint 0 - It enforces locally**: first-run setup, JWT auto-generation, no blocking prompt, TUI auto-launch, credential/cage box.
2. - [x] **TT Sprint 1 - No fake data**: metadata writes, `InteractionRecord` fields, cost/tokens/model/provider, active-call counter, clean block reason.
3. - [x] **TT Sprint 2 - It acts**: real approvals table, HITL panel, approve/reject/quarantine, policy/provider forms.
4. - [x] **TT Sprint 3 - Moat complete**: cage router, decision tree persistence/API, enforcement packet export, management auth.
5. - [x] **TT Sprint 4 - $1000 polish**: command palette, split inspector, help overlay, gauges, cost forecast, anomaly badges.

### WitnessCtl Track

1. - [x] **WC Sprint 0 - It proves locally**: HMAC auto-generation, correct proxy URL, TUI trust strip, export directory, clear first-run witness session.
2. - [x] **WC Sprint 1 - Evidence is real**: seal writes bundle, compliance export maps controls to captures, report download opens locally.
3. - [x] **WC Sprint 2 - It governs evidence**: quarantine, lock/unlock, HITL queue items/actions, PII original/redacted preview, tier-aware messaging.
4. - [x] **WC Sprint 3 - Custody complete**: custody/quorum panel, signed bundle verifier, canonical compliance map, per-capture cost.
5. - [x] **WC Sprint 4 - Auditor-grade polish**: Popeye mode, GRC/SIEM webhooks, legal hold/WORM profile, evidence packet viewer.

### Integration Track

1. - [x] **INT Sprint 0 - Shared IDs**: TraceTramp decision IDs link to WitnessCtl capture/evidence IDs.
2. - [x] **INT Sprint 1 - Async handoff**: TraceTramp forwards enforcement context to WitnessCtl without impacting hot-path latency.
3. - [x] **INT Sprint 2 - Dual packet**: operator can export TraceTramp enforcement packet and WitnessCtl proof packet for the same event.

---

## Reference: Current File Map

```
tracetramp/src/
  main.rs       - AppState, serve/start/tui/watch subcommands, spawn_detached_tui, doctor/setup
  control.rs    - Hot path: admission, policy, pii, llm, record_event
  connector.rs  - Connector OS client; WitnessCtl async handoff (`witness_tracetramp_handoff`)
  admin.rs      - Management plane REST routes, tenants, providers, policies, approvals, interactions
  auth.rs       - JWT/admin auth helpers; management routes guarded (insecure dev bypass opt-in)
  gateway.rs    - Public trace/cost/decision endpoints; `/decision/:trace_id` reads persisted `decision_trees`
  view.rs       - Decision tree construction/logging path
  tui.rs        - Ratatui enforcement console
  types.rs      - RuntimeExecutionRequest and shared runtime types
  storage.rs    - Redis cache helpers
  migrations/   - cost_records, decision_trees, rollups; several schemas still need runtime writers

witnessctl/src/
  main.rs       - Config, serve, tui, watch, doctor, setup, verify/export CLI paths
  routes.rs     - REST routes: sessions, captures, compliance, proof, pii, export, report, proxy, custody
  proxy.rs      - HTTP proxy forward logic
  tui.rs        - Ratatui evidence console
  compliance.rs - Framework mapping (HIPAA/SOC2/GDPR/EU_AI_ACT)
  export.rs     - PDF/JSON/CSV export logic
  capture.rs    - Capture record management and custody queue insertion
  session.rs    - Session lifecycle, seal metadata, proxy URL response
  custody.rs    - Replication queue processing and custody status
  connector.rs  - Connector OS client and agent register/reuse
  pii.rs        - PII detection patterns
  receipt.rs    - HMAC chain-of-custody and verification
  watchdog.rs   - Proxy/session watchdog surface
  migrations/   - core, HITL, custody, TSA, tenant isolation, proxy hardening
```
