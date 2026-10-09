# Connector Suite TUI Wizards Master Plan

## Purpose

Design three separate, lightweight but powerful TUIs:

- `devguard tui` (guardrails and enforcement cockpit)
- `tracetramp tui` (runtime control and policy/budget traffic cockpit)
- `witnessctl tui` (evidence, compliance, and report generation cockpit)

Each TUI boots independently, but all share a unified unlock model:

- User enters Connector API base URL and access key/token.
- Key is validated against Connector OS.
- TUI session loads tenant-scoped capabilities and history.

This document defines wizard goals, feature scope, screen design, and interaction model before implementation.

---

## Product Principles

- **Terminal-first speed:** keyboard-driven, low-latency, no heavy UI framework burden.
- **Simple surface, powerful depth:** start with defaults, allow deep drill-down when needed.
- **Zero-trust defaults:** every wizard should encourage safe setup and explicit confirmation.
- **Composable flows:** each wizard can skip advanced sections and still produce a usable config.
- **Connector-centered identity:** all actions are scoped by validated Connector credentials.
- **Auditability built in:** every important action should be traceable in history views.

## TUI Framework Decision (Locked)

- **Primary implementation:** `ratatui` full-screen, stateful wizard experiences for all three products.
- **Wizard requirement:** multi-step visual flow (stepper/sidebar, form states, validation, review/confirm), not plain sequential CLI prompts.
- **Optional fallback only:** support a minimal non-interactive mode (`--quick`/`--from-env`) for automation and CI use, but this is secondary.
- **Terminal interaction stack:** `ratatui` + keyboard event loop (e.g., crossterm backend).

---

## Shared Boot and Unlock Flow (All Three TUIs)

## 1) Boot Screen

- Branding line (`DevGuard`, `TraceTramp`, `WitnessCtl`) + version.
- Shows runtime mode and detected OS.
- Quick key hints (`Enter`, `Tab`, `Ctrl+S`, `F1` Help).

## 2) Connector Access Wizard

- Fields:
  - `Connector Base URL` (default from env/config)
  - `Access Key / Token` (masked input)
  - Optional `Profile Name` (e.g., `prod-main`, `staging`)
- Actions:
  - `Test Connection`
  - `Save Profile`
  - `Continue (temporary session)`
- Validation:
  - URL health check
  - token validity
  - tenant/context resolution
- Failure states:
  - invalid token
  - missing scopes
  - endpoint mismatch
  - TLS/network error

## 3) Capability Handshake

- Fetch and display what this identity can do:
  - read/write policy
  - budgets
  - memory
  - evidence/report generation
  - admin actions
- Fetch and display Connector license status:
  - license tier
  - max agent allowance
  - current agent usage
- Enforce unlock model:
  - dev bypass allows up to 3 agents without key
  - >3 agents requires valid Connector API/access token and license-cap check
- Show warnings for restricted capability (read-only mode).

## 4) Workspace Detection

- Auto-detect local repo/project context.
- Confirm project root and plugin mode.
- Option: continue with no workspace (remote-only management mode).

---

## DevGuard TUI (`devguard tui`) - Deep Focus

DevGuard is the guardrail anchor. Wizard must ensure real enforcement and avoid false safety.

## Primary User Outcomes

- Quickly create a real guard policy profile for a repo/team.
- Enable cage mode with verifiable enforcement layers.
- See guard status live and detect drift immediately.
- Review and act on blocked operations with context.

## DevGuard Wizard Modules

### Module A: Protection Targeting

- Select project path(s).
- Choose protected assets:
  - `.env`, `secrets/`, infra folders, keys, prod configs
- Optional drag-and-drop style selector in terminal:
  - multi-select file patterns (`*`, `**`, regex presets)

### Module B: Enforcement Layers

- Toggle and configure:
  - Git hooks enforcement
  - File permission enforcement
  - Filesystem watchdog
  - Exec guard (including Linux hardening mode)
  - Network fence allow/deny lists
- For each layer, show:
  - `enabled?`
  - `verification method`
  - `degradation behavior`

### Module C: Agent Integration

- Choose adapter target:
  - Cursor / Claude / Windsurf / generic MCP client
- Install/validate hooks/channel scripts.
- Show “channel ready” vs “script only” status.

### Module D: Guardrail Policy Authoring

- Friendly wizard prompts convert to policy JSON/YAML:
  - “Block writes to these paths?”
  - “Require approval for these tools/commands?”
  - “Allow only these outbound hosts?”
- Advanced mode for direct rule editing.

### Module E: Verification and Dry-Run

- Runs active probes:
  - write-block probe
  - watchdog revert probe
  - hook path resolution probe
  - exec interception probe
- Displays pass/fail by layer with remediation suggestions.

## DevGuard Main Screens

- **Dashboard**
  - Enforcement mode (`advisory/hooks/cage/locked`)
  - Layer health
  - Active violations (last N)
  - Drift detector (policy vs runtime state)
- **Rules Explorer**
  - Browse and edit rule groups
  - enable/disable rule toggles
- **Events Stream (wireshark-like feel)**
  - live blocked/allowed events
  - filter by tool/path/actor/layer/severity
- **Verification Panel**
  - run probes on demand
  - compare current vs last verification
- **History**
  - policy changes
  - enforcement changes
  - blocked-action timeline with evidence pointers

---

## TraceTramp TUI (`tracetramp tui`)

TraceTramp wizard focuses on runtime control and safe throughput.

## Primary User Outcomes

- Configure policy/budget/runtime control quickly.
- Observe live request traffic, cost burn, and policy outcomes.
- Debug route/fallback behavior safely.

## TraceTramp Wizard Modules

### Module A: Runtime Profile

- Select mode defaults (`view` or `control`).
- Configure timeout and request profile.
- Choose fallback strategy from provider inventory.
- Set per-session agent allowance target and validate it against Connector license limits.

### Module B: Provider Chain Setup

- Ordered provider chain editor.
- Circuit breaker defaults:
  - fail threshold
  - open duration
- Health probe test for each provider.

### Module C: Budget and Usage Controls

- Default budget model:
  - per actor / tenant
  - token and cost limits
- Alert thresholds and action:
  - warn, throttle, hard reject

### Module D: Policy Route and Guard Flow

- Attach policy bundles and action controls.
- Define block/require-approval routes.
- Validate with simulation requests.

### Module E: Memory + Evidence Integration

- Configure memory write scope.
- Enable interaction logging and receipt behavior.

## TraceTramp Main Screens

- **Live Runtime Dashboard (nmap-like concise panels)**
  - active calls
  - p50/p95 latency
  - block rate
  - fallback attempts
  - token/cost burn
- **Traffic Stream**
  - per request row: actor, model, provider, decision, cost, latency
- **Policy Hits**
  - allow/block/approval reasons
- **Budget Monitor**
  - budget exhaustion risk and threshold alerts
- **Provider Health**
  - circuit state (closed/open/half-open later)
- **History**
  - incident timeline and decision trail

---

## WitnessCtl TUI (`witnessctl tui`)

WitnessCtl wizard focuses on evidence integrity and compliance reporting.

### Connector-Powered Unlock (Locked Requirement)

- WitnessCtl uses Connector unlock only (same contract as DevGuard and TraceTramp).
- Unlock mode is exactly:
  - Connector access key/token, or
  - dev bypass for up to 3 active agents.
- If requested active agents exceed 3, Connector key + license cap check is mandatory.
- No alternate/local-only auth model is permitted for normal operation.
- Wizard must show resolved unlock state before entering the dashboard:
  - `unlock_mode`, `requested_agents`, `current_agents`, `max_agents`, `license_tier`.

## Primary User Outcomes

- Ensure evidence capture is complete and tamper-evident.
- Generate and download reports fast.
- Track report history and integrity state.

## WitnessCtl Wizard Modules

### Module A: Evidence Source Mapping

- Choose source services/endpoints.
- Select event classes to capture.
- Configure retention windows.

### Module B: Integrity Chain Settings

- Receipt/signature policy.
- Hashing and chain options.
- Failure handling (queue/retry/degrade policy).

### Module C: Compliance Profile Setup

- Choose frameworks:
  - SOC2, HIPAA, GDPR, AI Act, etc.
- Map controls to data sources.
- Set report templates and schedules.

### Module D: PII and Data Handling

- PII scan configuration and sensitivity thresholds.
- Redaction/flag workflow.

### Module E: Report Output and Delivery

- Output formats (JSON/PDF where available).
- Download options and destination targets.
- Approval/export workflow.

## WitnessCtl Main Screens

- **Evidence Dashboard**
  - ingestion volume
  - chain integrity status
  - failed seals / retries
- **Integrity Monitor**
  - signature/receipt validation summary
- **Compliance Controls View**
  - control coverage and gaps
- **Report Builder**
  - select scope/date/framework
  - generate preview
  - generate final report
  - download/export actions
- **Report History**
  - generated reports table
  - status, hash, timestamp, generated-by
  - re-download and verify hash

---

## History and Audit UX (All TUIs)

- Unified timeline model:
  - `who`, `what`, `when`, `where`, `result`, `evidence_ref`
- Default filters:
  - severity
  - actor
  - date range
  - object (policy, provider, report)
- Quick actions:
  - copy evidence ID
  - open related trace
  - export selected rows

---

## Interaction Model

- **Keyboard-first controls**
  - `j/k` move
  - `Enter` open
  - `/` filter
  - `g` goto
  - `:` command palette
- **Panels**
  - left nav (sections)
  - center content
  - right detail/inspector
  - bottom hotkeys/log line
- **Command Palette**
  - `Create Policy`, `Run Verify`, `Generate Report`, `Switch Profile`

---

## Data and Config Profiles

- Local profile store per TUI:
  - named Connector endpoints/tokens (token optionally not persisted)
  - default tenant/workspace bindings
  - recent actions
- Redaction-safe display:
  - never print full token in UI logs
  - only prefix/suffix visible

---

## Security and Reliability Requirements

- Never allow “fake green” status:
  - if enforcement/evidence checks are degraded, UI must show warning state.
- Connector token lifecycle:
  - manual paste or env reference
  - optional in-memory-only session mode
- Degraded mode behavior:
  - read-only when critical capabilities missing
  - explicit banner for partial operation

---

## Suggested Build Phases

## Phase 1: Skeleton TUIs

- Launch each TUI independently.
- Implement shared Connector unlock wizard.
- Add basic dashboard + history placeholders.

## Phase 2: Core Wizards

- DevGuard enforcement wizard + verify panel.
- TraceTramp provider/budget wizard + live stream.
- WitnessCtl report builder + download.

## Phase 3: Operational Depth

- Advanced filters, command palette, profile switching.
- Better drill-down and evidence linking.

## Phase 4: Polish

- Performance tuning and terminal UX refinement.
- Help overlays and guided keyboard tutorial.

---

## Acceptance Criteria (Initial)

- Each TUI starts in <2s on dev machine.
- Connector unlock flow validates and scopes session before main screen.
- Each wizard can produce a usable baseline config in <=5 minutes.
- History view available in all three TUIs.
- WitnessCtl can generate and download a report from TUI.
- DevGuard verification clearly shows true enforcement state.
- TraceTramp dashboard shows live request + provider + budget state.

---

## Notes for Part 2 Implementation

- Keep all three TUIs separate binaries/commands but share core TUI components:
  - auth/profile module
  - event table widget
  - filter/query bar
  - status badge renderer
- Use `ratatui` as the shared rendering layer across all three TUIs for consistency and maintainability.
- Preserve “operator feel” similar to `nmap`/packet tools:
  - dense useful info, low decoration, fast keyboard loops.
