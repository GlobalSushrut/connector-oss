# Connector OS — Master Issue Registry
> All known problems across DevGuard, TraceTramp, Connector OS UX, and business/compliance gaps.
> Written after live prod testing on 2026-04-26.
> **Every item has a checklist. Fix in order. Do not skip steps.**

---

## Compliance plane roadmap (WitnessCtl + TraceTramp)

Phased work toward high-assurance control + evidence is tracked in:

**[`platform/docs/arch/WITNESSCTL_TRACETRAMP_MILITARY_COMPLIANCE_PLAN.md`](platform/docs/arch/WITNESSCTL_TRACETRAMP_MILITARY_COMPLIANCE_PLAN.md)** — Phases P0–P4, verification **V1–V7**, **Section 9** operator outcomes (PDF any-browser + server, decision flags, Block space, git-level policy, TUI contract), and **Section 10** executable coding checklist (checkboxes → issues). Use IDs `P0-*` … `P4-*` plus `10.x` labels when filing.

---

## How to use this file

- `[ ]` = not started
- `[~]` = in progress
- `[x]` = done
- Priority: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low
- Owner columns: **TT** = TraceTramp · **DG** = DevGuard · **OS** = Connector OS · **UX** = All

---

## Part 1 — TraceTramp: Technical Bugs

### TT-01 🔴 ConnectorClient calls itself (self-loop)
`TRACETRAMP_CONNECTOR_BASE_URL` defaults to `http://localhost:9091` — TraceTramp's own data
plane. Every Connector OS call (policy check, receipts, admission, billing) hits itself → 404 → 502.

- [x] Change default `TRACETRAMP_CONNECTOR_BASE_URL` to `http://localhost:9735` (Connector OS port)
- [x] Add startup check: if `CONNECTOR_BASE_URL == self data plane port` → log fatal error and refuse to start
- [x] Update `.env.example` with correct Connector OS URL
- [x] Update `docker-compose.yml` to add `connector` service dependency with `service_healthy`
- [x] Test: start both Connector OS + TraceTramp, verify `POST /aapi/policies/evaluate` resolves correctly

### TT-02 🔴 Wrong Connector OS API endpoints in ConnectorClient
TraceTramp calls URLs that do not exist in Connector OS. Every call fails silently.

| TraceTramp calls | Should call | Status |
|---|---|---|
| `POST /aapi/policies/check` | `POST /aapi/policies/evaluate` | ❌ Wrong |
| `POST /aapi/receipts/issue` | `POST /aapi/capabilities/issue` | ❌ Invented |
| `POST /aapi/admission/check` | `POST /aapi/capabilities/verify` | ❌ Invented |
| `POST /billing/record` | `POST /aapi/budgets/consume` | ❌ Wrong |
| `GET /agents/{id}/cost` | `GET /aapi/budgets/:pid/:resource` | ❌ Wrong |
| `GET /monitor/trust?agent=` | `GET /monitor/trust` (no query param) | ⚠️ Near miss |

- [x] Rewrite `check_policy()` → `POST /aapi/policies/evaluate` with `PolicyRule` payload
- [x] Rewrite `issue_receipt()` → `POST /aapi/capabilities/issue` (UCAN token per request)
- [x] Rewrite `check_admission()` → `POST /aapi/capabilities/verify` (verify token)
- [x] Rewrite `record_usage()` → `POST /aapi/budgets/consume` with `agent_pid` + `resource=tokens`
- [x] Rewrite `get_agent_cost()` → `GET /aapi/budgets/:pid/tokens`
- [x] Fix `get_trust_score()` → `GET /monitor/trust` (remove wrong `?agent=` param, pass in body)
- [x] Add `log_interaction()` → `POST /aapi/interactions` for every proxied call
- [x] Integration test each endpoint against a live Connector OS instance

### TT-03 🔴 TraceTramp is architecturally standalone — not a real Connector OS plugin
TraceTramp rebuilds its own tenant DB, policy engine, budget tables, provider registry, and audit
log instead of using Connector OS capabilities. It is a parallel product, not a plugin.

- [x] Remove `tenants` table — use Connector OS agent identity (`POST /api/v1/agents`)
- [x] Remove `policies` table — use `POST /aapi/policies` + `POST /aapi/policies/evaluate`
- [x] Remove `budgets` table — use `POST /aapi/budgets` + `POST /aapi/budgets/consume`
- [x] Remove `trace_events` table — write to `POST /aapi/interactions` (durable audit chain)
- [x] Remove `api_keys` table — use Connector OS `cpk_live_*` / `cpk_test_*` keys natively
- [x] Keep only TraceTramp-specific tables: `providers`, `workflow_definitions`, `function_registry`
- [x] Route all LLM traffic through Connector OS `/v1/chat/completions` gateway, not directly to OpenAI
- [x] Use Connector OS Guard Pipeline (content filter, rate limit, circuit breaker) instead of local regex
- [x] Use Connector OS memory kernel for agent context, not stateless per-request

### TT-04 🔴 Policy enforcement reads local regex, ignores tenant DB policies
After our workaround fix, `check_policy()` does local pattern matching but ignores the
`policies` table entirely. A tenant can create 100 policies — none take effect.

- [x] Replace local regex engine with DB policy read: `SELECT rules, enforcement_mode FROM policies WHERE tenant_id = $1 AND is_active = true ORDER BY priority DESC`
- [x] Evaluate `rules` JSON against request payload for each active policy
- [x] Respect `enforcement_mode`: `monitor` = log only, `block` = reject, `alert` = log + notify
- [x] Unit test: create policy, send matching call, verify blocked

### TT-05 🔴 Budget enforcement is a warning only — no hard stop
`current_spend` is never updated. Budget creation succeeds but no spend is ever deducted
and no hard stop fires when `limit_amount` is exceeded.

- [x] On every proxied call: `UPDATE budgets SET current_spend = current_spend + $cost WHERE tenant_id = $1`
- [x] Before proxying: check `current_spend >= limit_amount` → return 429 with budget exhausted error
- [x] Alert at `alert_threshold` percent: emit warning log + (future) webhook notification
- [x] Unit test: set $0.01 budget, send call, verify rejection

### TT-06 🟠 Receipt issuance returns 502
`issue_receipt()` calls a non-existent endpoint → 502 propagates up as a gateway error
on every successfully completed call.

- [x] Short term: make `issue_receipt()` return a locally-generated receipt (SHA256 of request_id + trace_id + timestamp) instead of failing
- [x] Long term: wire to `POST /aapi/capabilities/issue` in Connector OS (see TT-02)
- [x] Never let receipt failure block the primary response — receipt errors must be async/best-effort

### TT-07 🟠 Duplicate records accumulate on every simulation run
`create_budget` and `create_policy` have no `ON CONFLICT` / upsert guard.
Every test run inserts new rows. 4 identical budgets + 4 identical policies in DB after today's test.

- [x] Add `ON CONFLICT (tenant_id, name) DO UPDATE SET updated_at = NOW()` to budget INSERT
- [x] Add `ON CONFLICT (tenant_id, name) DO UPDATE SET updated_at = NOW()` to policy INSERT
- [x] Add unique index: `CREATE UNIQUE INDEX IF NOT EXISTS idx_budgets_tenant_name ON budgets(tenant_id, name)`
- [x] Add unique index: `CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_name ON policies(tenant_id, name)`
- [x] Clean existing duplicates: `DELETE FROM budgets WHERE id NOT IN (SELECT MIN(id) FROM budgets GROUP BY tenant_id, name)`

### TT-08 🟠 No provider fallback — timeout causes hard failure
When Ollama times out or OpenAI has no key, the proxy hard-fails with no retry or degradation.

- [x] Add provider priority chain: try provider 1, on timeout/5xx try provider 2, etc.
- [x] Read fallback chain from `providers` table ordered by priority
- [x] Add per-provider circuit breaker: after 3 consecutive failures, skip for 60s
- [x] Return `503` with `X-Fallback-Attempted: true` header when all providers exhausted
- [x] Log which provider served the request in every trace event

### TT-09 🟡 No "one-command" setup
Starting TraceTramp requires: PostgreSQL running + DB/role created + Redis running + migrations
applied + `.env` configured + `cargo run`. No single entrypoint.

- [x] Add `tracetramp setup` subcommand: checks PostgreSQL, creates DB/role if missing, runs migrations, writes `.env` from prompts
- [x] Add `tracetramp doctor` command: checks all dependencies, prints status like `devguard doctor`
- [x] Update `docker-compose.yml` to be truly one-command: `docker compose up` starts everything including TraceTramp
- [x] Add `Makefile` targets: `make setup`, `make run`, `make test`

### TT-10 🟡 `BudgetRow` / `PolicyRow` struct field types mismatch actual schema
ALTER-added columns are nullable but structs used `f64`/`String` (non-Option). Caused runtime
panics until manually patched this session.

- [x] Audit all `sqlx::FromRow` structs against actual DB schema
- [x] Add schema snapshot test: compile-time `sqlx::query!` macros that fail build if schema drifts
- [ ] Run `cargo sqlx prepare` to generate offline query cache
- [x] Add CI step: `cargo sqlx prepare --check` to catch schema drift before deploy

---

## Part 2 — TraceTramp: Missing Features (vs. stated purpose)

### TT-11 🔴 No TUI / live dashboard
TraceTramp has no visual interface. There is no htop-style live view of agent calls,
policy hits, budget burn, PII detections, or blocked requests.

- [x] Add `tracetramp tui` command using `ratatui` crate
- [x] Live panels: active calls (with latency), recent blocks (reason + actor), budget burn rate, policy hit counters
- [x] Keyboard shortcuts: `q` quit, `f` filter by tenant, `p` pause, `e` export current view
- [x] Refresh rate: 1s default, configurable
- [x] Show: trace_id, actor, model, provider, decision (ALLOW/BLOCK/REDACT), cost_usd, latency_ms

### TT-12 🟠 Compliance export planned in TraceTramp — belongs in WitnessCtl instead
> **Boundary violation.** See Part 9. TraceTramp must NOT build its own compliance report
> engine. WitnessCtl already has `compliance.rs` + `export.rs` for this.

- [x] Remove any planned TraceTramp compliance export endpoint
- [x] TraceTramp's role: after every proxied call, `POST /api/v1/witnessctl/ingest` (async, non-blocking) so WitnessCtl captures it
- [x] Compliance reports come from WitnessCtl: `GET /api/v1/witnessctl/sessions/:id/report?framework=soc2`
- [x] Wire `connectorctl compliance report` (OS-02) to WitnessCtl report endpoint, not TraceTramp
- [x] TraceTramp only exposes: `GET /trace/:id`, `GET /explain/:id`, `GET /cost/:id` — live execution views, not sealed evidence

### TT-13 🟠 PII detection persistence planned in TraceTramp — belongs in WitnessCtl instead
> **Boundary violation.** See Part 9. WitnessCtl already has `pii.rs` and
> `witness_captures.pii_in_request / pii_in_response` columns doing exactly this.

- [x] Remove planned `pii_detections` table from TraceTramp migrations
- [x] TraceTramp's role: detect PII in real-time (to decide BLOCK/REDACT) — the detection itself is correct
- [x] Persistence of PII detections for compliance: forward the call to WitnessCtl via `/ingest` — WitnessCtl records `pii_in_request=true` and the field classifications
- [x] For instant BLOCK decisions by TraceTramp: keep local in-memory regex (already working), just don't persist to a parallel table

### TT-14 🟡 No streaming support for proxied LLM calls
`stream: true` requests to the data plane are not forwarded as SSE. They block until complete
or timeout.

- [x] Detect `"stream": true` in request body
- [x] Forward response as `text/event-stream` using `axum::response::sse::Sse`
- [x] Trace each streaming chunk (token count estimated from chunk size)
- [x] Flush final usage metrics to audit on stream end

### TT-15 🟡 Workflow engine exists in code but no routes are wired
`/v1/workflows` routes are declared in `gateway.rs` but the workflow engine handlers
return stubs or are unimplemented.

- [x] Audit all workflow route handlers — mark which are stubs
- [x] Implement `POST /v1/workflows` → store workflow definition in DB
- [x] Implement `POST /v1/workflows/:id/run` → execute steps sequentially
- [x] Wire human-in-the-loop step type to `POST /admin/approvals`
- [x] Each workflow step writes a trace event

### TT-16 🟡 No one-command live boot for TraceTramp + workflow + always-live TUI
Operators should be able to launch a complete live TraceTramp runtime by issuing a single
command, with workflow runtime checks, detached live TUI, and service startup.

- [x] Add `tracetramp start` as one-command boot entrypoint
- [x] `start` runs setup prerequisites and validates workflow runtime tables
- [x] `start` launches `tracetramp tui` in detached app window by default
- [x] `start` launches TraceTramp server in background so shell remains usable
- [x] Add `--foreground` option so operators can run server inline when needed
- [x] Add `--no-tui` option for automation/headless startup

---

## Part 3 — DevGuard: Technical Bugs

### DG-01 🔴 DevGuard logic is embedded inside Connector OS kernel — boundary violation
`devguard.rs`, `policy_config.rs`, `exec_guard.rs`, `fs_guard.rs` live in
`platform/server/src/services/` — inside the OS kernel. This is like Firefox compiled into Linux.

- [x] Extract `devguard.rs` → `plugins/devguard/src/services/session.rs`
- [x] Extract `policy_config.rs` → `plugins/devguard/src/config.rs` (partially done)
- [x] Extract dangerous patterns from `exec_guard.rs` → DevGuard (policy check stays in Connector AAPI)
- [x] Extract `fs_guard.rs` policy rules → DevGuard (scan engine stays in Connector)
- [x] Refactor `anthropic_gateway.rs:171-238` — remove hardcoded `devguard::resolve_session`; replace with generic hook registration
- [x] Move `protocols.rs` `devguard_*` MCP tools → DevGuard registers them via Connector MCP hosting API
- [x] After extraction: verify `cargo build` for Connector OS has zero DevGuard imports

### DG-02 🟠 `devguard connect windsurf` requires manual hook wiring
Connecting Windsurf (or any IDE) requires the user to manually configure MCP settings,
copy hook paths, and restart the IDE. No guided flow exists.

- [x] `devguard connect windsurf` → auto-detect Windsurf config path (`~/.windsurf/settings.json` or equivalent)
- [x] Auto-write MCP server entry pointing to DevGuard's MCP endpoint
- [x] Print clear instructions: "Restart Windsurf → DevGuard MCP is now active"
- [x] Add `--dry-run` flag: shows what would be written without writing
- [x] Add `devguard connect --list` to show all connected tools and their status

### DG-03 🟠 `devguard doctor` does not check Connector OS connectivity
`devguard doctor` runs but doesn't verify the full chain:
DevGuard → Connector OS → AAPI → audit chain.

- [x] Add Connector OS health check: `GET $CONNECTOR_URL/health`
- [x] Add AAPI reachability check: `GET $CONNECTOR_URL/aapi/capabilities`
- [x] Add audit chain write test: write a test event, read it back
- [x] Add LLM gateway check: `GET $CONNECTOR_URL/v1/models`
- [x] Print full chain status: `devguard ──► connector-os ──► aapi ──► audit ──► llm-gateway`

### DG-04 🟡 `devguard.yaml` has no interactive editor or validation feedback
Configuration errors in `devguard.yaml` are only caught at `devguard connect` time.
No live validation, no schema documentation inline.

- [x] `devguard config edit` → open `devguard.yaml` in `$EDITOR` with schema validation on save
- [x] `devguard config validate --verbose` → print each rule with PASS/FAIL and the reason
- [x] `devguard policy matrix` → already exists, improve output: show which tools can read/write which paths
- [x] Add JSON Schema for `devguard.yaml` so IDEs provide autocomplete

### DG-05 🟡 Approval workflow has no timeout or escalation
`require_approval` actions queue in the approval queue but never expire.
If the approver is offline, the agent blocks indefinitely.

- [x] Add `timeout_minutes` field to approval queue (default: 30)
- [x] Background job: expire approvals older than `timeout_minutes` → auto-reject with reason
- [x] Add escalation: after timeout, notify secondary approver list
- [x] `devguard approvals list` should show time-remaining countdown

---

## Part 4 — DevGuard: Missing Features

### DG-06 🟠 No IDE extension / plugin — setup is CLI only
DevGuard has no IDE extension for Windsurf, Cursor, or VS Code. The only UX is CLI commands.
Developers can't see governance status while coding.

- [x] Design DevGuard IDE extension API (status endpoint for extensions to poll)
- [x] `GET /devguard/status` → current session, active role, pending approvals count, budget remaining
- [x] Build Windsurf extension: status bar showing role + budget + last blocked action
- [x] Build VS Code extension (same API)
- [x] Extension shows red badge when approval is pending

### DG-07 🟡 No team onboarding flow for `devguard init --team`
`devguard init --team` generates a template but the assignments section is blank.
New teams have to manually fill in identity→role mappings with no guidance.

- [x] `devguard init --team` → interactive wizard: asks for team member GitHub handles, assigns roles
- [x] `devguard team add <identity> --role <role>` → appends to assignments section
- [x] `devguard team list` → shows all assignments and their effective permissions
- [x] `devguard team audit` → shows which members have access to which paths

### DG-07A 🔴 No one-command guided start for git + tool + access-key + team role key
DevGuard startup must be a guided wizard, not fragmented CLI steps. Expected operator flow:
select git project → select coding agent tool (Cursor/Windsurf/etc) → choose Connector access key
or dev bypass (3 agents) → provide team role key from webapp (or default to mid-developer profile)
→ open live DevGuard UI and keep recording real actions while user continues coding in CLI.

- [x] Add `devguard start` guided wizard entrypoint (single command boot)
- [x] Wizard step 1: detect current git workspace and confirm target project root
- [x] Wizard step 2: select active coding tool (`cursor`, `windsurf`, `claude-code`, etc)
- [x] Wizard step 3: unlock mode — Connector access key OR dev bypass (`<=3` agents)
- [x] Wizard step 4: team role key prompt (from webapp); if absent, auto-apply default `mid_developer` config
- [x] If team role key mode selected, require webapp login/session before activation
- [x] Start live DevGuard UI/dashboard and keep it detached/persistent while CLI remains usable
- [x] Persist startup profile (workspace, tool, role mode, connector URL) for reuse
- [x] Ensure runtime records real DevGuard enforcement actions to Connector/Witness surfaces

---

## Part 5 — Connector OS: UX / Observability

### OS-01 🔴 No htop-style live agent monitor
`connectorctl top` exists but output is a static table dump. There is no live-refreshing
terminal UI equivalent to `htop` for running agents.

- [ ] Add `connectorctl watch` as a real live-refresh TUI (already in spec — implement it)
- [ ] Panels: agent list (pid, name, model, status, tokens, cost, trust score), system load, budget burn
- [ ] Color coding: green = healthy, yellow = degraded, red = blocked/failed
- [ ] Keyboard: `k` kill agent, `i` inspect, `t` trace, `e` explain, `/` filter, `q` quit
- [ ] Refresh rate: 2s default, `--interval` flag
- [ ] Implement with `ratatui` + `crossterm`

### OS-02 🔴 No compliance report download from CLI
Connector OS has `GET /compliance/report`, `GET /compliance/gdpr/data-subjects`,
`POST /compliance/gdpr/forget/:pid` etc. but `connectorctl compliance` is not wired to them.

- [x] `connectorctl compliance report --framework soc2 --output report.pdf`
- [x] `connectorctl compliance report --framework hipaa --from 2026-01-01 --to 2026-04-30`
- [x] `connectorctl compliance report --framework gdpr` → includes data subject list + erasure log
- [x] `connectorctl compliance report --framework eu-ai-act` → high-risk system log + human oversight events
- [x] `connectorctl compliance findings` → filterable findings table with remediation steps
- [x] Each report: signed SHA256 hash printed to stdout for chain-of-custody
- [x] `--output` flag: `json`, `csv`, `pdf` (pdf via headless render or text format)

### OS-03 🟠 `connectorctl trace` shows no PII events, no blocked calls, no policy hits
`connectorctl trace <agent>` shows a timeline of tool calls but never shows:
- PII detection events
- Policy block events
- Budget warning events
- Guard pipeline triggers

- [x] Extend trace timeline to include `event_type: pii_detected | policy_blocked | budget_warning | guard_triggered`
- [x] Color-code events: red = blocked, orange = warning, green = allowed
- [x] `connectorctl trace <agent> --filter blocked` → show only blocked events
- [x] `connectorctl trace <agent> --pii` → show PII detections with redacted values

### OS-04 🟠 GDPR Article 17 erasure flow has no CLI wrapper
`POST /compliance/gdpr/forget/:pid` exists in the server but there is no CLI command.
Compliance officers must use raw curl.

- [x] `connectorctl compliance gdpr forget <agent-id>` → calls `POST /compliance/gdpr/forget/:pid`
- [x] Prompt for confirmation: "This will seal agent namespace and is irreversible. Type agent ID to confirm:"
- [x] Print erasure receipt with timestamp and CID
- [x] `connectorctl compliance gdpr data-subjects` → list all agents with PII interactions
- [x] `connectorctl compliance gdpr erasure-log` → show all completed erasures

### OS-05 🟡 No audit trail download for individual agents
Operators need to export a full audit trail for a specific agent for legal/compliance review.
No download endpoint or CLI command exists.

- [x] `connectorctl audit export <agent-id> --from <date> --to <date> --output audit.csv`
- [x] Export includes: every action, receipt hash, decision outcome, actor, timestamp, cost
- [x] Export is signed (SHA256 of file contents printed to stdout)
- [x] `connectorctl audit verify <audit.csv>` → re-computes hash and verifies chain integrity

### OS-06 🟡 `connectorctl` has no setup wizard for new users
First-time users face a blank terminal. There is no guided setup sequence.

- [x] `connectorctl quickstart` → interactive wizard: check connectivity, create first agent, run first call, show trace
- [x] `connectorctl doctor` → already exists, extend to cover: LLM key, Connector OS version, plugin status
- [x] First-run detection: if no agents exist, print "Run `connectorctl quickstart` to get started"

---

## Part 6 — Business / Product Gaps

### BIZ-01 🔴 No single "one URL, point your agent here" onboarding story
The product promise (section 0.4 of CAGE docs) is "point your OpenAI SDK at one URL — governance
is automatic." This is not achievable today without 8 manual setup steps.

- [x] Single onboarding URL: `https://your-connector.example.com/v1` (or localhost equiv)
- [x] `make run-local` already works — document this as THE onboarding command in README
- [x] Add quickstart README section: 3 steps (clone, `make run-local`, change `OPENAI_BASE_URL`)
- [x] Test with real OpenAI SDK: `openai.OpenAI(base_url="http://localhost:9091/v1", api_key="dev-token")`
- [x] Test with LangChain, LangGraph, CrewAI pointing at Connector gateway

### BIZ-02 🔴 TraceTramp is marketed as an enterprise product but has no enterprise auth
TraceTramp has JWT auth with a hardcoded secret (`"your-256-bit-secret"`) and no way
to rotate keys, create real API keys, or integrate with SSO/OAuth.

- [x] Remove hardcoded JWT secret — read from `TRACETRAMP_JWT_SECRET` env var, fail to start if not set
- [x] Wire API key creation to `POST /admin/tenants/:id/api-keys` management endpoint
- [x] Store API keys as PBKDF2 hash (not plaintext) in DB
- [x] Add API key rotation endpoint
- [x] Document: in production, auth must go through Connector OS identity (not TraceTramp's own JWT)

### BIZ-03 🟠 No demo mode / sandbox environment
There is no safe "try it without real keys" mode for evaluating the product.

- [ ] `TRACETRAMP_DEMO_MODE=1` → uses stub LLM responses, pre-populated demo tenant, fake audit data
- [ ] `connectorctl demo start` → starts full stack in demo mode, no keys needed
- [ ] Demo data includes: 3 agents (normal, blocked, PII-leaking), pre-built compliance report
- [ ] Demo mode clearly watermarks all output: "DEMO DATA — not for production use"

### BIZ-04 🟠 Compliance frameworks are listed but not mapped to specific agent behaviors
HIPAA/SOC2/GDPR/EU AI Act are referenced throughout but there is no mapping of
"which agent actions trigger which compliance obligation."

- [x] Create compliance mapping table: `action_type → frameworks → obligation → evidence_required`
- [x] Example: `pii_access → GDPR Art.6 → lawful basis required → log data subject consent`
- [x] Example: `high_risk_decision → EU AI Act Art.9 → human oversight required → HITL approval log`
- [x] Wire mapping into compliance export (TT-12 / OS-02)

### BIZ-05 🟡 No pricing/tier enforcement in the plugin layer
Connector OS has billing (Stripe integration) but TraceTramp and DevGuard have no awareness
of which features are available at which pricing tier.

- [x] Define feature tiers: Free (trace only), Pro (trace + policy), Enterprise (full control + compliance)
- [x] Add `CONNECTOR_LICENSE_TIER` env var check at startup
- [x] Gate enterprise features (GDPR export, HITL approvals, multi-tenant) behind tier check
- [x] Show clear error: "This feature requires Enterprise tier. Contact sales."

---

## Part 7 — Cross-Cutting Infrastructure

### INF-01 🔴 No integration test suite — all testing is manual curl
Zero automated tests verify the TraceTramp ↔ Connector OS integration.
All testing done by hand with shell scripts.

- [ ] Add `tests/integration/` directory in TraceTramp
- [ ] Test: tenant resolution from API key
- [ ] Test: normal call → ALLOW → trace event written
- [ ] Test: jailbreak call → BLOCK → block event written
- [ ] Test: PII call → BLOCK → PII detection written
- [ ] Test: budget exceeded → 429 returned
- [ ] Test: policy created → takes effect on next call
- [ ] Run tests in CI against real PostgreSQL + Redis (Docker Compose in CI)

### INF-02 🟠 Port conflicts between plugins
`engram` defaults to port 9092 — same as TraceTramp's management plane and Connector OS
protocol port. Running multiple plugins on one machine causes silent binding failures.

- [x] Standardise ports per CAGE doc Part G: Connector OS = 9735, plugins = 9740+
- [x] TraceTramp: data plane = 9741, management plane = 9742
- [x] Update all `.env.example` files with correct non-conflicting ports
- [x] Add port conflict detection in `doctor` commands

### INF-03 🟠 No `docker-compose.cage.yml` that starts everything correctly
Each plugin has its own `docker-compose.yml` with no `depends_on: connector: condition: service_healthy`.
Running `docker compose up` in a plugin dir does not start Connector OS first.

- [ ] Create `/home/umesh/Projects/connector-private/docker-compose.cage.yml`
- [ ] Services: connector-os, postgresql, redis, tracetramp, devguard-daemon (if applicable)
- [ ] `tracetramp` depends_on `connector-os: condition: service_healthy`
- [ ] `connector-os` depends_on `postgresql: condition: service_healthy`
- [ ] Single command: `docker compose -f docker-compose.cage.yml up tracetramp`

### INF-04 🟡 Schema drift between migration files and application structs
`BudgetRow`/`PolicyRow` Rust structs drifted from the actual DB schema (discovered live this session).
No compile-time guard prevents this from silently causing runtime panics.

- [ ] Enable `sqlx offline mode`: run `cargo sqlx prepare` in TraceTramp
- [ ] Replace all `sqlx::query_as::<_, StructName>("SELECT ...")` with `sqlx::query_as!` macros
- [ ] Add CI step: `cargo sqlx prepare --check` fails build on schema drift
- [ ] Run `cargo sqlx prepare` every time a migration is added

---

## Part 8 — DevGuard: Deep Enforcement Bugs (from code audit)

These 5 issues were found by reading the actual enforcement source code, not from testing.
They are **silent failures** — DevGuard appears to work but doesn't actually protect anything.

### DG-08 🔴 Filesystem watchdog uses polling + bash `sha256sum` — 1-second blind window
**File:** `commands/cage.rs:334–393`

The watchdog is a bash script that checks file hashes every `sleep 1`. Any AI agent
(Windsurf, Cursor, Claude Code) can write a forbidden file, read it, and delete it
within 1 second — all completely undetected and unreverted. The `inotify` comment in
`stop_fs_watchdog()` at line 459 (`pkill -f devguard.*watchdog`) references inotify
but the actual implementation is pure polling bash. Inotify is never used.

```
ATTACK WINDOW:
  t=0ms  agent writes .env (forbidden)
  t=10ms agent reads .env (grabs secrets)  ← UNDETECTED
  t=50ms agent deletes .env
  t=1000ms watchdog polls — file gone, no hash change, no alert
```

- [x] Replace bash polling with `inotify-rs` (Rust crate `notify` v6) in a proper Rust daemon
- [x] Add `notify::RecommendedWatcher` in `cage start` — fires on `Create`, `Modify`, `Remove` events instantly
- [x] Forbidden-file DELETE events must also be alerted (an AI deleting `.env` is suspicious even if it can't write it)
- [x] Write the watchdog as a proper Rust binary (`devguard-watchd`) not a bash script
- [ ] Until fixed: document the 1-second blind window prominently — do not present as "bypass-proof"
- [ ] Test: write a file, verify alert fires in < 100ms

### DG-09 🔴 Exec wrapper only works in interactive bash — does NOT intercept AI tool calls
**File:** `commands/cage.rs:479–531`

The exec wrapper uses `trap '__devguard_trap' DEBUG` — a bash `DEBUG` trap. This only
fires in the **current interactive shell** where the user sources `exec_wrapper.sh`.
AI coding agents (Windsurf, Cursor, Claude Code) spawn their own child processes or use
internal APIs to run commands — **none of them source the user's shell rc files** or run
inside the trapped shell. The trap is completely bypassed.

```
REAL execution path for Windsurf/Cursor shell tool:
  Windsurf internal → execve("/bin/bash", ["-c", "rm -rf /important"]) → kernel
  ↑ DevGuard DEBUG trap is NEVER in this execution chain
```

- [ ] The only reliable exec interception is at the MCP/tool-call protocol level — intercept `bash`/`run_terminal_cmd` tool calls in the adapter before they are sent to the IDE
- [x] In `WindsurfAdapter`, `CursorAdapter`, `ClaudeAdapter`: intercept `bash` tool calls, call `devguard check exec` before forwarding
- [x] For cage mode: additionally set up `LD_PRELOAD` or `seccomp` filter on the agent process if PID is known
- [x] Remove the claim "commands checked before execution" from cage output — it is only partially true for MCP-intercepted tools
- [x] Add integration test: spawn a bash command through each adapter's tool channel, verify it hits the check

### DG-10 🔴 Git hooks use hardcoded path to `devguard` binary — breaks after `cargo build`
**File:** `commands/cage.rs:186–187`

```rust
let devguard_bin = std::env::current_exe()
    .unwrap_or_else(|_| PathBuf::from("devguard"));
```

The pre-commit and pre-push hooks are written with the absolute path to the binary
**at the time `devguard cage start` was run**. This is typically
`/home/user/Projects/.../target/debug/devguard`. After `cargo build --release` or
after the developer installs a new version, the path changes and the hook silently
fails (exits 0 = commit allowed) because the binary is not found.

```bash
# Hook contains:
DG="/home/umesh/Projects/connector-private/target/debug/devguard"
# After: cargo build --release
# Binary moves to: target/release/devguard
# Hook: silently passes ALL commits ← security gap
```

- [x] Generate hooks that call `devguard` by name only (must be on `PATH`), not by absolute path
- [x] Add a `--path` override for orgs that want a pinned path
- [x] In hook script: add `if ! command -v devguard &> /dev/null; then echo "[DevGuard] WARNING: devguard not on PATH — hook disabled"; exit 0; fi`
- [x] Document in README: `devguard` must be on PATH for git hooks to work
- [x] Add `devguard cage status` check: verify the binary path in the installed hooks still resolves

### DG-11 🔴 `devguard connect` enforcement is advisory only — no physical blocking channel
**File:** `commands/connect.rs:183–193`

`devguard connect windsurf` prints:
```
  ✓ File guard:    reads/writes checked against role policy
  ✓ Exec guard:    commands checked against allow/deny lists
```

But tracing the actual code path: `connect()` calls `adapter.connect()` which writes
MCP config and environment variables. The **actual enforcement** only fires when:
1. The AI agent itself calls `devguard check file write <path>` before writing, OR
2. The pre-commit git hook catches it after the write is staged

Neither Windsurf, Cursor, nor Claude Code natively call `devguard check` before every
file operation. The MCP adapter installs DevGuard as an MCP tool — meaning the AI
**may choose** to call it, but is never **forced** to. A sufficiently capable or
adversarial AI simply doesn't invoke the check tool.

```
What actually happens:
  AI agent → writes forbidden file → file written ← no interception
  AI agent → (optionally) calls devguard check → check fires ← only if AI cooperates
  
What the docs imply:
  AI agent → writes forbidden file → DevGuard intercepts → DENY ← NOT TRUE
```

- [x] For Windsurf: the only reliable blocking channel is `.windsurf/hooks.json` (already partially done in `install_windsurf_hooks`) — but this must be verified against actual Windsurf hook execution model
- [x] For Cursor: investigate Cursor's `rules` file — `.cursor/rules` can inject system prompt constraints  
- [x] For Claude Code: investigate `claude_desktop_config.json` hooks or `CLAUDE_BASH_HOOK` env var
- [x] Add `DEVGUARD_ENFORCEMENT_MODE` output that accurately states: `advisory` (MCP tool available), `hooks` (git hooks installed), `cage` (watchdog active), `locked` (all layers active + inotify)
- [x] Never print "✓ File guard: writes blocked" unless a physical blocking channel is confirmed active
- [x] Add `devguard cage status --verify` that probes each enforcement layer by actually attempting a write to a protected path in a tmpdir

### DG-12 🟠 `devguard cage stop` leaves dangling watchdog process if PID file is stale
**File:** `commands/cage.rs:452–467`

```rust
fn stop_fs_watchdog(workspace: &Path) -> Result<()> {
    let pid_file = workspace.join(".devguard/watchdog.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            let _ = std::process::Command::new("kill")
                .arg(pid_str.trim())
                .output();
            let _ = std::process::Command::new("pkill")
                .args(["-f", "devguard.*watchdog"])
                .output();
        }
        let _ = std::fs::remove_file(&pid_file);
    }
    Ok(())  // ← always returns Ok even if watchdog is still running
}
```

Three silent failure paths:
1. PID file exists but PID is stale (reboot, crash) → `kill` returns ESRCH, ignored → `cage.json` deleted → `cage status` says inactive but watchdog may still be running
2. Multiple `devguard cage start` calls → multiple watchdog processes → `kill` kills only one
3. `devguard cage stop` succeeds even when `kill` fails — caller has no indication enforcement is still active

- [x] After `kill`, verify process is dead: `kill -0 <pid>` should return error
- [x] If process still alive after `kill`, escalate to `kill -9`
- [x] If process still alive after `kill -9`, return `Err(...)` — do not silently succeed
- [x] On `cage start`: check for existing watchdog PID and refuse to start a second one (or kill the old one first)
- [x] `cage status` must live-check PID liveness, not just read `cage.json`
- [x] Add watchdog heartbeat: write timestamp to `.devguard/watchdog.heartbeat` every 5s; `cage status` flags as DEAD if heartbeat is > 10s old

---

## Part 9 — Plugin Boundary Definition: TraceTramp vs WitnessCtl

> **This section is the permanent contract.** Any future feature added to either plugin
> must be checked against this boundary first. Overlap = wrong.

### One-line definitions (non-negotiable)

| Plugin | What it is | Subject | Trigger |
|---|---|---|---|
| **TraceTramp** | **AI agent runtime execution control plane** | AI agent ↔ LLM/tool calls | Inline, real-time, every request |
| **WitnessCtl** | **API witness and compliance evidence layer** | Any HTTP API call (REST, webhook, LLM) | Capture session, then seal + export |

---

### TraceTramp owns

TraceTramp sits **inline in the LLM request path**. Every AI agent call passes through it.
It is a **real-time enforcement proxy** — it either lets a call through, transforms it, or blocks it
**before** the response is returned. Its job is governance of the live execution loop.

```
AI agent → [TraceTramp] → LLM / Tool / Function → response back through TraceTramp → AI agent
                ↑
          Enforces here, in real-time
```

| TraceTramp responsibility | Detail |
|---|---|
| **LLM proxy** | Routes OpenAI/Anthropic/Ollama calls, normalises to unified format |
| **Real-time policy enforcement** | ALLOW/BLOCK/REDACT decisions per request, evaluated against tenant policies |
| **Real-time budget enforcement** | Hard-stop when token/cost budget exceeded mid-session |
| **Provider routing + fallback** | Smart routing to cheapest/fastest provider, fallback chain on failure |
| **Tool execution governance** | Intercepts `POST /v1/tools/invoke` — checks tool authorization before execution |
| **Workflow / pipeline orchestration** | Multi-step agentic pipelines with HITL pause points |
| **Tenant / API key management** | Which agent belongs to which tenant, what key they carry |
| **Live execution traces** | `GET /trace/:trace_id` — the running log of what an agent did in this session |
| **Streaming** | SSE-forwarded LLM streams, chunked tracing |

**TraceTramp does NOT own:** tamper-evident receipt chains, sealed proof bundles, compliance report
generation, schema drift detection, call replay, or cross-session API behaviour analysis.

---

### WitnessCtl owns

WitnessCtl sits **beside** API calls, not inline in an agent's execution loop.
You open a **session**, point your API client at WitnessCtl's proxy URL, and it captures
every call. At the end you **seal** the session — producing a cryptographically verified,
tamper-evident evidence bundle that an auditor can verify independently.

```
API client → [WitnessCtl proxy] → any upstream (OpenAI, internal API, webhook)
                     ↑
             Captures + seals. Not for real-time blocking.
```

| WitnessCtl responsibility | Detail |
|---|---|
| **Universal API capture** | Any HTTP call — REST, LLM, webhook, internal service — not just AI agents |
| **HMAC-SHA256 chained receipt chain** | Every call gets a receipt linked to the previous (tamper-evident) |
| **Session seal + proof bundle** | `seal_session()` generates a cryptographic proof of the entire session |
| **Proof verification** | `connectorctl witness verify <bundle>` — independently verifiable |
| **Call replay** | Reproduce any past call from sealed evidence |
| **Schema drift detection** | Auto-infers request/response schema, alerts when API behaviour changes |
| **Compliance report export** | SOC2 / HIPAA / GDPR / EU AI Act report per session, signed |
| **PII field classification** | Per-field PII/PHI detection and tagging in captured payloads |
| **Cross-session analysis** | `witness diff` — behaviour comparison between two sealed sessions |
| **Proxy modes** | Proxy URL, SDK shim (Python/Node), webhook ingest |

**WitnessCtl does NOT own:** real-time blocking, LLM provider routing, budget enforcement,
tool invocation governance, agentic workflow execution, tenant/API-key management.

---

### Where they share Connector OS — but do NOT share code

Both plugins call the same Connector OS primitives but **independently** and for different purposes:

| Connector OS primitive | TraceTramp uses it for | WitnessCtl uses it for |
|---|---|---|
| `POST /aapi/policies/evaluate` | Real-time ALLOW/BLOCK per agent call | Admission verdict before forwarding captured call |
| `POST /aapi/capabilities/issue` | Issue UCAN token per request for the live agent | Issue capability for a capture session identity |
| `POST /aapi/budgets/consume` | Deduct tokens from live agent's budget | Attribute API call cost to a witness session |
| `POST /aapi/interactions` | Write live execution trace event | Write captured call event to audit chain |
| `GET /monitor/trust` | Pre-call trust check for the calling agent | — (WitnessCtl does not need trust scoring) |
| `POST /api/v1/agents` | Register a governed agent | Register a witness session as an agent identity |

They are **separate processes on separate ports**. They never call each other.
They share no database tables. They share no Rust code.

---

### Current Violations in TraceTramp (must be removed)

These capabilities currently exist in TraceTramp's code but **belong exclusively to WitnessCtl**:

| Feature in TraceTramp | Where | Should be |
|---|---|---|
| HMAC receipt chain generation | `connector.rs` `issue_receipt()` (broken) | WitnessCtl `receipt.rs` only |
| Tamper-evident audit trail | `trace_events` table | WitnessCtl `witness_receipts` + WitnessCtl `witness_captures` |
| Compliance report export (TT-12) | Not yet built but planned in TraceTramp | WitnessCtl `compliance.rs` + `export.rs` |
| PII detection persistence (TT-13) | Planned in TraceTramp | WitnessCtl `pii.rs` + `witness_captures.pii_in_request` |
| Schema/behaviour tracking | Not yet built but implied in TraceTramp | WitnessCtl `schema.rs` only |

**Fix for all of the above:** TraceTramp should call `POST /api/v1/witnessctl/ingest` (webhook mode)
for any call it wants added to a compliance evidence chain. TraceTramp stays in the runtime control
path. WitnessCtl handles the evidence and compliance report generation.

```
AI agent → [TraceTramp] (ALLOW/BLOCK in real-time)
                  ↓ async, non-blocking
           POST /api/v1/witnessctl/ingest
                  ↓
           [WitnessCtl] (receipt chain, PII tagging, schema tracking, compliance evidence)
```

---

### Rule going forward

> **TraceTramp = runtime control plane = synchronous, in the request path, per-call decisions.**
> **WitnessCtl = evidence plane = asynchronous, out of the request path, per-session sealing.**
>
> If a feature involves: receipts, proofs, compliance reports, sealed evidence, schema drift,
> call replay, or cross-session analysis → **it belongs in WitnessCtl**.
>
> If a feature involves: blocking, routing, budgets, tool authorization, workflow execution,
> live streaming, provider fallback → **it belongs in TraceTramp**.

---

## Part 10 — WitnessCtl: Bugs and Missing Features (from code audit)

WitnessCtl has the best code quality of the three plugins but has significant gaps
before it is production-ready as a compliance and evidence tool.

### CISO/Court-grade target (locked)
WitnessCtl compliance is now held to a hard bar: evidence must be defensible for
current CISO review and court scrutiny, not just dashboard-level reporting.

- [x] Add readiness gate endpoint: `GET /api/v1/compliance/:session_id/readiness`
- [x] Gate output must explicitly report court-defensibility booleans and a CISO readiness score
- [x] Gate must fail if core evidence conditions are missing (seal, chain head, receipts, framework pass, firewall coverage)
- [x] Add dual-attestor requirement mode for high-risk frameworks (SOC2/HIPAA/PCI)
- [x] Add cryptographic timestamp authority (TSA/RFC3161) hook for sealed bundles
- [x] Add immutable WORM export target option (S3 Object Lock / append-only store)
- [x] Require signed attestor identity binding mode (JWT subject + optional issuer/audience checks)
- [x] Readiness gate must consume attestor identity subjects (not just display names) for dual-attestor compliance
- [x] Add remote immutable export sink hook (`WITNESSCTL_WORM_HTTP_URL`) with no-overwrite semantics
- [x] Add strict RFC3161 verification mode (`openssl ts -verify` with trusted CA file) for TSA tokens
- [x] Make TSA verification policy framework-aware (HIPAA/SOC2/PCI sessions require valid TSA at seal + readiness gate)

### WitnessCtl state snapshot (2026-04-27)
Code audit against `plugins/witnessctl` shows WitnessCtl is functional but not yet at
"real caged proxy + autonomous custody + advanced operator UX" standard.

- [x] Real reverse proxy path exists: `/witness/*path` with `any(proxy_forward)` and upstream forwarding in `proxy.rs`
- [x] Capture pipeline exists (`capture.rs`): admission, firewall, PII tagging, schema drift, receipt chain writes
- [x] Cryptographic custody base exists: HMAC receipt chaining in `receipt.rs` and verify endpoint in `routes.rs`
- [x] Compliance engine exists for 4 frameworks (HIPAA, SOC2, GDPR, EU AI Act) in `compliance.rs`
- [x] Export engine exists for JSON/CSV only in `export.rs` (no PDF yet)
- [x] WitnessCtl currently observes API traffic sessions; Connector OS "self-observation" exists only as partial proof/compliance fetch calls, not full autonomous continuous monitoring
- [x] No cage-grade proxy hardening profile (strict fail modes, persistent watchdog, controlled egress, VPS route profile) is implemented yet
- [x] No Wireshark-grade live TUI/wizard for WitnessCtl operations yet
- [x] No human-in-the-loop interaction UI for compliance review/attestation/escalation yet
- [x] No 7-framework report suite with signed PDF outputs yet

### WC-01 🔴 `CONNECTOR_BASE_URL` defaults to `http://localhost:9091` — same self-loop bug as TraceTramp
**File:** `config.rs:27`

```rust
connector_base_url: std::env::var("CONNECTOR_BASE_URL")
    .unwrap_or_else(|_| "http://localhost:9091".to_string()),
```

Port 9091 is TraceTramp's data plane. When `CONNECTOR_BASE_URL` is unset, WitnessCtl
calls TraceTramp for `firewall_inspect`, `policy_check`, `register_agent`, `generate_proof`
— all silently hitting the wrong service. Calls fail or produce wrong results with no
warning in logs.

- [x] Change default to `http://localhost:9735` (Connector OS canonical port per CONNECTOR_CAGE_NODE_AND_PLUGINS.md)
- [x] If `CONNECTOR_BASE_URL` is not set, log a startup warning: `WitnessCtl: CONNECTOR_BASE_URL not configured — compliance enforcement disabled`
- [x] Add `connector_available: bool` to health check response

### WC-02 🔴 `WITNESSCTL_HMAC_SECRET` defaults to `"change-me-in-production"` — all receipts trivially forgeable
**File:** `config.rs:31`

```rust
hmac_secret: std::env::var("WITNESSCTL_HMAC_SECRET")
    .unwrap_or_else(|_| "change-me-in-production".to_string()),
```

The entire tamper-evidence guarantee depends on HMAC-SHA256 chain integrity. With a
known, published default secret, anyone can recompute valid HMACs for arbitrary payloads,
making the chain worthless as legal evidence. The verify endpoint (`GET /verify/:id`)
will return `chain_valid: true` for forged chains.

- [x] **On startup, if `WITNESSCTL_HMAC_SECRET == "change-me-in-production"`, refuse to start** (not a warning, an error)
- [x] Add to `Config::from_env()`: `if self.hmac_secret == "change-me-in-production" { return Err(...) }`
- [x] Add `witnessctl setup` command that generates a cryptographically random secret and writes `.env`
- [x] Document: HMAC secret must be stored in a secrets manager (Vault, AWS Secrets Manager) — never in `.env` for production

### WC-03 🔴 Export only supports `json` and `csv` — no PDF, no signed document, no auditor-usable output
**File:** `export.rs:175`

```rust
_ => Err(AppError::BadRequest(format!(
    "Unsupported export format: {}. Use 'json' or 'csv'.", format
))),
```

Compliance auditors for SOC2 Type II, HIPAA, GDPR, and EU AI Act require a **PDF
report with a cover page, executive summary, control mapping, evidence tables, and
digital signature or hash**. JSON/CSV are raw data dumps — not auditor-deliverables.

- [x] Add PDF export using `printpdf` or `wkhtmltopdf` (call as subprocess)
- [x] PDF must contain: cover page (org name, session ID, period, date), executive summary (overall score, framework verdicts), per-framework control table with pass/fail/evidence, appendix with receipt chain head HMAC
- [x] PDF footer: `Generated by WitnessCtl — HMAC chain: <head>` for tamper evidence linkage
- [x] Add `markdown` export format — renders to clean compliance-report.md (use the existing template at `templates/compliance_report.md`)
- [x] Add `?format=pdf`, `?format=markdown` to `GET /export/:id`
- [x] PDF file signed with SHA256 hash appended to filename: `witness-<id>-<hash8>.pdf`

### WC-04 🟠 Compliance evaluation logic has false positives — `denied > 0` passes HIPAA access control
**File:** `compliance.rs:193–196`

```rust
// 164.312(a)(1) Access Control
controls.push(ControlResult {
    name: "hipaa.164.312.a1.access_control".to_string(),
    passed: denied > 0 || total == 0,  // ← WRONG
    message: if denied > 0 || total == 0 {
        "Access controls enforced — denied calls present".to_string()
    } else {
        "No denied calls — access control enforcement unclear".to_string()
    },
});
```

HIPAA 164.312(a)(1) is NOT "did we deny any calls". It requires a documented access
control policy with user/role assignments. Having zero denials on a legitimate system is
normal. This logic fails systems with zero denied calls even if they are perfectly
compliant. The same pattern repeats across SOC2 CC6.2, CC8.1, and EU AI Act Art.14.

- [x] Separate "enforcement active" (policy exists, HMAC chain present) from "enforcement fired" (events happened to be denied)
- [x] Access control pass condition: `policy != null && receipt_count > 0` (policy is configured and audit trail exists)
- [x] Authentication pass condition: check for session token presence, not `blocked > 0`
- [x] Add `manual_attestations` table: auditor can mark controls as manually verified with evidence link
- [x] Add `compliance.manual_attest(session_id, control_name, evidence_url, attestor)` API
- [x] Rewrite all 4 framework evaluators with correct control semantics

### WC-05 🟠 `capture.ingest()` calls `firewall_inspect` synchronously — adds Connector latency to every proxied call
**File:** `capture.rs:36`

```rust
let fw = self.connector.firewall_inspect(&agent_pid, req_body, &format!("witness/{}", session_id)).await?;
```

Every call proxied through WitnessCtl blocks on a `POST /api/v1/guard/firewall` call to
Connector OS. If Connector is slow or unavailable this adds 50–500ms to every API call,
or makes WitnessCtl return a 500 to the upstream client.

- [x] Make firewall inspection async/non-blocking: spawn task, capture result to DB after the proxied call completes
- [x] Add `firewall_timeout_ms` config with default 200ms; if exceeded, proceed with `verdict: timeout` and log
- [x] If Connector is unavailable: degrade gracefully — capture the call, mark `firewall_checked: false`, continue
- [x] Add `WITNESSCTL_STRICT_MODE=true` env var for environments that need hard failure if firewall is unavailable

### WC-06 🟠 Proxy mode (`/witness/*path`) only accepts `POST` — `GET`, `PUT`, `DELETE` calls not capturable
**File:** `routes.rs:55`

```rust
.route("/witness/*path", post(proxy_forward))
```

The proxy only registers a `post()` handler. Any API the user wants to witness that uses
`GET`, `PUT`, `PATCH`, or `DELETE` will receive a 405 Method Not Allowed and be
uncaptured.

- [x] Register all methods: `.route("/witness/*path", any(proxy_forward))`
- [x] In `proxy_forward`, read method from `X-Original-Method` header OR from Axum's `method` extractor
- [x] Add method to the `RawRequest` struct and pass to `CaptureEngine`
- [x] Test: GET /witness/openai.com/v1/models is captured correctly

### WC-07 🟠 `seal_session()` calls `connector.generate_proof()` — fails with 404 when Connector is down, blocking seal
**File:** `session.rs:143`

```rust
let proof = self.connector.generate_proof(&pid, "witnessctl_session").await?;
```

If Connector is not running, `generate_proof` returns `Err(...)` and the entire seal
operation fails — leaving the session in a permanently unsealed state with no way to
recover. The session's local HMAC chain is already complete and valid.

- [x] Make `generate_proof` optional: `let proof = self.connector.generate_proof(...).await.ok()`
- [x] If proof is `None`, seal proceeds with `connector_proof: null` and a warning in the seal response
- [x] Add `force_seal: true` parameter to `POST /sessions/:id/seal` that bypasses Connector proof
- [x] Sessions sealed without Connector proof are marked `proof_source: local_only`

### WC-08 🟠 No `witnessctl` CLI — all operations require raw curl/HTTP calls
WitnessCtl only exposes an HTTP API. There is no CLI. Operators cannot:
- Open a session from the terminal
- See live call stream
- Seal a session
- Export a report
- Verify a proof bundle

without writing curl commands.

- [x] Add `witnessctl` binary (separate from the server) with subcommands:
  - [x] `witnessctl session open --upstream https://api.openai.com --role analyst` → prints proxy URL
  - [x] `witnessctl session list` → tabular view of active sessions
  - [x] `witnessctl session seal <id>` → seals and prints proof ID
  - [x] `witnessctl export <id> --format pdf` → downloads report
  - [x] `witnessctl verify <id>` → verifies chain and exits 0/1
  - [x] `witnessctl watch <id>` → live streaming call view (htop-style, ratatui)

### WC-09 🟡 PII scan `field_path` is always `"text"` — no field-level attribution
**File:** `pii.rs:49, 58, 68...`

```rust
hits.push(PiiDetection {
    pii_type: PiiType::Email,
    field_path: "text".to_string(),  // ← always "text" for scan_text()
```

`scan_text()` loses the JSON path context. When an auditor asks "which field contained
the SSN?" the answer is always "text" instead of e.g. `messages[2].content.patient_ssn`.

- [x] Always use `scan_json()` for JSON payloads, `scan_text()` only for plain strings
- [x] In `capture.ingest()`: attempt `serde_json::from_str(req_body)` first; if valid JSON use `scan_json()`
- [x] `witness_pii_hits` table must store `field_path` from `scan_json()`, not hardcoded `"text"`
- [x] In PII report: show `field_path` per hit for compliance evidence

### WC-10 🟡 `redis_url` is loaded in config but Redis is never used — dead config
**File:** `config.rs:24–25`

```rust
redis_url: std::env::var("WITNESSCTL_REDIS_URL")
    .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
```

`redis_url` is read from env but there is no Redis connection, no Redis pool, no usage
anywhere in the codebase. This creates two problems: operators spin up Redis thinking
it's needed, and actual Redis-dependent features (rate limiting, live streaming pub/sub
for `watch` mode) are never implemented.

- [ ] Either: remove `redis_url` from config until Redis is actually used
- [x] Or: document it as "reserved for live stream pub/sub in WC-08's `watch` mode"
- [ ] If removing: add back only when implementing `witnessctl watch` live stream

### WC-11 🟡 No `witnessctl doctor` or setup command — operators start blind
No way to verify that WitnessCtl's database, Connector, and HMAC secret are correctly
configured before starting capture sessions.

- [x] Add `witnessctl doctor` that checks: DB connection, migrations applied, Connector reachability, HMAC secret is non-default, Redis (if configured)
- [x] Add `witnessctl setup` interactive wizard: generates HMAC secret, writes `.env`, runs migrations, optionally opens first session
- [x] Add startup health check: if DB migrations not applied, refuse to start with a clear message

### WC-12 🟡 No multi-tenant isolation — all sessions share one DB without tenant scoping
`witness_sessions`, `witness_captures`, `witness_receipts` have no `tenant_id` column.
Any API key can read any session. In a SaaS deployment this is a data isolation violation.

- [x] Add `tenant_id UUID NOT NULL` to all tables (migration)
- [x] `session_token` lookup must be scoped to `tenant_id`
- [x] All list endpoints filter by `tenant_id` derived from API key
- [x] `GET /sessions` without auth returns 401

### WC-13 🔴 No cage-grade always-on proxy profile (route lock + VPS path control + strict operation)
WitnessCtl proxy works, but there is no "caged proxy" mode that operators can trust for
24x7 production custody. We need an enforceable route profile where all observed traffic
must traverse WitnessCtl's proxy path with controlled upstream routing.

- [x] Add `witnessctl cage start` mode: enforce proxy route lock (session-scoped token + upstream allowlist + method/path constraints)
- [x] Add VPS route profile support (`--route-profile vps-prod`) with explicit upstream host pinning and TLS constraints
- [x] Add strict mode policy: fail-closed on route mismatch / upstream mismatch / missing witness session token
- [x] Add persistent watchdog heartbeat for proxy service health and route-lock integrity (24x7 status)
- [x] Add explicit "observed via witness route" attestation in every capture record

### WC-14 🔴 No autonomous distributed custody fabric (local + replicated + proof-linked)
Current recording is local DB centric. We need distributed autonomous custody that can
replicate evidence across nodes while preserving chain integrity.

- [x] Add autonomous custody worker: append-only event replication queue for witness captures/receipts
- [x] Add replicated chain checkpoints (local head + remote head) with divergence detection
- [x] Add custody quorum status endpoint: local_only / replicated_partial / replicated_quorum
- [x] Add signed periodic custody checkpoints (hash bundle) for long-running sessions
- [x] Add replay-safe idempotency keys for distributed ingest/capture writes

### WC-15 🔴 No advanced WitnessCtl operator UI (Wireshark-style wizard + live stream)
WitnessCtl needs same UX standard as DevGuard/TraceTramp but with deeper packet/evidence
inspection and workflow controls.

- [x] Add `witnessctl tui` full-screen `ratatui` cockpit (live call stream, filters, inspector)
- [x] Build setup wizard screens: caged proxy profile, route policy, custody replication, framework selection, report profile
- [x] Add Wireshark-style event table: time, method, host, path, verdict, pii, drift, latency, receipt seq, chain head
- [x] Add deep inspector pane (raw request/response, schema diff, PII hit fields, compliance control links)
- [x] Add keyboard workflows (`/` filter, `Enter` inspect, `s` seal, `r` report, `h` HITL review)

- [x] WitnessCtl server startup auto-launches detached TUI window by default (can be disabled with `WITNESSCTL_TUI_AUTO_DISABLE=true`)

### WC-16 🔴 No human interaction workflow for compliance adjudication/attestation
WitnessCtl needs explicit human interaction surfaces for escalations, manual attestations,
control overrides, and sign-off custody.

- [x] Add HITL queue for compliance exceptions (pending review, approved, rejected, escalated)
- [x] Add API + UI for manual control attestation with evidence link and approver identity
- [x] Add escalation chain config (primary/secondary reviewers) with timeout actions
- [x] Add signed reviewer action log linked into receipt chain
- [x] Add reviewer dashboard in TUI with pending items and SLA countdown

### WC-17 🔴 No 7-framework signed PDF report suite (auditor-deliverable outputs missing)
WitnessCtl currently supports 4-framework evaluation and JSON/CSV export, but product
requirement is multiple real auditor PDFs with cryptographic custody linkage.

- [x] Expand framework set to 7 report profiles (HIPAA, SOC2, GDPR, EU AI Act, ISO 27001, PCI DSS, NIST 800-53)
- [x] Add `GET /api/v1/report/:session_id?framework=<name>&format=pdf` route with framework-specific templates
- [x] Add signed PDF generation pipeline with embedded chain head and document hash
- [x] Add report wizard in TUI (select framework, date window, tenant scope, sign/export)
- [x] Add multi-report batch export and custody manifest (`.json`) for auditor handoff

### WC-18 🔴 WitnessCtl unlock path is not hard-locked to Connector access model
WitnessCtl must be powered by Connector-only identity/entitlement, same as DevGuard and
TraceTramp. No parallel auth model is allowed.

- [x] All WitnessCtl entrypoints (API, CLI, TUI) must validate Connector access key/session via Connector capabilities endpoint before activation
- [x] Support shared unlock contract: Connector access key OR dev bypass mode (`<=3` active agents)
- [x] Enforce license cap for `>3` agents through Connector license status check (fail closed if unavailable)
- [x] Add explicit startup mode output: `unlock_mode=dev_bypass|connector_key`, `requested_agents`, `max_agents`
- [x] Wire this into `witnessctl start`/`witnessctl tui` wizard so behavior matches DevGuard/TraceTramp unlock UX
- [x] Reject local-only fallback auth paths when Connector validation fails (except dev bypass within limit)

---

## Part 11 — TraceTramp: UX, Wizard, and Easy-to-Use Features

### TT-UX-01 🔴 No `tracetramp setup` wizard — onboarding requires 8 manual steps
Setting up TraceTramp requires: create DB, run migrations, set 8+ env vars, register
tenant, register provider, create API key via curl, start service, verify health. Any
mistake causes a silent failure.

- [ ] Add `tracetramp setup` interactive wizard:
  1. Detect existing DB or prompt for DB URL
  2. Run migrations automatically
  3. Generate and show data plane + management plane ports
  4. Prompt: "Create demo tenant? [Y/n]" → inserts tenant + API key
  5. Prompt: "Register LLM provider? OpenAI/Anthropic/Ollama/skip"
  6. Write `.env` file with all values
  7. Start service in foreground with live health check
  8. Print: `TraceTramp ready. Data plane: http://localhost:9741 | Management: http://localhost:9742`
- [ ] `tracetramp setup --non-interactive` for CI/Docker: reads from env, writes state

### TT-UX-02 🔴 No `tracetramp tui` — no live operational visibility
Already listed as TT-11. The TUI must show **raw IO**, not just metadata.

- [ ] `tracetramp tui` launches full-terminal dashboard using `ratatui`
- [ ] **Panel 1 — Call Stream** (top-left): scrolling table `TIME | TENANT | MODEL | DECISION | LATENCY | COST` with `▶` on each row
- [ ] **Panel 2 — IO Inspector** (top-right, activated on `Enter`): shows the SELECTED call in full:
  - `ACTION` — what type: `llm_call`, `tool_call`, `execute_command`, `file_read`, `file_write`
  - `LOCATION` — workspace path where the action occurred (e.g. `/home/user/project/src/auth/`)
  - `TENANT` / `DECISION` / `LATENCY` / `COST`
  - **RAW INPUT section**: exact JSON string sent to LLM or exact command string sent to shell
  - **RAW OUTPUT section**: exact JSON string returned by LLM or exact stdout/stderr from command
  - **POLICY VERDICT section**: which rule matched (or NONE), PII type + field path if detected, BLOCK/ALLOW/REDACT + reason, redacted form of the input if REDACT
- [ ] `[r]` toggle between pretty-printed JSON and raw single-line string in IO inspector
- [ ] **Panel 3 — Stats bar** (bottom): Calls / Blocked / Redacted / PII hits / Budget burn progress bar / total cost
- [ ] **Panel 4 — Provider Health** (bottom-right): each provider with ● GREEN/YELLOW/RED + last latency
- [ ] Keybindings: `q` quit, `↑↓` select call, `Enter` expand IO, `r` raw/pretty toggle, `f` filter by tenant, `p` pause stream, `e` export visible to CSV, `/` search trace_id or content
- [ ] For BLOCKED calls: IO inspector shows raw input that was blocked + TraceTramp's 403 response body + exact PII location (field path + char offset)
- [ ] For EXECUTE calls: IO inspector shows `Type`, `Location`, `Command`, `Exit code`, `Duration`, `STDOUT` (raw), `STDERR` (raw), `POST-EXEC SCAN` (PII + secret scan of output)
- [ ] Refresh: 1s default, `r` to force refresh

### TT-UX-03 🟠 No `tracetramp doctor` — no way to diagnose broken setup
No diagnostic command exists. When TraceTramp silently fails (wrong DB URL, no providers,
expired API key, Connector down) the only clue is in raw logs.

- [ ] Add `tracetramp doctor` that checks and prints per-item pass/fail:
  - Database connection + migration version
  - Redis connection
  - Connector OS reachability (`TRACETRAMP_CONNECTOR_BASE_URL`)
  - At least one LLM provider registered and reachable
  - At least one tenant + API key exists
  - Data plane port not already bound
  - Management plane port not already bound
- [ ] Exit code 0 = all OK, 1 = warnings, 2 = critical failures
- [ ] `tracetramp doctor --fix` auto-fixes what it can (re-run migrations, register demo tenant)

### TT-UX-04 🟠 Management plane requires raw JWT — no CLI login or token management
Operators must manually generate a JWT with the right claims, tenant ID, and expiry to
call any management API. There is no `tracetramp login` or `tracetramp token` command.

- [ ] Add `tracetramp login --url http://localhost:9742 --secret <jwt-secret>` → stores token in `~/.tracetramp/token`
- [ ] All management CLI commands read token from `~/.tracetramp/token` automatically
- [ ] Add `tracetramp token show` and `tracetramp token refresh`
- [ ] Token expiry warning: if token expires in < 1h, warn on every CLI call

### TT-UX-05 🟠 No `tracetramp explain` command — when a call is blocked, user has no easy way to see why
Blocked calls appear in DB `trace_events` but there is no user-facing command to look
up a trace ID and explain the decision in plain English.

- [ ] Add `tracetramp explain <trace_id>` that prints:
  ```
  Trace: abc123
  Status: BLOCKED
  Reason: PII detected — SSN found in messages[1].content
  Policy: tenant:demo / policy:default
  Actor:  agent:analyst
  Time:   2026-04-26 09:00:00 UTC
  Cost:   $0.00 (blocked before LLM call)
  ```
- [ ] Add `tracetramp history [--tenant X] [--last N]` — tabular view of recent calls

---

## Part 12 — PDF Report Generation and Real Compliance Deliverables

All three plugins need to produce reports that a human auditor or legal team can
actually use — not just JSON dumps.

### RPT-01 🔴 No PDF generation anywhere in the stack — compliance reports are JSON only
WitnessCtl returns JSON from `GET /compliance/:id/evaluate`. TraceTramp has no report
at all. Neither produces a document an auditor would accept.

- [ ] Add `printpdf` crate to WitnessCtl `Cargo.toml`
- [ ] Implement `ExportEngine::export_pdf(session_id)`:
  - **Page 1 — Cover**: Organization name (from session role), Session ID, Report period (created_at → sealed_at), Generated by (WitnessCtl version), HMAC chain head (for tamper evidence), "CONFIDENTIAL" watermark
  - **Page 2 — Executive Summary**: Overall compliance score gauge (0–100), Framework verdicts table (HIPAA ✓, SOC2 ✗, GDPR ✓, EU AI Act ✓), Key metrics (total calls, blocked calls, PII hits, cost)
  - **Page 3+ — Framework Details**: Per framework: each control with pass/fail, evidence statement, article/section reference
  - **Appendix**: Receipt chain table (seq, event_type, hmac, timestamp)
- [ ] File naming: `compliance-report-<session_id>-<framework>-<date>.pdf`
- [ ] SHA256 hash of PDF appended to `sealed_at` in DB for tamper evidence

### RPT-02 🔴 GDPR Data Subject Report not implemented — required by Art. 15
GDPR Art. 15 gives data subjects the right to receive a copy of their data and an
explanation of how it was processed. No such report exists.

- [ ] Add `GET /api/v1/gdpr/subject-report?email=<email>&session_id=<id>` endpoint
- [ ] Report includes: all PII hits for the subject's email, what fields were found, action taken (blocked/allowed/redacted), timestamps
- [ ] PDF version downloadable
- [ ] Add `GET /api/v1/gdpr/erasure-request` — flags all captures containing subject's email for deletion
- [ ] Deletion must also generate a receipt: `event_type: "gdpr.erasure"` with timestamp and requestor

### RPT-03 🟠 Compliance score (0–100) has no defined SLA threshold — passes/fails mean nothing without a baseline
`overall_score` is computed as average of per-framework scores (0–100) but there is no
concept of a "passing score" threshold. A score of 42 is returned as just a number —
the operator doesn't know if this is acceptable.

- [ ] Add `compliance_thresholds` config: default `{ "hipaa": 90, "soc2": 85, "gdpr": 90, "eu_ai_act": 80 }`
- [ ] `ComplianceReport.overall_passed` should be `score >= threshold` not just `all controls passed`
- [ ] In PDF report: show score gauge with threshold marker (e.g. "Required: 90 | Actual: 72 ← FAIL")
- [ ] Add `GET /api/v1/compliance/thresholds` + `PUT /api/v1/compliance/thresholds` for operator config

### RPT-04 🟠 Export endpoint has no authentication — anyone can download compliance reports
**File:** `routes.rs:53`

```rust
.route("/api/v1/export/:session_id", get(export_session))
```

No authentication middleware. Any HTTP client that knows a session UUID can download
the full evidence bundle including PII detection details. Session UUIDs are not secret
(they're logged, printed in CLI output, stored in DB).

- [x] Add auth middleware to all `/api/v1/*` routes
- [x] Export endpoint: require `Bearer <session_token>` matching the session being exported, OR an admin token
- [x] Rate limit export endpoint: max 10 requests/hour per IP

---

## Part 13 — Production Readiness: Cross-Cutting Gaps

### PROD-01 🔴 None of the three plugins have a working `Dockerfile` or `docker-compose.yml`
DevGuard, TraceTramp, and WitnessCtl all require separate manual setup. There is no
single-command way to run the full stack.

- [ ] Write `docker-compose.cage.yml` (already in sprint plan as INF-03):
  - `connector-os` on port 9735
  - `tracetramp` on ports 9741/9742, depends_on connector-os: service_healthy
  - `witnessctl` on port 7443, depends_on connector-os: service_healthy
  - `postgres` shared (or separate DBs per plugin)
  - `redis` shared
  - All env vars via `.env.example` → `.env`
- [ ] Write `Dockerfile` for each plugin (multi-stage: builder + runtime)
- [ ] `docker compose up` should result in all three plugins healthy within 60s

### PROD-02 🔴 No rate limiting on any endpoint in any plugin — all APIs are open to DoS
TraceTramp data plane, WitnessCtl proxy, and DevGuard connect all accept unlimited
requests. A misbehaving AI agent can exhaust the DB connection pool or billing budget.

- [x] Add `tower_governor` rate limiter to TraceTramp data plane: 100 req/min per API key
- [x] Add rate limiter to WitnessCtl proxy: 1000 req/min per session token
- [x] Add rate limiter to DevGuard status/audit endpoints: 60 req/min per IP
- [x] Return `429 Too Many Requests` with `Retry-After` header

### PROD-03 🔴 `CONNECTOR_API_KEY` is empty string by default in WitnessCtl and TraceTramp
**Files:** `witnessctl/config.rs:29`, `tracetramp` config

```rust
connector_api_key: std::env::var("CONNECTOR_API_KEY")
    .unwrap_or_else(|_| "".to_string()),
```

An empty API key sent as `Authorization: Bearer ` causes Connector OS to reject all
calls with 401, but this is indistinguishable from Connector being down. Plugins
silently degrade without any startup warning that API key is missing.

- [x] On startup: if `CONNECTOR_API_KEY` is empty, log `ERROR: CONNECTOR_API_KEY not set — all Connector calls will fail`
- [x] Add `connector_authenticated: bool` to health check
- [x] `witnessctl doctor` / `tracetramp doctor` must check: API key is non-empty AND a test call to Connector `/health` succeeds with it

### PROD-04 🟠 No structured logging — all logs are plaintext, unqueryable in production
All three plugins use `tracing` with `FmtSubscriber` text format. In production
(EKS, GKE, Docker) operators need JSON logs for CloudWatch/Datadog/Grafana Loki.

- [ ] Add `LOG_FORMAT=json` env var support using `tracing-subscriber::fmt::json()`
- [ ] Structured log fields: `plugin`, `tenant_id`, `session_id`, `trace_id`, `outcome`, `latency_ms`
- [ ] Default to text in dev (`LOG_FORMAT=text`), JSON in prod
- [ ] Ship a Grafana dashboard JSON for each plugin (query by `tenant_id`, `outcome`, `latency`)

### PROD-05 🟠 No Prometheus metrics endpoint in WitnessCtl or TraceTramp
No `GET /metrics` endpoint. No counters for calls, blocks, PII hits, latencies. No way
to set up alerting for "more than N blocks in 5 minutes" or "avg latency > 500ms".

- [ ] Add `metrics-exporter-prometheus` crate to both plugins
- [ ] TraceTramp metrics: `tt_calls_total{tenant,model,verdict}`, `tt_latency_ms{model}`, `tt_pii_hits_total`, `tt_budget_remaining{tenant}`
- [ ] WitnessCtl metrics: `wc_captures_total{session}`, `wc_blocked_total`, `wc_pii_hits_total`, `wc_chain_length{session}`
- [ ] Ship Grafana dashboard JSON

### PROD-06 🟠 No `.env.example` for WitnessCtl — operators don't know what variables to set
TraceTramp has `.env.example`. WitnessCtl has no documented env vars.

- [x] Write `plugins/witnessctl/.env.example` with every variable, its default, and a comment explaining what it does
- [ ] Include in `witnessctl doctor` output: "Missing env vars: X, Y, Z"

### PROD-07 🟡 No migration version check on startup — stale schema causes silent data corruption
All plugins run `sqlx::migrate!()` on startup, which is correct. But if the binary is
newer than the DB schema (e.g. rolled back binary, or two instances running different
versions), columns may be missing and inserts silently fail.

- [x] Add startup check: `SELECT version FROM _sqlx_migrations ORDER BY installed_on DESC LIMIT 1` and compare to expected version embedded in the binary
- [x] If DB is behind: refuse to start, print: `Run migrations: sqlx migrate run`
- [x] If DB is ahead: refuse to start (rolled-back binary against newer schema), print warning

---

## Summary Counts

| Category | Critical 🔴 | High 🟠 | Medium 🟡 | Total |
|---|---|---|---|---|
| TraceTramp Technical | 5 | 3 | 2 | 10 |
| TraceTramp Features | 1 | 3 | 2 | 6 |
| DevGuard Technical (original) | 1 | 2 | 2 | 5 |
| DevGuard Deep Enforcement Bugs | 4 | 1 | 0 | 5 |
| DevGuard Features | 0 | 1 | 1 | 2 |
| Connector OS UX | 2 | 2 | 2 | 6 |
| Business/Product | 2 | 2 | 1 | 5 |
| Infrastructure | 1 | 2 | 1 | 4 |
| **WitnessCtl Bugs** | **3** | **4** | **5** | **12** |
| **TraceTramp UX/Wizard** | **2** | **3** | **0** | **5** |
| **PDF/Compliance Reports** | **2** | **2** | **0** | **4** |
| **Prod Readiness (Cross-cutting)** | **3** | **3** | **1** | **7** |
| **Total** | **26** | **28** | **17** | **71** |

> **26 Critical issues.** The 4 DevGuard enforcement bypass bugs and the 3 WitnessCtl
> security defaults (HMAC secret, self-loop, unauthenticated export) mean neither plugin
> is safe to use in a real project right now.

---

## Recommended Fix Order (Sprint Plan)

### Sprint 0 — Security Holes (must fix before any real project)
*These make plugins actively dangerous — false security guarantees.*

1. `[WC-02]` WitnessCtl: refuse startup with default HMAC secret
2. `[WC-01]` WitnessCtl: fix `CONNECTOR_BASE_URL` default (9091 → 9735)
3. `[PROD-03]` Both plugins: warn loudly on empty `CONNECTOR_API_KEY`
4. `[RPT-04]` WitnessCtl: add auth to all `/api/v1/*` export endpoints
5. `[DG-11]` DevGuard: stop printing "✓ writes blocked" — state real enforcement mode
6. `[DG-10]` DevGuard: fix git hooks binary path — use name on PATH, not absolute
7. `[DG-08]` DevGuard: replace 1s bash polling watchdog with `notify` crate (inotify)
8. `[DG-09]` DevGuard: move exec interception to MCP protocol layer
9. `[DG-12]` DevGuard: fix watchdog stop — verify dead, add heartbeat

### Sprint 1 — Core Bug Fixes (make everything actually work)
10. `[TT-01]` TraceTramp: fix ConnectorClient self-loop
11. `[TT-02]` TraceTramp: fix all wrong Connector OS API URLs
12. `[WC-06]` WitnessCtl: proxy accepts GET/PUT/DELETE (not POST only)
13. `[WC-07]` WitnessCtl: `seal_session` must not fail when Connector is down
14. `[TT-07]` TraceTramp: fix duplicate inserts (ON CONFLICT)
15. `[TT-06]` TraceTramp: stub receipt locally (stop 502s)
16. `[INF-02]` Fix port conflicts across stack

### Sprint 2 — Setup & Doctor (operator can actually use these)
17. `[TT-UX-01]` TraceTramp: `tracetramp setup` wizard
18. `[TT-UX-03]` TraceTramp: `tracetramp doctor`
19. `[TT-UX-04]` TraceTramp: `tracetramp login` / token management
20. `[WC-11]` WitnessCtl: `witnessctl setup` + `witnessctl doctor`
21. `[PROD-06]` WitnessCtl: write `.env.example`
22. `[PROD-01]` All: Dockerfile + `docker-compose.cage.yml`

### Sprint 3 — Real Enforcement (TraceTramp + WitnessCtl)
23. `[TT-04]` TraceTramp: wire DB policies into enforcement
24. `[TT-05]` TraceTramp: wire budget hard stop
25. `[WC-05]` WitnessCtl: make firewall inspection async/non-blocking
26. `[WC-04]` WitnessCtl: rewrite compliance evaluation logic (correct semantics)
27. `[WC-09]` WitnessCtl: fix PII `field_path` to use `scan_json()`
28. `[TT-03]` TraceTramp: begin Connector OS AAPI integration

### Sprint 4 — UX, TUI, and CLI (human-usable interfaces)
29. `[TT-UX-02]` TraceTramp: `tracetramp tui` (ratatui dashboard)
30. `[TT-UX-05]` TraceTramp: `tracetramp explain <trace_id>`
31. `[WC-08]` WitnessCtl: `witnessctl` CLI binary
32. `[OS-01]` Connector OS: `connectorctl watch` (htop-style)
33. `[DG-02]` DevGuard: auto-wire IDE hooks with verified blocking channel

### Sprint 5 — Compliance Reports and PDF
34. `[RPT-01]` WitnessCtl: PDF export with cover page, control tables, signed hash
35. `[RPT-02]` WitnessCtl: GDPR data subject report (Art. 15)
36. `[RPT-03]` WitnessCtl: compliance score thresholds
37. `[WC-12]` WitnessCtl: add `tenant_id` isolation
38. `[OS-02]` Connector OS: `connectorctl compliance report`
39. `[OS-04]` Connector OS: GDPR erasure CLI

### Sprint 6 — Production Hardening
40. `[PROD-02]` Rate limiting: all endpoints (tower_governor)
41. `[PROD-04]` Structured JSON logging (LOG_FORMAT=json)
42. `[PROD-05]` Prometheus metrics + Grafana dashboards
43. `[PROD-07]` Migration version check on startup
44. `[INF-01]` Integration test suite
45. `[INF-04]` sqlx offline mode + compile-time schema checks
46. `[TT-08]` TraceTramp: provider fallback chain
47. `[TT-14]` TraceTramp: SSE streaming support
48. `[BIZ-02]` Real auth (no hardcoded JWT secret)
49. `[BIZ-01]` One-URL onboarding + quickstart README
50. `[WC-10]` WitnessCtl: remove dead redis_url or implement it

---

## Part 14 — Final Goals: What Each Plugin Looks Like When Done

> This is the north star. Every sprint, every bug fix, every feature moves toward this.
> When a new engineer joins, this section tells them what success looks like.

---

## DevGuard — Final State

**One-line**: *DevGuard is a military-grade cage for AI coding agents. When it's on, the agent cannot read, write, execute, or communicate anything you haven't explicitly permitted. Not "should not". Cannot.*

### What you see when you run `devguard connect claude-code --cage`

```
✓ Overlay filesystem mounted     .env, secrets/, infra/prod/ — physically invisible to agent
✓ Network fence active           api.anthropic.com — BLOCKED (only localhost:9735 reachable)
✓ Command jail active            every exec intercepted before running
✓ Git hooks installed            pre-commit, pre-push enforced
✓ Secret vault active            env vars replaced with opaque references
✓ LLM proxy locked               ONLY path to LLM: http://localhost:9735

Session:  dg_a3f8b2c1  |  Tool: claude-code  |  Role: builder
Run: ANTHROPIC_BASE_URL=http://localhost:9735 claude "your task"
```

### Capabilities — what DevGuard delivers at final state

**Cage and Enforcement**
- Overlay filesystem: hidden files are **physically absent** from agent namespace — `ls`, `find`, `cat` return nothing
- Network namespace: direct calls to OpenAI/Anthropic blocked at OS level — only Connector proxy allowed
- Command jail (PTY broker): every shell command intercepted **before** execution — `rm -rf /` blocked at kernel
- Git fence: pre-commit and pre-push hooks block writes to protected branches — cannot be bypassed
- Secret vault: `.env` values replaced with opaque references — agent never sees the actual secret value
- CI/CD gate: `kubectl apply`, Terraform, GitHub Actions — held for human approval before execution

**Policy and Roles**
- `devguard.yaml` defines roles (builder, reviewer, auditor), file visibility, exec allowlists, branch rules, budget caps
- Role-based access: same agent gets different permissions on different tasks
- Policy fingerprinting: SHA-256 of compiled rules attached to every decision — policy drift detected mid-session
- Auto-approve safe patterns (test files, docs) — no noise for obvious safe actions

**Approval Workflow**
- High-risk actions (auth code, migrations, infra, secrets) pause and wait for human approval
- `devguard approvals list` — tabular view: action, file, risk level, requester, age
- `devguard approvals approve <id>` — action lands on disk / executes
- `devguard approvals reject <id> --reason "..."` — action discarded with reason recorded
- Approval timeout + escalation: after N minutes unreviewed → escalates to senior reviewer
- All approvals recorded in tamper-evident audit chain via Connector OS

**Memory and Continuity**
- Repo memory: architecture patterns, module map, conventions — persisted across sessions
- Session memory: current task, recent edits, scoped intent — bounded, evicted when stale
- Decision memory: why past actions were allowed/blocked — prevents contradictory decisions in long sessions
- Context pack: DevGuard assembles a governed context window for the LLM — no sensitive data leaks in

**Observability**
- `devguard status` — live: files read/written, commands run/blocked, secrets redacted, LLM calls, tokens, cost
- `devguard trace` — full timeline of every action this session
- `devguard explain <action_id>` — plain-English explanation: "This was blocked because src/auth/ is in the protected zone for role:builder"
- `devguard prove <session_id>` — cryptographic proof bundle from Connector OS (HMAC chain)

**Tool Support (14 tools)**
- **Level 1 (full cage)**: Claude Code, Kiro, Aider — LLM calls go through proxy, tool_use intercepted
- **Level 2 (strong)**: Cursor, Windsurf — MCP tools governed, workspace policy enforced
- **Level 3 (extension)**: Continue, Cline, Roo Code, Copilot Workspace — MCP-based governance
- **Level 4 (proxy only)**: GitHub Copilot, Zed, Gemini Code Assist — LLM traffic audited
- Auto-detection: `devguard doctor` finds installed tools and shows enforcement level for each

**Human Management ("easy to manage if something goes wrong")**
- `devguard cage stop` — immediately terminates all enforcement layers, restores real FS view
- `devguard cage status` — live heartbeat: is the cage actually running? PID liveness check
- `devguard disconnect` — clean teardown: unmounts overlay, removes network rules, uninstalls git hooks
- `devguard doctor` — full diagnostic: Connector OS reachable? Tools detected? Cage active? Policy valid?
- Emergency: `devguard cage stop --force` — kills everything unconditionally, resets to baseline

---

## TraceTramp — Final State

**One-line**: *TraceTramp is the runtime control plane for AI agents. Every LLM call, tool invocation, and function execution your agent makes goes through TraceTramp — which decides in real time: allow, block, redact, or pause for human review.*

### What you see when TraceTramp is running (`tracetramp tui`)

Three panels. Left = call list. Right = IO detail for selected call. Bottom = stats bar.
Press `Enter` on any call to load its full IO into the right panel.

**Default view — call list + selected call IO:**
```
 TraceTramp  [tenant: all]  [paused: no]  2026-04-26 09:23:11
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  CALLS                              │  SELECTED  trace_id: abc123
 ────────────────────────────────   │ ─────────────────────────────────────────
  09:23:01  acme  gpt-4o   ALLOW    │  action    llm_call
  09:23:02  acme  gpt-4o   BLOCK    │  tenant    acme-corp
  09:23:05  demo  claude   ALLOW    │  model     gpt-4o
▶ 09:23:07  acme  gpt-4o   REDACT   │  decision  REDACT        cost  $0.004
  09:23:09  acme  gpt-4o   ALLOW    │  latency   312ms         at    09:23:07
  09:23:11  demo  claude   ALLOW    │
                                     │  INPUT  ───────────────────────────────
                                     │  "messages": [
                                     │    { "role": "user",
                                     │      "content": "My email is john@acme.com,
                                     │                  help me write a welcome
                                     │                  message for our users"  }
                                     │  ]
                                     │
                                     │  OUTPUT  ──────────────────────────────
                                     │  "content": "Here is a welcome message:
                                     │   Dear [EMAIL REDACTED], welcome to Acme!
                                     │   We are glad to have you on board..."
                                     │
                                     │  VERDICT  ─────────────────────────────
                                     │  rule      pii.email
                                     │  matched   messages[0].content
                                     │  action    REDACT  (forwarded, email masked)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  calls 1,204   blocked 23   redacted 4   pii 7   budget ████░░░░ 45%  $4.51
  OpenAI ● 312ms   Anthropic ● 891ms   Ollama ◑ 2,100ms
  [↑↓] select   [Enter] pin   [r] raw   [f] filter   [p] pause   [/] search   [q] quit
```

**BLOCK example** — right panel shows what was stopped before it reached the LLM:
```
  SELECTED  trace_id: def456
 ─────────────────────────────────────────────
  action    llm_call
  decision  BLOCK         cost   $0.000
  latency   2ms  (stopped before LLM call)

  INPUT  ─────────────────────────────────────
  "messages": [
    { "role": "user",
      "content": "My SSN is 123-45-6789, help
                  me fill this healthcare form" }
  ]

  OUTPUT  ────────────────────────────────────
  { "error": "blocked",
    "reason": "PII: SSN detected",
    "trace_id": "def456" }

  VERDICT  ───────────────────────────────────
  rule      pii.ssn
  matched   messages[0].content  chars 10–21
  action    BLOCK  (LLM never called)
```

**EXECUTE example** — right panel shows command, location, and raw stdout/stderr:
```
  SELECTED  trace_id: ghi789
 ─────────────────────────────────────────────
  action    execute_command
  decision  ALLOW
  location  /home/user/project/
  command   cargo test --lib auth
  exit      0     duration  4,312ms

  STDOUT  ────────────────────────────────────
  running 3 tests
  test auth::test_valid_token ... ok
  test auth::test_expired_token ... ok
  test auth::test_invalid_signature ... ok
  test result: ok. 3 passed; 0 failed

  STDERR  ────────────────────────────────────
  (none)

  POST-EXEC SCAN  ────────────────────────────
  pii in output     CLEAN
  secrets in output CLEAN
  cage allowlist    PASS
```

### Capabilities — what TraceTramp delivers at final state

**LLM Proxy (inline, real-time)**
- Single proxy endpoint for all providers: OpenAI, Anthropic, Ollama, Cohere, Mistral, and any OpenAI-compat
- Every request evaluated against tenant policy **before** it reaches the LLM — ALLOW / BLOCK / REDACT
- Streaming support: SSE forwarded chunk-by-chunk, tracing happens per-chunk
- Smart routing: cheapest provider that meets latency SLA
- Fallback chain: if OpenAI times out → retry Anthropic → retry Ollama → return graceful error (not 500)
- Response normalization: unified format regardless of upstream provider

**Real-time Policy Enforcement**
- PII detection in request/response: email, SSN, credit card, phone, AWS key, password — BLOCK or REDACT in-flight
- Jailbreak detection: prompt injection, role confusion, system prompt leakage — blocked before LLM call
- Custom tenant policies: operator writes rules like "never send messages mentioning competitor names"
- Policy loaded from DB (not hardcoded): operator adds rules via management API, enforced immediately
- Per-action result: ALLOW / BLOCK / REDACT with reason recorded in trace

**Budget Enforcement (hard stop)**
- Per-tenant, per-agent, per-day/week/month token and cost budgets
- Enforcement is **hard**: when budget is exhausted, calls are rejected with `402 Budget Exhausted`
- Budget burn rate shown live in TUI
- Warning at 80% threshold, email/webhook alert configurable
- Budget reset on schedule (daily/weekly/monthly)

**Tool and Function Governance**
- `POST /v1/tools/invoke` — checks tool authorization before execution
- `POST /v1/functions/execute` — governed Python/JS function execution with output scanning
- Tool allowlist/blocklist per tenant — agent cannot invoke unapproved tools
- Output of tool execution scanned for PII and secrets before returning to agent

**Multi-tenant Management**
- Each tenant has isolated API key, budget, policy set, and trace history
- Management plane (`tracetramp login` → JWT): create tenants, register providers, set policies
- `tracetramp tui --tenant acme-corp` — filtered view per tenant
- Tenant activity report: `tracetramp report --tenant X --last 30d`

**Tracing and Explainability**
- Every call gets a `trace_id` — immutable, written on first contact
- `tracetramp explain <trace_id>` — plain-English: what happened, why blocked, which PII type, which rule
- `tracetramp history --tenant X --last 50` — recent call table with decisions
- `GET /trace/:id` — full execution record: input (hashed), output (hashed), policy result, cost, latency
- Trace forwarded async to WitnessCtl via `POST /witnessctl/ingest` for compliance evidence (non-blocking)

**Setup and Operations**
- `tracetramp setup` — interactive wizard: DB → migrations → tenant → provider → API key → write `.env` → start
- `tracetramp doctor` — diagnoses every dependency with pass/fail and `--fix` for automatable repairs
- `tracetramp login` → stores JWT token locally, all CLI commands use it automatically
- `docker compose up` — full stack running in < 60s
- Prometheus metrics at `/metrics`, Grafana dashboard shipped

---

## WitnessCtl — Final State

**One-line**: *WitnessCtl is the compliance evidence layer and Connector OS health monitor. Every API call gets a tamper-evident receipt. Every Connector OS internal action is traced for correctness. At any time you can download a signed PDF compliance report an auditor can independently verify.*

---

### WitnessCtl TUI — `witnessctl tui`

Three panels. Left = session list. Right = live call stream for selected session + Connector OS health. Bottom = report actions.

```
 WitnessCtl  [tenant: acme-corp]  2026-04-26 09:23:11
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  SESSIONS                           │  SESSION  wst_a3f8b2c1  [ACTIVE]
 ──────────────────────────────────  │ ──────────────────────────────────────────
  wst_a3f8  ACTIVE   844 calls  ▶    │  upstream   https://api.openai.com
  wst_b1c2  SEALED   312 calls       │  role       analyst
  wst_c3d4  SEALED   91  calls       │  started    09:00:14    cost  $2.34
  wst_e5f6  ACTIVE   7   calls  ▶    │  calls      844   blocked  12   pii  3
                                     │
                                     │  LIVE CAPTURES  ───────────────────────
                                     │  09:23:01  POST  /v1/chat/completions  ALLOW
                                     │  09:23:02  POST  /v1/chat/completions  BLOCK  ← SSN
                                     │  09:23:07  POST  /v1/embeddings        ALLOW
                                     │  09:23:09  GET   /v1/models            ALLOW
                                     │  09:23:11  POST  /v1/chat/completions  REDACT ← email
                                     │
                                     │  CONNECTOR OS HEALTH  ──────────────────
                                     │  agent lifecycle     ● OK   last: 09:23:09
                                     │  audit chain         ● OK   receipts: 844
                                     │  policy engine       ● OK   rules: 7 active
                                     │  guard pipeline      ● OK   last check: 2ms
                                     │  memory kernel       ● OK   packets: 1,203
                                     │  trust scoring       ◑ WARN score drift +4pts
                                     │  billing             ● OK   $2.34 attributed
                                     │  admission control   ● OK   12 denied correct

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  REPORTS:  [h] HIPAA   [s] SOC2   [g] GDPR   [e] EU AI Act   [f] FedRAMP
            [Enter] generate + download PDF   [v] verify chain   [q] quit
  retention: 7-day auto  |  sealed sessions kept 30 days  |  export: witnessctl export
```

Pressing `Enter` on a call in LIVE CAPTURES expands its IO inline (same as TraceTramp — INPUT / OUTPUT / VERDICT).

Pressing `Enter` on a session row while in SESSIONS panel seals it and starts report generation.

---

### Connector OS Internal Stability and Security Trace

WitnessCtl monitors every Connector OS primitive before it trusts any audit data coming from it. Before generating a compliance report, WitnessCtl runs a **pre-audit integrity check** — verifying that Connector OS itself behaved correctly during the session.

**What WitnessCtl checks on Connector OS per session before generating any report:**

```
witnessctl pre-audit check  wst_a3f8b2c1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Connector OS integrity trace
 ──────────────────────────────────────────────────────────
  audit chain continuity    PASS   no gaps in receipt seq 1–844
  HMAC chain integrity      PASS   all 844 receipts verify
  policy evaluated per call PASS   844/844 calls had policy result
  denied calls recorded     PASS   12 denials in chain, 12 in DB
  PII detections consistent PASS   3 PII hits match receipt events
  billing attribution       PASS   $2.34 matches 844 call costs
  trust score stability     WARN   score changed +4pts mid-session
                                   event: agent re-registered at 09:12:44
  admission control timing  PASS   all decisions before forwarding
  memory write integrity    PASS   all memory packets have receipts
  schema baseline present   PASS   3 endpoints fingerprinted
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Result: 9/10 checks PASS  |  1 WARNING (non-blocking)
  Safe to generate compliance report: YES
```

If any check FAILS (e.g. gap in receipt sequence, denial not recorded, policy skipped for a call), the report is **blocked** and the failure is included as a finding in the evidence bundle.

**Connector OS checks WitnessCtl runs:**
- Audit chain has no sequence gaps (no calls missing a receipt)
- Every HMAC in the chain re-computes correctly
- Every call that was denied appears in both the receipt chain AND the captures table
- Policy evaluation result was recorded for every captured call (not just some)
- PII hit count in DB matches PII receipt events in the chain
- Billing cost sum matches the sum of per-call attributed costs
- Trust score changes during session are explained by a logged event (re-registration, policy change)
- All admission control decisions are timestamped BEFORE the call was forwarded (not after)
- Memory writes during session have corresponding audit receipts

---

### Report Retention Policy

```
Active sessions:      kept until sealed  (no expiry)
Sealed sessions:      kept 30 days       (full captures + receipts accessible)
PDF reports:          kept 7 days        (auto-generated on seal)
After 30 days:        captures purged,   receipt chain head + proof bundle kept forever
```

**Commands:**
```
witnessctl export <id> --format pdf              # download any time while in retention
witnessctl export <id> --format pdf --week 2     # week 2 of a 30-day session
witnessctl reports list                          # show all reports with expiry dates
witnessctl reports download <report_id>          # download by report ID
witnessctl archive <session_id> --path ./audit/  # user saves full bundle before 30-day purge
```

After 30 days the user is responsible for archiving. `witnessctl` warns at day 25 and day 28:
```
WARNING: session wst_a3f8b2c1 purges in 5 days.
Run: witnessctl archive wst_a3f8b2c1 --path ./audit/ to save permanently.
```

---

### PDF Report Layouts — one per framework

#### PDF Layout 1 — HIPAA

```
╔══════════════════════════════════════════════════════════════════════╗
║          HIPAA COMPLIANCE EVIDENCE REPORT                           ║
║          Health Insurance Portability and Accountability Act        ║
╠══════════════════════════════════════════════════════════════════════╣
║  Organization:  Acme Corp                                           ║
║  Session ID:    wst_a3f8b2c1                                        ║
║  Period:        2026-04-19 → 2026-04-26  (7 days)                  ║
║  Generated:     2026-04-26 09:23:01 UTC                             ║
║  HMAC chain:    a3f8b2c1d4e5f678  (independently verifiable)        ║
║  File hash:     SHA256: 9f3a...   CONFIDENTIAL                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL SCORE:  94 / 100   PASS  (threshold: 90)                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  EXECUTIVE SUMMARY                                                  ║
║  Total API calls:    844     Blocked (access denied):  12           ║
║  PHI fields detected: 3      PHI fields redacted:       3           ║
║  Audit receipts:     847     Chain integrity:          VALID        ║
║  Cost attributed:    $2.34                                          ║
╠══════════════════════════════════════════════════════════════════════╣
║  CONTROL RESULTS                                                    ║
║                                                                     ║
║  §164.312(a)(1)  Access Control               PASS                 ║
║    Evidence: Session token required. 12 calls denied before        ║
║    forwarding. Policy active for 100% of calls.                    ║
║                                                                     ║
║  §164.312(b)     Audit Controls               PASS                 ║
║    Evidence: 847 HMAC-chained receipts. No sequence gaps.          ║
║    Chain head: a3f8b2c1... independently verifiable.               ║
║                                                                     ║
║  §164.312(c)(1)  Integrity                    PASS                 ║
║    Evidence: All receipts re-verify. No tamper detected.           ║
║                                                                     ║
║  §164.312(d)     Authentication               PASS                 ║
║    Evidence: Session opened with authenticated identity.            ║
║    Role: analyst. Token validated on every capture.                ║
║                                                                     ║
║  §164.312(e)(2)  PHI Transmission Security    PASS                 ║
║    Evidence: 3 PHI fields detected (patient_id, dob, mrn).        ║
║    All 3 redacted before forwarding. 0 PHI transmitted raw.        ║
║                                                                     ║
║  §164.308(a)(1)  Risk Analysis                WARN                 ║
║    Evidence: Trust score shifted +4pts at 09:12:44.                ║
║    Event: agent re-registration. Manual review recommended.        ║
╠══════════════════════════════════════════════════════════════════════╣
║  PHI FIELD DETECTIONS                                               ║
║  Call            Field path                    Action               ║
║  abc123  09:04   messages[0].content.patient_id  REDACTED          ║
║  def456  09:11   messages[1].content.dob          REDACTED          ║
║  ghi789  09:19   request.body.mrn                 REDACTED          ║
╠══════════════════════════════════════════════════════════════════════╣
║  RECEIPT CHAIN TAIL (last 5 of 847)                                 ║
║  seq   event_type        hmac (first 16)    timestamp               ║
║  843   capture           a1b2c3d4e5f67890   09:23:01                ║
║  844   capture.blocked   b2c3d4e5f6789012   09:23:02                ║
║  845   capture           c3d4e5f678901234   09:23:07                ║
║  846   capture           d4e5f67890123456   09:23:09                ║
║  847   session.sealed    e5f6789012345678   09:23:11                ║
╠══════════════════════════════════════════════════════════════════════╣
║  Verify this report independently:                                  ║
║  witnessctl verify soe1-sha256-a3f8b2c1d4e5f678                    ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

#### PDF Layout 2 — SOC2 Type II

```
╔══════════════════════════════════════════════════════════════════════╗
║          SOC 2 TYPE II COMPLIANCE EVIDENCE REPORT                   ║
║          Service Organization Controls — Security & Availability    ║
╠══════════════════════════════════════════════════════════════════════╣
║  Organization:  Acme Corp                                           ║
║  Session ID:    wst_a3f8b2c1                                        ║
║  Period:        2026-04-19 → 2026-04-26  (7 days)                  ║
║  Generated:     2026-04-26 09:23:01 UTC                             ║
║  HMAC chain:    a3f8b2c1d4e5f678        File hash: SHA256: 9f3a...  ║
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL SCORE:  88 / 100   PASS  (threshold: 85)                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  EXECUTIVE SUMMARY                                                  ║
║  Total calls: 844   Access denials: 12   Schema drifts detected: 1  ║
║  Change events logged: 1   Availability uptime: 100%               ║
╠══════════════════════════════════════════════════════════════════════╣
║  TRUST SERVICES CRITERIA                                            ║
║                                                                     ║
║  CC6.1  Logical Access Controls              PASS                  ║
║    Evidence: API key + session token required. 12 denials.         ║
║    Role-based access enforced for all 844 calls.                   ║
║                                                                     ║
║  CC6.2  Authentication Mechanisms            PASS                  ║
║    Evidence: Session identity verified at open. Token non-null     ║
║    for all 844 calls. No anonymous access observed.                ║
║                                                                     ║
║  CC7.1  Change Detection                     WARN                  ║
║    Evidence: Schema drift detected on api.openai.com/v1/chat       ║
║    Field `reasoning` appeared in response at 09:14:22.             ║
║    Unexpected field — review vendor changelog.                     ║
║                                                                     ║
║  CC7.2  Incident Identification              PASS                  ║
║    Evidence: 12 blocked calls recorded with reason and actor.      ║
║    3 PII hits flagged and redacted. All events in audit chain.     ║
║                                                                     ║
║  CC8.1  Change Management                    PASS                  ║
║    Evidence: 1 schema drift event logged with timestamp, field     ║
║    diff, and baseline fingerprint. Auditable change record.        ║
║                                                                     ║
║  A1.1   Availability Monitoring              PASS                  ║
║    Evidence: 0 upstream timeouts. 100% of calls received a        ║
║    response or explicit block. No silent failures.                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  SCHEMA DRIFT EVENTS                                                ║
║  endpoint              field         change        detected          ║
║  /v1/chat/completions  reasoning     ADDED         09:14:22          ║
╠══════════════════════════════════════════════════════════════════════╣
║  Verify:  witnessctl verify soe1-sha256-a3f8b2c1d4e5f678           ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

#### PDF Layout 3 — GDPR

```
╔══════════════════════════════════════════════════════════════════════╗
║          GDPR DATA PROTECTION COMPLIANCE REPORT                     ║
║          General Data Protection Regulation (EU) 2016/679           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Organization:  Acme Corp         Data Controller: Acme Corp        ║
║  Session ID:    wst_a3f8b2c1      DPO Contact:  dpo@acme.com        ║
║  Period:        2026-04-19 → 2026-04-26                             ║
║  Generated:     2026-04-26 09:23:01 UTC    SHA256: 9f3a...          ║
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL SCORE:  91 / 100   PASS  (threshold: 90)                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  EXECUTIVE SUMMARY                                                  ║
║  Data subjects detected:  2  (by email address)                    ║
║  Personal data fields:    3  (email ×2, phone ×1)                  ║
║  Fields redacted:         3  (100% redaction rate)                 ║
║  Erasure requests:        0                                         ║
║  Lawful basis on record:  YES  (session role: analyst)             ║
╠══════════════════════════════════════════════════════════════════════╣
║  ARTICLE CONTROLS                                                   ║
║                                                                     ║
║  Art. 5(1)(f)  Integrity & Confidentiality        PASS             ║
║    Evidence: HMAC-SHA256 chain. 0 tamper events. All PII           ║
║    redacted before transmission. Chain verifies independently.     ║
║                                                                     ║
║  Art. 13/14   Transparency — Processing Info      PASS             ║
║    Evidence: Session role, upstream, and purpose recorded at       ║
║    open. All captures attributed to a named identity.              ║
║                                                                     ║
║  Art. 25      Data Protection by Design           PASS             ║
║    Evidence: PII scan runs on every request before forwarding.     ║
║    Redaction applied automatically. No opt-out required.           ║
║                                                                     ║
║  Art. 17      Right to Erasure                    PASS             ║
║    Evidence: Erasure endpoint available. 0 requests this period.   ║
║    All captures flaggable by email address.                        ║
║                                                                     ║
║  Art. 35      Data Protection Impact Assessment   WARN             ║
║    Evidence: No DPIA document linked to this session.              ║
║    Recommend: attach DPIA ref via witnessctl attest.               ║
╠══════════════════════════════════════════════════════════════════════╣
║  PERSONAL DATA DETECTED                                             ║
║  call    field path                  type   action    subject       ║
║  abc123  messages[0].content.email   EMAIL  REDACTED  john@acme.com ║
║  def456  messages[1].content.email   EMAIL  REDACTED  sue@corp.com  ║
║  ghi789  request.body.phone          PHONE  REDACTED  +1-555-...    ║
╠══════════════════════════════════════════════════════════════════════╣
║  DATA SUBJECT RIGHTS LOG                                            ║
║  No erasure or access requests received this period.               ║
╠══════════════════════════════════════════════════════════════════════╣
║  Verify:  witnessctl verify soe1-sha256-a3f8b2c1d4e5f678           ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

#### PDF Layout 4 — EU AI Act

```
╔══════════════════════════════════════════════════════════════════════╗
║          EU AI ACT COMPLIANCE EVIDENCE REPORT                       ║
║          Regulation (EU) 2024/1689 — High-Risk AI Systems           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Organization:  Acme Corp                                           ║
║  AI System:     LLM API Gateway (gpt-4o via TraceTramp)            ║
║  Risk Class:    HIGH  (automated decision + personal data)          ║
║  Session ID:    wst_a3f8b2c1                                        ║
║  Period:        2026-04-19 → 2026-04-26                             ║
║  Generated:     2026-04-26 09:23:01 UTC    SHA256: 9f3a...          ║
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL SCORE:  72 / 100   FAIL  (threshold: 80)                  ║
║  !! Art. 14 Human Oversight gap — see below                        ║
╠══════════════════════════════════════════════════════════════════════╣
║  EXECUTIVE SUMMARY                                                  ║
║  AI calls logged:       844    Automated decisions:  844            ║
║  Human review events:   0      Override events:      0             ║
║  Traceability:          FULL   Model used:     gpt-4o              ║
║  Risk classification:   DONE   Technical docs: MISSING             ║
╠══════════════════════════════════════════════════════════════════════╣
║  ARTICLE CONTROLS                                                   ║
║                                                                     ║
║  Art. 9   Risk Management System              PASS                 ║
║    Evidence: Policy engine active. 12 denials. PII detection       ║
║    on 100% of calls. Risk rules documented in devguard.yaml.       ║
║                                                                     ║
║  Art. 10  Data Governance                     PASS                 ║
║    Evidence: 3 PII fields detected and redacted. Schema            ║
║    baseline maintained. Drift flagged on 1 endpoint.               ║
║                                                                     ║
║  Art. 12  Record Keeping & Traceability       PASS                 ║
║    Evidence: 844 calls with full input hash, output hash,          ║
║    policy verdict, model ID, latency, cost. HMAC chain valid.      ║
║                                                                     ║
║  Art. 13  Transparency                        PASS                 ║
║    Evidence: Session identity disclosed. Model name logged.        ║
║    All decisions traceable to named policy rule.                   ║
║                                                                     ║
║  Art. 14  Human Oversight                     FAIL  ← critical     ║
║    Evidence: 0 human review events in 844 AI decisions.            ║
║    No human-in-the-loop checkpoints configured.                    ║
║    Remediation: configure approval gates in devguard.yaml          ║
║    for high-risk actions. At least 1 HITL checkpoint required.     ║
║                                                                     ║
║  Art. 15  Accuracy & Robustness               PASS                 ║
║    Evidence: 0 upstream failures. Provider fallback not            ║
║    triggered. All 844 calls completed or explicitly blocked.       ║
╠══════════════════════════════════════════════════════════════════════╣
║  REQUIRED ACTIONS TO ACHIEVE PASS                                   ║
║  1. Configure at least 1 human approval gate (Art. 14)             ║
║  2. Link technical documentation via: witnessctl attest            ║
║     --control eu_ai_act.art15 --doc-url https://...               ║
╠══════════════════════════════════════════════════════════════════════╣
║  Verify:  witnessctl verify soe1-sha256-a3f8b2c1d4e5f678           ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

#### PDF Layout 5 — FedRAMP

```
╔══════════════════════════════════════════════════════════════════════╗
║          FedRAMP COMPLIANCE EVIDENCE REPORT                         ║
║          Federal Risk and Authorization Management Program          ║
║          NIST SP 800-53 Rev 5 Control Baseline                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Organization:   Acme Corp                                          ║
║  System Name:    AI API Gateway                                     ║
║  Impact Level:   MODERATE  (preliminary — verify with your AO)     ║
║  Session ID:     wst_a3f8b2c1                                       ║
║  Period:         2026-04-19 → 2026-04-26                            ║
║  Generated:      2026-04-26 09:23:01 UTC    SHA256: 9f3a...         ║
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL SCORE:  81 / 100   PASS (preliminary)                     ║
║  NOTE: FedRAMP authorization requires ATO from a 3PAO.             ║
║  This report provides evidence artifacts only.                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  NIST 800-53 CONTROL EVIDENCE                                       ║
║                                                                     ║
║  AU-2   Audit Events                          PASS                 ║
║    Evidence: 847 audit events. Every API call, block, and          ║
║    PII hit recorded with timestamp, actor, and outcome.            ║
║                                                                     ║
║  AU-9   Protection of Audit Information       PASS                 ║
║    Evidence: HMAC-SHA256 chained receipts. Receipts immutable      ║
║    after write. Chain verifies independently without DB access.    ║
║                                                                     ║
║  AC-2   Account Management                    PASS                 ║
║    Evidence: Session opened with named identity. Role assigned.    ║
║    Token validated per call. 12 access denials recorded.           ║
║                                                                     ║
║  AC-17  Remote Access                         PASS                 ║
║    Evidence: All API calls proxied through WitnessCtl.             ║
║    No direct upstream access observed outside proxy.               ║
║                                                                     ║
║  SI-3   Malicious Code Protection             PASS                 ║
║    Evidence: PII + secret scan on every request/response.          ║
║    3 PII hits redacted. 0 secret exfiltration events.             ║
║                                                                     ║
║  SI-7   Software & Information Integrity      PASS                 ║
║    Evidence: HMAC chain re-verified. 0 tamper events.              ║
║    Schema baseline maintained on 3 endpoints.                      ║
║                                                                     ║
║  CM-3   Configuration Change Control         WARN                 ║
║    Evidence: 1 schema drift event (new field `reasoning`).         ║
║    Change recorded with timestamp and diff. Review required.       ║
║                                                                     ║
║  IA-5   Authenticator Management             PASS                 ║
║    Evidence: No credentials observed in captured payloads.         ║
║    0 API keys or passwords detected in transit.                    ║
╠══════════════════════════════════════════════════════════════════════╣
║  EVIDENCE ARTIFACTS                                                 ║
║  Receipt chain:  847 records  (downloadable JSON)                  ║
║  Proof bundle:   soe1-sha256-a3f8b2c1d4e5f678                      ║
║  Capture log:    844 calls with request/response hashes            ║
║  PII report:     3 detections with field paths                     ║
║  Schema history: 3 endpoints with baseline + drift log             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Verify:  witnessctl verify soe1-sha256-a3f8b2c1d4e5f678           ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

### What you see on seal (`witnessctl session seal <id>`)

```
Session sealed: wst_a3f8b2c1
────────────────────────────────────────────────────
Pre-audit check:   9/10 PASS  1 WARN  0 FAIL
HMAC chain:        847 receipts  VALID ✓
────────────────────────────────────────────────────
HIPAA:     PASS  94/100    SOC2:      PASS  88/100
GDPR:      PASS  91/100    EU AI Act:  FAIL  72/100
FedRAMP:   PASS  81/100
────────────────────────────────────────────────────
Reports saved (7-day retention):
  compliance-report-a3f8-hipaa-2026-04-26.pdf     SHA256: 9f3a...
  compliance-report-a3f8-soc2-2026-04-26.pdf      SHA256: 1a2b...
  compliance-report-a3f8-gdpr-2026-04-26.pdf      SHA256: 3c4d...
  compliance-report-a3f8-euaiact-2026-04-26.pdf   SHA256: 5e6f...
  compliance-report-a3f8-fedramp-2026-04-26.pdf   SHA256: 7a8b...
────────────────────────────────────────────────────
Download:  witnessctl export wst_a3f8b2c1 --format pdf --framework hipaa
Verify:    witnessctl verify soe1-sha256-a3f8b2c1d4e5f678
Archive:   witnessctl archive wst_a3f8b2c1 --path ./audit/
Retention: purges in 30 days (2026-05-26). Archive before then.
```

---

### Capabilities — what WitnessCtl delivers at final state

**Universal API Capture**
- Proxy mode: `API_BASE_URL=http://localhost:7443/witness/<upstream>` — zero client change
- SDK shim: `WitnessSession(upstream=...)` — drop-in Python/Node replacement
- Webhook ingest: `POST /api/v1/ingest` — external systems push call records
- Captures ALL HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Not limited to AI agents: any REST API, any service, any upstream

**Connector OS Internal Stability Monitoring**
- Before every compliance report: runs full pre-audit integrity check on Connector OS
- Verifies: receipt chain continuity, HMAC re-computation, denial count consistency, policy coverage, billing attribution, trust score stability, admission control ordering
- Report is blocked if Connector OS has integrity failures — failure included as finding
- `CONNECTOR OS HEALTH` panel in TUI: live per-service status (agent lifecycle, audit chain, policy engine, guard pipeline, memory kernel, trust scoring, billing, admission control)

**Tamper-Evident Receipt Chain**
- Every captured call: HMAC-SHA256 chained to previous receipt
- Independently verifiable without DB access: `witnessctl verify <id>` → 0 = valid, 1 = tampered
- Chain head HMAC printed in every export

**Compliance Reports — 5 frameworks**
- HIPAA §164.312 — PHI detection, access control, audit controls, integrity, transmission security
- SOC2 Type II CC6/CC7/CC8/A1 — access, change detection, availability, incident identification
- GDPR Art.5/13/14/17/25/35 — data protection by design, transparency, erasure, DPIA
- EU AI Act Art.9/10/12/13/14/15 — risk management, traceability, human oversight
- FedRAMP NIST 800-53 — AU-2, AU-9, AC-2, AC-17, SI-3, SI-7, CM-3, IA-5

**PDF Reports**
- One PDF per framework per sealed session
- Cover page, executive summary, per-control pass/fail with evidence, PII/drift/chain appendix
- SHA256 hash in filename — tamper-evident filename
- Each framework has its own distinct layout (legal citations match the framework)
- Downloadable any time within 30-day retention window
- `witnessctl export <id> --format pdf --framework hipaa`

**Retention**
- PDFs available for 7 days by default after seal
- Full session (captures + receipts) kept 30 days
- Receipt chain head + proof bundle kept forever
- Warning at day 25 and day 28 to archive
- `witnessctl archive <id> --path ./audit/` saves full bundle permanently

**PII and PHI Detection (field-level)**
- Email, phone, SSN, credit card, AWS keys, passwords, HIPAA PHI field names
- Field-level attribution: exact JSON path (`messages[0].content.patient_id`)
- GDPR data subject report by email address, downloadable as PDF
- GDPR erasure request generates `gdpr.erasure` receipt in chain

**Schema Drift Detection**
- Auto-infers schema per `host + path + method` on first capture
- Every subsequent call compared — added/removed/changed fields flagged
- `witnessctl diff <session_a> <session_b>` — cross-session behaviour comparison
- SOC2 CC7.1 and FedRAMP CM-3: drift = automatic change management control flag

**Operations and CLI**
- `witnessctl tui` — live 3-panel dashboard with Connector OS health panel
- `witnessctl session open/list/seal` — full session lifecycle
- `witnessctl export <id> --format pdf --framework <name>` — download specific report
- `witnessctl reports list` — all reports with expiry dates
- `witnessctl archive <id> --path ./` — save full bundle before purge
- `witnessctl verify <id>` — chain integrity check, exits 0/1
- `witnessctl watch <id>` — live scrolling capture stream
- `witnessctl doctor` — full dependency + configuration check
- `witnessctl setup` — interactive wizard

**Multi-tenant and Security**
- All data scoped to `tenant_id` — no cross-tenant reads
- Session tokens required — no anonymous access
- HMAC secret: refuses startup if default value
- Connector API key: warns loudly if empty
- Rate-limited export: 10 downloads/hour per IP

---

### WitnessCtl Notification System — Hold, Done, and Check Acknowledgement

WitnessCtl does not just silently record. When something is wrong, held, or completed it
**notifies actively**. And for every notification it tracks whether a human actually looked
at it — without knowing who, just that someone did.

---

#### Three notification states

**HOLD** — WitnessCtl is blocking something and waiting
```
[HOLD]  wst_a3f8  09:23:02
  Capture blocked before forwarding.
  Reason: SSN detected in request body (messages[0].content chars 10-21)
  Upstream call NOT sent. Waiting.

  To release:  witnessctl hold release <hold_id>
  To discard:  witnessctl hold discard <hold_id> --reason "..."
  To inspect:  witnessctl hold show <hold_id>
```
HOLD fires when:
- A call is blocked by policy and `WITNESSCTL_HOLD_ON_BLOCK=true` (call is frozen, not discarded)
- Pre-audit integrity check fails (report generation paused — session held open)
- Connector OS health check returns FAIL during an active session
- HMAC chain break detected mid-session (all further captures suspended)
- Session approaching 30-day purge with no archive (hold = warning, not blocking)

**DONE** — WitnessCtl completed an operation that needs attention
```
[DONE]  wst_a3f8  09:23:11
  Session sealed. 5 compliance PDFs generated.
  HIPAA: PASS 94   SOC2: PASS 88   GDPR: PASS 91
  EU AI Act: FAIL 72  ← requires action
  FedRAMP: PASS 81

  Reports expire: 2026-05-03 (7 days)
  Archive before: 2026-05-26 (30 days)
  Check: witnessctl ack <notification_id>
```
DONE fires when:
- Session sealed + all PDFs generated
- Pre-audit integrity check completes (pass or warn)
- GDPR erasure request processed
- Schema drift detected on a monitored endpoint
- A report is approaching its 7-day expiry (fires at day 5 and day 7)
- Session approaching 30-day data purge (fires at day 25 and day 28)

**ALERT** — something is wrong that requires human action
```
[ALERT] wst_a3f8  09:23:07
  Connector OS integrity failure detected.
  Check: audit chain has gap at receipt seq 412.
  Expected seq 412, found seq 413. Receipt 412 missing.

  Session capture SUSPENDED. No new receipts will be issued
  until this is resolved or session is force-sealed.

  Investigate: witnessctl pre-audit check wst_a3f8
  Force seal:  witnessctl session seal wst_a3f8 --force
  Check:       witnessctl ack <notification_id>
```
ALERT fires when:
- Receipt chain gap detected (missing sequence number)
- HMAC re-verification fails for any receipt
- Denied call count in DB does not match chain events
- Connector OS returns 5xx on health check for > 60s
- EU AI Act or HIPAA score falls below threshold on seal
- Billing cost sum mismatch between DB and chain attribution

---

#### Notification delivery

Notifications go to every channel configured:

```
# .env / witnessctl setup
WITNESSCTL_NOTIFY_TERMINAL=true       # prints to witnessctl tui alert panel
WITNESSCTL_NOTIFY_WEBHOOK=https://... # POST JSON payload to Slack/Teams/custom
WITNESSCTL_NOTIFY_EMAIL=ops@acme.com  # SMTP (optional)
WITNESSCTL_NOTIFY_FILE=./witness.log  # append to log file
```

In the TUI, notifications appear as a persistent alert bar below the stats line:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
! HOLD  wst_a3f8  SSN blocked — upstream call waiting  [Space] inspect  [r] release
! DONE  wst_b1c2  Session sealed — EU AI Act FAIL 72   [Space] inspect  [a] ack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

#### Check Acknowledgement — "did anyone look at this?"

Every notification has an `ack` (acknowledgement) state. WitnessCtl does not know **who**
checked — it only knows **if** someone checked, **when**, and from **which IP/session token**.

```
witnessctl ack <notification_id>
```

```
Acknowledged: notif_x9y2z3
  type:     DONE / EU AI Act FAIL
  session:  wst_a3f8b2c1
  ack time: 2026-04-26 09:45:00 UTC
  acked by: session_token: wst_tok_... (identity not stored)
  from IP:  10.0.0.4  (internal network)
```

WitnessCtl stores:
- `acked: true/false`
- `acked_at: timestamp`
- `acked_from: IP address` (not the user identity — privacy-preserving)
- `acked_by_token_hash: SHA256(session_token)` — proves a valid token was used, not who held it

**Unacknowledged notifications escalate:**
```
0–15 min   unacked  →  stays in TUI alert bar + webhook
15–30 min  unacked  →  re-sends webhook with [REMINDER] prefix
30+ min    unacked  →  fires ALERT to all channels: "Notification unacknowledged 30+ min"
```

`witnessctl notifications list` shows the ack state of everything:
```
 NOTIFICATIONS  wst_a3f8b2c1
 ────────────────────────────────────────────────────────────────
 notif_a1  DONE   09:23:11  Session sealed        ACKED  09:45:00
 notif_b2  ALERT  09:14:22  Schema drift detected UNACKED  ← 31min ago
 notif_c3  HOLD   09:23:02  SSN block held        RELEASED 09:25:10
 ────────────────────────────────────────────────────────────────
 1 UNACKED alert — escalation sent at 09:44:22
```

Every `ack` event is recorded as a receipt in the HMAC chain:
```
event_type:  notification.acknowledged
notification_id: notif_a1
acked_at:    2026-04-26 09:45:00 UTC
token_hash:  sha256:ab12cd34...
```
This means the audit trail proves whether a human reacted to every compliance failure —
auditors can see "EU AI Act FAIL was generated at 09:23 and acknowledged at 09:45" in the
PDF appendix.

---

#### Implementation requirements (issues to add)

- [ ] **WC-NOTIF-01** Add `witness_notifications` table: `id, session_id, type (HOLD/DONE/ALERT), message, created_at, acked, acked_at, acked_from_ip, acked_token_hash`
- [ ] **WC-NOTIF-02** Emit HOLD notification on: policy block (if hold mode), chain gap, Connector OS FAIL
- [ ] **WC-NOTIF-03** Emit DONE notification on: session seal, pre-audit complete, report generated, expiry approaching
- [ ] **WC-NOTIF-04** Emit ALERT notification on: HMAC failure, chain gap, EU AI Act / HIPAA score below threshold
- [ ] **WC-NOTIF-05** `POST /api/v1/witnessctl/notifications/:id/ack` — stores ack timestamp + IP + token hash
- [ ] **WC-NOTIF-06** `GET /api/v1/witnessctl/notifications` — list with ack state
- [ ] **WC-NOTIF-07** Webhook delivery: POST JSON payload on every notification + re-POST on 15min unacked
- [ ] **WC-NOTIF-08** TUI alert bar: persistent unacked notifications, `[Space]` expand, `[a]` ack in-place
- [ ] **WC-NOTIF-09** `witnessctl ack <id>` CLI command
- [ ] **WC-NOTIF-10** `witnessctl notifications list` — table with ack state + age
- [ ] **WC-NOTIF-11** Ack event written to HMAC chain as `notification.acknowledged` receipt
- [ ] **WC-NOTIF-12** PDF appendix: include notification + ack log per session (proves human reviewed failures)
- [ ] **WC-NOTIF-13** `WITNESSCTL_HOLD_ON_BLOCK=true` env var — hold mode suspends upstream forwarding on block
- [ ] **WC-NOTIF-14** Escalation: 30+ min unacked → fire ALERT to all channels with `[ESCALATED]` prefix

---

## The Three Together — Full Picture

```
Developer runs: devguard connect claude-code --cage
                        ↓
         Agent runs inside DevGuard cage
         (overlay FS, network fence, command jail)
                        ↓
         Every LLM call → TraceTramp (inline, real-time)
         ├── PII detected in prompt → REDACT before sending
         ├── Budget check → allow or hard-stop
         ├── Policy check → allow or block
         └── After decision → async POST to WitnessCtl /ingest
                        ↓
         WitnessCtl builds tamper-evident receipt chain
         At session end: seal → PDF compliance report
                        ↓
         Auditor receives: witnessctl verify <proof_id>
         → "Chain: VALID | HIPAA: 94/100 | SOC2: 88/100"
```

**DevGuard** = the cage. Agent physically cannot escape.
**TraceTramp** = the controller. Every call judged and recorded in real time.
**WitnessCtl** = the witness. Every call sealed into tamper-evident evidence an auditor can verify independently.

All three report to **Connector OS** as their primitive layer — agents, sessions, audit chains, memory, trust scoring, evidence.

