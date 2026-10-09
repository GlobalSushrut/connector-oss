# Connector OS — Product Capabilities

**TraceTramp** and **WitnessCtl** are two production-grade runtime security layers for AI agents and API traffic. They ship as Rust binaries with embedded Postgres migrations, a live TUI dashboard, and a fully documented REST API. This document describes every capability that buyers receive and the compliance outcomes those capabilities produce.

---

## Table of Contents

1. [TraceTramp — AI Runtime Enforcement Engine](#tracetramp)
2. [WitnessCtl — Verifiable Evidence and Compliance Proxy](#witnessctl)
3. [Joint Capabilities — TraceTramp × WitnessCtl](#joint)
4. [Compliance Frameworks Supported](#frameworks)
5. [Security and Trust Properties](#security)
6. [Deployment and Operations](#deployment)

---

<a name="tracetramp"></a>
## 1. TraceTramp — AI Runtime Enforcement Engine

TraceTramp sits in-line between your AI agents and any LLM or tool endpoint. Every request travels through a multi-stage enforcement pipeline before being proxied upstream. Buyers get deterministic, auditable control over what agents are allowed to do at runtime.

### 1.1 Request Interception and Proxy

| Capability | Detail |
|---|---|
| OpenAI-compatible proxy | `POST /v1/chat/completions`, `/v1/embeddings`, `/v1/messages`, `/v1/responses`, `/v1/unified/completions` |
| Tool and function calls | `POST /v1/tools/invoke`, `/v1/tools/batch`, `/v1/functions/:name/call`, `/v1/functions/:name/async` |
| Workflow engine | Create, run, cancel, resume, and diff multi-step agent workflows via `GET/POST /v1/workflows/:id` |
| Pipeline processing | Submit pipelines, poll status (`/v1/pipelines/submit`, `/v1/pipelines/:id/status`) |
| Agent continuation | `POST /v1/agents/run`, `/v1/agents/:id/continue` — stateful multi-turn agent runs |
| Cage SDK path | `ANY /cage/:sha_address/*path` — air-gapped mesh proxy with SHA-addressed cage endpoints |
| Model routing | Tenant-configured provider chains with automatic failover to secondary/tertiary providers |
| Streaming | Token-stream pass-through with per-stream tracing (`GET /v1/stream/:stream_id`) |

### 1.2 Enforcement Modes

**View mode** — Trace and explain without blocking. Every request is logged, decision trees are built, PII is observed, and a full evidence record is written. No enforcement side effects.

**Control mode** — Full enforcement pipeline applied to every request:

| Stage | What It Does |
|---|---|
| Identity resolution | Every API key is resolved to a tenant identity and policy bundle via Connector OS before the request proceeds |
| Quarantine check | Quarantined tenants/agents are blocked immediately (fail-closed) |
| Policy gate | `allow` / `block` / `require_approval` per action + resource, evaluated against tenant policy bundle |
| HITL escalation | High-risk actions (finance, write operations) auto-escalate to human review queue with `202 Accepted` + `X-Approval-Required` header |
| Risk scoring | Per-request risk score computed from action type, resource sensitivity, memory context, and agent history |
| Budget enforcement | Per-tenant token and cost limits enforced with `429 Budget-Exceeded` before upstream call |
| Tool permission check | Every tool invocation is gated against the agent's declared tool allowlist |
| Local PII guard | Prompt and context scanned for PII patterns (email, phone, SSN, API keys, PHI, etc.) before leaving the perimeter |
| Memory scoping | Optional `memory_scope` header triggers Connector OS memory write for decision context persistence |
| Provider fallback | On upstream failure, configurable fallback chain tried in order |

### 1.3 Decision Evidence

Every request produces a tamper-evident decision record that buyers can audit, export, and reproduce:

| Evidence Type | Endpoint |
|---|---|
| Full trace with events | `GET /trace/:trace_id` |
| Decision explanation | `GET /explain/:request_id` |
| Cryptographic proof | `GET /prove/:request_id` |
| Cost breakdown | `GET /cost/:request_id` |
| Decision tree JSON | `GET /decision/:trace_id` |
| Decision diff | `GET /decision/diff` — compare two decision outcomes |
| Enforcement record | `GET /enforcement/:trace_id` |
| Workflow statement | `GET /workflow/:workflow_id/statement` |

### 1.4 Multi-Tenant Management API

All management operations are protected by JWT or admin-token auth and scoped to a tenant:

| Category | Operations |
|---|---|
| **Tenants** | CRUD, API key provisioning, key rotation |
| **Providers** | Register and update upstream LLM/tool providers per tenant |
| **RBAC** | Role definitions, user→role assignment (owner / admin / operator / viewer) |
| **Budgets** | Create and update per-tenant token/cost budgets |
| **Policies** | Policy bundle CRUD; allow/block/escalate rules per action+resource |
| **Approvals** | List, approve, reject, quarantine pending HITL actions |
| **Quarantine** | List quarantined entities; release quarantine |
| **Logging** | Configure audit log destinations |
| **Observability** | Interaction list, trace list, admin statistics |

### 1.5 TUI Dashboard

The TraceTramp TUI is a production-grade, fullscreen terminal application requiring no browser:

| TUI Feature | Keybinding |
|---|---|
| Live trace feed with tenant filter | `f` to filter by tenant |
| Time-window filter | `t` |
| Approvals palette — approve / reject / quarantine | `P` |
| Provider configuration form | `o` |
| Policy editor | `l` |
| Command palette | `:` |
| Decision diff viewer | `D` |
| OWASP LLM Top-10 risk panel | `O` |
| Inspector + decision JSON | click / enter |
| Export selected row / export evidence packet | `e` / `E` |
| Block and quarantine confirmations | context-aware |
| Help | `?` |

### 1.6 Operational Commands

```
tracetramp doctor     # pre-flight: DB, Redis, Connector, JWT, ports, migrations, cage
tracetramp setup      # guided .env + DB + migrations + Connector reachability
tracetramp start      # full startup with health gate; --foreground for containers
tracetramp stop       # graceful shutdown via PID file
tracetramp status     # connectivity + endpoint URLs
tracetramp tui        # attach TUI to running server
tracetramp serve      # server only (no setup steps)
```

---

<a name="witnessctl"></a>
## 2. WitnessCtl — Verifiable Evidence and Compliance Proxy

WitnessCtl captures, signs, and seals every API interaction into a tamper-evident session chain. Buyers receive receipts, compliance reports, and exportable evidence bundles that survive legal, regulatory, and audit scrutiny.

### 2.1 Session Lifecycle Management

A **session** wraps a bounded set of API calls. Sessions have deterministic lifecycle transitions enforced by the server:

| State | Transitions | Meaning |
|---|---|---|
| `active` | → locked, quarantined, sealed | Traffic captured and receipted |
| `locked` | → unlocked, sealed | Operational pause; no new traffic |
| `quarantined` | → unquarantine | Full traffic block |
| `sealed` | terminal | Immutable; no further writes; evidence finalized |

**Session API:**

```
POST   /api/v1/sessions                    open a new session
GET    /api/v1/sessions                    list sessions
GET    /api/v1/sessions/:id                get session detail
POST   /api/v1/sessions/:id/seal           immutably seal
POST   /api/v1/sessions/:id/lock           operational lock
POST   /api/v1/sessions/:id/unlock         release lock
POST   /api/v1/sessions/:id/quarantine     block all traffic
POST   /api/v1/sessions/:id/unquarantine   release quarantine
POST   /api/v1/sessions/:id/upstream       update upstream target
```

**Session configuration fields:** upstream URL, role, mode (proxy / sdk_shim / webhook), compliance frameworks to enforce, policy (clearance level, denied/allowed hosts, PII action, admission requirement, risk level, erasure flag), agent PID from Connector OS.

### 2.2 Traffic Capture and HMAC Receipt Chain

Every API call passing through WitnessCtl produces a **capture** and a **receipt**:

| Property | Detail |
|---|---|
| Idempotency | `x-witness-idempotency-key` / `x-idempotency-key` — duplicate requests return the existing capture, preventing double-logging |
| Request hash | SHA-256 of normalized request body |
| Response hash | SHA-256 of response body |
| HMAC chain | Every receipt is HMAC-SHA256 chained to the previous receipt; head HMAC stored on the session; chain is verifiable end-to-end |
| Firewall metadata | Firewall status, reason, blocked flag per capture — sourced from Connector OS async or sync path |
| PII flags | `pii_in_request`, `pii_in_response` — set by Connector OS firewall or local guard |
| Schema drift | Detected field-level schema drift from baseline snapshot, with `drift_fields` list |
| Admission verdict | `allow` / `deny` / `hold` per capture |
| Body preview | Prompt and response previews stored for TUI/API inspection |
| TraceTramp linkage | `tracetramp_risk_level`, `tracetramp_policy_verdict`, `tracetramp_trace_id`, `tracetramp_request_id` — aligned to TraceTramp decision records |

**Ingest API:**

```
POST /api/v1/ingest        SDK shim mode — structured ingest of request+response pair
/witness/*path             Proxy mode — real-time transparent proxy with capture
```

### 2.3 Compliance Evaluation Engine

WitnessCtl evaluates seven compliance frameworks in real time against the actual captured evidence — not static checklists:

| Framework | Identifier |
|---|---|
| HIPAA | `hipaa` |
| SOC 2 Type II | `soc2` |
| GDPR | `gdpr` |
| EU AI Act | `eu_ai_act` |
| ISO 27001 | `iso_27001` |
| PCI DSS | `pci_dss` |
| NIST 800-53 | `nist_800_53` |

**What is evaluated per framework:**
- Admission control gate (was `require_admission` enforced?)
- Blocked call ratio
- Firewall enforcement effectiveness
- PII detection and action rates
- Schema drift frequency
- Receipt chain integrity
- Policy enforcement (allowed/denied hosts)
- Session token presence
- Manual attestation records

**Compliance API:**

```
GET    /api/v1/compliance/:session_id              computed verdicts per framework
POST   /api/v1/compliance/:session_id/evaluate     trigger re-evaluation from live captures
GET    /api/v1/compliance/:session_id/readiness    readiness check before sealing
POST   /api/v1/compliance/:session_id/manual-attest  attach manual attestation with evidence URL + attestor JWT
GET    /api/v1/compliance/:session_id/hitl         list HITL queue items
POST   /api/v1/compliance/:session_id/hitl         create HITL review item
POST   /api/v1/compliance/:session_id/hitl/:id/resolve  resolve with approve/reject/escalate
```

**Verdict fields per framework:** `passed`, `score` (0–100), `controls` (per-control pass/fail + reason), `failed_controls`, `evaluated_at`.

### 2.4 Report and Evidence Export

| Format | Content |
|---|---|
| **PDF** | Fully styled HTML rendered via Google Chrome headless (or Chromium / wkhtmltopdf fallback). Includes executive summary, framework verdicts, evidence samples table, decision pentest summaries, HMAC chain footer. |
| **Markdown** | Human-readable, linkable, auditable text in the same structure as PDF. |
| **JSON** | Machine-readable full export: session metadata, all captures, all receipts, compliance verdicts, pentest summaries, export metadata with counts and timestamps. |
| **CSV** | Tabular captures for spreadsheet/SIEM ingestion. |

**WORM persistence:** Optional append-only write to a local directory or remote HTTP endpoint. `strict` profile requires at least one WORM destination to be configured — export fails otherwise.

**Export API:**

```
GET /api/v1/export/:session_id?format=json|csv|markdown|pdf&include_raw=true
GET /api/v1/report/:session_id?framework=hipaa&format=pdf        single-framework report
GET /api/v1/report/:session_id/batch?frameworks=hipaa,soc2&format=pdf  multi-framework report manifest
```

**Batch report manifest** includes `shared_artifact_filename`, `shared_artifact_sha256`, `custody_manifest_hash`, and per-framework entries — all in one API call.

### 2.5 Cryptographic Proof and Chain Verification

```
GET /api/v1/proof/:session_id      Connector OS proof bundle: chain_verified, receipt_count, journal_entries
GET /api/v1/verify/:session_id     In-process HMAC chain walk: chain_valid, head_matches, tamper_detected, receipt_count
```

Chain verification re-walks every receipt from genesis to head, recomputing HMAC at each step. `tamper_detected: true` means a receipt was modified after the fact.

### 2.6 PII Detection and Tokenization

```
GET /api/v1/pii/:session_id     Full PII report: all hits, field paths, types, actions, previews
```

**PII types detected:** email, phone, SSN, credit card, PHI, IP address, API key, AWS key, password, generic patterns.

**Actions per hit:** log-and-allow, redact, block — configured per session policy (`pii_action` field).

**Original and redacted previews** stored per hit for audit evidence.

### 2.7 Decision Pentest Reports

Per-decision security analysis assembled from Connector OS signals and cached locally:

| Component | Detail |
|---|---|
| Dehallucination chain | Step-by-step grounding analysis; risk score + flagged status per step |
| Dehallucination heatmap | Per-step risk heat visualization |
| Knot diversion score | 0.0–1.0 score measuring how far a decision diverged from intended routing |
| Knot diversion heatmap | Per-step diversion heat |
| PII components | Every PII datum that participated in the decision: type, location, action, tokenization ID |
| Tokenization trace | Step-by-step record of how private data was vaulted and surfaced without exposure |
| Mini pentest graph | Directed graph of decision nodes with risk scores and edge labels |
| Stability verdict | `stable` / `suspect` / `infected` — memory infection detection |
| Payload hash | SHA-256 of combined Connector OS payload for audit integrity |
| Connector availability flag | `connector_available: false` degrades gracefully to partial report |

```
GET /api/v1/pentest/:session_id/decisions              summary list (all cached + uncached stubs)
GET /api/v1/pentest/:session_id/decisions/:trace_id    full report (fetches from Connector OS on cache miss)
```

Pentest summaries are also embedded in all export formats (JSON `decision_pentest_summaries` array, Markdown table, PDF section).

### 2.8 Schema Drift Detection

```
GET /api/v1/schemas/:session_id    all schema snapshots, version history, drift events per endpoint
```

WitnessCtl baselines the JSON schema of every unique `host + path + method` combination. Subsequent captures that deviate from the baseline set `schema_drift: true` and record the specific `drift_fields`. Drift events accumulate in a per-endpoint log.

### 2.9 Custody and Chain-of-Custody Guard

```
GET /api/v1/custody/:session_id/status
```

The custody guard blocks export and report endpoints when custody conditions are not met. `force=true` overrides for authorized operators. Custody status reflects:
- pending / acknowledged / failed attestor steps
- quorum target vs achieved
- WORM write status

### 2.10 Reverse Proxy Security

The `/witness/*path` route proxies to the session's configured upstream. Production security controls applied:

| Control | Detail |
|---|---|
| Header stripping | `x-original-method` and `x-original-path` headers rejected to prevent cage bypass |
| Cage mode | When `cage_mode` is enabled, only allowlisted HTTP methods and paths are forwarded |
| Strict mode | Extends cage controls: also enforces allowlisted upstream hosts and HTTPS-only for `vps-prod` route profile |
| Path validation | Malformed paths (`//`, `\`) rejected before forwarding |
| Scheme validation | Upstream URL must be `http` or `https` |
| Rate limiting | 1,000 requests/minute per `x-witness-session` token, sliding window |

### 2.11 TraceTramp Integration

WitnessCtl receives handoff payloads from TraceTramp when TraceTramp blocks or redacts content in Control mode:

```
POST /api/v1/integrations/tracetramp/handoff     receive blocked/redacted event from TraceTramp
GET  /api/v1/integrations/tracetramp/by-trace/:trace_id   look up WitnessCtl capture by TraceTramp trace_id
```

Handoff payload links `trace_id`, `request_id`, risk level, policy verdict, PII flags, and firewall decision to the corresponding WitnessCtl capture row. Both systems share `x-trace-id` / `x-request-id` headers for end-to-end correlation.

### 2.12 Webhook Queue

WitnessCtl enqueues events to a configurable webhook destination for SIEM / SOC integration. Webhook payloads carry session events (open, seal, lock, quarantine, compliance verdict, export) with HMAC signatures for verification.

### 2.13 WitnessCtl TUI Dashboard

| Feature | Keybinding |
|---|---|
| Live capture feed with filter | `/` to filter by host/path/verdict |
| Session switcher | `g` |
| Capture inspector (request → prompt → response → compliance chain) | `Enter` |
| Compliance evaluate panel (live recompute) | `c` |
| Compliance report picker (framework + format → download) | `r` |
| Decision pentest panel (dehallucination, knot, PII, tokenization trace, mini graph) | `P` |
| HITL queue panel | `h` |
| Evidence export (writes signed file to `~/witnessctl/exports/`) | `E` |
| Verify receipt chain | `v` |
| Evidence packet viewer | `v` |
| Popeye health/risk scan | `p` |
| Session seal | `s` |
| Session lock / unlock | `l` / `u` |
| Session quarantine / release | `z` / `Z` |
| Upstream editor | `e` |
| Setup wizard | `w` |
| Copy last export SHA-256 to clipboard | `C` |
| Toast notifications (success/error, 2–4 s) | automatic |
| Chain integrity badge | status bar |
| Custody badge | status bar |
| Help | `?` |

---

<a name="joint"></a>
## 3. Joint Capabilities — TraceTramp × WitnessCtl

When both products are deployed together, buyers get a complete AI governance stack:

| Capability | How It Works |
|---|---|
| **End-to-end trace correlation** | TraceTramp sets `x-trace-id`; WitnessCtl stores it on every capture; both records are queryable by the same trace ID |
| **Runtime enforcement → immutable evidence** | TraceTramp makes the allow/block decision; WitnessCtl seals the evidence of that decision including TraceTramp's verdict, risk score, and policy outcome |
| **PII block with audit** | TraceTramp fires a handoff when PII is blocked; WitnessCtl captures the event with full PII hit metadata and receipts it into the HMAC chain |
| **Decision pentest reports** | WitnessCtl assembles per-decision pentest reports drawing from Connector OS capabilities seeded by TraceTramp trace IDs |
| **Compliance evaluation from real runtime signals** | WitnessCtl compliance verdicts are computed from actual TraceTramp-produced admission verdicts, firewall outcomes, and PII hits — not from static policy documents |
| **Unified export** | A single `GET /api/v1/export/:session_id?format=pdf` bundle includes TraceTramp-sourced risk levels, policy verdicts, and pentest data alongside WitnessCtl receipt chains, compliance verdicts, and custody status |

---

<a name="frameworks"></a>
## 4. Compliance Frameworks Supported

| Framework | Coverage |
|---|---|
| **HIPAA** | PHI detection and action, access controls, audit trail, session sealing as technical safeguard |
| **SOC 2 Type II** | Availability (session health, rate limiting), confidentiality (PII redact/block), processing integrity (HMAC chain, idempotency), security (auth, cage mode, strict proxy) |
| **GDPR** | PII detection, erasure flag, data minimization (redact action), manual attestation for DPA evidence. Enterprise tier required for GDPR PDF export. |
| **EU AI Act** | AI system transparency (decision evidence, explanation endpoints), human oversight (HITL queue, HITL resolution), risk classification (scoring, quarantine) |
| **ISO 27001** | Access control (bearer auth, RBAC), audit logging (HMAC receipt chain), information classification (PII types and actions), incident management (quarantine, lock) |
| **PCI DSS** | Credit card PII detection, firewall effectiveness, audit trail, sealed session as cardholder data protection evidence |
| **NIST 800-53** | AU (audit and accountability via receipt chain), AC (access control via session policy), SI (system and information integrity via schema drift and chain verification), IR (incident response via quarantine) |

---

<a name="security"></a>
## 5. Security and Trust Properties

### Authentication

| System | Mechanism |
|---|---|
| TraceTramp data plane | Bearer `cpk_live_*` / `cpk_test_*` API keys; JWT HS256 for management plane |
| TraceTramp management | `TRACETRAMP_ADMIN_TOKEN` or JWT with `admin` / `super_admin` / `owner` role |
| WitnessCtl API | `WITNESSCTL_ADMIN_TOKEN` (admin operations) or per-session `session_token` |
| TraceTramp→WitnessCtl handoff | `WITNESSCTL_TRACETRAMP_HANDOFF_SECRET` HMAC-verified handoff payload |
| Compliance attestor JWT | Optional JWT attestor binding with `attestor_subject`, `attestor_token_jti` for SOC2/ISO attestation workflows |

### Data Integrity

- **HMAC-SHA256 receipt chain** — every receipt is linked to the previous; any tampering breaks the chain walk at `GET /api/v1/verify/:session_id`
- **Request + response hashing** — SHA-256 of normalized request/response bodies stored on every capture
- **Sealed sessions** — server-enforced terminal state; no writes permitted after seal
- **WORM export** — `create_new` filesystem flag prevents overwrite of export artifacts; remote HTTP WORM uses `If-None-Match: *`
- **Idempotency keys** — duplicate ingestion returns the canonical record without creating a new one
- **Custody manifest hash** — batch report manifests include a SHA-256 of the full report array for artifact integrity

### Network Security

- Proxy strips `x-original-method` and `x-original-path` to prevent routing bypass
- Cage mode enforces allowlisted methods and paths at the proxy layer
- Strict mode adds host allowlisting and HTTPS enforcement for production route profiles
- All upstream URLs validated for `http`/`https` scheme; malformed paths rejected before forwarding

---

<a name="deployment"></a>
## 6. Deployment and Operations

### Infrastructure Requirements

| Requirement | TraceTramp | WitnessCtl |
|---|---|---|
| **Database** | PostgreSQL 14+ | PostgreSQL 14+ |
| **Cache** | Redis 6+ | Redis 6+ (optional, for webhook queue) |
| **PDF renderer** | — | Google Chrome / Chromium / wkhtmltopdf (any one; Chrome preferred) |
| **Connector OS** | Required (identity, policy, health) | Required (firewall, pentest, proof) |
| **Ports** | 9741 (data), 9742 (management) | 8080 (default, configurable) |

### Environment Variables (key prod secrets)

| Variable | Product | Purpose |
|---|---|---|
| `TRACETRAMP_JWT_SECRET` | TraceTramp | JWT signing key |
| `TRACETRAMP_ADMIN_TOKEN` | TraceTramp | Management plane auth |
| `TRACETRAMP_LOCAL_API_KEY` | TraceTramp | Local cage API key |
| `WITNESSCTL_ADMIN_TOKEN` | WitnessCtl | Admin bearer token |
| `WITNESSCTL_TRACETRAMP_HANDOFF_SECRET` | WitnessCtl | TraceTramp handoff HMAC |
| `WITNESSCTL_WORM_DIR` | WitnessCtl | Local WORM export path |
| `WITNESSCTL_WORM_HTTP_URL` | WitnessCtl | Remote WORM endpoint |
| `CONNECTOR_API_KEY` | Both | Connector OS access |
| `DATABASE_URL` | Both | PostgreSQL DSN |

### Migrations

Both services embed their own `sqlx` migrations and run them automatically on startup (or via `doctor` / `setup`). Migrations are numbered and sequential; checksum validation prevents replay of modified migrations.

WitnessCtl migrations in order:
- `20240101000001` — core tables (sessions, captures, receipts, schemas, PII hits, compliance)
- `20260427000002` through `20260427000013` — async firewall, manual attestations, custody hardening, TSA binding, HITL queue, custody fabric, cage proxy hardening, tenant isolation, PII previews, webhook queue, TraceTramp integration, body preview
- `20260428000014` — decision pentest cache

### Rate Limiting

| Surface | Limit |
|---|---|
| TraceTramp data plane | ~2 req/sec per API key (Governor; burst 100) |
| WitnessCtl proxy (`/witness/*`) | 1,000 req/min per session token |
| WitnessCtl export (`/api/v1/export/*`) | Configurable sliding window rate limit per token |

### Docker (lab) and runtime

TraceTramp and WitnessCtl lab images are built from **`lab/Dockerfile.tracetramp`** and **`lab/Dockerfile.witnessctl`** (see `lab/README.md`) via `lab/docker-compose.premium-lab.yml` + `lab/advanced.yml`. Kubernetes manifests under `plugins/tracetramp/k8s/` were removed (Connector OS targets microVM / supervisor). Recommended deployment:
- Separate database connection pools (max 20 for TraceTramp, max 5 for WitnessCtl TUI)
- `RUST_LOG=info` for structured JSON log output (`LOG_FORMAT=json`)
- Liveness probe: `/health` on the respective port
- Readiness probe: `/ready` (TraceTramp) / `/health` with DB check (WitnessCtl)

---

## Summary Table

| Capability | TraceTramp | WitnessCtl |
|---|:---:|:---:|
| LLM proxy (OpenAI-compatible) | ✓ | — |
| Tool / function call interception | ✓ | — |
| Workflow orchestration | ✓ | — |
| Runtime policy enforcement | ✓ | — |
| HITL escalation queue | ✓ | ✓ |
| Multi-tenant RBAC | ✓ | — |
| Agent identity resolution | ✓ | — |
| Per-tenant budget enforcement | ✓ | — |
| Provider failover routing | ✓ | — |
| Cage SDK mesh proxy | ✓ | — |
| API traffic capture + HMAC chain | — | ✓ |
| Session lifecycle management | — | ✓ |
| Schema drift detection | — | ✓ |
| PII detection and action | ✓ | ✓ |
| Compliance evaluation (7 frameworks) | — | ✓ |
| Manual attestation | — | ✓ |
| Cryptographic proof bundle | — | ✓ |
| Receipt chain verification | — | ✓ |
| PDF / Markdown / JSON / CSV export | — | ✓ |
| WORM artifact persistence | — | ✓ |
| Decision pentest reports | — | ✓ |
| Dehallucination chain analysis | — | ✓ |
| Knot diversion scoring + heatmaps | — | ✓ |
| Tokenization trace | — | ✓ |
| Stability / infection verdict | — | ✓ |
| TraceTramp ↔ WitnessCtl handoff | ✓ | ✓ |
| Webhook queue / SIEM integration | — | ✓ |
| Live TUI dashboard | ✓ | ✓ |
| Embedded Postgres migrations | ✓ | ✓ |
| Docker + Kubernetes manifests | ✓ | ✓ |
| Connector OS integration | ✓ | ✓ |

---

*Document generated from source: `plugins/tracetramp` and `plugins/witnessctl` — Connector OS platform.*
