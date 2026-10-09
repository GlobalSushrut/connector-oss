# Connector OS Code Reality, Security, and Buyer Architecture Report

**Review date:** 2026-08-03  
**Scope:** Connector OS core, TraceTramp, WitnessCtl, and DevGuard  
**Code baseline:** branch `main`, HEAD `d618a15ea74b`, plus the uncommitted working tree present during review  
**Review type:** static, code-first architecture and security review  

> This report intentionally excludes Conductor, AgentLoop, AgentPassport,
> LedgerLens, Relay, Engram, and other secondary services from maturity scoring.
> Those services are intentionally reserved for a later phase and are not treated
> as current product gaps.

---

## 1. Executive judgment

Connector OS is not vaporware. It contains a substantial Rust implementation of
a single-node governed AI runtime, an OpenAI-compatible gateway, a content-
addressed memory kernel, policy/admission machinery, plugin packaging and
isolation backends, an embedded operator UI, and three distinct first-party
product directions.

The strongest code-backed product shape is:

1. **Connector OS** provides the node, identity, API, gateway, memory, policy,
   plugin lifecycle, and operator surface.
2. **TraceTramp** provides inline LLM/API traffic control and operational
   observability.
3. **WitnessCtl** provides captured evidence, HMAC-linked receipts, sealed
   bundles, and offline integrity verification.
4. **DevGuard** provides repository policy-as-code and cooperative coding-agent
   controls through IDE hooks, git hooks, a watchdog, and optional Linux process
   interception.

The main issue is not absence of code. The issue is that several top-level
security and compliance claims are broader than the enforcement actually
guaranteed by the current wiring:

- The “nine rings” are distributed controls, not one structurally unavoidable
  execution pipeline.
- The central admission gate covers the primary LLM, memory-write, tool, and
  Anthropic paths, but not every mutating or agent-capable route.
- Multi-tenant identity can be selected using `X-Tenant-ID` when a valid token
  has no tenant claim.
- The kernel audit chain uses **keyed HMAC-SHA256** when `CONNECTOR_AUDIT_HMAC_KEY`
  is set, with recompute verification — but production must refuse the lab
  default key, and the HMAC still covers a narrow field set (not the full
  envelope). Residual: broader canonicalization + external anchoring.
- Proof generate paths must not claim `"verified": true` without recomputation;
  current `generate_proof` returns unverified until independent verify passes.
  Some certificate/SCITT surfaces remain SCITT-shaped rather than full
  external transparency.
- TraceTramp’s primary control path is real, but its management plane and
  several secondary data-plane routes are not adequately authenticated.
- WitnessCtl’s evidence integrity is real under symmetric-key custody, but
  cross-session authorization and tenant propagation are incomplete.
- DevGuard’s local controls are real for cooperative users and supported tools,
  but core server routes and gateway hook registration are not wired.

### Overall maturity assessment

| Area | Assessment | Meaning |
|---|---|---|
| Core node and packaging | **Substantial / pilot-ready** | Real single-node runtime and lifecycle |
| OpenAI gateway hot path | **Substantial** | Auth, admission, routing, memory, and audit side effects exist |
| Memory kernel | **Substantial** | Real syscall model, namespaces, content IDs, persistence, and audit events |
| Nine-ring universality | **Partial** | Controls exist, but no universal typed pipeline enforces every ring |
| Auth and RBAC | **Substantial but configuration-sensitive** | Production path is credible; fresh/local posture is open |
| Multi-tenancy | **Not production-safe yet** | Tenant binding and filtering have material gaps |
| Plugin packaging | **Substantial** | `.cpkg` format and Ed25519 signing exist |
| Plugin isolation | **Partial** | Strongest backend exists; effective guarantee depends on host and configuration |
| Audit/proof claims | **Mixed** | Useful records and real Ed25519 paths coexist with overclaimed endpoints |
| TraceTramp | **Strong pilot, not zero-trust production** | Core control path is real; auth and fail-open gaps block broad exposure |
| WitnessCtl | **Useful evidence pilot** | HMAC evidence works; authorization and non-repudiation do not meet enterprise bar |
| DevGuard | **Useful cooperative guardrails** | Local enforcement primitives work; server-mediated guarantees are incomplete |
| HA and multi-region | **Not current product strength** | Single-node architecture should be stated explicitly |

### Buyer recommendation

The product is suitable for a controlled proof of concept or hardened
single-node production pilot where:

- the buyer controls network routing;
- management planes are private;
- production presets and strict flags are explicitly applied;
- TraceTramp is the only permitted path to model providers;
- WitnessCtl is described as an integrity/evidence system under customer key
  custody, not independent non-repudiation;
- DevGuard is positioned as developer governance, not EDR or an unbypassable
  endpoint sandbox.

It should not yet be sold as:

- a cryptographically complete “all requests pass every ring” kernel;
- a secure shared multi-tenant SaaS control plane;
- an independent court-grade witness;
- an admin-resistant endpoint security agent;
- a built-in HA or multi-region platform;
- a compliance certification appliance.

---

## 2. Review method and confidence

This review followed executable code, router composition, middleware,
configuration defaults, persistence, migrations, plugin integration, and test
gates. Documentation was used to understand intended architecture but was not
accepted as proof of implementation.

### Evidence classifications

- **Solid:** implemented in an active path with meaningful tests or direct
  wiring.
- **Partial:** implemented but configuration-dependent, bypassable, incomplete,
  or not consistently applied.
- **Aspirational:** represented in documentation, schema, UI, workflow YAML, or
  dead/unmounted code without a complete active path.
- **Broken wiring:** implementation exists, but the current router/startup/client
  path cannot reach or activate it.

### Limitations

- This was primarily static analysis. It did not include a clean-machine install,
  penetration test, dependency CVE audit, fuzzing campaign, load test, or packet-
  level verification.
- The working tree contained extensive uncommitted changes and untracked files.
  Conclusions apply to that working tree, not only to HEAD `d618a15ea74b`.
- Line numbers may move. File paths and function names are the durable references.
- “P0” in this report means “must be fixed before exposing the affected feature
  as an enterprise production security boundary,” not necessarily remote code
  execution.

---

## 3. What the product is actually building

### 3.1 Product thesis

Connector OS is attempting to become an operating substrate for governed AI:

```text
Applications / agents / OpenAI-compatible clients
                         |
                         v
              Connector OS customer node
        identity | gateway | policy | memory
        tools | plugins | audit | operator UI
               /            |             \
              v             v              v
        TraceTramp      WitnessCtl       DevGuard
        live control    evidence         dev workstation
```

The product is intentionally broader than an LLM proxy. It combines:

- AI gateway and routing;
- identity, API keys, JWT, and RBAC;
- agent lifecycle and budgets;
- content and policy inspection;
- content-addressed memory;
- tool and MCP dispatch;
- audit and evidence surfaces;
- plugin packaging, discovery, supervision, and isolation;
- an embedded dashboard;
- a separate vendor licensing and account plane.

This breadth is a potential differentiator, but it increases the need for a
small number of mandatory enforcement primitives. A broad API surface with
route-specific controls is harder to secure than a narrow gateway.

### 3.2 Runtime topology

The customer-facing install centers on:

- `connector-platform` from `platform/server`;
- `connectorctl` from `platform/server/src/bin/connectorctl.rs`;
- the embedded Leptos operator dashboard;
- SQLite/redb-backed local state;
- optional or separately deployed plugin processes and PostgreSQL services.

The reference core tarball does not contain the complete TraceTramp,
WitnessCtl, and DevGuard deployment. Those products have separate build,
artifact, Helm, lab, or launcher paths. “One node” is therefore a coherent
control-plane product direction, but not yet literally one self-contained
binary artifact for all four products.

### 3.3 Customer plane and vendor plane

The code has a meaningful separation:

- **Customer node:** `connector-platform`, dashboard, customer data, policies,
  memory, plugins.
- **Vendor plane:** `connector-license-server`, portal, billing, key issuance,
  phone-home and fleet actions.

This split is architecturally reasonable, but buyers must explicitly review:

- what telemetry leaves the customer environment;
- whether remote `shutdown` or `degrade` actions are contractually acceptable;
- the air-gap path;
- license enforcement and grace behavior;
- the security of node-side license validation.

---

## 4. Core Connector OS architecture from code

### 4.1 Startup and state

`platform/server/src/main.rs` initializes configuration, license state,
SQLite/redb persistence, signing keys, the memory kernel, default policies,
runtime mode, services, background flush tasks, and the Axum router.

`platform/server/src/state.rs::PlatformState` is the central in-process state
container. Important members include:

- `kernel: Mutex<MemoryKernel>`;
- `kernel_store`;
- `engine_store`;
- `guard: Mutex<GuardPipeline>`;
- `llm_router`;
- `signing_key`;
- agent, AAPI, knot, secret, plugin, and kernel-host state.

This is a real integrated process, not a façade over unrelated HTTP services.
The downside is a large shared mutable state surface and a single-node
availability model.

### 4.2 Router and trust boundaries

`platform/server/src/router.rs::build_router` constructs four major surfaces:

1. `/api/v1/*` — large service API with auth, rate limits, body limits, tenant
   middleware, plugin gates, and trace context.
2. `/v1/*` — OpenAI and Anthropic-compatible model gateway.
3. `/plugin/<slug>/*` — authenticated proxy into plugin management planes.
4. Public infrastructure and UI routes — health, readiness, docs, metrics,
   manifest, and dashboard assets.

The gateway auth regression noted in comments has been addressed: the OpenAI
and Anthropic routes are behind `auth_middleware`.

The outer router still applies permissive CORS. With Bearer tokens this is not
an authentication bypass by itself because browsers do not automatically attach
Authorization headers cross-origin. It remains a hardening weakness and an
amplifier if a token is exposed to hostile JavaScript.

### 4.3 Real hot path: OpenAI chat

The strongest integrated path is:

```text
POST /v1/chat/completions
  -> authentication and rate limiting
  -> optional DevGuard session resolution
  -> central admission check
  -> HIPAA/configuration and entitlement checks
  -> token budget consumption
  -> sanitization and secret redaction
  -> optional memory retrieval
  -> LLM router or stub
  -> kernel memory packets
  -> engine audit and billing side effects
  -> OpenAI-compatible response
```

Primary code:

- `platform/server/src/services/gateway.rs::chat_completions`
- `platform/server/src/services/admission.rs::check`
- `platform/server/src/services/gateway_hooks.rs`
- `oss/vac/crates/vac-core/src/kernel.rs`

This path is substantive. It is the best foundation on which to make the
governance story true.

### 4.4 Central admission gate

`platform/server/src/services/admission.rs::check` implements:

- quarantine and pause checks;
- optional license enforcement;
- optional host-kernel attachment enforcement;
- the five-layer guard pipeline;
- semantic injection scoring;
- audit of allow and deny decisions;
- quarantine/HITL side effects for selected denials.

Active call sites were found in:

- OpenAI gateway;
- Anthropic gateway;
- primary memory write;
- tool dispatch.

The code comment states that every agent execution path must call admission.
That is not currently true. Many other routes, including shared knowledge
ingest and various debug, pipeline, multi-agent, and administrative mutation
paths, do not require an `AdmissionTicket`.

**Architectural conclusion:** admission is a strong library-level gate used by
important handlers, not yet an unavoidable kernel boundary.

### 4.5 Memory kernel

The VAC memory kernel is one of the more substantial components:

- content-addressed packets;
- namespace and agent metadata;
- syscall-like dispatch;
- security-level checks;
- persistent redb storage;
- audit events;
- memory recall and similarity paths;
- signing support for packets when enabled.

`POST /api/v1/memory/write` calls the admission gate and then dispatches a
`MemWrite` syscall. This is a credible protected path.

`POST /api/v1/memory/knowledge/ingest` does not receive equivalent admission
coverage. Because the shared knowledge plane may influence later model context,
this is a material memory-poisoning gap.

### 4.6 Policy and firewall

The code contains:

- a five-layer `GuardPipeline`;
- MAC controls;
- policy rules;
- content inspection;
- circuit breaker behavior;
- audit/HITL output;
- a diagnostic `/firewall/inspect` endpoint;
- the enforcing admission path.

Important distinction:

- `/firewall/inspect` reports a decision.
- `admission::check` is the path that turns a decision into denial/quarantine.

The policy layer permits requests when no policy rules are loaded. That may be
reasonable for local evaluation, but it contradicts unconditional “fail closed”
language unless production boot guarantees a default-deny bundle.

### 4.7 Boot/readiness

There are two overlapping boot models:

- a seven-bit readiness model driven from `main.rs`;
- a documented twelve-stage model exposed to the UI.

Several named stages are represented by progress/log bits rather than concrete
component initialization. Readiness does perform useful checks, including
kernel lock availability, audit-chain status, and license state, but the product
should not present decorative stages as completed security components.

### 4.8 Persistence

The core uses:

- SQLite through `EngineStore` for users, metadata, folders, and operational
  records;
- redb through `KernelStore` for memory-kernel state;
- periodic and shutdown flushes.

This is appropriate for a single-node product and supports a simple install.
The corresponding limitations are:

- no proven active/active state replication;
- backup and restore remain an operator responsibility;
- process-level mutexes serialize important paths;
- recovery properties depend on both stores remaining consistent.

---

## 5. The nine-ring claim: actual enforcement map

The nine-ring model is useful as product language, but it is not represented by
one typed request object that must traverse nine mandatory stages.

| Ring | Code reality | Current strength |
|---|---|---|
| Identity and boot | JWT/API key middleware, users, runtime mode, license | **Substantial**, but local/default mode can open auth |
| Network and gateway | Axum, gateway routes, rate limit, plugin proxy | **Substantial**, configuration-sensitive |
| Firewall and guard | Guard pipeline + admission | **Substantial on selected hot paths** |
| Memory | VAC kernel and namespace/syscall model | **Substantial** |
| Policy/governance | Multiple policy engines, admission, budgets, HITL | **Fragmented/partial** |
| Reasoning/LLM | LLM router, sanitization, RAG, cost | **Substantial** |
| Tool execution | Tool admission and plugin isolation | **Partial**, route/backend dependent |
| Audit | Kernel links, SQLite audit, plugin evidence | **Real records; cryptographic claims mixed** |
| Surface output | Dashboard, reports, redaction and proof views | **Presentation layer, not a security boundary** |

### What would make the claim structurally true

1. Define a canonical `GovernedRequest` and `GovernedDecision`.
2. Require all agent/memory/tool/model mutation handlers to obtain an
   unforgeable `AdmissionTicket`.
3. Move namespace and tenant identity into verified request extensions.
4. Make policy absence an explicit production error.
5. Emit one audit envelope atomically for each decision.
6. Add tests that attempt to register every relevant route without the required
   enforcement middleware and fail compilation or CI.
7. Change documentation from “every request” to “governed execution paths”
   until that architecture is complete.

---

## 6. Core security findings

### 6.1 Authentication and default posture

Solid:

- production JWT signing requires `CONNECTOR_JWT_SECRET`;
- JWT verification uses `jsonwebtoken`;
- passwords use Argon2;
- API keys are generated from random bytes and persisted as hashes;
- API scope and RBAC logic exists;
- production/dev conflict checks exist;
- gateway routes have auth middleware.

Gaps:

- fresh/local runtime mode normally sets development environment flags that
  enable unauthenticated access;
- the bootstrap SuperAdmin password can be emitted in plaintext logs;
- Ultimate Free/open-auth modes intentionally bypass normal identity;
- the dashboard stores tokens in local storage, increasing XSS impact;
- JWT secret rotation behavior is not a complete atomic key rotation system.

The correct product stance is:

- local mode is an explicit evaluation mode;
- the process must refuse non-loopback binding in open-auth mode unless the
  operator acknowledges it;
- production mode must be chosen during first boot, not discovered in a
  hardening guide after deployment.

### 6.2 Multi-tenant boundary

Confirmed issue:

1. Auth middleware validates a token.
2. Tenant middleware runs later.
3. If the token has no `tenant_id`, a caller can supply `X-Tenant-ID`.
4. The header becomes the `TenantContext`.

Normal `cpk_*` keys do not necessarily encode or resolve a tenant, and JWT
`tenant_id` is optional. This allows a valid authenticated principal without a
tenant binding to select another tenant on tenant-aware write paths.

Additional weaknesses:

- several list/read paths do not filter by tenant;
- many API subtrees are tenant-exempt;
- default tenant context permits broad namespace access;
- tenant quotas and kernel identity are not consistently first-class.

**Severity:** High for any shared multi-tenant deployment.

Required fix:

- derive tenant only from verified JWT claims or API-key registry records;
- reject tenantless tokens in multi-tenant mode;
- allow `X-Tenant-ID` only when it exactly matches the verified binding;
- require handlers to extract `TenantContext`;
- add cross-tenant negative tests for every list, get, write, export, and proxy
  surface.

### 6.3 Audit-chain semantics

**Current (as of maturity U0):** the kernel implements keyed HMAC-SHA256 over a
narrow canonical field set (audit id, timestamp, operation, agent PID, outcome)
plus chain linking, with recompute verification in `verify_audit_chain`.

Remaining honesty gaps:

- HMAC still excludes target, reason, error, and other envelope fields;
- lab default key material exists for local/dev — production / defense-strict
  boot must require `CONNECTOR_AUDIT_HMAC_KEY` (≥64 hex chars);
- no external transparency anchor for chain heads yet.

Required follow-ups:

1. Canonicalize the entire security-relevant audit envelope under the HMAC.
2. Keep `HMAC-SHA256(key, previous_mac || canonical_entry)` (or Ed25519 checkpoints).
3. Anchor chain heads externally or to a protected transparency service.
4. Version the chain format and migrate old entries without silently relabeling them.

Until the envelope is fully covered and keys are operator-managed, call this a
**keyed audit HMAC (narrow fields)** — not court-grade non-repudiation.

### 6.4 Proof surfaces

There are real Ed25519 functions:

- platform signing key persistence;
- certificate signing and verification;
- `.cpkg` signing;
- SCITT-shaped receipt signing.

But the proof API also includes residual gaps:

- `generate_proof` persists a bound artifact and returns `"verified": false` /
  `"verification_status": "unverified"` until independent recompute — do not
  regress to decorative `verified: true`;
- certificate / SCITT surfaces can still be SCITT-shaped without a complete
  external transparency log or meaningful inclusion proof;
- Merkle proof output often describes audit provenance rather than a formally
  verified inclusion path.

This is a P0 claim-accuracy problem for a product sold on proof.

Required fix:

- persist a canonical proof artifact;
- bind proof ID, subject, tenant, policy version, event range, chain head, and
  signing key ID;
- make unknown proof IDs fail;
- recompute all hashes and signatures;
- separate “platform-signed statement” from “SCITT transparency receipt”;
- publish a verifier independent of the issuing server.

### 6.5 Plugin supply chain

Solid:

- canonical `.cpkg` digest;
- Ed25519 signature envelope;
- trust-map verification;
- manifest parsing and validation.

Gap:

- signatures are optional unless configuration or request flags require them.

Production should:

- require signatures by default;
- ship a vendor trust root;
- support customer trust roots and revocation;
- verify before extraction;
- constrain paths and file sizes;
- record package digest, signer, and verification result in the audit log.

### 6.6 Plugin isolation and cage

The runtime supports:

- subprocess;
- Docker lab;
- Firecracker microVM;
- experimental WASM;
- optional seccomp, `no_new_privs`, cgroups, fuel, and egress rules.

This is substantive isolation work. However, the actual guarantee depends on:

- selected backend;
- Firecracker assets and host support;
- whether egress enforcement is available;
- whether strict/fail-closed settings are enabled;
- whether fallback to subprocess is allowed.

The in-process `*.cnktros` registry and authenticated `/plugin/<slug>/*` proxy
are useful stable routing mechanisms. They do not make a plugin trustworthy.
The proxy currently relies on powerful plugin admin bearer tokens held by the
platform.

Production posture should fail startup if a required isolation backend or
egress control cannot be established. It should not silently downgrade.

---

## 7. TraceTramp assessment

### 7.1 What TraceTramp really is

TraceTramp is a dual-plane Rust/Axum service:

- **Data plane (`:9741`):** OpenAI/Anthropic-shaped traffic, tool/function/
  workflow routes, traces, and cage paths.
- **Management plane (`:9742`):** operator APIs for traces, approvals,
  quarantine, operation blocks, policies, tenants, and providers.

The product’s most defensible role is:

> A governed AI traffic control point that combines deny-before-upstream
> decisions, operational traces, budgets, quarantine, HITL scaffolding, and
> optional evidence handoff.

### 7.2 Solid code-backed capabilities

- dual-plane service and migrations;
- default Control pipeline for chat;
- pre-upstream operation blocks and quarantine;
- policy calls and risk evaluation;
- budget enforcement;
- tool permission checks;
- input PII block/redaction;
- provider proxy and circuit-breaker behavior;
- trace events and decision trees;
- append-only database trigger for trace events;
- platform-side authenticated management proxy;
- TraceTramp-to-WitnessCtl handoff with a shared secret;
- setup, doctor, and deployment scaffolding.

The core Control path is the strongest first-party workflow/product in the
repository.

### 7.3 Critical gaps

#### Management API authentication is not attached

Admin middleware functions exist, but the management router does not apply
them. If `:9742` is reachable, callers can access high-impact administration
routes without TraceTramp-level authentication.

Platform auth reduces risk only when all management traffic is forced through
Connector’s proxy and the raw port is network-isolated.

#### Sensitive data-plane routes lack authentication

The main chat flow requires a key, but several routes for embeddings, tools,
functions, workflows, agents, traces, proof views, enforcement packets, and
compliance export do not consistently use the same auth boundary.

#### Connector policy can fail open

The TraceTramp client allows policy decisions when Connector is unavailable or
returns selected errors. For a security control point, this behavior must be an
explicit deployment policy, not a hidden fallback.

#### Cage address is not an authorization boundary

The cage path validates address format but does not cryptographically bind the
path address to the caller’s API key. It is routing/obscurity, not tenancy or
identity.

#### Data plane is not the platform plugin proxy

Connector’s `/plugin/tracetramp/*` path targets the management plane. Agent
LLM traffic must reach TraceTramp’s data plane directly. Deployment docs and UI
must make that distinction obvious.

#### Tenant and admin model

The platform generally uses one powerful TraceTramp admin token. Per-tenant
authorization is not carried end-to-end. Some read paths can return cross-
tenant data when no tenant filter is supplied.

### 7.4 Honest buyer positioning

Good fit:

- internal or VPC LLM gateway;
- security pilot with network-enforced model egress;
- AI cost and control plane;
- operational quarantine and review;
- trace/evidence generation.

Not yet appropriate:

- internet-exposed standalone gateway without compensating controls;
- zero-trust multi-tenant SaaS;
- guaranteed policy enforcement while Connector is unavailable;
- a product where direct provider access remains possible.

### 7.5 Minimum production conditions

1. Attach admin auth middleware to every management route.
2. Bind management listener to loopback/private interface by default.
3. Authenticate and authorize every non-health data-plane route.
4. Enforce tenant context from verified credentials.
5. Make policy failure closed by default in production.
6. Route all model egress through TraceTramp using network policy.
7. Keep management and data planes distinct in ingress configuration.
8. Add behavioral tests for 401, 403, cross-tenant denial, policy outage, and
   operation block before upstream.

---

## 8. WitnessCtl assessment

### 8.1 What WitnessCtl really is

WitnessCtl is an API evidence service that:

- opens evidence sessions;
- proxies or ingests calls;
- writes captures and linked receipts;
- seals sessions into `.witness` bundles;
- exports reports;
- verifies bundles offline;
- optionally correlates TraceTramp decisions;
- optionally requests Connector policy, firewall, audit, and proof actions.

The defensible product claim is:

> WitnessCtl produces tamper-detectable evidence bundles under customer-held
> symmetric-key custody for traffic that actually passes through its capture
> path.

### 8.2 Solid cryptographic capabilities

- HMAC-SHA256 receipt chain;
- `prev_hmac` linkage;
- request/response body hashes;
- bundle content hash;
- bundle HMAC over content hash and chain head;
- offline bundle verification;
- unit and smoke coverage for HMAC chain and bundle round trip.

These are useful. They are not non-repudiation because any holder of the HMAC
secret can forge a valid chain or bundle.

### 8.3 Critical authorization gaps

The API middleware verifies whether a Bearer token is the admin token or belongs
to some session. Several handlers do not then verify that the token owns the
session ID in the URL.

Affected classes include:

- session reads and seal;
- ingest;
- compliance evaluation and readiness;
- HITL paths;
- proof and verify;
- schema/PII views;
- selected pentest paths.

This is a cross-session IDOR. A caller with one valid session token may access
or mutate another known session ID.

### 8.4 Tenant propagation is incomplete

Connector’s WitnessCtl proxy converts `X-Tenant-ID` into a `tenant_id` query
parameter. WitnessCtl does not consume that query parameter for authorization.
The platform therefore presents tenant-scoped behavior that the plugin does not
actually enforce.

The shared platform admin token further collapses all dashboard users into one
god identity at WitnessCtl.

Until fixed, use:

- one WitnessCtl deployment per tenant; or
- an internal-only single-tenant deployment.

Do not market the current shared deployment as tenant-isolated.

### 8.5 Enforcement and evidence limits

- Policy calls can fail open.
- Firewall inspection is asynchronous by default; traffic may be forwarded
  before inspection completes.
- Connector decision recording is best effort.
- Connector proof at seal time is optional or skippable.
- The locally generated proof ID is not necessarily a Connector proof.
- TSA integration is optional and not a complete default RFC3161 trust path.
- Custody nodes use shared symmetric secrets rather than independent identities.
- The watchdog is a heartbeat/telemetry mechanism, not a route-enforcement
  control.
- Full request/response bodies are not always retained; hashes and truncated
  previews limit later reconstruction.
- Only traffic routed through WitnessCtl can be evidenced.

### 8.6 Honest buyer positioning

Good fit:

- internal evidence collection;
- incident and audit support;
- tamper detection under controlled key custody;
- SIEM/GRC export;
- TraceTramp correlation;
- offline artifact verification.

Not yet appropriate:

- independent third-party witness;
- public non-repudiation;
- court-grade timestamping by default;
- multi-tenant SaaS;
- guaranteed inline blocking in default mode;
- compliance certification.

### 8.7 Minimum production conditions

1. Enforce session ownership in every handler.
2. Bind admin and session credentials to a tenant.
3. Remove shared cross-tenant admin behavior or tightly scope it.
4. Make strict synchronous firewall and fail-closed policy the production
   defaults.
5. Require strong HMAC/admin/custody secrets and refuse known defaults.
6. Put TLS termination in front of the listener.
7. Use asymmetric signatures for externally verifiable bundles.
8. Add a real RFC3161 or equivalent trusted timestamp profile.
9. Add IDOR, cross-tenant, fail-open, and async-race integration tests.

---

## 9. DevGuard assessment

### 9.1 What DevGuard really is

DevGuard is a Rust CLI and policy-as-code system for coding-agent workstations.
It includes:

- `devguard.yaml` role and policy resolution;
- offline file/exec/git checks;
- Cursor and Windsurf pre-tool hooks;
- Claude-related hook support;
- git pre-commit/pre-push hooks;
- an inotify-based revert watchdog;
- file permission changes;
- a shell DEBUG wrapper;
- optional Linux `LD_PRELOAD` interception;
- a local status API and IDE status extensions;
- intended Connector session and gateway enforcement.

The defensible product claim is:

> DevGuard gives cooperative engineering teams centralized policy vocabulary,
> supported-IDE pre-tool blocking, local guardrails, and visibility into coding
> agent actions.

### 9.2 Solid local capabilities

- rich RBAC/policy schema;
- offline deterministic policy checks;
- dangerous-command patterns;
- Cursor/Windsurf pre-tool hook generation;
- blocking exit codes for supported hooks;
- git hook generation;
- cage status and verification helpers;
- local status service and extensions;
- a layered design that can become stronger with managed endpoint deployment.

### 9.3 Broken server wiring

The CLI expects session, audit, filesystem, execution, and policy endpoints
under `/api/v1/devguard/*`. Handlers exist in the platform service modules, but
the current router mounts only the simplified connect/info paths and selected
plugin proxy/team paths.

Consequences:

- CLI session creation can return 404.
- Connector-backed policy synchronization is not dependable.
- CLI `prove`, `trace`, and `explain` target routes that do not match the
  platform proof surface.

`install_gateway_hooks()` and related tool installation functions exist but are
not invoked during platform startup. Gateway guard callers commonly default to
allow when no hook is installed.

The Cursor adapter also uses a static API key value rather than the minted
DevGuard session token, so the gateway cannot resolve the intended governed
session.

### 9.4 Local bypass model

For a normal user:

- hooks can be removed;
- git can use `--no-verify`;
- the watchdog can be killed;
- file permissions can be restored;
- the policy file can be edited;
- the preload bypass environment variable can be set;
- direct provider keys can avoid the Connector gateway;
- unsupported editors and shell paths avoid the hooks.

For root/admin, all local controls are bypassable.

This does not make DevGuard useless. It means it is a governance and safety
tool, not tamper-resistant endpoint security.

### 9.5 Preventive versus advisory controls

| Control | Nature |
|---|---|
| Cursor/Windsurf pre-tool hook | Preventive when installed and honored |
| Offline `devguard check` | Evaluator; preventive only through a caller |
| Git hooks | Preventive but user-bypassable and fail-open |
| Filesystem watchdog | Reactive revert with race window |
| `chmod` protection | Weak prevention against cooperative processes |
| Shell DEBUG wrapper | Advisory/partial unless sourced |
| `LD_PRELOAD` | Partial Linux prevention, explicitly bypassable |
| IDE extension/status API | Observational |
| Cursor rules | Advisory |
| Gateway tool blocking | Solid logic but currently broken wiring |
| Network deny policy | Aspirational |
| Overlay filesystem/sandbox | Aspirational in DevGuard |
| HMAC receipt chain | Aspirational in DevGuard |
| Approval-gated execution | Aspirational/incomplete |

### 9.6 Honest buyer positioning

Good fit:

- coding-agent pilot;
- policy visibility and standardization;
- junior developer or controlled-repository guardrails;
- supported IDE pre-tool checks;
- evidence and education;
- foundation for an MDM-managed endpoint agent.

Not yet appropriate:

- EDR replacement;
- insider-resistant endpoint enforcement;
- administrator-proof sandbox;
- universal command interception;
- compliance-grade proof of every coding-agent action.

### 9.7 Minimum production conditions

1. Mount and test all required server APIs.
2. Install gateway hooks and MCP tools at platform boot.
3. Use the minted session token in every adapter.
4. Accept and verify the actual workspace policy during connect.
5. Make locked/cage mode fail closed when hooks or policy are unavailable.
6. Bind identity to Connector credentials and tenant.
7. Wire approval decisions into actual execution holds.
8. Align prove/trace/explain with real platform proof routes.
9. Add end-to-end tests for IDE block, gateway block, cage revert, approval,
   and bypass detection.
10. For enterprise enforcement, deploy through MDM/system service with
    administrator-controlled policy and network egress controls.

---

## 10. How the three products should work together

### Intended coherent flow

```text
Coding agent / application
          |
          | DevGuard policy and supported IDE hooks
          v
TraceTramp data plane
          |
          | Connector identity, admission, policy, budget
          v
Model provider / tool
          |
          | trace + decision handoff
          v
WitnessCtl evidence session and sealed bundle
```

### Current reality

- Connector’s OpenAI gateway is integrated and active.
- TraceTramp has its own stronger product-specific control path.
- DevGuard’s local hooks can act before tool execution, but its server session
  and gateway integration are not complete.
- TraceTramp can hand evidence to WitnessCtl, but this is best effort.
- WitnessCtl can produce a verifiable symmetric-key bundle, but tenant and
  session authorization are incomplete.
- The three products use different identity, tenant, policy, and evidence
  models.

### Required unification

Use one canonical envelope:

```text
tenant_id
principal_id
agent_id
session_id
request_id
trace_id
policy_bundle_id + version
admission_ticket_id
operation
input_digest
decision
output_digest
connector_audit_cid
tracetramp_trace_id
witness_receipt_id
timestamp
```

Every service should validate the envelope rather than trusting query
parameters, arbitrary headers, or independently generated identifiers.

The TraceTramp-to-WitnessCtl handoff should support:

- an authenticated service identity;
- replay protection;
- tenant binding;
- idempotency;
- durable retry/dead-letter behavior;
- a strict mode where selected regulated operations fail if evidence cannot be
  committed.

---

## 11. Operational architecture

### 11.1 Supported shape today

The most credible production shape is:

- one hardened Connector node per environment or trust zone;
- external TLS ingress;
- private plugin management interfaces;
- TraceTramp data plane reachable by governed clients;
- customer-managed PostgreSQL for TraceTramp and WitnessCtl;
- explicit production/defense-strict preset;
- Firecracker only where host capabilities are verified;
- customer-managed backup and monitoring.

### 11.2 HA and scale

The code and charts may expose replica settings, but the core state model is
single-node-centric. There is no sufficiently proven leader election,
distributed transaction model, or active/active consistency story for the
kernel’s SQLite/redb state.

Do not imply that setting Helm replicas above one makes Connector HA.

Recommended near-term HA model:

- active/passive node;
- replicated or backed-up data volume;
- tested restore procedure;
- external PostgreSQL HA for plugin databases;
- explicit RPO/RTO;
- stateless ingress failover;
- no concurrent writers until distributed semantics are complete.

### 11.3 Backup and recovery

Back up:

- Connector data directory;
- SQLite and redb files as a coordinated snapshot;
- platform signing keys;
- JWT/API-key and vault state;
- TraceTramp PostgreSQL;
- WitnessCtl PostgreSQL;
- Witness bundle directory;
- policy and plugin manifests;
- package trust roots.

Required test:

1. create governed events;
2. seal a Witness bundle;
3. stop services;
4. restore all state to a clean host;
5. verify login, memory, audit, package inventory, TraceTramp traces, and
   Witness bundle;
6. prove signing-key continuity;
7. record measured RPO/RTO.

### 11.4 Observability

The code provides:

- health/readiness endpoints;
- metrics;
- structured logs;
- optional OpenTelemetry;
- internal monitoring and status surfaces;
- plugin health and status APIs.

Production still needs:

- clear SLOs;
- database pool metrics;
- queue depth and dropped-event metrics;
- audit flush lag;
- evidence handoff failures;
- policy fail-open counters;
- tenant authorization denials;
- plugin isolation downgrade alerts;
- signing-key and license events.

---

## 12. Compliance and cryptography truth table

| Claim | Current truth |
|---|---|
| Content addressing | Real |
| Platform Ed25519 signatures | Real on selected paths |
| `.cpkg` Ed25519 verification | Real, but optional unless required |
| Kernel HMAC audit chain | **Not currently HMAC** |
| Kernel audit link verification | Real but weak; links are not recomputed |
| Witness HMAC receipt chain | Real |
| Witness bundle offline verification | Real |
| Witness public non-repudiation | Not provided |
| SCITT transparency receipt | SCITT-shaped signed statement; full transparency semantics incomplete |
| Merkle inclusion proof | Partial/inconsistent |
| Connector proof ID durability | Incomplete |
| SOC 2/HIPAA evidence reports | Useful self-generated evidence, not certification |
| Court-grade timestamp | Optional/partial, not default |
| All requests pass nine rings | Not structurally true |
| All agent actions pass admission | Not true |
| DevGuard bypass impossible | Not true |

Marketing, docs, API response fields, and UI labels should use this table as a
release gate.

---

## 13. Priority remediation plan

### P0 — before enterprise production claims

#### Core

- Secure first boot: no unauthenticated non-loopback listener by default.
- Stop logging bootstrap passwords; use a one-time `0600` secret file or
  operator-supplied secret.
- Bind tenant to verified credentials; remove arbitrary header selection.
- Enforce tenant filters across all list/get/write/export routes.
- Replace hardcoded proof validity with persisted, recomputed proof artifacts.
- Correct “HMAC” terminology or implement a real keyed chain.
- Add admission to shared knowledge ingest and all security-relevant mutation
  paths.
- Require signed `.cpkg` packages in production.

#### TraceTramp

- Attach admin auth to the management router.
- Authenticate all sensitive data-plane routes.
- Make policy failure closed in production.
- Bind cage and tenant identity to verified credentials.
- Remove or parameterize unsafe dynamic SQL updates.

#### WitnessCtl

- Enforce session ownership on every session-scoped handler.
- Make tenant propagation real and verified.
- Eliminate shared cross-tenant admin behavior.
- Make policy/firewall fail closed for the regulated profile.
- Refuse insecure default secrets in production.

#### DevGuard

- Mount required session, policy, filesystem, execution, and audit routes.
- Invoke gateway hook and MCP installation during boot.
- Use minted session tokens in adapters.
- Stop defaulting to allow when locked enforcement is unavailable.

### P1 — architecture consistency

- Create the canonical cross-product identity/decision/evidence envelope.
- Make the admission ticket mandatory for governed operations.
- Unify kernel and engine audit records using a shared CID.
- Implement full-entry keyed audit verification and signed checkpoints.
- Separate platform-signed proof, Witness evidence, and external transparency
  concepts.
- Add strict tenant-aware RBAC to plugin proxies.
- Add durable TraceTramp-to-WitnessCtl retries and evidence-required mode.
- Make microVM/egress capability checks fail closed in production.
- Consolidate the seven-stage and twelve-stage boot models.
- Restrict CORS to configured UI origins.

### P2 — production operations and scale

- Define active/passive HA and tested restore runbooks.
- Publish supported host and Firecracker matrix.
- Add clean-VM release acceptance.
- Add performance baselines for gateway, policy, audit, and plugin isolation.
- Add key rotation for JWT, platform signing, plugin admin, Witness HMAC, and
  handoff secrets.
- Add external audit anchoring and optional trusted timestamp service.
- Add MDM/system-service deployment for DevGuard.

---

## 14. Security test program

### Core tests

- unauthenticated request matrix for every route;
- API-key scope and RBAC matrix;
- tenant spoof and cross-tenant CRUD/export matrix;
- empty-policy behavior in production;
- admission coverage inventory;
- knowledge poisoning attempt;
- audit entry mutation and chain verification;
- unknown proof ID and altered proof verification;
- unsigned and malicious `.cpkg` install;
- isolation backend downgrade;
- plugin admin-token leakage impact.

### TraceTramp tests

- management port returns 401/403 without valid admin identity;
- every non-health data route requires correct scope;
- policy outage blocks in strict mode;
- direct upstream is prevented by deployment policy;
- cross-tenant traces/approvals are denied;
- operation block is proven to occur before upstream;
- cage address/key mismatch is denied;
- SQL and query fuzzing on admin updates;
- Witness handoff replay and outage.

### WitnessCtl tests

- session A cannot read, seal, ingest, export, prove, or attest session B;
- platform tenant A cannot query tenant B;
- strict firewall timeout blocks before upstream;
- policy outage blocks;
- default/insecure secrets prevent production startup;
- altered receipt and bundle fail verification;
- signer/key rotation behavior;
- TSA verification with trusted CA;
- handoff replay and idempotency.

### DevGuard tests

- CLI connect creates a real server session;
- adapter uses the minted session token;
- Cursor/Windsurf hook denial is behavioral, not string-presence only;
- Anthropic/OpenAI/MCP gateway action is denied before execution;
- locked mode fails closed when policy or binary is missing;
- watchdog revert and delete recovery;
- approval genuinely holds and resumes execution;
- direct-provider bypass detection;
- policy tampering alert;
- prove/trace/explain returns a bound artifact.

---

## 15. Buyer architecture guidance

### Good target buyer

- enterprise AI platform team;
- on-prem/VPC preference;
- regulated or audit-sensitive workload;
- willing to control network egress;
- accepts single-node or active/passive architecture initially;
- can operate PostgreSQL and TLS ingress;
- values integrated gateway, evidence, and developer governance.

### Poor target buyer today

- needs turnkey multi-region active/active;
- expects formal SOC 2/HIPAA certification from the software itself;
- requires a public third-party transparency witness;
- requires endpoint controls resistant to local administrators;
- cannot manage network routing or provider egress;
- expects all products in one self-contained tarball;
- requires zero operational dependency on customer-managed databases.

### Procurement questions

1. What exact data leaves the customer network during phone-home?
2. Can remote shutdown/degrade be disabled contractually and technically?
3. How are license keys cryptographically validated and bound to a node?
4. What is the supported HA topology and RPO/RTO?
5. What is the tested host matrix for Firecracker and egress enforcement?
6. Which routes are covered by the central admission gate?
7. What is the formal tenant isolation model?
8. Which proof formats have an independent verifier?
9. Who controls and rotates Witness HMAC and signing keys?
10. Is TraceTramp policy failure closed under Connector outage?
11. How is direct model-provider egress prevented?
12. Which DevGuard controls are preventive for each supported IDE?
13. Is DevGuard deployed through MDM/system service or by the developer?
14. Which compliance artifacts are vendor attestations versus generated
    customer evidence?
15. What external penetration testing and dependency audit evidence exists?

---

## 16. Recommended staged adoption

### Stage 0 — internal lab

- use synthetic/non-sensitive data;
- run Connector in local mode on loopback only;
- demonstrate OpenAI gateway admission;
- demonstrate TraceTramp block before upstream;
- create and verify a Witness bundle;
- demonstrate DevGuard hook denial;
- document every bypass encountered.

### Stage 1 — hardened pilot

- explicit production/defense-strict preset;
- production JWT secret;
- TLS ingress;
- private management ports;
- signed packages only;
- one tenant per deployment;
- strict TraceTramp policy behavior;
- strict Witness firewall behavior;
- customer-managed secrets;
- network-restricted provider egress;
- supported DevGuard IDEs only.

Do not proceed until all applicable P0 items are fixed or formally accepted with
compensating controls.

### Stage 2 — limited production

- active/passive restore test;
- PostgreSQL HA;
- SIEM and alert integration;
- key rotation drill;
- evidence-required mode for selected operations;
- measured gateway and audit SLOs;
- external penetration test;
- legal review of licensing/phone-home.

### Stage 3 — enterprise expansion

- verified multi-tenancy;
- independent proof verifier;
- asymmetric Witness bundles and trusted timestamps;
- managed DevGuard endpoint deployment;
- HA architecture supported by the vendor;
- formal compliance program and external attestations.

---

## 17. Defensible differentiators

If claims are narrowed to match implementation, the strongest differentiators
are:

1. **One governed AI node:** gateway, memory, policy, plugins, and UI in one
   installable runtime.
2. **Real content-addressed memory kernel:** more than a conventional reverse
   proxy.
3. **Inline control plus observability:** TraceTramp combines pre-upstream
   control with trace and cost context.
4. **Evidence artifact path:** WitnessCtl can produce offline-verifiable
   HMAC-protected bundles.
5. **Developer workflow integration:** DevGuard can block supported IDE tool
   actions before execution.
6. **Isolation ladder:** subprocess, Docker, microVM, and WASM backends are
   represented in real code.
7. **Plugin package signing:** `.cpkg` has a coherent canonical signing model.
8. **Self-hosted/VPC orientation:** useful for buyers unwilling to place all AI
   governance in a SaaS proxy.

The product should compete on **integrated governed execution and evidence**,
not on claims of perfect cryptography, universal enforcement, or certification.

---

## 18. Source evidence index

### Core

- `ARCHITECTURE.md`
- `README.md`
- `connector.yaml.example`
- `docs/PRODUCTION_HARDENING.md`
- `docs/KNOWN_LIMITATIONS.md`
- `platform/server/src/main.rs`
- `platform/server/src/router.rs`
- `platform/server/src/state.rs`
- `platform/server/src/auth/core.rs`
- `platform/server/src/auth/rbac.rs`
- `platform/server/src/middleware/tenant.rs`
- `platform/server/src/services/admission.rs`
- `platform/server/src/services/gateway.rs`
- `platform/server/src/services/anthropic_gateway.rs`
- `platform/server/src/services/memory.rs`
- `platform/server/src/services/tools.rs`
- `platform/server/src/services/firewall_config.rs`
- `platform/server/src/services/proof.rs`
- `platform/server/src/services/plugin_cage_proxy.rs`
- `platform/server/src/services/plugin_cpkg.rs`
- `platform/server/src/internal_dns/mod.rs`
- `platform/plugin-runtime/src/lib.rs`
- `platform/plugin-runtime/src/microvm_backend.rs`
- `platform/plugin-runtime/src/linux_hardening.rs`
- `platform/cpkg`
- `platform/plugin-handshake`
- `oss/connector/crates/connector-engine/src/guard_pipeline.rs`
- `oss/vac/crates/vac-core/src/kernel.rs`

### TraceTramp

- `plugins/tracetramp/src/main.rs`
- `plugins/tracetramp/src/gateway.rs`
- `plugins/tracetramp/src/control.rs`
- `plugins/tracetramp/src/admin.rs`
- `plugins/tracetramp/src/auth.rs`
- `plugins/tracetramp/src/connector.rs`
- `plugins/tracetramp/src/resolver.rs`
- `plugins/tracetramp/src/tenancy.rs`
- `plugins/tracetramp/migrations/20260503160000_trace_events_ledger_guard.sql`
- `platform/server/src/services/tracetramp_proxy.rs`

### WitnessCtl

- `plugins/witnessctl/src/main.rs`
- `plugins/witnessctl/src/routes.rs`
- `plugins/witnessctl/src/session.rs`
- `plugins/witnessctl/src/capture.rs`
- `plugins/witnessctl/src/proxy.rs`
- `plugins/witnessctl/src/receipt.rs`
- `plugins/witnessctl/src/connector.rs`
- `plugins/witnessctl/src/compliance.rs`
- `plugins/witnessctl/src/custody.rs`
- `plugins/witnessctl/src/custody_node.rs`
- `plugins/witnessctl/src/bin/witnessctl-verify.rs`
- `platform/server/src/services/witnessctl_proxy.rs`

### DevGuard

- `plugins/devguard/src/main.rs`
- `plugins/devguard/src/config.rs`
- `plugins/devguard/src/connector_client.rs`
- `plugins/devguard/src/commands/connect.rs`
- `plugins/devguard/src/commands/cage.rs`
- `plugins/devguard/src/commands/check.rs`
- `plugins/devguard/src/adapter/cursor.rs`
- `plugins/devguard/src/adapter/windsurf.rs`
- `plugins/devguard/src/adapter/claude.rs`
- `plugins/devguard/src/commands/status_api.rs`
- `platform/server/src/services/devguard.rs`
- `platform/server/src/services/gateway_hooks.rs`
- `platform/server/src/services/fs_guard.rs`
- `platform/server/src/services/exec_guard.rs`
- `platform/server/src/services/policy_config.rs`
- `platform/server/src/services/anthropic_gateway.rs`

### Tests and gates

- `platform/server/tests/prod_dogfood_http.rs`
- `platform/server/tests/rbac_http.rs`
- `platform/server/tests/multi_tenant_http.rs`
- `platform/server/tests/open_auth_http.rs`
- `platform/server/tests/enterprise_security.rs`
- `platform/scripts/prod-readiness-gate.sh`
- `platform/scripts/prod-dogfood-smoke.sh`
- `platform/scripts/tt-wc-prod-gate.sh`
- `plugins/tracetramp/tests`
- `plugins/witnessctl/tests/witness_bundle_smoke.rs`

---

## 19. Final conclusion

Connector OS has enough real implementation to justify continued product
investment and customer pilots. The core value proposition—governed AI traffic,
content-addressed memory, plugin workloads, operational control, evidence, and
developer guardrails—is coherent and differentiated.

The next phase should not prioritize adding more secondary products. The
highest-value work is to make the existing four-part system internally true:

- one verified identity and tenant model;
- one mandatory admission boundary;
- one canonical decision/evidence envelope;
- one honestly verifiable proof story;
- secure management-plane defaults;
- behavioral security tests;
- a precise distinction between prevention, detection, integrity, and
  certification.

If those boundaries are fixed, Connector OS can credibly become a governed AI
runtime for self-hosted enterprise environments. If they are not fixed, the
large feature surface and strong marketing language will create false assurance
and make enterprise security review harder than the underlying engineering
deserves.
