# Connector OS — Product Roadmap & Engineering Plan

> **Intelligence first.** Connector OS is the install/runtime/Hub shell for a **distributed intelligence system** — chartered principals, cages keyed by intelligence mark, evidence institutions — not a process firewall. Architecture + security waves: [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md).
>
> **One install. One control plane. One artifact.** Connector OS ships its own runtime (microVM), its own supervisor, its own admin UI. Plugins are standalone tools the OS manages. Workflows are the operator's "themes". This is WordPress for AI governance — except we never ask anyone to install Docker.
>
> **Designed for 100+ plugins from day one.** First-party plugins (TraceTramp, WitnessCtl, DevGuard, …) and third-party AGOS plugins authored by anyone are equal citizens. Same manifest, same lifecycle, same isolation, same Hub. The infra is built so that 100 idle plugins cost almost nothing and 100 active plugins still fit on a laptop.

## Naming

- **Connector OS** — the product (kernel + supervisor + microVM + dashboard + Hub).
- **AGOS** (Agent Operating System) — the stable API/ABI surface Connector OS exposes to plugin authors. "An AGOS plugin" = any plugin built against the AGOS contract; runs identically inside Connector OS regardless of who wrote it.
- **CLS / CCL** — Connector's own **workflow / contract language** (lexer → parser → sema → lower → emit pipeline already in `oss/connector/crates/connector-engine/src/cls/ccl_*.rs`). Workflows in Connector OS are CLS programs; the dashboard's drag-and-drop builder is just a visual front-end that emits CLS.
- **CNP** — Connector Network Protocol (`platform/server/src/cnp/stack.rs`, `cnp_surface.rs`). The layered transport that carries events between plugins, agents, and cells when a CLS workflow fires. Plugins talk over CNP; CLS programs are the choreography.
- **Connector Hub** — the public, signed registry where AGOS plugins, CLS workflow packages, and templates are published, searched, rated, and downloaded.

---

## 0. Why we are doing this (the chaos audit)

Today's stack feels like a puzzle because **there is no owner of the lifecycle**:

1. `connector-platform`, `tracetramp`, `witnessctl`, `devguard`, the Leptos `dist/` build, and three separate `docker-compose.yml` files are independent products glued together by env vars.
2. Tokens (`*_ADMIN_TOKEN`) must match across ≥2 places with nothing enforcing it.
3. Two "Connector" surfaces in the lab (`tt-premium-connector` container and the host `:9091` server). End users cannot tell which is "the" Connector.
4. UI `dist/` lives on disk. Forget to rebuild it → stale wasm.
5. Every restart turns into a debugging session because there is no `connector start | status | upgrade`.
6. Router fallthrough on `/api/v1/*` was returning the SPA `index.html` (HTTP 200 + HTML) → "Parse error: expected value at line 1 column 1" in the dashboard.
7. Stale root-owned `target/` defeats `cargo build` silently.
8. There is no single artifact a user can download and run.

**None of the application logic is broken. What is broken is that there is no product, only a kit of parts.**

---

## 1. The vision (final outcome)

### 1.1 What an operator does

A new operator:

1. Downloads **one tarball**: `connector-os-<ver>-x86_64-linux.tar.gz`.
2. Runs `connectorctl start`.
3. Opens `https://localhost:9091` — already in **dev mode**, with a sample admin account printed once on the terminal.
4. Goes to **Plugins** → clicks **Install** on TraceTramp / WitnessCtl / DevGuard / any of the 100+ Hub plugins / a community AGOS plugin.
5. Goes to **Service Map** → sees every plugin's port, route, proxy, health, last-seen, tags.
6. Goes to **Workflows** → clicks **New** → composes a flow that wires plugins together.
7. Records the lab demo without ever opening a terminal.

### 1.2 What an AGOS plugin author does

A plugin developer:

1. Runs `cargo connector new my-plugin` (or `cargo connector new vendor/slug`) — gets a working Rust scaffold, `plugin.toml`, and a minimal `main` binary (`cargo-connector` crate).
2. `connectorctl plugin run --dev` boots their plugin inside Connector OS in a microVM with hot reload.
3. `connectorctl plugin verify` runs the certification harness (manifest valid, signature, capability scan, resource budget, idle behaviour).
4. `connectorctl plugin publish` signs the `.cpkg` and pushes it to **Connector Hub**.
5. End users find it by search in the dashboard's **Add New** flow and install with one click.

That is the bar — **on both sides** of the platform.

---

## 2. The mental model

| WordPress | Connector OS |
|---|---|
| `wp-admin` + `wp-includes` | `connector-platform` (kernel) |
| `wp-content/plugins/<slug>/` | `<install>/plugins/<id>/` |
| `Plugin Name` PHP header | `plugin.toml` manifest |
| Hooks (actions/filters) | typed plugin contract over **CNP** |
| wordpress.org/plugins | Connector Hub (signed registry) |
| Themes | Workflows authored in **CLS** (drag-and-drop or hand-written) |
| Gutenberg block editor | **CLS Workflow Builder** (drag-drop ⇄ CLS source) |
| WP-CLI | `connectorctl` |

**Roles:**

- **Kernel** — boot, supervise, mint plugin tokens, run migrations, proxy `/api/v1/plugins/*`, aggregate health, enforce capabilities, single sign-on.
- **Plugins** — one artifact + one `plugin.toml`; declare routes, UI pages, migrations, capabilities; never read user env directly.
- **Workflows** — first-class declarative YAML stored in the kernel; trigger on plugin events; act on plugin APIs.
- **Marketplace** — signed `.cpkg` packages; install/upgrade/rollback through the UI.
- **Users** — `superadmin | operator | auditor | viewer`, capability-checked on every API call.

---

## 2A. Built for 100+ plugins (first-party + community AGOS plugins)

This is the load-bearing section. Every architectural decision below is judged against the 100-plugin test: *can the operator install 100 plugins, leave 80 idle, and have 20 active without the kernel, the host, or the dashboard breaking down?*

### 2A.1 Invariants (we never violate these)

1. **Same lifecycle for every plugin** — first-party, paid, community, user-authored. Identical manifest, identical install flow, identical isolation, identical UI surface. There is no "internal special case".
2. **Stable AGOS ABI** — kernel exposes a versioned, semver-governed API surface (`agos.v1`, `agos.v2`, …). Plugins declare which version they need. The kernel runs **multiple AGOS versions side-by-side** so a plugin built against `agos.v1` keeps working when the kernel ships `agos.v2`.
3. **Idle plugins are free** — an installed-but-not-used plugin must consume effectively zero RAM/CPU. Plugins boot on first request (lazy start) and suspend after an idle window.
4. **Active plugins are bounded** — every plugin declares `memory_mb`, `vcpus`, `max_concurrency`. Kernel enforces these; offending plugins are throttled, not the host.
5. **No plugin can crash the kernel** — strong isolation (microVM by default, wasm option), capability gates, and crash recovery with backoff.
6. **No plugin can read another plugin's data** — separate DB schemas, separate filesystem overlays, separate vsock channels. Cross-plugin calls go through declared workflows or kernel APIs only.
7. **No plugin gets ambient credentials** — kernel mints scoped tokens per request, capabilities checked on every call.
8. **One operator UI, regardless of plugin count** — the dashboard scales (search, filter, group, paginate) so 100 plugins are as usable as 5.

### 2A.2 Lifecycle for idle / active plugins (the "100 plugins on a laptop" trick)

Three runtime tiers, chosen automatically per plugin manifest + observed traffic:

- **Cold** — installed, manifest registered, migrations run, but no process. RAM cost: 0. Triggered by first request → kernel launches microVM, replays handshake, request waits up to `cold_start_budget_ms` (default 800 ms).
- **Warm** — microVM running, ready to serve. Reset to **Cold** after `idle_window` (default 5 min, configurable per plugin).
- **Hot** — pinned by operator or workflow; never sleeps; reserved RAM/CPU.

Default policy: **first-party = Hot**, **community = Warm with sleep**, **rarely-used = Cold**.

### 2A.3 Shared microVM tier (for tiny plugins)

Plugins that opt in (`runtime.shared = true` and a small RAM budget) run as **subprocesses inside one shared microVM** (the "plugin condo"). Used for slack-style notifiers, formatters, light webhook handlers. 50+ plugins in one VM is realistic. Heavier plugins (TraceTramp, WitnessCtl, anything with sqlite or LLM calls) keep a dedicated microVM.

### 2A.4 AGOS ABI versioning

- ABI is published as a Rust crate `agos-abi` and a JSON schema; semver applies.
- Kernel keeps the last **N** ABI versions live (default `N=3`). Plugins declaring `min_kernel_abi = "agos.v1"` keep working until N rotates.
- Breaking ABI change = major kernel version bump + 6 month deprecation window + dashboard warning + Hub flag on affected plugins.
- Stability tested by `connectorctl plugin verify` against the current kernel's `agos.vN`.

### 2A.5 Plugin namespacing & dependencies

- Plugin id format: `<vendor>/<slug>` (e.g. `connector/tracetramp`, `acme/slack-notifier`). Reserved namespace: `connector/*`.
- Plugins may declare `[depends]` on other plugin ids with semver ranges. Kernel resolves at install time and refuses to install on conflict.
- Plugins may declare `[provides]` (e.g. `provides = "queue"`) and other plugins consume that capability — kernel routes through the named provider.
- DB schemas are namespaced by plugin id; cross-plugin SQL is forbidden.

### 2A.6 Permissions & capability model (untrusted code)

- Capabilities are coarse: `aapi.evaluate`, `audit.write`, `trace.read`, `ui.embed`, `network.outbound:<host>`, `secret.read:<scope>`, `events.subscribe:<topic>`, `actions.dispatch:<plugin>`.
- Manifest declares them; install dialog asks the operator to grant them; kernel enforces them at the call site.
- Untrusted (community) plugins default to `runtime = "wasm"` or `runtime = "microvm"`; never `subprocess` unless the user explicitly trusts them.
- Egress firewall on the microVM denies outbound by default; allowlist driven by `network.outbound`.

### 2A.7 Observability & health rollup that scales

- One topic bus internal to kernel; plugins emit structured events to it; dashboard subscribes once and fan-outs.
- `/api/v1/health` returns aggregated status with per-plugin breakdown but the page itself is paginated.
- Service Map page (Section 5.2) handles 100+ rows: virtualized scroll, server-side filter, group by `vendor` / `state`.
- Logs / traces stay in the plugin's microVM; kernel pulls on demand (`View logs` action), not by default.

### 2A.8 Hub at scale (registry side)

- Search by name / tag / capability / vendor / license / rating.
- Semver resolver in the client: `connectorctl plugin install acme/slack-notifier@^1.2`.
- Signed by author key; verified by Hub root key; verified again by kernel at install.
- Rate limits per anonymous IP; auth required for publish; per-vendor namespaces.
- Public + private Hubs (enterprises run their own Hub mirror; airgap export is a `.cpkg` bundle).
- Plugin pages in the dashboard show: README, screenshots, capability list, version history, signing fingerprint, install count, ratings.

### 2A.9 Plugin certification (gate before Hub)

`connectorctl plugin verify` runs and must pass before publish:

1. Manifest schema valid; namespace + slug not reserved.
2. ABI compatibility against latest kernel.
3. Resource budget honored (`memory_mb`, `vcpus`, `max_concurrency`).
4. Idle behaviour: plugin sleeps within `idle_window` and wakes correctly.
5. Capability declarations match observed syscalls (no hidden network, no unexpected file access).
6. Ed25519 signature present and valid.
7. License & SPDX tag present.
8. Smoke test: plugin starts, `/health` is 200, `/admin/*` answers per manifest.
9. UI bundle (if any) loads without console errors.
10. No reserved kernel routes shadowed.

Failing checks block `connectorctl plugin publish`. The same harness runs in CI for first-party plugins, so internal plugins follow the same standard.

### 2A.10 Resource governance

- Every plugin VM is pinned with cgroups: `memory.max`, `cpu.weight`, `io.weight`.
- Per-plugin quota for kernel API calls (rate-limit per capability per minute).
- Per-plugin disk quota in its overlay rootfs.
- Per-plugin egress bandwidth cap (configurable; default low, raise via grant).
- Operator dashboard shows current usage vs budget per plugin; offenders flagged in the Service Map.

---

## 2B. Workflows: CLS + CNP + drag‑and‑drop (one engine, two front‑ends)

Workflows are not a new system. They are the existing **CLS** language and the existing **CNP** transport, made first‑class in the dashboard.

### 2B.1 Architecture

```
┌──────────────────────────────────┐    ┌────────────────────────────────┐
│  Drag‑and‑drop Workflow Builder  │ ⇄  │  CLS source editor (Monaco)    │
│  (Leptos · cls_builder.rs)       │    │  (cls_packages.rs)             │
└──────────────┬───────────────────┘    └──────────────┬─────────────────┘
               │  emits / round‑trips                   │
               ▼                                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          CLS / CCL pipeline                          │
│  ccl_lexer → ccl_parser → ccl_sema → ccl_opt → ccl_lower → ccl_emit  │
│  (oss/connector/crates/connector-engine/src/cls/)                    │
└──────────────────────────────────────┬───────────────────────────────┘
                                       │  compiled CCL package
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CLS engine (platform/server/src/cls/engine.rs)                      │
│  · resolves capabilities       · enforces policy                     │
│  · dispatches actions on plugins via CNP                             │
│  · subscribes to plugin events on CNP                                │
└──────────────────────────────────────┬───────────────────────────────┘
                                       │  CNP frames
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│  CNP stack (platform/server/src/cnp/stack.rs · cnp_surface.rs)       │
│  L1 transport · L2 framing · L3 routing · L4 sessions · L5 capabilities │
└──────────────────────────────────────┬───────────────────────────────┘
                                       ▼
                  TraceTramp · WitnessCtl · DevGuard · 100+ AGOS plugins
```

The drag‑and‑drop builder and the CLS source editor are **two views over the same artifact**. The compiled CCL package is the only thing the engine runs.

### 2B.2 Two ways to author the same workflow

- **No‑code** — drag‑and‑drop in the builder. Nodes are typed actions/triggers exported by installed plugins (their manifest's `[provides]`/`[capabilities]`). Edges are CNP topics. Saves as a CLS package.
- **Code** — write CLS directly in the source editor. Inline policy, loops, conditions, retries, time windows. Same package format.
- **Round‑trip** — clicking a node opens its CLS snippet; editing CLS source updates the visual graph. Builder shows a warning when CLS uses constructs the visual layer cannot fully represent (e.g. complex pattern matching) and falls back to a "code block" node.

### 2B.3 Plugins expose their workflow surface declaratively

A plugin's `plugin.toml` declares what the workflow layer can use:

```toml
[workflow.actions]
approve   = { input = "ApprovalRequest",  output = "Decision" }
reject    = { input = "ApprovalRequest",  output = "Decision" }
quarantine = { input = "ApprovalRequest", output = "Quarantine" }

[workflow.events]
"approvals.requested" = { payload = "ApprovalRequest" }
"approvals.resolved"  = { payload = "Decision" }
```

The kernel registers these on the CNP topic bus. The drag‑and‑drop builder reads them to populate its node palette. Operators never wire a plugin manually — installing a plugin makes its actions/events appear automatically.

### 2B.4 CNP as the runtime fabric

- Every workflow trigger is a **CNP subscribe**.
- Every workflow action is a **CNP dispatch** to a plugin.
- Cross‑plugin calls inside a workflow always go through CNP (never direct host calls), so capability checks, audit logs, and back‑pressure are uniform.
- CNP carries the kernel‑minted scoped token for every hop, so plugins never see operator credentials.

### 2B.5 Lifecycle of a CLS workflow

`DRAFT → COMPILED → STAGED (dry‑run) → ENABLED ↔ PAUSED → ARCHIVED`

- **Dry‑run** replays recent CNP events through the workflow without dispatching real actions; produces a diff of what *would* have happened.
- **Atomic enable**: kernel hot‑swaps the running CCL package; in‑flight executions finish under the old version.
- **Versioning**: every save is a new CCL package version; rollback is one click.

### 2B.6 CLS workflow packages on the Hub

- A CLS workflow can be packaged as a `.cpkg` (same format as plugins) and published to **Connector Hub**.
- Workflow packages declare their plugin dependencies (`requires = ["connector/tracetramp@^1", "connector/witnessctl@^1"]`); install resolves them.
- Examples: "HITL Approve‑and‑Audit", "PII Redaction Pipeline", "Incident → Slack → Jira".
- Operators install a workflow the same way they install a plugin — one click.

### 2B.7 Existing assets to promote (not rebuild)

- `platform/ui-leptos/dashboard/src/pages/cls_builder.rs` — drag‑and‑drop builder; needs node palette wired to plugin manifests.
- `platform/ui-leptos/dashboard/src/pages/cls_packages.rs` — source editor + package list.
- `platform/ui-leptos/dashboard/src/pages/cls_catalog.rs` — Hub‑sourced template catalog.
- `platform/ui-leptos/dashboard/src/pages/cls_execution.rs` — run history, traces, dry‑run output.
- `platform/server/src/services/cls.rs` + `platform/server/src/cls/*` — compile, install, execute.
- `platform/server/src/cnp/stack.rs` + `services/cnp_surface.rs` — runtime transport.

These already exist. Phase 3 wires them into the operator‑facing **Workflows** tab (Section 5) and the AGOS plugin contract (Section 6).

---

## 2C. Settings, secrets & LLM control — all from the UI (no env files)

Like every modern production product (Vercel, Supabase, Linear, GitHub), Connector OS settings live **inside Connector OS**, not in shell exports the operator has to align by hand. Env vars exist only for first‑boot bootstrap and CI; everything else is dashboard‑managed.

### 2C.1 The Secret Vault (already in the codebase — promote to UI)

The kernel already exposes `/api/v1/infra/vault/{store,resolve,redact,status}` (see `services/infra.rs`). The work is to give it a real UI and make it the only source for secrets:

- **Settings → Secrets** page in dashboard:
  - Categories: `LLM keys`, `Plugin auth`, `Payment (Stripe)`, `JWT signing`, `TLS certs`, `OAuth providers`, `Webhook secrets`, `Custom`.
  - Add / view‑masked / rotate / revoke / view audit log per secret.
  - "Test" button validates the secret against its target service before saving (e.g. ping OpenAI with the key).
- **Encryption at rest** with kernel master key. Master key options:
  - Auto‑generated, stored in OS keyring on first boot (default for self‑hosted).
  - HSM / TPM backed (enterprise).
  - Cloud KMS (AWS/GCP/Azure) for managed deployments.
- **Capability‑gated reads**: a plugin requests a secret via capability `secret.read:<scope>`; gets a **handle** (not the raw value) over CNP. Kernel injects the secret at the call site.
- **Audit log**: every read and write logged with operator id, plugin id, time. Visible in the same page.
- **Rotation**: schedule rotation per secret; on rotation, kernel re‑encrypts and notifies subscribers.
- **No secret in any env file after first boot**. `connectorctl bootstrap` migrates legacy env vars (e.g. `STRIPE_SECRET_KEY`, `CONNECTOR_TRACETRAMP_ADMIN_TOKEN`, `CONNECTOR_LLM_API_KEY`) into the vault and removes them from the on‑disk env on success.

### 2C.2 LLM control plane — switch + auto‑fallback from the UI

The `llm_router` / `adaptive_router` already exists in the kernel (`services/gateway.rs`, `services/monitor.rs`, `state.rs`). The work is the operator surface:

- **Settings → LLMs** page in dashboard:
  - Add provider: OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Google Vertex, **local Ollama / vLLM**, custom OpenAI‑compatible endpoint.
  - Per‑provider: API key (from the Secret Vault), model list, base URL, custom headers, timeout, cost per 1k tokens.
  - **Test connection** button.
- **Routing rules** UI (auto‑switching as a first‑class feature, not a hidden config):
  - Primary / fallback chain (e.g. `OpenAI gpt‑4o → Anthropic claude‑sonnet → local llama3:70b`).
  - Triggers: 5xx for N seconds, latency p95 > X ms, monthly cost cap exceeded, region/jurisdiction policy, content policy match.
  - Per‑plugin override (TraceTramp uses GPT‑4, WitnessCtl uses Claude, DevGuard uses local).
  - Per‑workflow override (CLS workflow can `pin_provider("anthropic", "claude‑sonnet")`).
- **Live observability**: per‑provider latency, tokens, cost, error rate; pinned chart in the page.
- **Cost guardrails**: monthly budget per provider; soft warning at 80%, hard stop at 100% (kernel returns `provider_budget_exhausted` and falls back).
- **Privacy / region tags**: providers tagged `us`, `eu`, `local`. Workflows / plugins can require a tag.

### 2C.3 General UI‑first settings (no chaos)

Everything an operator could plausibly configure is in **Settings → …**:

- General (instance name, timezone, default language)
- Secrets (Section 2C.1)
- LLMs (Section 2C.2)
- Networking (TLS certs, public URL, trusted proxies, ports)
- Identity (OIDC/SAML SSO, role mapping, password policy, 2FA)
- Plugins (per‑plugin Configure pages — generated from manifest)
- Workflows (defaults, dry‑run windows, alerting)
- Backup & restore (snapshot now, schedule, retention, restore)
- Telemetry (opt‑in product analytics, error reporting)
- License & updates

Bootstrap env (`CONNECTOR_PRESET`, `CONNECTOR_PORT`, `CONNECTOR_DATA_DIR`) is the **only** allowed env surface — and even those are seeded by the installer; the user never types them manually.

---

## 2D. Removal & deep cleanup audit (what we delete from the repo)

This is the concrete deletion list, audited against the current tree. Anything that duplicates a built‑in capability or contradicts the "one product, one runtime" rule is removed.

### 2D.1 Docker / Compose — collapse to `lab/` only

Reason: microVM is the production runtime; Docker is a *lab convenience* selected by `connectorctl start --runtime=docker`. We need exactly one set of compose files, scoped to `lab/`.

Delete or move to `lab/`:
- ~~`advanced-lab/docker-compose.extend.yml`~~ → **`lab/advanced.yml`** (done)
- ~~`plugins/tracetramp/docker-compose.yml`~~ (done — Phase 1.6: **`lab/docker-compose.premium-lab.yml`** is the lab base; scripts use `lab/advanced.yml` as overlay)
- ~~`platform/deploy/docker-compose.yml`~~ → deleted
- ~~`platform/deploy/docker-compose.observability.yml`~~ → deleted
- ~~`platform/deploy/docker-compose.prod.yml`~~ → deleted
- ~~`oss/docker-compose.yml`~~ → deleted
- ~~`deploy/docker-compose.yml`~~ → deleted

Dockerfiles (collapsed under `lab/` — done):
- ~~`platform/deploy/Dockerfile`~~ → deleted
- ~~`oss/Dockerfile`~~ → **`lab/Dockerfile.connector`** (build context still `oss/`)
- ~~`advanced-lab/{agents,runner}/Dockerfile`~~ → **`lab/Dockerfile.agents`**, **`lab/Dockerfile.lab-runner`**; ~~`advanced-lab/openfang/Dockerfile`~~ / ~~`advanced-lab/lab-llm/Dockerfile`~~ removed (unused by default Compose)
- ~~`plugins/tracetramp/Dockerfile`~~ / ~~`plugins/witnessctl/Dockerfile`~~ → **`lab/Dockerfile.tracetramp`**, **`lab/Dockerfile.witnessctl`**

### 2D.2 Grafana / Prometheus — replaced by built‑in observability

Reason: Connector OS already exposes `/metrics` (Prometheus format), structured traces, and ships the dashboard. Bundling external Grafana + Prometheus duplicates every panel and forces operators to run two more services for no gain.

Delete:
- ~~`plugins/tracetramp/monitoring/prometheus.yml`~~ (done — optional Prometheus/Grafana **services** also removed from `plugins/tracetramp/docker-compose.yml`)
- ~~`platform/deploy/prometheus/recording_rules.yml`~~ / ~~`alerts.yml`~~ (done)
- ~~`platform/deploy/grafana/dashboards/connector-agents.json`~~ (done)
- ~~`deploy/grafana/provisioning/datasources/prometheus.yml`~~ / ~~`deploy/grafana/connector-dashboard.json`~~ (done)
- ~~The whole `platform/deploy/prometheus/` and `deploy/grafana/` and `plugins/tracetramp/monitoring/` directories.~~ (done)

Replacement (already in tree, needs UI polish):
- Keep `/metrics` Prometheus endpoint (still useful for users who run external Prom).
- Built‑in metrics store inside the kernel (small TimescaleDB‑style ringbuffer).
- Built‑in dashboard charts: per‑plugin latency, RPS, errors, cost, microVM RAM/CPU.
- Built‑in alert rules edited in the UI (Settings → Alerts), delivered via the existing `AlertChannel` (Slack/PagerDuty/Webhook).

### 2D.3 Kubernetes manifests — microVM replaces them

Delete:
- ~~`plugins/tracetramp/k8s/deployment.yaml`~~ / ~~`configmap.yaml`~~ (done)
- Any other `k8s/` directory under `plugins/*/`.

Reason: scale‑out story for Connector OS will be **multi‑node Connector cluster** over CNP, not Kubernetes. K8s manifests today are aspirational and out of date.

### 2D.4 Env files & legacy bootstrap

Delete or shrink:
- ~~`platform/deploy/.env.example`~~ → **bootstrap‑only** (`CONNECTOR_PRESET`, `CONNECTOR_HOST`, `CONNECTOR_PORT`, `CONNECTOR_DATA_DIR`, optional license vars). No Stripe / JWT / LLM secrets — UI vault only.
- All scripts that export `CONNECTOR_TRACETRAMP_ADMIN_TOKEN`, `STRIPE_SECRET_KEY`, `CONNECTOR_LLM_API_KEY`, `CONNECTOR_JWT_SECRET`, etc. → either remove or rewrite to read from `connectorctl secret get`.

Files in scope (already greppable):
- `plugins/tracetramp/scripts/e2e_lab_video.sh`
- `plugins/tracetramp/scripts/smoke_lab_io.sh`
- `advanced-lab/runner/lab_runner/preflight.py`
- `advanced-lab/runner/lab_runner/smoke.py`
- `platform/scripts/plugins-dev-stack-up.sh`

### 2D.5 Deprecated route aliases & dead code

Done (Phase 0.7.6):
- ~~`platform/server/src/router.rs`: `with_deprecation_headers` + merged deprecated sub‑routers~~ — removed; legacy `/verify/*`, `/secrets/*`, `/orchestrator/*`, `/economy/reputation/*` are plain routes on the main API router (no `Deprecated:` headers). Prefer `/safety/formal/*`, `/infra/vault/*`, `/infra/orchestrator/*`, `/infra/reputation/*`.
- Removed duplicate `/memory/*2` suffix routes; dropped dead `services::memory` handlers `recall_memory`, `knowledge_query`, `interference_detect` (canonical recall/query/interference already use `memory2`).

### 2D.6 Old install / GTM noise outside scope

These are not deleted, but moved out of the runtime tree so they don't pollute build/test:
- `ppt/`, `platform/gtm-presentation/`, `platform/docs/landing-page/web/`, `platform/docs/connector-youtube-deck/` → keep, but exclude from `cargo` workspace and from the release tarball.

Done (Phase 0.7.7): there is **no repo-root Cargo workspace** (the kernel’s `platform/server` path deps inherit OSS workspace metadata; a root workspace would break that). These trees stay **npm-only** (no `Cargo.toml`); CI enforces that and mirrors the same paths in **`scripts/release-tar-excludes.txt`** for future `make package` / release tar steps.

### 2D.7 `.gitignore` updates

A unified `.gitignore` at repo root must add:

```
# build artifacts
target/
**/target/
.target-agent/
**/dist/                           # Leptos builds (UI is embedded; dist is reproducible)
**/node_modules/

# secrets & local state (never committed; UI is source of truth)
*.env
*.env.local
*.env.*.local
.secrets/
secrets.json
data/
~/.local/share/connector/

# microVM artifacts
vendor/firecracker/firecracker-*
platform/microvm/rootfs/*.img
platform/microvm/rootfs/build/

# IDE / OS noise
.vscode/.cache/
.idea/
.DS_Store
*.swp

# legacy compose / observability (until Phase 0 deletion lands)
**/docker-compose*.yml
**/Dockerfile
**/prometheus/
**/grafana/
**/k8s/
```

(After Phase 0 deletes them, the last block becomes redundant — that's fine; we keep the rules so a future regression doesn't re‑introduce them.)

### 2D.8 The single‑artifact rule

After Phase 1 + Phase 5, **the only release artifact** is `connector-os-<ver>-<arch>.tar.gz` containing:
- `connector-platform`, `connectorctl`
- Embedded dashboard SPA
- `firecracker` binary + Alpine rootfs
- First‑party plugins (`tracetramp`, `witnessctl`, `devguard`)
- Reference CLS workflow templates
- Example `connector.yaml` (bootstrap‑only, 3–5 keys)

No Docker images. No Helm charts. No Grafana JSON. No env templates beyond bootstrap. If a file is not in that tarball or its build inputs, it does not ship.

---

## 2E. Cage‑internal DNS & plugin addressing (`*.cnktros`)

Every plugin has a **stable, cage‑internal name** the kernel resolves; nothing outside the cage can reach it. The same name is used by CLS workflows, CNP routing, the dashboard proxy, and the Service Map. There is **one** identity per plugin instead of port + IP + token + URL fragments scattered across env files.

### 2E.1 The naming model

```
                   public origin (operator chooses)
            ────────────────────────────────────────
            http(s)://<host>:<port>/plugin/<slug>/...
                              │
                              │   kernel reverse proxy
                              ▼
                    cage origin (kernel‑private)
            ────────────────────────────────────────
                 http://<slug>.cnktros/admin/...
                              │
                              │   internal DNS + CNP routing
                              ▼
                       plugin microVM (vsock / loopback)
```

- **Cage TLD**: `.cnktros` (configurable via `connector.yaml` → `cage_tld`; default `cnktros`). Reserved name; kernel refuses to resolve it through any external resolver.
- **Cage host**: `<slug>.cnktros` per plugin (e.g. `tracetramp.cnktros`, `witnessctl.cnktros`, `acme-slack-notifier.cnktros`). Auto‑derived from the plugin id slug; overridable in manifest `[addressing] cage_host = "..."`.
- **Public path**: `/plugin/<slug>/*` under whatever origin the operator binds (`localhost:9091`, `connector.acme.corp`, custom). Kernel reverse‑proxies it to the cage host.
- **Optional external alias**: operator can map a public domain to a cage host via Settings → Networking, e.g. `tracetramp.acme.corp → tracetramp.cnktros`. Plugin author never hard‑codes a public URL.

### 2E.2 Why this matters

1. **No hard‑coded public URLs in manifests.** Plugin authors do not know whether the user runs on `localhost`, an intranet, behind Cloudflare, or under their own domain. The cage host is the only stable identity.
2. **CLS workflows + CNP both reference plugins by cage name**, not port or IP. A workflow saying `tracetramp.cnktros/admin/quarantine` keeps working when the operator changes ports, swaps backends, or adds an external alias.
3. **Default deny from the public internet.** `*.cnktros` does not resolve outside the cage. Plugin admin endpoints are unreachable except through the kernel's authenticated reverse proxy.
4. **Tenant isolation later.** A multi‑tenant Connector OS just gives each tenant a unique cage TLD (e.g. `t1.cnktros`, `t2.cnktros`); plugin names stay readable.
5. **Service Map gets a real legend.** Every row already has the cage host, the public path, and the runtime backend — operators can copy‑paste the cage host into a CLS node and it Just Works.

### 2E.3 Kernel responsibilities (mostly already in the tree)

The existing `services::internal_dns` module is the foundation; it currently registers `SVC_API` and similar names. Extend it:

- Register `<slug>.cnktros` for every enabled plugin at lifecycle transition `ENABLED`.
- De‑register on `DISABLED` / `UNINSTALLED`.
- Resolve `<slug>.cnktros` to the plugin's vsock socket (microVM runtime), unix socket (subprocess), or container IP (lab Docker runtime). Caller never sees which.
- Refuse to resolve `*.cnktros` via the host's `/etc/resolv.conf`. Kernel runs an in‑process resolver that CNP and the reverse proxy use; no UDP/53 leaks.
- **Reverse proxy** at `/plugin/<slug>/*`: rewrites Host header, injects kernel‑minted scoped token, forwards to `<slug>.cnktros`.
- **CLS / CNP plumbing**: a CLS node like `dispatch tracetramp.cnktros approve <payload>` routes through CNP using the same internal DNS lookup. No `localhost:19742` anywhere in user‑authored code.

### 2E.4 Custom domains & TLS (Settings → Networking)

Operators get a UI to:
- Bind a public domain (`connector.acme.corp`).
- Optionally map sub‑hosts: `tracetramp.acme.corp → tracetramp.cnktros`. Kernel issues a TLS cert (Let's Encrypt or imported) and reverse‑proxies through.
- Lock down which plugin paths are publicly reachable (default: only `/plugin/<slug>/*` paths flagged `public = true` in the plugin manifest; admin paths stay cage‑only).

Reachable surface example for an operator who buys `acme.corp`:

| Public URL | Maps to | Audience |
|---|---|---|
| `https://connector.acme.corp/` | dashboard | operators, SSO‑gated |
| `https://connector.acme.corp/api/v1/*` | kernel API | bearer‑gated |
| `https://connector.acme.corp/plugin/tracetramp/` | `tracetramp.cnktros/` | operators |
| `https://tracetramp.acme.corp/` (alias) | `tracetramp.cnktros/` | operators |
| `https://tracetramp.cnktros/admin/...` | n/a — **cage‑only**, never reachable from outside | kernel + CNP only |

### 2E.5 What this changes in the roadmap

- Plugin manifest gains `[addressing]` block (Section 6 above).
- Service Map shows three columns now: `Public path · Cage host · Runtime endpoint`.
- CLS node palette references plugins by cage host, not port.
- Settings → Networking grows a "Custom domains" tab.
- Phase 1 supervisor + Phase 5 microVM both register/deregister cage hosts on lifecycle transitions.

---

## 3. Default dev mode (zero-config first run)

Goal: the very first `connectorctl start` is **immediately usable**, no env files, no token alignment, no manual login.

**Implemented (Phase 1.9 partial):** `connector_profile::bootstrap_configuration` sets **`CONNECTOR_PRESET=local`** when `CONNECTOR_PRESET` is unset, `CONNECTOR_ENV` is not production/pilots, and neither `CONNECTOR_LICENSE` nor `CONNECTOR_LICENSE_KEY` is set — opt out with **`CONNECTOR_DISABLE_AUTO_LOCAL_PRESET=1`**. This pulls in the existing `local` preset (`CONNECTOR_DEV_MODE`, stub LLM unless overridden, etc.).

Behavior on first boot (full §3 target — remaining work):

`
- Detect "no license, no production preset" → set `CONNECTOR_PRESET=local`, `CONNECTOR_ENV=development`, `CONNECTOR_DEV_MODE=1`.
- Generate a random `superadmin` user. Print credentials **once** on the terminal. Persist a hash to `~/.local/share/connector/users.db`.
- Auto-mint admin tokens for every enabled plugin. Tokens never appear in env files.
- Login page always renders **Dev Bypass** button (already done in `platform/ui-leptos/dashboard/src/pages/login.rs`).
- Banner in dashboard: `DEV MODE — switch with: connectorctl mode prod`.
- `connectorctl mode prod` flips runtime mode, requires license, regenerates plugin tokens, removes Dev Bypass.

---

## 4. Micro VM — in-built runtime (no Docker dependency)

### 4.1 Why

Docker is heavy, requires root, blocks airgap users, and makes our "download and run" promise a lie. We ship our own microVM runtime so plugin isolation is **part of the product**, not part of the operator's homework.

### 4.2 What we ship inside the tarball

- **Firecracker** static binary (Apache 2.0) bundled in the artifact.
- A minimal **Alpine-based rootfs** (~30 MB) baked at build time.
- `connector-vm-agent` — runs as PID 1 inside guest, accepts plugin payload + handshake over **vsock**.
- One microVM per plugin by default. Configurable to a shared VM with cgroup separation when memory matters more than blast radius.
- ~125 ms boot, ~5 MB memory overhead per VM.

### 4.3 OS support matrix

| Host | Backend |
|---|---|
| Linux x86_64/arm64 | Firecracker direct (KVM) |
| macOS | Apple Virtualization.framework (Hypervisor.framework wrapper) |
| Windows | HyperV via WSL2-backed Firecracker |

All exposed through one trait: `MicroVmRuntime` (in new crate `platform/microvm/`). Subprocess + Docker runtimes implement the same trait so the supervisor doesn't care which is active.

### 4.4 How a plugin runs in a microVM

1. Kernel mints `(admin_token, management_url, kernel_callback_url)`.
2. Supervisor copies the plugin binary into the guest rootfs overlay.
3. Spawns a Firecracker VM with that overlay.
4. Inside, `connector-vm-agent` execs the plugin with the handshake env.
5. Health probes go over vsock; logs piped back over vsock.
6. UI shows `Plugin <id> running in microVM <vm-id> · 18 MB · 4 ms p99`.

### 4.5 Lab fallback (for video demos that need Docker visibility)

`connectorctl start --runtime=docker` switches isolation backend to Docker. Same operator UX, same dashboard, same APIs — just a different `MicroVmRuntime` impl.

### 4.6 Path to first working microVM (work order)

**Started (kernel control-plane scaffolding):** `services/kernel_host.rs` now exposes microVM cell/shard scheduler + hardware usage rollups:
- `POST /api/v1/kernel/microvm/cells`
- `POST /api/v1/kernel/microvm/shards`
- `POST /api/v1/kernel/microvm/agents/:pid/schedule`
- `POST /api/v1/kernel/microvm/agents/:pid/usage`
- `GET /api/v1/kernel/microvm/topology`
- `GET /api/v1/kernel/microvm/rollup`
- `GET /api/v1/kernel/microvm/carpenter-plan`

This enforces starter constraints (`<=2 cells/core`, shard CPU budget default `70%`, 10–20 agents per shard target, replica plan suggestions) and records resource usage by agent/cell/shard/core.

Runtime contract now wired: control plane stores and hot-switches isolation backend `internal|docker_lab` (`GET/POST /api/v1/runtime/isolation`), includes runtime backend in `/health`, `/api/v1`, and `/api/v1/runtime/mode`, and keeps core services Docker-independent by default (`internal`). **`GET /api/v1/runtime/isolation`** also returns **`operator_env`** (normalized **`CONNECTOR_DOCKER_LAB_EGRESS`**, **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE`**, **`CONNECTOR_PLUGIN_RUN_BACKEND`**, tier idle suspend ms — same helpers as **`plugins/status`** `phase_5_operator`). **CI:** `.github/workflows/connector-platform-kernel.yml` runs **`docker_egress`** unit tests (`phase5_operator_env`).

1. Bundle Firecracker binary in `platform/server/build.rs` (download checksummed release tarball at build time, vendor it under `vendor/firecracker/`).
2. Bake rootfs via `mkfs.ext4` + Alpine miniroot at build time (`platform/microvm/rootfs/`).
3. Build crate `platform/microvm/` wrapping the Firecracker REST API (Tokio + hyper unix).
4. Implement `MicroVmRuntime` trait with `Subprocess`, `Docker`, `Firecracker` impls.
5. Make `Firecracker` the default in production manifest; `Subprocess` default in dev.
6. Smoke test (`tests/microvm_smoke.rs`): launches a VM, runs `cat /etc/os-release` over vsock, prints kernel version. CI gate.

---

## 5. UI fixes (operator polish)

### 5.1 Header health indicator (the awkward badges)

Current header shows `TRUST | ALICE | AGENTS | COV | DEPLOY` chips that are visually noisy and rarely change. Replace with **one composite Health pill**:

- Single pill: green/amber/red dot + label `Healthy` / `Degraded` / `Down`.
- Click expands a popover with subsystem rows (Trust chain, Agents, Coverage, Deployments, Plugins).
- Drives off **one** source: `/api/v1/health` rollup.
- Persistent banner only when state ≠ green.

File to rewrite: `platform/ui-leptos/dashboard/src/components/header_health.rs` (new). Remove the per-badge components.

### 5.2 Service Map page (the "DNS-like" page, productionized)

Promote `internal_dns` + `plugins_status` into a single first-class page at `/admin/service-map`:

- **Table columns**: Plugin · **Cage host (`<slug>.cnktros`)** · **Public path (`/plugin/<slug>`)** · External alias · Runtime backend (microVM/subprocess/docker/wasm) · Auth · Health · Last seen · Tags · Actions.
- Live updates via SSE.
- Actions per row: **Open admin · Restart · View logs · Copy cage host · Edit alias**.
- Topology view (mermaid or react-flow style) showing **operator origin → kernel reverse proxy → cage hosts → plugins**.
- Filter chips: `enabled / degraded / disabled / not-installed`, plus by runtime backend.
- One‑click **Copy as CLS node** that puts `<slug>.cnktros` on clipboard for use in the workflow builder.
- This is the page operators look at first when something feels off. It replaces grep through logs.

### 5.3 Plugin installer (repurpose the existing app installer)

The existing app installer flow (in `platform/ui-leptos/dashboard/src/pages/marketplace.rs` and the matching wizard) becomes the **single Plugin Hub** flow used for every plugin install — TraceTramp, WitnessCtl, DevGuard, community plugins, and user-authored plugins.

Steps:

1. **Browse** Hub registry / sideload `.cpkg` / install from URL.
2. **Capability review** screen ("this plugin asks for: `aapi.evaluate`, `audit.write`").
3. **License/payment** screen if commercial.
4. **Resource budget** (RAM, CPU, microVM count).
5. **Install** → microVM provisioned → migrations run → health check → flip to **Enabled**.

### 5.4 Smaller UI polish (track in same phase)

- Plugins sidebar: checkmarks/red dots must drive off `/api/v1/plugins/status`, not local guesses.
- TraceTramp "Control plane" header: align sub-action buttons; merge banner + portal links into one card.
- Approver ID input: persist across page reloads (LocalStorage).
- Empty states: tell the operator what they can do, not just blank text.
- Loading skeletons everywhere a spinner is currently used.

---

## 6. Plugin contract (the AGOS standard every plugin must follow)

```toml
# plugin.toml — the AGOS plugin manifest
[plugin]
id            = "connector/tracetramp"   # vendor/slug — vendor must own the namespace
name          = "TraceTramp"
version       = "1.4.2"                  # semver
author        = "Connector"
license       = "Commercial"             # SPDX tag
min_kernel    = "0.9.0"
agos_abi      = "agos.v1"                # which AGOS surface the plugin uses

[addressing]
# Cage‑internal DNS name. Resolves only inside Connector OS (kernel internal DNS).
# Default: derived from slug → "<slug>.cnktros".
cage_host     = "tracetramp.cnktros"

# Path under the operator's public origin (whatever they bind: localhost, intranet host, custom domain).
# All plugin URLs surfaced to operators are http(s)://<operator-host>:<port>/plugin/<slug>/...
# The kernel reverse-proxies that path → cage_host via internal DNS + CNP.
public_path   = "/plugin/tracetramp"

[runtime]
type          = "microvm"                # microvm | subprocess | docker | wasm
shared        = false                    # true → run in shared "plugin condo" microVM
entrypoint    = "bin/tracetramp"
memory_mb     = 64
vcpus         = 1
max_concurrency = 32                     # kernel will throttle above this
idle_window   = "5m"                     # auto-suspend after this idle period
cold_start_budget_ms = 800

[ports]
admin         = "loopback"               # kernel allocates a free port

[routes]
prefix        = "/plugins/tracetramp"
admin         = "/plugins/tracetramp/admin/*"

[ui]
pages = [
  { path = "/plugins/tracetramp", title = "TraceTramp", role = "operator" }
]

[capabilities]
# Coarse capability tags; install dialog asks operator to grant them.
required = [
  "aapi.evaluate",
  "audit.write",
  "trace.read",
  "events.subscribe:approvals",
  "network.outbound:api.openai.com:443",
]

[depends]                                # other plugins this one needs
"connector/witnessctl" = "^1.0"

[provides]                               # what other plugins can request from us
queue = { protocol = "agos.queue.v1" }

[migrations]
dir           = "migrations/"            # SQL files run in version order

[settings]                               # rendered as a form in the Configure page
schema = "settings.schema.json"

[health]
path          = "/health"
interval      = "5s"

[signing]
pubkey        = "ed25519:..."
```

**Lifecycle**: `UNINSTALLED → INSTALLED → DISABLED → COLD ↔ WARM ↔ HOT (ENABLED) ↔ DEGRADED → STOPPED → UNINSTALLED`.

**Forbidden in a manifest**: ambient env reads, host filesystem paths, wildcard network capabilities, kernel-reserved route prefixes, reserved vendor namespace `connector/*` for non-first-party publishers.

---

## 7. Phased checklist (the master to-do — follow in order)

### Phase 0 — Stop the bleeding & cleanup audit (1–3 days)

- [x] **0.1** `chown -R $USER:$USER platform/server/target` and add CI guard against root-owned `target/` files. Script: `scripts/audit-target-not-root-owned.sh`; runs after kernel tests (`.github/workflows/connector-platform-kernel.yml`) and after `cargo build` in `platform/scripts/ci_beta_gate.sh`.
- [x] **0.2** Pick canonical binary path: `platform/server/target/release/connector-platform`. Document in `README.md`.
- [x] **0.3** Audit every `.merge(...)` / `.nest(...)` in `platform/server/src/router.rs` for SPA-fallthrough; add `.fallback(api_v1_not_found)` where needed (gateway, infra, api_v2).
- [x] **0.4** Regression coverage for unknown nested API routes (JSON 404, never SPA HTML): `platform/server/src/router.rs` → `#[cfg(test)] mod nested_api_fallback_tests` (`cargo test -p connector-platform nested_api_fallback_tests`).
- [x] **0.5** `make doctor` target: chown / port / build / dist freshness checks. Implemented: `make doctor` → `scripts/doctor.sh`.
- [x] **0.6** `scripts/lab_up.sh` — single script: `scripts/lab_up.sh up -d --build` (uses `advanced-lab/.env` + `lab/docker-compose.premium-lab.yml` + `lab/advanced.yml`).
- [x] **0.7** Apply the **Removal audit** (Section 2D):
  - [x] 0.7.1 Relocate `advanced-lab/docker-compose.extend.yml` → `lab/advanced.yml`; delete the other six root/platform/oss/deploy `docker-compose*.yml` files. **Phase 1.6** moved the premium lab base to **`lab/docker-compose.premium-lab.yml`** (no compose under `plugins/`).
  - [x] 0.7.2 Delete the eight `Dockerfile`s; lab builds use **`lab/Dockerfile.*`** only (`lab/README.md`). Compose `dockerfile:` paths are relative to each **build context**.
  - [x] 0.7.3 Delete every Prometheus/Grafana asset listed in 2D.2 (and the directories `platform/deploy/prometheus/`, `deploy/grafana/`, `plugins/tracetramp/monitoring/`).
  - [x] 0.7.4 Delete `plugins/tracetramp/k8s/`.
  - [x] 0.7.5 Shrink `platform/deploy/.env.example` to bootstrap‑only keys; remove all secrets from it.
  - [x] 0.7.6 Drop the `deprecated_*` route sub‑routers in `router.rs` and dead `memory::*` handlers superseded by `memory2` (2D.5). Legacy URL paths kept without deprecation headers until clients migrate.
  - [x] 0.7.7 Move `ppt/`, `platform/gtm-presentation/`, landing‑page, youtube‑deck out of cargo workspace and out of release tarball (2D.6). Enforced: `scripts/release-tar-excludes.txt` + `scripts/audit-release-tar-excludes.sh` (no `Cargo.toml` under those trees; tarball excludes list for Phase 1.7 `make package`).
- [x] **0.8** Update root `.gitignore` per Section 2D.7 (**done**). CI: `.github/workflows/repo-hygiene.yml` runs `scripts/audit-removed-paths.sh` on every PR/push to main.
- [x] **0.9** `connectorctl bootstrap` command: read legacy env vars, write them into the Secret Vault, then unset them. Run once during the migration. Implemented: `connectorctl bootstrap` (dry-run) / `connectorctl bootstrap --apply` → `POST /api/v1/infra/vault/secrets`; prints `unset` hints (host env cannot be cleared by the child process). See `README.md`.

### Phase 1 — Kernel foundation

- [x] **1.1** New crate `platform/supervisor/`: process group, async health probes, log fan-in, restart with backoff, graceful shutdown. Crate: `connector-supervisor` (`platform/supervisor/`). CI: `repo-hygiene` runs `cargo test` there. **1.2** will wire `connectorctl` to this library.
- [x] **1.2** Promote `connectorctl` to a real supervisor: `start | stop | status | logs | upgrade`. (`platform/server/src/bin/connectorctl.rs`.) **Done for local lifecycle:** background `start` uses `connector-supervisor` (`ProcessGroup`, `setpgid`); `stop` signals the process group on Unix; `status` shows supervisee pid when present; `logs` message documents `CONNECTOR_SUPERVISOR_LOGS` / `CONNECTOR_LOG_FILE`. `upgrade` remains the billing/tier command (binary updates = reinstall/build).
- [x] **1.3** `plugin.toml` schema in new crate `platform/plugin-manifest/` (`connector-plugin-manifest`: parse + validate; `examples/sample.plugin.toml`). CI: `repo-hygiene` runs `cargo test --manifest-path platform/plugin-manifest/Cargo.toml`.
- [x] **1.4** Plugin handshake (env path or inherited FD) for kernel → plugin bootstrap: crate `platform/plugin-handshake/` (`connector-plugin-handshake`); TraceTramp / WitnessCtl / DevGuard call `apply_from_env()` at process entry; maps into existing `CONNECTOR_*` / `TRACETRAMP_*` env. Contract: `PLUGIN_CONTRACT.md`. CI: `repo-hygiene` runs `cargo test --manifest-path platform/plugin-handshake/Cargo.toml`.
- [x] **1.4a** Cage‑internal DNS (Section 2E):
  - [x] 1.4a.1 `internal_dns`: on boot, `sync_plugin_cage_dns_records` registers `<slug>.<CONNECTOR_CAGE_TLD>` for each id in `CONNECTOR_PLUGINS_ENABLED`; clears entries for disabled slugs (same matrix as API gate).
  - [x] 1.4a.2 `resolve_cage_hostname` / `is_cage_host` — table-only resolution for the cage TLD (no OS / external resolver path in this API).
  - [x] 1.4a.3 Reverse proxy **`/plugin/{*rest}`** (auth layers match `/api/v1`): rewrites upstream `Host` to cage hostname, injects platform admin bearer (TraceTramp / WitnessCtl env parity with existing proxies); target `SocketAddr` from internal DNS (management URL → addr in lab).
  - [x] 1.4a.4 `internal_dns::cage_routing_key` / `plugin_cage_hostname` for stable keys; `GET /api/v1/plugins/status` exposes `cage_host` + `public_plugin_proxy_prefix` per plugin.
  - [x] 1.4a.5 `connector.yaml` → `connector.cage_tld` → `CONNECTOR_CAGE_TLD` (default `cnktros`). See `connector.yaml.example`, `PLUGIN_CONTRACT.md`.
- [x] **1.5** Embed dashboard `dist/` via `include_dir!` (`$OUT_DIR/dashboard_embed` staged in `platform/server/build.rs` from `../ui-leptos/dashboard/dist` or `dashboard-embed-stub/`). `resolve_dashboard_ui_dir()` no longer scans disk; default log label `embedded:…`. Optional **`CONNECTOR_UI_DIR`** disk override when set to a directory with an index file. `connectorctl` only forwards `CONNECTOR_UI_DIR` when the parent process sets it (no path hunting).
- [x] **1.6** Extend `connector.yaml` with `plugins: [...]`. Move per-plugin `docker-compose.yml` into `lab/` (lab-only) — **`lab/docker-compose.premium-lab.yml`**; `connector_profile` applies `CONNECTOR_PLUGINS_ENABLED` + optional `CONNECTOR_PLUGIN_*_LAB_COMPOSE` when env unset.
- [x] **1.7** `make package` produces single tarball; CI gate — `scripts/package-connector-os.sh` + **`make package`**; **`connector-platform-kernel`** runs the script (release build + archive layout check); **`repo-hygiene`** checks the script with `bash -n`.
- [x] **1.8** Unified `/api/v1/health` rollup (kernel + every plugin) — `services/unified_health.rs` (kernel = `monitor::kernel_health_snapshot`, plugins = same probes as hub); public like `GET /health`.
- [x] **1.9** Default dev mode on first run (Section 3). Implicit `CONNECTOR_PRESET=local` when unconfigured, first-run SuperAdmin bootstrap + `users.db` compatibility snapshot, auto-mint plugin admin tokens when unset, runtime banner payload in `GET /api/v1/runtime/mode`, and `connectorctl mode prod` alias for production switching.
- [x] **1.10** Built‑in observability replaces Grafana/Prometheus (Section 2D.2). Native in-process ringbuffer + `GET /api/v1/monitor/native` rollup (RPS, p95 latency, 5xx error rate, plugin request counts) + gateway-ledger cost chain endpoint `GET /api/v1/monitor/cost-chain` + runtime contract surface exposing `internal` vs `docker_lab` isolation (`GET/POST /api/v1/runtime/isolation`) with Docker availability status.
  - [x] 1.10.1 In‑kernel ringbuffer metric store (per‑plugin latency, RPS, errors, cost, microVM RAM/CPU): native monitor now includes microVM usage rollups (`by_agent/by_cell/by_shard/by_core`) sourced from kernel host usage sampling.
  - [x] 1.10.2 Native dashboard charts; pinnable per page (`GET /api/v1/monitor/native/charts`, `POST /api/v1/monitor/native/charts/pins`).
  - [x] 1.10.3 Alert rules editable in Settings → Alerts: create/list + update/delete dynamic rules via `/api/v1/monitor/alert-rules`.
  - [x] 1.10.4 Keep `/metrics` Prometheus endpoint as an opt‑in for users who run external Prom (`CONNECTOR_ENABLE_PROM_METRICS=1`).

### Phase 2 — Plugins hub UX

- [x] **2.1** Plugins page extended: Install / Enable / Disable / Update / Uninstall with state badges (`services/plugin_lifecycle.rs` + `/api/v1/plugins/status` lifecycle badges/actions + history endpoint).
- [x] **2.2** Per-plugin Configure page **generated from manifest** `[settings]` schema — no hand-coded forms (`GET /api/v1/plugins/:id/configure/schema`, `GET/POST /api/v1/plugins/:id/configure`) with typed field validation and persisted values.
- [x] **2.3** Lifecycle APIs in new file `platform/server/src/services/plugin_lifecycle.rs` (`GET /api/v1/plugins/lifecycle`, `GET/POST /api/v1/plugins/:id/lifecycle`, `GET /api/v1/plugins/:id/lifecycle/history`) with persisted state transitions + event history.
- [x] **2.4** Capability grant UI on install ("this plugin requests: …") via install preflight + grants APIs (`GET /api/v1/plugins/:id/install/preflight`, `POST /api/v1/plugins/:id/install/grants`) with persisted requested/granted capability sets.
- [x] **2.5** **Service Map page** (Section 5.2) backed by `GET /api/v1/plugins/service-map`.
- [x] **2.6** **Header Health pill** rewrite (Section 5.1) backed by `GET /api/v1/plugins/header-health`.
- [x] **2.7** **Plugin installer revamp** (Section 5.3) — repurpose existing app installer, backed by `GET /api/v1/plugins/:id/installer/plan` + lifecycle/install APIs.
- [x] **2.8** **Settings → Secrets** page (Section 2C.1): backend façade APIs shipped under `/api/v1/settings/secrets*`.
  - [x] 2.8.1 UI over `/api/v1/infra/vault/*` (already in kernel) with categories, masked view, rotate, revoke, audit log (`GET /api/v1/settings/secrets` + canonical action links + audit summary).
  - [x] 2.8.2 Master key options: OS keyring (default) / TPM / cloud KMS — selectable in setup (`GET /api/v1/settings/secrets/master-key/options`, `POST /api/v1/settings/secrets/master-key/select`).
  - [x] 2.8.3 Capability‑gated secret reads via CNP; plugins receive a handle, never the raw value (`POST /api/v1/settings/secrets/issue-handle` enforces granted `secret.read`, returns opaque handle only).
  - [x] 2.8.4 "Test" button per secret type (LLM key → ping provider, Stripe → call balance, etc.) (`POST /api/v1/settings/secrets/test`).
- [x] **2.9** **Settings → LLMs** page (Section 2C.2) — API surfaces over existing `llm_router` / `adaptive_router`:
  - [x] 2.9.1 Add provider form (OpenAI / Anthropic / Azure / Bedrock / Vertex / Ollama / vLLM / OpenAI‑compatible custom). Keys come from Secret Vault (`GET/POST /api/v1/settings/llms/providers`).
  - [x] 2.9.2 Routing rules editor: primary/fallback chain, triggers (5xx, latency p95, cost cap, region/policy) (`GET/POST /api/v1/settings/llms/routing-rules`).
  - [x] 2.9.3 Per‑plugin and per‑workflow provider override (`GET/POST /api/v1/settings/llms/overrides`).
  - [x] 2.9.4 Live charts: latency, tokens, cost, error rate per provider (`GET /api/v1/settings/llms/charts` sourced from monitor cost/native surfaces).
  - [x] 2.9.5 Cost guardrails: monthly budget, soft warning at 80%, hard stop at 100% (`GET/POST /api/v1/settings/llms/guardrails`).
  - [x] 2.9.6 Privacy/region tags (`us`, `eu`, `local`); workflows can require a tag (`GET/POST /api/v1/settings/llms/privacy-tags`).
- [x] **2.10** **Settings → Networking / Identity / Backup / Telemetry / License** pages (Section 2C.3) — UI + API surfaces: `GET/POST /api/v1/settings/system/{networking|identity|backup|telemetry|license}`.
- [x] **2.11** **Settings → Networking → Custom domains** (Section 2E.4): UI + API surface at `GET/POST /api/v1/settings/networking/custom-domains` (public domain, aliases, TLS mode, per-plugin public path allowlist).

### Phase 3 — Workflows = CLS + CNP + drag‑and‑drop builder

- [ ] **3.1** Promote existing CLS engine to the **single workflow runtime**: `platform/server/src/cls/engine.rs` resolves capabilities, runs CCL packages, dispatches via CNP. No new YAML/DSL. **Started:** workflow runtime control-plane endpoints added (`/api/v1/workflows`, `/api/v1/workflows/:id/lifecycle`, `/api/v1/workflows/:id/dry-run`) with explicit lifecycle states and dry-run no-side-effect reports. **Partial:** **`POST /api/v1/workflows`** (register/apply) and **`POST …/workflows/:id/dry-run`** run **`compile_ccl_contract`** (same **`CclParser`** path as **`POST /api/v1/cls/compile`**) on **`cls_source`**; success responses include **`cls_compile`** metadata; register rejects invalid CCL before persist; **`connectorctl workflow apply`** / **`dry-run`** surface failures (non-zero exit). Rollback does not re-parse (restore historical blobs even if the parser tightens).
- [ ] **3.2** Plugin manifest gains `[workflow.actions]` + `[workflow.events]` (Section 2B.3); kernel registers them on the CNP topic bus at plugin enable. **Started:** plugin workflow contract registration endpoints (`POST /api/v1/plugins/:id/workflow-contract`, `GET /api/v1/plugins/workflow-contracts`) for action/event catalog ingestion.
- [x] **3.3** **Workflows tab** in the dashboard wires the existing CLS pages together:
  - [x] 3.3.1 `cls_builder.rs` — **Plugin palette** tab: `GET /api/v1/plugins/workflow-contracts` populates draggable (and clickable) action/event chips; drop targets on Simple Workflow + palette panel; session import from Workflows/Packages.
  - [x] 3.3.2 `cls_packages.rs` — **Workflow registration** card: `POST /api/v1/workflows` with cls_source; **Builder session** load/push via `SessionStorage` round-trip (full Monaco deferred; monospace editor unchanged).
  - [x] 3.3.3 `cls_catalog.rs` — **Reference workflow templates** from `GET /api/v1/workflows/reference-templates` + “Open in Builder” (session source) + links to Workflows / Packages.
  - [x] 3.3.4 `cls_execution.rs` — existing package run history + **Workflows hub** banner for dry-run / lifecycle; dry-run JSON on `/workflows`; **Workflows hub** loads **`GET …/dry-runs`** (index + backfill hint) and **View report** → **`GET …/dry-runs/:run_id`** into the same summary panel as POST dry-run; **API detail** → **`GET …/workflows/:id`** (summary + JSON; refreshes after dry-run / rollback when that panel is open).
- [ ] **3.4** **Round‑trip guarantee**: builder ⇄ CLS source; code-block fallback when the graph cannot represent constructs. **Progress:** Source editor warns via `cls_source_simple_lane_ok`; Packages ⇄ Builder **session** round-trip for CLS blobs. **Remaining:** dedicated graph/code-block node (see **3.12**).
- [ ] **3.5** **Lifecycle states** for a workflow: `DRAFT → COMPILED → STAGED → ENABLED ↔ PAUSED → ARCHIVED`. Atomic hot‑swap on enable; in‑flight runs finish under the old version. **Started:** state machine + guarded transitions implemented in workflow runtime API. **Partial:** **`POST …/workflows/:id/lifecycle`** with **`state: COMPILED`** or **`ENABLED`** runs **`compile_ccl_contract`** (activation re-check catches parser drift or corrupted store); rejects invalid **`cls_source`** with the same **`cls_compile`** diagnostics as register/dry-run; idempotent no-op when already in target state; **`connectorctl workflow compiled`** / **`staged`** / **`enable`**; shell completion lists **`compiled`**, **`staged`**, **`versions`**, etc.
- [ ] **3.6** **Dry‑run** replays the last N minutes of CNP events through the new workflow and produces a diff of dispatched actions — no side effects. **Started:** `/api/v1/workflows/:id/dry-run` produces replay metadata + zero-side-effect diff contract. **Partial:** response includes **`cls_compile`** (**`contract_cid`**, **`contract_name`**, **`block_count`**) from shared **`services::cls::compile_ccl_contract`**; top-level **`ok`** is false when CCL parse fails; **`dispatched_actions`** lists a **static behavior blueprint** (parsed **`behavior`** steps → tool/emit/llm/mem/… rows; **`diff.new_actions`** = row count; not executed); **`cnp_replay`** — if the request body omits **`events`**, the kernel loads a **compact audit tail** (**`engine_audit_window`**) for the replay window (read-only; not CNP topic correlation) including **`category_counts`** over the fetched slice and **`matched_events`** = fetch size (not the embedded **`events`** row cap); if **`events`** are supplied, **`client_events`** echoes a capped sample; each run persists with **`recorded_at`**; **`GET …/workflows/:id/dry-runs`** lists last 50 **`run_id`** (index) and **`GET …/workflows/:id/dry-runs/:run_id`** returns the stored report; if the index is empty, listing **best-effort backfills** from **`workflow_runtime_runs`** (bounded key scan); **`connectorctl workflow dry-runs`** / **`dry-run-show`**; real CNP topic replay + dispatched-action diff vs blueprint still stub.
- [ ] **3.7** **CNP as the only fabric**: workflows never call plugins directly; every action goes through CNP with kernel‑minted scoped tokens (Section 2B.4). Audit logged.
- [ ] **3.8** **Versioning + rollback**: every save is a new CCL package version; one‑click rollback; dashboard shows version history with diff. **Partial:** **`GET /api/v1/workflows/:id`** returns one workflow with the same list-row enrichments plus **`version_log_len`**; **`GET /api/v1/workflows`** enriches each row with **`cls_source_fingerprint`** (**SHA-256**, first 8 bytes hex‑encoded, over UTF‑8 **`cls_source`**) and **`cls_source_byte_len`** for quick diff without parsing CCL; optional **`last_dry_run_id`** / **`last_dry_run_recorded_at`** from the newest **dry-run index** entry (omitted when index empty); **`GET /api/v1/workflows?hydrate_dry_run_index=true`** backfills up to **15** empty indices from stored runs (response **`dry_run_index_hydrations`**; **Admin or dev bypass only**; failure returns **401** (no credentials) or **403** (non-Admin) with **`code: HYDRATE_AUTH_REQUIRED`** + **`hint`**); **`connectorctl workflow list --hydrate-dry-run-index`** and **`connectorctl workflow logs … --hydrate-dry-run-index`** (same query); Workflows hub checkbox **Hydrate last dry-run column**; **`connectorctl workflow list`** prints fingerprint + last dry-run columns; Workflows table shows **Last dry-run**. **`GET …/workflows/:id/versions`** enriches each log row with **`cls_source_fingerprint`**, **`cls_source_byte_len`**, and **`fingerprint_changed_from_previous`** (null / true / false vs prior row); Workflows hub **Version history** button + table; **`connectorctl workflow versions`** prints **Δ**/**=** vs prior fingerprint. **Workflows hub:** **Rollback previous** (default **`POST …/rollback`**) and per-row **Restore** in the version table (**`index`**); browser confirm; reloads workflows + version panel when open. **Remaining:** semantic CCL diff in UI/kernel.
- [ ] **3.9** **Hub publishing** for workflows: a CLS workflow can be packaged as a `.cpkg` and published. `requires = [...]` declares plugin dependencies; install resolves them (Section 2B.6).
- [x] **3.10** CLI: `connectorctl workflow compile | apply | dry-run | dry-runs | dry-run-show | enable | pause | rollback | versions | show | list | logs | publish` via `connectorctl workflow <verb>` wired to `/api/v1/workflows*` + local compile/publish-preview helpers (**`show`** → **`GET /workflows/:id`**; **`logs`** / **`publish`** use that route when not hydrating the list).
- [x] **3.11** Reference templates shipped with Connector OS:
  - [x] HITL Approve‑and‑Audit (TraceTramp + WitnessCtl)
  - [x] PII Redaction Pipeline (any LLM gateway plugin + DevGuard)
  - [x] Incident → Slack → Jira (community plugins)
- [x] **3.12** Builder UX polish: snap‑to‑grid, multi‑select, copy/paste nodes, undo/redo, keyboard shortcuts, inline validation against CLS sema.

### Phase 4 — Connector Hub & marketplace (the AGOS scale layer)

- [x] **4.1** `.cpkg` package format crate `platform/cpkg/` — `plugin.toml` + binaries + UI bundle + signature + SBOM. **MVP:** ZIP layout (`plugin.toml`, optional `sbom.json`, optional `META/signature.json`, `bin/*`, `ui/*`), `read_cpkg` / `write_cpkg`, round-trip test.
- [x] **4.2** Ed25519 signing & verification — `canonical_payload_digest`, `sign_envelope`, `verify_envelope`, `read_cpkg_verify_optional`; optional `parent_key_id` on envelope for future Hub→author chain. **Trust:** caller-supplied `trust_keys` on install or `CONNECTOR_CPKG_REQUIRE_SIGNATURE`.
- [x] **4.3** Connector Hub MVP — `platform/hub/` (`connector-hub`): `/health`, `/v1/search`, `/v1/latest`, `/v1/cpkg`, `/v1/publish`, `/v1/yank` (local `CONNECTOR_HUB_DATA_DIR`). Ratings/facets = later.
- [x] **4.4** Hub client — `connectorctl hub search|install|update|publish|yank|uninstall|bundle-export|bundle-import` + `CONNECTOR_HUB_URL` / `CONNECTOR_HUB_PUBLISH_TOKEN`. **uninstall** maps to `POST /api/v1/plugins/:id/lifecycle` (`action: uninstall`); bundle commands wrap kernel `.cpkg` bundle APIs.
- [x] **4.5** Rollout + health rollback — install writes `data/plugins/cpkg_store/.../rollout.json` + `versions/<ver>/package.cpkg` + extracted `files/`; optional `verify_health_sec` compares unified health before/after and restores previous `rollout` + lifecycle version when health worsens from `ok`.
- [x] **4.6** Sideload — `POST /api/v1/plugins/cpkg/install` with `url` or `cpkg_base64`; `POST .../bundle/export` (zip of saved `.cpkg`); `POST .../bundle/import` (zip of `*.cpkg` members). Dashboard upload can POST same JSON as CLI.
- [x] **4.7** Private/enterprise Hub mirrors (self-hosted Hub on intranet); kernel supports multiple Hub URLs in priority order.
- [x] **4.8** Plugin pages in dashboard: README render, screenshots, capability list, version history, signing fingerprint, install count, ratings, "Report" link.
- [x] **4.9** Semver dependency resolver in install path (Section 2A.5); refuse to install on conflict; suggest resolution.
- [x] **4.10** Author developer portal: API tokens, vendor namespace claim, publish stats.

### Phase 5 — Isolation tiers (microVM is the heart, designed for 100+ plugins)

> **Phase 5 is not complete.** **Shipped in-repo:** **5.1**, **5.2**, **5.3.1–5.3.8** (vendored microVM assets + Firecracker host lifecycle + vm-agent scaffold + vsock probe/log fan-in + macOS sidecar wrapper + Windows WSL2 launch path + CI smoke script/workflow), **5.4.1–5.4.2** (tier scheduler + product hooks), **5.4.3** **partial** (idle demotion via **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`**; **`GET …/plugin-tier-scheduler`** **`utilization`** aggregate; optional **`cgroup_v2`** child **`cpu.stat`** sample when **`CONNECTOR_PLUGIN_TIER_CGROUP_SCAN`** + cgroup parent set; optional cgroup-accelerated Warm/Hot→Cold when **`CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE`** + idle policy), **5.5.1** (kernel condo registry only), **5.5.2** **partial** (condo **`placement`** on **`GET …/plugin-condos`** + **`POST …/plugin-condos/placement`** — state machine scaffold; no vm-agent yet), **5.7.1** (egress allowlist read API), **5.7.2** **partial** (Docker lab **`CONNECTOR_DOCKER_LAB_EGRESS`**, **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables`** / **`ip6tables`** on Linux — IPv4+IPv6 caps, dual-stack lab network, foreground or detached + **`docker wait`**, **`SpawnRequest::egress_allowlist`**; microVM fail-closed policy modes **`CONNECTOR_MICROVM_EGRESS_MODE=deny_all|allowlist_strict|custom`** with non-wildcard capability validation + normalized allowlist telemetry; **Linux native Firecracker** **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`**: per-VM TAP, **`ip=`** bootarg + **`PUT /network-interfaces/eth0`**, **`iptables` / `ip6tables` `FORWARD`** TCP allowlist (IPv4 + IPv6 when caps resolve to **`AAAA`**; guest ULA + **`connector.microvm_guest_ipv6`** / **`connector-vm-agent`**) + optional **`CONNECTOR_MICROVM_ALLOW_RESOLVER_DNS`**, **`MASQUERADE`** / NAT6 on WAN, and PID-exit cleanup watcher for best-effort rule/TAP teardown; non-Linux paths (macOS sidecar / Windows WSL bridge) now surface explicit enforcement resolution telemetry and can fail-closed when **`CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED=1`**; operator visibility includes normalized **`microvm_egress_enforce_required`**, **`connectorctl status`** / **`connectorctl doctor`** preflight warnings + compact `phase5_preflight=ok|warn (N)` summaries + **`--json`** top-level **`phase5_preflight_warning_level`**, **`phase5_preflight_warning_count`**, **`phase5_preflight_warnings`**, and API-level warning arrays on **`GET /api/v1/plugins/status`** (`phase_5_operator.preflight_warnings`, `phase_5_operator.preflight_warning_count`, `phase_5_operator.preflight_warning_level`) + **`GET /api/v1/runtime/isolation`** (`phase_5_operator_preflight_warnings`, `phase_5_operator_preflight_warning_count`, `phase_5_operator_preflight_warning_level`) when fail-closed egress enforce is incompatible with host OS), **5.8** **partial** (Linux subprocess cgroup v2 leaf attach + optional limits; see **5.8** bullet), **5.9** **partial** (Linux subprocess **`prctl`** + seccomp modes in **`pre_exec`**: **`CONNECTOR_PLUGIN_SUBPROCESS_NO_NEW_PRIVS`**, **`CONNECTOR_PLUGIN_SUBPROCESS_NOT_DUMPABLE`**, **`CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP=strict|deny_dangerous|network_deny|network_ingress_deny`** where **`deny_dangerous`** installs x86_64/aarch64 BPF filter denying high-risk syscalls, **`network_deny`** denies socket/connect/accept/bind/listen/send/recv syscall family, and **`network_ingress_deny`** denies bind/listen/accept while allowing outbound client sockets; operator intent selector **`CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT=off|strict|safe_default|no_network|no_ingress`** now maps to concrete seccomp policy and takes precedence over raw mode, with normalized seccomp policy + intent surfaced via `phase5_operator_env` / `plugins status` / `connectorctl status` / `runtime_control`), **5.10.1–5.10.4** (kernel crash recovery + supervisor restart policy), **5.10.3** (tabular **`/plugins`** + **`/service-map`**), **5.10.5** (per-plugin **ingress → proxy → cage → kernel** topology strip on **`/service-map`**), **5.10.7** **partial** (topology strip **zoom + scroll pan + responsive columns** in `ServiceMapIngressFlows`), **5.10.6** **partial** (`supervisee_inventory()` + **`GET /api/v1/kernel/supervisor/inventory`** + **`connectorctl supervisor inventory`**; `connector.yaml.example` supervisor env notes). **Still open:** condo guests **remainder** (**5.5.2** — vm-agent, real placement), wasm (**5.6**), egress enforce **remainder** (**5.7.2** — nftables/CNI polish, macOS sidecar egress, WSL operator polish), cgroups **remainder** (**5.8** — full I/O + bandwidth vs subprocess slice), seccomp / **`prctl` remainder** (**5.9** — profile tuning), tier idle suspend **remainder** (microVM coordinated guest suspend/power — **5.4.3** remainder; guest cmdline idle-ms hint shipped), Service Map **full** interactive graph (**5.10.7** remainder), **new** supervised AGOS entrypoints beyond node + plugin dev (**5.10.6** remainder).

- [x] **5.1** Subprocess runtime (default in dev) — `connector-plugin-runtime` + `IsolationRuntime::subprocess`; detached `tokio::process` with Unix process group.
- [x] **5.2** Docker runtime (lab convenience only; same trait) — `DockerLabBackend` (`docker run -d …`); selectable via `IsolationRuntime::docker_lab`.
- [x] **5.3** **microVM runtime — production default** (Section 4):
  - [x] 5.3.1 Bundle Firecracker binary in build.
  - [x] 5.3.2 Bake Alpine rootfs at build time.
  - [x] 5.3.3 `platform/microvm/` crate (Firecracker config + live host lifecycle via UDS API).
  - [x] 5.3.4 `connector-vm-agent` (PID 1 inside guest).
  - [x] 5.3.5 vsock health probes + log fan-in.
  - [x] 5.3.6 macOS via Virtualization.framework wrapper.
  - [x] 5.3.7 Windows via WSL2 backing.
  - [x] 5.3.8 Smoke test in CI.
- [x] **5.4** **Cold/Warm/Hot tier scheduler** (Section 2A.2) — Section 2A.2 lazy-start model in the kernel.
  - [x] **5.4.1** `plugin_tier_scheduler` + `GET /api/v1/kernel/plugin-tier-scheduler`; cold→warming coalesced waiters + budget-capped simulated cold start; **`admit_cold_start` is `Send`** (mutex released before any `.await`).
  - [x] **5.4.2** Product hooks — successful `.cpkg` install calls `admit_cold_start` using manifest `cold_start_budget_ms`; **`POST /api/v1/kernel/plugin-tier-admit`** and **`POST /api/v1/kernel/plugin-tier-touch`** (`touch` after successful activity); **`connectorctl plugin run --dev`** POSTs admit before each spawn attempt and touch after success; `GET /api/v1/plugins/status` includes `phase_5.tier_scheduler` / `phase_5.crash_recovery` per built-in plugin. **Operator surfaces:** **`connectorctl tier`** (`show` / `admit` / `touch`); **`connectorctl status --json`** → **`tier_scheduler`** and human **`status`** hint when plugins status is ok; **`connectorctl doctor --json`** → **`doctor_extensions.tier_scheduler`** + human doctor line; dashboard **Service Map** (`#tier-scheduler`) + **Plugins** hub lazy **Load snapshot**; **`docs/32-connectorctl.md`** Hub + tier sections; **`connector.yaml.example`** tier comment; **`GET /api/v1/runtime/isolation`** `phase_5.tier_scheduler` discovery string.
    - **Also shipped:** **`phase_5_operator`** production hygiene (**`connect_*`**, **`production_dev_mode_hygiene`**, **`process_env_operator_display_line`**); **`connectorctl status|doctor --json`** (**`tier_scheduler`**, **`shell_production_env`**, top-level **`process_env_operator_display_line`**); **`make kernel-prod-preflight`** / **`connector-kernel-prod-preflight.sh --with-connector`** (JSON invariants); dashboard **Phase5OperatorHints** + tier panel **Refresh**.
  - [ ] **5.4.3** Tier **idle suspend** / automated cold sleep when idle — **shipped (kernel slice):** **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`** (0/unset = off); Warm/Hot slots with no **`plugin-tier-touch`** past the window are demoted to **Cold** (counts **`idle_demotions`**); **`phase_5.tier_scheduler.idle_suspend`** is structured JSON; **`GET …/plugin-tier-scheduler`** returns **`idle_suspend_policy_after_ms`** and **`utilization`** (aggregate **`by_tier`** counts, **`idle_demotions_total`**, **`cgroup_accelerated_idle_demotions_total`**, **`cold_start_admits_total`**, **`scope`** — in-memory + optional cgroup paths). **Partial:** **`CONNECTOR_PLUGIN_TIER_CGROUP_SCAN=1`** + **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT`** adds **`utilization.cgroup_v2`** (**`usage_usec`** sample from **`runner-*`** cgroup children — Phase **5.8** subprocess slice). **Partial (cgroup-driven demotion):** **`CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE=1`** + idle policy + cgroup parent — samples runner cgroup **`usage_usec`** and can demote Warm/Hot → Cold before the full idle window when CPU growth stays below **`CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_MAX_USEC_PER_WALL_SEC`** (counts **`cgroup_accelerated_idle_demotions`** / **`cgroup_accelerated_idle_demotions_total`**). **Partial (guest visibility):** when idle policy > 0, **`connector-plugin-runtime`** microVM boot args include **`connector.plugin_idle_suspend_after_ms`** (and spawn **`detail.tier_idle_suspend_policy_ms_for_guest`**); **`connector-vm-agent`** logs the value — groundwork for guest power/suspend. **Still open:** coordinated microVM guest suspend / stop on tier Cold beyond cmdline hints.











- [ ] **5.5** **Shared "plugin condo" microVM** (Section 2A.3) for tiny / shared-runtime plugins; ≥50 plugins per condo target.
  - [x] **5.5.1** Kernel condo registry — engine store `plugin_condos`, `GET/POST …/plugin-condos` (create + assign, remap across condos, max 50 members).
  - [ ] **5.5.2** Guest-side multi-tenant **vm-agent** + microVM **placement** inside condos (registry → running guests). **Live bridge shipped:** **`CondoRecord.placement`** (state **`unassigned` \| `microvm_pending` \| `microvm_pool` \| `reserved`**, **`target_pool`**, notes, last-10 actions, guest heartbeat status) persisted; **`POST /api/v1/kernel/plugin-condos/placement`** executes runtime actions against `kernel_host` microVM placement primitives (pool parse **`<cell>/<shard>`**, upsert cell/shard, schedule/release member placements, rollback on partial schedule) and returns **`runtime_preflight`** + **`runtime_execution`**; **`POST /api/v1/kernel/plugin-condos/placement-plan`** includes preflight capacity checks (**`runtime_preflight_ok`**) in **`valid`**; **`POST /api/v1/kernel/plugin-condos/guest-heartbeat`** records vm-agent heartbeat and **`microvm_pool`** transition requires a fresh heartbeat (TTL gate). **Guest feed added:** `connector-vm-agent` posts condo heartbeats from env/kernel cmdline metadata; `connector-plugin-runtime` propagates condo heartbeat URL/token + condo identifiers into microVM boot args. **Hardening:** guest-heartbeat endpoint supports scoped token auth (`CONNECTOR_CONDO_GUEST_HEARTBEAT_TOKEN`) to avoid relying on broad admin API credentials. **Still open:** true guest-side multi-tenant vm-agent process hosting and per-condo in-guest workload runtime.
- [ ] **5.6** Wasm runtime for community plugins (wasmtime + WASI); default for unsigned community submissions.
- [ ] **5.7** Egress firewall on plugin VMs: deny by default, allowlist from explicit `network.outbound:host:port` capabilities (wildcards rejected at manifest validate).
  - [x] **5.7.1** `GET /api/v1/kernel/plugin-egress-allowlist?plugin_id=` — reads active rollout manifest.
  - [ ] **5.7.2** Enforce default-deny egress on the microVM / lab network path using 5.7.1 allowlist (nftables / Firecracker net / CNI — pick per runtime). **Partial (Docker lab):** **`CONNECTOR_DOCKER_LAB_EGRESS`** — `deny_all` → **`docker run --network none`**; `allowlist_strict` + empty **`SpawnRequest::egress_allowlist`** → **none**; non-empty allowlist → default bridge, or **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables`** (Linux, root/`CAP_NET_ADMIN`): static **`--ip`** / **`--ip6`** on **`connector_plugin_lab`** (IPv6 ULA **`fd00:c0ff:ee99::/64`** when caps/DNS need it; recreate network if pre-existing bridge lacks IPv6), **`iptables`/`ip6tables` `DOCKER-USER`** for resolved TCP + optional DNS (`CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS`). **Foreground** vs **detached** + **`docker wait`** as above. **Partial (Linux microVM / Firecracker):** **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`** + non-empty allowlist + egress mode ≠ **`deny_all`** → TAP + **`ip=`** + **`iptables` `FORWARD`** (IPv4 TCP) + **`MASQUERADE`**; resolved **`AAAA`** destinations add **`ip6tables` `FORWARD`** (TCPv6) + **`ip6tables` NAT `MASQUERADE`** (host must have a working IPv6 route to those destinations), per-VM ULA on the TAP, and **`connector.microvm_guest_ipv6`** on the kernel cmdline applied by **`connector-vm-agent`** (runs **`ip -6 addr add`** on **`eth0`**). PID-exit watcher tears down v4+v6 state (**`cleanup_hint`**). **Partial (Windows WSL2 microVM):** same **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`** runs **`connector-microvm-wsl-egress-apply.py`** inside **`CONNECTOR_WSL_DISTRO`** (CAP_NET_ADMIN / root in distro; **`iptables`+`ip`**, and **`ip6tables`** when caps resolve to IPv6), attaches TAP + **`ip=`** + optional guest ULA boot args, starts a WSL-side PID-exit cleanup helper (**`microvm_egress_cleanup_watcher`**). **Remainder:** nftables/CNI, macOS sidecar egress parity, richer in-kernel dual-stack boot args. **`SpawnRequest`** carries **`egress_allowlist`**, **`workspace_host_mount`**, **`docker_run_detached`**. **`connectorctl plugin run --dev`** + **`docker_lab`** uses foreground **`docker run`** (allowlist passed through).
- [ ] **5.8** Cgroup-based resource governance (memory, cpu, io, disk, egress bandwidth). **Partial (Linux subprocess):** **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT`** creates per-spawn **`runner-<plugin>-<pid>`** leaf, optional **`memory.max`** / **`cpu.max`** (**`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_MAX_BYTES`**, **`CONNECTOR_PLUGIN_SUBPROCESS_CPU_PCT`**), optional **`io.max`** throttling via explicit **`CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX`** (`<major>:<minor> rbps=.. wbps=.. riops=.. wiops=..`, comma-separated) or auto workspace/cwd device fallback (**`CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO=1`** + **`CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO_RBPS|WBPS|RIOPS|WIOPS`**), optional pre-spawn workspace disk cap via **`CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_BYTES`** (+ fail-closed **`CONNECTOR_PLUGIN_SUBPROCESS_WORKSPACE_MAX_ENFORCE`**), optional **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_ENFORCE`**; receipt includes **`cgroup.limits`** and **`workspace_quota`** JSON; tier scheduler optional scan (**`CONNECTOR_PLUGIN_TIER_CGROUP_SCAN`**).
  - [ ] **5.9** seccomp / SELinux profiles for subprocess runtime. **Partial:** Linux **`connector-plugin-runtime`** subprocess spawn — optional **`PR_SET_NO_NEW_PRIVS`** / **`PR_SET_DUMPABLE`** via **`CONNECTOR_PLUGIN_SUBPROCESS_NO_NEW_PRIVS`** / **`CONNECTOR_PLUGIN_SUBPROCESS_NOT_DUMPABLE`** (`linux_hardening.rs`), plus seccomp modes **`strict`**, **`deny_dangerous`** (x86_64/aarch64 BPF filter denying keyring/bpf/perf/userfaultfd/clone3/unshare syscall set), **`network_deny`** (socket/connect/accept/bind/listen/send/recv syscall family denied with `EPERM`), and **`network_ingress_deny`** (bind/listen/accept denied with `EPERM` while outbound client sockets are allowed); intent selector **`CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT=off|strict|safe_default|no_network|no_ingress`** maps to concrete policy and takes precedence over raw mode; normalized seccomp policy + intent labels are surfaced in operator/runtime status, and **`connectorctl doctor`** + **`connectorctl status`** emit preflight warnings for custom/unsupported seccomp resolution. Remainder: profile tuning.
- [x] **5.10** Crash recovery: restart with exponential backoff; quarantine after N failures; dashboard **`/plugins`** + **`/service-map`** for `phase_5` + cage topology + topology strip. Open polish: **5.10.7** remainder (placement timeline / drag layout); graph MVP shipped.
  - [x] **5.10.1** In-memory `PluginCrashRecovery` + `GET/POST …/plugin-crash-recovery/*` (record, clear, unquarantine, backoff hint); `.cpkg` post-install calls `record_failure` on health rollback or post-verify degradation; `plugins/status` `phase_5.crash_recovery` for built-ins.
  - [x] **5.10.2** `connector-supervisor`: optional `ProcessSpec::plugin_crash_plugin_id` — on **non-success** child exit, best-effort `POST …/plugin-crash-recovery/record` (`CONNECTOR_API_URL`, `CONNECTOR_API_KEY` / `dev-token` / dev bypass). **`notify_plugin_crash_on_exit`** is public for other callers; **`connectorctl plugin run --dev`** with **`CONNECTOR_PLUGIN_RUN_BACKEND=docker_lab`** invokes it on each failed `docker run`. `connectorctl start` leaves it unset; plugin dev subprocess path sets `plugin_crash_plugin_id` (Phase **6.4**).
  - [x] **5.10.3** Dashboard + Service Map surfaces quarantine / backoff — **`/plugins`** hub and **`/service-map`** (`connector-ui`): **`phase_5`** tier + crash table; **`GET /api/v1/plugins/status`** adds **`phase_5_operator`** (isolation runtime, tier idle policy ms, **`CONNECTOR_DOCKER_LAB_EGRESS`**, **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE`**, **`CONNECTOR_PLUGIN_RUN_BACKEND`** / default subprocess); hub shows **Node — Phase 5 operator hints**; **`connectorctl status`** / **`connectorctl doctor`** (`--json` **`doctor_extensions.phase_5_operator`**) surface the same summary when the API responds; **`GET /api/v1/kernel/plugin-egress-allowlist`** includes **`phase_5_operator_env`** (egress + enforce labels); Service Map cage table adds **`enabled_in_deployment`**, **`status_badge`**, **`upstream_reachable`**, **cage host**, internal DNS, **public proxy prefix**, dashboard link.
  - [x] **5.10.4** Restart policy — **`connectorctl plugin run --dev`**: **`--retry-max`** / **`--retry-base-ms`**, capped exponential backoff, re-check quarantine between attempts; **`GET …/plugin-crash-recovery/status?plugin_id=`** refuses spawn when quarantined (kernel online). **Background `connectorctl start`** (non-systemd): **`ProcessSpec::restart_on_code_failure`** from **`CONNECTOR_SUPERVISOR_RESTART_*`**, **`run_process_spec_with_restart`** (coded failures only; signal exits not retried; refreshes `connector.pid`).
  - [x] **5.10.5** Service Map **topology strip** — on **`/service-map`**, per built-in plugin: **client → `public_plugin_proxy_prefix` → `cage_host` → `phase_5` tier line** plus crash hint (`connector-ui` `ServiceMapIngressFlows`); same page shows shared **`Phase5OperatorHints`** (`phase_5_operator` from status).
  - [x] **5.10.6** Supervisee inventory — **`connector_supervisor::supervisee_inventory()`** (`platform/supervisor/src/inventory.rs`): catalog **`node_connector_platform`**, **`node_connector_platform_foreground`**, **`plugin_run_dev`** (crash hook + retry semantics); **`GET /api/v1/kernel/supervisor/inventory`**; **`connectorctl supervisor inventory`**; **`connectorctl status`** includes **`phase_5_operator`** from plugins status + **`connector_pid`** / **`connector_pid_file`** from **`CONNECTOR_DATA_DIR/connector.pid`**. **Remainder:** additional live **`ProcessGroup`** supervisees beyond these patterns as new entrypoints ship.
  - [ ] **5.10.7** Service Map **interactive** graph — historical placement, canvas-style graph, pan/zoom on a full graph (beyond tabular + topology strip). **MVP shipped:** ingress topology strip **zoom + scroll pan + responsive multi-column strip layout** in dashboard **`ServiceMapIngressFlows`**; **SVG dependency graph** on **`/service-map`** (**`ServiceMapDependencyGraph`**, `platform/ui-leptos/dashboard/src/pages/plugins/service_map_graph.rs`) from **`GET /api/v1/plugins/service-map`** (**nodes** + **edges**, circular layout, edge **kind** labels, tooltips, graph zoom + scroll pan). **Remainder:** condo placement timeline, drag reposition, non-SVG canvas if needed.

**Phase 5 — recommended next sequence:** **5.3.1–5.3.2** (Firecracker + rootfs) → **5.3.4–5.3.5** (guest agent + vsock) → **5.7.2** (egress enforce) in parallel with **5.5.2** + **5.10.7** + **5.4.3** remainder (utilization / guest sleep) → **5.6** wasm → **5.8–5.9** resource + syscall hardening.

### Phase 6 — AGOS developer SDK & certification (community growth)

**Status:** checklist **complete**; per-item **Remainder** / **Not yet** notes capture follow-on (e.g. **`agos.v2`** dual-run, full §2A.9 certification, SDK event bus).

- [x] **6.1** `agos-abi` crate: stable, semver-governed API surface (`agos.v1`); kernel exports it on **`GET /api/v1`** and **`GET /health`** as **`agos_abi`** (contract id, crate semver, handshake schema version, doc ref). CI: **`repo-hygiene`** runs **`cargo test --manifest-path agos-abi/Cargo.toml`**.
- [x] **6.2** `agos-sdk` crate (the public-facing plugin SDK): re-exports **`agos-abi`**, **`connector-plugin-handshake`** (`apply_from_env`, errors, env keys), **`connector-plugin-manifest`** (full `plugin.toml` surface); helpers **`load_manifest_path`**, **`assert_manifest_matches_abi`**; CI: **`repo-hygiene`** runs **`cargo test --manifest-path agos-sdk/Cargo.toml`**. **Remainder (later):** event bus, structured logging facade, idle/suspend hooks beyond manifest + handshake.
- [x] **6.3** `cargo connector new <name>` scaffold generator — **`cargo-connector`** binary (`cargo install --path cargo-connector` → `cargo connector new …`). **Rust MVP:** `vendor/slug` or bare `slug` (→ `local/slug`), `plugin.toml` + `Cargo.toml` + `src/main.rs` + `.gitignore`; **`--lang go|python`** reserved with a clear error. CI: **`repo-hygiene`** runs **`cargo test --manifest-path cargo-connector/Cargo.toml`**.
- [x] **6.4** `connectorctl plugin run --dev` — **subprocess dev reload (Phase 6.4):** **`--watch`** + **`--watch-interval-ms`** (default 750) after **exit 0** polls **`plugin.toml`** + entrypoint; on change re-reads rollout, **tier-admit → spawn → touch**. **`CONNECTOR_PLUGIN_RUN_BACKEND=microvm|docker_lab|wasm`:** `--watch` is ignored with a warning (microVM in-guest hot reload / shell TBD).
  - [x] **6.4.1** `connectorctl plugin run --dev [--retry-max <n>] [--retry-base-ms <ms>] [--watch] [--watch-interval-ms <ms>] <vendor/slug> [-- <args>…]` — runs `plugin.toml` `runtime.entrypoint` from active `cpkg_store` rollout (subprocess on host); each attempt **POST tier-admit**, quarantine **GET**, spawn; **POST tier-touch** after success; optional backoff retries; sets `ProcessSpec::plugin_crash_plugin_id` so non-success exit POSTs kernel `record_failure`.
- [x] **6.5** `connectorctl plugin verify <path> [--json] [--require-kernel] [--probe-health]` — **MVP shipped** in `connectorctl` (directory / `plugin.toml`, `.toml`, or `.cpkg`): manifest parse+validate, **`agos_sdk::assert_manifest_matches_abi`**, non-empty **`plugin.license`**, **SPDX-style `license` hint** (**`warn`** when weak; not a gate), **`resource_budget_declared`** echo (**`memory_mb` / `vcpus` / `max_concurrency`**), **`[health].path`** when present must be a non-root absolute path, **`routes.prefix` / `routes.admin`** must not shadow **`/api/v1`**, **`.cpkg`** requires **`META/signature.json`** envelope; when **`CONNECTOR_API_URL`** answers **`GET /api/v1`**, manifest **`agos_abi`** must appear in kernel **`agos_abi.supported_contract_ids`** when that array is non-empty, else fall back to **`contract_id`** equality (**6.9**); **`--require-kernel`** fails if the kernel is unreachable; **`--probe-health`** (optional) **`GET /api/v1/health`** and checks **`plugins.<slug>`** for built-in matrix ids (**`tracetramp`**, **`witnessctl`**, **`devguard`**) derived from **`plugin.id`** last segment — **`fail`** when enabled and **`unreachable`**; **`warn`** on **`unknown`**, **`unconfigured`**, or kernel unreachable; **`skip`** for third-party slugs not in the matrix. **Not yet:** full 2A.9 list (syscall/capability scan, idle wake proof, strict SPDX / license expression parser, UI bundle load, per-plugin HTTP probe to **`[health].path`** on a running instance, Ed25519 verify with trust keys, publish gate wiring).
- [x] **6.6** Plugin authoring docs **`docs/agos/plugin-authoring.md`** — AGOS overview, **`cargo connector` / `connectorctl plugin verify`**, rules (`id`, `agos_abi`, routes); **hello world under 30 lines** (25-line `plugin.toml` + 3-line `src/main.rs`, plus `Cargo.toml` snippet). **`docs/index.md`** (Section 8) and **`docs/32-connectorctl.md`** link here.
- [x] **6.7** Reference third-party AGOS plugins — **`examples/agos-reference-plugins/`**: in-repo stubs **`acme/slack-notifier`**, **`acme/jira-bridge`**, **`acme/datadog-forwarder`** (each **`cargo check`** + **`agos_sdk`** only: load `plugin.toml`, `assert_manifest_matches_abi`). Scoped **`network.outbound`** hosts (Slack / Atlassian / Datadog intake). **Hub publish** remains an operator step; CI: **`repo-hygiene`** runs **`cargo check`** on all three manifests.
- [x] **6.8** Author developer portal — same scope as **[x] 4.10**: **`GET/POST /api/v1/author/tokens`**, **`DELETE …/author/tokens/:id`**, **`POST /api/v1/author/namespaces/claim`**, **`GET /api/v1/author/namespaces`**, **`GET /api/v1/author/stats`** (`platform/server/src/services/author_portal.rs`). Dashboard UX polish TBD.
- [x] **6.9** ABI versioning — **`agos-abi`**: **`SUPPORTED_AGOS_CONTRACT_IDS`**, **`STAGED_AGOS_CONTRACT_IDS`**, reserved **`AGOS_CONTRACT_ID_V2`** (`agos.v2`); kernel **`GET /api/v1`** + **`GET /health`** **`agos_abi`** includes **`supported_contract_ids`**, **`staged_contract_ids`**, **`next_contract_id`**, doc pointer; **`agos_sdk::assert_manifest_matches_abi`** checks supported set; **`docs/agos/abi-versioning.md`** + **`PLUGIN_CONTRACT.md`** cross-link; **`connectorctl plugin verify`** uses **`supported_contract_ids`** when present. **Remainder:** dual-contract kernel behaviour + migrate tooling when **`agos.v2`** goes live.

---

## 8. Cross-cutting hygiene rules (always on)

- [ ] One target dir. Never run `cargo` as root.
- [ ] Every PR includes an integration test that boots kernel + the affected plugin via the supervisor.
- [ ] **No new operator‑facing env var.** Settings live in the dashboard, secrets live in the vault. The only allowed env vars are bootstrap (`CONNECTOR_PRESET`, `CONNECTOR_HOST`, `CONNECTOR_PORT`, `CONNECTOR_DATA_DIR`, optional `CONNECTOR_LICENSE`).
- [ ] **No new docker‑compose file, Prometheus rule, Grafana dashboard, or k8s manifest in the repo.** If observability or scale needs grow, extend the built‑in surfaces instead. CI grep‑gate enforces this.
- [ ] **No raw secret in any committed file.** Grep‑gate in CI for `sk-`, `whsec_`, `eyJ`, `cpk_`, `ed25519:`, etc.
- [ ] Routes API and SPA stay decoupled — nothing under `/api/v1/*` may ever return HTML.
- [x] **`ARCHITECTURE.md`** and **`PLUGIN_CONTRACT.md`** in repo root — both exist; keep them updated in the same PR as contract changes (review discipline).
- [ ] `.gitignore` is the source of truth for local artifacts; CI fails if any of its patterns appear in `git ls-files`.
- [ ] `make doctor` passes locally before any push.

---

## 9. File-by-file targets in this repo

### New crates / directories
- `platform/supervisor/`
- `platform/plugin-manifest/`
- `platform/plugin-handshake/`
- `platform/microvm/` (+ `platform/microvm/rootfs/`)
- `platform/workflow/`
- `platform/cpkg/`
- `agos-abi/`                  — versioned plugin ABI (semver-governed)
- `agos-sdk/`                  — public plugin SDK (Rust; Go/Python bindings later)
- `cargo-connector/`           — `cargo connector new …` AGOS plugin scaffold (Cargo subcommand binary)
- `platform/hub/`              — `connector-hub` HTTP registry (MVP: search/latest/download/publish/yank)
- `platform/microvm/`         — `connector-microvm` Firecracker-shaped types + stub host (Phase 5.3)
- `platform/plugin-runtime/`  — `connector-plugin-runtime` subprocess / Docker lab / microvm stub backends (Phase 5.1–5.3); `docker_egress.rs` + `docker.rs` (**5.7.2** optional **`iptables`** `DOCKER-USER`)
- `vendor/firecracker/`
- `lab/`                       — per-plugin docker-compose lives here (lab-only)
- `examples/agos-reference-plugins/` — reference **`acme/*`** stubs (**6.7**); `cargo check` + **`agos-sdk`** only

### Files to rewrite
- `platform/server/src/router.rs` (fallback audit, embed SPA, microvm-aware proxy)
- `platform/server/src/bin/connectorctl.rs` (supervisor commands)
- `platform/server/src/services/plugin_lifecycle.rs`
- `platform/server/src/services/plugin_cpkg.rs` (`.cpkg` install + bundles + health rollback)
- `platform/server/src/services/plugins_status.rs` (rollup → service map)
- `platform/server/src/services/tracetramp_proxy.rs` + `witnessctl_proxy.rs` + `devguard_proxy.rs` (optional: read plugin bootstrap from vault instead of raw env — platform process today)
- `plugins/tracetramp/src/main.rs` + `plugins/witnessctl/src/main.rs` + `plugins/devguard/src/main.rs` (**1.4** `connector-plugin-handshake` at entry)
- `platform/ui-leptos/dashboard/src/components/header_health.rs` (NEW — replace badge cluster)
- `platform/ui-leptos/dashboard/src/pages/service_map.rs` + `pages/plugins/phase5_shared.rs` (Service Map: **phase_5** / cage tables + **5.10.5** ingress topology strip)
- `platform/ui-leptos/dashboard/src/pages/marketplace.rs` (rewrite as Plugin Hub)
- `platform/ui-leptos/dashboard/src/pages/plugins/hub.rs` (extend)
- `platform/ui-leptos/dashboard/src/pages/login.rs` (already done — keep Dev Bypass always on)

### Files to extend (existing CLS / CNP / DNS foundation — do not rebuild)
- `platform/server/src/services/plugin_tier_scheduler.rs`, `plugin_crash_recovery.rs`, `plugin_condo.rs`, `plugin_egress_allowlist.rs` (**`GET …/plugin-egress-allowlist`** → **`phase_5_operator_env`**), `phase5_operator_env.rs`, `runtime_control.rs` (+ `router.rs`, `state.rs`, `main.rs`, `plugin_cpkg.rs`, `plugins_status.rs`) — Phase 5.4–5.7 / 5.10 kernel scaffolding; **`GET /api/v1/runtime/isolation`** `operator_env`.
- `platform/supervisor/src/process_group.rs`, `kernel_crash_notify.rs` — Phase **5.10.2** (`ProcessSpec::plugin_crash_plugin_id` → kernel `record_failure` on non-success exit).
- `platform/server/src/cls/engine.rs` — promote to the single workflow runtime
- `platform/server/src/cls/{compiler,installer,external_bridge}.rs` — wire to plugin lifecycle + Hub
- `oss/connector/crates/connector-engine/src/cls/ccl_*.rs` — CLS pipeline; treat as stable, version it
- `platform/server/src/cnp/stack.rs` + `services/cnp_surface.rs` — workflow transport, route by cage host
- `platform/server/src/services/internal_dns.rs` — register/resolve `<slug>.cnktros`; refuse external resolvers
- `platform/ui-leptos/dashboard/src/pages/cls_builder.rs` — drag‑and‑drop workflow builder
- `platform/ui-leptos/dashboard/src/pages/cls_packages.rs` — CLS source editor
- `platform/ui-leptos/dashboard/src/pages/cls_catalog.rs` — Hub workflow templates
- `platform/ui-leptos/dashboard/src/pages/cls_execution.rs` — run history + dry‑run output

### Files / paths to delete (after migration)
- Per-plugin `plugins/*/docker-compose.yml` outside `lab/`.
- Stale `target/` artifacts owned by root.
- Any doc that tells operators to set `CONNECTOR_TRACETRAMP_ADMIN_TOKEN`.

---

## 10. Definition of Done

The work is complete when **all** of these are true:

### Operator side
- [ ] One `connectorctl start` boots the entire stack (kernel + plugins + UI).
- [ ] One tarball download installs everything; no Docker required.
- [ ] Dev mode is default on first run; admin credentials printed once; Dev Bypass visible on login.
- [ ] Header shows **one** Health pill; click expands to subsystem breakdown.
- [ ] Service Map page shows every plugin / port / proxy / health live.
- [ ] Plugin Hub installs TraceTramp / WitnessCtl / DevGuard via UI in <30 s each.
- [ ] Plugins run in microVMs by default; `connectorctl plugin status` shows VM IDs.
- [ ] Workflows tab lets the operator wire two plugins together via **drag‑and‑drop**, with a one‑click switch to the **CLS source editor** for the same workflow.
- [ ] **Round‑trip**: a workflow built visually opens cleanly in the CLS editor; CLS edits show up correctly in the visual graph (or fall back to a code‑block node).
- [ ] Dry‑run shows what the workflow would have done over the last N minutes of CNP traffic — no side effects.
- [ ] At least three reference CLS workflow templates ship with Connector OS (HITL approve, PII redaction, incident routing).
- [ ] Lab demo recorded end-to-end without any terminal commands after `connectorctl start`.
- [ ] `make doctor` passes; CI green; one tarball uploaded as a release artifact.

### No‑chaos / single‑artifact (Section 2D)
- [x] Repo contains **zero** `docker-compose*.yml` outside `lab/` (Phase 1.6), **zero** Dockerfiles outside `lab/Dockerfile.*`, **zero** Prometheus/Grafana/k8s assets.
- [x] `platform/deploy/.env.example` bootstrap‑only; CI `repo-hygiene` + `scripts/audit-removed-paths.sh` blocks reintroduced §2D paths. (Broad “no secrets in repo” grep still optional.)
- [ ] All settings, secrets, LLM providers, networking, identity, backup, telemetry, license are configured **in the dashboard UI** — no shell exports required after first boot.
- [ ] `connectorctl bootstrap` migrates legacy env‑based secrets into the Secret Vault and removes them from the env file.
- [ ] LLM provider switching + auto‑fallback works end‑to‑end from the UI: kill a primary provider, traffic continues on fallback within the configured window; cost cap stops a runaway plugin.
- [ ] One release artifact only: `connector-os-<ver>-<arch>.tar.gz`. Anything outside that artifact's input tree is excluded from CI release builds.

### Cage addressing (Section 2E)
- [ ] No plugin manifest in the tree contains a hard‑coded public URL; every plugin has a `cage_host` (default `<slug>.cnktros`).
- [ ] `*.cnktros` resolves only inside Connector OS; an external resolver (`dig`, system DNS) cannot find it.
- [ ] Kernel reverse proxy serves `/plugin/<slug>/*` on the operator's chosen origin and forwards to `<slug>.cnktros` over the right runtime backend.
- [ ] CLS workflows reference plugins by cage host; replacing a plugin's runtime backend (subprocess → microVM → docker) does not break workflows.
- [ ] Settings → Networking → Custom domains lets the operator alias `tracetramp.acme.corp → tracetramp.cnktros` with a TLS cert; works end‑to‑end.

### Scale & extensibility (the 100+ plugin bar)
- [ ] 100 plugins installed on a laptop with 80 idle: kernel + dashboard remain responsive; idle plugins consume effectively zero RAM.
- [ ] Cold-start of a suspended plugin completes within its declared `cold_start_budget_ms` for p95 of requests.
- [ ] Shared "plugin condo" microVM hosts ≥50 small plugins without missing health probes.
- [ ] Two AGOS ABI versions (`agos.v1` + `agos.v2`) run side-by-side; older plugins keep working after a kernel upgrade.

### AGOS plugin author side
- [x] `cargo connector new my-plugin` scaffolds a working Rust plugin in seconds (**6.3**); Go/Python templates still open.
- [x] `connectorctl plugin run --dev` supports **subprocess `--watch`** reload (**6.4**); microVM in-guest hot reload still open.
- [ ] `connectorctl plugin verify` enforces **every** certification check from Section 2A.9 (today: **MVP subset** — see **6.5**).
- [ ] `connectorctl plugin publish` signs and pushes to Connector Hub.
- [ ] A first-time third-party developer ships a Hub-published plugin **without contacting us**.
- [ ] At least three reference community plugins are **live on the Hub**, installable from the dashboard (**in-repo Acme stubs:** **6.7** / `examples/agos-reference-plugins/`).

When this list is checked, the puzzle is gone. We have **Connector OS** — and AGOS plugins authored by anyone, in any language, are first-class citizens.
