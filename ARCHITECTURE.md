# Connector OS — architecture map

This file is the **entry index** for how the repository is laid out and where authoritative detail lives.

**Product capability standard (what Connector is for — control, evidence, proof, compliance):** [`platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md`](platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md). **Promise / outcomes:** [`CONNECTOR_PRODUCT_PROMISE.md`](platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md) · [`CONNECTOR_FINAL_OUTCOMES.md`](platform/docs/arch/CONNECTOR_FINAL_OUTCOMES.md). **Operational software (live Talk/tools/start/recall/spend):** [`CONNECTOR_OPERATIONAL_SOFTWARE.md`](platform/docs/arch/CONNECTOR_OPERATIONAL_SOFTWARE.md). **Agent isolation (AgentCell / MicroCell / Firecracker default):** [`CONNECTOR_AGENT_ISOLATION.md`](platform/docs/arch/CONNECTOR_AGENT_ISOLATION.md) · [`CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md`](platform/docs/arch/CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md). **Ecosystem government (OpenShell, OPA, SPIRE, JWT, Firecracker — prove, do not claim):** [`CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md`](platform/docs/arch/CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md). **Agency plane (target ARC):** [`CONNECTOR_ARC.md`](platform/docs/arch/CONNECTOR_ARC.md) · [`CONNECTOR_ARC_IMPLEMENTATION_PLAN.md`](platform/docs/arch/CONNECTOR_ARC_IMPLEMENTATION_PLAN.md).

**Full software architecture encyclopedia (system of record — every crate, binary, kernel/substrate/service module, data path, preset, API mount, effect path, tests, human-trust limits):** [`platform/docs/arch/CONNECTOR_FULL_ARCHITECTURE.md`](platform/docs/arch/CONNECTOR_FULL_ARCHITECTURE.md). **Seven Pillars living status:** [`platform/docs/arch/SEVEN_PILLARS_STATUS.md`](platform/docs/arch/SEVEN_PILLARS_STATUS.md) (`bash platform/scripts/seven-pillars-gate.sh`). Feature pamphlets under `platform/docs/arch/` (exclusivity, ZT, microVM channels, probabilistic LLM) are **slices**; they do not replace that document.

For product sequencing and phased delivery, see **`CONNECTOR_OS_ROADMAP.md`**. For kernel → plugin bootstrap JSON, see **`PLUGIN_CONTRACT.md`**.

## Product shape: one installable software node

**What people install** is a **single Connector OS node**: one product tarball (see **`README.md`** — `make package` → `dist/connector-os-<version>-<arch>-linux.tar.gz`) with **`connector-platform`** as the long-running **runtime** and **`connectorctl`** as the **lifecycle CLI** (start, stop, status, doctor, HTTP helpers). The operator dashboard is **embedded** in `connector-platform` unless you override with **`CONNECTOR_UI_DIR`**, so the default experience is “download, unpack, run one daemon, open the UI” — like normal application software, not a kit of unrelated services.

**Connector OS** is the **operating substrate**: identity, policy, agent lifecycle, gateway, memory, plugins/cage, metrics, and audit all run **in** that node. **Workflows**, **plugins** (AGOS / `.cpkg`), and governed integrations behave like **applications on top of the substrate**: installed, upgraded, started, and stopped **through** the same kernel API and dashboard, with the kernel enforcing caps and egress. The repo layout (`platform/server/`, `oss/connector/`, `platform/plugin-runtime/`) is implementation detail; the **product story** is **one governed node, many workloads on it**.

The **vendor control plane** (`connector-license-server`, account portal) is **outside** that installable node: it issues keys, hosts signup/billing surfaces, and sees fleet telemetry where you deploy it. Customers still experience **one** on-prem / VPC **software node**; the split below is **who runs which binary**, not “every operator assembles their own platform from pieces.”

## Operator story: bring the node up, then bring apps up

This is the **abstract UX** we want operators to internalize. Shorthand like **“connector up”** means **bring the Connector OS node online** (today: start **`connector-platform`**, usually via **`connectorctl start`** or systemd — see **`docs/32-connectorctl.md`**). Until the node is up, there is no stable **HTTP base URL** for the kernel, dashboard, or cage proxies.

**Apps on the node** (used loosely here) are anything the kernel governs or exposes as a **connectable workload**: **CLS workflows**, **AGOS / `.cpkg` plugins**, first-party stacks such as **WitnessCtl**, **TraceTramp**, **DevGuard**, and similar “agentic infra” that needs a **PID**, **listen port** (if any), and **URI** so other agents, tools, or external systems can attach. The product picture is: *after the node is healthy, you discover what is installed and what is active — then you start or enable specific apps and read back how to reach them.*

**At scale (dozens → hundreds of workflows):** Steady-state operations cannot mean “run **`connectorctl`** again for every new workflow someone authors.” The intended model is a **kernel-owned catalog**: when a new workflow appears (drop into a watched directory, CI/CD registration, API apply, or equivalent), **Connector OS detects it**, assigns or confirms a **stable id** and **human-readable name** from package / manifest / path conventions, and it **shows up in the same list** as every other app — **dashboard, list APIs, and automation** — without the operator re-learning new shell steps per artifact. **Bring-up** (“up”) is then **one action on that catalog row** (UI toggle, lifecycle API, policy group), not a separate manual **`connectorctl workflow …`** session per workflow for routine work. **`connectorctl`** remains the right tool for **first boot**, **break-glass**, **CI pipelines**, and **bulk scripted** changes; it is **not** the primary interface each time a teammate ships workflow #37 or #138.

- **Discover / list:** In the story you described, this is like **`app ls`**: one **merged catalog** of workloads and wiring. **Today** some of that is split across **`connectorctl plugins list`**, **`connectorctl workflow list`**, **`connectorctl health` / `status` / `doctor`**, and **`GET /api/v1/plugins/status`**; **product direction** is **automatic catalog updates** when new workflows land, plus a **single** list surface (CLI + API + UI) so operators are not touching the shell repeatedly as workflow count grows.
- **Start / enable an app:** Colloquially **“connector witnessctl up”** or **“workflow up”** means *transition that workload to an active, reachable state* (plugin process healthy, workflow lifecycle **ENABLED**, host agent running, etc.). **Today** you use plugin install/enable paths, **`connectorctl workflow enable <id>`**, lab scripts, or host installers depending on the app — because **DevGuard-style “computer-level”** setups touch the **host OS** (permissions, drivers, browser hooks) while **in-kernel workflows** are **data + lifecycle inside `connector-platform`**. Same *mental* step (“app up”); different *mechanics* by class of app. **Direction:** that transition should be invokable **from the catalog** (same place you listed it), not only by ad-hoc CLI flags per item.
- **Show / inspect:** Once an app is up, operators and automation need a **stable report**: **active or not**, **PID** when the kernel supervises a child process, **port** and **base URI** (public URL, cage-internal `*.cnktros` host, or gateway path) so **agentic infrastructure** can register and call it. **Today** much of this appears in **health / plugin status JSON**, dashboard Service Map, and **`connectorctl`** inspect verbs; the product direction is to make that summary **consistent per app**, like `show witnessctl` printing one small table row.

**Summary:** **One node** (substrate) → **many apps** (workflows, plugins, observability stacks, host tools) → **catalog that updates when new workflows appear** → **up / inspect from the catalog** (PID / port / URI) → governed agents and workflows drive the rest — with **`connectorctl`** for bootstrap and automation, **not** as a per-workflow treadmill.

## Customer node vs vendor control plane (two backends, two UIs)

Operators run **their** stack on their hardware or VPC. **We** run a separate control-plane stack for licensing, signup, billing handoff, and fleet visibility.

| Role | Binary / crate root | Primary HTTP API | Primary UI |
|------|---------------------|------------------|------------|
| **Customer / Connector OS node** | `connector-platform` → `platform/server/` | `/api/v1/*` (agents, gateway, governance, billing on the node) | **Operator dashboard** — Leptos app `platform/ui-leptos/dashboard/` (crate `connector-ui`), embedded in the server or overridden with `CONNECTOR_UI_DIR` (see `platform/server/src/router.rs` comments). |
| **Vendor-maintained control plane** | `connector-license-server` → `platform/licensing/` | `/api/v1/portal/*`, `/api/v1/keys/*`, `/rpc/v1/*`, surveillance/admin routes (see `platform/licensing/src/main.rs`) | **Account / marketing portal** — Leptos CSR `platform/ui-leptos/www/` (crate `connector-www`), static root + `CONNECTOR_WWW_DIR`; internal **admin** SPA at `/admin` + `CONNECTOR_ADMIN_UI_DIR`. **Planned:** same public origin also hosts **docs/tutorials** and embeds a **hosted playground** (shared `connector-platform` fleet) — see **`CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md`**. |

Production topology is spelled in **`docs/index.md`** (license server split) and **`platform/deploy/install.sh`** (systemd ordering: `connector-license` before `connector-platform` where both are used).

**Optional minimal OSS HTTP engine:** `connector-server` in `oss/connector/crates/connector-server` is a smaller surface for labs or embed-only runs; it is **not** the full commercial kernel. Path dependencies from `platform/server` still pull shared crates from `oss/connector/`.

## Runtime stack

| Layer | Location | Notes |
|--------|-----------|--------|
| Commercial kernel (HTTP, auth, plugins, workflows) | `platform/server/` | Axum router in `src/router.rs`; `connectorctl` in `src/bin/connectorctl.rs`. |
| Vendor license + portal API + www static | `platform/licensing/` | `connector-license-server`; portal REST under `/api/v1/portal/*`. |
| OSS connector / engine | `oss/connector/` | Shared engine, protocols, caps; used as path dependencies from `platform/server`. |
| VAC / storage substrate | `oss/vac/` | Supporting crates for distributed / storage paths. |
| Supervisor (process groups, crash hooks) | `platform/supervisor/` | `ProcessGroup`, `supervisee_inventory()` (`Phase 5.10.6`). |
| Plugin runtime (subprocess, Docker lab, microvm, wasm) | `platform/plugin-runtime/` | Isolation backends for AGOS entrypoints. |
| Hub (`.cpkg` registry MVP) | `platform/hub/` | Search / install / publish flows per roadmap §4.x. |

## AGOS plugins (community)

| Artifact | Location |
|-----------|-----------|
| ABI constants | `agos-abi/` |
| Public Rust SDK | `agos-sdk/` |
| `cargo connector new` | `cargo-connector/` |
| Manifest schema | `platform/plugin-manifest/` |
| Handshake | `platform/plugin-handshake/` |
| `.cpkg` format | `platform/cpkg/` |
| Reference third-party stubs | `examples/agos-reference-plugins/` |
| First-party plugin sources | `plugins/*` |

## Operator & author docs

- **Final AIOS → L5 coding checklist + claim:** [`FINAL_REACH.md`](FINAL_REACH.md) — **engineering gate:** `make engineering-reach-gate` (L3 AIOS + L4 substrate + L5 mesh soaks).
- **Distributed intelligence OS (kernel → ACS, what we built):** [`DISTRIBUTED_INTELLIGENCE_PLAN.md`](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3 §0**. Operator create: [`INTELLIGENCE_5MIN.md`](INTELLIGENCE_5MIN.md). Status: [`IIA_STATUS_REPORT.md`](IIA_STATUS_REPORT.md). **Now possible:** [`AGENTIC_INFRA_NOW_POSSIBLE.md`](AGENTIC_INFRA_NOW_POSSIBLE.md). **Court-defensible:** [`COURT_DEFENSIBLE_CHECKLIST.md`](COURT_DEFENSIBLE_CHECKLIST.md).
- **IIA v2 court-grade intelligence identity (P10 vertical spine on top of L3–L5):** [`IIA_CORE_UPGRADE_CHECKLIST.md`](IIA_CORE_UPGRADE_CHECKLIST.md) — N4 → QPR → DockLock → forensics; claim tests T19–T24.
- **What Connector can do when IIA is complete (on today’s stack):** [`CONNECTOR_WHEN_IIA_COMPLETE.md`](CONNECTOR_WHEN_IIA_COMPLETE.md).
- **Truthful product story (0 → today → future, what agents become):** [`docs/CONNECTOR_TRUTH_STORY.md`](docs/CONNECTOR_TRUTH_STORY.md).
- **21-segment maturity + coding upgrade plan:** `MATURITY_21_SEGMENTS.md` · `MATURITY_21_UPGRADE_PLAN.md`. Low-RAM: `docs/LOW_MEMORY_DEV.md` · light WF check: `bash platform/scripts/check-reference-templates-light.sh`.
- **Remaining work until “one setup” product (Ollama‑lite install, OS‑grade depth; market complexity + blueprint tracks):** `CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md` (companion to `CONNECTOR_OS_ROADMAP.md` §7 / §10).
- **Post–ship usage story (agents → TraceTramp / WitnessCtl / DevGuard / workflows):** `CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`.
- **Checklist to story finish line + public launch:** `CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`.
- **Hosted playground + public docs website (try before install / calendar):** `CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md`.
- **Doc library index:** `docs/index.md`
- **AGOS authoring:** `docs/agos/plugin-authoring.md`
- **ABI / `agos.v2` policy:** `docs/agos/abi-versioning.md`
- **CLI reference:** `docs/32-connectorctl.md`

## UI

- **Operator dashboard (ships with the node):** `platform/ui-leptos/dashboard/` (crate **`connector-ui`**) — Service Map, Plugins hub, CLS surfaces; HTTP client uses **`/api/v1`** (`platform/ui-leptos/dashboard/src/api.rs`). Served by **`connector-platform`** (embedded dist or `CONNECTOR_UI_DIR`).
- **Customer / vendor portal (we host):** `platform/ui-leptos/www/` (crate **`connector-www`**) — signup, login, billing, profile, API keys; client uses **`/api/v1/portal`** (`platform/ui-leptos/www/src/api.rs`). Static assets are served by **`connector-license-server`** at site root (`CONNECTOR_WWW_DIR`). The platform router notes that the portal SPA is **not** bundled into `connector-platform` (`router.rs` comment near dashboard static serving).

## CI & packaging

- **Workflows:** `.github/workflows/` (e.g. `repo-hygiene.yml`, kernel gates).
- **Scripts:** `platform/scripts/`, `scripts/` at repo root where present.

## Mental model (nine rings + intelligence OS)

Connector is described as concentric enforcement rings (identity → audit). The narrative lives in **`docs/11-architecture-overview.md`**; do not duplicate it here.

**On top of those rings** the node now runs a **distributed intelligence OS**: charter + ACS + NS FS per pid, three admission layers (Root / Cone / App), world grants per `(pid × address)`, and share only via contract/portal. Picture and honesty table: **[`DISTRIBUTED_INTELLIGENCE_PLAN.md`](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0**. This file stays the **install-node** map — one `connector-platform` daemon — not a rewrite of that stack.

---

When you change the **plugin wire contract** or **ABI fields** exposed on **`GET /api/v1`**, update **`PLUGIN_CONTRACT.md`** and **`agos-abi`** in the **same PR** as **`CONNECTOR_OS_ROADMAP.md`** calls out.
