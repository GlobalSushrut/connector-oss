# Connector OS — checklist to the story finish line + public launch

> **Goal:** Ship a **public** Connector OS build where the stories in **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** are true for a first-time operator, and releases are **repeatable, documented, and safe**.  
> **Sources of truth:** **`CONNECTOR_OS_ROADMAP.md`** §7 (phased engineering), §8 (hygiene), §10 (Definition of Done); **`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`** (complexity + blueprint **T1–T8**); **`ARCHITECTURE.md`**.

Use this file as the **master go / no-go** list. Check boxes in Git or your tracker of choice; keep section owners named in the column you use externally.

---

## Part A — Story acceptance (must match `CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`)

### A.1 Shared premise (Maya’s path)

- [ ] **Single artifact:** Linux tarball installs **`connector-platform`** + **`connectorctl`** + sample config (`make package` / CI equivalent); documented checksums on the release page.
- [ ] **One obvious start:** `connectorctl start` (or documented systemd unit) brings the **kernel + embedded UI**; no second “mystery” Connector process on the same host for the default path.
- [x] **Unified catalog API:** `GET /api/v1/apps` + `connectorctl app list|show` lists **plugins + workflows** with **status**, **port**, **uri** / **public_uri**, **cage host**, **actions**.
- [ ] **Unified catalog UI:** Dashboard Apps hub consumes `/api/v1/apps` (single index, not split pages only).
- [ ] **Catalog scale:** New workflow packages **appear in the list** without a bespoke shell ritual for each (kernel discovery / registration path implemented and tested).
- [ ] **Catalog scale:** New workflow packages **appear in the list** without a bespoke shell ritual for each (kernel discovery / registration path implemented and tested).

### A.2 Story A — Jordan (gateway + TraceTramp)

- [ ] **Gateway URL** is copy-pasteable from **Service Map** (or Settings) with correct TLS/host for the chosen deployment.
- [ ] **Scoped API keys** (or equivalent) can be minted with **least privilege** for “call gateway + emit traces” (no admin).
- [ ] **Settings → LLMs** fully drives providers used by agents (keys in vault); **Ollama / vLLM / OpenAI-compatible** paths validated in a clean install doc.
- [ ] **TraceTramp** installable from **Hub UI** within the roadmap time budget; **reachable** via **`/plugin/tracetramp/…`**; traces from gateway traffic visible end-to-end.

### A.3 Story B — Sam (WitnessCtl + receipts)

- [ ] **WitnessCtl** installable from Hub UI; reachable via **`/plugin/witnessctl/…`**; health green on Service Map.
- [ ] **CLS workflows** can express **witness / HITL** steps that execute against **CNP** (no direct plugin-to-plugin bypass); auditor-facing flows documented once.

### A.4 Story C — Riley (custom workflows)

- [ ] **Workflow publish path:** Package → Hub (or private mirror) → **install/enable from dashboard** documented for a third party.
- [ ] **Dry-run** reflects **realistic traffic semantics** (roadmap Phase **3.6** complete enough for “would have done” not only static blueprint); **rollback** exercised from UI or single API.
- [ ] **Builder ⇄ CLS** round-trip meets §10 (visual graph + source editor, or explicit code-block fallback where graph cannot represent).

### A.5 Story D — Alex (DevGuard + dev tools)

- [ ] **DevGuard** first-run / host integration documented for **at least one** supported dev stack (e.g. Linux + supported IDE path); **device registration** to the node works without prod secrets on the laptop.
- [ ] **Policy lineage:** Dev profile and staging/prod **policy / workflow ids** align in the documented quickstart (no “different product” between dev and prod governance fields).

### A.6 Trust plane (stories assume it)

- [ ] **REST RBAC:** Sensitive **`/api/v1/*`** routes enforce **JWT / role / scope** consistently (close gaps in **`platform/docs/arch/CONNECTOR_PROFILE_UI_RPC_RBAC_ASSESSMENT.md`**).
- [ ] **UI-RPC:** Per-method authorization; **no** privileged **`system.*`** without role checks.
- [ ] **`/auth/me`** (or one aggregate “operator profile”) supports dashboard **billing/plan** surfaces without fragile multi-call stitching **or** the UI is explicitly scoped to “node admin only” and documented as such.

---

## Part B — Definition of Done (`CONNECTOR_OS_ROADMAP.md` §10)

Mirror §10 here until every box is checked in the product, not only in docs.

### B.1 Operator side

- [ ] One `connectorctl start` boots the entire stack (kernel + plugins + UI).
- [ ] One tarball download installs everything; no Docker required.
- [ ] Dev mode is default on first run; admin credentials printed once; Dev Bypass visible on login.
- [ ] Header shows **one** Health pill; click expands to subsystem breakdown.
- [ ] Service Map page shows every plugin / port / proxy / health live.
- [ ] Plugin Hub installs TraceTramp / WitnessCtl / DevGuard via UI in <30 s each.
- [ ] Plugins run in microVMs by default; `connectorctl plugin status` shows VM IDs.
- [ ] Workflows tab lets the operator wire two plugins together via **drag‑and‑drop**, with a one‑click switch to the **CLS source editor** for the same workflow.
- [ ] **Round‑trip**: a workflow built visually opens cleanly in the CLS editor; CLS edits show up correctly in the visual graph (or fall back to a code‑block node).
- [ ] Dry‑run shows what the workflow would have done over the last N minutes of **CNP** traffic — no side effects.
- [ ] At least three reference CLS workflow templates ship with Connector OS (HITL approve, PII redaction, incident routing).
- [ ] Lab demo recorded end-to-end without any terminal commands after `connectorctl start`.
- [ ] `make doctor` passes; CI green; one tarball uploaded as a **release artifact**.

### B.2 No‑chaos / single‑artifact

- [ ] All settings, secrets, LLM providers, networking, identity, backup, telemetry, license are configured **in the dashboard UI** — no shell exports required after first boot.
- [ ] `connectorctl bootstrap` migrates legacy env‑based secrets into the Secret Vault and removes them from the env file (documented runbook).
- [ ] LLM provider switching + auto‑fallback works end‑to‑end from the UI: kill a primary provider, traffic continues on fallback within the configured window; cost cap stops a runaway plugin.
- [ ] One release artifact only: `connector-os-<ver>-<arch>.tar.gz`. Anything outside that artifact's input tree is excluded from CI release builds.

### B.3 Cage addressing (Section 2E)

- [ ] No plugin manifest in the tree contains a hard‑coded public URL; every plugin has a `cage_host` (default `<slug>.cnktros`).
- [ ] `*.cnktros` resolves only inside Connector OS; an external resolver (`dig`, system DNS) cannot find it.
- [ ] Kernel reverse proxy serves `/plugin/<slug>/*` on the operator's chosen origin and forwards to `<slug>.cnktros` over the right runtime backend.
- [ ] CLS workflows reference plugins by cage host; replacing a plugin's runtime backend (subprocess → microVM → docker) does not break workflows.
- [ ] Settings → Networking → Custom domains lets the operator alias `tracetramp.acme.corp → tracetramp.cnktros` with a TLS cert; works end‑to‑end.

### B.4 Scale & extensibility (100+ plugin bar)

- [ ] 100 plugins installed on a laptop with 80 idle: kernel + dashboard remain responsive; idle plugins consume effectively zero RAM.
- [ ] Cold-start of a suspended plugin completes within its declared `cold_start_budget_ms` for p95 of requests.
- [ ] Shared "plugin condo" microVM hosts ≥50 small plugins without missing health probes.
- [ ] Two AGOS ABI versions (`agos.v1` + `agos.v2`) run side-by-side; older plugins keep working after a kernel upgrade.

### B.5 AGOS plugin author side (public ecosystem)

- [ ] `connectorctl plugin verify` enforces **every** certification check from Section 2A.9 (today: MVP subset — see roadmap **6.5**).
- [ ] `connectorctl plugin publish` signs and pushes to Connector Hub.
- [ ] A first-time third-party developer ships a Hub-published plugin **without contacting us** (runbook + dogfood proof).
- [ ] At least three reference community plugins are **live on the Hub**, installable from the dashboard.

---

## Part C — Blueprint tracks (`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md` §3)

Condensed “all T’s green” for launch readiness.

- [ ] **T1 — Substrate boot:** Upgrade/restart story documented; no ambiguous multi-Connector on default install.
- [ ] **T2 — Operator shell:** Dashboard replaces env archaeology for all settings in Part B.2.
- [ ] **T3 — Workflow engine:** Phase **3** closeout — CLS single runtime path, **CNP-only** fabric, real dry-run/replay semantics, Hub workflow packages as needed.
- [ ] **T4 — Extension economy:** Hub + verify + publish path production-grade; signing trust documented.
- [ ] **T5 — Isolation & scale:** Phase **5** production defaults met for public claim (microVM default, egress + resource governance per roadmap open items you accept for v1).
- [ ] **T6 — Cage & naming:** Part B.3 complete in running builds.
- [ ] **T7 — Trust plane:** Part A.6 complete.
- [ ] **T8 — Commercial split:** Customer tarball path documented; optional **`connector-license-server`** + portal path documented for paid/SaaS without confusing the OSS-style single-node story.

---

## Part D — Public launch (distribution, docs, trust)

### D.1 Release mechanics

- [ ] **Versioning policy** published (semver for `connector-os` tarball; kernel API contract pointers in **`PLUGIN_CONTRACT.md`** / **`agos-abi`**).
- [ ] **CI release job** produces: tarball(s) per supported arch, **`SHA256SUMS`**, **release notes** (breaking / migration / known issues).
- [ ] **Artifact signing** (min: cosign or GPG signatures) documented; users can verify before install.
- [ ] **Upgrade guide:** from N to N+1 without data loss (backup/restore, `data_dir`, vault key handling called out).

### D.2 First-run documentation (public)

- [ ] **Public quickstart** (≤15 minutes): download → verify → start → login → install one plugin → run one workflow template → point one SDK at gateway (Jordan path).
- [ ] **Production hardening guide:** TLS, host firewall, `CONNECTOR_PRESET`/prod mode, backup, **no** default weak creds in prod.
- [ ] **Compatibility matrix:** supported Linux distros, libc, **aarch64 + x86_64** (or explicit exclusion).

### D.3 Legal & safety

- [ ] **License** file clear for tarball contents (kernel + embedded OSS; third-party notices if bundled).
- [ ] **Terms / privacy** for any phone-home, analytics, or vendor portal (**`connector-license-server`**) if enabled by default in a given SKU.
- [ ] **Security disclosure** process published (email or GitHub **SECURITY.md**); severity SLA stated.

### D.4 Support & community

- [ ] **Public issue templates** (bug / feature / security).
- [ ] **Changelog** discipline (`CHANGELOG.md` or GitHub Releases body) tied to semver.
- [ ] **Status page or “known limitations”** section for v1 (what is not promised yet).

---

## Part G — Playground + docs website (marketing launch)

Full plan: **`CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md`**. Required for **public try-before-install** and **calendar-after-try** funnel (not required to ship self-hosted tarball alone).

### G.1 One website (product + docs + try)

- [ ] Single branded origin (or documented subdomain set with **shared nav**): Product · **Docs** · **Playground** · Pricing · Book demo.
- [ ] Public docs IA live: quickstart, architecture summary, connectorctl, AGOS intro (≥5 pages from `docs/`).
- [ ] **Trust hub:** security disclosure, playground privacy/retention, license, changelog, known limitations.

### G.2 Hosted playground (real node)

- [ ] Playground runs **real** `connector-platform` + embedded **`connector-ui`** (not a mock).
- [ ] Session service: mint scoped key, TTL, idle wipe, rate limits; **automated test** that session A cannot read session B data.
- [ ] Playground LLM/cost caps; visitor BYOK for unrestricted providers **out of scope** for v1 unless explicitly designed.
- [ ] Pre-seeded catalog: TraceTramp / WitnessCtl / DevGuard + reference workflows per story doc §1.
- [ ] **Guided tour** (≥3 steps) + deep link from tutorials.

### G.3 Tutorials (website-only learning path)

- [ ] **T1–T3** completable without installing software (gateway, Service Map, TraceTramp peek).
- [ ] **T4–T7** documented (WitnessCtl, workflows, DevGuard concept, self-host download) — playground exercises where feasible.
- [ ] Each tutorial: Next · Open playground · **Book a call** (soft CTA).

### G.4 Conversion (calendar after try)

- [ ] Calendar embed on `/demo` and post-tutorial screens — **not** primary homepage hero.
- [ ] UTM / session context passed to booking tool for sales.
- [ ] Portal handoff documented: signup → install tarball / pilot grant.

### G.5 Playground ops

- [ ] Privacy policy covers playground session data.
- [ ] Playground SLO / capacity stated (single node v1 vs pool v1.5).
- [ ] Analytics: playground start, tutorial complete, calendar click (privacy-preserving).

---

## Part E — Cross-cutting engineering gates (`CONNECTOR_OS_ROADMAP.md` §8)

Treat as **launch blockers** until explicitly waived for a private beta only.

- [ ] One target dir. Never run `cargo` as root (enforced culturally + CI where possible).
- [ ] Every PR that touches kernel/plugins includes or updates an **integration test** that boots kernel + affected plugin via supervisor (per §8 intent).
- [ ] **No new operator-facing env var** beyond bootstrap allowlist (`CONNECTOR_PRESET`, `CONNECTOR_HOST`, `CONNECTOR_PORT`, `CONNECTOR_DATA_DIR`, optional `CONNECTOR_LICENSE`).
- [ ] **No new** `docker-compose*.yml` outside `lab/`, no new Prometheus/Grafana/k8s manifests in repo (CI grep gates).
- [ ] **No raw secrets** in git; secret grep CI green.
- [ ] **`/api/v1/*` never returns HTML** for unknown API paths (regression tests stay green).
- [ ] `.gitignore` patterns do not appear in `git ls-files` (if CI enforces).
- [ ] `make doctor` passes on release branch before tag.

---

## Part F — Go / no-go sign-off (fill at release time)

| Role | Name | Date | Notes |
|------|------|------|-------|
| Engineering lead | | | Parts A–E |
| Security | | | A.6, D.3, E |
| Docs / DevRel | | | D.2 |
| Product | | | Story doc reviewed against build |

---

## Quick links

| Doc | Role |
|-----|------|
| **`CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md`** | Target “feel” and personas |
| **`CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md`** | Hosted try + docs site + calendar |
| **`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`** | Why work is heavy + blueprint **T1–T8** |
| **`CONNECTOR_OS_ROADMAP.md`** §7 / §8 / §10 | Engineering order + DoD + hygiene |
| **`ARCHITECTURE.md`** | Node vs vendor plane, operator loop |
| **`docs/32-connectorctl.md`** | CLI mental model |

When **Part A + Part B + Part C** are satisfied, the **story** is honest. When **Part D + Part E** are satisfied, the **self-hosted public launch** is responsible. When **Part G** is satisfied, the **try-on-the-website + docs + calendar** funnel is ready.

| Doc | Role |
|-----|------|
| **`CONNECTOR_OS_PLAYGROUND_AND_DOCS_SITE_PLAN.md`** | Playground SaaS, docs IA, tutorials, calendar funnel (phases P0–P3) |
