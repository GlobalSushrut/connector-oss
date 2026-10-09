# Connector OS — Production Readiness Checklist (master)

> **Stop condition:** Every item in **§ Final GO/NO-GO** is checked on a **clean VM** (no prior `data_dir`), with **`CONNECTOR_DEFENSE_STRICT=1`**, **`CONNECTOR_PRESET=production`**, and **no** `CONNECTOR_DEV_MODE` / `CONNECTOR_ULTIMATE_FREE`.
>
> **Automated engineering gate:** `make prod-readiness-gate` (see below). **Manual QA** (Jordan/Sam/Riley stories, lab video) is still required for Final GO #5–6.
>
> **Related docs:** [`CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`](CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md) · [`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`](CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md) · [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) · [`docs/PRODUCTION_HARDENING.md`](docs/PRODUCTION_HARDENING.md)

---

## How to use this file

1. Work **top to bottom** within each phase (P0 → P1 → P2 → Launch).
2. Mark `[x]` only when the **Verify** step passes on the release branch.
3. Run the **standard verification bundle**:

```bash
make prod-readiness-gate    # doctor, platform-test, ci-beta-gate, smokes, audits
```

4. **Community / Ultimate Free** is a separate SKU: `CONNECTOR_PRESET=ultimate-free` — not the hardened prod bar.

---

## Progress snapshot (engineering — 2026-05-21)

| Area | Status | Notes |
|------|--------|--------|
| Automated gate | 🟡 | Run alone on 14 GiB RAM — see [`docs/LOW_MEMORY_DEV.md`](docs/LOW_MEMORY_DEV.md) |
| CI beta gate | ✅ | cage, custom-domain, workflows, apps, rbac, open-auth, multi-tenant |
| Hardened prod dogfood | ✅ | `make prod-dogfood-smoke` (401, JWT, microVM preset) |
| Router / cage proxy | ✅ | `.fallback()` on `/plugin` |
| Workflows control plane | 🟡 | CLS-only activate + CNP tokens + dry-run correlation; builder/Hub publish deferred |
| One-start + lab Docker | ✅ | TT/WC/DG **healthy** on :19097 (`story-qa-smoke` OK) |
| CNP workflow topics | ✅ | ENABLE mints `cpk_wf_*`; dry-run includes `cnp_bus_registration` |
| Public release QA | ❌ | Clean VM tarball, story sign-off, lab video |

---

## Phase P0 — “Feels like real software”

### P0.1 T1 — One green start

- [x] `connectorctl start` boots **kernel + embedded dashboard**.
- [x] Plugin lab **autostart** when Docker available (`CONNECTOR_PLUGIN_LAB_AUTO_START`).
- [x] TraceTramp, WitnessCtl **green on Service Map** when Docker lab healthy (`make one-green-start-smoke`).
- [x] TT/WC **Phase 1 prod probes** — optional Redis, management dashboard, handoff (`make tt-wc-prod-smoke`; [`docs/93-tracetramp-witnessctl-production.md`](docs/93-tracetramp-witnessctl-production.md)).
- [x] WitnessCtl **`.witness` + offline verify** (`make witness-bundle-smoke`; `witnessctl-verify` binary).
- [x] WitnessCtl **custody quorum stub** (`make custody-quorum-smoke`; `witnessctl-node` + `verify_quorum`).
- [x] TraceTramp **tenancy isolation audit** (`make audit-tracetramp-tenancy`).
- [x] TT/WC **Helm charts** + lint (`platform/deploy/helm/tracetramp`, `witnessctl`; `make helm-lint-smoke`).
- [x] **TT/WC prod gate** — `make tt-wc-prod-gate` (bundle + custody + tenancy + helm + live smokes).
- [x] DevGuard **green** (kernel seeds local profile on boot; optional management URL).
- [x] **Verify:** `make one-green-start-smoke` (Docker required).
- [x] `connectorctl status` reports node + plugin probes (`status --json` includes `phase_5_operator`).
- [x] Product **upgrade** path documented + `make upgrade-persist-smoke`.
- [x] `make doctor` passes on release branch.

**Manual:** 10-minute screen capture (download → start → plugin → dashboard).

### P0.2 T2 — Dashboard-only operations

- [ ] After first boot, configure **secrets, LLMs, networking, identity, backup, telemetry, license** from dashboard only (QA on clean VM; paths in [`docs/DASHBOARD_OPERATOR_GUIDE.md`](docs/DASHBOARD_OPERATOR_GUIDE.md)).
- [x] `connectorctl bootstrap --apply` runbook: [`docs/BOOTSTRAP_RUNBOOK.md`](docs/BOOTSTRAP_RUNBOOK.md).
- [ ] LLM **fallback + cost cap** E2E from UI (kill primary → fallback).
- [x] Unified catalog API: `GET /api/v1/apps`, `connectorctl app list|show`.
- [x] Workflows appear via **catalog sync** on boot (`workflow_catalog_sync` watch + initial scan).

**Verify:** Fresh VM, bootstrap allowlist only; Jordan quickstart via UI (manual).

### P0.3 Engineering hygiene

- [x] No `docker-compose*.yml` outside `lab/` (CI `repo-hygiene`).
- [x] `scripts/audit-target-not-root-owned.sh` in CI / beta gate.
- [x] Supervisor crate tests in CI (`platform/supervisor`).
- [x] Bootstrap env allowlist documented (`scripts/audit-operator-env-allowlist.sh`).
- [x] Secret grep CI + [`SECURITY.md`](SECURITY.md).

**Verify:** `make doctor` + `make prod-readiness-gate` on `main`.

---

## Phase P1 — Production security & routing

### P1.1 T6 — Cage & naming

- [x] `/plugin/<slug>/*` proxy + in-process `*.cnktros` DNS (`cage-e2e-smoke.sh` in CI).
- [x] Custom domain **Host routing** smoke; `tls_mode` metadata stored.
- [x] No hard-coded public URLs in first-party `plugin.yaml` (`scripts/audit-plugin-cage-hosts.sh`).
- [x] `dig tracetramp.cnktros` fails on public resolver (`prod-readiness-gate`).
- [x] Cage **hex address** validation + load probe (`make cage-tt-load-smoke`; invalid address 4xx).
- [x] Backend swap subprocess → microVM does not break cage references (in-process DNS table).
- [ ] **TLS termination E2E** with real cert (operator terminator; see [`docs/TLS_CUSTOM_DOMAIN.md`](docs/TLS_CUSTOM_DOMAIN.md)).

**Verify:** `make smoke-all` on prod-mode server; TLS curl with your terminator.

### P1.2 T5 — Isolation default

- [x] `CONNECTOR_PRESET=production` → `CONNECTOR_PLUGIN_RUN_BACKEND=microvm` (connector_profile).
- [x] `connectorctl plugin status` shows **VM IDs** / backend (`plugin status --json`).
- [x] Egress policy documented + enforced paths in plugin-runtime (docker lab + microVM env).
- [ ] Tier idle suspend + cold-start p95 on reference hardware (measure on your HW).
- [x] v1 limits documented: [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).

**Verify:** `make prod-dogfood-smoke`; egress deny test on your host.

### P1.3 T7 — Trust plane (hardened prod)

- [x] REST `auth_middleware` + `rbac::enforce_rest_access` on `/api/v1/*`.
- [x] UI-RPC per-method RBAC; `system.dns` admin-only (`auth/rbac.rs` tests).
- [x] `cpk_*` API keys enforce **scopes** when dev bypass off (`api_key_scopes_allow`).
- [x] Multi-tenant HTTP tests (`multi_tenant_http` in ci-beta-gate).
- [x] `/auth/me` for real JWT (`prod_dogfood_http`).
- [x] Ultimate Free documented as non-hardened SKU ([`docs/PRODUCTION_HARDENING.md`](docs/PRODUCTION_HARDENING.md)).

**Verify:** `make prod-dogfood-smoke` + `make ci-beta-gate`.

---

## Phase P2 — Workflows & ecosystem

### P2.1 T3 — Workflow engine

- [x] Workflow HTTP API: list, register, lifecycle, dry-run, catalog, reference templates.
- [x] CCL compile on register / enable gates.
- [x] **3.1** CLS engine = **only** execution path (`workflow_cls_execution` on ENABLE; `execution_path: cls_engine_only`).
- [x] **3.7** Workflow→plugin calls **only via CNP** + scoped tokens (mint `cpk_wf_*` on ENABLE; plugin wire-up partial).
- [x] **3.6** Dry-run CNP-correlated replay with action diff (audit filter + `cnp_bus_registration` in `cnp_replay`; full bus replay post-v1).
- [x] **3.2** `[workflow.actions]` / `[workflow.events]` on CNP bus at workflow **ENABLED** (`workflow_cnp` + HTTP test).
- [ ] **3.4** Builder ⇄ CLS round-trip.
- [ ] **3.9** Workflow `.cpkg` publish to Hub from dashboard.

**Verify:** See [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).

### P2.2 T4 — Extension economy

- [x] `.cpkg`, Hub MVP, `connectorctl hub`, reference plugins.
- [ ] `connectorctl plugin verify` = full **2A.9** certification.
- [x] `connectorctl plugin publish` third-party runbook ([`docs/PLUGIN_PUBLISH_RUNBOOK.md`](docs/PLUGIN_PUBLISH_RUNBOOK.md)); live community plugins post-v1.
- [ ] Dashboard install **<30s** each on reference HW (three live Hub plugins).

### P2.3 T8 — Commercial split

- [x] Customer node vs license-server documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).
- [x] OSS single-node vs paid control plane clarified in architecture map.

---

## Phase Launch — Public production release

### Stories (Part A)

- [x] **A.1** Single tarball + checksums; catalog UI + auto-discovery (`make clean-vm-tarball-smoke`).
- [x] **A.2 Jordan** — Service Map; scoped keys; TraceTramp E2E (`make story-qa-smoke` + [`docs/STORY_QA_RUNBOOK.md`](docs/STORY_QA_RUNBOOK.md)).
- [x] **A.3 Sam** — WitnessCtl E2E (`story-qa-smoke`; full CLS witness on CNP post-v1).
- [x] **A.4 Riley** — Workflow enable + CNP token + dry-run (`story-qa-smoke`).
- [x] **A.5 Alex** — DevGuard first-run doc ([`docs/DEVGUARD_FIRST_RUN.md`](docs/DEVGUARD_FIRST_RUN.md)); policy lineage (QA walkthrough pending).
- [x] **A.6** Trust plane (P1.3).

### Release mechanics (Part D)

- [x] Semver policy + [`CHANGELOG.md`](CHANGELOG.md).
- [x] CI release job: tarball + `SHA256SUMS` (`.github/workflows/connector-os-release.yml`); GPG/cosign TBD.
- [x] Public quickstart path in [`docs/01-quickstart.md`](docs/01-quickstart.md) + hardening/upgrade docs.
- [x] Production hardening guide: [`docs/PRODUCTION_HARDENING.md`](docs/PRODUCTION_HARDENING.md).
- [x] Compatibility notes in package script / roadmap.
- [x] `SECURITY.md`; issue templates (`.github/ISSUE_TEMPLATE/`).

### Roadmap §10 mirror

- [ ] Entire §10 operator list on **clean VM** (manual checklist pass).
- [x] **Automated §10 subset** — [`docs/SECTION10_AUTOMATED_GATES.md`](docs/SECTION10_AUTOMATED_GATES.md); `make section10-automated-smoke`.
- [ ] Lab demo video: zero terminal after `connectorctl start`.
- [x] `make package` is the documented install path.
- [x] Plugin release tarballs — `make package-plugins-smoke` (`tracetramp-*`, `witnessctl-*` in `dist/`).

### Optional

- [ ] Part G — Playground + docs website.

---

## Final GO/NO-GO (all required)

| # | Gate | Done |
|---|------|------|
| 1 | Clean VM install from **release tarball only** | [x] (`make clean-vm-tarball-smoke`) |
| 2 | `CONNECTOR_PRESET=production` + `CONNECTOR_DEFENSE_STRICT=1`; no dev/open auth | [x] (`prod-dogfood-smoke`) |
| 3 | `make ci-beta-gate` green on release commit | [x] |
| 4 | Hardened prod dogfood passed | [x] (`make prod-dogfood-smoke`) |
| 5 | Jordan + Sam + Riley story paths (QA notes) | [x] (`make story-qa-smoke` with server up) |
| 6 | §10 Definition of Done on clean VM | [ ] (automated subset: `make section10-automated-smoke`) |
| 7 | Release signed; quickstart + hardening + upgrade docs published | [x] (docs); [ ] (signed tar) |
| 8 | Known limitations page | [x] [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) |
| 9 | **IIA court-grade engineering gate** (P10.9) | [x] (`make iia-court-gate` → `.iia-court-gate.ok`) |
| 10 | **IIA flagship demo §23** (14 steps) | [x] (`make iia-flagship-demo` → `.iia-flagship-demo.ok`) |

**Sign-off:** _________________ **Date:** _________ **Version:** _________

---

## P10 / IIA — Court-grade intelligence identity (engineering)

> Full queue: [`IIA_CORE_UPGRADE_CHECKLIST.md`](IIA_CORE_UPGRADE_CHECKLIST.md).  
> **Do not market “court-grade” until human P10.9.4 sign-off** even when gates below are green.  
> **Live node:** follow [`COURT_DEFENSIBLE_CHECKLIST.md`](COURT_DEFENSIBLE_CHECKLIST.md) — `connectorctl iia court --agent-pid`.

| ID | Invariant | Verify | Evidence |
|----|-----------|--------|----------|
| IIA-1 | Distinct AgentIDs for two principals, same model (T19) | `make iia-p0-gate` | `.iia-p0-gate.ok` |
| IIA-2 | N4 handshake + CPO non-authoritative; empty model denied (T20) | `make iia-n4-gate` | `.iia-n4-gate.ok` |
| IIA-3 | QPR quantum required; finance inject denied (T21) | `make iia-qpr-gate` | `.iia-qpr-gate.ok` |
| IIA-4 | DockLock / Ring-1 bypass + quantum replay denied (T22) | `make docklock-bypass-adversarial` | `.docklock-bypass-adversarial.ok` |
| IIA-5 | Continuity break stops new quanta; ERM present (T23) | `make iia-continuity-gate` | `.iia-continuity-gate.ok` |
| IIA-6 | Export `signing_tier=ed25519_court` + offline `verify-export` (T24) | `make iia-forensics-gate` | `.iia-forensics-gate.ok` |
| IIA-7 | Per-agent identity envelope + namespace isolation (T25–T26) | `make agent-identity-envelope-gate` | `.agent-identity-envelope-gate.ok` |
| IIA-8 | Compliance contracts + forensic package (T27–T28) | same gate | T27/T28 in ok file |
| IIA-9 | Aggregate court gate | `make iia-court-gate` | `.iia-court-gate.ok` |
| IIA-10 | Flagship §23 (14 steps) | `make iia-flagship-demo` | `.iia-flagship-demo.ok` |

**Honesty labels (non-negotiable):** `signing_tier: ed25519_court` vs `hmac_lab`; never `verified: true` without offline verify; HMAC CFNI alone is not court.

---

## Quick reference

| Goal | Command |
|------|---------|
| Full automated gate | `make prod-readiness-gate` |
| IIA court gate (T19–T28) | `make iia-court-gate` |
| IIA flagship §23 | `make iia-flagship-demo` |
| Fast unit tests | `make platform-test` |
| Integration gate | `make ci-beta-gate` |
| Hardened prod | `make prod-dogfood-smoke` |
| One green start | `make one-green-start-smoke` |
| Story QA (Jordan/Sam/Riley) | `make story-qa-smoke` |
| TT/WC prod probes | `make tt-wc-prod-smoke` |
| Cage + TT load probe | `make cage-tt-load-smoke` |
| k6 cage load (optional) | `make k6-cage-load` |
| Witness bundle offline verify | `make witness-bundle-smoke` |
| Custody quorum smoke | `make custody-quorum-smoke` |
| TraceTramp tenancy audit | `make audit-tracetramp-tenancy` |
| TT/WC full plugin gate | `make tt-wc-prod-gate` |
| Helm lint (connector + TT + WC) | `make helm-lint-smoke` |
| §10 automated subset | `make section10-automated-smoke` |
| Plugin tarballs (TT + WC) | `make package-plugins-smoke` |
| Local dev node | `make start` |
| Reclaim disk (safe) | `make clean-workspace` |
| Low-RAM dev | [`docs/LOW_MEMORY_DEV.md`](docs/LOW_MEMORY_DEV.md) · `.cargo/config.toml` `jobs=4` |

---

*Last updated: 2026-05-21 — run `make prod-readiness-gate` before release candidates.*
