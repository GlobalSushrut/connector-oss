# BUG-FIX-2 — Multi-Taxonomy Defect Register & Remediation Backlog

This document complements [`SOE_CLI_BUG_FIXES.md`](./SOE_CLI_BUG_FIXES.md) (SOE/CLI/kernel/UI) with a **structured defect taxonomy**, **21 primary bug classes** used for top-tier triage (inspired by **IEEE anomaly classification**, **ODC-style dimensions**, and **NIST software flaw families**), and a **connector-private–specific** finding list per class.

**How to use:** Pick a class → scan “Known findings in this repo” → execute “Remediation” rows → add `BF2-XXX` IDs to PRs.

---

## 1. The 21 defect classes (taxonomy)

| # | Class | Plain-language meaning | Typical severity |
|---|--------|------------------------|------------------|
| 1 | **Functional** | Behavior disagrees with agreed spec or user-visible contract | High |
| 2 | **Logical / algorithmic** | Wrong branching, math, ordering, or state machine transitions | High |
| 3 | **Data & persistence** | Wrong/missing durable state, migrations, or store keys | High |
| 4 | **Concurrency & ordering** | Races, deadlocks, lock order inversions, stale reads | High |
| 5 | **Performance & scalability** | Latency, throughput, memory, hot paths, unbounded work | Medium–High |
| 6 | **Security** | AuthN/AuthZ flaws, injection, secret handling, trust boundaries | Critical |
| 7 | **Privacy & compliance** | PII handling, retention, HIPAA/FedRAMP-style controls | Critical |
| 8 | **Reliability & fault tolerance** | Crashes, panics, missing retries, partial failure modes | High |
| 9 | **Operational / SRE** | Deploy, config, observability, runbooks, kill switches | Medium |
| 10 | **Business & billing** | Entitlements, metering, limits, invoices vs runtime | High |
| 11 | **API & UX contract** | Error shapes, idempotency, versioning, misleading messages | Medium |
| 12 | **Integration & interoperability** | MCP/A2A/HTTP/protobuf skew, protocol drift | Medium–High |
| 13 | **Configuration & environment** | Orthogonal env vars, unsafe defaults, prod/dev leakage | High |
| 14 | **Documentation & spec drift** | Docs/manifests disagree with code | Low–Medium |
| 15 | **Input validation & boundaries** | Malformed, oversized, or adversarial inputs | High |
| 16 | **Resource & memory management** | Leaks, unbounded queues, FD exhaustion | Medium–High |
| 17 | **Time, ordering & causality** | Clock skew, TTLs, event ordering, idempotency keys | Medium |
| 18 | **Internationalization & encoding** | UTF-8, locale, collation | Low |
| 19 | **Test & quality debt** | Missing/flaky tests; env-dependent CI | Medium |
| 20 | **Build, supply chain & tooling** | Reproducible builds, vulnerable deps, warnings-as-errors | Medium |
| 21 | **Distributed & consistency** | Multi-cell replication, split-brain, CAP tradeoffs | High |

---

## 2. Findings by class (this repository)

Below, **BF2-** IDs are *new* backlog items for BUG-FIX-2. Items already tracked in `SOE_CLI_BUG_FIXES.md` are cross-referenced.

### Class 1 — Functional

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-F01 | v1 REST uses `agent_{uuid}` while v2 uses **kernel PID** as `id`; clients mixing APIs see “two truths” | `api_v2/agents.rs`, `services/agents.rs`; INFRA table in SOE doc | Document **canonical ID** per client; optional **v2 `api_pid`** field or header `X-Connector-Agent-Id-Model` |
| BF2-F02 | **BUG-SOE-12** (open): health surface `cpu_percent` often 0 — functional gap vs real ops view | `SOE_CLI_BUG_FIXES.md` Phase 3 | Extend `GET /api/v1/agents/:id` (or metrics route) with cgroup/CPU sampler **or** explicitly return `"n/a"` in SOE when absent |

### Class 2 — Logical / algorithmic

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-L01 | Pipeline parallel-group merge strategies (`vote`, `best_score`) depend on **string heuristics**; edge cases may pick wrong winner | `services/multiagent.rs` | Add **scored** merge using trust/KECS or explicit rubric JSON schema |
| BF2-L02 | KECS auto-suspend threshold is **hard-coded** (0.60) | `services/pipeline.rs` `kecs_suspend_sweep` | Drive from **`RuntimePolicy`** + audit reason codes |

### Class 3 — Data & persistence

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-D01 | **Books / sessions**: `active_memory_bytes` stubbed `0`; session close **TODO** | `services/books.rs` (~364, ~1236) | Wire packet size aggregation; implement kernel session close syscall path |
| BF2-D02 | Historical **duplicate deploy agents** may exist in old DBs (pre name-based dedupe) | `services/deploy.rs` (fixed forward-only) | One-off **reconcile** job: merge `agent_meta` by `agent_name` or mark legacy rows |

### Class 4 — Concurrency & ordering

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-C01 | Widespread `Mutex::lock().unwrap()` — **poisoned mutex = panic** | Many handlers (`router.rs`, `auth/core.rs`, `debug.rs`, …) | Prefer `lock()` + map poison to **503** or restart policy; document **single-threaded** admin tools |
| BF2-C02 | **Lock ordering** between `kernel` and `engine_store` is easy to regress | `services/agents.rs` (documented pattern) | Add **#[deny(clippy::await_holding_lock)]** where applicable; static comment + integration test for register/terminate |

### Class 5 — Performance & scalability

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-P01 | `list_agents` filters **full audit log per agent** in memory | `services/agents.rs` | Bounded **recent ops** index in engine_store or kernel secondary index |
| BF2-P02 | Large `connectorctl` surfaces pull **full** agent JSON | `connectorctl` + kernel bridge | Server-side **field mask** query param |

### Class 6 — Security

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-S01 | **MCP `agent_register`** tool creates kernel agents with **limit gate** but **no per-caller capability** beyond transport auth | `services/protocols.rs` | Require **scoped capability** (e.g. `mcp:agent:register`) + rate limit |
| BF2-S02 | **Protocol gateway** & **UI RPC** trust model must stay aligned with `dev_auth_bypass_allowed()` | `protocol_gateway/mod.rs`, `ui_rpc/mod.rs` (updated) | Periodic **pen test checklist**: DEFENSE_STRICT + Pilots + pilot keys |
| BF2-S03 | `jwt_secret()` treats `CONNECTOR_ENV=development` as dev; **`CONNECTOR_ENV=dev`** (runtime apply) path must stay consistent | `auth/core.rs` | Unit test matrix for env combinations |

### Class 7 — Privacy & compliance

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-R01 | Tenant middleware claims **kernel namespace isolation**; **kernel agent limit** is still **global** per process | `middleware/tenant.rs` vs `kernel_agent_limit_gate` | **BF2-B01** (enforce tenant cap in gate when `TenantContext` present) + namespace prefix on all register paths |
| BF2-R02 | Gateway audit payloads may retain **client User-Agent / origin** | `services/gateway.rs` audit JSON | Retention policy + **redaction tier** for defense deployments |

### Class 8 — Reliability & fault tolerance

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-X01 | OTLP init uses **`expect`** — misconfig can **abort** boot | `main.rs` | Degrade gracefully: log error + continue without tracer |
| BF2-X02 | Graceful shutdown **terminates** agents but does not **drain** in-flight LLM / gateway | `main.rs` + prior LIFE-05 notes | Phased shutdown: **stop accept** → **drain** `llm_router` / wait queue → flush |

### Class 9 — Operational / SRE

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-O01 | **Per-request** `CONNECTOR_ENV` inference in `api_key_or_jwt_middleware` can diverge from **store-backed** `runtime_mode` if env is tampered at process level | `router.rs` | Prefer **SharedState.runtime_mode** in middleware (requires `State` in layer or extension) |
| BF2-O02 | **`dev_log_middleware`** still keys off raw `CONNECTOR_DEV_MODE` for *logging*, not `dev_auth_bypass_allowed()` | `router.rs` | Align so DEFENSE_STRICT does not enable noisy dev logging |

### Class 10 — Business & billing

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-B01 | **`TenantTier::agent_limit`** vs **`resolved_kernel_agent_cap`** — two ceilings, gate uses only license+policy today | `middleware/tenant.rs`, `services/agents.rs` | **`min(kernel_cap, tenant.agent_limit)`** when tenant context exists |
| BF2-B02 | Monitor / economy dashboards may still show **license-only** cap | `services/monitor.rs` (historical) | Use **`resolved_kernel_agent_cap`** everywhere user-visible |

### Class 11 — API & UX contract

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-U01 | v1 vs v2 **error JSON** shapes differ (`agent_limit_reached` vs `V2Error`) | `api_v2/*`, `billing.rs` | Optional **error translation layer** for clients |
| BF2-U02 | **api_manifest** quickstart still shows legacy examples | `router.rs` `api_manifest` | Update sample **`namespace`** to `m/...` style |

### Class 12 — Integration & interoperability

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-I01 | **Three SOE pipelines** (HTTP overlay vs CLI inject vs engine-only) — numbers can diverge | `SOE_CLI_BUG_FIXES.md` §C | Long-term: **one server-rendered** SOE JSON; CLI consumes only |
| BF2-I02 | A2A **artifact** fallback text when no packets | `services/protocols.rs` `build_artifacts` | Include **task id** + **receipt** pointer for audit |

### Class 13 — Configuration & environment

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-G01 | **`CONNECTOR_EXPOSE_DEFENSE_DETAIL`** reveals posture — must stay **off** on public edges | `router.rs` | Add **startup warning** if bind address is `0.0.0.0` and expose flag set |
| BF2-G02 | **`CONNECTOR_DEV_EJECT_SUSPENDED`** defaults **off** — devs may think “limit broken” | `services/agents.rs` | Surface in **`connectorctl policy`** output |

### Class 14 — Documentation & spec drift

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-N01 | Tenant middleware header doc says “all kernel ops scoped” — **not fully true** until BF2-B01/R01 | `middleware/tenant.rs` module doc | Amend doc or implement enforcement |

### Class 15 — Input validation & boundaries

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-V01 | MCP tool args are **loosely typed** JSON | `services/protocols.rs` `call_tool` | JSON Schema per tool; reject unknown fields in DEFENSE_STRICT |
| BF2-V02 | **Manifest deploy** namespace not validated against **tenant prefix** | `services/deploy.rs` | Reject cross-tenant namespace patterns |

### Class 16 — Resource & memory management

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-M01 | Webhook / notification **queues** — verify back-pressure | `services/webhooks.rs`, `notifications.rs` | Cap pending deliveries; spill to engine_store |

### Class 17 — Time, ordering & causality

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-T01 | Action log dedup uses **timestamp + proxy id** | `services/agents.rs` BUG-022 comments | Prefer **stable event UUID** from kernel audit |

### Class 18 — Internationalization & encoding

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-A01 | Assumes **UTF-8** for manifest and MCP strings; invalid UTF-8 bytes in binary tools | Various | Explicit **lossy vs strict** policy in protocol docs |

### Class 19 — Test & quality debt

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-Q01 | Enterprise integration tests assume **DEV_MODE** server | `platform/server/tests/*.rs` headers | Add **auth fixture** path for Production-mode CI job |

### Class 20 — Build, supply chain & tooling

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-E01 | **vac-core** / workspace emits many **warnings** (deprecated ops, unused imports) | `cargo check` output | `-D warnings` CI job on platform crate subset |

### Class 21 — Distributed & consistency

| ID | Finding | Location / evidence | Remediation |
|----|---------|---------------------|-------------|
| BF2-Z01 | **Cell ID** now in shutdown reasons — **no cross-cell agent migration** story | `main.rs`, `distributed/transport.rs` | Document **sticky sessions** + **export/import** manifest for agents |
| BF2-Z02 | QUIC / HTTP3 transport **partial** | `distributed/transport.rs` | Harden **mTLS**, **replay protection**, **cell attestation** |

---

## 2.A Deep assurance — why “200% of all bugs” is never provable

Formal methods, fuzzing, penetration tests, and code review **reduce** unknown defects; they do **not** enumerate a finite “all bugs” set in a system this size (kernel + store + HTTP + protocols + LLM paths). **OS-grade** here means: **documented controls**, **measurable SLOs**, **adversarial review cadence**, and **honest residual-risk registers** — not a claim of zero defects.

**What we did for this pass**

| Method | Scope | Outcome |
|--------|--------|---------|
| Taxonomy walk (21 classes) | Platform + protocols + docs | BF2 backlog rows |
| `TODO` / `FIXME` / `XXX` scan | `platform/server/src` | Items in §2.C |
| `panic!` / `unsafe` scan | `platform/server/src` | Items in §2.C |
| Grep `unwrap`/`expect` sample | `connector-engine` hot paths | Spot checks; tests vs prod code |
| Auth allowlist review | `router.rs` `auth_middleware` | **BF2-S04** prefix risk |
| Cross-doc review | `SOE_CLI_BUG_FIXES.md` | Open SOE-12, INFRA residuals |

**Recommended ongoing**

- **Differential fuzzing** on MCP JSON-RPC and A2A task bodies.  
- **Kani / MIRI / Loom** only where justified (lock-heavy crates).  
- **Periodic** third-party pen test for defense deployments.  
- **`cargo audit`** / SBOM in CI.

---

## 2.B OS-grade infrastructure rubric (classical OS → Connector AIOS)

Use this to argue “infra at OS grade” to security/architecture reviewers. It is a **capability mapping**, not a certification.

| OS / exokernel concern | Connector / platform analogue | Status (2026-04) |
|------------------------|-------------------------------|------------------|
| **Process / task identity** | Kernel `AgentControlBlock`, opaque `agent_pid` | **Strong** — syscall model in vac-core |
| **Scheduling / fairness** | Adaptive router, budgets, circuit breakers | **Medium** — adaptive scoring no longer panics on missing health (**BF2-X03** fixed) |
| **Memory isolation** | Namespace MAC, `m/` vs policy | **Medium–Strong** — tenant vs global limit gap (**BF2-B01/R01**) |
| **Capability / AuthZ** | JWT, API keys, pilot scopes, MCP tools | **Medium** — MCP `agent_register` gated under DEFENSE_STRICT (**BF2-S01** partial); public route allowlist uses exact match (**BF2-S04** fixed) |
| **Auditing & provenance** | Kernel audit chain, SCITT hooks, gateway packets | **Strong** — paths exist; unify SOE pipelines (**BF2-I01**) |
| **Persistence / crash recovery** | redb kernel flush, SQLite engine store, boot stages | **Strong** — fatal errors on store open (fail-closed) |
| **Graceful shutdown** | SIGTERM → optional drain → `AgentTerminate` → flush | **Medium** — configurable **`CONNECTOR_SHUTDOWN_DRAIN_SECS`** window (**BF2-X02** partial); no explicit LLM queue drain API |
| **Observability** | tracing, metrics, OTEL | **Medium–Strong** — OTLP degrades gracefully (**BF2-X01**); Problem Details carry **trace_id** when span valid |
| **Network / distributed** | Internal DNS, QUIC transport, cell id | **Early** — BF2-Z02 |
| **Defense config** | `DEFENSE_STRICT`, airgap, JWT secret | **Strong** — recent hardening |

**Verdict:** The stack has **many OS-like primitives** (kernel, namespaces, audit, persistence). **“OS-grade for all workloads”** is **not** claimed until full LLM queue drain, distributed hardening (**BF2-Z02**), and remaining P2 taxonomy rows are closed or waived.

---

## 2.C Static analysis sweep — supplemental findings (platform/server)

Issues found by repository search that were **not** yet in §2 tables (many rows below are **closed in code** as of 2026-04-21; keep IDs for audit trail):

| ID | Class | Finding | Evidence | Fix direction |
|----|-------|---------|----------|---------------|
| BF2-S04 | Security | **`auth_middleware` allowlist** uses `starts_with` on path suffixes | `router.rs`: e.g. `/auth/signup` matches any **`/auth/signup/...`** | Use **longest exact prefix** list or **segment-boundary** match; review new routes under `/auth/*` |
| BF2-X03 | Reliability | **`panic!` if health map missing** in adaptive scoring | `services/adaptive.rs` (~462) | Return `None` or default score; **never panic** on request path |
| BF2-X04 | Reliability | **`panic!` in boot/recovery** on unexpected rollback branch | `boot/recovery.rs` (~810) | Map to `Result` + structured recovery state |
| BF2-X05 | Reliability | **`signing.rs`** panics on I/O errors for platform key | `signing.rs` (read/write key) | In orchestrated deploy, **fail fast with exit code** is OK; document vs **return Result** for embedders |
| BF2-D03 | Data | **`active_memory_bytes: 0`** stub | `services/books.rs` (~364) | Sum packet sizes or remove misleading field |
| BF2-D04 | Data | **Session not closed in kernel** | `services/books.rs` (~1236) | Wire `SessionClose` / equivalent syscall |
| BF2-O05 | Operational | **`trace_id: None`** in error mapping | `error.rs` (~470) | Propagate OTEL trace context into JSON errors |
| BF2-O06 | Operational | **Boot recovery** “attempt: 1” hard-coded | `boot/recovery.rs` (~422) | Persist attempt counter per stage |
| BF2-U03 | API / UX | **CLI completion** “Complete agent PIDs from API” | `cli/completion.rs` (~197) | Implement or gate behind feature flag |
| BF2-E02 | Build | **`llm_router`** uses `Mutex::lock().unwrap()` | `connector-engine/llm_router.rs` | Handle poisoned lock or use `parking_lot` |

**Intentional `unsafe`:** `runtime_control::apply_runtime_mode` uses `unsafe { env::set_var/remove_var }` — required by Rust’s env API; acceptable if **single-threaded at boot** (document).

**`cls/compiler.rs` test panics** — treat as **test-only** unless paths reach production CLS VM.

---

## 3. Severity × priority matrix (recommended)

| | **P0 (now)** | **P1 (next sprint)** | **P2 (backlog)** |
|---|-------------|----------------------|------------------|
| **Critical** | BF2-S01, BF2-R01/B01 (if multi-tenant prod) | BF2-X02, BF2-C01 (hardening) | BF2-Z02 |
| **High** | BF2-F02, BF2-B01 | BF2-P01, BF2-O01 | BF2-D02 |
| **Medium** | BF2-O02, BF2-U02, **BF2-S04** | BF2-I01, BF2-M01, **BF2-O05** | BF2-A01, **BF2-U03** |
| **Low** | — | BF2-D03, BF2-D04, BF2-O06 | BF2-E02, BF2-U03, BF2-X04, BF2-X05 |

---

## 4. Execution checklist (defense / autonomous AI deployments)

1. **Runtime:** `RuntimeMode::Production`, `CONNECTOR_DEFENSE_STRICT=1`, `CONNECTOR_JWT_SECRET` set, `CONNECTOR_AIRGAP` as required.  
2. **Limits:** Confirm **`resolved_kernel_agent_cap`** + **tenant** cap (after BF2-B01) in staging.  
3. **Protocols:** Pen-test MCP tool surface (BF2-S01, BF2-V01).  
4. **SOE:** Close **BUG-SOE-12** or explicitly document CPU as N/A (BF2-F02).  
5. **Drift:** Re-run this taxonomy quarterly; add rows under the same **class #** to preserve history.  
6. **Allowlist:** Review **`router.rs` ALLOWLIST** after any new `/auth/*` or `/license/*` route (**BF2-S04**).  
7. **Panics:** Grep `panic!` in `services/` before each release; eliminate from **request-scoring** paths (**BF2-X03**).

---

## 5. Continuous assurance program (recommended)

| Cadence | Activity | Owner |
|---------|----------|-------|
| **Per PR** | `cargo check`, unit tests, auth allowlist diff review | Engineering |
| **Weekly** | `cargo audit`, dependency review | Security / Eng |
| **Monthly** | Re-run §2.A scans + update BF2 table | Platform |
| **Quarterly** | External pen test (defense tier) + SOE/CLI regression suite | Security |
| **Release** | OS rubric §2.B sign-off matrix (pass / waive / open) | SRE + Arch |

---

## 6. Residual risk statement (sign-off language)

> **Connector Platform** implements kernel-style agent lifecycle, durable memory, audit hooks, and defense-oriented auth gates. **Not all defect classes are closed.** Remaining tracked work includes tenant-vs-global limits (**BF2-B01/R01**), auth allowlist prefix hygiene (**BF2-S04**), adaptive-router panic (**BF2-X03**), graceful drain (**BF2-X02**), and distributed hardening (**BF2-Z02**). **Production suitability** requires explicit waivers or closure of P0/P1 items for the deployment tier.

---

## 7. Document changelog

| Date | Change |
|------|--------|
| 2026-04-21 | Initial BF2 registry + 21-class taxonomy |
| 2026-04-21 | Added §2.A–2.C: assurance limits, OS-grade rubric, static-analysis supplements (**BF2-S04**–**BF2-O06**, **BF2-E02**, **BF2-X03**–**BF2-X05**) |
| 2026-04-21 | Follow-up: **BF2-O02**, **BF2-U02**, **BF2-G01**, **BF2-X02** (drain window), **BF2-S01**, **BF2-I02**, **BF2-F02** (explicit `health_metrics`), **BF2-B02**, **BF2-L02** (`kecs_suspend_threshold` in `RuntimePolicy`), **BF2-G02** (policy API + `connectorctl`), **BF2-N01**, **BF2-U03** (zsh inspect placeholder), **BF2-X04**/**BF2-X05** (tests / exit-on-I/O for signing key) |

---

## 8. References (external)

- NIST — *Taxonomy of Software Flaws* (security-oriented families).  
- IEEE Std 1044 / 1044.1 — *Classification for Software Anomalies* (type, mode, activity).  
- IBM ODC — Orthogonal Defect Classification (trigger, target, defect type).  

---

*Document version: 2026-04-21 — BUG-FIX-2 registry + deep assurance appendix.*
