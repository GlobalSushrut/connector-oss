# Backend Top-Grade Track (No UI)

**Scope:** Security · network (CFNI/edge) · storage · isolation · lifecycle · forensics until Grade B substrate gates close.  
**Explicitly out of scope:** `platform/ui-leptos/**` and all UI checklist items.

**Maps to:** [BACKEND_UNIVERSAL_CHECKLIST.md](BACKEND_UNIVERSAL_CHECKLIST.md) · [CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md](CHAOS_AND_UNIVERSAL_SUBSTRATE_CHECKLIST.md) · [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) (backend columns only)

---

## Progress summary

| Phase | Theme | Status |
|-------|--------|--------|
| **T0** | Operator registries (surface, caps, edge, pulse) | ☑ Done |
| **T1** | P0 stop bleeding | ☑ Done |
| **T2** | P1 identity envelope | ☑ Done |
| **T3** | P2 storage physiology | ☑ Done — write-through + audit overflow persist + kill soak |
| **T4** | P3 CFNI transit | ☑ Done — gateway + TT/WC/cage outbound + mesh relay verify + MCP egress allowlist |
| **T5** | P4 usage + moment + fabric | ☑ UsageEvent SoT + Moment API + Object Fabric |
| **T6** | Isolation + lifecycle + forensics APIs | ☑ Cage principal binding + isolation grade gates |
| **T7** | Adversarial CI | ☑ Extended tests + audit script + admission matrix gate |

---

## T1 — P0 Security (stop bleeding)

| ID | Task | Status | Location |
|----|------|--------|----------|
| T1-1 | Tenant header rejected without verified principal | ☑ | `middleware/tenant.rs` |
| T1-2 | Open-auth loopback bind at boot | ☑ | `runtime_control::reject_open_auth_non_loopback_bind` |
| T1-3 | WC session export IDOR guard | ☑ | `witnessctl_proxy::wc_assert_session_access` |
| T1-4 | TT/WC mgmt proxy requires platform auth | ☑ | `substrate/proxy_auth.rs` + proxies |
| T1-5 | No fake `verified: true` in APIs | ☑ | `report_center`, `disputes` |
| T1-6 | Books costs unavailable ≠ `$0` | ☑ | `books::get_costs` |

---

## T2 — P1 Identity envelope

| ID | Task | Status | Location |
|----|------|--------|----------|
| T2-1 | Admission on operator writes | ☑ | `require_admin_or_dev` on PUT surface, POST edge |
| T2-2 | Principal on plugin proxies | ☑ | `substrate/outbound.rs` → TT/WC/cage |
| T2-3 | Prod rejects dev-mode bypass | ☑ | `main.rs` boot guard |
| T2-4 | Cage hostname ≠ authz | ☑ | `proxy_auth::require_plugin_cage_auth` |
| T2-5 | Causal envelope on admission pass | ☑ | `substrate/causal.rs` + `admission.rs` |

---

## T3 — P2 Storage physiology

| ID | Task | Status | Location |
|----|------|--------|----------|
| T3-1 | `UsageEventV2` contract | ☑ | `connector-trust/usage_event.rs` |
| T3-2 | UsageEvent append on LLM completion | ☑ | `billing.rs` → `substrate/usage_event.rs` |
| T3-3 | `ArtifactLogRecordV2` append | ☑ | `substrate/artifact_log.rs` |
| T3-4 | MemWrite WAL / checkpoint metrics | ☑ | `memwrite_durability.rs` write-through + flush + kill soak |
| T3-5 | Knot rebuild on boot | ☑ | `substrate/knot_rebuild.rs` + `main.rs` |
| T3-6 | `GET /substrate/status` | ☑ | `substrate/status.rs` |
| T3-7 | `MomentManifestV2` + API | ☑ | `connector-trust/moment.rs`, `services/moment.rs` |
| T3-8 | Object Fabric put/get | ☑ | `services/object_fabric.rs` |

---

## T4 — P3 Network / CFNI

| ID | Task | Status | Location |
|----|------|--------|----------|
| T4-1 | `ForensicFlowIdentityV2` mint/verify | ☑ | `connector-trust/forensic_flow.rs` |
| T4-2 | Gateway response CFNI header | ☑ | `gateway.rs` + `substrate/cfni.rs` |
| T4-3 | TT/WC stamp on forward | ☑ | `outbound::stamp_reqwest` + principal header |
| T4-4 | Edge `require_cfni` honesty | ☑ | `operator/edge.rs` |
| T4-5 | kerneld fail-closed egress | ☑ | flow lease on `GET /kernel/status` + kerneld `IPAddressDeny=any` |
| T4-6 | CFNI mesh relay verify (inbound) | ☑ | `substrate/cfni.rs` + protocol gateway + `/protocols/mcp/*` |
| T4-7 | MCP egress host allowlist | ☑ | `substrate/egress_policy.rs` + `CONNECTOR_MCP_EGRESS_ALLOWLIST` |
| T4-8 | CNP edges on REST `/protocols/*` | ☑ | `substrate/cnp_edge.rs` + `protocols.rs` |
| T4-9 | Admission on MCP bridge + experiments LLM | ☑ | `protocols.rs` + `experiments.rs` |

---

## T5 — Isolation · lifecycle · forensics

| ID | Task | Status | Location |
|----|------|--------|----------|
| T5-1 | Runtime isolation GET/POST wired | ☑ | `router.rs` → `runtime_control` |
| T5-2 | Isolation fail-closed on POST | ☑ | `set_isolation_runtime` + `resolve_isolation_fail_closed` |
| T5-3 | Plugin inventory wired | ☑ | `/runtime/plugin-inventory` |
| T5-4 | Plugin + kernel lifecycle routes | ☑ | cpkg, plugin lifecycle, kernel_host, condos, tier |
| T5-5 | `WorkloadLifecycleState` summary API | ☑ | `services/workload_lifecycle.rs` |
| T5-6 | Forensics status aggregate | ☑ | `GET /forensics/status` |
| T5-7 | Graph writes require admission | ☑ | `memory2` entity/edge/seed/compile/import/purge/compact + sessions/seal + `mcp_register` |
| T5-10 | Pipeline + asset ingest admission | ☑ | `multiagent::run_pipeline`, `assets::upload_asset` / `ingest_assets` |
| T5-11 | Admission matrix honesty API | ☑ | `GET /substrate/admission/matrix` + `scripts/audit-admission-matrix.sh` |
| T5-8 | Stream metering honesty header | ☑ | `x-connector-usage-metering` on SSE path |
| T5-9 | Isolation declared vs effective | ☑ | `plugin-inventory` attestation block |
| T5-12 | TT/WC projection + handoff queue | ☑ | `projection.rs` + `handoff_queue.rs` + backpressure mode |
| T5-13 | CNP protocol edge log | ☑ Partial | gateway handlers + matrix expansion in progress |
| T5-14 | Memory recall tenant isolation | ☑ | `assert_namespace_readable` on recall/search/packet |
| T5-15 | Orchestration LLM admission | ☑ | `require_llm_chat` in pipeline + mesh grant/revoke gates |
| T5-16 | Cage principal binding + scoped cap | ☑ | `substrate/cage_security.rs` + `plugin_cage_proxy.rs` |
| T5-17 | Subprocess isolation denied in prod | ☑ | `resolve_isolation_fail_closed` + cage grade gate |
| T5-18 | Handoff evidence-required prod default | ☑ | `apply_production_substrate_defaults` + TT/WC projection |
| T5-19 | Orchestration Intelligence v1 (real parallel + chain) | ☑ | `orchestration_intelligence.rs` — k8s-style control plane, light leaves, `intelligence_chain[]` |
| T5-20 | Graph Firewall v1 (relation-graph + agentic breaker) | ☑ | `substrate/graph_firewall.rs` — admission Step 1.6, `GET /firewall/standard` |
| T5-21 | Agent progeny v1 (kernel lifecycle tree) | ☑ | `substrate/agent_progeny.rs` — register/terminate cascade, `GET /agents/progeny/tree` |

---

## T6 — Remaining Grade C backend (no UI)

- I-03 vac-core segment WAL backend (write-through + kill soak shipped; full segment optional)
- I-07 TT stream metering backend — gateway SSE header + UsageEvent on non-zero tokens
- I-14 TT/WC durable handoff to WC (platform projection shipped; plugin handoff still best-effort)
- I-18 CNP virtualize external protocols (MCP edge log shipped; full fabric open)
- I-21 Kerneld flow lease enforcement — ☑ platform map + kerneld deny fragment
- I-27 Adversarial + soak test suite — in `ci_beta_gate.sh`

---

## Exit gate (backend-only, before any UI)

- [x] `GET /substrate/status` + `GET /forensics/status`
- [x] `cargo test -p connector-trust`
- [x] `cargo test -p connector-platform --test trust_foundation_adversarial`
- [x] No `verified: true` in `platform/server/src/services/**` (grep CI)
- [x] Orphaned kernel/runtime/plugin routes wired
- [x] Admission matrix CI (`scripts/audit-admission-matrix.sh`) + `GET /substrate/admission/matrix`
- [x] Route inventory wired paths (`scripts/audit-route-admission-inventory.py`) — 29 effect routes
- [x] Cage principal binding (`substrate/cage_security.rs`)
- [x] Production isolation grade gates (subprocess deny, downgrade block)
- [x] Handoff evidence-required default in production/pilots mode
- [x] Adversarial HTTP suite in `ci_beta_gate.sh` (`trust_adversarial_http`)
- [x] SIGKILL durability soak (`platform/server/scripts/durability-kill-soak.sh`)
- [x] kerneld flow lease deny when `enforcement_enabled` + zero active leases
- [x] `CONNECTOR_HANDOFF_REQUIRED=1` blocks TT mutating proxy on backpressure
- [ ] Adversarial HTTP suite green in CI (requires beta gate workflow run)
- [ ] CHAOS P0–P3 fully closed (plugin TT→WC handoff in plugins; vac-core segment WAL optional)

---

*Do not start Leptos shell until this exit gate is checked.*
