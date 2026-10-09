# Connector OS — 21-Segment Maturity Report

**Date:** 2026-08-04  
**Last coded:** 2026-08-08 (P0 truth sync: checklist I-done items + gap honesty; upgrade plan U0–U8 **code complete**; human Final GO / L4–L5 claim gates remain)  
**Method:** Code-first review (crates under `platform/`, `oss/`, `plugins/`), cross-checked against `IMP_1000.md`, `docs/architecture/substrate-map.md`, `PRODUCTION_READINESS_CHECKLIST.md`, and `MATURITY_CHECKLIST_30.md`.  
**Product posture today:** hardened **single-node pilot** — not multi-tenant SaaS, not HA fleet, not court-grade custody, not L5 global mesh. Upgrade coding checklist: [MATURITY_21_UPGRADE_PLAN.md](MATURITY_21_UPGRADE_PLAN.md). Final queue: [FINAL_REACH.md](FINAL_REACH.md).

**Upgrade plan (code against this):** [MATURITY_21_UPGRADE_PLAN.md](MATURITY_21_UPGRADE_PLAN.md)  
**Related:** [ARCHITECTURE.md](ARCHITECTURE.md) · [IMP_1000.md](IMP_1000.md) · [FINAL_OUTCOME.md](FINAL_OUTCOME.md) · [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) · [docs/architecture/doctrine-coders.md](docs/architecture/doctrine-coders.md)

---

## Scoring rubric

| Grade | Meaning |
|-------|---------|
| **Prototype** | Specs, stubs, or unwired libraries |
| **Early** | Real modules; not product default / not wired into `connector-platform` |
| **Partial** | Usable paths with material gaps |
| **Shipped-gaps** | Operators can use it; honesty / HA / universality gaps remain |
| **Production-ready** | Fail-closed, proven ops, no known structural bypasses |

**Five lenses** (each scored **0–5**):

| Lens | 0 | 3 | 5 |
|------|---|---|---|
| **Isolation** | No boundary | Config-sensitive cages / namespaces | Fail-closed host + network + process |
| **Distribution** | Single process only | Multi-host intent / libraries | Automatic failover + consistent SoT |
| **Parallel / concurrency** | Serial / unsafe | Tokio + coarse locks | Scalable scheduling without global bottlenecks |
| **Memory** | Ephemeral / undocumented | Durable packets with crash window | Crash-safe WAL + verified rebuild |
| **Knowledge network** | None | Local graph / index | Multi-node semantic fabric with admission |

`MATURITY_CHECKLIST_30.md` now marks **11/30** I-items done where code already satisfies them (I-01, I-03–I-07, I-09, I-11–I-12, I-16, I-26). Grade-C exit remains incomplete (I-02, I-08, I-10, I-13–I-15, I-17–I-25, I-27–I-30 open).

---

## Executive scoreboard

| # | Segment | Overall | Iso | Dist | Par | Mem | KN |
|---|---------|---------|-----|------|-----|-----|-----|
| 1 | Constitutional Trust & Contracts | Shipped-gaps | 3 | 1 | 2 | 3 | 2 |
| 2 | VAC Kernel & Durable Storage | Shipped-gaps | 3 | 1 | 2 | 4 | 3 |
| 3 | Memory Plane (MemPackets / Knot / Vector Box / Moment) | Shipped-gaps | 3 | 1 | 2 | 4 | 3 |
| 4 | Knowledge Network & Semantic Graph | Partial | 3 | 1 | 2 | 3 | 3 |
| 5 | Identity, Auth & Authority | Shipped-gaps | 4 | 2 | 2 | 2 | 1 |
| 6 | Admission, Execution & Resource Quotas | Shipped-gaps | 3 | 1 | 3 | 3 | 2 |
| 7 | Isolation & Cage Runtime | Shipped-gaps | 4 | 1 | 3 | 2 | 1 |
| 8 | Naming, CNP & Protocol Fabric | Partial → Shipped-gaps | 3 | 2 | 2 | 1 | 1 |
| 9 | Distribution, Cluster & Federation | Early (deferred HA) | 2 | 2 | 2 | 1 | 1 |
| 10 | Parallelism, Concurrency & Scheduling | Partial | 2 | 1 | 3 | 2 | 1 |
| 11 | Causality, Audit & Proof / Custody | Shipped-gaps | 3 | 2 | 2 | 3 | 2 |
| 12 | Commercial Kernel Runtime (`connector-platform`) | Shipped-gaps | 3 | 1 | 3 | 3 | 2 |
| 13 | Agent Lifecycle & Multi-Agent Orchestration | Shipped-gaps | 3 | 1 | 4 | 3 | 2 |
| 14 | LLM Gateway, Tools & MCP Bridges | Shipped-gaps | 3 | 1 | 3 | 3 | 2 |
| 15 | Policy, CCL/CLS & Workflow Catalog | Partial → Shipped-gaps | 2 | 1 | 2 | 3 | 2 |
| 16 | Plugin Economy (AGOS / `.cpkg` / Hub) | Shipped-gaps | 4 | 1 | 3 | 2 | 1 |
| 17 | First-Party Institutions (TT / WC / DG) | Shipped-gaps | 3 | 2 | 3 | 3 | 2 |
| 18 | Operator Plane (Dashboard / CLI / Supervisor) | Shipped-gaps | 3 | 1 | 2 | 2 | 2 |
| 19 | Vendor Control Plane (License / Portal / Playground) | Partial | 2 | 3 | 2 | 1 | 0 |
| 20 | Packaging, Deploy & Ops Hardening | Partial | 3 | 2 | 2 | 1 | 0 |
| 21 | Labs, SDKs, CI Gates & Maturity Evidence | Partial | 2 | 2 | 2 | 1 | 1 |

**Strongest:** Memory/VAC (2–3), Auth/Admission/isolation (5–7), LLM + institutions + operator (14, 17, 18), substrate WF sample (15).  
**Weakest relative to OS claims:** Distribution/HA (9, deferred), packaging Final GO (20), Grade-C checklist closure (21).

---

## Segment detail

### 1 — Constitutional Trust & Contracts

**Paths:** `oss/connector/crates/connector-trust/`; `platform/server/src/substrate/`; `docs/architecture/substrate-map.md`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Contracts describe grants/cages; enforcement lives elsewhere |
| Distribution | 1 | Node-local schemas; no mesh SoT |
| Parallel | 2 | Pure types; platform persists under mutex stores |
| Memory | 2 | Moment / Vector Box / UsageEvent schemas present |
| Knowledge | 2 | Types only — not a runtime graph |

**Overall:** Partial → Shipped-gaps  

**Shipped:** `PrincipalContextV2`, `AdmissionTicketV2`, `CausalEnvelopeV2`, `CustodyReceiptV2` (explicit verify states), `ForensicFlowIdentityV2`, `MomentManifestV2`, `UsageEventV2`, `ArtifactLogRecordV2`; CFNI mint/verify + HTTP stamp; prod preset sets `CONNECTOR_CFNI_ENFORCE=1`; causal `integrity_mac` is keyed HMAC (`CONNECTOR_CAUSAL_HMAC_KEY` or audit key) with verify/tamper reject.  
**Gaps:** Institution CFNI correlation / TT↔WC E2E still open (I-17); `HardwarePlacementV2` / edge-state batch incomplete (I-02); usage-first books / ArtifactLog-as-SoT not universal; keyed HMAC ≠ court-grade multi-party custody.

---

### 2 — VAC Kernel & Durable Storage

**Paths:** `oss/vac/crates/vac-core/` (+ `vac-store`, `vac-prolly`, `vac-crypto`, `vac-cluster`, `vac-replicate`, `vac-sync`); platform flush in `platform/server/src/main.rs`, `substrate/memwrite_durability.rs`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Namespaces + kernel security checks; host cages separate |
| Distribution | 1 | Single-node SoT; replicate/cluster crates early / unwired |
| Parallel | 2 | Kernel behind `Mutex` in platform |
| Memory | 4 | MemPackets, redb store, periodic + sync flush paths |
| Knowledge | 3 | Knot / knowledge modules in-process |

**Overall:** Shipped-gaps  

**Shipped:** MemWrite syscalls, CID packets, `KernelStore`, audit batching, keyed audit HMAC + recompute verify.  
**Gaps:** Default audit key if `CONNECTOR_AUDIT_HMAC_KEY` unset; HMAC covers narrow fields; crash window unless sync flush / write-through; `vac-core/isolation.rs` is model-level, not the production enforcer.

---

### 3 — Memory Plane (MemPackets / Knot / Vector Box / Moment)

**Paths:** `services/memory*.rs`, `moment.rs`, `object_fabric.rs`, `memory_vector_box.rs`, `substrate/knot_rebuild.rs`, `substrate/memwrite_durability.rs`; trust `vector_box` / `moment`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Per-agent namespaces; ingest admission uneven |
| Distribution | 1 | Zone replication intent — not multi-node memory mesh |
| Parallel | 2 | Kernel / knot / engine_store mutex-serialized |
| Memory | 4 | Strongest plane; boot knot rebuild from packets |
| Knowledge | 3 | Packets feed Knot; Vector Box / Moment early |

**Overall:** Partial → Shipped-gaps  

**Shipped:** MemPackets writes; Vector Box lift/list/get; knot rebuild at boot; moment persist + LLM commit hook; object fabric put/get; moment recall hydrate-by-budget with `truncated` / `hydrate_errors` honesty (I-12); multimodal `parts[]` → `object_ref` on MemWrite (I-11).  
**Gaps:** Object Fabric not yet the sole off-hot-DB SoT for large bytes (I-10); ArtifactLog segment backend / rebuild-as-SoT incomplete (I-13); knowledge ingest weaker than MemWrite admission; graph durability still packet-replay dependent.

---

### 4 — Knowledge Network & Semantic Graph

**Paths:** `oss/vac/crates/vac-core/src/{knot,knowledge}.rs`; `platform/server/src/knowledge/`; `services/{knowledge_pipeline,knowledge_transfer,mesh_knowledge_plane,memory_graph}.rs`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Namespace + grants; poisoning risk if ingest under-admitted |
| Distribution | 1 | Single-node graph; mesh plane not proven |
| Parallel | 2 | Knot under `Mutex`; index `RwLock` |
| Memory | 3 | Packet-backed rebuild; HNSW/index largely in-RAM |
| Knowledge | 3 | Real local graph + search; not multi-node fabric |

**Overall:** Partial  

**Shipped:** Knot upsert/query/RRF; packet ingest; boot rebuild; knowledge ingest/query routes.  
**Gaps:** In-memory HNSW (not distributed ANN); Kafka-style pipeline is analogy; no proven cross-node semantic fabric; ingest/admission asymmetry.

---

### 5 — Identity, Auth & Authority (RBAC / Caps)

**Paths:** `platform/server/src/auth/`; `middleware/tenant.rs`; `connector-caps`; `connector-trust` principal/capability

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Roles, scoped tokens, sandbox plans; ambient admin risk on plugins |
| Distribution | 2 | mTLS module exists; not fleet IdP |
| Parallel | 2 | Store-backed auth under platform locks |
| Memory | 2 | UserStore persist; not memory plane |
| Knowledge | 1 | N/A |

**Overall:** Shipped-gaps  

**Shipped:** JWT / API keys / RBAC / tenant binding; `PrincipalContextV2` middleware wiring.  
**Gaps:** `connector-caps` HttpRunner/StoreRunner return mock results; protocol-gateway `cpk_` prefix trust path; synthetic/legacy principals still in contract.

---

### 6 — Admission, Execution & Resource Quotas

**Paths:** `services/admission.rs`; `substrate/{admission_gate,admission_matrix,graph_firewall}.rs`; `agents/{resource_manager,capacity,…}`; VAC registration caps

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Quarantine + breaker + injection checks |
| Distribution | 1 | Host kerneld attach incomplete |
| Parallel | 3 | Multiagent waves call admission |
| Memory | 3 | MemWrite gated on hot paths |
| Knowledge | 2 | Knowledge ingest not equally gated |

**Overall:** Shipped-gaps  

**Shipped:** Admission gate + matrix + graph firewall on major effect routes; kernel agent registration caps; token budgets.  
**Gaps:** `connector-kerneld` not fully wired; dual quota stacks (`agents/*` vs services + kernel); not every effect route admitted.

---

### 7 — Isolation & Cage Runtime

**Paths:** `platform/plugin-runtime/`; `platform/microvm/`; `substrate/cage_security.rs`; `connector-kerneld`; plugin cage proxy

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 4 | Strongest when microvm/docker + egress fail-closed |
| Distribution | 1 | Per-host cages; not cluster orchestration |
| Parallel | 3 | Per-plugin processes/VMs; concurrent proxy |
| Memory | 2 | cgroup limits partial |
| Knowledge | 1 | N/A beyond egress to APIs |

**Overall:** Partial  

**Shipped:** Multi-backend trait (subprocess / Docker / microVM / WASM); grade gates; cage HMAC bindings; `*.cnktros` DNS.  
**Gaps:** Subprocess break-glass misconfig risk; cage secret fallbacks; cgroup/disk Phase 5.8 partial; host-dependent egress; WASM experimental.

---

### 8 — Naming, CNP & Protocol Fabric

**Paths:** `platform/server/src/{cnp,protocol_gateway,protocols,internal_dns}/`; `connector-protocol(s)`; `connector-glue`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Cage DNS never hits host resolv |
| Distribution | 2 | DNS gossip aspirational; in-process registry |
| Parallel | 2 | Extra tokio protocol listener |
| Memory | 1 | N/A |
| Knowledge | 1 | Protocol surface only |

**Overall:** Partial  

**Shipped:** Protocol gateway listener; internal DNS registry; MCP/A2A/… protocol crates partial.  
**Gaps:** CNP L2–L7 crypto/transport incomplete (mTLS establish returns empty keys in places); `connector-glue` stub executor / CID registry stub; not real distributed DNS.

---

### 9 — Distribution, Cluster & Federation

**Paths:** `platform/server/src/distributed/`; `services/ha_federation.rs`; `vac-cluster`, `vac-replicate`, `vac-sync`; `aapi-federation`; `docs/architecture/ha-federation.md`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Federation mTLS env flag, not automatic |
| Distribution | 2 | Honesty API: `automatic_failover: false` |
| Parallel | 2 | Cell scheduler library, not default |
| Memory | 1 | Cluster WAL often in-memory tier |
| Knowledge | 1 | Federation marketplace crates offline from runtime |

**Overall:** Early (product) / Partial (OSS libs)  

**Shipped:** Honesty HA status API; QUIC cell transport experiments; substantial OSS cluster crates.  
**Gaps:** Cluster crates **not wired** into `platform/server` Cargo.toml; peer TLS skip-verify; operator HA only; single-node is the product SoT.

---

### 10 — Parallelism, Concurrency & Scheduling

**Paths:** `background.rs`; `services/multiagent.rs`; `platform/supervisor/`; `distributed/scheduler.rs`; `plugin_tier_scheduler.rs`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Process groups via supervisor |
| Distribution | 1 | MiniScheduler not product default |
| Parallel | 3 | `join_all` waves + background loops real |
| Memory | 2 | Contended by global kernel/store mutexes |
| Knowledge | 1 | N/A |

**Overall:** Partial  

**Shipped:** Background maintenance loops; multiagent parallel groups; supervisor inventory/backoff.  
**Gaps:** Global `Mutex` contention on kernel/engine_store; distributed scheduler not default; supervisor is process inventory, not OS scheduler.

---

### 11 — Causality, Audit & Proof / Custody

**Paths:** VAC `make_audit` / `verify_audit_chain`; `connector-trust` custody/causal/forensic_flow; `services/{proof,forensics}.rs`; WitnessCtl custody

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Evidence only if traffic hits TT/WC / audited paths |
| Distribution | 2 | Witness custody replicate exists; kernel audit node-local |
| Parallel | 2 | Audit batch flush + overflow drain |
| Memory | 3 | Artifacts / moments fold into forensics |
| Knowledge | 2 | Knot ≠ custody SoT |

**Overall:** Shipped-gaps  

**Shipped:** Kernel keyed audit HMAC + verify; proof generate returns `"verified": false` until recompute; WitnessCtl HMAC receipts; causal envelopes with keyed `integrity_mac` (HMAC verify); CFNI helpers + production enforce preset; DI audit middle.  
**Gaps:** Default/lab secrets outside prod fail-closed; narrow audit HMAC field set; TT/WC CFNI correlation incomplete (I-17); symmetric issuer HMAC ≠ non-repudiation / court-grade N-of-M custody (Final P8.6 — live 3-node soak green via `.custody-multinode-soak.ok`; still not market “court-grade” without P9 sign-off).

---

### 12 — Commercial Kernel Runtime (`connector-platform`)

**Paths:** `platform/server/src/{main,router,state,boot,storage}/`; `api_v2/`; license / runtime_control

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Runtime modes + defense-strict presets |
| Distribution | 1 | Single-node default |
| Parallel | 3 | Multi-listener boot; tokio runtime |
| Memory | 3 | redb kernel_store + engine_store |
| Knowledge | 2 | Routes into knowledge/memory services |

**Overall:** Shipped-gaps  

**Shipped:** Boot stages, Axum router, PlatformState, embedded dashboard, dual store, doctor/recovery probes.  
**Gaps:** HA not productized; object storage adapter facade (not full AWS SDK path); observability samples often in-memory.

---

### 13 — Agent Lifecycle & Multi-Agent Orchestration

**Paths:** `services/{agents,multiagent,agent_lifecycle}.rs`; `substrate/agent_progeny.rs`; VAC `AgentRegister`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Quarantine / pause / clearance |
| Distribution | 1 | Migrate/residency hooks weak without cluster |
| Parallel | 4 | Parallel pipeline waves + budgets |
| Memory | 3 | Import/purge under agents |
| Knowledge | 2 | Agent context surfaces |

**Overall:** Shipped-gaps  

**Shipped:** Kernel register/start/terminate + caps; progeny tree; REST lifecycle; multiagent HITL/parallel waves.  
**Gaps:** Orphaned `agent_lifecycle::AgentRegistry`; `agents/*` allocator stack not unified with kernel path; cross-cell migrate needs wired vac-cluster.

---

### 14 — LLM Gateway, Tools & MCP Bridges

**Paths:** `services/gateway.rs`; `protocol_gateway/`; `services/tools.rs`; `services/protocols.rs`; `connector-protocols` MCP client/server

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Admission on chat; protocol GW on separate port |
| Distribution | 1 | Node-local gateway |
| Parallel | 3 | Concurrent requests; stream paths |
| Memory | 3 | Moment commit on LLM path (partial) |
| Knowledge | 2 | Grounding/dispute surfaces partial |

**Overall:** Shipped-gaps (LLM) / Partial (tools/MCP)  

**Shipped:** OpenAI-compatible gateway with admission + metering.  
**Gaps:** MCP/A2A/ACP/ANP/AP2 depth uneven; peer UsageReceipt unfinished (I-08); `CONNECTOR_LLM_STUB` still first-class; admission not universal on every tool effect.

---

### 15 — Policy, CCL/CLS & Workflow Catalog

**Paths:** `platform/server/src/cls/`; `services/{cls,compliance,policy_check,workflow_runtime}.rs`; `resources/workflow_templates/`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | ENABLE mints CNP tokens; CLS-only activate |
| Distribution | 1 | Catalog local to node |
| Parallel | 2 | Workflow runtime concurrency limited |
| Memory | 2 | Policy/decision ledger partial |
| Knowledge | 1 | Templates, not knowledge fabric |

**Overall:** Partial  

**Shipped:** Compile/install/lifecycle routes; dry-run/enable patterns; large compliance surface; CCL templates.  
**Gaps:** Full CNP-correlated replay unfinished; dispatch-only CLS path unfinished; Hub publish of workflows deferred; dry-run still audit-tail/blueprint-shaped (`docs/KNOWN_LIMITATIONS.md`).

---

### 16 — Plugin Economy (AGOS / `.cpkg` / Hub / Handshake)

**Paths:** `agos-abi/`, `agos-sdk/`, `platform/{cpkg,hub,plugin-runtime,plugin-handshake,plugin-manifest}/`, `cargo-connector/`, `examples/agos-reference-plugins/`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 4 | Real cage backends behind install/enable |
| Distribution | 1 | Local Hub index MVP — not community marketplace |
| Parallel | 3 | Concurrent plugin processes |
| Memory | 2 | cgroup memory limits via env |
| Knowledge | 1 | N/A |

**Overall:** Shipped-gaps (format+hub) / Partial (ecosystem)  

**Shipped:** Signed `.cpkg`; Hub install/handshake; ABI constants; `cargo connector new`; multi-backend runtime.  
**Gaps:** Reference plugins are stubs (no live vendor traffic); wasm not default; community Hub / marketplace unfinished.

---

### 17 — First-Party Institutions (TraceTramp / WitnessCtl / DevGuard)

**Paths:** `plugins/{tracetramp,witnessctl,devguard}/`; deferred trees: `conductor`, `agentloop`, `ledgerlens`, `relay`, `engram`, `agentpassport` (see `docs/architecture/secondary-plugins-deferred.md`)

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Cage/proxy; DevGuard host policy |
| Distribution | 2 | Helm/lab multi-service; WF Postgres projections |
| Parallel | 3 | Real service workloads |
| Memory | 3 | Own DB projections + soft soft-correlation |
| Knowledge | 2 | Evidence/explain surfaces; not KN SoT |

**Overall:** Shipped-gaps (TT/WC/DG only)  

**Shipped:** TraceTramp evidence; WitnessCtl custody/receipts; DevGuard host/IDE policy.  
**Gaps:** Soft header correlation vs CFNI everywhere; WF-owned DBs vs substrate log-as-truth; custody quorum incomplete; **do not market deferred plugins as shipping control planes**.

---

### 18 — Operator Plane (Dashboard / `connectorctl` / Supervisor)

**Paths:** `platform/ui-leptos/dashboard/`; `platform/server/src/bin/connectorctl.rs`; `platform/supervisor/`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | JWT/RBAC on APIs; UI trust = API trust |
| Distribution | 1 | Talks to one node |
| Parallel | 2 | WASM UI + CLI; not fleet console |
| Memory | 1 | Displays memory planes; not SoT |
| Knowledge | 2 | Memory/graph/operator views |

**Overall:** Shipped-gaps  

**Shipped:** Embedded Leptos dashboard; substantial `connectorctl`; supervisor process-group/backoff.  
**Gaps:** UI greenfield/makeover still in flight; supervisor ≠ fleet orchestrator; some operator stories still manual QA.

---

### 19 — Vendor Control Plane (License / Portal / Playground)

**Paths:** `platform/licensing/`; `platform/ui-leptos/{www,admin}/`; `platform/deploy/fly.*.toml`, playground Dockerfiles/compose

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Separate binary / origin from customer node |
| Distribution | 3 | Fly + compose deploy paths exist |
| Parallel | 2 | Standard web service concurrency |
| Memory | 1 | Portal data, not VAC |
| Knowledge | 0 | N/A |

**Overall:** Partial  

**Shipped:** License server, portal APIs, www/admin SPAs, playground deploy artifacts (deploy-specific).  
**Gaps:** Not part of customer single-node production bar; www/admin thinner than operator dashboard; docs site / playground still plan-tracked.

---

### 20 — Packaging, Deploy & Ops Hardening

**Paths:** root `Makefile` (`package`, gates); `platform/deploy/` (compose, Fly, Helm, `install.sh`); `SECURITY.md`; `PRODUCTION_READINESS_CHECKLIST.md`

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 3 | Prod presets, microVM default, defense-strict |
| Distribution | 2 | Helm/compose for node + TT/WC |
| Parallel | 2 | CI packaging jobs |
| Memory | 1 | Data-dir conventions |
| Knowledge | 0 | N/A |

**Overall:** Partial  

**Shipped:** Tarball package path; compose/Fly/Helm charts; install script; engineering readiness gates.  
**Gaps:** Clean-VM Final GO incomplete; signed releases (GPG/cosign) not fully automated; Helm often lint-smoke vs install-proven; `SECURITY.md` thin.

---

### 21 — Labs, SDKs, CI Gates & Maturity Evidence

**Paths:** `lab/`; `advanced-lab/`; `.github/workflows/`; `oss/sdks/`; `docs/SECTION10_AUTOMATED_GATES.md`; maturity docs (`IMP_1000`, checklists)

| Lens | Score | Notes |
|------|-------|-------|
| Isolation | 2 | Lab compose isolation for TT/WC |
| Distribution | 2 | Multi-container lab topologies |
| Parallel | 2 | CI matrix + scenario runners |
| Memory | 1 | Lab DBs / scenario artifacts |
| Knowledge | 1 | Attack/scenario corpora |

**Overall:** Partial  

**Shipped:** Platform beta/kernel/UI/hygiene workflows; lab Dockerfiles; advanced-lab attack/action scenarios; Python/TS SDKs; honest maturity docs.  
**Gaps:** Final GO needs clean VM + human stories + lab video; advanced-lab not release gate; `MATURITY_CHECKLIST_30` 11/30 checked (Grade-C exit open); many §10 items still manual; L4/L5 claim gates (Final P7/P9) unsigned.

---

## Cross-cutting lens summary

### Isolation
**Best:** cage runtime + plugin backends (7, 16) when microvm/docker + egress fail-closed.  
**Risk:** break-glass subprocess, default secrets, ambient plugin admin, bypass routes that skip admission/CFNI.

### Distribution
**Reality:** product is **single-node**. Cluster/federation crates and honesty APIs exist; automatic failover is explicitly **false**.  
**Do not claim:** multi-region SoT, automatic leader takeover, or distributed Knot.

### Parallel / concurrency
**Strength:** multiagent parallel waves, tokio listeners, per-plugin processes.  
**Bottleneck:** platform-wide `Mutex` around kernel / engine_store; distributed schedulers not default.

### Memory
**Strength:** VAC MemPackets + redb + boot knot rebuild + Vector Box / Moment persist + budgeted recall hydrate — best-developed constitutional plane.  
**Risk:** residual crash window if sync flush off; Object Fabric / ArtifactLog SoT incomplete; dual-store consistency; knowledge ingest admission weaker than MemWrite.

### Knowledge network
**Strength:** in-process Knot + local HNSW/inverted index + knowledge routes.  
**Gap:** not a multi-node semantic fabric; mesh knowledge plane is surface/intent; packets remain the durability story.

---

## Recommended next focus (maturity ROI)

1. **Final P1–P5 (L3)** — backup/restore, admission universality, CLS-only + CNP dry-run truth, Hub WF publish, institution lineage ([FINAL_REACH.md](FINAL_REACH.md)).  
2. **Grade-C residuals** — Object Fabric off hot DB (I-10), ArtifactLog segments (I-13), peer UsageReceipt (I-08), CFNI TT/WC E2E (I-17), SGKE/placement (I-19–I-20).  
3. **Isolation defaults** — fail-closed cage grade; no silent microVM downgrade; no secret fallbacks.  
4. **Distribution honesty** — L5 engineering soaks green (`.l5-mesh-soak.ok`, fabric claim); keep `automatic_failover: false` and do not market QUIC mutual_auth / court-grade until P9 human sign-off.  
5. **Release proof** — clean-VM tarball + signed package + story QA (segments 20–21); then P7 L4 claim gate.

---

## How to use this file

1. Treat grades as **engineering maturity**, not marketing claims.  
2. When a segment moves, update its five lens scores and the executive scoreboard in the same change.  
3. Prefer linking concrete PRs to segment numbers (e.g. “closes gaps in §3 Memory / §11 Custody”).  
4. Grade-C work in `MATURITY_CHECKLIST_30.md` maps mainly to segments **1, 3, 4, 11, 14, 15, 17, 18**.
