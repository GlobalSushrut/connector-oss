# Connector OS — Complete Software Architecture (Encyclopedia)

**Standard:** every piece an architect must understand to reason about the product — not a security pamphlet and not a marketing overview.  
**Audience:** architects, security reviewers, operators, and engineers owning the node.  
**Scope:** installable customer node, guest isolation plane, vendor control plane, OSS path-deps, first-party plugins, data, presets, APIs.  
**Truth rule:** implemented in this repo, or explicitly marked **remaining / human-trusted / lab-only / unwired**.

| Companion | Path |
|-----------|------|
| **PDF booklet (isometric drawings)** | [`Connector_OS_Full_Architecture.pdf`](Connector_OS_Full_Architecture.pdf) — rebuild: `bash platform/docs/arch/pdf-assets/rebuild_pdf.sh` |
| **Seven Pillars status** | [`SEVEN_PILLARS_STATUS.md`](SEVEN_PILLARS_STATUS.md) — `bash platform/scripts/seven-pillars-gate.sh` |
| **Court / military claims** | [`COURT_GRADE_CLAIMS.md`](COURT_GRADE_CLAIMS.md) — binder: `court-grade-evidence-bind.sh` |
| Entry index | [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) |
| Nine rings narrative | [`docs/11-architecture-overview.md`](../../../docs/11-architecture-overview.md) |
| Effect exclusivity slice | [`EFFECT_EXCLUSIVITY.md`](EFFECT_EXCLUSIVITY.md) |
| ZT handshake slice | [`ZT_HANDSHAKE.md`](ZT_HANDSHAKE.md) |
| MicroVM channels slice | [`MICROVM_CHANNELS.md`](MICROVM_CHANNELS.md) |
| Probabilistic LLM slice | [`PROBABILISTIC_LLM.md`](PROBABILISTIC_LLM.md) |
| Plugin wire contract | [`PLUGIN_CONTRACT.md`](../../../PLUGIN_CONTRACT.md) |
| Roadmap | [`CONNECTOR_OS_ROADMAP.md`](../../../CONNECTOR_OS_ROADMAP.md) |

---

## How to read this document

| Part | What you get |
|------|----------------|
| **I** | Product topology + mental model (node vs vendor, planes, rings) |
| **II** | Repository anatomy — every top-level path |
| **III** | Binary & crate census |
| **IV** | In-daemon `platform/server/src` tree map |
| **V** | Kernel encyclopedia — every `kernel/*.rs` |
| **VI** | Substrate encyclopedia — every `substrate/*.rs` |
| **VII** | Services encyclopedia — every `services/*.rs` |
| **VIII** | Supporting packages (auth, boot, CLS, CNP, api_v2, operator, …) |
| **IX** | Isolation / microVM / kerneld plane |
| **X** | OSS path dependencies (`oss/connector`, `oss/vac`, `oss/aapi`) |
| **XI** | First-party plugins |
| **XII** | Data & persistence layout |
| **XIII** | Presets, env, production hardening |
| **XIV** | HTTP / protocol API surface map |
| **XV** | End-to-end effect & talk paths (piece-by-piece) |
| **XVI** | Hard problems each subsystem solves |
| **XVII** | Testing remaining |
| **XVIII** | Real limitations + humans always trusted |

Slices under `platform/docs/arch/*` deepen one concern; **this file is the system of record for the whole OS.**

---

# Part I — Product topology and mental model

## I.1 What people install vs what we run

```
┌──────────────────────────────────────────────────────────────────────────┐
│  VENDOR CONTROL PLANE (Connector Inc. runs)                              │
│  connector-license-server · www portal · admin SPA · keys · Stripe       │
│  optional: hub, hosted playground fleet                                  │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ license activate / heartbeat / telemetry
┌───────────────────────────────▼──────────────────────────────────────────┐
│  CUSTOMER NODE = one installable Connector OS                            │
│                                                                          │
│  Binaries: connector-platform · connectorctl                             │
│  Optional host helpers: connector-kerneld · Firecracker + vm-agent       │
│                                                                          │
│  ┌─ CONTROL PLANE (same process) ──────────────────────────────────────┐ │
│  │ auth · RBAC · agents CRUD · HITL · quarantine · grants · settings   │ │
│  │ plugin/workflow catalog · runtime_control · dashboard embed         │ │
│  └─────────────────────────────┬───────────────────────────────────────┘ │
│  ┌─ DATA / EFFECT PLANE ───────▼───────────────────────────────────────┐ │
│  │ MemoryKernel · Knot · governed_effect · ZT · admission · MCP broker │ │
│  │ CLS lease runner · mission journal · CONP · credential_proxy        │ │
│  └─────────────────────────────┬───────────────────────────────────────┘ │
│  ┌─ GUEST ISOLATION PLANE ─────▼───────────────────────────────────────┐ │
│  │ microVM · docker_lab · wasm · subprocess(lab)                       │ │
│  │ tools I/O · robotics/IoT/MQTT/Modbus channels (flags)               │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
     ▲ LLM providers    ▲ MCP bridges    ▲ robots/IoT    ▲ operators/CI
```

| Role | Binary | UI | State |
|------|--------|-----|-------|
| Customer node | `connector-platform` | Embedded Leptos dashboard (`connector-ui`) | `CONNECTOR_DATA_DIR` |
| Customer CLI | `connectorctl` | — | talks to node / systemd |
| Vendor license | `connector-license-server` | `connector-www` + `connector-admin` | Postgres (typical) |
| Optional hub | `connector-hub` | — | `.cpkg` registry |
| Host egress helper | `connector-kerneld` | — | systemd/nft + eBPF mark-deny |
| Guest agent | `connector-vm-agent` | — | inside microVM |

**Mental model:** one governed node; workflows, `.cpkg` plugins, and world adapters are **workloads on the substrate**, not a kit of unrelated services. Vendor billing is **outside** the customer governance kernel.

## I.2 Nine rings + intelligence overlay

Every external call still walks concentric rings (`docs/11-architecture-overview.md`). On top: chartered intelligence (principal, ACS, NS FS, world grants, AutonomyGateway).

| Ring | Concern | Primary code |
|------|---------|--------------|
| 1 | Identity & boot | `auth/`, `boot/`, keys under `data/keys/` |
| 2 | Network & gateway | `router.rs`, TLS/rate middleware, session |
| 3 | Firewall & guard | DevGuard, injection, AutonomyGateway, graph firewall |
| 4 | Memory kernel | `vac-core`, `services/memory*`, Knot |
| 5 | Policy & governance | CCL/CLS, contracts, HITL, admission |
| 6 | Reasoning & LLM | `gateway.rs`, LlmRouter, agentic inject |
| 7 | Tool execution | ZT → microVM / MCP broker / CONP |
| 8 | Audit chain | HMAC journal, receipts, forensics |
| 9 | Surface output | SOE / role redaction |

| Intelligence overlay | Module | Binds |
|----------------------|--------|-------|
| Principal + contract | `kernel/agent_principal.rs` | Cryptographic agent identity |
| Identity envelope | `kernel/agent_identity_envelope.rs` | Setup/activate, grants |
| Character (ACS) | `kernel/acs.rs` | Name, purpose, cage posture |
| NS FS | `kernel/nsfs.rs` | Per-pid `/m` `/k` `/p` `/share` |
| World grants | `kernel/world_gateway.rs` | Per (agent × address) |
| AutonomyGateway | `kernel/action_binding.rs` | Allow / Ask / Block |
| Agentic context | `substrate/agentic_context.rs` | Who-am-I into talk |

## I.3 Control vs data vs guest (secrets & sockets)

| Plane | May hold secrets? | Open sockets to world? | Primary code |
|-------|-------------------|------------------------|--------------|
| Control | Yes (operator vault) | Yes (broker to LLM/MCP) | `services/*`, `auth/*` |
| Data/effect | Vault handles → materialize at last mile | Only broker + ZT | `substrate/*`, `kernel/*`, vac |
| Guest | **No** (membrane strips) | **No** under distrust | `plugin-runtime`, `microvm_tool_plane` |

---

# Part II — Repository anatomy (every top-level path)

| Path | What it is | Product relevance |
|------|------------|-------------------|
| `platform/` | Commercial OS: server, UI, runtime, licensing, deploy, arch docs | **Ships** |
| `oss/` | Path-deps: connector-engine, trust, vac-*, aapi-*, SDKs | Linked into platform |
| `plugins/` | First-party AGOS products (TraceTramp, WitnessCtl, …) | Separate bins; cage-proxied |
| `agos-abi/` | Semver AGOS ABI constants | Plugin contract |
| `agos-sdk/` | Public plugin SDK (ABI + manifest + handshake) | Authors |
| `cargo-connector/` | `cargo connector new` scaffold | Authors |
| `docs/` | Operator/author library (rings, APIs, tutorials) | Human docs |
| `lab/` | Docker lab overlays | **Not** production path |
| `advanced-lab/` | Attack/simulation lab | **Not** production path |
| `data/` | Default local runtime state | Dev node state |
| `scripts/` | package, doctor, lab_up, release sign | Ops |
| `examples/` | Sample / reference plugins | Authors |
| `demos/` | Demo scenarios | Marketing/lab |
| `deploy/` | Small root deploy helpers | Prefer `platform/deploy/` |
| `dist/` | `make package` output | Release artifact |
| `platform/release/` | Per-arch node installer packs | Release |
| `vendor/` | Vendored Firecracker / microVM assets | Isolation |
| `.github/` | CI workflows | Gates |
| Root `*.md` | Roadmap, IIA/AIOS truth, UI plans | Product truth |
| `connector.yaml.example` | Example node YAML | Config |

---

# Part III — Binary and crate census

## III.1 Platform crates

| Dir | Package | Binary(ies) | Job |
|-----|---------|-------------|-----|
| `platform/server` | `connector-platform` | `connector-platform`, `connectorctl` | Commercial kernel + CLI |
| `platform/supervisor` | `connector-supervisor` | lib | Process groups for `connectorctl start/stop` |
| `platform/plugin-runtime` | `connector-plugin-runtime` | lib | Subprocess / DockerLab / Microvm / Wasm + membrane |
| `platform/microvm` | `connector-microvm` | lib | Firecracker-shaped host types |
| `platform/connector-vm-agent` | `connector-vm-agent` | `connector-vm-agent` | Guest PID1 / vsock loop |
| `platform/connector-kerneld` | `connector-kerneld` | `connector-kerneld` | systemd egress + eBPF mark-deny (`ebpf-load`) |
| `platform/plugin-manifest` | `connector-plugin-manifest` | lib | Parse `plugin.toml` |
| `platform/plugin-handshake` | `connector-plugin-handshake` | lib | Bootstrap JSON via path/FD |
| `platform/cpkg` | `connector-cpkg` | lib | `.cpkg` ZIP, SBOM, Ed25519 |
| `platform/hub` | `connector-hub` | `connector-hub` | Minimal `.cpkg` registry HTTP |
| `platform/licensing` | `connector-license-server` | `connector-license-server` | Vendor keys/portal/Stripe |
| `platform/ui-leptos/dashboard` | `connector-ui` | WASM/lib (embed) | Operator dashboard |
| `platform/ui-leptos/dashboard-server` | `connector-ui-server` | `connector-ui-server` | Optional standalone UI |
| `platform/ui-leptos/www` | `connector-www` | `connector-www` | Vendor portal SPA |
| `platform/ui-leptos/admin` | `connector-admin` | `connector-admin` | Vendor admin SPA |
| `platform/ui-leptos/trial` | `connector-trial` | `connector-trial` | Trial/playground UI |

## III.2 Other platform trees

| Path | Role |
|------|------|
| `platform/deploy/` | install.sh, systemd, Helm, Dockerfiles, terraform, Caddy |
| `platform/docs/arch/` | This encyclopedia + security slices |
| `platform/scripts/` | Platform gates/smoke |
| `platform/sdk/python/` | Python SDK |
| `platform/agents/` | Sample adapters (LangChain, CrewAI, MCP, A2A) |
| `platform/integrations/`, `products/`, `examples/`, `k6/` | Integrations, catalog, load |

## III.3 Isolation backends (`connector-plugin-runtime`)

| Backend | When | Network under distrust |
|---------|------|------------------------|
| `subprocess` | Lab/dev | Host process — weak |
| `docker_lab` | Lab / optional | `--network none` under membrane |
| `microvm` | Production hardening | vsock-only, no TAP under distrust |
| `wasm` | Constrained | WASI, no TCP |
| `internal` | In-process | **Break-glass / lab** |

Selected by `CONNECTOR_ISOLATION_RUNTIME` / `CONNECTOR_PLUGIN_RUN_BACKEND`.

---

# Part IV — In-daemon source tree (`platform/server/src`)

```
HTTP edge (router + auth + ring1 middleware)
  → services/*          REST handlers (~160 modules)
  → api_v2/*            Simplified V2 REST
  → operator/*          Universal operator surfaces
  → kernel/*            Identity, ACS, NSFS, world, ZT, DockLock, AutonomyGateway
  → substrate/*         governed_effect, exclusivity, agentic_context, microvm plane
  → cls/ · cnp/ · protocol_gateway/ · ui_rpc/
  → oss vac / connector-engine (MemoryKernel, Knot, …)
  → plugin-runtime / microVM guests
```

| Top-level | Files (approx) | Role |
|-----------|----------------|------|
| `kernel/` | 41 | Agent kernel / IIA |
| `substrate/` | 33 | Constitutional effect membrane |
| `services/` | 160 | HTTP business surface |
| `auth/` | 5 | JWT, RBAC, API keys, mTLS |
| `api_v2/` | 17 | Beginner V2 REST |
| `operator/` | 12 | Pulse, fix queue, honesty |
| `boot/` | 5 | 12-stage boot |
| `cli/` | 4 | connectorctl helpers |
| `cls/` | 8 | CLS compile/engine |
| `cnp/` | 3 | CNP wire/stack |
| `intelligence_admission/` | 2 | N4 Gate 1 |
| `quanta_polar/` | 1 | QPR Gate 2 |
| `protocol_gateway/` | 3 | :9092 MCP/A2A/… |
| `internal_dns/` | 1 | `*.cnktros` name→addr |
| `ui_rpc/` | 1 | Dashboard WS JSON-RPC |
| `middleware/` | 6 | body, otel, rate, ring1, tenant |
| `agents/` | 7 | allocator/autoscaler (not HTTP SoT) |
| `distributed/` | 10 | cells, scheduler, leader |
| `kms/` | 7 | cloud/local KMS |
| `knowledge/` | 7 | index, dehall, CoT |
| `knot/` | 2 | Knot capabilities |
| `storage/` | 2 | S3/Kafka-style adapters |
| `compliance/` | 6 | evidence, custody |
| `data/` | 6 | consent, subject isolation |
| `proof/` | 3 | chain + verifying |
| `policy/` | 2 | policy chain |
| `protocols/` | 2 | glue |
| `security/` | 2 | network/infra cache |
| `export/` | 7 | OTEL/OCSF/Prometheus |
| `privacy/` | 3 | anonymizer, blind query |
| `network/` | 1 | manager |

### Root files

| File | Role |
|------|------|
| `main.rs` | Process entry, boot, serve |
| `router.rs` | Axum route tree |
| `state.rs` | `PlatformState` / `SharedState` |
| `config.rs` | Config / ports / storage URLs |
| `connector_profile.rs` | Presets + production hardening |
| `error.rs` | `ConnectorError` denial JSON |
| `license.rs`, `license_file.rs`, `machine.rs` | Licensing + machine id |
| `background.rs` | Background tasks |
| `dashboard_embed.rs`, `dashboard_static.rs` | Embedded SPA |
| `signing.rs`, `binary_id.rs`, `phone_home.rs` | Binary identity / telemetry |
| `util_lock.rs` | Poison-safe locks |
| `phase5_operator_display.rs` | Plugin status one-liners |
| `cluster_boot.rs` | Optional vac-cluster cell boot |
| `ws.rs` | Placeholder |
| `bin/connectorctl.rs` | Operator CLI |

---

# Part V — Kernel encyclopedia (`kernel/`)

Every module under `platform/server/src/kernel/`.

| Module | Responsibility | Key types / APIs |
|--------|----------------|------------------|
| `mod.rs` | Kernel root; apps are not kernel types | re-exports |
| `operating_layer.rs` | AIOS three sockets; vendor-blind absorb | `Socket`, `record`, `absorb_catalog`, `wm_prompt` |
| `aios.rs` | Memory OS syscalls: core/recall/archival + generation | `ensure_memory_os`, `core_get/set`, `recall_*`, `begin_generation` |
| `intelligence_matrix.rs` | CDMI Albus cell: SP · WM · VJ · BG-socket | `albus_node`, `cell` |
| `acs.rs` | Agentic Character Surface | `ACS_SCHEMA`, `render` |
| `nsfs.rs` | Per-agent NS FS `nsfs/{pid}/` (`/m` `/k` `/p` `/v`) | `ensure_tree`, `assert_quota`, `snapshot` |
| `address_cage.rs` | Outer world as typed addresses; strip host identity | `CagedAddress`, `classify_address`, `LOCAL_HOST_ADDR` |
| `address_contracts.rs` | Per-address rules ≠ HITL contracts + seals | `AddressRulesContractV1`, `AddressDacVerdict` |
| `address_dac_api.rs` | HTTP for address DAC + identity-stack query | `get/put_address_dac_*`, `get_identity_stack` |
| `world_gateway.rs` | Owner grants `(agent × address)` + root pass | `WorldGrantV1`, `put_grant`, `assert_grant_allows` |
| `admission_layers.rs` | Root HITL / Cone / App membrane | `AdmissionLayer`, `WorldAdmit`, `admit_world` |
| `action_binding.rs` | AutonomyGateway + digest HITL (tools/talk/CONP) | `AutonomyVerdict`, `admit_tool_or_ask` |
| `agent_principal.rs` | Mint/load principal + contract | `IntelligencePrincipalV2`, `AgentContractV2` |
| `agent_foundation.rs` | Hash-anchored foundation + who-am-I | `mint_foundation_block`, `who_am_i_authoritative` |
| `agent_identity_envelope.rs` | Setup/activate, NS grants, forensic universal | `mint_default_setup`, `save_activation` |
| `compliance_contract.rs` | Auditor contract at activate | `bind_at_activate` |
| `continuity.rs` | Continuity + Execution Reality Manifest | `evaluate_continuity`, `mint_execution_reality_manifest` |
| `intelligence_spec.rs` | Declare-then-apply: skills/knowledge/portals/rules | `IntelligenceSpecV1`, `persist_bound_pack` |
| `intelligence_purge.rs` | Purge IIA + NS FS on kill | `purge_intelligence` |
| `share_portal.rs` | Cross-agent share only via human+root | `ShareContractV1`, `SharePortalV1` |
| `council.rs` | Sibling intelligences under root; hash floor | `CouncilV1`, `FloorEntry` |
| `docklock.rs` | Ring-1 single-use ExecutionQuantum + cage env | `DockLockBindingV1`, `cage_env_for_intelligence` |
| `ring1_context.rs` | Per-request quantum at HTTP edge | `scope`, `current`, `resolve_quantum_id` |
| `zt_handshake.rs` | Ed25519 genesis + hash-chained single-use tickets | `ZtHandshake`, `mint_ticket`, `admit_tool_effect` |
| `credential_proxy.rs` | Resolve `vault:` on platform plane; strip cage secrets | `materialize_secret_refs`, `strip_secret_env_keys` |
| `mission_journal.rs` | Durable steps so resume does not re-fire | `MissionV1`, `begin_step`, `complete_step` |
| `membrane_posture.rs` | Refuse start/effects if Landlock/backends missing | `assert_membrane_ready_for_*` |
| `isolation_tiers.rs` | Honest tier ladder light→docker→microvm | `resolve_tier`, `isolation_for_agent` |
| `matrix_isolation.rs` | Continuity break → revoke quanta, quarantine, cut egress | `react_on_continuity_break` |
| `matrix_host_egress.rs` | nftables/iptables cut by intelligence mark | `apply_matrix_host_egress_cut` |
| `vault_seal.rs` | AES-256-GCM seal for in-process vault blob | `persist`, `load_store` |
| `fabric_task.rs` | Fabric task SoT for multiagent/A2A | `FabricTaskV2`, `transition` |
| `decision_trace.rs` | Hash-chained decision traces | `DecisionTraceV1`, `verify_trace_chain` |
| `forensics.rs` | Receipt chain CPO→quantum→DockLock→effect | `append_receipt`, `export_receipt_chain` |
| `forensic_package.rs` | MANIFEST + joined DFIR package | `build_package` |
| `forensic_rollups.rs` | Hourly rollups + WitnessCtl joins | `record_event`, `witnessctl_export_join` |
| `agent_chat.rs` | Talk threads/turns in engine_store | `create_thread`, `append_turn` |
| `agent_explain.rs` | Ordered story: lifecycle + identity + who stopped | `get_agent_explain` |
| `iia_llm_inject.rs` | who-am-I + agentic inject for non-gateway callers | `inject_*_engine_messages` |
| `node_fabric.rs` | Single-node / peer topology honesty | `snapshot`, `live_peer_count` |
| `witnessctl_align.rs` | Align WitnessCtl frameworks on activate | `align_on_activate` |

---

# Part VI — Substrate encyclopedia (`substrate/`)

Every module under `platform/server/src/substrate/`.

| Module | Responsibility | Key types / APIs |
|--------|----------------|------------------|
| `mod.rs` | Constitutional substrate root | module list |
| `governed_effect.rs` | Unified effect admission (character, entropy, contract → admission) | `evaluate_effect`, `GovernedEffectResult` |
| `admission_gate.rs` | Ring-1 helpers for memory/tool/LLM/MCP/pipeline | `require_memory_write*`, `require_tool_dispatch*` |
| `admission_matrix.rs` | Coverage map handlers ↔ effect routes | `CRITICAL_HANDLERS`, `admission_matrix_json` |
| `admission_status.rs` | HTTP admission matrix | `get_admission_matrix` |
| `identity_stack.rs` | Character + last memory + address graph gate | `inspect`, `enforce` |
| `agentic_context.rs` | who-am-I / character / memory / knowledge / rules | `build_for_shared`, `require_or_hitl` |
| `probabilistic_llm.rs` | Bypass→quarantine; pillar fail→HITL | `quarantine_for_bypass`, `require_human_for_rule` |
| `effect_exclusivity.rs` | Close six alternate paths; probes | `AlternatePath`, `assert_effect_exclusivity_ready` |
| `microvm_tool_plane.rs` | I/O + robot/IoT/MQTT/Modbus via microVM | `ToolExecPlan`, `invoke_io_in_microvm`, `invoke_channel_in_microvm` |
| `cage_security.rs` | Cage principal, isolation grade, cage caps | `mint_cage_cap`, `assert_isolation_runtime_grade` |
| `egress_policy.rs` | MCP/L7 allowlist, DNS pin, deny raw provider | `assert_mcp_egress_allowed`, `reqwest_*_pinned` |
| `cfni.rs` | CFNI mint/verify for gateway and mesh | `mint_for_principal`, `verify_inbound_headers` |
| `flow_lease.rs` | Short-lived egress tickets by CFNI flow | `mint_on_admission_pass`, `require_active_flow_lease` |
| `graph_firewall.rs` | Relation-graph rules + circuit breaker | `GraphFirewallVerdict`, `evaluate` |
| `sgke_gate.rs` | κ/Ψ × placement deny | `SgkeVerdict`, `evaluate_sgke_gate` |
| `agent_lifecycle_gate.rs` | **Only** platform path to kernel lifecycle syscalls | `authorize_lifecycle`, `register_and_start` |
| `agent_progeny.rs` | Parent/child PID tree (VAC SoT) | `register_with_progeny`, `progeny_forest` |
| `outbound.rs` | Stamp principal + CFNI on plugin proxy | `stamp_reqwest` |
| `proxy_auth.rs` | Auth for TT/WC management proxies + cage | `require_management_proxy_auth` |
| `artifact_log.rs` | Append-only artifact log | `append_artifact_record` |
| `causal.rs` | Causal envelope per admission pass | `record_admission_envelope` |
| `usage_event.rs` | Billing usage events | `append_usage_event` |
| `usage_receipt.rs` | Peer UsageReceipts | `append_usage_receipt` |
| `cnp_edge.rs` | CNP edge records | `record_gateway_handler` |
| `durability.rs` | Kernel durability metrics | `durability_snapshot` |
| `memwrite_durability.rs` | Write-through after MemWrite | `sync_after_memwrite` |
| `knot_rebuild.rs` | Rebuild KnotEngine from packets on boot | `rebuild_knot_from_kernel` |
| `handoff_queue.rs` | WC/TT handoff correlation | `handoff_queue_stats` |
| `projection.rs` | Durable TT/WC proxy hop records | `record_tracetramp_admin_forward` |
| `retention.rs` | Retention policy + cold-tier stub | `RetentionPolicyV1`, `run_retention_job_stub` |
| `status.rs` | Substrate health HTTP | `get_substrate_status` |
| `docklock_bridge.rs` | Legacy re-export to Ring-1 DockLock | re-exports |

---

# Part VII — Services encyclopedia (`services/`)

Every HTTP-facing business module under `platform/server/src/services/` (~160). Grouped by job; each row is one file.

## VII.1 Agents / identity / lifecycle

| File | Role |
|------|------|
| `agents.rs` | Agent CRUD registry |
| `agent_identity.rs` | Setup/activate/envelope HTTP |
| `agent_lifecycle.rs` | In-memory lifecycle (**deprecated SoT**) |
| `agent_reaper.rs` | Background zombie reap |
| `agent_resource_manager.rs` | Per-agent resources (**unwired SoT**) |
| `agent_traffic_police.rs` | Scheduler/pooler |
| `agent_index_integration.rs` | Cross-cell discovery |
| `auto_allocator.rs` | Slot allocation ~25–150 agents/node |
| `intelligence_authority.rs` | Lifecycle transition gate |
| `intelligence_quick.rs` | `POST /intelligence/apply` |
| `workload_lifecycle.rs` | Agents+plugins lifecycle summary |
| `acs.rs` | ACS/NSFS/share HTTP |
| `world_gateway.rs` | World grants HTTP |
| `council.rs` | Council HTTP |
| `missions.rs` | Mission journal HTTP |
| `fabric.rs` | Fabric task HTTP |
| `aios.rs` | AIOS claim/modules/fleet HTTP |
| `iia_runtime.rs` | `/runtime/self`, N4, QPR |
| `admission.rs` | Central `admission::check` for all effects |
| `namespace_isolation.rs` | MAC + virtualization tree |

## VII.2 Memory / knowledge / cognitive

| File | Role |
|------|------|
| `memory.rs` | Write/recall/RAG/regions |
| `memory2.rs` | Sessions/packets/seal |
| `memory_plane.rs` | Unified memory overview |
| `memory_graph.rs` | Graph + dehall chains |
| `memory_vector_box.rs` | MemPacket → MemoryVectorBox |
| `moment.rs` | Moment manifests |
| `chain_tree.rs` | Hyperbolic knowledge tree |
| `knowledge_pipeline.rs` | Large-scale ingest contract |
| `knowledge_transfer.rs` | Inter-agent KTG |
| `assets.rs` | `/v/` → `/k/` asset pipeline |
| `cognitive.rs` | Perceive/plan/reason loop |
| `context.rs` | Snapshot/compress/resume |
| `prompts.rs` | Versioned prompt registry |
| `grounding.rs` | Grounding tables / claims |
| `safety.rs` | Hallucination + formal verify surface |
| `kecs_calculator.rs` | KECS spectral scores |

## VII.3 Tools / gateway / protocols

| File | Role |
|------|------|
| `tools.rs` | MCP bridges, approvals, signals, ZT admit |
| `gateway.rs` | OpenAI `/v1/chat/completions` + agentic inject |
| `gateway_hooks.rs` | Session/message guards |
| `anthropic_gateway.rs` | Anthropic `/v1/messages` |
| `adaptive.rs` | Multi-provider LLM router |
| `llm_output_contract.rs` | Output attestation |
| `protocols.rs` | MCP/A2A/ACP/ANP/AP2 bridges |
| `cnp_surface.rs` | CNP 7-layer control plane |
| `conp_protocol.rs` | CONP robots/machines (+ microVM channel) |
| `mcp_hosting.rs` | In-process hosted MCP tools |
| `aapi.rs` | Capability issue/delegate/budgets |
| `policy_check.rs` | Pre-check like `access(2)` |

## VII.4 Plugins / workflows / apps

| File | Role |
|------|------|
| `apps_catalog.rs` | Unified plugins+workflows list |
| `plugin_cpkg.rs` | `.cpkg` install/verify/rollout |
| `plugin_depends.rs` | Semver depends check |
| `plugin_lifecycle.rs` | Plugin state machine |
| `plugin_hub.rs` | Install preflight / service map |
| `plugin_configure.rs` | Plugin settings schema/values |
| `plugin_marketplace.rs` | Marketplace detail |
| `plugin_matrix.rs` | `CONNECTOR_PLUGINS_ENABLED` gate |
| `plugin_cage_proxy.rs` | `/plugin/<slug>/*` reverse proxy |
| `plugin_condo.rs` | Multi-plugin → one microVM slot |
| `plugin_crash_recovery.rs` | Durable quarantine/backoff |
| `plugin_egress_allowlist.rs` | Manifest egress allowlist |
| `plugin_runtime_inventory.rs` | microVM/plugin inventory |
| `plugin_tier_scheduler.rs` | cold/warm/hot tiers |
| `plugin_upstream_probe.rs` | TT/WC/DG reachability |
| `plugins_status.rs` | Aggregate plugins status |
| `cage_proof.rs` | Cage routing E2E proof |
| `cpkg_gloo_burnin.rs` | Burn Gloo workflows into registry |
| `hub_mirrors.rs` | Airgap hub mirrors |
| `hub_workflow_publish.rs` | Hub workflow publish stub |
| `author_portal.rs` | Author tokens/namespaces |
| `workflow_runtime.rs` | Workflow register/transition |
| `workflow_bootstrap.rs` | One-shot register→ENABLED |
| `workflow_runner.rs` | Lease-based CLS runner |
| `workflow_cls_execution.rs` | Activation via CLS+CNP |
| `workflow_cnp.rs` | Workflow↔CNP bus registration |
| `workflow_catalog_sync.rs` | Watch dir for `*.ccl` |
| `workflow_reference.rs` | Reference install/sample-run |
| `cls.rs` | CLS compile/validate HTTP |
| `custom_domain_routing.rs` | Host→plugin cage aliases |

## VII.5 DevGuard / WitnessCtl / TraceTramp

| File | Role |
|------|------|
| `devguard.rs` | Coding-agent governance sessions |
| `devguard_workspace.rs` | Agent-only workspace FS/git |
| `devguard_team.rs` | Multi-tenant DevGuard teams |
| `devguard_local_profile.rs` | Workstation profile |
| `devguard_proxy.rs` | Extension status-api proxy |
| `fs_guard.rs` | File path visibility/writes |
| `exec_guard.rs` | Shell command governance |
| `secret_broker.rs` | Secret scan/redact |
| `policy_config.rs` | `.connector/policy.yaml` |
| `witnessctl_proxy.rs` | WC management proxy |
| `tracetramp_proxy.rs` | TT management proxy |
| `policy_lineage.rs` | Shared principal lineage honesty |

## VII.6 Runtime / mesh / infra / security ops

| File | Role |
|------|------|
| `runtime_control.rs` | Mode, activation, isolation policy |
| `runtime_enforcement.rs` | Enforcement status (ZT, exclusivity, distrust, …) |
| `runtime_egress.rs` | Egress/kerneld status |
| `kernel_host.rs` | Host kernel profiles/microVM cells |
| `phase5_operator_env.rs` | Docker-lab/microVM env labels |
| `supervisor_inventory.rs` | Supervisee catalog |
| `ha_federation.rs` | HA/federation honesty |
| `mesh_status.rs` | Mesh/cells honesty |
| `mesh_channel.rs` | Cross-cell governed channel |
| `mesh_join_token.rs` | Lab join tokens |
| `mesh_knowledge_plane.rs` | Shared k/ + grants |
| `membership_heartbeat.rs` | CRDT membership tick |
| `cell_spiffe.rs` | Cell SPIFFE-ish IDs |
| `infra.rs` | BFT, vault, DAG, EigenTrust |
| `orchestrator.rs` | DAG/saga orchestrator |
| `orchestration_intelligence.rs` | Intelligence-leaf scheduling |
| `deploy.rs` / `registry.rs` | Deploy manifests / AgentRegistry |
| `firewall_config.rs` | Adaptive firewall rules |
| `security_signals.rs` | Control-plane security signals |
| `support_bundle.rs` | Redacted support bundle |
| `unified_health.rs` | `/health` aggregate |
| `federation_policy.rs` | Federated policy stub |

## VII.7 Audit / proof / compliance / books

| File | Role |
|------|------|
| `debug.rs` | Sessions, audit, agent debug |
| `actionlog.rs` | Action/interaction log + exports |
| `proof.rs` | Proof certificates / SCITT |
| `proof_chain.rs` | Tree-structured proof chains |
| `audit_receipts.rs` | Signed audit receipts |
| `compliance.rs` | Compliance reports/findings |
| `forensics.rs` | IIA forensics/court readiness |
| `verify.rs` | Formal invariant checker |
| `books.rs` | Accounting-style operational ledger |
| `disputes.rs` | Decision provenance / defense pkg |
| `history.rs` | Agent timeline/replay |
| `pipeline.rs` | Pipeline integrity/CID chain |
| `multiagent.rs` | Multi-agent pipelines |
| `experiments.rs` | Experiment tracking |
| `monitor.rs` | Health/trust/cost/SLOs |
| `observability.rs` | Native ringbuffer charts |
| `insights.rs` | Optimize/self-heal |
| `report_center.rs` | Report center aggregate |
| `topology_center.rs` | Topology aggregate |
| `command_center.rs` | Thin UI aggregator |

## VII.8 Business / settings / playground / surfaces

| File | Role |
|------|------|
| `licensing.rs` | License activate/heartbeat |
| `billing.rs` | Usage metering / entitlements |
| `payment.rs` | Stripe checkout |
| `analytics.rs` | Funnel telemetry |
| `economy.rs` | Escrow/pricing/reputation |
| `marketplace.rs` | Agent marketplace contracts |
| `catalog.rs` | Product catalog JSON |
| `deployment.rs` | playground vs self-deploy mode |
| `secrets.rs` | Opaque secret handles |
| `settings_llms.rs` | LLM providers/routing |
| `settings_secrets.rs` | Master key / secret test |
| `settings_system.rs` | Networking/identity/backup |
| `connector_yaml.rs` | Edit `connector.yaml` |
| `setup.rs` | Setup wizard + recommendations |
| `playground.rs` | Hosted trial sessions |
| `playground_export.rs` | Export/import session tarball |
| `telemetry_playground.rs` | Anonymous funnel events |
| `notebook.rs` | Interactive notebook |
| `webhooks.rs` | Outbound webhook delivery |
| `notifications.rs` | Alert/reminder engine |
| `scim.rs` | SCIM 2.0 over user_store |
| `episodes.rs` | Named episode grouping |
| `object_fabric.rs` | Content-addressed blob CAS |
| `surfaces.rs`, `surface_http.rs`, `surface_monitor_live.rs` | SOE surface JSON |
| `mod.rs` | Module declarations |

---

# Part VIII — Supporting in-daemon packages

## VIII.1 Auth (`auth/`)

| File | Role |
|------|------|
| `mod.rs` | Auth root |
| `core.rs` | Users, API keys, JWT claims, password hashing |
| `rbac.rs` | REST + UI-RPC permission checks |
| `scoped_tokens.rs` | Fine-grained API key scopes |
| `mtls.rs` | Node-to-node mTLS certs |

## VIII.2 API v2 (`api_v2/`)

`mod.rs`, `router.rs`, `errors.rs`, `agents.rs`, `memory.rs`, `tools.rs`, `sessions.rs`, `audit.rs`, `health.rs`, `deploy.rs`, `dns.rs`, `exec.rs`, `network.rs`, `registry.rs`, `storage.rs`, `system.rs`, `tls.rs` — beginner-friendly REST parallel to `/api/v1`.

## VIII.3 Operator (`operator/`)

`pulse.rs`, `fix_queue.rs`, `surfaces`, `capability*`, `edge.rs`, `honesty.rs`, `lint_surface.rs`, `setup_summary.rs`, `watch_events.rs`, `surface_merge.rs` — universal operator UX aggregators.

## VIII.4 Boot / CLS / CNP / gates

| Area | Pieces | Job |
|------|--------|-----|
| `boot/` | 12-stage boot, probes, recovery, reporter | Node bring-up honesty |
| `cls/` | compiler, engine, installer, burner, business_logic | Workflow language runtime |
| `cnp/` | `stack.rs`, `wire.rs` | CNP L3+; refuse empty mTLS key |
| `intelligence_admission/` | N4 Gate 1 | handshake→profile→CPO |
| `quanta_polar/` | QPR Gate 2 | CPO→ExecutionQuantum |
| `protocol_gateway/` | :9092 listener | MCP/A2A/ACP/ANP/AP2 |
| `internal_dns/` | name→SocketAddr | `*.cnktros` cage DNS |
| `ui_rpc/` | WS JSON-RPC | Dashboard live channel |
| `middleware/` | body, otel, rate, ring1, tenant | Edge policy |
| `kms/` | AWS/Azure/GCP/Vault/local | Secret backends |
| `knowledge/` | index, dehall, CoT ledger | Knowledge plane helpers |
| `knot/` | Knot capabilities | Graph memory |
| `distributed/` | cells, scheduler, leader, transport | Multi-cell lab/prod direction |
| `export/` | OTEL/OCSF/CloudEvents/Prometheus | Observability egress |
| `compliance/`, `data/`, `proof/`, `policy/`, `privacy/` | Evidence, consent, verifying, anonymizer | GRC surfaces |

---

# Part IX — Isolation / microVM / host helpers

| Piece | Path | Job |
|-------|------|-----|
| Isolation membrane | `plugin-runtime/src/isolation_membrane.rs` | Force deny_all, strip secrets, broker-only env |
| Docker backend | `plugin-runtime` docker | `-e` guest env; membrane → `--network none` |
| MicroVM backend | `plugin-runtime` + `platform/microvm` | vsock-only under membrane; no API keys on cmdline |
| Tool/channel plane | `substrate/microvm_tool_plane.rs` | Classify + invoke I/O and physical channels |
| Guest agent | `connector-vm-agent` | Heartbeat / control in guest |
| Host kerneld | `connector-kerneld` | systemd/nft + eBPF `cgroup/skb` mark-deny (`ebpf-load`) |
| Vendored assets | `vendor/` | Firecracker kernel/rootfs operator-supplied in prod |

**Env (prod defaults via profile):** `CONNECTOR_ISOLATION_RUNTIME=microvm`, `CONNECTOR_TOOLS_IN_MICROVM=1`, `CONNECTOR_WORLD_CHANNEL_VIA_MICROVM=1`, `CONNECTOR_DOCKER_LAB_EGRESS=deny_all`, `CONNECTOR_MICROVM_EGRESS_MODE=deny_all`, `CONNECTOR_ALLOW_HOST_MCP_BROKER=1` (remote MCP HTTPS only).

---

# Part X — OSS path dependencies

## X.1 `oss/connector/crates/`

| Crate | Bin | Job |
|-------|-----|-----|
| `connector-caps` | — | Capability computer |
| `connector-engine` | — | VAC Memory Kernel ↔ AAPI Action Kernel |
| `connector-api` | — | Developer agent API |
| `connector-protocols` | — | MCP/A2A/ACP/ANP/AP2 |
| `connector-protocol` | — | CP/1.0 robots/machines/tools |
| `connector-glue` | — | GLUE governed developer interface |
| `connector-trust` | — | Shared v2 trust contracts |
| `connector-report-pdf` | — | Compliance PDF/HTML |
| `connector-cli` | `connector` | OSS CLI |
| `connector-server` | `connector-server` | Lightweight REST (**not** commercial kernel) |

## X.2 `oss/vac/crates/`

| Crate | Job |
|-------|-----|
| `vac-core` | MemoryKernel / packets |
| `vac-store` | Content-addressed storage |
| `vac-crypto` | Ed25519, UCAN |
| `vac-prolly` | Prolly trees |
| `vac-red` | Regressive Entropic Displacement |
| `vac-sync` / `vac-replicate` | Sync + CID streaming |
| `vac-bus` | Event bus |
| `vac-cluster` | Cell clustering (optional feature) |
| `vac-route` | Consistent-hash routing |
| `vac-ffi` / `vac-wasm` | Language bindings |

## X.3 `oss/aapi/crates/`

`aapi-core`, `aapi-gateway`, `aapi-pipeline`, `aapi-crypto`, `aapi-federation`, `aapi-indexdb`, `aapi-metarules`, `aapi-adapters`, `aapi-sdk`, bin `aapi` — Action kernel path-deps into platform.

---

# Part XI — First-party plugins

| Plugin | Binaries | Job |
|--------|----------|-----|
| `tracetramp` | `tracetramp` | Runtime proxy / execution control plane |
| `witnessctl` | `witnessctl`, `witnessctl-verify`, `witnessctl-node` | Witness, seal, prove |
| `devguard` | `devguard` | Governance for AI coding agents |
| `conductor` | `conductor` | Multi-agent orchestration |
| `agentloop` | `agentloop` | DNS/mesh/workers agentic web layer |
| `agentpassport` | `agentpassport` | KYA identity / W3C creds |
| `engram` | `engram` | Governed memory |
| `ledgerlens` | `ledgerlens` | AI FinOps |
| `relay` | `relay` | Zero-framework governed functions |
| Clients | `tracetramp-client-node`, `tracetramp-client-py` | Language clients |

Cage: `<slug>.cnktros` + `/plugin/<slug>/*`. Reference stubs: `examples/agos-reference-plugins/`.

---

# Part XII — Data and persistence

**Root:** `CONNECTOR_DATA_DIR` (default `./data`).

| Path | Role |
|------|------|
| `engine.db` | SQLite — engine/audit/secrets/escrow (Ring 1–4 class) |
| `kernel.redb` | redb — memory kernel packets, agents, SCITT |
| `users.db` | Auth/users |
| `keys/` | Platform signing/verifying keys |
| `workflows/`, `catalog/` | Workflow catalog |
| `object_fabric_cas/` | CAS blobs |
| `playground/` | Playground sessions |
| `plugins/cpkg_store` | Installed `.cpkg` rollouts |
| `connector.pid` | PID for connectorctl |
| `nsfs/{pid}/` | Per-intelligence filesystem homes |

Config storage URLs (typical): `CONNECTOR_ENGINE_STORAGE=sqlite:…/engine.db`, `CONNECTOR_KERNEL_STORAGE=redb:…/kernel.redb`.

---

# Part XIII — Presets, env, hardening

**SoT:** `platform/server/src/connector_profile.rs`  
Layered: `connector.yaml` + `CONNECTOR_PRESET` fills *unset* env only.

## XIII.1 Presets

| Preset | Class | Notes |
|--------|-------|-------|
| `local`, `development`, `dev` | Lab | DEV_MODE, plugin lab |
| `local-live-llm` | Lab | Dev + live LLM |
| `docker-local` | Lab | Bind 0.0.0.0 |
| `ci` | Lab | Stub LLM + airgap |
| `preview` | Pilot | `CONNECTOR_ENV=pilots` |
| `staging`, `production`, `airgap`, `defense-strict`, `edge-satellite` | Prod-like | Hardening + microvm |
| `multi-tenant` | Mode | `CONNECTOR_MULTI_TENANT=1` |
| `plugin-workbench` | Lab | Dev + plugin lab |
| `ultimate-free` | Tier | Free tier flags |
| `playground`, `trial`, `saas-trial` | Hosted trial | TTL, caps, stub LLM |

## XIII.2 Core ports / config

| Env | Default / meaning |
|-----|-------------------|
| `CONNECTOR_DATA_DIR` | `./data` |
| `CONNECTOR_PORT` / `HOST` | `9091` / `0.0.0.0` |
| `CONNECTOR_PROTOCOL_PORT` | `9092` (0 = main) |
| `CONNECTOR_UI_RPC_PORT` | `9093` |
| `CONNECTOR_PUBLIC_URL`, `CELL_ID`, `LICENSE`, LLM_* | Optional |

## XIII.3 Production hardening defaults (non-exhaustive)

Ring-1 / QPR / DockLock / HITL · setup gate · ban anon gateway · kernel fail-closed · Landlock fail-closed · L7 egress · MCP egress · **effect exclusivity** · matrix HW · **ZT handshake** · **LLM distrust** · docker/microvm `deny_all` · isolation `microvm` · **tools in microVM** · **world channel via microVM** · host MCP broker · **agentic context require** · memwrite sync · CFNI enforce.

**Break-glass (audit findings):** `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS`, `CONNECTOR_ALLOW_GUEST_EGRESS`, `CONNECTOR_TOOLS_IN_MICROVM_STRICT` off, mis-set isolation runtime.

---

# Part XIV — HTTP / protocol API surface map

## XIV.1 Mounts (`router.rs`)

| Mount | Role |
|-------|------|
| `/api/v1/*` | Primary REST (auth-gated + allowlist) |
| `/api/v2/*` | Simplified V2 |
| `/v1/chat/completions`, `/v1/models`, `/v1/messages` | OpenAI/Anthropic gateway |
| `/plugin/<slug>/*` | Cage reverse-proxy |
| `/healthz`, `/readyz`, `/metrics`, OpenAPI, A2A AgentCard, boot | Infra |
| UI-RPC port | Dashboard WebSocket JSON-RPC |
| Protocol port | MCP/A2A/ACP/ANP/AP2 listener |

## XIV.2 `/api/v1` section groups (from router)

Debug · ActionLog · Proof · Memory · Monitor · Deployment/Support · Products · Runtime · History · Multiagent · Disputes · Pipeline · Experiments · Prompts · Tools · Insights · Agents · Compliance · Books · Assets · Notifications · Webhooks · Licensing · Auth · Distribution · Portal aliases · Notebook · Verify/Grounding/Economy/Marketplace/Context/Firewall · Payment · Memory2 · AAPI · Cognitive · Protocols · Safety · Infra · Billing · Deploy/Registry · Docs · CLS · Apps · Workflows · Plugins/cage · Author portal · TraceTramp/WitnessCtl/DevGuard proxies · Playground · Setup · connector.yaml · Kernel/IIA/ACS/World/Missions · Substrate · Operator surfaces · ZT / exclusivity / microvm-tools / probabilistic-llm status routes.

---

# Part XV — End-to-end paths (piece-by-piece)

## XV.1 Only legal effect path

1. **Agentic context** — `agentic_context` (+ identity stack)  
2. **governed_effect** — character, entropy, contract, DAC, `admission::check`  
3. **AutonomyGateway** — Allow | Ask | Block + digests (`action_binding`)  
4. **Effect exclusivity** — six alternate paths closed  
5. **ZT ticket** — `zt_handshake` (LLM cannot mint)  
6. **Credential proxy** — vault materialize on platform plane  
7. **Route** — microVM I/O · microVM channel · host MCP broker · Connector WM kernel  
8. **Mission journal + audit receipt**

## XV.2 Six alternate paths exclusivity closes

| Path | Closed by |
|------|-----------|
| Raw net from guest | deny_all / vsock-only membrane |
| Ungoverned shell | tools-in-microVM + exclusivity deny in-process |
| In-process tools | `assert_in_process_effects_denied` |
| Secrets in guest env | membrane strip + credential_proxy |
| Ungoverned memory | admission_gate + lifecycle_gate |
| A2A without grant | `assert_a2a_requires_grant` |

## XV.3 Talk / LLM path

Auth → agent_pid / budgets / injection score → inject who-am-I + agentic context + memory OS/RAG → incomplete stack under REQUIRE → HITL → LlmRouter → provider → audit + recall append.

Stance: model is **probabilistic**; bypass → **quarantine**; pillar fail → **mandatory HITL**.

## XV.4 Plugin / workflow path

`.cpkg` / workflow.yaml → verify (Ed25519, zip safety) → IsolationRuntime → plugin-runtime spawn **or** CLS lease runner → catalog row (id · status · PID · URI).

---

# Part XVI — Hard problems → which pieces solve them

| Hard problem | Pieces |
|--------------|--------|
| LLM invents who it is | principal, envelope, ACS, agentic_context, identity_stack |
| Model calls tools directly | zt_handshake, effect_exclusivity, guest deny_all |
| Identity collapse across agents | nsfs, share_portal, A2A grant |
| Host ambient authority | address_cage, world_gateway, strip host env |
| Robot/IoT/shell on control plane | microvm_tool_plane, CONP→channel |
| Probabilistic bypass/drift | probabilistic_llm quarantine/HITL |
| Resume re-fires effects | mission_journal, digests (**stronger durable ledger remaining**) |
| Secrets leak into cage | credential_proxy, isolation_membrane |
| CLI treadmill at scale | apps_catalog, workflow_catalog_sync (**unified catalog direction**) |
| Customer vs vendor | licensing binary + www separate from node |

---

# Part XVII — Testing remaining + Seven Pillars release gates

Living status tracker (status discipline): [`SEVEN_PILLARS_STATUS.md`](SEVEN_PILLARS_STATUS.md).  
Gate: `bash platform/scripts/seven-pillars-gate.sh` (CI: `.github/workflows/seven-pillars-gate.yml`).

| ID | Gap | Suggested gate |
|----|-----|----------------|
| T1 | OS child syscall / Landlock proof | Release or documented deferral |
| T2 | Transparent egress proxy | **Complete** — eBPF connect4 + nft NAT REDIRECT + `connector-egress-proxy` TLS terminate (Connector CA MITM) |
| T3 | Exact-action crypto approval bind | Hardening |
| T4 | Durable replay across restart | **Solidified** — `begin_step_detailed` + abandon stale Pending; RG-09 SHIPPED_VERIFIED (light soak) |
| T5 | MicroVM asset CI smoke | Release |
| T6 | CONP partner HAL (not lab echo) | **Complete** — ROS/Modbus/MQTT/TCP wire adapters + SIL safety interlock gate |
| T7 | Hosted MCP out-of-process default | **Solidified** — `TOOLS_IN_MICROVM_STRICT` + host broker off in unbypassable |
| T8 | Unified app catalog parity | **Solidified** — `/apps`, `/apps/parity`, `/workflows/catalog` mounted |
| T9 | Exclusivity adversarial in CI | Release |
| T10 | Agentic context → HITL e2e | Release |
| T11 | A2A remote without grant e2e | Release |
| T12 | Workflow live CNP bus honesty | Document or implement |
| RG-* | PDF Seven Pillars release gates | See `SEVEN_PILLARS_STATUS.md` |

**Honesty:** nothing is `SHIPPED_VERIFIED` until the linked adversarial/acceptance test is green. eBPF in `connector-kerneld` is **IMPLEMENTED_GATED** (`ebpf-load` + bpffs probe; needs `CAP_BPF`).

---

# Part XVIII — Real limitations and humans always trusted

## XVIII.1 Do not overclaim

1. Runtime membrane ≠ full OS syscall proof without T1.  
2. LLM forward-pass still runs in `connector-platform`.  
3. Remote MCP ignoring ZT headers needs network isolation.  
4. MicroVM needs operator-supplied kernel/rootfs.  
5. `connector-kerneld ebpf-load` loads real BPF; `ebpf_loaded` requires bpffs pins (not env alone).  
6. CONP lab HAL is echo — SIL is partner.  
7. Workflow CNP ENABLE is not a live event bus.  
8. Break-glass flags weaken the claim.  
9. Subprocess isolation is lab — prod prefers microVM.  
10. Vendor portal compromise ≠ automatic node compromise (and vice versa) — keep telemetry scoped.

## XVIII.2 Humans always trusted (by design)

| Role | Owns |
|------|------|
| Identity author | Purpose, character, denied ops |
| Grant author | Which addresses an intelligence may touch |
| Approver | Ask digests + unquarantine after bypass |
| Trust-anchor operator | Node keys, license roots, guest images |
| Physical safety owner | Robots / CNC / IoT beyond lab echo |
| Policy author | CCL/contracts — what “right” means |
| Incident commander | Break-glass during incidents |

**The LLM is never:** root of identity, signer of tool authority, issuer of world grants, judge of quarantine, or source of secrets.

---

## Closing claim (honest)

Connector OS is an **installable governance node**: identity, memory, policy, audit, and effect mediation for agentic workloads — with a **full module census** above so every small piece is findable.

Under production / `defense-strict` / `unbypassable` hardening it **closes** alternate effect paths, **distrusts** the probabilistic model, **projects** policy to Linux (systemd/nft/eBPF), and **pushes** tool and physical I/O into microVM channels with vsock tickets.

It claims **GOVERNANCE** and **HOST_LAB** when evidence is green (`COURT_GRADE_CLAIMS.md`). It does **not** claim **MILITARY_COURT**, SIL robotics, live CNP bus, or model autonomy without signed attach evidence. Where those matter, **humans stay trusted — by design.**

---

*System of record for commercial-node anatomy. When you add a kernel/substrate/service module, crate, binary, or preset, update the matching Part in this file and regenerate the PDF booklet in the same PR.*
