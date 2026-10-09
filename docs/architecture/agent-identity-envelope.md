# Agent Identity Envelope & Activation Architecture

> **Status:** Phases A–C implemented (P10.10.1–P10.10.5); Phase D (rollups/chain) pending  
> **Depends on:** [IIA v2 canon](./intelligence-identity-architecture-v2.md), [admission matrix](./admission-matrix.md), [substrate map](./substrate-map.md)  
> **Queue:** [IIA_CORE_UPGRADE_CHECKLIST.md](../../IIA_CORE_UPGRADE_CHECKLIST.md) — **P10.10**  
> **Rule:** Plan → gates → code. No agent reaches `Running` with empty identity envelope.

---

## 1. Problem statement

Today, two agents using the same LLM model can receive nearly identical runtime context. `who_am_i_authoritative()` in `agent_foundation.rs` already binds foundation IDs, purpose, KB address, and contract capabilities — but it does **not** yet surface:

- Live VAC memory plane state (7 cognitive types × namespace paths)
- Knot entity graph scope tied to this agent
- Philosophy / acume / use-case definition
- Execution rules and denied operations beyond a capability string
- HITL posture and forensic mode
- Per-agent activation manifest (what internal subsystems are on)
- Enforced isolation proof (“I cannot read agent B’s `/m/` unless granted”)

**Goal:** When any agent is asked “who am I?”, the answer must be **kernel-authoritative, agent-unique, and non-transferable** — not reconstructable from model weights or another agent’s namespace.

```
Agent A (FINANCE_AGENT_ACUME)          Agent B (SOC_ANALYST_ACUME)
─────────────────────────────          ────────────────────────────
/m/finance-a/*  (private)              /m/soc-b/*  (private)
/k/finance-kb   (read)                 /k/soc-corpus (read)
Knot slice: finance entities           Knot slice: incident entities
Contract: no shell, HITL on egress       Contract: forensic=all, HITL on export
Forensic: SOC2 + rollups               Forensic: NIST + chain custody
```

---

## 2. What exists today (baseline)

| Layer | Location | Current behavior |
|-------|----------|------------------|
| Foundation block | `platform/server/src/kernel/agent_foundation.rs` | Minted at `POST /agents`; hash-anchored IDs, KB address, P99 anchor, fusion |
| `who_am_i` | same + `gateway.rs` | Injected as system block before LLM; static text from foundation + contract caps |
| Principal / contract | `kernel/agent_principal.rs` | Ed25519 principal + `AgentContractV2` at register |
| Runtime envelope | `GET /api/v1/runtime/self` | `RuntimeSelfEnvelopeV2` — principal, contract, continuity, foundation, who_am_i |
| Memory (7 types) | `vac_core::types::MemoryType` | Working, Episodic, Semantic, Procedural, Relational, Reflective, Evidentiary |
| Namespace (9 prefixes) | `vac_core::namespace_types::NamespaceType` | `/m/ /k/ /v/ /x/ /c/ /a/ /t/ /s/ /p/` with default ACLs |
| MAC isolation | `vac_core::guard.rs` + kernel ACB | `readable_namespaces` / `writable_namespaces`; `AccessGrant` via multiagent |
| Knot | `vac_core::knot.rs`, `state.knot` | Global engine; ingest on write; not yet agent-scoped in identity |
| Knowledge | `POST /memory/knowledge/ingest`, `/k/{kb_id}` | Shared corpus; bound at register via `knowledge_base_id` |
| Forensics (IIA) | `kernel/forensics.rs` | `IntelligenceReceiptV2` hash chain; export via `/runtime/export` |
| TraceTramp | `plugins/tracetramp/` | Trace events, quarantine, compliance exports; **not** linked to CPO/quantum/PID |
| WitnessCtl | `plugins/witnessctl/` | HMAC custody receipts, SOC2/HIPAA/GDPR eval; **not** IIA §18 shape |
| Artifact log | `substrate/artifact_log.rs` | Append-only classes 1–7; **no** hash link to intelligence receipts |
| Activation | `runtime_control.rs` | **Node** license activation only — not per-agent |
| HITL | `agents.rs` `HITL_STORE` | In-memory; quarantine on admission deny |
| Register fields | `RegisterAgentRequest` | `purpose`, `geo_id`, `master_agent_id`, `knowledge_base_id` (optional) |

**Gaps driving this plan:** no `AgentActivationProfile`, no namespace isolation gate on all read paths, no enriched identity context, no unified forensic correlation, v1 register auto-starts without validating setup completeness.

---

## 3. Target architecture

### 3.1 Core types (connector-trust + platform)

```text
AgentSetupSpecV2          — input at register / configure (operator + API)
AgentActivationProfileV2  — persisted; what must be true before activate
AgentIdentityEnvelopeV2   — superset of RuntimeSelfEnvelopeV2 + live slices
AgentCapabilityManifestV2 — 7 memory + thinking + knowledge + knot + forensic flags
NamespaceGrantV2          — explicit cross-agent or common-space ACL
ForensicRollupBucketV2    — time-bucket aggregate for high-volume intelligence ops
```

#### `AgentSetupSpecV2` (minimum before activate)

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Display + ACB label |
| `acume` / `purpose` | yes | e.g. `FINANCE_AGENT_ACUME` — drives contract template + KB default |
| `memory_profile` | yes | Default cognitive type + quota tier; maps to `/m/{agent}/memory/{type}/` |
| `knowledge_base` | yes | `kb_id` or name-only stub; may be empty corpus but path must exist |
| `use_case_def` | recommended | Structured JSON: domain, constraints, output schema |
| `contract_ref` | yes | IIA `AgentContractV2` or CLS template id |
| `hitl_policy` | yes | `none` \| `egress` \| `tool` \| `export` \| `all_material` |
| `forensic_profile` | yes | `off` \| `standard` \| `soc2` \| `court` — enables TT/WC/IIA wiring |
| `philosophy_digest` | optional | Hash of operator doctrine / acume charter (not free-text in kernel) |
| `common_spaces` | optional | List of `NamespaceGrantV2` for shared `/k/` or `/p/` |

#### `AgentIdentityEnvelopeV2` (runtime truth for “who am I?”)

Extends `RuntimeSelfEnvelopeV2` with:

```rust
// connector-trust/src/iia/types.rs (planned)
pub struct AgentIdentityEnvelopeV2 {
    pub base: RuntimeSelfEnvelopeV2,
    pub activation: AgentActivationProfileV2,
    pub capability_manifest: AgentCapabilityManifestV2,
    pub memory_summary: AgentMemorySummaryV2,      // counts per MemoryType, last_sn
    pub knowledge_summary: AgentKnowledgeSummaryV2,  // kb_id, packet_count, last_ingest
    pub knot_summary: AgentKnotSummaryV2,            // node/edge counts in agent window
    pub namespace_scope: AgentNamespaceScopeV2,      // readable/writable paths + grants
    pub hitl_posture: HitlPostureV2,
    pub forensic_posture: ForensicPostureV2,
    pub execution_rules_digest: String,              // hash of contract + denied_ops + docklock profile
}
```

`who_am_i_authoritative()` becomes a **bounded render** of `AgentIdentityEnvelopeV2` (token budget ~2–4k), not a hand-maintained format string.

### 3.2 Namespace isolation matrix

**Invariant I-NS-1:** Default deny cross-agent `/m/` and `/a/` paths.

| Path prefix | Default owner | Cross-agent access |
|-------------|---------------|-------------------|
| `/m/{agent}/` | agent | **Deny** unless `NamespaceGrantV2` or `POST /multiagent/grant` |
| `/a/{agent}/` | agent | **Deny** unless grant |
| `/k/{kb}/` | corpus | Read if `knowledge_base_id` bound at setup; write via ingest role |
| `/p/` | public | Read-all; write restricted |
| `/v/` | staging | Pipeline to `/k/` only |
| `/t/` | session | Ephemeral; no cross-agent |
| `/c/`, `/s/` | kernel | Kernel-only write |

**Common space:** Operator declares `common_spaces[]` at setup — each entry:

```json
{
  "grant_id": "grant:finance-soc-shared",
  "path": "/k/shared/incident-2026",
  "readable_by": ["agent:finance-a", "agent:soc-b"],
  "writable_by": ["agent:soc-b"],
  "expires_at_ms": null
}
```

Persisted in `engine_store` folder `namespace_grant_v2`; enforced at:

1. `vac_core::guard::check_mac_guard` (kernel syscall)
2. `admission::check` (HTTP effect gate)
3. `assert_namespace_readable` (multi-tenant HTTP)
4. Gateway RAG recall (must not pull other agent’s `/m/`)

**Wire today’s dead code:** `services/namespace_isolation.rs` → either delete or align to `vac_core::namespace_types` (single SoT).

### 3.3 Agent lifecycle (revised)

```text
┌─────────────┐    configure     ┌──────────────┐    activate     ┌─────────┐
│  REGISTERED │ ───────────────► │ SETUP_READY  │ ──────────────► │ RUNNING │
│  (identity  │   validate spec  │ (profile ok) │  mint manifest  │ (all    │
│   minted)   │                  │              │  + subsystems on  │ caps on)│
└─────────────┘                  └──────────────┘                   └─────────┘
       │                                  │                                │
       │ v1 today: skips SETUP_READY      │                                │
       └──────────────────────────────────┴── target: v1 gated by flag ────┘
```

| Phase | Actions | Stores |
|-------|---------|--------|
| **Register** | Mint principal, contract, foundation, continuity | `agent_meta`, IIA folders, foundation block |
| **Configure** | `POST /agents/:pid/setup` — acume, KB, memory profile, HITL, forensic, grants | `agent_setup_spec_v2`, optional KB seed |
| **Activate** | `POST /agents/:pid/activate` — validate setup, flip manifest, kernel `AgentStart`, subsystem hooks | `agent_activation_profile_v2`, handshake receipt |
| **Run** | Gateway injects full envelope slice; effects require quantum | receipts append per action |

**Breaking change (flagged):** `CONNECTOR_AGENT_SETUP_GATE=1` → v1 register stops auto-start; requires explicit activate. Default off until gates green.

### 3.4 Capability manifest (9 + internal)

On activate, platform sets `AgentCapabilityManifestV2`:

| Capability | Subsystem | Activate hook |
|------------|-----------|---------------|
| `memory.working` … `memory.evidentiary` (7) | VAC cognitive paths | Ensure `/m/{agent}/memory/{type}/` exists |
| `namespace.memory` | `/m/` | ACB namespace bind |
| `namespace.knowledge` | `/k/` | KB bind + read ACL |
| `namespace.tool` | `/t/` | Session ephemeral |
| `thinking` | N4 + gateway | CPO path enabled |
| `knowledge.rag` | recall + `/memory/knowledge/query` | KB non-empty or stub ack |
| `knot.graph` | KnotEngine window for agent | Register `window_entity_index` slice |
| `forensic.iia` | IntelligenceReceiptV2 | Always on if `forensic_profile != off` |
| `forensic.tracetramp` | TT tenant + trace projection | Proxy register with four-ID |
| `forensic.witnessctl` | WC session + custody | Open session on activate |
| `hitl` | HITL policy | Queue bindings |

**UI (later):** `GET /agents/:pid/capabilities` returns manifest + live health per flag.

### 3.5 Knowledge at setup

Three tiers (operator chooses):

1. **Name-only:** `knowledge_base_id` + empty `/k/{id}` — agent knows corpus id, no packets yet
2. **Seed ingest:** `POST /agents/:pid/setup/knowledge` with cleaned packets or asset pipeline ref
3. **Full corpus:** bind existing `/k/{domain}` via grant

Validation at activate:

- Path exists in namespace validator
- If `forensic_profile >= soc2`, ingest must have provenance `SourceKind::Operator` or pipeline CID

### 3.6 “Who am I?” rendering pipeline

```text
load AgentIdentityEnvelopeV2(api_pid)
  ├─ foundation + principal + contract (existing)
  ├─ memory_summary from kernel packet index (per-type counts)
  ├─ knowledge_summary from /k/ listing (bounded)
  ├─ knot_summary from KnotEngine agent window
  ├─ namespace_scope from ACB + grants
  ├─ hitl_posture + forensic_posture
  └─ render_who_am_i(envelope, max_tokens=3500)
        → gateway system block
        → GET /runtime/self field
        → MCP tool `connector_who_am_i` (read-only)
```

**LLM rule (unchanged):** Model must echo kernel block; contradiction → admission log + optional quarantine.

---

## 4. Forensic & compliance architecture (SOC-aligned, high volume)

> **Forensics-team view (contract + package + control matrix):** [forensic-compliance-contract-view.md](./forensic-compliance-contract-view.md)

### 4.1 Three-tier receipt model (unified view)

```text
                    ┌─────────────────────────────┐
                    │   ForensicCorrelationV2    │
                    │   (single join table/API)   │
                    └──────────────┬──────────────┘
           ┌──────────────────────┼──────────────────────┐
           ▼                      ▼                      ▼
 IntelligenceReceiptV2    WitnessCtl Receipt      TraceTramp trace_event
 (IIA court, Ed25519)      (custody, HMAC)         (action projection)
           │                      │                      │
           └──────────────────────┴──────────────────────┘
                         ArtifactLogRecordV2
                         (rollup + segment index)
```

**Correlation keys:** `four_id`, `cpo_id`, `quantum_id`, `agent_pid`, `session_id`, `trace_id`, `fni_flow_id`, `moment_id`

### 4.2 High-volume preservation (millions of events)

Intelligence actions (N4 cognize, tool call, memory write, gateway turn) emit **micro-receipts**; storage uses:

| Mechanism | Purpose |
|-----------|---------|
| **Time buckets** | `rollup:{agent}:{YYYYMMDDHH}` — counts, digests, first/last receipt id |
| **Merkle segment** | Per-hour segment root over receipt digests (ArtifactLog class `Proof`) |
| **Memory trace index** | `memory_trace:{agent}:{session}` — packet CIDs touched in session |
| **Spill to cold** | Segments > 24h compressed; court export includes segment roots only |
| **Sampling gate** | `forensic_profile=standard` rolls up; `court` retains every receipt |

New type: `ForensicRollupBucketV2` in connector-trust; writer in `kernel/forensics.rs`.

### 4.3 TraceTramp enhancements (P10.7.1)

| Event field (new) | Source |
|-------------------|--------|
| `cpo_id`, `quantum_id` | Ring-1 context / QPR |
| `agent_pid`, `principal_id` | Foundation block |
| `four_id` | CFNI headers |
| `docklock_profile_id` | DockLock compile |
| `memory_cids[]` | Effect handler |
| `rollup_segment_id` | Forensic bucket |

TT management API: `GET /admin/traces/:id/iia-correlation` (proxied).

### 4.4 WitnessCtl enhancements (P10.7.2)

- Session open carries `AgentIdentityEnvelopeV2` digest (not full envelope)
- Receipt shape adds optional `intelligence_receipt_id` back-link
- Compliance eval inputs: activation manifest + namespace grants
- Export bundle includes IIA export slice when `forensic_profile=court`
- HITL items tagged with `agent_pid` + `quantum_id`

### 4.5 ArtifactLog hash chain (P10.7.3)

Append `IntelligenceReceiptV2.receipt_id` as `ArtifactLogRecordV2` class `Proof` with:

- `previous_segment_digest`
- `segment_root` (hourly Merkle)
- Enables `connectorctl verify-export` to cross-check TT/WC/IIA

### 4.6 Platform APIs (forensic)

| API | Method | Purpose |
|-----|--------|---------|
| `/api/v1/runtime/self` | GET | Full `AgentIdentityEnvelopeV2` |
| `/api/v1/agents/:pid/setup` | POST/GET | Setup spec CRUD |
| `/api/v1/agents/:pid/activate` | POST | Gated activation |
| `/api/v1/agents/:pid/capabilities` | GET | Manifest + health |
| `/api/v1/forensics/chain` | GET | Unified correlation (route today missing) |
| `/api/v1/forensics/rollups/:agent` | GET | Bucket list + segment roots |
| `/api/v1/runtime/export` | GET | Extended with rollups + TT/WC refs |

---

## 5. Implementation phases

### Phase A — Schema & persistence (no behavior change)

- [ ] Add types to `connector-trust/src/iia/types.rs`
- [ ] `engine_store` folders: `agent_setup_spec_v2`, `agent_activation_profile_v2`, `namespace_grant_v2`
- [ ] `GET /runtime/self` returns envelope when present; backward compatible

### Phase B — Namespace isolation enforcement

- [ ] Single SoT: `vac_core::namespace_types` + grant table
- [ ] Wire grants into kernel ACB `readable_namespaces` / `writable_namespaces` on activate
- [ ] Gateway RAG scoped to agent `/m/` + granted `/k/` only
- [ ] Gate: `agent-namespace-isolation-gate.sh` (agent A cannot read agent B `/m/`)

### Phase C — Setup & activation gate

- [ ] `POST /agents/:pid/setup` + validation
- [ ] `POST /agents/:pid/activate` mints manifest + starts subsystems
- [ ] `CONNECTOR_AGENT_SETUP_GATE` for v1 register behavior
- [ ] Enrich `who_am_i_authoritative()` from envelope builder

### Phase D — Forensic correlation & rollups

- [ ] `ForensicRollupBucketV2` writer
- [ ] Route `/forensics/chain`
- [ ] TT/WC proxy payload extensions (four-ID, quantum)
- [ ] ArtifactLog segment Merkle
- [ ] Gate: extend `iia-forensics-gate.sh`

### Phase E — UI & operator surfaces (deferred → planned)

**Plan:** [UI_IIA_ENHANCEMENT_PLAN.md](../../UI_IIA_ENHANCEMENT_PLAN.md) · **Backend gaps:** [BACKEND_IIA_COMPLETION_BACKLOG.md](../../BACKEND_IIA_COMPLETION_BACKLOG.md) (B1–B22).

- [ ] Charter Studio S0–S11: purpose, **contract allow/deny/FS/network**, HITL policy, forensic profile, memory/KB, grants, tools, budgets, WC/TT bind, activate (E2)
- [ ] Backend **B1** `PATCH /agents/:pid/contract` (+ B5 HITL enforce, B7 DockLock←contract, B2 Talk façade — see backlog)
- [ ] RUN workbench: Talk · Charter · Manage · Identity · Evidence (E1+)
- [ ] **Talk** → real agent, not raw LLM (E5 + completions façade)
- [ ] WATCH/FIX recorder + forensics/WC/TT join (E3–E4)

---

## 6. Gates & evidence

| Gate | Proves |
|------|--------|
| `agent-namespace-isolation-gate` | Cross-agent `/m/` deny; grant allows shared `/k/` |
| `agent-activation-gate` | Cannot activate without name+acume+memory+knowledge+contract |
| `agent-identity-envelope-gate` | A vs B `who_am_i` differ on purpose, namespace, KB, knot stats |
| `iia-forensics-gate` (extended) | Rollups + chain API + offline verify |
| `iia-court-gate` | Aggregates all above |

Evidence files: `.agent-identity-envelope-gate.ok`, etc.

---

## 7. Non-goals (this phase)

- Replacing WitnessCtl HMAC chain with Ed25519 everywhere (P10.7.4 separate)
- Full UI wizard (Phase E)
- Migrating all v2 agents to IIA principal mint at register
- Per-receipt stable Ed25519 node key (forensics.rs generates per receipt today)

---

## 8. Decision log

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | 7 memory types + 9 namespace prefixes both appear in manifest | User asked for “9 types”; canon uses 9 namespace + 7 cognitive — manifest lists both clearly |
| D2 | `acume` aliases `purpose` at API | `FINANCE_AGENT_ACUME` already in register API |
| D3 | Common space = explicit `NamespaceGrantV2`, never implicit | Fail-closed isolation |
| D4 | `who_am_i` is rendered envelope, not ad-hoc format | One builder, gateway + API + MCP share it |
| D5 | Forensic rollups mandatory for `soc2`+ profiles | Million-events/minute intelligence ops cannot store raw only |
| D6 | v1 auto-start preserved behind flag until gates green | Avoid breaking existing demos |

---

## 9. File touch map (when coding starts)

| Area | Files |
|------|-------|
| Types | `oss/connector/crates/connector-trust/src/iia/types.rs` |
| Envelope builder | `platform/server/src/kernel/agent_identity_envelope.rs` (new) |
| Foundation | `platform/server/src/kernel/agent_foundation.rs` |
| Agents HTTP | `platform/server/src/services/agents.rs` |
| Runtime API | `platform/server/src/services/iia_runtime.rs` |
| Gateway | `platform/server/src/services/gateway.rs` |
| Isolation | `oss/vac/crates/vac-core/src/guard.rs`, `services/multiagent.rs` |
| Forensics | `platform/server/src/kernel/forensics.rs`, `substrate/artifact_log.rs` |
| TT/WC proxies | `services/tracetramp_proxy.rs`, `services/witnessctl_proxy.rs` |
| Gates | `platform/scripts/agent-identity-envelope-gate.sh` (new) |
| Router | `platform/server/src/router.rs` |

---

*Next step: review this plan, then implement Phase A → B with gates before enriching gateway context.*
