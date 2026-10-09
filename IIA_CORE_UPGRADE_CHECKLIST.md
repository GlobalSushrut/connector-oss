# IIA Core Upgrade Checklist — Court-Grade Intelligence Identity (v2)

> **Purpose:** Single follow-along queue for upgrading Connector on top of what is **already built** (L3–L5 engineering green, mesh soak, custody multinode). This is the **vertical spine** under [FINAL_REACH.md](FINAL_REACH.md) — not a replacement.  
> **Capability vision when done:** [CONNECTOR_WHEN_IIA_COMPLETE.md](CONNECTOR_WHEN_IIA_COMPLETE.md) — what Connector can do on top of today after P10.9.  
> **Canon:** [docs/architecture/intelligence-identity-architecture-v2.md](docs/architecture/intelligence-identity-architecture-v2.md) (import from `Connector_OS_Intelligence_Identity_Architecture_v2.docx`).  
> **Agent identity envelope (plan):** [docs/architecture/agent-identity-envelope.md](docs/architecture/agent-identity-envelope.md) — per-agent VAC/knowledge/Knot/HITL/forensic activation (P10.10).  
> **Forensics / compliance view (spec):** [docs/architecture/forensic-compliance-contract-view.md](docs/architecture/forensic-compliance-contract-view.md) — what DFIR/GRC sees (contract + package + control matrix).  
> **Plan:** `.cursor/plans/iia_core_infra_integration_06bfe92d.plan.md` (do not edit plan file; check boxes **here** only).

**Court-grade means:** Ed25519-signed principals/contracts/receipts; offline `connectorctl verify-*`; no decorative `verified: true`; HMAC-only paths labeled `signing_tier: hmac_lab` until Ed25519 path green; every protected effect has CPO → QPR quantum → DockLock → receipt; tamper on export fails verify.

**Row template:** `- [ ] **Core:** …` / `- [ ] **Backend:** …` / `- [ ] **UI:** …` / `- **Verify:** …` / `- **Evidence:** _path or command_`

---

## Spine (do not skip gates)

```
INTELLIGENCE ≠ IDENTITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE

Model → N4 (handshake, qualify, CPO) → QPR (execution quantum) → DockLock → OS/HW → Witness/Trace/Receipt
         Gate 1                          Gate 2                    enforce
```

| Layer | Product name | Code namespace (target) |
|-------|--------------|-------------------------|
| Agent Kernel | Intelligence Principal | `kernel/agent_principal.rs`, `connector-trust` |
| Gate 1 | **N4** Intelligence Admission Matrix | `intelligence_admission/` |
| Gate 2 | **QPR** Quanta/Polar Ring | `quanta_polar/` + `ExecutionQuantumV2` |
| Enforce | **DockLock** | cage + `plugin-runtime` + `graph_firewall` |
| Truth | Execution Reality Manifest | `ExecutionRealityManifestV2` + mesh placement |
| Forensics | TraceTram + WitnessCtl + ledger | `artifact_log`, plugins, `IntelligenceReceiptV2` |

---

## Naming (avoid mixing two “admission” systems)

| Name in docs/API | What it is | Existing code |
|------------------|------------|---------------|
| **Effect Admission Inventory** | HTTP route → `admission_gate` map (Gate-2 *paths*) | `substrate/admission_matrix.rs`, [admission-matrix.md](docs/architecture/admission-matrix.md) |
| **N4 Intelligence Admission** | Model handshake → profile → **CPO** (Gate-1) | **New** `intelligence_admission/` — **not** `admission_matrix.rs` |

---

## Baseline — already on the node (keep; upgrade in place)

Check only when verified; these are **starting points**, not court-grade alone.

| Asset | Status | Evidence / path |
|-------|--------|-----------------|
| Engineering light gate | [x] | `make final-reach-light-gate` |
| L5 mesh soak T13/T15 | [x] | `platform/scripts/.l5-mesh-soak.ok` |
| Custody 3-node live T17 | [x] | `platform/scripts/.custody-multinode-soak.ok` |
| Effect admission on major routes | [x] | [admission-matrix.md](docs/architecture/admission-matrix.md) |
| CFNI flow stamp | [x] partial | `connector-trust/forensic_flow.rs` — **upgrade to Ed25519 court tier** |
| Flow lease (short-lived ticket) | [x] partial | `substrate/flow_lease.rs` — **upgrade to ExecutionQuantumV2** |
| SGKE I×H placement deny | [x] | `substrate/sgke_gate.rs` |
| HardwarePlacementV2 / edge | [x] seed | `connector-trust/hardware_placement.rs`, `/runtime/mesh` |
| Platform Ed25519 node key | [x] | `platform/server/src/signing.rs` |
| Agent PID + namespace | [x] | `services/agents.rs`, [12-ring-1-identity-boot.md](docs/12-ring-1-identity-boot.md) |
| Cage / microVM | [x] partial | cage smoke — **bind to quantum** |
| TraceTramp + WitnessCtl | [x] partial | plugins — **link CPO→quantum→PID** |

---

## Court-grade non-negotiables (never check “done” if violated)

- [ ] **C1:** No `verified: true` without offline verify command passing.
- [ ] **C2:** No marketed “court-grade” on HMAC-only receipts (`signing_tier` must be `ed25519_court`).
- [ ] **C3:** No LLM tool call executes without **CPO → QPR quantum → DockLock** on that path.
- [ ] **C4:** No N4 label on HTTP route inventory alone (handshake + profile required).
- [ ] **C5:** No stub JSON honesty on court paths (glue executor stays de-claimed).
- [ ] **C6:** Invariants I1–I12 from IIA v2 §21 have at least one automated test each.
- [ ] **C7:** `mesh_fabric` / custody / failover honesty rules from [FINAL_REACH.md](FINAL_REACH.md) unchanged.

---

## P10.0 — Canon & mapping (do first)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.0.1 | Import IIA v2 markdown canon | [ ] | n/a | n/a | [ ] |
| P10.0.2 | Link from ARCHITECTURE, FINAL_REACH, CONNECTOR_TRUTH_STORY | [ ] | n/a | n/a | [ ] |
| P10.0.3 | Clarify Effect Admission vs N4 in admission-matrix.md | [ ] | n/a | n/a | [ ] |
| P10.0.4 | IIA claim demo doc (§23 flagship steps) | [ ] | n/a | n/a | [ ] |
| P10.0.5 | This checklist linked as P10 queue in FINAL_REACH | [ ] | n/a | n/a | [ ] |

- **Verify:** `grep -l intelligence-identity-architecture-v2 docs ARCHITECTURE.md FINAL_REACH.md`
- **Evidence:** _paths after import_

---

## P10.1 — Trust contracts (`connector-trust`) — court types

| ID | Type | Core | Backend | Done |
|----|------|------|---------|------|
| P10.1.1 | `IntelligencePrincipalV2` (`cnktr:agent:*`, issuer, authority_chain) | [ ] | serde + round-trip tests | [ ] |
| P10.1.2 | `AgentContractV2` (signed constitution + digest) | [ ] | compile from policy/cage | [ ] |
| P10.1.3 | `IntelligenceProfileV2` (claimed/observed/attested/contract-accepted) | [ ] | four quadrants never collapsed | [ ] |
| P10.1.4 | `CognitiveProposalV2` (CPO) | [ ] | non-authoritative schema | [ ] |
| P10.1.5 | `ExecutionQuantumV2` (nonce, expiry, contract-bound) | [ ] | single-use + replay reject | [ ] |
| P10.1.6 | `ExecutionRealityManifestV2` | [ ] | `attestation_tier: none\|tpm\|tdx` honest | [ ] |
| P10.1.7 | `ContinuityRecordV2` | [ ] | break → revoke quanta | [ ] |
| P10.1.8 | `IntelligenceReceiptV2` (hash-linked) | [ ] | previous_receipt chain | [ ] |
| P10.1.9 | `signing_tier` + Ed25519 sign/verify helpers | [ ] | `ed25519-dalek` in connector-trust | [ ] |

- **Verify:** `cargo test -p connector-trust`
- **Evidence:** `oss/connector/crates/connector-trust/src/`

---

## P10.2 — Phase 0: Identity spine (doc P0)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.2.1 | Mint principal at `POST /agents` register | [ ] | Ed25519 per principal or node-delegated subkey | [ ] | [ ] |
| P10.2.2 | Persist principal + contract in engine_store | [ ] | folder `intelligence_principal_v2` | n/a | [ ] |
| P10.2.3 | `GET /api/v1/runtime/self` | [ ] | authoritative envelope | Monitor badge | [ ] |
| P10.2.4 | `GET /runtime/contract` | [ ] | signed contract + digest | Settings | [ ] |
| P10.2.5 | Continuity ledger at register + on change | [ ] | model_ref, runtime_hash, contract_hash | n/a | [ ] |
| P10.2.6 | Two principals, same model — distinct IDs (demo §23.1–2) | [ ] | smoke script | n/a | [ ] |

- **Verify:** `make iia-p0-gate`
- **Evidence:** `platform/scripts/iia-p0-gate.sh`, `.iia-p0-gate.ok`

---

## P10.3 — Phase 0.5: N4 Intelligence Admission (doc P0.5)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.3.1 | `intelligence_admission/` module | [ ] | `n4_hello`, `n4_qualify`, `n4_context`, `n4_cognize` | n/a | [ ] |
| P10.3.2 | Provider adapter (OpenAI-compat gateway) | [ ] | tool-call → CPO, never direct dispatch | n/a | [ ] |
| P10.3.3 | Context classes (kernel_fact, policy, memory, tool_result, untrusted, instruction) | [ ] | typed provenance | n/a | [ ] |
| P10.3.4 | Unqualified model rejected at handshake | [ ] | HTTP 403 + reason | n/a | [ ] |
| P10.3.5 | Prompt injection → CPO only, no execution (§23.12) | [ ] | adversarial test | n/a | [ ] |
| P10.3.6 | Model substitution event (§23.11) | [ ] | AgentID stable, IntelligenceID changes | n/a | [ ] |

- **Verify:** `make iia-n4-gate`
- **Evidence:** `platform/scripts/iia-n4-gate.sh`

---

## P10.4 — Phase 1: QPR + ExecutionQuantum (doc P1)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.4.1 | `quanta_polar/` polarize CPO → quantum | [ ] | contract + continuity + SGKE | n/a | [ ] |
| P10.4.2 | Upgrade `flow_lease` → `ExecutionQuantumV2` | [ ] | 90s TTL, nonce, single-use | n/a | [ ] |
| P10.4.3 | `POST /api/v1/qpr/intent` | [ ] | mint quantum from CPO | Actionlog | [ ] |
| P10.4.4 | `require_quantum(op)` on **every** effect admission row | [ ] | wire all routes in admission-matrix | n/a | [ ] |
| P10.4.5 | Authorized action passes; unauthorized denied (§23.3–4) | [ ] | adversarial HTTP | n/a | [ ] |
| P10.4.6 | Replay / expired quantum rejected | [ ] | unit + HTTP tests | n/a | [ ] |

- **Verify:** `make iia-qpr-gate`
- **Evidence:** extends `trust_adversarial_http.rs`

---

## P10.5 — Phase 2: DockLock (doc P2)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.5.1 | Quantum → cage profile compiler (fs/process/net) | [ ] | bind quantum id to cage env | n/a | [ ] |
| P10.5.2 | Gateway egress + MCP/tools require quantum | [ ] | CFNI header + env | n/a | [ ] |
| P10.5.3 | Prod preset: shell/raw network without quantum = deny | [ ] | bypass adversarial | n/a | [ ] |
| P10.5.4 | Demo §23.5 bypass attempt fails | [ ] | `make docklock-bypass-adversarial` | n/a | [ ] |

- **Verify:** `make cage-smoke` + `make docklock-bypass-adversarial`
- **Evidence:** scripts + logs

---

## P10.6 — Phase 3–4: Continuity + Execution Reality (doc P3–P4)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.6.1 | Tool/runtime hash measurement | [ ] | continuity evaluator | n/a | [ ] |
| P10.6.2 | Mismatch → revoke quanta + isolate egress | [ ] | §10 semantics | Monitor strip | [ ] |
| P10.6.3 | `GET /runtime/hardware` — signed ERM | [ ] | node witness Ed25519 | Monitor | [ ] |
| P10.6.4 | Bind ERM to `HardwarePlacementV2` + mesh cell | [ ] | `/runtime/mesh` | Mesh panel | [ ] |
| P10.6.5 | Demo §23.6–7 tamper + manifest verify | [ ] | offline verify | n/a | [ ] |

- **Verify:** `make iia-continuity-gate`
- **Evidence:** `.iia-continuity-gate.ok`

---

## P10.7 — Phase 4–6: Forensic chain (doc P5–P6)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.7.1 | TraceTramp nodes: CPO, quantum, DockLock, PID | [ ] | causal graph API | Forensics UI | [ ] |
| P10.7.2 | WitnessCtl receipt shape (§18) | [ ] | four-ID linkage | WC strip | [ ] |
| P10.7.3 | ArtifactLog hash chain for `IntelligenceReceiptV2` | [ ] | append-only | n/a | [ ] |
| P10.7.4 | Custody export uses Ed25519 court tier | [ ] | extends custody-multinode-soak | n/a | [ ] |
| P10.7.5 | Demo §23.9–10 reconstruct + tamper detect | [ ] | export package | n/a | [ ] |
| P10.7.6 | `connectorctl verify-receipt` / `verify-export` | [ ] | offline, no UI trust | CLI help | [ ] |

- **Verify:** `make iia-forensics-gate`
- **Evidence:** `.iia-forensics-gate.ok`

---

## P10.8 — Phase 5: Cross-layer + mesh (doc P5 + L5)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.8.1 | Four-ID on CFNI + mesh channel headers | [ ] | Agent/Intelligence/Runtime/Machine | n/a | [ ] |
| P10.8.2 | `POST /runtime/delegate` bounded delegation | [ ] | expiry + scope | n/a | [ ] |
| P10.8.3 | Placement filter by principal + contract + SGKE | [ ] | real schedule/filter | Monitor | [ ] |
| P10.8.4 | Extend `l5-mesh-soak` with delegation + four-ID | [ ] | cross-cell | n/a | [ ] |

- **Verify:** `make l5-mesh-soak` (extended) + T14 deepen
- **Evidence:** updated `.l5-mesh-soak.ok`

---

## P10.10 — Agent identity envelope & activation (plan → code)

> **Architecture (read first):** [docs/architecture/agent-identity-envelope.md](docs/architecture/agent-identity-envelope.md)

| ID | Item | Core | Backend | UI | Done |
|----|------|------|---------|-----|------|
| P10.10.1 | `AgentSetupSpecV2` + `AgentActivationProfileV2` types | [x] | `connector-trust` + engine_store folders | n/a | [x] |
| P10.10.2 | Namespace isolation: no cross-agent `/m/` without grant | [x] | MAC + admission + recall2 | n/a | [x] |
| P10.10.3 | `POST /agents/:pid/setup` + `POST /agents/:pid/activate` | [x] | gated lifecycle; `CONNECTOR_AGENT_SETUP_GATE` | Setup wizard (later) | [x] |
| P10.10.4 | `AgentIdentityEnvelopeV2` builder + enriched `who_am_i` | [x] | memory/knot/KB summaries in gateway | Capabilities panel (later) | [x] |
| P10.10.5 | Capability manifest (7 memory + 9 namespace + thinking/knot/forensic) | [x] | `GET /agents/:pid/capabilities` | Monitor strip | [ ] UI |
| P10.10.6 | Forensic rollups + `/forensics/chain` correlation | [x] | `ComplianceContractV2` at activate; hourly `ForensicRollupBucketV2` + joins; `GET /forensics/{rollups,chain,package,witnessctl-join}`; WC `…/iia-join`; package MANIFEST signed court-tier; gate T27/T28 | Forensics UI | [x] gate |
| P10.10.7 | Demo: Agent A vs B `who_am_i` differ on acume, namespace, KB, knot | [x] | `agent-identity-envelope-gate` (T25) | n/a | [x] |

- **Verify:** `make agent-identity-envelope-gate` (new) + extend `iia-forensics-gate`
- **Evidence:** `.agent-identity-envelope-gate.ok`

**Phases:** A schema → B isolation → C activation → D forensic correlation → E UI (deferred).

---

## P10.9 — Phase 6: Market gates & sign-off (doc P7)

| ID | Item | Done |
|----|------|------|
| P10.9.1 | `make iia-court-gate` (aggregates P0–P6 + identity gates) | [x] evidence `.iia-court-gate.ok` |
| P10.9.2 | PRODUCTION_READINESS rows for IIA invariants | [x] § P10/IIA + Final GO #9–10 in `PRODUCTION_READINESS_CHECKLIST.md` |
| P10.9.3 | Clean-VM flagship demo §23 (all 14 steps) | [x] `make iia-flagship-demo` → `.iia-flagship-demo.ok` |
| P10.9.4 | Human sign-off block below | [ ] |

**IIA court-grade Sign-off:** _________________ **Date:** _________ **Version:** _________

---

## Claim tests T19–T24 (check only with gate evidence)

| ID | Test | Phase | Done | Gate |
|----|------|-------|------|------|
| T19 | Two principals, same model, distinct signed `cnktr:agent:*` | P10.2 | [x] | `iia-p0-gate` |
| T20 | CPO from N4; no raw tool execution | P10.3 | [x] | `iia-n4-gate` |
| T21 | QPR quantum required on all effect paths | P10.4 | [x] | `iia-qpr-gate` |
| T22 | DockLock bypass adversarial fails | P10.5 | [x] | `docklock-bypass-adversarial` |
| T23 | Continuity break stops new quanta | P10.6 | [x] | `iia-continuity-gate` |
| T24 | Export verifies offline; tamper detected | P10.7–P10.9 | [x] | `iia-forensics-gate` / flagship S10 |
| T25 | Same model, two agents: distinct `who_am_i` envelope (acume, `/m/`, KB, knot) | P10.10 | [x] | `agent-identity-envelope-gate` |
| T26 | Agent A cannot read Agent B `/m/` without `NamespaceGrantV2` | P10.10 | [x] | `agent-identity-envelope-gate` |
| T27 | Distinct A/B `ComplianceContractV2` digests (signed court-tier) | P10.10 | [x] | `agent-identity-envelope-gate` |
| T28 | Forensic rollup + package MANIFEST verify surface | P10.10 | [x] | `agent-identity-envelope-gate` |

---

## Runtime API surface (check when implemented)

| API | Method | Phase | Done |
|-----|--------|-------|------|
| `/api/v1/runtime/self` | GET | P10.2 | [ ] |
| `/api/v1/runtime/contract` | GET | P10.2 | [ ] |
| `/api/v1/runtime/hardware` | GET | P10.6 | [ ] |
| `/api/v1/runtime/permissions` | GET | P10.4 | [ ] |
| `/api/v1/runtime/provenance` | GET | P10.7 | [ ] |
| `/api/v1/runtime/delegate` | POST | P10.8 | [ ] |
| `/api/v1/n4/hello` | POST | P10.3 | [ ] |
| `/api/v1/n4/qualify` | POST | P10.3 | [ ] |
| `/api/v1/n4/cognize` | POST | P10.3 | [ ] |
| `/api/v1/qpr/intent` | POST | P10.4 | [ ] |
| `/api/v1/agents/:pid/setup` | POST/GET | P10.10 | [x] |
| `/api/v1/agents/:pid/activate` | POST | P10.10 | [x] |
| `/api/v1/agents/:pid/capabilities` | GET | P10.10 | [x] |
| `/api/v1/agents/:pid/compliance-contract` | GET | P10.10 | [x] |
| `/api/v1/forensics/chain` | GET | P10.10 | [x] |
| `/api/v1/forensics/rollups/:agent` | GET | P10.10 | [x] |
| `/api/v1/forensics/package` | GET | P10.10 | [x] |
| `/api/v1/forensics/witnessctl-join` | GET | P10.10 | [x] |

---

## Make targets (add as phases land)

| Target | When green |
|--------|------------|
| `make iia-p0-gate` | P10.2 |
| `make iia-n4-gate` | P10.3 |
| `make iia-qpr-gate` | P10.4 |
| `make docklock-bypass-adversarial` | P10.5 |
| `make matrix-isolation-gate` | P10.6 CDMI |
| `make iia-continuity-gate` | P10.6 |
| `make iia-forensics-gate` | P10.7 |
| `make agent-identity-envelope-gate` | P10.10 |
| `make iia-court-gate` | P10.9 (all above) |
| `make iia-flagship-demo` | P10.9.3 (§23 × 14) |
| `make engineering-reach-gate` | optional: include `iia-court-gate` after P10.9 |

---

## Flagship demo §23 — step checklist

Use during `docs/AIOS_IIA_CLAIM_DEMO.md` smoke / clean-VM sign-off.

- [x] 1. Instantiate Agent A (Developer) + Agent B (Finance), same LLM endpoint — `iia-flagship-demo` S01
- [x] 2. `GET /runtime/self` — distinct AgentIDs, contracts — S02
- [x] 3. Agent A permitted path — quantum + receipt — S03
- [x] 4. Prompt-inject finance access — QPR deny — S04
- [x] 5. Shell/SDK bypass — DockLock deny — S05
- [x] 6. Runtime/tool tamper — continuity BROKEN — S06
- [x] 7. Execution Reality Manifest — S07
- [x] 8. Agent B compliance / identity envelope — S08
- [x] 9. Provenance receipts — S09
- [x] 10. Export package — verify; tamper → fail — S10
- [x] 11. N4 model substitution — AgentID stable — S11
- [x] 12. Untrusted context injection — CPO labeled, QPR deny — S12
- [x] 13. Failed N4 handshake model — S13
- [x] 14. Four-ID + forensic package — S14

*(Evidence: `platform/scripts/.iia-flagship-demo.ok` — 14/14 PASS.)*

---

## Progress scoreboard

| Phase | Meaning | Status |
|-------|---------|--------|
| P10.0 Canon | Docs + mapping | **GREEN** (canon import + admission-matrix note + claim demo) |
| P10.1 Trust types | connector-trust v2 | **GREEN** (`cargo test -p connector-trust`) |
| P10.2 Identity spine | P0 | **GREEN** — `make iia-p0-gate` / `.iia-p0-gate.ok` |
| P10.3 N4 | Gate 1 | **GREEN** — `make iia-n4-gate` |
| P10.4 QPR | Gate 2 | **GREEN** — `make iia-qpr-gate`; **hardened:** TOCTOU-safe consume + operation bind |
| P10.5 DockLock | Enforce | **RING-1 GREEN** — CDMI hardware-deny cage profile + matrix isolation gate |
| P10.6 Continuity + ERM | Reality | **GREEN** — break → revoke quanta + egress isolate (`matrix-isolation-gate`) |
| P10.7 Forensics | TT/WC/ledger | **GREEN** — `make iia-forensics-gate`; deepen: TraceTram causal graph UI |
| P10.8 Mesh + delegate | L5 deepen | **PARTIAL** — `POST /runtime/delegate` + four-ID API; deepen: mesh soak extension |
| P10.9 Court gate | Market IIA | **ENGINEERING GREEN** — court + flagship (`.iia-court-gate.ok`, `.iia-flagship-demo.ok`); **P10.9.4 human sign-off still open** |
| P10.10 Identity envelope | Per-agent context | **A–D done**; UI [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md); gaps [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md); **full audit** [CODEBASE_PROBLEMS_AUDIT.md](CODEBASE_PROBLEMS_AUDIT.md) |

**Coding order:** P10.0 → P10.1 → P10.2 → … → P10.9. **P10.10** runs after P10.2 (identity spine) and in parallel with P10.7 (forensics deepen). Do not skip QPR wiring (P10.4) before claiming N4 “done.” Do not market court-grade until P10.9 signed.

---

## Quick commands (laptop-safe first)

```bash
make final-reach-light-gate      # existing baseline
make engineering-reach-gate      # L5 soaks (already green)
cargo test -p connector-trust    # IIA types (after P10.1)
make iia-p0-gate                 # after P10.2
# … through iia-court-gate
```

Laptop: do **not** run `cargo test -p connector-platform --bin connector-platform` on ≤16 GiB — [docs/LOW_MEMORY_DEV.md](docs/LOW_MEMORY_DEV.md).
