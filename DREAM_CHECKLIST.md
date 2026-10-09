# Dream checklist — digital intelligence OS

**Date:** 2026-08-13  
**Goal:** Ops-honest claims on the shipped membrane (DI-0…5 + TG-0…6 + ACS / layers / world / share).  
**SoT:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3** — final arch **§0** (kernel → ACS).  
**Specs:** [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md) · [CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md](CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md) · [NATIVE_PROTOCOL_TG_PLAN.md](NATIVE_PROTOCOL_TG_PLAN.md)

**How to use:** Check items only when the **Done when** test passes. Do waves in order (TG-0 → TG-6). Ops items can run in parallel.

**5-minute intelligence create:** [INTELLIGENCE_5MIN.md](INTELLIGENCE_5MIN.md) · `POST /api/v1/intelligence/apply` · `connectorctl iia apply --file …`  
**World connect:** [OPERATOR_WORLD_AGENTS.md](OPERATOR_WORLD_AGENTS.md) · `GET /api/v1/protocol/world`

---

## Legend

| Mark | Meaning |
|------|---------|
| `[ ]` | Not done |
| `[x]` | Done (verified) |
| **Spine** | Already shipped under DI-0…5 — listed for orientation, not rework |

---

## 0. Spine already in place (do not rebuild)

- [x] Principal mint + contract PATCH + activate / demote on charter change  
- [x] Force-pid Talk + who_am_i + RAG (stream + non-stream)  
- [x] LLM link (Settings + `connectorctl llm link` + vault)  
- [x] DockLock v2 + Landlock intent + matrix mark cut path  
- [x] Credential proxy / keys-out-of-cage spine  
- [x] Grants + dispatch (queued) + inter-intel grant gate  
- [x] Forensic package download + court-readiness API  
- [x] LAB MODE API + intelligence crumbs (WATCH/Control/MONITOR)  
- [x] `connectorctl iia smoke` (two-agent path)  
- [x] L7 **app** allowlist (`CONNECTOR_L7_EGRESS_PROXY`)  
- [x] **ACS + NS FS + light_ns** — per-pid character + isolation trees (`/runtime/acs/:pid`)  
- [x] **Three admission layers** — Root HITL · Cone · App Allow (human+root); fold Block > Ask > App  
- [x] **World grants** — `(agent_pid × CNP address)` + kernel root passcode  
- [x] **Share portals** — contract (what/where/how much/why) before `/share/{id}`  
- [x] **5-min IntelligenceSpec** — `POST /intelligence/apply` · `connectorctl iia apply`

---

## TG-0 — Prod honesty (DI-6)

**Intent:** Physics must not lie. Lab vs applied is unmistakable.

### Backend / posture
- [x] `applied_truth` on Landlock / matrix / DockLock / L7 in posture APIs (intent ≠ applied) — `GET /runtime/intelligence-posture` → `applied_truth`  
- [x] Under harden/prod: missing Landlock ABI or matrix tools → **refuse** start/tool (not soft green) — `membrane_posture::assert_membrane_ready_*`  
- [x] `GET /runtime/lab-mode` (or equivalent) true whenever any critical gate off  
- [x] Residual C9 audit: list any mutating path still without `require_contract_action` / grant  
  - Gated: tools (`admit_tool_or_ask`), Talk (`admit_talk_or_ask`), CONP command, A2A send, memory share, multiagent dispatch grant, inter-agent `signal.send`, operator `agent.signal`, plugin cold-start ambient shell/net under harden  

### UI / Control
- [x] LAB MODE banner impossible to miss when lab — sticky amber bar + enable hardening CTA (`shell/mod.rs`)  
- [x] One-click / clear path to enable hardening preset — `POST /runtime/enable-hardening` from banner  
- [x] Control: **Start** wired (not only pause/kill) — `ControlTab` → `POST /agents/{pid}/start`  
- [x] Control: cage/runtime log stream distinct from audit activity — `GET /agents/{pid}/cage-runtime` panel  

### Done when
- [x] Soft-fail cannot show as “applied” in MONITOR (`applied_truth` vocabulary excludes bare `applied`)  
- [x] Operator can start → talk → pause → kill without CLI — Control UI + `connectorctl iia smoke` lifecycle (start/pause/resume/kill + Talk admit path)  

---

## TG-1 — Action-bound HITL (DI-7)

**Intent:** Approve exact action `A`, not a vibes checkbox.

### Protocol
- [x] `ActionBinding` schema (agent, tool, params, contract_digest, policy_version) — `kernel/action_binding.rs`  
- [x] `action_digest = sha256(JCS(binding))` (canonical key-sorted JSON)  
- [x] HITL create stores digest + expiry + `fail_closed_on_timeout`  
- [x] Approve/deny creates terminal resolution; **revalidate digest pre-exec** (`hitl_consume_for_action`)  
- [x] One-time consume under concurrency  
- [x] Timeout / restart / malformed → deny (never auto-allow)  
- [x] Authenticated approver identity (no free-text spoof) — operator+ on approve/deny  

### Done when
- [x] Unit: approval for digest A **cannot** execute digest B  
- [x] Unit: policy/contract version change invalidates pending approval  
- [x] Unit: timeout fails closed (`hitl_timed_out_fail_closed`) — process-restart durable store still TG-3  

---

## TG-2 — Autonomy gateway (DI-8)

**Intent:** Allow / Ask / Block — Ask is suspended admission, not hard deny.

### Gateway
- [x] `AutonomyGateway.decide(A) → Allow | Ask | Block` — `autonomy_decide`  
- [x] Inputs: contract caps, denied_ops, HITL policy, risk class (anomaly/budget Phase B)  
- [x] Wire into **tools** path (`admit_tool_or_ask` in `tools.rs`)  
- [x] Wire into **Talk** path (`admit_talk_or_ask` in gateway stream + non-stream)  
- [x] Ask → creates TG-1 HITL (digest-bound)  
- [x] Block → deterministic reason code  
- [x] MONITOR metrics: allow / ask / block rates — `intelligence-posture.autonomy_gateway`  

### Done when
- [x] HITL=tool + high-risk tool → Ask (not silent Allow) — via setup `HitlPolicyV2` + gateway  
- [x] Denied op → Block (not Ask)  
- [x] Rates visible on MONITOR (`GET /runtime/intelligence-posture`) 

---

## TG-3 — Mission journal (DI-9)

**Intent:** Session memory ≠ durable execution.

### Runtime
- [x] `MissionV1` / steps append-only in engine_store (`iia_missions` / `iia_mission_steps`)  
- [x] Step kinds: `llm` | `tool` | `hitl_wait` | `fabric` | `conp_command` | `cnp_message` | `compensate`  
- [x] Mutating **MCP tools** wrapped with `(mission_id, idempotency_key) → receipt` (`mcp_invoke` / scoped)  
- [x] `POST /missions/:id/resume` returns completed vs open (skip re-fire by idempotency)  
- [x] HITL durable across process restart (`iia_hitl_requests` folder + hydrate)  
- [x] Irreversible tools require Ask or explicit charter `no_compensate` (capability)  

### Done when
- [x] CONP command: completed idempotency_key → resume does **not** re-invoke HAL  
- [x] HITL wait survives restart (engine_store persist + hydrate)  
- [x] Journal reconstructs who/what/when for completed CONP/MCP/mission steps (`GET /missions/:id`)  

---

## TG-4 — A2A fabric lifecycle (DI-10)

**Intent:** Queued folder → real task machine with authority.

### Fabric
- [x] `fabric.task.v2` with A2A states: SUBMITTED, WORKING, INPUT_REQUIRED, AUTH_REQUIRED, COMPLETED, FAILED, CANCELED, REJECTED  
- [x] Terminal states immutable  
- [x] `context_id` groups related tasks (`GET /fabric/tasks?context_id=`)  
- [x] APIs: get / cancel / transition / list-by-context (SSE subscribe still bridge-path)  
- [x] Authority on every task: principal, mark, grant_id, contract_digest, namespace (+ optional `conp_entity_id`)  
- [x] Protocols A2A get/cancel share fabric SoT with multiagent dispatch  
- [x] Extend `connectorctl iia smoke` → assert terminal COMPLETED (+ terminal immutability)  

### Done when
- [x] Unauthorized cross-agent dispatch → 403 (grant/contract gates unchanged)  
- [x] Authorized path reaches terminal state (smoke → COMPLETED)  
- [x] INPUT_REQUIRED + resume with same taskId works — `POST /fabric/tasks/:id/resume` + smoke asserts WORKING same taskId  

---

## TG-5 — Decision traces & court shape (DI-11)

**Intent:** Logs ≠ decision traces.

### Evidence
- [x] `DecisionTraceV1` on tool + CONP + fabric transitions (`kernel/decision_trace.rs`)  
- [x] Fields: principal, gateway, action_digest, approval id, model_ref, rag hashes, outcome, prev/record hash (+ CONP message_type/capability_id)  
- [x] Forensic package includes traces + approval resolutions + contract digests  
- [x] `connectorctl iia verify-export` validates decision-trace chain (+ court receipt path)  
- [x] Court-readiness fails closed when WC/CFNI missing (`ready: false` + `missing[]`)  
- [x] No `gateway-*` attribution on principal-bound traces (stripped + verify rejects)  

### Done when
- [x] Export package decision_traces verify offline (`verify-export`)  
- [x] Trace answers who/what/why (principal + action_digest + gateway + outcome)  
- [x] Checklist red without WC/CFNI when those are required for the claim  

---

## TG-6 — Cage tiers & FC default (DI-12)

**Intent:** Membrane materials with a claim ladder.

### Isolation
- [x] `IsolationTier`: ProcessLandlock | DockerLab | MicroVm | HostSimulated  
- [x] `GET /runtime/isolation/:agent_pid` → tier + landlock + matrix + soft_fail + applied_truth  
- [x] Prod/harden preset: Landlock FC + matrix required (unless MicroVm tier) — membrane refuse path  
- [x] Refuse agent/tool start when FC required and apply failed (`assert_membrane_ready_*`)  
- [x] MicroVM path documented/usable for **high-risk** class (not silent default claim)  
- [x] eBPF Host Active only with real apply + explicit flag (honesty: unknown_until_attach)  

### Done when
- [x] FC on + Landlock unavailable → denied with honest error  
- [x] Posture never claims matrix applied when insert failed (`applied_truth`)  
- [x] Tier visible to operator (`GET /runtime/isolation/:agent_pid`)  

---

## Ops soak (parallel — required for “dream claim”)

- [x] `make l5-mesh-soak` (or equiv) green with `CONNECTOR_MESH_FABRIC=1` — PASS 2026-08-12 (`platform/scripts/.l5-mesh-soak.ok`)  
- [x] Court: **no court claim without backends** — smoke asserts `court-readiness ready=false` + `missing[]` when WC/CFNI unset (live green only when secrets present; not claimed here)  
- [ ] **Court-defensible on a real node** — follow [COURT_DEFENSIBLE_CHECKLIST.md](COURT_DEFENSIBLE_CHECKLIST.md); `connectorctl iia court --agent-pid` exit 0 + CD-9 sign-off  
- [x] **AIOS V1 kernel ABI** — [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md); `GET /kernel/aios/claim-readiness` `v1_buyer_os`; `connectorctl iia aios`  
- [ ] **AIOS leftover U1–U16** — [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) (memory/knowledge/fleet as WM+levels; sit beneath vLLM/LangGraph)  
- [x] Prod preset dogfood: harden on, LAB MODE off path — `make prod-dogfood-smoke` (script sets `CONNECTOR_AUDIT_HMAC_KEY` + stub allow)  
- [x] Two-charter regression: `connectorctl iia smoke` in CI release gate — wired into `platform/scripts/ci_beta_gate.sh`  

---

## Native protocol (CNP + CP/1.0) — fold into TG waves

**Intent:** Robots / machines / APIs speak **our** vocabulary (CONP 30 types + 120 caps; CNP spine). Same membrane as tools — not a side door. Full plan: [NATIVE_PROTOCOL_TG_PLAN.md](NATIVE_PROTOCOL_TG_PLAN.md).

### Designed (already in OSS — do not rebuild)
- [x] CP/1.0 `MessageType` × **30** (`connector-protocol` / CONP)  
- [x] CP capability registry × **120** (`machine.*` / `actuator.*` / `sensor.*` / `safety.*` / net…)  
- [x] CNP 7-layer spine + `sensor` / `actuation` payloads (`connector-engine` CNP)  
- [x] Platform `GET /api/v1/cnp/overview` (bridges map MCP/A2A → CNP)  

### Wire into dream (checklist)
- [x] NP-0: posture exposes `native_protocol` applied_truth (CNP mTLS / HAL present ≠ SIL)  
- [x] NP-1: `platform` depends on `connector-protocol`; CONP → `ActionBinding` digests  
- [x] NP-2: gateway uses CP `RiskLevel`; e-stop ambient Allow+audit; Command path admitted  
- [x] NP-3: journal steps for CONP `Command`/`CommandAck` via `mission_id` (TG-3 spine)  
- [x] NP-4: fabric tasks carry CONP entity + grant + mark (`conp_entity_id` on fabric.task.v2)  
- [x] NP-5: DecisionTrace includes `message_type` / `capability_id` / CNP ids  
- [x] Catalog APIs: `GET /protocol/conp/info` + `capabilities`; `POST …/command` + `…/estop`  
- [x] Lab stub HAL echo — **not** ROS/SIL claim (`sil_certified: false`)  

### Done when
- [x] Mutating CONP Command goes through digest HITL / gateway (`admit_conp_or_ask`)  
- [x] Posture never implies certified robot safety from CONP taxonomy alone  
- [x] Unit: MessageType count 30 + registry 120 green (`connector-protocol` tests)  

---

## Residual T0 (effect exclusivity)

Close any remaining side doors (grep / audit as you go):

- [x] All MCP / tool bridges gated — `admit_tool_or_ask`  
- [x] All CONP Command / CNP actuation paths gated (same as tools) — CONP command admit; CNP surface is catalog/overview only  
- [x] All memory share / packet paths grant-checked under harden  
- [x] All signal / A2A / fabric paths grant + contract checked  
- [x] No LLM/tool secrets in cage env — `strip_secret_env_keys` + smoke cage-runtime key assert  
- [x] Plugin paths cannot open ambient shell / unrestricted net — refuse under harden if `CONNECTOR_PLUGIN_AMBIENT_SHELL` / `UNRESTRICTED_NET`  

**Done when:** typed-action paths above cannot bypass charter under harden (smoke + unit gates).

---

## Dream definition of done (all must be true)

- [x] TG-0 through TG-6 checklists complete  
- [x] Ops soak items complete for the claims you make (mesh claimed via `.l5-mesh-soak.ok`; court **not** claimed — fail-closed verified)  
- [x] Acceptance from DI plan §6 (items 11–15) verified — digest HITL, mission resume, fabric terminals, decision traces, IsolationTier FC  
- [x] No marketing of eBPF / MicroVM / court without backends  
- [x] Out-of-scope held: SIL robotics, ROS body, battlespace C2  

---

## Progress tracker

| Wave | Status | Owner | Notes |
|------|--------|-------|-------|
| Spine DI-0…5 | **Done** | — | Foundation |
| Membrane (ACS / 3 layers / world / share) | **Done** | — | Plan v3 §0 — in code; court/mesh still ops |
| TG-0 Honesty | **Done** | | UI + C9 residual + lifecycle smoke |
| TG-1 Digest HITL | **Done** | | Consume-once + durable store |
| TG-2 Gateway | **Done** | | Tools + Talk + CONP |
| Native CNP/CONP | **Done** | | NP-0…5 |
| TG-3 Journal | **Done** | | |
| TG-4 A2A | **Done** | | INPUT_REQUIRED→resume→COMPLETED |
| TG-5 Traces | **Done** | | |
| TG-6 Tiers | **Done** | | |
| Ops soak | **Done** | | Mesh green; court fail-closed; CI smoke; dogfood script fixed |
| TG-0 UI | **Done** | | Control Start + cage ≠ audit + LAB sticky |

---

*Check the box only when the test says so. Philosophy without the Done-when is theater.*
