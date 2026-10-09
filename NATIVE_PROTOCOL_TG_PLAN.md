# Native Protocol → Dream TG Plan

**Date:** 2026-08-12  
**Status:** Folded into platform IIA (NP-0…NP-6). Partner SIL/ROS remain out of core.  
**SoT companions:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) v2 · [DREAM_CHECKLIST.md](DREAM_CHECKLIST.md) · [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md)

---

## 0. Verdict (what we already designed)

Connector already has a **native dual-stack** for agents, APIs, machines, and robots — not “MCP only.”

| Layer | Name | Crate / surface | Job |
|-------|------|-----------------|-----|
| **Spine** | **CNP** — Connector Native Protocol | `oss/connector/crates/connector-engine/src/cnp/` · `platform/server/src/services/cnp_surface.rs` · `platform/server/src/cnp/` | 7-layer cell fabric: codec → Noise → ports → routing → contracts → cognitive. Carries `sensor` / `actuation` / `tensor` / tool / knowledge payloads. MCP & A2A are **bridges** into CNP. |
| **Machine control vocabulary** | **CP/1.0 (CONP)** — Connector Protocol | `oss/connector/crates/connector-protocol/` | Universal control protocol for **robots, machines, tools, software**. Magic `CONP`. **Exactly 30 `MessageType`s** + **120 capabilities** (machine/actuator/sensor/safety/net…). |
| **Bridges** | MCP · A2A · ACP · ANP · AP2 | `oss/connector/crates/connector-protocols/` · `platform/server/src/services/protocols.rs` | External ecosystems → kernel / CNP semantics. |
| **Governed actions** | AAPI Vakya | `oss/aapi/` | Signed action grammar for agent/API effects. |
| **Multimodal fabric events** | VAC `EventType` (38) | `oss/vac/crates/vac-core/src/fabric/types.rs` | Includes perception/actuation event kinds. |

**Honesty boundary (keep):** CP/CNP are the **control-plane vocabulary + admission spine**. SIL-certified safety loops, ROS body HAL, and battlespace C2 remain **partner islands** — we do not fake them. Partner HALs speak CONP/CNP; certified e-stop stays outside Connector core.

---

## 1. The “30+ types” (found)

### 1.1 CP/1.0 — **30** wire `MessageType`s (primary match)

**File:** `oss/connector/crates/connector-protocol/src/envelope.rs`

| Group | Types |
|-------|-------|
| Handshake | `Handshake`, `HandshakeResponse`, `Ping`, `Pong` |
| Capability | `CapabilityRequest`, `CapabilityGrant`, `CapabilityRevoke`, `CapabilityDelegate` |
| Contract | `ContractOffer`, `ContractGrant`, `ContractReceipt`, `ContractRollback` |
| Command | `Command`, `CommandAck`, `Telemetry`, `Event` |
| Consensus | `ConsensusPropose`, `ConsensusPrepare`, `ConsensusPrecommit`, `ConsensusCommit` |
| Safety | `EmergencyStop`, `ClearStop`, `SafetyHeartbeat`, `SafetyFault`, `SafetyInterlock` |
| Discovery | `DiscoverRequest`, `DiscoverResponse`, `StateSync`, `AttestationRequest`, `AttestationResponse` |

Plus: `Priority` (Emergency…Bulk), `OrderingMode`, `EntityClass::{Agent, Machine, Device, Service, Sensor, Actuator, Composite}`.

### 1.2 CP capabilities — **120** (machine API surface)

**File:** `oss/connector/crates/connector-protocol/src/capability.rs`

Includes (non-exhaustive): `machine.*` (14: `move_axis`, `program_run`, `rapid`, …), `actuator.*` (10), `sensor.*` (10), `safety.*` (16), Modbus/MQTT net caps, etc. Each has `RiskLevel::{Low,Medium,High,Critical}`.

### 1.3 CNP payload kinds (~15) + VAC events (38)

- CNP: `CnpPayload::{Sensor, Actuation, Tensor, Request, Response, ToolGrant, Cognitive, …}`  
- CNP actuation: `SetVelocity`, `SetPosition`, `Gripper`, `NavigateTo`, `EmergencyStop`, `Custom`  
- VAC: `SensorReadingRecorded`, `ActuationCommandIssued`, `PerceptionOutputProduced`, …

---

## 2. Gap today (why this plan exists)

| Fact | Status |
|------|--------|
| CP/1.0 type system + unit tests | **Designed & implemented** in OSS crate |
| CNP stack types + in-process stack | **Implemented**; cross-cell mTLS not productized (`mutual_auth_product: false`) |
| Platform `GET /api/v1/cnp/overview` | **Live** |
| `platform/server` Cargo dep on `connector-protocol` | **Present** — CONP catalog + admit path on the platform IIA surface |
| CP `/protocol/*` routes | **Live** on platform (`/protocol/conp/info`, `/command`, `/message`, `/estop`) |
| TG-1 `ActionBinding` / TG-2 gateway | Wired for MCP, CONP Command/grants, CNP send **and** `POST /cnp/actuation` |
| Package pin on CONP/CNP/A2A | **Gated** on mutating drivers (lab/dev may unpackaged; EmergencyStop cut-through) |
| CapabilityGrant / ContractGrant persist | **Durable** in `conp_capability_grants_v1` / `conp_contracts_v1` |
| Partner HAL drivers (ROS/Modbus/CAN) | **Out of core** — adapters later; SIL still partner-side |
| Envoy data-plane execute / WIT component link | **Labeled non-claims** |

**Rule:** Dream waves must treat **CNP as transport spine** and **CP/1.0 as machine/API message+capability SoT** — same admission physics as tools (digest → gateway → journal → fabric → trace).

**Rule:** Dream waves must treat **CNP as transport spine** and **CP/1.0 as machine/API message+capability SoT** — same admission physics as tools (digest → gateway → journal → fabric → trace).

---

## 3. Target architecture (how native protocol sits in dream)

```text
                    ┌──────────── CONTROL ────────────┐
                    │ AutonomyGateway · digest HITL   │
                    │ Charter · applied_truth         │
                    └──────────────┬──────────────────┘
                                   │ admit A
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                        ▼
   ┌─────────────┐         ┌─────────────┐          ┌─────────────┐
   │ MCP bridge  │         │ A2A bridge  │          │ CONP ingress│
   │ (tools)     │         │ (tasks)     │          │ (machines)  │
   └──────┬──────┘         └──────┬──────┘          └──────┬──────┘
          │                       │                         │
          └───────────────────────┼─────────────────────────┘
                                  ▼
                    ┌─────────────────────────────┐
                    │ CNP spine (L1–L7)           │
                    │ sensor · actuation · tool   │
                    │ knowledge · cognitive       │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │ Partner HAL / API adapter   │  ← ROS/Modbus/HTTP machine APIs
                    │ (outside SIL core claim)    │
                    └─────────────────────────────┘
```

Every CONP `Command` / CNP `Actuation` / MCP tool becomes one **ActionBinding** with:

- `operation` = CP cap id or CNP kind (`machine.move_axis`, `cnp.actuation.set_position`, `tool.dispatch`)  
- `parameters` = canonical payload  
- `contract_digest` + `policy_version`  
- `action_digest` = sha256(canonical JSON)

Safety ambient rule (from CP design): `EmergencyStop` is always admissible for cut-through, still **digest-audited**, never silently dropped — but gateway cannot Block e-stop (special case).

---

## 4. Coding waves (use inside TG-0…TG-6)

Do **not** open a parallel greenfield. Fold native protocol into existing TG order.

### NP-0 / TG-0 — Honesty for protocol plane

- [x] `GET /runtime/intelligence-posture` includes `native_protocol: { cnp, conp }` with applied_truth (intent vs peer mTLS vs HAL present)  
- [x] Never claim “robot safety certified” from CONP taxonomy alone (`sil_certified: false`)  
- [x] Lab stub flag honesty for CNP mTLS (`CONNECTOR_CNP_ALLOW_MTLS_STUB`) surfaced in posture  

### NP-1 / TG-1 — Digest-bind CONP + CNP actions

- [x] Add `connector-protocol` path dep to `platform/server`  
- [x] `ActionBinding` helpers: `binding_for_conp_command` (+ `admit_conp_or_ask`)  
- [x] Map remaining mutating `MessageType`s (capability grants, contract grant/rollback) beyond Command/E-stop — `MessageType::is_mutating` + `POST /protocol/conp/message`  
- [x] Persist CapabilityGrant/Delegate/Revoke and ContractOffer/Grant/Rollback to `conp_capability_grants_v1` / `conp_contracts_v1`  
- [x] Unit: digest of `machine.move_axis` params A ≠ B  

### NP-2 / TG-2 — Gateway risk from CP `RiskLevel`

- [x] `admit_conp_or_ask` consumes `ProtocolCapability.risk`  
- [x] `Critical`/`High` → Ask path via gateway (unless e-stop ambient Allow)  
- [x] `EmergencyStop` → Allow + audit receipt (DecisionTrace package still TG-5)  
- [x] Wire `POST /protocol/conp/command` through `admit_conp_or_ask`  
- [x] Package pin on mutating CONP/CNP/A2A drivers (`gate_mutating_package`; EmergencyStop cut-through)  
- [x] `POST /cnp/actuation` + `POST /cnp/messages` admit `connector.cnp.actuation.v1`  
- [x] `connectorctl iia smoke [--conp]`  

### NP-3 / TG-3 — Journal machine steps

- [x] Step kinds add `conp_command` | `cnp_message`  
- [x] Idempotency key on CONP command + mission journal  
- [x] `CommandAck` stored as step output — resume must not re-fire lab HAL  

### NP-4 / TG-4 — Fabric = A2A + CNP task semantics

- [x] A2A TaskState SoT maps to CNP L6/L7 (`fabric_task::cnp_layer_semantics` + `GET /cnp/overview` bridge_map)  
- [x] Machine-facing tasks carry CONP `EntityId` + intelligence mark + grant_id (`create_machine_task`)  
- [x] Cross-machine `Command` requires grant pore (same as inter-agent) — `assert_conp_cross_machine_grant`  

### NP-5 / TG-5 — Traces include protocol evidence

- [x] `DecisionTrace` fields: `message_type`, `cnp_message_id`, `capability_id`, `gateway`, `action_digest`  
- [x] Forensic package includes decision_traces (+ CONP fields on CONP admits)  

### NP-6 / TG-6 — Isolation for machine adapters

- [x] Partner HAL processes run under DockLock / Landlock tier; posture shows HAL plane separate from SIL claim (`partner_hal::isolation_posture`)  
- [x] High-risk `machine.program_run` / `machine.rapid` prefer MicroVM or dedicated cell when tier available  

---

## 5. Minimal schemas (platform)

### 5.1 CONP action envelope (platform)

```json
{
  "schema": "connector.conp.action.v1",
  "message_type": "Command",
  "capability_id": "machine.move_axis",
  "entity_id": "conp:machine:…",
  "agent_pid": "agent_…",
  "parameters": { "axis": "X", "target_mm": 12.5 },
  "priority": "Realtime",
  "ordering": "Causal",
  "contract_digest": "…",
  "policy_version": "…"
}
```

`action_digest = sha256(canonical_json(ActionBinding from this))`.

### 5.2 CNP actuation envelope

```json
{
  "schema": "connector.cnp.actuation.v1",
  "message_id": "…",
  "from_agent": "agent_…",
  "to_agent": "agent_machine_proxy",
  "command": "SetPosition",
  "parameters": {},
  "deadline_us": null
}
```

### 5.3 Capability → gateway table (Phase A)

| RiskLevel | Default verdict | Notes |
|-----------|-----------------|-------|
| Low | Allow | Still C9 + journal if mutating |
| Medium | Allow or Ask per HitlPolicy | |
| High | Ask | Digest HITL |
| Critical | Ask | Except ambient `EmergencyStop` → Allow+trace |
| Denied by charter | Block | Never Ask |

---

## 6. API surface to add (platform)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/protocol/conp/info` | Version, 30 types, 120 caps catalog (proxy OSS types) |
| `GET /api/v1/protocol/conp/capabilities` | Filterable registry |
| `POST /api/v1/protocol/conp/command` | Digest-bound Command → gateway → CNP/HAL |
| `POST /api/v1/protocol/conp/safety/estop` | Ambient e-stop path (audited) |
| `POST /api/v1/cnp/messages` | Alias of `/cnp/actuation` (`connector.cnp.actuation.v1`) |
| `POST /api/v1/cnp/actuation` | Admit CNP actuation via ActionBinding/PATE; persist receipt; not SIL/ROS |
| `connectorctl iia smoke [--conp]` | Catalog smoke; `--conp` persists CapabilityGrant/Revoke + actuation |
| Existing `GET /api/v1/cnp/overview` | Keep as spine catalog |

OSS `connector-server` `/protocol/*` remains reference; **platform IIA path is SoT for production**.

---

## 7. Acceptance tests

| Gate | Test |
|------|------|
| Types present | Unit: `MessageType` discriminant count == 30 |
| Caps present | Unit: registry len == 120 |
| Digest bind | `machine.move_axis` param swap → consume deny |
| E-stop ambient | E-stop not Blocked by HitlPolicy::AllMaterial |
| Gateway rates | CONP Command Ask increments `autonomy_gateway.ask` |
| Journal | Crash after CommandAck → resume no second actuation |
| Honesty | Posture never claims SIL from CONP alone |
| Smoke | Extend `connectorctl iia smoke` optional `--conp` stub HAL echo |

---

## 8. Build order (next coding, after/with TG-3)

```text
1. Cargo: platform depends on connector-protocol
2. NP-1 helpers + catalog GET routes
3. NP-2 wire Command/Actuation through AutonomyGateway
4. NP-0 posture fields
5. NP-3 journal step kinds (with TG-3 MissionV1)
6. NP-4 machine tasks on fabric.task.v2
7. NP-5 traces
8. Stub HAL echo adapter (lab) — not ROS
```

---

## 9. Out of scope (do not fake)

- ISO 10218 / SIL dual-channel safety controller  
- Full ROS 2 / DDS stack as Connector core  
- Claiming CP e-stop JSON == certified safety bus  
- Battlespace C2  

Partner path: HAL process implements CONP Command/Telemetry; Connector admits + journals + traces.

---

## 10. Bottom line

We **already designed** the native protocol for machines/robots/APIs:

1. **CNP** = how cells/agents/plugins talk (spine, already on platform).  
2. **CP/1.0 CONP** = **30 message types** + **120 capabilities** for robots/machines/safety/net.  
3. Dream coding must **fuse CONP into TG-1…TG-5** the same way MCP tools were fused — digest, gateway, journal, fabric, traces — without claiming physical SIL completeness.

*Native protocol TG waves NP-0…NP-6 are folded into the platform IIA path. Partner SIL / ROS remain out of core.*
