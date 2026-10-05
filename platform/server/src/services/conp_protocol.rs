//! CP/1.0 (CONP) — platform IIA surface for robots/machines/APIs.
//!
//! Catalog of 30 MessageTypes + 120 capabilities; digest-bound Command path
//! through AutonomyGateway. Lab HAL is an echo stub — not SIL/ROS.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use connector_native_contract::PackagePin;
use connector_protocol::{
    CapabilityCategory, MessageType, ProtocolCapabilityRegistry, ALL_MESSAGE_TYPES, MAGIC, VERSION,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::PlatformRole;
use crate::kernel::action_binding::AutonomyVerdict;
use crate::kernel::mission_journal::{self, StepKind};
use crate::services::agents::caller;
use crate::state::SharedState;

fn message_type_catalog() -> Vec<Value> {
    ALL_MESSAGE_TYPES
        .iter()
        .map(|mt| {
            json!({
                "name": format!("{:?}", mt),
                "code": *mt as u8,
                "group": mt.group(),
                "safety_critical": mt.is_safety_critical(),
            })
        })
        .collect()
}

/// GET /protocol/conp/info — enterprise catalog (30 types + honesty).
pub async fn conp_info() -> Json<Value> {
    let reg = ProtocolCapabilityRegistry::with_defaults();
    Json(json!({
        "ok": true,
        "schema": "connector.conp.info.v1",
        "protocol": "CP/1.0",
        "magic": "CONP",
        "magic_bytes": MAGIC,
        "version": VERSION,
        "message_type_count": ALL_MESSAGE_TYPES.len(),
        "message_types": message_type_catalog(),
        "capability_count": reg.count(),
        "entity_classes": entity_class_catalog(),
        "identity_proofs": ["dice", "spiffe", "self_signed"],
        "native_spine": "CNP",
        "world_connect": "/api/v1/protocol/world",
        "honesty": "Taxonomy + admission path — not a SIL-certified safety bus or ROS body HAL. Partner HALs speak CONP; e-stop here is control-plane ambient Allow+audit.",
        "routes": {
            "world": "/api/v1/protocol/world",
            "capabilities": "/api/v1/protocol/conp/capabilities",
            "command": "POST /api/v1/protocol/conp/command",
            "estop": "POST /api/v1/protocol/conp/estop",
            "estop_alias": "POST /api/v1/protocol/conp/safety/estop",
            "message": "POST /api/v1/protocol/conp/message",
            "cnp_overview": "/api/v1/cnp/overview",
            "cnp_actuation": "POST /api/v1/cnp/actuation",
        },
    }))
}

fn entity_class_catalog() -> Vec<Value> {
    use connector_protocol::EntityClass;
    [
        EntityClass::Agent,
        EntityClass::Machine,
        EntityClass::Device,
        EntityClass::Service,
        EntityClass::Sensor,
        EntityClass::Actuator,
        EntityClass::Composite,
    ]
    .into_iter()
    .map(|c| {
        json!({
            "id": c.to_string(),
            "default_sil": format!("{:?}", c.default_sil()),
            "requires_realtime": c.requires_realtime(),
        })
    })
    .collect()
}

/// GET /protocol/world — operator map: any agent → secure CNP/CONP → world types + cpkg + audit.
pub async fn world_connect() -> Json<Value> {
    let reg = ProtocolCapabilityRegistry::with_defaults();
    let world_targets = world_target_catalog();
    Json(json!({
        "ok": true,
        "schema": "connector.protocol.world.v1",
        "summary": "Build any chartered agent; connect to APIs, networks, robots, IoT, and services over CNP spine + CONP vocabulary; ship custom logic as .cpkg; governed effects are audited.",
        "agent_model": {
            "any_kind": true,
            "how": "Register agent → charter (capabilities/network/HITL) → activate → Talk/tools/CONP",
            "identity": "IntelligencePrincipalV2 + DID-style EntityId; proofs: dice | spiffe | self_signed",
            "charter_is_cage": true,
        },
        "secure_connect": {
            "spine": "CNP (7-layer: codec → encrypted transport → ports → routing → contracts → cognitive)",
            "machine_vocabulary": "CP/1.0 CONP — 30 MessageTypes + 120 capabilities",
            "admission": "Same AutonomyGateway as tools (Allow / Ask / Block + digest HITL)",
            "keys_out_of_cage": true,
            "mtls_product": "Cross-cell mTLS productization still ops; lab stub flagged in posture",
            "partner_hal": "ROS/Modbus/CAN/MQTT adapters speak CONP — SIL body loops stay partner-side",
        },
        "entity_classes": entity_class_catalog(),
        "message_type_count": ALL_MESSAGE_TYPES.len(),
        "capability_count": reg.count(),
        "capability_categories": [
            "agent","machine","device","sensor","actuator","net","fs","proc","store","crypto","gpu","safety"
        ],
        "world_target_count": world_targets.len(),
        "world_targets": world_targets,
        "cpkg_custom_logic": {
            "what": "Ship your own agent/plugin logic as signed .cpkg (Hub install / connectorctl hub|plugin)",
            "uses_connector": [
                "memory (/api/v1/memory/*)",
                "knowledge / RAG / knot",
                "Talk LLM gateway (/v1/chat/completions with agent_pid)",
                "tools / MCP",
                "fabric / multiagent grants",
                "cluster / mesh cells",
                "security rings / DockLock cage",
                "HITL + decision traces",
            ],
            "run": "connectorctl plugin run --dev <vendor/slug> (subprocess | docker_lab | microvm | wasm)",
            "harden": "Ambient shell / unrestricted net refused under intelligence harden",
            "audit": "Calls through platform APIs with agent_pid inherit charter + DecisionTrace + audit",
        },
        "audit": {
            "claim": "Governed effect paths are audited — not every internal kernel log line",
            "per_agent": [
                "DecisionTraceV1 (Talk, tools, CONP, fabric) with hash chain",
                "Kernel audit activity stream",
                "Mission journal steps",
                "Forensic package download + verify-export",
                "Court-readiness (green only with WC+CFNI backends)",
            ],
            "routes": {
                "activity": "GET /api/v1/agents/:pid/activity",
                "traces": "GET /api/v1/agents/:pid/traces (or forensic package)",
                "cage_runtime": "GET /api/v1/agents/:pid/cage-runtime",
                "package": "forensic package download",
                "court": "GET /api/v1/forensics/court-readiness?agent_pid=",
            },
            "honesty": "100% of charter-gated effects (Talk/tools/CONP/fabric/share/signal) leave traces when they hit the membrane. Custom .cpkg code that bypasses platform APIs is out of band — refuse ambient shell under harden.",
        },
        "operator_quickstart": [
            "1. POST /api/v1/intelligence/apply with IntelligenceSpec (parameters→skills→knowledge→limits→portals→rules) — ~5 min",
            "Or: register + POST /agents/:pid/setup with skills/portals/rules/knowledge (enhances existing setup)",
            "2. Link LLM; Start from Control",
            "3. Connect machines via CONP command (or MCP/A2A) — bound skills + charter gate",
            "4. Optional .cpkg for custom runtime logic as that agent_pid",
            "5. Download forensic package when you need proof",
        ],
        "routes": {
            "intelligence_apply": "POST /api/v1/intelligence/apply",
            "intelligence_schema": "GET /api/v1/intelligence/spec-schema",
            "conp_info": "/api/v1/protocol/conp/info",
            "conp_capabilities": "/api/v1/protocol/conp/capabilities",
            "conp_command": "POST /api/v1/protocol/conp/command",
            "cnp_overview": "/api/v1/cnp/overview",
            "posture": "/api/v1/runtime/intelligence-posture",
        },
    }))
}

/// 20+ world connection targets (entity classes + bridges + common IoT/API shapes).
fn world_target_catalog() -> Vec<Value> {
    let rows: &[(&str, &str, &str)] = &[
        ("agent", "entity", "Chartered intelligence principal"),
        ("machine", "entity", "CNC / industrial machine (CONP)"),
        ("device", "entity", "Generic device / IoT endpoint"),
        ("service", "entity", "Software service / microservice"),
        ("sensor", "entity", "Sensor / telemetry source"),
        ("actuator", "entity", "Actuator / effector"),
        ("composite", "entity", "Multi-part robot or cell"),
        (
            "http_api",
            "bridge",
            "Any HTTP API via gateway / Relay / MCP",
        ),
        (
            "openai_compat",
            "bridge",
            "OpenAI-compatible clients → /v1/chat/completions",
        ),
        (
            "anthropic_compat",
            "bridge",
            "Anthropic-compatible gateway surface",
        ),
        ("mcp_tool", "bridge", "MCP tool bridges"),
        ("a2a_task", "bridge", "A2A cross-vendor tasks"),
        ("acp", "bridge", "ACP protocol bridge"),
        ("anp", "bridge", "ANP protocol bridge"),
        ("ap2", "bridge", "AP2 protocol bridge"),
        (
            "mqtt",
            "cap_net",
            "MQTT via CONP net.* capabilities + partner HAL",
        ),
        ("modbus", "cap_net", "Modbus via CONP net.* + partner HAL"),
        (
            "robot_hal",
            "partner",
            "Partner ROS/body HAL speaking CONP (not SIL core)",
        ),
        (
            "iot_endpoint",
            "partner",
            "IoT gateways as Device/Sensor EntityId",
        ),
        ("network_peer", "cnp", "CNP L5 cross-cell / mesh peer"),
        ("cluster_cell", "cnp", "Cluster / multi-cell fabric"),
        (
            "webhook",
            "bridge",
            "Inbound/outbound webhooks under charter",
        ),
        (
            "cpkg_plugin",
            "runtime",
            "Custom .cpkg logic in DockLock cage",
        ),
        (
            "knowledge_plane",
            "platform",
            "Memory / RAG / knot knowledge APIs",
        ),
        (
            "security_plane",
            "platform",
            "Admission, HITL, DockLock, matrix mark cut",
        ),
    ];
    rows.iter()
        .map(|(id, kind, summary)| json!({ "id": id, "kind": kind, "summary": summary }))
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct CapQuery {
    pub category: Option<String>,
    pub prefix: Option<String>,
}

/// GET /protocol/conp/capabilities
pub async fn conp_capabilities(Query(q): Query<CapQuery>) -> Json<Value> {
    let reg = ProtocolCapabilityRegistry::with_defaults();
    let mut caps: Vec<Value> = reg
        .list_all()
        .into_iter()
        .filter(|c| {
            if let Some(ref cat) = q.category {
                let want = cat.to_ascii_lowercase();
                let got = format!("{:?}", c.category).to_ascii_lowercase();
                if got != want {
                    return false;
                }
            }
            if let Some(ref p) = q.prefix {
                if !c.id.starts_with(p) {
                    return false;
                }
            }
            true
        })
        .map(|c| {
            json!({
                "id": c.id,
                "category": c.category,
                "risk": c.risk,
                "description": c.description,
                "min_sil": format!("{:?}", c.min_sil),
                "requires_realtime": c.requires_realtime,
            })
        })
        .collect();
    // Stable for UI
    caps.sort_by(|a, b| {
        a.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("id").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({
        "ok": true,
        "schema": "connector.conp.capabilities.v1",
        "count": caps.len(),
        "registry_total": reg.count(),
        "categories": [
            "agent","machine","device","sensor","actuator","net","fs","proc","store","crypto","gpu","safety"
        ],
        "capabilities": caps,
        "filter": { "category": q.category, "prefix": q.prefix },
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConpCommandBody {
    pub agent_pid: String,
    pub capability_id: String,
    pub entity_id: String,
    #[serde(default)]
    pub parameters: Value,
    /// Optional mission for TG-3 journal / idempotent resume.
    pub mission_id: Option<String>,
    pub idempotency_key: Option<String>,
    /// CP/1.0 MessageType. Defaults to Command. Grants/contracts are mutating but do not move HAL.
    #[serde(default)]
    pub message_type: Option<String>,
    /// World grant pore id for machine-facing fabric tasks (NP-4).
    #[serde(default)]
    pub grant_id: Option<String>,
    /// Lab-only echo HAL. Default **false** — must set `lab_echo_hal=true` *and*
    /// `CONNECTOR_CONP_LAB_ECHO=1` outside productionish, or use partner/microVM HAL.
    #[serde(default)]
    pub lab_echo_hal: bool,
    /// Partner SIL safe-state attestation token (`sil.v1|entity|exp|sig`).
    #[serde(default)]
    pub sil_attestation: Option<String>,
    /// AppPackageV2 pin — required for mutating CONP outside lab/dev.
    #[serde(default)]
    pub package: Option<PackagePin>,
}

fn dispatch_hal_via_landlock_child(
    state: &crate::state::PlatformState,
    body: &ConpCommandBody,
    command_id: &str,
    action_digest: &str,
) -> (bool, Value) {
    let Some(endpoint) = crate::kernel::partner_hal::partner_endpoint() else {
        return (
            false,
            json!({
                "hal": "not_configured",
                "error": "partner_hal_url_unset",
            }),
        );
    };
    let (host, port) = match crate::pore_worker::parse_url_host_port(&endpoint) {
        Ok(v) => v,
        Err(e) => {
            return (
                false,
                json!({"hal": "partner_failed", "error": e}),
            )
        }
    };
    let address = if body.entity_id.trim().is_empty() {
        endpoint.clone()
    } else {
        body.entity_id.clone()
    };
    let envelope = json!({
        "schema": "connector.conp.partner_hal.v1",
        "protocol": "CP/1.0",
        "message_type": "Command",
        "command_id": command_id,
        "capability_id": body.capability_id,
        "entity_id": body.entity_id,
        "parameters": body.parameters,
        "action_digest": action_digest,
    });
    match crate::kernel::landlock_child::tcp_send(
        state,
        &body.agent_pid,
        &address,
        &host,
        port,
        envelope,
    ) {
        Ok(receipt) => (
            true,
            json!({
                "hal": "landlock_child",
                "command_id": command_id,
                "pore": receipt,
                "honesty": "Partner HAL TCP ran in dest-pinned Landlock child — not platform PID, not SIL",
            }),
        ),
        Err(e) => (
            false,
            json!({
                "hal": "landlock_child_failed",
                "command_id": command_id,
                "error": e,
            }),
        ),
    }
}

fn lab_echo_allowed() -> bool {
    match std::env::var("CONNECTOR_CONP_LAB_ECHO") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
                && !crate::connector_profile::is_productionish_env()
        }
        Err(_) => false,
    }
}

fn partner_hal_configured() -> bool {
    crate::kernel::partner_hal::configured_kind().is_some()
        && crate::kernel::partner_hal::partner_endpoint().is_some()
}

fn parse_conp_message_type(raw: Option<&str>) -> Result<MessageType, Json<Value>> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(MessageType::Command),
        Some(s) => MessageType::parse(s).ok_or_else(|| {
            Json(json!({
                "ok": false,
                "error": "unknown_message_type",
                "status": 400,
                "got": s,
                "honesty": "NP-1 — mutating types (CapabilityGrant/Revoke/Delegate, ContractGrant/Rollback) must use catalog names",
            }))
        }),
    }
}

fn dispatch_partner_or_echo(
    state: &crate::state::PlatformState,
    body: &ConpCommandBody,
    command_id: &str,
    action_digest: &str,
) -> (bool, Value) {
    if body.lab_echo_hal && lab_echo_allowed() {
        return (
            true,
            json!({
                "hal": "lab_echo",
                "command_id": command_id,
                "capability_id": body.capability_id,
                "entity_id": body.entity_id,
                "accepted": true,
                "echo_parameters": body.parameters,
                "honesty": "Lab stub HAL — replace with partner CONP adapter; not ROS/SIL",
            }),
        );
    }
    if partner_hal_configured() {
        if let Err(e) = crate::kernel::partner_hal::assert_dispatch_isolation() {
            return (
                false,
                json!({
                    "hal": "partner_isolation_denied",
                    "command_id": command_id,
                    "error": e,
                    "status": crate::kernel::partner_hal::status(),
                    "honesty": "NP-6 — partner HAL refused: DockLock/Landlock fail-closed without kernel ABI",
                }),
            );
        }
        if crate::kernel::landlock_child::enforced() {
            return dispatch_hal_via_landlock_child(state, body, command_id, action_digest);
        }
        return match crate::kernel::partner_hal::dispatch_conp_command(
            command_id,
            &body.capability_id,
            &body.entity_id,
            &body.parameters,
            action_digest,
        ) {
            Ok(receipt) => (true, receipt),
            Err(e) => (
                false,
                json!({
                    "hal": "partner_failed",
                    "command_id": command_id,
                    "error": e,
                    "status": crate::kernel::partner_hal::status(),
                    "honesty": "T6 — partner HAL dial/write failed; SIL still partner-side",
                }),
            ),
        };
    }
    (
        false,
        json!({
            "hal": "not_configured",
            "command_id": command_id,
            "error": "partner_hal_required",
            "honesty": "T6 — lab echo disabled under harden; set CONNECTOR_CONP_PARTNER_HAL / microVM world channel, or CONNECTOR_CONP_LAB_ECHO=1 in lab only",
        }),
    )
}

/// POST /protocol/conp/message — same admission as Command for remaining mutating MessageTypes.
pub async fn conp_message(
    state: State<SharedState>,
    headers: HeaderMap,
    body: Json<ConpCommandBody>,
) -> Json<Value> {
    conp_command(state, headers, body).await
}

/// POST /protocol/conp/command — digest-bound machine command.
pub async fn conp_command(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ConpCommandBody>,
) -> Json<Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let _ = user_id;

    if body.agent_pid.trim().is_empty() || body.capability_id.trim().is_empty() {
        return Json(
            json!({"ok": false, "error": "agent_pid_and_capability_id_required", "status": 400}),
        );
    }

    // Membrane FC under harden
    if let Err(e) =
        crate::kernel::membrane_posture::assert_membrane_ready_for_effects(&body.agent_pid)
    {
        return Json(e);
    }

    // P2: governed_effect shim (parity with Talk/MCP) before AutonomyGateway.
    let conp_ns = format!("conp/{}", body.capability_id);
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        &body.agent_pid,
        &conp_ns,
        crate::services::admission::AdmissionOp::ConpCommand {
            capability_id: body.capability_id.clone(),
            entity_id: body.entity_id.clone(),
        },
        Some(&body.capability_id),
    ) {
        return Json(crate::substrate::governed_effect::denial_json(&err));
    }

    let message_type = match parse_conp_message_type(body.message_type.as_deref()) {
        Ok(mt) => mt,
        Err(resp) => return resp,
    };
    if message_type.is_mutating() && body.capability_id.trim().is_empty() {
        return Json(json!({
            "ok": false,
            "error": "agent_pid_and_capability_id_required",
            "status": 400,
        }));
    }
    // Protocol driver: PATE ATU + native envelope (keeps existing HAL path).
    let (driver, atu) = match crate::substrate::protocol_drivers::admit_conp_command(
        &state,
        &body.agent_pid,
        &body.capability_id,
        &body.entity_id,
        &body.parameters,
        message_type,
        body.mission_id.clone(),
        body.package.clone(),
    ) {
        Ok(v) => v,
        Err(e) => {
            return Json(crate::substrate::protocol_drivers::admit_denied_json(
                "conp", &e,
            ));
        }
    };
    let atu = atu;
    let _ = driver;
    let decision = atu.autonomy.clone().unwrap_or_else(|| {
        crate::kernel::action_binding::AutonomyDecision {
            schema: crate::kernel::action_binding::AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: crate::kernel::action_binding::AutonomyVerdict::Allow,
            reason_code: "pate_conp".into(),
            action_digest: atu.action_digest.clone(),
            policy_version: "1".into(),
            risk_class: atu.tool_footprint.risk_class.clone(),
        }
    });

    // CONP DNA honesty (A25 / S20): mint+assert when DNA required; lab echo stays labeled.
    if let Err(e) = crate::substrate::packet_dna::mint_require_and_log(
        state.as_ref(),
        &body.agent_pid,
        "conp.command",
        &body.capability_id,
        &body.parameters,
        &body.parameters,
    ) {
        if crate::substrate::packet_dna::dna_required() {
            return Json(json!({
                "ok": false,
                "error": "packet_dna_required",
                "denial_reason": e,
                "status": 403,
                "honesty": "CONP outbound requires Packet DNA under CONNECTOR_PACKET_DNA_REQUIRE",
            }));
        }
    }

    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        &body.agent_pid,
        "conp.command",
        true,
        &json!({ "capability_id": body.capability_id }),
    );

    // TG-3: idempotent journal when mission provided
    let idem = body
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("conp:{}:{}", body.capability_id, decision.action_digest));
    let mut step_id: Option<String> = None;
    if let Some(ref mid) = body.mission_id {
        if let Some(done) =
            mission_journal::find_completed_by_idempotency(state.as_ref(), mid, &idem)
        {
            return Json(json!({
                "ok": true,
                "schema": "connector.conp.command_ack.v1",
                "message_type": "CommandAck",
                "replayed": true,
                "action_digest": decision.action_digest,
                "gateway": { "verdict": "allow", "reason_code": "journal_replay" },
                "step": done,
                "honesty": "TG-3 — completed idempotency_key; HAL not re-invoked",
            }));
        }
        match mission_journal::begin_step_detailed(
            state.as_ref(),
            mid,
            &body.agent_pid,
            StepKind::ConpCommand,
            &idem,
            &json!({
                "capability_id": body.capability_id,
                "entity_id": body.entity_id,
                "parameters": body.parameters,
            }),
            Some(json!({
                "message_type": format!("{:?}", message_type),
                "capability_id": body.capability_id,
                "action_digest": decision.action_digest,
            })),
        ) {
            Ok((s, outcome)) => {
                use mission_journal::BeginOutcome;
                match outcome {
                    BeginOutcome::ExistingCompleted => {
                        return Json(json!({
                            "ok": true,
                            "schema": "connector.conp.command_ack.v1",
                            "replayed": true,
                            "step": s,
                            "action_digest": decision.action_digest,
                        }));
                    }
                    BeginOutcome::ExistingInFlight => {
                        return Json(json!({
                            "ok": false,
                            "error": "mission_step_not_reentrant",
                            "status": 409,
                            "step": s,
                            "honesty": "T4 — Pending/Failed CONP step after restart must not re-invoke HAL",
                        }));
                    }
                    BeginOutcome::New => {
                        step_id = Some(s.step_id);
                    }
                }
            }
            Err(e) => {
                return Json(json!({
                    "ok": false,
                    "error": e,
                    "status": 400
                }));
            }
        }
    }

    // ARC-5: conp.command lease-mediated when CONNECTOR_ARC_LEASE=1.
    let mut arc_lease = match crate::substrate::arc::lease::LeaseSinkGuard::begin_sink(
        &body.agent_pid,
        &atu.action_digest,
        &atu.task_id,
        atu.iac_epoch,
        crate::substrate::arc::lease::SINK_CONP_COMMAND,
    ) {
        Ok(g) => g,
        Err(e) => {
            return Json(json!({
                "ok": false,
                "error": "arc_lease_required",
                "denial_reason": e.human_readable,
                "hint": e.hint,
                "status": 403,
                "honesty": "NoLease ⇒ NoEffect on conp.command when CONNECTOR_ARC_LEASE=1",
            }));
        }
    };

    // Physical world channels (robot / IoT / machine / …) leave only via microVM.
    let channel_kind = if message_type.dispatches_hal() {
        match crate::substrate::microvm_tool_plane::assert_world_channel_via_microvm(
            state.as_ref(),
            &body.agent_pid,
            &body.entity_id,
            &body.capability_id,
        ) {
            Ok(k) => k,
            Err(e) => {
                if crate::substrate::probabilistic_llm::distrust_enforced()
                    && e.get("denial_reason").and_then(|v| v.as_str())
                        == Some("in_process_effect_path")
                {
                    return Json(crate::substrate::probabilistic_llm::quarantine_for_bypass(
                        &state,
                        &body.agent_pid,
                        "conp_channel_not_in_microvm",
                        e.get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("CONP channel refused outside microVM"),
                    ));
                }
                return Json(e);
            }
        }
    } else {
        crate::substrate::microvm_tool_plane::classify_address_channel(&body.entity_id, None)
    };

    // T6 — SIL safety interlock before any physical / partner HAL effect.
    let sil = if message_type.dispatches_hal() {
        match crate::kernel::sil_interlock::assert_sil_safe_for_dispatch(
            &body.entity_id,
            body.sil_attestation.as_deref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                if let (Some(mid), Some(sid)) = (body.mission_id.as_ref(), step_id.as_ref()) {
                    let _ = mission_journal::fail_step(state.as_ref(), mid, sid, &e);
                }
                return Json(json!({
                    "ok": false,
                    "error": e,
                    "status": 403,
                    "sil": crate::kernel::sil_interlock::status(),
                    "honesty": "SIL interlock refused dispatch — partner safety body must attest safe-state",
                }));
            }
        }
    } else {
        json!({
            "skipped": true,
            "reason": "control_plane_message",
            "message_type": format!("{:?}", message_type),
        })
    };

    let prefer_microvm = crate::kernel::partner_hal::prefer_microvm_cell(&body.capability_id)
        || (channel_kind.is_physical_world()
            && crate::substrate::microvm_tool_plane::world_channel_via_microvm());
    let command_id = format!("cmd_{}", Uuid::new_v4());
    let (ok, mut ack) = if !message_type.dispatches_hal() {
        (
            true,
            json!({
                "hal": "none",
                "command_id": command_id,
                "capability_id": body.capability_id,
                "entity_id": body.entity_id,
                "message_type": format!("{:?}", message_type),
                "accepted": true,
                "honesty": "NP-1 — capability/contract mutating types are digest-bound on the admission plane; they do not dispatch partner HAL",
            }),
        )
    } else if prefer_microvm {
        match crate::substrate::microvm_tool_plane::invoke_conp_channel_in_microvm(
            &state,
            &body.agent_pid,
            &body.capability_id,
            &body.entity_id,
            &body.parameters,
            &decision.action_digest,
        )
        .await
        {
            Ok(receipt) => (
                true,
                json!({
                    "hal": "microvm_channel",
                    "command_id": command_id,
                    "capability_id": body.capability_id,
                    "entity_id": body.entity_id,
                    "channel": channel_kind.as_str(),
                    "accepted": true,
                    "microvm": receipt,
                    "honesty": "NP-6 — high-risk machine.program_run/rapid and physical CONP go via microVM, not host HAL",
                }),
            ),
            Err(e) => {
                if crate::connector_profile::is_productionish_env()
                    || crate::kernel::partner_hal::prefer_microvm_cell(&body.capability_id)
                {
                    (
                        false,
                        json!({
                            "hal": "microvm_channel_failed",
                            "command_id": command_id,
                            "error": e,
                            "honesty": "NP-6 — high-risk CONP refused without microVM / dedicated cell",
                        }),
                    )
                } else if channel_kind.is_physical_world()
                    && crate::substrate::microvm_tool_plane::world_channel_via_microvm()
                {
                    (
                        false,
                        json!({
                            "hal": "microvm_channel_failed",
                            "command_id": command_id,
                            "error": e,
                            "honesty": "Physical CONP refused — microVM channel required",
                        }),
                    )
                } else {
                    dispatch_partner_or_echo(state.as_ref(), &body, &command_id, &decision.action_digest)
                }
            }
        }
    } else {
        dispatch_partner_or_echo(state.as_ref(), &body, &command_id, &decision.action_digest)
    };
    if let Some(obj) = ack.as_object_mut() {
        obj.insert("sil".into(), sil);
    }
    if let (Some(mid), Some(sid)) = (body.mission_id.as_ref(), step_id.as_ref()) {
        if ok {
            let _ = mission_journal::complete_step(state.as_ref(), mid, sid, ack.clone());
        } else {
            let _ = mission_journal::fail_step(state.as_ref(), mid, sid, "partner_hal_required");
        }
    }
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &atu,
        if ok { "ok" } else { "failed" },
        json!({
            "capability_id": body.capability_id,
            "command_id": command_id,
            "ack": ack,
        }),
    );
    if ok {
        arc_lease.success();
    } else {
        arc_lease.fail();
    }

    // Persist command receipt for forensics
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{}_{}", chrono::Utc::now().timestamp_millis(), command_id);
        let _ = es.folder_put(
            "conp_command_receipts",
            &key,
            &json!({
                "schema": "connector.conp.receipt.v1",
                "command_id": command_id,
                "agent_pid": body.agent_pid,
                "capability_id": body.capability_id,
                "entity_id": body.entity_id,
                "action_digest": decision.action_digest,
                "gateway_reason": decision.reason_code,
                "ack": ack,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }

    // P2: CNP WireEnvelope + packet DNA commit; AAPI audit sidecar (HAL path unchanged).
    let mut cnp_commit = json!(null);
    let mut aapi_audit = json!(null);
    let mut fabric_task = json!(null);
    if ok {
        cnp_commit = crate::substrate::cnp_commit::commit_conp_to_cnp(
            &state,
            &body.agent_pid,
            &body.capability_id,
            &body.entity_id,
            &decision.action_digest,
            &command_id,
            &ack,
        );
        aapi_audit = crate::substrate::aapi_bridge::record_atu_commit(
            &state,
            &atu,
            "ok",
            vec![decision.action_digest.clone(), command_id.clone()],
        );
        if message_type.dispatches_hal() {
            let gid = body
                .grant_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| {
                    crate::kernel::world_gateway::grant_key(&body.agent_pid, &body.entity_id)
                });
            if let Ok(t) = crate::kernel::fabric_task::create_machine_task(
                state.as_ref(),
                &body.agent_pid,
                &body.entity_id,
                json!({
                    "command_id": command_id,
                    "capability_id": body.capability_id,
                    "message_type": format!("{:?}", message_type),
                    "action_digest": decision.action_digest,
                }),
                None,
                body.mission_id.as_deref(),
                Some(gid.as_str()),
                Some(body.entity_id.as_str()),
            ) {
                fabric_task = crate::kernel::fabric_task::task_json(&t);
            }
        }
    }

    let mut stored_authority = json!(null);
    if ok {
        match crate::kernel::conp_authority::apply_admitted_message(
            state.as_ref(),
            message_type,
            &body.agent_pid,
            &body.entity_id,
            &body.capability_id,
            body.grant_id.as_deref(),
            &body.parameters,
            &decision.action_digest,
        ) {
            Ok(Some(v)) => {
                stored_authority = v;
                if let Some(obj) = ack.as_object_mut() {
                    obj.insert("stored".into(), stored_authority.clone());
                }
            }
            Ok(None) => {}
            Err(e) => {
                return Json(json!({
                    "ok": false,
                    "error": "conp_authority_store_failed",
                    "denial_reason": e,
                    "status": 500,
                    "honesty": "CapabilityGrant/ContractGrant must persist after admit; HAL was not dispatched for control-plane types",
                }));
            }
        }
    }

    Json(json!({
        "ok": ok,
        "schema": "connector.conp.command_ack.v1",
        "message_type": "CommandAck",
        "command_id": command_id,
        "action_digest": decision.action_digest,
        "gateway": {
            "verdict": match decision.verdict {
                AutonomyVerdict::Allow => "allow",
                AutonomyVerdict::Ask => "ask",
                AutonomyVerdict::Block => "block",
            },
            "reason_code": decision.reason_code,
            "risk_class": decision.risk_class,
        },
        "capability_id": body.capability_id,
        "entity_id": body.entity_id,
        "mission_id": body.mission_id,
        "step_id": step_id,
        "ack": ack,
        "cnp_commit": cnp_commit,
        "aapi_audit": aapi_audit,
        "fabric_task": fabric_task,
        "stored": stored_authority,
        "conp_message_type": format!("{:?}", message_type),
        "operator_plane": true,
        "sil_certified": false,
    }))
}

#[derive(Debug, Deserialize)]
pub struct EstopBody {
    pub agent_pid: String,
    pub entity_id: Option<String>,
    pub reason: Option<String>,
    pub mission_id: Option<String>,
}

/// POST /protocol/conp/safety/estop — ambient Allow + audit (not Ask-delayed).
pub async fn conp_estop(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<EstopBody>,
) -> Json<Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Operator.rank() {
        return Json(json!({"ok": false, "error": "operator_required", "status": 403}));
    }

    let entity = body
        .entity_id
        .unwrap_or_else(|| "conp:machine:broadcast".into());
    let params = json!({
        "reason": body.reason.clone().unwrap_or_else(|| format!("estop by {user_id}")),
        "scope": "control_plane",
    });

    // Grant/ticket mint for audit — e-stop stays ambient Allow in ActionBinding/PATE.
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        &body.agent_pid,
        "conp/safety.emergency_stop",
        crate::services::admission::AdmissionOp::ConpCommand {
            capability_id: "safety.emergency_stop".into(),
            entity_id: entity.clone(),
        },
        body.reason.as_deref(),
    ) {
        return Json(crate::substrate::governed_effect::denial_json(&err));
    }

    let decision = match crate::substrate::pate::admit_conp(
        &state,
        &body.agent_pid,
        "safety.emergency_stop",
        &entity,
        &params,
        MessageType::EmergencyStop,
        None,
    ) {
        Ok(atu) => {
            let digest = atu.action_digest.clone();
            atu.autonomy.unwrap_or_else(|| {
                crate::kernel::action_binding::AutonomyDecision {
                    schema: crate::kernel::action_binding::AUTONOMY_GATEWAY_SCHEMA.into(),
                    verdict: crate::kernel::action_binding::AutonomyVerdict::Allow,
                    reason_code: "estop_ambient_allow".into(),
                    action_digest: digest,
                    policy_version: "1".into(),
                    risk_class: "estop".into(),
                }
            })
        }
        Err(e) => {
            return Json(json!({
                "ok": false,
                "error": e.denial_reason.slug(),
                "denial_reason": e.human_readable,
                "status": 403,
            }));
        }
    };

    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        &body.agent_pid,
        "conp.estop",
        true,
        &json!({ "entity": entity }),
    );

    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("estop_{}", chrono::Utc::now().timestamp_millis());
        let _ = es.folder_put(
            "conp_safety_events",
            &key,
            &json!({
                "schema": "connector.conp.estop.v1",
                "agent_pid": body.agent_pid,
                "entity_id": entity,
                "action_digest": decision.action_digest,
                "decided_by": user_id,
                "reason": params.get("reason"),
                "at_ms": chrono::Utc::now().timestamp_millis(),
                "honesty": "Control-plane e-stop audit — not dual-channel SIL hardware",
            }),
        );
    }

    if let Some(ref mid) = body.mission_id {
        let idem = format!("estop:{}", decision.action_digest);
        if let Ok(s) = mission_journal::begin_step(
            state.as_ref(),
            mid,
            &body.agent_pid,
            StepKind::ConpCommand,
            &idem,
            &params,
            Some(json!({"message_type": "EmergencyStop"})),
        ) {
            let _ = mission_journal::complete_step(
                state.as_ref(),
                mid,
                &s.step_id,
                json!({"estop": true, "action_digest": decision.action_digest}),
            );
        }
    }

    Json(json!({
        "ok": true,
        "schema": "connector.conp.estop_ack.v1",
        "message_type": "EmergencyStop",
        "action_digest": decision.action_digest,
        "gateway_reason": decision.reason_code,
        "entity_id": entity,
        "sil_certified": false,
        "honesty": "Ambient control-plane e-stop recorded; partner safety PLC remains source of truth for SIL",
    }))
}

/// Compile-time-ish category list helper for docs (unused warning suppress via test).
#[allow(dead_code)]
fn _categories() -> &'static [CapabilityCategory] {
    &[
        CapabilityCategory::Agent,
        CapabilityCategory::Machine,
        CapabilityCategory::Device,
        CapabilityCategory::Sensor,
        CapabilityCategory::Actuator,
        CapabilityCategory::Net,
        CapabilityCategory::Fs,
        CapabilityCategory::Proc,
        CapabilityCategory::Store,
        CapabilityCategory::Crypto,
        CapabilityCategory::Gpu,
        CapabilityCategory::Safety,
    ]
}
