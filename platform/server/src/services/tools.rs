use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};

/// JSON surface returned on successful tool calls — shared by `mcp_invoke` and `mcp_invoke_scoped`.
fn mcp_execution_isolation_block() -> serde_json::Value {
    serde_json::json!({
        "kernel_operation": "ToolDispatch",
        "semantic_input_gate_threshold": 0.75,
        "audit_trail": "Kernel audit + GET /api/v1/actionlog/actions",
        "contract_binding": "CLS + agent contract routes constrain capability — see /api/v1/cls/*",
        "os_process_model": if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced() {
            "Local tool I/O (shell/filesystem/exec) runs inside microVM. Remote MCP may use host HTTPS broker only when CONNECTOR_ALLOW_HOST_MCP_BROKER=1."
        } else {
            "MCP ToolDispatch runs inside the connector-platform OS process on this host; remote MCP bridges are still network-separated processes you operate."
        },
        "tools_in_microvm": crate::substrate::microvm_tool_plane::tools_in_microvm_enforced(),
        "control_plane_pid": std::process::id(),
        "stability": "Audit-ordered kernel transitions + Knot serial windows + budget groups — enterprise hardening adds systemd hardening, separate bridge hosts, and network policy.",
        "runtime_enforcement_surface": "GET /api/v1/runtime/enforcement (live host telemetry + agent lifecycle)",
    })
}

/// `tool_id` as `bridge_id:tool_name`, or bare `tool_name` (bridge = "default").
pub(crate) fn parse_bridge_and_tool(tool_id: &str) -> (String, String) {
    let tool_id = tool_id.trim();
    if let Some((a, b)) = tool_id.split_once(':') {
        let bridge = a.trim();
        let tool = b.trim();
        if bridge.is_empty() {
            (
                "default".to_string(),
                if tool.is_empty() {
                    tool_id.to_string()
                } else {
                    tool.to_string()
                },
            )
        } else if tool.is_empty() {
            (bridge.to_string(), String::new())
        } else {
            (bridge.to_string(), tool.to_string())
        }
    } else {
        ("default".to_string(), tool_id.to_string())
    }
}

/// Optional TG-3 mission journaling for MCP tool dispatch.
pub struct ToolMissionOpts<'a> {
    pub mission_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

/// Shared async entry: route local I/O into microVM, then host MCP dispatch.
pub async fn dispatch_mcp_tool(
    state: &SharedState,
    bridge_id: &str,
    tool_name: &str,
    agent_pid: &str,
    input: &serde_json::Value,
    reason: String,
    mission: ToolMissionOpts<'_>,
) -> Result<serde_json::Value, serde_json::Value> {
    if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced()
        && agent_pid.is_empty()
    {
        return Err(serde_json::json!({
            "error": "agent_pid required",
            "denial_reason": "validation_error",
        }));
    }
    if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced() {
        match crate::substrate::microvm_tool_plane::assert_preflight(
            state.as_ref(),
            agent_pid,
            bridge_id,
            tool_name,
        ) {
            Ok(plan @ crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmIo)
            | Ok(plan @ crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmChannel) => {
                let atu = match crate::substrate::pate::admit_tool(
                    state,
                    agent_pid,
                    bridge_id,
                    tool_name,
                    input,
                    mission.mission_id.map(|s| s.to_string()),
                ) {
                    Ok(atu)
                        if crate::substrate::pate::host_admission_allows_execution(atu.verdict) =>
                    {
                        atu
                    }
                    Ok(atu) => {
                        return Err(serde_json::json!({
                            "ok": false,
                            "error": "pate_not_proceed",
                            "pate_task_id": atu.task_id,
                            "executed": false,
                        }));
                    }
                    Err(error) => {
                        return Err(serde_json::json!({
                            "ok": false,
                            "error": error.denial_reason.slug(),
                            "denial_reason": error.human_readable,
                            "executed": false,
                        }));
                    }
                };
                let ticket = Some(crate::substrate::microvm_tool_plane::ExecutionTicket {
                    task_id: &atu.task_id,
                    action_digest: &atu.action_digest,
                });
                let invoked = match plan {
                    crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmIo => {
                        crate::substrate::microvm_tool_plane::invoke_io_in_microvm(
                            state, agent_pid, bridge_id, tool_name, input, ticket,
                        )
                        .await
                    }
                    crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmChannel => {
                        crate::substrate::microvm_tool_plane::invoke_channel_in_microvm(
                            state, agent_pid, bridge_id, tool_name, input, ticket,
                        )
                        .await
                    }
                    _ => unreachable!("matched only the microvm plans"),
                };
                match invoked {
                    Ok(mut out) => {
                        let _ = crate::substrate::pate::complete_augmented_task(
                            state,
                            &atu,
                            "ok",
                            serde_json::json!({"observed": true, "runtime": "microvm"}),
                        );
                        if let Some(object) = out.as_object_mut() {
                            object.insert("pate_task_id".into(), serde_json::json!(atu.task_id));
                            object.insert("admits".into(), serde_json::json!(false));
                        }
                        let _ = crate::substrate::svf::observe_tool_result(
                            state, agent_pid, bridge_id, tool_name, Some(&atu.task_id), &mut out,
                        );
                        return Ok(out);
                    }
                    Err(error) => {
                        let _ = crate::substrate::pate::complete_augmented_task(
                            state,
                            &atu,
                            "deny",
                            serde_json::json!({"observed": false, "runtime": "microvm"}),
                        );
                        return Err(error);
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                if crate::substrate::probabilistic_llm::distrust_enforced()
                    && e.get("denial_reason").and_then(|v| v.as_str())
                        == Some("in_process_effect_path")
                {
                    return Err(crate::substrate::probabilistic_llm::quarantine_for_bypass(
                        state,
                        agent_pid,
                        "tool_not_in_microvm",
                        e.get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tool effect refused outside microVM"),
                    ));
                }
                return Err(e);
            }
        }
    }
    let mut out =
        dispatch_mcp_tool_core(state, bridge_id, tool_name, agent_pid, input, reason, mission)?;
    // OBSERVE: remask → MemPacket + COPG + SEMANTICIZE (standing secrets leave model plane).
    let pate_id = out
        .get("pate_task_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let _ = crate::substrate::svf::observe_tool_result(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        pate_id.as_deref(),
        &mut out,
    );
    let tool_ok = !out.get("error").is_some();
    if let Some(p) = crate::substrate::aipsprt::maybe_passport_file_write(
        state.as_ref(),
        agent_pid,
        tool_name,
        input,
        tool_ok,
    ) {
        if let Ok(v) = serde_json::to_value(&p) {
            out["connector_aipsprt"] = v;
        }
    }
    Ok(out)
}

pub(crate) fn dispatch_mcp_tool_core(
    state: &SharedState,
    bridge_id: &str,
    tool_name: &str,
    agent_pid: &str,
    input: &serde_json::Value,
    reason: String,
    mission: ToolMissionOpts<'_>,
) -> Result<serde_json::Value, serde_json::Value> {
    // ── ADMISSION GATE: runs BEFORE bridge lookup ────────────────────────
    // Security enforcement must happen first — a missing bridge is an infra
    // error, not a security decision. If the agent is quarantined or the
    // content is malicious, we must deny before even checking the bridge.
    let input_str = serde_json::to_string(input).unwrap_or_default();
    {
        if let Err(e) = crate::substrate::ops_runtime::preflight_agent_effect(state, agent_pid) {
            return Err(serde_json::json!({
                "error": e.human_readable,
                "denial_reason": e.denial_reason.slug(),
                "bridge_id": bridge_id,
                "tool": tool_name,
            }));
        }
        // Knowledge boundary: URL/source-like args must not be prohibited.
        let mut cited = Vec::new();
        if let Some(obj) = input.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    if s.contains("://") || k.contains("url") || k.contains("source") {
                        cited.push(s.to_string());
                    }
                }
            }
        }
        if !cited.is_empty() {
            if let Err(e) = crate::substrate::ops_runtime::assert_knowledge_may_justify(
                state.as_ref(),
                agent_pid,
                &cited,
            ) {
                return Err(serde_json::json!({
                    "error": e.human_readable,
                    "denial_reason": e.denial_reason.slug(),
                    "bridge_id": bridge_id,
                    "tool": tool_name,
                    "honesty": "Prohibited/unsupported knowledge cannot justify tool effect",
                }));
            }
        }
        let admission_result = crate::substrate::governed_effect::evaluate_effect(
            state,
            None,
            agent_pid,
            &format!("tools/{}", bridge_id),
            crate::services::admission::AdmissionOp::ToolDispatch {
                tool_id: format!("{}:{}", bridge_id, tool_name),
            },
            Some(&input_str),
        );
        if let Err(err) = admission_result {
            return Err(serde_json::json!({
                "error": err.human_readable,
                "denial_reason": err.denial_reason.slug(),
                "audit_cid": err.audit_cid,
                "bridge_id": bridge_id,
                "tool": tool_name,
            }));
        }
    }

    // ── C9: charter capabilities / denied_operations ─────────────────────
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        agent_pid,
        "tool.dispatch",
        &format!("{bridge_id}:{tool_name}"),
    ) {
        if crate::substrate::probabilistic_llm::distrust_enforced() {
            return Err(crate::substrate::probabilistic_llm::apply_denial(
                state,
                agent_pid,
                crate::substrate::probabilistic_llm::DenialClass::Rule,
                "knowledge",
                &e,
            ));
        }
        return Err(serde_json::json!({
            "error": e,
            "denial_reason": "contract_denied",
            "bridge_id": bridge_id,
            "tool": tool_name,
            "honesty": "C9 — AgentContract must allow tool capability",
        }));
    }

    // ── TG-0: membrane fail-closed under harden (Landlock ABI / matrix tools)
    if let Err(e) = crate::kernel::membrane_posture::assert_membrane_ready_for_effects(agent_pid) {
        return Err(e);
    }
    if let Err(e) =
        crate::substrate::sandbox_unbypassable::assert_sandbox_unbypassable(state.as_ref(), agent_pid)
    {
        return Err(e);
    }

    // ── Effect exclusivity / microVM tool plane (async handlers route MicrovmIo first)
    let effect = crate::substrate::microvm_tool_plane::classify_tool(bridge_id, tool_name);
    if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced() {
        match crate::substrate::microvm_tool_plane::assert_preflight(
            state.as_ref(),
            agent_pid,
            bridge_id,
            tool_name,
        ) {
            Ok(crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmIo) => {
                return Err(serde_json::json!({
                    "error": "host_io_refused",
                    "denial_reason": "in_process_effect_path",
                    "bridge_id": bridge_id,
                    "tool": tool_name,
                    "message": "Local I/O cannot run on the Connector host — use microVM tool plane",
                }));
            }
            Ok(crate::substrate::microvm_tool_plane::ToolExecPlan::MicrovmChannel) => {
                return Err(serde_json::json!({
                    "error": "host_channel_refused",
                    "denial_reason": "in_process_effect_path",
                    "bridge_id": bridge_id,
                    "tool": tool_name,
                    "message": "Robotics/IoT/device channels cannot run on the Connector host — use microVM channel",
                }));
            }
            Ok(_) => {}
            Err(e) => {
                if crate::substrate::probabilistic_llm::distrust_enforced()
                    && e.get("denial_reason").and_then(|v| v.as_str())
                        == Some("in_process_effect_path")
                {
                    return Err(crate::substrate::probabilistic_llm::quarantine_for_bypass(
                        state,
                        agent_pid,
                        "tool_not_in_microvm",
                        e.get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tool effect refused outside microVM"),
                    ));
                }
                return Err(e);
            }
        }
    } else if let Err(e) = crate::substrate::effect_exclusivity::assert_in_process_dispatch_allowed(
        state.as_ref(),
        agent_pid,
        effect,
    ) {
        if crate::substrate::probabilistic_llm::distrust_enforced() {
            return Err(crate::substrate::probabilistic_llm::quarantine_for_bypass(
                state,
                agent_pid,
                "in_process_effect_path",
                "LLM attempted an ungoverned in-process tool path around Connector isolation",
            ));
        }
        return Err(e);
    }

    if let Err(e) =
        crate::substrate::effect_exclusivity::assert_effect_exclusivity_ready(agent_pid, state.as_ref())
    {
        return Err(e);
    }

    // ── SVF / broker: validate opaque ONLY (no expand) — Admit digest covers handles
    let opaque_input = match crate::substrate::llm_broker_gate::egress_validate_opaque(
        state, agent_pid, input,
    ) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    // ── TG-2 / PATE: AutonomyGateway Allow | Ask | Block (digest over opaque params)
    let tool_atu = match crate::substrate::pate::admit_tool(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        &opaque_input,
        mission.mission_id.map(|s| s.to_string()),
    ) {
        Ok(atu) => atu,
        Err(e) => {
            return Err(serde_json::json!({
                "error": e.denial_reason.slug(),
                "denial_reason": e.human_readable,
                "pate_task_id": serde_json::Value::Null,
                "bridge_id": bridge_id,
                "tool": tool_name,
            }));
        }
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &tool_atu);

    // ARC-5 / C4: tool.dispatch is the first lease-only sink under CONNECTOR_ARC_LEASE.
    let mut arc_lease = match crate::substrate::arc::lease::LeaseSinkGuard::begin(
        agent_pid,
        &tool_atu.action_digest,
        &tool_atu.task_id,
        tool_atu.iac_epoch,
    ) {
        Ok(g) => g,
        Err(e) => {
            return Err(serde_json::json!({
                "error": "arc_lease_required",
                "denial_reason": e.human_readable,
                "hint": e.hint,
                "bridge_id": bridge_id,
                "tool": tool_name,
                "pate_task_id": tool_atu.task_id,
                "honesty": "NoLease ⇒ NoEffect on tool.dispatch when CONNECTOR_ARC_LEASE=1",
            }));
        }
    };

    // ── SVF CDP: expand tokens only post-Admit (IFC D3), then ActionBroker materialize
    if let Err(e) = crate::substrate::svf::assert_cdp_thawed(state, agent_pid) {
        return Err(e);
    }
    let mut input = match crate::substrate::llm_broker_gate::expand_after_admit(
        state,
        agent_pid,
        &opaque_input,
    ) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    crate::substrate::svf::record_expand_receipt(
        state,
        agent_pid,
        &opaque_input,
        &input,
        Some(&tool_atu.task_id),
    );

    // RESOLVE (binding lookup) when args carry a semantic handle — does not mint leases.
    if crate::substrate::svf::svf_enabled() {
        if let Some(handle) = opaque_input
            .pointer("/svf_handle")
            .or_else(|| opaque_input.get("svf_handle"))
            .and_then(|v| v.as_str())
        {
            let purpose = opaque_input
                .get("purpose")
                .and_then(|v| v.as_str())
                .unwrap_or("tool.dispatch");
            let mat = crate::substrate::svf::materialize_with_resolve(
                state,
                agent_pid,
                bridge_id,
                tool_name,
                handle,
                purpose,
                &opaque_input,
                &tool_atu.task_id,
                &tool_atu.action_digest,
                &mut input,
            );
            if let Err(e) = mat {
                // Unresolved handle → still allow CDP materialize (binding optional).
                let deny = e
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if deny == "resolve_failed" {
                    match crate::substrate::svf::materialize_after_admit(
                        state,
                        agent_pid,
                        bridge_id,
                        tool_name,
                        &mut input,
                        &tool_atu.task_id,
                        &tool_atu.action_digest,
                    ) {
                        Ok(_) => {}
                        Err(e2) => return Err(e2),
                    }
                } else {
                    return Err(e);
                }
            }
        } else {
            match crate::substrate::svf::materialize_after_admit(
                state,
                agent_pid,
                bridge_id,
                tool_name,
                &mut input,
                &tool_atu.task_id,
                &tool_atu.action_digest,
            ) {
                Ok((n, mode)) if n > 0 => {
                    tracing::info!(
                        n,
                        agent_pid,
                        tool = tool_name,
                        ?mode,
                        "svf CDP: ActionBroker materialized vault handles"
                    );
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    } else {
        match crate::substrate::svf::materialize_after_admit(
            state,
            agent_pid,
            bridge_id,
            tool_name,
            &mut input,
            &tool_atu.task_id,
            &tool_atu.action_digest,
        ) {
            Ok((n, mode)) if n > 0 => {
                tracing::info!(
                    n,
                    agent_pid,
                    tool = tool_name,
                    ?mode,
                    "svf CDP: ActionBroker materialized vault handles"
                );
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
    let input = &input;

    // Packet DNA on outbound tool effects (A6 / S20) when required.
    let _packet_dna = match crate::substrate::packet_dna::mint_require_and_log(
        state.as_ref(),
        agent_pid,
        "tool.dispatch",
        &format!("{bridge_id}:{tool_name}"),
        input,
        input,
    ) {
        Ok(d) => Some(d),
        Err(e) if crate::substrate::packet_dna::dna_required() => {
            return Err(serde_json::json!({
                "error": "packet_dna_required",
                "denial_reason": e,
                "bridge_id": bridge_id,
                "tool": tool_name,
            }));
        }
        Err(_) => None,
    };

    // Zero-trust handshake: LLM cannot mint tickets; Connector is the only signer.
    let zt_ticket = match crate::kernel::zt_handshake::admit_tool_effect(
        state.as_ref(),
        agent_pid,
        bridge_id,
        tool_name,
        input,
    ) {
        Ok(t) => t,
        Err(e) => {
            let reason = e
                .get("denial_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("zt_handshake");
            if crate::substrate::probabilistic_llm::distrust_enforced()
                && crate::substrate::probabilistic_llm::is_bypass_reason(reason)
            {
                return Err(crate::substrate::probabilistic_llm::quarantine_for_bypass(
                    state,
                    agent_pid,
                    reason,
                    e.get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("zero-trust handshake refused"),
                ));
            }
            return Err(e);
        }
    };

    // Seven Pillars §3/§5 — mint EffectAuthorization + EffectEnvelope before last-mile.
    let binding = crate::kernel::action_binding::ActionBinding::new(
        agent_pid,
        "tool.invoke",
        tool_name,
        format!("{bridge_id}/{tool_name}"),
        input.clone(),
        None,
        "1",
        None,
    );
    let authz = crate::kernel::effect_authz::mint_from_action_binding(
        state.as_ref(),
        &binding,
        None,
        None,
        None,
        None,
        Some(zt_ticket.handshake_id.clone()),
        120,
    );
    if let Err(e) = crate::kernel::effect_authz::assert_valid_for_effect(
        state.as_ref(),
        &authz,
        &binding.target.resource,
        &binding.operation,
        input,
    ) {
        return Err(serde_json::json!({
            "error": "effect_authorization_denied",
            "denial_reason": e,
            "bridge_id": bridge_id,
            "tool": tool_name,
        }));
    }
    let mission_id = mission.mission_id.map(|s| s.to_string());
    let envelope = crate::substrate::effect_envelope_bus::mint_for_tool(
        state.as_ref(),
        &binding,
        Some(authz.digest_hex.clone()),
        None,
        authz.quantum_id.clone(),
        mission_id,
        120,
    );
    if let Err(e) = crate::substrate::effect_envelope_bus::verify_envelope(&envelope) {
        return Err(serde_json::json!({
            "error": "effect_envelope_denied",
            "denial_reason": e,
            "bridge_id": bridge_id,
            "tool": tool_name,
        }));
    }
    let _ = (&zt_ticket, &envelope);

    // U1 — WM syscalls as admit_tool (bridge wm). No MCP catalog. No OpenAI tool inject (Ring-1).
    if bridge_id == "wm" {
        if !crate::kernel::aios::SYSCALLS.contains(&tool_name)
            || tool_name == "llm.complete"
            || tool_name == "tool.invoke"
            || tool_name == "agent.kill_switch"
        {
            return Err(serde_json::json!({
                "error": "unknown_wm_syscall",
                "tool": tool_name,
                "catalog": crate::kernel::aios::SYSCALLS,
            }));
        }
        if let Err(e) =
            crate::kernel::aios::syscall_contract_gate(state.as_ref(), agent_pid, tool_name)
        {
            return Err(serde_json::json!({
                "error": e,
                "denial_reason": "contract_denied",
                "bridge_id": "wm",
                "tool": tool_name,
            }));
        }
        let result =
            crate::kernel::aios::dispatch_with(Some(state.as_ref()), agent_pid, tool_name, input);
        crate::kernel::operating_layer::record(
            crate::kernel::operating_layer::Socket::Syscall,
            agent_pid,
            tool_name,
            result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
            &result,
        );
        let ok_body = serde_json::json!({
            "bridge_id": "wm",
            "tool": tool_name,
            "agent_pid": agent_pid,
            "result": result,
            "pate_task_id": tool_atu.task_id,
            "action_digest": tool_atu.action_digest,
            "zt_handshake": {
                "handshake_id": zt_ticket.handshake_id,
                "seq": zt_ticket.seq,
                "block_hash": zt_ticket.block_hash,
            },
            "honesty": "WM syscall behind admit_tool. Kernel paging still owns overflow."
        });
        open_proceed.disarm();
        let _ = crate::substrate::pate::complete_augmented_task(
            state,
            &tool_atu,
            "ok",
            serde_json::json!({ "tool": tool_name, "bridge_id": "wm" }),
        );
        arc_lease.success();
        return Ok(ok_body);
    }

    // ── TG-3: mission journal — skip re-fire if idempotency already completed
    let idem = mission
        .idempotency_key
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let dig = crate::kernel::mission_journal::input_digest_of(input);
            format!("tool:{bridge_id}:{tool_name}:{dig}")
        });
    let mut journal_step_id: Option<String> = None;
    if let Some(mid) = mission.mission_id.filter(|s| !s.is_empty()) {
        if let Some(done) = crate::kernel::mission_journal::find_completed_by_idempotency(
            state.as_ref(),
            mid,
            &idem,
        ) {
            return Ok({
                arc_lease.success();
                serde_json::json!({
                "bridge_id": bridge_id,
                "tool": tool_name,
                "agent_pid": agent_pid,
                "outcome": "Replayed",
                "replayed": true,
                "mission_id": mid,
                "step": done,
                "honesty": "TG-3 — completed idempotency_key; tool not re-invoked",
                "execution_isolation": mcp_execution_isolation_block(),
            })});
        }
        match crate::kernel::mission_journal::begin_step_detailed(
            state.as_ref(),
            mid,
            agent_pid,
            crate::kernel::mission_journal::StepKind::Tool,
            &idem,
            input,
            Some(serde_json::json!({
                "bridge_id": bridge_id,
                "tool": tool_name,
            })),
        ) {
            Ok((s, outcome)) => {
                use crate::kernel::mission_journal::BeginOutcome;
                match outcome {
                    BeginOutcome::ExistingCompleted => {
                        arc_lease.success();
                        return Ok(serde_json::json!({
                            "bridge_id": bridge_id,
                            "tool": tool_name,
                            "agent_pid": agent_pid,
                            "outcome": "Replayed",
                            "replayed": true,
                            "mission_id": mid,
                            "step": s,
                            "execution_isolation": mcp_execution_isolation_block(),
                        }));
                    }
                    BeginOutcome::ExistingInFlight => {
                        return Err(serde_json::json!({
                            "error": "mission_step_not_reentrant",
                            "denial_reason": "mission_step_not_reentrant",
                            "mission_id": mid,
                            "step": s,
                            "honesty": "T4 — Pending/Failed idempotency_key after restart must not re-invoke side effects",
                        }));
                    }
                    BeginOutcome::New => {
                        journal_step_id = Some(s.step_id);
                    }
                }
            }
            Err(e) => {
                return Err(serde_json::json!({
                    "error": e,
                    "denial_reason": "mission_journal_error",
                    "mission_id": mid,
                }));
            }
        }
    }

    // ── DEVGUARD: Policy enforcement for every MCP tool call ────────────
    // This is the physical enforcement point for Windsurf, Cursor (MCP mode),
    // and any MCP-connected coding agent. Actions are checked against the
    // loaded devguard.yaml policy BEFORE execution.
    {
        crate::services::gateway_hooks::ensure_default_hooks();
        // Check file operations
        let is_file_read = tool_name == "read_file"
            || tool_name == "connector_read_file"
            || tool_name == "Read"
            || tool_name == "read";
        let is_file_write = tool_name == "write_file"
            || tool_name == "connector_write_file"
            || tool_name == "Write"
            || tool_name == "write"
            || tool_name == "edit"
            || tool_name == "file_edit"
            || tool_name == "multi_edit"
            || tool_name == "write_to_file";
        let is_exec = tool_name == "run_command"
            || tool_name == "connector_exec"
            || tool_name == "bash"
            || tool_name == "execute"
            || tool_name == "shell";

        if is_file_read {
            if let Some(path) = input
                .get("path")
                .or(input.get("file_path"))
                .and_then(|v| v.as_str())
            {
                let check =
                    crate::services::gateway_hooks::guard_file_op(state, agent_pid, "read", path)
                        .unwrap_or_else(|| {
                            let fail_closed =
                                crate::services::runtime_control::defense_strict_enabled()
                                    || matches!(
                                        std::env::var("CONNECTOR_ENV")
                                            .unwrap_or_default()
                                            .to_ascii_lowercase()
                                            .as_str(),
                                        "production" | "prod" | "staging" | "pilots" | "pilot"
                                    );
                            crate::services::gateway_hooks::FileGuardResult {
                                allowed: !fail_closed,
                                verdict: if fail_closed {
                                    "DENY".into()
                                } else {
                                    "ALLOW".into()
                                },
                                reason: if fail_closed {
                                    "No file guard registered (fail-closed)".into()
                                } else {
                                    "No file guard registered".into()
                                },
                                requires_approval: false,
                            }
                        });
                if !check.allowed {
                    return Err(serde_json::json!({
                        "error": format!("[DevGuard] READ DENIED: {}", check.reason),
                        "tool": tool_name,
                        "path": path,
                        "verdict": "DENY",
                        "devguard": true,
                    }));
                }
                if let Some((tenant, repo_id)) =
                    crate::services::devguard_workspace::repo_binding_for_agent(state, agent_pid)
                {
                    let executed = crate::services::devguard_workspace::mcp_workspace_read(
                        state, &tenant, &repo_id, path,
                    );
                    open_proceed.finish_observed(executed.is_ok());
                    return executed;
                }
            }
        }

        if is_file_write {
            if let Some(path) = input
                .get("path")
                .or(input.get("file_path"))
                .or(input.get("TargetFile"))
                .and_then(|v| v.as_str())
            {
                let check =
                    crate::services::gateway_hooks::guard_file_op(state, agent_pid, "write", path)
                        .unwrap_or_else(|| {
                            let fail_closed =
                                crate::services::runtime_control::defense_strict_enabled()
                                    || matches!(
                                        std::env::var("CONNECTOR_ENV")
                                            .unwrap_or_default()
                                            .to_ascii_lowercase()
                                            .as_str(),
                                        "production" | "prod" | "staging" | "pilots" | "pilot"
                                    );
                            crate::services::gateway_hooks::FileGuardResult {
                                allowed: !fail_closed,
                                verdict: if fail_closed {
                                    "DENY".into()
                                } else {
                                    "ALLOW".into()
                                },
                                reason: if fail_closed {
                                    "No file guard registered (fail-closed)".into()
                                } else {
                                    "No file guard registered".into()
                                },
                                requires_approval: false,
                            }
                        });
                if !check.allowed {
                    return Err(serde_json::json!({
                        "error": format!("[DevGuard] WRITE DENIED: {}", check.reason),
                        "tool": tool_name,
                        "path": path,
                        "verdict": "DENY",
                        "devguard": true,
                    }));
                }
                if let Some((tenant, repo_id)) =
                    crate::services::devguard_workspace::repo_binding_for_agent(state, agent_pid)
                {
                    let content = input
                        .get("content")
                        .or_else(|| input.get("contents"))
                        .or_else(|| input.get("new_string"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let executed = crate::services::devguard_workspace::mcp_workspace_write(
                        state, &tenant, &repo_id, path, content, agent_pid,
                    );
                    open_proceed.finish_observed(executed.is_ok());
                    return executed.map(|v| {
                        arc_lease.success();
                        v
                    });
                }
            }
        }

        if is_exec {
            if let Some(cmd) = input
                .get("command")
                .or(input.get("CommandLine"))
                .and_then(|v| v.as_str())
            {
                if let Err(e) =
                    crate::kernel::action_binding::admit_devguard_exec_or_ask(state, agent_pid, cmd)
                {
                    return Err(e);
                }
                if let Some((tenant, repo_id)) =
                    crate::services::devguard_workspace::repo_binding_for_agent(state, agent_pid)
                {
                    let executed = crate::services::devguard_workspace::mcp_workspace_exec(
                        state, &tenant, &repo_id, cmd,
                    );
                    open_proceed.finish_observed(executed.is_ok());
                    return executed.map(|v| {
                        arc_lease.success();
                        v
                    });
                }
            }
        }
    }

    // Hosted MCP last mile (DevGuard + playground demo tools) — after PATE sandwich.
    // Avoids requiring a remote mcp_bridges URL on try.cnktros.com.
    crate::services::mcp_hosting::ensure_default_plugins();
    if let Some(hosted) =
        crate::services::mcp_hosting::call_tool(state, agent_pid, tool_name, input.clone())
    {
        let text = hosted
            .content
            .iter()
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let is_err = hosted.is_error.unwrap_or(false);
        crate::kernel::operating_layer::record(
            crate::kernel::operating_layer::Socket::World,
            agent_pid,
            "mcp.hosted",
            !is_err,
            &serde_json::json!({
                "bridge_id": bridge_id,
                "tool": tool_name,
                "hosted": true,
            }),
        );
        if is_err {
            open_proceed.disarm();
            let _ = crate::substrate::pate::complete_augmented_task(
                state,
                &tool_atu,
                "deny",
                serde_json::json!({ "tool": tool_name, "hosted": true, "text": text }),
            );
            return Err(serde_json::json!({
                "error": text,
                "denial_reason": "hosted_tool_denied",
                "bridge_id": bridge_id,
                "tool": tool_name,
                "pate_task_id": tool_atu.task_id,
                "action_digest": tool_atu.action_digest,
                "honesty": "PATE admitted; hosted last-mile denied (grant-list DROP or tool error). Not nft court grade.",
            }));
        }
        let ok_body = serde_json::json!({
            "bridge_id": bridge_id,
            "tool": tool_name,
            "agent_pid": agent_pid,
            "hosted": true,
            "result": text,
            "pate_task_id": tool_atu.task_id,
            "action_digest": tool_atu.action_digest,
            "zt_handshake": {
                "handshake_id": zt_ticket.handshake_id,
                "seq": zt_ticket.seq,
                "block_hash": zt_ticket.block_hash,
            },
            "honesty": "Hosted MCP tool after Admit / PATE. No remote MCP bridge required.",
        });
        open_proceed.disarm();
        let _ = crate::substrate::pate::complete_augmented_task(
            state,
            &tool_atu,
            "ok",
            serde_json::json!({ "tool": tool_name, "hosted": true }),
        );
        if let (Some(mid), Some(sid)) = (mission.mission_id, journal_step_id.as_ref()) {
            let _ = crate::kernel::mission_journal::complete_step(
                state.as_ref(),
                mid,
                sid,
                ok_body.clone(),
            );
        }
        arc_lease.success();
        return Ok(ok_body);
    }

    let bridge = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("mcp_bridges", bridge_id).ok().flatten()
    };

    let b = match bridge {
        Some(b) => b,
        None => {
            return Err(serde_json::json!({
                "error": format!("MCP bridge '{}' not found — register via POST /api/v1/mcp/bridges", bridge_id),
                "status": 404,
            }));
        }
    };

    // ── DI-3: L7 app allowlist (CONNECTOR_L7_EGRESS_PROXY=1) ─────────────
    if let Some(url) = b.get("url").and_then(|v| v.as_str()) {
        if let Err(e) = crate::substrate::egress_policy::assert_agent_l7_egress_allowed(
            state.as_ref(),
            agent_pid,
            url,
        ) {
            crate::substrate::pate::note_runtime_deny_after_admit(
                state.as_ref(),
                agent_pid,
                &tool_atu.task_id,
                &tool_atu.action_digest,
                "egress_allowlist",
                "l7_egress_denied",
                url,
            );
            return Err(serde_json::json!({
                "error": e,
                "denial_reason": "l7_egress_denied",
                "bridge_id": bridge_id,
                "tool": tool_name,
                "bridge_url": url,
                "pate_task_id": tool_atu.task_id,
                "action_digest": tool_atu.action_digest,
                "deny_wins": true,
                "honesty": "PATE admitted. The node L7 allowlist denied the socket. This is not an OpenShell OPA decision.",
            }));
        }
    }

    let result = {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(vac_core::kernel::SyscallRequest {
            agent_pid: agent_pid.to_string(),
            operation: vac_core::types::MemoryKernelOp::ToolDispatch,
            payload: vac_core::kernel::SyscallPayload::ToolDispatch {
                tool_id: format!("mcp:{}:{}", bridge_id, tool_name),
                action: tool_name.to_string(),
                request: input.clone(),
            },
            reason: Some(reason),
            vakya_id: Some(format!("vakya:tool_dispatch:{}:{}", bridge_id, tool_name)),
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };

    if result.outcome == vac_core::types::OpOutcome::Skipped {
        let waiting = matches!(
            &result.value,
            vac_core::kernel::SyscallValue::Error(msg) if msg.contains("Requires approval")
        );
        if waiting {
            let audit_id = result.audit_entry.audit_id.clone();
            let mut es = state.engine_store.lock().unwrap();
            let _ = es.folder_put(
                "pending_approvals",
                &audit_id,
                &serde_json::json!({
                    "audit_id": audit_id,
                    "agent_pid": agent_pid,
                    "tool_id": format!("mcp:{}:{}", bridge_id, tool_name),
                    "tool": tool_name,
                    "action": tool_name,
                    "request": input,
                    "bridge_id": bridge_id,
                    "created_at": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }
    }

    let account_id = {
        let es = state.engine_store.lock().unwrap();
        let meta = es.folder_get("agent_meta", agent_pid).ok().flatten();
        crate::services::billing::billing_tenant_id_from_agent_meta(meta.as_ref())
            .unwrap_or_else(|| agent_pid.to_string())
    };
    crate::services::billing::record_tool_call(state, &account_id, agent_pid, tool_name);

    crate::services::analytics::emit(
        state,
        crate::services::analytics::AnalyticsEvent::new(
            "tool.invoked",
            &account_id,
            serde_json::json!({
                "tool": tool_name,
                "bridge_id": bridge_id,
                "outcome": format!("{:?}", result.outcome),
            }),
        )
        .with_agent(agent_pid),
    );

    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        agent_pid,
        "mcp.invoke",
        true,
        &serde_json::json!({
            "bridge_id": bridge_id,
            "tool": tool_name,
            "outcome": format!("{:?}", result.outcome),
        }),
    );

    let body = serde_json::json!({
        "bridge_id": bridge_id,
        "tool": tool_name,
        "agent_pid": agent_pid,
        "outcome": format!("{:?}", result.outcome),
        "bridge_url": b.get("url"),
        "input": input,
        "injection_checked": true,
        "replayed": false,
        "mission_id": mission.mission_id,
        "pate_task_id": tool_atu.task_id,
        "action_digest": tool_atu.action_digest,
        "execution_isolation": mcp_execution_isolation_block(),
        "zt_handshake": {
            "handshake_id": zt_ticket.handshake_id,
            "seq": zt_ticket.seq,
            "block_hash": zt_ticket.block_hash,
            "prev_hash": zt_ticket.prev_hash,
            "headers": crate::kernel::zt_handshake::ticket_headers(&zt_ticket),
            "honesty": "Ticket is node-signed and single-use. LLM cannot mint or replay it.",
        },
    });

    if let (Some(mid), Some(sid)) = (mission.mission_id, journal_step_id.as_ref()) {
        let _ =
            crate::kernel::mission_journal::complete_step(state.as_ref(), mid, sid, body.clone());
    }
    open_proceed.disarm();
    let _ = crate::substrate::pate::complete_augmented_task(
        state,
        &tool_atu,
        "ok",
        serde_json::json!({
            "bridge_id": bridge_id,
            "tool": tool_name,
            "outcome": format!("{:?}", result.outcome),
        }),
    );

    arc_lease.success();
    Ok(body)
}

/// Track 3 Phase E — Item E.2: Register MCP bridge
pub async fn mcp_register(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let pin = crate::substrate::package_gate::package_pin_from_json(&req);
    if let Err(e) =
        crate::substrate::package_gate::require_package_for_consequential_effect(pin.as_ref())
    {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "honesty": "MCP bridge registration requires signed AppPackageV2 pin outside lab",
        }));
    }
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("mcp-bridge");
    if let Err(deny) = crate::substrate::admission_gate::require_memory_write(
        &state,
        agent_pid,
        "tools/mcp/register",
    ) {
        return Json(deny);
    }
    let bridge_id = req
        .get("bridge_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let url = req.get("url").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "mcp_bridge_url_required",
        }));
    }
    if let Err(code) = crate::substrate::egress_policy::assert_safe_outbound_url(url) {
        return Json(serde_json::json!({
            "ok": false,
            "error": code,
            "message": "MCP bridge URL is not safe for outbound access",
        }));
    }
    if let Err(code) = crate::substrate::egress_policy::assert_mcp_egress_allowed(url) {
        return Json(serde_json::json!({
            "ok": false,
            "error": code,
            "message": "MCP bridge URL is denied by the node egress allowlist",
        }));
    }
    if let Err(message) = crate::substrate::egress_policy::assert_agent_l7_egress_allowed(
        state.as_ref(),
        agent_pid,
        url,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": "l7_egress_denied",
            "message": message,
        }));
    }
    if let Err(detail) = crate::kernel::action_binding::admit_tool_or_ask(
        &state,
        agent_pid,
        "tools/mcp/register",
        "mcp.register",
        &serde_json::json!({"bridge_id": bridge_id, "url": url}),
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": "mcp_registration_governance_denied",
            "detail": detail,
        }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "tools",
        "mcp_register",
        &serde_json::json!({"bridge_id": bridge_id, "url": url}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let tools: Vec<String> = req
        .get("tools")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "mcp_bridges",
        bridge_id,
        &serde_json::json!({
            "bridge_id": bridge_id,
            "url": url,
            "tools": tools,
            "registered_at": chrono::Utc::now().to_rfc3339(),
            "status": "active",
        }),
    );
    drop(es);

    let vendor_cut = crate::kernel::llm_vendor_cut::engage(
        state.as_ref(),
        bridge_id,
        agent_pid,
        "mcp",
        "mcp_register",
    );
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "bridge_id": bridge_id,
        "url": url,
        "tools_count": tools.len(),
        "registered": true,
        "vendor_cut": vendor_cut,
        "honesty": "Direct LLM vendor dests are exclusive to the Connector cage once this tool is connected.",
    }))
}

/// Track 3 Phase E — Item E.3: Invoke MCP tool through kernel
pub async fn mcp_invoke(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let bridge_id = req
        .get("bridge_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let tool_name = req.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let input = req.get("input").cloned().unwrap_or(serde_json::json!({}));
    let mission_id = req.get("mission_id").and_then(|v| v.as_str());
    let idempotency_key = req.get("idempotency_key").and_then(|v| v.as_str());

    match dispatch_mcp_tool(
        &state,
        bridge_id,
        tool_name,
        agent_pid,
        &input,
        format!("MCP invoke {} via {}", tool_name, bridge_id),
        ToolMissionOpts {
            mission_id,
            idempotency_key,
        },
    )
    .await
    {
        Ok(mut body) => {
            if let Some(o) = body.as_object_mut() {
                let mut iso = mcp_execution_isolation_block();
                if let Some(m) = iso.as_object_mut() {
                    m.insert(
                        "scoped_invoke".to_string(),
                        serde_json::json!("POST /api/v1/tools/mcp/invoke-scoped enforces tool_scope + circuit breaker before the same ToolDispatch path"),
                    );
                }
                o.insert("execution_isolation".to_string(), iso);
            }
            Json(body)
        }
        Err(e) => Json(e),
    }
}

/// Track 3 Phase E — Item E.4: List active MCP bridges
pub async fn mcp_bridges(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("mcp_bridges", None).unwrap_or_default();
    let bridges: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("mcp_bridges", k).ok().flatten())
        .collect();

    Json(serde_json::json!({
        "count": bridges.len(),
        "bridges": bridges,
    }))
}

/// `DELETE /tools/mcp/bridges/:bridge_id` — unregister an MCP bridge.
///
/// Registration was one-way: a bridge pointing at a wrong or compromised URL
/// could be created from the UI but never removed, so the only remedy was
/// editing the store by hand. Removing the record stops further dispatch
/// through it; any circuit-breaker config for the same id is dropped with it.
pub async fn mcp_unregister(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(bridge_id): Path<String>,
) -> Json<serde_json::Value> {
    if let Err(e) = crate::services::workflow_runtime::require_admin_or_dev(&headers) {
        return Json(e);
    }
    let bridge_id = bridge_id.trim().to_string();
    if bridge_id.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "bridge_id_required"}));
    }

    let mut es = state.engine_store.lock().unwrap();
    let existing = es.folder_get("mcp_bridges", &bridge_id).ok().flatten();
    if existing.is_none() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "bridge_not_found",
            "bridge_id": bridge_id,
        }));
    }
    let removed = es.folder_delete("mcp_bridges", &bridge_id).is_ok();
    let breaker_removed = es.folder_delete("mcp_circuit_breakers", &bridge_id).is_ok();

    Json(serde_json::json!({
        "ok": removed,
        "bridge_id": bridge_id,
        "removed": removed,
        "circuit_breaker_cleared": breaker_removed,
        "previous": existing,
        "admits": false,
        "honesty": "Removes the bridge record. This is not an admitted effect. In-flight calls already dispatched are not recalled.",
    }))
}

/// Track 3 Phase E — Item E.5: List tool calls awaiting human approval
pub async fn approvals_pending(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("pending_approvals", None).unwrap_or_default();
    let pending: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|audit_id| {
            let call = es.folder_get("pending_approvals", audit_id).ok().flatten()?;
            Some(serde_json::json!({
                "audit_id": audit_id,
                "agent_pid": call.get("agent_pid"),
                "tool": call.get("tool").or_else(|| call.get("tool_id")),
                "created_at": call.get("created_at"),
            }))
        })
        .collect();

    Json(serde_json::json!({
        "pending_count": pending.len(),
        "approvals": pending,
        "honesty": "Only rows still in pending_approvals. Historical ToolDispatch+Skipped audit is not pending work.",
    }))
}

/// Track 3 Phase E — Item E.6: Approve pending tool call
/// FIX BUG-021: Now re-executes the tool after approval and stores result for agent retrieval
pub async fn approve_tool(
    State(state): State<SharedState>,
    Path(audit_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let approved_by = req
        .get("approved_by")
        .and_then(|v| v.as_str())
        .unwrap_or("admin");
    let now = chrono::Utc::now().to_rfc3339();

    // FIX BUG-021: Retrieve the pending tool call details
    let pending_call = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("pending_approvals", &audit_id).ok().flatten()
    };
    let subject = pending_call
        .as_ref()
        .and_then(|c| c.get("agent_pid"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("tools");
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "approve_pending_tool",
        &serde_json::json!({"audit_id": audit_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let tool_result = if let Some(call) = pending_call {
        let agent_pid = call.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
        let tool_id = call.get("tool_id").and_then(|v| v.as_str()).unwrap_or("");
        let action = call.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let request = call
            .get("request")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // Re-dispatch the tool call via kernel
        let result = {
            let mut k = state.kernel.lock().unwrap();
            k.dispatch(vac_core::kernel::SyscallRequest {
                agent_pid: agent_pid.to_string(),
                operation: vac_core::types::MemoryKernelOp::ToolDispatch,
                payload: vac_core::kernel::SyscallPayload::ToolDispatch {
                    tool_id: tool_id.to_string(),
                    action: action.to_string(),
                    request: request.clone(),
                },
                reason: Some(format!("Approved by {} at {}", approved_by, now)),
                vakya_id: Some(format!("vakya:tool_approval:{}:{}", agent_pid, audit_id)),
                trace_parent: None,
                trace_state: None,
                api_version: None,
            })
        };

        Some(serde_json::json!({
            "outcome": format!("{:?}", result.outcome),
            "value": format!("{:?}", result.value),
        }))
    } else {
        None
    };

    // Store approval and result in engine store
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "approvals",
        &audit_id,
        &serde_json::json!({
            "audit_id": audit_id,
            "approved_by": approved_by,
            "approved_at": now,
            "status": "approved",
            "tool_result": tool_result,
        }),
    );

    // FIX BUG-021: Remove from pending approvals
    let _ = es.folder_delete("pending_approvals", &audit_id);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "audit_id": audit_id,
        "approved": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "approved_by": approved_by,
        "tool_executed": tool_result.is_some(),
        "result": tool_result,
    }))
}

/// Deny a pending tool call — remove from pending_approvals without executing.
pub async fn deny_tool(
    State(state): State<SharedState>,
    Path(audit_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let denied_by = req
        .get("denied_by")
        .or_else(|| req.get("approved_by"))
        .and_then(|v| v.as_str())
        .unwrap_or("operator-ui");
    let reason = req
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("denied by operator");
    let now = chrono::Utc::now().to_rfc3339();

    let pending = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("pending_approvals", &audit_id).ok().flatten()
    };
    if pending.is_none() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "not_found",
            "audit_id": audit_id,
            "status": 404,
            "hint": "No pending_approvals row for this audit_id (already decided or never queued).",
        }));
    }
    let subject = pending
        .as_ref()
        .and_then(|c| c.get("agent_pid"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("tools");
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "deny_pending_tool",
        &serde_json::json!({"audit_id": audit_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "approvals",
        &audit_id,
        &serde_json::json!({
            "audit_id": audit_id,
            "denied_by": denied_by,
            "denied_at": now,
            "status": "denied",
            "reason": reason,
            "pending": pending,
        }),
    );
    let _ = es.folder_delete("pending_approvals", &audit_id);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "audit_id": audit_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "approved": false,
        "denied": true,
        "denied_by": denied_by,
        "reason": reason,
    }))
}

/// Track 3 Phase G — Item G.4: Send signal between agents
pub async fn send_signal(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let from_pid = req.get("from_pid").and_then(|v| v.as_str()).unwrap_or("");
    let to_pid = req.get("to_pid").and_then(|v| v.as_str()).unwrap_or("");
    let signal_type = req
        .get("signal")
        .and_then(|v| v.as_str())
        .unwrap_or("notify");
    let payload = req
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::json!(null));

    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        from_pid,
        "signal.send",
        to_pid,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
        }));
    }
    if let Err(e) = crate::kernel::agent_identity_envelope::require_inter_intelligence_grant(
        state.as_ref(),
        from_pid,
        to_pid,
        None,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "grant_required",
            "status": 403,
        }));
    }

    let k = state.kernel.lock().unwrap();
    // Verify both agents exist
    let from_ok = k.get_agent(from_pid).is_some();
    let to_ok = k.get_agent(to_pid).is_some();

    if !from_ok || !to_ok {
        return Json(serde_json::json!({
            "error": "One or both agents not found",
            "from_exists": from_ok,
            "to_exists": to_ok,
        }));
    }

    // Log signal in engine store
    drop(k);
    let subject = if from_pid.is_empty() { "tools" } else { from_pid };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "queue_agent_notice",
        &serde_json::json!({"from_pid": from_pid, "to_pid": to_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let signal_id = format!("sig_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let signal_data = serde_json::json!({
        "signal_id": signal_id,
        "from": from_pid,
        "to": to_pid,
        "signal": signal_type,
        "payload": payload,
        "sent_at": now,
        "status": "pending",
    });
    let _ = es.folder_put("signals", &signal_id, &signal_data);

    // FIX BUG-019: Add signal to target agent's pending signals list for polling
    let pending_key = format!("pending_signals:{}", to_pid);
    let existing = es
        .folder_get("agent_signals", &pending_key)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"signals": []}));
    let mut pending = existing.as_object().cloned().unwrap_or_default();
    let mut signals_arr = pending
        .get("signals")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    signals_arr.push(serde_json::json!(signal_id));
    pending.insert("signals".into(), serde_json::json!(signals_arr));
    pending.insert("last_updated".into(), serde_json::json!(now));
    let _ = es.folder_put(
        "agent_signals",
        &pending_key,
        &serde_json::Value::Object(pending),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "signal_id": signal_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "from": from_pid,
        "to": to_pid,
        "signal": signal_type,
        "delivered": true,
        "note": "Signal queued. Target agent can poll GET /tools/signals/{to_pid} to retrieve pending signals.",
    }))
}

/// Track 3 Phase H — Item H.2: Register/view agent DID
pub async fn agent_did(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            let did = format!(
                "did:connector:{}:{}",
                state.storage_layout.cell_id, agent_pid
            );
            Json(serde_json::json!({
                "agent_pid": agent_pid,
                "did": did,
                "name": &acb.agent_name,
                "role": format!("{:?}", acb.role),
                "status": format!("{:?}", acb.status),
                "registered_at": acb.registered_at,
                "namespace": &acb.namespace,
                "tool_bindings": acb.tool_bindings.len(),
                "verification_method": "Ed25519",
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        ),
    }
}

/// Track 3 Phase H — Item H.3: Agent card (public profile)
pub async fn agent_card(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            let trust = connector_engine::TrustComputer::compute(&k);
            let ops = k
                .audit_log()
                .iter()
                .filter(|e| e.agent_pid == agent_pid)
                .count();
            let did = format!(
                "did:connector:{}:{}",
                state.storage_layout.cell_id, agent_pid
            );

            Json(serde_json::json!({
                "card": {
                    "did": did,
                    "name": &acb.agent_name,
                    "role": format!("{:?}", acb.role),
                    "capabilities": acb.tool_bindings.iter().map(|tb| &tb.tool_id).collect::<Vec<_>>(),
                    "namespace": &acb.namespace,
                    "total_operations": ops,
                    "agent_health_score": trust.score,
                    "trust_grade": trust.grade,
                },
                "protocols": ["mcp", "a2a"],
                "version": "1.0",
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        ),
    }
}

// ── E4.7: Tool permission scopes ──────────────────────────────────────────────

/// POST /tools/bindings/scoped — bind tool with allowed_operations + allowed_paths
pub async fn bind_tool_scoped(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let tool_id = req.get("tool_id").and_then(|v| v.as_str()).unwrap_or("");
    let allowed_ops: Vec<String> = req
        .get("allowed_operations")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let allowed_paths: Vec<String> = req
        .get("allowed_paths")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let now = chrono::Utc::now();

    if agent_pid.is_empty() || tool_id.is_empty() {
        return Json(serde_json::json!({"error": "agent_pid and tool_id required", "status": 400}));
    }

    let scope_key = format!("tool_scope_{}_{}", agent_pid, tool_id);
    let scope = serde_json::json!({
        "agent_pid":          agent_pid,
        "tool_id":            tool_id,
        "allowed_operations": allowed_ops,
        "allowed_paths":      allowed_paths,
        "created_at":         now.to_rfc3339(),
    });
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("tool_scopes", &scope_key, &scope);

    Json(serde_json::json!({
        "scope_key":          scope_key,
        "agent_pid":          agent_pid,
        "tool_id":            tool_id,
        "allowed_operations": allowed_ops,
        "allowed_paths":      allowed_paths,
        "created_at":         now.to_rfc3339(),
        "enforcement":        "Scope checked on mcp_invoke and mcp_invoke_scoped for this agent+tool pair",
    }))
}

/// POST /tools/mcp/invoke-scoped — scope-enforced + circuit-breaker-aware invocation,
/// then the **same** kernel `ToolDispatch` path as `mcp_invoke` (real execution, not a stub).
pub async fn mcp_invoke_scoped(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let tool_id = req.get("tool_id").and_then(|v| v.as_str()).unwrap_or("");
    let operation = req.get("operation").and_then(|v| v.as_str()).unwrap_or("");
    let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let input = req.get("input").cloned().unwrap_or(serde_json::json!({}));
    let now = chrono::Utc::now();

    if agent_pid.is_empty() || tool_id.is_empty() {
        return Json(serde_json::json!({"error": "agent_pid and tool_id required", "status": 400}));
    }

    let bridge_for_breaker = parse_bridge_and_tool(tool_id).0;

    {
        let es = state.engine_store.lock().unwrap();

        // Scope check
        let scope_key = format!("tool_scope_{}_{}", agent_pid, tool_id);
        if let Some(scope) = es.folder_get("tool_scopes", &scope_key).ok().flatten() {
            let allowed_ops: Vec<String> = scope
                .get("allowed_operations")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            if !allowed_ops.is_empty()
                && !operation.is_empty()
                && !allowed_ops.iter().any(|o| o == operation || o == "*")
            {
                return Json(serde_json::json!({
                    "error":     "SCOPE_VIOLATION",
                    "message":   format!("Operation '{}' not in allowed_operations for tool '{}'", operation, tool_id),
                    "allowed":   allowed_ops,
                    "requested": operation,
                }));
            }
            let allowed_paths: Vec<String> = scope
                .get("allowed_paths")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            if !allowed_paths.is_empty() && !path.is_empty() {
                let path_ok = allowed_paths.iter().any(|p| {
                    if p.ends_with("/*") {
                        path.starts_with(p.trim_end_matches('*').trim_end_matches('/'))
                    } else {
                        p == path || p == "*"
                    }
                });
                if !path_ok {
                    return Json(serde_json::json!({
                        "error":     "SCOPE_VIOLATION",
                        "message":   format!("Path '{}' not in allowed_paths for tool '{}'", path, tool_id),
                        "allowed":   allowed_paths,
                        "requested": path,
                    }));
                }
            }
        }

        // Circuit breaker check (keyed by MCP bridge id)
        let cb_key = format!("cb_{}", bridge_for_breaker);
        if let Some(cb) = es.folder_get("circuit_breakers", &cb_key).ok().flatten() {
            if cb.get("state").and_then(|v| v.as_str()) == Some("open") {
                return Json(serde_json::json!({
                    "error":       "CIRCUIT_OPEN",
                    "message":     format!("Circuit breaker open for bridge '{}'", bridge_for_breaker),
                    "retry_after": cb.get("open_until"),
                }));
            }
        }
    }

    let (bridge_id, tool_name) = parse_bridge_and_tool(tool_id);
    let reason = format!(
        "MCP invoke-scoped {} via {} (operation={}, path={})",
        tool_name, bridge_id, operation, path
    );

    let mission_id = req.get("mission_id").and_then(|v| v.as_str());
    let idempotency_key = req.get("idempotency_key").and_then(|v| v.as_str());
    match dispatch_mcp_tool(
        &state,
        &bridge_id,
        &tool_name,
        agent_pid,
        &input,
        reason,
        ToolMissionOpts {
            mission_id,
            idempotency_key,
        },
    )
    .await
    {
        Ok(mut body) => {
            if let Some(o) = body.as_object_mut() {
                o.insert("scope".to_string(), serde_json::json!("passed"));
                o.insert("tool_id".to_string(), serde_json::json!(tool_id));
                o.insert("operation".to_string(), serde_json::json!(operation));
                o.insert("path".to_string(), serde_json::json!(path));
                o.insert(
                    "invoked_at".to_string(),
                    serde_json::json!(now.to_rfc3339()),
                );
                let mut iso = mcp_execution_isolation_block();
                if let Some(m) = iso.as_object_mut() {
                    m.insert(
                        "gate".to_string(),
                        serde_json::json!(
                            "tool_scope + circuit_breaker evaluated before ToolDispatch"
                        ),
                    );
                }
                o.insert("execution_isolation".to_string(), iso);
            }
            Json(body)
        }
        Err(e) => Json(e),
    }
}

// ── E4.8: Circuit breaker per bridge ─────────────────────────────────────────

/// POST /tools/bridges/{bridge_id}/circuit-breaker — configure circuit breaker
pub async fn configure_circuit_breaker(
    State(state): State<SharedState>,
    axum::extract::Path(bridge_id): axum::extract::Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let timeout_ms = req
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000);
    let failure_threshold = req
        .get("failure_threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(5);
    let half_open_after_secs = req
        .get("half_open_after_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(60);
    let now = chrono::Utc::now();

    let cb_key = format!("cb_{}", bridge_id);
    let es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("circuit_breakers", &cb_key)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"state": "closed", "consecutive_failures": 0}));
    let current_state = existing
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("closed");
    let consec_failures = existing
        .get("consecutive_failures")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let (new_state, open_until): (&str, Option<i64>) =
        if consec_failures >= failure_threshold && current_state != "open" {
            (
                "open",
                Some(now.timestamp_millis() + half_open_after_secs as i64 * 1000),
            )
        } else if current_state == "open" {
            let ot = existing
                .get("open_until")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if now.timestamp_millis() >= ot {
                ("half_open", None)
            } else {
                ("open", Some(ot))
            }
        } else {
            (current_state, None)
        };
    drop(es);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "tools",
        "lifecycle",
        "configure_breaker",
        &serde_json::json!({"bridge_id": bridge_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let cb = serde_json::json!({
        "bridge_id":            bridge_id,
        "timeout_ms":           timeout_ms,
        "failure_threshold":    failure_threshold,
        "half_open_after_secs": half_open_after_secs,
        "state":                new_state,
        "consecutive_failures": consec_failures,
        "open_until":           open_until,
        "updated_at":           now.to_rfc3339(),
    });
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("circuit_breakers", &cb_key, &cb);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "bridge_id":            bridge_id,
        "task_id":              admitted.task_id,
        "executed":             true,
        "admits":               false,
        "state":                new_state,
        "consecutive_failures": consec_failures,
        "failure_threshold":    failure_threshold,
        "timeout_ms":           timeout_ms,
        "open_until":           open_until,
        "updated_at":           now.to_rfc3339(),
        "transitions": {
            "closed_to_open": format!("After {} consecutive failures", failure_threshold),
            "open_to_half":   format!("After {}s cooldown", half_open_after_secs),
            "half_to_closed": "First successful invoke in half_open state",
        },
    }))
}

/// GET /tools/bridges/{bridge_id}/circuit-breaker — status
pub async fn circuit_breaker_status(
    State(state): State<SharedState>,
    axum::extract::Path(bridge_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let cb_key = format!("cb_{}", bridge_id);
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();

    match es.folder_get("circuit_breakers", &cb_key).ok().flatten() {
        Some(cb) => {
            let state_str = cb.get("state").and_then(|v| v.as_str()).unwrap_or("closed");
            let open_until = cb.get("open_until").and_then(|v| v.as_i64());
            let remaining = open_until.map(|t| ((t - now.timestamp_millis()) / 1000).max(0));
            Json(serde_json::json!({
                "bridge_id":               bridge_id,
                "state":                   state_str,
                "consecutive_failures":    cb.get("consecutive_failures"),
                "failure_threshold":       cb.get("failure_threshold"),
                "timeout_ms":              cb.get("timeout_ms"),
                "open_until":              open_until,
                "remaining_cooldown_secs": remaining,
                "checked_at":              now.to_rfc3339(),
            }))
        }
        None => Json(serde_json::json!({
            "bridge_id": bridge_id,
            "state":     "closed",
            "note":      "No circuit breaker configured. POST /tools/bridges/{id}/circuit-breaker to configure.",
        })),
    }
}

// ── E4.9: Tool name collision detection ──────────────────────────────────────

/// GET /tools/mcp/collision-check?tool_name={name}
pub async fn tool_collision_check(
    State(state): State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let tool_name = q.get("tool_name").map(|s| s.as_str()).unwrap_or("");
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();

    let bridge_keys = es.folder_keys("mcp_bridges", None).unwrap_or_default();
    let mut query_conflicts: Vec<serde_json::Value> = Vec::new();
    let mut name_index: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for bridge_id in &bridge_keys {
        let bridge = match es.folder_get("mcp_bridges", bridge_id).ok().flatten() {
            Some(b) => b,
            None => continue,
        };
        let tools: Vec<String> = bridge
            .get("tools")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        for tool in tools {
            if !tool_name.is_empty() && tool == tool_name {
                query_conflicts.push(serde_json::json!({
                    "tool_name":     &tool,
                    "bridge_id":     bridge_id,
                    "qualified_name":format!("{}:{}", bridge_id, tool),
                }));
            }
            name_index.entry(tool).or_default().push(bridge_id.clone());
        }
    }

    let global_collisions: Vec<serde_json::Value> = name_index.iter()
        .filter(|(_, bridges)| bridges.len() > 1)
        .map(|(name, bridges)| serde_json::json!({
            "tool_name":       name,
            "collision_count": bridges.len(),
            "bridges":         bridges,
            "disambiguation":  bridges.iter().map(|b| format!("{}:{}", b, name)).collect::<Vec<_>>(),
            "recommendation":  format!("Use qualified name 'bridge_id:{}' to avoid ambiguity", name),
        }))
        .collect();

    Json(serde_json::json!({
        "checked_at":        now.to_rfc3339(),
        "query_tool_name":   tool_name,
        "total_bridges":     bridge_keys.len(),
        "query_conflicts":   query_conflicts,
        "global_collisions": global_collisions,
        "collision_count":   global_collisions.len(),
        "status":            if global_collisions.is_empty() { "NO_COLLISIONS" } else { "COLLISIONS_DETECTED" },
        "note":              "Use 'bridge_id:tool_name' qualified names in mcp_invoke to avoid ambiguity",
    }))
}

// ── Phase G.5: Signal handler registration ────────────────────────────────────

#[derive(serde::Deserialize, serde::Serialize)]
pub struct SignalHandlerRequest {
    pub agent_pid: String,
    pub signal_type: String,
    pub handler: String,
    pub auto_heal: Option<bool>,
    pub priority: Option<u8>,
}

/// POST /tools/signals/handlers
/// Register a signal handler for an agent. When signal_type fires, handler action is triggered.
pub async fn register_signal_handler(
    State(state): State<SharedState>,
    Json(req): Json<SignalHandlerRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let handler_id = uuid::Uuid::new_v4().to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.agent_pid,
        "lifecycle",
        "register_event_handler",
        &serde_json::json!({"agent_pid": req.agent_pid.as_str(), "handler_id": handler_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "handler_id":    handler_id,
        "agent_pid":     req.agent_pid,
        "signal_type":   req.signal_type,
        "handler":       req.handler,
        "auto_heal":     req.auto_heal.unwrap_or(false),
        "priority":      req.priority.unwrap_or(0),
        "registered_at": now.to_rfc3339(),
        "active":        true,
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("signal_handlers", &handler_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "handler_id":    handler_id,
        "task_id":       admitted.task_id,
        "executed":      true,
        "admits":        false,
        "agent_pid":     req.agent_pid,
        "signal_type":   req.signal_type,
        "registered_at": now.to_rfc3339(),
        "note": "Handler registered. Signals of this type will trigger the handler action.",
    }))
}

/// GET /tools/signals/handlers
/// List all registered signal handlers.
pub async fn list_signal_handlers(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("signal_handlers", None).unwrap_or_default();
    let handlers: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("signal_handlers", k).ok().flatten())
        .collect();
    Json(serde_json::json!({
        "total":    handlers.len(),
        "handlers": handlers,
    }))
}

// ── Phase H.4-H.5: A2A channel open + send ────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct A2AOpenRequest {
    pub from_agent_pid: String,
    pub to_agent_uri: String,
    pub protocol: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// POST /tools/a2a/open
/// Opens an A2A channel from a local agent to an external agent URI.
pub async fn a2a_open(
    State(state): State<SharedState>,
    Json(req): Json<A2AOpenRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &req.from_agent_pid,
        "a2a.open",
        &req.to_agent_uri,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
        }));
    }
    if let Err(e) = crate::substrate::effect_exclusivity::assert_a2a_requires_grant(
        state.as_ref(),
        &req.from_agent_pid,
        &req.to_agent_uri,
    ) {
        return Json(e);
    }

    let now = chrono::Utc::now();
    let channel_id = uuid::Uuid::new_v4().to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.from_agent_pid,
        "lifecycle",
        "open_channel",
        &serde_json::json!({"from_pid": req.from_agent_pid.as_str(), "channel_id": channel_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "channel_id":     channel_id,
        "from_agent_pid": req.from_agent_pid,
        "to_agent_uri":   req.to_agent_uri,
        "protocol":       req.protocol.unwrap_or_else(|| "a2a/1.0".into()),
        "metadata":       req.metadata.unwrap_or(serde_json::json!({})),
        "opened_at":      now.to_rfc3339(),
        "status":         "open",
        "message_count":  0u64,
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("a2a_channels", &channel_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok":           true,
        "channel_id":   channel_id,
        "task_id":      admitted.task_id,
        "executed":     true,
        "admits":       false,
        "from":         req.from_agent_pid,
        "to":           req.to_agent_uri,
        "opened_at":    now.to_rfc3339(),
        "send_url":     format!("/tools/a2a/{}/send", channel_id),
    }))
}

#[derive(serde::Deserialize)]
pub struct A2ASendRequest {
    pub payload: serde_json::Value,
    pub message_type: Option<String>,
}

/// POST /tools/a2a/{channel_id}/send
/// Sends a message over an open A2A channel.
pub async fn a2a_send(
    State(state): State<SharedState>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(req): Json<A2ASendRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let msg_id = uuid::Uuid::new_v4().to_string();
    let es = state.engine_store.lock().unwrap();

    let channel = match es.folder_get("a2a_channels", &channel_id).ok().flatten() {
        Some(c) => c,
        None => {
            return Json(
                serde_json::json!({"error": "Channel not found", "status": 404, "channel_id": channel_id}),
            )
        }
    };

    let to_uri = channel
        .get("to_agent_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let from_pid = channel
        .get("from_agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    drop(es);

    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &from_pid,
        "a2a.send",
        &to_uri,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
        }));
    }
    if let Err(e) = crate::substrate::effect_exclusivity::assert_a2a_requires_grant(
        state.as_ref(),
        &from_pid,
        &to_uri,
    ) {
        return Json(e);
    }

    let atu = match crate::substrate::pate::admit_a2a(&state, &from_pid, &to_uri, &req.payload, None) {
        Ok(atu) if crate::substrate::pate::host_admission_allows_execution(atu.verdict) => atu,
        Ok(atu) => {
            return Json(serde_json::json!({
                "ok": false,
                "executed": false,
                "pate_task_id": atu.task_id,
                "error": "pate_not_proceed",
            }));
        }
        Err(error) => {
            return Json(serde_json::json!({
                "ok": false,
                "executed": false,
                "error": error.human_readable,
            }));
        }
    };

    let message = serde_json::json!({
        "message_id":   msg_id,
        "channel_id":   channel_id,
        "from":         from_pid,
        "to":           to_uri,
        "type":         req.message_type.unwrap_or_else(|| "data".into()),
        "payload":      req.payload,
        "sent_at":      now.to_rfc3339(),
    });

    let msg_key = format!("{}:{}", channel_id, msg_id);
    let mut es2 = state.engine_store.lock().unwrap();
    let _ = es2.folder_put("a2a_messages", &msg_key, &message);
    drop(es2);
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &atu,
        "ok",
        serde_json::json!({"observed": true, "channel_id": channel_id, "message_id": msg_id}),
    );

    Json(serde_json::json!({
        "ok":          true,
        "message_id":  msg_id,
        "channel_id":  channel_id,
        "pate_task_id": atu.task_id,
        "sent_at":     now.to_rfc3339(),
        "status":      "queued",
        "admits": false,
        "note":        "Message stored after PATE proceed. Delivery depends on external A2A agent availability.",
    }))
}

// ── Phase I.1: cgroup registration ───────────────────────────────────────────

#[derive(serde::Deserialize, serde::Serialize)]
pub struct CgroupRequest {
    pub cgroup_id: String,
    pub agent_pids: Vec<String>,
    pub max_cpu_pct: Option<f64>,
    pub max_memory_mb: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_tokens: Option<u64>,
}

/// POST /tools/cgroups
/// Register a compute resource group for a set of agents.
pub async fn register_cgroup(
    State(state): State<SharedState>,
    Json(req): Json<CgroupRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "tools",
        "lifecycle",
        "register_cgroup",
        &serde_json::json!({"cgroup_id": req.cgroup_id.as_str(), "agents": req.agent_pids.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "cgroup_id":     req.cgroup_id,
        "agent_pids":    req.agent_pids,
        "max_cpu_pct":   req.max_cpu_pct.unwrap_or(100.0),
        "max_memory_mb": req.max_memory_mb.unwrap_or(4096),
        "max_cost_usd":  req.max_cost_usd.unwrap_or(10.0),
        "max_tokens":    req.max_tokens.unwrap_or(1_000_000u64),
        "created_at":    now.to_rfc3339(),
        "status":        "active",
        "current_cpu_pct":  0.0,
        "current_cost_usd": 0.0,
        "current_tokens":   0u64,
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("cgroups", &req.cgroup_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "cgroup_id":  req.cgroup_id,
        "task_id":    admitted.task_id,
        "executed":   true,
        "admits":     false,
        "created_at": now.to_rfc3339(),
        "agent_count": req.agent_pids.len(),
        "limits": {
            "max_cpu_pct":   req.max_cpu_pct.unwrap_or(100.0),
            "max_memory_mb": req.max_memory_mb.unwrap_or(4096),
            "max_cost_usd":  req.max_cost_usd.unwrap_or(10.0),
            "max_tokens":    req.max_tokens.unwrap_or(1_000_000u64),
        },
        "note": "Resource group registered. Agents in this group share the specified budget.",
    }))
}

/// GET /tools/cgroups
/// List all registered cgroups with current utilisation.
pub async fn list_cgroups(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let k = state.kernel.lock().unwrap();
    let es = state.engine_store.lock().unwrap();

    let keys = es.folder_keys("cgroups", None).unwrap_or_default();
    let cgroups: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|key| {
            let mut cg = es.folder_get("cgroups", key).ok().flatten()?;
            let agent_pids: Vec<String> = cg
                .get("agent_pids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            // Sum up live cost + token usage across agents in this group
            let (total_cost, total_tokens) =
                agent_pids.iter().fold((0.0f64, 0u64), |(c, t), pid| {
                    if let Some(acb) = k.get_agent(pid) {
                        (c + acb.total_cost_usd, t + acb.total_tokens_consumed as u64)
                    } else {
                        (c, t)
                    }
                });

            if let Some(obj) = cg.as_object_mut() {
                obj.insert(
                    "current_cost_usd".into(),
                    serde_json::json!((total_cost * 10_000.0).round() / 10_000.0),
                );
                obj.insert("current_tokens".into(), serde_json::json!(total_tokens));
                obj.insert("checked_at".into(), serde_json::json!(now.to_rfc3339()));
                let max_cost = obj
                    .get("max_cost_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(10.0);
                let over_budget = total_cost >= max_cost;
                obj.insert("over_budget".into(), serde_json::json!(over_budget));
            }
            Some(cg)
        })
        .collect();

    Json(serde_json::json!({
        "total":   cgroups.len(),
        "cgroups": cgroups,
    }))
}
