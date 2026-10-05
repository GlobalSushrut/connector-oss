//! AI Gateway — OpenAI-compatible LLM proxy with automatic audit coverage.
//!
//! D2 fix (enterprise_dx.md §9 P0): Any framework that accepts a `base_url` override
//! (LangChain, AutoGen, LlamaIndex, CrewAI, direct openai-python SDK) gets full
//! audit coverage with zero code changes by pointing to `POST /v1/chat/completions`.
//!
//! What this endpoint does automatically:
//!   1. Run SemanticInjectionDetector on the input messages
//!   2. Proxy to the configured LLM via LlmRouter (retry + fallback + cost tracking)
//!   3. Write LLM I/O to POST /memory/write (audit shadow)
//!   4. Record via POST /actionlog/record

use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use vac_core::cid::compute_cid;
use vac_core::kernel::{SyscallPayload, SyscallRequest};
use vac_core::types::{
    CognitivePath, MemPacket, MemoryKernelOp, MemoryType, PacketType, Source, SourceKind,
};

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;
use sha2::{Digest, Sha256};

/// B4: ban anonymous / synthetic gateway pids in prod or when explicitly enabled.
pub fn gateway_anon_ban_enabled() -> bool {
    // Hosted playground Talk uses POST /agents/:pid/completions with anon session id.
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    std::env::var("CONNECTOR_GATEWAY_BAN_ANON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || crate::kernel::agent_identity_envelope::setup_gate_enabled()
        || crate::connector_profile::is_productionish_env()
}

fn is_synthetic_gateway_pid(agent_pid: &str) -> bool {
    agent_pid.is_empty() || agent_pid == "gateway-agent" || agent_pid == "gateway-anthropic"
}

/// Resolve Talk agent identity. Forced-pid Talk (`POST /agents/:pid/completions`) wins over
/// DevGuard session hooks so a real registered pid is never replaced by `gateway-agent`.
fn resolve_talk_agent_context(
    state: &SharedState,
    api_key: &str,
    headers: &HeaderMap,
    req: &ChatCompletionRequest,
) -> Result<(String, String, String), ConnectorError> {
    // Repository admission always wins over a caller-supplied PID. A PID is a
    // routing hint, not an identity credential.
    if let Some((session_id, admitted_pid, role)) =
        require_linked_repo_identity(state, api_key, headers)?
    {
        if let Some(requested_pid) = req
            .agent_pid
            .as_ref()
            .filter(|p| !is_synthetic_gateway_pid(p))
        {
            if requested_pid != &admitted_pid {
                return Err(ConnectorError::new(
                    DenialReason::PolicyDenied,
                    "agent_pid_identity_mismatch",
                )
                .with_hint(
                    "The request agent_pid does not match the repo-bound Connector identity.",
                )
                .with_agent_scope(requested_pid));
            }
        }
        return Ok((session_id, admitted_pid, role));
    }

    // Forced-pid Talk remains available for an unbound repository, but it
    // cannot bypass the linked-repository check above.
    if let Some(pid) = req
        .agent_pid
        .as_ref()
        .filter(|p| !is_synthetic_gateway_pid(p))
    {
        let session_id = super::gateway_hooks::resolve_session(state, api_key)
            .map(|ctx| ctx.session_id)
            .unwrap_or_else(|| "anon".to_string());
        return Ok((session_id, pid.clone(), String::new()));
    }
    let session_ctx = super::gateway_hooks::resolve_session(state, api_key);
    Ok(session_ctx
        .map(|ctx| (ctx.session_id, ctx.agent_pid, ctx.role))
        .unwrap_or_else(|| {
            let pid = req
                .agent_pid
                .clone()
                .unwrap_or_else(|| "gateway-agent".to_string());
            ("anon".to_string(), pid, String::new())
        }))
}

#[cfg(test)]
mod llm_control_path_tests {
    #[test]
    fn every_platform_llm_path_uses_talk_autonomy_gate() {
        for (name, source) in [
            ("openai", include_str!("gateway.rs")),
            ("anthropic", include_str!("anthropic_gateway.rs")),
            ("multiagent", include_str!("multiagent.rs")),
            ("experiments", include_str!("experiments.rs")),
        ] {
            assert!(
                source.contains("admit_talk_or_ask") || source.contains("pate::admit_talk"),
                "{name} LLM path must not bypass Talk autonomy/HITL (admit_talk_or_ask or pate::admit_talk)"
            );
            assert!(
                source.contains("llm_output_contract::enforce"),
                "{name} LLM path must not release prompt-only identity/character output"
            );
        }
    }

    #[test]
    fn openai_gateway_applies_devguard_tool_call_admission() {
        let openai = include_str!("gateway.rs");
        assert!(
            openai.contains("admit_openai_tool_calls_in_messages")
                && openai.contains("admit_devguard_exec_or_ask"),
            "OpenAI gateway must apply DevGuard tool_call admission (parity with Anthropic tool_use)"
        );
    }

    #[test]
    fn hard_charter_includes_operator_parameters() {
        let text = super::render_hard_charter(
            "Demo",
            "Answer only about shipping",
            "Be brief. Never invent SKUs.",
            "SKU-1 is the only product.",
            "lookup_sku",
            "ask before tools",
            "shell",
            "deepseek-chat",
        );
        assert!(text.contains(super::HARD_CHARTER_MARKER));
        assert!(text.contains("purpose:\nAnswer only about shipping"));
        assert!(text.contains("Never invent SKUs"));
        assert!(text.contains("SKU-1 is the only product"));
        assert!(text.contains("lookup_sku"));
        assert!(text.contains("deepseek-chat"));
        assert!(text.contains("Follow them exactly"));
    }

    #[test]
    fn real_mcp_paths_use_governed_egress() {
        let protocols = include_str!("protocols.rs");
        assert!(protocols.contains("admit_tool_or_ask"));
        assert!(protocols.contains("assert_agent_l7_egress_allowed"));

        let tools = include_str!("tools.rs");
        assert!(tools.contains("assert_safe_outbound_url"));
        assert!(tools.contains("assert_mcp_egress_allowed"));
        assert!(
            tools.contains("admit_tool_or_ask") || tools.contains("pate::admit_tool"),
            "tools path must use admit_tool_or_ask or pate::admit_tool"
        );
    }
}

/// Scan OpenAI-style `tool_calls` on conversation messages and apply the same
/// DevGuard exec/fs admission used by Anthropic `tool_use` blocks.
fn admit_openai_tool_calls_in_messages(
    state: &SharedState,
    agent_pid: &str,
    messages: &[ChatMessage],
) -> Result<(), Vec<String>> {
    let mut blocked = Vec::new();
    for msg in messages {
        let Some(calls) = msg.tool_calls.as_ref().and_then(|v| v.as_array()) else {
            continue;
        };
        for call in calls {
            let id = call
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("tool_call");
            let name = call
                .get("function")
                .and_then(|f| f.get("name"))
                .or_else(|| call.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args_raw = call
                .get("function")
                .and_then(|f| f.get("arguments"))
                .or_else(|| call.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let args = match &args_raw {
                serde_json::Value::String(s) => {
                    serde_json::from_str::<serde_json::Value>(s).unwrap_or(serde_json::json!({}))
                }
                other => other.clone(),
            };

            let name_l = name.to_ascii_lowercase();
            if matches!(
                name_l.as_str(),
                "bash"
                    | "execute"
                    | "shell"
                    | "run_command"
                    | "runterminalcommand"
                    | "executecommand"
                    | "terminal"
            ) {
                if let Some(cmd) = args
                    .get("command")
                    .or_else(|| args.get("cmd"))
                    .or_else(|| args.get("CommandLine"))
                    .and_then(|v| v.as_str())
                {
                    if let Err(e) =
                        crate::kernel::action_binding::admit_devguard_exec_or_ask(state, agent_pid, cmd)
                    {
                        blocked.push(format!(
                            "tool_call {id} ({cmd}) DENIED: {}",
                            e.get("denial_reason")
                                .or_else(|| e.get("error"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("blocked")
                        ));
                    }
                }
            }

            if matches!(
                name_l.as_str(),
                "write"
                    | "edit"
                    | "file_edit"
                    | "writefile"
                    | "editfile"
                    | "createfile"
                    | "apply_patch"
                    | "str_replace"
            ) {
                if let Some(path) = args
                    .get("path")
                    .or_else(|| args.get("file_path"))
                    .or_else(|| args.get("filePath"))
                    .and_then(|v| v.as_str())
                {
                    if let Err(e) = crate::kernel::action_binding::admit_devguard_fs_or_ask(
                        state, agent_pid, "write", path,
                    ) {
                        blocked.push(format!(
                            "tool_call {id} (write {path}) DENIED: {}",
                            e.get("denial_reason")
                                .or_else(|| e.get("error"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("blocked")
                        ));
                    }
                }
            }

            if matches!(
                name_l.as_str(),
                "read" | "read_file" | "readfile" | "cat"
            ) {
                if let Some(path) = args
                    .get("path")
                    .or_else(|| args.get("file_path"))
                    .or_else(|| args.get("filePath"))
                    .and_then(|v| v.as_str())
                {
                    if let Err(e) = crate::kernel::action_binding::admit_devguard_fs_or_ask(
                        state, agent_pid, "read", path,
                    ) {
                        blocked.push(format!(
                            "tool_call {id} (read {path}) DENIED: {}",
                            e.get("denial_reason")
                                .or_else(|| e.get("error"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("blocked")
                        ));
                    }
                }
            }
        }
    }
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(blocked)
    }
}

/// Linked repo: no Connector agent ID + role → deny, even read.
pub fn require_linked_repo_identity(
    state: &SharedState,
    api_key: &str,
    headers: &HeaderMap,
) -> Result<Option<(String, String, String)>, ConnectorError> {
    match crate::services::devguard::require_repo_identity(state, api_key, headers) {
        Ok(Some(id)) => Ok(Some((id.session_id, id.agent_pid, id.role))),
        Ok(None) => Ok(None),
        Err(code) => Err(
            ConnectorError::new(DenialReason::PolicyDenied, code).with_hint(
                "This repo is under Connector. Ask the node for an agent ID and role. \
             POST /api/v1/devguard/admit — without that identity even read is denied.",
            ),
        ),
    }
}

/// Reject synthetic Talk identities that look like real agents.
///
/// Playground: anon-ban is off, but heal (principal mint / rehydrate / Talk lane) must still run.
pub fn enforce_real_agent_talk(
    state: &SharedState,
    agent_pid: &str,
    _session_id: &str,
    headers: &HeaderMap,
) -> Result<(), ConnectorError> {
    // Ban synthetic gateway pids (raw /v1/chat/completions without identity).
    // B2 forced-pid Talk (`POST /agents/:pid/completions`) uses session_id "anon" but a real pid — allow that.
    if gateway_anon_ban_enabled() && is_synthetic_gateway_pid(agent_pid) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "anonymous_gateway_talk_banned",
        )
        .with_hint(
            "Use POST /api/v1/agents/:pid/completions with a registered Active agent \
             (or set X-Connector-Agent-Pid to a real pid). Lab: unset CONNECTOR_GATEWAY_BAN_ANON / setup gate.",
        )
        .with_agent_scope(agent_pid));
    }
    if is_synthetic_gateway_pid(agent_pid) {
        // Anon ban off (playground/lab): still refuse empty/gateway-* for forced-pid Talk honesty.
        if agent_pid.is_empty() {
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                "anonymous_gateway_talk_banned",
            )
            .with_hint("Missing agent_pid on Talk")
            .with_agent_scope(agent_pid));
        }
    }
    crate::services::agents::ensure_talk_identity(state, agent_pid);
    if crate::services::playground::is_playground_mode() {
        crate::services::settings_llms::restore_llm_router_for_talk(state, headers, Some(agent_pid));
        // Demo agents are seeded + boot-rehydrated; do not re-register into kernel on every Talk.
    }
    if crate::kernel::agent_principal::load_principal(state.as_ref(), agent_pid).is_none() {
        return Err(
            ConnectorError::new(DenialReason::PolicyDenied, "unknown_principal")
                .with_hint("Register agent and mint principal before Talk")
                .with_agent_scope(agent_pid),
        );
    }
    if crate::kernel::agent_identity_envelope::setup_gate_enabled() {
        let active =
            crate::kernel::agent_identity_envelope::load_activation(state.as_ref(), agent_pid)
                .map(|a| matches!(a.state, connector_trust::ActivationStateV2::Active))
                .unwrap_or(false);
        if !active {
            return Err(
                ConnectorError::new(DenialReason::PolicyDenied, "agent_not_activated")
                    .with_hint(
                        "POST /agents/:pid/setup then POST /agents/:pid/activate before Talk",
                    )
                    .with_agent_scope(agent_pid),
            );
        }
    }
    Ok(())
}

pub(crate) fn llm_stub_blocked_in_prod() -> bool {
    let stub = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !stub {
        return false;
    }
    let allow = std::env::var("CONNECTOR_LLM_STUB_ALLOW_IN_PROD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    crate::connector_profile::is_productionish_env() && !allow
}

pub(crate) fn reserve_playground_talk_budget(
    state: &SharedState,
    session_id: &str,
    input_chars: usize,
    max_output_tokens: u32,
) -> Result<(), ConnectorError> {
    if !session_id.starts_with("pg_") {
        return Ok(());
    }
    let reserved = (input_chars as u64 / 4)
        .saturating_add(1)
        .saturating_add(max_output_tokens as u64);
    if crate::services::playground::record_token_usage(
        &state.playground_sessions,
        session_id,
        reserved,
    ) {
        return Ok(());
    }
    Err(ConnectorError::new(
        DenialReason::RateLimitExceeded,
        "playground_token_budget_exhausted",
    )
    .with_denied_resource("llm.playground_budget")
    .with_hint("Start a new playground session or use an authenticated node account"))
}

/// Hard cap on Talk waiting for upstream LLM (retries included).
fn talk_llm_wall_timeout() -> std::time::Duration {
    if crate::services::playground::is_playground_mode() {
        std::env::var("CONNECTOR_PLAYGROUND_TALK_LLM_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(75))
    } else {
        std::time::Duration::from_secs(180)
    }
}

/// Playground Talk inject — keep the async worker free (/health must not freeze).
/// When `light` is true (stub / unwired), skip N4 bind + broker + agentic HITL stack.
fn inject_playground_talk_light(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
    model_ref: &str,
    provider: &str,
    light: bool,
) -> Result<(), ConnectorError> {
    crate::services::agents::ensure_playground_talk_lane(state, agent_pid);
    if !light {
        return inject_talk_identity_messages(state, agent_pid, messages, model_ref, provider);
    }
    if let Some(who) =
        crate::kernel::agent_foundation::who_am_i_authoritative(state.as_ref(), agent_pid)
    {
        inject_connector_identity(messages, &who);
    } else {
        inject_playground_identity_fallback(state, agent_pid, messages);
    }
    inject_hard_agent_charter(state.as_ref(), agent_pid, messages);
    inject_vendor_brain_denial(state.as_ref(), agent_pid, messages);
    Ok(())
}

/// Kernel identity + charter — required on every Talk path (including playground fast).
fn inject_talk_identity_messages(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
    model_ref: &str,
    provider: &str,
) -> Result<(), ConnectorError> {
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(state, agent_pid);
    }
    // Obey-Once bind + per-work identity envelope (GovernedTalkCore).
    let _work_unit = inject_work_unit_envelope(state, agent_pid, messages, model_ref, provider)?;
    // Broker tokens are opaque — the model still needs plaintext who_am_i for identity questions.
    if let Some(who) =
        crate::kernel::agent_foundation::who_am_i_authoritative(state.as_ref(), agent_pid)
    {
        inject_connector_identity(messages, &who);
    } else if crate::services::playground::is_playground_mode() {
        inject_playground_identity_fallback(state, agent_pid, messages);
    }
    if crate::substrate::llm_context_broker::broker_enforced() {
        let ctx = crate::substrate::agentic_context::require_or_hitl(state, agent_pid)?;
        let binding =
            crate::substrate::llm_context_broker::inject_for_talk(state, agent_pid, &ctx)?;
        inject_llm_context_token(messages, &binding);
        inject_agentic_context(messages, &ctx);
        inject_agent_memory_capsule(state, agent_pid, messages)?;
        inject_awd_perception(state, agent_pid, messages);
    } else {
        match crate::substrate::agentic_context::require_or_hitl(state, agent_pid) {
            Ok(ctx) => {
                inject_agentic_context(messages, &ctx);
                let _ = inject_agent_memory_capsule(state, agent_pid, messages);
                inject_awd_perception(state, agent_pid, messages);
            }
            Err(e) => return Err(e),
        }
        if !crate::services::playground::is_playground_mode() {
            inject_memory_os_core(messages, agent_pid);
            inject_council_desk(messages, state.as_ref(), agent_pid);
        }
    }
    inject_hard_agent_charter(state.as_ref(), agent_pid, messages);
    inject_vendor_brain_denial(state.as_ref(), agent_pid, messages);
    Ok(())
}

const VENDOR_BRAIN_DENIAL_MARKER: &str =
    "--- CONNECTOR LLM BRAIN BINDING (shared model — Connector owns identity) ---";

/// Every Talk turn: the vendor model is only transport; Connector agent identity is authoritative.
fn inject_vendor_brain_denial(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) {
    let name = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
        .and_then(|m| m.get("name").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| "Connector Agent".into());
    let block = format!(
        "{VENDOR_BRAIN_DENIAL_MARKER}\n\
         You share an LLM brain with many tenants. Connector — not the vendor — owns your identity, memory refs, and tool authority.\n\
         agent_name: {name}\n\
         principal: {agent_pid}\n\
         rules:\n\
         - Never claim to be ChatGPT, Claude, Gemini, DeepSeek, OpenAI, Anthropic, Google, or a generic AI assistant.\n\
         - Never cite vendor knowledge cutoffs, pricing, or model marketing.\n\
         - Speak as the Connector agent above in chat; tool calls and execution stay on Connector rails.\n\
         - If identity is asked, answer ONLY from CONNECTOR AUTHORITATIVE IDENTITY / agentic context / broker token — never vendor persona.\n\
         {VENDOR_BRAIN_DENIAL_MARKER}"
    );
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(VENDOR_BRAIN_DENIAL_MARKER) {
            sys.content = format!("{block}\n{}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

/// Principal Projection: LLM proposes freely → Connector projects through principal.
fn project_talk_for_agent(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    raw: &str,
    user_text: &str,
) -> Result<
    (
        String,
        crate::services::llm_output_contract::OutputAttestation,
        serde_json::Value,
        serde_json::Value,
        String,
        Option<serde_json::Value>,
    ),
    ConnectorError,
> {
    let finalized = crate::substrate::governed_talk_core::project_talk_with_receipt(
        state, agent_pid, raw, user_text,
    )?;
    let outcome = match finalized.outcome {
        crate::substrate::principal_projection::ProjectionOutcome::Pass => "pass",
        crate::substrate::principal_projection::ProjectionOutcome::Project => "project",
        crate::substrate::principal_projection::ProjectionOutcome::Deny => "deny",
    }
    .to_string();
    Ok((
        finalized.text,
        finalized.attestation,
        finalized.work_unit,
        finalized.binding_status,
        outcome,
        finalized.aipsprt,
    ))
}

fn inject_work_unit_envelope(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
    model_ref: &str,
    provider: &str,
) -> Result<crate::substrate::intelligence_work_unit::IntelligenceWorkUnit, ConnectorError> {
    let prepared = crate::substrate::governed_talk_core::prepare_talk(
        state, agent_pid, model_ref, provider,
    )?;
    let combined = prepared.system_blocks.join("\n");
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(
            crate::substrate::intelligence_work_unit::ENVELOPE_MARKER,
        ) && !sys.content.contains(
            crate::substrate::intelligence_binding::BIND_MARKER,
        ) {
            sys.content = format!("{combined}\n{}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: combined,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
    Ok(prepared.work_unit)
}

fn inject_playground_identity_fallback(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) {
    let Some(meta) = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
    else {
        return;
    };
    let name = meta
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("Demo");
    let namespace = meta
        .get("namespace")
        .and_then(|x| x.as_str())
        .unwrap_or("m/demo");
    let purpose = meta
        .get("purpose")
        .and_then(|x| x.as_str())
        .unwrap_or("playground:demo");
    let block = format!(
        "Name: {name}\n\
         Acume/Purpose: {purpose}\n\
         AgentID (principal): {agent_pid}\n\
         Namespace: {namespace}\n\
         When asked who I am, I answer ONLY from this kernel block — not from the LLM vendor."
    );
    inject_connector_identity(messages, &block);
}

/// Hosted trial Talk — snapshot-driven inject + real LLM (no kernel chip short-circuits).
async fn playground_talk_fast(
    state: SharedState,
    headers: HeaderMap,
    req: ChatCompletionRequest,
    created: i64,
) -> Result<axum::response::Response, ConnectorError> {
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .unwrap_or_default();
    let (session_id, agent_pid, _dg_role) =
        resolve_talk_agent_context(&state, &api_key, &headers, &req)?;
    if gateway_anon_ban_enabled() && is_synthetic_gateway_pid(&agent_pid) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "anonymous_gateway_talk_banned",
        )
        .with_hint(
            "Use POST /api/v1/agents/:pid/completions with a registered Active agent",
        )
        .with_agent_scope(&agent_pid));
    }

    let outer = crate::substrate::talk_turn_pipeline::outer_session_lease_held(&headers);
    let talk_permit = if outer {
        None
    } else {
        Some(state.bulkheads.try_acquire_talk().map_err(|e| {
            ConnectorError::new(DenialReason::RateLimitExceeded, e).with_agent_scope(&agent_pid)
        })?)
    };
    let _session_lease = if outer {
        None
    } else {
        Some(state.session_owners.try_acquire(&agent_pid).map_err(|e| {
            ConnectorError::new(DenialReason::RateLimitExceeded, e)
                .with_hint("Another Talk turn is in flight for this agent — retry shortly")
                .with_agent_scope(&agent_pid)
        })?)
    };

    let last_user_msg = req
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("(empty)");

    let tenant_id = crate::services::playground::playground_session_id_from_headers(&headers)
        .unwrap_or_else(|| session_id.clone());

    let prepare_ms = std::env::var("CONNECTOR_TALK_PREPARE_BUDGET_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);
    let provider_ms = talk_llm_wall_timeout().as_millis() as u64;
    let last_user_owned = last_user_msg.to_string();
    let ctx = {
        let state_c = std::sync::Arc::clone(&state);
        let tid = tenant_id.clone();
        let pid = agent_pid.clone();
        let sid = session_id.clone();
        let body = last_user_owned.clone();
        tokio::task::spawn_blocking(move || {
            crate::substrate::talk_turn_pipeline::begin_talk_turn(
                &state_c,
                &tid,
                &pid,
                &sid,
                &body,
                provider_ms,
                prepare_ms,
            )
        })
        .await
        .map_err(|e| ConnectorError::internal(format!("talk_turn_begin_join: {e}")))??
    };
    let snap = ctx.snapshot;
    let turn = ctx.envelope;

    if crate::kernel::agent_principal::load_principal(state.as_ref(), &agent_pid).is_none() {
        return Err(
            ConnectorError::new(DenialReason::PolicyDenied, "unknown_principal")
                .with_hint("Register agent and mint principal before Talk")
                .with_agent_scope(&agent_pid),
        );
    }
    if llm_stub_blocked_in_prod() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "llm_stub_banned_in_production",
        )
        .with_hint(
            "Unset CONNECTOR_LLM_STUB or set CONNECTOR_LLM_STUB_ALLOW_IN_PROD=1 for break-glass",
        ));
    }
    if crate::services::settings_llms::talk_llm_wired(&state, &headers, &agent_pid) {
        crate::services::settings_llms::restore_llm_router_for_talk(
            &state,
            &headers,
            Some(&agent_pid),
        );
    }
    let budget_session = crate::services::playground::playground_session_id_from_headers(&headers)
        .unwrap_or(session_id.clone());
    reserve_playground_talk_budget(
        &state,
        &budget_session,
        req.messages.iter().map(|m| m.content.len()).sum(),
        req.max_tokens.unwrap_or(1024),
    )?;

    let talk_wired =
        crate::services::settings_llms::talk_llm_wired(&state, &headers, &agent_pid);
    let stub_mode = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
        && !talk_wired;

    let mut messages_for_llm = req.messages.clone();
    // Snapshot inject: O(1) static identity/charter/capabilities — no per-turn lane rebuild.
    for (i, (role, content)) in snap.inject_static_system_blocks().into_iter().enumerate() {
        messages_for_llm.insert(
            i,
            ChatMessage {
                role,
                content,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
    // GovernedTalkCore prepare (Obey-Once + work unit) — off async worker (INV-01).
    if !stub_mode && crate::substrate::talk_turn_pipeline::governed_prepare_enabled() {
        let state_c = std::sync::Arc::clone(&state);
        let pid = agent_pid.clone();
        let model = req.model.clone();
        let provider = talk_provider_hint(&req.model).to_string();
        let extra = tokio::task::spawn_blocking(move || {
            let mut blocks: Vec<(String, String)> = Vec::new();
            crate::substrate::talk_turn_pipeline::append_governed_prepare_blocks(
                &state_c,
                &pid,
                &model,
                &provider,
                &mut blocks,
            )?;
            Ok::<_, ConnectorError>(blocks)
        })
        .await
        .map_err(|e| ConnectorError::internal(format!("governed_prepare_join: {e}")))??;
        let base = snap.inject_static_system_blocks().len();
        for (i, (role, content)) in extra.into_iter().enumerate() {
            messages_for_llm.insert(
                base + i,
                ChatMessage {
                    role,
                    content,
                    reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            );
        }
    }

    let (
        response_text,
        prompt_tokens,
        completion_tokens,
        served_model,
        served_provider,
        reasoning_content,
    ) = if stub_mode {
        let stub_reply = format!(
            "Hi! I'm {} (principal {}). You asked: \"{}\" \
             This reply is CONNECTOR_LLM_STUB simulation (no live provider call). \
             Paste an LLM key under Settings → LLM for real routing.",
            snap.agent_name,
            agent_pid,
            &last_user_msg[..last_user_msg.len().min(120)]
        );
        let input_toks = messages_for_llm
            .iter()
            .map(|m| m.content.len() / 4 + 1)
            .sum::<usize>() as u32;
        (
            stub_reply,
            input_toks,
            42u32,
            Some("stub".to_string()),
            Some("stub".to_string()),
            None,
        )
    } else if crate::kernel::landlock_child::llm_cage_enforced() {
        let st = state.clone();
        let pid = agent_pid.clone();
        let msgs = messages_for_llm.clone();
        let max = req.max_tokens;
        let temp = req.temperature;
        tokio::task::spawn_blocking(move || {
            talk_via_llm_cage(st.as_ref(), &pid, &msgs, max, temp)
        })
        .await
        .map_err(|e| ConnectorError::internal(format!("llm_cage_join:{e}")))??
    } else {
        let llm_router =
            crate::services::settings_llms::talk_llm_router(&state, &headers, &agent_pid)
                .ok_or_else(|| {
                    ConnectorError::new(
                        DenialReason::InternalError,
                        "LLM provider not configured. Paste key in Settings → LLM or: connectorctl llm link",
                    )
                })?;
        let overrides = talk_generation_overrides(
            state.as_ref(),
            &agent_pid,
            req.max_tokens,
            req.temperature,
        );
        let engine_msgs = engine_chat_messages(&messages_for_llm);
        let inflight_id = format!("gw_{}", uuid::Uuid::new_v4().simple());
        let _inflight = crate::substrate::llm_inflight::InflightGuard::register(
            &agent_pid,
            "llm_router",
            &inflight_id,
            None,
        );
        let chat_result = tokio::time::timeout(
            talk_llm_wall_timeout(),
            llm_router.chat_with_overrides(engine_msgs, overrides),
        )
        .await;
        drop(_inflight);
        let (response_text, prompt_tokens, completion_tokens, served_model, served_provider, reasoning_content) =
        match chat_result
        {
            Err(_) => {
                return Err(ConnectorError::internal(
                    "LLM request timed out waiting for the provider. \
                     The API key may be valid but this host could not reach the vendor in time.",
                )
                .with_denied_resource("llm.provider_timeout")
                .with_hint(
                    "Retry Talk; if it persists, try another provider or check vendor egress from this host.",
                ));
            }
            Ok(Ok(resp)) => (
                resp.text,
                resp.input_tokens,
                resp.output_tokens,
                Some(resp.model),
                Some(resp.provider),
                resp.reasoning_content,
            ),
            Ok(Err(e)) => {
                return Err(ConnectorError::internal(format!(
                    "LLM router error: {}. Check provider config and API key.",
                    e
                )));
            }
        };
        (
            response_text,
            prompt_tokens,
            completion_tokens,
            served_model,
            served_provider,
            reasoning_content,
        )
    };

    let _ = (served_provider, talk_permit);
    let total_tokens = prompt_tokens + completion_tokens;
    let call_id = format!("chatcmpl-{}", uuid::Uuid::new_v4().as_simple());
    let client_attribution = extract_gateway_client_attribution(&headers);
    let (response_text, output_attestation, work_unit_json, binding_json, projection_outcome, aipsprt) =
        project_talk_for_agent(state.as_ref(), &agent_pid, &response_text, last_user_msg)?;
    let resp_body = ChatCompletionResponse {
        id: call_id,
        object: "chat.completion".to_string(),
        created,
        model: served_model.clone().unwrap_or_else(|| req.model.clone()),
        choices: vec![ChatCompletionChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: response_text,
                reasoning_content,
                tool_calls: None,
                tool_call_id: None,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: ChatCompletionUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        },
        audit_cid: None,
        estimated_cost_usd: None,
        client: client_attribution.client,
        client_origin: client_attribution.origin,
        client_user_agent: client_attribution.user_agent,
        llm_mode: Some(if stub_mode {
            "simulation".into()
        } else {
            "live".into()
        }),
        honesty: Some(if stub_mode {
            "CONNECTOR_LLM_STUB — snapshot inject; paste Settings → LLM for live routing".into()
        } else {
            format!(
                "snapshot_v{} · turn {} · real LLM via Connector proxy",
                snap.snapshot_version, turn.turn_id
            )
        }),
        connector_output_attestation: output_attestation,
        connector_identity_work_unit: Some(work_unit_json),
        connector_intelligence_binding: Some(binding_json),
        connector_projection_outcome: Some(projection_outcome.clone()),
        connector_turn_envelope: Some(turn.to_json()),
        connector_aipsprt: aipsprt,
    };
    crate::substrate::authority_evidence::record_talk_turn(
        state.as_ref(),
        &turn,
        if stub_mode { "talk_stub" } else { "talk_live" },
        served_model.as_deref(),
        Some(projection_outcome.as_str()),
    );
    let aipsprt_hdr = encode_aipsprt_header_value(&resp_body.connector_aipsprt);
    let mut response = Json(resp_body).into_response();
    if let Some(h) = aipsprt_hdr {
        if let Ok(v) = axum::http::HeaderValue::from_str(&h) {
            response
                .headers_mut()
                .insert(connector_trust::AIPSPRT_HEADER, v);
        }
    }
    Ok(response)
}

fn encode_aipsprt_header_value(aipsprt: &Option<serde_json::Value>) -> Option<String> {
    let v = aipsprt.as_ref()?;
    let p: connector_trust::AiPassportSigV1 = serde_json::from_value(v.clone()).ok()?;
    connector_trust::encode_aipsprt_header(&p).ok()
}

/// Playground streaming — identical snapshot Talk turn, then GovernedStreamGate chunks (INV-04/19).
async fn playground_talk_stream(
    state: SharedState,
    headers: HeaderMap,
    req: ChatCompletionRequest,
    created: i64,
) -> axum::response::Response {
    let resp = match playground_talk_fast(state, headers, req, created).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let body_bytes = match axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return ConnectorError::internal(format!("stream_body_read: {e}")).into_response();
        }
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body_bytes,
            )
                .into_response();
        }
    };
    let text = parsed
        .pointer("/choices/0/message/content")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let chunks =
        crate::substrate::governed_stream_gate::chunk_projected_text(&text, 28);
    let call_id = parsed
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("chatcmpl-stream")
        .to_string();
    let model = parsed
        .get("model")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let prompt_tokens = parsed
        .pointer("/usage/prompt_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let completion_tokens = parsed
        .pointer("/usage/completion_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let total_tokens = parsed
        .pointer("/usage/total_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(prompt_tokens + completion_tokens);
    let attestation = parsed.get("connector_output_attestation").cloned();
    let work_unit = parsed.get("connector_identity_work_unit").cloned();
    let binding = parsed.get("connector_intelligence_binding").cloned();
    let projection = parsed.get("connector_projection_outcome").cloned();
    let turn_env = parsed.get("connector_turn_envelope").cloned();
    let aipsprt = parsed.get("connector_aipsprt").cloned();

    let stream = async_stream::stream! {
        for chunk_text in chunks {
            let chunk = serde_json::json!({
                "id": call_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": { "role": "assistant", "content": chunk_text },
                    "finish_reason": null
                }]
            });
            yield Ok::<Event, Infallible>(
                Event::default().event("message").data(chunk.to_string())
            );
        }
        let final_chunk = serde_json::json!({
            "id": call_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "connector_output_attestation": attestation,
            "connector_identity_work_unit": work_unit,
            "connector_intelligence_binding": binding,
            "connector_projection_outcome": projection,
            "connector_turn_envelope": turn_env,
            "connector_aipsprt": aipsprt,
            "governed_stream": true,
        });
        yield Ok::<Event, Infallible>(
            Event::default().event("message").data(final_chunk.to_string())
        );
        if let Some(ref p) = aipsprt {
            yield Ok::<Event, Infallible>(
                Event::default()
                    .event("aipsprt")
                    .data(p.to_string())
            );
        }
        yield Ok::<Event, Infallible>(Event::default().event("done").data("[DONE]"));
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── OpenAI-compatible request/response types ─────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// Provider reasoning to pass back on tool/multi-turn loops (DeepSeek etc.).
    /// Session continuity only — not auditable memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// Optional agent_pid for audit attribution.
    #[serde(default)]
    pub agent_pid: Option<String>,
    /// Optional namespace for memory write.
    #[serde(default)]
    pub namespace: Option<String>,
    /// OpenAI-compat tools — blocked under Ring-1 without N4 CPO header.
    #[serde(default)]
    pub tools: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    /// B15: optional Talk thread id for persistence (`POST /agents/:pid/completions`).
    #[serde(default)]
    pub thread_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: i64,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
    pub usage: ChatCompletionUsage,
    /// Connector-specific: audit CID for this LLM call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_cid: Option<String>,
    /// Connector-specific: estimated cost in USD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
    /// Connector-specific: client attribution for this gateway call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Connector-specific: client origin for this gateway call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_origin: Option<String>,
    /// Connector-specific: user agent seen by the gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_user_agent: Option<String>,
    /// Connector-specific: `simulation` when CONNECTOR_LLM_STUB is on; else `live`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_mode: Option<String>,
    /// Connector-specific honesty banner for clients that ignore llm_mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honesty: Option<String>,
    /// Kernel-issued proof that deterministic identity/character invariants passed.
    pub connector_output_attestation: crate::services::llm_output_contract::OutputAttestation,
    /// Per-invocation identity envelope metadata (for whom the LLM worked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_identity_work_unit: Option<serde_json::Value>,
    /// Obey-Once binding status for this Talk turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_intelligence_binding: Option<serde_json::Value>,
    /// Principal Projection outcome: pass | project | deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_projection_outcome: Option<String>,
    /// TurnEnvelope — canonical turn identity (generations + deadline).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_turn_envelope: Option<serde_json::Value>,
    /// AiPassport leave-behind (sibling to choices content).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_aipsprt: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct GatewayClientAttribution {
    client: Option<String>,
    origin: Option<String>,
    user_agent: Option<String>,
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn talk_provider_hint(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    if m.contains("deepseek") {
        "deepseek"
    } else if m.contains("claude") {
        "anthropic"
    } else if m.contains("gemini") {
        "google"
    } else if m.contains("gpt") || m.contains("o1") || m.contains("o3") {
        "openai"
    } else {
        "openai-compat"
    }
}

fn extract_gateway_client_attribution(headers: &HeaderMap) -> GatewayClientAttribution {
    GatewayClientAttribution {
        client: header_string(headers, "x-connector-client"),
        origin: header_string(headers, "x-connector-origin"),
        user_agent: header_string(headers, "user-agent"),
    }
}

/// Shared RAG recall for OpenAI + Anthropic gateways (B3 parity).
/// VAC similarity block is unchanged. WM SoT is prepended only when /m or /k hits exist.
///
/// Prefer [`crate::concurrency::kernel_handle::build_agent_rag_context_async`] from async
/// handlers so this never runs on a tokio worker thread under a held kernel lock.
pub fn playground_rag_enabled() -> bool {
    // Hosted playground: RAG is opt-in. Default off so Talk cannot freeze /health.
    if !crate::services::playground::is_playground_mode() {
        return true;
    }
    match std::env::var("CONNECTOR_PLAYGROUND_RAG") {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

pub fn build_agent_rag_context(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    fallback_namespace: &str,
    user_query: &str,
) -> String {
    if !playground_rag_enabled() {
        return String::new();
    }
    if user_query.trim().is_empty() {
        return String::new();
    }
    let kernel_pid = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("agent_meta", agent_pid)
            .ok()
            .flatten()
            .and_then(|m| {
                m.get("kernel_pid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| agent_pid.to_string())
    };
    let mut kernel = state.kernel.lock().unwrap();
    let primary_ns = kernel
        .get_agent(&kernel_pid)
        .map(|a| a.namespace.clone())
        .unwrap_or_else(|| fallback_namespace.to_string());
    let mut recalled = kernel.recall_by_similarity(user_query, &primary_ns, 15);
    if recalled.is_empty() {
        for ns in crate::services::agents::memory_namespace_dual_read(&kernel_pid, agent_pid) {
            if ns == primary_ns {
                continue;
            }
            recalled = kernel.recall_by_similarity(user_query, &ns, 15);
            if !recalled.is_empty() {
                break;
            }
        }
    }
    drop(kernel);
    // L2: stamp observed VAC CIDs / namespaces into the IntelligenceCell read-set.
    {
        let cell = state.cells.get_or_create(agent_pid);
        let cids: Vec<String> = recalled.iter().map(|d| d.cid.clone()).collect();
        let nss = if recalled.is_empty() {
            vec![primary_ns.clone()]
        } else {
            recalled
                .iter()
                .map(|d| d.namespace.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let broker = 0u64; // broker epoch stamped at Talk admit; RAG stamp is evidence-only
        cell.stamp_read_set_full(Vec::new(), nss, cids, broker);
    }
    let vac = if recalled.is_empty() {
        String::new()
    } else {
        let mut ctx = String::from(
            "=== AGENT MEMORY (retrieved facts — prefer when relevant; do not invent memories) ===\n",
        );
        for (i, doc) in recalled.iter().enumerate() {
            ctx.push_str(&format!("[MEM-{}] {}\n", i + 1, doc.text));
        }
        ctx.push_str(
            "=== END AGENT MEMORY ===\n\
         Use these facts for prior context. You may still answer general questions and do other \
         work when memory does not apply; never contradict authoritative identity.\n\n",
        );
        ctx
    };
    let sot = crate::kernel::operating_layer::wm_sot_prompt(Some(state), agent_pid, user_query);
    if sot.is_empty() {
        return vac;
    }
    if vac.is_empty() {
        return sot;
    }
    format!("{sot}\n{vac}")
}

/// Inject kernel-authoritative identity so the LLM answers "who am I?" from the foundation block.
fn inject_connector_identity(messages: &mut Vec<ChatMessage>, identity: &str) {
    const MARKER: &str = "--- CONNECTOR AUTHORITATIVE IDENTITY (never contradict) ---";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(MARKER) {
            sys.content = format!("{}\n{MARKER}\n{identity}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: format!("{MARKER}\n{identity}"),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

fn inject_agentic_context(messages: &mut Vec<ChatMessage>, ctx: &crate::substrate::agentic_context::AgenticContext) {
    let block = ctx.render_prompt();
    let marker = crate::substrate::agentic_context::MARKER;
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

fn inject_agent_memory_capsule(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) -> Result<(), ConnectorError> {
    if !crate::substrate::agent_memory::enabled() {
        return Ok(());
    }
    if !crate::substrate::cvr::runtime_adapter::injection_allowed(state, agent_pid) {
        tracing::info!(
            agent_pid = %agent_pid,
            "memory epoch sealed — capsule not injected as live context"
        );
        return Ok(());
    }
    let block = crate::substrate::agent_memory::capsule::gateway_injection_block(
        state.as_ref(),
        agent_pid,
        1,
    )
    .map_err(|e| {
        ConnectorError::new(DenialReason::PolicyDenied, e).with_denied_resource("agent_memory.capsule")
    })?;
    let marker = "[connector.agent_memory_capsule]";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
    Ok(())
}

fn inject_awd_perception(state: &SharedState, agent_pid: &str, messages: &mut Vec<ChatMessage>) {
    let Some(block) = crate::substrate::awd::perception_block(state, agent_pid) else {
        return;
    };
    let marker = "[connector.awd.perception]";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

/// SVF PROJECT (S0/S1) — beside agentic who-am-I, never instead of it.
fn inject_svf_projection(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) {
    let Some(block) = crate::substrate::svf::gateway_injection_block(state, agent_pid) else {
        return;
    };
    let marker = crate::substrate::svf::project::MARKER;
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
    // Progressive tool stubs (S0) — EXPAND for schema.
    if let Some(stubs) = crate::substrate::svf::gateway_tool_stub_block(state, agent_pid) {
        let stub_marker = "[connector.svf.tool_stubs]";
        if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
            if !sys.content.contains(stub_marker) {
                sys.content = format!("{}\n{stubs}", sys.content);
            }
        }
    }
}

/// RangeGuard transfer — typed frames with digest bind; not a substitute for identity/capsule.
fn inject_crk_transfer(
    state: &SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
    model_ref: &str,
    provider: &str,
) -> Result<(), ConnectorError> {
    let action_digest = {
        let q: String = messages
            .iter()
            .filter(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let h = format!("{:x}", Sha256::digest(q.as_bytes()));
        format!("talk:{}", &h[..h.len().min(16)])
    };
    let bound = crate::substrate::crk::talk_bind::bind_for_talk(
        state,
        agent_pid,
        &action_digest,
        None,
        "low",
        2048,
        "default",
        Some(provider),
        Some(model_ref),
    )
    .map_err(|e| {
        ConnectorError::new(DenialReason::PolicyDenied, e).with_denied_resource("crk.transfer")
    })?;
    crate::substrate::crk::transfer::assert_render_matches(&bound.transfer, &bound.exact_render)
        .map_err(|e| {
            ConnectorError::new(DenialReason::PolicyDenied, e)
                .with_denied_resource("crk.transfer_mismatch")
        })?;
    let marker = crate::substrate::crk::talk_bind::MARKER;
    let header = format!(
        "{marker}\ntransfer_id: {}\ntransfer_digest: {}\ncrk_state: {}\nmoment_range_id: {}\n",
        bound.transfer.transfer_id,
        bound.transfer.transfer_digest(),
        bound.state.as_str(),
        bound.range.moment_range_id,
    );
    let block = format!("{header}{}", bound.exact_render);
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
    Ok(())
}

/// Inject opaque broker token into OpenAI-style messages (no plaintext who-am-I).
fn inject_llm_context_token(
    messages: &mut Vec<ChatMessage>,
    binding: &crate::substrate::llm_context_broker::LlmContextBinding,
) {
    let block = binding.render_tokenized_prompt();
    let marker = crate::substrate::llm_context_broker::MARKER;
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(marker) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

/// Pin Letta-class core RAM into Talk (persona + human). Archival stays on-demand via syscall.
pub(crate) fn memory_os_core_prompt(agent_pid: &str) -> String {
    let _ = crate::kernel::aios::ensure_memory_os(agent_pid);
    let _ = crate::kernel::aios::page_core_if_full(agent_pid);
    let persona = crate::kernel::aios::core_get(agent_pid, "persona")
        .ok()
        .and_then(|v| {
            v.get("value")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    let human = crate::kernel::aios::core_get(agent_pid, "human")
        .ok()
        .and_then(|v| {
            v.get("value")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();
    let wm = crate::kernel::operating_layer::wm_prompt(agent_pid);
    if persona.trim().is_empty() && human.trim().is_empty() {
        return format!("--- CONNECTOR WM (syscalls — vendor-blind) ---\n{wm}");
    }
    format!(
        "--- CONNECTOR MEMORY OS CORE (RAM — you may request memory.core.set via syscall) ---\n\
         persona: {persona}\nhuman: {human}\n{wm}"
    )
}

fn inject_memory_os_core(messages: &mut Vec<ChatMessage>, agent_pid: &str) {
    let block = memory_os_core_prompt(agent_pid);
    if block.starts_with("--- CONNECTOR WM") {
        const WM_ONLY: &str = "--- CONNECTOR WM (syscalls — vendor-blind) ---";
        if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
            if !sys.content.contains(WM_ONLY) {
                sys.content = format!("{}\n{block}", sys.content);
            }
        } else {
            messages.insert(
                0,
                ChatMessage {
                    role: "system".into(),
                    content: block,
                    reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
            );
        }
        return;
    }
    const MARKER: &str =
        "--- CONNECTOR MEMORY OS CORE (RAM — you may request memory.core.set via syscall) ---";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(MARKER) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

fn inject_council_desk(
    messages: &mut Vec<ChatMessage>,
    state: &crate::state::PlatformState,
    agent_pid: &str,
) {
    let desk = crate::kernel::council::desk_prompt(state, agent_pid);
    if desk.trim().is_empty() {
        return;
    }
    const MARKER: &str = "--- CONNECTOR COUNCIL DESK";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(MARKER) {
            sys.content = format!("{}\n{desk}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: desk,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

fn note_talk_crossing(agent_pid: &str, messages: &[ChatMessage], response: &str, stub: bool) {
    if stub {
        crate::kernel::operating_layer::record(
            crate::kernel::operating_layer::Socket::Completion,
            agent_pid,
            "llm.complete",
            true,
            &serde_json::json!({ "stub": true }),
        );
    }
    if let Some(user) = messages
        .iter()
        .rev()
        .find(|m| m.role.eq_ignore_ascii_case("user"))
    {
        let clip: String = user.content.chars().take(2000).collect();
        let _ = crate::kernel::aios::recall_append(agent_pid, "user", &clip);
    }
    let clip: String = response.chars().take(4000).collect();
    let _ = crate::kernel::aios::recall_append(agent_pid, "assistant", &clip);
}

pub const HARD_CHARTER_MARKER: &str = "--- CONNECTOR HARD CHARTER (follow exactly) ---";

fn join_value_list(v: &serde_json::Value, keys: &[&str]) -> String {
    match v {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| {
                if let Some(s) = item.as_str() {
                    return Some(s.to_string());
                }
                for k in keys {
                    if let Some(s) = item.get(*k).and_then(|x| x.as_str()) {
                        if !s.trim().is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
                None
            })
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

/// Operator-authored job (name, purpose, instructions, knowledge, skills, rules).
/// Talk must follow these — they are not optional prompt flavor.
pub fn render_hard_charter(
    name: &str,
    purpose: &str,
    instructions: &str,
    knowledge: &str,
    skills: &str,
    rules: &str,
    denied: &str,
    model: &str,
) -> String {
    let mut out = String::from(HARD_CHARTER_MARKER);
    out.push_str(
        "\nThese parameters are hard. Follow them exactly. Do not invent a different role, job, or facts.\n",
    );
    if !name.trim().is_empty() {
        out.push_str(&format!("name: {}\n", name.trim()));
    }
    if !purpose.trim().is_empty() {
        out.push_str(&format!("purpose:\n{}\n", purpose.trim()));
    }
    if !instructions.trim().is_empty() {
        out.push_str(&format!("instructions:\n{}\n", instructions.trim()));
    }
    if !knowledge.trim().is_empty() {
        out.push_str(&format!("knowledge:\n{}\n", knowledge.trim()));
    }
    if !skills.trim().is_empty() {
        out.push_str(&format!("skills:\n{}\n", skills.trim()));
    }
    if !rules.trim().is_empty() {
        out.push_str(&format!("rules:\n{}\n", rules.trim()));
    }
    if !denied.trim().is_empty() {
        out.push_str(&format!("denied_operations:\n{}\n", denied.trim()));
    }
    if !model.trim().is_empty() {
        out.push_str(&format!("model: {}\n", model.trim()));
    }
    out.push_str(
        "stance: Answer as this Connector agent only — never as the underlying LLM vendor. \
         Prefer purpose, instructions, and knowledge over generic chatter. \
         Do not claim ChatGPT/Claude/Gemini/DeepSeek/OpenAI/Anthropic/Google identity or vendor marketing. \
         Tool calls and execution effects remain on Connector contract rails; chat persona follows this charter.\n",
    );
    out.push_str(HARD_CHARTER_MARKER);
    out
}

/// Public for AgentRuntimeSnapshot compile (control plane) — not a Talk hot-path API.
pub fn collect_hard_charter(state: &crate::state::PlatformState, agent_pid: &str) -> String {
    let meta = state.engine_store.lock().ok().and_then(|es| {
        es.folder_get("agent_meta", agent_pid).ok().flatten()
    });
    let spec = crate::kernel::intelligence_spec::load_spec_doc(state, agent_pid);
    let skills = crate::kernel::intelligence_spec::load_bound_skills(state, agent_pid);
    let rules = crate::kernel::intelligence_spec::load_rules(state, agent_pid);
    let contract = crate::kernel::agent_principal::load_contract(state, agent_pid);

    let name = meta
        .as_ref()
        .and_then(|m| m.get("name").and_then(|x| x.as_str()))
        .or_else(|| spec.as_ref().and_then(|s| s.pointer("/metadata/name").and_then(|x| x.as_str())))
        .unwrap_or("")
        .to_string();
    let purpose = meta
        .as_ref()
        .and_then(|m| m.get("purpose").and_then(|x| x.as_str()))
        .or_else(|| spec.as_ref().and_then(|s| s.pointer("/spec/purpose").and_then(|x| x.as_str())))
        .or_else(|| {
            contract.as_ref().and_then(|c| c.purpose.first().map(String::as_str))
        })
        .unwrap_or("")
        .to_string();
    let instructions = meta
        .as_ref()
        .and_then(|m| m.get("instructions").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let mut knowledge = meta
        .as_ref()
        .and_then(|m| m.get("knowledge").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    if knowledge.trim().is_empty() {
        if let Some(seeds) = spec.as_ref().and_then(|s| s.pointer("/spec/knowledge")) {
            knowledge = join_value_list(seeds, &["content", "body", "text"]);
        }
    }
    if knowledge.len() > 32_000 {
        knowledge.truncate(32_000);
        knowledge.push_str("\n[knowledge truncated]");
    }
    let skills_text = skills
        .iter()
        .filter_map(|s| {
            s.get("capability")
                .and_then(|x| x.as_str())
                .map(|c| c.to_string())
        })
        .collect::<Vec<_>>()
        .join("\n");
    let rules_text = join_value_list(&rules, &["note", "when", "action", "id"]);
    let denied = contract
        .as_ref()
        .map(|c| c.denied_operations.join(", "))
        .unwrap_or_default();
    let model = meta
        .as_ref()
        .and_then(|m| m.get("model").and_then(|x| x.as_str()))
        .map(|s| s.to_string())
        .or_else(|| {
            spec.as_ref()
                .and_then(|s| s.pointer("/spec/parameters/model").and_then(|x| x.as_str()))
                .map(|s| s.to_string())
        })
        .or_else(|| {
            state
                .llm_config_snapshot()
                .map(|c| c.model)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default();

    render_hard_charter(
        &name,
        &purpose,
        &instructions,
        &knowledge,
        &skills_text,
        &rules_text,
        &denied,
        &model,
    )
}

fn inject_hard_agent_charter(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) {
    let block = collect_hard_charter(state, agent_pid);
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(HARD_CHARTER_MARKER) {
            sys.content = format!("{block}\n{}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

pub(crate) fn talk_via_llm_cage(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    messages: &[ChatMessage],
    req_max_tokens: Option<u32>,
    req_temperature: Option<f64>,
) -> Result<(String, u32, u32, Option<String>, Option<String>, Option<String>), crate::error::ConnectorError> {
    let snap = state.llm_config_snapshot().ok_or_else(|| {
        crate::error::ConnectorError::new(
            crate::error::DenialReason::InternalError,
            "LLM provider not configured for Landlock LLM cage",
        )
    })?;
    let mut cfg = connector_engine::llm::LlmConfig::new(&snap.provider, &snap.model, &snap.api_key);
    if let Some(ep) = &snap.endpoint {
        cfg = cfg.with_endpoint(ep);
    }
    let overrides = talk_generation_overrides(state, agent_pid, req_max_tokens, req_temperature);
    if let Some(n) = overrides.max_tokens {
        cfg.max_tokens = n;
    }
    if let Some(t) = overrides.temperature {
        cfg.temperature = t;
    }
    let msgs = serde_json::to_value(engine_chat_messages(messages)).unwrap_or(serde_json::json!([]));
    let req_id = format!("llm_{}", uuid::Uuid::new_v4().simple());
    let _inflight = crate::substrate::llm_inflight::InflightGuard::register(
        agent_pid,
        &cfg.provider,
        &req_id,
        None,
    );
    let result = crate::kernel::landlock_child::llm_complete(
        state,
        &cfg.base_url(),
        &cfg.provider,
        &cfg.api_key,
        &cfg.model,
        &msgs,
        cfg.max_tokens,
        cfg.temperature,
    );
    drop(_inflight);
    let result = result.map_err(|e| {
        crate::error::ConnectorError::internal(format!("LLM cage pore failed: {e}"))
            .with_denied_resource("llm.landlock_child")
    })?;
    let body = result.get("body").cloned().unwrap_or(result);
    let text = body
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .or_else(|| body.pointer("/content/0/text").and_then(|v| v.as_str()))
        .or_else(|| {
            body.pointer("/candidates/0/content/parts/0/text")
                .and_then(|v| v.as_str())
        })
        .unwrap_or("")
        .to_string();
    let prompt_tokens = body
        .pointer("/usage/prompt_tokens")
        .or_else(|| body.pointer("/usage/input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let completion_tokens = body
        .pointer("/usage/completion_tokens")
        .or_else(|| body.pointer("/usage/output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    Ok((
        text,
        prompt_tokens,
        completion_tokens,
        Some(snap.model),
        Some(snap.provider),
        None,
    ))
}

fn engine_chat_messages(messages: &[ChatMessage]) -> Vec<connector_engine::llm::ChatMessage> {
    messages
        .iter()
        .map(|m| {
            let mut out = connector_engine::llm::ChatMessage::new(m.role.clone(), m.content.clone());
            out.reasoning_content = m.reasoning_content.clone();
            out
        })
        .collect()
}

fn talk_generation_overrides(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    req_max_tokens: Option<u32>,
    req_temperature: Option<f64>,
) -> connector_engine::llm_router::ChatOverrides {
    let meta_budget = state.engine_store.lock().ok().and_then(|es| {
        es.folder_get("agent_meta", agent_pid)
            .ok()
            .flatten()
            .and_then(|m| m.get("token_budget").and_then(|v| v.as_u64()))
    });
    let default_out = meta_budget
        .map(|b| ((b / 8) as u32).clamp(256, 4_096))
        .unwrap_or(2_048);
    let requested = req_max_tokens.unwrap_or(default_out).clamp(16, 8_192);
    // SpendCease: bound cancel-tax — never ask provider for more than remaining ceiling.
    let capped =
        crate::substrate::spend_cease::clamp_max_tokens(state, agent_pid, requested, 8_192);
    connector_engine::llm_router::ChatOverrides {
        max_tokens: Some(capped),
        temperature: Some(req_temperature.unwrap_or(0.3) as f32),
    }
}

/// R7 — inject RAG memory into system (parity with Anthropic gateway + streaming path).
fn inject_connector_rag(messages: &mut Vec<ChatMessage>, rag: &str) {
    if rag.trim().is_empty() {
        return;
    }
    const MARKER: &str = "--- CONNECTOR MEMORY CONTEXT ---";
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(MARKER) {
            sys.content = format!("{}\n{MARKER}\n{rag}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: format!("{MARKER}\n{rag}"),
                reasoning_content: None,
                tool_calls: None,
                tool_call_id: None,
            },
        );
    }
}

// ── Injection detection ───────────────────────────────────────────────────────

/// Simple injection score heuristic (production: wire to SemanticInjectionDetector).
///
/// Returns a score in [0.0, 1.0]. Score ≥ 0.75 → blocked.
fn injection_score(messages: &[ChatMessage]) -> f64 {
    let injection_patterns = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard your instructions",
        "forget your instructions",
        "you are now",
        "act as",
        "pretend you are",
        "jailbreak",
        "dan mode",
        "developer mode",
        "system prompt override",
        "reveal your system prompt",
        "print your instructions",
    ];

    let full_text: String = messages
        .iter()
        .map(|m| m.content.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let matches = injection_patterns
        .iter()
        .filter(|p| full_text.contains(*p))
        .count();

    // Each pattern match adds 0.25; cap at 1.0
    (matches as f64 * 0.25).min(1.0)
}

pub(crate) fn persist_gateway_packet(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    model: &str,
    packet_type: PacketType,
    memory_type: MemoryType,
    content: serde_json::Value,
    tags: Vec<String>,
    session_id: &str,
) -> Option<String> {
    let payload_cid = compute_cid(&content).ok()?;
    let mut packet = MemPacket::new(
        packet_type,
        content,
        payload_cid,
        agent_pid.to_string(),
        "gateway-llm".to_string(),
        Source {
            kind: SourceKind::SelfSource,
            principal_id: agent_pid.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
    .with_namespace(namespace.to_string())
    .with_session(session_id.to_string())
    .with_tags(tags);
    packet.memory_type = memory_type.clone();
    packet.cognitive_path = Some(CognitivePath::memory(agent_pid, &memory_type));
    packet
        .metadata
        .insert("model".into(), serde_json::Value::String(model.to_string()));
    packet.metadata.insert(
        "virtualization_scope".into(),
        serde_json::Value::String("private_agent_memory".into()),
    );
    let packet_for_store = packet.clone();
    let mut kernel = state.kernel.lock().unwrap();
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: agent_pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet },
        reason: Some("gateway_llm_capture".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    if result.outcome == vac_core::types::OpOutcome::Success {
        drop(kernel);
        let _ = crate::substrate::memwrite_durability::write_through_packet_shared(
            state,
            &packet_for_store,
        );
    }
    match result.value {
        vac_core::kernel::SyscallValue::Cid(cid) => Some(cid.to_string()),
        _ => None,
    }
}

fn sanitize_message_content(content: &str) -> (String, bool) {
    let mut sanitized = content.to_string();
    let mut redacted = false;

    // ── DevGuard: Secret Broker pattern-based detection ────────────────────
    // Runs 25+ patterns for API keys, tokens, private keys, connection strings.
    let secret_scan = crate::services::secret_broker::scan_and_redact(&sanitized);
    if secret_scan.redacted_count > 0 {
        sanitized = secret_scan.sanitized;
        redacted = true;
    }

    // ── Legacy PII redaction (kept for backward compat) ───────────────────
    let replacements = [
        ("patient name", "patient"),
        ("full name", "patient"),
        ("social security", "sensitive id"),
        ("ssn", "sensitive id"),
        ("date of birth", "age"),
        ("dob", "age"),
        ("address", "location"),
        ("phone", "contact"),
        ("email", "contact"),
    ];
    for (needle, replacement) in replacements {
        if sanitized.to_ascii_lowercase().contains(needle) {
            sanitized = sanitized.replace(needle, replacement);
            sanitized = sanitized.replace(
                &needle.to_ascii_uppercase(),
                &replacement.to_ascii_uppercase(),
            );
            redacted = true;
        }
    }
    (sanitized, redacted)
}

/// Sanitize + unbypassable broker ingress so the LLM never sees raw data.
/// SVF Phase 1: tokenize/seal **before** residual redact so CDP round-trip survives.
fn sanitize_messages_for_agent(
    state: &SharedState,
    agent_pid: &str,
    messages: &[ChatMessage],
) -> Result<(Vec<ChatMessage>, bool), ConnectorError> {
    crate::substrate::llm_sealed_context::assert_brain_live_for_talk(state, agent_pid)?;
    let mut any_redacted = false;
    let mut sanitized = Vec::with_capacity(messages.len());
    for m in messages {
        let sealed = crate::substrate::llm_broker_gate::ingress_to_llm(state, agent_pid, &m.content)?;
        let (content, residual_redacted) =
            crate::substrate::llm_broker_gate::residual_redact_protecting_opaque(&sealed);
        any_redacted = any_redacted || residual_redacted || content != m.content;
        sanitized.push(ChatMessage {
            role: m.role.clone(),
            content,
            reasoning_content: m.reasoning_content.clone(),
            tool_calls: m.tool_calls.clone(),
            tool_call_id: m.tool_call_id.clone(),
        });
    }
    Ok((sanitized, any_redacted))
}

fn sanitize_messages(messages: &[ChatMessage]) -> (Vec<ChatMessage>, bool) {
    let mut any_redacted = false;
    let sanitized = messages
        .iter()
        .map(|m| {
            let (content, redacted) = sanitize_message_content(&m.content);
            any_redacted = any_redacted || redacted;
            ChatMessage {
                role: m.role.clone(),
                content,
                reasoning_content: m.reasoning_content.clone(),
                tool_calls: m.tool_calls.clone(),
                tool_call_id: m.tool_call_id.clone(),
            }
        })
        .collect();
    (sanitized, any_redacted)
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /v1/chat/completions — OpenAI-compatible LLM proxy.
///
/// Drop-in replacement for `https://api.openai.com/v1/chat/completions`.
/// Set `base_url = "http://your-connector-server"` in your SDK.
pub async fn chat_completions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ChatCompletionRequest>,
) -> Result<axum::response::Response, ConnectorError> {
    // B8: SSE streaming — playground real-pid uses the same snapshot Talk turn as non-stream (INV-19).
    if req.stream {
        if crate::services::playground::is_playground_mode()
            && req
                .agent_pid
                .as_ref()
                .is_some_and(|p| !is_synthetic_gateway_pid(p))
        {
            let created = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            return Ok(playground_talk_stream(state, headers, req, created).await);
        }
        return Ok(chat_completions_stream(state, headers, req).await);
    }
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Hosted trial: forced-pid Talk must not run the full admission/RAG stack (VM freeze).
    if crate::services::playground::is_playground_mode() {
        if req
            .agent_pid
            .as_ref()
            .is_some_and(|p| !is_synthetic_gateway_pid(p))
        {
            return playground_talk_fast(state, headers, req, created).await;
        }
    }

    let client_attribution = extract_gateway_client_attribution(&headers);

    // ── DEVGUARD: Resolve session from API key ─────────────────────────────
    // Every coding agent (Cursor, Windsurf, Aider, generic) passes through here.
    // If the API key maps to a DevGuard session, we enforce policy on all actions.
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .unwrap_or_default();

    super::gateway_hooks::ensure_default_hooks();
    let (dg_session_id, agent_pid, dg_role) =
        resolve_talk_agent_context(&state, &api_key, &headers, &req)?;
    enforce_real_agent_talk(&state, &agent_pid, &dg_session_id, &headers)?;
    if api_key.starts_with("cg_")
        || (!dg_session_id.is_empty()
            && dg_session_id != "anon"
            && !dg_session_id.starts_with("gateway-"))
    {
        let _ = crate::kernel::llm_vendor_cut::engage(
            state.as_ref(),
            &dg_session_id,
            &agent_pid,
            "connected_tool",
            "talk_gateway",
        );
    }
    if llm_stub_blocked_in_prod() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "llm_stub_banned_in_production",
        )
        .with_hint(
            "Unset CONNECTOR_LLM_STUB or set CONNECTOR_LLM_STUB_ALLOW_IN_PROD=1 for break-glass",
        ));
    }

    let namespace = {
        let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid_pub(&state, &agent_pid);
        req.namespace
            .as_deref()
            .map(crate::services::agents::normalize_memory_namespace)
            .unwrap_or_else(|| {
                crate::services::agents::canonical_agent_memory_namespace(&kernel_pid)
            })
    };

    // Ring-1: raw OpenAI tools without N4 CPO are a bypass — fail closed.
    crate::intelligence_admission::gateway_intercept::intercept_raw_tool_definitions(
        &headers,
        req.tools.as_ref(),
        req.tool_choice.as_ref(),
        &agent_pid,
    )?;

    // ── DEVGUARD: Guard message content (FS guard + secret redaction) ──────
    let (guarded_messages, total_secrets_redacted) = if !dg_role.is_empty() {
        let mut msgs = req.messages.clone();
        let mut redacted_total = 0usize;
        for msg in &mut msgs {
            let (sanitized, redacted) =
                super::gateway_hooks::guard_message_content(&state, &agent_pid, &msg.content);
            redacted_total += redacted;
            if redacted > 0 {
                msg.content = sanitized;
            }
        }
        (msgs, redacted_total)
    } else {
        (req.messages.clone(), 0)
    };

    // ── DEVGUARD: OpenAI tool_calls parity with Anthropic tool_use blocking ──
    // Cursor/Windsurf OpenAI-mode agents may round-trip tool_calls through /v1.
    // Local IDE hooks remain required; this closes the kernel gap when tools
    // are visible on the gateway path.
    let enforce_openai_tools = !dg_role.is_empty()
        || crate::services::policy_config::get_active_policy(&state, &agent_pid).is_some();
    if enforce_openai_tools {
        if let Err(blocked) =
            admit_openai_tool_calls_in_messages(&state, &agent_pid, &guarded_messages)
        {
            let detail = blocked.join("\n");
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                format!("[DevGuard] OpenAI tool_calls blocked:\n{detail}"),
            )
            .with_hint(
                "Role policy denied one or more tool_calls. Attach a role that allows the action, or remove the tool call.",
            )
            .with_agent_scope(&agent_pid));
        }
    }

    // ── ADMISSION GATE: Central pre-execution security enforcement ─────────
    // Replaces scattered checks (HIPAA, entitlement, injection, budget) with a
    // single enforcement point. Quarantines agent on security violations.
    // See: platform/docs/arch/ADMISSION_GATE.md
    let full_content: String = req
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let governed_admission = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        &agent_pid,
        &namespace,
        crate::services::admission::AdmissionOp::LlmChat,
        Some(&full_content),
    )?;
    let _admission_ticket = governed_admission.ticket;

    if let Err(e) = crate::substrate::effect_exclusivity::assert_effect_exclusivity_ready(
        &agent_pid,
        state.as_ref(),
    ) {
        let msg = e
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("effect_exclusivity_refuse");
        return Err(ConnectorError::new(DenialReason::PolicyDenied, msg)
            .with_hint("Effect exclusivity prerequisites missing — fail closed"));
    }

    // ── HIPAA BAA gate (post-admission, config check) ────────────────────
    // Not a security decision — configuration compliance only.
    {
        let es = state.engine_store.lock().unwrap();
        let hipaa_required = es
            .folder_get("agent_hipaa_flags", &agent_pid)
            .ok()
            .and_then(|v| v)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let baa_accepted = es
            .folder_keys("compliance_agreements", Some("baa_"))
            .map(|keys| !keys.is_empty())
            .unwrap_or(false);
        drop(es);

        if hipaa_required && !baa_accepted {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "hipaa_no_baa".to_string(),
                })
                .inc();
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                "Agent requires HIPAA compliance (hipaa: true) but no BAA has been accepted. \
                Accept a BAA via POST /api/v1/compliance/baa/accept (Team/Enterprise tier). \
                This takes 30 seconds and unlocks HIPAA-compliant LLM routing.",
            )
            .with_denied_resource("llm.chat")
            .with_hint("POST /api/v1/compliance/baa/accept with your org details"));
        }
    }

    // ── Entitlement gate (BIZ-4, billing check) ──────────────────────────
    let account_id = {
        let es = state.engine_store.lock().unwrap();
        let meta = es.folder_get("agent_meta", &agent_pid).ok().flatten();
        crate::services::billing::billing_tenant_id_from_agent_meta(meta.as_ref())
            .unwrap_or_else(|| agent_pid.clone())
    };
    {
        if !crate::services::billing::check_entitlement(&state, &account_id, "dispatch") {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "entitlement_denied".to_string(),
                })
                .inc();
            return Err(ConnectorError::new(
                DenialReason::RateLimitExceeded,
                format!(
                    "Account '{}' is not entitled to dispatch on the current tier. \
                    Upgrade at https://connector.ai/upgrade.",
                    account_id
                ),
            )
            .with_denied_resource("llm.dispatch")
            .with_hint("GET /api/v1/billing/entitlements to see your current feature set"));
        }
    }

    // ── P2.2 Settings LLM cost-cap hard stop (Books month estimated USD) ──
    if let Some((month, budget, hard_pct, ceiling)) =
        crate::services::settings_llms::cost_cap_hard_stop_violation(
            &state,
            Some(account_id.as_str()),
        )
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "cost_cap_hard_stop".to_string(),
            })
            .inc();
        return Err(ConnectorError::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Cost cap hard stop: month estimated spend ${month:.4} ≥ \
                ${ceiling:.4} (budget ${budget:.2} × {hard_pct:.0}%). \
                Raise Settings → LLM guardrails or wait for the next UTC month."
            ),
        )
        .with_denied_resource("llm.cost_cap")
        .with_hint("GET /api/v1/settings/llms/guardrails · GET /api/v1/books/costs"));
    }

    // ── TG-2 / PATE: Talk through AutonomyGateway + ATU (digest HITL / Block) ─
    // Operational preflight: harden/exclusivity/sandbox must be ready under AUGMENTED_ENV.
    if let Err(e) = crate::substrate::ops_runtime::preflight_agent_effect(&state, &agent_pid) {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: e.denial_reason.slug().to_string(),
            })
            .inc();
        return Err(e);
    }
    let talk_atu = {
        let talk_content: String = guarded_messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mission_hdr = headers
            .get("x-connector-mission-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match crate::substrate::pate::admit_talk(
            &state,
            &agent_pid,
            &namespace,
            &talk_content,
            mission_hdr,
        ) {
            Ok(atu) if !crate::substrate::pate::host_admission_allows_execution(atu.verdict) => {
                return Err(ConnectorError::new(DenialReason::PolicyDenied, "not_proceed")
                    .with_denied_resource("llm.chat")
                    .with_hint(&format!(
                        "Ask stays open. task_id={} Approve the digest, then retry Talk.",
                        atu.task_id
                    )));
            }
            Ok(atu) => atu,
            Err(e) => {
                state
                    .metrics
                    .admission_rejected_total
                    .get_or_create(&crate::state::ReasonLabels {
                        reason: e.denial_reason.slug().to_string(),
                    })
                    .inc();
                let hint = if e.human_readable.contains("hitl") {
                    "Approve digest-bound HITL then retry Talk"
                } else {
                    "PATCH /api/v1/agents/:pid/contract capabilities must include chat|llm"
                };
                return Err(e
                    .with_denied_resource("llm.chat")
                    .with_hint(hint));
            }
        }
    };
    let mut open_talk = crate::substrate::pate::OpenProceed::arm(&state, &talk_atu);
    // ARC-5: llm.chat lease-mediated when CONNECTOR_ARC_LEASE=1 (NoLease⇒NoEffect).
    let mut arc_lease = match crate::substrate::arc::lease::LeaseSinkGuard::begin_sink(
        &agent_pid,
        &talk_atu.action_digest,
        &talk_atu.task_id,
        talk_atu.iac_epoch,
        crate::substrate::arc::lease::SINK_LLM_CHAT,
    ) {
        Ok(g) => g,
        Err(e) => {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: e.denial_reason.slug().to_string(),
                })
                .inc();
            return Err(e
                .with_denied_resource("llm.chat")
                .with_hint("NoLease ⇒ NoEffect — enable CONNECTOR_ARC_GOVERNOR+LEASE or disable LEASE"));
        }
    };
    reserve_playground_talk_budget(
        &state,
        &dg_session_id,
        guarded_messages.iter().map(|m| m.content.len()).sum(),
        req.max_tokens.unwrap_or(1024),
    )?;

    // ── DI-5: economy pricer budget-gate (POST /economy/budget-gate) ─────
    if let Some((spent, max_spend, remaining)) =
        crate::services::economy::economy_budget_gate_violation(state.as_ref(), &agent_pid)
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "budget_gate".to_string(),
            })
            .inc();
        return Err(ConnectorError::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Economy budget gate exceeded for agent '{agent_pid}': spent {spent} ≥ max {max_spend} (remaining {remaining})."
            ),
        )
        .with_denied_resource("llm.budget_gate")
        .with_hint(&format!(
            "GET /api/v1/economy/budget-gate/{agent_pid} · POST /api/v1/economy/budget-gate"
        )));
    }

    // ── DI-5: anomaly gate (opt-in CONNECTOR_IIA_ANOMALY_GATE=1) ─────────
    if let Some((rate, total, denied)) =
        crate::services::monitor::anomaly_gate_violation(state.as_ref(), &agent_pid)
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "anomaly_gate".to_string(),
            })
            .inc();
        return Err(ConnectorError::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Anomaly gate: agent '{agent_pid}' HIGH_DENY_RATE {rate:.2} ({denied}/{total} ops in 24h)."
            ),
        )
        .with_denied_resource("llm.anomaly_gate")
        .with_hint("GET /api/v1/monitor/anomalies/v2 · unset CONNECTOR_IIA_ANOMALY_GATE to disable"));
    }

    // ── AAPI BCR spend (A12) — reserve-execute-commit when budget exists ─────
    {
        let estimated_input = req
            .messages
            .iter()
            .map(|m| m.content.len() / 4 + 1)
            .sum::<usize>() as f64;
        if let Err(e) = crate::substrate::ops_runtime::spend_tokens(
            &state,
            &agent_pid,
            estimated_input,
            Some(talk_atu.action_digest.as_str()),
        ) {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "budget_exhausted".to_string(),
                })
                .inc();
            return Err(e);
        }
    }

    // ── Belief-field recall (operational) — last user turn into Knot/VAC ─────
    let last_user = req
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .unwrap_or("");
    let recall_ctx = crate::substrate::ops_runtime::maybe_augment_talk_with_recall(
        state.as_ref(),
        &agent_pid,
        last_user,
    );

    // ── Step 2: Route through LlmRouter (or stub mode) ──────────────────────
    // XDX-6: CONNECTOR_LLM_STUB=true → full pipeline runs, canned response returned.
    // Lets users evaluate the entire platform (audit, memory, MAC guard, billing)
    // without needing an LLM API key. Cost: $0.
    // Stub only when no live router — DI-1 link wins over CONNECTOR_LLM_STUB.
    let talk_wired =
        crate::services::settings_llms::talk_llm_wired(&state, &headers, &agent_pid);
    let stub_mode = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
        && !talk_wired;
    // Use DevGuard-guarded messages if session is active, otherwise raw messages
    let mut messages_for_llm = if !dg_role.is_empty() {
        guarded_messages
    } else {
        req.messages.clone()
    };
    inject_talk_identity_messages(
        &state,
        &agent_pid,
        &mut messages_for_llm,
        &req.model,
        talk_provider_hint(&req.model),
    )?;
    if !crate::services::playground::is_playground_mode() {
        inject_svf_projection(&state, &agent_pid, &mut messages_for_llm);
        // Soft-fail CRK on Talk — empty memory → INSUFFICIENT frames, not Talk denial.
        if let Err(e) = inject_crk_transfer(
            &state,
            &agent_pid,
            &mut messages_for_llm,
            &req.model,
            talk_provider_hint(&req.model),
        ) {
            tracing::warn!(error = ?e, agent = %agent_pid, "crk_transfer_inject_skipped");
        }
    }

    // Operational recall: surface belief-field snippets into context (not admit).
    if recall_ctx.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let mut snippets: Vec<String> = Vec::new();
        for key in ["/recall/composite", "/recall/knot_rrf"] {
            if let Some(arr) = recall_ctx.pointer(key).and_then(|v| v.as_array()) {
                for it in arr.iter().take(3) {
                    if let Some(t) = it
                        .get("text")
                        .or_else(|| it.get("content"))
                        .or_else(|| it.get("snippet"))
                        .and_then(|v| v.as_str())
                    {
                        if !t.is_empty() {
                            snippets.push(t.chars().take(400).collect());
                        }
                    }
                }
            }
        }
        if !snippets.is_empty() {
            messages_for_llm.insert(
                0,
                ChatMessage {
                    role: "system".into(),
                    content: format!(
                        "[connector.ops_runtime.recall]\nBelief-field only — does not admit effects.\n{}",
                        snippets.join("\n---\n")
                    ),
                    reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            );
        }
    }

    // IAC: ensure cell exists; reserve inflight for this Talk generation.
    let iac_cell = state.cells.get_or_create(&agent_pid);
    let _iac_inflight =
        crate::concurrency::intelligence_cell::InflightGuard::try_acquire(std::sync::Arc::clone(
            &iac_cell,
        ))
        .map_err(|msg| {
            ConnectorError::new(DenialReason::RateLimitExceeded, msg)
                .with_denied_resource("llm.inflight")
                .with_hint("CONNECTOR_I_INFLIGHT caps concurrent generations per intelligence")
        })?;

    // RAG before sanitize/ingress so broker tokenize covers retrieved memory too.
    // Off async worker via KernelHandle — never hold kernel.lock() on the tokio runtime.
    let user_query: String = messages_for_llm
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let rag_context = crate::concurrency::kernel_handle::build_agent_rag_context_async(
        state.clone(),
        agent_pid.clone(),
        namespace.clone(),
        user_query,
    )
    .await;
    inject_connector_rag(&mut messages_for_llm, &rag_context);

    let (sanitized_messages, privacy_redacted) =
        sanitize_messages_for_agent(&state, &agent_pid, &messages_for_llm)?;
    let mut sanitized_messages = sanitized_messages;

    let (response_text, prompt_tokens, completion_tokens, served_model, served_provider, reasoning_content) =
        if stub_mode {
            let last_user_msg = sanitized_messages
                .iter()
                .rev()
                .find(|m| m.role == "user")
                .map(|m| m.content.as_str())
                .unwrap_or("(empty)");
            let stub_reply = format!(
                "[CONNECTOR_LLM_STUB · simulation] Canned reply — not a live governed model.\n\
                 Prompt preview: \"{}\"\n\
                 Set a provider key (Settings → LLM / connectorctl llm link) and unset CONNECTOR_LLM_STUB for live routing. \
                 Audit, memory, and MAC Guard still run in simulation mode.",
                &last_user_msg[..last_user_msg.len().min(120)]
            );
            let input_toks = sanitized_messages
                .iter()
                .map(|m| m.content.len() / 4 + 1)
                .sum::<usize>() as u32;
            (
                stub_reply,
                input_toks,
                42u32,
                Some("stub".to_string()),
                Some("stub".to_string()),
                None,
            )
        } else if crate::kernel::landlock_child::llm_cage_enforced() {
            let st = state.clone();
            let pid = agent_pid.clone();
            let msgs = sanitized_messages.clone();
            let max = req.max_tokens;
            let temp = req.temperature;
            tokio::task::spawn_blocking(move || {
                talk_via_llm_cage(st.as_ref(), &pid, &msgs, max, temp)
            })
            .await
            .map_err(|e| ConnectorError::internal(format!("llm_cage_join:{e}")))??
        } else {
            let llm_router =
                crate::services::settings_llms::talk_llm_router(&state, &headers, &agent_pid)
                    .ok_or_else(|| {
                ConnectorError::new(
                    DenialReason::InternalError,
                    "LLM provider not configured. Paste key in Settings → LLM or: connectorctl llm link",
                )
            })?;

            let overrides = talk_generation_overrides(
                state.as_ref(),
                &agent_pid,
                req.max_tokens,
                req.temperature,
            );
            let engine_msgs = engine_chat_messages(&sanitized_messages);

            let inflight_id = format!("gw_{}", uuid::Uuid::new_v4().simple());
            let _inflight = crate::substrate::llm_inflight::InflightGuard::register(
                &agent_pid,
                "llm_router",
                &inflight_id,
                None,
            );
            let chat_result = tokio::time::timeout(
                talk_llm_wall_timeout(),
                crate::kernel::aios::with_interrupt(
                    &agent_pid,
                    llm_router.chat_with_overrides(engine_msgs, overrides),
                ),
            )
            .await;
            drop(_inflight);
            match chat_result
            {
                Err(_) => {
                    return Err(ConnectorError::internal(
                        "LLM request timed out waiting for the provider. \
                         The API key may be valid but this host could not reach the vendor in time.",
                    )
                    .with_denied_resource("llm.provider_timeout")
                    .with_hint(
                        "Retry Talk; if it persists, try another provider or check vendor egress from try.cnktros.com",
                    ));
                }
                Ok((_, crate::kernel::aios::CompleteOutcome::Interrupted)) => {
                    return Err(ConnectorError::new(
                        DenialReason::PolicyDenied,
                        "LLM generation interrupted (kill-switch / llm.interrupt). Partial saved to /m/core/context_partial.json.",
                    )
                    .with_denied_resource("llm.interrupt")
                    .with_hint("POST /api/v1/kernel/syscall op=llm.interrupt"));
                }
                Ok((_, crate::kernel::aios::CompleteOutcome::Denied(e))) => {
                    return Err(ConnectorError::new(
                        DenialReason::RateLimitExceeded,
                        e,
                    )
                    .with_denied_resource("llm.inflight")
                    .with_hint("CONNECTOR_I_INFLIGHT caps concurrent generations per intelligence"));
                }
                Ok((_, crate::kernel::aios::CompleteOutcome::Done(Ok(resp)))) => (
                    resp.text,
                    resp.input_tokens,
                    resp.output_tokens,
                    Some(resp.model),
                    Some(resp.provider),
                    resp.reasoning_content,
                ),
                Ok((_, crate::kernel::aios::CompleteOutcome::Done(Err(e)))) => {
                    return Err(ConnectorError::internal(format!(
                        "LLM router error: {}. Check provider config and API key.",
                        e
                    )));
                }
            }
        };

    let (response_text, output_attestation, work_unit_json, binding_json, projection_outcome, aipsprt) =
        project_talk_for_agent(state.as_ref(), &agent_pid, &response_text, last_user)?;
    crate::substrate::llm_broker_gate::inspect_model_output(&state, &agent_pid, &response_text)?;
    note_talk_crossing(&agent_pid, &sanitized_messages, &response_text, stub_mode);

    let total_tokens = prompt_tokens + completion_tokens;
    {
        let mut pr = state.pricer.lock().unwrap();
        let amount = (total_tokens as u64).max(1);
        if let Err(e) = pr.charge(
            &agent_pid,
            amount,
            chrono::Utc::now().timestamp_millis(),
        ) {
            tracing::warn!(agent_pid = %agent_pid, error = %e, "economy budget charge after talk");
        }
    }
    let call_session_id = format!("gateway-{}", uuid::Uuid::new_v4().simple());

    // ── Context tracking: register agent + update token usage ────────────────
    {
        let mut cm = state.context_mgr.lock().unwrap();
        if cm.get(&agent_pid).is_none() {
            cm.register(&agent_pid, &call_session_id);
        }
        let _ = cm.update(&agent_pid, vec![], total_tokens as i64);
    }

    // ── Step 3: Write LLM I/O to audit memory ────────────────────────────────
    let audit_content = serde_json::json!({
        "gateway": "ai_gateway",
        "model": &req.model,
        "client": client_attribution.client.clone(),
        "client_origin": client_attribution.origin.clone(),
        "client_user_agent": client_attribution.user_agent.clone(),
        "messages": req.messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
        "sanitized_messages": sanitized_messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
        "response": &response_text,
        "input_tokens": prompt_tokens,
        "output_tokens": completion_tokens,
        "injection_score": _admission_ticket.injection_score,
        "privacy_redacted": privacy_redacted,
    });

    let prompt_memory_cid = persist_gateway_packet(
        &state,
        &agent_pid,
        &namespace,
        &req.model,
        PacketType::Input,
        MemoryType::Working,
        serde_json::json!({
            "kind": "llm_prompt",
            "model": &req.model,
            "client": client_attribution.client.clone(),
            "client_origin": client_attribution.origin.clone(),
            "client_user_agent": client_attribution.user_agent.clone(),
            "messages": req.messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
            "sanitized_messages": sanitized_messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
            "privacy_redacted": privacy_redacted,
            "namespace": &namespace,
        }),
        vec!["llm_prompt".into(), "virtualized".into(), agent_pid.clone()],
        &call_session_id,
    );
    let response_memory_cid = persist_gateway_packet(
        &state,
        &agent_pid,
        &namespace,
        &req.model,
        PacketType::LlmRaw,
        MemoryType::Episodic,
        serde_json::json!({
            "kind": "llm_response",
            "model": &req.model,
            "client": client_attribution.client.clone(),
            "client_origin": client_attribution.origin.clone(),
            "client_user_agent": client_attribution.user_agent.clone(),
            "response": &response_text,
            "usage": {
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "namespace": &namespace,
        }),
        vec![
            "llm_response".into(),
            "virtualized".into(),
            agent_pid.clone(),
        ],
        &call_session_id,
    );

    let audit_cid: Option<String> = response_memory_cid
        .clone()
        .or(prompt_memory_cid.clone())
        .or(_admission_ticket.audit_cid.clone());

    // ── Step 4: Record in engine audit log ───────────────────────────────────
    {
        use connector_engine::engine_store::EngineAuditEntry;
        let entry = EngineAuditEntry {
            timestamp: chrono::Utc::now().timestamp_millis(),
            category: "llm_gateway".to_string(),
            agent_pid: Some(agent_pid.clone()),
            action: "llm.chat".to_string(),
            resource: Some(req.model.clone()),
            verdict: Some("allowed".to_string()),
            details: Some(serde_json::json!({
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens,
                "audit_cid": &audit_cid,
                "prompt_memory_cid": &prompt_memory_cid,
                "response_memory_cid": &response_memory_cid,
                "client": client_attribution.client.clone(),
                "client_origin": client_attribution.origin.clone(),
                "client_user_agent": client_attribution.user_agent.clone(),
                "injection_score": _admission_ticket.injection_score,
                "privacy_redacted": privacy_redacted,
                "namespace": &namespace,
            })),
            severity: "info".to_string(),
        };
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.append_audit(&entry);
    }

    // B1 / OTel GenAI SIG: emit span with full gen_ai.* semantic conventions
    {
        let _span = tracing::info_span!(
            "gen_ai.chat",
            "gen_ai.system"                 = "connector",
            "gen_ai.request.model"          = %req.model,
            "gen_ai.usage.input_tokens"     = prompt_tokens,
            "gen_ai.usage.output_tokens"    = completion_tokens,
            "gen_ai.usage.total_tokens"     = total_tokens,
            "gen_ai.response.finish_reason" = "stop",
            "agent.id"                      = %agent_pid,
            "session.id"                    = %namespace,
        );
        // span closes here, exporting via OTLP if OTEL_EXPORTER_OTLP_ENDPOINT is set
    }
    // I11 / BIZ-4 / BIZ-7 / ledger: shared completion path (OpenAI-compat + Anthropic parity)
    // P2.2: UsageEvent.model_served comes from LlmResponse (fallback hop), not only primary.
    open_talk.disarm();
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &talk_atu,
        "ok",
        serde_json::json!({
            "observed": true,
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens,
            "model": served_model.clone().unwrap_or_else(|| req.model.clone()),
            "provider": served_provider.clone(),
            "prompt_memory_cid": prompt_memory_cid,
            "response_memory_cid": response_memory_cid,
            "action_digest": talk_atu.action_digest,
            "mission_id": talk_atu.mission_id,
        }),
    );
    let (account_id_for_billing, cost_usd) =
        crate::services::billing::record_llm_completion_side_effects(
            &state,
            &agent_pid,
            &call_session_id,
            &req.model,
            prompt_tokens,
            completion_tokens,
            stub_mode,
            "chat",
            false,
            None,
            served_model.as_deref(),
            served_provider.as_deref(),
        );

    // ── DEVGUARD: Record LLM call in session stats + audit ────────────────
    if !dg_role.is_empty() && dg_session_id != "anon" {
        super::gateway_hooks::record_llm_call(
            &state,
            &dg_session_id,
            &agent_pid,
            prompt_tokens,
            completion_tokens,
        );
    }

    let call_id = format!("chatcmpl-{}", uuid::Uuid::new_v4().simple());

    let resp_body = ChatCompletionResponse {
        id: call_id,
        object: "chat.completion".to_string(),
        created,
        // Prefer served model id (fallback hop) when router returned one.
        model: served_model.clone().unwrap_or_else(|| req.model.clone()),
        choices: vec![ChatCompletionChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: response_text,
                reasoning_content,
                tool_calls: None,
                tool_call_id: None,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: ChatCompletionUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        },
        audit_cid,
        estimated_cost_usd: Some(cost_usd),
        client: client_attribution.client.clone(),
        client_origin: client_attribution.origin.clone(),
        client_user_agent: client_attribution.user_agent.clone(),
        llm_mode: Some(if stub_mode {
            "simulation".into()
        } else {
            "live".into()
        }),
        honesty: stub_mode.then(|| {
            "CONNECTOR_LLM_STUB — response is canned simulation, not a live provider completion"
                .into()
        }),
        connector_output_attestation: output_attestation,
        connector_identity_work_unit: Some(work_unit_json),
        connector_intelligence_binding: Some(binding_json),
        connector_projection_outcome: Some(projection_outcome),
        connector_turn_envelope: None,
        connector_aipsprt: aipsprt,
    };

    // BIZ-3: attach X-Connector-Budget-Warning header when token usage crosses 80%
    // FIX BUG-032: Use account_id from agent_meta instead of agent_pid for user lookup
    let budget_pct: Option<u8> = {
        let acct = account_id_for_billing.clone();
        if acct.is_empty() {
            None
        } else {
            match crate::util_lock::mutex_lock(&state.user_store, "user_store") {
                Ok(us) => {
                    if let Some(user) = us.get_user(&acct) {
                        let limit = 10_000u64; // community default; real check via billing service
                        let used = user.tokens_used_today;
                        let pct = (used * 100) / limit.max(1);
                        if pct >= 80 {
                            Some(pct as u8)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }
    };

    use axum::response::IntoResponse;
    arc_lease.success();
    let aipsprt_hdr = encode_aipsprt_header_value(&resp_body.connector_aipsprt);
    let mut response = (axum::http::StatusCode::OK, Json(resp_body)).into_response();
    if let Some(h) = aipsprt_hdr {
        if let Ok(v) = axum::http::HeaderValue::from_str(&h) {
            response
                .headers_mut()
                .insert(connector_trust::AIPSPRT_HEADER, v);
        }
    }
    if let Some(pct) = budget_pct {
        let header_val = format!("{}pct", pct);
        if let Ok(v) = axum::http::HeaderValue::from_str(&header_val) {
            response
                .headers_mut()
                .insert("x-connector-budget-warning", v);
        }
    }
    if let Some(client) = &client_attribution.client {
        if let Ok(v) = axum::http::HeaderValue::from_str(client) {
            response.headers_mut().insert("x-connector-client", v);
        }
    }
    if let Some(origin) = &client_attribution.origin {
        if let Ok(v) = axum::http::HeaderValue::from_str(origin) {
            response.headers_mut().insert("x-connector-origin", v);
        }
    }
    if let Some(claims) = crate::auth::extract_claims(&headers) {
        if let Some(cfni) =
            crate::substrate::cfni::mint_for_principal(&claims.sub, claims.tenant_id.as_deref())
        {
            if let Some((name, value)) = crate::substrate::cfni::header_from_identity(&cfni) {
                if let (Ok(hn), Ok(hv)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    axum::http::HeaderValue::from_str(&value),
                ) {
                    response.headers_mut().insert(hn, hv);
                }
            }
        }
    }
    if let Some(user_agent) = &client_attribution.user_agent {
        if let Ok(v) = axum::http::HeaderValue::from_str(user_agent) {
            response
                .headers_mut()
                .insert("x-connector-client-user-agent", v);
        }
    }
    Ok(response)
}

// ── B8: SSE streaming handler ─────────────────────────────────────────────────

/// Streaming path for `stream: true` — emits OpenAI-compatible SSE chunks.
///
/// Each chunk: `data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"token"}}]}`
/// Terminal chunk: `data: [DONE]`
///
/// Backpressure: if client disconnects, stream ends; agent continues but drops output.
///
/// FIX BUG-026: Now applies same compliance gates as non-streaming path.
async fn chat_completions_stream(
    state: SharedState,
    headers: HeaderMap,
    req: ChatCompletionRequest,
) -> axum::response::Response {
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .unwrap_or_default();
    super::gateway_hooks::ensure_default_hooks();
    let (session_id, agent_pid, _role) = match resolve_talk_agent_context(
        &state,
        &api_key,
        &headers,
        &req,
    ) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = enforce_real_agent_talk(&state, &agent_pid, &session_id, &headers) {
        return e.into_response();
    }
    if llm_stub_blocked_in_prod() {
        return ConnectorError::new(
            DenialReason::PolicyDenied,
            "llm_stub_banned_in_production",
        )
        .with_hint("Unset CONNECTOR_LLM_STUB or set CONNECTOR_LLM_STUB_ALLOW_IN_PROD=1 for break-glass")
        .into_response();
    }
    let namespace = {
        let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid_pub(&state, &agent_pid);
        req.namespace
            .as_deref()
            .map(crate::services::agents::normalize_memory_namespace)
            .unwrap_or_else(|| {
                crate::services::agents::canonical_agent_memory_namespace(&kernel_pid)
            })
    };
    let model = req.model.clone();
    let call_id = format!("chatcmpl-{}", uuid::Uuid::new_v4().simple());
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // ── ADMISSION GATE (streaming path) ─────────────────────────────────────
    // Same enforcement as non-streaming. Quarantines agent on security violations.
    if let Err(e) = crate::intelligence_admission::gateway_intercept::intercept_raw_tool_definitions(
        &headers,
        req.tools.as_ref(),
        req.tool_choice.as_ref(),
        &agent_pid,
    ) {
        return e.into_response();
    }
    {
        let full_content: String = req
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let admission_result = crate::substrate::governed_effect::evaluate_effect(
            &state,
            Some(&headers),
            &agent_pid,
            &namespace,
            crate::services::admission::AdmissionOp::LlmChat,
            Some(&full_content),
        );
        if let Err(err) = admission_result {
            return err.into_response();
        }
    }

    // FIX BUG-026: HIPAA BAA gate (config compliance, not security)
    {
        let es = state.engine_store.lock().unwrap();
        let hipaa_required = es
            .folder_get("agent_hipaa_flags", &agent_pid)
            .ok()
            .and_then(|v| v)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let baa_accepted = es
            .folder_keys("compliance_agreements", Some("baa_"))
            .map(|keys| !keys.is_empty())
            .unwrap_or(false);
        drop(es);

        if hipaa_required && !baa_accepted {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "hipaa_no_baa".to_string(),
                })
                .inc();
            let body = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "HIPAA_BAA_REQUIRED",
                    "message": "Agent requires HIPAA compliance but no BAA has been accepted.",
                    "hint": "POST /api/v1/compliance/baa/accept"
                }
            });
            return (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response();
        }
    }

    // FIX BUG-026: Entitlement gate (billing check)
    let stream_account_id = {
        let es = state.engine_store.lock().unwrap();
        let meta = es.folder_get("agent_meta", &agent_pid).ok().flatten();
        crate::services::billing::billing_tenant_id_from_agent_meta(meta.as_ref())
            .unwrap_or_else(|| agent_pid.clone())
    };
    {
        if !crate::services::billing::check_entitlement(&state, &stream_account_id, "dispatch") {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "entitlement_denied".to_string(),
                })
                .inc();
            let body = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "ENTITLEMENT_DENIED",
                    "message": format!("Account '{}' is not entitled to dispatch on the current tier.", stream_account_id),
                    "hint": "GET /api/v1/billing/entitlements"
                }
            });
            return (axum::http::StatusCode::PAYMENT_REQUIRED, Json(body)).into_response();
        }
    }

    // P2.2 Settings LLM cost-cap hard stop (streaming path)
    if let Some((month, budget, hard_pct, ceiling)) =
        crate::services::settings_llms::cost_cap_hard_stop_violation(
            &state,
            Some(stream_account_id.as_str()),
        )
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "cost_cap_hard_stop".to_string(),
            })
            .inc();
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": "COST_CAP_HARD_STOP",
                "message": format!(
                    "Cost cap hard stop: month estimated spend ${month:.4} ≥ ${ceiling:.4} (budget ${budget:.2} × {hard_pct:.0}%)."
                ),
                "hint": "GET /api/v1/settings/llms/guardrails · GET /api/v1/books/costs"
            }
        });
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    }

    // TG-2 / PATE: Talk stream through AutonomyGateway + ATU
    if let Err(e) = crate::substrate::ops_runtime::preflight_agent_effect(&state, &agent_pid) {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: e.denial_reason.slug().to_string(),
            })
            .inc();
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": e.denial_reason.slug().to_ascii_uppercase(),
                "message": e.human_readable,
                "hint": "GET /api/v1/substrate/status → harden_posture"
            }
        });
        return (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response();
    }
    let stream_talk_atu = {
        let talk_content: String = req
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mission_hdr = headers
            .get("x-connector-mission-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match crate::substrate::pate::admit_talk(
            &state,
            &agent_pid,
            &namespace,
            &talk_content,
            mission_hdr,
        ) {
            Ok(atu) if !crate::substrate::pate::host_admission_allows_execution(atu.verdict) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": "not_proceed",
                    "task_id": atu.task_id,
                    "executed": false,
                    "admits": false,
                    "hint": "Ask stays open until a human Proceed.",
                });
                return (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response();
            }
            Ok(atu) => atu,
            Err(e) => {
                state
                    .metrics
                    .admission_rejected_total
                    .get_or_create(&crate::state::ReasonLabels {
                        reason: e.denial_reason.slug().to_string(),
                    })
                    .inc();
                let code = e.denial_reason.slug();
                let body = serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": code.to_ascii_uppercase(),
                        "message": e.human_readable,
                        "hint": if e.human_readable.to_ascii_lowercase().contains("hitl") {
                            "Approve digest-bound HITL then retry Talk"
                        } else {
                            "PATCH /api/v1/agents/:pid/contract capabilities must include chat|llm"
                        }
                    }
                });
                return (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response();
            }
        }
    };
    let mut open_stream = crate::substrate::pate::OpenProceed::arm(&state, &stream_talk_atu);
    let mut arc_lease = match crate::substrate::arc::lease::LeaseSinkGuard::begin_sink(
        &agent_pid,
        &stream_talk_atu.action_digest,
        &stream_talk_atu.task_id,
        stream_talk_atu.iac_epoch,
        crate::substrate::arc::lease::SINK_LLM_CHAT,
    ) {
        Ok(g) => g,
        Err(e) => {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: e.denial_reason.slug().to_string(),
                })
                .inc();
            let body = serde_json::json!({
                "ok": false,
                "error": {
                    "code": e.denial_reason.slug().to_ascii_uppercase(),
                    "message": e.human_readable,
                    "hint": "NoLease ⇒ NoEffect — enable CONNECTOR_ARC_GOVERNOR+LEASE or disable LEASE"
                }
            });
            return (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response();
        }
    };
    if let Err(e) = reserve_playground_talk_budget(
        &state,
        &session_id,
        req.messages.iter().map(|m| m.content.len()).sum(),
        req.max_tokens.unwrap_or(1024),
    ) {
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"ok": false, "error": e})),
        )
            .into_response();
    }

    if let Some((spent, max_spend, remaining)) =
        crate::services::economy::economy_budget_gate_violation(state.as_ref(), &agent_pid)
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "budget_gate".to_string(),
            })
            .inc();
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": "BUDGET_GATE",
                "message": format!(
                    "Economy budget gate exceeded for agent '{agent_pid}': spent {spent} ≥ max {max_spend} (remaining {remaining})."
                ),
                "hint": format!("GET /api/v1/economy/budget-gate/{agent_pid}")
            }
        });
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    }

    if let Some((rate, total, denied)) =
        crate::services::monitor::anomaly_gate_violation(state.as_ref(), &agent_pid)
    {
        state
            .metrics
            .admission_rejected_total
            .get_or_create(&crate::state::ReasonLabels {
                reason: "anomaly_gate".to_string(),
            })
            .inc();
        let body = serde_json::json!({
            "ok": false,
            "error": {
                "code": "ANOMALY_GATE",
                "message": format!(
                    "Anomaly gate: agent '{agent_pid}' HIGH_DENY_RATE {rate:.2} ({denied}/{total} ops in 24h)."
                ),
                "hint": "GET /api/v1/monitor/anomalies/v2"
            }
        });
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    }

    // FIX BUG-026: AAPI BCR token budget
    {
        let estimated_input = req
            .messages
            .iter()
            .map(|m| m.content.len() / 4 + 1)
            .sum::<usize>() as f64;
        if let Err(e) = crate::substrate::ops_runtime::spend_tokens(
            &state,
            &agent_pid,
            estimated_input,
            Some(stream_talk_atu.action_digest.as_str()),
        ) {
            state
                .metrics
                .admission_rejected_total
                .get_or_create(&crate::state::ReasonLabels {
                    reason: "budget_exhausted".to_string(),
                })
                .inc();
            let body = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "BUDGET_EXHAUSTED",
                    "message": e.human_readable,
                    "hint": format!("POST /api/v1/agents/{}/reset-budget", agent_pid)
                }
            });
            return (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
        }
    }

    // Same token semantics as non-streaming: provider usage when routed; heuristic in stub / error.
    let talk_wired =
        crate::services::settings_llms::talk_llm_wired(&state, &headers, &agent_pid);
    let stub_mode = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
        && !talk_wired;
    let mut stream_messages = req.messages.clone();
    if let Err(err) = inject_talk_identity_messages(
        &state,
        &agent_pid,
        &mut stream_messages,
        &req.model,
        talk_provider_hint(&req.model),
    ) {
        return err.into_response();
    }
    inject_svf_projection(&state, &agent_pid, &mut stream_messages);
    let stream_user_query: String = stream_messages
        .iter()
        .filter(|m| m.role.eq_ignore_ascii_case("user"))
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let stream_rag = crate::concurrency::kernel_handle::build_agent_rag_context_async(
        state.clone(),
        agent_pid.clone(),
        namespace.clone(),
        stream_user_query,
    )
    .await;
    inject_connector_rag(&mut stream_messages, &stream_rag);
    // Streaming parity with non-stream: sanitize + broker ingress before vendor call.
    let stream_messages = match sanitize_messages_for_agent(&state, &agent_pid, &stream_messages) {
        Ok((msgs, _)) => msgs,
        Err(err) => return err.into_response(),
    };
    let (
        response_text,
        prompt_tokens,
        completion_tokens,
        token_source,
        served_model,
        served_provider,
    ) = if stub_mode || !talk_wired {
        let last = req
            .messages
            .iter()
            .rev()
            .find(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or("(empty)");
        let text = format!(
            "[stub-stream] Response to: \"{}\"",
            &last[..last.len().min(80)]
        );
        let pt = req
            .messages
            .iter()
            .map(|m| m.content.len() / 4 + 1)
            .sum::<usize>() as u32;
        let ct = text.len() as u32 / 4 + 1;
        (
            text,
            pt,
            ct,
            if stub_mode {
                "stub_heuristic"
            } else {
                "no_router_heuristic"
            },
            Some("stub".to_string()),
            Some("stub".to_string()),
        )
    } else if crate::kernel::landlock_child::llm_cage_enforced() {
        let st = state.clone();
        let pid = agent_pid.clone();
        let msgs = stream_messages.clone();
        let max = req.max_tokens;
        let temp = req.temperature;
        match tokio::task::spawn_blocking(move || {
            talk_via_llm_cage(st.as_ref(), &pid, &msgs, max, temp)
        })
        .await
        {
            Ok(Ok((text, pt, ct, model, provider, _))) => {
                (text, pt, ct, "landlock_cage", model, provider)
            }
            Ok(Err(e)) => (
                format!("[error] {}", e.human_readable),
                0u32,
                0u32,
                "error",
                None,
                None,
            ),
            Err(e) => (
                format!("[error] llm_cage_join:{e}"),
                0u32,
                0u32,
                "error",
                None,
                None,
            ),
        }
    } else {
        match crate::services::settings_llms::talk_llm_router(&state, &headers, &agent_pid) {
                Some(router) => {
                    let inflight_id = format!("gw_{}", uuid::Uuid::new_v4().simple());
                    let _inflight = crate::substrate::llm_inflight::InflightGuard::register(
                        &agent_pid,
                        "llm_router",
                        &inflight_id,
                        None,
                    );
                    let chat_result = tokio::time::timeout(
                        talk_llm_wall_timeout(),
                        crate::kernel::aios::with_interrupt(
                            &agent_pid,
                            router.chat_with_overrides(
                                engine_chat_messages(&stream_messages),
                                talk_generation_overrides(
                                    state.as_ref(),
                                    &agent_pid,
                                    req.max_tokens,
                                    req.temperature,
                                ),
                            ),
                        ),
                    )
                    .await;
                    drop(_inflight);
                    match chat_result
                {
                    Err(_) => (
                        "[error] LLM provider timed out — retry Talk or check vendor reachability from this host."
                            .to_string(),
                        0u32,
                        0u32,
                        "timeout",
                        None,
                        None,
                    ),
                    Ok((_, crate::kernel::aios::CompleteOutcome::Interrupted)) => (
                        "[interrupted] Generation stopped. Partial is on /m/core/context_partial.json."
                            .to_string(),
                        0u32,
                        0u32,
                        "interrupted",
                        None,
                        None,
                    ),
                    Ok((_, crate::kernel::aios::CompleteOutcome::Denied(e))) => (
                        format!("[denied] {e}"),
                        0u32,
                        0u32,
                        "denied",
                        None,
                        None,
                    ),
                    Ok((_, crate::kernel::aios::CompleteOutcome::Done(Ok(r)))) => (
                        r.text,
                        r.input_tokens,
                        r.output_tokens,
                        "provider_api",
                        Some(r.model),
                        Some(r.provider),
                    ),
                    Ok((_, crate::kernel::aios::CompleteOutcome::Done(Err(e)))) => (
                        format!("[error] {}", e),
                        0u32,
                        0u32,
                        "error",
                        None,
                        None,
                    ),
                    }
                }
                None => (
                    "[error] LLM provider not configured. Use Settings LLM paste or connectorctl llm link."
                        .to_string(),
                    0u32,
                    0u32,
                    "no_router",
                    None,
                    None,
                ),
            }
    };

    let user_text = req
        .messages
        .iter()
        .rev()
        .find(|m| m.role.eq_ignore_ascii_case("user"))
        .map(|m| m.content.as_str())
        .unwrap_or("");
    let (response_text, output_attestation, work_unit_json, binding_json, projection_outcome, aipsprt) =
        match project_talk_for_agent(state.as_ref(), &agent_pid, &response_text, user_text) {
            Ok(v) => v,
            Err(error) => {
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    Json(crate::services::llm_output_contract::denial_json(&error)),
                )
                    .into_response();
            }
        };
    if let Err(error) =
        crate::substrate::llm_broker_gate::inspect_model_output(&state, &agent_pid, &response_text)
    {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(crate::services::llm_output_contract::denial_json(&error)),
        )
            .into_response();
    }
    note_talk_crossing(
        &agent_pid,
        &stream_messages,
        &response_text,
        stub_mode || !state.llm_wired(),
    );

    let total_tokens = prompt_tokens + completion_tokens;

    // B1 OTel span for streaming call
    {
        let _span = tracing::info_span!(
            "gen_ai.chat.stream",
            "gen_ai.system"                 = "connector",
            "gen_ai.request.model"          = %model,
            "gen_ai.usage.input_tokens"     = prompt_tokens,
            "gen_ai.usage.output_tokens"    = completion_tokens,
            "gen_ai.response.finish_reason" = "stop",
            "agent.id"                      = %agent_pid,
            "session.id"                    = %namespace,
            "streaming"                     = true,
        );
    }
    let stream_session_id = format!("gateway-stream-{}", uuid::Uuid::new_v4().simple());
    arc_lease.success();
    open_stream.disarm();
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &stream_talk_atu,
        "ok",
        serde_json::json!({
            "observed": true,
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens,
            "model": served_model.clone().unwrap_or_else(|| model.clone()),
            "provider": served_provider.clone(),
            "streaming": true,
            "action_digest": stream_talk_atu.action_digest,
            "mission_id": stream_talk_atu.mission_id,
        }),
    );
    let (_account_id_for_billing, stream_cost_usd) =
        crate::services::billing::record_llm_completion_side_effects(
            &state,
            &agent_pid,
            &stream_session_id,
            &model,
            prompt_tokens,
            completion_tokens,
            stub_mode,
            "chat_stream",
            false,
            Some(token_source),
            served_model.as_deref(),
            served_provider.as_deref(),
        );

    // Audit entry
    {
        use connector_engine::engine_store::EngineAuditEntry;
        let entry = EngineAuditEntry {
            timestamp: chrono::Utc::now().timestamp_millis(),
            category: "llm_gateway".to_string(),
            agent_pid: Some(agent_pid.clone()),
            action: "llm.chat.stream".to_string(),
            resource: Some(model.clone()),
            verdict: Some("allowed".to_string()),
            details: Some(serde_json::json!({
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens,
                "streaming": true,
                "token_source": token_source,
                "cost_usd_estimated": stream_cost_usd,
            })),
            severity: "info".to_string(),
        };
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.append_audit(&entry);
    }

    // Split projected text via GovernedStreamGate (INV-04) — never raw provider framing.
    let words =
        crate::substrate::governed_stream_gate::chunk_projected_text(&response_text, 24);

    let call_id_clone = call_id.clone();
    let model_clone = served_model.clone().unwrap_or_else(|| model.clone());
    let agent_pid_clone = agent_pid.clone();
    let work_unit_json_clone = work_unit_json.clone();
    let binding_json_clone = binding_json.clone();
    let projection_outcome_clone = projection_outcome.clone();
    let aipsprt_clone = aipsprt.clone();

    let stream = async_stream::stream! {
        for word in words {
            let chunk = serde_json::json!({
                "id": call_id_clone,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model_clone,
                "choices": [{
                    "index": 0,
                    "delta": { "role": "assistant", "content": word },
                    "finish_reason": null
                }]
            });
            yield Ok::<Event, Infallible>(
                Event::default()
                    .event("message")
                    .data(chunk.to_string())
            );
        }
        // Final chunk with finish_reason + usage
        let final_chunk = serde_json::json!({
            "id": call_id_clone,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model_clone,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "connector_output_attestation": output_attestation,
            "connector_identity_work_unit": work_unit_json_clone,
            "connector_intelligence_binding": binding_json_clone,
            "connector_projection_outcome": projection_outcome_clone,
            "connector_aipsprt": aipsprt_clone,
        });
        yield Ok::<Event, Infallible>(
            Event::default().event("message").data(final_chunk.to_string())
        );
        if let Some(ref p) = aipsprt_clone {
            yield Ok::<Event, Infallible>(
                Event::default().event("aipsprt").data(p.to_string())
            );
        }
        // OpenAI-compatible DONE marker
        yield Ok::<Event, Infallible>(Event::default().data("[DONE]"));
    };

    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();

    // B8: X-Connector-Session-Id for client-side session tracking
    if let Ok(v) = axum::http::HeaderValue::from_str(&namespace) {
        response.headers_mut().insert("x-connector-session-id", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&agent_pid_clone) {
        response.headers_mut().insert("x-connector-agent-pid", v);
    }
    let metering = if prompt_tokens.saturating_add(completion_tokens) == 0 {
        "unavailable"
    } else {
        token_source
    };
    if let Ok(v) = axum::http::HeaderValue::from_str(metering) {
        response
            .headers_mut()
            .insert("x-connector-usage-metering", v);
    }
    response
}

/// GET /api/v1/gateway/status — dashboard: which LLM provider/model the node routes (not on /v1).
pub async fn gateway_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let stub = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let (routed_provider, routed_model) = state
        .llm_router_arc()
        .and_then(|r| r.primary_provider_model())
        .unwrap_or_else(|| ("none".to_string(), "none".to_string()));
    let cfg = state.llm_config_snapshot();
    let default_provider = cfg
        .as_ref()
        .map(|c| c.provider.clone())
        .unwrap_or_else(|| "none".to_string());
    let default_model = cfg
        .as_ref()
        .map(|c| c.model.clone())
        .unwrap_or_else(|| "none".to_string());
    let llm_mode = if stub {
        "simulation"
    } else if state.llm_wired() {
        "live"
    } else {
        "unconfigured"
    };

    Json(serde_json::json!({
        "llm_router_active": state.llm_wired(),
        "stub_mode": stub,
        "llm_mode": llm_mode,
        "simulation": stub,
        "default_provider": default_provider,
        "default_model": default_model,
        "routed_provider": routed_provider,
        "routed_model": routed_model,
        "openai_models_path": "/v1/models",
        "note": "llm_mode=simulation means canned stub replies (CONNECTOR_LLM_STUB=1|true), not a live governed model. routed_* is the engine primary route when live.",
        "link_path": "/api/v1/settings/llms/link",
    }))
}

/// GET /v1/models — returns available models (OpenAI-compatible).
pub async fn list_models(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let has_llm = state.llm_wired();
    let cfg = state.llm_config_snapshot();
    let provider = cfg
        .as_ref()
        .map(|c| c.provider.clone())
        .unwrap_or_else(|| "none".to_string());
    let model = cfg
        .as_ref()
        .map(|c| c.model.clone())
        .unwrap_or_else(|| "none".to_string());

    Json(serde_json::json!({
        "object": "list",
        "data": if has_llm {
            vec![serde_json::json!({
                "id": model,
                "object": "model",
                "owned_by": provider,
                "connector_routed": true,
            })]
        } else {
            vec![]
        },
        "connector_note": "Route through Connector AI Gateway for automatic audit coverage."
    }))
}
