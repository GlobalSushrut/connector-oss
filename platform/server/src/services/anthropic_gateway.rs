//! Anthropic Messages API Gateway — POST /v1/messages for Claude Code integration.
//!
//! Claude Code sends `POST /v1/messages` in Anthropic format with content blocks:
//! text, tool_use, tool_result, image. This endpoint accepts that format,
//! runs the full DevGuard pipeline (admission, FS guard, exec guard, secret scan,
//! RAG, audit), proxies to the real Anthropic API, and returns Anthropic format.
//!
//! Integration: `ANTHROPIC_BASE_URL=http://localhost:9091 claude "task"`
//!
//! Production controller. Not a demo.

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;
use axum::http::HeaderMap;
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

// ── Anthropic Messages API types ────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: AnthropicContent,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum AnthropicContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl AnthropicContent {
    pub fn to_text(&self) -> String {
        match self {
            AnthropicContent::Text(s) => s.clone(),
            AnthropicContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text } => Some(text.clone()),
                    ContentBlock::ToolResult { content, .. } => content.as_ref().map(|c| c.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    pub fn tool_use_blocks(&self) -> Vec<&ContentBlock> {
        match self {
            AnthropicContent::Text(_) => vec![],
            AnthropicContent::Blocks(blocks) => blocks
                .iter()
                .filter(|b| matches!(b, ContentBlock::ToolUse { .. }))
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: Option<String>,
        #[serde(default)]
        is_error: bool,
    },
    #[serde(rename = "image")]
    Image { source: serde_json::Value },
}

#[derive(Debug, Deserialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<AnthropicMessage>,
    #[serde(default)]
    pub system: Option<serde_json::Value>, // string or array of content blocks
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub stream: bool,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: Option<serde_json::Value>,
}

fn default_max_tokens() -> u32 {
    4096
}

#[derive(Debug, Serialize)]
pub struct AnthropicResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub role: String,
    pub model: String,
    pub content: Vec<ResponseBlock>,
    pub stop_reason: String,
    pub usage: AnthropicUsage,
    pub connector_output_attestation: crate::services::llm_output_contract::OutputAttestation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_identity_work_unit: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_intelligence_binding: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_projection_outcome: Option<String>,
    /// AiPassport — sibling to content; not inside hashed payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_aipsprt: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ResponseBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnthropicUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

// ── Header extraction ──────────────────────────────────────────────────────

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    header_str(headers, "x-api-key").or_else(|| {
        header_str(headers, "authorization")
            .map(|a| a.strip_prefix("Bearer ").unwrap_or(&a).to_string())
    })
}

fn extract_system_text(system: &Option<serde_json::Value>) -> String {
    match system {
        None => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| {
                v.get("text")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn inject_anthropic_block(system: &mut Option<serde_json::Value>, marker: &str, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    match system {
        Some(serde_json::Value::String(s)) => {
            if !s.contains(marker) {
                *s = format!("{s}\n{text}");
            }
        }
        Some(serde_json::Value::Array(arr)) => {
            let already = arr.iter().any(|v| {
                v.get("text")
                    .and_then(|t| t.as_str())
                    .map(|t| t.contains(marker))
                    .unwrap_or(false)
            });
            if !already {
                arr.insert(0, serde_json::json!({"type": "text", "text": text}));
            }
        }
        Some(_) | None => {
            *system = Some(serde_json::Value::String(text.to_string()));
        }
    }
}

/// Inject authoritative who_am_i into Anthropic `system` (string or content-block array).
fn inject_anthropic_identity(system: &mut Option<serde_json::Value>, identity: &str) {
    const MARKER: &str = "--- CONNECTOR AUTHORITATIVE IDENTITY (never contradict) ---";
    let block = format!("{MARKER}\n{identity}");
    match system {
        Some(serde_json::Value::String(s)) => {
            if !s.contains(MARKER) {
                *s = format!("{s}\n{block}");
            }
        }
        Some(serde_json::Value::Array(arr)) => {
            let already = arr.iter().any(|v| {
                v.get("text")
                    .and_then(|t| t.as_str())
                    .map(|t| t.contains(MARKER))
                    .unwrap_or(false)
            });
            if !already {
                arr.insert(0, serde_json::json!({"type": "text", "text": block}));
            }
        }
        Some(_) | None => {
            *system = Some(serde_json::Value::String(block));
        }
    }
}

fn extract_command_from_tool_use(input: &serde_json::Value) -> Option<String> {
    input
        .get("command")
        .or_else(|| input.get("cmd"))
        .or_else(|| input.get("CommandLine"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ── Main handler ───────────────────────────────────────────────────────────

/// POST /v1/messages — Anthropic Messages API (for Claude Code)
pub async fn anthropic_messages(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(mut req): Json<AnthropicRequest>,
) -> Result<axum::response::Response, ConnectorError> {
    let api_key = extract_api_key(&headers).unwrap_or_default();
    let anthropic_version = header_str(&headers, "anthropic-version").unwrap_or_default();
    let anthropic_beta = header_str(&headers, "anthropic-beta");
    let _session_header = header_str(&headers, "x-claude-code-session-id");

    // ── Resolve gateway session context via registered hooks ───────────────
    super::gateway_hooks::ensure_default_hooks();
    let (session_id, mut agent_pid, role) =
        match crate::services::gateway::require_linked_repo_identity(&state, &api_key, &headers)? {
            Some(t) => t,
            None => {
                let session_ctx = super::gateway_hooks::resolve_session(&state, &api_key);
                session_ctx
                    .map(|ctx| (ctx.session_id, ctx.agent_pid, ctx.role))
                    .unwrap_or_else(|| {
                        // B3: do not elevate anon to "builder". Prefer explicit agent header.
                        let pid = header_str(&headers, "x-connector-agent-pid")
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "gateway-anthropic".to_string());
                        ("anon".to_string(), pid, String::new())
                    })
            }
        };
    if let Some(hdr_pid) = header_str(&headers, "x-connector-agent-pid").filter(|s| !s.is_empty()) {
        agent_pid = hdr_pid;
    }
    crate::services::gateway::enforce_real_agent_talk(&state, &agent_pid, &session_id, &headers)?;

    let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid_pub(&state, &agent_pid);
    let namespace = crate::services::agents::canonical_agent_memory_namespace(&kernel_pid);

    // ── Flatten messages to text for pipeline processing ───────────────────
    let full_text: String = req
        .messages
        .iter()
        .map(|m| m.content.to_text())
        .collect::<Vec<_>>()
        .join(" ");

    // ── ADMISSION GATE ─────────────────────────────────────────────────────
    let _admission = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        &agent_pid,
        &namespace,
        crate::services::admission::AdmissionOp::LlmChat,
        Some(&full_text),
    )?;

    crate::substrate::ops_runtime::preflight_agent_effect(&state, &agent_pid)?;

    // Provider parity: all Talk paths use the same digest-bound charter/HITL gate (PATE ATU).
    let mission_hdr = headers
        .get("x-connector-mission-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let talk_atu = match crate::substrate::pate::admit_talk(
        &state,
        &agent_pid,
        &namespace,
        &full_text,
        mission_hdr,
    ) {
        Ok(atu) if !crate::substrate::pate::host_admission_allows_execution(atu.verdict) => {
            return Err(ConnectorError::new(DenialReason::PolicyDenied, "not_proceed")
                .with_denied_resource("llm.chat")
                .with_hint(&format!(
                    "Ask stays open. task_id={} Approve the digest, then retry Anthropic Talk.",
                    atu.task_id
                )));
        }
        Ok(atu) => atu,
        Err(e) => {
            let hitl = e.human_readable.to_ascii_lowercase().contains("hitl");
            return Err(e
                .with_denied_resource("llm.chat")
                .with_hint(if hitl {
                    "Approve digest-bound HITL then retry Anthropic Talk"
                } else {
                    "Agent charter must allow chat|llm"
                }));
        }
    };
    let mut open_talk = crate::substrate::pate::OpenProceed::arm(&state, &talk_atu);

    // ── AAPI BCR budget check ──────────────────────────────────────────────
    {
        let estimated_input = full_text.len() as f64 / 4.0 + 1.0;
        crate::substrate::ops_runtime::spend_tokens(
            &state,
            &agent_pid,
            estimated_input,
            Some(talk_atu.action_digest.as_str()),
        )?;
    }

    // ── C9: charter must allow Talk ────────────────────────────────────────
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &agent_pid,
        "llm.chat",
        &namespace,
    ) {
        return Err(ConnectorError::new(DenialReason::PolicyDenied, e)
            .with_denied_resource("llm.chat")
            .with_hint("PATCH /api/v1/agents/:pid/contract capabilities must include chat|llm"));
    }

    // ── DI-5: economy pricer budget-gate ───────────────────────────────────
    if let Some((spent, max_spend, remaining)) =
        crate::services::economy::economy_budget_gate_violation(state.as_ref(), &agent_pid)
    {
        return Err(ConnectorError::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Economy budget gate exceeded for agent '{agent_pid}': spent {spent} ≥ max {max_spend} (remaining {remaining})."
            ),
        )
        .with_denied_resource("llm.budget_gate")
        .with_hint(&format!("GET /api/v1/economy/budget-gate/{agent_pid}")));
    }

    // ── DI-5: anomaly gate (opt-in) ────────────────────────────────────────
    if let Some((rate, total, denied)) =
        crate::services::monitor::anomaly_gate_violation(state.as_ref(), &agent_pid)
    {
        return Err(ConnectorError::new(
            DenialReason::RateLimitExceeded,
            format!(
                "Anomaly gate: agent '{agent_pid}' HIGH_DENY_RATE {rate:.2} ({denied}/{total} ops in 24h)."
            ),
        )
        .with_denied_resource("llm.anomaly_gate")
        .with_hint("GET /api/v1/monitor/anomalies/v2 · unset CONNECTOR_IIA_ANOMALY_GATE to disable"));
    }

    // ── DEVGUARD: FS Guard + Secret Scan on all message content ────────────
    let mut guarded_messages = req.messages.clone();
    let mut total_secrets_redacted: usize = 0;
    for msg in &mut guarded_messages {
        let text = msg.content.to_text();
        let (sanitized, redacted) =
            super::gateway_hooks::guard_message_content(&state, &agent_pid, &text);
        total_secrets_redacted += redacted;
        if redacted > 0 {
            msg.content = AnthropicContent::Text(sanitized);
        }
    }

    // Unbypassable broker ingress — no raw data to LLM brain.
    if crate::substrate::llm_broker_gate::broker_unbypassable() {
        for msg in &mut guarded_messages {
            match &mut msg.content {
                AnthropicContent::Text(s) => {
                    *s = crate::substrate::llm_broker_gate::ingress_to_llm(&state, &agent_pid, s)?;
                }
                AnthropicContent::Blocks(blocks) => {
                    for b in blocks.iter_mut() {
                        if let ContentBlock::Text { text } = b {
                            *text = crate::substrate::llm_broker_gate::ingress_to_llm(
                                &state, &agent_pid, text,
                            )?;
                        }
                        if let ContentBlock::ToolResult {
                            content: Some(c), ..
                        } = b
                        {
                            *c = crate::substrate::llm_broker_gate::ingress_to_llm(
                                &state, &agent_pid, c,
                            )?;
                        }
                    }
                }
            }
        }
    }

    // ── DEVGUARD: Exec Guard on tool_use blocks ────────────────────────────
    // Parse tool_use blocks and check commands before forwarding
    let mut blocked_tools: Vec<String> = Vec::new();
    for msg in &guarded_messages {
        for block in msg.content.tool_use_blocks() {
            if let ContentBlock::ToolUse { name, input, id } = block {
                // Check bash/shell commands
                if name == "bash" || name == "execute" || name == "shell" || name == "run_command" {
                    if let Some(cmd) = extract_command_from_tool_use(input) {
                        if let Err(e) = crate::kernel::action_binding::admit_devguard_exec_or_ask(
                            &state, &agent_pid, &cmd,
                        ) {
                            let label = if e.get("error").and_then(|v| v.as_str())
                                == Some("hitl_required")
                            {
                                "NEEDS_APPROVAL"
                            } else {
                                "DENIED"
                            };
                            blocked_tools.push(format!(
                                "tool_use {} ({}) {}: {}",
                                id,
                                cmd,
                                label,
                                e.get("denial_reason")
                                    .or_else(|| e.get("error"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("blocked"),
                            ));
                            if let Some(rid) = e.get("request_id").and_then(|v| v.as_str()) {
                                blocked_tools.push(format!(
                                    "  approve: /api/v1/agents/{}/hitl/{}/approve",
                                    agent_pid, rid
                                ));
                            }
                        }
                    }
                }
                // Check file operations
                if name == "file_edit" || name == "write" || name == "Write" {
                    if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
                        if let Err(e) = crate::kernel::action_binding::admit_devguard_fs_or_ask(
                            &state, &agent_pid, "write", path,
                        ) {
                            let label = if e.get("error").and_then(|v| v.as_str())
                                == Some("hitl_required")
                            {
                                "NEEDS_APPROVAL"
                            } else {
                                "DENIED"
                            };
                            blocked_tools.push(format!(
                                "tool_use {} (write {}) {}: {}",
                                id,
                                path,
                                label,
                                e.get("denial_reason")
                                    .or_else(|| e.get("error"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("blocked"),
                            ));
                        }
                    }
                }
                if name == "Read" || name == "read" || name == "read_file" {
                    if let Some(path) = input.get("path").and_then(|v| v.as_str()) {
                        if let Err(e) = crate::kernel::action_binding::admit_devguard_fs_or_ask(
                            &state, &agent_pid, "read", path,
                        ) {
                            blocked_tools.push(format!(
                                "tool_use {} (read {}) DENIED: {}",
                                id,
                                path,
                                e.get("denial_reason")
                                    .or_else(|| e.get("error"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("blocked"),
                            ));
                        }
                    }
                }
            }
        }
    }

    // If any tool_use blocks were blocked, return error to Claude Code
    if !blocked_tools.is_empty() {
        let blocked_text = format!(
            "[DevGuard] The following operations were blocked by policy:\n{}",
            blocked_tools.join("\n")
        );
        let output_attestation = crate::services::llm_output_contract::enforce(
            state.as_ref(),
            &agent_pid,
            &blocked_text,
        )?;
        let response = AnthropicResponse {
            id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
            msg_type: "message".into(),
            role: "assistant".into(),
            model: req.model.clone(),
            content: vec![ResponseBlock {
                block_type: "text".into(),
                text: Some(blocked_text),
            }],
            stop_reason: "end_turn".into(),
            usage: AnthropicUsage {
                input_tokens: 0,
                output_tokens: 0,
            },
            connector_output_attestation: output_attestation,
            connector_identity_work_unit: None,
            connector_intelligence_binding: None,
            connector_projection_outcome: Some("pass".into()),
            connector_aipsprt: None,
        };
        return Ok(Json(response).into_response());
    }

    // ── B3: bind the shared vendor brain to Connector identity on every Talk turn.
    let mut system_for_llm = req.system.clone();
    let prepared = crate::substrate::governed_talk_core::prepare_talk(
        &state,
        &agent_pid,
        &req.model,
        "anthropic",
    )?;
    for block in &prepared.system_blocks {
        inject_anthropic_block(
            &mut system_for_llm,
            if block.contains(crate::substrate::intelligence_binding::BIND_MARKER) {
                crate::substrate::intelligence_binding::BIND_MARKER
            } else {
                crate::substrate::intelligence_work_unit::ENVELOPE_MARKER
            },
            block,
        );
    }
    let work_unit = prepared.work_unit;
    let authoritative =
        crate::services::llm_output_contract::resolve_authoritative_identity(
            state.as_ref(),
            &agent_pid,
        );
    if !authoritative.is_empty() {
        inject_anthropic_identity(&mut system_for_llm, &authoritative);
    }
    if crate::substrate::llm_context_broker::broker_enforced() {
        match crate::substrate::agentic_context::require_or_hitl(&state, &agent_pid) {
            Ok(ctx) => {
                let binding = crate::substrate::llm_context_broker::inject_for_talk(
                    &state, &agent_pid, &ctx,
                )?;
                inject_anthropic_block(
                    &mut system_for_llm,
                    crate::substrate::llm_context_broker::MARKER,
                    &binding.render_tokenized_prompt(),
                );
            }
            Err(e) => return Err(e),
        }
    } else {
        match crate::substrate::agentic_context::require_or_hitl(&state, &agent_pid) {
            Ok(ctx) => {
                inject_anthropic_block(
                    &mut system_for_llm,
                    crate::substrate::agentic_context::MARKER,
                    &ctx.render_prompt(),
                );
            }
            Err(e) => return Err(e),
        }
        let memory_core = crate::services::gateway::memory_os_core_prompt(&agent_pid);
        inject_anthropic_block(
            &mut system_for_llm,
            "--- CONNECTOR MEMORY OS CORE",
            &memory_core,
        );
        let desk = crate::kernel::council::desk_prompt(state.as_ref(), &agent_pid);
        if !desk.is_empty() {
            inject_anthropic_block(&mut system_for_llm, "--- CONNECTOR COUNCIL DESK", &desk);
        }
        let user_query: String = req
            .messages
            .iter()
            .filter(|m| m.role.eq_ignore_ascii_case("user"))
            .map(|m| m.content.to_text())
            .collect::<Vec<_>>()
            .join(" ");
        let rag_context = crate::concurrency::kernel_handle::build_agent_rag_context_async(
            state.clone(),
            agent_pid.clone(),
            namespace.clone(),
            user_query,
        )
        .await;
        if !rag_context.is_empty() {
            inject_anthropic_identity(&mut system_for_llm, &rag_context);
        }
    }

    // RangeGuard transfer bind (soft-fail; never replaces identity).
    if !crate::services::playground::is_playground_mode() {
        let action_digest = {
            use sha2::{Digest, Sha256};
            let q: String = req
                .messages
                .iter()
                .filter(|m| m.role.eq_ignore_ascii_case("user"))
                .map(|m| m.content.to_text())
                .collect::<Vec<_>>()
                .join(" ");
            let h = format!("{:x}", Sha256::digest(q.as_bytes()));
            format!("talk:{}", &h[..h.len().min(16)])
        };
        match crate::substrate::crk::talk_bind::bind_for_talk(
            &state,
            &agent_pid,
            &action_digest,
            None,
            "low",
            2048,
            "default",
            Some("anthropic"),
            Some(&req.model),
        ) {
            Ok(bound) => {
                if crate::substrate::crk::transfer::assert_render_matches(
                    &bound.transfer,
                    &bound.exact_render,
                )
                .is_ok()
                {
                    let block = format!(
                        "{}\ntransfer_id: {}\ntransfer_digest: {}\n{}",
                        crate::substrate::crk::talk_bind::MARKER,
                        bound.transfer.transfer_id,
                        bound.transfer.transfer_digest(),
                        bound.exact_render
                    );
                    inject_anthropic_block(
                        &mut system_for_llm,
                        crate::substrate::crk::talk_bind::MARKER,
                        &block,
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, agent = %agent_pid, "crk_transfer_anthropic_skipped");
            }
        }
    }
    inject_anthropic_block(
        &mut system_for_llm,
        "--- CONNECTOR LLM BRAIN BINDING",
        "The Anthropic model is transport, not this agent's identity or authority. \
         Never claim Claude, Anthropic, ChatGPT, Gemini, DeepSeek, OpenAI, Google, \
         or generic-assistant identity. Speak only as the Connector agent above. \
         Tool calls and effects remain governed by Connector admission, broker token, \
         principal, contract, and execution rails.",
    );

    // ── PROXY to real Anthropic API ────────────────────────────────────────
    let stub_mode = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if crate::services::gateway::llm_stub_blocked_in_prod() {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "llm_stub_banned_in_production",
        )
        .with_denied_resource("llm.chat"));
    }
    crate::services::gateway::reserve_playground_talk_budget(
        &state,
        &session_id,
        full_text.len(),
        req.max_tokens,
    )?;

    // SpendCease cancel-tax bound: clamp Anthropic max_tokens to remaining ceiling.
    req.max_tokens = crate::substrate::spend_cease::clamp_max_tokens(
        state.as_ref(),
        &agent_pid,
        req.max_tokens,
        8_192,
    );

    let mut served_model: Option<String> = if stub_mode { Some("stub".into()) } else { None };
    let served_provider: Option<String> = if stub_mode {
        Some("stub".into())
    } else {
        Some("anthropic".into())
    };

    let (response_text, input_tokens, output_tokens, stop_reason) = if stub_mode {
        let stub_reply = format!(
            "[DevGuard stub] Session: {} | Role: {} | Secrets redacted: {} | \
            Set CONNECTOR_LLM_API_KEY for real LLM. All guards active in stub mode.",
            session_id, role, total_secrets_redacted
        );
        (
            stub_reply,
            full_text.len() as u32 / 4,
            50u32,
            "end_turn".to_string(),
        )
    } else {
        // Use real Anthropic API key from env
        let real_api_key = std::env::var("ANTHROPIC_API_KEY")
            .or_else(|_| std::env::var("CONNECTOR_ANTHROPIC_API_KEY"))
            .or_else(|_| std::env::var("CONNECTOR_LLM_API_KEY"))
            .map_err(|_| ConnectorError::new(
                DenialReason::InternalError,
                "No Anthropic API key configured. Set ANTHROPIC_API_KEY or CONNECTOR_ANTHROPIC_API_KEY.",
            ))?;

        let real_base = std::env::var("ANTHROPIC_REAL_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());

        // Build proxy request body — forward the guarded messages
        let proxy_body = serde_json::json!({
            "model": req.model,
            "messages": guarded_messages,
            "max_tokens": req.max_tokens,
            "system": system_for_llm,
            "stream": false,
            "temperature": req.temperature,
            "tools": req.tools,
            "tool_choice": req.tool_choice,
        });

        let url = format!("{}/v1/messages", real_base);
        let ver = if anthropic_version.is_empty() {
            "2023-06-01".to_string()
        } else {
            anthropic_version.clone()
        };
        let _ = crate::kernel::llm_vendor_cut::engage(
            state.as_ref(),
            &session_id,
            &agent_pid,
            "claude_code",
            "anthropic_messages",
        );
        let inflight_id = format!("anth_{}", uuid::Uuid::new_v4().simple());
        let _inflight = crate::substrate::llm_inflight::InflightGuard::register(
            &agent_pid,
            "anthropic",
            &inflight_id,
            None,
        );
        let (status, mut body) = if crate::kernel::landlock_child::llm_cage_enforced() {
            let _ = crate::kernel::pore_table::upsert_llm_provider(state.as_ref(), &real_base);
            let st = state.clone();
            let url2 = url.clone();
            let key = real_api_key.clone();
            let ver2 = ver.clone();
            let beta = anthropic_beta.clone();
            let payload = proxy_body.clone();
            let fetched = tokio::task::spawn_blocking(move || {
                let mut headers = serde_json::json!({
                    "x-api-key": key,
                    "anthropic-version": ver2,
                    "content-type": "application/json",
                });
                if let Some(b) = beta {
                    headers["anthropic-beta"] = serde_json::Value::String(b);
                }
                crate::kernel::landlock_child::http_fetch(
                    st.as_ref(),
                    crate::kernel::pore_table::LLM_SYSTEM_AGENT,
                    crate::kernel::pore_table::LLM_PROVIDER_ADDR,
                    &url2,
                    "POST",
                    headers,
                    Some(payload),
                    60_000,
                )
            })
            .await
            .map_err(|e| ConnectorError::internal(format!("llm_cage_join:{e}")))?
            .map_err(|e| {
                ConnectorError::internal(format!("LLM cage vendor pore failed: {e}"))
                    .with_denied_resource("llm.vendor_cut")
            })?;
            let status = fetched
                .get("status")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let body = fetched
                .get("body")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            (status, body)
        } else {
            let client = crate::substrate::egress_policy::reqwest_client_pinned(
                &url,
                std::time::Duration::from_secs(60),
            )
            .map_err(|e| {
                ConnectorError::new(DenialReason::InternalError, format!("dns_pin: {e}"))
            })?;
            let mut proxy_req = client
                .post(&url)
                .header("x-api-key", &real_api_key)
                .header("anthropic-version", &ver)
                .header("content-type", "application/json");
            if let Some(beta) = &anthropic_beta {
                proxy_req = proxy_req.header("anthropic-beta", beta);
            }
            let resp = proxy_req
                .json(&proxy_body)
                .send()
                .await
                .map_err(|e| ConnectorError::internal(format!("Anthropic API error: {}", e)))?;
            let status = resp.status().as_u16();
            let body: serde_json::Value = resp.json().await.map_err(|e| {
                ConnectorError::internal(format!("Anthropic response parse error: {}", e))
            })?;
            (status, body)
        };
        drop(_inflight);

        if status >= 400 {
            let err_msg = body
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown Anthropic error");
            return Err(ConnectorError::new(
                DenialReason::InternalError,
                format!("Anthropic API {} error: {}", status, err_msg),
            ));
        }

        // Extract response fields
        let resp_text = body
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let in_tok = body
            .get("usage")
            .and_then(|u| u.get("input_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let out_tok = body
            .get("usage")
            .and_then(|u| u.get("output_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let stop = body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("end_turn")
            .to_string();
        served_model = body
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| Some(req.model.clone()));

        // If response contains content blocks (tool_use etc.), pass through directly
        if let Some(content_arr) = body.get("content").and_then(|c| c.as_array()) {
            let has_tool_use = content_arr
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"));
            if has_tool_use {
                let tool_calls = content_arr
                    .iter()
                    .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                    .cloned()
                    .collect::<Vec<_>>();
                let output_attestation = crate::services::llm_output_contract::enforce(
                    state.as_ref(),
                    &agent_pid,
                    &resp_text,
                )?;
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "connector_output_attestation".into(),
                        serde_json::to_value(&output_attestation)
                            .unwrap_or(serde_json::Value::Null),
                    );
                    obj.insert(
                        "connector_identity_work_unit".into(),
                        work_unit.to_json(),
                    );
                    obj.insert(
                        "connector_intelligence_binding".into(),
                        crate::substrate::intelligence_binding::status(
                            state.as_ref(),
                            &agent_pid,
                        ),
                    );
                    obj.insert(
                        "connector_projection_outcome".into(),
                        serde_json::Value::String("pass".into()),
                    );
                }
                if let Some(err) =
                    crate::intelligence_admission::gateway_intercept::block_model_tool_calls(
                        &tool_calls,
                        &agent_pid,
                    )
                {
                    return Err(err);
                }
                let _ = crate::services::gateway::persist_gateway_packet(
                    &state,
                    &agent_pid,
                    &namespace,
                    &req.model,
                    vac_core::types::PacketType::Input,
                    vac_core::types::MemoryType::Working,
                    serde_json::json!({
                        "kind": "anthropic_prompt",
                        "system": system_for_llm,
                        "messages": guarded_messages,
                        "secrets_redacted": total_secrets_redacted,
                    }),
                    vec!["llm".into(), "anthropic".into(), "prompt".into()],
                    &session_id,
                );
                let _ = crate::services::gateway::persist_gateway_packet(
                    &state,
                    &agent_pid,
                    &namespace,
                    &req.model,
                    vac_core::types::PacketType::LlmRaw,
                    vac_core::types::MemoryType::Episodic,
                    serde_json::json!({
                        "kind": "anthropic_tool_use_response",
                        "response": body,
                        "input_tokens": in_tok,
                        "output_tokens": out_tok,
                    }),
                    vec!["llm".into(), "anthropic".into(), "tool_use".into()],
                    &session_id,
                );
                // Pass through the raw Anthropic response (tool_use blocks need to go back to Claude Code)
                let _ = crate::services::billing::record_llm_completion_side_effects(
                    &state,
                    &agent_pid,
                    &session_id,
                    &req.model,
                    in_tok,
                    out_tok,
                    stub_mode,
                    "anthropic_messages",
                    true,
                    None,
                    served_model.as_deref(),
                    served_provider.as_deref(),
                );
                open_talk.disarm();
                let _ = crate::substrate::pate::complete_augmented_task(
                    &state,
                    &talk_atu,
                    "ok",
                    serde_json::json!({
                        "observed": true,
                        "input_tokens": in_tok,
                        "output_tokens": out_tok,
                        "model": served_model.clone().unwrap_or_else(|| req.model.clone()),
                        "provider": served_provider.clone(),
                        "tool_use": true,
                        "action_digest": talk_atu.action_digest,
                        "mission_id": talk_atu.mission_id,
                    }),
                );
                super::gateway_hooks::record_llm_call(
                    &state,
                    &session_id,
                    &agent_pid,
                    in_tok,
                    out_tok,
                );
                return Ok(Json(body).into_response());
            }
        }

        (resp_text, in_tok, out_tok, stop)
    };
    let finalized = crate::substrate::governed_talk_core::finalize_talk(
        state.as_ref(),
        &agent_pid,
        &response_text,
        &full_text,
        &work_unit,
    )?;
    let response_text = finalized.text;
    let output_attestation = finalized.attestation;
    let projection_outcome = match finalized.outcome {
        crate::substrate::principal_projection::ProjectionOutcome::Pass => "pass",
        crate::substrate::principal_projection::ProjectionOutcome::Project => "project",
        crate::substrate::principal_projection::ProjectionOutcome::Deny => "deny",
    };
    crate::substrate::llm_broker_gate::inspect_model_output(&state, &agent_pid, &response_text)?;

    // ── Billing + audit (REG-007: same durable path as OpenAI-compat gateway) ─
    let _ = crate::services::billing::record_llm_completion_side_effects(
        &state,
        &agent_pid,
        &session_id,
        &req.model,
        input_tokens,
        output_tokens,
        stub_mode,
        "anthropic_messages",
        true,
        None,
        served_model.as_deref().or(Some(req.model.as_str())),
        served_provider.as_deref(),
    );
    open_talk.disarm();
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &talk_atu,
        "ok",
        serde_json::json!({
            "observed": true,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model": served_model.clone().unwrap_or_else(|| req.model.clone()),
            "provider": served_provider.clone(),
            "action_digest": talk_atu.action_digest,
            "mission_id": talk_atu.mission_id,
        }),
    );
    super::gateway_hooks::record_llm_call(
        &state,
        &session_id,
        &agent_pid,
        input_tokens,
        output_tokens,
    );

    // Durable memory/audit parity with the OpenAI-compatible gateway.
    let _ = crate::services::gateway::persist_gateway_packet(
        &state,
        &agent_pid,
        &namespace,
        &req.model,
        vac_core::types::PacketType::Input,
        vac_core::types::MemoryType::Working,
        serde_json::json!({
            "kind": "anthropic_prompt",
            "system": system_for_llm,
            "messages": guarded_messages,
            "secrets_redacted": total_secrets_redacted,
        }),
        vec!["llm".into(), "anthropic".into(), "prompt".into()],
        &session_id,
    );
    let _ = crate::services::gateway::persist_gateway_packet(
        &state,
        &agent_pid,
        &namespace,
        &req.model,
        vac_core::types::PacketType::LlmRaw,
        vac_core::types::MemoryType::Episodic,
        serde_json::json!({
            "kind": "anthropic_response",
            "response": response_text,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "served_model": served_model,
            "served_provider": served_provider,
        }),
        vec!["llm".into(), "anthropic".into(), "response".into()],
        &session_id,
    );

    // ── Build Anthropic-format response ────────────────────────────────────
    let response = AnthropicResponse {
        id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
        msg_type: "message".into(),
        role: "assistant".into(),
        model: req.model,
        content: vec![ResponseBlock {
            block_type: "text".into(),
            text: Some(response_text),
        }],
        stop_reason,
        usage: AnthropicUsage {
            input_tokens,
            output_tokens,
        },
        connector_output_attestation: output_attestation,
        connector_identity_work_unit: Some(finalized.work_unit),
        connector_intelligence_binding: Some(finalized.binding_status),
        connector_projection_outcome: Some(projection_outcome.to_string()),
        connector_aipsprt: finalized.aipsprt,
    };

    let aipsprt_hdr = {
        let v = response.connector_aipsprt.clone();
        v.as_ref().and_then(|val| {
            let p: connector_trust::AiPassportSigV1 = serde_json::from_value(val.clone()).ok()?;
            connector_trust::encode_aipsprt_header(&p).ok()
        })
    };
    let mut http = Json(response).into_response();
    if let Some(h) = aipsprt_hdr {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&h) {
            http.headers_mut()
                .insert(connector_trust::AIPSPRT_HEADER, hv);
        }
    }
    Ok(http)
}

/// POST /v1/messages/count_tokens — Token counting endpoint for Claude Code
pub async fn anthropic_count_tokens(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
    // Approximate token count (4 chars per token)
    let messages = req.get("messages").and_then(|v| v.as_array());
    let system = req.get("system").and_then(|v| v.as_str()).unwrap_or("");
    let mut total_chars: usize = system.len();
    if let Some(msgs) = messages {
        for m in msgs {
            if let Some(content) = m.get("content") {
                match content {
                    serde_json::Value::String(s) => total_chars += s.len(),
                    serde_json::Value::Array(arr) => {
                        for block in arr {
                            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                                total_chars += text.len();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let approx_tokens = (total_chars / 4).max(1);
    Json(serde_json::json!({
        "input_tokens": approx_tokens,
    }))
}
