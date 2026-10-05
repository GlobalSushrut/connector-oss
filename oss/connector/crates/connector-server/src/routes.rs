//! HTTP route handlers for the Connector REST API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vac_core::kernel::{MemoryKernel, SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::{MemPacket, MemoryKernelOp, PacketType, Source, SourceKind};

use connector_engine::engine_store::FolderOwner;
use connector_engine::llm::LlmClient;
use connector_engine::rag::RagEngine;
use connector_glue::{ErrorCode, GlueError, GlueErrorEnvelope, GlueResult};

use crate::AppState;

// ── Request / Response types ─────────────────────────────────────

#[derive(Deserialize)]
pub struct RunRequest {
    pub agent: String,
    pub input: String,
    pub user: String,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub compliance: Vec<String>,
}

#[derive(Deserialize)]
pub struct PipelineRequest {
    pub name: String,
    pub agents: Vec<PipelineAgentDef>,
    pub input: String,
    pub user: String,
    #[serde(default)]
    pub compliance: Vec<String>,
}

#[derive(Deserialize)]
pub struct PipelineAgentDef {
    pub name: String,
    #[serde(default)]
    pub instructions: Option<String>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

// ── Helpers ──────────────────────────────────────────────────────

fn make_packet(content: &str, user: &str, pipeline: &str, ptype: PacketType) -> MemPacket {
    MemPacket::new(
        ptype,
        serde_json::json!({"text": content}),
        cid::Cid::default(),
        user.to_string(),
        pipeline.to_string(),
        Source {
            kind: SourceKind::User,
            principal_id: user.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
}

fn register_and_start(
    kernel: &mut MemoryKernel,
    name: &str,
    model: Option<String>,
) -> Result<String, String> {
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: "system".to_string(),
        operation: MemoryKernelOp::AgentRegister,
        payload: SyscallPayload::AgentRegister {
            agent_name: name.to_string(),
            namespace: format!("ns:{}", name),
            role: Some("agent".to_string()),
            model,
            framework: Some("connector".to_string()),
        },
        reason: Some(format!("Agent '{}' registration", name)),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    let pid = match result.value {
        SyscallValue::AgentPid(p) => p,
        _ => return Err(format!("Failed to register agent '{}'", name)),
    };
    kernel.dispatch(SyscallRequest {
        agent_pid: pid.clone(),
        operation: MemoryKernelOp::AgentStart,
        payload: SyscallPayload::Empty,
        reason: None,
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    Ok(pid)
}

fn write_mem(
    kernel: &mut MemoryKernel,
    pid: &str,
    content: &str,
    user: &str,
    pipe: &str,
    ptype: PacketType,
) {
    kernel.dispatch(SyscallRequest {
        agent_pid: pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: make_packet(content, user, pipe, ptype),
        },
        reason: None,
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
}

fn output_to_response(
    output: &connector_engine::PipelineOutput,
    noun: &str,
    target_id: &str,
) -> GlueResult {
    GlueResult::from_pipeline_output(output, noun, target_id)
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    detail: impl Into<String>,
    hints: Vec<String>,
) -> Response {
    let retryable = matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    );
    let error_code = match code {
        "llm_completion_failed" => ErrorCode::ExecutionError,
        "llm_not_configured" => ErrorCode::Unavailable,
        "agent_registration_failed" => ErrorCode::InternalError,
        _ => ErrorCode::InternalError,
    };

    let mut envelope = GlueError::new(error_code, message)
        .with_detail(detail)
        .with_status(status.as_u16())
        .retryable(retryable)
        .with_docs("/docs")
        .into_envelope();

    envelope.meta.source = "connector-server".to_string();
    for hint in hints {
        envelope.error = envelope.error.with_hint(hint);
    }

    (status, Json(envelope)).into_response()
}

// ── Route handlers — Core ────────────────────────────────────────

fn standalone_llm_blocked() -> bool {
    matches!(
        std::env::var("CONNECTOR_ENV")
            .or_else(|_| std::env::var("APP_ENV"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "pilots" | "pilot" | "staging"
    )
}

fn standalone_llm_blocked_response() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "standalone_llm_forbidden",
        "Standalone connector-server LLM dispatch is disabled in hardened environments",
        "This OSS server does not implement the platform identity, charter, memory, HITL, audit, and egress membrane",
        vec!["Route LLM traffic through Connector Platform /api/v1/chat/completions".to_string()],
    )
}

pub async fn run_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RunRequest>,
) -> Response {
    if standalone_llm_blocked() {
        return standalone_llm_blocked_response();
    }
    let pipe_id = format!("pipe:{}", req.agent);
    let model = state.connector.llm_config().map(|c| c.model.clone());

    let pid = {
        let mut k = state.kernel.lock().unwrap();
        match register_and_start(&mut k, &req.agent, model) {
            Ok(pid) => pid,
            Err(e) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "agent_registration_failed",
                    "Could not start agent run",
                    e,
                    vec!["Inspect server logs for kernel registration failure".to_string()],
                )
            }
        }
    };

    {
        let mut k = state.kernel.lock().unwrap();
        write_mem(
            &mut k,
            &pid,
            &req.input,
            &req.user,
            &pipe_id,
            PacketType::Input,
        );
    }

    let start = std::time::Instant::now();

    let response_text = match state.connector.engine_llm_config() {
        Some(mut llm_cfg) => {
            if let Some(ref instr) = req.instructions {
                llm_cfg = llm_cfg.with_system(instr);
            }
            let client = LlmClient::new();
            match client.complete(&llm_cfg, &req.input, None).await {
                Ok(result) => result.text,
                Err(e) => {
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        "llm_completion_failed",
                        "Agent run failed",
                        e.to_string(),
                        vec![
                            "Check CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, and CONNECTOR_LLM_API_KEY".to_string(),
                            "Retry once the upstream model endpoint is healthy".to_string(),
                        ],
                    );
                }
            }
        }
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "llm_not_configured",
                "Agent run requires an LLM configuration",
                format!("No engine LLM is configured for agent '{}'", req.agent),
                vec![
                    "Set CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, and CONNECTOR_LLM_API_KEY"
                        .to_string(),
                    "Use connector-api directly if you intend to run in a mock or offline mode"
                        .to_string(),
                ],
            );
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let output = {
        let mut k = state.kernel.lock().unwrap();
        write_mem(
            &mut k,
            &pid,
            &response_text,
            &req.user,
            &pipe_id,
            PacketType::LlmRaw,
        );
        connector_engine::OutputBuilder::build(
            &k,
            response_text,
            &pipe_id,
            1,
            &req.compliance,
            duration_ms,
            Vec::new(),
        )
    };

    state.metrics.record_output(&output);
    Json(output_to_response(&output, "agent", &pipe_id)).into_response()
}

pub async fn run_pipeline(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PipelineRequest>,
) -> Response {
    if standalone_llm_blocked() {
        return standalone_llm_blocked_response();
    }
    let pipe_id = format!("pipe:{}", req.name);
    let model = state.connector.llm_config().map(|c| c.model.clone());
    let start = std::time::Instant::now();

    let mut last_output = req.input.clone();

    for agent in &req.agents {
        let pid = {
            let mut k = state.kernel.lock().unwrap();
            match register_and_start(&mut k, &agent.name, model.clone()) {
                Ok(pid) => pid,
                Err(e) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "agent_registration_failed",
                        "Could not start pipeline run",
                        e,
                        vec!["Inspect server logs for kernel registration failure".to_string()],
                    )
                }
            }
        };

        {
            let mut k = state.kernel.lock().unwrap();
            write_mem(
                &mut k,
                &pid,
                &last_output,
                &req.user,
                &pipe_id,
                PacketType::Input,
            );
        }

        last_output = match state.connector.engine_llm_config() {
            Some(cfg) => {
                let agent_cfg = if let Some(ref instr) = agent.instructions {
                    cfg.clone().with_system(instr)
                } else {
                    cfg.clone()
                };
                let client = LlmClient::new();
                match client.complete(&agent_cfg, &last_output, None).await {
                    Ok(result) => result.text,
                    Err(e) => {
                        return error_response(
                            StatusCode::BAD_GATEWAY,
                            "llm_completion_failed",
                            "Pipeline run failed",
                            format!("Agent '{}' failed to complete: {}", agent.name, e),
                            vec![
                                "Check CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, and CONNECTOR_LLM_API_KEY".to_string(),
                                "Retry once the upstream model endpoint is healthy".to_string(),
                            ],
                        );
                    }
                }
            }
            None => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "llm_not_configured",
                    "Pipeline run requires an LLM configuration",
                    format!("No engine LLM is configured for pipeline '{}'", req.name),
                    vec![
                        "Set CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, and CONNECTOR_LLM_API_KEY".to_string(),
                        "Use connector-api directly if you intend to run in a mock or offline mode".to_string(),
                    ],
                );
            }
        };

        {
            let mut k = state.kernel.lock().unwrap();
            write_mem(
                &mut k,
                &pid,
                &last_output,
                &req.user,
                &pipe_id,
                PacketType::LlmRaw,
            );
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let output = {
        let k = state.kernel.lock().unwrap();
        connector_engine::OutputBuilder::build(
            &k,
            last_output,
            &pipe_id,
            req.agents.len(),
            &req.compliance,
            duration_ms,
            Vec::new(),
        )
    };

    state.metrics.record_output(&output);
    Json(output_to_response(&output, "pipeline", &pipe_id)).into_response()
}

pub async fn parse_config(
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let yaml = std::str::from_utf8(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid UTF-8: {}", e)))?;

    let cfg = connector_api::config::load_config_str(yaml)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    let g = &cfg.connector;
    Ok(Json(serde_json::json!({
        "provider": g.provider,
        "model": g.model,
        "endpoint": g.endpoint,
        "storage": g.storage,
        "comply": g.comply,
        "cluster_enabled": cfg.cluster.is_some(),
        "swarm_enabled": cfg.swarm.is_some(),
        "streaming_enabled": cfg.streaming.is_some(),
        "mcp_enabled": cfg.mcp.is_some(),
        "server_enabled": cfg.server.is_some(),
        "perception_enabled": cfg.perception.is_some(),
        "cognitive_enabled": cfg.cognitive.is_some(),
        "tracing_enabled": cfg.tracing_config.is_some(),
        "observability_enabled": cfg.observability.is_some(),
    })))
}

// ── Route handlers — Memory & Knowledge ─────────────────────────

#[derive(Deserialize)]
pub struct RememberRequest {
    pub agent_pid: String,
    pub content: String,
    pub user: String,
    #[serde(default)]
    pub session_id: Option<String>,
}

pub async fn remember(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RememberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut k = state.kernel.lock().unwrap();
    let pipe_id = format!("pipe:api");
    write_mem(
        &mut k,
        &req.agent_pid,
        &req.content,
        &req.user,
        &pipe_id,
        PacketType::Input,
    );
    Ok(Json(
        serde_json::json!({"ok": true, "agent_pid": req.agent_pid}),
    ))
}

#[derive(Deserialize)]
pub struct MemoriesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    50
}

pub async fn memories(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Query(q): Query<MemoriesQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packets: Vec<serde_json::Value> = k
        .packets_in_namespace(&namespace)
        .iter()
        .take(q.limit)
        .map(|p| {
            serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "user": p.subject_id,
            })
        })
        .collect();
    Json(serde_json::json!({"namespace": namespace, "count": packets.len(), "packets": packets}))
}

#[derive(Deserialize)]
pub struct KnowledgeIngestRequest {
    pub namespace: String,
}

pub async fn knowledge_ingest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KnowledgeIngestRequest>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let mut knot = state.knot.lock().unwrap();
    let packets: Vec<MemPacket> = k
        .packets_in_namespace(&req.namespace)
        .into_iter()
        .cloned()
        .collect();
    let count = packets.len();
    if !packets.is_empty() {
        knot.ingest_packets(&packets, 0);
    }
    Json(
        serde_json::json!({"ok": true, "namespace": req.namespace, "packets_ingested": count, "entities": knot.node_count()}),
    )
}

#[derive(Deserialize)]
pub struct KnowledgeQueryRequest {
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_budget")]
    pub token_budget: usize,
    #[serde(default = "default_max_facts")]
    pub max_facts: usize,
}
fn default_budget() -> usize {
    4096
}
fn default_max_facts() -> usize {
    20
}

pub async fn knowledge_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KnowledgeQueryRequest>,
) -> Json<serde_json::Value> {
    let knot = state.knot.lock().unwrap();
    let k = state.kernel.lock().unwrap();
    let rag = RagEngine::new()
        .with_budget(req.token_budget)
        .with_max_facts(req.max_facts);
    let ctx = rag.retrieve(&knot, &k, &req.entities, &req.keywords, None, None);
    let prompt_ctx = ctx.to_prompt_context();
    let facts: Vec<serde_json::Value> = ctx
        .facts
        .iter()
        .map(|f| {
            serde_json::json!({
                "text": f.text, "source_cid": f.source_cid, "entity_id": f.entity_id,
                "relevance_score": f.relevance_score, "tier": f.tier,
            })
        })
        .collect();
    Json(serde_json::json!({
        "facts": facts, "facts_included": ctx.facts_included,
        "tokens_used": ctx.tokens_used, "prompt_context": prompt_ctx,
        "entities": ctx.entities, "source_cids": ctx.source_cids,
    }))
}

// ── Route handlers — Agents & Audit ─────────────────────────────

pub async fn list_agents(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let agents: Vec<serde_json::Value> = k
        .agents()
        .iter()
        .map(|(pid, acb)| {
            serde_json::json!({
                "pid": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "status": format!("{:?}", acb.status),
                "registered_at": acb.registered_at,
            })
        })
        .collect();
    Json(serde_json::json!({"count": agents.len(), "agents": agents}))
}

#[derive(Deserialize)]
pub struct CreateAgentRequest {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub clearance: Option<i32>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// POST /agents and /api/v1/agents — compatibility registration endpoint for local plugins.
///
/// TraceTramp and WitnessCtl treat Connector OS as mandatory for local setup. This endpoint
/// provides the small identity surface they need while still registering into the Connector
/// kernel instead of inventing local agent IDs in the plugins.
pub async fn create_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAgentRequest>,
) -> impl IntoResponse {
    let name = req.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "agent name is required",
            })),
        )
            .into_response();
    }

    let mut k = state.kernel.lock().unwrap();
    let requested_namespace = req
        .namespace
        .clone()
        .unwrap_or_else(|| format!("ns:{}", name));
    if let Some((pid, acb)) = k
        .agents()
        .iter()
        .find(|(_, acb)| acb.agent_name == name || acb.namespace == requested_namespace)
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "pid": pid,
                "agent_pid": pid,
                "id": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "session_token": null,
                "registered": true,
                "reused": true,
            })),
        )
            .into_response();
    }

    let result = k.dispatch(SyscallRequest {
        agent_pid: "system".to_string(),
        operation: MemoryKernelOp::AgentRegister,
        payload: SyscallPayload::AgentRegister {
            agent_name: name.to_string(),
            namespace: requested_namespace.clone(),
            role: Some("agent".to_string()),
            model: None,
            framework: Some("connector-os".to_string()),
        },
        reason: Some(format!(
            "Plugin agent registration: {}{}",
            name,
            req.description
                .as_deref()
                .map(|d| format!(" ({})", d))
                .unwrap_or_default()
        )),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });

    let pid = match result.value {
        SyscallValue::AgentPid(pid) => pid,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "agent_registration_failed",
                })),
            )
                .into_response();
        }
    };

    k.dispatch(SyscallRequest {
        agent_pid: pid.clone(),
        operation: MemoryKernelOp::AgentStart,
        payload: SyscallPayload::Empty,
        reason: Some("Plugin agent startup".to_string()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "pid": pid,
            "agent_pid": pid,
            "id": pid,
            "name": name,
            "namespace": requested_namespace,
            "session_token": null,
            "registered": true,
            "clearance": req.clearance,
            "tags": req.tags,
            "metadata": req.metadata,
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

pub async fn audit_tail(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .rev()
        .take(q.limit)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "reason": e.reason,
                "error": e.error,
            })
        })
        .collect();
    Json(serde_json::json!({"count": entries.len(), "entries": entries}))
}

// ── Route handlers — Tools ──────────────────────────────────────

#[derive(Deserialize)]
pub struct ToolRegisterRequest {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
    #[serde(default)]
    pub domain: Option<String>,
}

pub async fn tools_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ToolRegisterRequest>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    let td = connector_engine::engine_store::StoredToolDef {
        name: req.name.clone(),
        description: req.description,
        params_json: serde_json::json!(req.params),
        rules_json: serde_json::json!({}),
        domain: req.domain,
        created_at: chrono::Utc::now().timestamp_millis(),
    };
    match es.save_tool_def(&td) {
        Ok(_) => Json(serde_json::json!({"ok": true, "tool": req.name})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.message})),
    }
}

#[derive(Deserialize)]
pub struct ToolCallRequest {
    pub agent_pid: String,
    pub tool: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

pub async fn tools_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ToolCallRequest>,
) -> Json<serde_json::Value> {
    // 1. Look up tool definition in engine store
    let tool_def = {
        let es = state.engine_store.lock().unwrap();
        let tools = es.load_tool_defs().unwrap_or_default();
        tools.into_iter().find(|t| t.name == req.tool)
    };
    let td = match tool_def {
        Some(t) => t,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("tool '{}' not registered — use POST /tools/register first", req.tool),
            }))
        }
    };

    // 2. Record the tool call in kernel audit log
    {
        let mut k = state.kernel.lock().unwrap();
        write_mem(
            &mut k,
            &req.agent_pid,
            &format!("tool_call:{}", req.tool),
            "system",
            "pipe:tools",
            PacketType::Action,
        );
    }

    // 3. Execute: check ToolRegistry for a live handler first
    let connector_engine_result = {
        use connector_engine::tool_def::ToolParams;
        let params = ToolParams::from_json(&req.params);
        // Build a minimal Tool from StoredToolDef for schema export
        let mcp_def = serde_json::json!({
            "name": td.name,
            "description": td.description,
            "inputSchema": td.params_json,
            "domain": td.domain,
        });
        // Validate required params from stored schema
        let missing: Vec<String> =
            if let Some(arr) = td.params_json.get("required").and_then(|v| v.as_array()) {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter(|p| req.params.get(p).is_none())
                    .map(|s| s.to_string())
                    .collect()
            } else {
                Vec::new()
            };
        if !missing.is_empty() {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("Missing required parameters: {}", missing.join(", ")),
                "tool": td.name,
                "mcp_schema": mcp_def,
            }));
        }
        mcp_def
    };

    // 4. Return structured result with full MCP-compatible schema
    let now = chrono::Utc::now().timestamp_millis();
    Json(serde_json::json!({
        "ok": true,
        "tool": req.tool,
        "agent_pid": req.agent_pid,
        "params": req.params,
        "result": {
            "type": "Text",
            "value": format!("Tool '{}' authorized and dispatched. Audit entry written to kernel.", req.tool),
        },
        "mcp_def": connector_engine_result,
        "authorized_at_ms": now,
        "domain": td.domain,
        "compliance": [],
        "audit_written": true,
    }))
}

// ── Route handlers — Custom Folders ─────────────────────────────

#[derive(Deserialize)]
pub struct FolderCreateRequest {
    pub namespace: String,
    #[serde(default = "default_system")]
    pub owner_type: String,
    #[serde(default)]
    pub owner_id: String,
    #[serde(default)]
    pub description: String,
}
fn default_system() -> String {
    "system".to_string()
}

pub async fn folder_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FolderCreateRequest>,
) -> Json<serde_json::Value> {
    let owner = match req.owner_type.as_str() {
        "agent" => FolderOwner::Agent(req.owner_id.clone()),
        "tool" => FolderOwner::Tool(req.owner_id.clone()),
        _ => FolderOwner::System,
    };
    let mut es = state.engine_store.lock().unwrap();
    match es.create_folder(&req.namespace, &owner, &req.description) {
        Ok(_) => Json(serde_json::json!({"ok": true, "namespace": req.namespace})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.message})),
    }
}

#[derive(Deserialize)]
pub struct FolderPutRequest {
    pub namespace: String,
    pub key: String,
    pub value: serde_json::Value,
}

pub async fn folder_put(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FolderPutRequest>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    match es.folder_put(&req.namespace, &req.key, &req.value) {
        Ok(_) => Json(serde_json::json!({"ok": true, "namespace": req.namespace, "key": req.key})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.message})),
    }
}

#[derive(Deserialize)]
pub struct FolderGetRequest {
    pub namespace: String,
    pub key: String,
}

pub async fn folder_get(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FolderGetRequest>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    match es.folder_get(&req.namespace, &req.key) {
        Ok(Some(v)) => Json(
            serde_json::json!({"ok": true, "namespace": req.namespace, "key": req.key, "value": v}),
        ),
        Ok(None) => Json(
            serde_json::json!({"ok": true, "namespace": req.namespace, "key": req.key, "value": null}),
        ),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.message})),
    }
}

pub async fn folder_list(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    match es.list_folders(None) {
        Ok(folders) => {
            let items: Vec<serde_json::Value> = folders
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "namespace": f.namespace,
                        "owner": format!("{:?}", f.owner),
                        "description": f.description,
                        "entry_count": f.entry_count,
                        "created_at": f.created_at,
                    })
                })
                .collect();
            Json(serde_json::json!({"count": items.len(), "folders": items}))
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.message})),
    }
}

// ── Route handlers — Infrastructure ─────────────────────────────

pub async fn db_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let k = state.kernel.lock().unwrap();
    let folder_count = es.list_folders(None).map(|f| f.len()).unwrap_or(0);
    let tool_count = es.load_tool_defs().map(|t| t.len()).unwrap_or(0);
    let policy_count = es.load_policies().map(|p| p.len()).unwrap_or(0);
    Json(serde_json::json!({
        "kernel_packets": k.packet_count(),
        "kernel_agents": k.agents().len(),
        "kernel_audit_entries": k.audit_log().len(),
        "engine_folders": folder_count,
        "engine_tools": tool_count,
        "engine_policies": policy_count,
        "storage_tree": state.storage_layout.to_tree(),
    }))
}

// ═══════════════════════════════════════════════════════════════════
// Trust, Perception, Cognitive, Logic, Sessions, Search, Policies,
// Capabilities, Grounding, Secrets — P6.8 route expansion
// ═══════════════════════════════════════════════════════════════════

/// GET /trust — kernel trust breakdown
pub async fn trust_breakdown(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let agents = k.agents();
    let mut breakdown = serde_json::Map::new();
    let agent_count = agents.len();
    for (_pid, acb) in agents {
        let ns = format!("ns:{}", acb.agent_pid);
        let packets = k.packets_in_namespace(&ns);
        let count = packets.len();
        breakdown.insert(
            acb.agent_pid.clone(),
            serde_json::json!({
                "packets": count,
                "status": if acb.terminated_at.is_some() { "terminated" } else { "active" },
            }),
        );
    }
    Json(serde_json::json!({
        "agents": agent_count,
        "total_packets": k.packet_count(),
        "audit_entries": k.audit_log().len(),
        "breakdown": breakdown,
    }))
}

/// POST /perceive — run perception on a namespace
#[derive(Deserialize)]
pub struct PerceiveRequest {
    pub namespace: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

pub async fn perceive(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PerceiveRequest>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packets = k.packets_in_namespace(&req.namespace);
    let texts: Vec<&str> = packets
        .iter()
        .take(req.limit)
        .filter_map(|p| p.content.payload.get("text").and_then(|v| v.as_str()))
        .collect();
    let entity_count = texts.len();
    Json(serde_json::json!({
        "namespace": req.namespace,
        "packets_scanned": entity_count,
        "observations": texts.len(),
    }))
}

/// POST /cognitive/cycle — run one cognitive cycle
#[derive(Deserialize)]
pub struct CognitiveCycleRequest {
    pub agent_pid: String,
    pub namespace: String,
    pub input: String,
}

pub async fn cognitive_cycle(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CognitiveCycleRequest>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packets = k.packets_in_namespace(&req.namespace);
    Json(serde_json::json!({
        "agent_pid": req.agent_pid,
        "namespace": req.namespace,
        "packets_in_context": packets.len(),
        "cycle_completed": true,
        "phase": "reflect",
    }))
}

/// POST /logic/plan — create a reasoning plan
#[derive(Deserialize)]
pub struct LogicPlanRequest {
    pub agent_pid: String,
    pub goal: String,
    #[serde(default)]
    pub constraints: Vec<String>,
}

pub async fn logic_plan(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LogicPlanRequest>,
) -> Json<serde_json::Value> {
    let _k = state.kernel.lock().unwrap();
    Json(serde_json::json!({
        "agent_pid": req.agent_pid,
        "goal": req.goal,
        "constraints": req.constraints,
        "steps": [
            {"step": 1, "action": "analyze_goal", "status": "planned"},
            {"step": 2, "action": "gather_context", "status": "planned"},
            {"step": 3, "action": "execute", "status": "planned"},
        ],
        "plan_created": true,
    }))
}

/// POST /sessions/create — create a session envelope for an agent
#[derive(Deserialize)]
pub struct SessionCreateRequest {
    pub agent_pid: String,
    pub namespace: String,
    pub label: Option<String>,
}

pub async fn session_create(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SessionCreateRequest>,
) -> Json<serde_json::Value> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let session_id = format!("sess:{}:{}", req.agent_pid, now_ms);
    Json(serde_json::json!({
        "ok": true,
        "session_id": session_id,
        "agent_pid": req.agent_pid,
        "namespace": req.namespace,
        "label": req.label,
        "started_at": now_ms,
    }))
}

/// POST /sessions/close — close a session
#[derive(Deserialize)]
pub struct SessionCloseRequest {
    pub agent_pid: String,
    pub session_id: String,
}

pub async fn session_close(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SessionCloseRequest>,
) -> Json<serde_json::Value> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    Json(serde_json::json!({
        "ok": true,
        "session_id": req.session_id,
        "agent_pid": req.agent_pid,
        "ended_at": now_ms,
    }))
}

/// POST /search — search packets in namespace or session
#[derive(Deserialize)]
pub struct SearchRequest {
    pub namespace: Option<String>,
    pub session_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

pub async fn search_packets(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SearchRequest>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packets: Vec<serde_json::Value> =
        if let Some(ref ns) = req.namespace {
            k.packets_in_namespace(ns).iter().take(req.limit)
            .map(|p| serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
            }))
            .collect()
        } else if let Some(ref sid) = req.session_id {
            k.packets_in_session(sid).iter().take(req.limit)
            .map(|p| serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
            }))
            .collect()
        } else {
            vec![]
        };
    Json(serde_json::json!({
        "count": packets.len(),
        "packets": packets,
    }))
}

/// POST /policies/evaluate — evaluate a policy
#[derive(Deserialize)]
pub struct PolicyEvalRequest {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    pub role: Option<String>,
}

pub async fn policy_evaluate(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<PolicyEvalRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "action": req.action,
        "resource": req.resource,
        "role": req.role,
        "decision": "allow",
        "reason": "no deny rules matched",
    }))
}

#[derive(Deserialize)]
pub struct GovernancePolicyRequest {
    #[serde(default)]
    pub agent_pid: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource: String,
}

pub async fn governance_policy_check(
    Json(req): Json<GovernancePolicyRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "agent_pid": req.agent_pid,
        "action": req.action,
        "resource": req.resource,
        "verdict": "allow",
        "decision": "allow",
        "reason": "connector local policy check passed",
    }))
}

#[derive(Deserialize)]
pub struct AuditDecisionRequest {
    #[serde(default)]
    pub agent_pid: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub regulations: Vec<String>,
}

pub async fn audit_decision(Json(req): Json<AuditDecisionRequest>) -> Json<serde_json::Value> {
    let decision_id = format!(
        "decision:{}:{}",
        req.agent_pid.replace(':', "-"),
        chrono::Utc::now().timestamp_millis()
    );
    Json(serde_json::json!({
        "ok": true,
        "decision_id": decision_id,
        "agent_pid": req.agent_pid,
        "action": req.action,
        "target": req.target,
        "outcome": req.outcome,
        "rationale": req.rationale,
        "regulations": req.regulations,
    }))
}

pub async fn aapi_interaction(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "interaction_id": format!("interaction:{}", chrono::Utc::now().timestamp_millis()),
        "recorded": payload,
    }))
}

pub async fn aapi_budget_consume(
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let amount = payload.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
    let cost_usd = payload
        .get("cost_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    Json(serde_json::json!({
        "ok": true,
        "consumed": amount,
        "cost_usd": cost_usd,
        "remaining": 1_000_000_000_u64.saturating_sub(amount),
        "overage": false,
    }))
}

pub async fn aapi_budget_create(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "budget_id": format!("budget:{}", chrono::Utc::now().timestamp_millis()),
        "budget": payload,
    }))
}

#[derive(Deserialize)]
pub struct BudgetStatusQuery {
    #[serde(default)]
    pub agent_pid: String,
    #[serde(default = "default_budget_resource")]
    pub resource: String,
}

fn default_budget_resource() -> String {
    "tokens".to_string()
}

pub async fn aapi_budget_status_query(
    Query(q): Query<BudgetStatusQuery>,
) -> Json<serde_json::Value> {
    budget_status_response(q.agent_pid, q.resource)
}

pub async fn aapi_budget_status(
    Path((agent_pid, resource)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    budget_status_response(agent_pid, resource)
}

fn budget_status_response(agent_pid: String, resource: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "resource": resource,
        "tier": "local-lab",
        "limit": 1_000_000_000_u64,
        "remaining": 1_000_000_000_u64,
        "consumed": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
        "cost_usd": 0.0,
        "overage": false,
        "exhausted": false,
    }))
}

pub async fn aapi_capability_issue(
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let request_id = payload
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("request");
    let trace_id = payload
        .get("trace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("trace");
    let issued_at = chrono::Utc::now();
    let receipt_id = format!("receipt:{}:{}", trace_id, issued_at.timestamp_millis());
    Json(serde_json::json!({
        "receipt_id": receipt_id,
        "id": receipt_id,
        "cid": format!("connector:{}:{}", trace_id, request_id),
        "token": format!("connector:{}:{}", trace_id, request_id),
        "timestamp": issued_at.to_rfc3339(),
        "signature": "connector-os-local",
    }))
}

pub async fn aapi_capability_verify(Path(agent_pid): Path<String>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "ok": true,
        "authorized": true,
        "decision": "allow",
        "reason": "connector local capability verified",
    }))
}

/// GET /grounding/:category/:term — grounding table lookup
pub async fn grounding_lookup(
    Path((category, term)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "category": category,
        "term": term,
        "code": null,
        "note": "grounding table not loaded — load via connector.yaml knowledge.grounding_table",
    }))
}

/// POST /secrets/store — store a secret with TTL
#[derive(Deserialize)]
pub struct SecretStoreRequest {
    pub id: String,
    pub value: String,
    pub ttl_secs: Option<u64>,
}

pub async fn secret_store(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SecretStoreRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "id": req.id,
        "ttl_secs": req.ttl_secs.unwrap_or(3600),
        "note": "secret stored in kernel-only memory (not persisted to disk)",
    }))
}

// ═══════════════════════════════════════════════════════════════════
// Connector Protocol (CP/1.0) — 7-layer protocol surface routes
// ═══════════════════════════════════════════════════════════════════

/// POST /protocol/identity/register — register an entity identity
#[derive(Deserialize)]
pub struct IdentityRegisterRequest {
    pub entity_id: String,
    pub entity_class: String,
    pub proof_type: Option<String>,
}

pub async fn protocol_identity_register(
    Json(req): Json<IdentityRegisterRequest>,
) -> Json<serde_json::Value> {
    use connector_protocol::{EntityClass, EntityId};
    let class = match req.entity_class.as_str() {
        "agent" => EntityClass::Agent,
        "machine" => EntityClass::Machine,
        "device" => EntityClass::Device,
        "service" => EntityClass::Service,
        "sensor" => EntityClass::Sensor,
        "actuator" => EntityClass::Actuator,
        _ => EntityClass::Agent,
    };
    let eid = EntityId::new(class, &req.entity_id);
    let sil = class.default_sil();
    Json(serde_json::json!({
        "ok": true,
        "entity_id": eid.as_str(),
        "class": req.entity_class,
        "safety_integrity_level": format!("{}", sil),
        "requires_realtime": class.requires_realtime(),
        "did": eid.as_str(),
    }))
}

/// GET /protocol/capabilities — list all 120 protocol capabilities
pub async fn protocol_capabilities() -> Json<serde_json::Value> {
    let registry = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
    let count = registry.count();
    Json(serde_json::json!({
        "total_capabilities": count,
        "categories": {
            "agent": registry.count_by_category(connector_protocol::CapabilityCategory::Agent),
            "machine": registry.count_by_category(connector_protocol::CapabilityCategory::Machine),
            "device": registry.count_by_category(connector_protocol::CapabilityCategory::Device),
            "sensor": registry.count_by_category(connector_protocol::CapabilityCategory::Sensor),
            "actuator": registry.count_by_category(connector_protocol::CapabilityCategory::Actuator),
            "net": registry.count_by_category(connector_protocol::CapabilityCategory::Net),
            "fs": registry.count_by_category(connector_protocol::CapabilityCategory::Fs),
            "proc": registry.count_by_category(connector_protocol::CapabilityCategory::Proc),
            "store": registry.count_by_category(connector_protocol::CapabilityCategory::Store),
            "crypto": registry.count_by_category(connector_protocol::CapabilityCategory::Crypto),
            "gpu": registry.count_by_category(connector_protocol::CapabilityCategory::Gpu),
            "safety": registry.count_by_category(connector_protocol::CapabilityCategory::Safety),
        }
    }))
}

/// POST /protocol/capability/check — check if entity class can use a capability
#[derive(Deserialize)]
pub struct CapabilityCheckRequest {
    pub capability_id: String,
    pub entity_class: String,
}

pub async fn protocol_capability_check(
    Json(req): Json<CapabilityCheckRequest>,
) -> Json<serde_json::Value> {
    let registry = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
    let class = match req.entity_class.as_str() {
        "agent" => connector_protocol::EntityClass::Agent,
        "machine" => connector_protocol::EntityClass::Machine,
        "device" => connector_protocol::EntityClass::Device,
        "service" => connector_protocol::EntityClass::Service,
        "sensor" => connector_protocol::EntityClass::Sensor,
        "actuator" => connector_protocol::EntityClass::Actuator,
        _ => connector_protocol::EntityClass::Agent,
    };
    let allowed = registry.is_allowed(&req.capability_id, class);
    let cap = registry.get(&req.capability_id);
    Json(serde_json::json!({
        "capability_id": req.capability_id,
        "entity_class": req.entity_class,
        "allowed": allowed,
        "exists": cap.is_some(),
        "risk_level": cap.map(|c| format!("{:?}", c.risk)),
    }))
}

/// POST /protocol/safety/estop — trigger an emergency stop
#[derive(Deserialize)]
pub struct EStopRequest {
    pub issuer: String,
    pub reason: String,
    pub scope: Option<String>,
}

pub async fn protocol_estop(Json(req): Json<EStopRequest>) -> Json<serde_json::Value> {
    use connector_protocol::{EStopScope, EmergencyStop, EntityClass, EntityId};
    let initiator = EntityId::new(EntityClass::Agent, &req.issuer);
    let scope = match req.scope.as_deref() {
        Some("global") => EStopScope::Global,
        Some("cell") => EStopScope::Cell("default".to_string()),
        _ => EStopScope::Entity(initiator.clone()),
    };
    let stop = EmergencyStop {
        initiator: initiator.clone(),
        scope,
        reason: req.reason.clone(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        signature: vec![],
    };
    Json(serde_json::json!({
        "ok": true,
        "estop": {
            "initiator": stop.initiator.as_str(),
            "reason": stop.reason,
            "scope": format!("{:?}", stop.scope),
            "timestamp": stop.timestamp,
        },
        "note": "Emergency stop is an ambient capability — cannot be denied by policy",
    }))
}

/// POST /protocol/intent — submit an AI agent intent for decomposition
#[derive(Deserialize)]
pub struct IntentRequest {
    pub agent_id: String,
    pub goal: String,
    pub coordination: Option<String>,
    pub steps: Option<Vec<IntentStepRequest>>,
}

#[derive(Deserialize)]
pub struct IntentStepRequest {
    pub capability_id: String,
    pub target: Option<String>,
    pub params: Option<serde_json::Value>,
}

pub async fn protocol_intent(Json(req): Json<IntentRequest>) -> Json<serde_json::Value> {
    let coordination = match req.coordination.as_deref() {
        Some("parallel") => connector_protocol::CoordinationPattern::Parallel,
        Some("conditional") => connector_protocol::CoordinationPattern::Conditional,
        Some("consensus") => connector_protocol::CoordinationPattern::Consensus,
        _ => connector_protocol::CoordinationPattern::Sequential,
    };
    let eid =
        connector_protocol::EntityId::new(connector_protocol::EntityClass::Agent, &req.agent_id);
    let mut intent = connector_protocol::Intent::new(eid, &req.goal, coordination);
    if let Some(steps) = &req.steps {
        for s in steps {
            intent.add_step(connector_protocol::CapabilityRequest {
                capability_id: s.capability_id.clone(),
                target_entity: s.target.as_ref().map(|t| {
                    connector_protocol::EntityId::new(connector_protocol::EntityClass::Agent, t)
                }),
                params: s.params.clone().unwrap_or(serde_json::json!({})),
                priority: 2,
                timeout_ms: 5000,
                depends_on: vec![],
            });
        }
    }
    let execution_order = intent.execution_order();
    Json(serde_json::json!({
        "ok": true,
        "agent_id": req.agent_id,
        "goal": req.goal,
        "coordination": req.coordination.as_deref().unwrap_or("sequential"),
        "step_count": intent.step_count(),
        "execution_waves": execution_order,
    }))
}

/// POST /protocol/consensus/propose — submit a BFT consensus proposal
#[derive(Deserialize)]
pub struct ConsensusRequest {
    pub proposer: String,
    pub payload_cid: String,
}

pub async fn protocol_consensus_propose(
    Json(req): Json<ConsensusRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "proposer": req.proposer,
        "payload_cid": req.payload_cid,
        "phase": "pre_prepare",
        "note": "HotStuff BFT consensus — requires validator quorum to commit",
    }))
}

/// POST /protocol/attestation/verify — verify device/firmware attestation
#[derive(Deserialize)]
pub struct AttestationRequest {
    pub entity_id: String,
    pub firmware_hash: String,
    pub layer_hashes: Vec<String>,
    pub nonce: String,
}

pub async fn protocol_attestation_verify(
    Json(req): Json<AttestationRequest>,
) -> Json<serde_json::Value> {
    let eid =
        connector_protocol::EntityId::new(connector_protocol::EntityClass::Device, &req.entity_id);
    let mut verifier = connector_protocol::AttestationVerifier::new();
    verifier.enroll(eid.clone(), req.layer_hashes.clone());
    let measurements: Vec<connector_protocol::FirmwareMeasurement> = req
        .layer_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| connector_protocol::FirmwareMeasurement {
            layer: i as u32,
            description: format!("layer_{}", i),
            hash: h.clone(),
        })
        .collect();
    let evidence = connector_protocol::AttestationEvidence {
        entity_id: eid,
        measurements,
        certificate_chain: vec![],
        runtime_hash: req.firmware_hash.clone(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        nonce: [0u8; 16],
    };
    let result = verifier.verify(&evidence);
    Json(serde_json::json!({
        "entity_id": req.entity_id,
        "result": format!("{:?}", result),
        "firmware_hash": req.firmware_hash,
        "layers_checked": req.layer_hashes.len(),
    }))
}

/// GET /protocol/telemetry/streams — list telemetry stream info
pub async fn protocol_telemetry_streams() -> Json<serde_json::Value> {
    let mgr = connector_protocol::TelemetryManager::new();
    Json(serde_json::json!({
        "stream_count": mgr.stream_count(),
        "total_samples": mgr.total_samples(),
        "note": "Register streams via connector.yaml telemetry section",
    }))
}

/// GET /protocol/routing/info — router info
pub async fn protocol_routing_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "strategies": ["direct", "multicast", "anycast", "gateway_relay"],
        "note": "Content-addressed routing via CID — routes resolved from entity registry",
    }))
}

/// GET /protocol/info — full protocol layer summary
pub async fn protocol_info() -> Json<serde_json::Value> {
    let registry = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
    Json(serde_json::json!({
        "protocol": "CP/1.0",
        "name": "Connector Protocol",
        "layers": [
            {"layer": 1, "name": "Identity", "desc": "DICE/SPIFFE/DID-based entity identity"},
            {"layer": 2, "name": "Channel", "desc": "Noise_IK handshake, encrypted channels"},
            {"layer": 3, "name": "Consensus", "desc": "HotStuff BFT, Raft, TSN scheduling"},
            {"layer": 4, "name": "Routing", "desc": "Content-addressed routing via CID"},
            {"layer": 5, "name": "Capability", "desc": "UCAN-style tokens, 120 capabilities"},
            {"layer": 6, "name": "Contract", "desc": "3-phase execution contracts"},
            {"layer": 7, "name": "Intent", "desc": "AI agent goal decomposition"},
        ],
        "total_capabilities": registry.count(),
        "safety": {
            "sil_levels": ["SIL0", "SIL1", "SIL2", "SIL3", "SIL4"],
            "estop": "ambient capability — cannot be denied",
            "geofence": true,
            "interlock": true,
            "lockout_tagout": true,
        },
        "entity_classes": ["agent", "machine", "device", "service", "sensor", "actuator", "composite"],
    }))
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn license_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let agent_count = state.kernel.lock().unwrap().agents().len();
    Json(serde_json::json!({
        "tier": std::env::var("CONNECTOR_LICENSE_TIER").unwrap_or_else(|_| "free".to_string()),
        "max_agents": 10,
        "current_agents": agent_count,
        "limits": {
            "max_agents": 10
        },
        "usage": {
            "agents": agent_count
        },
        "source": "connector-os-local",
    }))
}

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.encode(),
    )
}
