//! HTTP route handlers for the Connector REST API.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::{MemoryKernelOp, PacketType, Source, SourceKind, MemPacket};

use connector_engine::llm::LlmClient;

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
pub struct RunResponse {
    pub text: String,
    pub trust: u32,
    pub trust_grade: String,
    pub ok: bool,
    pub duration_ms: u64,
    pub actors: usize,
    pub steps: usize,
    pub event_count: usize,
    pub span_count: usize,
    pub trace_id: String,
    pub verified: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub provenance: serde_json::Value,
    pub json: serde_json::Value,
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
        Source { kind: SourceKind::User, principal_id: user.to_string() },
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
    });
    Ok(pid)
}

fn write_mem(kernel: &mut MemoryKernel, pid: &str, content: &str, user: &str, pipe: &str, ptype: PacketType) {
    kernel.dispatch(SyscallRequest {
        agent_pid: pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: make_packet(content, user, pipe, ptype),
        },
        reason: None,
        vakya_id: None,
    });
}

fn output_to_response(output: &connector_engine::PipelineOutput) -> RunResponse {
    RunResponse {
        text: output.text.clone(),
        trust: output.status.trust,
        trust_grade: output.status.trust_grade.clone(),
        ok: output.status.ok,
        duration_ms: output.status.duration_ms,
        actors: output.status.actors,
        steps: output.status.steps,
        event_count: output.events.len(),
        span_count: output.trace.spans.len(),
        trace_id: output.trace.trace_id.clone(),
        verified: output.all_observations_verified(),
        warnings: output.warnings.clone(),
        errors: output.errors.clone(),
        provenance: output.provenance_summary(),
        json: output.to_json(),
    }
}

// ── Route handlers ───────────────────────────────────────────────

pub async fn run_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, String)> {
    let mut kernel = MemoryKernel::new();
    let pipe_id = format!("pipe:{}", req.agent);
    let model = state.connector.llm_config().map(|c| c.model.clone());

    let pid = register_and_start(&mut kernel, &req.agent, model)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    write_mem(&mut kernel, &pid, &req.input, &req.user, &pipe_id, PacketType::Input);

    let start = std::time::Instant::now();

    // Call real LLM (async)
    let response_text = match state.connector.engine_llm_config() {
        Some(mut llm_cfg) => {
            if let Some(ref instr) = req.instructions {
                llm_cfg = llm_cfg.with_system(instr);
            }
            let client = LlmClient::new();
            client.complete(&llm_cfg, &req.input, None).await
                .map(|r| r.text)
                .unwrap_or_else(|e| format!("[LLM error: {}]", e))
        }
        None => format!("[no LLM configured — agent '{}' echo: {}]", req.agent, req.input),
    };

    write_mem(&mut kernel, &pid, &response_text, &req.user, &pipe_id, PacketType::LlmRaw);

    let duration_ms = start.elapsed().as_millis() as u64;

    let output = connector_engine::OutputBuilder::build(
        &kernel, response_text, &pipe_id, 1,
        &req.compliance, duration_ms, Vec::new(),
    );

    state.metrics.record_output(&output);

    Ok(Json(output_to_response(&output)))
}

pub async fn run_pipeline(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PipelineRequest>,
) -> Result<Json<RunResponse>, (StatusCode, String)> {
    let mut kernel = MemoryKernel::new();
    let pipe_id = format!("pipe:{}", req.name);
    let model = state.connector.llm_config().map(|c| c.model.clone());
    let start = std::time::Instant::now();

    let mut last_output = req.input.clone();

    for agent in &req.agents {
        let pid = register_and_start(&mut kernel, &agent.name, model.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        write_mem(&mut kernel, &pid, &last_output, &req.user, &pipe_id, PacketType::Input);

        // Call real LLM for each agent (async)
        last_output = match state.connector.engine_llm_config() {
            Some(cfg) => {
                let agent_cfg = if let Some(ref instr) = agent.instructions {
                    cfg.clone().with_system(instr)
                } else { cfg.clone() };
                let client = LlmClient::new();
                client.complete(&agent_cfg, &last_output, None).await
                    .map(|r| r.text)
                    .unwrap_or_else(|e| format!("[LLM error: {}]", e))
            }
            None => format!("[no LLM — {}: {}]", agent.name, last_output),
        };

        write_mem(&mut kernel, &pid, &last_output, &req.user, &pipe_id, PacketType::LlmRaw);
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    let output = connector_engine::OutputBuilder::build(
        &kernel, last_output, &pipe_id,
        req.agents.len(), &req.compliance, duration_ms, Vec::new(),
    );

    state.metrics.record_output(&output);

    Ok(Json(output_to_response(&output)))
}

/// POST /config/parse
/// Body: raw YAML string (Content-Type: application/yaml)
/// Returns: JSON with the parsed connector section (provider, model, endpoint)
/// Used by the TypeScript SDK's Connector.fromConfigStr() to validate and
/// extract LLM settings from a connector.yaml without exposing the api_key.
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

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn metrics_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.encode(),
    )
}
