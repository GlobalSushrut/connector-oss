//! Shared admission helpers for mutating substrate paths (Ring-1 aware).

use axum::http::HeaderMap;

use crate::services::admission::{AdmissionOp, AdmissionOp as Op};
use crate::state::SharedState;

fn check_with_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    operation: AdmissionOp,
    content: Option<&str>,
) -> Result<(), serde_json::Value> {
    crate::substrate::governed_effect::evaluate_effect(
        state,
        headers,
        agent_pid,
        namespace,
        operation,
        content,
    )
    .map(|_| ())
    .map_err(|e| crate::substrate::governed_effect::denial_json(&e))
}

pub fn require_memory_write(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
) -> Result<(), serde_json::Value> {
    require_memory_write_headers(state, None, agent_pid, namespace)
}

pub fn require_memory_write_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
) -> Result<(), serde_json::Value> {
    check_with_headers(
        state,
        headers,
        agent_pid,
        namespace,
        Op::MemoryWrite,
        None,
    )
}

pub fn require_tool_dispatch(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    tool_id: &str,
) -> Result<(), serde_json::Value> {
    require_tool_dispatch_headers(state, None, agent_pid, namespace, tool_id)
}

pub fn require_tool_dispatch_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    tool_id: &str,
) -> Result<(), serde_json::Value> {
    check_with_headers(
        state,
        headers,
        agent_pid,
        namespace,
        Op::ToolDispatch {
            tool_id: tool_id.to_string(),
        },
        None,
    )
}

pub fn require_llm_chat(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    content: Option<&str>,
) -> Result<(), serde_json::Value> {
    require_llm_chat_headers(state, None, agent_pid, namespace, content)
}

pub fn require_llm_chat_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    content: Option<&str>,
) -> Result<(), serde_json::Value> {
    check_with_headers(
        state,
        headers,
        agent_pid,
        namespace,
        Op::LlmChat,
        content,
    )
}

pub fn require_mcp_call(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    tool_name: &str,
    content: Option<&str>,
) -> Result<(), serde_json::Value> {
    require_mcp_call_headers(state, None, agent_pid, namespace, tool_name, content)
}

pub fn require_mcp_call_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    namespace: &str,
    tool_name: &str,
    content: Option<&str>,
) -> Result<(), serde_json::Value> {
    check_with_headers(
        state,
        headers,
        agent_pid,
        namespace,
        Op::McpCall {
            tool_name: tool_name.to_string(),
        },
        content,
    )
}

pub fn require_pipeline_step(
    state: &SharedState,
    agent_pid: &str,
    pipeline_id: &str,
    step: usize,
) -> Result<(), serde_json::Value> {
    require_pipeline_step_headers(state, None, agent_pid, pipeline_id, step)
}

pub fn require_pipeline_step_headers(
    state: &SharedState,
    headers: Option<&HeaderMap>,
    agent_pid: &str,
    pipeline_id: &str,
    step: usize,
) -> Result<(), serde_json::Value> {
    check_with_headers(
        state,
        headers,
        agent_pid,
        &format!("pipeline/{pipeline_id}"),
        Op::PipelineStep {
            pipeline_id: pipeline_id.to_string(),
            step,
        },
        None,
    )
}
