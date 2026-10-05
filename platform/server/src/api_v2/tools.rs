//! V2 Tools API — Tool registry and invocation
//!
//! Routes:
//!   GET    /api/v2/tools              — List available tools
//!   GET    /api/v2/tools/:id          — Get tool details
//!   POST   /api/v2/tools/:id/invoke   — Invoke a tool

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::V2Response;
use crate::state::SharedState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub parameters: serde_json::Value,
    pub requires_approval: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListToolsQuery {
    pub category: Option<String>,
    pub agent_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct InvokeToolRequest {
    pub agent_id: String,
    #[serde(default, alias = "input")]
    pub parameters: serde_json::Value,
}

/// GET /api/v2/tools — List available tools
pub async fn list_tools(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ListToolsQuery>,
) -> V2Response<Vec<Tool>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    
    let tools: Vec<Tool> = {
        let kernel = state.kernel.lock().unwrap();
        
        // Get all agents and their tool bindings
        let mut all_tools = Vec::new();
        
        for (agent_pid, acb) in kernel.agents().iter() {
            if let Some(ref filter_agent) = query.agent_id {
                if agent_pid != filter_agent {
                    continue;
                }
            }
            
            for binding in &acb.tool_bindings {
                let tool = Tool {
                    id: binding.tool_id.clone(),
                    name: binding.tool_id.clone(),
                    description: format!("Tool: {}", binding.tool_id),
                    category: "general".to_string(),
                    parameters: serde_json::json!({}),
                    requires_approval: binding.requires_approval,
                };
                all_tools.push(tool);
            }
        }
        
        all_tools.into_iter().take(limit).collect()
    };
    
    V2Response::success(tools)
}

/// GET /api/v2/tools/:id — Get tool details
pub async fn get_tool(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<Tool> {
    let kernel = state.kernel.lock().unwrap();
    
    // Find tool in any agent's bindings
    for (_agent_pid, acb) in kernel.agents().iter() {
        for binding in &acb.tool_bindings {
            if binding.tool_id == id {
                let tool = Tool {
                    id: binding.tool_id.clone(),
                    name: binding.tool_id.clone(),
                    description: format!("Tool: {}", binding.tool_id),
                    category: "general".to_string(),
                    parameters: serde_json::json!({}),
                    requires_approval: binding.requires_approval,
                };
                return V2Response::success(tool);
            }
        }
    }
    
    V2Response {
        ok: false,
        data: None,
        error: Some(super::V2Error {
            code: "tool_not_found".to_string(),
            message: format!("Tool '{}' not found", id),
            hint: Some("List available tools to find valid tool IDs".to_string()),
            reason: None,
            example: None,
            field: None,
            expected: None,
            received: None,
            docs: "https://connector.ai/docs/errors/tool_not_found".to_string(),
            see_also: Vec::new(),
        }),
        meta: super::V2Meta::now(),
    }
}

/// POST /api/v2/tools/:id/invoke — same MCP dispatch as POST /api/v1/tools/mcp/invoke.
///
/// `id` is `bridge:tool` (or a bare tool name on the `default` bridge). This does
/// not invent a pending queue — the kernel either ran or the error is returned.
pub async fn invoke_tool(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<InvokeToolRequest>,
) -> V2Response<ToolInvocationResult> {
    if req.agent_id.trim().is_empty() {
        return V2Response {
            ok: false,
            data: None,
            error: Some(super::V2Error {
                code: "agent_id_required".to_string(),
                message: "agent_id is required to dispatch a tool.".to_string(),
                hint: Some("Pass the agent pid that holds the tool capability.".to_string()),
                reason: None,
                example: None,
                field: Some("agent_id".to_string()),
                expected: None,
                received: None,
                docs: "https://connector.ai/docs/errors/agent_id_required".to_string(),
                see_also: vec!["POST /api/v1/tools/mcp/invoke".to_string()],
            }),
            meta: super::V2Meta::now(),
        };
    }

    let (bridge, tool) = crate::services::tools::parse_bridge_and_tool(&id);
    match crate::services::tools::dispatch_mcp_tool(
        &state,
        &bridge,
        &tool,
        &req.agent_id,
        &req.parameters,
        format!("v2 invoke {id}"),
        crate::services::tools::ToolMissionOpts {
            mission_id: None,
            idempotency_key: None,
        },
    )
    .await
    {
        Ok(result) => {
            let status = result
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("dispatched")
                .to_string();
            V2Response::success(ToolInvocationResult {
                tool_id: id,
                agent_id: req.agent_id,
                status,
                result: Some(result),
                error: None,
                executed_at: Utc::now().to_rfc3339(),
            })
        }
        Err(e) => {
            let message = e
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("tool dispatch failed")
                .to_string();
            V2Response {
                ok: false,
                data: Some(ToolInvocationResult {
                    tool_id: id,
                    agent_id: req.agent_id,
                    status: "failed".to_string(),
                    result: Some(e.clone()),
                    error: Some(message.clone()),
                    executed_at: Utc::now().to_rfc3339(),
                }),
                error: Some(super::V2Error {
                    code: e
                        .get("denial_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tool_dispatch_failed")
                        .to_string(),
                    message,
                    hint: Some(
                        "This is the same executor as POST /api/v1/tools/mcp/invoke.".to_string(),
                    ),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/tool_dispatch_failed".to_string(),
                    see_also: vec!["POST /api/v1/tools/mcp/invoke".to_string()],
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationResult {
    pub tool_id: String,
    pub agent_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub executed_at: String,
}
