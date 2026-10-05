//! MCP Server Bridge — exposes VAC namespaces + ToolBindings as an MCP server.
//!
//! Implements JSON-RPC 2.0 protocol (MCP spec) to serve:
//! - `tools/list` → enumerate agent's ToolBindings
//! - `tools/call` → translate to SyscallPayload::ToolDispatch
//! - `resources/list` → enumerate agent's readable namespaces
//! - `resources/read` → translate to SyscallPayload::MemRead
//!
//! All calls go through AgentFirewall before reaching the kernel.


use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{ProtocolError, ProtocolResult};

// ── JSON-RPC 2.0 Types ─────────────────────────────────────────────

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// ── MCP-Specific Types ──────────────────────────────────────────────

/// An MCP tool definition served by this bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// An MCP resource definition served by this bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResourceDef {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// Result of a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// MCP content block (text or other types).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

// ── MCP Server ──────────────────────────────────────────────────────

/// Trait for the kernel backend that the MCP server delegates to.
///
/// This abstracts the actual kernel operations so the MCP server
/// can be tested without a full kernel.
pub trait McpKernelBackend: Send + Sync {
    /// List available tools for the given agent.
    fn list_tools(&self, agent_pid: &str) -> ProtocolResult<Vec<McpToolDef>>;

    /// Call a tool.
    fn call_tool(
        &self,
        agent_pid: &str,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> ProtocolResult<McpToolResult>;

    /// List readable resources (namespaces) for the given agent.
    fn list_resources(&self, agent_pid: &str) -> ProtocolResult<Vec<McpResourceDef>>;

    /// Read a resource by URI.
    fn read_resource(&self, agent_pid: &str, uri: &str) -> ProtocolResult<String>;
}

/// MCP Server that handles JSON-RPC 2.0 requests.
pub struct McpServer<B: McpKernelBackend> {
    backend: B,
    /// Server info returned in `initialize` response.
    server_name: String,
    server_version: String,
}

impl<B: McpKernelBackend> McpServer<B> {
    pub fn new(backend: B, server_name: impl Into<String>, server_version: impl Into<String>) -> Self {
        Self {
            backend,
            server_name: server_name.into(),
            server_version: server_version.into(),
        }
    }

    /// Handle a JSON-RPC 2.0 request and return a response.
    pub fn handle_request(
        &self,
        agent_pid: &str,
        request: &JsonRpcRequest,
    ) -> JsonRpcResponse {
        debug!(method = %request.method, agent = %agent_pid, "MCP request");

        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(agent_pid, request),
            "tools/call" => self.handle_tools_call(agent_pid, request),
            "resources/list" => self.handle_resources_list(agent_pid, request),
            "resources/read" => self.handle_resources_read(agent_pid, request),
            "ping" => JsonRpcResponse::success(request.id.clone(), serde_json::json!({})),
            _ => JsonRpcResponse::error(
                request.id.clone(),
                -32601,
                format!("Method not found: {}", request.method),
            ),
        }
    }

    fn handle_initialize(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": { "subscribe": false, "listChanged": false }
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version
                }
            }),
        )
    }

    fn handle_tools_list(&self, agent_pid: &str, request: &JsonRpcRequest) -> JsonRpcResponse {
        match self.backend.list_tools(agent_pid) {
            Ok(tools) => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({ "tools": tools }),
            ),
            Err(e) => JsonRpcResponse::error(request.id.clone(), -32000, e.to_string()),
        }
    }

    fn handle_tools_call(&self, agent_pid: &str, request: &JsonRpcRequest) -> JsonRpcResponse {
        let name = request.params.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let arguments = request.params.get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        if name.is_empty() {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32602,
                "Missing required parameter: name",
            );
        }

        match self.backend.call_tool(agent_pid, name, arguments) {
            Ok(result) => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::to_value(&result).unwrap_or_default(),
            ),
            Err(ProtocolError::FirewallBlocked(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                -32003,
                format!("Firewall blocked: {}", msg),
            ),
            Err(ProtocolError::AuthzDenied(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                -32002,
                format!("Authorization denied: {}", msg),
            ),
            Err(ProtocolError::NotFound(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                -32001,
                format!("Tool not found: {}", msg),
            ),
            Err(e) => JsonRpcResponse::error(request.id.clone(), -32000, e.to_string()),
        }
    }

    fn handle_resources_list(&self, agent_pid: &str, request: &JsonRpcRequest) -> JsonRpcResponse {
        match self.backend.list_resources(agent_pid) {
            Ok(resources) => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({ "resources": resources }),
            ),
            Err(e) => JsonRpcResponse::error(request.id.clone(), -32000, e.to_string()),
        }
    }

    fn handle_resources_read(&self, agent_pid: &str, request: &JsonRpcRequest) -> JsonRpcResponse {
        let uri = request.params.get("uri")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if uri.is_empty() {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32602,
                "Missing required parameter: uri",
            );
        }

        match self.backend.read_resource(agent_pid, uri) {
            Ok(content) => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": content
                    }]
                }),
            ),
            Err(ProtocolError::NotFound(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                -32001,
                format!("Resource not found: {}", msg),
            ),
            Err(ProtocolError::AuthzDenied(msg)) => JsonRpcResponse::error(
                request.id.clone(),
                -32002,
                format!("Access denied: {}", msg),
            ),
            Err(e) => JsonRpcResponse::error(request.id.clone(), -32000, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock backend for testing.
    struct MockBackend {
        tools: Vec<McpToolDef>,
        resources: Vec<McpResourceDef>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                tools: vec![
                    McpToolDef {
                        name: "search".to_string(),
                        description: "Search the knowledge base".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "query": { "type": "string" }
                            },
                            "required": ["query"]
                        }),
                    },
                    McpToolDef {
                        name: "calculate".to_string(),
                        description: "Perform calculations".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "expression": { "type": "string" }
                            }
                        }),
                    },
                ],
                resources: vec![
                    McpResourceDef {
                        uri: "mem://agents/doctor/notes".to_string(),
                        name: "Doctor Notes".to_string(),
                        description: "Clinical notes namespace".to_string(),
                        mime_type: "text/plain".to_string(),
                    },
                ],
            }
        }
    }

    impl McpKernelBackend for MockBackend {
        fn list_tools(&self, _agent_pid: &str) -> ProtocolResult<Vec<McpToolDef>> {
            Ok(self.tools.clone())
        }

        fn call_tool(
            &self,
            _agent_pid: &str,
            tool_name: &str,
            arguments: serde_json::Value,
        ) -> ProtocolResult<McpToolResult> {
            match tool_name {
                "search" => {
                    let query = arguments.get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    Ok(McpToolResult {
                        content: vec![McpContent {
                            content_type: "text".to_string(),
                            text: format!("Results for: {}", query),
                        }],
                        is_error: None,
                    })
                }
                "blocked_tool" => Err(ProtocolError::FirewallBlocked("risk too high".to_string())),
                _ => Err(ProtocolError::NotFound(tool_name.to_string())),
            }
        }

        fn list_resources(&self, _agent_pid: &str) -> ProtocolResult<Vec<McpResourceDef>> {
            Ok(self.resources.clone())
        }

        fn read_resource(&self, _agent_pid: &str, uri: &str) -> ProtocolResult<String> {
            if uri == "mem://agents/doctor/notes" {
                Ok("Patient presented with fever.".to_string())
            } else if uri == "mem://agents/admin/secret" {
                Err(ProtocolError::AuthzDenied("no access to admin namespace".to_string()))
            } else {
                Err(ProtocolError::NotFound(uri.to_string()))
            }
        }
    }

    fn make_request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: method.to_string(),
            params,
        }
    }

    #[test]
    fn test_mcp_initialize() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("initialize", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "connector");
    }

    #[test]
    fn test_mcp_tools_list() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("tools/list", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "search");
        assert_eq!(tools[1]["name"], "calculate");
    }

    #[test]
    fn test_mcp_tools_call_success() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("tools/call", serde_json::json!({
            "name": "search",
            "arguments": { "query": "fever treatment" }
        }));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fever treatment"));
    }

    #[test]
    fn test_mcp_tools_call_not_found() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("tools/call", serde_json::json!({
            "name": "nonexistent",
            "arguments": {}
        }));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32001);
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn test_mcp_tools_call_firewall_blocked() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("tools/call", serde_json::json!({
            "name": "blocked_tool",
            "arguments": {}
        }));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32003);
        assert!(err.message.contains("Firewall"));
    }

    #[test]
    fn test_mcp_tools_call_missing_name() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("tools/call", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn test_mcp_resources_list() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("resources/list", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
        let resources = resp.result.unwrap()["resources"].as_array().unwrap().clone();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "mem://agents/doctor/notes");
    }

    #[test]
    fn test_mcp_resources_read_success() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("resources/read", serde_json::json!({
            "uri": "mem://agents/doctor/notes"
        }));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
        let contents = resp.result.unwrap();
        let text = contents["contents"][0]["text"].as_str().unwrap();
        assert!(text.contains("fever"));
    }

    #[test]
    fn test_mcp_resources_read_access_denied() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("resources/read", serde_json::json!({
            "uri": "mem://agents/admin/secret"
        }));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32002);
        assert!(err.message.contains("denied"));
    }

    #[test]
    fn test_mcp_unknown_method() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("nonexistent/method", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_mcp_ping() {
        let server = McpServer::new(MockBackend::new(), "connector", "0.1.0");
        let req = make_request("ping", serde_json::json!({}));
        let resp = server.handle_request("agent-1", &req);

        assert!(resp.error.is_none());
    }
}
