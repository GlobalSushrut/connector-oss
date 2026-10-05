//! MCP Client Bridge — connect to external MCP servers and proxy tool calls.
//!
//! - Discover external MCP server capabilities
//! - Register discovered tools as McpBridgeEntry in kernel registry
//! - Proxy tool calls: kernel ToolDispatch → MCP client → external server → result
//! - Cache tool schemas for validation

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{ProtocolError, ProtocolResult};
use crate::mcp_server::{JsonRpcRequest, JsonRpcResponse, McpToolDef};

// ── MCP Client Types ────────────────────────────────────────────────

/// A discovered remote MCP server with its tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRemoteServer {
    /// URL or transport identifier for the server
    pub url: String,
    /// Server name (from initialize response)
    pub name: String,
    /// Server version
    pub version: String,
    /// Discovered tools
    pub tools: Vec<McpToolDef>,
    /// When the tools were last refreshed
    pub discovered_at: i64,
}

/// Entry in the kernel tool registry for a bridged MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeEntry {
    /// The remote server this tool belongs to
    pub server_url: String,
    /// The tool definition
    pub tool: McpToolDef,
    /// Cached input schema for validation
    pub schema: serde_json::Value,
}

/// Trait for the transport layer used to communicate with remote MCP servers.
///
/// This abstracts the actual HTTP/stdio/SSE transport so the client
/// can be tested without real network calls.
pub trait McpTransport: Send + Sync {
    /// Send a JSON-RPC request and receive a response.
    fn send(&self, url: &str, request: &JsonRpcRequest) -> ProtocolResult<JsonRpcResponse>;
}

/// MCP Client that discovers and calls tools on remote MCP servers.
pub struct McpClient<T: McpTransport> {
    transport: T,
    /// Cache of discovered servers and their tools.
    servers: HashMap<String, McpRemoteServer>,
    /// Flattened tool registry: tool_name → bridge entry
    tool_registry: HashMap<String, McpBridgeEntry>,
    /// Timeout for remote calls
    timeout: Duration,
}

impl<T: McpTransport> McpClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            servers: HashMap::new(),
            tool_registry: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Discover tools from a remote MCP server.
    pub fn discover(&mut self, url: &str) -> ProtocolResult<Vec<McpToolDef>> {
        debug!(url = %url, "Discovering MCP server");

        // 1. Initialize
        let init_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "initialize".to_string(),
            params: serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "connector-mcp-client",
                    "version": "0.1.0"
                }
            }),
        };

        let init_resp = self.transport.send(url, &init_req)?;
        let server_info = init_resp.result.ok_or_else(|| {
            ProtocolError::Protocol("Initialize returned no result".to_string())
        })?;

        let server_name = server_info["serverInfo"]["name"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let server_version = server_info["serverInfo"]["version"]
            .as_str()
            .unwrap_or("0.0.0")
            .to_string();

        // 2. List tools
        let tools_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(2)),
            method: "tools/list".to_string(),
            params: serde_json::json!({}),
        };

        let tools_resp = self.transport.send(url, &tools_req)?;
        let tools_result = tools_resp.result.ok_or_else(|| {
            ProtocolError::Protocol("tools/list returned no result".to_string())
        })?;

        let tools: Vec<McpToolDef> = serde_json::from_value(
            tools_result["tools"].clone(),
        )
        .map_err(|e| ProtocolError::Serialization(format!("Failed to parse tools: {}", e)))?;

        // 3. Cache
        let server = McpRemoteServer {
            url: url.to_string(),
            name: server_name,
            version: server_version,
            tools: tools.clone(),
            discovered_at: chrono::Utc::now().timestamp_millis(),
        };

        // Register each tool
        for tool in &tools {
            let entry = McpBridgeEntry {
                server_url: url.to_string(),
                tool: tool.clone(),
                schema: tool.input_schema.clone(),
            };
            self.tool_registry.insert(tool.name.clone(), entry);
        }

        self.servers.insert(url.to_string(), server);

        debug!(url = %url, tool_count = tools.len(), "Discovered MCP server tools");
        Ok(tools)
    }

    /// Call a tool by name (looks up which server hosts it).
    pub fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> ProtocolResult<serde_json::Value> {
        let entry = self.tool_registry.get(tool_name).ok_or_else(|| {
            ProtocolError::NotFound(format!("Tool '{}' not found in registry", tool_name))
        })?;

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(3)),
            method: "tools/call".to_string(),
            params: serde_json::json!({
                "name": tool_name,
                "arguments": arguments,
            }),
        };

        let resp = self.transport.send(&entry.server_url, &req)?;

        if let Some(err) = resp.error {
            return Err(ProtocolError::Protocol(format!(
                "Tool call failed: {} (code {})",
                err.message, err.code
            )));
        }

        resp.result.ok_or_else(|| {
            ProtocolError::Protocol("Tool call returned no result".to_string())
        })
    }

    /// Get all registered tools.
    pub fn registered_tools(&self) -> Vec<&McpBridgeEntry> {
        self.tool_registry.values().collect()
    }

    /// Get a specific server's info.
    pub fn server_info(&self, url: &str) -> Option<&McpRemoteServer> {
        self.servers.get(url)
    }

    /// Number of discovered servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Number of registered tools across all servers.
    pub fn tool_count(&self) -> usize {
        self.tool_registry.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock transport that simulates a remote MCP server.
    struct MockTransport {
        tools: Vec<McpToolDef>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                tools: vec![
                    McpToolDef {
                        name: "github_search".to_string(),
                        description: "Search GitHub repos".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": { "query": { "type": "string" } }
                        }),
                    },
                    McpToolDef {
                        name: "github_pr".to_string(),
                        description: "Create a pull request".to_string(),
                        input_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "repo": { "type": "string" },
                                "title": { "type": "string" }
                            }
                        }),
                    },
                ],
            }
        }
    }

    impl McpTransport for MockTransport {
        fn send(&self, _url: &str, request: &JsonRpcRequest) -> ProtocolResult<JsonRpcResponse> {
            match request.method.as_str() {
                "initialize" => Ok(JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({
                        "protocolVersion": "2024-11-05",
                        "serverInfo": { "name": "mock-github", "version": "1.0.0" }
                    }),
                )),
                "tools/list" => Ok(JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({ "tools": self.tools }),
                )),
                "tools/call" => {
                    let name = request.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    match name {
                        "github_search" => Ok(JsonRpcResponse::success(
                            request.id.clone(),
                            serde_json::json!({
                                "content": [{ "type": "text", "text": "Found 42 repos" }]
                            }),
                        )),
                        _ => Ok(JsonRpcResponse::error(request.id.clone(), -32001, "Not found")),
                    }
                }
                _ => Ok(JsonRpcResponse::error(request.id.clone(), -32601, "Method not found")),
            }
        }
    }

    /// Mock transport that always fails (simulates network error).
    struct FailTransport;

    impl McpTransport for FailTransport {
        fn send(&self, _url: &str, _request: &JsonRpcRequest) -> ProtocolResult<JsonRpcResponse> {
            Err(ProtocolError::Transport("connection refused".to_string()))
        }
    }

    #[test]
    fn test_mcp_client_discover() {
        let mut client = McpClient::new(MockTransport::new());
        let tools = client.discover("http://localhost:3000").unwrap();

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "github_search");
        assert_eq!(tools[1].name, "github_pr");
        assert_eq!(client.server_count(), 1);
        assert_eq!(client.tool_count(), 2);

        let info = client.server_info("http://localhost:3000").unwrap();
        assert_eq!(info.name, "mock-github");
    }

    #[test]
    fn test_mcp_client_call_tool() {
        let mut client = McpClient::new(MockTransport::new());
        client.discover("http://localhost:3000").unwrap();

        let result = client.call_tool("github_search", serde_json::json!({"query": "rust"})).unwrap();
        assert!(result["content"][0]["text"].as_str().unwrap().contains("42"));
    }

    #[test]
    fn test_mcp_client_call_unknown_tool() {
        let mut client = McpClient::new(MockTransport::new());
        client.discover("http://localhost:3000").unwrap();

        let result = client.call_tool("nonexistent", serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_mcp_client_transport_failure() {
        let mut client = McpClient::new(FailTransport);
        let result = client.discover("http://localhost:3000");
        assert!(result.is_err());
    }

    #[test]
    fn test_mcp_client_schema_cached() {
        let mut client = McpClient::new(MockTransport::new());
        client.discover("http://localhost:3000").unwrap();

        let tools = client.registered_tools();
        assert_eq!(tools.len(), 2);
        for entry in tools {
            assert!(!entry.schema.is_null(), "Schema should be cached");
        }
    }
}
