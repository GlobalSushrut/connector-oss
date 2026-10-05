use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use connector_protocols::mcp_server::{McpToolDef, McpToolResult};
use lazy_static::lazy_static;

use crate::state::SharedState;

type HostedHandler =
    dyn Fn(&SharedState, &str, serde_json::Value) -> McpToolResult + Send + Sync + 'static;

#[derive(Clone)]
struct HostedTool {
    def: McpToolDef,
    handler: Arc<HostedHandler>,
}

lazy_static! {
    static ref HOSTED_TOOLS: RwLock<HashMap<String, HostedTool>> = RwLock::new(HashMap::new());
}

pub fn register_tool(
    name: &str,
    description: &str,
    input_schema: serde_json::Value,
    handler: Arc<HostedHandler>,
) {
    if let Ok(mut reg) = HOSTED_TOOLS.write() {
        reg.insert(
            name.to_string(),
            HostedTool {
                def: McpToolDef {
                    name: name.to_string(),
                    description: description.to_string(),
                    input_schema,
                },
                handler,
            },
        );
    }
}

pub fn ensure_default_plugins() {
    // Plugin-owned MCP tools are registered externally via plugin bootstrapping.
}

pub fn list_tools() -> Vec<McpToolDef> {
    HOSTED_TOOLS
        .read()
        .map(|reg| reg.values().map(|t| t.def.clone()).collect())
        .unwrap_or_default()
}

pub fn call_tool(
    state: &SharedState,
    agent_pid: &str,
    name: &str,
    args: serde_json::Value,
) -> Option<McpToolResult> {
    // T7 — under microVM-strict, refuse in-process hosted MCP handlers.
    if !in_process_hosted_mcp_allowed() {
        return Some(McpToolResult {
            content: vec![connector_protocols::mcp_server::McpContent {
                content_type: "text".into(),
                text: "hosted_mcp_requires_oopc: CONNECTOR_TOOLS_IN_MICROVM_STRICT denies in-process hosted tools".into(),
            }],
            is_error: Some(true),
        });
    }
    let reg = HOSTED_TOOLS.read().ok()?;
    let tool = reg.get(name)?;
    Some((tool.handler)(state, agent_pid, args))
}

/// In-process hosted MCP is allowed only when not under TOOLS_IN_MICROVM_STRICT
/// (or break-glass CONNECTOR_ALLOW_IN_PROCESS_EFFECTS).
pub fn in_process_hosted_mcp_allowed() -> bool {
    fn truthy(name: &str) -> bool {
        match std::env::var(name) {
            Ok(v) => {
                let t = v.trim().to_ascii_lowercase();
                matches!(t.as_str(), "1" | "true" | "yes" | "on")
            }
            Err(_) => false,
        }
    }
    if truthy("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS") {
        return true;
    }
    !truthy("CONNECTOR_TOOLS_IN_MICROVM_STRICT")
}
