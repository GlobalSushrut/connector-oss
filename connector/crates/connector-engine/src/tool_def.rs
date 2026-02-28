//! Tool Definition — simple-but-enterprise-ready tool interface.
//!
//! Developers define tools with parameters and optional rules.
//! The system auto-generates: JSON Schema (for LLMs), MCP definition,
//! AAPI Kriya verb, Kernel ToolBinding, and ActionRecord template.
//!
//! Three layers:
//! - **Layer 0**: `Tool::new("search", "Search the web").param("query", String, "query").build()`
//! - **Layer 1**: Add `.handler(|params| ...)` for execution
//! - **Layer 2**: Add `.data_class("phi").require_approval().allowed_roles(&["doctor"])` for enterprise

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;

// ─── ToolHandler ─────────────────────────────────────────────────

/// Tool handler — the actual function that runs when a tool is called.
/// Takes JSON params, returns JSON result or error string.
pub type ToolHandler = Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ─── ParamType ───────────────────────────────────────────────────

/// Parameter types — maps directly to JSON Schema types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    String,
    Integer,
    Float,
    Boolean,
    Array(Box<ParamType>),
    Object,
    Enum(Vec<std::string::String>),
    Optional(Box<ParamType>),
}

impl ParamType {
    /// Convert to JSON Schema type string.
    pub fn json_schema_type(&self) -> &'static str {
        match self {
            ParamType::String | ParamType::Enum(_) => "string",
            ParamType::Integer => "integer",
            ParamType::Float => "number",
            ParamType::Boolean => "boolean",
            ParamType::Array(_) => "array",
            ParamType::Object => "object",
            ParamType::Optional(inner) => inner.json_schema_type(),
        }
    }

    /// Convert to JSON Schema value.
    pub fn to_json_schema(&self) -> serde_json::Value {
        match self {
            ParamType::String => serde_json::json!({"type": "string"}),
            ParamType::Integer => serde_json::json!({"type": "integer"}),
            ParamType::Float => serde_json::json!({"type": "number"}),
            ParamType::Boolean => serde_json::json!({"type": "boolean"}),
            ParamType::Array(inner) => serde_json::json!({
                "type": "array",
                "items": inner.to_json_schema()
            }),
            ParamType::Object => serde_json::json!({"type": "object"}),
            ParamType::Enum(values) => serde_json::json!({
                "type": "string",
                "enum": values
            }),
            ParamType::Optional(inner) => inner.to_json_schema(),
        }
    }
}

// ─── ToolParam ───────────────────────────────────────────────────

/// A single tool parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParam {
    pub name: std::string::String,
    pub param_type: ParamType,
    pub description: std::string::String,
    pub required: bool,
    pub default: Option<serde_json::Value>,
}

// ─── ToolRules ───────────────────────────────────────────────────

/// Enterprise rules for a tool — all optional.
/// Layer 0 tools have all defaults (no restrictions).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolRules {
    /// Data classification: "phi", "pii", "public", "internal", "confidential"
    pub data_classification: Option<std::string::String>,
    /// Whether human approval is required before execution
    pub require_approval: bool,
    /// Roles allowed to use this tool
    pub allowed_roles: Vec<std::string::String>,
    /// Roles explicitly denied
    pub denied_roles: Vec<std::string::String>,
    /// Max calls per minute
    pub rate_limit: Option<u32>,
    /// Max cost per call in USD
    pub max_cost_usd: Option<f64>,
    /// Max tokens per call
    pub max_tokens: Option<u64>,
    /// Compliance frameworks this tool falls under
    pub compliance: Vec<std::string::String>,
    /// Whether this tool is idempotent (safe to retry)
    pub idempotent: bool,
    /// Whether this tool's effects can be reversed
    pub reversible: bool,
    /// Execution timeout in milliseconds
    pub timeout_ms: Option<u64>,
}

// ─── ToolResult ──────────────────────────────────────────────────

/// Result of a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ToolResult {
    Text(std::string::String),
    Json(serde_json::Value),
    Error(std::string::String),
    PendingApproval(std::string::String),
}

impl ToolResult {
    pub fn text(s: impl Into<std::string::String>) -> Self { ToolResult::Text(s.into()) }
    pub fn json(v: serde_json::Value) -> Self { ToolResult::Json(v) }
    pub fn error(s: impl Into<std::string::String>) -> Self { ToolResult::Error(s.into()) }
    pub fn pending(reason: impl Into<std::string::String>) -> Self { ToolResult::PendingApproval(reason.into()) }
}

// ─── ToolParams (runtime parameter bag) ──────────────────────────

/// Runtime parameter bag passed to tool handlers.
#[derive(Debug, Clone)]
pub struct ToolParams {
    values: std::collections::HashMap<std::string::String, serde_json::Value>,
}

impl ToolParams {
    pub fn new() -> Self {
        Self { values: std::collections::HashMap::new() }
    }

    pub fn set(&mut self, key: &str, value: serde_json::Value) {
        self.values.insert(key.to_string(), value);
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.values.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(|v| v.as_str())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.values.get(key).and_then(|v| v.as_i64())
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.values.get(key).and_then(|v| v.as_f64())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.values.get(key).and_then(|v| v.as_bool())
    }

    pub fn from_json(value: &serde_json::Value) -> Self {
        let mut params = Self::new();
        if let Some(obj) = value.as_object() {
            for (k, v) in obj {
                params.set(k, v.clone());
            }
        }
        params
    }
}

// ─── Tool ────────────────────────────────────────────────────────

/// A tool that an agent can call.
///
/// Defined once by the developer. The system auto-generates all kernel,
/// AAPI, and LLM-compatible representations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name (e.g., "read_ehr", "search", "send_email")
    pub name: std::string::String,
    /// Human-readable description
    pub description: std::string::String,
    /// Domain (auto-derived from name if contains ".")
    pub domain: Option<std::string::String>,
    /// Parameters
    pub params: Vec<ToolParam>,
    /// Return type
    pub returns: Option<ParamType>,
    /// Enterprise rules
    pub rules: ToolRules,
}

impl Tool {
    /// Create a new tool builder.
    pub fn new(name: &str, description: &str) -> ToolBuilder {
        ToolBuilder {
            name: name.to_string(),
            description: description.to_string(),
            domain: if name.contains('.') {
                name.split('.').next().map(|s| s.to_string())
            } else {
                None
            },
            params: Vec::new(),
            returns: None,
            rules: ToolRules::default(),
        }
    }

    // ─── Export: JSON Schema (OpenAI function calling) ────────────

    /// Export as OpenAI function calling schema.
    pub fn to_openai_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.params_to_json_schema(),
            }
        })
    }

    // ─── Export: Anthropic Tool Definition ────────────────────────

    /// Export as Anthropic Claude tool definition.
    pub fn to_anthropic_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "input_schema": self.params_to_json_schema(),
        })
    }

    // ─── Export: MCP Tool Definition ──────────────────────────────

    /// Export as MCP tool definition.
    pub fn to_mcp_tool(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.params_to_json_schema(),
        })
    }

    // ─── Export: Kernel ToolBinding ───────────────────────────────

    /// Generate a VAC kernel ToolBinding.
    pub fn to_tool_binding(&self, namespace: &str) -> serde_json::Value {
        let domain = self.domain.as_deref().unwrap_or("tool");
        serde_json::json!({
            "tool_id": self.name,
            "namespace_path": format!("{}/tools/{}", namespace, domain),
            "allowed_actions": [format!("{}.{}", domain, self.verb())],
            "data_classification": self.rules.data_classification.as_deref().unwrap_or("public"),
            "requires_approval": self.rules.require_approval,
        })
    }

    // ─── Export: AAPI Kriya ──────────────────────────────────────

    /// Generate an AAPI Kriya verb descriptor.
    pub fn to_kriya(&self) -> serde_json::Value {
        let domain = self.domain.as_deref().unwrap_or("tool");
        let verb = self.verb();
        serde_json::json!({
            "action": format!("{}.{}", domain, verb),
            "domain": domain,
            "verb": verb,
            "expected_effect": if self.rules.idempotent { "none" } else { "state_change" },
            "idempotent": self.rules.idempotent,
        })
    }

    // ─── Helpers ─────────────────────────────────────────────────

    /// Extract verb from tool name.
    fn verb(&self) -> &str {
        if let Some((_domain, verb)) = self.name.split_once('.') {
            verb
        } else {
            &self.name
        }
    }

    /// Build JSON Schema for parameters.
    fn params_to_json_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.params {
            let mut schema = param.param_type.to_json_schema();
            if let Some(obj) = schema.as_object_mut() {
                obj.insert("description".to_string(), serde_json::json!(param.description));
            }
            properties.insert(param.name.clone(), schema);

            if param.required {
                required.push(serde_json::json!(param.name));
            }
        }

        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }

    /// Validate parameters against the tool's schema.
    pub fn validate_params(&self, params: &ToolParams) -> Result<(), std::string::String> {
        for param in &self.params {
            if param.required && params.get(&param.name).is_none() {
                return Err(format!("Missing required parameter: '{}'", param.name));
            }
        }
        Ok(())
    }

    /// Check if a role is allowed to use this tool.
    pub fn is_role_allowed(&self, role: &str) -> bool {
        if !self.rules.denied_roles.is_empty() && self.rules.denied_roles.iter().any(|r| r == role) {
            return false;
        }
        if self.rules.allowed_roles.is_empty() {
            return true; // No restrictions
        }
        self.rules.allowed_roles.iter().any(|r| r == role)
    }
}

// ─── ToolBuilder ─────────────────────────────────────────────────

/// Fluent builder for Tool.
pub struct ToolBuilder {
    name: std::string::String,
    description: std::string::String,
    domain: Option<std::string::String>,
    params: Vec<ToolParam>,
    returns: Option<ParamType>,
    rules: ToolRules,
}

impl ToolBuilder {
    /// Add a required parameter.
    pub fn param(mut self, name: &str, param_type: ParamType, description: &str) -> Self {
        self.params.push(ToolParam {
            name: name.to_string(),
            param_type,
            description: description.to_string(),
            required: true,
            default: None,
        });
        self
    }

    /// Add an optional parameter with a default value.
    pub fn optional_param(mut self, name: &str, param_type: ParamType, description: &str, default: serde_json::Value) -> Self {
        self.params.push(ToolParam {
            name: name.to_string(),
            param_type,
            description: description.to_string(),
            required: false,
            default: Some(default),
        });
        self
    }

    /// Set the return type.
    pub fn returns(mut self, returns: ParamType) -> Self {
        self.returns = Some(returns);
        self
    }

    /// Set the domain (auto-derived from name if contains ".").
    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = Some(domain.to_string());
        self
    }

    // ─── Enterprise rules ────────────────────────────────────────

    /// Set data classification (e.g., "phi", "pii", "public").
    pub fn data_class(mut self, classification: &str) -> Self {
        self.rules.data_classification = Some(classification.to_string());
        self
    }

    /// Require human approval before execution.
    pub fn require_approval(mut self) -> Self {
        self.rules.require_approval = true;
        self
    }

    /// Set allowed roles.
    pub fn allowed_roles(mut self, roles: &[&str]) -> Self {
        self.rules.allowed_roles = roles.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set denied roles.
    pub fn denied_roles(mut self, roles: &[&str]) -> Self {
        self.rules.denied_roles = roles.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set rate limit (calls per minute).
    pub fn rate_limit(mut self, calls_per_minute: u32) -> Self {
        self.rules.rate_limit = Some(calls_per_minute);
        self
    }

    /// Set max cost per call.
    pub fn max_cost(mut self, usd: f64) -> Self {
        self.rules.max_cost_usd = Some(usd);
        self
    }

    /// Set max tokens per call.
    pub fn max_tokens(mut self, tokens: u64) -> Self {
        self.rules.max_tokens = Some(tokens);
        self
    }

    /// Set compliance frameworks.
    pub fn compliance(mut self, frameworks: &[&str]) -> Self {
        self.rules.compliance = frameworks.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Mark as idempotent (safe to retry).
    pub fn idempotent(mut self) -> Self {
        self.rules.idempotent = true;
        self
    }

    /// Mark as reversible.
    pub fn reversible(mut self) -> Self {
        self.rules.reversible = true;
        self
    }

    /// Set execution timeout.
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.rules.timeout_ms = Some(ms);
        self
    }

    /// Build the tool.
    pub fn build(self) -> Tool {
        Tool {
            name: self.name,
            description: self.description,
            domain: self.domain,
            params: self.params,
            returns: self.returns,
            rules: self.rules,
        }
    }
}

// ─── Display ─────────────────────────────────────────────────────

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "🔧 {} — {}", self.name, self.description)?;
        if !self.params.is_empty() {
            write!(f, " (")?;
            for (i, p) in self.params.iter().enumerate() {
                if i > 0 { write!(f, ", ")?; }
                write!(f, "{}: {}", p.name, p.param_type.json_schema_type())?;
                if !p.required { write!(f, "?")?; }
            }
            write!(f, ")")?;
        }
        if self.rules.require_approval {
            write!(f, " ⏳ approval required")?;
        }
        if let Some(dc) = &self.rules.data_classification {
            write!(f, " 🔒 {}", dc)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ToolResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolResult::Text(s) => write!(f, "✅ {}", s),
            ToolResult::Json(v) => write!(f, "✅ {}", v),
            ToolResult::Error(e) => write!(f, "💥 Error: {}", e),
            ToolResult::PendingApproval(r) => write!(f, "⏳ Pending: {}", r),
        }
    }
}

// ─── ExecutableTool ──────────────────────────────────────────────

/// A tool paired with its executable handler.
/// `Tool` is serializable (for schemas/config). `ExecutableTool` adds the runtime handler.
pub struct ExecutableTool {
    pub tool: Tool,
    pub handler: Option<ToolHandler>,
}

impl ExecutableTool {
    /// Create an executable tool from a Tool definition (no handler).
    pub fn from_def(tool: Tool) -> Self {
        Self { tool, handler: None }
    }

    /// Create an executable tool with a handler.
    pub fn with_handler<F>(tool: Tool, handler: F) -> Self
    where
        F: Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    {
        Self { tool, handler: Some(Arc::new(handler)) }
    }

    /// Execute the tool handler with the given params.
    /// Returns Err if no handler is registered.
    pub fn execute(&self, params: serde_json::Value) -> Result<serde_json::Value, String> {
        match &self.handler {
            Some(h) => h(params),
            None => Err(format!("No handler registered for tool '{}'", self.tool.name)),
        }
    }

    /// Check if this tool has an executable handler.
    pub fn has_handler(&self) -> bool {
        self.handler.is_some()
    }
}

impl std::fmt::Debug for ExecutableTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableTool")
            .field("tool", &self.tool)
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

// ─── ToolRegistry ────────────────────────────────────────────────

/// Shared tool registry — register tools once, use across all agents.
///
/// Supports three tiers:
/// - **Metadata-only**: Tool definition with schema but no handler
/// - **Executable**: Tool with a handler closure that runs on tool_call
/// - **MCP**: Tool definitions loaded from an MCP server (stub)
pub struct ToolRegistry {
    tools: HashMap<String, ExecutableTool>,
}

impl ToolRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self { tools: HashMap::new() }
    }

    /// Register a tool definition (no handler).
    pub fn register(&mut self, tool: Tool) {
        let name = tool.name.clone();
        self.tools.insert(name, ExecutableTool::from_def(tool));
    }

    /// Register a tool with an executable handler.
    pub fn register_with_handler<F>(&mut self, tool: Tool, handler: F)
    where
        F: Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    {
        let name = tool.name.clone();
        self.tools.insert(name, ExecutableTool::with_handler(tool, handler));
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<&ExecutableTool> {
        self.tools.get(name)
    }

    /// Execute a tool by name with given params.
    pub fn execute(&self, name: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        match self.tools.get(name) {
            Some(t) => t.execute(params),
            None => Err(format!("Tool '{}' not found in registry", name)),
        }
    }

    /// List all registered tool names.
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    /// Get all tool definitions (for schema export).
    pub fn tool_defs(&self) -> Vec<&Tool> {
        self.tools.values().map(|et| &et.tool).collect()
    }

    /// Export all tools as OpenAI function calling schemas.
    pub fn to_openai_schemas(&self) -> Vec<serde_json::Value> {
        self.tools.values().map(|et| et.tool.to_openai_schema()).collect()
    }

    /// Export all tools as Anthropic tool definitions.
    pub fn to_anthropic_schemas(&self) -> Vec<serde_json::Value> {
        self.tools.values().map(|et| et.tool.to_anthropic_schema()).collect()
    }

    /// Export all tools as MCP tool definitions.
    pub fn to_mcp_tools(&self) -> Vec<serde_json::Value> {
        self.tools.values().map(|et| et.tool.to_mcp_tool()).collect()
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Check if a tool has an executable handler.
    pub fn has_handler(&self, name: &str) -> bool {
        self.tools.get(name).map(|t| t.has_handler()).unwrap_or(false)
    }
}

impl std::fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("count", &self.tools.len())
            .field("tools", &self.tool_names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer0_minimal_tool() {
        let tool = Tool::new("search", "Search the web")
            .param("query", ParamType::String, "Search query")
            .build();

        assert_eq!(tool.name, "search");
        assert_eq!(tool.description, "Search the web");
        assert_eq!(tool.params.len(), 1);
        assert_eq!(tool.params[0].name, "query");
        assert!(tool.params[0].required);
        assert!(!tool.rules.require_approval);
        assert!(tool.rules.data_classification.is_none());
    }

    #[test]
    fn test_layer2_enterprise_tool() {
        let tool = Tool::new("read_ehr", "Read patient EHR")
            .param("patient_id", ParamType::String, "Patient ID")
            .param("section", ParamType::Enum(vec![
                "vitals".into(), "labs".into(), "notes".into(), "all".into()
            ]), "EHR section")
            .returns(ParamType::Object)
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor", "nurse"])
            .denied_roles(&["billing"])
            .rate_limit(30)
            .max_cost(0.50)
            .compliance(&["hipaa", "soc2"])
            .idempotent()
            .build();

        assert_eq!(tool.name, "read_ehr");
        assert_eq!(tool.params.len(), 2);
        assert!(tool.rules.require_approval);
        assert_eq!(tool.rules.data_classification.as_deref(), Some("phi"));
        assert_eq!(tool.rules.allowed_roles, vec!["doctor", "nurse"]);
        assert_eq!(tool.rules.denied_roles, vec!["billing"]);
        assert_eq!(tool.rules.rate_limit, Some(30));
        assert_eq!(tool.rules.compliance, vec!["hipaa", "soc2"]);
        assert!(tool.rules.idempotent);
    }

    #[test]
    fn test_openai_schema_export() {
        let tool = Tool::new("search", "Search the web")
            .param("query", ParamType::String, "Search query")
            .param("limit", ParamType::Integer, "Max results")
            .build();

        let schema = tool.to_openai_schema();
        assert_eq!(schema["type"], "function");
        assert_eq!(schema["function"]["name"], "search");
        assert_eq!(schema["function"]["description"], "Search the web");

        let params = &schema["function"]["parameters"];
        assert_eq!(params["type"], "object");
        assert_eq!(params["properties"]["query"]["type"], "string");
        assert_eq!(params["properties"]["query"]["description"], "Search query");
        assert_eq!(params["properties"]["limit"]["type"], "integer");

        let required = params["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("query")));
        assert!(required.contains(&serde_json::json!("limit")));
    }

    #[test]
    fn test_mcp_tool_export() {
        let tool = Tool::new("search", "Search the web")
            .param("query", ParamType::String, "Search query")
            .build();

        let mcp = tool.to_mcp_tool();
        assert_eq!(mcp["name"], "search");
        assert_eq!(mcp["description"], "Search the web");
        assert_eq!(mcp["inputSchema"]["type"], "object");
        assert_eq!(mcp["inputSchema"]["properties"]["query"]["type"], "string");
    }

    #[test]
    fn test_tool_binding_export() {
        let tool = Tool::new("read_ehr", "Read patient EHR")
            .domain("ehr")
            .data_class("phi")
            .require_approval()
            .build();

        let binding = tool.to_tool_binding("ns:org/hospital");
        assert_eq!(binding["tool_id"], "read_ehr");
        assert_eq!(binding["namespace_path"], "ns:org/hospital/tools/ehr");
        assert_eq!(binding["data_classification"], "phi");
        assert_eq!(binding["requires_approval"], true);
    }

    #[test]
    fn test_kriya_export() {
        let tool = Tool::new("ehr.read", "Read patient EHR")
            .idempotent()
            .build();

        let kriya = tool.to_kriya();
        assert_eq!(kriya["action"], "ehr.read");
        assert_eq!(kriya["domain"], "ehr");
        assert_eq!(kriya["verb"], "read");
        assert_eq!(kriya["idempotent"], true);
        assert_eq!(kriya["expected_effect"], "none");
    }

    #[test]
    fn test_enum_param_schema() {
        let tool = Tool::new("classify", "Classify urgency")
            .param("level", ParamType::Enum(vec![
                "low".into(), "medium".into(), "high".into(), "critical".into()
            ]), "Urgency level")
            .build();

        let schema = tool.to_openai_schema();
        let level = &schema["function"]["parameters"]["properties"]["level"];
        assert_eq!(level["type"], "string");
        let enums = level["enum"].as_array().unwrap();
        assert_eq!(enums.len(), 4);
        assert!(enums.contains(&serde_json::json!("critical")));
    }

    #[test]
    fn test_array_param_schema() {
        let tool = Tool::new("check_interactions", "Check drug interactions")
            .param("medications", ParamType::Array(Box::new(ParamType::String)), "List of medications")
            .build();

        let schema = tool.to_openai_schema();
        let meds = &schema["function"]["parameters"]["properties"]["medications"];
        assert_eq!(meds["type"], "array");
        assert_eq!(meds["items"]["type"], "string");
    }

    #[test]
    fn test_optional_param() {
        let tool = Tool::new("search", "Search")
            .param("query", ParamType::String, "Query")
            .optional_param("limit", ParamType::Integer, "Max results", serde_json::json!(10))
            .build();

        assert_eq!(tool.params.len(), 2);
        assert!(tool.params[0].required);
        assert!(!tool.params[1].required);
        assert_eq!(tool.params[1].default, Some(serde_json::json!(10)));

        let schema = tool.to_openai_schema();
        let required = schema["function"]["parameters"]["required"].as_array().unwrap();
        assert_eq!(required.len(), 1); // Only "query" is required
        assert!(required.contains(&serde_json::json!("query")));
    }

    #[test]
    fn test_role_access_control() {
        let tool = Tool::new("prescribe", "Prescribe medication")
            .allowed_roles(&["doctor"])
            .denied_roles(&["billing", "admin"])
            .build();

        assert!(tool.is_role_allowed("doctor"));
        assert!(!tool.is_role_allowed("billing"));
        assert!(!tool.is_role_allowed("admin"));
        assert!(!tool.is_role_allowed("nurse")); // Not in allowed list
    }

    #[test]
    fn test_role_no_restrictions() {
        let tool = Tool::new("search", "Search").build();

        assert!(tool.is_role_allowed("anyone"));
        assert!(tool.is_role_allowed("doctor"));
        assert!(tool.is_role_allowed("admin"));
    }

    #[test]
    fn test_param_validation() {
        let tool = Tool::new("search", "Search")
            .param("query", ParamType::String, "Query")
            .build();

        let mut params = ToolParams::new();
        assert!(tool.validate_params(&params).is_err());

        params.set("query", serde_json::json!("test"));
        assert!(tool.validate_params(&params).is_ok());
    }

    #[test]
    fn test_tool_params_from_json() {
        let json = serde_json::json!({
            "patient_id": "P-123",
            "section": "vitals",
            "include_history": true
        });

        let params = ToolParams::from_json(&json);
        assert_eq!(params.get_str("patient_id"), Some("P-123"));
        assert_eq!(params.get_str("section"), Some("vitals"));
        assert_eq!(params.get_bool("include_history"), Some(true));
    }

    #[test]
    fn test_tool_display() {
        let tool = Tool::new("read_ehr", "Read patient EHR")
            .param("patient_id", ParamType::String, "Patient ID")
            .data_class("phi")
            .require_approval()
            .build();

        let display = format!("{}", tool);
        assert!(display.contains("read_ehr"));
        assert!(display.contains("Read patient EHR"));
        assert!(display.contains("patient_id: string"));
        assert!(display.contains("approval required"));
        assert!(display.contains("phi"));
    }

    #[test]
    fn test_tool_result_display() {
        assert!(format!("{}", ToolResult::text("done")).contains("✅"));
        assert!(format!("{}", ToolResult::error("fail")).contains("💥"));
        assert!(format!("{}", ToolResult::pending("waiting")).contains("⏳"));
    }

    #[test]
    fn test_hospital_tool_suite() {
        let classify = Tool::new("classify_patient", "Classify patient urgency")
            .param("symptoms", ParamType::String, "Patient symptoms")
            .param("age", ParamType::Integer, "Patient age")
            .returns(ParamType::Enum(vec!["ESI-1".into(), "ESI-2".into(), "ESI-3".into(), "ESI-4".into(), "ESI-5".into()]))
            .compliance(&["hipaa"])
            .build();

        let read_ehr = Tool::new("ehr.read", "Read patient EHR")
            .param("patient_id", ParamType::String, "Patient ID")
            .param("section", ParamType::Enum(vec!["vitals".into(), "labs".into(), "notes".into()]), "Section")
            .data_class("phi")
            .allowed_roles(&["doctor", "nurse"])
            .idempotent()
            .compliance(&["hipaa"])
            .build();

        let prescribe = Tool::new("pharmacy.prescribe", "Prescribe medication")
            .param("patient_id", ParamType::String, "Patient ID")
            .param("medication", ParamType::String, "Medication name")
            .param("dosage", ParamType::String, "Dosage")
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing", "admin"])
            .compliance(&["hipaa", "fda"])
            .build();

        // Verify all export formats work
        assert!(classify.to_openai_schema()["function"]["name"] == "classify_patient");
        assert!(read_ehr.to_mcp_tool()["name"] == "ehr.read");
        assert!(prescribe.to_tool_binding("ns:hospital")["requires_approval"] == true);
        assert!(prescribe.to_kriya()["domain"] == "pharmacy");

        // Verify RBAC
        assert!(prescribe.is_role_allowed("doctor"));
        assert!(!prescribe.is_role_allowed("nurse"));
        assert!(!prescribe.is_role_allowed("billing"));

        // Verify display
        let display = format!("{}", prescribe);
        assert!(display.contains("pharmacy.prescribe"));
        assert!(display.contains("phi"));
        assert!(display.contains("approval"));
    }

    // ─── New tests: ExecutableTool, ToolRegistry, Anthropic schema ──

    #[test]
    fn test_anthropic_schema_export() {
        let tool = Tool::new("search", "Search the web")
            .param("query", ParamType::String, "Search query")
            .build();

        let schema = tool.to_anthropic_schema();
        assert_eq!(schema["name"], "search");
        assert_eq!(schema["description"], "Search the web");
        assert_eq!(schema["input_schema"]["type"], "object");
        assert_eq!(schema["input_schema"]["properties"]["query"]["type"], "string");
    }

    #[test]
    fn test_executable_tool_no_handler() {
        let tool = Tool::new("search", "Search").build();
        let exec = ExecutableTool::from_def(tool);
        assert!(!exec.has_handler());
        assert!(exec.execute(serde_json::json!({})).is_err());
    }

    #[test]
    fn test_executable_tool_with_handler() {
        let tool = Tool::new("add", "Add two numbers")
            .param("a", ParamType::Integer, "First number")
            .param("b", ParamType::Integer, "Second number")
            .build();

        let exec = ExecutableTool::with_handler(tool, |params| {
            let a = params["a"].as_i64().unwrap_or(0);
            let b = params["b"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({"result": a + b}))
        });

        assert!(exec.has_handler());
        let result = exec.execute(serde_json::json!({"a": 3, "b": 4})).unwrap();
        assert_eq!(result["result"], 7);
    }

    #[test]
    fn test_executable_tool_handler_error() {
        let tool = Tool::new("fail", "Always fails").build();
        let exec = ExecutableTool::with_handler(tool, |_| {
            Err("Something went wrong".to_string())
        });

        let result = exec.execute(serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Something went wrong"));
    }

    #[test]
    fn test_tool_registry_register_and_lookup() {
        let mut reg = ToolRegistry::new();
        assert!(reg.is_empty());

        reg.register(Tool::new("search", "Search the web").build());
        reg.register(Tool::new("calc", "Calculate").build());

        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());
        assert!(reg.get("search").is_some());
        assert!(reg.get("calc").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_tool_registry_execute() {
        let mut reg = ToolRegistry::new();

        let tool = Tool::new("double", "Double a number")
            .param("n", ParamType::Integer, "Number")
            .build();

        reg.register_with_handler(tool, |params| {
            let n = params["n"].as_i64().unwrap_or(0);
            Ok(serde_json::json!({"result": n * 2}))
        });

        assert!(reg.has_handler("double"));
        let result = reg.execute("double", serde_json::json!({"n": 5})).unwrap();
        assert_eq!(result["result"], 10);

        // Non-existent tool
        assert!(reg.execute("nope", serde_json::json!({})).is_err());
    }

    #[test]
    fn test_tool_registry_schema_export() {
        let mut reg = ToolRegistry::new();
        reg.register(Tool::new("search", "Search the web")
            .param("query", ParamType::String, "Query")
            .build());
        reg.register(Tool::new("calc", "Calculate")
            .param("expr", ParamType::String, "Expression")
            .build());

        let openai = reg.to_openai_schemas();
        assert_eq!(openai.len(), 2);
        assert!(openai.iter().any(|s| s["function"]["name"] == "search"));

        let anthropic = reg.to_anthropic_schemas();
        assert_eq!(anthropic.len(), 2);
        assert!(anthropic.iter().any(|s| s["name"] == "calc"));

        let mcp = reg.to_mcp_tools();
        assert_eq!(mcp.len(), 2);
    }

    #[test]
    fn test_tool_registry_metadata_only() {
        let mut reg = ToolRegistry::new();
        reg.register(Tool::new("search", "Search").build());

        // Metadata-only tool has no handler
        assert!(!reg.has_handler("search"));
        assert!(reg.execute("search", serde_json::json!({})).is_err());
    }

    #[test]
    fn test_tool_registry_debug() {
        let mut reg = ToolRegistry::new();
        reg.register(Tool::new("a", "A").build());
        reg.register(Tool::new("b", "B").build());
        let debug = format!("{:?}", reg);
        assert!(debug.contains("ToolRegistry"));
        assert!(debug.contains("count: 2"));
    }
}
