//! CLS Contract Templates — Standard contract templates for common patterns.
//!
//! Provides pre-built contract templates that can be customized and compiled.
//! Templates reduce boilerplate and ensure best practices.
//!
//! ## Available Templates
//!
//! | Template | Description | Use Case |
//! |----------|-------------|----------|
//! | `simple_qa` | Question-answering agent | Chatbots, support |
//! | `rag_pipeline` | RAG with retrieval + generation | Knowledge bases |
//! | `tool_agent` | Tool-calling agent | Automation |
//! | `multi_step` | Multi-step reasoning | Complex tasks |
//! | `approval_gate` | Human-in-the-loop | Sensitive operations |
//! | `saga_pipeline` | Multi-agent saga | Distributed workflows |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::types::{ParamDef, ParamType, ContractVersion};
use super::compiler::SurfaceContract;

/// Template identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateId {
    SimpleQa,
    RagPipeline,
    ToolAgent,
    MultiStep,
    ApprovalGate,
    SagaPipeline,
    Custom(String),
}

impl std::fmt::Display for TemplateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimpleQa => write!(f, "simple_qa"),
            Self::RagPipeline => write!(f, "rag_pipeline"),
            Self::ToolAgent => write!(f, "tool_agent"),
            Self::MultiStep => write!(f, "multi_step"),
            Self::ApprovalGate => write!(f, "approval_gate"),
            Self::SagaPipeline => write!(f, "saga_pipeline"),
            Self::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Template metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMetadata {
    pub id: TemplateId,
    pub name: String,
    pub description: String,
    pub version: ContractVersion,
    pub author: String,
    pub tags: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub required_tools: Vec<String>,
}

/// A contract template with customizable parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTemplate {
    pub metadata: TemplateMetadata,
    /// Parameters that can be customized when instantiating
    pub parameters: Vec<TemplateParam>,
    /// The template YAML with {{placeholder}} markers
    pub template_yaml: String,
    /// Example instantiation
    pub example: Option<HashMap<String, serde_json::Value>>,
}

/// A customizable parameter in a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParam {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
    pub description: String,
    pub default: Option<serde_json::Value>,
    pub validation: Option<String>,
}

/// Result of template instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResult {
    pub ok: bool,
    pub contract_yaml: Option<String>,
    pub errors: Vec<TemplateError>,
    pub warnings: Vec<String>,
}

/// Template instantiation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateError {
    pub param: String,
    pub message: String,
    pub hint: Option<String>,
}

/// Template library — registry of available templates.
pub struct TemplateLibrary {
    templates: HashMap<TemplateId, ContractTemplate>,
}

impl TemplateLibrary {
    /// Create a new template library with built-in templates.
    pub fn new() -> Self {
        let mut lib = Self {
            templates: HashMap::new(),
        };
        lib.register_builtin_templates();
        lib
    }

    /// Register built-in templates.
    fn register_builtin_templates(&mut self) {
        self.templates.insert(TemplateId::SimpleQa, Self::simple_qa_template());
        self.templates.insert(TemplateId::RagPipeline, Self::rag_pipeline_template());
        self.templates.insert(TemplateId::ToolAgent, Self::tool_agent_template());
        self.templates.insert(TemplateId::MultiStep, Self::multi_step_template());
        self.templates.insert(TemplateId::ApprovalGate, Self::approval_gate_template());
        self.templates.insert(TemplateId::SagaPipeline, Self::saga_pipeline_template());
    }

    /// List all available templates.
    pub fn list(&self) -> Vec<&TemplateMetadata> {
        self.templates.values().map(|t| &t.metadata).collect()
    }

    /// Get a template by ID.
    pub fn get(&self, id: &TemplateId) -> Option<&ContractTemplate> {
        self.templates.get(id)
    }

    /// Register a custom template.
    pub fn register(&mut self, template: ContractTemplate) {
        self.templates.insert(template.metadata.id.clone(), template);
    }

    /// Instantiate a template with parameters.
    pub fn instantiate(
        &self,
        id: &TemplateId,
        params: HashMap<String, serde_json::Value>,
    ) -> TemplateResult {
        let template = match self.get(id) {
            Some(t) => t,
            None => return TemplateResult {
                ok: false,
                contract_yaml: None,
                errors: vec![TemplateError {
                    param: "template_id".to_string(),
                    message: format!("Template not found: {}", id),
                    hint: Some("Use /contracts/templates to list available templates".to_string()),
                }],
                warnings: vec![],
            },
        };

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut yaml = template.template_yaml.clone();

        // Validate and substitute parameters
        for param in &template.parameters {
            let value = params.get(&param.name).or(param.default.as_ref());

            match value {
                Some(v) => {
                    // Substitute placeholder
                    let placeholder = format!("{{{{{}}}}}", param.name);
                    let value_str = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    yaml = yaml.replace(&placeholder, &value_str);
                }
                None if param.required => {
                    errors.push(TemplateError {
                        param: param.name.clone(),
                        message: format!("Required parameter '{}' is missing", param.name),
                        hint: Some(format!("Expected type: {:?}. {}", param.param_type, param.description)),
                    });
                }
                None => {
                    warnings.push(format!("Optional parameter '{}' not provided, using default", param.name));
                }
            }
        }

        if !errors.is_empty() {
            return TemplateResult {
                ok: false,
                contract_yaml: None,
                errors,
                warnings,
            };
        }

        TemplateResult {
            ok: true,
            contract_yaml: Some(yaml),
            errors: vec![],
            warnings,
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Built-in Templates
    // ═══════════════════════════════════════════════════════════════

    fn simple_qa_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::SimpleQa,
                name: "Simple Q&A Agent".to_string(),
                description: "A basic question-answering agent with memory".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["qa".to_string(), "chatbot".to_string(), "simple".to_string()],
                required_capabilities: vec!["llm.chat".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "agent_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the agent".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "system_prompt".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "System prompt defining agent behavior".to_string(),
                    default: Some(serde_json::json!("You are a helpful assistant.")),
                    validation: None,
                },
                TemplateParam {
                    name: "model".to_string(),
                    param_type: ParamType::String,
                    required: false,
                    description: "LLM model to use".to_string(),
                    default: Some(serde_json::json!("gpt-4")),
                    validation: None,
                },
                TemplateParam {
                    name: "max_tokens".to_string(),
                    param_type: ParamType::Integer,
                    required: false,
                    description: "Maximum tokens per response".to_string(),
                    default: Some(serde_json::json!(1000)),
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{agent_name}}"
  version: "1.0.0"
  description: "Simple Q&A agent"

interface:
  inputs:
    - name: query
      type: string
      required: true
      description: "User question"
  outputs:
    - name: response
      type: string
      description: "Agent response"

resources:
  token_budget: {{max_tokens}}
  cost_limit_usd: 0.10
  timeout_ms: 30000

flow:
  - id: answer
    type: llm_call
    model: "{{model}}"
    system: "{{system_prompt}}"
    input: "{{query}}"
    output: response

governance:
  preconditions:
    - type: input_not_empty
      field: query
  postconditions:
    - type: output_not_empty
      field: response
"#.to_string(),
            example: Some(HashMap::from([
                ("agent_name".to_string(), serde_json::json!("support-bot")),
                ("system_prompt".to_string(), serde_json::json!("You are a helpful customer support agent.")),
            ])),
        }
    }

    fn rag_pipeline_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::RagPipeline,
                name: "RAG Pipeline".to_string(),
                description: "Retrieval-Augmented Generation pipeline with memory search".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["rag".to_string(), "retrieval".to_string(), "knowledge".to_string()],
                required_capabilities: vec!["llm.chat".to_string(), "memory.read".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "agent_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the agent".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "namespace".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Memory namespace to search".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "top_k".to_string(),
                    param_type: ParamType::Integer,
                    required: false,
                    description: "Number of documents to retrieve".to_string(),
                    default: Some(serde_json::json!(5)),
                    validation: None,
                },
                TemplateParam {
                    name: "system_prompt".to_string(),
                    param_type: ParamType::String,
                    required: false,
                    description: "System prompt for generation".to_string(),
                    default: Some(serde_json::json!("Answer based on the provided context. If the context doesn't contain the answer, say so.")),
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{agent_name}}"
  version: "1.0.0"
  description: "RAG pipeline with retrieval and generation"

interface:
  inputs:
    - name: query
      type: string
      required: true
  outputs:
    - name: response
      type: string
    - name: sources
      type: list
      description: "Retrieved source documents"

resources:
  token_budget: 4000
  cost_limit_usd: 0.20
  timeout_ms: 60000

flow:
  - id: retrieve
    type: memory_search
    namespace: "{{namespace}}"
    query: "{{query}}"
    top_k: {{top_k}}
    output: context

  - id: generate
    type: llm_call
    model: "gpt-4"
    system: "{{system_prompt}}"
    input: |
      Context:
      {{context}}
      
      Question: {{query}}
    output: response

  - id: extract_sources
    type: transform
    input: context
    operation: extract_cids
    output: sources

governance:
  preconditions:
    - type: input_not_empty
      field: query
  invariants:
    - type: context_grounded
      description: "Response must be grounded in retrieved context"
"#.to_string(),
            example: Some(HashMap::from([
                ("agent_name".to_string(), serde_json::json!("knowledge-bot")),
                ("namespace".to_string(), serde_json::json!("ns:docs/medical")),
            ])),
        }
    }

    fn tool_agent_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::ToolAgent,
                name: "Tool-Calling Agent".to_string(),
                description: "Agent that can call external tools based on user requests".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["tools".to_string(), "automation".to_string(), "function-calling".to_string()],
                required_capabilities: vec!["llm.chat".to_string(), "tool.invoke".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "agent_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the agent".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "tools".to_string(),
                    param_type: ParamType::List(Box::new(ParamType::String)),
                    required: true,
                    description: "List of tool IDs the agent can use".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "system_prompt".to_string(),
                    param_type: ParamType::String,
                    required: false,
                    description: "System prompt".to_string(),
                    default: Some(serde_json::json!("You are a helpful assistant with access to tools. Use them when appropriate.")),
                    validation: None,
                },
                TemplateParam {
                    name: "max_tool_calls".to_string(),
                    param_type: ParamType::Integer,
                    required: false,
                    description: "Maximum tool calls per request".to_string(),
                    default: Some(serde_json::json!(5)),
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{agent_name}}"
  version: "1.0.0"
  description: "Tool-calling agent"

interface:
  inputs:
    - name: request
      type: string
      required: true
  outputs:
    - name: response
      type: string
    - name: tool_calls
      type: list

capabilities:
  tools: {{tools}}

resources:
  token_budget: 4000
  cost_limit_usd: 0.50
  timeout_ms: 120000
  max_tool_calls: {{max_tool_calls}}

flow:
  - id: plan
    type: llm_call
    model: "gpt-4"
    system: "{{system_prompt}}"
    input: "{{request}}"
    tools: {{tools}}
    output: plan

  - id: execute_tools
    type: tool_loop
    plan: "{{plan}}"
    max_iterations: {{max_tool_calls}}
    output: tool_results

  - id: synthesize
    type: llm_call
    model: "gpt-4"
    system: "Synthesize the tool results into a final response."
    input: |
      Original request: {{request}}
      Tool results: {{tool_results}}
    output: response

governance:
  preconditions:
    - type: tools_available
      tools: {{tools}}
  postconditions:
    - type: output_not_empty
      field: response
"#.to_string(),
            example: Some(HashMap::from([
                ("agent_name".to_string(), serde_json::json!("automation-agent")),
                ("tools".to_string(), serde_json::json!(["web_search", "calculator", "calendar"])),
            ])),
        }
    }

    fn multi_step_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::MultiStep,
                name: "Multi-Step Reasoning".to_string(),
                description: "Agent that breaks down complex tasks into steps".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["reasoning".to_string(), "chain-of-thought".to_string(), "complex".to_string()],
                required_capabilities: vec!["llm.chat".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "agent_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the agent".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "max_steps".to_string(),
                    param_type: ParamType::Integer,
                    required: false,
                    description: "Maximum reasoning steps".to_string(),
                    default: Some(serde_json::json!(10)),
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{agent_name}}"
  version: "1.0.0"
  description: "Multi-step reasoning agent"

interface:
  inputs:
    - name: task
      type: string
      required: true
  outputs:
    - name: result
      type: string
    - name: reasoning_chain
      type: list

resources:
  token_budget: 8000
  cost_limit_usd: 1.00
  timeout_ms: 300000

state_machine:
  initial: planning
  states: [planning, executing, reflecting, complete]
  transitions:
    - from: planning
      to: executing
      trigger: plan_ready
    - from: executing
      to: reflecting
      trigger: step_complete
    - from: reflecting
      to: executing
      trigger: continue
    - from: reflecting
      to: complete
      trigger: done

flow:
  - id: plan
    type: llm_call
    model: "gpt-4"
    system: "Break down this task into clear steps. Output a numbered list."
    input: "{{task}}"
    output: plan

  - id: execute_steps
    type: step_loop
    plan: "{{plan}}"
    max_iterations: {{max_steps}}
    per_step:
      - id: execute
        type: llm_call
        model: "gpt-4"
        input: "Execute step: {{current_step}}"
        output: step_result
      - id: reflect
        type: llm_call
        model: "gpt-4"
        input: "Reflect on result: {{step_result}}. Should we continue or are we done?"
        output: reflection
    output: reasoning_chain

  - id: synthesize
    type: llm_call
    model: "gpt-4"
    input: |
      Task: {{task}}
      Reasoning chain: {{reasoning_chain}}
      Provide the final answer.
    output: result

governance:
  invariants:
    - type: max_iterations
      limit: {{max_steps}}
"#.to_string(),
            example: Some(HashMap::from([
                ("agent_name".to_string(), serde_json::json!("reasoner")),
                ("max_steps".to_string(), serde_json::json!(5)),
            ])),
        }
    }

    fn approval_gate_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::ApprovalGate,
                name: "Human Approval Gate".to_string(),
                description: "Agent that requires human approval for sensitive actions".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["approval".to_string(), "human-in-loop".to_string(), "safety".to_string()],
                required_capabilities: vec!["llm.chat".to_string(), "approval.request".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "agent_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the agent".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "approvers".to_string(),
                    param_type: ParamType::List(Box::new(ParamType::String)),
                    required: true,
                    description: "List of approver agent/user IDs".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "approval_timeout_ms".to_string(),
                    param_type: ParamType::Integer,
                    required: false,
                    description: "Timeout for approval in milliseconds".to_string(),
                    default: Some(serde_json::json!(300000)),
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{agent_name}}"
  version: "1.0.0"
  description: "Agent with human approval gate"

interface:
  inputs:
    - name: action
      type: string
      required: true
    - name: context
      type: json
  outputs:
    - name: result
      type: string
    - name: approval_status
      type: string

resources:
  timeout_ms: {{approval_timeout_ms}}

state_machine:
  initial: pending
  states: [pending, awaiting_approval, approved, rejected, executed]
  transitions:
    - from: pending
      to: awaiting_approval
      trigger: submit
    - from: awaiting_approval
      to: approved
      trigger: approve
    - from: awaiting_approval
      to: rejected
      trigger: reject
    - from: approved
      to: executed
      trigger: execute

flow:
  - id: prepare
    type: llm_call
    model: "gpt-4"
    system: "Summarize this action for human review."
    input: |
      Action: {{action}}
      Context: {{context}}
    output: summary

  - id: request_approval
    type: approval_gate
    approvers: {{approvers}}
    summary: "{{summary}}"
    timeout_ms: {{approval_timeout_ms}}
    output: approval

  - id: execute_if_approved
    type: conditional
    condition: "{{approval.approved}}"
    if_true:
      - id: execute
        type: llm_call
        input: "Execute: {{action}}"
        output: result
    if_false:
      - id: reject_response
        type: constant
        value: "Action rejected by approver"
        output: result

governance:
  preconditions:
    - type: approvers_valid
      approvers: {{approvers}}
"#.to_string(),
            example: Some(HashMap::from([
                ("agent_name".to_string(), serde_json::json!("sensitive-action-agent")),
                ("approvers".to_string(), serde_json::json!(["admin@company.com"])),
            ])),
        }
    }

    fn saga_pipeline_template() -> ContractTemplate {
        ContractTemplate {
            metadata: TemplateMetadata {
                id: TemplateId::SagaPipeline,
                name: "Saga Pipeline".to_string(),
                description: "Multi-agent saga with compensation on failure".to_string(),
                version: ContractVersion::new(1, 0, 0),
                author: "connector".to_string(),
                tags: vec!["saga".to_string(), "distributed".to_string(), "rollback".to_string()],
                required_capabilities: vec!["agent.delegate".to_string()],
                required_tools: vec![],
            },
            parameters: vec![
                TemplateParam {
                    name: "saga_name".to_string(),
                    param_type: ParamType::String,
                    required: true,
                    description: "Name of the saga".to_string(),
                    default: None,
                    validation: None,
                },
                TemplateParam {
                    name: "steps".to_string(),
                    param_type: ParamType::Json,
                    required: true,
                    description: "Saga steps with agent and compensation".to_string(),
                    default: None,
                    validation: None,
                },
            ],
            template_yaml: r#"
contract:
  name: "{{saga_name}}"
  version: "1.0.0"
  description: "Saga pipeline with rollback"

interface:
  inputs:
    - name: payload
      type: json
      required: true
  outputs:
    - name: result
      type: json
    - name: saga_status
      type: string

resources:
  timeout_ms: 600000

state_machine:
  initial: started
  states: [started, executing, compensating, completed, failed]
  transitions:
    - from: started
      to: executing
      trigger: begin
    - from: executing
      to: completed
      trigger: all_success
    - from: executing
      to: compensating
      trigger: step_failed
    - from: compensating
      to: failed
      trigger: compensation_done

flow:
  - id: saga_executor
    type: saga
    steps: {{steps}}
    input: "{{payload}}"
    on_failure: compensate
    output: result

governance:
  invariants:
    - type: saga_atomicity
      description: "All steps succeed or all are compensated"
"#.to_string(),
            example: Some(HashMap::from([
                ("saga_name".to_string(), serde_json::json!("order-fulfillment")),
                ("steps".to_string(), serde_json::json!([
                    {"agent": "inventory-agent", "action": "reserve", "compensate": "release"},
                    {"agent": "payment-agent", "action": "charge", "compensate": "refund"},
                    {"agent": "shipping-agent", "action": "ship", "compensate": "cancel"}
                ])),
            ])),
        }
    }
}

impl Default for TemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// Simple Contract Builder — JSON flow → CLS
// ═══════════════════════════════════════════════════════════════

/// Simple contract definition for auto-generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleContractDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub memory_namespaces: Vec<String>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub approvers: Vec<String>,
}

impl SimpleContractDef {
    /// Generate CLS YAML from simple definition.
    pub fn to_cls_yaml(&self) -> String {
        let model = self.model.as_deref().unwrap_or("gpt-4");
        let system = self.system_prompt.as_deref().unwrap_or("You are a helpful assistant.");
        let max_tokens = self.max_tokens.unwrap_or(2000);
        let timeout = self.timeout_ms.unwrap_or(60000);
        let description = self.description.as_deref().unwrap_or("Auto-generated contract");

        let tools_yaml = if self.tools.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", self.tools.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(", "))
        };

        let namespaces_yaml = if self.memory_namespaces.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", self.memory_namespaces.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(", "))
        };

        let mut yaml = format!(r#"
contract:
  name: "{}"
  version: "1.0.0"
  description: "{}"

interface:
  inputs:
    - name: input
      type: string
      required: true
  outputs:
    - name: output
      type: string

capabilities:
  tools: {}
  namespaces: {}

resources:
  token_budget: {}
  timeout_ms: {}
"#, self.name, description, tools_yaml, namespaces_yaml, max_tokens, timeout);

        // Add flow
        if !self.memory_namespaces.is_empty() {
            yaml.push_str(&format!(r#"
flow:
  - id: retrieve
    type: memory_search
    namespace: "{}"
    query: "{{{{input}}}}"
    top_k: 5
    output: context

  - id: generate
    type: llm_call
    model: "{}"
    system: "{}"
    input: |
      Context: {{{{context}}}}
      Query: {{{{input}}}}
    output: output
"#, self.memory_namespaces[0], model, system));
        } else if !self.tools.is_empty() {
            yaml.push_str(&format!(r#"
flow:
  - id: process
    type: llm_call
    model: "{}"
    system: "{}"
    input: "{{{{input}}}}"
    tools: {}
    output: output
"#, model, system, tools_yaml));
        } else {
            yaml.push_str(&format!(r#"
flow:
  - id: process
    type: llm_call
    model: "{}"
    system: "{}"
    input: "{{{{input}}}}"
    output: output
"#, model, system));
        }

        // Add approval gate if required
        if self.require_approval && !self.approvers.is_empty() {
            let approvers_yaml = format!("[{}]", self.approvers.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(", "));
            yaml.push_str(&format!(r#"
  - id: approval
    type: approval_gate
    approvers: {}
    summary: "{{{{output}}}}"
    output: approval_result
"#, approvers_yaml));
        }

        yaml
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_library_creation() {
        let lib = TemplateLibrary::new();
        assert!(lib.list().len() >= 6);
    }

    #[test]
    fn test_template_instantiation() {
        let lib = TemplateLibrary::new();
        let params = HashMap::from([
            ("agent_name".to_string(), serde_json::json!("test-bot")),
            ("system_prompt".to_string(), serde_json::json!("You are helpful.")),
        ]);
        let result = lib.instantiate(&TemplateId::SimpleQa, params);
        assert!(result.ok);
        assert!(result.contract_yaml.is_some());
    }

    #[test]
    fn test_simple_contract_generation() {
        let def = SimpleContractDef {
            name: "my-agent".to_string(),
            description: Some("Test agent".to_string()),
            system_prompt: Some("Be helpful".to_string()),
            model: Some("gpt-4".to_string()),
            tools: vec![],
            memory_namespaces: vec![],
            max_tokens: Some(1000),
            timeout_ms: Some(30000),
            require_approval: false,
            approvers: vec![],
        };
        let yaml = def.to_cls_yaml();
        assert!(yaml.contains("my-agent"));
        assert!(yaml.contains("Be helpful"));
    }
}
