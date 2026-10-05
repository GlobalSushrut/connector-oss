//! CLS Compiler — compiles YAML contract definitions into SolutionContract.
//!
//! Pipeline: YAML string → SurfaceIR (serde) → ContractIR (lowered) → SolutionContract (signed)
//!
//! The compiler performs:
//!   Pass 1: Parse — YAML → SurfaceIR (raw deserialized form)
//!   Pass 2: Desugar — expand shorthands, defaults
//!   Pass 3: Lower — SurfaceIR → ContractIR (build DAG)
//!   Pass 4: Verify — validate contract structure
//!   Pass 5: Emit — produce signed SolutionContract

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use crate::cls::types::*;

// ═══════════════════════════════════════════════════════════════
// Surface IR — the YAML-deserialized form
// ═══════════════════════════════════════════════════════════════

/// What the YAML contract file deserializes into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceContract {
    /// Contract metadata
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub domain: Option<String>,

    /// Interface
    #[serde(default)]
    pub inputs: Vec<SurfaceParam>,
    #[serde(default)]
    pub outputs: Vec<SurfaceParam>,

    /// Tools the contract uses
    #[serde(default)]
    pub tools: Vec<String>,

    /// Memory namespaces
    #[serde(default)]
    pub memory: Vec<String>,

    /// State machine
    pub states: SurfaceStates,

    /// Execution steps (ordered — compiled into DAG)
    pub steps: Vec<SurfaceStep>,

    /// Governance
    #[serde(default)]
    pub governance: SurfaceGovernance,

    /// Resource budget
    #[serde(default)]
    pub budget: SurfaceBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceParam {
    pub name: String,
    #[serde(rename = "type", default = "default_param_type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
}

fn default_param_type() -> String { "string".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceStates {
    pub initial: String,
    #[serde(default)]
    pub terminal: Vec<String>,
    pub transitions: Vec<SurfaceTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceTransition {
    pub from: String,
    pub to: String,
    pub trigger: String,
    #[serde(default)]
    pub guard: Option<SurfaceGuard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SurfaceGuard {
    Simple(String),
    Predicate(Predicate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceStep {
    pub id: String,
    #[serde(default)]
    pub label: String,
    /// Step type: tool_call | llm_infer | mem_read | mem_write | branch | set_var | emit_event | transition | checkpoint
    #[serde(rename = "type")]
    pub step_type: String,
    /// Step-specific parameters
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
    /// Precondition
    #[serde(default)]
    pub precondition: Option<Predicate>,
    /// Postcondition
    #[serde(default)]
    pub postcondition: Option<Predicate>,
    /// Next step(s) — if absent, proceed to next in list
    #[serde(default)]
    pub next: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceGovernance {
    #[serde(default)]
    pub preconditions: Vec<Predicate>,
    #[serde(default)]
    pub postconditions: Vec<Predicate>,
    #[serde(default)]
    pub invariants: Vec<Predicate>,
    #[serde(default = "default_failure_strategy")]
    pub failure_strategy: String,
    #[serde(default)]
    pub clearance: Option<String>,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    #[serde(default)]
    pub compliance_tags: Vec<String>,
}

fn default_failure_strategy() -> String { "abort".into() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceBudget {
    #[serde(default = "default_tokens")]
    pub tokens: f64,
    #[serde(default = "default_cost")]
    pub cost_usd: f64,
    #[serde(default = "default_tool_calls")]
    pub tool_calls: f64,
    #[serde(default = "default_time")]
    pub time_ms: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: f64,
}

fn default_tokens() -> f64 { 8192.0 }
fn default_cost() -> f64 { 1.0 }
fn default_tool_calls() -> f64 { 20.0 }
fn default_time() -> f64 { 60_000.0 }
fn default_memory() -> f64 { 128.0 }

// ═══════════════════════════════════════════════════════════════
// Compiler
// ═══════════════════════════════════════════════════════════════

/// CLS Compiler — transforms YAML → SolutionContract.
pub struct ClsCompiler;

impl ClsCompiler {
    /// Compile a YAML string into a SolutionContract.
    pub fn compile(yaml: &str) -> ClsResult<SolutionContract> {
        // Pass 1: Parse
        let surface = Self::parse(yaml)?;
        // Pass 2: Desugar (expand defaults)
        let surface = Self::desugar(surface);
        // Pass 3: Lower (SurfaceIR → ContractIR)
        let (ir, interface, sm) = Self::lower(&surface)?;
        // Pass 4: Verify
        let governance = Self::build_governance(&surface.governance);
        let envelope = Self::build_envelope(&surface.budget);
        // Pass 5: Emit
        let contract = Self::emit(surface, ir, interface, sm, governance, envelope)?;
        Ok(contract)
    }

    /// Pass 1: Parse YAML into SurfaceContract.
    fn parse(yaml: &str) -> ClsResult<SurfaceContract> {
        serde_yaml::from_str(yaml).map_err(|e| ClsError::CompilationError {
            detail: format!("YAML parse error: {}", e),
        })
    }

    /// Pass 2: Desugar — fill in defaults, expand shorthands.
    fn desugar(mut surface: SurfaceContract) -> SurfaceContract {
        // Ensure all steps have labels
        for step in &mut surface.steps {
            if step.label.is_empty() {
                step.label = step.id.clone();
            }
        }
        // Collect all states from transitions
        let mut states: Vec<String> = vec![surface.states.initial.clone()];
        states.extend(surface.states.terminal.clone());
        for t in &surface.states.transitions {
            if !states.contains(&t.from) { states.push(t.from.clone()); }
            if !states.contains(&t.to) { states.push(t.to.clone()); }
        }
        // We'll use these states in lowering
        surface
    }

    /// Pass 3: Lower — build ContractIR DAG from surface steps.
    fn lower(surface: &SurfaceContract) -> ClsResult<(ContractIR, ContractInterface, ContractStateMachine)> {
        // Build IR nodes from steps
        let mut nodes = Vec::new();
        let mut step_index: HashMap<String, usize> = HashMap::new();

        for (i, step) in surface.steps.iter().enumerate() {
            let op = Self::lower_step(step)?;
            nodes.push(IRNode {
                node_id: step.id.clone(),
                label: step.label.clone(),
                op,
                precondition: step.precondition.clone(),
                postcondition: step.postcondition.clone(),
            });
            step_index.insert(step.id.clone(), i);
        }

        // Build edges
        let mut edges = Vec::new();
        for (i, step) in surface.steps.iter().enumerate() {
            if let Some(next_ids) = &step.next {
                for next_id in next_ids {
                    if let Some(&target_idx) = step_index.get(next_id) {
                        edges.push((i, target_idx));
                    }
                }
            } else if i + 1 < surface.steps.len() {
                // Default: sequential flow to next step
                edges.push((i, i + 1));
            }
        }

        let ir = ContractIR { nodes, edges, entry: 0 };

        // Build interface
        let interface = ContractInterface {
            inputs: surface.inputs.iter().map(|p| ParamDef {
                name: p.name.clone(),
                param_type: Self::parse_param_type(&p.param_type),
                required: p.required,
                description: p.description.clone(),
                default: p.default.clone(),
            }).collect(),
            outputs: surface.outputs.iter().map(|p| ParamDef {
                name: p.name.clone(),
                param_type: Self::parse_param_type(&p.param_type),
                required: p.required,
                description: p.description.clone(),
                default: p.default.clone(),
            }).collect(),
            events: vec![],
            required_tools: surface.tools.clone(),
            required_namespaces: surface.memory.clone(),
            required_capabilities: vec![],
        };

        // Build state machine
        let mut all_states: Vec<String> = vec![surface.states.initial.clone()];
        all_states.extend(surface.states.terminal.clone());
        for t in &surface.states.transitions {
            if !all_states.contains(&t.from) { all_states.push(t.from.clone()); }
            if !all_states.contains(&t.to) { all_states.push(t.to.clone()); }
        }
        let sm = ContractStateMachine {
            initial_state: surface.states.initial.clone(),
            terminal_states: surface.states.terminal.clone(),
            states: all_states,
            transitions: surface.states.transitions.iter().map(|t| StateTransition {
                from: t.from.clone(),
                to: t.to.clone(),
                trigger: t.trigger.clone(),
                guard: t.guard.as_ref().map(|g| match g {
                    SurfaceGuard::Simple(s) => Predicate::Custom { name: s.clone(), args: HashMap::new() },
                    SurfaceGuard::Predicate(p) => p.clone(),
                }),
            }).collect(),
        };

        Ok((ir, interface, sm))
    }

    /// Lower a single surface step into a CIROp.
    fn lower_step(step: &SurfaceStep) -> ClsResult<CIROp> {
        match step.step_type.as_str() {
            "tool_call" => {
                let tool_id = get_str(&step.params, "tool").unwrap_or_default();
                let output_var = get_str(&step.params, "output").unwrap_or_else(|| format!("{}_result", step.id));
                let params = step.params.iter()
                    .filter(|(k, _)| !["tool", "output"].contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Ok(CIROp::ToolCall { tool_id, params, output_var })
            }
            "llm_infer" => {
                let prompt_template = get_str(&step.params, "prompt").unwrap_or_default();
                let output_var = get_str(&step.params, "output").unwrap_or_else(|| format!("{}_result", step.id));
                let input_vars = get_str_list(&step.params, "inputs");
                let max_tokens = get_u32(&step.params, "max_tokens").unwrap_or(1024);
                let temperature = get_f64(&step.params, "temperature").unwrap_or(0.7);
                Ok(CIROp::LlmInfer { prompt_template, input_vars, output_var, max_tokens, temperature })
            }
            "mem_read" => {
                let namespace = get_str(&step.params, "namespace").unwrap_or_default();
                let query = get_str(&step.params, "query").unwrap_or_default();
                let output_var = get_str(&step.params, "output").unwrap_or_else(|| format!("{}_result", step.id));
                let max_results = get_u32(&step.params, "max_results").unwrap_or(10);
                Ok(CIROp::MemRead { namespace, query, output_var, max_results })
            }
            "mem_write" => {
                let namespace = get_str(&step.params, "namespace").unwrap_or_default();
                let content_var = get_str(&step.params, "content").unwrap_or_default();
                let tags = get_str_list(&step.params, "tags");
                Ok(CIROp::MemWrite { namespace, content_var, tags })
            }
            "branch" => {
                let condition = step.precondition.clone().unwrap_or(Predicate::Always);
                let then_node = get_str(&step.params, "then").unwrap_or_default();
                let else_node = get_str_opt(&step.params, "else");
                Ok(CIROp::Branch { condition, then_node, else_node })
            }
            "set_var" => {
                let name = get_str(&step.params, "var").unwrap_or_default();
                let value = step.params.get("value").cloned().unwrap_or(serde_json::Value::Null);
                Ok(CIROp::SetVar { name, value })
            }
            "emit_event" => {
                let event_type = get_str(&step.params, "event").unwrap_or_default();
                let data_vars = get_str_list(&step.params, "data");
                Ok(CIROp::EmitEvent { event_type, data_vars })
            }
            "transition" => {
                let to_state = get_str(&step.params, "to").unwrap_or_default();
                Ok(CIROp::Transition { to_state })
            }
            "checkpoint" => {
                let label = get_str(&step.params, "label").unwrap_or_else(|| step.id.clone());
                Ok(CIROp::Checkpoint { label })
            }
            "send_message" => {
                let to_agent = get_str(&step.params, "to_agent").unwrap_or_default();
                let payload_var = get_str(&step.params, "payload").unwrap_or_default();
                Ok(CIROp::SendMessage { to_agent, payload_var })
            }
            other => Err(ClsError::CompilationError {
                detail: format!("Unknown step type: '{}'", other),
            }),
        }
    }

    fn build_governance(sg: &SurfaceGovernance) -> Governance {
        Governance {
            preconditions: sg.preconditions.clone(),
            postconditions: sg.postconditions.clone(),
            invariants: sg.invariants.clone(),
            failure_strategy: match sg.failure_strategy.as_str() {
                "retry" => FailureStrategy::Retry { max_retries: 3, backoff_ms: 1000 },
                "human_review" => FailureStrategy::HumanReview,
                "accept_and_log" => FailureStrategy::AcceptAndLog,
                _ => FailureStrategy::Abort,
            },
            clearance: sg.clearance.clone(),
            allowed_roles: sg.allowed_roles.clone(),
            compliance_tags: sg.compliance_tags.clone(),
        }
    }

    fn build_envelope(sb: &SurfaceBudget) -> ResourceEnvelope {
        ResourceEnvelope::new()
            .with_limit("tokens", sb.tokens)
            .with_limit("cost_usd", sb.cost_usd)
            .with_limit("tool_calls", sb.tool_calls)
            .with_limit("time_ms", sb.time_ms)
            .with_limit("memory_mb", sb.memory_mb)
    }

    /// Pass 5: Emit — build the final SolutionContract.
    fn emit(
        surface: SurfaceContract,
        ir: ContractIR,
        interface: ContractInterface,
        state_machine: ContractStateMachine,
        governance: Governance,
        resource_envelope: ResourceEnvelope,
    ) -> ClsResult<SolutionContract> {
        let compiled_at = now_ms();

        // Compute contract CID (includes name + version for uniqueness)
        let cid_input = serde_json::json!({
            "name": surface.name,
            "version": surface.version,
            "description": surface.description,
            "ir": ir,
        });
        let contract_bytes = serde_json::to_vec(&cid_input).unwrap_or_default();
        let cid = compute_cid(&contract_bytes);

        let version = Self::parse_version(&surface.version);

        let contract = SolutionContract {
            id: ContractId {
                cid,
                name: surface.name,
                version,
                author: surface.author,
            },
            interface,
            ir,
            state_machine,
            governance,
            resource_envelope,
            domain: surface.domain,
            description: surface.description,
            compiled_at,
            signature: None,
        };

        // Validate
        let errors = contract.validate();
        if !errors.is_empty() {
            return Err(ClsError::ValidationError {
                errors: errors.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect(),
            });
        }

        Ok(contract)
    }

    fn parse_version(v: &str) -> ContractVersion {
        let parts: Vec<u32> = v.split('.').filter_map(|s| s.parse().ok()).collect();
        ContractVersion {
            major: parts.first().copied().unwrap_or(1),
            minor: parts.get(1).copied().unwrap_or(0),
            patch: parts.get(2).copied().unwrap_or(0),
        }
    }

    fn parse_param_type(t: &str) -> ParamType {
        match t {
            "string" => ParamType::String,
            "integer" | "int" => ParamType::Integer,
            "float" | "number" => ParamType::Float,
            "boolean" | "bool" => ParamType::Boolean,
            "json" | "object" => ParamType::Json,
            "binary" | "bytes" => ParamType::Binary,
            "cid" => ParamType::CidRef,
            _ => ParamType::String,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn get_str(params: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    params.get(key).and_then(|v| v.as_str().map(|s| s.to_string()))
}

fn get_str_opt(params: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    get_str(params, key)
}

fn get_str_list(params: &HashMap<String, serde_json::Value>, key: &str) -> Vec<String> {
    params.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn get_u32(params: &HashMap<String, serde_json::Value>, key: &str) -> Option<u32> {
    params.get(key).and_then(|v| v.as_u64().map(|n| n as u32))
}

fn get_f64(params: &HashMap<String, serde_json::Value>, key: &str) -> Option<f64> {
    params.get(key).and_then(|v| v.as_f64())
}

fn compute_cid(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("cls1-sha256-{}", hex::encode(hash))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TRIAGE_YAML: &str = r#"
name: patient_triage
version: "1.0.0"
description: "Triage incoming patients by severity"
author: "connector-platform"
domain: medical

inputs:
  - name: patient_id
    type: string
    required: true
    description: "Patient identifier"
  - name: symptoms
    type: string
    required: true
    description: "Reported symptoms"

outputs:
  - name: triage_result
    type: json
    description: "Triage assessment result"
  - name: severity_score
    type: float
    description: "Severity score 0-10"

tools:
  - lookup_patient
  - assess_severity
  - assign_priority
  - notify_staff

memory:
  - patient_records
  - triage_history

states:
  initial: intake
  terminal:
    - triaged
    - escalated
    - failed
  transitions:
    - from: intake
      to: assessing
      trigger: start_assessment
    - from: assessing
      to: triaged
      trigger: assessment_complete
    - from: assessing
      to: escalated
      trigger: critical_detected
    - from: assessing
      to: failed
      trigger: error

steps:
  - id: lookup
    label: "Look up patient record"
    type: tool_call
    tool: lookup_patient
    patient_id: "${patient_id}"
    output: patient_record

  - id: transition_assessing
    label: "Move to assessing state"
    type: transition
    to: assessing

  - id: recall
    label: "Recall patient history"
    type: mem_read
    namespace: patient_records
    query: "${patient_id}"
    output: history
    max_results: 5

  - id: assess
    label: "LLM-based triage assessment"
    type: llm_infer
    prompt: "prompts/triage_reasoning.md"
    inputs: ["patient_record", "history", "symptoms"]
    output: assessment
    max_tokens: 2048
    temperature: 0.3

  - id: score
    label: "Compute severity score"
    type: tool_call
    tool: assess_severity
    assessment: "${assessment}"
    output: severity_score

  - id: check_critical
    label: "Check if critical"
    type: branch
    precondition:
      type: field_gt
      field: severity_score
      value: 8.0
    then: escalate
    else: assign

  - id: escalate
    label: "Escalate to emergency"
    type: tool_call
    tool: notify_staff
    priority: critical
    patient_id: "${patient_id}"
    output: escalation_result
    next: [transition_escalated]

  - id: assign
    label: "Assign normal priority"
    type: tool_call
    tool: assign_priority
    severity: "${severity_score}"
    patient_id: "${patient_id}"
    output: assignment_result
    next: [save_record]

  - id: transition_escalated
    label: "Move to escalated state"
    type: transition
    to: escalated
    next: [save_record]

  - id: save_record
    label: "Save triage record to memory"
    type: mem_write
    namespace: triage_history
    content: assessment
    tags: ["triage", "patient"]

  - id: emit_done
    label: "Emit triage complete event"
    type: emit_event
    event: triage_complete
    data: ["severity_score", "assessment"]

  - id: complete
    label: "Mark triaged"
    type: transition
    to: triaged

governance:
  allowed_roles:
    - medical_staff
    - triage_nurse
    - admin
  clearance: "medical"
  compliance_tags:
    - hipaa
    - phi
  failure_strategy: human_review

budget:
  tokens: 4096
  cost_usd: 0.50
  tool_calls: 10
  time_ms: 30000
  memory_mb: 64
"#;

    #[test]
    fn test_compile_triage_contract() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();

        assert_eq!(contract.id.name, "patient_triage");
        assert_eq!(contract.id.version, ContractVersion::new(1, 0, 0));
        assert_eq!(contract.domain.as_deref(), Some("medical"));
        assert_eq!(contract.description, "Triage incoming patients by severity");
    }

    #[test]
    fn test_compiled_interface() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        assert_eq!(contract.interface.inputs.len(), 2);
        assert_eq!(contract.interface.outputs.len(), 2);
        assert_eq!(contract.interface.required_tools.len(), 4);
        assert_eq!(contract.interface.required_namespaces.len(), 2);
    }

    #[test]
    fn test_compiled_state_machine() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let sm = &contract.state_machine;

        assert_eq!(sm.initial_state, "intake");
        assert!(sm.terminal_states.contains(&"triaged".to_string()));
        assert!(sm.terminal_states.contains(&"escalated".to_string()));
        assert!(sm.is_valid_transition("intake", "assessing"));
        assert!(sm.is_valid_transition("assessing", "triaged"));
        assert!(!sm.is_valid_transition("intake", "triaged"));
    }

    #[test]
    fn test_compiled_ir() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let ir = &contract.ir;

        // Should have all steps as nodes
        assert!(ir.nodes.len() >= 10);

        // Entry should be the first step
        assert_eq!(ir.entry, 0);
        assert_eq!(ir.nodes[0].node_id, "lookup");

        // Topo order should be valid
        let order = ir.topo_order();
        assert!(!order.is_empty());
    }

    #[test]
    fn test_compiled_governance() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        assert!(contract.governance.allowed_roles.contains(&"triage_nurse".to_string()));
        assert_eq!(contract.governance.clearance.as_deref(), Some("medical"));
        assert!(contract.governance.compliance_tags.contains(&"hipaa".to_string()));
        assert!(matches!(contract.governance.failure_strategy, FailureStrategy::HumanReview));
    }

    #[test]
    fn test_compiled_budget() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let limits = &contract.resource_envelope.limits;
        assert_eq!(limits.get("tokens"), Some(&4096.0));
        assert_eq!(limits.get("cost_usd"), Some(&0.50));
        assert_eq!(limits.get("tool_calls"), Some(&10.0));
    }

    #[test]
    fn test_contract_cid() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        assert!(contract.id.cid.starts_with("cls1-sha256-"));
    }

    #[test]
    fn test_contract_validates() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let errors = contract.validate();
        assert!(errors.is_empty(), "Validation errors: {:?}", errors.iter().map(|e| &e.message).collect::<Vec<_>>());
    }

    #[test]
    fn test_invalid_yaml() {
        let result = ClsCompiler::compile("not: valid: yaml: [[[");
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_step_type() {
        let yaml = r#"
name: test
version: "1.0.0"
description: "test"
states:
  initial: init
  terminal: [done]
  transitions:
    - from: init
      to: done
      trigger: go
steps:
  - id: bad
    type: unknown_type
"#;
        let result = ClsCompiler::compile(yaml);
        assert!(result.is_err());
    }
}
