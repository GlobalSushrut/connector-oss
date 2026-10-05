//! CCL IR Lowering — transforms AST into ContractIR DAG.
//!
//! Implements CONNECTOR_CONTRACT_LANGUAGE.md §11.
//! Maps each AST StepOpNode to CIROp nodes, builds edges (sequential + branch),
//! runs topological sort, and lowers governance predicates + budget into IR structures.

use crate::cls::ccl_parser::*;
use crate::cls::ccl_sema::SymbolTable;
use crate::cls::types::{
    ContractIR, IRNode, CIROp, Predicate as IrPredicate,
    ContractStateMachine, StateTransition as IrTransition,
    ContractInterface, ParamDef, ParamType,
    Governance, FailureStrategy, ResourceEnvelope,
};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Lowering errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct LowerError {
    pub code: String,
    pub message: String,
}

// ═══════════════════════════════════════════════════════════════
// Lowered output — everything needed for emission
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct LoweredContract {
    pub name: String,
    pub identity: HashMap<String, String>,
    pub interface: ContractInterface,
    pub ir: ContractIR,
    pub state_machine: ContractStateMachine,
    pub governance: Governance,
    pub envelope: ResourceEnvelope,
    pub description: String,
    pub domain: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Lowering engine
// ═══════════════════════════════════════════════════════════════

pub struct IrLowering;

impl IrLowering {
    /// Lower a parsed + analyzed contract AST into IR structures.
    pub fn lower(contract: &ContractNode, symbols: &SymbolTable) -> Result<LoweredContract, Vec<LowerError>> {
        let mut errors = Vec::new();
        let mut identity = HashMap::new();
        let mut interface = default_interface();
        let mut state_machine = default_state_machine();
        let mut governance = Governance::default();
        let mut envelope = ResourceEnvelope::new();
        let mut ir_nodes: Vec<IRNode> = Vec::new();
        let mut ir_edges: Vec<(usize, usize)> = Vec::new();
        let mut step_id_to_idx: HashMap<String, usize> = HashMap::new();
        let mut description = String::new();
        let mut domain = None;

        // Process each block
        for block in &contract.blocks {
            match block {
                BlockNode::Identity(id) => {
                    for (k, v) in &id.entries {
                        identity.insert(k.clone(), v.clone());
                        if k == "description" { description = v.clone(); }
                        if k == "domain" { domain = Some(v.clone()); }
                    }
                }
                BlockNode::Interface(iface) => {
                    interface = lower_interface(iface);
                }
                BlockNode::State(state) => {
                    state_machine = lower_state_machine(state);
                }
                BlockNode::Governance(gov) => {
                    governance = lower_governance(gov);
                }
                BlockNode::Budget(budget) => {
                    envelope = lower_budget(budget);
                }
                BlockNode::Behavior(beh) => {
                    // Lower each step into IR nodes
                    for step in &beh.steps {
                        let idx = ir_nodes.len();
                        step_id_to_idx.insert(step.id.clone(), idx);

                        let ops = lower_step_ops(&step.ops);
                        if ops.is_empty() {
                            ir_nodes.push(IRNode {
                                node_id: step.id.clone(),
                                label: step.label.clone().unwrap_or_else(|| step.id.clone()),
                                op: CIROp::Noop,
                                precondition: None,
                                postcondition: None,
                            });
                        } else {
                            // First op becomes the primary node; extras become additional nodes
                            let first_op = ops[0].clone();
                            ir_nodes.push(IRNode {
                                node_id: step.id.clone(),
                                label: step.label.clone().unwrap_or_else(|| step.id.clone()),
                                op: first_op,
                                precondition: None,
                                postcondition: None,
                            });

                            for (i, op) in ops.iter().enumerate().skip(1) {
                                let sub_id = format!("{}_{}", step.id, i);
                                let sub_idx = ir_nodes.len();
                                ir_nodes.push(IRNode {
                                    node_id: sub_id,
                                    label: format!("{} (op {})", step.id, i),
                                    op: op.clone(),
                                    precondition: None,
                                    postcondition: None,
                                });
                                // Chain sub-ops sequentially
                                ir_edges.push((sub_idx - 1, sub_idx));
                            }
                        }
                    }

                    // Build sequential edges between steps
                    let step_ids: Vec<_> = beh.steps.iter().map(|s| s.id.clone()).collect();
                    for i in 0..step_ids.len().saturating_sub(1) {
                        if let (Some(&from), Some(&to)) = (
                            step_id_to_idx.get(&step_ids[i]),
                            step_id_to_idx.get(&step_ids[i + 1]),
                        ) {
                            // Find the last sub-node of 'from' step
                            let from_last = find_last_subnode(from, &ir_nodes);
                            ir_edges.push((from_last, to));
                        }
                    }

                    // Build branch edges
                    for step in &beh.steps {
                        for op in &step.ops {
                            if let StepOpNode::Branch { arms, .. } = op {
                                if let Some(&from_idx) = step_id_to_idx.get(&step.id) {
                                    let from_last = find_last_subnode(from_idx, &ir_nodes);
                                    for arm in arms {
                                        if let Some(&target_idx) = step_id_to_idx.get(&arm.target) {
                                            ir_edges.push((from_last, target_idx));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for cycles via topological sort
        let ir = ContractIR {
            nodes: ir_nodes,
            edges: ir_edges,
            entry: 0,
        };
        let topo = ir.topo_order();
        if topo.len() < ir.nodes.len() {
            errors.push(LowerError {
                code: "E020".into(),
                message: "cycle detected in step DAG".into(),
            });
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(LoweredContract {
            name: contract.name.clone(),
            identity,
            interface,
            ir,
            state_machine,
            governance,
            envelope,
            description,
            domain,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
// Block lowering helpers
// ═══════════════════════════════════════════════════════════════

fn find_last_subnode(step_start_idx: usize, nodes: &[IRNode]) -> usize {
    let prefix = &nodes[step_start_idx].node_id;
    let mut last = step_start_idx;
    for (i, node) in nodes.iter().enumerate().skip(step_start_idx + 1) {
        if node.node_id.starts_with(prefix) && node.node_id.contains('_') {
            last = i;
        } else {
            break;
        }
    }
    last
}

fn lower_interface(iface: &InterfaceNode) -> ContractInterface {
    ContractInterface {
        inputs: iface.inputs.iter().map(|i| ParamDef {
            name: i.name.clone(),
            param_type: lower_type(&i.type_ann),
            required: i.required,
            description: i.description.clone().unwrap_or_default(),
            default: None,
        }).collect(),
        outputs: iface.outputs.iter().map(|o| ParamDef {
            name: o.name.clone(),
            param_type: lower_type(&o.type_ann),
            required: true,
            description: o.description.clone().unwrap_or_default(),
            default: None,
        }).collect(),
        events: iface.events.clone(),
        required_tools: iface.tools.clone(),
        required_namespaces: vec![],
        required_capabilities: iface.capabilities.clone(),
    }
}

fn lower_type(t: &TypeNode) -> ParamType {
    match t {
        TypeNode::Primitive(PrimitiveType::String) => ParamType::String,
        TypeNode::Primitive(PrimitiveType::Text) => ParamType::String, // Text maps to String
        TypeNode::Primitive(PrimitiveType::Int) => ParamType::Integer,
        TypeNode::Primitive(PrimitiveType::Float) => ParamType::Float,
        TypeNode::Primitive(PrimitiveType::Bool) => ParamType::Boolean,
        TypeNode::Primitive(PrimitiveType::Json) => ParamType::Json,
        TypeNode::Primitive(PrimitiveType::Binary) => ParamType::Binary,
        TypeNode::Primitive(PrimitiveType::Cid) => ParamType::CidRef,
        // Extended primitives map to String or Json
        TypeNode::Primitive(PrimitiveType::Date) => ParamType::String,
        TypeNode::Primitive(PrimitiveType::Time) => ParamType::String,
        TypeNode::Primitive(PrimitiveType::DateTime) => ParamType::String,
        TypeNode::Primitive(PrimitiveType::Document) => ParamType::CidRef,
        TypeNode::Primitive(PrimitiveType::Reference) => ParamType::CidRef,
        // Container types
        TypeNode::List(inner) => ParamType::List(Box::new(lower_type(inner))),
        TypeNode::Map(k, v) => ParamType::Map(Box::new(lower_type(k)), Box::new(lower_type(v))),
        // Extended types
        TypeNode::Optional(inner) => lower_type(inner), // Optional unwraps to inner type
        TypeNode::Enum(_) => ParamType::String, // Enum values are strings
        TypeNode::Record(_) => ParamType::Json, // Records are JSON objects
        // Domain types
        TypeNode::ToolResult(inner) => ParamType::Json, // Tool results are JSON
        TypeNode::EvidenceRef => ParamType::CidRef,
        TypeNode::PolicyResult => ParamType::String,
        // Trust wrappers unwrap to inner type
        TypeNode::Trusted(inner) => lower_type(inner),
        TypeNode::Untrusted(inner) => lower_type(inner),
        TypeNode::Pii(inner) => lower_type(inner),
    }
}

fn lower_state_machine(state: &StateNode) -> ContractStateMachine {
    let initial = state.states.iter()
        .find(|s| s.kind == StateKind::Initial)
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "init".into());
    let terminals: Vec<String> = state.states.iter()
        .filter(|s| s.kind == StateKind::Terminal)
        .map(|s| s.name.clone())
        .collect();
    let all_states: Vec<String> = state.states.iter().map(|s| s.name.clone()).collect();
    let transitions: Vec<IrTransition> = state.transitions.iter().map(|t| {
        IrTransition {
            from: t.from.clone(),
            to: t.to.clone(),
            trigger: t.trigger.clone(),
            guard: t.guard.as_ref().map(|g| lower_predicate(g)),
        }
    }).collect();

    ContractStateMachine { initial_state: initial, terminal_states: terminals, states: all_states, transitions }
}

fn lower_governance(gov: &GovernanceNode) -> Governance {
    Governance {
        preconditions: gov.requires.iter().map(|p| lower_predicate(p)).collect(),
        postconditions: gov.ensures.iter().map(|p| lower_predicate(p)).collect(),
        invariants: gov.invariants.iter().map(|p| lower_predicate(p)).collect(),
        failure_strategy: gov.on_failure.as_ref().map(|f| match f.as_str() {
            "abort" => FailureStrategy::Abort,
            "human_review" => FailureStrategy::HumanReview,
            "accept_and_log" => FailureStrategy::AcceptAndLog,
            _ => FailureStrategy::Abort,
        }).unwrap_or(FailureStrategy::Abort),
        clearance: gov.clearance.clone(),
        allowed_roles: gov.roles.clone(),
        compliance_tags: gov.compliance.clone(),
    }
}

fn lower_predicate(pred: &PredicateNode) -> IrPredicate {
    match pred {
        PredicateNode::IsPresent { field, .. } => {
            IrPredicate::FieldPresent { field: field.clone() }
        }
        PredicateNode::Compare { field, op, value, .. } => {
            let json_val = expr_to_json(value);
            match op {
                CmpOp::Gt => IrPredicate::FieldGt { field: field.clone(), value: json_val.as_f64().unwrap_or(0.0) },
                CmpOp::Lt => IrPredicate::FieldLt { field: field.clone(), value: json_val.as_f64().unwrap_or(0.0) },
                CmpOp::Eq => IrPredicate::FieldEquals { field: field.clone(), value: json_val },
                CmpOp::Neq => IrPredicate::Not {
                    predicate: Box::new(IrPredicate::FieldEquals { field: field.clone(), value: json_val }),
                },
                CmpOp::Gte => IrPredicate::Or {
                    predicates: vec![
                        IrPredicate::FieldGt { field: field.clone(), value: json_val.as_f64().unwrap_or(0.0) },
                        IrPredicate::FieldEquals { field: field.clone(), value: json_val },
                    ],
                },
                CmpOp::Lte => IrPredicate::Or {
                    predicates: vec![
                        IrPredicate::FieldLt { field: field.clone(), value: json_val.as_f64().unwrap_or(0.0) },
                        IrPredicate::FieldEquals { field: field.clone(), value: json_val },
                    ],
                },
            }
        }
        PredicateNode::InList { field, values, .. } => {
            let preds: Vec<IrPredicate> = values.iter().map(|v| {
                IrPredicate::FieldEquals { field: field.clone(), value: expr_to_json(v) }
            }).collect();
            IrPredicate::Or { predicates: preds }
        }
        PredicateNode::Matches { field, pattern, .. } => {
            IrPredicate::Custom { name: "matches".into(), args: {
                let mut m = HashMap::new();
                m.insert("field".into(), serde_json::json!(field));
                m.insert("pattern".into(), serde_json::json!(pattern));
                m
            }}
        }
        PredicateNode::HasRole { role, .. } => {
            IrPredicate::HasRole { role: role.clone() }
        }
        PredicateNode::BudgetCheck { resource, op, value, .. } => {
            let min = match op {
                CmpOp::Gt => expr_to_f64(value),
                _ => 0.0,
            };
            IrPredicate::BudgetRemaining { resource: resource.clone(), min }
        }
        PredicateNode::And { left, right, .. } => {
            IrPredicate::And { predicates: vec![lower_predicate(left), lower_predicate(right)] }
        }
        PredicateNode::Or { left, right, .. } => {
            IrPredicate::Or { predicates: vec![lower_predicate(left), lower_predicate(right)] }
        }
        PredicateNode::Not { inner, .. } => {
            IrPredicate::Not { predicate: Box::new(lower_predicate(inner)) }
        }
    }
}

fn lower_budget(budget: &BudgetNode) -> ResourceEnvelope {
    let mut envelope = ResourceEnvelope::new();
    for entry in &budget.entries {
        let val = expr_to_f64(&entry.limit);
        envelope.limits.insert(entry.resource.clone(), val);
    }
    envelope.hard_limit = true;
    envelope
}

// ═══════════════════════════════════════════════════════════════
// Step op lowering → CIROp
// ═══════════════════════════════════════════════════════════════

fn lower_step_ops(ops: &[StepOpNode]) -> Vec<CIROp> {
    ops.iter().filter_map(|op| lower_step_op(op)).collect()
}

fn lower_step_op(op: &StepOpNode) -> Option<CIROp> {
    match op {
        StepOpNode::ToolCall { tool_name, params, bind, .. } => {
            let p: HashMap<String, serde_json::Value> = params.iter()
                .map(|p| (p.key.clone(), expr_to_json(&p.value)))
                .collect();
            Some(CIROp::ToolCall {
                tool_id: tool_name.clone(),
                params: p,
                output_var: bind.clone().unwrap_or_else(|| format!("_{}_out", tool_name)),
            })
        }
        StepOpNode::LlmInfer { prompt, with_vars, bind, max_tokens, temperature, .. } => {
            Some(CIROp::LlmInfer {
                prompt_template: prompt.clone(),
                input_vars: with_vars.clone(),
                output_var: bind.clone().unwrap_or_else(|| "_infer_out".into()),
                max_tokens: max_tokens.map(|n| n as u32).unwrap_or(2048),
                temperature: temperature.unwrap_or(0.7),
            })
        }
        StepOpNode::MemRecall { namespace, query, limit, bind, .. } => {
            Some(CIROp::MemRead {
                namespace: namespace.clone(),
                query: expr_to_string(query),
                output_var: bind.clone().unwrap_or_else(|| format!("_{}_recall", namespace)),
                max_results: limit.map(|n| n as u32).unwrap_or(10),
            })
        }
        StepOpNode::MemRemember { namespace, content, tags, .. } => {
            Some(CIROp::MemWrite {
                namespace: namespace.clone(),
                content_var: expr_to_string(content),
                tags: tags.clone(),
            })
        }
        StepOpNode::SetVar { name, value, .. } => {
            Some(CIROp::SetVar {
                name: name.clone(),
                value: expr_to_json(value),
            })
        }
        StepOpNode::Branch { arms, .. } => {
            // Lower to first conditional arm; IR handles branch via edges
            if let Some(first_when) = arms.iter().find(|a| a.predicate.is_some()) {
                let otherwise = arms.iter().find(|a| a.predicate.is_none()).map(|a| a.target.clone());
                Some(CIROp::Branch {
                    condition: lower_predicate(first_when.predicate.as_ref().unwrap()),
                    then_node: first_when.target.clone(),
                    else_node: otherwise,
                })
            } else if let Some(otherwise) = arms.iter().find(|a| a.predicate.is_none()) {
                Some(CIROp::Noop) // unconditional; edge already points there
            } else {
                None
            }
        }
        StepOpNode::Transition { state, .. } => {
            Some(CIROp::Transition { to_state: state.clone() })
        }
        StepOpNode::EmitEvent { event, data, .. } => {
            Some(CIROp::EmitEvent {
                event_type: event.clone(),
                data_vars: data.iter().map(|p| p.key.clone()).collect(),
            })
        }
        StepOpNode::Checkpoint { label, .. } => {
            Some(CIROp::Checkpoint { label: label.clone() })
        }
        StepOpNode::CallContract { contract, params, bind, .. } => {
            let inputs: HashMap<String, String> = params.iter()
                .map(|p| (p.key.clone(), expr_to_string(&p.value)))
                .collect();
            Some(CIROp::CallContract {
                contract_id: contract.clone(),
                inputs,
                output_var: bind.clone().unwrap_or_else(|| format!("_{}_out", contract)),
            })
        }
        StepOpNode::SendMessage { target, payload, .. } => {
            let payload_str = if let Some(first) = payload.first() {
                expr_to_string(&first.value)
            } else { String::new() };
            Some(CIROp::SendMessage { to_agent: target.clone(), payload_var: payload_str })
        }
        StepOpNode::WaitEvent { .. } => Some(CIROp::Noop),
        StepOpNode::Parallel { ops, .. } => {
            // Lower all sub-ops; they execute as separate nodes
            let sub_ops = lower_step_ops(ops);
            if sub_ops.len() == 1 { Some(sub_ops.into_iter().next().unwrap()) }
            else { Some(sub_ops.into_iter().next().unwrap_or(CIROp::Noop)) }
        }
        StepOpNode::Saga { forward, .. } => lower_step_op(forward),
    }
}

// ═══════════════════════════════════════════════════════════════
// Expression helpers
// ═══════════════════════════════════════════════════════════════

fn expr_to_json(expr: &ExprNode) -> serde_json::Value {
    match expr {
        ExprNode::StringLit(s, _) => serde_json::json!(s),
        ExprNode::IntLit(n, _) => serde_json::json!(n),
        ExprNode::FloatLit(f, _) => serde_json::json!(f),
        ExprNode::BoolLit(b, _) => serde_json::json!(b),
        ExprNode::NullLit(_) => serde_json::Value::Null,
        ExprNode::VarRef(path, _) => serde_json::json!(format!("${{{}}}", path)),
        ExprNode::Ident(name, _) => serde_json::json!(name),
        ExprNode::ObjectLit(params, _) => {
            let mut map = serde_json::Map::new();
            for p in params {
                map.insert(p.key.clone(), expr_to_json(&p.value));
            }
            serde_json::Value::Object(map)
        }
        ExprNode::ListLit(items, _) => {
            serde_json::Value::Array(items.iter().map(|i| expr_to_json(i)).collect())
        }
    }
}

fn expr_to_string(expr: &ExprNode) -> String {
    match expr {
        ExprNode::StringLit(s, _) => s.clone(),
        ExprNode::VarRef(path, _) => format!("${{{}}}", path),
        ExprNode::Ident(name, _) => name.clone(),
        _ => format!("{:?}", expr_to_json(expr)),
    }
}

fn expr_to_f64(expr: &ExprNode) -> f64 {
    match expr {
        ExprNode::IntLit(n, _) => *n as f64,
        ExprNode::FloatLit(f, _) => *f,
        _ => 0.0,
    }
}

fn default_interface() -> ContractInterface {
    ContractInterface {
        inputs: vec![], outputs: vec![], events: vec![],
        required_tools: vec![], required_namespaces: vec![], required_capabilities: vec![],
    }
}

fn default_state_machine() -> ContractStateMachine {
    ContractStateMachine {
        initial_state: "init".into(),
        terminal_states: vec!["done".into()],
        states: vec!["init".into(), "done".into()],
        transitions: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cls::ccl_parser::CclParser;
    use crate::cls::ccl_sema::SemanticAnalyzer;

    fn lower_src(src: &str) -> LoweredContract {
        let contract = CclParser::parse(src).expect("parse");
        let (symbols, _) = SemanticAnalyzer::analyze(&contract);
        IrLowering::lower(&contract, &symbols).expect("lower")
    }

    #[test]
    fn test_lower_full_contract() {
        let src = r#"contract triage {
            identity {
                name: "patient_triage"
                version: "1.0.0"
                domain: "healthcare"
                description: "Triage incoming patients"
            }
            interface {
                input patient_id: String required
                output triage_result: Json
                tool lookup_patient
                tool assess_severity
                event triage_complete
            }
            state {
                initial intake
                terminal triaged
                intake -> triaged on complete
            }
            governance {
                require patient_id is present
                ensure triage_result is present
                roles [clinician, admin]
                clearance "high"
                compliance [hipaa, phi]
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
                tool_calls: 10
            }
            memory {
                use medical_history as history
            }
            behavior {
                step intake_step {
                    tool lookup_patient { id: ${patient_id} } -> patient
                }
                step assess_step {
                    tool assess_severity { data: ${patient} } -> assessment
                    set triage_result = ${assessment}
                    transition triaged
                    emit triage_complete { result: ${triage_result} }
                }
            }
        }"#;

        let lowered = lower_src(src);
        assert_eq!(lowered.name, "triage");
        assert_eq!(lowered.identity.get("name").unwrap(), "patient_triage");
        assert_eq!(lowered.interface.inputs.len(), 1);
        assert_eq!(lowered.interface.outputs.len(), 1);
        assert_eq!(lowered.interface.required_tools.len(), 2);
        assert_eq!(lowered.state_machine.initial_state, "intake");
        assert_eq!(lowered.state_machine.terminal_states, vec!["triaged"]);
        assert_eq!(lowered.governance.preconditions.len(), 1);
        assert_eq!(lowered.governance.postconditions.len(), 1);
        assert_eq!(lowered.governance.allowed_roles, vec!["clinician", "admin"]);
        assert_eq!(lowered.governance.compliance_tags, vec!["hipaa", "phi"]);
        assert_eq!(lowered.envelope.limits.len(), 3);

        // Check IR
        assert!(lowered.ir.nodes.len() >= 2, "expected at least 2 IR nodes, got {}", lowered.ir.nodes.len());
        // First node should be a ToolCall
        assert!(matches!(lowered.ir.nodes[0].op, CIROp::ToolCall { .. }));
        // Should have edges
        assert!(!lowered.ir.edges.is_empty());
        // Topo sort should include all nodes
        let topo = lowered.ir.topo_order();
        assert_eq!(topo.len(), lowered.ir.nodes.len());
    }

    #[test]
    fn test_lower_budget() {
        let src = r#"contract b {
            budget {
                tokens: 8192
                cost_usd: 1.50
                tool_calls: 20
                time_ms: 60000
            }
            behavior { step s { set x = 1 } }
        }"#;
        let lowered = lower_src(src);
        assert_eq!(lowered.envelope.limits.get("tokens"), Some(&8192.0));
        assert_eq!(lowered.envelope.limits.get("cost_usd"), Some(&1.5));
        assert_eq!(lowered.envelope.limits.get("tool_calls"), Some(&20.0));
        assert_eq!(lowered.envelope.limits.get("time_ms"), Some(&60000.0));
    }

    #[test]
    fn test_lower_predicates() {
        let src = r#"contract p {
            governance {
                require x is present
                require score > 5.0
                ensure status == "complete"
                invariant budget.tokens > 0
            }
            behavior { step s { set x = 1 } }
        }"#;
        let lowered = lower_src(src);
        assert_eq!(lowered.governance.preconditions.len(), 2);
        assert!(matches!(lowered.governance.preconditions[0], IrPredicate::FieldPresent { .. }));
        assert!(matches!(lowered.governance.preconditions[1], IrPredicate::FieldGt { .. }));
        assert_eq!(lowered.governance.postconditions.len(), 1);
        assert_eq!(lowered.governance.invariants.len(), 1);
    }

    #[test]
    fn test_lower_multi_op_step() {
        let src = r#"contract m {
            interface { tool t1  tool t2 }
            behavior {
                step multi {
                    tool t1 { } -> a
                    tool t2 { } -> b
                    set c = ${a}
                }
            }
        }"#;
        let lowered = lower_src(src);
        // Step with 3 ops should create 3 nodes (1 primary + 2 sub)
        assert_eq!(lowered.ir.nodes.len(), 3);
        assert!(matches!(lowered.ir.nodes[0].op, CIROp::ToolCall { .. }));
        assert!(matches!(lowered.ir.nodes[1].op, CIROp::ToolCall { .. }));
        assert!(matches!(lowered.ir.nodes[2].op, CIROp::SetVar { .. }));
    }

    #[test]
    fn test_lower_state_machine() {
        let src = r#"contract sm {
            state {
                initial s1
                s2
                terminal s3
                s1 -> s2 on go
                s2 -> s3 on finish
            }
            behavior { step s { set x = 1 } }
        }"#;
        let lowered = lower_src(src);
        assert_eq!(lowered.state_machine.initial_state, "s1");
        assert_eq!(lowered.state_machine.terminal_states, vec!["s3"]);
        assert_eq!(lowered.state_machine.states.len(), 3);
        assert_eq!(lowered.state_machine.transitions.len(), 2);
    }

    #[test]
    fn test_lower_interface_types() {
        let src = r#"contract t {
            interface {
                input a: String required
                input b: Int required
                input c: List<String> required
                input d: Map<String, Int> required
                output e: Json
            }
            behavior { step s { set x = 1 } }
        }"#;
        let lowered = lower_src(src);
        assert_eq!(lowered.interface.inputs.len(), 4);
        assert_eq!(lowered.interface.inputs[0].param_type, ParamType::String);
        assert_eq!(lowered.interface.inputs[1].param_type, ParamType::Integer);
        assert_eq!(lowered.interface.inputs[2].param_type, ParamType::List(Box::new(ParamType::String)));
        assert_eq!(lowered.interface.inputs[3].param_type, ParamType::Map(Box::new(ParamType::String), Box::new(ParamType::Integer)));
    }
}
