//! CCL Verification Pass — final checks before emission.
//!
//! Implements CONNECTOR_CONTRACT_LANGUAGE.md §13.
//! Produces hard errors (block compilation) and warnings (informational).
//! Runs after optimization on the lowered IR + structures.

use crate::cls::ccl_lower::LoweredContract;
use crate::cls::types::{ContractIR, CIROp, Predicate};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════
// Verification diagnostics
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyLevel {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct VerifyDiagnostic {
    pub level: VerifyLevel,
    pub code: String,
    pub message: String,
}

impl VerifyDiagnostic {
    fn error(code: &str, msg: impl Into<String>) -> Self {
        Self { level: VerifyLevel::Error, code: code.into(), message: msg.into() }
    }
    fn warning(code: &str, msg: impl Into<String>) -> Self {
        Self { level: VerifyLevel::Warning, code: code.into(), message: msg.into() }
    }
    pub fn is_error(&self) -> bool { self.level == VerifyLevel::Error }
}

// ═══════════════════════════════════════════════════════════════
// Verification result
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub diagnostics: Vec<VerifyDiagnostic>,
    pub passed: bool,
}

impl VerifyResult {
    pub fn errors(&self) -> Vec<&VerifyDiagnostic> {
        self.diagnostics.iter().filter(|d| d.is_error()).collect()
    }
    pub fn warnings(&self) -> Vec<&VerifyDiagnostic> {
        self.diagnostics.iter().filter(|d| !d.is_error()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Verifier
// ═══════════════════════════════════════════════════════════════

pub struct IrVerifier;

impl IrVerifier {
    /// Verify a lowered contract. Returns diagnostics and pass/fail.
    pub fn verify(contract: &LoweredContract) -> VerifyResult {
        let mut diags = Vec::new();

        Self::verify_state_machine(contract, &mut diags);
        Self::verify_ir_structure(&contract.ir, &mut diags);
        Self::verify_budget(contract, &mut diags);
        Self::verify_governance(contract, &mut diags);
        Self::verify_interface(contract, &mut diags);
        Self::verify_node_consistency(&contract.ir, contract, &mut diags);

        let passed = !diags.iter().any(|d| d.is_error());
        VerifyResult { diagnostics: diags, passed }
    }

    // ── State machine checks ────────────────────────────────────

    fn verify_state_machine(contract: &LoweredContract, diags: &mut Vec<VerifyDiagnostic>) {
        let sm = &contract.state_machine;

        // E001: no initial state
        if sm.states.is_empty() {
            return; // No state block — not an error at verify stage
        }

        if !sm.states.contains(&sm.initial_state) {
            diags.push(VerifyDiagnostic::error("E001",
                format!("initial state '{}' not found in states list", sm.initial_state)));
        }

        // E002: no terminal states
        if sm.terminal_states.is_empty() {
            diags.push(VerifyDiagnostic::error("E002", "no terminal states declared"));
        }

        // Terminal states must be in states list
        for ts in &sm.terminal_states {
            if !sm.states.contains(ts) {
                diags.push(VerifyDiagnostic::error("E002",
                    format!("terminal state '{}' not in states list", ts)));
            }
        }

        // E004: terminal states must not have outgoing transitions
        for t in &sm.transitions {
            if sm.terminal_states.contains(&t.from) {
                diags.push(VerifyDiagnostic::error("E004",
                    format!("terminal state '{}' has transition to '{}'", t.from, t.to)));
            }
        }

        // E003: all states reachable from initial
        let mut reachable = HashSet::new();
        let mut queue = vec![sm.initial_state.clone()];
        while let Some(state) = queue.pop() {
            if !reachable.insert(state.clone()) { continue; }
            for t in &sm.transitions {
                if t.from == state && !reachable.contains(&t.to) {
                    queue.push(t.to.clone());
                }
            }
        }
        for state in &sm.states {
            if !reachable.contains(state) {
                diags.push(VerifyDiagnostic::error("E003",
                    format!("state '{}' is unreachable from initial state '{}'", state, sm.initial_state)));
            }
        }
    }

    // ── IR structure checks ─────────────────────────────────────

    fn verify_ir_structure(ir: &ContractIR, diags: &mut Vec<VerifyDiagnostic>) {
        // IR001: must have at least one node
        if ir.nodes.is_empty() {
            diags.push(VerifyDiagnostic::error("IR001", "contract IR has no nodes"));
            return;
        }

        // IR002: entry must be valid
        if ir.entry >= ir.nodes.len() {
            diags.push(VerifyDiagnostic::error("IR002",
                format!("entry node index {} out of bounds (nodes: {})", ir.entry, ir.nodes.len())));
        }

        // E020: cycle detection via topo sort
        let topo = ir.topo_order();
        if topo.len() < ir.nodes.len() {
            diags.push(VerifyDiagnostic::error("E020",
                format!("cycle detected in IR DAG: topo sort covers {}/{} nodes", topo.len(), ir.nodes.len())));
        }

        // Edge bounds check
        for (i, &(from, to)) in ir.edges.iter().enumerate() {
            if from >= ir.nodes.len() || to >= ir.nodes.len() {
                diags.push(VerifyDiagnostic::error("IR003",
                    format!("edge {} references out-of-bounds node: ({}, {})", i, from, to)));
            }
        }

        // Duplicate node IDs
        let mut seen_ids = HashSet::new();
        for node in &ir.nodes {
            if !seen_ids.insert(&node.node_id) {
                diags.push(VerifyDiagnostic::warning("IR004",
                    format!("duplicate IR node ID '{}'", node.node_id)));
            }
        }
    }

    // ── Budget checks ───────────────────────────────────────────

    fn verify_budget(contract: &LoweredContract, diags: &mut Vec<VerifyDiagnostic>) {
        let env = &contract.envelope;

        // E030: budget must have at least one resource
        if env.limits.is_empty() {
            diags.push(VerifyDiagnostic::error("E030", "budget block must define at least one resource"));
        }

        // Check for zero or negative limits
        for (resource, limit) in &env.limits {
            if *limit <= 0.0 {
                diags.push(VerifyDiagnostic::error("E031",
                    format!("budget resource '{}' has non-positive limit: {}", resource, limit)));
            }
        }

        // W020: only one resource
        if env.limits.len() == 1 {
            diags.push(VerifyDiagnostic::warning("W020",
                format!("only '{}' is budgeted — consider adding cost_usd and time_ms",
                    env.limits.keys().next().unwrap())));
        }

        // W022: missing common resources
        if !env.limits.is_empty() {
            if !env.limits.contains_key("tokens") {
                diags.push(VerifyDiagnostic::warning("W022", "budget missing 'tokens' — LLM calls may be unbounded"));
            }
        }
    }

    // ── Governance checks ───────────────────────────────────────

    fn verify_governance(contract: &LoweredContract, diags: &mut Vec<VerifyDiagnostic>) {
        let gov = &contract.governance;

        if gov.preconditions.is_empty() {
            diags.push(VerifyDiagnostic::warning("W010", "contract has no preconditions"));
        }

        if gov.postconditions.is_empty() {
            diags.push(VerifyDiagnostic::warning("W011", "contract has no postconditions"));
        }

        if gov.invariants.is_empty() && !gov.preconditions.is_empty() {
            diags.push(VerifyDiagnostic::warning("W012",
                "contract has preconditions but no invariants — consider adding runtime invariants"));
        }
    }

    // ── Interface checks ────────────────────────────────────────

    fn verify_interface(contract: &LoweredContract, diags: &mut Vec<VerifyDiagnostic>) {
        let iface = &contract.interface;

        // Check all required inputs have descriptions
        for input in &iface.inputs {
            if input.required && input.description.is_empty() {
                diags.push(VerifyDiagnostic::warning("W030",
                    format!("required input '{}' has no description", input.name)));
            }
        }
    }

    // ── Node consistency checks ─────────────────────────────────

    fn verify_node_consistency(ir: &ContractIR, contract: &LoweredContract, diags: &mut Vec<VerifyDiagnostic>) {
        let declared_tools: HashSet<&str> = contract.interface.required_tools.iter()
            .map(|s| s.as_str()).collect();

        for node in &ir.nodes {
            match &node.op {
                CIROp::ToolCall { tool_id, .. } => {
                    if !declared_tools.contains(tool_id.as_str()) {
                        diags.push(VerifyDiagnostic::error("E011",
                            format!("IR node '{}' calls tool '{}' not in interface", node.node_id, tool_id)));
                    }
                }
                CIROp::Transition { to_state } => {
                    if !contract.state_machine.states.contains(to_state) {
                        diags.push(VerifyDiagnostic::error("E013_ST",
                            format!("IR node '{}' transitions to undeclared state '{}'", node.node_id, to_state)));
                    }
                }
                CIROp::EmitEvent { event_type, .. } => {
                    if !contract.interface.events.contains(event_type) {
                        diags.push(VerifyDiagnostic::error("E013",
                            format!("IR node '{}' emits undeclared event '{}'", node.node_id, event_type)));
                    }
                }
                CIROp::Branch { then_node, else_node, .. } => {
                    // Check branch targets exist as node IDs
                    let node_ids: HashSet<&str> = ir.nodes.iter().map(|n| n.node_id.as_str()).collect();
                    if !node_ids.contains(then_node.as_str()) {
                        diags.push(VerifyDiagnostic::warning("W040",
                            format!("branch in '{}' targets '{}' which is not an IR node ID", node.node_id, then_node)));
                    }
                    if let Some(else_n) = else_node {
                        if !node_ids.contains(else_n.as_str()) {
                            diags.push(VerifyDiagnostic::warning("W040",
                                format!("branch in '{}' else targets '{}' which is not an IR node ID", node.node_id, else_n)));
                        }
                    }
                }
                _ => {}
            }
        }
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
    use crate::cls::ccl_lower::IrLowering;

    fn verify_src(src: &str) -> VerifyResult {
        let contract = CclParser::parse(src).expect("parse");
        let (symbols, _) = SemanticAnalyzer::analyze(&contract);
        let lowered = IrLowering::lower(&contract, &symbols).expect("lower");
        IrVerifier::verify(&lowered)
    }

    #[test]
    fn test_valid_contract_passes() {
        let src = r#"contract valid {
            interface {
                input x: String required
                output y: Json
                tool my_tool
                event done
            }
            state {
                initial start
                terminal end
                start -> end on finish
            }
            governance {
                require x is present
                ensure y is present
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
            }
            behavior {
                step work {
                    tool my_tool { id: ${x} } -> result
                    set y = ${result}
                    transition end
                    emit done { data: ${y} }
                }
            }
        }"#;
        let result = verify_src(src);
        assert!(result.passed, "errors: {:?}", result.errors());
    }

    #[test]
    fn test_empty_budget_fails() {
        let src = r#"contract bad {
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(result.diagnostics.iter().any(|d| d.code == "E030"), "expected E030: {:?}", result.diagnostics);
    }

    #[test]
    fn test_zero_budget_fails() {
        let src = r#"contract bad {
            budget { tokens: 0 }
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(result.diagnostics.iter().any(|d| d.code == "E031"), "expected E031: {:?}", result.diagnostics);
    }

    #[test]
    fn test_no_preconditions_warning() {
        let src = r#"contract w {
            budget { tokens: 100 cost_usd: 1.0 }
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(result.warnings().iter().any(|d| d.code == "W010"));
    }

    #[test]
    fn test_unreachable_state_error() {
        let src = r#"contract bad {
            state {
                initial s1
                terminal s2
                orphan
                s1 -> s2 on go
            }
            budget { tokens: 100 cost_usd: 1.0 }
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(result.diagnostics.iter().any(|d| d.code == "E003"), "expected E003: {:?}", result.diagnostics);
    }

    #[test]
    fn test_terminal_with_outgoing_error() {
        let src = r#"contract bad {
            state {
                initial s1
                terminal s2
                s1 -> s2 on go
                s2 -> s1 on back
            }
            budget { tokens: 100 cost_usd: 1.0 }
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(result.diagnostics.iter().any(|d| d.code == "E004"), "expected E004: {:?}", result.diagnostics);
    }

    #[test]
    fn test_ir_has_nodes() {
        let src = r#"contract ok {
            budget { tokens: 100 cost_usd: 1.0 }
            behavior { step s { set x = 1 } }
        }"#;
        let result = verify_src(src);
        assert!(!result.diagnostics.iter().any(|d| d.code == "IR001"));
    }
}
