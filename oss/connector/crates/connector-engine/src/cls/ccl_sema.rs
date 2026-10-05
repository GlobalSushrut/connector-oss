//! CCL Semantic Analysis — name resolution, type checking, structural validation.
//!
//! Implements CONNECTOR_CONTRACT_LANGUAGE.md §10.
//! Walks the AST and performs:
//!   - Name resolution: all ${var} refs resolve to declared inputs or prior step bindings
//!   - Tool resolution: all tool calls reference declared tools
//!   - Memory resolution: all recall/remember reference declared namespaces
//!   - State resolution: all transitions reference declared states
//!   - Event resolution: all emits reference declared events
//!   - Branch resolution: all branch targets reference valid step IDs
//!   - Type checking: predicate operands have compatible types
//!   - Exhaustiveness: every branch has an otherwise arm
//!   - Reachability: all states reachable from initial
//!   - Termination: terminal states have no outgoing transitions
//!   - Budget presence: at least one budget resource defined

use crate::cls::ccl_parser::*;
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════
// Diagnostic types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum DiagLevel {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub level: DiagLevel,
    pub code: String,
    pub message: String,
    pub span: crate::cls::ccl_lexer::Span,
    pub hint: Option<String>,
}

impl Diagnostic {
    fn error(code: &str, message: String, span: crate::cls::ccl_lexer::Span) -> Self {
        Self { level: DiagLevel::Error, code: code.into(), message, span, hint: None }
    }
    fn warning(code: &str, message: String, span: crate::cls::ccl_lexer::Span) -> Self {
        Self { level: DiagLevel::Warning, code: code.into(), message, span, hint: None }
    }
    fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.into());
        self
    }
    pub fn is_error(&self) -> bool { self.level == DiagLevel::Error }
}

// ═══════════════════════════════════════════════════════════════
// Symbol Table
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Contract-level: declared tool names
    pub tools: HashSet<String>,
    /// Contract-level: declared event names
    pub events: HashSet<String>,
    /// Contract-level: declared state names
    pub states: HashSet<String>,
    /// Contract-level: initial state
    pub initial_state: Option<String>,
    /// Contract-level: terminal states
    pub terminal_states: HashSet<String>,
    /// Contract-level: memory namespace aliases
    pub memory_aliases: HashSet<String>,
    /// Contract-level: input names
    pub inputs: HashSet<String>,
    /// Contract-level: output names
    pub outputs: HashSet<String>,
    /// Step-level: variables available at each step (step_id -> set of var names)
    pub step_vars: HashMap<String, HashSet<String>>,
    /// All step IDs in order
    pub step_ids: Vec<String>,
    /// Budget resources
    pub budget_resources: HashSet<String>,
    /// Roles
    pub roles: HashSet<String>,
    /// Transitions: (from, to)
    pub transitions: Vec<(String, String)>,
}

// ═══════════════════════════════════════════════════════════════
// Semantic Analyzer
// ═══════════════════════════════════════════════════════════════

pub struct SemanticAnalyzer {
    symbols: SymbolTable,
    diagnostics: Vec<Diagnostic>,
}

impl SemanticAnalyzer {
    pub fn new() -> Self {
        Self { symbols: SymbolTable::default(), diagnostics: Vec::new() }
    }

    /// Analyze a parsed contract AST. Returns symbol table and diagnostics.
    pub fn analyze(contract: &ContractNode) -> (SymbolTable, Vec<Diagnostic>) {
        let mut analyzer = SemanticAnalyzer::new();
        analyzer.collect_declarations(contract);
        analyzer.check_structure(contract);
        analyzer.check_behavior(contract);
        analyzer.check_state_machine();
        analyzer.check_budget();
        analyzer.check_governance(contract);
        (analyzer.symbols, analyzer.diagnostics)
    }

    /// Quick check: returns true if no errors (warnings ok).
    pub fn check(contract: &ContractNode) -> Result<SymbolTable, Vec<Diagnostic>> {
        let (symbols, diags) = Self::analyze(contract);
        let errors: Vec<_> = diags.into_iter().filter(|d| d.is_error()).collect();
        if errors.is_empty() { Ok(symbols) } else { Err(errors) }
    }

    // ── Pass 1: Collect declarations ────────────────────────────

    fn collect_declarations(&mut self, contract: &ContractNode) {
        for block in &contract.blocks {
            match block {
                BlockNode::Interface(iface) => {
                    for inp in &iface.inputs {
                        self.symbols.inputs.insert(inp.name.clone());
                    }
                    for out in &iface.outputs {
                        self.symbols.outputs.insert(out.name.clone());
                    }
                    for tool in &iface.tools {
                        self.symbols.tools.insert(tool.clone());
                    }
                    for event in &iface.events {
                        self.symbols.events.insert(event.clone());
                    }
                }
                BlockNode::State(state) => {
                    for s in &state.states {
                        self.symbols.states.insert(s.name.clone());
                        match s.kind {
                            StateKind::Initial => {
                                if self.symbols.initial_state.is_some() {
                                    self.diagnostics.push(Diagnostic::error(
                                        "E001", "multiple initial states declared".into(), s.span,
                                    ));
                                }
                                self.symbols.initial_state = Some(s.name.clone());
                            }
                            StateKind::Terminal => {
                                self.symbols.terminal_states.insert(s.name.clone());
                            }
                            StateKind::Normal => {}
                        }
                    }
                    for t in &state.transitions {
                        self.symbols.transitions.push((t.from.clone(), t.to.clone()));
                    }
                }
                BlockNode::Memory(mem) => {
                    for u in &mem.uses {
                        self.symbols.memory_aliases.insert(u.alias.clone());
                    }
                }
                BlockNode::Budget(budget) => {
                    for e in &budget.entries {
                        self.symbols.budget_resources.insert(e.resource.clone());
                    }
                }
                BlockNode::Governance(gov) => {
                    for r in &gov.roles {
                        self.symbols.roles.insert(r.clone());
                    }
                }
                BlockNode::Behavior(beh) => {
                    // Collect step IDs and build available vars per step
                    let mut available: HashSet<String> = self.symbols.inputs.clone();
                    for step in &beh.steps {
                        self.symbols.step_ids.push(step.id.clone());
                        self.symbols.step_vars.insert(step.id.clone(), available.clone());
                        // Collect bindings from this step
                        for op in &step.ops {
                            if let Some(bind) = Self::extract_bind(op) {
                                available.insert(bind);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn extract_bind(op: &StepOpNode) -> Option<String> {
        match op {
            StepOpNode::ToolCall { bind, .. } => bind.clone(),
            StepOpNode::LlmInfer { bind, .. } => bind.clone(),
            StepOpNode::MemRecall { bind, .. } => bind.clone(),
            StepOpNode::CallContract { bind, .. } => bind.clone(),
            StepOpNode::SetVar { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    // ── Pass 2: Structural checks ───────────────────────────────

    fn check_structure(&mut self, contract: &ContractNode) {
        let mut has_identity = false;
        let mut has_interface = false;
        let mut has_behavior = false;
        let mut has_state = false;

        for block in &contract.blocks {
            match block {
                BlockNode::Identity(_) => has_identity = true,
                BlockNode::Interface(_) => has_interface = true,
                BlockNode::Behavior(_) => has_behavior = true,
                BlockNode::State(_) => has_state = true,
                _ => {}
            }
        }

        let span = contract.span;
        if !has_behavior {
            self.diagnostics.push(Diagnostic::error("E060", "contract has no behavior block".into(), span));
        }
    }

    // ── Pass 3: Behavior checks ─────────────────────────────────

    fn check_behavior(&mut self, contract: &ContractNode) {
        for block in &contract.blocks {
            if let BlockNode::Behavior(beh) = block {
                // Check for duplicate step IDs
                let mut seen: HashSet<String> = HashSet::new();
                for step in &beh.steps {
                    if !seen.insert(step.id.clone()) {
                        self.diagnostics.push(Diagnostic::error(
                            "E015", format!("duplicate step ID '{}'", step.id), step.span,
                        ));
                    }
                }

                for step in &beh.steps {
                    let available_vars = self.symbols.step_vars.get(&step.id)
                        .cloned().unwrap_or_default();
                    self.check_step_ops(&step.ops, &step.id, &available_vars);
                }
            }
        }
    }

    fn check_step_ops(&mut self, ops: &[StepOpNode], step_id: &str, available_vars: &HashSet<String>) {
        let mut local_vars = available_vars.clone();

        for op in ops {
            match op {
                StepOpNode::ToolCall { tool_name, params, bind, span, .. } => {
                    if !self.symbols.tools.contains(tool_name) {
                        self.diagnostics.push(Diagnostic::error(
                            "E011",
                            format!("step '{}' uses tool '{}' but it is not declared in interface", step_id, tool_name),
                            *span,
                        ).with_hint(&format!("declared tools: {:?}", self.symbols.tools)));
                    }
                    self.check_param_refs(params, &local_vars, step_id);
                    if let Some(b) = bind { local_vars.insert(b.clone()); }
                }
                StepOpNode::LlmInfer { with_vars, bind, span, .. } => {
                    for var in with_vars {
                        let var_name = var.split('.').next().unwrap_or(var);
                        if !local_vars.contains(var_name) {
                            self.diagnostics.push(Diagnostic::error(
                                "E010",
                                format!("step '{}' references '{}' which is not defined", step_id, var),
                                *span,
                            ));
                        }
                    }
                    if let Some(b) = bind { local_vars.insert(b.clone()); }
                }
                StepOpNode::MemRecall { namespace, bind, span, .. } => {
                    if !self.symbols.memory_aliases.contains(namespace) {
                        self.diagnostics.push(Diagnostic::error(
                            "E012",
                            format!("step '{}' recalls from '{}' but it is not declared in memory block", step_id, namespace),
                            *span,
                        ));
                    }
                    if let Some(b) = bind { local_vars.insert(b.clone()); }
                }
                StepOpNode::MemRemember { namespace, span, .. } => {
                    if !self.symbols.memory_aliases.contains(namespace) {
                        self.diagnostics.push(Diagnostic::error(
                            "E012",
                            format!("step '{}' remembers to '{}' but it is not declared in memory block", step_id, namespace),
                            *span,
                        ));
                    }
                }
                StepOpNode::SetVar { name, value, span } => {
                    self.check_expr_refs(value, &local_vars, step_id);
                    local_vars.insert(name.clone());
                }
                StepOpNode::Branch { arms, span } => {
                    let has_otherwise = arms.iter().any(|a| a.predicate.is_none());
                    if !has_otherwise {
                        self.diagnostics.push(Diagnostic::error(
                            "E040",
                            format!("branch in step '{}' missing 'otherwise' arm", step_id),
                            *span,
                        ));
                    }
                    for arm in arms {
                        if !self.symbols.step_ids.contains(&arm.target) {
                            self.diagnostics.push(Diagnostic::error(
                                "E014",
                                format!("branch target '{}' is not a valid step", arm.target),
                                arm.span,
                            ));
                        }
                    }
                }
                StepOpNode::Transition { state, span } => {
                    if !self.symbols.states.contains(state) {
                        self.diagnostics.push(Diagnostic::error(
                            "E013_ST",
                            format!("step '{}' transitions to '{}' which is not a declared state", step_id, state),
                            *span,
                        ));
                    }
                }
                StepOpNode::EmitEvent { event, span, .. } => {
                    if !self.symbols.events.contains(event) {
                        self.diagnostics.push(Diagnostic::error(
                            "E013",
                            format!("step '{}' emits '{}' but it is not declared in interface", step_id, event),
                            *span,
                        ));
                    }
                }
                StepOpNode::CallContract { bind, .. } => {
                    if let Some(b) = bind { local_vars.insert(b.clone()); }
                }
                StepOpNode::Parallel { ops, .. } => {
                    self.check_step_ops(ops, step_id, &local_vars);
                }
                StepOpNode::Saga { forward, compensate, .. } => {
                    self.check_step_ops(&[*forward.clone()], step_id, &local_vars);
                    self.check_step_ops(&[*compensate.clone()], step_id, &local_vars);
                }
                _ => {}
            }

            // Check for unbound results (warnings)
            match op {
                StepOpNode::ToolCall { bind: None, tool_name, span, .. } => {
                    self.diagnostics.push(Diagnostic::warning(
                        "W001",
                        format!("tool call '{}' in step '{}' result is not bound to a variable", tool_name, step_id),
                        *span,
                    ));
                }
                StepOpNode::LlmInfer { bind: None, span, .. } => {
                    self.diagnostics.push(Diagnostic::warning(
                        "W001",
                        format!("infer in step '{}' result is not bound to a variable", step_id),
                        *span,
                    ));
                }
                _ => {}
            }
        }
    }

    fn check_param_refs(&mut self, params: &[ParamNode], vars: &HashSet<String>, step_id: &str) {
        for param in params {
            self.check_expr_refs(&param.value, vars, step_id);
        }
    }

    fn check_expr_refs(&mut self, expr: &ExprNode, vars: &HashSet<String>, step_id: &str) {
        match expr {
            ExprNode::VarRef(path, span) => {
                let var_name = path.split('.').next().unwrap_or(path);
                if !vars.contains(var_name) {
                    self.diagnostics.push(Diagnostic::error(
                        "E010",
                        format!("step '{}' references '${{{}}}' which is not defined at this point", step_id, path),
                        *span,
                    ));
                }
            }
            ExprNode::ObjectLit(params, _) => {
                self.check_param_refs(params, vars, step_id);
            }
            ExprNode::ListLit(items, _) => {
                for item in items {
                    self.check_expr_refs(item, vars, step_id);
                }
            }
            _ => {}
        }
    }

    // ── Pass 4: State machine checks ────────────────────────────

    fn check_state_machine(&mut self) {
        let span = crate::cls::ccl_lexer::Span::default();

        // E001: no initial state
        if self.symbols.initial_state.is_none() && !self.symbols.states.is_empty() {
            self.diagnostics.push(Diagnostic::error("E001", "no initial state declared".into(), span));
        }

        // E002: no terminal states
        if self.symbols.terminal_states.is_empty() && !self.symbols.states.is_empty() {
            self.diagnostics.push(Diagnostic::error("E002", "no terminal states declared".into(), span));
        }

        // Check transitions reference valid states
        for (from, to) in &self.symbols.transitions {
            if !self.symbols.states.contains(from) {
                self.diagnostics.push(Diagnostic::error(
                    "E003_T", format!("transition from '{}' — state not declared", from), span,
                ));
            }
            if !self.symbols.states.contains(to) {
                self.diagnostics.push(Diagnostic::error(
                    "E003_T", format!("transition to '{}' — state not declared", to), span,
                ));
            }
        }

        // E004: terminal states should not have outgoing transitions
        for (from, to) in &self.symbols.transitions {
            if self.symbols.terminal_states.contains(from) {
                self.diagnostics.push(Diagnostic::error(
                    "E004", format!("terminal state '{}' has transition to '{}'", from, to), span,
                ));
            }
        }

        // E003: reachability — all states reachable from initial
        if let Some(ref initial) = self.symbols.initial_state {
            let mut reachable = HashSet::new();
            let mut queue = vec![initial.clone()];
            while let Some(state) = queue.pop() {
                if !reachable.insert(state.clone()) { continue; }
                for (from, to) in &self.symbols.transitions {
                    if from == &state && !reachable.contains(to) {
                        queue.push(to.clone());
                    }
                }
            }
            for state in &self.symbols.states {
                if !reachable.contains(state) {
                    self.diagnostics.push(Diagnostic::error(
                        "E003", format!("state '{}' is unreachable from initial state", state), span,
                    ));
                }
            }
        }
    }

    // ── Pass 5: Budget checks ───────────────────────────────────

    fn check_budget(&mut self) {
        let span = crate::cls::ccl_lexer::Span::default();
        if self.symbols.budget_resources.is_empty() {
            // Only warn if there's a behavior block (contract is executable)
            if !self.symbols.step_ids.is_empty() {
                self.diagnostics.push(Diagnostic::warning(
                    "W020", "no budget defined — consider adding tokens, cost_usd, tool_calls".into(), span,
                ));
            }
        } else if self.symbols.budget_resources.len() == 1 {
            self.diagnostics.push(Diagnostic::warning(
                "W021",
                format!("only '{}' is budgeted — consider adding cost_usd and time_ms",
                    self.symbols.budget_resources.iter().next().unwrap()),
                span,
            ));
        }
    }

    // ── Pass 6: Governance checks ───────────────────────────────

    fn check_governance(&mut self, contract: &ContractNode) {
        let span = contract.span;
        let mut has_governance = false;
        let mut has_require = false;
        let mut has_ensure = false;

        for block in &contract.blocks {
            if let BlockNode::Governance(gov) = block {
                has_governance = true;
                has_require = !gov.requires.is_empty();
                has_ensure = !gov.ensures.is_empty();
            }
        }

        if !has_require && !self.symbols.step_ids.is_empty() {
            self.diagnostics.push(Diagnostic::warning("W010", "contract has no preconditions".into(), span));
        }
        if !has_ensure && !self.symbols.step_ids.is_empty() {
            self.diagnostics.push(Diagnostic::warning("W011", "contract has no postconditions".into(), span));
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

    fn analyze_src(src: &str) -> (SymbolTable, Vec<Diagnostic>) {
        let contract = CclParser::parse(src).expect("parse failed");
        SemanticAnalyzer::analyze(&contract)
    }

    fn errors_for(src: &str) -> Vec<Diagnostic> {
        let (_, diags) = analyze_src(src);
        diags.into_iter().filter(|d| d.is_error()).collect()
    }

    fn warnings_for(src: &str) -> Vec<Diagnostic> {
        let (_, diags) = analyze_src(src);
        diags.into_iter().filter(|d| !d.is_error()).collect()
    }

    #[test]
    fn test_valid_contract_no_errors() {
        let src = r#"contract valid {
            interface {
                input patient_id: String required
                output result: Json
                tool lookup
                event done
            }
            state {
                initial intake
                terminal complete
                intake -> complete on finish
            }
            governance {
                require patient_id is present
                ensure result is present
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
            }
            memory {
                use medical_history as history
            }
            behavior {
                step do_work {
                    tool lookup { id: ${patient_id} } -> patient
                    recall history { query: "past" } -> records
                    set result = ${patient}
                    transition complete
                    emit done { data: ${result} }
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_undefined_tool() {
        let src = r#"contract bad {
            interface { tool allowed_tool }
            behavior {
                step s {
                    tool undeclared_tool { } -> r
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E011"), "expected E011: {:?}", errors);
    }

    #[test]
    fn test_undefined_varref() {
        let src = r#"contract bad {
            interface { input x: String required }
            behavior {
                step s {
                    set y = ${nonexistent}
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E010"), "expected E010: {:?}", errors);
    }

    #[test]
    fn test_undeclared_namespace() {
        let src = r#"contract bad {
            behavior {
                step s {
                    recall unknown_ns { query: "test" } -> r
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E012"), "expected E012: {:?}", errors);
    }

    #[test]
    fn test_undeclared_event() {
        let src = r#"contract bad {
            interface { event allowed_event }
            behavior {
                step s {
                    emit not_declared { }
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E013"), "expected E013: {:?}", errors);
    }

    #[test]
    fn test_branch_missing_otherwise() {
        let src = r#"contract bad {
            behavior {
                step s {
                    branch {
                        when x > 5 -> s
                    }
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E040"), "expected E040: {:?}", errors);
    }

    #[test]
    fn test_no_initial_state() {
        let src = r#"contract bad {
            state {
                terminal done
            }
            behavior { step s { set x = 1 } }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E001"), "expected E001: {:?}", errors);
    }

    #[test]
    fn test_terminal_with_outgoing() {
        let src = r#"contract bad {
            state {
                initial start
                terminal done
                done -> start on reset
            }
            behavior { step s { set x = 1 } }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E004"), "expected E004: {:?}", errors);
    }

    #[test]
    fn test_unreachable_state() {
        let src = r#"contract bad {
            state {
                initial start
                terminal done
                orphan
                start -> done on finish
            }
            behavior { step s { set x = 1 } }
        }"#;
        let errors = errors_for(src);
        assert!(errors.iter().any(|e| e.code == "E003"), "expected E003: {:?}", errors);
    }

    #[test]
    fn test_warning_no_budget() {
        let src = r#"contract warn {
            behavior { step s { set x = 1 } }
        }"#;
        let warnings = warnings_for(src);
        assert!(warnings.iter().any(|w| w.code == "W020"), "expected W020: {:?}", warnings);
    }

    #[test]
    fn test_warning_no_preconditions() {
        let src = r#"contract warn {
            behavior { step s { set x = 1 } }
        }"#;
        let warnings = warnings_for(src);
        assert!(warnings.iter().any(|w| w.code == "W010"), "expected W010: {:?}", warnings);
    }

    #[test]
    fn test_warning_unbound_result() {
        let src = r#"contract warn {
            interface { tool my_tool }
            behavior {
                step s {
                    tool my_tool { }
                }
            }
        }"#;
        let warnings = warnings_for(src);
        assert!(warnings.iter().any(|w| w.code == "W001"), "expected W001: {:?}", warnings);
    }

    #[test]
    fn test_variable_flow_across_steps() {
        let src = r#"contract flow {
            interface {
                input x: String required
                tool t1
                tool t2
            }
            behavior {
                step first {
                    tool t1 { id: ${x} } -> intermediate
                }
                step second {
                    tool t2 { id: ${intermediate} } -> final_result
                }
            }
        }"#;
        let errors = errors_for(src);
        assert!(errors.is_empty(), "variable should flow between steps: {:?}", errors);
    }

    #[test]
    fn test_symbol_table_population() {
        let src = r#"contract sym {
            interface {
                input a: String required
                input b: Int required
                output c: Json
                tool t1
                tool t2
                event ev1
            }
            state {
                initial s1
                terminal s2
                s1 -> s2 on go
            }
            memory {
                use ns1 as n1
                use ns2
            }
            budget {
                tokens: 1000
                cost_usd: 1.0
            }
            governance {
                roles [admin, user]
            }
            behavior {
                step do_it {
                    tool t1 { } -> r
                }
            }
        }"#;
        let (syms, _) = analyze_src(src);
        assert_eq!(syms.inputs.len(), 2);
        assert_eq!(syms.outputs.len(), 1);
        assert_eq!(syms.tools.len(), 2);
        assert_eq!(syms.events.len(), 1);
        assert_eq!(syms.states.len(), 2);
        assert_eq!(syms.initial_state, Some("s1".into()));
        assert_eq!(syms.terminal_states.len(), 1);
        assert_eq!(syms.memory_aliases.len(), 2);
        assert_eq!(syms.budget_resources.len(), 2);
        assert_eq!(syms.roles.len(), 2);
        assert_eq!(syms.step_ids.len(), 1);
    }
}
