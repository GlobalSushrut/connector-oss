//! CLS Types — the type system for the Connector Logic System.
//!
//! Defines:
//!   - SolutionContract: compiled, signed, self-describing executable unit
//!   - ContractIR: canonical intermediate representation (DAG of CIROps)
//!   - CIROp: individual operations in the contract IR
//!   - ResourceEnvelope: multi-dimensional resource budget (gas analog)
//!   - ExecutionReceipt: signed, chained evidence of contract execution
//!   - Predicate system: pre/post/invariant conditions
//!   - State machine: contract lifecycle states

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Contract Identity
// ═══════════════════════════════════════════════════════════════

/// Unique identity of a compiled contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractId {
    /// Content identifier (SHA-256 of compiled contract bytes)
    pub cid: String,
    /// Human-readable name
    pub name: String,
    /// Semantic version
    pub version: ContractVersion,
    /// Author agent DID
    pub author: String,
}

/// Semantic versioning for contracts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ContractVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn is_compatible(&self, other: &ContractVersion) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ═══════════════════════════════════════════════════════════════
// Contract Interface
// ═══════════════════════════════════════════════════════════════

/// What a contract exposes to the outside world.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInterface {
    /// Input parameters the contract accepts
    pub inputs: Vec<ParamDef>,
    /// Output parameters the contract produces
    pub outputs: Vec<ParamDef>,
    /// Events the contract may emit
    pub events: Vec<String>,
    /// Tools the contract requires
    pub required_tools: Vec<String>,
    /// Memory namespaces the contract accesses
    pub required_namespaces: Vec<String>,
    /// Capabilities the contract requires from callers
    pub required_capabilities: Vec<String>,
}

/// A parameter definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDef {
    pub name: String,
    pub param_type: ParamType,
    pub required: bool,
    pub description: String,
    pub default: Option<serde_json::Value>,
}

/// Parameter type in the contract type system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    String,
    Integer,
    Float,
    Boolean,
    Json,
    Binary,
    CidRef,
    List(Box<ParamType>),
    Map(Box<ParamType>, Box<ParamType>),
}

// ═══════════════════════════════════════════════════════════════
// State Machine
// ═══════════════════════════════════════════════════════════════

/// Contract state machine — defines valid states and transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStateMachine {
    pub initial_state: String,
    pub terminal_states: Vec<String>,
    pub states: Vec<String>,
    pub transitions: Vec<StateTransition>,
}

impl ContractStateMachine {
    /// Check if a transition from `from` to `to` is valid.
    pub fn is_valid_transition(&self, from: &str, to: &str) -> bool {
        self.transitions.iter().any(|t| t.from == from && t.to == to)
    }

    /// Get valid next states from a given state.
    pub fn next_states(&self, from: &str) -> Vec<&str> {
        self.transitions.iter()
            .filter(|t| t.from == from)
            .map(|t| t.to.as_str())
            .collect()
    }

    /// Check if a state is terminal.
    pub fn is_terminal(&self, state: &str) -> bool {
        self.terminal_states.iter().any(|s| s == state)
    }
}

/// A state transition with optional guard predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub guard: Option<Predicate>,
}

// ═══════════════════════════════════════════════════════════════
// Predicate System
// ═══════════════════════════════════════════════════════════════

/// A predicate — evaluatable condition for governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Predicate {
    /// Always true.
    #[serde(rename = "always")]
    Always,
    /// Always false.
    #[serde(rename = "never")]
    Never,
    /// Check a field against a value.
    #[serde(rename = "field_equals")]
    FieldEquals { field: String, value: serde_json::Value },
    /// Check a field is greater than a value.
    #[serde(rename = "field_gt")]
    FieldGt { field: String, value: f64 },
    /// Check a field is less than a value.
    #[serde(rename = "field_lt")]
    FieldLt { field: String, value: f64 },
    /// Check a field is not empty/null.
    #[serde(rename = "field_present")]
    FieldPresent { field: String },
    /// Check agent has a role.
    #[serde(rename = "has_role")]
    HasRole { role: String },
    /// Check remaining budget.
    #[serde(rename = "budget_remaining")]
    BudgetRemaining { resource: String, min: f64 },
    /// Logical AND of predicates.
    #[serde(rename = "and")]
    And { predicates: Vec<Predicate> },
    /// Logical OR of predicates.
    #[serde(rename = "or")]
    Or { predicates: Vec<Predicate> },
    /// Logical NOT.
    #[serde(rename = "not")]
    Not { predicate: Box<Predicate> },
    /// Custom predicate (evaluated by domain kernel).
    #[serde(rename = "custom")]
    Custom { name: String, args: HashMap<String, serde_json::Value> },
}

impl Predicate {
    /// Evaluate this predicate against an execution context.
    pub fn evaluate(&self, ctx: &ExecutionContext) -> bool {
        match self {
            Predicate::Always => true,
            Predicate::Never => false,
            Predicate::FieldEquals { field, value } => {
                ctx.variables.get(field).map_or(false, |v| v == value)
            }
            Predicate::FieldGt { field, value } => {
                ctx.variables.get(field)
                    .and_then(|v| v.as_f64())
                    .map_or(false, |v| v > *value)
            }
            Predicate::FieldLt { field, value } => {
                ctx.variables.get(field)
                    .and_then(|v| v.as_f64())
                    .map_or(false, |v| v < *value)
            }
            Predicate::FieldPresent { field } => {
                ctx.variables.get(field).map_or(false, |v| !v.is_null())
            }
            Predicate::HasRole { role } => ctx.agent_roles.contains(role),
            Predicate::BudgetRemaining { resource, min } => {
                ctx.resource_usage.get(resource)
                    .and_then(|used| ctx.resource_envelope.limits.get(resource).map(|limit| limit - used))
                    .map_or(false, |remaining| remaining >= *min)
            }
            Predicate::And { predicates } => predicates.iter().all(|p| p.evaluate(ctx)),
            Predicate::Or { predicates } => predicates.iter().any(|p| p.evaluate(ctx)),
            Predicate::Not { predicate } => !predicate.evaluate(ctx),
            Predicate::Custom { .. } => true, // Domain kernel evaluates
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Governance
// ═══════════════════════════════════════════════════════════════

/// Governance rules for a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// Preconditions (checked before each node executes)
    pub preconditions: Vec<Predicate>,
    /// Postconditions (checked after each node executes)
    pub postconditions: Vec<Predicate>,
    /// Invariants (checked throughout execution)
    pub invariants: Vec<Predicate>,
    /// Failure strategy
    pub failure_strategy: FailureStrategy,
    /// Required clearance level
    pub clearance: Option<String>,
    /// Allowed agent roles
    pub allowed_roles: Vec<String>,
    /// Compliance tags
    pub compliance_tags: Vec<String>,
}

impl Default for Governance {
    fn default() -> Self {
        Self {
            preconditions: vec![],
            postconditions: vec![],
            invariants: vec![],
            failure_strategy: FailureStrategy::Abort,
            clearance: None,
            allowed_roles: vec![],
            compliance_tags: vec![],
        }
    }
}

/// What to do when execution fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStrategy {
    Abort,
    Retry { max_retries: u32, backoff_ms: u64 },
    Fallback { node_id: String },
    HumanReview,
    AcceptAndLog,
}

// ═══════════════════════════════════════════════════════════════
// Resource Envelope — multi-dimensional gas analog
// ═══════════════════════════════════════════════════════════════

/// Multi-dimensional resource budget for contract execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEnvelope {
    /// Resource name → limit (e.g., "tokens" → 4096, "cost_usd" → 0.50)
    pub limits: HashMap<String, f64>,
    /// Whether to hard-fail on budget exceed
    pub hard_limit: bool,
}

impl ResourceEnvelope {
    pub fn new() -> Self {
        Self { limits: HashMap::new(), hard_limit: true }
    }

    pub fn with_limit(mut self, resource: &str, limit: f64) -> Self {
        self.limits.insert(resource.to_string(), limit);
        self
    }

    /// Check if usage is within limits.
    pub fn check(&self, usage: &HashMap<String, f64>) -> ResourceCheck {
        let mut over = Vec::new();
        for (resource, limit) in &self.limits {
            if let Some(used) = usage.get(resource) {
                if *used > *limit {
                    over.push(ResourceViolation {
                        resource: resource.clone(),
                        limit: *limit,
                        used: *used,
                    });
                }
            }
        }
        if over.is_empty() {
            ResourceCheck::Ok
        } else {
            ResourceCheck::Exceeded(over)
        }
    }
}

impl Default for ResourceEnvelope {
    fn default() -> Self {
        Self::new()
            .with_limit("tokens", 8192.0)
            .with_limit("cost_usd", 1.0)
            .with_limit("tool_calls", 20.0)
            .with_limit("time_ms", 60_000.0)
            .with_limit("memory_mb", 128.0)
    }
}

/// Result of a resource check.
#[derive(Debug, Clone)]
pub enum ResourceCheck {
    Ok,
    Exceeded(Vec<ResourceViolation>),
}

/// A single resource violation.
#[derive(Debug, Clone)]
pub struct ResourceViolation {
    pub resource: String,
    pub limit: f64,
    pub used: f64,
}

// ═══════════════════════════════════════════════════════════════
// Contract IR — the executable DAG
// ═══════════════════════════════════════════════════════════════

/// Contract Intermediate Representation — a DAG of CIROps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractIR {
    /// Nodes in the execution graph
    pub nodes: Vec<IRNode>,
    /// Edges: (from_node_idx, to_node_idx)
    pub edges: Vec<(usize, usize)>,
    /// Entry node index
    pub entry: usize,
}

impl ContractIR {
    /// Get the successors of a node.
    pub fn successors(&self, node_idx: usize) -> Vec<usize> {
        self.edges.iter()
            .filter(|(from, _)| *from == node_idx)
            .map(|(_, to)| *to)
            .collect()
    }

    /// Get nodes with no predecessors (roots).
    pub fn roots(&self) -> Vec<usize> {
        let has_predecessor: std::collections::HashSet<usize> =
            self.edges.iter().map(|(_, to)| *to).collect();
        (0..self.nodes.len())
            .filter(|i| !has_predecessor.contains(i))
            .collect()
    }

    /// Topological order for execution.
    pub fn topo_order(&self) -> Vec<usize> {
        let n = self.nodes.len();
        let mut in_degree = vec![0usize; n];
        for (_, to) in &self.edges {
            in_degree[*to] += 1;
        }
        let mut queue: std::collections::VecDeque<usize> =
            in_degree.iter().enumerate()
                .filter(|(_, d)| **d == 0)
                .map(|(i, _)| i)
                .collect();
        let mut order = Vec::with_capacity(n);
        while let Some(node) = queue.pop_front() {
            order.push(node);
            for (from, to) in &self.edges {
                if *from == node {
                    in_degree[*to] -= 1;
                    if in_degree[*to] == 0 {
                        queue.push_back(*to);
                    }
                }
            }
        }
        order
    }
}

/// A node in the IR DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRNode {
    pub node_id: String,
    pub label: String,
    pub op: CIROp,
    pub precondition: Option<Predicate>,
    pub postcondition: Option<Predicate>,
}

/// Operations in the Contract IR — the instruction set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum CIROp {
    /// Call a tool with parameters.
    #[serde(rename = "tool_call")]
    ToolCall {
        tool_id: String,
        params: HashMap<String, serde_json::Value>,
        output_var: String,
    },

    /// Invoke LLM inference.
    #[serde(rename = "llm_infer")]
    LlmInfer {
        prompt_template: String,
        input_vars: Vec<String>,
        output_var: String,
        max_tokens: u32,
        temperature: f64,
    },

    /// Read from memory.
    #[serde(rename = "mem_read")]
    MemRead {
        namespace: String,
        query: String,
        output_var: String,
        max_results: u32,
    },

    /// Write to memory.
    #[serde(rename = "mem_write")]
    MemWrite {
        namespace: String,
        content_var: String,
        tags: Vec<String>,
    },

    /// Conditional branch.
    #[serde(rename = "branch")]
    Branch {
        condition: Predicate,
        then_node: String,
        else_node: Option<String>,
    },

    /// Set a variable in the execution context.
    #[serde(rename = "set_var")]
    SetVar {
        name: String,
        value: serde_json::Value,
    },

    /// Compute a value from an expression.
    #[serde(rename = "compute")]
    Compute {
        expression: String,
        input_vars: Vec<String>,
        output_var: String,
    },

    /// Emit an event.
    #[serde(rename = "emit_event")]
    EmitEvent {
        event_type: String,
        data_vars: Vec<String>,
    },

    /// Transition the contract state machine.
    #[serde(rename = "transition")]
    Transition {
        to_state: String,
    },

    /// Call another contract (composition).
    #[serde(rename = "call_contract")]
    CallContract {
        contract_id: String,
        inputs: HashMap<String, String>,
        output_var: String,
    },

    /// Send a CNP message to another agent.
    #[serde(rename = "send_message")]
    SendMessage {
        to_agent: String,
        payload_var: String,
    },

    /// Checkpoint (for recovery).
    #[serde(rename = "checkpoint")]
    Checkpoint {
        label: String,
    },

    /// No-op (placeholder, pipeline join).
    #[serde(rename = "noop")]
    Noop,
}

// ═══════════════════════════════════════════════════════════════
// SolutionContract — the compiled, signed executable unit
// ═══════════════════════════════════════════════════════════════

/// A compiled, signed, self-describing contract — the central artifact of CLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolutionContract {
    /// Contract identity
    pub id: ContractId,
    /// What the contract exposes
    pub interface: ContractInterface,
    /// The executable IR
    pub ir: ContractIR,
    /// State machine
    pub state_machine: ContractStateMachine,
    /// Governance rules
    pub governance: Governance,
    /// Resource budget
    pub resource_envelope: ResourceEnvelope,
    /// Domain-specific metadata
    pub domain: Option<String>,
    /// Contract description
    pub description: String,
    /// Compilation timestamp
    pub compiled_at: i64,
    /// Ed25519 signature of the contract (hex-encoded)
    pub signature: Option<String>,
}

impl SolutionContract {
    /// Validate the contract structure.
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check state machine has initial state in states list
        if !self.state_machine.states.contains(&self.state_machine.initial_state) {
            errors.push(ValidationError {
                code: "SM001".into(),
                message: format!("Initial state '{}' not in states list", self.state_machine.initial_state),
            });
        }

        // Check all terminal states are in states list
        for ts in &self.state_machine.terminal_states {
            if !self.state_machine.states.contains(ts) {
                errors.push(ValidationError {
                    code: "SM002".into(),
                    message: format!("Terminal state '{}' not in states list", ts),
                });
            }
        }

        // Check IR has at least one node
        if self.ir.nodes.is_empty() {
            errors.push(ValidationError {
                code: "IR001".into(),
                message: "Contract IR has no nodes".into(),
            });
        }

        // Check entry node is valid
        if self.ir.entry >= self.ir.nodes.len() {
            errors.push(ValidationError {
                code: "IR002".into(),
                message: format!("Entry node index {} out of bounds", self.ir.entry),
            });
        }

        // Check resource envelope has limits
        if self.resource_envelope.limits.is_empty() {
            errors.push(ValidationError {
                code: "RE001".into(),
                message: "Resource envelope has no limits".into(),
            });
        }

        errors
    }
}

/// Validation error.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
}

// ═══════════════════════════════════════════════════════════════
// Execution Context — runtime state during contract execution
// ═══════════════════════════════════════════════════════════════

/// Runtime context passed through contract execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Contract being executed
    pub contract_id: String,
    /// Current state in the state machine
    pub current_state: String,
    /// Agent executing the contract
    pub agent_pid: String,
    /// Agent roles
    pub agent_roles: Vec<String>,
    /// Session ID
    pub session_id: String,
    /// Variables (name → value)
    pub variables: HashMap<String, serde_json::Value>,
    /// Resource usage so far
    pub resource_usage: HashMap<String, f64>,
    /// Resource envelope (budget)
    pub resource_envelope: ResourceEnvelope,
    /// Current node index in IR
    pub current_node: usize,
    /// Execution trace (node_id, timestamp)
    pub trace: Vec<(String, i64)>,
    /// Start time
    pub started_at: i64,
    /// Events emitted
    pub events: Vec<ExecutionEvent>,
}

impl ExecutionContext {
    pub fn new(
        contract_id: &str,
        initial_state: &str,
        agent_pid: &str,
        session_id: &str,
        resource_envelope: ResourceEnvelope,
    ) -> Self {
        Self {
            contract_id: contract_id.to_string(),
            current_state: initial_state.to_string(),
            agent_pid: agent_pid.to_string(),
            agent_roles: vec![],
            session_id: session_id.to_string(),
            variables: HashMap::new(),
            resource_usage: HashMap::new(),
            resource_envelope,
            current_node: 0,
            trace: vec![],
            started_at: now_ms(),
            events: vec![],
        }
    }

    /// Record resource usage.
    pub fn use_resource(&mut self, resource: &str, amount: f64) {
        *self.resource_usage.entry(resource.to_string()).or_insert(0.0) += amount;
    }

    /// Check if any resource limit is exceeded.
    pub fn check_budget(&self) -> ResourceCheck {
        self.resource_envelope.check(&self.resource_usage)
    }

    /// Set a variable.
    pub fn set_var(&mut self, name: &str, value: serde_json::Value) {
        self.variables.insert(name.to_string(), value);
    }

    /// Get a variable.
    pub fn get_var(&self, name: &str) -> Option<&serde_json::Value> {
        self.variables.get(name)
    }

    /// Record a trace entry.
    pub fn trace_node(&mut self, node_id: &str) {
        self.trace.push((node_id.to_string(), now_ms()));
    }

    /// Emit an event.
    pub fn emit_event(&mut self, event_type: &str, data: serde_json::Value) {
        self.events.push(ExecutionEvent {
            event_type: event_type.to_string(),
            data,
            timestamp: now_ms(),
        });
    }

    /// Elapsed time since start.
    pub fn elapsed_ms(&self) -> i64 {
        now_ms() - self.started_at
    }
}

/// An event emitted during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub event_type: String,
    pub data: serde_json::Value,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════
// Execution Receipt — signed evidence of contract execution
// ═══════════════════════════════════════════════════════════════

/// A signed receipt proving contract execution — the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Receipt ID
    pub receipt_id: String,
    /// Contract that was executed
    pub contract_id: String,
    /// Agent that executed it
    pub agent_pid: String,
    /// Session ID
    pub session_id: String,
    /// Execution outcome
    pub outcome: ExecutionOutcome,
    /// Final state in state machine
    pub final_state: String,
    /// Output variables
    pub outputs: HashMap<String, serde_json::Value>,
    /// Resource usage
    pub resource_usage: HashMap<String, f64>,
    /// Execution trace (node_id, timestamp)
    pub trace: Vec<(String, i64)>,
    /// Events emitted
    pub events: Vec<ExecutionEvent>,
    /// Duration in ms
    pub duration_ms: i64,
    /// CID of previous receipt in chain (None = first)
    pub previous_receipt_cid: Option<String>,
    /// CID of this receipt (computed from content)
    pub receipt_cid: String,
    /// Timestamp
    pub timestamp: i64,
    /// Ed25519 signature (hex-encoded)
    pub signature: Option<String>,
}

/// Execution outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Contract executed successfully to terminal state.
    Success,
    /// Contract execution failed.
    Failed { reason: String },
    /// Contract execution was aborted by governance.
    Aborted { reason: String },
    /// Budget exceeded.
    BudgetExceeded { resource: String },
    /// Predicate violation.
    PredicateViolation { predicate: String, node_id: String },
    /// Timeout.
    Timeout,
}

// ═══════════════════════════════════════════════════════════════
// Node Execution Result
// ═══════════════════════════════════════════════════════════════

/// Result of executing a single IR node.
#[derive(Debug, Clone)]
pub enum NodeResult {
    /// Node succeeded, proceed to successors.
    Continue,
    /// Node produced a branch decision.
    Branch { target_node_id: String },
    /// Node requested a state transition.
    Transition { to_state: String },
    /// Node failed.
    Failed { error: String },
    /// Node completed the contract (reached terminal logic).
    Complete,
}

// ═══════════════════════════════════════════════════════════════
// CLS Error
// ═══════════════════════════════════════════════════════════════

/// Errors from the CLS contract system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClsError {
    CompilationError { detail: String },
    ValidationError { errors: Vec<String> },
    ExecutionError { detail: String },
    PredicateViolation { predicate: String, node_id: String },
    BudgetExceeded { resource: String, used: f64, limit: f64 },
    InvalidTransition { from: String, to: String },
    ContractNotFound { contract_id: String },
    RegistryError { detail: String },
    GovernanceError { detail: String },
}

impl std::fmt::Display for ClsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClsError::CompilationError { detail } => write!(f, "CLS compile: {}", detail),
            ClsError::ValidationError { errors } => write!(f, "CLS validate: {}", errors.join(", ")),
            ClsError::ExecutionError { detail } => write!(f, "CLS exec: {}", detail),
            ClsError::PredicateViolation { predicate, node_id } =>
                write!(f, "CLS predicate '{}' violated at node {}", predicate, node_id),
            ClsError::BudgetExceeded { resource, used, limit } =>
                write!(f, "CLS budget: {} used {}/{}", resource, used, limit),
            ClsError::InvalidTransition { from, to } =>
                write!(f, "CLS invalid transition: {} → {}", from, to),
            ClsError::ContractNotFound { contract_id } =>
                write!(f, "CLS contract not found: {}", contract_id),
            ClsError::RegistryError { detail } => write!(f, "CLS registry: {}", detail),
            ClsError::GovernanceError { detail } => write!(f, "CLS governance: {}", detail),
        }
    }
}

impl std::error::Error for ClsError {}

pub type ClsResult<T> = Result<T, ClsError>;

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

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

    fn test_envelope() -> ResourceEnvelope {
        ResourceEnvelope::new()
            .with_limit("tokens", 1000.0)
            .with_limit("tool_calls", 5.0)
    }

    fn test_ctx() -> ExecutionContext {
        let mut ctx = ExecutionContext::new("test-contract", "init", "agent-1", "sess-1", test_envelope());
        ctx.agent_roles = vec!["writer".into()];
        ctx.set_var("severity", serde_json::json!(8.5));
        ctx.set_var("patient_name", serde_json::json!("John Doe"));
        ctx
    }

    #[test]
    fn test_version_compat() {
        let v1 = ContractVersion::new(1, 0, 0);
        let v1_1 = ContractVersion::new(1, 1, 0);
        let v2 = ContractVersion::new(2, 0, 0);
        assert!(v1.is_compatible(&v1_1));
        assert!(!v1.is_compatible(&v2));
    }

    #[test]
    fn test_predicate_field_equals() {
        let ctx = test_ctx();
        let pred = Predicate::FieldEquals {
            field: "patient_name".into(),
            value: serde_json::json!("John Doe"),
        };
        assert!(pred.evaluate(&ctx));
    }

    #[test]
    fn test_predicate_field_gt() {
        let ctx = test_ctx();
        let pred = Predicate::FieldGt { field: "severity".into(), value: 7.0 };
        assert!(pred.evaluate(&ctx));
        let pred2 = Predicate::FieldGt { field: "severity".into(), value: 9.0 };
        assert!(!pred2.evaluate(&ctx));
    }

    #[test]
    fn test_predicate_has_role() {
        let ctx = test_ctx();
        assert!(Predicate::HasRole { role: "writer".into() }.evaluate(&ctx));
        assert!(!Predicate::HasRole { role: "admin".into() }.evaluate(&ctx));
    }

    #[test]
    fn test_predicate_budget() {
        let mut ctx = test_ctx();
        ctx.use_resource("tokens", 500.0);

        let pred = Predicate::BudgetRemaining { resource: "tokens".into(), min: 400.0 };
        assert!(pred.evaluate(&ctx)); // 500 remaining ≥ 400

        ctx.use_resource("tokens", 200.0);
        assert!(!pred.evaluate(&ctx)); // 300 remaining < 400
    }

    #[test]
    fn test_predicate_and_or_not() {
        let ctx = test_ctx();
        let combined = Predicate::And {
            predicates: vec![
                Predicate::HasRole { role: "writer".into() },
                Predicate::FieldPresent { field: "severity".into() },
            ],
        };
        assert!(combined.evaluate(&ctx));

        let or_pred = Predicate::Or {
            predicates: vec![
                Predicate::HasRole { role: "admin".into() },
                Predicate::FieldGt { field: "severity".into(), value: 5.0 },
            ],
        };
        assert!(or_pred.evaluate(&ctx));

        let not_pred = Predicate::Not {
            predicate: Box::new(Predicate::HasRole { role: "admin".into() }),
        };
        assert!(not_pred.evaluate(&ctx));
    }

    #[test]
    fn test_resource_envelope() {
        let envelope = test_envelope();
        let mut usage = HashMap::new();
        usage.insert("tokens".into(), 500.0);
        assert!(matches!(envelope.check(&usage), ResourceCheck::Ok));

        usage.insert("tokens".into(), 1500.0);
        assert!(matches!(envelope.check(&usage), ResourceCheck::Exceeded(_)));
    }

    #[test]
    fn test_state_machine() {
        let sm = ContractStateMachine {
            initial_state: "init".into(),
            terminal_states: vec!["done".into(), "failed".into()],
            states: vec!["init".into(), "assessing".into(), "done".into(), "failed".into()],
            transitions: vec![
                StateTransition { from: "init".into(), to: "assessing".into(), trigger: "start".into(), guard: None },
                StateTransition { from: "assessing".into(), to: "done".into(), trigger: "complete".into(), guard: None },
                StateTransition { from: "assessing".into(), to: "failed".into(), trigger: "error".into(), guard: None },
            ],
        };
        assert!(sm.is_valid_transition("init", "assessing"));
        assert!(!sm.is_valid_transition("init", "done"));
        assert!(sm.is_terminal("done"));
        assert!(!sm.is_terminal("init"));
        assert_eq!(sm.next_states("assessing"), vec!["done", "failed"]);
    }

    #[test]
    fn test_contract_ir_topo() {
        let ir = ContractIR {
            nodes: vec![
                IRNode { node_id: "n0".into(), label: "start".into(), op: CIROp::Noop, precondition: None, postcondition: None },
                IRNode { node_id: "n1".into(), label: "call tool".into(), op: CIROp::Noop, precondition: None, postcondition: None },
                IRNode { node_id: "n2".into(), label: "end".into(), op: CIROp::Noop, precondition: None, postcondition: None },
            ],
            edges: vec![(0, 1), (1, 2)],
            entry: 0,
        };
        assert_eq!(ir.topo_order(), vec![0, 1, 2]);
        assert_eq!(ir.successors(0), vec![1]);
        assert_eq!(ir.roots(), vec![0]);
    }

    #[test]
    fn test_execution_context() {
        let mut ctx = test_ctx();
        ctx.use_resource("tokens", 100.0);
        ctx.use_resource("tokens", 200.0);
        assert_eq!(ctx.resource_usage.get("tokens"), Some(&300.0));
        assert!(matches!(ctx.check_budget(), ResourceCheck::Ok));

        ctx.trace_node("n0");
        assert_eq!(ctx.trace.len(), 1);

        ctx.emit_event("triage_started", serde_json::json!({"patient": "John"}));
        assert_eq!(ctx.events.len(), 1);
    }
}
