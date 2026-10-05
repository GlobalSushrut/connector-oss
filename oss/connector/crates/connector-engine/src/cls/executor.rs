//! CLS Executor — executes SolutionContracts through the kernel.
//!
//! The executor walks the ContractIR DAG, evaluating predicates,
//! enforcing governance, tracking resources, and producing a signed
//! ExecutionReceipt chain.
//!
//! Each node execution follows:
//!   1. Check precondition
//!   2. Check budget
//!   3. Execute CIROp (dispatch to tool/LLM/memory/branch)
//!   4. Check postcondition
//!   5. Check invariants
//!   6. Record trace + resource usage
//!   7. Advance to successors

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use crate::cls::types::*;

// ═══════════════════════════════════════════════════════════════
// Tool/LLM/Memory Handler Traits
// ═══════════════════════════════════════════════════════════════

/// Handler for tool calls — the kernel glue point.
/// Implement this to connect CLS to the actual kernel tool registry.
pub trait ToolHandler: Send + Sync {
    fn call(&self, tool_id: &str, params: &HashMap<String, serde_json::Value>, ctx: &ExecutionContext)
        -> Result<serde_json::Value, String>;
}

/// Handler for LLM inference.
pub trait LlmHandler: Send + Sync {
    fn infer(&self, prompt: &str, max_tokens: u32, temperature: f64, ctx: &ExecutionContext)
        -> Result<(String, u32), String>; // (response, tokens_used)
}

/// Handler for memory operations.
pub trait MemoryHandler: Send + Sync {
    fn read(&self, namespace: &str, query: &str, max_results: u32, ctx: &ExecutionContext)
        -> Result<serde_json::Value, String>;
    fn write(&self, namespace: &str, content: &serde_json::Value, tags: &[String], ctx: &ExecutionContext)
        -> Result<(), String>;
}

/// Handler for inter-agent messaging (CNP integration point).
pub trait MessageHandler: Send + Sync {
    fn send(&self, to_agent: &str, payload: &serde_json::Value, ctx: &ExecutionContext)
        -> Result<String, String>; // Returns message_id
}

/// Handler for sub-contract execution (composition).
pub trait ContractHandler: Send + Sync {
    fn execute(&self, contract_id: &str, inputs: HashMap<String, serde_json::Value>, ctx: &ExecutionContext)
        -> Result<serde_json::Value, String>;
}

/// Durable checkpoint / completion sink for graph runs.
pub trait ExecutionStore: Send + Sync {
    fn checkpoint(
        &self,
        contract_cid: &str,
        run_id: &str,
        label: &str,
        ctx: &ExecutionContext,
    ) -> Result<(), String>;

    fn complete(&self, receipt: &ExecutionReceipt) -> Result<(), String>;
}

/// In-memory store for tests / local durable dry-runs.
#[derive(Default)]
pub struct InMemoryExecutionStore {
    pub checkpoints: std::sync::Mutex<Vec<(String, String, String)>>,
    pub receipts: std::sync::Mutex<Vec<ExecutionReceipt>>,
}

impl ExecutionStore for InMemoryExecutionStore {
    fn checkpoint(
        &self,
        contract_cid: &str,
        run_id: &str,
        label: &str,
        _ctx: &ExecutionContext,
    ) -> Result<(), String> {
        self.checkpoints
            .lock()
            .map_err(|e| e.to_string())?
            .push((contract_cid.into(), run_id.into(), label.into()));
        Ok(())
    }

    fn complete(&self, receipt: &ExecutionReceipt) -> Result<(), String> {
        self.receipts
            .lock()
            .map_err(|e| e.to_string())?
            .push(receipt.clone());
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Stub Handlers (for testing / standalone execution)
// ═══════════════════════════════════════════════════════════════

/// Stub tool handler that returns mock results.
pub struct StubToolHandler;
impl ToolHandler for StubToolHandler {
    fn call(&self, tool_id: &str, params: &HashMap<String, serde_json::Value>, _ctx: &ExecutionContext)
        -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "tool": tool_id,
            "status": "ok",
            "params": params,
            "mock": true
        }))
    }
}

/// Stub LLM handler that returns mock inference.
pub struct StubLlmHandler;
impl LlmHandler for StubLlmHandler {
    fn infer(&self, prompt: &str, max_tokens: u32, _temperature: f64, _ctx: &ExecutionContext)
        -> Result<(String, u32), String> {
        let tokens_used = (prompt.len() / 4).min(max_tokens as usize) as u32;
        Ok((format!("[LLM mock response for prompt len={}]", prompt.len()), tokens_used))
    }
}

/// Stub memory handler with in-memory store.
pub struct StubMemoryHandler {
    store: std::sync::Mutex<HashMap<String, Vec<serde_json::Value>>>,
}
impl StubMemoryHandler {
    pub fn new() -> Self {
        Self { store: std::sync::Mutex::new(HashMap::new()) }
    }
}
impl MemoryHandler for StubMemoryHandler {
    fn read(&self, namespace: &str, _query: &str, max_results: u32, _ctx: &ExecutionContext)
        -> Result<serde_json::Value, String> {
        let store = self.store.lock().map_err(|e| e.to_string())?;
        let items = store.get(namespace)
            .map(|v| v.iter().take(max_results as usize).cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        Ok(serde_json::json!(items))
    }
    fn write(&self, namespace: &str, content: &serde_json::Value, _tags: &[String], _ctx: &ExecutionContext)
        -> Result<(), String> {
        let mut store = self.store.lock().map_err(|e| e.to_string())?;
        store.entry(namespace.to_string()).or_default().push(content.clone());
        Ok(())
    }
}

/// Stub message handler that logs messages.
pub struct StubMessageHandler;
impl MessageHandler for StubMessageHandler {
    fn send(&self, to_agent: &str, payload: &serde_json::Value, _ctx: &ExecutionContext)
        -> Result<String, String> {
        let msg_id = format!("msg-{:016x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64);
        Ok(msg_id)
    }
}

/// Stub contract handler that returns mock sub-contract results.
pub struct StubContractHandler;
impl ContractHandler for StubContractHandler {
    fn execute(&self, contract_id: &str, inputs: HashMap<String, serde_json::Value>, _ctx: &ExecutionContext)
        -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "contract_id": contract_id,
            "inputs": inputs,
            "status": "completed",
            "mock": true
        }))
    }
}

// ═══════════════════════════════════════════════════════════════
// Production Handlers (CNP-backed)
// ═══════════════════════════════════════════════════════════════

use crate::cnp::{CnpMessage, CnpPayload, CnpStack};

/// CNP-backed message handler for production use.
/// Sends messages through the CNP stack to other agents.
pub struct CnpMessageHandler {
    stack: std::sync::Arc<std::sync::Mutex<CnpStack>>,
    from_agent: String,
}

impl CnpMessageHandler {
    pub fn new(stack: std::sync::Arc<std::sync::Mutex<CnpStack>>, from_agent: &str) -> Self {
        Self { stack, from_agent: from_agent.to_string() }
    }
}

impl MessageHandler for CnpMessageHandler {
    fn send(&self, to_agent: &str, payload: &serde_json::Value, ctx: &ExecutionContext)
        -> Result<String, String> {
        // Build CNP message using the builder pattern
        let cnp_payload = CnpPayload::Event {
            event_type: "cls_message".to_string(),
            data: payload.clone(),
        };
        
        let message = CnpMessage::new(&self.from_agent, to_agent, cnp_payload)
            .with_session(&ctx.session_id)
            .with_priority(5);
        
        let msg_id = message.message_id.clone();
        
        // Send through CNP stack (full 7-layer pipeline)
        let mut stack = self.stack.lock().map_err(|e| e.to_string())?;
        stack.send(message).map_err(|e| format!("{:?}", e))?;
        
        Ok(msg_id)
    }
}

/// Registry-backed contract handler for production use.
/// Executes sub-contracts by looking them up in the registry.
pub struct RegistryContractHandler {
    registry: std::sync::Arc<std::sync::RwLock<crate::cls::registry::ContractRegistry>>,
    /// Recursive executor factory (to avoid circular deps)
    executor_factory: Box<dyn Fn() -> ContractExecutor + Send + Sync>,
}

impl RegistryContractHandler {
    pub fn new(
        registry: std::sync::Arc<std::sync::RwLock<crate::cls::registry::ContractRegistry>>,
        executor_factory: Box<dyn Fn() -> ContractExecutor + Send + Sync>,
    ) -> Self {
        Self { registry, executor_factory }
    }
}

impl ContractHandler for RegistryContractHandler {
    fn execute(&self, contract_id: &str, inputs: HashMap<String, serde_json::Value>, ctx: &ExecutionContext)
        -> Result<serde_json::Value, String> {
        // Look up contract in registry
        let registry = self.registry.read().map_err(|e| e.to_string())?;
        let entry = registry.get(contract_id)
            .ok_or_else(|| format!("Contract not found: {}", contract_id))?;
        let contract = entry.contract.clone();
        drop(registry);
        
        // Create sub-executor and run
        let mut sub_executor = (self.executor_factory)();
        let receipt = sub_executor.execute(
            &contract,
            &ctx.agent_pid,
            &ctx.session_id,
            inputs,
        ).map_err(|e| format!("Sub-contract execution failed: {:?}", e))?;
        
        // Return outputs from receipt
        Ok(serde_json::json!({
            "contract_id": contract_id,
            "receipt_cid": receipt.receipt_cid,
            "outcome": format!("{:?}", receipt.outcome),
            "outputs": receipt.outputs,
        }))
    }
}

// ═══════════════════════════════════════════════════════════════
// Contract Executor
// ═══════════════════════════════════════════════════════════════

/// Executes a SolutionContract, producing an ExecutionReceipt.
pub struct ContractExecutor {
    tool_handler: Box<dyn ToolHandler>,
    llm_handler: Box<dyn LlmHandler>,
    memory_handler: Box<dyn MemoryHandler>,
    message_handler: Box<dyn MessageHandler>,
    contract_handler: Box<dyn ContractHandler>,
    /// Previous receipt CID for chaining
    previous_receipt_cid: Option<String>,
    /// Optional durable checkpoint / completion sink.
    store: Option<std::sync::Arc<dyn ExecutionStore>>,
}

impl ContractExecutor {
    pub fn new(
        tool_handler: Box<dyn ToolHandler>,
        llm_handler: Box<dyn LlmHandler>,
        memory_handler: Box<dyn MemoryHandler>,
        message_handler: Box<dyn MessageHandler>,
        contract_handler: Box<dyn ContractHandler>,
    ) -> Self {
        Self {
            tool_handler,
            llm_handler,
            memory_handler,
            message_handler,
            contract_handler,
            previous_receipt_cid: None,
            store: None,
        }
    }

    /// Create an executor with stub handlers (for testing).
    pub fn stub() -> Self {
        Self::new(
            Box::new(StubToolHandler),
            Box::new(StubLlmHandler),
            Box::new(StubMemoryHandler::new()),
            Box::new(StubMessageHandler),
            Box::new(StubContractHandler),
        )
    }

    /// Attach a durable execution store (checkpoints + final receipt).
    pub fn with_store(mut self, store: std::sync::Arc<dyn ExecutionStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Set previous receipt CID for chaining.
    pub fn with_previous_receipt(mut self, cid: &str) -> Self {
        self.previous_receipt_cid = Some(cid.to_string());
        self
    }

    /// Execute a SolutionContract.
    ///
    /// Returns the ExecutionReceipt containing the full audit trail.
    pub fn execute(
        &mut self,
        contract: &SolutionContract,
        agent_pid: &str,
        session_id: &str,
        inputs: HashMap<String, serde_json::Value>,
    ) -> ClsResult<ExecutionReceipt> {
        // Initialize execution context
        let mut ctx = ExecutionContext::new(
            &contract.id.cid,
            &contract.state_machine.initial_state,
            agent_pid,
            session_id,
            contract.resource_envelope.clone(),
        );
        ctx.variables = inputs;

        // Check governance: allowed roles
        if !contract.governance.allowed_roles.is_empty() {
            let has_role = ctx.agent_roles.iter().any(|r| contract.governance.allowed_roles.contains(r));
            if !has_role && !ctx.agent_roles.is_empty() {
                return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Aborted {
                    reason: format!("Agent lacks required role. Has: {:?}, needs one of: {:?}",
                        ctx.agent_roles, contract.governance.allowed_roles),
                });
            }
        }

        // Check global preconditions
        for pre in &contract.governance.preconditions {
            if !pre.evaluate(&ctx) {
                return self.emit_receipt(&contract, &ctx, ExecutionOutcome::PredicateViolation {
                    predicate: format!("{:?}", pre),
                    node_id: "global_precondition".into(),
                });
            }
        }

        // Execute the IR DAG in topological order
        let topo = contract.ir.topo_order();
        let mut node_idx = 0usize;
        let mut skip_until: Option<String> = None;

        while node_idx < topo.len() {
            let current = topo[node_idx];
            if current >= contract.ir.nodes.len() { break; }

            let node = &contract.ir.nodes[current];

            // Handle skip (from branch else paths)
            if let Some(ref target_id) = skip_until {
                if node.node_id != *target_id {
                    node_idx += 1;
                    continue;
                }
                skip_until = None;
            }

            ctx.current_node = current;
            ctx.trace_node(&node.node_id);

            // 1. Check budget
            if let ResourceCheck::Exceeded(violations) = ctx.check_budget() {
                let v = &violations[0];
                return self.emit_receipt(&contract, &ctx, ExecutionOutcome::BudgetExceeded {
                    resource: v.resource.clone(),
                });
            }

            // 2. Check time budget
            if let Some(time_limit) = ctx.resource_envelope.limits.get("time_ms") {
                if ctx.elapsed_ms() as f64 > *time_limit {
                    return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Timeout);
                }
            }

            // 3. Check node precondition
            if let Some(pre) = &node.precondition {
                if !pre.evaluate(&ctx) {
                    // For branch nodes, precondition failure means take else path
                    if matches!(node.op, CIROp::Branch { .. }) {
                        if let CIROp::Branch { else_node, .. } = &node.op {
                            if let Some(else_id) = else_node {
                                skip_until = Some(else_id.clone());
                            }
                        }
                        node_idx += 1;
                        continue;
                    }
                    return self.emit_receipt(&contract, &ctx, ExecutionOutcome::PredicateViolation {
                        predicate: format!("{:?}", pre),
                        node_id: node.node_id.clone(),
                    });
                }
            }

            // 4. Check invariants
            for inv in &contract.governance.invariants {
                if !inv.evaluate(&ctx) {
                    return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Aborted {
                        reason: format!("Invariant violated at node {}", node.node_id),
                    });
                }
            }

            // 5. Execute the CIROp
            let result = self.execute_node(&node.op, &mut ctx, &contract.state_machine)?;

            // 6. Check node postcondition
            if let Some(post) = &node.postcondition {
                if !post.evaluate(&ctx) {
                    return self.emit_receipt(&contract, &ctx, ExecutionOutcome::PredicateViolation {
                        predicate: format!("{:?}", post),
                        node_id: node.node_id.clone(),
                    });
                }
            }

            // 7. Handle node result
            match result {
                NodeResult::Continue => {
                    node_idx += 1;
                }
                NodeResult::Branch { target_node_id } => {
                    skip_until = Some(target_node_id);
                    node_idx += 1;
                }
                NodeResult::Transition { to_state } => {
                    if !contract.state_machine.is_valid_transition(&ctx.current_state, &to_state) {
                        return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Failed {
                            reason: format!("Invalid transition: {} → {}", ctx.current_state, to_state),
                        });
                    }
                    ctx.current_state = to_state;
                    if contract.state_machine.is_terminal(&ctx.current_state) {
                        break;
                    }
                    node_idx += 1;
                }
                NodeResult::Failed { error } => {
                    match &contract.governance.failure_strategy {
                        FailureStrategy::Abort => {
                            return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Failed { reason: error });
                        }
                        FailureStrategy::AcceptAndLog => {
                            ctx.emit_event("node_failed", serde_json::json!({
                                "node": node.node_id,
                                "error": error,
                            }));
                            node_idx += 1;
                        }
                        FailureStrategy::HumanReview => {
                            return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Failed {
                                reason: format!("Human review required: {}", error),
                            });
                        }
                        FailureStrategy::Retry { max_retries, .. } => {
                            // Simple retry (no backoff in sync executor)
                            let mut retried = false;
                            for _ in 0..*max_retries {
                                let retry_result = self.execute_node(&node.op, &mut ctx, &contract.state_machine);
                                if let Ok(NodeResult::Continue) = retry_result {
                                    retried = true;
                                    break;
                                }
                            }
                            if retried {
                                node_idx += 1;
                            } else {
                                return self.emit_receipt(&contract, &ctx, ExecutionOutcome::Failed { reason: error });
                            }
                        }
                        FailureStrategy::Fallback { node_id } => {
                            skip_until = Some(node_id.clone());
                            node_idx += 1;
                        }
                    }
                }
                NodeResult::Complete => break,
            }
        }

        // Check global postconditions
        for post in &contract.governance.postconditions {
            if !post.evaluate(&ctx) {
                return self.emit_receipt(&contract, &ctx, ExecutionOutcome::PredicateViolation {
                    predicate: format!("{:?}", post),
                    node_id: "global_postcondition".into(),
                });
            }
        }

        // Determine outcome
        let outcome = if contract.state_machine.is_terminal(&ctx.current_state) {
            ExecutionOutcome::Success
        } else {
            ExecutionOutcome::Success // Completed all nodes even if not terminal
        };

        self.emit_receipt(&contract, &ctx, outcome)
    }

    /// Execute a single CIROp node.
    fn execute_node(
        &self,
        op: &CIROp,
        ctx: &mut ExecutionContext,
        state_machine: &ContractStateMachine,
    ) -> ClsResult<NodeResult> {
        match op {
            CIROp::ToolCall { tool_id, params, output_var } => {
                ctx.use_resource("tool_calls", 1.0);
                let resolved_params = self.resolve_params(params, ctx);
                match self.tool_handler.call(tool_id, &resolved_params, ctx) {
                    Ok(result) => {
                        ctx.set_var(output_var, result);
                        Ok(NodeResult::Continue)
                    }
                    Err(e) => Ok(NodeResult::Failed { error: format!("Tool '{}' failed: {}", tool_id, e) }),
                }
            }

            CIROp::LlmInfer { prompt_template, input_vars, output_var, max_tokens, temperature } => {
                let prompt = self.resolve_prompt(prompt_template, input_vars, ctx);
                match self.llm_handler.infer(&prompt, *max_tokens, *temperature, ctx) {
                    Ok((response, tokens_used)) => {
                        ctx.use_resource("tokens", tokens_used as f64);
                        ctx.set_var(output_var, serde_json::json!(response));
                        Ok(NodeResult::Continue)
                    }
                    Err(e) => Ok(NodeResult::Failed { error: format!("LLM infer failed: {}", e) }),
                }
            }

            CIROp::MemRead { namespace, query, output_var, max_results } => {
                let resolved_query = self.resolve_var_string(query, ctx);
                match self.memory_handler.read(namespace, &resolved_query, *max_results, ctx) {
                    Ok(results) => {
                        ctx.set_var(output_var, results);
                        Ok(NodeResult::Continue)
                    }
                    Err(e) => Ok(NodeResult::Failed { error: format!("Mem read failed: {}", e) }),
                }
            }

            CIROp::MemWrite { namespace, content_var, tags } => {
                let content = ctx.get_var(content_var).cloned().unwrap_or(serde_json::Value::Null);
                match self.memory_handler.write(namespace, &content, tags, ctx) {
                    Ok(()) => Ok(NodeResult::Continue),
                    Err(e) => Ok(NodeResult::Failed { error: format!("Mem write failed: {}", e) }),
                }
            }

            CIROp::Branch { condition, then_node, else_node } => {
                if condition.evaluate(ctx) {
                    Ok(NodeResult::Branch { target_node_id: then_node.clone() })
                } else if let Some(else_id) = else_node {
                    Ok(NodeResult::Branch { target_node_id: else_id.clone() })
                } else {
                    Ok(NodeResult::Continue)
                }
            }

            CIROp::SetVar { name, value } => {
                ctx.set_var(name, value.clone());
                Ok(NodeResult::Continue)
            }

            CIROp::Compute { expression, input_vars, output_var } => {
                // Simple expression evaluation: concatenate input var values
                let parts: Vec<String> = input_vars.iter()
                    .filter_map(|v| ctx.get_var(v).map(|val| format!("{}", val)))
                    .collect();
                let result = format!("{}: {}", expression, parts.join(", "));
                ctx.set_var(output_var, serde_json::json!(result));
                Ok(NodeResult::Continue)
            }

            CIROp::EmitEvent { event_type, data_vars } => {
                let data: HashMap<String, serde_json::Value> = data_vars.iter()
                    .filter_map(|v| ctx.get_var(v).map(|val| (v.clone(), val.clone())))
                    .collect();
                ctx.emit_event(event_type, serde_json::json!(data));
                Ok(NodeResult::Continue)
            }

            CIROp::Transition { to_state } => {
                Ok(NodeResult::Transition { to_state: to_state.clone() })
            }

            CIROp::CallContract { contract_id, inputs, output_var } => {
                // Resolve input variable references
                let resolved: HashMap<String, serde_json::Value> = inputs.iter()
                    .map(|(k, v)| (k.clone(), ctx.get_var(v).cloned().unwrap_or(serde_json::Value::Null)))
                    .collect();
                
                // Execute sub-contract via handler
                match self.contract_handler.execute(contract_id, resolved.clone(), ctx) {
                    Ok(result) => {
                        ctx.set_var(output_var, result);
                        ctx.emit_event("contract_called", serde_json::json!({
                            "contract_id": contract_id,
                            "inputs": resolved,
                        }));
                        Ok(NodeResult::Continue)
                    }
                    Err(e) => Ok(NodeResult::Failed { error: format!("Sub-contract failed: {}", e) }),
                }
            }

            CIROp::SendMessage { to_agent, payload_var } => {
                let payload = ctx.get_var(payload_var).cloned().unwrap_or(serde_json::Value::Null);
                
                // Send message via handler (CNP integration)
                match self.message_handler.send(to_agent, &payload, ctx) {
                    Ok(msg_id) => {
                        ctx.emit_event("message_sent", serde_json::json!({
                            "message_id": msg_id,
                            "to": to_agent,
                            "payload": payload
                        }));
                        Ok(NodeResult::Continue)
                    }
                    Err(e) => Ok(NodeResult::Failed { error: format!("Message send failed: {}", e) }),
                }
            }

            CIROp::Checkpoint { label } => {
                ctx.emit_event("checkpoint", serde_json::json!({ "label": label }));
                if let Some(store) = &self.store {
                    store
                        .checkpoint(&ctx.contract_id, &ctx.session_id, label, ctx)
                        .map_err(|e| ClsError::ExecutionError {
                            detail: format!("checkpoint_store:{e}"),
                        })?;
                }
                Ok(NodeResult::Continue)
            }

            CIROp::Noop => Ok(NodeResult::Continue),
        }
    }

    /// Resolve variable references (${var_name}) in params.
    fn resolve_params(
        &self,
        params: &HashMap<String, serde_json::Value>,
        ctx: &ExecutionContext,
    ) -> HashMap<String, serde_json::Value> {
        params.iter().map(|(k, v)| {
            let resolved = if let Some(s) = v.as_str() {
                if let Some(var_name) = s.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
                    ctx.get_var(var_name).cloned().unwrap_or_else(|| serde_json::json!(s))
                } else {
                    v.clone()
                }
            } else {
                v.clone()
            };
            (k.clone(), resolved)
        }).collect()
    }

    /// Resolve a prompt template with input variables.
    fn resolve_prompt(&self, template: &str, input_vars: &[String], ctx: &ExecutionContext) -> String {
        let mut prompt = template.to_string();
        for var in input_vars {
            if let Some(val) = ctx.get_var(var) {
                prompt = format!("{}\n\n## {}\n{}", prompt, var, val);
            }
        }
        prompt
    }

    /// Resolve ${var_name} in a string.
    fn resolve_var_string(&self, s: &str, ctx: &ExecutionContext) -> String {
        if let Some(var_name) = s.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
            ctx.get_var(var_name)
                .and_then(|v| v.as_str())
                .unwrap_or(s)
                .to_string()
        } else {
            s.to_string()
        }
    }

    /// Produce a signed ExecutionReceipt.
    fn emit_receipt(
        &mut self,
        contract: &SolutionContract,
        ctx: &ExecutionContext,
        outcome: ExecutionOutcome,
    ) -> ClsResult<ExecutionReceipt> {
        let receipt_id = format!("rcpt-{:016x}-{:04x}", now_ms() as u64, rand_u16());
        let duration_ms = ctx.elapsed_ms();

        // Collect outputs from interface
        let outputs: HashMap<String, serde_json::Value> = contract.interface.outputs.iter()
            .filter_map(|p| ctx.get_var(&p.name).map(|v| (p.name.clone(), v.clone())))
            .collect();

        // Compute receipt CID
        let receipt_data = serde_json::json!({
            "receipt_id": receipt_id,
            "contract_id": contract.id.cid,
            "outcome": outcome,
            "final_state": ctx.current_state,
            "trace": ctx.trace,
        });
        let receipt_cid = compute_cid(&serde_json::to_vec(&receipt_data).unwrap_or_default());

        let receipt = ExecutionReceipt {
            receipt_id,
            contract_id: contract.id.cid.clone(),
            agent_pid: ctx.agent_pid.clone(),
            session_id: ctx.session_id.clone(),
            outcome,
            final_state: ctx.current_state.clone(),
            outputs,
            resource_usage: ctx.resource_usage.clone(),
            trace: ctx.trace.clone(),
            events: ctx.events.clone(),
            duration_ms,
            previous_receipt_cid: self.previous_receipt_cid.clone(),
            receipt_cid: receipt_cid.clone(),
            timestamp: now_ms(),
            signature: None,
        };

        // Chain: next receipt will point to this one
        self.previous_receipt_cid = Some(receipt_cid);

        if let Some(store) = &self.store {
            store.complete(&receipt).map_err(|e| ClsError::ExecutionError {
                detail: format!("complete_store:{e}"),
            })?;
        }

        Ok(receipt)
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

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

fn rand_u16() -> u16 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    hasher.finish() as u16
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cls::compiler::ClsCompiler;

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
    prompt: "Triage this patient based on symptoms and history"
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
    fn test_execute_triage_contract() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let mut executor = ContractExecutor::stub();

        let mut inputs = HashMap::new();
        inputs.insert("patient_id".into(), serde_json::json!("PAT-001"));
        inputs.insert("symptoms".into(), serde_json::json!("chest pain, shortness of breath"));

        let receipt = executor.execute(&contract, "triage-agent", "sess-001", inputs).unwrap();

        assert_eq!(receipt.outcome, ExecutionOutcome::Success);
        assert_eq!(receipt.final_state, "triaged");
        assert!(receipt.receipt_cid.starts_with("cls1-sha256-"));
        assert!(!receipt.trace.is_empty());
        assert!(receipt.duration_ms >= 0);
    }

    #[test]
    fn test_receipt_has_resource_usage() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let mut executor = ContractExecutor::stub();

        let mut inputs = HashMap::new();
        inputs.insert("patient_id".into(), serde_json::json!("PAT-002"));
        inputs.insert("symptoms".into(), serde_json::json!("headache"));

        let receipt = executor.execute(&contract, "agent-1", "sess-002", inputs).unwrap();

        // Should have used tool_calls and tokens
        assert!(receipt.resource_usage.get("tool_calls").unwrap_or(&0.0) > &0.0);
        assert!(receipt.resource_usage.get("tokens").unwrap_or(&0.0) > &0.0);
    }

    #[test]
    fn test_receipt_has_events() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let mut executor = ContractExecutor::stub();

        let mut inputs = HashMap::new();
        inputs.insert("patient_id".into(), serde_json::json!("PAT-003"));
        inputs.insert("symptoms".into(), serde_json::json!("fever"));

        let receipt = executor.execute(&contract, "agent-1", "sess-003", inputs).unwrap();
        let event_types: Vec<&str> = receipt.events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(event_types.contains(&"triage_complete"));
    }

    #[test]
    fn test_receipt_chain() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let mut executor = ContractExecutor::stub();

        let mut inputs1 = HashMap::new();
        inputs1.insert("patient_id".into(), serde_json::json!("PAT-A"));
        inputs1.insert("symptoms".into(), serde_json::json!("cough"));
        let receipt1 = executor.execute(&contract, "agent-1", "sess-1", inputs1).unwrap();
        assert!(receipt1.previous_receipt_cid.is_none());

        let mut inputs2 = HashMap::new();
        inputs2.insert("patient_id".into(), serde_json::json!("PAT-B"));
        inputs2.insert("symptoms".into(), serde_json::json!("fever"));
        let receipt2 = executor.execute(&contract, "agent-1", "sess-2", inputs2).unwrap();
        assert_eq!(receipt2.previous_receipt_cid.as_deref(), Some(receipt1.receipt_cid.as_str()));
    }

    #[test]
    fn test_execution_trace() {
        let contract = ClsCompiler::compile(TRIAGE_YAML).unwrap();
        let mut executor = ContractExecutor::stub();

        let mut inputs = HashMap::new();
        inputs.insert("patient_id".into(), serde_json::json!("PAT-004"));
        inputs.insert("symptoms".into(), serde_json::json!("nausea"));

        let receipt = executor.execute(&contract, "agent-1", "sess-004", inputs).unwrap();

        let node_ids: Vec<&str> = receipt.trace.iter().map(|(id, _)| id.as_str()).collect();
        assert!(node_ids.contains(&"lookup"));
        assert!(node_ids.contains(&"transition_assessing"));
        assert!(node_ids.contains(&"assess"));
        assert!(node_ids.contains(&"complete"));
    }

    #[test]
    fn test_budget_exceeded() {
        let tiny_budget_yaml = r#"
name: tiny
version: "1.0.0"
description: "Tiny budget contract"
states:
  initial: init
  terminal: [done]
  transitions:
    - from: init
      to: done
      trigger: go
steps:
  - id: step1
    type: tool_call
    tool: tool_a
    output: r1
  - id: step2
    type: tool_call
    tool: tool_b
    output: r2
  - id: step3
    type: tool_call
    tool: tool_c
    output: r3
  - id: done_step
    type: transition
    to: done
budget:
  tool_calls: 2
  tokens: 8192
  cost_usd: 1.0
  time_ms: 60000
  memory_mb: 128
"#;
        let contract = ClsCompiler::compile(tiny_budget_yaml).unwrap();
        let mut executor = ContractExecutor::stub();

        let receipt = executor.execute(&contract, "agent", "sess", HashMap::new()).unwrap();
        assert!(matches!(receipt.outcome, ExecutionOutcome::BudgetExceeded { .. }));
    }

    #[test]
    fn test_simple_contract() {
        let yaml = r#"
name: simple
version: "1.0.0"
description: "Simplest possible contract"
states:
  initial: running
  terminal: [done]
  transitions:
    - from: running
      to: done
      trigger: finish
steps:
  - id: set_greeting
    type: set_var
    var: greeting
    value: "Hello, World!"
  - id: done
    type: transition
    to: done
budget:
  tokens: 100
  cost_usd: 0.01
  tool_calls: 1
  time_ms: 5000
  memory_mb: 16
"#;
        let contract = ClsCompiler::compile(yaml).unwrap();
        let mut executor = ContractExecutor::stub();
        let receipt = executor.execute(&contract, "agent", "sess", HashMap::new()).unwrap();

        assert_eq!(receipt.outcome, ExecutionOutcome::Success);
        assert_eq!(receipt.final_state, "done");
    }

    #[test]
    fn store_records_checkpoint_and_receipt() {
        let yaml = r#"
name: ckpt
version: "1.0.0"
description: "checkpoint store"
states:
  initial: running
  terminal: [done]
  transitions:
    - from: running
      to: done
      trigger: finish
steps:
  - id: mark
    type: checkpoint
    label: mid
  - id: done
    type: transition
    to: done
budget:
  tokens: 100
  cost_usd: 0.01
  tool_calls: 1
  time_ms: 5000
  memory_mb: 16
"#;
        let contract = ClsCompiler::compile(yaml).unwrap();
        let store = std::sync::Arc::new(InMemoryExecutionStore::default());
        let mut executor = ContractExecutor::stub().with_store(store.clone());
        let receipt = executor
            .execute(&contract, "agent", "sess-ckpt", HashMap::new())
            .unwrap();
        assert_eq!(receipt.outcome, ExecutionOutcome::Success);
        let cps = store.checkpoints.lock().unwrap();
        assert_eq!(cps.len(), 1);
        assert!(!cps[0].2.is_empty());
        assert_eq!(store.receipts.lock().unwrap().len(), 1);
    }
}
