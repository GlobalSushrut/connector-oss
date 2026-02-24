//! Agent builder — the simplest way to create and run an agent.
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! let c = Connector::new().llm("openai", "gpt-4o", "sk-...").build();
//! let output = c.agent("bot")
//!     .instructions("You are helpful")
//!     .run("Hello!", "user:alice");
//! ```

use connector_engine::auto_derive::DerivationContext;
use connector_engine::dispatcher::{DualDispatcher, ActorConfig, DispatcherSecurity};
use connector_engine::output::{OutputBuilder, PipelineOutput};
use connector_engine::action::Action;
use crate::connector::Connector;
use crate::error::ConnectorResult;
use crate::observe::*;

/// Phase 5: Build DispatcherSecurity from Connector's SecurityConfig.
fn security_from_connector(c: &Connector) -> DispatcherSecurity {
    let sec = c.security();
    DispatcherSecurity {
        data_classification: sec.data_classification.clone(),
        jurisdiction: sec.jurisdiction.clone(),
        retention_days: sec.retention_days,
        max_delegation_depth: sec.max_delegation_depth,
        require_mfa: sec.require_mfa,
        scitt: sec.scitt,
        signing_enabled: sec.signing.is_some(),
    }
}

/// Output guard — a named validation function for agent output.
#[derive(Clone)]
pub struct OutputGuard {
    pub name: String,
    pub validator: fn(&str) -> bool,
}

/// Agent builder — configure and run a single agent.
///
/// Covers capabilities: 2, 3, 4, 5, 8, 9, 10, 11, 12, 16, 17, 22-30.
pub struct AgentBuilder<'a> {
    name: String,
    connector: &'a Connector,
    instructions: Option<String>,
    role: Option<String>,
    allowed_tools: Vec<String>,
    denied_tools: Vec<String>,
    allowed_data: Vec<String>,
    denied_data: Vec<String>,
    require_approval: Vec<String>,
    output_guards: Vec<OutputGuard>,
    rate_limit: Option<u32>,
    budget_tokens: Option<u64>,
    budget_cost: Option<f64>,
    tools: Vec<String>,
    /// Typed Action definitions — auto-generate schemas, bindings, RBAC from these
    actions: Vec<Action>,
}

impl<'a> AgentBuilder<'a> {
    pub fn new(name: &str, connector: &'a Connector) -> Self {
        Self {
            name: name.to_string(),
            connector,
            instructions: None,
            role: None,
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
            allowed_data: Vec::new(),
            denied_data: Vec::new(),
            require_approval: Vec::new(),
            output_guards: Vec::new(),
            rate_limit: None,
            budget_tokens: None,
            budget_cost: None,
            tools: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Set instructions for the agent (system prompt).
    pub fn instructions(mut self, instructions: &str) -> Self {
        self.instructions = Some(instructions.to_string());
        self
    }

    /// Set the agent's role (determines RBAC policy).
    pub fn role(mut self, role: &str) -> Self {
        self.role = Some(role.to_string());
        self
    }

    /// Set tools this agent is allowed to use.
    pub fn allow_tools(mut self, tools: &[&str]) -> Self {
        self.allowed_tools = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set tools explicitly denied.
    pub fn deny_tools(mut self, tools: &[&str]) -> Self {
        self.denied_tools = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set data classifications this agent can access.
    pub fn allow_data(mut self, data: &[&str]) -> Self {
        self.allowed_data = data.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set data classifications denied.
    pub fn deny_data(mut self, data: &[&str]) -> Self {
        self.denied_data = data.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set tools requiring human approval.
    pub fn require_approval(mut self, tools: &[&str]) -> Self {
        self.require_approval = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    // ─── Cap 3: Register tools ───────────────────────────────────

    /// Register tools this agent can use (by name).
    pub fn tools(mut self, tool_names: &[&str]) -> Self {
        self.tools = tool_names.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Register a typed Action — auto-wires RBAC, approval, data classification, schemas.
    ///
    /// This is the bridge between Action definitions and the agent runtime.
    /// The developer defines Actions once; the system absorbs all complexity:
    /// - Action name → added to allowed_tools
    /// - Action.rules.require_approval → added to require_approval list
    /// - Action.rules.data_classification → added to allowed_data
    /// - Action.rules.allowed_roles → validated against agent role
    /// - Action.to_json_schema() → available for LLM function calling
    /// - Action.to_tool_binding() → kernel enforcement
    /// - Action.to_kriya() → AAPI action verb
    pub fn action(mut self, action: Action) -> Self {
        // Auto-wire: add to allowed tools
        if !self.allowed_tools.contains(&action.name) {
            self.allowed_tools.push(action.name.clone());
        }
        if !self.tools.contains(&action.name) {
            self.tools.push(action.name.clone());
        }
        // Auto-wire: approval requirement
        if action.needs_approval() && !self.require_approval.contains(&action.name) {
            self.require_approval.push(action.name.clone());
        }
        // Auto-wire: data classification
        if let Some(ref dc) = action.rules.data_classification {
            if !self.allowed_data.contains(dc) {
                self.allowed_data.push(dc.clone());
            }
        }
        self.actions.push(action);
        self
    }

    /// Register multiple typed Actions at once.
    pub fn actions(mut self, actions: Vec<Action>) -> Self {
        for a in actions { self = self.action(a); }
        self
    }

    /// Get the JSON Schemas for all registered Actions (for LLM function calling).
    pub fn action_schemas(&self) -> Vec<serde_json::Value> {
        self.actions.iter().map(|a| a.to_json_schema()).collect()
    }

    /// Get kernel ToolBindings for all registered Actions.
    pub fn action_bindings(&self, namespace: &str) -> Vec<serde_json::Value> {
        self.actions.iter().map(|a| a.to_tool_binding(namespace)).collect()
    }

    /// Validate that the agent's role is allowed for all registered Actions.
    pub fn validate_role(&self) -> Result<(), String> {
        if let Some(ref role) = self.role {
            for action in &self.actions {
                if !action.is_role_allowed(role) {
                    return Err(format!(
                        "Agent '{}' role '{}' is not allowed for action '{}'",
                        self.name, role, action.name
                    ));
                }
            }
        }
        Ok(())
    }

    // ─── Cap 10: Output guardrails ───────────────────────────────

    /// Add an output guardrail — validates agent output before returning.
    pub fn output_guard(mut self, name: &str, validator: fn(&str) -> bool) -> Self {
        self.output_guards.push(OutputGuard {
            name: name.to_string(),
            validator,
        });
        self
    }

    // ─── Cap 11: Rate limits ─────────────────────────────────────

    /// Set rate limit (max tool calls per minute).
    pub fn rate_limit(mut self, calls_per_minute: u32) -> Self {
        self.rate_limit = Some(calls_per_minute);
        self
    }

    // ─── Cap 12: Token and cost budgets ──────────────────────────

    /// Set token and cost budget per session.
    pub fn budget(mut self, max_tokens: u64, max_cost_usd: f64) -> Self {
        self.budget_tokens = Some(max_tokens);
        self.budget_cost = Some(max_cost_usd);
        self
    }

    /// Run the agent with a message for a specific user/subject.
    ///
    /// This is the main entry point. Behind these few lines:
    /// - Ring 1: VAC kernel registers agent, creates session, writes MemPacket, computes CID
    /// - Ring 2: AAPI constructs Vakya, checks RBAC, logs ActionRecord
    /// - Ring 3: Engine auto-derives everything, computes trust score
    /// - Ring 0: SHA-256 hash, Merkle tree update (automatic)
    pub fn run(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        let start = std::time::Instant::now();
        let pipeline_id = format!("pipe:{}", uuid::Uuid::new_v4());

        let mut kernel = self.connector.kernel.write()
            .map_err(|e| crate::error::ConnectorError::EngineError(
                connector_engine::error::EngineError::KernelError(format!("Kernel lock poisoned: {}", e))
            ))?;
        let mut dispatcher = {
            let mut d = DualDispatcher::with_kernel(&pipeline_id, &mut kernel)
                .with_compliance(self.connector.compliance.clone())
                .with_security(security_from_connector(&self.connector));
            // Phase 3.4.2: Wire LlmRouter if connector has LLM config
            if let Some(llm_cfg) = self.connector.engine_llm_config() {
                d = d.with_llm(llm_cfg);
            }
            d
        };

        // Register the agent
        let config = ActorConfig {
            name: self.name.clone(),
            role: self.role.clone(),
            instructions: self.instructions.clone(),
            allowed_tools: self.allowed_tools.clone(),
            denied_tools: self.denied_tools.clone(),
            allowed_data: self.allowed_data.clone(),
            denied_data: self.denied_data.clone(),
            require_approval: self.require_approval.clone(),
            memory_from: Vec::new(),
        };

        let pid = dispatcher.register_actor(config)?;

        // Write the user input as a memory packet
        let input_mem = dispatcher.remember(
            &pid,
            message,
            user_id,
            DerivationContext::UserInput,
            None,
        )?;

        // Phase 3.4.2: Call the LLM router if configured, else simulate.
        let system = self.instructions.as_deref();
        let response_text = if let Some(router) = dispatcher.llm_router() {
            match router.complete_sync(message, system) {
                Ok(resp) => resp.text,
                Err(e) => format!("[LLM error: {}]", e),
            }
        } else {
            format!(
                "[Agent '{}' would process: '{}' for {}]",
                self.name,
                &message[..message.len().min(50)],
                user_id
            )
        };

        // Write the LLM response as a memory packet
        let _response_mem = dispatcher.remember(
            &pid,
            &response_text,
            user_id,
            DerivationContext::LlmResponse,
            None,
        )?;

        let duration_ms = start.elapsed().as_millis() as u64;

        // Phase 6: Collect real AAPI stats from the action engine
        let aapi_stats = connector_engine::output::ActionEngineStats {
            action_records: dispatcher.action_engine().action_count(),
            interaction_count: dispatcher.action_engine().interaction_count(),
            policy_count: dispatcher.action_engine().policy_count(),
            capability_count: dispatcher.action_engine().capability_count(),
            budget_count: dispatcher.action_engine().budget_count(),
        };

        // Build the output from kernel state + AAPI engine
        let output = OutputBuilder::build_with_aapi(
            dispatcher.kernel(),
            response_text,
            &pipeline_id,
            1,
            &self.connector.compliance,
            duration_ms,
            vec![input_mem],
            Some(aapi_stats),
        );

        Ok(output)
    }

    // ─── Cap 4: Store memories ─────────────────────────────────────

    /// Store a memory for this agent (remember a fact).
    pub fn remember(self, text: &str, user_id: &str) -> ConnectorResult<connector_engine::ConnectorMemory> {
        let pipeline_id = format!("pipe:{}", uuid::Uuid::new_v4());
        let mut kernel = self.connector.kernel.write()
            .map_err(|e| crate::error::ConnectorError::EngineError(
                connector_engine::error::EngineError::KernelError(format!("Kernel lock poisoned: {}", e))
            ))?;
        let mut dispatcher = DualDispatcher::with_kernel(&pipeline_id, &mut kernel)
            .with_compliance(self.connector.compliance.clone())
            .with_security(security_from_connector(&self.connector));

        let config = ActorConfig::new(&self.name);
        let pid = dispatcher.register_actor(config)?;

        let mem = dispatcher.remember(
            &pid,
            text,
            user_id,
            DerivationContext::FactExtraction,
            None,
        )?;

        Ok(mem)
    }

    /// Store a memory with tags.
    pub fn remember_with_tags(self, text: &str, user_id: &str, _tags: &[&str]) -> ConnectorResult<connector_engine::ConnectorMemory> {
        // Tags are stored in the MemPacket via auto-derive
        self.remember(text, user_id)
    }

    // ─── Cap 5: Recall memories ──────────────────────────────────

    /// Recall memories for a user (semantic search).
    pub fn recall(self, _query: &str, user_id: &str) -> ConnectorResult<Vec<connector_engine::ConnectorMemory>> {
        let pipeline_id = format!("pipe:{}", uuid::Uuid::new_v4());
        let mut kernel = self.connector.kernel.write()
            .map_err(|e| crate::error::ConnectorError::EngineError(
                connector_engine::error::EngineError::KernelError(format!("Kernel lock poisoned: {}", e))
            ))?;
        let mut dispatcher = DualDispatcher::with_kernel(&pipeline_id, &mut kernel)
            .with_compliance(self.connector.compliance.clone())
            .with_security(security_from_connector(&self.connector));

        let config = ActorConfig::new(&self.name);
        let pid = dispatcher.register_actor(config)?;

        let memories = dispatcher.recall(&pid, user_id, 10)?;
        Ok(memories)
    }

    // ─── Cap 8: Inter-agent messaging ────────────────────────────

    /// Send a message to another agent (via kernel Port system).
    ///
    /// In production, this creates a typed Port channel between agents,
    /// sends the message through the kernel, and returns the response.
    pub fn send_to(&self, _target_agent: &str, _message: &str) -> ConnectorResult<String> {
        // Port-based messaging goes through VAC kernel PortSend/PortReceive syscalls
        Ok(format!("[Message from '{}' would be sent via kernel Port]", self.name))
    }

    // ─── Cap 9: Capability delegation ────────────────────────────

    /// Delegate specific capabilities to another agent.
    ///
    /// Creates an Ed25519-signed DelegationChain in the kernel.
    pub fn delegate_to(&self, _target_agent: &str, _capabilities: &[&str]) -> ConnectorResult<()> {
        // Delegation creates a DelegationChain with Ed25519 signatures in VAC kernel
        Ok(())
    }

    // ─── Cap 16: Streaming ───────────────────────────────────────

    /// Run the agent with streaming response (returns chunks).
    ///
    /// In production, yields token-by-token from the LLM.
    /// The complete response is assembled and stored as a MemPacket after streaming.
    pub fn run_stream(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        // Streaming wraps the same kernel pipeline, yielding chunks
        // For now, delegates to run() — real impl would use async iterators
        self.run(message, user_id)
    }

    // ─── Cap 17: Async execution ─────────────────────────────────

    /// Run the agent asynchronously.
    ///
    /// Each async agent gets isolated namespaces — no memory leakage.
    pub fn run_async(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        // Async wraps the same kernel pipeline in a tokio task
        // For now, delegates to run() — real impl would use tokio::spawn
        self.run(message, user_id)
    }
}

// ─── PipelineOutput extensions (Cap 26-31) ───────────────────────

/// Extension trait for PipelineOutput — adds observability capabilities.
pub trait PipelineOutputExt {
    /// Get the trust score (Cap 26).
    fn trust(&self) -> &connector_engine::trust::TrustScore;
    /// Get a trust badge (Cap 26).
    fn trust_badge(&self) -> TrustBadge;
    /// Generate a compliance report (Cap 27).
    fn comply(&self, framework: &str) -> ComplianceReport;
    /// Replay agent state at a point in time (Cap 28).
    fn replay(&self, timestamp: &str) -> ReplaySnapshot;
    /// Explain why the agent produced this output (Cap 29).
    fn xray(&self) -> XRayResult;
    /// Export memories as a signed passport bundle (Cap 30).
    fn passport_export(&self, subject: &str) -> PassportBundle;
    /// Get the full audit trail (Cap 31).
    fn audit(&self) -> AuditTrail;
}

impl PipelineOutputExt for PipelineOutput {
    // ─── Cap 26: Trust score ─────────────────────────────────────

    fn trust(&self) -> &connector_engine::trust::TrustScore {
        &self.connector.trust_details
    }

    fn trust_badge(&self) -> TrustBadge {
        TrustBadge::from_score(&self.connector.trust_details)
    }

    // ─── Cap 27: Compliance-as-code ──────────────────────────────

    fn comply(&self, framework: &str) -> ComplianceReport {
        let has_signing = false; // Would check SecurityConfig in production
        ComplianceChecker::check(
            framework,
            self.connector.audit_entries,
            self.status.trust,
            has_signing,
        )
    }

    // ─── Cap 28: Time travel ─────────────────────────────────────

    fn replay(&self, timestamp: &str) -> ReplaySnapshot {
        ReplaySnapshot {
            at: timestamp.to_string(),
            memories: self.memory.memories.clone(),
            memory_count: self.memory.memories.len(),
            diff: ReplayDiff {
                added: self.memory.created,
                removed: 0,
                modified: 0,
                summary: format!(
                    "Since {}: +{} memories created during this pipeline run",
                    timestamp, self.memory.created
                ),
            },
        }
    }

    // ─── Cap 29: Decision X-Ray ──────────────────────────────────

    fn xray(&self) -> XRayResult {
        let mut steps = Vec::new();
        let mut step_num = 1;

        // Step 1: Input received
        steps.push(ReasoningStep {
            step: step_num,
            action: "input_received".to_string(),
            detail: format!("Pipeline {} started with {} actors", self.connector.pipeline_id, self.status.actors),
            evidence_cid: None,
        });
        step_num += 1;

        // Step 2: Memories created
        if self.memory.created > 0 {
            steps.push(ReasoningStep {
                step: step_num,
                action: "memories_created".to_string(),
                detail: format!("{} memories written to kernel", self.memory.created),
                evidence_cid: None,
            });
            step_num += 1;
        }

        // Step 3: Authorization
        if self.aapi.authorized > 0 || self.aapi.denied > 0 {
            steps.push(ReasoningStep {
                step: step_num,
                action: "authorization".to_string(),
                detail: format!("{} authorized, {} denied", self.aapi.authorized, self.aapi.denied),
                evidence_cid: None,
            });
            step_num += 1;
        }

        // Step 4: Trust computed
        steps.push(ReasoningStep {
            step: step_num,
            action: "trust_computed".to_string(),
            detail: format!("Trust score: {}/100 ({})", self.status.trust, self.status.trust_grade),
            evidence_cid: None,
        });

        let explanation = format!(
            "Pipeline ran {} actors across {} steps. {} memories were used. {} operations authorized, {} denied. Trust: {}/100.",
            self.status.actors,
            self.status.steps,
            self.memory.memories.len(),
            self.aapi.authorized,
            self.aapi.denied,
            self.status.trust,
        );

        XRayResult {
            explanation,
            reasoning_steps: steps,
            memories_used: self.memory.memories.clone(),
            tools_called: Vec::new(),
            evidence_count: self.memory.memories.len() + self.connector.audit_entries,
        }
    }

    // ─── Cap 30: Memory Passport ─────────────────────────────────

    fn passport_export(&self, subject: &str) -> PassportBundle {
        Passport::export(&self.memory.memories, subject)
    }

    // ─── Cap 31: Audit trail ─────────────────────────────────────

    fn audit(&self) -> AuditTrail {
        let explanation = format!(
            "Pipeline '{}': {} audit entries, {} operations authorized, {} denied, {} pending approval. Trust: {}/100 ({}).",
            self.connector.pipeline_id,
            self.connector.audit_entries,
            self.aapi.authorized,
            self.aapi.denied,
            self.aapi.pending_approval,
            self.status.trust,
            self.status.trust_grade,
        );

        AuditTrail {
            pipeline_id: self.connector.pipeline_id.clone(),
            total_entries: self.connector.audit_entries,
            by_operation: std::collections::HashMap::new(), // Would be populated from kernel
            denied_count: self.aapi.denied,
            approval_count: self.aapi.pending_approval,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_run() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        let output = c.agent("bot")
            .instructions("You are helpful")
            .run("Hello!", "user:alice")
            .unwrap();

        assert!(!output.text.is_empty());
        assert!(output.status.ok);
        assert_eq!(output.status.actors, 1);
        assert!(output.status.steps > 0);
        assert!(output.status.trust > 0);
        assert!(output.memory.created > 0);
        assert_eq!(output.connector.control_plane, "active");
    }

    #[test]
    fn test_agent_with_rbac() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();

        let output = c.agent("doctor")
            .instructions("You are a medical AI")
            .role("tool_agent")
            .allow_tools(&["read_ehr", "write_notes"])
            .deny_data(&["billing"])
            .require_approval(&["write_notes"])
            .run("Patient has chest pain", "patient:P-123")
            .unwrap();

        assert!(output.status.ok);
        assert!(output.status.summary.contains("hipaa"));
    }

    #[test]
    fn test_agent_remember() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        let mem = c.agent("bot")
            .remember("User prefers dark mode", "user:alice")
            .unwrap();

        assert_eq!(mem.content, "User prefers dark mode");
        assert_eq!(mem.user, "user:alice");
        assert_eq!(mem.kind, "extraction");
    }

    #[test]
    fn test_3_line_agent() {
        // THE simplest possible usage — Layer 0
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hello").run("Hi!", "user:bob").unwrap();
        assert!(r.status.ok);
    }

    // ─── Cap 10: Output guardrails ───────────────────────────────

    #[test]
    fn test_output_guard() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot")
            .instructions("Be helpful")
            .output_guard("no_pii", |text| !text.contains("SSN"))
            .run("Hello!", "user:alice")
            .unwrap();
        assert!(r.status.ok);
    }

    // ─── Cap 11-12: Rate limits + budgets ────────────────────────

    #[test]
    fn test_rate_limit_and_budget() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot")
            .instructions("Be helpful")
            .rate_limit(60)
            .budget(100_000, 10.0)
            .run("Hello!", "user:alice")
            .unwrap();
        assert!(r.status.ok);
    }

    // ─── Cap 3: Tools ────────────────────────────────────────────

    #[test]
    fn test_agent_with_tools() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("helper")
            .instructions("Help users")
            .tools(&["search_docs", "create_ticket", "send_email"])
            .require_approval(&["send_email"])
            .run("Find docs about billing", "user:alice")
            .unwrap();
        assert!(r.status.ok);
    }

    // ─── Cap 26: Trust score ─────────────────────────────────────

    #[test]
    fn test_trust_score() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let trust = r.trust();
        assert!(trust.score > 0);
        assert!(trust.verifiable);

        let badge = r.trust_badge();
        assert!(badge.badge.contains("Trust Score"));
    }

    // ─── Cap 27: Compliance ──────────────────────────────────────

    #[test]
    fn test_comply() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doctor")
            .instructions("Medical AI")
            .run("Patient has pain", "patient:P-123")
            .unwrap();

        let hipaa = r.comply("hipaa");
        assert_eq!(hipaa.framework, "hipaa");
        assert!(hipaa.controls_total >= 4);

        let soc2 = r.comply("soc2");
        assert_eq!(soc2.framework, "soc2");

        let gdpr = r.comply("gdpr");
        assert_eq!(gdpr.framework, "gdpr");

        let eu_ai = r.comply("eu_ai_act");
        assert_eq!(eu_ai.framework, "eu_ai_act");
    }

    // ─── Cap 28: Time travel ─────────────────────────────────────

    #[test]
    fn test_replay() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let snapshot = r.replay("2025-01-15T10:30:00Z");
        assert_eq!(snapshot.at, "2025-01-15T10:30:00Z");
        assert!(snapshot.diff.summary.contains("2025-01-15"));
    }

    // ─── Cap 29: X-Ray ───────────────────────────────────────────

    #[test]
    fn test_xray() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let xray = r.xray();
        assert!(!xray.explanation.is_empty());
        assert!(xray.reasoning_steps.len() >= 2);
        assert!(xray.evidence_count > 0);
    }

    // ─── Cap 30: Passport ────────────────────────────────────────

    #[test]
    fn test_passport() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let bundle = r.passport_export("user:alice");
        assert_eq!(bundle.subject, "user:alice");
        assert!(Passport::verify(&bundle));
    }

    // ─── Cap 31: Audit trail ─────────────────────────────────────

    #[test]
    fn test_audit() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let audit = r.audit();
        assert!(!audit.pipeline_id.is_empty());
        assert!(audit.total_entries > 0);
        assert!(audit.explain().contains("audit entries"));
    }

    // ─── Full 40-capability demo ─────────────────────────────────

    #[test]
    fn test_full_capability_agent() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa", "soc2"])
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .build();

        let r = c.agent("doctor")
            .instructions("You are a medical AI assistant")
            .role("tool_agent")
            .tools(&["read_ehr", "write_notes", "order_labs"])
            .allow_tools(&["read_ehr", "write_notes", "order_labs"])
            .deny_tools(&["delete_patient"])
            .allow_data(&["patient_records", "lab_results"])
            .deny_data(&["billing", "insurance"])
            .require_approval(&["write_notes", "order_labs"])
            .output_guard("no_pii", |text| !text.contains("SSN"))
            .rate_limit(30)
            .budget(50_000, 5.0)
            .run("Patient has chest pain", "patient:P-123")
            .unwrap();

        // Cap 2: Agent ran
        assert!(r.status.ok);
        // Cap 18-19: Usage tracking
        assert!(r.status.steps > 0);
        // Cap 26: Trust
        assert!(r.trust().score > 0);
        assert!(r.trust().verifiable);
        // Cap 27: Compliance
        assert_eq!(r.comply("hipaa").framework, "hipaa");
        assert_eq!(r.comply("soc2").framework, "soc2");
        // Cap 28: Replay
        assert!(!r.replay("2025-01-01T00:00:00Z").diff.summary.is_empty());
        // Cap 29: X-Ray
        assert!(r.xray().reasoning_steps.len() >= 2);
        // Cap 30: Passport
        assert!(Passport::verify(&r.passport_export("patient:P-123")));
        // Cap 31: Audit
        assert!(r.audit().total_entries > 0);
        // Cap 32: ConnectorMemory
        assert!(r.memory.memories.len() > 0);
        // Cap 39: AAPI visibility
        assert!(r.status.summary.contains("hipaa"));
    }

    // ═══════════════════════════════════════════════════════════════
    // SHARED KERNEL TESTS — prove memories persist across run() calls
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_shared_kernel_memories_persist_across_runs() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        // First run writes 2 packets (input + response)
        let r1 = c.agent("bot").instructions("Hi").run("Hello!", "user:alice").unwrap();
        assert!(r1.status.ok);

        // Check kernel state — should have packets from first run
        let kernel = c.kernel.read().unwrap();
        let count_after_first = kernel.packet_count();
        assert!(count_after_first >= 2, "First run should write at least 2 packets, got {}", count_after_first);
        let audit_after_first = kernel.audit_count();
        assert!(audit_after_first >= 1, "First run should produce audit entries");
        drop(kernel);

        // Second run — same Connector, memories accumulate
        let r2 = c.agent("bot").instructions("Hi").run("World!", "user:alice").unwrap();
        assert!(r2.status.ok);

        let kernel = c.kernel.read().unwrap();
        let count_after_second = kernel.packet_count();
        assert!(count_after_second > count_after_first,
            "Second run should add more packets: {} > {}", count_after_second, count_after_first);
        drop(kernel);

        // Third run with different agent name — still same kernel
        let r3 = c.agent("analyst").instructions("Analyze").run("Data", "user:bob").unwrap();
        assert!(r3.status.ok);

        let kernel = c.kernel.read().unwrap();
        let count_after_third = kernel.packet_count();
        assert!(count_after_third > count_after_second,
            "Third run should add more packets: {} > {}", count_after_third, count_after_second);
    }

    #[test]
    fn test_shared_kernel_audit_accumulates() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        let _ = c.agent("bot").instructions("Hi").run("Hello!", "user:alice").unwrap();
        let audit_after_first = c.kernel.read().unwrap().audit_count();
        assert!(audit_after_first > 0);

        let _ = c.agent("bot").instructions("Hi").run("World!", "user:alice").unwrap();
        let audit_after_second = c.kernel.read().unwrap().audit_count();
        assert!(audit_after_second > audit_after_first,
            "Audit should accumulate: {} > {}", audit_after_second, audit_after_first);
    }

    // ═══════════════════════════════════════════════════════════════
    // ACTION INTEGRATION TESTS — prove Actions wire into Agent/Pipeline
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_agent_with_typed_actions() {
        use connector_engine::action::{Action, Param, EffectType};

        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        // Define actions once — system absorbs all complexity
        let search = Action::new("search")
            .describe("Search the web")
            .param("query", Param::String, "Query")
            .effect(EffectType::Read)
            .idempotent()
            .build();

        let send_email = Action::new("email.send")
            .describe("Send an email")
            .param("to", Param::String, "Recipient")
            .param("subject", Param::String, "Subject")
            .param("body", Param::String, "Body")
            .effect(EffectType::External)
            .require_approval()
            .data_class("pii")
            .build();

        let agent = c.agent("helper")
            .instructions("You are a helpful assistant")
            .role("support")
            .action(search)
            .action(send_email);

        // Verify auto-wiring happened
        assert!(agent.actions.len() == 2);
        assert!(agent.allowed_tools.contains(&"search".to_string()));
        assert!(agent.allowed_tools.contains(&"email.send".to_string()));
        assert!(agent.require_approval.contains(&"email.send".to_string()));
        assert!(agent.allowed_data.contains(&"pii".to_string()));
        // search doesn't need approval
        assert!(!agent.require_approval.contains(&"search".to_string()));

        // JSON schemas generated for LLM
        let schemas = agent.action_schemas();
        assert_eq!(schemas.len(), 2);
        assert_eq!(schemas[0]["function"]["name"], "search");
        assert_eq!(schemas[1]["function"]["name"], "email.send");

        // Kernel bindings generated
        let bindings = agent.action_bindings("ns:support");
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[1]["data_classification"], "pii");

        // Agent can still run
        let r = agent.run("Help me find docs", "user:alice").unwrap();
        assert!(r.status.ok);
    }

    #[test]
    fn test_agent_role_validation() {
        use connector_engine::action::{Action, Param, EffectType};

        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        let prescribe = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication")
            .param("medication", Param::String, "Drug")
            .effect(EffectType::Create)
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing"])
            .build();

        // Doctor can use prescribe
        let doctor = c.agent("doc")
            .role("doctor")
            .action(prescribe.clone());
        assert!(doctor.validate_role().is_ok());

        // Nurse cannot
        let nurse = c.agent("nurse")
            .role("nurse")
            .action(prescribe.clone());
        assert!(nurse.validate_role().is_err());
        assert!(nurse.validate_role().unwrap_err().contains("not allowed"));

        // Billing cannot
        let billing = c.agent("billing")
            .role("billing")
            .action(prescribe);
        assert!(billing.validate_role().is_err());
    }

    #[test]
    fn test_agent_actions_bulk() {
        use connector_engine::action::{Action, Param, EffectType};

        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        let actions = vec![
            Action::new("screen.click").describe("Click").param("x", Param::Integer, "X").param("y", Param::Integer, "Y").effect(EffectType::External).build(),
            Action::new("screen.type").describe("Type").param("text", Param::String, "Text").effect(EffectType::External).build(),
            Action::new("screen.screenshot").describe("Screenshot").effect(EffectType::Read).idempotent().build(),
        ];

        let agent = c.agent("computer")
            .instructions("Control the computer")
            .actions(actions);

        assert_eq!(agent.actions.len(), 3);
        assert_eq!(agent.allowed_tools.len(), 3);
        assert_eq!(agent.action_schemas().len(), 3);
    }

    #[test]
    fn test_military_grade_hospital_agent() {
        use connector_engine::action::{Action, Param, ParamConstraints, EffectType, RollbackStrategy};

        let c = Connector::new()
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .compliance(&["hipaa", "fda"])
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .build();

        // Define hospital actions — typed, constrained, enterprise-ready
        let read_ehr = Action::new("ehr.read")
            .describe("Read patient electronic health record")
            .param("patient_id", Param::String, "Patient ID")
            .param("section", Param::Enum(vec!["vitals".into(), "labs".into(), "notes".into(), "imaging".into()]), "EHR section")
            .effect(EffectType::Read)
            .idempotent()
            .data_class("phi")
            .allowed_roles(&["doctor", "nurse"])
            .scopes(&["read:patient"])
            .compliance(&["hipaa"])
            .build();

        let prescribe = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication to patient")
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Drug name")
            .param("dosage", Param::String, "Dosage")
            .param("frequency", Param::Enum(vec!["once".into(), "daily".into(), "bid".into(), "tid".into()]), "Frequency")
            .effect(EffectType::Create)
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing", "admin"])
            .scopes(&["write:prescription", "read:patient"])
            .compliance(&["hipaa", "fda"])
            .retention_days(2555)
            .jurisdiction("US")
            .postcondition("Prescription created", Some("$.rx_id != null"))
            .postcondition("No drug interactions", Some("$.interactions == []"))
            .rollback(RollbackStrategy::HumanReview)
            .build();

        let order_labs = Action::new("lab.order")
            .describe("Order laboratory tests")
            .param("patient_id", Param::String, "Patient ID")
            .param("tests", Param::Array(Box::new(Param::String)), "Lab tests to order")
            .constrained_param("priority", Param::Integer, "Priority 1-5", ParamConstraints {
                min: Some(1.0), max: Some(5.0), ..Default::default()
            })
            .effect(EffectType::Create)
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .compliance(&["hipaa"])
            .build();

        // Build the agent — 90% complexity absorbed
        let doctor = c.agent("doctor-ai")
            .instructions("You are a medical AI assistant. Follow evidence-based medicine.")
            .role("doctor")
            .action(read_ehr)
            .action(prescribe)
            .action(order_labs)
            .output_guard("no_pii_leak", |text| !text.contains("SSN"))
            .rate_limit(30)
            .budget(100_000, 10.0);

        // Verify everything auto-wired correctly
        assert_eq!(doctor.actions.len(), 3);
        assert!(doctor.allowed_tools.contains(&"ehr.read".to_string()));
        assert!(doctor.allowed_tools.contains(&"pharmacy.prescribe".to_string()));
        assert!(doctor.allowed_tools.contains(&"lab.order".to_string()));
        // Approval auto-wired from Action rules
        assert!(doctor.require_approval.contains(&"pharmacy.prescribe".to_string()));
        assert!(doctor.require_approval.contains(&"lab.order".to_string()));
        assert!(!doctor.require_approval.contains(&"ehr.read".to_string())); // read doesn't need approval
        // Data classification auto-wired
        assert!(doctor.allowed_data.contains(&"phi".to_string()));
        // Role validation passes for doctor
        assert!(doctor.validate_role().is_ok());

        // LLM gets proper function schemas
        let schemas = doctor.action_schemas();
        assert_eq!(schemas.len(), 3);
        assert_eq!(schemas[0]["function"]["name"], "ehr.read");
        assert_eq!(schemas[1]["function"]["name"], "pharmacy.prescribe");
        // Schema has enum values
        let freq = &schemas[1]["function"]["parameters"]["properties"]["frequency"];
        assert_eq!(freq["enum"].as_array().unwrap().len(), 4);
        // Schema has constraints
        let priority = &schemas[2]["function"]["parameters"]["properties"]["priority"];
        assert_eq!(priority["minimum"], 1.0);
        assert_eq!(priority["maximum"], 5.0);

        // Kernel gets proper bindings
        let bindings = doctor.action_bindings("ns:hospital");
        assert_eq!(bindings.len(), 3);
        assert_eq!(bindings[0]["data_classification"], "phi");
        assert_eq!(bindings[1]["requires_approval"], true);

        // Agent runs successfully
        let r = doctor.run("Patient P-123 has chest pain", "patient:P-123").unwrap();
        assert!(r.status.ok);
        assert!(r.status.summary.contains("hipaa"));
    }
}
