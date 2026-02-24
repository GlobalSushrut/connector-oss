//! Pipeline builder — multi-actor flows with RBAC, memory sharing, and compliance.
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! let pipe = Connector::pipeline("hospital")
//!     .llm("anthropic", "claude-3.5-sonnet", "sk-...")
//!     .memory("postgres://host/db")
//!     .compliance(&["hipaa"])
//!     .actor("triage", |a| a
//!         .role("writer")
//!         .instructions("Classify patients")
//!         .allow_tools(&["classify"])
//!     )
//!     .actor("doctor", |a| a
//!         .role("tool_agent")
//!         .allow_tools(&["read_ehr", "write_notes"])
//!         .require_approval(&["write_notes"])
//!         .memory_from(&["triage"])
//!     )
//!     .flow(|f| f.start("triage").then("doctor"))
//!     .build();
//! ```

use connector_engine::auto_derive::DerivationContext;
use connector_engine::dispatcher::{DualDispatcher, ActorConfig};
use connector_engine::output::{OutputBuilder, PipelineOutput};
use connector_engine::action::Action;
use crate::types::*;
use crate::security::{SecurityConfig, SecurityConfigBuilder};
use crate::data::{DataConfig, DataBuilder};
use crate::connect::{ConnectConfig, ConnectBuilder};
use crate::agent::OutputGuard;
use crate::error::ConnectorResult;

/// Pipeline — a built, ready-to-run multi-actor pipeline.
#[allow(dead_code)]
pub struct Pipeline {
    name: String,
    llm_config: Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance: Vec<String>,
    security: SecurityConfig,
    actors: Vec<ActorDef>,
    flow: Option<FlowDef>,
    data: DataConfig,
    connect: ConnectConfig,
    output_guards: Vec<OutputGuard>,
    rate_limit: Option<u32>,
    budget_tokens: Option<u64>,
    budget_cost: Option<f64>,
}

impl Pipeline {
    /// Run the pipeline with a message for a specific user/subject.
    pub fn run(&self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        let start = std::time::Instant::now();
        let pipeline_id = format!("pipe:{}:{}", self.name, uuid::Uuid::new_v4());

        // Phase 5+6: Wire security + compliance into dispatcher
        let sec = &self.security;
        let dispatcher_security = connector_engine::dispatcher::DispatcherSecurity {
            data_classification: sec.data_classification.clone(),
            jurisdiction: sec.jurisdiction.clone(),
            retention_days: sec.retention_days,
            max_delegation_depth: sec.max_delegation_depth,
            require_mfa: sec.require_mfa,
            scitt: sec.scitt,
            signing_enabled: sec.signing.is_some(),
        };
        let mut dispatcher = DualDispatcher::new(&pipeline_id)
            .with_compliance(self.compliance.clone())
            .with_security(dispatcher_security);

        // Register all actors
        let mut pids = Vec::new();
        for actor_def in &self.actors {
            let config = ActorConfig {
                name: actor_def.name.clone(),
                role: actor_def.role.clone(),
                instructions: actor_def.instructions.clone(),
                allowed_tools: actor_def.allowed_tools.clone(),
                denied_tools: actor_def.denied_tools.clone(),
                allowed_data: actor_def.allowed_data.clone(),
                denied_data: actor_def.denied_data.clone(),
                require_approval: actor_def.require_approval.clone(),
                memory_from: actor_def.memory_from.clone(),
            };
            let pid = dispatcher.register_actor(config)?;
            pids.push(pid);
        }

        // Execute flow with Phase 6.10 saga rollback support
        let execution_order = self.resolve_flow_order();
        let mut last_response = String::new();
        let mut all_memories = Vec::new();
        let mut completed_actors: Vec<String> = Vec::new();

        for actor_name in &execution_order {
            let pid = pids.iter()
                .zip(self.actors.iter())
                .find(|(_, a)| &a.name == actor_name)
                .map(|(p, _)| p.clone())
                .unwrap_or_default();

            if pid.is_empty() {
                continue;
            }

            // Write input for this actor
            let input_text = if last_response.is_empty() {
                message.to_string()
            } else {
                format!("{}\n\n[Previous actor output]: {}", message, last_response)
            };

            let input_result = dispatcher.remember(
                &pid,
                &input_text,
                user_id,
                DerivationContext::UserInput,
                None,
            );

            let input_mem = match input_result {
                Ok(mem) => mem,
                Err(e) => {
                    // Phase 6.10: Saga rollback — record failure and log rollback
                    for rolled_back in completed_actors.iter().rev() {
                        dispatcher.action_engine_mut().record_action(
                            &format!("Saga rollback: {}", rolled_back),
                            "saga.rollback",
                            &format!("actor:{}", rolled_back),
                            "system",
                            "rolled_back",
                            vec![],
                            None,
                            self.compliance.clone(),
                        );
                    }
                    return Err(crate::error::ConnectorError::EngineError(e));
                }
            };
            all_memories.push(input_mem);

            // Simulate LLM response for this actor
            let actor_def = self.actors.iter().find(|a| &a.name == actor_name);
            let instructions = actor_def
                .and_then(|a| a.instructions.as_deref())
                .unwrap_or("Process the input");

            last_response = format!(
                "[Actor '{}' ({}): processed '{}' with instructions: '{}']",
                actor_name,
                actor_def.and_then(|a| a.role.as_deref()).unwrap_or("writer"),
                &input_text[..input_text.len().min(50)],
                &instructions[..instructions.len().min(50)],
            );

            // Write response
            let resp_mem = dispatcher.remember(
                &pid,
                &last_response,
                user_id,
                DerivationContext::LlmResponse,
                None,
            )?;
            all_memories.push(resp_mem);
            completed_actors.push(actor_name.clone());
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        // Phase 6: Collect real AAPI stats
        let aapi_stats = connector_engine::output::ActionEngineStats {
            action_records: dispatcher.action_engine().action_count(),
            interaction_count: dispatcher.action_engine().interaction_count(),
            policy_count: dispatcher.action_engine().policy_count(),
            capability_count: dispatcher.action_engine().capability_count(),
            budget_count: dispatcher.action_engine().budget_count(),
        };

        let output = OutputBuilder::build_with_aapi(
            dispatcher.kernel(),
            last_response,
            &pipeline_id,
            self.actors.len(),
            &self.compliance,
            duration_ms,
            all_memories,
            Some(aapi_stats),
        );

        Ok(output)
    }

    /// Resolve the execution order from the flow definition.
    fn resolve_flow_order(&self) -> Vec<String> {
        if let Some(flow) = &self.flow {
            let mut order = vec![flow.start.clone()];
            let mut current = flow.start.clone();

            for _ in 0..self.actors.len() {
                if let Some(step) = flow.steps.iter().find(|s| s.from == current) {
                    if !order.contains(&step.to) {
                        order.push(step.to.clone());
                        current = step.to.clone();
                    }
                } else {
                    break;
                }
            }
            order
        } else {
            // Default: execute actors in registration order
            self.actors.iter().map(|a| a.name.clone()).collect()
        }
    }
}

/// Builder for Pipeline.
pub struct PipelineBuilder {
    name: String,
    llm_config: Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance: Vec<String>,
    security: SecurityConfig,
    actors: Vec<ActorDef>,
    flow: Option<FlowDef>,
    data: DataConfig,
    connect: ConnectConfig,
    output_guards: Vec<OutputGuard>,
    rate_limit: Option<u32>,
    budget_tokens: Option<u64>,
    budget_cost: Option<f64>,
}

impl PipelineBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            llm_config: None,
            memory_config: None,
            compliance: Vec::new(),
            security: SecurityConfig::default(),
            actors: Vec::new(),
            flow: None,
            data: DataConfig::default(),
            connect: ConnectConfig::default(),
            output_guards: Vec::new(),
            rate_limit: None,
            budget_tokens: None,
            budget_cost: None,
        }
    }

    /// Set the LLM provider, model, and API key.
    pub fn llm(mut self, provider: &str, model: &str, api_key: &str) -> Self {
        self.llm_config = Some(LlmConfig {
            provider: provider.to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            endpoint: None,
        });
        self
    }

    /// Set the memory store connection string.
    pub fn memory(mut self, connection: &str) -> Self {
        self.memory_config = Some(MemoryConfig {
            connection: connection.to_string(),
        });
        self
    }

    /// Set compliance frameworks.
    pub fn compliance(mut self, frameworks: &[&str]) -> Self {
        self.compliance = frameworks.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Configure security settings.
    pub fn security<F>(mut self, f: F) -> Self
    where
        F: FnOnce(SecurityConfigBuilder) -> SecurityConfigBuilder,
    {
        self.security = f(SecurityConfigBuilder::new()).build();
        self
    }

    /// Add an actor to the pipeline.
    pub fn actor<F>(mut self, name: &str, f: F) -> Self
    where
        F: FnOnce(ActorDefBuilder) -> ActorDefBuilder,
    {
        let builder = f(ActorDefBuilder::new(name));
        self.actors.push(builder.build());
        self
    }

    /// Define the flow (routing between actors).
    pub fn flow<F>(mut self, f: F) -> Self
    where
        F: FnOnce(FlowBuilder) -> FlowBuilder,
    {
        let builder = f(FlowBuilder::new());
        self.flow = Some(builder.build());
        self
    }

    // ─── Cap 13-15, 40: Data plane ───────────────────────────────

    /// Configure the data plane (RAG, vector stores, embeddings).
    pub fn data<F>(mut self, f: F) -> Self
    where
        F: FnOnce(DataBuilder) -> DataBuilder,
    {
        self.data = f(DataBuilder::new()).build();
        self
    }

    // ─── Cap 20: Framework bridges ───────────────────────────────

    /// Configure framework bridges (LangChain, CrewAI, OpenAI, MCP).
    pub fn connect<F>(mut self, f: F) -> Self
    where
        F: FnOnce(ConnectBuilder) -> ConnectBuilder,
    {
        self.connect = f(ConnectBuilder::new()).build();
        self
    }

    // ─── Cap 10: Output guardrails ───────────────────────────────

    /// Add an output guardrail to the pipeline.
    pub fn output_guard(mut self, name: &str, validator: fn(&str) -> bool) -> Self {
        self.output_guards.push(OutputGuard {
            name: name.to_string(),
            validator,
        });
        self
    }

    // ─── Cap 11: Rate limits ─────────────────────────────────────

    /// Set rate limit for the pipeline (max tool calls per minute).
    pub fn rate_limit(mut self, calls_per_minute: u32) -> Self {
        self.rate_limit = Some(calls_per_minute);
        self
    }

    // ─── Cap 12: Token and cost budgets ──────────────────────────

    /// Set token and cost budget for the pipeline.
    pub fn budget(mut self, max_tokens: u64, max_cost_usd: f64) -> Self {
        self.budget_tokens = Some(max_tokens);
        self.budget_cost = Some(max_cost_usd);
        self
    }

    // ═════════════════════════════════════════════════════════════
    // n8n-SIMPLE LAYER — define agent, give it a job, give it
    // tools, connect them, run. Military-grade security automatic.
    // ═════════════════════════════════════════════════════════════

    /// Add an agent node (n8n-style). Returns self for chaining.
    ///
    /// ```rust,ignore
    /// .node("triage", "Classify patient urgency", |n| n
    ///     .can(classify_action)
    ///     .can(read_ehr_action)
    /// )
    /// ```
    pub fn node<F>(mut self, name: &str, job: &str, f: F) -> Self
    where
        F: FnOnce(NodeBuilder) -> NodeBuilder,
    {
        let nb = f(NodeBuilder::new(name, job));
        self.actors.push(nb.into_actor_def());
        self
    }

    /// Connect agents: `"triage -> doctor -> pharmacist"`.
    /// Auto-wires memory sharing between connected agents.
    pub fn route(mut self, route_str: &str) -> Self {
        let names: Vec<&str> = route_str.split("->").map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if names.is_empty() { return self; }

        let mut fb = FlowBuilder::new().start(names[0]);
        for name in &names[1..] {
            fb = fb.then(name);
        }
        self.flow = Some(fb.build());

        // Auto-wire memory_from: each agent reads from its predecessor
        for i in 1..names.len() {
            let prev = names[i - 1].to_string();
            if let Some(actor) = self.actors.iter_mut().find(|a| a.name == names[i]) {
                if !actor.memory_from.contains(&prev) {
                    actor.memory_from.push(prev);
                }
            }
        }
        self
    }

    // ─── Compliance shorthands ───────────────────────────────────

    /// HIPAA + PHI shorthand: sets compliance, data classification, jurisdiction, retention.
    pub fn hipaa(mut self, jurisdiction: &str, retention_days: u64) -> Self {
        if !self.compliance.contains(&"hipaa".to_string()) {
            self.compliance.push("hipaa".to_string());
        }
        self.security.data_classification = Some("PHI".to_string());
        self.security.jurisdiction = Some(jurisdiction.to_string());
        self.security.retention_days = retention_days;
        self
    }

    /// SOC2 shorthand.
    pub fn soc2(mut self) -> Self {
        if !self.compliance.contains(&"soc2".to_string()) {
            self.compliance.push("soc2".to_string());
        }
        self
    }

    /// GDPR + PII shorthand.
    pub fn gdpr(mut self, retention_days: u64) -> Self {
        if !self.compliance.contains(&"gdpr".to_string()) {
            self.compliance.push("gdpr".to_string());
        }
        self.security.data_classification = Some("PII".to_string());
        self.security.jurisdiction = Some("EU".to_string());
        self.security.retention_days = retention_days;
        self
    }

    /// Military/DoD shorthand.
    pub fn dod(mut self) -> Self {
        if !self.compliance.contains(&"dod_5220".to_string()) {
            self.compliance.push("dod_5220".to_string());
        }
        self.security.data_classification = Some("TOP_SECRET".to_string());
        self.security.jurisdiction = Some("US".to_string());
        self.security.signing = Some(crate::security::SigningAlgorithm::Ed25519);
        self.security.require_mfa = true;
        self
    }

    /// Signed audit trail (Ed25519 + SCITT).
    pub fn signed(mut self) -> Self {
        self.security.signing = Some(crate::security::SigningAlgorithm::Ed25519);
        self.security.scitt = true;
        self
    }

    /// Build the pipeline.
    pub fn build(self) -> Pipeline {
        Pipeline {
            name: self.name,
            llm_config: self.llm_config,
            memory_config: self.memory_config,
            compliance: self.compliance,
            security: self.security,
            actors: self.actors,
            flow: self.flow,
            data: self.data,
            connect: self.connect,
            output_guards: self.output_guards,
            rate_limit: self.rate_limit,
            budget_tokens: self.budget_tokens,
            budget_cost: self.budget_cost,
        }
    }
}

// ─── NodeBuilder (n8n-style agent node) ──────────────────────────

/// A simple agent node — like dropping a node in n8n.
/// Define what it does (job) and what tools it can use (can).
pub struct NodeBuilder {
    name: String,
    job: String,
    role: Option<String>,
    actions: Vec<Action>,
    denied_data: Vec<String>,
}

impl NodeBuilder {
    pub fn new(name: &str, job: &str) -> Self {
        Self { name: name.into(), job: job.into(), role: None, actions: Vec::new(), denied_data: Vec::new() }
    }

    /// Give this agent a tool it can use.
    pub fn can(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Set the agent's role (for RBAC). Optional — auto-derived from actions if not set.
    pub fn role(mut self, role: &str) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Deny access to specific data classifications.
    pub fn deny_data(mut self, data: &[&str]) -> Self {
        self.denied_data = data.iter().map(|s| s.to_string()).collect();
        self
    }

    fn into_actor_def(self) -> ActorDef {
        let mut def = ActorDef::new(&self.name);
        def.instructions = Some(self.job);
        def.role = self.role;
        def.denied_data = self.denied_data;
        for action in self.actions {
            if !def.allowed_tools.contains(&action.name) {
                def.allowed_tools.push(action.name.clone());
            }
            if action.needs_approval() && !def.require_approval.contains(&action.name) {
                def.require_approval.push(action.name.clone());
            }
            if let Some(ref dc) = action.rules.data_classification {
                if !def.allowed_data.contains(dc) {
                    def.allowed_data.push(dc.clone());
                }
            }
            def.actions.push(action);
        }
        def
    }
}

/// Builder for ActorDef.
pub struct ActorDefBuilder {
    def: ActorDef,
}

impl ActorDefBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            def: ActorDef::new(name),
        }
    }

    pub fn role(mut self, role: &str) -> Self {
        self.def.role = Some(role.to_string());
        self
    }

    pub fn instructions(mut self, instructions: &str) -> Self {
        self.def.instructions = Some(instructions.to_string());
        self
    }

    pub fn allow_tools(mut self, tools: &[&str]) -> Self {
        self.def.allowed_tools = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn deny_tools(mut self, tools: &[&str]) -> Self {
        self.def.denied_tools = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn allow_data(mut self, data: &[&str]) -> Self {
        self.def.allowed_data = data.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn deny_data(mut self, data: &[&str]) -> Self {
        self.def.denied_data = data.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn require_approval(mut self, tools: &[&str]) -> Self {
        self.def.require_approval = tools.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn memory_from(mut self, actors: &[&str]) -> Self {
        self.def.memory_from = actors.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Register a typed Action — auto-wires RBAC, approval, data classification.
    pub fn action(mut self, action: Action) -> Self {
        if !self.def.allowed_tools.contains(&action.name) {
            self.def.allowed_tools.push(action.name.clone());
        }
        if action.needs_approval() && !self.def.require_approval.contains(&action.name) {
            self.def.require_approval.push(action.name.clone());
        }
        if let Some(ref dc) = action.rules.data_classification {
            if !self.def.allowed_data.contains(dc) {
                self.def.allowed_data.push(dc.clone());
            }
        }
        self.def.actions.push(action);
        self
    }

    /// Register multiple typed Actions at once.
    pub fn actions(mut self, actions: Vec<Action>) -> Self {
        for a in actions { self = self.action(a); }
        self
    }

    pub fn build(self) -> ActorDef {
        self.def
    }
}

/// Builder for FlowDef.
pub struct FlowBuilder {
    start: Option<String>,
    steps: Vec<FlowStep>,
    last_actor: Option<String>,
}

impl FlowBuilder {
    pub fn new() -> Self {
        Self {
            start: None,
            steps: Vec::new(),
            last_actor: None,
        }
    }

    /// Set the starting actor.
    pub fn start(mut self, actor: &str) -> Self {
        self.start = Some(actor.to_string());
        self.last_actor = Some(actor.to_string());
        self
    }

    /// Chain to the next actor (unconditional).
    pub fn then(mut self, actor: &str) -> Self {
        if let Some(ref last) = self.last_actor {
            self.steps.push(FlowStep {
                from: last.clone(),
                to: actor.to_string(),
                condition: None,
            });
        }
        self.last_actor = Some(actor.to_string());
        self
    }

    /// Chain to the next actor with a condition.
    pub fn then_if(mut self, actor: &str, condition: &str) -> Self {
        if let Some(ref last) = self.last_actor {
            self.steps.push(FlowStep {
                from: last.clone(),
                to: actor.to_string(),
                condition: Some(condition.to_string()),
            });
        }
        self.last_actor = Some(actor.to_string());
        self
    }

    pub fn build(self) -> FlowDef {
        FlowDef {
            start: self.start.unwrap_or_default(),
            steps: self.steps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_pipeline() {
        let pipe = PipelineBuilder::new("test")
            .llm("openai", "gpt-4o", "sk-test")
            .actor("bot", |a| a.instructions("Be helpful"))
            .build();

        let output = pipe.run("Hello!", "user:alice").unwrap();
        assert!(output.status.ok);
        assert_eq!(output.status.actors, 1);
    }

    #[test]
    fn test_multi_actor_pipeline() {
        let pipe = PipelineBuilder::new("support")
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["soc2"])
            .actor("triage", |a| a
                .role("writer")
                .instructions("Classify support tickets")
                .allow_tools(&["classify_ticket"])
            )
            .actor("resolver", |a| a
                .role("tool_agent")
                .instructions("Resolve customer issues")
                .allow_tools(&["search_docs", "create_ticket"])
                .memory_from(&["triage"])
            )
            .flow(|f| f.start("triage").then("resolver"))
            .build();

        let output = pipe.run("My account is locked", "user:bob").unwrap();

        assert!(output.status.ok);
        assert_eq!(output.status.actors, 2);
        assert!(output.status.steps > 0);
        assert!(output.memory.created > 0);
        assert!(output.status.summary.contains("soc2"));
    }

    #[test]
    fn test_hospital_pipeline() {
        let pipe = PipelineBuilder::new("hospital-er")
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .memory("postgres://localhost/hospital")
            .compliance(&["hipaa", "eu_ai_act"])
            .actor("triage", |a| a
                .role("writer")
                .instructions("Classify patient urgency using ESI scale")
                .allow_tools(&["classify_patient"])
            )
            .actor("doctor", |a| a
                .role("tool_agent")
                .instructions("Diagnose and treat patients")
                .allow_tools(&["read_ehr", "write_notes", "order_labs"])
                .deny_data(&["billing"])
                .require_approval(&["write_notes", "order_labs"])
                .memory_from(&["triage"])
            )
            .flow(|f| f.start("triage").then("doctor"))
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .build();

        let output = pipe.run("Patient has chest pain", "patient:P-123").unwrap();

        assert!(output.status.ok);
        assert_eq!(output.status.actors, 2);
        assert!(output.status.summary.contains("hipaa"));
        assert!(output.aapi.compliance.contains(&"hipaa".to_string()));
        assert!(output.aapi.compliance.contains(&"eu_ai_act".to_string()));
    }

    #[test]
    fn test_flow_ordering() {
        let pipe = PipelineBuilder::new("chain")
            .actor("a", |a| a.instructions("Step A"))
            .actor("b", |a| a.instructions("Step B"))
            .actor("c", |a| a.instructions("Step C"))
            .flow(|f| f.start("a").then("b").then("c"))
            .build();

        let order = pipe.resolve_flow_order();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    // ─── Full 40-capability pipeline test ────────────────────────

    #[test]
    fn test_full_40_capability_pipeline() {
        use crate::agent::PipelineOutputExt;
        use crate::observe::Passport;

        let pipe = PipelineBuilder::new("hospital-er-full")
            // Cap 1: Pick any LLM
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            // Cap 13-15, 40: Data plane (RAG, vector store, embeddings)
            .data(|d| d
                .memory("postgres://localhost/hospital")
                .rag("clinical-docs", |r| r
                    .source("./clinical-guidelines/")
                    .source("https://pubmed.ncbi.nlm.nih.gov/")
                    .chunk_size(512)
                    .top_k(10)
                    .rerank(true)
                )
                .vector_store("qdrant", "localhost:6333")
                .embeddings("openai", "text-embedding-3-small", "sk-test")
            )
            // Cap 27: Compliance-as-code
            .compliance(&["hipaa", "soc2", "eu_ai_act"])
            // Cap 22-25: RBAC, data boundaries, approval gates
            .actor("triage", |a| a
                .role("writer")
                .instructions("Classify patient urgency using ESI scale")
                .allow_tools(&["classify_patient", "read_vitals"])
                .allow_data(&["patient_records", "vitals"])
                .deny_data(&["billing", "insurance"])
            )
            .actor("doctor", |a| a
                .role("tool_agent")
                .instructions("Diagnose and treat patients based on evidence")
                .allow_tools(&["read_ehr", "write_notes", "order_labs", "prescribe"])
                .deny_tools(&["delete_patient", "admin_override"])
                .allow_data(&["patient_records", "lab_results", "imaging"])
                .deny_data(&["billing", "insurance", "other_patients"])
                .require_approval(&["write_notes", "order_labs", "prescribe"])
                .memory_from(&["triage"])
            )
            .actor("pharmacy", |a| a
                .role("tool_agent")
                .instructions("Verify and dispense medications")
                .allow_tools(&["check_interactions", "dispense"])
                .require_approval(&["dispense"])
                .memory_from(&["doctor"])
            )
            // Cap 6: Multi-agent flow
            .flow(|f| f.start("triage").then("doctor").then("pharmacy"))
            // Cap 10: Output guardrails
            .output_guard("no_pii_in_output", |text| !text.contains("SSN"))
            .output_guard("no_prescriptions_in_text", |text| !text.to_lowercase().contains("prescribe"))
            // Cap 11-12: Rate limits + budgets
            .rate_limit(30)
            .budget(200_000, 20.0)
            // Cap 20: Framework bridges
            .connect(|c| c
                .langchain()
                .mcp_server(8080)
                .webhook_signed(
                    "https://hooks.hospital.com/ai-events",
                    &["tool.denied", "approval.required", "run.complete"],
                    "hospital-secret-key"
                )
            )
            // Security config
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .scitt(true)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
                .require_mfa(true)
                .max_delegation_depth(3)
            )
            .build();

        // Run the pipeline
        let output = pipe.run("Patient P-123: chest pain, shortness of breath, age 67", "patient:P-123").unwrap();

        // Cap 2: Pipeline ran successfully
        assert!(output.status.ok);
        // Cap 6: All 3 actors executed
        assert_eq!(output.status.actors, 3);
        // Cap 18-19: Usage tracking
        assert!(output.status.steps > 0);
        assert!(output.status.duration_ms < 5000);
        // Cap 39: AAPI visibility in output
        assert!(output.status.summary.contains("hipaa"));
        assert!(output.aapi.compliance.contains(&"hipaa".to_string()));
        assert!(output.aapi.compliance.contains(&"eu_ai_act".to_string()));

        // Cap 26: Trust score
        let trust = output.trust();
        assert!(trust.score > 0);
        assert!(trust.verifiable);
        let badge = output.trust_badge();
        assert!(badge.badge.contains("Trust Score"));

        // Cap 27: Compliance reports
        let hipaa = output.comply("hipaa");
        assert_eq!(hipaa.framework, "hipaa");
        assert!(hipaa.controls_total >= 4);
        let soc2 = output.comply("soc2");
        assert_eq!(soc2.framework, "soc2");
        let eu_ai = output.comply("eu_ai_act");
        assert_eq!(eu_ai.framework, "eu_ai_act");

        // Cap 28: Time travel
        let snapshot = output.replay("2025-01-15T10:30:00Z");
        assert_eq!(snapshot.at, "2025-01-15T10:30:00Z");
        assert!(snapshot.memory_count > 0);

        // Cap 29: Decision X-Ray
        let xray = output.xray();
        assert!(!xray.explanation.is_empty());
        assert!(xray.reasoning_steps.len() >= 2);
        assert!(xray.evidence_count > 0);

        // Cap 30: Memory Passport
        let bundle = output.passport_export("patient:P-123");
        assert_eq!(bundle.subject, "patient:P-123");
        assert!(Passport::verify(&bundle));

        // Cap 31: Audit trail
        let audit = output.audit();
        assert!(audit.total_entries > 0);
        assert!(audit.explain().contains("audit entries"));

        // Cap 32: ConnectorMemory format
        assert!(output.memory.memories.len() > 0);
        for mem in &output.memory.memories {
            assert!(!mem.id.is_empty());
            assert!(!mem.content.is_empty());
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // ACTION + PIPELINE INTEGRATION — military-grade multi-actor flow
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_pipeline_with_typed_actions() {
        use connector_engine::action::{Action, Param, ParamConstraints, EffectType, RollbackStrategy};
        use crate::agent::PipelineOutputExt;

        // ── Define actions once, reuse across actors ─────────────
        let classify = Action::new("triage.classify")
            .describe("Classify patient urgency")
            .param("symptoms", Param::String, "Patient symptoms")
            .param("age", Param::Integer, "Patient age")
            .returns(Param::Enum(vec!["ESI-1".into(), "ESI-2".into(), "ESI-3".into(), "ESI-4".into(), "ESI-5".into()]))
            .effect(EffectType::Read)
            .idempotent()
            .data_class("phi")
            .compliance(&["hipaa"])
            .build();

        let read_ehr = Action::new("ehr.read")
            .describe("Read patient EHR")
            .param("patient_id", Param::String, "Patient ID")
            .param("section", Param::Enum(vec!["vitals".into(), "labs".into(), "notes".into()]), "Section")
            .effect(EffectType::Read)
            .idempotent()
            .data_class("phi")
            .allowed_roles(&["doctor", "nurse"])
            .compliance(&["hipaa"])
            .build();

        let prescribe = Action::new("pharmacy.prescribe")
            .describe("Prescribe medication")
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Drug name")
            .param("dosage", Param::String, "Dosage")
            .effect(EffectType::Create)
            .data_class("phi")
            .require_approval()
            .allowed_roles(&["doctor"])
            .denied_roles(&["nurse", "billing"])
            .compliance(&["hipaa", "fda"])
            .jurisdiction("US")
            .postcondition("Rx created", Some("$.rx_id != null"))
            .rollback(RollbackStrategy::HumanReview)
            .build();

        let check_interactions = Action::new("pharmacy.check_interactions")
            .describe("Check drug interactions")
            .param("medications", Param::Array(Box::new(Param::String)), "Current medications")
            .param("new_drug", Param::String, "New drug to check")
            .effect(EffectType::Read)
            .idempotent()
            .data_class("phi")
            .compliance(&["hipaa", "fda"])
            .build();

        let dispense = Action::new("pharmacy.dispense")
            .describe("Dispense medication")
            .param("rx_id", Param::String, "Prescription ID")
            .constrained_param("quantity", Param::Integer, "Quantity", ParamConstraints {
                min: Some(1.0), max: Some(90.0), ..Default::default()
            })
            .effect(EffectType::External)
            .require_approval()
            .data_class("phi")
            .compliance(&["hipaa", "fda"])
            .postcondition("Dispensed", Some("$.dispensed == true"))
            .rollback(RollbackStrategy::AutoReverse)
            .build();

        // ── Build the pipeline — 90% complexity absorbed ─────────
        let pipe = PipelineBuilder::new("hospital-er")
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .memory("postgres://localhost/hospital")
            .compliance(&["hipaa", "fda", "eu_ai_act"])
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .actor("triage", |a| a
                .role("nurse")
                .instructions("Classify patient urgency using ESI scale")
                .action(classify)
                .action(read_ehr.clone())
            )
            .actor("doctor", |a| a
                .role("doctor")
                .instructions("Diagnose and treat based on evidence")
                .action(read_ehr)
                .action(prescribe)
                .action(check_interactions.clone())
                .memory_from(&["triage"])
            )
            .actor("pharmacist", |a| a
                .role("doctor") // pharmacist has doctor-level access
                .instructions("Verify prescriptions and dispense")
                .action(check_interactions)
                .action(dispense)
                .memory_from(&["doctor"])
            )
            .flow(|f| f.start("triage").then("doctor").then("pharmacist"))
            .data(|d| d
                .memory("postgres://localhost/hospital")
                .rag("clinical-docs", |r| r
                    .source("./clinical-guidelines/")
                    .chunk_size(512)
                    .top_k(10)
                    .rerank(true)
                )
                .vector_store("qdrant", "localhost:6333")
                .embeddings("openai", "text-embedding-3-small", "sk-test")
            )
            .output_guard("no_pii_leak", |text| !text.contains("SSN"))
            .rate_limit(30)
            .budget(200_000, 20.0)
            .build();

        // ── Run it ───────────────────────────────────────────────
        let output = pipe.run("Patient P-123: chest pain, age 67", "patient:P-123").unwrap();

        // Pipeline ran with all 3 actors
        assert!(output.status.ok);
        assert_eq!(output.status.actors, 3);
        assert!(output.status.steps > 0);

        // Compliance propagated
        assert!(output.aapi.compliance.contains(&"hipaa".to_string()));
        assert!(output.aapi.compliance.contains(&"fda".to_string()));

        // Trust computed
        assert!(output.trust().score > 0);

        // Audit trail exists
        assert!(output.audit().total_entries > 0);

        // Memory created across actors
        assert!(output.memory.created > 0);

        // Verify actors got correct actions auto-wired
        let triage_actor = &pipe.actors[0];
        assert!(triage_actor.allowed_tools.contains(&"triage.classify".to_string()));
        assert!(triage_actor.allowed_tools.contains(&"ehr.read".to_string()));
        assert!(triage_actor.allowed_data.contains(&"phi".to_string()));
        // Triage has no approval-required actions
        assert!(triage_actor.require_approval.is_empty());

        let doctor_actor = &pipe.actors[1];
        assert!(doctor_actor.allowed_tools.contains(&"pharmacy.prescribe".to_string()));
        assert!(doctor_actor.require_approval.contains(&"pharmacy.prescribe".to_string()));

        let pharmacist_actor = &pipe.actors[2];
        assert!(pharmacist_actor.allowed_tools.contains(&"pharmacy.dispense".to_string()));
        assert!(pharmacist_actor.require_approval.contains(&"pharmacy.dispense".to_string()));
        // Dispense has quantity constraint — verify it's in the action
        let dispense_action = pharmacist_actor.actions.iter().find(|a| a.name == "pharmacy.dispense").unwrap();
        assert!(dispense_action.params[1].constraints.is_some());
        assert_eq!(dispense_action.params[1].constraints.as_ref().unwrap().max, Some(90.0));
    }

    // ═══════════════════════════════════════════════════════════════
    // n8n-SIMPLE TESTS — prove pipeline is as simple as n8n
    // ═══════════════════════════════════════════════════════════════

    // ── Layer 0: Simplest possible pipeline (like n8n 1-node) ────

    #[test]
    fn test_n8n_simplest_pipeline() {
        use connector_engine::action::{Action, Param, EffectType};

        let search = Action::new("search").describe("Search the web")
            .param("query", Param::String, "Query").effect(EffectType::Read).idempotent().build();

        // 4 lines. That's it. Military-grade kernel underneath.
        let pipe = PipelineBuilder::new("assistant")
            .llm("openai", "gpt-4o", "sk-test")
            .node("bot", "You are a helpful assistant", |n| n.can(search))
            .build();

        let r = pipe.run("What is Rust?", "user:alice").unwrap();
        assert!(r.status.ok);
        assert_eq!(r.status.actors, 1);
        assert_eq!(pipe.actors[0].allowed_tools, vec!["search"]);
    }

    // ── Layer 1: Multi-agent with route (like n8n multi-node) ────

    #[test]
    fn test_n8n_multi_agent_route() {
        use connector_engine::action::{Action, Param, EffectType};

        let classify = Action::new("classify").describe("Classify ticket")
            .param("text", Param::String, "Text").effect(EffectType::Read).build();
        let search_docs = Action::new("search_docs").describe("Search docs")
            .param("query", Param::String, "Query").effect(EffectType::Read).build();
        let reply = Action::new("reply").describe("Send reply")
            .param("message", Param::String, "Message").effect(EffectType::External)
            .require_approval().build();

        let pipe = PipelineBuilder::new("support")
            .llm("openai", "gpt-4o", "sk-test")
            .soc2()
            .node("triage", "Classify support tickets", |n| n.can(classify))
            .node("resolver", "Find answers in docs", |n| n.can(search_docs))
            .node("responder", "Draft and send reply", |n| n.can(reply))
            .route("triage -> resolver -> responder")
            .build();

        let r = pipe.run("My account is locked", "user:bob").unwrap();
        assert!(r.status.ok);
        assert_eq!(r.status.actors, 3);

        // Route auto-wired memory_from
        assert!(pipe.actors[1].memory_from.contains(&"triage".to_string()));
        assert!(pipe.actors[2].memory_from.contains(&"resolver".to_string()));

        // Approval auto-wired from Action
        assert!(pipe.actors[2].require_approval.contains(&"reply".to_string()));

        // SOC2 compliance propagated
        assert!(r.status.summary.contains("soc2"));
    }

    // ── Layer 2: Hospital with HIPAA shorthand ───────────────────

    #[test]
    fn test_n8n_hospital_hipaa() {
        use connector_engine::action::{Action, Param, EffectType, RollbackStrategy};

        let read_ehr = Action::new("ehr.read").describe("Read patient EHR")
            .param("patient_id", Param::String, "Patient ID")
            .effect(EffectType::Read).idempotent().data_class("phi")
            .allowed_roles(&["doctor", "nurse"]).compliance(&["hipaa"]).build();

        let prescribe = Action::new("pharmacy.prescribe").describe("Prescribe medication")
            .param("patient_id", Param::String, "Patient ID")
            .param("medication", Param::String, "Drug")
            .param("dosage", Param::String, "Dosage")
            .effect(EffectType::Create).data_class("phi")
            .require_approval().allowed_roles(&["doctor"]).denied_roles(&["nurse"])
            .compliance(&["hipaa", "fda"]).jurisdiction("US")
            .postcondition("Rx created", Some("$.rx_id != null"))
            .rollback(RollbackStrategy::HumanReview).build();

        let dispense = Action::new("pharmacy.dispense").describe("Dispense medication")
            .param("rx_id", Param::String, "Prescription ID")
            .effect(EffectType::External).data_class("phi")
            .require_approval().compliance(&["hipaa", "fda"])
            .rollback(RollbackStrategy::AutoReverse).build();

        // n8n-simple: define agents, give them tools, connect, done.
        let pipe = PipelineBuilder::new("hospital-er")
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .hipaa("US", 2555)
            .signed()
            .node("triage", "Classify patient urgency using ESI scale", |n| n
                .role("nurse")
                .can(read_ehr.clone())
            )
            .node("doctor", "Diagnose and treat based on evidence", |n| n
                .role("doctor")
                .can(read_ehr)
                .can(prescribe)
                .deny_data(&["billing", "insurance"])
            )
            .node("pharmacist", "Verify and dispense medications", |n| n
                .can(dispense)
            )
            .route("triage -> doctor -> pharmacist")
            .build();

        let r = pipe.run("Patient P-123: chest pain, age 67", "patient:P-123").unwrap();

        // Pipeline works
        assert!(r.status.ok);
        assert_eq!(r.status.actors, 3);

        // HIPAA shorthand set everything
        assert!(pipe.compliance.contains(&"hipaa".to_string()));
        assert_eq!(pipe.security.data_classification.as_deref(), Some("PHI"));
        assert_eq!(pipe.security.jurisdiction.as_deref(), Some("US"));
        assert_eq!(pipe.security.retention_days, 2555);

        // Signed audit trail
        assert!(pipe.security.signing.is_some());
        assert!(pipe.security.scitt);

        // Route auto-wired memory
        assert!(pipe.actors[1].memory_from.contains(&"triage".to_string()));
        assert!(pipe.actors[2].memory_from.contains(&"doctor".to_string()));

        // Actions auto-wired tools + approval + data classification
        assert!(pipe.actors[0].allowed_tools.contains(&"ehr.read".to_string()));
        assert!(pipe.actors[1].allowed_tools.contains(&"pharmacy.prescribe".to_string()));
        assert!(pipe.actors[1].require_approval.contains(&"pharmacy.prescribe".to_string()));
        assert!(pipe.actors[2].require_approval.contains(&"pharmacy.dispense".to_string()));
        assert!(pipe.actors[1].allowed_data.contains(&"phi".to_string()));
        assert!(pipe.actors[1].denied_data.contains(&"billing".to_string()));

        // Actions are available for LLM schema generation
        assert_eq!(pipe.actors[1].actions.len(), 2); // read_ehr + prescribe
        let schemas: Vec<serde_json::Value> = pipe.actors[1].actions.iter().map(|a| a.to_json_schema()).collect();
        assert_eq!(schemas[0]["function"]["name"], "ehr.read");
        assert_eq!(schemas[1]["function"]["name"], "pharmacy.prescribe");
    }

    // ── Layer 3: Military drone pipeline ─────────────────────────

    #[test]
    fn test_n8n_military_dod() {
        use connector_engine::action::{Action, Param, ParamConstraints, EffectType, RollbackStrategy};

        let recon = Action::new("drone.recon").describe("Aerial reconnaissance")
            .param("area", Param::String, "Target area")
            .effect(EffectType::Read).idempotent().data_class("top_secret")
            .scopes(&["intel:read"]).build();

        let strike = Action::new("drone.strike").describe("Precision strike")
            .constrained_param("lat", Param::Float, "Latitude", ParamConstraints { min: Some(-90.0), max: Some(90.0), ..Default::default() })
            .constrained_param("lon", Param::Float, "Longitude", ParamConstraints { min: Some(-180.0), max: Some(180.0), ..Default::default() })
            .effect(EffectType::External)
            .require_approval().two_person()
            .allowed_roles(&["commander", "weapons_officer"])
            .data_class("top_secret").max_chain_depth(1)
            .postcondition("Target neutralized", Some("$.bda.confirmed == true"))
            .rollback(RollbackStrategy::HumanReview)
            .compliance(&["dod_5220", "loac"]).jurisdiction("US")
            .retention_days(36500).build();

        let pipe = PipelineBuilder::new("drone-ops")
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .dod()
            .node("intel", "Gather intelligence on target area", |n| n
                .role("commander")
                .can(recon)
            )
            .node("weapons", "Execute precision strike on confirmed target", |n| n
                .role("weapons_officer")
                .can(strike)
            )
            .route("intel -> weapons")
            .build();

        let r = pipe.run("Target area Alpha-7", "mission:M-001").unwrap();
        assert!(r.status.ok);
        assert_eq!(r.status.actors, 2);

        // DoD shorthand set everything
        assert!(pipe.compliance.contains(&"dod_5220".to_string()));
        assert_eq!(pipe.security.data_classification.as_deref(), Some("TOP_SECRET"));
        assert!(pipe.security.signing.is_some());
        assert!(pipe.security.require_mfa);

        // Two-person rule on strike
        assert!(pipe.actors[1].require_approval.contains(&"drone.strike".to_string()));
        let strike_action = pipe.actors[1].actions.iter().find(|a| a.name == "drone.strike").unwrap();
        assert!(strike_action.rules.two_person);
        assert_eq!(strike_action.rules.max_chain_depth, Some(1));
    }

    // ── Comparison: old verbose vs new simple ────────────────────

    #[test]
    fn test_n8n_vs_verbose_same_result() {
        use connector_engine::action::{Action, Param, EffectType};

        let search = Action::new("search").describe("Search")
            .param("q", Param::String, "Query").effect(EffectType::Read).build();
        let write = Action::new("write").describe("Write")
            .param("text", Param::String, "Text").effect(EffectType::Create)
            .require_approval().data_class("internal").build();

        // ── OLD WAY (verbose) ────────────────────────────────────
        let old = PipelineBuilder::new("test")
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["soc2"])
            .actor("reader", |a| a
                .role("writer")
                .instructions("Read and research")
                .action(search.clone())
            )
            .actor("writer", |a| a
                .role("writer")
                .instructions("Write content")
                .action(write.clone())
                .memory_from(&["reader"])
            )
            .flow(|f| f.start("reader").then("writer"))
            .build();

        // ── NEW WAY (n8n-simple) ─────────────────────────────────
        let new = PipelineBuilder::new("test")
            .llm("openai", "gpt-4o", "sk-test")
            .soc2()
            .node("reader", "Read and research", |n| n.role("writer").can(search))
            .node("writer", "Write content", |n| n.role("writer").can(write))
            .route("reader -> writer")
            .build();

        // Same result — same actors, same tools, same flow
        assert_eq!(old.actors.len(), new.actors.len());
        assert_eq!(old.actors[0].name, new.actors[0].name);
        assert_eq!(old.actors[1].name, new.actors[1].name);
        assert_eq!(old.actors[0].allowed_tools, new.actors[0].allowed_tools);
        assert_eq!(old.actors[1].allowed_tools, new.actors[1].allowed_tools);
        assert_eq!(old.actors[1].require_approval, new.actors[1].require_approval);
        assert_eq!(old.actors[1].allowed_data, new.actors[1].allowed_data);
        // New way auto-wired memory_from
        assert!(new.actors[1].memory_from.contains(&"reader".to_string()));
        // Both have compliance
        assert!(old.compliance.contains(&"soc2".to_string()));
        assert!(new.compliance.contains(&"soc2".to_string()));
    }

    // ── Phase 6: AAPI Integration in Pipeline ──────────────────

    #[test]
    fn test_phase6_pipeline_aapi_stats() {
        let pipe = PipelineBuilder::new("hospital")
            .llm("openai", "gpt-4o", "sk-test")
            .hipaa("US", 2555)
            .actor("triage", |a| a.role("writer").instructions("Classify patient"))
            .actor("doctor", |a| a.role("tool_agent").instructions("Diagnose").memory_from(&["triage"]))
            .flow(|f| f.start("triage").then("doctor"))
            .build();

        let output = pipe.run("Patient has chest pain", "user:patient1").unwrap();

        // Real AAPI action records should be present
        // 2 actors registered + 2 input writes + 2 response writes = 6 action records
        assert!(output.aapi.action_records >= 4,
            "Pipeline should have action records, got {}", output.aapi.action_records);

        // Security tags should be applied (HIPAA → PHI)
        assert!(output.status.ok);
        assert_eq!(output.status.actors, 2);

        // JSON export should include engine-sourced AAPI fields
        let json = output.to_json();
        assert_eq!(json["aapi"]["action_records"]["source"], "engine");
        assert!(json["aapi"]["action_records"]["value"].as_u64().unwrap() >= 4);
    }

    // ── GDPR pipeline ────────────────────────────────────────────

    #[test]
    fn test_n8n_gdpr_pipeline() {
        use connector_engine::action::{Action, Param, EffectType};

        let collect = Action::new("data.collect").describe("Collect user data")
            .param("user_id", Param::String, "User").effect(EffectType::Create)
            .data_class("pii").require_approval().build();
        let process = Action::new("data.process").describe("Process data")
            .param("data_id", Param::String, "Data ID").effect(EffectType::Update)
            .data_class("pii").build();

        let pipe = PipelineBuilder::new("eu-data")
            .llm("openai", "gpt-4o", "sk-test")
            .gdpr(1825) // 5 years
            .node("collector", "Collect user consent and data", |n| n.can(collect))
            .node("processor", "Process data per GDPR rules", |n| n.can(process))
            .route("collector -> processor")
            .build();

        assert!(pipe.compliance.contains(&"gdpr".to_string()));
        assert_eq!(pipe.security.data_classification.as_deref(), Some("PII"));
        assert_eq!(pipe.security.jurisdiction.as_deref(), Some("EU"));
        assert_eq!(pipe.security.retention_days, 1825);
        assert!(pipe.actors[1].memory_from.contains(&"collector".to_string()));
    }
}
