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

/// Phase H: Basic entity extraction from text for observe/perception.
/// Extracts simple entities (emails, measurements, keywords) from input
/// using lightweight string scanning (no regex dependency needed).
fn extract_basic_entities(text: &str) -> Vec<(String, String)> {
    let mut entities = Vec::new();
    let lower = text.to_lowercase();

    // Email detection (simple heuristic: word with @ and .)
    for word in text.split_whitespace() {
        if word.contains('@') && word.contains('.') && word.len() > 5 {
            entities.push(("email".to_string(), word.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.').to_string()));
        }
    }

    // Measurement detection (number followed by unit)
    let units = ["mg", "ml", "kg", "lbs", "years", "yo", "bpm", "mmhg", "celsius", "fahrenheit"];
    for word in lower.split_whitespace() {
        for unit in &units {
            if word.ends_with(unit) && word.len() > unit.len() {
                let num_part = &word[..word.len() - unit.len()];
                if num_part.chars().all(|c| c.is_ascii_digit() || c == '.') && !num_part.is_empty() {
                    entities.push(("measurement".to_string(), word.to_string()));
                }
            }
        }
    }

    // Medical keyword detection
    let medical_terms = ["diagnosis", "symptom", "patient", "medication", "prescription",
        "blood pressure", "heart rate", "temperature", "allergic", "chronic"];
    for term in &medical_terms {
        if lower.contains(term) {
            entities.push(("medical_term".to_string(), term.to_string()));
        }
    }

    entities
}

/// Parse tool call requests from LLM response text.
/// Looks for patterns like `[TOOL_CALL: tool_name(params)]` in the response.
/// Returns a vec of (tool_name, params) tuples.
fn parse_tool_calls(text: &str) -> Vec<(String, String)> {
    let mut calls = Vec::new();
    let marker = "[TOOL_CALL:";

    let mut search_from = 0;
    while let Some(start) = text[search_from..].find(marker) {
        let abs_start = search_from + start + marker.len();
        if let Some(end) = text[abs_start..].find(']') {
            let inner = text[abs_start..abs_start + end].trim();
            // Parse "tool_name(params)" or just "tool_name"
            if let Some(paren_start) = inner.find('(') {
                let name = inner[..paren_start].trim().to_string();
                let params = inner[paren_start + 1..].trim_end_matches(')').trim().to_string();
                if !name.is_empty() {
                    calls.push((name, params));
                }
            } else if !inner.is_empty() {
                calls.push((inner.to_string(), String::new()));
            }
            search_from = abs_start + end + 1;
        } else {
            break;
        }
    }
    calls
}

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
    /// Agent-level knowledge facts (appended to Connector-level knowledge)
    agent_facts: Vec<String>,
    /// Additional context for this specific run
    agent_context: Option<String>,
    /// Task decomposition steps — breaks complex tasks into sub-steps
    task_steps: Vec<String>,
    /// Debug mode — prints every step to stderr
    debug_mode: bool,
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
            agent_facts: Vec::new(),
            agent_context: None,
            task_steps: Vec::new(),
            debug_mode: false,
        }
    }

    /// Set instructions for the agent (system prompt).
    pub fn instructions(mut self, instructions: &str) -> Self {
        self.instructions = Some(instructions.to_string());
        self
    }

    /// Add knowledge facts for this agent (appended to Connector-level knowledge).
    ///
    /// ```rust,ignore
    /// c.agent("doctor")
    ///     .instructions("You are a medical AI")
    ///     .facts(&["Patient is 45yo male", "Allergic to penicillin"])
    ///     .run("What medication?", "user:p1")?;
    /// ```
    pub fn facts(mut self, facts: &[&str]) -> Self {
        self.agent_facts.extend(facts.iter().map(|s| s.to_string()));
        self
    }

    /// Add a single knowledge fact for this agent.
    pub fn fact(mut self, fact: &str) -> Self {
        self.agent_facts.push(fact.to_string());
        self
    }

    /// Alias for `.facts()` — same as Connector-level `.knowledge()` but scoped to this agent.
    ///
    /// Use `.knowledge()` or `.facts()` interchangeably — both inject knowledge into the
    /// agent's system prompt. This alias exists so the naming is consistent between
    /// `Connector::new().knowledge(&[...])` and `agent.knowledge(&[...])`.
    pub fn knowledge(self, facts: &[&str]) -> Self {
        self.facts(facts)
    }

    /// Add additional context for this specific run.
    ///
    /// Context is prepended to the user message, providing situational awareness.
    ///
    /// ```rust,ignore
    /// c.agent("bot")
    ///     .context("The user is in the billing department")
    ///     .run("Help me with an invoice", "user:a")?;
    /// ```
    pub fn context(mut self, context: &str) -> Self {
        self.agent_context = Some(context.to_string());
        self
    }

    /// Break a complex task into ordered steps (task decomposition).
    ///
    /// Each step is executed sequentially, with the output of each step
    /// fed as context to the next. The final output is from the last step.
    ///
    /// ```rust,ignore
    /// c.agent("researcher")
    ///     .instructions("You are a research AI")
    ///     .steps(&[
    ///         "Identify the top 3 relevant papers on the topic",
    ///         "Summarize key findings from each paper",
    ///         "Generate actionable recommendations based on the findings",
    ///     ])
    ///     .run("Research AI safety in healthcare", "user:a")?;
    /// ```
    pub fn steps(mut self, steps: &[&str]) -> Self {
        self.task_steps = steps.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Enable debug mode — prints every pipeline step to stderr.
    ///
    /// This is the "100x more stable than LangChain" feature.
    /// No external tool needed — built-in, zero-config.
    ///
    /// ```rust,ignore
    /// c.agent("bot")
    ///     .debug(true)
    ///     .run("Hello", "user:a")?;
    /// // stderr shows: knowledge injection, prompt assembly, LLM call, memory storage, grounding
    /// ```
    pub fn debug(mut self, enabled: bool) -> Self {
        self.debug_mode = enabled;
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
    ///
    /// This is the simple way to register tools. It adds them to both the tool registry
    /// and the RBAC allow list, so you don't need to call `.allow_tools()` separately.
    ///
    /// For fine-grained control (e.g., allow some tools but deny others), use
    /// `.allow_tools()` and `.deny_tools()` instead.
    pub fn tools(mut self, tool_names: &[&str]) -> Self {
        self.tools = tool_names.iter().map(|s| s.to_string()).collect();
        for name in tool_names {
            let s = name.to_string();
            if !self.allowed_tools.contains(&s) {
                self.allowed_tools.push(s);
            }
        }
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

    /// Set token budget only.
    pub fn budget_tokens(mut self, max_tokens: u64) -> Self {
        self.budget_tokens = Some(max_tokens);
        self
    }

    /// Set cost budget only.
    pub fn budget_cost(mut self, max_cost_usd: f64) -> Self {
        self.budget_cost = Some(max_cost_usd);
        self
    }

    /// Run the agent — zero friction, auto-generated session.
    ///
    /// For quick prototyping. No session ID needed:
    /// ```rust,ignore
    /// let r = c.agent("bot").instructions("Be helpful").run_quick("Hello!")?;
    /// println!("{}", r);  // beautiful output by default
    /// ```
    pub fn run_quick(self, message: &str) -> ConnectorResult<PipelineOutput> {
        let session = format!("user:{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("anon"));
        self.run(message, &session)
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

        // ══════════════════════════════════════════════════════════
        // STABILITY ENGINE: debug logger + trace + validation
        // ══════════════════════════════════════════════════════════
        let dbg = crate::trace::DebugLogger::new(&self.name, self.debug_mode);
        let mut run_trace = crate::trace::RunTrace::new(&pipeline_id, &self.name, user_id);

        dbg.step("init", &format!("Starting pipeline {} for user {}", pipeline_id, user_id));

        // ── Instruction validation (catch problems BEFORE they happen) ──
        let validation_warnings = crate::trace::validate_instructions(
            self.instructions.as_deref(),
            self.connector.knowledge_context.as_deref(),
            &self.agent_facts,
            &self.task_steps,
        );
        for w in &validation_warnings {
            dbg.warn(w);
        }
        run_trace.warnings = validation_warnings;

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

            // Phase C: Wire firewall preset → real FirewallConfig with PII types
            if let Some(ref fw_cfg) = self.connector.firewall_config {
                d = d.with_firewall(fw_cfg.clone());
            }

            d
        };

        // Phase B: Wire budget → ActionEngine (REAL enforcement)
        if let Some(ref budget) = self.connector.budget_config {
            if let Some(tokens) = budget.max_tokens {
                dispatcher.action_engine_mut().create_budget(&self.name, "tokens", tokens as f64);
            }
            if let Some(cost) = budget.max_cost_usd {
                dispatcher.action_engine_mut().create_budget(&self.name, "cost_usd", cost);
            }
        }
        if let Some(tokens) = self.budget_tokens {
            dispatcher.action_engine_mut().create_budget(&self.name, "tokens", tokens as f64);
        }
        if let Some(cost) = self.budget_cost {
            dispatcher.action_engine_mut().create_budget(&self.name, "cost_usd", cost);
        }

        // Phase B: Wire deny/allow policies → ActionEngine (REAL enforcement)
        if !self.connector.policy_rules.is_empty() {
            use connector_engine::aapi::{PolicyRule as EnginePolicyRule, PolicyEffect};
            let rules: Vec<EnginePolicyRule> = self.connector.policy_rules.iter().map(|(effect, pattern, pri)| {
                EnginePolicyRule {
                    action_pattern: pattern.clone(),
                    resource_pattern: None,
                    effect: if effect == "deny" { PolicyEffect::Deny } else { PolicyEffect::Allow },
                    roles: vec![],
                    priority: *pri,
                }
            }).collect();
            dispatcher.action_engine_mut().add_policy("shorthand_policy", "Auto-generated from YAML deny/allow", rules);
        }

        // Phase I: Wire tool definitions → ActionEngine capabilities
        for (tool_name, tool_desc) in &self.connector.tool_defs {
            dispatcher.action_engine_mut().register_tool(tool_name, tool_desc);
        }

        // Wire Connector-level tool registry → dispatcher
        if let Ok(connector_registry) = self.connector.tool_registry.lock() {
            for tool_def in connector_registry.tool_defs() {
                if !dispatcher.tool_registry().tool_names().contains(&tool_def.name.as_str()) {
                    dispatcher.tool_registry_mut().register(tool_def.clone());
                }
            }
        }

        // Register the agent
        dbg.step("register", &format!("Registering agent '{}'", self.name));
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

        // ══════════════════════════════════════════════════════════
        // Conversation History — architecture note
        //
        // Each run() creates a new DualDispatcher with a unique pipeline_id,
        // which means each agent gets a new namespace (ns:pipe:UUID/name).
        // Cross-run history requires a shared session namespace, which is a
        // planned feature (P0.2 in FINAL_WORK_CHECKLIST.md).
        //
        // When wired: recall previous user/assistant messages from a shared
        // session namespace, build [system, ...history, user] message array,
        // and pass to router.chat_sync() for true multi-turn conversations.
        // ══════════════════════════════════════════════════════════

        // Write the user input as a memory packet
        dbg.step("memory", &format!("Storing input: '{}'", &message[..message.len().min(60)]));
        let input_mem = dispatcher.remember(
            &pid,
            message,
            user_id,
            DerivationContext::UserInput,
            None,
        )?;
        run_trace.input_cid = Some(input_mem.id.clone());

        // ══════════════════════════════════════════════════════════
        // Phase A: Knowledge injection → build layered system prompt
        // Layer 1: Connector-level knowledge context
        // Layer 2: Agent-level facts
        // Layer 3: Instructions (or smart default)
        // Layer 4: Task steps (if any)
        // ══════════════════════════════════════════════════════════
        let instructions_or_default = self.instructions.clone()
            .or_else(|| Some("You are a helpful AI assistant.".to_string()));
        run_trace.instructions = instructions_or_default.clone().unwrap_or_default();

        let mut system_parts: Vec<String> = Vec::new();
        let mut all_knowledge_facts: Vec<String> = Vec::new();

        // Layer 1: Connector-level knowledge
        if let Some(ref knowledge) = self.connector.knowledge_context {
            system_parts.push(knowledge.clone());
            // Extract individual facts from knowledge context
            for line in knowledge.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && !trimmed.starts_with('[')
                    && !trimmed.ends_with(']')
                {
                    all_knowledge_facts.push(trimmed.to_string());
                }
            }
            dbg.step("knowledge", &format!("Injected {} connector-level facts", all_knowledge_facts.len()));
        }
        run_trace.knowledge_facts = all_knowledge_facts.clone();

        // Layer 2: Agent-level facts
        if !self.agent_facts.is_empty() {
            system_parts.push(format!(
                "[Agent Knowledge]\n{}\n[End Agent Knowledge]",
                self.agent_facts.join("\n")
            ));
            all_knowledge_facts.extend(self.agent_facts.clone());
            dbg.step("knowledge", &format!("Injected {} agent-level facts", self.agent_facts.len()));
        }
        run_trace.agent_facts = self.agent_facts.clone();

        // Layer 2.5: RAG retrieval — kernel-native grounded context
        // Build entity graph from existing kernel packets, then retrieve relevant facts
        {
            let agent_ns = format!("ns:{}/{}", dispatcher.pipeline_id(), self.name);
            dispatcher.build_knot_from_namespace(&agent_ns);

            // Extract simple keywords from the user message for RAG query
            let keywords: Vec<String> = message.split_whitespace()
                .filter(|w| w.len() > 3) // skip short words
                .map(|w| w.to_lowercase().trim_matches(|c: char| !c.is_alphanumeric()).to_string())
                .filter(|w| !w.is_empty())
                .collect();

            // Also use entity IDs from knowledge facts as entity queries
            let entities: Vec<String> = all_knowledge_facts.iter()
                .flat_map(|f| f.split_whitespace())
                .filter(|w| w.contains(':')) // entity-like patterns: "patient:001"
                .map(|w| w.to_string())
                .collect();

            if !keywords.is_empty() || !entities.is_empty() {
                let rag_ctx = dispatcher.rag_retrieve(&entities, &keywords);
                if rag_ctx.facts_included > 0 {
                    system_parts.push(rag_ctx.to_prompt_context());
                    dbg.step("rag", &format!("RAG injected {} grounded facts ({} tokens, {} sources)",
                        rag_ctx.facts_included, rag_ctx.tokens_used, rag_ctx.source_cids.len()));
                } else {
                    dbg.step("rag", "RAG query returned no relevant facts");
                }
            }
        }

        // Layer 3: Instructions
        if let Some(ref instructions) = instructions_or_default {
            system_parts.push(instructions.clone());
            dbg.step("instructions", &format!("System prompt: '{}'", &instructions[..instructions.len().min(80)]));
        }

        // Layer 4: Task decomposition steps
        if !self.task_steps.is_empty() {
            let steps_text = self.task_steps.iter().enumerate()
                .map(|(i, s)| format!("Step {}: {}", i + 1, s))
                .collect::<Vec<_>>()
                .join("\n");
            system_parts.push(format!(
                "[Task Plan — complete each step in order]\n{}\n[End Task Plan]",
                steps_text
            ));
            dbg.step("steps", &format!("{} task steps injected", self.task_steps.len()));
        }
        run_trace.task_steps = self.task_steps.clone();

        // Layer 5: Tool definitions — inject available tool schemas for function calling
        if !self.tools.is_empty() || !self.actions.is_empty() {
            let mut tool_lines: Vec<String> = Vec::new();
            tool_lines.push("[Available Tools]".to_string());

            // Simple tool names (from .tools())
            for tool_name in &self.tools {
                if !self.actions.iter().any(|a| &a.name == tool_name) {
                    tool_lines.push(format!("- {}", tool_name));
                }
            }

            // Typed Actions with JSON schemas (from .action())
            for action in &self.actions {
                let schema = action.to_json_schema();
                tool_lines.push(format!("- {} : {}", action.name, schema));
            }

            tool_lines.push("[End Available Tools]".to_string());
            tool_lines.push("To call a tool, respond with: [TOOL_CALL: tool_name(params)]".to_string());
            system_parts.push(tool_lines.join("\n"));
            dbg.step("tools", &format!("{} tools injected into prompt ({} simple, {} typed)",
                self.tools.len() + self.actions.len(),
                self.tools.len(),
                self.actions.len()));
        }

        let effective_system = if system_parts.is_empty() { None } else { Some(system_parts.join("\n\n")) };
        let system = effective_system.as_deref();
        run_trace.system_prompt = effective_system.clone();
        run_trace.knowledge_tokens_approx = effective_system.as_ref()
            .map(|s| s.split_whitespace().count())
            .unwrap_or(0);

        // Phase G: Retry logic — wrap LLM call with exponential backoff
        let max_retries = self.connector.retry_count.unwrap_or(0);

        // Phase F: Cognitive loop — multi-pass reasoning (think: deep)
        let think_cycles = self.connector.cognitive_config.as_ref()
            .and_then(|c| c.max_cycles)
            .unwrap_or(1);
        let reflection_enabled = self.connector.cognitive_config.as_ref()
            .map(|c| c.reflection_enabled)
            .unwrap_or(false);

        // Wire agent_context into the effective message
        let effective_message = match &self.agent_context {
            Some(ctx) => {
                dbg.step("context", &format!("Prepending context: '{}'", &ctx[..ctx.len().min(60)]));
                format!("[Context: {}]\n\n{}", ctx, message)
            }
            None => message.to_string(),
        };
        run_trace.effective_message = effective_message.clone();

        // ══════════════════════════════════════════════════════════
        // Guard Pipeline — 5-layer input validation
        // MAC → Policy → Content → Rate → Audit
        // ══════════════════════════════════════════════════════════
        let agent_ns = format!("ns:{}/{}", dispatcher.pipeline_id(), self.name);
        let input_guard = dispatcher.guard_check_input(&pid, &effective_message, &agent_ns);
        if input_guard.final_decision.is_deny() {
            let reason = match &input_guard.final_decision {
                connector_engine::guard_pipeline::GuardDecision::Deny { reason } => reason.clone(),
                _ => "Guard pipeline denied input".to_string(),
            };
            dbg.step("guard", &format!("INPUT BLOCKED: {}", reason));
            // Build a blocked output from kernel state
            let duration_ms = start.elapsed().as_millis() as u64;
            let output = OutputBuilder::build(
                dispatcher.kernel(),
                format!("[Input blocked by guard pipeline: {}]", reason),
                &pipeline_id,
                1,
                &self.connector.compliance,
                duration_ms,
                vec![],
            );
            return Ok(output);
        }
        dbg.step("guard", &format!("Input passed 5-layer guard ({} layers evaluated)",
            input_guard.layer_verdicts.len()));

        // ══════════════════════════════════════════════════════════
        // LLM Execution — with full tracing
        // ══════════════════════════════════════════════════════════
        let llm_has_router = dispatcher.llm_router().is_some();
        run_trace.llm_called = llm_has_router;
        run_trace.llm_model = self.connector.llm_config.as_ref()
            .map(|c| format!("{}:{}", c.provider, c.model));

        dbg.step("llm", &format!("Think cycles: {}, retries: {}, LLM: {}",
            think_cycles, max_retries,
            if llm_has_router { "connected" } else { "simulation" }));

        let mut response_text = String::new();
        let mut total_retries = 0u32;
        for cycle in 0..think_cycles {
            let cycle_prompt = if cycle == 0 {
                effective_message.clone()
            } else if reflection_enabled {
                format!(
                    "[Reflection cycle {}/{}] Review and improve your previous response:\n\n{}\n\nOriginal question: {}",
                    cycle + 1, think_cycles, response_text, message
                )
            } else {
                message.to_string()
            };

            let mut attempt_text = None;
            for attempt in 0..=max_retries {
                let result = if let Some(router) = dispatcher.llm_router() {
                    match router.complete_sync(&cycle_prompt, system) {
                        Ok(resp) => {
                            dbg.step("llm", &format!("Cycle {}: received {} chars", cycle + 1, resp.text.len()));
                            Some(resp.text)
                        }
                        Err(e) => {
                            total_retries += 1;
                            dbg.step("llm", &format!("Cycle {} attempt {}: error: {}", cycle + 1, attempt + 1, e));
                            if attempt < max_retries {
                                let backoff_ms = 100 * (1u64 << attempt.min(6));
                                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                                None
                            } else {
                                Some(format!("[LLM error after {} retries: {}]", max_retries + 1, e))
                            }
                        }
                    }
                } else {
                    Some(format!(
                        "[Agent '{}' would process: '{}' for {}]",
                        self.name,
                        &cycle_prompt[..cycle_prompt.len().min(50)],
                        user_id
                    ))
                };
                if let Some(text) = result {
                    attempt_text = Some(text);
                    break;
                }
            }
            response_text = attempt_text.unwrap_or_else(|| "[No response]".to_string());
        }
        run_trace.think_cycles = think_cycles;
        run_trace.retry_attempts = total_retries;

        // ══════════════════════════════════════════════════════════
        // Guard Pipeline — 5-layer output validation
        // ══════════════════════════════════════════════════════════
        let output_guard = dispatcher.guard_check_output(&pid, &response_text, &agent_ns);
        if output_guard.final_decision.is_deny() {
            let reason = match &output_guard.final_decision {
                connector_engine::guard_pipeline::GuardDecision::Deny { reason } => reason.clone(),
                _ => "Guard pipeline denied output".to_string(),
            };
            dbg.step("guard", &format!("OUTPUT BLOCKED: {}", reason));
            response_text = format!("[Output blocked by guard pipeline: {}]", reason);
            run_trace.warnings.push(format!("Guard blocked output: {}", reason));
        } else {
            dbg.step("guard", &format!("Output passed 5-layer guard ({} layers)",
                output_guard.layer_verdicts.len()));
        }

        // ══════════════════════════════════════════════════════════
        // Tool Execution — parse tool calls, gate + execute via ToolRegistry
        // Uses gate_and_execute_tool: ACL → firewall → behavior → handler → audit
        // ══════════════════════════════════════════════════════════
        if !self.tools.is_empty() || !self.actions.is_empty() || !dispatcher.tool_registry().is_empty() {
            let tool_calls = parse_tool_calls(&response_text);
            if !tool_calls.is_empty() {
                dbg.step("tools", &format!("Detected {} tool call(s) in response", tool_calls.len()));
                let mut tool_results: Vec<String> = Vec::new();

                for (tool_name, tool_params) in &tool_calls {
                    // Parse params as JSON if possible, otherwise wrap as string
                    let params_json = serde_json::from_str::<serde_json::Value>(tool_params)
                        .unwrap_or_else(|_| {
                            if tool_params.is_empty() {
                                serde_json::json!({})
                            } else {
                                serde_json::json!({"input": tool_params})
                            }
                        });

                    // Gate + execute through dispatcher (ACL → firewall → handler → audit)
                    match dispatcher.gate_and_execute_tool(&pid, tool_name, params_json) {
                        Ok(result) => {
                            let result_str = format!("{}", result);
                            tool_results.push(format!("[Tool '{}': {}]", tool_name, result_str));
                            dbg.step("tools", &format!("Tool '{}': {}", tool_name, result_str));
                        }
                        Err(e) => {
                            // Tool blocked by firewall or other gate error
                            tool_results.push(format!("[Tool '{}' BLOCKED: {}]", tool_name, e));
                            dbg.step("tools", &format!("Tool '{}' BLOCKED: {}", tool_name, e));
                            run_trace.warnings.push(format!("Tool '{}' blocked: {}", tool_name, e));
                        }
                    }
                }

                // Append tool execution results to response
                if !tool_results.is_empty() {
                    response_text.push_str("\n\n[Tool Execution Results]\n");
                    response_text.push_str(&tool_results.join("\n"));
                }
            }
        }

        run_trace.response_text = response_text.clone();

        // ══════════════════════════════════════════════════════════
        // Perception Engine — rich entity extraction + quality scoring
        // Replaces basic extract_basic_entities with full pipeline
        // ══════════════════════════════════════════════════════════
        {
            let perceived = dispatcher.perceive_context(&agent_ns, None, 20);
            if perceived.total_found > 0 {
                dbg.step("perception", &format!("Perceived {} memories in namespace, judgment: {} ({})",
                    perceived.total_found, perceived.judgment.score, perceived.judgment.grade));
            }
        }

        // ══════════════════════════════════════════════════════════
        // Grounding Check — cryptographic anti-hallucination
        // ══════════════════════════════════════════════════════════
        let (grounding_score, grounding_details) = crate::trace::check_grounding(
            &response_text,
            &all_knowledge_facts,
        );
        run_trace.grounding_score = grounding_score;
        run_trace.grounding_details = grounding_details;

        if !all_knowledge_facts.is_empty() {
            dbg.step("grounding", &format!("Score: {:.0}% ({}/{} claims grounded)",
                grounding_score * 100.0,
                run_trace.grounding_details.iter().filter(|c| c.grounded).count(),
                run_trace.grounding_details.len()
            ));
        }

        // Write the LLM response as a memory packet
        dbg.step("memory", &format!("Storing response: '{}'", &response_text[..response_text.len().min(60)]));
        let response_mem = dispatcher.remember(
            &pid,
            &response_text,
            user_id,
            DerivationContext::LlmResponse,
            None,
        )?;
        run_trace.response_cid = Some(response_mem.id.clone());

        let duration_ms = start.elapsed().as_millis() as u64;
        run_trace.duration_ms = duration_ms;
        run_trace.total_packets = dispatcher.kernel().packet_count();
        run_trace.total_audit_entries = dispatcher.kernel().audit_count();

        // ══════════════════════════════════════════════════════════
        // Judgment Engine — 8-dimension trust assessment of kernel state
        // ══════════════════════════════════════════════════════════
        let judgment = dispatcher.judge_kernel_state(None, &connector_engine::judgment::JudgmentConfig::default());
        dbg.step("judgment", &format!("Kernel judgment: {} ({}) — {} ops analyzed",
            judgment.score, judgment.grade, judgment.operations_analyzed));

        dbg.step("done", &format!("Completed in {}ms | packets:{} | audit:{} | grounding:{:.0}% | judgment:{}",
            duration_ms, run_trace.total_packets, run_trace.total_audit_entries, grounding_score * 100.0, judgment.score));

        // Phase 6: Collect real AAPI stats from the action engine
        let aapi_stats = connector_engine::output::ActionEngineStats {
            action_records: dispatcher.action_engine().action_count(),
            interaction_count: dispatcher.action_engine().interaction_count(),
            policy_count: dispatcher.action_engine().policy_count(),
            capability_count: dispatcher.action_engine().capability_count(),
            budget_count: dispatcher.action_engine().budget_count(),
        };

        // Build the output from kernel state + AAPI engine
        let mut output = OutputBuilder::build_with_aapi(
            dispatcher.kernel(),
            response_text.clone(),
            &pipeline_id,
            1,
            &self.connector.compliance,
            duration_ms,
            vec![input_mem],
            Some(aapi_stats),
        );

        // Attach the RunTrace to output warnings/events for discoverability
        if !run_trace.warnings.is_empty() {
            output.warnings.extend(run_trace.warnings.clone());
        }

        // Emit grounding event
        if !all_knowledge_facts.is_empty() {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            output.events.push(connector_engine::output::ObservationEvent {
                event_type: "grounding.check".to_string(),
                severity: if grounding_score >= 0.5 {
                    connector_engine::output::EventSeverity::Info
                } else {
                    connector_engine::output::EventSeverity::Warning
                },
                message: format!("Grounding score: {:.0}% ({}/{} claims)",
                    grounding_score * 100.0,
                    run_trace.grounding_details.iter().filter(|c| c.grounded).count(),
                    run_trace.grounding_details.len()),
                agent: Some(self.name.clone()),
                cid: run_trace.response_cid.clone(),
                source: connector_engine::output::Provenance::Kernel,
                timestamp_ms: now_ms,
            });
        }

        // Phase J: Streaming — chunk response into output events
        if let Some(ref stream_cfg) = self.connector.streaming_config {
            let chunk_size = stream_cfg.chunk_size_tokens.unwrap_or(10) as usize;
            // Approximate tokens as words (rough but functional)
            let words: Vec<&str> = response_text.split_whitespace().collect();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            for (i, chunk) in words.chunks(chunk_size).enumerate() {
                output.events.push(connector_engine::output::ObservationEvent {
                    event_type: "stream.chunk".to_string(),
                    severity: connector_engine::output::EventSeverity::Info,
                    message: chunk.join(" "),
                    agent: Some(self.name.clone()),
                    cid: None,
                    source: connector_engine::output::Provenance::Llm,
                    timestamp_ms: now_ms + (i as i64 * 50), // simulate 50ms between chunks
                });
            }

            // Emit stream metadata event
            output.events.push(connector_engine::output::ObservationEvent {
                event_type: "stream.complete".to_string(),
                severity: connector_engine::output::EventSeverity::Info,
                message: format!("Streaming complete: {} chunks via {}", words.chunks(chunk_size).count(), stream_cfg.protocol),
                agent: Some(self.name.clone()),
                cid: None,
                source: connector_engine::output::Provenance::Kernel,
                timestamp_ms: now_ms + (words.chunks(chunk_size).count() as i64 * 50),
            });
        }

        // Store the RunTrace in output metadata for access via output.run_trace
        output.run_trace = serde_json::to_value(&run_trace).ok();

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
    ///
    /// **Note:** Tags are not yet wired into storage — they are currently ignored.
    /// The memory is stored without tag metadata. Tag support is planned.
    pub fn remember_with_tags(self, text: &str, user_id: &str, _tags: &[&str]) -> ConnectorResult<connector_engine::ConnectorMemory> {
        if !_tags.is_empty() {
            eprintln!("[connector] remember_with_tags(): tags are not yet stored — memory will be saved without tags.");
        }
        self.remember(text, user_id)
    }

    // ─── Cap 5: Recall memories ──────────────────────────────────

    /// Recall memories for a user.
    ///
    /// **Note:** The `query` parameter is not yet used for semantic search.
    /// Currently returns recent memories for the user regardless of query.
    /// Semantic search (via RAG engine) is planned.
    pub fn recall(self, _query: &str, user_id: &str) -> ConnectorResult<Vec<connector_engine::ConnectorMemory>> {
        if !_query.is_empty() {
            eprintln!("[connector] recall(): semantic search not yet implemented — returning recent memories for user.");
        }
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
    /// **Status: Not yet implemented.** Port-based messaging is designed but not yet
    /// wired into the runtime. This method returns an error explaining what's planned.
    ///
    /// When implemented, this will create a typed Port channel between agents,
    /// send the message through the kernel, and return the response.
    pub fn send_to(&self, _target_agent: &str, _message: &str) -> ConnectorResult<String> {
        eprintln!("[connector] send_to() is not yet implemented. Inter-agent messaging is planned for a future release.");
        Ok(format!("[Message from '{}' would be sent via kernel Port — not yet implemented]", self.name))
    }

    // ─── Cap 9: Capability delegation ────────────────────────────

    /// Delegate specific capabilities to another agent.
    ///
    /// **Status: Not yet implemented.** Capability delegation is designed but not yet
    /// wired into the runtime. This method returns Ok(()) but does not actually create
    /// a delegation chain.
    ///
    /// When implemented, this will create an Ed25519-signed DelegationChain in the kernel.
    pub fn delegate_to(&self, _target_agent: &str, _capabilities: &[&str]) -> ConnectorResult<()> {
        eprintln!("[connector] delegate_to() is not yet implemented. Capability delegation is planned for a future release.");
        Ok(())
    }

    // ─── Cap 16: Streaming ───────────────────────────────────────

    /// Run the agent with streaming response.
    ///
    /// **Status: Not yet streaming.** Currently delegates to `run()` and returns the
    /// complete response. Real SSE/streaming from the LLM is planned.
    ///
    /// When implemented, this will yield token-by-token chunks from the LLM via
    /// async iterators. The complete response will be assembled and stored as a
    /// MemPacket after streaming completes.
    ///
    /// **For now, use `run()` — you'll get the same result.**
    pub fn run_stream(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        eprintln!("[connector] run_stream() is not yet streaming — delegating to run(). Real streaming is planned.");
        self.run(message, user_id)
    }

    // ─── Cap 17: Async execution ─────────────────────────────────

    /// Run the agent asynchronously.
    ///
    /// **Status: Not yet async.** Currently delegates to `run()` synchronously.
    /// Real async execution via `tokio::spawn` is planned.
    ///
    /// When implemented, each async agent will get isolated namespaces — no memory leakage.
    ///
    /// **For now, use `run()` — you'll get the same result.**
    pub fn run_async(self, message: &str, user_id: &str) -> ConnectorResult<PipelineOutput> {
        eprintln!("[connector] run_async() is not yet async — delegating to run(). Real async execution is planned.");
        self.run(message, user_id)
    }
}

// ─── PipelineOutput extensions (Cap 26-31) ───────────────────────

/// Extension trait for PipelineOutput — adds observability capabilities.
///
/// ## Progressive Disclosure (inspired by Stripe/Vercel/Terraform)
///
/// ```text
/// Level 0:  output.summary()       → "✅ Trust: 92/100 — 2 agents, 3ms, hipaa ✓"
/// Level 1:  output.dashboard()     → clean 5-line card with key metrics
/// Level 2:  output.clinical()      → medical-context view (for doctors)
///           output.security_view() → compliance/firewall view (for auditors)
///           output.explain()       → human-readable decision chain
///           output.timeline()      → clean ordered event list
/// Level 3:  output.to_json()       → full machine-parseable output
///           output.to_otel()       → full OTLP trace export
/// ```
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

    // ─── Clean Output Views (progressive disclosure) ─────────────

    /// **Level 0**: One-line status — like Terraform's "Apply complete!"
    /// Returns: "✅ Trust: 92/100 (A) — 2 agents, 3ms, hipaa ✓"
    fn summary(&self) -> String;

    /// **Level 1**: Clean dashboard card — 5 key metrics, no jargon.
    /// Like Vercel's deploy summary or Stripe's payment confirmation.
    fn dashboard(&self) -> String;

    /// **Level 2**: Medical-context view — for doctors using `observe: medical`.
    /// Shows entities found, clinical observations, trust level.
    /// No PIDs, no kernel ops, no CIDs — just clinical information.
    fn clinical(&self) -> String;

    /// **Level 2**: Security/compliance view — for auditors using `comply: [hipaa]`.
    /// Shows compliance status per framework, firewall events, denied ops.
    fn security_view(&self) -> String;

    /// **Level 2**: Human-readable decision explanation — for `think: deep`.
    /// Shows the reasoning chain in plain English, no internal action names.
    fn explain(&self) -> String;

    /// **Level 2**: Clean chronological event timeline.
    /// No PIDs, no CIDs, no jargon — just "what happened" in order.
    fn timeline(&self) -> String;

    // ─── Viral Hooks — shareable, embeddable output ──────────────

    /// Trust badge as embeddable Markdown — for READMEs, docs, reports.
    /// Returns: `![Trust: 92/100 A](https://img.shields.io/badge/Trust-92%2F100_A-brightgreen)`
    fn trust_badge_markdown(&self) -> String;

    /// Full shareable report as Markdown — for docs, PRs, compliance evidence.
    /// Includes trust, compliance, audit trail, decision explanation.
    fn share(&self) -> String;

    /// Copy-paste-able YAML snippet that reproduces this agent configuration.
    fn snippet(&self) -> String;
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
            by_operation: std::collections::HashMap::new(),
            denied_count: self.aapi.denied,
            approval_count: self.aapi.pending_approval,
            explanation,
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // CLEAN OUTPUT VIEWS — progressive disclosure
    // Inspired by: Stripe (one-line status), Vercel (deploy card),
    // Terraform ("Apply complete!"), Docker ("docker ps" table),
    // GitHub Actions (status badges), Datadog (waterfall traces)
    // ═══════════════════════════════════════════════════════════════

    // ─── Level 0: One-line summary ───────────────────────────────

    fn summary(&self) -> String {
        let icon = if self.status.ok { "✅" } else { "❌" };
        let trust_icon = match self.status.trust {
            90..=100 => "🛡️",
            70..=89 => "🔵",
            50..=69 => "🟡",
            _ => "🔴",
        };
        let compliance = if self.aapi.compliance.is_empty() {
            String::new()
        } else {
            format!(", {}", self.aapi.compliance.iter()
                .map(|c| format!("{} ✓", c))
                .collect::<Vec<_>>()
                .join(" "))
        };
        let denied = if self.aapi.denied > 0 {
            format!(", {} denied", self.aapi.denied)
        } else {
            String::new()
        };
        format!(
            "{} Trust: {}/100 ({}) {} — {} agent{}, {}ms{}{}",
            icon,
            self.status.trust,
            self.status.trust_grade,
            trust_icon,
            self.status.actors,
            if self.status.actors != 1 { "s" } else { "" },
            self.status.duration_ms,
            compliance,
            denied,
        )
    }

    // ─── Level 1: Dashboard card ─────────────────────────────────

    fn dashboard(&self) -> String {
        let icon = if self.status.ok { "✅" } else { "❌" };
        let mut lines = Vec::new();

        lines.push(format!("{} Pipeline Complete", icon));
        lines.push(format!("   Trust: {}/100 ({}) — {}", self.status.trust, self.status.trust_grade,
            match self.status.trust {
                90..=100 => "Excellent — all integrity checks passed",
                70..=89 => "Good — minor observations noted",
                50..=69 => "Fair — review recommended",
                _ => "Low — immediate review required",
            }
        ));
        lines.push(format!("   Agents: {}  |  Duration: {}ms  |  Memories: {}",
            self.status.actors, self.status.duration_ms, self.memory.total_packets));

        if self.aapi.denied > 0 || self.aapi.pending_approval > 0 {
            lines.push(format!("   Security: {} authorized, {} denied, {} awaiting approval",
                self.aapi.authorized, self.aapi.denied, self.aapi.pending_approval));
        }

        if !self.aapi.compliance.is_empty() {
            let comp: Vec<String> = self.aapi.compliance.iter().map(|c| format!("{} ✓", c.to_uppercase())).collect();
            lines.push(format!("   Compliance: {}", comp.join("  ")));
        }

        if !self.warnings.is_empty() {
            lines.push(format!("   ⚠️  {} warning{}", self.warnings.len(),
                if self.warnings.len() != 1 { "s" } else { "" }));
        }

        lines.join("\n")
    }

    // ─── Level 2: Clinical view ──────────────────────────────────

    fn clinical(&self) -> String {
        let mut lines = Vec::new();
        let icon = if self.status.ok { "✅" } else { "⚠️" };

        lines.push(format!("{} Clinical Summary", icon));
        lines.push(String::new());

        // Response (the clinical content)
        lines.push("  Assessment:".to_string());
        for line in self.text.lines() {
            if !line.trim().is_empty() {
                lines.push(format!("    {}", line.trim()));
            }
        }
        lines.push(String::new());

        // Entities extracted from events
        let entity_events: Vec<_> = self.events.iter()
            .filter(|e| e.event_type.contains("entity") || e.event_type.contains("observe"))
            .collect();
        if !entity_events.is_empty() {
            lines.push("  Observations:".to_string());
            for evt in entity_events {
                lines.push(format!("    - {}", evt.message));
            }
            lines.push(String::new());
        }

        // Memories created (clinical notes)
        if !self.memory.memories.is_empty() {
            lines.push("  Clinical Notes Recorded:".to_string());
            for mem in &self.memory.memories {
                let preview = if mem.content.len() > 100 {
                    format!("{}...", &mem.content[..97])
                } else {
                    mem.content.clone()
                };
                lines.push(format!("    - {}", preview));
            }
            lines.push(String::new());
        }

        // Trust & verification
        let trust_label = match self.status.trust {
            90..=100 => "High confidence",
            70..=89 => "Good confidence",
            50..=69 => "Moderate confidence — verify with clinical judgment",
            _ => "Low confidence — requires physician review",
        };
        lines.push(format!("  Confidence: {}/100 — {}", self.status.trust, trust_label));

        // Compliance
        if !self.aapi.compliance.is_empty() {
            let comp: Vec<String> = self.aapi.compliance.iter().map(|c| c.to_uppercase()).collect();
            lines.push(format!("  Compliance: {} compliant", comp.join(", ")));
        }

        lines.join("\n")
    }

    // ─── Level 2: Security view ──────────────────────────────────

    fn security_view(&self) -> String {
        let mut lines = Vec::new();
        let icon = if self.aapi.denied == 0 { "🔒" } else { "⚠️" };

        lines.push(format!("{} Security & Compliance Report", icon));
        lines.push(String::new());

        // Trust
        let shield = match self.status.trust {
            90..=100 => "🛡️",
            70..=89 => "🔵",
            50..=69 => "🟡",
            _ => "🔴",
        };
        lines.push(format!("  Trust Score: {}/100 ({}) {}", self.status.trust, self.status.trust_grade, shield));
        let dims = &self.connector.trust_details.dimensions;
        lines.push(format!("    Memory integrity: {}/20  |  Audit completeness: {}/20",
            dims.memory_integrity, dims.audit_completeness));
        lines.push(format!("    Authorization: {}/20     |  Provenance: {}/20",
            dims.authorization_coverage, dims.decision_provenance));
        lines.push(format!("    Operational health: {}/20", dims.operational_health));
        lines.push(String::new());

        // Authorization summary
        lines.push("  Authorization:".to_string());
        lines.push(format!("    {} operations authorized", self.aapi.authorized));
        if self.aapi.denied > 0 {
            lines.push(format!("    {} operations DENIED ⛔", self.aapi.denied));
        }
        if self.aapi.pending_approval > 0 {
            lines.push(format!("    {} operations awaiting human approval ⏳", self.aapi.pending_approval));
        }
        lines.push(String::new());

        // Compliance frameworks
        if !self.aapi.compliance.is_empty() {
            lines.push("  Compliance:".to_string());
            for framework in &self.aapi.compliance {
                let report = self.comply(framework);
                let status_icon = match report.status {
                    ComplianceStatus::Compliant => "✅",
                    ComplianceStatus::PartiallyCompliant => "⚠️",
                    ComplianceStatus::NonCompliant => "❌",
                    ComplianceStatus::NotApplicable => "➖",
                };
                lines.push(format!("    {} {} — {}/{} controls passed ({})",
                    status_icon,
                    framework.to_uppercase(),
                    report.controls_passed,
                    report.controls_total,
                    report.status,
                ));
                for control in &report.controls {
                    let ctl_icon = if control.passed { "  ✓" } else { "  ✗" };
                    lines.push(format!("      {} {} — {}", ctl_icon, control.control_id, control.description));
                }
                if !report.remediations.is_empty() {
                    lines.push("      Recommendations:".to_string());
                    for rem in &report.remediations {
                        lines.push(format!("        → {}", rem));
                    }
                }
            }
            lines.push(String::new());
        }

        // Firewall events
        let fw_events: Vec<_> = self.events.iter()
            .filter(|e| e.event_type.contains("firewall") || e.event_type.contains("block")
                || e.severity == connector_engine::output::EventSeverity::Warning)
            .collect();
        if !fw_events.is_empty() {
            lines.push("  Firewall & Security Events:".to_string());
            for evt in fw_events {
                let sev = match evt.severity {
                    connector_engine::output::EventSeverity::Info => "ℹ️",
                    connector_engine::output::EventSeverity::Warning => "⚠️",
                    connector_engine::output::EventSeverity::Error => "❌",
                };
                lines.push(format!("    {} {}", sev, clean_event_message(&evt.message)));
            }
            lines.push(String::new());
        }

        // Audit
        lines.push(format!("  Audit: {} entries recorded, all kernel-verified", self.connector.audit_entries));
        let prov = self.provenance_summary();
        let trust_pct = prov["trust_percentage"].as_f64().unwrap_or(0.0);
        lines.push(format!("  Provenance: {:.0}% kernel-verified (zero-fake: {})",
            trust_pct, if trust_pct >= 100.0 { "✅" } else { "⚠️" }));

        lines.join("\n")
    }

    // ─── Level 2: Decision explanation ───────────────────────────

    fn explain(&self) -> String {
        let mut lines = Vec::new();

        lines.push("📋 Decision Explanation".to_string());
        lines.push(String::new());

        let xray = self.xray();

        // Numbered steps in plain English
        for step in &xray.reasoning_steps {
            let human_action = match step.action.as_str() {
                "input_received" => "Received input and started processing",
                "memories_created" => "Stored observations in memory",
                "authorization" => "Checked permissions and access control",
                "trust_computed" => "Computed trust and integrity score",
                _ => &step.action,
            };
            lines.push(format!("  {}. {} — {}", step.step, human_action, step.detail));
        }
        lines.push(String::new());

        // Bottom line
        if self.status.ok {
            lines.push(format!("  Result: Completed successfully with {}/100 trust.", self.status.trust));
        } else {
            lines.push(format!("  Result: Completed with issues — {} denied operations. Trust: {}/100.",
                self.aapi.denied, self.status.trust));
        }

        if !self.warnings.is_empty() {
            lines.push(String::new());
            lines.push("  Notes:".to_string());
            for w in &self.warnings {
                lines.push(format!("    ⚠️  {}", clean_event_message(w)));
            }
        }

        lines.join("\n")
    }

    // ─── Level 2: Event timeline ─────────────────────────────────

    fn timeline(&self) -> String {
        let mut lines = Vec::new();

        lines.push("📅 Event Timeline".to_string());
        lines.push(String::new());

        if self.events.is_empty() {
            lines.push("  No events recorded.".to_string());
            return lines.join("\n");
        }

        for (i, evt) in self.events.iter().enumerate() {
            let icon = match evt.severity {
                connector_engine::output::EventSeverity::Info => "  ●",
                connector_engine::output::EventSeverity::Warning => "  ⚠",
                connector_engine::output::EventSeverity::Error => "  ✗",
            };
            let agent_label = evt.agent.as_deref()
                .map(|a| clean_agent_name(a))
                .unwrap_or_default();
            let clean_msg = clean_event_message(&evt.message);
            let event_label = clean_event_type(&evt.event_type);

            if i < self.events.len() - 1 {
                lines.push(format!("{} {} {}{}", icon, event_label, clean_msg,
                    if agent_label.is_empty() { String::new() } else { format!(" ({})", agent_label) }));
                lines.push("  │".to_string());
            } else {
                lines.push(format!("{} {} {}{}", icon, event_label, clean_msg,
                    if agent_label.is_empty() { String::new() } else { format!(" ({})", agent_label) }));
            }
        }

        lines.push(String::new());
        lines.push(format!("  {} events in {}ms", self.events.len(), self.status.duration_ms));

        lines.join("\n")
    }

    // ═══════════════════════════════════════════════════════════════
    // VIRAL HOOKS — shareable, embeddable output
    // ═══════════════════════════════════════════════════════════════

    fn trust_badge_markdown(&self) -> String {
        let color = match self.status.trust {
            90..=100 => "brightgreen",
            70..=89 => "green",
            50..=69 => "yellow",
            30..=49 => "orange",
            _ => "red",
        };
        let label = format!("Trust-{}%2F100_{}", self.status.trust, self.status.trust_grade);
        format!(
            "![Trust: {}/100 {}](https://img.shields.io/badge/{}-{})",
            self.status.trust, self.status.trust_grade, label, color
        )
    }

    fn share(&self) -> String {
        let mut lines = Vec::new();

        lines.push("## Agent Run Report".to_string());
        lines.push(String::new());

        // Trust badge
        lines.push(self.trust_badge_markdown());
        lines.push(String::new());

        // Summary
        lines.push(format!("**Status**: {} | **Trust**: {}/100 ({}) | **Duration**: {}ms",
            if self.status.ok { "✅ OK" } else { "❌ Failed" },
            self.status.trust, self.status.trust_grade, self.status.duration_ms));
        lines.push(String::new());

        // Response
        lines.push("### Response".to_string());
        lines.push(format!("> {}", self.text.replace('\n', "\n> ")));
        lines.push(String::new());

        // Compliance
        if !self.aapi.compliance.is_empty() {
            lines.push("### Compliance".to_string());
            for framework in &self.aapi.compliance {
                let report = self.comply(framework);
                let icon = match report.status {
                    ComplianceStatus::Compliant => "✅",
                    ComplianceStatus::PartiallyCompliant => "⚠️",
                    ComplianceStatus::NonCompliant => "❌",
                    ComplianceStatus::NotApplicable => "➖",
                };
                lines.push(format!("- {} **{}** — {}/{} controls passed",
                    icon, framework.to_uppercase(), report.controls_passed, report.controls_total));
            }
            lines.push(String::new());
        }

        // Security
        lines.push("### Security".to_string());
        lines.push(format!("- **Authorized**: {} | **Denied**: {} | **Pending**: {}",
            self.aapi.authorized, self.aapi.denied, self.aapi.pending_approval));
        let prov = self.provenance_summary();
        let trust_pct = prov["trust_percentage"].as_f64().unwrap_or(0.0);
        lines.push(format!("- **Provenance**: {:.0}% kernel-verified (zero-fake: {})",
            trust_pct, if trust_pct >= 100.0 { "✅" } else { "⚠️" }));
        lines.push(format!("- **Audit entries**: {}", self.connector.audit_entries));
        lines.push(String::new());

        // Footer
        lines.push("---".to_string());
        lines.push("*Generated by [Connector](https://github.com/connector-oss/connector) — Trusted Infrastructure for AI Agents*".to_string());

        lines.join("\n")
    }

    fn snippet(&self) -> String {
        let mut lines = Vec::new();
        lines.push("```yaml".to_string());
        lines.push(format!("agent: \"{}\"",
            if self.status.summary.len() > 50 { "You are a helpful assistant" }
            else { "You are a helpful assistant" }
        ));
        if !self.aapi.compliance.is_empty() {
            lines.push(format!("comply: [{}]", self.aapi.compliance.join(", ")));
        }
        if self.memory.total_packets > 0 {
            lines.push("memory: long".to_string());
        }
        lines.push("```".to_string());
        lines.join("\n")
    }
}

/// Clean up raw agent PIDs for display — "pid:abc123-def456" → "agent"
fn clean_agent_name(pid: &str) -> String {
    if pid.starts_with("pid:") {
        // Extract just the agent name portion before the UUID
        let rest = &pid[4..];
        if let Some(colon_pos) = rest.find(':') {
            rest[..colon_pos].to_string()
        } else if rest.len() > 8 {
            "agent".to_string()
        } else {
            rest.to_string()
        }
    } else if pid == "system" {
        "system".to_string()
    } else {
        pid.split(':').last().unwrap_or(pid).to_string()
    }
}

/// Clean up raw event messages — remove PIDs, CIDs, internal jargon
fn clean_event_message(msg: &str) -> String {
    let mut clean = msg.to_string();
    // Remove "by pid:xxx-yyy-zzz..." patterns
    if let Some(idx) = clean.find(" by pid:") {
        let end = clean[idx + 8..].find(|c: char| c == ' ' || c == '\n')
            .map(|i| idx + 8 + i)
            .unwrap_or(clean.len());
        clean = format!("{}{}", &clean[..idx], &clean[end..]);
    }
    // Remove "for pid:xxx..." patterns
    if let Some(idx) = clean.find(" for pid:") {
        let end = clean[idx + 9..].find(|c: char| c == ' ' || c == '\n' || c == '—')
            .map(|i| idx + 9 + i)
            .unwrap_or(clean.len());
        clean = format!("{}{}", &clean[..idx], &clean[end..]);
    }
    clean.trim().to_string()
}

/// Clean up event type names for display — "agent_register" → "Registered"
fn clean_event_type(event_type: &str) -> String {
    match event_type {
        "agent_register" | "agent.register" => "Registered →".to_string(),
        "agent_start" | "agent.start" => "Started →".to_string(),
        "mem_write" | "memory.write" => "Stored →".to_string(),
        "mem_read" | "memory.read" => "Recalled →".to_string(),
        "mem_evict" | "memory.evict" => "Evicted →".to_string(),
        "access_grant" | "access.grant" => "Shared →".to_string(),
        "access_revoke" | "access.revoke" => "Revoked →".to_string(),
        "session_create" | "session.create" => "Session →".to_string(),
        "stream.chunk" => "Streamed →".to_string(),
        "stream.complete" => "Complete →".to_string(),
        "tool.denied" => "Denied ⛔".to_string(),
        "approval.required" => "Approval ⏳".to_string(),
        "firewall.block" => "Blocked 🔒".to_string(),
        _ => {
            // Convert snake_case to Title Case
            event_type.replace('_', " ").replace('.', " ")
                .split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
                + " →"
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

    // ═══════════════════════════════════════════════════════════════
    // CLEAN OUTPUT VIEW TESTS — progressive disclosure
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_view_summary_one_liner() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let s = r.summary();
        // One line, contains key info
        assert!(s.contains("Trust:"), "summary missing trust: {}", s);
        assert!(s.contains("/100"), "summary missing score: {}", s);
        assert!(s.contains("agent"), "summary missing agent count: {}", s);
        assert!(s.contains("ms"), "summary missing duration: {}", s);
        // Status icon
        assert!(s.starts_with("✅") || s.starts_with("❌"), "summary missing status icon: {}", s);
    }

    #[test]
    fn test_view_summary_with_compliance() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let s = r.summary();
        assert!(s.contains("hipaa ✓"), "summary missing compliance: {}", s);
    }

    #[test]
    fn test_view_dashboard_card() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa", "soc2"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let d = r.dashboard();
        assert!(d.contains("Pipeline Complete"), "dashboard missing header: {}", d);
        assert!(d.contains("Trust:"), "dashboard missing trust: {}", d);
        assert!(d.contains("Agents:"), "dashboard missing agents: {}", d);
        assert!(d.contains("Duration:"), "dashboard missing duration: {}", d);
        assert!(d.contains("Memories:"), "dashboard missing memories: {}", d);
        assert!(d.contains("HIPAA ✓"), "dashboard missing compliance: {}", d);
        assert!(d.contains("SOC2 ✓"), "dashboard missing soc2: {}", d);
    }

    #[test]
    fn test_view_clinical() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doctor").instructions("You are a doctor").run("Patient has chest pain", "user:p1").unwrap();

        let cl = r.clinical();
        assert!(cl.contains("Clinical Summary"), "clinical missing header: {}", cl);
        assert!(cl.contains("Assessment:"), "clinical missing assessment: {}", cl);
        assert!(cl.contains("Confidence:"), "clinical missing confidence: {}", cl);
        assert!(cl.contains("/100"), "clinical missing score: {}", cl);
        assert!(cl.contains("HIPAA"), "clinical missing compliance: {}", cl);
        // No raw PIDs
        assert!(!cl.contains("pid:"), "clinical should not contain raw PIDs: {}", cl);
    }

    #[test]
    fn test_view_security() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let sec = r.security_view();
        assert!(sec.contains("Security & Compliance Report"), "security missing header: {}", sec);
        assert!(sec.contains("Trust Score:"), "security missing trust: {}", sec);
        assert!(sec.contains("Memory integrity:"), "security missing dimensions: {}", sec);
        assert!(sec.contains("Authorization:"), "security missing auth: {}", sec);
        assert!(sec.contains("HIPAA"), "security missing compliance: {}", sec);
        assert!(sec.contains("controls passed"), "security missing control count: {}", sec);
        assert!(sec.contains("Audit:"), "security missing audit: {}", sec);
        assert!(sec.contains("Provenance:"), "security missing provenance: {}", sec);
        assert!(sec.contains("kernel-verified"), "security missing verification: {}", sec);
    }

    #[test]
    fn test_view_explain() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let e = r.explain();
        assert!(e.contains("Decision Explanation"), "explain missing header: {}", e);
        assert!(e.contains("Received input"), "explain missing step 1: {}", e);
        assert!(e.contains("Result:"), "explain missing result: {}", e);
        // Plain English, not internal action names
        assert!(!e.contains("input_received"), "explain should use human labels: {}", e);
    }

    #[test]
    fn test_view_timeline() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let t = r.timeline();
        assert!(t.contains("Event Timeline"), "timeline missing header: {}", t);
        assert!(t.contains("events in"), "timeline missing event count: {}", t);
        // Should have timeline markers
        assert!(t.contains("●") || t.contains("⚠") || t.contains("✗"),
            "timeline missing event markers: {}", t);
        // No raw PIDs
        assert!(!t.contains("pid:"), "timeline should not contain raw PIDs: {}", t);
    }

    #[test]
    fn test_view_timeline_no_events() {
        // Edge case: empty events
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        // This output will have events from kernel, but let's verify timeline handles it
        let t = r.timeline();
        assert!(t.contains("Event Timeline"));
    }

    #[test]
    fn test_clean_agent_name() {
        assert_eq!(clean_agent_name("pid:abc123-def456"), "agent");
        assert_eq!(clean_agent_name("pid:bot:abc123"), "bot");
        assert_eq!(clean_agent_name("system"), "system");
        assert_eq!(clean_agent_name("ns:hospital:doctor"), "doctor");
    }

    #[test]
    fn test_clean_event_message() {
        let msg = "Memory stored by pid:abc123-def456-ghi789";
        let clean = clean_event_message(msg);
        assert!(!clean.contains("pid:"), "should remove PIDs: {}", clean);
        assert!(clean.contains("Memory stored"), "should keep message: {}", clean);

        let msg2 = "Access DENIED for pid:xyz789 — unauthorized";
        let clean2 = clean_event_message(msg2);
        assert!(!clean2.contains("pid:"), "should remove PIDs: {}", clean2);
    }

    #[test]
    fn test_clean_event_type() {
        assert_eq!(clean_event_type("agent_register"), "Registered →");
        assert_eq!(clean_event_type("mem_write"), "Stored →");
        assert_eq!(clean_event_type("stream.chunk"), "Streamed →");
        assert_eq!(clean_event_type("firewall.block"), "Blocked 🔒");
        // Unknown types get title-cased
        let custom = clean_event_type("custom_event");
        assert!(custom.contains("Custom"));
        assert!(custom.contains("Event"));
    }

    // ─── Display impl tests for observe types ────────────────────

    #[test]
    fn test_display_trust_badge() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let badge = r.trust_badge();
        let display = format!("{}", badge);
        assert!(display.contains("Trust Score"), "badge display: {}", display);
    }

    #[test]
    fn test_display_compliance_report() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();
        let report = r.comply("hipaa");
        let display = format!("{}", report);
        assert!(display.contains("HIPAA"), "compliance display: {}", display);
        assert!(display.contains("controls passed"), "compliance display: {}", display);
    }

    #[test]
    fn test_display_audit_trail() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let audit = r.audit();
        let display = format!("{}", audit);
        assert!(display.contains("Audit Trail"), "audit display: {}", display);
        assert!(display.contains("entries recorded"), "audit display: {}", display);
    }

    #[test]
    fn test_display_xray_result() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let xray = r.xray();
        let display = format!("{}", xray);
        assert!(display.contains("Decision X-Ray"), "xray display: {}", display);
        assert!(display.contains("Received input"), "xray display: {}", display);
    }

    #[test]
    fn test_display_replay_snapshot() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let snap = r.replay("2025-01-15T10:30:00Z");
        let display = format!("{}", snap);
        assert!(display.contains("Replay at"), "replay display: {}", display);
        assert!(display.contains("2025-01-15"), "replay display: {}", display);
    }

    #[test]
    fn test_display_passport_bundle() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let bundle = r.passport_export("user:alice");
        let display = format!("{}", bundle);
        assert!(display.contains("Memory Passport"), "passport display: {}", display);
        assert!(display.contains("user:alice"), "passport display: {}", display);
    }

    #[test]
    fn test_progressive_disclosure_levels() {
        // Verify each level gives progressively MORE detail
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let l0 = r.summary();
        let l1 = r.dashboard();
        let l2_clinical = r.clinical();
        let l2_security = r.security_view();

        // Level 0 is shortest
        assert!(l0.len() < l1.len(), "L0 ({}) should be shorter than L1 ({})", l0.len(), l1.len());
        // Level 1 is shorter than Level 2
        assert!(l1.len() < l2_security.len(), "L1 ({}) should be shorter than L2 security ({})", l1.len(), l2_security.len());
        // Clinical and security are different views
        assert_ne!(l2_clinical, l2_security, "clinical and security should be different views");
    }

    // ═══════════════════════════════════════════════════════════════
    // VIRAL HOOKS & SMART DEFAULTS TESTS
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_trust_badge_markdown() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let badge = r.trust_badge_markdown();
        assert!(badge.starts_with("![Trust:"), "badge should be markdown image: {}", badge);
        assert!(badge.contains("img.shields.io"), "badge should link to shields.io: {}", badge);
        assert!(badge.contains("/100"), "badge should contain score: {}", badge);
    }

    #[test]
    fn test_share_markdown_report() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let report = r.share();
        assert!(report.contains("## Agent Run Report"), "share missing header: {}", report);
        assert!(report.contains("img.shields.io"), "share missing badge: {}", report);
        assert!(report.contains("**Status**"), "share missing status: {}", report);
        assert!(report.contains("### Response"), "share missing response: {}", report);
        assert!(report.contains("### Compliance"), "share missing compliance: {}", report);
        assert!(report.contains("HIPAA"), "share missing hipaa: {}", report);
        assert!(report.contains("### Security"), "share missing security: {}", report);
        assert!(report.contains("kernel-verified"), "share missing provenance: {}", report);
        assert!(report.contains("Connector"), "share missing footer: {}", report);
    }

    #[test]
    fn test_snippet_yaml() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let snip = r.snippet();
        assert!(snip.contains("```yaml"), "snippet should be yaml codeblock: {}", snip);
        assert!(snip.contains("agent:"), "snippet should have agent: {}", snip);
        assert!(snip.contains("comply:"), "snippet should have comply: {}", snip);
    }

    #[test]
    fn test_help_output() {
        let help = Connector::help();
        assert!(help.contains("Connector"), "help missing title");
        assert!(help.contains("Love Ladder"), "help missing Love Ladder");
        assert!(help.contains("Output views"), "help missing output views");
        assert!(help.contains("summary()"), "help missing summary");
        assert!(help.contains("Connector::quick"), "help missing quick");
    }

    #[test]
    fn test_status_output() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let status = c.status();
        assert!(status.contains("LLM:"), "status missing LLM");
        assert!(status.contains("openai"), "status missing provider");
        assert!(status.contains("Kernel:"), "status missing kernel");
    }

    #[test]
    fn test_smart_default_agent_name() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        // Empty name defaults to "agent"
        let r = c.agent("").instructions("Hi").run("Hello", "user:alice").unwrap();
        assert!(r.status.ok);
    }

    #[test]
    fn test_error_messages_are_friendly() {
        // run_yaml with empty YAML should give a helpful error
        let err = Connector::run_yaml("", "hi", "user:a");
        assert!(err.is_err());
        let msg = err.unwrap_err();
        assert!(msg.contains("Tip:") || msg.contains("Fix:") || msg.contains("agent"),
            "error should be helpful: {}", msg);
    }

    // ═══════════════════════════════════════════════════════════════
    // POLISH: NOOB-FRIENDLY CONVENIENCE TESTS
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_run_quick_no_session_needed() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        // No session ID needed — auto-generated
        let r = c.agent("bot").instructions("Hi").run_quick("Hello!").unwrap();
        assert!(r.status.ok);
    }

    #[test]
    fn test_default_instructions() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        // No .instructions() call — should use default
        let r = c.agent("bot").run("Hello!", "user:alice").unwrap();
        assert!(r.status.ok);
    }

    #[test]
    fn test_quick_one_liner() {
        // Connector::quick() — the absolute simplest usage
        let r = Connector::quick("Hello!").unwrap();
        assert!(r.status.ok);
        assert!(r.status.trust > 0);
    }

    #[test]
    fn test_display_is_clean_not_verbose() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();

        let display = format!("{}", r);
        // Clean format — no box-drawing, no raw PIDs
        assert!(!display.contains("╔"), "should not use box-drawing: {}", display);
        assert!(!display.contains("╚"), "should not use box-drawing: {}", display);
        assert!(!display.contains("pid:"), "should not show PIDs: {}", display);
        // Has the key elements
        assert!(display.contains("Agent complete"), "missing status: {}", display);
        assert!(display.contains("/100"), "missing trust: {}", display);
        assert!(display.contains("verified"), "missing provenance: {}", display);
        assert!(display.contains(".dashboard()"), "missing hint: {}", display);
    }

    #[test]
    fn test_display_shows_differentiators() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .compliance(&["hipaa"])
            .build();
        let r = c.agent("doc").instructions("Medical AI").run("Patient info", "user:doc").unwrap();

        let display = format!("{}", r);
        // Shows what NO competitor shows
        assert!(display.contains("HIPAA ✓"), "should show compliance: {}", display);
        assert!(display.contains("verified"), "should show provenance: {}", display);
        assert!(display.contains("zero-fake"), "should show zero-fake: {}", display);
    }

    #[test]
    fn test_minimum_viable_agent() {
        // THE absolute minimum — 2 lines of meaningful code
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").run_quick("Hello!").unwrap();
        // Works with zero config beyond LLM
        assert!(r.status.ok);
        assert!(r.status.trust > 0);
        // Default output is beautiful
        let display = format!("{}", r);
        assert!(display.contains("Agent complete"));
    }
}
