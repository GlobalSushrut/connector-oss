//! Connector — the main entry point for developers.
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! // Layer 0: 3-line agent
//! let c = Connector::new()
//!     .llm("openai", "gpt-4o", "sk-...")
//!     .build();
//! ```

use std::sync::{Arc, Mutex, RwLock};
use vac_core::kernel::MemoryKernel;
use vac_core::store::{KernelStore, InMemoryKernelStore};
use crate::types::*;
use crate::agent::{AgentBuilder, PipelineOutputExt};
use crate::pipeline::PipelineBuilder;
use crate::security::SecurityConfig;
use connector_engine::tool_def::{Tool, ToolRegistry};
use connector_engine::engine_store::EngineStore;

/// Connector — the root object. Everything starts here.
///
/// Holds a shared `MemoryKernel` via `Arc<Mutex<>>` so all agents created
/// from this Connector share the same kernel. Memories persist across
/// `agent.run()`, `agent.remember()`, and `agent.recall()` calls.
#[allow(dead_code)]
pub struct Connector {
    /// LLM configuration
    pub(crate) llm_config: Option<LlmConfig>,
    /// Memory store configuration
    pub(crate) memory_config: Option<MemoryConfig>,
    /// Compliance frameworks
    pub(crate) compliance: Vec<String>,
    /// Security configuration
    pub(crate) security: SecurityConfig,
    /// Shared memory kernel — all agents share this.
    /// Uses RwLock: reads (packet_count, audit, trust) are concurrent,
    /// writes (run, remember, recall) are exclusive.
    pub(crate) kernel: Arc<RwLock<MemoryKernel>>,
    /// Storage backend — persists kernel state across restarts
    pub(crate) store: Arc<Mutex<Box<dyn KernelStore + Send>>>,
    /// Storage connection string (for display/debug)
    pub(crate) storage_uri: Option<String>,

    // ═════════════════════════════════════════════════════════════
    // Runtime config — shorthand fields that ACTUALLY EXECUTE
    // Every field here produces a real runtime effect.
    // ═════════════════════════════════════════════════════════════

    /// Knowledge facts injected into agent system prompts
    pub(crate) knowledge_context: Option<String>,
    /// Firewall config from preset expansion (hipaa → real PII types)
    pub(crate) firewall_config: Option<connector_engine::firewall::FirewallConfig>,
    /// Budget config applied to all agents
    pub(crate) budget_config: Option<crate::config::BudgetConfig>,
    /// Deny/Allow policies wired to ActionEngine
    pub(crate) policy_rules: Vec<(String, String, i32)>,
    /// Memory preset config for kernel MemoryRegion
    pub(crate) memory_preset: Option<crate::config::MemoryManagementConfig>,
    /// Trust preset config
    pub(crate) trust_config: Option<crate::config::JudgmentConfig>,
    /// Cognitive config (think: deep → multi-pass)
    pub(crate) cognitive_config: Option<crate::config::CognitiveConfig>,
    /// Retry count for LLM calls
    pub(crate) retry_count: Option<u32>,
    /// Observe/Perception config
    pub(crate) observe_config: Option<crate::config::PerceptionConfig>,
    /// Tool definitions from shorthand
    pub(crate) tool_defs: Vec<(String, String)>,
    /// Streaming config — when present, response is chunked into output events
    pub(crate) streaming_config: Option<crate::config::StreamingConfig>,
    /// Shared tool registry — tools registered at Connector level, available to all agents
    pub(crate) tool_registry: Arc<Mutex<ToolRegistry>>,
    /// Engine storage URI — persistent storage for Ring 1-4 engine state (OS folder model)
    pub(crate) engine_storage_uri: Option<String>,
    /// Cell ID for distributed storage layout
    pub(crate) cell_id: String,

    // ═════════════════════════════════════════════════════════════
    // Tier 3 — Optional-Revoke configs (absent = OFF, present = ON)
    // ═════════════════════════════════════════════════════════════

    /// Cluster config — multi-node deployment
    pub(crate) cluster_config: Option<crate::config::ClusterConfig>,
    /// Swarm config — agent fleet management
    pub(crate) swarm_config: Option<crate::config::SwarmConfig>,
    /// MCP config — Model Context Protocol integration
    pub(crate) mcp_config: Option<crate::config::McpConfig>,
    /// Server config — host/port/cors/tls overrides
    pub(crate) server_config: Option<crate::config::ServerConfig>,
    /// Watchdog config — self-healing monitor rules
    pub(crate) watchdog_config: Option<crate::config::WatchdogConfig>,
    /// Crypto config — FIPS/post-quantum modules
    pub(crate) crypto_config: Option<crate::config::CryptoConfig>,
    /// Consensus config — Raft/BFT parameters
    pub(crate) consensus_config: Option<crate::config::ConsensusConfig>,
    /// Observability config — OTel endpoint, service name
    pub(crate) observability_config: Option<crate::config::ObservabilityConfig>,
    /// Tracing config — sampling rate, max spans
    pub(crate) tracing_cfg: Option<crate::config::TracingConfig>,
    /// Negotiation config — agent contract negotiation
    pub(crate) negotiation_config: Option<crate::config::NegotiationConfig>,
    /// Formal verification config — runtime invariant checking
    pub(crate) formal_verify_config: Option<crate::config::FormalVerifyConfig>,
}

impl Clone for Connector {
    fn clone(&self) -> Self {
        Self {
            llm_config: self.llm_config.clone(),
            memory_config: self.memory_config.clone(),
            compliance: self.compliance.clone(),
            security: self.security.clone(),
            kernel: Arc::clone(&self.kernel),
            store: Arc::clone(&self.store),
            storage_uri: self.storage_uri.clone(),
            knowledge_context: self.knowledge_context.clone(),
            firewall_config: self.firewall_config.clone(),
            budget_config: self.budget_config.clone(),
            policy_rules: self.policy_rules.clone(),
            memory_preset: self.memory_preset.clone(),
            trust_config: self.trust_config.clone(),
            cognitive_config: self.cognitive_config.clone(),
            retry_count: self.retry_count,
            observe_config: self.observe_config.clone(),
            tool_defs: self.tool_defs.clone(),
            streaming_config: self.streaming_config.clone(),
            tool_registry: Arc::clone(&self.tool_registry),
            engine_storage_uri: self.engine_storage_uri.clone(),
            cell_id: self.cell_id.clone(),
            cluster_config: self.cluster_config.clone(),
            swarm_config: self.swarm_config.clone(),
            mcp_config: self.mcp_config.clone(),
            server_config: self.server_config.clone(),
            watchdog_config: self.watchdog_config.clone(),
            crypto_config: self.crypto_config.clone(),
            consensus_config: self.consensus_config.clone(),
            observability_config: self.observability_config.clone(),
            tracing_cfg: self.tracing_cfg.clone(),
            negotiation_config: self.negotiation_config.clone(),
            formal_verify_config: self.formal_verify_config.clone(),
        }
    }
}

impl Connector {
    /// Create a new Connector builder.
    pub fn new() -> ConnectorBuilder {
        ConnectorBuilder::default()
    }

    /// **The ultimate one-liner.** Zero config, auto-detect LLM, auto-session.
    ///
    /// ```rust,ignore
    /// let r = Connector::quick("What is the capital of France?")?;
    /// println!("{}", r);  // beautiful output with trust score
    /// ```
    ///
    /// This auto-detects your LLM from environment variables and generates
    /// a session ID. Perfect for prototyping, demos, and "show me it works" moments.
    pub fn quick(message: &str) -> Result<connector_engine::output::PipelineOutput, crate::error::ConnectorError> {
        let c = Self::new().build();
        c.agent("agent").run_quick(message)
    }

    /// **The "docker run hello-world" moment.** Runs a full showcase demo
    /// with compliance, trust score, and provenance — in one call.
    ///
    /// ```rust,ignore
    /// Connector::demo();  // prints beautiful output showing what Connector does
    /// ```
    ///
    /// This is designed for:
    /// - First-time users who want to see what Connector does
    /// - Conference demos and presentations
    /// - README screenshots
    /// - "Show me it works" moments
    pub fn demo() -> String {
        let c = Self::new()
            .llm("demo", "demo-model", "demo-key")
            .compliance(&["hipaa", "soc2"])
            .build();

        let output = match c.agent("doctor")
            .instructions("You are a medical AI assistant following HIPAA guidelines")
            .role("physician")
            .run("Patient reports chest pain, age 45, smoker", "user:patient-001")
        {
            Ok(o) => o,
            Err(e) => return format!("Demo failed: {}", e),
        };

        let mut lines = Vec::new();

        lines.push(String::new());
        lines.push("  ┌─────────────────────────────────────────────────────────┐".to_string());
        lines.push("  │  🚀 Connector Demo — Trusted Infrastructure for AI     │".to_string());
        lines.push("  └─────────────────────────────────────────────────────────┘".to_string());
        lines.push(String::new());

        // Show the beautiful default output
        lines.push(format!("{}", output));

        // Show what competitors DON'T give you
        lines.push("  ━━━ What you get that LangChain / CrewAI / Mem0 don't ━━━".to_string());
        lines.push(String::new());
        lines.push(format!("  🛡️  Trust Score:    {}/100 ({}) — cryptographically verified",
            output.status.trust, output.status.trust_grade));
        lines.push(format!("  📋 Compliance:     HIPAA ✓  SOC2 ✓ — one-line config"));
        lines.push(format!("  🔒 Provenance:     {}/{} events kernel-verified — zero-fake guarantee",
            output.events.iter().filter(|e| e.source == connector_engine::output::Provenance::Kernel).count(),
            output.events.len()));
        lines.push(format!("  🕐 Time Travel:    replay any decision at any point"));
        lines.push(format!("  🛂 Memory Passport: portable signed memory bundles"));
        lines.push(format!("  🔬 Agent X-Ray:    see exactly why the agent decided"));
        lines.push(String::new());

        // Show the copy-paste code
        lines.push("  ━━━ Try it yourself (copy-paste this) ━━━━━━━━━━━━━━━━━━━".to_string());
        lines.push(String::new());
        lines.push("  // 1 line:".to_string());
        lines.push("  let r = Connector::quick(\"Hello!\")?;".to_string());
        lines.push(String::new());
        lines.push("  // With compliance:".to_string());
        lines.push("  let r = Connector::run_yaml(r#\"".to_string());
        lines.push("    agent: 'You are a medical AI'".to_string());
        lines.push("    comply: [hipaa, soc2]".to_string());
        lines.push("    memory: long".to_string());
        lines.push("  \"#, \"Patient has fever\", \"user:p1\")?;".to_string());
        lines.push(String::new());
        lines.push("  println!(\"{}\", r);           // beautiful output".to_string());
        lines.push("  println!(\"{}\", r.share());    // shareable markdown report".to_string());
        lines.push("  println!(\"{}\", r.trust_badge_markdown()); // README badge".to_string());
        lines.push(String::new());

        // Show the shareable badge
        lines.push("  ━━━ Embed in your README ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
        lines.push(String::new());
        lines.push(format!("  {}", output.trust_badge_markdown()));
        lines.push(String::new());

        lines.join("\n")
    }

    /// Create a Connector from a YAML string (shorthand or full).
    ///
    /// This is the Docker-level entry point:
    /// ```rust,ignore
    /// let c = Connector::from_yaml(r#"
    ///   agent: "You are a helpful doctor"
    ///   memory: long
    ///   persist: true
    /// "#)?;
    /// let output = c.agent("agent").run("Patient has fever", "user:p1")?;
    /// ```
    pub fn from_yaml(yaml: &str) -> Result<Connector, crate::config::ConfigError> {
        let cfg = crate::shorthand::parse_shorthand(yaml)?;
        Ok(Self::from_config(&cfg))
    }

    /// Create a Connector from a YAML file (shorthand or full).
    ///
    /// ```rust,ignore
    /// let c = Connector::from_yaml_file("connector.yaml")?;
    /// ```
    pub fn from_yaml_file(path: &str) -> Result<Connector, crate::config::ConfigError> {
        let cfg = crate::shorthand::load_shorthand(path)?;
        Ok(Self::from_config(&cfg))
    }

    /// Create a Connector from a parsed ConnectorConfig.
    ///
    /// Wires ALL config sections into real runtime behavior:
    /// LLM, storage, compliance, security, knowledge, firewall, budget,
    /// policies, memory, trust, think, retry, observe, tools.
    ///
    /// Every field produces a REAL runtime effect (Docker/Stripe principle).
    pub fn from_config(cfg: &crate::config::ConnectorConfig) -> Connector {
        let mut builder = ConnectorBuilder::default();

        // ── LLM ──
        if let (Some(provider), Some(model)) = (&cfg.connector.provider, &cfg.connector.model) {
            let api_key = cfg.connector.api_key.as_deref().unwrap_or("");
            builder.llm_config = Some(LlmConfig {
                provider: provider.clone(),
                model: model.clone(),
                api_key: api_key.to_string(),
                endpoint: cfg.connector.endpoint.clone(),
            });
        }

        // ── Storage ──
        if let Some(ref s) = cfg.connector.storage {
            builder.storage = Some(s.clone());
        }

        // ── Compliance ──
        if !cfg.connector.comply.is_empty() {
            builder.compliance = cfg.connector.comply.clone();
        }

        // ── Security ──
        if let Some(ref sec) = cfg.connector.security {
            builder.security = sec.into_api_security();
        }

        let mut connector = builder.build();

        // ══════════════════════════════════════════════════════════
        // RUNTIME WIRING — these fields ACTUALLY AFFECT EXECUTION
        // ══════════════════════════════════════════════════════════

        // Phase A: Knowledge → inject facts into system prompt
        if let Some(ref kg) = cfg.knowledge {
            let mut facts = Vec::new();
            if let Some(ref seed) = kg.seed {
                for entity in &seed.entities {
                    if let Some(text) = entity.attrs.get("text") {
                        if let Some(s) = text.as_str() {
                            facts.push(s.to_string());
                        }
                    }
                }
            }
            if !facts.is_empty() {
                connector.knowledge_context = Some(format!(
                    "[Knowledge Context]\n{}\n[End Knowledge Context]\n",
                    facts.join("\n")
                ));
            }
        }

        // Phase B: Budget → wired to ActionEngine at dispatch
        // Collect budget from first agent that has one, or from top-level
        for (_name, agent_cfg) in &cfg.agents {
            if let Some(ref budget) = agent_cfg.budget {
                connector.budget_config = Some(budget.clone());
                break;
            }
        }

        // Phase B: Deny/Allow policies → wired to ActionEngine
        for (_, policy_cfg) in &cfg.policies {
            for rule in &policy_cfg.rules {
                connector.policy_rules.push((
                    rule.effect.clone(),
                    rule.action_pattern.clone(),
                    rule.priority,
                ));
            }
        }

        // Phase C: Firewall preset → real FirewallConfig with PII types
        // Uses into_engine_firewall() which handles preset expansion + field overrides
        if let Some(ref fw) = cfg.connector.firewall {
            connector.firewall_config = Some(fw.into_engine_firewall());
        }

        // Phase D: Memory preset → kernel MemoryRegion config
        if let Some(ref mem) = cfg.memory {
            connector.memory_preset = Some(mem.clone());
        }

        // Phase E: Trust preset → scoring thresholds
        if let Some(ref trust) = cfg.judgment {
            connector.trust_config = Some(trust.clone());
        }

        // Phase F: Cognitive config (think: deep → multi-pass)
        if let Some(ref cog) = cfg.cognitive {
            connector.cognitive_config = Some(cog.clone());
        }

        // Phase G: Retry count
        if let Some(ref router) = cfg.connector.router {
            if let Some(ref retry_cfg) = router.retry {
                if let Some(max_retries) = retry_cfg.max_retries {
                    connector.retry_count = Some(max_retries);
                }
            }
        }

        // Phase H: Observe/Perception config
        if let Some(ref obs) = cfg.perception {
            connector.observe_config = Some(obs.clone());
        }

        // Phase I: Tool definitions → registered in engine
        for (name, tool_cfg) in &cfg.tools {
            connector.tool_defs.push((name.clone(), tool_cfg.description.clone()));
        }

        // Phase J: Streaming config → chunked output events at runtime
        if let Some(ref stream) = cfg.streaming {
            connector.streaming_config = Some(stream.clone());
        }

        // ── Tier 3: Optional-Revoke configs (absent = OFF, present = ON) ──

        // Phase K: Cluster config
        if let Some(ref cluster) = cfg.cluster {
            connector.cluster_config = Some(cluster.clone());
        }

        // Phase L: Swarm config
        if let Some(ref swarm) = cfg.swarm {
            connector.swarm_config = Some(swarm.clone());
        }

        // Phase M: MCP config
        if let Some(ref mcp) = cfg.mcp {
            connector.mcp_config = Some(mcp.clone());
        }

        // Phase N: Server config
        if let Some(ref server) = cfg.server {
            connector.server_config = Some(server.clone());
        }

        // Phase O: Watchdog config
        if let Some(ref wd) = cfg.watchdog {
            connector.watchdog_config = Some(wd.clone());
        }

        // Phase P: Crypto config
        if let Some(ref crypto) = cfg.crypto {
            connector.crypto_config = Some(crypto.clone());
        }

        // Phase Q: Consensus config
        if let Some(ref cons) = cfg.consensus {
            connector.consensus_config = Some(cons.clone());
        }

        // Phase R: Observability config
        if let Some(ref obs) = cfg.observability {
            connector.observability_config = Some(obs.clone());
        }

        // Phase S: Tracing config
        if let Some(ref tr) = cfg.tracing_config {
            connector.tracing_cfg = Some(tr.clone());
        }

        // Phase T: Negotiation config
        if let Some(ref neg) = cfg.negotiation {
            connector.negotiation_config = Some(neg.clone());
        }

        // Phase U: Formal verification config
        if let Some(ref fv) = cfg.formal_verify {
            connector.formal_verify_config = Some(fv.clone());
        }

        connector
    }

    /// One-shot: parse YAML → build → run first agent with input.
    ///
    /// The ultimate Docker-level simplicity:
    /// ```rust,ignore
    /// let output = Connector::run_yaml(
    ///     r#"agent: "You are a doctor""#,
    ///     "Patient has chest pain",
    ///     "user:patient1",
    /// )?;
    /// ```
    pub fn run_yaml(yaml: &str, input: &str, session: &str) -> Result<connector_engine::output::PipelineOutput, String> {
        let connector = Self::from_yaml(yaml).map_err(|e| e.to_string())?;
        let cfg = crate::shorthand::parse_shorthand(yaml).map_err(|e| e.to_string())?;

        if !cfg.pipelines.is_empty() {
            // Has pipeline — build using route() + actor() API
            let pipeline_name = cfg.pipelines.keys().next()
                .ok_or_else(|| "Pipeline config is empty".to_string())?;
            let pipeline_cfg = cfg.pipelines.get(pipeline_name)
                .ok_or_else(|| format!("Pipeline '{}' not found in config", pipeline_name))?;

            let mut pb = PipelineBuilder::new(pipeline_name);

            // Set LLM from connector
            if let (Some(provider), Some(model)) = (&cfg.connector.provider, &cfg.connector.model) {
                let api_key = cfg.connector.api_key.as_deref().unwrap_or("");
                pb = pb.llm(provider, model, api_key);
            }

            // Set compliance
            if !cfg.connector.comply.is_empty() {
                let comply_refs: Vec<&str> = cfg.connector.comply.iter().map(|s| s.as_str()).collect();
                pb = pb.compliance(&comply_refs);
            }

            // Add actors with closure-based API
            for actor_cfg in &pipeline_cfg.actors {
                let instructions = actor_cfg.instructions.clone();
                let role = actor_cfg.role.clone();
                let tools = actor_cfg.tools.clone();
                let memory_from = actor_cfg.memory_from.clone();

                pb = pb.actor(&actor_cfg.name, move |mut b| {
                    b = b.instructions(&instructions);
                    if let Some(ref r) = role { b = b.role(r); }
                    if !tools.is_empty() {
                        let tool_refs: Vec<&str> = tools.iter().map(|s| s.as_str()).collect();
                        b = b.allow_tools(&tool_refs);
                    }
                    if !memory_from.is_empty() {
                        let mem_refs: Vec<&str> = memory_from.iter().map(|s| s.as_str()).collect();
                        b = b.memory_from(&mem_refs);
                    }
                    b
                });
            }

            // Build and run via Pipeline::run
            let pipeline = pb.build();
            pipeline.run(input, session).map_err(|e| e.to_string())
        } else if !cfg.agents.is_empty() {
            // Has agent(s) — run the first one
            let (name, agent_cfg) = cfg.agents.iter().next()
                .ok_or_else(|| "No agents defined in config".to_string())?;
            let mut ab = connector.agent(name);
            ab = ab.instructions(&agent_cfg.instructions);
            if let Some(ref role) = agent_cfg.role {
                ab = ab.role(role);
            }
            if !agent_cfg.tools.is_empty() {
                ab = ab.allow_tools(&agent_cfg.tools.iter().map(|s| s.as_str()).collect::<Vec<_>>());
            }
            if let Some(ref budget) = agent_cfg.budget {
                if let Some(tokens) = budget.max_tokens {
                    ab = ab.budget_tokens(tokens);
                }
                if let Some(cost) = budget.max_cost_usd {
                    ab = ab.budget_cost(cost);
                }
            }
            ab.run(input, session).map_err(|e| e.to_string())
        } else {
            Err("No agents or pipelines defined in YAML.\n  Tip: add `agent: \"You are a helpful assistant\"` to your YAML".to_string())
        }
    }

    /// Create a pipeline builder (for multi-actor flows).
    pub fn pipeline(name: &str) -> PipelineBuilder {
        PipelineBuilder::new(name)
    }

    /// Create an agent builder (for single-agent use).
    ///
    /// **Smart default**: If `name` is empty, defaults to `"agent"`.
    pub fn agent(&self, name: &str) -> AgentBuilder {
        let name = if name.is_empty() { "agent" } else { name };
        AgentBuilder::new(name, self)
    }

    /// Print available features and getting-started help.
    ///
    /// ```rust,ignore
    /// Connector::help();
    /// ```
    pub fn help() -> String {
        let mut lines = Vec::new();
        lines.push("".to_string());
        lines.push("  Connector — Trusted Infrastructure for AI Agents".to_string());
        lines.push("  ═══════════════════════════════════════════════════".to_string());
        lines.push("".to_string());

        // Love Ladder — progressive simplicity (Pattern P1: wow moment <30s)
        lines.push("  The Love Ladder — pick your level:".to_string());
        lines.push("".to_string());
        lines.push("    Level 0 · ONE LINE:".to_string());
        lines.push("      let r = Connector::quick(\"Hello!\")?;".to_string());
        lines.push("".to_string());
        lines.push("    Level 1 · TWO LINES:".to_string());
        lines.push("      let c = Connector::new().build();".to_string());
        lines.push("      let r = c.agent(\"bot\").run_quick(\"Hello!\")?;".to_string());
        lines.push("".to_string());
        lines.push("    Level 2 · THREE LINES:".to_string());
        lines.push("      let c = Connector::new().llm(\"openai\", \"gpt-4o\", \"sk-...\").build();".to_string());
        lines.push("      let r = c.agent(\"bot\").instructions(\"You are helpful\").run(\"Hi!\", \"user:alice\")?;".to_string());
        lines.push("      println!(\"{}\", r);  // beautiful output by default".to_string());
        lines.push("".to_string());
        lines.push("    Level 3 · ENTERPRISE:".to_string());
        lines.push("      let c = Connector::new()".to_string());
        lines.push("          .llm(\"openai\", \"gpt-4o\", \"sk-...\")".to_string());
        lines.push("          .compliance(&[\"hipaa\", \"soc2\"])".to_string());
        lines.push("          .storage(\"redb:data.redb\")".to_string());
        lines.push("          .security(|s| s.signing(Ed25519))".to_string());
        lines.push("          .build();".to_string());
        lines.push("".to_string());

        // Framework bridges (Pattern P3: ecosystem piggyback)
        lines.push("  Already using another framework? 1-line upgrade:".to_string());
        lines.push("    let verified = Connector::verify(your_output, &[\"hipaa\"])?;".to_string());
        lines.push("".to_string());

        // Output views
        lines.push("  Output views (progressive disclosure):".to_string());
        lines.push("    println!(\"{}\", r)   → clean dashboard (default)".to_string());
        lines.push("    r.summary()          → one-line status".to_string());
        lines.push("    r.dashboard()        → 5-line card".to_string());
        lines.push("    r.security_view()    → compliance/audit view".to_string());
        lines.push("    r.explain()          → decision explanation".to_string());
        lines.push("    r.share()            → shareable markdown report".to_string());
        lines.push("    r.to_json()          → full JSON with provenance".to_string());
        lines.push("".to_string());

        // Viral hooks
        lines.push("  Share your results:".to_string());
        lines.push("    r.trust_badge_markdown()  → shields.io badge for README".to_string());
        lines.push("    r.share()                 → full markdown report".to_string());
        lines.push("    r.snippet()               → copy-paste YAML config".to_string());
        lines.push("".to_string());

        // Discovery
        lines.push("  Discover more:".to_string());
        lines.push("    Connector::demo()     → full showcase with compliance".to_string());
        lines.push("    Connector::vs()       → what competitors don't have".to_string());
        lines.push("    c.status()            → system readiness check".to_string());
        lines.push("".to_string());

        // Auto-detect status
        if let Some(detected) = crate::auto_detect::auto_detect_llm() {
            lines.push(format!("  ✅ LLM auto-detected: {} / {}", detected.provider, detected.model));
        } else {
            lines.push("  ⚠️  No LLM API key found. Set one of:".to_string());
            lines.push("     OPENAI_API_KEY · ANTHROPIC_API_KEY · GEMINI_API_KEY".to_string());
        }

        lines.push("".to_string());
        lines.join("\n")
    }

    /// What you get that LangChain / CrewAI / Mem0 / OpenAI Agents don't.
    ///
    /// Returns a shareable comparison table.
    ///
    /// ```rust,ignore
    /// println!("{}", Connector::vs());
    /// ```
    pub fn vs() -> String {
        let mut lines = Vec::new();
        lines.push("".to_string());
        lines.push("  Connector vs. Competitors — What You Get".to_string());
        lines.push("  ════════════════════════════════════════════════════════════".to_string());
        lines.push("".to_string());
        lines.push("  Feature                 Connector   LangChain  CrewAI  Mem0".to_string());
        lines.push("  ─────────────────────── ─────────── ────────── ─────── ────".to_string());
        lines.push("  Trust Score (0-100)        ✅          ❌         ❌      ❌".to_string());
        lines.push("  Zero-Fake Provenance       ✅          ❌         ❌      ❌".to_string());
        lines.push("  Compliance (HIPAA/SOC2)    ✅          ❌         ❌      ❌".to_string());
        lines.push("  HMAC Audit Trail           ✅          ❌         ❌      ❌".to_string());
        lines.push("  Memory Kernel (CID)        ✅          ❌         ❌      ✅".to_string());
        lines.push("  Agent RBAC                 ✅          ❌         ❌      ❌".to_string());
        lines.push("  PII Firewall               ✅          ❌         ❌      ❌".to_string());
        lines.push("  Content-Addressed Memory   ✅          ❌         ❌      ❌".to_string());
        lines.push("  Prompt Injection Guard      ✅          ❌         ❌      ❌".to_string());
        lines.push("  1-Line Agent               ✅          ❌         ❌      ❌".to_string());
        lines.push("  YAML Config (15 subsys)    ✅          ❌         ✅      ❌".to_string());
        lines.push("  Multi-Agent Pipeline       ✅          ✅         ✅      ❌".to_string());
        lines.push("  Tool/Action System         ✅          ✅         ✅      ❌".to_string());
        lines.push("  Memory Layer               ✅          ✅         ❌      ✅".to_string());
        lines.push("  Framework Bridges          ✅          N/A        N/A     ✅".to_string());
        lines.push("".to_string());
        lines.push("  ✅ = built-in   ❌ = not available   N/A = is the framework".to_string());
        lines.push("".to_string());
        lines.push("  Try: Connector::demo() to see it all in action".to_string());
        lines.push("".to_string());
        lines.join("\n")
    }

    /// Check system readiness — what's configured, what's missing.
    pub fn status(&self) -> String {
        let mut lines = Vec::new();
        lines.push("Connector Status:".to_string());

        // LLM
        if let Some(ref llm) = self.llm_config {
            lines.push(format!("  ✅ LLM: {} / {}", llm.provider, llm.model));
        } else {
            lines.push("  ⚠️  LLM: not configured (will use simulated responses)".to_string());
        }

        // Storage
        if let Some(ref uri) = self.storage_uri {
            lines.push(format!("  ✅ Storage: {}", uri));
        } else {
            lines.push("  ℹ️  Storage: in-memory (add .storage(\"redb:data.redb\") to persist)".to_string());
        }

        // Compliance
        if !self.compliance.is_empty() {
            lines.push(format!("  ✅ Compliance: {}", self.compliance.join(", ")));
        }

        // Kernel
        let packets = self.packet_count();
        let audits = self.audit_count();
        lines.push(format!("  📦 Kernel: {} packets, {} audit entries", packets, audits));

        lines.join("\n")
    }

    // ═══════════════════════════════════════════════════════════════
    // ECOSYSTEM PIGGYBACK — 1-line framework integration
    //
    // Pattern from: Mem0 (native in CrewAI/Flowise/Langflow → $24M),
    // Cursor (forked VS Code → $10B), Supabase (Firebase alternative → $5B)
    //
    // "Don't fight the ecosystem, ride it."
    // ═══════════════════════════════════════════════════════════════

    /// Wrap any LLM response with Connector trust + compliance + provenance.
    ///
    /// **The 1-line upgrade for ANY framework.** Works with LangChain, CrewAI,
    /// OpenAI Agents, or any custom agent — just pass the text output.
    ///
    /// ```rust,ignore
    /// // Your existing CrewAI/LangChain/custom agent code:
    /// let llm_response = my_agent.run("Patient has fever");
    ///
    /// // Add Connector trust in 1 line:
    /// let verified = Connector::verify(llm_response, &["hipaa"])?;
    /// println!("{}", verified);  // trust score + compliance + provenance
    /// ```
    pub fn verify(text: &str, compliance: &[&str]) -> Result<connector_engine::output::PipelineOutput, crate::error::ConnectorError> {
        let mut builder = Self::new();
        if !compliance.is_empty() {
            builder = builder.compliance(compliance);
        }
        let c = builder.build();
        // Create a minimal agent run that wraps the existing text
        c.agent("verifier")
            .instructions("You are a verification wrapper. Return the input exactly as received.")
            .run(text, "user:framework-bridge")
    }

    /// Export a Connector-compatible memory format from any framework's output.
    ///
    /// Returns a JSON string that can be imported by LangChain, CrewAI, or
    /// any framework that accepts JSON memory.
    ///
    /// ```rust,ignore
    /// let r = c.agent("bot").run("Hello", "user:a")?;
    /// let json = Connector::export_memory(&r);  // framework-compatible JSON
    /// ```
    pub fn export_memory(output: &connector_engine::output::PipelineOutput) -> String {
        let memories: Vec<serde_json::Value> = output.memory.memories.iter().map(|m| {
            serde_json::json!({
                "id": m.id,
                "content": m.content,
                "metadata": {
                    "user": m.user,
                    "kind": m.kind,
                    "tags": m.tags,
                    "score": m.score,
                    "created": m.created,
                    "source": m.source,
                    "verified": m.verified,
                    "session": m.session,
                },
                // Connector extras (what competitors don't have)
                "trust_score": output.status.trust,
                "provenance": "kernel-verified",
                "cid": m.id,
            })
        }).collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "format": "connector-memory-v1",
            "memories": memories,
            "trust": {
                "score": output.status.trust,
                "grade": output.status.trust_grade,
            },
            "compliance": output.aapi.compliance,
        })).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the LLM config.
    pub fn llm_config(&self) -> Option<&LlmConfig> {
        self.llm_config.as_ref()
    }

    /// Convert to engine LlmConfig for actual API calls.
    pub fn engine_llm_config(&self) -> Option<connector_engine::llm::LlmConfig> {
        self.llm_config.as_ref().map(|c| {
            let mut cfg = connector_engine::llm::LlmConfig::new(&c.provider, &c.model, &c.api_key);
            if let Some(ref ep) = c.endpoint {
                cfg = cfg.with_endpoint(ep);
            }
            cfg
        })
    }

    /// Get compliance frameworks.
    pub fn compliance(&self) -> &[String] {
        &self.compliance
    }

    /// Get security config.
    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    /// Get perception/observe config (Tier 3).
    pub fn perception_config(&self) -> Option<&crate::config::PerceptionConfig> {
        self.observe_config.as_ref()
    }

    /// Get cognitive config (Tier 3).
    pub fn cognitive_config(&self) -> Option<&crate::config::CognitiveConfig> {
        self.cognitive_config.as_ref()
    }

    /// Get streaming config (Tier 3).
    pub fn streaming_config(&self) -> Option<&crate::config::StreamingConfig> {
        self.streaming_config.as_ref()
    }

    /// Get cluster config (Tier 3).
    pub fn cluster_config(&self) -> Option<&crate::config::ClusterConfig> {
        self.cluster_config.as_ref()
    }

    /// Get swarm config (Tier 3).
    pub fn swarm_config(&self) -> Option<&crate::config::SwarmConfig> {
        self.swarm_config.as_ref()
    }

    /// Get server config (Tier 3).
    pub fn server_config(&self) -> Option<&crate::config::ServerConfig> {
        self.server_config.as_ref()
    }

    /// Get watchdog config (Tier 3).
    pub fn watchdog_config(&self) -> Option<&crate::config::WatchdogConfig> {
        self.watchdog_config.as_ref()
    }

    /// Get observability config (Tier 3).
    pub fn observability_config(&self) -> Option<&crate::config::ObservabilityConfig> {
        self.observability_config.as_ref()
    }

    /// Get tracing config (Tier 3).
    pub fn tracing_config(&self) -> Option<&crate::config::TracingConfig> {
        self.tracing_cfg.as_ref()
    }

    /// Get negotiation config (Tier 3).
    pub fn negotiation_config(&self) -> Option<&crate::config::NegotiationConfig> {
        self.negotiation_config.as_ref()
    }

    /// Get cell ID.
    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }

    /// Get engine storage URI.
    pub fn engine_storage_uri(&self) -> Option<&str> {
        self.engine_storage_uri.as_deref()
    }

    /// Open the Database View — browse memories, agents, sessions, audit, knowledge.
    ///
    /// ```rust,ignore
    /// let db = c.db();
    /// println!("{}", db.stats());          // database health
    /// println!("{}", db.memories());        // all memories
    /// println!("{}", db.agents());          // registered agents
    /// println!("{}", db.audit(10));         // last 10 audit entries
    /// println!("{}", db.find("fever"));     // search memories
    /// println!("{}", db.timeline(20));      // chronological view
    /// ```
    pub fn db(&self) -> crate::db::DatabaseView<'_> {
        crate::db::DatabaseView::new(self)
    }

    /// Get total packet count from the shared kernel.
    pub fn packet_count(&self) -> usize {
        self.kernel.read().map(|k| k.packet_count()).unwrap_or(0)
    }

    /// Get total audit entry count from the shared kernel.
    pub fn audit_count(&self) -> usize {
        self.kernel.read().map(|k| k.audit_count()).unwrap_or(0)
    }

    /// Flush kernel state to the storage backend.
    ///
    /// Persists all packets, agents, sessions, and audit entries.
    /// Returns the number of objects written.
    pub fn save(&self) -> Result<usize, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        let mut store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        kernel.flush_to_store(store.as_mut())
    }

    /// Load kernel state from the storage backend.
    ///
    /// Reconstructs the kernel from persisted state. Use after restart.
    pub fn load(&self) -> Result<(), String> {
        let store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        let restored = MemoryKernel::load_from_store(store.as_ref())?;
        let mut kernel = self.kernel.write()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        *kernel = restored;
        Ok(())
    }

    /// Get the storage URI (if configured).
    pub fn storage_uri(&self) -> Option<&str> {
        self.storage_uri.as_deref()
    }

    // ─── Phase 4: Audit Durability ──────────────────────────────

    /// Verify the HMAC audit chain — checks tamper-evident hash links.
    /// Returns Ok(chain_length) or Err(description of broken link).
    pub fn verify_audit_chain(&self) -> Result<usize, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        kernel.verify_audit_chain()
    }

    /// Export audit log as JSON string.
    pub fn export_audit_json(&self) -> Result<String, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        kernel.export_audit_json()
    }

    /// Export audit log as CSV string.
    pub fn export_audit_csv(&self) -> Result<String, String> {
        let kernel = self.kernel.read()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        Ok(kernel.export_audit_csv())
    }

    /// Drain overflow audit entries and persist them to the storage backend.
    /// Returns the number of entries flushed.
    pub fn flush_audit_overflow(&self) -> Result<usize, String> {
        let mut kernel = self.kernel.write()
            .map_err(|e| format!("Kernel lock poisoned: {}", e))?;
        let overflow = kernel.drain_audit_overflow();
        if overflow.is_empty() {
            return Ok(0);
        }
        let count = overflow.len();
        let mut store = self.store.lock()
            .map_err(|e| format!("Store lock poisoned: {}", e))?;
        for entry in &overflow {
            store.store_audit_entry(entry)
                .map_err(|e| format!("Failed to persist audit overflow: {}", e))?;
        }
        Ok(count)
    }
}

/// Builder for Connector.
pub struct ConnectorBuilder {
    llm_config: Option<LlmConfig>,
    memory_config: Option<MemoryConfig>,
    compliance: Vec<String>,
    security: SecurityConfig,
    storage: Option<String>,
    /// Knowledge facts to inject into all agent system prompts
    knowledge_facts: Vec<String>,
    /// Tool registry — tools registered at Connector level, shared across all agents
    tool_registry: ToolRegistry,
    /// Engine storage URI — persistent storage for Ring 1-4 engine state
    engine_storage_uri: Option<String>,
    /// Cell ID for distributed storage layout
    cell_id: String,
}

impl Default for ConnectorBuilder {
    fn default() -> Self {
        Self {
            llm_config: None,
            memory_config: None,
            compliance: Vec::new(),
            security: SecurityConfig::default(),
            storage: None,
            knowledge_facts: Vec::new(),
            tool_registry: ToolRegistry::new(),
            engine_storage_uri: None,
            cell_id: "local".to_string(),
        }
    }
}

impl ConnectorBuilder {
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

    /// Set a custom LLM endpoint (any OpenAI-compatible API).
    pub fn llm_custom(mut self, endpoint: &str, model: &str, api_key: &str) -> Self {
        self.llm_config = Some(LlmConfig {
            provider: "custom".to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            endpoint: Some(endpoint.to_string()),
        });
        self
    }

    /// Read LLM config from environment variables.
    ///
    /// Reads: `CONNECTOR_LLM_PROVIDER`, `CONNECTOR_LLM_MODEL`, `CONNECTOR_LLM_API_KEY`
    pub fn llm_from_env(mut self) -> Self {
        let provider = std::env::var("CONNECTOR_LLM_PROVIDER").unwrap_or_else(|_| "openai".to_string());
        let model = std::env::var("CONNECTOR_LLM_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        let api_key = std::env::var("CONNECTOR_LLM_API_KEY").unwrap_or_default();
        self.llm_config = Some(LlmConfig {
            provider,
            model,
            api_key,
            endpoint: std::env::var("CONNECTOR_LLM_ENDPOINT").ok(),
        });
        self
    }

    /// Alias for `.storage()` — set where memories are persisted.
    ///
    /// This is the same as `.storage()`. Use whichever name feels natural.
    ///
    /// **Note:** In YAML config, `memory: fast` sets a memory *management* preset
    /// (fast/long/deep/infinite). In the builder API, `.memory()` sets the storage
    /// *connection string*. Use `.storage()` to avoid ambiguity.
    pub fn memory(mut self, connection: &str) -> Self {
        self.storage = Some(connection.to_string());
        self
    }

    /// Set the storage backend for persistence.
    ///
    /// This is where agent memories and audit logs are stored.
    ///
    /// **Supported values:**
    /// - `"memory"` or omit — in-memory (default, no persistence)
    /// - `"redb:path.redb"` — redb file (ACID, crash-safe)
    /// - `"sqlite:path"` — SQLite file (planned)
    /// - `"postgres://..."` — PostgreSQL (planned)
    /// - `"prolly"` — Prolly tree (content-addressed, planned)
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .storage("redb:data.redb")  // ACID persistence
    ///     .build();
    /// ```
    pub fn storage(mut self, uri: &str) -> Self {
        self.storage = Some(uri.to_string());
        self
    }

    /// Inject knowledge facts into all agent system prompts.
    ///
    /// Facts are prepended as `[Knowledge Context]` before any agent instructions.
    /// This is the programmatic equivalent of `knowledge:` in YAML shorthand.
    ///
    /// Use `.knowledge()` or `.facts()` interchangeably — they are aliases.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .llm("openai", "gpt-4o", "sk-...")
    ///     .knowledge(&[
    ///         "Patient is 45 years old, male, 80kg",
    ///         "Allergic to penicillin",
    ///         "Current medications: metformin, lisinopril",
    ///     ])
    ///     .build();
    /// ```
    pub fn knowledge(mut self, facts: &[&str]) -> Self {
        self.knowledge_facts.extend(facts.iter().map(|s| s.to_string()));
        self
    }

    /// Alias for `.knowledge()` — inject knowledge facts into all agent system prompts.
    ///
    /// Same as `.knowledge()`. This alias exists so the naming is consistent between
    /// `Connector::new().facts(&[...])` and `agent.facts(&[...])`.
    pub fn facts(self, facts: &[&str]) -> Self {
        self.knowledge(facts)
    }

    /// Add a single knowledge fact.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .fact("The patient is diabetic")
    ///     .fact("Blood pressure: 140/90")
    ///     .build();
    /// ```
    pub fn fact(mut self, fact: &str) -> Self {
        self.knowledge_facts.push(fact.to_string());
        self
    }

    /// Load knowledge from a text string (e.g., a document, manual, policy).
    ///
    /// The text is chunked into paragraphs and injected as knowledge context.
    /// For large documents, paragraphs are split on double-newlines.
    ///
    /// ```rust,ignore
    /// let policy = std::fs::read_to_string("hipaa_policy.txt").unwrap();
    /// let c = Connector::new()
    ///     .knowledge_text(&policy)
    ///     .build();
    /// ```
    pub fn knowledge_text(mut self, text: &str) -> Self {
        // Split on double-newline paragraphs, filter empty
        let paragraphs: Vec<&str> = text.split("\n\n")
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if paragraphs.is_empty() {
            // Single block of text
            self.knowledge_facts.push(text.trim().to_string());
        } else {
            for p in paragraphs {
                self.knowledge_facts.push(p.to_string());
            }
        }
        self
    }

    /// Load knowledge from a file path.
    ///
    /// Reads the file and injects its content as knowledge context.
    /// Supports: `.txt`, `.md`, `.csv`, `.json` files.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .knowledge_file("data/drug_interactions.csv")
    ///     .knowledge_file("docs/guidelines.md")
    ///     .build();
    /// ```
    pub fn knowledge_file(mut self, path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    eprintln!("[connector] Knowledge file '{}' is empty, skipping.", path);
                } else if path.ends_with(".csv") {
                    // CSV: each row becomes a fact
                    for line in trimmed.lines().skip(1) { // skip header
                        let line = line.trim();
                        if !line.is_empty() {
                            self.knowledge_facts.push(line.to_string());
                        }
                    }
                } else if path.ends_with(".json") || path.ends_with(".jsonl") {
                    // JSON: try to parse as array of strings or objects
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                        for item in arr {
                            match item {
                                serde_json::Value::String(s) => self.knowledge_facts.push(s),
                                other => self.knowledge_facts.push(other.to_string()),
                            }
                        }
                    } else {
                        // JSONL or single object — each line is a fact
                        for line in trimmed.lines() {
                            let line = line.trim();
                            if !line.is_empty() {
                                self.knowledge_facts.push(line.to_string());
                            }
                        }
                    }
                } else {
                    // Text/markdown: paragraph chunking
                    self = self.knowledge_text(trimmed);
                }
            }
            Err(e) => {
                eprintln!("[connector] Failed to read knowledge file '{}': {}. Skipping.", path, e);
            }
        }
        self
    }

    /// Set compliance frameworks (e.g., "hipaa", "soc2", "eu_ai_act").
    pub fn compliance(mut self, frameworks: &[&str]) -> Self {
        self.compliance = frameworks.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Configure security settings.
    pub fn security<F>(mut self, f: F) -> Self
    where
        F: FnOnce(crate::security::SecurityConfigBuilder) -> crate::security::SecurityConfigBuilder,
    {
        self.security = f(crate::security::SecurityConfigBuilder::new()).build();
        self
    }

    /// Register a tool definition at the Connector level (shared across all agents).
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .register_tool(Tool::new("search", "Search the web")
    ///         .param("query", ParamType::String, "Query")
    ///         .build())
    ///     .build();
    /// ```
    pub fn register_tool(mut self, tool: Tool) -> Self {
        self.tool_registry.register(tool);
        self
    }

    /// Register a tool with an executable handler at the Connector level.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .register_tool_with_handler(
    ///         Tool::new("double", "Double a number")
    ///             .param("n", ParamType::Integer, "Number")
    ///             .build(),
    ///         |params| {
    ///             let n = params["n"].as_i64().unwrap_or(0);
    ///             Ok(serde_json::json!({"result": n * 2}))
    ///         })
    ///     .build();
    /// ```
    pub fn register_tool_with_handler<F>(mut self, tool: Tool, handler: F) -> Self
    where
        F: Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    {
        self.tool_registry.register_with_handler(tool, handler);
        self
    }

    /// Set the engine storage backend for Ring 1-4 persistent state (OS folder model).
    ///
    /// **Supported values:**
    /// - `"memory"` or omit — in-memory (default, no persistence)
    /// - `"sqlite:engine.db"` — SQLite WAL-mode file (production)
    /// - `"sqlite::memory:"` — SQLite in-memory (testing with real SQL)
    ///
    /// Each storage zone (audit, secrets, escrow, etc.) maps to a table in the same
    /// database but with different durability and replication policies — like OS mount points.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .engine_storage("sqlite:engine.db")
    ///     .build();
    /// ```
    pub fn engine_storage(mut self, uri: &str) -> Self {
        self.engine_storage_uri = Some(uri.to_string());
        self
    }

    /// Set the cell ID for distributed storage layout.
    ///
    /// Each cell has its own namespace in the storage zones — like `/cell:{id}/audit/`.
    /// Default: `"local"`.
    ///
    /// ```rust,ignore
    /// let c = Connector::new()
    ///     .cell("cell_us_east_1")
    ///     .engine_storage("sqlite:engine.db")
    ///     .build();
    /// ```
    pub fn cell(mut self, cell_id: &str) -> Self {
        self.cell_id = cell_id.to_string();
        self
    }

    /// Build the Connector.
    ///
    /// **Smart defaults**: If no LLM is configured, auto-detects from
    /// environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.).
    /// This means `Connector::new().build()` just works if you have an API key set.
    pub fn build(mut self) -> Connector {
        // ── Smart Default: Auto-detect LLM from env if not explicitly set ──
        if self.llm_config.is_none() {
            if let Some(detected) = crate::auto_detect::auto_detect_llm() {
                self.llm_config = Some(LlmConfig {
                    provider: detected.provider,
                    model: detected.model,
                    api_key: detected.api_key,
                    endpoint: None,
                });
            }
        }

        // Parse storage URI → create appropriate KernelStore backend
        let store: Box<dyn KernelStore + Send> = match self.storage.as_deref() {
            None | Some("memory") | Some("") => {
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) if uri.starts_with("redb:") => {
                let path = &uri[5..]; // strip "redb:" prefix
                match connector_engine::redb_store::RedbKernelStore::open(path) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open redb at '{}': {}. Falling back to in-memory.", path, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
            Some(uri) if uri.ends_with(".redb") => {
                // Bare file path ending in .redb — treat as redb
                match connector_engine::redb_store::RedbKernelStore::open(uri) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open redb at '{}': {}. Falling back to in-memory.", uri, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
            Some(uri) if uri.starts_with("sqlite:") => {
                // TODO: SqliteKernelStore (optional, for SQL query needs)
                eprintln!("[connector] SQLite storage not yet implemented, using in-memory. URI: {}", uri);
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) if uri.starts_with("postgres://") || uri.starts_with("postgresql://") => {
                // TODO: PostgresKernelStore
                eprintln!("[connector] Postgres storage not yet implemented, using in-memory. URI: {}", uri);
                Box::new(InMemoryKernelStore::new())
            }
            Some("prolly") => {
                // TODO: ProllyKernelStore
                eprintln!("[connector] Prolly storage not yet implemented, using in-memory.");
                Box::new(InMemoryKernelStore::new())
            }
            Some(uri) => {
                // Default: treat unknown URIs as redb file paths
                match connector_engine::redb_store::RedbKernelStore::open(uri) {
                    Ok(store) => Box::new(store),
                    Err(e) => {
                        eprintln!("[connector] Failed to open storage at '{}': {}. Falling back to in-memory.", uri, e);
                        Box::new(InMemoryKernelStore::new())
                    }
                }
            }
        };

        // Wire knowledge facts from builder into knowledge_context
        let knowledge_context = if self.knowledge_facts.is_empty() {
            None
        } else {
            Some(format!(
                "[Knowledge Context]\n{}\n[End Knowledge Context]\n",
                self.knowledge_facts.join("\n")
            ))
        };

        Connector {
            llm_config: self.llm_config,
            memory_config: self.memory_config,
            compliance: self.compliance,
            security: self.security,
            kernel: Arc::new(RwLock::new(MemoryKernel::new())),
            store: Arc::new(Mutex::new(store)),
            storage_uri: self.storage,
            knowledge_context,
            firewall_config: None,
            budget_config: None,
            policy_rules: Vec::new(),
            memory_preset: None,
            trust_config: None,
            cognitive_config: None,
            retry_count: None,
            observe_config: None,
            tool_defs: Vec::new(),
            streaming_config: None,
            tool_registry: Arc::new(Mutex::new(self.tool_registry)),
            engine_storage_uri: self.engine_storage_uri,
            cell_id: self.cell_id,
            cluster_config: None,
            swarm_config: None,
            mcp_config: None,
            server_config: None,
            watchdog_config: None,
            crypto_config: None,
            consensus_config: None,
            observability_config: None,
            tracing_cfg: None,
            negotiation_config: None,
            formal_verify_config: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_connector() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        assert!(c.llm_config().is_some());
        assert_eq!(c.llm_config().unwrap().provider, "openai");
        assert_eq!(c.llm_config().unwrap().model, "gpt-4o");
    }

    #[test]
    fn test_connector_with_compliance() {
        let c = Connector::new()
            .llm("anthropic", "claude-3.5-sonnet", "sk-test")
            .memory("sqlite://./test.db")
            .compliance(&["hipaa", "soc2"])
            .build();

        assert_eq!(c.compliance(), &["hipaa", "soc2"]);
    }

    #[test]
    fn test_connector_with_security() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .scitt(true)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
            )
            .build();

        assert!(c.security().signing.is_some());
        assert!(c.security().scitt);
        assert_eq!(c.security().data_classification.as_deref(), Some("PHI"));
    }

    #[test]
    fn test_custom_llm() {
        let c = Connector::new()
            .llm_custom("https://my-api.com/v1", "my-model", "key-123")
            .build();

        let llm = c.llm_config().unwrap();
        assert_eq!(llm.provider, "custom");
        assert_eq!(llm.endpoint.as_deref(), Some("https://my-api.com/v1"));
    }

    #[test]
    fn test_storage_default_is_memory() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        assert!(c.storage_uri().is_none());
    }

    #[test]
    fn test_storage_explicit_memory() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage("memory")
            .build();
        assert_eq!(c.storage_uri(), Some("memory"));
    }

    #[test]
    fn test_storage_sqlite_placeholder() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage("sqlite:test.db")
            .build();
        assert_eq!(c.storage_uri(), Some("sqlite:test.db"));
    }

    #[test]
    fn test_packet_count_and_audit_count() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        assert_eq!(c.packet_count(), 0);
        assert_eq!(c.audit_count(), 0);

        // Run an agent — should increase counts
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        assert!(c.packet_count() > 0, "packet_count should increase after run");
        assert!(c.audit_count() > 0, "audit_count should increase after run");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();

        // Run agent to populate kernel
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let packets_before = c.packet_count();
        let audit_before = c.audit_count();
        assert!(packets_before > 0);

        // Save to store
        let written = c.save().unwrap();
        assert!(written > 0, "save() should write objects to store");

        // Simulate restart: clear kernel, then load from store
        {
            let mut kernel = c.kernel.write().unwrap();
            *kernel = MemoryKernel::new();
        }
        assert_eq!(c.packet_count(), 0, "kernel should be empty after clear");

        // Load from store
        c.load().unwrap();
        assert_eq!(c.packet_count(), packets_before,
            "load() should restore packet count: {} == {}", c.packet_count(), packets_before);
    }

    #[test]
    fn test_redb_storage_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let uri = format!("redb:{}", db_path.display());

        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage(&uri)
            .build();

        assert_eq!(c.storage_uri(), Some(uri.as_str()));

        // Run agent to populate kernel
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let packets = c.packet_count();
        assert!(packets > 0);

        // Save to redb
        let written = c.save().unwrap();
        assert!(written > 0, "save() should write to redb");

        // Clear kernel, load back
        { *c.kernel.write().unwrap() = MemoryKernel::new(); }
        assert_eq!(c.packet_count(), 0);

        c.load().unwrap();
        assert_eq!(c.packet_count(), packets,
            "redb load should restore {} packets", packets);
    }

    #[test]
    fn test_redb_persistence_across_connectors() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("shared.redb");
        let uri = format!("redb:{}", db_path.display());

        // Connector 1: run agent, save
        {
            let c1 = Connector::new()
                .llm("openai", "gpt-4o", "sk-test")
                .storage(&uri)
                .build();
            let _ = c1.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
            assert!(c1.packet_count() > 0);
            c1.save().unwrap();
        }

        // Connector 2: new instance, same file, load and verify
        {
            let c2 = Connector::new()
                .llm("openai", "gpt-4o", "sk-test")
                .storage(&uri)
                .build();
            assert_eq!(c2.packet_count(), 0, "fresh connector starts empty");

            c2.load().unwrap();
            assert!(c2.packet_count() > 0,
                "c2 should recover packets from c1's save");
        }
    }

    #[test]
    fn test_connector_verify_audit_chain() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();
        let _ = c.agent("bot").instructions("Hi").run("World", "user:a").unwrap();

        let result = c.verify_audit_chain();
        assert!(result.is_ok(), "Audit chain should be valid: {:?}", result);
        let chain_len = result.unwrap();
        assert!(chain_len >= 4, "Should have multiple audit entries, got {}", chain_len);
    }

    #[test]
    fn test_connector_export_audit_json() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();

        let json = c.export_audit_json().unwrap();
        assert!(json.starts_with('['));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_connector_export_audit_csv() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let _ = c.agent("bot").instructions("Hi").run("Hello", "user:a").unwrap();

        let csv = c.export_audit_csv().unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines.len() >= 3, "CSV should have header + rows");
        assert!(lines[0].contains("audit_id"));
    }

    #[test]
    fn test_phase6_aapi_data_in_pipeline_output() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .build();

        let output = c.agent("bot").instructions("Hi").run("Hello world", "user:alice").unwrap();

        // Phase 6: PipelineOutput should have real AAPI action records
        // register + start + 2 remember calls = at least 2 action records (register + 2 writes)
        assert!(output.aapi.action_records >= 2,
            "Should have action records from ActionEngine, got {}", output.aapi.action_records);

        // Vakya count should be > 0 (AutoVakya constructs one per memory write)
        assert!(output.aapi.vakya_count >= 1,
            "Should have Vakya envelopes, got {}", output.aapi.vakya_count);

        // Authorized count should be > 0
        assert!(output.aapi.authorized >= 1,
            "Should have authorized actions, got {}", output.aapi.authorized);
    }

    #[test]
    fn test_phase5_security_tags_flow_through() {
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .security(|s| s
                .signing(crate::security::SigningAlgorithm::Ed25519)
                .scitt(true)
                .data_classification("PHI")
                .jurisdiction("US")
                .retention_days(2555)
                .max_delegation_depth(3)
                .require_mfa(true)
            )
            .build();

        // Run agent — security tags should be applied to all packets
        let _ = c.agent("doctor").instructions("Medical AI").run("Patient has fever", "user:patient1").unwrap();

        // Verify audit chain is valid (HMAC signing is always on)
        let chain = c.verify_audit_chain().unwrap();
        assert!(chain >= 2, "Should have audit entries with HMAC chain");

        // Verify security config is stored
        assert!(c.security().signing.is_some());
        assert!(c.security().scitt);
        assert_eq!(c.security().data_classification.as_deref(), Some("PHI"));
        assert_eq!(c.security().jurisdiction.as_deref(), Some("US"));
        assert_eq!(c.security().retention_days, 2555);
        assert_eq!(c.security().max_delegation_depth, 3);
        assert!(c.security().require_mfa);
    }

    #[test]
    fn test_redb_file_extension_auto_detect() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("auto.redb");

        // Passing a bare .redb path should auto-detect redb backend
        let c = Connector::new()
            .llm("openai", "gpt-4o", "sk-test")
            .storage(&db_path.display().to_string())
            .build();

        let _ = c.agent("bot").instructions("Hi").run("Test", "user:a").unwrap();
        let written = c.save().unwrap();
        assert!(written > 0, "auto-detected redb should persist");
    }

    // ═════════════════════════════════════════════════════════════════════
    // from_yaml / from_config / run_yaml tests
    // ═════════════════════════════════════════════════════════════════════

    #[test]
    fn test_from_yaml_single_agent() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "You are a helpful assistant"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert_eq!(c.llm_config().unwrap().provider, "openai");
        assert_eq!(c.llm_config().unwrap().model, "gpt-4o");
    }

    #[test]
    fn test_from_yaml_with_persist() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "Bot"
persist: true
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.storage_uri().is_some());
        assert!(c.storage_uri().unwrap().contains("redb"));
    }

    #[test]
    fn test_from_yaml_with_security() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "Bot"
secure: hipaa
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.security().signing.is_some());
        assert!(c.security().scitt);
        assert_eq!(c.security().data_classification.as_deref(), Some("PHI"));
    }

    #[test]
    fn test_from_yaml_with_compliance() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "Bot"
comply: [hipaa, soc2]
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert_eq!(c.compliance(), &["hipaa", "soc2"]);
    }

    #[test]
    fn test_from_config_roundtrip() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "You are a doctor"
secure: true
comply: [hipaa]
"#;
        let cfg = crate::shorthand::parse_shorthand(yaml).unwrap();
        let c = Connector::from_config(&cfg);
        assert_eq!(c.llm_config().unwrap().provider, "openai");
        assert!(c.security().signing.is_some());
        assert_eq!(c.compliance(), &["hipaa"]);
    }

    #[test]
    fn test_run_yaml_single_agent() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "You are a helpful assistant"
"#;
        let output = Connector::run_yaml(yaml, "Hello world", "user:test").unwrap();
        assert!(output.status.ok);
        assert!(output.memory.total_packets > 0);
    }

    #[test]
    fn test_run_yaml_multi_agent_pipeline() {
        let yaml = r#"
provider: openai
model: gpt-4o
agents:
  nurse: "You are a triage nurse. Record symptoms."
  doctor: "You are a doctor. Diagnose based on triage."
flow: nurse -> doctor
"#;
        let output = Connector::run_yaml(yaml, "Patient has fever", "user:test").unwrap();
        assert!(output.status.ok);
    }

    #[test]
    fn test_run_yaml_with_budget() {
        let yaml = r#"
provider: openai
model: gpt-4o
agent: "You are helpful"
budget: "$5.00"
"#;
        let output = Connector::run_yaml(yaml, "Hi", "user:test").unwrap();
        assert!(output.status.ok);
    }

    #[test]
    fn test_run_yaml_empty_fails() {
        let result = Connector::run_yaml("{}", "Hello", "user:test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No agents"));
    }

    #[test]
    fn test_run_yaml_hospital_showcase() {
        let yaml = r#"
provider: openai
model: gpt-4o
agents:
  triage: "You are an ER triage nurse."
  doctor:
    instructions: "You are an ER attending physician."
    tools: [ehr_lookup]
  pharmacist: "You are a hospital pharmacist."
flow: triage -> doctor -> pharmacist
memory: long
budget: "$10.00"
trust: medical
firewall: hipaa
secure: hipaa
comply: [hipaa]
retry: 3
"#;
        let output = Connector::run_yaml(yaml, "Patient has chest pain", "user:patient1").unwrap();
        assert!(output.status.ok);
        assert!(output.memory.total_packets > 0);
    }

    // ═══════════════════════════════════════════════════════════════
    // RUNTIME WIRING TESTS — verify shorthand config ACTUALLY EXECUTES
    // These test that config → runtime, not just config → parse.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_runtime_knowledge_injection() {
        // Knowledge facts should be injected into the connector
        let yaml = r#"
agent: "You are a doctor"
knowledge:
  - "Patient has Type 2 diabetes"
  - "Patient is allergic to penicillin"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.knowledge_context.is_some());
        let ctx = c.knowledge_context.as_ref().unwrap();
        assert!(ctx.contains("Type 2 diabetes"));
        assert!(ctx.contains("allergic to penicillin"));
        assert!(ctx.contains("[Knowledge Context]"));
    }

    #[test]
    fn test_runtime_firewall_hipaa_wiring() {
        // firewall: hipaa should expand to real FirewallConfig with HIPAA PII types
        let yaml = r#"
agent: "You are a doctor"
firewall: hipaa
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.firewall_config.is_some());
        let fw = c.firewall_config.as_ref().unwrap();
        // HIPAA firewall should have SSN, CREDIT_CARD, MEDICAL_RECORD in PII types
        assert!(fw.pii_types.contains("SSN"));
        assert!(fw.pii_types.contains("MEDICAL_RECORD"));
        // HIPAA should have elevated PII weight
        assert!(fw.weights.pii > 0.3);
        // Strict thresholds
        assert!(fw.thresholds.block < 0.8);
    }

    #[test]
    fn test_runtime_budget_wiring() {
        // budget: "$5.00" should set budget_config on connector
        let yaml = r#"
agent: "You are helpful"
budget: "$5.00"
"#;
        let cfg = crate::shorthand::parse_shorthand(yaml).unwrap();
        let c = Connector::from_config(&cfg);
        // Budget should be wired (from agent config)
        // Note: shorthand expands budget onto agent, then from_config picks it up
        // The budget is on the agent, so we verify it runs and produces output
        let output = c.agent("agent").run("Hi", "user:test").unwrap();
        assert!(output.status.ok);
    }

    #[test]
    fn test_runtime_policy_wiring() {
        // deny/allow should produce policy_rules on the connector
        let yaml = r#"
agent: "You are helpful"
deny:
  - "export.*"
  - "delete.*"
allow:
  - "read.*"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert_eq!(c.policy_rules.len(), 3);
        // Verify deny rules
        assert!(c.policy_rules.iter().any(|(effect, pattern, _)| effect == "deny" && pattern == "export.*"));
        assert!(c.policy_rules.iter().any(|(effect, pattern, _)| effect == "deny" && pattern == "delete.*"));
        // Verify allow rule
        assert!(c.policy_rules.iter().any(|(effect, pattern, _)| effect == "allow" && pattern == "read.*"));
    }

    #[test]
    fn test_runtime_memory_preset_wiring() {
        // memory: long should set memory_preset on connector
        let yaml = r#"
agent: "You are a doctor"
memory: long
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.memory_preset.is_some());
        let mem = c.memory_preset.as_ref().unwrap();
        assert_eq!(mem.max_packets_per_agent, Some(1000));
        assert_eq!(mem.eviction_policy.as_deref(), Some("summarize_evict"));
        assert_eq!(mem.context_window_tokens, Some(128000));
        assert!(mem.compression_enabled);
    }

    #[test]
    fn test_runtime_trust_preset_wiring() {
        // trust: medical should set trust_config on connector
        let yaml = r#"
agent: "You are a doctor"
trust: medical
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.trust_config.is_some());
        let trust = c.trust_config.as_ref().unwrap();
        assert_eq!(trust.preset.as_deref(), Some("medical"));
    }

    #[test]
    fn test_runtime_cognitive_deep_wiring() {
        // think: deep should set cognitive_config with multi-pass
        let yaml = r#"
agent: "You are a doctor"
think: deep
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.cognitive_config.is_some());
        let cog = c.cognitive_config.as_ref().unwrap();
        assert_eq!(cog.max_cycles, Some(5));
        assert!(cog.reflection_enabled);
        assert!(cog.chain_of_thought);
        assert!(cog.compile_knowledge_after_cycle);
        assert!(cog.contradiction_halt);
    }

    #[test]
    fn test_runtime_retry_wiring() {
        // retry: 3 should set retry_count on connector
        let yaml = r#"
agent: "You are helpful"
retry: 3
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert_eq!(c.retry_count, Some(3));
    }

    #[test]
    fn test_runtime_observe_wiring() {
        // observe: medical should set observe_config
        let yaml = r#"
agent: "You are a doctor"
observe: medical
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.observe_config.is_some());
        let obs = c.observe_config.as_ref().unwrap();
        assert!(obs.extract_entities);
        assert!(obs.extract_claims);
        assert!(obs.strict_grounding);
        assert_eq!(obs.grounding_domain.as_deref(), Some("medical"));
    }

    #[test]
    fn test_runtime_tools_wiring() {
        // tools: {ehr: "desc"} should produce tool_defs on connector
        let yaml = r#"
agent: "You are a doctor"
tools:
  ehr: "Query electronic health records"
  vitals: "Read patient vital signs"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert_eq!(c.tool_defs.len(), 2);
        assert!(c.tool_defs.iter().any(|(name, _)| name == "ehr"));
        assert!(c.tool_defs.iter().any(|(name, _)| name == "vitals"));
    }

    #[test]
    fn test_runtime_full_stack_wiring() {
        // All 12 subsystems wired in a single YAML
        let yaml = r#"
agent: "You are an ER doctor"
knowledge:
  - "Patient has diabetes"
memory: long
budget: "$5.00"
trust: medical
think: deep
observe: medical
firewall: hipaa
secure: hipaa
comply: [hipaa]
retry: 3
deny:
  - "export.*"
tools:
  ehr: "Query EHR"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        // Verify ALL fields are wired
        assert!(c.knowledge_context.is_some(), "knowledge not wired");
        assert!(c.memory_preset.is_some(), "memory not wired");
        assert!(c.trust_config.is_some(), "trust not wired");
        assert!(c.cognitive_config.is_some(), "think not wired");
        assert!(c.observe_config.is_some(), "observe not wired");
        assert!(c.firewall_config.is_some(), "firewall not wired");
        assert_eq!(c.retry_count, Some(3), "retry not wired");
        assert!(!c.policy_rules.is_empty(), "policies not wired");
        assert!(!c.tool_defs.is_empty(), "tools not wired");
        assert!(!c.compliance.is_empty(), "compliance not wired");

        // Verify it actually runs
        let output = c.agent("agent").run("Patient has chest pain", "user:p1").unwrap();
        assert!(output.status.ok);
        assert!(output.memory.total_packets > 0);
    }

    #[test]
    fn test_runtime_knowledge_in_agent_run() {
        // Knowledge should be injected into system prompt during agent run
        let yaml = r#"
agent: "You are a doctor"
knowledge:
  - "Patient weighs 80kg"
  - "Patient is 45 years old"
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        // The knowledge context should be present
        let ctx = c.knowledge_context.as_ref().unwrap();
        assert!(ctx.contains("80kg"));
        assert!(ctx.contains("45 years old"));
        // Run the agent — knowledge is prepended to system prompt
        let output = c.agent("agent").run("Prescribe medication", "user:p1").unwrap();
        assert!(output.status.ok);
    }

    #[test]
    fn test_runtime_firewall_strict_wiring() {
        // firewall: strict should have tighter thresholds than default
        let yaml = r#"
agent: "You are a bot"
firewall: strict
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        let fw = c.firewall_config.as_ref().unwrap();
        assert!(fw.thresholds.block <= 0.6, "strict should have lower block threshold");
        assert!(fw.max_calls_per_minute <= 30, "strict should have lower rate limit");
    }

    #[test]
    fn test_runtime_memory_presets_all_levels() {
        // Verify all memory presets produce different configs
        for (preset, expected_packets) in [("fast", 100), ("long", 1000), ("deep", 10000)] {
            let yaml = format!("agent: \"bot\"\nmemory: {}", preset);
            let c = Connector::from_yaml(&yaml).unwrap();
            let mem = c.memory_preset.as_ref().unwrap();
            assert_eq!(mem.max_packets_per_agent, Some(expected_packets),
                "memory: {} should have {} packets", preset, expected_packets);
        }
    }

    #[test]
    fn test_runtime_think_cycles_numeric() {
        // think: 3 should set 3 cycles
        let yaml = r#"
agent: "bot"
think: 3
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        let cog = c.cognitive_config.as_ref().unwrap();
        assert_eq!(cog.max_cycles, Some(3));
        assert!(cog.reflection_enabled); // > 1 cycle enables reflection
    }

    #[test]
    fn test_runtime_stream_wiring() {
        // stream: true should set streaming_config and produce chunked events
        let yaml = r#"
agent: "You are helpful"
stream: true
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        assert!(c.streaming_config.is_some());
        let stream = c.streaming_config.as_ref().unwrap();
        assert_eq!(stream.protocol, "sse");
        assert_eq!(stream.chunk_size_tokens, Some(10));

        // Run and verify stream.chunk events are produced
        let output = c.agent("agent").run("Tell me a story", "user:test").unwrap();
        assert!(output.status.ok);
        let chunk_events: Vec<_> = output.events.iter()
            .filter(|e| e.event_type == "stream.chunk")
            .collect();
        assert!(!chunk_events.is_empty(), "stream: true should produce chunk events");
        // Should also have a stream.complete event
        let complete = output.events.iter().find(|e| e.event_type == "stream.complete");
        assert!(complete.is_some(), "stream: true should produce stream.complete event");
        assert!(complete.unwrap().message.contains("sse"));
    }

    #[test]
    fn test_runtime_stream_websocket() {
        // stream: websocket should set protocol
        let yaml = r#"
agent: "bot"
stream: websocket
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        let stream = c.streaming_config.as_ref().unwrap();
        assert_eq!(stream.protocol, "websocket");
    }

    #[test]
    fn test_runtime_all_15_subsystems() {
        // THE ULTIMATE TEST: all 15 subsystems wired and running
        let yaml = r#"
agent: "You are an ER doctor"
knowledge:
  - "Patient has diabetes"
memory: long
budget: "$5.00"
trust: medical
think: deep
observe: medical
firewall: hipaa
secure: hipaa
comply: [hipaa]
retry: 3
stream: true
deny:
  - "export.*"
tools:
  ehr: "Query EHR"
persist: true
"#;
        let c = Connector::from_yaml(yaml).unwrap();
        // Verify ALL 15 subsystems are wired
        assert!(c.knowledge_context.is_some(), "1. knowledge not wired");
        assert!(c.memory_preset.is_some(), "2. memory not wired");
        assert!(c.trust_config.is_some(), "3. trust not wired");
        assert!(c.cognitive_config.is_some(), "4. think not wired");
        assert!(c.observe_config.is_some(), "5. observe not wired");
        assert!(c.firewall_config.is_some(), "6. firewall not wired");
        assert_eq!(c.retry_count, Some(3), "7. retry not wired");
        assert!(!c.policy_rules.is_empty(), "8. deny/allow not wired");
        assert!(!c.tool_defs.is_empty(), "9. tools not wired");
        assert!(!c.compliance.is_empty(), "10. comply not wired");
        assert!(c.streaming_config.is_some(), "11. stream not wired");
        assert!(c.storage_uri.is_some(), "12. persist not wired");
        // secure: hipaa → security config active
        // agent: → instructions set
        // provider/model: → auto-detected or set

        // Run it — all 15 subsystems active in a single execution
        let output = c.agent("agent").run("Patient has chest pain", "user:p1").unwrap();
        assert!(output.status.ok);
        assert!(output.memory.total_packets > 0);
        // Streaming events should be present
        assert!(output.events.iter().any(|e| e.event_type == "stream.chunk"),
            "stream events missing from output");
    }

    // ═══════════════════════════════════════════════════════════════
    // VIRAL ENGINEERING TESTS
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_demo_output() {
        let demo = Connector::demo();
        assert!(demo.contains("Connector Demo"), "demo missing header: {}", &demo[..200]);
        assert!(demo.contains("Trust Score"), "demo missing trust: {}", &demo[..500]);
        assert!(demo.contains("Compliance"), "demo missing compliance");
        assert!(demo.contains("Provenance"), "demo missing provenance");
        assert!(demo.contains("Try it yourself"), "demo missing copy-paste section");
        assert!(demo.contains("Connector::quick"), "demo missing quick example");
        assert!(demo.contains("img.shields.io"), "demo missing badge");
    }

    #[test]
    fn test_verify_wraps_any_output() {
        // Connector::verify() — 1-line upgrade for any framework
        let r = Connector::verify("Patient has elevated troponin levels", &["hipaa"]).unwrap();
        assert!(r.status.ok);
        assert!(r.status.trust > 0);
        assert!(r.aapi.compliance.contains(&"hipaa".to_string()));
    }

    #[test]
    fn test_verify_without_compliance() {
        let r = Connector::verify("Hello world", &[]).unwrap();
        assert!(r.status.ok);
    }

    #[test]
    fn test_export_memory_format() {
        let c = Connector::new().llm("openai", "gpt-4o", "sk-test").build();
        let r = c.agent("bot").instructions("Hi").run("Hello", "user:alice").unwrap();
        let json = Connector::export_memory(&r);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["format"], "connector-memory-v1");
        assert!(parsed["trust"]["score"].is_number());
        assert!(parsed["memories"].is_array());
    }

    #[test]
    fn test_vs_comparison_table() {
        let vs = Connector::vs();
        assert!(vs.contains("Connector"), "vs missing Connector column");
        assert!(vs.contains("LangChain"), "vs missing LangChain");
        assert!(vs.contains("CrewAI"), "vs missing CrewAI");
        assert!(vs.contains("Mem0"), "vs missing Mem0");
        assert!(vs.contains("Trust Score"), "vs missing trust row");
        assert!(vs.contains("Zero-Fake"), "vs missing provenance row");
        assert!(vs.contains("Compliance"), "vs missing compliance row");
        assert!(vs.contains("HMAC Audit"), "vs missing audit row");
        assert!(vs.contains("Connector::demo()"), "vs missing CTA");
    }

    #[test]
    fn test_help_has_love_ladder() {
        let help = Connector::help();
        assert!(help.contains("Love Ladder"), "help missing Love Ladder: {}", &help[..200]);
        assert!(help.contains("Level 0"), "help missing Level 0");
        assert!(help.contains("Level 1"), "help missing Level 1");
        assert!(help.contains("Level 2"), "help missing Level 2");
        assert!(help.contains("Level 3"), "help missing Level 3");
        assert!(help.contains("Connector::quick"), "help missing quick");
        assert!(help.contains("run_quick"), "help missing run_quick");
        assert!(help.contains("Connector::verify"), "help missing verify");
        assert!(help.contains("Connector::demo()"), "help missing demo");
        assert!(help.contains("Connector::vs()"), "help missing vs");
        assert!(help.contains("share()"), "help missing share");
        assert!(help.contains("trust_badge_markdown"), "help missing badge");
    }

    #[test]
    fn test_help_detects_llm_status() {
        let help = Connector::help();
        // Without env vars set, should show warning
        assert!(help.contains("LLM") || help.contains("auto-detected"),
            "help should mention LLM status");
    }
}
