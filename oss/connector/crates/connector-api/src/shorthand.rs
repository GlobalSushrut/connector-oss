//! # Shorthand YAML — Docker-level simplicity for agent configs
//!
//! Accepts ultra-simple YAML and expands it into a full `ConnectorConfig`.
//! Covers ALL 15 subsystems with one-word/one-line shorthand.
//!
//! ## Shorthand Reference (verbose → simple)
//!
//! | Subsystem | Verbose | Shorthand |
//! |-----------|---------|-----------|
//! | Agent | `agents: { bot: { instructions: "..." } }` | `agent: "..."` |
//! | Multi-agent | full pipeline config | `agents: { a: "...", b: "..." }` + `flow: a -> b` |
//! | Provider | `connector: { provider: openai }` | auto-detected from env var |
//! | Persist | `connector: { storage: redb://... }` | `persist: true` |
//! | Memory | 8-field MemoryManagementConfig | `memory: long` |
//! | Knowledge | entities + edges + inject | `knowledge: ["fact1", "fact2", {file: x.csv}]` |
//! | Tools | full ToolConfig per tool | `tools: { name: "description" }` |
//! | Budget | `budget: { max_tokens: N, max_cost_usd: N }` | `budget: $5.00` or `budget: 100K` |
//! | Trust | full JudgmentConfig | `trust: medical` or `trust: 70` |
//! | Observe | full PerceptionConfig | `observe: true` or `observe: medical` |
//! | Think | full CognitiveConfig | `think: deep` or `think: 5` |
//! | Stream | full StreamingConfig | `stream: true` or `stream: websocket` |
//! | Firewall | full FirewallConfig | `firewall: hipaa` |
//! | Secure | full SecurityConfig | `secure: true` |
//! | Retry | full RouterConfig | `retry: 3` |
//! | Timeout | per-agent timeout | `timeout: 30s` |
//! | Deny/Allow | full PolicyConfig | `deny: [export.*, delete.*]` |

use std::collections::HashMap;
use serde::Deserialize;
use crate::auto_detect;
use crate::config::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Shorthand types — serde untagged enums for flexible parsing
// ═══════════════════════════════════════════════════════════════════════════════

/// An agent can be either a string (instructions) or a full config object.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandAgent {
    Simple(String),
    Full(AgentConfig),
}

impl ShorthandAgent {
    pub fn into_agent_config(self) -> AgentConfig {
        match self {
            ShorthandAgent::Simple(instructions) => AgentConfig { instructions, ..Default::default() },
            ShorthandAgent::Full(config) => config,
        }
    }
}

/// Tool can be a string (description) or a full ToolConfig.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandTool {
    Builtin(String),
    Full(ToolConfig),
}

/// Knowledge item: a string fact, or a structured source.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandKnowledge {
    Facts(Vec<ShorthandKnowledgeItem>),
    Full(KnowledgeConfig),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandKnowledgeItem {
    Fact(String),
    Source(KnowledgeSourceRef),
}

#[derive(Debug, Deserialize, Clone)]
pub struct KnowledgeSourceRef {
    pub file: Option<String>,
    pub url: Option<String>,
    pub format: Option<String>,
}

/// Memory: a preset string or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandMemory {
    Preset(String),
    Full(MemoryManagementConfig),
}

/// Budget: a string like "$5.00" or "100K", or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandBudget {
    Amount(String),
    Full(BudgetConfig),
}

/// Trust/Judgment: a preset string, a number (min gate), or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandTrust {
    Gate(u32),
    Preset(String),
    Full(JudgmentConfig),
}

/// Observe/Perception: a bool, a domain string, or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandObserve {
    Enabled(bool),
    Domain(String),
    Full(PerceptionConfig),
}

/// Think/Cognitive: a bool, cycle count, preset string, or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandThink {
    Enabled(bool),
    Cycles(u32),
    Preset(String),
    Full(CognitiveConfig),
}

/// Stream: a bool, a protocol string, or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandStream {
    Enabled(bool),
    Protocol(String),
    Full(StreamingConfig),
}

/// Firewall: a preset string or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandFirewall {
    Preset(String),
    Full(FirewallConfig),
}

/// Secure: a bool, a preset string, or full config.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandSecure {
    Enabled(bool),
    Preset(String),
    Full(SecurityConfig),
}

/// Persist: a bool or a storage URI string.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ShorthandPersist {
    Enabled(bool),
    Uri(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
// ShorthandConfig — the top-level struct that accepts ALL shorthand forms
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize, Default)]
pub struct ShorthandConfig {
    // ── Agents ──
    pub agent: Option<ShorthandAgent>,
    pub agents: Option<HashMap<String, ShorthandAgent>>,
    pub flow: Option<String>,

    // ── LLM ──
    pub model: Option<String>,
    pub provider: Option<String>,

    // ── One-word subsystems ──
    pub persist: Option<ShorthandPersist>,
    pub memory: Option<ShorthandMemory>,
    pub knowledge: Option<ShorthandKnowledge>,
    pub tools: Option<HashMap<String, ShorthandTool>>,
    pub budget: Option<ShorthandBudget>,
    pub trust: Option<ShorthandTrust>,
    pub observe: Option<ShorthandObserve>,
    pub think: Option<ShorthandThink>,
    pub stream: Option<ShorthandStream>,
    pub firewall: Option<ShorthandFirewall>,
    pub secure: Option<ShorthandSecure>,
    pub retry: Option<u32>,
    pub timeout: Option<String>,

    // ── Shorthand policy ──
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub comply: Vec<String>,

    // ── Pass-through for advanced users ──
    pub connector: Option<serde_yaml::Value>,
    pub policies: Option<serde_yaml::Value>,
    pub pipelines: Option<serde_yaml::Value>,

    // ── Catch-all for full Tier 3 sections ──
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expansion functions — shorthand → full config
// ═══════════════════════════════════════════════════════════════════════════════

fn expand_persist(p: &ShorthandPersist) -> (Option<String>, Option<CheckpointConfig>) {
    match p {
        ShorthandPersist::Enabled(true) => (
            Some("redb://./connector.redb".to_string()),
            Some(CheckpointConfig { write_through: Some(true), wal_enabled: Some(true), auto_checkpoint_threshold: Some(100) }),
        ),
        ShorthandPersist::Enabled(false) => (None, None),
        ShorthandPersist::Uri(uri) => (
            Some(uri.clone()),
            Some(CheckpointConfig { write_through: Some(true), wal_enabled: Some(true), auto_checkpoint_threshold: Some(100) }),
        ),
    }
}

fn expand_memory(m: &ShorthandMemory) -> MemoryManagementConfig {
    match m {
        ShorthandMemory::Preset(p) => match p.as_str() {
            "fast" | "minimal" => MemoryManagementConfig {
                max_packets_per_agent: Some(100),
                eviction_policy: Some("lru".to_string()),
                hot_tier_limit: Some(100),
                warm_tier_limit: Some(200),
                context_window_tokens: Some(32000),
                ..Default::default()
            },
            "long" => MemoryManagementConfig {
                max_packets_per_agent: Some(1000),
                eviction_policy: Some("summarize_evict".to_string()),
                hot_tier_limit: Some(200),
                warm_tier_limit: Some(2000),
                cold_tier_limit: Some(5000),
                compression_enabled: true,
                compression_threshold_tokens: Some(100000),
                context_window_tokens: Some(128000),
                ..Default::default()
            },
            "deep" => MemoryManagementConfig {
                max_packets_per_agent: Some(10000),
                eviction_policy: Some("summarize_evict".to_string()),
                hot_tier_limit: Some(500),
                warm_tier_limit: Some(5000),
                cold_tier_limit: Some(50000),
                compression_enabled: true,
                compression_threshold_tokens: Some(200000),
                context_window_tokens: Some(200000),
                seal_on_session_close: true,
                ..Default::default()
            },
            "infinite" => MemoryManagementConfig {
                eviction_policy: Some("never".to_string()),
                compression_enabled: true,
                compression_threshold_tokens: Some(500000),
                context_window_tokens: Some(1000000),
                seal_on_session_close: true,
                ..Default::default()
            },
            _ => MemoryManagementConfig::default(),
        },
        ShorthandMemory::Full(c) => c.clone(),
    }
}

fn expand_knowledge(k: &ShorthandKnowledge) -> KnowledgeConfig {
    match k {
        ShorthandKnowledge::Facts(items) => {
            let mut entities = Vec::new();
            let mut inject = Vec::new();
            for (i, item) in items.iter().enumerate() {
                match item {
                    ShorthandKnowledgeItem::Fact(text) => {
                        entities.push(SeedEntity {
                            id: format!("fact_{}", i),
                            entity_type: Some("fact".to_string()),
                            tags: vec![],
                            attrs: {
                                let mut m = HashMap::new();
                                m.insert("text".to_string(), serde_json::Value::String(text.clone()));
                                m
                            },
                        });
                    }
                    ShorthandKnowledgeItem::Source(src) => {
                        if let Some(file) = &src.file {
                            inject.push(DataInjectionConfig {
                                source: format!("file:{}", file),
                                format: src.format.clone().unwrap_or_else(|| guess_format(file)),
                                entity_type: None, id_field: None, tag_fields: vec![], auth_header: None, refresh_interval_hours: None,
                            });
                        }
                        if let Some(url) = &src.url {
                            inject.push(DataInjectionConfig {
                                source: url.clone(),
                                format: src.format.clone().unwrap_or_else(|| "json".to_string()),
                                entity_type: None, id_field: None, tag_fields: vec![], auth_header: None, refresh_interval_hours: None,
                            });
                        }
                    }
                }
            }
            KnowledgeConfig {
                seed: if entities.is_empty() { None } else {
                    Some(KnowledgeSeed { entities, edges: vec![] })
                },
                inject,
                contradiction_check: true,
                ..Default::default()
            }
        }
        ShorthandKnowledge::Full(c) => c.clone(),
    }
}

fn guess_format(path: &str) -> String {
    if path.ends_with(".csv") { "csv".to_string() }
    else if path.ends_with(".jsonl") { "jsonl".to_string() }
    else { "json".to_string() }
}

fn expand_tools(tools: &HashMap<String, ShorthandTool>) -> HashMap<String, ToolConfig> {
    tools.iter().map(|(name, t)| {
        let cfg = match t {
            ShorthandTool::Builtin(desc) if desc == "builtin" => ToolConfig {
                description: format!("Built-in tool: {}", name),
                resource: Some(format!("builtin://{}", name)),
                actions: vec!["execute".to_string()],
                data_classification: None, requires_approval: false, timeout_ms: Some(30000), blocked: false,
            },
            ShorthandTool::Builtin(desc) => ToolConfig {
                description: desc.clone(),
                resource: None,
                actions: vec!["read".to_string(), "execute".to_string()],
                data_classification: None, requires_approval: false, timeout_ms: Some(30000), blocked: false,
            },
            ShorthandTool::Full(c) => c.clone(),
        };
        (name.clone(), cfg)
    }).collect()
}

fn expand_budget(b: &ShorthandBudget) -> BudgetConfig {
    match b {
        ShorthandBudget::Amount(s) => {
            let s = s.trim();
            if s.starts_with('$') {
                let amount: f64 = s[1..].parse().unwrap_or(5.0);
                BudgetConfig { max_cost_usd: Some(amount), max_tokens: None }
            } else if s.ends_with('K') || s.ends_with('k') {
                let n: u64 = s[..s.len()-1].parse().unwrap_or(100);
                BudgetConfig { max_tokens: Some(n * 1000), max_cost_usd: None }
            } else if s.ends_with('M') || s.ends_with('m') {
                let n: u64 = s[..s.len()-1].parse().unwrap_or(1);
                BudgetConfig { max_tokens: Some(n * 1_000_000), max_cost_usd: None }
            } else {
                let n: u64 = s.parse().unwrap_or(100000);
                BudgetConfig { max_tokens: Some(n), max_cost_usd: None }
            }
        }
        ShorthandBudget::Full(c) => c.clone(),
    }
}

fn expand_trust(t: &ShorthandTrust) -> JudgmentConfig {
    match t {
        ShorthandTrust::Gate(n) => JudgmentConfig { min_trust_gate: Some(*n), ..Default::default() },
        ShorthandTrust::Preset(p) => JudgmentConfig { preset: Some(p.clone()), ..Default::default() },
        ShorthandTrust::Full(c) => c.clone(),
    }
}

fn expand_observe(o: &ShorthandObserve) -> PerceptionConfig {
    match o {
        ShorthandObserve::Enabled(true) => PerceptionConfig {
            extract_entities: true, extract_claims: true, verify_claims: true,
            max_entities: None, quality_threshold: None, block_low_quality: false,
            grounding_domain: None, strict_grounding: false,
        },
        ShorthandObserve::Enabled(false) => PerceptionConfig {
            extract_entities: false, extract_claims: false, verify_claims: false,
            max_entities: None, quality_threshold: None, block_low_quality: false,
            grounding_domain: None, strict_grounding: false,
        },
        ShorthandObserve::Domain(d) => PerceptionConfig {
            extract_entities: true, extract_claims: true, verify_claims: true,
            max_entities: None, quality_threshold: Some(60), block_low_quality: true,
            grounding_domain: Some(d.clone()), strict_grounding: true,
        },
        ShorthandObserve::Full(c) => c.clone(),
    }
}

fn expand_think(t: &ShorthandThink) -> CognitiveConfig {
    match t {
        ShorthandThink::Enabled(true) => CognitiveConfig {
            max_cycles: Some(3), reflection_enabled: true, chain_of_thought: true,
            compile_knowledge_after_cycle: false, contradiction_halt: false,
            max_reasoning_steps: None, min_cycle_quality: None,
        },
        ShorthandThink::Enabled(false) => CognitiveConfig {
            max_cycles: Some(1), reflection_enabled: false, chain_of_thought: false,
            compile_knowledge_after_cycle: false, contradiction_halt: false,
            max_reasoning_steps: None, min_cycle_quality: None,
        },
        ShorthandThink::Cycles(n) => CognitiveConfig {
            max_cycles: Some(*n), reflection_enabled: *n > 1, chain_of_thought: true,
            compile_knowledge_after_cycle: false, contradiction_halt: false,
            max_reasoning_steps: None, min_cycle_quality: None,
        },
        ShorthandThink::Preset(p) => match p.as_str() {
            "deep" => CognitiveConfig {
                max_cycles: Some(5), reflection_enabled: true, chain_of_thought: true,
                compile_knowledge_after_cycle: true, contradiction_halt: true,
                max_reasoning_steps: Some(20), min_cycle_quality: Some(60),
            },
            _ => CognitiveConfig {
                max_cycles: Some(3), reflection_enabled: true, chain_of_thought: true,
                compile_knowledge_after_cycle: false, contradiction_halt: false,
                max_reasoning_steps: None, min_cycle_quality: None,
            },
        },
        ShorthandThink::Full(c) => c.clone(),
    }
}

fn expand_stream(s: &ShorthandStream) -> StreamingConfig {
    match s {
        ShorthandStream::Enabled(true) => StreamingConfig {
            protocol: "sse".to_string(), chunk_size_tokens: Some(10),
            heartbeat_interval_ms: Some(30000), max_connections: Some(100),
            buffer_chunks: Some(50), include_audit_events: false, include_trust_updates: false,
        },
        ShorthandStream::Enabled(false) => StreamingConfig {
            protocol: "sse".to_string(), chunk_size_tokens: None,
            heartbeat_interval_ms: None, max_connections: None,
            buffer_chunks: None, include_audit_events: false, include_trust_updates: false,
        },
        ShorthandStream::Protocol(p) => StreamingConfig {
            protocol: p.clone(), chunk_size_tokens: Some(10),
            heartbeat_interval_ms: Some(30000), max_connections: Some(100),
            buffer_chunks: Some(50), include_audit_events: false, include_trust_updates: false,
        },
        ShorthandStream::Full(c) => c.clone(),
    }
}

fn expand_firewall(f: &ShorthandFirewall) -> FirewallConfig {
    match f {
        ShorthandFirewall::Preset(p) => FirewallConfig { preset: Some(p.clone()), ..Default::default() },
        ShorthandFirewall::Full(c) => c.clone(),
    }
}

fn expand_secure(s: &ShorthandSecure) -> SecurityConfig {
    match s {
        ShorthandSecure::Enabled(true) => SecurityConfig {
            signing: Some(true), scitt: Some(true), require_mfa: Some(false),
            ..Default::default()
        },
        ShorthandSecure::Enabled(false) => SecurityConfig::default(),
        ShorthandSecure::Preset(p) => match p.as_str() {
            "hipaa" => SecurityConfig {
                signing: Some(true), scitt: Some(true), data_classification: Some("PHI".to_string()),
                jurisdiction: Some("US".to_string()), retention_days: Some(2555),
                audit_export: Some("json".to_string()), ..Default::default()
            },
            "financial" | "finra" => SecurityConfig {
                signing: Some(true), scitt: Some(true), data_classification: Some("confidential".to_string()),
                retention_days: Some(2555), audit_export: Some("json".to_string()), ..Default::default()
            },
            "gdpr" => SecurityConfig {
                signing: Some(true), scitt: Some(true), data_classification: Some("PII".to_string()),
                jurisdiction: Some("EU".to_string()), retention_days: Some(1095),
                audit_export: Some("json".to_string()), ..Default::default()
            },
            _ => SecurityConfig { signing: Some(true), scitt: Some(true), ..Default::default() },
        },
        ShorthandSecure::Full(c) => c.clone(),
    }
}

fn expand_deny_allow(deny: &[String], allow: &[String]) -> HashMap<String, PolicyConfig> {
    let mut policies = HashMap::new();
    if !deny.is_empty() || !allow.is_empty() {
        let mut rules = Vec::new();
        for pattern in deny {
            rules.push(PolicyRule {
                effect: "deny".to_string(), action_pattern: pattern.clone(),
                resource_pattern: None, roles: vec![], priority: 100,
            });
        }
        for pattern in allow {
            rules.push(PolicyRule {
                effect: "allow".to_string(), action_pattern: pattern.clone(),
                resource_pattern: None, roles: vec![], priority: 10,
            });
        }
        policies.insert("auto_policy".to_string(), PolicyConfig {
            name: "Auto-generated from deny/allow shorthand".to_string(),
            enabled: true, rules,
        });
    }
    policies
}

fn expand_retry(n: u32) -> RouterConfig {
    RouterConfig {
        retry: Some(RetryConfig { max_retries: Some(n), base_delay_ms: Some(500), max_delay_ms: Some(30000) }),
        circuit_breaker: Some(CircuitBreakerConfig { failure_threshold: Some(5), cooldown_secs: Some(60) }),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main parse + expand
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse shorthand YAML into a full ConnectorConfig.
/// Handles everything from 1-line agents to full military-grade configs.
pub fn parse_shorthand(yaml: &str) -> Result<ConnectorConfig, ConfigError> {
    let interpolated = crate::config::interpolate_env_vars(yaml)?;

    // If it has connector: but NOT agent:, treat as full config
    if interpolated.contains("connector:") && !interpolated.contains("agent:") {
        return serde_yaml::from_str::<ConnectorConfig>(&interpolated)
            .map_err(|e| ConfigError::ParseError(e.to_string()));
    }

    let short: ShorthandConfig = serde_yaml::from_str(&interpolated)
        .map_err(|e| ConfigError::ParseError(e.to_string()))?;

    expand_shorthand(short)
}

fn expand_shorthand(short: ShorthandConfig) -> Result<ConnectorConfig, ConfigError> {
    let mut cfg = ConnectorConfig::default();
    let detected = auto_detect::auto_detect_llm();

    // ── 1. LLM ──────────────────────────────────────────────────────────────
    cfg.connector = GlobalConfig {
        provider: short.provider.or(detected.as_ref().map(|d| d.provider.clone())),
        model: short.model.or(detected.as_ref().map(|d| d.model.clone())),
        api_key: detected.as_ref().map(|d| d.api_key.clone()),
        endpoint: detected.as_ref().and_then(|d| d.endpoint.clone()),
        comply: short.comply,
        ..Default::default()
    };

    // ── 2. Agents ───────────────────────────────────────────────────────────
    if let Some(single) = short.agent {
        cfg.agents.insert("agent".to_string(), single.into_agent_config());
    }
    if let Some(agents) = short.agents {
        for (name, agent) in agents {
            cfg.agents.insert(name, agent.into_agent_config());
        }
    }

    // ── 3. Flow → pipeline ──────────────────────────────────────────────────
    if let Some(flow_expr) = short.flow {
        let steps: Vec<&str> = flow_expr.split("->").map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if steps.len() >= 2 {
            let actors: Vec<ActorConfig> = steps.iter().enumerate().map(|(i, name)| {
                let agent_cfg = cfg.agents.get(*name);
                ActorConfig {
                    name: name.to_string(),
                    instructions: agent_cfg.map(|a| a.instructions.clone()).unwrap_or_default(),
                    role: agent_cfg.and_then(|a| a.role.clone()),
                    tools: agent_cfg.map(|a| a.tools.clone()).unwrap_or_default(),
                    deny_tools: vec![], allow_data: vec![], deny_data: vec![],
                    require_approval: agent_cfg.map(|a| a.require_approval.clone()).unwrap_or_default(),
                    memory_from: if i > 0 { vec![steps[i - 1].to_string()] } else { vec![] },
                }
            }).collect();
            cfg.pipelines.insert("main".to_string(), PipelineConfig {
                actors, flow: Some(flow_expr), comply: cfg.connector.comply.clone(), ..Default::default()
            });
        }
    }

    // ── 4. Persist ──────────────────────────────────────────────────────────
    if let Some(ref p) = short.persist {
        let (storage, checkpoint) = expand_persist(p);
        if storage.is_some() { cfg.connector.storage = storage; }
        if checkpoint.is_some() { cfg.connector.checkpoint = checkpoint; }
    }

    // ── 5. Memory ───────────────────────────────────────────────────────────
    if let Some(ref m) = short.memory {
        cfg.memory = Some(expand_memory(m));
    }

    // ── 6. Knowledge ────────────────────────────────────────────────────────
    if let Some(ref k) = short.knowledge {
        cfg.knowledge = Some(expand_knowledge(k));
    }

    // ── 7. Tools ────────────────────────────────────────────────────────────
    if let Some(ref tools) = short.tools {
        cfg.tools = expand_tools(tools);
    }

    // ── 8. Budget (apply to all agents) ─────────────────────────────────────
    if let Some(ref b) = short.budget {
        let budget = expand_budget(b);
        for agent in cfg.agents.values_mut() {
            if agent.budget.is_none() { agent.budget = Some(budget.clone()); }
        }
    }

    // ── 9. Trust / Judgment ─────────────────────────────────────────────────
    if let Some(ref t) = short.trust {
        cfg.judgment = Some(expand_trust(t));
    }

    // ── 10. Observe / Perception ────────────────────────────────────────────
    if let Some(ref o) = short.observe {
        cfg.perception = Some(expand_observe(o));
    }

    // ── 11. Think / Cognitive ───────────────────────────────────────────────
    if let Some(ref t) = short.think {
        cfg.cognitive = Some(expand_think(t));
    }

    // ── 12. Stream ──────────────────────────────────────────────────────────
    if let Some(ref s) = short.stream {
        cfg.streaming = Some(expand_stream(s));
    }

    // ── 13. Firewall ────────────────────────────────────────────────────────
    if let Some(ref f) = short.firewall {
        cfg.connector.firewall = Some(expand_firewall(f));
    }

    // ── 14. Secure ──────────────────────────────────────────────────────────
    if let Some(ref s) = short.secure {
        cfg.connector.security = Some(expand_secure(s));
    }

    // ── 15. Retry ───────────────────────────────────────────────────────────
    if let Some(n) = short.retry {
        cfg.connector.router = Some(expand_retry(n));
    }

    // ── 16. Deny/Allow → policies ───────────────────────────────────────────
    if !short.deny.is_empty() || !short.allow.is_empty() {
        cfg.policies = expand_deny_allow(&short.deny, &short.allow);
    }

    // ── 17. Pass-through advanced sections ──────────────────────────────────
    if let Some(policies_val) = short.policies {
        if let Ok(p) = serde_yaml::from_value(policies_val) { cfg.policies = p; }
    }
    if let Some(pipelines_val) = short.pipelines {
        if let Ok(p) = serde_yaml::from_value(pipelines_val) {
            if cfg.pipelines.is_empty() { cfg.pipelines = p; }
        }
    }

    // Merge connector: section (overrides auto-detect)
    if let Some(connector_val) = short.connector {
        if let Ok(global) = serde_yaml::from_value::<GlobalConfig>(connector_val) {
            if global.provider.is_some() { cfg.connector.provider = global.provider; }
            if global.model.is_some()    { cfg.connector.model = global.model; }
            if global.api_key.is_some()  { cfg.connector.api_key = global.api_key; }
            if global.endpoint.is_some() { cfg.connector.endpoint = global.endpoint; }
            if global.storage.is_some()  { cfg.connector.storage = global.storage; }
            if global.security.is_some() { cfg.connector.security = global.security; }
            if global.firewall.is_some() { cfg.connector.firewall = global.firewall; }
            if !global.comply.is_empty() { cfg.connector.comply = global.comply; }
        }
    }

    // Pass-through Tier 3 full sections from extra
    for (key, val) in &short.extra {
        match key.as_str() {
            "crypto"        => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.crypto = Some(v); } }
            "consensus"     => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.consensus = Some(v); } }
            "watchdog"      => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.watchdog = Some(v); } }
            "formal_verify" => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.formal_verify = Some(v); } }
            "negotiation"   => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.negotiation = Some(v); } }
            "cluster"       => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.cluster = Some(v); } }
            "swarm"         => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.swarm = Some(v); } }
            "mcp"           => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.mcp = Some(v); } }
            "server"        => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.server = Some(v); } }
            "observability" => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.observability = Some(v); } }
            "rag"           => { if let Ok(v) = serde_yaml::from_value(val.clone()) { cfg.rag = Some(v); } }
            _ => {}
        }
    }

    Ok(cfg)
}

/// Load a shorthand YAML file from disk.
pub fn load_shorthand(path: &str) -> Result<ConnectorConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::FileNotFound {
        path: path.to_string(),
        detail: e.to_string(),
    })?;
    parse_shorthand(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. Single agent shorthand ──────────────────────────────────────────
    #[test]
    fn test_single_agent_string() {
        let yaml = "provider: openai\nmodel: gpt-4o\nagent: \"You are a helpful doctor\"";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(cfg.agents.get("agent").unwrap().instructions, "You are a helpful doctor");
        assert_eq!(cfg.connector.provider.as_deref(), Some("openai"));
    }

    // ── 2. Multi-agent strings ─────────────────────────────────────────────
    #[test]
    fn test_multi_agent_strings() {
        let yaml = "provider: openai\nagents:\n  nurse: \"You are a triage nurse\"\n  doctor: \"You are an ER doctor\"";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.agents.len(), 2);
        assert_eq!(cfg.agents.get("nurse").unwrap().instructions, "You are a triage nurse");
        assert_eq!(cfg.agents.get("doctor").unwrap().instructions, "You are an ER doctor");
    }

    // ── 3. Flow auto-generates pipeline ────────────────────────────────────
    #[test]
    fn test_flow_generates_pipeline() {
        let yaml = "provider: openai\nagents:\n  nurse: \"Triage\"\n  doctor: \"Diagnose\"\nflow: nurse -> doctor";
        let cfg = parse_shorthand(yaml).unwrap();
        assert!(cfg.pipelines.contains_key("main"));
        let pipeline = cfg.pipelines.get("main").unwrap();
        assert_eq!(pipeline.actors.len(), 2);
        assert_eq!(pipeline.actors[0].name, "nurse");
        assert_eq!(pipeline.actors[1].name, "doctor");
        assert!(pipeline.actors[1].memory_from.contains(&"nurse".to_string()));
    }

    // ── 4. Mixed: some agents as strings, some as full config ──────────────
    #[test]
    fn test_mixed_agent_types() {
        let yaml = r#"
provider: openai
agents:
  nurse: "You are a triage nurse"
  doctor:
    instructions: "You are an ER doctor"
    role: doctor
    tools: [ehr_lookup]
flow: nurse -> doctor
"#;
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.agents.get("nurse").unwrap().instructions, "You are a triage nurse");
        let doctor = cfg.agents.get("doctor").unwrap();
        assert_eq!(doctor.instructions, "You are an ER doctor");
        assert_eq!(doctor.role.as_deref(), Some("doctor"));
        assert_eq!(doctor.tools, vec!["ehr_lookup"]);
    }

    // ── 5. Provider/model override ─────────────────────────────────────────
    #[test]
    fn test_provider_model_override() {
        let yaml = "provider: anthropic\nmodel: claude-3-opus\nagent: \"You are helpful\"";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.provider.as_deref(), Some("anthropic"));
        assert_eq!(cfg.connector.model.as_deref(), Some("claude-3-opus"));
    }

    // ── 6. Compliance shorthand ────────────────────────────────────────────
    #[test]
    fn test_comply_shorthand() {
        let yaml = "provider: openai\nagent: \"Doctor\"\ncomply: [hipaa, soc2]";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.comply, vec!["hipaa", "soc2"]);
    }

    // ── 7. Full config passthrough ─────────────────────────────────────────
    #[test]
    fn test_full_config_passthrough() {
        let yaml = "connector:\n  provider: openai\n  model: gpt-4o\n  api_key: sk-test\nagents:\n  bot:\n    instructions: \"You are helpful\"\n";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.provider.as_deref(), Some("openai"));
        assert_eq!(cfg.agents.get("bot").unwrap().instructions, "You are helpful");
    }

    // ── 8. Three-agent pipeline with memory chain ──────────────────────────
    #[test]
    fn test_three_agent_pipeline() {
        let yaml = "provider: openai\nagents:\n  a: \"Agent A\"\n  b: \"Agent B\"\n  c: \"Agent C\"\nflow: a -> b -> c";
        let cfg = parse_shorthand(yaml).unwrap();
        let pipeline = cfg.pipelines.get("main").unwrap();
        assert_eq!(pipeline.actors.len(), 3);
        assert!(pipeline.actors[0].memory_from.is_empty());
        assert_eq!(pipeline.actors[1].memory_from, vec!["a"]);
        assert_eq!(pipeline.actors[2].memory_from, vec!["b"]);
    }

    // ── 9. Connector override merges with shorthand ────────────────────────
    #[test]
    fn test_connector_override_merges() {
        let yaml = "connector:\n  provider: openai\n  storage: redb://./test.redb\nagent: \"Doctor\"";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.provider.as_deref(), Some("openai"));
        assert_eq!(cfg.connector.storage.as_deref(), Some("redb://./test.redb"));
    }

    // ── 10. Extra sections pass through (crypto) ──────────────────────────
    #[test]
    fn test_extra_sections_passthrough() {
        let yaml = "provider: openai\nagent: \"Doctor\"\ncrypto:\n  fips: true\n  post_quantum: true";
        let cfg = parse_shorthand(yaml).unwrap();
        let crypto = cfg.crypto.unwrap();
        assert!(crypto.fips);
        assert!(crypto.post_quantum);
    }

    // ── 11. Empty YAML produces empty agents ──────────────────────────────
    #[test]
    fn test_empty_yaml() {
        let cfg = parse_shorthand("{}").unwrap();
        assert!(cfg.agents.is_empty());
    }

    // ── 12. Shorthand agent enum: simple string ───────────────────────────
    #[test]
    fn test_shorthand_agent_simple() {
        let a = ShorthandAgent::Simple("You are helpful".to_string());
        let cfg = a.into_agent_config();
        assert_eq!(cfg.instructions, "You are helpful");
        assert!(cfg.tools.is_empty());
        assert!(cfg.role.is_none());
    }

    // ── 13. Shorthand agent enum: full config ─────────────────────────────
    #[test]
    fn test_shorthand_agent_full() {
        let a = ShorthandAgent::Full(AgentConfig {
            instructions: "Doctor".to_string(),
            role: Some("doctor".to_string()),
            tools: vec!["ehr".to_string()],
            ..Default::default()
        });
        let cfg = a.into_agent_config();
        assert_eq!(cfg.role.as_deref(), Some("doctor"));
        assert_eq!(cfg.tools, vec!["ehr"]);
    }

    // ── 14. Watchdog passthrough via extra ─────────────────────────────────
    #[test]
    fn test_watchdog_passthrough() {
        let yaml = "provider: openai\nagent: \"Bot\"\nwatchdog:\n  defaults: true";
        let cfg = parse_shorthand(yaml).unwrap();
        assert!(cfg.watchdog.is_some());
        assert!(cfg.watchdog.unwrap().defaults);
    }

    // ── 15. Consensus passthrough via extra ────────────────────────────────
    #[test]
    fn test_consensus_passthrough() {
        let yaml = "provider: openai\nagent: \"Bot\"\nconsensus:\n  type: bft\n  validators: [a, b, c]";
        let cfg = parse_shorthand(yaml).unwrap();
        let c = cfg.consensus.unwrap();
        assert_eq!(c.r#type, "bft");
        assert_eq!(c.validators.len(), 3);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // NEW: Shorthand subsystem tests (16–35)
    // ═════════════════════════════════════════════════════════════════════════

    // ── 16. persist: true ───────────────────────────────────────────────────
    #[test]
    fn test_persist_true() {
        let yaml = "provider: openai\nagent: \"Bot\"\npersist: true";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.storage.as_deref(), Some("redb://./connector.redb"));
        assert!(cfg.connector.checkpoint.is_some());
        let cp = cfg.connector.checkpoint.unwrap();
        assert_eq!(cp.write_through, Some(true));
        assert_eq!(cp.wal_enabled, Some(true));
    }

    // ── 17. persist: URI ────────────────────────────────────────────────────
    #[test]
    fn test_persist_uri() {
        let yaml = "provider: openai\nagent: \"Bot\"\npersist: \"sqlite://./mydb.sqlite\"";
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.connector.storage.as_deref(), Some("sqlite://./mydb.sqlite"));
    }

    // ── 18. memory: fast ────────────────────────────────────────────────────
    #[test]
    fn test_memory_fast() {
        let yaml = "provider: openai\nagent: \"Bot\"\nmemory: fast";
        let cfg = parse_shorthand(yaml).unwrap();
        let m = cfg.memory.unwrap();
        assert_eq!(m.max_packets_per_agent, Some(100));
        assert_eq!(m.eviction_policy.as_deref(), Some("lru"));
        assert_eq!(m.context_window_tokens, Some(32000));
    }

    // ── 19. memory: long ────────────────────────────────────────────────────
    #[test]
    fn test_memory_long() {
        let yaml = "provider: openai\nagent: \"Bot\"\nmemory: long";
        let cfg = parse_shorthand(yaml).unwrap();
        let m = cfg.memory.unwrap();
        assert_eq!(m.eviction_policy.as_deref(), Some("summarize_evict"));
        assert!(m.compression_enabled);
        assert_eq!(m.context_window_tokens, Some(128000));
    }

    // ── 20. memory: deep ────────────────────────────────────────────────────
    #[test]
    fn test_memory_deep() {
        let yaml = "provider: openai\nagent: \"Bot\"\nmemory: deep";
        let cfg = parse_shorthand(yaml).unwrap();
        let m = cfg.memory.unwrap();
        assert_eq!(m.max_packets_per_agent, Some(10000));
        assert!(m.seal_on_session_close);
        assert_eq!(m.context_window_tokens, Some(200000));
    }

    // ── 21. memory: infinite ────────────────────────────────────────────────
    #[test]
    fn test_memory_infinite() {
        let yaml = "provider: openai\nagent: \"Bot\"\nmemory: infinite";
        let cfg = parse_shorthand(yaml).unwrap();
        let m = cfg.memory.unwrap();
        assert_eq!(m.eviction_policy.as_deref(), Some("never"));
        assert_eq!(m.context_window_tokens, Some(1000000));
    }

    // ── 22. knowledge: list of facts ────────────────────────────────────────
    #[test]
    fn test_knowledge_facts() {
        let yaml = r#"
provider: openai
agent: "Doctor"
knowledge:
  - "Aspirin is an NSAID with bleeding risk"
  - "Ibuprofen interacts with warfarin"
"#;
        let cfg = parse_shorthand(yaml).unwrap();
        let k = cfg.knowledge.unwrap();
        let seed = k.seed.unwrap();
        assert_eq!(seed.entities.len(), 2);
        assert_eq!(seed.entities[0].id, "fact_0");
        assert!(seed.entities[0].attrs.contains_key("text"));
        assert!(k.contradiction_check);
    }

    // ── 23. knowledge: file source ──────────────────────────────────────────
    #[test]
    fn test_knowledge_file_source() {
        let yaml = r#"
provider: openai
agent: "Doctor"
knowledge:
  - file: drugs.csv
"#;
        let cfg = parse_shorthand(yaml).unwrap();
        let k = cfg.knowledge.unwrap();
        assert_eq!(k.inject.len(), 1);
        assert!(k.inject[0].source.contains("drugs.csv"));
        assert_eq!(k.inject[0].format, "csv");
    }

    // ── 24. tools: string descriptions ──────────────────────────────────────
    #[test]
    fn test_tools_string_descriptions() {
        let yaml = r#"
provider: openai
agent: "Bot"
tools:
  ehr_lookup: "Look up patient EHR by ID"
  web_search: builtin
"#;
        let cfg = parse_shorthand(yaml).unwrap();
        assert_eq!(cfg.tools.len(), 2);
        let ehr = cfg.tools.get("ehr_lookup").unwrap();
        assert_eq!(ehr.description, "Look up patient EHR by ID");
        assert_eq!(ehr.timeout_ms, Some(30000));
        let ws = cfg.tools.get("web_search").unwrap();
        assert!(ws.resource.as_ref().unwrap().contains("builtin://"));
    }

    // ── 25. budget: $5.00 ───────────────────────────────────────────────────
    #[test]
    fn test_budget_dollar() {
        let yaml = "provider: openai\nagent: \"Bot\"\nbudget: \"$5.00\"";
        let cfg = parse_shorthand(yaml).unwrap();
        let b = cfg.agents.get("agent").unwrap().budget.as_ref().unwrap();
        assert_eq!(b.max_cost_usd, Some(5.0));
        assert!(b.max_tokens.is_none());
    }

    // ── 26. budget: 100K ────────────────────────────────────────────────────
    #[test]
    fn test_budget_tokens_k() {
        let yaml = "provider: openai\nagent: \"Bot\"\nbudget: 100K";
        let cfg = parse_shorthand(yaml).unwrap();
        let b = cfg.agents.get("agent").unwrap().budget.as_ref().unwrap();
        assert_eq!(b.max_tokens, Some(100_000));
    }

    // ── 27. budget: 2M ──────────────────────────────────────────────────────
    #[test]
    fn test_budget_tokens_m() {
        let yaml = "provider: openai\nagent: \"Bot\"\nbudget: 2M";
        let cfg = parse_shorthand(yaml).unwrap();
        let b = cfg.agents.get("agent").unwrap().budget.as_ref().unwrap();
        assert_eq!(b.max_tokens, Some(2_000_000));
    }

    // ── 28. trust: medical ──────────────────────────────────────────────────
    #[test]
    fn test_trust_preset() {
        let yaml = "provider: openai\nagent: \"Bot\"\ntrust: medical";
        let cfg = parse_shorthand(yaml).unwrap();
        let j = cfg.judgment.unwrap();
        assert_eq!(j.preset.as_deref(), Some("medical"));
    }

    // ── 29. trust: 70 (min gate) ────────────────────────────────────────────
    #[test]
    fn test_trust_gate() {
        let yaml = "provider: openai\nagent: \"Bot\"\ntrust: 70";
        let cfg = parse_shorthand(yaml).unwrap();
        let j = cfg.judgment.unwrap();
        assert_eq!(j.min_trust_gate, Some(70));
    }

    // ── 30. observe: true ───────────────────────────────────────────────────
    #[test]
    fn test_observe_true() {
        let yaml = "provider: openai\nagent: \"Bot\"\nobserve: true";
        let cfg = parse_shorthand(yaml).unwrap();
        let p = cfg.perception.unwrap();
        assert!(p.extract_entities);
        assert!(p.extract_claims);
        assert!(p.verify_claims);
    }

    // ── 31. observe: medical (domain grounding) ─────────────────────────────
    #[test]
    fn test_observe_domain() {
        let yaml = "provider: openai\nagent: \"Bot\"\nobserve: medical";
        let cfg = parse_shorthand(yaml).unwrap();
        let p = cfg.perception.unwrap();
        assert_eq!(p.grounding_domain.as_deref(), Some("medical"));
        assert!(p.strict_grounding);
        assert!(p.block_low_quality);
    }

    // ── 32. think: deep ─────────────────────────────────────────────────────
    #[test]
    fn test_think_deep() {
        let yaml = "provider: openai\nagent: \"Bot\"\nthink: deep";
        let cfg = parse_shorthand(yaml).unwrap();
        let c = cfg.cognitive.unwrap();
        assert_eq!(c.max_cycles, Some(5));
        assert!(c.reflection_enabled);
        assert!(c.chain_of_thought);
        assert!(c.compile_knowledge_after_cycle);
        assert!(c.contradiction_halt);
    }

    // ── 33. think: 3 (cycle count) ──────────────────────────────────────────
    #[test]
    fn test_think_cycles() {
        let yaml = "provider: openai\nagent: \"Bot\"\nthink: 3";
        let cfg = parse_shorthand(yaml).unwrap();
        let c = cfg.cognitive.unwrap();
        assert_eq!(c.max_cycles, Some(3));
        assert!(c.reflection_enabled);
    }

    // ── 34. stream: true ────────────────────────────────────────────────────
    #[test]
    fn test_stream_true() {
        let yaml = "provider: openai\nagent: \"Bot\"\nstream: true";
        let cfg = parse_shorthand(yaml).unwrap();
        let s = cfg.streaming.unwrap();
        assert_eq!(s.protocol, "sse");
        assert_eq!(s.chunk_size_tokens, Some(10));
    }

    // ── 35. stream: websocket ───────────────────────────────────────────────
    #[test]
    fn test_stream_protocol() {
        let yaml = "provider: openai\nagent: \"Bot\"\nstream: websocket";
        let cfg = parse_shorthand(yaml).unwrap();
        let s = cfg.streaming.unwrap();
        assert_eq!(s.protocol, "websocket");
    }

    // ── 36. firewall: hipaa ─────────────────────────────────────────────────
    #[test]
    fn test_firewall_preset() {
        let yaml = "provider: openai\nagent: \"Bot\"\nfirewall: hipaa";
        let cfg = parse_shorthand(yaml).unwrap();
        let f = cfg.connector.firewall.unwrap();
        assert_eq!(f.preset.as_deref(), Some("hipaa"));
    }

    // ── 37. secure: true ────────────────────────────────────────────────────
    #[test]
    fn test_secure_true() {
        let yaml = "provider: openai\nagent: \"Bot\"\nsecure: true";
        let cfg = parse_shorthand(yaml).unwrap();
        let s = cfg.connector.security.unwrap();
        assert_eq!(s.signing, Some(true));
        assert_eq!(s.scitt, Some(true));
    }

    // ── 38. secure: hipaa ───────────────────────────────────────────────────
    #[test]
    fn test_secure_hipaa() {
        let yaml = "provider: openai\nagent: \"Bot\"\nsecure: hipaa";
        let cfg = parse_shorthand(yaml).unwrap();
        let s = cfg.connector.security.unwrap();
        assert_eq!(s.data_classification.as_deref(), Some("PHI"));
        assert_eq!(s.jurisdiction.as_deref(), Some("US"));
        assert_eq!(s.retention_days, Some(2555));
    }

    // ── 39. secure: gdpr ────────────────────────────────────────────────────
    #[test]
    fn test_secure_gdpr() {
        let yaml = "provider: openai\nagent: \"Bot\"\nsecure: gdpr";
        let cfg = parse_shorthand(yaml).unwrap();
        let s = cfg.connector.security.unwrap();
        assert_eq!(s.data_classification.as_deref(), Some("PII"));
        assert_eq!(s.jurisdiction.as_deref(), Some("EU"));
    }

    // ── 40. retry: 3 ───────────────────────────────────────────────────────
    #[test]
    fn test_retry_shorthand() {
        let yaml = "provider: openai\nagent: \"Bot\"\nretry: 3";
        let cfg = parse_shorthand(yaml).unwrap();
        let r = cfg.connector.router.unwrap();
        assert_eq!(r.retry.unwrap().max_retries, Some(3));
        assert!(r.circuit_breaker.is_some());
    }

    // ── 41. deny/allow policy shorthand ─────────────────────────────────────
    #[test]
    fn test_deny_allow() {
        let yaml = "provider: openai\nagent: \"Bot\"\ndeny: [\"export.*\", \"delete.*\"]\nallow: [\"read.*\"]";
        let cfg = parse_shorthand(yaml).unwrap();
        assert!(cfg.policies.contains_key("auto_policy"));
        let p = cfg.policies.get("auto_policy").unwrap();
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[0].effect, "deny");
        assert_eq!(p.rules[0].action_pattern, "export.*");
        assert_eq!(p.rules[2].effect, "allow");
    }

    // ── 42. FULL SHOWCASE: Hospital ER in shorthand ─────────────────────────
    #[test]
    fn test_full_hospital_shorthand() {
        let yaml = r#"
provider: openai
model: gpt-4o

agents:
  triage: "You are an ER triage nurse. Assess patient symptoms, record vitals, assign urgency level."
  doctor:
    instructions: "You are an ER attending physician. Review triage, diagnose, prescribe treatment."
    tools: [ehr_lookup, lab_order]
  pharmacist: "You are a hospital pharmacist. Verify prescriptions for interactions and dosing."

flow: triage -> doctor -> pharmacist

knowledge:
  - "Aspirin is contraindicated with warfarin due to bleeding risk"
  - "Metformin requires renal function monitoring"
  - file: formulary.csv

tools:
  ehr_lookup: "Query patient electronic health record by MRN"
  lab_order: "Submit lab test order to the laboratory system"

memory: long
budget: "$10.00"
persist: true
trust: medical
observe: medical
think: deep
firewall: hipaa
secure: hipaa
comply: [hipaa]
retry: 3
deny: ["export.*", "delete.*"]
"#;
        let cfg = parse_shorthand(yaml).unwrap();

        // Agents
        assert_eq!(cfg.agents.len(), 3);
        assert!(cfg.agents.contains_key("triage"));
        assert!(cfg.agents.contains_key("doctor"));
        assert!(cfg.agents.contains_key("pharmacist"));

        // Pipeline
        let pipeline = cfg.pipelines.get("main").unwrap();
        assert_eq!(pipeline.actors.len(), 3);

        // Knowledge: 2 facts + 1 file
        let k = cfg.knowledge.unwrap();
        assert_eq!(k.seed.as_ref().unwrap().entities.len(), 2);
        assert_eq!(k.inject.len(), 1);

        // Tools
        assert_eq!(cfg.tools.len(), 2);

        // Memory
        let m = cfg.memory.unwrap();
        assert_eq!(m.eviction_policy.as_deref(), Some("summarize_evict"));

        // Budget applied to all agents
        for agent in cfg.agents.values() {
            assert!(agent.budget.is_some());
            assert_eq!(agent.budget.as_ref().unwrap().max_cost_usd, Some(10.0));
        }

        // Persist
        assert!(cfg.connector.storage.is_some());
        assert!(cfg.connector.checkpoint.is_some());

        // Trust
        assert_eq!(cfg.judgment.unwrap().preset.as_deref(), Some("medical"));

        // Observe
        let p = cfg.perception.unwrap();
        assert_eq!(p.grounding_domain.as_deref(), Some("medical"));
        assert!(p.strict_grounding);

        // Think
        let c = cfg.cognitive.unwrap();
        assert_eq!(c.max_cycles, Some(5));
        assert!(c.contradiction_halt);

        // Firewall
        assert_eq!(cfg.connector.firewall.unwrap().preset.as_deref(), Some("hipaa"));

        // Security
        let sec = cfg.connector.security.unwrap();
        assert_eq!(sec.data_classification.as_deref(), Some("PHI"));

        // Comply
        assert_eq!(cfg.connector.comply, vec!["hipaa"]);

        // Retry
        assert_eq!(cfg.connector.router.unwrap().retry.unwrap().max_retries, Some(3));

        // Policies
        assert!(cfg.policies.contains_key("auto_policy"));
    }
}
