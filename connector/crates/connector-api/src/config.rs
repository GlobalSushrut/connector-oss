//! # Connector Config — YAML-driven, Rust-native, zero-friction setup
//!
//! Loads `connector.yaml` into typed Rust structs via serde.
//! Supports `${ENV_VAR}` interpolation in all string values.
//!
//! ## Quick start
//! ```yaml
//! # connector.yaml
//! connector:
//!   provider: openai
//!   model: gpt-4o
//!   api_key: ${OPENAI_API_KEY}
//! agents:
//!   bot:
//!     instructions: "You are helpful"
//! ```
//! ```rust,ignore
//! let c = Connector::from_config("connector.yaml")?;
//! ```

use std::collections::HashMap;
use serde::Deserialize;
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Config file not found: {path}\n  Fix: create connector.yaml or set CONNECTOR_CONFIG env var\n  Details: {detail}")]
    FileNotFound { path: String, detail: String },

    #[error("Failed to parse config: {0}\n  Check YAML syntax — common issues: wrong indentation, missing quotes around special chars like ':' or '#'")]
    ParseError(String),

    #[error("Missing environment variables referenced in config:\n{0}\n\n  Tip: copy .env.example to .env and fill in the values")]
    MissingEnvVars(String),

    #[error("Config validation error in [{section}]: {message}")]
    ValidationError { section: String, message: String },
}

// ── Top-level ─────────────────────────────────────────────────────────────────

/// Root structure of `connector.yaml`.
///
/// ## Three-tier config design:
/// - **Tier 1 — Mandatory**: `connector.provider`, `connector.model`, `connector.api_key`
///   Must be set (or via env var). Runtime error if absent.
/// - **Tier 2 — Default**: All other `connector.*`, `security`, `firewall`, `behavior`,
///   `checkpoint`, `memory`, `judgment`, `router`. Safe defaults apply — omit freely.
/// - **Tier 3 — Optional-Revoke**: `cluster`, `swarm`, `streaming`, `mcp`, `server`,
///   `perception`, `cognitive`, `tracing_config`. Absent = feature OFF. Present = feature ON.
///   Setting these fields activates the capability; removing them disables it.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct ConnectorConfig {
    // ── Tier 1+2: Core (always present, safe defaults) ──
    #[serde(default)]
    pub connector: GlobalConfig,
    #[serde(default)]
    pub agents: HashMap<String, AgentConfig>,
    #[serde(default)]
    pub pipelines: HashMap<String, PipelineConfig>,
    #[serde(default)]
    pub tools: HashMap<String, ToolConfig>,
    #[serde(default)]
    pub policies: HashMap<String, PolicyConfig>,

    // ── Tier 2: Optional with defaults (omit = defaults apply) ──
    pub knowledge: Option<KnowledgeConfig>,
    pub rag: Option<RagConfig>,
    pub memory: Option<MemoryManagementConfig>,
    pub judgment: Option<JudgmentConfig>,

    // ── Tier 3: Optional-Revoke (absent = feature OFF, present = feature ON) ──
    pub cluster: Option<ClusterConfig>,
    pub swarm: Option<SwarmConfig>,
    pub streaming: Option<StreamingConfig>,
    pub mcp: Option<McpConfig>,
    pub server: Option<ServerConfig>,
    pub perception: Option<PerceptionConfig>,
    pub cognitive: Option<CognitiveConfig>,
    pub tracing_config: Option<TracingConfig>,
    pub observability: Option<ObservabilityConfig>,

    // ── Tier 3: Military-Grade (absent = standard crypto, present = hardened) ──
    pub crypto: Option<CryptoConfig>,
    pub consensus: Option<ConsensusConfig>,
    pub watchdog: Option<WatchdogConfig>,
    pub formal_verify: Option<FormalVerifyConfig>,
    pub negotiation: Option<NegotiationConfig>,
}

// ── Global / connector: ───────────────────────────────────────────────────────

/// Global connector settings — inherited by all agents and pipelines.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct GlobalConfig {
    // ── LLM ──
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub system_prompt: Option<String>,

    // ── Fallbacks ──
    #[serde(default)]
    pub fallbacks: Vec<LlmFallbackConfig>,

    // ── Router ──
    pub router: Option<RouterConfig>,

    // ── Storage ──
    /// Storage URI: sqlite:<path> | memory:// | prolly:<path>
    pub storage: Option<String>,

    // ── Compliance ──
    /// Compliance frameworks to enforce: hipaa | soc2 | gdpr | eu_ai_act | dod
    #[serde(default)]
    pub comply: Vec<String>,

    // ── Sub-configs ──
    pub security: Option<SecurityConfig>,
    pub firewall: Option<FirewallConfig>,
    pub behavior: Option<BehaviorConfig>,
    pub checkpoint: Option<CheckpointConfig>,
}

// ── LLM Fallback ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct LlmFallbackConfig {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
}

// ── Router ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct RouterConfig {
    pub retry: Option<RetryConfig>,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RetryConfig {
    pub max_retries: Option<u32>,
    pub base_delay_ms: Option<u64>,
    pub max_delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: Option<u32>,
    pub cooldown_secs: Option<u64>,
}

// ── Security ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct SecurityConfig {
    /// Enable Ed25519 packet signing
    pub signing: Option<bool>,
    /// Enable SCITT receipt anchoring
    pub scitt: Option<bool>,
    pub key_rotation_days: Option<u64>,
    /// PHI | PII | confidential | internal | public
    pub data_classification: Option<String>,
    /// US | EU | UK | CA | AU
    pub jurisdiction: Option<String>,
    pub retention_days: Option<u64>,
    /// Require MFA for approval-gated tool calls
    pub require_mfa: Option<bool>,
    pub max_delegation_depth: Option<u8>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    /// Audit export format: json | csv | otel
    pub audit_export: Option<String>,
}

impl SecurityConfig {
    pub fn into_api_security(&self) -> crate::security::SecurityConfig {
        use crate::security::{SecurityConfig as ApiSec, SigningAlgorithm};
        ApiSec {
            signing: if self.signing.unwrap_or(false) { Some(SigningAlgorithm::Ed25519) } else { None },
            scitt: self.scitt.unwrap_or(false),
            data_classification: self.data_classification.clone(),
            jurisdiction: self.jurisdiction.clone(),
            retention_days: self.retention_days.unwrap_or(0),
            key_rotation_days: self.key_rotation_days.unwrap_or(0),
            audit_export: self.audit_export.clone(),
            max_delegation_depth: self.max_delegation_depth.unwrap_or(3),
            require_mfa: self.require_mfa.unwrap_or(false),
            ip_allowlist: self.ip_allowlist.clone(),
        }
    }

    pub fn into_dispatcher_security(&self) -> connector_engine::dispatcher::DispatcherSecurity {
        connector_engine::dispatcher::DispatcherSecurity {
            signing_enabled: self.signing.unwrap_or(false),
            scitt: self.scitt.unwrap_or(false),
            require_mfa: self.require_mfa.unwrap_or(false),
            max_delegation_depth: self.max_delegation_depth.unwrap_or(3),
            data_classification: self.data_classification.clone(),
            jurisdiction: self.jurisdiction.clone(),
            retention_days: self.retention_days.unwrap_or(0),
        }
    }
}

// ── Firewall ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct FirewallConfig {
    /// Preset shortcut: "default" | "strict" | "hipaa"
    /// Overrides all individual fields; individual fields then act as overrides on top of preset.
    pub preset: Option<String>,
    pub block_injection: Option<bool>,
    pub injection_threshold: Option<f64>,
    /// PII types to scan: ssn | credit_card | email | phone | dob | medical_record
    #[serde(default)]
    pub pii_types: Vec<String>,
    pub pii_threshold: Option<f64>,
    /// Tool IDs that are always blocked regardless of agent config
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    pub max_calls_per_minute: Option<u32>,
    pub max_input_length: Option<usize>,
    pub weights: Option<SignalWeights>,
    pub thresholds: Option<VerdictThresholds>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignalWeights {
    pub injection: Option<f64>,
    pub pii: Option<f64>,
    pub anomaly: Option<f64>,
    pub policy_violation: Option<f64>,
    pub rate_pressure: Option<f64>,
    pub boundary_crossing: Option<f64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VerdictThresholds {
    pub warn: Option<f64>,
    pub review: Option<f64>,
    pub block: Option<f64>,
}

impl FirewallConfig {
    pub fn into_engine_firewall(&self) -> connector_engine::firewall::FirewallConfig {
        use connector_engine::firewall::FirewallConfig as EngFw;
        let mut base = match self.preset.as_deref() {
            Some("strict") => EngFw::strict(),
            Some("hipaa")  => EngFw::hipaa(),
            _              => EngFw::default(),
        };
        if let Some(v) = self.block_injection       { base.block_injection_by_default = v; }
        if let Some(v) = self.max_calls_per_minute  { base.max_calls_per_minute = v; }
        if let Some(v) = self.max_input_length      { base.max_input_length = v; }
        if !self.blocked_tools.is_empty()           { base.blocked_tools = self.blocked_tools.clone(); }
        if !self.pii_types.is_empty()               { base.pii_types = self.pii_types.iter().cloned().collect(); }
        if let Some(w) = &self.weights {
            if let Some(v) = w.injection         { base.weights.injection = v; }
            if let Some(v) = w.pii               { base.weights.pii = v; }
            if let Some(v) = w.anomaly           { base.weights.anomaly = v; }
            if let Some(v) = w.policy_violation  { base.weights.policy_violation = v; }
            if let Some(v) = w.rate_pressure     { base.weights.rate_pressure = v; }
            if let Some(v) = w.boundary_crossing { base.weights.boundary_crossing = v; }
        }
        if let Some(t) = &self.thresholds {
            if let Some(v) = t.warn   { base.thresholds.warn = v; }
            if let Some(v) = t.review { base.thresholds.review = v; }
            if let Some(v) = t.block  { base.thresholds.block = v; }
        }
        base
    }
}

// ── Behavior ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct BehaviorConfig {
    pub window_ms: Option<i64>,
    pub baseline_sample_size: Option<usize>,
    pub anomaly_threshold: Option<f64>,
    pub max_actions_per_window: Option<u32>,
    pub max_tool_diversity: Option<usize>,
    pub max_error_rate: Option<f64>,
    pub max_data_volume: Option<u64>,
    pub detect_contamination: Option<bool>,
}

impl BehaviorConfig {
    pub fn into_engine_behavior(&self) -> connector_engine::behavior::BehaviorConfig {
        use connector_engine::behavior::BehaviorConfig as EngBh;
        let d = EngBh::default();
        EngBh {
            window_ms:              self.window_ms.unwrap_or(d.window_ms),
            baseline_sample_size:   self.baseline_sample_size.unwrap_or(d.baseline_sample_size),
            anomaly_threshold:      self.anomaly_threshold.unwrap_or(d.anomaly_threshold),
            max_actions_per_window: self.max_actions_per_window.unwrap_or(d.max_actions_per_window),
            max_tool_diversity:     self.max_tool_diversity.unwrap_or(d.max_tool_diversity),
            max_error_rate:         self.max_error_rate.unwrap_or(d.max_error_rate),
            max_data_volume:        self.max_data_volume.unwrap_or(d.max_data_volume),
            detect_contamination:   self.detect_contamination.unwrap_or(d.detect_contamination),
        }
    }
}

// ── Checkpoint ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct CheckpointConfig {
    pub write_through: Option<bool>,
    pub wal_enabled: Option<bool>,
    pub auto_checkpoint_threshold: Option<usize>,
}

impl CheckpointConfig {
    pub fn into_engine_checkpoint(&self) -> connector_engine::checkpoint::CheckpointConfig {
        use connector_engine::checkpoint::CheckpointConfig as EngCp;
        let d = EngCp::default();
        EngCp {
            write_through:             self.write_through.unwrap_or(d.write_through),
            wal_enabled:               self.wal_enabled.unwrap_or(d.wal_enabled),
            auto_checkpoint_threshold: self.auto_checkpoint_threshold.unwrap_or(d.auto_checkpoint_threshold),
        }
    }
}

// ── Agent ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AgentConfig {
    #[serde(default)]
    pub instructions: String,
    /// executor | reviewer | auditor | reader | writer | admin
    pub role: Option<String>,
    /// Tool IDs this agent is allowed to use (must be defined in tools:)
    #[serde(default)]
    pub tools: Vec<String>,
    /// Tool IDs explicitly denied for this agent
    #[serde(default)]
    pub deny_tools: Vec<String>,
    /// Data classifications this agent can access
    #[serde(default)]
    pub allow_data: Vec<String>,
    /// Data classifications this agent cannot access
    #[serde(default)]
    pub deny_data: Vec<String>,
    /// Tool IDs that require human approval before execution
    #[serde(default)]
    pub require_approval: Vec<String>,
    /// Compliance frameworks for this agent (inherits from connector: if not set)
    #[serde(default)]
    pub comply: Vec<String>,
    pub budget: Option<BudgetConfig>,
    /// Max calls per minute for this agent
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub output_guards: Vec<OutputGuardConfig>,
    /// Agent-level security overrides (inherits from connector.security if not set)
    pub security: Option<SecurityConfig>,
    pub llm: Option<LlmFallbackConfig>,
    /// Contract: SLA, escrow, capabilities, pricing
    pub contract: Option<ContractConfig>,
    /// MAC clearance level: public | internal | confidential | secret | top_secret
    pub clearance: Option<ClearanceConfig>,
    /// Watchdog rules specific to this agent
    pub watchdog: Option<WatchdogConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BudgetConfig {
    pub max_tokens: Option<u64>,
    pub max_cost_usd: Option<f64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutputGuardConfig {
    pub name: String,
    /// Regex pattern to match against output
    pub pattern: String,
    /// If true, block when pattern matches; if false, block when it doesn't
    #[serde(default)]
    pub negate: bool,
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PipelineConfig {
    #[serde(default)]
    pub actors: Vec<ActorConfig>,
    /// Flow expression: "intake -> diagnosis -> treatment"
    pub flow: Option<String>,
    #[serde(default)]
    pub comply: Vec<String>,
    pub hipaa: Option<HipaaConfig>,
    pub gdpr: Option<GdprConfig>,
    pub security: Option<SecurityConfig>,
    pub budget: Option<BudgetConfig>,
    pub rate_limit: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ActorConfig {
    pub name: String,
    pub instructions: String,
    pub role: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub deny_tools: Vec<String>,
    #[serde(default)]
    pub allow_data: Vec<String>,
    #[serde(default)]
    pub deny_data: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
    /// Namespaces this actor can read memory from
    #[serde(default)]
    pub memory_from: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HipaaConfig {
    pub jurisdiction: Option<String>,
    pub retention_days: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GdprConfig {
    pub retention_days: Option<u64>,
    pub dsar_enabled: Option<bool>,
}

// ── Tools ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct ToolConfig {
    pub description: String,
    /// Resource URI pattern: ehr://patients/* | system://shell
    pub resource: Option<String>,
    /// Allowed actions: read | write | execute | delete
    #[serde(default)]
    pub actions: Vec<String>,
    /// PHI | PII | confidential | internal | public
    pub data_classification: Option<String>,
    /// Whether this tool always requires human approval
    #[serde(default)]
    pub requires_approval: bool,
    pub timeout_ms: Option<u64>,
    /// If true, firewall blocks this tool regardless of agent config
    #[serde(default)]
    pub blocked: bool,
}

// ── Knowledge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default, Clone)]
pub struct KnowledgeConfig {
    /// Static entities and edges to seed at startup
    pub seed: Option<KnowledgeSeed>,
    /// External data sources to inject into the knowledge graph
    #[serde(default)]
    pub inject: Vec<DataInjectionConfig>,
    /// Grounding tables for claim verification
    #[serde(default)]
    pub grounding: Vec<GroundingConfig>,
    /// Compile knowledge graph to summaries at startup
    #[serde(default)]
    pub compile_on_startup: bool,
    pub max_compiled_summaries: Option<usize>,
    /// Alert when contradicting facts are detected
    #[serde(default)]
    pub contradiction_check: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KnowledgeSeed {
    #[serde(default)]
    pub entities: Vec<SeedEntity>,
    #[serde(default)]
    pub edges: Vec<SeedEdge>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SeedEntity {
    pub id: String,
    #[serde(rename = "type")]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attrs: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SeedEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub weight: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DataInjectionConfig {
    /// Source URI: file:./path.json | https://api.example.com/data
    pub source: String,
    /// Format: json | jsonl | csv
    pub format: String,
    pub entity_type: Option<String>,
    pub id_field: Option<String>,
    #[serde(default)]
    pub tag_fields: Vec<String>,
    /// Authorization header value for HTTP sources (use ${ENV_VAR})
    pub auth_header: Option<String>,
    /// Re-fetch interval in hours (0 or absent = once at startup only)
    pub refresh_interval_hours: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GroundingConfig {
    pub source: String,
    pub format: String,
}

// ── RAG ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct RagConfig {
    /// Auto-retrieve relevant knowledge during run() (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Max tokens of retrieved context to inject into prompt
    pub budget: Option<usize>,
    /// Max number of facts to retrieve per query
    pub max_facts: Option<usize>,
    /// Minimum relevance score 0.0–1.0 (default: 0.3)
    pub min_relevance: Option<f64>,
    /// Retrieval strategy: keyword | semantic | hybrid (default: hybrid)
    pub strategy: Option<String>,
    /// Namespaces to retrieve from (empty = all accessible)
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// Source priority: knowledge_graph | memory | shared_memory
    #[serde(default)]
    pub sources: Vec<String>,
}

impl Default for RagConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            budget: None,
            max_facts: None,
            min_relevance: None,
            strategy: None,
            namespaces: vec![],
            sources: vec![],
        }
    }
}

fn default_true() -> bool { true }

// ── AAPI Policies ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyRule {
    /// allow | deny | require_approval
    pub effect: String,
    /// Glob pattern for action names: "export.*" | "delete.*" | "*"
    pub action_pattern: String,
    /// Glob pattern for resource names
    pub resource_pattern: Option<String>,
    /// Roles this rule applies to (empty = all roles)
    #[serde(default)]
    pub roles: Vec<String>,
    /// Higher priority rules are evaluated first
    #[serde(default)]
    pub priority: i32,
}

// ── Memory Management (Tier 2 — default) ─────────────────────────────────────

/// Kernel memory tuning. Omit entirely to use safe defaults.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct MemoryManagementConfig {
    /// Max packets stored per agent namespace before eviction triggers
    pub max_packets_per_agent: Option<usize>,
    /// Eviction policy: lru | fifo | ttl | priority | summarize_evict | never
    pub eviction_policy: Option<String>,
    /// Hot-tier packet limit (in-flight working memory)
    pub hot_tier_limit: Option<usize>,
    /// Warm-tier packet limit (recent episodic memory)
    pub warm_tier_limit: Option<usize>,
    /// Cold-tier packet limit (long-term semantic memory)
    pub cold_tier_limit: Option<usize>,
    /// Garbage collection interval in seconds
    pub gc_interval_secs: Option<u64>,
    /// Session TTL in seconds (0 = never expire)
    pub session_ttl_secs: Option<u64>,
    /// Enable recursive summarization when context window fills
    #[serde(default)]
    pub compression_enabled: bool,
    /// Token count that triggers compression
    pub compression_threshold_tokens: Option<usize>,
    /// Max tokens in active context window per agent
    pub context_window_tokens: Option<usize>,
    /// Enable memory sealing (immutable after seal — tamper-evident)
    #[serde(default)]
    pub seal_on_session_close: bool,
}

// ── Judgment / Trust Scoring (Tier 2 — default) ───────────────────────────────

/// Trust scoring configuration. Omit to use defaults.
/// Preset shortcuts: "default" | "medical" | "legal" | "financial"
#[derive(Debug, Deserialize, Default, Clone)]
pub struct JudgmentConfig {
    /// Preset: default | medical | legal | financial
    pub preset: Option<String>,
    /// Temporal decay half-life in milliseconds (default: 3,600,000 = 1 hour)
    pub decay_half_life_ms: Option<f64>,
    /// Minimum kernel operations before scoring is meaningful
    pub min_operations: Option<usize>,
    /// Per-dimension weights (8 dimensions, all default to 1.0)
    pub weights: Option<JudgmentWeights>,
    /// Minimum trust score to allow agent to proceed (0-100, default: 0 = no gate)
    pub min_trust_gate: Option<u32>,
}

/// Weights for the 8 trust scoring dimensions.
#[derive(Debug, Deserialize, Clone)]
pub struct JudgmentWeights {
    pub cid_integrity: Option<f64>,
    pub audit_coverage: Option<f64>,
    pub access_control: Option<f64>,
    pub evidence_quality: Option<f64>,
    pub claim_coverage: Option<f64>,
    pub temporal_freshness: Option<f64>,
    pub contradiction_score: Option<f64>,
    pub source_credibility: Option<f64>,
}

// ── Cluster / Distribution (Tier 3 — optional-revoke) ────────────────────────

/// Multi-node deployment. Absent = standalone single-node (default).
/// Present = cluster mode activated.
#[derive(Debug, Deserialize, Clone)]
pub struct ClusterConfig {
    /// standalone | cluster | federated
    #[serde(default = "default_standalone")]
    pub mode: String,
    /// Unique ID for this node (use ${NODE_ID} for env-var injection)
    pub node_id: Option<String>,
    /// Peer node addresses for cluster mode
    #[serde(default)]
    pub peers: Vec<String>,
    /// Number of replicas for each memory namespace (default: 1)
    pub replication_factor: Option<u8>,
    /// Consensus protocol: raft | gossip (default: raft)
    pub consensus: Option<String>,
    /// Partition strategy: consistent_hash | range (default: consistent_hash)
    pub partition_strategy: Option<String>,
    /// Max nodes in the cluster
    pub max_nodes: Option<u16>,
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: Option<u64>,
    /// Election timeout in milliseconds (raft)
    pub election_timeout_ms: Option<u64>,
    /// Replication bus URI: nats://... | redis://... | grpc://...
    pub replication_bus: Option<String>,
    /// Enable cross-cell SCITT attestation exchange
    #[serde(default)]
    pub scitt_federation: bool,
}

fn default_standalone() -> String { "standalone".to_string() }

// ── Swarm / Multi-Agent Fleet (Tier 3 — optional-revoke) ─────────────────────

/// Agent fleet management. Absent = single-agent mode.
/// Present = swarm/fleet mode activated.
#[derive(Debug, Deserialize, Clone)]
pub struct SwarmConfig {
    /// Max agents running concurrently across the fleet
    pub max_concurrent_agents: Option<u32>,
    /// Pre-warmed agent pool size (0 = on-demand only)
    pub agent_pool_size: Option<u32>,
    /// Spawn strategy: on_demand | pre_warm | fixed
    pub spawn_strategy: Option<String>,
    /// Timeout for agent-to-agent handoff in milliseconds
    pub handoff_timeout_ms: Option<u64>,
    /// Enable agent-to-agent (A2A) direct communication
    #[serde(default)]
    pub a2a_enabled: bool,
    /// A2A protocol: direct | bus | mcp (default: direct)
    pub a2a_protocol: Option<String>,
    /// Max hops for A2A delegation chains
    pub max_delegation_hops: Option<u8>,
    /// Enable automatic load balancing across agent pool
    #[serde(default)]
    pub load_balance: bool,
    /// Load balancing strategy: round_robin | least_loaded | consistent_hash
    pub load_balance_strategy: Option<String>,
    /// Enable saga-style rollback across multi-agent pipelines
    #[serde(default)]
    pub saga_rollback: bool,
    /// Max pipeline steps before saga coordinator intervenes
    pub max_pipeline_steps: Option<u32>,
}

// ── Streaming (Tier 3 — optional-revoke) ─────────────────────────────────────

/// Real-time streaming output. Absent = batch mode (default).
/// Present = streaming activated.
#[derive(Debug, Deserialize, Clone)]
pub struct StreamingConfig {
    /// Streaming protocol: sse | websocket | grpc
    #[serde(default = "default_sse")]
    pub protocol: String,
    /// Tokens per chunk (default: 10)
    pub chunk_size_tokens: Option<u32>,
    /// Heartbeat ping interval in milliseconds
    pub heartbeat_interval_ms: Option<u64>,
    /// Max concurrent streaming connections
    pub max_connections: Option<u32>,
    /// Buffer size in chunks before backpressure kicks in
    pub buffer_chunks: Option<u32>,
    /// Include kernel audit events in the stream
    #[serde(default)]
    pub include_audit_events: bool,
    /// Include trust score updates in the stream
    #[serde(default)]
    pub include_trust_updates: bool,
}

fn default_sse() -> String { "sse".to_string() }

// ── MCP — Model Context Protocol (Tier 3 — optional-revoke) ──────────────────

/// MCP server/client integration. Absent = MCP disabled.
/// Present = MCP activated.
#[derive(Debug, Deserialize, Clone)]
pub struct McpConfig {
    /// server | client | both
    #[serde(default = "default_server")]
    pub mode: String,
    /// Port for MCP server (default: 8090)
    pub server_port: Option<u16>,
    /// Host for MCP server (default: 127.0.0.1)
    pub server_host: Option<String>,
    /// Remote MCP server endpoints (for client mode)
    #[serde(default)]
    pub client_endpoints: Vec<String>,
    /// Tool discovery: auto | manual (auto = expose all registered tools)
    pub tool_discovery: Option<String>,
    /// Auth token for MCP server (use ${MCP_TOKEN})
    pub auth_token: Option<String>,
    /// Enable MCP resource subscriptions
    #[serde(default)]
    pub resource_subscriptions: bool,
    /// Max concurrent MCP sessions
    pub max_sessions: Option<u32>,
    /// Session timeout in seconds
    pub session_timeout_secs: Option<u64>,
}

fn default_server() -> String { "server".to_string() }

// ── Server / HTTP API (Tier 3 — optional-revoke) ─────────────────────────────

/// HTTP API server config. Absent = no HTTP server started.
/// Present = connector-server activated on the specified port.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Bind host (default: 0.0.0.0)
    pub host: Option<String>,
    /// Bind port (default: 8080)
    pub port: Option<u16>,
    /// CORS allowed origins (default: ["*"])
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Request timeout in seconds
    pub request_timeout_secs: Option<u64>,
    /// Max request body size in bytes
    pub max_request_size_bytes: Option<usize>,
    /// Enable Prometheus metrics endpoint at /metrics
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
    /// Enable health check endpoint at /health
    #[serde(default = "default_true")]
    pub health_enabled: bool,
    /// TLS config (absent = plain HTTP)
    pub tls: Option<TlsConfig>,
    /// API key required for all requests (use ${SERVER_API_KEY})
    pub api_key: Option<String>,
    /// Rate limit: max requests per second per IP
    pub rate_limit_rps: Option<u32>,
}

/// TLS configuration — activates HTTPS when present.
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate file (use ${TLS_CERT_PATH})
    pub cert_file: String,
    /// Path to TLS private key file (use ${TLS_KEY_PATH})
    pub key_file: String,
    /// Minimum TLS version: 1.2 | 1.3 (default: 1.2)
    pub min_version: Option<String>,
}

// ── Perception / Claims (Tier 3 — optional-revoke) ───────────────────────────

/// Observation pipeline config. Absent = basic memory write only.
/// Present = full perception pipeline (entity extraction, claim verification).
#[derive(Debug, Deserialize, Clone)]
pub struct PerceptionConfig {
    /// Extract entities from every input automatically
    #[serde(default)]
    pub extract_entities: bool,
    /// Extract and track claims from LLM outputs
    #[serde(default)]
    pub extract_claims: bool,
    /// Verify extracted claims against source CIDs
    #[serde(default)]
    pub verify_claims: bool,
    /// Max entities to extract per observation
    pub max_entities: Option<usize>,
    /// Minimum quality score (0-100) to accept an observation
    pub quality_threshold: Option<u32>,
    /// Block observations below quality threshold
    #[serde(default)]
    pub block_low_quality: bool,
    /// Grounding domain: medical | legal | financial | custom
    pub grounding_domain: Option<String>,
    /// Strict grounding: block ungrounded claims (false = warn only)
    #[serde(default)]
    pub strict_grounding: bool,
}

// ── Cognitive Loop / Binding Engine (Tier 3 — optional-revoke) ───────────────

/// Cognitive loop (observe→think→act cycle) config. Absent = single-pass mode.
/// Present = full multi-cycle cognitive loop activated.
#[derive(Debug, Deserialize, Clone)]
pub struct CognitiveConfig {
    /// Max cognitive cycles per agent invocation (default: 1)
    pub max_cycles: Option<u32>,
    /// Enable reflection phase (evaluate reasoning quality after each cycle)
    #[serde(default)]
    pub reflection_enabled: bool,
    /// Compile knowledge graph after each cognitive cycle
    #[serde(default)]
    pub compile_knowledge_after_cycle: bool,
    /// Halt the cycle if a contradiction is detected
    #[serde(default)]
    pub contradiction_halt: bool,
    /// Enable multi-step reasoning chains (chain-of-thought)
    #[serde(default)]
    pub chain_of_thought: bool,
    /// Max reasoning steps per cycle
    pub max_reasoning_steps: Option<u32>,
    /// Min quality score to proceed to next cycle (0-100)
    pub min_cycle_quality: Option<u32>,
}

// ── Tracing / Spans (Tier 3 — optional-revoke) ───────────────────────────────

/// Distributed tracing config. Absent = no span export.
/// Present = span export activated.
#[derive(Debug, Deserialize, Clone)]
pub struct TracingConfig {
    /// Export spans in OTel format
    #[serde(default = "default_true")]
    pub otel_format: bool,
    /// Include low-level kernel spans (memory read/write/gc)
    #[serde(default)]
    pub include_kernel_spans: bool,
    /// Include LLM generation spans
    #[serde(default = "default_true")]
    pub include_llm_spans: bool,
    /// Include tool call spans
    #[serde(default = "default_true")]
    pub include_tool_spans: bool,
    /// Max spans per trace (prevents runaway traces)
    pub max_spans_per_trace: Option<usize>,
    /// Sampling rate 0.0–1.0 (1.0 = trace everything)
    pub sampling_rate: Option<f64>,
    /// OTel collector endpoint (use ${OTEL_EXPORTER_OTLP_ENDPOINT})
    pub otel_endpoint: Option<String>,
    /// OTel export protocol: grpc | http/protobuf | http/json
    pub otel_protocol: Option<String>,
}

// ── Observability (Tier 3 — optional-revoke) ─────────────────────────────────

/// Unified observability config (metrics + logs + traces export).
/// Absent = local logging only. Present = full observability pipeline.
#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    /// Service name in OTel resource attributes
    pub service_name: Option<String>,
    /// Service version
    pub service_version: Option<String>,
    /// Deployment environment: production | staging | development
    pub environment: Option<String>,
    /// OTel collector endpoint (use ${OTEL_EXPORTER_OTLP_ENDPOINT})
    pub otel_endpoint: Option<String>,
    /// OTel protocol: grpc | http (default: grpc)
    pub otel_protocol: Option<String>,
    /// Trace sampling rate 0.0–1.0
    pub trace_sampling_rate: Option<f64>,
    /// Enable Prometheus metrics export
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
    /// Metrics export interval in seconds
    pub metrics_interval_secs: Option<u64>,
    /// Log level: trace | debug | info | warn | error (default: info)
    pub log_level: Option<String>,
    /// Log format: json | text (default: json in prod, text in dev)
    pub log_format: Option<String>,
    /// Enable structured log export to OTel
    #[serde(default)]
    pub log_export: bool,
    /// Additional resource attributes (key-value pairs)
    #[serde(default)]
    pub resource_attrs: HashMap<String, String>,
}

// ── Contracts / SLA / Economy ─────────────────────────────────────────────────

/// Agent service contracts — SLA, escrow, capabilities, pricing.
/// Defined per-agent or at pipeline level.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct ContractConfig {
    /// SLA constraints for this agent
    pub sla: Option<SlaConfig>,
    /// Escrow for trustless payment
    pub escrow: Option<EscrowConfig>,
    /// Capabilities this agent provides
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Capabilities this agent is denied
    #[serde(default)]
    pub deny_capabilities: Vec<String>,
    /// Pricing model: free | per_call | per_token | subscription
    pub pricing: Option<String>,
    /// Price per unit (interpretation depends on pricing model)
    pub price_per_unit: Option<f64>,
    /// Currency: credits | usd | tokens
    pub currency: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SlaConfig {
    /// Max latency in milliseconds
    pub max_latency_ms: Option<u64>,
    /// Required uptime percentage (e.g., 99.9)
    pub uptime_pct: Option<f64>,
    /// Max error rate as percentage
    pub max_error_rate: Option<f64>,
    /// Max retries before SLA breach
    pub max_retries: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EscrowConfig {
    /// Amount to lock in escrow
    pub amount: Option<u64>,
    /// Currency: credits | usd
    pub currency: Option<String>,
    /// Auto-release after successful completion
    #[serde(default = "default_true")]
    pub auto_release: bool,
    /// Slash on failure
    #[serde(default)]
    pub slash_on_failure: bool,
    /// Dispute window in milliseconds
    pub dispute_window_ms: Option<i64>,
}

/// Negotiation config for multi-agent economy
#[derive(Debug, Deserialize, Default, Clone)]
pub struct NegotiationConfig {
    /// Max negotiation rounds before timeout
    pub max_rounds: Option<u32>,
    /// TTL for negotiation sessions in milliseconds
    pub ttl_ms: Option<i64>,
    /// Auto-accept if price is below threshold
    pub auto_accept_below: Option<f64>,
}

// ── Crypto / Military-Grade (Tier 3 — optional-revoke) ───────────────────────

/// Cryptographic hardening config. Absent = standard crypto (Ed25519 + AES-256-GCM).
/// Present = military-grade crypto activated.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct CryptoConfig {
    /// Enable FIPS 140-3 crypto module (uses NIST-approved algorithms only)
    #[serde(default)]
    pub fips: bool,
    /// Enable post-quantum cryptography (ML-DSA-65 hybrid signatures)
    #[serde(default)]
    pub post_quantum: bool,
    /// Enable Noise_IK encrypted channels for inter-agent communication
    #[serde(default)]
    pub noise_channels: bool,
    /// Enable encryption at rest (AES-256-GCM) for all stored packets
    #[serde(default)]
    pub encryption_at_rest: bool,
    /// Encryption key (use ${ENCRYPTION_KEY} — 32 bytes hex-encoded)
    pub encryption_key: Option<String>,
    /// HMAC audit chain (tamper-evident audit log)
    #[serde(default)]
    pub hmac_audit_chain: bool,
}

// ── Consensus / BFT (Tier 3 — optional-revoke) ──────────────────────────────

/// Byzantine fault tolerance consensus. Absent = no BFT.
/// Present = BFT consensus activated for multi-cell coordination.
#[derive(Debug, Deserialize, Clone)]
pub struct ConsensusConfig {
    /// Consensus type: bft | raft (default: bft)
    #[serde(default = "default_bft")]
    pub r#type: String,
    /// Validator cell IDs
    #[serde(default)]
    pub validators: Vec<String>,
    /// Proposal timeout in milliseconds
    pub proposal_timeout_ms: Option<u64>,
    /// Enable formal verification of consensus state
    #[serde(default)]
    pub formal_verify: bool,
}

fn default_bft() -> String { "bft".to_string() }

// ── Watchdog (Tier 3 — optional-revoke) ──────────────────────────────────────

/// System watchdog rules. Absent = default watchdog (threat + budget rules).
/// Present = custom watchdog configuration.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct WatchdogConfig {
    /// Use default watchdog rules (ThreatScoreElevated, TokenBudgetExhausted)
    #[serde(default = "default_true")]
    pub defaults: bool,
    /// Custom watchdog rules
    #[serde(default)]
    pub rules: Vec<WatchdogRuleConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WatchdogRuleConfig {
    /// Rule name (for logging)
    pub name: String,
    /// Condition: cell_heartbeat_missed | agent_error_rate_high | token_budget_exhausted
    ///          | memory_quota_exceeded | cluster_partition | trust_score_low | threat_elevated
    pub condition: String,
    /// Action: restart_agent | suspend_agent | evict_to_tier | trigger_sync
    ///       | send_signal | notify_human | execute_vakya
    pub action: String,
    /// Cooldown between triggers in milliseconds
    pub cooldown_ms: Option<i64>,
    /// Agent pattern (* = all agents)
    pub agent_pattern: Option<String>,
}

// ── Agent Clearance (MAC security levels) ────────────────────────────────────

/// Mandatory Access Control clearance levels for agents.
/// Maps to Bell-LaPadula (confidentiality) + Biba (integrity) in the kernel.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct ClearanceConfig {
    /// Confidentiality level: public | internal | confidential | secret | top_secret
    pub level: Option<String>,
    /// Integrity level: low | medium | high | critical
    pub integrity: Option<String>,
    /// Guard mode: mac | rbac | none (default: mac)
    pub guard: Option<String>,
}

// ── Formal Verification (Tier 3 — optional-revoke) ──────────────────────────

/// Runtime formal verification. Absent = no verification.
/// Present = invariant checking activated.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct FormalVerifyConfig {
    /// Enable runtime invariant checking
    #[serde(default)]
    pub enabled: bool,
    /// Check lifecycle invariants (agent state transitions)
    #[serde(default = "default_true")]
    pub lifecycle: bool,
    /// Check namespace isolation invariants
    #[serde(default = "default_true")]
    pub namespace_isolation: bool,
    /// Check budget invariants (no overspend)
    #[serde(default = "default_true")]
    pub budget: bool,
    /// Check audit completeness (every op has audit entry)
    #[serde(default = "default_true")]
    pub audit_completeness: bool,
}

// ── Env-var interpolation ─────────────────────────────────────────────────────

/// Replace all `${VAR_NAME}` occurrences with environment variable values.
/// Collects ALL missing variables and reports them together in one error.
pub fn interpolate_env_vars(input: &str) -> Result<String, ConfigError> {
    let mut result = input.to_string();
    let mut missing: Vec<String> = Vec::new();
    let mut search = input;

    while let Some(start) = search.find("${") {
        let rest = &search[start + 2..];
        if let Some(end) = rest.find('}') {
            let var_name = &rest[..end];
            match std::env::var(var_name) {
                Ok(val) => {
                    result = result.replace(&format!("${{{}}}", var_name), &val);
                }
                Err(_) => {
                    if !missing.iter().any(|m: &String| m.contains(var_name)) {
                        missing.push(format!(
                            "  ${{{var_name}}} is not set.\n  Fix: export {var_name}=<your-value>"
                        ));
                    }
                }
            }
            search = &rest[end + 1..];
        } else {
            break;
        }
    }

    if !missing.is_empty() {
        return Err(ConfigError::MissingEnvVars(missing.join("\n\n")));
    }
    Ok(result)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load a `connector.yaml` file, interpolate `${ENV_VAR}`, and deserialize.
///
/// # Errors
/// - [`ConfigError::FileNotFound`] — file does not exist
/// - [`ConfigError::MissingEnvVars`] — one or more `${VAR}` not set in environment
/// - [`ConfigError::ParseError`] — invalid YAML syntax or type mismatch
pub fn load_config(path: &str) -> Result<ConnectorConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::FileNotFound {
        path: path.to_string(),
        detail: e.to_string(),
    })?;
    let interpolated = interpolate_env_vars(&raw)?;
    serde_yaml::from_str(&interpolated).map_err(|e| ConfigError::ParseError(e.to_string()))
}

/// Parse a YAML string directly — useful for tests and in-memory configs.
pub fn load_config_str(yaml: &str) -> Result<ConnectorConfig, ConfigError> {
    let interpolated = interpolate_env_vars(yaml)?;
    serde_yaml::from_str(&interpolated).map_err(|e| ConfigError::ParseError(e.to_string()))
}
