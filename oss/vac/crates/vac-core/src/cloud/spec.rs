//! Declarative Agent Specifications
//!
//! Kubernetes-style declarative specs for agents, following the K8s API conventions.
//!
//! # Example YAML (what users write)
//!
//! ```yaml
//! apiVersion: connector.io/v1
//! kind: AgentDeployment
//! metadata:
//!   name: triage-bot
//!   namespace: hospital
//!   labels:
//!     app: triage
//!     tier: frontend
//! spec:
//!   replicas: 5
//!   selector:
//!     matchLabels:
//!       app: triage
//!   template:
//!     metadata:
//!       labels:
//!         app: triage
//!     spec:
//!       model: gpt-4
//!       framework: langchain
//!       resources:
//!         limits:
//!           memory: 128Mi
//!           tokens-daily: 100000
//!           cost-daily-usd: 10.0
//!         requests:
//!           memory: 64Mi
//!           tokens-daily: 10000
//!   strategy:
//!     type: RollingUpdate
//!     rollingUpdate:
//!       maxUnavailable: 1
//!       maxSurge: 2
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════
// Object Metadata (K8s-compatible)
// ═══════════════════════════════════════════════════════════════════════

/// Standard object metadata (matches K8s ObjectMeta)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Object name (unique within namespace)
    pub name: String,
    /// Namespace (default: "default")
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Labels for selection and grouping
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Annotations for non-identifying metadata
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Unique identifier (set by system)
    #[serde(default)]
    pub uid: String,
    /// Resource version for optimistic concurrency
    #[serde(default)]
    pub resource_version: String,
    /// Generation number (incremented on spec change)
    #[serde(default)]
    pub generation: i64,
    /// Creation timestamp (ms epoch)
    #[serde(default)]
    pub creation_timestamp: i64,
    /// Deletion timestamp (set when delete requested)
    #[serde(default)]
    pub deletion_timestamp: Option<i64>,
    /// Finalizers that must complete before deletion
    #[serde(default)]
    pub finalizers: Vec<String>,
    /// Owner references for garbage collection
    #[serde(default)]
    pub owner_references: Vec<OwnerReference>,
}

fn default_namespace() -> String {
    "default".to_string()
}

/// Owner reference for garbage collection (like K8s)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default)]
    pub controller: bool,
    #[serde(default)]
    pub block_owner_deletion: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Resource Requirements (K8s-compatible)
// ═══════════════════════════════════════════════════════════════════════

/// Resource requirements for an agent (like K8s ResourceRequirements)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Maximum resources the agent can use
    #[serde(default)]
    pub limits: ResourceLimits,
    /// Minimum resources guaranteed to the agent
    #[serde(default)]
    pub requests: ResourceLimits,
}

/// Resource limits/requests
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResourceLimits {
    /// Memory limit in bytes (e.g., "128Mi" = 134217728)
    #[serde(default)]
    pub memory_bytes: u64,
    /// Maximum packets stored
    #[serde(default)]
    pub max_packets: u64,
    /// Daily token limit
    #[serde(default)]
    pub tokens_daily: u64,
    /// Hourly token limit
    #[serde(default)]
    pub tokens_hourly: u64,
    /// Daily cost limit in USD
    #[serde(default)]
    pub cost_daily_usd: f64,
    /// Operations per second limit
    #[serde(default)]
    pub ops_per_second: u32,
    /// Operations per minute limit
    #[serde(default)]
    pub ops_per_minute: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 100 * 1024 * 1024, // 100MB
            max_packets: 10_000,
            tokens_daily: 1_000_000,
            tokens_hourly: 100_000,
            cost_daily_usd: 100.0,
            ops_per_second: 100,
            ops_per_minute: 3000,
        }
    }
}

impl ResourceLimits {
    /// Parse K8s-style memory string (e.g., "128Mi", "1Gi")
    pub fn parse_memory(s: &str) -> Result<u64, String> {
        let s = s.trim();
        if s.ends_with("Ki") {
            s[..s.len()-2].parse::<u64>().map(|v| v * 1024)
                .map_err(|e| e.to_string())
        } else if s.ends_with("Mi") {
            s[..s.len()-2].parse::<u64>().map(|v| v * 1024 * 1024)
                .map_err(|e| e.to_string())
        } else if s.ends_with("Gi") {
            s[..s.len()-2].parse::<u64>().map(|v| v * 1024 * 1024 * 1024)
                .map_err(|e| e.to_string())
        } else if s.ends_with("Ti") {
            s[..s.len()-2].parse::<u64>().map(|v| v * 1024 * 1024 * 1024 * 1024)
                .map_err(|e| e.to_string())
        } else {
            s.parse::<u64>().map_err(|e| e.to_string())
        }
    }

    /// Format memory as K8s-style string
    pub fn format_memory(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 * 1024 {
            format!("{}Ti", bytes / (1024 * 1024 * 1024 * 1024))
        } else if bytes >= 1024 * 1024 * 1024 {
            format!("{}Gi", bytes / (1024 * 1024 * 1024))
        } else if bytes >= 1024 * 1024 {
            format!("{}Mi", bytes / (1024 * 1024))
        } else if bytes >= 1024 {
            format!("{}Ki", bytes / 1024)
        } else {
            format!("{}", bytes)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Agent Spec (like PodSpec)
// ═══════════════════════════════════════════════════════════════════════

/// Agent specification (like K8s PodSpec)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSpec {
    /// LLM model to use (e.g., "gpt-4", "claude-3")
    #[serde(default)]
    pub model: Option<String>,
    /// Agent framework (e.g., "langchain", "autogen")
    #[serde(default)]
    pub framework: Option<String>,
    /// Agent role (e.g., "reader", "writer", "admin")
    #[serde(default)]
    pub role: Option<String>,
    /// Resource requirements
    #[serde(default)]
    pub resources: ResourceRequirements,
    /// Tools the agent can use
    #[serde(default)]
    pub tools: Vec<String>,
    /// Capabilities required
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Restart policy
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// Termination grace period (seconds)
    #[serde(default = "default_grace_period")]
    pub termination_grace_period_seconds: u32,
    /// Node selector for cell affinity
    #[serde(default)]
    pub node_selector: HashMap<String, String>,
    /// Tolerations for cell taints
    #[serde(default)]
    pub tolerations: Vec<Toleration>,
    /// Affinity rules
    #[serde(default)]
    pub affinity: Option<Affinity>,
    /// Priority class name
    #[serde(default)]
    pub priority_class_name: Option<String>,
    /// Service account name
    #[serde(default)]
    pub service_account_name: Option<String>,
    /// Security context
    #[serde(default)]
    pub security_context: Option<SecurityContext>,
    /// Liveness probe
    #[serde(default)]
    pub liveness_probe: Option<Probe>,
    /// Readiness probe
    #[serde(default)]
    pub readiness_probe: Option<Probe>,
    /// Startup probe
    #[serde(default)]
    pub startup_probe: Option<Probe>,
}

fn default_grace_period() -> u32 { 30 }

/// Environment variable
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value_from: Option<EnvVarSource>,
}

/// Environment variable source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvVarSource {
    #[serde(default)]
    pub secret_key_ref: Option<SecretKeySelector>,
    #[serde(default)]
    pub config_map_key_ref: Option<ConfigMapKeySelector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeySelector {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapKeySelector {
    pub name: String,
    pub key: String,
}

/// Restart policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RestartPolicy {
    #[default]
    Always,
    OnFailure,
    Never,
}

/// Toleration for cell taints
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Toleration {
    pub key: Option<String>,
    pub operator: Option<TolerationOperator>,
    pub value: Option<String>,
    pub effect: Option<TaintEffect>,
    pub toleration_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TolerationOperator {
    Exists,
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

/// Affinity rules
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affinity {
    #[serde(default)]
    pub node_affinity: Option<NodeAffinity>,
    #[serde(default)]
    pub agent_affinity: Option<AgentAffinity>,
    #[serde(default)]
    pub agent_anti_affinity: Option<AgentAntiAffinity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeAffinity {
    #[serde(default)]
    pub required_during_scheduling_ignored_during_execution: Option<NodeSelector>,
    #[serde(default)]
    pub preferred_during_scheduling_ignored_during_execution: Vec<PreferredSchedulingTerm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelector {
    pub node_selector_terms: Vec<NodeSelectorTerm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorTerm {
    #[serde(default)]
    pub match_expressions: Vec<NodeSelectorRequirement>,
    #[serde(default)]
    pub match_fields: Vec<NodeSelectorRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferredSchedulingTerm {
    pub weight: i32,
    pub preference: NodeSelectorTerm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAffinity {
    #[serde(default)]
    pub required_during_scheduling_ignored_during_execution: Vec<AgentAffinityTerm>,
    #[serde(default)]
    pub preferred_during_scheduling_ignored_during_execution: Vec<WeightedAgentAffinityTerm>,
}

pub type AgentAntiAffinity = AgentAffinity;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAffinityTerm {
    pub label_selector: Option<super::labels::LabelSelector>,
    pub topology_key: String,
    #[serde(default)]
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedAgentAffinityTerm {
    pub weight: i32,
    pub agent_affinity_term: AgentAffinityTerm,
}

/// Security context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContext {
    /// Security clearance level
    #[serde(default)]
    pub security_level: Option<String>,
    /// Run as specific identity
    #[serde(default)]
    pub run_as_identity: Option<String>,
    /// Read-only memory region
    #[serde(default)]
    pub read_only_memory: bool,
    /// Allowed namespaces
    #[serde(default)]
    pub allowed_namespaces: Vec<String>,
}

/// Health probe
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// Heartbeat check
    #[serde(default)]
    pub heartbeat: Option<HeartbeatAction>,
    /// Tool execution check
    #[serde(default)]
    pub exec: Option<ExecAction>,
    /// Initial delay before starting probes (seconds)
    #[serde(default = "default_initial_delay")]
    pub initial_delay_seconds: u32,
    /// Period between probes (seconds)
    #[serde(default = "default_period")]
    pub period_seconds: u32,
    /// Timeout for probe (seconds)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,
    /// Success threshold
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    /// Failure threshold
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

fn default_initial_delay() -> u32 { 0 }
fn default_period() -> u32 { 10 }
fn default_timeout() -> u32 { 1 }
fn default_success_threshold() -> u32 { 1 }
fn default_failure_threshold() -> u32 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAction {
    /// Maximum time since last heartbeat (seconds)
    pub max_age_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecAction {
    /// Tool to execute
    pub tool: String,
    /// Arguments
    #[serde(default)]
    pub args: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Agent Template (like PodTemplateSpec)
// ═══════════════════════════════════════════════════════════════════════

/// Agent template for creating agents (like PodTemplateSpec)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentTemplate {
    /// Template metadata
    pub metadata: ObjectMeta,
    /// Agent spec
    pub spec: AgentSpec,
}

// ═══════════════════════════════════════════════════════════════════════
// Deployment Strategy
// ═══════════════════════════════════════════════════════════════════════

/// Deployment strategy (like K8s DeploymentStrategy)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum DeploymentStrategy {
    /// Rolling update (default)
    RollingUpdate {
        #[serde(default)]
        rolling_update: RollingUpdateStrategy,
    },
    /// Recreate all at once
    Recreate,
    /// Blue-green deployment
    BlueGreen {
        /// Percentage of traffic to new version during transition
        #[serde(default)]
        preview_percentage: u8,
    },
    /// Canary deployment
    Canary {
        /// Percentage of traffic to canary
        weight: u8,
        /// Steps for gradual rollout
        #[serde(default)]
        steps: Vec<CanaryStep>,
    },
}

impl Default for DeploymentStrategy {
    fn default() -> Self {
        DeploymentStrategy::RollingUpdate {
            rolling_update: RollingUpdateStrategy::default(),
        }
    }
}

/// Rolling update parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateStrategy {
    /// Maximum unavailable agents during update
    #[serde(default = "default_max_unavailable")]
    pub max_unavailable: IntOrString,
    /// Maximum extra agents during update
    #[serde(default = "default_max_surge")]
    pub max_surge: IntOrString,
}

impl Default for RollingUpdateStrategy {
    fn default() -> Self {
        Self {
            max_unavailable: IntOrString::Int(1),
            max_surge: IntOrString::Int(1),
        }
    }
}

fn default_max_unavailable() -> IntOrString { IntOrString::Int(1) }
fn default_max_surge() -> IntOrString { IntOrString::Int(1) }

/// Canary step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanaryStep {
    /// Weight percentage for this step
    #[serde(default)]
    pub set_weight: Option<u8>,
    /// Pause duration (seconds, 0 = manual)
    #[serde(default)]
    pub pause: Option<u32>,
}

/// Integer or percentage string (like K8s IntOrString)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntOrString {
    Int(u32),
    String(String),
}

impl IntOrString {
    /// Resolve to absolute value given total
    pub fn resolve(&self, total: u32) -> u32 {
        match self {
            IntOrString::Int(v) => *v,
            IntOrString::String(s) => {
                if s.ends_with('%') {
                    let pct: u32 = s[..s.len()-1].parse().unwrap_or(0);
                    (total * pct + 99) / 100 // round up
                } else {
                    s.parse().unwrap_or(0)
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Condition (K8s-style status conditions)
// ═══════════════════════════════════════════════════════════════════════

/// Status condition (like K8s Condition)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition
    pub type_: String,
    /// Status: True, False, Unknown
    pub status: ConditionStatus,
    /// Last time the condition transitioned
    pub last_transition_time: i64,
    /// Reason for the condition
    #[serde(default)]
    pub reason: String,
    /// Human-readable message
    #[serde(default)]
    pub message: String,
    /// Observed generation
    #[serde(default)]
    pub observed_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory() {
        assert_eq!(ResourceLimits::parse_memory("1024").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("1Ki").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("1Mi").unwrap(), 1024 * 1024);
        assert_eq!(ResourceLimits::parse_memory("1Gi").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(ResourceLimits::parse_memory("128Mi").unwrap(), 128 * 1024 * 1024);
    }

    #[test]
    fn test_format_memory() {
        assert_eq!(ResourceLimits::format_memory(1024), "1Ki");
        assert_eq!(ResourceLimits::format_memory(1024 * 1024), "1Mi");
        assert_eq!(ResourceLimits::format_memory(128 * 1024 * 1024), "128Mi");
        assert_eq!(ResourceLimits::format_memory(1024 * 1024 * 1024), "1Gi");
    }

    #[test]
    fn test_int_or_string_resolve() {
        assert_eq!(IntOrString::Int(5).resolve(100), 5);
        assert_eq!(IntOrString::String("25%".to_string()).resolve(100), 25);
        assert_eq!(IntOrString::String("25%".to_string()).resolve(10), 3); // rounds up
    }

    #[test]
    fn test_default_resource_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.tokens_daily, 1_000_000);
    }

    #[test]
    fn test_agent_spec_serde() {
        let spec = AgentSpec {
            model: Some("gpt-4".to_string()),
            framework: Some("langchain".to_string()),
            resources: ResourceRequirements::default(),
            ..Default::default()
        };
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: AgentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.model, Some("gpt-4".to_string()));
    }
}
