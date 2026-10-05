//! Horizontal Agent Autoscaler (HPA)
//!
//! Automatically scales agent replicas based on observed metrics.
//! Like Kubernetes HorizontalPodAutoscaler.
//!
//! # Metrics Supported
//!
//! - **Resource metrics** — Token usage, memory, cost
//! - **External metrics** — Custom metrics from monitoring systems
//! - **Object metrics** — Metrics from other Connector objects
//!
//! # Scaling Algorithm
//!
//! ```text
//! desiredReplicas = ceil(currentReplicas * (currentMetricValue / desiredMetricValue))
//! ```
//!
//! With stabilization windows to prevent thrashing.
//!
//! # Example
//!
//! ```yaml
//! apiVersion: autoscaling/v2
//! kind: HorizontalAgentAutoscaler
//! metadata:
//!   name: triage-hpa
//! spec:
//!   scaleTargetRef:
//!     apiVersion: connector.io/v1
//!     kind: AgentDeployment
//!     name: triage-bot
//!   minReplicas: 2
//!   maxReplicas: 100
//!   metrics:
//!   - type: Resource
//!     resource:
//!       name: tokens
//!       target:
//!         type: Utilization
//!         averageUtilization: 70
//!   behavior:
//!     scaleDown:
//!       stabilizationWindowSeconds: 300
//!       policies:
//!       - type: Percent
//!         value: 10
//!         periodSeconds: 60
//!     scaleUp:
//!       stabilizationWindowSeconds: 0
//!       policies:
//!       - type: Pods
//!         value: 4
//!         periodSeconds: 60
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use super::spec::{Condition, ConditionStatus, ObjectMeta};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// HorizontalAgentAutoscaler
// ═══════════════════════════════════════════════════════════════════════

/// Horizontal Agent Autoscaler (like K8s HPA v2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalAgentAutoscaler {
    /// API version
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "default_hpa_kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Specification
    pub spec: HPASpec,
    /// Current status
    #[serde(default)]
    pub status: HPAStatus,
}

fn default_api_version() -> String { "autoscaling/v2".to_string() }
fn default_hpa_kind() -> String { "HorizontalAgentAutoscaler".to_string() }

/// HPA specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HPASpec {
    /// Reference to the scalable resource
    pub scale_target_ref: CrossVersionObjectReference,
    /// Minimum replicas (0 = scale to zero allowed)
    #[serde(default = "default_min_replicas")]
    pub min_replicas: u32,
    /// Maximum replicas
    pub max_replicas: u32,
    /// Metrics to scale on
    #[serde(default)]
    pub metrics: Vec<MetricSpec>,
    /// Scaling behavior
    #[serde(default)]
    pub behavior: Option<HPAScalingBehavior>,
}

fn default_min_replicas() -> u32 { 1 }

/// Reference to scalable object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossVersionObjectReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
}

/// Metric specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSpec {
    /// Type of metric
    #[serde(rename = "type")]
    pub type_: MetricSourceType,
    /// Resource metric (CPU, memory, tokens)
    #[serde(default)]
    pub resource: Option<ResourceMetricSource>,
    /// External metric
    #[serde(default)]
    pub external: Option<ExternalMetricSource>,
    /// Object metric
    #[serde(default)]
    pub object: Option<ObjectMetricSource>,
    /// Pods metric (average across all pods)
    #[serde(default)]
    pub pods: Option<PodsMetricSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricSourceType {
    Resource,
    External,
    Object,
    Pods,
}

/// Resource metric source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetricSource {
    /// Resource name (tokens, memory, cost)
    pub name: ResourceName,
    /// Target value
    pub target: MetricTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceName {
    Tokens,
    Memory,
    Cost,
    Ops,
}

/// External metric source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalMetricSource {
    /// Metric name
    pub metric: MetricIdentifier,
    /// Target value
    pub target: MetricTarget,
}

/// Object metric source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMetricSource {
    /// Object reference
    pub described_object: CrossVersionObjectReference,
    /// Metric name
    pub metric: MetricIdentifier,
    /// Target value
    pub target: MetricTarget,
}

/// Pods metric source
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodsMetricSource {
    /// Metric name
    pub metric: MetricIdentifier,
    /// Target value
    pub target: MetricTarget,
}

/// Metric identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricIdentifier {
    /// Metric name
    pub name: String,
    /// Selector for metric
    #[serde(default)]
    pub selector: Option<super::labels::LabelSelector>,
}

/// Metric target
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricTarget {
    /// Target type
    #[serde(rename = "type")]
    pub type_: MetricTargetType,
    /// Target value (for Value type)
    #[serde(default)]
    pub value: Option<i64>,
    /// Target average value (for AverageValue type)
    #[serde(default)]
    pub average_value: Option<i64>,
    /// Target utilization percentage (for Utilization type)
    #[serde(default)]
    pub average_utilization: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricTargetType {
    Utilization,
    Value,
    AverageValue,
}

/// HPA scaling behavior
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HPAScalingBehavior {
    /// Scale up behavior
    #[serde(default)]
    pub scale_up: Option<HPAScalingRules>,
    /// Scale down behavior
    #[serde(default)]
    pub scale_down: Option<HPAScalingRules>,
}

/// Scaling rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HPAScalingRules {
    /// Stabilization window (seconds)
    #[serde(default = "default_stabilization_window")]
    pub stabilization_window_seconds: u32,
    /// Select policy (Max, Min, Disabled)
    #[serde(default)]
    pub select_policy: Option<ScalingPolicySelect>,
    /// Scaling policies
    #[serde(default)]
    pub policies: Vec<HPAScalingPolicy>,
}

fn default_stabilization_window() -> u32 { 300 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalingPolicySelect {
    Max,
    Min,
    Disabled,
}

/// Scaling policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HPAScalingPolicy {
    /// Policy type
    #[serde(rename = "type")]
    pub type_: HPAScalingPolicyType,
    /// Value
    pub value: u32,
    /// Period (seconds)
    pub period_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HPAScalingPolicyType {
    Pods,
    Percent,
}

// ═══════════════════════════════════════════════════════════════════════
// HPA Status
// ═══════════════════════════════════════════════════════════════════════

/// HPA status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HPAStatus {
    /// Observed generation
    pub observed_generation: i64,
    /// Last scale time
    #[serde(default)]
    pub last_scale_time: Option<i64>,
    /// Current replicas
    pub current_replicas: u32,
    /// Desired replicas
    pub desired_replicas: u32,
    /// Current metrics
    #[serde(default)]
    pub current_metrics: Vec<MetricStatus>,
    /// Conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Current metric status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricStatus {
    /// Metric type
    #[serde(rename = "type")]
    pub type_: MetricSourceType,
    /// Resource metric status
    #[serde(default)]
    pub resource: Option<ResourceMetricStatus>,
    /// External metric status
    #[serde(default)]
    pub external: Option<ExternalMetricStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetricStatus {
    pub name: ResourceName,
    pub current: MetricValueStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalMetricStatus {
    pub metric: MetricIdentifier,
    pub current: MetricValueStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricValueStatus {
    #[serde(default)]
    pub value: Option<i64>,
    #[serde(default)]
    pub average_value: Option<i64>,
    #[serde(default)]
    pub average_utilization: Option<u32>,
}

// ═══════════════════════════════════════════════════════════════════════
// HPA Controller
// ═══════════════════════════════════════════════════════════════════════

/// Controller that reconciles HPA desired state
pub struct HPAController {
    /// Registered HPAs
    hpas: HashMap<String, HorizontalAgentAutoscaler>,
    /// Recommendation history for stabilization
    recommendations: HashMap<String, VecDeque<ScaleRecommendation>>,
    /// Reconciliation interval (ms)
    pub reconcile_interval_ms: u64,
    /// Last reconciliation time
    last_reconcile: i64,
    /// Tolerance for metric comparison (default 10%)
    pub tolerance: f64,
}

#[derive(Debug, Clone)]
struct ScaleRecommendation {
    timestamp: i64,
    replicas: u32,
}

impl HPAController {
    pub fn new() -> Self {
        Self {
            hpas: HashMap::new(),
            recommendations: HashMap::new(),
            reconcile_interval_ms: 15_000, // 15s like K8s
            last_reconcile: 0,
            tolerance: 0.1,
        }
    }

    /// Register an HPA
    pub fn register(&mut self, hpa: HorizontalAgentAutoscaler) -> Result<(), String> {
        let key = format!("{}/{}", hpa.metadata.namespace, hpa.metadata.name);
        if self.hpas.contains_key(&key) {
            return Err(format!("HPA {} already exists", key));
        }
        self.hpas.insert(key, hpa);
        Ok(())
    }

    /// Update an HPA
    pub fn update(&mut self, hpa: HorizontalAgentAutoscaler) -> Result<(), String> {
        let key = format!("{}/{}", hpa.metadata.namespace, hpa.metadata.name);
        if let Some(existing) = self.hpas.get_mut(&key) {
            existing.spec = hpa.spec;
            existing.metadata.generation += 1;
            Ok(())
        } else {
            Err(format!("HPA {} not found", key))
        }
    }

    /// Delete an HPA
    pub fn delete(&mut self, namespace: &str, name: &str) -> Option<HorizontalAgentAutoscaler> {
        let key = format!("{}/{}", namespace, name);
        self.recommendations.remove(&key);
        self.hpas.remove(&key)
    }

    /// Get an HPA
    pub fn get(&self, namespace: &str, name: &str) -> Option<&HorizontalAgentAutoscaler> {
        let key = format!("{}/{}", namespace, name);
        self.hpas.get(&key)
    }

    /// List all HPAs
    pub fn list(&self) -> Vec<&HorizontalAgentAutoscaler> {
        self.hpas.values().collect()
    }

    /// Calculate desired replicas based on metrics
    pub fn calculate_desired_replicas(
        &self,
        hpa: &HorizontalAgentAutoscaler,
        current_replicas: u32,
        metrics: &HashMap<String, f64>,
    ) -> u32 {
        if hpa.spec.metrics.is_empty() {
            return current_replicas;
        }

        let mut max_desired: u32 = 0;

        for metric_spec in &hpa.spec.metrics {
            let desired = match &metric_spec.type_ {
                MetricSourceType::Resource => {
                    if let Some(resource) = &metric_spec.resource {
                        self.calculate_for_resource(resource, current_replicas, metrics)
                    } else {
                        current_replicas
                    }
                }
                MetricSourceType::External => {
                    if let Some(external) = &metric_spec.external {
                        self.calculate_for_external(external, current_replicas, metrics)
                    } else {
                        current_replicas
                    }
                }
                _ => current_replicas,
            };

            max_desired = max_desired.max(desired);
        }

        // Apply min/max bounds
        max_desired.clamp(hpa.spec.min_replicas, hpa.spec.max_replicas)
    }

    fn calculate_for_resource(
        &self,
        resource: &ResourceMetricSource,
        current_replicas: u32,
        metrics: &HashMap<String, f64>,
    ) -> u32 {
        let metric_key = match resource.name {
            ResourceName::Tokens => "tokens_utilization",
            ResourceName::Memory => "memory_utilization",
            ResourceName::Cost => "cost_utilization",
            ResourceName::Ops => "ops_utilization",
        };

        let current_value = metrics.get(metric_key).copied().unwrap_or(0.0);

        match resource.target.type_ {
            MetricTargetType::Utilization => {
                let target = resource.target.average_utilization.unwrap_or(80) as f64;
                self.calculate_replicas(current_replicas, current_value, target)
            }
            MetricTargetType::Value | MetricTargetType::AverageValue => {
                let target = resource.target.value.or(resource.target.average_value).unwrap_or(100) as f64;
                self.calculate_replicas(current_replicas, current_value, target)
            }
        }
    }

    fn calculate_for_external(
        &self,
        external: &ExternalMetricSource,
        current_replicas: u32,
        metrics: &HashMap<String, f64>,
    ) -> u32 {
        let current_value = metrics.get(&external.metric.name).copied().unwrap_or(0.0);

        match external.target.type_ {
            MetricTargetType::Value => {
                let target = external.target.value.unwrap_or(100) as f64;
                self.calculate_replicas(current_replicas, current_value, target)
            }
            MetricTargetType::AverageValue => {
                let target = external.target.average_value.unwrap_or(100) as f64;
                self.calculate_replicas(current_replicas, current_value, target)
            }
            MetricTargetType::Utilization => {
                let target = external.target.average_utilization.unwrap_or(80) as f64;
                self.calculate_replicas(current_replicas, current_value, target)
            }
        }
    }

    fn calculate_replicas(&self, current: u32, current_value: f64, target_value: f64) -> u32 {
        if target_value == 0.0 {
            return current;
        }

        let ratio = current_value / target_value;

        // Apply tolerance
        if (ratio - 1.0).abs() <= self.tolerance {
            return current;
        }

        let desired = (current as f64 * ratio).ceil() as u32;
        desired.max(1)
    }

    /// Apply stabilization window
    fn stabilize(&mut self, key: &str, desired: u32, direction: ScaleDirection) -> u32 {
        let now = now_ms();
        let history = self.recommendations.entry(key.to_string()).or_insert_with(VecDeque::new);

        // Add current recommendation
        history.push_back(ScaleRecommendation {
            timestamp: now,
            replicas: desired,
        });

        // Get stabilization window
        let window_ms = match direction {
            ScaleDirection::Up => 0, // No stabilization for scale up by default
            ScaleDirection::Down => 300_000, // 5 minutes for scale down
        };

        // Remove old entries
        let cutoff = now - window_ms;
        while history.front().map(|r| r.timestamp < cutoff).unwrap_or(false) {
            history.pop_front();
        }

        // Return stabilized value
        match direction {
            ScaleDirection::Up => history.iter().map(|r| r.replicas).max().unwrap_or(desired),
            ScaleDirection::Down => history.iter().map(|r| r.replicas).min().unwrap_or(desired),
        }
    }

    /// Reconcile HPAs and return scaling actions
    pub fn reconcile(&mut self, current_metrics: &HashMap<String, HashMap<String, f64>>) -> Vec<HPAAction> {
        let now = now_ms();
        if now - self.last_reconcile < self.reconcile_interval_ms as i64 {
            return Vec::new();
        }
        self.last_reconcile = now;

        // Phase 1: Collect scaling decisions (read-only on hpas)
        let mut scaling_decisions: Vec<(String, u32, u32, ScaleDirection)> = Vec::new();
        for (key, hpa) in &self.hpas {
            let target_key = format!("{}/{}", hpa.metadata.namespace, hpa.spec.scale_target_ref.name);
            let metrics = current_metrics.get(&target_key).cloned().unwrap_or_default();

            let current = hpa.status.current_replicas;
            let desired = self.calculate_desired_replicas(hpa, current, &metrics);

            if desired != current {
                let direction = if desired > current {
                    ScaleDirection::Up
                } else {
                    ScaleDirection::Down
                };
                scaling_decisions.push((key.clone(), current, desired, direction));
            }
        }

        // Phase 2: Apply stabilization and collect actions
        let mut actions = Vec::new();
        let mut updates: Vec<(String, u32, Option<i64>)> = Vec::new();

        for (key, current, desired, direction) in scaling_decisions {
            let stabilized = self.stabilize(&key, desired, direction);

            if stabilized != current {
                if let Some(hpa) = self.hpas.get(&key) {
                    actions.push(HPAAction {
                        hpa_namespace: hpa.metadata.namespace.clone(),
                        hpa_name: hpa.metadata.name.clone(),
                        target_ref: hpa.spec.scale_target_ref.clone(),
                        current_replicas: current,
                        desired_replicas: stabilized,
                    });
                    updates.push((key, stabilized, Some(now)));
                }
            }
        }

        // Phase 3: Apply updates to HPAs
        for (key, stabilized, last_scale_time) in updates {
            if let Some(hpa) = self.hpas.get_mut(&key) {
                hpa.status.desired_replicas = stabilized;
                hpa.status.last_scale_time = last_scale_time;
            }
        }

        // Phase 4: Update observed generation for all HPAs
        for hpa in self.hpas.values_mut() {
            hpa.status.observed_generation = hpa.metadata.generation;
        }

        actions
    }

    /// Update current replicas for an HPA
    pub fn update_current_replicas(&mut self, namespace: &str, name: &str, replicas: u32) {
        let key = format!("{}/{}", namespace, name);
        if let Some(hpa) = self.hpas.get_mut(&key) {
            hpa.status.current_replicas = replicas;
        }
    }
}

impl Default for HPAController {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
enum ScaleDirection {
    Up,
    Down,
}

/// Action to take for HPA scaling
#[derive(Debug, Clone)]
pub struct HPAAction {
    pub hpa_namespace: String,
    pub hpa_name: String,
    pub target_ref: CrossVersionObjectReference,
    pub current_replicas: u32,
    pub desired_replicas: u32,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hpa(name: &str, min: u32, max: u32, target_utilization: u32) -> HorizontalAgentAutoscaler {
        HorizontalAgentAutoscaler {
            api_version: default_api_version(),
            kind: default_hpa_kind(),
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: "default".to_string(),
                ..Default::default()
            },
            spec: HPASpec {
                scale_target_ref: CrossVersionObjectReference {
                    api_version: "connector.io/v1".to_string(),
                    kind: "AgentDeployment".to_string(),
                    name: "triage".to_string(),
                },
                min_replicas: min,
                max_replicas: max,
                metrics: vec![MetricSpec {
                    type_: MetricSourceType::Resource,
                    resource: Some(ResourceMetricSource {
                        name: ResourceName::Tokens,
                        target: MetricTarget {
                            type_: MetricTargetType::Utilization,
                            average_utilization: Some(target_utilization),
                            value: None,
                            average_value: None,
                        },
                    }),
                    external: None,
                    object: None,
                    pods: None,
                }],
                behavior: None,
            },
            status: HPAStatus {
                current_replicas: 5,
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_calculate_scale_up() {
        let controller = HPAController::new();
        let hpa = make_hpa("test-hpa", 1, 100, 50);

        let mut metrics = HashMap::new();
        metrics.insert("tokens_utilization".to_string(), 80.0); // 80% > 50% target

        let desired = controller.calculate_desired_replicas(&hpa, 5, &metrics);
        assert!(desired > 5); // Should scale up
    }

    #[test]
    fn test_calculate_scale_down() {
        let controller = HPAController::new();
        let hpa = make_hpa("test-hpa", 1, 100, 50);

        let mut metrics = HashMap::new();
        metrics.insert("tokens_utilization".to_string(), 20.0); // 20% < 50% target

        let desired = controller.calculate_desired_replicas(&hpa, 10, &metrics);
        assert!(desired < 10); // Should scale down
    }

    #[test]
    fn test_min_max_bounds() {
        let controller = HPAController::new();
        let hpa = make_hpa("test-hpa", 2, 10, 50);

        // Try to scale below min
        let mut metrics = HashMap::new();
        metrics.insert("tokens_utilization".to_string(), 1.0);
        let desired = controller.calculate_desired_replicas(&hpa, 5, &metrics);
        assert!(desired >= 2);

        // Try to scale above max
        metrics.insert("tokens_utilization".to_string(), 500.0);
        let desired = controller.calculate_desired_replicas(&hpa, 5, &metrics);
        assert!(desired <= 10);
    }

    #[test]
    fn test_tolerance() {
        let controller = HPAController::new();
        let hpa = make_hpa("test-hpa", 1, 100, 50);

        // Within tolerance (50% ± 10% = 45-55%)
        let mut metrics = HashMap::new();
        metrics.insert("tokens_utilization".to_string(), 52.0);

        let desired = controller.calculate_desired_replicas(&hpa, 5, &metrics);
        assert_eq!(desired, 5); // Should not scale
    }

    #[test]
    fn test_controller_register() {
        let mut controller = HPAController::new();
        let hpa = make_hpa("test-hpa", 1, 100, 50);

        assert!(controller.register(hpa.clone()).is_ok());
        assert!(controller.register(hpa).is_err()); // duplicate
    }
}
