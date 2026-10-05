//! AgentSet Controller
//!
//! Maintains a stable set of replica agents, like Kubernetes ReplicaSet.
//!
//! # Responsibilities
//!
//! 1. Ensure desired number of agent replicas are running
//! 2. Replace failed/terminated agents automatically
//! 3. Scale up/down based on replica count changes
//! 4. Select agents using label selectors
//!
//! # Example
//!
//! ```yaml
//! apiVersion: connector.io/v1
//! kind: AgentSet
//! metadata:
//!   name: triage-set
//!   namespace: hospital
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
//!       resources:
//!         limits:
//!           memory: 128Mi
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::labels::LabelSelector;
use super::spec::{AgentTemplate, Condition, ConditionStatus, ObjectMeta};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// AgentSet
// ═══════════════════════════════════════════════════════════════════════

/// AgentSet maintains a stable set of replica agents (like K8s ReplicaSet)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSet {
    /// API version
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "default_agent_set_kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Specification
    pub spec: AgentSetSpec,
    /// Current status
    #[serde(default)]
    pub status: AgentSetStatus,
}

fn default_api_version() -> String { "connector.io/v1".to_string() }
fn default_agent_set_kind() -> String { "AgentSet".to_string() }

/// AgentSet specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSetSpec {
    /// Desired number of replicas
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Minimum ready seconds before considering available
    #[serde(default)]
    pub min_ready_seconds: u32,
    /// Label selector for agents
    pub selector: LabelSelector,
    /// Agent template
    pub template: AgentTemplate,
}

fn default_replicas() -> u32 { 1 }

/// AgentSet status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSetStatus {
    /// Total replicas (running + pending)
    pub replicas: u32,
    /// Fully running replicas
    pub ready_replicas: u32,
    /// Available replicas (ready for min_ready_seconds)
    pub available_replicas: u32,
    /// Replicas with current spec
    pub updated_replicas: u32,
    /// Observed generation
    pub observed_generation: i64,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// Collision count (for name generation)
    #[serde(default)]
    pub collision_count: u32,
}

impl AgentSet {
    /// Create a new AgentSet
    pub fn new(name: &str, namespace: &str, replicas: u32, selector: LabelSelector, template: AgentTemplate) -> Self {
        Self {
            api_version: default_api_version(),
            kind: default_agent_set_kind(),
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                creation_timestamp: now_ms(),
                generation: 1,
                ..Default::default()
            },
            spec: AgentSetSpec {
                replicas,
                min_ready_seconds: 0,
                selector,
                template,
            },
            status: AgentSetStatus::default(),
        }
    }

    /// Check if status needs reconciliation
    pub fn needs_reconcile(&self) -> bool {
        self.status.replicas != self.spec.replicas ||
        self.status.observed_generation != self.metadata.generation
    }

    /// Calculate scaling delta
    pub fn scaling_delta(&self) -> i32 {
        self.spec.replicas as i32 - self.status.replicas as i32
    }

    /// Update status after reconciliation
    pub fn update_status(&mut self, replicas: u32, ready: u32, available: u32) {
        self.status.replicas = replicas;
        self.status.ready_replicas = ready;
        self.status.available_replicas = available;
        self.status.updated_replicas = replicas;
        self.status.observed_generation = self.metadata.generation;

        // Update conditions
        self.update_conditions();
    }

    fn update_conditions(&mut self) {
        let now = now_ms();

        // ReplicaFailure condition
        let failure_condition = if self.status.replicas < self.spec.replicas {
            Condition {
                type_: "ReplicaFailure".to_string(),
                status: ConditionStatus::True,
                last_transition_time: now,
                reason: "InsufficientReplicas".to_string(),
                message: format!("Only {}/{} replicas running",
                    self.status.replicas, self.spec.replicas),
                observed_generation: self.metadata.generation,
            }
        } else {
            Condition {
                type_: "ReplicaFailure".to_string(),
                status: ConditionStatus::False,
                last_transition_time: now,
                reason: "ReplicasSatisfied".to_string(),
                message: "All replicas running".to_string(),
                observed_generation: self.metadata.generation,
            }
        };

        // Update or add condition
        if let Some(existing) = self.status.conditions.iter_mut()
            .find(|c| c.type_ == "ReplicaFailure")
        {
            if existing.status != failure_condition.status {
                *existing = failure_condition;
            }
        } else {
            self.status.conditions.push(failure_condition);
        }
    }

    /// Generate a unique agent name for this set
    pub fn generate_agent_name(&mut self) -> String {
        self.status.collision_count += 1;
        format!("{}-{:05}", self.metadata.name, self.status.collision_count)
    }

    /// Check if an agent belongs to this set (by labels)
    pub fn owns_agent(&self, agent_labels: &HashMap<String, String>) -> bool {
        self.spec.selector.matches(agent_labels)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// AgentSet Controller
// ═══════════════════════════════════════════════════════════════════════

/// Controller that reconciles AgentSet desired state
pub struct AgentSetController {
    /// Registered AgentSets
    agent_sets: HashMap<String, AgentSet>,
    /// Agent to AgentSet mapping (agent_pid → set_key)
    agent_ownership: HashMap<String, String>,
    /// Reconciliation interval (ms)
    pub reconcile_interval_ms: u64,
    /// Last reconciliation time
    last_reconcile: i64,
}

impl AgentSetController {
    pub fn new() -> Self {
        Self {
            agent_sets: HashMap::new(),
            agent_ownership: HashMap::new(),
            reconcile_interval_ms: 5_000,
            last_reconcile: 0,
        }
    }

    /// Register an AgentSet
    pub fn register(&mut self, agent_set: AgentSet) -> Result<(), String> {
        let key = format!("{}/{}", agent_set.metadata.namespace, agent_set.metadata.name);
        if self.agent_sets.contains_key(&key) {
            return Err(format!("AgentSet {} already exists", key));
        }
        self.agent_sets.insert(key, agent_set);
        Ok(())
    }

    /// Update an AgentSet spec
    pub fn update(&mut self, agent_set: AgentSet) -> Result<(), String> {
        let key = format!("{}/{}", agent_set.metadata.namespace, agent_set.metadata.name);
        if let Some(existing) = self.agent_sets.get_mut(&key) {
            existing.spec = agent_set.spec;
            existing.metadata.generation += 1;
            Ok(())
        } else {
            Err(format!("AgentSet {} not found", key))
        }
    }

    /// Delete an AgentSet
    pub fn delete(&mut self, namespace: &str, name: &str) -> Option<AgentSet> {
        let key = format!("{}/{}", namespace, name);
        self.agent_sets.remove(&key)
    }

    /// Get an AgentSet
    pub fn get(&self, namespace: &str, name: &str) -> Option<&AgentSet> {
        let key = format!("{}/{}", namespace, name);
        self.agent_sets.get(&key)
    }

    /// List all AgentSets
    pub fn list(&self) -> Vec<&AgentSet> {
        self.agent_sets.values().collect()
    }

    /// List AgentSets in a namespace
    pub fn list_in_namespace(&self, namespace: &str) -> Vec<&AgentSet> {
        self.agent_sets.values()
            .filter(|s| s.metadata.namespace == namespace)
            .collect()
    }

    /// Record that an agent was created for a set
    pub fn record_agent_created(&mut self, agent_pid: &str, set_namespace: &str, set_name: &str) {
        let key = format!("{}/{}", set_namespace, set_name);
        self.agent_ownership.insert(agent_pid.to_string(), key);
    }

    /// Record that an agent was terminated
    pub fn record_agent_terminated(&mut self, agent_pid: &str) {
        self.agent_ownership.remove(agent_pid);
    }

    /// Get the AgentSet that owns an agent
    pub fn get_owner(&self, agent_pid: &str) -> Option<&AgentSet> {
        self.agent_ownership.get(agent_pid)
            .and_then(|key| self.agent_sets.get(key))
    }

    /// Reconcile all AgentSets
    ///
    /// Returns actions to take: (set_key, scale_delta)
    /// Positive delta = scale up, negative = scale down
    pub fn reconcile(&mut self) -> Vec<ReconcileAction> {
        let now = now_ms();
        if now - self.last_reconcile < self.reconcile_interval_ms as i64 {
            return Vec::new();
        }
        self.last_reconcile = now;

        let mut actions = Vec::new();

        // Count agents per set
        let mut agent_counts: HashMap<String, u32> = HashMap::new();
        for set_key in self.agent_ownership.values() {
            *agent_counts.entry(set_key.clone()).or_insert(0) += 1;
        }

        // Check each set
        for (key, set) in &mut self.agent_sets {
            let current = *agent_counts.get(key).unwrap_or(&0);
            let desired = set.spec.replicas;

            if current != desired {
                let delta = desired as i32 - current as i32;
                actions.push(ReconcileAction {
                    set_namespace: set.metadata.namespace.clone(),
                    set_name: set.metadata.name.clone(),
                    action_type: if delta > 0 {
                        ReconcileActionType::ScaleUp(delta as u32)
                    } else {
                        ReconcileActionType::ScaleDown((-delta) as u32)
                    },
                    template: set.spec.template.clone(),
                });
            }

            // Update status
            set.status.replicas = current;
            set.status.ready_replicas = current; // simplified
            set.status.available_replicas = current;
            set.status.observed_generation = set.metadata.generation;
        }

        actions
    }

    /// Scale an AgentSet
    pub fn scale(&mut self, namespace: &str, name: &str, replicas: u32) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);
        if let Some(set) = self.agent_sets.get_mut(&key) {
            set.spec.replicas = replicas;
            set.metadata.generation += 1;
            Ok(())
        } else {
            Err(format!("AgentSet {} not found", key))
        }
    }
}

impl Default for AgentSetController {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to take during reconciliation
#[derive(Debug, Clone)]
pub struct ReconcileAction {
    pub set_namespace: String,
    pub set_name: String,
    pub action_type: ReconcileActionType,
    pub template: AgentTemplate,
}

#[derive(Debug, Clone)]
pub enum ReconcileActionType {
    ScaleUp(u32),
    ScaleDown(u32),
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::spec::AgentSpec;

    fn make_agent_set(name: &str, replicas: u32) -> AgentSet {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), name.to_string());

        AgentSet::new(
            name,
            "default",
            replicas,
            LabelSelector::from_labels(labels.clone()),
            AgentTemplate {
                metadata: ObjectMeta {
                    labels,
                    ..Default::default()
                },
                spec: AgentSpec::default(),
            },
        )
    }

    #[test]
    fn test_create_agent_set() {
        let set = make_agent_set("triage", 5);
        assert_eq!(set.spec.replicas, 5);
        assert_eq!(set.metadata.name, "triage");
        assert_eq!(set.metadata.namespace, "default");
    }

    #[test]
    fn test_scaling_delta() {
        let mut set = make_agent_set("triage", 5);
        assert_eq!(set.scaling_delta(), 5); // 5 - 0 = 5

        set.status.replicas = 3;
        assert_eq!(set.scaling_delta(), 2); // 5 - 3 = 2

        set.status.replicas = 7;
        assert_eq!(set.scaling_delta(), -2); // 5 - 7 = -2
    }

    #[test]
    fn test_generate_agent_name() {
        let mut set = make_agent_set("triage", 5);
        assert_eq!(set.generate_agent_name(), "triage-00001");
        assert_eq!(set.generate_agent_name(), "triage-00002");
        assert_eq!(set.generate_agent_name(), "triage-00003");
    }

    #[test]
    fn test_owns_agent() {
        let set = make_agent_set("triage", 5);

        let mut matching = HashMap::new();
        matching.insert("app".to_string(), "triage".to_string());
        assert!(set.owns_agent(&matching));

        let mut non_matching = HashMap::new();
        non_matching.insert("app".to_string(), "other".to_string());
        assert!(!set.owns_agent(&non_matching));
    }

    #[test]
    fn test_controller_register() {
        let mut controller = AgentSetController::new();
        let set = make_agent_set("triage", 5);

        assert!(controller.register(set.clone()).is_ok());
        assert!(controller.register(set).is_err()); // duplicate
    }

    #[test]
    fn test_controller_scale() {
        let mut controller = AgentSetController::new();
        controller.register(make_agent_set("triage", 5)).unwrap();

        assert!(controller.scale("default", "triage", 10).is_ok());
        let set = controller.get("default", "triage").unwrap();
        assert_eq!(set.spec.replicas, 10);
    }

    #[test]
    fn test_controller_reconcile() {
        let mut controller = AgentSetController::new();
        controller.reconcile_interval_ms = 0; // immediate
        controller.register(make_agent_set("triage", 3)).unwrap();

        // First reconcile should request scale up
        let actions = controller.reconcile();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].action_type, ReconcileActionType::ScaleUp(3)));

        // Record agents created
        controller.record_agent_created("agent:001", "default", "triage");
        controller.record_agent_created("agent:002", "default", "triage");
        controller.record_agent_created("agent:003", "default", "triage");

        // Next reconcile should be satisfied
        let actions = controller.reconcile();
        assert!(actions.is_empty());

        // Terminate one agent
        controller.record_agent_terminated("agent:002");

        // Should request scale up by 1
        let actions = controller.reconcile();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].action_type, ReconcileActionType::ScaleUp(1)));
    }

    #[test]
    fn test_controller_scale_down() {
        let mut controller = AgentSetController::new();
        controller.reconcile_interval_ms = 0;
        controller.register(make_agent_set("triage", 5)).unwrap();

        // Create 5 agents
        for i in 0..5 {
            controller.record_agent_created(&format!("agent:{:03}", i), "default", "triage");
        }

        // Scale down to 3
        controller.scale("default", "triage", 3).unwrap();

        let actions = controller.reconcile();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].action_type, ReconcileActionType::ScaleDown(2)));
    }
}
