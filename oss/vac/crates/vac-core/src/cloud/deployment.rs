//! AgentDeployment Controller
//!
//! Declarative updates for agents with rolling update, rollback, and canary support.
//! Like Kubernetes Deployment, manages AgentSets to achieve desired state.
//!
//! # Features
//!
//! - **Rolling Updates** — Gradually replace old agents with new ones
//! - **Rollback** — Revert to previous revision on failure
//! - **Canary** — Route percentage of traffic to new version
//! - **Blue-Green** — Switch all traffic at once
//! - **Revision History** — Track deployment history for rollback
//!
//! # Example
//!
//! ```yaml
//! apiVersion: connector.io/v1
//! kind: AgentDeployment
//! metadata:
//!   name: triage-bot
//! spec:
//!   replicas: 5
//!   selector:
//!     matchLabels:
//!       app: triage
//!   strategy:
//!     type: RollingUpdate
//!     rollingUpdate:
//!       maxUnavailable: 1
//!       maxSurge: 2
//!   template:
//!     spec:
//!       model: gpt-4
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::agent_set::{AgentSet, AgentSetSpec};
use super::labels::LabelSelector;
use super::spec::{AgentTemplate, Condition, ConditionStatus, DeploymentStrategy, ObjectMeta, RollingUpdateStrategy};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// AgentDeployment
// ═══════════════════════════════════════════════════════════════════════

/// AgentDeployment provides declarative updates for agents (like K8s Deployment)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDeployment {
    /// API version
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "default_deployment_kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Specification
    pub spec: AgentDeploymentSpec,
    /// Current status
    #[serde(default)]
    pub status: AgentDeploymentStatus,
}

fn default_api_version() -> String { "connector.io/v1".to_string() }
fn default_deployment_kind() -> String { "AgentDeployment".to_string() }

/// AgentDeployment specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDeploymentSpec {
    /// Desired number of replicas
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Label selector
    pub selector: LabelSelector,
    /// Agent template
    pub template: AgentTemplate,
    /// Deployment strategy
    #[serde(default)]
    pub strategy: DeploymentStrategy,
    /// Minimum seconds for agent to be ready before available
    #[serde(default)]
    pub min_ready_seconds: u32,
    /// Number of old AgentSets to retain for rollback
    #[serde(default = "default_revision_history_limit")]
    pub revision_history_limit: u32,
    /// Progress deadline (seconds)
    #[serde(default = "default_progress_deadline")]
    pub progress_deadline_seconds: u32,
    /// Paused (no reconciliation)
    #[serde(default)]
    pub paused: bool,
}

fn default_replicas() -> u32 { 1 }
fn default_revision_history_limit() -> u32 { 10 }
fn default_progress_deadline() -> u32 { 600 }

/// AgentDeployment status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDeploymentStatus {
    /// Observed generation
    pub observed_generation: i64,
    /// Total replicas
    pub replicas: u32,
    /// Updated replicas (new version)
    pub updated_replicas: u32,
    /// Ready replicas
    pub ready_replicas: u32,
    /// Available replicas
    pub available_replicas: u32,
    /// Unavailable replicas
    pub unavailable_replicas: u32,
    /// Current revision
    pub current_revision: String,
    /// Collision count
    #[serde(default)]
    pub collision_count: u32,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

impl AgentDeployment {
    /// Create a new AgentDeployment
    pub fn new(
        name: &str,
        namespace: &str,
        replicas: u32,
        selector: LabelSelector,
        template: AgentTemplate,
    ) -> Self {
        Self {
            api_version: default_api_version(),
            kind: default_deployment_kind(),
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                creation_timestamp: now_ms(),
                generation: 1,
                ..Default::default()
            },
            spec: AgentDeploymentSpec {
                replicas,
                selector,
                template,
                strategy: DeploymentStrategy::default(),
                min_ready_seconds: 0,
                revision_history_limit: default_revision_history_limit(),
                progress_deadline_seconds: default_progress_deadline(),
                paused: false,
            },
            status: AgentDeploymentStatus::default(),
        }
    }

    /// Check if deployment is paused
    pub fn is_paused(&self) -> bool {
        self.spec.paused
    }

    /// Check if deployment is progressing
    pub fn is_progressing(&self) -> bool {
        self.status.updated_replicas < self.spec.replicas ||
        self.status.ready_replicas < self.status.updated_replicas
    }

    /// Check if deployment is complete
    pub fn is_complete(&self) -> bool {
        self.status.updated_replicas == self.spec.replicas &&
        self.status.ready_replicas == self.spec.replicas &&
        self.status.available_replicas == self.spec.replicas &&
        self.status.observed_generation == self.metadata.generation
    }

    /// Get rolling update parameters
    pub fn rolling_update_params(&self) -> RollingUpdateStrategy {
        match &self.spec.strategy {
            DeploymentStrategy::RollingUpdate { rolling_update } => rolling_update.clone(),
            _ => RollingUpdateStrategy::default(),
        }
    }

    /// Calculate max unavailable during rolling update
    pub fn max_unavailable(&self) -> u32 {
        let params = self.rolling_update_params();
        params.max_unavailable.resolve(self.spec.replicas)
    }

    /// Calculate max surge during rolling update
    pub fn max_surge(&self) -> u32 {
        let params = self.rolling_update_params();
        params.max_surge.resolve(self.spec.replicas)
    }

    /// Generate AgentSet name for this deployment
    pub fn generate_agent_set_name(&mut self) -> String {
        self.status.collision_count += 1;
        format!("{}-{}", self.metadata.name, hash_template(&self.spec.template))
    }

    /// Create an AgentSet from this deployment's template
    pub fn create_agent_set(&self, name: &str) -> AgentSet {
        AgentSet {
            api_version: "connector.io/v1".to_string(),
            kind: "AgentSet".to_string(),
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: self.metadata.namespace.clone(),
                labels: self.spec.template.metadata.labels.clone(),
                owner_references: vec![super::spec::OwnerReference {
                    api_version: self.api_version.clone(),
                    kind: self.kind.clone(),
                    name: self.metadata.name.clone(),
                    uid: self.metadata.uid.clone(),
                    controller: true,
                    block_owner_deletion: true,
                }],
                creation_timestamp: now_ms(),
                ..Default::default()
            },
            spec: AgentSetSpec {
                replicas: self.spec.replicas,
                min_ready_seconds: self.spec.min_ready_seconds,
                selector: self.spec.selector.clone(),
                template: self.spec.template.clone(),
            },
            status: Default::default(),
        }
    }

    /// Update status conditions
    pub fn update_conditions(&mut self) {
        let now = now_ms();

        // Available condition
        let available = if self.status.available_replicas >= self.spec.replicas {
            Condition {
                type_: "Available".to_string(),
                status: ConditionStatus::True,
                last_transition_time: now,
                reason: "MinimumReplicasAvailable".to_string(),
                message: "Deployment has minimum availability".to_string(),
                observed_generation: self.metadata.generation,
            }
        } else {
            Condition {
                type_: "Available".to_string(),
                status: ConditionStatus::False,
                last_transition_time: now,
                reason: "MinimumReplicasUnavailable".to_string(),
                message: format!("Deployment does not have minimum availability: {}/{}",
                    self.status.available_replicas, self.spec.replicas),
                observed_generation: self.metadata.generation,
            }
        };

        // Progressing condition
        let progressing = if self.is_complete() {
            Condition {
                type_: "Progressing".to_string(),
                status: ConditionStatus::True,
                last_transition_time: now,
                reason: "NewReplicaSetAvailable".to_string(),
                message: "Deployment has successfully progressed".to_string(),
                observed_generation: self.metadata.generation,
            }
        } else if self.is_paused() {
            Condition {
                type_: "Progressing".to_string(),
                status: ConditionStatus::Unknown,
                last_transition_time: now,
                reason: "DeploymentPaused".to_string(),
                message: "Deployment is paused".to_string(),
                observed_generation: self.metadata.generation,
            }
        } else {
            Condition {
                type_: "Progressing".to_string(),
                status: ConditionStatus::True,
                last_transition_time: now,
                reason: "ReplicaSetUpdated".to_string(),
                message: format!("Updated {} of {} replicas",
                    self.status.updated_replicas, self.spec.replicas),
                observed_generation: self.metadata.generation,
            }
        };

        // Update conditions
        self.status.conditions = vec![available, progressing];
    }
}

/// Hash template for generating unique AgentSet names
fn hash_template(template: &AgentTemplate) -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    // Hash key fields
    if let Some(model) = &template.spec.model {
        model.hash(&mut hasher);
    }
    if let Some(framework) = &template.spec.framework {
        framework.hash(&mut hasher);
    }
    template.spec.resources.limits.memory_bytes.hash(&mut hasher);
    template.spec.resources.limits.tokens_daily.hash(&mut hasher);

    format!("{:08x}", hasher.finish() as u32)
}

// ═══════════════════════════════════════════════════════════════════════
// Deployment Controller
// ═══════════════════════════════════════════════════════════════════════

/// Controller that reconciles AgentDeployment desired state
pub struct DeploymentController {
    /// Registered deployments
    deployments: HashMap<String, AgentDeployment>,
    /// Revision history (deployment_key → Vec<revision>)
    revision_history: HashMap<String, Vec<DeploymentRevision>>,
    /// Reconciliation interval (ms)
    pub reconcile_interval_ms: u64,
    /// Last reconciliation time
    last_reconcile: i64,
}

/// A deployment revision for rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRevision {
    pub revision: u64,
    pub template: AgentTemplate,
    pub created_at: i64,
    pub agent_set_name: String,
}

impl DeploymentController {
    pub fn new() -> Self {
        Self {
            deployments: HashMap::new(),
            revision_history: HashMap::new(),
            reconcile_interval_ms: 5_000,
            last_reconcile: 0,
        }
    }

    /// Create or update a deployment
    pub fn apply(&mut self, deployment: AgentDeployment) -> Result<ApplyResult, String> {
        let key = format!("{}/{}", deployment.metadata.namespace, deployment.metadata.name);

        if self.deployments.contains_key(&key) {
            // Update existing - extract data first
            let (spec_changed, template, name, limit) = {
                let existing = self.deployments.get(&key).unwrap();
                let changed = existing.spec.template.spec.model != deployment.spec.template.spec.model ||
                    existing.spec.template.spec.framework != deployment.spec.template.spec.framework ||
                    existing.spec.replicas != deployment.spec.replicas;
                (changed, deployment.spec.template.clone(), deployment.metadata.name.clone(), 
                 deployment.spec.revision_history_limit)
            };

            // Now mutate
            let existing = self.deployments.get_mut(&key).unwrap();
            existing.spec = deployment.spec;
            existing.metadata.generation += 1;

            if spec_changed {
                // Record revision with extracted data
                self.record_revision_data(&key, template, name, limit);
            }

            Ok(ApplyResult::Updated)
        } else {
            // Create new - extract data first
            let template = deployment.spec.template.clone();
            let name = deployment.metadata.name.clone();
            let limit = deployment.spec.revision_history_limit;

            self.record_revision_data(&key, template, name, limit);
            self.deployments.insert(key, deployment);
            Ok(ApplyResult::Created)
        }
    }

    fn record_revision_data(&mut self, key: &str, template: AgentTemplate, name: String, limit: u32) {
        let history = self.revision_history.entry(key.to_string()).or_insert_with(Vec::new);

        let revision = history.len() as u64 + 1;
        history.push(DeploymentRevision {
            revision,
            template: template.clone(),
            created_at: now_ms(),
            agent_set_name: format!("{}-{}", name, hash_template(&template)),
        });

        // Trim history
        let limit = limit as usize;
        while history.len() > limit {
            history.remove(0);
        }
    }

    /// Delete a deployment
    pub fn delete(&mut self, namespace: &str, name: &str) -> Option<AgentDeployment> {
        let key = format!("{}/{}", namespace, name);
        self.revision_history.remove(&key);
        self.deployments.remove(&key)
    }

    /// Get a deployment
    pub fn get(&self, namespace: &str, name: &str) -> Option<&AgentDeployment> {
        let key = format!("{}/{}", namespace, name);
        self.deployments.get(&key)
    }

    /// List all deployments
    pub fn list(&self) -> Vec<&AgentDeployment> {
        self.deployments.values().collect()
    }

    /// Scale a deployment
    pub fn scale(&mut self, namespace: &str, name: &str, replicas: u32) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);
        if let Some(dep) = self.deployments.get_mut(&key) {
            dep.spec.replicas = replicas;
            dep.metadata.generation += 1;
            Ok(())
        } else {
            Err(format!("Deployment {}/{} not found", namespace, name))
        }
    }

    /// Pause a deployment
    pub fn pause(&mut self, namespace: &str, name: &str) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);
        if let Some(dep) = self.deployments.get_mut(&key) {
            dep.spec.paused = true;
            Ok(())
        } else {
            Err(format!("Deployment {}/{} not found", namespace, name))
        }
    }

    /// Resume a deployment
    pub fn resume(&mut self, namespace: &str, name: &str) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);
        if let Some(dep) = self.deployments.get_mut(&key) {
            dep.spec.paused = false;
            Ok(())
        } else {
            Err(format!("Deployment {}/{} not found", namespace, name))
        }
    }

    /// Rollback to a previous revision
    pub fn rollback(&mut self, namespace: &str, name: &str, revision: Option<u64>) -> Result<(), String> {
        let key = format!("{}/{}", namespace, name);

        let target_revision = {
            let history = self.revision_history.get(&key)
                .ok_or_else(|| format!("No revision history for {}", key))?;

            let rev = if let Some(r) = revision {
                history.iter().find(|h| h.revision == r)
                    .ok_or_else(|| format!("Revision {} not found", r))?
            } else {
                // Rollback to previous
                history.iter().rev().nth(1)
                    .ok_or_else(|| "No previous revision to rollback to".to_string())?
            };
            rev.clone()
        };

        if let Some(dep) = self.deployments.get_mut(&key) {
            dep.spec.template = target_revision.template.clone();
            dep.metadata.generation += 1;
            let template = dep.spec.template.clone();
            let name = dep.metadata.name.clone();
            let limit = dep.spec.revision_history_limit;
            drop(dep);
            self.record_revision_data(&key, template, name, limit);
            Ok(())
        } else {
            Err(format!("Deployment {}/{} not found", namespace, name))
        }
    }

    /// Get revision history
    pub fn history(&self, namespace: &str, name: &str) -> Vec<&DeploymentRevision> {
        let key = format!("{}/{}", namespace, name);
        self.revision_history.get(&key)
            .map(|h| h.iter().collect())
            .unwrap_or_default()
    }

    /// Reconcile deployments and return actions
    pub fn reconcile(&mut self) -> Vec<DeploymentAction> {
        let now = now_ms();
        if now - self.last_reconcile < self.reconcile_interval_ms as i64 {
            return Vec::new();
        }
        self.last_reconcile = now;

        let mut actions = Vec::new();

        for (key, dep) in &mut self.deployments {
            if dep.is_paused() {
                continue;
            }

            // Check if we need to create/update AgentSet
            if dep.status.observed_generation != dep.metadata.generation {
                let agent_set_name = format!("{}-{}", dep.metadata.name, hash_template(&dep.spec.template));

                actions.push(DeploymentAction {
                    deployment_key: key.clone(),
                    action_type: DeploymentActionType::CreateOrUpdateAgentSet {
                        agent_set: dep.create_agent_set(&agent_set_name),
                        strategy: dep.spec.strategy.clone(),
                    },
                });

                dep.status.observed_generation = dep.metadata.generation;
                dep.status.current_revision = agent_set_name;
            }

            dep.update_conditions();
        }

        actions
    }
}

impl Default for DeploymentController {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of apply operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    Created,
    Updated,
}

/// Action to take during deployment reconciliation
#[derive(Debug, Clone)]
pub struct DeploymentAction {
    pub deployment_key: String,
    pub action_type: DeploymentActionType,
}

#[derive(Debug, Clone)]
pub enum DeploymentActionType {
    CreateOrUpdateAgentSet {
        agent_set: AgentSet,
        strategy: DeploymentStrategy,
    },
    ScaleDown {
        agent_set_name: String,
        replicas: u32,
    },
    DeleteAgentSet {
        agent_set_name: String,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::spec::AgentSpec;

    fn make_deployment(name: &str, replicas: u32) -> AgentDeployment {
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), name.to_string());

        AgentDeployment::new(
            name,
            "default",
            replicas,
            LabelSelector::from_labels(labels.clone()),
            AgentTemplate {
                metadata: ObjectMeta {
                    labels,
                    ..Default::default()
                },
                spec: AgentSpec {
                    model: Some("gpt-4".to_string()),
                    ..Default::default()
                },
            },
        )
    }

    #[test]
    fn test_create_deployment() {
        let dep = make_deployment("triage", 5);
        assert_eq!(dep.spec.replicas, 5);
        assert_eq!(dep.metadata.name, "triage");
    }

    #[test]
    fn test_max_unavailable() {
        let dep = make_deployment("triage", 10);
        assert_eq!(dep.max_unavailable(), 1); // default
    }

    #[test]
    fn test_is_complete() {
        let mut dep = make_deployment("triage", 5);
        assert!(!dep.is_complete());

        dep.status.replicas = 5;
        dep.status.updated_replicas = 5;
        dep.status.ready_replicas = 5;
        dep.status.available_replicas = 5;
        dep.status.observed_generation = dep.metadata.generation;
        assert!(dep.is_complete());
    }

    #[test]
    fn test_controller_apply() {
        let mut controller = DeploymentController::new();
        let dep = make_deployment("triage", 5);

        let result = controller.apply(dep.clone()).unwrap();
        assert_eq!(result, ApplyResult::Created);

        let result = controller.apply(dep).unwrap();
        assert_eq!(result, ApplyResult::Updated);
    }

    #[test]
    fn test_controller_scale() {
        let mut controller = DeploymentController::new();
        controller.apply(make_deployment("triage", 5)).unwrap();

        controller.scale("default", "triage", 10).unwrap();
        let dep = controller.get("default", "triage").unwrap();
        assert_eq!(dep.spec.replicas, 10);
    }

    #[test]
    fn test_controller_pause_resume() {
        let mut controller = DeploymentController::new();
        controller.apply(make_deployment("triage", 5)).unwrap();

        controller.pause("default", "triage").unwrap();
        assert!(controller.get("default", "triage").unwrap().is_paused());

        controller.resume("default", "triage").unwrap();
        assert!(!controller.get("default", "triage").unwrap().is_paused());
    }

    #[test]
    fn test_revision_history() {
        let mut controller = DeploymentController::new();
        controller.apply(make_deployment("triage", 5)).unwrap();

        // Update spec
        let mut dep = make_deployment("triage", 5);
        dep.spec.template.spec.model = Some("gpt-4-turbo".to_string());
        controller.apply(dep).unwrap();

        let history = controller.history("default", "triage");
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_rollback() {
        let mut controller = DeploymentController::new();
        controller.apply(make_deployment("triage", 5)).unwrap();

        // Update to new model
        let mut dep = make_deployment("triage", 5);
        dep.spec.template.spec.model = Some("gpt-4-turbo".to_string());
        controller.apply(dep).unwrap();

        // Rollback
        controller.rollback("default", "triage", None).unwrap();

        let current = controller.get("default", "triage").unwrap();
        assert_eq!(current.spec.template.spec.model, Some("gpt-4".to_string()));
    }
}
