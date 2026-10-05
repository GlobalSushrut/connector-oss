//! # Container Model
//!
//! A container is a **governed mounted memory volume** — not just a folder or
//! a bucket prefix. Each container binds together all five fabric layers:
//! commit stream scope, object namespace, metadata scope, vector scope,
//! continuity scope, and policy/retention/evidence rules.
//!
//! ## Container Types
//!
//! | Type | URI | Purpose |
//! |------|-----|---------|
//! | Agent | `mem://agent/{id}` | Private memory for one agent |
//! | Shared | `mem://shared/{scope}` | Joint memory for collaborating agents |
//! | Organizational | `mem://org/{domain}` | Tenant-level curated memory |
//! | Evidence | `mem://system/evidence` | Proof bundles, receipts, audit |
//! | Projection | `mem://projection/{src}_to_{dst}` | Policy-controlled derived view |

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::types::*;

// =============================================================================
// ContainerPolicy — access and resource policy
// =============================================================================

/// Access control and resource limits for a memory container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPolicy {
    pub visibility: Visibility,
    pub read_agents: Vec<String>,
    pub write_agents: Vec<String>,
    pub max_objects: u64,
    pub max_size_bytes: u64,
    pub encryption_required: bool,
    pub evidence_required: bool,
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            visibility: Visibility::Private,
            read_agents: Vec::new(),
            write_agents: Vec::new(),
            max_objects: 0,       // 0 = unlimited
            max_size_bytes: 0,    // 0 = unlimited
            encryption_required: false,
            evidence_required: false,
        }
    }
}

// =============================================================================
// RetentionPolicy — lifecycle management
// =============================================================================

/// Retention rules governing memory lifecycle within a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Default retention class for new objects.
    pub default_class: RetentionClass,
    /// Time before hot → warm transition (ms, 0 = no auto-transition).
    pub hot_to_warm_ms: u64,
    /// Time before warm → cold transition (ms).
    pub warm_to_cold_ms: u64,
    /// Time before cold → archive transition (ms).
    pub cold_to_archive_ms: u64,
    /// Time before deletion (ms, 0 = no auto-delete).
    pub delete_after_ms: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_class: RetentionClass::LongTerm,
            hot_to_warm_ms: 24 * 3600 * 1000,          // 24 hours
            warm_to_cold_ms: 30 * 24 * 3600 * 1000,    // 30 days
            cold_to_archive_ms: 365 * 24 * 3600 * 1000, // 1 year
            delete_after_ms: 0,                          // never
        }
    }
}

// =============================================================================
// ContainerState
// =============================================================================

/// Lifecycle state of a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    Active,
    Suspended,
    ReadOnly,
    Archiving,
    Deleted,
}

// =============================================================================
// ContainerStats
// =============================================================================

/// Runtime statistics for a container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerStats {
    pub object_count: u64,
    pub total_bytes: u64,
    pub event_count: u64,
    pub vector_count: u64,
    pub continuity_nodes: u64,
    pub last_write_at: i64,
}

// =============================================================================
// MemoryContainer
// =============================================================================

/// A governed memory volume binding all fabric layers together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryContainer {
    pub container_id: String,
    pub container_type: ContainerType,
    pub tenant_id: String,
    pub owner_ids: Vec<String>,

    // Fabric scope bindings
    pub stream_scope: String,
    pub object_namespace: String,

    // Policy
    pub policy: ContainerPolicy,
    pub retention: RetentionPolicy,

    // Lifecycle
    pub created_at: i64,
    pub updated_at: i64,
    pub state: ContainerState,

    // Stats (updated lazily)
    pub stats: ContainerStats,
}

impl MemoryContainer {
    /// Create an agent-private container.
    pub fn agent(tenant_id: &str, agent_id: &str) -> Self {
        let container_id = format!("mem://agent/{}", agent_id);
        Self {
            container_id: container_id.clone(),
            container_type: ContainerType::Agent,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![agent_id.to_string()],
            stream_scope: format!("stream://{}/agent_{}/episodic", tenant_id, agent_id),
            object_namespace: format!("tenants/{}/containers/agent_{}", tenant_id, agent_id),
            policy: ContainerPolicy {
                visibility: Visibility::Private,
                read_agents: vec![agent_id.to_string()],
                write_agents: vec![agent_id.to_string()],
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create a shared container for collaborating agents.
    pub fn shared(tenant_id: &str, scope: &str, agent_ids: &[&str]) -> Self {
        let container_id = format!("mem://shared/{}", scope);
        Self {
            container_id,
            container_type: ContainerType::Shared,
            tenant_id: tenant_id.to_string(),
            owner_ids: agent_ids.iter().map(|s| s.to_string()).collect(),
            stream_scope: format!("stream://{}/shared_{}/episodic", tenant_id, scope),
            object_namespace: format!("tenants/{}/containers/shared_{}", tenant_id, scope),
            policy: ContainerPolicy {
                visibility: Visibility::Shared,
                read_agents: agent_ids.iter().map(|s| s.to_string()).collect(),
                write_agents: agent_ids.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create an organizational container.
    pub fn organizational(tenant_id: &str, domain: &str) -> Self {
        let container_id = format!("mem://org/{}", domain);
        Self {
            container_id,
            container_type: ContainerType::Organizational,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![],
            stream_scope: format!("stream://{}/org_{}/all", tenant_id, domain),
            object_namespace: format!("tenants/{}/containers/org_{}", tenant_id, domain),
            policy: ContainerPolicy {
                visibility: Visibility::Organizational,
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create an evidence container.
    pub fn evidence(tenant_id: &str) -> Self {
        Self {
            container_id: "mem://system/evidence".to_string(),
            container_type: ContainerType::Evidence,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![],
            stream_scope: format!("stream://{}/system/evidence", tenant_id),
            object_namespace: format!("tenants/{}/containers/system_evidence", tenant_id),
            policy: ContainerPolicy {
                visibility: Visibility::System,
                encryption_required: true,
                evidence_required: true,
                ..Default::default()
            },
            retention: RetentionPolicy {
                default_class: RetentionClass::Evidence,
                delete_after_ms: 0,
                ..Default::default()
            },
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create a projection container (derived view from source to destination).
    pub fn projection(tenant_id: &str, source_id: &str, dest_id: &str) -> Self {
        let scope = format!("{}_to_{}", source_id, dest_id);
        Self {
            container_id: format!("mem://projection/{}", scope),
            container_type: ContainerType::Projection,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![source_id.to_string()],
            stream_scope: format!("stream://{}/projection_{}", tenant_id, scope),
            object_namespace: format!("tenants/{}/containers/projection_{}", tenant_id, scope),
            policy: ContainerPolicy {
                visibility: Visibility::Shared,
                read_agents: vec![dest_id.to_string()],
                write_agents: vec![source_id.to_string()],
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Check if an agent has read access.
    pub fn can_read(&self, agent_id: &str) -> bool {
        match self.policy.visibility {
            Visibility::Public | Visibility::System => true,
            Visibility::Organizational => true,
            _ => self.policy.read_agents.contains(&agent_id.to_string())
                || self.owner_ids.contains(&agent_id.to_string()),
        }
    }

    /// Check if an agent has write access.
    pub fn can_write(&self, agent_id: &str) -> bool {
        if self.state != ContainerState::Active {
            return false;
        }
        self.policy.write_agents.contains(&agent_id.to_string())
            || self.owner_ids.contains(&agent_id.to_string())
    }

    /// URI for this container.
    pub fn uri(&self) -> &str {
        &self.container_id
    }

    // =========================================================================
    // ML / Neural Network / Data Science Containers
    // =========================================================================

    /// Create a model registry container for versioned neural network weights,
    /// configs, ONNX exports, safetensors, and training metadata.
    pub fn model_registry(tenant_id: &str, registry_name: &str, owner_ids: &[&str]) -> Self {
        let container_id = format!("mem://models/{}", registry_name);
        Self {
            container_id,
            container_type: ContainerType::ModelRegistry,
            tenant_id: tenant_id.to_string(),
            owner_ids: owner_ids.iter().map(|s| s.to_string()).collect(),
            stream_scope: format!("stream://{}/models_{}/all", tenant_id, registry_name),
            object_namespace: format!("tenants/{}/containers/models_{}", tenant_id, registry_name),
            policy: ContainerPolicy {
                visibility: Visibility::Shared,
                read_agents: owner_ids.iter().map(|s| s.to_string()).collect(),
                write_agents: owner_ids.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            retention: RetentionPolicy {
                default_class: RetentionClass::Permanent,
                ..Default::default()
            },
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create a dataset container for training/evaluation data shards,
    /// versioned datasets, and data lineage tracking.
    pub fn dataset(tenant_id: &str, dataset_name: &str, owner_ids: &[&str]) -> Self {
        let container_id = format!("mem://dataset/{}", dataset_name);
        Self {
            container_id,
            container_type: ContainerType::Dataset,
            tenant_id: tenant_id.to_string(),
            owner_ids: owner_ids.iter().map(|s| s.to_string()).collect(),
            stream_scope: format!("stream://{}/dataset_{}/all", tenant_id, dataset_name),
            object_namespace: format!("tenants/{}/containers/dataset_{}", tenant_id, dataset_name),
            policy: ContainerPolicy {
                visibility: Visibility::Shared,
                read_agents: owner_ids.iter().map(|s| s.to_string()).collect(),
                write_agents: owner_ids.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create an experiment container for tracking training runs, metrics,
    /// hyperparameters, gradient snapshots, and evaluation results.
    pub fn experiment(tenant_id: &str, experiment_name: &str, owner_id: &str) -> Self {
        let container_id = format!("mem://experiment/{}", experiment_name);
        Self {
            container_id,
            container_type: ContainerType::Experiment,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![owner_id.to_string()],
            stream_scope: format!("stream://{}/experiment_{}/all", tenant_id, experiment_name),
            object_namespace: format!("tenants/{}/containers/experiment_{}", tenant_id, experiment_name),
            policy: ContainerPolicy {
                visibility: Visibility::Private,
                read_agents: vec![owner_id.to_string()],
                write_agents: vec![owner_id.to_string()],
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    // =========================================================================
    // Sensor / Robotics / Embodied Agent Containers
    // =========================================================================

    /// Create a sensor stream container for continuous sensor data ingestion
    /// (accelerometer, gyroscope, LiDAR, GPS, temperature, camera feeds, etc.).
    pub fn sensor_stream(tenant_id: &str, sensor_name: &str, agent_id: &str) -> Self {
        let container_id = format!("mem://sensor/{}", sensor_name);
        Self {
            container_id,
            container_type: ContainerType::SensorStream,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![agent_id.to_string()],
            stream_scope: format!("stream://{}/sensor_{}/ingest", tenant_id, sensor_name),
            object_namespace: format!("tenants/{}/containers/sensor_{}", tenant_id, sensor_name),
            policy: ContainerPolicy {
                visibility: Visibility::Private,
                read_agents: vec![agent_id.to_string()],
                write_agents: vec![agent_id.to_string()],
                ..Default::default()
            },
            retention: RetentionPolicy {
                default_class: RetentionClass::ShortTerm,
                hot_to_warm_ms: 3600 * 1000,            // 1 hour
                warm_to_cold_ms: 24 * 3600 * 1000,      // 1 day
                cold_to_archive_ms: 7 * 24 * 3600 * 1000, // 1 week
                delete_after_ms: 30 * 24 * 3600 * 1000,   // 30 days
            },
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create a perception pipeline container for object detection, segmentation,
    /// scene understanding, SLAM, and other perception outputs.
    pub fn perception_pipeline(tenant_id: &str, pipeline_name: &str, agent_ids: &[&str]) -> Self {
        let container_id = format!("mem://perception/{}", pipeline_name);
        Self {
            container_id,
            container_type: ContainerType::PerceptionPipeline,
            tenant_id: tenant_id.to_string(),
            owner_ids: agent_ids.iter().map(|s| s.to_string()).collect(),
            stream_scope: format!("stream://{}/perception_{}/output", tenant_id, pipeline_name),
            object_namespace: format!("tenants/{}/containers/perception_{}", tenant_id, pipeline_name),
            policy: ContainerPolicy {
                visibility: Visibility::Shared,
                read_agents: agent_ids.iter().map(|s| s.to_string()).collect(),
                write_agents: agent_ids.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            retention: RetentionPolicy::default(),
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }

    /// Create an actuation log container for recording motor commands,
    /// servo positions, actuator states, and control signals.
    pub fn actuation_log(tenant_id: &str, actuator_name: &str, agent_id: &str) -> Self {
        let container_id = format!("mem://actuation/{}", actuator_name);
        Self {
            container_id,
            container_type: ContainerType::ActuationLog,
            tenant_id: tenant_id.to_string(),
            owner_ids: vec![agent_id.to_string()],
            stream_scope: format!("stream://{}/actuation_{}/log", tenant_id, actuator_name),
            object_namespace: format!("tenants/{}/containers/actuation_{}", tenant_id, actuator_name),
            policy: ContainerPolicy {
                visibility: Visibility::Private,
                read_agents: vec![agent_id.to_string()],
                write_agents: vec![agent_id.to_string()],
                evidence_required: true,
                ..Default::default()
            },
            retention: RetentionPolicy {
                default_class: RetentionClass::LongTerm,
                ..Default::default()
            },
            created_at: now_ms(),
            updated_at: now_ms(),
            state: ContainerState::Active,
            stats: ContainerStats::default(),
        }
    }
}

// =============================================================================
// ContainerRegistry — manages all containers for a tenant
// =============================================================================

/// Registry of all memory containers for a tenant.
#[derive(Debug, Default)]
pub struct ContainerRegistry {
    containers: HashMap<String, MemoryContainer>,
    /// Index: agent_id → container_ids they can access
    agent_index: HashMap<String, Vec<String>>,
}

impl ContainerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new container.
    pub fn register(&mut self, container: MemoryContainer) -> Result<(), String> {
        if self.containers.contains_key(&container.container_id) {
            return Err(format!("Container already exists: {}", container.container_id));
        }

        // Update agent index (deduplicate across read/write/owner lists)
        let mut seen_agents = std::collections::HashSet::new();
        for agent_id in container.policy.read_agents.iter()
            .chain(container.policy.write_agents.iter())
            .chain(container.owner_ids.iter())
        {
            if seen_agents.insert(agent_id.clone()) {
                self.agent_index
                    .entry(agent_id.clone())
                    .or_default()
                    .push(container.container_id.clone());
            }
        }

        self.containers.insert(container.container_id.clone(), container);
        Ok(())
    }

    /// Get a container by ID.
    pub fn get(&self, container_id: &str) -> Option<&MemoryContainer> {
        self.containers.get(container_id)
    }

    /// Get a mutable container by ID.
    pub fn get_mut(&mut self, container_id: &str) -> Option<&mut MemoryContainer> {
        self.containers.get_mut(container_id)
    }

    /// Remove a container (marks as deleted, does not destroy data).
    pub fn remove(&mut self, container_id: &str) -> bool {
        if let Some(c) = self.containers.get_mut(container_id) {
            c.state = ContainerState::Deleted;
            c.updated_at = now_ms();
            true
        } else {
            false
        }
    }

    /// Get all containers accessible by an agent.
    pub fn containers_for_agent(&self, agent_id: &str) -> Vec<&MemoryContainer> {
        self.agent_index
            .get(agent_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.containers.get(id))
                    .filter(|c| c.state != ContainerState::Deleted)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all containers of a specific type.
    pub fn containers_by_type(&self, ct: ContainerType) -> Vec<&MemoryContainer> {
        self.containers.values()
            .filter(|c| c.container_type == ct && c.state != ContainerState::Deleted)
            .collect()
    }

    /// Get all active containers.
    pub fn active_containers(&self) -> Vec<&MemoryContainer> {
        self.containers.values()
            .filter(|c| c.state == ContainerState::Active)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.containers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_container() {
        let c = MemoryContainer::agent("acme", "pid:001");
        assert_eq!(c.container_type, ContainerType::Agent);
        assert_eq!(c.container_id, "mem://agent/pid:001");
        assert!(c.can_read("pid:001"));
        assert!(c.can_write("pid:001"));
        assert!(!c.can_read("pid:002"));
        assert!(!c.can_write("pid:002"));
    }

    #[test]
    fn test_shared_container() {
        let c = MemoryContainer::shared("acme", "team_ops", &["pid:001", "pid:002"]);
        assert_eq!(c.container_type, ContainerType::Shared);
        assert!(c.can_read("pid:001"));
        assert!(c.can_read("pid:002"));
        assert!(c.can_write("pid:001"));
        assert!(!c.can_read("pid:003"));
    }

    #[test]
    fn test_evidence_container() {
        let c = MemoryContainer::evidence("acme");
        assert_eq!(c.container_type, ContainerType::Evidence);
        assert!(c.policy.encryption_required);
        assert!(c.policy.evidence_required);
        assert_eq!(c.retention.default_class, RetentionClass::Evidence);
    }

    #[test]
    fn test_projection_container() {
        let c = MemoryContainer::projection("acme", "pid:001", "shared_AB");
        assert_eq!(c.container_type, ContainerType::Projection);
        assert!(c.can_write("pid:001"));
        assert!(!c.can_write("shared_AB"));
        assert!(c.can_read("shared_AB"));
    }

    #[test]
    fn test_container_state_blocks_writes() {
        let mut c = MemoryContainer::agent("acme", "pid:001");
        assert!(c.can_write("pid:001"));

        c.state = ContainerState::ReadOnly;
        assert!(!c.can_write("pid:001"));
        assert!(c.can_read("pid:001"));
    }

    #[test]
    fn test_container_registry() {
        let mut reg = ContainerRegistry::new();

        let c1 = MemoryContainer::agent("acme", "pid:001");
        let c2 = MemoryContainer::agent("acme", "pid:002");
        let shared = MemoryContainer::shared("acme", "team", &["pid:001", "pid:002"]);

        reg.register(c1).unwrap();
        reg.register(c2).unwrap();
        reg.register(shared).unwrap();

        assert_eq!(reg.len(), 3);

        let agent_containers = reg.containers_for_agent("pid:001");
        assert_eq!(agent_containers.len(), 2); // own + shared

        let shared_containers = reg.containers_by_type(ContainerType::Shared);
        assert_eq!(shared_containers.len(), 1);
    }

    #[test]
    fn test_container_registry_duplicate() {
        let mut reg = ContainerRegistry::new();
        let c = MemoryContainer::agent("acme", "pid:001");
        reg.register(c.clone()).unwrap();
        assert!(reg.register(c).is_err());
    }

    #[test]
    fn test_container_registry_remove() {
        let mut reg = ContainerRegistry::new();
        reg.register(MemoryContainer::agent("acme", "pid:001")).unwrap();
        assert_eq!(reg.active_containers().len(), 1);

        reg.remove("mem://agent/pid:001");
        assert_eq!(reg.active_containers().len(), 0);
        assert_eq!(reg.len(), 1); // still exists, just deleted state
    }

    #[test]
    fn test_organizational_container() {
        let c = MemoryContainer::organizational("acme", "medical");
        assert_eq!(c.container_id, "mem://org/medical");
        assert_eq!(c.policy.visibility, Visibility::Organizational);
        // Organizational is readable by all agents in the org
        assert!(c.can_read("anyone"));
    }

    // ── ML / Neural Network Container Tests ──

    #[test]
    fn test_model_registry_container() {
        let c = MemoryContainer::model_registry("acme", "vision_models", &["trainer:001", "deployer:002"]);
        assert_eq!(c.container_type, ContainerType::ModelRegistry);
        assert_eq!(c.container_id, "mem://models/vision_models");
        assert_eq!(c.retention.default_class, RetentionClass::Permanent);
        assert!(c.can_read("trainer:001"));
        assert!(c.can_write("deployer:002"));
        assert!(!c.can_read("outsider:999"));
    }

    #[test]
    fn test_dataset_container() {
        let c = MemoryContainer::dataset("acme", "imagenet_v2", &["data_eng:001"]);
        assert_eq!(c.container_type, ContainerType::Dataset);
        assert_eq!(c.container_id, "mem://dataset/imagenet_v2");
        assert!(c.can_write("data_eng:001"));
    }

    #[test]
    fn test_experiment_container() {
        let c = MemoryContainer::experiment("acme", "resnet_finetune_run3", "researcher:001");
        assert_eq!(c.container_type, ContainerType::Experiment);
        assert_eq!(c.policy.visibility, Visibility::Private);
        assert!(c.can_write("researcher:001"));
        assert!(!c.can_read("researcher:002"));
    }

    // ── Sensor / Robotics Container Tests ──

    #[test]
    fn test_sensor_stream_container() {
        let c = MemoryContainer::sensor_stream("acme", "imu_front", "robot:001");
        assert_eq!(c.container_type, ContainerType::SensorStream);
        assert_eq!(c.container_id, "mem://sensor/imu_front");
        assert_eq!(c.retention.default_class, RetentionClass::ShortTerm);
        assert!(c.retention.delete_after_ms > 0); // auto-delete enabled
        assert!(c.can_write("robot:001"));
    }

    #[test]
    fn test_perception_pipeline_container() {
        let c = MemoryContainer::perception_pipeline("acme", "obstacle_detect", &["lidar:001", "camera:002"]);
        assert_eq!(c.container_type, ContainerType::PerceptionPipeline);
        assert!(c.can_read("lidar:001"));
        assert!(c.can_write("camera:002"));
    }

    #[test]
    fn test_actuation_log_container() {
        let c = MemoryContainer::actuation_log("acme", "arm_servos", "robot:001");
        assert_eq!(c.container_type, ContainerType::ActuationLog);
        assert!(c.policy.evidence_required); // actuation needs audit trail
        assert!(c.can_write("robot:001"));
    }

    #[test]
    fn test_registry_with_ml_containers() {
        let mut reg = ContainerRegistry::new();
        reg.register(MemoryContainer::model_registry("acme", "nlp", &["t:1"])).unwrap();
        reg.register(MemoryContainer::dataset("acme", "corpus", &["t:1"])).unwrap();
        reg.register(MemoryContainer::sensor_stream("acme", "imu", "r:1")).unwrap();

        assert_eq!(reg.containers_by_type(ContainerType::ModelRegistry).len(), 1);
        assert_eq!(reg.containers_by_type(ContainerType::Dataset).len(), 1);
        assert_eq!(reg.containers_by_type(ContainerType::SensorStream).len(), 1);
    }
}
