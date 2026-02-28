//! Pipeline Saga Bridge — connects the AAPI pipeline saga to the connector engine.
//!
//! The AAPI Pipeline (`aapi-pipeline`) provides distributed VAKYA execution
//! with saga-based rollback. This bridge module defines the engine-side
//! interface for managing pipeline lifecycles and saga coordination.
//!
//! Architecture:
//! ```text
//! ConnectorEngine → SagaBridge → [VakyaPipeline + SagaCoordinator]
//! ```
//!
//! The bridge tracks pipeline state and provides rollback coordination
//! without pulling in aapi-pipeline's async deps directly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Pipeline Step State
// ═══════════════════════════════════════════════════════════════

/// Status of a pipeline step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    RolledBack,
    Skipped,
}

impl StepStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, StepStatus::Succeeded | StepStatus::Failed | StepStatus::RolledBack | StepStatus::Skipped)
    }

    pub fn is_success(&self) -> bool {
        *self == StepStatus::Succeeded
    }
}

/// A step in a managed pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedStep {
    pub step_id: String,
    pub action: String,
    pub target_cell: Option<String>,
    pub status: StepStatus,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub reversible: bool,
}

// ═══════════════════════════════════════════════════════════════
// Managed Pipeline
// ═══════════════════════════════════════════════════════════════

/// Engine-side pipeline tracker with saga rollback support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedPipeline {
    pub pipeline_id: String,
    pub agent_pid: String,
    pub steps: Vec<ManagedStep>,
    pub status: PipelineStatus,
    pub created_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    Running,
    Succeeded,
    Failed,
    RollingBack,
    RolledBack,
}

impl ManagedPipeline {
    pub fn new(pipeline_id: impl Into<String>, agent_pid: impl Into<String>, now_ms: u64) -> Self {
        Self {
            pipeline_id: pipeline_id.into(),
            agent_pid: agent_pid.into(),
            steps: Vec::new(),
            status: PipelineStatus::Running,
            created_at_ms: now_ms,
            completed_at_ms: None,
        }
    }

    /// Add a step to the pipeline.
    pub fn add_step(&mut self, step_id: impl Into<String>, action: impl Into<String>, reversible: bool) {
        self.steps.push(ManagedStep {
            step_id: step_id.into(),
            action: action.into(),
            target_cell: None,
            status: StepStatus::Pending,
            result: None,
            error: None,
            reversible,
        });
    }

    /// Mark a step as succeeded.
    pub fn step_succeeded(&mut self, step_id: &str, result: serde_json::Value) -> Result<(), String> {
        let step = self.steps.iter_mut().find(|s| s.step_id == step_id)
            .ok_or_else(|| format!("Step not found: {}", step_id))?;
        step.status = StepStatus::Succeeded;
        step.result = Some(result);
        Ok(())
    }

    /// Mark a step as failed — triggers saga rollback of prior steps.
    pub fn step_failed(&mut self, step_id: &str, error: String) -> Result<SagaRollbackPlan, String> {
        let step = self.steps.iter_mut().find(|s| s.step_id == step_id)
            .ok_or_else(|| format!("Step not found: {}", step_id))?;
        step.status = StepStatus::Failed;
        step.error = Some(error.clone());

        self.status = PipelineStatus::RollingBack;

        // Build rollback plan: reverse order of succeeded reversible steps
        let rollback_steps: Vec<String> = self.steps.iter()
            .filter(|s| s.status == StepStatus::Succeeded && s.reversible)
            .rev()
            .map(|s| s.step_id.clone())
            .collect();

        Ok(SagaRollbackPlan {
            pipeline_id: self.pipeline_id.clone(),
            failed_step: step_id.to_string(),
            failure_reason: error,
            steps_to_rollback: rollback_steps,
        })
    }

    /// Mark a step as rolled back.
    pub fn step_rolled_back(&mut self, step_id: &str) {
        if let Some(step) = self.steps.iter_mut().find(|s| s.step_id == step_id) {
            step.status = StepStatus::RolledBack;
        }
        // Check if all rollbacks are complete
        let all_rolled = self.steps.iter()
            .filter(|s| s.reversible && s.status == StepStatus::Succeeded)
            .count() == 0;
        if all_rolled {
            self.status = PipelineStatus::RolledBack;
        }
    }

    /// Mark pipeline as fully succeeded.
    pub fn complete(&mut self, now_ms: u64) {
        self.status = PipelineStatus::Succeeded;
        self.completed_at_ms = Some(now_ms);
    }

    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    pub fn succeeded_count(&self) -> usize {
        self.steps.iter().filter(|s| s.status.is_success()).count()
    }
}

/// A plan for rolling back pipeline steps after failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaRollbackPlan {
    pub pipeline_id: String,
    pub failed_step: String,
    pub failure_reason: String,
    pub steps_to_rollback: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Pipeline Manager
// ═══════════════════════════════════════════════════════════════

/// Manages pipeline lifecycles and saga rollback.
pub struct PipelineManager {
    pipelines: HashMap<String, ManagedPipeline>,
    pub total_pipelines: u64,
    pub total_rollbacks: u64,
}

impl PipelineManager {
    pub fn new() -> Self {
        Self {
            pipelines: HashMap::new(),
            total_pipelines: 0,
            total_rollbacks: 0,
        }
    }

    /// Create a new pipeline.
    pub fn create(&mut self, pipeline_id: impl Into<String>, agent_pid: impl Into<String>, now_ms: u64) -> &mut ManagedPipeline {
        let id = pipeline_id.into();
        self.total_pipelines += 1;
        self.pipelines.insert(id.clone(), ManagedPipeline::new(id.clone(), agent_pid, now_ms));
        self.pipelines.get_mut(&id).unwrap()
    }

    pub fn get(&self, id: &str) -> Option<&ManagedPipeline> {
        self.pipelines.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut ManagedPipeline> {
        self.pipelines.get_mut(id)
    }

    /// Execute saga rollback for a failed pipeline.
    pub fn rollback(&mut self, pipeline_id: &str) -> Result<SagaRollbackPlan, String> {
        let pipeline = self.pipelines.get(pipeline_id)
            .ok_or_else(|| format!("Pipeline not found: {}", pipeline_id))?;

        if pipeline.status != PipelineStatus::RollingBack {
            return Err(format!("Pipeline {} is not in rollback state", pipeline_id));
        }

        self.total_rollbacks += 1;
        let rollback_steps: Vec<String> = pipeline.steps.iter()
            .filter(|s| s.status == StepStatus::Succeeded && s.reversible)
            .rev()
            .map(|s| s.step_id.clone())
            .collect();

        let failed_step = pipeline.steps.iter()
            .find(|s| s.status == StepStatus::Failed)
            .map(|s| s.step_id.clone())
            .unwrap_or_default();

        Ok(SagaRollbackPlan {
            pipeline_id: pipeline_id.to_string(),
            failed_step,
            failure_reason: "saga rollback".into(),
            steps_to_rollback: rollback_steps,
        })
    }

    pub fn active_count(&self) -> usize {
        self.pipelines.values().filter(|p| p.status == PipelineStatus::Running).count()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_lifecycle_success() {
        let mut pipeline = ManagedPipeline::new("pipe:1", "pid:a", 1000);
        pipeline.add_step("step:1", "memory.write", true);
        pipeline.add_step("step:2", "tool.call", true);
        pipeline.add_step("step:3", "memory.seal", false);

        assert_eq!(pipeline.step_count(), 3);
        assert_eq!(pipeline.status, PipelineStatus::Running);

        pipeline.step_succeeded("step:1", serde_json::json!({"ok": true})).unwrap();
        pipeline.step_succeeded("step:2", serde_json::json!({"ok": true})).unwrap();
        pipeline.step_succeeded("step:3", serde_json::json!({"ok": true})).unwrap();
        pipeline.complete(2000);

        assert_eq!(pipeline.status, PipelineStatus::Succeeded);
        assert_eq!(pipeline.succeeded_count(), 3);
        assert_eq!(pipeline.completed_at_ms, Some(2000));
    }

    #[test]
    fn test_pipeline_failure_triggers_rollback_plan() {
        let mut pipeline = ManagedPipeline::new("pipe:2", "pid:a", 1000);
        pipeline.add_step("step:1", "memory.write", true);
        pipeline.add_step("step:2", "tool.call", true);
        pipeline.add_step("step:3", "memory.seal", false);

        pipeline.step_succeeded("step:1", serde_json::json!({})).unwrap();
        pipeline.step_succeeded("step:2", serde_json::json!({})).unwrap();

        // Step 3 fails
        let plan = pipeline.step_failed("step:3", "connection timeout".into()).unwrap();
        assert_eq!(pipeline.status, PipelineStatus::RollingBack);
        assert_eq!(plan.steps_to_rollback, vec!["step:2", "step:1"]); // Reverse order
        assert_eq!(plan.failure_reason, "connection timeout");
    }

    #[test]
    fn test_rollback_marks_steps() {
        let mut pipeline = ManagedPipeline::new("pipe:3", "pid:a", 1000);
        pipeline.add_step("step:1", "write", true);
        pipeline.add_step("step:2", "call", true);

        pipeline.step_succeeded("step:1", serde_json::json!({})).unwrap();
        pipeline.step_succeeded("step:2", serde_json::json!({})).unwrap();
        pipeline.step_failed("step:2", "fail".into()).ok();

        pipeline.step_rolled_back("step:2");
        assert_eq!(pipeline.steps[1].status, StepStatus::RolledBack);
        // step:1 still succeeded → not fully rolled back
        assert_eq!(pipeline.status, PipelineStatus::RollingBack);

        pipeline.step_rolled_back("step:1");
        assert_eq!(pipeline.status, PipelineStatus::RolledBack);
    }

    #[test]
    fn test_non_reversible_steps_excluded_from_rollback() {
        let mut pipeline = ManagedPipeline::new("pipe:4", "pid:a", 1000);
        pipeline.add_step("step:1", "write", true);
        pipeline.add_step("step:2", "audit.log", false); // Not reversible
        pipeline.add_step("step:3", "call", true);

        pipeline.step_succeeded("step:1", serde_json::json!({})).unwrap();
        pipeline.step_succeeded("step:2", serde_json::json!({})).unwrap();

        let plan = pipeline.step_failed("step:3", "error".into()).unwrap();
        // step:2 excluded (not reversible)
        assert_eq!(plan.steps_to_rollback, vec!["step:1"]);
    }

    #[test]
    fn test_pipeline_manager() {
        let mut mgr = PipelineManager::new();
        let pipe = mgr.create("pipe:1", "pid:a", 1000);
        pipe.add_step("s1", "write", true);
        pipe.add_step("s2", "call", true);

        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.total_pipelines, 1);

        let pipe = mgr.get_mut("pipe:1").unwrap();
        pipe.step_succeeded("s1", serde_json::json!({})).unwrap();
        pipe.step_succeeded("s2", serde_json::json!({})).unwrap();
        pipe.complete(2000);

        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_manager_rollback() {
        let mut mgr = PipelineManager::new();
        let pipe = mgr.create("pipe:r", "pid:a", 1000);
        pipe.add_step("s1", "write", true);
        pipe.add_step("s2", "call", true);

        let pipe = mgr.get_mut("pipe:r").unwrap();
        pipe.step_succeeded("s1", serde_json::json!({})).unwrap();
        pipe.step_failed("s2", "boom".into()).unwrap();

        let plan = mgr.rollback("pipe:r").unwrap();
        assert_eq!(plan.steps_to_rollback, vec!["s1"]);
        assert_eq!(mgr.total_rollbacks, 1);
    }

    #[test]
    fn test_step_status_properties() {
        assert!(StepStatus::Succeeded.is_terminal());
        assert!(StepStatus::Failed.is_terminal());
        assert!(StepStatus::RolledBack.is_terminal());
        assert!(!StepStatus::Pending.is_terminal());
        assert!(!StepStatus::Running.is_terminal());
        assert!(StepStatus::Succeeded.is_success());
        assert!(!StepStatus::Failed.is_success());
    }

    #[test]
    fn test_step_not_found_error() {
        let mut pipeline = ManagedPipeline::new("pipe:e", "pid:a", 1000);
        assert!(pipeline.step_succeeded("nonexistent", serde_json::json!({})).is_err());
        assert!(pipeline.step_failed("nonexistent", "err".into()).is_err());
    }
}
