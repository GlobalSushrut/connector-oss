//! Distributed VAKYA pipeline engine.
//!
//! A `VakyaPipeline` chains multiple `PipelineStep`s across cells.
//! Each step wraps a VAKYA, may target a local or remote cell, and
//! declares dependencies on other steps. Execution respects the
//! dependency DAG and triggers saga rollback on failure.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use aapi_adapters::effect::CapturedEffect;
use aapi_adapters::traits::{ExecutionContext, ExecutionResult};
use aapi_adapters::registry::Dispatcher;
use aapi_core::Vakya;

use crate::error::{PipelineError, PipelineResult};
use crate::router::{RouteTarget, VakyaRouter};

// ============================================================================
// Pipeline Types
// ============================================================================

/// Status of a single pipeline step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running { cell_id: String, started_at: i64 },
    Completed { duration_ms: u64 },
    Failed { error: String },
    Skipped { reason: String },
    RolledBack,
}

impl StepStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            StepStatus::Completed { .. }
                | StepStatus::Failed { .. }
                | StepStatus::Skipped { .. }
                | StepStatus::RolledBack
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self, StepStatus::Completed { .. })
    }
}

/// Overall pipeline state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineState {
    Building,
    Running,
    Completed,
    Failed,
    RollingBack,
    RolledBack,
}

/// A single step in the pipeline.
#[derive(Debug, Clone)]
pub struct PipelineStep {
    pub step_id: String,
    pub vakya: Vakya,
    /// `None` = decide at runtime via router. `Some(cell_id)` = pinned.
    pub target_cell: Option<String>,
    /// Step IDs this step depends on (must complete first).
    pub depends_on: Vec<String>,
    /// Captured effects after execution (for rollback).
    pub effects: Vec<CapturedEffect>,
    pub status: StepStatus,
}

impl PipelineStep {
    pub fn new(step_id: impl Into<String>, vakya: Vakya) -> Self {
        Self {
            step_id: step_id.into(),
            vakya,
            target_cell: None,
            depends_on: Vec::new(),
            effects: Vec::new(),
            status: StepStatus::Pending,
        }
    }

    pub fn with_target(mut self, cell_id: impl Into<String>) -> Self {
        self.target_cell = Some(cell_id.into());
        self
    }

    pub fn with_dependency(mut self, dep: impl Into<String>) -> Self {
        self.depends_on.push(dep.into());
        self
    }

    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.depends_on = deps;
        self
    }
}

/// Result of a completed pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult2 {
    pub pipeline_id: String,
    pub state: PipelineState,
    pub steps_completed: usize,
    pub steps_failed: usize,
    pub total_duration_ms: u64,
    pub step_results: HashMap<String, StepOutcome>,
}

/// Outcome of a single step (for the result).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepOutcome {
    pub step_id: String,
    pub status: StepStatus,
    pub result_data: Option<serde_json::Value>,
    pub effects: Vec<CapturedEffect>,
}

// ============================================================================
// VakyaPipeline
// ============================================================================

/// A distributed VAKYA pipeline — chain of steps across cells.
pub struct VakyaPipeline {
    pub pipeline_id: String,
    pub steps: Vec<PipelineStep>,
    pub state: PipelineState,
    pub local_cell_id: String,
    step_results: HashMap<String, ExecutionResult>,
}

impl VakyaPipeline {
    pub fn new(pipeline_id: impl Into<String>, local_cell_id: impl Into<String>) -> Self {
        Self {
            pipeline_id: pipeline_id.into(),
            steps: Vec::new(),
            state: PipelineState::Building,
            local_cell_id: local_cell_id.into(),
            step_results: HashMap::new(),
        }
    }

    /// Add a step to the pipeline.
    pub fn add_step(&mut self, step: PipelineStep) {
        self.steps.push(step);
    }

    /// Validate the pipeline DAG: check for missing deps and cycles.
    pub fn validate(&self) -> PipelineResult<()> {
        let step_ids: HashSet<&str> = self.steps.iter().map(|s| s.step_id.as_str()).collect();

        // Check all dependencies exist
        for step in &self.steps {
            for dep in &step.depends_on {
                if !step_ids.contains(dep.as_str()) {
                    return Err(PipelineError::DependencyNotMet {
                        step_id: step.step_id.clone(),
                        dependency: dep.clone(),
                    });
                }
            }
        }

        // Check for cycles via topological sort (Kahn's algorithm)
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for step in &self.steps {
            in_degree.entry(step.step_id.as_str()).or_insert(0);
            adj.entry(step.step_id.as_str()).or_default();
            for dep in &step.depends_on {
                adj.entry(dep.as_str()).or_default().push(step.step_id.as_str());
                *in_degree.entry(step.step_id.as_str()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();
        let mut visited = 0usize;

        while let Some(node) = queue.pop() {
            visited += 1;
            if let Some(neighbors) = adj.get(node) {
                for &neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(neighbor);
                        }
                    }
                }
            }
        }

        if visited != self.steps.len() {
            return Err(PipelineError::CircularDependency(
                "cycle detected in pipeline DAG".into(),
            ));
        }

        Ok(())
    }

    /// Compute a topological execution order.
    pub fn execution_order(&self) -> PipelineResult<Vec<usize>> {
        self.validate()?;

        let id_to_idx: HashMap<&str, usize> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| (s.step_id.as_str(), i))
            .collect();

        let mut in_degree: Vec<usize> = vec![0; self.steps.len()];
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); self.steps.len()];

        for (i, step) in self.steps.iter().enumerate() {
            for dep in &step.depends_on {
                let dep_idx = id_to_idx[dep.as_str()];
                adj[dep_idx].push(i);
                in_degree[i] += 1;
            }
        }

        let mut queue: Vec<usize> = in_degree
            .iter()
            .enumerate()
            .filter(|(_, &d)| d == 0)
            .map(|(i, _)| i)
            .collect();
        let mut order = Vec::with_capacity(self.steps.len());

        while let Some(idx) = queue.pop() {
            order.push(idx);
            for &neighbor in &adj[idx] {
                in_degree[neighbor] -= 1;
                if in_degree[neighbor] == 0 {
                    queue.push(neighbor);
                }
            }
        }

        Ok(order)
    }

    /// Execute the pipeline locally.
    ///
    /// Steps are executed in topological order. Remote steps are recorded
    /// as skipped (actual remote forwarding requires an EventBus, handled
    /// by the ClusterGateway in D12).
    pub async fn execute(
        &mut self,
        dispatcher: &Dispatcher,
        router: &VakyaRouter,
    ) -> PipelineResult<PipelineResult2> {
        if self.state == PipelineState::Running {
            return Err(PipelineError::AlreadyRunning);
        }
        if self.state != PipelineState::Building {
            return Err(PipelineError::InvalidState(format!("{:?}", self.state)));
        }

        self.validate()?;
        self.state = PipelineState::Running;

        let order = self.execution_order()?;
        let pipeline_start = Instant::now();
        let mut completed_step_ids: HashSet<String> = HashSet::new();

        for idx in &order {
            // Clone needed data upfront to avoid borrow conflicts
            let step_id = self.steps[*idx].step_id.clone();
            let deps = self.steps[*idx].depends_on.clone();
            let target_cell = self.steps[*idx].target_cell.clone();
            let vakya = self.steps[*idx].vakya.clone();

            // Check dependencies are met
            let deps_met = deps.iter().all(|dep| completed_step_ids.contains(dep));

            if !deps_met {
                // A dependency failed — skip this step
                self.steps[*idx].status = StepStatus::Skipped {
                    reason: "dependency not completed".into(),
                };
                continue;
            }

            // Determine routing target
            let target = match &target_cell {
                Some(cell_id) => {
                    if cell_id == &self.local_cell_id || cell_id == "local" {
                        RouteTarget::Local
                    } else {
                        RouteTarget::Remote {
                            cell_id: cell_id.clone(),
                        }
                    }
                }
                None => router.route_vakya(&vakya, &self.local_cell_id),
            };

            match target {
                RouteTarget::Local => {
                    let ctx = ExecutionContext::new(&step_id);
                    let started_at = chrono::Utc::now().timestamp();
                    self.steps[*idx].status = StepStatus::Running {
                        cell_id: self.local_cell_id.clone(),
                        started_at,
                    };

                    debug!(
                        pipeline = %self.pipeline_id,
                        step = %step_id,
                        "Executing step locally"
                    );

                    let exec_start = Instant::now();
                    let result = dispatcher.dispatch(&vakya, &ctx).await;
                    let duration_ms = exec_start.elapsed().as_millis() as u64;

                    match result {
                        Ok(exec_result) => {
                            self.steps[*idx].effects = exec_result.effects.clone();
                            self.steps[*idx].status =
                                StepStatus::Completed { duration_ms };
                            self.step_results
                                .insert(step_id.clone(), exec_result);
                            completed_step_ids.insert(step_id);
                        }
                        Err(e) => {
                            let error_msg = e.to_string();
                            warn!(
                                pipeline = %self.pipeline_id,
                                step = %step_id,
                                error = %error_msg,
                                "Step failed"
                            );
                            self.steps[*idx].status = StepStatus::Failed {
                                error: error_msg.clone(),
                            };
                            self.state = PipelineState::Failed;

                            return Ok(self.build_result(pipeline_start));
                        }
                    }
                }
                RouteTarget::Remote { cell_id } => {
                    // Remote execution placeholder — actual forwarding via EventBus
                    // is implemented in D12 (ClusterGateway).
                    debug!(
                        pipeline = %self.pipeline_id,
                        step = %step_id,
                        target_cell = %cell_id,
                        "Step routed to remote cell (placeholder)"
                    );
                    self.steps[*idx].status = StepStatus::Skipped {
                        reason: format!("remote execution on cell {} (not yet wired)", cell_id),
                    };
                }
            }
        }

        self.state = PipelineState::Completed;
        Ok(self.build_result(pipeline_start))
    }

    /// Build the pipeline result summary.
    fn build_result(&self, start: Instant) -> PipelineResult2 {
        let mut step_results = HashMap::new();
        let mut completed = 0usize;
        let mut failed = 0usize;

        for step in &self.steps {
            if step.status.is_success() {
                completed += 1;
            }
            if matches!(step.status, StepStatus::Failed { .. }) {
                failed += 1;
            }

            let result_data = self
                .step_results
                .get(&step.step_id)
                .and_then(|r| r.data.clone());

            step_results.insert(
                step.step_id.clone(),
                StepOutcome {
                    step_id: step.step_id.clone(),
                    status: step.status.clone(),
                    result_data,
                    effects: step.effects.clone(),
                },
            );
        }

        PipelineResult2 {
            pipeline_id: self.pipeline_id.clone(),
            state: self.state,
            steps_completed: completed,
            steps_failed: failed,
            total_duration_ms: start.elapsed().as_millis() as u64,
            step_results,
        }
    }

    /// Get the status of a specific step.
    pub fn step_status(&self, step_id: &str) -> Option<&StepStatus> {
        self.steps
            .iter()
            .find(|s| s.step_id == step_id)
            .map(|s| &s.status)
    }

    /// Get completed steps in execution order (for saga rollback).
    pub fn completed_steps(&self) -> Vec<&PipelineStep> {
        self.steps
            .iter()
            .filter(|s| s.status.is_success())
            .collect()
    }

    /// Number of steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}
