//! Distributed VAKYA pipeline engine.
//!
//! A `VakyaPipeline` chains multiple `PipelineStep`s across cells.
//! Each step wraps a VAKYA, may target a local or remote cell, and
//! declares dependencies on other steps. Execution respects the
//! dependency DAG and triggers saga rollback on failure.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use aapi_adapters::effect::CapturedEffect;
use aapi_adapters::traits::{ExecutionContext, ExecutionResult};
use aapi_adapters::registry::Dispatcher;
use aapi_core::Vakya;
use vac_bus::{EventBus, ReplicationEvent, ReplicationOp};

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
    remote_bus: Option<Arc<dyn EventBus>>,
    step_results: HashMap<String, ExecutionResult>,
}

#[async_trait]
pub trait ProposerPhaseGuard: Send + Sync {
    async fn enter_read_only(&self, proposer_pid: &str) -> PipelineResult<()>;
    async fn restore_active(&self, proposer_pid: &str) -> PipelineResult<()>;
}

#[derive(Default)]
pub struct NoopPhaseGuard;

#[async_trait]
impl ProposerPhaseGuard for NoopPhaseGuard {
    async fn enter_read_only(&self, _proposer_pid: &str) -> PipelineResult<()> {
        Ok(())
    }

    async fn restore_active(&self, _proposer_pid: &str) -> PipelineResult<()> {
        Ok(())
    }
}

impl VakyaPipeline {
    pub fn new(pipeline_id: impl Into<String>, local_cell_id: impl Into<String>) -> Self {
        Self {
            pipeline_id: pipeline_id.into(),
            steps: Vec::new(),
            state: PipelineState::Building,
            local_cell_id: local_cell_id.into(),
            remote_bus: None,
            step_results: HashMap::new(),
        }
    }

    pub fn with_event_bus(mut self, remote_bus: Arc<dyn EventBus>) -> Self {
        self.remote_bus = Some(remote_bus);
        self
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

    /// Execute the pipeline.
    ///
    /// Steps are executed in topological order. Remote steps are forwarded
    /// over the EventBus when configured; otherwise they are skipped.
    pub async fn execute(
        &mut self,
        dispatcher: &Dispatcher,
        router: &VakyaRouter,
    ) -> PipelineResult<PipelineResult2> {
        self.execute_with_phase_guard(dispatcher, router, &NoopPhaseGuard).await
    }

    pub async fn execute_with_phase_guard(
        &mut self,
        dispatcher: &Dispatcher,
        router: &VakyaRouter,
        phase_guard: &dyn ProposerPhaseGuard,
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

                    // § 5.1 AgentPhase::ReadOnly enforcement.
                    // The proposing agent (v1_karta.pid) transitions to ReadOnly
                    // before dispatch so it cannot mutate its own state during
                    // execution. The executor is a separate PID (§ 5.2).
                    // We record the proposer PID for the post-execution restore.
                    let proposer_pid = vakya.v1_karta.pid.0.clone();
                    debug!(
                        pipeline = %self.pipeline_id,
                        step = %step_id,
                        proposer = %proposer_pid,
                        "Transitioning proposer to ReadOnly before dispatch"
                    );

                    phase_guard.enter_read_only(&proposer_pid).await.map_err(|e| {
                        PipelineError::PhaseTransitionFailed {
                            agent_pid: proposer_pid.clone(),
                            reason: e.to_string(),
                        }
                    })?;

                    let exec_start = Instant::now();
                    let result = dispatcher.dispatch(&vakya, &ctx).await;
                    let duration_ms = exec_start.elapsed().as_millis() as u64;

                    // § 5.1 Restore: proposer returns to Active only after
                    // execution completes and evidence is committed.
                    debug!(
                        pipeline = %self.pipeline_id,
                        step = %step_id,
                        proposer = %proposer_pid,
                        duration_ms = duration_ms,
                        "Restoring proposer to Active after dispatch"
                    );
                    phase_guard.restore_active(&proposer_pid).await.map_err(|e| {
                        PipelineError::PhaseTransitionFailed {
                            agent_pid: proposer_pid.clone(),
                            reason: e.to_string(),
                        }
                    })?;

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
                    let Some(bus) = self.remote_bus.clone() else {
                        debug!(
                            pipeline = %self.pipeline_id,
                            step = %step_id,
                            target_cell = %cell_id,
                            "Step routed to remote cell but no EventBus configured"
                        );
                        self.steps[*idx].status = StepStatus::Skipped {
                            reason: format!("remote execution on cell {} (no EventBus configured)", cell_id),
                        };
                        continue;
                    };

                    let started_at = chrono::Utc::now().timestamp();
                    self.steps[*idx].status = StepStatus::Running {
                        cell_id: cell_id.clone(),
                        started_at,
                    };

                    let exec_start = Instant::now();
                    let reply_topic = format!(
                        "cell.{}.vakya.reply.{}.{}",
                        self.local_cell_id, self.pipeline_id, step_id
                    );
                    let mut reply_rx = bus
                        .subscribe(&reply_topic)
                        .await
                        .map_err(|e| PipelineError::Internal(format!("EventBus subscribe failed: {}", e)))?;

                    let vakya_cbor = serde_json::to_vec(&vakya)
                        .map_err(|e| PipelineError::Internal(format!("Failed to serialize remote VAKYA: {}", e)))?;
                    let forward = ReplicationEvent::new(
                        self.local_cell_id.clone(),
                        0,
                        ReplicationOp::VakyaForward {
                            vakya_cbor,
                            pipeline_id: self.pipeline_id.clone(),
                            step_id: step_id.clone(),
                            reply_topic: reply_topic.clone(),
                        },
                    );
                    let topic = format!("cell.{}.vakya", cell_id);
                    bus.publish(&topic, &forward)
                        .await
                        .map_err(|e| PipelineError::Internal(format!("EventBus publish failed: {}", e)))?;

                    let timeout = Duration::from_millis(30_000);
                    let reply = tokio::time::timeout(timeout, reply_rx.recv())
                        .await
                        .map_err(|_| PipelineError::RemoteTimeout {
                            step_id: step_id.clone(),
                            cell_id: cell_id.clone(),
                        })?
                        .ok_or_else(|| PipelineError::RemoteTimeout {
                            step_id: step_id.clone(),
                            cell_id: cell_id.clone(),
                        })?;

                    match reply.op {
                        ReplicationOp::VakyaReply { step_id: reply_step_id, result_cbor } => {
                            if reply_step_id != step_id {
                                return Err(PipelineError::Internal(format!(
                                    "Unexpected remote step reply: expected {}, got {}",
                                    step_id, reply_step_id
                                )));
                            }

                            let exec_result: ExecutionResult = serde_json::from_slice(&result_cbor)
                                .map_err(|e| PipelineError::Internal(format!("Failed to decode remote execution result: {}", e)))?;
                            let duration_ms = exec_start.elapsed().as_millis() as u64;

                            if exec_result.success {
                                self.steps[*idx].effects = exec_result.effects.clone();
                                self.steps[*idx].status = StepStatus::Completed { duration_ms };
                                self.step_results.insert(step_id.clone(), exec_result);
                                completed_step_ids.insert(step_id);
                            } else {
                                let error_msg = exec_result.error.clone().unwrap_or_else(|| "unknown remote error".into());
                                self.steps[*idx].status = StepStatus::Failed {
                                    error: error_msg,
                                };
                                self.state = PipelineState::Failed;
                                self.step_results.insert(step_id.clone(), exec_result);
                                return Ok(self.build_result(pipeline_start));
                            }
                        }
                        other => {
                            return Err(PipelineError::Internal(format!(
                                "Unexpected EventBus reply op for remote step {}: {}",
                                step_id,
                                other.op_type()
                            )));
                        }
                    }
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
