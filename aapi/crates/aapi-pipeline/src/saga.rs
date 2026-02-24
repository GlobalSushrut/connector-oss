//! Saga Coordinator — distributed transaction rollback.
//!
//! When a multi-step pipeline fails, the SagaCoordinator rolls back
//! all completed steps in **reverse order**. Each step's `CapturedEffect`
//! contains `ReversalInstructions` that tell us how to undo it.
//!
//! - **Local steps**: rolled back via the Dispatcher's `rollback()` method.
//! - **Remote steps**: a rollback request is published to the target cell
//!   via the event bus (placeholder until D12 wires the ClusterGateway).
//!
//! The saga pattern guarantees eventual consistency: either all steps
//! succeed, or all completed steps are compensated.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use aapi_adapters::effect::CapturedEffect;
use aapi_adapters::registry::Dispatcher;

use crate::error::PipelineResult;

// ============================================================================
// Types
// ============================================================================

/// A completed step that may need rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedStep {
    pub step_id: String,
    pub cell_id: String,
    pub effects: Vec<CapturedEffect>,
}

/// Result of rolling back a single step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackOutcome {
    /// Successfully rolled back locally.
    RolledBack,
    /// Rollback request sent to remote cell (fire-and-forget for now).
    RemoteRequested { cell_id: String },
    /// Step had no reversible effects — nothing to do.
    NoOp,
    /// Rollback failed with an error.
    Failed { error: String },
}

/// Summary of a saga rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaRollbackResult {
    pub saga_id: String,
    pub total_steps: usize,
    pub rolled_back: usize,
    pub remote_requested: usize,
    pub no_ops: usize,
    pub failures: usize,
    pub step_outcomes: HashMap<String, RollbackOutcome>,
}

// ============================================================================
// SagaCoordinator
// ============================================================================

/// Coordinates reverse-order rollback of completed pipeline steps.
///
/// Usage:
/// 1. After a pipeline failure, collect all completed steps.
/// 2. Create a `SagaCoordinator` with those steps.
/// 3. Call `rollback()` to compensate in reverse order.
pub struct SagaCoordinator {
    pub saga_id: String,
    pub local_cell_id: String,
    pub completed_steps: Vec<CompletedStep>,
}

impl SagaCoordinator {
    pub fn new(
        saga_id: impl Into<String>,
        local_cell_id: impl Into<String>,
        completed_steps: Vec<CompletedStep>,
    ) -> Self {
        Self {
            saga_id: saga_id.into(),
            local_cell_id: local_cell_id.into(),
            completed_steps,
        }
    }

    /// Build a SagaCoordinator from a failed pipeline's completed steps.
    pub fn from_pipeline(
        saga_id: impl Into<String>,
        local_cell_id: impl Into<String>,
        steps: &[crate::pipeline::PipelineStep],
    ) -> Self {
        let completed: Vec<CompletedStep> = steps
            .iter()
            .filter(|s| s.status.is_success())
            .map(|s| CompletedStep {
                step_id: s.step_id.clone(),
                cell_id: s
                    .target_cell
                    .clone()
                    .unwrap_or_else(|| "local".to_string()),
                effects: s.effects.clone(),
            })
            .collect();

        Self::new(saga_id, local_cell_id, completed)
    }

    /// Rollback all completed steps in reverse order.
    ///
    /// Local steps are rolled back via the Dispatcher.
    /// Remote steps get a placeholder (actual bus publish in D12).
    pub async fn rollback(
        &self,
        dispatcher: &Dispatcher,
    ) -> PipelineResult<SagaRollbackResult> {
        let mut outcomes = HashMap::new();
        let mut rolled_back = 0usize;
        let mut remote_requested = 0usize;
        let mut no_ops = 0usize;
        let mut failures = 0usize;

        // Reverse order — last completed step first
        for step in self.completed_steps.iter().rev() {
            let reversible_effects: Vec<&CapturedEffect> = step
                .effects
                .iter()
                .filter(|e| e.reversible)
                .collect();

            if reversible_effects.is_empty() {
                debug!(
                    saga = %self.saga_id,
                    step = %step.step_id,
                    "No reversible effects — skipping"
                );
                outcomes.insert(step.step_id.clone(), RollbackOutcome::NoOp);
                no_ops += 1;
                continue;
            }

            let is_local = step.cell_id == self.local_cell_id
                || step.cell_id == "local";

            if is_local {
                // Rollback locally via Dispatcher
                let mut step_failed = false;
                for effect in &reversible_effects {
                    debug!(
                        saga = %self.saga_id,
                        step = %step.step_id,
                        effect = %effect.effect_id,
                        "Rolling back effect locally"
                    );
                    if let Err(e) = dispatcher.rollback(effect).await {
                        warn!(
                            saga = %self.saga_id,
                            step = %step.step_id,
                            error = %e,
                            "Rollback failed for effect"
                        );
                        step_failed = true;
                        outcomes.insert(
                            step.step_id.clone(),
                            RollbackOutcome::Failed {
                                error: e.to_string(),
                            },
                        );
                        failures += 1;
                        break;
                    }
                }
                if !step_failed {
                    outcomes.insert(step.step_id.clone(), RollbackOutcome::RolledBack);
                    rolled_back += 1;
                }
            } else {
                // Remote rollback — placeholder for D12
                debug!(
                    saga = %self.saga_id,
                    step = %step.step_id,
                    cell = %step.cell_id,
                    "Requesting remote rollback (placeholder)"
                );
                outcomes.insert(
                    step.step_id.clone(),
                    RollbackOutcome::RemoteRequested {
                        cell_id: step.cell_id.clone(),
                    },
                );
                remote_requested += 1;
            }
        }

        Ok(SagaRollbackResult {
            saga_id: self.saga_id.clone(),
            total_steps: self.completed_steps.len(),
            rolled_back,
            remote_requested,
            no_ops,
            failures,
            step_outcomes: outcomes,
        })
    }

    /// Number of steps that need rollback.
    pub fn step_count(&self) -> usize {
        self.completed_steps.len()
    }

    /// Number of steps with reversible effects.
    pub fn reversible_count(&self) -> usize {
        self.completed_steps
            .iter()
            .filter(|s| s.effects.iter().any(|e| e.reversible))
            .count()
    }
}
