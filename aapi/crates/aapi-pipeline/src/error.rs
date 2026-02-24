//! Pipeline error types.

use thiserror::Error;

/// Pipeline errors
#[derive(Error, Debug)]
pub enum PipelineError {
    #[error("Pipeline step failed: {step_id} — {reason}")]
    StepFailed { step_id: String, reason: String },

    #[error("Dependency not met: step {step_id} depends on {dependency}")]
    DependencyNotMet { step_id: String, dependency: String },

    #[error("Circular dependency detected involving step: {0}")]
    CircularDependency(String),

    #[error("Step not found: {0}")]
    StepNotFound(String),

    #[error("Pipeline already running")]
    AlreadyRunning,

    #[error("Pipeline not in a runnable state: {0:?}")]
    InvalidState(String),

    #[error("Routing error: {0}")]
    RoutingError(String),

    #[error("Timeout waiting for remote step: {step_id} on cell {cell_id}")]
    RemoteTimeout { step_id: String, cell_id: String },

    #[error("Adapter error: {0}")]
    Adapter(#[from] aapi_adapters::error::AdapterError),

    #[error("Saga rollback failed: {0}")]
    SagaRollbackFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type PipelineResult<T> = Result<T, PipelineError>;
