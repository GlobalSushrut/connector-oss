//! Error types for connector-caps.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapsError {
    #[error("capability not found: {0}")]
    CapabilityNotFound(String),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("token expired")]
    TokenExpired,

    #[error("token revoked: {0}")]
    TokenRevoked(String),

    #[error("token signature invalid: {0}")]
    TokenSignatureInvalid(String),

    #[error("attenuation violation: {0}")]
    AttenuationViolation(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("policy requires approval: {0}")]
    PolicyRequiresApproval(String),

    #[error("contract error: {0}")]
    ContractError(String),

    #[error("chain integrity violated: {0}")]
    ChainIntegrity(String),

    #[error("postcondition failed: {0}")]
    PostconditionFailed(String),

    #[error("sandbox violation: {0}")]
    SandboxViolation(String),

    #[error("execution timeout")]
    Timeout,

    #[error("runner error: {0}")]
    RunnerError(String),

    #[error("device error: {0}")]
    DeviceError(String),

    #[error("safety constraint violated: {0}")]
    SafetyViolation(String),

    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("signature error: {0}")]
    SignatureError(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type CapsResult<T> = Result<T, CapsError>;
