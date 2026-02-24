//! Federation error types.

use thiserror::Error;

/// Federation errors
#[derive(Error, Debug)]
pub enum FederationError {
    #[error("Unknown cell: {0}")]
    UnknownCell(String),

    #[error("Capability verification failed: {0}")]
    CapabilityVerificationFailed(String),

    #[error("Delegation chain invalid: {0}")]
    InvalidDelegationChain(String),

    #[error("SCITT receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),

    #[error("Unknown issuer: {0}")]
    UnknownIssuer(String),

    #[error("Policy evaluation error: {0}")]
    PolicyEvaluation(String),

    #[error("MetaRules error: {0}")]
    MetaRules(#[from] aapi_metarules::error::MetaRulesError),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type FederationResult<T> = Result<T, FederationError>;
