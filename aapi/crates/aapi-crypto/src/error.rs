//! Cryptographic error types

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Capability token error: {0}")]
    CapabilityError(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Token not yet valid")]
    TokenNotYetValid,

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Invalid subject")]
    InvalidSubject,

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("Caveat validation failed: {0}")]
    CaveatFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
