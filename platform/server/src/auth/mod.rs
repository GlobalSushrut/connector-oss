//! Authentication and Authorization Module
//!
//! Provides:
//! - JWT-based authentication with HMAC-SHA256
//! - RBAC with 6 platform roles
//! - Scoped API tokens for fine-grained access control
//! - TOTP 2FA support
//! - Rate limiting and account lockout
//! - mTLS for node-to-node authentication

mod core;
pub mod rbac;
pub mod scoped_tokens;
pub mod mtls;

// Re-export everything from core for backwards compatibility
pub use core::*;

// Re-export scoped token types
pub use scoped_tokens::{
    ScopedToken, TokenScopes, ResourceScopes, ActionScope,
    CreateTokenRequest, CreateTokenResponse,
    check_permission, generate_token, hash_token,
};

// Re-export mTLS types
pub use mtls::{
    MtlsConfig, MtlsManager, CertificateStore, CertificateValidator,
    CertificateEntry, CertificateType, CertificateStatus,
    NodeIdentity, NodeRole, ValidationResult,
    CertificateSigningRequest, generate_self_signed_cert,
};
