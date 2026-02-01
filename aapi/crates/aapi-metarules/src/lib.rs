//! AAPI MetaRules - Policy Engine for Action Authorization
//!
//! MetaRules provides:
//! - Policy-based authorization for VĀKYA requests
//! - Human-in-the-loop approval workflows
//! - Rate limiting and budget enforcement
//! - Audit logging of policy decisions

pub mod engine;
pub mod rules;
pub mod context;
pub mod decision;
pub mod error;

pub use engine::*;
pub use rules::*;
pub use context::*;
pub use decision::*;
pub use error::*;
