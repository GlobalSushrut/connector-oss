//! # Connector Caps (Ring 0 + Ring 1)
//!
//! Capability Computer — execution contracts, runners, sandboxing, hardware abstraction.
//!
//! Every agent action in the real world is contracted, sandboxed, and cryptographically proven.
//!
//! ## Modules
//!
//! - **capability**: Capability registry (84 capabilities, 10 categories)
//! - **token**: CapabilityToken (issue, attenuate, verify, revoke)
//! - **contract**: Execution Contract (3-phase: Offer → Grant → Receipt)
//! - **journal**: Execution Journal (hash-chained, Merkle-rooted)
//! - **runner**: Runner framework (Runner trait + registry)
//! - **policy**: Policy gate (authorization, risk escalation)
//! - **postcondition**: Postcondition verifier + rollback
//! - **sandbox**: Sandbox configuration
//! - **device**: Hardware abstraction layer
//! - **verify**: Chain and contract verification

pub mod error;
pub mod capability;
pub mod token;
pub mod contract;
pub mod journal;
pub mod runner;
pub mod policy;
pub mod postcondition;
pub mod sandbox;
pub mod device;
pub mod verify;

pub use error::*;
pub use capability::*;
pub use token::{CapabilityToken, CapabilityGrant, GrantConstraints, TokenIssuer};
pub use contract::*;
pub use journal::{ExecutionStore, InMemoryExecutionStore};
pub use runner::{Runner, ExecRequest, ExecResult, RunnerRegistry};
pub use policy::{Policy, PolicyDecision, DefaultPolicy};
pub use postcondition::{PostconditionSpec, PostconditionResult, verify_postconditions};
pub use sandbox::SandboxConfig;
pub use device::{DeviceDescriptor, SafetyConstraints, DeviceRegistry};
pub use verify::{verify_chain, verify_contract};
