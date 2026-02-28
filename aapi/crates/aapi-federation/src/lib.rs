//! AAPI Federation — Cross-org trust, federated policy, capability verification.
//!
//! Provides:
//! - `FederatedPolicyEngine`: 3-level policy evaluation (local/cluster/federation)
//! - `CrossCellCapabilityVerifier`: DelegationHop chain verification across cells
//! - `ScittExchange`: Cross-org attestation via SCITT transparency receipts

pub mod error;
pub mod federated_policy;
pub mod capability_verify;
pub mod scitt_exchange;
pub mod payment;
pub mod marketplace;

pub use error::*;
pub use federated_policy::*;
pub use capability_verify::*;
pub use scitt_exchange::*;

#[cfg(test)]
mod tests;
