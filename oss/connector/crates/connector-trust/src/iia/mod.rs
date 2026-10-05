//! Intelligence Identity Architecture (IIA) v2 — court-grade contracts.

pub mod signing;
pub mod types;
pub mod verify;

pub use signing::{
    canonical_digest_json, sign_json_ed25519, verify_json_ed25519, verify_signed_payload_v2,
    SignedPayloadV2,
};
pub use types::*;
pub use verify::{
    verify_cpo_structure, verify_export_chain, verify_principal_envelope, verify_quantum_active,
};
