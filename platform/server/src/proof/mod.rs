//! Proof Systems — Chain, Anchoring, Verification

pub mod chain;
pub mod anchoring;

pub use chain::{ProofGenerator, MerkleTree, MerkleProof, VerificationStatus};
pub use anchoring::{AnchorManager, Anchor, AnchorType, VerificationResult};
