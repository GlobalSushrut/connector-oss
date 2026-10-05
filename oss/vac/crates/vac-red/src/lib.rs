//! VAC RED - Regressive Entropic Displacement Engine
//!
//! Non-ML learning system based on information-theoretic principles:
//! - Maximum Entropy Principle (Jaynes)
//! - KL Divergence as information gain
//! - Multiplicative Weights Update (Hedge algorithm)
//! - Free Energy minimization

pub mod vector;
pub mod displacement;
pub mod entropy;

pub use vector::*;
pub use displacement::*;
pub use entropy::*;

/// Default number of dimensions for feature vectors
pub const DEFAULT_DIMS: usize = 65536; // 2^16

/// Default learning rate (eta)
pub const DEFAULT_ETA: f64 = 0.1;
