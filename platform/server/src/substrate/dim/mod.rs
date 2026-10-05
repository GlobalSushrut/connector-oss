//! Dynamic Intelligence Manifold (DIM) — persistent cognitive condition substrate.
//!
//! Regulates intelligence-dynamics only. Never authorizes world effects.
//! See `platform/docs/arch/DYNAMIC_INTELLIGENCE_MANIFOLD.md`.

pub mod state;
pub mod regime;
pub mod regulate;
pub mod estimate;
pub mod persist;
pub mod api;
pub mod wake;
pub mod bands;

pub use estimate::refresh_for_agent;
pub use persist::{load, save};
pub use regulate::{apply_regulation, propose_regulation};
pub use state::{CognitiveRegime, DynamicIntelligenceState, RegulationAction, DIM_SCHEMA, DIM_FOLDER};
