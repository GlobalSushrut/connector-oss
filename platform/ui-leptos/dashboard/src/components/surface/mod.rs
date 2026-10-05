// Phase 6.9 — Leptos macro-expanded prop structs trip
// `dead_code` lints in modules that aren't currently composed into a
// page. Silence at the module level; functionality is intact.
#![allow(dead_code)]

pub mod summary;
pub mod identity;
pub mod trust;
pub mod evidence;
pub mod ops;
pub mod exec;

// Phase 6.9 — Overview was rewritten to read the surface payload
// directly into a 3-cell Worklist instead of mounting six panels.
// The individual panel components are kept available behind
// `#[allow(unused_imports)]` so other pages can still embed them on
// demand without re-importing the inner module path.
#[allow(unused_imports)]
pub use summary::SurfaceSummary;
#[allow(unused_imports)]
pub use identity::SurfaceIdentity;
#[allow(unused_imports)]
pub use trust::SurfaceTrust;
#[allow(unused_imports)]
pub use evidence::SurfaceEvidence;
#[allow(unused_imports)]
pub use ops::SurfaceOps;
#[allow(unused_imports)]
pub use exec::SurfaceExec;
