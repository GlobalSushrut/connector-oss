//! Plugin setup wizards (Phase 4.5–4.7).
//!
//! Each wizard here mirrors the corresponding TUI flow in
//! `TUI_WIZARDS_MASTER_PLAN.md`:
//!
//! * [`devguard`] — Modules A → E (protection, enforcement, agents,
//!   policy, verification).
//! * [`tracetramp`] — Modules A → E (runtime profile, providers,
//!   budget, policy route, memory).
//! * [`witnessctl`] — Modules A → E (sources, integrity, compliance,
//!   PII, delivery).
//!
//! Phase 4 ships the wizards' *shape* end-to-end (rendering,
//! persistence, validation) and wires the Finish step to the existing
//! product endpoint where one exists. The deeper, field-level
//! configuration arrives in Phase 5 when each plugin gains its full
//! dashboard.

pub mod devguard;
pub mod tracetramp;
pub mod witnessctl;

pub use devguard::DevGuardSetupWizard;
pub use tracetramp::TraceTrampSetupWizard;
pub use witnessctl::WitnessCtlSetupWizard;
