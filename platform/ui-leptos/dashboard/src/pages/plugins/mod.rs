//! Institution plugin consoles + setup wizards.
//!
//! Default `/plugins/<id>` → light consoles (backend-aligned).

mod contract_live;
mod deployment_gate;
mod light_consoles;
mod rules_panels;
mod setup;

pub use deployment_gate::{DevGuardPluginRouted, TracetrampPluginRouted, WitnessctlPluginRouted};
pub use setup::{DevGuardSetupWizard, TraceTrampSetupWizard, WitnessCtlSetupWizard};
