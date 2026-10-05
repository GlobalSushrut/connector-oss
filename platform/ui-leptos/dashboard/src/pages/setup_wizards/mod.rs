//! Onboarding wizards (Phase 4).
//!
//! Each file in this module is a self-contained multi-step wizard
//! built on top of `crate::components::wizard`. The hub at
//! [`crate::pages::setup`] lists them all and shows completion state
//! read from `localStorage`.

pub mod first_run;
pub mod connect_tool;
pub mod install_workflow;
pub mod create_agent;
pub mod agent_charter_studio;
pub mod setup_budget;
pub mod playground_tour;
pub mod invite_teammate;

pub use first_run::FirstRunWizard;
pub use connect_tool::ConnectToolWizard;
pub use install_workflow::InstallWorkflowWizard;
pub use create_agent::CreateAgentWizard;
pub use agent_charter_studio::AgentCharterStudio;
pub use setup_budget::SetupBudgetWizard;
pub use playground_tour::PlaygroundTour;
pub use invite_teammate::InviteTeammateWizard;
