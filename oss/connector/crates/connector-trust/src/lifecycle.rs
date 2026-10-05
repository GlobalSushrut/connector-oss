//! Common workload / workflow lifecycle states for first- and third-party plugins.

use serde::{Deserialize, Serialize};

/// Shared lifecycle for installable workloads (plugins, agents, cages).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadLifecycleState {
    Installed,
    Starting,
    Running,
    Paused,
    Upgrading,
    RollingBack,
    Revoked,
    Terminated,
}

impl WorkloadLifecycleState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use WorkloadLifecycleState::*;
        matches!(
            (self, next),
            (Installed, Starting)
                | (Starting, Running)
                | (Starting, Terminated)
                | (Running, Paused)
                | (Running, Upgrading)
                | (Running, Revoked)
                | (Running, Terminated)
                | (Paused, Running)
                | (Paused, Revoked)
                | (Paused, Terminated)
                | (Upgrading, Running)
                | (Upgrading, RollingBack)
                | (RollingBack, Running)
                | (RollingBack, Terminated)
                | (Revoked, Terminated)
                | (Installed, Revoked)
                | (Installed, Terminated)
        )
    }
}

/// Naming binding for a cage / CNP / plugin route to verified identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadNameBindingV2 {
    pub name: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    pub lifecycle: WorkloadLifecycleState,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_can_pause() {
        assert!(WorkloadLifecycleState::Running.can_transition_to(WorkloadLifecycleState::Paused));
        assert!(!WorkloadLifecycleState::Terminated.can_transition_to(WorkloadLifecycleState::Running));
    }
}
