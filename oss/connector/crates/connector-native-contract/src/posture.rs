//! Enforcement posture for workloads and receipts.

use serde::{Deserialize, Serialize};

/// How strongly a workload/channel is enforced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPosture {
    Native,
    AdapterEnforced,
    ProtocolEnforced,
    TransportEnforced,
    Advisory,
    #[default]
    Unprotected,
}

impl EnforcementPosture {
    /// True for postures that actively enforce (not advisory/unprotected).
    pub fn is_enforced(self) -> bool {
        matches!(
            self,
            Self::Native
                | Self::AdapterEnforced
                | Self::ProtocolEnforced
                | Self::TransportEnforced
        )
    }

    /// Whether this posture may assert transport-level enforcement.
    pub fn can_claim_transport_enforcement(self) -> bool {
        matches!(self, Self::Native | Self::TransportEnforced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_enforced_transport_vs_advisory() {
        assert!(EnforcementPosture::TransportEnforced.is_enforced());
        assert!(!EnforcementPosture::Advisory.is_enforced());
        assert!(!EnforcementPosture::Unprotected.is_enforced());
        assert!(EnforcementPosture::Native.is_enforced());
    }

    #[test]
    fn transport_claim() {
        assert!(EnforcementPosture::TransportEnforced.can_claim_transport_enforcement());
        assert!(EnforcementPosture::Native.can_claim_transport_enforcement());
        assert!(!EnforcementPosture::AdapterEnforced.can_claim_transport_enforcement());
        assert!(!EnforcementPosture::Advisory.can_claim_transport_enforcement());
    }
}
