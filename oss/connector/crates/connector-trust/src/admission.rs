//! Admission ticket — unforgeable (by convention) proof of gate approval.

use serde::{Deserialize, Serialize};

/// Proof that the admission gate approved an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdmissionTicketV2 {
    pub ticket_id: String,
    #[serde(default)]
    pub injection_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_policy_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_host_apply_state: Option<String>,
    /// Action that was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Resource that was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl AdmissionTicketV2 {
    /// Lift today's platform `AdmissionTicket` fields into v2.
    pub fn from_legacy_fields(
        ticket_id: impl Into<String>,
        injection_score: f64,
        audit_cid: Option<String>,
        kernel_policy_revision: Option<u64>,
        kernel_host_apply_state: Option<String>,
    ) -> Self {
        Self {
            ticket_id: ticket_id.into(),
            injection_score,
            audit_cid,
            kernel_policy_revision,
            kernel_host_apply_state,
            action: None,
            resource: None,
            contract_version: 2,
        }
    }
}
