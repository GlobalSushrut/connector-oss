//! Governed request — principal + action + resource for admission.

use serde::{Deserialize, Serialize};

use crate::PrincipalContextV2;

/// Normalized request presented to the admission / policy boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernedRequestV2 {
    pub principal: PrincipalContextV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent pid when an agent is the actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    pub action: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    /// Content digest (hex SHA-256) when content was inspected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}
