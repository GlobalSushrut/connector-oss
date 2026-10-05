//! Software, workload, and intelligence identity contracts.
//!
//! Critical: identity types intentionally omit model_ref / provider fields.

use serde::{Deserialize, Serialize};

use crate::posture::EnforcementPosture;

/// Prefixed software UID (`sw_…`).
pub type SoftwareUid = String;
/// Prefixed workload UID (`wl_…`).
pub type WorkloadUid = String;
/// Prefixed intelligence UID (`intel_…`).
pub type IntelligenceUid = String;
/// Host UID.
pub type HostUid = String;
/// Tenant identifier.
pub type TenantId = String;
/// Principal reference string.
pub type PrincipalRef = String;
/// Contract reference string.
pub type ContractRef = String;
/// Mission reference string.
pub type MissionRef = String;
/// Publisher reference string.
pub type PublisherRef = String;
/// Process reference (pidfd/path) — not ambient authority.
pub type ProcessRef = String;
/// Kernel workload identity reference.
pub type KernelWorkloadRef = String;

/// Declared software identity (install / publish side).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoftwareIdentity {
    pub software_uid: SoftwareUid,
    pub tenant: TenantId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_name: Option<String>,
    /// Executable digest (hex sha256), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_origin: Option<String>,
    pub metadata_revision: u64,
}

/// Workload lifecycle state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadLifecycle {
    Registered,
    Starting,
    Active,
    Degraded,
    Draining,
    Stopped,
    #[default]
    Unknown,
}

/// Runtime workload identity bound to software and host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadIdentity {
    pub workload_uid: WorkloadUid,
    pub software_uid: SoftwareUid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_uid: Option<HostUid>,
    /// Process root reference (pidfd/path) — not ambient authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_root: Option<ProcessRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_identity: Option<KernelWorkloadRef>,
    pub started_at_ms: i64,
    pub lifecycle: WorkloadLifecycle,
    pub enforcement_posture: EnforcementPosture,
}

/// Intelligence instance lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceLifecycle {
    Bound,
    Active,
    Quarantined,
    Draining,
    #[default]
    Stopped,
}

/// Context scope for an intelligence instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContextScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Authority scope for an intelligence instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthorityScope {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
}

/// Bound intelligence instance (no model_ref / provider identity fields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceInstance {
    pub intelligence_uid: IntelligenceUid,
    pub workload_uid: WorkloadUid,
    pub principal: PrincipalRef,
    pub contract_ref: ContractRef,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_ref: Option<MissionRef>,
    #[serde(default)]
    pub context_scope: ContextScope,
    #[serde(default)]
    pub authority_scope: AuthorityScope,
    pub lifecycle: IntelligenceLifecycle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::new_uid;

    #[test]
    fn intelligence_serde_roundtrip_without_model_ref() {
        let inst = IntelligenceInstance {
            intelligence_uid: new_uid("intel_"),
            workload_uid: new_uid("wl_"),
            principal: "principal:alice".into(),
            contract_ref: "contract:v1".into(),
            generation: 1,
            mission_ref: None,
            context_scope: ContextScope::default(),
            authority_scope: AuthorityScope::default(),
            lifecycle: IntelligenceLifecycle::Active,
        };
        let json = serde_json::to_value(&inst).expect("serialize");
        assert!(json.get("model_ref").is_none());
        assert!(json.get("provider").is_none());
        let back: IntelligenceInstance = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, inst);
    }

    #[test]
    fn intelligence_rejects_extra_model_ref_silently_ignored_or_absent() {
        // Deserializing JSON without model_ref succeeds; field must not exist on type.
        let raw = r#"{
            "intelligence_uid": "intel_1",
            "workload_uid": "wl_1",
            "principal": "p",
            "contract_ref": "c",
            "generation": 0,
            "lifecycle": "bound"
        }"#;
        let inst: IntelligenceInstance = serde_json::from_str(raw).expect("parse");
        assert_eq!(inst.lifecycle, IntelligenceLifecycle::Bound);
        let out = serde_json::to_string(&inst).expect("ser");
        assert!(!out.contains("model_ref"));
    }
}
