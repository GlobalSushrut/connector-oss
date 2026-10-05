//! cpkg workload-security contract (Seven Pillars §7) — beyond packaging metadata.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CPKG_SECURITY_CONTRACT_SCHEMA: &str = "connector.cpkg_security_contract.v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpkgSecurityContractV1 {
    pub schema: String,
    pub workload_id: String,
    pub version: String,
    pub required_capabilities: Vec<String>,
    pub filesystem_requirements: Vec<String>,
    pub network_destinations: Vec<String>,
    pub device_requirements: Vec<String>,
    pub secret_requirements: Vec<String>,
    pub isolation_tier: String,
    pub protocol_surfaces: Vec<String>,
    pub cls_contract_refs: Vec<String>,
    pub sbom_digest: Option<String>,
    pub signature_present: bool,
    pub dependency_hashes: Vec<String>,
}

impl CpkgSecurityContractV1 {
    pub fn digest_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    /// Activation gate: signature/SBOM/deps present when production-hardened.
    pub fn assert_ready_for_activation(&self, require_signature: bool) -> Result<(), String> {
        if self.workload_id.trim().is_empty() {
            return Err("cpkg_workload_id_missing".into());
        }
        if require_signature && !self.signature_present {
            return Err("cpkg_signature_required".into());
        }
        if self.isolation_tier.trim().is_empty() {
            return Err("cpkg_isolation_tier_required".into());
        }
        Ok(())
    }
}

/// Derive a security contract skeleton from plugin.toml-ish fields.
pub fn from_manifest_fields(
    workload_id: &str,
    version: &str,
    isolation_tier: &str,
    capabilities: &[String],
    signature_present: bool,
    sbom_digest: Option<String>,
) -> CpkgSecurityContractV1 {
    CpkgSecurityContractV1 {
        schema: CPKG_SECURITY_CONTRACT_SCHEMA.into(),
        workload_id: workload_id.into(),
        version: version.into(),
        required_capabilities: capabilities.to_vec(),
        filesystem_requirements: vec![],
        network_destinations: vec![],
        device_requirements: vec![],
        secret_requirements: vec![],
        isolation_tier: isolation_tier.into(),
        protocol_surfaces: vec![],
        cls_contract_refs: vec![],
        sbom_digest,
        signature_present,
        dependency_hashes: vec![],
    }
}
