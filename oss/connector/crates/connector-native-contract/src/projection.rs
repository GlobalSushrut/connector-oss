//! Contract projection and inference capability descriptors.
//!
//! Projection shapes intentionally omit bearer grants and credentials.

use serde::{Deserialize, Serialize};

use crate::digest_hex_str;

/// Inference-surface capability hints for projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InferenceCapabilities {
    pub instruction_precedence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_mode: Option<String>,
    pub strict_schema_support: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub multimodal_types: Vec<String>,
    pub output_schema_support: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retention_modes: Vec<String>,
    pub confidential_execution: bool,
    pub hosted_effects: bool,
}

/// Neutral contract projection (no bearer grants / credentials).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractProjection {
    pub intelligence_ref: String,
    pub generation: u64,
    pub principal_projection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_manifest: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub knowledge_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_blocks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted_tool_descriptions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retention_requirements: Vec<String>,
    pub projection_revision: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_digests: Vec<String>,
    pub expires_at_ms: i64,
    /// SHA-256 hex of canonical projection fields.
    pub projection_digest: String,
}

impl ContractProjection {
    /// Compute a stable digest over canonical projection fields (excludes `projection_digest`).
    pub fn compute_digest(&self) -> String {
        let material = format!(
            "{intel}|{gen}|{principal}|{mission}|{disclosure}|{knowledge}|{memory}|{instr}|{tools}|{resp}|{ret}|{rev}|{sources}|{exp}",
            intel = self.intelligence_ref,
            gen = self.generation,
            principal = self.principal_projection,
            mission = self.mission_ref.as_deref().unwrap_or(""),
            disclosure = self.disclosure_manifest.join(","),
            knowledge = self.knowledge_refs.join(","),
            memory = self.memory_scope.as_deref().unwrap_or(""),
            instr = self.instruction_blocks.join("\n"),
            tools = self.permitted_tool_descriptions.join(","),
            resp = self.response_constraints.join(","),
            ret = self.retention_requirements.join(","),
            rev = self.projection_revision,
            sources = self.source_digests.join(","),
            exp = self.expires_at_ms,
        );
        digest_hex_str(&material)
    }

    /// Whether stored digest matches recomputed canonical digest.
    pub fn digest_matches(&self) -> bool {
        self.projection_digest == self.compute_digest()
    }
}

/// Report of features lost when projecting onto a narrower surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectionLossReport {
    pub projection_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lost_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_failures: Vec<String>,
    pub downgrade_allowed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_projection() -> ContractProjection {
        let mut p = ContractProjection {
            intelligence_ref: "intel_1".into(),
            generation: 1,
            principal_projection: "principal:alice".into(),
            mission_ref: None,
            disclosure_manifest: vec!["public".into()],
            knowledge_refs: vec![],
            memory_scope: None,
            instruction_blocks: vec!["be helpful".into()],
            permitted_tool_descriptions: vec![],
            response_constraints: vec![],
            retention_requirements: vec![],
            projection_revision: 1,
            source_digests: vec![],
            expires_at_ms: 9_999,
            projection_digest: String::new(),
        };
        p.projection_digest = p.compute_digest();
        p
    }

    #[test]
    fn projection_has_no_credential_like_json_keys() {
        let p = sample_projection();
        let v = serde_json::to_value(&p).expect("ser");
        let obj = v.as_object().expect("object");
        for key in obj.keys() {
            let lower = key.to_ascii_lowercase();
            assert!(
                !lower.contains("api_key")
                    && !lower.contains("token")
                    && !lower.contains("grant")
                    && !lower.contains("password")
                    && !lower.contains("secret")
                    && !lower.contains("credential"),
                "credential-like key present: {key}"
            );
        }
        // Structure must not expose bearer fields (compile-time by type; runtime check above).
        assert!(p.digest_matches());
    }
}
