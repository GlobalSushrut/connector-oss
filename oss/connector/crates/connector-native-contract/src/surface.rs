//! Surface and target references.

use serde::{Deserialize, Serialize};

use crate::semantic::{SemanticConfidence, SemanticProvenance};

/// How a surface relates to the world / peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceRelation {
    Inference,
    WorldRead,
    WorldWrite,
    Execution,
    Communication,
    Storage,
    Filesystem,
    Database,
    Device,
    Human,
    PeerIntelligence,
    #[default]
    Unknown,
}

/// Resolution progress for surface semantics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticResolutionState {
    #[default]
    Unresolved,
    TransportObserved,
    ProtocolObserved,
    AdapterVerified,
    NativeVerified,
}

/// Observed peer / process identity hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservedIdentity {
    pub kind: String,
    pub value: String,
}

/// Locator for a surface endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Locator {
    pub scheme: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Named interface on a surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Surface reference with semantic resolution metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfaceRef {
    pub surface_uid: String,
    pub relation: SurfaceRelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_identity: Option<ObservedIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<Locator>,
    pub semantic_state: SemanticResolutionState,
    pub confidence: SemanticConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceRef>,
    pub provenance: SemanticProvenance,
    pub revision: u64,
}

/// Canonical connector target reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetRef {
    pub tenant: String,
    pub namespace: String,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Canonical `connector://…` form.
    pub uri: String,
}

/// Authorization-filtered catalog view of a surface/target (discovery metadata only).
///
/// Descriptors never mint grants. `target` is present only when resolved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetDescriptor {
    pub schema: String,
    pub surface_uid: String,
    pub tenant_id: String,
    pub confidence: SemanticConfidence,
    pub semantic_state: SemanticResolutionState,
    pub relation: SurfaceRelation,
    pub provenance: SemanticProvenance,
    pub surface_revision: u64,
    /// Catalog revision when this descriptor was indexed/observed.
    pub catalog_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<Locator>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceRef>,
    /// Probe readiness: `unknown` | `ready` | `degraded` | `unready`.
    #[serde(default = "default_readiness")]
    pub readiness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe_at_ms: Option<i64>,
    /// Optional supervised workload binding (not a spawn claim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervised_workload_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_lifecycle: Option<String>,
    pub updated_at_ms: i64,
}

fn default_readiness() -> String {
    "unknown".into()
}

pub const TARGET_DESCRIPTOR_SCHEMA: &str = "connector.target_descriptor.v1";

impl TargetDescriptor {
    pub fn from_surface(
        surface: &SurfaceRef,
        tenant_id: &str,
        catalog_revision: u64,
        target: Option<TargetRef>,
    ) -> Self {
        Self {
            schema: TARGET_DESCRIPTOR_SCHEMA.into(),
            surface_uid: surface.surface_uid.clone(),
            tenant_id: tenant_id.into(),
            confidence: surface.confidence,
            semantic_state: surface.semantic_state,
            relation: surface.relation,
            provenance: surface.provenance.clone(),
            surface_revision: surface.revision,
            catalog_revision,
            target,
            locators: surface.locators.clone(),
            interfaces: surface.interfaces.clone(),
            readiness: "unknown".into(),
            last_probe_at_ms: None,
            supervised_workload_uid: None,
            workload_lifecycle: None,
            updated_at_ms: 0,
        }
    }
}

impl TargetRef {
    /// Build a canonical connector URI string.
    pub fn canonical_uri(
        tenant: &str,
        namespace: &str,
        kind: &str,
        name: &str,
        api: Option<&str>,
        operation: Option<&str>,
    ) -> String {
        let mut uri = format!("connector://{tenant}/{namespace}/{kind}/{name}");
        if let Some(api) = api {
            uri.push_str("?api=");
            uri.push_str(api);
        }
        if let Some(op) = operation {
            uri.push('#');
            uri.push_str(op);
        }
        uri
    }
}

/// Target resolution state along the semantic pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Unresolved { observed_peer: ObservedIdentity },
    Surface { surface_uid: String },
    Resolved { target: TargetRef },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_state_serde_variants() {
        let unresolved = TargetState::Unresolved {
            observed_peer: ObservedIdentity {
                kind: "dns".into(),
                value: "api.example.com".into(),
            },
        };
        let surface = TargetState::Surface {
            surface_uid: "surf_abc".into(),
        };
        let resolved = TargetState::Resolved {
            target: TargetRef {
                tenant: "t".into(),
                namespace: "ns".into(),
                kind: "svc".into(),
                name: "n".into(),
                api: None,
                operation: None,
                uri: "connector://t/ns/svc/n".into(),
            },
        };

        for state in [unresolved, surface, resolved] {
            let v = serde_json::to_value(&state).expect("ser");
            let back: TargetState = serde_json::from_value(v).expect("de");
            assert_eq!(back, state);
        }
    }
}
