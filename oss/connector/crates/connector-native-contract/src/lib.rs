//! Neutral CNKTROS runtime contracts (Phase 0).
//!
//! Software / workload / intelligence identity, channels, surfaces,
//! invocation, leases, projection, and edge receipts — without ambient
//! authority or bearer credentials in identity/projection shapes.

pub mod api_contract;
pub mod binding;
pub mod channel;
pub mod config_envelope;
pub mod developer_specs;
pub mod error;
pub mod extension_wit;
pub mod identity;
pub mod invocation;
pub mod ir;
pub mod lease;
pub mod operation;
pub mod package_gate;
pub mod posture;
pub mod projection;
pub mod protocol_driver;
pub mod proxy;
pub mod receipt;
pub mod semantic;
pub mod surface;
pub mod uri;

pub use api_contract::{
    openapi_error_schema, ApiErrorEnvelope, ApiOperationRef, API_ERROR_SCHEMA, API_OPERATION_SCHEMA,
};
pub use binding::{AugmentedBinding, BindingMode, ExecutableConstraints};
pub use channel::{
    ChannelDirection, ChannelObservation, ChannelRef, ChannelState, TransportObservation,
};
pub use config_envelope::{
    precedence_rank, ConfigPlane, ConfigProvenance, ConfigSource, ConnectorConfigEnvelope,
    IntelligenceConfigRef, NodeProfileRef, PackageManifestRef, RuntimeSnapshot,
    CONFIG_ENVELOPE_SCHEMA,
};
pub use developer_specs::{
    spec_digest, AgentSpec, BudgetSpec, GrantRequest, GraphCompensationSpec, GraphEdgeSpec,
    GraphNodeSpec, GraphSpec, InferenceSpec, ListenerSpec, MemorySpec, RouteHopSpec, RouteSpec,
    SecretRef, SupervisionSpec, TargetSpec, ToolSpec, TransformSpec, AGENT_SPEC_SCHEMA,
    BUDGET_SPEC_SCHEMA, GRANT_REQUEST_SCHEMA, GRAPH_SPEC_SCHEMA, INFERENCE_SPEC_SCHEMA,
    LISTENER_SPEC_SCHEMA, MEMORY_SPEC_SCHEMA, ROUTE_SPEC_SCHEMA, SECRET_REF_SCHEMA,
    SUPERVISION_SPEC_SCHEMA, TARGET_SPEC_SCHEMA, TOOL_SPEC_SCHEMA, TRANSFORM_SPEC_SCHEMA,
};
pub use error::NativeContractError;
pub use extension_wit::{
    ExtensionCapabilityImport, ExtensionWitExport, ExtensionWitWorld, EXTENSION_WIT_SCHEMA,
    EXTENSION_WIT_WORLD,
};
pub use identity::{
    AuthorityScope, ContextScope, ContractRef, HostUid, IntelligenceInstance,
    IntelligenceLifecycle, IntelligenceUid, KernelWorkloadRef, MissionRef, PrincipalRef,
    ProcessRef, PublisherRef, SoftwareIdentity, SoftwareUid, TenantId, WorkloadIdentity,
    WorkloadLifecycle, WorkloadUid,
};
pub use invocation::{
    CanonicalAction, EffectDescriptor, InvocationEnvelope, InvocationMode, InvocationOrigin,
};
pub use ir::{
    ConnectorIrV1, IrAuthorityCheck, IrCapabilityImport, IrChannelHint, IrCompensationHint,
    IrEffectRow, IrInterfaceDecl, IrSupervision, IrWorldDecl, CONNECTOR_IR_V1_SCHEMA,
};
pub use operation::{
    operation_status_from_mission, OperationRef, OperationStatus, OPERATION_SCHEMA,
};
pub use package_gate::{
    admit_package_for_effect, gate_allows, PackageGateDecision, PackageGateVerdict, PackagePin,
    RuntimeProfile, PACKAGE_GATE_SCHEMA,
};
pub use lease::{DestinationConstraint, FlowLease};
pub use posture::EnforcementPosture;
pub use projection::{ContractProjection, InferenceCapabilities, ProjectionLossReport};
pub use protocol_driver::{ProtocolDriverId, PROTOCOL_DRIVER_SCHEMA};
pub use proxy::{ProxyHop, ProxyHopKind, RouteGraph, PROXY_HOP_SCHEMA, ROUTE_GRAPH_SCHEMA};
pub use receipt::EdgeReceipt;
pub use semantic::{SemanticConfidence, SemanticProvenance};
pub use surface::{
    InterfaceRef, Locator, ObservedIdentity, SemanticResolutionState, SurfaceRef, SurfaceRelation,
    TargetDescriptor, TargetRef, TargetState, TARGET_DESCRIPTOR_SCHEMA,
};
pub use uri::parse_connector_uri;

use sha2::{Digest, Sha256};

/// Schema identifier for native contract payloads.
pub const NATIVE_CONTRACT_SCHEMA: &str = "connector.native_contract.v1";

/// Contract schema version.
pub const NATIVE_CONTRACT_VERSION: u32 = 1;

/// Allocate a new prefixed UID (`prefix` + UUID v4).
pub fn new_uid(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4())
}

/// Hex-encoded SHA-256 digest of `bytes`.
pub fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hex-encoded SHA-256 digest of UTF-8 text.
pub fn digest_hex_str(s: &str) -> String {
    digest_hex(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constants() {
        assert_eq!(NATIVE_CONTRACT_SCHEMA, "connector.native_contract.v1");
        assert_eq!(NATIVE_CONTRACT_VERSION, 1);
    }

    #[test]
    fn new_uid_prefixes() {
        let id = new_uid("sw_");
        assert!(id.starts_with("sw_"));
        assert!(id.len() > 3);
    }
}
