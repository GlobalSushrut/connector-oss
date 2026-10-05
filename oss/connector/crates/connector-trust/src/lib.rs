//! Connector Trust Contracts (v2)
//!
//! Shared, versioned types for constitutional substrate primitives:
//! identity, authority, governed execution, causality, and custody.
//!
//! These contracts are independent of HTTP APIs. Platform and workflows
//! adapt existing types (`Claims`, `AdmissionTicket`) into v2 shapes.

pub mod principal;
pub mod capability;
pub mod authority;
pub mod governed;
pub mod admission;
pub mod causal;
pub mod custody;
pub mod verify;
pub mod lifecycle;
pub mod vector_box;
pub mod audit_middle;
pub mod data_context;
pub mod forensic_flow;
pub mod usage_event;
pub mod usage_receipt;
pub mod artifact_log;
pub mod moment;
pub mod agent_memory;
pub mod context_rollup;
pub mod crk;
pub mod svf;
pub mod hardware_placement;
pub mod iia;
pub mod effect_authorization;
pub mod effect_envelope;
pub mod packet_dna;
pub mod aipsprt_sig;
pub mod spend_cease;

pub use principal::PrincipalContextV2;
pub use capability::CapabilityGrantV2;
pub use authority::{
    attenuates_ok, attenuation_digest, AuthorityRevisionRecord, AuthorityRoot, GrantRef,
    RevocationTombstone, AUTHORITY_SCHEMA, GRANT_REF_SCHEMA, REVISION_SCHEMA, TOMBSTONE_SCHEMA,
};
pub use governed::GovernedRequestV2;
pub use effect_authorization::{
    digest_hex_for_params, EffectAuthorizationV1, EFFECT_AUTHORIZATION_SCHEMA,
};
pub use effect_envelope::{EffectEnvelopeV1, EFFECT_ENVELOPE_SCHEMA};
pub use packet_dna::{
    decode_dna_header, effect_digest_of, encode_dna_header, mint_packet_dna, payload_digest_json,
    verify_packet_dna, AgentGenomeV1, AgentPacketDnaV1, PACKET_DNA_GENOME_LEN, PACKET_DNA_HEADER,
    PACKET_DNA_SCHEMA,
};
pub use aipsprt_sig::{
    agent_subject_id_public, c2pa_export_mapping, decode_aipsprt_header, encode_aipsprt_header,
    issuer_id_from_pubkey_hex, mint_aipsprt_sig, payload_digest_bytes as aipsprt_payload_digest_bytes,
    verify_aipsprt_sig, AiPassportPrivateRecordV1, AiPassportSigV1, ArtifactProfile, DigestRef,
    MintAiPassportArgs, ProvenanceRole, AIPSPRT_HEADER, AIPSPRT_HONESTY, AIPSPRT_PRIVATE_SCHEMA,
    AIPSPRT_SIG_SCHEMA,
};
pub use spend_cease::{
    egress_operation_id, CeaseReason, CeaseReceiptV1, HopReservationV1, ReservationState,
    SpendCeilingV1, SpendEnforcement, CEASE_RECEIPT_SCHEMA, HOP_RESERVATION_SCHEMA,
    SPEND_CEILING_SCHEMA,
};
pub use admission::AdmissionTicketV2;
pub use causal::CausalEnvelopeV2;
pub use custody::CustodyReceiptV2;
pub use lifecycle::{WorkloadLifecycleState, WorkloadNameBindingV2};
pub use vector_box::{MemoryVectorBox, MemoryRawPlane, MemoryLogPlane, build_super_key};
pub use audit_middle::{DiAuditMiddleEvent, DiAuditMiddleExport, DiControlHit, DI_AUDIT_MIDDLE_SCHEMA};
pub use data_context::{DataContextContainer, RelationalContainer, IdentityGraphNodeRef, ExternalDataRef};
pub use forensic_flow::{
    decode_header_value, encode_header_value, mint_flow_identity, verify_flow_identity,
    ForensicFlowIdentityV2, CFNI_HEADER, CFNI_SCHEMA,
};
pub use usage_event::{UsageEventV2, UsageTokenSource, USAGE_EVENT_SCHEMA};
pub use usage_receipt::{
    append_usage_receipt, PeerKind, UnmeteredPeerHonesty, UsageReceipt, USAGE_RECEIPT_SCHEMA,
};
pub use artifact_log::{ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA};
pub use moment::{MomentManifestV2, MomentPartV2, MOMENT_MANIFEST_SCHEMA};
pub use agent_memory::{
    AgentMemoryCapsule, ContextCheckpoint, ContextDelta, ContextReference, ContextTransition,
    DecisionMemory, EpistemicClass, EvidenceRecord, MemoryPoint, MemoryTierTarget, MomentProof,
    AGENT_MEMORY_SCHEMA, AMC_SCHEMA, CHECKPOINT_SCHEMA, CONTEXT_DELTA_SCHEMA,
    CONTEXT_TRANSITION_SCHEMA, DECISION_MEMORY_SCHEMA, EVIDENCE_RECORD_SCHEMA,
    MEMORY_POINT_SCHEMA, MOMENT_PROOF_SCHEMA,
};
pub use crk::{
    relation_type_pairing_ok, ActionCueEnvelope, ContextFrame, ContextFrameKind,
    ContextTransferEnvelope, ContinuityRollup, CrkState, InfluenceManifest, MemoryCommit,
    MemoryDnaType, MemoryEnvelope, MemoryRelation, MemoryRelationKind, MemorySequenceDnaV1,
    MomentRange, ProcedureStep, RecallSession, RenderPolicy, StateClaim, TrustTier,
    VerifiedProcedureCapsule, ACTION_CUE_SCHEMA, CONTEXT_FRAME_SCHEMA, CONTEXT_TRANSFER_SCHEMA,
    CONTINUITY_ROLLUP_SCHEMA, INFLUENCE_MANIFEST_SCHEMA, MEMORY_COMMIT_SCHEMA,
    MEMORY_ENVELOPE_SCHEMA, MEMORY_RELATION_SCHEMA, MEMORY_SEQUENCE_DNA_LEN,
    MEMORY_SEQUENCE_DNA_SCHEMA, MOMENT_RANGE_SCHEMA, PROCEDURE_CAPSULE_SCHEMA,
    RECALL_SESSION_SCHEMA, STATE_CLAIM_SCHEMA,
};
pub use context_rollup::{
    AgentRollupBudget, CausalMemorySkeleton, ContextRollup, DailyAgentRollup, DecisionRollup,
    EvidenceClass, EvidenceTombstone, FadeLock, FadePolicy, FadeState, ProofLevel, RollupExplain,
    RollupMetrics, SessionRollup, CAUSAL_SKELETON_SCHEMA, CONTEXT_ROLLUP_SCHEMA, DAILY_ROLLUP_SCHEMA,
    DECISION_ROLLUP_SCHEMA, EVIDENCE_TOMBSTONE_SCHEMA, FADE_LOCK_SCHEMA, FADE_POLICY_SCHEMA,
    FADE_STATE_SCHEMA, PROOF_LEVEL_SCHEMA, ROLLUP_BUDGET_SCHEMA, ROLLUP_METRICS_SCHEMA,
    SESSION_ROLLUP_SCHEMA,
};
pub use svf::{
    AgenticObject, BrokerDecision, BrokerDecisionCode, ContextFragment, ContextManifest,
    DerivedKnowledge, DisclosureGrant, DisclosureLevel, DisclosureReceipt, EffectReceipt,
    MaterializationRequest, MaterializeMode, ObservationRemaskReport, Projection, ResolveRequest,
    ResolveResult, SemanticContract, SemanticHandle, SvfEpoch, TaskRequestEnvelope,
    AGENTIC_OBJECT_SCHEMA, BROKER_DECISION_SCHEMA, CONTEXT_MANIFEST_SCHEMA,
    DERIVED_KNOWLEDGE_SCHEMA, DISCLOSURE_GRANT_SCHEMA, DISCLOSURE_RECEIPT_SCHEMA,
    EFFECT_RECEIPT_SCHEMA, MATERIALIZATION_REQUEST_SCHEMA, OBSERVATION_REMASK_SCHEMA,
    PROJECTION_SCHEMA, RESOLVE_REQUEST_SCHEMA, RESOLVE_RESULT_SCHEMA, SEMANTIC_CONTRACT_SCHEMA,
    SEMANTIC_HANDLE_SCHEMA, SVF_EPOCH_SCHEMA, SVF_SCHEMA, TASK_REQUEST_ENVELOPE_SCHEMA,
};
pub use hardware_placement::{
    HardwarePlacementV2, IntelligenceEdgeStateV2, HARDWARE_PLACEMENT_SCHEMA,
    INTELLIGENCE_EDGE_STATE_SCHEMA,
};
pub use iia::{
    canonical_digest_json, sign_json_ed25519, verify_json_ed25519, verify_signed_payload_v2,
    verify_cpo_structure, verify_export_chain, verify_principal_envelope, verify_quantum_active,
    AgentContractV2,
    AttestationTierV2, CognitiveProposalV2, ContextClassV2, ContextSliceV2, ContinuityRecordV2,
    ContinuityStateV2, ExecutionQuantumV2, ExecutionRealityManifestV2, FourIdLinkageV2,
    AgentFoundationBlockV2, FoundationFusionV2,
    AgentActivationProfileV2, AgentCapabilityManifestV2, AgentIdentityEnvelopeV2,
    AgentKnowledgeSummaryV2, AgentKnotSummaryV2, AgentMemorySummaryV2,
    AgentNamespaceScopeV2, AgentSetupSpecV2, ActivationStateV2,
    ForensicPostureV2, ForensicProfileV2, ForensicUniversalEnvelopeV2,
    ForensicRollupBucketV2, ForensicRollupCountsV2, ForensicRollupMemoryTraceV2,
    ForensicCorrelationJoinV2, ForensicPackageManifestV2, ForensicPackageHonestyV2,
    ComplianceContractV2, ComplianceFrameworkBindingV2, EvidencePolicyV2,
    HitlPolicyV2, HitlPostureV2, MemoryProfileV2, NamespaceGrantV2,
    AGENT_IDENTITY_SCHEMA, COGNITIVE_MEMORY_TYPES, FORENSIC_UNIVERSAL_SCHEMA,
    COMPLIANCE_CONTRACT_SCHEMA, FORENSIC_ROLLUP_SCHEMA, FORENSIC_PACKAGE_SCHEMA,
    FORENSIC_CORRELATION_SCHEMA, NAMESPACE_PREFIX_TYPES,
    IIA_SCHEMA, IntelligencePrincipalV2, IntelligenceProfileV2, IntelligenceReceiptV2,
    PRINCIPAL_PREFIX, ProfileQuadrantV2, RuntimeSelfEnvelopeV2, SignedPayloadV2, SigningTierV2,
    mint_principal_id,
};

/// Contract schema major version for these types.
pub const TRUST_CONTRACT_VERSION: u32 = 2;
