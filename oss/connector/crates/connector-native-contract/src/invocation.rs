//! Invocation envelopes and related descriptors.

use serde::{Deserialize, Serialize};

use crate::semantic::{SemanticConfidence, SemanticProvenance};
use crate::surface::TargetState;

/// Invocation lifecycle mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum InvocationMode {
    #[default]
    Call,
    Request,
    Start,
    Stream,
    Session,
    Signal,
}

/// Origin of an invocation (workload + intelligence + principal).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationOrigin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_uid: Option<String>,
    pub workload_uid: String,
    pub intelligence_uid: String,
    pub principal: String,
}

/// Canonical action description (verb + optional resource / params digest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalAction {
    pub verb: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_digest: Option<String>,
}

/// Effect class for authority / disclosure checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectDescriptor {
    pub effect_class: String,
    pub mutates: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_class: Option<String>,
}

/// Canonical invocation envelope (neutral CNKTROS form).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationEnvelope {
    pub invocation_id: String,
    pub origin: InvocationOrigin,
    pub target: TargetState,
    pub semantic_provenance: SemanticProvenance,
    pub semantic_confidence: SemanticConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<CanonicalAction>,
    pub effect: EffectDescriptor,
    pub contract_ref: String,
    pub contract_revision: u64,
    pub authority_ref: String,
    pub authority_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_ref: Option<String>,
    pub lifecycle_mode: InvocationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<i64>,
}
