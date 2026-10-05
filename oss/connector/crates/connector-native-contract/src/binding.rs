//! Augmented software/intelligence bindings.

use serde::{Deserialize, Serialize};

/// Executable constraints for an augmented binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutableConstraints {
    pub path_or_selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_policy: Option<String>,
}

/// Binding mode for managed vs attached workloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum BindingMode {
    #[default]
    Managed,
    Attached,
}

/// Augmented binding of software to an intelligence contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AugmentedBinding {
    pub binding_uid: String,
    pub software_uid: String,
    pub executable_constraints: ExecutableConstraints,
    pub intelligence_contract: String,
    /// Surface policies as opaque strings for v1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_surfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adapter_set: Vec<String>,
    pub channel_policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enforcement_requirements: Vec<String>,
    pub mode: BindingMode,
}
