//! Data context, identity graph refs, and relational containers.
//!
//! For heavier content and external-world data: same keys as Vector Box,
//! pointing into Knot / relational memory without a second kernel.

use serde::{Deserialize, Serialize};

use crate::vector_box::MemoryVectorBox;

/// External or heavy payload reference — content stays content-addressed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalDataRef {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u64>,
    /// When the blob was also stored as a MemPacket CID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_cid: Option<String>,
}

/// Identity / entity graph node reference (Knot-compatible).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityGraphNodeRef {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Owning identity key (agent DID / principal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    #[serde(default)]
    pub packet_cids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityGraphEdgeRef {
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_cid: Option<String>,
}

/// Relational container — edges + member boxes for play/analyse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationalContainer {
    pub container_id: String,
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_key: Option<String>,
    #[serde(default)]
    pub member_super_keys: Vec<String>,
    #[serde(default)]
    pub member_cids: Vec<String>,
    #[serde(default)]
    pub edges: Vec<IdentityGraphEdgeRef>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

/// Data context — heavier / external world bound to the same identity + keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataContextContainer {
    pub context_id: String,
    /// Same identity key family as MemoryVectorBox.
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Core memory boxes in this context.
    #[serde(default)]
    pub boxes: Vec<MemoryVectorBox>,
    /// Heavy / external refs.
    #[serde(default)]
    pub external: Vec<ExternalDataRef>,
    /// Identity graph projection.
    #[serde(default)]
    pub graph_nodes: Vec<IdentityGraphNodeRef>,
    #[serde(default)]
    pub graph_edges: Vec<IdentityGraphEdgeRef>,
    /// Relational projections.
    #[serde(default)]
    pub relational: Vec<RelationalContainer>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

impl DataContextContainer {
    pub fn new(context_id: impl Into<String>, identity_key: impl Into<String>) -> Self {
        Self {
            context_id: context_id.into(),
            identity_key: identity_key.into(),
            tenant_id: None,
            session_id: None,
            boxes: vec![],
            external: vec![],
            graph_nodes: vec![],
            graph_edges: vec![],
            relational: vec![],
            contract_version: 2,
        }
    }
}
