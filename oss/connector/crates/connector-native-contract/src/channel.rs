//! Channel observation and binding state.

use serde::{Deserialize, Serialize};

use crate::semantic::SemanticConfidence;

/// Channel traffic direction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChannelDirection {
    Outbound,
    Inbound,
    Bidirectional,
}

/// Channel classification / admission state machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    #[default]
    Observed,
    BoundToOrigin,
    Classifying,
    Unresolved,
    ProtocolObserved,
    AdapterVerified,
    NativeVerified,
    AuthorityCheck,
    Denied,
    InputRequired,
    Admitted,
    Executing,
    Succeeded,
    Failed,
    UnknownOutcome,
    Cancelled,
}

/// Transport-layer observation for a channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TransportObservation {
    /// Transport name (`tcp`, `udp`, `unix`, `http`, …).
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_lineage: Option<String>,
}

/// Raw observation of a channel prior to full binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelObservation {
    pub origin_intelligence: String,
    pub origin_workload: String,
    pub direction: ChannelDirection,
    pub transport: TransportObservation,
    pub observed_at_ms: i64,
    #[serde(default = "default_raw_hints")]
    pub raw_hints: serde_json::Value,
}

fn default_raw_hints() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

impl Default for ChannelObservation {
    fn default() -> Self {
        Self {
            origin_intelligence: String::new(),
            origin_workload: String::new(),
            direction: ChannelDirection::Outbound,
            transport: TransportObservation::default(),
            observed_at_ms: 0,
            raw_hints: default_raw_hints(),
        }
    }
}

/// Bound channel reference with semantic and authority revisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRef {
    pub channel_uid: String,
    pub origin_intelligence: String,
    pub origin_workload: String,
    pub direction: ChannelDirection,
    pub transport: TransportObservation,
    /// Peer surface UID when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    pub contract_revision: u64,
    pub authority_revision: u64,
    pub semantic_confidence: SemanticConfidence,
    pub state: ChannelState,
}
