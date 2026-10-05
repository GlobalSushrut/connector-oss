//! Hardware placement + intelligence edge state — seed for L5 geo-identity.
//!
//! Field vocabulary binds to platform `CellAddress` (`distributed/transport.rs`):
//! `cell_id`, `region`, `endpoints`, `capabilities`, `location_signature`.

use serde::{Deserialize, Serialize};

pub const HARDWARE_PLACEMENT_SCHEMA: &str = "hardware_placement.v2";
pub const INTELLIGENCE_EDGE_STATE_SCHEMA: &str = "intelligence_edge_state.v2";

/// Portable cell/hardware placement (CellAddress-equivalent trust contract).
///
/// Endpoints are strings (e.g. `quic://1.2.3.4:4433`) so this crate stays free of
/// platform socket / transport enums; platform adapts `Vec<Endpoint>` ↔ strings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwarePlacementV2 {
    pub schema: String,
    /// Global cell id when known (`CellAddress.cell_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<String>,
    /// Region / geo label (`CellAddress.region`).
    pub region: String,
    /// Network endpoints as portable strings (`CellAddress.endpoints`).
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Capabilities this placement provides (`CellAddress.capabilities`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Digital location signature when present (`CellAddress.location_signature`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_signature: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl HardwarePlacementV2 {
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            schema: HARDWARE_PLACEMENT_SCHEMA.into(),
            cell_id: None,
            region: region.into(),
            endpoints: Vec::new(),
            capabilities: Vec::new(),
            location_signature: None,
            contract_version: 2,
        }
    }

    pub fn with_cell_id(mut self, cell_id: impl Into<String>) -> Self {
        self.cell_id = Some(cell_id.into());
        self
    }

    pub fn with_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_location_signature(mut self, sig: impl Into<String>) -> Self {
        self.location_signature = Some(sig.into());
        self
    }
}

/// Intelligence identity placed on a hardware/geo edge (identity × placement).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceEdgeStateV2 {
    pub schema: String,
    /// Intelligence / agent / principal identity at this edge.
    pub identity_id: String,
    pub placement: HardwarePlacementV2,
    /// Optional health vocabulary aligned with `CellHealth` (`healthy` / `degraded` / …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<i64>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

impl IntelligenceEdgeStateV2 {
    pub fn new(identity_id: impl Into<String>, placement: HardwarePlacementV2) -> Self {
        Self {
            schema: INTELLIGENCE_EDGE_STATE_SCHEMA.into(),
            identity_id: identity_id.into(),
            placement,
            health: None,
            last_seen_ms: None,
            contract_version: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_placement_round_trip() {
        let p = HardwarePlacementV2::new("us-east-1")
            .with_cell_id("cell-a")
            .with_endpoints(vec!["quic://10.0.0.1:4433".into(), "tcp://10.0.0.1:8443".into()])
            .with_capabilities(vec!["memory".into(), "llm".into()])
            .with_location_signature("sig-abc");
        assert_eq!(p.schema, HARDWARE_PLACEMENT_SCHEMA);
        let json = serde_json::to_string(&p).unwrap();
        let back: HardwarePlacementV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.region, "us-east-1");
        assert_eq!(back.cell_id.as_deref(), Some("cell-a"));
        assert_eq!(back.endpoints.len(), 2);
        assert_eq!(back.capabilities, vec!["memory", "llm"]);
        assert_eq!(back.location_signature.as_deref(), Some("sig-abc"));
    }

    #[test]
    fn intelligence_edge_state_round_trip() {
        let placement = HardwarePlacementV2::new("eu-west-1")
            .with_endpoints(vec!["quic://192.0.2.10:4433".into()])
            .with_capabilities(vec!["custody".into()]);
        let edge = IntelligenceEdgeStateV2 {
            health: Some("healthy".into()),
            last_seen_ms: Some(1_700_000_000_000),
            ..IntelligenceEdgeStateV2::new("agent_pid_1", placement)
        };
        assert_eq!(edge.schema, INTELLIGENCE_EDGE_STATE_SCHEMA);
        let json = serde_json::to_string(&edge).unwrap();
        let back: IntelligenceEdgeStateV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, edge);
        assert_eq!(back.identity_id, "agent_pid_1");
        assert_eq!(back.placement.region, "eu-west-1");
        assert_eq!(back.health.as_deref(), Some("healthy"));
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let p = HardwarePlacementV2::new("local");
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("cell_id").is_none());
        assert!(json.get("location_signature").is_none());
        assert_eq!(json["endpoints"], serde_json::json!([]));
    }
}
