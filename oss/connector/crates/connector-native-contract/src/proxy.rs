//! Embedded proxy plane contracts — route graph hops (Envoy/xDS deferred).

use serde::{Deserialize, Serialize};

use crate::package_gate::PackagePin;

pub const PROXY_HOP_SCHEMA: &str = "connector.proxy_hop.v1";
pub const ROUTE_GRAPH_SCHEMA: &str = "connector.route_graph.v1";

/// Kind of hop in the Connector-owned route graph.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHopKind {
    /// In-process forward (cage / local adapter).
    Embedded,
    /// Transparent egress channel hop (ticket + optional kernel redirect).
    TransparentEgress,
    /// Protocol driver (MCP/CNP/…) — authority still Connector.
    ProtocolDriver,
    /// Reserved for future Envoy/xDS backend.
    Envoy,
}

/// Single hop: resolve → destination lease → execute via existing forward/egress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyHop {
    pub schema: String,
    pub hop_id: String,
    pub kind: ProxyHopKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    /// Max child hops reachable from this node (inclusive of self).
    #[serde(default = "default_hop_budget")]
    pub hop_budget: u32,
}

fn default_hop_budget() -> u32 {
    8
}

impl ProxyHop {
    pub fn transparent_egress(
        hop_id: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        flow_id: Option<String>,
    ) -> Self {
        Self {
            schema: PROXY_HOP_SCHEMA.into(),
            hop_id: hop_id.into(),
            kind: ProxyHopKind::TransparentEgress,
            channel_uid: None,
            surface_uid: None,
            destination_host: Some(host.into()),
            destination_port: Some(port),
            destination_protocol: Some("tcp".into()),
            flow_id,
            hop_budget: default_hop_budget(),
        }
    }

    /// Protocol-driver hop — Connector remains authority; driver only decodes.
    pub fn protocol_driver(
        hop_id: impl Into<String>,
        protocol: impl Into<String>,
        channel_uid: Option<String>,
        surface_uid: Option<String>,
        flow_id: Option<String>,
    ) -> Self {
        Self {
            schema: PROXY_HOP_SCHEMA.into(),
            hop_id: hop_id.into(),
            kind: ProxyHopKind::ProtocolDriver,
            channel_uid,
            surface_uid,
            destination_host: None,
            destination_port: None,
            destination_protocol: Some(protocol.into()),
            flow_id,
            hop_budget: default_hop_budget(),
        }
    }
}

/// Versioned route graph snapshot (embedded executor; Envoy compile later).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteGraph {
    pub schema: String,
    pub revision: u64,
    pub tenant_id: String,
    pub hops: Vec<ProxyHop>,
    /// Hard cap on hops traversed per execution (fail closed).
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    /// Signed AppPackageV2 pin for route_set publish (required outside lab).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackagePin>,
}

fn default_max_hops() -> u32 {
    8
}

impl RouteGraph {
    pub fn new(tenant_id: impl Into<String>, revision: u64, hops: Vec<ProxyHop>) -> Self {
        Self {
            schema: ROUTE_GRAPH_SCHEMA.into(),
            revision,
            tenant_id: tenant_id.into(),
            hops,
            max_hops: default_max_hops(),
            package: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.hops.is_empty() {
            return Err("route_graph_empty".into());
        }
        if self.hops.len() as u32 > self.max_hops {
            return Err(format!(
                "route_graph_hop_limit:{}>{}",
                self.hops.len(),
                self.max_hops
            ));
        }
        for h in &self.hops {
            if h.hop_budget == 0 {
                return Err(format!("hop_budget_zero:{}", h.hop_id));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_limit_denies_oversized_graph() {
        let hops: Vec<_> = (0..10)
            .map(|i| ProxyHop::transparent_egress(format!("h{i}"), "example.com", 443, None))
            .collect();
        let g = RouteGraph {
            max_hops: 8,
            ..RouteGraph::new("t1", 1, hops)
        };
        assert!(g.validate().unwrap_err().contains("hop_limit"));
    }

    #[test]
    fn valid_single_hop() {
        let g = RouteGraph::new(
            "t1",
            1,
            vec![ProxyHop::transparent_egress("h0", "api.example", 443, Some("fl_1".into()))],
        );
        assert!(g.validate().is_ok());
        assert_eq!(g.hops[0].kind, ProxyHopKind::TransparentEgress);
    }
}
