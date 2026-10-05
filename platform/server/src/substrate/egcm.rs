//! EGCM — Entropic Graph Control Management (shadow-capable control graph).
//!
//! Unifies CONP capability nodes, CNP wire edges, and address-identity edges
//! into one snapshot for RGO disorder bumps. P2 ships observe/shadow first —
//! does not replace ActionBinding.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;
use connector_protocol::ProtocolCapabilityRegistry;

pub const EGCM_SCHEMA: &str = "connector.egcm.snapshot.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlNodeKind {
    Tool,
    ConpCapability,
    CnpPeer,
    Address,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlNode {
    pub id: String,
    pub kind: ControlNodeKind,
    pub risk: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGraphSnapshot {
    pub schema: String,
    pub agent_pid: String,
    pub nodes: Vec<ControlNode>,
    pub edges: Vec<ControlEdge>,
    /// 0.0–1.0 disorder estimate from local graph density / entropy hints.
    pub disorder: f32,
    /// When true, RGO should bump reversibility class by one.
    pub disorder_bump: bool,
    pub shadow: bool,
}

fn disorder_threshold() -> f32 {
    std::env::var("CONNECTOR_EGCM_DISORDER_BUMP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.72)
}

fn shadow_mode() -> bool {
    match std::env::var("CONNECTOR_EGCM_SHADOW").ok().as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        // Default on for P2 — observe without enforcing graph deny.
        _ => true,
    }
}

/// Build a control-graph snapshot for an agent (CONP caps + address + CNP peers).
pub fn snapshot_for_agent(state: &PlatformState, agent_pid: &str) -> ControlGraphSnapshot {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let agent_id = format!("agent:{agent_pid}");
    nodes.push(ControlNode {
        id: agent_id.clone(),
        kind: ControlNodeKind::Agent,
        risk: "r1".into(),
        label: Some(agent_pid.into()),
    });

    // CONP capability taxonomy (bounded sample of high-risk + all if small).
    let reg = ProtocolCapabilityRegistry::with_defaults();
    let caps = reg.list_all();
    for cap in caps.iter().take(120) {
        let id = format!("conp:{}", cap.id);
        let risk = match cap.risk {
            connector_protocol::RiskLevel::Critical => "irreversible",
            connector_protocol::RiskLevel::High => "high",
            connector_protocol::RiskLevel::Medium => "medium",
            connector_protocol::RiskLevel::Low => "normal",
        };
        nodes.push(ControlNode {
            id: id.clone(),
            kind: ControlNodeKind::ConpCapability,
            risk: risk.into(),
            label: Some(cap.id.clone()),
        });
        edges.push(ControlEdge {
            from: agent_id.clone(),
            to: id,
            relation: "may_invoke".into(),
        });
    }

    // Address identity edges (existence only — DAC details stay in address_dac).
    for addr in crate::kernel::address_contracts::known_addresses(state)
        .into_iter()
        .take(64)
    {
        let id = format!("addr:{addr}");
        nodes.push(ControlNode {
            id: id.clone(),
            kind: ControlNodeKind::Address,
            risk: "r1".into(),
            label: Some(addr),
        });
        edges.push(ControlEdge {
            from: agent_id.clone(),
            to: id,
            relation: "address_scope".into(),
        });
    }

    // CNP peer map (if present on state).
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(peers)) = es.folder_get("cnp_peers", "index") {
            if let Some(arr) = peers.as_array() {
                for p in arr.iter().take(32) {
                    let peer = p
                        .get("peer_id")
                        .or_else(|| p.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("peer");
                    let id = format!("cnp:{peer}");
                    nodes.push(ControlNode {
                        id: id.clone(),
                        kind: ControlNodeKind::CnpPeer,
                        risk: "medium".into(),
                        label: Some(peer.into()),
                    });
                    edges.push(ControlEdge {
                        from: agent_id.clone(),
                        to: id,
                        relation: "cnp_wire".into(),
                    });
                }
            }
        }
    }

    // Disorder: high-risk share + KECS hint if available.
    let high = nodes
        .iter()
        .filter(|n| matches!(n.risk.as_str(), "high" | "irreversible" | "critical"))
        .count() as f32;
    let mut disorder = if nodes.is_empty() {
        0.0
    } else {
        (high / nodes.len() as f32).clamp(0.0, 1.0)
    };
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(meta)) = es.folder_get("agent_meta", agent_pid) {
            if let Some(kecs) = meta
                .get("kecs_score")
                .or_else(|| meta.get("entropy_radius"))
                .and_then(|v| v.as_f64())
            {
                disorder = disorder.max((kecs as f32).clamp(0.0, 1.0));
            }
        }
    }

    let bump = disorder >= disorder_threshold();
    ControlGraphSnapshot {
        schema: EGCM_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        nodes,
        edges,
        disorder,
        disorder_bump: bump,
        shadow: shadow_mode(),
    }
}

pub fn snapshot_json(state: &PlatformState, agent_pid: &str) -> Value {
    let s = snapshot_for_agent(state, agent_pid);
    serde_json::to_value(s).unwrap_or(json!({ "error": "egcm_serialize" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constant() {
        assert!(EGCM_SCHEMA.contains("egcm"));
    }
}
