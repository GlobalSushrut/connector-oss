//! Distributed Agent Network Surface — DAO-style registry, location, discovery
//!
//! Surfaces for viewing the distributed multi-agent network topology.

use super::document::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cell (node) in the distributed network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellInfo {
    pub cell_id: String,
    pub region: String,
    pub zone: String,
    pub status: CellStatus,
    pub agent_count: u32,
    pub capacity: u32,
    pub load_percent: f64,
    pub last_heartbeat: i64,
    pub public_endpoint: Option<String>,
    pub internal_endpoint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellStatus {
    Online,
    Degraded,
    Offline,
    Draining,
    Maintenance,
}

impl CellStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "ONLINE",
            Self::Degraded => "DEGRADED",
            Self::Offline => "OFFLINE",
            Self::Draining => "DRAINING",
            Self::Maintenance => "MAINTENANCE",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Online => Severity::Ok,
            Self::Degraded | Self::Draining => Severity::Warn,
            Self::Offline => Severity::Critical,
            Self::Maintenance => Severity::Info,
        }
    }
}

/// Agent location in the distributed network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLocation {
    pub agent_pid: String,
    pub cell_id: String,
    pub region: String,
    pub registered_at: i64,
    pub last_seen: i64,
    pub status: AgentNetworkStatus,
    pub capabilities: Vec<String>,
    pub service_contract_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentNetworkStatus {
    Active,
    Idle,
    Busy,
    Migrating,
    Unreachable,
    Terminated,
}

/// Network topology view
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub cells: Vec<CellInfo>,
    pub agents: Vec<AgentLocation>,
    pub total_agents: u32,
    pub total_capacity: u32,
    pub cross_cell_messages_24h: u64,
    pub avg_latency_ms: u64,
}

impl NetworkTopology {
    pub fn agents_by_cell(&self) -> HashMap<String, Vec<&AgentLocation>> {
        let mut map: HashMap<String, Vec<&AgentLocation>> = HashMap::new();
        for agent in &self.agents {
            map.entry(agent.cell_id.clone()).or_default().push(agent);
        }
        map
    }

    pub fn online_cells(&self) -> Vec<&CellInfo> {
        self.cells.iter().filter(|c| c.status == CellStatus::Online).collect()
    }

    pub fn active_agents(&self) -> Vec<&AgentLocation> {
        self.agents.iter().filter(|a| a.status == AgentNetworkStatus::Active).collect()
    }
}

/// Agent discovery query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    pub capability: Option<String>,
    pub region: Option<String>,
    pub min_reputation: Option<f64>,
    pub max_latency_ms: Option<u64>,
    pub exclude_busy: bool,
}

/// Discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub query: DiscoveryQuery,
    pub matches: Vec<AgentMatch>,
    pub total_searched: u32,
    pub search_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMatch {
    pub agent_pid: String,
    pub cell_id: String,
    pub score: f64,
    pub latency_ms: u64,
    pub reputation: f64,
    pub capabilities: Vec<String>,
}

/// Build network topology surface
pub fn build_network_surface(topology: &NetworkTopology, view: SurfaceView) -> SurfaceDocument {
    let online_count = topology.cells.iter().filter(|c| c.status == CellStatus::Online).count();
    let active_agents = topology.agents.iter().filter(|a| a.status == AgentNetworkStatus::Active).count();

    let health = if online_count == topology.cells.len() {
        Severity::Ok
    } else if online_count > topology.cells.len() / 2 {
        Severity::Warn
    } else {
        Severity::Critical
    };

    let mut sections = vec![
        SurfaceSection {
            title: "Network Overview".into(),
            kind: SectionKind::StatsGrid,
            content: SectionContent::Stats(vec![
                StatItem { label: "Cells".into(), value: format!("{}/{} online", online_count, topology.cells.len()), link: None },
                StatItem { label: "Agents".into(), value: format!("{}/{} active", active_agents, topology.total_agents), link: None },
                StatItem { label: "Capacity".into(), value: format!("{}%", (topology.total_agents as f64 / topology.total_capacity as f64 * 100.0) as u32), link: None },
                StatItem { label: "Cross-Cell (24h)".into(), value: topology.cross_cell_messages_24h.to_string(), link: None },
                StatItem { label: "Avg Latency".into(), value: format!("{}ms", topology.avg_latency_ms), link: None },
            ]),
            collapsed: false,
        },
    ];

    // Cell list
    sections.push(SurfaceSection {
        title: "Cells".into(),
        kind: SectionKind::List,
        content: SectionContent::List(topology.cells.iter().map(|c| ListItem {
            text: format!("{} ({}/{}) [{}] - {} agents, {:.0}% load",
                c.cell_id, c.region, c.zone, c.status.as_str(), c.agent_count, c.load_percent),
            link: Some(ResourceLink::inspect(ResourceKind::Agent, &c.cell_id)),
        }).collect()),
        collapsed: view == SurfaceView::Summary,
    });

    if view == SurfaceView::Ops || view == SurfaceView::Forensic {
        // Agent distribution by region
        let mut by_region: HashMap<String, u32> = HashMap::new();
        for agent in &topology.agents {
            *by_region.entry(agent.region.clone()).or_default() += 1;
        }
        sections.push(SurfaceSection {
            title: "Agent Distribution".into(),
            kind: SectionKind::KeyValueTable,
            content: SectionContent::KeyValue(by_region.iter().map(|(k, v)| KeyValueItem {
                key: k.clone(),
                value: v.to_string(),
                link: None,
            }).collect()),
            collapsed: false,
        });
    }

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Monitor,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: "NETWORK: Distributed Agent Topology".into(),
            subject: SubjectIdentity {
                display: "network/global".into(),
                inspect: "global".into(),
                proof: "net_global".into(),
                uid: "global".into(),
                kind: ResourceKind::Agent,
                namespace: None,
            },
            state: StateVector {
                execution: ExecutionState::Active,
                trust: TrustState::Verified,
                health: if health == Severity::Ok { HealthState::Healthy } else { HealthState::Degraded },
                compliance: ComplianceState::Compliant,
            },
            badges: vec![
                SurfaceBadge { label: "Cells".into(), value: format!("{}", topology.cells.len()), severity: Severity::Info },
                SurfaceBadge { label: "Agents".into(), value: format!("{}", topology.total_agents), severity: Severity::Info },
                SurfaceBadge { label: "Health".into(), value: if health == Severity::Ok { "HEALTHY" } else { "DEGRADED" }.into(), severity: health },
            ],
            time_range: None,
        },
        summary: Some(format!("{} cells, {} agents across {} regions",
            topology.cells.len(), topology.total_agents,
            topology.cells.iter().map(|c| &c.region).collect::<std::collections::HashSet<_>>().len())),
        sections,
        actions: vec![
            SurfaceAction { label: "Refresh".into(), description: "Refresh topology".into(), command: "connectorctl network status".into(), primary: true },
            SurfaceAction { label: "Discover".into(), description: "Discover agents".into(), command: "connectorctl network discover".into(), primary: false },
        ],
        footer: None,
    }
}

/// Build agent location surface
pub fn build_agent_location_surface(agent: &AgentLocation, view: SurfaceView) -> SurfaceDocument {
    let status_severity = match agent.status {
        AgentNetworkStatus::Active => Severity::Ok,
        AgentNetworkStatus::Idle | AgentNetworkStatus::Busy => Severity::Info,
        AgentNetworkStatus::Migrating => Severity::Warn,
        AgentNetworkStatus::Unreachable | AgentNetworkStatus::Terminated => Severity::Critical,
    };

    SurfaceDocument {
        meta: SurfaceMeta {
            surface_type: SurfaceType::Agent,
            view,
            generated_at: chrono::Utc::now().timestamp_millis(),
        },
        header: SurfaceHeader {
            title: format!("LOCATION: {}", agent.agent_pid),
            subject: SubjectIdentity::new(ResourceKind::Agent, &agent.agent_pid),
            state: StateVector::active_verified(),
            badges: vec![
                SurfaceBadge { label: "Cell".into(), value: agent.cell_id.clone(), severity: Severity::Info },
                SurfaceBadge { label: "Region".into(), value: agent.region.clone(), severity: Severity::Info },
                SurfaceBadge { label: "Status".into(), value: format!("{:?}", agent.status), severity: status_severity },
            ],
            time_range: None,
        },
        summary: Some(format!("Agent {} located in {} ({})", agent.agent_pid, agent.cell_id, agent.region)),
        sections: vec![
            SurfaceSection {
                title: "Location Details".into(),
                kind: SectionKind::KeyValueTable,
                content: SectionContent::KeyValue(vec![
                    KeyValueItem { key: "Agent PID".into(), value: agent.agent_pid.clone(), link: None },
                    KeyValueItem { key: "Cell".into(), value: agent.cell_id.clone(), link: Some(ResourceLink::inspect(ResourceKind::Agent, &agent.cell_id)) },
                    KeyValueItem { key: "Region".into(), value: agent.region.clone(), link: None },
                    KeyValueItem { key: "Status".into(), value: format!("{:?}", agent.status), link: None },
                    KeyValueItem { key: "Last Seen".into(), value: format!("{}ms ago", chrono::Utc::now().timestamp_millis() - agent.last_seen), link: None },
                ]),
                collapsed: false,
            },
            SurfaceSection {
                title: "Capabilities".into(),
                kind: SectionKind::List,
                content: SectionContent::List(agent.capabilities.iter().map(|c| ListItem {
                    text: c.clone(),
                    link: None,
                }).collect()),
                collapsed: false,
            },
        ],
        actions: vec![
            SurfaceAction { label: "Migrate".into(), description: "Migrate to another cell".into(), command: format!("connectorctl agent migrate {}", agent.agent_pid), primary: false },
            SurfaceAction { label: "Inspect".into(), description: "Deep inspect".into(), command: format!("connectorctl agent inspect {}", agent.agent_pid), primary: true },
        ],
        footer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_surface() {
        let topology = NetworkTopology {
            cells: vec![
                CellInfo {
                    cell_id: "cell-us-east-1".into(),
                    region: "us-east".into(),
                    zone: "1a".into(),
                    status: CellStatus::Online,
                    agent_count: 10,
                    capacity: 50,
                    load_percent: 20.0,
                    last_heartbeat: chrono::Utc::now().timestamp_millis(),
                    public_endpoint: Some("https://cell-us-east-1.connector.io".into()),
                    internal_endpoint: "10.0.1.1:8080".into(),
                },
            ],
            agents: vec![],
            total_agents: 10,
            total_capacity: 50,
            cross_cell_messages_24h: 1000,
            avg_latency_ms: 50,
        };

        let doc = build_network_surface(&topology, SurfaceView::Summary);
        assert!(doc.header.title.contains("NETWORK"));
    }
}
