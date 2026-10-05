//! Network Management API
//!
//! Provides endpoints for network operations using real kernel state.

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::state::SharedState;
use super::V2Response;

/// List networks from kernel namespaces
pub async fn list_networks(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let networks: Vec<serde_json::Value> = {
        let kernel = state.kernel.lock().unwrap();
        let agents = kernel.agents();
        let mut namespaces: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (pid, agent) in agents.iter() {
            namespaces.entry(agent.namespace.clone()).or_default().push(pid.clone());
        }
        namespaces
            .into_iter()
            .map(|(ns, pids)| {
                serde_json::json!({
                    "namespace": ns,
                    "agent_pids": pids,
                    "agent_count": pids.len(),
                    "honesty": "Kernel namespace membership. Not a VPC or CIDR.",
                })
            })
            .collect()
    };
    
    let response = serde_json::json!({
        "total": networks.len(),
        "namespaces": networks,
    });
    
    V2Response::success(response)
}

/// Inspect network details
pub async fn inspect_network(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Find agents in this namespace
    let network = {
        let kernel = state.kernel.lock().unwrap();
        let ns = format!("ns:{}", name.replace("-", ":"));
        let agents_in_ns: Vec<_> = kernel.agents()
            .iter()
            .filter(|(_, a)| a.namespace == ns || a.namespace.contains(&name))
            .map(|(pid, _)| pid.clone())
            .collect();
        
        serde_json::json!({
            "name": name,
            "namespace": ns,
            "agent_pids": agents_in_ns,
            "agent_count": agents_in_ns.len(),
            "honesty": "Kernel namespace membership. Not a VPC, CIDR, route table, or security group.",
        })
    };
    
    V2Response::success(network)
}

/// POST /api/v2/network/test — real TCP connectivity probe against target:port.
///
/// This previously reported `reachable` whenever any agent existed and returned
/// the mutex-acquire time as network latency, never contacting the target at all.
pub async fn test_network(
    State(_state): State<SharedState>,
    Json(request): Json<NetworkTestRequest>,
) -> impl IntoResponse {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    let target = request.target.clone();
    let port = request.port;
    let probe = tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let mut addrs = match format!("{target}:{port}").to_socket_addrs() {
            Ok(a) => a,
            Err(e) => return (false, None, Some(format!("resolve failed: {e}"))),
        };
        let Some(addr) = addrs.next() else {
            return (
                false,
                None,
                Some("hostname resolved to no addresses".to_string()),
            );
        };
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(_) => (true, Some(started.elapsed().as_millis() as u64), None),
            Err(e) => (false, None, Some(e.to_string())),
        }
    })
    .await;

    let (reachable, latency_ms, error) = match probe {
        Ok(v) => v,
        Err(e) => (false, None, Some(format!("probe task failed: {e}"))),
    };

    let result = NetworkTestResult {
        target: request.target,
        port: request.port,
        reachable,
        latency_ms,
        error,
        tested_at: Utc::now().to_rfc3339(),
    };

    V2Response::success(result)
}

// Types
#[derive(Debug, Clone, Serialize)]
pub struct Network {
    pub name: String,
    pub cidr: String,
    pub region: String,
    pub status: String,
    pub vpc_id: String,
    pub subnets: Vec<Subnet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subnet {
    pub id: String,
    pub cidr: String,
    pub availability_zone: String,
    pub available_ips: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListNetworksResponse {
    pub networks: Vec<Network>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkDetails {
    pub name: String,
    pub cidr: String,
    pub region: String,
    pub status: String,
    pub vpc_id: String,
    pub route_tables: Vec<RouteTable>,
    pub security_groups: Vec<SecurityGroup>,
    pub peering_connections: Vec<PeeringConnection>,
    pub agents: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteTable {
    pub id: String,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub destination: String,
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityGroup {
    pub id: String,
    pub name: String,
    pub inbound_rules: Vec<SecurityRule>,
    pub outbound_rules: Vec<SecurityRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityRule {
    pub protocol: String,
    pub port: String,
    pub source: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeeringConnection {
    pub id: String,
    pub peer_vpc: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkTestRequest {
    pub target: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,
}

fn default_port() -> u16 { 443 }
fn default_timeout() -> u32 { 10 }

#[derive(Debug, Clone, Serialize)]
pub struct NetworkTestResult {
    pub target: String,
    pub port: u16,
    pub reachable: bool,
    /// Connect time, present only when the probe actually connected.
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
    pub tested_at: String,
}
