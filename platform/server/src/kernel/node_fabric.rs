//! Node fabric — honest topology for a sovereign cell.
//!
//! This node is the unit of global infra. Multi-cell is opt-in via durable
//! peer URLs + heartbeat. CNP L5 routing is not claimed live. Agent state
//! does not migrate. Mesh is only `cell_mesh` when at least one peer ACK'd
//! within the TTL.

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::PlatformState;

pub const FABRIC_SCHEMA: &str = "connector.node.fabric.v1";
pub const PEER_FOLDER: &str = "node_fabric_peers_v1";
const PEER_TTL_SECS: i64 = 90;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn local_cell_id() -> String {
    std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cell-local".into())
}

/// True when `CONNECTOR_CNP_PEERS` seeds at least one static 1-hop route.
pub fn cnp_l5_static_live() -> bool {
    crate::cnp::wire::l5_static_routing_live()
}

/// Record a successful peer ping (durable). Call from membership heartbeat.
pub fn record_peer_ack(state: &PlatformState, peer_url: &str) {
    let url = peer_url.trim();
    if url.is_empty() {
        return;
    }
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let rec = json!({
        "url": url,
        "last_ack_unix": now_unix(),
        "cell_id": local_cell_id(),
    });
    let _ = es.folder_put(PEER_FOLDER, url, &rec);
}

pub fn live_peer_count(state: &PlatformState) -> usize {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    let now = now_unix();
    let keys = es.folder_keys(PEER_FOLDER, None).unwrap_or_default();
    let mut n = 0usize;
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(PEER_FOLDER, &k) {
            let ack = v.get("last_ack_unix").and_then(|x| x.as_i64()).unwrap_or(0);
            if now.saturating_sub(ack) <= PEER_TTL_SECS {
                n += 1;
            }
        }
    }
    n
}

/// Product topology. Never reports cell_mesh without a live peer ACK.
pub fn snapshot(state: &PlatformState) -> Value {
    let peers = live_peer_count(state);
    let env_mesh = std::env::var("CONNECTOR_MESH_FABRIC")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let mesh = env_mesh && peers >= 1;
    json!({
        "schema": FABRIC_SCHEMA,
        "cell_id": local_cell_id(),
        "product_sot": if mesh { "cell_mesh" } else { "single_node" },
        "mesh_fabric": mesh,
        "live_peers": peers,
        "cnp_l5_live": cnp_l5_static_live(),
        "cnp_l5_mode": if cnp_l5_static_live() { "static_1hop" } else { "none" },
        "agent_migration": false,
        "cluster_replication": false,
        "honesty": "One sovereign node is the unit. CNP L5 is static 1-hop via CONNECTOR_CNP_PEERS (no multi-hop mesh). Peers are durable heartbeat records. Agent kernel state does not replicate. CONNECTOR_MESH_FABRIC=1 with zero live peers stays single_node.",
    })
}
