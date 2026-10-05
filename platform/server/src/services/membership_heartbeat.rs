//! Local vac-cluster CRDT membership heartbeat (P8.4) + peer count (L5 T13).
//!
//! SWIM remains library-only — see `docs/architecture/mesh-membership.md`.
//! `mesh_fabric` becomes true only when `CONNECTOR_MESH_FABRIC=1` **and** peers_seen ≥ 2
//! (operator flips after `make l5-mesh-soak`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::services::ha_federation::peer_urls;
use crate::services::mesh_channel::probe_peer_mesh;

static HEARTBEAT_TICK: AtomicU64 = AtomicU64::new(0);
static LAST_HEARTBEAT_MS: AtomicU64 = AtomicU64::new(0);
static PEERS_SEEN: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Product membership algorithm label (vac-cluster CRDT — not SWIM).
pub const MEMBERSHIP_ALGORITHM: &str = "vac_cluster_crdt";

pub fn mesh_fabric_claimed() -> bool {
    matches!(
        std::env::var("CONNECTOR_MESH_FABRIC").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

/// Async peer probe — call from axum handlers or background loop.
pub async fn probe_and_tick(state: Option<&PlatformState>, local_cell_id: &str) -> Value {
    let tick = HEARTBEAT_TICK.fetch_add(1, Ordering::Relaxed) + 1;
    let ms = now_ms();
    LAST_HEARTBEAT_MS.store(ms, Ordering::Relaxed);

    let peers = peer_urls();
    let mut detail = Vec::new();
    let mut reachable = 0u64;
    for p in &peers {
        let ok = probe_peer_mesh(p).await;
        if ok {
            reachable += 1;
            if let Some(st) = state {
                crate::kernel::node_fabric::record_peer_ack(st, p);
            }
        }
        detail.push(json!({"url": p, "mesh_reachable": ok}));
    }
    let peers_seen = 1 + reachable;
    PEERS_SEEN.store(peers_seen, Ordering::Relaxed);

    let claim = mesh_fabric_claimed();
    let mesh_fabric = claim && peers_seen >= 2;
    let product_sot = if mesh_fabric {
        "cell_mesh"
    } else {
        "single_node"
    };

    json!({
        "membership_algorithm": MEMBERSHIP_ALGORITHM,
        "peers_seen": peers_seen,
        "local_cell_id": local_cell_id,
        "heartbeat_tick": tick,
        "last_heartbeat_ms": ms,
        "peer_probes": detail,
        "swim": "library_only",
        "swim_path": "platform/server/src/distributed/failure_detector.rs",
        "mesh_fabric": mesh_fabric,
        "mesh_fabric_env": claim,
        "product_sot": product_sot,
        "cnp_l5_static_live": crate::cnp::wire::l5_static_routing_live(),
        "cnp_l5_mode": if crate::cnp::wire::l5_static_routing_live() {
            "static_1hop"
        } else {
            "local_only"
        },
        "honesty": if mesh_fabric {
            "CONNECTOR_MESH_FABRIC=1 and peers_seen≥2 — fabric claimed after soak."
        } else if claim {
            "CONNECTOR_MESH_FABRIC=1 but peers_seen<2 — stay single_node until peers answer."
        } else {
            "Local CRDT membership + peer probe; mesh_fabric false until CONNECTOR_MESH_FABRIC=1 after make l5-mesh-soak."
        },
    })
}

/// Sync tick without network (unit tests / substrate).
#[allow(dead_code)]
pub fn tick_local_membership(local_cell_id: &str) -> Value {
    let tick = HEARTBEAT_TICK.fetch_add(1, Ordering::Relaxed) + 1;
    let ms = now_ms();
    LAST_HEARTBEAT_MS.store(ms, Ordering::Relaxed);
    let peers_seen = PEERS_SEEN.load(Ordering::Relaxed).max(1);
    json!({
        "membership_algorithm": MEMBERSHIP_ALGORITHM,
        "peers_seen": peers_seen,
        "local_cell_id": local_cell_id,
        "heartbeat_tick": tick,
        "last_heartbeat_ms": ms,
        "swim": "library_only",
        "mesh_fabric": mesh_fabric_claimed() && peers_seen >= 2,
        "product_sot": if mesh_fabric_claimed() && peers_seen >= 2 { "cell_mesh" } else { "single_node" },
        "honesty": "Sync snapshot — use probe_and_tick for live peer count.",
    })
}

pub fn last_peers_seen() -> u64 {
    PEERS_SEEN.load(Ordering::Relaxed).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_reports_vac_cluster_crdt() {
        std::env::remove_var("CONNECTOR_MESH_FABRIC");
        PEERS_SEEN.store(1, Ordering::Relaxed);
        let v = tick_local_membership("cell_local");
        assert_eq!(
            v.get("membership_algorithm").and_then(|x| x.as_str()),
            Some("vac_cluster_crdt")
        );
        assert_eq!(v.get("peers_seen").and_then(|x| x.as_u64()), Some(1));
        assert_eq!(v.get("mesh_fabric").and_then(|x| x.as_bool()), Some(false));
    }
}
