//! Runtime mesh honesty surface (L5 starting point).
//!
//! Reports fabric / peer-TLS / failover truth until vac-cluster soak flips flags.
//! Exposes local `HardwarePlacementV2` + example `IntelligenceEdgeStateV2` (P8.1).
//! Local cell SPIFFE-ish id: `spiffe://{trust_domain}/cell/{cell_id}` (P8.3).
//! Local CRDT membership heartbeat: `membership_algorithm=vac_cluster_crdt` (P8.4).

use axum::{extract::State, Json};
use connector_engine::storage_zone::{ReplicationPolicy, StorageZone, ZoneConfig};
use connector_trust::{HardwarePlacementV2, IntelligenceEdgeStateV2};
use serde_json::{json, Value};

use crate::distributed::transport::{distributed_allow_insecure_tls, peer_tls_honesty};
use crate::services::cell_spiffe::{self, CELL_SPIFFE_URI_TEMPLATE};
use crate::services::ha_federation::{join_instructions, peer_urls};
use crate::services::membership_heartbeat;

/// Measured mesh fabric — env flag alone is never enough (peers_seen ≥ 2 required).
pub fn measured_mesh_fabric() -> bool {
    let peers_seen = membership_heartbeat::last_peers_seen();
    let mesh_fabric_env = membership_heartbeat::mesh_fabric_claimed();
    mesh_fabric_env && peers_seen >= 2
}

/// Zone replication honesty for GET /runtime/mesh (P8 — local until soak).
fn zone_replication_honesty() -> Value {
    let sample_zones = [
        StorageZone::Audit,
        StorageZone::AgentBreakers,
        StorageZone::AgentSecrets,
    ];
    let policies: Vec<Value> = sample_zones
        .iter()
        .map(|z| {
            let cfg = ZoneConfig::default_for(*z);
            let policy = match cfg.replication {
                ReplicationPolicy::LocalOnly => "local_only",
                ReplicationPolicy::ClusterWide => "cluster_wide",
                ReplicationPolicy::QuorumWrite => "quorum_write",
                ReplicationPolicy::NeverReplicate => "never_replicate",
                ReplicationPolicy::OnDemand => "on_demand",
            };
            json!({
                "zone": format!("{:?}", z),
                "replication_policy": policy,
            })
        })
        .collect();
    let wired = if cfg!(feature = "cluster") {
        json!("partial")
    } else {
        json!(false)
    };
    json!({
        "wired": wired,
        "policy_honored": "local_only_until_soak",
        "sample_zone_policies": policies,
        "note": "MemPacket zones declare ReplicationPolicy in connector-engine; cross-cell replicate deferred until soak.",
    })
}

/// Region for the local cell — `CONNECTOR_CELL_REGION`, default `"local"`.
pub fn cell_region() -> String {
    std::env::var("CONNECTOR_CELL_REGION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".into())
}

/// Node-scoped geo_id — aligns with foundation (`CONNECTOR_PLACEMENT_REGION` → `geo:…`).
pub fn local_geo_id() -> String {
    if let Ok(raw) = std::env::var("CONNECTOR_PLACEMENT_REGION") {
        let s = raw.trim();
        if !s.is_empty() {
            return if s.starts_with("geo:") {
                s.to_string()
            } else {
                format!("geo:{s}")
            };
        }
    }
    let region = cell_region();
    if region.starts_with("geo:") {
        region
    } else {
        format!("geo:{region}")
    }
}

/// Local single-node placement (geo-identity seed until multi-cell registry is live).
pub fn local_hardware_placement() -> HardwarePlacementV2 {
    HardwarePlacementV2::new(cell_region())
        .with_cell_id("local")
        .with_endpoints(vec!["local://node".into()])
        .with_capabilities(vec!["single_node".into()])
}

fn example_intelligence_edge(placement: HardwarePlacementV2) -> IntelligenceEdgeStateV2 {
    IntelligenceEdgeStateV2 {
        health: Some("healthy".into()),
        last_seen_ms: None,
        ..IntelligenceEdgeStateV2::new("local_node", placement)
    }
}

/// GET /api/v1/runtime/mesh/ping — liveness for peer probes (no nested peer HTTP).
///
/// `probe_peer_mesh` must **not** call `/runtime/mesh` (that runs `probe_and_tick` and
/// would recurse A↔B until both timeouts fail soak T13).
pub async fn get_runtime_mesh_ping() -> Json<Value> {
    let local_cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cell_local".to_string());
    Json(json!({
        "ok": true,
        "schema": "runtime_mesh_ping.v1",
        "local_cell_id": local_cell_id,
        "region": cell_region(),
        "geo_id": local_geo_id(),
        "spiffe_id": cell_spiffe::local_cell_spiffe_id(),
    }))
}

/// Build mesh status JSON (tests pass `state: None`).
pub async fn runtime_mesh_json(state: Option<&crate::state::PlatformState>) -> Value {
    let placement = local_hardware_placement();
    let region = placement.region.clone();
    let edge = example_intelligence_edge(placement.clone());
    let peers = peer_urls();
    let cells = vec![json!({
        "cell_id": placement.cell_id.clone(),
        "region": region.clone(),
        "placement": placement.clone(),
        "health": "healthy",
        "role": "local",
    })];

    let local_cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cell_local".to_string());
    let spiffe_id = cell_spiffe::local_cell_spiffe_id();
    let membership = membership_heartbeat::probe_and_tick(state, &local_cell_id).await;
    let mesh_fabric = membership
        .get("mesh_fabric")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let product_sot = membership
        .get("product_sot")
        .and_then(|v| v.as_str())
        .unwrap_or("single_node")
        .to_string();
    let geo_id = local_geo_id();
    let mut body = json!({
        "schema": "runtime_mesh.v1",
        "mesh_fabric": mesh_fabric,
        "peer_tls": peer_tls_honesty(),
        "peer_tls_lab_escape": "CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1",
        "peer_tls_insecure": distributed_allow_insecure_tls(),
        "automatic_failover": false,
        "product_sot": product_sot,
        "geo_id": geo_id,
        "local_placement": placement,
        "spiffe_id": spiffe_id,
        "spiffe_uri_template": CELL_SPIFFE_URI_TEMPLATE,
        "trust_domain": cell_spiffe::trust_domain(),
        "membership_algorithm": membership.get("membership_algorithm").cloned().unwrap_or(json!("vac_cluster_crdt")),
        "peers_seen": membership.get("peers_seen").cloned().unwrap_or(json!(1)),
        "membership": membership,
        "cells": cells,
        "cells_by_region": {
            "capability": "distributed::service_registry::ServiceRegistry::get_cells_by_region",
            "wired_to_fabric": false,
            "region": region.clone(),
            "cells": [{
                "cell_id": "local",
                "region": region,
            }],
            "note": "Lists local cell from CONNECTOR_CELL_REGION (default local). Multi-region fabric not live until vac-cluster soak."
        },
        "intelligence_edge_example": edge,
        "peers": peers,
        "join": join_instructions(),
        "zone_replication": zone_replication_honesty(),
        "cluster_feature": cfg!(feature = "cluster"),
        "cluster_feature_compiled": cfg!(feature = "cluster"),
        "local_cell_id": local_cell_id.clone(),
        "honesty": [
            "mesh_fabric true only when CONNECTOR_MESH_FABRIC=1 and peers_seen≥2 after make l5-mesh-soak.",
            "peer_tls is fail_closed by default; insecure_lab only with CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1.",
            "automatic_failover remains false until HA soak proves it (separate from mesh_fabric).",
            "product_sot=cell_mesh when mesh_fabric claimed; else single_node.",
            "local_placement / intelligence_edge_example are geo-identity seeds (P8.1).",
            "spiffe_id is SPIFFE-ish cell URI (P8.3); not a full SVID issuance stack.",
            "Cross-cell channel: POST /runtime/mesh/channel/send (T15) with CONNECTOR_MESH_CHANNEL_SECRET.",
            "membership_algorithm=vac_cluster_crdt; peers_seen=1+reachable peer probes via /runtime/mesh/ping; SWIM library-only (P8.4).",
            "zone_replication.policy_honored=local_only_until_soak; wired false|partial until cross-cell replicate soaks.",
            "Lab join tokens: CONNECTOR_MESH_JOIN_LAB=1 → GET/POST /runtime/mesh/join-token.",
        ],
    });
    #[cfg(feature = "cluster")]
    {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "cluster_boot".into(),
                crate::cluster_boot::cluster_boot_status(&local_cell_id),
            );
        }
    }
    body
}

/// GET /api/v1/runtime/mesh — operator honesty for global mesh posture.
pub async fn get_runtime_mesh(State(state): State<crate::state::SharedState>) -> Json<Value> {
    Json(runtime_mesh_json(Some(state.as_ref())).await)
}

/// GET /api/v1/runtime/cells — local cell list (placement by region).
pub async fn get_runtime_cells() -> Json<Value> {
    let placement = local_hardware_placement();
    let geo_id = local_geo_id();
    // Align with /runtime/mesh soak honesty (never invent multi-cell schedule).
    let peers_seen = crate::services::membership_heartbeat::last_peers_seen();
    let mesh_fabric_env = crate::services::membership_heartbeat::mesh_fabric_claimed();
    let mesh_fabric = mesh_fabric_env && peers_seen >= 2;
    let product_sot = if mesh_fabric {
        "cell_mesh"
    } else {
        "single_node"
    };
    Json(json!({
        "schema": "runtime_cells.v1",
        "wired_to_fabric": mesh_fabric,
        "mesh_fabric": mesh_fabric,
        "product_sot": product_sot,
        "geo_id": geo_id.clone(),
        "soak_claim": {
            "mesh_fabric_env": mesh_fabric_env,
            "peers_seen": peers_seen,
            "note": "Ops: make l5-mesh-soak then CONNECTOR_MESH_FABRIC=1 with peers_seen≥2",
        },
        "placement_schema": connector_trust::HARDWARE_PLACEMENT_SCHEMA,
        "hardware_placement_v2": true,
        "cells": [{
            "cell_id": placement.cell_id,
            "region": placement.region,
            "geo_id": geo_id,
            "placement": placement,
            "role": "local",
        }],
        "honesty": [
            if mesh_fabric {
                "mesh_fabric claimed after soak (env + peers_seen≥2) — still not a multi-cell scheduler."
            } else {
                "Single local cell until multi-node registry is soaked."
            },
            "Region from CONNECTOR_CELL_REGION (default local).",
            "geo_id from CONNECTOR_PLACEMENT_REGION or geo:{region} — node-scoped.",
            "Each cell.placement is HardwarePlacementV2 (serialize/round-trip vocabulary seed for P8).",
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mesh_status_is_honest_single_node() {
        std::env::remove_var("CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS");
        std::env::remove_var("CONNECTOR_CELL_REGION");
        let v = runtime_mesh_json(None).await;
        assert_eq!(v.get("mesh_fabric").and_then(|x| x.as_bool()), Some(false));
        assert_eq!(
            v.get("automatic_failover").and_then(|x| x.as_bool()),
            Some(false)
        );
        assert_eq!(
            v.get("peer_tls").and_then(|x| x.as_str()),
            Some("fail_closed")
        );
        assert_eq!(
            v.get("product_sot").and_then(|x| x.as_str()),
            Some("single_node")
        );
        assert_eq!(
            v.pointer("/local_placement/region")
                .and_then(|x| x.as_str()),
            Some("local")
        );
        assert_eq!(
            v.pointer("/local_placement/schema")
                .and_then(|x| x.as_str()),
            Some("hardware_placement.v2")
        );
        assert_eq!(
            v.pointer("/intelligence_edge_example/schema")
                .and_then(|x| x.as_str()),
            Some("intelligence_edge_state.v2")
        );
        assert_eq!(
            v.pointer("/intelligence_edge_example/identity_id")
                .and_then(|x| x.as_str()),
            Some("local_node")
        );
        let cells = v.get("cells").and_then(|x| x.as_array()).expect("cells");
        assert_eq!(cells.len(), 1);
        assert_eq!(
            v.get("membership_algorithm").and_then(|x| x.as_str()),
            Some("vac_cluster_crdt")
        );
        assert_eq!(v.get("peers_seen").and_then(|x| x.as_u64()), Some(1));
        let spiffe = v
            .get("spiffe_id")
            .and_then(|x| x.as_str())
            .expect("spiffe_id");
        assert!(spiffe.starts_with("spiffe://"));
        assert!(spiffe.contains("/cell/"));
        assert_eq!(
            v.pointer("/zone_replication/policy_honored")
                .and_then(|x| x.as_str()),
            Some("local_only_until_soak")
        );
        let wired = v.pointer("/zone_replication/wired");
        assert!(
            wired == Some(&json!(false)) || wired == Some(&json!("partial")),
            "zone_replication.wired must be false or partial"
        );
    }

    #[tokio::test]
    async fn mesh_ping_is_lightweight() {
        std::env::set_var("CONNECTOR_CELL_ID", "cell_ping_test");
        let Json(v) = get_runtime_mesh_ping().await;
        assert_eq!(v.get("ok").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(
            v.get("schema").and_then(|x| x.as_str()),
            Some("runtime_mesh_ping.v1")
        );
        assert_eq!(
            v.get("local_cell_id").and_then(|x| x.as_str()),
            Some("cell_ping_test")
        );
        assert!(v.get("peers_seen").is_none());
        std::env::remove_var("CONNECTOR_CELL_ID");
    }

    #[tokio::test]
    async fn mesh_respects_connector_cell_region() {
        std::env::set_var("CONNECTOR_CELL_REGION", "us-east-1");
        let v = runtime_mesh_json(None).await;
        assert_eq!(
            v.pointer("/local_placement/region")
                .and_then(|x| x.as_str()),
            Some("us-east-1")
        );
        assert_eq!(
            v.pointer("/cells_by_region/region")
                .and_then(|x| x.as_str()),
            Some("us-east-1")
        );
        std::env::remove_var("CONNECTOR_CELL_REGION");
    }

    #[tokio::test]
    async fn runtime_cells_lists_local() {
        std::env::remove_var("CONNECTOR_CELL_REGION");
        let Json(v) = get_runtime_cells().await;
        assert_eq!(
            v.get("wired_to_fabric").and_then(|x| x.as_bool()),
            Some(false)
        );
        let cells = v.get("cells").and_then(|x| x.as_array()).expect("cells");
        assert_eq!(cells.len(), 1);
        assert_eq!(
            cells[0]
                .pointer("/placement/region")
                .and_then(|x| x.as_str()),
            Some("local")
        );
        assert_eq!(
            v.get("placement_schema").and_then(|x| x.as_str()),
            Some("hardware_placement.v2")
        );
        assert_eq!(
            v.get("hardware_placement_v2").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert_eq!(
            cells[0]
                .pointer("/placement/schema")
                .and_then(|x| x.as_str()),
            Some("hardware_placement.v2")
        );
    }
}
