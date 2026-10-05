//! Active/passive HA posture and federation trust-root honesty.
//!
//! Connector's basic install is single-node. HA and federation are explicit
//! operator upgrades — this module reports readiness without overclaiming.

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HaFederationStatus {
    pub mode: String,
    pub single_node_active: bool,
    pub active_passive_configured: bool,
    pub automatic_failover: bool,
    /// True only when `CONNECTOR_MESH_FABRIC=1` and peers_seen≥2 (same rule as `/runtime/mesh`).
    pub mesh_fabric: bool,
    /// `fail_closed` (default) or `insecure_lab` when CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS=1.
    pub peer_tls: &'static str,
    pub federation_enabled: bool,
    pub trust_roots_configured: bool,
    pub cells_by_region: CellsByRegionNote,
    /// Operator join steps (env bootstrap; join-token API not shipping yet).
    pub join: JoinInstructions,
    pub honesty: Vec<&'static str>,
    pub env: HaFederationEnv,
}

#[derive(Debug, Serialize)]
pub struct JoinInstructions {
    pub docs: &'static str,
    pub peer_env: &'static str,
    pub region_env: &'static str,
    pub steps: Vec<&'static str>,
    pub join_token_api: bool,
    pub add_peer_ui: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CellsByRegionNote {
    pub capability: &'static str,
    pub wired_to_fabric: bool,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HaFederationEnv {
    pub peer_urls: Vec<String>,
    pub role: String,
    pub shared_data_dir: bool,
    pub federation_trust_domain: Option<String>,
    pub audit_hmac_key_set: bool,
    pub mtls_required: bool,
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Peer base URLs from HA / federation env (shared with mesh status).
pub fn peer_urls() -> Vec<String> {
    std::env::var("CONNECTOR_HA_PEER_URLS")
        .or_else(|_| std::env::var("CONNECTOR_FEDERATION_PEERS"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Operator join instructions for multi-node bootstrap (P8.8).
pub fn join_instructions() -> JoinInstructions {
    let lab = crate::services::mesh_join_token::join_token_api_enabled();
    JoinInstructions {
        docs: "docs/architecture/ha-federation.md",
        peer_env: "CONNECTOR_HA_PEER_URLS (or CONNECTOR_FEDERATION_PEERS)",
        region_env: "CONNECTOR_CELL_REGION (default local)",
        steps: if lab {
            vec![
                "Lab: POST /api/v1/runtime/mesh/join-token (CONNECTOR_MESH_JOIN_LAB=1) mints an in-memory soak token.",
                "On the joining node, set CONNECTOR_HA_ROLE=passive (or secondary) and CONNECTOR_CELL_REGION=<region>.",
                "Set CONNECTOR_HA_PEER_URLS to the active node's base URL (comma-separated for multiple).",
                "Optional: send X-Connector-Join-Token on mesh channel inbox for lab validation.",
                "Operator VIP/geo-DNS points clients at the active endpoint — see ha-federation.md.",
            ]
        } else {
            vec![
                "On the joining node, set CONNECTOR_HA_ROLE=passive (or secondary) and CONNECTOR_CELL_REGION=<region>.",
                "Set CONNECTOR_HA_PEER_URLS to the active node's base URL (comma-separated for multiple).",
                "Share audit/trust roots (CONNECTOR_AUDIT_HMAC_KEY / CONNECTOR_FEDERATION_TRUST_DOMAIN) and require mTLS when ready (CONNECTOR_FEDERATION_MTLS_REQUIRED=1).",
                "Operator VIP/geo-DNS points clients at the active endpoint — see ha-federation.md.",
                "Join-token mint is lab-only (CONNECTOR_MESH_JOIN_LAB=1); Settings add-peer submit remains a stub.",
            ]
        },
        join_token_api: lab,
        add_peer_ui: "stub",
    }
}

/// GET /api/v1/runtime/ha-federation — operator honesty surface.
pub async fn get_ha_federation_status() -> Json<HaFederationStatus> {
    let peers = peer_urls();
    let role = std::env::var("CONNECTOR_HA_ROLE")
        .unwrap_or_else(|_| "standalone".into())
        .trim()
        .to_ascii_lowercase();
    let shared = env_flag("CONNECTOR_HA_SHARED_STORAGE");
    let federation = env_flag("CONNECTOR_FEDERATION_ENABLED") || !peers.is_empty();
    let trust_domain = std::env::var("CONNECTOR_FEDERATION_TRUST_DOMAIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let audit_key = std::env::var("CONNECTOR_AUDIT_HMAC_KEY")
        .map(|s| s.trim().len() >= 64)
        .unwrap_or(false);
    let mtls = env_flag("CONNECTOR_FEDERATION_MTLS_REQUIRED");
    let active_passive = matches!(
        role.as_str(),
        "active" | "passive" | "primary" | "secondary"
    ) || shared
        || !peers.is_empty();

    let local_cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cell_local".to_string());
    let membership = crate::services::membership_heartbeat::probe_and_tick(None, &local_cell_id).await;
    let mesh_fabric = membership
        .get("mesh_fabric")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Json(HaFederationStatus {
        mode: if mesh_fabric {
            "cell_mesh".into()
        } else if federation {
            "federation_optional".into()
        } else if active_passive {
            "active_passive_operator".into()
        } else {
            "single_node".into()
        },
        single_node_active: !active_passive && !federation && !mesh_fabric,
        active_passive_configured: active_passive,
        automatic_failover: false, // never claim automatic multi-master
        mesh_fabric,
        peer_tls: crate::distributed::transport::peer_tls_honesty(),
        federation_enabled: federation,
        trust_roots_configured: audit_key || trust_domain.is_some() || mtls,
        cells_by_region: CellsByRegionNote {
            capability: "distributed::service_registry::ServiceRegistry::get_cells_by_region",
            wired_to_fabric: false,
            note: "Capability exists in-process; multi-region registry still not a live vac-cluster fabric.",
        },
        join: join_instructions(),
        honesty: vec![
            "Basic install is single-node active.",
            "Active/passive failover is operator-managed (VIP/DNS/shared storage).",
            "Automatic multi-master consistency is not provided.",
            "Federation requires explicit peers + trust roots (audit key / trust domain / mTLS).",
            "mesh_fabric follows /runtime/mesh: CONNECTOR_MESH_FABRIC=1 and peers_seen≥2 after make l5-mesh-soak.",
            "peer_tls fail_closed by default; QUIC mTLS is separate from HMAC mesh channel.",
            "Join via env peers today; lab join-token mint via CONNECTOR_MESH_JOIN_LAB=1 + /runtime/mesh/join-token.",
        ],
        env: HaFederationEnv {
            peer_urls: peers,
            role,
            shared_data_dir: shared,
            federation_trust_domain: trust_domain,
            audit_hmac_key_set: audit_key,
            mtls_required: mtls,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_is_single_node_without_automatic_failover() {
        std::env::remove_var("CONNECTOR_HA_PEER_URLS");
        std::env::remove_var("CONNECTOR_FEDERATION_PEERS");
        std::env::remove_var("CONNECTOR_HA_ROLE");
        std::env::remove_var("CONNECTOR_FEDERATION_ENABLED");
        std::env::remove_var("CONNECTOR_DISTRIBUTED_ALLOW_INSECURE_TLS");
        std::env::remove_var("CONNECTOR_MESH_FABRIC");
        let Json(status) = get_ha_federation_status().await;
        assert!(status.single_node_active);
        assert!(!status.automatic_failover);
        assert!(!status.mesh_fabric);
        assert_eq!(status.peer_tls, "fail_closed");
        assert!(!status.cells_by_region.wired_to_fabric);
    }
}
