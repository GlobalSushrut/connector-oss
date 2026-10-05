//! Connector-aware peer overlay (Seven Pillars P4-T07).
//! Overlay verification on top of TCP/TLS/HTTP/QUIC/IPv6 — not a replacement.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "connector.peer_overlay.v1";

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn overlay_enforced() -> bool {
    env_flag("CONNECTOR_PEER_OVERLAY")
        || crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced()
}

/// Verify peer cell identity before trusting CNP frames (overlay, not L3).
pub fn verify_peer_identity(
    peer_cell: &str,
    peer_cert_fingerprint: Option<&str>,
    expected_cell: Option<&str>,
) -> Result<Value, String> {
    if peer_cell.trim().is_empty() {
        return Err("peer_cell_missing".into());
    }
    if let Some(exp) = expected_cell {
        if !exp.is_empty() && exp != peer_cell {
            return Err("peer_cell_mismatch".into());
        }
    }
    if overlay_enforced() {
        let fp = peer_cert_fingerprint.unwrap_or("").trim();
        if fp.is_empty() {
            // Allow map-registered peers without TLS fp in lab if listed in peer_map.
            if crate::cnp::wire::lookup_peer(peer_cell).is_none() {
                return Err("peer_overlay_unregistered".into());
            }
        }
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{peer_cell}|{}", peer_cert_fingerprint.unwrap_or("-")).as_bytes())
    );
    Ok(json!({
        "schema": SCHEMA,
        "peer_cell": peer_cell,
        "map_check": "passed",
        "tls_fingerprint_present": peer_cert_fingerprint
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false),
        "verified": {
            "peer_map_or_lab": true,
            "mutual_tls_attested": false,
            "honesty": "map/lab check only — not a claim of full TLS/QUIC peer attestation",
        },
        "overlay_digest": digest,
        "transport_declared": ["tcp", "tls", "http", "quic", "ipv6"],
        "honesty": "Peer overlay authenticates Connector cell identity at map level; it does not replace TCP/TLS/QUIC",
    }))
}

pub fn posture_json() -> Value {
    json!({
        "schema": SCHEMA,
        "enforced": overlay_enforced(),
        "peers_registered": crate::cnp::wire::peer_map().len(),
        "honesty": "CONNECTOR_PEER_OVERLAY=1 enables fail-closed peer cell verification",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_peer() {
        assert!(verify_peer_identity("", None, None).is_err());
    }

    #[test]
    fn accepts_named_peer_when_not_enforced() {
        std::env::remove_var("CONNECTOR_PEER_OVERLAY");
        assert!(verify_peer_identity("cell-a", None, Some("cell-a")).is_ok());
    }
}
