//! Federated policy honesty stub (P8.7).
//!
//! Cross-domain deny-overrides and `aapi-federation` wiring are not product yet.
//! This surface stays truthful: local-only deny wins; federation not wired.

use axum::Json;
use serde_json::{json, Value};

/// `GET /api/v1/runtime/federation-policy` — honesty stub for mesh policy federation.
pub async fn get_federation_policy() -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": "runtime.federation_policy.v1",
        "implemented": false,
        "deny_overrides": "local_only",
        "aapi_federation_wired": false,
        "mesh_fabric": false,
        "honesty": [
            "deny_overrides=local_only until FederatedPolicyEngine + peer soak (P8.7).",
            "aapi_federation_wired=false — do not claim cross-domain deny wins yet.",
            "mesh_fabric stays false until vac-cluster multi-node soak."
        ],
        "docs": "docs/architecture/ha-federation.md",
        "future": {
            "engine": "aapi-federation FederatedPolicyEngine",
            "knowledge_plane": "mesh_knowledge_plane + vac sync replicated grants",
            "deny_overrides": "peer_deny_wins when soak flips honesty"
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn federation_policy_is_local_only_honesty() {
        let Json(v) = get_federation_policy().await;
        assert_eq!(
            v.get("deny_overrides").and_then(|x| x.as_str()),
            Some("local_only")
        );
        assert_eq!(
            v.get("aapi_federation_wired").and_then(|x| x.as_bool()),
            Some(false)
        );
        assert_eq!(v.get("implemented").and_then(|x| x.as_bool()), Some(false));
        assert_eq!(v.get("mesh_fabric").and_then(|x| x.as_bool()), Some(false));
    }
}
