//! CFNI mint/verify for HTTP gateway and management proxies.

use axum::http::HeaderMap;
use connector_trust::{
    decode_header_value, encode_header_value, mint_flow_identity, verify_flow_identity,
    ForensicFlowIdentityV2, CFNI_HEADER,
};

/// Node secret for CFNI signing. Production / defense-strict must set explicitly (boot-validated).
pub fn cfni_secret() -> Vec<u8> {
    if let Ok(s) = std::env::var("CONNECTOR_CFNI_SECRET") {
        let t = s.trim();
        if !t.is_empty() {
            return t.as_bytes().to_vec();
        }
    }
    let prodish = matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod"
    ) || std::env::var("CONNECTOR_DEFENSE_STRICT")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if prodish {
        tracing::error!(
            "CONNECTOR_CFNI_SECRET missing under production/defense-strict — using reject marker"
        );
        return b"connector-cfni-MISSING-PROD-SECRET".to_vec();
    }
    std::env::var("CONNECTOR_JWT_SECRET")
        .unwrap_or_else(|_| "connector-cfni-dev-only".into())
        .into_bytes()
}

pub fn cfni_enabled() -> bool {
    std::env::var("CONNECTOR_CFNI_DISABLE")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            !(t == "1" || t == "true" || t == "yes")
        })
        .unwrap_or(true)
}

/// True when an explicit `CONNECTOR_CFNI_SECRET` is set (not JWT/dev fallback).
pub fn cfni_secret_configured() -> bool {
    std::env::var("CONNECTOR_CFNI_SECRET")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

pub fn cfni_enforce_production() -> bool {
    std::env::var("CONNECTOR_CFNI_ENFORCE")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        })
        .unwrap_or(
            matches!(
                std::env::var("CONNECTOR_ENV")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "production" | "prod"
            ),
        )
}

/// Mint flow identity for an authenticated principal.
pub fn mint_for_principal(
    principal_id: &str,
    tenant_id: Option<&str>,
) -> Option<ForensicFlowIdentityV2> {
    if !cfni_enabled() {
        return None;
    }
    let ttl_ms = std::env::var("CONNECTOR_CFNI_TTL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    Some(mint_flow_identity(
        &cfni_secret(),
        principal_id,
        tenant_id.map(str::to_string),
        ttl_ms,
        None,
    ))
}

pub fn header_from_identity(identity: &ForensicFlowIdentityV2) -> Option<(String, String)> {
    let enc = encode_header_value(identity).ok()?;
    Some((CFNI_HEADER.to_string(), enc))
}

/// Verify inbound CFNI header when enforcement is on.
pub fn verify_inbound_headers(headers: &HeaderMap) -> Result<Option<ForensicFlowIdentityV2>, &'static str> {
    let Some(raw) = headers.get(CFNI_HEADER).and_then(|v| v.to_str().ok()) else {
        if cfni_enforce_production() {
            return Err("missing_cfni");
        }
        return Ok(None);
    };
    let id = decode_header_value(raw)?;
    let now = chrono::Utc::now().timestamp_millis();
    verify_flow_identity(&id, &cfni_secret(), now)?;
    Ok(Some(id))
}

/// When a CFNI header is present, always verify signature/TTL (any environment).
pub fn verify_inbound_if_present(
    headers: &HeaderMap,
) -> Result<Option<ForensicFlowIdentityV2>, &'static str> {
    if headers.get(CFNI_HEADER).is_none() {
        return Ok(None);
    }
    verify_inbound_headers(headers)
}

/// True when caller declares this request as an internal mesh relay hop.
pub fn mesh_hop_declared(headers: &HeaderMap) -> bool {
    headers
        .get("x-connector-mesh-hop")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

/// Mesh relay hops must present valid CFNI when enforcement is on; otherwise verify only if sent.
pub fn verify_inbound_mesh_relay(
    headers: &HeaderMap,
) -> Result<Option<ForensicFlowIdentityV2>, &'static str> {
    if mesh_hop_declared(headers) {
        return verify_inbound_headers(headers);
    }
    verify_inbound_if_present(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn mesh_hop_without_cfni_errors_when_enforced() {
        std::env::set_var("CONNECTOR_CFNI_ENFORCE", "1");
        let mut headers = HeaderMap::new();
        headers.insert("x-connector-mesh-hop", HeaderValue::from_static("1"));
        let err = verify_inbound_mesh_relay(&headers).unwrap_err();
        assert_eq!(err, "missing_cfni");
        std::env::remove_var("CONNECTOR_CFNI_ENFORCE");
    }

    #[test]
    fn no_mesh_hop_without_cfni_ok_in_dev() {
        std::env::remove_var("CONNECTOR_CFNI_ENFORCE");
        std::env::set_var("CONNECTOR_ENV", "development");
        let headers = HeaderMap::new();
        assert!(verify_inbound_mesh_relay(&headers).unwrap().is_none());
    }
}
