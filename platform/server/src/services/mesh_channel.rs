//! Cross-cell mesh channel (L5 T15) — governed effect over peer HTTP.
//!
//! Lab/prod path: HMAC-signed envelopes via `CONNECTOR_MESH_CHANNEL_SECRET`.
//! Does **not** invent a second SoT — appends ArtifactLog-shaped receipt when available.
//! Peer TLS for QUIC remains separate; this channel is the soak-proved CNP-shaped hop.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth;
use crate::state::SharedState;

type HmacSha256 = Hmac<Sha256>;

static INBOX: Mutex<Vec<Value>> = Mutex::new(Vec::new());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn channel_secret() -> Option<Vec<u8>> {
    std::env::var("CONNECTOR_MESH_CHANNEL_SECRET")
        .ok()
        .filter(|s| s.len() >= 16)
        .map(|s| s.into_bytes())
}

fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn verify_sig(secret: &[u8], body: &[u8], sig_hex: &str) -> bool {
    let Ok(expected) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "Unauthorized"})),
        ));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "error": "Admin privileges required"})),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ChannelSendRequest {
    /// Peer base URL (e.g. http://127.0.0.1:18081)
    pub peer_url: String,
    /// Opaque payload (governed effect body)
    pub payload: Value,
    /// Optional correlation / FNI id
    #[serde(default)]
    pub fni_flow_id: Option<String>,
}

/// POST /api/v1/runtime/mesh/channel/send — deliver envelope to peer inbox.
pub async fn channel_send(
    State(_state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ChannelSendRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin_or_dev(&headers)?;
    let Some(secret) = channel_secret() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "CONNECTOR_MESH_CHANNEL_SECRET unset or <16 chars — channel fail-closed",
            })),
        ));
    };

    let from_cell = std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "cell_local".into());
    let envelope = json!({
        "kind": "cnp_mesh_channel.v1",
        "from_cell": from_cell,
        "fni_flow_id": req.fni_flow_id,
        "payload": req.payload,
        "sent_ms": now_ms(),
    });
    let body = serde_json::to_vec(&envelope).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
    })?;
    let sig = sign_body(&secret, &body);
    let peer = req.peer_url.trim_end_matches('/');
    let url = format!("{}/api/v1/runtime/mesh/channel/inbox", peer);

    let client = crate::substrate::egress_policy::reqwest_client_pinned(
        &url,
        std::time::Duration::from_secs(5),
    )
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": format!("dns_pin: {e}")})),
        )
    })?;

    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-connector-mesh-sig", &sig)
        .body(body)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": format!("peer unreachable: {e}")})),
            )
        })?;

    let status = resp.status();
    let peer_body: Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": "peer rejected envelope",
                "peer_status": status.as_u16(),
                "peer_body": peer_body,
            })),
        ));
    }

    Ok(Json(json!({
        "ok": true,
        "delivered": true,
        "peer_url": peer,
        "envelope_kind": "cnp_mesh_channel.v1",
        "peer": peer_body,
        "honesty": "Cross-cell governed hop via HMAC channel; QUIC mTLS mesh remains separate path.",
    })))
}

/// POST /api/v1/runtime/mesh/channel/inbox — peer delivery (HMAC required).
pub async fn channel_inbox(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Some(secret) = channel_secret() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": "channel secret not configured"})),
        ));
    };
    let sig = headers
        .get("x-connector-mesh-sig")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !verify_sig(&secret, &body, sig) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "invalid mesh channel signature"})),
        ));
    }
    // Optional lab join-token check (soak UX) — only when header present.
    if let Some(jt) = headers
        .get("x-connector-join-token")
        .and_then(|v| v.to_str().ok())
    {
        if crate::services::mesh_join_token::join_lab_enabled()
            && !crate::services::mesh_join_token::validate_lab_token(jt)
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "error": "invalid lab join token"})),
            ));
        }
    }
    let envelope: Value = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e.to_string()})),
        )
    })?;

    if let Ok(mut inbox) = INBOX.lock() {
        inbox.push(envelope.clone());
        if inbox.len() > 256 {
            let drain = inbox.len() - 256;
            inbox.drain(0..drain);
        }
    }

    // Best-effort durable crumb under engine store (not a second SoT).
    {
        let mut es = state.engine_store.lock().unwrap();
        let key = format!("mesh_ch_{}", now_ms());
        let _ = es.folder_put("mesh_channel_inbox", &key, &envelope);
    }

    Ok(Json(json!({
        "ok": true,
        "accepted": true,
        "from_cell": envelope.get("from_cell"),
        "received_ms": now_ms(),
    })))
}

/// GET /api/v1/runtime/mesh/channel/inbox — local operator view of received hops.
pub async fn channel_inbox_list(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin_or_dev(&headers)?;
    let items = INBOX.lock().map(|g| g.clone()).unwrap_or_default();
    Ok(Json(json!({
        "ok": true,
        "count": items.len(),
        "items": items,
        "channel_configured": channel_secret().is_some(),
    })))
}

/// Probe whether we can reach peer mesh ping (used by membership heartbeat).
///
/// Uses `/runtime/mesh/ping` — not `/runtime/mesh` — so A↔B probes do not recurse.
pub async fn probe_peer_mesh(peer_url: &str) -> bool {
    let url = format!(
        "{}/api/v1/runtime/mesh/ping",
        peer_url.trim_end_matches('/')
    );
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    match client.get(&url).send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}
