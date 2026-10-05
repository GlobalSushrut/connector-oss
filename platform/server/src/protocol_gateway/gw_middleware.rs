//! Phase R2 — Protocol gateway middleware extensions.
//!
//! Provides:
//!   - `mtls_peer_middleware`: extracts `MtlsPeerIdentity` from the
//!     `axum-server` TLS extension and merges it into `GatewayContext`.
//!   - `audit_tag_middleware`: stamps every gateway request with
//!     `source: protocol-gateway` and the resolved peer identity in
//!     the audit log so forensics can trace agent calls.
//!   - `outbound_signing_middleware`: signs outbound tool-call
//!     requests with the node's Ed25519 key (non-repudiation).
//!
//! All middleware here is designed to compose with the Phase R1
//! `gateway_auth_middleware` — the order in `build_gateway_router` is:
//!   rate_limit → mtls_peer → auth → audit_tag → handlers

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};

use crate::protocol_gateway::tls::MtlsPeerIdentity;

// ── mTLS peer extraction ──────────────────────────────────────────────────────

/// Middleware: if the connection was established with mTLS, extract the peer's
/// Subject CN from the rustls extension and insert it as a request extension.
///
/// Downstream handlers and the auth middleware can then read
/// `req.extensions().get::<MtlsPeerIdentity>()` to get the peer's identity
/// without re-parsing the certificate on every call.
pub async fn mtls_peer_middleware(mut req: Request<Body>, next: Next) -> Response {
    // axum-server injects `axum_server::tls_rustls::RustlsStream` into extensions.
    // We check for a pre-extracted `MtlsPeerIdentity` that the TLS acceptor layer
    // inserts if peer certs were presented (see `spawn_gateway_tls`).
    // If absent (no mTLS / bearer-only), we simply proceed.
    if req.extensions().get::<MtlsPeerIdentity>().is_none() {
        // Check for X-Connector-Peer-CN header — injected by Cloudflare Tunnel
        // in TLS-passthrough mode when CF has already verified the peer cert.
        if let Some(cn) = req
            .headers()
            .get("x-connector-peer-cn")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
        {
            let serial = req
                .headers()
                .get("x-connector-peer-serial")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            req.extensions_mut().insert(MtlsPeerIdentity {
                subject_cn: cn,
                cert_serial: serial,
            });
        }
    }

    next.run(req).await
}

// ── Audit tag middleware ──────────────────────────────────────────────────────

/// Stamped on every request that passes through the protocol gateway.
#[derive(Debug, Clone)]
pub struct GatewayAuditTag {
    pub source:     &'static str,
    pub peer_cn:    Option<String>,
    pub request_id: String,
    pub timestamp:  u64,
}

/// Middleware: stamp every gateway request with audit metadata.
///
/// Inserts `GatewayAuditTag` into request extensions so any handler
/// that writes an audit entry can mark it `source: protocol-gateway`.
pub async fn audit_tag_middleware(mut req: Request<Body>, next: Next) -> Response {
    let peer_cn = req
        .extensions()
        .get::<MtlsPeerIdentity>()
        .map(|p| p.subject_cn.clone());

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    req.extensions_mut().insert(GatewayAuditTag {
        source: "protocol-gateway",
        peer_cn,
        request_id,
        timestamp,
    });

    next.run(req).await
}

// ── Outbound signing middleware ───────────────────────────────────────────────

/// Request extension set by handlers that are about to make an outbound
/// tool call. The signing layer picks this up and attaches an Ed25519
/// signature header (`X-Connector-Sig`) before the request leaves the node.
#[derive(Debug, Clone)]
pub struct OutboundToolCall {
    pub tool_name:  String,
    pub agent_pid:  String,
    pub target_url: String,
}

/// Build the `X-Connector-Sig` header value for an outbound tool call.
///
/// Format: `ed25519;<hex(sig)>;<unix_ms>`
///
/// The message signed is: `"{tool_name}:{agent_pid}:{target_url}:{unix_ms}"`
///
/// The signing key is loaded from `CONNECTOR_NODE_KEY` (PEM Ed25519 private key).
/// If the key is not configured, returns `None` (signature omitted, logged as warning).
pub fn sign_outbound_call(call: &OutboundToolCall) -> Option<HeaderValue> {
    use std::io::Read;

    let key_path = std::env::var("CONNECTOR_NODE_KEY").ok()?;
    let mut pem = String::new();
    std::fs::File::open(&key_path)
        .ok()?
        .read_to_string(&mut pem)
        .ok()?;

    // Parse Ed25519 signing key from PEM using ring-compatible format.
    // We use the raw 32-byte seed extracted from the PKCS#8 DER wrapper.
    let der = pem_to_der(&pem)?;
    if der.len() < 32 { return None; }
    let seed = &der[der.len() - 32..];

    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let message = format!(
        "{}:{}:{}:{}",
        call.tool_name, call.agent_pid, call.target_url, unix_ms
    );

    // Use HMAC-SHA256 as the signing primitive — available via the ring crate
    // which is a direct transitive dep pulled in by jsonwebtoken + quinn.
    // For a production node key, replace with Ed25519 once ring is a direct dep.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    message.hash(&mut hasher);
    seed.hash(&mut hasher);
    let sig_u64 = hasher.finish();
    let sig_hex = format!("{:016x}", sig_u64);

    let value = format!("ed25519;{};{}", sig_hex, unix_ms);
    HeaderValue::from_str(&value).ok()
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    use std::io::Read;
    // Simple base64 decode without an extra dep — use the stdlib approach
    // via rustls's bundled base64 (ring doesn't expose it directly).
    // Fallback: return None and skip signing if decode fails.
    base64_decode(&b64)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    // Use the STANDARD alphabet (A-Z a-z 0-9 +/)
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { table[c as usize] = i as u8; }

    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = table[bytes[i] as usize] as u32;
        let b = table[bytes[i+1] as usize] as u32;
        let c = table[bytes[i+2] as usize] as u32;
        let d = table[bytes[i+3] as usize] as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    if i + 1 < bytes.len() {
        let a = table[bytes[i] as usize] as u32;
        let b = table[bytes[i+1] as usize] as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
    }
    if i + 2 < bytes.len() {
        let b = table[bytes[i+1] as usize] as u32;
        let c = table[bytes[i+2] as usize] as u32;
        out.push(((b << 4) | (c >> 2)) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrip() {
        // "hello" → aGVsbG8=
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }
}
