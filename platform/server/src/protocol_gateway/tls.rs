//! Phase R2 — mTLS configuration for the Protocol Gateway.
//!
//! Builds a `rustls::ServerConfig` that:
//!   1. Presents the node's own certificate to connecting peers.
//!   2. Requires the peer to present a certificate signed by the
//!      connector peer-CA (`CONNECTOR_PEER_CA_CERT`).
//!   3. Extracts the peer's Subject CN as a `PeerIdentity` that
//!      downstream handlers can read from the request extensions.
//!
//! Environment variables:
//!   CONNECTOR_TLS_CERT      — path to PEM server certificate (chain)
//!   CONNECTOR_TLS_KEY       — path to PEM private key
//!   CONNECTOR_PEER_CA_CERT  — path to PEM CA that signs peer certs
//!
//! If any variable is absent, `build_tls_config` returns `None`
//! and the gateway falls back to plain TLS (Phase R1 behaviour).

use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;

/// Peer identity extracted from the mTLS client certificate.
#[derive(Debug, Clone)]
pub struct MtlsPeerIdentity {
    /// Subject common name from the peer's certificate.
    pub subject_cn: String,
    /// Serial number of the peer cert (hex).
    pub cert_serial: String,
}

// ── Certificate loading helpers ───────────────────────────────────────────────

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = fs::File::open(path)
        .map_err(|e| format!("open cert {}: {}", path, e))?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert {}: {}", path, e))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = fs::File::open(path)
        .map_err(|e| format!("open key {}: {}", path, e))?;
    let mut reader = BufReader::new(f);

    // Try PKCS#8 first, then RSA
    if let Ok(Some(key)) = rustls_pemfile::private_key(&mut reader) {
        return Ok(key);
    }

    Err(format!("no private key found in {}", path))
}

fn load_ca_store(path: &str) -> Result<RootCertStore, String> {
    let certs = load_certs(path)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert)
            .map_err(|e| format!("add CA cert: {}", e))?;
    }
    Ok(store)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a rustls `ServerConfig` with mutual TLS.
///
/// Returns `None` if the required env vars are not set (graceful degradation).
/// Returns `Err` if the vars are set but the files are invalid/missing.
pub fn build_tls_config() -> Result<Option<Arc<ServerConfig>>, String> {
    let cert_path = std::env::var("CONNECTOR_TLS_CERT").ok();
    let key_path  = std::env::var("CONNECTOR_TLS_KEY").ok();
    let ca_path   = std::env::var("CONNECTOR_PEER_CA_CERT").ok();

    // All three must be present to enable mTLS
    let (cert_path, key_path, ca_path) = match (cert_path, key_path, ca_path) {
        (Some(c), Some(k), Some(ca)) => (c, k, ca),
        _ => {
            tracing::info!(
                "mTLS not configured (CONNECTOR_TLS_CERT/KEY/PEER_CA_CERT not set) — \
                 protocol gateway using bearer-only auth"
            );
            return Ok(None);
        }
    };

    let certs  = load_certs(&cert_path)?;
    let key    = load_key(&key_path)?;
    let ca     = load_ca_store(&ca_path)?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(ca))
        .build()
        .map_err(|e| format!("build client verifier: {}", e))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("build server config: {}", e))?;

    tracing::info!(
        cert = %cert_path,
        ca   = %ca_path,
        "mTLS enabled on protocol gateway"
    );

    Ok(Some(Arc::new(config)))
}

/// Extract peer Subject CN from a rustls `ServerConnection`.
///
/// Called from the `gateway_auth_middleware` after the TLS handshake.
/// Returns `None` if the peer did not present a certificate (bearer fallback).
pub fn extract_peer_cn(peer_certs: &[CertificateDer<'_>]) -> Option<MtlsPeerIdentity> {
    let cert_der = peer_certs.first()?;

    // Parse the DER certificate to extract the Subject field.
    // We use a minimal hand-rolled parser to avoid pulling in a full X.509 crate.
    // The Subject CN is adequate for peer identity; UCAN / JWT provides fine-grained authz.
    let cn = extract_cn_from_der(cert_der.as_ref())?;

    // Serial: last 8 bytes of DER as hex (stable identifier for audit logs).
    let serial = if cert_der.len() > 8 {
        hex_encode(&cert_der[cert_der.len() - 8..])
    } else {
        hex_encode(cert_der.as_ref())
    };

    Some(MtlsPeerIdentity { subject_cn: cn, cert_serial: serial })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Minimal DER parser: walk the ASN.1 TLV structure to find Subject CN.
/// Full X.509 parsing is not needed — we only need the CN string.
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // OID for commonName: 2.5.4.3 → 55 04 03
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03];

    let pos = der.windows(cn_oid.len())
        .position(|w| w == cn_oid)?;

    // After OID: skip OID bytes + type byte + length byte
    let value_start = pos + cn_oid.len() + 2;
    if value_start >= der.len() { return None; }

    let len = der[value_start - 1] as usize;
    let value_end = value_start + len;
    if value_end > der.len() { return None; }

    String::from_utf8(der[value_start..value_end].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_stable() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn build_tls_no_env_returns_none() {
        // Without env vars set, should return Ok(None)
        std::env::remove_var("CONNECTOR_TLS_CERT");
        std::env::remove_var("CONNECTOR_TLS_KEY");
        std::env::remove_var("CONNECTOR_PEER_CA_CERT");
        let result = build_tls_config();
        assert!(matches!(result, Ok(None)));
    }
}
