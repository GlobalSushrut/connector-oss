//! TLS/Certificate Management API
//!
//! Live probes perform a real rustls handshake. Trust is webpki-roots only —
//! never inferred from a TCP connect or a hostname containing "local".

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{TimeZone, Utc};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::oid_registry;

use super::V2Response;
use crate::state::SharedState;

/// GET /api/v2/tls/check — rustls handshake + webpki-roots verification.
pub async fn check_tls(
    State(_state): State<SharedState>,
    Query(params): Query<TlsCheckQuery>,
) -> impl IntoResponse {
    if params.domain.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            V2Response::<()>::error("tls_domain_required", "Query parameter domain is required."),
        )
            .into_response();
    }

    match probe_tls(&params.domain, params.port).await {
        Ok(probe) => {
            let mut warnings = Vec::new();
            if !probe.trusted {
                warnings.push(
                    "Peer certificate did not verify against webpki-roots.".to_string(),
                );
            }
            if let Some(days) = probe.days_until_expiry {
                if days < 0 {
                    warnings.push("Certificate not_after is in the past.".to_string());
                } else if days < 30 {
                    warnings.push(format!("Certificate expires in {days} days."));
                }
            }
            let valid = probe.handshake_ok
                && probe.trusted
                && probe
                    .days_until_expiry
                    .map(|d| d >= 0)
                    .unwrap_or(false);
            V2Response::success(TlsCheckResult {
                domain: params.domain,
                port: params.port,
                valid,
                trusted: probe.trusted,
                expires: probe.not_after.clone(),
                days_until_expiry: probe.days_until_expiry,
                protocols: probe.protocol.clone().into_iter().collect(),
                cipher_suites: probe.cipher_suite.clone().into_iter().collect(),
                warnings,
                checked_at: Utc::now().to_rfc3339(),
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            V2Response::<()>::error_with_hint(
                "tls_handshake_failed",
                &format!("TLS probe of {}:{} failed: {e}", params.domain, params.port),
                "Confirm the host accepts TLS on this port. Trust is evaluated against webpki-roots, not a TCP connect.",
            ),
        )
            .into_response(),
    }
}

/// GET /api/v2/tls/cert-info — handshake, then parse the peer leaf with x509-parser.
pub async fn get_cert_info(
    State(_state): State<SharedState>,
    Query(params): Query<CertInfoQuery>,
) -> impl IntoResponse {
    if params.domain.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            V2Response::<()>::error("tls_domain_required", "Query parameter domain is required."),
        )
            .into_response();
    }

    match probe_tls(&params.domain, params.port).await {
        Ok(probe) => {
            let Some(der) = probe.leaf_der else {
                return (
                    StatusCode::BAD_GATEWAY,
                    V2Response::<()>::error(
                        "tls_no_peer_certificate",
                        "Handshake completed but rustls returned no peer certificate.",
                    ),
                )
                    .into_response();
            };
            let parsed = parse_leaf(&der);
            V2Response::success(CertificateInfo {
                domain: params.domain,
                port: params.port,
                trusted: probe.trusted,
                subject: parsed.subject,
                issuer: parsed.issuer,
                serial_number: parsed.serial,
                fingerprint: fingerprint_sha256(&der),
                not_before: parsed.not_before,
                not_after: parsed.not_after,
                sans: parsed.sans,
                key_algorithm: parsed.key_algorithm,
                key_size: parsed.key_size,
                signature_algorithm: parsed.signature_algorithm,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            V2Response::<()>::error_with_hint(
                "tls_handshake_failed",
                &format!("No certificate retrieved for {}:{}: {e}", params.domain, params.port),
                "The probe performs a real TLS handshake. Unreachable hosts fail instead of inventing a certificate.",
            ),
        )
            .into_response(),
    }
}

/// List certificates from engine store
pub async fn list_certificates(
    State(state): State<SharedState>,
    Query(_params): Query<ListCertsQuery>,
) -> impl IntoResponse {
    let certs = {
        let engine_store = state.engine_store.lock().unwrap();
        engine_store
            .folder_get("certificates", "all")
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value::<Vec<CertificateSummary>>(v).ok())
            .unwrap_or_default()
    };

    let expiring_soon = certs.iter().filter(|c| c.days_until_expiry < 30).count();
    let expired = certs.iter().filter(|c| c.days_until_expiry < 0).count();

    V2Response::success(ListCertsResponse {
        certificates: certs,
        expiring_soon,
        expired,
    })
}

/// Request new certificate — refused: no ACME/issuer is wired.
pub async fn request_certificate(
    State(_state): State<SharedState>,
    Json(request): Json<RequestCertRequest>,
) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        V2Response::<()>::error_with_hint(
            "tls_request_not_implemented",
            &format!(
                "No certificate was requested for {}: this build has no ACME or CA issuer.",
                request.domain
            ),
            "Issue certificates out-of-band. GET /api/v2/tls/certificates lists only store-backed rows. GET /api/v2/tls/check probes a live peer.",
        ),
    )
}

struct TlsProbe {
    handshake_ok: bool,
    trusted: bool,
    protocol: Option<String>,
    cipher_suite: Option<String>,
    leaf_der: Option<Vec<u8>>,
    not_after: Option<String>,
    days_until_expiry: Option<i64>,
}

#[derive(Debug)]
struct CaptureVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    captured: Mutex<Captured>,
}

#[derive(Debug, Default, Clone)]
struct Captured {
    trusted: bool,
    leaf: Option<Vec<u8>>,
}

impl rustls::client::danger::ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let trusted = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        *self.captured.lock().unwrap() = Captured {
            trusted,
            leaf: Some(end_entity.as_ref().to_vec()),
        };
        // Always complete the handshake so cert-info can parse untrusted leaves.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

async fn probe_tls(domain: &str, port: u16) -> Result<TlsProbe, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("webpki verifier: {e}"))?;
    let capture = Arc::new(CaptureVerifier {
        inner,
        captured: Mutex::new(Captured::default()),
    });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let host = domain.trim().trim_matches(['[', ']']);
    let addr = format!("{host}:{port}");
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("TCP connect to {addr} timed out"))?
    .map_err(|e| format!("TCP connect to {addr}: {e}"))?;

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid TLS server name {host}: {e}"))?;
    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS handshake: {e}"))?;

    let (_, conn) = tls.get_ref();
    let protocol = conn.protocol_version().map(|v| format!("{v:?}"));
    let cipher_suite = conn.negotiated_cipher_suite().map(|c| format!("{c:?}"));
    let captured = capture.captured.lock().unwrap().clone();
    let parsed = captured.leaf.as_deref().map(parse_leaf);

    Ok(TlsProbe {
        handshake_ok: true,
        trusted: captured.trusted,
        protocol,
        cipher_suite,
        leaf_der: captured.leaf,
        not_after: parsed.as_ref().and_then(|p| p.not_after.clone()),
        days_until_expiry: parsed.as_ref().and_then(|p| p.days_until_expiry),
    })
}

fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    format!(
        "sha256:{}",
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

struct ParsedLeaf {
    subject: CertSubject,
    issuer: CertIssuer,
    serial: String,
    not_before: Option<String>,
    not_after: Option<String>,
    days_until_expiry: Option<i64>,
    sans: Vec<String>,
    key_algorithm: Option<String>,
    key_size: Option<u32>,
    signature_algorithm: Option<String>,
}

fn parse_leaf(der: &[u8]) -> ParsedLeaf {
    use x509_parser::prelude::*;

    let empty_subject = CertSubject {
        common_name: None,
        organization: None,
        country: None,
    };
    let empty_issuer = CertIssuer {
        common_name: None,
        organization: None,
        country: None,
    };

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return ParsedLeaf {
            subject: empty_subject,
            issuer: empty_issuer,
            serial: String::new(),
            not_before: None,
            not_after: None,
            days_until_expiry: None,
            sans: Vec::new(),
            key_algorithm: None,
            key_size: None,
            signature_algorithm: None,
        };
    };

    let not_before = asn1_to_rfc3339(cert.validity().not_before);
    let not_after = asn1_to_rfc3339(cert.validity().not_after);
    let days_until_expiry = Some((cert.validity().not_after.timestamp() - Utc::now().timestamp()) / 86_400);

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(s) => Some(s.to_string()),
                    GeneralName::IPAddress(b) => Some(format!("ip:{b:?}")),
                    GeneralName::URI(s) => Some(s.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let (key_algorithm, key_size) = match cert.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => (
            Some("RSA".to_string()),
            Some(rsa.key_size() as u32),
        ),
        Ok(x509_parser::public_key::PublicKey::EC(_)) => (Some("EC".to_string()), None),
        Ok(_) => (
            Some(cert.public_key().algorithm.algorithm.to_id_string()),
            None,
        ),
        Err(_) => (None, None),
    };

    ParsedLeaf {
        subject: CertSubject {
            common_name: rdn_str(cert.subject(), &oid_registry::OID_X509_COMMON_NAME),
            organization: rdn_str(cert.subject(), &oid_registry::OID_X509_ORGANIZATION_NAME),
            country: rdn_str(cert.subject(), &oid_registry::OID_X509_COUNTRY_NAME),
        },
        issuer: CertIssuer {
            common_name: rdn_str(cert.issuer(), &oid_registry::OID_X509_COMMON_NAME),
            organization: rdn_str(cert.issuer(), &oid_registry::OID_X509_ORGANIZATION_NAME),
            country: rdn_str(cert.issuer(), &oid_registry::OID_X509_COUNTRY_NAME),
        },
        serial: cert.raw_serial_as_string(),
        not_before,
        not_after,
        days_until_expiry,
        sans,
        key_algorithm,
        key_size,
        signature_algorithm: Some(cert.signature_algorithm.oid().to_id_string()),
    }
}

fn rdn_str(name: &x509_parser::x509::X509Name<'_>, oid: &oid_registry::Oid<'_>) -> Option<String> {
    name.iter_by_oid(oid)
        .next()
        .and_then(|attr| attr.as_str().ok().map(|s| s.to_string()))
}

fn asn1_to_rfc3339(t: x509_parser::time::ASN1Time) -> Option<String> {
    Utc.timestamp_opt(t.timestamp(), 0)
        .single()
        .map(|dt| dt.to_rfc3339())
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsCheckQuery {
    pub domain: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    443
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCheckResult {
    pub domain: String,
    pub port: u16,
    pub valid: bool,
    pub trusted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,
    /// Negotiated protocol only — not an invented supported-protocol list.
    pub protocols: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub warnings: Vec<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertInfoQuery {
    pub domain: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub domain: String,
    pub port: u16,
    pub trusted: bool,
    pub subject: CertSubject,
    pub issuer: CertIssuer,
    pub serial_number: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub sans: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertIssuer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListCertsQuery {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateSummary {
    pub id: String,
    pub domain: String,
    pub issuer: String,
    pub status: String,
    pub expires: String,
    pub days_until_expiry: i64,
    pub auto_renew: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListCertsResponse {
    pub certificates: Vec<CertificateSummary>,
    pub expiring_soon: usize,
    pub expired: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestCertRequest {
    pub domain: String,
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub auto_renew: bool,
}
