//! Cryptographic forensic flow identity (CFNI) — v2 wire contract.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CFNI_HEADER: &str = "x-connector-flow-id";
pub const CFNI_SCHEMA: &str = "forensic_flow_identity.v2";

/// Signed flow stamp attached to governed HTTP/RPC transits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicFlowIdentityV2 {
    pub schema: String,
    pub flow_id: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub hop: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_flow_id: Option<String>,
    pub signature_hex: String,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

fn canonical_signing_bytes(
    flow_id: &str,
    principal_id: &str,
    tenant_id: Option<&str>,
    issued_at_ms: i64,
    expires_at_ms: i64,
    hop: u32,
    parent_flow_id: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(flow_id.as_bytes());
    out.push(0);
    out.extend_from_slice(principal_id.as_bytes());
    out.push(0);
    out.extend_from_slice(tenant_id.unwrap_or("").as_bytes());
    out.push(0);
    out.extend_from_slice(&issued_at_ms.to_le_bytes());
    out.extend_from_slice(&expires_at_ms.to_le_bytes());
    out.extend_from_slice(&hop.to_le_bytes());
    out.extend_from_slice(parent_flow_id.unwrap_or("").as_bytes());
    out
}

fn sign(secret: &[u8], payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(payload);
    hex::encode(h.finalize())
}

/// Mint a new flow identity (server-side only).
pub fn mint_flow_identity(
    secret: &[u8],
    principal_id: impl Into<String>,
    tenant_id: Option<String>,
    ttl_ms: i64,
    parent_flow_id: Option<String>,
) -> ForensicFlowIdentityV2 {
    let principal_id = principal_id.into();
    let flow_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    let expires_at_ms = now.saturating_add(ttl_ms);
    let hop = parent_flow_id.as_ref().map(|_| 1).unwrap_or(0);
    let payload = canonical_signing_bytes(
        &flow_id,
        &principal_id,
        tenant_id.as_deref(),
        now,
        expires_at_ms,
        hop,
        parent_flow_id.as_deref(),
    );
    let signature_hex = sign(secret, &payload);
    ForensicFlowIdentityV2 {
        schema: CFNI_SCHEMA.into(),
        flow_id,
        principal_id,
        tenant_id,
        issued_at_ms: now,
        expires_at_ms,
        hop,
        parent_flow_id,
        signature_hex,
        contract_version: 2,
    }
}

/// Verify signature and expiry.
pub fn verify_flow_identity(
    identity: &ForensicFlowIdentityV2,
    secret: &[u8],
    now_ms: i64,
) -> Result<(), &'static str> {
    if identity.schema != CFNI_SCHEMA {
        return Err("invalid_schema");
    }
    if now_ms > identity.expires_at_ms {
        return Err("expired");
    }
    let payload = canonical_signing_bytes(
        &identity.flow_id,
        &identity.principal_id,
        identity.tenant_id.as_deref(),
        identity.issued_at_ms,
        identity.expires_at_ms,
        identity.hop,
        identity.parent_flow_id.as_deref(),
    );
    let expected = sign(secret, &payload);
    if expected != identity.signature_hex {
        return Err("bad_signature");
    }
    Ok(())
}

/// Compact wire form for HTTP header (base64url JSON).
pub fn encode_header_value(identity: &ForensicFlowIdentityV2) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_vec(identity)?;
    Ok(base64_url_encode(&raw))
}

pub fn decode_header_value(value: &str) -> Result<ForensicFlowIdentityV2, &'static str> {
    let bytes = base64_url_decode(value).ok_or("bad_encoding")?;
    serde_json::from_slice(&bytes).map_err(|_| "bad_json")
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify_round_trip() {
        let secret = b"test-secret";
        let id = mint_flow_identity(secret, "usr_1", Some("acme".into()), 60_000, None);
        verify_flow_identity(&id, secret, id.issued_at_ms + 1).expect("valid");
    }

    #[test]
    fn rejects_tampered_signature() {
        let secret = b"test-secret";
        let mut id = mint_flow_identity(secret, "usr_1", None, 60_000, None);
        id.signature_hex = "00".repeat(64);
        assert_eq!(verify_flow_identity(&id, secret, id.issued_at_ms), Err("bad_signature"));
    }

    #[test]
    fn header_round_trip() {
        let secret = b"test-secret";
        let id = mint_flow_identity(secret, "usr_1", None, 60_000, None);
        let enc = encode_header_value(&id).unwrap();
        let dec = decode_header_value(&enc).unwrap();
        assert_eq!(dec.flow_id, id.flow_id);
    }
}
