//! Cryptographic primitives for AgentPassport.
//!
//! - Ed25519 keypair generation and signing
//! - DID minting (did:connector:agent:<uuid>)
//! - CID computation (SHA-256 of canonical JSON)
//! - Liability signature: Ed25519(agent_did ‖ sponsor_did ‖ timestamp)
//! - Verification proof construction

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::types::VerificationProof;

// ── DID Minting ────────────────────────────────────────────────────────────────

pub fn mint_agent_did(id: &Uuid) -> String {
    format!("did:connector:agent:{}", id)
}

pub fn mint_user_did(email: &str) -> String {
    let hash = hex::encode(Sha256::digest(email.as_bytes()));
    format!("did:connector:user:{}", &hash[..16])
}

pub fn mint_passport_did(instance_id: &str) -> String {
    format!("did:connector:agentpassport:{}", instance_id)
}

// ── Ed25519 Keypair ────────────────────────────────────────────────────────────

pub struct AgentKeypair {
    pub signing_key:   SigningKey,
    pub verifying_key: VerifyingKey,
    pub public_key_hex: String,
}

impl AgentKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        Self { signing_key, verifying_key, public_key_hex }
    }
}

// ── Signing key from hex ───────────────────────────────────────────────────────

pub fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey> {
    let bytes = hex::decode(hex_str).context("invalid hex signing key")?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str).context("invalid hex verifying key")?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("verifying key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 verifying key")
}

// ── Sign bytes ─────────────────────────────────────────────────────────────────

pub fn sign_bytes(key: &SigningKey, message: &[u8]) -> String {
    let sig: Signature = key.sign(message);
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], sig_b64: &str) -> Result<()> {
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)
        .context("invalid base64 signature")?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    verifying_key.verify(message, &sig).context("signature verification failed")
}

// ── CID (Content ID) ───────────────────────────────────────────────────────────
//
// CID = "cid:" + hex(SHA-256(canonical_json))
// Canonical JSON = serde_json sorted keys, no extra whitespace

pub fn compute_cid(content: &Value) -> String {
    let canonical = canonical_json(content);
    let hash = Sha256::digest(canonical.as_bytes());
    format!("cid:{}", hex::encode(hash))
}

pub fn compute_cid_str(s: &str) -> String {
    let hash = Sha256::digest(s.as_bytes());
    format!("cid:{}", hex::encode(hash))
}

pub fn chain_cid(prev_cid: Option<&str>, content: &Value) -> String {
    let payload = match prev_cid {
        Some(p) => format!("{}{}", p, canonical_json(content)),
        None    => canonical_json(content),
    };
    let hash = Sha256::digest(payload.as_bytes());
    format!("cid:{}", hex::encode(hash))
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys.iter()
                .map(|k| format!("\"{}\":{}", k, canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

// ── Liability signature ────────────────────────────────────────────────────────
//
// Signs: agent_did ‖ ":" ‖ sponsor_did ‖ ":" ‖ ISO8601(timestamp)
// This binds the sponsor to a specific agent at a specific moment.

pub fn sign_liability(
    key: &SigningKey,
    agent_did: &str,
    sponsor_did: &str,
) -> String {
    let ts = Utc::now().to_rfc3339();
    let msg = format!("{}:{}:{}", agent_did, sponsor_did, ts);
    sign_bytes(key, msg.as_bytes())
}

// ── Verification proof ─────────────────────────────────────────────────────────

pub fn build_verification_proof(
    key: &SigningKey,
    instance_did: &str,
    key_id: &str,
    payload_json: &Value,
) -> VerificationProof {
    let canonical = canonical_json(payload_json);
    let signature = sign_bytes(key, canonical.as_bytes());
    VerificationProof {
        proof_type:          "Ed25519Signature2020".into(),
        created:             Utc::now(),
        verification_method: format!("{}#{}", instance_did, key_id),
        signature,
    }
}

// ── W3C VC proof ───────────────────────────────────────────────────────────────

pub fn sign_vc(key: &SigningKey, vc_json: &Value) -> String {
    let canonical = canonical_json(vc_json);
    sign_bytes(key, canonical.as_bytes())
}

pub fn verify_vc_proof(
    public_key_hex: &str,
    vc_json: &Value,
    proof_sig: &str,
) -> Result<()> {
    let vk = verifying_key_from_hex(public_key_hex)?;
    let canonical = canonical_json(vc_json);
    verify_signature(&vk, canonical.as_bytes(), proof_sig)
}
