//! Phase 4.2 — canonical package digest + Ed25519 sign / verify.

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::CpkgError;
use crate::layout::SIGNATURE_PATH;
use crate::signature::CpkgSignatureEnvelope;

/// Domain separation prefix for bytes fed to Ed25519 (full message = prefix || digest32).
pub const SIGN_MESSAGE_PREFIX: &[u8] = b"CONNECTOR_CPKG_SIGN_V1\0";

#[derive(Serialize)]
struct CanonicalFileEntry {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct CanonicalPayloadV1 {
    schema: u32,
    manifest_sha256: String,
    files: Vec<CanonicalFileEntry>,
}

/// Deterministic SHA-256 over canonical JSON (sorted file entries, excluding signature).
pub fn canonical_payload_digest(
    manifest_src: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<[u8; 32], CpkgError> {
    let mut manifest_hasher = Sha256::new();
    manifest_hasher.update(manifest_src.as_bytes());
    let manifest_sha256 = hex::encode(manifest_hasher.finalize());

    let mut entries: Vec<CanonicalFileEntry> = Vec::new();
    for (path, bytes) in files {
        if path == SIGNATURE_PATH {
            continue;
        }
        let mut h = Sha256::new();
        h.update(bytes);
        entries.push(CanonicalFileEntry {
            path: path.clone(),
            sha256: hex::encode(h.finalize()),
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let body = CanonicalPayloadV1 {
        schema: 1,
        manifest_sha256,
        files: entries,
    };
    let json = serde_json::to_vec(&body)?;
    let mut hasher = Sha256::new();
    hasher.update(&json);
    Ok(hasher.finalize().into())
}

fn signing_message(digest: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGN_MESSAGE_PREFIX.len() + 32);
    m.extend_from_slice(SIGN_MESSAGE_PREFIX);
    m.extend_from_slice(digest);
    m
}

/// Build signature envelope (does not embed in ZIP — caller passes to [`crate::write_cpkg`]).
pub fn sign_envelope(
    manifest_src: &str,
    files: &BTreeMap<String, Vec<u8>>,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<CpkgSignatureEnvelope, CpkgError> {
    let digest = canonical_payload_digest(manifest_src, files)?;
    let msg = signing_message(&digest);
    let sig = signing_key.sign(&msg);
    Ok(CpkgSignatureEnvelope {
        algorithm: "ed25519".into(),
        key_id: key_id.into(),
        payload_sha256: Some(hex::encode(digest)),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        parent_key_id: None,
    })
}

/// Parse a 32-byte verifying key from standard base64 (raw public key).
pub fn parse_verifying_key_b64(b64: &str) -> Result<VerifyingKey, CpkgError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| CpkgError::Invalid("invalid base64 for ed25519 public key"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CpkgError::Invalid("ed25519 public key must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CpkgError::Invalid("invalid ed25519 public key bytes"))
}

/// Verify detached signature against canonical digest; `trust` maps `key_id` → verifying key.
pub fn verify_envelope(
    envelope: &CpkgSignatureEnvelope,
    manifest_src: &str,
    files: &BTreeMap<String, Vec<u8>>,
    trust: &BTreeMap<String, VerifyingKey>,
) -> Result<(), CpkgError> {
    if !envelope.algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(CpkgError::Invalid("signature algorithm must be ed25519"));
    }
    let vk = trust
        .get(&envelope.key_id)
        .ok_or_else(|| CpkgError::TrustKeyNotFound(envelope.key_id.clone()))?;
    let digest = canonical_payload_digest(manifest_src, files)?;
    if let Some(ref expect) = envelope.payload_sha256 {
        if expect.to_ascii_lowercase() != hex::encode(digest) {
            return Err(CpkgError::SignatureInvalid);
        }
    }
    let msg = signing_message(&digest);
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.signature_b64.trim())
        .map_err(|_| CpkgError::SignatureInvalid)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CpkgError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(&msg, &signature)
        .map_err(|_| CpkgError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let mut trust = BTreeMap::new();
        trust.insert("k1".into(), vk);

        let manifest = "[plugin]\nid = \"a/b\"\nname = \"T\"\nversion = \"1.0.0\"\nauthor = \"a\"\nlicense = \"MIT\"\nmin_kernel = \"0.1.0\"\nagos_abi = \"agos.v1\"\n\n[runtime]\ntype = \"subprocess\"\nentrypoint = \"bin/x\"\nmemory_mb = 1\nvcpus = 1\nshared = false\nmax_concurrency = 1\nidle_window = \"1s\"\ncold_start_budget_ms = 1\n\n[routes]\nprefix = \"/p\"\nadmin = \"/a\"\n\n[capabilities]\nrequired = []\n";
        let mut files = BTreeMap::new();
        files.insert("bin/x".into(), vec![1, 2, 3]);

        let env = sign_envelope(manifest, &files, "k1", &sk).unwrap();
        verify_envelope(&env, manifest, &files, &trust).unwrap();

        files.insert("bin/y".into(), vec![4]);
        assert!(verify_envelope(&env, manifest, &files, &trust).is_err());
    }
}
