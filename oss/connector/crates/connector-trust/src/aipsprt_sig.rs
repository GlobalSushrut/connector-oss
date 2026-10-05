//! AiPassport.sig — transition record from ephemeral agent execution to persistent matter.
//!
//! Schema: `connector.aipsprt.sig.v1`
//!
//! Separates content identity (`payload` DigestRef), object instance
//! (`artifact_instance_id`), and egress event (`egress_event_id`). Passport rides
//! **outside** the hashed payload (sidecar / envelope sibling / stream closure).
//! External verify uses Ed25519; HMAC is local/dev only.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AIPSPRT_SIG_SCHEMA: &str = "connector.aipsprt.sig.v1";
pub const AIPSPRT_HEADER: &str = "x-connector-aipsprt-sig";
pub const AIPSPRT_HONESTY: &str =
    "issuer_attestation_not_env_truth_not_court_grade_not_delivery";

/// Named digest with explicit domain — never a bare hex without context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigestRef {
    pub digest_alg: String,
    pub digest_domain: String,
    pub canonicalization_version: String,
    pub digest: String,
}

impl DigestRef {
    pub fn sha256_domain(domain: &str, canon_version: &str, digest_hex: impl Into<String>) -> Self {
        Self {
            digest_alg: "sha256".into(),
            digest_domain: domain.into(),
            canonicalization_version: canon_version.into(),
            digest: digest_hex.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRole {
    Created,
    Transformed,
    Relayed,
    Observed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProfile {
    BufferedJson,
    StreamingClosure,
    FileBytes,
    EmailParts,
    ObjectStore,
    Other,
}

/// Public leave-behind passport (counterparties / archives).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiPassportSigV1 {
    pub schema: String,
    pub passport_id: String,
    pub artifact_instance_id: String,
    pub egress_event_id: String,
    pub generation_id: String,
    pub provenance_role: ProvenanceRole,
    pub artifact_profile: ArtifactProfile,
    pub payload: DigestRef,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_passport_id: Option<String>,
    /// Public pseudonym — not raw agent_pid.
    pub agent_subject_id: String,
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub character_profile: DigestRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_exposure_manifest_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_manifest_digest: Option<String>,
    pub issued_at_ms: i64,
    pub node_seq: u64,
    pub digest_hex: String,
    pub signature_ed25519_b64: String,
    pub honesty: String,
}

impl AiPassportSigV1 {
    pub fn unsigned_preimage(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": AIPSPRT_SIG_SCHEMA,
            "passport_id": self.passport_id,
            "artifact_instance_id": self.artifact_instance_id,
            "egress_event_id": self.egress_event_id,
            "generation_id": self.generation_id,
            "provenance_role": self.provenance_role,
            "artifact_profile": self.artifact_profile,
            "payload": self.payload,
            "media_type": self.media_type,
            "parent_passport_id": self.parent_passport_id,
            "agent_subject_id": self.agent_subject_id,
            "issuer_id": self.issuer_id,
            "issuer_key_id": self.issuer_key_id,
            "character_profile": self.character_profile,
            "context_exposure_manifest_id": self.context_exposure_manifest_id,
            "transit_manifest_digest": self.transit_manifest_digest,
            "issued_at_ms": self.issued_at_ms,
            "node_seq": self.node_seq,
            "honesty": AIPSPRT_HONESTY,
        })
    }

    pub fn compute_digest_hex(&self) -> String {
        let bytes = serde_json::to_vec(&self.unsigned_preimage()).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    pub fn digest_matches(&self) -> bool {
        self.digest_hex == self.compute_digest_hex()
    }
}

/// Private forensic record — never default-egress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiPassportPrivateRecordV1 {
    pub schema: String,
    pub passport_id: String,
    pub agent_subject_id: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub node_id_internal: String,
    pub quantum_id: String,
    pub egress_operation_id: String,
    pub issued_at_ms: i64,
}

pub const AIPSPRT_PRIVATE_SCHEMA: &str = "connector.aipsprt.private.v1";

pub fn payload_digest_bytes(domain: &str, canon_version: &str, bytes: &[u8]) -> DigestRef {
    DigestRef::sha256_domain(domain, canon_version, format!("{:x}", Sha256::digest(bytes)))
}

pub fn agent_subject_id_public(tenant_or_node: &str, agent_pid: &str) -> String {
    let material = format!("agpub|{tenant_or_node}|{agent_pid}");
    let h = format!("{:x}", Sha256::digest(material.as_bytes()));
    format!("agpub_{}", &h[..24.min(h.len())])
}

pub fn issuer_id_from_pubkey_hex(pubkey_hex: &str) -> String {
    let h = format!("{:x}", Sha256::digest(pubkey_hex.as_bytes()));
    format!("connectorissuer_{}", &h[..16.min(h.len())])
}

fn sign_digest_ed25519(signing_key: &SigningKey, digest_hex: &str) -> String {
    let sig = signing_key.sign(digest_hex.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes())
}

fn verify_digest_ed25519(
    verifying_key: &VerifyingKey,
    digest_hex: &str,
    signature_b64: &str,
) -> bool {
    let Ok(sig_bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
    else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    verifying_key.verify(digest_hex.as_bytes(), &sig).is_ok()
}

pub struct MintAiPassportArgs<'a> {
    pub signing_key: &'a SigningKey,
    pub issuer_key_id: &'a str,
    pub pubkey_hex: &'a str,
    pub agent_subject_id: &'a str,
    pub generation_id: &'a str,
    pub provenance_role: ProvenanceRole,
    pub artifact_profile: ArtifactProfile,
    pub payload: DigestRef,
    pub media_type: &'a str,
    pub character_profile: DigestRef,
    pub parent_passport_id: Option<String>,
    pub context_exposure_manifest_id: Option<String>,
    pub transit_manifest_digest: Option<String>,
    pub artifact_instance_id: Option<String>,
    pub egress_event_id: Option<String>,
    pub node_seq: u64,
}

/// Mint Ed25519-signed public passport. Caller keeps private record separately.
pub fn mint_aipsprt_sig(args: MintAiPassportArgs<'_>) -> AiPassportSigV1 {
    let now = chrono::Utc::now().timestamp_millis();
    let passport_id = format!("aipsprt_{}", uuid::Uuid::new_v4());
    let artifact_instance_id = args
        .artifact_instance_id
        .unwrap_or_else(|| format!("ainst_{}", uuid::Uuid::new_v4()));
    let egress_event_id = args
        .egress_event_id
        .unwrap_or_else(|| format!("eeg_{}", uuid::Uuid::new_v4()));
    let mut passport = AiPassportSigV1 {
        schema: AIPSPRT_SIG_SCHEMA.into(),
        passport_id,
        artifact_instance_id,
        egress_event_id,
        generation_id: args.generation_id.into(),
        provenance_role: args.provenance_role,
        artifact_profile: args.artifact_profile,
        payload: args.payload,
        media_type: args.media_type.into(),
        parent_passport_id: args.parent_passport_id,
        agent_subject_id: args.agent_subject_id.into(),
        issuer_id: issuer_id_from_pubkey_hex(args.pubkey_hex),
        issuer_key_id: args.issuer_key_id.into(),
        character_profile: args.character_profile,
        context_exposure_manifest_id: args.context_exposure_manifest_id,
        transit_manifest_digest: args.transit_manifest_digest,
        issued_at_ms: now,
        node_seq: args.node_seq,
        digest_hex: String::new(),
        signature_ed25519_b64: String::new(),
        honesty: AIPSPRT_HONESTY.into(),
    };
    passport.digest_hex = passport.compute_digest_hex();
    passport.signature_ed25519_b64 =
        sign_digest_ed25519(args.signing_key, &passport.digest_hex);
    passport
}

pub fn verify_aipsprt_sig(
    passport: &AiPassportSigV1,
    verifying_key: &VerifyingKey,
    expected_payload_digest: Option<&str>,
) -> Result<(), &'static str> {
    if passport.schema != AIPSPRT_SIG_SCHEMA {
        return Err("aipsprt_invalid_schema");
    }
    if !passport.digest_matches() {
        return Err("aipsprt_digest_mismatch");
    }
    if !verify_digest_ed25519(
        verifying_key,
        &passport.digest_hex,
        &passport.signature_ed25519_b64,
    ) {
        return Err("aipsprt_signature_invalid");
    }
    if let Some(want) = expected_payload_digest {
        if want != passport.payload.digest {
            return Err("aipsprt_payload_digest_mismatch");
        }
    }
    Ok(())
}

/// Local/dev HMAC over digest — never for customer verify.
pub fn mint_aipsprt_hmac_dev(
    secret: &[u8],
    mut passport: AiPassportSigV1,
) -> AiPassportSigV1 {
    passport.digest_hex = passport.compute_digest_hex();
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b"|aipsprt.v1.hmac_dev|");
    h.update(passport.digest_hex.as_bytes());
    passport.signature_ed25519_b64 = format!("hmac_dev:{}", hex::encode(h.finalize()));
    passport.issuer_key_id = "hmac_dev".into();
    passport
}

pub fn encode_aipsprt_header(passport: &AiPassportSigV1) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_vec(passport)?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

pub fn decode_aipsprt_header(value: &str) -> Result<AiPassportSigV1, String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "aipsprt_header_b64".to_string())?;
    serde_json::from_slice(&raw).map_err(|e| format!("aipsprt_header_json:{e}"))
}

/// Thin C2PA Content Credentials export map — **not** a full manifest embedder.
///
/// Maps AiPassport fields onto the assertion vocabulary operators would feed a
/// future C2PA bridge. Generated from the sealed passport so it cannot diverge
/// from an unsigned parallel path (Integrity Clash class of failure).
pub fn c2pa_export_mapping(passport: &AiPassportSigV1) -> serde_json::Value {
    let digital_source_type = match passport.provenance_role {
        ProvenanceRole::Created => "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        ProvenanceRole::Transformed => {
            "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
        }
        ProvenanceRole::Relayed | ProvenanceRole::Observed => {
            "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia"
        }
    };
    let actions = match passport.provenance_role {
        ProvenanceRole::Created => vec!["c2pa.created"],
        ProvenanceRole::Transformed => vec!["c2pa.converted", "c2pa.edited"],
        ProvenanceRole::Relayed => vec!["c2pa.transcoded"],
        ProvenanceRole::Observed => vec!["c2pa.opened"],
    };
    serde_json::json!({
        "schema": "connector.aipsprt.c2pa_export_map.v1",
        "source_passport_id": passport.passport_id,
        "source_digest_hex": passport.digest_hex,
        "hard_binding": {
            "alg": passport.payload.digest_alg,
            "hash": passport.payload.digest,
            "digest_domain": passport.payload.digest_domain,
            "canonicalization_version": passport.payload.canonicalization_version,
            "note": "AiPassport DigestRef → C2PA hard binding at named domain",
        },
        "assertions_sketch": {
            "c2pa.actions": actions,
            "c2pa.ai-disclosure": {
                "digitalSourceType": digital_source_type,
                "generator": passport.issuer_id,
                "agent_subject_id": passport.agent_subject_id,
            },
        },
        "connector_extensions_not_in_c2pa_core": {
            "artifact_instance_id": passport.artifact_instance_id,
            "egress_event_id": passport.egress_event_id,
            "generation_id": passport.generation_id,
            "provenance_role": passport.provenance_role,
            "artifact_profile": passport.artifact_profile,
            "parent_passport_id": passport.parent_passport_id,
        },
        "honesty": "export_map_only_not_embedded_manifest_not_court_grade",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn mint_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let pk = hex::encode(vk.to_bytes());
        let payload = payload_digest_bytes("buffered_json.payload.v1", "1", b"hello");
        let char_d = DigestRef::sha256_domain("acs.canonical.v1", "1", "abcd");
        let p = mint_aipsprt_sig(MintAiPassportArgs {
            signing_key: &sk,
            issuer_key_id: "ed25519_test",
            pubkey_hex: &pk,
            agent_subject_id: "agpub_test",
            generation_id: "gen_1",
            provenance_role: ProvenanceRole::Created,
            artifact_profile: ArtifactProfile::BufferedJson,
            payload: payload.clone(),
            media_type: "text/plain",
            character_profile: char_d,
            parent_passport_id: None,
            context_exposure_manifest_id: None,
            transit_manifest_digest: None,
            artifact_instance_id: None,
            egress_event_id: None,
            node_seq: 1,
        });
        verify_aipsprt_sig(&p, &vk, Some(&payload.digest)).unwrap();

        let map = c2pa_export_mapping(&p);
        assert_eq!(map["schema"], "connector.aipsprt.c2pa_export_map.v1");
        assert_eq!(map["source_passport_id"], p.passport_id);
        assert!(map["assertions_sketch"]["c2pa.actions"].is_array());

        let mut evil = p.clone();
        evil.generation_id = "gen_2".into();
        assert!(verify_aipsprt_sig(&evil, &vk, Some(&payload.digest)).is_err());
    }

    #[test]
    fn same_bytes_different_instances() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let payload = payload_digest_bytes("file_bytes.v1", "1", b"OK");
        let char_d = DigestRef::sha256_domain("acs.canonical.v1", "1", "c");
        let a = mint_aipsprt_sig(MintAiPassportArgs {
            signing_key: &sk,
            issuer_key_id: "k",
            pubkey_hex: &pk,
            agent_subject_id: "agpub_a",
            generation_id: "g1",
            provenance_role: ProvenanceRole::Created,
            artifact_profile: ArtifactProfile::FileBytes,
            payload: payload.clone(),
            media_type: "text/plain",
            character_profile: char_d.clone(),
            parent_passport_id: None,
            context_exposure_manifest_id: None,
            transit_manifest_digest: None,
            artifact_instance_id: Some("ainst_a".into()),
            egress_event_id: Some("eeg_1".into()),
            node_seq: 1,
        });
        let b = mint_aipsprt_sig(MintAiPassportArgs {
            signing_key: &sk,
            issuer_key_id: "k",
            pubkey_hex: &pk,
            agent_subject_id: "agpub_b",
            generation_id: "g2",
            provenance_role: ProvenanceRole::Created,
            artifact_profile: ArtifactProfile::FileBytes,
            payload,
            media_type: "text/plain",
            character_profile: char_d,
            parent_passport_id: None,
            context_exposure_manifest_id: None,
            transit_manifest_digest: None,
            artifact_instance_id: Some("ainst_b".into()),
            egress_event_id: Some("eeg_2".into()),
            node_seq: 2,
        });
        assert_eq!(a.payload.digest, b.payload.digest);
        assert_ne!(a.artifact_instance_id, b.artifact_instance_id);
        assert_ne!(a.passport_id, b.passport_id);
    }

    #[test]
    fn header_codec() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let p = mint_aipsprt_sig(MintAiPassportArgs {
            signing_key: &sk,
            issuer_key_id: "k",
            pubkey_hex: &pk,
            agent_subject_id: "agpub_x",
            generation_id: "g",
            provenance_role: ProvenanceRole::Relayed,
            artifact_profile: ArtifactProfile::Other,
            payload: payload_digest_bytes("d", "1", b"x"),
            media_type: "application/octet-stream",
            character_profile: DigestRef::sha256_domain("acs", "1", "z"),
            parent_passport_id: None,
            context_exposure_manifest_id: None,
            transit_manifest_digest: None,
            artifact_instance_id: None,
            egress_event_id: None,
            node_seq: 0,
        });
        let h = encode_aipsprt_header(&p).unwrap();
        let back = decode_aipsprt_header(&h).unwrap();
        assert_eq!(back.passport_id, p.passport_id);
    }
}
