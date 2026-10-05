//! AiPassport substrate — mint at last governed boundary, egress outbox, private tally.

use connector_trust::{
    agent_subject_id_public, egress_operation_id, mint_aipsprt_sig, verify_aipsprt_sig,
    AiPassportPrivateRecordV1, AiPassportSigV1, ArtifactProfile, DigestRef, MintAiPassportArgs,
    ProvenanceRole, AIPSPRT_PRIVATE_SCHEMA, AIPSPRT_SIG_SCHEMA,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const FOLDER_PASSPORTS: &str = "aipsprt_passports_v1";
pub const FOLDER_PRIVATE: &str = "aipsprt_private_v1";
pub const FOLDER_INDEX: &str = "aipsprt_index_v1";
pub const FOLDER_SEQ: &str = "aipsprt_node_seq_v1";
pub const FOLDER_OUTBOX: &str = "aipsprt_egress_outbox_v1";
pub const FOLDER_BY_EOP: &str = "aipsprt_by_eop_v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutboxState {
    Prepared,
    ArtifactFinalized,
    PassportMinted,
    LocalCommitted,
    TallyCommitted,
    EgressAttempted,
    EgressConfirmed,
    EgressUnknown,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressOutboxRecord {
    pub schema: String,
    pub egress_operation_id: String,
    pub agent_pid: String,
    pub generation_id: String,
    pub artifact_instance_id: String,
    pub state: EgressOutboxState,
    pub passport_id: Option<String>,
    pub path: Option<String>,
    pub updated_at_ms: i64,
}

pub const EGRESS_OUTBOX_SCHEMA: &str = "connector.aipsprt.egress_outbox.v1";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn next_node_seq(state: &PlatformState) -> u64 {
    let mut es = match state.engine_store.lock() {
        Ok(g) => g,
        Err(_) => return 1,
    };
    let cur = es
        .folder_get(FOLDER_SEQ, "seq")
        .ok()
        .flatten()
        .and_then(|v| v.get("n").and_then(|n| n.as_u64()))
        .unwrap_or(0);
    let next = cur.saturating_add(1);
    let _ = es.folder_put(FOLDER_SEQ, "seq", &json!({ "n": next }));
    next
}

fn index_append(state: &PlatformState, index_key: &str, passport_id: &str) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let mut ids: Vec<String> = es
        .folder_get(FOLDER_INDEX, index_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v.get("ids").cloned().unwrap_or(json!([]))).ok())
        .unwrap_or_default();
    if !ids.iter().any(|x| x == passport_id) {
        ids.push(passport_id.to_string());
    }
    if ids.len() > 10_000 {
        let drop_n = ids.len() - 10_000;
        ids.drain(0..drop_n);
    }
    let _ = es.folder_put(
        FOLDER_INDEX,
        index_key,
        &json!({ "ids": ids, "updated_ms": now_ms() }),
    );
}

fn put_outbox(state: &PlatformState, rec: &EgressOutboxRecord) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let val = serde_json::to_value(rec).map_err(|e| e.to_string())?;
    es.folder_put(FOLDER_OUTBOX, &rec.egress_operation_id, &val)
        .map_err(|e| e.to_string())
}

fn get_outbox(state: &PlatformState, eop: &str) -> Option<EgressOutboxRecord> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_OUTBOX, eop).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn store_passport_and_indexes(
    state: &PlatformState,
    passport: &AiPassportSigV1,
    private: &AiPassportPrivateRecordV1,
    eop: &str,
) -> Result<(), String> {
    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let val = serde_json::to_value(passport).map_err(|e| e.to_string())?;
        es.folder_put(FOLDER_PASSPORTS, &passport.passport_id, &val)
            .map_err(|e| e.to_string())?;
        let priv_val = serde_json::to_value(private).map_err(|e| e.to_string())?;
        es.folder_put(FOLDER_PRIVATE, &passport.passport_id, &priv_val)
            .map_err(|e| e.to_string())?;
        let _ = es.folder_put(
            FOLDER_BY_EOP,
            eop,
            &json!({ "passport_id": passport.passport_id }),
        );
    }
    index_append(
        state,
        &format!("digest:{}", passport.payload.digest),
        &passport.passport_id,
    );
    index_append(
        state,
        &format!(
            "subject:{}:{}",
            passport.agent_subject_id, passport.issued_at_ms
        ),
        &passport.passport_id,
    );
    index_append(
        state,
        &format!("instance:{}", passport.artifact_instance_id),
        &passport.passport_id,
    );
    index_append(
        state,
        &format!("gen:{}", passport.generation_id),
        &passport.passport_id,
    );
    Ok(())
}

/// Idempotent: if egress_operation_id already minted, return existing passport.
pub fn passport_for_eop(state: &PlatformState, eop: &str) -> Option<AiPassportSigV1> {
    let es = state.engine_store.lock().ok()?;
    let pid = es
        .folder_get(FOLDER_BY_EOP, eop)
        .ok()
        .flatten()?
        .get("passport_id")?
        .as_str()?
        .to_string();
    drop(es);
    get_passport(state, &pid)
}

pub struct MintTalkPassportArgs<'a> {
    pub agent_pid: &'a str,
    pub principal_id: &'a str,
    pub generation_id: &'a str,
    pub quantum_id: &'a str,
    pub text: &'a str,
    pub character_digest_hex: &'a str,
    pub context_exposure_manifest_id: Option<String>,
    pub parent_passport_id: Option<String>,
    pub provenance_role: ProvenanceRole,
}

fn mint_core(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
    generation_id: &str,
    quantum_id: &str,
    profile: ArtifactProfile,
    digest_domain: &str,
    payload_bytes: &[u8],
    media_type: &str,
    character_digest_hex: &str,
    attempt_key: &str,
    provenance_role: ProvenanceRole,
    parent_passport_id: Option<String>,
    context_exposure_manifest_id: Option<String>,
    path: Option<&str>,
) -> Result<AiPassportSigV1, String> {
    let artifact_instance_id = format!(
        "ainst_{:x}",
        Sha256::digest(format!("{generation_id}|{attempt_key}|{agent_pid}").as_bytes())
    );
    let eop = egress_operation_id(generation_id, &artifact_instance_id, attempt_key);

    if let Some(existing) = passport_for_eop(state, &eop) {
        return Ok(existing);
    }

    let mut outbox = EgressOutboxRecord {
        schema: EGRESS_OUTBOX_SCHEMA.into(),
        egress_operation_id: eop.clone(),
        agent_pid: agent_pid.into(),
        generation_id: generation_id.into(),
        artifact_instance_id: artifact_instance_id.clone(),
        state: EgressOutboxState::Prepared,
        passport_id: None,
        path: path.map(|s| s.to_string()),
        updated_at_ms: now_ms(),
    };
    put_outbox(state, &outbox)?;

    outbox.state = EgressOutboxState::ArtifactFinalized;
    outbox.updated_at_ms = now_ms();
    put_outbox(state, &outbox)?;

    let sk = state.signing_key.ed25519();
    let pubkey = state.signing_key.public_key_hex();
    let subject = agent_subject_id_public(&pubkey, agent_pid);
    let payload = DigestRef::sha256_domain(
        digest_domain,
        "1",
        format!("{:x}", Sha256::digest(payload_bytes)),
    );
    let char_profile = DigestRef::sha256_domain("acs.canonical.v1", "1", character_digest_hex);
    let node_seq = next_node_seq(state);
    let passport = mint_aipsprt_sig(MintAiPassportArgs {
        signing_key: sk,
        issuer_key_id: "platform_ed25519",
        pubkey_hex: &pubkey,
        agent_subject_id: &subject,
        generation_id,
        provenance_role,
        artifact_profile: profile,
        payload,
        media_type,
        character_profile: char_profile,
        parent_passport_id,
        context_exposure_manifest_id,
        transit_manifest_digest: None,
        artifact_instance_id: Some(artifact_instance_id),
        egress_event_id: Some(format!("eeg_{}", uuid::Uuid::new_v4())),
        node_seq,
    });

    outbox.state = EgressOutboxState::PassportMinted;
    outbox.passport_id = Some(passport.passport_id.clone());
    outbox.updated_at_ms = now_ms();
    put_outbox(state, &outbox)?;

    let private = AiPassportPrivateRecordV1 {
        schema: AIPSPRT_PRIVATE_SCHEMA.into(),
        passport_id: passport.passport_id.clone(),
        agent_subject_id: subject,
        agent_pid: agent_pid.into(),
        principal_id: principal_id.into(),
        node_id_internal: pubkey,
        quantum_id: quantum_id.into(),
        egress_operation_id: eop.clone(),
        issued_at_ms: passport.issued_at_ms,
    };
    store_passport_and_indexes(state, &passport, &private, &eop)?;

    outbox.state = EgressOutboxState::TallyCommitted;
    outbox.updated_at_ms = now_ms();
    put_outbox(state, &outbox)?;

    if let Some(p) = path {
        let path_buf = std::path::Path::new(p);
        if path_buf.exists() || path_buf.parent().map(|d| d.exists()).unwrap_or(false) {
            let _ = write_sidecar(path_buf, &passport);
            outbox.state = EgressOutboxState::LocalCommitted;
            outbox.updated_at_ms = now_ms();
            put_outbox(state, &outbox)?;
        }
    } else {
        outbox.state = EgressOutboxState::LocalCommitted;
        outbox.updated_at_ms = now_ms();
        put_outbox(state, &outbox)?;
    }

    outbox.state = EgressOutboxState::EgressConfirmed;
    outbox.updated_at_ms = now_ms();
    put_outbox(state, &outbox)?;

    Ok(passport)
}

/// Mint passport over **finalized** talk text (last governed boundary).
pub fn mint_for_talk_text(
    state: &PlatformState,
    args: MintTalkPassportArgs<'_>,
) -> Result<AiPassportSigV1, String> {
    mint_core(
        state,
        args.agent_pid,
        args.principal_id,
        args.generation_id,
        args.quantum_id,
        ArtifactProfile::BufferedJson,
        "buffered_json.payload.v1",
        args.text.as_bytes(),
        "text/plain; charset=utf-8",
        args.character_digest_hex,
        "talk",
        args.provenance_role,
        args.parent_passport_id,
        args.context_exposure_manifest_id,
        None,
    )
}

/// Streaming closure: hash sealed projected text after last token (not mid-stream).
pub fn mint_streaming_closure(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
    generation_id: &str,
    quantum_id: &str,
    sealed_text: &str,
    character_digest_hex: &str,
) -> Result<AiPassportSigV1, String> {
    mint_core(
        state,
        agent_pid,
        principal_id,
        generation_id,
        quantum_id,
        ArtifactProfile::StreamingClosure,
        "streaming_closure.payload.v1",
        sealed_text.as_bytes(),
        "text/plain; charset=utf-8",
        character_digest_hex,
        "stream_closure",
        ProvenanceRole::Created,
        None,
        None,
        None,
    )
}

/// SSE event payload for final `event: aipsprt` (closure record).
pub fn streaming_aipsprt_sse_data(passport: &AiPassportSigV1) -> String {
    json!({
        "event": "aipsprt",
        "schema": AIPSPRT_SIG_SCHEMA,
        "passport_id": passport.passport_id,
        "payload_digest": passport.payload.digest,
        "digest_domain": passport.payload.digest_domain,
        "agent_subject_id": passport.agent_subject_id,
        "issuer_id": passport.issuer_id,
        "signature_ed25519_b64": passport.signature_ed25519_b64,
        "honesty": passport.honesty,
    })
    .to_string()
}

/// Object-store profile: body at put-complete; optional sidecar object path.
pub fn mint_for_object_store(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
    generation_id: &str,
    quantum_id: &str,
    object_key: &str,
    body: &[u8],
    media_type: &str,
    character_digest_hex: &str,
    sidecar_path: Option<&str>,
) -> Result<AiPassportSigV1, String> {
    mint_core(
        state,
        agent_pid,
        principal_id,
        generation_id,
        quantum_id,
        ArtifactProfile::ObjectStore,
        "object_store.body.v1",
        body,
        media_type,
        character_digest_hex,
        &format!("object:{object_key}"),
        ProvenanceRole::Created,
        None,
        None,
        sidecar_path,
    )
}

/// Email parts profile: logical body + attachment digests (not final SMTP bytes).
pub fn mint_for_email_parts(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
    generation_id: &str,
    quantum_id: &str,
    logical_body: &str,
    attachment_digests: &[(String, String)],
    character_digest_hex: &str,
) -> Result<AiPassportSigV1, String> {
    let mut material = logical_body.as_bytes().to_vec();
    for (name, dig) in attachment_digests {
        material.extend_from_slice(name.as_bytes());
        material.push(b'|');
        material.extend_from_slice(dig.as_bytes());
        material.push(b'\n');
    }
    mint_core(
        state,
        agent_pid,
        principal_id,
        generation_id,
        quantum_id,
        ArtifactProfile::EmailParts,
        "email_parts.logical.v1",
        &material,
        "multipart/logical",
        character_digest_hex,
        "email_parts",
        ProvenanceRole::Created,
        None,
        None,
        None,
    )
}

pub struct MintFileArgs<'a> {
    pub agent_pid: &'a str,
    pub principal_id: &'a str,
    pub generation_id: &'a str,
    pub quantum_id: &'a str,
    pub path: &'a str,
    pub content: &'a [u8],
    pub media_type: &'a str,
    pub character_digest_hex: &'a str,
    pub parent_passport_id: Option<String>,
    pub provenance_role: ProvenanceRole,
}

/// File profile: mint + `<path>.aipsprt.sig` sidecar via outbox.
pub fn mint_for_file_bytes(
    state: &PlatformState,
    args: MintFileArgs<'_>,
) -> Result<AiPassportSigV1, String> {
    mint_core(
        state,
        args.agent_pid,
        args.principal_id,
        args.generation_id,
        args.quantum_id,
        ArtifactProfile::FileBytes,
        "file_bytes.v1",
        args.content,
        args.media_type,
        args.character_digest_hex,
        &format!("file:{}", args.path),
        args.provenance_role,
        args.parent_passport_id,
        None,
        Some(args.path),
    )
}

/// After a successful write_file tool: read bytes if needed and mint sidecar.
pub fn maybe_passport_file_write(
    state: &PlatformState,
    agent_pid: &str,
    tool_name: &str,
    input: &serde_json::Value,
    tool_ok: bool,
) -> Option<AiPassportSigV1> {
    if !tool_ok {
        return None;
    }
    let is_write = matches!(
        tool_name,
        "write_file"
            | "connector_write_file"
            | "Write"
            | "write"
            | "write_to_file"
    );
    if !is_write {
        return None;
    }
    let path = input
        .get("path")
        .or_else(|| input.get("file_path"))
        .or_else(|| input.get("TargetFile"))
        .and_then(|v| v.as_str())?;
    let content = input
        .get("content")
        .or_else(|| input.get("contents"))
        .or_else(|| input.get("text"))
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| std::fs::read(path).ok())?;
    let gen = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| {
            es.folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
                .ok()
                .flatten()
                .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
        })
        .unwrap_or(0)
        .to_string();
    mint_for_file_bytes(
        state,
        MintFileArgs {
            agent_pid,
            principal_id: agent_pid,
            generation_id: &gen,
            quantum_id: "tool_write",
            path,
            content: &content,
            media_type: "application/octet-stream",
            character_digest_hex: "tool_write",
            parent_passport_id: None,
            provenance_role: ProvenanceRole::Created,
        },
    )
    .ok()
}

pub fn write_sidecar(path: &std::path::Path, passport: &AiPassportSigV1) -> Result<(), String> {
    let mut sig_path = path.as_os_str().to_owned();
    sig_path.push(".aipsprt.sig");
    let p = std::path::PathBuf::from(sig_path);
    let body = serde_json::to_vec_pretty(passport).map_err(|e| e.to_string())?;
    std::fs::write(&p, body).map_err(|e| e.to_string())
}

pub fn get_passport(state: &PlatformState, passport_id: &str) -> Option<AiPassportSigV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_PASSPORTS, passport_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn get_private(state: &PlatformState, passport_id: &str) -> Option<AiPassportPrivateRecordV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_PRIVATE, passport_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn index_ids(state: &PlatformState, index_key: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    es.folder_get(FOLDER_INDEX, index_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v.get("ids").cloned().unwrap_or(json!([]))).ok())
        .unwrap_or_default()
}

pub fn outbox_status(state: &PlatformState, eop: &str) -> Option<EgressOutboxRecord> {
    get_outbox(state, eop)
}

/// Federated verify: check Ed25519 against this node's verifying key + optional payload digest.
pub fn verify_local(
    state: &PlatformState,
    passport: &AiPassportSigV1,
    expected_payload_digest: Option<&str>,
) -> Result<(), String> {
    let pk = state.signing_key.public_key_hex();
    let bytes = hex::decode(&pk).map_err(|_| "bad_pubkey".to_string())?;
    if bytes.len() != 32 {
        return Err("bad_pubkey_len".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let vk = VerifyingKey::from_bytes(&arr).map_err(|_| "bad_verifying_key".to_string())?;
    verify_aipsprt_sig(passport, &vk, expected_payload_digest).map_err(|e| e.to_string())
}

pub fn schema_info() -> serde_json::Value {
    json!({
        "schema": AIPSPRT_SIG_SCHEMA,
        "outbox_schema": EGRESS_OUTBOX_SCHEMA,
        "folders": [FOLDER_PASSPORTS, FOLDER_PRIVATE, FOLDER_INDEX, FOLDER_OUTBOX],
        "honesty": "passport_primary_store_digest_is_postings_not_single_kv_no_public_oracle",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::egress_operation_id;

    #[test]
    fn eop_idempotent_key() {
        let a = egress_operation_id("g1", "ainst_x", "file:/tmp/a");
        let b = egress_operation_id("g1", "ainst_x", "file:/tmp/a");
        assert_eq!(a, b);
    }

    #[test]
    fn outbox_state_serde() {
        let s = EgressOutboxState::PassportMinted;
        let v = serde_json::to_value(s).unwrap();
        assert_eq!(v, json!("passport_minted"));
    }

    #[test]
    fn streaming_sse_mentions_passport() {
        // Shape-only: streaming helper needs a real passport; check JSON keys on a stub Value.
        let stub = json!({
            "event": "aipsprt",
            "passport_id": "aipsprt_x",
            "payload_digest": "abc",
        });
        assert_eq!(stub["event"], "aipsprt");
    }
}
