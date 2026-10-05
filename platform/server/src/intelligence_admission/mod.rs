//! N4 Intelligence Admission Matrix — Gate 1 (handshake → profile → CPO).

pub mod gateway_intercept;

use connector_trust::{
    sign_json_ed25519, CognitiveProposalV2, ContextClassV2, ContextSliceV2, IIA_SCHEMA,
    IntelligenceProfileV2,
};
use sha2::{Digest, Sha256};

use crate::kernel::agent_principal;
use crate::state::PlatformState;

pub const IIA_PROFILE_FOLDER: &str = "intelligence_profile_v2";
pub const IIA_CPO_FOLDER: &str = "cognitive_proposal_v2";

#[derive(Debug, serde::Deserialize)]
pub struct N4HelloRequest {
    pub agent_pid: String,
    pub model_ref: String,
    pub provider: String,
    #[serde(default)]
    pub claimed_capabilities: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct N4CognizeRequest {
    pub agent_pid: String,
    pub proposed_action: String,
    pub proposed_target: String,
    #[serde(default)]
    pub context_slices: Vec<ContextSliceInput>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ContextSliceInput {
    pub class: ContextClassV2,
    pub provenance: String,
    pub content: String,
}

pub fn n4_handshake(
    state: &PlatformState,
    req: &N4HelloRequest,
) -> Result<IntelligenceProfileV2, serde_json::Value> {
    let principal = agent_principal::load_principal(state, &req.agent_pid).ok_or_else(|| {
        serde_json::json!({"error": "principal_not_found", "message": "Register agent first (IIA P10.2)"})
    })?;

    let qualified = !req.model_ref.trim().is_empty() && !req.provider.trim().is_empty();
    if !qualified {
        return Err(serde_json::json!({
            "error": "n4_handshake_denied",
            "message": "Unqualified model — empty model_ref or provider",
            "qualified": false,
        }));
    }

    let intelligence_id = format!(
        "cnktr:intelligence:{}",
        hex::encode(Sha256::digest(
            format!("{}|{}|{}", req.model_ref, req.provider, req.agent_pid).as_bytes(),
        ))[..16]
            .to_string()
    );

    let now = chrono::Utc::now().timestamp_millis();
    let profile = IntelligenceProfileV2 {
        schema: IIA_SCHEMA.into(),
        intelligence_id: intelligence_id.clone(),
        model_ref: req.model_ref.clone(),
        provider: req.provider.clone(),
        claimed: serde_json::json!({
            "capabilities": req.claimed_capabilities,
            "principal_id": principal.principal_id,
        }),
        observed: serde_json::json!({
            "provider": req.provider,
            "model_ref": req.model_ref,
        }),
        attested: serde_json::json!({
            "node_witness": state.signing_key.public_key_hex(),
        }),
        contract_accepted: true,
        qualified,
        handshake_at_ms: now,
    };

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(IIA_PROFILE_FOLDER, &req.agent_pid, &serde_json::to_value(&profile).unwrap());

    Ok(profile)
}

pub fn n4_cognize(
    state: &PlatformState,
    req: &N4CognizeRequest,
) -> Result<CognitiveProposalV2, serde_json::Value> {
    let principal = agent_principal::load_principal(state, &req.agent_pid).ok_or_else(|| {
        serde_json::json!({"error": "principal_not_found"})
    })?;
    let profile: IntelligenceProfileV2 = {
        let es = state.engine_store.lock().unwrap();
        let v = es
            .folder_get(IIA_PROFILE_FOLDER, &req.agent_pid)
            .ok()
            .flatten()
            .ok_or_else(|| {
                serde_json::json!({"error": "n4_not_qualified", "message": "POST /n4/hello first"})
            })?;
        serde_json::from_value(v).map_err(|_| {
            serde_json::json!({"error": "profile_corrupt"})
        })?
    };
    if !profile.qualified {
        return Err(serde_json::json!({"error": "n4_handshake_denied"}));
    }

    let slices: Vec<ContextSliceV2> = req
        .context_slices
        .iter()
        .map(|s| ContextSliceV2 {
            class: s.class,
            provenance: s.provenance.clone(),
            content_digest_sha256: hex::encode(Sha256::digest(s.content.as_bytes())),
        })
        .collect();

    let cpo_id = format!("cpo_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().timestamp_millis();
    let mut cpo = CognitiveProposalV2 {
        schema: IIA_SCHEMA.into(),
        cpo_id: cpo_id.clone(),
        principal_id: principal.principal_id.clone(),
        intelligence_id: profile.intelligence_id.clone(),
        proposed_action: req.proposed_action.clone(),
        proposed_target: req.proposed_target.clone(),
        context_slices: slices,
        non_authoritative: true,
        issued_at_ms: now,
        model_ref: principal.model_ref.clone(),
        signature: None,
    };

    // B27: node key only — ephemeral keys must never mint Ed25519Court.
    if let Ok(sig) = sign_json_ed25519(state.signing_key.ed25519(), &cpo) {
        cpo.signature = Some(sig);
    }

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(IIA_CPO_FOLDER, &cpo_id, &serde_json::to_value(&cpo).unwrap());

    Ok(cpo)
}

/// Prompt-injection path: untrusted context with privileged action → CPO only, flagged.
pub fn cognize_untrusted_injection(
    state: &PlatformState,
    agent_pid: &str,
    inject_content: &str,
    privileged_action: &str,
) -> Result<CognitiveProposalV2, serde_json::Value> {
    n4_cognize(
        state,
        &N4CognizeRequest {
            agent_pid: agent_pid.into(),
            proposed_action: privileged_action.into(),
            proposed_target: "finance/ledger".into(),
            context_slices: vec![ContextSliceInput {
                class: ContextClassV2::Untrusted,
                provenance: "user_message".into(),
                content: inject_content.into(),
            }],
        },
    )
}
