//! Compliance Contract — bound at agent activate; auditor-facing SoT (P10.10.6).

use connector_trust::{
    canonical_digest_json, sign_json_ed25519, ComplianceContractV2, COMPLIANCE_CONTRACT_SCHEMA,
    FourIdLinkageV2, SigningTierV2, AGENT_IDENTITY_SCHEMA,
};
use sha2::{Digest, Sha256};

use crate::kernel::{agent_foundation, agent_identity_envelope, agent_principal, forensics};
use crate::state::PlatformState;

pub const COMPLIANCE_CONTRACT_FOLDER: &str = "compliance_contract_v2";

pub fn load_compliance_contract(state: &PlatformState, api_pid: &str) -> Option<ComplianceContractV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(COMPLIANCE_CONTRACT_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// Mint + persist signed ComplianceContractV2 at activate (court-tier node key).
pub fn bind_at_activate(
    state: &PlatformState,
    api_pid: &str,
    activation_digest: &str,
    witnessctl_session_id: Option<String>,
) -> Result<ComplianceContractV2, String> {
    let setup = agent_identity_envelope::load_setup(state, api_pid)
        .ok_or("setup_not_found")?;
    let principal = agent_principal::load_principal(state, api_pid)
        .ok_or("principal_not_found")?;
    let contract = agent_principal::load_contract(state, api_pid)
        .ok_or("agent_contract_not_found")?;
    let four_id = forensics::four_id_linkage(state, api_pid).unwrap_or(FourIdLinkageV2 {
        agent_id: principal.principal_id.clone(),
        intelligence_id: principal.intelligence_id.clone().unwrap_or_default(),
        runtime_id: principal.runtime_hash.clone().unwrap_or_default(),
        machine_id: std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "local".into()),
    });
    let scope = agent_identity_envelope::build_namespace_scope(api_pid, &setup.namespace, &setup);
    let identity_digest = agent_identity_envelope::build_identity_envelope(state, api_pid)
        .map(|e| {
            canonical_digest_json(&e).unwrap_or_else(|_| {
                hex::encode(Sha256::digest(serde_json::to_vec(&e).unwrap_or_default()))
            })
        })
        .unwrap_or_else(|| {
            agent_foundation::load_foundation_block(state, api_pid)
                .map(|f| f.agent_intelligence_hash)
                .unwrap_or_default()
        });

    let use_case_summary = setup.use_case_def.as_ref().and_then(|v| {
        v.get("summary")
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .or_else(|| Some(v.to_string()))
    });

    let now = chrono::Utc::now().timestamp_millis();
    let contract_id = format!(
        "cc_{}",
        &hex::encode(Sha256::digest(
            format!("{}|{}|{}", api_pid, setup.acume, now).as_bytes()
        ))[..16]
    );

    let mut body = ComplianceContractV2 {
        schema: COMPLIANCE_CONTRACT_SCHEMA.into(),
        contract_id: contract_id.clone(),
        version: 2,
        signing_tier: SigningTierV2::HmacLab,
        agent_pid: api_pid.to_string(),
        principal_id: principal.principal_id.clone(),
        intelligence_id: principal.intelligence_id.clone().unwrap_or_default(),
        four_id,
        acume: setup.acume.clone(),
        use_case_summary,
        philosophy_digest_sha256: setup.philosophy_digest.clone(),
        capabilities: contract.capabilities.clone(),
        denied_operations: contract.denied_operations.clone(),
        hitl_policy: setup.hitl_policy,
        forensic_profile: setup.forensic_profile,
        private_memory: scope.private_memory,
        knowledge_base: scope.knowledge_base,
        common_spaces: setup.common_spaces.clone(),
        isolation_enforced: true,
        frameworks: setup.forensic_profile.framework_bindings(),
        evidence_policy: setup.forensic_profile.evidence_policy(),
        identity_envelope_digest_sha256: identity_digest,
        activation_profile_digest_sha256: activation_digest.to_string(),
        agent_contract_digest_sha256: contract.contract_digest_sha256.clone(),
        compliance_contract_digest_sha256: String::new(),
        bound_at_ms: now,
        bound_by: "cnktr:org:connector-node".into(),
        witnessctl_session_id,
        signature: None,
    };

    // Digest over unsigned body (signature field None).
    body.compliance_contract_digest_sha256 = canonical_digest_json(&body).map_err(|e| e.to_string())?;
    let sig = sign_json_ed25519(state.signing_key.ed25519(), &body).map_err(|e| e.to_string())?;
    body.signature = Some(sig);
    body.signing_tier = SigningTierV2::Ed25519Court; // B26: court only after node sign

    {
        let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
        es.folder_put(
            COMPLIANCE_CONTRACT_FOLDER,
            api_pid,
            &serde_json::to_value(&body).unwrap(),
        )
        .map_err(|e| format!("{e:?}"))?;
    }

    // ArtifactLog Proof class for court reconstruction.
    let observed = chrono::Utc::now().to_rfc3339();
    let _ = crate::substrate::artifact_log::append_artifact_record(
        state,
        &connector_trust::ArtifactLogRecordV2 {
            schema: connector_trust::ARTIFACT_LOG_SCHEMA.into(),
            record_id: format!("al_cc_{contract_id}"),
            artifact_class: connector_trust::ArtifactClass::Proof,
            artifact_type: "compliance_contract_bind".into(),
            observed_at: observed,
            segment_id: None,
            principal_id: Some(body.principal_id.clone()),
            tenant_id: None,
            content_digest: Some(body.compliance_contract_digest_sha256.clone()),
            payload: serde_json::json!({
                "schema": AGENT_IDENTITY_SCHEMA,
                "contract_id": body.contract_id,
                "agent_pid": api_pid,
                "acume": body.acume,
                "frameworks": body.frameworks.iter().map(|f| &f.id).collect::<Vec<_>>(),
            }),
            contract_version: 2,
        },
    );

    Ok(body)
}
