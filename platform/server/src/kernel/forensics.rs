//! Intelligence receipt chain — CPO → quantum → DockLock → effect (IIA P10.7).
//! Court-tier: signed with the stable node Ed25519 key (never ephemeral per receipt).

use connector_trust::{
    sign_json_ed25519, ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA, FourIdLinkageV2,
    IntelligenceReceiptV2, IIA_SCHEMA, SigningTierV2,
};
use sha2::{Digest, Sha256};

use crate::kernel::{agent_principal, forensic_rollups};
use crate::state::PlatformState;

pub const IIA_RECEIPT_INDEX: &str = "intelligence_receipt_index_v2";

/// B26: court tier only when a node Ed25519 signature is present.
pub fn tier_for_signed(signed: bool) -> SigningTierV2 {
    if signed {
        SigningTierV2::Ed25519Court
    } else {
        SigningTierV2::HmacLab
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct AppendReceiptParams {
    pub agent_pid: String,
    pub cpo_id: Option<String>,
    pub quantum_id: Option<String>,
    pub docklock_profile_id: Option<String>,
    pub effect_digest: String,
}

pub fn append_receipt(
    state: &PlatformState,
    params: AppendReceiptParams,
) -> IntelligenceReceiptV2 {
    let principal = agent_principal::load_principal(state, &params.agent_pid);
    let prev = chain_head_for_agent(state, &params.agent_pid);
    let now = chrono::Utc::now().timestamp_millis();
    let receipt_id = format!("ir_{}", uuid::Uuid::new_v4());
    let chain_head = hex::encode(Sha256::digest(
        format!(
            "{}|{}|{}|{}",
            receipt_id,
            params.effect_digest,
            prev.as_deref().unwrap_or("genesis"),
            now
        )
        .as_bytes(),
    ));

    let mut receipt = IntelligenceReceiptV2 {
        schema: IIA_SCHEMA.into(),
        receipt_id: receipt_id.clone(),
        principal_id: principal
            .as_ref()
            .map(|p| p.principal_id.clone())
            .unwrap_or_default(),
        intelligence_id: principal
            .and_then(|p| p.intelligence_id)
            .unwrap_or_default(),
        cpo_id: params.cpo_id.clone(),
        quantum_id: params.quantum_id.clone(),
        docklock_profile_id: params.docklock_profile_id.clone(),
        effect_digest_sha256: params.effect_digest.clone(),
        previous_receipt_digest: prev,
        chain_head_digest: chain_head.clone(),
        issued_at_ms: now,
        // B26: provisional lab until node Ed25519 sign succeeds.
        signing_tier: SigningTierV2::HmacLab,
        signature: None,
    };

    // Stable node key — auditor can verify against platform_verifying.pub.
    if let Ok(sig) = sign_json_ed25519(state.signing_key.ed25519(), &receipt) {
        receipt.signature = Some(sig);
        receipt.signing_tier = SigningTierV2::Ed25519Court;
    }

    {
        let mut es = state.engine_store.lock().unwrap();
        let prev_count = es
            .folder_get(IIA_RECEIPT_INDEX, &params.agent_pid)
            .ok()
            .flatten()
            .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
            .unwrap_or(0);
        let _ = es.folder_put(
            agent_principal::IIA_RECEIPT_CHAIN_FOLDER,
            &receipt_id,
            &serde_json::to_value(&receipt).unwrap(),
        );
        let _ = es.folder_put(
            IIA_RECEIPT_INDEX,
            &params.agent_pid,
            &serde_json::json!({
                "head": receipt.chain_head_digest,
                "last_id": receipt_id,
                "count": prev_count + 1,
            }),
        );
    }

    let _ = crate::substrate::artifact_log::append_artifact_record(
        state,
        &ArtifactLogRecordV2 {
            schema: ARTIFACT_LOG_SCHEMA.into(),
            record_id: format!("al_ir_{receipt_id}"),
            artifact_class: ArtifactClass::Proof,
            artifact_type: "intelligence_receipt_v2".into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            segment_id: None,
            principal_id: Some(receipt.principal_id.clone()),
            tenant_id: None,
            content_digest: Some(receipt.chain_head_digest.clone()),
            payload: serde_json::json!({
                "receipt_id": receipt.receipt_id,
                "cpo_id": receipt.cpo_id,
                "quantum_id": receipt.quantum_id,
                "docklock_profile_id": receipt.docklock_profile_id,
                "effect_digest_sha256": receipt.effect_digest_sha256,
            }),
            contract_version: 2,
        },
    );

    let leaf = hex::encode(Sha256::digest(
        format!("{}|{}", receipt_id, params.effect_digest).as_bytes(),
    ));
    let _ = forensic_rollups::record_event(
        state,
        forensic_rollups::RollupEvent {
            agent_pid: &params.agent_pid,
            event_kind: "intelligence_receipt",
            leaf_digest: leaf,
            universal_envelope_id: None,
            namespace: None,
            cross_agent_denied: false,
            admission_deny: false,
            continuity_break: false,
            quarantine: false,
            egress_isolated: false,
            cpo_id: params.cpo_id,
            quantum_id: params.quantum_id,
            docklock_profile_id: params.docklock_profile_id,
            intelligence_receipt_id: Some(receipt_id),
            witnessctl_session_id: None,
            tracetramp_trace_id: None,
            fni_flow_id: None,
            moment_id: None,
        },
    );

    receipt
}

pub fn chain_head_for_agent(state: &PlatformState, api_pid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(IIA_RECEIPT_INDEX, api_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("head").and_then(|h| h.as_str().map(str::to_string)))
}

pub fn export_receipt_chain(state: &PlatformState, api_pid: &str) -> Vec<IntelligenceReceiptV2> {
    let principal = match agent_principal::load_principal(state, api_pid) {
        Some(p) => p,
        None => return vec![],
    };
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys(agent_principal::IIA_RECEIPT_CHAIN_FOLDER, None)
        .unwrap_or_default();
    let mut receipts: Vec<IntelligenceReceiptV2> = keys
        .into_iter()
        .filter_map(|k| {
            let v = es
                .folder_get(agent_principal::IIA_RECEIPT_CHAIN_FOLDER, &k)
                .ok()
                .flatten()?;
            serde_json::from_value::<IntelligenceReceiptV2>(v).ok()
        })
        .filter(|r| r.principal_id == principal.principal_id)
        .collect();
    receipts.sort_by_key(|r| r.issued_at_ms);
    receipts
}

pub fn four_id_linkage(state: &PlatformState, api_pid: &str) -> Option<FourIdLinkageV2> {
    let p = agent_principal::load_principal(state, api_pid)?;
    Some(FourIdLinkageV2 {
        agent_id: p.principal_id.clone(),
        intelligence_id: p.intelligence_id.clone().unwrap_or_default(),
        runtime_id: p.runtime_hash.clone().unwrap_or_default(),
        machine_id: std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "local".into()),
    })
}

pub fn receipt_index_count(state: &PlatformState, api_pid: &str) -> u64 {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(IIA_RECEIPT_INDEX, api_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
        .unwrap_or(0)
}
