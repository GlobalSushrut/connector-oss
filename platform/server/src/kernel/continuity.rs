//! Continuity evaluation + Execution Reality Manifest (IIA P10.6).

use connector_trust::{
    AttestationTierV2, ContinuityRecordV2, ContinuityStateV2, ExecutionRealityManifestV2,
    IIA_SCHEMA,
};
use sha2::{Digest, Sha256};

use crate::kernel::agent_principal;
use crate::state::{PlatformState, SharedState};

pub const IIA_ERM_FOLDER: &str = "execution_reality_manifest_v2";

pub fn evaluate_continuity(
    state: &SharedState,
    api_pid: &str,
    observed_runtime_hash: &str,
    observed_model_ref: &str,
) -> ContinuityRecordV2 {
    let contract = agent_principal::load_contract(state.as_ref(), api_pid);
    let principal = agent_principal::load_principal(state.as_ref(), api_pid);
    let mut record = agent_principal::load_continuity(state.as_ref(), api_pid).unwrap_or_else(|| {
        ContinuityRecordV2 {
            schema: IIA_SCHEMA.into(),
            principal_id: principal
                .as_ref()
                .map(|p| p.principal_id.clone())
                .unwrap_or_default(),
            state: ContinuityStateV2::Unknown,
            model_ref: observed_model_ref.into(),
            runtime_hash: observed_runtime_hash.into(),
            contract_digest_sha256: contract
                .as_ref()
                .map(|c| c.contract_digest_sha256.clone())
                .unwrap_or_default(),
            evaluated_at_ms: chrono::Utc::now().timestamp_millis(),
            break_reason: None,
        }
    });

    let mut broken = false;
    let mut reason = None;
    if let Some(p) = &principal {
        if let Some(m) = &p.model_ref {
            if m != observed_model_ref {
                broken = true;
                reason = Some("model_substitution".into());
            }
        }
        if let Some(rh) = &p.runtime_hash {
            if rh != observed_runtime_hash {
                broken = true;
                reason = Some(reason.unwrap_or_else(|| "runtime_hash_mismatch".into()));
            }
        }
    }

    record.state = if broken {
        ContinuityStateV2::Broken
    } else {
        ContinuityStateV2::Verified
    };
    record.break_reason = reason;
    record.evaluated_at_ms = chrono::Utc::now().timestamp_millis();
    record.runtime_hash = observed_runtime_hash.into();
    record.model_ref = observed_model_ref.into();

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            agent_principal::IIA_CONTINUITY_FOLDER,
            api_pid,
            &serde_json::to_value(&record).unwrap(),
        );
    }
    if record.state == ContinuityStateV2::Broken {
        let reason = record
            .break_reason
            .clone()
            .unwrap_or_else(|| "continuity_broken".into());
        crate::kernel::matrix_isolation::react_on_continuity_break(state, api_pid, &reason);
    }
    record
}

pub fn load_execution_reality_manifest(state: &PlatformState) -> Option<ExecutionRealityManifestV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_ERM_FOLDER, "latest").ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn mint_execution_reality_manifest(state: &PlatformState) -> ExecutionRealityManifestV2 {
    let now = chrono::Utc::now().timestamp_millis();
    let node_id = std::env::var("CONNECTOR_CELL_ID").unwrap_or_else(|_| "local".into());
    let cell_id = std::env::var("CONNECTOR_CELL_REGION").unwrap_or_else(|_| "local".into());
    let runtime_hash = hex::encode(Sha256::digest(
        std::env::var("CONNECTOR_BINARY_ID")
            .unwrap_or_else(|_| "connector-platform".into())
            .as_bytes(),
    ));
    // Honesty: never claim TPM/TDX without a real quote path.
    let allow_claim = std::env::var("CONNECTOR_ATTESTATION_ALLOW_CLAIM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let tier = match std::env::var("CONNECTOR_ATTESTATION_TIER")
        .unwrap_or_else(|_| "none".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "tpm" | "tdx" if allow_claim => {
            tracing::warn!(
                "CONNECTOR_ATTESTATION_ALLOW_CLAIM=1 — recording claimed attestation tier without quote verification"
            );
            if std::env::var("CONNECTOR_ATTESTATION_TIER")
                .unwrap_or_default()
                .eq_ignore_ascii_case("tdx")
            {
                AttestationTierV2::Tdx
            } else {
                AttestationTierV2::Tpm
            }
        }
        "tpm" | "tdx" => {
            tracing::warn!(
                "CONNECTOR_ATTESTATION_TIER set but no quote path — forcing None (set CONNECTOR_ATTESTATION_ALLOW_CLAIM=1 to override)"
            );
            AttestationTierV2::None
        }
        _ => AttestationTierV2::None,
    };

    let mut manifest = ExecutionRealityManifestV2 {
        schema: IIA_SCHEMA.into(),
        manifest_id: format!("erm_{}", uuid::Uuid::new_v4()),
        node_id,
        cell_id,
        runtime_hash: runtime_hash.clone(),
        hardware_fingerprint: machine_fingerprint(),
        attestation_tier: tier,
        issued_at_ms: now,
        signature: None,
    };

    let digest = connector_trust::canonical_digest_json(&manifest).unwrap_or_default();
    let sig_b64 = state.signing_key.sign(digest.as_bytes());
    manifest.signature = Some(connector_trust::SignedPayloadV2 {
        content_digest_sha256: digest,
        signature_b64: sig_b64,
        public_key_hex: state.signing_key.public_key_hex(),
        signing_tier: connector_trust::SigningTierV2::Ed25519Court,
    });

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(IIA_ERM_FOLDER, "latest", &serde_json::to_value(&manifest).unwrap());
    }
    manifest
}

fn machine_fingerprint() -> String {
    hex::encode(Sha256::digest(
        format!(
            "{}|{}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
            std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "data".into()),
        )
        .as_bytes(),
    ))[..16]
        .to_string()
}

pub fn break_continuity_lab(state: &PlatformState, api_pid: &str, reason: &str) {
    if let Some(mut c) = agent_principal::load_continuity(state, api_pid) {
        c.state = ContinuityStateV2::Broken;
        c.break_reason = Some(reason.into());
        c.evaluated_at_ms = chrono::Utc::now().timestamp_millis();
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put(
                agent_principal::IIA_CONTINUITY_FOLDER,
                api_pid,
                &serde_json::to_value(&c).unwrap(),
            );
        }
        crate::kernel::matrix_isolation::react_on_continuity_break_platform(state, api_pid, reason);
    }
}
