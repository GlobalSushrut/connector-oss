//! Mint and persist `IntelligencePrincipalV2` + `AgentContractV2` at agent register.

use connector_trust::{
    AgentContractV2, ContinuityRecordV2, ContinuityStateV2, IIA_SCHEMA,
    IntelligencePrincipalV2, RuntimeSelfEnvelopeV2, SigningTierV2, mint_principal_id,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const IIA_PRINCIPAL_FOLDER: &str = "intelligence_principal_v2";
pub const IIA_CONTRACT_FOLDER: &str = "agent_contract_v2";
pub const IIA_CONTINUITY_FOLDER: &str = "continuity_record_v2";
pub const IIA_RECEIPT_CHAIN_FOLDER: &str = "intelligence_receipt_v2";

#[derive(Debug, Clone)]
pub struct MintPrincipalParams<'a> {
    pub api_pid: &'a str,
    pub agent_name: &'a str,
    pub issuer: &'a str,
    pub model_ref: Option<&'a str>,
    pub purpose: Vec<String>,
    pub capabilities: Vec<String>,
    pub namespace: &'a str,
    pub master_agent_id: Option<String>,
    pub geo_id: Option<String>,
    pub knowledge_base_id: Option<String>,
}

pub fn contract_digest(contract: &AgentContractV2) -> String {
    let bytes = serde_json::to_vec(contract).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

fn env_csv(name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(name).ok()?;
    let parts: Vec<String> = raw
        .split([':', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

fn env_truthy(name: &str) -> Option<bool> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Mint defaults: env overrides → namespace-scoped FS → safe deny-default network.
pub fn compile_contract(params: &MintPrincipalParams<'_>) -> AgentContractV2 {
    let agent_id = mint_principal_id(params.api_pid);
    let ns = params.namespace.trim().trim_matches('/');
    let fs_read = env_csv("CONNECTOR_CONTRACT_FS_READ").unwrap_or_else(|| {
        if ns.is_empty() {
            vec!["/workspace/**".into()]
        } else {
            vec![
                format!("/workspace/{ns}/**"),
                "/workspace/shared/**".into(),
            ]
        }
    });
    let fs_write = env_csv("CONNECTOR_CONTRACT_FS_WRITE").unwrap_or_else(|| {
        if ns.is_empty() {
            vec!["/workspace/out/**".into()]
        } else {
            vec![format!("/workspace/{ns}/out/**")]
        }
    });
    let denied = env_csv("CONNECTOR_CONTRACT_DENIED_OPS").unwrap_or_else(|| {
        vec!["modify_contract".into(), "ambient_shell".into()]
    });
    let network_allow = env_csv("CONNECTOR_CONTRACT_NETWORK_ALLOW").unwrap_or_default();
    let network_default = std::env::var("CONNECTOR_CONTRACT_NETWORK_DEFAULT")
        .unwrap_or_else(|_| "deny".into());
    let receipt_required = env_truthy("CONNECTOR_CONTRACT_RECEIPT_REQUIRED").unwrap_or(true);
    let mut contract = AgentContractV2 {
        schema: IIA_SCHEMA.into(),
        agent_id: agent_id.clone(),
        issuer: params.issuer.into(),
        purpose: params.purpose.clone(),
        capabilities: params.capabilities.clone(),
        denied_operations: denied,
        filesystem_read: fs_read,
        filesystem_write: fs_write,
        network_allow,
        network_default,
        receipt_required,
        contract_digest_sha256: String::new(),
        contract_version: 2,
    };
    contract.contract_digest_sha256 = contract_digest(&contract);
    contract
}

/// Mint principal + contract at register; persist under api_pid key.
pub fn mint_at_register(
    state: &PlatformState,
    params: MintPrincipalParams<'_>,
) -> Result<IntelligencePrincipalV2, String> {
    crate::kernel::address_cage::assert_agent_not_host_identity(params.api_pid)?;
    let subkey = SigningKey::generate(&mut OsRng);
    let contract = compile_contract(&params);
    let now = chrono::Utc::now().timestamp_millis();
    let intelligence_id = format!(
        "cnktr:intelligence:{}",
        hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}",
                params.model_ref.unwrap_or("unknown"),
                now,
                params.api_pid
            )
            .as_bytes()
        ))[..16]
            .to_string()
    );

    let principal = IntelligencePrincipalV2 {
        schema: IIA_SCHEMA.into(),
        principal_id: contract.agent_id.clone(),
        issuer: params.issuer.into(),
        authority_chain: vec![
            params.issuer.into(),
            contract.agent_id.clone(),
        ],
        public_key_hex: hex::encode(subkey.verifying_key().to_bytes()),
        contract_digest_sha256: contract.contract_digest_sha256.clone(),
        model_ref: params.model_ref.map(str::to_string),
        runtime_hash: Some(runtime_hash_placeholder()),
        intelligence_id: Some(intelligence_id),
        created_at_ms: now,
        node_witness_pubkey_hex: Some(state.signing_key.public_key_hex()),
        contract_version: 2,
    };

    let continuity = ContinuityRecordV2 {
        schema: IIA_SCHEMA.into(),
        principal_id: principal.principal_id.clone(),
        // B25: do not claim Verified until continuity evaluate — Unknown at mint.
        state: ContinuityStateV2::Unknown,
        model_ref: params.model_ref.unwrap_or("unknown").into(),
        runtime_hash: runtime_hash_placeholder(),
        contract_digest_sha256: contract.contract_digest_sha256.clone(),
        evaluated_at_ms: now,
        break_reason: None,
    };

    {
        let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
        let _ = es.folder_put(
            IIA_PRINCIPAL_FOLDER,
            params.api_pid,
            &serde_json::to_value(&principal).unwrap(),
        );
        let _ = es.folder_put(
            IIA_CONTRACT_FOLDER,
            params.api_pid,
            &serde_json::to_value(&contract).unwrap(),
        );
        let _ = es.folder_put(
            IIA_CONTINUITY_FOLDER,
            params.api_pid,
            &serde_json::to_value(&continuity).unwrap(),
        );
        // Store subkey bytes for lab signing (production: HSM / delegated subkey policy).
        let _ = es.folder_put(
            "intelligence_principal_subkey_v2",
            params.api_pid,
            &serde_json::json!({
                "subkey_hex": hex::encode(subkey.to_bytes()),
                "agent_name": params.agent_name,
            }),
        );
    }
    // Must release engine_store before foundation — append_receipt / rollups re-lock.

    let _ = crate::kernel::agent_foundation::mint_foundation_block(
        state,
        crate::kernel::agent_foundation::MintFoundationParams {
            api_pid: params.api_pid,
            principal: &principal,
            contract: &contract,
            namespace: params.namespace,
            purpose: params.purpose.clone(),
            master_agent_id: params.master_agent_id.clone(),
            geo_id: params.geo_id.clone(),
            knowledge_base_id: params.knowledge_base_id.clone(),
        },
    );

    Ok(principal)
}

pub fn load_principal(state: &PlatformState, api_pid: &str) -> Option<IntelligencePrincipalV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_PRINCIPAL_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// A20 — swap model_ref only; identity / grants / DIM persist.
pub fn set_model_ref(state: &PlatformState, api_pid: &str, model_ref: &str) -> Result<(), String> {
    let mut p = load_principal(state, api_pid).ok_or_else(|| "principal_not_found".to_string())?;
    p.model_ref = Some(model_ref.to_string());
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    es.folder_put(
        IIA_PRINCIPAL_FOLDER,
        api_pid,
        &serde_json::to_value(&p).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub fn load_contract(state: &PlatformState, api_pid: &str) -> Option<AgentContractV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_CONTRACT_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// True when Ring-1 / QPR / setup-gate force charter + fabric fail-closed.
pub fn intelligence_hardening_on() -> bool {
    // Playground: pilots must not force identity-stack fail-closed unless explicitly opted in.
    let playground = std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if playground {
        let explicit = std::env::var("CONNECTOR_IIA_RING1")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
            || std::env::var("CONNECTOR_SANDBOX_UNBYPASSABLE")
                .map(|v| {
                    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                })
                .unwrap_or(false);
        if !explicit {
            return false;
        }
    }
    crate::kernel::docklock::ring1_enforce_enabled()
        || std::env::var("CONNECTOR_IIA_QPR_ENFORCE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        || std::env::var("CONNECTOR_AGENT_SETUP_GATE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

/// C9 — charter gate for effect paths (tools / memory / Talk / fabric). Fail-closed when hardening on.
pub fn require_contract_action(
    state: &PlatformState,
    api_pid: &str,
    action: &str,
    target: &str,
) -> Result<(), String> {
    let enforce = intelligence_hardening_on();

    match load_contract(state, api_pid) {
        Some(contract) => {
            if crate::quanta_polar::contract_allows_action(&contract, action, target) {
                Ok(())
            } else {
                Err(format!(
                    "contract_denied: action={action} target={target} (capabilities/denied_operations)"
                ))
            }
        }
        None if enforce => Err(format!(
            "contract_required: no AgentContract for {api_pid} while intelligence hardening is on"
        )),
        None => Ok(()),
    }
}

/// Patch AgentContractV2 cage fields (B1). Recomputes digest; bumps contract_version.
/// Does not allow changing `agent_id` / `issuer`. Clears `modify_contract` from becoming allowed
/// unless explicitly removed from denied_operations by the caller.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ContractPatchV2 {
    pub purpose: Option<Vec<String>>,
    pub capabilities: Option<Vec<String>>,
    pub denied_operations: Option<Vec<String>>,
    pub filesystem_read: Option<Vec<String>>,
    pub filesystem_write: Option<Vec<String>>,
    pub network_allow: Option<Vec<String>>,
    pub network_default: Option<String>,
    pub receipt_required: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ContractUpdateResult {
    pub contract: AgentContractV2,
    pub revoked_quanta: usize,
    pub needs_reactivate: bool,
}

pub fn purpose_is_specific(items: &[String]) -> bool {
    items.iter().any(|item| {
        let trimmed = item.trim();
        !trimmed.is_empty()
            && !trimmed.eq_ignore_ascii_case("general-purpose")
            && !trimmed.eq_ignore_ascii_case("general_purpose")
            && !trimmed.eq_ignore_ascii_case("general,assistant")
    })
}

pub fn update_contract(
    state: &PlatformState,
    api_pid: &str,
    patch: ContractPatchV2,
) -> Result<ContractUpdateResult, String> {
    let mut contract = load_contract(state, api_pid).ok_or_else(|| "contract_not_found".to_string())?;
    let purpose_patched = patch.purpose.is_some();
    if let Some(v) = patch.purpose {
        if !purpose_is_specific(&v) {
            return Err("specific_purpose_required".into());
        }
        contract.purpose = v;
    }
    if let Some(v) = patch.capabilities {
        contract.capabilities = v;
    }
    if let Some(v) = patch.denied_operations {
        contract.denied_operations = v;
    }
    if let Some(v) = patch.filesystem_read {
        contract.filesystem_read = v;
    }
    if let Some(v) = patch.filesystem_write {
        contract.filesystem_write = v;
    }
    if let Some(v) = patch.network_allow {
        contract.network_allow = v;
    }
    if let Some(v) = patch.network_default {
        contract.network_default = v;
    }
    if let Some(v) = patch.receipt_required {
        contract.receipt_required = v;
    }
    // Digest field must be empty/zeroed before hashing content (exclude self).
    contract.contract_digest_sha256.clear();
    contract.contract_version = contract.contract_version.saturating_add(1);
    contract.contract_digest_sha256 = contract_digest(&contract);

    // Keep principal + continuity digests aligned.
    if let Some(mut principal) = load_principal(state, api_pid) {
        principal.contract_digest_sha256 = contract.contract_digest_sha256.clone();
        principal.contract_version = contract.contract_version;
        let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
        let _ = es.folder_put(
            IIA_PRINCIPAL_FOLDER,
            api_pid,
            &serde_json::to_value(&principal).map_err(|e| e.to_string())?,
        );
        let _ = es.folder_put(
            IIA_CONTRACT_FOLDER,
            api_pid,
            &serde_json::to_value(&contract).map_err(|e| e.to_string())?,
        );
        if let Ok(Some(mut cont_v)) = es.folder_get(IIA_CONTINUITY_FOLDER, api_pid) {
            if let Ok(mut cont) = serde_json::from_value::<ContinuityRecordV2>(cont_v.clone()) {
                cont.contract_digest_sha256 = contract.contract_digest_sha256.clone();
                cont.evaluated_at_ms = chrono::Utc::now().timestamp_millis();
                cont_v = serde_json::to_value(&cont).unwrap_or(cont_v);
                let _ = es.folder_put(IIA_CONTINUITY_FOLDER, api_pid, &cont_v);
            }
        }
    } else {
        let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
        let _ = es.folder_put(
            IIA_CONTRACT_FOLDER,
            api_pid,
            &serde_json::to_value(&contract).map_err(|e| e.to_string())?,
        );
    }

    // B6: void outstanding quanta — old authority must not outlive new digest.
    let revoked = crate::quanta_polar::revoke_all_quanta_for_agent(state, api_pid);
    // Seven Pillars §1/§3 — character/contract change invalidates flow leases + authz.
    crate::kernel::effect_authz::invalidate_on_identity_change(state, api_pid);

    // Demote activation so operator re-binds ComplianceContractV2.
    let mut needs_reactivate = false;
    if let Some(mut act) =
        crate::kernel::agent_identity_envelope::load_activation(state, api_pid)
    {
        if matches!(act.state, connector_trust::ActivationStateV2::Active) {
            act.state = connector_trust::ActivationStateV2::SetupReady;
            act.activated_at_ms = None;
            act.activation_receipt_id = None;
            let _ = crate::kernel::agent_identity_envelope::save_activation(state, &act);
            needs_reactivate = true;
        }
    }
    tracing::info!(
        api_pid = %api_pid,
        revoked_quanta = revoked,
        needs_reactivate,
        digest = %contract.contract_digest_sha256,
        "IIA contract patched"
    );

    if purpose_patched {
        let command = serde_json::json!({
            "schema": "connector.purpose_command.v1",
            "agent_pid": api_pid,
            "contract_version": contract.contract_version,
            "reactivation": if needs_reactivate { "demoted_to_setup_ready" } else { "not_active" },
            "restarted": false,
            "admits": false,
            "honesty": "Every purpose write uses this contract update. An active runtime is demoted to setup. This command does not start it.",
        });
        if let Ok(mut store) = state.engine_store.lock() {
            let _ = store.folder_put("purpose_command_v1", api_pid, &command);
            let _ = store.folder_put(
                "purpose_command_v1",
                &format!("{api_pid}:{}", contract.contract_version),
                &command,
            );
        }
    }

    Ok(ContractUpdateResult {
        contract,
        revoked_quanta: revoked,
        needs_reactivate,
    })
}

/// B6: after setup/charter material change, demote Active → SetupReady and void quanta.
pub fn demote_after_charter_change(state: &PlatformState, api_pid: &str) -> (usize, bool) {
    let revoked = crate::quanta_polar::revoke_all_quanta_for_agent(state, api_pid);
    let mut needs_reactivate = false;
    if let Some(mut act) = crate::kernel::agent_identity_envelope::load_activation(state, api_pid) {
        if matches!(act.state, connector_trust::ActivationStateV2::Active) {
            act.state = connector_trust::ActivationStateV2::SetupReady;
            act.activated_at_ms = None;
            act.activation_receipt_id = None;
            let _ = crate::kernel::agent_identity_envelope::save_activation(state, &act);
            needs_reactivate = true;
        }
    }
    (revoked, needs_reactivate)
}

pub fn load_continuity(state: &PlatformState, api_pid: &str) -> Option<ContinuityRecordV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_CONTINUITY_FOLDER, api_pid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn runtime_self_envelope(
    state: &PlatformState,
    api_pid: &str,
) -> Option<RuntimeSelfEnvelopeV2> {
    let principal = load_principal(state, api_pid)?;
    let contract = load_contract(state, api_pid)?;
    let continuity = load_continuity(state, api_pid)?;
    let foundation_block = crate::kernel::agent_foundation::load_foundation_block(state, api_pid);
    // Do NOT call who_am_i_authoritative here — it builds the full identity envelope which
    // calls runtime_self_envelope again (stack overflow). Envelope layer fills who_am_i.
    let mut envelope = RuntimeSelfEnvelopeV2 {
        schema: IIA_SCHEMA.into(),
        principal,
        contract,
        continuity,
        signing_tier: SigningTierV2::HmacLab,
        principal_signature: None,
        foundation_block,
        who_am_i_authoritative: None,
    };
    if let Ok(digest) = connector_trust::canonical_digest_json(&envelope.principal) {
        let sig_b64 = state.signing_key.sign(digest.as_bytes());
        envelope.principal_signature = Some(connector_trust::SignedPayloadV2 {
            content_digest_sha256: digest,
            signature_b64: sig_b64,
            public_key_hex: state.signing_key.public_key_hex(),
            signing_tier: SigningTierV2::Ed25519Court,
        });
        envelope.signing_tier = SigningTierV2::Ed25519Court;
    }
    Some(envelope)
}

fn runtime_hash_placeholder() -> String {
    hex::encode(Sha256::digest(
        std::env::var("CONNECTOR_BINARY_ID")
            .unwrap_or_else(|_| "connector-platform-dev".into())
            .as_bytes(),
    ))[..16]
        .to_string()
}

/// Resolve api_pid from kernel_pid via engine_store map.
pub fn api_pid_from_kernel(state: &PlatformState, kernel_pid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get("agent_pid_map", kernel_pid)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_or_general_purpose_is_rejected() {
        assert!(!purpose_is_specific(&[]));
        assert!(!purpose_is_specific(&["general-purpose".into()]));
        assert!(!purpose_is_specific(&["general,assistant".into()]));
        assert!(purpose_is_specific(&["Review unpaid invoices for the finance desk".into()]));
    }

    #[test]
    fn contract_digest_stable_for_same_content() {
        let p = MintPrincipalParams {
            api_pid: "agent_test",
            agent_name: "test",
            issuer: "cnktr:org:lab",
            model_ref: Some("gpt-test"),
            purpose: vec!["inspect".into()],
            capabilities: vec!["read".into()],
            namespace: "m/test",
            master_agent_id: None,
            geo_id: None,
            knowledge_base_id: None,
        };
        let c1 = compile_contract(&p);
        let c2 = compile_contract(&p);
        assert_eq!(c1.contract_digest_sha256, c2.contract_digest_sha256);
    }
}
