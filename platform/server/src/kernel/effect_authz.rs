//! Effect authorization mint/verify — platform adapter over connector-trust schemas.
//! Seven Pillars §3: signed exact-action artifacts; last-mile re-verify.

use std::time::{SystemTime, UNIX_EPOCH};

use connector_trust::{EffectAuthorizationV1, EFFECT_AUTHORIZATION_SCHEMA};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::kernel::action_binding::ActionBinding;
use crate::state::PlatformState;

type HmacSha256 = Hmac<Sha256>;

const NONCE_FOLDER: &str = "effect_authz_nonce_v1";
const INVALIDATE_FOLDER: &str = "effect_authz_invalidate_v1";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn node_id(_state: &PlatformState) -> String {
    std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "node-local".into())
}

fn signing_key(_state: &PlatformState) -> Vec<u8> {
    for key in [
        "CONNECTOR_EFFECT_AUTHZ_HMAC",
        "CONNECTOR_AUDIT_HMAC_SECRET",
        "CONNECTOR_AUDIT_HMAC_KEY",
    ] {
        if let Ok(s) = std::env::var(key) {
            if !s.trim().is_empty() {
                return s.into_bytes();
            }
        }
    }
    if crate::connector_profile::is_productionish_env() {
        panic!(
            "effect authz: CONNECTOR_EFFECT_AUTHZ_HMAC (or CONNECTOR_AUDIT_HMAC_KEY) required under production / defense-strict; refusing hardcoded lab key"
        );
    }
    tracing::warn!("effect authz: using lab-only HMAC key (set CONNECTOR_EFFECT_AUTHZ_HMAC for real deployments)");
    b"connector-effect-authz-dev-key".to_vec()
}

fn sign_digest(key: &[u8], digest_hex: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(key).unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").expect("hmac"));
    mac.update(digest_hex.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_sig(key: &[u8], digest_hex: &str, signature: &str) -> bool {
    sign_digest(key, digest_hex) == signature
}

/// Project ActionBinding into EffectAuthorization and sign it.
pub fn mint_from_action_binding(
    state: &PlatformState,
    binding: &ActionBinding,
    character_hash: Option<String>,
    contract_hash: Option<String>,
    grant_id: Option<String>,
    hitl_approval_ref: Option<String>,
    quantum_id: Option<String>,
    ttl_secs: u64,
) -> EffectAuthorizationV1 {
    let now = now_unix();
    let principal = binding
        .principal_id
        .clone()
        .unwrap_or_else(|| format!("agent:{}", binding.agent_pid));
    let mut authz = EffectAuthorizationV1 {
        schema: EFFECT_AUTHORIZATION_SCHEMA.into(),
        principal_id: principal,
        node_id: node_id(state),
        agent_pid: binding.agent_pid.clone(),
        address: binding.target.resource.clone(),
        operation: binding.operation.clone(),
        parameters_canonical: binding.parameters.clone(),
        character_hash,
        contract_hash: contract_hash.or_else(|| binding.contract_digest.clone()),
        policy_version: binding.policy_version.clone(),
        grant_id,
        hitl_approval_ref,
        nonce: Uuid::new_v4().to_string(),
        issued_at_unix: now,
        expires_at_unix: now.saturating_add(ttl_secs.max(30)),
        quantum_id,
        signer_key_id: "node-hmac-v1".into(),
        digest_hex: String::new(),
        signature: String::new(),
    };
    authz.digest_hex = authz.compute_digest_hex();
    authz.signature = sign_digest(&signing_key(state), &authz.digest_hex);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            NONCE_FOLDER,
            &authz.nonce,
            &serde_json::json!({ "expires_at_unix": authz.expires_at_unix, "spent": false }),
        );
    }
    authz
}

/// Verify digest, signature, expiry, and single-use nonce. Marks nonce spent.
pub fn verify_and_consume(
    state: &PlatformState,
    authz: &EffectAuthorizationV1,
) -> Result<(), String> {
    if !authz.digest_matches() {
        return Err("effect_authorization_digest_mismatch".into());
    }
    if authz.is_expired(now_unix()) {
        return Err("effect_authorization_expired".into());
    }
    if !verify_sig(&signing_key(state), &authz.digest_hex, &authz.signature) {
        return Err("effect_authorization_signature_invalid".into());
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("store_lock:{e}"))?;
    if let Ok(Some(v)) = es.folder_get(NONCE_FOLDER, &authz.nonce) {
        if v.get("spent").and_then(|x| x.as_bool()) == Some(true) {
            return Err("effect_authorization_nonce_replay".into());
        }
    }
    let _ = es.folder_put(
        NONCE_FOLDER,
        &authz.nonce,
        &serde_json::json!({
            "spent": true,
            "expires_at_unix": authz.expires_at_unix,
            "digest": authz.digest_hex,
        }),
    );
    Ok(())
}

/// Last-mile re-verify before credential materialization / adapter open.
pub fn assert_valid_for_effect(
    state: &PlatformState,
    authz: &EffectAuthorizationV1,
    address: &str,
    operation: &str,
    parameters: &serde_json::Value,
) -> Result<(), String> {
    verify_and_consume(state, authz)?;
    if authz.address != address {
        return Err("effect_authorization_address_mismatch".into());
    }
    if authz.operation != operation {
        return Err("effect_authorization_operation_mismatch".into());
    }
    let mut probe = authz.clone();
    probe.parameters_canonical = parameters.clone();
    if probe.compute_digest_hex() != authz.digest_hex {
        return Err("effect_authorization_parameters_tampered".into());
    }
    Ok(())
}

/// Invalidate outstanding authz markers when character/contract changes.
pub fn invalidate_on_identity_change(state: &PlatformState, agent_pid: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            INVALIDATE_FOLDER,
            agent_pid,
            &serde_json::json!({
                "invalidated_at_unix": now_unix(),
                "reason": "character_or_contract_change",
            }),
        );
    }
    crate::substrate::atomic_revoke::revoke_agent_authority(
        state,
        agent_pid,
        "character_or_contract_change",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tampered_params_change_digest() {
        let mut a = EffectAuthorizationV1 {
            schema: EFFECT_AUTHORIZATION_SCHEMA.into(),
            principal_id: "p".into(),
            node_id: "n".into(),
            agent_pid: "a".into(),
            address: "r".into(),
            operation: "op".into(),
            parameters_canonical: serde_json::json!({"x": 1}),
            character_hash: None,
            contract_hash: None,
            policy_version: "1".into(),
            grant_id: None,
            hitl_approval_ref: None,
            nonce: "n1".into(),
            issued_at_unix: 1,
            expires_at_unix: u64::MAX,
            quantum_id: None,
            signer_key_id: "k".into(),
            digest_hex: String::new(),
            signature: String::new(),
        };
        a.digest_hex = a.compute_digest_hex();
        let mut probe = a.clone();
        probe.parameters_canonical = serde_json::json!({"x": 2});
        assert_ne!(probe.compute_digest_hex(), a.digest_hex);
    }
}
