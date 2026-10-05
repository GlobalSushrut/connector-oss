use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::json;

use crate::{auth, state::SharedState};

const MASTER_KEY_FOLDER: &str = "settings_master_key";

#[derive(Debug, Deserialize)]
pub struct SelectMasterKeyRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct SecretTestRequest {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct IssuePluginHandleRequest {
    pub plugin_id: String,
    pub secret_id: String,
    pub agent_pid: String,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

pub async fn secrets_overview(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let (secret_count, handle_count) = {
        let ss = state.secret_store.lock().unwrap();
        (ss.secret_count(), ss.handle_count())
    };
    let audit = crate::services::secrets::audit_trail(State(state.clone()))
        .await
        .0;
    let vault = json!({
        "total_secrets": secret_count,
        "total_handles": handle_count,
        "status": "ok"
    });
    Json(json!({
        "ok": true,
        "categories": ["llm", "payments", "plugins", "integrations"],
        "masked_view": true,
        "vault": vault,
        "actions": {
            "store": "/api/v1/infra/vault/secrets",
            "resolve": "/api/v1/infra/vault/resolve",
            "rotate": "/api/v1/secrets/:id/rotate",
            "revoke": "/api/v1/secrets/:id",
            "audit": "/api/v1/secrets/audit"
        },
        "audit_summary": audit,
    }))
}

pub async fn master_key_options(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let current = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(MASTER_KEY_FOLDER, "selected")
            .ok()
            .flatten()
            .and_then(|v| {
                v.get("mode")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "os_keyring".to_string())
    };
    Json(json!({
        "ok": true,
        "current": current,
        "options": [
            {"id":"os_keyring","label":"OS keyring","default":true},
            {"id":"tpm","label":"TPM"},
            {"id":"cloud_kms","label":"Cloud KMS"}
        ]
    }))
}

pub async fn select_master_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SelectMasterKeyRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let mode = req.mode.trim().to_ascii_lowercase();
    if !["os_keyring", "tpm", "cloud_kms"].contains(&mode.as_str()) {
        return Json(json!({"ok": false, "error": "mode must be os_keyring|tpm|cloud_kms"}));
    }
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        MASTER_KEY_FOLDER,
        "selected",
        &json!({"mode": mode, "updated_at": chrono::Utc::now().to_rfc3339()}),
    );
    Json(json!({"ok": true, "mode": mode}))
}

pub async fn test_secret(
    headers: HeaderMap,
    Json(req): Json<SecretTestRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let kind = req.kind.trim().to_ascii_lowercase();
    let ok = match kind.as_str() {
        "llm" => req.value.len() > 16,
        "stripe" => req.value.starts_with("sk_"),
        _ => !req.value.trim().is_empty(),
    };
    Json(json!({
        "ok": true,
        "kind": kind,
        "passed": ok,
        "message": if ok { "Secret test passed" } else { "Secret format check failed" }
    }))
}

pub async fn issue_plugin_secret_handle(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<IssuePluginHandleRequest>,
) -> Json<serde_json::Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let plugin_id = req.plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let grant = crate::services::plugin_hub::load_grant(&state, &plugin_id);
    if !grant.granted.iter().any(|g| g == "secret.read") {
        return Json(json!({"ok": false, "error": "Plugin lacks granted capability secret.read"}));
    }
    let mut ss = state.secret_store.lock().unwrap();
    match ss.issue_handle(&req.secret_id, &req.agent_pid) {
        Ok(handle) => {
            if let Err(e) = crate::kernel::vault_seal::persist(&ss) {
                return Json(json!({"ok": false, "error": format!("vault_persist: {e}")}));
            }
            Json(json!({
            "ok": true,
            "plugin_id": plugin_id,
            "handle_id": handle.handle_id,
            "secret_id": handle.secret_id,
            "agent_pid": handle.agent_pid,
            "note": "Opaque handle issued. Plugin gets handle only; raw secret never returned."
        }))
        },
        Err(err) => Json(json!({"ok": false, "error": err})),
    }
}
