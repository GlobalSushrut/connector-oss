//! Every agent has its own Keycloak account: a name and a password, like a Linux user.
//!
//! Connector creates the account when the agent is registered and returns the password once.
//! The password is never stored here. The agent signs in to Keycloak itself and presents
//! that access token; Connector checks it against Keycloak's keys and against this record.
//! Cease, pause, and stop refuse the agent's tokens at once, then disable the account and
//! end its Keycloak sessions. An operator turns the account back on explicitly.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};

use crate::state::SharedState;

pub const FOLDER: &str = "agent_keycloak";

#[derive(Clone)]
struct Config {
    base: String,
    realm: String,
    admin_client_id: String,
    admin_client_secret: String,
    agent_client_id: String,
    insecure_tls: bool,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn config() -> Option<Config> {
    Some(Config {
        base: env("CONNECTOR_KEYCLOAK_URL")?.trim_end_matches('/').to_string(),
        realm: env("CONNECTOR_KEYCLOAK_REALM").unwrap_or_else(|| "connector".into()),
        admin_client_id: env("CONNECTOR_KEYCLOAK_ADMIN_CLIENT_ID")?,
        admin_client_secret: env("CONNECTOR_KEYCLOAK_ADMIN_CLIENT_SECRET")?,
        agent_client_id: env("CONNECTOR_KEYCLOAK_AGENT_CLIENT_ID")?,
        insecure_tls: !crate::connector_profile::is_productionish_env()
            && env("CONNECTOR_SSO_INSECURE_TLS")
                .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false),
    })
}

pub fn configured() -> bool {
    config().is_some()
}

impl Config {
    fn token_url(&self) -> String {
        format!("{}/realms/{}/protocol/openid-connect/token", self.base, self.realm)
    }
    fn users_url(&self) -> String {
        format!("{}/admin/realms/{}/users", self.base, self.realm)
    }
    fn client(&self) -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(self.insecure_tls)
            .build()
            .map_err(|e| format!("keycloak_http_client:{e}"))
    }
    async fn admin_token(&self, client: &reqwest::Client) -> Result<String, String> {
        let resp = client
            .post(self.token_url())
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.admin_client_id.as_str()),
                ("client_secret", self.admin_client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("keycloak_admin_token:{e}"))?;
        if !resp.status().is_success() {
            return Err(format!("keycloak_admin_token_http_{}", resp.status().as_u16()));
        }
        let body: Value = resp.json().await.map_err(|e| format!("keycloak_admin_token:{e}"))?;
        body.get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| "keycloak_admin_token_missing".into())
    }
}

fn random_password() -> String {
    use rand::Rng;
    const SET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24).map(|_| SET[rng.gen_range(0..SET.len())] as char).collect()
}

fn username_for(name: &str, api_pid: &str) -> String {
    let mut slug: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-');
    let slug: String = slug.chars().take(32).collect();
    let tail: String = api_pid.chars().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
    if slug.is_empty() {
        format!("agent-{tail}")
    } else {
        format!("agent-{slug}-{tail}")
    }
}

/// Agent record key. Accepts the API pid, or a kernel pid via `agent_pid_map`.
fn record_key(state: &SharedState, pid: &str) -> Option<(String, Value)> {
    let mut es = state.engine_store.lock().ok()?;
    if let Ok(Some(v)) = es.folder_get(FOLDER, pid) {
        return Some((pid.to_string(), v));
    }
    let api_pid = es
        .folder_get("agent_pid_map", pid)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(String::from))?;
    let v = es.folder_get(FOLDER, &api_pid).ok().flatten()?;
    Some((api_pid, v))
}

fn put_record(state: &SharedState, api_pid: &str, record: &Value) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(FOLDER, api_pid, record);
    }
}

fn public_view(record: &Value) -> Value {
    json!({
        "username": record.get("username"),
        "status": record.get("status"),
        "keycloak_enabled": record.get("keycloak_enabled"),
        "created_at": record.get("created_at"),
        "status_changed_at": record.get("status_changed_at"),
        "last_error": record.get("last_error"),
    })
}

fn sign_in_hint(cfg: &Config, username: &str) -> Value {
    json!({
        "token_url": cfg.token_url(),
        "client_id": cfg.agent_client_id,
        "grant_type": "password",
        "username": username,
        "then": "Send the access_token as Authorization: Bearer to GET /api/v1/agent/me and to effect requests.",
    })
}

async fn set_password(
    cfg: &Config,
    client: &reqwest::Client,
    admin: &str,
    user_id: &str,
    password: &str,
) -> Result<(), String> {
    let resp = client
        .put(format!("{}/{user_id}/reset-password", cfg.users_url()))
        .bearer_auth(admin)
        .json(&json!({"type": "password", "value": password, "temporary": false}))
        .send()
        .await
        .map_err(|e| format!("keycloak_set_password:{e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("keycloak_set_password_http_{}", resp.status().as_u16()))
    }
}

async fn find_user_id(
    cfg: &Config,
    client: &reqwest::Client,
    admin: &str,
    username: &str,
) -> Result<Option<String>, String> {
    let resp = client
        .get(cfg.users_url())
        .bearer_auth(admin)
        .query(&[("username", username), ("exact", "true")])
        .send()
        .await
        .map_err(|e| format!("keycloak_find_user:{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("keycloak_find_user_http_{}", resp.status().as_u16()));
    }
    let list: Value = resp.json().await.map_err(|e| format!("keycloak_find_user:{e}"))?;
    Ok(list
        .as_array()
        .and_then(|a| a.first())
        .and_then(|u| u.get("id"))
        .and_then(|v| v.as_str())
        .map(String::from))
}

async fn set_enabled(
    cfg: &Config,
    client: &reqwest::Client,
    admin: &str,
    user_id: &str,
    enabled: bool,
) -> Result<(), String> {
    let resp = client
        .put(format!("{}/{user_id}", cfg.users_url()))
        .bearer_auth(admin)
        .json(&json!({"enabled": enabled}))
        .send()
        .await
        .map_err(|e| format!("keycloak_set_enabled:{e}"))?;
    if !resp.status().is_success() {
        return Err(format!("keycloak_set_enabled_http_{}", resp.status().as_u16()));
    }
    if !enabled {
        let resp = client
            .post(format!("{}/{user_id}/logout", cfg.users_url()))
            .bearer_auth(admin)
            .send()
            .await
            .map_err(|e| format!("keycloak_logout:{e}"))?;
        if !resp.status().is_success() {
            return Err(format!("keycloak_logout_http_{}", resp.status().as_u16()));
        }
    }
    Ok(())
}

/// Create the agent's Keycloak account. The returned `password` is the only copy.
pub async fn provision(state: &SharedState, api_pid: &str, name: &str) -> Value {
    let Some(cfg) = config() else {
        return json!({
            "configured": false,
            "detail": "Keycloak agent accounts are not configured on this node. First boot writes CONNECTOR_KEYCLOAK_*.",
        });
    };
    let username = username_for(name, api_pid);
    let password = random_password();
    let result: Result<String, String> = async {
        let client = cfg.client()?;
        let admin = cfg.admin_token(&client).await?;
        let resp = client
            .post(cfg.users_url())
            .bearer_auth(&admin)
            .json(&json!({
                "username": username,
                "enabled": true,
                "email": format!("{username}@agents.connector.local"),
                "emailVerified": true,
                "firstName": name,
                "lastName": "agent",
                "requiredActions": [],
                "attributes": {"connector_agent_pid": [api_pid]},
            }))
            .send()
            .await
            .map_err(|e| format!("keycloak_create_user:{e}"))?;
        if !resp.status().is_success() && resp.status().as_u16() != 409 {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "keycloak_create_user_http_{status}:{}",
                body.chars().take(160).collect::<String>()
            ));
        }
        let user_id = find_user_id(&cfg, &client, &admin, &username)
            .await?
            .ok_or("keycloak_user_not_found_after_create")?;
        set_password(&cfg, &client, &admin, &user_id, &password).await?;
        Ok(user_id)
    }
    .await;
    match result {
        Ok(user_id) => {
            let now = chrono::Utc::now().to_rfc3339();
            let record = json!({
                "schema": "connector.agent_keycloak.v1",
                "api_pid": api_pid,
                "username": username,
                "keycloak_user_id": user_id,
                "status": "active",
                "keycloak_enabled": true,
                "created_at": now,
                "status_changed_at": now,
                "password_stored": false,
            });
            put_record(state, api_pid, &record);
            crate::substrate::cvr::deployment_verify::record_operation_success(
                state.as_ref(),
                "iam",
                "agent_account_created",
                json!({"api_pid": api_pid, "username": username, "password_stored": false}),
            );
            json!({
                "configured": true,
                "ok": true,
                "username": username,
                "password": password,
                "shown_once": true,
                "sign_in": sign_in_hint(&cfg, &username),
            })
        }
        Err(error) => json!({"configured": true, "ok": false, "error": error}),
    }
}

/// Cease, pause, and stop. The local refusal is immediate; Keycloak is updated in the background.
pub fn on_cease(state: &SharedState, pid: &str, reason: &str) {
    let Some((api_pid, mut record)) = record_key(state, pid) else { return };
    if record.get("status").and_then(|v| v.as_str()) == Some("ceased") {
        return;
    }
    record["status"] = json!("ceased");
    record["status_reason"] = json!(reason);
    record["status_changed_at"] = json!(chrono::Utc::now().to_rfc3339());
    put_record(state, &api_pid, &record);

    let (Some(cfg), Some(user_id)) = (
        config(),
        record.get("keycloak_user_id").and_then(|v| v.as_str()).map(String::from),
    ) else {
        return;
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    let state = state.clone();
    handle.spawn(async move {
        let outcome: Result<(), String> = async {
            let client = cfg.client()?;
            let admin = cfg.admin_token(&client).await?;
            set_enabled(&cfg, &client, &admin, &user_id, false).await
        }
        .await;
        if let Some((key, mut rec)) = record_key(&state, &api_pid) {
            match &outcome {
                Ok(()) => {
                    rec["keycloak_enabled"] = json!(false);
                    rec["last_error"] = Value::Null;
                    crate::substrate::cvr::deployment_verify::record_operation_success(
                        state.as_ref(),
                        "iam",
                        "agent_account_disabled",
                        json!({"api_pid": key, "sessions_ended": true}),
                    );
                }
                Err(e) => rec["last_error"] = json!(e),
            }
            put_record(&state, &key, &rec);
        }
    });
}

/// Agent self-check: the bearer must be a Keycloak access token for this agent's account.
pub async fn verify_agent_bearer(state: &SharedState, headers: &HeaderMap) -> Result<(String, Value), Value> {
    let Some(cfg) = config() else {
        return Err(json!({"error": "agent_accounts_not_configured", "status": 503}));
    };
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return Err(json!({"error": "agent_token_required", "status": 401}));
    }
    let claims = crate::auth::verify_idp_access_token(token, &cfg.agent_client_id)
        .await
        .map_err(|e| json!({"error": "agent_token_invalid", "detail": e, "status": 401}))?;
    let api_pid = claims
        .get("connector_agent_pid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json!({"error": "agent_token_has_no_agent", "status": 403}))?
        .to_string();
    let Some((_, record)) = record_key(state, &api_pid) else {
        return Err(json!({"error": "agent_account_unknown", "status": 403}));
    };
    if record.get("status").and_then(|v| v.as_str()) != Some("active") {
        return Err(json!({
            "error": "agent_account_ceased",
            "detail": "Connector refuses this agent's tokens until an operator turns the account back on.",
            "status": 403,
        }));
    }
    let username = claims.get("preferred_username").and_then(|v| v.as_str());
    if username != record.get("username").and_then(|v| v.as_str()) {
        return Err(json!({"error": "agent_token_username_mismatch", "status": 403}));
    }
    Ok((api_pid, record))
}

/// GET /agent/me — an agent asks who it is, with its own Keycloak token.
pub async fn agent_me(State(state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    match verify_agent_bearer(&state, &headers).await {
        Ok((api_pid, record)) => Json(json!({
            "ok": true,
            "agent_pid": api_pid,
            "username": record.get("username"),
            "status": record.get("status"),
            "verified_by": "keycloak_jwks",
        })),
        Err(body) => Json(body),
    }
}

/// GET /agents/:pid/identity — operator view. Never contains a password.
pub async fn get_identity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if let Err(v) = crate::services::intelligence_authority::require_lifecycle_actor(&headers, 3) {
        return Json(v);
    }
    let (_, api_pid) = crate::services::agents::resolve_kernel_pid_pub(&state, &pid);
    match record_key(&state, &api_pid) {
        Some((key, record)) => Json(json!({
            "ok": true,
            "agent_pid": key,
            "configured": configured(),
            "account": public_view(&record),
        })),
        None => Json(json!({"ok": true, "agent_pid": api_pid, "configured": configured(), "account": null})),
    }
}

/// POST /agents/:pid/identity/rotate — new password, shown once. Creates the account if it is missing.
pub async fn rotate_identity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if let Err(v) = crate::services::intelligence_authority::require_lifecycle_actor(&headers, 4) {
        return Json(v);
    }
    let (_, api_pid) = crate::services::agents::resolve_kernel_pid_pub(&state, &pid);
    let Some((key, record)) = record_key(&state, &api_pid) else {
        let name = state
            .engine_store
            .lock()
            .ok()
            .and_then(|mut es| es.folder_get("agent_meta", &api_pid).ok().flatten())
            .and_then(|m| m.get("name").and_then(|v| v.as_str()).map(String::from));
        let Some(name) = name else {
            return Json(json!({"ok": false, "error": "agent_not_found", "status": 404}));
        };
        return Json(provision(&state, &api_pid, &name).await);
    };
    let Some(cfg) = config() else {
        return Json(json!({"ok": false, "error": "agent_accounts_not_configured", "status": 503}));
    };
    let username = record.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let user_id = record.get("keycloak_user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let password = random_password();
    let outcome: Result<(), String> = async {
        let client = cfg.client()?;
        let admin = cfg.admin_token(&client).await?;
        set_password(&cfg, &client, &admin, &user_id, &password).await
    }
    .await;
    match outcome {
        Ok(()) => {
            let mut rec = record.clone();
            rec["password_rotated_at"] = json!(chrono::Utc::now().to_rfc3339());
            put_record(&state, &key, &rec);
            Json(json!({
                "ok": true,
                "username": username,
                "password": password,
                "shown_once": true,
                "sign_in": sign_in_hint(&cfg, &username),
            }))
        }
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// POST /agents/:pid/identity/enable — an operator turns a ceased account back on.
pub async fn enable_identity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    let (user_id_actor, _) =
        match crate::services::intelligence_authority::require_lifecycle_actor(&headers, 4) {
            Ok(c) => c,
            Err(v) => return Json(v),
        };
    let (_, api_pid) = crate::services::agents::resolve_kernel_pid_pub(&state, &pid);
    let Some((key, mut record)) = record_key(&state, &api_pid) else {
        return Json(json!({"ok": false, "error": "agent_account_unknown", "status": 404}));
    };
    let Some(cfg) = config() else {
        return Json(json!({"ok": false, "error": "agent_accounts_not_configured", "status": 503}));
    };
    let user_id = record.get("keycloak_user_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let outcome: Result<(), String> = async {
        let client = cfg.client()?;
        let admin = cfg.admin_token(&client).await?;
        set_enabled(&cfg, &client, &admin, &user_id, true).await
    }
    .await;
    if let Err(e) = outcome {
        return Json(json!({"ok": false, "error": e}));
    }
    record["status"] = json!("active");
    record["keycloak_enabled"] = json!(true);
    record["status_reason"] = json!(format!("enabled_by:{user_id_actor}"));
    record["status_changed_at"] = json!(chrono::Utc::now().to_rfc3339());
    record["last_error"] = Value::Null;
    put_record(&state, &key, &record);
    Json(json!({"ok": true, "agent_pid": key, "account": public_view(&record)}))
}

/// Terminate removes the Keycloak account.
pub async fn remove(state: &SharedState, pid: &str) {
    let Some((api_pid, mut record)) = record_key(state, pid) else { return };
    record["status"] = json!("removed");
    record["status_changed_at"] = json!(chrono::Utc::now().to_rfc3339());
    put_record(state, &api_pid, &record);
    let (Some(cfg), Some(user_id)) = (
        config(),
        record.get("keycloak_user_id").and_then(|v| v.as_str()).map(String::from),
    ) else {
        return;
    };
    let outcome: Result<(), String> = async {
        let client = cfg.client()?;
        let admin = cfg.admin_token(&client).await?;
        let resp = client
            .delete(format!("{}/{user_id}", cfg.users_url()))
            .bearer_auth(&admin)
            .send()
            .await
            .map_err(|e| format!("keycloak_delete_user:{e}"))?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("keycloak_delete_user_http_{}", resp.status().as_u16()))
        }
    }
    .await;
    if let Err(e) = outcome {
        record["last_error"] = json!(e);
        put_record(state, &api_pid, &record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_linux_like_and_unique_per_pid() {
        assert_eq!(username_for("Billing Bot!", "agent_0123456789abcdef"), "agent-billing-bot-abcdef");
        assert_eq!(username_for("***", "agent_aa11bb22cc33"), "agent-22cc33");
        assert_ne!(
            username_for("same", "agent_000000000001"),
            username_for("same", "agent_000000000002")
        );
    }

    #[test]
    fn passwords_are_long_and_varied() {
        let a = random_password();
        let b = random_password();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
    }
}
