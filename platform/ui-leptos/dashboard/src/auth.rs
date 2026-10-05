use leptos::prelude::*;
use gloo_storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::api;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub totp_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct AuthState {
    pub user: Option<User>,
    pub is_authenticated: bool,
}

impl AuthState {
    #[allow(dead_code)]
    pub fn has_min_role(&self, role: &str) -> bool {
        let rank = |r: &str| match r {
            "viewer" => 1, "developer" => 2, "operator" => 3, "admin" => 4, "super_admin" => 5, _ => 0,
        };
        let user_rank = self.user.as_ref().map(|u| rank(&u.role)).unwrap_or(0);
        user_rank >= rank(role)
    }

    #[allow(dead_code)]
    pub fn has_permission(&self, perm: &str) -> bool {
        self.user.as_ref()
            .map(|u| u.permissions.iter().any(|p| p == perm))
            .unwrap_or(false)
    }
}

fn store_tokens(access: &str, refresh: &str) {
    let _ = LocalStorage::set("access_token", access);
    let _ = LocalStorage::set("refresh_token", refresh);
}

/// True when the browser likely has a playground session (used to avoid a
/// blank frame while bootstrap_session runs).
pub fn has_local_session() -> bool {
    let key = LocalStorage::get::<String>("api_key")
        .or_else(|_| LocalStorage::get::<String>("trial_api_key"))
        .unwrap_or_default();
    if key.starts_with("cpk_") {
        return true;
    }
    LocalStorage::get::<String>("access_token")
        .ok()
        .filter(|t| t.contains('.'))
        .is_some()
}

fn user_from_response(data: &Value) -> Option<User> {
    value_to_user(data)
        .or_else(|| value_to_user(api::resource_object(data)))
}

/// Exchange api_key for JWT, then validate via /auth/me. Returns true on success.
pub async fn bootstrap_session(set_auth: WriteSignal<AuthState>) -> bool {
    if let Ok(key) = LocalStorage::get::<String>("api_key") {
        if key.starts_with("cpk_") {
            if login_with_api_key(set_auth, key).await.is_ok() {
                return true;
            }
        }
    } else if let Ok(key) = LocalStorage::get::<String>("trial_api_key") {
        if key.starts_with("cpk_") {
            if login_with_api_key(set_auth, key).await.is_ok() {
                return true;
            }
        }
    }

    match api::get_value("/auth/me").await {
        Ok(data) if data.get("error").is_none() => {
            if let Some(user) = user_from_response(&data) {
                set_auth.set(AuthState { user: Some(user), is_authenticated: true });
                return true;
            }
        }
        _ => {}
    }

    logout(set_auth);
    false
}

pub fn redirect_to_trial_login() {
    if let Some(w) = web_sys::window() {
        let path = w.location().pathname().unwrap_or_default();
        let search = w.location().search().unwrap_or_default();
        let next = format!("{path}{search}");
        let dest = if next.len() > 1 {
            format!("/login?next={}", js_sys::encode_uri_component(&next))
        } else {
            "/login".to_string()
        };
        let _ = w.location().set_href(&dest);
    }
}

fn value_to_user(data: &Value) -> Option<User> {
    Some(User {
        user_id:      data["user_id"].as_str()?.to_string(),
        email:        data["email"].as_str().unwrap_or("").to_string(),
        name:         data["name"].as_str().unwrap_or("").to_string(),
        role:         data["role"].as_str().unwrap_or("viewer").to_string(),
        permissions:  data["permissions"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        totp_enabled: data["totp_enabled"].as_bool().unwrap_or(false),
    })
}

/// Email + password login. Currently only consumed by `dev_bypass` (gated
/// behind the `dev-bypass` Cargo feature). Kept available for future
/// portal-style email/password flows.
#[allow(dead_code)]
pub async fn login(
    set_auth: WriteSignal<AuthState>,
    email: String,
    password: String,
    totp_code: Option<String>,
) -> Result<(), String> {
    let mut body = serde_json::json!({ "email": email, "password": password });
    if let Some(code) = totp_code {
        body["totp_code"] = Value::String(code);
    }
    let data: Value = api::post("/auth/login", body).await
        .map_err(|e| e.message.clone())?;
    if let Some(err) = data["error"].as_str() {
        return Err(err.to_string());
    }
    let access  = data["access_token"].as_str().unwrap_or("").to_string();
    let refresh = data["refresh_token"].as_str().unwrap_or("").to_string();
    store_tokens(&access, &refresh);
    if let Some(user) = value_to_user(&data["user"]).or_else(|| value_to_user(&data)) {
        set_auth.set(AuthState { user: Some(user), is_authenticated: true });
        Ok(())
    } else {
        Err("Login failed: no user in response".into())
    }
}

/// Login with a cpk_... API key — the ONLY login method on the operator dashboard
pub async fn login_with_api_key(
    set_auth: WriteSignal<AuthState>,
    key: String,
) -> Result<(), String> {
    if key.starts_with("cpk_") {
        let _ = LocalStorage::set("api_key", &key);
    }
    let body = serde_json::json!({ "api_key": key });
    let data: Value = api::post("/auth/token", body).await
        .map_err(|e| e.message.clone())?;
    if let Some(err) = data["error"].as_str() {
        return Err(err.to_string());
    }
    let access  = data["access_token"].as_str().unwrap_or("").to_string();
    let refresh = data["refresh_token"].as_str().unwrap_or("").to_string();
    if access.is_empty() {
        return Err("No access token returned".into());
    }
    store_tokens(&access, &refresh);
    let _ = LocalStorage::set("api_key", &key);
    if let Some(tid) = data["tenant_id"].as_str().filter(|s| !s.is_empty()) {
        let _ = LocalStorage::set("tenant_id", tid);
    }
    // Build user from response fields
    let user = value_to_user(&data["user"])
        .or_else(|| value_to_user(&data))
        .unwrap_or_else(|| User {
            user_id: data["user_id"].as_str().unwrap_or("").to_string(),
            email:   data["email"].as_str().unwrap_or("").to_string(),
            name:    data["name"].as_str().unwrap_or("Operator").to_string(),
            role:    data["role"].as_str().unwrap_or("operator").to_string(),
            permissions: vec![],
            totp_enabled: false,
        });
    set_auth.set(AuthState { user: Some(user), is_authenticated: true });
    Ok(())
}

pub async fn fetch_me(set_auth: WriteSignal<AuthState>) {
    let _ = bootstrap_session(set_auth).await;
}

/// Developer-only authentication shortcut.
///
/// Only compiled when the `dev-bypass` Cargo feature is enabled. Production
/// builds (`trunk build --release` without features) cannot call this — the
/// symbol does not exist in the binary. See `dashboard/Cargo.toml::[features]`.
///
/// Phase 5.2 — even when the feature is compiled in, this function
/// **refuses to run** if the live server reports `mode == "playground"`.
/// Playground sessions are hosted demos; a dev-bypass auto-login would
/// hand out an operator session to anonymous visitors. We pre-flight
/// `GET /api/v1/deployment/info` and bail with a console warning if
/// we're talking to a Playground server.
#[cfg(feature = "dev-bypass")]
pub async fn dev_bypass(set_auth: WriteSignal<AuthState>) {
    // Pre-flight: refuse to run against a Playground server even when
    // the dev-bypass feature was compiled in by mistake.
    if let Ok(info) = api::get::<Value>("/deployment/info").await {
        if info.get("mode").and_then(|v| v.as_str()) == Some("playground") {
            web_sys::console::warn_1(
                &"dev_bypass(): refusing to run against a Playground deployment".into(),
            );
            return;
        }
    }

    let email = "dev@connector.local";
    let password = "Dev@bypass1!";
    // Always call signup first: in ultimate-free mode this upgrades an existing
    // Viewer account to Operator in-place (409 conflict is expected + silently handled).
    let _ = api::post::<Value>("/auth/signup",
        serde_json::json!({"name":"Dev","email":email,"password":password})).await;
    if login(set_auth, email.into(), password.into(), None).await.is_ok() { return; }
    // Last resort — offline dev token with operator role
    let _ = LocalStorage::set("access_token", "dev-token");
    set_auth.set(AuthState {
        user: Some(User {
            user_id: "dev".into(), email: email.into(), name: "Dev".into(),
            role: "operator".into(), permissions: vec![], totp_enabled: false,
        }),
        is_authenticated: true,
    });
}

pub fn logout(set_auth: WriteSignal<AuthState>) {
    api::clear_tokens();
    set_auth.set(AuthState::default());
    // Navigation handled by <Redirect> in main.rs Show fallback — no hard reload needed
}
