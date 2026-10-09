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
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct AuthState {
    pub user: Option<User>,
    pub is_authenticated: bool,
}

fn store_tokens(access: &str, refresh: &str) {
    let _ = LocalStorage::set("access_token", access);
    let _ = LocalStorage::set("refresh_token", refresh);
}

fn value_to_user(data: &Value) -> Option<User> {
    Some(User {
        user_id: data["user_id"].as_str()?.to_string(),
        email:   data["email"].as_str().unwrap_or("").to_string(),
        name:    data["name"].as_str().unwrap_or("Operator").to_string(),
        role:    data["role"].as_str().unwrap_or("operator").to_string(),
    })
}

pub async fn login_with_api_key(
    set_auth: WriteSignal<AuthState>,
    key: String,
) -> Result<(), String> {
    // Set before the network round-trip so the dashboard auth gate sees a key
    // immediately on hard_redirect (avoids bounce back to /login).
    if key.starts_with("cpk_") {
        let _ = LocalStorage::set("api_key", &key);
    }
    let body = serde_json::json!({ "api_key": key });
    let data: Value = api::post_value("/auth/token", body).await
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
    let user = value_to_user(&data["user"])
        .or_else(|| value_to_user(&data))
        .unwrap_or_else(|| User {
            user_id: data["user_id"].as_str().unwrap_or("").to_string(),
            email:   data["email"].as_str().unwrap_or("").to_string(),
            name:    data["name"].as_str().unwrap_or("Operator").to_string(),
            role:    data["role"].as_str().unwrap_or("operator").to_string(),
        });
    set_auth.set(AuthState { user: Some(user), is_authenticated: true });
    Ok(())
}

pub async fn fetch_me(set_auth: WriteSignal<AuthState>) {
    match api::get::<Value>("/auth/me").await {
        Ok(data) if data["user_id"].is_string() => {
            if let Some(user) = value_to_user(&data) {
                set_auth.set(AuthState { user: Some(user), is_authenticated: true });
            }
        }
        _ => {
            api::clear_tokens();
            set_auth.set(AuthState::default());
        }
    }
}
