use leptos::prelude::*;
use gloo_storage::{LocalStorage, Storage};
use serde_json::Value;
use crate::api;

#[derive(Clone, Default, PartialEq)]
pub struct User {
    pub user_id: String,
    pub email:   String,
    pub name:    String,
    pub plan:    String,
}

#[derive(Clone, Default, PartialEq)]
pub struct AuthState {
    pub user:             Option<User>,
    pub is_authenticated: bool,
}

pub async fn fetch_me(set_auth: WriteSignal<AuthState>) {
    if LocalStorage::get::<String>("portal_token").unwrap_or_default().is_empty() { return; }
    if let Ok(v) = api::get_value("/me").await {
        if let Some(uid) = v["user_id"].as_str() {
            set_auth.set(AuthState {
                user: Some(User {
                    user_id: uid.to_string(),
                    email:   v["email"].as_str().unwrap_or("").to_string(),
                    name:    v["name"].as_str().unwrap_or("").to_string(),
                    plan:    v["tier"].as_str().unwrap_or("Community").to_string(),
                }),
                is_authenticated: true,
            });
        }
    }
}

pub async fn login(set_auth: WriteSignal<AuthState>, email: String, password: String, totp: Option<String>) -> Result<(), String> {
    let body = serde_json::json!({ "email": email, "password": password, "totp_code": totp });
    let data: Value = api::post_value("/login", body).await.map_err(|e| e.message)?;
    if let Some(err) = data["error"].as_str() { return Err(err.to_string()); }
    let token = data["access_token"].as_str().unwrap_or("").to_string();
    if token.is_empty() { return Err("No token returned".into()); }
    let _ = LocalStorage::set("portal_token", &token);
    fetch_me(set_auth).await;
    Ok(())
}

pub async fn register(
    set_auth: WriteSignal<AuthState>,
    name: String,
    email: String,
    password: String,
    license_key: Option<String>,
) -> Result<(), String> {
    let body = serde_json::json!({
        "name": name,
        "email": email,
        "password": password,
        "license_key": license_key,
    });
    let data: Value = api::post_value("/register", body).await.map_err(|e| e.message)?;
    if let Some(err) = data["error"].as_str() { return Err(err.to_string()); }
    let token = data["access_token"].as_str().unwrap_or("").to_string();
    if token.is_empty() { return Err("No token returned".into()); }
    let _ = LocalStorage::set("portal_token", &token);
    fetch_me(set_auth).await;
    Ok(())
}

pub fn logout(set_auth: WriteSignal<AuthState>) {
    let _ = LocalStorage::delete("portal_token");
    set_auth.set(AuthState::default());
}
