use leptos::prelude::*;
use gloo_storage::{LocalStorage, Storage};

#[derive(Clone, Default, PartialEq)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub key_hint:         String,
}

/// Check if a valid admin key exists in LocalStorage.
/// Only accepts keys with the `sk_admin_` prefix — no dev bypasses.
pub fn check_auth() -> AuthState {
    let key = LocalStorage::get::<String>("admin_api_key").unwrap_or_default();
    if key.starts_with("sk_admin_") && key.len() >= 20 {
        AuthState { is_authenticated: true, key_hint: format!("{}…", &key[..12]) }
    } else {
        // Clear any stale/invalid tokens
        if !key.is_empty() {
            let _ = LocalStorage::delete("admin_api_key");
        }
        AuthState::default()
    }
}

pub fn logout(set_auth: WriteSignal<AuthState>) {
    let _ = LocalStorage::delete("admin_api_key");
    set_auth.set(AuthState::default());
}
