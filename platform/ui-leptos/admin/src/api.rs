use gloo_net::http::Request;
use gloo_storage::{LocalStorage, Storage};
use serde_json::Value;

const BASE: &str = "/api/v1";

#[derive(Debug, Clone)]
pub struct ApiError { pub message: String }

pub async fn get_value(path: &str) -> Result<Value, ApiError> {
    let key = LocalStorage::get::<String>("admin_api_key").unwrap_or_default();
    Request::get(&format!("{BASE}{path}"))
        .header("X-API-Key", &key)
        .send().await
        .map_err(|e| ApiError { message: e.to_string() })?
        .json::<Value>().await
        .map_err(|e| ApiError { message: e.to_string() })
}

/// POST /api/v1/admin/auth — authenticate with email + password, get admin_key back
pub async fn post_admin_login(email: &str, password: &str) -> Result<Value, ApiError> {
    let body = serde_json::json!({ "email": email, "password": password });
    let resp = Request::post(&format!("{BASE}/admin/auth"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| ApiError { message: e.to_string() })?
        .send().await
        .map_err(|e| ApiError { message: e.to_string() })?;
    if resp.status() == 401 || resp.status() == 403 {
        return Err(ApiError { message: "Invalid email or password.".into() });
    }
    resp.json::<Value>().await.map_err(|e| ApiError { message: e.to_string() })
}

pub async fn post_value(path: &str, body: Value) -> Result<Value, ApiError> {
    let key = LocalStorage::get::<String>("admin_api_key").unwrap_or_default();
    Request::post(&format!("{BASE}{path}"))
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| ApiError { message: e.to_string() })?
        .send().await
        .map_err(|e| ApiError { message: e.to_string() })?
        .json::<Value>().await
        .map_err(|e| ApiError { message: e.to_string() })
}
