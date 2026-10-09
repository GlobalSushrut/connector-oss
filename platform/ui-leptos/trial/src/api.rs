use gloo_net::http::Request;
use gloo_storage::{LocalStorage, Storage};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub const BASE: &str = "/api/v1";

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API {} — {}", self.status, self.message)
    }
}

fn auth_header() -> Option<String> {
    LocalStorage::get::<String>("access_token").ok()
        .filter(|t| !t.is_empty())
        .map(|t| format!("Bearer {t}"))
}

pub async fn post_value(path: &str, body: Value) -> Result<Value, ApiError> {
    let url = format!("{BASE}{path}");
    let mut req = Request::post(&url)
        .header("Content-Type", "application/json");
    if let Some(auth) = auth_header() {
        req = req.header("Authorization", &auth);
    }
    let resp = req.body(body.to_string())
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?
        .send().await
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?;
    let status = resp.status();
    let raw: Value = resp.json().await
        .map_err(|e| ApiError { status, message: e.to_string() })?;
    if status >= 400 {
        let msg = raw["message"].as_str()
            .or_else(|| raw["error"].as_str())
            .unwrap_or("Request failed").to_string();
        return Err(ApiError { status, message: msg });
    }
    // Unwrap { ok, data } envelope — but only when a `data` field actually
    // exists. Some endpoints (e.g. /playground/session) return `ok` with the
    // payload fields at the top level.
    if raw.get("ok").is_some() && raw.get("data").is_some() {
        return Ok(raw["data"].clone());
    }
    Ok(raw)
}

pub async fn get<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    let url = format!("{BASE}{path}");
    let mut req = Request::get(&url);
    if let Some(auth) = auth_header() {
        req = req.header("Authorization", &auth);
    }
    let resp = req.send().await
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?;
    let status = resp.status();
    resp.json::<T>().await
        .map_err(|e| ApiError { status, message: e.to_string() })
}

pub async fn post<T: DeserializeOwned>(path: &str, body: Value) -> Result<T, ApiError> {
    let url = format!("{BASE}{path}");
    let mut req = Request::post(&url)
        .header("Content-Type", "application/json");
    if let Some(auth) = auth_header() {
        req = req.header("Authorization", &auth);
    }
    let resp = req.body(body.to_string())
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?
        .send().await
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?;
    let status = resp.status();
    resp.json::<T>().await
        .map_err(|e| ApiError { status, message: e.to_string() })
}

pub fn clear_tokens() {
    let _ = LocalStorage::delete("access_token");
    let _ = LocalStorage::delete("refresh_token");
}
