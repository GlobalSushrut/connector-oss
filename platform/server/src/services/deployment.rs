//! Deployment metadata service.
//!
//! Exposes `GET /api/v1/deployment/info` — a small, public-safe blob that
//! tells the Leptos dashboard which distribution it is rendering against:
//!
//! - `playground`  → vendor-hosted SaaS trial (`try.cnktros.com`,
//!   `CONNECTOR_PRESET=playground`). The UI surfaces the countdown timer,
//!   conversion CTAs, and the playground-only wizards.
//! - `self_hosted` → tarball / Compose install (`install.sh`). The UI
//!   surfaces the full operator dashboard, real admin pages, no countdown.
//!
//! This endpoint is the single chokepoint that every later phase (wizards,
//! countdown, conversion, admin gating) reads at boot. It must remain
//! intentionally tiny and side-effect-free.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::{PlatformState, SharedState};

/// Server-visible deployment mode.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    Playground,
    SelfHosted,
}

impl DeploymentMode {
    pub fn from_env() -> Self {
        // CONNECTOR_PRESET=playground / trial / saas-trial all flip the
        // playground flag in apply_preset_from_env. Reading the resolved
        // flag (rather than the raw preset string) means anyone setting
        // CONNECTOR_PLAYGROUND=1 directly also lands here.
        if crate::services::playground::is_playground_mode() {
            DeploymentMode::Playground
        } else {
            DeploymentMode::SelfHosted
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentMode::Playground => "playground",
            DeploymentMode::SelfHosted => "self_hosted",
        }
    }

    pub fn edition(&self, license_tier: &str) -> &'static str {
        match self {
            DeploymentMode::Playground => "playground",
            DeploymentMode::SelfHosted => match license_tier.to_ascii_lowercase().as_str() {
                "enterprise" | "ent" => "enterprise",
                _ => "community",
            },
        }
    }
}

fn public_url(mode: DeploymentMode) -> String {
    if let Ok(v) = std::env::var("CONNECTOR_PUBLIC_URL") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    match mode {
        DeploymentMode::Playground => "https://try.cnktros.com".to_string(),
        DeploymentMode::SelfHosted => "http://localhost:9091".to_string(),
    }
}

fn playground_session_ttl_secs() -> u64 {
    std::env::var("CONNECTOR_PLAYGROUND_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5400)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn feature_flags(mode: DeploymentMode) -> Value {
    json!({
        "wizards_enabled": true,
        "playground_telemetry": matches!(mode, DeploymentMode::Playground),
        "self_deploy_admin": matches!(mode, DeploymentMode::SelfHosted),
    })
}

/// Build the JSON payload returned by `GET /api/v1/deployment/info`.
///
/// Public-safe: no secrets, no PII, no host-specific paths. The Leptos UI
/// is the only intended consumer but the endpoint is open to any caller.
pub fn deployment_info_value(state: &PlatformState) -> Value {
    let mode = DeploymentMode::from_env();
    let tier = format!("{:?}", state.license.tier).to_ascii_lowercase();
    let now_secs = now_unix() as i64;
    let license_status = if state.license.is_time_valid(now_secs) {
        "active"
    } else {
        "expired"
    };
    let edition = mode.edition(&tier);
    let mut payload = json!({
        "mode": mode.as_str(),
        "edition": edition,
        "public_url": public_url(mode),
        "version": env!("CARGO_PKG_VERSION"),
        "feature_flags": feature_flags(mode),
    });

    match mode {
        DeploymentMode::Playground => {
            let ttl = playground_session_ttl_secs();
            payload["session_ttl_secs"] = json!(ttl);
            payload["caps"] = json!({
                "max_agents_per_session": crate::services::playground::max_agents(),
                "max_concurrent_sessions": crate::services::playground::max_sessions(),
                "session_ttl_secs": ttl,
                "token_budget_per_session": crate::services::playground::token_budget(),
            });
        }
        DeploymentMode::SelfHosted => {
            payload["license_tier"] = json!(tier);
            payload["license_status"] = json!(license_status);
        }
    }
    payload
}

/// `GET /api/v1/deployment/info` handler.
pub async fn deployment_info(State(state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    let mut payload = deployment_info_value(state.as_ref());
    if crate::services::playground::is_playground_mode() {
        if let Some(claims) = crate::auth::extract_claims(&headers) {
            if let Some(expires_at) = crate::services::playground::lookup_session_expires_at(
                &state.playground_sessions,
                &claims.sub,
            ) {
                payload["session_expires_at"] = json!(expires_at);
            }
        }
    }
    Json(payload)
}
