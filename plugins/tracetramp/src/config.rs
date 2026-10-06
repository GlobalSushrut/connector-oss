//! TraceTramp configuration

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Port for the Data Plane (API Gateway, View/Control pipelines)
    #[serde(default = "default_data_plane_port")]
    pub data_plane_port: u16,
    
    /// Port for the Management Plane (Admin, Tenants, Providers)
    #[serde(default = "default_management_plane_port")]
    pub management_plane_port: u16,
    
    /// Connector API base URL
    #[serde(default = "default_connector_url")]
    pub connector_base_url: String,
    
    /// Connector API key
    #[serde(default = "default_connector_api_key")]
    pub connector_api_key: String,
    
    /// Database URL
    #[serde(default = "default_database_url")]
    pub database_url: String,
    
    /// Redis URL (optional). Omit, or set `off` / `disabled` / `none` for PostgreSQL-only deployments.
    #[serde(default)]
    pub redis_url: Option<String>,
    
    /// Default request timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub request_timeout_secs: u64,
    
    /// Enable Control Mode (enforcement) vs View Mode only
    #[serde(default = "default_control_mode")]
    pub control_mode_enabled: bool,

    /// When `false` (default), every chat request uses the **Control** pipeline (meter + policy filter
    /// + quarantine hooks + full trace evidence). Set `true` only in lab/diagnostics to allow
    /// passthrough **View** when the client sends `X-TraceTramp-Pipeline: view`.
    #[serde(default)]
    pub allow_view_pipeline: bool,

    /// Management-plane JWT secret (required)
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,

    /// License tier for feature gating: free | pro | enterprise
    #[serde(default = "default_license_tier")]
    pub license_tier: String,

    /// WitnessCtl base URL for async TraceTramp enforcement handoff (e.g. `http://127.0.0.1:17443`).
    #[serde(default)]
    pub witness_handoff_base_url: Option<String>,

    /// Shared secret with WitnessCtl `WITNESSCTL_TRACETRAMP_HANDOFF_SECRET` (must match).
    #[serde(default)]
    pub witness_handoff_secret: Option<String>,

    /// When `true`, connector policy **block** becomes a **pending approval** (202) instead of immediate 403 — operator chooses approve / quarantine / reject in TUI or admin API (`TRACETRAMP_SOFT_POLICY_BLOCK`).
    #[serde(default)]
    pub soft_policy_block: bool,

    /// When `true`, risk score ≥ 0.7 pauses before the LLM with a hold (same queue as HITL) (`TRACETRAMP_HIGH_RISK_HOLD_BEFORE_LLM`).
    #[serde(default)]
    pub high_risk_hold_before_llm: bool,

    /// When `true`, disallowed tools become **pending approval** (202) instead of immediate 403 (`TRACETRAMP_SOFT_TOOL_BLOCK`).
    #[serde(default)]
    pub soft_tool_block: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        apply_connector_key_alias();
        
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("TRACETRAMP"))
            .build()
            .map_err(|e| ConfigError::Build(e.to_string()))?;
            
        config.try_deserialize()
            .map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn connector_api_key_present(&self) -> bool {
        let key = self.connector_api_key.trim();
        !key.is_empty() && !key.eq_ignore_ascii_case("replace_with_connector_api_key")
    }

    pub fn jwt_secret_present(&self) -> bool {
        !self.jwt_secret.trim().is_empty()
    }

    /// True when a Redis URL is configured and not explicitly disabled.
    pub fn redis_enabled(&self) -> bool {
        self.redis_url
            .as_ref()
            .map(|u| {
                let t = u.trim().to_ascii_lowercase();
                !t.is_empty() && t != "off" && t != "disabled" && t != "none"
            })
            .unwrap_or(false)
    }

    pub fn validate_license_tier(&self) -> Result<(), ConfigError> {
        let normalized = self.license_tier.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "free" | "pro" | "enterprise") {
            Ok(())
        } else {
            Err(ConfigError::Parse(format!(
                "Invalid CONNECTOR_LICENSE_TIER '{}'. Expected one of: free, pro, enterprise.",
                self.license_tier
            )))
        }
    }
}

fn apply_connector_key_alias() {
    let explicit = std::env::var("TRACETRAMP_CONNECTOR_API_KEY").unwrap_or_default();
    let explicit_ok =
        !explicit.trim().is_empty() && !explicit.trim().eq_ignore_ascii_case("replace_with_connector_api_key");
    if explicit_ok {
        return;
    }
    let shared = std::env::var("CONNECTOR_KEY").unwrap_or_default();
    if shared.trim().is_empty() {
        return;
    }
    std::env::set_var("TRACETRAMP_CONNECTOR_API_KEY", shared.trim());
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to build configuration: {0}")]
    Build(String),
    #[error("Failed to parse configuration: {0}")]
    Parse(String),
}

fn default_data_plane_port() -> u16 { 9741 }
fn default_management_plane_port() -> u16 { 9742 }
fn default_connector_url() -> String { "http://localhost:9735".to_string() }
fn default_connector_api_key() -> String { "replace_with_connector_api_key".to_string() }
fn default_database_url() -> String { "postgres://localhost/tracetramp".to_string() }
fn default_timeout_secs() -> u64 { 300 }
fn default_control_mode() -> bool { true }
fn default_jwt_secret() -> String { "".to_string() }
fn default_license_tier() -> String { "free".to_string() }
