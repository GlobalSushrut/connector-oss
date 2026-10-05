//! Typed HTTP client for Connector platform native APIs.
//!
//! Speaks `/api/v1/native/*` using [`connector_native_contract`] types.
//! Never invents tokens or fabricates `{ok:true}` on transport failure.
//! Package digests are required outside lab (see [`package_gate`]).

use connector_native_contract::{
    admit_package_for_effect, gate_allows, ApiErrorEnvelope, ChannelObservation, PackagePin,
    RuntimeProfile,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub use connector_native_contract::{
    AgentSpec, BudgetSpec, EffectDescriptor, GrantRequest, GraphSpec, InferenceSpec, ListenerSpec,
    RouteSpec, SecretRef, TargetSpec, ToolSpec,
};

/// Default platform listener (matches connectorctl / DevGuard).
pub const DEFAULT_API_URL: &str = "http://127.0.0.1:9091";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("api: {status}: {body}")]
    Api { status: u16, body: String },
    #[error("api_envelope[{code}]: {message}")]
    ApiEnvelope {
        status: u16,
        code: String,
        message: String,
        envelope: ApiErrorEnvelope,
    },
    #[error("config: {0}")]
    Config(String),
    #[error("package_gate: {0}")]
    PackageGate(String),
    #[error("auth: no API key configured (set CONNECTOR_API_KEY); refusing silent tokens")]
    MissingAuth,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_secs: u64,
    pub runtime_profile: RuntimeProfile,
    /// When true, mutating calls require PackagePin outside lab.
    pub enforce_package_gate: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: std::env::var("CONNECTOR_API_URL")
                .or_else(|_| std::env::var("CONNECTOR_URL"))
                .unwrap_or_else(|_| DEFAULT_API_URL.into()),
            api_key: std::env::var("CONNECTOR_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            timeout_secs: std::env::var("CONNECTOR_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            runtime_profile: RuntimeProfile::parse(
                &std::env::var("CONNECTOR_ENV").unwrap_or_else(|_| "development".into()),
            ),
            enforce_package_gate: true,
        }
    }
}

/// Reference ConnectorClient (Rust SoT for SDK/CLI).
#[derive(Debug, Clone)]
pub struct ConnectorClient {
    config: ClientConfig,
    http: reqwest::blocking::Client,
}

impl ConnectorClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Ok(Self { config, http })
    }

    pub fn from_env() -> Result<Self, ClientError> {
        Self::new(ClientConfig::default())
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        let k = key.into();
        if !k.trim().is_empty() {
            self.config.api_key = Some(k);
        }
        self
    }

    pub fn with_package_gate(mut self, enforce: bool) -> Self {
        self.config.enforce_package_gate = enforce;
        self
    }

    fn url(&self, path: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        format!("{base}{path}")
    }

    fn apply_auth(&self, req: reqwest::blocking::RequestBuilder) -> Result<reqwest::blocking::RequestBuilder, ClientError> {
        match &self.config.api_key {
            Some(k) => Ok(req.bearer_auth(k)),
            None => {
                // Lab/dev may call unauthenticated local endpoints; production callers should set a key.
                if self.config.runtime_profile.requires_signed_package() {
                    Err(ClientError::MissingAuth)
                } else {
                    Ok(req)
                }
            }
        }
    }

    fn send_json<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, ClientError> {
        let mut req = self.http.request(method, self.url(path));
        req = self.apply_auth(req)?;
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| ClientError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(env) = ApiErrorEnvelope::from_response_value(&v) {
                    return Err(ClientError::ApiEnvelope {
                        status,
                        code: env.code.clone(),
                        message: env.message.clone(),
                        envelope: env,
                    });
                }
            }
            return Err(ClientError::Api {
                status,
                body: text,
            });
        }
        // 2xx bodies may still carry structured denials (legacy handlers return 200 + ok:false).
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.get("ok") == Some(&Value::Bool(false)) {
                if let Some(env) = ApiErrorEnvelope::from_response_value(&v) {
                    return Err(ClientError::ApiEnvelope {
                        status,
                        code: env.code.clone(),
                        message: env.message.clone(),
                        envelope: env,
                    });
                }
                if let Some(s) = v.get("error").and_then(|e| e.as_str()) {
                    if let Some(env) = ApiErrorEnvelope::from_legacy_string(s) {
                        return Err(ClientError::ApiEnvelope {
                            status,
                            code: env.code.clone(),
                            message: env.message.clone(),
                            envelope: env,
                        });
                    }
                }
            }
        }
        serde_json::from_str(&text).map_err(|e| ClientError::Decode(format!("{e}: {text}")))
    }

    fn send_value(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ClientError> {
        self.send_json(method, path, body)
    }

    // ── Native surfaces / channels ──────────────────────────────────────────

    pub fn list_surfaces(&self) -> Result<Value, ClientError> {
        self.send_value(reqwest::Method::GET, "/api/v1/native/surfaces", None)
    }

    pub fn list_channels(&self) -> Result<Value, ClientError> {
        self.send_value(reqwest::Method::GET, "/api/v1/native/channels", None)
    }

    pub fn observe_channel(&self, observation: &ChannelObservation) -> Result<Value, ClientError> {
        let body = serde_json::to_value(observation)
            .map_err(|e| ClientError::Decode(e.to_string()))?;
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/channels/observe",
            Some(&body),
        )
    }

    pub fn probe_surface(&self, surface_id: &str) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            &format!("/api/v1/native/surfaces/{surface_id}/probe"),
            Some(&json!({})),
        )
    }

    // ── Invocations / receipts ──────────────────────────────────────────────

    pub fn invoke(&self, body: Value, package: Option<PackagePin>) -> Result<Value, ClientError> {
        if self.config.enforce_package_gate {
            let decision = admit_package_for_effect(
                self.config.runtime_profile,
                package.as_ref(),
                true,
            );
            if !gate_allows(&decision) {
                return Err(ClientError::PackageGate(decision.honesty));
            }
        }
        let mut payload = body;
        if let Some(pin) = package {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "package".into(),
                    serde_json::to_value(pin).unwrap_or(Value::Null),
                );
            }
        }
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/invocations",
            Some(&payload),
        )
    }

    pub fn get_receipt(&self, operation_id: &str) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::GET,
            &format!("/api/v1/native/receipts/{operation_id}"),
            None,
        )
    }

    // ── Origin binding ──────────────────────────────────────────────────────

    pub fn bind_software(&self, body: Value) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/software/bind",
            Some(&body),
        )
    }

    pub fn create_workload(&self, body: Value) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/workloads",
            Some(&body),
        )
    }

    pub fn create_intelligence(&self, body: Value) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/intelligence",
            Some(&body),
        )
    }

    /// Compose a status view from native list endpoints (best-effort).
    pub fn status(&self) -> Result<NativeStatus, ClientError> {
        let surfaces = self.list_surfaces().unwrap_or(json!({ "ok": false }));
        let channels = self.list_channels().unwrap_or(json!({ "ok": false }));
        Ok(NativeStatus {
            api_url: self.config.base_url.clone(),
            runtime_profile: self.config.runtime_profile,
            package_gate_enforced: self.config.enforce_package_gate,
            surfaces,
            channels,
            honesty: "status assembles native catalog views; confidence/posture come from surface records when present".into(),
        })
    }

    pub fn put_proxy_routes(&self, graph: Value) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/proxy/routes",
            Some(&graph),
        )
    }

    pub fn execute_proxy(&self, body: Value) -> Result<Value, ClientError> {
        self.send_value(
            reqwest::Method::POST,
            "/api/v1/native/proxy/execute",
            Some(&body),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeStatus {
    pub api_url: String,
    pub runtime_profile: RuntimeProfile,
    pub package_gate_enforced: bool,
    pub surfaces: Value,
    pub channels: Value,
    pub honesty: String,
}

/// Re-export commonly needed contract types for CLI/SDK consumers.
pub mod contracts {
    pub use connector_native_contract::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_url_is_9091() {
        // Isolated from ambient env where possible.
        let mut cfg = ClientConfig {
            base_url: DEFAULT_API_URL.into(),
            api_key: None,
            timeout_secs: 30,
            runtime_profile: RuntimeProfile::Lab,
            enforce_package_gate: true,
        };
        assert!(cfg.base_url.contains("9091"));
        cfg.runtime_profile = RuntimeProfile::Production;
        assert!(cfg.runtime_profile.requires_signed_package());
    }

    #[test]
    fn invoke_package_gate_blocks_production_without_pin() {
        let client = ConnectorClient::new(ClientConfig {
            base_url: "http://127.0.0.1:9".into(),
            api_key: Some("test".into()),
            timeout_secs: 1,
            runtime_profile: RuntimeProfile::Production,
            enforce_package_gate: true,
        })
        .unwrap();
        let err = client.invoke(json!({"effect": {"effect_class": "x", "mutates": true}}), None);
        assert!(matches!(err, Err(ClientError::PackageGate(_))));
    }
}
