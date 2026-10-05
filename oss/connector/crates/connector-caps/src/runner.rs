//! Runner Framework — sandboxed execution environments.
//!
//! Agents never execute directly. Every action goes through a runner
//! that enforces sandbox limits and produces cryptographic receipts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CapsError, CapsResult};
use crate::sandbox::SandboxConfig;

fn sandbox_side_effects(request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<Vec<String>> {
    let plan = sandbox.execution_plan(&request.capability_id)?;
    let mut side_effects = vec![
        format!("sandbox_backend:{}", plan.backend.as_str()),
        format!("sandbox_profile:{}", plan.isolation_profile),
    ];
    side_effects.extend(plan.runtime_hints.into_iter().map(|hint| format!("sandbox_hint:{}", hint)));
    Ok(side_effects)
}

fn enforce_resource_limits(request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<()> {
    if request.timeout_ms == 0 {
        return Err(CapsError::Timeout);
    }
    if let Some(max_duration_ms) = sandbox.max_duration_ms {
        if request.timeout_ms > max_duration_ms {
            return Err(CapsError::ResourceLimit(format!(
                "timeout_ms {} exceeds sandbox max_duration_ms {}",
                request.timeout_ms, max_duration_ms
            )));
        }
    }
    if let Some(max_memory_bytes) = sandbox.max_memory_bytes {
        let requested = request.params.get("max_memory_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        if requested > max_memory_bytes {
            return Err(CapsError::ResourceLimit(format!(
                "max_memory_bytes {} exceeds sandbox limit {}",
                requested, max_memory_bytes
            )));
        }
    }
    if let Some(max_cpu_percent) = sandbox.max_cpu_percent {
        let requested = request.params.get("max_cpu_percent").and_then(|v| v.as_u64()).unwrap_or(0);
        if requested > max_cpu_percent as u64 {
            return Err(CapsError::ResourceLimit(format!(
                "max_cpu_percent {} exceeds sandbox limit {}",
                requested, max_cpu_percent
            )));
        }
    }
    if let Some(max_pids) = sandbox.max_pids {
        let requested = request.params.get("max_pids").and_then(|v| v.as_u64()).unwrap_or(0);
        if requested > max_pids as u64 {
            return Err(CapsError::ResourceLimit(format!(
                "max_pids {} exceeds sandbox limit {}",
                requested, max_pids
            )));
        }
    }
    Ok(())
}

fn extract_domain(url: &str) -> &str {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    without_scheme.split('/').next().unwrap_or(without_scheme)
}

/// Request to execute a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub contract_id: String,
    pub capability_id: String,
    pub params: serde_json::Value,
    pub params_hash: String,
    pub token_id: String,
    pub timeout_ms: u64,
}

/// Result of executing a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub output: serde_json::Value,
    pub output_hash: String,
    pub output_cid: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub side_effects: Vec<String>,
}

/// Trait for execution runners.
pub trait Runner: Send + Sync {
    /// Runner identifier.
    fn id(&self) -> &str;

    /// Execute a request within the given sandbox.
    fn execute(&self, request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<ExecResult>;

    /// Capabilities this runner supports.
    fn supported_capabilities(&self) -> Vec<String>;
}

/// No-op runner for testing — returns pre-configured output.
pub struct NoopRunner {
    output: serde_json::Value,
}

impl NoopRunner {
    pub fn new() -> Self {
        Self { output: serde_json::json!({"status": "ok"}) }
    }

    pub fn with_output(output: serde_json::Value) -> Self {
        Self { output }
    }
}

impl Default for NoopRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for NoopRunner {
    fn id(&self) -> &str { "noop" }

    fn execute(&self, request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        enforce_resource_limits(request, sandbox)?;
        let side_effects = sandbox_side_effects(request, sandbox)?;
        Ok(ExecResult {
            output: self.output.clone(),
            output_hash: "sha256:noop".to_string(),
            output_cid: "cid:noop".to_string(),
            exit_code: 0,
            duration_ms: 1,
            side_effects,
        })
    }

    fn supported_capabilities(&self) -> Vec<String> {
        vec!["*".to_string()]
    }
}

fn mock_runners_allowed() -> bool {
    std::env::var("CONNECTOR_CAPS_ALLOW_MOCK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
        || cfg!(test)
}

/// HTTP runner — executes net.* capabilities.
/// Mock success bodies only when `CONNECTOR_CAPS_ALLOW_MOCK=1` or under `cfg(test)`.
pub struct HttpRunner;

impl Runner for HttpRunner {
    fn id(&self) -> &str { "http" }

    fn execute(&self, request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        enforce_resource_limits(request, sandbox)?;
        let mut side_effects = sandbox_side_effects(request, sandbox)?;
        let url = request.params.get("url").and_then(|v| v.as_str()).unwrap_or("");
        let domain = extract_domain(url);

        if !sandbox.is_domain_allowed(domain) {
            return Err(CapsError::SandboxViolation(format!(
                "Domain not allowed: {}", domain
            )));
        }

        if !mock_runners_allowed() {
            return Err(CapsError::RunnerError(
                "HttpRunner mock disabled; set CONNECTOR_CAPS_ALLOW_MOCK=1 for lab only \
                 (rejected under production / defense-strict boot)"
                    .into(),
            ));
        }

        Ok(ExecResult {
            output: serde_json::json!({"url": url, "status": 200, "body": "mock"}),
            output_hash: "sha256:http-mock".to_string(),
            output_cid: "cid:http-mock".to_string(),
            exit_code: 0,
            duration_ms: 50,
            side_effects: {
                side_effects.push(format!("http_request:{}", url));
                side_effects
            },
        })
    }

    fn supported_capabilities(&self) -> Vec<String> {
        vec!["net.http_get".into(), "net.http_post".into(), "net.http_put".into(), "net.http_delete".into()]
    }
}

/// Store runner — executes store.* capabilities against VAC namespaces.
/// Mock success bodies only when `CONNECTOR_CAPS_ALLOW_MOCK=1` or under `cfg(test)`.
pub struct StoreRunner;

impl Runner for StoreRunner {
    fn id(&self) -> &str { "store" }

    fn execute(&self, request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        enforce_resource_limits(request, sandbox)?;
        let side_effects = sandbox_side_effects(request, sandbox)?;
        let ns = request.params.get("namespace").and_then(|v| v.as_str()).unwrap_or("default");
        if let Some(path) = request.params.get("path").and_then(|v| v.as_str()) {
            if !sandbox.is_path_allowed(path) {
                return Err(CapsError::PermissionDenied(format!(
                    "Path not allowed by sandbox: {}",
                    path
                )));
            }
        }
        if !mock_runners_allowed() {
            return Err(CapsError::RunnerError(
                "StoreRunner mock disabled; set CONNECTOR_CAPS_ALLOW_MOCK=1 for lab only \
                 (rejected under production / defense-strict boot)"
                    .into(),
            ));
        }
        Ok(ExecResult {
            output: serde_json::json!({"namespace": ns, "result": "ok"}),
            output_hash: "sha256:store-mock".to_string(),
            output_cid: "cid:store-mock".to_string(),
            exit_code: 0,
            duration_ms: 5,
            side_effects,
        })
    }

    fn supported_capabilities(&self) -> Vec<String> {
        vec!["store.read".into(), "store.write".into(), "store.delete".into(), "store.query".into()]
    }
}

/// Registry of available runners.
pub struct RunnerRegistry {
    runners: HashMap<String, Box<dyn Runner>>,
}

impl RunnerRegistry {
    pub fn new() -> Self {
        Self { runners: HashMap::new() }
    }

    /// Create with default runners registered.
    ///
    /// Http/Store runners refuse mock success unless `CONNECTOR_CAPS_ALLOW_MOCK=1`
    /// (or under unit tests). Production boot rejects that flag.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register(Box::new(NoopRunner::new()));
        reg.register(Box::new(HttpRunner));
        reg.register(Box::new(StoreRunner));
        reg
    }

    pub fn register(&mut self, runner: Box<dyn Runner>) {
        self.runners.insert(runner.id().to_string(), runner);
    }

    pub fn get(&self, id: &str) -> CapsResult<&dyn Runner> {
        self.runners
            .get(id)
            .map(|r| r.as_ref())
            .ok_or_else(|| CapsError::RunnerError(format!("Runner not found: {}", id)))
    }

    /// Select the best runner for a capability. Prefers specific matches over wildcard.
    pub fn select_for_capability(&self, capability_id: &str) -> CapsResult<&dyn Runner> {
        let mut wildcard: Option<&dyn Runner> = None;
        for runner in self.runners.values() {
            let caps = runner.supported_capabilities();
            if caps.iter().any(|c| c == capability_id) {
                return Ok(runner.as_ref()); // exact match wins
            }
            if wildcard.is_none() && caps.iter().any(|c| c == "*") {
                wildcard = Some(runner.as_ref());
            }
        }
        wildcard.ok_or_else(|| CapsError::RunnerError(format!("No runner for capability: {}", capability_id)))
    }

    pub fn len(&self) -> usize { self.runners.len() }
    pub fn is_empty(&self) -> bool { self.runners.is_empty() }
}

impl Default for RunnerRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(cap: &str) -> ExecRequest {
        ExecRequest {
            contract_id: "cid:test".into(),
            capability_id: cap.into(),
            params: serde_json::json!({"url": "https://api.example.com/data"}),
            params_hash: "hash".into(),
            token_id: "tok".into(),
            timeout_ms: 5000,
        }
    }

    #[test]
    fn test_noop_runner() {
        let runner = NoopRunner::new();
        let result = runner.execute(&make_request("fs.read"), &SandboxConfig::default()).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.side_effects.iter().any(|effect| effect == "sandbox_backend:native"));
    }

    #[test]
    fn test_noop_runner_timeout_zero() {
        let runner = NoopRunner::new();
        let mut req = make_request("fs.read");
        req.timeout_ms = 0;
        assert!(runner.execute(&req, &SandboxConfig::default()).is_err());
    }

    #[test]
    fn test_http_runner_domain_check() {
        let runner = HttpRunner;
        let sandbox = SandboxConfig {
            allowed_domains: vec!["api.example.com".into()],
            ..SandboxConfig::default()
        };
        let result = runner.execute(&make_request("net.http_get"), &sandbox).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.side_effects.iter().any(|effect| effect == "sandbox_backend:native"));
    }

    #[test]
    fn test_nsjail_runner_plan_hint() {
        let runner = NoopRunner::new();
        let sandbox = SandboxConfig {
            backend: crate::sandbox::SandboxBackendKind::Nsjail,
            nsjail: Some(crate::sandbox::NsjailConfig {
                binary_path: "/usr/bin/nsjail".into(),
                config_path: None,
                profile: Some("tight".into()),
            }),
            ..SandboxConfig::default()
        };
        let result = runner.execute(&make_request("fs.read"), &sandbox).unwrap();
        assert!(result.side_effects.iter().any(|effect| effect == "sandbox_backend:nsjail"));
        assert!(result.side_effects.iter().any(|effect| effect == "sandbox_hint:nsjail_profile:tight"));
    }

    #[test]
    fn test_http_runner_domain_blocked() {
        let runner = HttpRunner;
        let sandbox = SandboxConfig {
            allowed_domains: vec!["safe.com".into()],
            ..SandboxConfig::default()
        };
        assert!(runner.execute(&make_request("net.http_get"), &sandbox).is_err());
    }

    #[test]
    fn test_http_runner_network_disabled() {
        let runner = HttpRunner;
        let sandbox = SandboxConfig {
            network_disabled: true,
            ..SandboxConfig::default()
        };
        assert!(matches!(
            runner.execute(&make_request("net.http_get"), &sandbox),
            Err(CapsError::SandboxViolation(_))
        ));
    }

    #[test]
    fn test_store_runner_path_blocked() {
        let runner = StoreRunner;
        let sandbox = SandboxConfig {
            allowed_paths: vec!["/safe/*".into()],
            ..SandboxConfig::default()
        };
        let mut req = make_request("store.read");
        req.params = serde_json::json!({"namespace": "default", "path": "/etc/passwd"});
        assert!(matches!(
            runner.execute(&req, &sandbox),
            Err(CapsError::PermissionDenied(_))
        ));
    }

    #[test]
    fn test_resource_limit_timeout_exceeded() {
        let runner = NoopRunner::new();
        let sandbox = SandboxConfig {
            max_duration_ms: Some(1000),
            ..SandboxConfig::default()
        };
        let mut req = make_request("fs.read");
        req.timeout_ms = 2000;
        assert!(matches!(
            runner.execute(&req, &sandbox),
            Err(CapsError::ResourceLimit(_))
        ));
    }

    #[test]
    fn test_resource_limit_memory_exceeded() {
        let runner = NoopRunner::new();
        let sandbox = SandboxConfig {
            max_memory_bytes: Some(1024),
            ..SandboxConfig::default()
        };
        let mut req = make_request("fs.read");
        req.params = serde_json::json!({"max_memory_bytes": 4096});
        assert!(matches!(
            runner.execute(&req, &sandbox),
            Err(CapsError::ResourceLimit(_))
        ));
    }

    #[test]
    fn test_runner_registry_defaults() {
        let reg = RunnerRegistry::with_defaults();
        assert_eq!(reg.len(), 3);
        assert!(reg.get("noop").is_ok());
        assert!(reg.get("http").is_ok());
        assert!(reg.get("store").is_ok());
    }

    #[test]
    fn test_runner_registry_select() {
        let reg = RunnerRegistry::with_defaults();
        let runner = reg.select_for_capability("net.http_get").unwrap();
        assert_eq!(runner.id(), "http");

        let runner = reg.select_for_capability("store.read").unwrap();
        assert_eq!(runner.id(), "store");
    }

    #[test]
    fn test_runner_registry_unknown() {
        let mut reg = RunnerRegistry::new();
        reg.register(Box::new(HttpRunner));
        // No noop runner = no wildcard fallback
        assert!(reg.select_for_capability("crypto.hash").is_err());
    }
}
