//! Runner Framework — sandboxed execution environments.
//!
//! Agents never execute directly. Every action goes through a runner
//! that enforces sandbox limits and produces cryptographic receipts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CapsError, CapsResult};
use crate::sandbox::SandboxConfig;

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

    fn execute(&self, request: &ExecRequest, _sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        if request.timeout_ms == 0 {
            return Err(CapsError::Timeout);
        }
        Ok(ExecResult {
            output: self.output.clone(),
            output_hash: "sha256:noop".to_string(),
            output_cid: "cid:noop".to_string(),
            exit_code: 0,
            duration_ms: 1,
            side_effects: vec![],
        })
    }

    fn supported_capabilities(&self) -> Vec<String> {
        vec!["*".to_string()]
    }
}

/// HTTP runner stub — executes net.* capabilities.
pub struct HttpRunner;

impl Runner for HttpRunner {
    fn id(&self) -> &str { "http" }

    fn execute(&self, request: &ExecRequest, sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        let url = request.params.get("url").and_then(|v| v.as_str()).unwrap_or("");

        // Check domain allowlist
        if !sandbox.allowed_domains.is_empty() {
            let domain_ok = sandbox.allowed_domains.iter().any(|d| url.contains(d));
            if !domain_ok {
                return Err(CapsError::SandboxViolation(format!(
                    "Domain not in allowlist: {}", url
                )));
            }
        }

        // Stub: return a mock response
        Ok(ExecResult {
            output: serde_json::json!({"url": url, "status": 200, "body": "mock"}),
            output_hash: "sha256:http-mock".to_string(),
            output_cid: "cid:http-mock".to_string(),
            exit_code: 0,
            duration_ms: 50,
            side_effects: vec![format!("http_request:{}", url)],
        })
    }

    fn supported_capabilities(&self) -> Vec<String> {
        vec!["net.http_get".into(), "net.http_post".into(), "net.http_put".into(), "net.http_delete".into()]
    }
}

/// Store runner stub — executes store.* capabilities against VAC namespaces.
pub struct StoreRunner;

impl Runner for StoreRunner {
    fn id(&self) -> &str { "store" }

    fn execute(&self, request: &ExecRequest, _sandbox: &SandboxConfig) -> CapsResult<ExecResult> {
        let ns = request.params.get("namespace").and_then(|v| v.as_str()).unwrap_or("default");
        Ok(ExecResult {
            output: serde_json::json!({"namespace": ns, "result": "ok"}),
            output_hash: "sha256:store-mock".to_string(),
            output_cid: "cid:store-mock".to_string(),
            exit_code: 0,
            duration_ms: 5,
            side_effects: vec![],
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
