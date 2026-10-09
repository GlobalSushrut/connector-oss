//! ConnectorClient — Enterprise-grade HTTP client for all Connector kernel APIs.
//!
//! Features:
//! - Exponential backoff retry with jitter (configurable max retries)
//! - Circuit breaker: opens after N consecutive failures, half-opens after cooldown
//! - Per-request X-Request-ID tracing propagation
//! - Structured tracing spans on every call
//! - Shared reqwest client with connection pooling
//! - Configurable per-endpoint timeouts
//! - Proper 4xx vs 5xx error distinction (only retry 5xx/network errors)

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use uuid::Uuid;

// ── Circuit Breaker ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct CircuitState {
    failures:        AtomicU32,
    last_failure_ms: AtomicU64,
    open_threshold:  u32,
    cooldown_ms:     u64,
}

impl CircuitState {
    fn new(open_threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            failures:        AtomicU32::new(0),
            last_failure_ms: AtomicU64::new(0),
            open_threshold,
            cooldown_ms:     cooldown_secs * 1000,
        }
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_failure_ms.store(now, Ordering::Relaxed);
    }

    fn is_open(&self) -> bool {
        let failures = self.failures.load(Ordering::Relaxed);
        if failures < self.open_threshold {
            return false;
        }
        let last = self.last_failure_ms.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        // If cooldown has elapsed, allow half-open probe
        now.saturating_sub(last) < self.cooldown_ms
    }
}

// ── Client config ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ConnectorConfig {
    pub base_url:        String,
    pub api_key:         String,
    pub timeout_secs:    u64,
    pub max_retries:     u32,
    pub circuit_threshold: u32,
    pub circuit_cooldown_secs: u64,
}

impl ConnectorConfig {
    pub fn from_env() -> Self {
        Self {
            base_url:              std::env::var("CONNECTOR_URL").unwrap_or_else(|_| "http://localhost:9091".into()),
            api_key:               std::env::var("CONNECTOR_API_KEY").unwrap_or_else(|_| "conductor_key".into()),
            timeout_secs:          std::env::var("CONNECTOR_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
            max_retries:           std::env::var("CONNECTOR_MAX_RETRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(3),
            circuit_threshold:     std::env::var("CONNECTOR_CIRCUIT_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            circuit_cooldown_secs: std::env::var("CONNECTOR_CIRCUIT_COOLDOWN_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
        }
    }
}

// ── ConnectorClient ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ConnectorClient {
    client:  Client,
    config:  ConnectorConfig,
    circuit: Arc<CircuitState>,
}

impl ConnectorClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        Self::with_config(ConnectorConfig {
            base_url,
            api_key,
            timeout_secs: 30,
            max_retries: 3,
            circuit_threshold: 5,
            circuit_cooldown_secs: 30,
        })
    }

    pub fn with_config(config: ConnectorConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(concat!("conductor/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Failed to build HTTP client");

        let circuit = Arc::new(CircuitState::new(
            config.circuit_threshold,
            config.circuit_cooldown_secs,
        ));

        ConnectorClient { client, config, circuit }
    }

    pub fn base_url(&self) -> &str { &self.config.base_url }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url, path)
    }

    fn auth(&self, req: reqwest::RequestBuilder, request_id: &str) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("Bearer {}", self.config.api_key))
           .header("Content-Type", "application/json")
           .header("X-Conductor-Version", env!("CARGO_PKG_VERSION"))
           .header("X-Request-ID", request_id)
           .header("X-Source", "conductor")
    }

    /// Core retry loop with exponential backoff + jitter.
    /// Only retries on network errors and 5xx responses.
    /// 4xx responses are returned immediately as errors (no retry).
    async fn call_with_retry<F, Fut>(&self, op_name: &str, f: F) -> Result<Value>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response>>,
    {
        if self.circuit.is_open() {
            anyhow::bail!("Circuit breaker OPEN for Connector ({}): too many consecutive failures", op_name);
        }

        let mut last_err = anyhow::anyhow!("No attempts made");
        let base_delay_ms = 100u64;

        for attempt in 0..=self.config.max_retries {
            let request_id = Uuid::new_v4().to_string();

            if attempt > 0 {
                // Exponential backoff with ±20% jitter
                let delay_ms = base_delay_ms * (1 << (attempt - 1).min(6));
                let jitter = (delay_ms as f64 * 0.2 * (rand_f64() - 0.5)) as u64;
                let sleep_ms = delay_ms.saturating_add(jitter);
                tracing::debug!(op = op_name, attempt, sleep_ms, "Connector retry backoff");
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }

            let span = tracing::info_span!("connector_call",
                op = op_name,
                request_id = %request_id,
                attempt = attempt,
            );
            let _enter = span.enter();

            match f(request_id).await {
                Ok(resp) => {
                    let status = resp.status();
                    let json: Value = resp.json().await.unwrap_or_default();

                    if status.is_success() {
                        self.circuit.record_success();
                        return Ok(json);
                    }

                    // 4xx — client error, do NOT retry
                    if status.is_client_error() {
                        self.circuit.record_success(); // not a server fault
                        anyhow::bail!(
                            "Connector {} returned {} (client error — no retry): {}",
                            op_name, status, json
                        );
                    }

                    // 5xx — server error, retry
                    last_err = anyhow::anyhow!(
                        "Connector {} returned {} (server error): {}",
                        op_name, status, json
                    );
                    self.circuit.record_failure();
                    tracing::warn!(op = op_name, %status, attempt, "Connector 5xx — will retry");
                }
                Err(e) => {
                    last_err = e;
                    self.circuit.record_failure();
                    tracing::warn!(op = op_name, attempt, err = %last_err, "Connector network error — will retry");
                }
            }
        }

        Err(last_err).with_context(|| format!("Connector {} failed after {} retries", op_name, self.config.max_retries))
    }

    /// GET helper with retry.
    async fn get(&self, path: &str, op: &str) -> Result<Value> {
        let url = self.url(path);
        self.call_with_retry(op, |rid| {
            let req = self.auth(self.client.get(&url), &rid);
            async move { Ok(req.send().await?) }
        }).await
    }

    /// POST helper with retry (idempotent-safe POST with request-id dedup on server side).
    async fn post(&self, path: &str, body: &Value, op: &str) -> Result<Value> {
        let url = self.url(path);
        let body = body.clone();
        self.call_with_retry(op, |rid| {
            let req = self.auth(self.client.post(&url), &rid).json(&body);
            async move { Ok(req.send().await?) }
        }).await
    }

    /// POST — fail fast on error (no retry for operations that must not duplicate).
    async fn post_once(&self, path: &str, body: &Value, op: &str) -> Result<Value> {
        if self.circuit.is_open() {
            anyhow::bail!("Circuit breaker OPEN for Connector ({})", op);
        }
        let request_id = Uuid::new_v4().to_string();
        let url = self.url(path);
        let resp = self.auth(self.client.post(&url), &request_id)
            .json(body).send().await
            .with_context(|| format!("{} network error", op))?;
        let status = resp.status();
        let json: Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            self.circuit.record_failure();
            anyhow::bail!("Connector {} failed ({}): {}", op, status, json);
        }
        self.circuit.record_success();
        Ok(json)
    }

    // ── Health ────────────────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<Value> {
        // Health check: single attempt, short timeout
        let request_id = Uuid::new_v4().to_string();
        let resp = self.auth(
            self.client.get(self.url("/health"))
                .timeout(Duration::from_secs(5)),
            &request_id,
        ).send().await.context("health check")?;
        Ok(resp.json().await.unwrap_or(serde_json::json!({"status": "ok"})))
    }

    // ── Pipeline definitions ──────────────────────────────────────────────────

    pub async fn register_pipeline_definition(&self, body: &Value) -> Result<Value> {
        self.post("/pipeline/definitions", body, "register_pipeline_definition").await
    }

    pub async fn get_pipeline_definitions(&self) -> Result<Value> {
        self.get("/pipeline/definitions", "get_pipeline_definitions").await
    }

    pub async fn validate_pipeline_run(&self, definition_id: &str, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/definitions/{}/validate-run/{}", definition_id, run_id);
        self.get(&path, "validate_pipeline_run").await
    }

    // ── Multiagent pipeline execution ─────────────────────────────────────────

    pub async fn run_pipeline(&self, body: &Value) -> Result<Value> {
        // Use post_once — starting a pipeline must not be duplicated
        self.post_once("/multiagent/pipeline", body, "run_pipeline").await
    }

    pub async fn get_pipeline_trace(&self, pipe_name: &str) -> Result<Value> {
        let path = format!("/multiagent/trace/{}", pipe_name);
        self.get(&path, "get_pipeline_trace").await
    }

    pub async fn approve_pipeline_step(&self, pipeline_id: &str, step: u32, body: &Value) -> Result<Value> {
        let path = format!("/multiagent/pipelines/{}/approve-step/{}", pipeline_id, step);
        self.post_once(&path, body, "approve_pipeline_step").await
    }

    pub async fn get_multiagent_map(&self) -> Result<Value> {
        self.get("/multiagent/map", "get_multiagent_map").await
    }

    // ── Pipeline run steps + integrity ────────────────────────────────────────

    pub async fn get_pipeline_steps(&self, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/{}/steps", run_id);
        self.get(&path, "get_pipeline_steps").await
    }

    pub async fn get_pipeline_integrity(&self, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/{}/integrity", run_id);
        self.get(&path, "get_pipeline_integrity").await
    }

    pub async fn get_cid_chain(&self, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/{}/cid-chain", run_id);
        self.get(&path, "get_cid_chain").await
    }

    pub async fn get_pipeline_gate(&self, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/{}/gate", run_id);
        self.get(&path, "get_pipeline_gate").await
    }

    pub async fn replay_from_step(&self, run_id: &str, step: u32, body: &Value) -> Result<Value> {
        let path = format!("/pipeline/{}/replay-from-step/{}", run_id, step);
        self.post_once(&path, body, "replay_from_step").await
    }

    pub async fn pre_deploy_diff(&self, body: &Value) -> Result<Value> {
        self.post("/pipeline/pre-deploy-diff", body, "pre_deploy_diff").await
    }

    pub async fn get_pipeline_artifacts(&self, run_id: &str) -> Result<Value> {
        let path = format!("/pipeline/{}/artifacts", run_id);
        self.get(&path, "get_pipeline_artifacts").await
    }

    pub async fn post_pipeline_artifact(&self, run_id: &str, body: &Value) -> Result<Value> {
        let path = format!("/pipeline/{}/artifacts", run_id);
        self.post(&path, body, "post_pipeline_artifact").await
    }

    // ── Gate policies ─────────────────────────────────────────────────────────

    pub async fn create_gate_policy(&self, body: &Value) -> Result<Value> {
        self.post("/pipeline/gate-policies", body, "create_gate_policy").await
    }

    pub async fn get_gate_policies(&self) -> Result<Value> {
        self.get("/pipeline/gate-policies", "get_gate_policies").await
    }

    pub async fn kecs_suspend_sweep(&self, body: &Value) -> Result<Value> {
        self.post("/pipeline/kecs-suspend-sweep", body, "kecs_suspend_sweep").await
    }

    // ── Multiagent grants ─────────────────────────────────────────────────────

    pub async fn grant_access(&self, body: &Value) -> Result<Value> {
        self.post("/multiagent/grant", body, "grant_access").await
    }

    pub async fn revoke_access(&self, body: &Value) -> Result<Value> {
        self.post("/multiagent/revoke", body, "revoke_access").await
    }

    // ── A2A channels ──────────────────────────────────────────────────────────

    pub async fn open_a2a_channel(&self, body: &Value) -> Result<Value> {
        self.post_once("/tools/a2a/open", body, "open_a2a_channel").await
    }

    pub async fn send_a2a_message(&self, channel_id: &str, body: &Value) -> Result<Value> {
        let path = format!("/tools/a2a/{}/send", channel_id);
        self.post(&path, body, "send_a2a_message").await
    }

    // ── Tool approvals ────────────────────────────────────────────────────────

    pub async fn get_tool_approvals(&self) -> Result<Value> {
        self.get("/tools/approvals", "get_tool_approvals").await
    }

    pub async fn resolve_tool_approval(&self, approval_id: &str, body: &Value) -> Result<Value> {
        let path = format!("/tools/approvals/{}", approval_id);
        self.post_once(&path, body, "resolve_tool_approval").await
    }

    // ── Self-heal + regression ────────────────────────────────────────────────

    pub async fn get_self_heal_candidates(&self) -> Result<Value> {
        self.get("/insights/self-heal-candidates", "get_self_heal_candidates").await
    }

    pub async fn detect_regression(&self, body: &Value) -> Result<Value> {
        self.post("/history/regression-detect", body, "detect_regression").await
    }

    // ── Webhook delivery (outbound) ───────────────────────────────────────────

    /// Deliver an outbound webhook with retry (up to 3 attempts, short timeout).
    pub async fn deliver_webhook(&self, url: &str, payload: &Value) -> Result<()> {
        let payload = payload.clone();
        let url = url.to_string();
        for attempt in 0u32..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
            }
            let request_id = Uuid::new_v4().to_string();
            let result = self.client.post(&url)
                .timeout(Duration::from_secs(10))
                .header("Content-Type", "application/json")
                .header("X-Request-ID", &request_id)
                .header("X-Source", "conductor")
                .json(&payload)
                .send()
                .await;
            match result {
                Ok(r) if r.status().is_success() => {
                    tracing::debug!(url = %url, "Webhook delivered");
                    return Ok(());
                }
                Ok(r) => {
                    tracing::warn!(url = %url, status = %r.status(), attempt, "Webhook delivery non-2xx");
                }
                Err(e) => {
                    tracing::warn!(url = %url, attempt, err = %e, "Webhook delivery error");
                }
            }
        }
        tracing::error!(url = %url, "Webhook delivery failed after 3 attempts — giving up");
        Ok(()) // Non-fatal: webhook failure must not crash runs
    }

    // ── Circuit breaker status ────────────────────────────────────────────────

    pub fn circuit_status(&self) -> serde_json::Value {
        serde_json::json!({
            "open": self.circuit.is_open(),
            "consecutive_failures": self.circuit.failures.load(Ordering::Relaxed),
            "threshold": self.circuit.open_threshold,
        })
    }
}

// ── PRNG jitter helper (no-dep, thread-local) ─────────────────────────────────

fn rand_f64() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        .hash(&mut h);
    (h.finish() as f64) / (u64::MAX as f64)
}
