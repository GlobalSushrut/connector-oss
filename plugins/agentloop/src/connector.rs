//! ConnectorClient — bridge to the Connector kernel.
//! Provides all AgentLoop data surfaces: history, prompts, experiments, insights, monitor.
//! Production-grade: retry with exponential backoff + jitter, circuit breaker, X-Request-ID.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use uuid::Uuid;

// ── Circuit breaker ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct CircuitState {
    failures:        AtomicU32,
    last_failure_ms: AtomicU64,
    open_threshold:  u32,
    cooldown_ms:     u64,
}

impl CircuitState {
    fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            failures:        AtomicU32::new(0),
            last_failure_ms: AtomicU64::new(0),
            open_threshold:  threshold,
            cooldown_ms:     cooldown_secs * 1000,
        }
    }

    fn is_open(&self) -> bool {
        if self.failures.load(Ordering::Relaxed) < self.open_threshold { return false; }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let last   = self.last_failure_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last) < self.cooldown_ms
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        self.last_failure_ms.store(now_ms, Ordering::Relaxed);
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub base_url:             String,
    pub api_key:              String,
    pub timeout_secs:         u64,
    pub max_retries:          u32,
    pub circuit_threshold:    u32,
    pub circuit_cooldown_secs: u64,
}

impl ConnectorConfig {
    pub fn from_env() -> Self {
        Self {
            base_url:             std::env::var("CONNECTOR_URL").unwrap_or_else(|_| "http://localhost:9091".into()),
            api_key:              std::env::var("CONNECTOR_API_KEY").unwrap_or_else(|_| "agentloop_key".into()),
            timeout_secs:         std::env::var("CONNECTOR_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
            max_retries:          std::env::var("CONNECTOR_MAX_RETRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(3),
            circuit_threshold:    std::env::var("CONNECTOR_CIRCUIT_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            circuit_cooldown_secs: std::env::var("CONNECTOR_CIRCUIT_COOLDOWN_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConnectorClient {
    client:  Client,
    config:  ConnectorConfig,
    circuit: Arc<CircuitState>,
}

impl ConnectorClient {
    pub fn new(config: ConnectorConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .context("build reqwest client")?;

        let circuit = Arc::new(CircuitState::new(
            config.circuit_threshold,
            config.circuit_cooldown_secs,
        ));

        Ok(Self { client, config, circuit })
    }

    pub fn circuit_open(&self) -> bool { self.circuit.is_open() }

    // ── History surfaces ──────────────────────────────────────────────────────

    /// Fetch agent run history from Connector.
    pub async fn get_history(&self, agent_id: &str, limit: u32) -> Result<Value> {
        self.get(&format!("/api/v1/history?agent_id={}&limit={}", agent_id, limit)).await
    }

    /// Fetch a single run by Connector run ID.
    pub async fn get_run(&self, run_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/history/{}", run_id)).await
    }

    /// Fetch run steps for a Connector run.
    pub async fn get_run_steps(&self, run_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/history/{}/steps", run_id)).await
    }

    /// Deterministic replay of a run via Connector.
    pub async fn replay_run(&self, run_id: &str, body: &Value) -> Result<Value> {
        self.post_once(&format!("/api/v1/history/{}/replay", run_id), body).await
    }

    // ── Prompt surfaces ───────────────────────────────────────────────────────

    /// Push a prompt version to Connector's prompt registry.
    pub async fn register_prompt(&self, body: &Value) -> Result<Value> {
        self.post_once("/api/v1/prompts", body).await
    }

    /// Fetch Connector-side prompt evaluation results.
    pub async fn evaluate_prompt(&self, prompt_id: &str, body: &Value) -> Result<Value> {
        self.post_once(&format!("/api/v1/prompts/{}/evaluate", prompt_id), body).await
    }

    // ── Experiment surfaces ───────────────────────────────────────────────────

    /// Register an experiment with Connector for traffic routing.
    pub async fn create_experiment(&self, body: &Value) -> Result<Value> {
        self.post_once("/api/v1/experiments", body).await
    }

    /// Fetch experiment metrics from Connector.
    pub async fn get_experiment_metrics(&self, exp_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/experiments/{}/metrics", exp_id)).await
    }

    /// Promote experiment winner in Connector.
    pub async fn promote_experiment(&self, exp_id: &str, body: &Value) -> Result<Value> {
        self.post_once(&format!("/api/v1/experiments/{}/promote", exp_id), body).await
    }

    // ── Insights / Optimize surfaces ──────────────────────────────────────────

    /// Fetch Connector's causal analysis for an agent.
    pub async fn get_insights(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/insights?agent_id={}", agent_id)).await
    }

    /// Fetch Connector's rightsize recommendations.
    pub async fn get_recommendations(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/insights/recommendations?agent_id={}", agent_id)).await
    }

    /// Fetch drift signals from Connector's monitor surface.
    pub async fn get_drift(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/api/v1/monitor/drift?agent_id={}", agent_id)).await
    }

    /// Apply a recommendation action via Connector.
    pub async fn apply_recommendation(&self, rec_id: &str, body: &Value) -> Result<Value> {
        self.post_once(&format!("/api/v1/insights/recommendations/{}/apply", rec_id), body).await
    }

    // ── Health ────────────────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<Value> {
        self.get("/health").await
    }

    // ── Internal HTTP ─────────────────────────────────────────────────────────

    async fn get(&self, path: &str) -> Result<Value> {
        if self.circuit.is_open() {
            anyhow::bail!("Circuit breaker open — Connector unavailable");
        }
        let url = format!("{}{}", self.config.base_url, path);
        let mut last_err = anyhow::anyhow!("no attempts");
        for attempt in 0..=self.config.max_retries {
            if attempt > 0 { self.backoff(attempt).await; }
            let req_id = Uuid::new_v4().to_string();
            match self.client.get(&url)
                .header("X-API-Key", &self.config.api_key)
                .header("X-Request-ID", &req_id)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    self.circuit.record_success();
                    return resp.json().await.context("parse GET response");
                }
                Ok(resp) if resp.status().is_client_error() => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    anyhow::bail!("Connector 4xx {}: {}", status, body);
                }
                Ok(resp) => {
                    last_err = anyhow::anyhow!("Connector 5xx {}", resp.status());
                    self.circuit.record_failure();
                }
                Err(e) => {
                    last_err = anyhow::anyhow!(e);
                    self.circuit.record_failure();
                }
            }
        }
        Err(last_err)
    }

    async fn post_once(&self, path: &str, body: &Value) -> Result<Value> {
        if self.circuit.is_open() {
            anyhow::bail!("Circuit breaker open — Connector unavailable");
        }
        let url = format!("{}{}", self.config.base_url, path);
        let req_id = Uuid::new_v4().to_string();
        let resp = self.client.post(&url)
            .header("X-API-Key", &self.config.api_key)
            .header("X-Request-ID", &req_id)
            .json(body)
            .send().await
            .context("POST to Connector")?;

        if resp.status().is_success() {
            self.circuit.record_success();
            return resp.json().await.context("parse POST response");
        }
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_server_error() { self.circuit.record_failure(); }
        anyhow::bail!("Connector {} {}: {}", status.as_u16(), path, text);
    }

    async fn backoff(&self, attempt: u32) {
        use std::time::Duration;
        let base_ms = 100u64 * (1 << attempt.min(5));
        let jitter   = (rand_jitter() * base_ms as f64 * 0.4) as u64;
        tokio::time::sleep(Duration::from_millis(base_ms + jitter)).await;
    }
}

fn rand_jitter() -> f64 {
    // Simple LCG-based float in [0,1) — no rand crate needed
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as u64;
    let v = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (v >> 33) as f64 / (1u64 << 31) as f64
}
