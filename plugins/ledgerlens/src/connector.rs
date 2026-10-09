//! ConnectorOS kernel bridge for LedgerLens.
//!
//! LedgerLens does NOT re-implement billing, metering, anomaly detection,
//! forecasting, or rightsizing. ConnectorOS already provides all of these.
//! This module is the typed client that wraps every relevant kernel endpoint.
//!
//! ConnectorOS surfaces used:
//!   /monitor/cost-dashboard        — fleet cost summary
//!   /monitor/cost-center           — cost by agent/team
//!   /monitor/anomalies/v2          — anomaly feed
//!   /monitor/forecast              — capacity forecast
//!   /monitor/budget-alerts         — budget alert status
//!   /history/agents/:pid/cost-timeline — per-agent cost history
//!   /history/fleet/compare         — fleet cost comparison
//!   /insights/budget-forecast/:pid — per-agent budget forecast
//!   /insights/model-recommendation/:pid — rightsizing suggestion
//!   /monitor/usage-export          — raw usage export
//!   /agents/:pid/cost              — per-agent cost
//!   /experiments/:id/compare-cost  — A/B cost comparison

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ConnectorConfig {
    pub base_url: String,
    pub api_key:  String,
}

impl ConnectorConfig {
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("CONNECTOR_URL")
                .unwrap_or_else(|_| "http://localhost:9091".into()),
            api_key:  std::env::var("CONNECTOR_API_KEY")
                .unwrap_or_default(),
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ConnectorClient {
    http:   Client,
    config: ConnectorConfig,
}

impl ConnectorClient {
    pub fn new(config: ConnectorConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("ledgerlens/0.1")
            .build()
            .context("build http client")?;
        Ok(Self { http, config })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let resp = self.http
            .get(self.url(path))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("X-LedgerLens-Client", "true")
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(Value::Null);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("ConnectorOS {path} returned {status}: {body}");
        }
        resp.json::<Value>().await.context("parse json")
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let resp = self.http
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("X-LedgerLens-Client", "true")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("ConnectorOS {path} returned {status}: {text}");
        }
        resp.json::<Value>().await.context("parse json")
    }

    // ── Health ────────────────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<()> {
        self.get("/health").await?;
        Ok(())
    }

    // ── Cost dashboard (fleet summary) ────────────────────────────────────────

    pub async fn cost_dashboard(&self) -> Result<Value> {
        self.get("/monitor/cost-dashboard").await
    }

    pub async fn cost_center(&self) -> Result<Value> {
        self.get("/monitor/cost-center").await
    }

    // ── Per-agent cost ────────────────────────────────────────────────────────

    pub async fn agent_cost(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/agents/{agent_id}/cost")).await
    }

    pub async fn agent_cost_timeline(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/history/agents/{agent_id}/cost-timeline")).await
    }

    // ── Fleet cost comparison ─────────────────────────────────────────────────

    pub async fn fleet_compare(&self) -> Result<Value> {
        self.get("/history/fleet/compare").await
    }

    // ── Anomalies (from ConnectorOS) ──────────────────────────────────────────

    pub async fn anomalies(&self) -> Result<Value> {
        self.get("/monitor/anomalies/v2").await
    }

    // ── Budget alerts ─────────────────────────────────────────────────────────

    pub async fn budget_alerts(&self) -> Result<Value> {
        self.get("/monitor/budget-alerts").await
    }

    // ── Forecasting ───────────────────────────────────────────────────────────

    pub async fn capacity_forecast(&self) -> Result<Value> {
        self.get("/monitor/forecast").await
    }

    pub async fn agent_budget_forecast(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/insights/budget-forecast/{agent_id}")).await
    }

    // ── Rightsizing / model recommendations ──────────────────────────────────

    pub async fn model_recommendation(&self, agent_id: &str) -> Result<Value> {
        self.get(&format!("/insights/model-recommendation/{agent_id}")).await
    }

    pub async fn apply_fix(&self, rec_id: &str) -> Result<Value> {
        self.post(&format!("/insights/apply-fix/{rec_id}"), &serde_json::json!({})).await
    }

    // ── Raw usage export (sync from ConnectorOS) ──────────────────────────────

    pub async fn usage_export(&self, from: Option<&str>, to: Option<&str>) -> Result<Vec<ConnectorUsageRecord>> {
        let mut path = "/monitor/usage-export".to_string();
        let mut parts = vec![];
        if let Some(f) = from { parts.push(format!("from={f}")); }
        if let Some(t) = to   { parts.push(format!("to={t}")); }
        if !parts.is_empty() { path = format!("{}?{}", path, parts.join("&")); }

        let val = self.get(&path).await?;
        if val.is_null() { return Ok(vec![]); }
        serde_json::from_value(val).context("parse usage records")
    }

    // ── Experiment cost comparison (Ship / A/B) ───────────────────────────────

    pub async fn experiment_cost_compare(&self, exp_id: &str) -> Result<Value> {
        self.get(&format!("/experiments/{exp_id}/compare-cost")).await
    }
}

// ── ConnectorOS response types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorUsageRecord {
    pub id:            Option<String>,
    pub agent_id:      String,
    pub model:         Option<String>,
    pub provider:      Option<String>,
    pub input_tokens:  Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens:  Option<i64>,
    pub cost_usd:      Option<f64>,
    pub timestamp:     Option<String>,
}
