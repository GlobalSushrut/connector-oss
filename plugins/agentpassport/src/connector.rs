//! ConnectorOS kernel bridge.
//!
//! Thin async HTTP client wrapping the ConnectorOS REST API.
//! AgentPassport uses ConnectorOS for:
//!   - Fetching live trust scores
//!   - Quarantining / terminating agents
//!   - Fetching agent DID + agent card
//!   - Recording interaction counts
//!   - Fetching provenance / defense packages

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub base_url: String,
    pub api_key:  String,
}

impl ConnectorConfig {
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("CONNECTOR_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            api_key: std::env::var("CONNECTOR_API_KEY")
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorClient {
    client: Client,
    config: ConnectorConfig,
}

#[derive(Debug, Deserialize)]
pub struct TrustResponse {
    pub trust_score: Option<f64>,
    pub violations:  Option<i64>,
    pub status:      Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DidResponse {
    pub did:        Option<String>,
    pub agent_card: Option<Value>,
}

#[derive(Debug, Serialize)]
struct QuarantinePayload {
    reason: String,
}

impl ConnectorClient {
    pub fn new(config: ConnectorConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(format!("agentpassport/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self { client, config })
    }

    pub async fn health(&self) -> Result<()> {
        let url = format!("{}/health", self.config.base_url);
        let resp = self.client.get(&url)
            .header("X-API-Key", &self.config.api_key)
            .send().await.context("health check")?;
        if resp.status().is_success() { Ok(()) }
        else { anyhow::bail!("ConnectorOS health: {}", resp.status()) }
    }

    pub async fn get_trust(&self, pid: &str) -> Result<TrustResponse> {
        let url = format!("{}/monitor/trust?pid={}", self.config.base_url, pid);
        let resp = self.client.get(&url)
            .header("X-API-Key", &self.config.api_key)
            .send().await.context("get trust")?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(TrustResponse { trust_score: None, violations: None, status: None });
        }
        resp.json().await.context("parse trust response")
    }

    pub async fn get_did_and_card(&self, pid: &str) -> Result<DidResponse> {
        let did_url  = format!("{}/tools/agents/{}/did",  self.config.base_url, pid);
        let card_url = format!("{}/tools/agents/{}/card", self.config.base_url, pid);

        let (did_resp, card_resp) = tokio::join!(
            self.client.get(&did_url).header("X-API-Key", &self.config.api_key).send(),
            self.client.get(&card_url).header("X-API-Key", &self.config.api_key).send(),
        );

        let did = did_resp.ok()
            .and_then(|r| if r.status().is_success() { Some(r) } else { None })
            .and_then(|r| tokio::runtime::Handle::current().block_on(r.json::<Value>()).ok())
            .and_then(|v| v.get("did").and_then(|d| d.as_str()).map(String::from));

        let agent_card = card_resp.ok()
            .and_then(|r| if r.status().is_success() { Some(r) } else { None })
            .and_then(|r| tokio::runtime::Handle::current().block_on(r.json::<Value>()).ok());

        Ok(DidResponse { did, agent_card })
    }

    pub async fn quarantine_agent(&self, pid: &str, reason: &str) -> Result<()> {
        let url = format!("{}/agents/{}/quarantine", self.config.base_url, pid);
        let resp = self.client.post(&url)
            .header("X-API-Key", &self.config.api_key)
            .json(&QuarantinePayload { reason: reason.to_string() })
            .send().await.context("quarantine agent")?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            anyhow::bail!("quarantine failed: {}", resp.status())
        }
    }

    pub async fn terminate_agent(&self, pid: &str, reason: &str) -> Result<()> {
        let url = format!("{}/agents/{}/terminate", self.config.base_url, pid);
        let resp = self.client.post(&url)
            .header("X-API-Key", &self.config.api_key)
            .json(&serde_json::json!({ "reason": reason }))
            .send().await.context("terminate agent")?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            anyhow::bail!("terminate failed: {}", resp.status())
        }
    }

    pub async fn get_trust_trend(&self, pid: &str) -> Result<Value> {
        let url = format!("{}/monitor/trust-trend?pid={}", self.config.base_url, pid);
        let resp = self.client.get(&url)
            .header("X-API-Key", &self.config.api_key)
            .send().await.context("trust trend")?;
        if !resp.status().is_success() {
            return Ok(serde_json::json!([]));
        }
        resp.json().await.context("parse trust trend")
    }

    pub async fn get_defense_package(&self, agent_pid: &str) -> Result<Value> {
        let url = format!("{}/agents/{}/defense-package", self.config.base_url, agent_pid);
        let resp = self.client.get(&url)
            .header("X-API-Key", &self.config.api_key)
            .send().await.context("defense package")?;
        if !resp.status().is_success() {
            return Ok(serde_json::json!(null));
        }
        resp.json().await.context("parse defense package")
    }
}
