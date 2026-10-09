//! ConnectorOS kernel bridge.
//!
//! Wraps the Connector memory kernel, namespace isolation, dehallucination chain,
//! and audit log APIs. Engram builds all of its intelligence on top of these
//! primitives — no re-implementation of what the kernel already provides.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct ConnectorClient {
    http:     reqwest::Client,
    base_url: String,
    api_key:  String,
}

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub base_url: String,
    pub api_key:  String,
}

impl ConnectorConfig {
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("CONNECTOR_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            api_key: std::env::var("CONNECTOR_API_KEY")
                .unwrap_or_default(),
        }
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MemPacket {
    pub cid:         String,
    pub content:     String,
    pub namespace:   String,
    pub memory_type: String,
    pub tags:        Vec<String>,
    pub score:       Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct WriteMemoryResponse {
    pub cid: String,
}

#[derive(Debug, Deserialize)]
pub struct RecallResponse {
    pub packets: Vec<MemPacket>,
}

#[derive(Debug, Deserialize)]
pub struct InterferenceResult {
    pub contradictions: Vec<Contradiction>,
    pub count: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Contradiction {
    pub a:     String,
    pub b:     String,
    pub score: f64,
}

#[derive(Debug, Deserialize)]
pub struct DehallResult {
    pub claim_text:      String,
    pub grounding_score: f64,
    pub source_cids:     Vec<String>,
    pub grounded:        bool,
}

#[derive(Debug, Deserialize)]
pub struct DehallResponse {
    pub results:  Vec<DehallResult>,
    pub chain_cid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectorHealth {
    pub status: String,
}

// ── Client impl ───────────────────────────────────────────────────────────────

impl ConnectorClient {
    pub fn new(cfg: ConnectorConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(format!("engram/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_owned(),
            api_key:  cfg.api_key,
        })
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    /// Verify Connector kernel is reachable.
    pub async fn health(&self) -> Result<ConnectorHealth> {
        let resp = self.http
            .get(format!("{}/health", self.base_url))
            .header("Authorization", self.auth())
            .send().await
            .context("Connector health check failed")?
            .json::<ConnectorHealth>().await
            .context("Failed to parse health response")?;
        Ok(resp)
    }

    /// Write a memory packet to the Connector kernel.
    pub async fn write_memory(
        &self,
        agent_pid:   &str,
        namespace:   &str,
        content:     &str,
        memory_type: &str,
        tags:        &[String],
        entity_kind: Option<&str>,
        session_id:  Option<&str>,
    ) -> Result<WriteMemoryResponse> {
        let mut body = json!({
            "agent_pid":   agent_pid,
            "namespace":   namespace,
            "content":     content,
            "memory_type": memory_type,
            "tags":        tags,
        });
        if let Some(ek) = entity_kind {
            body["entity_kind"] = json!(ek);
        }
        if let Some(sid) = session_id {
            body["session_id"] = json!(sid);
        }

        let resp = self.http
            .post(format!("{}/api/v1/memory", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("write_memory request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Connector write_memory {status}: {text}");
        }

        resp.json::<WriteMemoryResponse>().await
            .context("Failed to parse write_memory response")
    }

    /// Semantic recall from the Connector kernel.
    pub async fn recall_memory(
        &self,
        namespace:   &str,
        query:       &str,
        top_k:       i32,
        memory_type: Option<&str>,
    ) -> Result<RecallResponse> {
        let mut body = json!({
            "namespace": namespace,
            "query":     query,
            "top_k":     top_k,
        });
        if let Some(mt) = memory_type {
            body["memory_type"] = json!(mt);
        }

        let resp = self.http
            .post(format!("{}/api/v1/memory/search", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("recall_memory request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Connector recall_memory {status}: {text}");
        }

        resp.json::<RecallResponse>().await
            .context("Failed to parse recall_memory response")
    }

    /// Get contradiction pairs for a namespace (entropy contradiction component).
    pub async fn get_interference(
        &self,
        namespace: &str,
    ) -> Result<InterferenceResult> {
        let resp = self.http
            .get(format!("{}/api/v1/memory/interference", self.base_url))
            .header("Authorization", self.auth())
            .query(&[("namespace", namespace)])
            .send().await
            .context("get_interference request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Connector get_interference {status}: {text}");
        }

        resp.json::<InterferenceResult>().await
            .context("Failed to parse interference response")
    }

    /// Run Connector's dehallucination chain (Chain 3) against a set of claims.
    pub async fn ground_claims(
        &self,
        namespace:  &str,
        claims:     &[String],
        threshold:  f64,
    ) -> Result<DehallResponse> {
        let body = json!({
            "namespace": namespace,
            "claims":    claims,
            "threshold": threshold,
        });

        let resp = self.http
            .post(format!("{}/api/v1/memory/ground", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("ground_claims request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Connector ground_claims {status}: {text}");
        }

        resp.json::<DehallResponse>().await
            .context("Failed to parse ground_claims response")
    }

    /// Write an audit journal entry (WitnessCtl / books.rs).
    pub async fn write_audit(
        &self,
        event_type: &str,
        agent_id:   &str,
        namespace:  &str,
        payload:    Value,
    ) -> Result<String> {
        let body = json!({
            "event_type": event_type,
            "agent_pid":  agent_id,
            "namespace":  namespace,
            "payload":    payload,
        });

        let resp = self.http
            .post(format!("{}/api/v1/books/journal", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("write_audit request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Connector write_audit {status}: {text}");
        }

        let v: Value = resp.json().await.context("Failed to parse audit response")?;
        Ok(v["audit_cid"].as_str().unwrap_or("").to_owned())
    }

    /// Count total memory packets in a namespace (for redundancy/stale scoring).
    pub async fn count_namespace_packets(
        &self,
        namespace: &str,
    ) -> Result<i64> {
        let resp = self.http
            .get(format!("{}/api/v1/memory/stats", self.base_url))
            .header("Authorization", self.auth())
            .query(&[("namespace", namespace)])
            .send().await
            .context("count_namespace_packets request failed")?;

        if !resp.status().is_success() {
            return Ok(0);
        }

        let v: Value = resp.json().await.context("Failed to parse stats")?;
        Ok(v["total_packets"].as_i64().unwrap_or(0))
    }
}
