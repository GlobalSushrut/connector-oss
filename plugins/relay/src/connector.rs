//! ConnectorOS kernel bridge for Relay.
//! Wraps: RBAC auth, admission gate, budget gate, memory kernel,
//! MCP tool listing, audit log, AgentPassport DID, HIPAA scrub.

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

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthVerifyResponse {
    pub valid:   bool,
    pub role:    Option<String>,
    pub org_id:  Option<String>,
    pub budget_remaining_usd: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct AdmissionResponse {
    pub verdict:    String,   // "ALLOW" | "DENY" | "REDACT"
    pub reason:     Option<String>,
    pub redacted:   Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct BudgetCheckResponse {
    pub allowed:     bool,
    pub remaining:   Option<f64>,
    pub resets_at:   Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MemoryContextResponse {
    pub entries: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct McpToolsResponse {
    pub tools: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct AgentPassportResponse {
    pub did:   String,
    pub key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HipaaScrubbedResponse {
    pub content: Value,
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectorHealth {
    pub status: String,
}

// ── Token/cost extract from LLM proxy headers ─────────────────────────────────

#[derive(Debug, Default)]
pub struct LlmUsage {
    pub tokens_in:  i32,
    pub tokens_out: i32,
    pub cost_usd:   f64,
    pub model_used: Option<String>,
}

impl ConnectorClient {
    pub fn new(cfg: ConnectorConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(format!("relay/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("Failed to build Relay HTTP client")?;

        Ok(Self {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_owned(),
            api_key:  cfg.api_key,
        })
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    pub async fn health(&self) -> Result<ConnectorHealth> {
        self.http
            .get(format!("{}/health", self.base_url))
            .header("Authorization", self.auth())
            .send().await?
            .json::<ConnectorHealth>().await
            .context("Connector health failed")
    }

    /// Verify an API key via Connector RBAC.
    pub async fn verify_key(&self, api_key: &str) -> Result<AuthVerifyResponse> {
        let resp = self.http
            .get(format!("{}/auth/verify", self.base_url))
            .header("Authorization", format!("Bearer {api_key}"))
            .send().await
            .context("verify_key request failed")?;

        if !resp.status().is_success() {
            return Ok(AuthVerifyResponse {
                valid: false, role: None, org_id: None, budget_remaining_usd: None,
            });
        }

        resp.json::<AuthVerifyResponse>().await
            .context("Failed to parse auth response")
    }

    /// Run Connector admission gate on the incoming payload.
    pub async fn admission_check(
        &self,
        content:  &Value,
        function: &str,
    ) -> Result<AdmissionResponse> {
        let body = json!({ "content": content, "function": function });

        let resp = self.http
            .post(format!("{}/admission/check", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("admission_check failed")?;

        if !resp.status().is_success() {
            // Connector unavailable → allow with warning
            tracing::warn!(function = function, "Admission gate unavailable — allowing");
            return Ok(AdmissionResponse {
                verdict: "ALLOW".into(), reason: Some("admission_gate_unavailable".into()), redacted: None,
            });
        }

        resp.json::<AdmissionResponse>().await
            .context("Failed to parse admission response")
    }

    /// Check per-function budget against Connector metering.
    pub async fn budget_check(
        &self,
        function:      &str,
        org_id:        Option<&str>,
        per_day_usd:   Option<f64>,
    ) -> Result<BudgetCheckResponse> {
        let body = json!({
            "function":    function,
            "org_id":      org_id,
            "per_day_usd": per_day_usd,
        });

        let resp = self.http
            .post(format!("{}/metering/check", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("budget_check failed")?;

        if !resp.status().is_success() {
            // Connector unavailable → allow
            return Ok(BudgetCheckResponse {
                allowed: true, remaining: None, resets_at: None,
            });
        }

        resp.json::<BudgetCheckResponse>().await
            .context("Failed to parse budget response")
    }

    /// Fetch persistent memory context for an agent DID.
    pub async fn get_memory_context(
        &self,
        agent_did: &str,
        limit:     i32,
    ) -> Result<MemoryContextResponse> {
        let resp = self.http
            .get(format!("{}/memory/agent", self.base_url))
            .header("Authorization", self.auth())
            .query(&[("did", agent_did), ("limit", &limit.to_string())])
            .send().await
            .context("get_memory_context failed")?;

        if !resp.status().is_success() {
            return Ok(MemoryContextResponse { entries: vec![] });
        }

        resp.json::<MemoryContextResponse>().await
            .context("Failed to parse memory context")
    }

    /// Get filtered tool list from Connector MCP server.
    pub async fn get_tools(&self, allowed: &[String]) -> Result<McpToolsResponse> {
        let resp = self.http
            .get(format!("{}/mcp/tools", self.base_url))
            .header("Authorization", self.auth())
            .query(&[("allowed", &allowed.join(","))])
            .send().await
            .context("get_tools failed")?;

        if !resp.status().is_success() {
            return Ok(McpToolsResponse { tools: vec![] });
        }

        resp.json::<McpToolsResponse>().await
            .context("Failed to parse tools")
    }

    /// Register or fetch the AgentPassport DID for a function.
    pub async fn ensure_passport(&self, function_name: &str) -> Result<AgentPassportResponse> {
        let body = json!({
            "name":  format!("relay/{function_name}"),
            "kind":  "function",
            "relay": true,
        });

        let resp = self.http
            .post(format!("{}/agentpassport/register", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("ensure_passport failed")?;

        if !resp.status().is_success() {
            // Passport unavailable — generate a synthetic DID
            return Ok(AgentPassportResponse {
                did: format!("did:connector:relay/{function_name}"),
                key_id: None,
            });
        }

        resp.json::<AgentPassportResponse>().await
            .context("Failed to parse passport response")
    }

    /// HIPAA-scrub a response body.
    pub async fn hipaa_scrub(&self, content: &Value) -> Result<HipaaScrubbedResponse> {
        let body = json!({ "content": content });

        let resp = self.http
            .post(format!("{}/hipaa/scrub", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("hipaa_scrub failed")?;

        if !resp.status().is_success() {
            return Ok(HipaaScrubbedResponse {
                content: content.clone(),
                redacted_fields: vec![],
            });
        }

        resp.json::<HipaaScrubbedResponse>().await
            .context("Failed to parse hipaa scrub response")
    }

    /// Write audit journal entry to WitnessCtl.
    pub async fn write_audit(
        &self,
        event_type:    &str,
        function_name: &str,
        agent_did:     Option<&str>,
        payload:       Value,
    ) -> Result<String> {
        let body = json!({
            "event_type":  event_type,
            "agent_pid":   agent_did.unwrap_or(function_name),
            "namespace":   format!("relay/{function_name}"),
            "payload":     payload,
        });

        let resp = self.http
            .post(format!("{}/api/v1/books/journal", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await
            .context("write_audit failed")?;

        if !resp.status().is_success() {
            return Ok(String::new());
        }

        let v: Value = resp.json().await.context("Failed to parse audit response")?;
        Ok(v["audit_cid"].as_str().unwrap_or("").to_owned())
    }

    /// Record cost to Connector ledger.
    pub async fn record_cost(
        &self,
        function_name: &str,
        tokens_in:     i32,
        tokens_out:    i32,
        cost_usd:      f64,
        model:         Option<&str>,
    ) -> Result<()> {
        let body = json!({
            "function":   function_name,
            "tokens_in":  tokens_in,
            "tokens_out": tokens_out,
            "cost_usd":   cost_usd,
            "model":      model,
        });

        let _ = self.http
            .post(format!("{}/metering/record", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await;

        Ok(())
    }

    /// Write a memory update from the function's response.
    pub async fn write_memory(
        &self,
        agent_did: &str,
        entries:   &Value,
    ) -> Result<()> {
        let body = json!({ "did": agent_did, "entries": entries });
        let _ = self.http
            .post(format!("{}/memory/agent", self.base_url))
            .header("Authorization", self.auth())
            .json(&body)
            .send().await;
        Ok(())
    }
}
