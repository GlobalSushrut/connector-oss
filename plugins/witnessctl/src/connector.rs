use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::AppError;

fn pct_path_seg(s: &str) -> String {
    s.bytes().fold(String::new(), |mut acc, b| {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => acc.push(b as char),
            _ => acc.push_str(&format!("%{:02X}", b)),
        }
        acc
    })
}

#[derive(Clone)]
pub struct ConnectorClient {
    client: Client,
    base_url: String,
    api_key: String,
}

#[derive(Debug, Clone)]
pub struct LicenseStatus {
    pub tier: String,
    pub max_agents: Option<usize>,
    pub current_agents: Option<usize>,
}

// ── Connector response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentResponse {
    pub pid: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub registered: Option<bool>,
}

/// Matches `POST /api/v1/firewall/inspect` (`firewall_config::inspect_content`).
/// Extra fields from older clients are ignored; missing optional fields default.
#[derive(Debug, Deserialize)]
pub struct FirewallResponse {
    pub blocked: bool,
    #[serde(default)]
    pub final_decision: Option<String>,
    #[serde(default)]
    pub pii_detected: bool,
    #[serde(default)]
    pub injection_detected: bool,
    #[serde(default)]
    pub layers: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyCheckResponse {
    pub verdict: String,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MemoryWriteResponse {
    pub cid: String,
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct MemoryRecallResponse {
    pub packets: Vec<Value>,
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub proof_id: String,
    pub chain_verified: bool,
    pub receipt_count: u64,
    pub journal_entries: u64,
    pub chains: Value,
}

#[derive(Debug, Deserialize)]
pub struct AuditRecordResponse {
    pub ok: bool,
    pub decision_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptResponse {
    pub receipt_id: String,
    pub cid: String,
    pub timestamp: String,
}

impl ConnectorClient {
    pub fn new(base_url: &str, api_key: &str) -> Self {
        ConnectorClient {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    // ── Agent registration ──────────────────────────────────────────────────

    pub async fn register_agent(
        &self,
        name: &str,
        description: &str,
        clearance: i32,
    ) -> Result<AgentResponse, AppError> {
        // Reuse by exact agent name only (stable names from SessionManager) so restarts do not burn lab slots
        // and we never accidentally bind another tenant's witnessctl-tagged agent.
        if let Ok(list_resp) = self
            .client
            .get(format!("{}/api/v1/agents", self.base_url))
            .header("Authorization", self.auth_header())
            .send()
            .await
        {
            if list_resp.status().is_success() {
                if let Ok(body) = list_resp.json::<serde_json::Value>().await {
                    let agents = body.get("agents").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    if let Some(agent) = agents.iter().find(|a| {
                        a.get("name").and_then(|v| v.as_str()) == Some(name)
                    }) {
                        if let Some(pid) = agent.get("pid").and_then(|v| v.as_str()) {
                            tracing::info!("Reusing existing Connector agent by name '{}': {}", name, pid);
                            return Ok(AgentResponse {
                                pid: pid.to_string(),
                                namespace: agent.get("namespace").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                session_token: None,
                                registered: Some(true),
                            });
                        }
                    }
                }
            }
        }

        // No reusable agent found — register fresh
        let resp = self
            .client
            .post(format!("{}/api/v1/agents", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "name": name,
                "namespace": format!("witnessctl/{}", name),
                "description": description,
                "clearance": clearance,
                "tags": ["witnessctl"]
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            // Agent limit reached — try to reuse the first available pid from the error hint
            if status.as_u16() == 503 || text.contains("agent_limit_reached") {
                let hint: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                let candidates = hint.get("reusable_candidates")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if let Some(pid) = candidates {
                    tracing::warn!("Agent limit reached — reusing candidate pid: {}", pid);
                    return Ok(AgentResponse {
                        pid,
                        namespace: Some(format!("witnessctl/{}", name)),
                        session_token: None,
                        registered: Some(true),
                    });
                }
            }
            return Err(AppError::ConnectorError(format!("register_agent: {}", text)));
        }

        resp.json::<AgentResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("register_agent parse: {}", e))
        })
    }

    // ── Firewall inspection ─────────────────────────────────────────────────

    pub async fn firewall_inspect(
        &self,
        agent_pid: &str,
        content: &str,
        namespace: &str,
    ) -> Result<FirewallResponse, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/firewall/inspect", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "agent_pid": agent_pid,
                "content": content,
                "namespace": namespace,
                "checks": ["pii", "injection", "exfiltration"]
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!("firewall_inspect: {}", text)));
        }

        resp.json::<FirewallResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("firewall_inspect parse: {}", e))
        })
    }

    /// `GET /api/v1/kernel/agents/:pid/status` — `data` object or `None` if not attached.
    pub async fn get_kernel_agent_status(&self, agent_pid: &str) -> Result<Option<Value>, AppError> {
        let enc = pct_path_seg(agent_pid);
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/kernel/agents/{}/status",
                self.base_url, enc
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!(
                "get_kernel_agent_status: {}",
                text
            )));
        }
        let body: Value = resp.json().await.map_err(|e| {
            AppError::ConnectorError(format!("get_kernel_agent_status parse: {}", e))
        })?;
        Ok(body.get("data").cloned())
    }

    // ── Policy / admission gate ─────────────────────────────────────────────

    pub async fn policy_check(
        &self,
        agent_pid: &str,
        action: &str,
        resource: &str,
    ) -> Result<PolicyCheckResponse, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/governance/policy-check", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "agent_pid": agent_pid,
                "action": action,
                "resource": resource
            }))
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::warn!("Connector policy-check endpoint not found — defaulting to allow");
            return Ok(PolicyCheckResponse {
                verdict: "allow".to_string(),
                reason: Some("policy_check endpoint unavailable — local allow".to_string()),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!("policy_check returned {} — defaulting to allow: {}", status, text);
            return Ok(PolicyCheckResponse {
                verdict: "allow".to_string(),
                reason: Some(format!("policy_check degraded ({}) — local allow", status)),
            });
        }

        resp.json::<PolicyCheckResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("policy_check parse: {}", e))
        })
    }

    // ── Memory write ────────────────────────────────────────────────────────

    pub async fn write_memory(
        &self,
        agent_pid: &str,
        content: &str,
        ptype: &str,
        memory_type: &str,
        tags: &[&str],
    ) -> Result<MemoryWriteResponse, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/memory/write", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "agent_pid": agent_pid,
                "content": content,
                "ptype": ptype,
                "memory_type": memory_type,
                "tags": tags
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!("write_memory: {}", text)));
        }

        resp.json::<MemoryWriteResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("write_memory parse: {}", e))
        })
    }

    // ── Memory recall ───────────────────────────────────────────────────────

    pub async fn recall_memory(
        &self,
        namespace: &str,
        limit: usize,
        memory_type: Option<&str>,
    ) -> Result<MemoryRecallResponse, AppError> {
        let mut url = format!(
            "{}/api/v1/memory/recall?namespace={}&limit={}",
            self.base_url, namespace, limit
        );
        if let Some(mt) = memory_type {
            url.push_str(&format!("&memory_type={}", mt));
        }

        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!("recall_memory: {}", text)));
        }

        resp.json::<MemoryRecallResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("recall_memory parse: {}", e))
        })
    }

    // ── Audit record ────────────────────────────────────────────────────────

    pub async fn record_decision(
        &self,
        agent_pid: &str,
        action: &str,
        target: &str,
        outcome: &str,
        rationale: Option<&str>,
        regulations: &[&str],
    ) -> Result<AuditRecordResponse, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/audit/decision", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "agent_pid": agent_pid,
                "action": action,
                "target": target,
                "outcome": outcome,
                "rationale": rationale,
                "regulations": regulations
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!("record_decision non-200: {}", text);
            return Ok(AuditRecordResponse { ok: false, decision_id: None });
        }

        resp.json::<AuditRecordResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("record_decision parse: {}", e))
        })
    }

    // ── Proof / receipt ─────────────────────────────────────────────────────

    pub async fn generate_proof(
        &self,
        agent_pid: &str,
        title: &str,
    ) -> Result<ProofBundle, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/proof/generate", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({ "agent_pid": agent_pid, "title": title }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!("generate_proof: {}", text)));
        }

        resp.json::<ProofBundle>().await.map_err(|e| {
            AppError::ConnectorError(format!("generate_proof parse: {}", e))
        })
    }

    pub async fn issue_receipt(
        &self,
        agent_pid: &str,
        event_type: &str,
        payload: &Value,
        prev_receipt_id: Option<&str>,
    ) -> Result<ReceiptResponse, AppError> {
        let resp = self
            .client
            .post(format!("{}/api/v1/audit/receipt", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "agent_pid": agent_pid,
                "event_type": event_type,
                "payload": payload,
                "prev_receipt_id": prev_receipt_id
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorError(format!("issue_receipt: {}", text)));
        }

        resp.json::<ReceiptResponse>().await.map_err(|e| {
            AppError::ConnectorError(format!("issue_receipt parse: {}", e))
        })
    }

    // ── Health check ────────────────────────────────────────────────────────

    pub async fn health_check(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url))
            .header("Authorization", self.auth_header())
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    pub async fn validate_access_key(&self) -> Result<(), AppError> {
        let candidates = [
            format!("{}/api/v1/aapi/capabilities", self.base_url),
            format!("{}/aapi/capabilities", self.base_url),
            format!("{}/health", self.base_url),
        ];
        let mut last_err = None;
        for url in candidates {
            let resp = self
                .client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => last_err = Some(format!("{} -> {}", url, r.status())),
                Err(e) => last_err = Some(format!("{} -> {}", url, e)),
            }
        }
        Err(AppError::ConnectorError(format!(
            "Connector access key validation failed: {}",
            last_err.unwrap_or_else(|| "unknown".to_string())
        )))
    }

    pub async fn get_license_status(&self) -> Result<LicenseStatus, AppError> {
        let candidates = [
            format!("{}/api/v1/license/status", self.base_url),
            format!("{}/license/status", self.base_url),
        ];
        let mut last_err = None;
        for url in candidates {
            let resp = self
                .client
                .get(&url)
                .header("Authorization", self.auth_header())
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let body: serde_json::Value = r
                        .json()
                        .await
                        .map_err(|e| AppError::ConnectorError(format!("license parse: {}", e)))?;
                    let tier = body
                        .get("tier")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let max_agents = body
                        .get("limits")
                        .and_then(|v| v.get("max_agents"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as usize)
                        .or_else(|| body.get("max_agents").and_then(|v| v.as_u64()).map(|v| v as usize));
                    let current_agents = body
                        .get("usage")
                        .and_then(|v| v.get("agents"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as usize)
                        .or_else(|| body.get("current_agents").and_then(|v| v.as_u64()).map(|v| v as usize));
                    return Ok(LicenseStatus {
                        tier,
                        max_agents,
                        current_agents,
                    });
                }
                Ok(r) => {
                    // 404 = endpoint not present in this Connector build — degrade gracefully
                    if r.status() == reqwest::StatusCode::NOT_FOUND {
                        tracing::warn!(
                            "Connector license endpoint not found ({}), defaulting to free tier",
                            url
                        );
                        return Ok(LicenseStatus {
                            tier: "free".to_string(),
                            max_agents: Some(10),
                            current_agents: Some(0),
                        });
                    }
                    last_err = Some(format!("{} -> {}", url, r.status()));
                }
                Err(e) => last_err = Some(format!("{} -> {}", url, e)),
            }
        }
        // All attempts failed — degrade gracefully instead of killing startup
        tracing::warn!(
            "License status lookup failed ({}), proceeding with free-tier defaults",
            last_err.as_deref().unwrap_or("unknown")
        );
        Ok(LicenseStatus {
            tier: "free".to_string(),
            max_agents: Some(10),
            current_agents: Some(0),
        })
    }

    // ── Compliance report ───────────────────────────────────────────────────

    pub async fn get_regulation_report(
        &self,
        regulation: &str,
        agent_pid: &str,
    ) -> Result<Value, AppError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/v1/compliance/report?regulation={}&agent_pid={}",
                self.base_url, regulation, agent_pid
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!("get_regulation_report non-200: {}", text);
            return Ok(json!({ "ok": false, "regulation": regulation }));
        }

        resp.json::<Value>().await.map_err(|e| {
            AppError::ConnectorError(format!("get_regulation_report parse: {}", e))
        })
    }

    // ── Decision Pentest Capabilities (Connector OS) ─────────────────────────

    /// Fetch the full per-decision pentest payload from Connector OS.
    /// Returns the raw JSON; WitnessCtl assembles DecisionPentestReport from it.
    /// Falls back gracefully if the endpoint is not available in this Connector build.
    pub async fn get_decision_pentest(
        &self,
        trace_id: &str,
        agent_pid: Option<&str>,
    ) -> Result<Value, AppError> {
        let mut url = format!(
            "{}/api/v1/pentest/decision/{}",
            self.base_url, trace_id
        );
        if let Some(pid) = agent_pid {
            url = format!("{}?agent_pid={}", url, pid);
        }
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                r.json::<Value>().await.map_err(|e| {
                    AppError::ConnectorError(format!("get_decision_pentest parse: {}", e))
                })
            }
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                tracing::warn!(
                    "Connector pentest endpoint not found for trace_id={} — returning empty pentest",
                    trace_id
                );
                Ok(json!({ "ok": false, "trace_id": trace_id, "connector_available": false }))
            }
            Ok(r) => {
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                tracing::warn!("get_decision_pentest {}: {}", status, text);
                Ok(json!({ "ok": false, "trace_id": trace_id, "connector_available": false, "error": text }))
            }
            Err(e) => {
                tracing::warn!("get_decision_pentest request failed: {}", e);
                Ok(json!({ "ok": false, "trace_id": trace_id, "connector_available": false, "error": e.to_string() }))
            }
        }
    }

    /// Fetch the tokenization trace for a decision from Connector OS.
    pub async fn get_tokenization_trace(
        &self,
        trace_id: &str,
    ) -> Result<Value, AppError> {
        let url = format!(
            "{}/api/v1/pentest/tokenization/{}",
            self.base_url, trace_id
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                r.json::<Value>().await.map_err(|e| {
                    AppError::ConnectorError(format!("get_tokenization_trace parse: {}", e))
                })
            }
            Ok(_) | Err(_) => {
                Ok(json!({ "ok": false, "trace_id": trace_id, "steps": [] }))
            }
        }
    }

    /// Fetch decision stability + memory infection verdict from Connector OS.
    pub async fn get_decision_stability(
        &self,
        trace_id: &str,
    ) -> Result<Value, AppError> {
        let url = format!(
            "{}/api/v1/pentest/stability/{}",
            self.base_url, trace_id
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                r.json::<Value>().await.map_err(|e| {
                    AppError::ConnectorError(format!("get_decision_stability parse: {}", e))
                })
            }
            Ok(_) | Err(_) => {
                Ok(json!({ "ok": false, "trace_id": trace_id, "verdict": "unknown" }))
            }
        }
    }
}
