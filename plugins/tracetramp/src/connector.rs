//! Connector API client
//!
//! Thin client for calling Connector kernel endpoints

use reqwest::{Client, Response};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::error::AppError;
use crate::types::{ChatCompletionRequest, RuntimeExecutionRequest};

#[derive(Clone)]
pub struct ConnectorClient {
    client: Client,
    base_url: String,
    api_key: String,
}

#[derive(Debug, Clone)]
pub struct ConnectorIdentity {
    pub tenant_id: String,
    pub actor_id: String,
    pub actor_role: String,
}

fn pct_path_seg(s: &str) -> String {
    s.bytes().fold(String::new(), |mut acc, b| {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                acc.push(b as char)
            }
            _ => acc.push_str(&format!("%{:02X}", b)),
        }
        acc
    })
}

/// Fail closed when Connector admission/policy is unreachable unless explicitly in lab mode.
fn governance_fail_closed() -> bool {
    if std::env::var("TRACETRAMP_FAIL_CLOSED")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        return true;
    }
    if std::env::var("TRACETRAMP_ALLOW_FAIL_OPEN")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        return false;
    }
    matches!(
        std::env::var("CONNECTOR_ENV")
            .or_else(|_| std::env::var("TRACETRAMP_ENV"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "pilots" | "pilot" | "staging"
    )
}

impl ConnectorClient {
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(100)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// TraceTramp management plane (admin API). Derived from Connector URL unless overridden.
    /// Use when Connector is on a mapped host port (e.g. Docker `19735:9735` → set
    /// `TRACETRAMP_MANAGEMENT_BASE_URL=http://127.0.0.1:19742`).
    /// Public URL for admin / management API (same logic as internal `management_plane_base`).
    pub fn management_plane_url(&self) -> String {
        self.management_plane_base()
    }

    fn management_plane_base(&self) -> String {
        if let Ok(url) = std::env::var("TRACETRAMP_MANAGEMENT_BASE_URL") {
            let u = url.trim();
            if !u.is_empty() {
                return u.trim_end_matches('/').to_string();
            }
        }
        if let Ok(port) = std::env::var("TRACETRAMP_MANAGEMENT_PLANE_PORT") {
            let p = port.trim();
            if !p.is_empty() {
                return format!("http://127.0.0.1:{}", p);
            }
        }
        self.base_url
            .replace(":9091", ":9742")
            .replace(":9735", ":9742")
    }

    /// TraceTramp data plane (gateway / enforcement reads).
    fn data_plane_base(&self) -> String {
        if let Ok(url) = std::env::var("TRACETRAMP_DATA_PLANE_BASE_URL") {
            let u = url.trim();
            if !u.is_empty() {
                return u.trim_end_matches('/').to_string();
            }
        }
        self.base_url
            .replace(":9091", ":9741")
            .replace(":9735", ":9741")
    }

    /// Proxy a chat completion request to the configured LLM upstream.
    ///
    /// Connector OS is not an OpenAI-compatible gateway in the premium lab; it exposes
    /// kernel/governance routes. `TRACETRAMP_UPSTREAM_OPENAI_BASE_URL` keeps LLM traffic
    /// on the lab-llm OpenAI shim while Connector can still be used for governance
    /// signals when its endpoints exist.
    pub async fn proxy_chat_completion(
        &self,
        request: &ChatCompletionRequest,
        headers: &[(String, String)],
    ) -> Result<Response, AppError> {
        let upstream_from_env = std::env::var("TRACETRAMP_UPSTREAM_OPENAI_BASE_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());
        if upstream_from_env.is_some() && governance_fail_closed() {
            return Err(AppError::Config(
                "TRACETRAMP_UPSTREAM_OPENAI_BASE_URL is forbidden in production/staging: \
                 route through Connector /v1/chat/completions so identity, charter, memory, HITL, \
                 audit, and egress controls remain mandatory"
                    .into(),
            ));
        }
        let url = match upstream_from_env {
            Some(ref upstream) => format!("{}/chat/completions", upstream),
            None => format!("{}/v1/chat/completions", self.base_url),
        };
        // When an upstream OpenAI-compatible key is configured (e.g. DeepSeek), use it.
        // Fall back to the connector API key only for the local lab-llm shim.
        let upstream_api_key = std::env::var("TRACETRAMP_UPSTREAM_OPENAI_API_KEY")
            .ok()
            .filter(|v| !v.is_empty() && v != "lab-llm-demo-key")
            .unwrap_or_else(|| self.api_key.clone());

        debug!("Proxying chat completion to upstream: {}", url);

        let mut req_builder = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", upstream_api_key));

        // Forward client headers but strip auth/identity headers that must not reach the upstream LLM.
        // Also strip accept-encoding: reqwest does not have the gzip feature compiled in, so if we
        // forward the client's "Accept-Encoding: gzip" the upstream LLM may return a compressed
        // body that reqwest cannot decompress, and we would pass raw gzip bytes to the client.
        let skip_headers: &[&str] = &[
            "authorization",
            "x-api-key",
            "x-witness-session",
            "x-agent-id",
            "x-actor-id",
            "x-scenario-tag",
            "x-provider-preference",
            "host",
            "content-length",
            "transfer-encoding",
            "accept-encoding",
        ];
        for (key, value) in headers {
            if !skip_headers.contains(&key.to_lowercase().as_str()) {
                req_builder = req_builder.header(key, value);
            }
        }

        let response = req_builder
            .json(request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Failed to proxy request: {}", e)))?;

        Ok(response)
    }

    /// Check admission gate for a request
    pub async fn check_admission(
        &self,
        request: &RuntimeExecutionRequest,
    ) -> Result<AdmissionResult, AppError> {
        debug!("Checking admission for request: {}", request.request_id);

        let response = match self
            .get_with_aapi_fallback(&format!("/aapi/capabilities/{}/verify", request.actor_id))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if governance_fail_closed() {
                    warn!("Admission check network error — fail-closed deny: {}", e);
                    return Ok(AdmissionResult {
                        allowed: false,
                        reason: Some(format!("admission_unavailable: {e}")),
                        quarantine: false,
                        policy_hits: vec!["fail_closed".into()],
                    });
                }
                warn!("Admission check network error — lab fail-open allow: {}", e);
                return Ok(AdmissionResult {
                    allowed: true,
                    reason: None,
                    quarantine: false,
                    policy_hits: vec![],
                });
            }
        };

        if response.status() == reqwest::StatusCode::NOT_FOUND || !response.status().is_success() {
            if governance_fail_closed() {
                warn!(
                    "Admission check endpoint unavailable ({}) — fail-closed deny",
                    response.status()
                );
                return Ok(AdmissionResult {
                    allowed: false,
                    reason: Some(format!(
                        "admission_unavailable_status:{}",
                        response.status()
                    )),
                    quarantine: false,
                    policy_hits: vec!["fail_closed".into()],
                });
            }
            warn!(
                "Admission check endpoint unavailable ({}) — lab fail-open allow",
                response.status()
            );
            return Ok(AdmissionResult {
                allowed: true,
                reason: None,
                quarantine: false,
                policy_hits: vec![],
            });
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let allowed = body
            .get("allowed")
            .and_then(|v| v.as_bool())
            .or_else(|| body.get("valid").and_then(|v| v.as_bool()))
            .unwrap_or(!governance_fail_closed());
        Ok(AdmissionResult {
            allowed,
            reason: body
                .get("reason")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            quarantine: body
                .get("quarantine")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            policy_hits: body
                .get("policy_hits")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// `GET /api/v1/kernel/agents/:pid/status` — returns the `data` attachment object, or `None` if not found.
    pub async fn get_kernel_agent_status(
        &self,
        agent_pid: &str,
    ) -> Result<Option<serde_json::Value>, AppError> {
        let enc = pct_path_seg(agent_pid);
        let url = format!("{}/api/v1/kernel/agents/{}/status", self.base_url, enc);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("kernel status: {}", e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::ConnectorProxy(format!(
                "kernel status {}: {}",
                status, text
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body.get("data").cloned())
    }

    /// Connector `GET /api/v1/kernel/cage-manifest` — kernel snapshot + ledger contracts for GRC / cage review.
    pub async fn get_kernel_cage_manifest(&self) -> Result<serde_json::Value, AppError> {
        let url = format!("{}/api/v1/kernel/cage-manifest", self.base_url);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("kernel cage-manifest: {}", e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::ConnectorProxy(format!(
                "kernel cage-manifest {}: {}",
                status, text
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body.get("data").cloned().unwrap_or(body))
    }

    /// Record usage in Connector billing
    pub async fn record_usage(
        &self,
        agent_pid: &str,
        tokens_in: u64,
        tokens_out: u64,
        cost_usd: f64,
    ) -> Result<(), AppError> {
        let payload = serde_json::json!({
            "agent_pid": agent_pid,
            "resource": "tokens",
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "amount": tokens_in + tokens_out,
            "cost_usd": cost_usd,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        match self
            .post_with_aapi_fallback("/aapi/budgets/consume", &payload)
            .await
        {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => {
                warn!(
                    "Usage recording returned {} — skipping (non-fatal)",
                    r.status()
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Usage recording network error — skipping (non-fatal): {}",
                    e
                );
                Ok(())
            }
        }
    }

    /// Get agent cost from Connector
    pub async fn get_agent_cost(&self, agent_pid: &str) -> Result<AgentCost, AppError> {
        let response = self
            .get_with_aapi_fallback(&format!("/aapi/budgets/{}/tokens", agent_pid))
            .await;

        let response = match response {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    "Agent cost endpoint returned {} — returning zero cost",
                    r.status()
                );
                return Ok(AgentCost {
                    agent_pid: agent_pid.to_string(),
                    total_tokens: 0,
                    total_cost_usd: 0.0,
                    current_tier: "unknown".to_string(),
                    tier_limit: 0,
                    overage: false,
                });
            }
            Err(e) => {
                warn!("Agent cost fetch error — returning zero cost: {}", e);
                return Ok(AgentCost {
                    agent_pid: agent_pid.to_string(),
                    total_tokens: 0,
                    total_cost_usd: 0.0,
                    current_tier: "unknown".to_string(),
                    tier_limit: 0,
                    overage: false,
                });
            }
        };
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let total_tokens = body
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| body.get("consumed").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let total_cost_usd = body
            .get("total_cost_usd")
            .and_then(|v| v.as_f64())
            .or_else(|| body.get("cost_usd").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        let overage = body
            .get("overage")
            .and_then(|v| v.as_bool())
            .or_else(|| {
                let remaining = body.get("remaining").and_then(|v| v.as_i64()).unwrap_or(0);
                Some(remaining <= 0 && total_tokens > 0)
            })
            .unwrap_or(false);
        Ok(AgentCost {
            agent_pid: agent_pid.to_string(),
            total_tokens,
            total_cost_usd,
            current_tier: body
                .get("tier")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            tier_limit: body.get("limit").and_then(|v| v.as_u64()).unwrap_or(0),
            overage,
        })
    }

    /// Issue a receipt for a request
    pub async fn issue_receipt(
        &self,
        request_id: &str,
        trace_id: &str,
        outcome: &str,
    ) -> Result<Receipt, AppError> {
        let payload = serde_json::json!({
            "request_id": request_id,
            "trace_id": trace_id,
            "outcome": outcome,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let response = self
            .post_with_aapi_fallback("/aapi/capabilities/issue", &payload)
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| AppError::Serialization(e.to_string()))?;
                let receipt_id = body
                    .get("receipt_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("tt_{}", trace_id));
                let cid = body
                    .get("cid")
                    .or_else(|| body.get("token"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        sha256::digest(format!(
                            "{}:{}:{}",
                            request_id,
                            trace_id,
                            chrono::Utc::now().timestamp_millis()
                        ))
                    });
                Ok(Receipt {
                    receipt_id,
                    cid,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    signature: body
                        .get("signature")
                        .and_then(|v| v.as_str())
                        .unwrap_or("connector")
                        .to_string(),
                })
            }
            Ok(resp) => {
                warn!(
                    "Connector receipt issuance failed with status {}, using local fallback",
                    resp.status()
                );
                Ok(self.local_receipt(request_id, trace_id))
            }
            Err(e) => {
                warn!(
                    "Connector receipt issuance error: {}, using local fallback",
                    e
                );
                Ok(self.local_receipt(request_id, trace_id))
            }
        }
    }

    /// Get trust score for an agent
    pub async fn get_trust_score(&self, agent_pid: &str) -> Result<TrustScore, AppError> {
        let mut response_opt = None;
        for path in ["/monitor/trust", "/api/v1/monitor/trust"] {
            let url = format!("{}{}", self.base_url, path);
            let resp = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .send()
                .await
                .map_err(|e| {
                    AppError::ConnectorProxy(format!("Failed to get trust score: {}", e))
                })?;
            if resp.status() != reqwest::StatusCode::NOT_FOUND {
                response_opt = Some(resp);
                break;
            }
            response_opt = Some(resp);
        }
        let response = response_opt.expect("at least one trust endpoint candidate");

        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            let maybe_agent = body.get(agent_pid).cloned().unwrap_or(body.clone());
            Ok(TrustScore {
                agent_pid: agent_pid.to_string(),
                score: maybe_agent
                    .get("score")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                trend: maybe_agent
                    .get("trend")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                factors: maybe_agent
                    .get("factors")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        } else {
            Err(AppError::NotFound(format!(
                "Trust score for agent {} not found",
                agent_pid
            )))
        }
    }

    /// Check policy for a request — local evaluation (no external kernel required)
    pub async fn check_policy(
        &self,
        request: &RuntimeExecutionRequest,
        policy_bundle: &str,
    ) -> Result<PolicyResult, AppError> {
        let payload = serde_json::json!({
            "request_id": request.request_id,
            "trace_id": request.trace_id,
            "tenant_id": request.tenant_id,
            "actor_id": request.actor_id,
            "environment": request.environment,
            "policy_bundle": policy_bundle,
            "input_payload": request.input_payload,
            "tools_requested": request.tools_requested,
            "output_mode": request.output_mode,
            "execution_profile": request.execution_profile,
        });

        let remote = self
            .post_with_aapi_fallback("/aapi/policies/evaluate", &payload)
            .await;

        if let Ok(resp) = remote {
            if resp.status().is_success() {
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| AppError::Serialization(e.to_string()))?;
                return Ok(PolicyResult {
                    outcome: body
                        .get("outcome")
                        .and_then(|v| v.as_str())
                        .unwrap_or("allow")
                        .to_string(),
                    reason: body
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("connector policy evaluation")
                        .to_string(),
                    routing_target: body
                        .get("routing_target")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    transform_rules: body
                        .get("transform_rules")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    approvers: body
                        .get("approvers")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                });
            }
        }

        if governance_fail_closed() {
            warn!("Connector policy pipeline unavailable — fail-closed deny");
            return Ok(PolicyResult {
                outcome: "deny".to_string(),
                reason: "fail_closed_connector_policy_unavailable".to_string(),
                routing_target: None,
                transform_rules: vec![],
                approvers: vec![],
            });
        }
        warn!("Connector policy pipeline unavailable — defaulting to allow for local/lab mode");
        Ok(PolicyResult {
            outcome: "allow".to_string(),
            reason: "local_default_allow_connector_policy_unavailable".to_string(),
            routing_target: None,
            transform_rules: vec![],
            approvers: vec![],
        })
    }

    pub async fn log_interaction(
        &self,
        request_id: &str,
        trace_id: &str,
        tenant_id: &str,
        action: &str,
        outcome: &str,
    ) -> Result<(), AppError> {
        let target = format!("trace:{}:request:{}", trace_id, request_id);
        let payload = serde_json::json!({
            "agent_pid": tenant_id,
            "itype": "trace_event",
            "target": target,
            "operation": action,
            "status": outcome,
            "duration_ms": 0,
        });
        let response = self
            .post_with_aapi_fallback("/aapi/interactions", &payload)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Interaction logging failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Interaction logging failed: {}",
                response.status()
            )))
        }
    }

    pub async fn list_interactions(
        &self,
        agent_pid: Option<&str>,
    ) -> Result<Vec<InteractionRecord>, AppError> {
        // Read from TraceTramp's own management plane, not Connector OS
        let mgmt_base = self.management_plane_base();
        let path = match agent_pid {
            Some(pid) if !pid.is_empty() => format!(
                "{}/admin/interactions?agent_pid={}&limit=200",
                mgmt_base, pid
            ),
            _ => format!("{}/admin/interactions?limit=200", mgmt_base),
        };
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Interaction list failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Interaction list failed: {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let records = body
            .get("interactions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| serde_json::from_value::<InteractionRecord>(v).ok())
            .collect::<Vec<_>>();
        Ok(records)
    }

    /// List aggregated traces (one row per trace) from /admin/traces — richer evidence than /admin/interactions
    pub async fn list_traces(
        &self,
        agent_pid: Option<&str>,
    ) -> Result<Vec<InteractionRecord>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = match agent_pid {
            Some(pid) if !pid.is_empty() => {
                format!("{}/admin/traces?agent_pid={}&limit=200", mgmt_base, pid)
            }
            _ => format!("{}/admin/traces?limit=200", mgmt_base),
        };
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Trace list failed: {}", e)))?;
        if !response.status().is_success() {
            return self.list_interactions(agent_pid).await; // fallback
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let records = body
            .get("traces")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|v| InteractionRecord {
                id: v
                    .get("trace_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                agent_pid: v
                    .get("agent_pid")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                interaction_type: "trace".to_string(),
                target: format!(
                    "trace:{}",
                    v.get("trace_id").and_then(|x| x.as_str()).unwrap_or("")
                ),
                operation: v
                    .get("outcome")
                    .and_then(|x| x.as_str())
                    .unwrap_or("ResponseReleased")
                    .to_string(),
                status: v
                    .get("outcome")
                    .and_then(|x| x.as_str())
                    .unwrap_or("Success")
                    .to_string(),
                duration_ms: v.get("latency_ms").and_then(|x| x.as_u64()).unwrap_or(0),
                tokens: Some(
                    v.get("tokens_in").and_then(|x| x.as_u64()).unwrap_or(0)
                        + v.get("tokens_out").and_then(|x| x.as_u64()).unwrap_or(0),
                ),
                cost_usd: v.get("cost_usd").and_then(|x| x.as_f64()),
                model: v.get("model").and_then(|x| x.as_str()).map(str::to_string),
                provider: v
                    .get("provider")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                decision_reason: v
                    .get("policy_reason")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                policy_source: v
                    .get("policy_verdict")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                timestamp: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                prompt_preview: v
                    .get("prompt_preview")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                response_preview: v
                    .get("response_preview")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                risk_level: v
                    .get("risk_level")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                risk_score: v.get("risk_score").and_then(|x| x.as_f64()),
                trace_id: v
                    .get("trace_id")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                tenant_id: v
                    .get("tenant_id")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                pii_detected: v.get("pii_detected").and_then(|x| x.as_bool()),
                had_pii_block: v
                    .get("had_pii_block")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                had_tool_block: v
                    .get("had_tool_block")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                had_operation_block: v
                    .get("had_operation_block")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                had_quarantine_block: v
                    .get("had_quarantine_block")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
            })
            .collect::<Vec<_>>();
        Ok(records)
    }

    /// Active operation-scoped blocks (data-plane `llm.chat` / `tool:*` / …).
    pub async fn list_operation_blocks(&self) -> Result<Vec<OperationBlockBrief>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/operation-blocks", mgmt_base);
        let response = self.management_get(&path).await.map_err(|e| {
            AppError::ConnectorProxy(format!("Operation blocks list failed: {}", e))
        })?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Operation blocks list failed: {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let blocks = body
            .get("operation_blocks")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                Some(OperationBlockBrief {
                    tenant_id: v
                        .get("tenant_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    actor_id: v
                        .get("actor_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    operation_key: v
                        .get("operation_key")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    reason: v
                        .get("reason")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    active: v.get("active").and_then(|x| x.as_bool()).unwrap_or(false),
                })
            })
            .collect::<Vec<_>>();
        Ok(blocks)
    }

    pub async fn get_admin_stats(&self) -> Result<AdminStats, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/stats", mgmt_base);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Admin stats failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Admin stats failed: {}",
                response.status()
            )));
        }
        response
            .json::<AdminStats>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    pub async fn get_trace_events(&self, trace_id: &str) -> Result<Vec<TraceEvent>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/traces/{}/events", mgmt_base, trace_id);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Trace events failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Trace events failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let events = body
            .get("events")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| serde_json::from_value::<TraceEvent>(v).ok())
            .collect::<Vec<_>>();
        Ok(events)
    }

    /// Fetch decision tree data for a specific trace
    pub async fn get_trace_decision(&self, trace_id: &str) -> Result<serde_json::Value, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/traces/{}/decision", mgmt_base, trace_id);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Trace decision failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Trace decision failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body)
    }

    /// Block a specific operation for tenant+actor on the data plane (403 before LLM/tools).
    pub async fn create_operation_block(
        &self,
        tenant_id: &str,
        actor_id: &str,
        operation_key: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/operation-blocks", mgmt_base);
        let tenant = if tenant_id.trim().is_empty() || tenant_id == "unknown" {
            "*"
        } else {
            tenant_id
        };
        let actor = if actor_id.trim().is_empty() || actor_id == "unknown" {
            "*"
        } else {
            actor_id
        };
        let response = self
            .management_post_json(
                &path,
                serde_json::json!({
                    "tenant_id": tenant,
                    "actor_id": actor,
                    "operation_key": operation_key,
                    "reason": reason,
                }),
            )
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("operation block failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "operation block failed: {}",
                response.status()
            )))
        }
    }

    /// Quarantine an agent by PID — blocks all future requests from that agent
    pub async fn quarantine_agent(&self, agent_pid: &str) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/quarantine", mgmt_base);
        let actor = if agent_pid.trim().is_empty() || agent_pid == "unknown" {
            "*"
        } else {
            agent_pid
        };
        let response = self
            .management_post_json(
                &path,
                serde_json::json!({
                    "actor_id": actor,
                    "reason": "operator quarantine via TUI",
                    "quarantine_type": "agent"
                }),
            )
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Agent quarantine failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Agent quarantine failed: {}",
                response.status()
            )))
        }
    }

    pub async fn list_approvals(&self, status: &str) -> Result<Vec<ApprovalItem>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/approvals?status={}", mgmt_base, status);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Approvals list failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Approvals list failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body
            .get("approvals")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ApprovalItem>(v).ok())
            .collect::<Vec<_>>())
    }

    pub async fn list_quarantines(&self, status: &str) -> Result<Vec<ApprovalItem>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/quarantine?status={}", mgmt_base, status);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Quarantines list failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Quarantines list failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body
            .get("quarantines")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ApprovalItem>(v).ok())
            .collect::<Vec<_>>())
    }

    pub async fn list_all_quarantines(&self) -> Result<Vec<serde_json::Value>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/quarantine/all", mgmt_base);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Quarantine all list failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Quarantine all list failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body
            .get("quarantines")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    pub async fn approve_approval(&self, id: &str, approver_id: &str) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/approvals/{}/approve", mgmt_base, id);
        let response = self
            .management_post_json(&path, serde_json::json!({ "approver_id": approver_id }))
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Approval approve failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Approval approve failed: {}",
                response.status()
            )))
        }
    }

    pub async fn reject_approval(&self, id: &str, approver_id: &str) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/approvals/{}/reject", mgmt_base, id);
        let response = self
            .management_post_json(&path, serde_json::json!({ "approver_id": approver_id }))
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Approval reject failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Approval reject failed: {}",
                response.status()
            )))
        }
    }

    pub async fn quarantine_approval(&self, id: &str, approver_id: &str) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/approvals/{}/quarantine", mgmt_base, id);
        let response = self
            .management_post_json(&path, serde_json::json!({ "approver_id": approver_id }))
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Approval quarantine failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Approval quarantine failed: {}",
                response.status()
            )))
        }
    }

    pub async fn list_providers(&self) -> Result<Vec<ProviderItem>, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/providers", mgmt_base);
        let response = self
            .management_get(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Provider list failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Provider list failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body
            .get("providers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| serde_json::from_value::<ProviderItem>(v).ok())
            .collect::<Vec<_>>())
    }

    pub async fn create_provider(&self, req: ProviderUpsertRequest) -> Result<String, AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/providers", mgmt_base);
        let response = self
            .management_post_json(
                &path,
                serde_json::to_value(req).map_err(|e| AppError::Serialization(e.to_string()))?,
            )
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Provider create failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Provider create failed: {}",
                response.status()
            )));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        Ok(body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string())
    }

    pub async fn update_provider(
        &self,
        id: &str,
        req: ProviderUpsertRequest,
    ) -> Result<(), AppError> {
        let mgmt_base = self.management_plane_base();
        let path = format!("{}/admin/providers/{}", mgmt_base, id);
        let response = self
            .management_put_json(
                &path,
                serde_json::to_value(req).map_err(|e| AppError::Serialization(e.to_string()))?,
            )
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Provider update failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Provider update failed: {}",
                response.status()
            )))
        }
    }

    pub async fn get_enforcement_packet(
        &self,
        trace_id: &str,
    ) -> Result<serde_json::Value, AppError> {
        let data_base = self.data_plane_base();
        let path = format!("{}/enforcement/{}", data_base, trace_id);
        let response = self
            .client
            .get(&path)
            .header(
                "Authorization",
                format!("Bearer {}", self.management_auth_token()),
            )
            .send()
            .await
            .map_err(|e| {
                AppError::ConnectorProxy(format!("Enforcement packet fetch failed: {}", e))
            })?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Enforcement packet fetch failed: {}",
                response.status()
            )));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    pub async fn get_decision_diff(
        &self,
        trace_a: &str,
        trace_b: &str,
    ) -> Result<serde_json::Value, AppError> {
        let data_base = self.data_plane_base();
        let path = format!(
            "{}/decision/diff?trace_a={}&trace_b={}",
            data_base, trace_a, trace_b
        );
        let response = self
            .client
            .get(&path)
            .header(
                "Authorization",
                format!("Bearer {}", self.management_auth_token()),
            )
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Decision diff fetch failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "Decision diff fetch failed: {}",
                response.status()
            )));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    /// Async handoff to WitnessCtl (`POST /api/v1/integrations/tracetramp/handoff`).
    /// No-op when `witness_base_url` is unset/empty. Requires `witness_secret` when base URL is set.
    pub async fn witness_tracetramp_handoff(
        &self,
        witness_base_url: Option<&str>,
        witness_secret: Option<&str>,
        payload: &serde_json::Value,
    ) -> Result<(), AppError> {
        let Some(base_raw) = witness_base_url.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let base = base_raw.trim_end_matches('/');
        let Some(secret_raw) = witness_secret.map(str::trim).filter(|s| !s.is_empty()) else {
            tracing::warn!(
                "TRACETRAMP_WITNESS_HANDOFF_BASE_URL is set but TRACETRAMP_WITNESS_HANDOFF_SECRET is missing; skipping WitnessCtl handoff"
            );
            return Ok(());
        };
        let url = format!("{}/api/v1/integrations/tracetramp/handoff", base);
        let response = self
            .client
            .post(&url)
            .header("X-WitnessCtl-Tracetramp-Handoff-Secret", secret_raw)
            .json(payload)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("WitnessCtl handoff failed: {}", e)))?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(AppError::ConnectorProxy(format!(
                "WitnessCtl handoff failed: {} {}",
                status, body
            )))
        }
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
                .header("Authorization", format!("Bearer {}", self.api_key))
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let body: serde_json::Value = r
                        .json()
                        .await
                        .map_err(|e| AppError::Serialization(e.to_string()))?;
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
                        .or_else(|| {
                            body.get("max_agents")
                                .and_then(|v| v.as_u64())
                                .map(|v| v as usize)
                        });
                    let current_agents = body
                        .get("usage")
                        .and_then(|v| v.get("agents"))
                        .and_then(|v| v.as_u64())
                        .map(|v| v as usize);
                    return Ok(LicenseStatus {
                        tier,
                        max_agents,
                        current_agents,
                    });
                }
                Ok(r) => {
                    last_err = Some(format!("{} -> {}", url, r.status()));
                }
                Err(e) => {
                    last_err = Some(format!("{} -> {}", url, e));
                }
            }
        }
        // License endpoint not available - return default unlimited license
        // This allows the TUI to work in development/lab environments
        tracing::warn!(
            "License endpoint not available, using default unlimited license: {}",
            last_err.unwrap_or_else(|| "unknown".to_string())
        );
        Ok(LicenseStatus {
            tier: "dev-unlimited".to_string(),
            max_agents: Some(1000),
            current_agents: Some(0),
        })
    }

    pub async fn get_moment_proof(
        &self,
        moment_id: &str,
    ) -> Result<serde_json::Value, AppError> {
        let path = format!(
            "/api/v1/forensics/moment/{}/proof",
            pct_path_seg(moment_id)
        );
        let resp = self
            .get_with_aapi_fallback(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "moment proof {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))
    }

    pub async fn list_agent_moments(
        &self,
        agent_vid: &str,
    ) -> Result<serde_json::Value, AppError> {
        let path = format!(
            "/api/v1/forensics/moments/{}",
            pct_path_seg(agent_vid)
        );
        let resp = self
            .get_with_aapi_fallback(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "moments index {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))
    }

    pub async fn get_rollup_explain(
        &self,
        agent_vid: &str,
        evidence_id: &str,
    ) -> Result<serde_json::Value, AppError> {
        let path = format!(
            "/api/v1/rollup/{}/explain/{}",
            pct_path_seg(agent_vid),
            pct_path_seg(evidence_id)
        );
        let resp = self
            .get_with_aapi_fallback(&path)
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AppError::ConnectorProxy(format!(
                "rollup explain {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::ConnectorProxy(e.to_string()))
    }

    fn local_receipt(&self, request_id: &str, trace_id: &str) -> Receipt {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let cid = sha256::digest(format!("{}:{}:{}", request_id, trace_id, timestamp));
        Receipt {
            receipt_id: format!("local_{}", &cid[..16]),
            cid,
            timestamp,
            signature: "local-fallback".to_string(),
        }
    }

    pub async fn resolve_agent_identity(
        &self,
        presented_key: &str,
    ) -> Result<ConnectorIdentity, AppError> {
        let key_hash = sha256::digest(presented_key);
        let short = &key_hash[..8];
        let name = format!("tt-{}", short);
        let namespace = format!("tracetramp/{}", short);
        let create_url = format!("{}/api/v1/agents", self.base_url);
        let payload = serde_json::json!({
            "name": name,
            "namespace": namespace,
            "metadata": {
                "source": "tracetramp",
                "presented_key_hash": key_hash,
            }
        });

        let resp = match self
            .client
            .post(&create_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                warn!(
                    "Connector agent identity create network error ({}); using deterministic local identity",
                    e
                );
                return Ok(ConnectorIdentity {
                    tenant_id: namespace.clone(),
                    actor_id: name,
                    actor_role: "agent".to_string(),
                });
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                "Connector agent identity create unavailable ({} {}); using deterministic local identity",
                status, body
            );
            return Ok(ConnectorIdentity {
                tenant_id: namespace.clone(),
                actor_id: name,
                actor_role: "agent".to_string(),
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;

        let pid = body
            .get("pid")
            .or_else(|| body.get("agent_pid"))
            .or_else(|| body.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(&namespace)
            .to_string();

        Ok(ConnectorIdentity {
            tenant_id: namespace,
            actor_id: pid,
            actor_role: "agent".to_string(),
        })
    }

    pub async fn add_dynamic_policy(
        &self,
        id: &str,
        name: &str,
        rules: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        let url = format!("{}/api/v1/aapi/policies", self.base_url);
        let payload = serde_json::json!({
            "id": id,
            "name": name,
            "rules": rules,
        });
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Failed to add policy: {}", e)))?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorProxy(format!(
                "Failed to add policy: {}",
                body
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    pub async fn evaluate_action_policy(
        &self,
        action: &str,
        resource: &str,
        role: Option<&str>,
    ) -> Result<serde_json::Value, AppError> {
        let url = format!("{}/api/v1/aapi/policies/evaluate", self.base_url);
        let payload = serde_json::json!({
            "action": action,
            "resource": resource,
            "role": role,
        });
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Policy evaluation failed: {}", e)))?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorProxy(format!(
                "Policy evaluation failed: {}",
                body
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    pub async fn create_budget(
        &self,
        agent_pid: &str,
        resource: &str,
        limit: f64,
    ) -> Result<serde_json::Value, AppError> {
        let payload = serde_json::json!({
            "agent_pid": agent_pid,
            "resource": resource,
            "limit": limit,
        });
        let resp = self
            .post_with_aapi_fallback("/aapi/budgets", &payload)
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Budget create failed: {}", e)))?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::ConnectorProxy(format!(
                "Budget create failed: {}",
                body
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))
    }

    pub async fn get_budget_status(
        &self,
        agent_pid: &str,
        resource: &str,
    ) -> Result<BudgetStatus, AppError> {
        let status_path = format!(
            "/aapi/budgets/status?agent_pid={}&resource={}",
            agent_pid, resource
        );
        let resp = match self.get_with_aapi_fallback(&status_path).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "Budget fetch network error — defaulting to unlimited: {}",
                    e
                );
                return Ok(BudgetStatus {
                    remaining: None,
                    exhausted: false,
                });
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status().as_u16() == 501 {
            tracing::warn!(
                "Budget endpoint unavailable ({}) — defaulting to unlimited",
                resp.status()
            );
            return Ok(BudgetStatus {
                remaining: None,
                exhausted: false,
            });
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(
                "Budget fetch failed ({}) — defaulting to unlimited: {}",
                status,
                body
            );
            return Ok(BudgetStatus {
                remaining: None,
                exhausted: false,
            });
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let remaining = body.get("remaining").and_then(|v| v.as_f64());
        let exhausted = body
            .get("exhausted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || remaining.map(|v| v <= 0.0).unwrap_or(false);
        Ok(BudgetStatus {
            remaining,
            exhausted,
        })
    }

    fn aapi_candidates(&self, path: &str) -> Vec<String> {
        if path.starts_with("/aapi/") {
            vec![
                format!("{}{}", self.base_url, path),
                format!("{}/api/v1{}", self.base_url, path),
            ]
        } else {
            vec![format!("{}{}", self.base_url, path)]
        }
    }

    async fn post_with_aapi_fallback<T: serde::Serialize>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<Response, reqwest::Error> {
        let mut last = None;
        for url in self.aapi_candidates(path) {
            let resp = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .json(payload)
                .send()
                .await?;
            if resp.status() != reqwest::StatusCode::NOT_FOUND {
                return Ok(resp);
            }
            last = Some(resp);
        }
        Ok(last.expect("at least one candidate URL"))
    }

    async fn get_with_aapi_fallback(&self, path: &str) -> Result<Response, reqwest::Error> {
        let mut last = None;
        for url in self.aapi_candidates(path) {
            let resp = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .send()
                .await?;
            if resp.status() != reqwest::StatusCode::NOT_FOUND {
                return Ok(resp);
            }
            last = Some(resp);
        }
        Ok(last.expect("at least one candidate URL"))
    }

    fn management_auth_token(&self) -> String {
        std::env::var("TRACETRAMP_ADMIN_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| self.api_key.clone())
    }

    async fn management_get(&self, path: &str) -> Result<Response, reqwest::Error> {
        self.client
            .get(path)
            .header(
                "Authorization",
                format!("Bearer {}", self.management_auth_token()),
            )
            .send()
            .await
    }

    async fn management_post_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<Response, reqwest::Error> {
        self.client
            .post(path)
            .header(
                "Authorization",
                format!("Bearer {}", self.management_auth_token()),
            )
            .json(&payload)
            .send()
            .await
    }

    async fn management_put_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> Result<Response, reqwest::Error> {
        self.client
            .put(path)
            .header(
                "Authorization",
                format!("Bearer {}", self.management_auth_token()),
            )
            .json(&payload)
            .send()
            .await
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AdmissionResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub quarantine: bool,
    pub policy_hits: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AgentCost {
    pub agent_pid: String,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub current_tier: String,
    pub tier_limit: u64,
    pub overage: bool,
}

#[derive(Debug, Clone)]
pub struct BudgetStatus {
    pub remaining: Option<f64>,
    pub exhausted: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub cid: String,
    pub timestamp: String,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TrustScore {
    pub agent_pid: String,
    pub score: f64,
    pub trend: String,
    pub factors: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct InteractionRecord {
    pub id: String,
    pub agent_pid: String,
    #[serde(rename = "type")]
    pub interaction_type: String,
    pub target: String,
    pub operation: String,
    pub status: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub tokens: Option<u64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub decision_reason: Option<String>,
    /// Policy lane verdict from `PolicyChecked` (Allow / Block / …) when trace projection includes it.
    #[serde(default)]
    pub policy_source: Option<String>,
    pub timestamp: String,
    #[serde(default)]
    pub prompt_preview: Option<String>,
    #[serde(default)]
    pub response_preview: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub pii_detected: Option<bool>,
    /// From `/admin/traces` projection — output blocked for PII.
    #[serde(default)]
    pub had_pii_block: bool,
    /// From `/admin/traces` projection — tool invocation blocked.
    #[serde(default)]
    pub had_tool_block: bool,
    /// From `/admin/traces` — `PolicyChecked` row with `operation_blocked` metadata (data-plane op scope).
    #[serde(default)]
    pub had_operation_block: bool,
    /// From `/admin/traces` — `PolicyChecked` row with `quarantined` metadata (agent/session quarantine).
    #[serde(default)]
    pub had_quarantine_block: bool,
}

/// One operation-scoped block row from management API (`active` may be false after release).
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct OperationBlockBrief {
    pub tenant_id: String,
    pub actor_id: String,
    pub operation_key: String,
    pub reason: String,
    pub active: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct AdminStats {
    #[serde(default)]
    pub active_calls: u64,
    #[serde(default)]
    pub budget_burn_per_min: f64,
    #[serde(default)]
    pub policy_hits_last_5m: u64,
    #[serde(default)]
    pub forecast_monthly_usd: f64,
    #[serde(default)]
    pub anomaly_score: f64,
    #[serde(default)]
    pub anomaly_flag: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TraceEvent {
    pub id: i64,
    pub trace_id: String,
    pub request_id: String,
    pub event_type: String,
    pub step: String,
    pub status: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
    pub timestamp: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct ApprovalItem {
    pub id: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub trace_id: String,
    #[serde(default)]
    pub actor_id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    /// `hitl` core from control: `lane`, `block.class`, `evidence.refs`, optional tool/policy/risk fields.
    #[serde(default)]
    pub hold_metadata: serde_json::Value,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct ProviderItem {
    pub id: String,
    pub name: String,
    pub api_base: String,
    pub provider_type: String,
    pub is_active: bool,
    #[serde(default)]
    pub has_api_key: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderUpsertRequest {
    pub name: String,
    pub api_base: String,
    pub provider_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LicenseStatus {
    pub tier: String,
    pub max_agents: Option<usize>,
    pub current_agents: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BudgetContext, OutputMode, RequestMode};
    use uuid::Uuid;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_request() -> RuntimeExecutionRequest {
        RuntimeExecutionRequest {
            request_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            tenant_id: "tenant-default".to_string(),
            app_id: "app".to_string(),
            environment: "prod".to_string(),
            workflow_id: None,
            session_id: None,
            actor_id: "actor-1".to_string(),
            actor_role: "developer".to_string(),
            request_mode: RequestMode::Control,
            model_intent: "code".to_string(),
            model_id: "gpt-4o".to_string(),
            input_payload: serde_json::json!({"prompt":"hello"}),
            tools_requested: vec!["bash".to_string()],
            memory_scope: None,
            action_targets: vec![],
            output_mode: OutputMode::Text,
            budget_context: BudgetContext::default(),
            compliance_tags: vec![],
            execution_profile: "default".to_string(),
            policy_bundle: "default".to_string(),
            kernel_host_snapshot: None,
            hitl_bypass: false,
            test_hold_requested: false,
        }
    }

    #[tokio::test]
    async fn check_policy_calls_connector_aapi_evaluate() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aapi/policies/evaluate"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "outcome": "allow",
                "reason": "ok-from-connector"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ConnectorClient::new(&server.uri(), "test-key");
        let req = sample_request();
        let result = client
            .check_policy(&req, "default")
            .await
            .expect("policy call should succeed");

        assert_eq!(result.outcome, "allow");
        assert_eq!(result.reason, "ok-from-connector");
    }

    #[tokio::test]
    async fn check_policy_propagates_blocked_outcome() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aapi/policies/evaluate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "outcome": "block",
                "reason": "tool policy denied"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = ConnectorClient::new(&server.uri(), "test-key");
        let req = sample_request();
        let result = client
            .check_policy(&req, "default")
            .await
            .expect("policy call should return block decision");

        assert_eq!(result.outcome, "block");
        assert_eq!(result.reason, "tool policy denied");
    }
}

impl ConnectorClient {
    /// Get receipt by request_id
    pub async fn get_receipt(&self, request_id: &str) -> Result<Receipt, AppError> {
        let url = format!("{}/receipts/{}", self.base_url, request_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Get receipt failed: {}", e)))?;

        if response.status().is_success() {
            response
                .json::<Receipt>()
                .await
                .map_err(|e| AppError::Serialization(e.to_string()))
        } else {
            Err(AppError::NotFound(format!(
                "Receipt not found for {}",
                request_id
            )))
        }
    }

    /// Health check for Connector
    pub async fn health_check(&self) -> Result<(), AppError> {
        let url = format!("{}/health", self.base_url);
        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Health check failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::ConnectorProxy(format!(
                "Connector unhealthy: {}",
                response.status()
            )))
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyResult {
    pub outcome: String, // allow, allow_with_transform, route, require_approval, block
    pub reason: String,
    pub routing_target: Option<String>,
    pub transform_rules: Vec<String>,
    pub approvers: Vec<String>,
}
