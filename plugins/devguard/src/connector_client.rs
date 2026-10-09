//! HTTP client for Connector OS APIs.
//!
//! DevGuard talks to Connector exclusively through this client.
//! No Connector crate is linked. All communication is HTTP + JSON.

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ConnectorClient {
    base_url: String,
    http: reqwest::Client,
    access_key: Option<String>,
}

impl ConnectorClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            access_key: std::env::var("CONNECTOR_ACCESS_KEY").ok().filter(|v| !v.trim().is_empty()),
        }
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    /// Prefer an issued `cg_` session token for DevGuard online checks.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        let t = token.into();
        if !t.trim().is_empty() {
            self.access_key = Some(t);
        }
        self
    }

    pub fn set_bearer_token(&mut self, token: Option<String>) {
        self.access_key = token.filter(|t| !t.trim().is_empty());
    }

    // ── Agent / Session APIs ──────────────────────────────────────────────

    /// Create a governed agent (session).
    pub async fn create_agent(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/agents", body).await
    }

    /// Get agent state.
    pub async fn get_agent(&self, pid: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/agents/{}", pid)).await
    }

    /// Destroy agent.
    pub async fn destroy_agent(&self, pid: &str) -> Result<serde_json::Value> {
        self.delete(&format!("/api/v1/agents/{}", pid)).await
    }

    /// List all agents.
    pub async fn list_agents(&self) -> Result<serde_json::Value> {
        self.get("/api/v1/agents").await
    }

    // ── DevGuard session APIs — must match platform/server router mounts ──
    // Contract (METHOD PATH): see DEVGUARD_HTTP_CONTRACT below and
    // platform/server `devguard_http_contract()` / DG-02.

    /// Machine-readable client↔server contract used by unit tests (DG-02).
    pub const DEVGUARD_HTTP_CONTRACT: &[(&str, &str)] = &[
        ("POST", "/api/v1/devguard/connect"),
        ("GET", "/api/v1/devguard/connect/info"),
        ("POST", "/api/v1/devguard/admit"),
        ("GET", "/api/v1/devguard/workspaces/discover"),
        ("GET", "/api/v1/devguard/repos"),
        ("GET", "/api/v1/devguard/repos/:repo_id"),
        ("POST", "/api/v1/devguard/repos/:repo_id/agents"),
        ("POST", "/api/v1/devguard/repos/:repo_id/roles"),
        ("GET", "/api/v1/devguard/repos/:repo_id/tree"),
        ("GET", "/api/v1/devguard/repos/:repo_id/file"),
        ("PUT", "/api/v1/devguard/repos/:repo_id/file"),
        ("DELETE", "/api/v1/devguard/repos/:repo_id/file"),
        ("POST", "/api/v1/devguard/repos/:repo_id/git/:op"),
        ("GET", "/api/v1/devguard/github/status"),
        ("POST", "/api/v1/devguard/github/checks/evaluate"),
        ("GET", "/api/v1/devguard/github/checks/:repo_id/:head_sha"),
        ("POST", "/api/v1/devguard/sessions"),
        ("GET", "/api/v1/devguard/sessions"),
        ("GET", "/api/v1/devguard/sessions/:session_id"),
        ("POST", "/api/v1/devguard/sessions/:session_id/end"),
        ("GET", "/api/v1/devguard/sessions/:session_id/audit"),
        ("POST", "/api/v1/devguard/tokens/:token_key/revoke"),
        ("POST", "/api/v1/devguard/fs/check"),
        ("POST", "/api/v1/devguard/fs/guard"),
        ("POST", "/api/v1/devguard/exec/check"),
        ("POST", "/api/v1/devguard/secrets/scan"),
        ("POST", "/api/v1/devguard/policy/load"),
        ("POST", "/api/v1/devguard/policy/validate"),
        ("POST", "/api/v1/devguard/policy/check"),
        ("POST", "/api/v1/devguard/policy/history"),
        ("POST", "/api/v1/devguard/policy/rollback"),
    ];

    pub async fn connect_repo(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/connect", body).await
    }

    pub async fn connect_info(&self) -> Result<serde_json::Value> {
        self.get("/api/v1/devguard/connect/info").await
    }

    pub async fn admit(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/admit", body).await
    }

    pub async fn attach_agent(&self, repo_id: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(&format!("/api/v1/devguard/repos/{}/agents", repo_id), body)
            .await
    }

    pub async fn session_start(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/sessions", body).await
    }

    pub async fn session_status(&self, session_id: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/devguard/sessions/{}", session_id))
            .await
    }

    pub async fn session_list(&self) -> Result<serde_json::Value> {
        self.get("/api/v1/devguard/sessions").await
    }

    pub async fn session_end(&self, session_id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("/api/v1/devguard/sessions/{}/end", session_id),
            &serde_json::json!({}),
        )
        .await
    }

    // ── Audit / Evidence APIs ─────────────────────────────────────────────

    pub async fn audit_record(&self, agent_pid: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post(&format!("/api/v1/agents/{}/audit/record", agent_pid), body).await
    }

    pub async fn audit_trail(&self, session_id: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/devguard/sessions/{}/audit", session_id))
            .await
    }

    /// Approve a kernel HITL hold (DG-09 resume path).
    pub async fn hitl_approve(&self, agent_pid: &str, request_id: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("/api/v1/agents/{}/hitl/{}/approve", agent_pid, request_id),
            &serde_json::json!({}),
        )
        .await
    }

    /// Deny a kernel HITL hold.
    pub async fn hitl_deny(
        &self,
        agent_pid: &str,
        request_id: &str,
        reason: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.post(
            &format!("/api/v1/agents/{}/hitl/{}/deny", agent_pid, request_id),
            &serde_json::json!({ "reason": reason.unwrap_or("Rejected by operator") }),
        )
        .await
    }

    /// List pending HITL for an agent.
    pub async fn hitl_pending(&self, agent_pid: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/agents/{}/hitl/pending", agent_pid))
            .await
    }

    /// Admin revoke of a cg_ token by prefix or full token (DG-05).
    pub async fn revoke_cg_token(&self, token_or_prefix: &str) -> Result<serde_json::Value> {
        self.post(
            &format!("/api/v1/devguard/tokens/{}/revoke", token_or_prefix),
            &serde_json::json!({}),
        )
        .await
    }

    // ── Guard Check APIs (server-side enforcement) ────────────────────────

    pub async fn fs_check(&self, agent_pid: &str, path: &str, operation: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/fs/check", &serde_json::json!({
            "agent_pid": agent_pid, "path": path, "operation": operation,
        })).await
    }

    pub async fn exec_check(&self, agent_pid: &str, command: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/exec/check", &serde_json::json!({
            "agent_pid": agent_pid, "command": command,
        })).await
    }

    pub async fn secret_scan(&self, content: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/secrets/scan", &serde_json::json!({ "content": content })).await
    }

    // ── Policy APIs ─────────────────────────────────────────────────────

    pub async fn policy_load(&self, agent_pid: &str, role: &str, yaml: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/policy/load", &serde_json::json!({
            "agent_pid": agent_pid, "role": role, "policy_yaml": yaml,
        })).await
    }

    pub async fn policy_validate(&self, yaml: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/policy/validate", &serde_json::json!({
            "policy_yaml": yaml,
        })).await
    }

    pub async fn policy_check(&self, agent_pid: &str, operation: &str, target: &str) -> Result<serde_json::Value> {
        self.post("/api/v1/devguard/policy/check", &serde_json::json!({
            "agent_pid": agent_pid, "operation": operation, "target": target,
        })).await
    }

    // ── Surface / SOE APIs ────────────────────────────────────────────────

    pub async fn surface_trace(&self, subject: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/surface/trace/{}", subject)).await
    }

    pub async fn surface_explain(&self, subject: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/surface/explain/{}", subject)).await
    }

    pub async fn surface_prove(&self, subject: &str) -> Result<serde_json::Value> {
        self.get(&format!("/api/v1/surface/prove/{}", subject)).await
    }

    // ── Hook APIs (for Phase 1+, when Connector supports generic hooks) ──

    pub async fn register_hook(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/hooks/register", body).await
    }

    pub async fn unregister_hook(&self, hook_id: &str) -> Result<serde_json::Value> {
        self.delete(&format!("/api/v1/hooks/{}", hook_id)).await
    }

    // ── Native origin-binding APIs ────────────────────────────────────────

    pub async fn native_bind_software(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.post("/api/v1/native/software/bind", body).await
    }

    pub async fn native_register_workload(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post("/api/v1/native/workloads", body).await
    }

    pub async fn native_register_intelligence(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.post("/api/v1/native/intelligence", body).await
    }

    // ── Health ────────────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<serde_json::Value> {
        self.get("/health").await
    }

    // ── Internal HTTP methods ─────────────────────────────────────────────

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url);
        if let Some(key) = &self.access_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("GET {} failed — is Connector running at {}?", path, self.base_url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET {} returned {}: {}", path, status, body);
        }

        resp.json().await.with_context(|| format!("Failed to parse response from GET {}", path))
    }

    async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.post(&url);
        if let Some(key) = &self.access_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        let resp = req
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {} failed — is Connector running at {}?", path, self.base_url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("POST {} returned {}: {}", path, status, body);
        }

        resp.json().await.with_context(|| format!("Failed to parse response from POST {}", path))
    }

    async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.delete(&url);
        if let Some(key) = &self.access_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("DELETE {} failed — is Connector running at {}?", path, self.base_url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("DELETE {} returned {}: {}", path, status, body);
        }

        resp.json().await.with_context(|| format!("Failed to parse response from DELETE {}", path))
    }
}

#[cfg(test)]
mod contract_tests {
    use super::ConnectorClient;

    #[test]
    fn client_contract_covers_session_and_guard_routes() {
        let paths: Vec<&str> = ConnectorClient::DEVGUARD_HTTP_CONTRACT
            .iter()
            .map(|(_, p)| *p)
            .collect();
        assert!(paths.contains(&"/api/v1/devguard/sessions"));
        assert!(paths.contains(&"/api/v1/devguard/sessions/:session_id/end"));
        assert!(paths.contains(&"/api/v1/devguard/fs/check"));
        assert!(paths.contains(&"/api/v1/devguard/policy/check"));
        assert!(paths.contains(&"/api/v1/devguard/github/checks/evaluate"));
        // Legacy singular /session/start must never reappear.
        assert!(!paths.iter().any(|p| p.contains("/devguard/session/")));
    }
}
