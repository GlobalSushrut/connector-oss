//! Session lifecycle — manages DevGuard sessions via Connector APIs.
//!
//! A session represents one governed coding agent instance.
//! Session state is stored in Connector (via agent APIs).
//! DevGuard CLI creates/queries/destroys sessions through HTTP.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::action::ToolId;
use crate::connector_client::ConnectorClient;
use crate::services::session::build_session_instructions;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_pid: String,
    pub identity: String,
    pub role: String,
    pub tool: ToolId,
    pub workspace: String,
    pub connector_url: String,
    pub cage: bool,
    pub policy_fingerprint: String,
    pub session_token: Option<String>,
    pub created_at: String,
}

impl SessionInfo {
    /// Start a new governed session via Connector API.
    pub async fn start(
        client: &ConnectorClient,
        identity: &str,
        role: &str,
        tool: &ToolId,
        workspace: &str,
        connector_url: &str,
        cage: bool,
        policy_fingerprint: &str,
    ) -> Result<Self> {
        let session_id = format!("dg_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);
        let agent_pid = format!("devguard-{}-{}", tool.display_name().to_lowercase().replace(' ', "_"), &session_id[3..]);

        let body = serde_json::json!({
            "role": role,
            "tool": tool.display_name(),
            "workspace": workspace,
            "session_id": &session_id,
            "agent_pid": &agent_pid,
            "identity": identity,
            "cage": cage,
            "policy_fingerprint": policy_fingerprint,
        });

        // Call Connector API to create session
        let resp = client.session_start(&body).await?;

        // Use server-returned IDs if available, else our generated ones
        let server_session_id = resp.get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&session_id);
        let server_agent_pid = resp.get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or(&agent_pid);

        Ok(Self {
            session_id: server_session_id.to_string(),
            agent_pid: server_agent_pid.to_string(),
            identity: identity.to_string(),
            role: role.to_string(),
            tool: tool.clone(),
            workspace: workspace.to_string(),
            connector_url: connector_url.to_string(),
            cage,
            policy_fingerprint: policy_fingerprint.to_string(),
            session_token: resp.get("session_token").and_then(|v| v.as_str()).map(|s| s.into()),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn instructions(&self) -> Option<String> {
        self.session_token
            .as_ref()
            .map(|token| build_session_instructions(&self.tool.display_name().to_lowercase().replace(' ', "_"), token))
    }

    /// Query session status from Connector.
    pub async fn status(client: &ConnectorClient, session_id: &str) -> Result<serde_json::Value> {
        client.session_status(session_id).await
    }

    /// List all active sessions.
    pub async fn list(client: &ConnectorClient) -> Result<serde_json::Value> {
        client.session_list().await
    }

    /// End a session.
    pub async fn end(client: &ConnectorClient, session_id: &str) -> Result<serde_json::Value> {
        client.session_end(session_id).await
    }
}
