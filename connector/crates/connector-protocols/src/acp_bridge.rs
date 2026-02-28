//! ACP Bridge — IBM/Linux Foundation Agent Communication Protocol.
//!
//! REST-based async inter-agent messaging:
//! - POST /agents/{id}/messages → send message (202 Accepted)
//! - GET /agents/{id}/messages/{mid} → poll for result
//! - Maps to ReplicationOp::VakyaForward / VakyaReply internally


use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{ProtocolError, ProtocolResult};

// ── ACP Types ───────────────────────────────────────────────────────

/// An ACP message exchanged between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub content_type: String,
    pub body: serde_json::Value,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

/// Status of an ACP message delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcpMessageStatus {
    Accepted,
    Processing,
    Completed,
    Failed,
}

impl std::fmt::Display for AcpMessageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::Processing => write!(f, "processing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Response to a message send (202 Accepted pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpAcceptedResponse {
    pub message_id: String,
    pub status: AcpMessageStatus,
    pub poll_url: String,
}

/// Full message status (returned when polling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpMessageResult {
    pub message_id: String,
    pub status: AcpMessageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<AcpMessage>,
}

// ── ACP Bridge ──────────────────────────────────────────────────────

/// Trait for the kernel backend that the ACP bridge delegates to.
pub trait AcpKernelBackend: Send + Sync {
    /// Send a message to an agent (async — returns immediately with accepted status).
    fn send_message(&self, message: &AcpMessage) -> ProtocolResult<AcpAcceptedResponse>;

    /// Poll for message result.
    fn get_message_status(&self, message_id: &str) -> ProtocolResult<AcpMessageResult>;
}

/// ACP Bridge that handles REST-based async messaging.
pub struct AcpBridge<B: AcpKernelBackend> {
    backend: B,
}

impl<B: AcpKernelBackend> AcpBridge<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// POST /agents/{id}/messages — send a message.
    pub fn send_message(&self, message: &AcpMessage) -> ProtocolResult<AcpAcceptedResponse> {
        debug!(from = %message.from, to = %message.to, "ACP send_message");
        self.backend.send_message(message)
    }

    /// GET /agents/{id}/messages/{mid} — poll for result.
    pub fn get_message_status(&self, message_id: &str) -> ProtocolResult<AcpMessageResult> {
        debug!(message_id = %message_id, "ACP get_message_status");
        self.backend.get_message_status(message_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAcpBackend {
        messages: std::sync::Mutex<HashMap<String, (AcpMessage, AcpMessageStatus)>>,
    }

    impl MockAcpBackend {
        fn new() -> Self {
            Self { messages: std::sync::Mutex::new(HashMap::new()) }
        }
    }

    impl AcpKernelBackend for MockAcpBackend {
        fn send_message(&self, message: &AcpMessage) -> ProtocolResult<AcpAcceptedResponse> {
            let mut msgs = self.messages.lock().unwrap();
            msgs.insert(message.id.clone(), (message.clone(), AcpMessageStatus::Processing));
            Ok(AcpAcceptedResponse {
                message_id: message.id.clone(),
                status: AcpMessageStatus::Accepted,
                poll_url: format!("/agents/{}/messages/{}", message.to, message.id),
            })
        }

        fn get_message_status(&self, message_id: &str) -> ProtocolResult<AcpMessageResult> {
            let msgs = self.messages.lock().unwrap();
            match msgs.get(message_id) {
                Some((msg, _status)) => Ok(AcpMessageResult {
                    message_id: message_id.to_string(),
                    status: AcpMessageStatus::Completed,
                    reply: Some(AcpMessage {
                        id: format!("reply-{}", message_id),
                        from: msg.to.clone(),
                        to: msg.from.clone(),
                        content_type: "text/plain".to_string(),
                        body: serde_json::json!("Reply to your message"),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        reply_to: Some(message_id.to_string()),
                    }),
                }),
                None => Err(ProtocolError::NotFound(format!("Message {}", message_id))),
            }
        }
    }

    #[test]
    fn test_acp_send_message() {
        let bridge = AcpBridge::new(MockAcpBackend::new());
        let msg = AcpMessage {
            id: "msg-001".to_string(),
            from: "agent-a".to_string(),
            to: "agent-b".to_string(),
            content_type: "text/plain".to_string(),
            body: serde_json::json!("Hello from A"),
            created_at: chrono::Utc::now().to_rfc3339(),
            reply_to: None,
        };

        let resp = bridge.send_message(&msg).unwrap();
        assert_eq!(resp.status, AcpMessageStatus::Accepted);
        assert_eq!(resp.message_id, "msg-001");
        assert!(resp.poll_url.contains("msg-001"));
    }

    #[test]
    fn test_acp_poll_message() {
        let bridge = AcpBridge::new(MockAcpBackend::new());
        let msg = AcpMessage {
            id: "msg-002".to_string(),
            from: "agent-a".to_string(),
            to: "agent-b".to_string(),
            content_type: "text/plain".to_string(),
            body: serde_json::json!("Question"),
            created_at: chrono::Utc::now().to_rfc3339(),
            reply_to: None,
        };
        bridge.send_message(&msg).unwrap();

        let result = bridge.get_message_status("msg-002").unwrap();
        assert_eq!(result.status, AcpMessageStatus::Completed);
        assert!(result.reply.is_some());
        let reply = result.reply.unwrap();
        assert_eq!(reply.from, "agent-b");
        assert_eq!(reply.to, "agent-a");
    }

    #[test]
    fn test_acp_poll_nonexistent() {
        let bridge = AcpBridge::new(MockAcpBackend::new());
        let result = bridge.get_message_status("nonexistent");
        assert!(result.is_err());
    }
}
