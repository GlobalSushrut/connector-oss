//! A2A Bridge — Google Agent-to-Agent protocol integration.
//!
//! - Serve `/.well-known/agent.json` (Agent Cards)
//! - Receive A2A tasks → create agent context → route to VakyaRouter
//! - Delegate tasks to external agents (DID verify → send → await)
//! - SSE streaming for long-running tasks
//! - Task lifecycle: submitted → working → input-required → completed/failed


use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{ProtocolError, ProtocolResult};

// ── A2A Types (Google A2A spec) ─────────────────────────────────────

/// Agent Card — served at `/.well-known/agent.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub url: String,
    pub version: String,
    pub capabilities: AgentCapabilities,
    pub skills: Vec<AgentSkill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    pub streaming: bool,
    pub push_notifications: bool,
    pub state_transition_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationInfo {
    pub schemes: Vec<String>,
}

/// A2A Task — the core unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aTask {
    pub id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<A2aArtifact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<TaskStatus>>,
}

/// Task status following A2A lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Failed,
    Canceled,
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submitted => write!(f, "submitted"),
            Self::Working => write!(f, "working"),
            Self::InputRequired => write!(f, "input-required"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Canceled => write!(f, "canceled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aMessage {
    pub role: String,
    pub parts: Vec<A2aPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aPart {
    #[serde(rename = "type")]
    pub part_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aArtifact {
    pub name: String,
    pub parts: Vec<A2aPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
}

/// Request to send a task to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSendRequest {
    pub id: String,
    pub message: A2aMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ── A2A Bridge ──────────────────────────────────────────────────────

/// Trait for the kernel backend that the A2A bridge delegates to.
pub trait A2aKernelBackend: Send + Sync {
    /// Get the agent card for this server.
    fn agent_card(&self) -> ProtocolResult<AgentCard>;

    /// Submit a task — returns the initial task state.
    fn submit_task(&self, request: &TaskSendRequest) -> ProtocolResult<A2aTask>;

    /// Get task status by ID.
    fn get_task(&self, task_id: &str) -> ProtocolResult<A2aTask>;

    /// Cancel a task.
    fn cancel_task(&self, task_id: &str) -> ProtocolResult<A2aTask>;
}

/// A2A Bridge that serves Agent Cards and handles task delegation.
pub struct A2aBridge<B: A2aKernelBackend> {
    backend: B,
}

impl<B: A2aKernelBackend> A2aBridge<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Serve the agent card (GET /.well-known/agent.json).
    pub fn get_agent_card(&self) -> ProtocolResult<AgentCard> {
        self.backend.agent_card()
    }

    /// Handle task/send — submit a new task.
    pub fn send_task(&self, request: &TaskSendRequest) -> ProtocolResult<A2aTask> {
        debug!(task_id = %request.id, "A2A task/send");
        self.backend.submit_task(request)
    }

    /// Handle task/get — get current task status.
    pub fn get_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
        debug!(task_id = %task_id, "A2A task/get");
        self.backend.get_task(task_id)
    }

    /// Handle task/cancel — cancel a running task.
    pub fn cancel_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
        debug!(task_id = %task_id, "A2A task/cancel");
        self.backend.cancel_task(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockA2aBackend {
        tasks: std::sync::Mutex<HashMap<String, A2aTask>>,
    }

    impl MockA2aBackend {
        fn new() -> Self {
            Self {
                tasks: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl A2aKernelBackend for MockA2aBackend {
        fn agent_card(&self) -> ProtocolResult<AgentCard> {
            Ok(AgentCard {
                name: "Doctor AI".to_string(),
                description: "Medical assistant agent".to_string(),
                url: "https://hospital.example.com/agent".to_string(),
                version: "1.0.0".to_string(),
                capabilities: AgentCapabilities {
                    streaming: true,
                    push_notifications: false,
                    state_transition_history: true,
                },
                skills: vec![
                    AgentSkill {
                        id: "diagnosis".to_string(),
                        name: "Diagnosis".to_string(),
                        description: "Analyze symptoms and suggest diagnoses".to_string(),
                        tags: Some(vec!["medical".to_string()]),
                        examples: Some(vec!["What could cause persistent headaches?".to_string()]),
                    },
                ],
                authentication: Some(AuthenticationInfo {
                    schemes: vec!["Bearer".to_string()],
                }),
            })
        }

        fn submit_task(&self, request: &TaskSendRequest) -> ProtocolResult<A2aTask> {
            let task = A2aTask {
                id: request.id.clone(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                },
                message: Some(request.message.clone()),
                artifacts: None,
                history: Some(vec![TaskStatus {
                    state: TaskState::Submitted,
                    message: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                }]),
            };
            self.tasks.lock().unwrap().insert(request.id.clone(), task.clone());
            Ok(task)
        }

        fn get_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
            self.tasks.lock().unwrap()
                .get(task_id)
                .cloned()
                .ok_or_else(|| ProtocolError::NotFound(format!("Task {}", task_id)))
        }

        fn cancel_task(&self, task_id: &str) -> ProtocolResult<A2aTask> {
            let mut tasks = self.tasks.lock().unwrap();
            match tasks.get_mut(task_id) {
                Some(task) => {
                    task.status = TaskStatus {
                        state: TaskState::Canceled,
                        message: None,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    Ok(task.clone())
                }
                None => Err(ProtocolError::NotFound(format!("Task {}", task_id))),
            }
        }
    }

    #[test]
    fn test_a2a_agent_card() {
        let bridge = A2aBridge::new(MockA2aBackend::new());
        let card = bridge.get_agent_card().unwrap();

        assert_eq!(card.name, "Doctor AI");
        assert!(card.capabilities.streaming);
        assert_eq!(card.skills.len(), 1);
        assert_eq!(card.skills[0].id, "diagnosis");
    }

    #[test]
    fn test_a2a_send_task() {
        let bridge = A2aBridge::new(MockA2aBackend::new());
        let req = TaskSendRequest {
            id: "task-001".to_string(),
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![A2aPart {
                    part_type: "text".to_string(),
                    text: Some("What causes headaches?".to_string()),
                    data: None,
                    mime_type: None,
                }],
            },
            session_id: None,
        };

        let task = bridge.send_task(&req).unwrap();
        assert_eq!(task.id, "task-001");
        assert_eq!(task.status.state, TaskState::Working);
        assert!(task.history.unwrap().len() >= 1);
    }

    #[test]
    fn test_a2a_get_task() {
        let bridge = A2aBridge::new(MockA2aBackend::new());

        // Submit first
        let req = TaskSendRequest {
            id: "task-002".to_string(),
            message: A2aMessage { role: "user".to_string(), parts: vec![] },
            session_id: None,
        };
        bridge.send_task(&req).unwrap();

        // Now get
        let task = bridge.get_task("task-002").unwrap();
        assert_eq!(task.id, "task-002");
    }

    #[test]
    fn test_a2a_get_nonexistent_task() {
        let bridge = A2aBridge::new(MockA2aBackend::new());
        let result = bridge.get_task("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_a2a_cancel_task() {
        let bridge = A2aBridge::new(MockA2aBackend::new());

        let req = TaskSendRequest {
            id: "task-003".to_string(),
            message: A2aMessage { role: "user".to_string(), parts: vec![] },
            session_id: None,
        };
        bridge.send_task(&req).unwrap();

        let task = bridge.cancel_task("task-003").unwrap();
        assert_eq!(task.status.state, TaskState::Canceled);
    }
}
