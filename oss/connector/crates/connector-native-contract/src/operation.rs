//! Durable operation refs — mission_journal is the store; these are the neutral contract.

use serde::{Deserialize, Serialize};

/// Schema for operation payloads.
pub const OPERATION_SCHEMA: &str = "connector.operation.v1";

/// Lifecycle of a durable operation (maps 1:1 onto mission journal statuses).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Accepted / open — durable accept-before-effect.
    Accepted,
    /// Actively running an admitted step.
    Running,
    /// Waiting on human / HITL input.
    InputRequired,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

/// Neutral handle for a durable operation (`mission_id` today).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationRef {
    pub schema: String,
    pub operation_id: String,
    pub status: OperationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl OperationRef {
    pub fn new(
        operation_id: impl Into<String>,
        status: OperationStatus,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> Self {
        Self {
            schema: OPERATION_SCHEMA.into(),
            operation_id: operation_id.into(),
            status,
            agent_pid: None,
            label: None,
            created_at_ms,
            updated_at_ms,
        }
    }
}

/// Map legacy mission status strings onto OperationStatus.
pub fn operation_status_from_mission(status: &str) -> OperationStatus {
    match status.trim().to_ascii_lowercase().as_str() {
        "open" => OperationStatus::Accepted,
        "waiting_hitl" => OperationStatus::InputRequired,
        "completed" => OperationStatus::Succeeded,
        "failed" => OperationStatus::Failed,
        "canceled" | "cancelled" => OperationStatus::Cancelled,
        "expired" => OperationStatus::Expired,
        "running" => OperationStatus::Running,
        _ => OperationStatus::Accepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mission_status_mapping() {
        assert_eq!(
            operation_status_from_mission("waiting_hitl"),
            OperationStatus::InputRequired
        );
        assert_eq!(
            operation_status_from_mission("canceled"),
            OperationStatus::Cancelled
        );
    }
}
