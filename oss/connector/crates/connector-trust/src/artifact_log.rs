//! Append-only artifact log record — classes 1–7 projection source.

use serde::{Deserialize, Serialize};

pub const ARTIFACT_LOG_SCHEMA: &str = "artifact_log_record.v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    Memory,
    Usage,
    Audit,
    Proof,
    Custody,
    Workflow,
    Operator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactLogRecordV2 {
    pub schema: String,
    pub record_id: String,
    pub artifact_class: ArtifactClass,
    pub artifact_type: String,
    pub observed_at: String,
    /// Segment bucket for append/rebuild (I-13). Set on platform append when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    pub payload: serde_json::Value,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl ArtifactLogRecordV2 {
    pub fn from_usage_event(event: &crate::usage_event::UsageEventV2) -> Self {
        Self {
            schema: ARTIFACT_LOG_SCHEMA.into(),
            record_id: uuid::Uuid::new_v4().to_string(),
            artifact_class: ArtifactClass::Usage,
            artifact_type: "usage_event".into(),
            observed_at: event.observed_at.clone(),
            segment_id: None,
            principal_id: event.account_id.clone(),
            tenant_id: None,
            content_digest: None,
            payload: serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
            contract_version: 2,
        }
    }
}
