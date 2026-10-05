//! Lean multimodal moment manifest — D/R/U/A/I/O part refs per governed turn.

use serde::{Deserialize, Serialize};

pub const MOMENT_MANIFEST_SCHEMA: &str = "moment_manifest.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MomentPartV2 {
    /// `text` | `image` | `audio` | `object_ref` | `tool_result` | `usage`
    pub part_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MomentManifestV2 {
    pub schema: String,
    pub moment_id: String,
    pub session_id: String,
    pub agent_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_event_id: Option<String>,
    pub parts: Vec<MomentPartV2>,
    pub occurred_at_ms: i64,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl MomentManifestV2 {
    pub fn new_llm_turn(
        session_id: impl Into<String>,
        agent_pid: impl Into<String>,
        model: &str,
        prompt_tokens: u32,
        completion_tokens: u32,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        let moment_id = format!("mom_{}", uuid::Uuid::new_v4().simple());
        Self {
            schema: MOMENT_MANIFEST_SCHEMA.into(),
            moment_id,
            session_id: session_id.into(),
            agent_pid: agent_pid.into(),
            tenant_id: None,
            admission_ticket_id: None,
            causal_envelope_id: None,
            usage_event_id: None,
            parts: vec![
                MomentPartV2 {
                    part_kind: "usage".into(),
                    text: Some(format!(
                        "model={model} prompt_tokens={prompt_tokens} completion_tokens={completion_tokens}"
                    )),
                    object_ref: None,
                    content_hash: None,
                    mime_type: None,
                },
            ],
            occurred_at_ms: now,
            contract_version: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moment_schema_round_trip() {
        let m = MomentManifestV2::new_llm_turn("sess", "agent", "claude", 10, 20);
        assert_eq!(m.schema, MOMENT_MANIFEST_SCHEMA);
        let json = serde_json::to_string(&m).unwrap();
        let back: MomentManifestV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(back.moment_id, m.moment_id);
    }
}
