//! Immutable usage metering event — source of truth for books / billing projections.

use serde::{Deserialize, Serialize};

pub const USAGE_EVENT_SCHEMA: &str = "usage_event.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UsageTokenSource {
    ProviderApi,
    StubHeuristic,
    NoRouterHeuristic,
    PeerReported,
    Error,
    Unavailable,
}

impl UsageTokenSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProviderApi => "provider_api",
            Self::StubHeuristic => "stub_heuristic",
            Self::NoRouterHeuristic => "no_router_heuristic",
            Self::PeerReported => "peer_reported",
            Self::Error => "error",
            Self::Unavailable => "unavailable",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "provider_api" => Self::ProviderApi,
            "stub_heuristic" => Self::StubHeuristic,
            "no_router_heuristic" => Self::NoRouterHeuristic,
            "peer_reported" => Self::PeerReported,
            "error" => Self::Error,
            _ => Self::Unavailable,
        }
    }
}

/// One observed usage write per LLM completion / tool call (append-only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageEventV2 {
    pub schema: String,
    pub event_id: String,
    pub event_type: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_served: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub token_source: String,
    /// Estimated USD — never authoritative invoice truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_estimated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_id: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl UsageEventV2 {
    pub fn new_llm_completion(
        account_id: impl Into<String>,
        agent_pid: impl Into<String>,
        session_id: impl Into<String>,
        model_requested: impl Into<String>,
        model_served: impl Into<String>,
        provider: impl Into<String>,
        prompt_tokens: u32,
        completion_tokens: u32,
        token_source: UsageTokenSource,
        cost_usd_estimated: Option<f64>,
        flow_id: Option<String>,
    ) -> Self {
        let total = prompt_tokens.saturating_add(completion_tokens) as u64;
        Self {
            schema: USAGE_EVENT_SCHEMA.into(),
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: "llm_completion".into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
            account_id: Some(account_id.into()),
            agent_pid: Some(agent_pid.into()),
            session_id: Some(session_id.into()),
            model_requested: Some(model_requested.into()),
            model_served: Some(model_served.into()),
            provider: Some(provider.into()),
            prompt_tokens: prompt_tokens as u64,
            completion_tokens: completion_tokens as u64,
            total_tokens: total,
            token_source: token_source.as_str().into(),
            cost_usd_estimated,
            flow_id,
            moment_id: None,
            contract_version: 2,
        }
    }
}
