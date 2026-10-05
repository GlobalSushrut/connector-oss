//! Gateway N4 intercept — block raw tool execution without CPO→QPR spine (C3).

use axum::http::HeaderMap;
use serde_json::Value;

use crate::error::{ConnectorError, DenialReason};
use crate::kernel::docklock;

/// Reject OpenAI-compat requests that carry `tools` / `tool_choice` without N4 CPO binding.
pub fn intercept_raw_tool_definitions(
    headers: &HeaderMap,
    tools: Option<&Value>,
    tool_choice: Option<&Value>,
    agent_pid: &str,
) -> Result<(), ConnectorError> {
    if !docklock::ring1_enforce_enabled() {
        return Ok(());
    }
    let has_tools = tools
        .map(|t| !t.is_null() && !(t.is_array() && t.as_array().map(|a| a.is_empty()).unwrap_or(true)))
        .unwrap_or(false);
    let has_choice = tool_choice
        .map(|t| !t.is_null() && t.as_str() != Some("none"))
        .unwrap_or(false);
    if !has_tools && !has_choice {
        return Ok(());
    }

    let cpo_bound = headers
        .get(docklock::CPO_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();
    if !cpo_bound {
        return Err(
            ConnectorError::new(
                DenialReason::PolicyDenied,
                "Ring-1 blocks raw gateway tools without N4 CPO — POST /n4/cognize then /qpr/intent",
            )
            .with_denied_resource("gateway.tools")
            .with_agent_scope(agent_pid)
            .with_hint(&format!(
                "Set header {} after N4 cognize, or remove tools from request",
                docklock::CPO_HEADER
            )),
        );
    }
    Ok(())
}

/// Model-emitted tool calls must not auto-dispatch — return blocked envelope for client.
pub fn block_model_tool_calls(tool_calls: &[Value], agent_pid: &str) -> Option<ConnectorError> {
    if !docklock::ring1_enforce_enabled() || tool_calls.is_empty() {
        return None;
    }
    Some(
        ConnectorError::new(
            DenialReason::PolicyDenied,
            "Model tool_calls blocked under Ring-1 — route through N4 cognize → QPR → tool dispatch",
        )
        .with_denied_resource("gateway.tool_calls")
        .with_agent_scope(agent_pid),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn allows_chat_without_tools_when_ring1_off() {
        std::env::remove_var("CONNECTOR_IIA_RING1");
        let h = HeaderMap::new();
        assert!(intercept_raw_tool_definitions(&h, None, None, "a").is_ok());
    }
}
