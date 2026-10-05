//! LLM Transport Layer (LTL) — provider-native session fidelity helpers.
//!
//! Keeps stochastic proposer round-trips lossless: `reasoning_content` and
//! related fields must survive Talk / tool loops. Does **not** treat reasoning
//! as auditable memory — passback only.

use connector_engine::llm::{ChatMessage, LlmResponse, ToolCall};
use serde_json::Value;

/// Attach provider reasoning onto an assistant turn for the next request.
pub fn assistant_with_reasoning(text: impl Into<String>, reasoning: Option<String>) -> ChatMessage {
    let mut msg = ChatMessage::new("assistant", text);
    msg.reasoning_content = reasoning;
    msg
}

/// Extract reasoning to pass back from a completed generation.
pub fn reasoning_from_response(resp: &LlmResponse) -> Option<String> {
    resp.reasoning_content.clone()
}

/// True when the message carries opaque reasoning that must be replayed.
pub fn has_reasoning_passback(msg: &ChatMessage) -> bool {
    msg.reasoning_content
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// DeepSeek / OpenAI multi-turn tool loop: rebuild assistant message with
/// tool_calls + reasoning_content so the next provider call stays lossless.
pub fn assistant_tool_turn(
    text: impl Into<String>,
    tool_calls: Vec<ToolCall>,
    reasoning: Option<String>,
) -> ChatMessage {
    let mut msg = ChatMessage::new("assistant", text);
    msg.tool_calls = if tool_calls.is_empty() {
        None
    } else {
        Some(tool_calls)
    };
    msg.reasoning_content = reasoning;
    msg
}

/// Append a tool result turn (no reasoning — tools do not invent CoT).
pub fn tool_result_turn(tool_call_id: &str, content: impl Into<String>) -> ChatMessage {
    let mut msg = ChatMessage::new("tool", content);
    msg.tool_call_id = Some(tool_call_id.into());
    msg
}

/// Ensure the last assistant message keeps reasoning from `last_response`.
pub fn stitch_reasoning_into_history(history: &mut [ChatMessage], last_response: &LlmResponse) {
    let Some(reasoning) = reasoning_from_response(last_response) else {
        return;
    };
    if let Some(last) = history.last_mut() {
        if last.role == "assistant" && last.reasoning_content.is_none() {
            last.reasoning_content = Some(reasoning);
        }
    }
}

/// OpenAI Responses-style reasoning item passback (opaque JSON blob).
pub fn openai_reasoning_item_passback(item: &Value) -> Option<ChatMessage> {
    let reasoning = item
        .get("reasoning")
        .or_else(|| item.get("reasoning_content"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    let text = item
        .get("content")
        .or_else(|| item.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Some(assistant_with_reasoning(text, Some(reasoning)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passback_round_trip() {
        let msg = assistant_with_reasoning("answer", Some("think…".into()));
        assert!(has_reasoning_passback(&msg));
        assert_eq!(msg.reasoning_content.as_deref(), Some("think…"));
    }

    #[test]
    fn empty_reasoning_is_not_passback() {
        let msg = assistant_with_reasoning("answer", Some("  ".into()));
        assert!(!has_reasoning_passback(&msg));
    }

    #[test]
    fn tool_turn_keeps_reasoning() {
        let msg = assistant_tool_turn("call tools", vec![], Some("plan".into()));
        assert!(has_reasoning_passback(&msg));
    }
}
