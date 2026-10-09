//! System prompt injection at the proxy layer.
//!
//! If a function has `instructions` set in relay.yaml, Relay prepends them
//! to the system message before forwarding to the function. This is transparent —
//! the function code never knows the instructions were injected.

use serde_json::{json, Value};

/// Inject `instructions` into an OpenAI-format `messages` array.
///
/// If a system message exists → prepend instructions to its content.
/// If no system message → insert one as messages[0].
/// If body is not an OpenAI-format messages array → return body unchanged.
pub fn inject(mut body: Value, instructions: &str) -> Value {
    let instructions = instructions.trim();
    if instructions.is_empty() {
        return body;
    }

    let messages = match body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        Some(m) => m,
        None    => return body,
    };

    // Find existing system message
    if let Some(system_msg) = messages.iter_mut().find(|m| {
        m.get("role").and_then(|r| r.as_str()) == Some("system")
    }) {
        if let Some(content) = system_msg.get_mut("content") {
            if let Some(existing) = content.as_str() {
                *content = json!(format!("{instructions}\n\n{existing}"));
                return body;
            }
        }
    }

    // No system message — insert at position 0
    messages.insert(0, json!({
        "role":    "system",
        "content": instructions,
    }));

    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prepends_to_existing_system() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "You are helpful." },
                { "role": "user",   "content": "Hello" }
            ]
        });
        let out = inject(body, "Always respond in JSON.");
        let sys = &out["messages"][0]["content"];
        assert!(sys.as_str().unwrap().starts_with("Always respond in JSON."));
        assert!(sys.as_str().unwrap().contains("You are helpful."));
    }

    #[test]
    fn inserts_new_system_message() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "Hello" }
            ]
        });
        let out = inject(body, "Be concise.");
        assert_eq!(out["messages"][0]["role"], "system");
        assert_eq!(out["messages"][0]["content"], "Be concise.");
    }

    #[test]
    fn passthrough_non_messages_body() {
        let body = json!({ "query": "hello", "namespace": "test" });
        let out = inject(body.clone(), "instructions");
        assert_eq!(out, body);
    }

    #[test]
    fn empty_instructions_passthrough() {
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let out = inject(body.clone(), "  ");
        assert_eq!(out, body);
    }
}
