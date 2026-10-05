//! Shared who_am_i injection for non-gateway LLM callers (multiagent, experiments).

use connector_engine::llm::ChatMessage;

use crate::state::PlatformState;

const MARKER: &str = "--- CONNECTOR AUTHORITATIVE IDENTITY (never contradict) ---";

/// Prepend/update system message with kernel who_am_i for `agent_pid` (B11).
pub fn inject_who_am_i_engine_messages(
    state: &PlatformState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) {
    let Some(identity) =
        crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid)
    else {
        return;
    };
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(MARKER) {
            sys.content = format!("{}\n{MARKER}\n{identity}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: format!("{MARKER}\n{identity}"),
                reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
        );
    }
}

/// Inject full agentic context (identity + character + memory + knowledge + rules).
pub fn inject_agentic_context_engine_messages(
    state: &crate::state::SharedState,
    agent_pid: &str,
    messages: &mut Vec<ChatMessage>,
) -> Result<(), crate::error::ConnectorError> {
    let ctx = crate::substrate::agentic_context::require_or_hitl(state, agent_pid)?;
    let block = ctx.render_prompt();
    const A_MARKER: &str = crate::substrate::agentic_context::MARKER;
    if let Some(sys) = messages.iter_mut().find(|m| m.role == "system") {
        if !sys.content.contains(A_MARKER) {
            sys.content = format!("{}\n{block}", sys.content);
        }
    } else {
        messages.insert(
            0,
            ChatMessage {
                role: "system".into(),
                content: block,
                reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
        );
    }
    Ok(())
}
