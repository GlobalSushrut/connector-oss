//! Governed agent-loop adapter — Ring-1 tool proposals → PATE → tools dispatch.
//!
//! Provider `tool_calls` are **proposals only**. This module canonicalizes them,
//! admits via [`crate::substrate::pate::admit_tool`] (wrapping ActionBinding),
//! dispatches through [`crate::services::tools`], and returns a sanitized receipt
//! for LTL session append. Raw Talk auto-dispatch remains blocked.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;
use crate::substrate::pate::{self, AugmentedTaskUnit};

pub const AGENT_LOOP_SCHEMA: &str = "connector.agent_loop.proposal.v1";
pub const RECEIPT_SCHEMA: &str = "connector.agent_loop.receipt.v1";

/// One provider-emitted tool call, normalized for admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProposal {
    pub schema: String,
    pub call_id: String,
    pub bridge_id: String,
    pub tool_name: String,
    pub arguments: Value,
    pub mission_id: Option<String>,
}

/// Sanitized receipt appended back into the LTL session (no raw reasoning).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolReceipt {
    pub schema: String,
    pub call_id: String,
    pub tool_name: String,
    pub ok: bool,
    pub action_digest: Option<String>,
    pub task_id: Option<String>,
    pub result: Value,
    pub error: Option<String>,
}

impl ToolProposal {
    pub fn from_openai_style(
        call: &Value,
        default_bridge: &str,
        mission_id: Option<String>,
    ) -> Result<Self, ConnectorError> {
        let call_id = call
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let fn_obj = call.get("function").cloned().unwrap_or(Value::Null);
        let tool_name = fn_obj
            .get("name")
            .and_then(|v| v.as_str())
            .or_else(|| call.get("name").and_then(|v| v.as_str()))
            .unwrap_or("")
            .trim()
            .to_string();
        if tool_name.is_empty() {
            return Err(ConnectorError::new(
                DenialReason::ValidationError,
                "tool_proposal_missing_name",
            ));
        }
        let arguments = parse_arguments(
            fn_obj
                .get("arguments")
                .or_else(|| call.get("arguments"))
                .or_else(|| call.get("input")),
        )?;
        let bridge_id = call
            .get("bridge_id")
            .and_then(|v| v.as_str())
            .unwrap_or(default_bridge)
            .to_string();
        Ok(Self {
            schema: AGENT_LOOP_SCHEMA.into(),
            call_id: if call_id.is_empty() {
                format!("call_{}", uuid::Uuid::new_v4().simple())
            } else {
                call_id
            },
            bridge_id,
            tool_name,
            arguments,
            mission_id,
        })
    }
}

fn parse_arguments(raw: Option<&Value>) -> Result<Value, ConnectorError> {
    match raw {
        None | Some(Value::Null) => Ok(json!({})),
        Some(Value::Object(_)) => Ok(raw.unwrap().clone()),
        Some(Value::String(s)) => serde_json::from_str(s).map_err(|e| {
            ConnectorError::new(
                DenialReason::ValidationError,
                format!("tool_proposal_bad_arguments_json: {e}"),
            )
        }),
        Some(other) => Ok(other.clone()),
    }
}

/// Admit a single tool proposal through PATE (does not execute).
pub fn admit_proposal(
    state: &SharedState,
    agent_pid: &str,
    proposal: &ToolProposal,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    crate::substrate::ops_runtime::preflight_agent_effect(state, agent_pid)?;
    pate::admit_tool(
        state,
        agent_pid,
        &proposal.bridge_id,
        &proposal.tool_name,
        &proposal.arguments,
        proposal.mission_id.clone(),
    )
}

/// Admit + dispatch one proposal; returns a receipt safe for LTL append.
pub async fn execute_governed_proposal(
    state: &SharedState,
    agent_pid: &str,
    proposal: ToolProposal,
) -> ToolReceipt {
    execute_governed_proposal_checked(state, agent_pid, None, proposal).await
}

/// Same as [`execute_governed_proposal`] with CIP inhibit + broker epoch check from DAL run.
pub async fn execute_governed_proposal_checked(
    state: &SharedState,
    agent_pid: &str,
    run: Option<&crate::substrate::dynamic_agent_loop::AgentRunState>,
    proposal: ToolProposal,
) -> ToolReceipt {
    if let Some(run) = run {
        if let Err(e) = crate::substrate::dynamic_agent_loop::assert_turn_allowed(state, run) {
            return ToolReceipt {
                schema: RECEIPT_SCHEMA.into(),
                call_id: proposal.call_id,
                tool_name: proposal.tool_name,
                ok: false,
                action_digest: None,
                task_id: None,
                result: Value::Null,
                error: Some(e.human_readable),
            };
        }
        let cip = crate::substrate::cip_executive::project_from_run(run);
        if crate::substrate::cip_executive::should_inhibit_effect(&cip) {
            return ToolReceipt {
                schema: RECEIPT_SCHEMA.into(),
                call_id: proposal.call_id,
                tool_name: proposal.tool_name,
                ok: false,
                action_digest: None,
                task_id: None,
                result: Value::Null,
                error: Some("cip_inhibit_effect".into()),
            };
        }
    }

    // Admission happens inside tools::dispatch_mcp_tool via pate::admit_tool (SVF sandwich).
    let dispatch = crate::services::tools::dispatch_mcp_tool(
        state,
        &proposal.bridge_id,
        &proposal.tool_name,
        agent_pid,
        &proposal.arguments,
        format!("agent_loop:{}", proposal.call_id),
        crate::services::tools::ToolMissionOpts {
            mission_id: proposal.mission_id.as_deref(),
            idempotency_key: Some(proposal.call_id.as_str()),
        },
    )
    .await;

    match dispatch {
        Ok(result) => ToolReceipt {
            schema: RECEIPT_SCHEMA.into(),
            call_id: proposal.call_id,
            tool_name: proposal.tool_name,
            ok: true,
            action_digest: result
                .get("action_digest")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            task_id: result
                .get("pate_task_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            result: sanitize_tool_result(result),
            error: None,
        },
        Err(err) => {
            let msg = err
                .get("denial_reason")
                .or_else(|| err.get("error"))
                .or_else(|| err.get("message"))
                .cloned()
                .unwrap_or_else(|| json!("tool_dispatch_failed"));
            ToolReceipt {
                schema: RECEIPT_SCHEMA.into(),
                call_id: proposal.call_id,
                tool_name: proposal.tool_name,
                ok: false,
                action_digest: err
                    .get("action_digest")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                task_id: err
                    .get("pate_task_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                result: Value::Null,
                error: Some(msg.as_str().unwrap_or("tool_dispatch_failed").to_string()),
            }
        }
    }
}

/// Strip oversized / sensitive fields before feeding the model again.
fn sanitize_tool_result(mut v: Value) -> Value {
    const MAX: usize = 16_384;
    if let Ok(s) = serde_json::to_string(&v) {
        if s.len() > MAX {
            return json!({
                "truncated": true,
                "preview": &s[..MAX],
                "bytes": s.len(),
            });
        }
    }
    if let Some(obj) = v.as_object_mut() {
        for key in ["api_key", "token", "password", "secret", "authorization"] {
            if obj.contains_key(key) {
                obj.insert(key.into(), json!("[redacted]"));
            }
        }
    }
    v
}

/// Batch: admit+dispatch each proposal sequentially (bounded recursion belongs to DAL).
pub async fn run_tool_proposals(
    state: &SharedState,
    agent_pid: &str,
    proposals: Vec<ToolProposal>,
) -> Vec<ToolReceipt> {
    let mut out = Vec::with_capacity(proposals.len());
    for p in proposals {
        out.push(execute_governed_proposal(state, agent_pid, p).await);
    }
    out
}

/// DAL-owned batch: CIP + broker_epoch checked before each dispatch.
pub async fn run_tool_proposals_for_run(
    state: &SharedState,
    run: &crate::substrate::dynamic_agent_loop::AgentRunState,
    proposals: Vec<ToolProposal>,
) -> Vec<ToolReceipt> {
    let mut out = Vec::with_capacity(proposals.len());
    for p in proposals {
        let live = crate::substrate::llm_context_broker::current_generation(state, &run.agent_pid);
        if crate::substrate::dynamic_agent_loop::loop_must_stop(run.broker_epoch, live) {
            out.push(ToolReceipt {
                schema: RECEIPT_SCHEMA.into(),
                call_id: p.call_id,
                tool_name: p.tool_name,
                ok: false,
                action_digest: None,
                task_id: None,
                result: json!({"stopped": "operator_cease"}),
                error: Some(
                    "operator_cease: the loop stopped. Remaining steps were not run.".into(),
                ),
            });
            break;
        }
        out.push(execute_governed_proposal_checked(state, &run.agent_pid, Some(run), p).await);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openai_function_call() {
        let call = json!({
            "id": "call_abc",
            "type": "function",
            "function": {
                "name": "lookup_sku",
                "arguments": "{\"sku\":\"SKU-1\"}"
            }
        });
        let p = ToolProposal::from_openai_style(&call, "default", None).unwrap();
        assert_eq!(p.tool_name, "lookup_sku");
        assert_eq!(p.call_id, "call_abc");
        assert_eq!(p.arguments["sku"], "SKU-1");
    }

    #[test]
    fn rejects_missing_name() {
        let err = ToolProposal::from_openai_style(&json!({"id": "x"}), "b", None).unwrap_err();
        assert!(err.human_readable.contains("missing_name"));
    }
}
