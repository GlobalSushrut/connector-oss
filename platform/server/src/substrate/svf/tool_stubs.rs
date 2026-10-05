//! Progressive MCP tool stubs — S0 name → S1 description → S2 schema (EXPAND for more).

use connector_trust::DisclosureLevel;
use serde_json::{json, Value};

use crate::state::SharedState;

use super::{broker_epoch, grants, svf_enabled};

/// Catalog stubs for Ring 6 context budget — never full schemas by default.
pub fn tool_stubs(state: &SharedState, agent_pid: &str, level: DisclosureLevel) -> Value {
    if !svf_enabled() {
        return json!({
            "ok": false,
            "error": "svf_disabled",
            "tools": [],
        });
    }
    if grants::grants_frozen(state, agent_pid) {
        return json!({
            "ok": false,
            "error": "quarantine_freezes_cdp",
            "decision": "quarantine",
            "tools": [],
        });
    }
    // Cap model-plane stubs at S2 (schema without secrets).
    let level = if level.rank() > DisclosureLevel::S2Schema.rank() {
        DisclosureLevel::S2Schema
    } else {
        level
    };

    let tools: Vec<Value> = crate::services::mcp_hosting::list_tools()
        .into_iter()
        .take(64)
        .map(|t| match level {
            DisclosureLevel::S0Stub => json!({
                "name": t.name,
                "disclosure": "S0_stub",
            }),
            DisclosureLevel::S1Labels => json!({
                "name": t.name,
                "description": t.description.chars().take(160).collect::<String>(),
                "disclosure": "S1_labels",
            }),
            _ => json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "disclosure": "S2_schema",
                "honesty": "S3+ values require purpose-bound EXPAND; secrets via CDP post-Admit",
            }),
        })
        .collect();

    json!({
        "schema": "connector.svf.tool_stubs.v1",
        "agent_vid": agent_pid,
        "broker_epoch": broker_epoch(state, agent_pid),
        "disclosure": level.as_str(),
        "count": tools.len(),
        "tools": tools,
        "honesty": "Stubs shrink AffordanceEnvelope surface for context — not grants",
    })
}

/// Compact Talk injection block (S0/S1 stubs only).
pub fn gateway_tool_stub_block(state: &SharedState, agent_pid: &str) -> Option<String> {
    if !svf_enabled() {
        return None;
    }
    let stubs = tool_stubs(state, agent_pid, DisclosureLevel::S0Stub);
    let tools = stubs.get("tools").and_then(|t| t.as_array())?;
    if tools.is_empty() {
        return None;
    }
    let mut lines = vec![
        "[connector.svf.tool_stubs]".to_string(),
        "disclosure: S0_stub — EXPAND for description/schema".into(),
        "tools:".into(),
    ];
    for t in tools.iter().take(24) {
        if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
            lines.push(format!("  - {name}"));
        }
    }
    Some(lines.join("\n"))
}
