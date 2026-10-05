//! MCP protocol driver — peer metadata ≠ Connector authority.

use connector_native_contract::{EffectDescriptor, PackagePin, ProtocolDriverId};
use serde_json::{json, Value};

use super::{record_atu_admit, DriverAdmitResult, ProtocolEffect};
use crate::substrate::pate::AugmentedTaskUnit;
use crate::state::SharedState;

pub fn decode_mcp_call(
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    server_url: &str,
    arguments: &Value,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> ProtocolEffect {
    let (host, port) = parse_host_port(server_url);
    let mutates = !is_read_only_tool(tool_name);
    let governed_args = match arguments.as_object() {
        Some(obj) => {
            let mut obj = obj.clone();
            obj.insert("url".into(), json!(server_url));
            Value::Object(obj)
        }
        None => json!({
            "url": server_url,
            "arguments": arguments,
        }),
    };
    ProtocolEffect {
        protocol: ProtocolDriverId::Mcp,
        bridge_id: bridge_id.into(),
        tool_name: tool_name.into(),
        resource: server_url.into(),
        parameters: governed_args,
        effect: EffectDescriptor {
            effect_class: "mcp.tools_call".into(),
            mutates,
            disclosure_class: Some("mcp".into()),
        },
        agent_pid: agent_pid.into(),
        mission_id,
        locator: Some(format!(
            "mcp://{}/{}",
            host.as_deref().unwrap_or("peer"),
            tool_name
        )),
        destination_host: host,
        destination_port: port,
        destination_protocol: Some("https".into()),
        upgrade_adapter_verified: true,
        package,
    }
}

fn parse_host_port(server_url: &str) -> (Option<String>, Option<u16>) {
    let rest = server_url
        .split("://")
        .nth(1)
        .unwrap_or(server_url)
        .split('/')
        .next()
        .unwrap_or("");
    let (host_part, port) = if let Some((h, p)) = rest.rsplit_once(':') {
        if h.starts_with('[') {
            (rest, None)
        } else {
            (h, p.parse::<u16>().ok())
        }
    } else {
        (rest, None)
    };
    let host = host_part.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        (None, port.or(Some(443)))
    } else {
        (Some(host.to_string()), port.or(Some(443)))
    }
}

fn is_read_only_tool(tool_name: &str) -> bool {
    let t = tool_name.to_ascii_lowercase();
    t.starts_with("list_")
        || t.starts_with("get_")
        || t.starts_with("read_")
        || t == "list_tools"
        || t == "list_resources"
        || t == "list_prompts"
}

/// Admit MCP tools/call through PATE and leave the task open for the HTTP call.
pub fn admit_mcp_call(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    server_url: &str,
    arguments: &Value,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> Result<(DriverAdmitResult, AugmentedTaskUnit), String> {
    let effect = decode_mcp_call(
        agent_pid,
        bridge_id,
        tool_name,
        server_url,
        arguments,
        mission_id.clone(),
        package,
    );
    super::gate_mutating_package(&effect, false)?;
    let atu = crate::substrate::pate::admit_tool(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        &effect.parameters,
        mission_id,
    )
    .map_err(|error| error.human_readable)?;
    let mut result = record_atu_admit(state, effect, &atu)?;
    result.atu_task_id = Some(atu.task_id.clone());
    Ok((result, atu))
}
