//! OBSERVE — remask tool/world results into VAC MemPacket + COPG + re-SEMANTICIZE.

use serde_json::{json, Value};
use vac_core::cid::compute_cid;
use vac_core::types::{MemoryKernelOp, MemoryType, OpOutcome, PacketType, Source, SourceKind};
use vac_core::{MemPacket, SyscallPayload, SyscallRequest};

use crate::state::SharedState;

use super::{broker_epoch, remask, semanticize, svf_enabled};

/// Remask observation, write ToolResult MemPacket, COPG edge, re-semanticize.
pub fn observe_tool_result(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    pate_task_id: Option<&str>,
    result: &mut Value,
) -> Value {
    let report = remask::remask_observation(state, agent_pid, result);
    if !svf_enabled() {
        return json!({ "remask": report, "mem_packet_cid": Value::Null });
    }

    let ns = crate::services::agents::canonical_agent_memory_namespace(agent_pid);
    let content = json!({
        "bridge_id": bridge_id,
        "tool": tool_name,
        "pate_task_id": pate_task_id,
        "broker_epoch": report.broker_epoch,
        "observation": result,
        "honesty": "Remasked — secrets not on model plane",
    });
    let cid = match write_tool_result_packet(state, agent_pid, &ns, &content) {
        Some(c) => {
            if let Some(tid) = pate_task_id {
                crate::substrate::arc::copg::record_svf_edge(
                    agent_pid,
                    tid,
                    &c,
                    "svf_observe",
                    json!({
                        "bridge_id": bridge_id,
                        "tool": tool_name,
                        "tokens_minted": report.tokens_minted,
                        "broker_epoch": report.broker_epoch,
                    }),
                );
            }
            let _ = semanticize::semanticize_agent(state, agent_pid);
            Some(c)
        }
        None => None,
    };

    json!({
        "schema": "connector.svf.observe.v1",
        "remask": report,
        "mem_packet_cid": cid,
        "broker_epoch": broker_epoch(state, agent_pid),
    })
}

fn write_tool_result_packet(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    content: &Value,
) -> Option<String> {
    let payload_cid = compute_cid(content).ok()?;
    let mut packet = MemPacket::new(
        PacketType::ToolResult,
        content.clone(),
        payload_cid,
        agent_pid.to_string(),
        "svf-observe".to_string(),
        Source {
            kind: SourceKind::Tool,
            principal_id: agent_pid.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
    .with_namespace(namespace.to_string())
    .with_tags(vec!["svf".into(), "observe".into(), "remask".into()]);
    packet.memory_type = MemoryType::Episodic;
    packet.metadata.insert(
        "svf".into(),
        json!({ "plane": "observe", "schema": "connector.svf.observe.v1" }),
    );
    let packet_for_store = packet.clone();
    let cid_str = packet.index.packet_cid.to_string();
    let mut kernel = state.kernel.lock().ok()?;
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: agent_pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet },
        reason: Some("svf_observe_remask".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    if result.outcome != OpOutcome::Success {
        return None;
    }
    drop(kernel);
    let _ = crate::substrate::memwrite_durability::write_through_packet_shared(
        state,
        &packet_for_store,
    );
    Some(cid_str)
}
