//! A2A protocol driver — agent cards authenticate peers; Connector authorizes effects.

use connector_native_contract::{EffectDescriptor, PackagePin, ProtocolDriverId};
use serde_json::{json, Value};

use super::{gate_mutating_package, record_atu_admit, DriverAdmitResult, ProtocolEffect};
use crate::state::SharedState;

pub fn decode_a2a_send(
    agent_pid: &str,
    session_or_peer: &str,
    task_id: &str,
    message: &Value,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> ProtocolEffect {
    ProtocolEffect {
        protocol: ProtocolDriverId::A2a,
        bridge_id: "a2a".into(),
        tool_name: "a2a.send".into(),
        resource: session_or_peer.into(),
        parameters: json!({
            "schema": "connector.a2a.task.v1",
            "task_id": task_id,
            "session_id": session_or_peer,
            "message": message,
        }),
        effect: EffectDescriptor {
            effect_class: "a2a.send_task".into(),
            mutates: true,
            disclosure_class: Some("a2a".into()),
        },
        agent_pid: agent_pid.into(),
        mission_id,
        locator: Some(format!("a2a://{session_or_peer}/{task_id}")),
        destination_host: None,
        destination_port: None,
        destination_protocol: Some("a2a".into()),
        upgrade_adapter_verified: true,
        package,
    }
}

/// Admit A2A task send through pate::admit_a2a (ActionBinding/PATE) + receipt envelope.
pub fn admit_a2a_send(
    state: &SharedState,
    agent_pid: &str,
    session_or_peer: &str,
    task_id: &str,
    message: &Value,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> Result<(DriverAdmitResult, crate::substrate::pate::AugmentedTaskUnit), String> {
    let effect = decode_a2a_send(
        agent_pid,
        session_or_peer,
        task_id,
        message,
        mission_id.clone(),
        package,
    );
    gate_mutating_package(&effect, false)?;
    let atu = crate::substrate::pate::admit_a2a(
        state,
        agent_pid,
        session_or_peer,
        &effect.parameters,
        mission_id,
    )
    .map_err(|e| e.human_readable)?;
    let mut result = super::record_atu_admit(state, effect, &atu)?;
    result.atu_task_id = Some(atu.task_id.clone());
    Ok((result, atu))
}
