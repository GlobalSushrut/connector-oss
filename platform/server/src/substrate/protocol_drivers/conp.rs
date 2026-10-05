//! CONP protocol driver — CP/1.0 commands lower to pate::admit_conp.

use connector_native_contract::{EffectDescriptor, PackagePin, ProtocolDriverId};
use connector_protocol::MessageType;
use serde_json::{json, Value};

use super::{gate_mutating_package, record_atu_admit, DriverAdmitResult, ProtocolEffect};
use crate::state::SharedState;
use crate::substrate::pate;

pub fn decode_conp_command(
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    message_type: MessageType,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> ProtocolEffect {
    let mutates = message_type.is_mutating();
    ProtocolEffect {
        protocol: ProtocolDriverId::Conp,
        bridge_id: "conp".into(),
        tool_name: capability_id.into(),
        resource: entity_id.into(),
        parameters: json!({
            "schema": "connector.conp.action.v1",
            "message_type": format!("{:?}", message_type),
            "capability_id": capability_id,
            "entity_id": entity_id,
            "parameters": parameters,
        }),
        effect: EffectDescriptor {
            effect_class: if message_type.dispatches_hal() {
                "conp.command".into()
            } else {
                format!(
                    "conp.{}",
                    format!("{:?}", message_type).to_ascii_lowercase()
                )
            },
            mutates,
            disclosure_class: Some("conp".into()),
        },
        agent_pid: agent_pid.into(),
        mission_id,
        locator: Some(format!("conp://{entity_id}/{capability_id}")),
        destination_host: None,
        destination_port: None,
        destination_protocol: Some("conp".into()),
        upgrade_adapter_verified: true,
        package,
    }
}

/// Admit CONP via existing pate::admit_conp, then mint native receipt envelope.
pub fn admit_conp_command(
    state: &SharedState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    message_type: MessageType,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> Result<(DriverAdmitResult, pate::AugmentedTaskUnit), String> {
    let effect = decode_conp_command(
        agent_pid,
        capability_id,
        entity_id,
        parameters,
        message_type,
        mission_id.clone(),
        package,
    );
    // EmergencyStop is ambient cut-through; still digest-audited after admit.
    gate_mutating_package(&effect, matches!(message_type, MessageType::EmergencyStop))?;
    let atu = pate::admit_conp(
        state,
        agent_pid,
        capability_id,
        entity_id,
        parameters,
        message_type,
        mission_id,
    )
    .map_err(|e| e.human_readable)?;
    let result = record_atu_admit(state, effect, &atu)?;
    Ok((result, atu))
}
