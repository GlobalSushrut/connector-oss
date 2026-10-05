//! CNP protocol driver — L2 wire send and actuation require ActionBinding/PATE.

use connector_engine::cnp::types::ActuationCommand;
use connector_native_contract::{EffectDescriptor, PackagePin, ProtocolDriverId};
use serde_json::{json, Value};

use super::{gate_mutating_package, record_atu_admit, DriverAdmitResult, ProtocolEffect};
use crate::state::SharedState;
use crate::substrate::pate;

pub fn decode_cnp_send(
    agent_pid: &str,
    dest_cell: &str,
    text: &str,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> ProtocolEffect {
    ProtocolEffect {
        protocol: ProtocolDriverId::Cnp,
        bridge_id: "cnp".into(),
        tool_name: "cnp.send".into(),
        resource: dest_cell.into(),
        parameters: json!({
            "schema": "connector.cnp.send.v1",
            "dest_cell": dest_cell,
            "text": text,
        }),
        effect: EffectDescriptor {
            effect_class: "cnp.send".into(),
            mutates: true,
            disclosure_class: Some("cnp".into()),
        },
        agent_pid: agent_pid.into(),
        mission_id,
        locator: Some(format!("cnp://cell/{dest_cell}")),
        destination_host: Some(dest_cell.into()),
        destination_port: None,
        destination_protocol: Some("cnp".into()),
        upgrade_adapter_verified: true,
        package,
    }
}

/// Admit CNP send through pate::admit_cnp_send + native receipt envelope.
pub fn admit_cnp_send(
    state: &SharedState,
    agent_pid: &str,
    dest_cell: &str,
    text: &str,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> Result<(DriverAdmitResult, pate::AugmentedTaskUnit), String> {
    let effect = decode_cnp_send(agent_pid, dest_cell, text, mission_id.clone(), package);
    gate_mutating_package(&effect, false)?;
    let payload = effect.parameters.clone();
    let atu = pate::admit_cnp_send(state, agent_pid, dest_cell, &payload, mission_id)
        .map_err(|e| e.human_readable)?;
    let result = record_atu_admit(state, effect, &atu)?;
    Ok((result, atu))
}

pub fn decode_cnp_actuation(
    from_agent: &str,
    to_agent: &str,
    command: &ActuationCommand,
    parameters: &Value,
    deadline_us: Option<u64>,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> ProtocolEffect {
    let cmd_name = actuation_command_name(command);
    ProtocolEffect {
        protocol: ProtocolDriverId::Cnp,
        bridge_id: "cnp".into(),
        tool_name: format!("cnp.actuation.{cmd_name}"),
        resource: to_agent.into(),
        parameters: json!({
            "schema": "connector.cnp.actuation.v1",
            "from_agent": from_agent,
            "to_agent": to_agent,
            "command": cmd_name,
            "parameters": parameters,
            "deadline_us": deadline_us,
        }),
        effect: EffectDescriptor {
            effect_class: "cnp.actuation".into(),
            mutates: true,
            disclosure_class: Some("cnp".into()),
        },
        agent_pid: from_agent.into(),
        mission_id,
        locator: Some(format!("cnp://actuation/{to_agent}/{cmd_name}")),
        destination_host: Some(to_agent.into()),
        destination_port: None,
        destination_protocol: Some("cnp".into()),
        upgrade_adapter_verified: true,
        package,
    }
}

/// Admit CNP actuation through ActionBinding/PATE. Not a SIL-certified motion loop.
pub fn admit_cnp_actuation(
    state: &SharedState,
    from_agent: &str,
    to_agent: &str,
    command: &ActuationCommand,
    parameters: &Value,
    deadline_us: Option<u64>,
    mission_id: Option<String>,
    package: Option<PackagePin>,
) -> Result<(DriverAdmitResult, pate::AugmentedTaskUnit), String> {
    let skip_package = matches!(command, ActuationCommand::EmergencyStop);
    let effect = decode_cnp_actuation(
        from_agent,
        to_agent,
        command,
        parameters,
        deadline_us,
        mission_id.clone(),
        package,
    );
    gate_mutating_package(&effect, skip_package)?;
    let payload = effect.parameters.clone();
    let atu = pate::admit_cnp_actuation(state, from_agent, to_agent, &payload, mission_id)
        .map_err(|e| e.human_readable)?;
    let result = record_atu_admit(state, effect, &atu)?;
    Ok((result, atu))
}

pub fn parse_actuation_command(command: &str, parameters: &Value) -> Result<ActuationCommand, String> {
    match command.trim().to_ascii_lowercase().as_str() {
        "set_velocity" | "setvelocity" => Ok(ActuationCommand::SetVelocity {
            joint_velocities: json_f64_vec(parameters, "joint_velocities")?,
        }),
        "set_position" | "setposition" => Ok(ActuationCommand::SetPosition {
            joint_positions: json_f64_vec(parameters, "joint_positions")?,
        }),
        "gripper" => Ok(ActuationCommand::Gripper {
            open: parameters
                .get("open")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            force_n: parameters
                .get("force_n")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
        }),
        "navigate_to" | "navigateto" => Ok(ActuationCommand::NavigateTo {
            x: json_f64(parameters, "x")?,
            y: json_f64(parameters, "y")?,
            z: parameters.get("z").and_then(|v| v.as_f64()).unwrap_or(0.0),
            heading_rad: parameters
                .get("heading_rad")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
        }),
        "emergency_stop" | "emergencystop" => Ok(ActuationCommand::EmergencyStop),
        "custom" => Ok(ActuationCommand::Custom {
            command_type: parameters
                .get("command_type")
                .and_then(|v| v.as_str())
                .unwrap_or("custom")
                .to_string(),
            params: parameters.clone(),
        }),
        other => Err(format!("unknown_actuation_command:{other}")),
    }
}

pub fn actuation_command_name(command: &ActuationCommand) -> &'static str {
    match command {
        ActuationCommand::SetVelocity { .. } => "set_velocity",
        ActuationCommand::SetPosition { .. } => "set_position",
        ActuationCommand::Gripper { .. } => "gripper",
        ActuationCommand::NavigateTo { .. } => "navigate_to",
        ActuationCommand::EmergencyStop => "emergency_stop",
        ActuationCommand::Custom { .. } => "custom",
    }
}

fn json_f64(v: &Value, key: &str) -> Result<f64, String> {
    v.get(key)
        .and_then(|x| x.as_f64())
        .ok_or_else(|| format!("actuation_parameter_required:{key}"))
}

fn json_f64_vec(v: &Value, key: &str) -> Result<Vec<f64>, String> {
    let arr = v
        .get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("actuation_parameter_required:{key}"))?;
    arr.iter()
        .map(|x| {
            x.as_f64()
                .ok_or_else(|| format!("actuation_parameter_not_number:{key}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_position_and_estop() {
        let cmd = parse_actuation_command(
            "SetPosition",
            &json!({"joint_positions": [0.1, 0.2]}),
        )
        .unwrap();
        match cmd {
            ActuationCommand::SetPosition { joint_positions } => {
                assert_eq!(joint_positions, vec![0.1, 0.2]);
            }
            _ => panic!("expected SetPosition"),
        }
        assert!(matches!(
            parse_actuation_command("emergency_stop", &json!({})).unwrap(),
            ActuationCommand::EmergencyStop
        ));
    }

    #[test]
    fn decode_actuation_is_mutating() {
        let cmd = ActuationCommand::SetPosition {
            joint_positions: vec![1.0],
        };
        let e = decode_cnp_actuation(
            "agent_a",
            "agent_machine_proxy",
            &cmd,
            &json!({"joint_positions": [1.0]}),
            None,
            None,
            None,
        );
        assert!(e.effect.mutates);
        assert_eq!(e.effect.effect_class, "cnp.actuation");
        assert!(e.package.is_none());
    }
}
