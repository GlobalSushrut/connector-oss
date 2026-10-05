//! Project `SolutionContract` / CLS IR into neutral `ConnectorIrV1`.

use connector_native_contract::{
    ConnectorIrV1, IrAuthorityCheck, IrCapabilityImport, IrChannelHint, IrCompensationHint,
    IrEffectRow, IrInterfaceDecl, IrSupervision, CONNECTOR_IR_V1_SCHEMA,
};

use crate::cls::types::{CIROp, SolutionContract};

/// Build a sealed `ConnectorIrV1` from a compiled `SolutionContract`.
pub fn connector_ir_from_solution(
    contract: &SolutionContract,
    solution_contract_cid: &str,
) -> ConnectorIrV1 {
    let version = format!(
        "{}.{}.{}",
        contract.id.version.major, contract.id.version.minor, contract.id.version.patch
    );

    let tools: Vec<String> = contract.interface.required_tools.clone();

    let interfaces = vec![IrInterfaceDecl {
        name: contract.id.name.clone(),
        inputs: contract
            .interface
            .inputs
            .iter()
            .map(|p| p.name.clone())
            .collect(),
        outputs: contract
            .interface
            .outputs
            .iter()
            .map(|p| p.name.clone())
            .collect(),
        tools: tools.clone(),
        events: contract.interface.events.clone(),
    }];

    let mut capability_imports: Vec<IrCapabilityImport> = tools
        .into_iter()
        .map(|name| IrCapabilityImport {
            name,
            kind: "tool".into(),
            attenuations: vec![],
        })
        .collect();

    for cap in &contract.interface.required_capabilities {
        capability_imports.push(IrCapabilityImport {
            name: cap.clone(),
            kind: "capability".into(),
            attenuations: vec![],
        });
    }

    for role in &contract.governance.allowed_roles {
        capability_imports.push(IrCapabilityImport {
            name: role.clone(),
            kind: "role".into(),
            attenuations: vec![],
        });
    }

    let entry_node = contract
        .ir
        .nodes
        .get(contract.ir.entry)
        .map(|n| n.node_id.clone());

    let mut effect_rows = Vec::new();
    let mut channel_surface_hints = Vec::new();
    let mut compensation = Vec::new();

    for node in &contract.ir.nodes {
        if let Some(row) = effect_row_from_op(&node.node_id, &node.op) {
            if let Some(ref ch) = row.channel_hint {
                channel_surface_hints.push(IrChannelHint {
                    kind: ch.clone(),
                    target: row.target.clone(),
                });
            }
            if matches!(node.op, CIROp::CallContract { .. }) {
                compensation.push(IrCompensationHint {
                    node_id: node.node_id.clone(),
                    hint: "nested_contract_compensation_via_parent_receipt".into(),
                });
            }
            effect_rows.push(row);
        }
    }

    let authority_checks: Vec<IrAuthorityCheck> = contract
        .governance
        .preconditions
        .iter()
        .map(|p| IrAuthorityCheck {
            kind: "precondition".into(),
            subject: format!("{p:?}"),
        })
        .chain(contract.governance.postconditions.iter().map(|p| {
            IrAuthorityCheck {
                kind: "postcondition".into(),
                subject: format!("{p:?}"),
            }
        }))
        .collect();

    let supervision = Some(IrSupervision {
        initial_state: contract.state_machine.initial_state.clone(),
        terminal_states: contract.state_machine.terminal_states.clone(),
        roles: contract.governance.allowed_roles.clone(),
    });

    ConnectorIrV1 {
        schema: CONNECTOR_IR_V1_SCHEMA.into(),
        ir_cid: String::new(),
        solution_contract_cid: Some(solution_contract_cid.to_string()),
        name: contract.id.name.clone(),
        version,
        domain: contract.domain.clone(),
        interfaces,
        worlds: vec![],
        capability_imports,
        effect_rows,
        invocation_modes: vec![
            "call".into(),
            "request".into(),
            "signal".into(),
        ],
        supervision,
        compensation,
        channel_surface_hints,
        authority_checks,
        node_count: contract.ir.nodes.len(),
        entry_node,
        compiled_at_ms: contract.compiled_at,
    }
    .seal()
}

fn effect_row_from_op(node_id: &str, op: &CIROp) -> Option<IrEffectRow> {
    let (kind, mutates, requires_admission, target, semantic_verb, channel_hint) = match op {
        CIROp::ToolCall { tool_id, .. } => (
            "tool_call",
            true,
            true,
            Some(tool_id.clone()),
            Some("invoke".into()),
            Some("native".into()),
        ),
        CIROp::LlmInfer { .. } => (
            "llm_infer",
            false,
            true, // proposals still need admission before hosted effects
            None,
            Some("infer".into()),
            Some("inference".into()),
        ),
        CIROp::MemRead { namespace, .. } => (
            "mem_read",
            false,
            false,
            Some(namespace.clone()),
            Some("read".into()),
            Some("memory".into()),
        ),
        CIROp::MemWrite { namespace, .. } => (
            "mem_write",
            true,
            true,
            Some(namespace.clone()),
            Some("write".into()),
            Some("memory".into()),
        ),
        CIROp::EmitEvent { event_type, .. } => (
            "emit_event",
            true,
            true,
            Some(event_type.clone()),
            Some("signal".into()),
            Some("event".into()),
        ),
        CIROp::CallContract { contract_id, .. } => (
            "call_contract",
            true,
            true,
            Some(contract_id.clone()),
            Some("delegate".into()),
            Some("native".into()),
        ),
        CIROp::SendMessage { to_agent, .. } => (
            "send_message",
            true,
            true,
            Some(to_agent.clone()),
            Some("send".into()),
            Some("cnp".into()),
        ),
        CIROp::Transition { to_state } => (
            "transition",
            false,
            false,
            Some(to_state.clone()),
            Some("transition".into()),
            None,
        ),
        CIROp::Branch { .. }
        | CIROp::SetVar { .. }
        | CIROp::Compute { .. }
        | CIROp::Checkpoint { .. }
        | CIROp::Noop => return None,
    };

    Some(IrEffectRow {
        node_id: node_id.into(),
        kind: kind.into(),
        mutates,
        requires_admission,
        target,
        semantic_verb,
        channel_hint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cls::ccl_emit::{compile_ccl, EmitConfig};

    fn sample_src() -> &'static str {
        r#"contract patient_triage {
            identity {
                name: "patient_triage"
                version: "1.0.0"
                domain: "healthcare"
                description: "Triage incoming patients"
            }
            interface {
                input patient_id: String required
                output triage_result: Json
                tool lookup_patient
                tool assess_severity
                event triage_complete
            }
            state {
                initial intake
                terminal triaged
                intake -> triaged on complete
            }
            governance {
                require patient_id is present
                ensure triage_result is present
                roles [clinician]
                clearance "high"
                compliance [hipaa]
            }
            budget {
                tokens: 4096
                cost_usd: 0.50
                tool_calls: 10
            }
            memory {
                use medical_history as history
            }
            behavior {
                step do_lookup {
                    tool lookup_patient { id: ${patient_id} } -> patient
                }
                step do_assess {
                    tool assess_severity { data: ${patient} } -> assessment
                    set triage_result = ${assessment}
                    transition triaged
                    emit triage_complete { result: ${triage_result} }
                }
            }
        }"#
    }

    #[test]
    fn projects_effect_rows_from_ccl() {
        let emit = compile_ccl(sample_src(), &EmitConfig::default()).expect("compile");
        let ir = connector_ir_from_solution(&emit.contract, &emit.cid);
        assert!(ir.ir_cid.starts_with("cir1-sha256-"));
        assert_eq!(ir.solution_contract_cid.as_deref(), Some(emit.cid.as_str()));
        assert!(ir.requires_admission());
        assert!(ir.effect_rows.iter().any(|r| r.kind == "tool_call"));
        assert!(ir.effect_rows.iter().any(|r| r.kind == "emit_event"));
        assert!(!ir.capability_imports.is_empty());
        assert!(ir.supervision.is_some());
    }
}
