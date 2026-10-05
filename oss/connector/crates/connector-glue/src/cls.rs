//! CLS compiler integration for GLUE — real CCL → ConnectorIrV1 pipeline.

use crate::{CompiledContract, GlueError, ErrorCode};

/// Compile CCL source through lexer→sema→lower→verify→emit into a
/// `CompiledContract` annotated with sealed `ConnectorIrV1` metadata.
pub fn compile(source: &str) -> Result<CompiledContract, GlueError> {
    use connector_engine::cls::ccl_emit::{compile_ccl, EmitConfig};
    use connector_engine::cls::ccl_parser::CclParser;

    // Prefer precise parse diagnostics when the front-end fails.
    if let Err(errors) = CclParser::parse(source) {
        let first = errors.first();
        let msg = first
            .map(|e| e.message.clone())
            .unwrap_or_else(|| "Parse error".into());
        let mut err = GlueError::new(ErrorCode::CompileError, msg);
        if let Some(e) = first {
            err = err.with_detail(format!(
                "at line {}, column {}",
                e.span.start.line, e.span.start.col
            ));
            if let Some(hint) = &e.hint {
                err = err.with_hint(hint.clone());
            }
        }
        return Err(err);
    }

    let emit = compile_ccl(source, &EmitConfig::default()).map_err(|e| {
        GlueError::new(
            ErrorCode::CompileError,
            format!("CCL compilation failed: {e:?}"),
        )
        .with_hint(
            "CCL must pass semantic analysis, IR lowering and verification (not parse-only)"
                .to_string(),
        )
    })?;

    let ir = &emit.connector_ir;
    let version = Some(format!(
        "{}.{}.{}",
        emit.contract.id.version.major,
        emit.contract.id.version.minor,
        emit.contract.id.version.patch
    ));

    let mut contract = CompiledContract::new(emit.cid.clone(), emit.contract.id.name.clone());
    contract.source = Some(source.to_string());
    contract.version = version;
    contract.tools = emit.contract.interface.required_tools.clone();
    contract.capabilities = emit.contract.interface.required_capabilities.clone();

    for p in &emit.contract.interface.inputs {
        contract.inputs.push(crate::contract::ParamDef {
            name: p.name.clone(),
            type_name: format!("{:?}", p.param_type).to_ascii_lowercase(),
            required: p.required,
            description: if p.description.is_empty() {
                None
            } else {
                Some(p.description.clone())
            },
        });
    }
    for p in &emit.contract.interface.outputs {
        contract.outputs.push(crate::contract::ParamDef {
            name: p.name.clone(),
            type_name: format!("{:?}", p.param_type).to_ascii_lowercase(),
            required: true,
            description: if p.description.is_empty() {
                None
            } else {
                Some(p.description.clone())
            },
        });
    }

    contract.metadata.insert(
        "ir_cid".into(),
        serde_json::Value::String(ir.ir_cid.clone()),
    );
    contract.metadata.insert(
        "requires_admission".into(),
        serde_json::Value::Bool(ir.requires_admission()),
    );
    contract.metadata.insert(
        "effect_row_count".into(),
        serde_json::json!(ir.effect_rows.len()),
    );
    contract.metadata.insert(
        "node_count".into(),
        serde_json::json!(ir.node_count),
    );
    if let Ok(v) = serde_json::to_value(ir) {
        contract.metadata.insert("connector_ir".into(), v);
    }

    Ok(contract)
}

/// Macro for compile-time CLS validation
#[macro_export]
macro_rules! cls {
    ($source:expr) => {
        $crate::cls::compile($source)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_src() -> &'static str {
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
    fn test_compile_full_pipeline_emits_ir() {
        let contract = compile(full_src()).expect("should compile");
        assert_eq!(contract.name, "patient_triage");
        assert!(contract.cid.starts_with("cls1-sha256-"));
        assert!(contract.inputs.iter().any(|i| i.name == "patient_id"));
        let ir_cid = contract
            .metadata
            .get("ir_cid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(ir_cid.starts_with("cir1-sha256-"));
        assert_eq!(
            contract.metadata.get("requires_admission"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn test_compile_error() {
        let source = "not valid cls at all @#$%";
        let result = compile(source);
        assert!(result.is_err(), "Expected compile error for invalid source");
    }
}
