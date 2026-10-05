//! Runtime execution layer for GLUE operations

use crate::cnp::{
    CnpCapabilityContract, CnpMessageContract, CnpPortContract, CnpRouteContract, CnpRouteStatus,
    CnpSessionContract,
};
use crate::data::{
    normalize_knowledge_namespace, normalize_memory_namespace, DataInjection, KnowledgeContract,
    KnowledgeQuery, KnowledgeSource, MemoryContract,
};
use crate::infra::{PipelineContract, SecurityContract, ToolContract};
use crate::protocol::{ProtocolAction, ProtocolContract};
use crate::{ErrorCode, Glue, GlueError, GlueReceipt, GlueResult, Noun};
use connector_engine::cnp::types::CNP_ACK_TIMEOUT_MS;
use connector_engine::cnp::{
    CellStatus as EngineCellStatus, CnpError as EngineCnpError, CnpMessage as EngineCnpMessage,
    CnpPayload as EngineCnpPayload, CnpPortDirection as EngineCnpPortDirection,
    CnpPortPermission as EngineCnpPortPermission, CnpPortType as EngineCnpPortType,
    CnpRouter as EngineCnpRouter, CnpSession as EngineCnpSession,
    CnpSessionState as EngineCnpSessionState, CNP_DEFAULT_TTL_MS, CNP_MAX_DELEGATION_DEPTH,
    CNP_MAX_MESSAGE_BYTES, CNP_MAX_RETRIES,
};
use std::collections::HashMap;

// =============================================================================
// Core Verb Implementations
// =============================================================================

/// Execute a contract through the CLS executor.
///
/// This function compiles and executes a CLS contract, producing a full
/// execution receipt with audit trail, resource usage, and outputs.
fn glue_stub_allowed() -> bool {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let prodish = matches!(env.as_str(), "production" | "prod");
    let defense = std::env::var("CONNECTOR_DEFENSE_STRICT")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let allow = std::env::var("CONNECTOR_GLUE_ALLOW_STUB")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    !(prodish || defense) || allow
}

fn looks_like_ccl(source: &str) -> bool {
    let trimmed = source.trim_start();
    trimmed.starts_with("contract ") || trimmed.starts_with("contract\t")
}

pub fn execute_run(
    _glue: Glue,
    target: String,
    inputs: HashMap<String, serde_json::Value>,
    policy: Option<String>,
) -> Result<GlueResult, GlueError> {
    use connector_engine::cls::{ClsCompiler, ContractExecutor, ExecutionOutcome};

    if !glue_stub_allowed() {
        return Err(GlueError::new(
            ErrorCode::ExecutionError,
            "connector-glue stub executor forbidden under production / defense-strict \
             (unset CONNECTOR_ENV=production or set CONNECTOR_GLUE_ALLOW_STUB=1 for break-glass lab only)",
        ));
    }

    let trace_id = generate_trace_id();
    let agent_pid = format!("glue-agent-{}", &trace_id[..8]);
    let session_id = format!("glue-session-{}", &trace_id[..8]);

    // Try to compile the target as CLS source
    // If it's a CID reference, we'd look it up in the registry (future work)
    let contract = if target.starts_with("cls1-") || target.starts_with("cid:") {
        // CID targets require a live registry / platform package — never fake success.
        return Err(GlueError::new(
            ErrorCode::ExecutionError,
            format!(
                "contract CID '{target}' requires registry lookup via platform/cnktros invoke \
                 with a signed AppPackageV2 pin — refusing pending_registry stub success"
            ),
        ));
    } else if looks_like_ccl(&target) {
        // Inline CCL — real pipeline (SolutionContract + ConnectorIrV1), then stub execute.
        use connector_engine::cls::ccl_emit::{compile_ccl, EmitConfig};
        let emit = compile_ccl(&target, &EmitConfig::default()).map_err(|e| {
            GlueError::new(
                ErrorCode::CompileError,
                format!("CCL compilation failed: {:?}", e),
            )
        })?;
        let contract = emit.contract;
        // Execute the contract with stub handlers (lab/dev only — gated above)
        let mut executor = ContractExecutor::stub();
        let receipt = executor
            .execute(&contract, &agent_pid, &session_id, inputs.clone())
            .map_err(|e| {
                GlueError::new(
                    ErrorCode::ExecutionError,
                    format!("CLS execution failed: {:?}", e),
                )
            })?;

        let state = match &receipt.outcome {
            ExecutionOutcome::Success => "completed",
            ExecutionOutcome::Failed { .. } => "failed",
            ExecutionOutcome::Aborted { .. } => "aborted",
            ExecutionOutcome::Timeout => "timeout",
            ExecutionOutcome::BudgetExceeded { .. } => "budget_exceeded",
            ExecutionOutcome::PredicateViolation { .. } => "predicate_violation",
        };

        let mut result = GlueResult::success("run", "contract", &contract.id.name)
            .with_resource(
                &contract.id.cid,
                &format!("exec_{}", &trace_id[..8]),
                "execution",
            )
            .with_state(state)
            .with_receipt(GlueReceipt::new(&trace_id));

        result.data.insert(
            "contract_cid".into(),
            serde_json::Value::String(contract.id.cid.clone()),
        );
        result.data.insert(
            "honesty".into(),
            serde_json::json!(
                "lab/dev stub handlers only — production uses platform ContractExecutor via cnktros/workflow ENABLE"
            ),
        );
        result.data.insert(
            "ir_cid".into(),
            serde_json::Value::String(emit.connector_ir.ir_cid.clone()),
        );
        result.data.insert(
            "contract_name".into(),
            serde_json::Value::String(contract.id.name.clone()),
        );
        result.data.insert(
            "receipt_cid".into(),
            serde_json::Value::String(receipt.receipt_cid.clone()),
        );
        result.data.insert(
            "outcome".into(),
            serde_json::to_value(&receipt.outcome).unwrap_or_default(),
        );
        result.data.insert(
            "final_state".into(),
            serde_json::to_value(&receipt.final_state).unwrap_or_default(),
        );
        return Ok(result);
    } else {
        // Target is inline YAML CLS source - legacy ClsCompiler path
        ClsCompiler::compile(&target).map_err(|e| {
            GlueError::new(
                ErrorCode::CompileError,
                format!("CLS compilation failed: {:?}", e),
            )
        })?
    };

    // Execute the contract with stub handlers (lab/dev only — gated above)
    let mut executor = ContractExecutor::stub();
    let receipt = executor
        .execute(&contract, &agent_pid, &session_id, inputs.clone())
        .map_err(|e| {
            GlueError::new(
                ErrorCode::ExecutionError,
                format!("CLS execution failed: {:?}", e),
            )
        })?;

    // Map execution outcome to GLUE result
    let state = match &receipt.outcome {
        ExecutionOutcome::Success => "completed",
        ExecutionOutcome::Failed { .. } => "failed",
        ExecutionOutcome::Aborted { .. } => "aborted",
        ExecutionOutcome::Timeout => "timeout",
        ExecutionOutcome::BudgetExceeded { .. } => "budget_exceeded",
        ExecutionOutcome::PredicateViolation { .. } => "predicate_violation",
    };

    let mut result = GlueResult::success("run", "contract", &contract.id.name)
        .with_resource(
            &contract.id.cid,
            &format!("exec_{}", &trace_id[..8]),
            "execution",
        )
        .with_state(state)
        .with_receipt(GlueReceipt::new(&trace_id));

    // Attach execution details
    result.data.insert(
        "contract_cid".into(),
        serde_json::Value::String(contract.id.cid.clone()),
    );
    result.data.insert(
        "contract_name".into(),
        serde_json::Value::String(contract.id.name.clone()),
    );
    result.data.insert(
        "receipt_cid".into(),
        serde_json::Value::String(receipt.receipt_cid.clone()),
    );
    result.data.insert(
        "outcome".into(),
        serde_json::to_value(&receipt.outcome).unwrap_or_default(),
    );
    result.data.insert(
        "final_state".into(),
        serde_json::Value::String(receipt.final_state.clone()),
    );
    result.data.insert(
        "outputs".into(),
        serde_json::to_value(&receipt.outputs).unwrap_or_default(),
    );
    result.data.insert(
        "resource_usage".into(),
        serde_json::to_value(&receipt.resource_usage).unwrap_or_default(),
    );
    result.data.insert(
        "duration_ms".into(),
        serde_json::Value::Number(receipt.duration_ms.into()),
    );
    result.data.insert(
        "trace".into(),
        serde_json::to_value(&receipt.trace).unwrap_or_default(),
    );
    result.data.insert(
        "events".into(),
        serde_json::to_value(&receipt.events).unwrap_or_default(),
    );

    if let Some(p) = policy {
        result
            .data
            .insert("policy".into(), serde_json::Value::String(p));
    }

    Ok(result)
}

pub fn execute_protocol_action(
    _glue: Glue,
    contract: ProtocolContract,
    action: ProtocolAction,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let target = contract
        .endpoint
        .clone()
        .or(contract.agent.clone())
        .or(contract.namespace.clone())
        .unwrap_or_else(|| contract.kind.as_str().to_string());

    let mut result = GlueResult::success(action.verb(), "protocol", &target)
        .with_resource(&target, &format!("proto_{}", &trace_id[..8]), "protocol")
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "protocol_kind".into(),
        serde_json::Value::String(contract.kind.as_str().into()),
    );
    result.data.insert(
        "protocol_mode".into(),
        serde_json::to_value(contract.mode).unwrap_or_default(),
    );
    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result.data.insert(
        "action".into(),
        serde_json::to_value(&action).unwrap_or_default(),
    );

    Ok(result)
}

pub fn execute_pipeline(_glue: Glue, contract: PipelineContract) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let mut result = GlueResult::success("run", "pipeline", &contract.id)
        .with_resource(
            &contract.id,
            &format!("pipe_{}", &trace_id[..8]),
            "pipeline",
        )
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "agent".into(),
        serde_json::to_value(&contract.agent).unwrap_or_default(),
    );
    result.data.insert(
        "stages".into(),
        serde_json::to_value(&contract.stages).unwrap_or_default(),
    );
    result.data.insert(
        "rollback".into(),
        serde_json::Value::Bool(contract.rollback),
    );
    result.data.insert(
        "streaming".into(),
        serde_json::Value::Bool(contract.streaming),
    );
    result.data.insert(
        "audit_required".into(),
        serde_json::Value::Bool(contract.audit_required),
    );

    Ok(result)
}

pub fn execute_cnp_session(
    _glue: Glue,
    contract: CnpSessionContract,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let local_agent = contract
        .local_agent
        .clone()
        .unwrap_or_else(|| "glue-agent".to_string());
    let mut session = EngineCnpSession::new(local_agent.clone(), contract.remote_agent.clone());
    session.noise_channel_id = Some(
        contract
            .channel_binding
            .clone()
            .unwrap_or_else(|| format!("ch-{}-{}", local_agent, contract.remote_agent)),
    );
    session.port_id = Some(format!("port-{}-{}", local_agent, contract.remote_agent));
    session.ttl_ms = CNP_DEFAULT_TTL_MS;
    session
        .transition(EngineCnpSessionState::Active)
        .map_err(map_cnp_error)?;

    let mut result = GlueResult::success("establish", "cnp_session", &contract.remote_agent)
        .with_resource(
            &session.session_id,
            &format!("cnps_{}", &trace_id[..8]),
            "cnp_session",
        )
        .with_state("active")
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result.data.insert(
        "engine_session".into(),
        serde_json::to_value(&session).unwrap_or_default(),
    );
    result.data.insert(
        "remote_cell".into(),
        serde_json::to_value(&contract.remote_cell).unwrap_or_default(),
    );
    result.data.insert(
        "namespace".into(),
        serde_json::to_value(&contract.namespace).unwrap_or_default(),
    );
    result.data.insert(
        "evidence_required".into(),
        serde_json::Value::Bool(contract.evidence_required),
    );
    result.data.insert(
        "can_send".into(),
        serde_json::Value::Bool(session.can_send()),
    );

    Ok(result)
}

pub fn execute_cnp_port(_glue: Glue, contract: CnpPortContract) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let port_id = contract.id.clone();
    let engine_port_type = map_cnp_port_type(contract.port_type);
    let engine_direction = map_cnp_port_direction(contract.direction);

    let mut result = GlueResult::success("open", "cnp_port", &port_id)
        .with_resource(&port_id, &format!("cnpp_{}", &trace_id[..8]), "cnp_port")
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result.data.insert(
        "engine_port_type".into(),
        serde_json::to_value(engine_port_type).unwrap_or_default(),
    );
    result.data.insert(
        "engine_direction".into(),
        serde_json::to_value(engine_direction).unwrap_or_default(),
    );
    result.data.insert(
        "bound_agents".into(),
        serde_json::to_value(&contract.bound_agents).unwrap_or_default(),
    );
    result.data.insert(
        "allowed_payload_types".into(),
        serde_json::to_value(&contract.allowed_payload_types).unwrap_or_default(),
    );

    Ok(result)
}

pub fn execute_cnp_capability(
    _glue: Glue,
    contract: CnpCapabilityContract,
) -> Result<GlueResult, GlueError> {
    if contract.delegation_depth > CNP_MAX_DELEGATION_DEPTH {
        return Err(GlueError::invalid_input(
            "cnp capability delegation depth exceeds engine maximum",
        )
        .with_detail(format!(
            "got {}, max {}",
            contract.delegation_depth, CNP_MAX_DELEGATION_DEPTH
        )));
    }

    let trace_id = generate_trace_id();
    let target = format!("{}:{}", contract.port_id, contract.holder_agent);
    let engine_permission = map_cnp_port_permission(contract.permission);

    let mut result = GlueResult::success("grant", "cnp_capability", &target)
        .with_resource(
            &target,
            &format!("cnpc_{}", &trace_id[..8]),
            "cnp_capability",
        )
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result.data.insert(
        "engine_permission".into(),
        serde_json::to_value(engine_permission).unwrap_or_default(),
    );
    result.data.insert(
        "delegation_depth".into(),
        serde_json::Value::Number(contract.delegation_depth.into()),
    );

    Ok(result)
}

pub fn execute_cnp_message(
    _glue: Glue,
    contract: CnpMessageContract,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let payload = build_engine_cnp_payload(contract.payload_kind, contract.body.clone())?;
    let from_agent = contract
        .from_agent
        .clone()
        .unwrap_or_else(|| "glue-agent".to_string());
    let mut message = EngineCnpMessage::new(from_agent, contract.to_agent.clone(), payload);
    if let Some(session_id) = contract.session_id.clone() {
        message = message.with_session(session_id);
    }
    if let Some(port_id) = contract.port_id.clone() {
        message = message.with_port(port_id);
    }
    message.ttl_ms = contract.ttl_ms.unwrap_or(CNP_DEFAULT_TTL_MS);
    if let Some(priority) = contract.priority {
        message = message.with_priority(priority);
    }
    if let Some(reply_to) = contract.reply_to.clone() {
        message = message.with_reply_to(reply_to);
    }
    if let Some(evidence_cid) = contract.evidence_cid.clone() {
        message = message.with_evidence(evidence_cid);
    }
    message.trace_id = contract.trace_id.clone();
    message.metadata = build_engine_metadata(&contract.metadata)?;

    let payload_size_bytes = serde_json::to_vec(&message)
        .map_err(|e| {
            GlueError::new(
                ErrorCode::ExecutionError,
                "failed to serialize engine cnp message",
            )
            .with_detail(e.to_string())
        })?
        .len() as u64;
    if payload_size_bytes > CNP_MAX_MESSAGE_BYTES {
        return Err(
            GlueError::invalid_input("cnp message exceeds engine max message size").with_detail(
                format!("{} > {} bytes", payload_size_bytes, CNP_MAX_MESSAGE_BYTES),
            ),
        );
    }

    let mut result = GlueResult::success("send", "cnp_message", &contract.to_agent)
        .with_resource(
            &message.message_id,
            &format!("cnpm_{}", &trace_id[..8]),
            "cnp_message",
        )
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result.data.insert(
        "engine_message".into(),
        serde_json::to_value(&message).unwrap_or_default(),
    );
    result.data.insert(
        "payload_kind".into(),
        serde_json::to_value(contract.payload_kind).unwrap_or_default(),
    );
    result.data.insert(
        "payload_size_bytes".into(),
        serde_json::Value::Number(payload_size_bytes.into()),
    );
    result.data.insert(
        "is_cognitive".into(),
        serde_json::Value::Bool(message.is_cognitive()),
    );
    result.data.insert(
        "expects_response".into(),
        serde_json::Value::Bool(message.expects_response()),
    );
    result.data.insert(
        "route_status".into(),
        serde_json::to_value(CnpRouteStatus::PendingAck).unwrap_or_default(),
    );

    Ok(result)
}

pub fn execute_cnp_route(_glue: Glue, contract: CnpRouteContract) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let local_cell = "glue-local";
    let target_cell = contract
        .target_cell
        .clone()
        .unwrap_or_else(|| local_cell.to_string());
    let mut router = EngineCnpRouter::new(local_cell);
    router.register_agent(&contract.target_agent, &target_cell);
    if target_cell != local_cell {
        router.set_cell_status(&target_cell, EngineCellStatus::Reachable);
    }
    let is_local = router.is_local(&contract.target_agent);
    let resolved_status = if is_local {
        CnpRouteStatus::Local
    } else {
        CnpRouteStatus::Forwarded
    };

    let mut result = GlueResult::success("resolve", "cnp_route", &contract.target_agent)
        .with_resource(
            &contract.target_agent,
            &format!("cnpr_{}", &trace_id[..8]),
            "cnp_route",
        )
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "contract".into(),
        serde_json::to_value(&contract).unwrap_or_default(),
    );
    result
        .data
        .insert("sticky".into(), serde_json::Value::Bool(contract.sticky));
    result
        .data
        .insert("target_cell".into(), serde_json::Value::String(target_cell));
    result
        .data
        .insert("is_local".into(), serde_json::Value::Bool(is_local));
    result.data.insert(
        "ack_timeout_ms".into(),
        serde_json::Value::Number(contract.ack_timeout_ms.unwrap_or(CNP_ACK_TIMEOUT_MS).into()),
    );
    result.data.insert(
        "max_retries".into(),
        serde_json::Value::Number(contract.max_retries.unwrap_or(CNP_MAX_RETRIES).into()),
    );
    result.data.insert(
        "resolved_status".into(),
        serde_json::to_value(contract.expected_status.unwrap_or(resolved_status))
            .unwrap_or_default(),
    );

    Ok(result)
}

pub fn execute_memory_contract_write(
    glue: Glue,
    contract: MemoryContract,
    injection: DataInjection,
) -> Result<GlueResult, GlueError> {
    execute_remember(
        glue,
        contract.namespace.clone(),
        None,
        Some(contract.namespace.clone()),
        Some(contract),
        Some(injection),
    )
}

pub fn execute_knowledge_ingest(
    _glue: Glue,
    contract: KnowledgeContract,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let namespace = require_knowledge_namespace(&contract.namespace)?;

    let mut result = GlueResult::success("ingest", "knowledge", &namespace)
        .with_resource(&namespace, &format!("kn_{}", &trace_id[..8]), "knowledge")
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("namespace".into(), serde_json::Value::String(namespace));
    result.data.insert(
        "source_kind".into(),
        serde_json::Value::String(contract.source.kind().into()),
    );
    result.data.insert(
        "token_budget".into(),
        serde_json::Value::Number(contract.token_budget.into()),
    );
    result.data.insert(
        "max_facts".into(),
        serde_json::Value::Number(contract.max_facts.into()),
    );
    result.data.insert(
        "graph_ingest".into(),
        serde_json::Value::Bool(contract.graph_ingest),
    );
    result.data.insert(
        "contradiction_detection".into(),
        serde_json::Value::Bool(contract.contradiction_detection),
    );
    result.data.insert(
        "storage_tier".into(),
        serde_json::to_value(contract.storage_tier).unwrap_or_default(),
    );

    match contract.source {
        KnowledgeSource::Namespace(ns) => {
            result
                .data
                .insert("source_namespace".into(), serde_json::Value::String(ns));
        }
        KnowledgeSource::Injection(injection) => {
            result.data.insert(
                "injection_kind".into(),
                serde_json::Value::String(injection.kind().into()),
            );
            result.data.insert(
                "estimated_size_bytes".into(),
                serde_json::Value::Number(injection.estimated_size_bytes().into()),
            );
        }
        KnowledgeSource::CompiledKnowledge(cid) => {
            result
                .data
                .insert("compiled_knowledge".into(), serde_json::Value::String(cid));
        }
        KnowledgeSource::Seed(seed) => {
            result
                .data
                .insert("seed".into(), serde_json::Value::String(seed));
        }
    }

    Ok(result)
}

pub fn execute_knowledge_query(
    _glue: Glue,
    namespace: String,
    query: KnowledgeQuery,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let namespace = require_knowledge_namespace(&normalize_knowledge_namespace(namespace))?;

    let mut result = GlueResult::success("query", "knowledge", &namespace)
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("namespace".into(), serde_json::Value::String(namespace));
    result.data.insert(
        "entities".into(),
        serde_json::to_value(&query.entities).unwrap_or_default(),
    );
    result.data.insert(
        "keywords".into(),
        serde_json::to_value(&query.keywords).unwrap_or_default(),
    );
    result.data.insert(
        "token_budget".into(),
        serde_json::Value::Number(query.token_budget.unwrap_or(4096).into()),
    );
    result.data.insert(
        "max_facts".into(),
        serde_json::Value::Number(query.max_facts.unwrap_or(20).into()),
    );
    result
        .data
        .insert("facts".into(), serde_json::Value::Array(vec![]));

    Ok(result)
}

pub fn execute_remember(
    glue: Glue,
    key: String,
    content: Option<String>,
    namespace: Option<String>,
    contract: Option<MemoryContract>,
    injection: Option<DataInjection>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let requested_ns = namespace
        .clone()
        .unwrap_or_else(|| glue.config().default_namespace.clone());
    let mut contract = contract.unwrap_or_else(|| MemoryContract::new(requested_ns));
    if let Some(ns) = namespace {
        contract.namespace = normalize_memory_namespace(ns);
    }
    let ns = require_memory_namespace(&contract.namespace)?;
    let injection = injection.or_else(|| content.map(DataInjection::Text));

    let mut result = GlueResult::success("remember", "memory", &key)
        .with_resource(&key, &format!("mem_{}", &trace_id[..8]), "memory")
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("namespace".into(), serde_json::Value::String(ns));
    result.data.insert(
        "packet_type".into(),
        serde_json::Value::String(contract.packet_type.clone()),
    );
    result.data.insert(
        "auto_enrich".into(),
        serde_json::Value::Bool(contract.auto_enrich),
    );
    result.data.insert(
        "contradiction_check".into(),
        serde_json::Value::Bool(contract.contradiction_check),
    );
    result.data.insert(
        "tags".into(),
        serde_json::to_value(&contract.tags).unwrap_or_default(),
    );
    if let Some(memory_type) = contract.memory_type {
        result
            .data
            .insert("memory_type".into(), serde_json::Value::String(memory_type));
    }
    if let Some(session_id) = contract.session_id {
        result
            .data
            .insert("session_id".into(), serde_json::Value::String(session_id));
    }
    if let Some(injection) = injection {
        result.data.insert(
            "injection_kind".into(),
            serde_json::Value::String(injection.kind().into()),
        );
        result.data.insert(
            "content_length".into(),
            serde_json::Value::Number(injection.estimated_size_bytes().into()),
        );
    }

    Ok(result)
}

pub fn execute_recall(
    glue: Glue,
    query: String,
    namespace: Option<String>,
    limit: Option<usize>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let ns = require_memory_namespace(&normalize_memory_namespace(
        namespace.unwrap_or_else(|| glue.config().default_namespace.clone()),
    ))?;

    let mut result =
        GlueResult::success("recall", "memory", &query).with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("namespace".into(), serde_json::Value::String(ns));
    result.data.insert(
        "limit".into(),
        serde_json::Value::Number((limit.unwrap_or(10)).into()),
    );
    result
        .data
        .insert("results".into(), serde_json::Value::Array(vec![]));

    Ok(result)
}

pub fn execute_search(
    glue: Glue,
    query: String,
    namespace: Option<String>,
    limit: Option<usize>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let ns = require_knowledge_namespace(&normalize_knowledge_namespace(
        namespace.unwrap_or_else(|| glue.config().default_namespace.clone()),
    ))?;

    let mut result = GlueResult::success("search", "knowledge", &query)
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("namespace".into(), serde_json::Value::String(ns));
    result.data.insert(
        "limit".into(),
        serde_json::Value::Number((limit.unwrap_or(20)).into()),
    );
    result
        .data
        .insert("results".into(), serde_json::Value::Array(vec![]));

    Ok(result)
}

pub fn execute_list(
    _glue: Glue,
    noun: Noun,
    namespace: Option<String>,
    limit: Option<usize>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("list", noun.as_str(), "all").with_receipt(GlueReceipt::new(&trace_id));

    if let Some(ns) = namespace {
        result
            .data
            .insert("namespace".into(), serde_json::Value::String(ns));
    }
    result.data.insert(
        "limit".into(),
        serde_json::Value::Number((limit.unwrap_or(50)).into()),
    );
    result
        .data
        .insert("items".into(), serde_json::Value::Array(vec![]));
    result
        .data
        .insert("total".into(), serde_json::Value::Number(0.into()));

    Ok(result)
}

pub fn execute_show(_glue: Glue, noun: Noun, target: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let result = GlueResult::success("show", noun.as_str(), &target)
        .with_resource(
            &target,
            &format!("{}_{}", noun.as_str(), &trace_id[..8]),
            noun.as_str(),
        )
        .with_receipt(GlueReceipt::new(&trace_id));

    Ok(result)
}

pub fn execute_audit(_glue: Glue, target: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("audit", "execution", &target)
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("trace".into(), serde_json::Value::Array(vec![]));
    result
        .data
        .insert("decisions".into(), serde_json::Value::Array(vec![]));

    Ok(result)
}

pub fn execute_verify(
    _glue: Glue,
    what: String,
    for_agent: Option<String>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("verify", "compliance", &what)
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("compliant".into(), serde_json::Value::Bool(true));
    if let Some(agent) = for_agent {
        result
            .data
            .insert("agent".into(), serde_json::Value::String(agent));
    }

    Ok(result)
}

// =============================================================================
// Agent Operations
// =============================================================================

pub fn agent_start(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();
    let uid = format!("agt_{}", &trace_id[..12]);

    Ok(GlueResult::success("start", "agent", &name)
        .with_resource(&name, &uid, "agent")
        .with_state("running")
        .with_receipt(GlueReceipt::new(&trace_id)))
}

pub fn agent_stop(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    Ok(GlueResult::success("stop", "agent", &name)
        .with_resource(&name, &format!("agt_{}", &trace_id[..12]), "agent")
        .with_state("stopped")
        .with_receipt(GlueReceipt::new(&trace_id)))
}

pub fn agent_status(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("status", "agent", &name)
        .with_resource(&name, &format!("agt_{}", &trace_id[..12]), "agent")
        .with_state("running")
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("uptime_ms".into(), serde_json::Value::Number(0.into()));
    result
        .data
        .insert("executions".into(), serde_json::Value::Number(0.into()));

    Ok(result)
}

pub fn agent_pause(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    Ok(GlueResult::success("pause", "agent", &name)
        .with_resource(&name, &format!("agt_{}", &trace_id[..12]), "agent")
        .with_state("paused")
        .with_receipt(GlueReceipt::new(&trace_id)))
}

pub fn agent_resume(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    Ok(GlueResult::success("resume", "agent", &name)
        .with_resource(&name, &format!("agt_{}", &trace_id[..12]), "agent")
        .with_state("running")
        .with_receipt(GlueReceipt::new(&trace_id)))
}

// =============================================================================
// Memory Operations
// =============================================================================

pub fn memory_write(
    _glue: Glue,
    namespace: String,
    content: String,
) -> Result<GlueResult, GlueError> {
    let namespace = require_memory_namespace(&normalize_memory_namespace(namespace))?;
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("write", "memory", &namespace)
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert(
        "bytes_written".into(),
        serde_json::Value::Number(content.len().into()),
    );

    Ok(result)
}

pub fn memory_read(_glue: Glue, namespace: String) -> Result<GlueResult, GlueError> {
    let namespace = require_memory_namespace(&normalize_memory_namespace(namespace))?;
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("read", "memory", &namespace).with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("content".into(), serde_json::Value::Null);

    Ok(result)
}

pub fn memory_range(
    _glue: Glue,
    namespace: String,
    start: usize,
    end: usize,
) -> Result<GlueResult, GlueError> {
    let namespace = require_memory_namespace(&normalize_memory_namespace(namespace))?;
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("range", "memory", &namespace)
        .with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("start".into(), serde_json::Value::Number(start.into()));
    result
        .data
        .insert("end".into(), serde_json::Value::Number(end.into()));
    result
        .data
        .insert("items".into(), serde_json::Value::Array(vec![]));

    Ok(result)
}

// =============================================================================
// Tool Operations
// =============================================================================

pub fn tool_call(
    _glue: Glue,
    name: String,
    params: serde_json::Value,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("call", "tool", &name).with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert("params".into(), params);
    result.data.insert("output".into(), serde_json::Value::Null);

    Ok(result)
}

pub fn tool_call_with_contract(
    _glue: Glue,
    name: String,
    params: serde_json::Value,
    contract: ToolContract,
    security: Option<SecurityContract>,
) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result = GlueResult::success("call", "tool", &name)
        .with_resource(&name, &format!("tool_{}", &trace_id[..8]), "tool")
        .with_receipt(GlueReceipt::new(&trace_id));

    result.data.insert("params".into(), params);
    result.data.insert(
        "tool_contract".into(),
        serde_json::to_value(contract).unwrap_or_default(),
    );
    result.data.insert(
        "security_contract".into(),
        serde_json::to_value(security.unwrap_or_default()).unwrap_or_default(),
    );
    result.data.insert("output".into(), serde_json::Value::Null);

    Ok(result)
}

pub fn tool_info(_glue: Glue, name: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("info", "tool", &name).with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("name".into(), serde_json::Value::String(name));
    result
        .data
        .insert("available".into(), serde_json::Value::Bool(true));

    Ok(result)
}

// =============================================================================
// Policy Operations
// =============================================================================

pub fn policy_bind(_glue: Glue, policy: String, agent: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("bind", "policy", &policy).with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("agent".into(), serde_json::Value::String(agent));
    result
        .data
        .insert("bound".into(), serde_json::Value::Bool(true));

    Ok(result)
}

pub fn policy_check(_glue: Glue, policy: String, agent: String) -> Result<GlueResult, GlueError> {
    let trace_id = generate_trace_id();

    let mut result =
        GlueResult::success("check", "policy", &policy).with_receipt(GlueReceipt::new(&trace_id));

    result
        .data
        .insert("agent".into(), serde_json::Value::String(agent));
    result
        .data
        .insert("compliant".into(), serde_json::Value::Bool(true));

    Ok(result)
}

// =============================================================================
// Helpers
// =============================================================================

fn map_cnp_error(error: EngineCnpError) -> GlueError {
    match error {
        EngineCnpError::InvalidStateTransition { from, to } => GlueError::new(
            ErrorCode::InvalidState,
            "invalid cnp session state transition",
        )
        .with_detail(format!("{} -> {}", from, to)),
        EngineCnpError::RoutingError { detail }
        | EngineCnpError::SessionError { detail }
        | EngineCnpError::ChannelError { detail }
        | EngineCnpError::TransportError { detail }
        | EngineCnpError::NegotiationError { detail }
        | EngineCnpError::CodecError { detail } => {
            GlueError::new(ErrorCode::ExecutionError, "cnp runtime error").with_detail(detail)
        }
        EngineCnpError::SecurityError { verdict } => {
            GlueError::new(ErrorCode::PolicyViolation, "cnp security validation failed")
                .with_detail(verdict)
        }
        EngineCnpError::MessageExpired { message_id, ttl_ms } => {
            GlueError::new(ErrorCode::Timeout, "cnp message expired")
                .with_detail(format!("message={}, ttl_ms={}", message_id, ttl_ms))
        }
        EngineCnpError::RateLimitExceeded { agent, limit } => {
            GlueError::new(ErrorCode::QuotaReached, "cnp rate limit exceeded")
                .with_detail(format!("agent={}, limit={}", agent, limit))
        }
        EngineCnpError::AgentNotFound { agent_pid } => {
            GlueError::not_found("cnp target agent").with_detail(agent_pid)
        }
        EngineCnpError::VersionMismatch { local, remote } => {
            GlueError::new(ErrorCode::ValidationError, "cnp version mismatch")
                .with_detail(format!("local={}, remote={}", local, remote))
        }
        EngineCnpError::PayloadTooLarge { size, max } => {
            GlueError::invalid_input("cnp payload too large")
                .with_detail(format!("{} > {} bytes", size, max))
        }
    }
}

fn map_cnp_port_type(port_type: crate::cnp::CnpPortType) -> EngineCnpPortType {
    match port_type {
        crate::cnp::CnpPortType::MemoryShare => EngineCnpPortType::MemoryShare,
        crate::cnp::CnpPortType::ToolDelegate => EngineCnpPortType::ToolDelegate,
        crate::cnp::CnpPortType::EventStream => EngineCnpPortType::EventStream,
        crate::cnp::CnpPortType::RequestResponse => EngineCnpPortType::RequestResponse,
        crate::cnp::CnpPortType::Broadcast => EngineCnpPortType::Broadcast,
        crate::cnp::CnpPortType::Pipeline => EngineCnpPortType::Pipeline,
    }
}

fn map_cnp_port_direction(direction: crate::cnp::CnpPortDirection) -> EngineCnpPortDirection {
    match direction {
        crate::cnp::CnpPortDirection::Send => EngineCnpPortDirection::Send,
        crate::cnp::CnpPortDirection::Receive => EngineCnpPortDirection::Receive,
        crate::cnp::CnpPortDirection::Bidirectional => EngineCnpPortDirection::Bidirectional,
    }
}

fn map_cnp_port_permission(permission: crate::cnp::CnpPortPermission) -> EngineCnpPortPermission {
    match permission {
        crate::cnp::CnpPortPermission::Send => EngineCnpPortPermission::Send,
        crate::cnp::CnpPortPermission::Receive => EngineCnpPortPermission::Receive,
        crate::cnp::CnpPortPermission::SendReceive => EngineCnpPortPermission::SendReceive,
    }
}

fn cnp_payload_tag(kind: crate::cnp::CnpPayloadKind) -> &'static str {
    match kind {
        crate::cnp::CnpPayloadKind::Raw => "raw",
        crate::cnp::CnpPayloadKind::Sensor => "sensor",
        crate::cnp::CnpPayloadKind::Actuation => "actuation",
        crate::cnp::CnpPayloadKind::Tensor => "tensor",
        crate::cnp::CnpPayloadKind::PacketShare => "packet_share",
        crate::cnp::CnpPayloadKind::ToolGrant => "tool_grant",
        crate::cnp::CnpPayloadKind::Event => "event",
        crate::cnp::CnpPayloadKind::Request => "request",
        crate::cnp::CnpPayloadKind::Response => "response",
        crate::cnp::CnpPayloadKind::PipelineHandoff => "pipeline_handoff",
        crate::cnp::CnpPayloadKind::Cognitive => "cognitive",
        crate::cnp::CnpPayloadKind::KnowledgeRequest => "knowledge_request",
        crate::cnp::CnpPayloadKind::KnowledgeResponse => "knowledge_response",
        crate::cnp::CnpPayloadKind::Negotiation => "negotiation",
        crate::cnp::CnpPayloadKind::Text => "text",
    }
}

fn build_engine_metadata(
    metadata: &serde_json::Value,
) -> Result<HashMap<String, String>, GlueError> {
    match metadata {
        serde_json::Value::Object(map) => Ok(map
            .iter()
            .map(|(key, value)| {
                let normalized = value
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| value.to_string());
                (key.clone(), normalized)
            })
            .collect()),
        serde_json::Value::Null => Ok(HashMap::new()),
        _ => Err(GlueError::invalid_input(
            "cnp metadata must be a JSON object",
        )),
    }
}

fn build_engine_cnp_payload(
    kind: crate::cnp::CnpPayloadKind,
    body: serde_json::Value,
) -> Result<EngineCnpPayload, GlueError> {
    let tagged_value = match (kind, body) {
        (crate::cnp::CnpPayloadKind::Text, serde_json::Value::String(content)) => {
            serde_json::json!({ "type": "text", "content": content })
        }
        (payload_kind, serde_json::Value::Object(mut map)) => {
            map.insert(
                "type".to_string(),
                serde_json::Value::String(cnp_payload_tag(payload_kind).to_string()),
            );
            serde_json::Value::Object(map)
        }
        (payload_kind, _) => {
            return Err(GlueError::invalid_input(
                "cnp payload body must be a JSON object for this payload kind",
            )
            .with_detail(format!("payload_kind={}", cnp_payload_tag(payload_kind))));
        }
    };

    serde_json::from_value(tagged_value).map_err(|e| {
        GlueError::new(
            ErrorCode::ValidationError,
            "failed to build engine cnp payload",
        )
        .with_detail(e.to_string())
    })
}

fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", ts)
}

fn require_memory_namespace(namespace: &str) -> Result<String, GlueError> {
    if namespace.starts_with("m/") {
        Ok(namespace.to_string())
    } else {
        Err(GlueError::invalid_input(
            "memory operations require an m/ namespace or MemoryContract",
        ))
    }
}

fn require_knowledge_namespace(namespace: &str) -> Result<String, GlueError> {
    if namespace.starts_with("k/") {
        Ok(namespace.to_string())
    } else {
        Err(GlueError::invalid_input(
            "knowledge operations require a k/ namespace or KnowledgeContract",
        ))
    }
}
