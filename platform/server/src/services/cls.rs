//! CLS Contract API Service
//!
//! Endpoints for compiling, validating, and managing CLS contracts.

use crate::state::SharedState;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

// =============================================================================
// Types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    #[serde(alias = "cls_source")]
    pub source: String,
    #[serde(default)]
    pub options: CompileOptions,
}

fn seeded_cls_packages() -> Vec<ClsPackageInfo> {
    vec![
        ClsPackageInfo {
            id: "pkg-basic-tool-agent".into(),
            name: "Basic Tool Agent Package".into(),
            version: "v1.0.0".into(),
            status: "active".into(),
            install_status: "installed".into(),
            owner: "Connector Platform".into(),
            domain: "general".into(),
            target_binding: serde_json::json!({"agent": "agent-demo", "node": "node-a", "environment": "production"}),
            replacement_lineage: vec![
                "pkg-basic-tool-agent@v0.9.0".into(),
                "pkg-basic-tool-agent@v1.0.0".into(),
            ],
            runtime_prerequisites: vec![
                "llm_infer tool bridge".into(),
                "agent namespace /m/agent".into(),
                "policy gate enabled".into(),
            ],
            dependency_review: vec!["llm_infer >= 1.0".into(), "approval policy optional".into()],
            install_proof: serde_json::json!({"proof_id": "proof-cls-install-001", "receipt_cid": "cid-install-proof-001", "execution_proof": "verified"}),
        },
        ClsPackageInfo {
            id: "pkg-review-workflow".into(),
            name: "Review Workflow Package".into(),
            version: "v1.2.0".into(),
            status: "active".into(),
            install_status: "deployed".into(),
            owner: "Connector Ops".into(),
            domain: "workflow".into(),
            target_binding: serde_json::json!({"agent": "review-agent", "node": "node-b", "environment": "staging"}),
            replacement_lineage: vec![
                "pkg-review-workflow@v1.0.0".into(),
                "pkg-review-workflow@v1.1.0".into(),
                "pkg-review-workflow@v1.2.0".into(),
            ],
            runtime_prerequisites: vec![
                "approval_queue bridge".into(),
                "notify bridge".into(),
                "review namespace /m/review".into(),
            ],
            dependency_review: vec!["approval_queue >= 2.1".into(), "notify >= 1.4".into()],
            install_proof: serde_json::json!({"proof_id": "proof-cls-install-002", "receipt_cid": "cid-install-proof-002", "execution_proof": "verified"}),
        },
    ]
}

fn cls_package_registry() -> &'static RwLock<HashMap<String, ClsPackageInfo>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, ClsPackageInfo>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let seeded = seeded_cls_packages()
            .into_iter()
            .map(|pkg| (pkg.id.clone(), pkg))
            .collect::<HashMap<_, _>>();
        RwLock::new(seeded)
    })
}

fn cls_templates() -> Vec<TemplateInfo> {
    vec![
        TemplateInfo {
            id: "basic_tool_agent".into(),
            name: "Basic Tool Agent".into(),
            description: "Simple agent with tool calling".into(),
            category: "general".into(),
            lifecycle_status: "active".into(),
            version: "v1".into(),
            owner: "Connector Platform".into(),
            domain: "general".into(),
            required_tools: vec!["llm_infer".into()],
            required_namespaces: vec!["/m/agent".into()],
            required_capabilities: vec!["general.process".into()],
            execution_count: 14,
            last_execution: Some("2026-04-02T22:30:00Z".into()),
        },
        TemplateInfo {
            id: "rag_agent".into(),
            name: "RAG Agent".into(),
            description: "Retrieval-augmented generation".into(),
            category: "knowledge".into(),
            lifecycle_status: "active".into(),
            version: "v2".into(),
            owner: "Connector Knowledge".into(),
            domain: "knowledge".into(),
            required_tools: vec!["llm_infer".into(), "vector_search".into()],
            required_namespaces: vec!["/k/shared".into(), "/m/agent".into()],
            required_capabilities: vec!["knowledge.retrieve".into(), "knowledge.answer".into()],
            execution_count: 29,
            last_execution: Some("2026-04-02T23:45:00Z".into()),
        },
        TemplateInfo {
            id: "review_workflow".into(),
            name: "Review Workflow".into(),
            description: "Human-in-the-loop review".into(),
            category: "workflow".into(),
            lifecycle_status: "active".into(),
            version: "v1".into(),
            owner: "Connector Ops".into(),
            domain: "workflow".into(),
            required_tools: vec!["approval_queue".into(), "notify".into()],
            required_namespaces: vec!["/m/review".into()],
            required_capabilities: vec!["workflow.review".into(), "workflow.escalate".into()],
            execution_count: 11,
            last_execution: Some("2026-04-02T21:10:00Z".into()),
        },
        TemplateInfo {
            id: "claims_processor".into(),
            name: "Claims Processor".into(),
            description: "Healthcare claims processing".into(),
            category: "healthcare".into(),
            lifecycle_status: "active".into(),
            version: "v3".into(),
            owner: "Connector Health".into(),
            domain: "healthcare".into(),
            required_tools: vec!["parser".into(), "validator".into(), "submitter".into()],
            required_namespaces: vec!["/m/claims".into(), "/k/policies".into()],
            required_capabilities: vec!["claims.validate".into(), "claims.route".into()],
            execution_count: 7,
            last_execution: Some("2026-04-01T18:20:00Z".into()),
        },
        TemplateInfo {
            id: "document_analyzer".into(),
            name: "Document Analyzer".into(),
            description: "Document analysis pipeline".into(),
            category: "documents".into(),
            lifecycle_status: "active".into(),
            version: "v2".into(),
            owner: "Connector Docs".into(),
            domain: "documents".into(),
            required_tools: vec!["ocr".into(), "classifier".into()],
            required_namespaces: vec!["/v/uploads".into(), "/k/docs".into()],
            required_capabilities: vec!["document.extract".into(), "document.classify".into()],
            execution_count: 19,
            last_execution: Some("2026-04-02T20:00:00Z".into()),
        },
        TemplateInfo {
            id: "multi_step_saga".into(),
            name: "Multi-Step Saga".into(),
            description: "Compensating transaction workflow".into(),
            category: "workflow".into(),
            lifecycle_status: "active".into(),
            version: "v1".into(),
            owner: "Connector Platform".into(),
            domain: "workflow".into(),
            required_tools: vec!["orchestrator".into(), "compensator".into()],
            required_namespaces: vec!["/m/saga".into()],
            required_capabilities: vec!["workflow.saga".into(), "workflow.recover".into()],
            execution_count: 9,
            last_execution: Some("2026-04-02T19:25:00Z".into()),
        },
    ]
}

#[derive(Debug, Default, Deserialize)]
pub struct CompileOptions {
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub validate_only: bool,
}

#[derive(Debug, Serialize)]
pub struct CompileResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<CompileData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
pub struct CompileData {
    pub contract_cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir_cid: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub block_count: usize,
    #[serde(default)]
    pub node_count: usize,
    #[serde(default)]
    pub effect_row_count: usize,
    #[serde(default)]
    pub requires_admission: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_ir: Option<connector_native_contract::ConnectorIrV1>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub lifecycle_status: String,
    pub version: String,
    pub owner: String,
    pub domain: String,
    pub required_tools: Vec<String>,
    pub required_namespaces: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub execution_count: u64,
    pub last_execution: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FromTemplateRequest {
    pub template_id: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SimpleContractRequest {
    pub name: String,
    pub steps: Vec<SimpleStep>,
}

#[derive(Debug, Deserialize)]
pub struct SimpleStep {
    pub id: String,
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct PlaygroundRequest {
    pub source: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClsPackageInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub install_status: String,
    pub owner: String,
    pub domain: String,
    pub target_binding: serde_json::Value,
    pub replacement_lineage: Vec<String>,
    pub runtime_prerequisites: Vec<String>,
    pub dependency_review: Vec<String>,
    pub install_proof: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPackageRequest {
    pub package_id: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct BindPackageRequest {
    pub agent: Option<String>,
    pub node: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LifecycleActionRequest {
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClsExecutionRun {
    pub run_id: String,
    pub package_id: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub logic_graph: serde_json::Value,
    pub governance: serde_json::Value,
    pub resource_envelope: serde_json::Value,
    pub explain: serde_json::Value,
    pub risk: serde_json::Value,
    pub prove: serde_json::Value,
    pub cost: serde_json::Value,
}

// =============================================================================
// CCL compile (shared by POST /cls/compile and workflow dry-run)
// =============================================================================

use connector_engine::cls::ccl_parser::{
    BlockNode, CclParser, ContractNode, ParseError, StepOpNode,
};

fn ccl_parse_errors_to_api_error(errors: &[ParseError]) -> ApiError {
    let diagnostics: Vec<Diagnostic> = errors
        .iter()
        .map(|e| Diagnostic {
            severity: "error".into(),
            code: e.code.clone(),
            message: e.message.clone(),
            line: e.span.start.line,
            column: e.span.start.col,
        })
        .collect();
    let first = errors.first();
    ApiError {
        code: first
            .map(|e| e.code.clone())
            .unwrap_or_else(|| "E_PARSE".into()),
        message: first
            .map(|e| e.message.clone())
            .unwrap_or_else(|| "Parse error".into()),
        hint: first.and_then(|e| e.hint.clone()),
        diagnostics,
    }
}

/// Parsed CCL contract AST (same entrypoint as compile).
pub fn parse_ccl_contract_ast(source: &str) -> Result<ContractNode, ApiError> {
    CclParser::parse(source).map_err(|e| ccl_parse_errors_to_api_error(&e))
}

/// Compile **CCL** through the real lexer→sema→lower→verify→emit pipeline,
/// producing a content-addressed `SolutionContract` CID and sealed `ConnectorIrV1`.
/// Used by **`POST /api/v1/cls/compile`** and workflow dry-run.
pub fn compile_ccl_contract(source: &str) -> Result<CompileData, ApiError> {
    let ast = parse_ccl_contract_ast(source)?;
    let emit = compile_ccl_emit(source)?;
    let ir = emit.connector_ir;
    let version = Some(format!(
        "{}.{}.{}",
        emit.contract.id.version.major,
        emit.contract.id.version.minor,
        emit.contract.id.version.patch
    ));

    let warnings: Vec<Diagnostic> = emit
        .verify_result
        .warnings()
        .iter()
        .map(|d| Diagnostic {
            severity: "warning".into(),
            code: d.code.clone(),
            message: d.message.clone(),
            line: 0,
            column: 0,
        })
        .collect();

    Ok(CompileData {
        contract_cid: emit.cid,
        ir_cid: Some(ir.ir_cid.clone()),
        name: emit.contract.id.name.clone(),
        version,
        block_count: ast.blocks.len(),
        node_count: ir.node_count,
        effect_row_count: ir.effect_rows.len(),
        requires_admission: ir.requires_admission(),
        connector_ir: Some(ir),
        warnings,
    })
}

/// Full CCL emit retaining [`SolutionContract`] for ContractExecutor.
pub fn compile_ccl_emit(
    source: &str,
) -> Result<connector_engine::cls::EmitResult, ApiError> {
    use connector_engine::cls::{compile_ccl, EmitConfig};

    let _ = parse_ccl_contract_ast(source)?;
    compile_ccl(
        source,
        &EmitConfig {
            sign: false,
            optimize: true,
            ..EmitConfig::default()
        },
    )
    .map_err(|e| {
        let detail = match &e {
            connector_engine::cls::ClsError::CompilationError { detail } => detail.clone(),
            other => format!("{other:?}"),
        };
        ApiError {
            code: "E_COMPILE".into(),
            message: detail,
            hint: Some(
                "CCL must pass semantic analysis, IR lowering and verification (not parse-only)"
                    .into(),
            ),
            diagnostics: vec![],
        }
    })
}

fn blueprint_push(
    out: &mut Vec<serde_json::Value>,
    step_id: &str,
    kind: &str,
    detail: serde_json::Value,
) {
    let mut obj = match detail {
        serde_json::Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("detail".into(), other);
            m
        }
    };
    obj.insert("kind".into(), serde_json::json!(kind));
    obj.insert("step_id".into(), serde_json::json!(step_id));
    out.push(serde_json::Value::Object(obj));
}

fn collect_step_ops_blueprint(ops: &[StepOpNode], step_id: &str, out: &mut Vec<serde_json::Value>) {
    for op in ops {
        match op {
            StepOpNode::ToolCall { tool_name, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "tool",
                    serde_json::json!({ "tool": tool_name }),
                );
            }
            StepOpNode::EmitEvent { event, .. } => {
                blueprint_push(out, step_id, "emit", serde_json::json!({ "event": event }));
            }
            StepOpNode::LlmInfer { prompt, .. } => {
                let preview = if prompt.chars().count() > 96 {
                    let s: String = prompt.chars().take(96).collect();
                    format!("{s}…")
                } else {
                    prompt.clone()
                };
                blueprint_push(
                    out,
                    step_id,
                    "llm_infer",
                    serde_json::json!({ "prompt_preview": preview }),
                );
            }
            StepOpNode::MemRecall { namespace, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "mem_recall",
                    serde_json::json!({ "namespace": namespace }),
                );
            }
            StepOpNode::MemRemember { namespace, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "mem_remember",
                    serde_json::json!({ "namespace": namespace }),
                );
            }
            StepOpNode::Transition { state, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "transition",
                    serde_json::json!({ "to_state": state }),
                );
            }
            StepOpNode::SendMessage { target, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "send_message",
                    serde_json::json!({ "target": target }),
                );
            }
            StepOpNode::WaitEvent { event, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "wait_event",
                    serde_json::json!({ "event": event }),
                );
            }
            StepOpNode::CallContract { contract, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "call_contract",
                    serde_json::json!({ "contract": contract }),
                );
            }
            StepOpNode::SetVar { name, .. } => {
                blueprint_push(out, step_id, "set_var", serde_json::json!({ "name": name }));
            }
            StepOpNode::Checkpoint { label, .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "checkpoint",
                    serde_json::json!({ "label": label }),
                );
            }
            StepOpNode::Parallel { ops: inner, .. } => {
                collect_step_ops_blueprint(inner, step_id, out);
            }
            StepOpNode::Saga {
                forward,
                compensate,
                ..
            } => {
                collect_step_ops_blueprint(std::slice::from_ref(forward.as_ref()), step_id, out);
                collect_step_ops_blueprint(std::slice::from_ref(compensate.as_ref()), step_id, out);
            }
            StepOpNode::Branch { .. } => {
                blueprint_push(
                    out,
                    step_id,
                    "branch",
                    serde_json::json!({ "note": "branch arms not expanded in static blueprint" }),
                );
            }
        }
    }
}

/// Static scan of **`behavior`** steps: tool / emit / LLM / … ops in document order (no CNP replay, no execution).
/// Prefers sealed `ConnectorIrV1` effect rows from the full compile pipeline when available.
/// Phase **3.6** partial — feeds **`dry_run.dispatched_actions`** as a **would-schedule** plan; **`workflow_runtime::dry_run_workflow`** adds **`dry_run.cnp_replay`** (audit tail or client **`events`** sample).
pub fn ccl_static_action_blueprint(source: &str) -> Result<Vec<serde_json::Value>, ApiError> {
    if let Ok(data) = compile_ccl_contract(source) {
        if let Some(ir) = data.connector_ir {
            return Ok(blueprint_from_connector_ir(&ir));
        }
    }
    let ast = parse_ccl_contract_ast(source)?;
    let mut out = Vec::new();
    for block in &ast.blocks {
        if let BlockNode::Behavior(b) = block {
            for step in &b.steps {
                collect_step_ops_blueprint(&step.ops, &step.id, &mut out);
            }
        }
    }
    Ok(out)
}

/// Blueprint rows from sealed Connector IR effect rows (admission-aware).
pub fn blueprint_from_connector_ir(
    ir: &connector_native_contract::ConnectorIrV1,
) -> Vec<serde_json::Value> {
    ir.effect_rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "step_id": row.node_id,
                "kind": row.kind,
                "target": row.target,
                "mutates": row.mutates,
                "requires_admission": row.requires_admission,
                "semantic_verb": row.semantic_verb,
                "channel_hint": row.channel_hint,
                "source": "connector_ir_v1",
            })
        })
        .collect()
}

// =============================================================================
// Handlers
// =============================================================================

/// POST /cls/compile
pub async fn compile(
    State(_state): State<SharedState>,
    Json(req): Json<CompileRequest>,
) -> impl IntoResponse {
    match compile_ccl_contract(&req.source) {
        Ok(data) => (
            StatusCode::OK,
            Json(CompileResponse {
                ok: true,
                data: Some(data),
                error: None,
            }),
        ),
        Err(api_err) => (
            StatusCode::BAD_REQUEST,
            Json(CompileResponse {
                ok: false,
                data: None,
                error: Some(api_err),
            }),
        ),
    }
}

pub async fn get_execution_surface(
    State(_state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let runs = cls_execution_runs()
        .into_iter()
        .filter(|run| run.package_id == id)
        .collect::<Vec<_>>();
    if runs.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "execution_not_found", "message": format!("No execution surface found for package '{}'", id) }
            })),
        );
    }
    let latest = runs.first().cloned().unwrap();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "data": {
                "package_id": id,
                "logic_graph": latest.logic_graph,
                "governance": latest.governance,
                "resource_envelope": latest.resource_envelope,
                "runs": runs,
            }
        })),
    )
}

pub async fn get_execution_run_detail(
    State(_state): State<SharedState>,
    Path((id, run_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match cls_execution_runs()
        .into_iter()
        .find(|run| run.package_id == id && run.run_id == run_id)
    {
        Some(run) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "data": run })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "run_not_found", "message": format!("Run '{}' not found for package '{}'", run_id, id) }
            })),
        ),
    }
}

pub async fn export_execution_report(
    State(_state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let runs = cls_execution_runs()
        .into_iter()
        .filter(|run| run.package_id == id)
        .collect::<Vec<_>>();
    if runs.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "execution_not_found", "message": format!("No execution report found for package '{}'", id) }
            })),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "data": {
                "package_id": id,
                "report_title": format!("CLS Execution Report — {}", id),
                "generated_at": "2026-04-03T05:45:00Z",
                "runs": runs,
                "export_receipt": {
                    "proof_id": format!("proof-export-{}", id),
                    "receipt_cid": format!("cid-export-{}", id),
                    "verification": "verified"
                }
            }
        })),
    )
}

pub async fn list_packages(State(_state): State<SharedState>) -> impl IntoResponse {
    let registry = cls_package_registry().read().unwrap();
    let packages = registry.values().cloned().collect::<Vec<_>>();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "data": { "packages": packages } })),
    )
}

pub async fn get_package_detail(
    State(_state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let registry = cls_package_registry().read().unwrap();
    match registry.get(&id).cloned() {
        Some(package) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "data": package })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "package_not_found", "message": format!("Package '{}' not found", id) }
            })),
        ),
    }
}

pub async fn register_package(
    State(state): State<SharedState>,
    Json(req): Json<RegisterPackageRequest>,
) -> impl IntoResponse {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "cls",
        "cls",
        "register_package",
        &serde_json::json!({"package_id": req.package_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return (StatusCode::OK, Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut registry = cls_package_registry().write().unwrap();
    let package = ClsPackageInfo {
        id: req.package_id.clone(),
        name: format!("{} Package", req.package_id),
        version: req.version.clone(),
        status: "registered".into(),
        install_status: "not_installed".into(),
        owner: "Connector Operator".into(),
        domain: "custom".into(),
        target_binding: serde_json::json!({"agent": serde_json::Value::Null, "node": serde_json::Value::Null, "environment": serde_json::Value::Null}),
        replacement_lineage: vec![format!("{}@{}", req.package_id, req.version)],
        runtime_prerequisites: vec!["compiler available".into(), "policy gate review".into()],
        dependency_review: vec!["No additional dependencies declared".into()],
        install_proof: serde_json::json!({"proof_id": serde_json::Value::Null, "receipt_cid": serde_json::Value::Null, "execution_proof": "pending"}),
    };
    registry.insert(req.package_id.clone(), package.clone());
    drop(registry);
    open_proceed.finish_observed(true);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "task_id": admitted.task_id,
            "executed": true,
            "admits": false,
            "data": package
        })),
    )
}

pub async fn install_package(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "cls",
        "cls",
        "install_package",
        &serde_json::json!({"package_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return (StatusCode::OK, Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut registry = cls_package_registry().write().unwrap();
    match registry.get_mut(&id) {
        Some(package) => {
            package.install_status = "installed".into();
            package.install_proof = serde_json::json!({
                "proof_id": format!("proof-{}", package.id),
                "receipt_cid": format!("cid-{}", package.id),
                "execution_proof": "verified",
                "installed_at": "2026-04-03T05:31:00Z"
            });
            let data = package.clone();
            drop(registry);
            open_proceed.finish_observed(true);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "task_id": admitted.task_id,
                    "executed": true,
                    "admits": false,
                    "data": data,
                })),
            )
        }
        None => {
            drop(registry);
            open_proceed.finish_observed(false);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "error": { "code": "package_not_found", "message": format!("Package '{}' not found", id) },
                    "task_id": admitted.task_id,
                    "executed": false,
                    "admits": false,
                })),
            )
        }
    }
}

pub async fn bind_package(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<BindPackageRequest>,
) -> impl IntoResponse {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "cls",
        "cls",
        "bind_package",
        &serde_json::json!({"package_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return (StatusCode::OK, Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut registry = cls_package_registry().write().unwrap();
    match registry.get_mut(&id) {
        Some(package) => {
            package.target_binding = serde_json::json!({
                "agent": req.agent.unwrap_or_else(|| "agent-demo".into()),
                "node": req.node.unwrap_or_else(|| "node-a".into()),
                "environment": req.environment.unwrap_or_else(|| "production".into()),
                "bound_at": "2026-04-03T05:32:00Z"
            });
            let data = package.clone();
            drop(registry);
            open_proceed.finish_observed(true);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "task_id": admitted.task_id,
                    "executed": true,
                    "admits": false,
                    "data": data,
                })),
            )
        }
        None => {
            drop(registry);
            open_proceed.finish_observed(false);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "error": { "code": "package_not_found", "message": format!("Package '{}' not found", id) },
                    "task_id": admitted.task_id,
                    "executed": false,
                    "admits": false,
                })),
            )
        }
    }
}

pub async fn lifecycle_action(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<LifecycleActionRequest>,
) -> impl IntoResponse {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "cls",
        "cls",
        "package_lifecycle",
        &serde_json::json!({"package_id": id.as_str(), "action": req.action.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return (StatusCode::OK, Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut registry = cls_package_registry().write().unwrap();
    match registry.get_mut(&id) {
        Some(package) => {
            package.status = match req.action.as_str() {
                "activate" => "active".into(),
                "deprecate" => "deprecated".into(),
                "archive" => "archived".into(),
                value => value.to_string(),
            };
            package
                .replacement_lineage
                .push(format!("{}:{}", package.id, package.status));
            let data = package.clone();
            drop(registry);
            open_proceed.finish_observed(true);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "task_id": admitted.task_id,
                    "executed": true,
                    "admits": false,
                    "data": data,
                })),
            )
        }
        None => {
            drop(registry);
            open_proceed.finish_observed(false);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "error": { "code": "package_not_found", "message": format!("Package '{}' not found", id) },
                    "task_id": admitted.task_id,
                    "executed": false,
                    "admits": false,
                })),
            )
        }
    }
}

/// GET /contracts/templates
pub async fn list_templates(State(_state): State<SharedState>) -> impl IntoResponse {
    let templates = cls_templates();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "data": { "templates": templates } })),
    )
}

/// GET /contracts/templates/{id}
pub async fn get_template_detail(
    State(_state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match cls_templates().into_iter().find(|t| t.id == id) {
        Some(template) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "data": template })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": { "code": "template_not_found", "message": format!("Template '{}' not found", id) }
            })),
        ),
    }
}

/// POST /agents/{id}/contract/from-template
pub async fn from_template(
    State(_state): State<SharedState>,
    Path(agent_id): Path<String>,
    Json(req): Json<FromTemplateRequest>,
) -> impl IntoResponse {
    let source = generate_from_template(&req.template_id, &req.parameters);
    match source {
        Some(src) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true, "data": { "agent_id": agent_id, "source": src }
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false, "error": { "code": "template_not_found", "message": format!("Template '{}' not found", req.template_id) }
            })),
        ),
    }
}

/// POST /agents/{id}/contract/simple
pub async fn simple_contract(
    State(_state): State<SharedState>,
    Path(agent_id): Path<String>,
    Json(req): Json<SimpleContractRequest>,
) -> impl IntoResponse {
    let source = generate_simple_contract(&req);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true, "data": { "agent_id": agent_id, "source": source }
        })),
    )
}

/// POST /cls/playground
pub async fn playground(
    State(state): State<SharedState>,
    Json(req): Json<PlaygroundRequest>,
) -> impl IntoResponse {
    let compile_result = compile(
        State(state),
        Json(CompileRequest {
            source: req.source,
            options: Default::default(),
        }),
    )
    .await;
    compile_result
}

// =============================================================================
// Helpers
// =============================================================================

fn generate_from_template(
    template_id: &str,
    params: &HashMap<String, serde_json::Value>,
) -> Option<String> {
    let name = params
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or("my_agent");
    match template_id {
        "basic_tool_agent" => Some(format!(
            r#"contract {} {{
    interface {{
        input query: string required
        output result: json
    }}
    behavior {{
        step main {{ llm_infer "Process: ${{query}}" -> result }}
    }}
}}"#,
            name
        )),
        "rag_agent" => Some(format!(
            r#"contract {} {{
    interface {{
        input query: string required
        output answer: string
    }}
    memory {{ use k/knowledge as kb }}
    behavior {{
        step recall {{ mem_recall kb query: ${{query}} limit: 5 -> context }}
        step answer {{ llm_infer "Context: ${{context}}\nQuery: ${{query}}" -> answer }}
    }}
}}"#,
            name
        )),
        _ => None,
    }
}

fn generate_simple_contract(req: &SimpleContractRequest) -> String {
    let mut steps = String::new();
    for step in &req.steps {
        steps.push_str(&format!(
            "        step {} {{ {} }}\n",
            step.id, step.step_type
        ));
    }
    format!(
        r#"contract {} {{
    behavior {{
{}    }}
}}"#,
        req.name, steps
    )
}

fn cls_execution_runs() -> Vec<ClsExecutionRun> {
    vec![
        ClsExecutionRun {
            run_id: "run-basic-001".into(),
            package_id: "pkg-basic-tool-agent".into(),
            status: "succeeded".into(),
            started_at: "2026-04-03T05:10:00Z".into(),
            finished_at: Some("2026-04-03T05:10:06Z".into()),
            logic_graph: serde_json::json!({
                "nodes": [
                    {"id": "input", "type": "input"},
                    {"id": "main", "type": "llm_infer"},
                    {"id": "result", "type": "output"}
                ],
                "edges": [
                    {"from": "input", "to": "main"},
                    {"from": "main", "to": "result"}
                ]
            }),
            governance: serde_json::json!({
                "invariants": ["tool access constrained", "output must be json"],
                "policy_checks": ["approval gate optional", "namespace access verified"],
                "verdict": "pass"
            }),
            resource_envelope: serde_json::json!({
                "token_budget": 12000,
                "tokens_used": 842,
                "max_latency_ms": 5000,
                "actual_latency_ms": 1240
            }),
            explain: serde_json::json!({"summary": "Processed operator query through single-step governed inference."}),
            risk: serde_json::json!({"score": 18, "level": "low", "notes": ["single tool path", "bounded namespace"]}),
            prove: serde_json::json!({"proof_id": "proof-run-basic-001", "receipt_cid": "cid-run-basic-001", "scitt": "verified"}),
            cost: serde_json::json!({"tokens": 842, "usd": 0.021, "budget_pct": 7.0}),
        },
        ClsExecutionRun {
            run_id: "run-review-001".into(),
            package_id: "pkg-review-workflow".into(),
            status: "succeeded".into(),
            started_at: "2026-04-03T05:15:00Z".into(),
            finished_at: Some("2026-04-03T05:15:11Z".into()),
            logic_graph: serde_json::json!({
                "nodes": [
                    {"id": "collect", "type": "tool"},
                    {"id": "review", "type": "approval"},
                    {"id": "notify", "type": "tool"}
                ],
                "edges": [
                    {"from": "collect", "to": "review"},
                    {"from": "review", "to": "notify"}
                ]
            }),
            governance: serde_json::json!({
                "invariants": ["human review required before notify"],
                "policy_checks": ["approval queue enforced", "review namespace isolated"],
                "verdict": "pass"
            }),
            resource_envelope: serde_json::json!({
                "token_budget": 20000,
                "tokens_used": 1330,
                "max_latency_ms": 10000,
                "actual_latency_ms": 3180
            }),
            explain: serde_json::json!({"summary": "Collected case data, enforced human approval, and sent governed notification."}),
            risk: serde_json::json!({"score": 34, "level": "medium", "notes": ["human approval path", "multi-step workflow"]}),
            prove: serde_json::json!({"proof_id": "proof-run-review-001", "receipt_cid": "cid-run-review-001", "scitt": "verified"}),
            cost: serde_json::json!({"tokens": 1330, "usd": 0.041, "budget_pct": 9.0}),
        },
    ]
}

#[cfg(test)]
mod compile_pipeline_tests {
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
    fn compile_ccl_emits_connector_ir_not_source_hash() {
        let data = compile_ccl_contract(full_src()).expect("compile");
        assert!(data.contract_cid.starts_with("cls1-sha256-"));
        let ir_cid = data.ir_cid.expect("ir_cid");
        assert!(ir_cid.starts_with("cir1-sha256-"));
        assert!(data.requires_admission);
        assert!(data.effect_row_count > 0);
        let ir = data.connector_ir.expect("connector_ir");
        assert_eq!(ir.ir_cid, ir_cid);
        assert!(ir.effect_rows.iter().any(|r| r.kind == "tool_call"));

        let bp = ccl_static_action_blueprint(full_src()).expect("blueprint");
        assert!(!bp.is_empty());
        assert_eq!(
            bp[0].get("source").and_then(|v| v.as_str()),
            Some("connector_ir_v1")
        );
    }
}
