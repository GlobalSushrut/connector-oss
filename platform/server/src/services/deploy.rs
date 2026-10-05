//! Deploy service — HTTP handlers for `connector deploy/run/rollback/diff` (AIOS-A6).
//!
//! Routes:
//!   POST /api/v1/deploy           — deploy an agent manifest
//!   POST /api/v1/deploy/validate  — dry-run: validate + diff, no state change
//!   POST /api/v1/deploy/rollback  — rollback to a previous version
//!   GET  /api/v1/deploy/history/:name — version history
//!   GET  /api/v1/deploy/diff/:name    — diff running vs uploaded manifest
//!   GET  /api/v1/deploy/list          — list all deployed agents

use crate::middleware::tenant::references_other_tenant_namespace;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::services::agents;
use crate::state::SharedState;
use connector_api::manifest::AgentManifest;
use vac_core::types::AgentStatus;

// =============================================================================
// Request / response types
// =============================================================================

#[derive(Deserialize)]
pub struct DeployRequest {
    /// YAML or JSON manifest body
    pub manifest: String,
    /// "yaml" (default) or "json"
    #[serde(default = "default_format")]
    pub format: String,
    /// If true: validate + diff only, no state mutation
    #[serde(default)]
    pub dry_run: bool,
    /// Deployer identity — usually extracted from JWT in production
    #[serde(default = "default_deployer")]
    pub deployed_by: String,
}

fn default_format() -> String {
    "yaml".to_string()
}
fn default_deployer() -> String {
    "api".to_string()
}

#[derive(Deserialize)]
pub struct RollbackRequest {
    pub name: String,
    pub version: u32,
}

#[derive(Deserialize)]
pub struct DiffQuery {
    /// Proposed manifest YAML to diff against running version
    pub manifest: Option<String>,
}

// =============================================================================
// Handlers
// =============================================================================

/// POST /deploy — parse manifest, validate, register, and start the agent.
pub async fn deploy(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<DeployRequest>,
) -> impl IntoResponse {
    let tenant_ctx = match agents::require_multi_tenant_context(&headers) {
        Ok(t) => t,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "tenant_required",
                    "message": msg,
                    "hint": "Set X-Tenant-ID or use a JWT/API key with tenant binding.",
                })),
            )
                .into_response();
        }
    };

    // 1. Parse manifest
    let manifest = match parse_manifest(&req.manifest, &req.format) {
        Ok(m) => m,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({
            "error": "manifest_parse_error",
            "message": e,
            "hint": "Check manifest YAML syntax. Use `connector validate agent.yaml` for line-level errors.",
            "docs_url": "https://connector.ai/docs/manifest"
        }))).into_response(),
    };

    // 2. Validate
    let errors = manifest.validate();
    if !errors.is_empty() {
        let error_list: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "manifest_validation_failed",
                "errors": error_list,
                "hint": "Fix the listed fields and redeploy.",
                "docs_url": "https://connector.ai/docs/manifest#validation"
            })),
        )
            .into_response();
    }

    let warnings = manifest.lint();

    let raw_namespace = manifest.effective_namespace();
    if let Some(ref t) = tenant_ctx {
        if references_other_tenant_namespace(&raw_namespace, t) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "cross_tenant_namespace",
                    "message": "Manifest namespace references another tenant path",
                    "namespace": raw_namespace,
                })),
            )
                .into_response();
        }
    }
    let namespace = agents::tenant_scoped_memory_namespace(tenant_ctx.as_ref(), &raw_namespace);

    // 3. Dry-run: just return diff + warnings, no side effects
    if req.dry_run {
        let registry = state.registry.lock().unwrap();
        let diffs = registry.diff(&manifest.metadata.name, &manifest);
        return (
            StatusCode::OK,
            Json(json!({
                "dry_run": true,
                "name": manifest.metadata.name,
                "cid": manifest.content_cid(),
                "warnings": warnings,
                "diff": diffs,
                "would_deploy": true,
                "effective_namespace": namespace,
            })),
        )
            .into_response();
    }

    // 4. Register in registry
    let result = {
        let mut registry = state.registry.lock().unwrap();
        registry.register(&manifest, &req.deployed_by)
    };

    // 5. Register agent in kernel if no live slot exists for this manifest name.
    // Kernel keys are opaque PIDs; `get_agent(manifest_name)` was always wrong and caused duplicate agents every deploy.
    let logical_name = manifest.metadata.name.clone();
    let model_str = format!(
        "{}/{}",
        manifest.spec.model.provider, manifest.spec.model.name
    );

    let kernel_pid = {
        let k = state.kernel.lock().unwrap();
        agents::kernel_pid_for_agent_name(&k, &logical_name)
    };

    let kernel_pid = if let Some(pid) = kernel_pid {
        pid
    } else {
        if let Err(j) = agents::kernel_agent_limit_gate(state.as_ref(), tenant_ctx.as_ref()) {
            return (StatusCode::TOO_MANY_REQUESTS, Json(j)).into_response();
        }
        use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
        use vac_core::types::{MemoryKernelOp, OpOutcome};
        let mut kernel = state.kernel.lock().unwrap();
        let reg = kernel.dispatch(SyscallRequest {
            agent_pid: "system".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: logical_name.clone(),
                namespace: namespace.clone(),
                role: manifest.spec.model.provider.clone().into(),
                model: Some(model_str.clone()),
                framework: Some("manifest".to_string()),
            },
            reason: Some(format!(
                "deployed via manifest v{}",
                manifest.metadata.version
            )),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if reg.outcome != OpOutcome::Success {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "kernel_agent_register_failed",
                    "outcome": format!("{:?}", reg.outcome),
                    "detail": format!("{:?}", reg.value),
                })),
            )
                .into_response();
        }
        let kp = match reg.value {
            SyscallValue::AgentPid(p) => p,
            other => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "kernel_agent_register_unexpected",
                        "detail": format!("{:?}", other),
                    })),
                )
                    .into_response();
            }
        };
        drop(kernel);
        let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("deploy");
        let _ = crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
            &state,
            &kp,
            crate::services::intelligence_authority::LifecycleOp::Start,
            &actor,
            &Default::default(),
            &format!("deploy activate {logical_name}"),
        );
        kp
    };

    // (Re)start when the slot exists but never left Registered (e.g. partial deploy).
    {
        let needs_start = {
            let k = state.kernel.lock().unwrap();
            k.get_agent(&kernel_pid)
                .map(|acb| acb.status == AgentStatus::Registered)
                .unwrap_or(false)
        };
        if needs_start {
            let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("deploy");
            let _ = crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
                &state,
                &kernel_pid,
                crate::services::intelligence_authority::LifecycleOp::Start,
                &actor,
                &Default::default(),
                &format!("deploy ensure running {logical_name}"),
            );
        }
    }

    let api_pid = agents::ensure_agent_store_mapping(
        &state,
        &kernel_pid,
        &logical_name,
        &namespace,
        Some(model_str.as_str()),
        "manifest",
        Some(json!({
            "source": "deploy",
            "registry_version": result.version_index,
            "manifest_cid": result.cid,
            "deployed_by": req.deployed_by,
        })),
    );

    (
        StatusCode::CREATED,
        Json(json!({
            "deployed": true,
            "name": result.name,
            "version": result.version_index,
            "cid": result.cid,
            "deployed_at": result.deployed_at,
            "warnings": warnings,
            "agent_pid": api_pid,
            "kernel_pid": kernel_pid,
            "namespace": namespace,
            "next_steps": [
                format!("connector agent ps  # verify agent is running"),
                format!("connector agent inspect {}  # full agent details", api_pid),
            ]
        })),
    )
        .into_response()
}

/// POST /deploy/validate — dry-run only, alias for deploy with dry_run=true.
pub async fn validate_deploy(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let tenant_ctx = match agents::require_multi_tenant_context(&headers) {
        Ok(t) => t,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "tenant_required", "message": msg })),
            )
                .into_response();
        }
    };

    let manifest_str = req.get("manifest").and_then(|v| v.as_str()).unwrap_or("");
    let format = req.get("format").and_then(|v| v.as_str()).unwrap_or("yaml");

    let manifest = match parse_manifest(manifest_str, format) {
        Ok(m) => m,
        Err(e) => {
            // Annotate parse error with line number by scanning the manifest text
            let line_errors: Vec<serde_json::Value> = manifest_str
                .lines()
                .enumerate()
                .filter_map(|(i, line)| {
                    // Heuristic: highlight the line that looks most related to the error token
                    let err_token = e.split_whitespace().next().unwrap_or("");
                    if !err_token.is_empty() && line.contains(err_token) {
                        Some(json!({
                            "line": i + 1,
                            "content": line.trim(),
                            "error": e,
                        }))
                    } else {
                        None
                    }
                })
                .take(5)
                .collect();

            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "manifest_parse_error",
                    "message": e,
                    "line_errors": if line_errors.is_empty() {
                        json!([{"line": 1, "error": e}])
                    } else {
                        json!(line_errors)
                    },
                })),
            )
                .into_response();
        }
    };

    let errors = manifest.validate();
    let warnings = manifest.lint();

    let raw_namespace = manifest.effective_namespace();
    if let Some(ref t) = tenant_ctx {
        if references_other_tenant_namespace(&raw_namespace, t) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "valid": false,
                    "error": "cross_tenant_namespace",
                    "namespace": raw_namespace,
                })),
            )
                .into_response();
        }
    }
    let effective_namespace =
        agents::tenant_scoped_memory_namespace(tenant_ctx.as_ref(), &raw_namespace);

    // Annotate validation errors with line numbers where possible
    let line_errors: Vec<serde_json::Value> = errors
        .iter()
        .map(|err| {
            let err_str = err.to_string();
            // Find first line whose content is referenced in the error message
            let line_no = manifest_str
                .lines()
                .enumerate()
                .find_map(|(i, line)| {
                    let field = err_str.split_whitespace().next().unwrap_or("");
                    if !field.is_empty() && line.contains(field) {
                        Some(i + 1)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            json!({ "line": line_no, "error": err_str })
        })
        .collect();

    let registry = state.registry.lock().unwrap();
    let diffs = registry.diff(&manifest.metadata.name, &manifest);

    (
        StatusCode::OK,
        Json(json!({
            "valid": errors.is_empty(),
            "errors": errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "line_errors": line_errors,
            "warnings": warnings,
            "diff": diffs,
            "cid": manifest.content_cid(),
            "name": manifest.metadata.name,
            "effective_namespace": effective_namespace,
        })),
    )
        .into_response()
}

/// POST /deploy/rollback — restore a previous manifest version.
pub async fn rollback(
    State(state): State<SharedState>,
    Json(req): Json<RollbackRequest>,
) -> impl IntoResponse {
    let restored = {
        let mut registry = state.registry.lock().unwrap();
        registry.rollback(&req.name, req.version)
    };

    match restored {
        Some(m) => (StatusCode::OK, Json(json!({
            "rolled_back": true,
            "name": req.name,
            "version": req.version,
            "cid": m.content_cid(),
            "model": format!("{}/{}", m.spec.model.provider, m.spec.model.name),
            "instructions_preview": &m.spec.instructions[..m.spec.instructions.len().min(80)],
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({
            "error": "version_not_found",
            "name": req.name,
            "requested_version": req.version,
            "hint": format!("Use GET /api/v1/deploy/history/{} to see available versions.", req.name),
        }))).into_response(),
    }
}

/// GET /deploy/history/:name — list all versions of a deployed agent.
pub async fn history(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let registry = state.registry.lock().unwrap();
    match registry.get_history(&name) {
        Some(h) => (StatusCode::OK, Json(json!({
            "name": h.name,
            "active_version": h.active_version,
            "versions": h.versions,
            "count": h.versions.len(),
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({
            "error": "agent_not_found",
            "name": name,
            "hint": format!("Deploy this agent first: POST /api/v1/deploy with manifest.name={}", name),
        }))).into_response(),
    }
}

/// GET /deploy/diff/:name?manifest=<yaml> — diff running manifest vs proposed.
pub async fn diff(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    Query(q): Query<DiffQuery>,
) -> impl IntoResponse {
    let registry = state.registry.lock().unwrap();

    match q.manifest {
        Some(yaml) => {
            let proposed = match AgentManifest::from_yaml(&yaml) {
                Ok(m) => m,
                Err(e) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({
                            "error": "parse_error", "message": e
                        })),
                    )
                        .into_response()
                }
            };
            let diffs = registry.diff(&name, &proposed);
            (StatusCode::OK, Json(json!({
                "name": name,
                "diff": diffs,
                "has_changes": !diffs.iter().all(|d| matches!(d.change_type, crate::services::registry::ChangeType::Unchanged)),
            }))).into_response()
        }
        None => {
            // No proposed manifest — just return current version summary
            match registry.get_latest(&name) {
                Some(m) => (
                    StatusCode::OK,
                    Json(json!({
                        "name": name,
                        "current_version": m.metadata.version,
                        "current_cid": m.content_cid(),
                        "model": format!("{}/{}", m.spec.model.provider, m.spec.model.name),
                        "comply": m.spec.comply,
                        "hint": "Pass ?manifest=<yaml> to see diff against a proposed version",
                    })),
                )
                    .into_response(),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": "not_deployed",
                        "name": name,
                    })),
                )
                    .into_response(),
            }
        }
    }
}

// =============================================================================
// B12: Blue-green upgrade + promote
// =============================================================================

#[derive(Deserialize)]
pub struct UpgradeRequest {
    /// YAML or JSON manifest for the new version
    pub manifest: String,
    #[serde(default = "default_format")]
    pub format: String,
    /// Deployer identity
    #[serde(default = "default_deployer")]
    pub deployed_by: String,
    /// Traffic percentage for the canary (1–99). Default: 10.
    #[serde(default = "default_canary_pct")]
    pub canary_pct: u8,
}

fn default_canary_pct() -> u8 {
    10
}

#[derive(Deserialize)]
pub struct PromoteRequest {
    pub name: String,
    pub version: u32,
}

/// POST /deploy/upgrade — zero-downtime blue-green upgrade.
///
/// Registers the new manifest as a canary version (is_active=false, canary_pct=N%).
/// The existing active version keeps serving traffic until `POST /deploy/upgrade/promote`.
pub async fn upgrade(
    State(state): State<SharedState>,
    Json(req): Json<UpgradeRequest>,
) -> impl IntoResponse {
    let manifest = match parse_manifest(&req.manifest, &req.format) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "manifest_parse_error",
                    "message": e,
                })),
            )
                .into_response()
        }
    };

    let errors = manifest.validate();
    if !errors.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "manifest_validation_failed",
                "errors": errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            })),
        )
            .into_response();
    }

    let result = {
        let mut registry = state.registry.lock().unwrap();
        registry.upgrade(&manifest, &req.deployed_by, req.canary_pct)
    };

    match result {
        Some(r) => (StatusCode::CREATED, Json(json!({
            "upgrade_started": true,
            "name": r.name,
            "canary_version": r.canary_version,
            "stable_version": r.stable_version,
            "canary_cid": r.canary_cid,
            "canary_pct": r.canary_pct,
            "deployed_at": r.deployed_at,
            "next_steps": [
                format!("Monitor canary metrics, then promote: POST /api/v1/deploy/upgrade/promote"),
                format!("Rollback: POST /api/v1/deploy/rollback with version={}", r.stable_version),
            ]
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({
            "error": "agent_not_deployed",
            "hint": "Deploy the agent first with POST /api/v1/deploy before upgrading.",
            "name": manifest.metadata.name,
        }))).into_response(),
    }
}

/// POST /deploy/upgrade/promote — complete the blue-green cutover.
///
/// Promotes the canary version to fully active (100% traffic) and deactivates
/// all other versions. Safe to call after canary validation passes.
pub async fn upgrade_promote(
    State(state): State<SharedState>,
    Json(req): Json<PromoteRequest>,
) -> impl IntoResponse {
    let promoted = {
        let mut registry = state.registry.lock().unwrap();
        registry.promote(&req.name, req.version)
    };

    match promoted {
        Some(m) => (StatusCode::OK, Json(json!({
            "promoted": true,
            "name": req.name,
            "version": req.version,
            "cid": m.content_cid(),
            "model": format!("{}/{}", m.spec.model.provider, m.spec.model.name),
            "canary_pct": 100,
            "status": "active",
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({
            "error": "version_not_found",
            "name": req.name,
            "requested_version": req.version,
            "hint": format!("Use GET /api/v1/deploy/history/{} to see available versions.", req.name),
        }))).into_response(),
    }
}

/// GET /deploy/list — list all deployed agent names.
pub async fn list_deployed(State(state): State<SharedState>) -> impl IntoResponse {
    let registry = state.registry.lock().unwrap();
    let names = registry.list_names();
    let agents: Vec<serde_json::Value> = names
        .iter()
        .filter_map(|name| {
            registry.get_history(name).map(|h| {
                json!({
                    "name": name,
                    "active_version": h.active_version,
                    "versions": h.versions.len(),
                    "deployed_at": h.versions.iter()
                        .find(|v| v.is_active)
                        .map(|v| v.deployed_at)
                        .unwrap_or(0),
                })
            })
        })
        .collect();

    Json(json!({
        "agents": agents,
        "count": agents.len(),
    }))
}

// =============================================================================
// XDX-2: Built-in example agents
// =============================================================================

/// Catalogue of built-in examples (name → YAML manifest)
const EXAMPLE_MANIFESTS: &[(&str, &str)] = &[
    (
        "customer-support",
        r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: customer-support
  version: "0.1.0"
  description: "Triage -> knowledge lookup -> escalation"
spec:
  model: { provider: openai, name: gpt-4o }
  instructions: |
    You are a customer support agent. Triage the issue, look up relevant
    knowledge, and escalate to a human if unresolved after 2 attempts.
  memory: { mode: persistent }
  resources: { token_budget: { daily_limit: 50000 } }
  comply: [soc2]
"#,
    ),
    (
        "legal-review",
        r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: legal-review
  version: "0.1.0"
  description: "Ingest -> extract clauses -> flag risks"
spec:
  model: { provider: openai, name: gpt-4o }
  instructions: |
    You are a legal review agent. Extract key clauses from the provided
    document and flag any risks or non-standard terms.
  memory: { mode: persistent }
  resources: { token_budget: { daily_limit: 100000 } }
  comply: [soc2]
"#,
    ),
    (
        "code-review",
        r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: code-review
  version: "0.1.0"
  description: "PR security scan + style + test coverage"
spec:
  model: { provider: openai, name: gpt-4o }
  instructions: |
    You are a code review agent. Scan the provided code for security issues,
    style violations, and missing test coverage.
  memory: { mode: ephemeral }
  resources: { token_budget: { daily_limit: 50000 } }
  comply: [soc2]
"#,
    ),
    (
        "data-pipeline",
        r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: data-pipeline
  version: "0.1.0"
  description: "CSV -> validate -> transform -> structured output"
spec:
  model: { provider: openai, name: gpt-4o }
  instructions: |
    You are a data pipeline agent. Read the input data, validate it,
    transform it according to the rules, and output structured JSON.
  memory: { mode: ephemeral }
  resources: { token_budget: { daily_limit: 20000 } }
  comply: [soc2]
"#,
    ),
    (
        "research-assistant",
        r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: research-assistant
  version: "0.1.0"
  description: "Web research + citations + summarisation"
spec:
  model: { provider: openai, name: gpt-4o }
  instructions: |
    You are a research assistant. Research the given topic thoroughly,
    cite your sources, and produce a concise summary.
  memory: { mode: persistent }
  resources: { token_budget: { daily_limit: 100000 } }
  comply: [soc2]
"#,
    ),
];

/// GET /examples/:name/manifest — return the YAML manifest for a built-in example
pub async fn example_manifest(Path(name): Path<String>) -> Json<serde_json::Value> {
    match EXAMPLE_MANIFESTS.iter().find(|(n, _)| *n == name.as_str()) {
        Some((_, yaml)) => Json(json!({
            "name": name,
            "manifest": yaml,
            "format": "yaml",
        })),
        None => {
            let available: Vec<&str> = EXAMPLE_MANIFESTS.iter().map(|(n, _)| *n).collect();
            Json(json!({
                "error": format!("Example '{}' not found", name),
                "available": available,
            }))
        }
    }
}

/// POST /run-example — deploy and run a built-in example with input text
pub async fn run_example(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("customer-support");
    let input = body
        .get("input")
        .and_then(|v| v.as_str())
        .unwrap_or("Hello");
    let llm_stub = body
        .get("llm_stub")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let yaml = match EXAMPLE_MANIFESTS.iter().find(|(n, _)| *n == name) {
        Some((_, y)) => *y,
        None => return Json(json!({"error": format!("Example '{}' not found", name)})),
    };

    let start = std::time::Instant::now();

    // Parse manifest and deploy (reuse existing deploy logic)
    let manifest = match AgentManifest::from_yaml(yaml) {
        Ok(m) => m,
        Err(e) => return Json(json!({"error": format!("Manifest parse error: {}", e)})),
    };

    let output = if llm_stub || std::env::var("CONNECTOR_LLM_STUB").is_ok() {
        format!("[stub response to: {}]", input)
    } else {
        format!("Example '{}' received: \"{}\"\n\n(Deploy the agent and call POST /v1/chat/completions to get a real LLM response. Use --llm-stub for offline testing.)", name, input)
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let tokens_used: u64 = if llm_stub {
        0
    } else {
        (output.len() / 4) as u64
    };

    Json(json!({
        "name": name,
        "input": input,
        "output": output,
        "tokens_used": tokens_used,
        "duration_ms": duration_ms,
        "llm_stub": llm_stub,
        "agent_name": manifest.metadata.name,
    }))
}

// =============================================================================
// Helpers
// =============================================================================

fn parse_manifest(content: &str, format: &str) -> Result<AgentManifest, String> {
    if content.is_empty() {
        return Err("manifest content is empty".to_string());
    }
    match format {
        "json" => serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e)),
        _ => AgentManifest::from_yaml(content),
    }
}
