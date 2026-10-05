//! Deployment Management API
//!
//! Provides endpoints for application deployment using real AgentRegistry.

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;

use crate::state::SharedState;
use connector_api::manifest::{AgentManifest, ManifestMetadata, AgentSpec, ModelSpec};
use super::{V2Response, NextAction};

/// Create deployment using real registry
pub async fn create_deployment(
    State(state): State<SharedState>,
    Json(request): Json<CreateDeploymentRequest>,
) -> impl IntoResponse {
    // Register in AgentRegistry using real AgentManifest
    let result = {
        let mut registry = state.registry.lock().unwrap();
        let manifest = AgentManifest {
            api_version: "connector/v1".to_string(),
            kind: "Agent".to_string(),
            metadata: ManifestMetadata {
                name: request.name.clone(),
                version: "1.0.0".to_string(),
                description: request.description.clone().unwrap_or_default(),
                author: request.author.clone().unwrap_or_else(|| "api".to_string()),
                cid: None,
                labels: Default::default(),
            },
            spec: AgentSpec {
                model: ModelSpec::default(),
                instructions: format!("Deployment agent for {}", request.name),
                tools: vec![],
                memory: Default::default(),
                resources: Default::default(),
                security: Default::default(),
                lifecycle: Default::default(),
                comply: vec![],
                residency: None,
                secrets: vec![],
            },
        };
        registry.register(&manifest, "api")
    };
    
    let response = DeploymentResponse {
        deployment_id: format!("deploy_{}", result.version_index),
        name: result.name.clone(),
        status: "registered".to_string(),
        image: request.image,
        replicas: Replicas {
            desired: if request.replicas == 0 { None } else { Some(request.replicas) },
            running: None,
            pending: None,
            failed: None,
        },
        created_at: Utc::now().to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
        url: None,
        honesty: "Registered AgentManifest in AgentRegistry. Not a container rollout; replicas and public URL are not measured here.".to_string(),
    };
    
    let actions = vec![
        NextAction {
            action: "check_status".to_string(),
            method: "GET".to_string(),
            path: format!("/api/v2/deploy/{}/status", result.name),
            description: "Check deployment status".to_string(),
            reason: Some("Wait for rollout".to_string()),
            example_body: None,
        },
    ];
    
    V2Response::success_with_actions(response, actions)
}

/// Create deployment plan
pub async fn create_deployment_plan(
    State(state): State<SharedState>,
    Json(request): Json<DeploymentPlanRequest>,
) -> impl IntoResponse {
    let plan_id = format!("plan_{}", generate_id());
    
    // Get current registry state for diff
    let changes = {
        let registry = state.registry.lock().unwrap();
        // Calculate changes based on current registry state
        let names = registry.list_names();
        vec![
            PlanChange {
                action: "create".to_string(),
                resource: "deployment".to_string(),
                old_value: None,
                new_value: format!("new agent (existing: {})", names.len()),
            },
        ]
    };
    
    let response = DeploymentPlan {
        plan_id: plan_id.clone(),
        changes,
        created_at: Utc::now().to_rfc3339(),
    };
    
    V2Response::success(response)
}

/// Apply deployment plan — refused: no rollout engine is wired.
pub async fn apply_deployment_plan(
    State(_state): State<SharedState>,
    Json(_request): Json<ApplyPlanRequest>,
) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        V2Response::<()>::error_with_hint(
            "deploy_apply_not_implemented",
            "No deployment was applied: this build has no rollout engine. POST /deploy/create only registers an AgentManifest.",
            "Use AgentRegistry rollback via POST /api/v2/deploy/{name}/rollback for version switches already in the registry.",
        ),
    )
}

/// Get deployment status from registry
pub async fn get_deployment_status(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Get from AgentRegistry
    let history = {
        let registry = state.registry.lock().unwrap();
        registry.get_history(&name)
    };
    
    if let Some(history) = history {
        let active_version = history.versions.iter().find(|v| v.is_active).cloned();
        let total_versions = history.versions.len();
        
        let status = DeploymentStatus {
            name: name.clone(),
            status: if active_version.is_some() { "active_in_registry".to_string() } else { "no_active_version".to_string() },
            replicas: Replicas {
                desired: None,
                running: None,
                pending: None,
                failed: None,
            },
            conditions: vec![
                DeploymentCondition {
                    type_: "RegistryActive".to_string(),
                    status: if active_version.is_some() { "True".to_string() } else { "False".to_string() },
                    message: format!("Version {} active in AgentRegistry", active_version.as_ref().map(|v| v.version_index).unwrap_or(0)),
                },
            ],
            health: None,
            versions: total_versions as u32,
            active_version: active_version.as_ref().map(|v| v.version_index).unwrap_or(0),
            honesty: "AgentRegistry version state. Replica counts and health scores are not measured.".to_string(),
        };
        
        use axum::response::IntoResponse as _;
        V2Response::success(status).into_response()
    } else {
        use axum::response::IntoResponse as _;
        V2Response::error("not_found", &format!("Deployment {} not found", name)).into_response()
    }
}

/// List deployments from registry
pub async fn list_deployments(
    State(state): State<SharedState>,
    Query(_params): Query<ListDeploymentsQuery>,
) -> impl IntoResponse {
    // Get all agents from registry
    let names = {
        let registry = state.registry.lock().unwrap();
        registry.list_names()
    };

    let summaries: Vec<DeploymentSummary> = names.into_iter()
        .map(|name| DeploymentSummary {
            name: name.clone(),
            status: "in_registry".to_string(),
            replicas: None,
            image: None,
            age: None,
        })
        .collect();
    
    let response = ListDeploymentsResponse {
        deployments: summaries.clone(),
        total: summaries.len(),
    };
    
    V2Response::success(response)
}

/// Rollback to previous version
pub async fn rollback_deployment(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    Json(request): Json<RollbackRequest>,
) -> impl IntoResponse {
    let target_version = request.to_version
        .as_deref()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1);
    
    let rolled_back = {
        let mut registry = state.registry.lock().unwrap();
        registry.rollback(&name, target_version)
    };
    
    let response = serde_json::json!({
        "deployment": name,
        "action": "rollback",
        "to_version": target_version,
        "started_at": Utc::now().to_rfc3339(),
        "status": if rolled_back.is_some() { "rolled_back" } else { "failed" },
    });
    
    V2Response::success(response)
}

/// Scale deployment — refused: AgentRegistry has no replica dimension.
pub async fn scale_deployment(
    State(_state): State<SharedState>,
    Path(name): Path<String>,
    Json(_request): Json<ScaleRequest>,
) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        V2Response::<()>::error_with_hint(
            "deploy_scale_not_implemented",
            &format!("No scale was applied for {name}: this registry does not run replica counts."),
            "Register or rollback AgentManifest versions. Replica scaling is not wired.",
        ),
    )
}

/// Get deployment logs
pub async fn get_deployment_logs(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    Query(_params): Query<DeploymentLogsQuery>,
) -> impl IntoResponse {
    // Get from engine store
    let logs = {
        let engine_store = state.engine_store.lock().unwrap();
        engine_store.folder_get("deployment_logs", &name).ok().flatten()
    };
    
    let log_entries: Vec<DeploymentLogEntry> = if let Some(stored) = logs {
        serde_json::from_value(stored).unwrap_or_default()
    } else {
        Vec::new()
    };
    
    let total_lines = log_entries.len();
    let response = serde_json::json!({
        "deployment": name,
        "logs": log_entries,
        "total_lines": total_lines,
    });
    
    V2Response::success(response)
}

/// Get deployment metrics from real metrics
pub async fn get_deployment_metrics(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let metrics = &state.metrics;
    
    let response = serde_json::json!({
        "name": name,
        "cpu_percent": null,
        "memory_mb": null,
        "rps": metrics.requests_total.get(),
        "latency_p50_ms": null,
        "latency_p99_ms": null,
        "error_rate": null,
        "agents_active": metrics.agents_active.get(),
        "honesty": "Host CPU/memory/latency are not sampled. rps and agents_active are process counters, not per-deployment.",
    });
    
    V2Response::success(response)
}

// Types
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDeploymentRequest {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub replicas: u32,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_millicores: u32,
    pub memory_mb: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentResponse {
    pub deployment_id: String,
    pub name: String,
    pub status: String,
    pub image: String,
    pub replicas: Replicas,
    pub created_at: String,
    pub updated_at: String,
    pub url: Option<String>,
    pub honesty: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Replicas {
    pub desired: Option<u32>,
    pub running: Option<u32>,
    pub pending: Option<u32>,
    pub failed: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentPlanRequest {
    pub spec: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentPlan {
    pub plan_id: String,
    pub changes: Vec<PlanChange>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanChange {
    pub action: String,
    pub resource: String,
    pub old_value: Option<String>,
    pub new_value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplyPlanRequest {
    pub plan_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentStatus {
    pub name: String,
    pub status: String,
    pub replicas: Replicas,
    pub conditions: Vec<DeploymentCondition>,
    pub health: Option<u32>,
    pub versions: u32,
    pub active_version: u32,
    pub honesty: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentCondition {
    pub type_: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListDeploymentsQuery {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentSummary {
    pub name: String,
    pub status: String,
    pub replicas: Option<String>,
    pub image: Option<String>,
    pub age: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListDeploymentsResponse {
    pub deployments: Vec<DeploymentSummary>,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RollbackRequest {
    #[serde(default)]
    to_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScaleRequest {
    pub replicas: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentLogsQuery {
    #[serde(default = "default_lines")]
    lines: usize,
    #[serde(default)]
    follow: bool,
}

fn default_lines() -> usize { 100 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentLogEntry {
    pub timestamp: String,
    pub pod: String,
    pub container: String,
    pub message: String,
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", now.as_nanos())
}
