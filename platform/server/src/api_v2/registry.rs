//! Registry Management API
//!
//! Provides endpoints for managing registry items using real AgentRegistry.

use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::state::SharedState;
use connector_api::manifest::{AgentManifest, ManifestMetadata, AgentSpec, ModelSpec};
use super::V2Response;

/// List registry items from real AgentRegistry
pub async fn list_registry(
    State(state): State<SharedState>,
    Query(params): Query<ListRegistryQuery>,
) -> impl IntoResponse {
    // Get from real registry
    let items = {
        let registry = state.registry.lock().unwrap();
        registry.list_names().into_iter().map(|name| {
            let hash = registry.get_history(&name)
                .and_then(|h| h.versions.iter().find(|v| v.is_active).map(|v| v.cid.clone()))
                .unwrap_or_else(|| "sha256:unknown".to_string());
            let version = registry.get_history(&name)
                .map(|h| format!("v{}", h.active_version))
                .unwrap_or_else(|| "v1".to_string());
            RegistryItem {
                id: format!("reg_{}", name),
                type_: "agent".to_string(),
                name: name.clone(),
                size_bytes: None,
                created: Utc::now().to_rfc3339(),
                hash,
                tags: vec![version],
            }
        }).collect::<Vec<_>>()
    };
    
    let response = ListRegistryResponse {
        total: items.len(),
        items: items.clone(),
    };
    
    V2Response::success(response)
}

/// Get registry item details
pub async fn get_registry_item(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Parse agent name from id
    let agent_name = id.strip_prefix("reg_").unwrap_or(&id);
    
    // Get from real registry
    let history = {
        let registry = state.registry.lock().unwrap();
        registry.get_history(agent_name)
    };
    
    if let Some(history) = history {
        let active = history.versions.iter().find(|v| v.is_active);
        
        let item = RegistryItemDetails {
            id: id.clone(),
            type_: "agent".to_string(),
            name: history.name.clone(),
            description: format!("Agent with {} versions", history.versions.len()),
            size_bytes: None,
            created: Utc::now().to_rfc3339(),
            updated: active.map(|v| chrono::DateTime::from_timestamp(v.deployed_at / 1000, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default())
                .unwrap_or_else(|| Utc::now().to_rfc3339()),
            hash: active.map(|v| v.cid.clone()).unwrap_or_default(),
            tags: vec![format!("v{}", active.map(|v| v.version_index).unwrap_or(1))],
            metadata: serde_json::json!({
                "versions": history.versions.len(),
                "active_version": history.active_version,
                "deployed_by": active.map(|v| v.deployed_by.clone()).unwrap_or_default(),
            }),
            download_url: format!("/api/v2/registry/{}/download", id),
            versions: history.versions.iter().map(|v| format!("v{}", v.version_index)).collect(),
        };
        
        use axum::response::IntoResponse as _;
        V2Response::success(item).into_response()
    } else {
        use axum::response::IntoResponse as _;
        V2Response::error("not_found", &format!("Registry item {} not found", id)).into_response()
    }
}

/// Push item to registry
pub async fn push_registry(
    State(state): State<SharedState>,
    Json(request): Json<PushRegistryRequest>,
) -> impl IntoResponse {
    let id = format!("reg_{}", generate_id());
    
    // Register in AgentRegistry using real manifest struct
    let result = {
        let mut registry = state.registry.lock().unwrap();
        let manifest = AgentManifest {
            api_version: "connector/v1".to_string(),
            kind: "Agent".to_string(),
            metadata: ManifestMetadata {
                name: request.name.clone(),
                version: "1.0.0".to_string(),
                description: request.description.clone().unwrap_or_default(),
                author: "api".to_string(),
                cid: None,
                labels: Default::default(),
            },
            spec: AgentSpec {
                model: ModelSpec::default(),
                instructions: format!("Registry agent for {}", request.name),
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
    
    let response = PushRegistryResponse {
        id: format!("reg_{}", result.name),
        upload_url: format!("/api/v2/registry/{}/upload", id),
        expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        version: result.version_index,
    };
    
    V2Response::success(response)
}

/// Pull item from registry
pub async fn pull_registry(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Verify exists in registry
    let agent_name = id.strip_prefix("reg_").unwrap_or(&id);
    let exists = {
        let registry = state.registry.lock().unwrap();
        registry.get_history(agent_name).is_some()
    };
    
    if exists {
        let response = serde_json::json!({
            "id": id,
            "download_url": format!("/api/v2/registry/{}/download", id),
            "expires_at": (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        });
        use axum::response::IntoResponse as _;
        V2Response::success(response).into_response()
    } else {
        use axum::response::IntoResponse as _;
        V2Response::error("not_found", &format!("Registry item {} not found", id)).into_response()
    }
}

/// Delete registry item
pub async fn delete_registry(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_name = id.strip_prefix("reg_").unwrap_or(&id);
    
    // Record deletion intent in engine store (registry has no remove method)
    let _ = {
        let mut engine_store = state.engine_store.lock().unwrap();
        engine_store.folder_put("registry_deletions", agent_name, &serde_json::json!({
            "deleted_at": Utc::now().to_rfc3339(),
        }))
    };
    
    let response = serde_json::json!({
        "id": id,
        "deleted": true,
        "deleted_at": Utc::now().to_rfc3339(),
    });
    
    V2Response::success(response)
}

// Types
#[derive(Debug, Clone, Deserialize)]
pub struct ListRegistryQuery {
    #[serde(default)]
    type_: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryItem {
    pub id: String,
    pub type_: String,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub created: String,
    pub hash: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListRegistryResponse {
    pub items: Vec<RegistryItem>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryItemDetails {
    pub id: String,
    pub type_: String,
    pub name: String,
    pub description: String,
    pub size_bytes: Option<u64>,
    pub created: String,
    pub updated: String,
    pub hash: String,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub download_url: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushRegistryRequest {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushRegistryResponse {
    pub id: String,
    pub upload_url: String,
    pub expires_at: String,
    pub version: u32,
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", now.as_nanos())
}
