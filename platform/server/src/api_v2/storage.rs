//! Storage Management API
//!
//! Provides endpoints for storage using real StorageLayout.

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::state::SharedState;
use super::V2Response;

/// List storage buckets from real storage layout
pub async fn list_storage(
    State(state): State<SharedState>,
    Query(_params): Query<ListStorageQuery>,
) -> impl IntoResponse {
    use connector_engine::storage_zone::StorageZone;
    let layout = &state.storage_layout;
    let audit_path = layout.zone_path(StorageZone::Audit);
    let behavior_path = layout.zone_path(StorageZone::AgentBehavior);
    let buckets = vec![
        StorageBucket {
            name: "audit".to_string(),
            region: "local".to_string(),
            size_bytes: dir_size_bytes(&audit_path),
            object_count: dir_file_count(&audit_path),
        created: None,
        storage_class: "APPEND_ONLY".to_string(),
        },
        StorageBucket {
            name: "agent-behavior".to_string(),
            region: "local".to_string(),
            size_bytes: dir_size_bytes(&behavior_path),
            object_count: dir_file_count(&behavior_path),
        created: None,
        storage_class: "STANDARD".to_string(),
        },
    ];
    
    let response = ListStorageResponse {
        total: buckets.len(),
        buckets,
    };
    
    V2Response::success(response)
}

/// Get bucket details
pub async fn get_bucket(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    use connector_engine::storage_zone::StorageZone;
    let zone = match name.as_str() {
        "audit" => StorageZone::Audit,
        "agent-behavior" => StorageZone::AgentBehavior,
        "secrets" => StorageZone::AgentSecrets,
        _ => {
            return V2Response::<()>::error("not_found", &format!("Unknown storage zone {name}")).into_response();
        }
    };
    let path = state.storage_layout.zone_path(zone);
    let bucket = serde_json::json!({
        "name": name,
        "size_bytes": dir_size_bytes(&path),
        "object_count": dir_file_count(&path),
        "created": null,
        "encryption": null,
        "lifecycle_rules": [],
        "honesty": "Directory size on this node's storage layout. Encryption and lifecycle are not measured here.",
    });
    
    V2Response::success(bucket).into_response()
}

/// Sync storage buckets
pub async fn sync_storage(
    State(_state): State<SharedState>,
    Json(request): Json<SyncRequest>,
) -> impl IntoResponse {
    // Filesystem-level sync via std::fs
    let (synced, duration) = {
        let start = std::time::Instant::now();
        let count = sync_dirs_fs(&request.source, &request.destination);
        let elapsed = start.elapsed().as_millis() as u64;
        (count, elapsed)
    };
    
    let response = SyncResponse {
        sync_id: format!("sync_{}", generate_id()),
        source: request.source,
        destination: request.destination,
        synced_objects: synced,
        synced_bytes: None,
        duration_ms: duration,
    };
    
    V2Response::success(response)
}

/// Cleanup storage — delete only `{data_dir}/tmp` files older than 24 hours.
///
/// Audit, secrets and other zones are never touched. If the tmp zone does not
/// exist, this reports zero deletions rather than inventing freed bytes.
pub async fn cleanup_storage(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let tmp = std::path::Path::new(&state.config.data_dir).join("tmp");
    let ttl = std::time::Duration::from_secs(24 * 3600);
    let (deleted_objects, freed_bytes, zone_exists) = sweep_tmp_zone(&tmp, ttl);
    V2Response::success(serde_json::json!({
        "deleted_objects": deleted_objects,
        "freed_bytes": freed_bytes,
        "orphaned_objects": 0,
        "incomplete_multiparts": 0,
        "zone": tmp.display().to_string(),
        "zone_exists": zone_exists,
        "ttl_hours": 24,
        "honesty": "Only files under {data_dir}/tmp older than 24h are removed. Audit and other zones are not janitor-owned.",
    }))
}

fn sweep_tmp_zone(tmp: &std::path::Path, ttl: std::time::Duration) -> (u64, u64, bool) {
    if !tmp.is_dir() {
        return (0, 0, false);
    }
    let now = std::time::SystemTime::now();
    let mut deleted = 0u64;
    let mut freed = 0u64;
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return (0, 0, true);
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let aged = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .map(|d| d >= ttl)
            .unwrap_or(false);
        if !aged {
            continue;
        }
        let size = meta.len();
        if std::fs::remove_file(&path).is_ok() {
            deleted += 1;
            freed += size;
        }
    }
    (deleted, freed, true)
}

// Types
#[derive(Debug, Clone, Deserialize)]
pub struct ListStorageQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize { 20 }

#[derive(Debug, Clone, Serialize)]
pub struct StorageBucket {
    pub name: String,
    pub region: String,
    pub size_bytes: u64,
    pub object_count: u64,
    pub created: Option<String>,
    pub storage_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListStorageResponse {
    pub buckets: Vec<StorageBucket>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BucketDetails {
    pub name: String,
    pub region: String,
    pub size_bytes: u64,
    pub object_count: u64,
    pub created: String,
    pub versioning: bool,
    pub encryption: String,
    pub lifecycle_rules: Vec<LifecycleRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleRule {
    pub id: String,
    pub prefix: String,
    pub transition_days: u32,
    pub storage_class: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncRequest {
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub delete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncResponse {
    pub sync_id: String,
    pub source: String,
    pub destination: String,
    pub synced_objects: u64,
    pub synced_bytes: Option<u64>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupResponse {
    pub deleted_objects: u64,
    pub freed_bytes: u64,
    pub orphaned_objects: u64,
    pub incomplete_multiparts: u64,
}

fn dir_size_bytes(path: &str) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum())
        .unwrap_or(0)
}

fn dir_file_count(path: &str) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| entries.filter_map(|e| e.ok()).count() as u64)
        .unwrap_or(0)
}

fn sync_dirs_fs(src: &str, dst: &str) -> u64 {
    let src_path = std::path::Path::new(src);
    if !src_path.exists() { return 0; }
    let _ = std::fs::create_dir_all(dst);
    std::fs::read_dir(src_path)
        .map(|entries| {
            entries.filter_map(|e| e.ok()).filter_map(|entry| {
                let dst_file = format!("{}/{}", dst, entry.file_name().to_string_lossy());
                std::fs::copy(entry.path(), dst_file).ok()
            }).count() as u64
        })
        .unwrap_or(0)
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:x}", now.as_nanos())
}
