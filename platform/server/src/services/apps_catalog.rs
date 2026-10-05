//! Unified **apps catalog** — plugins + CLS workflows in one list (`GET /api/v1/apps`).
//!
//! Product direction: operators discover workloads without stitching
//! `GET /api/v1/plugins/status` and `GET /api/v1/workflows` separately.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use connector_engine::engine_store::EngineStore;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    services::workflow_runtime::{WorkflowRecord, WorkflowState},
    state::SharedState,
};

const WORKFLOW_FOLDER: &str = "workflow_runtime";

#[derive(Debug, Deserialize, Default)]
pub struct ListAppsQuery {
    /// Filter: `plugin`, `workflow`, or omit for all.
    pub kind: Option<String>,
}

fn parse_host_port(url: &str) -> (Option<String>, Option<u16>) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    match reqwest::Url::parse(trimmed) {
        Ok(u) => {
            let host = u.host_str().map(|h| h.to_string());
            let port = u.port_or_known_default();
            (host, port)
        }
        Err(_) => (None, None),
    }
}

fn plugin_management_base(plugin_id: &str) -> Option<String> {
    match plugin_id {
        "tracetramp" => Some(
            std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
                .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
                .unwrap_or_else(|_| "http://127.0.0.1:19742".to_string()),
        ),
        "witnessctl" => crate::services::plugin_upstream_probe::witnessctl_management_url(),
        "devguard" => crate::services::plugin_upstream_probe::devguard_management_url(),
        _ => None,
    }
}

fn plugin_status_badge(
    installed: bool,
    enabled: bool,
    upstream_reachable: Option<bool>,
) -> &'static str {
    if !installed {
        return "not_installed";
    }
    if !enabled {
        return "disabled";
    }
    match upstream_reachable {
        Some(true) => "healthy",
        Some(false) => "degraded",
        None => "enabled",
    }
}

async fn plugin_upstream_reachable(plugin_id: &str) -> Option<bool> {
    match plugin_id {
        "tracetramp" => {
            if crate::services::tracetramp_proxy::tracetramp_management_plane_configured() {
                crate::services::tracetramp_proxy::tracetramp_upstream_reachable().await
            } else {
                None
            }
        }
        "witnessctl" => {
            crate::services::plugin_upstream_probe::witnessctl_upstream_reachable().await
        }
        "devguard" => crate::services::plugin_upstream_probe::devguard_upstream_reachable().await,
        _ => None,
    }
}

fn plugin_lifecycle_actions(installed: bool, enabled: bool) -> Vec<&'static str> {
    if !installed {
        return vec!["install"];
    }
    let mut out = vec!["update", "uninstall"];
    if enabled {
        out.push("disable");
    } else {
        out.push("enable");
    }
    out
}

fn workflow_status_badge(state: WorkflowState) -> &'static str {
    match state {
        WorkflowState::Enabled => "enabled",
        WorkflowState::Paused => "paused",
        WorkflowState::Compiled | WorkflowState::Staged => "staged",
        WorkflowState::Draft => "draft",
        WorkflowState::Archived => "archived",
    }
}

fn workflow_active(state: WorkflowState) -> bool {
    // WF-02: ENABLED is an activation/registration record, not a live executing worker.
    let _ = state;
    false
}

fn workflow_actions(state: WorkflowState) -> Vec<&'static str> {
    match state {
        WorkflowState::Draft => vec!["compile", "apply"],
        WorkflowState::Compiled => vec!["stage", "enable"],
        WorkflowState::Staged => vec!["enable", "dry-run"],
        WorkflowState::Enabled => vec!["pause", "dry-run", "rollback"],
        WorkflowState::Paused => vec!["enable", "dry-run", "rollback"],
        WorkflowState::Archived => vec!["apply"],
    }
}

/// Classify a plugin as a dev-tool app or a server-side app.
/// Dev apps connect AI coding tools (Cursor, Windsurf, Claude Code…) to the platform.
/// Server apps run alongside the kernel serving traffic or audit workloads.
fn plugin_app_category(plugin_id: &str) -> &'static str {
    match plugin_id {
        "devguard" => "dev_app",
        _ => "server_app",
    }
}

/// Human-readable display name for a plugin.
fn plugin_display_name(plugin_id: &str) -> String {
    match plugin_id {
        "devguard" => "DevGuard".into(),
        "tracetramp" => "TraceTramp".into(),
        "witnessctl" => "WitnessCtl".into(),
        other => other.to_string(),
    }
}

/// Short one-line description shown on app cards.
fn plugin_description(plugin_id: &str) -> &'static str {
    match plugin_id {
        "devguard"   => "AI coding agent governance — connect Cursor, Windsurf, Claude Code, or any OpenAI-compatible tool.",
        "tracetramp" => "LLM call tracing and enforcement for gateway traffic.",
        "witnessctl" => "Human-in-the-loop witness and audit receipts for agent workflows.",
        _ => "",
    }
}

async fn build_plugin_rows(state: &SharedState) -> Vec<Value> {
    let merged_domains =
        crate::services::custom_domain_routing::load_merged_custom_domains_for_host_routing(state);
    let mut rows = Vec::new();
    for plugin_id in crate::services::plugin_matrix::KNOWN_PLUGINS {
        let lifecycle =
            crate::services::plugin_lifecycle::load_plugin_lifecycle_state(state, plugin_id);
        let upstream = plugin_upstream_reachable(plugin_id).await;
        let badge = plugin_status_badge(lifecycle.installed, lifecycle.enabled, upstream);
        let cage_host = crate::internal_dns::plugin_cage_hostname(plugin_id);
        let public_prefix = format!("/plugin/{plugin_id}");
        let mgmt = plugin_management_base(plugin_id);
        let (mgmt_host, mgmt_port) = mgmt.as_deref().map(parse_host_port).unwrap_or((None, None));
        let active = lifecycle.installed && lifecycle.enabled;
        let custom_hosts = crate::services::custom_domain_routing::custom_domain_hosts_for_plugin(
            &merged_domains,
            plugin_id,
        );
        let category = plugin_app_category(plugin_id);
        let gateway_base = {
            let public = std::env::var("CONNECTOR_PUBLIC_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let host =
                        std::env::var("CONNECTOR_HOST").unwrap_or_else(|_| "127.0.0.1".into());
                    let port = std::env::var("CONNECTOR_PORT").unwrap_or_else(|_| "9091".into());
                    format!("http://{host}:{port}")
                });
            format!("{public}/v1")
        };
        let connect_endpoint = if category == "dev_app" {
            json!(format!("/api/v1/{plugin_id}/connect"))
        } else {
            Value::Null
        };
        let gateway_url = if category == "dev_app" {
            json!(gateway_base)
        } else {
            Value::Null
        };
        rows.push(json!({
            "kind": "plugin",
            "app_category": category,
            "id": plugin_id,
            "name": plugin_id,
            "display_name": plugin_display_name(plugin_id),
            "description": plugin_description(plugin_id),
            "active": active,
            "status_badge": badge,
            "pid": Value::Null,
            "port": mgmt_port,
            "management_host": mgmt_host,
            "uri": mgmt,
            "public_uri": public_prefix,
            "cage_host": cage_host,
            "gateway_url": gateway_url,
            "connect_endpoint": connect_endpoint,
            "custom_domain_hosts": custom_hosts,
            "host_proxy_hint": if custom_hosts.is_empty() {
                Value::Null
            } else {
                json!(format!(
                    "https://{}/… (Host header → cage; configure in Settings → Custom domains)",
                    custom_hosts[0]
                ))
            },
            "cage_internal_dns_registered": crate::internal_dns::resolve(&cage_host).is_some(),
            "dashboard_path": format!("/plugins/{plugin_id}"),
            "enabled_in_deployment": crate::services::plugin_matrix::is_plugin_enabled(plugin_id),
            "lifecycle": lifecycle,
            "actions": plugin_lifecycle_actions(lifecycle.installed, lifecycle.enabled),
            "runtime_backend": "microvm",
            "hint": "pid is reserved for kernel-supervised plugin processes; management plane may be external.",
        }));
    }
    rows
}

fn build_workflow_rows(state: &SharedState) -> Vec<Value> {
    let mut es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(WORKFLOW_FOLDER, None).unwrap_or_default();
    let mut items: Vec<WorkflowRecord> = keys
        .iter()
        .filter_map(|k| es.folder_get(WORKFLOW_FOLDER, k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<WorkflowRecord>(v).ok())
        .collect();
    items.sort_by(|a, b| a.workflow_id.cmp(&b.workflow_id));

    items
        .into_iter()
        .map(|rec| {
            let badge = workflow_status_badge(rec.state);
            let active = workflow_active(rec.state);
            let api_path = format!("/api/v1/workflows/{}", rec.workflow_id);
            json!({
                "kind": "workflow",
                "id": rec.workflow_id,
                "name": rec.workflow_id,
                "display_name": rec.package_id,
                "active": active,
                "status_badge": badge,
                "pid": Value::Null,
                "port": Value::Null,
                "uri": api_path,
                "public_uri": Value::Null,
                "cage_host": Value::Null,
                "dashboard_path": "/workflows",
                "package_id": rec.package_id,
                "version": rec.version,
                "state": rec.state,
                "updated_at": rec.updated_at,
                "actions": workflow_actions(rec.state),
                "hint": "Enable via POST /api/v1/workflows/:id/lifecycle {\"state\":\"ENABLED\"} or dashboard Workflows hub.",
            })
        })
        .collect()
}

async fn build_catalog(state: &SharedState, kind_filter: Option<&str>) -> Value {
    let want_plugins = kind_filter.map(|k| k == "plugin").unwrap_or(true);
    let want_workflows = kind_filter.map(|k| k == "workflow").unwrap_or(true);

    let mut apps = Vec::new();
    if want_plugins {
        apps.extend(build_plugin_rows(state).await);
    }
    if want_workflows {
        apps.extend(build_workflow_rows(state));
    }

    let plugin_count = apps
        .iter()
        .filter(|a| a.get("kind") == Some(&json!("plugin")))
        .count();
    let workflow_count = apps
        .iter()
        .filter(|a| a.get("kind") == Some(&json!("workflow")))
        .count();
    let active_count = apps
        .iter()
        .filter(|a| a.get("active").and_then(|v| v.as_bool()) == Some(true))
        .count();

    json!({
        "ok": true,
        "schema": "connector.apps.catalog.v1",
        "count": apps.len(),
        "counts": {
            "plugins": plugin_count,
            "workflows": workflow_count,
            "active": active_count,
        },
        "apps": apps,
        "sources": {
            "plugins_detail": "/api/v1/plugins/status",
            "workflows_detail": "/api/v1/workflows",
            "service_map": "/api/v1/plugins/service-map",
        },
        "hint": "Unified catalog for operator UI and connectorctl app list. PID populated when kernel supervises the workload (future).",
    })
}

/// `GET /api/v1/apps` — merged plugin + workflow catalog.
pub async fn list_apps(
    Query(q): Query<ListAppsQuery>,
    State(state): State<SharedState>,
) -> Json<Value> {
    let kind = q
        .kind
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(ref k) = kind {
        if k != "plugin" && k != "workflow" {
            return Json(json!({
                "ok": false,
                "error": "kind must be plugin or workflow",
                "code": "INVALID_KIND",
            }));
        }
    }
    Json(build_catalog(&state, kind.as_deref()).await)
}

/// `GET /api/v1/apps/parity` — T8 unified catalog depth / honesty status.
pub async fn catalog_parity_status(State(state): State<SharedState>) -> Json<Value> {
    let catalog = build_catalog(&state, None).await;
    let apps = catalog
        .get("apps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let plugins = apps
        .iter()
        .filter(|a| a.get("kind").and_then(|k| k.as_str()) == Some("plugin"))
        .count();
    let workflows = apps
        .iter()
        .filter(|a| a.get("kind").and_then(|k| k.as_str()) == Some("workflow"))
        .count();
    let sync = crate::services::workflow_catalog_sync::last_sync_report(&state);
    Json(json!({
        "ok": true,
        "schema": "connector.apps.catalog_parity.v1",
        "routes": {
            "apps": "/api/v1/apps",
            "app_by_id": "/api/v1/apps/:id",
            "workflow_catalog": "/api/v1/workflows/catalog",
            "workflow_catalog_sync": "POST /api/v1/workflows/catalog/sync",
        },
        "counts": { "plugins": plugins, "workflows": workflows, "total": apps.len() },
        "last_workflow_sync": sync,
        "parity": {
            "unified_list": true,
            "router_mounted": true,
            "plugins_status_still_exists": true,
            "workflow_active_honesty": "ENABLE ≠ live CNP bus; catalog may show active=false until runner attaches",
        },
        "honesty": "T8 — /apps is the unified operator surface; keep /plugins/status for deep health only",
    }))
}

/// `GET /api/v1/apps/:id` — one catalog row (`kind` + `id`).
pub async fn show_app(Path(id): Path<String>, State(state): State<SharedState>) -> Response {
    let id = id.trim();
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "id required"})),
        )
            .into_response();
    }
    let catalog = build_catalog(&state, None).await;
    let Some(apps) = catalog.get("apps").and_then(|v| v.as_array()) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "catalog build failed"})),
        )
            .into_response();
    };
    let found = apps.iter().find(|row| {
        row.get("id")
            .and_then(|v| v.as_str())
            .map(|s| s == id)
            .unwrap_or(false)
    });
    match found {
        Some(row) => Json(json!({
            "ok": true,
            "app": row,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": format!("app not found: {id}"),
                "hint": "Known plugin ids: tracetramp, witnessctl, devguard. Workflows use workflow_id from GET /api/v1/workflows.",
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_extracts_port() {
        let (h, p) = parse_host_port("http://127.0.0.1:19742/admin");
        assert_eq!(h.as_deref(), Some("127.0.0.1"));
        assert_eq!(p, Some(19742));
    }

    #[test]
    fn workflow_active_only_when_enabled() {
        assert!(workflow_active(WorkflowState::Enabled));
        assert!(!workflow_active(WorkflowState::Paused));
    }

    #[test]
    fn custom_domain_hosts_from_merged_config() {
        let cfg = serde_json::json!({
            "aliases": [
                {"host": "tt.acme.corp", "plugin_id": "tracetramp", "enabled": true},
            ],
        });
        let hosts = crate::services::custom_domain_routing::custom_domain_hosts_for_plugin(
            &cfg,
            "tracetramp",
        );
        assert_eq!(hosts, vec!["tt.acme.corp"]);
    }
}
