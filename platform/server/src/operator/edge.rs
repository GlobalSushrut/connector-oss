use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::honesty::operator_envelope,
    services::{
        custom_domain_routing,
        plugin_matrix,
        workflow_runtime::{require_admin_or_dev, WORKFLOW_FOLDER},
    },
    state::SharedState,
};

pub const EDGE_RECORD_SCHEMA: &str = "edge_record.v1";

fn public_base_url() -> Option<String> {
    std::env::var("CONNECTOR_PUBLIC_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("CONNECTOR_PLATFORM_PUBLIC_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
}

fn edge_record(
    id: &str,
    kind: &str,
    host: &str,
    target: Value,
    health: Value,
    hints: Value,
) -> Value {
    json!({
        "schema": EDGE_RECORD_SCHEMA,
        "id": id,
        "kind": kind,
        "host": host,
        "target": target,
        "health": health,
        "dns_hints": hints,
        "policy": {
            "require_cfni": crate::substrate::cfni::cfni_enforce_production(),
            "require_cfni_supported": crate::substrate::cfni::cfni_enabled(),
        }
    })
}

/// Merge custom domains, internal DNS, gateway, and plugin status into one plane.
pub fn merge_edge_plane(state: &SharedState) -> Value {
    let mut records: Vec<Value> = Vec::new();
    let cfg = custom_domain_routing::load_merged_custom_domains_for_host_routing(state);
    let public_url = public_base_url();

    if let Some(base) = public_url.as_deref() {
        records.push(edge_record(
            "gateway:public",
            "GATEWAY_ROUTE",
            base.trim().trim_start_matches("https://").trim_start_matches("http://"),
            json!({
                "type": "gateway",
                "public_url": base,
                "paths": ["/api/v1", "/v1", "/plugin/{slug}"]
            }),
            json!({ "status": "configured" }),
            json!({
                "message": format!("Public API base: {base}"),
                "record_type": "CNAME",
                "suggested_name": "connector",
                "suggested_target": "<your-node-host>"
            }),
        ));
    }

    if let Some(aliases) = cfg.get("aliases").and_then(|v| v.as_array()) {
        for entry in aliases.iter() {
            let enabled = entry.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            if !enabled {
                continue;
            }
            let host = entry
                .get("host")
                .or_else(|| entry.get("domain"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let slug = entry
                .get("plugin_id")
                .or_else(|| entry.get("plugin"))
                .or_else(|| entry.get("slug"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if host.is_empty() || slug.is_empty() {
                continue;
            }
            let id = format!("custom_domain:{slug}:{host}");
            records.push(edge_record(
                &id,
                "HOST_ALIAS",
                host,
                json!({
                    "type": "institution_route",
                    "plugin_id": slug,
                    "proxy_prefix": format!("/plugin/{slug}")
                }),
                json!({ "status": if enabled { "enabled" } else { "disabled" } }),
                json!({
                    "message": format!("Create DNS CNAME {host} → your Connector node"),
                    "record_type": "CNAME",
                    "name": host,
                    "target": public_url.clone().unwrap_or_else(|| "<connector-node>".into())
                }),
            ));
        }
    }

    for slug in plugin_matrix::enabled_plugin_ids() {
        let cage_host = crate::internal_dns::plugin_cage_hostname(slug);
        let dns_registered = crate::internal_dns::resolve(&cage_host).is_some();
        records.push(edge_record(
            &format!("cage_internal:{slug}"),
            "CAGE_INTERNAL",
            &cage_host,
            json!({
                "type": "cage_internal",
                "plugin_id": slug,
                "proxy_prefix": format!("/plugin/{slug}")
            }),
            json!({
                "status": if dns_registered { "registered" } else { "unregistered" },
                "internal_dns": dns_registered
            }),
            json!({
                "message": format!("Internal cage host {cage_host} (in-process DNS only)"),
                "record_type": "INTERNAL",
                "name": cage_host
            }),
        ));
    }

    let dns_entries: Vec<Value> = crate::internal_dns::dump_json()
        .into_iter()
        .map(|e| {
            json!({
                "name": e.name,
                "addr": e.addr,
                "healthy": e.healthy,
                "stale": e.stale,
                "description": e.description,
                "tags": e.tags
            })
        })
        .collect();

    json!({
        "schema": "operator_edge_plane.v1",
        "record_count": records.len(),
        "records": records,
        "internal_dns": dns_entries,
        "tls_mode": cfg.get("tls_mode").cloned().unwrap_or(json!("lets_encrypt")),
        "public_url": public_url,
        "cage_tld": crate::internal_dns::cage_tld(),
    })
}

/// `GET /api/v1/operator/edge/plane`
pub async fn get_operator_edge_plane(State(state): State<SharedState>) -> Json<Value> {
    let plane = merge_edge_plane(&state);
    Json(operator_envelope(plane))
}

#[derive(Debug, Deserialize)]
pub struct EdgeRecordWriteRequest {
    pub kind: Option<String>,
    pub host: String,
    pub plugin_id: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn dns_hints_from_plane(plane: &Value) -> Value {
    let hints: Vec<Value> = plane
        .get("records")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("dns_hints").cloned())
                .collect()
        })
        .unwrap_or_default();
    json!({
        "schema": "operator_edge_dns_hints.v1",
        "count": hints.len(),
        "hints": hints,
    })
}

/// `GET /api/v1/operator/edge/records`
pub async fn get_operator_edge_records(State(state): State<SharedState>) -> Json<Value> {
    let plane = merge_edge_plane(&state);
    Json(operator_envelope(json!({
        "records": plane.get("records").cloned().unwrap_or(json!([])),
        "record_count": plane.get("record_count"),
    })))
}

/// `GET /api/v1/operator/edge/dns-hints`
pub async fn get_operator_edge_dns_hints(State(state): State<SharedState>) -> Json<Value> {
    let plane = merge_edge_plane(&state);
    Json(operator_envelope(dns_hints_from_plane(&plane)))
}

/// `POST /api/v1/operator/edge/records`
pub async fn post_operator_edge_record(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<EdgeRecordWriteRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let kind = req.kind.as_deref().unwrap_or("HOST_ALIAS");
    if kind != "HOST_ALIAS" && kind != "INSTITUTION_ROUTE" {
        return Json(json!({
            "ok": false,
            "error": format!("unsupported edge record kind for write: {kind}"),
        }));
    }
    let slug = req
        .plugin_id
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if slug.is_empty() || !plugin_matrix::is_gated_plugin_segment(&slug) {
        return Json(json!({"ok": false, "error": "valid plugin_id required"}));
    }
    match custom_domain_routing::upsert_custom_domain_alias(&state, &req.host, &slug, req.enabled) {
        Ok(_) => {
            let plane = merge_edge_plane(&state);
            let id = format!("custom_domain:{slug}:{}", req.host.trim());
            Json(operator_envelope(json!({
                "written": true,
                "record_id": id,
                "plane": plane,
            })))
        }
        Err(err) => Json(json!({"ok": false, "error": err})),
    }
}

/// `DELETE /api/v1/operator/edge/records/:id`
pub async fn delete_operator_edge_record(
    State(state): State<SharedState>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    match custom_domain_routing::remove_custom_domain_by_record_id(&state, &record_id) {
        Ok(removed) => Json(operator_envelope(json!({
            "removed": removed,
            "record_id": record_id,
        }))),
        Err(err) => Json(json!({"ok": false, "error": err})),
    }
}

/// `POST /api/v1/operator/edge/records/:id/prove`
pub async fn prove_operator_edge_record(
    State(state): State<SharedState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    let plane = merge_edge_plane(&state);
    let records = plane.get("records").and_then(|v| v.as_array());
    let Some(records) = records else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "no records"})),
        )
            .into_response();
    };
    let found = records.iter().find(|r| r.get("id").and_then(|v| v.as_str()) == Some(record_id.as_str()));
    let Some(rec) = found else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "record not found"})),
        )
            .into_response();
    };
    let host = rec.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let slug = rec
        .get("target")
        .and_then(|t| t.get("plugin_id"))
        .and_then(|v| v.as_str());
    let cage_ok = slug
        .map(|s| {
            let cage = crate::internal_dns::plugin_cage_hostname(s);
            crate::internal_dns::resolve(&cage).is_some()
        })
        .unwrap_or(false);
    let host_ok = if host.is_empty() {
        false
    } else {
        custom_domain_routing::resolve_plugin_slug_for_host(&state, host).is_some()
            || crate::internal_dns::is_cage_host(host)
    };
    Json(operator_envelope(json!({
        "record_id": record_id,
        "proved_at": chrono::Utc::now().to_rfc3339(),
        "ok": cage_ok || host_ok,
        "checks": [
            {"id": "host_route", "ok": host_ok, "host": host},
            {"id": "cage_internal", "ok": cage_ok, "plugin_id": slug},
        ],
        "cage_proof_path": "/api/v1/plugins/cage-proof",
    })))
    .into_response()
}

/// `GET /api/v1/workflows/:id/edge`
pub async fn get_workflow_edge(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> Json<Value> {
    let exists = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(WORKFLOW_FOLDER, &workflow_id)
            .ok()
            .flatten()
            .is_some()
    };
    if !exists {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    }
    let plane = merge_edge_plane(&state);
    let records: Vec<Value> = plane
        .get("records")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| {
            r.get("kind").and_then(|v| v.as_str()) == Some("GATEWAY_ROUTE")
                || r.get("kind").and_then(|v| v.as_str()) == Some("CAGE_INTERNAL")
        })
        .collect();
    Json(operator_envelope(json!({
        "workflow_id": workflow_id,
        "records": records,
        "hint": "Workflow-specific binds (WORKFLOW_ROUTE) ship in a later milestone",
    })))
}

/// `GET /api/v1/agents/:pid/edge`
pub async fn get_agent_edge(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<Value> {
    let plane = merge_edge_plane(&state);
    Json(operator_envelope(json!({
        "agent_pid": pid,
        "records": plane.get("records").cloned().unwrap_or(json!([])),
        "devguard_connect_path": "/api/v1/devguard/connect",
        "hint": "Agent-specific edge binds filter in a later milestone",
    })))
}
