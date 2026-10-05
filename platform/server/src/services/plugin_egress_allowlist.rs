//! Phase 5.7 — egress allowlist derived from installed plugin manifest (`network.outbound:host:port`); VM firewall enforcement TBD.

use std::path::Path;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;
use crate::services::plugin_cpkg::safe_plugin_id;
use crate::services::runtime_control;
use crate::state::SharedState;
use connector_plugin_manifest::PluginManifest;

#[derive(Debug, Deserialize)]
pub struct EgressQuery {
    pub plugin_id: String,
}

fn require_auth_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(json!({"ok": false, "error": "Unauthorized"}))
}

fn store_root(state: &SharedState) -> std::path::PathBuf {
    Path::new(&state.config.data_dir)
        .join("plugins")
        .join("cpkg_store")
}

fn read_manifest_from_dir(files_dir: &Path) -> Option<PluginManifest> {
    let p = files_dir.join("plugin.toml");
    let raw = std::fs::read_to_string(p).ok()?;
    PluginManifest::parse(&raw).ok()
}

fn read_manifest_from_cpkg(pkg_path: &Path) -> Option<PluginManifest> {
    let bytes = std::fs::read(pkg_path).ok()?;
    connector_cpkg::read_cpkg(&bytes).ok().map(|b| b.manifest)
}

fn outbound_caps(manifest: &PluginManifest) -> Vec<String> {
    manifest
        .capabilities
        .required
        .iter()
        .filter(|c| {
            let t = c.trim();
            t.starts_with("network.outbound:") && !t.starts_with("network.outbound:*")
        })
        .cloned()
        .collect()
}

/// Outbound capability strings for plugin-runtime `SpawnRequest::egress_allowlist` (same rules as GET allowlist).
pub fn manifest_outbound_allowlist(manifest: &PluginManifest) -> Vec<String> {
    outbound_caps(manifest)
}

pub async fn get_plugin_egress_allowlist(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<EgressQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    let plugin_id = q.plugin_id.trim().to_string();
    if plugin_id.is_empty() || plugin_id.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }

    let sid = safe_plugin_id(&plugin_id);
    let root = store_root(&state).join(&sid);
    let versions_dir = root.join("versions");
    let rollout_path = root.join("rollout.json");
    let active_version = std::fs::read_to_string(&rollout_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| {
            v.get("active_version")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });

    let latest_files = active_version
        .as_ref()
        .map(|v| versions_dir.join(v).join("files"));
    let latest_pkg = active_version
        .as_ref()
        .map(|v| versions_dir.join(v).join("package.cpkg"));
    let manifest = latest_files
        .as_ref()
        .and_then(|d| read_manifest_from_dir(d))
        .or_else(|| latest_pkg.as_ref().and_then(|p| read_manifest_from_cpkg(p)));

    let allowlist = manifest.as_ref().map(outbound_caps).unwrap_or_default();
    Ok(Json(json!({
        "ok": true,
        "plugin_id": plugin_id,
        "active_version": active_version,
        "policy": "deny_by_default",
        "allowlist": allowlist,
        "phase_5_operator_env": {
            "docker_lab_egress": crate::services::phase5_operator_env::docker_lab_egress_mode_label(),
            "docker_lab_egress_enforce": crate::services::phase5_operator_env::docker_lab_egress_enforce_label(),
            "microvm_egress_mode": crate::services::phase5_operator_env::microvm_egress_mode_label(),
            "microvm_egress_enforce": crate::services::phase5_operator_env::microvm_egress_enforce_label(),
            "microvm_egress_enforce_required": crate::services::phase5_operator_env::microvm_egress_enforce_required_label(),
        },
        "hint": "Docker lab: CONNECTOR_DOCKER_LAB_EGRESS=deny_all|allowlist_strict; CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables (Linux) enforces IPv4/IPv6 via iptables+ip6tables DOCKER-USER. MicroVM (Linux Firecracker): CONNECTOR_MICROVM_EGRESS_MODE + CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables (TAP + FORWARD allowlist, IPv4 TCP; see connector-plugin-runtime). This endpoint is manifest truth.",
        "docker_lab_egress_env": "CONNECTOR_DOCKER_LAB_EGRESS=unrestricted|deny_all|allowlist_strict",
        "docker_lab_egress_enforce_env": "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables (Linux; see connector-plugin-runtime)",
        "microvm_egress_env": "CONNECTOR_MICROVM_EGRESS_MODE=deny_all|allowlist_strict|custom",
        "microvm_egress_enforce_env": "CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables (Linux native microVM spawn)",
        "microvm_egress_enforce_required_env": "CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED=1 (fail-closed when enforce is requested but unavailable)",
    })))
}
