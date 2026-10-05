//! Plugin + microVM runtime inventory for `GET /api/v1/runtime/plugin-inventory` and `connectorctl plugin status`.

use std::path::{Path, PathBuf};

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::internal_dns;
use crate::services::plugin_matrix;
use crate::services::runtime_control::{self, IsolationRuntime};
use crate::state::SharedState;

pub fn microvm_state_dir() -> PathBuf {
    std::env::var("CONNECTOR_MICROVM_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("connector-microvm"))
}

/// Scan `CONNECTOR_MICROVM_STATE_DIR` for Firecracker API sockets (`{vm_id}.sock`).
pub fn list_microvm_slots() -> Vec<Value> {
    let base = microvm_state_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&base) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".sock") {
            continue;
        }
        let vm_id = name.trim_end_matches(".sock").to_string();
        if vm_id.is_empty() {
            continue;
        }
        let vsock = base.join(format!("{vm_id}.vsock"));
        let log = base.join(format!("{vm_id}.log"));
        let metrics = base.join(format!("{vm_id}.metrics.fifo"));
        let socket_alive = path.exists();
        out.push(json!({
            "vm_id": vm_id,
            "api_socket": path.to_string_lossy(),
            "socket_alive": socket_alive,
            "vsock_path": vsock.to_string_lossy(),
            "vsock_exists": vsock.exists(),
            "log_path": log.to_string_lossy(),
            "log_exists": log.exists(),
            "metrics_fifo": metrics.to_string_lossy(),
        }));
    }
    out.sort_by(|a, b| {
        a.get("vm_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("vm_id").and_then(|v| v.as_str()).unwrap_or(""))
    });
    out
}

fn first_party_plugin_rows(state: &SharedState) -> Vec<Value> {
    plugin_matrix::KNOWN_PLUGINS
        .iter()
        .map(|slug| {
            let cage = internal_dns::plugin_cage_hostname(slug);
            let dns = internal_dns::resolve(&cage).is_some();
            let lifecycle =
                crate::services::plugin_lifecycle::load_plugin_lifecycle_state(state, slug);
            json!({
                "plugin_id": slug,
                "enabled_in_deployment": plugin_matrix::is_plugin_enabled(slug),
                "cage_host": cage,
                "cage_dns_registered": dns,
                "lifecycle": lifecycle,
                "public_path": format!("/plugin/{slug}"),
            })
        })
        .collect()
}

pub fn current_isolation_attestation(state: &SharedState) -> Value {
    let isolation = *state.isolation_runtime.read().unwrap();
    let effective_backend =
        crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label();
    isolation_attestation(isolation, &effective_backend)
}

fn isolation_attestation(declared: IsolationRuntime, effective_backend: &str) -> Value {
    let downgrade_risk = match declared {
        IsolationRuntime::Microvm => {
            !effective_backend.contains("microvm") && !effective_backend.contains("firecracker")
        }
        IsolationRuntime::DockerLab => !effective_backend.contains("docker"),
        IsolationRuntime::Wasm => !effective_backend.contains("wasm"),
        IsolationRuntime::Subprocess | IsolationRuntime::Internal => false,
    };
    json!({
        "declared_runtime": declared.as_str(),
        "effective_env_backend": effective_backend,
        "downgrade_risk": downgrade_risk,
        "fail_closed_prod": !std::env::var("CONNECTOR_ALLOW_ISOLATION_DOWNGRADE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    })
}

pub fn build_plugin_inventory(state: &SharedState) -> Value {
    let isolation = *state.isolation_runtime.read().unwrap();
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let effective_backend =
        crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label();
    let attestation = isolation_attestation(isolation, &effective_backend);
    let isolation_grade_ok = crate::substrate::cage_security::assert_cage_isolation_grade(state)
        .is_ok()
        && crate::substrate::cage_security::assert_isolation_runtime_grade(isolation).is_ok();
    let microvms = list_microvm_slots();
    let topology = state
        .kernel_host
        .lock()
        .ok()
        .map(|h| h.microvm_topology_json())
        .unwrap_or(Value::Null);

    json!({
        "ok": true,
        "schema": "connector.runtime.plugin_inventory.v1",
        "runtime_mode": runtime_mode.as_str(),
        "isolation_runtime": isolation.as_str(),
        "isolation_attestation": attestation,
        "isolation_grade_ok": isolation_grade_ok,
        "cage_security": crate::substrate::cage_security::cage_security_status(state),
        "isolation_default_for_mode": match runtime_mode {
            runtime_control::RuntimeMode::Dev => IsolationRuntime::Subprocess.as_str(),
            _ => IsolationRuntime::Microvm.as_str(),
        },
        "connectorctl_plugin_run_backend": crate::services::phase5_operator_env::connectorctl_plugin_run_backend_label(),
        "docker_available": runtime_control::docker_available(),
        "microvm_state_dir": microvm_state_dir().to_string_lossy(),
        "microvm_slots": microvms,
        "microvm_slot_count": microvms.len(),
        "microvm_topology": topology,
        "first_party_plugins": first_party_plugin_rows(state),
        "hints": {
            "spawn": "connectorctl plugin run --dev <vendor/slug>",
            "status_cli": "connectorctl plugin status [--json]",
            "isolation_api": "GET/POST /api/v1/runtime/isolation",
        },
    })
}

/// `GET /api/v1/runtime/plugin-inventory` — isolation backend + microVM slot scan + cage rows.
pub async fn get_plugin_inventory(State(state): State<SharedState>) -> Json<Value> {
    Json(build_plugin_inventory(&state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microvm_state_dir_has_default() {
        let p = microvm_state_dir();
        assert!(!p.to_string_lossy().is_empty());
    }
}
