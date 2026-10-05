//! ExtensionHost — unified facade over AGOS plugin lifecycle / cpkg.
//!
//! AttachedApp bind/activate stores a PackagePin and requires package gate
//! outside lab. WIT remains a typed stub (`connector_native_contract::ExtensionWitWorld`).

use connector_native_contract::{PackagePin, ExtensionWitWorld};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::services::plugin_lifecycle::{self, PluginLifecycleState};
use crate::state::SharedState;
use crate::substrate::package_gate;

const ATTACHED_FOLDER: &str = "attached_app_bindings_v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    AgosPlugin,
    AttachedApp,
    Adapter,
    Workflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionStatus {
    pub extension_id: String,
    pub kind: ExtensionKind,
    pub installed: bool,
    pub enabled: bool,
    pub version: String,
    pub revision: u64,
    pub last_action: String,
    pub wit: ExtensionWitWorld,
    pub honesty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<PackagePin>,
}

impl ExtensionStatus {
    fn from_plugin(row: &PluginLifecycleState) -> Self {
        Self {
            extension_id: row.plugin_id.clone(),
            kind: ExtensionKind::AgosPlugin,
            installed: row.installed,
            enabled: row.enabled,
            version: row.version.clone(),
            revision: row.revision,
            last_action: row.last_action.clone(),
            wit: ExtensionWitWorld::default_for(&row.plugin_id),
            honesty: "AGOS plugin adapter — install_only/bind does not auto-enable; legacy install still enables".into(),
            package: None,
        }
    }

    fn from_attached(id: &str, bound: &AttachedBinding) -> Self {
        Self {
            extension_id: id.into(),
            kind: ExtensionKind::AttachedApp,
            installed: bound.bound,
            enabled: bound.active,
            version: bound.version.clone(),
            revision: bound.revision,
            last_action: bound.last_action.clone(),
            wit: ExtensionWitWorld::default_for(id),
            honesty: "AttachedApp governance binding — executable stays external; package digest is authority".into(),
            package: Some(bound.package.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttachedBinding {
    package: PackagePin,
    bound: bool,
    active: bool,
    version: String,
    revision: u64,
    last_action: String,
    /// Birth-controlled launch recorded (TransportEnforced eligible).
    #[serde(default)]
    birth_controlled: bool,
    /// Advisory attach of an already-running PID (never TransportEnforced).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attached_pid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launch_cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_honesty: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExtensionActionRequest {
    pub action: String,
    #[serde(default)]
    pub target_version: Option<String>,
    #[serde(default)]
    pub kind: Option<ExtensionKind>,
    /// Required for AttachedApp bind/activate and AGOS activate outside lab.
    #[serde(default)]
    pub package: Option<PackagePin>,
    /// Absolute path or argv0 for controlled `run` (birth-controlled spawn intent).
    #[serde(default)]
    pub executable: Option<String>,
    /// Optional PID for advisory `attach` (already-running process).
    #[serde(default)]
    pub pid: Option<i32>,
    /// When true on `run`, records birth_controlled=true (required for TransportEnforced).
    #[serde(default)]
    pub birth_controlled: Option<bool>,
}

fn load_attached(state: &SharedState, id: &str) -> Option<AttachedBinding> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(ATTACHED_FOLDER, id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

fn store_attached(state: &SharedState, id: &str, bound: &AttachedBinding) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let v = serde_json::to_value(bound).map_err(|e| e.to_string())?;
    es.folder_put(ATTACHED_FOLDER, id, &v)
        .map_err(|e| e.to_string())
}

fn apply_attached_action(
    state: &SharedState,
    extension_id: &str,
    req: &ExtensionActionRequest,
) -> Result<ExtensionStatus, String> {
    let id = extension_id.trim().to_ascii_lowercase();
    let action = req.action.trim().to_ascii_lowercase();
    match action.as_str() {
        "preflight" | "query_status" | "query-status" | "status" => {
            if let Some(b) = load_attached(state, &id) {
                return Ok(ExtensionStatus::from_attached(&id, &b));
            }
            return Ok(ExtensionStatus {
                extension_id: id,
                kind: ExtensionKind::AttachedApp,
                installed: false,
                enabled: false,
                version: "0".into(),
                revision: 0,
                last_action: "none".into(),
                wit: ExtensionWitWorld::default_for(extension_id),
                honesty: "AttachedApp unbound — supply package pin on bind".into(),
                package: None,
            });
        }
        "install" | "install_only" | "bind" => {
            let pin = req
                .package
                .as_ref()
                .ok_or_else(|| "attached_app_bind_requires_package_pin".to_string())?;
            package_gate::require_package_for_consequential_effect(Some(pin))?;
            if pin.package_id.trim() != id && !pin.package_id.is_empty() {
                // Allow binding when extension_id aliases package_id; warn via honesty only if mismatch.
            }
            let bound = AttachedBinding {
                package: pin.clone(),
                bound: true,
                active: false,
                version: req
                    .target_version
                    .clone()
                    .unwrap_or_else(|| "0.1.0".into()),
                revision: load_attached(state, &id)
                    .map(|b| b.revision + 1)
                    .unwrap_or(1),
                last_action: "bind".into(),
                birth_controlled: false,
                attached_pid: None,
                launch_cmd: None,
                run_honesty: None,
            };
            store_attached(state, &id, &bound)?;
            Ok(ExtensionStatus::from_attached(&id, &bound))
        }
        "activate" | "enable" => {
            let mut bound = load_attached(state, &id)
                .ok_or_else(|| "attached_app_not_bound: run bind with package pin first".to_string())?;
            let pin = req.package.as_ref().unwrap_or(&bound.package);
            package_gate::require_package_for_consequential_effect(Some(pin))?;
            if pin.package_digest != bound.package.package_digest {
                return Err("attached_app_package_digest_mismatch".into());
            }
            let wit = ExtensionWitWorld::default_for(&id);
            wit.require_component_link_or_err()?;
            bound.active = true;
            bound.last_action = "activate".into();
            bound.revision += 1;
            store_attached(state, &id, &bound)?;
            Ok(ExtensionStatus::from_attached(&id, &bound))
        }
        "deactivate" | "disable" => {
            let mut bound = load_attached(state, &id)
                .ok_or_else(|| "attached_app_not_bound".to_string())?;
            bound.active = false;
            bound.last_action = "deactivate".into();
            bound.revision += 1;
            store_attached(state, &id, &bound)?;
            Ok(ExtensionStatus::from_attached(&id, &bound))
        }
        "uninstall" | "revoke" => {
            let mut es = state
                .engine_store
                .lock()
                .map_err(|_| "engine_store_lock".to_string())?;
            let _ = es.folder_delete(ATTACHED_FOLDER, &id);
            Ok(ExtensionStatus {
                extension_id: id,
                kind: ExtensionKind::AttachedApp,
                installed: false,
                enabled: false,
                version: "0".into(),
                revision: 0,
                last_action: "revoke".into(),
                wit: ExtensionWitWorld::default_for(extension_id),
                honesty: "AttachedApp binding revoked".into(),
                package: None,
            })
        }
        "run" => {
            let mut bound = load_attached(state, &id)
                .ok_or_else(|| "attached_app_not_bound: run bind with package pin first".to_string())?;
            if !bound.active {
                return Err("attached_app_not_active: activate before run".into());
            }
            let pin = req.package.as_ref().unwrap_or(&bound.package);
            package_gate::require_package_for_consequential_effect(Some(pin))?;
            let exe = req
                .executable
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "attached_app_run_requires_executable".to_string())?;
            let birth = req.birth_controlled.unwrap_or(true);
            // Record launch intent via origin_binding posture rules — do not claim host confinement
            // unless birth_controlled. Actual spawn is operator/supervisor owned.
            let posture = crate::substrate::origin_binding::resolve_workload_posture(
                None,
                birth,
            );
            bound.birth_controlled = birth;
            bound.launch_cmd = Some(exe.into());
            bound.attached_pid = None;
            bound.last_action = "run".into();
            bound.revision += 1;
            bound.run_honesty = Some(format!(
                "birth_controlled={birth}; posture={posture:?}; executable recorded — host spawn/supervisor applies confinement; activate alone is not TransportEnforced"
            ));
            store_attached(state, &id, &bound)?;
            let mut status = ExtensionStatus::from_attached(&id, &bound);
            status.honesty = bound
                .run_honesty
                .clone()
                .unwrap_or(status.honesty);
            Ok(status)
        }
        "attach" => {
            let mut bound = load_attached(state, &id)
                .ok_or_else(|| "attached_app_not_bound: run bind with package pin first".to_string())?;
            let pin = req.package.as_ref().unwrap_or(&bound.package);
            package_gate::require_package_for_consequential_effect(Some(pin))?;
            let pid = req
                .pid
                .filter(|p| *p > 0)
                .ok_or_else(|| "attached_app_attach_requires_pid".to_string())?;
            // Attach is always advisory — inherited FDs/sockets cannot claim TransportEnforced.
            bound.birth_controlled = false;
            bound.attached_pid = Some(pid);
            bound.last_action = "attach".into();
            bound.revision += 1;
            bound.run_honesty = Some(format!(
                "advisory_attach pid={pid}; birth_controlled=false; TransportEnforced refused until birth-controlled restart"
            ));
            store_attached(state, &id, &bound)?;
            let mut status = ExtensionStatus::from_attached(&id, &bound);
            status.honesty = bound
                .run_honesty
                .clone()
                .unwrap_or(status.honesty);
            Ok(status)
        }
        other => Err(format!(
            "attached_app_unsupported_action:{other} — use bind|activate|deactivate|revoke|run|attach"
        )),
    }
}

/// Query status through the host (plugin lifecycle + WIT stub).
pub fn status(state: &SharedState, extension_id: &str) -> Result<ExtensionStatus, String> {
    let id = extension_id.trim().to_ascii_lowercase();
    if let Some(b) = load_attached(state, &id) {
        return Ok(ExtensionStatus::from_attached(&id, &b));
    }
    let row = plugin_lifecycle::load_plugin_lifecycle_state(state, &id);
    Ok(ExtensionStatus::from_plugin(&row))
}

/// Apply an ExtensionHost action.
///
/// Canonical actions: `preflight` (status-only), `install` (= install_only),
/// `activate`, `deactivate`, `uninstall`/`revoke`, plus legacy aliases.
pub fn apply_action(
    state: &SharedState,
    extension_id: &str,
    req: &ExtensionActionRequest,
) -> Result<ExtensionStatus, String> {
    if matches!(req.kind, Some(ExtensionKind::AttachedApp)) {
        return apply_attached_action(state, extension_id, req);
    }

    let action = req.action.trim().to_ascii_lowercase();
    // AGOS activate/enable is consequential — require package outside lab.
    if matches!(action.as_str(), "activate" | "enable") {
        package_gate::require_package_for_consequential_effect(req.package.as_ref())?;
        ExtensionWitWorld::default_for(extension_id).require_component_link_or_err()?;
    }

    let mapped = match action.as_str() {
        "preflight" | "query_status" | "query-status" | "status" => {
            return status(state, extension_id);
        }
        // Host install does not auto-activate.
        "install" => "install_only",
        "activate" | "enable" => "activate",
        "deactivate" | "disable" => "deactivate",
        "uninstall" | "revoke" => "uninstall",
        "install_only" | "bind" | "update" => action.as_str(),
        other => other,
    };

    let updated = plugin_lifecycle::transition_lifecycle(
        state,
        extension_id,
        mapped,
        req.target_version.clone(),
    )?;
    Ok(ExtensionStatus::from_plugin(&updated))
}

pub fn list_extensions(state: &SharedState) -> Vec<ExtensionStatus> {
    let mut ids: std::collections::BTreeSet<String> = crate::services::plugin_matrix::KNOWN_PLUGINS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    ids.extend(crate::services::plugin_cpkg::list_cpkg_store_plugin_ids(state));
    {
        let es = state.engine_store.lock().unwrap();
        if let Ok(keys) = es.folder_keys("plugin_lifecycle", None) {
            ids.extend(keys);
        }
        if let Ok(keys) = es.folder_keys(ATTACHED_FOLDER, None) {
            ids.extend(keys);
        }
    }
    ids.into_iter()
        .map(|id| status(state, &id).unwrap_or_else(|_| {
            let row = plugin_lifecycle::load_plugin_lifecycle_state(state, &id);
            ExtensionStatus::from_plugin(&row)
        }))
        .collect()
}

// ── HTTP (native + thin aliases) ───────────────────────────────────────────

pub async fn get_extension(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::Json<Value> {
    match status(&state, &id) {
        Ok(s) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "extension": s,
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

pub async fn list_extensions_handler(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<Value> {
    let extensions = list_extensions(&state);
    axum::Json(crate::operator::honesty::measured_envelope(json!({
        "count": extensions.len(),
        "extensions": extensions,
        "honesty": "ExtensionHost — AttachedApp bind/activate/run/attach live; WIT typed stub unless CONNECTOR_WIT_REQUIRE_COMPONENT fail-closes",
    })))
}

pub async fn post_extension_action(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(req): axum::Json<ExtensionActionRequest>,
) -> axum::Json<Value> {
    match apply_action(&state, &id, &req) {
        Ok(s) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "extension": s,
            "action": req.action,
        }))),
        Err(e) => axum::Json(json!({ "ok": false, "error": e })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_stub_present_on_status_shape() {
        let row = PluginLifecycleState {
            plugin_id: "devguard".into(),
            installed: true,
            enabled: false,
            version: "1.0.0".into(),
            revision: 1,
            last_action: "install_only".into(),
            updated_at: "now".into(),
        };
        let s = ExtensionStatus::from_plugin(&row);
        assert_eq!(s.kind, ExtensionKind::AgosPlugin);
        assert!(!s.wit.world.is_empty());
    }
}
