//! Phase 4.9 — semver `[depends]` checks before `.cpkg` install.

use connector_plugin_manifest::PluginManifest;
use semver::{Version, VersionReq};
use serde_json::{json, Value};

use crate::services::plugin_lifecycle::load_plugin_lifecycle_state;
use crate::state::SharedState;

/// Returns `Err(json)` with `code: depends_unsatisfied` when install must be blocked.
pub fn evaluate_depends_for_install(
    manifest: &PluginManifest,
    state: &SharedState,
) -> Result<(), Value> {
    let Some(ref deps) = manifest.depends else {
        return Ok(());
    };
    if deps.is_empty() {
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut incompatible = Vec::new();

    for (dep_id, req_str) in deps.iter() {
        let req = match VersionReq::parse(req_str.trim()) {
            Ok(r) => r,
            Err(e) => {
                return Err(json!({
                    "ok": false,
                    "error": format!("invalid semver requirement for {dep_id}: {e}"),
                    "code": "depends_parse_error",
                    "dependency": dep_id,
                    "required": req_str,
                }));
            }
        };

        let life = load_plugin_lifecycle_state(state, dep_id);
        if !life.installed {
            missing.push(json!({
                "plugin_id": dep_id,
                "required": req_str,
                "suggestion": format!("install {dep_id} satisfying `{req_str}` before this package"),
            }));
            continue;
        }

        let vstr = life.version.trim();
        if vstr == "builtin" || vstr == "none" || vstr.is_empty() {
            // First-party built-ins without a numeric version: treat as satisfied when deployment enables them.
            continue;
        }

        match Version::parse(vstr) {
            Ok(v) => {
                if !req.matches(&v) {
                    incompatible.push(json!({
                        "plugin_id": dep_id,
                        "installed_version": vstr,
                        "required": req_str,
                        "suggestion": format!(
                            "upgrade or replace `{dep_id}` to a version matching `{req_str}` (currently {vstr})"
                        ),
                    }));
                }
            }
            Err(_) => {
                incompatible.push(json!({
                    "plugin_id": dep_id,
                    "installed_version": vstr,
                    "required": req_str,
                    "suggestion": format!(
                        "cannot compare installed version `{vstr}` for `{dep_id}` to `{req_str}`; use a semver release"
                    ),
                }));
            }
        }
    }

    if missing.is_empty() && incompatible.is_empty() {
        return Ok(());
    }

    Err(json!({
        "ok": false,
        "code": "depends_unsatisfied",
        "message": "Plugin dependencies are not satisfied; install or upgrade dependencies first.",
        "missing": missing,
        "incompatible": incompatible,
    }))
}
