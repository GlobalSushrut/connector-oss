//! `connector.yaml` editor (P2-24).
//!
//! Self-deploy operators edit the running node's config from the
//! dashboard via three endpoints:
//!
//! - `GET    /api/v1/settings/connector-yaml`           — read source +
//!   last-modified metadata.
//! - `POST   /api/v1/settings/connector-yaml/validate`  — parse without
//!   applying. Returns `{ok, errors[]}`.
//! - `PUT    /api/v1/settings/connector-yaml`           — write to disk
//!   (atomic-ish: write to `<path>.tmp` then rename) once validation
//!   passes. Returns the applied source.
//!
//! Authorisation: admin-only. Playground mode 404s because there is no
//! persistent config file backing a hosted trial session.
//!
//! Path resolution: `CONNECTOR_YAML_PATH` env var takes precedence,
//! falling back to `./connector.yaml` (operator-friendly default that
//! matches the docs runbooks).

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::{auth, state::SharedState};

fn yaml_path() -> PathBuf {
    if let Ok(p) = std::env::var("CONNECTOR_YAML_PATH") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("./connector.yaml")
}

fn require_admin(headers: &HeaderMap) -> Result<(), Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn refuse_in_playground() -> Option<Value> {
    if crate::services::playground::is_playground_mode() {
        Some(json!({
            "ok": false,
            "error": "connector.yaml editor not available in playground mode",
            "code": "EDITOR_PLAYGROUND_DISABLED",
        }))
    } else {
        None
    }
}

fn read_source(path: &Path) -> (String, String) {
    let src = std::fs::read_to_string(path).unwrap_or_default();
    let lm = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    (src, lm)
}

fn validate_source(source: &str) -> (bool, Vec<String>) {
    let mut errors = Vec::new();
    // Stage 1: YAML parse — gives a more pinpointed diagnostic than
    // the loader, which short-circuits on the first env-var miss.
    if let Err(e) = serde_yaml::from_str::<Value>(source) {
        errors.push(format!("yaml parse: {e}"));
        return (false, errors);
    }
    // Stage 2: domain validity. `load_config_str` runs the same env
    // interpolation + deserialize the real boot path uses, so the
    // editor surfaces the same diagnostics an operator would see in
    // `connector-platform` startup logs.
    if let Err(e) = connector_api::config::load_config_str(source) {
        errors.push(format!("connector schema: {e}"));
        return (false, errors);
    }
    (true, errors)
}

/// `GET /api/v1/settings/connector-yaml`
pub async fn get_yaml(State(_state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    if let Some(b) = refuse_in_playground() {
        return Json(b);
    }
    if let Err(e) = require_admin(&headers) {
        return Json(e);
    }
    let path = yaml_path();
    let (source, last_modified) = read_source(&path);
    Json(json!({
        "ok": true,
        "path": path.display().to_string(),
        "source": source,
        "last_modified": last_modified,
        "schema_version": env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Debug, Deserialize)]
pub struct YamlBody {
    pub source: String,
}

/// `POST /api/v1/settings/connector-yaml/validate`
pub async fn validate(
    State(_state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<YamlBody>,
) -> Json<Value> {
    if let Some(b) = refuse_in_playground() {
        return Json(b);
    }
    if let Err(e) = require_admin(&headers) {
        return Json(e);
    }
    let (ok, errors) = validate_source(&req.source);
    Json(json!({"ok": ok, "errors": errors}))
}

/// `PUT /api/v1/settings/connector-yaml`
pub async fn put_yaml(
    State(_state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<YamlBody>,
) -> Json<Value> {
    if let Some(b) = refuse_in_playground() {
        return Json(b);
    }
    if let Err(e) = require_admin(&headers) {
        return Json(e);
    }
    let (valid, errors) = validate_source(&req.source);
    if !valid {
        return Json(json!({
            "ok": false,
            "errors": errors,
            "applied_at": null,
        }));
    }

    let path = yaml_path();
    // Atomic-ish write: tmp + rename. Avoids leaving a partially
    // written file if the process dies mid-write. Doesn't survive a
    // power loss but covers the common case.
    let tmp = path.with_extension("yaml.tmp");
    if let Err(e) = std::fs::write(&tmp, req.source.as_bytes()) {
        return Json(json!({
            "ok": false,
            "errors": [format!("write tmp failed: {e}")],
        }));
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        return Json(json!({
            "ok": false,
            "errors": [format!("rename failed: {e}")],
        }));
    }
    Json(json!({
        "ok": true,
        "applied_at": chrono::Utc::now().to_rfc3339(),
        "path": path.display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_unparseable_yaml() {
        let (ok, errors) = validate_source("not: valid:\n  - yaml:::");
        assert!(!ok);
        assert!(errors.iter().any(|e| e.contains("yaml parse")));
    }

    #[test]
    fn validate_accepts_minimal_connector_yaml() {
        let src = "connector:\n  provider: openai\n  model: gpt-4o\n";
        let (ok, errors) = validate_source(src);
        assert!(ok, "expected valid config; got errors: {errors:?}");
        assert!(errors.is_empty());
    }
}
