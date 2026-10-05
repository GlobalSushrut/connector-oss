use serde_json::Value;

use crate::operator::surface_merge::normalize_accounting_mode;

const PANEL_TYPES: &[&str] = &[
    "kv",
    "summary",
    "summary_text",
    "chips",
    "institution_chips",
    "event_list",
    "table",
    "approval_queue",
];

/// Validate `operator_surface.v1` manifest (CLI + CI).
pub fn lint_operator_surface(manifest: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let schema = manifest.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema != "operator_surface.v1" {
        errors.push(format!("schema must be operator_surface.v1 (got {schema:?})"));
    }
    let title = manifest
        .get("display")
        .and_then(|d| d.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if title.trim().is_empty() {
        errors.push("display.title is required".into());
    }
    match manifest.get("accounting") {
        None => errors.push(
            "accounting is required (workflow_accounting.v1): mode must be action or service_monitoring"
                .into(),
        ),
        Some(acc) => {
            let mode = acc.get("mode").and_then(|v| v.as_str()).unwrap_or("");
            if normalize_accounting_mode(mode).is_none() {
                errors.push(format!(
                    "accounting.mode must be action or service_monitoring (got {mode:?})"
                ));
            }
        }
    }
    if let Some(inst) = manifest.get("institutions") {
        if !inst.is_array() {
            errors.push("institutions must be an array".into());
        }
    }
    if let Some(actions) = manifest.get("actions") {
        let Some(arr) = actions.as_array() else {
            errors.push("actions must be an array".into());
            return finish(errors);
        };
        for (i, a) in arr.iter().enumerate() {
            if a.get("id").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
                errors.push(format!("actions[{i}] missing id"));
            }
        }
    }
    if let Some(panels) = manifest.get("panels") {
        let Some(arr) = panels.as_array() else {
            errors.push("panels must be an array".into());
            return finish(errors);
        };
        for (i, p) in arr.iter().enumerate() {
            let ptype = p.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ptype.is_empty() {
                errors.push(format!("panels[{i}] missing type"));
            } else if !PANEL_TYPES.contains(&ptype) {
                errors.push(format!(
                    "panels[{i}] unknown type {ptype:?} (allowed: {})",
                    PANEL_TYPES.join(", ")
                ));
            }
        }
    }
    finish(errors)
}

fn finish(errors: Vec<String>) -> Result<(), Vec<String>> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_missing_title() {
        let m = json!({ "schema": "operator_surface.v1" });
        assert!(lint_operator_surface(&m).is_err());
    }

    #[test]
    fn accepts_minimal_manifest() {
        let m = json!({
            "schema": "operator_surface.v1",
            "display": { "title": "Test" },
            "accounting": { "mode": "action" },
            "institutions": [],
            "actions": [],
            "panels": []
        });
        assert!(lint_operator_surface(&m).is_ok());
    }

    #[test]
    fn rejects_bad_accounting_mode() {
        let m = json!({
            "schema": "operator_surface.v1",
            "display": { "title": "Test" },
            "accounting": { "mode": "hybrid" },
        });
        assert!(lint_operator_surface(&m).is_err());
    }
}
