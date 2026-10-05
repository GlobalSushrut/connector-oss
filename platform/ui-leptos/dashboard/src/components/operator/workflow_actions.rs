//! Workflow lifecycle helpers — DRAFT cannot jump straight to ENABLED/PAUSED.
//! Valid path: DRAFT → COMPILED → STAGED → ENABLED ⇄ PAUSED → ARCHIVED

use serde_json::{json, Value};

use crate::api::{self, ApiError};

/// Walk the state machine toward ENABLED (compile → stage → enable as needed).
pub async fn activate_workflow(workflow_id: &str) -> Result<String, String> {
    let current = current_state(workflow_id).await?;
    let steps: &[&str] = match current.as_str() {
        "DRAFT" => &["COMPILED", "STAGED", "ENABLED"],
        "COMPILED" => &["STAGED", "ENABLED"],
        "STAGED" => &["ENABLED"],
        "PAUSED" => &["ENABLED"],
        "ENABLED" => return Ok("Already ENABLED.".into()),
        "ARCHIVED" => {
            return Err("Archived workflows cannot be enabled — install a fresh copy.".into())
        }
        other => {
            return Err(format!(
                "Cannot enable from state {other}. Expected DRAFT/COMPILED/STAGED/PAUSED."
            ))
        }
    };
    let mut log = format!("from {current}");
    for state in steps {
        transition(workflow_id, state).await?;
        log.push_str(&format!(" → {state}"));
    }
    Ok(format!("Activated → ENABLED ({log})."))
}

pub async fn pause_workflow(workflow_id: &str) -> Result<String, String> {
    let current = current_state(workflow_id).await?;
    if current == "PAUSED" {
        return Ok("Already PAUSED.".into());
    }
    if current != "ENABLED" {
        return Err(format!(
            "Pause only works when ENABLED (current: {current}). Use Activate first."
        ));
    }
    transition(workflow_id, "PAUSED").await?;
    Ok("Lifecycle → PAUSED".into())
}

pub async fn archive_workflow(workflow_id: &str) -> Result<String, String> {
    let current = current_state(workflow_id).await?;
    if current == "ARCHIVED" {
        return Ok("Already ARCHIVED.".into());
    }
    transition(workflow_id, "ARCHIVED").await?;
    Ok("Lifecycle → ARCHIVED".into())
}

pub async fn current_state(workflow_id: &str) -> Result<String, String> {
    let v = api::get_value(&format!("/workflows/{workflow_id}"))
        .await
        .map_err(|e: ApiError| e.message)?;
    let state = v
        .pointer("/workflow/state")
        .or_else(|| v.get("state"))
        .and_then(|x| x.as_str())
        .unwrap_or("DRAFT")
        .to_ascii_uppercase();
    Ok(state)
}

/// Run one surface-declared action against the real API.
pub async fn run_surface_action(workflow_id: &str, action: &Value) -> Result<String, String> {
    let id = action
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("action");
    let method = action
        .get("method")
        .and_then(|x| x.as_str())
        .unwrap_or("POST")
        .to_ascii_uppercase();
    let path_tmpl = action
        .get("path")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("Action `{id}` has no path"))?;
    let path = path_tmpl.replace("{workflow_id}", workflow_id);

    // Prefer client_chain (Activate) over a single invalid ENABLED jump from DRAFT.
    if let Some(chain) = action.get("client_chain").and_then(|x| x.as_array()) {
        let steps: Vec<String> = chain
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_ascii_uppercase()))
            .collect();
        if !steps.is_empty() {
            let current = current_state(workflow_id).await?;
            let mut started = false;
            let mut log = format!("from {current}");
            for step in &steps {
                if !started {
                    if current == *step || already_past(&current, step) {
                        continue;
                    }
                    started = true;
                }
                transition(workflow_id, step).await?;
                log.push_str(&format!(" → {step}"));
            }
            if !started && current == "ENABLED" {
                return Ok("Already ENABLED.".into());
            }
            return Ok(format!(
                "Action `{id}` ok ({log}).\nAPI: POST {path} (chained)"
            ));
        }
    }

    if id == "activate" || (id == "enable" && current_state(workflow_id).await? == "DRAFT") {
        let msg = activate_workflow(workflow_id).await?;
        return Ok(format!("{msg}\nAPI: POST {path} (chained)"));
    }

    let body = action.get("body").cloned().unwrap_or(json!({}));
    let v = match method.as_str() {
        "GET" => api::get_value(&path).await.map_err(|e| e.message)?,
        _ => api::post_value(&path, body.clone())
            .await
            .map_err(|e| e.message)?,
    };
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("Action failed");
        return Err(format!("{err}\nAPI: {method} {path}"));
    }
    let state = v
        .pointer("/workflow/state")
        .and_then(|x| x.as_str())
        .unwrap_or("ok");
    Ok(format!(
        "Action `{id}` → {state}\nAPI: {method} {path}\nbody: {body}"
    ))
}

fn already_past(current: &str, step: &str) -> bool {
    const ORDER: &[&str] = &["DRAFT", "COMPILED", "STAGED", "ENABLED"];
    let ci = ORDER.iter().position(|s| *s == current);
    let si = ORDER.iter().position(|s| *s == step);
    match (ci, si) {
        (Some(c), Some(s)) => c > s,
        _ => false,
    }
}

async fn transition(workflow_id: &str, state: &str) -> Result<String, String> {
    let v = api::post_value(
        &format!("/workflows/{workflow_id}/lifecycle"),
        json!({ "state": state }),
    )
    .await
    .map_err(|e: ApiError| e.message)?;
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("Lifecycle transition failed");
        let detail = v
            .pointer("/cls_compile/error/message")
            .or_else(|| v.pointer("/cls_compile/error"))
            .map(|x| match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        if detail.is_empty() {
            return Err(err.to_string());
        }
        return Err(format!("{err}: {detail}"));
    }
    Ok(state.to_string())
}
