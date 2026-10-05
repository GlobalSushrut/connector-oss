//! Durable product task. Applies the model, contract, and one narrow grant.
//! It does not admit and it does not execute an effect.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::agent_principal::{self, ContractPatchV2};
use crate::kernel::world_gateway::{put_grant, WorldGrantV1};
use crate::state::SharedState;

pub const JOB_FOLDER: &str = "connector_product_task_v1";
pub const JOB_SCHEMA: &str = "connector.product_task.v1";

#[derive(Debug, Deserialize)]
pub struct ProductTaskBody {
    pub pid: String,
    pub model: String,
    pub purpose: String,
    pub surface: String,
    #[serde(default)]
    pub surface_kind: String,
    pub contract: ContractPatchV2,
}

pub fn confirmed_model(stored: Option<&str>, requested: &str) -> Option<String> {
    let stored = stored.filter(|value| !value.is_empty())?;
    if stored == requested.trim() && !requested.trim().is_empty() {
        Some(stored.to_string())
    } else {
        None
    }
}

pub fn narrow_surface_grant(pid: &str, surface: &str, purpose: &str, kind: &str) -> WorldGrantV1 {
    let address_type = match kind {
        "sandbox" => "openshell",
        "dedicated" => "microcell",
        _ => "filesystem",
    };
    WorldGrantV1 {
        agent_pid: pid.to_string(),
        address: surface.to_string(),
        address_type: address_type.into(),
        access: vec!["read".into()],
        effect: "ask".into(),
        layer: "cone".into(),
        app_allow: vec![],
        cone_ask: vec!["write".into()],
        justification: Some(purpose.to_string()),
        params: json!({"purpose": purpose, "surface_kind": kind}),
        note: Some("product-task-surface".into()),
    }
}

/// POST /api/v1/product/tasks
pub async fn post_product_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ProductTaskBody>,
) -> Json<Value> {
    if let Err(mut error) = crate::services::intelligence_authority::require_lifecycle_actor(&headers, 3) {
        if let Some(obj) = error.as_object_mut() {
            obj.insert("executed".into(), json!(false));
        }
        return Json(error);
    }
    let purpose = body.purpose.trim();
    if purpose.is_empty()
        || purpose.eq_ignore_ascii_case("general-purpose")
        || purpose.eq_ignore_ascii_case("general_purpose")
        || purpose.eq_ignore_ascii_case("GENERAL_PURPOSE")
    {
        return Json(json!({"ok": false, "error": "specific_purpose_required", "executed": false}));
    }
    if body.pid.trim().is_empty() || body.model.trim().is_empty() || body.purpose.trim().is_empty() {
        return Json(json!({"ok": false, "error": "task_fields_required", "executed": false}));
    }
    if let Err(error) = agent_principal::set_model_ref(state.as_ref(), &body.pid, body.model.trim()) {
        return Json(json!({"ok": false, "error": error, "executed": false}));
    }
    let stored = agent_principal::load_principal(state.as_ref(), &body.pid)
        .and_then(|principal| principal.model_ref);
    let Some(model) = confirmed_model(stored.as_deref(), &body.model) else {
        return Json(json!({"ok": false, "error": "model_not_confirmed", "executed": false}));
    };
    let updated = match agent_principal::update_contract(state.as_ref(), &body.pid, body.contract) {
        Ok(updated) => updated,
        Err(error) => return Json(json!({"ok": false, "error": error, "model": model, "executed": false})),
    };
    let purpose_bound = updated.contract.purpose.iter().any(|item| item == &body.purpose);
    if !purpose_bound {
        return Json(json!({
            "ok": false,
            "error": "purpose_not_on_contract",
            "model": model,
            "executed": false,
        }));
    }
    let grant = narrow_surface_grant(&body.pid, &body.surface, &body.purpose, &body.surface_kind);
    if let Err(error) = put_grant(state.as_ref(), &grant) {
        return Json(json!({"ok": false, "error": error, "model": model, "executed": false}));
    }
    let job = json!({
        "schema": JOB_SCHEMA,
        "ok": true,
        "pid": body.pid,
        "model": model,
        "purpose": body.purpose,
        "surface": body.surface,
        "contract_digest": updated.contract.contract_digest_sha256,
        "grant": {
            "address": grant.address,
            "effect": grant.effect,
            "layer": grant.layer,
        },
        "stage": "configured",
        "executed": false,
        "admits": false,
    });
    if let Ok(mut store) = state.engine_store.lock() {
        let _ = store.folder_put(JOB_FOLDER, &body.pid, &job);
    }
    Json(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_is_confirmed_only_when_the_stored_ref_matches() {
        assert_eq!(confirmed_model(Some("gpt"), "gpt").as_deref(), Some("gpt"));
        assert!(confirmed_model(Some("other"), "gpt").is_none());
        assert!(confirmed_model(None, "gpt").is_none());
        assert!(confirmed_model(Some("gpt"), "  ").is_none());
    }

    #[test]
    fn surface_grant_asks_and_does_not_allow() {
        let grant = narrow_surface_grant("agent-1", "/srv/app", "rotate one credential", "workspace");
        assert_eq!(grant.effect, "ask");
        assert_eq!(grant.address, "/srv/app");
        assert!(grant.app_allow.is_empty());
        assert_eq!(grant.access, vec!["read".to_string()]);
    }
}
