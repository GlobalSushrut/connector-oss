//! HTTP API — SVF posture, objects, EXPAND, grants, tool stubs.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use connector_trust::DisclosureLevel;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;

use super::{
    derived, expand, fade_bind, graph, grants, materialize_flow, posture_json, resolve,
    semanticize, store, svf_enabled, tool_stubs,
};

/// GET /api/v1/svf/posture
pub async fn get_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.svf.api.posture.v1",
        "svf": posture_json(),
        "docs": "platform/docs/arch/CONNECTOR_SVF.md",
    })))
}

/// GET /api/v1/svf/objects/:agent_vid
pub async fn get_objects(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    if !svf_enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "svf_disabled",
            "hint": "Set CONNECTOR_SVF=1",
        })));
    }
    let n = semanticize::semanticize_agent(&state, &agent_vid);
    let objects = store::list_objects(&state, &agent_vid);
    Json(operator_envelope(json!({
        "schema": "connector.svf.api.objects.v1",
        "agent_vid": agent_vid,
        "semanticized": n,
        "count": objects.len(),
        "objects": objects,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ExpandBody {
    pub agent_vid: String,
    pub object_id: String,
    pub level: String,
    #[serde(default)]
    pub purpose: String,
}

/// POST /api/v1/svf/expand
pub async fn post_expand(
    State(state): State<SharedState>,
    Json(body): Json<ExpandBody>,
) -> Json<Value> {
    let Some(level) = DisclosureLevel::parse(&body.level) else {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "invalid_disclosure_level",
            "level": body.level,
            "hint": "S0..S5 or s0_stub..s5_materialize",
        })));
    };
    let req = expand::ExpandRequest {
        agent_vid: body.agent_vid,
        object_id: body.object_id,
        level,
        purpose: body.purpose,
    };
    let result = expand::expand(&state, &req);
    Json(operator_envelope(expand::expand_result_json(&result)))
}

#[derive(Debug, Deserialize)]
pub struct GrantBody {
    pub agent_vid: String,
    pub object_id: String,
    pub max_level: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub ttl_ms: Option<i64>,
}

/// POST /api/v1/svf/grants — operator mint (HITL path can call this after Ask)
pub async fn post_grant(
    State(state): State<SharedState>,
    Json(body): Json<GrantBody>,
) -> Json<Value> {
    if !svf_enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "svf_disabled",
        })));
    }
    if grants::grants_frozen(&state, &body.agent_vid) {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "quarantine_freezes_cdp",
            "decision": "quarantine",
        })));
    }
    let Some(max_level) = DisclosureLevel::parse(&body.max_level) else {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "invalid_disclosure_level",
        })));
    };
    if max_level.model_plane_forbidden() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "s5_cdp_only",
            "honesty": "Do not mint S5 model-plane grants — use CDP materialize post-Admit",
        })));
    }
    let grant = grants::mint_grant(
        &state,
        &body.agent_vid,
        &body.object_id,
        max_level,
        &body.purpose,
        body.ttl_ms.or(Some(3_600_000)),
    );
    Json(operator_envelope(json!({
        "ok": true,
        "grant": grant,
    })))
}

/// GET /api/v1/svf/grants/:agent_vid
pub async fn get_grants(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.svf.api.grants.v1",
        "agent_vid": agent_vid,
        "frozen": grants::grants_frozen(&state, &agent_vid),
        "grants": grants::list_grants(&state, &agent_vid),
    })))
}

#[derive(Debug, Deserialize)]
pub struct StubQuery {
    #[serde(default = "default_stub_level")]
    pub level: String,
}

fn default_stub_level() -> String {
    "s0".into()
}

/// GET /api/v1/svf/tools/stubs/:agent_vid?level=s0|s1|s2
pub async fn get_tool_stubs(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
    Query(q): Query<StubQuery>,
) -> Json<Value> {
    let level = DisclosureLevel::parse(&q.level).unwrap_or(DisclosureLevel::S0Stub);
    Json(operator_envelope(tool_stubs::tool_stubs(
        &state, &agent_vid, level,
    )))
}

#[derive(Debug, Deserialize)]
pub struct ResolveBody {
    pub agent_vid: String,
    pub handle: String,
    #[serde(default)]
    pub purpose: String,
}

/// POST /api/v1/svf/resolve
pub async fn post_resolve(
    State(state): State<SharedState>,
    Json(body): Json<ResolveBody>,
) -> Json<Value> {
    Json(operator_envelope(resolve::resolve_json(
        &state,
        &body.agent_vid,
        &body.handle,
        &body.purpose,
    )))
}

#[derive(Debug, Deserialize)]
pub struct MaterializeBody {
    pub agent_vid: String,
    pub bridge_id: String,
    pub tool_name: String,
    pub handle: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub args: Value,
}

/// POST /api/v1/svf/materialize — Admit + lease + RESOLVE + CDP (no world effect).
pub async fn post_materialize(
    State(state): State<SharedState>,
    Json(body): Json<MaterializeBody>,
) -> Json<Value> {
    match materialize_flow::admit_resolve_materialize(
        &state,
        &body.agent_vid,
        &body.bridge_id,
        &body.tool_name,
        &body.handle,
        &body.purpose,
        &body.args,
    ) {
        Ok(v) => Json(operator_envelope(v)),
        Err(e) => Json(operator_envelope(e)),
    }
}

#[derive(Debug, Deserialize)]
pub struct RelationBody {
    pub agent_vid: String,
    pub from: String,
    pub to: String,
    #[serde(default = "default_relation")]
    pub relation: String,
    #[serde(default)]
    pub mirror_knot: bool,
}

fn default_relation() -> String {
    "relates".into()
}

/// POST /api/v1/svf/relations
pub async fn post_relation(
    State(state): State<SharedState>,
    Json(body): Json<RelationBody>,
) -> Json<Value> {
    Json(operator_envelope(graph::relate_objects(
        &state,
        &body.agent_vid,
        &body.from,
        &body.to,
        &body.relation,
        body.mirror_knot,
    )))
}

/// GET /api/v1/svf/relations/:agent_vid/:object_id
pub async fn get_relations(
    State(state): State<SharedState>,
    Path((agent_vid, object_id)): Path<(String, String)>,
) -> Json<Value> {
    Json(operator_envelope(graph::list_related(
        &state, &agent_vid, &object_id,
    )))
}

#[derive(Debug, Deserialize)]
pub struct DerivedBody {
    pub agent_vid: String,
    pub claim: String,
    #[serde(default)]
    pub source_object_ids: Vec<String>,
}

/// POST /api/v1/svf/derived
pub async fn post_derived(
    State(state): State<SharedState>,
    Json(body): Json<DerivedBody>,
) -> Json<Value> {
    match derived::record_derived(
        &state,
        &body.agent_vid,
        &body.source_object_ids,
        &body.claim,
    ) {
        Ok(v) => Json(operator_envelope(v)),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": e,
        }))),
    }
}

/// GET /api/v1/svf/derived/:agent_vid
pub async fn get_derived(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(derived::list_derived(&state, &agent_vid)))
}

/// POST /api/v1/svf/fade/sync/:agent_vid
pub async fn post_fade_sync(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(fade_bind::sync_agent_fade(
        &state, &agent_vid,
    )))
}

/// GET /api/v1/svf/receipts/:agent_vid — disclosure + effect receipts (forensics)
pub async fn get_receipts(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    if !svf_enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "svf_disabled",
            "hint": "Set CONNECTOR_SVF=1",
        })));
    }
    let disclosure = store::list_receipts(&state, &agent_vid);
    let effects = store::list_effect_receipts(&state, &agent_vid);
    Json(operator_envelope(json!({
        "schema": "connector.svf.api.receipts.v1",
        "agent_vid": agent_vid,
        "honesty": "disclosure receipts (EXPAND) ≠ effect receipts (CDP materialize)",
        "disclosure_count": disclosure.len(),
        "effect_count": effects.len(),
        "disclosure_receipts": disclosure,
        "effect_receipts": effects,
    })))
}
