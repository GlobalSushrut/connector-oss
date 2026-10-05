//! HTTP API — RangeGuard / CRK window, commit, replay.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;
use crate::substrate::crk::{self, context_frame, procedure_capsule, recall_session, transfer};
use crate::substrate::llm_context_broker;

#[derive(Debug, Deserialize)]
pub struct WindowBody {
    pub agent_pid: String,
    pub action_digest: String,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub bound_skill: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub token_budget: Option<u64>,
    #[serde(default)]
    pub max_range_cover: Option<u32>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// POST /api/v1/range/window
pub async fn post_window(
    State(state): State<SharedState>,
    Json(body): Json<WindowBody>,
) -> Json<Value> {
    let generation = llm_context_broker::current_generation(&state, &body.agent_pid);
    let cue = crk::cue_from(
        &body.agent_pid,
        generation,
        body.bound_skill.as_deref(),
        body.phase.as_deref().unwrap_or("recall"),
        &body.action_digest,
        body.risk.as_deref().unwrap_or("low"),
        body.token_budget.unwrap_or(2048),
        body.max_range_cover.unwrap_or(8),
    );

    let mut session = recall_session::begin(state.as_ref(), &cue);

    match crk::window(&state, &cue) {
        Ok((range, manifest, crk_state)) => {
            recall_session::record_round(
                &mut session,
                range.context_cids.clone(),
                manifest.excluded_conflicts.clone(),
            );
            let procedure = range
                .procedure_id
                .as_ref()
                .and_then(|id| procedure_capsule::load(state.as_ref(), &body.agent_pid, id));
            let mut frames =
                context_frame::from_moment_range(state.as_ref(), &range, procedure.as_ref());
            context_frame::fit_budget(&mut frames, cue.token_budget);
            let render = transfer::render_frames(&frames);
            let _ = recall_session::assert_pinned_root(state.as_ref(), &session);
            let xfer = transfer::mint(
                state.as_ref(),
                body.tenant_id.as_deref().unwrap_or("default"),
                &body.agent_pid,
                generation,
                generation,
                &session.pinned_memory_root,
                session.pinned_read_set_epoch,
                &range,
                &manifest,
                &frames,
                &render,
                None,
                None,
                cue.token_budget,
            );
            if let Ok(ref env) = xfer {
                llm_context_broker::attach_transfer(
                    &state,
                    &body.agent_pid,
                    &env.transfer_id,
                    &env.exact_render_digest,
                    &env.transfer_digest(),
                );
            }

            Json(operator_envelope(json!({
                "ok": true,
                "state": crk_state.as_str(),
                "moment_range": range,
                "influence_manifest": manifest,
                "procedure": procedure,
                "frames": frames,
                "transfer": xfer.ok(),
                "recall_session": session,
                "honesty": "CRK never authorizes — PATE still Allow/Deny",
            })))
        }
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "crk_window_failed",
            "message": e,
        }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct ObserveBody {
    pub agent_pid: String,
    pub subject: String,
    pub predicate: String,
    pub value: Value,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub trust: Option<String>,
    #[serde(default)]
    pub evidence_cids: Vec<String>,
    #[serde(default)]
    pub supersedes: Option<String>,
}

/// POST /api/v1/range/observe — write untrusted→bound observation as StateClaim.
pub async fn post_observe(
    State(state): State<SharedState>,
    Json(body): Json<ObserveBody>,
) -> Json<Value> {
    let trust = match body.trust.as_deref().unwrap_or("t1") {
        "t0" | "T0" | "external" => connector_trust::TrustTier::T0External,
        "t2" | "T2" => connector_trust::TrustTier::T2SourceBound,
        "t3" | "T3" => connector_trust::TrustTier::T3EnvVerified,
        "t4" | "T4" => connector_trust::TrustTier::T4OperatorVerified,
        _ => connector_trust::TrustTier::T1Observed,
    };
    let claim_id = format!(
        "claim_{}",
        &crk::digest_hex(
            format!(
                "{}|{}|{}|{}",
                body.agent_pid, body.subject, body.predicate, body.value
            )
            .as_bytes()
        )[..16]
    );
    match crk::temporal_ledger::put_claim(
        state.as_ref(),
        &body.agent_pid,
        &claim_id,
        &body.subject,
        &body.predicate,
        body.value,
        body.source.as_deref().unwrap_or("observe"),
        trust,
        body.evidence_cids,
        body.supersedes.as_deref(),
        0.8,
    ) {
        Ok(claim) => {
            let mc = crk::memory_commit::commit(
                state.as_ref(),
                &body.agent_pid,
                vec![claim.claim_id.clone()],
                vec![claim.envelope.cid.clone()],
                vec![claim.claim_id.clone()],
                vec![],
                vec![format!(
                    "current/{}/{}/{}",
                    body.agent_pid, body.subject, body.predicate
                )],
                None,
                &claim.envelope.lineage_digest,
            );
            if let Ok(ref commit) = mc {
                let data = serde_json::to_vec(&claim.value).unwrap_or_default();
                let dna = crk::sequence_dna::mint_node_dna(
                    &body.agent_pid,
                    connector_trust::MemoryDnaType::State,
                    &claim.claim_id,
                    &data,
                    "",
                    &format!("by_subject:{}:{}", body.subject, body.predicate),
                    &commit.resulting_root,
                );
                let _ = crk::node_index::put_node(
                    state.as_ref(),
                    &crk::node_index::IndexedNode {
                        dna,
                        trust_rank: claim.envelope.origin_authority.rank(),
                        active: claim.active,
                        skill_scope: claim.envelope.skill_scope.clone(),
                        subject: Some(claim.subject.clone()),
                        predicate: Some(claim.predicate.clone()),
                        updated_at_ms: claim.observed_at_ms,
                    },
                );
            }
            Json(operator_envelope(json!({ "ok": true, "claim": claim })))
        }
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "observe_failed",
            "message": e,
        }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct CommitProcedureBody {
    pub agent_pid: String,
    pub procedure_id: String,
    pub skill_id: String,
    pub procedure_version: String,
    pub steps: Vec<connector_trust::ProcedureStep>,
    #[serde(default)]
    pub provenance: Option<String>,
}

/// POST /api/v1/range/commit — commit a verified procedure capsule.
pub async fn post_commit_procedure(
    State(state): State<SharedState>,
    Json(body): Json<CommitProcedureBody>,
) -> Json<Value> {
    match procedure_capsule::put(
        state.as_ref(),
        &body.agent_pid,
        &body.procedure_id,
        &body.skill_id,
        &body.procedure_version,
        body.steps,
        body.provenance.as_deref().unwrap_or("operator"),
        connector_trust::TrustTier::T4OperatorVerified,
    ) {
        Ok(cap) => Json(operator_envelope(json!({ "ok": true, "procedure": cap }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "commit_procedure_failed",
            "message": e,
        }))),
    }
}

/// GET /api/v1/range/replay/:manifest_id
pub async fn get_replay(
    State(state): State<SharedState>,
    Path(manifest_id): Path<String>,
) -> Json<Value> {
    match crk::influence::load(state.as_ref(), &manifest_id) {
        Some(m) => {
            let range = crk::moment_range::load(state.as_ref(), &m.moment_range_id);
            Json(operator_envelope(json!({
                "ok": true,
                "manifest": m,
                "moment_range": range,
            })))
        }
        None => Json(operator_envelope(json!({
            "ok": false,
            "error": "manifest_not_found",
            "manifest_id": manifest_id,
        }))),
    }
}

/// GET /api/v1/range/status
pub async fn get_status() -> Json<Value> {
    Json(operator_envelope(crk::status()))
}

/// POST /api/v1/range/rollup — continuity rollup (state + procedures, not summaries).
pub async fn post_rollup(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Map<String, Value>>,
) -> Json<Value> {
    let agent_pid = body
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if agent_pid.is_empty() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "agent_pid_required",
        })));
    }
    match crk::continuity_rollup::commit_rollup(state.as_ref(), &agent_pid) {
        Ok(r) => Json(operator_envelope(json!({ "ok": true, "rollup": r }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "rollup_failed",
            "message": e,
        }))),
    }
}

/// POST /api/v1/range/demo/rangeguard — poison/stale/state-update acceptance.
pub async fn post_demo_rangeguard(State(state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(crk::demo::run(&state)))
}

#[derive(Debug, Deserialize)]
pub struct RelateBody {
    pub agent_pid: String,
    pub from_cid: String,
    pub to_cid: String,
    pub kind: String,
    pub from_type: String,
    pub to_type: String,
    #[serde(default)]
    pub weight: Option<f64>,
    #[serde(default)]
    pub provenance: Option<String>,
}

/// POST /api/v1/range/relate — typed MemoryRelation edge.
pub async fn post_relate(
    State(state): State<SharedState>,
    Json(body): Json<RelateBody>,
) -> Json<Value> {
    let kind = match crk::relations::parse_kind(&body.kind) {
        Some(k) => k,
        None => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": "invalid_relation_kind",
            })));
        }
    };
    let from_type = match crk::relations::parse_type(&body.from_type) {
        Some(t) => t,
        None => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": "invalid_from_type",
            })));
        }
    };
    let to_type = match crk::relations::parse_type(&body.to_type) {
        Some(t) => t,
        None => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": "invalid_to_type",
            })));
        }
    };
    match crk::relations::put_relation(
        state.as_ref(),
        &body.agent_pid,
        &body.from_cid,
        &body.to_cid,
        kind,
        from_type,
        to_type,
        body.weight.unwrap_or(1.0),
        body.provenance.as_deref().unwrap_or("operator"),
    ) {
        Ok(rel) => Json(operator_envelope(json!({ "ok": true, "relation": rel }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "relate_failed",
            "message": e,
        }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchBody {
    pub agent_pid: String,
    pub action_digest: String,
    #[serde(default)]
    pub bound_skill: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub page_size: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// POST /api/v1/range/search — paginated DNA field under pin (cold path).
pub async fn post_search(
    State(state): State<SharedState>,
    Json(body): Json<SearchBody>,
) -> Json<Value> {
    match crk::search::search(
        &state,
        &body.agent_pid,
        &body.action_digest,
        body.bound_skill.as_deref(),
        body.risk.as_deref().unwrap_or("low"),
        body.page_size.unwrap_or(16),
        body.cursor.as_deref(),
        body.session_id.as_deref(),
    ) {
        Ok(page) => Json(operator_envelope(json!({
            "ok": true,
            "session_id": page.session_id,
            "pinned_memory_root": page.pinned_memory_root,
            "page": page.page,
            "next_cursor": page.next_cursor,
            "round": page.round,
            "honesty": "Cold browse — does not Admit; feed window for exposure",
        }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": "search_failed",
            "message": e,
        }))),
    }
}
