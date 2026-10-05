//! Workbench orchestrator HTTP — Connector product façade for Talk + tools.
//!
//! Turn = governed Talk + Principal Projection + pending orders (no ToolDispatch).
//! Admit = identity stack → DAL → PATE → Connector `tools::dispatch_mcp_tool` → continue Talk.
//!
//! Lower-level `/agents/:pid/completions` and `/dal/*` remain for gateway/IDE clients.
//! Operators and the Workbench UI use this session API only.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::agent_principal;
use crate::kernel::workbench_session::{self, WorkbenchPhase, WorkbenchSession};
use crate::operator::honesty::operator_envelope;
use crate::services::admission::AdmissionOp;
use crate::services::agents::caller;
use crate::services::gateway::{self, ChatCompletionRequest, ChatMessage};
use crate::state::SharedState;
use crate::substrate::dynamic_agent_loop;
use crate::substrate::identity_stack;
use crate::substrate::intelligence_binding;

fn auth_operator_or_agent_self(headers: &HeaderMap, agent_pid: &str) -> bool {
    caller(headers).is_some()
        || crate::kernel::agent_identity_envelope::agent_self_access(headers, agent_pid)
}

fn deny(msg: &str) -> Json<Value> {
    Json(operator_envelope(json!({ "ok": false, "error": msg })))
}

fn require_principal(state: &SharedState, pid: &str) -> bool {
    agent_principal::load_principal(state.as_ref(), pid).is_some()
}

/// Connector vitals for the duty strip — honest lab vs court, never greenwashed.
fn vitals_for(state: &SharedState, session: &WorkbenchSession) -> Value {
    let pid = &session.agent_pid;
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(state, pid);
        crate::services::agents::ensure_playground_admit_lane(state, pid);
    }
    let binding = intelligence_binding::status(state.as_ref(), pid);
    let lab = crate::services::settings_llms::get_lab_mode_body();
    let lab_mode = lab.get("lab_mode").and_then(|x| x.as_bool()).unwrap_or(true);
    let stack = identity_stack::inspect(
        state,
        pid,
        "default",
        &AdmissionOp::ToolDispatch {
            tool_id: "workbench.admit".into(),
        },
    );
    let hitl_n = crate::services::agents::hitl_pending_count(pid);
    let hitl_items: Vec<Value> = crate::services::agents::hitl_store_snapshot()
        .into_values()
        .filter(|r| r.agent_pid == *pid && r.status == "pending")
        .take(12)
        .map(|r| {
            json!({
                "request_id": r.request_id,
                "action": r.action,
                "description": r.description,
                "created_at": r.created_at,
            })
        })
        .collect();

    let signing_tier = if lab_mode {
        "hmac_lab"
    } else {
        "production_candidate"
    };
    let court_claim = "never — SOAS/court only when CD checklist green; lab HMAC is not court";
    let posture = posture_summaries(state, session);

    json!({
        "schema": "connector.workbench.vitals.v1",
        "agent_pid": pid,
        "who": stack.character_name.clone().unwrap_or_default(),
        "purpose": stack.character_purpose.clone().unwrap_or_default(),
        "binding": binding,
        "lab_mode": lab_mode,
        "signing_tier_honesty": signing_tier,
        "court_claim": court_claim,
        "identity_stack": {
            "missing": stack.missing,
            "complete": stack.missing.is_empty(),
            "enforced": identity_stack::identity_stack_enforce_enabled(),
        },
        "hitl_pending_count": hitl_n,
        "hitl_pending": hitl_items,
        "last_projection_outcome": session.last_projection_outcome(),
        "phase": session.phase,
        "pending_order_count": session.pending_order_ids.len(),
        "held_order_count": session.held_order_ids.len(),
        "hitl_request_id": session.hitl_request_id,
        "dal_run_id": session.dal_run_id,
        "mission": posture.get("mission").cloned().unwrap_or(Value::Null),
        "dal": posture.get("dal").cloned().unwrap_or(Value::Null),
        "context": posture.get("context").cloned().unwrap_or(Value::Null),
        "budget": posture.get("budget").cloned().unwrap_or(Value::Null),
        "progeny": posture.get("progeny").cloned().unwrap_or(Value::Null),
        "capabilities": capability_summary(state),
        "demo_receipts": crate::services::playground_demo::list_demo_receipts(state, pid),
        "demo_receipts_honesty": "Prove / Isolate / Govern write playground_demo_receipts on this node. WitnessCtl sidecar ingest is not this path. Issuer HMAC is not court-grade.",
        "links": {
            "budget": format!("/economy/budget-gate/{pid}"),
            "context": format!("/context/{pid}/pressure"),
            "fix": "/fix",
            "capabilities": "/operator/capabilities",
            "proof": format!("/proof/export/{pid}"),
            "progeny": format!("/agents/{pid}/progeny"),
            "charter": format!("/agents/{pid}/charter"),
        },
        "honesty": "Vitals are measured. Lab nodes must not be presented as court-defensible. Absent capabilities are not shown as product tabs.",
    })
}

/// Inexpensive summaries from existing subsystems — no full payload aggregation.
fn posture_summaries(state: &SharedState, session: &WorkbenchSession) -> Value {
    let pid = &session.agent_pid;

    let dal = session
        .dal_run_id
        .as_ref()
        .and_then(|rid| dynamic_agent_loop::load(state.as_ref(), rid).ok().flatten())
        .map(|r| {
            json!({
                "run_id": r.run_id,
                "mission_id": r.mission_id,
                "phase": r.phase,
                "stop_reason": r.stop_reason,
                "budgets": r.budgets,
                "broker_epoch": r.broker_epoch,
            })
        })
        .unwrap_or(Value::Null);

    let mission = dal
        .get("mission_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|mid| {
            json!({
                "mission_id": mid,
                "dal_run_id": session.dal_run_id,
                "dal_phase": dal.get("phase"),
                "link": format!("/missions/{mid}"),
            })
        })
        .unwrap_or(json!({
            "mission_id": null,
            "dal_run_id": session.dal_run_id,
            "note": "No DAL mission bound until first Admit creates a run",
        }));

    let context = {
        let cm = state.context_mgr.lock().unwrap();
        match cm.get(pid) {
            Some(ctx) => json!({
                "tracked": true,
                "pressure_pct": (ctx.pressure() * 1000.0).round() / 10.0,
                "current_tokens": ctx.context_tokens,
                "max_tokens": ctx.context_max_tokens,
            }),
            None => json!({ "tracked": false, "pressure_pct": null }),
        }
    };

    let budget = {
        let pr = state.pricer.lock().unwrap();
        match pr.get_budget(pid) {
            Some(bg) => json!({
                "configured": true,
                "max_spend": bg.max_spend,
                "spent": bg.spent,
                "remaining": bg.remaining(),
                "exceeded": bg.is_exceeded(),
            }),
            None => json!({ "configured": false }),
        }
    };

    let (kernel_pid, _) = crate::services::agents::resolve_kernel_pid_pub(state, pid);
    let progeny_doc = crate::substrate::agent_progeny::agent_progeny_detail(state, &kernel_pid);
    let direct_children = progeny_doc
        .pointer("/subtree/children")
        .and_then(|c| c.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let progeny = json!({
        "ok": progeny_doc.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
        "direct_children": direct_children,
        "kernel_pid": kernel_pid,
    });

    json!({
        "dal": dal,
        "mission": mission,
        "context": context,
        "budget": budget,
        "progeny": progeny,
    })
}

fn capability_summary(state: &SharedState) -> Value {
    use crate::operator::capability_seed::seed_capabilities;
    use crate::services::plugin_matrix;
    let mut installed = 0usize;
    let mut total = 0usize;
    let mut labels = Vec::new();
    for rec in seed_capabilities() {
        total += 1;
        let id = rec
            .get("institution_id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let ok = match id {
            "kernel" => true,
            other if plugin_matrix::KNOWN_PLUGINS.contains(&other) => {
                plugin_matrix::is_plugin_enabled(other)
                    && crate::services::plugin_lifecycle::load_plugin_lifecycle_state(state, other)
                        .installed
            }
            _ => false,
        };
        if ok {
            installed += 1;
            labels.push(id.to_string());
        }
    }
    let tools: Vec<String> = crate::services::mcp_hosting::list_tools()
        .into_iter()
        .map(|t| t.name)
        .take(32)
        .collect();
    json!({
        "institutions_installed": installed,
        "institutions_known": total,
        "institutions": labels,
        "mcp_tools": tools,
        "mcp_tool_count": crate::services::mcp_hosting::list_tools().len(),
        "devguard": labels.iter().any(|x| x == "devguard"),
        "witnessctl": labels.iter().any(|x| x == "witnessctl"),
        "unsupported_here": [
            "browser_computer_use",
            "generic_terminal_stream",
            "conversational_checkpoint_rewind"
        ],
        "browser_explore": {
            "implemented": true,
            "route": "POST /api/v1/world/browser/navigate",
            "world_type": "browser",
            "honesty": "Document GET on a granted origin, dest-pinned and recorded. Not click/type/JS computer-use.",
        },
    })
}

fn session_body(state: &SharedState, session: &WorkbenchSession) -> Value {
    json!({
        "ok": true,
        "schema": "connector.workbench.session_response.v1",
        "session": session.snapshot(),
        "events": session.events,
        "pending_orders": session.pending_order_snapshots(),
        "vitals": vitals_for(state, session),
        "honesty": "Turn never dispatches. Admit is identity-stack → DAL/PATE → Connector ToolDispatch.",
        "links": {
            "theater": format!("/run/workbench/{}", session.agent_pid),
            "fix": "/fix",
            "charter": format!("/agents/{}/charter", session.agent_pid),
            "posture": "/api/v1/workbench/posture",
        },
    })
}

fn session_err(state: &SharedState, session: &WorkbenchSession, error: &str, extra: Value) -> Value {
    let mut body = session_body(state, session);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("ok".into(), json!(false));
        obj.insert("error".into(), json!(error));
        obj.insert("dispatched".into(), json!(false));
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    body
}

/// GET /api/v1/workbench/posture — Connector substrate honesty for Workbench.
pub async fn get_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.workbench.posture.v1",
        "owns": "operator session journal + turn/admit orchestration",
        "does_not_own": "tool sandwich (stays in tools.rs via DAL agent_loop)",
        "ring1": "turn appends orders only — never ToolDispatch",
        "admit": "identity_stack inspect → DAL run_turn → PATE → tools::dispatch_mcp_tool",
        "continue": "after Allow receipts, one more governed Talk with LTL tool messages",
        "layers": [
            "governed_talk_core (Obey-Once + work unit + Principal Projection)",
            "dynamic_agent_loop (DAL)",
            "agent_loop (proposal → receipt)",
            "pate (admit)",
            "tools (Connector ToolDispatch)",
        ],
        "api": [
            "POST /agents/:pid/workbench/sessions",
            "GET /agents/:pid/workbench/sessions",
            "GET /agents/:pid/workbench/sessions/:sid",
            "POST /agents/:pid/workbench/sessions/:sid/turn",
            "POST /agents/:pid/workbench/sessions/:sid/admit",
            "POST /agents/:pid/workbench/sessions/:sid/demo",
            "POST /agents/:pid/workbench/sessions/:sid/cancel-orders",
            "POST /agents/:pid/workbench/sessions/:sid/hitl-resume",
            "POST /agents/:pid/workbench/sessions/:sid/hitl-deny",
        ],
        "universal_claim": "Workbench composes registered Connector capabilities for any principal — it does not invent unsupported worlds (browser, IDE, terminal stream).",
        "docs": "platform/docs/arch/LLM_WORKBENCH.md",
    })))
}

/// POST /api/v1/agents/:pid/workbench/sessions
#[derive(Debug, Deserialize)]
pub struct CreateBody {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub goal: Option<String>,
}

pub async fn post_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<CreateBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    if !require_principal(&state, &pid) {
        return deny("unknown_principal");
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "workbench",
        "create_workbench_session",
        &json!({"agent_pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match workbench_session::create_session(
        state.as_ref(),
        &pid,
        body.title.as_deref(),
        body.goal.as_deref(),
    ) {
        Ok(s) => {
            open_proceed.finish_observed(true);
            let mut body = session_body(&state, &s);
            if let Some(obj) = body.as_object_mut() {
                obj.insert("task_id".into(), json!(admitted.task_id));
                obj.insert("executed".into(), json!(true));
                obj.insert("admits".into(), json!(false));
            }
            Json(operator_envelope(body))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            deny(&e)
        }
    }
}

/// GET /api/v1/agents/:pid/workbench/sessions
pub async fn list_sessions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    let sessions = workbench_session::list_sessions(state.as_ref(), &pid);
    Json(operator_envelope(json!({
        "ok": true,
        "agent_pid": pid,
        "sessions": sessions,
        "count": sessions.len(),
        "links": { "theater": format!("/run/workbench/{pid}"), "posture": "/api/v1/workbench/posture" },
    })))
}

/// GET /api/v1/agents/:pid/workbench/sessions/:sid
pub async fn get_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => Json(operator_envelope(session_body(&state, &s))),
        Ok(None) => deny("session_not_found"),
        Err(e) => deny(&e),
    }
}

#[derive(Debug, Deserialize)]
pub struct TurnBody {
    pub message: String,
    #[serde(default)]
    pub model: Option<String>,
}

/// POST .../sessions/:sid/turn — consult. Never ToolDispatch.
pub async fn post_turn(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<TurnBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    if !require_principal(&state, &pid) {
        return deny("unknown_principal");
    }
    let text = body.message.trim().to_string();
    if text.is_empty() {
        return deny("message_required");
    }

    let _session_lease = match state.session_owners.try_acquire(&pid) {
        Ok(l) => l,
        Err(e) => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": e,
                "hint": "Another consult is in flight — wait for Consulting to finish",
            })));
        }
    };
    let _talk_permit = match state.bulkheads.try_acquire_talk() {
        Ok(p) => p,
        Err(e) => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": e,
            })));
        }
    };

    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };

    session.append_user(&text);
    let _ = workbench_session::save_session(state.as_ref(), &session);

    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(&state, &pid);
        crate::services::agents::ensure_playground_admit_lane(&state, &pid);
    }

    let mut consult_headers = headers.clone();
    consult_headers.insert(
        axum::http::HeaderName::from_static(
            crate::substrate::talk_turn_pipeline::OUTER_SESSION_LEASE_HEADER,
        ),
        axum::http::HeaderValue::from_static("held"),
    );

    let consult_budget = if crate::services::playground::is_playground_mode() {
        std::time::Duration::from_secs(
            std::env::var("CONNECTOR_PLAYGROUND_TALK_LLM_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(75)
                .saturating_add(5),
        )
    } else {
        std::time::Duration::from_secs(185)
    };

    let consult_result = tokio::time::timeout(
        consult_budget,
        consult(
            &state,
            &consult_headers,
            &pid,
            &mut session,
            body.model.as_deref(),
            None,
        ),
    )
    .await;

    match consult_result {
        Ok(Ok(())) => {
            let _ = workbench_session::save_session(state.as_ref(), &session);
            Json(operator_envelope(session_body(&state, &session)))
        }
        Ok(Err(e)) => {
            session.append_system(&format!("consult_failed: {e}"), json!({ "error": e }));
            session.clear_consulting_on_error();
            let _ = workbench_session::save_session(state.as_ref(), &session);
            Json(operator_envelope(session_err(
                &state,
                &session,
                &e,
                json!({}),
            )))
        }
        Err(_) => {
            let e = format!(
                "consult_timed_out after {}s — provider/inject stalled; try again or link another LLM",
                consult_budget.as_secs()
            );
            session.append_system(&format!("consult_failed: {e}"), json!({ "error": e, "timeout": true }));
            session.clear_consulting_on_error();
            let _ = workbench_session::save_session(state.as_ref(), &session);
            Json(operator_envelope(session_err(
                &state,
                &session,
                &e,
                json!({ "timeout": true }),
            )))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AdmitBody {
    #[serde(default)]
    pub order_ids: Vec<String>,
}

/// POST .../sessions/:sid/admit — identity stack → DAL/PATE → Connector ToolDispatch.
pub async fn post_admit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<AdmitBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    if !require_principal(&state, &pid) {
        return deny("unknown_principal");
    }
    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };

    // Gate before consuming pending orders — Connector authority, not UI trust.
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_admit_lane(&state, &pid);
        // Compile snapshot once so EffectIntent can bind snapshot_version.
        let tid = crate::services::playground::playground_session_id_from_headers(&headers)
            .unwrap_or_else(|| sid.clone());
        let state_c = std::sync::Arc::clone(&state);
        let pid_c = pid.clone();
        let _ = tokio::task::spawn_blocking(move || {
            crate::substrate::agent_runtime_snapshot::get_or_compile(&state_c, &pid_c, &tid)
        })
        .await;
    }
    let _effect_permit = match state.bulkheads.try_acquire_effect() {
        Ok(p) => p,
        Err(e) => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": e,
            })));
        }
    };
    if identity_stack::identity_stack_enforce_enabled() {
        let stack = identity_stack::inspect(
            &state,
            &pid,
            "default",
            &AdmissionOp::ToolDispatch {
                tool_id: "workbench.admit".into(),
            },
        );
        if !stack.missing.is_empty() {
            session.append_system(
                &format!(
                    "admit_blocked_identity_stack: {}",
                    stack.missing.join(", ")
                ),
                json!({ "missing": stack.missing }),
            );
            let _ = workbench_session::save_session(state.as_ref(), &session);
            return Json(operator_envelope(session_err(
                &state,
                &session,
                "identity_stack_incomplete",
                json!({
                    "hint": "Mint character, last memory, address graph, RULES + HITL on SETUP / Access before Admit.",
                    "missing": stack.missing,
                }),
            )));
        }
    }

    let orders = session.take_pending_orders(&body.order_ids);
    if orders.is_empty() {
        return Json(operator_envelope(session_err(
            &state,
            &session,
            "no_pending_orders",
            json!({}),
        )));
    }

    let snap_version = state
        .runtime_snapshots
        .get(&pid)
        .map(|s| s.snapshot_version)
        .unwrap_or(0);
    let effect_intents: Vec<Value> = orders
        .iter()
        .map(|o| {
            let tool_name = o
                .payload
                .get("openai_call")
                .and_then(|c| c.get("function"))
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .or_else(|| o.payload.get("tool").and_then(|t| t.as_str()))
                .unwrap_or("workbench.order");
            let params = o
                .payload
                .get("openai_call")
                .and_then(|c| c.get("function"))
                .and_then(|f| f.get("arguments"))
                .cloned()
                .unwrap_or_else(|| o.payload.clone());
            let intent = crate::substrate::effect_intent::EffectIntent::from_workbench_order(
                &pid,
                &sid,
                &o.event_id,
                "workbench.admit",
                tool_name,
                params,
                snap_version,
                None,
            );
            serde_json::to_value(&intent).unwrap_or(json!({}))
        })
        .collect();
    session.append_system(
        "effect_intents_compiled",
        json!({
            "count": effect_intents.len(),
            "intents": effect_intents,
        }),
    );
    let digests: Vec<String> = effect_intents
        .iter()
        .filter_map(|v| v.get("intent_digest").and_then(|d| d.as_str()).map(str::to_string))
        .collect();
    crate::substrate::authority_evidence::record_effect_intents(
        state.as_ref(),
        &pid,
        &sid,
        snap_version,
        &digests,
    );

    // PATE: each order must pass tool admit bound to EffectIntent digest (INV-05).
    let mut pate_atus = Vec::new();
    let mut admitted_tasks = Vec::new();
    let release_open_proceed = |tasks: &[crate::substrate::pate::AugmentedTaskUnit], reason: &str| {
        for atu in tasks {
            if crate::substrate::pate::host_admission_allows_execution(atu.verdict) {
                let reason = reason.to_string();
                let _ = crate::substrate::pate::run_admitted_effect(&state, atu, |_| Err(reason));
            }
        }
    };
    for (order, intent_v) in orders.iter().zip(effect_intents.iter()) {
        let tool_name = order
            .payload
            .get("openai_call")
            .and_then(|c| c.get("function"))
            .and_then(|f| f.get("name"))
            .and_then(|n| n.as_str())
            .or_else(|| order.payload.get("tool").and_then(|t| t.as_str()))
            .unwrap_or("workbench.order");
        let mut args = order
            .payload
            .get("openai_call")
            .and_then(|c| c.get("function"))
            .and_then(|f| f.get("arguments"))
            .cloned()
            .unwrap_or_else(|| order.payload.clone());
        if let Some(obj) = args.as_object_mut() {
            obj.insert("effect_intent".into(), intent_v.clone());
            if let Some(d) = intent_v.get("intent_digest") {
                obj.insert("action_digest".into(), d.clone());
            }
        }
        match crate::substrate::pate::admit_tool(
            &state,
            &pid,
            "workbench",
            tool_name,
            &args,
            Some(sid.clone()),
        ) {
            Ok(atu) => {
                if let Some(auth) = intent_v.get("authority").and_then(|a| a.get("auth_digest")) {
                    if atu.action_digest != auth.as_str().unwrap_or("") {
                        // Digest identity differs by construction (binding vs intent) —
                        // record linkage; do not fail closed on inequality of schemes.
                        session.append_system(
                            "pate_intent_linked",
                            json!({
                                "order_id": order.event_id,
                                "pate_digest": atu.action_digest,
                                "intent_auth_digest": auth,
                                "intent_digest": intent_v.get("intent_digest"),
                            }),
                        );
                    }
                }
                admitted_tasks.push(atu.clone());
                pate_atus.push(json!({
                    "order_id": order.event_id,
                    "task_id": atu.task_id,
                    "action_digest": atu.action_digest,
                    "verdict": format!("{:?}", atu.verdict),
                }));
            }
            Err(e) => {
                session.append_system(
                    &format!("pate_admit_blocked: {}", e.human_readable),
                    json!({ "order_id": order.event_id, "error": e.human_readable, "hint": e.hint }),
                );
                for id in orders.iter().map(|o| o.event_id.clone()) {
                    session.pending_order_ids.push(id.clone());
                    session.mark_order_status(&id, "pending");
                }
                release_open_proceed(&admitted_tasks, &e.human_readable);
                session.phase = if workbench_session::is_hitl_signal(&e.human_readable) {
                    session.append_hitl(&e.human_readable, &orders.iter().map(|o| o.event_id.clone()).collect::<Vec<_>>());
                    WorkbenchPhase::HitlWait
                } else {
                    WorkbenchPhase::AwaitAdmit
                };
                let _ = workbench_session::save_session(state.as_ref(), &session);
                return Json(operator_envelope(session_err(
                    &state,
                    &session,
                    &e.human_readable,
                    json!({ "hint": e.hint, "pate": true }),
                )));
            }
        }
    }
    session.append_system("pate_admit_ok", json!({ "atus": pate_atus }));

    session.phase = WorkbenchPhase::Acting;
    let order_ids: Vec<String> = orders.iter().map(|o| o.event_id.clone()).collect();
    let tool_calls: Vec<Value> = orders
        .iter()
        .filter_map(|o| o.payload.get("openai_call").cloned())
        .collect();

    if session.dal_run_id.is_none() {
        match dynamic_agent_loop::start_run(&state, &pid, &session.goal, None) {
            Ok(run) => session.dal_run_id = Some(run.run_id),
            Err(e) => {
                release_open_proceed(&admitted_tasks, &e.human_readable);
                session.append_system(
                    &format!("dal_start_failed: {}", e.human_readable),
                    json!({ "error": e.human_readable }),
                );
                for id in &order_ids {
                    session.pending_order_ids.push(id.clone());
                    session.mark_order_status(id, "pending");
                }
                session.phase = WorkbenchPhase::AwaitAdmit;
                let _ = workbench_session::save_session(state.as_ref(), &session);
                return Json(operator_envelope(session_err(
                    &state,
                    &session,
                    &e.human_readable,
                    json!({}),
                )));
            }
        }
    }

    let run_id = session.dal_run_id.clone().unwrap_or_default();
    let mut run = match dynamic_agent_loop::load(state.as_ref(), &run_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            release_open_proceed(&admitted_tasks, "dal_run_not_found");
            session.append_system("dal_run_missing", json!({ "run_id": run_id }));
            for id in &order_ids {
                session.pending_order_ids.push(id.clone());
                session.mark_order_status(id, "pending");
            }
            session.phase = WorkbenchPhase::AwaitAdmit;
            let _ = workbench_session::save_session(state.as_ref(), &session);
            return Json(operator_envelope(session_err(
                &state,
                &session,
                "dal_run_not_found",
                json!({}),
            )));
        }
        Err(e) => {
            release_open_proceed(&admitted_tasks, &e.human_readable);
            let _ = workbench_session::save_session(state.as_ref(), &session);
            return Json(operator_envelope(session_err(
                &state,
                &session,
                &e.human_readable,
                json!({}),
            )));
        }
    };

    let turn = match dynamic_agent_loop::run_turn(&state, &mut run, &tool_calls, None, None).await {
        Ok(t) => {
            for atu in &admitted_tasks {
                if crate::substrate::pate::host_admission_allows_execution(atu.verdict) {
                    let _ = crate::substrate::pate::run_admitted_effect(&state, atu, |_| {
                        Ok(json!({"observed": true, "source": "workbench_turn"}))
                    });
                }
            }
            t
        }
        Err(e) => {
            for atu in &admitted_tasks {
                if crate::substrate::pate::host_admission_allows_execution(atu.verdict) {
                    let reason = e.human_readable.clone();
                    let _ = crate::substrate::pate::run_admitted_effect(&state, atu, |_| Err(reason));
                }
            }
            session.append_admission("block", &order_ids, json!({ "error": e.human_readable }));
            session.append_system(
                &format!("dal_turn_failed: {}", e.human_readable),
                json!({ "error": e.human_readable, "hint": e.hint }),
            );
            for id in &order_ids {
                session.mark_order_status(id, "blocked");
            }
            session.phase = if workbench_session::is_hitl_signal(&e.human_readable) {
                session.append_hitl(&e.human_readable, &order_ids);
                let rid = crate::services::agents::hitl_submit_with_state(
                    &pid,
                    "workbench_admit",
                    &e.human_readable,
                    Some(&state),
                );
                session.hitl_request_id = Some(rid);
                WorkbenchPhase::HitlWait
            } else {
                WorkbenchPhase::Idle
            };
            let _ = workbench_session::save_session(state.as_ref(), &session);
            return Json(operator_envelope(session_err(
                &state,
                &session,
                &e.human_readable,
                json!({ "hint": e.hint }),
            )));
        }
    };

    let receipts = turn.get("receipts").cloned().unwrap_or(json!([]));
    let mut any_hitl = false;
    let mut any_ok = false;
    if let Some(arr) = receipts.as_array() {
        for r in arr {
            let call_id = r.get("call_id").and_then(|x| x.as_str()).unwrap_or("");
            let tool_name = r.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
            let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
            let err = r.get("error").and_then(|x| x.as_str());
            if err.map(workbench_session::is_hitl_signal).unwrap_or(false) {
                any_hitl = true;
            }
            if ok {
                any_ok = true;
            }
            session.append_tool_receipt(
                call_id,
                tool_name,
                ok,
                r.get("action_digest").and_then(|x| x.as_str()),
                r.get("task_id").and_then(|x| x.as_str()),
                r.get("result").cloned().unwrap_or(Value::Null),
                err,
            );
        }
    }

    let verdict = if any_hitl {
        "ask"
    } else if any_ok {
        "allow"
    } else {
        "block"
    };
    session.append_admission(
        verdict,
        &order_ids,
        json!({ "dal": turn.get("run"), "cip": turn.get("cip") }),
    );
    for id in &order_ids {
        session.mark_order_status(id, verdict);
    }

    if any_hitl {
        session.append_hitl(
            "PATE Ask — approve on FIX, then Workbench hitl-resume (or Admit after resume)",
            &order_ids,
        );
        let rid = crate::services::agents::hitl_submit_with_state(
            &pid,
            "pate_ask",
            "Workbench admit requires human approval (PATE Ask)",
            Some(&state),
        );
        session.hitl_request_id = Some(rid);
        let _ = workbench_session::save_session(state.as_ref(), &session);
        return Json(operator_envelope(session_body(&state, &session)));
    }

    if any_ok {
        if let Err(e) = consult(
            &state,
            &headers,
            &pid,
            &mut session,
            None,
            Some(
                "Continue from admitted Connector tool receipts. Speak as the active principal. Do not claim any effect Connector did not admit and attest.",
            ),
        )
        .await
        {
            session.append_system(&format!("continue_failed: {e}"), json!({ "error": e }));
        }
    } else if session.pending_order_ids.is_empty() {
        session.phase = WorkbenchPhase::Idle;
    }

    let _ = workbench_session::save_session(state.as_ref(), &session);
    Json(operator_envelope(session_body(&state, &session)))
}

#[derive(Debug, Deserialize)]
pub struct CancelBody {
    #[serde(default)]
    pub order_ids: Vec<String>,
}

/// POST .../sessions/:sid/cancel-orders
pub async fn post_cancel_orders(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<CancelBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };
    let n = session.cancel_orders(&body.order_ids);
    let _ = workbench_session::save_session(state.as_ref(), &session);
    Json(operator_envelope(json!({
        "ok": true,
        "cancelled": n,
        "dispatched": false,
        "session": session.snapshot(),
        "events": session.events,
        "pending_orders": session.pending_order_snapshots(),
        "vitals": vitals_for(&state, &session),
    })))
}

#[derive(Debug, Deserialize)]
pub struct HitlResumeBody {
    #[serde(default)]
    pub request_id: Option<String>,
}

/// POST .../hitl-resume — after FIX approve: re-queue held Ask orders for Admit.
pub async fn post_hitl_resume(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<HitlResumeBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };
    if session.held_order_ids.is_empty() {
        return Json(operator_envelope(session_err(
            &state,
            &session,
            "no_held_orders",
            json!({ "hint": "Nothing held from PATE Ask." }),
        )));
    }
    let rid = body
        .request_id
        .as_deref()
        .or(session.hitl_request_id.as_deref())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let Some(rid) = rid else {
        return Json(operator_envelope(session_err(
            &state,
            &session,
            "hitl_request_id_required",
            json!({
                "hint": "Approve the PATE Ask on FIX first, then resume with the hitl_request_id."
            }),
        )));
    };

    match crate::services::agents::hitl_status(&pid, &rid).as_deref() {
        Some("approved") => {
            // Already decided on FIX — resume only; do not invent approval here.
        }
        Some("pending") => {
            return Json(operator_envelope(session_err(
                &state,
                &session,
                "fix_approve_required",
                json!({
                    "hitl_request_id": rid,
                    "hint": "Approve on FIX first. Workbench resume will not mint approval.",
                    "links": { "fix": "/fix" },
                }),
            )));
        }
        Some(other) => {
            return Json(operator_envelope(session_err(
                &state,
                &session,
                "hitl_not_approved",
                json!({
                    "hitl_request_id": rid,
                    "status": other,
                    "hint": "Only FIX-approved Ask requests can be resumed for Admit.",
                }),
            )));
        }
        None => {
            return Json(operator_envelope(session_err(
                &state,
                &session,
                "hitl_request_not_found",
                json!({
                    "hitl_request_id": rid,
                    "hint": "Unknown HITL request — approve on FIX, then retry resume.",
                }),
            )));
        }
    }

    let n = session.resume_held_orders();
    session.append_system(
        &format!("hitl_resumed:{rid} — orders re-queued for Admit"),
        json!({ "hitl_request_id": rid, "requeued": n }),
    );
    session.hitl_request_id = None;
    let _ = workbench_session::save_session(state.as_ref(), &session);
    Json(operator_envelope(json!({
        "ok": true,
        "requeued": n,
        "dispatched": false,
        "hint": "Orders are pending again — Admit to run DAL/PATE/ToolDispatch.",
        "session": session.snapshot(),
        "events": session.events,
        "pending_orders": session.pending_order_snapshots(),
        "vitals": vitals_for(&state, &session),
    })))
}

#[derive(Debug, Deserialize)]
pub struct HitlDenyBody {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// POST .../hitl-deny — cancel held Ask orders without ToolDispatch.
pub async fn post_hitl_deny(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<HitlDenyBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };
    if let Some(rid) = body
        .request_id
        .as_deref()
        .or(session.hitl_request_id.as_deref())
        .filter(|s| !s.is_empty())
    {
        let _ = crate::services::agents::hitl_mark_resolved(&pid, rid, "denied", "workbench");
    }
    let reason = body
        .reason
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("operator denied");
    let n = session.deny_held_orders(reason);
    let _ = workbench_session::save_session(state.as_ref(), &session);
    Json(operator_envelope(json!({
        "ok": true,
        "cancelled": n,
        "dispatched": false,
        "session": session.snapshot(),
        "events": session.events,
        "pending_orders": session.pending_order_snapshots(),
        "vitals": vitals_for(&state, &session),
    })))
}

#[derive(Deserialize)]
pub struct DemoVerbBody {
    pub verb: String,
}

/// POST .../sessions/:sid/demo — Isolate / Govern / Stop / Prove / bank Score|Hold|Decide|Ledger.
/// Bank verbs enqueue Admit orders that mutate the tenant playground ledger after PATE.
/// Stop cancels the loop. SpendCease is separate (`POST /agents/:pid/cease`).
pub async fn post_demo(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, sid)): Path<(String, String)>,
    Json(body): Json<DemoVerbBody>,
) -> Json<Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return deny("auth_required");
    }
    if !require_principal(&state, &pid) {
        return deny("unknown_principal");
    }
    crate::services::playground_demo::install_mcp_tools();
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_tool_lane(&state, &pid);
        crate::services::agents::ensure_playground_admit_lane(&state, &pid);
    }
    let mut session = match workbench_session::load_session(state.as_ref(), &pid, &sid) {
        Ok(Some(s)) => s,
        Ok(None) => return deny("session_not_found"),
        Err(e) => return deny(&e),
    };
    session.append_user(&format!("demo:{}", body.verb.trim().to_ascii_lowercase()));
    let verb = body.verb.clone();
    match crate::services::playground_demo::apply_verb(&mut session, &verb) {
        Ok(hint) => {
            let _ = workbench_session::save_session(state.as_ref(), &session);
            let mut out = session_body(&state, &session);
            if let Some(obj) = out.as_object_mut() {
                obj.insert("hint".into(), json!(hint));
                obj.insert("verb".into(), json!(verb));
            }
            Json(operator_envelope(out))
        }
        Err(e) => {
            let _ = workbench_session::save_session(state.as_ref(), &session);
            Json(operator_envelope(session_err(
                &state,
                &session,
                &e,
                json!({ "hint": "Use isolate | govern | stop | prove" }),
            )))
        }
    }
}

async fn consult(
    state: &SharedState,
    headers: &HeaderMap,
    pid: &str,
    session: &mut WorkbenchSession,
    model: Option<&str>,
    extra_user: Option<&str>,
) -> Result<(), String> {
    if let Some(extra) = extra_user {
        session.append_user(extra);
    }
    let tool_defs = crate::services::mcp_hosting::list_tools();
    let tool_names: Vec<String> = tool_defs.iter().map(|t| t.name.clone()).collect();
    let mut schemas = std::collections::HashMap::new();
    for t in &tool_defs {
        schemas.insert(t.name.clone(), t.input_schema.clone());
    }
    let order_sys = workbench_session::order_proposal_system_block(&tool_names);

    let mut messages: Vec<ChatMessage> = Vec::new();
    messages.push(ChatMessage {
        role: "system".into(),
        content: order_sys,
        reasoning_content: None,
        tool_calls: None,
        tool_call_id: None,
    });
    for m in session.llm_messages() {
        messages.push(ChatMessage {
            role: m.role,
            content: m.content,
            reasoning_content: None,
            tool_calls: m.tool_calls,
            tool_call_id: m.tool_call_id,
        });
    }
    if messages.len() <= 1 {
        return Err("empty_context".into());
    }

    // Cap context for long sessions — keep system proposal block + recent turns.
    const MAX_MSGS: usize = 48;
    if messages.len() > MAX_MSGS {
        let sys = messages.remove(0);
        let drop_n = messages.len() - (MAX_MSGS - 1);
        messages.drain(0..drop_n);
        messages.insert(0, sys);
    }

    let model = model
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".into());
    let req = ChatCompletionRequest {
        model,
        messages: messages.drain(..).collect(),
        stream: false,
        temperature: None,
        max_tokens: None,
        agent_pid: Some(pid.to_string()),
        namespace: None,
        // Ring-1: do not send native tools without CPO. Workbench uses connector.order.v1.
        tools: None,
        tool_choice: None,
        thread_id: None,
    };

    let response = gateway::chat_completions(State(state.clone()), headers.clone(), Json(req))
        .await
        .map_err(|e| e.human_readable)?;

    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| format!("read_completion: {e}"))?;
    if !parts.status.is_success() {
        let hint = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .or_else(|| v.get("message"))
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| {
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(400)
                    .collect()
            });
        session.append_system(
            &format!("lane: {hint}"),
            json!({ "http": parts.status.as_u16() }),
        );
        return Err(hint);
    }

    let v: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("bad_completion_json: {e}"))?;
    if let Some(err) = v
        .get("error")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        session.append_system(err, json!({ "body_error": true }));
        return Err(err.to_string());
    }

    let text = v
        .pointer("/choices/0/message/content")
        .or_else(|| v.pointer("/data/choices/0/message/content"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let native_calls = v
        .pointer("/choices/0/message/tool_calls")
        .or_else(|| v.pointer("/data/choices/0/message/tool_calls"))
        .cloned()
        .and_then(|c| c.as_array().cloned())
        .unwrap_or_default();

    let (display, parsed_calls) = workbench_session::parse_order_proposals(&text);
    let mut merged: Vec<Value> = native_calls;
    let unknown: Vec<String> = parsed_calls
        .iter()
        .chain(merged.iter())
        .filter_map(|c| {
            let name = c
                .pointer("/function/name")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if name.is_empty() || tool_names.iter().any(|t| t == name) {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    merged.extend(parsed_calls);

    let outcome = v
        .get("connector_projection_outcome")
        .or_else(|| v.pointer("/data/connector_projection_outcome"))
        .and_then(|x| x.as_str())
        .unwrap_or("pass")
        .to_string();

    // DENY: speak refusal, never mint executable orders.
    let tool_calls = if outcome.eq_ignore_ascii_case("deny") {
        None
    } else {
        let (filtered, schema_rejects) =
            workbench_session::filter_and_validate_proposals(merged, &tool_names, &schemas);
        if !schema_rejects.is_empty() {
            let detail: Vec<String> = schema_rejects
                .iter()
                .map(|(n, r)| format!("{n}:{r}"))
                .collect();
            session.append_system(
                &format!("order_rejected_schema: {}", detail.join(", ")),
                json!({ "schema_rejects": schema_rejects }),
            );
        }
        if filtered.is_empty() {
            None
        } else {
            Some(Value::Array(filtered))
        }
    };

    if !unknown.is_empty() && !outcome.eq_ignore_ascii_case("deny") {
        session.append_system(
            &format!("order_rejected_unknown_tool: {}", unknown.join(", ")),
            json!({ "unknown_tools": unknown, "registered": tool_names }),
        );
    }

    let work_unit = v
        .get("connector_identity_work_unit")
        .or_else(|| v.pointer("/data/connector_identity_work_unit"))
        .cloned()
        .unwrap_or(Value::Null);
    let binding = v
        .get("connector_intelligence_binding")
        .or_else(|| v.pointer("/data/connector_intelligence_binding"))
        .cloned()
        .unwrap_or(Value::Null);
    let mutations = v
        .pointer("/connector_output_attestation/enforced_rules")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let aipsprt = v
        .get("connector_aipsprt")
        .or_else(|| v.pointer("/data/connector_aipsprt"))
        .cloned();
    let shown = if display.trim().is_empty() {
        text
    } else {
        display
    };
    session.append_assistant_projected(
        &shown,
        &outcome,
        work_unit,
        binding,
        mutations,
        tool_calls,
        aipsprt,
    );
    Ok(())
}
