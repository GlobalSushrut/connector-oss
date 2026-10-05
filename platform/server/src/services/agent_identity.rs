//! Agent identity HTTP — setup, activate, capabilities, forensic universal envelope (P10.10).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use connector_trust::{
    AgentSetupSpecV2, ForensicProfileV2, HitlPolicyV2, MemoryProfileV2, NamespaceGrantV2,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::agent_identity_envelope::{
    self, activate_agent, build_identity_envelope, list_forensic_universal, load_activation,
    load_setup, save_setup, validate_setup,
};
use crate::kernel::agent_principal::{self, ContractPatchV2};
use crate::services::agents::caller;
use crate::services::gateway::{self, ChatCompletionRequest};
use crate::state::SharedState;

fn auth_operator_or_agent_self(headers: &HeaderMap, agent_pid: &str) -> bool {
    caller(headers).is_some()
        || crate::kernel::agent_identity_envelope::agent_self_access(headers, agent_pid)
}

#[derive(Debug, Deserialize)]
pub struct AgentSetupBody {
    pub name: Option<String>,
    pub acume: Option<String>,
    pub memory_profile: Option<MemoryProfileV2>,
    pub knowledge_base_id: Option<String>,
    pub use_case_def: Option<serde_json::Value>,
    pub contract_ref: Option<String>,
    pub hitl_policy: Option<String>,
    pub forensic_profile: Option<String>,
    pub philosophy_digest: Option<String>,
    pub common_spaces: Option<Vec<NamespaceGrantV2>>,
    /// B13: `false` keeps a draft (SetupReady path); default `true` for complete setup.
    pub setup_complete: Option<bool>,
    /// Enhance existing setup: bounded skills (typed — not markdown).
    #[serde(default)]
    pub skills: Option<Vec<crate::kernel::intelligence_spec::BoundSkillV1>>,
    #[serde(default)]
    pub portals: Option<Vec<crate::kernel::intelligence_spec::PortalV1>>,
    #[serde(default)]
    pub rules: Option<Vec<crate::kernel::intelligence_spec::RuleV1>>,
    /// Optional knowledge seeds on setup (1 line or long docs).
    #[serde(default)]
    pub knowledge: Option<Vec<crate::kernel::intelligence_spec::KnowledgeSeedV1>>,
}

fn parse_hitl(s: &str) -> HitlPolicyV2 {
    match s.to_lowercase().as_str() {
        "none" => HitlPolicyV2::None,
        "tool" => HitlPolicyV2::Tool,
        "export" => HitlPolicyV2::Export,
        "all_material" | "all" => HitlPolicyV2::AllMaterial,
        _ => HitlPolicyV2::Egress,
    }
}

fn parse_forensic(s: &str) -> ForensicProfileV2 {
    match s.to_lowercase().as_str() {
        "off" => ForensicProfileV2::Off,
        "standard" => ForensicProfileV2::Standard,
        "hipaa" => ForensicProfileV2::Hipaa,
        "court" => ForensicProfileV2::Court,
        _ => ForensicProfileV2::Soc2,
    }
}

/// GET /api/v1/agents/:pid/setup
pub async fn get_agent_setup(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match load_setup(state.as_ref(), &pid) {
        Some(spec) => Json(json!({
            "ok": true,
            "setup": spec,
            "bound_skills": crate::kernel::intelligence_spec::load_bound_skills(state.as_ref(), &pid),
            "portals": crate::kernel::intelligence_spec::load_portals(state.as_ref(), &pid),
            "rules": crate::kernel::intelligence_spec::load_rules(state.as_ref(), &pid),
        })),
        None => Json(json!({"ok": false, "error": "setup_not_found"})),
    }
}

/// POST /api/v1/agents/:pid/setup
pub async fn post_agent_setup(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<AgentSetupBody>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "auth_required"})),
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required"}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta = es.folder_get("agent_meta", &pid).ok().flatten();
    drop(es);
    let Some(meta) = meta else {
        return Json(json!({"ok": false, "error": "agent_not_found"}));
    };
    let namespace = meta
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("m/default")
        .to_string();
    let name = body
        .name
        .or_else(|| {
            meta.get("name")
                .and_then(|v| v.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| pid.clone());
    let acume = body.acume.unwrap_or_else(|| format!("agent:{}", name));
    let kb_id = body
        .knowledge_base_id
        .unwrap_or_else(|| format!("kb:{}", acume.to_lowercase().replace('_', "-")));
    let contract_ref = body
        .contract_ref
        .or_else(|| {
            crate::kernel::agent_principal::load_contract(state.as_ref(), &pid)
                .map(|c| c.contract_digest_sha256)
        })
        .unwrap_or_else(|| "iia:default".into());

    let spec = AgentSetupSpecV2 {
        schema: connector_trust::AGENT_IDENTITY_SCHEMA.into(),
        agent_pid: pid.clone(),
        name,
        acume: acume.clone(),
        namespace: namespace.clone(),
        memory_profile: body
            .memory_profile
            .unwrap_or_else(agent_identity_envelope::default_memory_profile),
        knowledge_base_id: kb_id.clone(),
        knowledge_base_address: format!(
            "/k/{}",
            agent_identity_envelope::normalize_kb_path_segment(&kb_id)
        ),
        use_case_def: body.use_case_def,
        contract_ref,
        hitl_policy: body
            .hitl_policy
            .as_deref()
            .map(parse_hitl)
            .unwrap_or(HitlPolicyV2::None),
        forensic_profile: body
            .forensic_profile
            .as_deref()
            .map(parse_forensic)
            .unwrap_or(ForensicProfileV2::Off),
        philosophy_digest: body.philosophy_digest,
        common_spaces: body.common_spaces.unwrap_or_default(),
        configured_at_ms: chrono::Utc::now().timestamp_millis(),
        setup_complete: body.setup_complete.unwrap_or(true),
    };

    if let Err(e) = validate_setup(&spec) {
        return Json(json!({"ok": false, "error": "validation_failed", "message": e}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "agent_setup",
        &json!({"setup_complete": spec.setup_complete}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    if let Err(e) = save_setup(state.as_ref(), &spec) {
        open_proceed.finish_observed(false);
        return Json(json!({
            "ok": false,
            "error": "persist_failed",
            "message": e,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    }

    // Enhance existing setup: persist bound skills / portals / rules when provided.
    let skills = body.skills.unwrap_or_default();
    let portals = body.portals.unwrap_or_default();
    let rules = body.rules.unwrap_or_default();
    let knowledge_seeds = body.knowledge.unwrap_or_default();
    if !skills.is_empty() || !portals.is_empty() || !rules.is_empty() {
        let mini = crate::kernel::intelligence_spec::IntelligenceSpecV1 {
            api_version: "connector.ai/v1".into(),
            kind: "Intelligence".into(),
            metadata: crate::kernel::intelligence_spec::IntelligenceMetadata {
                name: spec.name.clone(),
                labels: json!({}),
            },
            spec: crate::kernel::intelligence_spec::IntelligenceSpecBody {
                purpose: spec.acume.clone(),
                class: None,
                parameters: Default::default(),
                skills: skills.clone(),
                knowledge: knowledge_seeds.clone(),
                limitations: Default::default(),
                portals: portals.clone(),
                rules: rules.clone(),
                output_contract: Default::default(),
                harden: false,
                activate: false,
            },
        };
        if let Err(e) = crate::kernel::intelligence_spec::persist_bound_pack(
            state.as_ref(),
            &pid,
            &skills,
            &portals,
            &rules,
            &mini,
        ) {
            open_proceed.finish_observed(false);
            return Json(json!({
                "ok": false,
                "error": "persist_skills_failed",
                "message": e,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
    }

    let (revoked, needs_reactivate) =
        agent_principal::demote_after_charter_change(state.as_ref(), &pid);

    let next = if spec.setup_complete {
        format!("POST /api/v1/agents/{pid}/activate")
    } else {
        format!("POST /api/v1/agents/{pid}/setup with setup_complete=true, then activate")
    };

    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "setup": spec,
        "skills_bound": skills.len(),
        "portals": portals.len(),
        "rules": rules.len(),
        "knowledge_seeds": knowledge_seeds.len(),
        "knowledge_hint": if knowledge_seeds.is_empty() {
            Value::Null
        } else {
            json!("Ingest via POST /memory/knowledge/ingest or POST /intelligence/apply")
        },
        "quanta_revoked": revoked,
        "needs_reactivate": needs_reactivate,
        "next": next,
        "honesty": "Setup enhanced — bound skills/portals/rules on existing AgentSetupSpec path",
    }))
}

/// POST /api/v1/agents/:pid/activate
pub async fn post_agent_activate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "auth_required"})),
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required"}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "agent_activate",
        &json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match activate_agent(state.as_ref(), &pid) {
        Ok(profile) => {
            let envelope = build_identity_envelope(state.as_ref(), &pid);
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "activation": profile,
                "identity_envelope": envelope,
                "who_am_i_hint": format!("GET /api/v1/runtime/self?agent_pid={pid}"),
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({
                "ok": false,
                "error": "activate_failed",
                "message": e,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    }
}

/// GET /api/v1/agents/:pid/capabilities
pub async fn get_agent_capabilities(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let activation = load_activation(state.as_ref(), &pid);
    let envelope = build_identity_envelope(state.as_ref(), &pid);
    Json(json!({
        "ok": true,
        "agent_pid": pid,
        "activation_state": activation.as_ref().map(|a| format!("{:?}", a.state)),
        "capability_manifest": activation.map(|a| a.capability_manifest)
            .or_else(|| envelope.as_ref().map(|e| e.capability_manifest.clone())),
        "identity_envelope_digest": envelope.as_ref().map(|e| e.execution_rules_digest.clone()),
    }))
}

/// GET /api/v1/agents/:pid/identity-envelope — agent always has access to its own env
pub async fn get_agent_identity_envelope(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match build_identity_envelope(state.as_ref(), &pid) {
        Some(envelope) => Json(json!({
            "ok": true,
            "envelope": envelope,
            "who_am_i_authoritative": envelope.who_am_i_authoritative,
            "forensic_universal_schema": connector_trust::FORENSIC_UNIVERSAL_SCHEMA,
        })),
        None => Json(json!({"ok": false, "error": "envelope_not_found"})),
    }
}

/// GET /api/v1/agents/:pid/forensic/universal — WitnessCtl/SOC2-ready records
pub async fn get_agent_forensic_universal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let records = list_forensic_universal(state.as_ref(), &pid);
    Json(json!({
        "ok": true,
        "schema": connector_trust::FORENSIC_UNIVERSAL_SCHEMA,
        "agent_pid": pid,
        "count": records.len(),
        "records": records,
        "witnessctl_export_hint": format!("/plugins/witnessctl/api/v1/export/{{session_id}} — correlate via witnessctl_session_id in records"),
    }))
}

/// GET /api/v1/forensics/universal/:agent_pid
pub async fn get_forensics_universal_by_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    get_agent_forensic_universal(State(state), headers, Path(agent_pid)).await
}

/// GET /api/v1/agents/:pid/compliance-contract — auditor SoT bound at activate
pub async fn get_agent_compliance_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match crate::kernel::compliance_contract::load_compliance_contract(state.as_ref(), &pid) {
        Some(contract) => {
            let wc_alignment =
                crate::kernel::witnessctl_align::load_alignment(state.as_ref(), &pid);
            let mismatch = wc_alignment.as_ref().and_then(|a| {
                let status = a.get("status").and_then(|s| s.as_str()).unwrap_or("");
                if matches!(status, "pending_wc_unavailable" | "open_failed") {
                    Some(json!({
                        "frameworks_required": a.get("frameworks"),
                        "status": status,
                        "detail": a.get("detail"),
                        "honesty": "forensic_profile requires WC session; alignment incomplete",
                    }))
                } else {
                    None
                }
            });
            Json(json!({
                "ok": true,
                "schema": connector_trust::COMPLIANCE_CONTRACT_SCHEMA,
                "contract": contract,
                "witnessctl_alignment": wc_alignment,
                "witnessctl_framework_mismatch": mismatch,
                "verify": {
                    "node_pubkey_hex": state.signing_key.public_key_hex(),
                    "rule": "Verify signature over unsigned body; digest field must match recomputed canonical digest",
                },
                "forensic_package": format!("GET /api/v1/forensics/package?agent_pid={pid}"),
            }))
        }
        None => Json(json!({
            "ok": false,
            "error": "compliance_contract_not_found",
            "hint": "POST /agents/:pid/activate binds ComplianceContractV2",
        })),
    }
}

/// GET /api/v1/agents/:pid/contract — read AgentContractV2 cage
pub async fn get_agent_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match agent_principal::load_contract(state.as_ref(), &pid) {
        Some(c) => Json(json!({"ok": true, "contract": c})),
        None => Json(json!({"ok": false, "error": "contract_not_found"})),
    }
}

/// PATCH /api/v1/agents/:pid/contract — B1 write path for Charter S2
pub async fn patch_agent_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(patch): Json<ContractPatchV2>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(json!({"ok": false, "error": "auth_required"})),
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required"}));
    }
    match agent_principal::update_contract(state.as_ref(), &pid, patch) {
        Ok(result) => {
            let activation =
                crate::kernel::agent_identity_envelope::load_activation(state.as_ref(), &pid);
            Json(json!({
                "ok": true,
                "contract": result.contract,
                "quanta_revoked": result.revoked_quanta,
                "needs_reactivate": result.needs_reactivate,
                "activation_state": activation.map(|a| a.state),
                "note": "Contract digest updated; outstanding quanta revoked. POST /agents/:pid/activate to re-bind ComplianceContractV2.",
            }))
        }
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// POST /api/v1/agents/:pid/completions — B2 forced-pid Talk façade (no gateway-agent).
/// Optional body `thread_id` persists the last user message into B15 chat threads.
pub async fn post_agent_completions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(mut req): Json<ChatCompletionRequest>,
) -> Result<axum::response::Response, crate::error::ConnectorError> {
    if caller(&headers).is_none()
        && !crate::kernel::agent_identity_envelope::agent_self_access(&headers, &pid)
    {
        return Err(crate::error::ConnectorError::new(
            crate::error::DenialReason::AuthenticationRequired,
            "auth_required",
        ));
    }
    // Playground: gateway fast path handles identity + LLM; avoid duplicate sync rehydrate here.
    if crate::services::playground::is_playground_mode() {
        crate::services::settings_llms::restore_llm_router_for_talk(&state, &headers, Some(&pid));
    } else {
        crate::services::agents::ensure_talk_identity(&state, &pid);
    }
    if agent_principal::load_principal(state.as_ref(), &pid).is_none() {
        return Err(crate::error::ConnectorError::new(
            crate::error::DenialReason::PolicyDenied,
            "unknown_principal",
        )
        .with_hint("Register agent and mint principal before Talk")
        .with_agent_scope(&pid));
    }
    // B4: when setup gate is on, require ActivationState::Active before Talk.
    if crate::kernel::agent_identity_envelope::setup_gate_enabled() {
        let active = crate::kernel::agent_identity_envelope::load_activation(state.as_ref(), &pid)
            .map(|a| matches!(a.state, connector_trust::ActivationStateV2::Active))
            .unwrap_or(false);
        if !active {
            return Err(crate::error::ConnectorError::new(
                crate::error::DenialReason::PolicyDenied,
                "agent_not_activated",
            )
            .with_hint("POST /agents/:pid/setup then POST /agents/:pid/activate before Talk")
            .with_agent_scope(&pid));
        }
    }
    // B15: optional thread persistence for last user turn.
    let thread_id = req.thread_id.clone();
    if let Some(tid) = thread_id.clone() {
        if let Some(last_user) = req
            .messages
            .iter()
            .rev()
            .find(|m| m.role.eq_ignore_ascii_case("user"))
        {
            let _ = crate::kernel::agent_chat::append_turn(
                state.as_ref(),
                &pid,
                &tid,
                "user",
                &last_user.content,
            );
        }
    }
    // Path wins — ban anonymous / mismatched body pid.
    req.agent_pid = Some(pid.clone());
    let response = gateway::chat_completions(State(state.clone()), headers, Json(req)).await?;

    if let Some(tid) = thread_id {
        if response.status().is_success() {
            let (parts, body) = response.into_parts();
            match axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(content) = v
                            .pointer("/choices/0/message/content")
                            .and_then(|x| x.as_str())
                        {
                            let _ = crate::kernel::agent_chat::append_turn(
                                state.as_ref(),
                                &pid,
                                &tid,
                                "assistant",
                                content,
                            );
                        }
                    }
                    return Ok(axum::response::Response::from_parts(
                        parts,
                        axum::body::Body::from(bytes),
                    ));
                }
                Err(e) => {
                    return Err(crate::error::ConnectorError::internal(format!(
                        "failed to read completion response: {e}"
                    )));
                }
            }
        }
    }

    Ok(response)
}

/// GET /api/v1/agents/:pid/chat/threads — B15 list Talk threads.
pub async fn list_agent_chat_threads(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let threads = crate::kernel::agent_chat::list_threads(state.as_ref(), &pid);
    Json(json!({"ok": true, "agent_pid": pid, "threads": threads, "count": threads.len()}))
}

/// POST /api/v1/agents/:pid/chat/threads — B15 create thread.
pub async fn create_agent_chat_thread(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    if agent_principal::load_principal(state.as_ref(), &pid).is_none() {
        return Json(json!({"ok": false, "error": "unknown_principal"}));
    }
    let title = body.get("title").and_then(|t| t.as_str());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "chat",
        "create_chat_thread",
        &json!({"agent_pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let meta = crate::kernel::agent_chat::create_thread(state.as_ref(), &pid, title);
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "thread": meta,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /api/v1/agents/:pid/chat/threads/:thread_id — B15 get thread + turns.
pub async fn get_agent_chat_thread(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, thread_id)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match crate::kernel::agent_chat::get_thread(state.as_ref(), &pid, &thread_id) {
        Some(doc) => Json(json!({"ok": true, "thread": doc})),
        None => Json(json!({"ok": false, "error": "thread_not_found"})),
    }
}

/// GET /api/v1/agents/:pid/knot/summary — B21 Manage peek (not a full graph editor).
pub async fn get_agent_knot_summary(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let envelope = build_identity_envelope(state.as_ref(), &pid);
    Json(json!({
        "ok": true,
        "agent_pid": pid,
        "knot_summary": envelope.map(|e| e.knot_summary),
        "graph_routes": {
            "entities": "GET /api/v1/memory/graph/entities",
            "neighbors": "GET /api/v1/memory/graph/neighbors/:id",
            "add_entity": "POST /api/v1/memory/graph/entity",
            "add_edge": "POST /api/v1/memory/graph/edge",
        },
        "non_goals": "No DELETE/PATCH knot CRUD REST — Manage peek only (B21)",
    }))
}

/// GET /api/v1/agents/:pid/grants — B22 union of setup common_spaces + grant folder.
pub async fn list_agent_grants(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if !auth_operator_or_agent_self(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let setup_grants = load_setup(state.as_ref(), &pid)
        .map(|s| s.common_spaces)
        .unwrap_or_default();
    let mut folder_grants = Vec::new();
    if let Ok(es) = state.engine_store.lock() {
        let keys = es
            .folder_keys(crate::kernel::agent_identity_envelope::GRANT_FOLDER, None)
            .unwrap_or_default();
        for k in keys {
            if let Ok(Some(v)) =
                es.folder_get(crate::kernel::agent_identity_envelope::GRANT_FOLDER, &k)
            {
                if let Ok(g) = serde_json::from_value::<NamespaceGrantV2>(v) {
                    if g.readable_by.iter().any(|p| p == &pid)
                        || g.writable_by.iter().any(|p| p == &pid)
                        || k.contains(&pid)
                    {
                        folder_grants.push(g);
                    }
                }
            }
        }
    }
    Json(json!({
        "ok": true,
        "agent_pid": pid,
        "source_of_truth": "setup.common_spaces synced to namespace_grant_v2 + kernel on activate/grant",
        "setup_common_spaces": setup_grants,
        "grant_folder": folder_grants,
        "count": setup_grants.len().max(folder_grants.len()),
    }))
}
