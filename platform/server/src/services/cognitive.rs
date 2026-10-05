//! Cognitive Pipeline — P1 gap exposure
//!
//! Exposes the full cognitive loop from connector-engine:
//! - PerceptionEngine: observe + perceive
//! - LogicEngine: plan, complete_step, reflect, record_reasoning
//! - BindingEngine: cognitive_cycle
//! - JudgmentEngine: configurable profiles (default, medical, financial)

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::judgment::{JudgmentConfig, JudgmentEngine};
use connector_engine::logic::LogicEngine;
use connector_engine::perception::{ObservationConfig, PerceptionEngine};
use serde::Deserialize;

fn resolve_agent_pid(state: &SharedState, pid: &str) -> String {
    let es = state.engine_store.lock().unwrap();
    es.folder_get("agent_meta", pid)
        .ok()
        .flatten()
        .and_then(|m| {
            m.get("kernel_pid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| pid.to_string())
}

fn resolve_namespace(state: &SharedState, pid: &str) -> String {
    let kernel_pid = resolve_agent_pid(state, pid);
    let k = state.kernel.lock().unwrap();
    k.get_agent(&kernel_pid)
        .map(|a| a.namespace.clone())
        .unwrap_or_else(|| format!("ns:{}", pid.split(':').last().unwrap_or(pid)))
}

// ── Perceive ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ObserveRequest {
    pub agent_pid: String,
    pub input: String,
    pub user: String,
    #[serde(default = "default_pipeline")]
    pub pipeline: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub extract_claims: bool,
    #[serde(default = "default_profile")]
    pub judgment_profile: String,
}
fn default_pipeline() -> String {
    "default".into()
}
fn default_profile() -> String {
    "default".into()
}

/// POST /cognitive/observe
/// Observe raw input through PerceptionEngine:
/// write to kernel, entity extract, claim verify, quality score (0-100), grade (A+→F)
pub async fn observe(
    State(state): State<SharedState>,
    Json(req): Json<ObserveRequest>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let profile = match req.judgment_profile.as_str() {
        "medical" => JudgmentConfig::medical(),
        "financial" => JudgmentConfig::financial(),
        _ => JudgmentConfig::default(),
    };

    let obs_config = ObservationConfig {
        extract_claims: req.extract_claims,
        judgment_profile: profile,
        ..ObservationConfig::default()
    };

    let grounding_lock = state.grounding.lock().unwrap();
    let grounding_ref = Some(&*grounding_lock);
    let mut k = state.kernel.lock().unwrap();
    match PerceptionEngine::observe(
        &mut k,
        &kernel_pid,
        &req.input,
        &req.user,
        &req.pipeline,
        req.session_id.as_deref(),
        None,
        grounding_ref,
        &obs_config,
    ) {
        Ok(obs) => Json(serde_json::json!({
            "ok": true,
            "cid": obs.cid,
            "entities": obs.entities,
            "quality_score": obs.quality_score,
            "quality_grade": obs.quality_grade,
            "claims": obs.claims,
            "warnings": obs.warnings,
            "timestamp": obs.timestamp,
            "judgment_profile": req.judgment_profile,
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// GET /cognitive/context/:agent_pid
/// Retrieve perceived context for current agent state
pub async fn perceived_context(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ContextQuery>,
) -> Json<serde_json::Value> {
    let profile = match q.judgment_profile.as_deref() {
        Some("medical") => JudgmentConfig::medical(),
        Some("financial") => JudgmentConfig::financial(),
        _ => JudgmentConfig::default(),
    };
    let limit = q.limit.unwrap_or(50);
    let k = state.kernel.lock().unwrap();
    // perceive(kernel, namespace, session_id, limit, config)
    let namespace = resolve_namespace(&state, &agent_pid);
    let ctx = PerceptionEngine::perceive(&k, &namespace, q.session_id.as_deref(), limit, &profile);
    Json(serde_json::json!({
        "ok": true,
        "agent_pid": agent_pid,
        "namespace": ctx.namespace,
        "memories": ctx.memories.iter().map(|m| serde_json::json!({
            "cid": m.cid,
            "text": m.text,
            "type": m.packet_type,
            "timestamp": m.timestamp,
            "entities": m.entities,
            "tags": m.tags,
            "tier": m.tier,
            "session_id": m.session_id,
        })).collect::<Vec<_>>(),
        "total_found": ctx.total_found,
        "active_session": ctx.active_session,
        "judgment": {
            "score": ctx.judgment.score,
            "grade": ctx.judgment.grade,
            "explanation": ctx.judgment.explanation,
            "dimensions": {
                "cid_integrity": ctx.judgment.dimensions.cid_integrity,
                "audit_coverage": ctx.judgment.dimensions.audit_coverage,
                "access_control": ctx.judgment.dimensions.access_control,
                "evidence_quality": ctx.judgment.dimensions.evidence_quality,
                "claim_coverage": ctx.judgment.dimensions.claim_coverage,
                "temporal_freshness": ctx.judgment.dimensions.temporal_freshness,
                "contradiction_score": ctx.judgment.dimensions.contradiction_score,
                "source_credibility": ctx.judgment.dimensions.source_credibility,
            },
            "warnings": ctx.judgment.warnings,
        },
    }))
}

#[derive(Deserialize)]
pub struct ContextQuery {
    pub judgment_profile: Option<String>,
    pub session_id: Option<String>,
    pub limit: Option<usize>,
}

// ── Logic / Planning ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PlanRequest {
    pub agent_pid: String,
    pub goal: String,
    pub steps: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<(usize, usize)>,
}

/// POST /cognitive/plan
/// Create a dependency-aware execution plan, CID-backed in kernel
pub async fn create_plan(
    State(state): State<SharedState>,
    Json(req): Json<PlanRequest>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let step_refs: Vec<&str> = req.steps.iter().map(|s| s.as_str()).collect();
    let mut k = state.kernel.lock().unwrap();
    match LogicEngine::plan(
        &mut k,
        &kernel_pid,
        &req.goal,
        &step_refs,
        &req.dependencies,
    ) {
        Ok(plan) => Json(serde_json::json!({
            "ok": true,
            "goal": plan.goal,
            "plan_cid": plan.plan_cid,
            "step_count": plan.steps.len(),
            "steps": plan.steps.iter().map(|s| serde_json::json!({
                "index": s.index,
                "description": s.description,
                "dependencies": s.dependencies,
                "status": format!("{}", s.status),
            })).collect::<Vec<_>>(),
            "current_step": plan.current_step,
            "progress": plan.progress(),
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize)]
pub struct ReasoningStepRequest {
    pub agent_pid: String,
    pub thought: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub evidence_cids: Vec<String>,
}

/// POST /cognitive/reasoning/step
/// Record a reasoning step — every step persisted as kernel packet with evidence CIDs
pub async fn record_reasoning_step(
    State(state): State<SharedState>,
    Json(req): Json<ReasoningStepRequest>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let mut k = state.kernel.lock().unwrap();
    let mut chain = connector_engine::logic::ReasoningChain::new(&req.thought);
    match LogicEngine::record_reasoning_step(
        &mut k,
        &kernel_pid,
        &mut chain,
        &req.thought,
        req.action.as_deref(),
        req.result.as_deref(),
        req.evidence_cids.clone(),
    ) {
        Ok(()) => {
            let step = chain.steps.last().unwrap();
            Json(serde_json::json!({
                "ok": true,
                "step_number": step.step_number,
                "thought": step.thought,
                "action": step.action,
                "result": step.result,
                "cid": step.cid,
                "evidence_cids": step.evidence_cids,
            }))
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize)]
pub struct ConclusionRequest {
    pub agent_pid: String,
    pub conclusion: String,
    pub confidence: f64,
    #[serde(default)]
    pub evidence_cids: Vec<String>,
}

/// POST /cognitive/reasoning/conclude
/// Record conclusion + confidence → Decision packet in kernel
pub async fn record_conclusion(
    State(state): State<SharedState>,
    Json(req): Json<ConclusionRequest>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let mut k = state.kernel.lock().unwrap();
    let mut chain = connector_engine::logic::ReasoningChain::new(&req.conclusion);
    chain.all_evidence_cids = req.evidence_cids.clone();
    match LogicEngine::record_conclusion(
        &mut k,
        &kernel_pid,
        &mut chain,
        &req.conclusion,
        req.confidence,
    ) {
        Ok(cid) => Json(serde_json::json!({
            "ok": true,
            "cid": cid,
            "conclusion": req.conclusion,
            "confidence": req.confidence,
            "evidence_cids": req.evidence_cids,
            "packet_type": "Decision",
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

// ── Judgment ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct JudgmentRequest {
    pub agent_pid: String,
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// POST /cognitive/judgment
/// Run 8-dimension quality judgment on an agent's kernel state
pub async fn run_judgment(
    State(state): State<SharedState>,
    Json(req): Json<JudgmentRequest>,
) -> Json<serde_json::Value> {
    let profile = match req.profile.as_str() {
        "medical" => JudgmentConfig::medical(),
        "financial" => JudgmentConfig::financial(),
        _ => JudgmentConfig::default(),
    };
    let k = state.kernel.lock().unwrap();
    // judge_kernel uses default config; for profile use judge(kernel, None, config)
    let result = JudgmentEngine::judge(&k, None, &profile);
    Json(serde_json::json!({
        "agent_pid": req.agent_pid,
        "profile": req.profile,
        "score": result.score,
        "grade": result.grade,
        "explanation": result.explanation,
        "operations_analyzed": result.operations_analyzed,
        "dimensions": {
            "cid_integrity": result.dimensions.cid_integrity,
            "audit_coverage": result.dimensions.audit_coverage,
            "access_control": result.dimensions.access_control,
            "evidence_quality": result.dimensions.evidence_quality,
            "claim_coverage": result.dimensions.claim_coverage,
            "temporal_freshness": result.dimensions.temporal_freshness,
            "contradiction_score": result.dimensions.contradiction_score,
            "source_credibility": result.dimensions.source_credibility,
        },
        "weighted": {
            "cid_integrity": result.weighted.cid_integrity,
            "audit_coverage": result.weighted.audit_coverage,
            "evidence_quality": result.weighted.evidence_quality,
            "claim_coverage": result.weighted.claim_coverage,
        },
        "warnings": result.warnings,
    }))
}

// ── Full Cognitive Cycle ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CognitiveCycleRequest {
    pub agent_pid: String,
    pub input: String,
    pub user: String,
    #[serde(default = "default_pipeline")]
    pub pipeline: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub goal: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default = "default_profile")]
    pub judgment_profile: String,
}

/// POST /cognitive/cycle
/// Full perceive → retrieve → reason → reflect → act loop in one call
pub async fn cognitive_cycle(
    State(state): State<SharedState>,
    Json(req): Json<CognitiveCycleRequest>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let step_refs: Vec<&str> = req.steps.iter().map(|s| s.as_str()).collect();
    let mut binding = state.binding.lock().unwrap();
    let mut k = state.kernel.lock().unwrap();
    match binding.cognitive_cycle(
        &mut k,
        &kernel_pid,
        &req.input,
        &req.user,
        &req.pipeline,
        req.session_id.as_deref(),
        None,
        &req.goal,
        &step_refs,
    ) {
        Ok(summary) => Json(serde_json::json!({
            "ok": true,
            "cycle_number": summary.cycle_number,
            "phase": summary.phase,
            "observation_cid": summary.observation_cid,
            "facts_retrieved": summary.facts_retrieved,
            "reasoning_steps": summary.reasoning_steps,
            "quality_score": summary.quality_score,
            "contradiction_detected": summary.contradiction_detected,
            "decision_cid": summary.decision_cid,
            "warnings": summary.warnings,
            "agent_pid": req.agent_pid,
            "goal": req.goal,
        })),
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// GET /cognitive/report/:agent_pid
/// Get cognitive session report for an agent
pub async fn cognitive_report(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let binding = state.binding.lock().unwrap();
    let namespace = resolve_namespace(&state, &agent_pid);
    let report = binding.report(&agent_pid, &namespace);
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "total_cycles": report.total_cycles,
        "total_observations": report.total_observations,
        "total_reasoning_steps": report.total_reasoning_steps,
        "total_decisions": report.total_decisions,
        "contradictions_detected": report.contradictions_detected,
        "compilations": report.compilations,
        "final_quality_score": report.final_quality_score,
        "cycles": report.cycles.iter().map(|c| serde_json::json!({
            "cycle_number": c.cycle_number,
            "phase": c.phase,
            "observation_cid": c.observation_cid,
            "facts_retrieved": c.facts_retrieved,
            "reasoning_steps": c.reasoning_steps,
            "quality_score": c.quality_score,
            "contradiction_detected": c.contradiction_detected,
            "decision_cid": c.decision_cid,
        })).collect::<Vec<_>>(),
    }))
}
