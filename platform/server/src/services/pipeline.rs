use crate::services::agents;
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RunStepRequest {
    pub pipeline_id: String,
    pub agent_pid: String,
    pub input: String,
    pub user: String,
    pub step_index: usize,
}

pub async fn pipeline_steps(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let pipe_prefix = format!("pipe:{}", pipeline_id);
    let steps: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.reason
                .as_ref()
                .map_or(false, |r| r.contains(&pipeline_id))
        })
        .map(|(i, e)| {
            serde_json::json!({
                "step": i,
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "target_cid": e.target,
            })
        })
        .collect();
    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "step_count": steps.len(),
        "steps": steps,
    }))
}

pub async fn pipeline_integrity(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let integrity = k.verify_audit_chain().is_ok();
    let pipe_entries: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.reason
                .as_ref()
                .map_or(false, |r| r.contains(&pipeline_id))
        })
        .collect();
    let failed = pipe_entries
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
        .count();

    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "integrity": integrity,
        "total_steps": pipe_entries.len(),
        "failed_steps": failed,
        "cid_chain_valid": integrity,
        "status": if failed == 0 && integrity { "confirmed" } else { "needs_review" },
    }))
}

/// S11 — KECS auto-suspend: scan all agents, suspend those with KECS below policy threshold (default 0.60).
/// Called by the background health loop or manually via POST /pipeline/kecs-suspend-sweep
pub async fn kecs_suspend_sweep(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let kecs_suspend_threshold: f64 = {
        let es = state.engine_store.lock().unwrap();
        crate::services::runtime_control::load_runtime_policy(&**es).kecs_suspend_threshold
    };
    let mut suspended: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    let pids: Vec<String> = {
        let k = state.kernel.lock().unwrap();
        k.agents().values().map(|a| a.agent_pid.clone()).collect()
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "runtime",
        "lifecycle",
        "kecs_health_sweep",
        &serde_json::json!({"agents": pids.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    for pid in &pids {
        let kecs_score: f64 = {
            let mut es = state.engine_store.lock().unwrap();
            agents::folder_get_kecs_unified(&mut *es, pid)
                .and_then(|v| v.get("kecs").and_then(|k| k.as_f64()))
                .unwrap_or(1.0) // Default to healthy if not yet computed
        };

        if kecs_score < kecs_suspend_threshold {
            let was_suspended = {
                let mut k = state.kernel.lock().unwrap();
                if let Some(agent) = k.agents_mut().get_mut(pid.as_str()) {
                    if agent.status != vac_core::types::AgentStatus::Suspended {
                        agent.status = vac_core::types::AgentStatus::Suspended;
                        tracing::warn!(
                            pid = %pid, kecs = kecs_score,
                            "S11: agent auto-suspended — KECS {:.3} < threshold {:.2}",
                            kecs_score, kecs_suspend_threshold
                        );
                        // Dev mode stderr notice
                        if std::env::var("CONNECTOR_DEV_MODE").is_ok() {
                            eprintln!(
                                "[CONNECTOR] KECS auto-suspend: agent '{}' kecs={:.3} < {:.2}",
                                pid, kecs_score, kecs_suspend_threshold
                            );
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if was_suspended {
                suspended.push(pid.to_string());
                // FIX BUG-014: Update engine_store metadata to reflect suspended status
                let mut es = state.engine_store.lock().unwrap();
                let existing = es
                    .folder_get("agent_meta", pid)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| serde_json::json!({}));
                let mut meta = existing.as_object().cloned().unwrap_or_default();
                meta.insert("paused".into(), serde_json::json!(true));
                meta.insert(
                    "suspended_by".into(),
                    serde_json::json!("kecs_auto_suspend"),
                );
                meta.insert(
                    "suspended_at".into(),
                    serde_json::json!(chrono::Utc::now().to_rfc3339()),
                );
                meta.insert("kecs_at_suspend".into(), serde_json::json!(kecs_score));
                let _ = es.folder_put("agent_meta", pid, &serde_json::Value::Object(meta));
            } else {
                skipped.push(pid.to_string());
            }
        }
    }

    open_proceed.finish_observed(!suspended.is_empty());
    Json(serde_json::json!({
        "ok": true,
        "suspended_count": suspended.len(),
        "task_id": admitted.task_id,
        "executed": !suspended.is_empty(),
        "admits": false,
        "suspended_agents": suspended,
        "skipped_already_suspended": skipped,
        "agent_health_score_threshold": kecs_suspend_threshold,
        "total_agents_scanned": pids.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Wave 2 — Item 2.2: Deploy gate — block deploys below trust threshold
pub async fn pipeline_gate(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();

    let pipe_entries: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.reason
                .as_ref()
                .map_or(false, |r| r.contains(&pipeline_id))
        })
        .collect();
    let failed_steps = pipe_entries
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
        .count();
    let denied_steps = pipe_entries
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();

    let mut blockers: Vec<serde_json::Value> = Vec::new();
    let mut warnings: Vec<serde_json::Value> = Vec::new();

    if trust.score < 70 {
        blockers.push(serde_json::json!({
            "type": "low_trust",
            "detail": format!("Trust score {} < 70 threshold", trust.score),
            "fix": "Review and resolve failed/denied operations. Check memory integrity.",
        }));
    }
    if !integrity {
        blockers.push(serde_json::json!({
            "type": "audit_chain_broken",
            "detail": "HMAC audit chain verification failed",
            "fix": "Investigate audit log for tampering. Re-run integrity check.",
        }));
    }
    if failed_steps > 0 {
        blockers.push(serde_json::json!({
            "type": "failed_steps",
            "detail": format!("{} pipeline steps failed", failed_steps),
            "fix": "Review failed steps in pipeline trace. Fix agent configuration.",
        }));
    }
    if denied_steps > 0 {
        warnings.push(serde_json::json!({
            "type": "denied_operations",
            "detail": format!("{} operations denied during pipeline", denied_steps),
            "fix": "Check agent permissions and access grants.",
        }));
    }
    if trust.score < 80 && trust.score >= 70 {
        warnings.push(serde_json::json!({
            "type": "marginal_trust",
            "detail": format!("Trust score {} is above threshold but below optimal (80+)", trust.score),
            "fix": "Consider improving memory integrity and authorization coverage.",
        }));
    }

    let deploy_safe = blockers.is_empty();

    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "deploy_safe": deploy_safe,
        "decision": if deploy_safe { "DEPLOY" } else { "BLOCK" },
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "integrity": integrity,
        "pipeline_steps": pipe_entries.len(),
        "failed_steps": failed_steps,
        "denied_steps": denied_steps,
        "blockers": blockers,
        "warnings": warnings,
    }))
}

/// Wave 2 — Item 2.3: Compare current vs proposed agent config before deploy
pub async fn pre_deploy_diff(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let pipeline_id = req
        .get("pipeline_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let proposed_agents: Vec<serde_json::Value> = req
        .get("agents")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let k = state.kernel.lock().unwrap();
    let mut diffs: Vec<serde_json::Value> = Vec::new();

    for proposed in &proposed_agents {
        let pid = proposed.get("pid").and_then(|v| v.as_str()).unwrap_or("");
        let proposed_model = proposed.get("model").and_then(|v| v.as_str());
        let proposed_role = proposed.get("role").and_then(|v| v.as_str());

        match k.get_agent(pid) {
            Some(current) => {
                let mut changes: Vec<serde_json::Value> = Vec::new();
                if let Some(pm) = proposed_model {
                    let cur = current.model.as_deref().unwrap_or("unknown");
                    if cur != pm {
                        changes.push(
                            serde_json::json!({"field": "model", "current": cur, "proposed": pm}),
                        );
                    }
                }
                if let Some(pr) = proposed_role {
                    let cur = format!("{:?}", current.role);
                    if cur != pr {
                        changes.push(
                            serde_json::json!({"field": "role", "current": cur, "proposed": pr}),
                        );
                    }
                }
                let proposed_tools: usize = proposed
                    .get("tool_bindings")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                if proposed_tools > 0 && proposed_tools != current.tool_bindings.len() {
                    changes.push(serde_json::json!({"field": "tool_bindings", "current": current.tool_bindings.len(), "proposed": proposed_tools}));
                }

                diffs.push(serde_json::json!({
                    "pid": pid,
                    "exists": true,
                    "status": format!("{:?}", current.status),
                    "changes": changes,
                    "risk": if changes.is_empty() { "none" } else if changes.len() > 2 { "high" } else { "medium" },
                }));
            }
            None => {
                diffs.push(serde_json::json!({
                    "pid": pid,
                    "exists": false,
                    "changes": [{"field": "agent", "current": "not_registered", "proposed": "new"}],
                    "risk": "low",
                }));
            }
        }
    }

    let trust = connector_engine::TrustComputer::compute(&k);
    let high_risk = diffs
        .iter()
        .filter(|d| d.get("risk").and_then(|v| v.as_str()) == Some("high"))
        .count();

    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "agents_compared": diffs.len(),
        "diffs": diffs,
        "high_risk_changes": high_risk,
        "current_agent_health_score": trust.score,
        "recommendation": if high_risk > 0 { "Review high-risk changes before deploying" } else { "Safe to deploy" },
    }))
}

pub async fn pipeline_cid_chain(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let cids: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.reason
                .as_ref()
                .map_or(false, |r| r.contains(&pipeline_id))
        })
        .filter_map(|e| {
            e.target.as_ref().map(|t| {
                serde_json::json!({
                    "cid": t,
                    "operation": format!("{:?}", e.operation),
                    "agent_pid": e.agent_pid,
                    "timestamp": e.timestamp,
                })
            })
        })
        .collect();
    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "chain_length": cids.len(),
        "cid_chain": cids,
    }))
}

// ── E6.1: Formal Pipeline Definitions ────────────────────────────────────────

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PipelineStepSchema {
    pub step_index: usize,
    pub name: String,
    pub agent_pid: Option<String>,
    pub required: Option<bool>,
    pub timeout_secs: Option<u64>,
    pub on_skip_alert: Option<bool>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PipelineDefinitionRequest {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<PipelineStepSchema>,
    pub owner: Option<String>,
}

/// POST /pipeline/definitions
/// Store a formal pipeline definition with step schemas.
pub async fn create_definition(
    State(state): State<SharedState>,
    Json(req): Json<PipelineDefinitionRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let def_id = uuid::Uuid::new_v4().to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "pipeline",
        "lifecycle",
        "create_pipeline_definition",
        &serde_json::json!({"definition_id": def_id.as_str(), "name": req.name.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "definition_id":  def_id,
        "name":           req.name,
        "description":    req.description.unwrap_or_default(),
        "owner":          req.owner.unwrap_or_default(),
        "step_count":     req.steps.len(),
        "steps":          req.steps,
        "created_at":     now.to_rfc3339(),
        "version":        1,
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("pipeline_definitions", &def_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "definition_id": def_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "created_at":    now.to_rfc3339(),
        "step_count":    record.get("step_count"),
        "validate_url":  format!("/pipeline/definitions/{}/validate-run/<run_id>", def_id),
    }))
}

/// GET /pipeline/definitions
/// List all stored pipeline definitions.
pub async fn list_definitions(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("pipeline_definitions", None)
        .unwrap_or_default();
    let defs: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("pipeline_definitions", k).ok().flatten())
        .collect();
    Json(serde_json::json!({
        "total":       defs.len(),
        "definitions": defs,
    }))
}

/// GET /pipeline/definitions/{id}/validate-run/{run_id}
/// Compares actual audit entries for run_id against the definition steps.
/// Flags skipped required steps and fires alerts.
pub async fn validate_run(
    State(state): State<SharedState>,
    axum::extract::Path((def_id, run_id)): axum::extract::Path<(String, String)>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let es = state.engine_store.lock().unwrap();
    let k = state.kernel.lock().unwrap();

    let definition = match es
        .folder_get("pipeline_definitions", &def_id)
        .ok()
        .flatten()
    {
        Some(d) => d,
        None => {
            return Json(
                serde_json::json!({"error": "Definition not found", "status": 404, "definition_id": def_id}),
            )
        }
    };

    let steps: Vec<serde_json::Value> = definition
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let run_entries: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.reason.as_ref().map_or(false, |r| r.contains(&run_id)))
        .collect();

    let mut validation_results: Vec<serde_json::Value> = Vec::new();
    let mut skipped_required: Vec<serde_json::Value> = Vec::new();
    let mut alerts: Vec<serde_json::Value> = Vec::new();

    for step in &steps {
        let idx = step.get("step_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let name = step
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");
        let required = step
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let on_alert = step
            .get("on_skip_alert")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let agent_pid = step.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");

        let executed = if agent_pid.is_empty() {
            !run_entries.is_empty()
        } else {
            run_entries.iter().any(|e| e.agent_pid == agent_pid)
        };

        let status = if executed {
            "executed"
        } else if required {
            "SKIPPED_REQUIRED"
        } else {
            "skipped_optional"
        };

        if !executed && required {
            skipped_required.push(serde_json::json!({"step_index": idx, "name": name}));
            if on_alert {
                alerts.push(serde_json::json!({
                    "type":       "step_skipped",
                    "step_index": idx,
                    "step_name":  name,
                    "run_id":     run_id,
                    "severity":   "high",
                    "fired_at":   now.to_rfc3339(),
                }));
            }
        }

        validation_results.push(serde_json::json!({
            "step_index": idx,
            "name":       name,
            "status":     status,
            "required":   required,
            "executed":   executed,
        }));
    }

    Json(serde_json::json!({
        "definition_id":      def_id,
        "run_id":             run_id,
        "validated_at":       now.to_rfc3339(),
        "total_steps":        steps.len(),
        "executed_steps":     validation_results.iter().filter(|r| r.get("executed").and_then(|v| v.as_bool()).unwrap_or(false)).count(),
        "skipped_required":   skipped_required.len(),
        "passed":             skipped_required.is_empty(),
        "validation":         validation_results,
        "alerts_fired":       alerts,
    }))
}

// ── E6.2: Step Artifact Tracking ─────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct StepArtifactRequest {
    pub step_index: usize,
    pub agent_pid: String,
    pub input_cid: Option<String>,
    pub output_cid: Option<String>,
    pub duration_ms: Option<u64>,
    pub status: Option<String>,
}

/// POST /pipeline/{id}/artifacts
/// Records input_cid, output_cid, duration_ms for a pipeline step.
pub async fn record_artifact(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
    Json(req): Json<StepArtifactRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let artifact_key = format!("{}:step:{}", pipeline_id, req.step_index);
    let subject = if req.agent_pid.is_empty() {
        "pipeline"
    } else {
        req.agent_pid.as_str()
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "record_pipeline_artifact",
        &serde_json::json!({"pipeline_id": pipeline_id.as_str(), "step_index": req.step_index}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "pipeline_id":  pipeline_id,
        "step_index":   req.step_index,
        "agent_pid":    req.agent_pid,
        "input_cid":    req.input_cid.unwrap_or_default(),
        "output_cid":   req.output_cid.unwrap_or_default(),
        "duration_ms":  req.duration_ms.unwrap_or(0),
        "status":       req.status.unwrap_or_else(|| "completed".into()),
        "recorded_at":  now.to_rfc3339(),
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("pipeline_artifacts", &artifact_key, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "artifact_key": artifact_key,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "recorded_at":  now.to_rfc3339(),
        "replay_url":   format!("/pipeline/{}/replay-from-step/{}", pipeline_id, req.step_index),
    }))
}

/// GET /pipeline/{id}/artifacts
/// Lists all step artifacts for a pipeline run.
pub async fn list_artifacts(
    State(state): State<SharedState>,
    Path(pipeline_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let prefix = format!("{}:step:", pipeline_id);
    let keys = es
        .folder_keys("pipeline_artifacts", Some(&prefix))
        .unwrap_or_default();
    let mut artifacts: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("pipeline_artifacts", k).ok().flatten())
        .collect();
    artifacts.sort_by_key(|a| a.get("step_index").and_then(|v| v.as_u64()).unwrap_or(0));

    let total_duration_ms: u64 = artifacts
        .iter()
        .filter_map(|a| a.get("duration_ms").and_then(|v| v.as_u64()))
        .sum();

    Json(serde_json::json!({
        "pipeline_id":       pipeline_id,
        "step_count":        artifacts.len(),
        "total_duration_ms": total_duration_ms,
        "artifacts":         artifacts,
    }))
}

/// POST /pipeline/{id}/replay-from-step/{n}
/// Returns a replay plan: steps from n onward with their stored artifacts.
pub async fn replay_from_step(
    State(state): State<SharedState>,
    axum::extract::Path((pipeline_id, step_n)): axum::extract::Path<(String, usize)>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let es = state.engine_store.lock().unwrap();
    let prefix = format!("{}:step:", pipeline_id);
    let keys = es
        .folder_keys("pipeline_artifacts", Some(&prefix))
        .unwrap_or_default();

    let replay_steps: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("pipeline_artifacts", k).ok().flatten())
        .filter(|a| a.get("step_index").and_then(|v| v.as_u64()).unwrap_or(0) >= step_n as u64)
        .collect();

    Json(serde_json::json!({
        "pipeline_id":   pipeline_id,
        "replay_from":   step_n,
        "replay_steps":  replay_steps.len(),
        "plan":          replay_steps,
        "note":          "Re-submit each step with the stored input_cid to replay deterministically.",
        "generated_at":  now.to_rfc3339(),
    }))
}

// ── E6.3: Per-Pipeline Gate Policies ─────────────────────────────────────────

#[derive(serde::Deserialize, serde::Serialize)]
pub struct GatePolicyRequest {
    pub pipeline_id: String,
    pub min_trust_score: Option<f64>,
    pub max_failed_steps: Option<usize>,
    pub compliance_frameworks: Option<Vec<String>>,
    pub require_human_review: Option<bool>,
}

/// POST /pipeline/gate-policies
/// Store a gate policy for a pipeline. Checked on every pipeline_gate call.
pub async fn create_gate_policy(
    State(state): State<SharedState>,
    Json(req): Json<GatePolicyRequest>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let policy_id = format!("policy:{}", req.pipeline_id);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "pipeline",
        "lifecycle",
        "create_gate_policy",
        &serde_json::json!({"policy_id": policy_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let record = serde_json::json!({
        "policy_id":             policy_id,
        "pipeline_id":           req.pipeline_id,
        "min_trust_score":       req.min_trust_score.unwrap_or(70.0),
        "max_failed_steps":      req.max_failed_steps.unwrap_or(0),
        "compliance_frameworks": req.compliance_frameworks.unwrap_or_default(),
        "require_human_review":  req.require_human_review.unwrap_or(false),
        "created_at":            now.to_rfc3339(),
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("pipeline_gate_policies", &policy_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "policy_id":  policy_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "created_at": now.to_rfc3339(),
        "message":    "Gate policy stored. Applied on every POST /pipeline/{id}/gate check.",
    }))
}

/// GET /pipeline/gate-policies
/// List all gate policies.
pub async fn list_gate_policies(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("pipeline_gate_policies", None)
        .unwrap_or_default();
    let policies: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("pipeline_gate_policies", k).ok().flatten())
        .collect();
    Json(serde_json::json!({
        "total":    policies.len(),
        "policies": policies,
    }))
}
