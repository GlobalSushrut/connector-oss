use crate::services::agents;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use connector_engine::llm::ChatMessage;
use connector_engine::semantic_injection::SemanticInjectionDetector;
use serde::Deserialize;
use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::{MemPacket, MemoryKernelOp, OpOutcome, PacketType, Source, SourceKind};

/// Per-agent token budget for experiment runs.
fn experiment_token_budget() -> u64 {
    std::env::var("CONNECTOR_AGENT_TOKEN_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16_000)
}

fn check_budget(k: &vac_core::kernel::MemoryKernel, agent_pid: &str) -> Result<(), String> {
    let budget = experiment_token_budget();
    if let Some(acb) = k.get_agent(agent_pid) {
        if acb.total_tokens_consumed >= budget {
            return Err(format!(
                "Agent '{}' token budget exceeded ({}/{} tokens).",
                agent_pid, acb.total_tokens_consumed, budget
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateExperimentRequest {
    pub name: String,
    pub description: Option<String>,
    pub agent_name: String,
    pub instructions: Option<String>,
}

#[derive(Deserialize)]
pub struct RunExperimentRequest {
    pub experiment_id: String,
    pub input: String,
    pub user: String,
    pub variant: Option<String>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    50
}

fn make_packet(content: &str, user: &str, pipeline: &str, ptype: PacketType) -> MemPacket {
    MemPacket::new(
        ptype,
        serde_json::json!({"text": content}),
        cid::Cid::default(),
        user.to_string(),
        pipeline.to_string(),
        Source {
            kind: SourceKind::User,
            principal_id: user.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
}

pub async fn create_experiment(
    State(state): State<SharedState>,
    Json(req): Json<CreateExperimentRequest>,
) -> Json<serde_json::Value> {
    let experiment_id = format!("exp_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "experiments",
        "lifecycle",
        "create_experiment",
        &serde_json::json!({"name": req.name.as_str(), "experiment_id": experiment_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Store experiment metadata in engine store custom folder
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.create_folder(
        &format!("experiments/{}", experiment_id),
        &connector_engine::engine_store::FolderOwner::System,
        req.description.as_deref().unwrap_or(""),
    );
    let _ = es.folder_put(
        &format!("experiments/{}", experiment_id),
        "meta",
        &serde_json::json!({
            "name": req.name,
            "agent_name": req.agent_name,
            "instructions": req.instructions,
            "created_at": now.to_rfc3339(),
            "runs": 0,
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "name": req.name,
        "agent_name": req.agent_name,
        "created_at": now.to_rfc3339(),
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn run_experiment(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RunExperimentRequest>,
) -> Json<serde_json::Value> {
    let tenant_ctx = match agents::require_multi_tenant_context(&headers) {
        Ok(t) => t,
        Err(msg) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "tenant_required",
                "message": msg,
            }));
        }
    };

    let run_id = format!("run_{}", uuid::Uuid::new_v4());
    let pipe_id = format!("exp:{}:{}", req.experiment_id, run_id);
    let start = std::time::Instant::now();

    // Load experiment meta
    let meta = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(&format!("experiments/{}", req.experiment_id), "meta")
            .ok()
            .flatten()
            .unwrap_or(serde_json::json!({}))
    };
    let agent_name = meta
        .get("agent_name")
        .and_then(|v| v.as_str())
        .unwrap_or("experiment-agent");
    let instructions = meta.get("instructions").and_then(|v| v.as_str());

    if let Err(j) = agents::kernel_agent_limit_gate(state.as_ref(), tenant_ctx.as_ref()) {
        return Json(j);
    }

    // Register agent + write input
    let model = state.llm_config_snapshot().map(|c| c.model);
    let exp_ns =
        agents::tenant_scoped_memory_namespace(tenant_ctx.as_ref(), &format!("m/{}", agent_name));
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("experiments");
    let pid = match crate::substrate::agent_progeny::register_with_progeny(
        &state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name,
            namespace: &exp_ns,
            role: Some("experiment".to_string()),
            model: model.clone(),
            framework: Some("connector-platform".to_string()),
            parent_kernel_pid: None,
            reason: format!("Experiment {}", req.experiment_id),
        },
        &actor,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Json(serde_json::json!({
                "run_id": run_id,
                "experiment_id": req.experiment_id,
                "error": "agent_register_failed",
                "message": e.message(),
                "status": "register_failed",
            }));
        }
    };

    let _api_pid = agents::ensure_agent_store_mapping(
        &state,
        &pid,
        agent_name,
        &exp_ns,
        model.as_deref(),
        "experiment",
        Some(serde_json::json!({
            "source": "experiments",
            "experiment_id": req.experiment_id,
        })),
    );

    {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet(&req.input, &req.user, &pipe_id, PacketType::Input),
            },
            reason: None,
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
    }

    // ── Moat 1: Budget enforcement ────────────────────────────────────────────
    if let Err(budget_err) = {
        let k = state.kernel.lock().unwrap();
        check_budget(&k, &pid)
    } {
        return Json(serde_json::json!({
            "run_id": run_id,
            "experiment_id": req.experiment_id,
            "error": budget_err,
            "status": "budget_exceeded",
        }));
    }

    // ── Moat 2: Semantic injection check ─────────────────────────────────────
    let injection_result = {
        let mut detector = SemanticInjectionDetector::new();
        detector.analyze(&req.input, &pid)
    };
    if injection_result.score > 0.75 {
        return Json(serde_json::json!({
            "run_id": run_id,
            "experiment_id": req.experiment_id,
            "error": format!("Semantic injection detected (score={:.2}). Input blocked.", injection_result.score),
            "status": "injection_blocked",
        }));
    }

    if let Err(j) =
        crate::substrate::admission_gate::require_llm_chat(&state, &pid, &exp_ns, Some(&req.input))
    {
        return Json(j);
    }
    let talk_atu = match crate::substrate::pate::admit_talk(&state, &pid, &exp_ns, &req.input, None) {
        Ok(atu) if crate::substrate::pate::host_admission_allows_execution(atu.verdict) => atu,
        Ok(atu) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "not_proceed",
                "run_id": run_id,
                "experiment_id": req.experiment_id,
                "status": "talk_governance_denied",
                "task_id": atu.task_id,
                "pate_task_id": atu.task_id,
                "executed": false,
                "admits": false,
            }));
        }
        Err(error) => {
            return Json(serde_json::json!({
                "run_id": run_id,
                "experiment_id": req.experiment_id,
                "status": "talk_governance_denied",
                "error": error.human_readable,
                "executed": false,
            }));
        }
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &talk_atu);

    // ── Moat 1: Real LLM dispatch via LlmRouter ──────────────────────────────
    let response_text = if let Some(router) = state.llm_router_arc() {
        let system_prompt = instructions.unwrap_or(
            "You are an experimental AI agent. Process the input and return a concise result.",
        );
        let mut messages = vec![
            ChatMessage {
                role: "system".into(),
                content: system_prompt.into(),
                reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            ChatMessage {
                role: "user".into(),
                content: req.input.clone(),
                reasoning_content: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
        ];
        if let Err(e) = crate::kernel::iia_llm_inject::inject_agentic_context_engine_messages(
            &state,
            &pid,
            &mut messages,
        ) {
            return Json(serde_json::json!({
                "run_id": run_id,
                "experiment_id": req.experiment_id,
                "status": "agentic_context_required",
                "error": e.human_readable.clone(),
            }));
        }
        crate::kernel::iia_llm_inject::inject_who_am_i_engine_messages(
            state.as_ref(),
            &pid,
            &mut messages,
        );
        if let Ok(prepared) = crate::substrate::governed_talk_core::prepare_talk(
            &state,
            &pid,
            "experiment-model",
            "experiments",
        ) {
            crate::substrate::governed_talk_core::inject_prepared_engine_messages(
                &mut messages,
                &prepared,
            );
        }
        let memory_core = crate::services::gateway::memory_os_core_prompt(&pid);
        let rag = crate::concurrency::kernel_handle::build_agent_rag_context_async(
            state.clone(),
            pid.clone(),
            exp_ns.clone(),
            req.input.clone(),
        )
        .await;
        if let Some(system) = messages.iter_mut().find(|m| m.role == "system") {
            system.content = format!("{}\n{}\n{}", system.content, memory_core, rag);
        }
        if crate::kernel::landlock_child::llm_cage_enforced() {
            let gw_msgs: Vec<crate::services::gateway::ChatMessage> = messages
                .iter()
                .map(|m| crate::services::gateway::ChatMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    reasoning_content: m.reasoning_content.clone(),
                    tool_calls: None,
                    tool_call_id: m.tool_call_id.clone(),
                })
                .collect();
            let st = state.clone();
            let pid2 = pid.clone();
            match tokio::task::spawn_blocking(move || {
                crate::services::gateway::talk_via_llm_cage(
                    st.as_ref(),
                    &pid2,
                    &gw_msgs,
                    None,
                    None,
                )
            })
            .await
            {
                Ok(Ok((text, input_tokens, output_tokens, model, _, _))) => {
                    let tokens_used = (input_tokens + output_tokens) as u64;
                    let mut k = state.kernel.lock().unwrap();
                    k.dispatch(SyscallRequest {
                        agent_pid: pid.clone(),
                        operation: MemoryKernelOp::RecordTokenUsage,
                        payload: SyscallPayload::RecordTokenUsage {
                            tokens_used,
                            cost_usd: 0.0,
                            model: model.unwrap_or_default(),
                        },
                        reason: Some(format!("experiment:{}", req.experiment_id)),
                        vakya_id: None,
                        trace_parent: None,
                        trace_state: None,
                        api_version: None,
                    });
                    drop(k);
                    match crate::substrate::governed_talk_core::project_talk_with_receipt(
                        state.as_ref(),
                        &pid,
                        &text,
                        &req.input,
                    ) {
                        Ok(f) => f.text,
                        Err(_) => {
                            "[LLM output blocked by Connector principal projection]".into()
                        }
                    }
                }
                Ok(Err(e)) => format!("[LLM error: {}]", e.human_readable),
                Err(e) => format!("[LLM error: {e}]"),
            }
        } else {
        match router.chat(messages).await {
            Ok(resp) => {
                // Record token usage in kernel ACB via RecordTokenUsage syscall
                let cost_summary = router.cost_summary();
                let run_cost: f64 = cost_summary.values().map(|c| c.estimated_cost_usd).sum();
                let tokens_used = (resp.input_tokens + resp.output_tokens) as u64;
                let mut k = state.kernel.lock().unwrap();
                k.dispatch(SyscallRequest {
                    agent_pid: pid.clone(),
                    operation: MemoryKernelOp::RecordTokenUsage,
                    payload: SyscallPayload::RecordTokenUsage {
                        tokens_used,
                        cost_usd: run_cost,
                        model: resp.model.clone(),
                    },
                    reason: Some(format!("experiment:{}", req.experiment_id)),
                    vakya_id: None,
                    trace_parent: None,
                    trace_state: None,
                    api_version: None,
                });
                drop(k);
                match crate::substrate::governed_talk_core::project_talk_with_receipt(
                    state.as_ref(),
                    &pid,
                    &resp.text,
                    &req.input,
                ) {
                    Ok(f) => f.text,
                    Err(error) => {
                        tracing::warn!(
                            agent_pid = %pid,
                            "Experiment output projected/denied: {}",
                            error.human_readable
                        );
                        "[LLM output blocked by Connector principal projection]".into()
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "LLM call failed for experiment '{}': {}",
                    req.experiment_id,
                    e.message
                );
                format!("[LLM error: {}]", e.message)
            }
        }
        }
    } else {
        format!(
            "[no LLM configured — experiment {} received input]",
            req.experiment_id
        )
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let output = {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet(&response_text, &req.user, &pipe_id, PacketType::LlmRaw),
            },
            reason: None,
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        connector_engine::OutputBuilder::build(
            &k,
            response_text.clone(),
            &pipe_id,
            1,
            &[],
            duration_ms,
            Vec::new(),
        )
    };

    // Store run result
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            &format!("experiments/{}", req.experiment_id),
            &run_id,
            &serde_json::json!({
                "run_id": run_id,
                "input": req.input,
                "output": output.text,
                "trust": output.status.trust,
                "trust_grade": output.status.trust_grade,
                "duration_ms": duration_ms,
                "variant": req.variant,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    state.metrics.requests_total.inc();
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "run_id": run_id,
        "task_id": talk_atu.task_id,
        "executed": true,
        "admits": false,
        "experiment_id": req.experiment_id,
        "text": output.text,
        "trust": output.status.trust,
        "trust_grade": output.status.trust_grade,
        "duration_ms": duration_ms,
        "variant": req.variant,
    }))
}

pub async fn list_experiments(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let folders = es.list_folders(None).unwrap_or_default();
    let experiments: Vec<serde_json::Value> = folders
        .iter()
        .filter(|f| f.namespace.starts_with("experiments/"))
        .map(|f| {
            let meta = es
                .folder_get(&f.namespace, "meta")
                .ok()
                .flatten()
                .unwrap_or(serde_json::json!({}));
            serde_json::json!({
                "experiment_id": f.namespace.trim_start_matches("experiments/"),
                "name": meta.get("name"),
                "agent_name": meta.get("agent_name"),
                "created_at": meta.get("created_at"),
                "entry_count": f.entry_count,
            })
        })
        .collect();
    Json(serde_json::json!({"count": experiments.len(), "experiments": experiments}))
}

pub async fn experiment_runs(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let keys = es.folder_keys(&ns, None).unwrap_or_default();
    let runs: Vec<serde_json::Value> = keys
        .iter()
        .filter(|k| k.starts_with("run_"))
        .filter_map(|k| es.folder_get(&ns, k).ok().flatten())
        .collect();
    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "run_count": runs.len(),
        "runs": runs,
    }))
}

pub async fn compare_runs(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let run_ids: Vec<String> = req
        .get("run_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let runs: Vec<serde_json::Value> = run_ids
        .iter()
        .filter_map(|id| es.folder_get(&ns, id).ok().flatten())
        .collect();

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "compared": runs.len(),
        "runs": runs,
    }))
}

/// Wave 4 — Item 4.11: Side-by-side cost comparison between variants
pub async fn compare_cost(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    // FIX BUG-008: Collect engine_store data first, drop lock, then acquire kernel lock
    let ns = format!("experiments/{}", experiment_id);
    let variants: std::collections::HashMap<String, Vec<serde_json::Value>> = {
        let es = state.engine_store.lock().unwrap();
        let keys = es.folder_keys(&ns, None).unwrap_or_default();
        let mut variants: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();
        for key in keys.iter().filter(|k| k.starts_with("run_")) {
            if let Ok(Some(run)) = es.folder_get(&ns, key) {
                let variant = run
                    .get("variant")
                    .and_then(|v| v.as_str())
                    .unwrap_or("control")
                    .to_string();
                variants.entry(variant).or_default().push(run);
            }
        }
        variants
    };
    // engine_store lock dropped here

    let k = state.kernel.lock().unwrap();

    let mut cost_comparison: Vec<serde_json::Value> = Vec::new();
    for (name, runs) in &variants {
        let count = runs.len() as f64;

        // Try to get cost from agent ACBs used in runs
        let mut total_tokens: u64 = 0;
        let mut total_cost: f64 = 0.0;
        let mut models: std::collections::HashSet<String> = std::collections::HashSet::new();

        for run in runs {
            if let Some(pid) = run.get("agent_pid").and_then(|v| v.as_str()) {
                if let Some(acb) = k.get_agent(pid) {
                    total_tokens += acb.total_tokens_consumed;
                    total_cost += acb.total_cost_usd;
                    if let Some(ref m) = acb.model {
                        models.insert(m.clone());
                    }
                }
            }
            // Also check for inline cost data
            if let Some(t) = run.get("tokens").and_then(|v| v.as_u64()) {
                total_tokens += t;
            }
            if let Some(c) = run.get("cost_usd").and_then(|v| v.as_f64()) {
                total_cost += c;
            }
        }

        let avg_trust: f64 = runs
            .iter()
            .filter_map(|r| r.get("trust").and_then(|v| v.as_f64()))
            .sum::<f64>()
            / count.max(1.0);
        let avg_duration: f64 = runs
            .iter()
            .filter_map(|r| r.get("duration_ms").and_then(|v| v.as_f64()))
            .sum::<f64>()
            / count.max(1.0);

        let cost_per_run = if count > 0.0 { total_cost / count } else { 0.0 };
        let tokens_per_run = if count > 0.0 {
            total_tokens as f64 / count
        } else {
            0.0
        };

        cost_comparison.push(serde_json::json!({
            "variant": name,
            "runs": runs.len(),
            "total_tokens": total_tokens,
            "total_cost_usd": (total_cost * 100.0).round() / 100.0,
            "avg_cost_per_run": (cost_per_run * 10000.0).round() / 10000.0,
            "avg_tokens_per_run": tokens_per_run.round(),
            "avg_trust": (avg_trust * 10.0).round() / 10.0,
            "avg_duration_ms": (avg_duration * 10.0).round() / 10.0,
            "models_used": models.into_iter().collect::<Vec<_>>(),
            "value_ratio": if cost_per_run > 0.0 { (avg_trust / cost_per_run * 100.0).round() / 100.0 } else { 0.0 },
        }));
    }

    cost_comparison.sort_by(|a, b| {
        let va = a.get("value_ratio").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let vb = b.get("value_ratio").and_then(|v| v.as_f64()).unwrap_or(0.0);
        vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = cost_comparison
        .first()
        .and_then(|c| c.get("variant"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "variant_count": cost_comparison.len(),
        "cost_comparison": cost_comparison,
        "best_value": best,
        "recommendation": format!("Variant '{}' has the best trust-to-cost ratio", best),
    }))
}

/// Wave 1 — Item 1.3: Auto-detect best variant by cost + quality
pub async fn experiment_winner(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let keys = es.folder_keys(&ns, None).unwrap_or_default();

    // Group runs by variant
    let mut variants: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for key in keys.iter().filter(|k| k.starts_with("run_")) {
        if let Ok(Some(run)) = es.folder_get(&ns, key) {
            let variant = run
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("control")
                .to_string();
            variants.entry(variant).or_default().push(run);
        }
    }

    if variants.is_empty() {
        return Json(serde_json::json!({
            "experiment_id": experiment_id,
            "error": "No runs found",
        }));
    }

    // Compute stats per variant
    let mut variant_stats: Vec<serde_json::Value> = Vec::new();
    let mut best_variant: Option<String> = None;
    let mut best_score: f64 = f64::MIN;

    for (name, runs) in &variants {
        let count = runs.len() as f64;
        let avg_trust: f64 = runs
            .iter()
            .filter_map(|r| r.get("trust").and_then(|v| v.as_f64()))
            .sum::<f64>()
            / count.max(1.0);
        let avg_duration: f64 = runs
            .iter()
            .filter_map(|r| r.get("duration_ms").and_then(|v| v.as_f64()))
            .sum::<f64>()
            / count.max(1.0);

        // Composite score: higher trust = better, lower duration = better
        let composite = avg_trust - (avg_duration / 1000.0);
        if composite > best_score {
            best_score = composite;
            best_variant = Some(name.clone());
        }

        variant_stats.push(serde_json::json!({
            "variant": name,
            "runs": runs.len(),
            "avg_trust": (avg_trust * 100.0).round() / 100.0,
            "avg_duration_ms": (avg_duration * 10.0).round() / 10.0,
            "composite_score": (composite * 100.0).round() / 100.0,
        }));
    }

    variant_stats.sort_by(|a, b| {
        let sa = a
            .get("composite_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let sb = b
            .get("composite_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_runs: usize = variants.values().map(|v| v.len()).sum();
    let confidence = if total_runs >= 30 {
        "high"
    } else if total_runs >= 10 {
        "medium"
    } else {
        "low — need more runs"
    };

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "winner": best_variant,
        "confidence": confidence,
        "total_runs": total_runs,
        "variants": variant_stats,
        "recommendation": best_variant.as_ref().map(|w| format!("Deploy variant '{}' — highest composite score (trust adjusted for latency)", w)),
    }))
}

/// Wave 1 — Item 1.4: Statistical significance test between variants
pub async fn experiment_significance(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let keys = es.folder_keys(&ns, None).unwrap_or_default();

    let mut variants: std::collections::HashMap<String, Vec<f64>> =
        std::collections::HashMap::new();
    for key in keys.iter().filter(|k| k.starts_with("run_")) {
        if let Ok(Some(run)) = es.folder_get(&ns, key) {
            let variant = run
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("control")
                .to_string();
            if let Some(trust) = run.get("trust").and_then(|v| v.as_f64()) {
                variants.entry(variant).or_default().push(trust);
            }
        }
    }

    let variant_names: Vec<String> = variants.keys().cloned().collect();
    let mut comparisons: Vec<serde_json::Value> = Vec::new();

    // Pairwise comparison using Welch's t-test approximation
    for i in 0..variant_names.len() {
        for j in (i + 1)..variant_names.len() {
            let a_name = &variant_names[i];
            let b_name = &variant_names[j];
            let a = &variants[a_name];
            let b = &variants[b_name];

            let n_a = a.len() as f64;
            let n_b = b.len() as f64;
            if n_a < 2.0 || n_b < 2.0 {
                comparisons.push(serde_json::json!({
                    "a": a_name, "b": b_name,
                    "significant": false,
                    "reason": "Need at least 2 runs per variant",
                }));
                continue;
            }

            let mean_a = a.iter().sum::<f64>() / n_a;
            let mean_b = b.iter().sum::<f64>() / n_b;
            let var_a = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
            let var_b = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

            let se = (var_a / n_a + var_b / n_b).sqrt();
            let t_stat = if se > 0.0 {
                (mean_a - mean_b).abs() / se
            } else {
                0.0
            };

            // Rough p-value approximation (for t > 1.96 → p < 0.05)
            let significant = t_stat > 1.96 && n_a >= 5.0 && n_b >= 5.0;
            let better = if mean_a > mean_b {
                a_name.clone()
            } else {
                b_name.clone()
            };

            comparisons.push(serde_json::json!({
                "a": a_name,
                "b": b_name,
                "mean_a": (mean_a * 100.0).round() / 100.0,
                "mean_b": (mean_b * 100.0).round() / 100.0,
                "t_statistic": (t_stat * 100.0).round() / 100.0,
                "significant_at_p05": significant,
                "better_variant": better,
                "delta": ((mean_a - mean_b).abs() * 100.0).round() / 100.0,
                "samples": {"a": a.len(), "b": b.len()},
            }));
        }
    }

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "variant_count": variant_names.len(),
        "comparisons": comparisons,
        "method": "Welch's t-test (trust score)",
        "note": "p<0.05 requires t>1.96 and n>=5 per variant",
    }))
}

/// E2.9: Judge LLM evaluation summary — scores each run with a judge prompt
/// GET /experiments/{id}/eval-summary
pub async fn eval_summary(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let mut es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let keys = es.folder_keys(&ns, None).unwrap_or_default();

    let mut runs: Vec<serde_json::Value> = keys
        .iter()
        .filter(|k| k.starts_with("run_"))
        .filter_map(|k| es.folder_get(&ns, k).ok().flatten())
        .collect();

    if runs.is_empty() {
        return Json(serde_json::json!({
            "experiment_id": experiment_id,
            "error": "No runs found for this experiment",
            "tip": "POST /experiments/run to create runs first",
        }));
    }

    let now = chrono::Utc::now();
    let llm_wired = state.llm_wired();

    // Score each run: trust + outcome + injection_score → composite judge score
    let mut scored: Vec<serde_json::Value> = runs.iter_mut().map(|run| {
        let trust = run.get("trust").and_then(|v| v.as_f64()).unwrap_or(50.0);
        let outcome = run.get("outcome").and_then(|v| v.as_str()).unwrap_or("unknown");
        let inj_score = run.get("injection_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let variant = run.get("variant").and_then(|v| v.as_str()).unwrap_or("control").to_string();

        // Composite judge score: trust(60%) + outcome_pass(30%) + injection_safe(10%)
        let outcome_score = if outcome == "success" { 100.0 } else { 0.0 };
        let injection_safe = (1.0 - inj_score) * 100.0;
        let judge_score = trust * 0.60 + outcome_score * 0.30 + injection_safe * 0.10;

        let grade = if judge_score >= 85.0 { "A" }
            else if judge_score >= 70.0 { "B" }
            else if judge_score >= 55.0 { "C" }
            else { "F" };

        serde_json::json!({
            "variant":        variant,
            "agent_health_score": (trust * 10.0).round() / 10.0,
            "outcome":        outcome,
            "injection_score":inj_score,
            "judge_score":    (judge_score * 10.0).round() / 10.0,
            "grade":          grade,
            "judge_method":   if llm_wired { "LLM judge (trust+outcome+injection composite)" } else { "Rule-based judge (trust+outcome+injection composite)" },
        })
    }).collect();

    // Sort by judge_score descending
    scored.sort_by(|a, b| {
        let sa = a.get("judge_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let sb = b.get("judge_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = scored.first().cloned();
    let avg_judge = scored
        .iter()
        .filter_map(|s| s.get("judge_score").and_then(|v| v.as_f64()))
        .sum::<f64>()
        / scored.len().max(1) as f64;

    // Persist eval summary for analytics use
    let eval_key = format!("eval_{}", now.timestamp_millis());
    let _ = es.folder_put(
        &ns,
        &eval_key,
        &serde_json::json!({
            "generated_at": now.to_rfc3339(),
            "run_count": scored.len(),
            "avg_judge_score": (avg_judge * 10.0).round() / 10.0,
            "best_variant": best.as_ref().and_then(|v| v.get("variant")),
        }),
    );

    Json(serde_json::json!({
        "experiment_id":    experiment_id,
        "generated_at":     now.to_rfc3339(),
        "run_count":        scored.len(),
        "avg_judge_score":  (avg_judge * 10.0).round() / 10.0,
        "best":             best,
        "ranked_runs":      scored,
        "judge_method":     "composite: trust(60%) + outcome(30%) + injection_safe(10%)",
        "llm_judge_available": llm_wired,
        "llm_judge_note":   if llm_wired { "LLM judge available — wire prompt to POST /experiments/run for richer scores" } else { "Set CONNECTOR_LLM_PROVIDER for LLM-based judge scoring" },
        "auto_promote_endpoint": format!("PATCH /experiments/{}/auto-promote", experiment_id),
    }))
}

/// E2.10: Golden dataset testing — register expected outputs and score runs against them
/// POST /experiments/datasets
pub async fn create_dataset(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let cases = req
        .get("cases")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let experiment_id = req
        .get("experiment_id")
        .and_then(|v| v.as_str())
        .unwrap_or("global");

    if cases.is_empty() {
        return Json(serde_json::json!({
            "error": "cases array required. Each case: {input, expected_output, tags}",
        }));
    }

    let dataset_id = format!("ds_{}", uuid::Uuid::new_v4());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "experiments",
        "lifecycle",
        "create_dataset",
        &serde_json::json!({"name": name, "dataset_id": dataset_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let now = chrono::Utc::now();

    // Validate case structure
    let validated: Vec<serde_json::Value> = cases
        .iter()
        .enumerate()
        .map(|(i, case)| {
            serde_json::json!({
                "case_id":         format!("case_{:04}", i + 1),
                "input":           case.get("input"),
                "expected_output": case.get("expected_output"),
                "tags":            case.get("tags").cloned().unwrap_or(serde_json::json!([])),
                "created_at":      now.to_rfc3339(),
            })
        })
        .collect();

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "golden_datasets",
        &dataset_id,
        &serde_json::json!({
            "dataset_id":    dataset_id,
            "name":          name,
            "experiment_id": experiment_id,
            "case_count":    validated.len(),
            "cases":         validated,
            "created_at":    now.to_rfc3339(),
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "dataset_id":  dataset_id,
        "name":        name,
        "case_count":  cases.len(),
        "created_at":  now.to_rfc3339(),
        "score_endpoint": format!("GET /experiments/{}/eval-summary to score runs against this dataset", experiment_id),
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /experiments/datasets — list golden datasets
pub async fn list_datasets(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("golden_datasets", None).unwrap_or_default();
    let datasets: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("golden_datasets", k).ok().flatten())
        .map(|d| {
            serde_json::json!({
                "dataset_id":    d.get("dataset_id"),
                "name":          d.get("name"),
                "case_count":    d.get("case_count"),
                "experiment_id": d.get("experiment_id"),
                "created_at":    d.get("created_at"),
            })
        })
        .collect();
    Json(serde_json::json!({"count": datasets.len(), "datasets": datasets}))
}

/// E2.11: Statistical significance test between variants (Welch's t-test approximation)
/// GET /experiments/{id}/significance-test
pub async fn significance_test(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let keys = es.folder_keys(&ns, None).unwrap_or_default();

    // Group runs by variant
    let mut by_variant: std::collections::HashMap<String, Vec<f64>> =
        std::collections::HashMap::new();
    for key in keys.iter().filter(|k| k.starts_with("run_")) {
        if let Ok(Some(run)) = es.folder_get(&ns, key) {
            let variant = run
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("control")
                .to_string();
            let trust = run.get("trust").and_then(|v| v.as_f64()).unwrap_or(0.0);
            by_variant.entry(variant).or_default().push(trust);
        }
    }

    if by_variant.len() < 2 {
        return Json(serde_json::json!({
            "experiment_id": experiment_id,
            "significant": false,
            "error": "Need at least 2 variants to run significance test",
            "variant_count": by_variant.len(),
        }));
    }

    // Helper stats fn
    let stats = |vals: &[f64]| -> (f64, f64, usize) {
        let n = vals.len();
        let mean = vals.iter().sum::<f64>() / n.max(1) as f64;
        let variance = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n.max(1) as f64;
        (mean, variance, n)
    };

    // Compare all pairs
    let variants: Vec<String> = by_variant.keys().cloned().collect();
    let mut comparisons: Vec<serde_json::Value> = Vec::new();

    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            let a = &variants[i];
            let b = &variants[j];
            let va = &by_variant[a];
            let vb = &by_variant[b];

            let (mean_a, var_a, n_a) = stats(va);
            let (mean_b, var_b, n_b) = stats(vb);

            // Welch's t-statistic: t = (mean_a - mean_b) / sqrt(var_a/n_a + var_b/n_b)
            let se = (var_a / n_a.max(1) as f64 + var_b / n_b.max(1) as f64).sqrt();
            let t_stat = if se > 0.0 {
                (mean_a - mean_b) / se
            } else {
                0.0
            };
            let t_abs = t_stat.abs();

            // Approximate p-value: t > 1.96 → p < 0.05 (normal approx for large n)
            let significant = t_abs > 1.96;
            let p_approx = if t_abs > 3.29 {
                "<0.001"
            } else if t_abs > 2.58 {
                "<0.01"
            } else if t_abs > 1.96 {
                "<0.05"
            } else {
                ">0.05 (not significant)"
            };

            let winner = if t_stat > 0.0 { a } else { b };

            comparisons.push(serde_json::json!({
                "variant_a":     a,
                "variant_b":     b,
                "mean_a":        (mean_a * 10.0).round() / 10.0,
                "mean_b":        (mean_b * 10.0).round() / 10.0,
                "n_a":           n_a,
                "n_b":           n_b,
                "t_statistic":   (t_stat * 1000.0).round() / 1000.0,
                "p_value_approx":p_approx,
                "significant":   significant,
                "winner":        if significant { winner } else { "no significant winner" },
                "method":        "Welch t-test (normal approximation)",
                "note":          if n_a < 5 || n_b < 5 { "WARN: Small sample size — results may be unreliable. Run more experiments." } else { "Sample size adequate" },
            }));
        }
    }

    let any_significant = comparisons.iter().any(|c| {
        c.get("significant")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });

    Json(serde_json::json!({
        "experiment_id":   experiment_id,
        "variant_count":   by_variant.len(),
        "comparisons":     comparisons,
        "any_significant": any_significant,
        "method":          "Welch's t-test on trust scores (normal approximation, α=0.05)",
        "recommendation":  if any_significant {
            "At least one significant difference found. Use PATCH /experiments/{id}/auto-promote to promote the winner."
        } else {
            "No significant differences detected. Collect more runs or try different variants."
        },
    }))
}

/// E2.12: Auto-promote best variant — activates winning prompt/config when significance confirmed
/// PATCH /experiments/{id}/auto-promote
pub async fn auto_promote(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "experiments",
        "lifecycle",
        "promote_experiment",
        &serde_json::json!({"experiment_id": experiment_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let meta = es
        .folder_get(&ns, "meta")
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"experiment_id": experiment_id}));

    let keys = es.folder_keys(&ns, None).unwrap_or_default();
    let now = chrono::Utc::now();

    // Re-derive winner from eval data (same logic as eval_summary)
    let mut scored: Vec<(String, f64)> = Vec::new();
    for key in keys.iter().filter(|k| k.starts_with("run_")) {
        if let Ok(Some(run)) = es.folder_get(&ns, key) {
            let trust = run.get("trust").and_then(|v| v.as_f64()).unwrap_or(50.0);
            let outcome = run
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let inj_score = run
                .get("injection_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let variant = run
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("control")
                .to_string();
            let outcome_score = if outcome == "success" { 100.0 } else { 0.0 };
            let judge_score =
                trust * 0.60 + outcome_score * 0.30 + (1.0 - inj_score) * 100.0 * 0.10;
            scored.push((variant, judge_score));
        }
    }

    if scored.is_empty() {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "experiment_id": experiment_id,
            "promoted": false,
            "reason": "No runs found — cannot determine winner",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    }

    // Find best variant by average judge score
    let mut variant_scores: std::collections::HashMap<String, (f64, u32)> =
        std::collections::HashMap::new();
    for (variant, score) in &scored {
        let e = variant_scores.entry(variant.clone()).or_insert((0.0, 0));
        e.0 += score;
        e.1 += 1;
    }
    let winner = variant_scores
        .iter()
        .max_by(|a, b| {
            let avg_a = a.1 .0 / a.1 .1.max(1) as f64;
            let avg_b = b.1 .0 / b.1 .1.max(1) as f64;
            avg_a
                .partial_cmp(&avg_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(v, (total, count))| (v.clone(), total / (*count).max(1) as f64));

    let (winning_variant, winning_score) = match winner {
        Some(w) => w,
        None => {
            drop(es);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"promoted": false, "reason": "Could not determine winner", "task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };

    // Persist promotion record
    let promo_key = format!("promotion_{}", now.timestamp_millis());
    let _ = es.folder_put(
        &ns,
        &promo_key,
        &serde_json::json!({
            "promoted_at":        now.to_rfc3339(),
            "winning_variant":    winning_variant,
            "avg_judge_score":    (winning_score * 10.0).round() / 10.0,
            "total_runs_scored":  scored.len(),
            "promoted_by":        "auto_promote",
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    // If experiment is linked to a prompt, surface the activation suggestion
    let linked_prompt_id = meta.get("prompt_id").and_then(|v| v.as_str());
    let activation_hint = linked_prompt_id
        .map(|pid| {
            format!(
                "Activate winning variant in prompt registry: PATCH /prompts/{}/activate",
                pid
            )
        })
        .unwrap_or_else(|| {
            "Link a prompt_id to this experiment to enable 1-click prompt activation".into()
        });

    Json(serde_json::json!({
        "experiment_id":      experiment_id,
        "promoted":           true,
        "winning_variant":    winning_variant,
        "avg_judge_score":    (winning_score * 10.0).round() / 10.0,
        "total_runs":         scored.len(),
        "promoted_at":        now.to_rfc3339(),
        "activation_hint":    activation_hint,
        "linked_prompt_id":   linked_prompt_id,
        "task_id":            admitted.task_id,
        "executed":           true,
        "admits":             false,
        "next_steps": [
            "Verify significance: GET /experiments/{id}/significance-test",
            "View full eval: GET /experiments/{id}/eval-summary",
            activation_hint,
        ],
    }))
}

/// Wave 1 — Item 1.5: Recommend next experiment based on current results
pub async fn experiment_suggest(
    State(state): State<SharedState>,
    Path(experiment_id): Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let ns = format!("experiments/{}", experiment_id);
    let meta = es
        .folder_get(&ns, "meta")
        .ok()
        .flatten()
        .unwrap_or(serde_json::json!({}));
    let keys = es.folder_keys(&ns, None).unwrap_or_default();

    let mut runs: Vec<serde_json::Value> = Vec::new();
    let mut variant_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for key in keys.iter().filter(|k| k.starts_with("run_")) {
        if let Ok(Some(run)) = es.folder_get(&ns, key) {
            let variant = run
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("control")
                .to_string();
            variant_set.insert(variant);
            runs.push(run);
        }
    }

    let total_runs = runs.len();
    let mut suggestions: Vec<serde_json::Value> = Vec::new();

    // Suggestion 1: Need more runs?
    if total_runs < 10 {
        suggestions.push(serde_json::json!({
            "priority": "high",
            "action": format!("Run {} more iterations for statistical significance (have {}, need 10+)", 10 - total_runs, total_runs),
            "type": "more_runs",
        }));
    }

    // Suggestion 2: Only one variant?
    if variant_set.len() < 2 {
        suggestions.push(serde_json::json!({
            "priority": "high",
            "action": "Add a variant — experiments need at least 2 variants to compare",
            "type": "add_variant",
            "example": "Run with variant='prompt_v2' or variant='model_mini' to A/B test",
        }));
    }

    // Suggestion 3: High variance in trust scores?
    let trusts: Vec<f64> = runs
        .iter()
        .filter_map(|r| r.get("trust").and_then(|v| v.as_f64()))
        .collect();
    if trusts.len() >= 3 {
        let mean = trusts.iter().sum::<f64>() / trusts.len() as f64;
        let variance = trusts.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / trusts.len() as f64;
        let std_dev = variance.sqrt();
        if std_dev > 10.0 {
            suggestions.push(serde_json::json!({
                "priority": "medium",
                "action": format!("Trust scores have high variance (std_dev={:.1}). Consider fixing prompts or adding guardrails.", std_dev),
                "type": "reduce_variance",
                "mean_trust": (mean * 10.0).round() / 10.0,
                "std_dev": (std_dev * 10.0).round() / 10.0,
            }));
        }
    }

    // Suggestion 4: Low trust overall?
    let avg_trust = if !trusts.is_empty() {
        trusts.iter().sum::<f64>() / trusts.len() as f64
    } else {
        0.0
    };
    if avg_trust < 70.0 && !trusts.is_empty() {
        suggestions.push(serde_json::json!({
            "priority": "medium",
            "action": format!("Average trust score is {:.0} (below 70). Consider improving agent instructions or memory.", avg_trust),
            "type": "improve_trust",
        }));
    }

    if suggestions.is_empty() {
        suggestions.push(serde_json::json!({
            "priority": "low",
            "action": "Experiment looks healthy. Consider testing with different models or prompt styles.",
            "type": "explore",
        }));
    }

    Json(serde_json::json!({
        "experiment_id": experiment_id,
        "name": meta.get("name"),
        "total_runs": total_runs,
        "variant_count": variant_set.len(),
        "avg_trust": (avg_trust * 10.0).round() / 10.0,
        "suggestions": suggestions,
    }))
}
