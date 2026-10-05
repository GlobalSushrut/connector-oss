use crate::middleware::tenant::TenantContext;
use crate::services::orchestration_intelligence::{self, PipelineWave};
use crate::state::SharedState;
use aapi_adapters::pii_tokenizer::PiiTokenizer;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use connector_engine::llm::ChatMessage;
use connector_engine::semantic_injection::SemanticInjectionDetector;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::{MemPacket, MemoryKernelOp, OpOutcome, PacketType, Source, SourceKind};

/// Token budget per agent per pipeline run (configurable via env).
/// Default: 16 000 tokens (roughly $0.04 at gpt-4o rates).
pub fn agent_token_budget() -> u64 {
    std::env::var("CONNECTOR_AGENT_TOKEN_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16_000)
}

/// Enforce ACB token budget before dispatching an LLM call.
/// Returns an error string when the budget is exceeded.
fn check_budget(k: &vac_core::kernel::MemoryKernel, agent_pid: &str) -> Result<(), String> {
    let budget = agent_token_budget();
    if let Some(acb) = k.get_agent(agent_pid) {
        if acb.total_tokens_consumed >= budget {
            return Err(format!(
                "Agent '{}' token budget exceeded ({}/{} tokens). Retry after budget reset.",
                agent_pid, acb.total_tokens_consumed, budget
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct RunPipelineRequest {
    pub name: String,
    pub agents: Vec<PipelineAgentDef>,
    pub input: String,
    pub user: String,
    #[serde(default)]
    pub compliance: Vec<String>,
    // E3.4: Cost circuit breaker
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PipelineAgentDef {
    pub name: String,
    #[serde(default)]
    pub instructions: Option<String>,
    // E3.1: Human-in-the-loop approval gate
    #[serde(default)]
    pub requires_human_approval: bool,
    // E3.2: Parallel execution group (agents with same group run concurrently)
    #[serde(default)]
    pub parallel_group: Option<String>,
    // E3.2: Merge strategy for parallel group output
    #[serde(default)]
    pub merge_strategy: Option<String>, // concat | vote | best_score | summarize
    // E3.3: Per-step failure policy
    #[serde(default)]
    pub on_failure: Option<String>, // stop | skip | retry | fallback
    #[serde(default)]
    pub fallback_agent: Option<String>, // agent name to use on fallback
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

#[derive(Debug)]
enum StepFlow {
    Continue { output: String },
    Skip,
    BreakPipeline,
}

struct AgentStepOutcome {
    step_idx: usize,
    result: serde_json::Value,
    flow: StepFlow,
    tokens: u64,
}

fn router_total_cost(state: &SharedState) -> f64 {
    state
        .llm_router_arc()
        .map(|r| r.total_cost_usd())
        .unwrap_or(0.0)
}

fn hitl_gate(
    state: &SharedState,
    pipeline_id: &str,
    pipeline_name: &str,
    step_idx: usize,
    agent: &PipelineAgentDef,
    last_output: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if !agent.requires_human_approval {
        return false;
    }
    let approval_key = format!("step_approval_{}", step_idx);
    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get(
            &format!("pipeline_approvals/{}", pipeline_id),
            &approval_key,
        )
        .ok()
        .flatten();
    let approved = existing
        .as_ref()
        .and_then(|v| v.get("approved").and_then(|a| a.as_bool()))
        .unwrap_or(false);
    if approved {
        return false;
    }
    let _ = es.folder_put(
        &format!("pipeline_approvals/{}", pipeline_id),
        &approval_key,
        &serde_json::json!({
            "pipeline_id":   pipeline_id,
            "pipeline_name": pipeline_name,
            "step":          step_idx,
            "agent_name":    agent.name,
            "status":        "pending_approval",
            "created_at":    now.to_rfc3339(),
            "input_preview": last_output.chars().take(200).collect::<String>(),
            "approved":      false,
        }),
    );
    true
}

async fn execute_agent_step(
    state: SharedState,
    tenant_ctx: Option<TenantContext>,
    agent: PipelineAgentDef,
    step_idx: usize,
    input: String,
    pipe_id: String,
    pipeline_name: String,
    user: String,
    model: Option<String>,
    parent_kernel_pid: Option<String>,
) -> AgentStepOutcome {
    if let Err(limit_json) =
        crate::services::agents::kernel_agent_limit_gate(state.as_ref(), tenant_ctx.as_ref())
    {
        return AgentStepOutcome {
            step_idx,
            result: serde_json::json!({
                "step": step_idx,
                "name": agent.name,
                "status": "agent_limit_reached",
                "detail": limit_json,
            }),
            flow: StepFlow::BreakPipeline,
            tokens: 0,
        };
    }

    let step_ns = crate::services::agents::tenant_scoped_memory_namespace(
        tenant_ctx.as_ref(),
        &format!("m/{}", agent.name),
    );
    let pid = match crate::substrate::agent_progeny::register_with_progeny(
        &state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: &agent.name,
            namespace: &step_ns,
            role: Some("agent".to_string()),
            model: model.clone(),
            framework: Some("connector-platform".to_string()),
            parent_kernel_pid: parent_kernel_pid.as_deref(),
            reason: format!("Pipeline '{}' step {}", pipeline_name, step_idx),
        },
        &crate::substrate::agent_lifecycle_gate::LifecycleActor::system("multiagent_pipeline"),
    ) {
        Ok(p) => p,
        Err(e) => {
            return AgentStepOutcome {
                step_idx,
                result: serde_json::json!({
                    "step": step_idx,
                    "name": agent.name,
                    "status": "progeny_denied",
                    "error": e.message(),
                }),
                flow: StepFlow::BreakPipeline,
                tokens: 0,
            };
        }
    };

    {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet(&input, &user, &pipe_id, PacketType::Input),
            },
            reason: Some(format!(
                "Pipeline '{}' step {} input",
                pipeline_name, step_idx
            )),
            vakya_id: Some(format!(
                "vakya:pipeline:{}:step:{}:input",
                pipeline_name, step_idx
            )),
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
    };

    let _api_pid = crate::services::agents::ensure_agent_store_mapping(
        &state,
        &pid,
        &agent.name,
        &step_ns,
        model.as_deref(),
        "multiagent",
        Some(serde_json::json!({
            "source": "multiagent",
            "pipeline": pipeline_name,
            "step": step_idx,
        })),
    );

    if let Err(budget_err) = {
        let k = state.kernel.lock().unwrap();
        check_budget(&k, &pid)
    } {
        let policy = agent.on_failure.as_deref().unwrap_or("stop");
        return AgentStepOutcome {
            step_idx,
            result: serde_json::json!({
                "step": step_idx, "name": agent.name, "pid": pid,
                "status": if policy == "skip" { "skipped" } else { "budget_exceeded" },
                "reason": budget_err,
            }),
            flow: if policy == "skip" {
                StepFlow::Skip
            } else {
                StepFlow::BreakPipeline
            },
            tokens: 0,
        };
    }

    let injection_result = {
        let mut detector = SemanticInjectionDetector::new();
        detector.analyze(&input, &pid)
    };
    if injection_result.score > 0.75 {
        let policy = agent.on_failure.as_deref().unwrap_or("stop");
        let err_msg = format!("Injection detected (score={:.2})", injection_result.score);
        return AgentStepOutcome {
            step_idx,
            result: serde_json::json!({
                "step": step_idx, "name": agent.name, "pid": pid,
                "status": "injection_blocked",
                "error": err_msg,
                "score": injection_result.score,
            }),
            flow: if policy == "skip" {
                StepFlow::Skip
            } else {
                StepFlow::BreakPipeline
            },
            tokens: 0,
        };
    }

    let pii_json = serde_json::Value::String(input.clone());
    let (tokenized_json, token_map) = PiiTokenizer::tokenize(&pii_json);
    let tokenized_input = tokenized_json.as_str().unwrap_or(&input).to_string();

    let mut talk_task: Option<crate::substrate::pate::AugmentedTaskUnit> = None;
    if state.llm_wired() {
        if let Err(deny) = crate::substrate::admission_gate::require_llm_chat(
            &state,
            &pid,
            &step_ns,
            Some(&tokenized_input),
        ) {
            return AgentStepOutcome {
                step_idx,
                result: serde_json::json!({
                    "step": step_idx,
                    "name": agent.name,
                    "pid": pid,
                    "status": "admission_denied",
                    "error": deny,
                }),
                flow: StepFlow::BreakPipeline,
                tokens: 0,
            };
        }
        talk_task = Some(match crate::substrate::pate::admit_talk(
            &state,
            &pid,
            &step_ns,
            &tokenized_input,
            None,
        ) {
            Ok(atu) if crate::substrate::pate::host_admission_allows_execution(atu.verdict) => atu,
            Ok(atu) => {
                let _ = crate::substrate::pate::complete_augmented_task(
                    &state,
                    &atu,
                    "deny",
                    serde_json::json!({"observed": false}),
                );
                return AgentStepOutcome {
                    step_idx,
                    result: serde_json::json!({
                        "step": step_idx,
                        "name": agent.name,
                        "pid": pid,
                        "status": "talk_governance_denied",
                        "pate_task_id": atu.task_id,
                        "executed": false,
                    }),
                    flow: StepFlow::BreakPipeline,
                    tokens: 0,
                };
            }
            Err(deny) => {
            return AgentStepOutcome {
                step_idx,
                result: serde_json::json!({
                    "step": step_idx,
                    "name": agent.name,
                    "pid": pid,
                    "status": "talk_governance_denied",
                    "error": deny.human_readable,
                }),
                flow: StepFlow::BreakPipeline,
                tokens: 0,
            };
            }
        });
    }

    let max_retries: u32 = if agent.on_failure.as_deref() == Some("retry") {
        2
    } else {
        0
    };
    let mut llm_output: Option<String> = None;
    let mut llm_error: Option<String> = None;
    let mut step_tokens: u64 = 0;

    for attempt in 0..=max_retries {
        let step_output = if let Some(router) = state.llm_router_arc() {
            let system_prompt = agent.instructions.as_deref().unwrap_or(
                "You are a helpful AI agent. Process the input and return a concise result.",
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
                    content: tokenized_input.clone(),
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
                return AgentStepOutcome {
                    step_idx,
                    result: serde_json::json!({
                        "step": step_idx,
                        "name": agent.name,
                        "pid": pid,
                        "status": "agentic_context_required",
                        "error": e.human_readable.clone(),
                    }),
                    flow: StepFlow::BreakPipeline,
                    tokens: 0,
                };
            }
            crate::kernel::iia_llm_inject::inject_who_am_i_engine_messages(
                state.as_ref(),
                &pid,
                &mut messages,
            );
            if let Ok(prepared) = crate::substrate::governed_talk_core::prepare_talk(
                &state,
                &pid,
                "pipeline-model",
                "multiagent",
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
                step_ns.clone(),
                tokenized_input.clone(),
            )
            .await;
            if let Some(system) = messages.iter_mut().find(|m| m.role == "system") {
                system.content = format!("{}\n{}\n{}", system.content, memory_core, rag);
            }
            match router.chat(messages).await {
                Ok(resp) => {
                    step_tokens = (resp.input_tokens + resp.output_tokens) as u64;
                    let run_cost = router.total_cost_usd();
                    let mut k = state.kernel.lock().unwrap();
                    k.dispatch(SyscallRequest {
                        agent_pid: pid.clone(),
                        operation: MemoryKernelOp::RecordTokenUsage,
                        payload: SyscallPayload::RecordTokenUsage {
                            tokens_used: step_tokens,
                            cost_usd: run_cost,
                            model: resp.model.clone(),
                        },
                        reason: Some(format!("pipeline:{}", pipeline_name)),
                        vakya_id: Some(format!(
                            "vakya:pipeline:{}:step:{}:token_usage",
                            pipeline_name, step_idx
                        )),
                        trace_parent: None,
                        trace_state: None,
                        api_version: None,
                    });
                    drop(k);
                    let resp_json = serde_json::Value::String(resp.text.clone());
                    let remat_json = PiiTokenizer::rematerialize(&resp_json, &token_map);
                    let output = remat_json.as_str().unwrap_or(&resp.text).to_string();
                    let projected = crate::substrate::governed_talk_core::project_talk_with_receipt(
                        state.as_ref(),
                        &pid,
                        &output,
                        &tokenized_input,
                    );
                    match projected {
                        Ok(f) => Ok(f.text),
                        Err(error) => Err(format!(
                            "projection_denied: {}",
                            error.human_readable
                        )),
                    }
                }
                Err(e) => Err(e.message),
            }
        } else {
            Ok(format!("[no LLM — {} step {}]", agent.name, step_idx))
        };

        match step_output {
            Ok(text) => {
                llm_output = Some(text);
                if let Some(atu) = talk_task.as_ref() {
                    let _ = crate::substrate::pate::complete_augmented_task(
                        &state,
                        atu,
                        "ok",
                        serde_json::json!({"observed": true, "runtime": "talk"}),
                    );
                }
                break;
            }
            Err(e) => {
                llm_error = Some(e.clone());
                if attempt < max_retries {
                    tracing::warn!(
                        "Step {} attempt {} failed: {} — retrying",
                        step_idx,
                        attempt,
                        e
                    );
                }
            }
        }
    }

    let step_text = match llm_output {
        Some(t) => t,
        None => {
            let policy = agent.on_failure.as_deref().unwrap_or("stop");
            let err = llm_error.unwrap_or_else(|| "unknown error".into());
            match policy {
                "skip" => {
                    return AgentStepOutcome {
                        step_idx,
                        result: serde_json::json!({
                            "step": step_idx, "name": agent.name, "pid": pid,
                            "status": "skipped", "error": err,
                        }),
                        flow: StepFlow::Skip,
                        tokens: step_tokens,
                    };
                }
                "fallback" => {
                    let fb = agent.fallback_agent.as_deref().unwrap_or("fallback");
                    let step_text = format!("[fallback:{} — original error: {}]", fb, err);
                    {
                        let mut k = state.kernel.lock().unwrap();
                        k.dispatch(SyscallRequest {
                            agent_pid: pid.clone(),
                            operation: MemoryKernelOp::MemWrite,
                            payload: SyscallPayload::MemWrite {
                                packet: make_packet(
                                    &step_text,
                                    &user,
                                    &pipe_id,
                                    PacketType::LlmRaw,
                                ),
                            },
                            reason: Some(format!(
                                "Pipeline '{}' step {} fallback output",
                                pipeline_name, step_idx
                            )),
                            vakya_id: Some(format!(
                                "vakya:pipeline:{}:step:{}:output",
                                pipeline_name, step_idx
                            )),
                            trace_parent: None,
                            trace_state: None,
                            api_version: None,
                        });
                    }
                    return AgentStepOutcome {
                        step_idx,
                        result: serde_json::json!({
                            "step": step_idx,
                            "name": agent.name,
                            "pid": pid,
                            "status": "fallback",
                            "parallel_group": agent.parallel_group,
                            "output": step_text.chars().take(500).collect::<String>(),
                        }),
                        flow: StepFlow::Continue { output: step_text },
                        tokens: step_tokens,
                    };
                }
                _ => {
                    return AgentStepOutcome {
                        step_idx,
                        result: serde_json::json!({
                            "step": step_idx, "name": agent.name, "pid": pid,
                            "status": "failed", "error": err,
                        }),
                        flow: StepFlow::BreakPipeline,
                        tokens: step_tokens,
                    };
                }
            }
        }
    };

    {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite {
                packet: make_packet(&step_text, &user, &pipe_id, PacketType::LlmRaw),
            },
            reason: Some(format!(
                "Pipeline '{}' step {} output",
                pipeline_name, step_idx
            )),
            vakya_id: Some(format!(
                "vakya:pipeline:{}:step:{}:output",
                pipeline_name, step_idx
            )),
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
    }

    AgentStepOutcome {
        step_idx,
        result: serde_json::json!({
            "step":           step_idx,
            "name":           agent.name,
            "pid":            pid,
            "status":         "ok",
            "parallel_group": agent.parallel_group,
            "output":         step_text.chars().take(500).collect::<String>(),
        }),
        flow: StepFlow::Continue { output: step_text },
        tokens: step_tokens,
    }
}

/// GET /multiagent/intelligence/standard — Orchestration Intelligence v1 contract.
pub async fn intelligence_standard() -> Json<serde_json::Value> {
    Json(orchestration_intelligence::intelligence_standard_json())
}

pub async fn run_pipeline(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RunPipelineRequest>,
) -> Json<serde_json::Value> {
    let tenant_ctx = match crate::services::agents::require_multi_tenant_context(&headers) {
        Ok(t) => t,
        Err(msg) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "tenant_required",
                "message": msg,
            }));
        }
    };

    let subject = req
        .agents
        .first()
        .map(|agent| agent.name.clone())
        .unwrap_or_else(|| "pipeline".to_string());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &subject,
        "multiagent",
        "run_pipeline",
        &serde_json::json!({"name": req.name}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let pipe_id = format!("pipe:{}", req.name);
    let pipeline_id = format!("pipeline_{}", uuid::Uuid::new_v4());
    let model = state.llm_config_snapshot().map(|c| c.model);
    let start = std::time::Instant::now();
    let now = chrono::Utc::now();
    let mut last_output = req.input.clone();
    let mut agent_results: Vec<serde_json::Value> = Vec::new();
    let mut pipeline_cost_usd: f64 = 0.0;
    let mut pipeline_tokens: u64 = 0;
    let mut circuit_tripped = false;
    let mut hitl_pending = false;
    let mut hitl_step: Option<usize> = None;
    let mut warnings: Vec<String> = Vec::new();

    let total_steps = req.agents.len();
    let parallel_groups: Vec<Option<String>> = req
        .agents
        .iter()
        .map(|a| a.parallel_group.clone())
        .collect();
    let merge_strategies: Vec<Option<String>> = req
        .agents
        .iter()
        .map(|a| a.merge_strategy.clone())
        .collect();
    let waves = orchestration_intelligence::plan_waves(&parallel_groups, &merge_strategies);
    let mut orchestration_waves: Vec<serde_json::Value> = Vec::new();
    let mut intelligence_chain: Vec<orchestration_intelligence::IntelligenceChainLink> = Vec::new();
    let mut wave_index: u32 = 0;
    let max_parallel = orchestration_intelligence::parallel_max_agents();
    let mut pipeline_stopped = false;
    let mut progeny_parent: Option<String> = None;

    'waves: for wave in waves {
        if pipeline_stopped {
            break;
        }

        if let Some(max_cost) = req.max_cost_usd {
            if pipeline_cost_usd >= max_cost {
                circuit_tripped = true;
                warnings.push(format!(
                    "Cost circuit breaker tripped — ${:.4} >= max ${:.4}. Returning partial results.",
                    pipeline_cost_usd, max_cost
                ));
                break;
            }
        }
        if let Some(max_tok) = req.max_tokens {
            if pipeline_tokens >= max_tok {
                circuit_tripped = true;
                warnings.push(format!(
                    "Token circuit breaker tripped — {} >= max {} tokens. Returning partial results.",
                    pipeline_tokens, max_tok
                ));
                break;
            }
        }

        match wave {
            PipelineWave::Single { index } => {
                let agent = &req.agents[index];
                if let Err(deny) = crate::substrate::admission_gate::require_pipeline_step(
                    &state,
                    &agent.name,
                    &pipe_id,
                    index,
                ) {
                    open_proceed.finish_observed(!agent_results.is_empty());
                    return Json(deny);
                }
                if hitl_gate(
                    &state,
                    &pipeline_id,
                    &req.name,
                    index,
                    agent,
                    &last_output,
                    now,
                ) {
                    hitl_pending = true;
                    hitl_step = Some(index);
                    warnings.push(format!(
                        "Pipeline paused at step {} — agent '{}' requires human approval. POST /multiagent/pipelines/{}/approve-step/{}",
                        index, agent.name, pipeline_id, index
                    ));
                    break;
                }

                let wave_input = last_output.clone();
                let cost_before = router_total_cost(&state);
                let outcome = execute_agent_step(
                    state.clone(),
                    tenant_ctx.clone(),
                    agent.clone(),
                    index,
                    wave_input.clone(),
                    pipe_id.clone(),
                    req.name.clone(),
                    req.user.clone(),
                    model.clone(),
                    progeny_parent.clone(),
                )
                .await;
                pipeline_cost_usd += router_total_cost(&state) - cost_before;
                pipeline_tokens += outcome.tokens;
                let step_pid = outcome
                    .result
                    .get("pid")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                agent_results.push(outcome.result);

                match outcome.flow {
                    StepFlow::Continue { output } => {
                        last_output = output;
                        if let Some(p) = step_pid {
                            progeny_parent = Some(p);
                        }
                        intelligence_chain.push(orchestration_intelligence::record_chain_link(
                            wave_index,
                            "single",
                            &[agent.name.clone()],
                            None,
                            &wave_input,
                            &last_output,
                        ));
                        orchestration_waves.push(serde_json::json!({
                            "wave": wave_index,
                            "kind": "single",
                            "layer": "intelligence_leaf",
                            "index": index,
                            "agent": agent.name,
                        }));
                        wave_index += 1;
                    }
                    StepFlow::Skip => {
                        warnings.push(format!("Step {} skipped", index));
                    }
                    StepFlow::BreakPipeline => {
                        if agent_results
                            .last()
                            .and_then(|r| r.get("status"))
                            .and_then(|s| s.as_str())
                            == Some("agent_limit_reached")
                        {
                            warnings
                                .push(format!("Agent slot limit reached before step {}", index));
                        }
                        pipeline_stopped = true;
                    }
                }
            }
            PipelineWave::Parallel {
                group,
                indices,
                merge,
            } => {
                for &index in &indices {
                    let agent = &req.agents[index];
                    if let Err(deny) = crate::substrate::admission_gate::require_pipeline_step(
                        &state,
                        &agent.name,
                        &pipe_id,
                        index,
                    ) {
                        open_proceed.finish_observed(!agent_results.is_empty());
                        return Json(deny);
                    }
                    if hitl_gate(
                        &state,
                        &pipeline_id,
                        &req.name,
                        index,
                        agent,
                        &last_output,
                        now,
                    ) {
                        hitl_pending = true;
                        hitl_step = Some(index);
                        warnings.push(format!(
                            "Pipeline paused at step {} — agent '{}' requires human approval. POST /multiagent/pipelines/{}/approve-step/{}",
                            index, agent.name, pipeline_id, index
                        ));
                        break 'waves;
                    }
                }

                let cost_before = router_total_cost(&state);
                let wave_input = last_output.clone();
                let mut all_outcomes: Vec<AgentStepOutcome> = Vec::new();

                for chunk in indices.chunks(max_parallel) {
                    let futs: Vec<_> = chunk
                        .iter()
                        .map(|&index| {
                            let agent = req.agents[index].clone();
                            let state = state.clone();
                            let tenant_ctx = tenant_ctx.clone();
                            let pipe_id = pipe_id.clone();
                            let pipeline_name = req.name.clone();
                            let user = req.user.clone();
                            let model = model.clone();
                            let wave_input = wave_input.clone();
                            let parent = progeny_parent.clone();
                            async move {
                                execute_agent_step(
                                    state,
                                    tenant_ctx,
                                    agent,
                                    index,
                                    wave_input,
                                    pipe_id,
                                    pipeline_name,
                                    user,
                                    model,
                                    parent,
                                )
                                .await
                            }
                        })
                        .collect();
                    all_outcomes.extend(join_all(futs).await);
                }

                pipeline_cost_usd += router_total_cost(&state) - cost_before;
                all_outcomes.sort_by_key(|o| o.step_idx);

                let mut branches: Vec<(String, String)> = Vec::new();
                let mut wave_failed = false;
                let mut first_wave_pid: Option<String> = None;
                for outcome in all_outcomes {
                    pipeline_tokens += outcome.tokens;
                    let agent_name = outcome
                        .result
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("agent")
                        .to_string();
                    if first_wave_pid.is_none() {
                        first_wave_pid = outcome
                            .result
                            .get("pid")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                    }
                    agent_results.push(outcome.result);
                    match outcome.flow {
                        StepFlow::Continue { output } => {
                            branches.push((agent_name, output));
                        }
                        StepFlow::Skip => {
                            warnings.push(format!(
                                "Step {} skipped in parallel wave '{}'",
                                outcome.step_idx, group
                            ));
                        }
                        StepFlow::BreakPipeline => {
                            wave_failed = true;
                        }
                    }
                }

                if wave_failed {
                    pipeline_stopped = true;
                    break;
                }

                if !branches.is_empty() {
                    last_output =
                        orchestration_intelligence::merge_parallel_outputs(&branches, &merge);
                    if let Some(first_pid) = first_wave_pid {
                        progeny_parent = Some(first_pid);
                    }
                }

                let agent_names: Vec<String> = branches.iter().map(|(n, _)| n.clone()).collect();
                if !branches.is_empty() {
                    intelligence_chain.push(orchestration_intelligence::record_chain_link(
                        wave_index,
                        "parallel",
                        &agent_names,
                        Some(merge.as_str()),
                        &wave_input,
                        &last_output,
                    ));
                }

                orchestration_waves.push(serde_json::json!({
                    "wave": wave_index,
                    "kind": "parallel",
                    "layer": "intelligence_leaf",
                    "group": group,
                    "indices": indices,
                    "merge": merge,
                    "branches_executed": branches.len(),
                    "execution": "tokio::join_all",
                    "max_concurrency": max_parallel,
                }));
                wave_index += 1;
            }
        }
    }

    if circuit_tripped {
        let trip_ms = chrono::Utc::now().timestamp_millis();
        for ap in &agent_results {
            if let Some(pid) = ap.get("pid").and_then(|v| v.as_str()) {
                crate::substrate::graph_firewall::record_cost_trip(&state, pid, trip_ms);
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let output = {
        let k = state.kernel.lock().unwrap();
        connector_engine::OutputBuilder::build(
            &k,
            last_output.clone(),
            &pipe_id,
            total_steps,
            &req.compliance,
            duration_ms,
            Vec::new(),
        )
    };

    let cost_breakdown: Vec<serde_json::Value> = {
        let k = state.kernel.lock().unwrap();
        agent_results
            .iter()
            .filter_map(|ap| {
                let pid_str = ap.get("pid").and_then(|v| v.as_str())?;
                let acb = k.get_agent(pid_str)?;
                Some(serde_json::json!({
                    "name":     ap.get("name"),
                    "pid":      pid_str,
                    "tokens":   acb.total_tokens_consumed,
                    "cost_usd": acb.total_cost_usd,
                    "packets":  acb.total_packets,
                    "model":    acb.model.as_deref().unwrap_or("unknown"),
                }))
            })
            .collect()
    };

    state
        .metrics
        .pipeline_duration_ms
        .observe(duration_ms as f64);
    state.metrics.requests_total.inc();
    let pipeline_ok = output.status.ok && !circuit_tripped && !hitl_pending;
    open_proceed.finish_observed(pipeline_ok || !agent_results.is_empty());

    Json(serde_json::json!({
        "pipeline_id":   pipeline_id,
        "task_id":       admitted.task_id,
        "executed":      pipeline_ok || !agent_results.is_empty(),
        "admits":        false,
        "text":          output.text,
        "ok":            output.status.ok && !circuit_tripped && !hitl_pending,
        "trust":         output.status.trust,
        "trust_grade":   output.status.trust_grade,
        "duration_ms":   duration_ms,
        "actors":        output.status.actors,
        "steps":         output.status.steps,
        "agents":        agent_results,
        "orchestration": {
            "schema": orchestration_intelligence::SCHEMA,
            "placement_model": "intelligence_identity",
            "control_plane": "wave_scheduler",
            "waves": orchestration_waves,
            "intelligence_chain": serde_json::to_value(&intelligence_chain).unwrap_or_else(|_| serde_json::json!([])),
            "standard": "GET /multiagent/intelligence/standard",
            "not_infra_dag": "POST /infra/orchestrator/submit is heavy DAG planner only — not this chain",
        },
        "cost": {
            "total_usd":  pipeline_cost_usd,
            "total_tokens": pipeline_tokens,
            "by_agent":   cost_breakdown,
            "circuit_breaker": if circuit_tripped { "TRIPPED" } else { "OK" },
            "max_cost_usd":   req.max_cost_usd,
            "max_tokens":     req.max_tokens,
        },
        "hitl": {
            "pending":   hitl_pending,
            "step":      hitl_step,
            "approve_endpoint": if hitl_pending {
                Some(format!("POST /multiagent/pipelines/{}/approve-step/{}", pipeline_id, hitl_step.unwrap_or(0)))
            } else { None },
        },
        "event_count":   output.events.len(),
        "span_count":    output.trace.spans.len(),
        "trace_id":      output.trace.trace_id,
        "warnings":      warnings,
        "errors":        output.errors,
    }))
}

/// E3.1: HITL — Approve a pipeline step that is pending human review
/// POST /multiagent/pipelines/{pipeline_id}/approve-step/{step}
pub async fn approve_step(
    State(state): State<SharedState>,
    Path((pipeline_id, step)): Path<(String, usize)>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if let Err(deny) = crate::substrate::admission_gate::require_pipeline_step(
        &state,
        "hitl-approver",
        &pipeline_id,
        step,
    ) {
        return Json(deny);
    }
    let approver = req
        .get("approver")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let comment = req.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    let approved = req
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let now = chrono::Utc::now();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        approver,
        "multiagent",
        "approve_step",
        &serde_json::json!({"pipeline_id": pipeline_id, "step": step, "approved": approved}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let folder_key = format!("pipeline_approvals/{}", pipeline_id);
    let step_key = format!("step_approval_{}", step);

    let mut es = state.engine_store.lock().unwrap();
    let existing = es.folder_get(&folder_key, &step_key).ok().flatten();

    if existing.is_none() {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "error": format!("No pending approval found for pipeline {} step {}", pipeline_id, step),
            "pipeline_id": pipeline_id,
            "step": step,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    }

    let updated = serde_json::json!({
        "pipeline_id":  pipeline_id,
        "step":         step,
        "approved":     approved,
        "approver":     approver,
        "comment":      comment,
        "reviewed_at":  now.to_rfc3339(),
        "status":       if approved { "approved" } else { "rejected" },
    });
    let _ = es.folder_put(&folder_key, &step_key, &updated);

    // Audit log the approval decision
    let audit_id = format!("hitl_{}", uuid::Uuid::new_v4());
    let _ = es.folder_put(
        "hitl_audit",
        &audit_id,
        &serde_json::json!({
            "audit_id":    audit_id,
            "pipeline_id": pipeline_id,
            "step":        step,
            "approved":    approved,
            "approver":    approver,
            "comment":     comment,
            "reviewed_at": now.to_rfc3339(),
            "eu_ai_act_art14": "Human oversight decision recorded per EU AI Act Art.14",
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "pipeline_id": pipeline_id,
        "task_id":     admitted.task_id,
        "executed":    true,
        "admits":      false,
        "step":        step,
        "approved":    approved,
        "approver":    approver,
        "comment":     comment,
        "reviewed_at": now.to_rfc3339(),
        "next_action": if approved {
            format!("Re-POST /multiagent/run-pipeline with the same pipeline_id to resume from step {}", step)
        } else {
            format!("Pipeline step {} was rejected. Pipeline will not proceed.", step)
        },
        "audit_logged": true,
        "eu_ai_act_art14": "Approval decision recorded in HITL audit log",
    }))
}

pub async fn pipeline_trace(
    State(state): State<SharedState>,
    Path(pipe_name): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let pipe_id = format!("pipe:{}", pipe_name);
    let entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.reason.as_ref().map_or(false, |r| r.contains(&pipe_name)))
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "target": e.target,
            })
        })
        .collect();
    Json(serde_json::json!({
        "pipeline": pipe_name,
        "trace_entries": entries.len(),
        "trace": entries,
    }))
}

/// Track 2 Phase B — Item B.2: Manual AccessGrant between agents
pub async fn grant_access(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let grantor = req
        .get("grantor_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let grantee = req
        .get("grantee_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let namespace = req.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
    let justification = req
        .get("justification")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let permissions: Vec<String> = req
        .get("permissions")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| vec!["read".into()]);

    if grantor.is_empty() || namespace.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "invalid_request",
            "message": "grantor_pid and namespace are required",
        }));
    }
    if grantee.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "invalid_request",
            "message": "grantee_pid is required — isolated by default",
        }));
    }
    if justification.trim().len() < 16 {
        return Json(serde_json::json!({
            "ok": false,
            "error": "share_contract_required",
            "message": "Justify what, where, and how much (min 16 chars). Isolated by default — no silent share.",
        }));
    }
    if let Some((_, role)) = crate::services::agents::caller(&headers) {
        if let Err(e) = crate::kernel::share_portal::require_human_root(&headers, role.rank()) {
            return Json(serde_json::json!({"ok": false, "error": e, "status": 403}));
        }
    } else if !crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Json(serde_json::json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    if crate::kernel::world_gateway::root_is_set() {
        let pass = req
            .get("root_passcode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Err(e) = crate::kernel::world_gateway::verify_root_passcode(pass) {
            return Json(serde_json::json!({"ok": false, "error": e}));
        }
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        grantor,
        "multiagent",
        "grant_access",
        &serde_json::json!({"grantor": grantor, "grantee": grantee, "namespace": namespace}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let contract = crate::kernel::share_portal::ShareContractV1 {
        from_pid: grantor.to_string(),
        to_pid: grantee.to_string(),
        what: namespace.to_string(),
        r#where: req
            .get("where")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        bytes_max: req.get("bytes_max").and_then(|v| v.as_u64()).unwrap_or(0),
        packets_max: req.get("packets_max").and_then(|v| v.as_u64()).unwrap_or(0),
        ttl_ms: req.get("ttl_ms").and_then(|v| v.as_i64()).unwrap_or(0),
        permissions: permissions.clone(),
        justification: justification.to_string(),
    };
    let portal = match crate::kernel::share_portal::put_portal(state.as_ref(), &contract) {
        Ok(p) => p,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}));
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, grantor, namespace)
    {
        open_proceed.finish_observed(false);
        return Json(deny);
    }

    let result = {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(vac_core::kernel::SyscallRequest {
        agent_pid: grantor.to_string(),
        operation: vac_core::types::MemoryKernelOp::AccessGrant,
        payload: vac_core::kernel::SyscallPayload::AccessGrant {
            target_namespace: namespace.to_string(),
            grantee_pid: grantee.to_string(),
            read: permissions.contains(&"read".to_string()),
            write: permissions.contains(&"write".to_string()),
            expires_at: None,
        },
        reason: Some(format!("Grant {} access to {}", grantee, namespace)),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    })
    };

    // B22: sync runtime grant into setup common_spaces + grant folder (single SoT for Isolation UI).
    let granted = result.outcome == vac_core::types::OpOutcome::Success;
    let synced = if granted {
        sync_grant_to_setup_sot(
            state.as_ref(),
            grantor,
            grantee,
            namespace,
            &permissions,
            false,
        )
    } else {
        None
    };
    open_proceed.finish_observed(granted);

    Json(serde_json::json!({
        "ok": granted,
        "task_id": admitted.task_id,
        "executed": granted,
        "admits": false,
        "grantor": grantor,
        "grantee": grantee,
        "namespace": namespace,
        "permissions": permissions,
        "portal_id": portal.portal_id,
        "portal_bind": portal.bind,
        "outcome": format!("{:?}", result.outcome),
        "setup_synced": synced,
        "honesty": "Shared portal minted from human sharing contract. Isolated by default otherwise.",
    }))
}

/// Track 2 Phase B — Item B.3: Manual AccessRevoke
pub async fn revoke_access(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let revoker = req
        .get("revoker_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target = req.get("target_pid").and_then(|v| v.as_str()).unwrap_or("");
    let namespace = req.get("namespace").and_then(|v| v.as_str()).unwrap_or("");

    if revoker.is_empty() || namespace.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "invalid_request",
            "message": "revoker_pid and namespace are required",
        }));
    }
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, revoker, namespace)
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        revoker,
        "multiagent",
        "revoke_access",
        &serde_json::json!({"revoker": revoker, "target": target, "namespace": namespace}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let result = {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(vac_core::kernel::SyscallRequest {
        agent_pid: revoker.to_string(),
        operation: vac_core::types::MemoryKernelOp::AccessRevoke,
        payload: vac_core::kernel::SyscallPayload::AccessRevoke {
            target_namespace: namespace.to_string(),
            grantee_pid: target.to_string(),
        },
        reason: Some(format!("Revoke {} access from {}", namespace, target)),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    })
    };
    let revoked = result.outcome == vac_core::types::OpOutcome::Success;
    let synced = if revoked {
        sync_grant_to_setup_sot(state.as_ref(), revoker, target, namespace, &[], true)
    } else {
        None
    };
    open_proceed.finish_observed(revoked);

    Json(serde_json::json!({
        "ok": revoked,
        "task_id": admitted.task_id,
        "executed": revoked,
        "admits": false,
        "revoker": revoker,
        "target": target,
        "namespace": namespace,
        "outcome": format!("{:?}", result.outcome),
        "setup_synced": synced,
    }))
}

/// B22: upsert/remove NamespaceGrantV2 on grantor setup + grant folder.
fn sync_grant_to_setup_sot(
    state: &crate::state::PlatformState,
    grantor: &str,
    grantee: &str,
    namespace: &str,
    permissions: &[String],
    revoke: bool,
) -> Option<String> {
    use crate::kernel::agent_identity_envelope::{self, GRANT_FOLDER};
    use connector_trust::NamespaceGrantV2;
    use sha2::{Digest, Sha256};

    let mut setup = agent_identity_envelope::load_setup(state, grantor)?;
    let grant_id = format!(
        "ng_{}",
        &hex::encode(Sha256::digest(
            format!("{grantor}|{namespace}|{grantee}").as_bytes()
        ))[..16]
    );
    if revoke {
        setup
            .common_spaces
            .retain(|g| g.grant_id != grant_id && g.path != namespace);
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_delete(GRANT_FOLDER, &grant_id);
        }
        let _ = agent_identity_envelope::save_setup(state, &setup);
        return Some(grant_id);
    }
    let mut readable = vec![grantor.to_string(), grantee.to_string()];
    readable.sort();
    readable.dedup();
    let writable = if permissions.iter().any(|p| p == "write") {
        readable.clone()
    } else {
        vec![grantor.to_string()]
    };
    let grant = NamespaceGrantV2 {
        grant_id: grant_id.clone(),
        path: namespace.to_string(),
        readable_by: readable,
        writable_by: writable,
        expires_at_ms: None,
    };
    if let Some(existing) = setup
        .common_spaces
        .iter_mut()
        .find(|g| g.grant_id == grant_id || g.path == namespace)
    {
        *existing = grant.clone();
    } else {
        setup.common_spaces.push(grant.clone());
    }
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            GRANT_FOLDER,
            &grant_id,
            &serde_json::to_value(&grant).unwrap_or_default(),
        );
    }
    let _ = agent_identity_envelope::save_setup(state, &setup);
    Some(grant_id)
}

/// Track 2 Phase C — Item C.2: List active ports between agents
pub async fn list_ports(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();

    // Collect port info from audit log (PortBind/PortSend operations)
    let port_ops: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.operation == vac_core::types::MemoryKernelOp::PortBind
                || e.operation == vac_core::types::MemoryKernelOp::PortSend
                || e.operation == vac_core::types::MemoryKernelOp::PortReceive
        })
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": &e.agent_pid,
                "target": &e.target,
                "outcome": format!("{:?}", e.outcome),
            })
        })
        .collect();

    Json(serde_json::json!({
        "port_operations": port_ops.len(),
        "ports": port_ops,
    }))
}

pub async fn cross_agent_map(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let agents: Vec<serde_json::Value> = k
        .agents()
        .iter()
        .map(|(pid, acb)| {
            let ns = format!("ns:{}", acb.agent_pid);
            let shared_count = k
                .audit_log()
                .iter()
                .filter(|e| e.agent_pid == *pid && e.operation == MemoryKernelOp::AccessGrant)
                .count();
            serde_json::json!({
                "pid": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "shared_memories": shared_count,
            })
        })
        .collect();
    Json(serde_json::json!({
        "agents": agents,
        "mesh_knowledge_plane": "GET /api/v1/multiagent/mesh/knowledge-plane — shared knowledge, instruction injection, grants, ledger, Knot substrate",
    }))
}

/// DI-4 — chartered inter-intelligence task under grants (A2A-class fabric).
/// POST /multiagent/tasks/dispatch
pub async fn dispatch_task(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let from_pid = req
        .get("from_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let to_pid = req
        .get("to_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let namespace = req
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let message = req.get("message").cloned().unwrap_or(serde_json::json!({}));

    if from_pid.is_empty() || to_pid.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "invalid_request",
            "message": "from_pid and to_pid are required",
            "status": 400,
        }));
    }

    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &from_pid,
        "a2a.send",
        &to_pid,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
        }));
    }
    let ns_opt = if namespace.is_empty() {
        None
    } else {
        Some(namespace.as_str())
    };
    if let Err(e) = crate::kernel::agent_identity_envelope::require_inter_intelligence_grant(
        state.as_ref(),
        &from_pid,
        &to_pid,
        ns_opt,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "grant_required",
            "status": 403,
        }));
    }

    // REST callers pass api_pid (`agent_…`); kernel ACB is keyed by `pid:…`.
    let (from_kernel, from_api) =
        crate::services::agents::resolve_kernel_pid_pub(&state, &from_pid);
    let (to_kernel, to_api) = crate::services::agents::resolve_kernel_pid_pub(&state, &to_pid);
    let both_exist = {
        let k = state.kernel.lock().unwrap();
        k.get_agent(&from_kernel).is_some() && k.get_agent(&to_kernel).is_some()
    };
    if !both_exist {
        return Json(serde_json::json!({
            "ok": false,
            "error": "agent_not_found",
            "message": "from_pid and to_pid must be registered intelligences",
            "status": 404,
        }));
    }
    let from_pid = from_api;
    let to_pid = to_api;
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &from_pid,
        "lifecycle",
        "assign_agent_task",
        &serde_json::json!({"from_pid": from_pid.as_str(), "to_pid": to_pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let context_id = req.get("context_id").and_then(|v| v.as_str());
    let grant_id = req.get("grant_id").and_then(|v| v.as_str());
    let conp_entity_id = req.get("conp_entity_id").and_then(|v| v.as_str());
    let ns = if namespace.is_empty() {
        None
    } else {
        Some(namespace.as_str())
    };

    match crate::kernel::fabric_task::create_task(
        state.as_ref(),
        &from_pid,
        &to_pid,
        message,
        ns,
        context_id,
        grant_id,
        conp_entity_id,
    ) {
        Ok(task) => {
            // Auto-advance Submitted → Working (platform-mediated queue pickup).
            let task = crate::kernel::fabric_task::transition(
                state.as_ref(),
                &task.task_id,
                crate::kernel::fabric_task::FabricTaskState::Working,
                None,
            )
            .unwrap_or(task);
            let mut body = crate::kernel::fabric_task::task_json(&task);
            if let Some(o) = body.as_object_mut() {
                o.insert("status".into(), serde_json::json!(202));
                o.insert(
                    "get_hint".into(),
                    serde_json::json!(format!("GET /api/v1/fabric/tasks/{}", task.task_id)),
                );
                o.insert(
                    "honesty".into(),
                    serde_json::json!(
                        "TG-4 fabric.task.v2 — charter + grant gated; authority on every task"
                    ),
                );
            }
            open_proceed.finish_observed(true);
            if let Some(o) = body.as_object_mut() {
                o.insert("pate_task_id".into(), serde_json::json!(admitted.task_id));
                o.insert("executed".into(), serde_json::json!(true));
                o.insert("admits".into(), serde_json::json!(false));
            }
            Json(body)
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(serde_json::json!({
                "ok": false,
                "error": e,
                "status": 500,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    }
}
