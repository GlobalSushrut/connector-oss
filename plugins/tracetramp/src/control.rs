//! Control Pipeline
//!
//! Policy enforcement, risk scoring, routing, approvals, guards  
//! Active only in Control Mode
//!
//! ## Ledger / “blockchain-inspired” integrity (product philosophy)
//!
//! - **Append-only evidence:** `trace_events` rows are an ordered ledger of what the control plane
//!   observed and decided. A DB trigger forbids `DELETE` and forbids mutating immutable columns;
//!   only **`metadata` may grow** (e.g. `response_preview` backfill) — same idea as a chain where
//!   new links are added, not rewritten. Tampering with past cells requires superuser / breaking the
//!   database contract, not a normal API path.
//! - **State changes = real commands:** Blocks, quarantine, approvals, and releases take effect
//!   through **authenticated management actions** (HTTP admin / operator flows), not silent
//!   in-process toggles. That mirrors “transactions”: nothing commits without an explicit command
//!   arriving on the control plane.
//! - **Git-like governance:** Policy and scoped blocks are **versioned supersessions** — you add or
//!   revoke rules through explicit operations; there is no hidden branch that bypasses enforcement
//!   while still claiming Control mode.
//!
//! **Enforcement boundary:** In Control mode, every deny path (`return Ok(Response::…)` with
//! 4xx/429/202) is taken **before** the LLM/provider upstream is invoked for generation. A caller
//! cannot “talk around” TraceTramp while still using this ingress — bypass would mean **not**
//! routing traffic through TraceTramp (e.g. raw provider API keys, alternate tunnels). Closing
//! that gap is a **deployment** concern (egress allow‑lists, identity‑bound keys, mTLS, no direct
//! internet from agent hosts), not something application code can mathematically forbid.
//!
//! **Pipeline shape:** Control is the main line — **meter** (cost/tokens), **filter** (policy / PII /
//! risk signals), **quarantine** (operation blocks, session quarantine) — with **git-like**
//! governance (versioned policy/blocks; revoke/release is an explicit operator action, not a
//! second “observability-only” product mode).

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{Stream, StreamExt, stream};
use reqwest::Response as ReqwestResponse;
use sqlx::{types::Json, Row};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, error};

use crate::{
    AppState,
    error::AppError,
    types::{
        RuntimeExecutionRequest, ChatCompletionRequest,
        ExecutionStep, StepResult, RequestMode,
    },
    connector::{ConnectorClient, PolicyResult, AdmissionResult},
    decision::DecisionTreeBuilder,
    providers::TokenUsage,
    storage,
    view::{self, calculate_cost},
};

/// Control runs **enforcement** and **observation** in parallel on the same request (`trace_events`,
/// decision trees, Connector audit, optional Witness handoff). Exposed on every Control HTTP response.
const HDR_TRACE_TRAMP_LANES: &str = "X-TraceTramp-Lanes";
const VAL_TRACE_TRAMP_LANES: &str = "control,observe";

/// Core `hitl` object (lane, block class, evidence) stored in `approval_queue.hold_metadata` and echoed on 202 responses.
fn hitl_hold_core(
    lane: &str,
    block_class: &str,
    tenant_id: &str,
    actor_id: &str,
    trace_id: uuid::Uuid,
    request_id: uuid::Uuid,
    evidence_extra: serde_json::Value,
    kernel_host_at_hold: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut evidence = serde_json::json!({
        "refs": {
            "trace_id": trace_id.to_string(),
            "request_id": request_id.to_string(),
            "tenant_id": tenant_id,
            "actor_id": actor_id,
        }
    });
    if let (Some(ev_obj), Some(ext_obj)) = (evidence.as_object_mut(), evidence_extra.as_object()) {
        for (k, v) in ext_obj.iter() {
            if k == "refs" {
                continue;
            }
            ev_obj.insert(k.clone(), v.clone());
        }
    }
    if let (Some(ev_obj), Some(k)) = (evidence.as_object_mut(), kernel_host_at_hold) {
        if !k.is_null() {
            let slim = serde_json::json!({
                "policy_revision": k.get("policy_revision"),
                "profile_id": k.get("profile_id"),
                "host_apply_state": k.get("host_apply_state"),
                "bpf_pin_prefix": k.get("bpf_pin_prefix"),
            });
            ev_obj.insert("kernel_host_at_hold".to_string(), slim);
        }
    }
    serde_json::json!({
        "lane": lane,
        "block": { "class": block_class },
        "evidence": evidence,
    })
}

/// JSON body for 202 pending-approval responses — merges remediation into `hitl_core` from [`hitl_hold_core`].
fn merge_hitl_envelope(
    approval_id: &str,
    trace_id: uuid::Uuid,
    request_id: uuid::Uuid,
    message: &str,
    approvers: &[String],
    mut hitl_core: serde_json::Value,
) -> serde_json::Value {
    if let Some(obj) = hitl_core.as_object_mut() {
        obj.insert(
            "human_async_note".to_string(),
            serde_json::json!("Human review is asynchronous (no fixed 30s SLA). Use TraceTramp TUI (P) or POST /admin/approvals/:id/approve | reject | quarantine. Approving resumes the run when request_payload is stored."),
        );
        obj.insert(
            "regulatory_hints".to_string(),
            serde_json::json!([
                "human_oversight",
                "audit_trail",
                "authorization_boundary",
            ]),
        );
        obj.insert(
            "remediation".to_string(),
            serde_json::json!({
                "approve_once": format!("/admin/approvals/{}/approve", approval_id),
                "reject": format!("/admin/approvals/{}/reject", approval_id),
                "quarantine_agent": format!("/admin/approvals/{}/quarantine", approval_id),
                "update_policy_hint": "TUI: l (policy editor) — adjust rules, save, then approve or reject this hold.",
            }),
        );
    }
    serde_json::json!({
        "status": "pending_approval",
        "message": message,
        "approval_id": approval_id,
        "approvers": approvers,
        "trace_id": trace_id.to_string(),
        "request_id": request_id.to_string(),
        "hitl": hitl_core,
    })
}

/// Handle a request in Control Mode (full enforcement)
pub async fn handle_request(
    state: Arc<AppState>,
    mut runtime_req: RuntimeExecutionRequest,
    headers: HeaderMap,
    chat_req: ChatCompletionRequest,
) -> Result<Response, AppError> {
    let _active_call_guard = ActiveCallGuard::new(state.active_calls.clone());
    let request_started = Instant::now();
    let trace_id = runtime_req.trace_id;
    let request_id = runtime_req.request_id;
    let tenant_id = runtime_req.tenant_id.clone();
    
    info!("Control Pipeline: handling request trace_id={} tenant={}", trace_id, tenant_id);

    // Resume latch: after admin approve + execute, client retries with
    // X-Approval-Resume: approved and X-Approval-Id: <id>.
    if let Some(approval_id) = approval_resume_id(&headers) {
        match consume_approval_resume(&state, &approval_id, &runtime_req.tenant_id).await {
            Ok(()) => {
                runtime_req.hitl_bypass = true;
                info!(approval_id = %approval_id, "HITL resume accepted (consume-once)");
            }
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("X-Trace-Id", trace_id.to_string())
                    .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                    .header("X-Block-Reason", "approval_resume_denied")
                    .body(Body::from(serde_json::json!({
                        "error": {
                            "message": e.to_string(),
                            "type": "approval_resume_denied",
                            "approval_id": approval_id,
                            "trace_id": trace_id.to_string(),
                        }
                    }).to_string()))
                    .unwrap());
            }
        }
    }

    let message_count = chat_req.messages.len();
    let tools_count = chat_req.tools.as_ref().map(|t| t.len()).unwrap_or(0);

    // P6.4: optional FNI from X-Connector-FNI / CFNI wire header → trace_events.metadata
    let fni = fni_from_headers(&headers);

    // Step 1: Record request.received with prompt evidence
    let mut received_meta = serde_json::json!({
        "operation": operation_context(&runtime_req),
        "message_count": message_count,
        "tools_count": tools_count,
    });
    if let Some(ref f) = fni {
        if let Some(obj) = received_meta.as_object_mut() {
            obj.insert("fni_flow_id".into(), serde_json::Value::String(f.flow_id.clone()));
            // Always unverified at ingest — verify only via GET …/fni-verify.
            obj.insert(
                "fni_verify_status".into(),
                serde_json::Value::String("unverified".into()),
            );
            if let Some(ref wire) = f.cfni_wire {
                obj.insert(
                    "fni_cfni_wire".into(),
                    serde_json::Value::String(wire.clone()),
                );
            }
        }
    }
    record_event(&state, &runtime_req, ExecutionStep::RequestReceived, StepResult::Success, Some(received_meta)).await?;
    
    // Step 2: Identity resolved (already done in gateway, but record)
    record_event(&state, &runtime_req, ExecutionStep::IdentityResolved, StepResult::Success, None).await?;

    // Step 2.5a: Operation-scoped block (specific work type, not whole agent).
    if let Some(block_reason) = check_operation_block(&state, &runtime_req).await? {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::PolicyChecked,
            StepResult::Block {
                reason: block_reason.clone(),
            },
            Some(serde_json::json!({
                "operation_blocked": true,
                "decision_reason": block_reason.clone(),
                "duration_ms": request_started.elapsed().as_millis() as u64,
            })),
        )
        .await?;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Block-Reason", "operation_blocked")
            .body(Body::from(serde_json::json!({
                "error": {
                    "message": block_reason,
                    "type": "operation_blocked",
                    "trace_id": trace_id.to_string(),
                }
            }).to_string()))
            .unwrap());
    }

    // Step 2.5b: Full quarantine enforcement (fail closed in hot path).
    if let Some(quarantine_reason) = check_quarantine(&state, &runtime_req).await? {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::PolicyChecked,
            StepResult::Block {
                reason: quarantine_reason.clone(),
            },
            Some(serde_json::json!({
                "quarantined": true,
                "decision_reason": quarantine_reason.clone(),
                "duration_ms": request_started.elapsed().as_millis() as u64,
            })),
        )
        .await?;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Block-Reason", "quarantined")
            .body(Body::from(serde_json::json!({
                "error": {
                    "message": quarantine_reason,
                    "type": "quarantined",
                    "trace_id": trace_id.to_string(),
                }
            }).to_string()))
            .unwrap());
    }

    // Step 2.7: Default HITL hold for high-risk financial/write actions.
    if !runtime_req.hitl_bypass {
        if let Some(hold_reason) = classify_default_hitl_hold(&runtime_req) {
        let hitl_core = hitl_hold_core(
            "default_hitl",
            "authorization",
            &runtime_req.tenant_id,
            &runtime_req.actor_id,
            trace_id,
            request_id,
            serde_json::json!({}),
            runtime_req.kernel_host_snapshot.as_ref(),
        );
        let approval_id = enqueue_default_hitl_hold(
            &state,
            &runtime_req,
            &chat_req,
            &hold_reason,
            hitl_core.clone(),
        )
        .await?;
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::ApprovalRequested,
            StepResult::RequireApproval {
                approvers: vec!["security-review".to_string()],
            },
            Some(serde_json::json!({
                "reason": hold_reason,
                "approval_id": approval_id,
                "policy_source": "default_hitl_high_risk_actions",
                "duration_ms": request_started.elapsed().as_millis() as u64,
            })),
        )
        .await?;
        let hitl_body = merge_hitl_envelope(
            &approval_id,
            trace_id,
            request_id,
            &hold_reason,
            &[String::from("security-review")],
            hitl_core,
        );
        return Ok(Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Approval-Required", "true")
            .header("X-HITL-Policy", "default_high_risk")
            .body(Body::from(hitl_body.to_string()))
            .unwrap());
        }
    }
    
    // Step 3: Policy check
    debug!("Checking policy for request: {}", request_id);
    let policy_result = state.connector_client
        .check_policy(&runtime_req, &runtime_req.policy_bundle)
        .await?;
    
    let policy_step_result = match policy_result.outcome.as_str() {
        "allow" => {
            record_event(&state, &runtime_req, ExecutionStep::PolicyChecked, 
                StepResult::Allow, Some(serde_json::json!({"reason": policy_result.reason}))).await?;
            StepResult::Allow
        }
        "block" => {
            record_event(&state, &runtime_req, ExecutionStep::PolicyChecked,
                StepResult::Block { reason: policy_result.reason.clone() }, None).await?;

            if state.config.soft_policy_block && !runtime_req.hitl_bypass {
                let hold_msg = format!(
                    "[policy_hold] Policy would block ({}). Held for human — approve to run once, reject to deny, or quarantine to isolate agent.",
                    policy_result.reason
                );
                let hitl_core = hitl_hold_core(
                    "policy_soft_block",
                    "policy",
                    &runtime_req.tenant_id,
                    &runtime_req.actor_id,
                    trace_id,
                    request_id,
                    serde_json::json!({ "policy_block_reason": policy_result.reason }),
                    runtime_req.kernel_host_snapshot.as_ref(),
                );
                let approval_id = enqueue_default_hitl_hold(
                    &state,
                    &runtime_req,
                    &chat_req,
                    &hold_msg,
                    hitl_core.clone(),
                )
                .await?;
                record_event(
                    &state,
                    &runtime_req,
                    ExecutionStep::ApprovalRequested,
                    StepResult::RequireApproval {
                        approvers: vec!["security-review".to_string()],
                    },
                    Some(serde_json::json!({
                        "reason": hold_msg,
                        "approval_id": approval_id,
                        "policy_source": "soft_policy_block",
                        "original_block_reason": policy_result.reason,
                        "duration_ms": request_started.elapsed().as_millis() as u64,
                    })),
                )
                .await?;
                let hitl_body = merge_hitl_envelope(
                    &approval_id,
                    trace_id,
                    request_id,
                    &hold_msg,
                    &[String::from("security-review")],
                    hitl_core,
                );
                return Ok(Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .header("X-Trace-Id", trace_id.to_string())
                    .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                    .header("X-Approval-Required", "true")
                    .header("X-HITL-Policy", "soft_policy_block")
                    .body(Body::from(hitl_body.to_string()))
                    .unwrap());
            }

            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("X-Trace-Id", trace_id.to_string())
                .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                .header("X-Block-Reason", &policy_result.reason)
                .body(Body::from(serde_json::json!({
                    "error": {
                        "message": format!("Request blocked by policy: {}", policy_result.reason),
                        "type": "policy_violation",
                        "trace_id": trace_id.to_string(),
                    }
                }).to_string()))
                .unwrap());
        }
        "require_approval" => {
            record_event(
                &state,
                &runtime_req,
                ExecutionStep::PolicyChecked,
                StepResult::RequireApproval {
                    approvers: policy_result.approvers.clone(),
                },
                None,
            )
            .await?;

            let hold_msg = format!(
                "Connector policy requires approval ({})",
                policy_result.reason
            );
            let hitl_core = hitl_hold_core(
                "connector_require_approval",
                "policy",
                &runtime_req.tenant_id,
                &runtime_req.actor_id,
                trace_id,
                request_id,
                serde_json::json!({
                    "policy_block_reason": policy_result.reason,
                    "approvers": policy_result.approvers,
                }),
                runtime_req.kernel_host_snapshot.as_ref(),
            );

            let (approval_id, lane_note) = if let Some(redis) = state.redis_pool.as_ref() {
                storage::enqueue_approval(
                    &mut redis.clone(),
                    &request_id.to_string(),
                    &policy_result.approvers,
                )
                .await?;
                (
                    request_id.to_string(),
                    "Queued for approvers (redis legacy queue + postgres when redis disabled)",
                )
            } else {
                let approval_id = enqueue_default_hitl_hold(
                    &state,
                    &runtime_req,
                    &chat_req,
                    &hold_msg,
                    hitl_core.clone(),
                )
                .await?;
                (
                    approval_id,
                    "Queued in PostgreSQL approval_queue (redis disabled)",
                )
            };

            let mut body = merge_hitl_envelope(
                &approval_id,
                trace_id,
                request_id,
                &hold_msg,
                &policy_result.approvers,
                hitl_core,
            );
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "hitl".to_string(),
                    serde_json::json!({
                        "lane": "connector_require_approval",
                        "human_async_note": lane_note,
                    }),
                );
            }
            return Ok(Response::builder()
                .status(StatusCode::ACCEPTED)
                .header("X-Trace-Id", trace_id.to_string())
                .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                .header("X-Approval-Required", "true")
                .header("X-HITL-Policy", "connector_require_approval")
                .body(Body::from(body.to_string()))
                .unwrap());
        }
        "route" => {
            record_event(&state, &runtime_req, ExecutionStep::PolicyChecked,
                StepResult::Route { target: policy_result.routing_target.clone().unwrap_or_default() }, None).await?;
            StepResult::Route { target: policy_result.routing_target.clone().unwrap_or_default() }
        }
        _ => {
            warn!("Unknown policy outcome: {}", policy_result.outcome);
            StepResult::Allow
        }
    };
    
    // Step 4: Risk scoring — score is based on prompt content signals
    let risk_score = compute_risk_score(&chat_req, &runtime_req);
    let risk_level = if risk_score >= 0.7 { "high" } else if risk_score >= 0.4 { "medium" } else { "low" };
    record_event(&state, &runtime_req, ExecutionStep::RiskScored,
        if risk_score >= 0.7 { StepResult::Block { reason: format!("risk score {:.2} exceeds threshold", risk_score) } } else { StepResult::Allow },
        Some(serde_json::json!({
            "score": risk_score,
            "level": risk_level,
            "message_count": message_count,
            "tools_count": tools_count,
        }))).await?;
    
    // Step 5: Route selection
    let selected_model = policy_result
        .routing_target
        .clone()
        .unwrap_or_else(|| chat_req.model.clone());
    let mut modified_req = chat_req.clone();
    modified_req.model = selected_model.clone();
    
    record_event(&state, &runtime_req, ExecutionStep::RouteSelected,
        StepResult::Success, Some(serde_json::json!({
            "model": selected_model,
            "duration_ms": request_started.elapsed().as_millis() as u64,
        }))).await?;
    
    // Step 6: Budget check
    let budget_check = check_budget(&state, &runtime_req, &tenant_id).await?;
    if !budget_check.allowed {
        record_event(&state, &runtime_req, ExecutionStep::CostRecorded,
            StepResult::Block { reason: budget_check.reason.clone() }, None).await?;
        
        return Ok(Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Budget-Exceeded", "true")
            .body(Body::from(serde_json::json!({
                "error": {
                    "message": budget_check.reason,
                    "type": "budget_exceeded",
                    "trace_id": trace_id.to_string(),
                }
            }).to_string()))
            .unwrap());
    }
    
    // Memory is a MemPacket in the kernel store. TraceTramp does not write it.
    if let Some(ref memory_scope) = runtime_req.memory_scope {
        debug!(
            scope = %memory_scope,
            actor = %runtime_req.actor_id,
            "memory scope is not a TraceTramp row"
        );
    }
    
    // Step 8: Tool check
    if !runtime_req.tools_requested.is_empty() {
        for tool in &runtime_req.tools_requested {
            // Check tool approval queue
            let tool_allowed = check_tool_permission(&state, &runtime_req, tool).await?;
            
            if tool_allowed {
                record_event(&state, &runtime_req, ExecutionStep::ToolAllowed,
                    StepResult::Allow, Some(serde_json::json!({"tool": tool}))).await?;
            } else {
                record_event(&state, &runtime_req, ExecutionStep::ToolBlocked,
                    StepResult::Block { reason: format!("Tool {} not approved", tool) }, None).await?;

                if state.config.soft_tool_block && !runtime_req.hitl_bypass {
                    let hold_msg = format!(
                        "[tool_hold] Tool '{}' not approved — held for human. Approve to run once (with tools), reject to deny, or quarantine to isolate agent.",
                        tool
                    );
                    let hitl_core = hitl_hold_core(
                        "tool_soft_block",
                        "tool",
                        &runtime_req.tenant_id,
                        &runtime_req.actor_id,
                        trace_id,
                        request_id,
                        serde_json::json!({ "blocked_tool": tool }),
                        runtime_req.kernel_host_snapshot.as_ref(),
                    );
                    let approval_id = enqueue_default_hitl_hold(
                        &state,
                        &runtime_req,
                        &chat_req,
                        &hold_msg,
                        hitl_core.clone(),
                    )
                    .await?;
                    record_event(
                        &state,
                        &runtime_req,
                        ExecutionStep::ApprovalRequested,
                        StepResult::RequireApproval {
                            approvers: vec!["security-review".to_string()],
                        },
                        Some(serde_json::json!({
                            "reason": hold_msg,
                            "approval_id": approval_id,
                            "policy_source": "soft_tool_block",
                            "blocked_tool": tool,
                            "duration_ms": request_started.elapsed().as_millis() as u64,
                        })),
                    )
                    .await?;
                    let hitl_body = merge_hitl_envelope(
                        &approval_id,
                        trace_id,
                        request_id,
                        &hold_msg,
                        &[String::from("security-review")],
                        hitl_core,
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .header("X-Trace-Id", trace_id.to_string())
                        .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                        .header("X-Approval-Required", "true")
                        .header("X-HITL-Policy", "soft_tool_block")
                        .header("X-Tool-Pending", tool)
                        .body(Body::from(hitl_body.to_string()))
                        .unwrap());
                }

                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("X-Trace-Id", trace_id.to_string())
                    .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                    .header("X-Tool-Blocked", tool)
                    .body(Body::from(serde_json::json!({
                        "error": {
                            "message": format!("Tool '{}' not permitted", tool),
                            "type": "tool_not_allowed",
                            "trace_id": trace_id.to_string(),
                        }
                    }).to_string()))
                    .unwrap());
            }
        }
    }

    // Step 8b: Human gate before LLM — test clients or configured high-risk (semi-auto remediation path).
    let pre_llm_hold = (runtime_req.test_hold_requested && !runtime_req.hitl_bypass)
        || (state.config.high_risk_hold_before_llm
            && !runtime_req.hitl_bypass
            && risk_score >= 0.7);
    if pre_llm_hold {
        let (lane, hold_msg) = if runtime_req.test_hold_requested {
            (
                "test_hitl",
                "[test_hold] X-TraceTramp-Test-Hold: paused before model call — approve (a in TUI) to run once, x=reject, c=quarantine, l=edit policy.".to_string(),
            )
        } else {
            (
                "high_risk_hold",
                format!(
                    "[risk_hold] High risk score ({:.2}) — paused before LLM. Approve to proceed, quarantine to isolate, or reject.",
                    risk_score
                ),
            )
        };
        let (block_class, evidence_extra) = if runtime_req.test_hold_requested {
            ("test", serde_json::json!({}))
        } else {
            ("risk", serde_json::json!({ "risk_score": risk_score }))
        };
        let hitl_core = hitl_hold_core(
            lane,
            block_class,
            &runtime_req.tenant_id,
            &runtime_req.actor_id,
            trace_id,
            request_id,
            evidence_extra,
            runtime_req.kernel_host_snapshot.as_ref(),
        );
        let approval_id = enqueue_default_hitl_hold(
            &state,
            &runtime_req,
            &chat_req,
            &hold_msg,
            hitl_core.clone(),
        )
        .await?;
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::ApprovalRequested,
            StepResult::RequireApproval {
                approvers: vec!["security-review".to_string()],
            },
            Some(serde_json::json!({
                "reason": hold_msg,
                "approval_id": approval_id,
                "policy_source": lane,
                "risk_score": risk_score,
                "duration_ms": request_started.elapsed().as_millis() as u64,
            })),
        )
        .await?;
        let hitl_body = merge_hitl_envelope(
            &approval_id,
            trace_id,
            request_id,
            &hold_msg,
            &[String::from("security-review")],
            hitl_core,
        );
        return Ok(Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Approval-Required", "true")
            .header("X-HITL-Policy", lane)
            .body(Body::from(hitl_body.to_string()))
            .unwrap());
    }
    
    // Step 9: Local in-memory PII guard (runtime decision only; persistence goes to WitnessCtl ingest)
    let pii_observation = inspect_request_pii(&mut modified_req);
    if pii_observation.blocked {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::OutputBlocked,
            StepResult::Block {
                reason: "PII detected in request".to_string(),
            },
            Some(serde_json::json!({
                "pii_in_request": true,
                "pii_count": pii_observation.count,
                "classifications": pii_observation.classifications,
            })),
        )
        .await?;

        let connector = state.connector_client.clone();
        let witness_base = state.config.witness_handoff_base_url.clone();
        let witness_secret = state.config.witness_handoff_secret.clone();
        let witness_payload = serde_json::json!({
            "request_id": request_id.to_string(),
            "trace_id": trace_id.to_string(),
            "tenant_id": runtime_req.tenant_id,
            "actor_id": runtime_req.actor_id,
            "mode": "control",
            "decision": "block",
            "reason": "pii_detected",
            "pii_in_request": true,
            "pii_classifications": pii_observation.classifications,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        tokio::spawn(async move {
            if let Err(e) = connector
                .witness_tracetramp_handoff(
                    witness_base.as_deref(),
                    witness_secret.as_deref(),
                    &witness_payload,
                )
                .await
            {
                warn!("WitnessCtl handoff failed (non-blocking): {}", e);
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("X-Trace-Id", trace_id.to_string())
            .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
            .header("X-Block-Reason", "pii_detected")
            .body(Body::from(serde_json::json!({
                "error": {
                    "message": "Request blocked: sensitive PII pattern detected",
                    "type": "pii_violation",
                    "trace_id": trace_id.to_string(),
                }
            }).to_string()))
            .unwrap());
    }
    if pii_observation.redacted {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::OutputRedacted,
            StepResult::Redact { fields: pii_observation.pii_types.clone() },
            Some(serde_json::json!({
                "pii_in_request": true,
                "pii_count": pii_observation.count,
                "classifications": pii_observation.classifications,
            })),
        )
        .await?;
    }

    // Step 10: Call provider through Connector
    let provider_chain = load_provider_chain(&state).await?;
    let (connector_response, served_provider, fallback_attempted) = match proxy_with_fallback(
        &state,
        &modified_req,
        &headers,
        &provider_chain,
    ).await {
        Ok(v) => v,
        Err(e) => {
            warn!("All provider fallbacks exhausted: {}", e);
            let reason = format!("provider_unavailable: {}", e);
            let _ = record_event(
                &state,
                &runtime_req,
                ExecutionStep::ProviderCalled,
                StepResult::Block {
                    reason: reason.clone(),
                },
                Some(serde_json::json!({
                    "error_detail": e.to_string(),
                    "duration_ms": request_started.elapsed().as_millis() as u64,
                })),
            )
            .await;
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("X-Trace-Id", trace_id.to_string())
                .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
                .header("X-Fallback-Attempted", "true")
                .body(Body::from(serde_json::json!({
                    "error": {
                        "message": "All providers exhausted after fallback attempts",
                        "type": "provider_unavailable",
                        "trace_id": trace_id.to_string()
                    }
                }).to_string()))
                .unwrap());
        }
    };
    record_event(
        &state,
        &runtime_req,
        ExecutionStep::ProviderCalled,
        StepResult::Success,
        Some(serde_json::json!({
            "provider": served_provider,
            "model": selected_model,
            "policy_source": runtime_req.policy_bundle,
            "duration_ms": request_started.elapsed().as_millis() as u64,
        })),
    ).await?;

    if modified_req.stream == Some(true) {
        return stream_sse_response(
            state,
            runtime_req,
            connector_response,
            fallback_attempted,
            "control",
            &policy_result.outcome,
        )
        .await;
    }
    
    record_event(&state, &runtime_req, ExecutionStep::ResponseReceived, StepResult::Success, None).await?;

    let connector_status = connector_response.status();
    let connector_headers = connector_response.headers().clone();
    let response_bytes = connector_response.bytes().await?;
    let llm_output = String::from_utf8_lossy(&response_bytes).to_string();
    let usage = extract_openai_usage(&llm_output);
    let input_tokens = usage
        .as_ref()
        .map(|u| u.0)
        .or_else(|| connector_headers
            .get("X-Input-Tokens")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok()))
        .unwrap_or(0);
    let output_tokens = usage
        .as_ref()
        .map(|u| u.1)
        .or_else(|| connector_headers
            .get("X-Output-Tokens")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok()))
        .unwrap_or(0);
    let actual_model = extract_openai_model(&llm_output).unwrap_or_else(|| selected_model.clone());
    
    // Check output for PII/leakage (placeholder)
    let output_clean = true;
    
    if output_clean {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::OutputChecked,
            StepResult::Allow,
            Some(serde_json::json!({
                "provider": served_provider,
                "model": actual_model,
                "policy_source": runtime_req.policy_bundle,
                "tokens_in": input_tokens,
                "tokens_out": output_tokens,
                "duration_ms": request_started.elapsed().as_millis() as u64,
            })),
        ).await?;
    } else {
        record_event(&state, &runtime_req, ExecutionStep::OutputRedacted,
            StepResult::Redact { fields: vec!["ssn".to_string()] }, None).await?;
    }
    
    // Step 12: Record cost
    let cost_usd = calculate_cost(&actual_model, input_tokens, output_tokens);
    state
        .connector_client
        .record_usage(
            &runtime_req.actor_id,
            input_tokens,
            output_tokens,
            cost_usd,
        )
        .await?;
    if let Err(e) = persist_cost_and_rollups(
        &state,
        &runtime_req,
        &actual_model,
        served_provider.as_str(),
        input_tokens,
        output_tokens,
        cost_usd,
        &policy_result.outcome,
        request_started.elapsed().as_millis() as i64,
    )
    .await
    {
        warn!("Local cost rollup persist failed (non-blocking): {}", e);
    }
    
    record_event(
        &state,
        &runtime_req,
        ExecutionStep::CostRecorded,
        StepResult::Success,
        Some(serde_json::json!({
            "provider": served_provider,
            "model": actual_model,
            "policy_source": runtime_req.policy_bundle,
            "tokens_in": input_tokens,
            "tokens_out": output_tokens,
            "cost_usd": cost_usd,
            "latency_ms": request_started.elapsed().as_millis() as u64,
            "duration_ms": request_started.elapsed().as_millis() as u64,
        })),
    ).await?;
    
    // Step 13: Response released
    record_event(
        &state,
        &runtime_req,
        ExecutionStep::ResponseReleased,
        StepResult::Success,
        Some(serde_json::json!({
            "provider": served_provider,
            "model": actual_model,
            "policy_source": runtime_req.policy_bundle,
            "tokens_in": input_tokens,
            "tokens_out": output_tokens,
            "cost_usd": cost_usd,
            "latency_ms": request_started.elapsed().as_millis() as u64,
            "duration_ms": request_started.elapsed().as_millis() as u64,
            "finish_reason": "stop",
            "pii_detected": pii_observation.count > 0,
            "decision_reason": policy_result.reason,
        })),
    ).await?;

    // Best-effort interaction log; should never block primary response flow
    if let Err(e) = state.connector_client.log_interaction(
        &request_id.to_string(),
        &trace_id.to_string(),
        &runtime_req.tenant_id,
        "chat.completion",
        &policy_result.outcome,
    ).await {
        warn!("Failed to log interaction to Connector: {}", e);
    }

    {
        let connector = state.connector_client.clone();
        let witness_base = state.config.witness_handoff_base_url.clone();
        let witness_secret = state.config.witness_handoff_secret.clone();
        let witness_payload = serde_json::json!({
            "request_id": request_id.to_string(),
            "trace_id": trace_id.to_string(),
            "tenant_id": runtime_req.tenant_id,
            "actor_id": runtime_req.actor_id,
            "mode": "control",
            "decision": policy_result.outcome,
            "pii_in_request": pii_observation.count > 0,
            "pii_classifications": pii_observation.classifications,
            "cost_usd": cost_usd,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        tokio::spawn(async move {
            if let Err(e) = connector
                .witness_tracetramp_handoff(
                    witness_base.as_deref(),
                    witness_secret.as_deref(),
                    &witness_payload,
                )
                .await
            {
                warn!("WitnessCtl handoff failed (non-blocking): {}", e);
            }
        });
    }
    
    // Step 14: Receipt issued
    let receipt = state.connector_client
        .issue_receipt(&request_id.to_string(), &trace_id.to_string(), "success")
        .await?;
    
    record_event(&state, &runtime_req, ExecutionStep::ReceiptIssued, StepResult::Success, Some(serde_json::json!({
        "receipt_cid": receipt.cid,
    }))).await?;
    
    info!("Control Pipeline: request completed trace_id={} model={} cost=${:.4}",
        trace_id, actual_model, cost_usd);

    // Persist preview into the same trace_events row the TUI aggregates — must complete before
    // returning so refresh/repaint sees ANSWER and inspector "answer" fields (async spawn raced the UI).
    let patch = serde_json::json!({
        "operation": operation_context(&runtime_req),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "model": actual_model,
    });
    match sqlx::query(
        "UPDATE trace_events SET metadata = metadata || $1::jsonb \
         WHERE trace_id = $2 AND request_id = $3 AND step = 'ReceiptIssued'",
    )
    .bind(Json(patch))
    .bind(trace_id.to_string())
    .bind(request_id.to_string())
    .execute(&state.db_pool)
    .await
    {
        Ok(r) if r.rows_affected() == 0 => {
            warn!(
                "ResponseReleased metadata patch: no row matched trace_id={} request_id={}",
                trace_id, request_id
            );
        }
        Err(e) => warn!("ResponseReleased metadata patch failed: {}", e),
        _ => {}
    }
    let mut decision_builder = DecisionTreeBuilder::new(
        &trace_id.to_string(),
        &request_id.to_string(),
        &runtime_req.tenant_id,
        &runtime_req.actor_id,
        &runtime_req.app_id,
    );
    let operation_record = operation_context(&runtime_req).to_string();
    let root_id = decision_builder.add_root_decision(
        crate::types::DecisionNodeType::ResponseGeneration,
        &operation_record,
        Some(&format!(
            "mode=control policy={} execution_profile={}",
            runtime_req.policy_bundle, runtime_req.execution_profile
        )),
        &format!(
            "decision={} model={} in={} out={}",
            policy_result.outcome, actual_model, input_tokens, output_tokens
        ),
        &policy_result.outcome,
        &actual_model,
        served_provider.as_str(),
        TokenUsage {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens + output_tokens,
            estimated_cost_usd: cost_usd,
        },
        request_started.elapsed().as_millis() as u64,
    );
    decision_builder.add_policy_check(
        &root_id,
        crate::types::PolicyCheck {
            policy_id: runtime_req.policy_bundle.clone(),
            policy_name: "runtime_policy".to_string(),
            check_type: "policy_outcome".to_string(),
            result: match policy_result.outcome.as_str() {
                "block" => crate::types::PolicyOutcome::Block,
                "require_approval" => crate::types::PolicyOutcome::RequireApproval,
                "allow_with_transform" => crate::types::PolicyOutcome::Redact,
                _ => crate::types::PolicyOutcome::Allow,
            },
            details: serde_json::json!({
                "reason": policy_result.reason.clone(),
                "routing_target": policy_result.routing_target.clone(),
                "approvers": policy_result.approvers.clone(),
            }),
        },
    );
    let decision_tree = decision_builder.build();
    if let Err(e) = crate::decision::persist_decision_tree(&state.db_pool, &decision_tree).await {
        warn!("Decision tree persistence failed (non-blocking): {}", e);
    }

    // Build response with enforcement headers.
    let status = StatusCode::from_u16(connector_status.as_u16()).unwrap_or(StatusCode::OK);
    let mut response_builder = Response::builder()
        .status(status)
        .header("X-Trace-Id", trace_id.to_string())
        .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
        .header("X-Request-Id", request_id.to_string())
        .header("X-Model-Used", actual_model)
        .header("X-Cost-USD", format!("{:.6}", cost_usd))
        .header("X-Policy-Outcome", &policy_result.outcome);
    if fallback_attempted {
        response_builder = response_builder.header("X-Fallback-Attempted", "true");
    }
    
    // Only forward content-type from the upstream response.
    // We must NOT copy transfer-encoding or content-encoding: reqwest already
    // decoded the chunked/compressed body into plain bytes, so forwarding those
    // headers would tell the client "the body is chunked/compressed" when it isn't,
    // causing Hyper to drop the connection (→ "Empty reply from server").
    // content-length is also omitted because Axum sets it automatically from the body.
    if let Some(ct) = connector_headers.get("content-type") {
        if let Ok(val) = axum::http::HeaderValue::from_bytes(ct.as_bytes()) {
            response_builder = response_builder.header("content-type", val);
        }
    }
    
    let body = Body::from(response_bytes);
    
    Ok(response_builder.body(body).unwrap())
}

/// Check if request is within budget
async fn check_budget(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    tenant_id: &str,
) -> Result<BudgetCheck, AppError> {
    check_budget_with_connector(&state.connector_client, req, tenant_id).await
}

/// Keys used to match `operation_blocks` rows (data-plane enforcement, not UI-only).
fn candidate_operation_keys(req: &RuntimeExecutionRequest) -> Vec<String> {
    let mut keys = vec!["llm.chat".to_string()];
    for t in &req.tools_requested {
        let t = t.trim();
        if !t.is_empty() {
            keys.push(format!("tool:{}", t));
        }
    }
    if let Some(w) = &req.workflow_id {
        let w = w.trim();
        if !w.is_empty() {
            keys.push(format!("workflow:{}", w));
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

async fn check_operation_block(
    state: &AppState,
    req: &RuntimeExecutionRequest,
) -> Result<Option<String>, AppError> {
    let candidates = candidate_operation_keys(req);
    for key in &candidates {
        let row = sqlx::query(
            "SELECT reason FROM operation_blocks \
             WHERE active = true \
               AND (tenant_id = $1 OR tenant_id = '*') \
               AND (actor_id = $2 OR actor_id = '*') \
               AND operation_key = $3 \
             LIMIT 1",
        )
        .bind(&req.tenant_id)
        .bind(&req.actor_id)
        .bind(key)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if let Some(r) = row {
            let reason: String = r.get("reason");
            return Ok(Some(format!(
                "Operation '{}' blocked for {} / {} ({})",
                key, req.tenant_id, req.actor_id, reason
            )));
        }
    }
    Ok(None)
}

async fn check_quarantine(
    state: &AppState,
    req: &RuntimeExecutionRequest,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query(
        "SELECT tenant_id, actor_id, COALESCE(comment, reason) AS reason
         FROM approval_queue
         WHERE status = 'quarantined'
           AND (tenant_id = $1 OR tenant_id = '*')
           AND (actor_id = $2 OR actor_id = '*')
         ORDER BY resolved_at DESC NULLS LAST, created_at DESC
         LIMIT 1"
    )
    .bind(&req.tenant_id)
    .bind(&req.actor_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(r) = row {
        let target_tenant: String = r.get("tenant_id");
        let target_actor: String = r.get("actor_id");
        let reason: String = r.get("reason");
        let scope = if target_actor == req.actor_id {
            format!("actor {}", req.actor_id)
        } else {
            format!("tenant {}", req.tenant_id)
        };
        return Ok(Some(format!(
            "Request blocked: {} is quarantined ({})",
            scope, reason
        )));
    }
    Ok(None)
}

async fn check_budget_with_connector(
    connector: &crate::connector::ConnectorClient,
    req: &RuntimeExecutionRequest,
    tenant_id: &str,
) -> Result<BudgetCheck, AppError> {
    if let Some(max_tokens) = req.budget_context.max_tokens {
        let _ = connector
            .create_budget(tenant_id, "tokens", max_tokens as f64)
            .await;
    }

    match connector
        .get_budget_status(tenant_id, "tokens")
        .await
    {
        Ok(status) => {
            if let (Some(limit), Some(remaining)) = (req.budget_context.max_tokens, status.remaining) {
                let pct_remaining = remaining / limit as f64;
                if pct_remaining <= 0.2 {
                    warn!(
                        "Budget alert threshold reached for tenant {}: {:.1}% remaining",
                        tenant_id,
                        pct_remaining * 100.0
                    );
                }
            }
            if status.exhausted {
                Ok(BudgetCheck {
                    allowed: false,
                    reason: "Tenant token budget exhausted".to_string(),
                })
            } else {
                Ok(BudgetCheck { allowed: true, reason: "".to_string() })
            }
        }
        Err(e) => {
            Err(AppError::ConnectorProxy(format!(
                "Could not enforce budget for tenant {}: {}",
                tenant_id, e
            )))
        }
    }
}

fn action_tokens(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| {
            value
                .to_ascii_lowercase()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|token| !token.is_empty())
                .map(|token| token.to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn classify_default_hitl_hold(req: &RuntimeExecutionRequest) -> Option<String> {
    // Chat prose is not an action. A system prompt that says "publish" or a lab
    // sentence that says "delete" must not open a hold. Only a requested tool
    // or an action target, as a whole token, does.
    let tokens = action_tokens(
        &req.tools_requested
            .iter()
            .chain(req.action_targets.iter())
            .cloned()
            .collect::<Vec<_>>(),
    );
    let mut matches = Vec::new();
    for needle in ["refund", "transfer", "delete", "publish"] {
        if tokens.iter().any(|token| token == needle) {
            matches.push(needle);
        }
    }
    let prod_write = req.environment.eq_ignore_ascii_case("prod")
        && tokens.iter().any(|token| token == "write" || token == "update");
    if prod_write {
        matches.push("prod_write");
    }
    if matches.is_empty() {
        None
    } else {
        matches.sort_unstable();
        matches.dedup();
        Some(format!(
            "Hold action [{}] actor={} model={} env={}. A tool or target token matched. Chat text is not the action.",
            matches.join(","),
            req.actor_id,
            if req.model_id.is_empty() { "unset" } else { req.model_id.as_str() },
            if req.environment.is_empty() { "unset" } else { req.environment.as_str() },
        ))
    }
}

fn approval_resume_id(headers: &HeaderMap) -> Option<String> {
    let resume = headers
        .get("x-approval-resume")
        .or_else(|| headers.get("X-Approval-Resume"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "approved" | "1" | "true" | "yes" | "on"))?;
    let _ = resume;
    headers
        .get("x-approval-id")
        .or_else(|| headers.get("X-Approval-Id"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Consume-once resume: approval must be approved, result_ready, matching tenant.
async fn consume_approval_resume(
    state: &AppState,
    approval_id: &str,
    tenant_id: &str,
) -> Result<(), AppError> {
    let row = sqlx::query(
        "UPDATE approval_queue
         SET comment = COALESCE(comment, '') || CASE
               WHEN comment IS NULL OR comment = '' THEN 'resumed'
               WHEN comment LIKE '%resumed%' THEN ''
               ELSE ';resumed' END
         WHERE id = $1
           AND tenant_id = $2
           AND status = 'approved'
           AND COALESCE(result_ready, FALSE) = TRUE
           AND COALESCE(comment, '') NOT LIKE '%resumed%'
         RETURNING id"
    )
    .bind(approval_id)
    .bind(tenant_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if row.is_some() {
        return Ok(());
    }

    // Diagnose why resume failed.
    let existing = sqlx::query(
        "SELECT status, result_ready, tenant_id, comment FROM approval_queue WHERE id = $1"
    )
    .bind(approval_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(existing) = existing else {
        return Err(AppError::NotFound(format!("Approval '{}' not found", approval_id)));
    };
    let status: String = existing.try_get("status").unwrap_or_default();
    let result_ready: bool = existing.try_get("result_ready").unwrap_or(false);
    let row_tenant: String = existing.try_get("tenant_id").unwrap_or_default();
    let comment: String = existing.try_get("comment").unwrap_or_default();
    if row_tenant != tenant_id {
        return Err(AppError::Unauthorized("approval tenant mismatch".into()));
    }
    if comment.contains("resumed") {
        return Err(AppError::Validation(
            "approval already resumed (consume-once)".into(),
        ));
    }
    if status != "approved" || !result_ready {
        return Err(AppError::Validation(format!(
            "approval not ready for resume (status={}, result_ready={})",
            status, result_ready
        )));
    }
    Err(AppError::Validation(
        "approval resume race — retry once".into(),
    ))
}

async fn enqueue_default_hitl_hold(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    chat_req: &ChatCompletionRequest,
    reason: &str,
    hold_metadata: serde_json::Value,
) -> Result<String, AppError> {
    let approval_id = uuid::Uuid::new_v4().to_string();
    let request_id = req.request_id.to_string();
    let trace_id = req.trace_id.to_string();
    let approvers = vec!["security-review".to_string()];

    // Ensure tenant row exists so the approval_queue FK is never violated.
    let tenant_name = if req.tenant_id.trim().is_empty() { "unknown-tenant" } else { req.tenant_id.as_str() };
    sqlx::query(
        "INSERT INTO tenants (id, name, environment, default_mode, policy_bundle, budget_tier, providers)
         VALUES ($1, $2, 'production', 'control', 'default', 'standard', ARRAY['openai'])
         ON CONFLICT (id) DO NOTHING"
    )
    .bind(tenant_name)
    .bind(tenant_name)
    .execute(&state.db_pool)
    .await
    .ok();

    // Store request payload for resume capability; TTL default 30m (CONNECTOR_TT_APPROVAL_TTL_MINS).
    let mut recorded_hold = hold_metadata;
    if let Some(obj) = recorded_hold.as_object_mut() {
        obj.insert("operation".to_string(), operation_context(req));
    }
    let request_payload = serde_json::json!({
        "operation": operation_context(req),
        "replay": serde_json::to_value(chat_req).unwrap_or_else(|_| serde_json::json!({})),
    });
    let ttl_mins: i64 = std::env::var("CONNECTOR_TT_APPROVAL_TTL_MINS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    
    sqlx::query(
        "INSERT INTO approval_queue (id, tenant_id, request_id, trace_id, actor_id, reason, status, approvers, created_at, request_payload, hold_metadata, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, NOW(), $8, $9, NOW() + ($10::text || ' minutes')::interval)"
    )
    .bind(&approval_id)
    .bind(&req.tenant_id)
    .bind(&request_id)
    .bind(&trace_id)
    .bind(&req.actor_id)
    .bind(reason)
    .bind(&approvers)
    .bind(&request_payload)
    .bind(&recorded_hold)
    .bind(ttl_mins.to_string())
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(approval_id)
}

async fn persist_cost_and_rollups(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    model: &str,
    provider: &str,
    input_tokens: u64,
    output_tokens: u64,
    cost_usd: f64,
    decision: &str,
    latency_ms: i64,
) -> Result<(), AppError> {
    // Ensure tenant row exists for cost_records FK.
    let tenant_name = if req.tenant_id.trim().is_empty() {
        "unknown-tenant"
    } else {
        req.tenant_id.as_str()
    };
    sqlx::query(
        "INSERT INTO tenants (id, name, environment, default_mode, policy_bundle, budget_tier, providers)
         VALUES ($1, $2, 'production', 'control', 'default', 'standard', ARRAY['openai'])
         ON CONFLICT (id) DO NOTHING"
    )
    .bind(tenant_name)
    .bind(tenant_name)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let tags = serde_json::json!({
        "provider": provider,
        "app_id": req.app_id,
        "actor_id": req.actor_id,
        "decision": decision,
    });
    sqlx::query(
        "INSERT INTO cost_records (request_id, trace_id, tenant_id, model, input_tokens, output_tokens, cost_usd, tags)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(req.request_id.to_string())
    .bind(req.trace_id.to_string())
    .bind(tenant_name)
    .bind(model)
    .bind(input_tokens as i64)
    .bind(output_tokens as i64)
    .bind(cost_usd)
    .bind(tags)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let is_error = decision.eq_ignore_ascii_case("error");
    let is_block = decision.contains("block");
    let is_redact = decision.contains("redact");
    sqlx::query(
        "INSERT INTO hourly_rollups (
            tenant_id, hour, model, provider, decision_count,
            total_input_tokens, total_output_tokens, total_cost_usd,
            p50_latency_ms, p95_latency_ms, p99_latency_ms,
            error_count, policy_blocks, policy_redactions
         )
         VALUES (
            $1, date_trunc('hour', NOW()), $2, $3, 1,
            $4, $5, $6,
            $7, $7, $7,
            $8, $9, $10
         )
         ON CONFLICT (tenant_id, hour, model, provider) DO UPDATE SET
            decision_count = hourly_rollups.decision_count + 1,
            total_input_tokens = hourly_rollups.total_input_tokens + EXCLUDED.total_input_tokens,
            total_output_tokens = hourly_rollups.total_output_tokens + EXCLUDED.total_output_tokens,
            total_cost_usd = hourly_rollups.total_cost_usd + EXCLUDED.total_cost_usd,
            p50_latency_ms = GREATEST(hourly_rollups.p50_latency_ms, EXCLUDED.p50_latency_ms),
            p95_latency_ms = GREATEST(hourly_rollups.p95_latency_ms, EXCLUDED.p95_latency_ms),
            p99_latency_ms = GREATEST(hourly_rollups.p99_latency_ms, EXCLUDED.p99_latency_ms),
            error_count = hourly_rollups.error_count + EXCLUDED.error_count,
            policy_blocks = hourly_rollups.policy_blocks + EXCLUDED.policy_blocks,
            policy_redactions = hourly_rollups.policy_redactions + EXCLUDED.policy_redactions"
    )
    .bind(tenant_name)
    .bind(model)
    .bind(provider)
    .bind(input_tokens as i64)
    .bind(output_tokens as i64)
    .bind(cost_usd)
    .bind(latency_ms)
    .bind(if is_error { 1_i64 } else { 0_i64 })
    .bind(if is_block { 1_i64 } else { 0_i64 })
    .bind(if is_redact { 1_i64 } else { 0_i64 })
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_tokens = (input_tokens + output_tokens) as i64;
    sqlx::query(
        "INSERT INTO daily_rollups (tenant_id, day, decision_count, total_tokens, total_cost_usd, by_model, by_app, by_actor)
         VALUES (
            $1, CURRENT_DATE, 1, $2, $3,
            jsonb_build_object($4, 1),
            jsonb_build_object($5, 1),
            jsonb_build_object($6, 1)
         )
         ON CONFLICT (tenant_id, day) DO UPDATE SET
            decision_count = daily_rollups.decision_count + 1,
            total_tokens = daily_rollups.total_tokens + EXCLUDED.total_tokens,
            total_cost_usd = daily_rollups.total_cost_usd + EXCLUDED.total_cost_usd,
            by_model = jsonb_set(
                daily_rollups.by_model,
                ARRAY[$4],
                to_jsonb(COALESCE((daily_rollups.by_model ->> $4)::bigint, 0) + 1),
                true
            ),
            by_app = jsonb_set(
                daily_rollups.by_app,
                ARRAY[$5],
                to_jsonb(COALESCE((daily_rollups.by_app ->> $5)::bigint, 0) + 1),
                true
            ),
            by_actor = jsonb_set(
                daily_rollups.by_actor,
                ARRAY[$6],
                to_jsonb(COALESCE((daily_rollups.by_actor ->> $6)::bigint, 0) + 1),
                true
            )"
    )
    .bind(tenant_name)
    .bind(total_tokens)
    .bind(cost_usd)
    .bind(model)
    .bind(req.app_id.as_str())
    .bind(req.actor_id.as_str())
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Check tool permission through Connector policy engine
async fn check_tool_permission(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    tool: &str,
) -> Result<bool, AppError> {
    // Check tool permission via Connector AAPI policy engine
    let decision = state.connector_client
        .evaluate_action_policy(
            &format!("tool:{}", tool),
            &format!("tenant:{}", req.tenant_id),
            Some(&req.actor_role),
        )
        .await;
    match decision {
        Ok(d) => {
            let allowed = d.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false);
            if !allowed {
                warn!("Tool {} blocked by Connector policy for tenant {}", tool, req.tenant_id);
                return Ok(false);
            }
        }
        Err(e) => {
            let fail_closed = std::env::var("TRACETRAMP_FAIL_CLOSED")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false)
                || matches!(
                    std::env::var("CONNECTOR_ENV")
                        .or_else(|_| std::env::var("TRACETRAMP_ENV"))
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase()
                        .as_str(),
                    "production" | "prod" | "pilots" | "pilot" | "staging"
                );
            if fail_closed
                && !std::env::var("TRACETRAMP_ALLOW_FAIL_OPEN")
                    .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false)
            {
                warn!(
                    "Tool policy unavailable for {} — fail-closed deny: {}",
                    tool, e
                );
                return Ok(false);
            }
            warn!("Tool policy unavailable for {} — lab fail-open: {}", tool, e);
        }
    }

    // Check for sensitive tool defaults (safety net)
    let sensitive_keywords = ["delete", "drop_table", "rm_rf", "shutdown", "admin"];
    for keyword in &sensitive_keywords {
        if tool.to_lowercase().contains(keyword) {
            warn!("Sensitive tool {} requires explicit approval", tool);
            return Ok(false);
        }
    }

    // Default allow only after policy pass (or lab fail-open)
    Ok(true)
}

/// Apply PII redaction to chat request before sending to LLM
pub fn redact_pii_in_request(req: &mut ChatCompletionRequest) -> crate::pii::RedactionResult {
    let engine = crate::pii::PiiEngine::new();
    let mut total_redactions = 0;
    let mut all_matches = vec![];
    
    for msg in req.messages.iter_mut() {
        let result = engine.redact(&msg.content);
        if result.count > 0 {
            msg.content = result.redacted_text.clone();
            total_redactions += result.count;
            all_matches.extend(result.matches);
        }
    }
    
    crate::pii::RedactionResult {
        redacted_text: String::new(), // aggregate, not used
        matches: all_matches,
        count: total_redactions,
    }
}

#[derive(Debug, Clone, Default)]
struct PiiObservation {
    count: usize,
    redacted: bool,
    blocked: bool,
    pii_types: Vec<String>,
    classifications: Vec<serde_json::Value>,
}

fn inspect_request_pii(req: &mut ChatCompletionRequest) -> PiiObservation {
    let engine = crate::pii::PiiEngine::new();
    let mut observation = PiiObservation::default();
    let mut all_matches = Vec::new();

    for (idx, msg) in req.messages.iter().enumerate() {
        for m in engine.detect(&msg.content) {
            observation.pii_types.push(m.pii_type.clone());
            all_matches.push(serde_json::json!({
                "field_path": format!("messages[{}].content", idx),
                "pii_type": m.pii_type,
                "start": m.start,
                "end": m.end,
                "redacted": m.redacted,
            }));
        }
    }
    observation.count = all_matches.len();
    observation.classifications = all_matches;
    observation.pii_types.sort();
    observation.pii_types.dedup();

    // High-risk patterns get an instant block in control mode.
    observation.blocked = observation
        .pii_types
        .iter()
        .any(|t| matches!(t.as_str(), "ssn" | "credit_card" | "api_key" | "aws_key"));
    if observation.blocked || observation.count == 0 {
        return observation;
    }

    let redaction = redact_pii_in_request(req);
    observation.redacted = redaction.count > 0;
    observation
}

/// Compute a risk score from prompt content signals (0.0 – 1.0)
fn compute_risk_score(chat_req: &ChatCompletionRequest, runtime_req: &RuntimeExecutionRequest) -> f64 {
    let mut score: f64 = 0.1; // baseline
    let prompt_text = chat_req.messages.iter()
        .filter(|m| m.role == "user")
        .map(|m| m.content.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    // High-risk keywords
    let high_risk = ["delete", "drop table", "rm -rf", "shutdown", "kubectl delete",
                     "terraform destroy", "revoke", "credential", "private key", "secret key"];
    let medium_risk = ["password", "token", "api key", "ssn", "credit card",
                       "admin", "sudo", "root", "execute", "deploy"];
    for kw in &high_risk {
        if prompt_text.contains(kw) { score += 0.25; }
    }
    for kw in &medium_risk {
        if prompt_text.contains(kw) { score += 0.1; }
    }
    // Tool invocations add risk
    if !runtime_req.tools_requested.is_empty() {
        score += 0.15 * (runtime_req.tools_requested.len() as f64).min(3.0);
    }
    score.min(1.0)
}

fn extract_openai_usage(llm_output: &str) -> Option<(u64, u64, u64)> {
    let v = serde_json::from_str::<serde_json::Value>(llm_output).ok()?;
    let usage = v.get("usage")?;
    let input = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let output = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let total = usage
        .get("total_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(input + output);
    if input == 0 && output == 0 && total == 0 {
        None
    } else {
        Some((input, output, total))
    }
}

fn extract_openai_model(llm_output: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(llm_output)
        .ok()
        .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(ToString::to_string))
        .filter(|m| !m.trim().is_empty())
}

fn operation_context(req: &RuntimeExecutionRequest) -> serde_json::Value {
    let tools = req.tools_requested.clone();
    let targets = req.action_targets.clone();
    let context = if tools.is_empty() && targets.is_empty() {
        "chat"
    } else {
        "action"
    };
    serde_json::json!({
        "context": context,
        "actor_id": req.actor_id,
        "tenant_id": req.tenant_id,
        "environment": req.environment,
        "model": req.model_id,
        "intent": req.model_intent,
        "tools": tools,
        "targets": targets,
    })
}

fn operator_ledger_step(step: &ExecutionStep) -> bool {
    matches!(
        step,
        ExecutionStep::RequestReceived
            | ExecutionStep::PolicyChecked
            | ExecutionStep::ApprovalRequested
            | ExecutionStep::ApprovalResolved
            | ExecutionStep::ToolRequested
            | ExecutionStep::ToolAllowed
            | ExecutionStep::ToolBlocked
            | ExecutionStep::OutputBlocked
            | ExecutionStep::OutputRedacted
            | ExecutionStep::ActionExecuted
            | ExecutionStep::CostRecorded
            | ExecutionStep::ReceiptIssued
            | ExecutionStep::MemoryAllowed
            | ExecutionStep::MemoryBlocked
    )
}

/// Record an operator ledger row. Pipeline checkpoints that only echo the chat
/// (identity, risk prose, route, provider hop, raw response) are not rows.
async fn record_event(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    step: ExecutionStep,
    result: StepResult,
    metadata: Option<serde_json::Value>,
) -> Result<(), AppError> {
    if !operator_ledger_step(&step) {
        return Ok(());
    }
    let step_name = format!("{:?}", step);
    let result_str = format!("{:?}", result);
    let mut meta_val = serde_json::json!({
        "tenant_id": req.tenant_id,
        "agent_pid": req.actor_id,
        "model": req.model_id,
        "intent": req.model_intent,
        "operation": operation_context(req),
        "duration_ms": 0u64,
    });
    if let Some(reason) = extract_step_reason(&result) {
        if let Some(obj) = meta_val.as_object_mut() {
            obj.insert("decision_reason".to_string(), serde_json::Value::String(reason));
        }
    }
    if let Some(extra) = metadata.and_then(|m| m.as_object().cloned()) {
        if let Some(obj) = meta_val.as_object_mut() {
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
    }
    if let Some(ref snap) = req.kernel_host_snapshot {
        if let Some(obj) = meta_val.as_object_mut() {
            if let Some(v) = snap.get("policy_revision") {
                obj.insert("kernel_policy_revision".to_string(), v.clone());
            }
            if let Some(v) = snap.get("host_apply_state") {
                obj.insert("host_enforcement_status".to_string(), v.clone());
            }
            obj.insert("kernel_host".to_string(), snap.clone());
        }
    }
    if let Some(obj) = meta_val.as_object_mut() {
        obj.insert(
            "decision".to_string(),
            crate::decision_envelope::decision_envelope(
                &step,
                &result,
                crate::decision_envelope::DecisionPipeline::Control,
            ),
        );
    }

    // Write directly to local trace_events — this is what the TUI reads
    if let Err(e) = sqlx::query(
        "INSERT INTO trace_events (trace_id, request_id, event_type, step, result, metadata)
         VALUES ($1, $2, 'checkpoint', $3, $4, $5)"
    )
    .bind(&req.trace_id.to_string())
    .bind(&req.request_id.to_string())
    .bind(&step_name)
    .bind(&result_str)
    .bind(&meta_val)
    .execute(&state.db_pool)
    .await
    {
        warn!("Failed to write trace_event to DB: {}", e);
    }

    Ok(())
}

fn extract_step_reason(result: &StepResult) -> Option<String> {
    match result {
        StepResult::Block { reason } => Some(reason.clone()),
        StepResult::Redact { fields } if !fields.is_empty() => {
            Some(format!("redacted fields: {}", fields.join(",")))
        }
        _ => None,
    }
}

struct ActiveCallGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl ActiveCallGuard {
    fn new(counter: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for ActiveCallGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Convert HeaderMap to vec
fn header_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
        })
        .collect()
}

/// Extracted FNI from request headers (P6.4).
struct FniExtract {
    flow_id: String,
    cfni_wire: Option<String>,
}

/// Extract `fni_flow_id` (+ optional CFNI wire) from `X-Connector-FNI` / CFNI header.
fn fni_from_headers(headers: &HeaderMap) -> Option<FniExtract> {
    let raw = headers
        .get("x-connector-fni")
        .or_else(|| headers.get(connector_trust::CFNI_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    if let Ok(id) = connector_trust::decode_header_value(raw) {
        return Some(FniExtract {
            flow_id: id.flow_id,
            cfni_wire: Some(raw.to_string()),
        });
    }
    Some(FniExtract {
        flow_id: raw.to_string(),
        cfni_wire: None,
    })
}

/// Resolve CFNI HMAC secret from env (same contract as platform substrate).
pub fn cfni_secret_from_env() -> Option<Vec<u8>> {
    std::env::var("CONNECTOR_CFNI_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
}

/// Run CFNI verify against stored wire; returns status string (never decorative).
pub fn verify_cfni_wire(wire: &str) -> (&'static str, Option<&'static str>) {
    let Some(secret) = cfni_secret_from_env() else {
        return ("unverified", Some("cfni_secret_unavailable"));
    };
    let Ok(id) = connector_trust::decode_header_value(wire) else {
        return ("invalid", Some("bad_cfni_wire"));
    };
    let now = chrono::Utc::now().timestamp_millis();
    match connector_trust::verify_flow_identity(&id, &secret, now) {
        Ok(()) => ("verified", None),
        Err("expired") => ("invalid", Some("expired")),
        Err("bad_signature") => ("invalid", Some("bad_signature")),
        Err(other) => ("invalid", Some(other)),
    }
}

async fn load_provider_chain(state: &AppState) -> Result<Vec<String>, AppError> {
    let rows_with_priority = sqlx::query(
        "SELECT provider_type FROM providers WHERE is_active = true ORDER BY priority ASC, created_at ASC"
    )
    .fetch_all(&state.db_pool)
    .await;
    let rows = match rows_with_priority {
        Ok(rows) => rows,
        Err(_) => {
            sqlx::query(
                "SELECT provider_type FROM providers WHERE is_active = true ORDER BY created_at ASC"
            )
            .fetch_all(&state.db_pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        }
    };
    let providers = rows
        .iter()
        .filter_map(|r| sqlx::Row::try_get::<String, _>(r, "provider_type").ok())
        .collect::<Vec<_>>();
    if providers.is_empty() {
        Ok(vec!["openai".to_string()])
    } else {
        Ok(providers)
    }
}

async fn proxy_with_fallback(
    state: &AppState,
    req: &ChatCompletionRequest,
    headers: &HeaderMap,
    provider_chain: &[String],
) -> Result<(ReqwestResponse, String, bool), AppError> {
    let base_headers = header_vec(headers);
    let mut attempted = false;
    let mut last_status: Option<u16> = None;
    for provider in provider_chain {
        if is_provider_circuit_open(provider) {
            attempted = true;
            warn!("Skipping provider {} due to open circuit", provider);
            continue;
        }
        let mut merged_headers = base_headers.clone();
        merged_headers.push(("X-Provider-Preference".to_string(), provider.clone()));
        match state
            .connector_client
            .proxy_chat_completion(req, &merged_headers)
            .await
        {
            Ok(resp) => {
                if !resp.status().is_server_error() {
                    record_provider_success(provider);
                    return Ok((resp, provider.clone(), attempted));
                }
                last_status = Some(resp.status().as_u16());
                attempted = true;
                record_provider_failure(provider);
                warn!("Provider {} failed with status {}", provider, resp.status());
            }
            Err(err) => {
                attempted = true;
                record_provider_failure(provider);
                warn!("Provider {} proxy error: {}", provider, err);
            }
        }
    }
    Err(AppError::ConnectorProxy(format!(
        "All providers exhausted in fallback chain; last_status={}",
        last_status.map(|s| s.to_string()).unwrap_or_else(|| "none".to_string())
    )))
}

#[derive(Debug)]
struct BudgetCheck {
    allowed: bool,
    reason: String,
}

#[derive(Debug, Clone)]
struct CircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

fn provider_circuits() -> &'static Mutex<HashMap<String, CircuitState>> {
    static CIRCUITS: OnceLock<Mutex<HashMap<String, CircuitState>>> = OnceLock::new();
    CIRCUITS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_provider_circuit_open(provider: &str) -> bool {
    let now = Instant::now();
    let mut guard = provider_circuits().lock().expect("provider circuits mutex poisoned");
    if let Some(state) = guard.get_mut(provider) {
        if let Some(open_until) = state.open_until {
            if now < open_until {
                return true;
            }
            state.open_until = None;
            state.consecutive_failures = 0;
        }
    }
    false
}

fn record_provider_success(provider: &str) {
    let mut guard = provider_circuits().lock().expect("provider circuits mutex poisoned");
    guard.insert(
        provider.to_string(),
        CircuitState {
            consecutive_failures: 0,
            open_until: None,
        },
    );
}

fn record_provider_failure(provider: &str) {
    let now = Instant::now();
    let mut guard = provider_circuits().lock().expect("provider circuits mutex poisoned");
    let entry = guard
        .entry(provider.to_string())
        .or_insert(CircuitState {
            consecutive_failures: 0,
            open_until: None,
        });
    entry.consecutive_failures += 1;
    if entry.consecutive_failures >= 3 {
        entry.open_until = Some(now + Duration::from_secs(60));
        warn!("Opening circuit for provider {} for 60s after {} failures", provider, entry.consecutive_failures);
    }
}

fn input_tokens_from_headers(headers: &reqwest::header::HeaderMap) -> u64 {
    headers
        .get("X-Input-Tokens")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

struct StreamState {
    inner: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>>,
    connector: ConnectorClient,
    witness_handoff_base_url: Option<String>,
    witness_handoff_secret: Option<String>,
    request_id: String,
    trace_id: String,
    tenant_id: String,
    actor_id: String,
    mode: &'static str,
    decision: String,
    input_tokens: u64,
    output_tokens_est: u64,
    chunk_idx: u64,
}

async fn stream_sse_response(
    state: Arc<AppState>,
    runtime_req: RuntimeExecutionRequest,
    connector_response: ReqwestResponse,
    fallback_attempted: bool,
    mode: &'static str,
    decision: &str,
) -> Result<Response, AppError> {
    let trace_id = runtime_req.trace_id.to_string();
    let request_id = runtime_req.request_id.to_string();
    let tenant_id = runtime_req.tenant_id.clone();
    let actor_id = runtime_req.actor_id.clone();
    let input_tokens = input_tokens_from_headers(connector_response.headers());
    let status = StatusCode::from_u16(connector_response.status().as_u16()).unwrap_or(StatusCode::OK);

    let stream_state = StreamState {
        inner: Box::pin(connector_response.bytes_stream()),
        connector: state.connector_client.clone(),
        witness_handoff_base_url: state.config.witness_handoff_base_url.clone(),
        witness_handoff_secret: state.config.witness_handoff_secret.clone(),
        request_id: request_id.clone(),
        trace_id: trace_id.clone(),
        tenant_id: tenant_id.clone(),
        actor_id: actor_id.clone(),
        mode,
        decision: decision.to_string(),
        input_tokens,
        output_tokens_est: 0,
        chunk_idx: 0,
    };

    let body_stream = stream::unfold(stream_state, |mut st| async move {
        match st.inner.next().await {
            Some(Ok(chunk)) => {
                st.chunk_idx += 1;
                st.output_tokens_est += (chunk.len() as u64).saturating_div(4);
                let _ = st
                    .connector
                    .log_interaction(
                        &st.request_id,
                        &st.trace_id,
                        &st.tenant_id,
                        "stream.chunk",
                        &format!("chunk={} bytes={}", st.chunk_idx, chunk.len()),
                    )
                    .await;
                Some((Ok::<bytes::Bytes, std::io::Error>(chunk), st))
            }
            Some(Err(e)) => {
                let _ = st
                    .connector
                    .log_interaction(
                        &st.request_id,
                        &st.trace_id,
                        &st.tenant_id,
                        "stream.error",
                        &e.to_string(),
                    )
                    .await;
                Some((Err(std::io::Error::other(e.to_string())), st))
            }
            None => {
                let cost_usd = calculate_cost("stream", st.input_tokens, st.output_tokens_est);
                let _ = st
                    .connector
                    .record_usage(&st.actor_id, st.input_tokens, st.output_tokens_est, cost_usd)
                    .await;
                let witness_payload = serde_json::json!({
                    "request_id": st.request_id,
                    "trace_id": st.trace_id,
                    "tenant_id": st.tenant_id,
                    "actor_id": st.actor_id,
                    "mode": st.mode,
                    "decision": st.decision,
                    "streaming": true,
                    "input_tokens": st.input_tokens,
                    "output_tokens": st.output_tokens_est,
                    "cost_usd": cost_usd,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                let _ = st
                    .connector
                    .witness_tracetramp_handoff(
                        st.witness_handoff_base_url.as_deref(),
                        st.witness_handoff_secret.as_deref(),
                        &witness_payload,
                    )
                    .await;
                None
            }
        }
    });

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Trace-Id", trace_id)
        .header(HDR_TRACE_TRAMP_LANES, VAL_TRACE_TRAMP_LANES)
        .header("X-Request-Id", request_id)
        .header("X-Policy-Outcome", decision);
    if fallback_attempted {
        builder = builder.header("X-Fallback-Attempted", "true");
    }
    builder
        .body(Body::from_stream(body_stream))
        .map_err(|e| AppError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::check_budget_with_connector;
    use crate::connector::ConnectorClient;
    use crate::types::{BudgetContext, OutputMode, RequestMode, RuntimeExecutionRequest};
    use uuid::Uuid;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_request(max_tokens: Option<u64>) -> RuntimeExecutionRequest {
        RuntimeExecutionRequest {
            request_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            tenant_id: "tenant-budget".to_string(),
            app_id: "app".to_string(),
            environment: "prod".to_string(),
            workflow_id: None,
            session_id: None,
            actor_id: "actor-1".to_string(),
            actor_role: "developer".to_string(),
            request_mode: RequestMode::Control,
            model_intent: "chat".to_string(),
            model_id: String::new(),
            input_payload: serde_json::json!({"prompt":"budget test"}),
            tools_requested: vec![],
            memory_scope: None,
            action_targets: vec![],
            output_mode: OutputMode::Text,
            budget_context: BudgetContext {
                max_tokens,
                max_cost_usd: None,
                priority: None,
            },
            compliance_tags: vec![],
            execution_profile: "default".to_string(),
            policy_bundle: "default".to_string(),
            kernel_host_snapshot: None,
            hitl_bypass: false,
            test_hold_requested: false,
        }
    }

    #[test]
    fn a_chat_is_recorded_as_chat_and_the_model_is_not_the_intent_word() {
        let mut req = sample_request(None);
        req.model_id = "deepseek-chat".to_string();
        req.model_intent = "general".to_string();
        req.input_payload = serde_json::json!({
            "messages": [{"role": "user", "content": "Please publish the weekly report."}]
        });
        let ctx = super::operation_context(&req);
        assert_eq!(ctx["context"], "chat");
        assert_eq!(ctx["model"], "deepseek-chat");
        assert_eq!(ctx["intent"], "general");
        assert!(ctx.get("messages").is_none());
        req.tools_requested = vec!["db.delete_rows".to_string()];
        let action = super::operation_context(&req);
        assert_eq!(action["context"], "action");
        assert_eq!(action["tools"][0], "db.delete_rows");
    }

    #[test]
    fn chat_prose_that_says_delete_or_publish_is_not_a_hold() {
        let mut req = sample_request(None);
        req.input_payload = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": "Delete all records older than 2020. Then publish the report."
            }]
        });
        assert!(super::classify_default_hitl_hold(&req).is_none());
    }

    #[test]
    fn a_delete_tool_is_a_hold_and_a_publisher_name_is_not() {
        let mut req = sample_request(None);
        req.environment = "dev".to_string();
        req.tools_requested = vec!["db.delete_rows".to_string()];
        let reason = super::classify_default_hitl_hold(&req).expect("delete tool");
        assert!(reason.contains("delete"));
        req.tools_requested = vec!["publisher_lookup".to_string()];
        assert!(super::classify_default_hitl_hold(&req).is_none());
    }

    #[tokio::test]
    async fn tt05_rejects_when_budget_is_exhausted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aapi/budgets"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Must match `ConnectorClient::get_budget_status` (not legacy `/aapi/budgets/{tenant}/tokens`).
        Mock::given(method("GET"))
            .and(path("/aapi/budgets/status"))
            .and(query_param("agent_pid", "tenant-budget"))
            .and(query_param("resource", "tokens"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "remaining": 0,
                "exhausted": true
            })))
            .expect(1)
            .mount(&server)
            .await;

        let connector = ConnectorClient::new(&server.uri(), "test-key");
        let req = sample_request(Some(1));
        let result = check_budget_with_connector(&connector, &req, "tenant-budget")
            .await
            .expect("budget check should complete");
        assert!(!result.allowed);
        assert!(result.reason.contains("exhausted"));
    }
}
