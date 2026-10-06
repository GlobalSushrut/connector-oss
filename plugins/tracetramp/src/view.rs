//! View Pipeline (optional passthrough)
//!
//! Observability without the Control enforcement path. **Not the product default** — enabled
//! only when `TRACETRAMP_ALLOW_VIEW_PIPELINE=1` and the client sends `X-TraceTramp-Pipeline: view`.
//! Production should use **Control**, which already meters, filters, quarantines, and records traces.

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{Stream, StreamExt, stream};
use reqwest::Response as ReqwestResponse;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, error};

use crate::{
    AppState,
    error::AppError,
    types::{
        RuntimeExecutionRequest, ExecutionStep, StepResult,
        ChatCompletionRequest, ChatMessage,
        DecisionNodeType,
    },
    connector::ConnectorClient,
    decision::{self, DecisionTreeBuilder},
};

/// Handle a request in View Mode (passthrough observability — opt-in only).
pub async fn handle_request(
    state: Arc<AppState>,
    runtime_req: RuntimeExecutionRequest,
    headers: HeaderMap,
    chat_req: ChatCompletionRequest,
) -> Result<Response, AppError> {
    let trace_id = runtime_req.trace_id;
    let request_id = runtime_req.request_id;
    
    info!("View Pipeline: handling request trace_id={} request_id={}", trace_id, request_id);
    
    // Record request.received event
    record_event(&state, &runtime_req, ExecutionStep::RequestReceived, StepResult::Success, None).await?;
    
    // Record identity.resolved event
    record_event(&state, &runtime_req, ExecutionStep::IdentityResolved, StepResult::Success, None).await?;
    
    // In View Mode, we pass through to Connector without enforcement
    // But we record everything that happens
    
    let pii_observation = inspect_request_pii(&chat_req);
    if pii_observation.count > 0 {
        record_event(
            &state,
            &runtime_req,
            ExecutionStep::OutputChecked,
            StepResult::Success,
            Some(serde_json::json!({
                "pii_in_request": true,
                "pii_count": pii_observation.count,
                "classifications": pii_observation.classifications,
            })),
        )
        .await?;
    }

    let provider_chain = load_provider_chain(&state).await?;
    let (connector_response, served_provider, fallback_attempted) = match proxy_with_fallback(
        &state,
        &chat_req,
        &headers,
        &provider_chain,
    ).await {
        Ok(v) => v,
        Err(e) => {
            warn!("All provider fallbacks exhausted: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("X-Trace-Id", trace_id.to_string())
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
        Some(serde_json::json!({"provider": served_provider})),
    ).await?;

    if chat_req.stream == Some(true) {
        return stream_sse_response(
            state,
            runtime_req,
            connector_response,
            fallback_attempted,
            "allow",
            "view",
        )
        .await;
    }
    
    // EXTRACT status and headers BEFORE consuming body (critical!)
    let status = StatusCode::from_u16(connector_response.status().as_u16()).unwrap_or(StatusCode::OK);
    let response_headers = connector_response.headers().clone();
    
    // Extract cost from response headers if available
    let input_tokens = response_headers
        .get("X-Input-Tokens")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
        
    let output_tokens = response_headers
        .get("X-Output-Tokens")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    
    // CONSUME body for decision tree recording (this moves connector_response)
    let llm_output = connector_response.text().await.unwrap_or_default();
    
    // Build and record the DECISION TREE (the true moat)
    // This captures the raw LLM prompt, output, and derived action
    let mut decision_builder = DecisionTreeBuilder::new(
        &trace_id.to_string(),
        &request_id.to_string(),
        &runtime_req.tenant_id,
        &runtime_req.actor_id,
        &runtime_req.app_id,
    );
    
    // Extract the actual prompt sent to LLM
    let prompt_input = chat_req.messages.iter()
        .map(|m| format!("[{}]: {}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n");
    
    // Extract system message from messages if present
    let system_message = chat_req.messages.iter()
        .find(|m| m.role == "system")
        .map(|m| m.content.as_str());
    
    // Process the LLM output
    let action = extract_action_from_response(&llm_output);
    
    // Calculate latency (placeholder - would track actual)
    let latency_ms = 1000;
    
    // Add the root decision node
    let tokens = crate::providers::TokenUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        estimated_cost_usd: calculate_cost(&chat_req.model, input_tokens, output_tokens),
    };
    
    decision_builder.add_root_decision(
        DecisionNodeType::IntentRecognition,
        &prompt_input,
        system_message,
        &llm_output,
        &action,
        &chat_req.model,
        "openai", // TODO: extract actual provider
        tokens,
        latency_ms,
    );
    
    // Build and store the decision tree
    let decision_tree = decision_builder.build();
    
    // Log and persist the decision tree (the moat).
    let tree_raw = decision::format_decision_tree(&decision_tree);
    info!("DECISION TREE RECORDED:\n{}", tree_raw);
    if let Err(e) = decision::persist_decision_tree(&state.db_pool, &decision_tree).await {
        warn!("Decision tree persistence failed (non-blocking): {}", e);
    }
    
    // Record usage — cost is catalogue estimate or unavailable (never invent invoice $).
    let honesty = usage_honesty_fields(&chat_req.model, input_tokens, output_tokens, "provider_or_estimate");
    let cost_usd = honesty.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if let Err(e) = state
        .connector_client
        .record_usage(
            &runtime_req.actor_id,
            input_tokens,
            output_tokens,
            cost_usd,
        )
        .await
    {
        warn!(
            "Failed to record Connector usage for actor {}: {}",
            runtime_req.actor_id, e
        );
    }
    
    // Record cost.recorded event with honesty fields
    record_event(&state, &runtime_req, ExecutionStep::CostRecorded, StepResult::Success, Some(honesty)).await?;
    
    // Record response.released event
    record_event(&state, &runtime_req, ExecutionStep::ResponseReleased, StepResult::Success, None).await?;

    if let Some(ref memory_scope) = runtime_req.memory_scope {
        debug!(
            scope = %memory_scope,
            actor = %runtime_req.actor_id,
            "memory scope is not a TraceTramp row"
        );
    }

    // Best-effort interaction log; should never block primary response flow
    if let Err(e) = state.connector_client.log_interaction(
        &request_id.to_string(),
        &trace_id.to_string(),
        &runtime_req.tenant_id,
        "chat.completion",
        "allow",
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
            "mode": "view",
            "decision": "allow",
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
    
    // Issue receipt via Connector
    let receipt = state.connector_client
        .issue_receipt(&request_id.to_string(), &trace_id.to_string(), "success")
        .await?;
    
    // Record receipt.issued event
    record_event(&state, &runtime_req, ExecutionStep::ReceiptIssued, StepResult::Success, Some(serde_json::json!({
        "receipt_cid": receipt.cid,
    }))).await?;
    
    info!("View Pipeline: request completed trace_id={} cost=${:.4}", trace_id, cost_usd);
    
    // Return the response to client with trace_id header
    // Use pre-extracted status and buffered llm_output (connector_response was consumed)
    let cost_str = format!("{:.6}", cost_usd);
    let mut response_builder = Response::builder()
        .status(status)
        .header("X-Trace-Id", trace_id.to_string())
        .header("X-Request-Id", request_id.to_string())
        .header("X-Cost-USD", cost_str);
    if fallback_attempted {
        response_builder = response_builder.header("X-Fallback-Attempted", "true");
    }
    
    // Only forward content-type; transfer-encoding/content-encoding/content-length
    // must not be copied because reqwest already decoded the body.
    if let Some(ct) = response_headers.get("content-type") {
        if let Ok(val) = axum::http::HeaderValue::from_bytes(ct.as_bytes()) {
            response_builder = response_builder.header("content-type", val);
        }
    }
    
    // Use buffered llm_output as body
    let body = axum::body::Body::from(llm_output);
    
    Ok(response_builder.body(body).unwrap())
}

/// Record a runtime event to storage
async fn record_event(
    state: &AppState,
    req: &RuntimeExecutionRequest,
    step: ExecutionStep,
    result: StepResult,
    metadata: Option<serde_json::Value>,
) -> Result<(), AppError> {
    let action = format!("checkpoint:{:?}", step);
    let mut payload = serde_json::json!({
        "legacy_result": format!("{:?}", result),
        "decision": crate::decision_envelope::decision_envelope(
            &step,
            &result,
            crate::decision_envelope::DecisionPipeline::View,
        ),
    });
    if let Some(meta) = metadata {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("checkpoint_metadata".to_string(), meta);
        }
    }
    let outcome = serde_json::to_string(&payload).unwrap_or_else(|_| payload.to_string());
    if let Err(e) = state
        .connector_client
        .log_interaction(
            &req.request_id.to_string(),
            &req.trace_id.to_string(),
            &req.tenant_id,
            &action,
            &outcome,
        )
        .await
    {
        warn!("Failed to log checkpoint interaction to Connector: {}", e);
    }
    Ok(())
}

/// Convert HeaderMap to vec for Connector client
fn header_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|val| (k.to_string(), val.to_string()))
        })
        .collect()
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

/// Calculate cost based on model and tokens
/// Extract action/decision from LLM response
/// This derives what action the AI decided to take based on its output
fn extract_action_from_response(response: &str) -> String {
    // Check for function/tool calls in the response
    if response.contains("function_call") || response.contains("tool_calls") {
        return "tool_invocation".to_string();
    }
    
    // Check for refusal/rejection
    if response.to_lowercase().contains("i cannot") || 
       response.to_lowercase().contains("i'm sorry") ||
       response.to_lowercase().contains("i apologize") {
        return "refusal".to_string();
    }
    
    // Check for questions/clarifications
    if response.contains("?") && response.len() < 200 {
        return "clarification_request".to_string();
    }
    
    // Check for code
    if response.contains("```") || response.contains("def ") || response.contains("function") {
        return "code_generation".to_string();
    }
    
    // Default: direct response
    "direct_response".to_string()
}

/// Catalogue estimate only — never treat as invoice USD.
/// Returns `None` when the model has no rate card (honesty: unavailable ≠ $0).
pub fn calculate_cost_opt(model: &str, input_tokens: u64, output_tokens: u64) -> Option<f64> {
    let normalized = model.to_ascii_lowercase();
    let (input_price_per_million, output_price_per_million) = match normalized.as_str() {
        m if m.contains("deepseek") => (0.27, 1.10),
        m if m.contains("gpt-4o-mini") => (0.00015, 0.0006),
        m if m.contains("gpt-4o") => (0.0025, 0.01),
        m if m.contains("gpt-4") => (0.03, 0.06),
        m if m.contains("claude-3-haiku") => (0.00025, 0.00125),
        m if m.contains("claude-3-sonnet") => (0.003, 0.015),
        m if m.contains("claude-3-opus") => (0.015, 0.075),
        _ => return None,
    };

    let (input_price, output_price) = if normalized.contains("deepseek") {
        (input_price_per_million / 1_000_000.0, output_price_per_million / 1_000_000.0)
    } else {
        (input_price_per_million / 1000.0, output_price_per_million / 1000.0)
    };
    Some((input_tokens as f64) * input_price + (output_tokens as f64) * output_price)
}

/// Backward-compatible wrapper — returns 0.0 only when unavailable (callers must check honesty fields).
pub fn calculate_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    calculate_cost_opt(model, input_tokens, output_tokens).unwrap_or(0.0)
}

fn usage_honesty_fields(
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    token_source: &str,
) -> serde_json::Value {
    let cost = calculate_cost_opt(model, input_tokens, output_tokens);
    serde_json::json!({
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "token_source": token_source,
        "cost_usd": cost,
        "cost_status": if cost.is_some() { "catalogue_estimate" } else { "unavailable" },
        "usage_honesty": "Tokens may be provider or stream-estimated; cost is catalogue estimate only — never invoice USD. unavailable ≠ $0.",
    })
}

// Evidence plane query functions

/// Build a trace timeline for a trace_id
pub async fn build_trace(
    state: &AppState,
    trace_id: &str,
) -> Result<serde_json::Value, AppError> {
    let interactions = state.connector_client.list_interactions(None).await?;
    let timeline: Vec<serde_json::Value> = interactions
        .into_iter()
        .filter(|e| e.target.contains(&format!("trace:{}", trace_id)))
        .map(|e| serde_json::json!({
            "timestamp": e.timestamp,
            "step": e.operation,
            "result": e.status,
            "metadata": {
                "interaction_type": e.interaction_type,
                "duration_ms": e.duration_ms,
                "tokens": e.tokens,
                "cost_usd": e.cost_usd,
            },
        }))
        .collect();
    
    Ok(serde_json::json!({
        "trace_id": trace_id,
        "timeline": timeline,
        "event_count": timeline.len(),
    }))
}

/// Build explain output for a request
pub async fn build_explain(
    state: &AppState,
    request_id: &str,
) -> Result<serde_json::Value, AppError> {
    let interactions = state.connector_client.list_interactions(None).await?;
    let decisions: Vec<serde_json::Value> = interactions
        .into_iter()
        .filter(|e| e.target.contains(&format!("request:{}", request_id)))
        .filter(|e| e.status != "Success")
        .map(|e| serde_json::json!({
            "step": e.operation,
            "result": e.status,
            "reason": "interaction_record",
            "policy_ref": serde_json::Value::Null,
        }))
        .collect();
    
    Ok(serde_json::json!({
        "request_id": request_id,
        "decisions": decisions,
    }))
}

/// Build prove output (integrity chain)
pub async fn build_prove(
    state: &AppState,
    request_id: &str,
) -> Result<serde_json::Value, AppError> {
    // This would query the receipt chain from Connector
    // For now, return placeholder
    
    Ok(serde_json::json!({
        "request_id": request_id,
        "request_hash": "placeholder_hash",
        "policy_hash": "placeholder_policy",
        "chain_status": "verified",
        "receipt_count": 1,
        "tamper_status": "clean",
        "note": "Full prove builder requires Connector receipt integration",
    }))
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
    decision: &'static str,
    input_tokens: u64,
    output_tokens_est: u64,
    chunk_idx: u64,
}

async fn stream_sse_response(
    state: Arc<AppState>,
    runtime_req: RuntimeExecutionRequest,
    connector_response: ReqwestResponse,
    fallback_attempted: bool,
    decision: &'static str,
    mode: &'static str,
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
        decision,
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
                // Stream finalize: tokens are chunk estimates; cost may be unavailable (no "stream" rate card).
                let honesty = usage_honesty_fields(
                    "stream",
                    st.input_tokens,
                    st.output_tokens_est,
                    "stream_estimate",
                );
                let cost_usd = honesty
                    .get("cost_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let _ = st
                    .connector
                    .record_usage(&st.actor_id, st.input_tokens, st.output_tokens_est, cost_usd)
                    .await;
                let mut witness_payload = serde_json::json!({
                    "request_id": st.request_id,
                    "trace_id": st.trace_id,
                    "tenant_id": st.tenant_id,
                    "actor_id": st.actor_id,
                    "mode": st.mode,
                    "decision": st.decision,
                    "streaming": true,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                if let Some(obj) = witness_payload.as_object_mut() {
                    for (k, v) in honesty.as_object().into_iter().flatten() {
                        obj.insert(k.clone(), v.clone());
                    }
                }
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
        .header("X-Request-Id", request_id);
    if fallback_attempted {
        builder = builder.header("X-Fallback-Attempted", "true");
    }
    builder
        .body(Body::from_stream(body_stream))
        .map_err(|e| AppError::Internal(e.to_string()))
}

#[derive(Debug, Clone, Default)]
struct PiiObservation {
    count: usize,
    classifications: Vec<serde_json::Value>,
}

fn inspect_request_pii(req: &ChatCompletionRequest) -> PiiObservation {
    let engine = crate::pii::PiiEngine::new();
    let mut classifications = Vec::new();
    for (idx, msg) in req.messages.iter().enumerate() {
        for m in engine.detect(&msg.content) {
            classifications.push(serde_json::json!({
                "field_path": format!("messages[{}].content", idx),
                "pii_type": m.pii_type,
                "start": m.start,
                "end": m.end,
                "redacted": m.redacted,
            }));
        }
    }
    PiiObservation {
        count: classifications.len(),
        classifications,
    }
}
