//! Relay Watchdog — the 11-step invocation proxy.
//!
//! Steps (mirroring architecture doc §3.1):
//!   1.  Load function definition + check status
//!   2.  Admission gate (Connector pre-flight)
//!   3.  Budget check (Connector metering)
//!   4.  Memory injection (Connector memory kernel)
//!   5.  Tool injection (Connector MCP)
//!   6.  Instruction injection (system prompt prepend)
//!   7.  Identity header (AgentPassport DID)
//!   8.  Forward request → function URI (reqwest)
//!   9.  PII scrub on response (Connector HIPAA)
//!  10.  Memory update from response
//!  11.  Audit log + cost record → WitnessCtl + LedgerLens

use std::time::Instant;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::error::AppError;
use crate::instructions;
use crate::metrics;
use crate::types::{InvokeRequest, InvokeResponse};

pub struct ProxyResult {
    pub invocation_id: Uuid,
    pub output:        Value,
    pub tokens_in:     i32,
    pub tokens_out:    i32,
    pub cost_usd:      f64,
    pub latency_ms:    i64,
    pub outcome:       String,
    pub audit_cid:     Option<String>,
    pub model_used:    Option<String>,
}

pub async fn invoke(
    pool:          &PgPool,
    connector:     &ConnectorClient,
    http:          &reqwest::Client,
    function_name: &str,
    req:           &InvokeRequest,
) -> Result<ProxyResult, AppError> {
    let start = Instant::now();

    // ── Step 1: Load function ──────────────────────────────────────────────────
    let row = sqlx::query!(
        r#"
        SELECT id, uri, policy_json, instructions, status, health_status, agent_did
        FROM relay_functions
        WHERE name = $1
        "#,
        function_name,
    )
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("Function '{function_name}' not registered")))?;

    if row.status == "suspended" || row.status == "quarantined" {
        return Err(AppError::Forbidden(format!(
            "Function '{function_name}' is {}", row.status
        )));
    }

    if row.health_status == "unreachable" {
        tracing::warn!(function = function_name, "Function health status is unreachable — attempting anyway");
    }

    let policy: crate::types::PolicyConfig = serde_json::from_value(row.policy_json.clone())
        .unwrap_or_default();

    let agent_did = row.agent_did.clone()
        .unwrap_or_else(|| format!("did:connector:relay/{function_name}"));

    // ── Step 2: Admission gate ─────────────────────────────────────────────────
    let admission = connector.admission_check(&req.input, function_name).await
        .map_err(|e| AppError::Connector(e.to_string()))?;

    if admission.verdict == "DENY" {
        record_invocation(
            pool, row.id, function_name, &req.input, None,
            0, 0, 0.0, start.elapsed().as_millis() as i32,
            None, "denied", admission.reason.as_deref(), None, None,
        ).await;
        metrics::record_invocation(function_name, "denied");
        return Err(AppError::AdmissionDenied(
            admission.reason.unwrap_or_else(|| "content policy violation".into())
        ));
    }

    // Use redacted body if admission says REDACT
    let request_body = if admission.verdict == "REDACT" {
        admission.redacted.unwrap_or_else(|| req.input.clone())
    } else {
        req.input.clone()
    };

    // ── Step 3: Budget check ───────────────────────────────────────────────────
    let budget_ok = connector.budget_check(
        function_name,
        None,
        policy.budget.as_ref().and_then(|b| b.per_day_usd),
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    if !budget_ok.allowed {
        record_invocation(
            pool, row.id, function_name, &req.input, None,
            0, 0, 0.0, start.elapsed().as_millis() as i32,
            None, "budget_exceeded", Some("daily budget exhausted"), None, None,
        ).await;
        metrics::record_invocation(function_name, "budget_exceeded");
        return Err(AppError::BudgetExceeded(format!(
            "Daily budget exhausted — resets at {}",
            budget_ok.resets_at.as_deref().unwrap_or("midnight UTC")
        )));
    }

    // ── Step 4: Memory injection ───────────────────────────────────────────────
    let memory_ctx = connector.get_memory_context(&agent_did, 5).await
        .unwrap_or_else(|_| crate::connector::MemoryContextResponse { entries: vec![] });

    // ── Step 5: Tool injection ─────────────────────────────────────────────────
    let allowed_tools = policy.tools.clone().unwrap_or_default();
    let tools = if !allowed_tools.is_empty() {
        connector.get_tools(&allowed_tools).await
            .unwrap_or_else(|_| crate::connector::McpToolsResponse { tools: vec![] })
            .tools
    } else {
        vec![]
    };

    // ── Step 6: Instruction injection ─────────────────────────────────────────
    let mut forward_body = request_body.clone();
    if let Some(instr) = &row.instructions {
        forward_body = instructions::inject(forward_body, instr);
    }

    // ── Step 7: Identity header ────────────────────────────────────────────────
    // Encode memory context + tools for the function
    let memory_header = B64.encode(serde_json::to_string(&memory_ctx.entries).unwrap_or_default());
    let tools_header  = B64.encode(serde_json::to_string(&tools).unwrap_or_default());

    // ── Step 8: Forward to function ────────────────────────────────────────────
    let timeout = std::time::Duration::from_secs(
        policy.timeout_secs.unwrap_or(30)
    );

    let forward_resp = http
        .post(&row.uri)
        .timeout(timeout)
        .header("X-Relay-Agent-Did",       &agent_did)
        .header("X-Relay-Function",        function_name)
        .header("X-Relay-Memory-Context",  &memory_header)
        .header("X-Relay-Tools",           &tools_header)
        .json(&forward_body)
        .send()
        .await;

    let latency_ms = start.elapsed().as_millis() as i64;

    let (raw_response, status_code) = match forward_resp {
        Err(e) => {
            let err_msg = e.to_string();
            record_invocation(
                pool, row.id, function_name, &req.input, None,
                0, 0, 0.0, latency_ms as i32,
                None, "error", Some(&err_msg), None, None,
            ).await;
            metrics::record_invocation(function_name, "error");
            return Err(AppError::FunctionUnreachable(format!(
                "Function '{function_name}' did not respond: {err_msg}"
            )));
        }
        Ok(resp) => {
            let code = resp.status().as_u16() as i32;
            let body: Value = resp.json().await.unwrap_or(json!({}));
            (body, code)
        }
    };

    // Extract usage from response (function can return these from its LLM call)
    let tokens_in  = raw_response.get("_relay_tokens_in").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let tokens_out = raw_response.get("_relay_tokens_out").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let cost_usd   = raw_response.get("_relay_cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let model_used = raw_response.get("_relay_model").and_then(|v| v.as_str()).map(|s| s.to_owned());

    // ── Step 9: PII scrub on response ──────────────────────────────────────────
    let scrubbed_response = if policy.pii_redact.unwrap_or(false) || policy.hipaa.unwrap_or(false) {
        connector.hipaa_scrub(&raw_response).await
            .map(|r| r.content)
            .unwrap_or_else(|_| raw_response.clone())
    } else {
        raw_response.clone()
    };

    // ── Step 10: Memory update ─────────────────────────────────────────────────
    if let Some(mem_update) = scrubbed_response.get("memory_update") {
        let _ = connector.write_memory(&agent_did, mem_update).await;
    }

    // ── Step 11: Audit + cost ──────────────────────────────────────────────────
    let input_hash  = hash_value(&req.input);
    let output_hash = hash_value(&scrubbed_response);

    let audit_cid = connector.write_audit(
        "relay_invocation",
        function_name,
        Some(&agent_did),
        json!({
            "input_hash":  input_hash,
            "output_hash": output_hash,
            "tokens_in":   tokens_in,
            "tokens_out":  tokens_out,
            "cost_usd":    cost_usd,
            "model":       model_used,
            "status_code": status_code,
            "latency_ms":  latency_ms,
        }),
    ).await.ok().filter(|s| !s.is_empty());

    let _ = connector.record_cost(
        function_name, tokens_in, tokens_out, cost_usd, model_used.as_deref(),
    ).await;

    let invocation_id = record_invocation(
        pool, row.id, function_name, &req.input, Some(&scrubbed_response),
        tokens_in, tokens_out, cost_usd, latency_ms as i32,
        model_used.as_deref(), "success", None,
        audit_cid.as_deref(), None,
    ).await;

    // Update function aggregate counters
    let _ = sqlx::query!(
        r#"
        UPDATE relay_functions
        SET invocation_count = invocation_count + 1,
            total_cost_usd   = total_cost_usd + $1,
            updated_at       = NOW()
        WHERE id = $2
        "#,
        cost_usd,
        row.id,
    )
    .execute(pool)
    .await;

    metrics::record_invocation(function_name, "success");
    metrics::record_cost(function_name, cost_usd);
    metrics::record_latency(function_name, latency_ms);

    Ok(ProxyResult {
        invocation_id,
        output: scrubbed_response,
        tokens_in,
        tokens_out,
        cost_usd,
        latency_ms,
        outcome: "success".into(),
        audit_cid,
        model_used,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn hash_value(v: &Value) -> String {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

/// Persist an invocation record and return its UUID.
#[allow(clippy::too_many_arguments)]
async fn record_invocation(
    pool:          &PgPool,
    function_id:   Uuid,
    function_name: &str,
    input:         &Value,
    output:        Option<&Value>,
    tokens_in:     i32,
    tokens_out:    i32,
    cost_usd:      f64,
    latency_ms:    i32,
    model_used:    Option<&str>,
    outcome:       &str,
    deny_reason:   Option<&str>,
    audit_cid:     Option<&str>,
    trace_id:      Option<&str>,
) -> Uuid {
    let input_hash  = hash_value(input);
    let output_hash = output.map(hash_value);

    let row = sqlx::query!(
        r#"
        INSERT INTO relay_invocations
            (function_id, function_name, input_hash, output_hash, model_used,
             tokens_in, tokens_out, cost_usd, latency_ms, outcome,
             deny_reason, audit_cid, trace_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
        "#,
        function_id,
        function_name,
        input_hash,
        output_hash,
        model_used,
        tokens_in,
        tokens_out,
        cost_usd,
        latency_ms,
        outcome,
        deny_reason,
        audit_cid,
        trace_id,
    )
    .fetch_one(pool)
    .await;

    match row {
        Ok(r) => r.id,
        Err(e) => {
            tracing::error!(error = %e, "Failed to record invocation");
            Uuid::new_v4()
        }
    }
}
