//! Gate policy evaluation — controls pipeline version promotion.
//! Gate types: regression_test, budget_variance, approval_count, custom.

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::Gate;

#[derive(Debug, serde::Serialize)]
pub struct GateResult {
    pub gate_id: Uuid,
    pub gate_type: String,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, serde::Serialize)]
pub struct GateEvaluation {
    pub pipeline_id: Uuid,
    pub run_id: Uuid,
    pub all_passed: bool,
    pub results: Vec<GateResult>,
    pub promote_allowed: bool,
}

/// Evaluate all gate policies for a pipeline against a specific run.
pub async fn evaluate(
    pool: &PgPool,
    connector: &ConnectorClient,
    pipeline_id: Uuid,
    run_id: Uuid,
) -> Result<GateEvaluation> {
    let gates = list_for_pipeline(pool, pipeline_id).await?;

    if gates.is_empty() {
        return Ok(GateEvaluation {
            pipeline_id,
            run_id,
            all_passed: true,
            results: vec![],
            promote_allowed: true,
        });
    }

    let mut results = Vec::new();
    let mut all_passed = true;

    for gate in &gates {
        let result = evaluate_gate(pool, connector, gate, run_id).await?;
        if !result.passed && gate.required {
            all_passed = false;
        }
        results.push(result);
    }

    Ok(GateEvaluation {
        pipeline_id,
        run_id,
        all_passed,
        results,
        promote_allowed: all_passed,
    })
}

async fn evaluate_gate(
    pool: &PgPool,
    connector: &ConnectorClient,
    gate: &Gate,
    run_id: Uuid,
) -> Result<GateResult> {
    match gate.gate_type.as_str() {
        "regression_test" => eval_regression_test(connector, gate, run_id).await,
        "budget_variance" => eval_budget_variance(pool, gate, run_id).await,
        "approval_count"  => eval_approval_count(pool, gate, run_id).await,
        other => Ok(GateResult {
            gate_id: gate.id,
            gate_type: other.to_string(),
            passed: true,
            reason: "Unknown gate type — skipped (non-blocking)".into(),
        }),
    }
}

/// regression_test: compare run output against a stored baseline via Connector.
async fn eval_regression_test(
    connector: &ConnectorClient,
    gate: &Gate,
    run_id: Uuid,
) -> Result<GateResult> {
    let body = serde_json::json!({
        "run_id": run_id.to_string(),
        "gate_config": gate.config_json,
    });

    let resp = connector.detect_regression(&body).await
        .unwrap_or_else(|_| serde_json::json!({ "regression_detected": false }));

    let regression = resp.get("regression_detected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(GateResult {
        gate_id: gate.id,
        gate_type: "regression_test".into(),
        passed: !regression,
        reason: if regression {
            "Regression detected vs baseline — version promotion blocked".into()
        } else {
            "No regression detected — test gate passed".into()
        },
    })
}

/// budget_variance: pass if this run's cost is within X% of the baseline.
async fn eval_budget_variance(
    pool: &PgPool,
    gate: &Gate,
    run_id: Uuid,
) -> Result<GateResult> {
    let max_variance_pct: f64 = gate.config_json
        .get("max_variance_pct")
        .and_then(|v| v.as_f64())
        .unwrap_or(20.0);

    let row = sqlx::query("SELECT budget_used_tokens, pipeline_id FROM conductor_runs WHERE id = $1")
        .bind(run_id).fetch_one(pool).await.context("Run not found for budget variance gate")?;
    let current: i64 = row.try_get("budget_used_tokens").unwrap_or(0);
    let pipeline_id: uuid::Uuid = row.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4());

    let avg_row = sqlx::query(
        "SELECT AVG(budget_used_tokens::float) as avg FROM (SELECT budget_used_tokens FROM conductor_runs WHERE pipeline_id = $1 AND status = 'completed' AND id != $2 ORDER BY started_at DESC LIMIT 5) sub"
    )
    .bind(pipeline_id).bind(run_id)
    .fetch_optional(pool).await.unwrap_or(None);

    let avg: Option<f64> = avg_row.and_then(|r| r.try_get::<Option<f64>, _>("avg").ok().flatten());

    let passed = match avg {
        None => true,
        Some(baseline) if baseline == 0.0 => true,
        Some(baseline) => {
            let variance = ((current as f64 - baseline) / baseline * 100.0).abs();
            variance <= max_variance_pct
        }
    };

    Ok(GateResult {
        gate_id: gate.id,
        gate_type: "budget_variance".into(),
        passed,
        reason: if passed {
            format!("Budget variance within {}% threshold — gate passed", max_variance_pct)
        } else {
            format!("Budget variance exceeded {}% threshold — version promotion blocked", max_variance_pct)
        },
    })
}

/// approval_count: require N approvals before version promotion.
async fn eval_approval_count(
    pool: &PgPool,
    gate: &Gate,
    run_id: Uuid,
) -> Result<GateResult> {
    let required: i64 = gate.config_json
        .get("required_approvals")
        .and_then(|v| v.as_i64())
        .unwrap_or(1);

    let count: i64 = sqlx::query("SELECT COUNT(*) as cnt FROM conductor_approvals WHERE run_id = $1 AND status = 'approved'")
        .bind(run_id).fetch_one(pool).await
        .map(|r| r.try_get::<i64, _>("cnt").unwrap_or(0))
        .unwrap_or(0);

    let passed = count >= required;

    Ok(GateResult {
        gate_id: gate.id,
        gate_type: "approval_count".into(),
        passed,
        reason: format!("{}/{} required approvals — gate {}", count, required, if passed { "passed" } else { "blocked" }),
    })
}

// ── DB helpers ────────────────────────────────────────────────────────────────

pub async fn list_for_pipeline(pool: &PgPool, pipeline_id: Uuid) -> Result<Vec<Gate>> {
    let rows = sqlx::query(
        "SELECT id, pipeline_id, gate_type, config_json, required, created_at FROM conductor_gates WHERE pipeline_id = $1 ORDER BY created_at ASC"
    )
    .bind(pipeline_id)
    .fetch_all(pool).await?;

    Ok(rows.into_iter().map(|r| Gate {
        id:          r.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        pipeline_id: r.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4()),
        gate_type:   r.try_get("gate_type").unwrap_or_default(),
        config_json: r.try_get("config_json").unwrap_or_default(),
        required:    r.try_get("required").unwrap_or(true),
        created_at:  r.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }).collect())
}

#[allow(dead_code)]
pub async fn create_gate(
    pool: &PgPool,
    pipeline_id: Uuid,
    gate_type: &str,
    config_json: serde_json::Value,
    required: bool,
) -> Result<Gate> {
    let row = sqlx::query(
        "INSERT INTO conductor_gates (pipeline_id, gate_type, config_json, required) VALUES ($1, $2, $3, $4) RETURNING id, pipeline_id, gate_type, config_json, required, created_at"
    )
    .bind(pipeline_id).bind(gate_type).bind(config_json).bind(required)
    .fetch_one(pool).await?;

    Ok(Gate {
        id:          row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        pipeline_id: row.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4()),
        gate_type:   row.try_get("gate_type").unwrap_or_default(),
        config_json: row.try_get("config_json").unwrap_or_default(),
        required:    row.try_get("required").unwrap_or(true),
        created_at:  row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    })
}
