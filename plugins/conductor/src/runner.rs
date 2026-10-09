//! Pipeline runner — execute a pipeline via Connector, poll steps,
//! enforce budgets, validate schemas, and trigger HITL when needed.
//! Uses dynamic sqlx queries (no compile-time DATABASE_URL required).

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::hitl;
use crate::types::{PipelineDsl, Run, RunStatus, Step, StepStatus};

// ── Start a run ───────────────────────────────────────────────────────────────

/// Start a new pipeline run: create DB record, call Connector, spawn poll task.
pub async fn start(
    pool: &PgPool,
    connector: &ConnectorClient,
    pipeline_id: Uuid,
    compiled: &Value,
    dsl: &PipelineDsl,
    inputs: Value,
) -> Result<Run> {
    let run_id = Uuid::new_v4();

    sqlx::query("INSERT INTO conductor_runs (id, pipeline_id, status, inputs) VALUES ($1, $2, 'pending', $3)")
        .bind(run_id).bind(pipeline_id).bind(&inputs)
        .execute(pool).await.context("Failed to create run record")?;

    let run_body = serde_json::json!({
        "pipeline_id": pipeline_id.to_string(),
        "conductor_run_id": run_id.to_string(),
        "definition": compiled,
        "inputs": inputs,
    });

    let resp = connector.run_pipeline(&run_body).await?;
    let connector_run_id = resp.get("run_id")
        .or_else(|| resp.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or(&run_id.to_string())
        .to_string();

    sqlx::query("UPDATE conductor_runs SET status = 'running', connector_run_id = $1 WHERE id = $2")
        .bind(&connector_run_id).bind(run_id)
        .execute(pool).await?;

    // Spawn background step-polling task
    let pool_clone = pool.clone();
    let connector_clone = connector.clone();
    let run_id_clone = run_id;
    let connector_run_id_clone = connector_run_id.clone();
    let dsl_clone = dsl.clone();

    tokio::spawn(async move {
        let _ = poll_steps(
            &pool_clone,
            &connector_clone,
            run_id_clone,
            &connector_run_id_clone,
            &dsl_clone,
        ).await;
    });

    fetch_run(pool, run_id).await
}

// ── Step polling loop ─────────────────────────────────────────────────────────

async fn poll_steps(
    pool: &PgPool,
    connector: &ConnectorClient,
    run_id: Uuid,
    connector_run_id: &str,
    dsl: &PipelineDsl,
) -> Result<()> {
    let max_polls = 600; // 20 min at 2s interval

    for _ in 0..max_polls {
        // Check if run was paused/aborted externally
        let run_status = get_run_status(pool, run_id).await?;
        if run_status == "paused" || run_status == "aborted" {
            return Ok(());
        }

        let steps_resp = connector.get_pipeline_steps(connector_run_id).await
            .unwrap_or_default();

        let steps = steps_resp.get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let run_status_from_connector = steps_resp.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("running");

        let mut total_tokens: i64 = 0;
        let mut total_usd: f64 = 0.0;

        for step in &steps {
            let step_index = step.get("index").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let step_name = step.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let agent_id = step.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let status_str = step.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
            let output = step.get("output").cloned();
            let cost_tokens = step.get("cost_tokens").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let cost_usd = step.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);

            total_tokens += cost_tokens as i64;
            total_usd += cost_usd;

            upsert_step(pool, run_id, step_index, &step_name, &agent_id, status_str, step.clone(), output.clone(), cost_tokens, cost_usd).await?;

            // Budget check
            if let Some(budget) = &dsl.budget {
                if let Some(limit) = budget.total_per_run {
                    if total_tokens > limit as i64 {
                        pause_run(pool, run_id, "Budget limit exceeded").await?;
                        return Ok(());
                    }
                }
            }

            // Schema validation
            if let (Some(output_val), Some(edge)) = (&output, find_edge_for_step(dsl, &step_name)) {
                if let Some(schema) = &edge.schema {
                    let schema_valid = validate_schema(output_val, schema);
                    sqlx::query("UPDATE conductor_steps SET schema_valid = $1 WHERE run_id = $2 AND step_index = $3")
                        .bind(schema_valid).bind(run_id).bind(step_index)
                        .execute(pool).await?;

                    if !schema_valid {
                        fail_run(pool, run_id, &format!("Step '{}' output failed schema validation", step_name)).await?;
                        return Ok(());
                    }
                }
            }

            // HITL check — if step completed and edge has hitl config
            if status_str == "completed" {
                if let Some(edge) = find_edge_for_step(dsl, &step_name) {
                    if let Some(hitl_config) = &edge.hitl {
                        let requires_approval = if let Some(cond) = &hitl_config.required_if {
                            eval_condition(output.as_ref(), cond)
                        } else {
                            true
                        };

                        if requires_approval {
                            let step_id = get_step_id(pool, run_id, step_index).await?;
                            hitl::create_approval(pool, run_id, step_id, step_index, &step_name, hitl_config).await?;
                            pause_run(pool, run_id, &format!("HITL approval required for step '{}'", step_name)).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Update budget totals
        sqlx::query("UPDATE conductor_runs SET budget_used_tokens = $1, budget_used_usd = $2 WHERE id = $3")
            .bind(total_tokens).bind(total_usd).bind(run_id)
            .execute(pool).await?;

        // Check if pipeline finished
        match run_status_from_connector {
            "completed" | "succeeded" => {
                let outputs = steps_resp.get("outputs").cloned();
                complete_run(pool, run_id, outputs).await?;
                return Ok(());
            }
            "failed" | "error" => {
                let err = steps_resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
                fail_run(pool, run_id, err).await?;
                return Ok(());
            }
            _ => {}
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    fail_run(pool, run_id, "Run timed out after 20 minutes").await
}

// ── Run state transitions ─────────────────────────────────────────────────────

pub async fn pause(pool: &PgPool, run_id: Uuid) -> Result<()> {
    pause_run(pool, run_id, "Manually paused").await
}


pub async fn resume(pool: &PgPool, connector: &ConnectorClient, run_id: Uuid) -> Result<()> {
    let run = fetch_run(pool, run_id).await?;
    if run.status != RunStatus::Paused {
        anyhow::bail!("Run {} is not paused (status: {})", run_id, run.status);
    }

    let connector_run_id = run.connector_run_id
        .ok_or_else(|| anyhow::anyhow!("Run has no connector_run_id"))?;

    sqlx::query("UPDATE conductor_runs SET status = 'running' WHERE id = $1")
        .bind(run_id).execute(pool).await?;

    let pipeline = crate::pipeline::get(pool, run.pipeline_id).await?;
    let dsl = crate::pipeline::parse_yaml(&pipeline.yaml_source)?;

    let pool_clone = pool.clone();
    let connector_clone = connector.clone();
    tokio::spawn(async move {
        let _ = poll_steps(&pool_clone, &connector_clone, run_id, &connector_run_id, &dsl).await;
    });

    Ok(())
}

pub async fn abort(pool: &PgPool, run_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE conductor_runs SET status = 'aborted', ended_at = NOW() WHERE id = $1")
        .bind(run_id).execute(pool).await.context("Failed to abort run")?;
    Ok(())
}

/// Replay a run from a specific step, creating a new run linked to the parent.
pub async fn replay(
    pool: &PgPool,
    connector: &ConnectorClient,
    original_run_id: Uuid,
    step: u32,
    new_inputs: Option<Value>,
) -> Result<Run> {
    let original = fetch_run(pool, original_run_id).await?;
    let connector_run_id = original.connector_run_id
        .ok_or_else(|| anyhow::anyhow!("Original run has no connector_run_id"))?;

    let pipeline = crate::pipeline::get(pool, original.pipeline_id).await?;
    let dsl = crate::pipeline::parse_yaml(&pipeline.yaml_source)?;

    let inputs = new_inputs.unwrap_or(original.inputs.clone());
    let replay_body = serde_json::json!({ "inputs": inputs });
    let resp = connector.replay_from_step(&connector_run_id, step, &replay_body).await?;
    let new_connector_run_id = resp.get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&Uuid::new_v4().to_string())
        .to_string();

    let new_run_id = Uuid::new_v4();
    sqlx::query("INSERT INTO conductor_runs (id, pipeline_id, status, inputs, connector_run_id, parent_run_id, replay_from_step) VALUES ($1, $2, 'running', $3, $4, $5, $6)")
        .bind(new_run_id).bind(original.pipeline_id).bind(&inputs)
        .bind(&new_connector_run_id).bind(original_run_id).bind(step as i32)
        .execute(pool).await?;

    let pool_clone = pool.clone();
    let connector_clone = connector.clone();
    tokio::spawn(async move {
        let _ = poll_steps(&pool_clone, &connector_clone, new_run_id, &new_connector_run_id, &dsl).await;
    });

    fetch_run(pool, new_run_id).await
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn pause_run(pool: &PgPool, run_id: Uuid, reason: &str) -> Result<()> {
    sqlx::query("UPDATE conductor_runs SET status = 'paused', error_message = $1 WHERE id = $2")
        .bind(reason).bind(run_id).execute(pool).await?;
    Ok(())
}

async fn fail_run(pool: &PgPool, run_id: Uuid, reason: &str) -> Result<()> {
    sqlx::query("UPDATE conductor_runs SET status = 'failed', ended_at = NOW(), error_message = $1 WHERE id = $2")
        .bind(reason).bind(run_id).execute(pool).await?;
    Ok(())
}

async fn complete_run(pool: &PgPool, run_id: Uuid, outputs: Option<Value>) -> Result<()> {
    sqlx::query("UPDATE conductor_runs SET status = 'completed', ended_at = NOW(), outputs = $1 WHERE id = $2")
        .bind(outputs).bind(run_id).execute(pool).await?;
    Ok(())
}

async fn get_run_status(pool: &PgPool, run_id: Uuid) -> Result<String> {
    let row = sqlx::query("SELECT status FROM conductor_runs WHERE id = $1")
        .bind(run_id).fetch_one(pool).await?;
    Ok(row.try_get::<String, _>("status").unwrap_or_default())
}

async fn get_step_id(pool: &PgPool, run_id: Uuid, step_index: i32) -> Result<Uuid> {
    let row = sqlx::query("SELECT id FROM conductor_steps WHERE run_id = $1 AND step_index = $2")
        .bind(run_id).bind(step_index)
        .fetch_one(pool).await.context("Step not found")?;
    Ok(row.try_get::<Uuid, _>("id").context("Step id missing")?)
}

async fn upsert_step(
    pool: &PgPool,
    run_id: Uuid,
    step_index: i32,
    step_name: &str,
    agent_id: &str,
    status_str: &str,
    input_json: Value,
    output_json: Option<Value>,
    cost_tokens: i32,
    cost_usd: f64,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO conductor_steps
           (run_id, step_index, step_name, agent_id, status, input_json, output_json, cost_tokens, cost_usd)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (run_id, step_index) DO UPDATE
           SET status = EXCLUDED.status,
               output_json = EXCLUDED.output_json,
               cost_tokens = EXCLUDED.cost_tokens,
               cost_usd = EXCLUDED.cost_usd,
               ended_at = CASE WHEN EXCLUDED.status IN ('completed','failed','skipped') THEN NOW() ELSE conductor_steps.ended_at END"#
    )
    .bind(run_id).bind(step_index).bind(step_name).bind(agent_id).bind(status_str)
    .bind(input_json).bind(output_json).bind(cost_tokens).bind(cost_usd)
    .execute(pool).await?;
    Ok(())
}

fn find_edge_for_step<'a>(dsl: &'a PipelineDsl, step_name: &str) -> Option<&'a crate::types::EdgeDef> {
    dsl.edges.iter().find(|e| e.from == step_name)
}

fn validate_schema(output: &Value, schema: &Value) -> bool {
    if let Ok(validator) = jsonschema::JSONSchema::compile(schema) {
        validator.is_valid(output)
    } else {
        true // schema compile error → allow (don't block on bad schema)
    }
}

/// Simple condition evaluator: checks dot-path equality in JSON.
/// e.g. "result.qualified == true" or "result.tier == 'enterprise'"
fn eval_condition(output: Option<&Value>, condition: &str) -> bool {
    let output = match output {
        Some(v) => v,
        None => return false,
    };

    if let Some((path, expected)) = condition.split_once("==") {
        let path = path.trim();
        let expected = expected.trim().trim_matches('\'');
        let actual = get_json_path(output, path);
        match actual {
            Some(Value::Bool(b)) => b.to_string() == expected,
            Some(Value::String(s)) => s == expected,
            Some(Value::Number(n)) => n.to_string() == expected,
            _ => false,
        }
    } else {
        true // unknown condition → require approval (fail-safe)
    }
}

fn get_json_path<'a>(val: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = val;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current)
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

pub async fn fetch_run(pool: &PgPool, run_id: Uuid) -> Result<Run> {
    let row = sqlx::query(
        r#"SELECT id, pipeline_id, connector_run_id, status, inputs,
           outputs, budget_used_tokens, budget_used_usd,
           parent_run_id, replay_from_step, started_at, ended_at, error_message
           FROM conductor_runs WHERE id = $1"#
    )
    .bind(run_id)
    .fetch_one(pool)
    .await
    .context("Run not found")?;

    Ok(row_to_run(row))
}

pub async fn fetch_steps(pool: &PgPool, run_id: Uuid) -> Result<Vec<Step>> {
    let rows = sqlx::query(
        r#"SELECT id, run_id, step_index, step_name, agent_id, status,
           input_json, output_json, schema_valid, cost_tokens, cost_usd,
           started_at, ended_at, error_message
           FROM conductor_steps WHERE run_id = $1 ORDER BY step_index ASC"#
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(row_to_step).collect())
}

pub async fn list_runs(pool: &PgPool, pipeline_id: Option<Uuid>, status: Option<&str>) -> Result<Vec<Run>> {
    // Build dynamic query based on optional filters
    let rows = match (pipeline_id, status) {
        (Some(pid), Some(st)) => sqlx::query(
            "SELECT id, pipeline_id, connector_run_id, status, inputs, outputs, budget_used_tokens, budget_used_usd, parent_run_id, replay_from_step, started_at, ended_at, error_message FROM conductor_runs WHERE pipeline_id = $1 AND status = $2 ORDER BY started_at DESC LIMIT 100"
        ).bind(pid).bind(st).fetch_all(pool).await?,
        (Some(pid), None) => sqlx::query(
            "SELECT id, pipeline_id, connector_run_id, status, inputs, outputs, budget_used_tokens, budget_used_usd, parent_run_id, replay_from_step, started_at, ended_at, error_message FROM conductor_runs WHERE pipeline_id = $1 ORDER BY started_at DESC LIMIT 100"
        ).bind(pid).fetch_all(pool).await?,
        (None, Some(st)) => sqlx::query(
            "SELECT id, pipeline_id, connector_run_id, status, inputs, outputs, budget_used_tokens, budget_used_usd, parent_run_id, replay_from_step, started_at, ended_at, error_message FROM conductor_runs WHERE status = $1 ORDER BY started_at DESC LIMIT 100"
        ).bind(st).fetch_all(pool).await?,
        (None, None) => sqlx::query(
            "SELECT id, pipeline_id, connector_run_id, status, inputs, outputs, budget_used_tokens, budget_used_usd, parent_run_id, replay_from_step, started_at, ended_at, error_message FROM conductor_runs ORDER BY started_at DESC LIMIT 100"
        ).fetch_all(pool).await?,
    };
    Ok(rows.into_iter().map(row_to_run).collect())
}

fn parse_run_status(s: &str) -> RunStatus {
    match s {
        "running"   => RunStatus::Running,
        "paused"    => RunStatus::Paused,
        "completed" => RunStatus::Completed,
        "failed"    => RunStatus::Failed,
        "aborted"   => RunStatus::Aborted,
        _           => RunStatus::Pending,
    }
}

fn parse_step_status(s: &str) -> StepStatus {
    match s {
        "running"          => StepStatus::Running,
        "waiting_approval" => StepStatus::WaitingApproval,
        "completed"        => StepStatus::Completed,
        "failed"           => StepStatus::Failed,
        "skipped"          => StepStatus::Skipped,
        _                  => StepStatus::Pending,
    }
}

fn row_to_run(row: sqlx::postgres::PgRow) -> Run {
    let status: String = row.try_get("status").unwrap_or_default();
    Run {
        id:                  row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        pipeline_id:         row.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4()),
        connector_run_id:    row.try_get("connector_run_id").ok(),
        status:              parse_run_status(&status),
        inputs:              row.try_get("inputs").unwrap_or_default(),
        outputs:             row.try_get("outputs").ok(),
        budget_used_tokens:  row.try_get("budget_used_tokens").unwrap_or(0),
        budget_used_usd:     row.try_get::<f64, _>("budget_used_usd").unwrap_or(0.0),
        parent_run_id:       row.try_get("parent_run_id").ok(),
        replay_from_step:    row.try_get("replay_from_step").ok(),
        started_at:          row.try_get("started_at").unwrap_or_else(|_| Utc::now()),
        ended_at:            row.try_get("ended_at").ok(),
        error_message:       row.try_get("error_message").ok(),
    }
}

fn row_to_step(row: sqlx::postgres::PgRow) -> Step {
    let status: String = row.try_get("status").unwrap_or_default();
    Step {
        id:            row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        run_id:        row.try_get("run_id").unwrap_or_else(|_| Uuid::new_v4()),
        step_index:    row.try_get("step_index").unwrap_or(0),
        step_name:     row.try_get("step_name").unwrap_or_default(),
        agent_id:      row.try_get("agent_id").unwrap_or_default(),
        status:        parse_step_status(&status),
        input_json:    row.try_get("input_json").unwrap_or_default(),
        output_json:   row.try_get("output_json").ok(),
        schema_valid:  row.try_get("schema_valid").ok(),
        cost_tokens:   row.try_get("cost_tokens").unwrap_or(0),
        cost_usd:      row.try_get::<f64, _>("cost_usd").unwrap_or(0.0),
        started_at:    row.try_get("started_at").ok(),
        ended_at:      row.try_get("ended_at").ok(),
        error_message: row.try_get("error_message").ok(),
    }
}
