//! Pipeline YAML parsing, validation, compilation, and DB persistence.
//! Uses dynamic sqlx queries (no compile-time DATABASE_URL required).

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{Pipeline, PipelineDsl, PipelineStatus};

// ── Parse + Validate ─────────────────────────────────────────────────────────

pub fn parse_yaml(yaml: &str) -> Result<PipelineDsl> {
    let dsl: PipelineDsl = serde_yaml::from_str(yaml)
        .context("Invalid pipeline YAML — check indentation and required fields (name, agents)")?;
    validate_dsl(&dsl)?;
    Ok(dsl)
}

fn validate_dsl(dsl: &PipelineDsl) -> Result<()> {
    if dsl.name.trim().is_empty() {
        anyhow::bail!("pipeline.name is required and cannot be empty");
    }
    if dsl.agents.is_empty() {
        anyhow::bail!("pipeline.agents must define at least one agent");
    }
    let agent_ids: std::collections::HashSet<&str> =
        dsl.agents.iter().map(|a| a.id.as_str()).collect();
    for edge in &dsl.edges {
        if !agent_ids.contains(edge.from.as_str()) {
            anyhow::bail!("edge.from '{}' references undefined agent", edge.from);
        }
        if !agent_ids.contains(edge.to.as_str()) {
            anyhow::bail!("edge.to '{}' references undefined agent", edge.to);
        }
        if edge.from == edge.to {
            anyhow::bail!("edge from '{}' cannot point to itself", edge.from);
        }
    }
    Ok(())
}

// ── Compile ───────────────────────────────────────────────────────────────────

pub fn compile(dsl: &PipelineDsl) -> serde_json::Value {
    let agents: Vec<serde_json::Value> = dsl.agents.iter().map(|a| {
        let mut agent = serde_json::json!({ "id": a.id, "role": a.role, "tools": a.tools });
        if let Some(m) = &a.model { agent["model"] = serde_json::json!(m); }
        if let Some(p) = &a.system_prompt { agent["system_prompt"] = serde_json::json!(p); }
        if let Some(b) = &a.budget {
            let mut bv = serde_json::json!({});
            if let Some(t) = b.per_run      { bv["per_run_tokens"] = serde_json::json!(t); }
            if let Some(d) = b.per_day      { bv["per_day_tokens"] = serde_json::json!(d); }
            if let Some(c) = b.max_cost_usd { bv["max_cost_usd"]   = serde_json::json!(c); }
            agent["budget"] = bv;
        }
        agent
    }).collect();

    let edges: Vec<serde_json::Value> = dsl.edges.iter().map(|e| {
        let mut ev = serde_json::json!({ "from": e.from, "to": e.to });
        if let Some(w) = &e.when        { ev["condition"]     = serde_json::json!(w); }
        if let Some(s) = &e.schema      { ev["output_schema"] = s.clone(); }
        if let Some(h) = &e.hitl {
            let mut hv = serde_json::json!({ "reviewers": h.reviewers });
            if let Some(c) = &h.required_if     { hv["required_if"]     = serde_json::json!(c); }
            if let Some(t) = h.timeout_minutes  { hv["timeout_minutes"] = serde_json::json!(t); }
            ev["hitl"] = hv;
        }
        ev
    }).collect();

    let mut p = serde_json::json!({ "name": dsl.name, "version": dsl.version, "agents": agents, "edges": edges });
    if let Some(b) = &dsl.budget {
        let mut bv = serde_json::json!({});
        if let Some(t) = b.total_per_run  { bv["total_per_run_tokens"]  = serde_json::json!(t); }
        if let Some(d) = b.total_per_day  { bv["total_per_day_tokens"]  = serde_json::json!(d); }
        if let Some(a) = &b.on_exceed     { bv["on_exceed"]             = serde_json::json!(a); }
        p["budget"] = bv;
    }
    if let Some(d) = &dsl.description { p["description"] = serde_json::json!(d); }
    p
}

pub fn fingerprint(yaml: &str) -> String {
    format!("{:x}", Sha256::digest(yaml.as_bytes()))
}

// ── DB persistence ────────────────────────────────────────────────────────────

pub async fn create(pool: &PgPool, yaml: &str) -> Result<Pipeline> {
    let dsl = parse_yaml(yaml)?;
    let compiled = compile(&dsl);
    let fp = fingerprint(yaml);

    let next_version: i64 = sqlx::query(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM conductor_pipelines WHERE name = $1"
    )
    .bind(&dsl.name)
    .fetch_one(pool)
    .await
    .map(|r| r.try_get::<i64, _>(0).unwrap_or(1))
    .unwrap_or(1);

    let row = sqlx::query(
        r#"INSERT INTO conductor_pipelines
           (name, version, yaml_source, compiled_json, status, fingerprint)
           VALUES ($1, $2, $3, $4, 'active', $5)
           RETURNING id, name, version, yaml_source, compiled_json, status,
                     fingerprint, created_at, updated_at"#
    )
    .bind(&dsl.name)
    .bind(next_version as i32)
    .bind(yaml)
    .bind(serde_json::to_value(&compiled).unwrap_or_default())
    .bind(&fp)
    .fetch_one(pool)
    .await
    .context("Failed to insert pipeline")?;

    Ok(row_to_pipeline(row))
}

pub async fn list(pool: &PgPool) -> Result<Vec<Pipeline>> {
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (name) id, name, version, yaml_source,
           compiled_json, status, fingerprint, created_at, updated_at
           FROM conductor_pipelines
           WHERE status = 'active'
           ORDER BY name, version DESC"#
    )
    .fetch_all(pool)
    .await
    .context("Failed to list pipelines")?;

    Ok(rows.into_iter().map(row_to_pipeline).collect())
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Pipeline> {
    let row = sqlx::query(
        r#"SELECT id, name, version, yaml_source, compiled_json, status,
           fingerprint, created_at, updated_at
           FROM conductor_pipelines WHERE id = $1"#
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .context("Pipeline not found")?;

    Ok(row_to_pipeline(row))
}

pub async fn archive(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE conductor_pipelines SET status = 'archived', updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .context("Failed to archive pipeline")?;
    Ok(())
}

pub async fn register_with_connector(connector: &ConnectorClient, pipeline: &Pipeline) -> Result<String> {
    let body = serde_json::json!({
        "id": pipeline.id.to_string(),
        "name": pipeline.name,
        "version": pipeline.version,
        "definition": pipeline.compiled_json,
    });
    let resp = connector.register_pipeline_definition(&body).await?;
    Ok(resp.get("id").and_then(|v| v.as_str()).unwrap_or(&pipeline.id.to_string()).to_string())
}

// ── Row mapping ───────────────────────────────────────────────────────────────

fn row_to_pipeline(row: sqlx::postgres::PgRow) -> Pipeline {
    let status_str: String = row.try_get("status").unwrap_or_default();
    Pipeline {
        id:           row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        name:         row.try_get("name").unwrap_or_default(),
        version:      row.try_get("version").unwrap_or(1),
        yaml_source:  row.try_get("yaml_source").unwrap_or_default(),
        compiled_json: row.try_get("compiled_json").unwrap_or_default(),
        status:       if status_str == "active" { PipelineStatus::Active } else { PipelineStatus::Archived },
        fingerprint:  row.try_get("fingerprint").unwrap_or_default(),
        created_at:   row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:   row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}
