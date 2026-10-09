//! Design module — prompt registry, versioning, lint, approval flow, datasets.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::types::{ApprovalStatus, Dataset, Prompt, PromptStatus, PromptVersion};

// ── Agents ────────────────────────────────────────────────────────────────────

pub async fn create_agent(
    pool:         &PgPool,
    name:         &str,
    connector_id: Option<&str>,
    description:  Option<&str>,
    team:         Option<&str>,
    tags:         &[String],
    metadata:     &Value,
) -> Result<crate::types::Agent> {
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO al_agents (id, name, connector_id, description, team, tags, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *"
    )
    .bind(id).bind(name).bind(connector_id).bind(description).bind(team)
    .bind(tags).bind(metadata)
    .fetch_one(pool).await.context("create agent")?;
    Ok(row_to_agent(row))
}

pub async fn get_agent(pool: &PgPool, id: Uuid) -> Result<crate::types::Agent> {
    let row = sqlx::query("SELECT * FROM al_agents WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get agent")?;
    Ok(row_to_agent(row))
}

pub async fn list_agents(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<crate::types::Agent>> {
    let rows = sqlx::query(
        "SELECT * FROM al_agents WHERE status = 'active' ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(limit).bind(offset)
    .fetch_all(pool).await.context("list agents")?;
    Ok(rows.into_iter().map(row_to_agent).collect())
}

// ── Prompt Registry ───────────────────────────────────────────────────────────

pub async fn create_prompt(
    pool:         &PgPool,
    agent_id:     Option<Uuid>,
    name:         &str,
    description:  Option<&str>,
    tags:         &[String],
    system:       Option<&str>,
    user_tmpl:    Option<&str>,
    variables:    &Value,
    model_config: &Value,
    author:       Option<&str>,
    commit_msg:   Option<&str>,
) -> Result<(Prompt, PromptVersion)> {
    let prompt_id = Uuid::new_v4();

    // Create the prompt entity
    let prompt_row = sqlx::query(
        "INSERT INTO al_prompts (id, agent_id, name, description, tags, current_version)
         VALUES ($1,$2,$3,$4,$5,1) RETURNING *"
    )
    .bind(prompt_id).bind(agent_id).bind(name).bind(description).bind(tags)
    .fetch_one(pool).await.context("create prompt")?;

    let pv = create_prompt_version_inner(
        pool, prompt_id, 1, system, user_tmpl, variables, model_config, author, commit_msg,
    ).await?;

    Ok((row_to_prompt(prompt_row), pv))
}

pub async fn get_prompt(pool: &PgPool, id: Uuid) -> Result<Prompt> {
    let row = sqlx::query("SELECT * FROM al_prompts WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get prompt")?;
    Ok(row_to_prompt(row))
}

pub async fn list_prompts(
    pool:     &PgPool,
    agent_id: Option<Uuid>,
    limit:    i64,
    offset:   i64,
) -> Result<Vec<Prompt>> {
    let rows = if let Some(aid) = agent_id {
        sqlx::query(
            "SELECT * FROM al_prompts WHERE agent_id = $1 AND status = 'active'
             ORDER BY updated_at DESC LIMIT $2 OFFSET $3"
        ).bind(aid).bind(limit).bind(offset).fetch_all(pool).await
    } else {
        sqlx::query(
            "SELECT * FROM al_prompts WHERE status = 'active'
             ORDER BY updated_at DESC LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await
    }.context("list prompts")?;
    Ok(rows.into_iter().map(row_to_prompt).collect())
}

// ── Prompt Versions ───────────────────────────────────────────────────────────

pub async fn create_version(
    pool:         &PgPool,
    prompt_id:    Uuid,
    system:       Option<&str>,
    user_tmpl:    Option<&str>,
    variables:    &Value,
    model_config: &Value,
    author:       Option<&str>,
    commit_msg:   Option<&str>,
) -> Result<PromptVersion> {
    // Increment version
    let new_version: i32 = sqlx::query(
        "UPDATE al_prompts SET current_version = current_version + 1, updated_at = NOW()
         WHERE id = $1 RETURNING current_version"
    )
    .bind(prompt_id)
    .fetch_one(pool).await.context("bump version")?
    .try_get("current_version")?;

    create_prompt_version_inner(
        pool, prompt_id, new_version, system, user_tmpl, variables, model_config, author, commit_msg,
    ).await
}

async fn create_prompt_version_inner(
    pool:         &PgPool,
    prompt_id:    Uuid,
    version:      i32,
    system:       Option<&str>,
    user_tmpl:    Option<&str>,
    variables:    &Value,
    model_config: &Value,
    author:       Option<&str>,
    commit_msg:   Option<&str>,
) -> Result<PromptVersion> {
    let fingerprint = {
        let content = format!("{}|{}", system.unwrap_or(""), user_tmpl.unwrap_or(""));
        format!("{:x}", Sha256::digest(content.as_bytes()))
    };

    let lint = lint_prompt(system, user_tmpl);
    let id = Uuid::new_v4();

    let row = sqlx::query(
        "INSERT INTO al_prompt_versions
         (id, prompt_id, version, system_prompt, user_template, variables, model_config,
          lint_score, lint_issues, fingerprint, author, commit_message)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *"
    )
    .bind(id).bind(prompt_id).bind(version)
    .bind(system).bind(user_tmpl)
    .bind(variables).bind(model_config)
    .bind(lint.score).bind(&lint.issues)
    .bind(&fingerprint).bind(author).bind(commit_msg)
    .fetch_one(pool).await.context("create prompt version")?;

    Ok(row_to_prompt_version(row))
}

pub async fn get_version(pool: &PgPool, id: Uuid) -> Result<PromptVersion> {
    let row = sqlx::query("SELECT * FROM al_prompt_versions WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get prompt version")?;
    Ok(row_to_prompt_version(row))
}

pub async fn list_versions(pool: &PgPool, prompt_id: Uuid) -> Result<Vec<PromptVersion>> {
    let rows = sqlx::query(
        "SELECT * FROM al_prompt_versions WHERE prompt_id = $1 ORDER BY version DESC"
    )
    .bind(prompt_id).fetch_all(pool).await.context("list versions")?;
    Ok(rows.into_iter().map(row_to_prompt_version).collect())
}

pub async fn approve_version(
    pool:      &PgPool,
    id:        Uuid,
    approved:  bool,
    reviewer:  &str,
    _reason:   Option<&str>,
) -> Result<PromptVersion> {
    let status = if approved { "approved" } else { "rejected" };
    let row = sqlx::query(
        "UPDATE al_prompt_versions
         SET approval_status = $1, approved_by = $2, approved_at = NOW()
         WHERE id = $3 RETURNING *"
    )
    .bind(status).bind(reviewer).bind(id)
    .fetch_one(pool).await.context("approve version")?;
    Ok(row_to_prompt_version(row))
}

// ── Lint ──────────────────────────────────────────────────────────────────────

struct LintResult { score: i32, issues: Value }

fn lint_prompt(system: Option<&str>, user_tmpl: Option<&str>) -> LintResult {
    let mut issues: Vec<Value> = vec![];
    let mut deductions = 0i32;

    let system_text = system.unwrap_or("");
    let user_text   = user_tmpl.unwrap_or("");

    if system_text.is_empty() && user_text.is_empty() {
        issues.push(json!({ "code": "EMPTY_PROMPT", "severity": "error", "message": "Prompt has no content" }));
        deductions += 50;
    }
    if system_text.len() > 8000 {
        issues.push(json!({ "code": "SYSTEM_TOO_LONG", "severity": "warning", "message": "System prompt exceeds 8000 chars — high token cost" }));
        deductions += 10;
    }
    if user_text.contains("ignore previous instructions") || user_text.contains("ignore all instructions") {
        issues.push(json!({ "code": "INJECTION_PATTERN", "severity": "error", "message": "Possible prompt injection pattern detected" }));
        deductions += 30;
    }
    if !user_text.contains('{') && !user_text.contains("{{") && !system_text.contains("{{") {
        issues.push(json!({ "code": "NO_VARIABLES", "severity": "info", "message": "No template variables found — prompt may not be parameterised" }));
    }
    if system_text.to_lowercase().contains("you are") && system_text.len() < 20 {
        issues.push(json!({ "code": "THIN_PERSONA", "severity": "warning", "message": "System persona is very short — consider adding more context" }));
        deductions += 5;
    }

    LintResult { score: (100 - deductions).max(0), issues: json!(issues) }
}

// ── Datasets ──────────────────────────────────────────────────────────────────

pub async fn create_dataset(
    pool:        &PgPool,
    agent_id:    Option<Uuid>,
    name:        &str,
    description: Option<&str>,
    tags:        &[String],
) -> Result<Dataset> {
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO al_datasets (id, agent_id, name, description, tags)
         VALUES ($1,$2,$3,$4,$5) RETURNING *"
    )
    .bind(id).bind(agent_id).bind(name).bind(description).bind(tags)
    .fetch_one(pool).await.context("create dataset")?;
    Ok(row_to_dataset(row))
}

pub async fn get_dataset(pool: &PgPool, id: Uuid) -> Result<Dataset> {
    let row = sqlx::query("SELECT * FROM al_datasets WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get dataset")?;
    Ok(row_to_dataset(row))
}

pub async fn add_dataset_row(pool: &PgPool, dataset_id: Uuid, inputs: &Value, expected: Option<&Value>) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO al_dataset_rows (id, dataset_id, inputs, expected) VALUES ($1,$2,$3,$4)")
        .bind(id).bind(dataset_id).bind(inputs).bind(expected)
        .execute(pool).await.context("add dataset row")?;
    sqlx::query("UPDATE al_datasets SET row_count = row_count + 1, updated_at = NOW() WHERE id = $1")
        .bind(dataset_id).execute(pool).await.context("update row count")?;
    Ok(id)
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_agent(row: sqlx::postgres::PgRow) -> crate::types::Agent {
    use crate::types::AgentStatus;
    let s: String = row.try_get("status").unwrap_or_default();
    let status = match s.as_str() { "archived" => AgentStatus::Archived, "quarantined" => AgentStatus::Quarantined, _ => AgentStatus::Active };
    crate::types::Agent {
        id:           row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        connector_id: row.try_get("connector_id").ok(),
        name:         row.try_get("name").unwrap_or_default(),
        description:  row.try_get("description").ok(),
        team:         row.try_get("team").ok(),
        tags:         row.try_get("tags").unwrap_or_default(),
        status,
        metadata:     row.try_get("metadata").unwrap_or(json!({})),
        created_at:   row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:   row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_prompt(row: sqlx::postgres::PgRow) -> Prompt {
    let s: String = row.try_get("status").unwrap_or_default();
    let status = match s.as_str() { "archived" => PromptStatus::Archived, "deprecated" => PromptStatus::Deprecated, _ => PromptStatus::Active };
    Prompt {
        id:              row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:        row.try_get("agent_id").ok(),
        name:            row.try_get("name").unwrap_or_default(),
        description:     row.try_get("description").ok(),
        tags:            row.try_get("tags").unwrap_or_default(),
        status,
        current_version: row.try_get("current_version").unwrap_or(1),
        created_at:      row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:      row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_prompt_version(row: sqlx::postgres::PgRow) -> PromptVersion {
    let s: String = row.try_get("approval_status").unwrap_or_default();
    let approval_status = match s.as_str() {
        "pending"  => ApprovalStatus::Pending,
        "approved" => ApprovalStatus::Approved,
        "rejected" => ApprovalStatus::Rejected,
        _          => ApprovalStatus::Draft,
    };
    PromptVersion {
        id:              row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        prompt_id:       row.try_get("prompt_id").unwrap_or_else(|_| Uuid::new_v4()),
        version:         row.try_get("version").unwrap_or(1),
        system_prompt:   row.try_get("system_prompt").ok(),
        user_template:   row.try_get("user_template").ok(),
        variables:       row.try_get("variables").unwrap_or(json!([])),
        model_config:    row.try_get("model_config").unwrap_or(json!({})),
        lint_score:      row.try_get("lint_score").ok(),
        lint_issues:     row.try_get("lint_issues").unwrap_or(json!([])),
        fingerprint:     row.try_get("fingerprint").unwrap_or_default(),
        author:          row.try_get("author").ok(),
        commit_message:  row.try_get("commit_message").ok(),
        approval_status,
        approved_by:     row.try_get("approved_by").ok(),
        approved_at:     row.try_get("approved_at").ok(),
        created_at:      row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_dataset(row: sqlx::postgres::PgRow) -> Dataset {
    Dataset {
        id:          row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:    row.try_get("agent_id").ok(),
        name:        row.try_get("name").unwrap_or_default(),
        description: row.try_get("description").ok(),
        tags:        row.try_get("tags").unwrap_or_default(),
        row_count:   row.try_get("row_count").unwrap_or(0),
        created_at:  row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:  row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}
