//! Incident tracking, auto-quarantine, reputation cascade.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::agents::append_audit;
use crate::connector::ConnectorClient;
use crate::reputation;
use crate::types::{CreateIncidentRequest, IncidentRow, Pagination, ResolveIncidentRequest};

// ── Create incident ────────────────────────────────────────────────────────────

pub async fn create_incident(
    pool: &PgPool,
    connector: &ConnectorClient,
    org_id: Uuid,
    req: &CreateIncidentRequest,
    actor: &str,
) -> Result<IncidentRow> {
    // Resolve agent
    let agent_row = sqlx::query(
        "SELECT id, violation_count, incident_count, connector_pid
         FROM ap_agents WHERE did=$1 AND org_id=$2"
    ).bind(&req.agent_did).bind(org_id)
    .fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Agent not found"))?;

    let agent_id:     Uuid = agent_row.try_get("id")?;
    let violations:    i32 = agent_row.try_get("violation_count").unwrap_or(0);
    let incidents:     i32 = agent_row.try_get("incident_count").unwrap_or(0);
    let connector_pid: Option<String> = agent_row.try_get("connector_pid").ok().flatten();

    // Determine reputation delta and auto-action
    let (rep_event_type, rep_delta) = incident_rep_event(&req.incident_type, &req.severity);
    let new_score = reputation::apply_event(
        pool, agent_id, org_id,
        rep_event_type, rep_delta,
        Some(&req.description),
        req.evidence_cid.as_deref(),
        None,
    ).await.unwrap_or(0.0);

    // Auto-action decision
    let auto_action = determine_auto_action(&req.severity, violations + 1, new_score);

    // Execute auto-action if needed
    if auto_action == "quarantined" {
        sqlx::query("UPDATE ap_agents SET status='quarantined' WHERE id=$1")
            .bind(agent_id).execute(pool).await.ok();
        if let Some(ref pid) = connector_pid {
            connector.quarantine_agent(pid, &format!("auto-quarantine: {}", req.title))
                .await.ok();
        }
    } else if auto_action == "revoked" {
        sqlx::query(
            "UPDATE ap_agents SET status='revoked', revoked_at=NOW(), revocation_reason=$1, revoked_by='system'
             WHERE id=$2"
        ).bind(format!("auto-revoke: {}", req.title)).bind(agent_id)
        .execute(pool).await.ok();
        // Add to CRL
        sqlx::query(
            "INSERT INTO ap_crl (did, entity_type, reason, revoked_by)
             VALUES ($1,'agent','auto-revoked by incident policy','system')
             ON CONFLICT (did) DO NOTHING"
        ).bind(&req.agent_did).execute(pool).await.ok();
    }

    // Update counters
    sqlx::query(
        "UPDATE ap_agents
         SET violation_count = $1, incident_count = $2
         WHERE id = $3"
    )
    .bind(violations + 1).bind(incidents + 1).bind(agent_id)
    .execute(pool).await.ok();

    // Insert incident record
    let row = sqlx::query(
        "INSERT INTO ap_incidents
            (agent_id, org_id, incident_type, severity, title, description,
             evidence_cid, auto_action, reputation_delta)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING *"
    )
    .bind(agent_id)
    .bind(org_id)
    .bind(&req.incident_type)
    .bind(&req.severity)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.evidence_cid)
    .bind(&auto_action)
    .bind(rep_delta)
    .fetch_one(pool).await.context("insert incident")?;

    append_audit(pool, org_id, "incident", &row.try_get::<Uuid, _>("id")
        .map(|u| u.to_string()).unwrap_or_default(),
        "created", Some(actor), None,
        json!({
            "type": req.incident_type,
            "severity": req.severity,
            "auto_action": auto_action,
            "new_score": new_score
        }), None).await;

    Ok(row_to_incident(&row))
}

// ── List incidents ─────────────────────────────────────────────────────────────

pub async fn list_incidents(pool: &PgPool, org_id: Uuid, pg: &Pagination) -> Result<Vec<IncidentRow>> {
    let rows = sqlx::query(
        "SELECT * FROM ap_incidents WHERE org_id=$1
         ORDER BY created_at DESC LIMIT $2 OFFSET $3"
    ).bind(org_id).bind(pg.limit()).bind(pg.offset())
    .fetch_all(pool).await.context("list incidents")?;
    Ok(rows.iter().map(row_to_incident).collect())
}

// ── Resolve incident ───────────────────────────────────────────────────────────

pub async fn resolve_incident(
    pool: &PgPool,
    org_id: Uuid,
    incident_id: Uuid,
    req: &ResolveIncidentRequest,
    resolved_by: &str,
) -> Result<IncidentRow> {
    let row = sqlx::query(
        "UPDATE ap_incidents
         SET resolved_at=NOW(), resolved_by=$1, resolution_note=$2
         WHERE id=$3 AND org_id=$4 AND resolved_at IS NULL
         RETURNING *"
    )
    .bind(resolved_by).bind(&req.resolution_note)
    .bind(incident_id).bind(org_id)
    .fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Incident not found or already resolved"))?;

    Ok(row_to_incident(&row))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn incident_rep_event(incident_type: &str, severity: &str) -> (&'static str, f64) {
    match (incident_type, severity) {
        (_, "critical") | ("unauthorized_access", _) | ("security", _) =>
            ("severe_violation",   reputation::DELTA_SEVERE_VIOLATION),
        (_, "high")     | ("policy_violation", _) =>
            ("moderate_violation", reputation::DELTA_MODERATE_VIOLATION),
        ("budget_breach", _) =>
            ("budget_breach",      reputation::DELTA_BUDGET_BREACH),
        _ =>
            ("minor_violation",    reputation::DELTA_MINOR_VIOLATION),
    }
}

fn determine_auto_action(severity: &str, total_violations: i32, score: f64) -> String {
    if severity == "critical" || score < 0.3 || total_violations >= 5 {
        "revoked".into()
    } else if severity == "high" || score < 0.5 || total_violations >= 3 {
        "quarantined".into()
    } else {
        "reputation_decremented".into()
    }
}

fn row_to_incident(row: &sqlx::postgres::PgRow) -> IncidentRow {
    IncidentRow {
        id:                  row.try_get("id").unwrap_or_default(),
        agent_id:            row.try_get("agent_id").unwrap_or_default(),
        org_id:              row.try_get("org_id").unwrap_or_default(),
        incident_type:       row.try_get("incident_type").unwrap_or_default(),
        severity:            row.try_get("severity").unwrap_or_default(),
        title:               row.try_get("title").unwrap_or_default(),
        description:         row.try_get("description").unwrap_or_default(),
        evidence_cid:        row.try_get("evidence_cid").ok().flatten(),
        auto_action:         row.try_get("auto_action").ok().flatten(),
        reputation_delta:    row.try_get("reputation_delta").ok().flatten(),
        sponsor_notified_at: row.try_get("sponsor_notified_at").ok().flatten(),
        resolved_at:         row.try_get("resolved_at").ok().flatten(),
        created_at:          row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}
