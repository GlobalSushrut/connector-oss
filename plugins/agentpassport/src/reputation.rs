//! Reputation engine — portable, cross-deployment, decay-aware.
//!
//! Score is permanently attached to the DID, not the deployment.
//! Violations follow the agent even after re-registration attempts.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// ── Score deltas (hard-coded policy) ──────────────────────────────────────────

pub const DELTA_MINOR_VIOLATION:    f64 = -0.02;
pub const DELTA_MODERATE_VIOLATION: f64 = -0.05;
pub const DELTA_SEVERE_VIOLATION:   f64 = -0.15;
pub const DELTA_BUDGET_BREACH:      f64 = -0.03;
pub const DELTA_SECURITY_INCIDENT:  f64 = -0.25;
pub const DELTA_SPONSOR_REVOCATION: f64 = -0.30;
pub const DELTA_INTERACTION_BATCH:  f64 =  0.01;   // per 1000 clean interactions
pub const DELTA_COMPLIANCE_CRED:    f64 =  0.02;
pub const DELTA_FEDERATION_REF:     f64 =  0.03;
pub const DELTA_SPONSOR_RENEWAL:    f64 =  0.01;

// ── Apply a reputation event ───────────────────────────────────────────────────

pub async fn apply_event(
    pool: &PgPool,
    agent_id: Uuid,
    org_id: Uuid,
    event_type: &str,
    delta: f64,
    reason: Option<&str>,
    evidence_cid: Option<&str>,
    source_org_id: Option<Uuid>,
) -> Result<f64> {
    // Fetch current score
    let row = sqlx::query("SELECT did, trust_score FROM ap_agents WHERE id=$1")
        .bind(agent_id).fetch_one(pool).await.context("fetch agent for reputation")?;
    let did: String = row.try_get("did")?;
    let score_before: f64 = row.try_get("trust_score").unwrap_or(1.0);

    let score_after = (score_before + delta).clamp(0.0, 1.0);

    // Update agent score
    sqlx::query("UPDATE ap_agents SET trust_score=$1 WHERE id=$2")
        .bind(score_after).bind(agent_id)
        .execute(pool).await.context("update trust score")?;

    // Record event
    sqlx::query(
        "INSERT INTO ap_reputation_events
            (agent_id, agent_did, org_id, event_type, delta,
             score_before, score_after, reason, evidence_cid, source_org_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
    )
    .bind(agent_id)
    .bind(&did)
    .bind(org_id)
    .bind(event_type)
    .bind(delta)
    .bind(score_before)
    .bind(score_after)
    .bind(reason)
    .bind(evidence_cid)
    .bind(source_org_id)
    .execute(pool).await.context("insert rep event")?;

    metrics::counter!("agentpassport_reputation_events_total",
        "event_type" => event_type.to_string()
    ).increment(1);

    tracing::info!(
        agent_did = %did,
        event_type = event_type,
        score_before = score_before,
        score_after = score_after,
        "Reputation event applied"
    );

    Ok(score_after)
}

// ── Get reputation with 90d trend ─────────────────────────────────────────────

pub async fn get_reputation(pool: &PgPool, agent_did: &str) -> Result<Value> {
    let agent_row = sqlx::query(
        "SELECT id, did, trust_score, violation_count, incident_count,
                total_interactions, activated_at
         FROM ap_agents WHERE did=$1"
    ).bind(agent_did).fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Agent not found"))?;

    let agent_id:       Uuid  = agent_row.try_get("id")?;
    let trust_score:    f64   = agent_row.try_get("trust_score").unwrap_or(1.0);
    let violations:     i32   = agent_row.try_get("violation_count").unwrap_or(0);
    let incidents:      i32   = agent_row.try_get("incident_count").unwrap_or(0);
    let interactions:   i64   = agent_row.try_get("total_interactions").unwrap_or(0);

    // 90-day daily trend (one data point per day)
    let trend_rows = sqlx::query(
        "SELECT
             date_trunc('day', occurred_at) AS day,
             LAST_VALUE(score_after) OVER (
                 PARTITION BY date_trunc('day', occurred_at)
                 ORDER BY occurred_at
                 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
             ) AS eod_score
         FROM ap_reputation_events
         WHERE agent_id=$1 AND occurred_at >= NOW() - INTERVAL '90 days'
         GROUP BY day, score_after, occurred_at
         ORDER BY day"
    ).bind(agent_id).fetch_all(pool).await.unwrap_or_default();

    let trend: Vec<Value> = trend_rows.iter().map(|r| {
        json!({
            "date":  r.try_get::<chrono::DateTime<Utc>, _>("day").map(|d| d.date_naive().to_string()).unwrap_or_default(),
            "score": r.try_get::<f64, _>("eod_score").unwrap_or(trust_score),
        })
    }).collect();

    // Recent events (last 20)
    let events = sqlx::query(
        "SELECT event_type, delta, score_before, score_after, reason, occurred_at
         FROM ap_reputation_events WHERE agent_id=$1
         ORDER BY occurred_at DESC LIMIT 20"
    ).bind(agent_id).fetch_all(pool).await.unwrap_or_default();

    let recent_events: Vec<Value> = events.iter().map(|r| json!({
        "event_type":   r.try_get::<String, _>("event_type").unwrap_or_default(),
        "delta":        r.try_get::<f64, _>("delta").unwrap_or(0.0),
        "score_before": r.try_get::<f64, _>("score_before").unwrap_or(0.0),
        "score_after":  r.try_get::<f64, _>("score_after").unwrap_or(0.0),
        "reason":       r.try_get::<Option<String>, _>("reason").unwrap_or_default(),
        "occurred_at":  r.try_get::<chrono::DateTime<Utc>, _>("occurred_at").unwrap_or_else(|_| Utc::now()),
    })).collect();

    // Signal
    let signal = reputation_signal(trust_score, violations);

    Ok(json!({
        "agent_did":           agent_did,
        "trust_score":         trust_score,
        "signal":              signal,
        "total_interactions":  interactions,
        "violation_count":     violations,
        "incident_count":      incidents,
        "trend_90d":           trend,
        "recent_events":       recent_events,
        "as_of":               Utc::now(),
    }))
}

// ── Decay sweep (runs nightly) ─────────────────────────────────────────────────
//
// Violations older than 180 days lose 50% of their original weight per year.
// This allows genuinely reformed agents to recover, while keeping the record.

pub async fn run_decay_sweep(pool: &PgPool) -> Result<u64> {
    // Find all active agents with violations older than 180 days
    let rows = sqlx::query(
        "SELECT DISTINCT re.agent_id, a.trust_score
         FROM ap_reputation_events re
         JOIN ap_agents a ON a.id = re.agent_id
         WHERE re.event_type IN ('minor_violation','moderate_violation','severe_violation','security_incident')
           AND re.occurred_at < NOW() - INTERVAL '180 days'
           AND a.status = 'active'
           AND re.delta < 0"
    ).fetch_all(pool).await.context("decay sweep fetch")?;

    let mut recovered = 0u64;
    for row in &rows {
        let agent_id: Uuid = row.try_get("agent_id")?;
        let score: f64     = row.try_get("trust_score").unwrap_or(0.0);
        if score < 1.0 {
            let recovery = ((1.0 - score) * 0.001).min(0.005); // gentle daily recovery
            apply_event(pool, agent_id,
                // org_id not tracked here — use default
                Uuid::nil(),
                "admin_override",
                recovery,
                Some("Automatic decay recovery"),
                None, None).await.ok();
            recovered += 1;
        }
    }
    Ok(recovered)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

pub fn reputation_signal(score: f64, violations: i32) -> &'static str {
    if score >= 0.9 && violations == 0  { "✅ Trusted" }
    else if score >= 0.75               { "🟡 Monitor" }
    else if score >= 0.5                { "🟠 Caution" }
    else                                { "🔴 High Risk" }
}

pub fn delta_for_event_type(event_type: &str) -> f64 {
    match event_type {
        "minor_violation"    => DELTA_MINOR_VIOLATION,
        "moderate_violation" => DELTA_MODERATE_VIOLATION,
        "severe_violation"   => DELTA_SEVERE_VIOLATION,
        "budget_breach"      => DELTA_BUDGET_BREACH,
        "security_incident"  => DELTA_SECURITY_INCIDENT,
        "sponsor_revocation" => DELTA_SPONSOR_REVOCATION,
        "interaction_batch"  => DELTA_INTERACTION_BATCH,
        "compliance_credential" => DELTA_COMPLIANCE_CRED,
        "federation_reference"  => DELTA_FEDERATION_REF,
        "sponsor_renewal"       => DELTA_SPONSOR_RENEWAL,
        _ => 0.0,
    }
}
