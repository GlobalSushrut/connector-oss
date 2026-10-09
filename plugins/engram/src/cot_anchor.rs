//! CoT Anchor — Long-chain-of-thought stabiliser.
//!
//! Each reasoning step is submitted here. We ground the claim against memory
//! before the chain continues. If the claim fails:
//!   - on_fail=retry  → step is marked "retried"; caller must resubmit
//!   - on_fail=block  → step is marked "blocked"; session is aborted
//!   - on_fail=flag   → step is marked "flagged"; chain continues with warning
//!
//! On conclude, we write a proof bundle CID to WitnessCtl via the Connector audit log.

use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::dehallucination::{self, GroundingConfig, OnFail};
use crate::error::AppError;
use crate::metrics;
use crate::types::{CotConcludeResponse, CotSessionResponse, CotStepResponse};

/// Load a CoT session row, returning 404 if absent.
pub async fn load_session(pool: &PgPool, session_id: Uuid) -> Result<CotSessionRow, AppError> {
    let row = sqlx::query_as!(
        CotSessionRow,
        r#"
        SELECT s.id, s.session_name, s.agent_id, s.threshold, s.on_fail, s.status,
               s.step_count, s.passed_count, s.failed_count,
               s.started_at, s.concluded_at, s.proof_cid,
               n.path AS namespace
        FROM engram_cot_sessions s
        JOIN engram_namespaces n ON n.id = s.namespace_id
        WHERE s.id = $1
        "#,
        session_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("CoT session {session_id} not found")))?;

    Ok(row)
}

pub struct CotSessionRow {
    pub id:           Uuid,
    pub session_name: Option<String>,
    pub agent_id:     String,
    pub threshold:    f64,
    pub on_fail:      String,
    pub status:       String,
    pub step_count:   i32,
    pub passed_count: i32,
    pub failed_count: i32,
    pub started_at:   chrono::DateTime<Utc>,
    pub concluded_at: Option<chrono::DateTime<Utc>>,
    pub proof_cid:    Option<String>,
    pub namespace:    String,
}

impl From<CotSessionRow> for CotSessionResponse {
    fn from(r: CotSessionRow) -> Self {
        Self {
            id:           r.id,
            session_name: r.session_name,
            namespace:    r.namespace,
            agent_id:     r.agent_id,
            threshold:    r.threshold,
            on_fail:      r.on_fail,
            status:       r.status,
            step_count:   r.step_count,
            passed_count: r.passed_count,
            failed_count: r.failed_count,
            started_at:   r.started_at,
            concluded_at: r.concluded_at,
            proof_cid:    r.proof_cid,
        }
    }
}

/// Submit one reasoning step for grounding.
pub async fn submit_step(
    pool:       &PgPool,
    connector:  &ConnectorClient,
    session_id: Uuid,
    claim_text: &str,
) -> Result<CotStepResponse, AppError> {
    let session = load_session(pool, session_id).await?;

    if session.status != "active" {
        return Err(AppError::BadRequest(format!(
            "CoT session is '{}' — only 'active' sessions accept new steps",
            session.status
        )));
    }

    let step_number = session.step_count + 1;
    let config = GroundingConfig {
        threshold: session.threshold,
        on_fail:   OnFail::from_str(&session.on_fail),
    };

    // ── Ground the claim ──────────────────────────────────────────────────────
    let (results, _chain_cid) = dehallucination::ground_claims(
        connector,
        &session.namespace,
        &[claim_text.to_owned()],
        &config,
        &session.agent_id,
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    let result = results.into_iter().next()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("empty grounding result")))?;

    let grounding_score  = result.grounding_score;
    let source_cids_json = serde_json::to_value(&result.source_cids).unwrap_or_default();
    let grounded         = result.grounded;
    let outcome          = result.outcome.clone();

    // ── Persist step ──────────────────────────────────────────────────────────
    let retry_count = if outcome == "retried" { 1_i32 } else { 0_i32 };

    sqlx::query!(
        r#"
        INSERT INTO engram_cot_steps
            (session_id, step_number, claim_text, grounding_score,
             source_cids, outcome, retry_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (session_id, step_number) DO UPDATE
            SET outcome         = EXCLUDED.outcome,
                grounding_score = EXCLUDED.grounding_score,
                source_cids     = EXCLUDED.source_cids,
                retry_count     = engram_cot_steps.retry_count + 1
        "#,
        session_id,
        step_number,
        claim_text,
        grounding_score,
        source_cids_json,
        outcome,
        retry_count,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    // ── Update session counters ───────────────────────────────────────────────
    let (pass_delta, fail_delta) = if grounded { (1_i32, 0_i32) } else { (0_i32, 1_i32) };

    let new_status = if outcome == "blocked" { "aborted" } else { "active" };

    sqlx::query!(
        r#"
        UPDATE engram_cot_sessions
        SET step_count   = step_count + 1,
            passed_count = passed_count + $1,
            failed_count = failed_count + $2,
            status       = $3
        WHERE id = $4
        "#,
        pass_delta,
        fail_delta,
        new_status,
        session_id,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    metrics::record_cot_step(&session.namespace, &outcome);

    Ok(CotStepResponse {
        step_number,
        claim_text: claim_text.to_owned(),
        grounding_score,
        grounded,
        source_cids: result.source_cids,
        outcome,
        retry_count,
        session_status: new_status.to_owned(),
    })
}

/// Conclude a CoT session and write the proof bundle to the audit log.
pub async fn conclude_session(
    pool:       &PgPool,
    connector:  &ConnectorClient,
    session_id: Uuid,
) -> Result<CotConcludeResponse, AppError> {
    let session = load_session(pool, session_id).await?;

    if session.status != "active" {
        return Err(AppError::BadRequest(format!(
            "CoT session is '{}' — only 'active' sessions can be concluded",
            session.status
        )));
    }

    // Collect all steps for the proof bundle
    let steps = sqlx::query!(
        r#"
        SELECT step_number, claim_text, grounding_score, source_cids, outcome
        FROM engram_cot_steps
        WHERE session_id = $1
        ORDER BY step_number
        "#,
        session_id,
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;

    let proof_payload = json!({
        "session_id":  session_id,
        "namespace":   session.namespace,
        "agent_id":    session.agent_id,
        "threshold":   session.threshold,
        "step_count":  session.step_count + 1,
        "passed":      session.passed_count,
        "failed":      session.failed_count,
        "steps": steps.iter().map(|s| json!({
            "step":    s.step_number,
            "claim":   s.claim_text,
            "score":   s.grounding_score,
            "outcome": s.outcome,
            "sources": s.source_cids,
        })).collect::<Vec<_>>(),
    });

    let proof_cid = connector.write_audit(
        "cot_concluded",
        &session.agent_id,
        &session.namespace,
        proof_payload,
    ).await.unwrap_or_default();

    let concluded_at = Utc::now();

    sqlx::query!(
        r#"
        UPDATE engram_cot_sessions
        SET status       = 'concluded',
            concluded_at = $1,
            proof_cid    = $2
        WHERE id = $3
        "#,
        concluded_at,
        if proof_cid.is_empty() { None } else { Some(proof_cid.clone()) },
        session_id,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(CotConcludeResponse {
        session_id,
        step_count:   session.step_count + 1,
        passed_count: session.passed_count,
        failed_count: session.failed_count,
        proof_cid:    if proof_cid.is_empty() { None } else { Some(proof_cid) },
        concluded_at,
    })
}
