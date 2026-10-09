//! Knot entropy resolver — semantic thread separator.
//!
//! In Phase 1, the knot resolver is scaffolded with the data model and detection
//! interface. Full thread-tracking (cross-thread pollution scoring) ships in Phase 2
//! when CoT Anchor session IDs are used as thread identifiers.
//!
//! Phase 1 exports:
//!   - `KnotReport`  — structured knot analysis output
//!   - `analyze()`   — returns knot_score + threads_detected from DB snapshots

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ThreadKnot {
    pub thread_a:    String,
    pub thread_b:    String,
    pub shared_terms: Vec<String>,
    pub pollution:   f64,
}

#[derive(Debug, Serialize)]
pub struct KnotReport {
    pub namespace:       String,
    pub knot_score:      f64,
    pub threads_detected: i32,
    pub polluted_threads: i32,
    pub knots:           Vec<ThreadKnot>,
    pub recommended:     String,
}

/// Compute knot score from the latest entropy snapshot.
/// Full thread analysis (Phase 2) will query CoT session thread IDs.
pub async fn analyze(
    pool:      &PgPool,
    ns_id:     Uuid,
    namespace: &str,
) -> Result<KnotReport> {
    let row = sqlx::query!(
        r#"
        SELECT knot_score, threads_detected
        FROM engram_entropy_snapshots
        WHERE namespace_id = $1
        ORDER BY snapped_at DESC
        LIMIT 1
        "#,
        ns_id,
    )
    .fetch_optional(pool)
    .await?;

    let (knot_score, threads_detected) = row
        .map(|r| (r.knot_score, r.threads_detected))
        .unwrap_or((0.0, 0));

    let recommended = if knot_score >= 0.8 {
        "separate_threads — review CoT session namespacing".into()
    } else if knot_score >= 0.5 {
        "monitor — consider isolating high-traffic reasoning threads".into()
    } else {
        "none".into()
    };

    tracing::debug!(
        namespace  = namespace,
        knot_score = knot_score,
        threads    = threads_detected,
        "Knot analysis"
    );

    Ok(KnotReport {
        namespace: namespace.to_owned(),
        knot_score,
        threads_detected,
        polluted_threads: 0,   // Phase 2
        knots: vec![],         // Phase 2
        recommended,
    })
}
