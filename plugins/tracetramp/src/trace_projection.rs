//! Shared read models for **`trace_events`** — used by data-plane `/decision/:trace_id`,
//! enforcement packet, compliance-oriented exports, and admin `/traces/...` so projections stay
//! consistent (Section 10.2 military compliance plan).

use sqlx::PgPool;

use crate::error::AppError;

/// Ordered **`metadata.decision.action_trace`** entries concatenated for every checkpoint in the trace.
/// Each `record_event` stores a single-step envelope; this is the joined “filmstrip” for SIEM / PDF.
pub async fn cumulative_action_trace_entries(
    pool: &PgPool,
    trace_id: &str,
) -> Result<Vec<serde_json::Value>, AppError> {
    let rows = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT metadata FROM trace_events WHERE trace_id = $1 ORDER BY created_at ASC",
    )
    .bind(trace_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut out = Vec::new();
    for meta in rows {
        if let Some(decision) = meta.get("decision") {
            if let Some(arr) = decision.get("action_trace").and_then(|x| x.as_array()) {
                for entry in arr {
                    out.push(entry.clone());
                }
            }
        }
    }
    Ok(out)
}

/// Union of **`block_flags`** from each `metadata.decision` along the trace (stable dedup, sorted).
pub async fn cumulative_block_flags(pool: &PgPool, trace_id: &str) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT metadata FROM trace_events WHERE trace_id = $1 ORDER BY created_at ASC",
    )
    .bind(trace_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut set = std::collections::BTreeSet::<String>::new();
    for meta in rows {
        if let Some(decision) = meta.get("decision") {
            if let Some(flags) = decision.get("block_flags").and_then(|x| x.as_array()) {
                for f in flags {
                    if let Some(s) = f.as_str() {
                        set.insert(s.to_string());
                    }
                }
            }
        }
    }
    Ok(set.into_iter().collect())
}
