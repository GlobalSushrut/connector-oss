//! Entropy scoring engine.
//!
//! Computes a composite entropy score [0.0, 1.0] for a namespace by combining:
//!   1. Contradiction score  — from Connector's get_interference()
//!   2. Redundancy score     — near-duplicate ratio vs total packet count
//!   3. Stale score          — packets not accessed within stale_days
//!
//! Entropy thresholds from engram_namespaces drive actions:
//!   score < alert_threshold  → "good"
//!   score >= alert_threshold → "warning" + Prometheus alert
//!   score >= halt_threshold  → "halted"  + writes blocked via EntropyHalt error

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::metrics;

#[derive(Debug, Clone)]
pub struct EntropySnapshot {
    pub entropy_score:       f64,
    pub contradiction_count: i32,
    pub redundancy_count:    i32,
    pub stale_count:         i32,
    pub knot_score:          f64,
    pub threads_detected:    i32,
    pub health:              String,
    pub recommended_action:  String,
}

impl EntropySnapshot {
    pub fn health_label(score: f64, alert: f64, halt: f64) -> String {
        if score >= halt {
            "halted".into()
        } else if score >= alert {
            "warning".into()
        } else if score >= alert * 0.6 {
            "elevated".into()
        } else {
            "good".into()
        }
    }

    pub fn recommended_action(score: f64, alert: f64, halt: f64) -> String {
        if score >= halt {
            "halt_writes — run `engram consolidate` immediately".into()
        } else if score >= alert {
            "consolidate — run `engram consolidate --namespace <ns>`".into()
        } else {
            "none".into()
        }
    }
}

/// Compute a fresh entropy snapshot for a namespace.
/// Writes the result to `engram_entropy_snapshots` and updates Prometheus gauges.
pub async fn compute_and_store(
    pool:      &PgPool,
    connector: &ConnectorClient,
    ns_id:     Uuid,
    ns_path:   &str,
    alert_threshold: f64,
    halt_threshold:  f64,
    auto_consolidate: bool,
) -> Result<EntropySnapshot> {
    // ── 1. Contradiction score via Connector get_interference ─────────────────
    let interference = connector.get_interference(ns_path).await
        .unwrap_or_else(|e| {
            tracing::warn!(namespace = ns_path, error = %e, "get_interference failed — using 0");
            crate::connector::InterferenceResult { contradictions: vec![], count: 0 }
        });

    let contradiction_count = interference.count;
    // Each contradiction pair contributes +0.3, capped at 0.9
    let contradiction_component = (contradiction_count as f64 * 0.3_f64).min(0.9);

    // ── 2. Redundancy score — total packets from Connector stats ──────────────
    let total_packets = connector.count_namespace_packets(ns_path).await
        .unwrap_or(0);

    // Heuristic: assume ~10% redundancy base + contradiction inflation
    // In Phase 2 we will wire in a proper near-duplicate scan from the kernel.
    let redundancy_count = (total_packets as f64 * 0.05) as i32;
    let redundancy_component = if total_packets > 0 {
        (redundancy_count as f64 / total_packets as f64 * 0.4_f64).min(0.4)
    } else {
        0.0
    };

    // ── 3. Stale score — Connector does not expose this directly yet; ──────────
    //    we track writes via this plugin's own audit trail in Phase 2.
    //    For now, compute a conservative stale estimate from packet age.
    let stale_count = 0_i32; // placeholder until Phase 2 stale-tracking
    let stale_component = 0.0_f64;

    // ── 4. Composite entropy score ────────────────────────────────────────────
    let entropy_score = (contradiction_component
        + redundancy_component
        + stale_component)
        .min(1.0);

    // ── 5. Knot score — placeholder (Phase 2: thread tracker) ────────────────
    let knot_score       = 0.0_f64;
    let threads_detected = 0_i32;

    // ── 6. Persist snapshot ───────────────────────────────────────────────────
    let action_taken = determine_action(entropy_score, alert_threshold, halt_threshold, auto_consolidate);

    sqlx::query!(
        r#"
        INSERT INTO engram_entropy_snapshots
            (namespace_id, entropy_score, contradiction_count, redundancy_count,
             stale_count, knot_score, threads_detected, action_taken)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        ns_id,
        entropy_score,
        contradiction_count,
        redundancy_count,
        stale_count,
        knot_score,
        threads_detected,
        action_taken,
    )
    .execute(pool)
    .await?;

    // ── 7. Prometheus gauges ──────────────────────────────────────────────────
    metrics::set_entropy(ns_path, entropy_score);
    metrics::set_knot(ns_path, knot_score);

    let health = EntropySnapshot::health_label(entropy_score, alert_threshold, halt_threshold);
    let recommended_action = EntropySnapshot::recommended_action(entropy_score, alert_threshold, halt_threshold);

    tracing::info!(
        namespace  = ns_path,
        entropy    = entropy_score,
        health     = %health,
        contradictions = contradiction_count,
        "Entropy snapshot computed"
    );

    Ok(EntropySnapshot {
        entropy_score,
        contradiction_count,
        redundancy_count,
        stale_count,
        knot_score,
        threads_detected,
        health,
        recommended_action,
    })
}

/// Load the latest snapshot from DB (no Connector round-trip).
pub async fn latest_snapshot(
    pool:    &PgPool,
    ns_id:   Uuid,
    _ns_path: &str,
    alert_threshold: f64,
    halt_threshold:  f64,
) -> Result<Option<EntropySnapshot>> {
    let row = sqlx::query!(
        r#"
        SELECT entropy_score, contradiction_count, redundancy_count,
               stale_count, knot_score, threads_detected
        FROM engram_entropy_snapshots
        WHERE namespace_id = $1
        ORDER BY snapped_at DESC
        LIMIT 1
        "#,
        ns_id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| {
        let entropy_score = r.entropy_score;
        EntropySnapshot {
            entropy_score,
            contradiction_count: r.contradiction_count,
            redundancy_count:    r.redundancy_count,
            stale_count:         r.stale_count,
            knot_score:          r.knot_score,
            threads_detected:    r.threads_detected,
            health:              EntropySnapshot::health_label(entropy_score, alert_threshold, halt_threshold),
            recommended_action:  EntropySnapshot::recommended_action(entropy_score, alert_threshold, halt_threshold),
        }
    }))
}

/// Check if a namespace is halted (writes blocked). Fast path: only DB read.
pub async fn is_halted(pool: &PgPool, ns_path: &str) -> bool {
    let row = sqlx::query!(
        r#"
        SELECT n.entropy_halt, s.entropy_score
        FROM engram_namespaces n
        LEFT JOIN LATERAL (
            SELECT entropy_score FROM engram_entropy_snapshots
            WHERE namespace_id = n.id
            ORDER BY snapped_at DESC LIMIT 1
        ) s ON true
        WHERE n.path = $1
        "#,
        ns_path,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some(r) = row {
        let score: f64 = r.entropy_score.into();
        return score >= r.entropy_halt;
    }
    false
}

fn determine_action(score: f64, alert: f64, halt: f64, auto_consolidate: bool) -> String {
    if score >= halt {
        "halted".into()
    } else if score >= alert && auto_consolidate {
        "consolidated".into()
    } else if score >= alert {
        "alerted".into()
    } else {
        "none".into()
    }
}

/// Background sweep: recompute entropy for all namespaces.
pub async fn background_sweep(pool: PgPool, connector: ConnectorClient) {
    let rows = sqlx::query!(
        r#"
        SELECT id, path, entropy_alert, entropy_halt, auto_consolidate
        FROM engram_namespaces
        "#
    )
    .fetch_all(&pool)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Entropy sweep: failed to list namespaces");
            return;
        }
    };

    for ns in rows {
        if let Err(e) = compute_and_store(
            &pool,
            &connector,
            ns.id,
            &ns.path,
            ns.entropy_alert,
            ns.entropy_halt,
            ns.auto_consolidate,
        ).await {
            tracing::error!(namespace = %ns.path, error = %e, "Entropy sweep failed for namespace");
        }
    }

    tracing::info!("Entropy sweep complete");
}
