//! All 16 Engram HTTP route handlers.
//!
//! Route table:
//!   POST   /api/v1/namespaces                — create namespace
//!   GET    /api/v1/namespaces                — list namespaces + entropy health
//!   GET    /api/v1/namespaces/:path          — namespace detail + live entropy
//!   PUT    /api/v1/namespaces/:path          — update config
//!   POST   /api/v1/memory                   — write a memory fact
//!   POST   /api/v1/memory/recall             — hybrid recall
//!   POST   /api/v1/memory/search             — EQL query (Phase 2 full parser)
//!   POST   /api/v1/memory/ground             — dehallucination check
//!   GET    /api/v1/memory/health/:path       — entropy + knot score
//!   POST   /api/v1/memory/consolidate        — trigger entropy consolidation
//!   POST   /api/v1/cot/session               — start CoT anchor session
//!   POST   /api/v1/cot/session/:id/step      — submit step for grounding
//!   POST   /api/v1/cot/session/:id/conclude  — conclude + get proof bundle
//!   GET    /api/v1/cot/session/:id           — session status + step outcomes
//!   POST   /api/v1/knowledge/share           — create cross-agent knowledge share
//!   GET    /health                           — liveness + readiness

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use validator::Validate;

use crate::cot_anchor;
use crate::dehallucination::{self, GroundingConfig, OnFail};
use crate::entropy;
use crate::error::AppError;
use crate::knowledge_gate;
use crate::metrics;
use crate::state::AppState;
use crate::types::*;

// ── Namespace handlers ────────────────────────────────────────────────────────

pub async fn create_namespace(
    State(s): State<AppState>,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<NamespaceRow>), AppError> {
    req.validate()?;

    let row = sqlx::query!(
        r#"
        INSERT INTO engram_namespaces
            (path, team, retention_days, entropy_alert, entropy_halt,
             hipaa, auto_consolidate, stale_days)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, path, team, retention_days, entropy_alert, entropy_halt,
                  hipaa, auto_consolidate, stale_days, created_at, updated_at
        "#,
        req.path,
        req.team,
        req.retention_days,
        req.entropy_alert,
        req.entropy_halt,
        req.hipaa,
        req.auto_consolidate,
        req.stale_days,
    )
    .fetch_one(&s.pool)
    .await
    .map_err(AppError::Database)?;

    tracing::info!(namespace = %row.path, "Namespace created");

    Ok((StatusCode::CREATED, Json(NamespaceRow {
        id:               row.id,
        path:             row.path,
        team:             row.team,
        retention_days:   row.retention_days,
        entropy_alert:    row.entropy_alert,
        entropy_halt:     row.entropy_halt,
        hipaa:            row.hipaa,
        auto_consolidate: row.auto_consolidate,
        stale_days:       row.stale_days,
        created_at:       row.created_at,
        updated_at:       row.updated_at,
        latest_entropy:   None,
        latest_knot:      None,
        entropy_health:   "good".into(),
    })))
}

pub async fn list_namespaces(
    State(s): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT n.id, n.path, n.team, n.retention_days, n.entropy_alert, n.entropy_halt,
               n.hipaa, n.auto_consolidate, n.stale_days, n.created_at, n.updated_at,
               COALESCE(s.entropy_score, 0.0) AS entropy_score,
               COALESCE(s.knot_score, 0.0) AS knot_score
        FROM engram_namespaces n
        LEFT JOIN LATERAL (
            SELECT entropy_score, knot_score
            FROM engram_entropy_snapshots
            WHERE namespace_id = n.id
            ORDER BY snapped_at DESC LIMIT 1
        ) s ON true
        ORDER BY n.created_at DESC
        "#,
    )
    .fetch_all(&s.pool)
    .await
    .map_err(AppError::Database)?;

    let total = rows.len();
    let namespaces: Vec<Value> = rows.into_iter().map(|r| {
        let entropy = r.entropy_score.unwrap_or(0.0);
        let health  = entropy_health_label(entropy, r.entropy_alert, r.entropy_halt);
        json!({
            "id":               r.id,
            "path":             r.path,
            "team":             r.team,
            "retention_days":   r.retention_days,
            "entropy_alert":    r.entropy_alert,
            "entropy_halt":     r.entropy_halt,
            "hipaa":            r.hipaa,
            "auto_consolidate": r.auto_consolidate,
            "stale_days":       r.stale_days,
            "created_at":       r.created_at,
            "updated_at":       r.updated_at,
            "latest_entropy":   r.entropy_score,
            "latest_knot":      r.knot_score,
            "entropy_health":   health,
        })
    }).collect();

    Ok(Json(json!({ "namespaces": namespaces, "total": total })))
}

pub async fn get_namespace(
    State(s): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<Value>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT n.id, n.path, n.team, n.retention_days, n.entropy_alert, n.entropy_halt,
               n.hipaa, n.auto_consolidate, n.stale_days, n.created_at, n.updated_at,
               COALESCE(s.entropy_score, 0.0) AS entropy_score,
               COALESCE(s.knot_score, 0.0) AS knot_score,
               COALESCE(s.contradiction_count, 0) AS contradiction_count,
               COALESCE(s.redundancy_count, 0) AS redundancy_count,
               COALESCE(s.stale_count, 0) AS stale_count,
               COALESCE(s.threads_detected, 0) AS threads_detected,
               s.snapped_at
        FROM engram_namespaces n
        LEFT JOIN LATERAL (
            SELECT entropy_score, knot_score, contradiction_count,
                   redundancy_count, stale_count, threads_detected, snapped_at
            FROM engram_entropy_snapshots
            WHERE namespace_id = n.id
            ORDER BY snapped_at DESC LIMIT 1
        ) s ON true
        WHERE n.path = $1
        "#,
        path,
    )
    .fetch_optional(&s.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("Namespace '{path}' not found")))?;

    let entropy = row.entropy_score.unwrap_or(0.0);
    let health  = entropy_health_label(entropy, row.entropy_alert, row.entropy_halt);

    Ok(Json(json!({
        "id":                 row.id,
        "path":               row.path,
        "team":               row.team,
        "retention_days":     row.retention_days,
        "entropy_alert":      row.entropy_alert,
        "entropy_halt":       row.entropy_halt,
        "hipaa":              row.hipaa,
        "auto_consolidate":   row.auto_consolidate,
        "stale_days":         row.stale_days,
        "created_at":         row.created_at,
        "updated_at":         row.updated_at,
        "entropy_score":      row.entropy_score,
        "knot_score":         row.knot_score,
        "contradiction_count": row.contradiction_count,
        "redundancy_count":   row.redundancy_count,
        "stale_count":        row.stale_count,
        "threads_detected":   row.threads_detected,
        "entropy_health":     health,
        "last_snapshot":      row.snapped_at,
    })))
}

pub async fn update_namespace(
    State(s): State<AppState>,
    Path(path): Path<String>,
    Json(req): Json<UpdateNamespaceRequest>,
) -> Result<Json<Value>, AppError> {
    let result = sqlx::query!(
        r#"
        UPDATE engram_namespaces
        SET team             = COALESCE($1, team),
            retention_days   = COALESCE($2, retention_days),
            entropy_alert    = COALESCE($3, entropy_alert),
            entropy_halt     = COALESCE($4, entropy_halt),
            auto_consolidate = COALESCE($5, auto_consolidate),
            stale_days       = COALESCE($6, stale_days),
            updated_at       = NOW()
        WHERE path = $7
        "#,
        req.team,
        req.retention_days,
        req.entropy_alert,
        req.entropy_halt,
        req.auto_consolidate,
        req.stale_days,
        path,
    )
    .execute(&s.pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Namespace '{path}' not found")));
    }

    Ok(Json(json!({ "ok": true, "namespace": path })))
}

// ── Memory handlers ───────────────────────────────────────────────────────────

pub async fn write_memory(
    State(s): State<AppState>,
    Json(req): Json<MemWriteRequest>,
) -> Result<(StatusCode, Json<MemWriteResponse>), AppError> {
    req.validate()?;

    // Look up namespace
    let ns = namespace_by_path(&s, &s.engram_url.namespace).await?;

    // Entropy halt check — block writes if namespace is halted
    if entropy::is_halted(&s.pool, &ns.path).await {
        return Err(AppError::EntropyHalt(format!(
            "Namespace '{}' writes are halted — entropy ceiling reached. Run `engram consolidate`.",
            ns.path
        )));
    }

    let agent_id   = req.agent_id.as_deref().unwrap_or("engram-default");
    let tags       = req.tags.clone().unwrap_or_default();
    let entity_kind = req.entity_kind.as_deref();
    let session_id  = req.session_id.as_deref();

    let write_resp = s.connector.write_memory(
        agent_id,
        &ns.path,
        &req.content,
        &req.memory_type,
        &tags,
        entity_kind,
        session_id,
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    metrics::record_write(&ns.path, &req.memory_type);

    // Async entropy refresh (non-blocking)
    {
        let pool      = s.pool.clone();
        let connector = s.connector.clone();
        let ns_id     = ns.id;
        let ns_path   = ns.path.clone();
        let alert     = ns.entropy_alert;
        let halt      = ns.entropy_halt;
        let auto_con  = ns.auto_consolidate;
        tokio::spawn(async move {
            let _ = entropy::compute_and_store(
                &pool, &connector, ns_id, &ns_path, alert, halt, auto_con,
            ).await;
        });
    }

    // Read latest entropy score for response
    let snapshot = entropy::latest_snapshot(
        &s.pool, ns.id, &ns.path, ns.entropy_alert, ns.entropy_halt,
    ).await.ok().flatten();

    let entropy_score  = snapshot.as_ref().map(|s| s.entropy_score).unwrap_or(0.0);
    let entropy_health = snapshot.as_ref().map(|s| s.health.clone()).unwrap_or_else(|| "good".into());

    Ok((StatusCode::CREATED, Json(MemWriteResponse {
        cid: write_resp.cid,
        namespace: ns.path,
        entropy_score,
        entropy_health,
        ok: true,
    })))
}

pub async fn recall_memory(
    State(s): State<AppState>,
    Json(req): Json<MemRecallRequest>,
) -> Result<Json<MemRecallResponse>, AppError> {
    req.validate()?;

    let ns = namespace_by_path(&s, &s.engram_url.namespace).await?;

    let recall = s.connector.recall_memory(
        &ns.path,
        &req.query,
        req.top_k,
        req.memory_type.as_deref(),
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    metrics::record_recall(&ns.path);

    let sources: Vec<String> = recall.packets.iter().map(|p| p.cid.clone()).collect();

    let facts = recall.packets.into_iter().map(|p| MemFact {
        cid:         p.cid,
        content:     p.content,
        memory_type: p.memory_type,
        tags:        p.tags,
        score:       p.score.unwrap_or(0.0),
        created_at:  Utc::now(),
    }).collect();

    let snapshot = entropy::latest_snapshot(
        &s.pool, ns.id, &ns.path, ns.entropy_alert, ns.entropy_halt,
    ).await.ok().flatten();
    let entropy_health = snapshot.map(|s| s.health).unwrap_or_else(|| "good".into());

    Ok(Json(MemRecallResponse {
        facts,
        entropy_health,
        namespace: ns.path,
        sources,
    }))
}

pub async fn search_memory(
    State(s): State<AppState>,
    Json(req): Json<EqlSearchRequest>,
) -> Result<Json<EqlSearchResponse>, AppError> {
    req.validate()?;

    // Phase 1: forward query to Connector recall with raw query as natural language
    // Phase 2: full EQL parser + compiler
    let ns = namespace_by_path(&s, &s.engram_url.namespace).await?;
    let limit  = req.limit;
    let offset = req.offset.unwrap_or(0);

    let recall = s.connector.recall_memory(
        &ns.path,
        &req.query,
        limit,
        None,
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    let total   = recall.packets.len() as i64;
    let results = recall.packets.into_iter().map(|p| json!({
        "cid":         p.cid,
        "content":     p.content,
        "memory_type": p.memory_type,
        "tags":        p.tags,
        "score":       p.score,
        "namespace":   p.namespace,
    })).collect();

    Ok(Json(EqlSearchResponse { results, total, limit, offset }))
}

pub async fn ground_memory(
    State(s): State<AppState>,
    Json(req): Json<GroundRequest>,
) -> Result<Json<GroundResponse>, AppError> {
    let config = GroundingConfig {
        threshold: req.threshold,
        on_fail:   OnFail::from_str(&req.on_fail),
    };

    let (results, chain_cid) = dehallucination::ground_claims(
        &s.connector,
        &req.namespace,
        &req.claims,
        &config,
        "engram-api",
    ).await.map_err(|e| AppError::Connector(e.to_string()))?;

    let all_grounded = results.iter().all(|r| r.grounded);

    Ok(Json(GroundResponse {
        results,
        all_grounded,
        proof_cid: chain_cid,
    }))
}

pub async fn memory_health(
    State(s): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<EntropyHealthResponse>, AppError> {
    let ns = namespace_by_path(&s, &path).await?;

    let snapshot = entropy::latest_snapshot(
        &s.pool, ns.id, &ns.path, ns.entropy_alert, ns.entropy_halt,
    ).await.map_err(|e| AppError::Internal(e))?;

    let snap = snapshot.unwrap_or_else(|| entropy::EntropySnapshot {
        entropy_score:       0.0,
        contradiction_count: 0,
        redundancy_count:    0,
        stale_count:         0,
        knot_score:          0.0,
        threads_detected:    0,
        health:              "good".into(),
        recommended_action:  "none".into(),
    });

    Ok(Json(EntropyHealthResponse {
        namespace:           ns.path,
        entropy_score:       snap.entropy_score,
        knot_score:          snap.knot_score,
        contradiction_count: snap.contradiction_count,
        redundancy_count:    snap.redundancy_count,
        stale_count:         snap.stale_count,
        threads_detected:    snap.threads_detected,
        health:              snap.health,
        recommended_action:  snap.recommended_action,
        snapped_at:          None,
    }))
}

pub async fn consolidate_memory(
    State(s): State<AppState>,
    Json(req): Json<ConsolidateRequest>,
) -> Result<Json<ConsolidateResponse>, AppError> {
    let ns = namespace_by_path(&s, &req.namespace).await?;
    let dry_run = req.dry_run.unwrap_or(false);

    let snapshot_before = entropy::latest_snapshot(
        &s.pool, ns.id, &ns.path, ns.entropy_alert, ns.entropy_halt,
    ).await.ok().flatten();
    let before_entropy = snapshot_before.as_ref().map(|s| s.entropy_score).unwrap_or(0.0);

    let (merged, expired, flagged) = if dry_run {
        (0, 0, 0)
    } else {
        // Trigger fresh entropy compute (this is the consolidation in Phase 1)
        entropy::compute_and_store(
            &s.pool, &s.connector, ns.id, &ns.path,
            ns.entropy_alert, ns.entropy_halt, ns.auto_consolidate,
        ).await.map_err(|e| AppError::Connector(e.to_string()))?;

        // Record consolidation audit entry
        sqlx::query!(
            r#"
            INSERT INTO engram_consolidations
                (namespace_id, merged_count, expired_count, flagged_count,
                 before_entropy, initiated_by, completed_at)
            VALUES ($1, 0, 0, 0, $2, 'api', NOW())
            "#,
            ns.id,
            before_entropy,
        )
        .execute(&s.pool)
        .await
        .map_err(AppError::Database)?;

        metrics::record_consolidation(&ns.path, "api");
        (0_i32, 0_i32, 0_i32)
    };

    let after_snap = if !dry_run {
        entropy::latest_snapshot(
            &s.pool, ns.id, &ns.path, ns.entropy_alert, ns.entropy_halt,
        ).await.ok().flatten()
    } else {
        None
    };

    Ok(Json(ConsolidateResponse {
        namespace: ns.path,
        merged_count: merged,
        expired_count: expired,
        flagged_count: flagged,
        before_entropy,
        after_entropy: after_snap.map(|s| s.entropy_score),
        dry_run,
    }))
}

// ── CoT Anchor handlers ───────────────────────────────────────────────────────

pub async fn create_cot_session(
    State(s): State<AppState>,
    Json(req): Json<CreateCotSessionRequest>,
) -> Result<(StatusCode, Json<CotSessionResponse>), AppError> {
    req.validate()?;

    let ns = namespace_by_path(&s, &req.namespace).await?;

    let row = sqlx::query!(
        r#"
        INSERT INTO engram_cot_sessions
            (session_name, namespace_id, agent_id, threshold, on_fail)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, session_name, agent_id, threshold, on_fail, status,
                  step_count, passed_count, failed_count, started_at, concluded_at, proof_cid
        "#,
        req.session_name,
        ns.id,
        req.agent_id,
        req.threshold,
        req.on_fail,
    )
    .fetch_one(&s.pool)
    .await
    .map_err(AppError::Database)?;

    tracing::info!(
        session_id = %row.id,
        namespace  = %ns.path,
        agent_id   = %row.agent_id,
        "CoT session started"
    );

    Ok((StatusCode::CREATED, Json(CotSessionResponse {
        id:           row.id,
        session_name: row.session_name,
        namespace:    ns.path,
        agent_id:     row.agent_id,
        threshold:    row.threshold,
        on_fail:      row.on_fail,
        status:       row.status,
        step_count:   row.step_count,
        passed_count: row.passed_count,
        failed_count: row.failed_count,
        started_at:   row.started_at,
        concluded_at: row.concluded_at,
        proof_cid:    row.proof_cid,
    })))
}

pub async fn cot_step(
    State(s): State<AppState>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<CotStepRequest>,
) -> Result<Json<CotStepResponse>, AppError> {
    req.validate()?;
    let resp = cot_anchor::submit_step(&s.pool, &s.connector, session_id, &req.claim_text).await?;
    Ok(Json(resp))
}

pub async fn cot_conclude(
    State(s): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<CotConcludeResponse>, AppError> {
    let resp = cot_anchor::conclude_session(&s.pool, &s.connector, session_id).await?;
    Ok(Json(resp))
}

pub async fn get_cot_session(
    State(s): State<AppState>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<CotSessionResponse>, AppError> {
    let session = cot_anchor::load_session(&s.pool, session_id).await?;
    Ok(Json(session.into()))
}

// ── Knowledge sharing handlers ────────────────────────────────────────────────

pub async fn create_knowledge_share(
    State(s): State<AppState>,
    Json(req): Json<CreateShareRequest>,
) -> Result<(StatusCode, Json<ShareRow>), AppError> {
    req.validate()?;
    let share = knowledge_gate::create_share(&s.pool, &s.connector, &req).await?;
    Ok((StatusCode::CREATED, Json(share)))
}

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health(State(s): State<AppState>) -> Json<HealthResponse> {
    let db_status = sqlx::query("SELECT 1").execute(&s.pool).await
        .map(|_| "ok".to_owned())
        .unwrap_or_else(|e| format!("error: {e}"));

    let connector_status = s.connector.health().await
        .map(|h| h.status)
        .unwrap_or_else(|_| "unreachable".into());

    Json(HealthResponse {
        status:    if db_status == "ok" { "ok".into() } else { "degraded".into() },
        version:   env!("CARGO_PKG_VERSION").into(),
        db:        db_status,
        connector: connector_status,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct NsRow {
    id:               Uuid,
    path:             String,
    entropy_alert:    f64,
    entropy_halt:     f64,
    auto_consolidate: bool,
}

async fn namespace_by_path(s: &AppState, path: &str) -> Result<NsRow, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT id, path, entropy_alert, entropy_halt, auto_consolidate
        FROM engram_namespaces
        WHERE path = $1
        "#,
        path,
    )
    .fetch_optional(&s.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("Namespace '{path}' not found — run `engram ns create`")))?;

    Ok(NsRow {
        id:               row.id,
        path:             row.path,
        entropy_alert:    row.entropy_alert,
        entropy_halt:     row.entropy_halt,
        auto_consolidate: row.auto_consolidate,
    })
}

fn entropy_health_label(score: f64, alert: f64, halt: f64) -> String {
    if score >= halt {
        "halted".into()
    } else if score >= alert {
        "warning".into()
    } else {
        "good".into()
    }
}
