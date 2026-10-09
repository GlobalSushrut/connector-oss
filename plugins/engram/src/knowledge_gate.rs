//! Knowledge Gate — cross-agent knowledge sharing with UCAN permission gates.
//!
//! Manages `engram_knowledge_shares` rows and enforces permission checks
//! when agents query the /k/ namespace across namespaces.

use anyhow::Result;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::error::AppError;
use crate::types::{CreateShareRequest, ShareRow};

/// Create a new knowledge share and attempt UCAN capability delegation
/// via the Connector kernel's capabilities API.
pub async fn create_share(
    pool:      &PgPool,
    connector: &ConnectorClient,
    req:       &CreateShareRequest,
) -> Result<ShareRow, AppError> {
    // Validate permission value
    if req.permission != "read_only" && req.permission != "read_write" {
        return Err(AppError::Validation(
            "permission must be 'read_only' or 'read_write'".into(),
        ));
    }

    // Attempt UCAN delegation from Connector (non-fatal if kernel unavailable)
    let ucan_cid = connector.write_audit(
        "knowledge_share_created",
        &req.source_ns,
        &req.shared_path,
        json!({
            "source_ns":      req.source_ns,
            "target_pattern": req.target_pattern,
            "shared_path":    req.shared_path,
            "permission":     req.permission,
        }),
    ).await.ok();

    let row = sqlx::query!(
        r#"
        INSERT INTO engram_knowledge_shares
            (source_ns, target_pattern, shared_path, permission, ucan_cid)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, source_ns, target_pattern, shared_path, permission, ucan_cid, active, created_at
        "#,
        req.source_ns,
        req.target_pattern,
        req.shared_path,
        req.permission,
        ucan_cid.filter(|s| !s.is_empty()),
    )
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(ShareRow {
        id:             row.id,
        source_ns:      row.source_ns,
        target_pattern: row.target_pattern,
        shared_path:    row.shared_path,
        permission:     row.permission,
        ucan_cid:       row.ucan_cid,
        active:         row.active,
        created_at:     row.created_at,
    })
}

/// Check whether `requester_ns` has read access to `shared_path` from `source_ns`.
pub async fn check_access(
    pool:         &PgPool,
    requester_ns: &str,
    source_ns:    &str,
    shared_path:  &str,
) -> Result<bool> {
    // Match exact target or wildcard pattern "org/*"
    let row = sqlx::query!(
        r#"
        SELECT id FROM engram_knowledge_shares
        WHERE source_ns   = $1
          AND shared_path = $2
          AND active      = true
          AND (
              target_pattern = $3
              OR target_pattern = (split_part($3, '/', 1) || '/*')
          )
        LIMIT 1
        "#,
        source_ns,
        shared_path,
        requester_ns,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

/// List all active knowledge shares.
pub async fn list_shares(pool: &PgPool) -> Result<Vec<ShareRow>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, source_ns, target_pattern, shared_path, permission, ucan_cid, active, created_at
        FROM engram_knowledge_shares
        WHERE active = true
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| ShareRow {
        id:             r.id,
        source_ns:      r.source_ns,
        target_pattern: r.target_pattern,
        shared_path:    r.shared_path,
        permission:     r.permission,
        ucan_cid:       r.ucan_cid,
        active:         r.active,
        created_at:     r.created_at,
    }).collect())
}

/// Revoke a share (soft-delete by setting active=false).
pub async fn revoke_share(pool: &PgPool, share_id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query!(
        "UPDATE engram_knowledge_shares SET active = false WHERE id = $1",
        share_id,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Share {share_id} not found")));
    }
    Ok(())
}
