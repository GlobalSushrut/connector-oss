//! Federation — cross-org agent trust mesh.
//!
//! Register a peer AgentPassport instance, sync their agents,
//! and apply local trust overrides or filters.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::agents::append_audit;
use crate::types::{FederationPeerRow, RegisterFederationPeerRequest};

// ── Register peer ──────────────────────────────────────────────────────────────

pub async fn register_peer(
    pool: &PgPool,
    org_id: Uuid,
    req: &RegisterFederationPeerRequest,
    actor: &str,
) -> Result<FederationPeerRow> {
    let row = sqlx::query(
        "INSERT INTO ap_federation_peers
            (org_id, peer_name, peer_url, peer_public_key,
             trust_scope, min_trust_score, auto_trust, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending')
         RETURNING *"
    )
    .bind(org_id)
    .bind(&req.peer_name)
    .bind(&req.peer_url)
    .bind(&req.peer_public_key)
    .bind(req.trust_scope.clone().unwrap_or(json!({})))
    .bind(req.min_trust_score.unwrap_or(0.7))
    .bind(req.auto_trust.unwrap_or(false))
    .fetch_one(pool).await.context("insert federation peer")?;

    append_audit(pool, org_id, "federation", &row.try_get::<Uuid, _>("id")
        .map(|u| u.to_string()).unwrap_or_default(),
        "peer_registered", Some(actor), None,
        json!({ "peer_name": req.peer_name, "peer_url": req.peer_url }),
        None).await;

    Ok(row_to_peer(&row))
}

// ── List peers ─────────────────────────────────────────────────────────────────

pub async fn list_peers(pool: &PgPool, org_id: Uuid) -> Result<Vec<FederationPeerRow>> {
    let rows = sqlx::query(
        "SELECT * FROM ap_federation_peers WHERE org_id=$1 ORDER BY created_at DESC"
    ).bind(org_id).fetch_all(pool).await.context("list peers")?;
    Ok(rows.iter().map(row_to_peer).collect())
}

// ── Sync agents from peer ──────────────────────────────────────────────────────
//
// Calls the peer's GET /api/v1/agents endpoint (or a passport export),
// filters by the local trust policy, and upserts into ap_federated_agents.

pub async fn sync_peer(
    pool: &PgPool,
    org_id: Uuid,
    peer_id: Uuid,
    http: &reqwest::Client,
    actor: &str,
) -> Result<usize> {
    let peer = sqlx::query(
        "SELECT peer_url, peer_public_key, min_trust_score, auto_trust
         FROM ap_federation_peers WHERE id=$1 AND org_id=$2 AND status='active'"
    ).bind(peer_id).bind(org_id).fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Peer not found or inactive"))?;

    let peer_url:         String  = peer.try_get("peer_url")?;
    let min_trust_score:  f64     = peer.try_get("min_trust_score").unwrap_or(0.7);

    // Call peer's public agent list endpoint
    let list_url = format!("{}/api/v1/agents/export", peer_url);
    let resp = http.get(&list_url)
        .send().await.context("call peer export endpoint")?;

    if !resp.status().is_success() {
        anyhow::bail!("Peer returned {}", resp.status());
    }

    let body: Value = resp.json().await.context("parse peer response")?;
    let agents = body.get("agents")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();

    let mut imported = 0usize;
    for agent in &agents {
        let remote_did = match agent.get("did").and_then(|d| d.as_str()) {
            Some(d) => d,
            None    => continue,
        };
        let remote_name  = agent.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
        let remote_score = agent.get("trust_score").and_then(|s| s.as_f64()).unwrap_or(0.0);

        if remote_score < min_trust_score { continue; }

        sqlx::query(
            "INSERT INTO ap_federated_agents
                (org_id, peer_id, remote_did, remote_name, remote_passport, last_refresh_at)
             VALUES ($1,$2,$3,$4,$5,NOW())
             ON CONFLICT (org_id, remote_did) DO UPDATE
             SET remote_name=$4, remote_passport=$5, last_refresh_at=NOW()"
        )
        .bind(org_id).bind(peer_id)
        .bind(remote_did).bind(remote_name)
        .bind(agent)
        .execute(pool).await.ok();

        imported += 1;
    }

    // Update peer sync timestamp and agent count
    sqlx::query(
        "UPDATE ap_federation_peers
         SET last_sync_at=NOW(), agent_count=$1, status='active'
         WHERE id=$2"
    ).bind(imported as i32).bind(peer_id).execute(pool).await.ok();

    append_audit(pool, org_id, "federation", &peer_id.to_string(),
        "peer_synced", Some(actor), None,
        json!({ "imported": imported }), None).await;

    Ok(imported)
}

// ── Row mapper ─────────────────────────────────────────────────────────────────

fn row_to_peer(row: &sqlx::postgres::PgRow) -> FederationPeerRow {
    FederationPeerRow {
        id:              row.try_get("id").unwrap_or_default(),
        org_id:          row.try_get("org_id").unwrap_or_default(),
        peer_name:       row.try_get("peer_name").unwrap_or_default(),
        peer_url:        row.try_get("peer_url").unwrap_or_default(),
        peer_public_key: row.try_get("peer_public_key").ok().flatten(),
        trust_scope:     row.try_get("trust_scope").unwrap_or(json!({})),
        min_trust_score: row.try_get("min_trust_score").unwrap_or(0.7),
        auto_trust:      row.try_get("auto_trust").unwrap_or(false),
        status:          row.try_get("status").unwrap_or_default(),
        last_sync_at:    row.try_get("last_sync_at").ok().flatten(),
        agent_count:     row.try_get("agent_count").unwrap_or(0),
        created_at:      row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}
