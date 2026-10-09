//! Agent registration, directory, lifecycle, and revocation.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::crypto;
use crate::types::{AgentRow, Pagination, RegisterAgentRequest};

// ── Register ───────────────────────────────────────────────────────────────────

pub struct RegisterResult {
    pub agent:          AgentRow,
    pub approval_token: String,
}

pub async fn register_agent(
    pool: &PgPool,
    org_id: Uuid,
    req: &RegisterAgentRequest,
    signing_key_hex: &str,
) -> Result<RegisterResult> {
    let agent_id  = Uuid::new_v4();
    let did       = crypto::mint_agent_did(&agent_id);
    let user_did  = crypto::mint_user_did(&req.sponsor_email);
    let keypair   = crypto::AgentKeypair::generate();

    // Approval token: random UUID, expires in 48h
    let approval_token     = Uuid::new_v4().to_string().replace('-', "");
    let approval_token_exp = Utc::now() + chrono::Duration::hours(48);

    // Liability signature: sign with the instance key linking agent DID → sponsor
    let sk = crypto::signing_key_from_hex(signing_key_hex)
        .context("load signing key")?;
    let liability_sig = crypto::sign_liability(&sk, &did, &user_did);

    // Insert agent
    let agent_row = sqlx::query(
        "INSERT INTO ap_agents
            (id, org_id, did, name, version, description, agent_card,
             status, trust_score, public_key_ed25519, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',1.0,$8,$9)
         RETURNING *"
    )
    .bind(agent_id)
    .bind(org_id)
    .bind(&did)
    .bind(&req.name)
    .bind(req.version.as_deref().unwrap_or("1.0"))
    .bind(&req.description)
    .bind(req.agent_card.clone().unwrap_or(json!({})))
    .bind(&keypair.public_key_hex)
    .bind(req.metadata.clone().unwrap_or(json!({})))
    .fetch_one(pool).await.context("insert agent")?;

    let agent = row_to_agent(&agent_row);

    // Insert sponsor (pending until approval)
    let tax_id_hash: Option<String> = None;
    sqlx::query(
        "INSERT INTO ap_sponsors
            (agent_id, org_id, user_did, user_email, display_name,
             legal_entity, jurisdiction, tax_id_hash, liability_sig,
             approval_token, approval_token_exp, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')"
    )
    .bind(agent_id)
    .bind(org_id)
    .bind(&user_did)
    .bind(&req.sponsor_email)
    .bind(&req.sponsor_display_name)
    .bind(&req.sponsor_legal_entity)
    .bind(&req.sponsor_jurisdiction)
    .bind(&tax_id_hash)
    .bind(&liability_sig)
    .bind(&approval_token)
    .bind(approval_token_exp)
    .execute(pool).await.context("insert sponsor")?;

    // Audit log
    append_audit(pool, org_id, "agent", &did, "registered",
        Some(&user_did), None, json!({ "name": req.name }), None).await;

    Ok(RegisterResult { agent, approval_token })
}

// ── Sponsor approval ───────────────────────────────────────────────────────────

pub async fn approve_sponsorship(pool: &PgPool, token: &str) -> Result<()> {
    let row = sqlx::query(
        "SELECT s.id, s.agent_id, s.org_id, s.user_did FROM ap_sponsors s
         WHERE s.approval_token = $1
           AND s.status = 'pending'
           AND s.approval_token_exp > NOW()"
    ).bind(token).fetch_one(pool).await
        .map_err(|_| anyhow::anyhow!("Invalid or expired approval token"))?;

    let sponsor_id: Uuid = row.try_get("id")?;
    let agent_id:   Uuid = row.try_get("agent_id")?;
    let org_id:     Uuid = row.try_get("org_id")?;
    let user_did:   String = row.try_get("user_did")?;

    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(365);

    // Activate sponsor
    sqlx::query(
        "UPDATE ap_sponsors
         SET status='active', verified_at=$1, expires_at=$2,
             approval_token=NULL, approval_token_exp=NULL
         WHERE id=$3"
    ).bind(now).bind(expires_at).bind(sponsor_id)
     .execute(pool).await.context("activate sponsor")?;

    // Activate agent
    sqlx::query(
        "UPDATE ap_agents SET status='active', activated_at=$1 WHERE id=$2"
    ).bind(now).bind(agent_id)
     .execute(pool).await.context("activate agent")?;

    // Audit
    let did: String = sqlx::query_scalar("SELECT did FROM ap_agents WHERE id=$1")
        .bind(agent_id).fetch_one(pool).await.unwrap_or_default();
    append_audit(pool, org_id, "agent", &did, "activated",
        Some(&user_did), None, json!({ "sponsor": user_did }), None).await;

    Ok(())
}

// ── List agents ────────────────────────────────────────────────────────────────

pub async fn list_agents(pool: &PgPool, org_id: Uuid, pg: &Pagination) -> Result<Vec<AgentRow>> {
    let rows = if let Some(status) = &pg.status {
        sqlx::query(
            "SELECT * FROM ap_agents WHERE org_id=$1 AND status=$2
             ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        )
        .bind(org_id).bind(status).bind(pg.limit()).bind(pg.offset())
        .fetch_all(pool).await
    } else {
        sqlx::query(
            "SELECT * FROM ap_agents WHERE org_id=$1
             ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(org_id).bind(pg.limit()).bind(pg.offset())
        .fetch_all(pool).await
    }.context("list agents")?;

    Ok(rows.iter().map(row_to_agent).collect())
}

// ── Get agent by DID ───────────────────────────────────────────────────────────

pub async fn get_agent_by_did(pool: &PgPool, did: &str) -> Result<AgentRow> {
    let row = sqlx::query("SELECT * FROM ap_agents WHERE did=$1")
        .bind(did).fetch_one(pool).await
        .map_err(|_| anyhow::anyhow!("Agent not found: {}", did))?;
    Ok(row_to_agent(&row))
}

pub async fn get_agent_by_id(pool: &PgPool, id: Uuid) -> Result<AgentRow> {
    let row = sqlx::query("SELECT * FROM ap_agents WHERE id=$1")
        .bind(id).fetch_one(pool).await
        .map_err(|_| anyhow::anyhow!("Agent not found"))?;
    Ok(row_to_agent(&row))
}

// ── Revoke agent ───────────────────────────────────────────────────────────────

pub async fn revoke_agent(
    pool: &PgPool,
    org_id: Uuid,
    did: &str,
    reason: &str,
    revoked_by: &str,
) -> Result<()> {
    let now = Utc::now();

    let rows_affected = sqlx::query(
        "UPDATE ap_agents
         SET status='revoked', revoked_at=$1, revocation_reason=$2, revoked_by=$3
         WHERE did=$4 AND org_id=$5 AND status != 'revoked'"
    )
    .bind(now).bind(reason).bind(revoked_by).bind(did).bind(org_id)
    .execute(pool).await.context("revoke agent")?
    .rows_affected();

    if rows_affected == 0 {
        anyhow::bail!("Agent not found or already revoked");
    }

    // Add to CRL
    sqlx::query(
        "INSERT INTO ap_crl (did, entity_type, reason, revoked_by)
         VALUES ($1,'agent',$2,$3)
         ON CONFLICT (did) DO NOTHING"
    )
    .bind(did).bind(reason).bind(revoked_by)
    .execute(pool).await.context("crl insert")?;

    // Revoke all credentials
    sqlx::query(
        "UPDATE ap_credentials SET revoked_at=$1, revocation_reason='agent_revoked', revoked_by=$2
         WHERE agent_id = (SELECT id FROM ap_agents WHERE did=$3)
           AND revoked_at IS NULL"
    )
    .bind(now).bind(revoked_by).bind(did)
    .execute(pool).await.context("cascade revoke credentials")?;

    // Revoke active sponsor
    sqlx::query(
        "UPDATE ap_sponsors SET status='revoked', revoked_at=$1, revocation_reason='agent_revoked'
         WHERE agent_id = (SELECT id FROM ap_agents WHERE did=$2) AND status='active'"
    )
    .bind(now).bind(did)
    .execute(pool).await.context("cascade revoke sponsor")?;

    append_audit(pool, org_id, "agent", did, "revoked",
        Some(revoked_by), None, json!({ "reason": reason }), None).await;

    Ok(())
}

// ── Suspend / unsuspend ────────────────────────────────────────────────────────

pub async fn set_agent_status(
    pool: &PgPool,
    org_id: Uuid,
    did: &str,
    new_status: &str,
    actor: &str,
    reason: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE ap_agents SET status=$1 WHERE did=$2 AND org_id=$3"
    )
    .bind(new_status).bind(did).bind(org_id)
    .execute(pool).await.context("set agent status")?;

    append_audit(pool, org_id, "agent", did, new_status,
        Some(actor), None, json!({ "reason": reason }), None).await;
    Ok(())
}

// ── Sync interaction count from ConnectorOS ────────────────────────────────────

pub async fn sync_trust_from_connector(
    pool: &PgPool,
    connector: &crate::connector::ConnectorClient,
) -> Result<u64> {
    let rows = sqlx::query(
        "SELECT id, did, connector_pid FROM ap_agents
         WHERE status='active' AND connector_pid IS NOT NULL"
    ).fetch_all(pool).await.context("fetch active agents")?;

    let mut updated = 0u64;
    for row in &rows {
        let pid: Option<String> = row.try_get("connector_pid").ok();
        let agent_id: Uuid = row.try_get("id").unwrap_or_default();
        if let Some(ref pid) = pid {
            if let Ok(trust) = connector.get_trust(pid).await {
                if let Some(score) = trust.trust_score {
                    sqlx::query(
                        "UPDATE ap_agents SET trust_score=$1, last_seen_at=NOW() WHERE id=$2"
                    ).bind(score).bind(agent_id).execute(pool).await.ok();
                    updated += 1;
                }
            }
        }
    }
    Ok(updated)
}

// ── Audit log helper ───────────────────────────────────────────────────────────

pub async fn append_audit(
    pool: &PgPool,
    org_id: Uuid,
    entity_type: &str,
    entity_id: &str,
    action: &str,
    actor_did: Option<&str>,
    actor_ip: Option<&str>,
    payload: Value,
    prev_cid: Option<&str>,
) {
    let this_cid = crypto::chain_cid(prev_cid, &payload);
    sqlx::query(
        "INSERT INTO ap_audit_log
            (org_id, entity_type, entity_id, action, actor_did, actor_ip, payload, prev_cid, this_cid)
         VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9)"
    )
    .bind(org_id)
    .bind(entity_type)
    .bind(entity_id)
    .bind(action)
    .bind(actor_did)
    .bind(actor_ip)
    .bind(payload)
    .bind(prev_cid)
    .bind(&this_cid)
    .execute(pool).await.ok();
}

// ── Row mapper ─────────────────────────────────────────────────────────────────

pub fn row_to_agent(row: &sqlx::postgres::PgRow) -> AgentRow {
    AgentRow {
        id:                 row.try_get("id").unwrap_or_default(),
        org_id:             row.try_get("org_id").unwrap_or_default(),
        did:                row.try_get("did").unwrap_or_default(),
        name:               row.try_get("name").unwrap_or_default(),
        version:            row.try_get("version").unwrap_or_default(),
        description:        row.try_get("description").ok(),
        agent_card:         row.try_get("agent_card").unwrap_or(json!({})),
        connector_pid:      row.try_get("connector_pid").ok(),
        status:             row.try_get("status").unwrap_or_default(),
        trust_score:        row.try_get::<f64, _>("trust_score").unwrap_or(1.0),
        total_interactions: row.try_get("total_interactions").unwrap_or(0),
        violation_count:    row.try_get("violation_count").unwrap_or(0),
        incident_count:     row.try_get("incident_count").unwrap_or(0),
        public_key_ed25519: row.try_get("public_key_ed25519").ok(),
        created_at:         row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        activated_at:       row.try_get("activated_at").ok(),
        last_seen_at:       row.try_get("last_seen_at").ok(),
        revoked_at:         row.try_get("revoked_at").ok(),
        revocation_reason:  row.try_get("revocation_reason").ok(),
        revoked_by:         row.try_get("revoked_by").ok(),
        audit_cid:          row.try_get("audit_cid").ok(),
        metadata:           row.try_get("metadata").unwrap_or(json!({})),
    }
}
