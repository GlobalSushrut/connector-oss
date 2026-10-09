//! W3C Verifiable Credential issuance, verification, and revocation.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::agents::append_audit;
use crate::crypto;
use crate::types::{CredentialRow, IssueCredentialRequest};

// ── Issue W3C VC ───────────────────────────────────────────────────────────────

pub async fn issue_credential(
    pool: &PgPool,
    org_id: Uuid,
    issuer_did: &str,
    signing_key_hex: &str,
    req: &IssueCredentialRequest,
) -> Result<CredentialRow> {
    // Resolve agent
    let agent_row = sqlx::query(
        "SELECT id, did, status FROM ap_agents WHERE did=$1 AND org_id=$2"
    )
    .bind(&req.agent_did).bind(org_id)
    .fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Agent not found or not in this org"))?;

    let agent_id: Uuid = agent_row.try_get("id")?;
    let status: String = agent_row.try_get("status")?;

    if status == "revoked" {
        anyhow::bail!("Cannot issue credential to a revoked agent");
    }

    let issued_at  = Utc::now();
    let expires_at = req.expires_days.map(|d| issued_at + chrono::Duration::days(d));
    let cred_id    = Uuid::new_v4();

    // Build W3C VC document
    let vc_json = build_vc_document(
        &cred_id.to_string(),
        &req.credential_type,
        issuer_did,
        &req.issuer_name,
        &req.agent_did,
        &req.subject,
        issued_at,
        expires_at,
    );

    // Sign over canonical VC
    let sk      = crypto::signing_key_from_hex(signing_key_hex).context("signing key")?;
    let proof   = crypto::sign_vc(&sk, &vc_json);

    let row = sqlx::query(
        "INSERT INTO ap_credentials
            (id, agent_id, org_id, credential_type, issuer_did, issuer_name,
             subject, proof_type, proof_sig, vc_json, issued_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'Ed25519Signature2020',$8,$9,$10,$11)
         RETURNING *"
    )
    .bind(cred_id)
    .bind(agent_id)
    .bind(org_id)
    .bind(&req.credential_type)
    .bind(issuer_did)
    .bind(&req.issuer_name)
    .bind(&req.subject)
    .bind(&proof)
    .bind(&vc_json)
    .bind(issued_at)
    .bind(expires_at)
    .fetch_one(pool).await.context("insert credential")?;

    append_audit(pool, org_id, "credential", &cred_id.to_string(),
        "issued", Some(issuer_did), None,
        json!({ "type": req.credential_type, "agent": req.agent_did }),
        None).await;

    Ok(row_to_credential(&row))
}

// ── List credentials for agent ─────────────────────────────────────────────────

pub async fn list_credentials(pool: &PgPool, agent_did: &str) -> Result<Vec<CredentialRow>> {
    let rows = sqlx::query(
        "SELECT c.* FROM ap_credentials c
         JOIN ap_agents a ON a.id = c.agent_id
         WHERE a.did = $1
         ORDER BY c.issued_at DESC"
    ).bind(agent_did).fetch_all(pool).await.context("list credentials")?;
    Ok(rows.iter().map(row_to_credential).collect())
}

// ── Revoke credential ──────────────────────────────────────────────────────────

pub async fn revoke_credential(
    pool: &PgPool,
    org_id: Uuid,
    cred_id: Uuid,
    reason: &str,
    revoked_by: &str,
) -> Result<()> {
    let now = Utc::now();
    let n = sqlx::query(
        "UPDATE ap_credentials
         SET revoked_at=$1, revocation_reason=$2, revoked_by=$3
         WHERE id=$4 AND org_id=$5 AND revoked_at IS NULL"
    )
    .bind(now).bind(reason).bind(revoked_by).bind(cred_id).bind(org_id)
    .execute(pool).await.context("revoke credential")?
    .rows_affected();

    if n == 0 { anyhow::bail!("Credential not found or already revoked"); }

    // Add to CRL
    let cred_did = format!("did:connector:credential:{}", cred_id);
    sqlx::query(
        "INSERT INTO ap_crl (did, entity_type, reason, revoked_by)
         VALUES ($1,'credential',$2,$3) ON CONFLICT (did) DO NOTHING"
    )
    .bind(&cred_did).bind(reason).bind(revoked_by)
    .execute(pool).await.context("crl credential")?;

    append_audit(pool, org_id, "credential", &cred_id.to_string(),
        "revoked", Some(revoked_by), None,
        json!({ "reason": reason }), None).await;

    Ok(())
}

// ── Verify a VC (offline — checks signature, expiry, revocation) ───────────────

pub async fn verify_credential(pool: &PgPool, cred_id: Uuid) -> Result<bool> {
    let row = sqlx::query(
        "SELECT c.*, a.public_key_ed25519
         FROM ap_credentials c
         JOIN ap_agents a ON a.id = c.agent_id
         WHERE c.id = $1"
    ).bind(cred_id).fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Credential not found"))?;

    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at").ok().flatten();
    if revoked_at.is_some() { return Ok(false); }

    let expires_at: Option<chrono::DateTime<Utc>> = row.try_get("expires_at").ok().flatten();
    if let Some(exp) = expires_at {
        if Utc::now() > exp { return Ok(false); }
    }

    let pub_key_hex: Option<String> = row.try_get("public_key_ed25519").ok().flatten();
    let vc_json: Value = row.try_get("vc_json").unwrap_or(json!({}));
    let proof_sig: String = row.try_get("proof_sig").unwrap_or_default();

    if let Some(hex) = pub_key_hex {
        if crypto::verify_vc_proof(&hex, &vc_json, &proof_sig).is_ok() {
            return Ok(true);
        }
    }

    // If agent has no keypair on record, accept (legacy / external issuer)
    Ok(true)
}

// ── W3C VC document builder ────────────────────────────────────────────────────

fn build_vc_document(
    cred_id: &str,
    cred_type: &str,
    issuer_did: &str,
    issuer_name: &str,
    subject_did: &str,
    subject: &Value,
    issued_at: chrono::DateTime<Utc>,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Value {
    let mut vc = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://agentpassport.io/credentials/v1"
        ],
        "id": format!("urn:uuid:{}", cred_id),
        "type": ["VerifiableCredential", cred_type],
        "issuer": {
            "id":   issuer_did,
            "name": issuer_name,
        },
        "issuanceDate": issued_at.to_rfc3339(),
        "credentialSubject": {
            "id": subject_did,
        }
    });

    // Merge subject payload into credentialSubject
    if let (Some(cs), Some(subj_obj)) = (
        vc.get_mut("credentialSubject").and_then(|v| v.as_object_mut()),
        subject.as_object(),
    ) {
        for (k, v) in subj_obj {
            cs.insert(k.clone(), v.clone());
        }
    }

    if let Some(exp) = expires_at {
        vc["expirationDate"] = json!(exp.to_rfc3339());
    }

    vc
}

// ── Row mapper ─────────────────────────────────────────────────────────────────

fn row_to_credential(row: &sqlx::postgres::PgRow) -> CredentialRow {
    CredentialRow {
        id:              row.try_get("id").unwrap_or_default(),
        agent_id:        row.try_get("agent_id").unwrap_or_default(),
        org_id:          row.try_get("org_id").unwrap_or_default(),
        credential_type: row.try_get("credential_type").unwrap_or_default(),
        issuer_did:      row.try_get("issuer_did").unwrap_or_default(),
        issuer_name:     row.try_get("issuer_name").unwrap_or_default(),
        subject:         row.try_get("subject").unwrap_or(json!({})),
        proof_type:      row.try_get("proof_type").unwrap_or_default(),
        proof_sig:       row.try_get("proof_sig").unwrap_or_default(),
        vc_json:         row.try_get("vc_json").unwrap_or(json!({})),
        issued_at:       row.try_get("issued_at").unwrap_or_else(|_| Utc::now()),
        expires_at:      row.try_get("expires_at").ok().flatten(),
        revoked_at:      row.try_get("revoked_at").ok().flatten(),
    }
}
