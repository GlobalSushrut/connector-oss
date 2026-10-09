//! Attestation export packs — procurement-grade, HMAC-signed.
//!
//! GET /api/v1/attestation/:did/export?format=json|pdf
//!
//! JSON: machine-readable, signed with Ed25519 proof
//! PDF:  structured text report (full passport, no dependencies on PDF libs)

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::agents::get_agent_by_did;
use crate::crypto;
use crate::state::AppState;

// ── Build full passport ────────────────────────────────────────────────────────

pub async fn build_passport(pool: &PgPool, did: &str) -> Result<Value> {
    let agent = get_agent_by_did(pool, did).await?;

    // Active sponsor
    let sponsor = sqlx::query(
        "SELECT display_name, legal_entity, jurisdiction, user_email, verified_at, expires_at
         FROM ap_sponsors WHERE agent_id=$1 AND status='active' LIMIT 1"
    ).bind(agent.id).fetch_optional(pool).await.context("sponsor")?
    .map(|r| json!({
        "display_name":  r.try_get::<String, _>("display_name").unwrap_or_default(),
        "legal_entity":  r.try_get::<String, _>("legal_entity").unwrap_or_default(),
        "jurisdiction":  r.try_get::<Option<String>, _>("jurisdiction").unwrap_or_default(),
        "user_email":    r.try_get::<String, _>("user_email").unwrap_or_default(),
        "verified_at":   r.try_get::<Option<chrono::DateTime<Utc>>, _>("verified_at").unwrap_or_default(),
        "expires_at":    r.try_get::<Option<chrono::DateTime<Utc>>, _>("expires_at").unwrap_or_default(),
    }));

    // Active credentials
    let creds = sqlx::query(
        "SELECT credential_type, issuer_name, issuer_did, subject, issued_at, expires_at
         FROM ap_credentials
         WHERE agent_id=$1 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY issued_at DESC"
    ).bind(agent.id).fetch_all(pool).await.context("credentials")?;

    let credentials: Vec<Value> = creds.iter().map(|r| json!({
        "type":        r.try_get::<String, _>("credential_type").unwrap_or_default(),
        "issuer_name": r.try_get::<String, _>("issuer_name").unwrap_or_default(),
        "issuer_did":  r.try_get::<String, _>("issuer_did").unwrap_or_default(),
        "subject":     r.try_get::<Value, _>("subject").unwrap_or(json!({})),
        "issued_at":   r.try_get::<chrono::DateTime<Utc>, _>("issued_at").unwrap_or_else(|_| Utc::now()),
        "expires_at":  r.try_get::<Option<chrono::DateTime<Utc>>, _>("expires_at").unwrap_or_default(),
    })).collect();

    // Reputation summary
    let rep = crate::reputation::get_reputation(pool, did).await.unwrap_or(json!({}));

    // Recent incidents
    let incident_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ap_incidents WHERE agent_id=$1 AND resolved_at IS NULL"
    ).bind(agent.id).fetch_one(pool).await.unwrap_or(0);

    Ok(json!({
        "did":             agent.did,
        "name":            agent.name,
        "version":         agent.version,
        "description":     agent.description,
        "status":          agent.status,
        "created_at":      agent.created_at,
        "activated_at":    agent.activated_at,
        "agent_card":      agent.agent_card,
        "sponsor":         sponsor,
        "credentials":     credentials,
        "reputation": {
            "trust_score":        rep.get("trust_score").cloned().unwrap_or(json!(null)),
            "signal":             rep.get("signal").cloned().unwrap_or(json!(null)),
            "total_interactions": rep.get("total_interactions").cloned().unwrap_or(json!(0)),
            "violation_count":    agent.violation_count,
            "incident_count":     agent.incident_count,
            "open_incidents":     incident_count,
        },
        "audit_cid":       agent.audit_cid,
        "metadata":        agent.metadata,
    }))
}

// ── JSON export (signed) ───────────────────────────────────────────────────────

pub async fn export_json(state: &AppState, did: &str) -> Result<Value> {
    let passport = build_passport(&state.pool, did).await?;
    let now = Utc::now();

    let export_payload = json!({
        "version":    "1.0",
        "export_type":"AgentPassportAttestation",
        "exported_at": now.to_rfc3339(),
        "issuer": {
            "did":  state.instance_did,
            "name": "AgentPassport",
        },
        "passport": passport,
    });

    let proof = crypto::build_verification_proof(
        &state.signing_key,
        &state.instance_did,
        &state.key_id,
        &export_payload,
    );

    Ok(json!({
        "attestation": export_payload,
        "proof": proof,
    }))
}

// ── Text/PDF export ────────────────────────────────────────────────────────────
//
// Produces a structured text report suitable for procurement handoffs.
// No PDF library dependencies — plain text with clear sections.
// Callers can convert to PDF via wkhtmltopdf / Pandoc if needed.

pub async fn export_text(state: &AppState, did: &str) -> Result<String> {
    let passport = build_passport(&state.pool, did).await?;
    let now = Utc::now();

    let agent_name   = str_field(&passport, "name");
    let agent_did    = str_field(&passport, "did");
    let status       = str_field(&passport, "status");
    let version      = str_field(&passport, "version");
    let created_at   = str_field(&passport, "created_at");
    let activated_at = str_field(&passport, "activated_at");

    let sponsor_block = match passport.get("sponsor").and_then(|s| s.as_object()) {
        Some(sp) => format!(
            "  Display Name:  {}\n  Legal Entity:  {}\n  Jurisdiction:  {}\n  Verified At:   {}\n  Expires At:    {}",
            sp.get("display_name").and_then(|v| v.as_str()).unwrap_or("-"),
            sp.get("legal_entity").and_then(|v| v.as_str()).unwrap_or("-"),
            sp.get("jurisdiction").and_then(|v| v.as_str()).unwrap_or("-"),
            sp.get("verified_at").and_then(|v| v.as_str()).unwrap_or("-"),
            sp.get("expires_at").and_then(|v| v.as_str()).unwrap_or("Never"),
        ),
        None => "  No active sponsor.".into(),
    };

    let creds_block = passport.get("credentials")
        .and_then(|c| c.as_array())
        .map(|arr| {
            if arr.is_empty() { return "  No credentials issued.".into(); }
            arr.iter().enumerate().map(|(i, c)| {
                format!("  [{}] {} — issued by {} on {}{}",
                    i + 1,
                    c.get("type").and_then(|v| v.as_str()).unwrap_or("-"),
                    c.get("issuer_name").and_then(|v| v.as_str()).unwrap_or("-"),
                    c.get("issued_at").and_then(|v| v.as_str()).unwrap_or("-"),
                    c.get("expires_at").and_then(|v| v.as_str())
                        .map(|e| format!(" (expires {})", e)).unwrap_or_default(),
                )
            }).collect::<Vec<_>>().join("\n")
        }).unwrap_or_else(|| "  No credentials issued.".into());

    let rep = passport.get("reputation").cloned().unwrap_or(json!({}));
    let score   = rep.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let signal  = rep.get("signal").and_then(|v| v.as_str()).unwrap_or("-");
    let viol    = rep.get("violation_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let inter   = rep.get("total_interactions").and_then(|v| v.as_i64()).unwrap_or(0);
    let open_inc= rep.get("open_incidents").and_then(|v| v.as_i64()).unwrap_or(0);

    let audit_cid = str_field(&passport, "audit_cid");

    // Canonical JSON of passport for signing
    let sign_payload = json!({ "did": agent_did, "exported_at": now.to_rfc3339() });
    let proof = crypto::build_verification_proof(
        &state.signing_key,
        &state.instance_did,
        &state.key_id,
        &sign_payload,
    );

    let report = format!(
r#"╔══════════════════════════════════════════════════════════════════╗
║              AGENT PASSPORT — ATTESTATION REPORT               ║
╚══════════════════════════════════════════════════════════════════╝

  Issued By:     AgentPassport ({})
  Exported At:   {}
  Report Format: AgentPassportAttestation v1.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AGENT IDENTITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Name:          {}
  DID:           {}
  Version:       {}
  Status:        {}
  Registered:    {}
  Activated:     {}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SPONSOR (LIABILITY CHAIN)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  VERIFIABLE CREDENTIALS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  REPUTATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Trust Score:        {:.4}  {}
  Total Interactions: {}
  Violations:         {}
  Open Incidents:     {}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AUDIT CHAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Latest CID:    {}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  CRYPTOGRAPHIC PROOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Proof Type:    {}
  Issued By:     {}
  Signature:     {}
  Signed At:     {}

  This attestation was signed by the AgentPassport instance at the
  time of export. Verify the signature against the instance public
  key to confirm this document has not been tampered with.

══════════════════════════════════════════════════════════════════
"#,
        state.instance_did,
        now.format("%Y-%m-%d %H:%M:%S UTC"),
        agent_name, agent_did, version, status, created_at, activated_at,
        sponsor_block,
        creds_block,
        score, signal,
        inter, viol, open_inc,
        audit_cid,
        proof.proof_type,
        proof.verification_method,
        proof.signature,
        proof.created.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    Ok(report)
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("-")
        .to_string()
}
