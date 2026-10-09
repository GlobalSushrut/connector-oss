//! Public verification endpoint + Certificate Revocation List.
//!
//! POST /api/v1/verify   — callable by any external party, no auth required
//! GET  /api/v1/crl      — public CRL, cacheable, sorted by crl_seq DESC

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::crypto;
use crate::state::AppState;
use crate::types::{SponsorSummary, VerificationProof, VerifyRequest, VerifyResponse};

// ── Verify ─────────────────────────────────────────────────────────────────────

pub async fn verify(
    state: &AppState,
    req: &VerifyRequest,
    verifier_id: Option<&str>,
    verifier_ip: Option<&str>,
) -> Result<VerifyResponse> {
    let pool = &state.pool;
    let now  = Utc::now();

    // 1. Check CRL first — fastest rejection
    let on_crl: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ap_crl WHERE did=$1)"
    ).bind(&req.did).fetch_one(pool).await.unwrap_or(false);

    if on_crl {
        let proof = build_fail_proof(state, &req.did, "on_crl").await;
        log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
            Some("Agent is on the Certificate Revocation List"),
            None, &proof).await;
        return Ok(VerifyResponse {
            verified: false,
            agent_did: req.did.clone(),
            agent_name: None,
            trust_score: None,
            sponsor: None,
            credentials_verified: vec![],
            violations: 0,
            failure_reason: Some("on_crl".into()),
            verified_at: now,
            expires_in_sec: 0,
            proof,
        });
    }

    // 2. Load agent
    let agent_row = sqlx::query(
        "SELECT id, name, status, trust_score, violation_count FROM ap_agents WHERE did=$1"
    ).bind(&req.did).fetch_one(pool).await
    .map_err(|_| anyhow::anyhow!("Agent DID not found"))?;

    let agent_id:   uuid::Uuid = agent_row.try_get("id")?;
    let agent_name: String     = agent_row.try_get("name")?;
    let status:     String     = agent_row.try_get("status")?;
    let trust_score: f64       = agent_row.try_get("trust_score").unwrap_or(0.0);
    let violations:  i32       = agent_row.try_get("violation_count").unwrap_or(0);

    // 3. Status check
    if status != "active" {
        let proof = build_fail_proof(state, &req.did, &format!("status_{}", status)).await;
        log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
            Some(&format!("Agent status is '{}'", status)),
            Some(trust_score), &proof).await;
        return Ok(VerifyResponse {
            verified: false,
            agent_did: req.did.clone(),
            agent_name: Some(agent_name),
            trust_score: Some(trust_score),
            sponsor: None,
            credentials_verified: vec![],
            violations,
            failure_reason: Some(format!("agent_status_{}", status)),
            verified_at: now,
            expires_in_sec: 0,
            proof,
        });
    }

    // 4. Trust score check
    if let Some(min) = req.min_trust_score {
        if trust_score < min {
            let proof = build_fail_proof(state, &req.did, "trust_score_below_threshold").await;
            log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
                Some("Trust score below required minimum"),
                Some(trust_score), &proof).await;
            return Ok(VerifyResponse {
                verified: false,
                agent_did: req.did.clone(),
                agent_name: Some(agent_name),
                trust_score: Some(trust_score),
                sponsor: None,
                credentials_verified: vec![],
                violations,
                failure_reason: Some("trust_score_below_threshold".into()),
                verified_at: now,
                expires_in_sec: 0,
                proof,
            });
        }
    }

    // 5. Max violations check
    if let Some(max) = req.max_violations {
        if violations > max {
            let proof = build_fail_proof(state, &req.did, "violations_exceed_limit").await;
            log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
                Some("Violation count exceeds limit"),
                Some(trust_score), &proof).await;
            return Ok(VerifyResponse {
                verified: false,
                agent_did: req.did.clone(),
                agent_name: Some(agent_name),
                trust_score: Some(trust_score),
                sponsor: None,
                credentials_verified: vec![],
                violations,
                failure_reason: Some("violations_exceed_limit".into()),
                verified_at: now,
                expires_in_sec: 0,
                proof,
            });
        }
    }

    // 6. Active sponsor check
    let sponsor_summary = if req.require_active_sponsor.unwrap_or(false) {
        let sp = sqlx::query(
            "SELECT display_name, legal_entity, jurisdiction, status
             FROM ap_sponsors WHERE agent_id=$1 AND status='active'"
        ).bind(agent_id).fetch_optional(pool).await.unwrap_or(None);

        if sp.is_none() {
            let proof = build_fail_proof(state, &req.did, "no_active_sponsor").await;
            log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
                Some("No active sponsor"), Some(trust_score), &proof).await;
            return Ok(VerifyResponse {
                verified: false,
                agent_did: req.did.clone(),
                agent_name: Some(agent_name),
                trust_score: Some(trust_score),
                sponsor: None,
                credentials_verified: vec![],
                violations,
                failure_reason: Some("no_active_sponsor".into()),
                verified_at: now,
                expires_in_sec: 0,
                proof,
            });
        }
        sp.map(|r| SponsorSummary {
            display_name: r.try_get("display_name").unwrap_or_default(),
            legal_entity:  r.try_get("legal_entity").unwrap_or_default(),
            jurisdiction:  r.try_get("jurisdiction").ok().flatten(),
            verified:      true,
        })
    } else {
        // Fetch sponsor summary for the response even if not required
        sqlx::query(
            "SELECT display_name, legal_entity, jurisdiction FROM ap_sponsors
             WHERE agent_id=$1 AND status='active'"
        ).bind(agent_id).fetch_optional(pool).await.unwrap_or(None)
        .map(|r| SponsorSummary {
            display_name: r.try_get("display_name").unwrap_or_default(),
            legal_entity:  r.try_get("legal_entity").unwrap_or_default(),
            jurisdiction:  r.try_get("jurisdiction").ok().flatten(),
            verified:      true,
        })
    };

    // 7. Credential checks
    let mut credentials_verified = vec![];
    if let Some(required) = &req.required_credentials {
        for req_cred in required {
            let parts: Vec<&str> = req_cred.splitn(2, ':').collect();
            let cred_type = parts[0];
            let capability = parts.get(1).copied();

            let found = check_credential(pool, agent_id, cred_type, capability,
                req.issued_after).await;
            if !found {
                let proof = build_fail_proof(state, &req.did,
                    &format!("missing_credential_{}", req_cred)).await;
                log_verification(pool, &req.did, verifier_id, verifier_ip, req, false,
                    Some(&format!("Missing required credential: {}", req_cred)),
                    Some(trust_score), &proof).await;
                return Ok(VerifyResponse {
                    verified: false,
                    agent_did: req.did.clone(),
                    agent_name: Some(agent_name),
                    trust_score: Some(trust_score),
                    sponsor: sponsor_summary,
                    credentials_verified,
                    violations,
                    failure_reason: Some(format!("missing_credential_{}", req_cred)),
                    verified_at: now,
                    expires_in_sec: 0,
                    proof,
                });
            }
            credentials_verified.push(req_cred.clone());
        }
    }

    // 8. All checks passed — build signed proof
    let payload = json!({
        "did": req.did,
        "trust_score": trust_score,
        "verified_at": now.to_rfc3339(),
    });
    let proof = build_success_proof(state, &payload).await;

    log_verification(pool, &req.did, verifier_id, verifier_ip, req, true,
        None, Some(trust_score), &proof).await;

    metrics::counter!("agentpassport_verifications_total", "result" => "pass").increment(1);

    Ok(VerifyResponse {
        verified: true,
        agent_did: req.did.clone(),
        agent_name: Some(agent_name),
        trust_score: Some(trust_score),
        sponsor: sponsor_summary,
        credentials_verified,
        violations,
        failure_reason: None,
        verified_at: now,
        expires_in_sec: 300,
        proof,
    })
}

// ── CRL ────────────────────────────────────────────────────────────────────────

pub async fn get_crl(pool: &PgPool) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT did, entity_type, reason, revoked_at, crl_seq
         FROM ap_crl ORDER BY crl_seq DESC LIMIT 10000"
    ).fetch_all(pool).await.context("fetch crl")?;

    let entries: Vec<Value> = rows.iter().map(|r| json!({
        "did":         r.try_get::<String, _>("did").unwrap_or_default(),
        "entity_type": r.try_get::<String, _>("entity_type").unwrap_or_default(),
        "reason":      r.try_get::<Option<String>, _>("reason").unwrap_or_default(),
        "revoked_at":  r.try_get::<chrono::DateTime<Utc>, _>("revoked_at").unwrap_or_else(|_| Utc::now()),
        "crl_seq":     r.try_get::<i64, _>("crl_seq").unwrap_or(0),
    })).collect();

    Ok(json!({
        "issued_at":   Utc::now(),
        "count":       entries.len(),
        "revoked":     entries,
    }))
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async fn check_credential(
    pool: &PgPool,
    agent_id: uuid::Uuid,
    cred_type: &str,
    capability: Option<&str>,
    issued_after: Option<chrono::DateTime<Utc>>,
) -> bool {
    let base_q = "SELECT id FROM ap_credentials
                  WHERE agent_id=$1 AND credential_type=$2
                    AND revoked_at IS NULL
                    AND (expires_at IS NULL OR expires_at > NOW())";

    let row = if let Some(cap) = capability {
        sqlx::query(&format!("{} AND subject->>'capability' = $3
                              AND ($4::timestamptz IS NULL OR issued_at >= $4)
                              LIMIT 1", base_q))
            .bind(agent_id).bind(cred_type).bind(cap)
            .bind(issued_after)
            .fetch_optional(pool).await
    } else {
        sqlx::query(&format!("{} AND ($3::timestamptz IS NULL OR issued_at >= $3) LIMIT 1", base_q))
            .bind(agent_id).bind(cred_type)
            .bind(issued_after)
            .fetch_optional(pool).await
    };

    row.ok().flatten().is_some()
}

async fn build_success_proof(state: &AppState, payload: &Value) -> VerificationProof {
    let proof = crypto::build_verification_proof(
        &state.signing_key,
        &state.instance_did,
        &state.key_id,
        payload,
    );
    proof
}

async fn build_fail_proof(state: &AppState, did: &str, reason: &str) -> VerificationProof {
    let payload = json!({ "did": did, "result": "fail", "reason": reason,
                          "at": Utc::now().to_rfc3339() });
    crypto::build_verification_proof(
        &state.signing_key,
        &state.instance_did,
        &state.key_id,
        &payload,
    )
}

async fn log_verification(
    pool: &PgPool,
    agent_did: &str,
    verifier_id: Option<&str>,
    verifier_ip: Option<&str>,
    req: &VerifyRequest,
    result: bool,
    failure_reason: Option<&str>,
    trust_score: Option<f64>,
    proof: &VerificationProof,
) {
    sqlx::query(
        "INSERT INTO ap_verification_log
            (agent_did, verifier_id, verifier_ip, required_credentials,
             min_trust_score, require_active_sponsor, max_violations,
             result, failure_reason, trust_score_at_verify, proof_sig)
         VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11)"
    )
    .bind(agent_did)
    .bind(verifier_id)
    .bind(verifier_ip)
    .bind(req.required_credentials.as_ref().map(|v| serde_json::to_value(v).ok()))
    .bind(req.min_trust_score)
    .bind(req.require_active_sponsor.unwrap_or(false))
    .bind(req.max_violations)
    .bind(result)
    .bind(failure_reason)
    .bind(trust_score)
    .bind(&proof.signature)
    .execute(pool).await.ok();

    metrics::counter!("agentpassport_verifications_total",
        "result" => if result { "pass" } else { "fail" }
    ).increment(1);
}
