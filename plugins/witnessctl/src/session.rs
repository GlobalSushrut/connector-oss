use chrono::Utc;
use sqlx::{PgPool, Row};
use sqlx::types::BigDecimal;
use uuid::Uuid;
use std::process::Command;
use std::collections::HashSet;

use crate::{
    connector::ConnectorClient,
    error::AppError,
    bundle_file::{self, BUNDLE_TYPE},
    receipt::{compute_bundle_signature, generate_receipt, verify_chain},
    types::*,
    config::Config,
};

pub struct SessionManager {
    db: PgPool,
    connector: ConnectorClient,
    hmac_secret: String,
    tsa_url: Option<String>,
    tsa_required: bool,
    tsa_strict_verify: bool,
    tsa_ca_file: Option<String>,
    tsa_required_frameworks: HashSet<String>,
}

/// Stable Connector agent identity for `(tenant, role)` so process restarts do not register a new agent each time.
/// Override with `WITNESSCTL_CONNECTOR_AGENT_NAME` (single shared lab agent) when appropriate.
fn stable_connector_agent_name(role: &str, tenant_id: Uuid) -> String {
    const MAX_LEN: usize = 120;
    if let Ok(v) = std::env::var("WITNESSCTL_CONNECTOR_AGENT_NAME") {
        let t = v.trim().to_string();
        if !t.is_empty() {
            return t.chars().take(MAX_LEN).collect();
        }
    }
    let safe_role: String = role
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(48)
        .collect();
    let safe_role = if safe_role.is_empty() {
        "default".to_string()
    } else {
        safe_role
    };
    format!(
        "witnessctl-tenant-{}-role-{}",
        tenant_id.as_simple(),
        safe_role
    )
    .chars()
    .take(MAX_LEN)
    .collect()
}

fn numeric_to_f64(row: &sqlx::postgres::PgRow, column: &str) -> f64 {
    row.try_get::<BigDecimal, _>(column)
        .ok()
        .and_then(|v| v.to_string().parse::<f64>().ok())
        .unwrap_or(0.0)
}

impl SessionManager {
    pub fn new(db: PgPool, connector: ConnectorClient, config: &Config) -> Self {
        Self {
            db,
            connector,
            hmac_secret: config.hmac_secret.clone(),
            tsa_url: config.tsa_url.clone().filter(|v| !v.trim().is_empty()),
            tsa_required: config.tsa_url.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false),
            tsa_strict_verify: config.tsa_strict_verify,
            tsa_ca_file: config.tsa_ca_file.clone().filter(|v| !v.trim().is_empty()),
            tsa_required_frameworks: config.tsa_required_frameworks.iter().cloned().collect(),
        }
    }

    pub async fn open_session(&self, req: OpenSessionRequest, tenant_id: Uuid) -> Result<OpenSessionResponse, AppError> {
        let agent_name = stable_connector_agent_name(&req.role, tenant_id);
        let clearance = req.policy.as_ref().and_then(|p| p.clearance).unwrap_or(3);
        let agent = self.connector.register_agent(&agent_name, "witnessctl capture session", clearance).await?;

        let token = format!("wst_{}", Uuid::new_v4().to_string().replace("-", ""));
        let frameworks: Vec<_> = req.frameworks.as_ref().map(|f| 
            f.iter().filter_map(|s| ComplianceFramework::from_str(s)).collect()
        ).unwrap_or_else(|| vec![ComplianceFramework::Hipaa, ComplianceFramework::Soc2]);
        let mode = req.mode.unwrap_or(SessionMode::Proxy);

        let id = sqlx::query_scalar::<_, Uuid>(r#"
            INSERT INTO witness_sessions (tenant_id, upstream, role, agent_pid, mode, frameworks, policy, session_token)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
        "#)
        .bind(tenant_id).bind(&req.upstream).bind(&req.role).bind(&agent.pid).bind(mode.to_string())
        .bind(&frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>())
        .bind(serde_json::to_value(&req.policy.unwrap_or_default()).unwrap_or_default())
        .bind(&token).fetch_one(&self.db).await?;

        let receipt = generate_receipt(id, None, "session.open", 0, 
            serde_json::json!({"upstream": req.upstream, "role": req.role, "mode": mode.to_string()}),
            None, &self.hmac_secret);

        sqlx::query(r#"
            INSERT INTO witness_receipts (tenant_id, session_id, event_type, seq, payload, hmac, prev_hmac)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#)
        .bind(tenant_id).bind(id).bind(&receipt.event_type).bind(receipt.seq).bind(&receipt.payload)
        .bind(&receipt.hmac).bind(&receipt.prev_hmac).execute(&self.db).await?;

        sqlx::query("UPDATE witness_sessions SET chain_head_hmac = $1, receipt_seq = 1 WHERE id = $2")
            .bind(&receipt.hmac).bind(id).execute(&self.db).await?;

        Ok(OpenSessionResponse { session_id: id, agent_pid: Some(agent.pid), session_token: token.clone(),
            proxy_url: format!("{}/witness/{}", public_base_url(), id),
            proxy_header: format!("X-Witness-Session: {}", token), receipt_id: receipt.id })
    }

    pub async fn get_session(&self, id: Uuid) -> Result<Session, AppError> {
        let row = sqlx::query(r#"
            SELECT id, upstream, role, agent_pid, mode::text, status::text, frameworks, policy,
                session_token, chain_head_hmac, receipt_seq, total_calls, total_blocked,
                total_pii_hits, cost_usd, proof_id, bundle_path, sealed_at, created_at, updated_at
            FROM witness_sessions WHERE id = $1
        "#).bind(id).fetch_optional(&self.db).await?.ok_or_else(|| AppError::NotFound(format!("Session {}", id)))?;

        Ok(self.row_to_session(&row)?)
    }

    pub async fn get_session_by_token(&self, token: &str, tenant_id: Uuid) -> Result<Session, AppError> {
        let row = sqlx::query(r#"
            SELECT id, upstream, role, agent_pid, mode::text, status::text, frameworks, policy,
                session_token, chain_head_hmac, receipt_seq, total_calls, total_blocked,
                total_pii_hits, cost_usd, proof_id, bundle_path, sealed_at, created_at, updated_at
            FROM witness_sessions WHERE session_token = $1 AND tenant_id = $2
        "#).bind(token).bind(tenant_id).fetch_optional(&self.db).await?.ok_or_else(|| AppError::NotFound(format!("Session token {}", token)))?;

        Ok(self.row_to_session(&row)?)
    }

    pub async fn list_sessions(&self, limit: i64, tenant_id: Uuid) -> Result<Vec<SessionStats>, AppError> {
        let rows = sqlx::query(r#"
            SELECT id, upstream, role, status::text, total_calls, total_blocked,
                total_pii_hits, cost_usd, receipt_seq, created_at
            FROM witness_sessions WHERE tenant_id = $2 ORDER BY created_at DESC LIMIT $1
        "#).bind(limit).bind(tenant_id).fetch_all(&self.db).await?;

        let mut stats = Vec::new();
        for row in &rows {
            stats.push(SessionStats {
                session_id: row.get("id"), upstream: row.get("upstream"), role: row.get("role"),
                status: match row.get::<String, _>("status").as_str() {
                    "sealed" => SessionStatus::Sealed,
                    "locked" => SessionStatus::Locked,
                    "quarantined" => SessionStatus::Quarantined,
                    _ => SessionStatus::Active,
                },
                total_calls: row.get("total_calls"), total_blocked: row.get("total_blocked"),
                total_pii_hits: row.get("total_pii_hits"),
                cost_usd: numeric_to_f64(row, "cost_usd"),
                receipt_seq: row.get("receipt_seq"), created_at: row.get("created_at"),
            });
        }
        Ok(stats)
    }

    fn row_to_session(&self, row: &sqlx::postgres::PgRow) -> Result<Session, AppError> {
        Ok(Session {
            id: row.get("id"), upstream: row.get("upstream"), role: row.get("role"), agent_pid: row.get("agent_pid"),
            mode: match row.get::<String, _>("mode").as_str() { "proxy" => SessionMode::Proxy, "sdk_shim" => SessionMode::SdkShim, _ => SessionMode::Webhook },
            status: match row.get::<String, _>("status").as_str() {
                "sealed" => SessionStatus::Sealed,
                "locked" => SessionStatus::Locked,
                "quarantined" => SessionStatus::Quarantined,
                _ => SessionStatus::Active,
            },
            frameworks: row.get::<Vec<String>, _>("frameworks").iter().filter_map(|s| ComplianceFramework::from_str(s)).collect(),
            policy: serde_json::from_value(row.get("policy")).unwrap_or_default(),
            session_token: row.get("session_token"), chain_head_hmac: row.get("chain_head_hmac"),
            receipt_seq: row.get("receipt_seq"), total_calls: row.get("total_calls"),
            total_blocked: row.get("total_blocked"), total_pii_hits: row.get("total_pii_hits"),
            cost_usd: numeric_to_f64(row, "cost_usd"),
            proof_id: row.get("proof_id"), bundle_path: row.get("bundle_path"), sealed_at: row.get("sealed_at"),
            created_at: row.get("created_at"), updated_at: row.get("updated_at"),
        })
    }

    pub async fn seal_session(&self, id: Uuid, force_seal: bool) -> Result<SealResponse, AppError> {
        let session = self.get_session(id).await?;
        if session.status == SessionStatus::Sealed { return Err(AppError::BadRequest("Already sealed".to_string())); }
        let pid = session
            .agent_pid
            .clone()
            .ok_or_else(|| AppError::Internal("No agent_pid".to_string()))?;

        let receipts = sqlx::query_as::<_, (String, Option<String>, i64)>(r#"
            SELECT hmac, prev_hmac, seq FROM witness_receipts WHERE session_id = $1 ORDER BY seq
        "#).bind(id).fetch_all(&self.db).await?;

        let last_hmac = receipts.last().map(|r| r.0.clone());
        let close = generate_receipt(id, None, "session.close", session.receipt_seq,
            serde_json::json!({"reason": "sealed", "total_calls": session.total_calls}),
            last_hmac.as_deref(), &self.hmac_secret);

        sqlx::query(r#"
            INSERT INTO witness_receipts (tenant_id, session_id, event_type, seq, payload, hmac, prev_hmac)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#)
        .bind(derive_tenant_id_from_session_token(&session.session_token)).bind(id).bind(&close.event_type).bind(close.seq).bind(&close.payload)
        .bind(&close.hmac).bind(&close.prev_hmac).execute(&self.db).await?;

        let proof = if force_seal {
            None
        } else {
            self.connector.generate_proof(&pid, "witnessctl_session").await.ok()
        };
        let totals = sqlx::query(r#"
            SELECT COUNT(*) as calls, COUNT(*) FILTER (WHERE firewall_blocked) as blocked,
                SUM(CASE WHEN pii_in_request OR pii_in_response THEN 1 ELSE 0 END) as pii_hits,
                COALESCE(SUM(cost_usd), 0) as cost
            FROM witness_captures WHERE session_id = $1
        "#).bind(id).fetch_one(&self.db).await?;

        let (calls, blocked, pii_hits): (i64, i64, i64) = (totals.get("calls"), totals.get("blocked"), totals.get("pii_hits"));
        let cost: f64 = totals.get::<f64, _>("cost");
        let proof_id = format!("soe1-sha256-{}", &close.hmac[..16]);
        let bundle_path = self.materialize_witness_bundle(
            id,
            &session,
            &proof_id,
            &close.hmac,
            close.seq + 1,
            calls,
            blocked,
            pii_hits,
            cost,
            proof.as_ref(),
        ).await?;
        let tsa_required_for_session = self.is_tsa_required_for_session(&session.frameworks);
        if tsa_required_for_session && self.tsa_url.is_none() {
            return Err(AppError::Internal(
                "TSA is required for this framework set but WITNESSCTL_TSA_URL is not configured".to_string(),
            ));
        }
        let (tsa_status, tsa_token, tsa_verified, tsa_policy_oid) = self.request_tsa_token(id, &close.hmac).await;
        if (self.tsa_required || tsa_required_for_session) && tsa_status != "ok" {
            return Err(AppError::Internal("TSA timestamping is required but failed".to_string()));
        }
        if (self.tsa_strict_verify || tsa_required_for_session) && tsa_status == "ok" && tsa_verified != Some(true) {
            return Err(AppError::Internal("TSA strict verification enabled but token verification failed".to_string()));
        }

        sqlx::query(r#"
            UPDATE witness_sessions SET status = 'sealed', sealed_at = NOW(), proof_id = $1,
                bundle_path = $2, chain_head_hmac = $3, receipt_seq = $4,
                total_calls = $5, total_blocked = $6, total_pii_hits = $7, cost_usd = $8,
                tsa_status = $9, tsa_token = $10, tsa_timestamped_at = CASE WHEN $10 IS NULL THEN NULL ELSE NOW() END,
                tsa_verified = $11, tsa_policy_oid = $12
            WHERE id = $13
        "#)
        .bind(&proof_id).bind(&bundle_path).bind(&close.hmac).bind(close.seq + 1)
        .bind(calls).bind(blocked).bind(pii_hits).bind(cost)
        .bind(&tsa_status).bind(&tsa_token).bind(tsa_verified).bind(&tsa_policy_oid).bind(id).execute(&self.db).await?;

        let proof_source = if proof.is_some() { "connector".to_string() } else { "local_only".to_string() };
        let warning = match (proof.is_none(), tsa_status.as_str()) {
            (true, "failed") => Some("Session sealed without Connector proof and TSA timestamp failed".to_string()),
            (true, _) => Some("Session sealed without Connector proof (local_only)".to_string()),
            (false, "failed") => Some("Session sealed but TSA timestamp failed".to_string()),
            _ => None,
        };

        Ok(SealResponse { session_id: id, proof_id, bundle_path, chain_verified: proof.as_ref().map(|p| p.chain_verified).unwrap_or(true),
            proof_source, warning,
            receipt_count: proof.as_ref().map(|p| p.receipt_count as i64).unwrap_or(close.seq), total_calls: calls, pii_hits,
            compliance_pass: true, compliance_verdicts: std::collections::HashMap::new(), cost_usd: cost })
    }

    pub async fn set_session_lock(&self, id: Uuid, locked: bool) -> Result<Session, AppError> {
        let target = if locked { "locked" } else { "active" };
        let updated = sqlx::query("UPDATE witness_sessions SET status = $1, updated_at = NOW() WHERE id = $2 AND status != 'sealed'")
            .bind(target)
            .bind(id)
            .execute(&self.db)
            .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::BadRequest("Session is sealed or not found".to_string()));
        }
        self.get_session(id).await
    }

    pub async fn set_session_quarantine(
        &self,
        id: Uuid,
        quarantined: bool,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<Session, AppError> {
        let target = if quarantined { "quarantined" } else { "active" };
        let event = if quarantined {
            serde_json::json!({
                "status": "quarantined",
                "actor": actor,
                "reason": reason.unwrap_or("manual quarantine"),
                "at": Utc::now().to_rfc3339()
            })
        } else {
            serde_json::json!({
                "status": "active",
                "actor": actor,
                "reason": reason.unwrap_or("manual unquarantine"),
                "at": Utc::now().to_rfc3339()
            })
        };
        let updated = sqlx::query(
            "UPDATE witness_sessions
             SET status = $1,
                 policy = jsonb_set(COALESCE(policy,'{}'::jsonb), '{quarantine_event}', $2::jsonb, true),
                 updated_at = NOW()
             WHERE id = $3 AND status != 'sealed'"
        )
        .bind(target)
        .bind(event)
        .bind(id)
        .execute(&self.db)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::BadRequest("Session is sealed or not found".to_string()));
        }
        self.get_session(id).await
    }

    pub async fn update_session_upstream(&self, id: Uuid, upstream: &str) -> Result<Session, AppError> {
        let clean = upstream.trim();
        if clean.is_empty() {
            return Err(AppError::BadRequest("upstream cannot be empty".to_string()));
        }
        if reqwest::Url::parse(clean).is_err() {
            return Err(AppError::BadRequest("upstream must be a valid URL".to_string()));
        }
        let updated = sqlx::query(
            "UPDATE witness_sessions SET upstream = $1, updated_at = NOW() WHERE id = $2 AND status != 'sealed'"
        )
        .bind(clean)
        .bind(id)
        .execute(&self.db)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::BadRequest("Session is sealed or not found".to_string()));
        }
        self.get_session(id).await
    }

    async fn materialize_witness_bundle(
        &self,
        session_id: Uuid,
        session: &Session,
        proof_id: &str,
        chain_head_hmac: &str,
        receipt_seq: i64,
        total_calls: i64,
        total_blocked: i64,
        total_pii_hits: i64,
        cost_usd: f64,
        connector_proof: Option<&crate::connector::ProofBundle>,
    ) -> Result<String, AppError> {
        let ts = Utc::now().timestamp();
        let (witness_path, legacy_path, meta_path) = bundle_file::bundle_paths(session_id, ts);

        let captures_rows = sqlx::query(
            "SELECT id, seq, method, url, host, path, response_status, latency_ms, \
             admission_verdict, firewall_blocked, pii_in_request, pii_in_response, \
             schema_drift, drift_fields, request_hash, response_hash, created_at \
             FROM witness_captures WHERE session_id = $1 ORDER BY seq"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await
        .map_err(AppError::DatabaseError)?;

        let receipts_rows = sqlx::query(
            "SELECT id, session_id, capture_id, event_type, seq, payload, hmac, prev_hmac, created_at \
             FROM witness_receipts WHERE session_id = $1 ORDER BY seq"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await
        .map_err(AppError::DatabaseError)?;

        let receipts: Vec<Receipt> = receipts_rows
            .iter()
            .map(|r| Receipt {
                id: r.get("id"),
                session_id: r.get("session_id"),
                capture_id: r.get("capture_id"),
                event_type: r.get("event_type"),
                seq: r.get("seq"),
                payload: r.get("payload"),
                hmac: r.get("hmac"),
                prev_hmac: r.get("prev_hmac"),
                created_at: r.get("created_at"),
            })
            .collect();
        let chain_valid = verify_chain(&receipts, &self.hmac_secret);
        let expected_head = receipts.last().map(|r| r.hmac.clone());
        let head_matches = expected_head.as_deref() == Some(chain_head_hmac);
        let tamper_detected = !(chain_valid && head_matches);

        let captures = captures_rows
            .iter()
            .map(|r| serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "seq": r.get::<i64, _>("seq"),
                "method": r.get::<String, _>("method"),
                "url": r.get::<String, _>("url"),
                "host": r.get::<String, _>("host"),
                "path": r.get::<String, _>("path"),
                "response_status": r.get::<Option<i32>, _>("response_status"),
                "latency_ms": r.get::<Option<i32>, _>("latency_ms"),
                "admission_verdict": r.get::<String, _>("admission_verdict"),
                "firewall_blocked": r.get::<bool, _>("firewall_blocked"),
                "pii_in_request": r.get::<bool, _>("pii_in_request"),
                "pii_in_response": r.get::<bool, _>("pii_in_response"),
                "schema_drift": r.get::<bool, _>("schema_drift"),
                "drift_fields": r.get::<Vec<String>, _>("drift_fields"),
                "request_hash": r.get::<String, _>("request_hash"),
                "response_hash": r.get::<Option<String>, _>("response_hash"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            }))
            .collect::<Vec<_>>();
        let receipts_json = receipts
            .iter()
            .map(|r| serde_json::json!({
                "id": r.id,
                "capture_id": r.capture_id,
                "event_type": r.event_type,
                "seq": r.seq,
                "payload": r.payload,
                "hmac": r.hmac,
                "prev_hmac": r.prev_hmac,
                "created_at": r.created_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>();

        let content_sha256 = sha256::digest(serde_json::to_vec(&serde_json::json!({
            "captures": captures,
            "receipts": receipts_json,
        })).unwrap_or_default());
        let bundle_signature = compute_bundle_signature(&content_sha256, chain_head_hmac, &self.hmac_secret);
        let bundle = serde_json::json!({
            "bundle_type": BUNDLE_TYPE,
            "session": {
                "id": session.id,
                "upstream": session.upstream,
                "role": session.role,
                "mode": session.mode.to_string(),
                "status": "sealed",
                "frameworks": session.frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
                "proof_id": proof_id,
                "chain_head_hmac": chain_head_hmac,
                "receipt_seq": receipt_seq,
                "total_calls": total_calls,
                "total_blocked": total_blocked,
                "total_pii_hits": total_pii_hits,
                "cost_usd": cost_usd,
                "sealed_at": Utc::now().to_rfc3339(),
            },
            "verification_snapshot": {
                "chain_valid": chain_valid,
                "head_matches": head_matches,
                "tamper_detected": tamper_detected,
                "verified_at": Utc::now().to_rfc3339(),
            },
            "manifest": {
                "capture_count": captures.len(),
                "receipt_count": receipts_json.len(),
                "bundle_created_at": Utc::now().to_rfc3339(),
                "content_sha256": content_sha256,
            },
            "signature_metadata": {
                "algorithm": "hmac-sha256-chain+bundle-signature",
                "tsa_required": self.tsa_required,
                "tsa_url_configured": self.tsa_url.is_some(),
                "bundle_signature_fields": ["manifest.content_sha256", "session.chain_head_hmac"],
            },
            "bundle_signature": bundle_signature,
            "connector_proof": connector_proof.and_then(|p| serde_json::to_value(p).ok()),
            "captures": captures,
            "receipts": receipts_json,
        });

        let meta = serde_json::json!({
            "bundle_type": BUNDLE_TYPE,
            "primary_path": witness_path.display().to_string(),
            "legacy_path": legacy_path.display().to_string(),
            "session_id": session_id.to_string(),
            "proof_id": proof_id,
            "chain_head_hmac": chain_head_hmac,
            "sealed_at": Utc::now().to_rfc3339(),
            "verify_cli": "witnessctl-verify <primary_path> --hmac-secret $WITNESSCTL_HMAC_SECRET",
        });
        bundle_file::write_bundle_artifacts(&witness_path, &legacy_path, &meta_path, &bundle, &meta)
            .map_err(|e| AppError::Internal(format!("Failed to write witness bundle: {}", e)))?;
        Ok(witness_path.display().to_string())
    }

    async fn request_tsa_token(&self, session_id: Uuid, digest: &str) -> (String, Option<String>, Option<bool>, Option<String>) {
        let Some(tsa_url) = self.tsa_url.as_ref() else {
            return ("not_configured".to_string(), None, None, None);
        };
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "session_id": session_id,
            "digest": digest,
            "algorithm": "sha256",
            "source": "witnessctl",
        });
        match client.post(tsa_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        let token = body
                            .get("token")
                            .or_else(|| body.get("timestamp_token"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let verified = token
                            .as_ref()
                            .map(|t| self.verify_rfc3161_token(t, digest))
                            .or_else(|| body.get("verified").and_then(|v| v.as_bool()))
                            .or(Some(false));
                        let policy_oid = body
                            .get("policy_oid")
                            .or_else(|| body.get("policy"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        ("ok".to_string(), token, verified, policy_oid)
                    }
                    Err(_) => ("failed".to_string(), None, Some(false), None),
                }
            }
            _ => ("failed".to_string(), None, Some(false), None),
        }
    }

    fn verify_rfc3161_token(&self, token: &str, digest: &str) -> bool {
        let Some(ca_file) = self.tsa_ca_file.as_ref() else {
            return false;
        };
        let token_bytes = match base64::decode(token) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let dir = std::env::temp_dir();
        let nonce = uuid::Uuid::new_v4().to_string();
        let tsr_path = dir.join(format!("witnessctl-{}.tsr", nonce));
        let data_path = dir.join(format!("witnessctl-{}.txt", nonce));
        if std::fs::write(&tsr_path, token_bytes).is_err() {
            return false;
        }
        if std::fs::write(&data_path, digest.as_bytes()).is_err() {
            let _ = std::fs::remove_file(&tsr_path);
            return false;
        }
        let output = Command::new("openssl")
            .arg("ts")
            .arg("-verify")
            .arg("-in")
            .arg(&tsr_path)
            .arg("-data")
            .arg(&data_path)
            .arg("-CAfile")
            .arg(ca_file)
            .output();
        let _ = std::fs::remove_file(&tsr_path);
        let _ = std::fs::remove_file(&data_path);
        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    fn is_tsa_required_for_session(&self, frameworks: &[ComplianceFramework]) -> bool {
        frameworks
            .iter()
            .map(|f| f.to_string())
            .map(|s| s.to_lowercase())
            .any(|f| self.tsa_required_frameworks.contains(&f))
    }
}

fn public_base_url() -> String {
    if let Ok(base) = std::env::var("WITNESSCTL_BASE_URL") {
        let trimmed = base.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let host = std::env::var("WITNESSCTL_PUBLIC_HOST")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = std::env::var("WITNESSCTL_PORT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "7443".to_string());
    format!("http://{}:{}", host, port)
}

fn derive_tenant_id_from_session_token(token: &str) -> Uuid {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}
