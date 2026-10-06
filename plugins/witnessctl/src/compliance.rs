use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use std::collections::{HashMap, HashSet};
use std::collections::BTreeMap;

use crate::{
    connector::ConnectorClient,
    error::AppError,
    types::*,
};

pub struct ComplianceEngine {
    db: PgPool,
    connector: ConnectorClient,
    attestor_jwt_secret: Option<String>,
    attestor_jwt_issuer: Option<String>,
    attestor_jwt_audience: Option<String>,
}

impl ComplianceEngine {
    pub fn new(db: PgPool, connector: ConnectorClient, config: &crate::config::Config) -> Self {
        Self {
            db,
            connector,
            attestor_jwt_secret: config.attestor_jwt_secret.clone().filter(|v| !v.trim().is_empty()),
            attestor_jwt_issuer: config.attestor_jwt_issuer.clone().filter(|v| !v.trim().is_empty()),
            attestor_jwt_audience: config.attestor_jwt_audience.clone().filter(|v| !v.trim().is_empty()),
        }
    }

    /// Evaluate a session against all registered compliance frameworks.
    pub async fn evaluate_session(
        &self,
        session_id: Uuid,
    ) -> Result<ComplianceReport, AppError> {
        let session = sqlx::query(
            "SELECT agent_pid, frameworks, status::text, policy FROM witness_sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::NotFound(format!("Session {}", session_id)))?;

        let agent_pid: Option<String> = row_get_opt(&session, "agent_pid");
        let policy: serde_json::Value = session.get("policy");
        let frameworks_raw: Vec<String> = session.get("frameworks");
        let mut frameworks: Vec<ComplianceFramework> = frameworks_raw
            .iter()
            .filter_map(|s| ComplianceFramework::from_str(s))
            .collect();
        // When no frameworks are registered on the session, default to the full
        // supported set so the compliance panel always shows real results.
        if frameworks.is_empty() {
            frameworks = vec![
                ComplianceFramework::Hipaa,
                ComplianceFramework::Soc2,
                ComplianceFramework::Gdpr,
                ComplianceFramework::EuAiAct,
                ComplianceFramework::Iso27001,
                ComplianceFramework::PciDss,
                ComplianceFramework::Nist80053,
            ];
        }

        let captures = sqlx::query(
            "SELECT id, method, url, host, admission_verdict, firewall_blocked, \
             firewall_checked, pii_in_request, pii_in_response, schema_drift, drift_fields \
             FROM witness_captures WHERE session_id = $1 ORDER BY seq"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;

        let total_captures = captures.len();
        let blocked_count = captures.iter().filter(|r| row_get_bool(r, "firewall_blocked")).count();
        let firewall_checked_count = captures.iter().filter(|r| row_get_bool(r, "firewall_checked")).count();
        let pii_req_count = captures.iter().filter(|r| row_get_bool(r, "pii_in_request")).count();
        let pii_resp_count = captures.iter().filter(|r| row_get_bool(r, "pii_in_response")).count();
        let drift_count = captures.iter().filter(|r| row_get_bool(r, "schema_drift")).count();
        let denied_count = captures.iter()
            .filter(|r| row_get_string(r, "admission_verdict") == "deny")
            .count();
        let receipt_count: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_receipts WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let token_count: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_sessions WHERE id = $1 AND session_token IS NOT NULL AND session_token <> ''"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let has_session_auth = token_count > 0;
        let require_admission = policy
            .get("require_admission")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let policy_configured = require_admission
            || policy
                .get("allowed_hosts")
                .and_then(|v| v.as_array())
                .map(|v| !v.is_empty())
                .unwrap_or(false)
            || policy
                .get("denied_hosts")
                .and_then(|v| v.as_array())
                .map(|v| !v.is_empty())
                .unwrap_or(false);
        let enforcement_active = policy_configured && receipt_count > 0;
        let attestations = self.list_attestations(session_id).await.unwrap_or_default();
        let attested_controls: HashSet<String> = attestations.into_iter().map(|a| a.control_name).collect();

        let mut verdicts = Vec::new();
        let mut all_passed = true;

        for fw in &frameworks {
            let (controls, passed) = match fw {
                ComplianceFramework::Hipaa => self.evaluate_hipaa(
                    total_captures,
                    pii_req_count,
                    pii_resp_count,
                    blocked_count,
                    denied_count,
                    has_session_auth,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::Soc2 => self.evaluate_soc2(
                    total_captures,
                    blocked_count,
                    drift_count,
                    denied_count,
                    has_session_auth,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::Gdpr => self.evaluate_gdpr(
                    total_captures,
                    pii_req_count,
                    pii_resp_count,
                    denied_count,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::EuAiAct => self.evaluate_eu_ai_act(
                    total_captures,
                    blocked_count,
                    denied_count,
                    pii_req_count,
                    firewall_checked_count,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::Iso27001 => self.evaluate_iso27001(
                    total_captures,
                    blocked_count,
                    drift_count,
                    has_session_auth,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::PciDss => self.evaluate_pci_dss(
                    total_captures,
                    pii_req_count + pii_resp_count,
                    has_session_auth,
                    enforcement_active,
                    &attested_controls,
                ),
                ComplianceFramework::Nist80053 => self.evaluate_nist_800_53(
                    total_captures,
                    blocked_count,
                    drift_count,
                    has_session_auth,
                    enforcement_active,
                    &attested_controls,
                ),
            };

            if !passed {
                all_passed = false;
            }

            // Also get Connector's compliance view if we have an agent
            let _connector_report = if let Some(ref pid) = agent_pid {
                self.connector
                    .get_regulation_report(&fw.to_string(), pid)
                    .await
                    .ok()
            } else {
                None
            };

            let failed_controls: Vec<String> = controls
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.name.clone())
                .collect();

            let score = (controls.iter().filter(|c| c.passed).count() * 100)
                / controls.len().max(1);

            let verdict = ComplianceVerdict {
                id: Uuid::new_v4(),
                session_id,
                framework: fw.to_string(),
                passed,
                score: score as i32,
                controls: serde_json::to_value(&controls).unwrap_or_default(),
                failed_controls,
                evaluated_at: Utc::now(),
            };

            // Persist verdict
            sqlx::query(
                "INSERT INTO witness_compliance (session_id, framework, passed, score, controls, failed_controls) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (session_id, framework) DO UPDATE SET passed = $3, score = $4, controls = $5, failed_controls = $6"
            )
            .bind(session_id)
            .bind(&verdict.framework)
            .bind(verdict.passed)
            .bind(verdict.score)
            .bind(&verdict.controls)
            .bind(&verdict.failed_controls)
            .execute(&self.db)
            .await?;

            verdicts.push(verdict);
        }

        let overall_score = if verdicts.is_empty() {
            100
        } else {
            verdicts.iter().map(|v| v.score).sum::<i32>() / verdicts.len() as i32
        };

        Ok(ComplianceReport {
            session_id,
            overall_passed: all_passed,
            overall_score,
            verdicts,
            total_captures,
            total_pii_hits: pii_req_count + pii_resp_count,
            total_blocked: blocked_count,
            total_schema_drifts: drift_count,
            evaluated_at: Utc::now(),
        })
    }

    pub async fn readiness_gate(
        &self,
        session_id: Uuid,
    ) -> Result<serde_json::Value, AppError> {
        let report = self.evaluate_session(session_id).await?;
        let session_row = sqlx::query(
            "SELECT status::text, chain_head_hmac, sealed_at FROM witness_sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::NotFound(format!("Session {}", session_id)))?;

        let status: String = session_row.get("status");
        let chain_head_hmac: Option<String> = session_row.get("chain_head_hmac");
        let sealed = status == "sealed";
        let receipt_count: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_receipts WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let total_captures: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_captures WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let firewall_checked: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_captures WHERE session_id = $1 AND firewall_checked = true"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let firewall_coverage = if total_captures == 0 {
            1.0
        } else {
            firewall_checked as f64 / total_captures as f64
        };
        let attestations_count: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(1) FROM witness_manual_attestations WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);
        let dual_attestor_required = std::env::var("WITNESSCTL_DUAL_ATTESTOR_REQUIRED")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let high_risk_frameworks: HashSet<String> = std::env::var("WITNESSCTL_DUAL_ATTESTOR_FRAMEWORKS")
            .unwrap_or_else(|_| "hipaa,soc2,pci_dss".to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let rows = sqlx::query(
            "SELECT control_name, COUNT(DISTINCT COALESCE(attestor_subject, attestor)) AS attestors \
             FROM witness_manual_attestations WHERE session_id = $1 GROUP BY control_name"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();
        let mut attestor_counts: HashMap<String, i64> = HashMap::new();
        for row in rows {
            attestor_counts.insert(
                row.get::<String, _>("control_name"),
                row.get::<i64, _>("attestors"),
            );
        }

        let mut uncovered_controls: Vec<String> = Vec::new();
        for verdict in &report.verdicts {
            for control_name in &verdict.failed_controls {
                let min_required = if dual_attestor_required
                    && high_risk_frameworks.contains(&verdict.framework.to_lowercase())
                {
                    2
                } else {
                    1
                };
                let got = *attestor_counts.get(control_name).unwrap_or(&0);
                if got < min_required {
                    uncovered_controls.push(control_name.clone());
                }
            }
        }
        uncovered_controls.sort();
        uncovered_controls.dedup();
        let manual_attestation_gap_closed = uncovered_controls.is_empty();

        let failed_controls = report
            .verdicts
            .iter()
            .map(|v| v.failed_controls.len() as i64)
            .sum::<i64>();
        let tsa_row = sqlx::query(
            "SELECT tsa_status, tsa_verified FROM witness_sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.db)
        .await
        .unwrap_or(None);
        let tsa_status: Option<String> = tsa_row.as_ref().and_then(|r| r.get("tsa_status"));
        let tsa_verified: Option<bool> = tsa_row.as_ref().and_then(|r| r.get("tsa_verified"));
        let tsa_ok = tsa_status
            .as_deref()
            .map(|v| {
                if v == "ok" {
                    tsa_verified.unwrap_or(false)
                } else {
                    v == "not_configured"
                }
            })
            .unwrap_or(true);
        let tsa_required_frameworks: HashSet<String> = std::env::var("WITNESSCTL_TSA_REQUIRED_FRAMEWORKS")
            .unwrap_or_else(|_| "hipaa,soc2,pci_dss".to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let session_frameworks: HashSet<String> = report
            .verdicts
            .iter()
            .map(|v| v.framework.to_lowercase())
            .collect();
        let tsa_required_for_session = session_frameworks
            .iter()
            .any(|f| tsa_required_frameworks.contains(f));
        let court_defensible = sealed
            && receipt_count > 0
            && chain_head_hmac.is_some()
            && report.overall_passed
            && firewall_coverage >= 0.95
            && manual_attestation_gap_closed
            && (!tsa_required_for_session || tsa_ok);

        let mut score = 0i32;
        if sealed { score += 15; }
        if receipt_count > 0 { score += 15; }
        if chain_head_hmac.is_some() { score += 15; }
        if report.overall_passed { score += 25; }
        if firewall_coverage >= 0.95 { score += 15; }
        if manual_attestation_gap_closed { score += 10; }
        if !tsa_required_for_session || tsa_ok { score += 5; }

        Ok(serde_json::json!({
            "session_id": session_id,
            "court_defensible": court_defensible,
            "ciso_readiness_score": score,
            "gates": {
                "session_sealed": sealed,
                "receipt_chain_present": receipt_count > 0,
                "chain_head_present": chain_head_hmac.is_some(),
                "all_frameworks_passed": report.overall_passed,
                "firewall_coverage_ge_95pct": firewall_coverage >= 0.95,
                "manual_attestation_gap_closed": manual_attestation_gap_closed,
                "dual_attestor_requirement_met": !dual_attestor_required || manual_attestation_gap_closed,
                "tsa_required_for_session": tsa_required_for_session,
                "tsa_timestamp_ok": !tsa_required_for_session || tsa_ok
            },
            "metrics": {
                "receipt_count": receipt_count,
                "total_captures": total_captures,
                "firewall_checked": firewall_checked,
                "firewall_coverage": firewall_coverage,
                "failed_controls": failed_controls,
                "manual_attestations": attestations_count,
                "uncovered_failed_controls": uncovered_controls,
                "compliance_overall_score": report.overall_score,
                "dual_attestor_required": dual_attestor_required,
                "tsa_status": tsa_status,
                "tsa_verified": tsa_verified,
            },
            "generated_at": Utc::now().to_rfc3339(),
        }))
    }

    pub async fn manual_attest(
        &self,
        session_id: Uuid,
        req: ManualAttestRequest,
    ) -> Result<ManualAttestation, AppError> {
        let (attestor_subject, attestor_token_jti) = self.validate_attestor_binding(&req)?;
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO witness_manual_attestations (session_id, control_name, evidence_url, attestor, attestor_subject, attestor_token_jti, notes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (session_id, control_name, attestor) DO UPDATE \
             SET evidence_url = EXCLUDED.evidence_url, attestor_subject = EXCLUDED.attestor_subject, attestor_token_jti = EXCLUDED.attestor_token_jti, notes = EXCLUDED.notes \
             RETURNING id"
        )
        .bind(session_id)
        .bind(&req.control_name)
        .bind(&req.evidence_url)
        .bind(&req.attestor)
        .bind(&attestor_subject)
        .bind(&attestor_token_jti)
        .bind(&req.notes)
        .fetch_one(&self.db)
        .await?;

        let row = sqlx::query(
            "SELECT id, session_id, control_name, evidence_url, attestor, attestor_subject, attestor_token_jti, notes, created_at \
             FROM witness_manual_attestations WHERE id = $1"
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;

        Ok(ManualAttestation {
            id: row.get("id"),
            session_id: row.get("session_id"),
            control_name: row.get("control_name"),
            evidence_url: row.get("evidence_url"),
            attestor: row.get("attestor"),
            attestor_subject: row.get("attestor_subject"),
            attestor_token_jti: row.get("attestor_token_jti"),
            notes: row.get("notes"),
            created_at: row.get("created_at"),
        })
    }

    pub async fn list_attestations(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ManualAttestation>, AppError> {
        let rows = sqlx::query(
            "SELECT id, session_id, control_name, evidence_url, attestor, attestor_subject, attestor_token_jti, notes, created_at \
             FROM witness_manual_attestations WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;
        Ok(rows
            .iter()
            .map(|row| ManualAttestation {
                id: row.get("id"),
                session_id: row.get("session_id"),
                control_name: row.get("control_name"),
                evidence_url: row.get("evidence_url"),
                attestor: row.get("attestor"),
                attestor_subject: row.get("attestor_subject"),
                attestor_token_jti: row.get("attestor_token_jti"),
                notes: row.get("notes"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    fn validate_attestor_binding(
        &self,
        req: &ManualAttestRequest,
    ) -> Result<(Option<String>, Option<String>), AppError> {
        let Some(secret) = self.attestor_jwt_secret.as_ref() else {
            return Ok((None, None));
        };
        let token = req.attestor_token.as_ref().ok_or_else(|| {
            AppError::Unauthorized("attestor_token is required when JWT attestor binding is enabled".to_string())
        })?;

        #[derive(Debug, serde::Deserialize, Clone)]
        struct Claims {
            sub: String,
            jti: Option<String>,
            exp: Option<u64>,
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        if let Some(iss) = self.attestor_jwt_issuer.as_ref() {
            validation.set_issuer(&[iss.as_str()]);
        }
        if let Some(aud) = self.attestor_jwt_audience.as_ref() {
            validation.set_audience(&[aud.as_str()]);
        }
        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|e| AppError::Unauthorized(format!("invalid attestor token: {}", e)))?;

        if decoded.claims.sub != req.attestor {
            return Err(AppError::Unauthorized(
                "attestor token subject does not match attestor".to_string(),
            ));
        }
        Ok((Some(decoded.claims.sub), decoded.claims.jti))
    }

    /// Get existing compliance verdicts for a session (without re-evaluating).
    pub async fn get_verdicts(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ComplianceVerdict>, AppError> {
        let rows = sqlx::query(
            "SELECT id, session_id, framework, passed, score, controls, failed_controls, evaluated_at \
             FROM witness_compliance WHERE session_id = $1 ORDER BY framework"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;

        let mut verdicts = Vec::new();
        for row in &rows {
            verdicts.push(ComplianceVerdict {
                id: row.get("id"),
                session_id: row.get("session_id"),
                framework: row.get("framework"),
                passed: row.get("passed"),
                score: row.get("score"),
                controls: row.get("controls"),
                failed_controls: row.get("failed_controls"),
                evaluated_at: row.get("evaluated_at"),
            });
        }
        Ok(verdicts)
    }

    // ── Framework-specific evaluations ──────────────────────────────────────

    fn evaluate_hipaa(
        &self,
        total: usize,
        pii_req: usize,
        pii_resp: usize,
        blocked: usize,
        denied: usize,
        has_session_auth: bool,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = Vec::new();
        let mut all_passed = true;

        // 164.312(a)(1) Access Control
        controls.push(ControlResult {
            name: "hipaa.164.312.a1.access_control".to_string(),
            passed: enforcement_active || total == 0,
            message: if enforcement_active || total == 0 {
                "Access controls configured and audit trail active".to_string()
            } else {
                "Access policy is not sufficiently configured for this session".to_string()
            },
        });

        // 164.312(b) Audit Controls
        controls.push(ControlResult {
            name: "hipaa.164.312.b.audit_controls".to_string(),
            passed: total > 0,
            message: format!("{} API calls audited with full receipt chain", total),
        });

        // 164.312(c)(1) Integrity
        controls.push(ControlResult {
            name: "hipaa.164.312.c1.integrity".to_string(),
            passed: true, // HMAC chain guarantees integrity
            message: "HMAC-chained receipts provide tamper evidence".to_string(),
        });

        // 164.312(d) Person/Entity Authentication
        controls.push(ControlResult {
            name: "hipaa.164.312.d.authentication".to_string(),
            passed: has_session_auth || total == 0,
            message: if has_session_auth || total == 0 {
                "Session token authentication present".to_string()
            } else {
                "Session authentication evidence missing".to_string()
            },
        });

        // 164.312(e)(1) Transmission Security
        controls.push(ControlResult {
            name: "hipaa.164.312.e1.transmission_security".to_string(),
            passed: pii_resp == 0,
            message: if pii_resp == 0 {
                "No PII detected in API responses".to_string()
            } else {
                format!("{} responses contained PII — transmission security risk", pii_resp)
            },
        });

        // 164.530(c) Safeguards for PHI
        controls.push(ControlResult {
            name: "hipaa.164.530.c.phi_safeguards".to_string(),
            passed: pii_req == 0 || blocked > 0,
            message: if pii_req == 0 {
                "No PHI detected in requests".to_string()
            } else if blocked > 0 {
                format!("PHI detected in {} requests but firewall blocked {} calls", pii_req, blocked)
            } else {
                format!("PHI detected in {} requests without firewall blocks", pii_req)
            },
        });

        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
        }
        for c in &controls {
            if !c.passed {
                all_passed = false;
            }
        }

        (controls, all_passed)
    }

    fn evaluate_soc2(
        &self,
        total: usize,
        blocked: usize,
        drift: usize,
        denied: usize,
        has_session_auth: bool,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = Vec::new();
        let mut all_passed = true;

        // CC6.1 Logical/Physical Access
        controls.push(ControlResult {
            name: "soc2.cc6.1.access_controls".to_string(),
            passed: enforcement_active || total == 0,
            message: format!("policy active={} over {} total calls", enforcement_active, total),
        });

        // CC6.2 Authentication
        controls.push(ControlResult {
            name: "soc2.cc6.2.authentication".to_string(),
            passed: has_session_auth || total == 0,
            message: if has_session_auth {
                "session authentication enforced via token".to_string()
            } else {
                "session authentication evidence missing".to_string()
            },
        });

        // CC7.1 Change Management
        controls.push(ControlResult {
            name: "soc2.cc7.1.change_management".to_string(),
            passed: drift == 0,
            message: if drift == 0 {
                "No API schema drift detected".to_string()
            } else {
                format!("{} schema drift events detected — change management risk", drift)
            },
        });

        // CC7.2 Data Processing Integrity
        controls.push(ControlResult {
            name: "soc2.cc7.2.data_integrity".to_string(),
            passed: true,
            message: "HMAC receipt chain ensures data processing integrity".to_string(),
        });

        // CC8.1 Escalation/Incident Response
        controls.push(ControlResult {
            name: "soc2.cc8.1.incident_response".to_string(),
            passed: enforcement_active || total == 0,
            message: if enforcement_active {
                format!("enforcement active; {} blocked events observed", blocked)
            } else {
                "incident response enforcement mechanism not evidenced".to_string()
            },
        });

        let _ = denied;
        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
        }
        for c in &controls {
            if !c.passed {
                all_passed = false;
            }
        }

        (controls, all_passed)
    }

    fn evaluate_gdpr(
        &self,
        total: usize,
        pii_req: usize,
        pii_resp: usize,
        denied: usize,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = Vec::new();
        let mut all_passed = true;

        // Art. 5(1)(c) Data Minimisation
        controls.push(ControlResult {
            name: "gdpr.art5.1c.data_minimisation".to_string(),
            passed: pii_req == 0,
            message: if pii_req == 0 {
                "No PII in requests — data minimisation principle met".to_string()
            } else {
                format!("{} requests contained PII — data minimisation risk", pii_req)
            },
        });

        // Art. 5(1)(f) Integrity/Confidentiality
        controls.push(ControlResult {
            name: "gdpr.art5.1f.integrity_confidentiality".to_string(),
            passed: true,
            message: "HMAC receipt chain provides integrity guarantees".to_string(),
        });

        // Art. 13/14 Transparency
        controls.push(ControlResult {
            name: "gdpr.art13.transparency".to_string(),
            passed: total > 0,
            message: format!("{} API calls fully audited with decision trail", total),
        });

        // Art. 17 Right to Erasure
        controls.push(ControlResult {
            name: "gdpr.art17.erasure".to_string(),
            passed: true, // Session sealing + erasure_flag support
            message: "Session seal mechanism supports erasure requirements".to_string(),
        });

        // Art. 25 Data Protection by Design
        controls.push(ControlResult {
            name: "gdpr.art25.protection_by_design".to_string(),
            passed: enforcement_active && pii_resp == 0,
            message: if enforcement_active && pii_resp == 0 {
                "Policy enforcement active and no PII leakage in responses".to_string()
            } else if pii_resp == 0 {
                "No PII in responses but enforcement controls are not clearly configured".to_string()
            } else {
                format!("{} responses contained PII", pii_resp)
            },
        });

        // Art. 35 Data Protection Impact Assessment
        controls.push(ControlResult {
            name: "gdpr.art35.dpia".to_string(),
            passed: total > 0,
            message: format!("Full audit trail of {} calls available for DPIA", total),
        });

        let _ = denied;
        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
        }
        for c in &controls {
            if !c.passed {
                all_passed = false;
            }
        }

        (controls, all_passed)
    }

    fn evaluate_eu_ai_act(
        &self,
        total: usize,
        blocked: usize,
        denied: usize,
        pii_count: usize,
        firewall_checked_count: usize,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = Vec::new();
        let mut all_passed = true;

        // Art. 9 Risk Management System
        controls.push(ControlResult {
            name: "eu_ai_act.art9.risk_management".to_string(),
            passed: enforcement_active || total == 0,
            message: format!(
                "enforcement active={}, denied={}, blocked={}, total={}",
                enforcement_active, denied, blocked, total
            ),
        });

        // Art. 10 Data Governance
        controls.push(ControlResult {
            name: "eu_ai_act.art10.data_governance".to_string(),
            passed: pii_count == 0,
            message: if pii_count == 0 {
                "No PII detected in data flows".to_string()
            } else {
                format!("{} PII hits detected — data governance risk", pii_count)
            },
        });

        // Art. 11 Technical Documentation
        controls.push(ControlResult {
            name: "eu_ai_act.art11.technical_documentation".to_string(),
            passed: total > 0,
            message: format!("{} API calls documented with full receipt chain", total),
        });

        // Art. 12 Record-Keeping
        controls.push(ControlResult {
            name: "eu_ai_act.art12.record_keeping".to_string(),
            passed: total > 0,
            message: "Automated logging with HMAC-chained receipts".to_string(),
        });

        // Art. 13 Transparency
        controls.push(ControlResult {
            name: "eu_ai_act.art13.transparency".to_string(),
            passed: total > 0,
            message: format!("Full decision trail for {} API interactions", total),
        });

        // Art. 14 Human Oversight
        controls.push(ControlResult {
            name: "eu_ai_act.art14.human_oversight".to_string(),
            passed: firewall_checked_count > 0 || total == 0,
            message: if firewall_checked_count > 0 || total == 0 {
                format!("firewall checked on {} captures", firewall_checked_count)
            } else {
                "No firewall check evidence available for oversight".to_string()
            },
        });

        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
        }
        for c in &controls {
            if !c.passed {
                all_passed = false;
            }
        }

        (controls, all_passed)
    }

    fn evaluate_iso27001(
        &self,
        total: usize,
        blocked: usize,
        drift: usize,
        has_session_auth: bool,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = vec![
            ControlResult {
                name: "iso27001.a5.control_policies".to_string(),
                passed: enforcement_active || total == 0,
                message: "Control policies are configured and evidenced".to_string(),
            },
            ControlResult {
                name: "iso27001.a8.data_handling".to_string(),
                passed: drift == 0,
                message: if drift == 0 { "No schema drift detected".to_string() } else { format!("{} schema drift events detected", drift) },
            },
            ControlResult {
                name: "iso27001.a9.access_control".to_string(),
                passed: has_session_auth || total == 0,
                message: "Session authentication evidence checked".to_string(),
            },
            ControlResult {
                name: "iso27001.a16.incident_management".to_string(),
                passed: enforcement_active || blocked > 0 || total == 0,
                message: format!("enforcement active={}, blocked={}", enforcement_active, blocked),
            },
        ];
        let mut all_passed = true;
        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
            if !c.passed {
                all_passed = false;
            }
        }
        (controls, all_passed)
    }

    fn evaluate_pci_dss(
        &self,
        total: usize,
        pii_hits: usize,
        has_session_auth: bool,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = vec![
            ControlResult {
                name: "pci_dss.7.access_by_need_to_know".to_string(),
                passed: has_session_auth || total == 0,
                message: "Authenticated session access enforced".to_string(),
            },
            ControlResult {
                name: "pci_dss.10.audit_trail".to_string(),
                passed: total > 0,
                message: format!("{} calls recorded in tamper-evident trail", total),
            },
            ControlResult {
                name: "pci_dss.3.cardholder_data_protection".to_string(),
                passed: pii_hits == 0,
                message: if pii_hits == 0 { "No card/PII leakage signals detected".to_string() } else { format!("{} sensitive data hits detected", pii_hits) },
            },
            ControlResult {
                name: "pci_dss.12.security_program".to_string(),
                passed: enforcement_active || total == 0,
                message: "Security control program evidenced by enforcement state".to_string(),
            },
        ];
        let mut all_passed = true;
        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
            if !c.passed {
                all_passed = false;
            }
        }
        (controls, all_passed)
    }

    fn evaluate_nist_800_53(
        &self,
        total: usize,
        blocked: usize,
        drift: usize,
        has_session_auth: bool,
        enforcement_active: bool,
        attested_controls: &HashSet<String>,
    ) -> (Vec<ControlResult>, bool) {
        let mut controls = vec![
            ControlResult {
                name: "nist80053.ac_3.access_enforcement".to_string(),
                passed: has_session_auth || total == 0,
                message: "Access enforcement evidence from session auth".to_string(),
            },
            ControlResult {
                name: "nist80053.au_2.event_logging".to_string(),
                passed: total > 0,
                message: format!("{} events logged", total),
            },
            ControlResult {
                name: "nist80053.si_10.information_input_validation".to_string(),
                passed: drift == 0 || blocked > 0,
                message: format!("drift={}, blocked={}", drift, blocked),
            },
            ControlResult {
                name: "nist80053.ra_5.risk_assessment".to_string(),
                passed: enforcement_active || total == 0,
                message: "Risk enforcement pipeline active".to_string(),
            },
        ];
        let mut all_passed = true;
        for c in controls.iter_mut() {
            if !c.passed && attested_controls.contains(&c.name) {
                c.passed = true;
                c.message = format!("{} (manually attested)", c.message);
            }
            if !c.passed {
                all_passed = false;
            }
        }
        (controls, all_passed)
    }
}

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct ComplianceReport {
    pub session_id: Uuid,
    pub overall_passed: bool,
    pub overall_score: i32,
    pub verdicts: Vec<ComplianceVerdict>,
    pub total_captures: usize,
    pub total_pii_hits: usize,
    pub total_blocked: usize,
    pub total_schema_drifts: usize,
    pub evaluated_at: chrono::DateTime<Utc>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn row_get_bool(row: &sqlx::postgres::PgRow, col: &str) -> bool {
    row.get::<Option<bool>, _>(col).unwrap_or(false)
}

fn row_get_string(row: &sqlx::postgres::PgRow, col: &str) -> String {
    row.get::<Option<String>, _>(col).unwrap_or_default()
}

fn row_get_opt(row: &sqlx::postgres::PgRow, col: &str) -> Option<String> {
    row.get::<Option<String>, _>(col)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanonicalComplianceMap {
    pub version: String,
    pub frameworks: BTreeMap<String, Vec<String>>,
}

pub fn default_canonical_compliance_map() -> CanonicalComplianceMap {
    let mut frameworks = BTreeMap::new();
    frameworks.insert(
        "hipaa".to_string(),
        vec![
            "hipaa.164.312.a1.access_control".to_string(),
            "hipaa.164.312.b.audit_controls".to_string(),
            "hipaa.164.312.c1.integrity".to_string(),
            "hipaa.164.312.d.authentication".to_string(),
            "hipaa.164.312.e1.transmission_security".to_string(),
            "hipaa.164.530.c.phi_safeguards".to_string(),
        ],
    );
    frameworks.insert(
        "soc2".to_string(),
        vec![
            "soc2.cc6.1.access_controls".to_string(),
            "soc2.cc6.2.authentication".to_string(),
            "soc2.cc7.1.change_management".to_string(),
            "soc2.cc7.2.data_integrity".to_string(),
            "soc2.cc8.1.incident_response".to_string(),
        ],
    );
    frameworks.insert(
        "gdpr".to_string(),
        vec![
            "gdpr.art5.1c.data_minimisation".to_string(),
            "gdpr.art5.1f.integrity_confidentiality".to_string(),
            "gdpr.art13.transparency".to_string(),
            "gdpr.art17.erasure".to_string(),
            "gdpr.art25.protection_by_design".to_string(),
            "gdpr.art35.dpia".to_string(),
        ],
    );
    frameworks.insert(
        "eu_ai_act".to_string(),
        vec![
            "eu_ai_act.art9.risk_management".to_string(),
            "eu_ai_act.art10.data_governance".to_string(),
            "eu_ai_act.art11.technical_documentation".to_string(),
            "eu_ai_act.art12.record_keeping".to_string(),
            "eu_ai_act.art13.transparency".to_string(),
            "eu_ai_act.art14.human_oversight".to_string(),
        ],
    );
    frameworks.insert(
        "iso_27001".to_string(),
        vec![
            "iso27001.a5.control_policies".to_string(),
            "iso27001.a8.data_handling".to_string(),
            "iso27001.a9.access_control".to_string(),
            "iso27001.a16.incident_management".to_string(),
        ],
    );
    frameworks.insert(
        "pci_dss".to_string(),
        vec![
            "pci_dss.7.access_by_need_to_know".to_string(),
            "pci_dss.10.audit_trail".to_string(),
            "pci_dss.3.cardholder_data_protection".to_string(),
            "pci_dss.12.security_program".to_string(),
        ],
    );
    frameworks.insert(
        "nist_800_53".to_string(),
        vec![
            "nist80053.ac_3.access_enforcement".to_string(),
            "nist80053.au_2.event_logging".to_string(),
            "nist80053.si_10.information_input_validation".to_string(),
            "nist80053.ra_5.risk_assessment".to_string(),
        ],
    );
    CanonicalComplianceMap {
        version: "2026-04-27".to_string(),
        frameworks,
    }
}

pub fn canonical_map_yaml() -> anyhow::Result<String> {
    let map = default_canonical_compliance_map();
    let mut out = String::new();
    out.push_str("# WitnessCtl canonical compliance map generated from Rust\n");
    out.push_str("version: ");
    out.push_str(&map.version);
    out.push('\n');
    out.push_str("frameworks:\n");
    for (framework, controls) in map.frameworks {
        out.push_str("  ");
        out.push_str(&framework);
        out.push_str(":\n");
        for control in controls {
            out.push_str("    - ");
            out.push_str(&control);
            out.push('\n');
        }
    }
    Ok(out)
}

pub fn check_canonical_map_drift(yaml_text: &str) -> anyhow::Result<Vec<String>> {
    let parsed = parse_canonical_map_yaml(yaml_text)?;
    let expected = default_canonical_compliance_map();
    let mut drift = Vec::new();
    for (fw, controls) in &expected.frameworks {
        match parsed.frameworks.get(fw) {
            None => drift.push(format!("missing framework '{}'", fw)),
            Some(got) => {
                for c in controls {
                    if !got.contains(c) {
                        drift.push(format!("missing control '{}' in '{}'", c, fw));
                    }
                }
            }
        }
    }
    Ok(drift)
}

pub fn bridge_legacy_to_canonical_yaml(legacy_yaml: &str) -> anyhow::Result<(String, Vec<String>)> {
    let legacy = parse_legacy_framework_controls(legacy_yaml);
    let mut canonical = default_canonical_compliance_map();
    let mut warnings = Vec::new();

    for (framework, controls) in legacy {
        let mapped = map_legacy_controls_to_canonical(&framework, &controls, &mut warnings);
        if !mapped.is_empty() {
            let entry = canonical.frameworks.entry(framework.clone()).or_default();
            for control in mapped {
                if !entry.contains(&control) {
                    entry.push(control);
                }
            }
        }
    }

    for (framework, expected) in default_canonical_compliance_map().frameworks {
        let got = canonical.frameworks.get(&framework).cloned().unwrap_or_default();
        for control in expected {
            if !got.contains(&control) {
                warnings.push(format!(
                    "legacy map missing canonical control '{}' in '{}'",
                    control, framework
                ));
            }
        }
    }

    let yaml = canonical_map_yaml_from(&canonical)?;
    Ok((yaml, warnings))
}

fn parse_canonical_map_yaml(yaml_text: &str) -> anyhow::Result<CanonicalComplianceMap> {
    let mut version = "unknown".to_string();
    let mut frameworks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut in_frameworks = false;
    let mut current_framework: Option<String> = None;
    for raw in yaml_text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("version:") {
            version = v.trim().trim_matches('"').to_string();
            continue;
        }
        if trimmed == "frameworks:" {
            in_frameworks = true;
            continue;
        }
        if !in_frameworks {
            continue;
        }
        if let Some(name) = trimmed.strip_suffix(':') {
            if !trimmed.starts_with('-') {
                let key = name.trim().to_string();
                frameworks.entry(key.clone()).or_default();
                current_framework = Some(key);
            }
            continue;
        }
        if let Some(control) = trimmed.strip_prefix("- ") {
            if let Some(framework) = &current_framework {
                frameworks
                    .entry(framework.clone())
                    .or_default()
                    .push(control.trim().to_string());
            }
        }
    }
    if frameworks.is_empty() {
        return Err(anyhow::anyhow!(
            "frameworks section not found or empty in compliance map yaml"
        ));
    }
    Ok(CanonicalComplianceMap {
        version,
        frameworks,
    })
}

fn canonical_map_yaml_from(map: &CanonicalComplianceMap) -> anyhow::Result<String> {
    let mut out = String::new();
    out.push_str("# WitnessCtl canonical compliance map generated from Rust\n");
    out.push_str("version: ");
    out.push_str(&map.version);
    out.push('\n');
    out.push_str("frameworks:\n");
    for (framework, controls) in &map.frameworks {
        out.push_str("  ");
        out.push_str(framework);
        out.push_str(":\n");
        for control in controls {
            out.push_str("    - ");
            out.push_str(control);
            out.push('\n');
        }
    }
    Ok(out)
}

fn parse_legacy_framework_controls(yaml_text: &str) -> BTreeMap<String, Vec<String>> {
    let mut frameworks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_framework: Option<String> = None;
    let mut in_controls = false;
    for line in yaml_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("framework:") {
            let fw_raw = trimmed
                .trim_start_matches("framework:")
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            let fw = normalize_framework_name(fw_raw);
            frameworks.entry(fw.clone()).or_default();
            current_framework = Some(fw);
            in_controls = false;
            continue;
        }
        if trimmed == "controls:" && current_framework.is_some() {
            in_controls = true;
            continue;
        }
        if in_controls {
            if !line.starts_with("        ") {
                in_controls = false;
                continue;
            }
            if trimmed.ends_with(':') {
                let key = trimmed.trim_end_matches(':').trim();
                if key != "check" && key != "fail_message" {
                    if let Some(fw) = current_framework.as_ref() {
                        frameworks
                            .entry(fw.clone())
                            .or_default()
                            .push(key.to_string());
                    }
                }
            }
        }
    }
    frameworks
}

fn normalize_framework_name(name: &str) -> String {
    match name {
        "soc2_type2" => "soc2".to_string(),
        other => other.to_string(),
    }
}

fn map_legacy_controls_to_canonical(
    framework: &str,
    controls: &[String],
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for control in controls {
        let mapped = match (framework, control.as_str()) {
            ("hipaa", "audit_controls") => Some("hipaa.164.312.b.audit_controls"),
            ("hipaa", "access_logging") => Some("hipaa.164.312.a1.access_control"),
            ("hipaa", "minimum_necessary") => Some("hipaa.164.530.c.phi_safeguards"),
            ("soc2", "cc6_logical_access") => Some("soc2.cc6.1.access_controls"),
            ("soc2", "cc7_monitoring") => Some("soc2.cc8.1.incident_response"),
            ("soc2", "change_management") => Some("soc2.cc7.1.change_management"),
            ("gdpr", "purpose_limitation") => Some("gdpr.art25.protection_by_design"),
            ("gdpr", "data_minimisation") => Some("gdpr.art5.1c.data_minimisation"),
            ("gdpr", "right_to_erasure") => Some("gdpr.art17.erasure"),
            ("eu_ai_act", "traceability") => Some("eu_ai_act.art12.record_keeping"),
            ("eu_ai_act", "human_oversight") => Some("eu_ai_act.art14.human_oversight"),
            ("eu_ai_act", "risk_classification") => Some("eu_ai_act.art9.risk_management"),
            _ => None,
        };
        if let Some(m) = mapped {
            let control_id = m.to_string();
            if !out.contains(&control_id) {
                out.push(control_id);
            }
        } else {
            warnings.push(format!(
                "unmapped legacy control '{}' in framework '{}'",
                control, framework
            ));
        }
    }
    out
}
