use std::collections::HashMap;

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use crate::{config::Config, connector::ConnectorClient, error::AppError, pii::{scan_json, scan_text},
    receipt::generate_receipt,
    schema::{detect_drift, infer_schema},
    types::*,
};

pub struct CaptureEngine {
    db: PgPool,
    connector: ConnectorClient,
    hmac_secret: String,
    firewall_timeout_ms: u64,
    strict_mode: bool,
}

fn header_value_ci(headers: &HashMap<String, String>, name: &'static str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Extracted FNI from request headers (P6.4).
struct FniExtract {
    flow_id: String,
    /// Raw CFNI wire (base64url JSON) when header decodes as ForensicFlowIdentityV2.
    cfni_wire: Option<String>,
    /// Always `unverified` at ingest — verify only via dedicated GET.
    verify_status: &'static str,
}

/// Extract `fni_flow_id` (+ optional CFNI wire) from `X-Connector-FNI` / `x-connector-flow-id`.
fn fni_from_headers(headers: &HashMap<String, String>) -> Option<FniExtract> {
    let raw = header_value_ci(headers, "x-connector-fni")
        .or_else(|| header_value_ci(headers, connector_trust::CFNI_HEADER))?;
    if let Ok(id) = connector_trust::decode_header_value(&raw) {
        return Some(FniExtract {
            flow_id: id.flow_id,
            cfni_wire: Some(raw),
            verify_status: "unverified",
        });
    }
    // Plain flow id (lab / proxy passthrough) when not a CFNI envelope.
    Some(FniExtract {
        flow_id: raw,
        cfni_wire: None,
        verify_status: "unverified",
    })
}

/// Resolve CFNI HMAC secret from env (same contract as platform substrate).
pub fn cfni_secret_from_env() -> Option<Vec<u8>> {
    std::env::var("CONNECTOR_CFNI_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
}

/// Run CFNI verify against stored wire; returns status string (never decorative).
pub fn verify_cfni_wire(wire: &str) -> (&'static str, Option<&'static str>) {
    let Some(secret) = cfni_secret_from_env() else {
        return ("unverified", Some("cfni_secret_unavailable"));
    };
    let Ok(id) = connector_trust::decode_header_value(wire) else {
        return ("invalid", Some("bad_cfni_wire"));
    };
    let now = chrono::Utc::now().timestamp_millis();
    match connector_trust::verify_flow_identity(&id, &secret, now) {
        Ok(()) => ("verified", None),
        Err("expired") => ("invalid", Some("expired")),
        Err("bad_signature") => ("invalid", Some("bad_signature")),
        Err(other) => ("invalid", Some(other)),
    }
}

impl CaptureEngine {
    pub fn new(db: PgPool, connector: ConnectorClient, config: &Config) -> Self {
        Self {
            db,
            connector,
            hmac_secret: config.hmac_secret.clone(),
            firewall_timeout_ms: config.firewall_timeout_ms,
            strict_mode: config.strict_mode,
        }
    }

    pub async fn ingest(&self, session_id: Uuid, req: RawRequest, resp: Option<RawResponse>) 
        -> Result<CaptureResponse, AppError> {
        self.ingest_with_route_attestation(session_id, req, resp, false).await
    }

    pub async fn ingest_with_route_attestation(
        &self,
        session_id: Uuid,
        req: RawRequest,
        resp: Option<RawResponse>,
        observed_via_witness_route: bool,
    )
        -> Result<CaptureResponse, AppError> {
        let row = sqlx::query("SELECT tenant_id, agent_pid, status::text, chain_head_hmac, receipt_seq FROM witness_sessions WHERE id = $1")
            .bind(session_id).fetch_optional(&self.db).await?.ok_or(AppError::NotFound(format!("Session {}", session_id)))?;
        let tenant_id: Uuid = row.get("tenant_id");
        let status: String = row.get("status");
        if status == "sealed" { return Err(AppError::SessionSealed); }
        let agent_pid: String = row.get("agent_pid");
        let chain_head: Option<String> = row.get("chain_head_hmac");
        let receipt_seq: i64 = row.get("receipt_seq");

        let (host, path) = parse_url(&req.url);
        let idempotency_key = req
            .headers
            .get("x-witness-idempotency-key")
            .or_else(|| req.headers.get("x-idempotency-key"))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        if let Some(key) = &idempotency_key {
            if let Some(existing) = sqlx::query(
                "SELECT id, seq, admission_verdict, firewall_blocked, pii_in_request, pii_in_response, schema_drift, latency_ms \
                 FROM witness_captures WHERE session_id = $1 AND ingest_idempotency_key = $2"
            )
            .bind(session_id)
            .bind(key)
            .fetch_optional(&self.db)
            .await?
            {
                let capture_id: Uuid = existing.get("id");
                let seq: i64 = existing.get("seq");
                let verdict_str: String = existing.get("admission_verdict");
                let admission_verdict = match verdict_str.as_str() {
                    "deny" => AdmissionVerdict::Deny,
                    "hold" => AdmissionVerdict::Hold,
                    _ => AdmissionVerdict::Allow,
                };
                let receipt_id: Uuid = sqlx::query_scalar(
                    "SELECT id FROM witness_receipts WHERE capture_id = $1 ORDER BY created_at DESC LIMIT 1"
                )
                .bind(capture_id)
                .fetch_optional(&self.db)
                .await?
                .unwrap_or_else(Uuid::new_v4);
                return Ok(CaptureResponse {
                    capture_id,
                    receipt_id,
                    seq,
                    admission_verdict,
                    firewall_blocked: existing.get("firewall_blocked"),
                    pii_in_request: existing.get("pii_in_request"),
                    pii_in_response: existing.get("pii_in_response"),
                    schema_drift: existing.get("schema_drift"),
                    forwarded: false,
                    response: None,
                    latency_ms: existing.get("latency_ms"),
                });
            }
        }
        let tracetramp_trace_id = header_value_ci(&req.headers, "x-trace-id");
        let tracetramp_request_id = header_value_ci(&req.headers, "x-request-id");
        let fni = fni_from_headers(&req.headers);
        let fni_flow_id = fni.as_ref().map(|f| f.flow_id.clone());
        let fni_verify_status = fni.as_ref().map(|f| f.verify_status.to_string());
        let fni_cfni_wire = fni.as_ref().and_then(|f| f.cfni_wire.clone());
        let req_body = req.body.as_deref().unwrap_or("");
        let req_hash = hex::encode(Sha256::digest(req_body.as_bytes()));

        let pii_req = match serde_json::from_str::<serde_json::Value>(req_body) {
            Ok(v) => scan_json(&v, ""),
            Err(_) => scan_text(req_body),
        };
        let has_pii_req = !pii_req.is_empty();

        let adm = self.connector.policy_check(&agent_pid, "api.call", &req.url).await?;
        let admission_verdict = match adm.verdict.as_str() {
            "deny" => AdmissionVerdict::Deny, "hold" => AdmissionVerdict::Hold, _ => AdmissionVerdict::Allow
        };

        let (fw_blocked, fw_checked, fw_status, fw_reason) = if self.strict_mode {
            let fw = tokio::time::timeout(
                std::time::Duration::from_millis(self.firewall_timeout_ms),
                self.connector
                    .firewall_inspect(&agent_pid, req_body, &format!("witness/{}", session_id)),
            )
            .await;
            match fw {
                Ok(Ok(resp)) => (
                    resp.blocked,
                    true,
                    Some("ok".to_string()),
                    resp.final_decision,
                ),
                Ok(Err(err)) => {
                    return Err(err);
                }
                Err(_) => {
                    return Err(AppError::FirewallBlocked(format!(
                        "firewall check timed out after {}ms in strict mode",
                        self.firewall_timeout_ms
                    )));
                }
            }
        } else {
            (
                false,
                false,
                Some("pending_async".to_string()),
                Some("firewall deferred to async worker".to_string()),
            )
        };

        let (mut drift, mut drift_fields) = (false, vec![]);
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(req_body) {
            let new = infer_schema(&j);
            if let Some(ex) = sqlx::query("SELECT request_schema FROM witness_schemas WHERE session_id=$1 AND host=$2 AND path=$3 AND method=$4")
                .bind(session_id).bind(&host).bind(&path).bind(&req.method).fetch_optional(&self.db).await? {
                let prev: crate::schema::InferredSchema = serde_json::from_value(ex.get("request_schema")).unwrap_or_default();
                let d = detect_drift(&prev, &new, "request");
                drift = !d.is_empty(); drift_fields = d.iter().map(|x| x.field_path.clone()).collect();
            }
        }

        // Body previews — first 600 chars, never storing full PII content (we store hashes for integrity)
        let req_body_preview: Option<String> = extract_body_preview(req_body, 600);
        let prompt_preview: Option<String> = extract_chat_prompt(req_body, 300);

        let (resp_hash, resp_status, latency_ms, has_pii_resp, pii_resp, resp_body_preview, response_preview) = resp.as_ref().map(|r| {
            let body = r.body.as_deref().unwrap_or("");
            let hash = hex::encode(Sha256::digest(body.as_bytes()));
            let detections = match serde_json::from_str::<serde_json::Value>(body) {
                Ok(v) => scan_json(&v, ""),
                Err(_) => scan_text(body),
            };
            let pii = !detections.is_empty();
            let preview = extract_body_preview(body, 600);
            let resp_preview = extract_chat_response(body, 300);
            (Some(hash), Some(r.status as i32), r.latency_ms, pii, detections, preview, resp_preview)
        }).unwrap_or((None, None, None, false, Vec::new(), None, None));

        // TraceTramp risk/policy metadata from request headers
        let tracetramp_risk_level = header_value_ci(&req.headers, "x-risk-level");
        let tracetramp_policy_verdict = header_value_ci(&req.headers, "x-policy-outcome");

        let kernel_host = self
            .connector
            .get_kernel_agent_status(&agent_pid)
            .await
            .unwrap_or(None);

        let decision_digest = serde_json::json!({
            "schema_version": 1,
            "admission": { "verdict": admission_verdict.to_string() },
            "firewall": {
                "blocked": fw_blocked,
                "checked": fw_checked,
                "status": fw_status,
                "reason": fw_reason,
            },
            "kernel_host": kernel_host,
            "tracetramp": {
                "risk_level": tracetramp_risk_level,
                "policy_verdict": tracetramp_policy_verdict,
            },
            "fni_flow_id": fni_flow_id.clone(),
            "fni_verify_status": fni_verify_status.clone(),
        });

        let capture_cost_usd = estimate_capture_cost_usd(&req, resp.as_ref());
        let capture_id: Uuid = sqlx::query_scalar(
            "INSERT INTO witness_captures (tenant_id, session_id, seq, method, url, host, path, request_hash, response_hash, response_status, latency_ms, admission_verdict, firewall_blocked, firewall_checked, firewall_status, firewall_reason, pii_in_request, pii_in_response, schema_drift, drift_fields, cost_usd, ingest_idempotency_key, tracetramp_trace_id, tracetramp_request_id, observed_via_witness_route, request_body_preview, response_body_preview, prompt_preview, response_preview, tracetramp_risk_level, tracetramp_policy_verdict, kernel_host, decision_digest, fni_flow_id, fni_verify_status, fni_cfni_wire) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37) RETURNING id"
        )
            .bind(tenant_id).bind(session_id).bind(receipt_seq).bind(&req.method).bind(&req.url).bind(&host).bind(&path).bind(&req_hash)
            .bind(&resp_hash).bind(&resp_status).bind(&latency_ms).bind(admission_verdict.to_string())
            .bind(fw_blocked).bind(fw_checked).bind(&fw_status).bind(&fw_reason)
            .bind(has_pii_req).bind(has_pii_resp).bind(drift).bind(&drift_fields).bind(capture_cost_usd).bind(&idempotency_key)
            .bind(&tracetramp_trace_id).bind(&tracetramp_request_id).bind(observed_via_witness_route)
            .bind(&req_body_preview).bind(&resp_body_preview).bind(&prompt_preview).bind(&response_preview)
            .bind(&tracetramp_risk_level).bind(&tracetramp_policy_verdict).bind(&kernel_host).bind(&decision_digest)
            .bind(&fni_flow_id)
            .bind(&fni_verify_status)
            .bind(&fni_cfni_wire)
            .fetch_one(&self.db).await?;

        for hit in &pii_req {
            let original_preview = hit.value_preview.clone();
            let redacted_preview = redact_preview(&original_preview);
            sqlx::query(
                "INSERT INTO witness_pii_hits (tenant_id, session_id, capture_id, location, field_path, pii_type, action, original_preview, redacted_preview) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(capture_id)
            .bind("request")
            .bind(&hit.field_path)
            .bind(hit.pii_type.to_string())
            .bind("redacted")
            .bind(original_preview)
            .bind(redacted_preview)
            .execute(&self.db)
            .await?;
        }
        for hit in &pii_resp {
            let original_preview = hit.value_preview.clone();
            let redacted_preview = redact_preview(&original_preview);
            sqlx::query(
                "INSERT INTO witness_pii_hits (tenant_id, session_id, capture_id, location, field_path, pii_type, action, original_preview, redacted_preview) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(capture_id)
            .bind("response")
            .bind(&hit.field_path)
            .bind(hit.pii_type.to_string())
            .bind("redacted")
            .bind(original_preview)
            .bind(redacted_preview)
            .execute(&self.db)
            .await?;
        }

        let receipt = generate_receipt(session_id, Some(capture_id), "api.call", receipt_seq,
            serde_json::json!({"method": req.method, "url": req.url, "req_hash": req_hash, "resp_hash": resp_hash, "resp_status": resp_status, "fw_blocked": fw_blocked, "pii_req": has_pii_req, "pii_resp": has_pii_resp, "tracetramp_trace_id": tracetramp_trace_id, "tracetramp_request_id": tracetramp_request_id, "fni_flow_id": fni_flow_id, "fni_verify_status": fni_verify_status, "kernel_host": kernel_host, "decision_digest": decision_digest}),
            chain_head.as_deref(), &self.hmac_secret);

        sqlx::query("INSERT INTO witness_receipts (tenant_id, session_id, capture_id, event_type, seq, payload, hmac, prev_hmac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(tenant_id).bind(session_id).bind(capture_id).bind(&receipt.event_type).bind(receipt.seq).bind(&receipt.payload).bind(&receipt.hmac).bind(&receipt.prev_hmac)
            .execute(&self.db).await?;
        let custody_idempotency = format!("{}:{}:{}", session_id, receipt.seq, receipt.hmac);
        let _ = sqlx::query(
            "INSERT INTO witness_custody_queue (tenant_id, session_id, capture_id, receipt_seq, payload_hash, idempotency_key, status) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending') ON CONFLICT (idempotency_key) DO NOTHING"
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(capture_id)
        .bind(receipt.seq)
        .bind(&receipt.hmac)
        .bind(custody_idempotency)
        .execute(&self.db)
        .await;

        sqlx::query("UPDATE witness_sessions SET chain_head_hmac=$1, receipt_seq=$2, total_calls=total_calls+1, total_blocked=total_blocked+CASE WHEN $3 THEN 1 ELSE 0 END, total_pii_hits=total_pii_hits+CASE WHEN $4 OR $5 THEN 1 ELSE 0 END, cost_usd = cost_usd + $6 WHERE id=$7")
            .bind(&receipt.hmac).bind(receipt_seq+1).bind(fw_blocked).bind(has_pii_req).bind(has_pii_resp).bind(capture_cost_usd).bind(session_id).execute(&self.db).await?;

        let _ = self.connector.record_decision(&agent_pid, "witnessctl.api.call", &req.url,
            if fw_blocked {"blocked"} else {"allow"}, Some(&format!("{:?}, PII:{}", admission_verdict, has_pii_req||has_pii_resp)),
            if has_pii_req||has_pii_resp {&["hipaa"]} else {&[]}).await;

        if !self.strict_mode {
            let db = self.db.clone();
            let connector = self.connector.clone();
            let agent_pid_bg = agent_pid.clone();
            let session_id_bg = session_id;
            let capture_id_bg = capture_id;
            let req_url_bg = req.url.clone();
            let req_body_bg = req_body.to_string();
            let timeout_ms = self.firewall_timeout_ms;
            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    connector.firewall_inspect(&agent_pid_bg, &req_body_bg, &format!("witness/{}", session_id_bg)),
                )
                .await;

                match result {
                    Ok(Ok(resp)) => {
                        let blocked = resp.blocked;
                        let reason = resp.final_decision.unwrap_or_else(|| "async_firewall_ok".to_string());
                        let _ = sqlx::query(
                            "UPDATE witness_captures \
                             SET firewall_blocked = $1, firewall_checked = true, firewall_status = $2, firewall_reason = $3 \
                             WHERE id = $4"
                        )
                        .bind(blocked)
                        .bind("ok")
                        .bind(reason)
                        .bind(capture_id_bg)
                        .execute(&db)
                        .await;
                        if blocked {
                            let _ = sqlx::query(
                                "UPDATE witness_sessions SET total_blocked = total_blocked + 1 WHERE id = $1"
                            )
                            .bind(session_id_bg)
                            .execute(&db)
                            .await;
                        }
                    }
                    Ok(Err(err)) => {
                        let _ = sqlx::query(
                            "UPDATE witness_captures \
                             SET firewall_checked = false, firewall_status = $1, firewall_reason = $2 \
                             WHERE id = $3"
                        )
                        .bind("connector_unavailable")
                        .bind(err.to_string())
                        .bind(capture_id_bg)
                        .execute(&db)
                        .await;
                    }
                    Err(_) => {
                        let _ = sqlx::query(
                            "UPDATE witness_captures \
                             SET firewall_checked = false, firewall_status = $1, firewall_reason = $2 \
                             WHERE id = $3"
                        )
                        .bind("timeout")
                        .bind(format!("firewall check timeout after {}ms", timeout_ms))
                        .bind(capture_id_bg)
                        .execute(&db)
                        .await;
                    }
                }

                let _ = connector
                    .record_decision(
                        &agent_pid_bg,
                        "witnessctl.api.call.firewall_async",
                        &req_url_bg,
                        "observed",
                        Some("async firewall post-processing completed"),
                        &[],
                    )
                    .await;
            });
        }

        Ok(CaptureResponse { capture_id, receipt_id: receipt.id, seq: receipt_seq, admission_verdict,
            firewall_blocked: fw_blocked, pii_in_request: has_pii_req, pii_in_response: has_pii_resp,
            schema_drift: drift, forwarded: !fw_blocked && admission_verdict==AdmissionVerdict::Allow,
            response: resp, latency_ms })
    }
}

fn parse_url(url: &str) -> (String, String) {
    if let Ok(p) = url.parse::<reqwest::Url>() {
        (p.host_str().unwrap_or("unknown").to_string(), p.path().to_string())
    } else {
        let v: Vec<_> = url.split('/').collect();
        if v.len() >= 2 { (v[0].replace("https://", "").replace("http://", ""), format!("/{}", &v[1..].join("/")))
        } else { (url.to_string(), "/".to_string()) }
    }
}

fn redact_preview(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let keep = value.chars().take(2).collect::<String>();
    format!("{}***", keep)
}

/// Truncate raw body to `max_chars` for preview storage (never stores full content)
fn extract_body_preview(body: &str, max_chars: usize) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let trimmed = body.trim();
    if trimmed.len() <= max_chars {
        Some(trimmed.to_string())
    } else {
        Some(format!("{}…", &trimmed[..max_chars]))
    }
}

/// Extract the last user message content from a chat completion JSON body
fn extract_chat_prompt(body: &str, max_chars: usize) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let messages = v.get("messages")?.as_array()?;
    let prompt = messages.iter().rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())?;
    if prompt.len() <= max_chars {
        Some(prompt.to_string())
    } else {
        Some(format!("{}…", &prompt[..max_chars]))
    }
}

/// Extract the assistant response text from a chat completion response JSON
fn extract_chat_response(body: &str, max_chars: usize) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let content = v.get("choices")?.as_array()?.first()
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())?;
    if content.len() <= max_chars {
        Some(content.to_string())
    } else {
        Some(format!("{}…", &content[..max_chars]))
    }
}

fn estimate_capture_cost_usd(req: &RawRequest, resp: Option<&RawResponse>) -> f64 {
    let req_bytes = req.body.as_deref().map(|b| b.len()).unwrap_or(0) as f64;
    let resp_bytes = resp
        .and_then(|r| r.body.as_deref())
        .map(|b| b.len())
        .unwrap_or(0) as f64;
    // Conservative pre-revenue baseline until provider-token accounting is wired:
    // $0.50 / 1M request bytes + $1.00 / 1M response bytes.
    let req_cost = (req_bytes / 1_000_000.0) * 0.50;
    let resp_cost = (resp_bytes / 1_000_000.0) * 1.00;
    (req_cost + resp_cost).max(0.0)
}
