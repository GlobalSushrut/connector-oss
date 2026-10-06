use pulldown_cmark::{html as cmark_html, Options, Parser};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use std::io::Write;

use crate::{
    error::AppError,
};

pub struct ExportEngine {
    db: PgPool,
    hmac_secret: String,
    worm_dir: Option<String>,
    worm_http_url: Option<String>,
    worm_http_bearer: Option<String>,
    worm_profile: String,
}

impl ExportEngine {
    pub fn new(db: PgPool, config: &crate::config::Config) -> Self {
        Self {
            db,
            hmac_secret: config.hmac_secret.clone(),
            worm_dir: config.worm_dir.clone(),
            worm_http_url: config.worm_http_url.clone(),
            worm_http_bearer: config.worm_http_bearer.clone(),
            worm_profile: config.worm_profile.clone(),
        }
    }

    /// Export session data in the requested format.
    pub async fn export_session(
        &self,
        session_id: Uuid,
        format: &str,
        include_raw: bool,
    ) -> Result<ExportResult, AppError> {
        let session = sqlx::query(
            "SELECT upstream, role, mode::text, status::text, frameworks, \
             total_calls, total_blocked, total_pii_hits, cost_usd, \
             chain_head_hmac, receipt_seq, created_at, sealed_at, tenant_id \
             FROM witness_sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::NotFound(format!("Session {}", session_id)))?;

        let captures = sqlx::query(
            "SELECT seq, method, url, host, path, request_hash, response_hash, \
             response_status, latency_ms, admission_verdict, firewall_blocked, \
             pii_in_request, pii_in_response, schema_drift, drift_fields, created_at, \
             decision_digest, tracetramp_trace_id, tracetramp_request_id \
             FROM witness_captures WHERE session_id = $1 ORDER BY seq"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;

        let receipts = sqlx::query(
            "SELECT event_type, seq, payload, hmac, prev_hmac, created_at \
             FROM witness_receipts WHERE session_id = $1 ORDER BY seq"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await?;

        let upstream: String = session.get("upstream");
        let role: String = session.get("role");
        let mode: String = session.get("mode");
        let status: String = session.get("status");
        let total_calls: i64 = session.get("total_calls");
        let total_blocked: i64 = session.get("total_blocked");
        let total_pii_hits: i64 = session.get("total_pii_hits");
        let cost_usd: f64 = session.get("cost_usd");
        let chain_head: Option<String> = session.get("chain_head_hmac");
        let receipt_seq: i64 = session.get("receipt_seq");
        let created_at: chrono::DateTime<chrono::Utc> = session.get("created_at");
        let sealed_at: Option<chrono::DateTime<chrono::Utc>> = session.get("sealed_at");

        let compliance_rows = sqlx::query(
            "SELECT framework, passed, score, failed_controls, evaluated_at \
             FROM witness_compliance WHERE session_id = $1 ORDER BY framework"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        // Pull decision pentest summaries if available (best-effort — table may not exist yet)
        let pentest_summaries = sqlx::query(
            "SELECT trace_id, capture_id, \
                    dehallucination_step_count, dehallucination_flagged, \
                    knot_score, knot_diverted, pii_component_count, tokenization_count, \
                    stability_verdict, connector_available, generated_at \
             FROM witness_decision_pentest_cache \
             WHERE session_id = $1 \
             ORDER BY generated_at DESC"
        )
        .bind(session_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        let result = match format {
            "json" => {
                let mut capture_rows = Vec::new();
                for row in &captures {
                    capture_rows.push(serde_json::json!({
                        "seq": row.get::<i64, _>("seq"),
                        "method": row.get::<String, _>("method"),
                        "url": if include_raw { row.get::<String, _>("url") } else { format!("{}{}", row.get::<String, _>("host"), row.get::<String, _>("path")) },
                        "host": row.get::<String, _>("host"),
                        "path": row.get::<String, _>("path"),
                        "request_hash": row.get::<String, _>("request_hash"),
                        "response_hash": row.get::<Option<String>, _>("response_hash"),
                        "response_status": row.get::<Option<i32>, _>("response_status"),
                        "latency_ms": row.get::<Option<i32>, _>("latency_ms"),
                        "admission_verdict": row.get::<String, _>("admission_verdict"),
                        "firewall_blocked": row.get::<bool, _>("firewall_blocked"),
                        "pii_in_request": row.get::<bool, _>("pii_in_request"),
                        "pii_in_response": row.get::<bool, _>("pii_in_response"),
                        "schema_drift": row.get::<bool, _>("schema_drift"),
                        "drift_fields": row.get::<Vec<String>, _>("drift_fields"),
                        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                        "decision_digest": row.get::<Option<serde_json::Value>, _>("decision_digest"),
                    }));
                }

                let mut receipt_rows = Vec::new();
                for row in &receipts {
                    receipt_rows.push(serde_json::json!({
                        "event_type": row.get::<String, _>("event_type"),
                        "seq": row.get::<i64, _>("seq"),
                        "payload": row.get::<serde_json::Value, _>("payload"),
                        "hmac": row.get::<String, _>("hmac"),
                        "prev_hmac": row.get::<Option<String>, _>("prev_hmac"),
                        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                    }));
                }

                let mut pentest_rows_json = Vec::new();
                for row in &pentest_summaries {
                    pentest_rows_json.push(serde_json::json!({
                        "trace_id": row.get::<String, _>("trace_id"),
                        "capture_id": row.get::<Option<Uuid>, _>("capture_id"),
                        "dehallucination_step_count": row.get::<i32, _>("dehallucination_step_count"),
                        "dehallucination_flagged": row.get::<bool, _>("dehallucination_flagged"),
                        "knot_score": row.get::<f64, _>("knot_score"),
                        "knot_diverted": row.get::<bool, _>("knot_diverted"),
                        "pii_component_count": row.get::<i32, _>("pii_component_count"),
                        "tokenization_count": row.get::<i32, _>("tokenization_count"),
                        "stability_verdict": row.get::<String, _>("stability_verdict"),
                        "connector_available": row.get::<bool, _>("connector_available"),
                        "generated_at": row.get::<chrono::DateTime<chrono::Utc>, _>("generated_at").to_rfc3339(),
                    }));
                }

                let body = serde_json::json!({
                    "session": {
                        "id": session_id,
                        "upstream": upstream,
                        "role": role,
                        "mode": mode,
                        "status": status,
                        "total_calls": total_calls,
                        "total_blocked": total_blocked,
                        "total_pii_hits": total_pii_hits,
                        "cost_usd": cost_usd,
                        "chain_head_hmac": chain_head,
                        "receipt_seq": receipt_seq,
                        "created_at": created_at.to_rfc3339(),
                        "sealed_at": sealed_at.map(|t| t.to_rfc3339()),
                    },
                    "captures": capture_rows,
                    "receipts": receipt_rows,
                    "decision_pentest_summaries": pentest_rows_json,
                    "export_metadata": {
                        "format": "json",
                        "include_raw": include_raw,
                        "exported_at": chrono::Utc::now().to_rfc3339(),
                        "capture_count": capture_rows.len(),
                        "receipt_count": receipt_rows.len(),
                        "pentest_report_count": pentest_rows_json.len(),
                    }
                });

                Ok(ExportResult {
                    content_type: "application/json".to_string(),
                    body: serde_json::to_string_pretty(&body).unwrap_or_default().into_bytes(),
                    filename: format!("witness-{}-{}.json", session_id, chrono::Utc::now().timestamp()),
                })
            }
            "csv" => {
                let mut wtr = csv::Writer::from_writer(Vec::new());

                // Header
                wtr.write_record([
                    "seq", "method", "host", "path", "request_hash", "response_hash",
                    "response_status", "latency_ms", "admission_verdict", "firewall_blocked",
                    "pii_in_request", "pii_in_response", "schema_drift", "drift_fields", "created_at",
                    "decision_digest",
                ]).unwrap();

                for row in &captures {
                    wtr.write_record(&[
                        row.get::<i64, _>("seq").to_string(),
                        row.get::<String, _>("method"),
                        row.get::<String, _>("host"),
                        row.get::<String, _>("path"),
                        row.get::<String, _>("request_hash"),
                        row.get::<Option<String>, _>("response_hash").unwrap_or_default(),
                        row.get::<Option<i32>, _>("response_status").map(|s| s.to_string()).unwrap_or_default(),
                        row.get::<Option<i32>, _>("latency_ms").map(|s| s.to_string()).unwrap_or_default(),
                        row.get::<String, _>("admission_verdict"),
                        row.get::<bool, _>("firewall_blocked").to_string(),
                        row.get::<bool, _>("pii_in_request").to_string(),
                        row.get::<bool, _>("pii_in_response").to_string(),
                        row.get::<bool, _>("schema_drift").to_string(),
                        row.get::<Vec<String>, _>("drift_fields").join(";"),
                        row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                        row
                            .get::<Option<serde_json::Value>, _>("decision_digest")
                            .map(|v| v.to_string())
                            .unwrap_or_default(),
                    ]).unwrap();
                }

                let bytes = wtr.into_inner().unwrap();

                Ok(ExportResult {
                    content_type: "text/csv".to_string(),
                    body: bytes,
                    filename: format!("witness-{}-{}.csv", session_id, chrono::Utc::now().timestamp()),
                })
            }
            "markdown" | "md" => {
                let markdown = build_markdown_report(
                    session_id,
                    &upstream,
                    &role,
                    &mode,
                    &status,
                    total_calls,
                    total_blocked,
                    total_pii_hits,
                    cost_usd,
                    chain_head.clone(),
                    receipt_seq,
                    created_at,
                    sealed_at,
                    &captures,
                    &receipts,
                    &compliance_rows,
                    &pentest_summaries,
                );

                Ok(ExportResult {
                    content_type: "text/markdown; charset=utf-8".to_string(),
                    body: markdown.into_bytes(),
                    filename: format!("witness-{}-{}.md", session_id, chrono::Utc::now().timestamp()),
                })
            }
            "pdf" => {
                let markdown = build_markdown_report(
                    session_id,
                    &upstream,
                    &role,
                    &mode,
                    &status,
                    total_calls,
                    total_blocked,
                    total_pii_hits,
                    cost_usd,
                    chain_head.clone(),
                    receipt_seq,
                    created_at,
                    sealed_at,
                    &captures,
                    &receipts,
                    &compliance_rows,
                    &pentest_summaries,
                );
                let html = markdown_to_html(&markdown);
                let pdf_bytes = connector_report_pdf::render_pdf(&html).map_err(|e| {
                    AppError::Internal(e.to_string())
                })?;
                let hash8 = &sha256::digest(&pdf_bytes)[..8];
                Ok(ExportResult {
                    content_type: "application/pdf".to_string(),
                    body: pdf_bytes,
                    filename: format!("witness-{}-{}.pdf", session_id, hash8),
                })
            }
            "html" => {
                let markdown = build_markdown_report(
                    session_id,
                    &upstream,
                    &role,
                    &mode,
                    &status,
                    total_calls,
                    total_blocked,
                    total_pii_hits,
                    cost_usd,
                    chain_head.clone(),
                    receipt_seq,
                    created_at,
                    sealed_at,
                    &captures,
                    &receipts,
                    &compliance_rows,
                    &pentest_summaries,
                );
                let html = markdown_to_html(&markdown);
                Ok(ExportResult {
                    content_type: "text/html; charset=utf-8".to_string(),
                    body: html.into_bytes(),
                    filename: format!("witness-{}-{}.html", session_id, chrono::Utc::now().timestamp()),
                })
            }
            "di_audit_middle" | "di-audit" | "di_audit" => {
                use connector_trust::custody::CustodyVerificationStatus;
                use connector_trust::{
                    DiAuditMiddleEvent, DiAuditMiddleExport, DiControlHit, DI_AUDIT_MIDDLE_SCHEMA,
                };

                let session_tenant = session
                    .get::<Uuid, _>("tenant_id")
                    .to_string();

                let mut events = Vec::new();
                let mut session_trace_ids: Vec<String> = Vec::new();
                for row in &captures {
                    let seq = row.get::<i64, _>("seq") as u64;
                    let created = row.get::<chrono::DateTime<chrono::Utc>, _>("created_at");
                    let admission = row.get::<String, _>("admission_verdict");
                    let decision = match admission.to_ascii_lowercase().as_str() {
                        "deny" | "block" | "blocked" => "deny",
                        "hold" | "quarantine" => "hold",
                        _ => "allow",
                    };
                    let mut side = Vec::new();
                    if row.get::<bool, _>("firewall_blocked") {
                        side.push("firewall_blocked".into());
                    }
                    if row.get::<bool, _>("pii_in_request") {
                        side.push("pii_in_request".into());
                    }
                    if row.get::<bool, _>("pii_in_response") {
                        side.push("pii_in_response".into());
                    }
                    let digest = row.get::<Option<serde_json::Value>, _>("decision_digest");
                    let ticket = digest
                        .as_ref()
                        .and_then(|d| d.pointer("/admission/ticket_id").or_else(|| d.get("ticket_id")))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let col_trace = row.get::<Option<String>, _>("tracetramp_trace_id");
                    let col_req = row.get::<Option<String>, _>("tracetramp_request_id");
                    let digest_trace = digest
                        .as_ref()
                        .and_then(|d| d.pointer("/tracetramp/trace_id").or_else(|| d.get("trace_id")))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let trace_id = col_trace.clone().or(digest_trace);
                    if let Some(ref tid) = trace_id {
                        if !session_trace_ids.iter().any(|t| t == tid) {
                            session_trace_ids.push(tid.clone());
                        }
                    }

                    let controls = vec![
                        DiControlHit {
                            control_id: "soc2.cc6.1.access_controls".into(),
                            passed: true,
                            message: Some(format!("admission={admission}")),
                            framework: "soc2".into(),
                        },
                        DiControlHit {
                            control_id: "di.admission.decision_recorded".into(),
                            passed: true,
                            message: Some(decision.into()),
                            framework: "di".into(),
                        },
                        DiControlHit {
                            control_id: "di.tool_or_api.effect".into(),
                            passed: !row.get::<bool, _>("firewall_blocked"),
                            message: None,
                            framework: "di".into(),
                        },
                        DiControlHit {
                            control_id: "soc2.cc7.2.data_integrity".into(),
                            passed: row.get::<String, _>("request_hash").len() >= 16,
                            message: Some("request_hash present; chain recompute in custody header".into()),
                            framework: "soc2".into(),
                        },
                    ];

                    events.push(DiAuditMiddleEvent {
                        event_id: format!("wc_cap_{session_id}_{seq}"),
                        seq,
                        occurred_at_ms: created.timestamp_millis(),
                        identity_key: role.clone(),
                        tenant_id: Some(session_tenant.clone()),
                        session_id: Some(session_id.to_string()),
                        agent_pid: None,
                        action: format!(
                            "api.{}",
                            row.get::<String, _>("method").to_ascii_lowercase()
                        ),
                        resource: format!(
                            "{}{}",
                            row.get::<String, _>("host"),
                            row.get::<String, _>("path")
                        ),
                        decision: decision.into(),
                        admission_ticket_id: ticket,
                        input_digest: Some(row.get::<String, _>("request_hash")),
                        output_digest: row.get::<Option<String>, _>("response_hash"),
                        previous_mac: None,
                        integrity_mac: receipts
                            .iter()
                            .find(|r| r.get::<i64, _>("seq") == row.get::<i64, _>("seq"))
                            .map(|r| r.get::<String, _>("hmac")),
                        side_effects: side,
                        trace_id,
                        request_id: col_req,
                        memory_super_key: None,
                        memory_cid: None,
                        moment_id: None,
                        controls,
                        schema: DI_AUDIT_MIDDLE_SCHEMA.into(),
                        contract_version: 2,
                    });
                }

                // Fold TraceTramp → WitnessCtl handoffs correlated by capture trace_ids.
                let handoff_rows = if session_trace_ids.is_empty() {
                    Vec::new()
                } else {
                    sqlx::query(
                        "SELECT id, trace_id, request_id, tenant_id, payload, created_at \
                         FROM witness_tracetramp_handoffs \
                         WHERE trace_id = ANY($1) \
                         ORDER BY created_at ASC LIMIT 500",
                    )
                    .bind(&session_trace_ids)
                    .fetch_all(&self.db)
                    .await
                    .unwrap_or_default()
                };

                let mut next_seq = events.iter().map(|e| e.seq).max().unwrap_or(0).saturating_add(1);
                for h in &handoff_rows {
                    let hid: Uuid = h.get("id");
                    let tid: String = h.get("trace_id");
                    let rid: String = h.get("request_id");
                    let htenant: String = h.get("tenant_id");
                    let created: chrono::DateTime<chrono::Utc> = h.get("created_at");
                    let payload: serde_json::Value = h.get("payload");
                    let decision = payload
                        .get("decision")
                        .or_else(|| payload.pointer("/policy/verdict"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("allow");
                    let ledger = payload
                        .get("witness_ledger_contract")
                        .and_then(|v| v.as_str())
                        .unwrap_or("witnessctl_tracetramp_handoff_v1")
                        .to_string();
                    let digest = payload
                        .get("decision_digest")
                        .or_else(|| payload.get("digest"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            Some(format!(
                                "handoff:{}:{}",
                                &tid[..tid.len().min(16)],
                                &rid[..rid.len().min(16)]
                            ))
                        });

                    events.push(DiAuditMiddleEvent {
                        event_id: format!("wc_tt_handoff_{hid}"),
                        seq: next_seq,
                        occurred_at_ms: created.timestamp_millis(),
                        identity_key: role.clone(),
                        tenant_id: Some(htenant.clone()),
                        session_id: Some(session_id.to_string()),
                        agent_pid: None,
                        action: "tracetramp.handoff".into(),
                        resource: format!("trace:{tid}"),
                        decision: decision.into(),
                        admission_ticket_id: payload
                            .pointer("/admission/ticket_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        input_digest: digest,
                        output_digest: None,
                        previous_mac: None,
                        integrity_mac: None,
                        side_effects: vec![
                            "tracetramp_handoff".into(),
                            ledger.clone(),
                        ],
                        trace_id: Some(tid),
                        request_id: Some(rid),
                        memory_super_key: None,
                        memory_cid: None,
                        moment_id: payload
                            .get("moment_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        controls: vec![
                            DiControlHit {
                                control_id: "di.tracetramp.handoff_recorded".into(),
                                passed: true,
                                message: Some("TraceTramp decision folded into WitnessCtl middle stream".into()),
                                framework: "di".into(),
                            },
                            DiControlHit {
                                control_id: "soc2.cc7.2.data_integrity".into(),
                                passed: true,
                                message: Some(format!("ledger={ledger}")),
                                framework: "soc2".into(),
                            },
                        ],
                        schema: DI_AUDIT_MIDDLE_SCHEMA.into(),
                        contract_version: 2,
                    });
                    next_seq = next_seq.saturating_add(1);
                }

                // Fold receipt HMACs as previous_mac chain onto events when seq matches.
                for ev in &mut events {
                    if let Some(r) = receipts
                        .iter()
                        .find(|r| r.get::<i64, _>("seq") as u64 == ev.seq)
                    {
                        ev.previous_mac = r.get::<Option<String>, _>("prev_hmac");
                        if ev.integrity_mac.is_none() {
                            ev.integrity_mac = Some(r.get::<String, _>("hmac"));
                        }
                    }
                }

                let receipt_objs: Vec<crate::types::Receipt> = receipts
                    .iter()
                    .map(|r| crate::types::Receipt {
                        id: Uuid::nil(),
                        session_id,
                        capture_id: None,
                        event_type: r.get("event_type"),
                        seq: r.get("seq"),
                        payload: r.get("payload"),
                        hmac: r.get("hmac"),
                        prev_hmac: r.get("prev_hmac"),
                        created_at: r.get("created_at"),
                    })
                    .collect();
                let chain_valid = crate::receipt::verify_chain(&receipt_objs, &self.hmac_secret);
                let head_matches = receipt_objs
                    .last()
                    .map(|r| Some(&r.hmac) == chain_head.as_ref())
                    .unwrap_or(receipt_objs.is_empty());
                let integrity_status = if chain_valid && head_matches {
                    CustodyVerificationStatus::Verified
                } else if receipt_objs.is_empty() {
                    CustodyVerificationStatus::Incomplete
                } else {
                    CustodyVerificationStatus::Failed
                };

                let custody = connector_trust::CustodyReceiptV2 {
                    receipt_id: format!("wcust_{session_id}"),
                    proof_id: None,
                    principal_id: role.clone(),
                    tenant_id: None,
                    event_range_start: events.first().map(|e| e.seq.to_string()),
                    event_range_end: events.last().map(|e| e.seq.to_string()),
                    policy_revision: None,
                    chain_head: chain_head.clone(),
                    signer_key_id: Some("witnessctl-hmac".into()),
                    artifact_digests: receipt_objs.iter().take(32).map(|r| r.hmac.clone()).collect(),
                    signature_hex: None,
                    verification_status: integrity_status,
                    contract_version: 2,
                };

                let mut control_summary = Vec::new();
                for row in &compliance_rows {
                    let fw = row.get::<String, _>("framework");
                    let passed = row.get::<bool, _>("passed");
                    control_summary.push(DiControlHit {
                        control_id: format!("{fw}.overall"),
                        passed,
                        message: None,
                        framework: fw,
                    });
                }

                let export = DiAuditMiddleExport {
                    schema: DI_AUDIT_MIDDLE_SCHEMA.into(),
                    generated_at_ms: chrono::Utc::now().timestamp_millis(),
                    session_id: Some(session_id.to_string()),
                    custody: Some(custody),
                    events,
                    control_summary,
                    integrity_status,
                };

                Ok(ExportResult {
                    content_type: "application/json".to_string(),
                    body: serde_json::to_string_pretty(&export)
                        .unwrap_or_default()
                        .into_bytes(),
                    filename: format!(
                        "witness-di-audit-{}-{}.json",
                        session_id,
                        chrono::Utc::now().timestamp()
                    ),
                })
            }
            _ => Err(AppError::BadRequest(format!(
                "Unsupported export format: {}. Use 'json', 'csv', 'markdown', 'html', 'pdf', or 'di_audit_middle'.", format
            ))),
        }?;

        if let Err(e) = crate::compliance_ledger::record_export_moment(
            session_id,
            format,
            &sha256::digest(&result.body),
            result.body.len(),
        ) {
            tracing::warn!("compliance ledger append failed (non-fatal): {}", e);
        }

        self.persist_worm_copy_if_configured(&result).await?;
        Ok(result)
    }
}

pub struct ExportResult {
    pub content_type: String,
    pub body: Vec<u8>,
    pub filename: String,
}

fn build_markdown_report(
    session_id: Uuid,
    upstream: &str,
    role: &str,
    mode: &str,
    status: &str,
    total_calls: i64,
    total_blocked: i64,
    total_pii_hits: i64,
    cost_usd: f64,
    chain_head: Option<String>,
    receipt_seq: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    sealed_at: Option<chrono::DateTime<chrono::Utc>>,
    captures: &[sqlx::postgres::PgRow],
    receipts: &[sqlx::postgres::PgRow],
    compliance_rows: &[sqlx::postgres::PgRow],
    pentest_summaries: &[sqlx::postgres::PgRow],
) -> String {
    let mut out = String::new();
    out.push_str(&crate::compliance_ledger::court_grade_front_matter(
        session_id,
        chain_head.as_deref(),
    ));
    out.push_str("## WitnessCtl compliance report (exhibit body)\n\n");
    out.push_str(&format!("**Session ID:** `{}`  \n", session_id));
    out.push_str(&format!("**Generated At:** `{}`  \n", chrono::Utc::now().to_rfc3339()));
    out.push_str(&format!("**Upstream:** `{}`  \n", upstream));
    out.push_str(&format!("**Role:** `{}`  \n", role));
    out.push_str(&format!("**Mode:** `{}`  \n", mode));
    out.push_str(&format!("**Status:** `{}`\n\n", status));

    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!(
        "- Total calls: `{}`\n- Blocked calls: `{}`\n- PII hits: `{}`\n- Total cost (USD): `${:.6}`\n",
        total_calls, total_blocked, total_pii_hits, cost_usd
    ));
    out.push_str(&format!(
        "- Receipt sequence: `{}`\n- Receipt count: `{}`\n",
        receipt_seq,
        receipts.len()
    ));
    out.push_str(&format!(
        "- Chain head HMAC: `{}`\n",
        chain_head.clone().unwrap_or_else(|| "none".to_string())
    ));
    out.push_str(&format!("- Created at: `{}`\n", created_at.to_rfc3339()));
    out.push_str(&format!(
        "- Sealed at: `{}`\n\n",
        sealed_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "not sealed".to_string())
    ));

    out.push_str("## Framework Verdicts\n\n");
    out.push_str("| Framework | Passed | Score | Failed Controls |\n");
    out.push_str("|---|---:|---:|---|\n");
    if compliance_rows.is_empty() {
        out.push_str("| n/a | n/a | n/a | no compliance evaluation recorded |\n");
    } else {
        for row in compliance_rows {
            let framework: String = row.get("framework");
            let passed: bool = row.get("passed");
            let score: i32 = row.get("score");
            let failed_controls: Vec<String> = row.get("failed_controls");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                framework,
                if passed { "yes" } else { "no" },
                score,
                if failed_controls.is_empty() {
                    "-".to_string()
                } else {
                    failed_controls.join(", ")
                }
            ));
        }
    }
    out.push('\n');

    out.push_str("## Evidence Samples (First 20 Captures)\n\n");
    out.push_str("| Seq | Method | Host | Path | Verdict | Blocked | PII(req/resp) | Drift | Latency(ms) | Decision digest |\n");
    out.push_str("|---:|---|---|---|---|---:|---|---:|---:|---|\n");
    for row in captures.iter().take(20) {
        let seq: i64 = row.get("seq");
        let method: String = row.get("method");
        let host: String = row.get("host");
        let path: String = row.get("path");
        let verdict: String = row.get("admission_verdict");
        let blocked: bool = row.get("firewall_blocked");
        let pii_req: bool = row.get("pii_in_request");
        let pii_resp: bool = row.get("pii_in_response");
        let drift: bool = row.get("schema_drift");
        let latency_ms: Option<i32> = row.get("latency_ms");
        let digest_cell: String = row
            .try_get::<Option<serde_json::Value>, _>("decision_digest")
            .ok()
            .flatten()
            .map(|v| {
                let s = v.to_string();
                if s.len() > 120 {
                    format!("{}…", &s[..117])
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {}/{} | {} | {} | {} |\n",
            seq,
            method,
            host,
            path,
            verdict,
            blocked,
            pii_req,
            pii_resp,
            drift,
            latency_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            digest_cell.replace('|', "\\|"),
        ));
    }
    out.push('\n');
    // Decision Pentest Summary table
    if !pentest_summaries.is_empty() {
        out.push_str("## Decision Pentest Summaries\n\n");
        out.push_str("| Trace ID | Stability | Knot Score | Diverted | PII Comps | Tok Steps | Chain Flagged | Connector |\n");
        out.push_str("|---|---|---:|---|---:|---:|---|---|\n");
        for row in pentest_summaries {
            let trace_id: String = row.get("trace_id");
            let stability: String = row.get("stability_verdict");
            let knot_score: f64 = row.get("knot_score");
            let knot_diverted: bool = row.get("knot_diverted");
            let pii_count: i32 = row.get("pii_component_count");
            let tok_count: i32 = row.get("tokenization_count");
            let dh_flagged: bool = row.get("dehallucination_flagged");
            let conn_avail: bool = row.get("connector_available");
            out.push_str(&format!(
                "| `{}` | {} | {:.3} | {} | {} | {} | {} | {} |\n",
                &trace_id[..trace_id.len().min(12)],
                stability,
                knot_score,
                if knot_diverted { "yes ⚠" } else { "no" },
                pii_count,
                tok_count,
                if dh_flagged { "yes ⚠" } else { "no" },
                if conn_avail { "ok" } else { "unavail" },
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "_Generated by WitnessCtl - HMAC chain: {}_\n",
        chain_head
            .clone()
            .unwrap_or_else(|| "none".to_string())
    ));
    let digest = sha256::digest(out.as_bytes());
    out.push_str(&crate::compliance_ledger::court_grade_integrity_footer(&digest));
    out
}

/// Convert markdown to a production-quality HTML document using pulldown-cmark.
fn markdown_to_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_SMART_PUNCTUATION);

    let parser = Parser::new_ext(markdown, options);
    let mut html_body = String::with_capacity(markdown.len() * 2);
    cmark_html::push_html(&mut html_body, parser);

    let footer = format!("Generated by WitnessCtl — {}", chrono::Utc::now().to_rfc3339());
    connector_report_pdf::html_report_document(&html_body, "WitnessCtl Evidence Report", &footer)
}

impl ExportEngine {
    async fn persist_worm_copy_if_configured(&self, result: &ExportResult) -> Result<(), AppError> {
        let local_enabled = self
            .worm_dir
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let remote_enabled = self
            .worm_http_url
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

        if self.worm_profile == "strict" && !local_enabled && !remote_enabled {
            return Err(AppError::Internal(
                "WORM strict profile requires WITNESSCTL_WORM_DIR and/or WITNESSCTL_WORM_HTTP_URL".to_string(),
            ));
        }
        if !local_enabled && !remote_enabled {
            return Ok(());
        }

        if let Some(dir) = self.worm_dir.as_ref().filter(|d| !d.trim().is_empty()) {
            std::fs::create_dir_all(dir)
                .map_err(|e| AppError::Internal(format!("failed to create WORM directory: {}", e)))?;
            let hash = &sha256::digest(&result.body)[..12];
            let worm_name = format!("{}-{}", hash, result.filename);
            let worm_path = std::path::Path::new(dir).join(worm_name);
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&worm_path)
                .map_err(|e| AppError::Internal(format!("failed to persist WORM export: {}", e)))?;
            file.write_all(&result.body)
                .map_err(|e| AppError::Internal(format!("failed to write WORM export: {}", e)))?;
        }

        if let Some(remote_url) = self.worm_http_url.as_ref().filter(|u| !u.trim().is_empty()) {
            let client = reqwest::Client::new();
            let mut req = client
                .put(format!("{}/{}", remote_url.trim_end_matches('/'), result.filename))
                .header("If-None-Match", "*")
                .body(result.body.clone());
            if let Some(token) = self
                .worm_http_bearer
                .as_ref()
                .filter(|t| !t.trim().is_empty())
            {
                req = req.bearer_auth(token);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("failed to upload WORM export: {}", e)))?;
            if !resp.status().is_success() {
                return Err(AppError::Internal(format!(
                    "WORM export upload rejected: {}",
                    resp.status()
                )));
            }
        }
        Ok(())
    }
}
