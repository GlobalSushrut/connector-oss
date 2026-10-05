use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub agent_pid: Option<String>,
}
fn default_limit() -> usize {
    50
}

/// E1.2: Extended with chargeback metadata fields
/// I18: Extended with W3C Trace Context fields (RFC traceparent/tracestate)
#[derive(Deserialize)]
pub struct RecordActionRequest {
    pub agent_pid: String,
    pub intent: String,
    pub action: String,
    pub resource: Option<String>,
    pub outcome: Option<String>,
    pub confidence: Option<f64>,
    // E1.2: Cost chargeback tags
    pub cost_center: Option<String>,
    pub team: Option<String>,
    pub product_feature: Option<String>,
    pub cost_usd: Option<f64>,
    pub tokens_used: Option<u64>,
    // I18: W3C Trace Context — https://www.w3.org/TR/trace-context/
    // Format: "00-{trace_id}-{parent_id}-{flags}"
    pub traceparent: Option<String>,
    // Vendor-specific trace state key=value pairs
    pub tracestate: Option<String>,
}

#[derive(Deserialize)]
pub struct ExportQuery {
    pub from: Option<String>, // RFC3339
    pub to: Option<String>,   // RFC3339
    #[serde(default = "default_export_limit")]
    pub limit: usize,
}
fn default_export_limit() -> usize {
    10_000
}

#[derive(Deserialize)]
pub struct ChargebackQuery {
    pub period: Option<String>, // "7d", "30d", "month" — defaults to 30d
    pub cost_center: Option<String>,
    pub team: Option<String>,
}

#[derive(Deserialize)]
pub struct SubjectAccessQuery {
    pub user_id: String,
    #[serde(default = "default_export_limit")]
    pub limit: usize,
}

pub async fn record_action(
    State(state): State<SharedState>,
    Json(req): Json<RecordActionRequest>,
) -> Json<serde_json::Value> {
    let subject = if req.agent_pid.is_empty() {
        "actionlog"
    } else {
        req.agent_pid.as_str()
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "record_operator_action",
        &serde_json::json!({"agent_pid": req.agent_pid.as_str(), "action": req.action.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut aapi = state.aapi.lock().unwrap();
    let outcome = req.outcome.as_deref().unwrap_or("success");
    let action_id = format!("{}", uuid::Uuid::new_v4());
    aapi.record_action(
        &req.intent,
        &req.action,
        req.resource.as_deref().unwrap_or(""),
        &req.agent_pid,
        outcome,
        Vec::new(),
        req.confidence,
        Vec::new(),
    );
    state.metrics.actions_authorized.inc();

    // E1.2: Persist chargeback tags alongside the action record
    if req.cost_center.is_some() || req.team.is_some() || req.product_feature.is_some() {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "chargeback_tags",
            &action_id,
            &serde_json::json!({
                "action_id":      action_id,
                "agent_pid":      req.agent_pid,
                "action":         req.action,
                "intent":         req.intent,
                "outcome":        outcome,
                "cost_center":    req.cost_center,
                "team":           req.team,
                "product_feature":req.product_feature,
                "cost_usd":       req.cost_usd.unwrap_or(0.0),
                "tokens_used":    req.tokens_used.unwrap_or(0),
                "recorded_at":    chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    // I18: Parse traceparent and store trace_id + span_id in the response
    let (trace_id, span_id) = parse_traceparent(req.traceparent.as_deref());

    // I18: Persist trace context alongside chargeback tags if present
    if req.traceparent.is_some() {
        let mut es = state.engine_store.lock().unwrap();
        let trace_body = serde_json::json!({
            "action_id":   action_id,
            "agent_pid":   req.agent_pid,
            "traceparent": req.traceparent,
            "tracestate":  req.tracestate,
            "trace_id":    trace_id,
            "span_id":     span_id,
            "standard":    "W3C Trace Context",
            "recorded_at": chrono::Utc::now().to_rfc3339(),
        });
        let _ = es.folder_put("trace_context", &action_id, &trace_body);
        let _ = es.folder_put(
            "trace_context",
            &format!("agent:{}", req.agent_pid),
            &trace_body,
        );
    }

    drop(aapi);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "action_id": action_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "agent_pid": req.agent_pid,
        "action": req.action,
        "outcome": outcome,
        "trace_id": trace_id,
        "span_id":  span_id,
    }))
}

/// Parse a W3C `traceparent` header value into `(trace_id, span_id)`.
///
/// Format: `{version}-{trace_id}-{parent_id}-{trace_flags}`
/// e.g.   `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
///
/// Returns `(None, None)` on malformed input (spec §3.3: ignore invalid headers).
fn parse_traceparent(traceparent: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(tp) = traceparent else {
        return (None, None);
    };
    let parts: Vec<&str> = tp.splitn(4, '-').collect();
    if parts.len() != 4 {
        return (None, None);
    }
    let version = parts[0];
    let trace_id = parts[1];
    let parent_id = parts[2];
    // Reject invalid version ff (reserved) or wrong field lengths
    if version == "ff" || trace_id.len() != 32 || parent_id.len() != 16 {
        return (None, None);
    }
    (Some(trace_id.to_string()), Some(parent_id.to_string()))
}

pub async fn list_actions(
    State(state): State<SharedState>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let all = aapi.list_actions(q.agent_pid.as_deref());
    let filtered: Vec<serde_json::Value> = all
        .iter()
        .take(q.limit)
        .map(|a| {
            serde_json::json!({
                "agent_pid": a.agent_pid,
                "intent": a.intent,
                "action": a.action,
                "target": a.target,
                "outcome": a.outcome,
                "timestamp": a.timestamp,
            })
        })
        .collect();
    Json(serde_json::json!({"count": filtered.len(), "actions": filtered}))
}

pub async fn list_interactions(
    State(state): State<SharedState>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let all = aapi.list_interactions(q.agent_pid.as_deref());
    let filtered: Vec<serde_json::Value> = all
        .iter()
        .take(q.limit)
        .map(|i| {
            serde_json::json!({
                "agent_pid": i.agent_pid,
                "type": i.itype,
                "target": i.target,
                "operation": i.operation,
                "status": i.status,
                "duration_ms": i.duration_ms,
                "timestamp": i.timestamp,
            })
        })
        .collect();
    Json(serde_json::json!({"count": filtered.len(), "interactions": filtered}))
}

pub async fn denied_operations(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let denied: Vec<serde_json::Value> = k.audit_log().iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .map(|e| {
            let reason = e.reason.clone().unwrap_or_default();
            let error = e.error.clone().unwrap_or_default();
            let blob = format!("{reason} {error}").to_ascii_lowercase();
            let sgke_deny = blob.contains("sgke")
                || blob.contains("denied-by-sgke")
                || blob.contains("sgke_high_i_missing_h");
            let error_code = if sgke_deny {
                Some(crate::substrate::sgke_gate::REASON_HIGH_I_MISSING_H)
            } else if !error.is_empty() {
                Some(error.as_str())
            } else {
                None
            };
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "reason": e.reason,
                "error": e.error,
                "error_code": error_code,
                "sgke_deny": sgke_deny,
                "explainer": if sgke_deny {
                    Some("Denied-by-SGKE: high intelligence magnitude (I) without hardware/placement (H)")
                } else {
                    None
                },
            })
        })
        .collect();
    let sgke_count = denied
        .iter()
        .filter(|d| d.get("sgke_deny").and_then(|x| x.as_bool()) == Some(true))
        .count();
    Json(serde_json::json!({
        "count": denied.len(),
        "sgke_denied_count": sgke_count,
        "denied": denied,
        "honesty": "SGKE denials show Denied-by-SGKE when reason/error carries sgke_* codes; else error_code when present.",
    }))
}

/// Wave 2 — Item 2.4: Who has access to what — agent permissions matrix
pub async fn access_matrix(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let mut matrix: Vec<serde_json::Value> = Vec::new();

    for (pid, acb) in k.agents() {
        let tool_bindings: Vec<serde_json::Value> = acb
            .tool_bindings
            .iter()
            .map(|tb| {
                serde_json::json!({
                    "tool_id": tb.tool_id,
                    "namespace_path": tb.namespace_path,
                    "allowed_actions": tb.allowed_actions,
                    "allowed_resources": tb.allowed_resources,
                    "data_classification": tb.data_classification,
                    "requires_approval": tb.requires_approval,
                })
            })
            .collect();

        let namespace_mounts: Vec<serde_json::Value> = acb
            .namespace_mounts
            .iter()
            .map(|m| {
                serde_json::json!({
                    "source": m.source,
                    "mount_point": m.mount_point,
                    "mode": format!("{:?}", m.mode),
                })
            })
            .collect();

        let grant_count = k
            .audit_log()
            .iter()
            .filter(|e| {
                e.agent_pid == *pid && e.operation == vac_core::types::MemoryKernelOp::AccessGrant
            })
            .count();
        let revoke_count = k
            .audit_log()
            .iter()
            .filter(|e| {
                e.agent_pid == *pid && e.operation == vac_core::types::MemoryKernelOp::AccessRevoke
            })
            .count();

        matrix.push(serde_json::json!({
            "pid": pid,
            "name": &acb.agent_name,
            "role": format!("{:?}", acb.role),
            "namespace": &acb.namespace,
            "readable_namespaces": &acb.readable_namespaces,
            "writable_namespaces": &acb.writable_namespaces,
            "tool_bindings": tool_bindings,
            "namespace_mounts": namespace_mounts,
            "access_grants_given": grant_count,
            "access_revokes": revoke_count,
            "protection": {
                "read": acb.memory_region.protection.read,
                "write": acb.memory_region.protection.write,
                "execute": acb.memory_region.protection.execute,
                "share": acb.memory_region.protection.share,
                "requires_approval": acb.memory_region.protection.requires_approval,
            },
        }));
    }

    Json(serde_json::json!({
        "agent_count": matrix.len(),
        "matrix": matrix,
    }))
}

/// Wave 2 — Item 2.5: Show security holes per regulation framework
pub async fn compliance_gaps(State(state): State<SharedState>) -> Json<serde_json::Value> {
    // Flush pending audit entries before verifying chain
    if let Ok(mut k) = state.kernel.lock() {
        k.flush_audit_batch();
    }
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();

    let mut gaps: Vec<serde_json::Value> = Vec::new();

    // HIPAA checks
    let agents_without_bindings: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_pid, acb)| acb.tool_bindings.is_empty())
        .map(|(pid, _)| pid.clone())
        .collect();
    if !agents_without_bindings.is_empty() {
        gaps.push(serde_json::json!({
            "framework": "HIPAA",
            "requirement": "Access Controls (§164.312(a))",
            "gap": format!("{} agents have no tool bindings (ungated access)", agents_without_bindings.len()),
            "severity": "high",
            "agents": agents_without_bindings,
            "fix": "Bind tools with data_classification='phi' and requires_approval=true for PHI access",
        }));
    }

    if !integrity {
        gaps.push(serde_json::json!({
            "framework": "HIPAA",
            "requirement": "Audit Controls (§164.312(b))",
            "gap": "Audit chain integrity check FAILED",
            "severity": "critical",
            "fix": "Investigate audit log — HMAC chain is broken. Possible tampering.",
        }));
    }

    // SOC2 checks
    let denied_count = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let total_ops = k.audit_log().len();
    if total_ops > 0 && denied_count as f64 / total_ops as f64 > 0.1 {
        gaps.push(serde_json::json!({
            "framework": "SOC2",
            "requirement": "CC6.1 — Logical Access Security",
            "gap": format!(">10% of operations denied ({}/{}). Agents may have insufficient permissions.", denied_count, total_ops),
            "severity": "medium",
            "fix": "Review denied operations and update access grants or tool bindings.",
        }));
    }

    // EU AI Act checks
    if trust.score < 70 {
        gaps.push(serde_json::json!({
            "framework": "EU AI Act",
            "requirement": "Article 14 — Human Oversight",
            "gap": format!("Trust score {} < 70 — system may not meet oversight threshold", trust.score),
            "severity": "high",
            "fix": "Improve trust dimensions: memory integrity, authorization coverage, decision provenance.",
        }));
    }

    let agents_no_approval: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, acb)| !acb.tool_bindings.iter().any(|tb| tb.requires_approval))
        .filter(|(_, acb)| !acb.tool_bindings.is_empty())
        .map(|(pid, _)| pid.clone())
        .collect();
    if !agents_no_approval.is_empty() {
        gaps.push(serde_json::json!({
            "framework": "EU AI Act",
            "requirement": "Article 14 — Human-in-the-loop",
            "gap": format!("{} agents have tool bindings but none require human approval", agents_no_approval.len()),
            "severity": "medium",
            "agents": agents_no_approval,
            "fix": "Set requires_approval=true on high-risk tool bindings.",
        }));
    }

    // GDPR checks
    let total_agents = k.agents().len();
    if total_agents > 0 {
        let agents_with_phi: Vec<String> = k
            .agents()
            .iter()
            .filter(|(_, acb)| {
                acb.tool_bindings
                    .iter()
                    .any(|tb| tb.data_classification == "phi" || tb.data_classification == "pii")
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        if !agents_with_phi.is_empty() {
            // Not a gap, but an info item
            gaps.push(serde_json::json!({
                "framework": "GDPR",
                "requirement": "Article 30 — Records of Processing Activities",
                "gap": "informational",
                "severity": "info",
                "detail": format!("{} agents access PII/PHI-classified tools", agents_with_phi.len()),
                "agents": agents_with_phi,
                "fix": "Ensure data processing agreements are in place for these agents.",
            }));
        }
    }

    let compliant_count = gaps
        .iter()
        .filter(|g| g.get("severity").and_then(|v| v.as_str()) == Some("info"))
        .count();
    let gap_count = gaps.len() - compliant_count;

    Json(serde_json::json!({
        "total_gaps": gap_count,
        "info_items": compliant_count,
        "agent_health_score": trust.score,
        "integrity": integrity,
        "gaps": gaps,
    }))
}

/// Wave 4 — Item 4.4: Full regulation compliance report per framework
pub async fn regulation_report(
    State(state): State<SharedState>,
    Path(framework): Path<String>,
) -> Json<serde_json::Value> {
    // Flush pending audit entries before verifying chain
    if let Ok(mut k) = state.kernel.lock() {
        k.flush_audit_batch();
    }
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let aapi = state.aapi.lock().unwrap();
    let all_actions = aapi.list_actions(None);
    let now = chrono::Utc::now();

    let total_agents = k.agents().len();
    let total_audit = k.audit_log().len();
    let total_actions = all_actions.len();
    let denied = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();

    let agents_with_phi: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, acb)| {
            acb.tool_bindings
                .iter()
                .any(|tb| tb.data_classification == "phi" || tb.data_classification == "pii")
        })
        .map(|(pid, _)| pid.clone())
        .collect();
    let agents_with_approval: usize = k
        .agents()
        .iter()
        .filter(|(_, acb)| acb.tool_bindings.iter().any(|tb| tb.requires_approval))
        .count();

    let report = serde_json::json!({
        "framework": framework,
        "generated_at": now.to_rfc3339(),
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "integrity_verified": integrity,
        "system_summary": {
            "total_agents": total_agents,
            "total_audit_entries": total_audit,
            "total_actions": total_actions,
            "denied_operations": denied,
            "agents_accessing_phi_pii": agents_with_phi.len(),
            "agents_with_approval_gates": agents_with_approval,
        },
        "trust_dimensions": trust.dimensions,
        "evidence": {
            "audit_chain": if integrity { "PASS — HMAC chain verified" } else { "FAIL — chain broken" },
            "access_control": if total_agents > 0 { "Kernel-enforced role-based access" } else { "No agents registered" },
            "encryption": "CID content-addressing + Ed25519 signatures",
            "monitoring": format!("Trust score {} with 5-dimension continuous monitoring", trust.score),
        },
    });

    Json(serde_json::json!({
        "report": report,
        "export_formats": ["json", "pdf", "csv"],
    }))
}

/// Wave 4 — Item 4.5: Scan recent actions for PII exposure
pub async fn pii_scan(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let k = state.kernel.lock().unwrap();
    let all_actions = aapi.list_actions(None);

    // PII patterns (simplified regex-free matching)
    let pii_patterns = [
        ("email", "@", ".com"),
        ("phone", "+1", ""),
        ("ssn", "SSN", ""),
        ("ssn_pattern", "-XX-", ""),
        ("credit_card", "4111", ""),
        ("dob", "date of birth", ""),
        ("medical_record", "MRN", ""),
        ("patient_id", "patient", "ID"),
    ];

    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Scan action targets for PII
    for action in all_actions.iter().take(200) {
        for (pii_type, pattern1, pattern2) in &pii_patterns {
            let target = &action.target;
            if target.contains(pattern1) && (pattern2.is_empty() || target.contains(pattern2)) {
                findings.push(serde_json::json!({
                    "type": pii_type,
                    "location": "action_target",
                    "agent_pid": &action.agent_pid,
                    "action": &action.action,
                    "timestamp": action.timestamp,
                    "severity": if *pii_type == "ssn" || *pii_type == "credit_card" || *pii_type == "medical_record" { "critical" } else { "high" },
                }));
                break;
            }
        }
    }

    // Scan memory packets for PII
    for (pid, acb) in k.agents() {
        for p in k.packets_in_namespace(&acb.namespace).iter().take(100) {
            let text = p
                .content
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            for (pii_type, pattern1, pattern2) in &pii_patterns {
                if text.contains(pattern1) && (pattern2.is_empty() || text.contains(pattern2)) {
                    findings.push(serde_json::json!({
                        "type": pii_type,
                        "location": "memory_packet",
                        "agent_pid": pid,
                        "cid": p.content.payload_cid.to_string(),
                        "text_preview": text.chars().take(60).collect::<String>(),
                        "severity": if *pii_type == "ssn" || *pii_type == "credit_card" || *pii_type == "medical_record" { "critical" } else { "high" },
                    }));
                    break;
                }
            }
        }
    }

    let critical = findings
        .iter()
        .filter(|f| f.get("severity").and_then(|v| v.as_str()) == Some("critical"))
        .count();

    Json(serde_json::json!({
        "total_findings": findings.len(),
        "critical": critical,
        "high": findings.len() - critical,
        "findings": findings,
        "recommendation": if critical > 0 { "URGENT: Critical PII exposure found. Review and remediate immediately." } else if !findings.is_empty() { "PII detected. Review data handling practices." } else { "No PII detected in scanned scope." },
    }))
}

/// E1.1: OTel OTLP JSON export — audit entries as OTel GenAI traces
/// GET /actionlog/export/otel?from=&to=&limit=
pub async fn export_otel(
    State(state): State<SharedState>,
    Query(q): Query<ExportQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let aapi = state.aapi.lock().unwrap();
    let now = chrono::Utc::now();

    let from_ms = q
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    let to_ms =
        q.to.as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(now.timestamp_millis());

    // Build OTel resource spans from kernel audit log
    let mut spans: Vec<serde_json::Value> = Vec::new();

    for entry in k
        .audit_log()
        .iter()
        .filter(|e| e.timestamp >= from_ms && e.timestamp <= to_ms)
        .take(q.limit)
    {
        let start_ns = entry.timestamp * 1_000_000; // ms → ns
        let end_ns = start_ns + 1_000_000; // assume 1ms duration

        // Map kernel op to OTel GenAI semantic convention
        let (span_name, gen_ai_op) = match entry.operation {
            vac_core::types::MemoryKernelOp::MemWrite => ("memory.write", "create"),
            vac_core::types::MemoryKernelOp::MemRead => ("memory.read", "read"),
            vac_core::types::MemoryKernelOp::ToolDispatch => ("tool.dispatch", "execute"),
            vac_core::types::MemoryKernelOp::AccessGrant => ("access.grant", "authorize"),
            vac_core::types::MemoryKernelOp::AccessRevoke => ("access.revoke", "revoke"),
            _ => ("kernel.op", "unknown"),
        };

        let status_code = match entry.outcome {
            vac_core::types::OpOutcome::Success => "OK",
            vac_core::types::OpOutcome::Denied => "ERROR",
            vac_core::types::OpOutcome::Failed => "ERROR",
            _ => "UNSET",
        };

        spans.push(serde_json::json!({
            "traceId": format!("{:032x}", entry.timestamp),
            "spanId":  format!("{:016x}", entry.timestamp ^ entry.agent_pid.len() as i64),
            "operationName": span_name,
            "startTimeUnixNano": start_ns,
            "endTimeUnixNano": end_ns,
            "status": { "code": status_code },
            "attributes": [
                { "key": "gen_ai.operation.name",      "value": { "stringValue": gen_ai_op } },
                { "key": "gen_ai.system",              "value": { "stringValue": "connector-platform" } },
                { "key": "agent.pid",                  "value": { "stringValue": &entry.agent_pid } },
                { "key": "kernel.operation",           "value": { "stringValue": format!("{:?}", entry.operation) } },
                { "key": "kernel.outcome",             "value": { "stringValue": format!("{:?}", entry.outcome) } },
                { "key": "audit.id",                   "value": { "stringValue": &entry.audit_id } },
                { "key": "audit.target",               "value": { "stringValue": entry.target.as_deref().unwrap_or("") } },
                { "key": "audit.reason",               "value": { "stringValue": entry.reason.as_deref().unwrap_or("") } },
            ],
        }));
    }

    // Also include AAPI actions as additional spans
    for action in aapi
        .list_actions(None)
        .iter()
        .filter(|a| a.timestamp >= from_ms && a.timestamp <= to_ms)
        .take(q.limit.saturating_sub(spans.len()))
    {
        let start_ns = action.timestamp * 1_000_000;
        spans.push(serde_json::json!({
            "traceId": format!("{:032x}", action.timestamp),
            "spanId":  format!("{:016x}", action.timestamp ^ action.agent_pid.len() as i64 ^ 0xAA),
            "operationName": "agent.action",
            "startTimeUnixNano": start_ns,
            "endTimeUnixNano": start_ns + 1_000_000,
            "status": { "code": if action.outcome == "success" { "OK" } else { "ERROR" } },
            "attributes": [
                { "key": "gen_ai.operation.name",      "value": { "stringValue": "agent_action" } },
                { "key": "gen_ai.system",              "value": { "stringValue": "connector-platform" } },
                { "key": "agent.pid",                  "value": { "stringValue": &action.agent_pid } },
                { "key": "action.intent",              "value": { "stringValue": &action.intent } },
                { "key": "action.action",              "value": { "stringValue": &action.action } },
                { "key": "action.target",              "value": { "stringValue": &action.target } },
                { "key": "action.outcome",             "value": { "stringValue": &action.outcome } },
            ],
        }));
    }

    // OTLP JSON envelope (OTel Collector-compatible)
    Json(serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    { "key": "service.name",    "value": { "stringValue": "connector-platform" } },
                    { "key": "service.version", "value": { "stringValue": env!("CARGO_PKG_VERSION") } },
                    { "key": "telemetry.sdk.name", "value": { "stringValue": "connector-platform-otel-export" } },
                ]
            },
            "scopeSpans": [{
                "scope": {
                    "name": "connector.audit",
                    "version": "1.0.0",
                },
                "spans": spans,
            }],
        }],
        "export_meta": {
            "from": q.from,
            "to":   q.to,
            "span_count": spans.len(),
            "generated_at": now.to_rfc3339(),
            "format": "OTLP_JSON_v1",
            "convention": "OTel GenAI Semantic Conventions 1.27.0",
        },
    }))
}

/// E1.2: Cost chargeback report — grouped by cost_center / team / product_feature
/// GET /actionlog/chargeback-report?period=30d&cost_center=&team=
pub async fn chargeback_report(
    State(state): State<SharedState>,
    Query(q): Query<ChargebackQuery>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("chargeback_tags", None).unwrap_or_default();

    let period_days: i64 = match q.period.as_deref().unwrap_or("30d") {
        "7d" => 7,
        "month" => 30,
        s if s.ends_with('d') => s.trim_end_matches('d').parse().unwrap_or(30),
        _ => 30,
    };
    let cutoff_ms = (chrono::Utc::now() - chrono::Duration::days(period_days)).timestamp_millis();

    let mut by_cost_center: std::collections::HashMap<String, (f64, u64, u64)> =
        std::collections::HashMap::new();
    let mut by_team: std::collections::HashMap<String, (f64, u64, u64)> =
        std::collections::HashMap::new();
    let mut by_feature: std::collections::HashMap<String, (f64, u64, u64)> =
        std::collections::HashMap::new();
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut total_cost = 0.0_f64;
    let mut total_tokens: u64 = 0;

    for key in &keys {
        let val = match es.folder_get("chargeback_tags", key).ok().flatten() {
            Some(v) => v,
            None => continue,
        };

        // Filter by period
        let rec_ts = val
            .get("recorded_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(0);
        if rec_ts < cutoff_ms {
            continue;
        }

        // Filter by cost_center / team if provided
        let cc = val
            .get("cost_center")
            .and_then(|v| v.as_str())
            .unwrap_or("untagged")
            .to_string();
        let team = val
            .get("team")
            .and_then(|v| v.as_str())
            .unwrap_or("untagged")
            .to_string();
        let feature = val
            .get("product_feature")
            .and_then(|v| v.as_str())
            .unwrap_or("untagged")
            .to_string();

        if let Some(ref filter_cc) = q.cost_center {
            if &cc != filter_cc {
                continue;
            }
        }
        if let Some(ref filter_team) = q.team {
            if &team != filter_team {
                continue;
            }
        }

        let cost = val.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let tokens = val.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0);

        total_cost += cost;
        total_tokens += tokens;

        let e = by_cost_center.entry(cc.clone()).or_insert((0.0, 0, 0));
        e.0 += cost;
        e.1 += tokens;
        e.2 += 1;

        let e2 = by_team.entry(team.clone()).or_insert((0.0, 0, 0));
        e2.0 += cost;
        e2.1 += tokens;
        e2.2 += 1;

        let e3 = by_feature.entry(feature.clone()).or_insert((0.0, 0, 0));
        e3.0 += cost;
        e3.1 += tokens;
        e3.2 += 1;

        rows.push(val);
    }

    let cost_center_summary: Vec<serde_json::Value> = by_cost_center.iter().map(|(cc, (cost, tokens, count))| {
        serde_json::json!({ "cost_center": cc, "total_cost_usd": (cost * 100.0).round() / 100.0, "total_tokens": tokens, "action_count": count })
    }).collect();
    let team_summary: Vec<serde_json::Value> = by_team.iter().map(|(team, (cost, tokens, count))| {
        serde_json::json!({ "team": team, "total_cost_usd": (cost * 100.0).round() / 100.0, "total_tokens": tokens, "action_count": count })
    }).collect();
    let feature_summary: Vec<serde_json::Value> = by_feature.iter().map(|(feat, (cost, tokens, count))| {
        serde_json::json!({ "product_feature": feat, "total_cost_usd": (cost * 100.0).round() / 100.0, "total_tokens": tokens, "action_count": count })
    }).collect();

    Json(serde_json::json!({
        "period_days": period_days,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "totals": {
            "total_cost_usd": (total_cost * 100.0).round() / 100.0,
            "total_tokens": total_tokens,
            "tagged_actions": rows.len(),
        },
        "by_cost_center": cost_center_summary,
        "by_team": team_summary,
        "by_product_feature": feature_summary,
        "tip": "Tag actions with cost_center, team, product_feature in POST /actionlog/actions",
    }))
}

/// E1.3: GDPR Subject Access Request — all actions touching a user principal
/// GET /actionlog/subject-access?user_id={id}
pub async fn subject_access(
    State(state): State<SharedState>,
    Query(q): Query<SubjectAccessQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let aapi = state.aapi.lock().unwrap();
    let now = chrono::Utc::now();

    // Collect all audit entries where agent_pid or target contains the user_id
    let audit_entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.agent_pid.contains(&q.user_id)
                || e.target
                    .as_deref()
                    .map(|t| t.contains(&q.user_id))
                    .unwrap_or(false)
                || e.reason
                    .as_deref()
                    .map(|r| r.contains(&q.user_id))
                    .unwrap_or(false)
        })
        .take(q.limit)
        .map(|e| {
            serde_json::json!({
                "audit_id":  &e.audit_id,
                "timestamp": e.timestamp,
                "timestamp_iso": chrono::DateTime::from_timestamp_millis(e.timestamp)
                    .map(|d| d.to_rfc3339()).unwrap_or_default(),
                "operation": format!("{:?}", e.operation),
                "outcome":   format!("{:?}", e.outcome),
                "agent_pid": &e.agent_pid,
                "target":    &e.target,
                "reason":    &e.reason,
                "source":    "kernel_audit",
            })
        })
        .collect();

    // Collect AAPI action records
    let action_entries: Vec<serde_json::Value> = aapi
        .list_actions(None)
        .iter()
        .filter(|a| {
            a.agent_pid.contains(&q.user_id)
                || a.target.contains(&q.user_id)
                || a.intent.contains(&q.user_id)
        })
        .take(q.limit)
        .map(|a| {
            serde_json::json!({
                "timestamp": a.timestamp,
                "timestamp_iso": chrono::DateTime::from_timestamp_millis(a.timestamp)
                    .map(|d| d.to_rfc3339()).unwrap_or_default(),
                "agent_pid": &a.agent_pid,
                "intent":    &a.intent,
                "action":    &a.action,
                "target":    &a.target,
                "outcome":   &a.outcome,
                "source":    "action_log",
            })
        })
        .collect();

    // Collect chargeback records tagged with this user
    let es = state.engine_store.lock().unwrap();
    let cb_keys = es.folder_keys("chargeback_tags", None).unwrap_or_default();
    let chargeback_entries: Vec<serde_json::Value> = cb_keys
        .iter()
        .filter_map(|k| es.folder_get("chargeback_tags", k).ok().flatten())
        .filter(|v| {
            v.get("agent_pid")
                .and_then(|s| s.as_str())
                .map(|s| s.contains(&q.user_id))
                .unwrap_or(false)
        })
        .take(q.limit)
        .collect();

    let total = audit_entries.len() + action_entries.len() + chargeback_entries.len();

    Json(serde_json::json!({
        "subject_id": q.user_id,
        "generated_at": now.to_rfc3339(),
        "gdpr_article": "Art.15 — Right of Access; Art.17 — Right to Erasure (contact DPO to trigger erasure)",
        "total_records": total,
        "audit_entries": audit_entries,
        "action_entries": action_entries,
        "chargeback_entries": chargeback_entries,
        "erasure_endpoint": "POST /compliance/gdpr/erasure?user_id={subject_id}",
    }))
}

/// E1.4: Immutable HMAC-chained JSONL audit export, signed with platform Ed25519 key
/// GET /actionlog/export/jsonl?from=&to=&limit=
pub async fn export_jsonl(
    State(state): State<SharedState>,
    Query(q): Query<ExportQuery>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let from_ms = q
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    let to_ms =
        q.to.as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(now.timestamp_millis());

    let entries: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.timestamp >= from_ms && e.timestamp <= to_ms)
        .take(q.limit)
        .collect();

    // HMAC-SHA256 chain: each entry includes hash of previous entry
    type HmacSha256 = Hmac<Sha256>;
    let hmac_secret =
        std::env::var("CONNECTOR_JWT_SECRET").unwrap_or_else(|_| "connector-audit-chain-v1".into());
    let mut prev_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut lines: Vec<String> = Vec::with_capacity(entries.len() + 1);

    // Header line
    lines.push(
        serde_json::to_string(&serde_json::json!({
            "_type": "header",
            "format": "connector-audit-jsonl-v1",
            "generated_at": now.to_rfc3339(),
            "from": q.from,
            "to": q.to,
            "entry_count": entries.len(),
            "public_key_hex": state.signing_key.public_key_hex(),
            "algorithm": "HMAC-SHA256-chain + Ed25519-header-sig",
        }))
        .unwrap_or_default(),
    );

    for entry in &entries {
        let record = serde_json::json!({
            "audit_id":  entry.audit_id,
            "timestamp": entry.timestamp,
            "timestamp_iso": chrono::DateTime::from_timestamp_millis(entry.timestamp)
                .map(|d| d.to_rfc3339()).unwrap_or_default(),
            "agent_pid": entry.agent_pid,
            "operation": format!("{:?}", entry.operation),
            "outcome":   format!("{:?}", entry.outcome),
            "target":    entry.target,
            "reason":    entry.reason,
            "prev_hash": prev_hash,
        });
        let record_str = serde_json::to_string(&record).unwrap_or_default();

        // Compute HMAC over this entry's canonical JSON
        let mut mac = HmacSha256::new_from_slice(hmac_secret.as_bytes())
            .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").unwrap());
        mac.update(record_str.as_bytes());
        let this_hash = hex::encode(mac.finalize().into_bytes());

        let mut line_obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&record_str).unwrap_or_default();
        line_obj.insert("entry_hash".into(), serde_json::json!(this_hash));
        lines.push(serde_json::to_string(&line_obj).unwrap_or_default());

        prev_hash = this_hash;
    }

    // Footer: sign the final chain hash with Ed25519
    let chain_sig = state.signing_key.sign(prev_hash.as_bytes());
    lines.push(
        serde_json::to_string(&serde_json::json!({
            "_type": "footer",
            "final_chain_hash": prev_hash,
            "ed25519_signature": chain_sig,
            "public_key_hex": state.signing_key.public_key_hex(),
            "signed_at": now.to_rfc3339(),
        }))
        .unwrap_or_default(),
    );

    let body = lines.join("\n");
    let filename = format!("audit-{}.jsonl", now.format("%Y%m%d-%H%M%S"));

    (
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", filename) as &str,
            ),
        ],
        body,
    )
        .into_response()
}

/// E1.6: CloudEvents 1.0 wrapped OCSF export for webhook delivery
/// GET /actionlog/export/cloudevents?from=&to=&limit=
pub async fn export_cloudevents(
    State(state): State<SharedState>,
    Query(q): Query<ExportQuery>,
) -> Json<serde_json::Value> {
    use vac_core::ocsf_adapter::{to_cloudevent, to_ocsf, OcsfAdapterConfig};

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let from_ms = q
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    let to_ms =
        q.to.as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or(now.timestamp_millis());

    let config = OcsfAdapterConfig::default();
    let source = format!(
        "connector://{}",
        std::env::var("CONNECTOR_NODE_ID").unwrap_or_else(|_| "node-001".into())
    );

    let events: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.timestamp >= from_ms && e.timestamp <= to_ms)
        .take(q.limit)
        .map(|entry| {
            let ocsf = to_ocsf(entry, &config);
            let ce = to_cloudevent(ocsf, &source);
            serde_json::to_value(&ce).unwrap_or_default()
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "format": "cloudevents_1.0",
        "ocsf_version": "1.3.0",
        "source": source,
        "event_count": events.len(),
        "generated_at": now.to_rfc3339(),
        "events": events,
        "meta": {
            "from": q.from,
            "to": q.to,
            "limit": q.limit,
            "spec": "https://cloudevents.io/",
            "ocsf_spec": "https://schema.ocsf.io/1.3.0/"
        }
    }))
}

/// Wave 2 — Item 2.6: PHI/PII tool call classification report
pub async fn tool_audit(
    State(state): State<SharedState>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();

    // Find all ToolDispatch audit entries — they store "tool_id:action:classification" in target
    let tool_entries: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.operation == vac_core::types::MemoryKernelOp::ToolDispatch)
        .collect();

    let mut by_classification: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    let mut denied_tools: Vec<serde_json::Value> = Vec::new();

    for entry in &tool_entries {
        let target = entry.target.as_deref().unwrap_or("");
        let parts: Vec<&str> = target.splitn(3, ':').collect();
        let tool_id = parts.first().copied().unwrap_or("unknown");
        let action = parts.get(1).copied().unwrap_or("unknown");
        let classification = parts.get(2).copied().unwrap_or("unclassified");

        if entry.outcome == vac_core::types::OpOutcome::Denied {
            denied_tools.push(serde_json::json!({
                "tool_id": tool_id,
                "action": action,
                "agent_pid": &entry.agent_pid,
                "reason": &entry.error,
                "timestamp": entry.timestamp,
            }));
        } else {
            by_classification
                .entry(classification.to_string())
                .or_default()
                .push(serde_json::json!({
                    "tool_id": tool_id,
                    "action": action,
                    "agent_pid": &entry.agent_pid,
                    "outcome": format!("{:?}", entry.outcome),
                    "timestamp": entry.timestamp,
                }));
        }
    }

    let classification_summary: Vec<serde_json::Value> = by_classification
        .iter()
        .map(|(class, calls)| {
            let agents: std::collections::HashSet<&str> = calls
                .iter()
                .filter_map(|c| c.get("agent_pid").and_then(|v| v.as_str()))
                .collect();
            serde_json::json!({
                "classification": class,
                "total_calls": calls.len(),
                "unique_agents": agents.len(),
                "agents": agents.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "total_tool_calls": tool_entries.len(),
        "denied_calls": denied_tools.len(),
        "by_classification": classification_summary,
        "denied_details": denied_tools,
    }))
}

/// GET /actionlog/dependency-map
/// Returns a directed graph: agent → tool → resource for blast-radius analysis.
pub async fn dependency_map(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit_log = k.audit_log();

    let mut agent_tools: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    let mut tool_resources: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();

    for entry in audit_log.iter() {
        let agent = &entry.agent_pid;
        if entry.operation == vac_core::types::MemoryKernelOp::ToolDispatch {
            let target = entry.target.as_deref().unwrap_or("");
            let tool = target
                .splitn(2, ':')
                .next()
                .unwrap_or("unknown")
                .to_string();
            agent_tools
                .entry(agent.clone())
                .or_default()
                .insert(tool.clone());
            if let Some(resource) = entry
                .target
                .as_deref()
                .and_then(|t| t.splitn(3, ':').nth(2))
            {
                tool_resources
                    .entry(tool)
                    .or_default()
                    .insert(resource.to_string());
            }
        }
    }

    let agent_count = agent_tools.len();
    let tool_count = agent_tools
        .values()
        .flat_map(|s| s.iter())
        .collect::<std::collections::HashSet<_>>()
        .len();
    let resource_count = tool_resources
        .values()
        .flat_map(|s| s.iter())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut links: Vec<serde_json::Value> = Vec::new();

    for (agent, tools) in &agent_tools {
        nodes.push(serde_json::json!({"id": agent, "type": "agent"}));
        for tool in tools {
            if !nodes
                .iter()
                .any(|n| n.get("id").and_then(|v| v.as_str()) == Some(tool.as_str()))
            {
                nodes.push(serde_json::json!({"id": tool, "type": "tool"}));
            }
            links.push(serde_json::json!({"source": agent, "target": tool, "rel": "uses"}));
            if let Some(resources) = tool_resources.get(tool) {
                for res in resources {
                    if !nodes
                        .iter()
                        .any(|n| n.get("id").and_then(|v| v.as_str()) == Some(res.as_str()))
                    {
                        nodes.push(serde_json::json!({"id": res, "type": "resource"}));
                    }
                    links.push(
                        serde_json::json!({"source": tool, "target": res, "rel": "accesses"}),
                    );
                }
            }
        }
    }

    Json(serde_json::json!({
        "generated_at":   chrono::Utc::now().to_rfc3339(),
        "agent_count":    agent_count,
        "tool_count":     tool_count,
        "resource_count": resource_count,
        "nodes":          nodes,
        "links":          links,
        "use_case":       "Blast-radius analysis before infrastructure changes",
    }))
}

// ── LLM Call Trace endpoints (CLI-P2-4) ───────────────────────────────────────

#[derive(serde::Deserialize, Default)]
pub struct TraceQuery {
    pub agent: Option<String>,
    pub limit: Option<usize>,
    pub window_h: Option<u64>,
}

/// GET /actionlog/traces — list recent LLM call traces
pub async fn list_traces(
    State(state): State<SharedState>,
    Query(q): Query<TraceQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let limit = q.limit.unwrap_or(50);
    let cutoff_ms = q
        .window_h
        .map(|h| chrono::Utc::now().timestamp_millis() - (h as i64 * 3_600_000))
        .unwrap_or(0);

    let traces: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            let is_llm = e.operation == vac_core::types::MemoryKernelOp::LlmSchedule
                || e.operation == vac_core::types::MemoryKernelOp::ToolDispatch;
            if !is_llm {
                return false;
            }
            if e.timestamp < cutoff_ms {
                return false;
            }
            if let Some(ref ag) = q.agent {
                if !e.agent_pid.contains(ag.as_str()) {
                    return false;
                }
            }
            true
        })
        .rev()
        .take(limit)
        .map(|e| {
            let duration_ms: u64 = e
                .reason
                .as_deref()
                .and_then(|r| r.split("duration_ms=").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            serde_json::json!({
                "trace_id":   e.audit_id,
                "agent_pid":  e.agent_pid,
                "operation":  format!("{:?}", e.operation),
                "outcome":    format!("{:?}", e.outcome),
                "timestamp":  e.timestamp,
                "duration_ms": duration_ms,
                "target":     e.target,
            })
        })
        .collect();

    Json(serde_json::json!({
        "total":  traces.len(),
        "limit":  limit,
        "traces": traces,
    }))
}

/// GET /actionlog/traces/:id — single trace span by audit_id
pub async fn get_trace(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    for e in k.audit_log().iter() {
        if e.audit_id == id {
            let duration_ms: u64 = e
                .reason
                .as_deref()
                .and_then(|r| r.split("duration_ms=").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return Json(serde_json::json!({
                "trace_id":   e.audit_id,
                "agent_pid":  e.agent_pid,
                "operation":  format!("{:?}", e.operation),
                "outcome":    format!("{:?}", e.outcome),
                "timestamp":  e.timestamp,
                "duration_ms": duration_ms,
                "target":     e.target,
                "reason":     e.reason,
                "scitt_receipt_cid": e.scitt_receipt_cid,
            }));
        }
    }
    Json(serde_json::json!({"error": "Trace not found", "id": id, "status": 404}))
}

/// GET /actionlog/traces/stats — P50/P95/P99 latency + token usage aggregates
pub async fn trace_stats(
    State(state): State<SharedState>,
    Query(q): Query<TraceQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let cutoff_ms = q
        .window_h
        .map(|h| chrono::Utc::now().timestamp_millis() - (h as i64 * 3_600_000))
        .unwrap_or(0);

    let mut durations: Vec<u64> = k
        .audit_log()
        .iter()
        .filter(|e| {
            let is_llm = e.operation == vac_core::types::MemoryKernelOp::LlmSchedule;
            if !is_llm || e.timestamp < cutoff_ms {
                return false;
            }
            if let Some(ref ag) = q.agent {
                if !e.agent_pid.contains(ag.as_str()) {
                    return false;
                }
            }
            true
        })
        .filter_map(|e| {
            e.reason
                .as_deref()
                .and_then(|r| r.split("duration_ms=").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .collect();

    durations.sort_unstable();
    let n = durations.len();
    let p50 = if n > 0 { durations[n / 2] } else { 0 };
    let p95 = if n > 0 {
        durations[(n as f64 * 0.95) as usize]
    } else {
        0
    };
    let p99 = if n > 0 {
        durations[(n as f64 * 0.99) as usize]
    } else {
        0
    };
    let avg = if n > 0 {
        durations.iter().sum::<u64>() / n as u64
    } else {
        0
    };
    let max = durations.last().copied().unwrap_or(0);

    let llm_count = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.operation == vac_core::types::MemoryKernelOp::LlmSchedule && e.timestamp >= cutoff_ms
        })
        .count();
    let tool_count = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.operation == vac_core::types::MemoryKernelOp::ToolDispatch && e.timestamp >= cutoff_ms
        })
        .count();

    Json(serde_json::json!({
        "window_h":       q.window_h.unwrap_or(24),
        "llm_calls":      llm_count,
        "tool_calls":     tool_count,
        "latency_ms": {
            "p50": p50, "p95": p95, "p99": p99,
            "avg": avg, "max": max, "samples": n,
        },
    }))
}

/// GET /agents/:pid/traces — LLM call traces scoped to this agent
pub async fn agent_traces(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Query(q): Query<TraceQuery>,
) -> Json<serde_json::Value> {
    let mut q2 = q;
    q2.agent = Some(pid.clone());
    let k = state.kernel.lock().unwrap();
    let limit = q2.limit.unwrap_or(50);

    let traces: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            let is_llm = e.operation == vac_core::types::MemoryKernelOp::LlmSchedule
                || e.operation == vac_core::types::MemoryKernelOp::ToolDispatch;
            is_llm && e.agent_pid.contains(&pid)
        })
        .rev()
        .take(limit)
        .map(|e| {
            let duration_ms: u64 = e
                .reason
                .as_deref()
                .and_then(|r| r.split("duration_ms=").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            serde_json::json!({
                "trace_id":   e.audit_id,
                "agent_pid":  e.agent_pid,
                "operation":  format!("{:?}", e.operation),
                "outcome":    format!("{:?}", e.outcome),
                "timestamp":  e.timestamp,
                "duration_ms": duration_ms,
                "target":     e.target,
            })
        })
        .collect();

    Json(serde_json::json!({
        "pid": pid, "total": traces.len(), "traces": traces,
    }))
}
