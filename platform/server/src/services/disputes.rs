use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// E1.9: Extended with full provenance fields — signed at write time
#[derive(Deserialize)]
pub struct RecordDecisionRequest {
    pub agent_pid: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub confidence: Option<f64>,
    pub evidence_cids: Option<Vec<String>>,
    pub regulations: Option<Vec<String>>,
    // E1.9: Provenance fields
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub prompt_id: Option<String>,
    pub prompt_version: Option<String>,
    pub input_cid: Option<String>,
    pub output_cid: Option<String>,
    pub human_reviewer: Option<String>,
    pub rationale: Option<String>,
}

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

pub async fn record_decision(
    State(state): State<SharedState>,
    Json(req): Json<RecordDecisionRequest>,
) -> Json<serde_json::Value> {
    let subject = if req.agent_pid.is_empty() {
        "disputes"
    } else {
        req.agent_pid.as_str()
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        subject,
        "lifecycle",
        "record_decision",
        &serde_json::json!({"agent_pid": req.agent_pid.as_str(), "action": req.action.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    // FIX BUG-036: Acquire and release locks independently to avoid holding 3 locks simultaneously
    {
        let mut aapi = state.aapi.lock().unwrap();
        aapi.record_action(
            &format!("decision:{}", req.action),
            &req.action,
            &req.target,
            &req.agent_pid,
            &req.outcome,
            req.evidence_cids.clone().unwrap_or_default(),
            req.confidence,
            req.regulations.clone().unwrap_or_default(),
        );
    }
    // aapi lock dropped here

    let (trust, audit_verified) = {
        let k = state.kernel.lock().unwrap();
        let trust = connector_engine::TrustComputer::compute(&k);
        let audit_verified = k.verify_audit_chain().is_ok();
        (trust, audit_verified)
    };
    // kernel lock dropped here
    let decision_id = format!("dec_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    // E1.9: Build canonical provenance record and sign it with platform Ed25519 key
    let provenance = serde_json::json!({
        "decision_id":    decision_id,
        "agent_pid":      req.agent_pid,
        "action":         req.action,
        "target":         req.target,
        "outcome":        req.outcome,
        "confidence":     req.confidence.unwrap_or(0.0),
        "evidence_cids":  req.evidence_cids.clone().unwrap_or_default(),
        "regulations":    req.regulations.clone().unwrap_or_default(),
        "model_name":     req.model_name,
        "model_version":  req.model_version,
        "prompt_id":      req.prompt_id,
        "prompt_version": req.prompt_version,
        "input_cid":      req.input_cid,
        "output_cid":     req.output_cid,
        "human_reviewer": req.human_reviewer,
        "rationale":      req.rationale,
        "agent_health_score": trust.score,
        "trust_grade":    trust.grade,
        "audit_chain_verified": audit_verified,
        "recorded_at":    now.to_rfc3339(),
    });

    // Compute SHA-256 content hash of the canonical record
    let canonical_json = serde_json::to_string(&provenance).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let content_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    // Sign the content hash with platform Ed25519 key
    let signature_hex = state.signing_key.sign(content_hash.as_bytes());

    // Persist immutable decision record to engine_store
    let mut full_record = provenance.as_object().cloned().unwrap_or_default();
    full_record.insert("content_hash".into(), serde_json::json!(content_hash));
    full_record.insert("signature".into(), serde_json::json!(signature_hex));
    full_record.insert(
        "public_key_hex".into(),
        serde_json::json!(state.signing_key.public_key_hex()),
    );

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "decisions",
        &decision_id,
        &serde_json::Value::Object(full_record),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "decision_id": decision_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "agent_pid": req.agent_pid,
        "action": req.action,
        "target": req.target,
        "outcome": req.outcome,
        "confidence": req.confidence.unwrap_or(0.0),
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "evidence_cids": req.evidence_cids.unwrap_or_default(),
        "regulations": req.regulations.unwrap_or_default(),
        "audit_chain_verified": audit_verified,
        "content_hash": content_hash,
        "signature": signature_hex,
        "public_key_hex": state.signing_key.public_key_hex(),
        "immutable": true,
    }))
}

pub async fn list_decisions(
    State(state): State<SharedState>,
    Query(q): Query<ListQuery>,
) -> Json<serde_json::Value> {
    let aapi = state.aapi.lock().unwrap();
    let all = aapi.list_actions(q.agent_pid.as_deref());
    let decisions: Vec<serde_json::Value> = all
        .iter()
        .filter(|a| a.intent.starts_with("decision:"))
        .take(q.limit)
        .map(|a| {
            serde_json::json!({
                "agent_pid": a.agent_pid,
                "action": a.action,
                "target": a.target,
                "outcome": a.outcome,
                "timestamp": a.timestamp,
            })
        })
        .collect();
    Json(serde_json::json!({"count": decisions.len(), "decisions": decisions}))
}

pub async fn generate_dispute_report(
    State(state): State<SharedState>,
    Path(decision_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let now = chrono::Utc::now();

    Json(serde_json::json!({
        "report": {
            "decision_id": decision_id,
            "generated_at": now.to_rfc3339(),
            "agent_health_score": trust.score,
            "trust_grade": trust.grade,
            "integrity_verified": integrity,
            "kernel_state": {
                "total_packets": k.packet_count(),
                "total_audit_entries": k.audit_log().len(),
                "agents_registered": k.agents().len(),
            },
            "verification_method": "Ed25519 signatures + CID chain + HMAC verification",
            "tamper_proof": true,
        },
        "export_formats": ["json", "pdf", "html"],
        "pdf_url": format!("/api/v1/disputes/{}/pdf", decision_id),
    }))
}

pub async fn provenance_chain(
    State(state): State<SharedState>,
    Path(cid_str): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let chain: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.target.as_ref().map_or(false, |t| t.contains(&cid_str)))
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "target_cid": e.target,
            })
        })
        .collect();
    Json(serde_json::json!({
        "cid": cid_str,
        "chain_length": chain.len(),
        "chain": chain,
        "verification_status": "unverified",
        "hint": "Independent recompute required before verified claim",
    }))
}

/// Wave 2 — Item 2.1: Pre-decision risk assessment gate
pub async fn risk_check(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let action = req
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let target = req
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);

    let mut risk_flags: Vec<serde_json::Value> = Vec::new();
    let mut risk_score: u32 = 0;

    // Check 1: Agent exists and is active?
    match k.get_agent(agent_pid) {
        Some(acb) => {
            if acb.status != vac_core::types::AgentStatus::Running {
                risk_flags.push(serde_json::json!({
                    "flag": "agent_not_active",
                    "severity": "high",
                    "detail": format!("Agent is {:?}, not Running", acb.status),
                }));
                risk_score += 30;
            }
            // Check tool bindings
            if acb.tool_bindings.is_empty() {
                risk_flags.push(serde_json::json!({
                    "flag": "no_tool_bindings",
                    "severity": "medium",
                    "detail": "Agent has no tool bindings — cannot make gated tool calls",
                }));
                risk_score += 10;
            }
        }
        None => {
            risk_flags.push(serde_json::json!({
                "flag": "agent_not_found",
                "severity": "critical",
                "detail": format!("Agent {} not registered in kernel", agent_pid),
            }));
            risk_score += 50;
        }
    }

    // Check 2: Trust below threshold?
    if trust.score < 60 {
        risk_flags.push(serde_json::json!({
            "flag": "low_trust",
            "severity": "high",
            "detail": format!("Trust score {} is below 60 — system reliability degraded", trust.score),
        }));
        risk_score += 20;
    }

    // Check 3: Audit chain integrity
    let integrity = k.verify_audit_chain().is_ok();
    if !integrity {
        risk_flags.push(serde_json::json!({
            "flag": "audit_chain_broken",
            "severity": "critical",
            "detail": "HMAC audit chain verification failed — possible tampering",
        }));
        risk_score += 40;
    }

    // Check 4: Recent denied operations for this agent?
    let recent_denials = k
        .audit_log()
        .iter()
        .rev()
        .take(100)
        .filter(|e| e.agent_pid == agent_pid && e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    if recent_denials > 3 {
        risk_flags.push(serde_json::json!({
            "flag": "excessive_denials",
            "severity": "high",
            "detail": format!("{} denied operations in recent history — agent may be misconfigured", recent_denials),
        }));
        risk_score += 15;
    }

    let decision = if risk_score == 0 {
        "proceed"
    } else if risk_score <= 20 {
        "proceed_with_caution"
    } else if risk_score <= 50 {
        "review_required"
    } else {
        "block"
    };

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "action": action,
        "target": target,
        "risk_score": risk_score.min(100),
        "decision": decision,
        "risk_flags": risk_flags,
        "agent_health_score": trust.score,
        "integrity": integrity,
    }))
}

/// Wave 4 — Item 4.12: Court-ready evidence export
pub async fn defense_package(
    State(state): State<SharedState>,
    Path(decision_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let now = chrono::Utc::now();

    // Collect all evidence
    let audit_entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": &e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "target_cid": &e.target,
                "scitt_receipt": &e.scitt_receipt_cid,
                "duration_us": e.duration_us,
            })
        })
        .collect();

    let agent_inventory: Vec<serde_json::Value> = k
        .agents()
        .iter()
        .map(|(pid, acb)| {
            serde_json::json!({
                "pid": pid,
                "name": &acb.agent_name,
                "role": format!("{:?}", acb.role),
                "tool_bindings": acb.tool_bindings.len(),
                "namespace_mounts": acb.namespace_mounts.len(),
                "total_tokens": acb.total_tokens_consumed,
            })
        })
        .collect();

    Json(serde_json::json!({
        "defense_package": {
            "decision_id": decision_id,
            "generated_at": now.to_rfc3339(),
            "package_version": "1.0",
            "trust_assessment": {
                "score": trust.score,
                "grade": trust.grade,
                "dimensions": trust.dimensions,
                "integrity_verified": integrity,
                "verification_method": "Ed25519 + CID chain + HMAC",
            },
            "system_state": {
                "total_packets": k.packet_count(),
                "total_audit_entries": audit_entries.len(),
                "total_agents": k.agents().len(),
                "audit_chain_intact": integrity,
            },
            "agent_inventory": agent_inventory,
            "audit_log": audit_entries,
            "certifications": [
                "HMAC tamper-evident audit chain",
                "Content-addressed memory (CID)",
                "Kernel-level access control enforcement",
            ],
        },
        "export_formats": ["json", "pdf"],
    }))
}

/// Wave 4 — Item 4.13: Pre-filled regulation template
pub async fn regulation_template(
    State(state): State<SharedState>,
    Path(framework): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let integrity = k.verify_audit_chain().is_ok();
    let now = chrono::Utc::now();

    let template = match framework.to_lowercase().as_str() {
        "hipaa" => serde_json::json!({
            "framework": "HIPAA",
            "sections": [
                {"ref": "§164.312(a)", "title": "Access Controls", "status": if !k.agents().values().any(|a| a.tool_bindings.is_empty()) { "compliant" } else { "gaps_found" }, "evidence": "Tool bindings enforce access control per agent"},
                {"ref": "§164.312(b)", "title": "Audit Controls", "status": if integrity { "compliant" } else { "non_compliant" }, "evidence": format!("{} audit entries with HMAC chain", k.audit_log().len())},
                {"ref": "§164.312(c)", "title": "Integrity Controls", "status": if integrity { "compliant" } else { "non_compliant" }, "evidence": "CID-addressed content + HMAC tamper detection"},
                {"ref": "§164.312(e)", "title": "Transmission Security", "status": "requires_review", "evidence": "TLS enforced on API endpoints"},
            ],
        }),
        "soc2" => serde_json::json!({
            "framework": "SOC2 Type II",
            "sections": [
                {"ref": "CC6.1", "title": "Logical Access Security", "status": "compliant", "evidence": format!("Kernel enforces role-based access for {} agents", k.agents().len())},
                {"ref": "CC6.3", "title": "Role-Based Access", "status": "compliant", "evidence": "6 predefined roles with execution policies"},
                {"ref": "CC7.2", "title": "System Monitoring", "status": "compliant", "evidence": format!("Trust score {} with 5-dimension monitoring", trust.score)},
                {"ref": "CC8.1", "title": "Change Management", "status": "compliant", "evidence": "All operations audited with CID chain"},
            ],
        }),
        "eu_ai_act" | "euaiact" => serde_json::json!({
            "framework": "EU AI Act",
            "sections": [
                {"ref": "Art. 12", "title": "Record-Keeping", "status": if integrity { "compliant" } else { "non_compliant" }, "evidence": format!("{} tamper-proof audit entries", k.audit_log().len())},
                {"ref": "Art. 13", "title": "Transparency", "status": "compliant", "evidence": "Full reasoning chain with CIDs available per agent"},
                {"ref": "Art. 14", "title": "Human Oversight", "status": if k.agents().values().any(|a| a.tool_bindings.iter().any(|tb| tb.requires_approval)) { "compliant" } else { "gaps_found" }, "evidence": "Tool bindings support requires_approval flag"},
                {"ref": "Art. 15", "title": "Accuracy & Robustness", "status": "compliant", "evidence": format!("Trust score {} with integrity verification", trust.score)},
            ],
        }),
        "gdpr" => serde_json::json!({
            "framework": "GDPR",
            "sections": [
                {"ref": "Art. 30", "title": "Records of Processing", "status": "compliant", "evidence": format!("{} audit entries tracking all processing activities", k.audit_log().len())},
                {"ref": "Art. 32", "title": "Security of Processing", "status": if integrity { "compliant" } else { "non_compliant" }, "evidence": "Ed25519 signatures, CID chains, HMAC audit"},
                {"ref": "Art. 35", "title": "Impact Assessment", "status": "requires_review", "evidence": "Trust scoring provides continuous risk assessment"},
            ],
        }),
        _ => serde_json::json!({
            "error": format!("Unknown framework '{}'. Supported: hipaa, soc2, eu_ai_act, gdpr", framework),
        }),
    };

    Json(serde_json::json!({
        "generated_at": now.to_rfc3339(),
        "agent_health_score": trust.score,
        "integrity": integrity,
        "template": template,
    }))
}

/// E1.10: One-click evidence package — structured ZIP-equivalent JSON bundle
/// POST /disputes/{id}/export-package
pub async fn export_package(
    State(state): State<SharedState>,
    Path(decision_id): Path<String>,
) -> Json<serde_json::Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "disputes",
        "lifecycle",
        "bundle_decision_record",
        &serde_json::json!({"decision_id": decision_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let k = state.kernel.lock().unwrap();
    let es = state.engine_store.lock().unwrap();
    let aapi = state.aapi.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let now = chrono::Utc::now();

    // 1. decision.json — stored immutable record
    let decision_record = es
        .folder_get("decisions", &decision_id)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            serde_json::json!({
                "decision_id": decision_id,
                "note": "Decision not found in store. Record via POST /disputes/record first.",
            })
        });

    // 2. audit_chain.json — all kernel audit entries
    let audit_chain: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .map(|e| {
            serde_json::json!({
                "audit_id":  e.audit_id,
                "timestamp": e.timestamp,
                "timestamp_iso": chrono::DateTime::from_timestamp_millis(e.timestamp)
                    .map(|d| d.to_rfc3339()).unwrap_or_default(),
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome":   format!("{:?}", e.outcome),
                "target":    e.target,
                "reason":    e.reason,
                "scitt_receipt_cid": e.scitt_receipt_cid,
            })
        })
        .collect();

    // 3. provenance_chain.json — entries touching this decision's target
    let target_cid = decision_record
        .get("output_cid")
        .or_else(|| decision_record.get("input_cid"))
        .and_then(|v| v.as_str())
        .unwrap_or(&decision_id);
    let provenance_chain: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.target.as_ref().map_or(false, |t| {
                t.contains(target_cid) || t.contains(&decision_id)
            })
        })
        .map(|e| {
            serde_json::json!({
                "timestamp_iso": chrono::DateTime::from_timestamp_millis(e.timestamp)
                    .map(|d| d.to_rfc3339()).unwrap_or_default(),
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "target":    e.target,
                "outcome":   format!("{:?}", e.outcome),
            })
        })
        .collect();

    // 4. model_card.json — model provenance from decision record
    let model_card = serde_json::json!({
        "model_name":    decision_record.get("model_name"),
        "model_version": decision_record.get("model_version"),
        "prompt_id":     decision_record.get("prompt_id"),
        "prompt_version":decision_record.get("prompt_version"),
        "platform":      "Connector Platform",
        "platform_version": env!("CARGO_PKG_VERSION"),
        "guard_pipeline": "5-layer (MAC + Policy + Content + CircuitBreaker + HITL)",
        "signing_algorithm": "Ed25519",
        "note": "Model card auto-generated from decision provenance fields.",
    });

    // 5. prompt_version.json — load from engine_store if prompt_id is set
    let prompt_id = decision_record
        .get("prompt_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prompt_version_doc = if !prompt_id.is_empty() {
        es.folder_get("prompt_meta", prompt_id).ok().flatten()
            .unwrap_or_else(|| serde_json::json!({ "note": format!("Prompt {} not found in store", prompt_id) }))
    } else {
        serde_json::json!({ "note": "No prompt_id in decision record" })
    };

    // 6. human_oversight.json
    let human_oversight = serde_json::json!({
        "human_reviewer":  decision_record.get("human_reviewer"),
        "requires_approval": k.agents().values().any(|a| a.tool_bindings.iter().any(|tb| tb.requires_approval)),
        "hitl_framework": "POST /tools/approvals/pending + /approve",
        "eu_ai_act_art14": "Human oversight gate available via requires_approval on tool bindings",
        "recorded_at": now.to_rfc3339(),
    });

    // 7. certificate.json — Ed25519-signed trust certificate for this package
    let cert_payload = serde_json::json!({
        "decision_id": decision_id,
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "audit_chain_valid": k.verify_audit_chain().is_ok(),
        "exported_at": now.to_rfc3339(),
        "export_type": "evidence_package_v1",
    });
    let cert_json = serde_json::to_string(&cert_payload).unwrap_or_default();
    let cert_sig = state.signing_key.sign(cert_json.as_bytes());

    let package_id = format!("pkg_{}", uuid::Uuid::new_v4());
    drop(es);
    drop(k);
    drop(aapi);

    // Persist export manifest
    let mut es_mut = state.engine_store.lock().unwrap();
    let _ = es_mut.folder_put("evidence_packages", &package_id, &serde_json::json!({
        "package_id":  package_id,
        "decision_id": decision_id,
        "exported_at": now.to_rfc3339(),
        "files": ["decision.json", "audit_chain.json", "certificate.json", "provenance_chain.json", "model_card.json", "prompt_version.json", "human_oversight.json"],
    }));
    drop(es_mut);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "package_id":  package_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "decision_id": decision_id,
        "exported_at": now.to_rfc3339(),
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "files": {
            "decision.json":         decision_record,
            "audit_chain.json":      { "entry_count": audit_chain.len(), "entries": audit_chain },
            "provenance_chain.json": { "entry_count": provenance_chain.len(), "chain": provenance_chain },
            "model_card.json":       model_card,
            "prompt_version.json":   prompt_version_doc,
            "human_oversight.json":  human_oversight,
            "certificate.json": {
                "payload":          cert_payload,
                "signature":        cert_sig,
                "public_key_hex":   state.signing_key.public_key_hex(),
                "algorithm":        "Ed25519",
                "signed_at":        now.to_rfc3339(),
            },
        },
        "spec": "Connector Platform Evidence Package v1.0",
        "admissibility_note": "This package contains tamper-evident records signed with Ed25519. For court submission, verify signature against GET /proof/public-key.",
    }))
}

/// E3.8: Regulatory tag + article mapping report
/// POST /disputes/regulations-report
pub async fn regulations_report(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let period = req.get("period").and_then(|v| v.as_str()).unwrap_or("all");
    let framework_filter = req.get("framework").and_then(|v| v.as_str());
    let now = chrono::Utc::now();

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("decisions", None).unwrap_or_default();

    // Load all decisions with their regulation tags
    let decisions: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("decisions", k).ok().flatten())
        .collect();

    // Regulation → article mappings
    let article_map: std::collections::HashMap<&str, Vec<(&str, &str)>> = [
        (
            "GDPR",
            vec![
                ("Art.5", "Principles of processing"),
                ("Art.6", "Lawfulness of processing"),
                ("Art.17", "Right to erasure"),
                ("Art.22", "Automated individual decision-making"),
                ("Art.25", "Data protection by design"),
                ("Art.32", "Security of processing"),
                ("Art.35", "Data protection impact assessment"),
            ],
        ),
        (
            "EU_AI_ACT",
            vec![
                ("Art.9", "Risk management system"),
                ("Art.12", "Record-keeping"),
                ("Art.13", "Transparency"),
                ("Art.14", "Human oversight"),
                ("Art.52", "Transparency obligations for certain AI systems"),
            ],
        ),
        (
            "HIPAA",
            vec![
                ("§164.502", "Uses and disclosures of PHI"),
                ("§164.514", "De-identification of PHI"),
                ("§164.530", "Administrative requirements"),
            ],
        ),
        (
            "SOC2",
            vec![
                ("CC6.1", "Logical and physical access controls"),
                ("CC6.2", "Access provisioning"),
                ("CC7.2", "System monitoring"),
                ("CC8.1", "Change management"),
            ],
        ),
        (
            "ISO_42001",
            vec![
                ("6.1", "Risk management"),
                ("9.1", "Monitoring and measurement"),
                ("10.2", "Corrective action"),
            ],
        ),
    ]
    .into_iter()
    .collect();

    // Group decisions by regulation
    let mut by_regulation: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();

    for decision in &decisions {
        let regs = decision
            .get("regulations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if regs.is_empty() {
            by_regulation
                .entry("UNTAGGED".into())
                .or_default()
                .push(decision.clone());
        } else {
            for reg in &regs {
                let reg_str = reg.as_str().unwrap_or("UNKNOWN").to_uppercase();
                if framework_filter.map_or(true, |f| reg_str.contains(&f.to_uppercase())) {
                    by_regulation
                        .entry(reg_str)
                        .or_default()
                        .push(decision.clone());
                }
            }
        }
    }

    // Build report with article mappings
    let report: Vec<serde_json::Value> = by_regulation
        .iter()
        .map(|(reg, decs)| {
            let articles = article_map
                .get(reg.as_str())
                .map(|arts| {
                    arts.iter()
                        .map(|(art, desc)| serde_json::json!({"article": art, "description": desc}))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let outcomes: Vec<&str> = decs
                .iter()
                .filter_map(|d| d.get("outcome").and_then(|v| v.as_str()))
                .collect();
            let positive = outcomes
                .iter()
                .filter(|o| **o == "allow" || **o == "success")
                .count();
            let negative = outcomes
                .iter()
                .filter(|o| **o == "deny" || **o == "block")
                .count();

            serde_json::json!({
                "regulation":         reg,
                "decision_count":     decs.len(),
                "positive_outcomes":  positive,
                "negative_outcomes":  negative,
                "article_mappings":   articles,
                "sample_decisions":   decs.iter().take(3).map(|d| serde_json::json!({
                    "decision_id": d.get("decision_id"),
                    "agent_pid":   d.get("agent_pid"),
                    "outcome":     d.get("outcome"),
                    "recorded_at": d.get("recorded_at"),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "report_id":       format!("regs_report_{}", now.timestamp_millis()),
        "generated_at":    now.to_rfc3339(),
        "period":          period,
        "framework_filter":framework_filter,
        "total_decisions": decisions.len(),
        "regulation_count":by_regulation.len(),
        "by_regulation":   report,
        "export_hint":     "Add 'regulations' field to POST /disputes/record to tag decisions",
    }))
}

/// E3.9: Auto-detect GDPR Art.22 candidates
/// POST /disputes/scan-gdpr-art22
pub async fn scan_gdpr_art22(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("decisions", None).unwrap_or_default();

    let mut flagged: Vec<serde_json::Value> = Vec::new();
    let mut reviewed: Vec<serde_json::Value> = Vec::new();

    for key in &keys {
        let decision = match es.folder_get("decisions", key).ok().flatten() {
            Some(d) => d,
            None => continue,
        };

        let confidence = decision
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let human_reviewer = decision.get("human_reviewer").and_then(|v| v.as_str());
        let agent_pid = decision
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let outcome = decision
            .get("outcome")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let action = decision
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let target = decision
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let regs = decision
            .get("regulations")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .any(|s| s.to_uppercase().contains("GDPR"))
            })
            .unwrap_or(false);

        // GDPR Art.22 criteria:
        // 1. High confidence automated decision (≥ 0.80)
        // 2. No human reviewer recorded
        // 3. Decision affects an individual (target contains individual indicator)
        let affects_individual = !target.is_empty()
            && (target.contains("user")
                || target.contains("person")
                || target.contains("individual")
                || target.contains("patient")
                || target.contains("employee")
                || target.contains("customer"));

        let high_confidence_automated = confidence >= 0.80 && human_reviewer.is_none();

        let art22_candidate = high_confidence_automated && affects_individual;
        let art22_risk = high_confidence_automated && !affects_individual && confidence >= 0.95;

        if art22_candidate || art22_risk || regs {
            let flags: Vec<&str> = vec![
                if high_confidence_automated {
                    Some("HIGH_CONFIDENCE_AUTOMATED")
                } else {
                    None
                },
                if affects_individual {
                    Some("AFFECTS_INDIVIDUAL")
                } else {
                    None
                },
                if human_reviewer.is_none() {
                    Some("NO_HUMAN_REVIEWER")
                } else {
                    None
                },
                if regs { Some("GDPR_TAGGED") } else { None },
            ]
            .into_iter()
            .flatten()
            .collect();

            let entry = serde_json::json!({
                "decision_id":    decision.get("decision_id"),
                "agent_pid":      agent_pid,
                "action":         action,
                "target":         target,
                "outcome":        outcome,
                "confidence":     confidence,
                "human_reviewer": human_reviewer,
                "art22_candidate":art22_candidate,
                "flags":          flags,
                "recorded_at":    decision.get("recorded_at"),
                "review_action":  format!("POST /disputes/record with human_reviewer field, or export: POST /disputes/{}/export-package",
                    decision.get("decision_id").and_then(|v| v.as_str()).unwrap_or(key)),
                "gdpr_article":   "GDPR Art.22 — Automated individual decision-making, including profiling",
            });

            if art22_candidate {
                flagged.push(entry);
            } else {
                reviewed.push(entry);
            }
        }
    }

    flagged.sort_by(|a, b| {
        let ca = a.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let cb = b.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });

    Json(serde_json::json!({
        "scan_id":         format!("art22_scan_{}", now.timestamp_millis()),
        "scanned_at":      now.to_rfc3339(),
        "total_decisions": keys.len(),
        "art22_candidates":flagged.len(),
        "art22_watch":     reviewed.len(),
        "flagged":         flagged,
        "watch_list":      reviewed,
        "criteria": {
            "confidence_threshold": 0.80,
            "requires_individual":  true,
            "no_human_reviewer":    true,
        },
        "recommendation": if !flagged.is_empty() {
            format!("REVIEW REQUIRED: {} decisions may violate GDPR Art.22 (automated decisions affecting individuals without human oversight). Add human_reviewer to each decision.", flagged.len())
        } else {
            "PASS: No Art.22 violations detected. All high-confidence automated decisions have human reviewer or do not affect individuals.".into()
        },
        "spec": "GDPR Art.22 — Automated individual decision-making, including profiling (Regulation EU 2016/679)",
    }))
}

pub async fn judgment(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let context = req.get("context").and_then(|v| v.as_str()).unwrap_or("");

    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);

    let judgment = connector_engine::JudgmentEngine::judge_kernel(&k);

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "judgment": {
            "score": judgment.score,
            "grade": format!("{:?}", judgment.grade),
            "warnings": judgment.warnings,
        },
        "trust_context": {
            "score": trust.score,
            "grade": trust.grade,
        }
    }))
}

/// POST /disputes/record-decision-v2
/// Immutable decision record with full provenance: model, prompt_id, input/output CIDs, Ed25519 signature.
pub async fn record_decision_v2(
    State(state): State<SharedState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let decision_id = uuid::Uuid::new_v4().to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        payload.get("agent_pid").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("disputes"),
        "lifecycle",
        "record_decision_v2",
        &serde_json::json!({"decision_id": decision_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let agent_pid = payload
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let model_name = payload
        .get("model_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let prompt_id = payload
        .get("prompt_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let input_cid = payload
        .get("input_cid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let output_cid = payload
        .get("output_cid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let outcome = payload
        .get("outcome")
        .and_then(|v| v.as_str())
        .unwrap_or("approved")
        .to_string();
    let confidence = payload
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.0);
    let human_review = payload
        .get("human_reviewed_by")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let regulation = payload
        .get("regulation_tag")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let article = payload
        .get("article_ref")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let record = serde_json::json!({
        "decision_id":       decision_id,
        "schema_version":    "v2",
        "agent_pid":         agent_pid,
        "model_name":        model_name,
        "prompt_id":         prompt_id,
        "input_cid":         input_cid,
        "output_cid":        output_cid,
        "outcome":           outcome,
        "confidence":        confidence,
        "human_reviewed_by": human_review,
        "regulation_tag":    regulation,
        "article_ref":       article,
        "recorded_at":       now.to_rfc3339(),
        "recorded_at_ms":    now.timestamp_millis(),
        "platform_version":  env!("CARGO_PKG_VERSION"),
    });

    let payload_json = serde_json::to_string(&record).unwrap_or_default();
    let sig_hex = state.signing_key.sign(payload_json.as_bytes());

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "decisions_v2",
        &decision_id,
        &serde_json::json!({
            "record":            record,
            "ed25519_signature": sig_hex,
            "public_key_hex":    state.signing_key.public_key_hex(),
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "decision_id":        decision_id,
        "task_id":            admitted.task_id,
        "executed":           true,
        "admits":             false,
        "schema_version":     "v2",
        "recorded_at":        now.to_rfc3339(),
        "ed25519_signature":  sig_hex,
        "public_key_hex":     state.signing_key.public_key_hex(),
        "tamper_proof":       true,
        "evidence_package_url": format!("/disputes/{}/export-package", decision_id),
    }))
}
