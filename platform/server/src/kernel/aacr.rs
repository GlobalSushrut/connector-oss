//! AACR — Augmented Agentic Compliance Record (`connector.aacr.v1`).
//!
//! Top-tier kernel evidence standard for augmented agentic environments:
//! per-section digests, multi-framework SoA, forensic/court bindings,
//! Ed25519 when court-eligible. Never auto-greens CD-8/9 or playground→military.

use connector_trust::{
    canonical_digest_json, sign_json_ed25519, verify_signed_payload_v2, SignedPayloadV2,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.aacr.v1";
pub const STANDARD_VERSION: &str = "1.1.0";
pub const FOLDER: &str = "aacr_records_v1";
pub const INDEX_FOLDER: &str = "aacr_index_v1";

fn playground() -> bool {
    std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn head_for_agent(state: &PlatformState, agent_pid: &str) -> Option<(String, String)> {
    let es = state.engine_store.lock().ok()?;
    let idx = es.folder_get(INDEX_FOLDER, agent_pid).ok().flatten()?;
    let digest = idx.get("head_digest")?.as_str()?.to_string();
    let id = idx.get("last_id")?.as_str()?.to_string();
    Some((digest, id))
}

fn court_sign_eligible(state: &PlatformState, agent_pid: &str) -> bool {
    if playground() {
        return false;
    }
    if std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE"))
        .unwrap_or(false)
    {
        return false;
    }
    match crate::kernel::forensic_package::build_package(state, agent_pid, None, None) {
        Ok(pkg) => {
            let tier = pkg
                .pointer("/manifest/signing_tier")
                .and_then(|v| v.as_str())
                .unwrap_or("hmac_lab");
            tier == "ed25519_court"
        }
        Err(_) => false,
    }
}

fn section_digest(section: &Value) -> String {
    canonical_digest_json(section).unwrap_or_else(|_| {
        hex::encode(Sha256::digest(
            serde_json::to_vec(section).unwrap_or_default(),
        ))
    })
}

fn seal_section(
    id: &str,
    ok: bool,
    falsification_class: &str,
    evidence: Value,
    fix_hint: &str,
    industry: &[&str],
) -> Value {
    let mut sec = json!({
        "id": id,
        "ok": ok,
        "falsification_class": falsification_class,
        "fix_hint": fix_hint,
        "industry_maps": industry,
        "evidence": evidence,
    });
    let d = section_digest(&sec);
    if let Some(obj) = sec.as_object_mut() {
        obj.insert("section_digest_sha256".into(), json!(d));
    }
    sec
}

fn measure_sections(state: &PlatformState, agent_pid: &str) -> (Vec<Value>, Value) {
    let pllm = crate::substrate::probabilistic_llm::status();
    let id_stack = crate::substrate::identity_stack::posture_json();
    let agentic = crate::substrate::agentic_context::status();
    let broker = crate::substrate::llm_context_broker::status();
    let broker_gate = crate::substrate::llm_broker_gate::status();
    let sealed = crate::substrate::llm_sealed_context::status();
    let tokenization = crate::substrate::data_tokenization::status();
    let sandbox = crate::substrate::llm_agent_sandbox::status();
    let exclusivity = crate::substrate::effect_exclusivity::effect_exclusivity_status(state);
    let grants = crate::kernel::world_gateway::list_grants(state, Some(agent_pid));
    let grant_n = grants.len();
    let isolation = crate::kernel::isolation_tiers::isolation_for_agent(state, agent_pid);
    let address_dac = crate::kernel::address_contracts::posture_json();

    let hitl_pending = crate::services::agents::hitl_store_snapshot()
        .values()
        .filter(|r| r.agent_pid == agent_pid && r.status == "pending")
        .count();
    let hitl_approved = crate::services::agents::hitl_store_snapshot()
        .values()
        .filter(|r| {
            r.agent_pid == agent_pid && matches!(r.status.as_str(), "approved" | "consumed")
        })
        .count();

    let package = crate::kernel::forensic_package::build_package(state, agent_pid, None, None).ok();
    let package_tier = package
        .as_ref()
        .and_then(|pkg| {
            pkg.pointer("/manifest/signing_tier")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "hmac_lab".into());
    let package_root = package
        .as_ref()
        .and_then(|pkg| {
            pkg.pointer("/verify/manifest_digest")
                .or_else(|| pkg.pointer("/manifest/package_root_sha256"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    let receipt_head = crate::kernel::forensics::chain_head_for_agent(state, agent_pid);
    let receipt_count = package
        .as_ref()
        .and_then(|p| p.pointer("/manifest/receipt_count").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let quarantined = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
        .and_then(|m| m.get("quarantined").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    let distrust = pllm
        .get("distrust_enforced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let broker_on = broker
        .get("enforced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sections = vec![
        seal_section(
            "S0_honesty",
            true,
            "live_measure",
            json!({
                "playground": playground(),
                "not_cpa": true,
                "not_ocr_baa": true,
                "not_military_auto": true,
                "cd8_status": "pending_human",
                "cd9_status": "pending_counsel",
                "package_signing_tier": package_tier,
                "standard_version": STANDARD_VERSION,
            }),
            "Complete CD-8 WitnessCtl quorum + CD-9 counsel before marketing court-grade",
            &["SOC2", "ISO42001", "EU_AI_Act"],
        ),
        seal_section(
            "S1_probabilistic_identity",
            distrust || playground(),
            "live_measure",
            json!({
                "probabilistic_llm": pllm,
                "identity_stack": id_stack,
                "agentic_context": agentic,
                "address_dac": address_dac,
                "stance": "LLM/agent claims are not root of trust — continuous verify"
            }),
            "Enable probabilistic distrust + mint identity stack / IntelligenceSpec",
            &["NIST_Agent_Identity", "SOC2_CC6", "EU_Art14", "OWASP_ASI03"],
        ),
        seal_section(
            "S2_zero_trust_distributed",
            grant_n > 0 || playground(),
            "live_measure",
            json!({
                "world_grants_count": grant_n,
                "isolation": isolation,
                "effect_exclusivity": exclusivity,
                "stance": "deny-by-default world addresses; tenant NS; no ambient trust"
            }),
            "Owner grants Cone/App per tool:* / mcp:* address before world egress",
            &["NIST_CSF_PR", "ISO42001", "ZT_continuous_verify"],
        ),
        seal_section(
            "S3_autonomy_augmentation",
            true,
            "live_measure",
            json!({
                "admission_layers": crate::kernel::admission_layers::catalog(),
                "stance": "Root/Cone Ask until HITL digest; App Allow needs justification ≥16 chars"
            }),
            "Keep autonomy tier mapped to CSA Agentic Profile oversight obligations",
            &["CSA_Agentic_Profile", "EU_Art14", "ISO42001_8"],
        ),
        seal_section(
            "S4_tool_world_effects",
            grant_n > 0 || playground(),
            "live_measure",
            json!({
                "grants_sample": grants.into_iter().take(12).collect::<Vec<_>>(),
                "policy_decision": "admit_world + admit_tool_or_ask before dispatch"
            }),
            "Seed tool lane grants; require non-empty agent_pid on MCP invoke",
            &["OWASP_ASI02", "SOC2_CC6", "EU_Art12"],
        ),
        seal_section(
            "S5_llm_broker_lane",
            broker_on || playground(),
            "live_measure",
            json!({
                "broker": broker,
                "broker_gate": broker_gate,
                "sealed_context": sealed,
                "tokenization": tokenization,
                "sandbox": sandbox,
                "semantics": "200 resume / 409 redo / 499 need human"
            }),
            "CONNECTOR_LLM_CONTEXT_BROKER=1; never UNBYPASSABLE on shared Fly without host bar",
            &["SOC2_C1", "EU_Art15", "OWASP_ASI06", "HIPAA_164.312e"],
        ),
        seal_section(
            "S6_hitl_human_retrieval",
            true,
            "live_measure",
            json!({
                "pending": hitl_pending,
                "approved_or_consumed": hitl_approved,
                "digest_bound": true,
            }),
            "Approve digest-bound HITL; Force only as session break-glass on playground",
            &["EU_Art14", "ISO42001_oversight", "SOC2_approvals"],
        ),
        seal_section(
            "S7_continuous_audit_spine",
            receipt_head.is_some() || package_tier == "ed25519_court" || receipt_count > 0,
            if package_tier == "ed25519_court" {
                "ed25519_court"
            } else {
                "hmac_custody"
            },
            json!({
                "iia_chain_head": receipt_head,
                "receipt_count": receipt_count,
                "package_signing_tier": package_tier,
                "package_manifest_digest": package_root,
            }),
            "Activate court profile + Ed25519 receipts; empty stub scan for B26 court package",
            &["EU_Art12", "SOC2_CC7", "ISO42001_9", "Court_CD1_CD7"],
        ),
        seal_section(
            "S8_lifecycle_aims",
            true,
            "live_measure",
            json!({
                "agent_pid": agent_pid,
                "quarantined": quarantined,
                "aims": "ISO 42001 operational record — risk, impact, monitoring hooks"
            }),
            "Close quarantine via HITL; keep lifecycle audits continuous",
            &["ISO42001_6", "ISO42001_8", "EU_Art9", "EU_Art72"],
        ),
        seal_section(
            "S9_framework_soa",
            true,
            "live_measure",
            json!({
                "frameworks": [
                    "soc2_tsc", "hipaa_164", "nist_csf_2", "nist_ai_rmf_agentic",
                    "iso_42001", "eu_ai_act", "owasp_agentic", "csa_aicm"
                ],
                "stance": "SoA rows bind to section_digest_sha256 — never static coverage %"
            }),
            "Export framework= on GET /aacr/report for auditor-facing projection",
            &["ISO42001_SoA", "multi_framework"],
        ),
    ];

    let bindings = json!({
        "forensic_package_tier": package_tier,
        "forensic_manifest_digest": package_root,
        "iia_chain_head": crate::kernel::forensics::chain_head_for_agent(state, agent_pid),
        "node_pubkey_hex": state.signing_key.public_key_hex(),
        "court_readiness": "GET /api/v1/forensics/court-readiness?agent_pid=",
        "soas": "GET /api/v1/soas/report?agent_pid=",
    });

    (sections, bindings)
}

fn overall_grade(sections: &[Value], signing_tier: &str) -> String {
    if playground() {
        return "playground_demo".into();
    }
    let ok_n = sections
        .iter()
        .filter(|s| s.get("ok").and_then(|x| x.as_bool()) == Some(true))
        .count();
    let s7_ok = sections
        .iter()
        .find(|s| s.get("id").and_then(|x| x.as_str()) == Some("S7_continuous_audit_spine"))
        .and_then(|s| s.get("ok").and_then(|x| x.as_bool()))
        .unwrap_or(false);
    if signing_tier == "ed25519_court" && s7_ok && ok_n >= 8 {
        return "court_adoptable_pending_cd89".into();
    }
    if ok_n >= 7 {
        return "governance".into();
    }
    if ok_n >= 4 {
        return "host_lab".into();
    }
    "incomplete".into()
}

fn build_full_soa(sections: &[Value]) -> Value {
    let frameworks = [
        "soc2",
        "hipaa",
        "nist",
        "iso42001",
        "eu_ai_act",
        "owasp_agentic",
        "nist_ai_rmf_agentic",
    ];
    let mut out = serde_json::Map::new();
    for fw in frameworks {
        out.insert(fw.into(), framework_projection(sections, fw));
    }
    Value::Object(out)
}

fn framework_projection(sections: &[Value], framework: &str) -> Value {
    let fw = framework.trim().to_ascii_lowercase();
    let map = match fw.as_str() {
        "soc2" | "soc2_tsc" => json!([
            {"control_id": "CC6.1", "aacr": "S1_probabilistic_identity", "note": "Agent principal distinct from human JWT"},
            {"control_id": "CC6.2", "aacr": "S2_zero_trust_distributed", "note": "Least-privilege world grants"},
            {"control_id": "CC6.8", "aacr": "S5_llm_broker_lane", "note": "Injection / broker sanitize"},
            {"control_id": "CC7.2", "aacr": "S7_continuous_audit_spine", "note": "Continuous monitoring / IIA"},
            {"control_id": "CC7.3", "aacr": "S6_hitl_human_retrieval", "note": "Security events + human approval"},
            {"control_id": "CC8.1", "aacr": "S8_lifecycle_aims", "note": "Change / lifecycle"},
        ]),
        "hipaa" | "hipaa_164" => json!([
            {"control_id": "164.308(a)(4)", "aacr": "S2_zero_trust_distributed", "note": "Access management"},
            {"control_id": "164.312(a)", "aacr": "S2_zero_trust_distributed", "note": "Access control"},
            {"control_id": "164.312(b)", "aacr": "S7_continuous_audit_spine", "note": "Audit controls"},
            {"control_id": "164.312(c)", "aacr": "S7_continuous_audit_spine", "note": "Integrity"},
            {"control_id": "164.312(e)", "aacr": "S5_llm_broker_lane", "note": "Transmission — tokenize / vault handles"},
        ]),
        "nist" | "nist_csf" => json!([
            {"control_id": "GV", "aacr": "S0_honesty", "note": "Govern"},
            {"control_id": "ID", "aacr": "S1_probabilistic_identity", "note": "Identify agents"},
            {"control_id": "PR", "aacr": "S2_zero_trust_distributed", "note": "Protect"},
            {"control_id": "DE", "aacr": "S7_continuous_audit_spine", "note": "Detect"},
            {"control_id": "RS", "aacr": "S6_hitl_human_retrieval", "note": "Respond"},
            {"control_id": "RC", "aacr": "S8_lifecycle_aims", "note": "Recover / lifecycle"},
        ]),
        "nist_ai_rmf_agentic" => json!([
            {"control_id": "GOVERN.autonomy", "aacr": "S3_autonomy_augmentation", "note": "Autonomy tiering"},
            {"control_id": "MAP.tool_risk", "aacr": "S4_tool_world_effects", "note": "Tool-use risk"},
            {"control_id": "MEASURE.runtime", "aacr": "S7_continuous_audit_spine", "note": "Runtime metrics"},
            {"control_id": "MANAGE.incident", "aacr": "S6_hitl_human_retrieval", "note": "HITL / quarantine"},
            {"control_id": "IDENTITY", "aacr": "S1_probabilistic_identity", "note": "Agent identity"},
        ]),
        "iso42001" => json!([
            {"control_id": "6.1", "aacr": "S8_lifecycle_aims", "note": "AI risk"},
            {"control_id": "6.1.4", "aacr": "S1_probabilistic_identity", "note": "Impact / identity"},
            {"control_id": "8.2", "aacr": "S3_autonomy_augmentation", "note": "Operation / oversight"},
            {"control_id": "9.1", "aacr": "S7_continuous_audit_spine", "note": "Monitoring"},
            {"control_id": "SoA", "aacr": "S9_framework_soa", "note": "Statement of Applicability"},
        ]),
        "eu_ai_act" => json!([
            {"control_id": "Art.9", "aacr": "S8_lifecycle_aims", "note": "Risk management"},
            {"control_id": "Art.11", "aacr": "S9_framework_soa", "note": "Technical documentation"},
            {"control_id": "Art.12", "aacr": "S7_continuous_audit_spine", "note": "Logging"},
            {"control_id": "Art.14", "aacr": "S6_hitl_human_retrieval", "note": "Human oversight"},
            {"control_id": "Art.15", "aacr": "S5_llm_broker_lane", "note": "Accuracy / robustness / cyber"},
        ]),
        "owasp_agentic" => json!([
            {"control_id": "ASI01", "aacr": "S3_autonomy_augmentation", "note": "Goal hijack / autonomy"},
            {"control_id": "ASI02", "aacr": "S4_tool_world_effects", "note": "Tool misuse"},
            {"control_id": "ASI03", "aacr": "S1_probabilistic_identity", "note": "Identity / privilege"},
            {"control_id": "ASI06", "aacr": "S5_llm_broker_lane", "note": "Memory / context"},
            {"control_id": "ASI07", "aacr": "S2_zero_trust_distributed", "note": "Inter-agent boundaries"},
        ]),
        _ => json!([
            {"control_id": "*", "aacr": "S9_framework_soa", "note": "framework=soc2|hipaa|nist|nist_ai_rmf_agentic|iso42001|eu_ai_act|owasp_agentic"}
        ]),
    };
    let rows: Vec<Value> = map
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|row| {
            let sid = row.get("aacr").and_then(|x| x.as_str()).unwrap_or("");
            let sec = sections
                .iter()
                .find(|s| s.get("id").and_then(|x| x.as_str()) == Some(sid));
            json!({
                "control_id": row.get("control_id"),
                "aacr_section": sid,
                "ok": sec.and_then(|s| s.get("ok").and_then(|x| x.as_bool())).unwrap_or(false),
                "section_digest_sha256": sec.and_then(|s| s.get("section_digest_sha256")).cloned(),
                "falsification_class": sec.and_then(|s| s.get("falsification_class")).cloned(),
                "note": row.get("note"),
            })
        })
        .collect();
    let pass = rows
        .iter()
        .filter(|r| r.get("ok").and_then(|x| x.as_bool()) == Some(true))
        .count();
    json!({
        "framework": fw,
        "controls_total": rows.len(),
        "controls_ok": pass,
        "rows": rows,
        "honesty": "Projection only — not a CPA/OCR attestation"
    })
}

/// Mint a new AACR epoch for an agent (kernel-owned).
pub fn mint(state: &PlatformState, agent_pid: &str) -> Result<Value, String> {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return Err("agent_pid_required".into());
    }
    let now = chrono::Utc::now();
    let record_id = format!("aacr_{}", uuid::Uuid::new_v4().simple());
    let prev = head_for_agent(state, pid);
    let (sections, bindings) = measure_sections(state, pid);
    let soa = build_full_soa(&sections);
    let eligible = court_sign_eligible(state, pid);
    let window_ms: i64 = 30 * 86_400_000;

    let mut body = json!({
        "schema": SCHEMA,
        "standard": "Augmented Agentic Compliance Record",
        "standard_version": STANDARD_VERSION,
        "record_id": record_id,
        "agent_pid": pid,
        "issued_at": now.to_rfc3339(),
        "issued_at_ms": now.timestamp_millis(),
        "observation_window": {
            "from_ms": now.timestamp_millis() - window_ms,
            "to_ms": now.timestamp_millis(),
            "days": 30,
        },
        "previous_aacr_digest": prev.as_ref().map(|(d, _)| d.clone()),
        "previous_record_id": prev.as_ref().map(|(_, id)| id.clone()),
        "sections": sections,
        "statement_of_applicability": soa,
        "bindings": bindings,
        "honesty": {
            "not_cpa": true,
            "not_ocr_baa": true,
            "not_auto_court": true,
            "cd8_status": "pending_human",
            "cd9_status": "pending_counsel",
            "playground": playground(),
            "stance": "Probabilistic identity · zero-trust distributed · LLM untrusted until admit+HITL+broker",
            "adoption": "Court-adoptable after CD-1…CD-7 machine gates + CD-8 custody + CD-9 counsel — never auto-green"
        },
    });

    let content_digest = canonical_digest_json(&body).map_err(|e| e.to_string())?;
    let chain_head = hex::encode(Sha256::digest(
        format!(
            "{}|{}|{}",
            record_id,
            content_digest,
            prev.as_ref()
                .map(|(d, _)| d.as_str())
                .unwrap_or("genesis")
        )
        .as_bytes(),
    ));

    let (signing_tier, signature): (String, Option<SignedPayloadV2>) = if eligible {
        match sign_json_ed25519(state.signing_key.ed25519(), &body) {
            Ok(sig) => ("ed25519_court".into(), Some(sig)),
            Err(_) => ("hmac_lab".into(), None),
        }
    } else {
        ("hmac_lab".into(), None)
    };

    let grade = overall_grade(
        body.get("sections")
            .and_then(|s| s.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]),
        &signing_tier,
    );

    let section_rollup = {
        let mut h = Sha256::new();
        if let Some(arr) = body.get("sections").and_then(|s| s.as_array()) {
            for s in arr {
                if let Some(d) = s.get("section_digest_sha256").and_then(|x| x.as_str()) {
                    h.update(d.as_bytes());
                }
            }
        }
        hex::encode(h.finalize())
    };

    if let Some(obj) = body.as_object_mut() {
        obj.insert("content_digest_sha256".into(), json!(content_digest));
        obj.insert("section_digest_rollup_sha256".into(), json!(section_rollup));
        obj.insert("chain_head_digest".into(), json!(chain_head));
        obj.insert("signing_tier".into(), json!(signing_tier));
        obj.insert("overall_grade".into(), json!(grade));
        obj.insert(
            "node_pubkey_hex".into(),
            json!(state.signing_key.public_key_hex()),
        );
        if let Some(sig) = signature {
            obj.insert(
                "signature".into(),
                serde_json::to_value(sig).unwrap_or(Value::Null),
            );
        } else {
            obj.insert("signature".into(), Value::Null);
        }
        obj.insert(
            "falsification_class".into(),
            json!(if signing_tier == "ed25519_court" {
                "ed25519_court"
            } else {
                "live_measure"
            }),
        );
        obj.insert(
            "verify".into(),
            json!({
                "cli": "connectorctl aacr verify --file <aacr.json>",
                "http": "POST /api/v1/aacr/verify",
                "rule": "Any mutation of signed body fields MUST fail content_digest / Ed25519 verify",
            }),
        );
    }

    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let prev_count = es
            .folder_get(INDEX_FOLDER, pid)
            .ok()
            .flatten()
            .and_then(|v| v.get("count").and_then(|c| c.as_u64()))
            .unwrap_or(0);
        es.folder_put(FOLDER, &record_id, &body)
            .map_err(|e| e.to_string())?;
        es.folder_put(
            INDEX_FOLDER,
            pid,
            &json!({
                "head_digest": body.get("chain_head_digest"),
                "content_digest": body.get("content_digest_sha256"),
                "section_digest_rollup": body.get("section_digest_rollup_sha256"),
                "last_id": record_id,
                "count": prev_count + 1,
                "overall_grade": grade,
                "signing_tier": signing_tier,
                "standard_version": STANDARD_VERSION,
            }),
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(body)
}

pub fn latest(state: &PlatformState, agent_pid: &str) -> Option<Value> {
    let (_, id) = head_for_agent(state, agent_pid)?;
    let es = state.engine_store.lock().ok()?;
    es.folder_get(FOLDER, &id).ok().flatten()
}

pub fn chain_summary(state: &PlatformState, agent_pid: &str) -> Value {
    let idx = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get(INDEX_FOLDER, agent_pid).ok().flatten())
        .unwrap_or(json!({}));
    let latest_rec = latest(state, agent_pid);
    let verified = latest_rec
        .as_ref()
        .map(verify_record)
        .unwrap_or(json!({ "ok": false, "error": "no_record" }));
    let link_ok = verify_prev_link(state, agent_pid, latest_rec.as_ref());
    json!({
        "ok": true,
        "schema": SCHEMA,
        "standard_version": STANDARD_VERSION,
        "agent_pid": agent_pid,
        "index": idx,
        "latest_verify": verified,
        "previous_link_ok": link_ok,
    })
}

fn verify_prev_link(state: &PlatformState, agent_pid: &str, latest: Option<&Value>) -> Value {
    let Some(rec) = latest else {
        return json!({ "ok": false, "error": "no_latest" });
    };
    let prev_digest = rec
        .get("previous_aacr_digest")
        .and_then(|v| v.as_str());
    let Some(prev_d) = prev_digest else {
        return json!({ "ok": true, "genesis": true });
    };
    let prev_id = rec
        .get("previous_record_id")
        .and_then(|v| v.as_str());
    let Some(pid) = prev_id else {
        return json!({ "ok": false, "error": "missing_previous_record_id" });
    };
    let prev = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get(FOLDER, pid).ok().flatten());
    let Some(prev) = prev else {
        return json!({ "ok": false, "error": "previous_record_missing", "id": pid });
    };
    let actual = prev
        .get("chain_head_digest")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "ok": actual == prev_d,
        "expected": prev_d,
        "actual_previous_chain_head": actual,
        "agent_pid": agent_pid,
    })
}

/// Verify an AACR JSON object (digest + optional Ed25519).
pub fn verify_record(record: &Value) -> Value {
    let Some(digest) = record.get("content_digest_sha256").and_then(|v| v.as_str()) else {
        return json!({ "ok": false, "error": "missing_content_digest" });
    };
    let mut body = record.clone();
    if let Some(obj) = body.as_object_mut() {
        for k in [
            "content_digest_sha256",
            "section_digest_rollup_sha256",
            "chain_head_digest",
            "signing_tier",
            "overall_grade",
            "signature",
            "falsification_class",
            "node_pubkey_hex",
            "verify",
        ] {
            obj.remove(k);
        }
    }
    let Ok(recomputed) = canonical_digest_json(&body) else {
        return json!({ "ok": false, "error": "digest_serialize_failed" });
    };
    if recomputed != digest {
        return json!({
            "ok": false,
            "error": "content_digest_mismatch",
            "expected": digest,
            "recomputed": recomputed,
        });
    }

    // Re-check section digests.
    let mut section_ok = true;
    if let Some(arr) = body.get("sections").and_then(|s| s.as_array()) {
        for s in arr {
            let stored = s
                .get("section_digest_sha256")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let mut copy = s.clone();
            if let Some(o) = copy.as_object_mut() {
                o.remove("section_digest_sha256");
            }
            let d = section_digest(&copy);
            // section was sealed WITH digest field included in seal_section before digest insert...
            // Our seal_section digests BEFORE inserting digest — stored digest is over undigested form.
            // Recompute same way: strip digest then hash.
            if d != stored && !stored.is_empty() {
                // Try digest of full section including digest field (legacy).
                let full = canonical_digest_json(s).unwrap_or_default();
                if full != stored {
                    section_ok = false;
                    break;
                }
            }
        }
    }

    let tier = record
        .get("signing_tier")
        .and_then(|v| v.as_str())
        .unwrap_or("hmac_lab");
    if tier == "ed25519_court" {
        if let Ok(payload) = serde_json::from_value::<SignedPayloadV2>(
            record.get("signature").cloned().unwrap_or(Value::Null),
        ) {
            let ok = verify_signed_payload_v2(&body, &payload) && section_ok;
            return json!({
                "ok": ok,
                "signing_tier": tier,
                "falsification_class": "ed25519_court",
                "content_digest_sha256": digest,
                "section_digests_ok": section_ok,
                "standard_version": record.get("standard_version"),
            });
        }
        return json!({
            "ok": false,
            "error": "court_tier_missing_signature",
            "signing_tier": tier,
        });
    }
    json!({
        "ok": section_ok,
        "signing_tier": tier,
        "falsification_class": "live_measure",
        "content_digest_sha256": digest,
        "section_digests_ok": section_ok,
        "honesty": "Lab/live measure — digest intact but not court Ed25519",
        "standard_version": record.get("standard_version"),
    })
}

pub fn report(state: &PlatformState, agent_pid: &str, framework: &str) -> Value {
    let rec = latest(state, agent_pid).unwrap_or_else(|| {
        mint(state, agent_pid).unwrap_or_else(|e| json!({"ok": false, "error": e}))
    });
    let sections = rec
        .get("sections")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    let fw = if framework.trim().is_empty() || framework == "all" {
        build_full_soa(&sections)
    } else {
        framework_projection(&sections, framework)
    };
    json!({
        "ok": true,
        "schema": SCHEMA,
        "standard_version": STANDARD_VERSION,
        "aacr": rec,
        "framework_projection": fw,
        "verify": verify_record(&rec),
        "chain": chain_summary(state, agent_pid),
    })
}

pub fn head_content_digest(state: &PlatformState, agent_pid: &str) -> Option<String> {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get(INDEX_FOLDER, agent_pid).ok().flatten())
        .and_then(|v| {
            v.get("content_digest")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
}

/// Binding blob for forensic package MANIFEST consumers.
pub fn binding_for_package(state: &PlatformState, agent_pid: &str) -> Value {
    let idx = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get(INDEX_FOLDER, agent_pid).ok().flatten())
        .unwrap_or(json!({}));
    json!({
        "schema": SCHEMA,
        "standard_version": STANDARD_VERSION,
        "agent_pid": agent_pid,
        "aacr_index": idx,
        "mint": "POST /api/v1/aacr/mint?agent_pid=",
        "verify": "POST /api/v1/aacr/verify",
    })
}
