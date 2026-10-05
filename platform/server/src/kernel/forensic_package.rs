//! Forensic package builder — MANIFEST + joined evidence for DFIR/GRC (P10.10.6).

use connector_trust::{
    canonical_digest_json, sign_json_ed25519, ForensicPackageHonestyV2, ForensicPackageManifestV2,
    FORENSIC_PACKAGE_SCHEMA, SigningTierV2,
};
use sha2::{Digest, Sha256};

use crate::kernel::{
    agent_identity_envelope, agent_principal, compliance_contract, forensic_rollups, forensics,
};
use crate::state::PlatformState;

pub fn build_package(
    state: &PlatformState,
    api_pid: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<serde_json::Value, String> {
    let setup = agent_identity_envelope::load_setup(state, api_pid)
        .ok_or("setup_not_found")?;
    let contract = compliance_contract::load_compliance_contract(state, api_pid);
    let receipts = forensics::export_receipt_chain(state, api_pid);
    let universals = agent_identity_envelope::list_forensic_universal(state, api_pid);
    let rollups = forensic_rollups::list_rollups(state, api_pid, from_ms, to_ms);
    let joins = forensic_rollups::list_joins(state, api_pid);

    let from = from_ms.unwrap_or_else(|| {
        receipts
            .first()
            .map(|r| r.issued_at_ms)
            .or_else(|| universals.first().map(|u| u.issued_at_ms))
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis())
    });
    let to = to_ms.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let filtered_receipts: Vec<_> = receipts
        .into_iter()
        .filter(|r| r.issued_at_ms >= from && r.issued_at_ms <= to)
        .collect();
    let filtered_universals: Vec<_> = universals
        .into_iter()
        .filter(|u| u.issued_at_ms >= from && u.issued_at_ms <= to)
        .collect();
    let filtered_joins: Vec<_> = joins
        .into_iter()
        .filter(|j| j.issued_at_ms >= from && j.issued_at_ms <= to)
        .collect();

    let iia_head = forensics::chain_head_for_agent(state, api_pid);
    let segment_roots: Vec<String> = rollups
        .iter()
        .map(|r| r.events_merkle_root.clone())
        .collect();

    let package_id = format!(
        "fp_{}_{}",
        api_pid,
        &hex::encode(Sha256::digest(format!("{from}|{to}").as_bytes()))[..12]
    );

    let root_material = format!(
        "{}|{}|{}|{}|{}",
        package_id,
        iia_head.as_deref().unwrap_or("none"),
        filtered_receipts.len(),
        filtered_universals.len(),
        segment_roots.join(",")
    );
    let package_root = hex::encode(Sha256::digest(root_material.as_bytes()));

    let principal_id = filtered_receipts
        .first()
        .map(|r| r.principal_id.clone())
        .or_else(|| contract.as_ref().map(|c| c.principal_id.clone()))
        .unwrap_or_default();

    let mut manifest = ForensicPackageManifestV2 {
        schema: FORENSIC_PACKAGE_SCHEMA.into(),
        package_id: package_id.clone(),
        from_ms: from,
        to_ms: to,
        agent_pid: api_pid.to_string(),
        principal_id,
        acume: setup.acume.clone(),
        witnessctl_session_id: contract
            .as_ref()
            .and_then(|c| c.witnessctl_session_id.clone())
            .or_else(|| {
                agent_identity_envelope::load_activation(state, api_pid)
                    .and_then(|a| a.witnessctl_session_hint)
            }),
        compliance_contract_id: contract.as_ref().map(|c| c.contract_id.clone()),
        signing_tier: SigningTierV2::HmacLab,
        package_root_sha256: package_root,
        iia_chain_head: iia_head,
        artifact_log_segment_roots: segment_roots,
        honesty: ForensicPackageHonestyV2 {
            hmac_paths_present: true,
            hmac_not_court_grade: true,
            fni_verify_status: if crate::substrate::cfni::cfni_enabled() {
                "cfni_enabled_verify_per_capture".into()
            } else {
                "cfni_disabled".into()
            },
            stubs_in_window: scan_stubs_in_window(
                &filtered_receipts,
                &filtered_universals,
            ),
        },
        receipt_count: filtered_receipts.len() as u64,
        universal_envelope_count: filtered_universals.len() as u64,
        rollup_count: rollups.len() as u64,
        join_count: filtered_joins.len() as u64,
        verify_cli: "connectorctl iia verify-export --file export.json".into(),
        issued_at_ms: chrono::Utc::now().timestamp_millis(),
        signature: None,
    };

    if let Ok(sig) = sign_json_ed25519(state.signing_key.ed25519(), &manifest) {
        manifest.signature = Some(sig);
    }
    // B26: court package only when signed, no stubs, and all receipts court-signed.
    let receipts_court = !filtered_receipts.is_empty()
        && filtered_receipts.iter().all(|r| {
            matches!(r.signing_tier, SigningTierV2::Ed25519Court) && r.signature.is_some()
        });
    let court_ok = manifest.signature.is_some()
        && manifest.honesty.stubs_in_window.is_empty()
        && receipts_court;
    manifest.signing_tier = if court_ok {
        SigningTierV2::Ed25519Court
    } else {
        SigningTierV2::HmacLab
    };
    manifest.honesty.hmac_not_court_grade = !court_ok;
    manifest.honesty.hmac_paths_present = !court_ok;

    let envelope = agent_identity_envelope::build_identity_envelope(state, api_pid);
    let scorecard = build_control_scorecard(
        state,
        api_pid,
        &contract,
        &filtered_receipts,
        &rollups,
        from,
        to,
    );

    // TG-5: decision traces + approval resolutions in package
    let traces = crate::kernel::decision_trace::list_traces(state, api_pid, Some(from), Some(to));
    let chain_ok = crate::kernel::decision_trace::verify_trace_chain(&traces).is_ok();
    let approval_resolutions: Vec<_> = traces
        .iter()
        .filter_map(|t| {
            t.approval_resolution_id.as_ref().map(|rid| {
                serde_json::json!({
                    "resolution_id": rid,
                    "trace_id": t.trace_id,
                    "action_digest": t.action_digest,
                    "at_ms": t.at_ms,
                })
            })
        })
        .collect();
    let agent_contract = agent_principal::load_contract(state, api_pid);

    Ok(serde_json::json!({
        "ok": true,
        "schema": FORENSIC_PACKAGE_SCHEMA,
        "manifest": manifest,
        "compliance_contract": contract,
        "agent_contract_digest": agent_contract.as_ref().map(|c| &c.contract_digest_sha256),
        "identity_envelope": envelope,
        "timeline": {
            "rollups": rollups,
            "iia_chain_head": forensics::chain_head_for_agent(state, api_pid),
        },
        "receipts": {
            "intelligence_receipts": filtered_receipts,
            "universal_envelopes": filtered_universals,
        },
        "decision_traces": crate::kernel::decision_trace::traces_json(&traces),
        "approval_resolutions": approval_resolutions,
        "correlation": {
            "joins": filtered_joins,
        },
        "control_matrix": scorecard,
        "aacr": crate::kernel::aacr::binding_for_package(state, api_pid),
        "verify": {
            "node_pubkey_hex": state.signing_key.public_key_hex(),
            "cli": "connectorctl iia verify-export --file <export>",
            "aacr_cli": "connectorctl aacr verify --file <aacr.json>",
            "rule": "Any single-byte change in a court-tier receipt MUST fail verify",
            "decision_trace_chain_ok": chain_ok,
            "manifest_digest": canonical_digest_json(&manifest).ok(),
        },
    }))
}

/// B28: honesty scan — env stubs + unsigned / hmac-tier artifacts in the window.
fn scan_stubs_in_window(
    receipts: &[connector_trust::IntelligenceReceiptV2],
    universals: &[connector_trust::ForensicUniversalEnvelopeV2],
) -> Vec<String> {
    let mut stubs = Vec::new();
    let env_true = |k: &str| {
        std::env::var(k)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    };
    if env_true("CONNECTOR_LLM_STUB") {
        stubs.push("env:CONNECTOR_LLM_STUB".into());
    }
    if env_true("CONNECTOR_VAC_ALLOW_PLAINTEXT_SECRETS") {
        stubs.push("env:CONNECTOR_VAC_ALLOW_PLAINTEXT_SECRETS".into());
    }
    if env_true("VAC_ALLOW_STUB_AUDIT_SIG") {
        stubs.push("env:VAC_ALLOW_STUB_AUDIT_SIG".into());
    }
    for r in receipts {
        if r.signature.is_none() {
            stubs.push(format!("receipt_unsigned:{}", r.receipt_id));
        } else if matches!(r.signing_tier, SigningTierV2::HmacLab) {
            stubs.push(format!("receipt_hmac_lab:{}", r.receipt_id));
        }
    }
    for u in universals {
        if matches!(u.signing_tier, SigningTierV2::HmacLab) {
            stubs.push(format!("universal_hmac_lab:{}", u.envelope_id));
        }
    }
    stubs.sort();
    stubs.dedup();
    stubs
}

fn build_control_scorecard(
    state: &PlatformState,
    api_pid: &str,
    contract: &Option<connector_trust::ComplianceContractV2>,
    receipts: &[connector_trust::IntelligenceReceiptV2],
    rollups: &[connector_trust::ForensicRollupBucketV2],
    from_ms: i64,
    to_ms: i64,
) -> serde_json::Value {
    let isolation_ok = contract
        .as_ref()
        .map(|c| c.isolation_enforced)
        .unwrap_or(false);
    let chain_ok = !receipts.is_empty()
        && receipts.iter().all(|r| {
            matches!(r.signing_tier, SigningTierV2::Ed25519Court) && r.signature.is_some()
        });
    let merkle_ok = rollups.iter().all(|r| !r.events_merkle_root.is_empty());
    let deny_count: u64 = rollups.iter().map(|r| r.counts.admission_deny).sum();
    let cross_deny: u64 = rollups
        .iter()
        .map(|r| r.memory_trace.cross_agent_attempts_denied)
        .sum();

    let frameworks = contract
        .as_ref()
        .map(|c| c.frameworks.clone())
        .unwrap_or_default();

    let controls = vec![
        serde_json::json!({
            "id": "soc2.cc6.1.access_controls",
            "passed": isolation_ok,
            "evidence": [format!("compliance_contract:{}", contract.as_ref().map(|c| c.contract_id.as_str()).unwrap_or("none"))],
        }),
        serde_json::json!({
            "id": "soc2.cc6.6.namespace_isolation",
            "passed": isolation_ok,
            "cross_agent_denies": cross_deny,
            "evidence": ["admission:namespace_isolation", "GET /memory/recall2 with X-Connector-Agent-Pid"],
        }),
        serde_json::json!({
            "id": "soc2.cc7.2.data_integrity",
            "passed": chain_ok && merkle_ok,
            "receipt_count": receipts.len(),
            "rollup_count": rollups.len(),
            "evidence": ["intelligence_receipt_v2", "forensic_rollup_bucket_v2.events_merkle_root"],
        }),
        serde_json::json!({
            "id": "soc2.cc7.4.anomaly_detection",
            "passed": true,
            "admission_denies": deny_count,
            "evidence": ["forensic_rollup_bucket_v2.counts.admission_deny"],
        }),
        serde_json::json!({
            "id": "hipaa.164.312.b.audit_controls",
            "passed": !receipts.is_empty() || !rollups.is_empty(),
            "evidence": ["forensic_universal_envelope_v2", "intelligence_receipt_v2"],
        }),
        serde_json::json!({
            "id": "hipaa.164.312.c.integrity",
            "passed": chain_ok,
            "evidence": ["ed25519_court signatures on receipts"],
        }),
        serde_json::json!({
            "id": "eu_ai_act.art.12.logging",
            "passed": !rollups.is_empty() || !receipts.is_empty(),
            "evidence": ["forensic_package timeline"],
        }),
        {
            // B19: human oversight = actual HITL decisions in window, not merely policy≠None.
            let (approved, denied) =
                crate::services::agents::hitl_decisions_in_window(api_pid, from_ms, to_ms);
            let policy_on = contract
                .as_ref()
                .map(|c| !matches!(c.hitl_policy, connector_trust::HitlPolicyV2::None))
                .unwrap_or(false);
            let decisions = approved + denied;
            serde_json::json!({
                "id": "eu_ai_act.art.14.human_oversight",
                "passed": policy_on && decisions > 0,
                "hitl_approved_in_window": approved,
                "hitl_denied_in_window": denied,
                "policy_configured": policy_on,
                "evidence": if decisions > 0 {
                    vec!["hitl_decisions_in_window", "compliance_contract.hitl_policy"]
                } else {
                    vec!["no_hitl_decisions_in_window"]
                },
            })
        },
    ];

    let passed = controls.iter().filter(|c| c.get("passed").and_then(|v| v.as_bool()).unwrap_or(false)).count();
    let score = (passed * 100) / controls.len().max(1);

    serde_json::json!({
        "schema": "connector.compliance_scorecard.v2",
        "agent_pid": api_pid,
        "frameworks_bound": frameworks,
        "score": score,
        "passed": score >= 80,
        "controls": controls,
        "witnessctl_export_hint": "/plugins/witnessctl/api/v1/export/{session_id}",
        "platform_compliance": "/api/v1/compliance/scorecard",
        "iia_receipt_index_count": forensics::receipt_index_count(state, api_pid),
    })
}
