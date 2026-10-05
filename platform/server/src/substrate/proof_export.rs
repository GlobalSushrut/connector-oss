//! E5 — Proof export for an agent (and optional mission) window.
//! Reconstructible worldline: digests, receipts, journals, DIM — not a security cert.

use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::substrate::dim;

pub const PROOF_SCHEMA: &str = "connector.proof_export.v1";

const PACKET_DNA_LOG: &str = "packet_dna_log";

fn recent_packet_dna(state: &PlatformState, agent_pid: &str, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(es) = state.engine_store.lock() else {
        return out;
    };
    let Ok(keys) = es.folder_keys(PACKET_DNA_LOG, None) else {
        return out;
    };
    for k in keys.into_iter().rev().take(limit * 4) {
        if let Ok(Some(v)) = es.folder_get(PACKET_DNA_LOG, &k) {
            if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                out.push(v);
                if out.len() >= limit {
                    break;
                }
            }
        }
    }
    out
}

fn progeny_for_proof(state: &PlatformState, agent_pid: &str) -> Value {
    let Ok(k) = state.kernel.lock() else {
        return json!({"ok": false, "error": "kernel_lock"});
    };
    let parent = k
        .get_agent(agent_pid)
        .and_then(|a| a.parent_pid.clone());
    let children: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, acb)| acb.parent_pid.as_deref() == Some(agent_pid))
        .map(|(pid, _)| pid.clone())
        .collect();
    json!({
        "ok": true,
        "agent_pid": agent_pid,
        "parent_pid": parent,
        "children": children,
        "honesty": "A26/S5: child links for worldline — grants still enforced at admit",
    })
}

/// Export proof bundle for engineer/operator reconstruction (Product Promise: proof).
pub fn export_for_agent(
    state: &PlatformState,
    agent_pid: &str,
    mission_id: Option<&str>,
    limit: usize,
) -> Value {
    let limit = limit.clamp(1, 200);
    let dim_state = dim::persist::load(state, agent_pid);
    let dim_journal = dim::persist::list_recent_journal(state, agent_pid, limit.min(32));

    let mut aapi_actions = Vec::new();
    if let Ok(aapi) = state.aapi.lock() {
        for a in aapi.list_actions(Some(agent_pid)).into_iter().take(limit) {
            aapi_actions.push(json!({
                "record_id": a.record_id,
                "intent": a.intent,
                "action": a.action,
                "target": a.target,
                "outcome": a.outcome,
                "evidence_cids": a.evidence_cids,
                "timestamp": a.timestamp,
            }));
        }
    }

    let mut conp_receipts = Vec::new();
    let mut mission_steps = Vec::new();
    let mut cls_hints = Vec::new();
    let mut hitl_entries = Vec::new();
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys("conp_command_receipts", None) {
            for k in keys.into_iter().rev().take(limit) {
                if let Ok(Some(v)) = es.folder_get("conp_command_receipts", &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                        conp_receipts.push(v);
                    }
                }
            }
        }
        if let Ok(keys) = es.folder_keys("aapi_cls_hints", None) {
            for k in keys.into_iter().rev().take(limit.min(20)) {
                if let Ok(Some(v)) = es.folder_get("aapi_cls_hints", &k) {
                    cls_hints.push(v);
                }
            }
        }
        if let Some(mid) = mission_id {
            let prefix = format!("{mid}:");
            if let Ok(keys) = es.folder_keys(crate::kernel::mission_journal::STEP_FOLDER, Some(&prefix))
            {
                for k in keys.into_iter().take(limit) {
                    if let Ok(Some(v)) = es.folder_get(crate::kernel::mission_journal::STEP_FOLDER, &k)
                    {
                        mission_steps.push(v);
                    }
                }
            }
        }
        if let Ok(keys) = es.folder_keys("iia_hitl_requests", None) {
            for k in keys.into_iter().rev().take(limit) {
                if let Ok(Some(v)) = es.folder_get("iia_hitl_requests", &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                        hitl_entries.push(v);
                    }
                }
            }
        }
    }

    let posture = product_posture_with_state(state);

    let mut bundle = json!({
        "schema": PROOF_SCHEMA,
        "agent_pid": agent_pid,
        "mission_id": mission_id,
        "exported_at_ms": chrono::Utc::now().timestamp_millis(),
        "product_promise": {
            "guarantees": "honesty + exclusivity_when_applied + reconstructible_worldline + no_self_authorization",
            "does_not_guarantee": "absolute_security",
            "doc": "platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md",
        },
        "posture": posture,
        "dim": dim_state.operator_view(),
        "dim_journal": dim_journal,
        "aapi_actions": aapi_actions,
        "aapi_durable_ledger": crate::substrate::aapi_effect_field::list_durable_actions(
            state, agent_pid, limit,
        ),
        "aapi_effect_field": crate::substrate::aapi_effect_field::posture_json(),
        "conp_receipts": conp_receipts,
        "mission_steps": mission_steps,
        "aapi_cls_hints": cls_hints,
        "knowledge_boundary": crate::substrate::knowledge_boundary::posture_json(state, agent_pid),
        "hitl": hitl_entries,
        "packet_dna": {
            "status": crate::substrate::packet_dna::status_json(),
            "recent": recent_packet_dna(state, agent_pid, limit.min(16)),
        },
        "progeny": progeny_for_proof(state, agent_pid),
        "arc_worldline": crate::substrate::arc::worldline::export_graph(agent_pid),
        "arc_copg_graph": crate::substrate::arc::copg::graph_export(agent_pid),
        "arc_copg_sql": crate::substrate::arc::copg::sql_select(
            crate::substrate::arc::copg::CopgTable::WorldlineCommits,
            Some(agent_pid),
            limit,
        ),
        "arc_agency": {
            "reconstruct": crate::substrate::arc::worldline::reconstruct_agency_state(agent_pid, None).to_json(),
            "open_transactions": crate::substrate::arc::runtime::transactions()
                .list_for_agent(agent_pid)
                .into_iter()
                .take(limit)
                .map(|t| t.to_json())
                .collect::<Vec<_>>(),
            "durable": crate::substrate::arc::durable::posture_json(),
        },
        "cvr": {
            "isolation": crate::substrate::cvr::posture_for_agent(state, agent_pid),
            "execution_body": crate::substrate::cvr::load_body(state, agent_pid)
                .map(|b| b.to_json()),
            "microcell": crate::substrate::cvr::micro_cell::load_for_agent(state, agent_pid)
                .map(|m| m.to_json()),
            "host_probe": crate::substrate::cvr::probe_host().to_json(),
            "runtime_bundle": crate::substrate::cvr::RuntimeBundlePosture::discover().to_json(),
        },
        "honesty": "Proof of what was recorded — not a claim that the agent is 100% secure",
    });
    // Integrity digest over canonical body (excludes the integrity field itself).
    let body_bytes = serde_json::to_vec(&bundle).unwrap_or_default();
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(&body_bytes));
    if let Some(obj) = bundle.as_object_mut() {
        obj.insert(
            "integrity".into(),
            json!({
                "alg": "sha256",
                "digest_hex": digest,
                "covers": "entire_export_except_this_integrity_object",
            }),
        );
    }
    bundle
}

/// LAB vs harden continuum for E1/E7 + production R/A/E triad.
pub fn product_posture_json() -> Value {
    // Prefer live triad when PlatformState is not in scope — coarse flags only.
    let playground = crate::services::playground::is_playground_mode();
    let harden = crate::kernel::agent_principal::intelligence_hardening_on();
    let tier = crate::substrate::rgo::autonomy_tier();
    let lab = playground || !harden;
    json!({
        "profile": if playground {
            "playground"
        } else if harden {
            "harden"
        } else {
            "pilot"
        },
        "lab_mode": lab,
        "playground": playground,
        "intelligence_hardening": harden,
        "autonomy_tier": tier,
        "applied_truth": {
            "hardening_on": harden,
            "playground_soft": playground,
            "note": "Intent vs applied — soft-fail is labeled LAB, not production membrane. See harden_posture triad for Requested/Applied/Effective.",
        },
        "promise": "tools_env_isolation_monitoring_proof",
        "augmented_env": crate::substrate::harden_posture::augmented_env_harden(),
        "harden_refuse_start": crate::substrate::harden_posture::harden_refuse_start_enabled(),
    })
}

/// Full triad when state is available (status / proof export).
pub fn product_posture_with_state(state: &PlatformState) -> Value {
    let mut base = product_posture_json();
    if let Some(obj) = base.as_object_mut() {
        obj.insert(
            "harden_triad".into(),
            crate::substrate::harden_posture::posture_triad(state),
        );
        obj.insert(
            "membrane_applied_truth".into(),
            crate::kernel::membrane_posture::applied_truth_snapshot(state),
        );
        obj.insert(
            "effect_exclusivity".into(),
            crate::substrate::effect_exclusivity::effect_exclusivity_status(state),
        );
    }
    base
}
