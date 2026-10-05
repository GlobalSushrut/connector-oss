//! DerivedKnowledge → evidence + MomentProof + COPG lineage (informational).

use connector_trust::{
    DerivedKnowledge, DERIVED_KNOWLEDGE_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::SharedState;

use super::{fade_bind, graph, store, svf_enabled};

pub const DERIVED_FOLDER: &str = "svf_derived_knowledge";

/// Persist DerivedKnowledge, append evidence (E2), mint MomentProof, COPG edges.
pub fn record_derived(
    state: &SharedState,
    agent_vid: &str,
    source_object_ids: &[String],
    claim: &str,
) -> Result<Value, String> {
    if !svf_enabled() {
        return Err("svf_disabled".into());
    }
    if claim.trim().is_empty() {
        return Err("claim_required".into());
    }
    if !crate::substrate::agent_memory::enabled() {
        return Err("agent_memory_disabled — set CONNECTOR_AGENT_MEMORY=1".into());
    }

    for sid in source_object_ids {
        if store::get_object(state, agent_vid, sid).is_none() {
            let _ = super::semanticize::semanticize_agent(state, agent_vid);
            if store::get_object(state, agent_vid, sid).is_none() {
                return Err(format!("source_object_not_found:{sid}"));
            }
        }
    }

    let digest = format!("{:x}", Sha256::digest(claim.as_bytes()));
    let derived_id = format!("DK-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let dk = DerivedKnowledge {
        schema: DERIVED_KNOWLEDGE_SCHEMA.to_string(),
        derived_id: derived_id.clone(),
        agent_vid: agent_vid.to_string(),
        source_object_ids: source_object_ids.to_vec(),
        claim: claim.to_string(),
        epistemic_class: "E2_derived".into(),
        content_digest: digest.clone(),
    };

    store::put_json(
        state,
        DERIVED_FOLDER,
        &format!("{agent_vid}:{derived_id}"),
        &serde_json::to_value(&dk).map_err(|e| e.to_string())?,
    );

    let content = serde_json::to_string(&dk).unwrap_or_else(|_| claim.to_string());
    let evidence = crate::substrate::agent_memory::evidence::append_on_write(
        state.as_ref(),
        agent_vid,
        &derived_id,
        &content,
        &format!("svf:derived:{derived_id}"),
        "svf_derived",
    )
    .ok_or_else(|| "evidence_append_failed".to_string())?;

    fade_bind::bind_object_evidence(state, agent_vid, &derived_id, &evidence.evidence_id);
    for sid in source_object_ids {
        fade_bind::bind_object_evidence(state, agent_vid, sid, &evidence.evidence_id);
    }

    let moment = crate::substrate::agent_memory::moment::assemble(
        state.as_ref(),
        agent_vid,
        &derived_id,
        "derived_knowledge",
        claim,
        "recorded",
        &format!("evidence:{}", evidence.evidence_id),
        None,
        None,
    );

    for sid in source_object_ids {
        let _ = graph::relate_objects(
            state,
            agent_vid,
            &derived_id,
            sid,
            "derived_from",
            true,
        );
    }

    crate::substrate::arc::copg::record_svf_edge(
        agent_vid,
        &derived_id,
        &evidence.evidence_id,
        "svf_derived_evidence",
        json!({
            "moment_id": moment.moment_id,
            "content_digest": digest,
        }),
    );

    Ok(json!({
        "ok": true,
        "schema": "connector.svf.derived_result.v1",
        "derived": dk,
        "evidence_id": evidence.evidence_id,
        "moment_id": moment.moment_id,
        "proof_level": moment.current_proof_level,
        "honesty": "DerivedKnowledge is informational — does not mint Allow / WorldGrant",
    }))
}

pub fn list_derived(state: &SharedState, agent_vid: &str) -> Value {
    let Ok(es) = state.engine_store.lock() else {
        return json!({ "ok": false, "error": "engine_store", "items": [] });
    };
    let Ok(keys) = es.folder_keys(DERIVED_FOLDER, Some(agent_vid)) else {
        return json!({ "items": [], "count": 0 });
    };
    let items: Vec<Value> = keys
        .into_iter()
        .filter_map(|k| es.folder_get(DERIVED_FOLDER, &k).ok().flatten())
        .collect();
    json!({
        "schema": "connector.svf.derived.list.v1",
        "agent_vid": agent_vid,
        "count": items.len(),
        "items": items,
    })
}
