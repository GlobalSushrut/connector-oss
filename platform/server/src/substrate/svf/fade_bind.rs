//! Bind Context Rollup fade (F0–F3) / proof (P0–P3) onto AgenticObject fragments.

use connector_trust::{FadeState, ProofLevel};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

use super::{store, svf_enabled};

pub const OBJECT_EVIDENCE_FOLDER: &str = "svf_object_evidence";

/// Map object_id → evidence_id for fade sync.
pub fn bind_object_evidence(
    state: &SharedState,
    agent_vid: &str,
    object_id: &str,
    evidence_id: &str,
) {
    store::put_json(
        state,
        OBJECT_EVIDENCE_FOLDER,
        &format!("{agent_vid}:{object_id}"),
        &json!({ "evidence_id": evidence_id, "object_id": object_id }),
    );
}

fn evidence_for_object(state: &SharedState, agent_vid: &str, object_id: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(OBJECT_EVIDENCE_FOLDER, &format!("{agent_vid}:{object_id}"))
        .ok()
        .flatten()?;
    v.get("evidence_id")
        .and_then(|x| x.as_str())
        .map(str::to_string)
}

fn encode_fade_proof(fade: FadeState, proof: ProofLevel) -> String {
    format!("{}/{}", fade.as_str(), proof.as_str())
}

/// Sync one object's fragment fade from EvidenceMeta (rollup live state).
pub fn sync_object_fade(state: &SharedState, agent_vid: &str, object_id: &str) -> Option<Value> {
    if !svf_enabled() {
        return None;
    }
    let mut obj = store::get_object(state, agent_vid, object_id)?;
    let evidence_id = evidence_for_object(state, agent_vid, object_id)?;
    let meta = crate::substrate::agent_memory::rollup::eligibility::load_meta(
        state.as_ref(),
        agent_vid,
        &evidence_id,
    );
    let proof = ProofLevel::for_fade_state(meta.fade_state);
    let encoded = encode_fade_proof(meta.fade_state, proof);
    for frag in &mut obj.manifest.fragments {
        frag.fade_state = Some(encoded.clone());
    }
    if obj.manifest.fragments.is_empty() {
        obj.manifest.fragments.push(connector_trust::ContextFragment {
            fragment_id: format!("fade-{object_id}"),
            class: "fade_bind".into(),
            disclosure_level: connector_trust::DisclosureLevel::S1Labels,
            content_digest: evidence_id.clone(),
            fade_state: Some(encoded.clone()),
        });
    }
    store::put_object(state, &obj).ok()?;
    Some(json!({
        "object_id": object_id,
        "evidence_id": evidence_id,
        "fade_state": meta.fade_state.as_str(),
        "proof_level": proof.as_str(),
        "bound": encoded,
    }))
}

/// Sync all bound objects for an agent. Returns count updated.
pub fn sync_agent_fade(state: &SharedState, agent_vid: &str) -> Value {
    if !svf_enabled() {
        return json!({ "ok": false, "error": "svf_disabled", "updated": 0 });
    }
    let keys = {
        let Ok(es) = state.engine_store.lock() else {
            return json!({ "ok": false, "error": "engine_store", "updated": 0 });
        };
        es.folder_keys(OBJECT_EVIDENCE_FOLDER, Some(agent_vid))
            .unwrap_or_default()
    };
    let mut updated = Vec::new();
    for key in keys {
        let object_id = key
            .strip_prefix(&format!("{agent_vid}:"))
            .unwrap_or(&key)
            .to_string();
        if let Some(v) = sync_object_fade(state, agent_vid, &object_id) {
            updated.push(v);
        }
    }
    json!({
        "ok": true,
        "schema": "connector.svf.fade_sync.v1",
        "agent_vid": agent_vid,
        "updated": updated.len(),
        "objects": updated,
        "honesty": "Fragment fade mirrors EvidenceMeta — rollup owns authoritative fade",
    })
}

/// Called after rollup execute_fade — best-effort sync for linked objects.
pub fn after_evidence_fade(state: &PlatformState, agent_vid: &str, evidence_id: &str) {
    if !svf_enabled() {
        return;
    }
    let Ok(es) = state.engine_store.lock() else {
        return;
    };
    let Ok(keys) = es.folder_keys(OBJECT_EVIDENCE_FOLDER, Some(agent_vid)) else {
        return;
    };
    let mut object_ids = Vec::new();
    for key in keys {
        if let Ok(Some(v)) = es.folder_get(OBJECT_EVIDENCE_FOLDER, &key) {
            if v.get("evidence_id").and_then(|x| x.as_str()) == Some(evidence_id) {
                if let Some(oid) = v.get("object_id").and_then(|x| x.as_str()) {
                    object_ids.push(oid.to_string());
                }
            }
        }
    }
    drop(es);
    // Sync without SharedState: update fragments via engine_store directly.
    for oid in object_ids {
        sync_object_fade_platform(state, agent_vid, &oid);
    }
}

fn sync_object_fade_platform(state: &PlatformState, agent_vid: &str, object_id: &str) {
    let evidence_id = {
        let Ok(es) = state.engine_store.lock() else {
            return;
        };
        let Some(v) = es
            .folder_get(OBJECT_EVIDENCE_FOLDER, &format!("{agent_vid}:{object_id}"))
            .ok()
            .flatten()
        else {
            return;
        };
        match v.get("evidence_id").and_then(|x| x.as_str()) {
            Some(e) => e.to_string(),
            None => return,
        }
    };
    let meta = crate::substrate::agent_memory::rollup::eligibility::load_meta(
        state,
        agent_vid,
        &evidence_id,
    );
    let proof = ProofLevel::for_fade_state(meta.fade_state);
    let encoded = encode_fade_proof(meta.fade_state, proof);
    let key = format!("{agent_vid}:{object_id}");
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let Ok(Some(mut v)) = es.folder_get(store::OBJECT_FOLDER, &key) else {
        return;
    };
    if let Some(frags) = v
        .pointer_mut("/manifest/fragments")
        .and_then(|f| f.as_array_mut())
    {
        for frag in frags.iter_mut() {
            if let Some(obj) = frag.as_object_mut() {
                obj.insert("fade_state".into(), json!(encoded));
            }
        }
    }
    let _ = es.folder_put(store::OBJECT_FOLDER, &key, &v);
}
