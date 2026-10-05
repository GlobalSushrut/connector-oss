//! Object↔object relations — COPG primary; optional Knot informational mirror.

use serde_json::{json, Value};

use crate::state::SharedState;

use super::{store, svf_enabled};

/// Record a relation edge between AgenticObjects (informational — not a grant).
pub fn relate_objects(
    state: &SharedState,
    agent_vid: &str,
    from_object_id: &str,
    to_object_id: &str,
    relation: &str,
    mirror_to_knot: bool,
) -> Value {
    if !svf_enabled() {
        return json!({ "ok": false, "error": "svf_disabled" });
    }
    let rel = sanitize_rel(relation);
    let from = from_object_id.trim();
    let to = to_object_id.trim();
    if from.is_empty() || to.is_empty() {
        return json!({ "ok": false, "error": "missing_object_id" });
    }

    let body = json!({
        "from": from,
        "to": to,
        "relation": rel,
        "broker_epoch": super::broker_epoch(state, agent_vid),
        "honesty": "informational — AffordanceEnvelope / WorldGrant unchanged",
    });
    crate::substrate::arc::copg::record_svf_edge(
        agent_vid,
        from,
        to,
        &format!("svf_{rel}"),
        body.clone(),
    );

    let mut knot_mirrored = false;
    if mirror_to_knot {
        if let Ok(mut knot) = state.knot.lock() {
            let ts = chrono::Utc::now().timestamp_millis();
            knot.upsert_edge(from, to, &format!("svf_{rel}"), 1.0, ts, 0, None);
            knot_mirrored = true;
        }
    }

    // Belief-field neighborhood is interference/foresight only — surface as hint.
    let interference_n =
        crate::substrate::knot_belief_field::list_interference(state.as_ref(), agent_vid, 8).len();

    json!({
        "ok": true,
        "schema": "connector.svf.relation.v1",
        "agent_vid": agent_vid,
        "from": from,
        "to": to,
        "relation": rel,
        "copg_label": format!("svf_{rel}"),
        "knot_mirrored": knot_mirrored,
        "belief_field_interference_n": interference_n,
        "honesty": "COPG edge + optional Knot mirror; belief field remains cognitive-only",
    })
}

/// List COPG edges touching this object (+ optional store stubs).
pub fn list_related(state: &SharedState, agent_vid: &str, object_id: &str) -> Value {
    let export = crate::substrate::arc::copg::graph_export(agent_vid);
    let edges = export
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let oid = object_id.trim();
    let related: Vec<Value> = edges
        .into_iter()
        .filter(|e| {
            let from = e.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to = e.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let label = e.get("label").and_then(|v| v.as_str()).unwrap_or("");
            label.starts_with("svf_") && (from == oid || to == oid || from.contains(oid) || to.contains(oid))
        })
        .collect();

    let stubs: Vec<Value> = related
        .iter()
        .filter_map(|e| {
            let other = if e.get("from").and_then(|v| v.as_str()) == Some(oid) {
                e.get("to").and_then(|v| v.as_str())
            } else {
                e.get("from").and_then(|v| v.as_str())
            }?;
            store::get_object(state, agent_vid, other).map(|o| {
                json!({
                    "object_id": o.object_id,
                    "object_type": o.object_type,
                    "handle": o.handle.handle,
                    "fade": o.manifest.fragments.first().and_then(|f| f.fade_state.clone()),
                })
            })
        })
        .collect();

    json!({
        "schema": "connector.svf.relations.list.v1",
        "agent_vid": agent_vid,
        "object_id": oid,
        "edges": related,
        "objects": stubs,
        "count": related.len(),
    })
}

fn sanitize_rel(relation: &str) -> String {
    let s: String = relation
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if s.is_empty() {
        "relates".into()
    } else {
        s
    }
}
