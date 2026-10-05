//! SEMANTICIZE — MemPacket entities + Knot nodes → AgenticObject store.

use connector_trust::{
    AgenticObject, ContextFragment, ContextManifest, DisclosureLevel, SemanticHandle,
    AGENTIC_OBJECT_SCHEMA, CONTEXT_MANIFEST_SCHEMA, SEMANTIC_HANDLE_SCHEMA,
};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

use super::{broker_epoch, store, svf_enabled};

const MAX_OBJECTS: usize = 48;
const MAX_PACKETS_SCAN: usize = 80;

/// Scan agent VAC + Knot and upsert AgenticObjects. Returns count upserted.
pub fn semanticize_agent(state: &SharedState, agent_pid: &str) -> usize {
    if !svf_enabled() {
        return 0;
    }
    let epoch = broker_epoch(state, agent_pid);
    let mut upserted = 0usize;

    let ns = crate::services::agents::canonical_agent_memory_namespace(agent_pid);
    let packets: Vec<(String, Vec<String>, String)> = {
        let Ok(kernel) = state.kernel.lock() else {
            return 0;
        };
        kernel
            .packets_in_namespace(&ns)
            .into_iter()
            .take(MAX_PACKETS_SCAN)
            .map(|p| {
                let cid = p.index.packet_cid.to_string();
                let entities = p.content.entities.clone();
                let summary = payload_summary(&p.content.payload);
                (cid, entities, summary)
            })
            .collect()
    };

    for (cid, entities, summary) in packets {
        if entities.is_empty() {
            let object_id = format!("mem.{}", short_id(&cid));
            if upsert_object(
                state,
                agent_pid,
                "mem_packet",
                &object_id,
                epoch,
                Some(cid.clone()),
                None,
                &summary,
            ) {
                upserted += 1;
            }
            if upserted >= MAX_OBJECTS {
                return upserted;
            }
            continue;
        }
        for ent in entities.iter().take(8) {
            let (ty, id) = split_entity(ent);
            let object_id = format!("{ty}.{id}");
            if upsert_object(
                state,
                agent_pid,
                &ty,
                &object_id,
                epoch,
                Some(cid.clone()),
                None,
                &format!("{ent} · {summary}"),
            ) {
                upserted += 1;
            }
            if upserted >= MAX_OBJECTS {
                return upserted;
            }
        }
    }

    if let Ok(knot) = state.knot.lock() {
        for (key, node) in knot.nodes().iter().take(200) {
            if !node_belongs_to_agent(key, &node.entity_id, agent_pid) {
                continue;
            }
            let ty = node
                .entity_type
                .clone()
                .unwrap_or_else(|| split_entity(&node.entity_id).0);
            let object_id = sanitize_id(&node.entity_id);
            let summary = format!(
                "knot:{} mentions={} tags={}",
                node.entity_id,
                node.mention_count,
                node.tags
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let mem_cid = node.source_cids.first().map(|c| c.to_string());
            if upsert_object(
                state,
                agent_pid,
                &ty,
                &object_id,
                epoch,
                mem_cid,
                Some(node.entity_id.clone()),
                &summary,
            ) {
                upserted += 1;
            }
            if upserted >= MAX_OBJECTS {
                break;
            }
        }
    }

    upserted
}

fn upsert_object(
    state: &SharedState,
    agent_pid: &str,
    object_type: &str,
    object_id: &str,
    epoch: u64,
    mem_packet_cid: Option<String>,
    knot_node_id: Option<String>,
    summary: &str,
) -> bool {
    let handle_str = SemanticHandle::format_obj(object_type, object_id);
    let conn = format!(
        "⟦conn:obj:{}⟧",
        &format!(
            "{:x}",
            Sha256::digest(format!("{agent_pid}:{object_id}").as_bytes())
        )[..12]
    );
    let handle = SemanticHandle {
        schema: SEMANTIC_HANDLE_SCHEMA.to_string(),
        handle: format!("{handle_str} {conn}"),
        object_type: object_type.to_string(),
        object_id: object_id.to_string(),
        agent_vid: agent_pid.to_string(),
        disclosure_ceiling: DisclosureLevel::S1Labels,
        broker_epoch: epoch,
    };
    let frag = ContextFragment {
        fragment_id: format!("f0-{}", short_id(object_id)),
        class: "label".into(),
        disclosure_level: DisclosureLevel::S1Labels,
        content_digest: format!("{:x}", Sha256::digest(summary.as_bytes())),
        fade_state: Some("F0_full".into()),
    };
    let obj = AgenticObject {
        schema: AGENTIC_OBJECT_SCHEMA.to_string(),
        object_id: object_id.to_string(),
        object_type: object_type.to_string(),
        agent_vid: agent_pid.to_string(),
        handle,
        manifest: ContextManifest {
            schema: CONTEXT_MANIFEST_SCHEMA.to_string(),
            object_id: object_id.to_string(),
            fragments: vec![frag],
        },
        knot_node_id,
        mem_packet_cid,
    };
    store::put_object(state, &obj).is_ok()
}

fn split_entity(ent: &str) -> (String, String) {
    if let Some((ty, id)) = ent.split_once(':') {
        (sanitize_id(ty), sanitize_id(id))
    } else {
        ("entity".into(), sanitize_id(ent))
    }
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .chars()
        .take(64)
        .collect()
}

fn short_id(s: &str) -> String {
    let h = format!("{:x}", Sha256::digest(s.as_bytes()));
    h[..12.min(h.len())].to_string()
}

fn payload_summary(payload: &serde_json::Value) -> String {
    let s = match payload {
        serde_json::Value::String(t) => t.clone(),
        other => other.to_string(),
    };
    s.chars().take(120).collect()
}

fn node_belongs_to_agent(key: &str, entity_id: &str, agent_pid: &str) -> bool {
    let pid = agent_pid.trim();
    let short = pid.trim_start_matches("agent_");
    key.contains(pid)
        || key.contains(short)
        || entity_id.contains(pid)
        || entity_id.contains(short)
        || key.contains(&format!("m/{short}"))
        || key.contains(&format!("m/{pid}"))
}
