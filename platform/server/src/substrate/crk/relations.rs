//! CRK MemoryRelation store — typed edges for DNA activation.

use connector_trust::{
    MemoryDnaType, MemoryRelation, MemoryRelationKind, MEMORY_RELATION_SCHEMA,
};

use crate::state::PlatformState;

use super::sequence_dna;
use super::trust_firewall;
use super::{digest_hex, now_ms};

pub const FOLDER_RELATIONS: &str = "crk_memory_relations";

fn rel_key(agent_pid: &str, relation_id: &str) -> String {
    format!("{agent_pid}:{relation_id}")
}

fn out_key(agent_pid: &str, from_cid: &str) -> String {
    format!("out:{agent_pid}:{from_cid}")
}

fn in_key(agent_pid: &str, to_cid: &str) -> String {
    format!("in:{agent_pid}:{to_cid}")
}

pub fn put_relation(
    state: &PlatformState,
    agent_pid: &str,
    from_cid: &str,
    to_cid: &str,
    kind: MemoryRelationKind,
    from_type: MemoryDnaType,
    to_type: MemoryDnaType,
    weight: f64,
    provenance: &str,
) -> Result<MemoryRelation, String> {
    if !sequence_dna::edge_types_ok(kind, from_type, to_type) {
        return Err(format!(
            "relation_type_pairing_forbidden: {:?} {:?}→{:?}",
            kind, from_type, to_type
        ));
    }
    let w = if weight <= 0.0 { 1.0 } else { weight };
    let relation_id = format!(
        "rel_{}",
        &digest_hex(
            format!(
                "{}|{}|{}|{}|{}",
                agent_pid,
                from_cid,
                to_cid,
                kind_str(kind),
                now_ms()
            )
            .as_bytes()
        )[..16]
    );
    let envelope = trust_firewall::bind_envelope(
        &relation_id,
        agent_pid,
        provenance,
        connector_trust::TrustTier::T2SourceBound,
        "relation",
        vec![from_cid.into(), to_cid.into()],
        None,
        None,
        Some(now_ms()),
        None,
    );
    let rel = MemoryRelation {
        schema: MEMORY_RELATION_SCHEMA.into(),
        relation_id: relation_id.clone(),
        agent_pid: agent_pid.into(),
        from_cid: from_cid.into(),
        to_cid: to_cid.into(),
        kind,
        weight: w,
        envelope,
        from_type: Some(from_type),
        to_type: Some(to_type),
    };
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(&rel).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_RELATIONS, &rel_key(agent_pid, &relation_id), &val)
        .map_err(|e| format!("put relation: {e}"))?;
    push_index(&mut **es, &out_key(agent_pid, from_cid), &relation_id)?;
    push_index(&mut **es, &in_key(agent_pid, to_cid), &relation_id)?;
    Ok(rel)
}

fn push_index(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    key: &str,
    relation_id: &str,
) -> Result<(), String> {
    let mut ids: Vec<String> = es
        .folder_get(FOLDER_RELATIONS, key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if !ids.contains(&relation_id.to_string()) {
        ids.push(relation_id.to_string());
    }
    es.folder_put(FOLDER_RELATIONS, key, &serde_json::json!(ids))
        .map_err(|e| format!("put index: {e}"))?;
    Ok(())
}

fn kind_str(k: MemoryRelationKind) -> &'static str {
    match k {
        MemoryRelationKind::Next => "next",
        MemoryRelationKind::Requires => "requires",
        MemoryRelationKind::Refines => "refines",
        MemoryRelationKind::Forbids => "forbids",
        MemoryRelationKind::Derives => "derives",
        MemoryRelationKind::Conflicts => "conflicts",
        MemoryRelationKind::Supersedes => "supersedes",
        MemoryRelationKind::Causal => "causal",
    }
}

pub fn load(state: &PlatformState, agent_pid: &str, relation_id: &str) -> Option<MemoryRelation> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER_RELATIONS, &rel_key(agent_pid, relation_id))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

pub fn list_out(state: &PlatformState, agent_pid: &str, from_cid: &str) -> Vec<MemoryRelation> {
    list_by_index(state, agent_pid, &out_key(agent_pid, from_cid))
}

pub fn list_in(state: &PlatformState, agent_pid: &str, to_cid: &str) -> Vec<MemoryRelation> {
    list_by_index(state, agent_pid, &in_key(agent_pid, to_cid))
}

fn list_by_index(state: &PlatformState, agent_pid: &str, key: &str) -> Vec<MemoryRelation> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let ids: Vec<String> = es
        .folder_get(FOLDER_RELATIONS, key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let mut out = Vec::new();
    for id in ids {
        if let Ok(Some(v)) = es.folder_get(FOLDER_RELATIONS, &rel_key(agent_pid, &id)) {
            if let Ok(r) = serde_json::from_value::<MemoryRelation>(v) {
                out.push(r);
            }
        }
    }
    out
}

pub fn parse_kind(s: &str) -> Option<MemoryRelationKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "next" => Some(MemoryRelationKind::Next),
        "requires" => Some(MemoryRelationKind::Requires),
        "refines" => Some(MemoryRelationKind::Refines),
        "forbids" => Some(MemoryRelationKind::Forbids),
        "derives" => Some(MemoryRelationKind::Derives),
        "conflicts" => Some(MemoryRelationKind::Conflicts),
        "supersedes" => Some(MemoryRelationKind::Supersedes),
        "causal" => Some(MemoryRelationKind::Causal),
        _ => None,
    }
}

pub fn parse_type(s: &str) -> Option<MemoryDnaType> {
    match s.trim().to_ascii_lowercase().as_str() {
        "state" => Some(MemoryDnaType::State),
        "procedure" => Some(MemoryDnaType::Procedure),
        "evidence" => Some(MemoryDnaType::Evidence),
        "relation" => Some(MemoryDnaType::Relation),
        "conflict" => Some(MemoryDnaType::Conflict),
        "open_work" | "openwork" => Some(MemoryDnaType::OpenWork),
        "index" => Some(MemoryDnaType::Index),
        _ => None,
    }
}
