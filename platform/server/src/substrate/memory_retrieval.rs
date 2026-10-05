//! Composite memory retrieval — VAC vector + Knot RRF + ReadSet + DIM radius + interference.

use serde_json::{json, Value};
use vac_core::knot::{KnotQuery, RetrievalChannel};
use vac_core::vector::{CompositeDistance, IndexedDoc};

use crate::state::PlatformState;
use crate::substrate::knot_belief_field;
use crate::substrate::knowledge_boundary;

pub const RETRIEVAL_SCHEMA: &str = "connector.mem.retrieval.v1";

/// Trust-aware composite recall for an agent namespace.
pub fn retrieve(
    state: &PlatformState,
    agent_pid: &str,
    query: &str,
    top_k: usize,
) -> Value {
    if crate::services::playground::is_playground_mode()
        && !crate::services::gateway::playground_rag_enabled()
    {
        return json!({
            "ok": false,
            "skipped": "playground_rag_off",
            "agent_pid": agent_pid,
        });
    }
    let namespace = format!("m/{}", agent_pid.trim_start_matches("agent_"));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let broker_epoch = state.cells.get_or_create(agent_pid).current_epoch();

    let radius_m = knot_belief_field::recall_radius_multiplier(state, agent_pid);
    let effective_k = ((top_k as f32) * radius_m).round().max(1.0) as usize;
    let effective_k = effective_k.clamp(1, 64);

    let (docs, read_set, ts_trust): (Vec<IndexedDoc>, Vec<String>, Vec<(i64, f32)>) = {
        let kernel = match state.kernel.lock() {
            Ok(k) => k,
            Err(_) => {
                return json!({"ok": false, "error": "kernel_lock"});
            }
        };
        let candidates = kernel.vector_index.query_if_ready(
            query,
            &namespace,
            effective_k.saturating_mul(4).max(effective_k),
        );
        let weights = CompositeDistance::default();
        let mut rescored: Vec<(IndexedDoc, i64, f32)> = candidates
            .into_iter()
            .map(|doc| {
                let (ts, trust) = doc
                    .cid
                    .parse()
                    .ok()
                    .and_then(|c| kernel.get_packet(&c).map(|p| (p.index.ts, p.trust_score)))
                    .unwrap_or((0, 0.0));
                let mut d = doc;
                d.score = weights.score(d.score, ts, now_ms, 86_400_000, 0, 0, trust);
                (d, ts, trust)
            })
            .collect();
        rescored.sort_by(|a, b| {
            b.0.score
                .partial_cmp(&a.0.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        rescored.truncate(effective_k);
        let read_set: Vec<String> = rescored.iter().map(|(d, _, _)| d.cid.clone()).collect();
        let ts_trust: Vec<(i64, f32)> = rescored.iter().map(|(_, t, tr)| (*t, *tr)).collect();
        let docs: Vec<IndexedDoc> = rescored.into_iter().map(|(d, _, _)| d).collect();
        (docs, read_set, ts_trust)
    };
    let _ = ts_trust;

    // Knot RRF fusion (complement channels).
    let mut knot_hits = Vec::new();
    if let Ok(knot) = state.knot.lock() {
        let q = KnotQuery {
            entities: vec![],
            keywords: query
                .split_whitespace()
                .take(8)
                .map(|s| s.to_string())
                .collect(),
            time_range: None,
            semantic_query: Some(query.into()),
            limit: effective_k,
            token_budget: 4096,
            min_trust_tier: None,
            rrf_k: 60.0,
        };
        for hit in knot.query(&q) {
            knot_hits.push(json!({
                "id": hit.id,
                "rrf_score": hit.rrf_score,
                "channels": hit.channels.iter().map(|c| match c {
                    RetrievalChannel::Temporal => "temporal",
                    RetrievalChannel::Graph => "graph",
                    RetrievalChannel::Keyword => "keyword",
                    RetrievalChannel::Semantic => "semantic",
                }).collect::<Vec<_>>(),
                "packet_cids": hit.packet_cids.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            }));
        }
    }

    // Stamp ReadSet on the agent's I-Cell for L2 stale-gen.
    state
        .cells
        .get_or_create(agent_pid)
        .stamp_read_set(read_set.clone(), vec![namespace.clone()]);

    let interference = knot_belief_field::detect_and_persist_interference(state, agent_pid);
    let foresight = knot_belief_field::selective_foresight(state, agent_pid);

    // Knowledge boundary (§5): filter composite + knot hits by source labels.
    let boundary = knowledge_boundary::load(state, agent_pid);
    let mut source_ids: Vec<String> = read_set
        .iter()
        .map(|cid| format!("memory:{cid}"))
        .collect();
    for h in &knot_hits {
        if let Some(id) = h.get("id").and_then(|v| v.as_str()) {
            source_ids.push(format!("knot:{id}"));
        }
    }
    let kb_filter = knowledge_boundary::filter_sources(&boundary, &source_ids);
    let denied_set: std::collections::HashSet<String> = kb_filter
        .get("denied")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("source").and_then(|s| s.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let composite_filtered: Vec<Value> = docs
        .iter()
        .filter(|d| !denied_set.contains(&format!("memory:{}", d.cid)))
        .map(|d| {
            json!({
                "cid": d.cid,
                "score": d.score,
                "text_preview": d.text.chars().take(160).collect::<String>(),
            })
        })
        .collect();
    let knot_filtered: Vec<Value> = knot_hits
        .into_iter()
        .filter(|h| {
            h.get("id")
                .and_then(|v| v.as_str())
                .map(|id| !denied_set.contains(&format!("knot:{id}")))
                .unwrap_or(true)
        })
        .collect();

    json!({
        "ok": true,
        "schema": RETRIEVAL_SCHEMA,
        "namespace": namespace,
        "broker_epoch": broker_epoch,
        "recall_radius_multiplier": radius_m,
        "effective_top_k": effective_k,
        "read_set": read_set,
        "read_set_stamped_at_ms": now_ms,
        "composite": composite_filtered,
        "knot_rrf": knot_filtered,
        "knowledge_boundary": kb_filter,
        "interference": interference,
        "selective_foresight": foresight,
        "belief_field": knot_belief_field::posture_json(),
        "honesty": "ReadSet stamps candidates for L2 stale-gen; knowledge boundary filters recall; DIM modulates radius only; ActionBinding still gates writes",
    })
}
