//! Interference Engine — StateVector extraction, InterferenceEdge computation, and compaction.
//!
//! Extracts meaning from raw MemPackets into structured StateVectors.
//! Computes deltas (InterferenceEdges) between consecutive windows.
//! Enables infinite memory through compaction: raw packets → SV + IE chains.
//!
//! Design sources: CRDT delta state vectors, Hindsight CARA reflect,
//! EverMemOS engram lifecycle, Event Sourcing snapshots.

use std::collections::{BTreeMap, HashSet};

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::cid::compute_cid;
use crate::types::*;

// =============================================================================
// StateVector — what the agent knows at a point in time
// =============================================================================

/// An entity's known state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityState {
    /// Entity identifier (e.g., "patient:P-001", "user:alice")
    pub entity_id: String,
    /// Key-value attributes known about this entity
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Last updated timestamp
    pub last_seen: i64,
    /// Number of times this entity was mentioned
    pub mention_count: u64,
    /// Source packet CIDs that contributed to this state
    pub source_cids: Vec<Cid>,
}

/// An active intent or goal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Intent {
    /// Intent identifier
    pub intent_id: String,
    /// Description of the goal
    pub description: String,
    /// Whether this intent is still open
    pub open: bool,
    /// When this intent was created
    pub created_at: i64,
    /// When this intent was resolved (if closed)
    pub resolved_at: Option<i64>,
    /// Evidence CIDs
    pub evidence_cids: Vec<Cid>,
}

/// A decision made by the agent
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionRecord {
    /// What was decided
    pub description: String,
    /// Reasoning behind the decision
    pub reasoning: Option<String>,
    /// Confidence (0.0 - 1.0)
    pub confidence: Option<f32>,
    /// When the decision was made
    pub decided_at: i64,
    /// Source packet CID
    pub source_cid: Option<Cid>,
}

/// A detected contradiction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContradictionRecord {
    /// Entity involved
    pub entity_id: String,
    /// The old claim
    pub old_claim: String,
    /// The new claim
    pub new_claim: String,
    /// Resolution (if any)
    pub resolution: Option<String>,
    /// When detected
    pub detected_at: i64,
    /// Source CIDs
    pub old_cid: Option<Cid>,
    pub new_cid: Option<Cid>,
}

/// An objective observation about an entity (from Hindsight pattern)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    /// Entity this observation is about
    pub entity_id: String,
    /// Objective summary text
    pub summary: String,
    /// When this observation was generated/updated
    pub updated_at: i64,
    /// Source fact CIDs
    pub source_cids: Vec<Cid>,
}

/// StateVector — a snapshot of everything the agent knows at a given RangeWindow.
///
/// This is the "meaning" layer: raw packets are compressed into structured knowledge.
/// The SV is the agent's "understanding" at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVector {
    /// Which RangeWindow this summarizes
    pub sn: u64,
    /// Agent PID
    pub agent_pid: String,
    /// Namespace
    pub namespace: String,

    /// Known entities and their current state
    pub entities: BTreeMap<String, EntityState>,
    /// Active intents/goals
    pub intents: Vec<Intent>,
    /// Decisions made
    pub decisions: Vec<DecisionRecord>,
    /// Detected contradictions
    pub contradictions: Vec<ContradictionRecord>,
    /// Objective entity observations (Hindsight pattern)
    pub observations: Vec<Observation>,

    /// Summary text (human-readable)
    pub summary: Option<String>,
    /// Total packets that contributed to this SV
    pub source_packet_count: u64,
    /// Total tokens across source packets
    pub source_token_count: u64,

    /// CID of the RangeWindow this was derived from
    pub source_rw_root: [u8; 32],
    /// CID of this StateVector itself (set after computation)
    pub sv_cid: Option<Cid>,
    /// Timestamp
    pub created_at: i64,
}

// =============================================================================
// InterferenceEdge — what changed between two consecutive StateVectors
// =============================================================================

/// The delta between two consecutive StateVectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    /// Entities that appeared for the first time
    pub entities_added: Vec<EntityState>,
    /// Entities whose attributes changed: (entity_id, changed_keys)
    pub entities_changed: Vec<EntityChange>,
    /// Entities that were removed/forgotten
    pub entities_removed: Vec<String>,
    /// New intents opened
    pub intents_opened: Vec<Intent>,
    /// Intents that were resolved/closed
    pub intents_closed: Vec<String>,
    /// Decisions made in this window
    pub decisions_made: Vec<DecisionRecord>,
    /// Contradictions detected in this window
    pub contradictions_detected: Vec<ContradictionRecord>,
    /// Observations updated
    pub observations_updated: Vec<Observation>,
}

/// A change to an entity's attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityChange {
    pub entity_id: String,
    /// Keys that were added or modified
    pub changed_keys: Vec<String>,
    /// Keys that were removed
    pub removed_keys: Vec<String>,
}

/// InterferenceEdge — the delta between two consecutive StateVectors.
///
/// This is the "evolution" layer: how the agent's understanding changed.
/// IE edges form a chain: SV₀ → IE₀₁ → SV₁ → IE₁₂ → SV₂ → ...
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterferenceEdge {
    /// Agent PID this edge belongs to (D2 FIX: needed for store key consistency)
    pub agent_pid: String,
    /// Source window serial number
    pub from_sn: u64,
    /// Target window serial number
    pub to_sn: u64,
    /// The actual delta
    pub delta: StateDelta,
    /// CIDs of packets that caused this change
    pub cause_evidence_cids: Vec<Cid>,
    /// Confidence in this delta (0.0 - 1.0)
    pub confidence: f64,
    /// CID of this InterferenceEdge itself
    pub ie_cid: Option<Cid>,
    /// Timestamp
    pub created_at: i64,
}

// =============================================================================
// Extraction — build StateVector from MemPackets
// =============================================================================

/// Extract a StateVector from a set of MemPackets (typically one RangeWindow's worth).
///
/// This is a deterministic, non-LLM extraction that builds structured state
/// from the packet metadata (entities, types, payloads).
pub fn extract_state_vector(
    sn: u64,
    agent_pid: &str,
    namespace: &str,
    packets: &[MemPacket],
    rw_root: [u8; 32],
) -> StateVector {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let mut entities: BTreeMap<String, EntityState> = BTreeMap::new();
    let mut intents: Vec<Intent> = Vec::new();
    let mut decisions: Vec<DecisionRecord> = Vec::new();
    let mut contradictions: Vec<ContradictionRecord> = Vec::new();
    let mut observations: Vec<Observation> = Vec::new();
    let mut total_tokens: u64 = 0;

    for packet in packets {
        let ts = packet.index.ts;
        let cid = packet.index.packet_cid.clone();

        // Count tokens from tool interactions
        if let Some(ref ti) = packet.tool_interaction {
            if let Some(ref tu) = ti.token_usage {
                total_tokens += tu.total_tokens;
            }
        }

        // Extract entities
        for entity_id in &packet.content.entities {
            let entry = entities.entry(entity_id.clone()).or_insert_with(|| EntityState {
                entity_id: entity_id.clone(),
                attributes: BTreeMap::new(),
                last_seen: ts,
                mention_count: 0,
                source_cids: Vec::new(),
            });
            entry.mention_count += 1;
            entry.last_seen = entry.last_seen.max(ts);
            entry.source_cids.push(cid.clone());
        }

        // Extract by packet type
        match packet.content.packet_type {
            PacketType::Extraction => {
                // Extractions contribute attributes to entities
                if let Some(obj) = packet.content.payload.as_object() {
                    for entity_id in &packet.content.entities {
                        if let Some(entry) = entities.get_mut(entity_id) {
                            for (k, v) in obj {
                                entry.attributes.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }

                // D13 FIX: Build observation for ALL entities, not just the first.
                // Previously only entities[0] got an observation, silently dropping the rest.
                let summary = if let Some(obj) = packet.content.payload.as_object() {
                    obj.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    packet.content.payload.to_string()
                };
                for entity_id in &packet.content.entities {
                    observations.push(Observation {
                        entity_id: entity_id.clone(),
                        summary: summary.clone(),
                        updated_at: ts,
                        source_cids: vec![cid.clone()],
                    });
                }
            }
            PacketType::Decision => {
                let desc = packet.content.payload.get("action")
                    .or_else(|| packet.content.payload.get("decision"))
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .unwrap_or_else(|| packet.content.payload.to_string());

                decisions.push(DecisionRecord {
                    description: desc,
                    reasoning: packet.provenance.reasoning.clone(),
                    confidence: packet.provenance.confidence,
                    decided_at: ts,
                    source_cid: Some(cid.clone()),
                });
            }
            PacketType::Contradiction => {
                let entity_id = packet.content.entities.first()
                    .cloned()
                    .unwrap_or_default();
                let old_claim = packet.content.payload.get("old")
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let new_claim = packet.content.payload.get("new")
                    .map(|v| v.to_string())
                    .unwrap_or_default();

                contradictions.push(ContradictionRecord {
                    entity_id,
                    old_claim,
                    new_claim,
                    resolution: packet.content.payload.get("resolution")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    detected_at: ts,
                    old_cid: packet.provenance.supersedes.clone(),
                    new_cid: Some(cid.clone()),
                });
            }
            PacketType::Input => {
                // Inputs may represent user intents
                if let Some(text) = packet.content.payload.as_str() {
                    if text.contains('?') || text.to_lowercase().contains("please") || text.to_lowercase().contains("need") {
                        intents.push(Intent {
                            intent_id: format!("intent:{}", cid),
                            description: text.to_string(),
                            open: true,
                            created_at: ts,
                            resolved_at: None,
                            evidence_cids: vec![cid.clone()],
                        });
                    }
                }
            }
            PacketType::Action | PacketType::ToolResult => {
                // Actions/results may close intents
                // (Simple heuristic: mark oldest open intent as closed)
                if let Some(intent) = intents.iter_mut().find(|i| i.open) {
                    intent.open = false;
                    intent.resolved_at = Some(ts);
                    intent.evidence_cids.push(cid.clone());
                }
            }
            _ => {}
        }
    }

    let mut sv = StateVector {
        sn,
        agent_pid: agent_pid.to_string(),
        namespace: namespace.to_string(),
        entities,
        intents,
        decisions,
        contradictions,
        observations,
        summary: None,
        source_packet_count: packets.len() as u64,
        source_token_count: total_tokens,
        source_rw_root: rw_root,
        sv_cid: None,
        created_at: now,
    };

    // Compute CID for the StateVector
    if let Ok(cid) = compute_cid(&sv) {
        sv.sv_cid = Some(cid);
    }

    sv
}

// =============================================================================
// Delta computation — InterferenceEdge between two StateVectors
// =============================================================================

/// Compute the InterferenceEdge (delta) between two consecutive StateVectors.
pub fn compute_interference(sv_prev: &StateVector, sv_curr: &StateVector) -> InterferenceEdge {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let mut entities_added = Vec::new();
    let mut entities_changed = Vec::new();
    let mut entities_removed = Vec::new();

    // Find added and changed entities
    for (id, curr_state) in &sv_curr.entities {
        match sv_prev.entities.get(id) {
            None => {
                entities_added.push(curr_state.clone());
            }
            Some(prev_state) => {
                let mut changed_keys = Vec::new();
                let mut removed_keys = Vec::new();

                // Check for changed/added attributes
                for (k, v) in &curr_state.attributes {
                    match prev_state.attributes.get(k) {
                        None => changed_keys.push(k.clone()),
                        Some(prev_v) if prev_v != v => changed_keys.push(k.clone()),
                        _ => {}
                    }
                }

                // Check for removed attributes
                for k in prev_state.attributes.keys() {
                    if !curr_state.attributes.contains_key(k) {
                        removed_keys.push(k.clone());
                    }
                }

                if !changed_keys.is_empty() || !removed_keys.is_empty() {
                    entities_changed.push(EntityChange {
                        entity_id: id.clone(),
                        changed_keys,
                        removed_keys,
                    });
                }
            }
        }
    }

    // Find removed entities
    for id in sv_prev.entities.keys() {
        if !sv_curr.entities.contains_key(id) {
            entities_removed.push(id.clone());
        }
    }

    // Intents opened/closed
    let prev_intent_ids: HashSet<&str> = sv_prev.intents.iter().map(|i| i.intent_id.as_str()).collect();
    let _curr_intent_ids: HashSet<&str> = sv_curr.intents.iter().map(|i| i.intent_id.as_str()).collect();

    let intents_opened: Vec<Intent> = sv_curr.intents.iter()
        .filter(|i| !prev_intent_ids.contains(i.intent_id.as_str()))
        .cloned()
        .collect();

    let intents_closed: Vec<String> = sv_prev.intents.iter()
        .filter(|i| i.open)
        .filter(|i| {
            sv_curr.intents.iter()
                .find(|ci| ci.intent_id == i.intent_id)
                .map(|ci| !ci.open)
                .unwrap_or(false)
        })
        .map(|i| i.intent_id.clone())
        .collect();

    // New decisions (in curr but not in prev)
    let prev_decision_count = sv_prev.decisions.len();
    let decisions_made: Vec<DecisionRecord> = if sv_curr.decisions.len() > prev_decision_count {
        sv_curr.decisions[prev_decision_count..].to_vec()
    } else {
        Vec::new()
    };

    // New contradictions
    let prev_contradiction_count = sv_prev.contradictions.len();
    let contradictions_detected: Vec<ContradictionRecord> = if sv_curr.contradictions.len() > prev_contradiction_count {
        sv_curr.contradictions[prev_contradiction_count..].to_vec()
    } else {
        Vec::new()
    };

    // Updated observations
    let prev_obs_entities: HashSet<&str> = sv_prev.observations.iter().map(|o| o.entity_id.as_str()).collect();
    let observations_updated: Vec<Observation> = sv_curr.observations.iter()
        .filter(|o| !prev_obs_entities.contains(o.entity_id.as_str()))
        .cloned()
        .collect();

    // Collect cause evidence CIDs from all new entities and changes
    let mut cause_cids: Vec<Cid> = Vec::new();
    for e in &entities_added {
        cause_cids.extend(e.source_cids.iter().cloned());
    }
    for d in &decisions_made {
        if let Some(ref cid) = d.source_cid {
            cause_cids.push(cid.clone());
        }
    }

    let delta = StateDelta {
        entities_added,
        entities_changed,
        entities_removed,
        intents_opened,
        intents_closed,
        decisions_made,
        contradictions_detected,
        observations_updated,
    };

    // Compute confidence based on how much changed
    let total_changes = delta.entities_added.len()
        + delta.entities_changed.len()
        + delta.entities_removed.len()
        + delta.intents_opened.len()
        + delta.intents_closed.len()
        + delta.decisions_made.len()
        + delta.contradictions_detected.len();

    let confidence = if total_changes == 0 { 1.0 } else { 0.9 };

    let mut ie = InterferenceEdge {
        agent_pid: sv_curr.agent_pid.clone(),
        from_sn: sv_prev.sn,
        to_sn: sv_curr.sn,
        delta,
        cause_evidence_cids: cause_cids,
        confidence,
        ie_cid: None,
        created_at: now,
    };

    // Compute CID
    if let Ok(cid) = compute_cid(&ie) {
        ie.ie_cid = Some(cid);
    }

    ie
}

// =============================================================================
// Compaction — compress old windows into SV + IE chains
// =============================================================================

/// Result of compacting a RangeWindow
#[derive(Debug, Clone)]
pub struct CompactionResult {
    /// The StateVector extracted from the window
    pub state_vector: StateVector,
    /// The InterferenceEdge from previous SV (None for first window)
    pub interference_edge: Option<InterferenceEdge>,
    /// CIDs of raw packets that can now be archived/evicted
    pub archivable_cids: Vec<Cid>,
    /// Summary text
    pub summary: String,
}

/// Compact a window's packets into a StateVector, optionally computing an IE from the previous SV.
pub fn compact_window(
    sn: u64,
    agent_pid: &str,
    namespace: &str,
    packets: &[MemPacket],
    rw_root: [u8; 32],
    prev_sv: Option<&StateVector>,
) -> CompactionResult {
    // Extract StateVector
    let sv = extract_state_vector(sn, agent_pid, namespace, packets, rw_root);

    // Compute InterferenceEdge if we have a previous SV
    let ie = prev_sv.map(|prev| compute_interference(prev, &sv));

    // Build summary
    let summary = format!(
        "Window sn={}: {} entities, {} decisions, {} contradictions, {} packets",
        sn,
        sv.entities.len(),
        sv.decisions.len(),
        sv.contradictions.len(),
        sv.source_packet_count,
    );

    // All packet CIDs are now archivable (SV preserves the meaning)
    let archivable_cids: Vec<Cid> = packets.iter()
        .map(|p| p.index.packet_cid.clone())
        .collect();

    CompactionResult {
        state_vector: sv,
        interference_edge: ie,
        archivable_cids,
        summary,
    }
}

/// Walk the IE chain to answer "what changed between sn_from and sn_to?"
pub fn walk_interference_chain(
    edges: &[InterferenceEdge],
    from_sn: u64,
    to_sn: u64,
) -> Vec<&InterferenceEdge> {
    edges.iter()
        .filter(|ie| ie.from_sn >= from_sn && ie.to_sn <= to_sn)
        .collect()
}

/// Merge multiple StateDelta into one cumulative delta
pub fn merge_deltas(deltas: &[&StateDelta]) -> StateDelta {
    let mut merged = StateDelta {
        entities_added: Vec::new(),
        entities_changed: Vec::new(),
        entities_removed: Vec::new(),
        intents_opened: Vec::new(),
        intents_closed: Vec::new(),
        decisions_made: Vec::new(),
        contradictions_detected: Vec::new(),
        observations_updated: Vec::new(),
    };

    let mut seen_entities: HashSet<String> = HashSet::new();

    for delta in deltas {
        for e in &delta.entities_added {
            if seen_entities.insert(e.entity_id.clone()) {
                merged.entities_added.push(e.clone());
            }
        }
        merged.entities_changed.extend(delta.entities_changed.iter().cloned());
        merged.entities_removed.extend(delta.entities_removed.iter().cloned());
        merged.intents_opened.extend(delta.intents_opened.iter().cloned());
        merged.intents_closed.extend(delta.intents_closed.iter().cloned());
        merged.decisions_made.extend(delta.decisions_made.iter().cloned());
        merged.contradictions_detected.extend(delta.contradictions_detected.iter().cloned());
        merged.observations_updated.extend(delta.observations_updated.iter().cloned());
    }

    merged
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source() -> Source {
        Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkTest".to_string(),
        }
    }

    fn make_extraction(subject: &str, entities: &[&str], payload: serde_json::Value, ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Extraction,
            payload,
            Cid::default(),
            subject.to_string(),
            "pipeline:test".to_string(),
            make_source(),
            ts,
        )
        .with_entities(entities.iter().map(|s| s.to_string()).collect())
    }

    fn make_decision(desc: &str, ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Decision,
            serde_json::json!({"action": desc}),
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            ts,
        )
        .with_reasoning("test reasoning".to_string())
        .with_confidence(0.9)
    }

    fn make_contradiction(entity: &str, old: &str, new: &str, ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Contradiction,
            serde_json::json!({"old": old, "new": new}),
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            ts,
        )
        .with_entities(vec![entity.to_string()])
    }

    #[test]
    fn test_extract_state_vector_entities() {
        let packets = vec![
            make_extraction("p1", &["alice", "bob"], serde_json::json!({"role": "admin"}), 1000),
            make_extraction("p1", &["alice"], serde_json::json!({"email": "a@b.com"}), 2000),
            make_extraction("p1", &["charlie"], serde_json::json!({"role": "user"}), 3000),
        ];

        let sv = extract_state_vector(0, "pid:001", "ns:test", &packets, [0u8; 32]);

        assert_eq!(sv.sn, 0);
        assert_eq!(sv.entities.len(), 3); // alice, bob, charlie
        assert_eq!(sv.entities["alice"].mention_count, 2);
        assert_eq!(sv.entities["bob"].mention_count, 1);
        assert_eq!(sv.entities["charlie"].mention_count, 1);

        // Alice should have both attributes merged
        assert!(sv.entities["alice"].attributes.contains_key("role"));
        assert!(sv.entities["alice"].attributes.contains_key("email"));

        assert_eq!(sv.source_packet_count, 3);
        assert!(sv.sv_cid.is_some());
    }

    #[test]
    fn test_extract_state_vector_decisions() {
        let packets = vec![
            make_decision("update_allergy", 1000),
            make_decision("schedule_followup", 2000),
        ];

        let sv = extract_state_vector(0, "pid:001", "ns:test", &packets, [0u8; 32]);

        assert_eq!(sv.decisions.len(), 2);
        assert_eq!(sv.decisions[0].description, "update_allergy");
        assert_eq!(sv.decisions[1].description, "schedule_followup");
        assert_eq!(sv.decisions[0].confidence, Some(0.9));
    }

    #[test]
    fn test_extract_state_vector_contradictions() {
        let packets = vec![
            make_contradiction("patient:P-001", "no allergy", "penicillin allergy", 1000),
        ];

        let sv = extract_state_vector(0, "pid:001", "ns:test", &packets, [0u8; 32]);

        assert_eq!(sv.contradictions.len(), 1);
        assert_eq!(sv.contradictions[0].entity_id, "patient:P-001");
    }

    #[test]
    fn test_compute_interference_entities_added() {
        let sv_prev = StateVector {
            sn: 0,
            agent_pid: "pid:001".to_string(),
            namespace: "ns:test".to_string(),
            entities: BTreeMap::new(),
            intents: Vec::new(),
            decisions: Vec::new(),
            contradictions: Vec::new(),
            observations: Vec::new(),
            summary: None,
            source_packet_count: 0,
            source_token_count: 0,
            source_rw_root: [0u8; 32],
            sv_cid: None,
            created_at: 1000,
        };

        let mut entities = BTreeMap::new();
        entities.insert("alice".to_string(), EntityState {
            entity_id: "alice".to_string(),
            attributes: BTreeMap::from([("role".to_string(), serde_json::json!("admin"))]),
            last_seen: 2000,
            mention_count: 1,
            source_cids: vec![],
        });

        let sv_curr = StateVector {
            sn: 1,
            entities,
            ..sv_prev.clone()
        };

        let ie = compute_interference(&sv_prev, &sv_curr);

        assert_eq!(ie.from_sn, 0);
        assert_eq!(ie.to_sn, 1);
        assert_eq!(ie.delta.entities_added.len(), 1);
        assert_eq!(ie.delta.entities_added[0].entity_id, "alice");
        assert!(ie.delta.entities_changed.is_empty());
        assert!(ie.delta.entities_removed.is_empty());
        assert!(ie.ie_cid.is_some());
    }

    #[test]
    fn test_compute_interference_entities_changed() {
        let mut prev_entities = BTreeMap::new();
        prev_entities.insert("alice".to_string(), EntityState {
            entity_id: "alice".to_string(),
            attributes: BTreeMap::from([("role".to_string(), serde_json::json!("user"))]),
            last_seen: 1000,
            mention_count: 1,
            source_cids: vec![],
        });

        let mut curr_entities = BTreeMap::new();
        curr_entities.insert("alice".to_string(), EntityState {
            entity_id: "alice".to_string(),
            attributes: BTreeMap::from([
                ("role".to_string(), serde_json::json!("admin")),  // changed
                ("email".to_string(), serde_json::json!("a@b.com")), // added
            ]),
            last_seen: 2000,
            mention_count: 2,
            source_cids: vec![],
        });

        let sv_prev = StateVector {
            sn: 0, agent_pid: "p".into(), namespace: "n".into(),
            entities: prev_entities, intents: vec![], decisions: vec![],
            contradictions: vec![], observations: vec![], summary: None,
            source_packet_count: 0, source_token_count: 0,
            source_rw_root: [0u8; 32], sv_cid: None, created_at: 1000,
        };

        let sv_curr = StateVector {
            sn: 1, entities: curr_entities, created_at: 2000, ..sv_prev.clone()
        };

        let ie = compute_interference(&sv_prev, &sv_curr);

        assert_eq!(ie.delta.entities_changed.len(), 1);
        let change = &ie.delta.entities_changed[0];
        assert_eq!(change.entity_id, "alice");
        assert!(change.changed_keys.contains(&"role".to_string()));
        assert!(change.changed_keys.contains(&"email".to_string()));
    }

    #[test]
    fn test_compute_interference_entities_removed() {
        let mut prev_entities = BTreeMap::new();
        prev_entities.insert("alice".to_string(), EntityState {
            entity_id: "alice".to_string(),
            attributes: BTreeMap::new(),
            last_seen: 1000, mention_count: 1, source_cids: vec![],
        });
        prev_entities.insert("bob".to_string(), EntityState {
            entity_id: "bob".to_string(),
            attributes: BTreeMap::new(),
            last_seen: 1000, mention_count: 1, source_cids: vec![],
        });

        // Only alice remains
        let mut curr_entities = BTreeMap::new();
        curr_entities.insert("alice".to_string(), EntityState {
            entity_id: "alice".to_string(),
            attributes: BTreeMap::new(),
            last_seen: 2000, mention_count: 2, source_cids: vec![],
        });

        let sv_prev = StateVector {
            sn: 0, agent_pid: "p".into(), namespace: "n".into(),
            entities: prev_entities, intents: vec![], decisions: vec![],
            contradictions: vec![], observations: vec![], summary: None,
            source_packet_count: 0, source_token_count: 0,
            source_rw_root: [0u8; 32], sv_cid: None, created_at: 1000,
        };
        let sv_curr = StateVector {
            sn: 1, entities: curr_entities, created_at: 2000, ..sv_prev.clone()
        };

        let ie = compute_interference(&sv_prev, &sv_curr);
        assert_eq!(ie.delta.entities_removed, vec!["bob".to_string()]);
    }

    #[test]
    fn test_compact_window() {
        let packets = vec![
            make_extraction("p1", &["alice"], serde_json::json!({"role": "admin"}), 1000),
            make_decision("grant_access", 2000),
            make_contradiction("alice", "user", "admin", 3000),
        ];

        let result = compact_window(0, "pid:001", "ns:test", &packets, [0u8; 32], None);

        assert_eq!(result.state_vector.entities.len(), 1);
        assert_eq!(result.state_vector.decisions.len(), 1);
        assert_eq!(result.state_vector.contradictions.len(), 1);
        assert!(result.interference_edge.is_none()); // No previous SV
        assert_eq!(result.archivable_cids.len(), 3);
        assert!(result.summary.contains("sn=0"));
    }

    #[test]
    fn test_compact_window_with_previous_sv() {
        let packets_0 = vec![
            make_extraction("p1", &["alice"], serde_json::json!({"role": "user"}), 1000),
        ];
        let result_0 = compact_window(0, "pid:001", "ns:test", &packets_0, [0u8; 32], None);

        let packets_1 = vec![
            make_extraction("p1", &["alice", "bob"], serde_json::json!({"role": "admin"}), 2000),
            make_decision("promote_alice", 3000),
        ];
        let result_1 = compact_window(1, "pid:001", "ns:test", &packets_1, [1u8; 32], Some(&result_0.state_vector));

        assert!(result_1.interference_edge.is_some());
        let ie = result_1.interference_edge.unwrap();
        assert_eq!(ie.from_sn, 0);
        assert_eq!(ie.to_sn, 1);
        // bob was added
        assert!(ie.delta.entities_added.iter().any(|e| e.entity_id == "bob"));
        // alice's role changed from user to admin
        assert!(ie.delta.entities_changed.iter().any(|c| c.entity_id == "alice"));
    }

    #[test]
    fn test_merge_deltas() {
        let d1 = StateDelta {
            entities_added: vec![EntityState {
                entity_id: "alice".into(), attributes: BTreeMap::new(),
                last_seen: 1000, mention_count: 1, source_cids: vec![],
            }],
            entities_changed: vec![], entities_removed: vec![],
            intents_opened: vec![], intents_closed: vec![],
            decisions_made: vec![DecisionRecord {
                description: "d1".into(), reasoning: None, confidence: None,
                decided_at: 1000, source_cid: None,
            }],
            contradictions_detected: vec![], observations_updated: vec![],
        };

        let d2 = StateDelta {
            entities_added: vec![EntityState {
                entity_id: "bob".into(), attributes: BTreeMap::new(),
                last_seen: 2000, mention_count: 1, source_cids: vec![],
            }],
            entities_changed: vec![], entities_removed: vec![],
            intents_opened: vec![], intents_closed: vec![],
            decisions_made: vec![DecisionRecord {
                description: "d2".into(), reasoning: None, confidence: None,
                decided_at: 2000, source_cid: None,
            }],
            contradictions_detected: vec![], observations_updated: vec![],
        };

        let merged = merge_deltas(&[&d1, &d2]);
        assert_eq!(merged.entities_added.len(), 2);
        assert_eq!(merged.decisions_made.len(), 2);
    }

    #[test]
    fn test_walk_interference_chain() {
        let edges = vec![
            InterferenceEdge {
                agent_pid: "test-agent".to_string(),
                from_sn: 0, to_sn: 1,
                delta: StateDelta {
                    entities_added: vec![], entities_changed: vec![], entities_removed: vec![],
                    intents_opened: vec![], intents_closed: vec![],
                    decisions_made: vec![], contradictions_detected: vec![], observations_updated: vec![],
                },
                cause_evidence_cids: vec![], confidence: 1.0, ie_cid: None, created_at: 1000,
            },
            InterferenceEdge {
                agent_pid: "test-agent".to_string(),
                from_sn: 1, to_sn: 2,
                delta: StateDelta {
                    entities_added: vec![], entities_changed: vec![], entities_removed: vec![],
                    intents_opened: vec![], intents_closed: vec![],
                    decisions_made: vec![], contradictions_detected: vec![], observations_updated: vec![],
                },
                cause_evidence_cids: vec![], confidence: 1.0, ie_cid: None, created_at: 2000,
            },
            InterferenceEdge {
                agent_pid: "test-agent".to_string(),
                from_sn: 2, to_sn: 3,
                delta: StateDelta {
                    entities_added: vec![], entities_changed: vec![], entities_removed: vec![],
                    intents_opened: vec![], intents_closed: vec![],
                    decisions_made: vec![], contradictions_detected: vec![], observations_updated: vec![],
                },
                cause_evidence_cids: vec![], confidence: 1.0, ie_cid: None, created_at: 3000,
            },
        ];

        let chain = walk_interference_chain(&edges, 0, 2);
        assert_eq!(chain.len(), 2); // edges 0→1 and 1→2

        let chain = walk_interference_chain(&edges, 1, 3);
        assert_eq!(chain.len(), 2); // edges 1→2 and 2→3

        let chain = walk_interference_chain(&edges, 0, 3);
        assert_eq!(chain.len(), 3); // all edges
    }
}
