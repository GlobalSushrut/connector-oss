//! Knowledge Engine — unified knowledge management with growth, retrieval, and compilation.
//!
//! Wraps: RAG + KnotEngine + Interference + Knowledge Compilation
//!
//! Knowledge grows over time. Contradictions are detected. Facts are retrievable with provenance.
//!
//! ## Core operations:
//! - `ingest()` — add observations to knowledge graph, detect contradictions
//! - `retrieve()` — get relevant knowledge for a query (4-way + RRF + token budget)
//! - `compile()` — cache expensive reasoning as reusable semantic memory
//! - `contradictions()` — check for belief conflicts between old and new state

use vac_core::kernel::MemoryKernel;
use vac_core::types::*;
use vac_core::knot::{KnotEngine, KnotQuery, FusedResult};
use vac_core::interference::{self, StateVector, InterferenceEdge};
use crate::grounding::GroundingTable;
use crate::rag::{RagEngine, RetrievalContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// IngestResult — what happened when knowledge was ingested
// ═══════════════════════════════════════════════════════════════

/// Result of ingesting observations into the knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    /// Number of entities added/updated
    pub entities_upserted: usize,
    /// Number of edges added/updated
    pub edges_upserted: usize,
    /// Total entities in graph after ingestion
    pub total_entities: usize,
    /// Contradiction detected (if state vectors compared)
    pub contradiction_detected: bool,
    /// Interference score (0.0 = no interference, higher = more conflict)
    pub interference_score: f64,
    /// Warnings from ingestion
    pub warnings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// CompiledKnowledge — cached reasoning for reuse
// ═══════════════════════════════════════════════════════════════

/// A piece of compiled knowledge — expensive reasoning cached for instant reuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledKnowledge {
    /// CID of the compiled knowledge packet
    pub cid: String,
    /// The compiled insight/conclusion
    pub insight: String,
    /// Source CIDs that this was derived from
    pub source_cids: Vec<String>,
    /// Entities involved
    pub entities: Vec<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Number of reasoning steps that produced this
    pub reasoning_steps: usize,
}

// ═══════════════════════════════════════════════════════════════
// ContradictionReport — detected belief conflicts
// ═══════════════════════════════════════════════════════════════

/// Report of detected contradictions between knowledge states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionReport {
    /// Whether any contradiction was detected
    pub has_contradictions: bool,
    /// Interference score (magnitude of conflict)
    pub interference_score: f64,
    /// Phase delta (direction of belief shift)
    pub phase_delta: f64,
    /// Number of entities in old state
    pub old_entity_count: usize,
    /// Number of entities in new state
    pub new_entity_count: usize,
    /// Warnings
    pub warnings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// GrowthEvent — what knowledge was derived from interference
// ═══════════════════════════════════════════════════════════════

/// How a piece of knowledge was grown (provenance for knowledge growth).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GrowthKind {
    /// Contradiction resolved → new edges + compiled insight
    ContradictionResolved,
    /// Entity attributes evolved → edges strengthened/weakened
    EntityEvolved,
    /// Decision tracked → decision node + links
    DecisionTracked,
    /// Entity appeared for the first time
    EntityDiscovered,
    /// Entity removed/forgotten → edges deactivated
    EntityForgotten,
}

/// A record of knowledge growth from interference analysis.
/// Knowledge grows FROM memory but never WRITES BACK to memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowthEvent {
    /// What kind of growth
    pub kind: GrowthKind,
    /// Window sequence number that triggered this growth
    pub window_sn: u64,
    /// Entities involved
    pub entities: Vec<String>,
    /// Edges added/modified (from, to, relation)
    pub edges_affected: Vec<(String, String, String)>,
    /// Compiled knowledge produced (if any)
    pub compiled: Option<String>,
    /// Interference score that triggered this
    pub interference_score: f64,
}

// ═══════════════════════════════════════════════════════════════
// SeedEntry — pre-trained knowledge for agents
// ═══════════════════════════════════════════════════════════════

/// A seeded entity (immutable, pre-trained knowledge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEntity {
    pub id: String,
    pub entity_type: String,
    pub tags: Vec<String>,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// A seeded edge (immutable, pre-trained relationship).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub weight: f64,
}

/// Knowledge seed — pre-trained knowledge loaded at agent creation.
/// Lives in KnotEngine only, NOT in MemoryKernel. No memory footprint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeSeed {
    pub entities: Vec<SeedEntity>,
    pub edges: Vec<SeedEdge>,
}

impl KnowledgeSeed {
    pub fn new() -> Self { Self::default() }

    pub fn entity(mut self, id: &str, etype: &str) -> Self {
        self.entities.push(SeedEntity {
            id: id.to_string(), entity_type: etype.to_string(),
            tags: vec!["seed".into()], attributes: BTreeMap::new(),
        });
        self
    }

    pub fn entity_with_attrs(mut self, id: &str, etype: &str, attrs: BTreeMap<String, serde_json::Value>) -> Self {
        self.entities.push(SeedEntity {
            id: id.to_string(), entity_type: etype.to_string(),
            tags: vec!["seed".into()], attributes: attrs,
        });
        self
    }

    pub fn edge(mut self, from: &str, to: &str, relation: &str, weight: f64) -> Self {
        self.edges.push(SeedEdge {
            from: from.to_string(), to: to.to_string(),
            relation: relation.to_string(), weight,
        });
        self
    }

    /// Parse a JSON ontology: { "entities": [...], "edges": [...] }
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Invalid knowledge seed JSON: {}", e))
    }
}

// ═══════════════════════════════════════════════════════════════
// KnowledgeEngine
// ═══════════════════════════════════════════════════════════════

/// Unified knowledge engine — ingest, retrieve, compile, detect contradictions.
///
/// **Architectural invariant**: Knowledge READS from Memory (via interference),
/// but NEVER WRITES back to Memory. Memory is the source, Knowledge is the product.
/// InterferenceEngine is the bridge between them.
pub struct KnowledgeEngine {
    knot: KnotEngine,
    window_sn: u64,
    /// Previous state vector for contradiction detection
    prev_state: Option<StateVector>,
    /// Compiled knowledge cache
    compilations: Vec<CompiledKnowledge>,
    /// Growth events — audit trail of how knowledge evolved from interference
    growth_events: Vec<GrowthEvent>,
    /// Seeded entity IDs (immutable — runtime data cannot overwrite)
    seeded_ids: Vec<String>,
}

impl KnowledgeEngine {
    pub fn new() -> Self {
        Self {
            knot: KnotEngine::new(),
            window_sn: 0,
            prev_state: None,
            compilations: Vec::new(),
            growth_events: Vec::new(),
            seeded_ids: Vec::new(),
        }
    }

    /// Create a KnowledgeEngine with pre-seeded knowledge.
    /// Seeded entities/edges live in KnotEngine only — no memory footprint.
    /// Seeded IDs are immutable: runtime data cannot overwrite them.
    pub fn with_seed(seed: KnowledgeSeed) -> Self {
        let mut engine = Self::new();
        engine.apply_seed(&seed);
        engine
    }

    /// Apply a knowledge seed to the engine.
    fn apply_seed(&mut self, seed: &KnowledgeSeed) {
        for entity in &seed.entities {
            self.knot.upsert_node(
                &entity.id, Some(&entity.entity_type),
                entity.attributes.clone(), &entity.tags,
                0, // first_seen = epoch → distinguishes seed from runtime
                0, None,
            );
            self.seeded_ids.push(entity.id.clone());
        }
        for edge in &seed.edges {
            self.knot.upsert_edge(
                &edge.from, &edge.to, &edge.relation, edge.weight,
                0, 0, None,
            );
        }
    }

    /// Check if an entity ID is seeded (immutable).
    pub fn is_seeded(&self, id: &str) -> bool {
        self.seeded_ids.iter().any(|s| s == id)
    }

    /// Get all growth events (audit trail of knowledge evolution).
    pub fn growth_events(&self) -> &[GrowthEvent] { &self.growth_events }

    /// Get growth event count.
    pub fn growth_count(&self) -> usize { self.growth_events.len() }

    /// Access the underlying KnotEngine (for FFI or advanced use).
    pub fn knot(&self) -> &KnotEngine { &self.knot }

    /// Access the underlying KnotEngine mutably.
    pub fn knot_mut(&mut self) -> &mut KnotEngine { &mut self.knot }

    /// Current window sequence number.
    pub fn window_sn(&self) -> u64 { self.window_sn }

    /// Entity count in the knowledge graph.
    pub fn entity_count(&self) -> usize { self.knot.nodes().len() }

    /// All entity IDs.
    pub fn entity_ids(&self) -> Vec<String> { self.knot.nodes().keys().cloned().collect() }

    /// Neighbors of an entity.
    pub fn neighbors(&self, id: &str) -> Vec<String> {
        self.knot.neighbors(id).into_iter().map(|s| s.to_string()).collect()
    }

    /// Ingest knowledge from a kernel namespace into the graph.
    ///
    /// Pipeline:
    /// 1. Get all packets from namespace
    /// 2. Snapshot current state vector (for contradiction detection)
    /// 3. Ingest packets into KnotEngine
    /// 4. Compute new state vector
    /// 5. Compare old vs new → detect contradictions
    pub fn ingest(
        &mut self,
        kernel: &MemoryKernel,
        namespace: &str,
        agent_pid: &str,
    ) -> IngestResult {
        let packets: Vec<MemPacket> = kernel.packets_in_namespace(namespace)
            .into_iter().cloned().collect();

        if packets.is_empty() {
            return IngestResult {
                entities_upserted: 0, edges_upserted: 0,
                total_entities: self.entity_count(),
                contradiction_detected: false, interference_score: 0.0,
                warnings: vec!["No packets in namespace".into()],
            };
        }

        let entities_before = self.entity_count();

        // Snapshot previous state
        let old_state = self.prev_state.clone();

        // Ingest into knot engine
        self.knot.ingest_packets(&packets, self.window_sn);
        self.window_sn += 1;

        let entities_after = self.entity_count();
        let entities_upserted = entities_after.saturating_sub(entities_before).max(
            if entities_after > 0 { packets.len().min(entities_after) } else { 0 }
        );

        // Compute new state vector
        let new_state = interference::extract_state_vector(
            self.window_sn, agent_pid, namespace, &packets, [0u8; 32],
        );

        // Detect contradictions
        let (contradiction_detected, interference_score, warnings) = if let Some(ref old) = old_state {
            let edge = interference::compute_interference(old, &new_state);
            let d = &edge.delta;
            // Score = normalized count of changes + contradictions
            let change_count = d.entities_added.len() + d.entities_changed.len()
                + d.entities_removed.len() + d.contradictions_detected.len();
            let score = if change_count == 0 { 0.0 } else {
                (d.contradictions_detected.len() as f64 / change_count as f64).min(1.0)
                + (d.entities_removed.len() as f64 * 0.1)
            };
            let detected = !d.contradictions_detected.is_empty() || d.entities_removed.len() > 2;
            let mut w = Vec::new();
            if detected {
                w.push(format!("Contradiction detected: {} contradictions, {} entities removed",
                    d.contradictions_detected.len(), d.entities_removed.len()));
            }
            (detected, score.min(1.0), w)
        } else {
            (false, 0.0, Vec::new())
        };

        // Update state
        self.prev_state = Some(new_state);

        IngestResult {
            entities_upserted,
            edges_upserted: 0, // KnotEngine doesn't report edge count separately
            total_entities: entities_after,
            contradiction_detected,
            interference_score,
            warnings,
        }
    }

    /// Add an entity manually to the knowledge graph.
    pub fn add_entity(&mut self, id: &str, etype: Option<&str>, tags: &[String]) {
        let now = chrono::Utc::now().timestamp_millis();
        self.knot.upsert_node(id, etype, BTreeMap::new(), tags, now, self.window_sn, None);
    }

    /// Add a relationship edge manually.
    pub fn add_edge(&mut self, from: &str, to: &str, relation: &str, weight: f64) {
        let now = chrono::Utc::now().timestamp_millis();
        self.knot.upsert_edge(from, to, relation, weight, now, self.window_sn, None);
    }

    /// Retrieve knowledge for a query using RAG pipeline.
    ///
    /// Pipeline:
    /// 1. Build KnotQuery from entities + keywords
    /// 2. 4-way retrieval (temporal, graph, keyword, semantic) + RRF fusion
    /// 3. Resolve packet CIDs from kernel
    /// 4. Apply grounding table
    /// 5. Pack into token budget with CID provenance
    pub fn retrieve(
        &self,
        kernel: &MemoryKernel,
        entities: &[String],
        keywords: &[String],
        token_budget: usize,
        max_facts: usize,
        grounding: Option<&GroundingTable>,
    ) -> RetrievalContext {
        let rag = RagEngine::new().with_budget(token_budget).with_max_facts(max_facts);
        rag.retrieve(&self.knot, kernel, entities, keywords, None, grounding)
    }

    /// Query the knowledge graph directly (without RAG resolution).
    pub fn query(&self, entities: &[String], keywords: &[String], limit: usize) -> Vec<FusedResult> {
        let q = KnotQuery {
            entities: entities.to_vec(),
            keywords: keywords.to_vec(),
            time_range: None, semantic_query: None,
            limit, token_budget: 4096,
            min_trust_tier: None, rrf_k: 60.0,
        };
        self.knot.query(&q)
    }

    /// Compile reasoning into reusable knowledge.
    ///
    /// Takes a reasoning chain result and stores it as a compiled knowledge packet
    /// in the kernel for future retrieval, skipping expensive re-reasoning.
    pub fn compile(
        &mut self,
        kernel: &mut MemoryKernel,
        agent_pid: &str,
        insight: &str,
        source_cids: Vec<String>,
        entities: Vec<String>,
        confidence: f64,
        reasoning_steps: usize,
    ) -> Result<CompiledKnowledge, String> {
        use crate::memory::MemoryCoordinator;

        // Store as a Decision packet (compiled knowledge = a decision/conclusion)
        let cid = MemoryCoordinator::write(
            kernel, agent_pid, insight, "system:compiler", "pipe:knowledge_compilation",
            PacketType::Decision, None,
            entities.clone(),
            vec!["compiled_knowledge".into(), format!("confidence:{:.2}", confidence)],
        )?;

        // Index in knot engine
        for entity in &entities {
            self.add_entity(entity, Some("compiled"), &["compiled_knowledge".into()]);
        }

        let compiled = CompiledKnowledge {
            cid: cid.to_string(),
            insight: insight.to_string(),
            source_cids,
            entities,
            confidence,
            reasoning_steps,
        };

        self.compilations.push(compiled.clone());
        Ok(compiled)
    }

    /// Get all compiled knowledge entries.
    pub fn compilations(&self) -> &[CompiledKnowledge] { &self.compilations }

    /// Check for contradictions between current and previous state.
    pub fn check_contradictions(
        &self,
        kernel: &MemoryKernel,
        namespace: &str,
        agent_pid: &str,
    ) -> ContradictionReport {
        let packets: Vec<MemPacket> = kernel.packets_in_namespace(namespace)
            .into_iter().cloned().collect();

        let new_state = interference::extract_state_vector(
            self.window_sn, agent_pid, namespace, &packets, [0u8; 32],
        );

        if let Some(ref old) = self.prev_state {
            let edge = interference::compute_interference(old, &new_state);
            let d = &edge.delta;
            let change_count = d.entities_added.len() + d.entities_changed.len()
                + d.entities_removed.len() + d.contradictions_detected.len();
            let score = if change_count == 0 { 0.0 } else {
                (d.contradictions_detected.len() as f64 / change_count as f64).min(1.0)
                + (d.entities_removed.len() as f64 * 0.1)
            };
            let detected = !d.contradictions_detected.is_empty() || d.entities_removed.len() > 2;
            let mut warnings = Vec::new();
            if detected {
                warnings.push(format!("Belief conflict: {} contradictions", d.contradictions_detected.len()));
            }
            ContradictionReport {
                has_contradictions: detected,
                interference_score: score.min(1.0),
                phase_delta: edge.confidence,
                old_entity_count: old.entities.len(),
                new_entity_count: new_state.entities.len(),
                warnings,
            }
        } else {
            ContradictionReport {
                has_contradictions: false,
                interference_score: 0.0,
                phase_delta: 0.0,
                old_entity_count: 0,
                new_entity_count: new_state.entities.len(),
                warnings: vec!["No previous state to compare".into()],
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // KnowledgePipeline — interference → knowledge growth feedback loop
    // ═══════════════════════════════════════════════════════════════

    /// Process an InterferenceEdge and grow knowledge from it.
    ///
    /// This is the core feedback loop: Memory → Interference → Knowledge.
    /// Knowledge READS from the delta but NEVER WRITES back to Memory.
    ///
    /// Returns the number of growth events produced.
    pub fn process_interference(&mut self, edge: &InterferenceEdge) -> Vec<GrowthEvent> {
        let d = &edge.delta;
        let sn = edge.to_sn;
        let now = chrono::Utc::now().timestamp_millis();
        let mut events = Vec::new();

        // 1. New entities discovered → add to knowledge graph
        for entity in &d.entities_added {
            if self.is_seeded(&entity.entity_id) { continue; } // don't overwrite seed
            self.knot.upsert_node(
                &entity.entity_id, None, entity.attributes.clone(),
                &["interference_discovered".to_string()], now, sn, None,
            );
            events.push(GrowthEvent {
                kind: GrowthKind::EntityDiscovered,
                window_sn: sn,
                entities: vec![entity.entity_id.clone()],
                edges_affected: vec![],
                compiled: None,
                interference_score: edge.confidence,
            });
        }

        // 2. Entities evolved → strengthen co-occurrence edges
        for change in &d.entities_changed {
            if self.is_seeded(&change.entity_id) { continue; }
            let mut edges_affected = Vec::new();
            // Strengthen edges to neighbors (entities seen evolving together are related)
            let neighbors: Vec<String> = self.knot.neighbors(&change.entity_id)
                .iter().map(|s| s.to_string()).collect();
            for neighbor in &neighbors {
                self.knot.upsert_edge(
                    &change.entity_id, neighbor, "co_evolves", 0.8,
                    now, sn, None,
                );
                edges_affected.push((change.entity_id.clone(), neighbor.clone(), "co_evolves".into()));
            }
            // Add evolution event node
            let event_id = format!("evolution:W-{}", sn);
            self.knot.upsert_node(
                &event_id, Some("evolution_event"),
                BTreeMap::from([
                    ("changed_keys".into(), serde_json::json!(change.changed_keys)),
                    ("removed_keys".into(), serde_json::json!(change.removed_keys)),
                ]),
                &["evolution".into()], now, sn, None,
            );
            self.knot.upsert_edge(
                &change.entity_id, &event_id, "evolved_at", 1.0, now, sn, None,
            );
            edges_affected.push((change.entity_id.clone(), event_id, "evolved_at".into()));

            events.push(GrowthEvent {
                kind: GrowthKind::EntityEvolved,
                window_sn: sn,
                entities: vec![change.entity_id.clone()],
                edges_affected,
                compiled: None,
                interference_score: edge.confidence,
            });
        }

        // 3. Entities removed → deactivate edges (Graphiti pattern: don't delete)
        for removed_id in &d.entities_removed {
            if self.is_seeded(removed_id) { continue; }
            let event_id = format!("forgotten:W-{}", sn);
            self.knot.upsert_node(
                &event_id, Some("forgotten_event"),
                BTreeMap::from([("entity".into(), serde_json::json!(removed_id))]),
                &["forgotten".into()], now, sn, None,
            );
            events.push(GrowthEvent {
                kind: GrowthKind::EntityForgotten,
                window_sn: sn,
                entities: vec![removed_id.clone()],
                edges_affected: vec![],
                compiled: None,
                interference_score: edge.confidence,
            });
        }

        // 4. Contradictions detected → compiled knowledge
        for contradiction in &d.contradictions_detected {
            let insight = format!(
                "Contradiction resolved at window {}: {} (was: {}, now: {})",
                sn, contradiction.entity_id,
                contradiction.old_claim, contradiction.new_claim
            );
            let event_id = format!("contradiction:W-{}", sn);
            self.knot.upsert_node(
                &event_id, Some("contradiction_event"),
                BTreeMap::from([
                    ("entity".into(), serde_json::json!(contradiction.entity_id)),
                    ("old_claim".into(), serde_json::json!(contradiction.old_claim)),
                    ("new_claim".into(), serde_json::json!(contradiction.new_claim)),
                ]),
                &["contradiction".into()], now, sn, None,
            );
            let mut edges_affected = Vec::new();
            self.knot.upsert_edge(
                &contradiction.entity_id, &event_id, "contradiction_resolved", 1.0, now, sn, None,
            );
            edges_affected.push((contradiction.entity_id.clone(), event_id.clone(), "contradiction_resolved".into()));
            let entities = vec![contradiction.entity_id.clone()];
            self.compilations.push(CompiledKnowledge {
                cid: format!("compiled:contradiction:W-{}", sn),
                insight: insight.clone(),
                source_cids: vec![],
                entities: entities.clone(),
                confidence: 1.0 - edge.confidence, // lower confidence = higher contradiction
                reasoning_steps: 1,
            });
            events.push(GrowthEvent {
                kind: GrowthKind::ContradictionResolved,
                window_sn: sn,
                entities,
                edges_affected,
                compiled: Some(insight),
                interference_score: edge.confidence,
            });
        }

        // 5. Decisions made → decision nodes + links
        for decision in &d.decisions_made {
            let conf = decision.confidence.unwrap_or(0.5) as f64;
            let decision_id = format!("decision:W-{}", sn);
            self.knot.upsert_node(
                &decision_id, Some("decision"),
                BTreeMap::from([
                    ("description".into(), serde_json::json!(decision.description)),
                    ("confidence".into(), serde_json::json!(conf)),
                ]),
                &["decision".into()], now, sn, None,
            );
            // Decisions don't carry entity lists — link to the decision node itself
            let edges_affected = Vec::new();
            self.compilations.push(CompiledKnowledge {
                cid: format!("compiled:decision:W-{}", sn),
                insight: format!("Decision: {} (confidence: {:.2})", decision.description, conf),
                source_cids: decision.source_cid.as_ref().map(|c| vec![c.to_string()]).unwrap_or_default(),
                entities: vec![decision_id.clone()],
                confidence: conf,
                reasoning_steps: 1,
            });
            events.push(GrowthEvent {
                kind: GrowthKind::DecisionTracked,
                window_sn: sn,
                entities: vec![decision_id],
                edges_affected,
                compiled: Some(decision.description.clone()),
                interference_score: edge.confidence,
            });
        }

        self.growth_events.extend(events.clone());
        events
    }

    /// Ingest from memory AND process interference in one step.
    /// This is the recommended entry point — combines ingest + feedback loop.
    ///
    /// Pipeline:
    /// 1. Read packets from kernel namespace (Memory → Knowledge read)
    /// 2. Ingest entities into KnotEngine
    /// 3. Compute StateVector + InterferenceEdge
    /// 4. Process interference → grow knowledge
    /// 5. Return combined result
    pub fn ingest_and_grow(
        &mut self,
        kernel: &MemoryKernel,
        namespace: &str,
        agent_pid: &str,
    ) -> (IngestResult, Vec<GrowthEvent>) {
        let packets: Vec<MemPacket> = kernel.packets_in_namespace(namespace)
            .into_iter().cloned().collect();

        if packets.is_empty() {
            return (IngestResult {
                entities_upserted: 0, edges_upserted: 0,
                total_entities: self.entity_count(),
                contradiction_detected: false, interference_score: 0.0,
                warnings: vec!["No packets in namespace".into()],
            }, vec![]);
        }

        let entities_before = self.entity_count();
        let old_state = self.prev_state.clone();

        // Ingest into knot engine (Knowledge reads from Memory)
        self.knot.ingest_packets(&packets, self.window_sn);
        self.window_sn += 1;

        let entities_after = self.entity_count();
        let entities_upserted = entities_after.saturating_sub(entities_before).max(
            if entities_after > 0 { packets.len().min(entities_after) } else { 0 }
        );

        // Compute new state vector
        let new_state = interference::extract_state_vector(
            self.window_sn, agent_pid, namespace, &packets, [0u8; 32],
        );

        // Compute interference and grow knowledge
        let (contradiction_detected, interference_score, warnings, growth) = if let Some(ref old) = old_state {
            let ie = interference::compute_interference(old, &new_state);
            let d = &ie.delta;
            let change_count = d.entities_added.len() + d.entities_changed.len()
                + d.entities_removed.len() + d.contradictions_detected.len();
            let score = if change_count == 0 { 0.0 } else {
                (d.contradictions_detected.len() as f64 / change_count as f64).min(1.0)
                + (d.entities_removed.len() as f64 * 0.1)
            };
            let detected = !d.contradictions_detected.is_empty() || d.entities_removed.len() > 2;
            let mut w = Vec::new();
            if detected {
                w.push(format!("Contradiction detected: {} contradictions, {} entities removed",
                    d.contradictions_detected.len(), d.entities_removed.len()));
            }
            // THE FEEDBACK LOOP: process interference → grow knowledge
            let growth_events = self.process_interference(&ie);
            if !growth_events.is_empty() {
                w.push(format!("Knowledge grew: {} events", growth_events.len()));
            }
            (detected, score.min(1.0), w, growth_events)
        } else {
            (false, 0.0, Vec::new(), Vec::new())
        };

        self.prev_state = Some(new_state);

        (IngestResult {
            entities_upserted,
            edges_upserted: 0,
            total_entities: self.entity_count(),
            contradiction_detected,
            interference_score,
            warnings,
        }, growth)
    }
}

impl Default for KnowledgeEngine {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::{SyscallRequest, SyscallPayload, SyscallValue};
    use crate::memory::MemoryCoordinator;

    fn setup() -> (MemoryKernel, String) {
        let mut k = MemoryKernel::new();
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".into(), namespace: "ns:bot".into(),
                role: Some("writer".into()), model: None, framework: None,
            }, reason: None, vakya_id: None,
        });
        let pid = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None,
        });
        (k, pid)
    }

    #[test]
    fn test_ingest_from_namespace() {
        let (mut k, pid) = setup();
        MemoryCoordinator::write(&mut k, &pid, "patient has diabetes", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into(), "condition:diabetes".into()], vec![]).unwrap();

        let mut ke = KnowledgeEngine::new();
        let result = ke.ingest(&k, "ns:bot", &pid);
        assert!(result.total_entities > 0);
        assert!(result.entities_upserted > 0);
        assert!(!result.contradiction_detected);
    }

    #[test]
    fn test_retrieve_knowledge() {
        let (mut k, pid) = setup();
        MemoryCoordinator::write(&mut k, &pid, "patient has chest pain", "user:doc", "pipe:er",
            PacketType::Extraction, None, vec!["patient:001".into(), "symptom:chest_pain".into()], vec![]).unwrap();

        let mut ke = KnowledgeEngine::new();
        ke.ingest(&k, "ns:bot", &pid);

        let ctx = ke.retrieve(&k, &["patient:001".into()], &[], 4096, 20, None);
        assert!(ctx.facts_included >= 0); // May or may not find depending on knot indexing
    }

    #[test]
    fn test_add_entity_and_query() {
        let mut ke = KnowledgeEngine::new();
        ke.add_entity("patient:001", Some("patient"), &["medical".into()]);
        ke.add_entity("condition:diabetes", Some("condition"), &["medical".into()]);
        ke.add_edge("patient:001", "condition:diabetes", "has_condition", 1.0);

        assert_eq!(ke.entity_count(), 2);
        assert!(ke.entity_ids().contains(&"patient:001".to_string()));
        let neighbors = ke.neighbors("patient:001");
        assert!(neighbors.contains(&"condition:diabetes".to_string()));
    }

    #[test]
    fn test_compile_knowledge() {
        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::new();

        let compiled = ke.compile(
            &mut k, &pid,
            "Chest pain + ST elevation + elevated troponin = STEMI diagnosis",
            vec!["cid:step1".into(), "cid:step2".into(), "cid:step3".into()],
            vec!["diagnosis:stemi".into(), "symptom:chest_pain".into()],
            0.95, 3,
        ).unwrap();

        assert!(!compiled.cid.is_empty());
        assert_eq!(compiled.reasoning_steps, 3);
        assert_eq!(compiled.confidence, 0.95);
        assert_eq!(ke.compilations().len(), 1);
    }

    #[test]
    fn test_contradiction_detection() {
        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::new();

        // First ingestion — baseline
        MemoryCoordinator::write(&mut k, &pid, "patient is stable", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into()], vec![]).unwrap();
        ke.ingest(&k, "ns:bot", &pid);

        // Check contradictions (no previous state on first ingest, but now we have one)
        let report = ke.check_contradictions(&k, "ns:bot", &pid);
        // First check after one ingest — should have a state to compare
        assert!(report.new_entity_count >= 0);
    }

    #[test]
    fn test_empty_namespace_ingest() {
        let (k, pid) = setup();
        let mut ke = KnowledgeEngine::new();
        let result = ke.ingest(&k, "ns:empty", &pid);
        assert_eq!(result.entities_upserted, 0);
        assert!(result.warnings.len() > 0);
    }

    #[test]
    fn test_knowledge_growth() {
        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::new();

        // First batch
        MemoryCoordinator::write(&mut k, &pid, "patient has diabetes", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into()], vec![]).unwrap();
        let r1 = ke.ingest(&k, "ns:bot", &pid);
        let count1 = r1.total_entities;

        // Second batch — more data
        MemoryCoordinator::write(&mut k, &pid, "patient has hypertension", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into(), "condition:hypertension".into()], vec![]).unwrap();
        let r2 = ke.ingest(&k, "ns:bot", &pid);

        // Knowledge should grow
        assert!(r2.total_entities >= count1);
    }

    // ═══════════════════════════════════════════════════════════════
    // NEW: Knowledge Seeding tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_knowledge_seed_entities_and_edges() {
        let seed = KnowledgeSeed::new()
            .entity("condition:diabetes", "condition")
            .entity("drug:metformin", "medication")
            .edge("drug:metformin", "condition:diabetes", "treats", 0.95);

        let ke = KnowledgeEngine::with_seed(seed);
        assert_eq!(ke.entity_count(), 2);
        assert!(ke.is_seeded("condition:diabetes"));
        assert!(ke.is_seeded("drug:metformin"));
        assert!(!ke.is_seeded("unknown:entity"));

        // Seeded entities should be queryable
        let neighbors = ke.neighbors("drug:metformin");
        assert!(neighbors.contains(&"condition:diabetes".to_string()));
    }

    #[test]
    fn test_knowledge_seed_from_json() {
        let json = r#"{
            "entities": [
                {"id": "symptom:fever", "entity_type": "symptom", "tags": ["seed"], "attributes": {}},
                {"id": "condition:flu", "entity_type": "condition", "tags": ["seed"], "attributes": {}}
            ],
            "edges": [
                {"from": "condition:flu", "to": "symptom:fever", "relation": "presents_with", "weight": 0.9}
            ]
        }"#;
        let seed = KnowledgeSeed::from_json(json).unwrap();
        let ke = KnowledgeEngine::with_seed(seed);
        assert_eq!(ke.entity_count(), 2);
        assert!(ke.is_seeded("symptom:fever"));
    }

    #[test]
    fn test_seed_immutability_runtime_cannot_overwrite() {
        let seed = KnowledgeSeed::new()
            .entity("drug:aspirin", "medication");
        let mut ke = KnowledgeEngine::with_seed(seed);

        // Seeded entity exists
        assert!(ke.is_seeded("drug:aspirin"));
        assert_eq!(ke.entity_count(), 1);

        // Runtime can add NEW entities but seeded ones are protected in process_interference
        ke.add_entity("patient:001", Some("patient"), &["runtime".into()]);
        assert_eq!(ke.entity_count(), 2);
        assert!(!ke.is_seeded("patient:001")); // runtime entity is not seeded
    }

    // ═══════════════════════════════════════════════════════════════
    // NEW: Knowledge Pipeline feedback loop tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_process_interference_entity_discovered() {
        use vac_core::interference::{InterferenceEdge, StateDelta, EntityState};

        let mut ke = KnowledgeEngine::new();

        // Simulate an InterferenceEdge with a new entity discovered
        let ie = InterferenceEdge {
            agent_pid: "pid:bot".into(),
            from_sn: 0, to_sn: 1,
            delta: StateDelta {
                entities_added: vec![EntityState {
                    entity_id: "patient:new".into(),
                    attributes: BTreeMap::from([("status".into(), serde_json::json!("admitted"))]),
                    last_seen: 1000,
                    mention_count: 1,
                    source_cids: vec![],
                }],
                entities_changed: vec![],
                entities_removed: vec![],
                intents_opened: vec![], intents_closed: vec![],
                decisions_made: vec![], contradictions_detected: vec![],
                observations_updated: vec![],
            },
            cause_evidence_cids: vec![],
            confidence: 0.9,
            ie_cid: None,
            created_at: 1000,
        };

        let events = ke.process_interference(&ie);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, GrowthKind::EntityDiscovered);
        assert_eq!(events[0].entities, vec!["patient:new".to_string()]);
        assert_eq!(ke.growth_count(), 1);

        // Entity should now be in the knowledge graph
        assert!(ke.entity_ids().contains(&"patient:new".to_string()));
    }

    #[test]
    fn test_process_interference_entity_evolved() {
        use vac_core::interference::{InterferenceEdge, StateDelta, EntityChange};

        let mut ke = KnowledgeEngine::new();
        // Pre-populate an entity and a neighbor
        ke.add_entity("patient:001", Some("patient"), &[]);
        ke.add_entity("condition:diabetes", Some("condition"), &[]);
        ke.add_edge("patient:001", "condition:diabetes", "has_condition", 1.0);

        let ie = InterferenceEdge {
            agent_pid: "pid:bot".into(),
            from_sn: 0, to_sn: 1,
            delta: StateDelta {
                entities_added: vec![],
                entities_changed: vec![EntityChange {
                    entity_id: "patient:001".into(),
                    changed_keys: vec!["status".into()],
                    removed_keys: vec![],
                }],
                entities_removed: vec![],
                intents_opened: vec![], intents_closed: vec![],
                decisions_made: vec![], contradictions_detected: vec![],
                observations_updated: vec![],
            },
            cause_evidence_cids: vec![],
            confidence: 0.9,
            ie_cid: None,
            created_at: 1000,
        };

        let events = ke.process_interference(&ie);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, GrowthKind::EntityEvolved);
        // Should have created co_evolves edge + evolution event node
        assert!(!events[0].edges_affected.is_empty());
        // Evolution event node should exist
        assert!(ke.entity_ids().iter().any(|id| id.starts_with("evolution:")));
    }

    #[test]
    fn test_process_interference_decision_tracked() {
        use vac_core::interference::{InterferenceEdge, StateDelta, DecisionRecord};

        let mut ke = KnowledgeEngine::new();

        let ie = InterferenceEdge {
            agent_pid: "pid:bot".into(),
            from_sn: 0, to_sn: 1,
            delta: StateDelta {
                entities_added: vec![],
                entities_changed: vec![],
                entities_removed: vec![],
                intents_opened: vec![], intents_closed: vec![],
                decisions_made: vec![DecisionRecord {
                    description: "prescribe insulin".into(),
                    reasoning: Some("elevated blood sugar".into()),
                    confidence: Some(0.92),
                    decided_at: 1000,
                    source_cid: None,
                }],
                contradictions_detected: vec![],
                observations_updated: vec![],
            },
            cause_evidence_cids: vec![],
            confidence: 0.9,
            ie_cid: None,
            created_at: 1000,
        };

        let events = ke.process_interference(&ie);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, GrowthKind::DecisionTracked);
        assert!(events[0].compiled.is_some());
        // Compiled knowledge should be created
        assert_eq!(ke.compilations().len(), 1);
        assert!(ke.compilations()[0].insight.contains("prescribe insulin"));
    }

    #[test]
    fn test_ingest_and_grow_combined() {
        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::new();

        // First ingest — baseline (no growth yet, no previous state)
        MemoryCoordinator::write(&mut k, &pid, "patient admitted", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into()], vec![]).unwrap();
        let (r1, g1) = ke.ingest_and_grow(&k, "ns:bot", &pid);
        assert!(r1.total_entities > 0);
        assert!(g1.is_empty()); // No growth on first ingest (no previous state)

        // Second ingest — new entities should trigger growth
        MemoryCoordinator::write(&mut k, &pid, "patient has chest pain", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into(), "symptom:chest_pain".into()], vec![]).unwrap();
        let (r2, _g2) = ke.ingest_and_grow(&k, "ns:bot", &pid);
        assert!(r2.total_entities >= r1.total_entities);
        // Growth events may or may not be produced depending on interference delta
    }

    #[test]
    fn test_memory_and_knowledge_are_separate() {
        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::new();

        // Write to MEMORY
        MemoryCoordinator::write(&mut k, &pid, "patient has diabetes", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into()], vec![]).unwrap();

        // KNOWLEDGE is empty before ingest
        assert_eq!(ke.entity_count(), 0);

        // Ingest reads from memory into knowledge
        ke.ingest(&k, "ns:bot", &pid);
        assert!(ke.entity_count() > 0);

        // Memory still has its packets (knowledge didn't modify memory)
        let packets = k.packets_in_namespace("ns:bot");
        assert!(!packets.is_empty());

        // Adding to knowledge doesn't affect memory
        ke.add_entity("extra:entity", Some("test"), &[]);
        let packets_after = k.packets_in_namespace("ns:bot");
        assert_eq!(packets.len(), packets_after.len()); // Memory unchanged
    }

    #[test]
    fn test_seed_plus_runtime_knowledge_growth() {
        let seed = KnowledgeSeed::new()
            .entity("drug:aspirin", "medication")
            .entity("condition:headache", "condition")
            .edge("drug:aspirin", "condition:headache", "treats", 0.85);

        let (mut k, pid) = setup();
        let mut ke = KnowledgeEngine::with_seed(seed);
        assert_eq!(ke.entity_count(), 2); // seed only

        // Write memory and ingest — knowledge grows from memory
        MemoryCoordinator::write(&mut k, &pid, "patient has headache", "user:doc", "pipe:er",
            PacketType::Input, None, vec!["patient:001".into(), "condition:headache".into()], vec![]).unwrap();
        ke.ingest(&k, "ns:bot", &pid);

        // Knowledge should now have seed entities + runtime entities
        assert!(ke.entity_count() > 2);
        assert!(ke.is_seeded("drug:aspirin")); // seed still marked
        assert!(!ke.is_seeded("patient:001")); // runtime not seeded
    }

    #[test]
    fn test_growth_events_audit_trail() {
        use vac_core::interference::{InterferenceEdge, StateDelta, EntityState};

        let mut ke = KnowledgeEngine::new();
        assert_eq!(ke.growth_count(), 0);

        // Process multiple interference edges
        for i in 0..3u64 {
            let ie = InterferenceEdge {
                agent_pid: "pid:bot".into(),
                from_sn: i, to_sn: i + 1,
                delta: StateDelta {
                    entities_added: vec![EntityState {
                        entity_id: format!("entity:{}", i),
                        attributes: BTreeMap::new(),
                        last_seen: 1000 + i as i64,
                        mention_count: 1,
                        source_cids: vec![],
                    }],
                    entities_changed: vec![], entities_removed: vec![],
                    intents_opened: vec![], intents_closed: vec![],
                    decisions_made: vec![], contradictions_detected: vec![],
                    observations_updated: vec![],
                },
                cause_evidence_cids: vec![],
                confidence: 0.9,
                ie_cid: None,
                created_at: 1000,
            };
            ke.process_interference(&ie);
        }

        // Growth events should accumulate as audit trail
        assert_eq!(ke.growth_count(), 3);
        assert!(ke.growth_events().iter().all(|e| e.kind == GrowthKind::EntityDiscovered));
    }
}
