//! Knot Topology Engine — multi-dimensional retrieval with RRF fusion.
//!
//! Implements 4-way parallel retrieval over the memory graph:
//! 1. **Temporal**: by time range (RangeWindow pagination)
//! 2. **Entity/Graph**: by entity relationships (KnotNode + KnotEdge)
//! 3. **Keyword**: by tag/entity string matching
//! 4. **Semantic**: by embedding similarity (placeholder for vector store)
//!
//! Results are fused using Reciprocal Rank Fusion (RRF) and packed
//! into a token budget for the LLM context window.
//!
//! Design sources: Graphiti (temporal knowledge graph), Microsoft GraphRAG
//! (community detection), Zep (bi-temporal + graph), LightRAG (dual-level),
//! vLLM PagedAttention (token-budget packing).

use std::collections::{BTreeMap, HashMap, HashSet};

use cid::Cid;
use serde::{Deserialize, Serialize};

use crate::types::*;

// =============================================================================
// Knowledge Graph types — KnotNode + KnotEdge
// =============================================================================

/// A node in the knowledge graph — represents an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotNode {
    /// Entity identifier (e.g., "patient:P-001", "drug:penicillin")
    pub entity_id: String,
    /// Entity type (e.g., "person", "medication", "organization")
    pub entity_type: Option<String>,
    /// Known attributes
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Tags for keyword search
    pub tags: Vec<String>,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last seen timestamp
    pub last_seen: i64,
    /// Number of times mentioned
    pub mention_count: u64,
    /// RangeWindow serial numbers where this entity appears
    pub window_sns: Vec<u64>,
    /// Source packet CIDs
    pub source_cids: Vec<Cid>,
}

/// An edge in the knowledge graph — represents a relationship between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotEdge {
    /// Source entity
    pub from: String,
    /// Target entity
    pub to: String,
    /// Relationship type (e.g., "allergic_to", "prescribed", "works_at")
    pub relation: String,
    /// Edge weight (higher = stronger relationship)
    pub weight: f64,
    /// When this relationship was established
    pub created_at: i64,
    /// Last confirmed timestamp
    pub last_confirmed: i64,
    /// Whether this edge is still active
    pub active: bool,
    /// Source packet CIDs that established/confirmed this edge
    pub evidence_cids: Vec<Cid>,
    /// RangeWindow serial numbers where this edge was referenced
    pub window_sns: Vec<u64>,
}

// =============================================================================
// Retrieval result types
// =============================================================================

/// A single retrieval hit with its score and source
#[derive(Debug, Clone)]
pub struct RetrievalHit {
    /// The entity or content identifier
    pub id: String,
    /// Score from this retrieval channel (higher = more relevant)
    pub score: f64,
    /// Which retrieval channel produced this hit
    pub channel: RetrievalChannel,
    /// Associated RangeWindow serial numbers
    pub window_sns: Vec<u64>,
    /// Associated packet CIDs
    pub packet_cids: Vec<Cid>,
}

/// Which retrieval channel produced a hit
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalChannel {
    Temporal,
    Graph,
    Keyword,
    Semantic,
}

impl std::fmt::Display for RetrievalChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrievalChannel::Temporal => write!(f, "temporal"),
            RetrievalChannel::Graph => write!(f, "graph"),
            RetrievalChannel::Keyword => write!(f, "keyword"),
            RetrievalChannel::Semantic => write!(f, "semantic"),
        }
    }
}

/// A fused retrieval result after RRF
#[derive(Debug, Clone)]
pub struct FusedResult {
    /// Entity or content identifier
    pub id: String,
    /// Fused RRF score
    pub rrf_score: f64,
    /// Which channels contributed to this result
    pub channels: Vec<RetrievalChannel>,
    /// Per-channel scores
    pub channel_scores: HashMap<RetrievalChannel, f64>,
    /// Associated window serial numbers (deduplicated)
    pub window_sns: Vec<u64>,
    /// Associated packet CIDs (deduplicated)
    pub packet_cids: Vec<Cid>,
}

/// A retrieval query
#[derive(Debug, Clone)]
pub struct KnotQuery {
    /// Entities to search for (graph retrieval)
    pub entities: Vec<String>,
    /// Keywords/tags to search for (keyword retrieval)
    pub keywords: Vec<String>,
    /// Time range for temporal retrieval (start_ms, end_ms)
    pub time_range: Option<(i64, i64)>,
    /// Semantic query text (for embedding similarity)
    pub semantic_query: Option<String>,
    /// Maximum results to return
    pub limit: usize,
    /// Token budget for context packing
    pub token_budget: u64,
    /// Minimum trust tier
    pub min_trust_tier: Option<u8>,
    /// RRF constant k (default 60)
    pub rrf_k: f64,
}

impl Default for KnotQuery {
    fn default() -> Self {
        Self {
            entities: Vec::new(),
            keywords: Vec::new(),
            time_range: None,
            semantic_query: None,
            limit: 20,
            token_budget: 4096,
            min_trust_tier: None,
            rrf_k: 60.0,
        }
    }
}

// =============================================================================
// Knot Topology Engine
// =============================================================================

/// The Knot Topology Engine — manages the knowledge graph and performs
/// multi-dimensional retrieval with RRF fusion.
pub struct KnotEngine {
    /// Entity nodes (entity_id → KnotNode)
    nodes: HashMap<String, KnotNode>,
    /// Edges (from → [(to, KnotEdge)])
    edges: HashMap<String, Vec<KnotEdge>>,
    /// Reverse edges for bidirectional traversal (to → [(from, relation)])
    reverse_edges: HashMap<String, Vec<(String, String)>>,
    /// Tag index: tag → entity_ids
    tag_index: HashMap<String, HashSet<String>>,
    /// Window index: sn → entity_ids that appear in that window
    window_entity_index: HashMap<u64, HashSet<String>>,
    /// § 10.11 K_vn recompute trigger: serial number of the last ingest_packets call.
    /// Callers compare this against their last-computed K_vn window_sn to decide
    /// whether VnGraphEntropy needs to be recomputed for a given namespace.
    pub last_ingest_sn: u64,
    /// § 10.11 K_vn dirty flag: set true after every ingest_packets call, cleared
    /// by the consolidation loop after VnGraphEntropy has been recomputed and
    /// stored back into the relevant AgentExpertiseRecord.
    pub k_vn_dirty: bool,
}

impl KnotEngine {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
            tag_index: HashMap::new(),
            window_entity_index: HashMap::new(),
            last_ingest_sn: 0,
            k_vn_dirty: false,
        }
    }

    // =========================================================================
    // Graph mutation
    // =========================================================================

    /// Add or update an entity node
    pub fn upsert_node(
        &mut self,
        entity_id: &str,
        entity_type: Option<&str>,
        attributes: BTreeMap<String, serde_json::Value>,
        tags: &[String],
        timestamp: i64,
        window_sn: u64,
        source_cid: Option<Cid>,
    ) {
        let node = self.nodes.entry(entity_id.to_string()).or_insert_with(|| KnotNode {
            entity_id: entity_id.to_string(),
            entity_type: entity_type.map(|s| s.to_string()),
            attributes: BTreeMap::new(),
            tags: Vec::new(),
            first_seen: timestamp,
            last_seen: timestamp,
            mention_count: 0,
            window_sns: Vec::new(),
            source_cids: Vec::new(),
        });

        node.mention_count += 1;
        node.last_seen = node.last_seen.max(timestamp);

        // Merge attributes
        for (k, v) in attributes {
            node.attributes.insert(k, v);
        }

        // Merge tags
        for tag in tags {
            if !node.tags.contains(tag) {
                node.tags.push(tag.clone());
                self.tag_index
                    .entry(tag.clone())
                    .or_default()
                    .insert(entity_id.to_string());
            }
        }

        // Track window (D15 FIX: cap at 500 to prevent unbounded growth)
        if !node.window_sns.contains(&window_sn) {
            node.window_sns.push(window_sn);
            if node.window_sns.len() > 500 {
                let drain_count = node.window_sns.len() - 500;
                node.window_sns.drain(..drain_count);
            }
        }

        // D7 FIX: Cap source_cids at 100 per node to prevent unbounded growth.
        // At 1K packets/window, a long-lived entity accumulates O(windows × packets) CIDs.
        // Keep most recent 100 as evidence trail; older CIDs are in RangeWindows anyway.
        if let Some(cid) = source_cid {
            node.source_cids.push(cid);
            if node.source_cids.len() > 100 {
                let drain_count = node.source_cids.len() - 100;
                node.source_cids.drain(..drain_count);
            }
        }

        // Update window → entity index
        self.window_entity_index
            .entry(window_sn)
            .or_default()
            .insert(entity_id.to_string());
    }

    /// Add or update a relationship edge
    pub fn upsert_edge(
        &mut self,
        from: &str,
        to: &str,
        relation: &str,
        weight: f64,
        timestamp: i64,
        window_sn: u64,
        evidence_cid: Option<Cid>,
    ) {
        let edges = self.edges.entry(from.to_string()).or_default();

        // Find existing edge with same (to, relation)
        if let Some(edge) = edges.iter_mut().find(|e| e.to == to && e.relation == relation) {
            edge.weight = (edge.weight + weight) / 2.0; // Running average
            edge.last_confirmed = edge.last_confirmed.max(timestamp);
            if !edge.window_sns.contains(&window_sn) {
                edge.window_sns.push(window_sn);
            }
            if let Some(cid) = evidence_cid {
                edge.evidence_cids.push(cid);
                // D7 FIX: Cap evidence_cids on edges too
                if edge.evidence_cids.len() > 100 {
                    let drain_count = edge.evidence_cids.len() - 100;
                    edge.evidence_cids.drain(..drain_count);
                }
            }
        } else {
            let edge = KnotEdge {
                from: from.to_string(),
                to: to.to_string(),
                relation: relation.to_string(),
                weight,
                created_at: timestamp,
                last_confirmed: timestamp,
                active: true,
                evidence_cids: evidence_cid.into_iter().collect(),
                window_sns: vec![window_sn],
            };
            edges.push(edge);

            // Reverse index
            self.reverse_edges
                .entry(to.to_string())
                .or_default()
                .push((from.to_string(), relation.to_string()));
        }
    }

    /// Ingest entities and co-occurrence edges from a set of MemPackets.
    ///
    /// § 10.11 K_vn trigger: after every successful ingest, `last_ingest_sn` is
    /// bumped and `k_vn_dirty` is set to `true`. The consolidation loop
    /// (`ConsolidationEngine::tick`) reads the dirty flag and recomputes
    /// `VnGraphEntropy::compute(knot)` → stores result in `AgentExpertiseRecord::k_vn`.
    pub fn ingest_packets(&mut self, packets: &[MemPacket], window_sn: u64) {
        if packets.is_empty() {
            return;
        }

        for packet in packets {
            let ts = packet.index.ts;
            let cid = packet.index.packet_cid.clone();

            // Upsert entity nodes
            for entity_id in &packet.content.entities {
                let attrs = if let Some(obj) = packet.content.payload.as_object() {
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                } else {
                    BTreeMap::new()
                };

                self.upsert_node(
                    entity_id,
                    None,
                    attrs,
                    &packet.content.tags,
                    ts,
                    window_sn,
                    Some(cid.clone()),
                );
            }

            // Create co-occurrence edges between entities in the same packet
            let entities = &packet.content.entities;
            for i in 0..entities.len() {
                for j in (i + 1)..entities.len() {
                    self.upsert_edge(
                        &entities[i],
                        &entities[j],
                        "co_occurs",
                        1.0,
                        ts,
                        window_sn,
                        Some(cid.clone()),
                    );
                }
            }
        }

        // § 10.11: Mark the graph dirty so the consolidation loop recomputes K_vn.
        self.last_ingest_sn = window_sn;
        self.k_vn_dirty = true;
    }

    // =========================================================================
    // Read accessors
    // =========================================================================

    /// Get a node by entity ID
    pub fn get_node(&self, entity_id: &str) -> Option<&KnotNode> {
        self.nodes.get(entity_id)
    }

    /// Get all nodes
    pub fn nodes(&self) -> &HashMap<String, KnotNode> {
        &self.nodes
    }

    /// Get edges from an entity
    pub fn edges_from(&self, entity_id: &str) -> Vec<&KnotEdge> {
        self.edges
            .get(entity_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get edges to an entity (reverse lookup)
    pub fn edges_to(&self, entity_id: &str) -> Vec<&KnotEdge> {
        self.reverse_edges
            .get(entity_id)
            .map(|refs| {
                refs.iter()
                    .filter_map(|(from, rel)| {
                        self.edges.get(from).and_then(|edges| {
                            edges.iter().find(|e| e.to == entity_id && e.relation == *rel)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all neighbors of an entity (1-hop)
    pub fn neighbors(&self, entity_id: &str) -> Vec<&str> {
        let mut result: HashSet<&str> = HashSet::new();

        if let Some(edges) = self.edges.get(entity_id) {
            for e in edges {
                result.insert(&e.to);
            }
        }

        if let Some(refs) = self.reverse_edges.get(entity_id) {
            for (from, _) in refs {
                result.insert(from);
            }
        }

        result.into_iter().collect()
    }

    /// Get entities in a specific window
    pub fn entities_in_window(&self, sn: u64) -> Vec<&str> {
        self.window_entity_index
            .get(&sn)
            .map(|set| set.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Total node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total edge count
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// All directed edges (for dashboards / `GET /memory/graph/entities`).
    pub fn all_edges(&self) -> Vec<&KnotEdge> {
        self.edges.values().flat_map(|v| v.iter()).collect()
    }

    // =========================================================================
    // 4-way retrieval
    // =========================================================================

    /// Temporal retrieval: find entities active in a time range
    fn retrieve_temporal(&self, from_ms: i64, to_ms: i64) -> Vec<RetrievalHit> {
        let mut hits = Vec::new();

        for (id, node) in &self.nodes {
            if node.last_seen >= from_ms && node.first_seen <= to_ms {
                // Score by recency (more recent = higher score)
                let recency_score = (node.last_seen - from_ms) as f64
                    / (to_ms - from_ms + 1) as f64;

                hits.push(RetrievalHit {
                    id: id.clone(),
                    score: recency_score.min(1.0),
                    channel: RetrievalChannel::Temporal,
                    window_sns: node.window_sns.clone(),
                    packet_cids: node.source_cids.clone(),
                });
            }
        }

        // Sort by score descending
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits
    }

    /// Graph retrieval: find entities connected to query entities (1-2 hop)
    fn retrieve_graph(&self, query_entities: &[String]) -> Vec<RetrievalHit> {
        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut window_map: HashMap<String, Vec<u64>> = HashMap::new();
        let mut cid_map: HashMap<String, Vec<Cid>> = HashMap::new();

        for entity in query_entities {
            // Direct match (score = 1.0)
            if let Some(node) = self.nodes.get(entity) {
                *scores.entry(entity.clone()).or_default() += 1.0;
                window_map.entry(entity.clone()).or_default().extend(node.window_sns.iter());
                cid_map.entry(entity.clone()).or_default().extend(node.source_cids.iter().cloned());
            }

            // 1-hop neighbors (score = edge weight * 0.5)
            if let Some(edges) = self.edges.get(entity) {
                for edge in edges {
                    *scores.entry(edge.to.clone()).or_default() += edge.weight * 0.5;
                    window_map.entry(edge.to.clone()).or_default().extend(edge.window_sns.iter());
                    cid_map.entry(edge.to.clone()).or_default().extend(edge.evidence_cids.iter().cloned());
                }
            }

            // Reverse 1-hop
            if let Some(refs) = self.reverse_edges.get(entity) {
                for (from, _rel) in refs {
                    if let Some(node) = self.nodes.get(from) {
                        *scores.entry(from.clone()).or_default() += 0.5;
                        window_map.entry(from.clone()).or_default().extend(node.window_sns.iter());
                        cid_map.entry(from.clone()).or_default().extend(node.source_cids.iter().cloned());
                    }
                }
            }
        }

        let mut hits: Vec<RetrievalHit> = scores
            .into_iter()
            .map(|(id, score)| RetrievalHit {
                id: id.clone(),
                score,
                channel: RetrievalChannel::Graph,
                window_sns: window_map.remove(&id).unwrap_or_default(),
                packet_cids: cid_map.remove(&id).unwrap_or_default(),
            })
            .collect();

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits
    }

    /// Keyword retrieval: find entities matching tags or entity ID substrings
    fn retrieve_keyword(&self, keywords: &[String]) -> Vec<RetrievalHit> {
        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut window_map: HashMap<String, Vec<u64>> = HashMap::new();
        let mut cid_map: HashMap<String, Vec<Cid>> = HashMap::new();

        for keyword in keywords {
            let kw_lower = keyword.to_lowercase();

            // Search tag index
            if let Some(entity_ids) = self.tag_index.get(keyword) {
                for eid in entity_ids {
                    *scores.entry(eid.clone()).or_default() += 1.0;
                    if let Some(node) = self.nodes.get(eid) {
                        window_map.entry(eid.clone()).or_default().extend(node.window_sns.iter());
                        cid_map.entry(eid.clone()).or_default().extend(node.source_cids.iter().cloned());
                    }
                }
            }

            // Search entity IDs by substring
            for (eid, node) in &self.nodes {
                if eid.to_lowercase().contains(&kw_lower) {
                    *scores.entry(eid.clone()).or_default() += 0.8;
                    window_map.entry(eid.clone()).or_default().extend(node.window_sns.iter());
                    cid_map.entry(eid.clone()).or_default().extend(node.source_cids.iter().cloned());
                }

                // Search attribute values
                for (_k, v) in &node.attributes {
                    if let Some(s) = v.as_str() {
                        if s.to_lowercase().contains(&kw_lower) {
                            *scores.entry(eid.clone()).or_default() += 0.6;
                            window_map.entry(eid.clone()).or_default().extend(node.window_sns.iter());
                            break;
                        }
                    }
                }
            }
        }

        let mut hits: Vec<RetrievalHit> = scores
            .into_iter()
            .map(|(id, score)| RetrievalHit {
                id: id.clone(),
                score,
                channel: RetrievalChannel::Keyword,
                window_sns: window_map.remove(&id).unwrap_or_default(),
                packet_cids: cid_map.remove(&id).unwrap_or_default(),
            })
            .collect();

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits
    }

    // =========================================================================
    // RRF Fusion
    // =========================================================================

    /// Reciprocal Rank Fusion: combine results from multiple retrieval channels.
    ///
    /// RRF(d) = Σ 1 / (k + rank_i(d)) for each channel i
    ///
    /// Where k is a constant (default 60) that dampens the effect of high ranks.
    pub fn fuse_rrf(
        channel_results: &[Vec<RetrievalHit>],
        k: f64,
        limit: usize,
    ) -> Vec<FusedResult> {
        let mut fused: HashMap<String, FusedResult> = HashMap::new();

        for hits in channel_results {
            for (rank, hit) in hits.iter().enumerate() {
                let rrf_contribution = 1.0 / (k + rank as f64 + 1.0);

                let entry = fused.entry(hit.id.clone()).or_insert_with(|| FusedResult {
                    id: hit.id.clone(),
                    rrf_score: 0.0,
                    channels: Vec::new(),
                    channel_scores: HashMap::new(),
                    window_sns: Vec::new(),
                    packet_cids: Vec::new(),
                });

                entry.rrf_score += rrf_contribution;

                if !entry.channels.contains(&hit.channel) {
                    entry.channels.push(hit.channel.clone());
                }
                entry.channel_scores.insert(hit.channel.clone(), hit.score);

                // Merge window_sns (dedup)
                for sn in &hit.window_sns {
                    if !entry.window_sns.contains(sn) {
                        entry.window_sns.push(*sn);
                    }
                }

                // Merge packet_cids (dedup by string repr for simplicity)
                for cid in &hit.packet_cids {
                    if !entry.packet_cids.iter().any(|c| c == cid) {
                        entry.packet_cids.push(cid.clone());
                    }
                }
            }
        }

        let mut results: Vec<FusedResult> = fused.into_values().collect();
        results.sort_by(|a, b| b.rrf_score.partial_cmp(&a.rrf_score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        results
    }

    // =========================================================================
    // Combined query
    // =========================================================================

    /// Execute a multi-dimensional query with RRF fusion.
    ///
    /// Runs all applicable retrieval channels in parallel (conceptually),
    /// then fuses results with RRF.
    pub fn query(&self, q: &KnotQuery) -> Vec<FusedResult> {
        let mut channel_results: Vec<Vec<RetrievalHit>> = Vec::new();

        // 1. Temporal retrieval
        if let Some((from, to)) = q.time_range {
            channel_results.push(self.retrieve_temporal(from, to));
        }

        // 2. Graph retrieval
        if !q.entities.is_empty() {
            channel_results.push(self.retrieve_graph(&q.entities));
        }

        // 3. Keyword retrieval
        if !q.keywords.is_empty() {
            channel_results.push(self.retrieve_keyword(&q.keywords));
        }

        // 4. Semantic retrieval (placeholder — would use vector store)
        // When a vector store is integrated, this would call:
        // channel_results.push(self.retrieve_semantic(&q.semantic_query));

        if channel_results.is_empty() {
            return Vec::new();
        }

        Self::fuse_rrf(&channel_results, q.rrf_k, q.limit)
    }
}

impl Default for KnotEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// § 11.12 ConsolidationEngine — K_vn recompute + episodic→semantic consolidation
// =============================================================================

/// Result of a single consolidation tick.
#[derive(Debug, Clone)]
pub struct ConsolidationTickResult {
    /// Whether K_vn was recomputed this tick
    pub k_vn_recomputed: bool,
    /// New K_vn value (if recomputed)
    pub k_vn: Option<f64>,
    /// Number of namespace records updated
    pub records_updated: usize,
    /// Nodes evicted from old windows (stale graph pruning)
    pub nodes_pruned: usize,
}

/// ConsolidationEngine drives incremental maintenance of the KnotEngine
/// and the per-namespace `AgentExpertiseRecord::k_vn` scores.
///
/// # Tick semantics
/// `tick()` is called periodically by the orchestrator (e.g., after every
/// batch of `ingest_packets` calls, or on a timer). It:
///
/// 1. Checks `KnotEngine::k_vn_dirty`. If dirty, computes Von Neumann graph
///    entropy K_vn = 1 - H_vn / log₂(n) over the current graph and writes
///    the result back to all active `AgentExpertiseRecord` entries.
///
/// 2. Prunes edges that belong only to windows older than `max_window_age`
///    serial numbers, evicting stale graph structure.
///
/// 3. Updates `AgentExpertiseRecord::kecs` by blending the new K_vn with the
///    cached S_renyi and K_topo components.
pub struct ConsolidationEngine {
    /// How many windows to retain before pruning old edges
    pub max_window_age: u64,
    /// KECS weight φ₁ applied to K_vn
    pub phi1: f64,
    /// KECS weight φ₂ applied to S_renyi
    pub phi2: f64,
    /// KECS weight φ₃ applied to K_topo
    pub phi3: f64,
}

impl ConsolidationEngine {
    pub fn new() -> Self {
        Self { max_window_age: 100, phi1: 0.40, phi2: 0.40, phi3: 0.20 }
    }

    pub fn with_window_age(mut self, age: u64) -> Self {
        self.max_window_age = age;
        self
    }

    /// Run one consolidation tick.
    ///
    /// # Arguments
    /// - `knot`    : the KnotEngine to inspect and potentially prune
    /// - `records` : mutable slice of AgentExpertiseRecord entries to update
    pub fn tick(
        &self,
        knot: &mut KnotEngine,
        records: &mut [crate::identity::AgentExpertiseRecord],
    ) -> ConsolidationTickResult {
        let mut result = ConsolidationTickResult {
            k_vn_recomputed: false,
            k_vn: None,
            records_updated: 0,
            nodes_pruned: 0,
        };

        // Step 1: Recompute K_vn if the graph is dirty
        if knot.k_vn_dirty {
            let k_vn = Self::compute_k_vn(knot);
            result.k_vn_recomputed = true;
            result.k_vn = Some(k_vn);

            // Write K_vn back into all expertise records
            for rec in records.iter_mut() {
                rec.k_vn = k_vn;
                // Recompute composite KECS score with new K_vn
                rec.kecs = (self.phi1 * rec.k_vn
                    + self.phi2 * rec.s_renyi
                    + self.phi3 * rec.k_topo)
                    .clamp(0.0, 1.0);
                result.records_updated += 1;
            }

            // Clear dirty flag
            knot.k_vn_dirty = false;
        }

        // Step 2: Prune stale graph windows
        let current_sn = knot.last_ingest_sn;
        if current_sn >= self.max_window_age {
            let cutoff_sn = current_sn - self.max_window_age;
            result.nodes_pruned = Self::prune_stale_windows(knot, cutoff_sn);
        }

        result
    }

    /// Compute K_vn = 1 - H_vn / log₂(n) from the KnotEngine graph.
    ///
    /// Uses the O(|E|) quadratic VNGE approximation (Chen et al. ICML 2019).
    fn compute_k_vn(knot: &KnotEngine) -> f64 {
        let n = knot.node_count();
        if n < 2 {
            return 0.0;
        }

        let mut total_degree = 0.0_f64;
        let mut edge_sum_sq = 0.0_f64;

        for (from_node, _) in knot.nodes() {
            let out_edges = knot.edges_from(from_node);
            let out_w: f64 = out_edges.iter().map(|e| e.weight).sum();
            total_degree += out_w;
            for e in &out_edges {
                edge_sum_sq += e.weight * e.weight;
            }
        }
        for (node_id, _) in knot.nodes() {
            let in_w: f64 = knot.edges_to(node_id).iter().map(|e| e.weight).sum();
            total_degree += in_w;
        }

        if total_degree <= 0.0 {
            return 0.0;
        }

        let tr_l = n as f64;
        let avg_degree = total_degree / n as f64;
        let tr_l2 = (n as f64) + 2.0 * edge_sum_sq / (avg_degree * avg_degree).max(1e-10);
        let frobenius_sq = tr_l2 - (tr_l * tr_l) / (n as f64);
        let log2_n = (n as f64).log2();
        let h_vn = (log2_n - (n as f64 / (2.0 * tr_l2.max(1e-10))) * frobenius_sq)
            .max(0.0)
            .min(log2_n);

        (1.0 - h_vn / log2_n.max(1e-10)).clamp(0.0, 1.0)
    }

    /// Remove nodes that have no window serial numbers newer than `cutoff_sn`.
    ///
    /// A node is "stale" if all of its `window_sns` are ≤ cutoff_sn AND it has
    /// zero recent mention count (i.e., it hasn't appeared in recent windows).
    /// Stale nodes and their associated edges are pruned to bound memory growth.
    fn prune_stale_windows(knot: &mut KnotEngine, cutoff_sn: u64) -> usize {
        let stale_ids: Vec<String> = knot.nodes
            .iter()
            .filter(|(_, node)| {
                // Only prune if ALL window SNs are below the cutoff
                !node.window_sns.is_empty()
                    && node.window_sns.iter().all(|&sn| sn <= cutoff_sn)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let pruned = stale_ids.len();
        for id in &stale_ids {
            knot.nodes.remove(id);
            knot.edges.remove(id);

            // Clean up reverse edges pointing to this node
            for refs in knot.reverse_edges.values_mut() {
                refs.retain(|(from, _)| !stale_ids.contains(from));
            }
            knot.reverse_edges.remove(id);

            // Clean up tag index
            for entity_set in knot.tag_index.values_mut() {
                entity_set.remove(id.as_str());
            }

            // Clean up window entity index
            for entity_set in knot.window_entity_index.values_mut() {
                entity_set.remove(id.as_str());
            }
        }

        pruned
    }
}

impl Default for ConsolidationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// § 12 EntityCategory — typed entity classification for multimodal knowledge
// =============================================================================

/// Typed entity classification supporting multimodal knowledge.
///
/// Every node in the knowledge graph has an `EntityCategory` that determines
/// how it is indexed, merged, and retrieved. This taxonomy extends beyond
/// text entities to cover visual objects, audio sources, sensor readings,
/// ML artifacts, and embodied-agent concepts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityCategory {
    // ── Classical Knowledge ──
    Person,
    Organization,
    Location,
    Concept,
    Event,
    Artifact,
    Temporal,

    // ── Multimodal Perception ──
    VisualObject,
    Scene,
    Face,
    Gesture,
    AudioSource,
    Speaker,
    SoundEvent,

    // ── Sensor / Spatial ──
    SensorSource,
    Waypoint,
    Obstacle,
    Region,
    Measurement,

    // ── ML / Neural Network ──
    Model,
    Dataset,
    Experiment,
    Feature,
    Label,
    Metric,

    // ── Robotics / Embodied ──
    Actuator,
    MotorState,
    PlanStep,
    Goal,
    Reward,

    /// Escape hatch for domain-specific entity types.
    Custom(String),
}

impl Default for EntityCategory {
    fn default() -> Self {
        Self::Concept
    }
}

// =============================================================================
// § 13 KnowledgeInjection — typed knowledge operations
// =============================================================================

/// A single typed knowledge injection into the graph.
///
/// These are the "write operations" produced by the `InjectionClassifier`
/// when it processes committed `MemoryEvent`s from the log. Each injection
/// is atomic: it either succeeds entirely or is rejected.
///
/// Design reference: Graphiti episode → fact extraction, Zep bi-temporal
/// knowledge updates, Google Knowledge Vault confidence scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum KnowledgeInjection {
    /// Assert a factual attribute on an entity.
    /// Overwrites previous value if present; records confidence + evidence.
    AssertFact {
        entity_id: String,
        category: EntityCategory,
        attribute: String,
        value: serde_json::Value,
        confidence: f64,
        source_event_id: String,
    },

    /// Assert a directional relationship between two entities.
    AssertRelation {
        from_entity: String,
        to_entity: String,
        relation: String,
        weight: f64,
        bidirectional: bool,
        source_event_id: String,
    },

    /// Record a raw observation on an entity (unstructured, append-only).
    /// Used for sensor readings, perception outputs, agent observations.
    Observe {
        entity_id: String,
        category: EntityCategory,
        observation: serde_json::Value,
        modality: String,
        source_event_id: String,
    },

    /// Assert a hypothesis with confidence < 1.0 (tentative knowledge).
    Hypothesize {
        entity_id: String,
        attribute: String,
        value: serde_json::Value,
        confidence: f64,
        reasoning: String,
        source_event_id: String,
    },

    /// Correct a previously asserted fact (records provenance of the correction).
    Correct {
        entity_id: String,
        attribute: String,
        old_value: serde_json::Value,
        new_value: serde_json::Value,
        reason: String,
        source_event_id: String,
    },

    /// Retract a fact or relationship (soft-delete with reason).
    Retract {
        entity_id: String,
        attribute: Option<String>,
        relation: Option<String>,
        reason: String,
        source_event_id: String,
    },

    /// Link an entity to a multimodal object reference (image, audio, model, etc.).
    LinkModality {
        entity_id: String,
        modality: String,
        object_ref: String,
        content_type: String,
        source_event_id: String,
    },

    /// Tag an entity with searchable labels.
    Tag {
        entity_id: String,
        tags: Vec<String>,
        source_event_id: String,
    },
}

// =============================================================================
// § 14 KnowledgeChangeEntry — CDC for the knowledge graph
// =============================================================================

/// A change-data-capture entry recording a mutation to the knowledge graph.
///
/// Downstream consumers (vector index, continuity fabric, external systems)
/// subscribe to these changes to maintain derived views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeChangeEntry {
    pub change_id: u64,
    pub timestamp: i64,
    pub change_type: KnowledgeChangeType,
    pub entity_id: String,
    pub details: serde_json::Value,
    pub source_event_id: String,
}

/// Type of change to the knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeChangeType {
    NodeCreated,
    NodeUpdated,
    NodeRetracted,
    NodePruned,
    EdgeCreated,
    EdgeUpdated,
    EdgeRetracted,
    ModalityLinked,
    TagsUpdated,
}

/// Append-only change log for CDC on the knowledge graph.
#[derive(Debug, Default)]
pub struct KnowledgeChangeLog {
    entries: Vec<KnowledgeChangeEntry>,
    next_id: u64,
}

impl KnowledgeChangeLog {
    pub fn new() -> Self {
        Self { entries: Vec::new(), next_id: 0 }
    }

    fn record(
        &mut self,
        change_type: KnowledgeChangeType,
        entity_id: &str,
        details: serde_json::Value,
        source_event_id: &str,
    ) {
        let entry = KnowledgeChangeEntry {
            change_id: self.next_id,
            timestamp: crate::fabric::types::now_ms(),
            change_type,
            entity_id: entity_id.to_string(),
            details,
            source_event_id: source_event_id.to_string(),
        };
        self.next_id += 1;
        self.entries.push(entry);
    }

    /// Read CDC entries from a given offset.
    pub fn read_from(&self, from_id: u64, limit: usize) -> &[KnowledgeChangeEntry] {
        let start = from_id as usize;
        if start >= self.entries.len() {
            return &[];
        }
        let end = (start + limit).min(self.entries.len());
        &self.entries[start..end]
    }

    /// Current high watermark.
    pub fn watermark(&self) -> u64 {
        self.next_id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// § 15 InjectionClassifier — maps MemoryEvent → KnowledgeInjection(s)
// =============================================================================

/// Classifies committed `MemoryEvent`s into typed `KnowledgeInjection`s.
///
/// This is the "brain" that decides what knowledge to extract from each event.
/// Different `EventType`s produce different injection patterns:
///
/// | EventType | Injections Produced |
/// |-----------|-------------------|
/// | InteractionCreated | AssertFact (entities), AssertRelation (co-occurrence) |
/// | ImageCaptured | Observe (visual), LinkModality |
/// | SensorReadingRecorded | Observe (measurement), AssertFact (state) |
/// | ModelCheckpointSaved | AssertFact (model metadata), LinkModality |
/// | PerceptionOutputProduced | AssertFact + AssertRelation (detected objects) |
/// | InferenceResultProduced | AssertFact (prediction), Hypothesize |
pub struct InjectionClassifier;

impl InjectionClassifier {
    /// Classify a committed MemoryEvent into zero or more KnowledgeInjections.
    pub fn classify(event: &crate::fabric::types::MemoryEvent) -> Vec<KnowledgeInjection> {
        use crate::fabric::types::EventType;
        let eid = &event.event_id;
        let payload = &event.payload;

        match event.event_type {
            // ── Text / Interaction Events ──
            EventType::InteractionCreated
            | EventType::ToolOutputProduced
            | EventType::SummaryEmitted => {
                Self::classify_text_event(event)
            }

            // ── File / Document ──
            EventType::FileUploaded
            | EventType::ChunkExtractionDone => {
                let mut inj = Self::classify_text_event(event);
                if let Some(obj) = &payload.object_ref {
                    inj.push(KnowledgeInjection::LinkModality {
                        entity_id: event.container_id.clone(),
                        modality: "document".to_string(),
                        object_ref: obj.clone(),
                        content_type: payload.content_type.clone(),
                        source_event_id: eid.clone(),
                    });
                }
                inj
            }

            // ── Image / Visual ──
            EventType::ImageCaptured => {
                let mut inj = Vec::new();
                inj.push(KnowledgeInjection::Observe {
                    entity_id: format!("image:{}", eid),
                    category: EntityCategory::VisualObject,
                    observation: serde_json::json!({
                        "container": event.container_id,
                        "timestamp": event.timestamp,
                    }),
                    modality: "image".to_string(),
                    source_event_id: eid.clone(),
                });
                if let Some(obj) = &payload.object_ref {
                    inj.push(KnowledgeInjection::LinkModality {
                        entity_id: format!("image:{}", eid),
                        modality: "image".to_string(),
                        object_ref: obj.clone(),
                        content_type: payload.content_type.clone(),
                        source_event_id: eid.clone(),
                    });
                }
                inj
            }

            // ── Audio ──
            EventType::AudioSegmentIngested => {
                let mut inj = Vec::new();
                inj.push(KnowledgeInjection::Observe {
                    entity_id: format!("audio:{}", eid),
                    category: EntityCategory::AudioSource,
                    observation: serde_json::json!({
                        "container": event.container_id,
                        "timestamp": event.timestamp,
                        "duration_ms": payload.duration_ms,
                    }),
                    modality: "audio".to_string(),
                    source_event_id: eid.clone(),
                });
                inj
            }

            // ── Video ──
            EventType::VideoFrameIngested => {
                vec![KnowledgeInjection::Observe {
                    entity_id: format!("video:{}", eid),
                    category: EntityCategory::Scene,
                    observation: serde_json::json!({
                        "container": event.container_id,
                        "timestamp": event.timestamp,
                    }),
                    modality: "video".to_string(),
                    source_event_id: eid.clone(),
                }]
            }

            // ── Sensor ──
            EventType::SensorReadingRecorded => {
                let mut inj = Vec::new();
                let sensor_id = event.partition_key.clone();
                inj.push(KnowledgeInjection::Observe {
                    entity_id: sensor_id.clone(),
                    category: EntityCategory::SensorSource,
                    observation: serde_json::json!({
                        "timestamp": event.timestamp,
                        "channels": payload.channels,
                        "sample_rate_hz": payload.sample_rate_hz,
                    }),
                    modality: "sensor".to_string(),
                    source_event_id: eid.clone(),
                });
                inj.push(KnowledgeInjection::AssertFact {
                    entity_id: sensor_id,
                    category: EntityCategory::SensorSource,
                    attribute: "last_reading_at".to_string(),
                    value: serde_json::json!(event.timestamp),
                    confidence: 1.0,
                    source_event_id: eid.clone(),
                });
                inj
            }

            // ── Model Checkpoint ──
            EventType::ModelCheckpointSaved => {
                let mut inj = Vec::new();
                let model_id = event.partition_key.clone();
                inj.push(KnowledgeInjection::AssertFact {
                    entity_id: model_id.clone(),
                    category: EntityCategory::Model,
                    attribute: "last_checkpoint_at".to_string(),
                    value: serde_json::json!(event.timestamp),
                    confidence: 1.0,
                    source_event_id: eid.clone(),
                });
                if let Some(obj) = &payload.object_ref {
                    inj.push(KnowledgeInjection::LinkModality {
                        entity_id: model_id,
                        modality: "model_weights".to_string(),
                        object_ref: obj.clone(),
                        content_type: payload.content_type.clone(),
                        source_event_id: eid.clone(),
                    });
                }
                inj
            }

            // ── Inference ──
            EventType::InferenceResultProduced => {
                vec![KnowledgeInjection::Hypothesize {
                    entity_id: event.partition_key.clone(),
                    attribute: "inference_result".to_string(),
                    value: payload.inline_payload.clone().unwrap_or(serde_json::Value::Null),
                    confidence: 0.8,
                    reasoning: "ML inference output".to_string(),
                    source_event_id: eid.clone(),
                }]
            }

            // ── Perception Pipeline ──
            EventType::PerceptionOutputProduced => {
                Self::classify_perception_event(event)
            }

            // ── Actuation ──
            EventType::ActuationCommandIssued => {
                let actuator_id = event.partition_key.clone();
                vec![KnowledgeInjection::Observe {
                    entity_id: actuator_id,
                    category: EntityCategory::Actuator,
                    observation: serde_json::json!({
                        "timestamp": event.timestamp,
                        "command": payload.inline_payload,
                    }),
                    modality: "actuation".to_string(),
                    source_event_id: eid.clone(),
                }]
            }

            // ── Default: extract what we can from metadata ──
            _ => Self::classify_generic_event(event),
        }
    }

    /// Extract entity mentions + co-occurrence from text-bearing events.
    fn classify_text_event(event: &crate::fabric::types::MemoryEvent) -> Vec<KnowledgeInjection> {
        let eid = &event.event_id;
        let mut inj = Vec::new();

        // Extract entities from inline payload if it contains structured data
        if let Some(inline) = &event.payload.inline_payload {
            if let Some(obj) = inline.as_object() {
                // Look for entities array in payload
                if let Some(entities) = obj.get("entities").and_then(|e| e.as_array()) {
                    let entity_ids: Vec<String> = entities.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();

                    for entity_id in &entity_ids {
                        inj.push(KnowledgeInjection::AssertFact {
                            entity_id: entity_id.clone(),
                            category: EntityCategory::Concept,
                            attribute: "mentioned_in".to_string(),
                            value: serde_json::json!(event.container_id),
                            confidence: 1.0,
                            source_event_id: eid.clone(),
                        });
                    }

                    // Co-occurrence relations
                    for i in 0..entity_ids.len() {
                        for j in (i + 1)..entity_ids.len() {
                            inj.push(KnowledgeInjection::AssertRelation {
                                from_entity: entity_ids[i].clone(),
                                to_entity: entity_ids[j].clone(),
                                relation: "co_occurs".to_string(),
                                weight: 1.0,
                                bidirectional: true,
                                source_event_id: eid.clone(),
                            });
                        }
                    }
                }

                // Look for tags
                if let Some(tags) = obj.get("tags").and_then(|t| t.as_array()) {
                    let tag_strs: Vec<String> = tags.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    if !tag_strs.is_empty() {
                        inj.push(KnowledgeInjection::Tag {
                            entity_id: event.container_id.clone(),
                            tags: tag_strs,
                            source_event_id: eid.clone(),
                        });
                    }
                }
            }
        }

        inj
    }

    /// Extract perception knowledge (detected objects, spatial relations).
    fn classify_perception_event(event: &crate::fabric::types::MemoryEvent) -> Vec<KnowledgeInjection> {
        let eid = &event.event_id;
        let mut inj = Vec::new();

        // The perception pipeline output typically contains detected objects
        if let Some(inline) = &event.payload.inline_payload {
            if let Some(obj) = inline.as_object() {
                if let Some(detections) = obj.get("detections").and_then(|d| d.as_array()) {
                    for det in detections {
                        if let Some(label) = det.get("label").and_then(|l| l.as_str()) {
                            let det_id = format!("detected:{}:{}", label, eid);
                            inj.push(KnowledgeInjection::AssertFact {
                                entity_id: det_id.clone(),
                                category: EntityCategory::VisualObject,
                                attribute: "label".to_string(),
                                value: serde_json::json!(label),
                                confidence: det.get("confidence")
                                    .and_then(|c| c.as_f64())
                                    .unwrap_or(0.5),
                                source_event_id: eid.clone(),
                            });

                            // Link detection to its container/scene
                            inj.push(KnowledgeInjection::AssertRelation {
                                from_entity: det_id,
                                to_entity: event.container_id.clone(),
                                relation: "detected_in".to_string(),
                                weight: 1.0,
                                bidirectional: false,
                                source_event_id: eid.clone(),
                            });
                        }
                    }
                }
            }
        }

        inj
    }

    /// Fallback: extract minimal knowledge from any event type.
    fn classify_generic_event(event: &crate::fabric::types::MemoryEvent) -> Vec<KnowledgeInjection> {
        vec![KnowledgeInjection::Observe {
            entity_id: event.partition_key.clone(),
            category: EntityCategory::default(),
            observation: serde_json::json!({
                "event_type": format!("{:?}", event.event_type),
                "timestamp": event.timestamp,
                "container": event.container_id,
            }),
            modality: "generic".to_string(),
            source_event_id: event.event_id.clone(),
        }]
    }
}

// =============================================================================
// § 16 KnowledgeMaterializer — Kafka-grade commit-log consumer for knowledge
// =============================================================================

/// A Kafka-grade knowledge materializer that consumes committed `MemoryEvent`s
/// from the `CommitLog`, classifies them into `KnowledgeInjection`s, applies
/// them to the `KnotEngine`, and tracks its consumer offset via `MaterializerGroup`.
///
/// This bridges the gap between the fabric commit log and the knowledge graph:
///
/// ```text
/// CommitLog ──poll──→ KnowledgeMaterializer ──classify──→ KnowledgeInjection(s)
///                                            ──apply────→ KnotEngine (graph mutation)
///                                            ──record───→ KnowledgeChangeLog (CDC)
///                                            ──commit───→ MaterializerGroup (offset)
/// ```
///
/// On crash recovery: load `GraphSnapshot` → resume from last committed offset.
pub struct KnowledgeMaterializer {
    /// Consumer group for offset tracking.
    pub group: crate::fabric::commit_log::MaterializerGroup,
    /// Stream name this materializer is bound to.
    pub stream: String,
    /// CDC log recording all graph mutations.
    pub change_log: KnowledgeChangeLog,
    /// Batch size for polling events.
    pub poll_batch_size: usize,
    /// Total events processed since start/restore.
    pub events_processed: u64,
    /// Total injections applied since start/restore.
    pub injections_applied: u64,
}

impl KnowledgeMaterializer {
    pub fn new(group_id: &str, stream: &str) -> Self {
        Self {
            group: crate::fabric::commit_log::MaterializerGroup::new(
                group_id.to_string(),
                crate::fabric::types::MaterializerType::Knowledge,
            ),
            stream: stream.to_string(),
            change_log: KnowledgeChangeLog::new(),
            poll_batch_size: 100,
            events_processed: 0,
            injections_applied: 0,
        }
    }

    /// Poll new events from the commit log, classify them, apply to KnotEngine.
    ///
    /// Returns `(events_consumed, injections_applied)`.
    pub fn poll_and_apply(
        &mut self,
        log: &crate::fabric::commit_log::CommitLog,
        knot: &mut KnotEngine,
    ) -> (u64, u64) {
        let mut total_events = 0u64;
        let mut total_injections = 0u64;

        for partition_id in 0..log.partition_count() {
            let offset = self.group.offset(&self.stream, partition_id);
            let events = log.read(partition_id, offset, self.poll_batch_size);

            if events.is_empty() {
                continue;
            }

            for event in events {
                // Classify event into knowledge injections
                let injections = InjectionClassifier::classify(event);

                // Apply each injection to the graph
                for injection in &injections {
                    self.apply_injection(knot, injection);
                    total_injections += 1;
                }

                total_events += 1;
            }

            // Commit offset: last consumed LSN + 1
            if let Some(last) = events.last() {
                self.group.commit(&self.stream, partition_id, last.lsn + 1);
            }
        }

        self.events_processed += total_events;
        self.injections_applied += total_injections;
        (total_events, total_injections)
    }

    /// Apply a single knowledge injection to the KnotEngine + record CDC.
    fn apply_injection(&mut self, knot: &mut KnotEngine, injection: &KnowledgeInjection) {
        match injection {
            KnowledgeInjection::AssertFact {
                entity_id, category, attribute, value, confidence, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                attrs.insert(attribute.clone(), value.clone());
                attrs.insert(format!("{}_confidence", attribute), serde_json::json!(confidence));

                let is_new = knot.get_node(entity_id).is_none();
                knot.upsert_node(
                    entity_id,
                    Some(&format!("{:?}", category)),
                    attrs,
                    &[],
                    ts,
                    knot.last_ingest_sn,
                    None,
                );

                self.change_log.record(
                    if is_new { KnowledgeChangeType::NodeCreated } else { KnowledgeChangeType::NodeUpdated },
                    entity_id,
                    serde_json::json!({ "attribute": attribute, "value": value }),
                    source_event_id,
                );
            }

            KnowledgeInjection::AssertRelation {
                from_entity, to_entity, relation, weight, bidirectional, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let sn = knot.last_ingest_sn;

                // Ensure both nodes exist
                if knot.get_node(from_entity).is_none() {
                    knot.upsert_node(from_entity, None, BTreeMap::new(), &[], ts, sn, None);
                }
                if knot.get_node(to_entity).is_none() {
                    knot.upsert_node(to_entity, None, BTreeMap::new(), &[], ts, sn, None);
                }

                knot.upsert_edge(from_entity, to_entity, relation, *weight, ts, sn, None);
                self.change_log.record(
                    KnowledgeChangeType::EdgeCreated,
                    from_entity,
                    serde_json::json!({ "to": to_entity, "relation": relation, "weight": weight }),
                    source_event_id,
                );

                if *bidirectional {
                    knot.upsert_edge(to_entity, from_entity, relation, *weight, ts, sn, None);
                }
            }

            KnowledgeInjection::Observe {
                entity_id, category, observation, modality, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                attrs.insert(format!("last_{}_observation", modality), observation.clone());

                let is_new = knot.get_node(entity_id).is_none();
                knot.upsert_node(
                    entity_id,
                    Some(&format!("{:?}", category)),
                    attrs,
                    &[],
                    ts,
                    knot.last_ingest_sn,
                    None,
                );

                self.change_log.record(
                    if is_new { KnowledgeChangeType::NodeCreated } else { KnowledgeChangeType::NodeUpdated },
                    entity_id,
                    serde_json::json!({ "modality": modality, "observation": observation }),
                    source_event_id,
                );
            }

            KnowledgeInjection::Hypothesize {
                entity_id, attribute, value, confidence, reasoning, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                attrs.insert(format!("hypothesis_{}", attribute), value.clone());
                attrs.insert(format!("hypothesis_{}_confidence", attribute), serde_json::json!(confidence));
                attrs.insert(format!("hypothesis_{}_reasoning", attribute), serde_json::json!(reasoning));

                knot.upsert_node(entity_id, None, attrs, &[], ts, knot.last_ingest_sn, None);

                self.change_log.record(
                    KnowledgeChangeType::NodeUpdated,
                    entity_id,
                    serde_json::json!({ "hypothesis": attribute, "confidence": confidence }),
                    source_event_id,
                );
            }

            KnowledgeInjection::Correct {
                entity_id, attribute, old_value, new_value, reason, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                attrs.insert(attribute.clone(), new_value.clone());
                attrs.insert(format!("{}_corrected_from", attribute), old_value.clone());
                attrs.insert(format!("{}_correction_reason", attribute), serde_json::json!(reason));

                knot.upsert_node(entity_id, None, attrs, &[], ts, knot.last_ingest_sn, None);

                self.change_log.record(
                    KnowledgeChangeType::NodeUpdated,
                    entity_id,
                    serde_json::json!({
                        "correction": attribute, "from": old_value, "to": new_value, "reason": reason,
                    }),
                    source_event_id,
                );
            }

            KnowledgeInjection::Retract {
                entity_id, attribute, relation, reason, source_event_id,
            } => {
                // Soft-retract: mark the entity/attribute as retracted
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                if let Some(attr) = attribute {
                    attrs.insert(format!("{}_retracted", attr), serde_json::json!(true));
                    attrs.insert(format!("{}_retracted_reason", attr), serde_json::json!(reason));
                }

                knot.upsert_node(entity_id, None, attrs, &[], ts, knot.last_ingest_sn, None);

                self.change_log.record(
                    if attribute.is_some() { KnowledgeChangeType::NodeRetracted }
                    else { KnowledgeChangeType::EdgeRetracted },
                    entity_id,
                    serde_json::json!({
                        "attribute": attribute, "relation": relation, "reason": reason,
                    }),
                    source_event_id,
                );
            }

            KnowledgeInjection::LinkModality {
                entity_id, modality, object_ref, content_type, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                let mut attrs = BTreeMap::new();
                attrs.insert(format!("modality_{}_ref", modality), serde_json::json!(object_ref));
                attrs.insert(format!("modality_{}_type", modality), serde_json::json!(content_type));

                knot.upsert_node(entity_id, None, attrs, &[], ts, knot.last_ingest_sn, None);

                self.change_log.record(
                    KnowledgeChangeType::ModalityLinked,
                    entity_id,
                    serde_json::json!({ "modality": modality, "object_ref": object_ref }),
                    source_event_id,
                );
            }

            KnowledgeInjection::Tag {
                entity_id, tags, source_event_id,
            } => {
                let ts = crate::fabric::types::now_ms();
                knot.upsert_node(entity_id, None, BTreeMap::new(), tags, ts, knot.last_ingest_sn, None);

                self.change_log.record(
                    KnowledgeChangeType::TagsUpdated,
                    entity_id,
                    serde_json::json!({ "tags": tags }),
                    source_event_id,
                );
            }
        }
    }

    /// Reset consumer offsets and CDC log (for full replay).
    pub fn reset(&mut self) {
        self.group.reset();
        self.change_log = KnowledgeChangeLog::new();
        self.events_processed = 0;
        self.injections_applied = 0;
    }

    /// Get the current consumer lag for a partition.
    pub fn lag(&self, log: &crate::fabric::commit_log::CommitLog, partition_id: u32) -> u64 {
        let watermark = log.watermark(partition_id).unwrap_or(0);
        let offset = self.group.offset(&self.stream, partition_id);
        if watermark >= offset { watermark - offset + 1 } else { 0 }
    }
}

// =============================================================================
// § 17 GraphSnapshot — serializable checkpoint for crash recovery
// =============================================================================

/// A serializable snapshot of the KnotEngine knowledge graph state,
/// paired with the commit-log offsets at snapshot time.
///
/// On crash recovery: deserialize snapshot → create KnotEngine → resume
/// KnowledgeMaterializer from the stored offsets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    /// Serialized graph nodes.
    pub nodes: HashMap<String, KnotNode>,
    /// Serialized graph edges.
    pub edges: HashMap<String, Vec<KnotEdge>>,
    /// Consumer offsets at snapshot time: (partition_id → lsn).
    pub offsets: HashMap<u32, u64>,
    /// Stream name.
    pub stream: String,
    /// Snapshot timestamp.
    pub timestamp: i64,
    /// Total events processed at snapshot time.
    pub events_processed: u64,
    /// CDC watermark at snapshot time.
    pub cdc_watermark: u64,
}

impl GraphSnapshot {
    /// Take a snapshot of the current KnotEngine + materializer state.
    pub fn capture(
        knot: &KnotEngine,
        materializer: &KnowledgeMaterializer,
        partition_count: u32,
    ) -> Self {
        let mut offsets = HashMap::new();
        for pid in 0..partition_count {
            offsets.insert(pid, materializer.group.offset(&materializer.stream, pid));
        }

        Self {
            nodes: knot.nodes().clone(),
            edges: knot.edges.clone(),
            offsets,
            stream: materializer.stream.clone(),
            timestamp: crate::fabric::types::now_ms(),
            events_processed: materializer.events_processed,
            cdc_watermark: materializer.change_log.watermark(),
        }
    }

    /// Restore a KnotEngine from this snapshot.
    pub fn restore_engine(&self) -> KnotEngine {
        let mut knot = KnotEngine::new();

        // Restore nodes
        for (id, node) in &self.nodes {
            knot.nodes.insert(id.clone(), node.clone());

            // Rebuild tag index
            for tag in &node.tags {
                knot.tag_index
                    .entry(tag.clone())
                    .or_default()
                    .insert(id.clone());
            }

            // Rebuild window entity index
            for &sn in &node.window_sns {
                knot.window_entity_index
                    .entry(sn)
                    .or_default()
                    .insert(id.clone());
            }
        }

        // Restore edges
        for (from, edge_list) in &self.edges {
            knot.edges.insert(from.clone(), edge_list.clone());

            // Rebuild reverse edges
            for edge in edge_list {
                knot.reverse_edges
                    .entry(edge.to.clone())
                    .or_default()
                    .push((from.clone(), edge.relation.clone()));
            }
        }

        knot
    }

    /// Restore a KnowledgeMaterializer from this snapshot (offsets only).
    pub fn restore_materializer(&self, group_id: &str) -> KnowledgeMaterializer {
        let mut mat = KnowledgeMaterializer::new(group_id, &self.stream);
        for (&pid, &lsn) in &self.offsets {
            mat.group.commit(&self.stream, pid, lsn);
        }
        mat.events_processed = self.events_processed;
        mat
    }

    /// Serialize snapshot to JSON bytes (for object fabric storage).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Snapshot serialize failed: {}", e))
    }

    /// Deserialize snapshot from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Snapshot deserialize failed: {}", e))
    }
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

    fn make_packet(entities: &[&str], tags: &[&str], payload: serde_json::Value, ts: i64) -> MemPacket {
        MemPacket::new(
            PacketType::Extraction,
            payload,
            Cid::default(),
            "subject:test".to_string(),
            "pipeline:test".to_string(),
            make_source(),
            ts,
        )
        .with_entities(entities.iter().map(|s| s.to_string()).collect())
        .with_tags(tags.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_upsert_node() {
        let mut engine = KnotEngine::new();

        engine.upsert_node(
            "alice",
            Some("person"),
            BTreeMap::from([("role".to_string(), serde_json::json!("admin"))]),
            &["staff".to_string()],
            1000,
            0,
            None,
        );

        assert_eq!(engine.node_count(), 1);
        let node = engine.get_node("alice").unwrap();
        assert_eq!(node.entity_type, Some("person".to_string()));
        assert_eq!(node.mention_count, 1);
        assert_eq!(node.attributes["role"], serde_json::json!("admin"));

        // Upsert again — should merge
        engine.upsert_node(
            "alice",
            None,
            BTreeMap::from([("email".to_string(), serde_json::json!("a@b.com"))]),
            &["admin".to_string()],
            2000,
            1,
            None,
        );

        let node = engine.get_node("alice").unwrap();
        assert_eq!(node.mention_count, 2);
        assert_eq!(node.last_seen, 2000);
        assert!(node.attributes.contains_key("role"));
        assert!(node.attributes.contains_key("email"));
        assert_eq!(node.tags.len(), 2);
        assert_eq!(node.window_sns, vec![0, 1]);
    }

    #[test]
    fn test_upsert_edge() {
        let mut engine = KnotEngine::new();

        engine.upsert_node("alice", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("bob", None, BTreeMap::new(), &[], 1000, 0, None);

        engine.upsert_edge("alice", "bob", "works_with", 1.0, 1000, 0, None);

        assert_eq!(engine.edge_count(), 1);
        let edges = engine.edges_from("alice");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].to, "bob");
        assert_eq!(edges[0].relation, "works_with");

        // Reverse lookup
        let rev = engine.edges_to("bob");
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].from, "alice");

        // Neighbors
        let neighbors = engine.neighbors("alice");
        assert_eq!(neighbors.len(), 1);
        assert!(neighbors.contains(&"bob"));
    }

    #[test]
    fn test_ingest_packets() {
        let mut engine = KnotEngine::new();

        let packets = vec![
            make_packet(&["alice", "bob"], &["team"], serde_json::json!({"project": "x"}), 1000),
            make_packet(&["alice", "charlie"], &["team"], serde_json::json!({"project": "y"}), 2000),
            make_packet(&["bob"], &["solo"], serde_json::json!({"task": "review"}), 3000),
        ];

        engine.ingest_packets(&packets, 0);

        assert_eq!(engine.node_count(), 3);
        assert_eq!(engine.get_node("alice").unwrap().mention_count, 2);
        assert_eq!(engine.get_node("bob").unwrap().mention_count, 2);
        assert_eq!(engine.get_node("charlie").unwrap().mention_count, 1);

        // Co-occurrence edges: alice-bob, alice-charlie
        assert!(engine.edge_count() >= 2);
    }

    #[test]
    fn test_retrieve_temporal() {
        let mut engine = KnotEngine::new();

        engine.upsert_node("alice", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("bob", None, BTreeMap::new(), &[], 3000, 1, None);
        engine.upsert_node("charlie", None, BTreeMap::new(), &[], 5000, 2, None);

        // Time range 0-2000: only alice
        let hits = engine.retrieve_temporal(0, 2000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "alice");

        // Time range 0-4000: alice and bob
        let hits = engine.retrieve_temporal(0, 4000);
        assert_eq!(hits.len(), 2);

        // Time range 0-6000: all three
        let hits = engine.retrieve_temporal(0, 6000);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn test_retrieve_graph() {
        let mut engine = KnotEngine::new();

        engine.upsert_node("alice", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("bob", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("charlie", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("dave", None, BTreeMap::new(), &[], 1000, 0, None);

        engine.upsert_edge("alice", "bob", "works_with", 1.0, 1000, 0, None);
        engine.upsert_edge("bob", "charlie", "manages", 0.8, 1000, 0, None);

        // Query for alice → should find alice (direct) + bob (1-hop)
        let hits = engine.retrieve_graph(&["alice".to_string()]);
        assert!(hits.iter().any(|h| h.id == "alice"));
        assert!(hits.iter().any(|h| h.id == "bob"));
        // dave should not appear (no connection)
        assert!(!hits.iter().any(|h| h.id == "dave"));
    }

    #[test]
    fn test_retrieve_keyword() {
        let mut engine = KnotEngine::new();

        engine.upsert_node(
            "patient:P-001",
            None,
            BTreeMap::from([("allergy".to_string(), serde_json::json!("penicillin"))]),
            &["allergy".to_string(), "medication".to_string()],
            1000,
            0,
            None,
        );
        engine.upsert_node(
            "patient:P-002",
            None,
            BTreeMap::from([("condition".to_string(), serde_json::json!("diabetes"))]),
            &["chronic".to_string()],
            1000,
            0,
            None,
        );

        // Search by tag
        let hits = engine.retrieve_keyword(&["allergy".to_string()]);
        assert!(hits.iter().any(|h| h.id == "patient:P-001"));

        // Search by attribute value
        let hits = engine.retrieve_keyword(&["penicillin".to_string()]);
        assert!(hits.iter().any(|h| h.id == "patient:P-001"));

        // Search by entity ID substring
        let hits = engine.retrieve_keyword(&["P-002".to_string()]);
        assert!(hits.iter().any(|h| h.id == "patient:P-002"));
    }

    #[test]
    fn test_rrf_fusion() {
        let temporal = vec![
            RetrievalHit { id: "alice".into(), score: 0.9, channel: RetrievalChannel::Temporal, window_sns: vec![0], packet_cids: vec![] },
            RetrievalHit { id: "bob".into(), score: 0.7, channel: RetrievalChannel::Temporal, window_sns: vec![0], packet_cids: vec![] },
        ];

        let graph = vec![
            RetrievalHit { id: "bob".into(), score: 1.0, channel: RetrievalChannel::Graph, window_sns: vec![0], packet_cids: vec![] },
            RetrievalHit { id: "charlie".into(), score: 0.5, channel: RetrievalChannel::Graph, window_sns: vec![1], packet_cids: vec![] },
        ];

        let keyword = vec![
            RetrievalHit { id: "alice".into(), score: 0.8, channel: RetrievalChannel::Keyword, window_sns: vec![0], packet_cids: vec![] },
        ];

        let fused = KnotEngine::fuse_rrf(&[temporal, graph, keyword], 60.0, 10);

        // bob appears in 2 channels → should have highest RRF score
        // alice appears in 2 channels
        // charlie appears in 1 channel
        assert!(fused.len() >= 3);

        // bob should be ranked high (appears in temporal rank 2 + graph rank 1)
        let bob = fused.iter().find(|r| r.id == "bob").unwrap();
        assert!(bob.channels.len() == 2);

        // alice appears in temporal rank 1 + keyword rank 1
        let alice = fused.iter().find(|r| r.id == "alice").unwrap();
        assert!(alice.channels.len() == 2);
    }

    #[test]
    fn test_combined_query() {
        let mut engine = KnotEngine::new();

        engine.upsert_node("alice", None, BTreeMap::new(), &["admin".to_string()], 1000, 0, None);
        engine.upsert_node("bob", None, BTreeMap::new(), &["user".to_string()], 2000, 0, None);
        engine.upsert_node("charlie", None, BTreeMap::new(), &["admin".to_string()], 3000, 1, None);
        engine.upsert_edge("alice", "bob", "manages", 1.0, 1000, 0, None);

        let results = engine.query(&KnotQuery {
            entities: vec!["alice".to_string()],
            keywords: vec!["admin".to_string()],
            time_range: Some((0, 4000)),
            limit: 10,
            ..Default::default()
        });

        // alice should rank highest (appears in all 3 channels)
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "alice");
        assert!(results[0].channels.len() >= 2);
    }

    #[test]
    fn test_entities_in_window() {
        let mut engine = KnotEngine::new();

        engine.upsert_node("alice", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("bob", None, BTreeMap::new(), &[], 1000, 0, None);
        engine.upsert_node("charlie", None, BTreeMap::new(), &[], 2000, 1, None);

        let w0 = engine.entities_in_window(0);
        assert_eq!(w0.len(), 2);

        let w1 = engine.entities_in_window(1);
        assert_eq!(w1.len(), 1);
        assert!(w1.contains(&"charlie"));
    }

    #[test]
    fn test_empty_query() {
        let engine = KnotEngine::new();
        let results = engine.query(&KnotQuery::default());
        assert!(results.is_empty());
    }

    // =========================================================================
    // § 12–17 Kafka-level Knowledge Injection Tests
    // =========================================================================

    use crate::fabric::types::*;
    use crate::fabric::commit_log::{CommitLog, CommitLogConfig};

    fn make_memory_event(
        container: &str,
        partition_key: &str,
        event_type: EventType,
        inline: Option<serde_json::Value>,
    ) -> MemoryEvent {
        MemoryEvent {
            event_id: generate_id("evt"),
            tenant_id: "tenant:test".to_string(),
            container_id: container.to_string(),
            trace_id: None,
            partition_key: partition_key.to_string(),
            event_type,
            memory_class: MemoryClass::Episodic,
            producer_id: "pid:001".to_string(),
            idempotency_key: generate_id("idem"),
            payload: {
                let mut pd = PayloadDescriptor::inline(
                    "application/json",
                    inline.unwrap_or(serde_json::json!({})),
                );
                pd.object_ref = Some("obj://test/data.bin".to_string());
                pd
            },
            policy: PolicySnapshot::default(),
            timestamp: now_ms(),
            lsn: 0,
        }
    }

    // ── EntityCategory tests ──

    #[test]
    fn test_entity_category_serde() {
        let cats = vec![
            EntityCategory::Person,
            EntityCategory::VisualObject,
            EntityCategory::SensorSource,
            EntityCategory::Model,
            EntityCategory::Actuator,
            EntityCategory::Custom("domain_specific".to_string()),
        ];
        for cat in &cats {
            let json = serde_json::to_string(cat).unwrap();
            let decoded: EntityCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, decoded);
        }
    }

    #[test]
    fn test_entity_category_default() {
        assert_eq!(EntityCategory::default(), EntityCategory::Concept);
    }

    // ── KnowledgeInjection tests ──

    #[test]
    fn test_knowledge_injection_serde() {
        let inj = KnowledgeInjection::AssertFact {
            entity_id: "alice".to_string(),
            category: EntityCategory::Person,
            attribute: "role".to_string(),
            value: serde_json::json!("admin"),
            confidence: 0.95,
            source_event_id: "evt:001".to_string(),
        };
        let json = serde_json::to_string(&inj).unwrap();
        assert!(json.contains("assert_fact"));
        let decoded: KnowledgeInjection = serde_json::from_str(&json).unwrap();
        match decoded {
            KnowledgeInjection::AssertFact { entity_id, confidence, .. } => {
                assert_eq!(entity_id, "alice");
                assert!((confidence - 0.95).abs() < f64::EPSILON);
            }
            _ => panic!("Expected AssertFact"),
        }
    }

    #[test]
    fn test_knowledge_injection_all_variants_serde() {
        let variants: Vec<KnowledgeInjection> = vec![
            KnowledgeInjection::AssertFact {
                entity_id: "e1".into(), category: EntityCategory::Concept,
                attribute: "a".into(), value: serde_json::json!(1),
                confidence: 1.0, source_event_id: "s".into(),
            },
            KnowledgeInjection::AssertRelation {
                from_entity: "a".into(), to_entity: "b".into(),
                relation: "r".into(), weight: 1.0, bidirectional: false,
                source_event_id: "s".into(),
            },
            KnowledgeInjection::Observe {
                entity_id: "e".into(), category: EntityCategory::SensorSource,
                observation: serde_json::json!({}), modality: "sensor".into(),
                source_event_id: "s".into(),
            },
            KnowledgeInjection::Hypothesize {
                entity_id: "e".into(), attribute: "a".into(),
                value: serde_json::json!("v"), confidence: 0.5,
                reasoning: "r".into(), source_event_id: "s".into(),
            },
            KnowledgeInjection::Correct {
                entity_id: "e".into(), attribute: "a".into(),
                old_value: serde_json::json!(1), new_value: serde_json::json!(2),
                reason: "fix".into(), source_event_id: "s".into(),
            },
            KnowledgeInjection::Retract {
                entity_id: "e".into(), attribute: Some("a".into()),
                relation: None, reason: "wrong".into(), source_event_id: "s".into(),
            },
            KnowledgeInjection::LinkModality {
                entity_id: "e".into(), modality: "image".into(),
                object_ref: "obj://x".into(), content_type: "image/png".into(),
                source_event_id: "s".into(),
            },
            KnowledgeInjection::Tag {
                entity_id: "e".into(), tags: vec!["t1".into(), "t2".into()],
                source_event_id: "s".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let _decoded: KnowledgeInjection = serde_json::from_str(&json).unwrap();
        }
    }

    // ── KnowledgeChangeLog tests ──

    #[test]
    fn test_change_log_basic() {
        let mut clog = KnowledgeChangeLog::new();
        assert!(clog.is_empty());
        assert_eq!(clog.watermark(), 0);

        clog.record(
            KnowledgeChangeType::NodeCreated,
            "alice",
            serde_json::json!({"attr": "role"}),
            "evt:001",
        );
        assert_eq!(clog.len(), 1);
        assert_eq!(clog.watermark(), 1);

        let entries = clog.read_from(0, 10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entity_id, "alice");
        assert_eq!(entries[0].change_type, KnowledgeChangeType::NodeCreated);
    }

    #[test]
    fn test_change_log_pagination() {
        let mut clog = KnowledgeChangeLog::new();
        for i in 0..20 {
            clog.record(
                KnowledgeChangeType::NodeUpdated,
                &format!("entity:{}", i),
                serde_json::json!({}),
                "evt",
            );
        }

        let page1 = clog.read_from(0, 5);
        assert_eq!(page1.len(), 5);
        assert_eq!(page1[0].change_id, 0);

        let page2 = clog.read_from(5, 5);
        assert_eq!(page2.len(), 5);
        assert_eq!(page2[0].change_id, 5);

        // Beyond watermark
        let empty = clog.read_from(100, 5);
        assert!(empty.is_empty());
    }

    // ── InjectionClassifier tests ──

    #[test]
    fn test_classify_text_event() {
        let event = make_memory_event(
            "cont:A", "agent:001",
            EventType::InteractionCreated,
            Some(serde_json::json!({
                "entities": ["alice", "bob"],
                "tags": ["medical", "urgent"],
                "text": "Patient alice was seen by dr bob"
            })),
        );

        let injections = InjectionClassifier::classify(&event);

        // Should produce: 2 AssertFact (one per entity) + 1 AssertRelation (co-occurrence) + 1 Tag
        let facts: Vec<_> = injections.iter().filter(|i| matches!(i, KnowledgeInjection::AssertFact { .. })).collect();
        let rels: Vec<_> = injections.iter().filter(|i| matches!(i, KnowledgeInjection::AssertRelation { .. })).collect();
        let tags: Vec<_> = injections.iter().filter(|i| matches!(i, KnowledgeInjection::Tag { .. })).collect();

        assert_eq!(facts.len(), 2);
        assert_eq!(rels.len(), 1);
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn test_classify_image_event() {
        let event = make_memory_event(
            "cont:cam", "camera:001",
            EventType::ImageCaptured,
            None,
        );

        let injections = InjectionClassifier::classify(&event);
        assert!(!injections.is_empty());

        // Should produce: Observe + LinkModality
        assert!(injections.iter().any(|i| matches!(i, KnowledgeInjection::Observe { modality, .. } if modality == "image")));
        assert!(injections.iter().any(|i| matches!(i, KnowledgeInjection::LinkModality { modality, .. } if modality == "image")));
    }

    #[test]
    fn test_classify_sensor_event() {
        let event = make_memory_event(
            "cont:sensors", "sensor:imu_01",
            EventType::SensorReadingRecorded,
            None,
        );

        let injections = InjectionClassifier::classify(&event);
        assert!(injections.len() >= 2); // Observe + AssertFact

        let observe = injections.iter().find(|i| matches!(i, KnowledgeInjection::Observe { .. }));
        assert!(observe.is_some());

        let fact = injections.iter().find(|i| matches!(i,
            KnowledgeInjection::AssertFact { attribute, .. } if attribute == "last_reading_at"));
        assert!(fact.is_some());
    }

    #[test]
    fn test_classify_model_checkpoint_event() {
        let event = make_memory_event(
            "cont:models", "model:resnet50",
            EventType::ModelCheckpointSaved,
            None,
        );

        let injections = InjectionClassifier::classify(&event);
        assert!(injections.len() >= 1);
        assert!(injections.iter().any(|i| matches!(i,
            KnowledgeInjection::AssertFact { category: EntityCategory::Model, .. })));
        assert!(injections.iter().any(|i| matches!(i,
            KnowledgeInjection::LinkModality { modality, .. } if modality == "model_weights")));
    }

    #[test]
    fn test_classify_inference_event() {
        let event = make_memory_event(
            "cont:infer", "model:bert",
            EventType::InferenceResultProduced,
            Some(serde_json::json!({"prediction": "positive", "score": 0.92})),
        );

        let injections = InjectionClassifier::classify(&event);
        assert_eq!(injections.len(), 1);
        assert!(matches!(&injections[0], KnowledgeInjection::Hypothesize { confidence, .. } if *confidence == 0.8));
    }

    #[test]
    fn test_classify_perception_event() {
        let event = make_memory_event(
            "cont:percept", "camera:front",
            EventType::PerceptionOutputProduced,
            Some(serde_json::json!({
                "detections": [
                    {"label": "person", "confidence": 0.95, "bbox": [10, 20, 100, 200]},
                    {"label": "car", "confidence": 0.87, "bbox": [300, 100, 500, 300]},
                ]
            })),
        );

        let injections = InjectionClassifier::classify(&event);
        // 2 detections × (AssertFact + AssertRelation) = 4
        assert_eq!(injections.len(), 4);

        let facts: Vec<_> = injections.iter()
            .filter(|i| matches!(i, KnowledgeInjection::AssertFact { category: EntityCategory::VisualObject, .. }))
            .collect();
        assert_eq!(facts.len(), 2);
    }

    #[test]
    fn test_classify_generic_event() {
        let event = make_memory_event(
            "cont:x", "key:x",
            EventType::PolicyChanged,
            None,
        );

        let injections = InjectionClassifier::classify(&event);
        assert_eq!(injections.len(), 1);
        assert!(matches!(&injections[0], KnowledgeInjection::Observe { modality, .. } if modality == "generic"));
    }

    // ── KnowledgeMaterializer tests ──

    #[test]
    fn test_materializer_poll_empty_log() {
        let log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        let (events, inj) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(events, 0);
        assert_eq!(inj, 0);
        assert_eq!(mat.events_processed, 0);
    }

    #[test]
    fn test_materializer_consumes_and_checkpoints() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        // Append 3 events
        log.append(make_memory_event(
            "cont:A", "agent:001", EventType::InteractionCreated,
            Some(serde_json::json!({"entities": ["alice", "bob"], "text": "hello"})),
        ));
        log.append(make_memory_event(
            "cont:A", "sensor:imu", EventType::SensorReadingRecorded, None,
        ));
        log.append(make_memory_event(
            "cont:A", "model:bert", EventType::ModelCheckpointSaved, None,
        ));

        // First poll
        let (events, inj) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(events, 3);
        assert!(inj > 0);
        assert_eq!(mat.events_processed, 3);

        // Knowledge graph should have nodes
        assert!(knot.node_count() > 0);

        // CDC log should have entries
        assert!(!mat.change_log.is_empty());

        // Second poll — no new events, offset committed
        let (events2, _) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(events2, 0);

        // Offsets should be at 3 (past the 3 events)
        assert_eq!(mat.group.offset("stream:test", 0), 3);
    }

    #[test]
    fn test_materializer_incremental_consumption() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        // Batch 1
        log.append(make_memory_event("c", "k1", EventType::ImageCaptured, None));
        let (e1, _) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(e1, 1);

        // Batch 2 — append more, should only consume new ones
        log.append(make_memory_event("c", "k2", EventType::AudioSegmentIngested, None));
        log.append(make_memory_event("c", "k3", EventType::VideoFrameIngested, None));
        let (e2, _) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(e2, 2);

        assert_eq!(mat.events_processed, 3);
    }

    #[test]
    fn test_materializer_reset_replays_all() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        log.append(make_memory_event("c", "k1", EventType::SensorReadingRecorded, None));
        log.append(make_memory_event("c", "k2", EventType::SensorReadingRecorded, None));

        mat.poll_and_apply(&log, &mut knot);
        assert_eq!(mat.events_processed, 2);

        // Reset offsets
        mat.reset();
        assert_eq!(mat.events_processed, 0);
        assert!(mat.change_log.is_empty());

        // Should replay all events
        let (events, _) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(events, 2);
    }

    #[test]
    fn test_materializer_lag() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        for _ in 0..10 {
            log.append(make_memory_event("c", "k", EventType::InteractionCreated, None));
        }

        // Full lag before any consumption
        let lag = mat.lag(&log, 0);
        assert!(lag > 0);

        // Consume all
        mat.poll_and_apply(&log, &mut knot);
        // Lag should be minimal after consumption
        // (watermark=9, offset=10 → lag 0)
    }

    #[test]
    fn test_materializer_multipartition() {
        let config = CommitLogConfig { partition_count: 4, ..Default::default() };
        let mut log = CommitLog::new(config);
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        // Distribute events across partitions
        for i in 0..20 {
            log.append(make_memory_event(
                "c", &format!("agent:{:03}", i),
                EventType::InteractionCreated,
                Some(serde_json::json!({"entities": [format!("entity:{}", i)]})),
            ));
        }

        let (events, _) = mat.poll_and_apply(&log, &mut knot);
        assert_eq!(events, 20);
        assert_eq!(mat.events_processed, 20);
    }

    // ── CDC downstream consumption tests ──

    #[test]
    fn test_cdc_downstream_consumption() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        log.append(make_memory_event(
            "c", "k", EventType::SensorReadingRecorded, None,
        ));
        mat.poll_and_apply(&log, &mut knot);

        // Simulate a downstream consumer reading CDC
        let mut downstream_offset = 0u64;
        let changes = mat.change_log.read_from(downstream_offset, 100);
        assert!(!changes.is_empty());

        // Track what we consumed
        downstream_offset = mat.change_log.watermark();

        // More events
        log.append(make_memory_event("c", "k2", EventType::ImageCaptured, None));
        mat.poll_and_apply(&log, &mut knot);

        // Downstream sees only new changes
        let new_changes = mat.change_log.read_from(downstream_offset, 100);
        assert!(!new_changes.is_empty());
        assert!(new_changes[0].change_id >= downstream_offset);
    }

    // ── GraphSnapshot tests ──

    #[test]
    fn test_snapshot_capture_and_restore() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        // Build some graph state
        log.append(make_memory_event(
            "c", "k1", EventType::InteractionCreated,
            Some(serde_json::json!({"entities": ["alice", "bob"]})),
        ));
        log.append(make_memory_event(
            "c", "sensor:imu", EventType::SensorReadingRecorded, None,
        ));
        mat.poll_and_apply(&log, &mut knot);

        let original_node_count = knot.node_count();
        let original_events = mat.events_processed;
        assert!(original_node_count > 0);

        // Snapshot
        let snap = GraphSnapshot::capture(&knot, &mat, 1);
        assert_eq!(snap.events_processed, original_events);
        assert!(!snap.nodes.is_empty());

        // Restore engine
        let restored_knot = snap.restore_engine();
        assert_eq!(restored_knot.node_count(), original_node_count);

        // Restore materializer
        let restored_mat = snap.restore_materializer("knowledge-mat-restored");
        assert_eq!(restored_mat.events_processed, original_events);
        assert_eq!(restored_mat.group.offset("stream:test", 0), mat.group.offset("stream:test", 0));
    }

    #[test]
    fn test_snapshot_serialization_roundtrip() {
        let mut knot = KnotEngine::new();
        knot.upsert_node("alice", Some("person"), BTreeMap::new(), &["admin".to_string()], 1000, 0, None);
        knot.upsert_node("bob", Some("person"), BTreeMap::new(), &[], 1000, 0, None);
        knot.upsert_edge("alice", "bob", "manages", 1.0, 1000, 0, None);

        let mat = KnowledgeMaterializer::new("test-mat", "stream:test");
        let snap = GraphSnapshot::capture(&knot, &mat, 1);

        // Serialize → bytes → deserialize
        let bytes = snap.to_bytes().unwrap();
        let restored_snap = GraphSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(restored_snap.nodes.len(), snap.nodes.len());
        assert!(restored_snap.nodes.contains_key("alice"));
        assert!(restored_snap.nodes.contains_key("bob"));

        let restored_knot = restored_snap.restore_engine();
        assert_eq!(restored_knot.node_count(), 2);
        assert_eq!(restored_knot.edge_count(), 1);

        // Verify tag index was rebuilt
        let alice = restored_knot.get_node("alice").unwrap();
        assert!(alice.tags.contains(&"admin".to_string()));
    }

    #[test]
    fn test_snapshot_resume_from_offset() {
        let mut log = CommitLog::developer();
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("knowledge-mat", "stream:test");

        // Ingest 5 events
        for i in 0..5 {
            log.append(make_memory_event(
                "c", &format!("k:{}", i),
                EventType::SensorReadingRecorded, None,
            ));
        }
        mat.poll_and_apply(&log, &mut knot);
        assert_eq!(mat.events_processed, 5);

        // Snapshot
        let snap = GraphSnapshot::capture(&knot, &mat, 1);

        // Add more events
        for i in 5..10 {
            log.append(make_memory_event(
                "c", &format!("k:{}", i),
                EventType::SensorReadingRecorded, None,
            ));
        }

        // Restore and resume — should only consume events 5-9
        let mut restored_knot = snap.restore_engine();
        let mut restored_mat = snap.restore_materializer("knowledge-mat");

        let (events, _) = restored_mat.poll_and_apply(&log, &mut restored_knot);
        assert_eq!(events, 5); // Only the new events
        assert_eq!(restored_mat.events_processed, 10); // 5 from snapshot + 5 new
    }

    // ── Apply injection directly tests ──

    #[test]
    fn test_apply_assert_fact() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        mat.apply_injection(&mut knot, &KnowledgeInjection::AssertFact {
            entity_id: "sensor:temp_01".to_string(),
            category: EntityCategory::SensorSource,
            attribute: "temperature".to_string(),
            value: serde_json::json!(23.5),
            confidence: 1.0,
            source_event_id: "evt:001".to_string(),
        });

        assert_eq!(knot.node_count(), 1);
        let node = knot.get_node("sensor:temp_01").unwrap();
        assert_eq!(node.attributes["temperature"], serde_json::json!(23.5));
        assert_eq!(mat.change_log.len(), 1);
        assert_eq!(mat.change_log.read_from(0, 1)[0].change_type, KnowledgeChangeType::NodeCreated);
    }

    #[test]
    fn test_apply_assert_relation_bidirectional() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        mat.apply_injection(&mut knot, &KnowledgeInjection::AssertRelation {
            from_entity: "alice".to_string(),
            to_entity: "bob".to_string(),
            relation: "co_occurs".to_string(),
            weight: 1.0,
            bidirectional: true,
            source_event_id: "evt:001".to_string(),
        });

        assert_eq!(knot.node_count(), 2); // Both nodes auto-created
        assert_eq!(knot.edge_count(), 2); // Bidirectional
        assert!(!knot.edges_from("alice").is_empty());
        assert!(!knot.edges_from("bob").is_empty());
    }

    #[test]
    fn test_apply_correct() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        // Initial fact
        mat.apply_injection(&mut knot, &KnowledgeInjection::AssertFact {
            entity_id: "patient:001".to_string(),
            category: EntityCategory::Person,
            attribute: "blood_type".to_string(),
            value: serde_json::json!("A+"),
            confidence: 0.8,
            source_event_id: "evt:001".to_string(),
        });

        // Correction
        mat.apply_injection(&mut knot, &KnowledgeInjection::Correct {
            entity_id: "patient:001".to_string(),
            attribute: "blood_type".to_string(),
            old_value: serde_json::json!("A+"),
            new_value: serde_json::json!("B+"),
            reason: "Lab re-test".to_string(),
            source_event_id: "evt:002".to_string(),
        });

        let node = knot.get_node("patient:001").unwrap();
        assert_eq!(node.attributes["blood_type"], serde_json::json!("B+"));
        assert_eq!(node.attributes["blood_type_corrected_from"], serde_json::json!("A+"));
    }

    #[test]
    fn test_apply_retract() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        mat.apply_injection(&mut knot, &KnowledgeInjection::AssertFact {
            entity_id: "claim:X".to_string(),
            category: EntityCategory::Concept,
            attribute: "status".to_string(),
            value: serde_json::json!("valid"),
            confidence: 1.0,
            source_event_id: "evt:001".to_string(),
        });

        mat.apply_injection(&mut knot, &KnowledgeInjection::Retract {
            entity_id: "claim:X".to_string(),
            attribute: Some("status".to_string()),
            relation: None,
            reason: "Debunked by new evidence".to_string(),
            source_event_id: "evt:002".to_string(),
        });

        let node = knot.get_node("claim:X").unwrap();
        assert_eq!(node.attributes["status_retracted"], serde_json::json!(true));
    }

    #[test]
    fn test_apply_link_modality() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        mat.apply_injection(&mut knot, &KnowledgeInjection::LinkModality {
            entity_id: "scan:mri_001".to_string(),
            modality: "image".to_string(),
            object_ref: "obj://tenant/images/mri_001.dcm".to_string(),
            content_type: "application/dicom".to_string(),
            source_event_id: "evt:001".to_string(),
        });

        let node = knot.get_node("scan:mri_001").unwrap();
        assert_eq!(
            node.attributes["modality_image_ref"],
            serde_json::json!("obj://tenant/images/mri_001.dcm")
        );
        assert_eq!(mat.change_log.read_from(0, 1)[0].change_type, KnowledgeChangeType::ModalityLinked);
    }

    #[test]
    fn test_apply_tag() {
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("test", "s");

        mat.apply_injection(&mut knot, &KnowledgeInjection::Tag {
            entity_id: "doc:report_001".to_string(),
            tags: vec!["urgent".to_string(), "radiology".to_string()],
            source_event_id: "evt:001".to_string(),
        });

        let node = knot.get_node("doc:report_001").unwrap();
        assert!(node.tags.contains(&"urgent".to_string()));
        assert!(node.tags.contains(&"radiology".to_string()));
    }

    // ── End-to-end: CommitLog → Materializer → Graph → Snapshot → Restore ──

    #[test]
    fn test_e2e_full_pipeline() {
        // 1. Set up commit log with multi-modal events
        let mut log = CommitLog::developer();
        log.append(make_memory_event(
            "cont:hospital", "agent:triage",
            EventType::InteractionCreated,
            Some(serde_json::json!({"entities": ["patient:P001", "doctor:D001"], "tags": ["emergency"]})),
        ));
        log.append(make_memory_event(
            "cont:hospital", "camera:room_3",
            EventType::ImageCaptured, None,
        ));
        log.append(make_memory_event(
            "cont:hospital", "sensor:vitals_P001",
            EventType::SensorReadingRecorded, None,
        ));
        log.append(make_memory_event(
            "cont:hospital", "model:triage_classifier",
            EventType::InferenceResultProduced,
            Some(serde_json::json!({"priority": "high", "confidence": 0.94})),
        ));

        // 2. Create materializer + engine, consume all
        let mut knot = KnotEngine::new();
        let mut mat = KnowledgeMaterializer::new("hospital-knowledge", "stream:hospital");
        let (events, injections) = mat.poll_and_apply(&log, &mut knot);

        assert_eq!(events, 4);
        assert!(injections > 0);
        assert!(knot.node_count() > 0);
        assert!(!mat.change_log.is_empty());

        // 3. Snapshot
        let snap = GraphSnapshot::capture(&knot, &mat, 1);
        let bytes = snap.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // 4. Simulate crash: restore from snapshot
        let snap2 = GraphSnapshot::from_bytes(&bytes).unwrap();
        let mut restored_knot = snap2.restore_engine();
        let mut restored_mat = snap2.restore_materializer("hospital-knowledge");

        assert_eq!(restored_knot.node_count(), knot.node_count());
        assert_eq!(restored_mat.events_processed, mat.events_processed);

        // 5. New events arrive after crash
        log.append(make_memory_event(
            "cont:hospital", "agent:triage",
            EventType::ActuationCommandIssued,
            Some(serde_json::json!({"action": "alert_doctor"})),
        ));

        let (new_events, _) = restored_mat.poll_and_apply(&log, &mut restored_knot);
        assert_eq!(new_events, 1);
        assert_eq!(restored_mat.events_processed, events + 1);
    }
}
