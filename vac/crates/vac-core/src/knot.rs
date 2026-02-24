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
}

impl KnotEngine {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
            tag_index: HashMap::new(),
            window_entity_index: HashMap::new(),
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

    /// Ingest entities and co-occurrence edges from a set of MemPackets
    pub fn ingest_packets(&mut self, packets: &[MemPacket], window_sn: u64) {
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
}
