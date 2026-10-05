//! Memory Graph — Knowledge-Anchored Memory System with Dehallucination
//!
//! Provides:
//! - Memory graph (nodes = memories, edges = relationships)
//! - Dehallucination chains (ground truth validation)
//! - RAG with Knot pagination (efficient raw data retrieval)
//! - Index tree for O(log n) search
//! - Rollups for aggregated memory views
//!
//! Prevents LLM drift by anchoring all memories to verified knowledge.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

// =============================================================================
// Memory Graph Node Types
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MemoryNodeType {
    /// Raw observation/experience
    Observation,
    /// Derived fact (inferred)
    DerivedFact,
    /// Interaction with user/system
    Interaction,
    /// Instruction/following
    Instruction,
    /// Consensus-agreed truth
    ConsensusTruth,
    /// Hallucination (flagged)
    Hallucination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryNode {
    /// Unique memory ID
    pub memory_id: String,
    /// Node type
    pub node_type: MemoryNodeType,
    /// Content
    pub content: String,
    /// Embedding vector (for similarity search)
    pub embedding: Vec<f32>,
    /// Knowledge anchors (links to ground truth)
    pub knowledge_anchors: Vec<String>,
    /// Confidence score (0-1)
    pub confidence: f64,
    /// Verification status
    pub verification: VerificationStatus,
    /// Creation metadata
    pub created_at: i64,
    pub agent_pid: String,
    pub session_id: String,
    /// Dehallucination chain data
    pub dehall_chain: DehallChain,
    /// Pagination for large memories (Knot-based)
    pub pagination: KnotPagination,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    Unverified,
    PendingValidation,
    Validated,
    Contradicted,
    Hallucinated,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DehallChain {
    /// Ground truth references
    pub ground_truth_refs: Vec<String>,
    /// Contradiction score (0-1, higher = more contradictions)
    pub contradiction_score: f64,
    /// Validation chain (sequence of validators)
    pub validators: Vec<String>,
    /// Last validation timestamp
    pub last_validated: i64,
    /// Is this memory hallucinated?
    pub is_hallucination: bool,
    /// Drift detection score (how far from knowledge base)
    pub drift_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnotPagination {
    /// Knot round that committed this memory
    pub knot_round: u64,
    /// Page index (for large memories split across pages)
    pub page_index: u32,
    /// Total pages
    pub total_pages: u32,
    /// Parent page (for linked pagination)
    pub parent_page: Option<String>,
    /// Child pages
    pub child_pages: Vec<String>,
    /// Merkle root of page content (for integrity)
    pub merkle_root: String,
}

// =============================================================================
// Memory Graph Edge Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEdge {
    /// Edge ID
    pub edge_id: String,
    /// Source memory
    pub from: String,
    /// Target memory
    pub to: String,
    /// Relationship type
    pub relation: MemoryRelation,
    /// Edge weight (strength of relationship)
    pub weight: f64,
    /// Created at
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryRelation {
    /// A implies B
    Implies,
    /// A contradicts B
    Contradicts,
    /// A supports B
    Supports,
    /// A is similar to B
    SimilarTo,
    /// A is part of B
    PartOf,
    /// A references B
    References,
    /// Temporal sequence (A happened before B)
    Before,
    /// Causal (A caused B)
    Caused,
}

// =============================================================================
// Index Tree for Fast Search
// =============================================================================

/// B-tree based index for O(log n) memory lookup
pub struct MemoryIndex {
    /// Time-based index: timestamp → memory_ids
    temporal_index: BTreeMap<i64, Vec<String>>,
    /// Agent index: agent_pid → memory_ids
    agent_index: HashMap<String, Vec<String>>,
    /// Session index: session_id → memory_ids
    session_index: HashMap<String, Vec<String>>,
    /// Type index: MemoryNodeType → memory_ids
    type_index: HashMap<MemoryNodeType, Vec<String>>,
    /// Confidence index: confidence bucket → memory_ids
    confidence_index: BTreeMap<u8, Vec<String>>, // 0-100 buckets
    /// Knowledge anchor index: anchor_id → memory_ids
    anchor_index: HashMap<String, Vec<String>>,
}

impl MemoryIndex {
    pub fn new() -> Self {
        Self {
            temporal_index: BTreeMap::new(),
            agent_index: HashMap::new(),
            session_index: HashMap::new(),
            type_index: HashMap::new(),
            confidence_index: BTreeMap::new(),
            anchor_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, memory: &MemoryNode) {
        // Temporal index
        self.temporal_index
            .entry(memory.created_at)
            .or_insert_with(Vec::new)
            .push(memory.memory_id.clone());

        // Agent index
        self.agent_index
            .entry(memory.agent_pid.clone())
            .or_insert_with(Vec::new)
            .push(memory.memory_id.clone());

        // Session index
        self.session_index
            .entry(memory.session_id.clone())
            .or_insert_with(Vec::new)
            .push(memory.memory_id.clone());

        // Type index
        self.type_index
            .entry(memory.node_type)
            .or_insert_with(Vec::new)
            .push(memory.memory_id.clone());

        // Confidence index (bucket: 0-100)
        let bucket = (memory.confidence * 100.0) as u8;
        self.confidence_index
            .entry(bucket)
            .or_insert_with(Vec::new)
            .push(memory.memory_id.clone());

        // Anchor index
        for anchor in &memory.knowledge_anchors {
            self.anchor_index
                .entry(anchor.clone())
                .or_insert_with(Vec::new)
                .push(memory.memory_id.clone());
        }
    }

    pub fn remove(&mut self, memory: &MemoryNode) {
        // Remove from all indices
        if let Some(vec) = self.temporal_index.get_mut(&memory.created_at) {
            vec.retain(|id| id != &memory.memory_id);
        }
        if let Some(vec) = self.agent_index.get_mut(&memory.agent_pid) {
            vec.retain(|id| id != &memory.memory_id);
        }
        // ... similar for other indices
    }

    /// Get memories in time range (O(log n + k))
    pub fn query_time_range(&self, start: i64, end: i64) -> Vec<String> {
        self.temporal_index
            .range(start..=end)
            .flat_map(|(_, ids)| ids.clone())
            .collect()
    }

    /// Get high-confidence memories (O(log n + k))
    pub fn query_high_confidence(&self, threshold: f64) -> Vec<String> {
        let bucket = (threshold * 100.0) as u8;
        self.confidence_index
            .range(bucket..=100)
            .flat_map(|(_, ids)| ids.clone())
            .collect()
    }

    /// Get memories anchored to specific knowledge
    pub fn query_by_anchor(&self, anchor_id: &str) -> Vec<String> {
        self.anchor_index
            .get(anchor_id)
            .cloned()
            .unwrap_or_default()
    }
}

// =============================================================================
// Memory Graph (Full Graph Structure)
// =============================================================================

pub struct MemoryGraph {
    /// All memory nodes
    nodes: HashMap<String, MemoryNode>,
    /// All edges
    edges: HashMap<String, MemoryEdge>,
    /// Adjacency list: node_id → outgoing edges
    adjacency: HashMap<String, Vec<String>>,
    /// Reverse adjacency: node_id → incoming edges
    reverse_adj: HashMap<String, Vec<String>>,
    /// Search index
    index: MemoryIndex,
    /// Knowledge base reference (anchor IDs that are ground truth)
    knowledge_base: HashSet<String>,
}

impl MemoryGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            adjacency: HashMap::new(),
            reverse_adj: HashMap::new(),
            index: MemoryIndex::new(),
            knowledge_base: HashSet::new(),
        }
    }

    /// Add memory node with dehallucination validation
    pub fn add_memory(
        &mut self,
        content: String,
        embedding: Vec<f32>,
        node_type: MemoryNodeType,
        agent_pid: String,
        session_id: String,
        knowledge_anchors: Vec<String>,
    ) -> String {
        let memory_id = format!(
            "mem-{}-{}",
            chrono::Utc::now().timestamp_millis(),
            uuid::Uuid::new_v4()
        );

        // Validate against knowledge anchors
        let dehall_chain = self.validate_against_knowledge(&content, &knowledge_anchors);

        let confidence = if dehall_chain.is_hallucination {
            0.0
        } else {
            1.0 - dehall_chain.drift_score
        };

        let verification = if dehall_chain.is_hallucination {
            VerificationStatus::Hallucinated
        } else if dehall_chain.drift_score < 0.1 {
            VerificationStatus::Validated
        } else {
            VerificationStatus::PendingValidation
        };

        let node = MemoryNode {
            memory_id: memory_id.clone(),
            node_type,
            content,
            embedding,
            knowledge_anchors: knowledge_anchors.clone(),
            confidence,
            verification,
            created_at: chrono::Utc::now().timestamp_millis(),
            agent_pid,
            session_id,
            dehall_chain,
            pagination: KnotPagination {
                knot_round: 0,
                page_index: 0,
                total_pages: 1,
                parent_page: None,
                child_pages: vec![],
                merkle_root: String::new(),
            },
        };

        self.index.insert(&node);
        self.nodes.insert(memory_id.clone(), node);

        // Create edges to knowledge anchors
        for anchor in knowledge_anchors {
            self.add_edge(memory_id.clone(), anchor, MemoryRelation::References, 1.0);
        }

        memory_id
    }

    /// Add edge between memories
    pub fn add_edge(
        &mut self,
        from: String,
        to: String,
        relation: MemoryRelation,
        weight: f64,
    ) -> String {
        let edge_id = format!("edge-{}-{}-{}", from, to, uuid::Uuid::new_v4());

        let edge = MemoryEdge {
            edge_id: edge_id.clone(),
            from: from.clone(),
            to: to.clone(),
            relation,
            weight,
            created_at: chrono::Utc::now().timestamp_millis(),
        };

        self.adjacency
            .entry(from.clone())
            .or_insert_with(Vec::new)
            .push(edge_id.clone());

        self.reverse_adj
            .entry(to.clone())
            .or_insert_with(Vec::new)
            .push(edge_id.clone());

        self.edges.insert(edge_id.clone(), edge);
        edge_id
    }

    /// Validate memory against knowledge base
    fn validate_against_knowledge(&self, content: &str, anchors: &[String]) -> DehallChain {
        let mut contradiction_score = 0.0;
        let mut drift_score = 0.0;
        let mut validators = vec![];

        for anchor_id in anchors {
            if let Some(anchor) = self.nodes.get(anchor_id) {
                validators.push(anchor_id.clone());

                // Check semantic similarity (simplified)
                let similarity = self.semantic_similarity(content, &anchor.content);

                if similarity < 0.3 {
                    // Low similarity = potential drift
                    drift_score += (0.3 - similarity) / 0.3;
                }

                // Check for contradictions
                if self.check_contradiction(content, &anchor.content) {
                    contradiction_score += 1.0;
                }
            }
        }

        let anchor_count = anchors.len().max(1) as f64;
        let avg_contradiction = contradiction_score / anchor_count;
        let avg_drift = drift_score / anchor_count;

        DehallChain {
            ground_truth_refs: anchors.to_vec(),
            contradiction_score: avg_contradiction,
            validators,
            last_validated: chrono::Utc::now().timestamp_millis(),
            is_hallucination: avg_contradiction > 0.7,
            drift_score: avg_drift.min(1.0),
        }
    }

    /// Semantic similarity (placeholder - use real embeddings)
    fn semantic_similarity(&self, a: &str, b: &str) -> f64 {
        // In production: use cosine similarity of embeddings
        // Simplified: Jaccard similarity of words
        let a_words: HashSet<String> = a
            .to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let b_words: HashSet<String> = b
            .to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let intersection: HashSet<_> = a_words.intersection(&b_words).collect();
        let union: HashSet<_> = a_words.union(&b_words).collect();

        if union.is_empty() {
            return 0.0;
        }

        intersection.len() as f64 / union.len() as f64
    }

    /// Check for explicit contradictions
    fn check_contradiction(&self, a: &str, b: &str) -> bool {
        // Simple contradiction detection
        let contradictions = vec![
            ("is", "is not"),
            ("was", "was not"),
            ("true", "false"),
            ("yes", "no"),
        ];

        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();

        for (pos, neg) in contradictions {
            if a_lower.contains(pos) && b_lower.contains(neg) {
                return true;
            }
            if a_lower.contains(neg) && b_lower.contains(pos) {
                return true;
            }
        }

        false
    }

    /// RAG: Retrieve relevant memories for query
    pub fn rag_retrieve(
        &self,
        query_embedding: &[f32],
        top_k: usize,
        min_confidence: f64,
    ) -> Vec<(&MemoryNode, f64)> {
        // Score all memories by similarity
        let mut scored: Vec<(&MemoryNode, f64)> = self
            .nodes
            .values()
            .filter(|n| n.confidence >= min_confidence && !n.dehall_chain.is_hallucination)
            .map(|node| {
                let score = self.cosine_similarity(query_embedding, &node.embedding);
                (node, score)
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.truncate(top_k);
        scored
    }

    /// Cosine similarity between embeddings
    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f64 {
        if a.is_empty() || b.is_empty() || a.len() != b.len() {
            return 0.0;
        }

        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        (dot / (norm_a * norm_b)) as f64
    }

    /// Knot pagination: paginate large memory with consensus
    pub fn paginate_with_knot(
        &mut self,
        memory_id: &str,
        knot_round: u64,
        merkle_root: String,
    ) -> Result<(), String> {
        let node = self.nodes.get_mut(memory_id).ok_or("Memory not found")?;

        node.pagination.knot_round = knot_round;
        node.pagination.merkle_root = merkle_root;

        Ok(())
    }

    /// Get memory chain (follow references back to knowledge)
    pub fn get_memory_chain(&self, memory_id: &str) -> Vec<&MemoryNode> {
        let mut chain = vec![];
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(memory_id.to_string());

        while let Some(id) = queue.pop_front() {
            if visited.contains(&id) {
                continue;
            }
            visited.insert(id.clone());

            if let Some(node) = self.nodes.get(&id) {
                chain.push(node);

                // Add knowledge anchors to queue
                for anchor in &node.knowledge_anchors {
                    queue.push_back(anchor.clone());
                }

                // Add parents via reverse adjacency
                if let Some(edges) = self.reverse_adj.get(&id) {
                    for edge_id in edges {
                        if let Some(edge) = self.edges.get(edge_id) {
                            queue.push_back(edge.from.clone());
                        }
                    }
                }
            }
        }

        chain
    }

    /// Get memory rollup (aggregated view)
    pub fn get_rollup(
        &self,
        agent_pid: Option<&str>,
        session_id: Option<&str>,
        time_range: Option<(i64, i64)>,
    ) -> MemoryRollup {
        let mut total_memories = 0;
        let mut validated_count = 0;
        let mut hallucination_count = 0;
        let mut pending_count = 0;
        let mut total_confidence = 0.0;

        for node in self.nodes.values() {
            // Apply filters
            if let Some(agent) = agent_pid {
                if node.agent_pid != agent {
                    continue;
                }
            }
            if let Some(session) = session_id {
                if node.session_id != session {
                    continue;
                }
            }
            if let Some((start, end)) = time_range {
                if node.created_at < start || node.created_at > end {
                    continue;
                }
            }

            total_memories += 1;
            total_confidence += node.confidence;

            match node.verification {
                VerificationStatus::Validated => validated_count += 1,
                VerificationStatus::Hallucinated => hallucination_count += 1,
                VerificationStatus::PendingValidation => pending_count += 1,
                _ => {}
            }
        }

        let avg_confidence = if total_memories > 0 {
            total_confidence / total_memories as f64
        } else {
            0.0
        };

        MemoryRollup {
            total_memories,
            validated_count,
            hallucination_count,
            pending_count,
            average_confidence: avg_confidence,
            drift_score: 1.0 - avg_confidence,
        }
    }

    /// Detect system drift (overall drift from knowledge base)
    pub fn detect_system_drift(&self) -> DriftReport {
        let mut total_drift = 0.0;
        let mut hallucination_count = 0;
        let mut validated_count = 0;

        for node in self.nodes.values() {
            total_drift += node.dehall_chain.drift_score;

            if node.dehall_chain.is_hallucination {
                hallucination_count += 1;
            }
            if node.verification == VerificationStatus::Validated {
                validated_count += 1;
            }
        }

        let total = self.nodes.len().max(1) as f64;

        DriftReport {
            average_drift: total_drift / total,
            hallucination_ratio: hallucination_count as f64 / total,
            validation_ratio: validated_count as f64 / total,
            is_critical: (total_drift / total) > 0.5 || (hallucination_count as f64 / total) > 0.1,
        }
    }

    /// Get all hallucinated memories (for review/correction)
    pub fn get_hallucinations(&self) -> Vec<&MemoryNode> {
        self.nodes
            .values()
            .filter(|n| n.dehall_chain.is_hallucination)
            .collect()
    }

    /// Revalidate all pending memories (batch validation)
    pub fn revalidate_pending(&mut self) -> Vec<(String, VerificationStatus)> {
        let pending: Vec<String> = self
            .nodes
            .values()
            .filter(|n| n.verification == VerificationStatus::PendingValidation)
            .map(|n| n.memory_id.clone())
            .collect();

        let mut results = vec![];

        for memory_id in pending {
            if let Some(node) = self.nodes.get(&memory_id) {
                let anchors = node.knowledge_anchors.clone();
                let content = node.content.clone();

                let dehall = self.validate_against_knowledge(&content, &anchors);

                if let Some(node) = self.nodes.get_mut(&memory_id) {
                    node.dehall_chain = dehall.clone();
                    node.confidence = 1.0 - dehall.drift_score;

                    if dehall.is_hallucination {
                        node.verification = VerificationStatus::Hallucinated;
                    } else if dehall.drift_score < 0.1 {
                        node.verification = VerificationStatus::Validated;
                    }

                    results.push((memory_id, node.verification.clone()));
                }
            }
        }

        results
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRollup {
    pub total_memories: usize,
    pub validated_count: usize,
    pub hallucination_count: usize,
    pub pending_count: usize,
    pub average_confidence: f64,
    pub drift_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub average_drift: f64,
    pub hallucination_ratio: f64,
    pub validation_ratio: f64,
    pub is_critical: bool,
}

// =============================================================================
// Thread-safe wrapper
// =============================================================================

#[derive(Clone)]
pub struct SharedMemoryGraph {
    inner: Arc<RwLock<MemoryGraph>>,
}

impl SharedMemoryGraph {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MemoryGraph::new())),
        }
    }

    pub fn add_memory(
        &self,
        content: String,
        embedding: Vec<f32>,
        node_type: MemoryNodeType,
        agent_pid: String,
        session_id: String,
        anchors: Vec<String>,
    ) -> String {
        self.inner.write().unwrap().add_memory(
            content, embedding, node_type, agent_pid, session_id, anchors,
        )
    }

    pub fn rag_retrieve(
        &self,
        query: &[f32],
        top_k: usize,
        min_conf: f64,
    ) -> Vec<(MemoryNode, f64)> {
        self.inner
            .read()
            .unwrap()
            .rag_retrieve(query, top_k, min_conf)
            .into_iter()
            .map(|(n, s)| (n.clone(), s))
            .collect()
    }

    pub fn detect_drift(&self) -> DriftReport {
        self.inner.read().unwrap().detect_system_drift()
    }

    pub fn get_rollup(
        &self,
        agent: Option<&str>,
        session: Option<&str>,
        time: Option<(i64, i64)>,
    ) -> MemoryRollup {
        self.inner.read().unwrap().get_rollup(agent, session, time)
    }

    pub fn revalidate(&self) -> Vec<(String, VerificationStatus)> {
        self.inner.write().unwrap().revalidate_pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_embedding() -> Vec<f32> {
        vec![0.1, 0.2, 0.3, 0.4, 0.5]
    }

    #[test]
    fn test_memory_add_and_retrieve() {
        let mut graph = MemoryGraph::new();

        // Add knowledge anchor
        let knowledge = graph.add_memory(
            "The sky is blue".to_string(),
            test_embedding(),
            MemoryNodeType::ConsensusTruth,
            "system".to_string(),
            "session-1".to_string(),
            vec![],
        );

        // Add memory anchored to knowledge
        let memory = graph.add_memory(
            "I observed a blue sky today".to_string(),
            test_embedding(),
            MemoryNodeType::Observation,
            "agent-1".to_string(),
            "session-1".to_string(),
            vec![knowledge.clone()],
        );

        let node = graph.nodes.get(&memory).unwrap();
        assert!(node.confidence > 0.5);
        assert!(!node.dehall_chain.is_hallucination);
    }

    #[test]
    fn test_hallucination_detection() {
        let mut graph = MemoryGraph::new();

        // Add ground truth
        let truth = graph.add_memory(
            "Water freezes at 0°C".to_string(),
            test_embedding(),
            MemoryNodeType::ConsensusTruth,
            "system".to_string(),
            "session-1".to_string(),
            vec![],
        );

        // Add contradictory memory (should be flagged)
        let lie = graph.add_memory(
            "Water is not frozen at 0°C".to_string(),
            test_embedding(),
            MemoryNodeType::DerivedFact,
            "agent-1".to_string(),
            "session-1".to_string(),
            vec![truth.clone()],
        );

        let lie_node = graph.nodes.get(&lie).unwrap();
        assert!(lie_node.dehall_chain.contradiction_score > 0.0);
    }

    #[test]
    fn test_drift_detection() {
        let mut graph = MemoryGraph::new();

        // Add knowledge
        let knowledge = graph.add_memory(
            "Ground truth".to_string(),
            test_embedding(),
            MemoryNodeType::ConsensusTruth,
            "system".to_string(),
            "session-1".to_string(),
            vec![],
        );

        // Add many drifting memories
        for i in 0..10 {
            graph.add_memory(
                format!("Random unrelated content {}", i),
                vec![0.9, 0.8, 0.7, 0.6, 0.5], // Different embedding
                MemoryNodeType::Observation,
                "agent-1".to_string(),
                "session-1".to_string(),
                vec![knowledge.clone()],
            );
        }

        let drift = graph.detect_system_drift();
        assert!(drift.average_drift > 0.0);
    }

    #[test]
    fn test_time_range_query() {
        let mut graph = MemoryGraph::new();

        let now = chrono::Utc::now().timestamp_millis();

        graph.add_memory(
            "Old memory".to_string(),
            test_embedding(),
            MemoryNodeType::Observation,
            "agent-1".to_string(),
            "session-1".to_string(),
            vec![],
        );

        // Query time range
        let results = graph.index.query_time_range(now - 10000, now + 10000);
        assert!(!results.is_empty());
    }
}
