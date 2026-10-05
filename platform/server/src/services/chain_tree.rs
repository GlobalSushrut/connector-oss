//! Chain Tree — Hyperbolic Knowledge & Memory System
//!
//! Manages:
//! - Chain tree of knowledge (HAT: Hierarchical Attention Tree)
//! - Memory recall with hyperbolic embeddings
//! - Cross-cell consensus chains
//! - Dehallucination validation chains
//! - Infinite chain tree of thoughts
//!
//! Uses hyperbolic geometry (Poincaré disk model) for chain distances
//! and KECS for chain stability scoring.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

// =============================================================================
// Hyperbolic Geometry for Chain Distances
// =============================================================================

/// Poincaré disk model: points live in unit disk D = {x ∈ ℝⁿ : ||x|| < 1}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HyperbolicPoint {
    pub x: f64,
    pub y: f64,
    pub z: f64, // For 3D hyperbolic space
}

impl HyperbolicPoint {
    /// Create point in Poincaré disk (must satisfy x² + y² < 1)
    pub fn new(x: f64, y: f64) -> Self {
        let norm_sq = x * x + y * y;
        if norm_sq >= 1.0 {
            // Project onto boundary
            let scale = 0.99 / norm_sq.sqrt();
            Self {
                x: x * scale,
                y: y * scale,
                z: 0.0,
            }
        } else {
            Self { x, y, z: 0.0 }
        }
    }

    /// Euclidean norm squared
    pub fn norm_sq(&self) -> f64 {
        self.x * self.x + self.y * self.y + self.z * self.z
    }

    /// Hyperbolic distance between two points
    /// d(u,v) = arcosh(1 + 2||u-v||² / ((1-||u||²)(1-||v||²)))
    pub fn distance_to(&self, other: &HyperbolicPoint) -> f64 {
        let num = 2.0 * self.euclidean_dist_sq(other);
        let denom = (1.0 - self.norm_sq()) * (1.0 - other.norm_sq());
        let arg = 1.0 + num / denom.max(1e-10);
        arg.max(1.0).acosh()
    }

    /// Euclidean distance squared
    fn euclidean_dist_sq(&self, other: &HyperbolicPoint) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        dx * dx + dy * dy + dz * dz
    }

    /// Mobius addition for hyperbolic vector space
    pub fn mobius_add(&self, other: &HyperbolicPoint) -> HyperbolicPoint {
        let self_sq = self.norm_sq();
        let other_sq = other.norm_sq();
        let dot = self.x * other.x + self.y * other.y + self.z * other.z;

        let num_factor =
            (1.0 + 2.0 * dot + other_sq) / (1.0 + 2.0 * dot + self_sq * other_sq).max(1e-10);
        let denom = 1.0 + 2.0 * dot + self_sq * other_sq;

        HyperbolicPoint {
            x: (self.x + other.x * num_factor) / denom,
            y: (self.y + other.y * num_factor) / denom,
            z: (self.z + other.z * num_factor) / denom,
        }
    }
}

// =============================================================================
// Chain Tree Node (HAT: Hierarchical Attention Tree)
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainNodeType {
    /// Knowledge fact or concept
    Knowledge,
    /// Memory from agent interaction
    Memory,
    /// Reasoning step / thought
    Thought,
    /// Consensus checkpoint
    Consensus,
    /// Cross-cell communication
    CrossCell,
    /// Dehallucination validation
    Dehallucination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainNode {
    /// Unique node ID
    pub node_id: String,
    /// Node type
    pub node_type: ChainNodeType,
    /// Content (knowledge, memory, thought, etc.)
    pub content: String,
    /// Hyperbolic embedding position
    pub embedding: HyperbolicPoint,
    /// KECS stability score
    pub kecs_score: f64,
    /// Confidence (0-1)
    pub confidence: f64,
    /// Creation timestamp
    pub created_at: i64,
    /// Parent nodes (forms the tree structure)
    pub parents: Vec<String>,
    /// Child nodes
    pub children: Vec<String>,
    /// Cross-cell references (for distributed chains)
    pub cross_cell_refs: Vec<CrossCellRef>,
    /// Dehallucination validation data
    pub dehall_data: Option<DehallData>,
    /// Consensus rounds this node participated in
    pub consensus_rounds: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCellRef {
    pub cell_id: String,
    pub remote_node_id: String,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncStatus {
    Pending,
    Synced,
    Conflicted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehallData {
    /// Ground truth sources
    pub ground_truth_refs: Vec<String>,
    /// Contradiction detection score
    pub contradiction_score: f64,
    /// Validation chain
    pub validation_chain: Vec<String>,
    /// Is hallucination?
    pub is_hallucination: bool,
}

// =============================================================================
// Chain Tree (Forest of Knowledge Trees)
// =============================================================================

pub struct ChainTree {
    /// All nodes in the forest
    nodes: HashMap<String, ChainNode>,
    /// Root nodes of each tree
    roots: Vec<String>,
    /// Hyperbolic radius for new node placement
    radius: f64,
    /// KECS threshold for chain stability
    kecs_threshold: f64,
    /// Maximum tree depth
    max_depth: usize,
}

impl ChainTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            radius: 0.5, // Keep within inner half of Poincaré disk
            kecs_threshold: 0.6,
            max_depth: 100,
        }
    }

    /// Create a new knowledge node
    pub fn create_knowledge_node(
        &mut self,
        content: String,
        parents: Vec<String>,
        kecs_score: f64,
    ) -> String {
        let node_id = format!(
            "kn-{}-{}",
            chrono::Utc::now().timestamp_millis(),
            uuid::Uuid::new_v4()
        );

        // Calculate hyperbolic embedding based on parents
        let embedding = self.calculate_embedding(&parents);

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::Knowledge,
            content,
            embedding,
            kecs_score,
            confidence: kecs_score, // Confidence = stability
            created_at: chrono::Utc::now().timestamp_millis(),
            parents: parents.clone(),
            children: Vec::new(),
            cross_cell_refs: Vec::new(),
            dehall_data: None,
            consensus_rounds: Vec::new(),
        };

        // Link to parents
        for parent_id in &parents {
            if let Some(parent) = self.nodes.get_mut(parent_id) {
                parent.children.push(node_id.clone());
            }
        }

        // Add root if no parents
        if parents.is_empty() {
            self.roots.push(node_id.clone());
        }

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    /// Create memory node (linked to knowledge)
    pub fn create_memory_node(
        &mut self,
        content: String,
        knowledge_parent: String,
        agent_pid: &str,
    ) -> String {
        let node_id = format!("mem-{}-{}", agent_pid, uuid::Uuid::new_v4());

        let mut parents = vec![knowledge_parent.clone()];

        // Calculate embedding near parent knowledge
        let embedding = self.calculate_embedding(&parents);

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::Memory,
            content,
            embedding,
            kecs_score: 0.7, // Memory starts with good stability
            confidence: 0.8,
            created_at: chrono::Utc::now().timestamp_millis(),
            parents,
            children: Vec::new(),
            cross_cell_refs: Vec::new(),
            dehall_data: None,
            consensus_rounds: Vec::new(),
        };

        // Link to parent knowledge
        if let Some(parent) = self.nodes.get_mut(&knowledge_parent) {
            parent.children.push(node_id.clone());
        }

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    /// Create thought node (chain of thought)
    pub fn create_thought_node(
        &mut self,
        content: String,
        parent_thought: Option<String>,
        reasoning_step: u32,
    ) -> String {
        let node_id = format!("thought-{}-{}", reasoning_step, uuid::Uuid::new_v4());

        let parents = parent_thought.map(|p| vec![p]).unwrap_or_default();
        let embedding = self.calculate_embedding(&parents);

        // Thoughts have lower initial confidence
        let confidence = 0.5 + (reasoning_step as f64 * 0.05).min(0.3);

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::Thought,
            content,
            embedding,
            kecs_score: confidence,
            confidence,
            created_at: chrono::Utc::now().timestamp_millis(),
            parents,
            children: Vec::new(),
            cross_cell_refs: Vec::new(),
            dehall_data: None,
            consensus_rounds: Vec::new(),
        };

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    /// Create consensus checkpoint
    pub fn create_consensus_node(
        &mut self,
        round: u64,
        value: String,
        evidence_nodes: Vec<String>,
        kecs_score: f64,
    ) -> String {
        let node_id = format!("consensus-{}", round);

        let embedding = self.calculate_embedding(&evidence_nodes);

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::Consensus,
            content: value,
            embedding,
            kecs_score,
            confidence: kecs_score,
            created_at: chrono::Utc::now().timestamp_millis(),
            parents: evidence_nodes.clone(),
            children: Vec::new(),
            cross_cell_refs: Vec::new(),
            dehall_data: None,
            consensus_rounds: vec![round],
        };

        // Link to evidence
        for evidence_id in &evidence_nodes {
            if let Some(evidence) = self.nodes.get_mut(evidence_id) {
                evidence.children.push(node_id.clone());
                evidence.consensus_rounds.push(round);
            }
        }

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    /// Create cross-cell reference
    pub fn create_cross_cell_node(
        &mut self,
        content: String,
        local_parent: String,
        remote_cell: String,
        remote_node: String,
    ) -> String {
        let node_id = format!("crosscell-{}-{}", remote_cell, uuid::Uuid::new_v4());

        let parents = vec![local_parent.clone()];
        let embedding = self.calculate_embedding(&parents);

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::CrossCell,
            content,
            embedding,
            kecs_score: 0.6, // Cross-cell starts uncertain
            confidence: 0.5,
            created_at: chrono::Utc::now().timestamp_millis(),
            parents,
            children: Vec::new(),
            cross_cell_refs: vec![CrossCellRef {
                cell_id: remote_cell,
                remote_node_id: remote_node,
                sync_status: SyncStatus::Pending,
            }],
            dehall_data: None,
            consensus_rounds: Vec::new(),
        };

        if let Some(parent) = self.nodes.get_mut(&local_parent) {
            parent.children.push(node_id.clone());
        }

        self.nodes.insert(node_id.clone(), node);
        node_id
    }

    /// Create dehallucination validation node
    pub fn create_dehall_node(
        &mut self,
        target_node: String,
        ground_truth: Vec<String>,
    ) -> Result<String, String> {
        let target = self
            .nodes
            .get(&target_node)
            .ok_or("Target node not found")?;

        // Check for contradictions
        let contradiction_score = self.detect_contradictions(&target_node, &ground_truth);
        let is_hallucination = contradiction_score > 0.7;

        let node_id = format!("dehall-{}", target_node);

        let dehall_data = DehallData {
            ground_truth_refs: ground_truth.clone(),
            contradiction_score,
            validation_chain: vec![target_node.clone()],
            is_hallucination,
        };

        let node = ChainNode {
            node_id: node_id.clone(),
            node_type: ChainNodeType::Dehallucination,
            content: if is_hallucination {
                format!("HALLUCINATION DETECTED: {}", target.content)
            } else {
                format!("VALIDATED: {}", target.content)
            },
            embedding: target.embedding.clone(),
            kecs_score: if is_hallucination { 0.1 } else { 0.9 },
            confidence: if is_hallucination { 0.0 } else { 1.0 },
            created_at: chrono::Utc::now().timestamp_millis(),
            parents: vec![target_node],
            children: Vec::new(),
            cross_cell_refs: Vec::new(),
            dehall_data: Some(dehall_data),
            consensus_rounds: Vec::new(),
        };

        self.nodes.insert(node_id.clone(), node);
        Ok(node_id)
    }

    /// Calculate hyperbolic embedding for new node
    fn calculate_embedding(&self, parents: &[String]) -> HyperbolicPoint {
        if parents.is_empty() {
            // Random position near center
            return HyperbolicPoint::new(0.0, 0.0);
        }

        // Mobius average of parent positions
        let mut sum = HyperbolicPoint::new(0.0, 0.0);
        for parent_id in parents {
            if let Some(parent) = self.nodes.get(parent_id) {
                sum = sum.mobius_add(&parent.embedding);
            }
        }

        // Normalize to ensure within disk
        let count = parents.len() as f64;
        HyperbolicPoint::new(sum.x / count, sum.y / count)
    }

    /// Detect contradictions between node and ground truth
    fn detect_contradictions(&self, target: &str, ground_truth: &[String]) -> f64 {
        let target_node = match self.nodes.get(target) {
            Some(n) => n,
            None => return 1.0, // Missing = contradiction
        };

        let mut contradictions = 0;
        let mut checks = 0;

        for truth_id in ground_truth {
            if let Some(truth) = self.nodes.get(truth_id) {
                checks += 1;
                // Check hyperbolic distance
                let dist = target_node.embedding.distance_to(&truth.embedding);
                if dist > 2.0 {
                    // Threshold for contradiction in hyperbolic space
                    contradictions += 1;
                }
            }
        }

        if checks == 0 {
            return 0.5; // Unknown
        }

        contradictions as f64 / checks as f64
    }

    /// Memory recall: find nodes similar to query in hyperbolic space
    pub fn memory_recall(
        &self,
        query_embedding: &HyperbolicPoint,
        max_distance: f64,
    ) -> Vec<&ChainNode> {
        self.nodes
            .values()
            .filter(|node| {
                let dist = node.embedding.distance_to(query_embedding);
                dist < max_distance && node.kecs_score >= self.kecs_threshold
            })
            .collect()
    }

    /// Get chain of thought path from root to node
    pub fn get_thought_chain(&self, node_id: &str) -> Option<Vec<&ChainNode>> {
        let mut chain = Vec::new();
        let mut current = node_id;

        loop {
            let node = self.nodes.get(current)?;
            chain.push(node);

            if node.parents.is_empty() {
                break;
            }

            // Follow first parent (main reasoning path)
            current = &node.parents[0];
        }

        chain.reverse();
        Some(chain)
    }

    /// Prune unstable chains (low KECS score)
    pub fn prune_unstable_chains(&mut self) -> Vec<String> {
        let unstable: Vec<String> = self
            .nodes
            .values()
            .filter(|n| n.kecs_score < 0.3 && n.children.is_empty())
            .map(|n| n.node_id.clone())
            .collect();

        for node_id in &unstable {
            self.nodes.remove(node_id);
        }

        unstable
    }

    /// Get all nodes of a specific type
    pub fn get_nodes_by_type(&self, node_type: ChainNodeType) -> Vec<&ChainNode> {
        self.nodes
            .values()
            .filter(|n| n.node_type == node_type)
            .collect()
    }

    /// Calculate total chain stability
    pub fn total_stability(&self) -> f64 {
        if self.nodes.is_empty() {
            return 1.0;
        }
        self.nodes.values().map(|n| n.kecs_score).sum::<f64>() / self.nodes.len() as f64
    }

    /// Check if chain tree is solid (all chains stable)
    pub fn is_solid(&self) -> bool {
        self.total_stability() >= self.kecs_threshold
    }
}

// =============================================================================
// Chain Tree Manager (Thread-safe)
// =============================================================================

#[derive(Clone)]
pub struct SharedChainTree {
    inner: Arc<Mutex<ChainTree>>,
}

impl SharedChainTree {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChainTree::new())),
        }
    }

    pub fn create_knowledge(&self, content: String, parents: Vec<String>, kecs: f64) -> String {
        self.inner
            .lock()
            .unwrap()
            .create_knowledge_node(content, parents, kecs)
    }

    pub fn create_memory(&self, content: String, knowledge_parent: String, agent: &str) -> String {
        self.inner
            .lock()
            .unwrap()
            .create_memory_node(content, knowledge_parent, agent)
    }

    pub fn create_thought(&self, content: String, parent: Option<String>, step: u32) -> String {
        self.inner
            .lock()
            .unwrap()
            .create_thought_node(content, parent, step)
    }

    pub fn create_consensus(
        &self,
        round: u64,
        value: String,
        evidence: Vec<String>,
        kecs: f64,
    ) -> String {
        self.inner
            .lock()
            .unwrap()
            .create_consensus_node(round, value, evidence, kecs)
    }

    pub fn validate_dehall(
        &self,
        target: String,
        ground_truth: Vec<String>,
    ) -> Result<String, String> {
        self.inner
            .lock()
            .unwrap()
            .create_dehall_node(target, ground_truth)
    }

    pub fn memory_recall(&self, query: &HyperbolicPoint, max_dist: f64) -> Vec<ChainNode> {
        self.inner
            .lock()
            .unwrap()
            .memory_recall(query, max_dist)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn is_solid(&self) -> bool {
        self.inner.lock().unwrap().is_solid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyperbolic_distance() {
        let origin = HyperbolicPoint::new(0.0, 0.0);
        let point = HyperbolicPoint::new(0.5, 0.0);

        // Distance from center increases as we move outward
        let dist = origin.distance_to(&point);
        assert!(dist > 0.0);

        // Distance to self is zero
        assert_eq!(origin.distance_to(&origin), 0.0);
    }

    #[test]
    fn test_chain_tree_knowledge() {
        let mut tree = ChainTree::new();

        // Create knowledge hierarchy
        let root = tree.create_knowledge_node("Root concept".to_string(), vec![], 0.8);

        let child =
            tree.create_knowledge_node("Child concept".to_string(), vec![root.clone()], 0.7);

        let grandchild =
            tree.create_knowledge_node("Grandchild concept".to_string(), vec![child.clone()], 0.6);

        // Get thought chain
        let chain = tree.get_thought_chain(&grandchild).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].node_id, root);
        assert_eq!(chain[2].node_id, grandchild);
    }

    #[test]
    fn test_memory_recall() {
        let mut tree = ChainTree::new();

        let knowledge = tree.create_knowledge_node("Test knowledge".to_string(), vec![], 0.9);

        tree.create_memory_node("Memory of test".to_string(), knowledge.clone(), "agent-1");

        // Query near the knowledge embedding
        let query = tree.nodes.get(&knowledge).unwrap().embedding.clone();
        let recalled = tree.memory_recall(&query, 1.0);

        assert!(!recalled.is_empty());
    }

    #[test]
    fn test_dehallucination() {
        let mut tree = ChainTree::new();

        let truth = tree.create_knowledge_node("Ground truth".to_string(), vec![], 1.0);

        let suspicious = tree.create_knowledge_node("Contradictory claim".to_string(), vec![], 0.3);

        // Place suspicious far from truth in hyperbolic space
        {
            let truth_node = tree.nodes.get_mut(&truth).unwrap();
            truth_node.embedding = HyperbolicPoint::new(0.1, 0.1);

            let suspicious_node = tree.nodes.get_mut(&suspicious).unwrap();
            suspicious_node.embedding = HyperbolicPoint::new(0.8, 0.8);
        }

        let dehall = tree
            .create_dehall_node(suspicious.clone(), vec![truth.clone()])
            .unwrap();

        let dehall_node = tree.nodes.get(&dehall).unwrap();
        assert!(dehall_node.dehall_data.as_ref().unwrap().is_hallucination);
    }

    #[test]
    fn test_chain_solidity() {
        let mut tree = ChainTree::new();

        // Empty tree is solid
        assert!(tree.is_solid());

        // Add stable nodes
        tree.create_knowledge_node("Stable 1".to_string(), vec![], 0.9);
        tree.create_knowledge_node("Stable 2".to_string(), vec![], 0.9);

        assert!(tree.is_solid());

        // Add unstable node
        tree.create_knowledge_node("Unstable".to_string(), vec![], 0.2);

        // Still solid because average is above threshold
        assert!(tree.total_stability() > 0.6);
    }
}
