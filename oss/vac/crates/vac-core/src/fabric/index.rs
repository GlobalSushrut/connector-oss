//! # Index Fabric
//!
//! Materialized indexes derived from committed events. These are **not truth** —
//! they are retrieval acceleration planes that can be rebuilt from the commit log.
//!
//! ## Sub-Indexes
//!
//! | Index | Purpose | Query Pattern |
//! |-------|---------|--------------|
//! | Vector | Semantic candidate retrieval | `nearest(embedding, k, filter)` |
//! | Metadata | Typed filters, ownership, tags | `filter(container, class, tags)` |
//! | Timeline | Temporal continuity | `range(container, from_ts, to_ts)` |
//! | Relation | Cross-container refs | `traverse(from_id, edge_type, depth)` |
//!
//! ## Backends
//!
//! | Mode | Vector | Metadata | Timeline |
//! |------|--------|----------|----------|
//! | Developer | In-memory brute-force | HashMap | BTreeMap |
//! | Production | Qdrant cluster | Postgres | Postgres partitioned |

use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};
use super::types::*;

// =============================================================================
// Vector Index
// =============================================================================

/// A single entry in the vector index.
///
/// Supports multimodal embeddings: text (sentence-transformers), image (CLIP),
/// audio (wav2vec), sensor (learned representations), point cloud (PointNet),
/// code (CodeBERT), and any custom embedding space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorIndexEntry {
    pub memory_id: String,
    pub container_id: String,
    pub embedding: Vec<f32>,
    pub memory_class: MemoryClass,
    pub modality: Modality,
    /// Embedding model/space identifier (e.g., "clip-vit-b32", "all-MiniLM-L6").
    pub embedding_model: String,
    /// Dimensionality of the embedding vector.
    pub embedding_dim: u32,
    pub timestamp: i64,
    pub payload: HashMap<String, serde_json::Value>,
}

/// Result from a vector search query.
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    pub memory_id: String,
    pub score: f32,
    pub entry: VectorIndexEntry,
}

/// Filter for vector search queries.
#[derive(Debug, Clone, Default)]
pub struct VectorFilter {
    pub container_ids: Vec<String>,
    pub memory_classes: Vec<MemoryClass>,
    pub modalities: Vec<Modality>,
    pub embedding_models: Vec<String>,
    pub min_timestamp: Option<i64>,
    pub max_timestamp: Option<i64>,
}

/// In-memory vector index using brute-force cosine similarity.
/// For developer mode. Production uses Qdrant.
#[derive(Debug, Default)]
pub struct InMemoryVectorIndex {
    entries: Vec<VectorIndexEntry>,
}

impl InMemoryVectorIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an embedding entry.
    pub fn insert(&mut self, entry: VectorIndexEntry) {
        // Upsert by memory_id
        if let Some(pos) = self.entries.iter().position(|e| e.memory_id == entry.memory_id) {
            self.entries[pos] = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Remove an entry by memory_id.
    pub fn remove(&mut self, memory_id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.memory_id != memory_id);
        self.entries.len() < before
    }

    /// Search for nearest neighbors using cosine similarity.
    pub fn search(&self, query: &[f32], k: usize, filter: &VectorFilter) -> Vec<VectorSearchResult> {
        let mut scored: Vec<VectorSearchResult> = self.entries.iter()
            .filter(|e| {
                if !filter.container_ids.is_empty() && !filter.container_ids.contains(&e.container_id) {
                    return false;
                }
                if !filter.memory_classes.is_empty() && !filter.memory_classes.contains(&e.memory_class) {
                    return false;
                }
                if !filter.modalities.is_empty() && !filter.modalities.contains(&e.modality) {
                    return false;
                }
                if !filter.embedding_models.is_empty() && !filter.embedding_models.contains(&e.embedding_model) {
                    return false;
                }
                if let Some(min_ts) = filter.min_timestamp {
                    if e.timestamp < min_ts { return false; }
                }
                if let Some(max_ts) = filter.max_timestamp {
                    if e.timestamp > max_ts { return false; }
                }
                true
            })
            .map(|e| {
                let score = cosine_similarity(query, &e.embedding);
                VectorSearchResult {
                    memory_id: e.memory_id.clone(),
                    score,
                    entry: e.clone(),
                }
            })
            .collect();

        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}

// =============================================================================
// Metadata Index
// =============================================================================

/// A single entry in the metadata index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub memory_id: String,
    pub container_id: String,
    pub memory_class: MemoryClass,
    pub producer_id: String,
    pub tags: Vec<String>,
    pub trace_id: Option<String>,
    pub visibility: Visibility,
    pub retention_class: RetentionClass,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Filter for metadata queries.
#[derive(Debug, Clone, Default)]
pub struct MetadataFilter {
    pub container_ids: Vec<String>,
    pub memory_classes: Vec<MemoryClass>,
    pub tags: Vec<String>,
    pub producer_ids: Vec<String>,
    pub visibility: Option<Visibility>,
    pub trace_id: Option<String>,
}

/// In-memory metadata index. Production uses Postgres.
#[derive(Debug, Default)]
pub struct InMemoryMetadataIndex {
    entries: HashMap<String, MetadataEntry>,
    /// Secondary index: container_id → memory_ids
    by_container: HashMap<String, Vec<String>>,
    /// Secondary index: tag → memory_ids
    by_tag: HashMap<String, Vec<String>>,
    /// Secondary index: trace_id → memory_ids
    by_trace: HashMap<String, Vec<String>>,
}

impl InMemoryMetadataIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a metadata entry.
    pub fn upsert(&mut self, entry: MetadataEntry) {
        let mid = entry.memory_id.clone();

        // Update container index
        self.by_container
            .entry(entry.container_id.clone())
            .or_default()
            .push(mid.clone());

        // Update tag index
        for tag in &entry.tags {
            self.by_tag
                .entry(tag.clone())
                .or_default()
                .push(mid.clone());
        }

        // Update trace index
        if let Some(ref tid) = entry.trace_id {
            self.by_trace
                .entry(tid.clone())
                .or_default()
                .push(mid.clone());
        }

        self.entries.insert(mid, entry);
    }

    /// Get a metadata entry by memory_id.
    pub fn get(&self, memory_id: &str) -> Option<&MetadataEntry> {
        self.entries.get(memory_id)
    }

    /// Remove a metadata entry.
    pub fn remove(&mut self, memory_id: &str) -> bool {
        if let Some(entry) = self.entries.remove(memory_id) {
            // Clean secondary indexes
            if let Some(v) = self.by_container.get_mut(&entry.container_id) {
                v.retain(|id| id != memory_id);
            }
            for tag in &entry.tags {
                if let Some(v) = self.by_tag.get_mut(tag) {
                    v.retain(|id| id != memory_id);
                }
            }
            if let Some(ref tid) = entry.trace_id {
                if let Some(v) = self.by_trace.get_mut(tid) {
                    v.retain(|id| id != memory_id);
                }
            }
            true
        } else {
            false
        }
    }

    /// Query with filters. Returns matching entries.
    pub fn query(&self, filter: &MetadataFilter, limit: usize) -> Vec<&MetadataEntry> {
        self.entries.values()
            .filter(|e| {
                if !filter.container_ids.is_empty() && !filter.container_ids.contains(&e.container_id) {
                    return false;
                }
                if !filter.memory_classes.is_empty() && !filter.memory_classes.contains(&e.memory_class) {
                    return false;
                }
                if !filter.tags.is_empty() && !filter.tags.iter().any(|t| e.tags.contains(t)) {
                    return false;
                }
                if !filter.producer_ids.is_empty() && !filter.producer_ids.contains(&e.producer_id) {
                    return false;
                }
                if let Some(vis) = filter.visibility {
                    if e.visibility != vis { return false; }
                }
                if let Some(ref tid) = filter.trace_id {
                    if e.trace_id.as_ref() != Some(tid) { return false; }
                }
                true
            })
            .take(limit)
            .collect()
    }

    /// Get all entries for a container.
    pub fn by_container(&self, container_id: &str) -> Vec<&MetadataEntry> {
        self.by_container
            .get(container_id)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all entries for a trace.
    pub fn by_trace(&self, trace_id: &str) -> Vec<&MetadataEntry> {
        self.by_trace
            .get(trace_id)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// Timeline Index
// =============================================================================

/// A single entry in the timeline index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub container_id: String,
    pub timestamp: i64,
    pub memory_id: String,
    pub event_type: EventType,
    pub trace_id: Option<String>,
}

/// In-memory timeline index using BTreeMap for ordered range scans.
/// Key: (container_id, timestamp, memory_id) for unique ordering.
#[derive(Debug, Default)]
pub struct InMemoryTimelineIndex {
    entries: BTreeMap<(String, i64, String), TimelineEntry>,
}

impl InMemoryTimelineIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entry: TimelineEntry) {
        let key = (entry.container_id.clone(), entry.timestamp, entry.memory_id.clone());
        self.entries.insert(key, entry);
    }

    pub fn remove(&mut self, container_id: &str, timestamp: i64, memory_id: &str) -> bool {
        self.entries.remove(&(container_id.to_string(), timestamp, memory_id.to_string())).is_some()
    }

    /// Range query: get all entries in [from_ts, to_ts] for a container.
    pub fn range(&self, container_id: &str, from_ts: i64, to_ts: i64) -> Vec<&TimelineEntry> {
        let start = (container_id.to_string(), from_ts, String::new());
        let end = (container_id.to_string(), to_ts, String::from("\x7f".repeat(256)));
        self.entries
            .range(start..=end)
            .map(|(_, e)| e)
            .collect()
    }

    /// Get the latest N entries for a container.
    pub fn latest(&self, container_id: &str, n: usize) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|((cid, _, _), _)| cid == container_id)
            .take(n)
            .map(|(_, e)| e)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// Relation Index
// =============================================================================

/// A single entry in the relation index (adjacency list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationEntry {
    pub from_id: String,
    pub to_id: String,
    pub edge_type: EdgeType,
    pub weight: f64,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

/// In-memory relation index using adjacency lists.
#[derive(Debug, Default)]
pub struct InMemoryRelationIndex {
    /// Forward adjacency: from_id → edges
    forward: HashMap<String, Vec<RelationEntry>>,
    /// Reverse adjacency: to_id → edges
    reverse: HashMap<String, Vec<RelationEntry>>,
}

impl InMemoryRelationIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a relation.
    pub fn add(&mut self, entry: RelationEntry) {
        self.reverse
            .entry(entry.to_id.clone())
            .or_default()
            .push(entry.clone());
        self.forward
            .entry(entry.from_id.clone())
            .or_default()
            .push(entry);
    }

    /// Get outgoing edges from a node.
    pub fn outgoing(&self, from_id: &str) -> &[RelationEntry] {
        self.forward.get(from_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get incoming edges to a node.
    pub fn incoming(&self, to_id: &str) -> &[RelationEntry] {
        self.reverse.get(to_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get outgoing edges of a specific type.
    pub fn outgoing_typed(&self, from_id: &str, edge_type: EdgeType) -> Vec<&RelationEntry> {
        self.outgoing(from_id).iter().filter(|e| e.edge_type == edge_type).collect()
    }

    /// Traverse from a node up to `depth` hops following specific edge types.
    pub fn traverse(&self, from_id: &str, edge_types: &[EdgeType], depth: usize) -> Vec<&RelationEntry> {
        let mut result = Vec::new();
        let mut frontier = vec![from_id.to_string()];
        let mut visited = std::collections::HashSet::new();
        visited.insert(from_id.to_string());

        for _ in 0..depth {
            let mut next_frontier = Vec::new();
            for node in &frontier {
                for edge in self.outgoing(node) {
                    if (edge_types.is_empty() || edge_types.contains(&edge.edge_type))
                        && visited.insert(edge.to_id.clone())
                    {
                        result.push(edge);
                        next_frontier.push(edge.to_id.clone());
                    }
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }
        result
    }

    /// Remove all edges involving a node (both directions).
    pub fn remove_node(&mut self, node_id: &str) {
        self.forward.remove(node_id);
        self.reverse.remove(node_id);
        for edges in self.forward.values_mut() {
            edges.retain(|e| e.to_id != node_id);
        }
        for edges in self.reverse.values_mut() {
            edges.retain(|e| e.from_id != node_id);
        }
    }

    pub fn edge_count(&self) -> usize {
        self.forward.values().map(|v| v.len()).sum()
    }

    pub fn node_count(&self) -> usize {
        let mut nodes = std::collections::HashSet::new();
        for edges in self.forward.values() {
            for e in edges {
                nodes.insert(&e.from_id);
                nodes.insert(&e.to_id);
            }
        }
        nodes.len()
    }
}

// =============================================================================
// IndexFabric — unified index layer
// =============================================================================

/// Unified index fabric combining all four sub-indexes.
pub struct IndexFabric {
    pub vector: InMemoryVectorIndex,
    pub metadata: InMemoryMetadataIndex,
    pub timeline: InMemoryTimelineIndex,
    pub relations: InMemoryRelationIndex,
}

impl IndexFabric {
    pub fn new() -> Self {
        Self {
            vector: InMemoryVectorIndex::new(),
            metadata: InMemoryMetadataIndex::new(),
            timeline: InMemoryTimelineIndex::new(),
            relations: InMemoryRelationIndex::new(),
        }
    }

    /// Total entries across all indexes.
    pub fn total_entries(&self) -> usize {
        self.vector.len() + self.metadata.len() + self.timeline.len() + self.relations.edge_count()
    }
}

impl Default for IndexFabric {
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

    #[test]
    fn test_cosine_similarity_identical() {
        let v = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_opposite() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert!((cosine_similarity(&a, &b) + 1.0).abs() < 0.001);
    }

    #[test]
    fn test_vector_index_insert_search() {
        let mut idx = InMemoryVectorIndex::new();
        idx.insert(VectorIndexEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![1.0, 0.0, 0.0],
            memory_class: MemoryClass::Episodic,
            modality: Modality::Text,
            embedding_model: "all-MiniLM-L6".to_string(),
            embedding_dim: 3,
            timestamp: 1000,
            payload: HashMap::new(),
        });
        idx.insert(VectorIndexEntry {
            memory_id: "m2".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![0.9, 0.1, 0.0],
            memory_class: MemoryClass::Episodic,
            modality: Modality::Text,
            embedding_model: "all-MiniLM-L6".to_string(),
            embedding_dim: 3,
            timestamp: 2000,
            payload: HashMap::new(),
        });
        idx.insert(VectorIndexEntry {
            memory_id: "m3".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![0.0, 0.0, 1.0],
            memory_class: MemoryClass::Semantic,
            modality: Modality::Text,
            embedding_model: "all-MiniLM-L6".to_string(),
            embedding_dim: 3,
            timestamp: 3000,
            payload: HashMap::new(),
        });

        let results = idx.search(&[1.0, 0.0, 0.0], 2, &VectorFilter::default());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].memory_id, "m1"); // highest similarity
        assert_eq!(results[1].memory_id, "m2");
    }

    #[test]
    fn test_vector_index_filter() {
        let mut idx = InMemoryVectorIndex::new();
        idx.insert(VectorIndexEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![1.0, 0.0],
            memory_class: MemoryClass::Episodic,
            modality: Modality::Text,
            embedding_model: "test".to_string(),
            embedding_dim: 2,
            timestamp: 1000,
            payload: HashMap::new(),
        });
        idx.insert(VectorIndexEntry {
            memory_id: "m2".to_string(),
            container_id: "c2".to_string(),
            embedding: vec![1.0, 0.0],
            memory_class: MemoryClass::Semantic,
            modality: Modality::Image,
            embedding_model: "clip-vit-b32".to_string(),
            embedding_dim: 2,
            timestamp: 2000,
            payload: HashMap::new(),
        });

        let filter = VectorFilter {
            container_ids: vec!["c1".to_string()],
            ..Default::default()
        };
        let results = idx.search(&[1.0, 0.0], 10, &filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, "m1");

        // Filter by modality
        let filter = VectorFilter {
            modalities: vec![Modality::Image],
            ..Default::default()
        };
        let results = idx.search(&[1.0, 0.0], 10, &filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, "m2");

        // Filter by embedding model
        let filter = VectorFilter {
            embedding_models: vec!["clip-vit-b32".to_string()],
            ..Default::default()
        };
        let results = idx.search(&[1.0, 0.0], 10, &filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, "m2");
    }

    #[test]
    fn test_vector_index_upsert() {
        let mut idx = InMemoryVectorIndex::new();
        idx.insert(VectorIndexEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![1.0, 0.0],
            memory_class: MemoryClass::Episodic,
            modality: Modality::Text,
            embedding_model: "test".to_string(),
            embedding_dim: 2,
            timestamp: 1000,
            payload: HashMap::new(),
        });
        assert_eq!(idx.len(), 1);

        idx.insert(VectorIndexEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            embedding: vec![0.0, 1.0],
            memory_class: MemoryClass::Episodic,
            modality: Modality::Text,
            embedding_model: "test".to_string(),
            embedding_dim: 2,
            timestamp: 2000,
            payload: HashMap::new(),
        });
        assert_eq!(idx.len(), 1); // upserted, not duplicated
    }

    #[test]
    fn test_metadata_index_upsert_query() {
        let mut idx = InMemoryMetadataIndex::new();
        idx.upsert(MetadataEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            memory_class: MemoryClass::Episodic,
            producer_id: "pid:001".to_string(),
            tags: vec!["important".to_string(), "medical".to_string()],
            trace_id: Some("trace:001".to_string()),
            visibility: Visibility::Private,
            retention_class: RetentionClass::LongTerm,
            created_at: 1000,
            updated_at: 1000,
        });

        assert_eq!(idx.len(), 1);

        let filter = MetadataFilter {
            tags: vec!["medical".to_string()],
            ..Default::default()
        };
        let results = idx.query(&filter, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, "m1");
    }

    #[test]
    fn test_metadata_index_by_container() {
        let mut idx = InMemoryMetadataIndex::new();
        idx.upsert(MetadataEntry {
            memory_id: "m1".to_string(),
            container_id: "c1".to_string(),
            memory_class: MemoryClass::Episodic,
            producer_id: "p".to_string(),
            tags: vec![], trace_id: None,
            visibility: Visibility::Private,
            retention_class: RetentionClass::LongTerm,
            created_at: 1000, updated_at: 1000,
        });
        idx.upsert(MetadataEntry {
            memory_id: "m2".to_string(),
            container_id: "c2".to_string(),
            memory_class: MemoryClass::Semantic,
            producer_id: "p".to_string(),
            tags: vec![], trace_id: None,
            visibility: Visibility::Private,
            retention_class: RetentionClass::LongTerm,
            created_at: 2000, updated_at: 2000,
        });

        let c1 = idx.by_container("c1");
        assert_eq!(c1.len(), 1);
        assert_eq!(c1[0].memory_id, "m1");
    }

    #[test]
    fn test_timeline_index_range() {
        let mut idx = InMemoryTimelineIndex::new();
        for i in 0..10 {
            idx.insert(TimelineEntry {
                container_id: "c1".to_string(),
                timestamp: 1000 + i * 100,
                memory_id: format!("m{}", i),
                event_type: EventType::InteractionCreated,
                trace_id: None,
            });
        }
        assert_eq!(idx.len(), 10);

        let range = idx.range("c1", 1200, 1500);
        assert_eq!(range.len(), 4); // timestamps 1200, 1300, 1400, 1500
    }

    #[test]
    fn test_timeline_index_latest() {
        let mut idx = InMemoryTimelineIndex::new();
        for i in 0..5 {
            idx.insert(TimelineEntry {
                container_id: "c1".to_string(),
                timestamp: 1000 + i,
                memory_id: format!("m{}", i),
                event_type: EventType::InteractionCreated,
                trace_id: None,
            });
        }

        let latest = idx.latest("c1", 2);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].timestamp, 1004);
        assert_eq!(latest[1].timestamp, 1003);
    }

    #[test]
    fn test_relation_index_add_traverse() {
        let mut idx = InMemoryRelationIndex::new();

        idx.add(RelationEntry {
            from_id: "A".to_string(), to_id: "B".to_string(),
            edge_type: EdgeType::Next, weight: 1.0,
            created_at: 1000, metadata: HashMap::new(),
        });
        idx.add(RelationEntry {
            from_id: "B".to_string(), to_id: "C".to_string(),
            edge_type: EdgeType::Next, weight: 1.0,
            created_at: 2000, metadata: HashMap::new(),
        });
        idx.add(RelationEntry {
            from_id: "A".to_string(), to_id: "D".to_string(),
            edge_type: EdgeType::ForksTo, weight: 0.5,
            created_at: 3000, metadata: HashMap::new(),
        });

        assert_eq!(idx.outgoing("A").len(), 2);
        assert_eq!(idx.incoming("B").len(), 1);
        assert_eq!(idx.outgoing_typed("A", EdgeType::Next).len(), 1);

        // Traverse depth=2 following Next edges
        let reached = idx.traverse("A", &[EdgeType::Next], 2);
        assert_eq!(reached.len(), 2); // A→B, B→C
    }

    #[test]
    fn test_relation_index_remove_node() {
        let mut idx = InMemoryRelationIndex::new();
        idx.add(RelationEntry {
            from_id: "A".to_string(), to_id: "B".to_string(),
            edge_type: EdgeType::Next, weight: 1.0,
            created_at: 1000, metadata: HashMap::new(),
        });
        idx.add(RelationEntry {
            from_id: "B".to_string(), to_id: "C".to_string(),
            edge_type: EdgeType::Next, weight: 1.0,
            created_at: 2000, metadata: HashMap::new(),
        });
        assert_eq!(idx.edge_count(), 2);

        idx.remove_node("B");
        assert_eq!(idx.outgoing("A").len(), 0); // A→B removed
        assert!(idx.outgoing("B").is_empty()); // B→C removed
    }

    #[test]
    fn test_index_fabric_combined() {
        let fabric = IndexFabric::new();
        assert_eq!(fabric.total_entries(), 0);
    }
}
