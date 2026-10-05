//! MEM-4: VectorIndex — pluggable semantic search backend.
//!
//! Trait hierarchy:
//!   `VectorIndex` — upsert + query interface (implementors: `KeywordIndex`, future: sqlite-vec, Qdrant)
//!   `EmbeddingBackend` — pluggable text → vector (implementors: `NoopEmbedding`, future: MiniLM, OpenAI)
//!
//! Default backend: `KeywordIndex` — TF-IDF-like keyword scoring, zero dependencies.
//! T2+: swap in `SqliteVecIndex` (sqlite-vec extension) or `QdrantIndex` via the trait.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── EmbeddingBackend trait ─────────────────────────────────────────────────────

/// Converts text into a float vector for similarity search.
pub trait EmbeddingBackend: Send + Sync {
    fn embed(&self, text: &str) -> Vec<f32>;
    fn dimensions(&self) -> usize;
    fn name(&self) -> &'static str;
}

/// No-op embedding backend — returns a zero vector.
/// Used when no embedding model is configured; falls back to keyword scoring.
pub struct NoopEmbedding;

impl EmbeddingBackend for NoopEmbedding {
    fn embed(&self, _text: &str) -> Vec<f32> { vec![0.0; 64] }
    fn dimensions(&self) -> usize { 64 }
    fn name(&self) -> &'static str { "noop" }
}

// ── VectorIndex trait ──────────────────────────────────────────────────────────

/// A document stored in the vector index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedDoc {
    /// CID of the source MemPacket
    pub cid: String,
    /// Namespace this doc belongs to
    pub namespace: String,
    /// Text content used for embedding / keyword scoring
    pub text: String,
    /// Similarity score (filled by query, 0.0–1.0)
    pub score: f32,
    /// Arbitrary metadata (packet_type, agent_pid, ts_ms, etc.)
    pub metadata: serde_json::Value,
}

/// Pluggable vector index trait.
///
/// Implementors must be `Send + Sync` so the kernel can hold them behind a `Mutex`.
pub trait VectorIndex: Send + Sync {
    /// Upsert a document. Overwrites existing doc with same CID.
    fn upsert(&mut self, doc: IndexedDoc);
    /// Remove a document by CID.
    fn remove(&mut self, cid: &str);
    /// Query for the top-k most similar documents to `query` in `namespace`.
    /// Returns results sorted by score descending.
    fn query(&self, query: &str, namespace: &str, top_k: usize) -> Vec<IndexedDoc>;
    /// Name of this backend (for logging / debug).
    fn backend_name(&self) -> &'static str;
}

// ── KeywordIndex (default T0/T1 backend) ─────────────────────────────────────

/// Keyword-based similarity index — TF-IDF-style term overlap scoring.
///
/// Zero external dependencies. Scores = `|query_terms ∩ doc_terms| / |query_terms|`.
/// Good enough for short episodic/semantic text (agent logs, tool results, reflections).
/// Replace with `SqliteVecIndex` for semantic search in T2+.
pub struct KeywordIndex {
    /// namespace → cid → IndexedDoc
    docs: HashMap<String, HashMap<String, IndexedDoc>>,
}

impl KeywordIndex {
    pub fn new() -> Self {
        Self { docs: HashMap::new() }
    }

    fn tokenize(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 2)
            .map(|t| t.to_string())
            .collect()
    }

    fn score(query_tokens: &[String], doc_tokens: &[String]) -> f32 {
        if query_tokens.is_empty() { return 0.0; }
        let matches = query_tokens.iter()
            .filter(|qt| doc_tokens.iter().any(|dt| dt == *qt))
            .count();
        matches as f32 / query_tokens.len() as f32
    }
}

impl Default for KeywordIndex {
    fn default() -> Self { Self::new() }
}

impl VectorIndex for KeywordIndex {
    fn upsert(&mut self, doc: IndexedDoc) {
        self.docs
            .entry(doc.namespace.clone())
            .or_default()
            .insert(doc.cid.clone(), doc);
    }

    fn remove(&mut self, cid: &str) {
        for ns_docs in self.docs.values_mut() {
            ns_docs.remove(cid);
        }
    }

    fn query(&self, query: &str, namespace: &str, top_k: usize) -> Vec<IndexedDoc> {
        let query_tokens = Self::tokenize(query);
        let empty = HashMap::new();
        let ns_docs = self.docs.get(namespace).unwrap_or(&empty);

        let mut scored: Vec<IndexedDoc> = ns_docs.values()
            .map(|doc| {
                let doc_tokens = Self::tokenize(&doc.text);
                let score = Self::score(&query_tokens, &doc_tokens);
                let mut d = doc.clone();
                d.score = score;
                d
            })
            .filter(|d| d.score > 0.0)
            .collect();

        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        scored
    }

    fn backend_name(&self) -> &'static str { "keyword" }
}

// ── Shared / background-safe index (P2: out of MemoryKernel exclusive lock) ─

/// Thread-safe vector index with readiness gating.
///
/// Talk recall uses `query_if_ready` — returns empty when cold or under write
/// rebuild, never blocks the fleet on index construction.
pub struct SharedVectorIndex {
    inner: std::sync::RwLock<Box<dyn VectorIndex>>,
    ready: std::sync::atomic::AtomicBool,
}

impl SharedVectorIndex {
    pub fn new(index: Box<dyn VectorIndex>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            inner: std::sync::RwLock::new(index),
            // Empty KeywordIndex is immediately queryable.
            ready: std::sync::atomic::AtomicBool::new(true),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn mark_not_ready(&self) {
        self.ready
            .store(false, std::sync::atomic::Ordering::Release);
    }

    pub fn mark_ready(&self) {
        self.ready
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Non-blocking recall: empty if index is cold or write-locked.
    pub fn query_if_ready(&self, query: &str, namespace: &str, top_k: usize) -> Vec<IndexedDoc> {
        if !self.is_ready() {
            return Vec::new();
        }
        match self.inner.try_read() {
            Ok(g) => g.query(query, namespace, top_k),
            Err(_) => Vec::new(),
        }
    }

    pub fn upsert(&self, doc: IndexedDoc) {
        if let Ok(mut g) = self.inner.write() {
            g.upsert(doc);
        }
    }

    /// Replace contents with a fresh KeywordIndex and mark ready.
    pub fn rebuild_with_docs(&self, docs: Vec<IndexedDoc>) {
        self.mark_not_ready();
        if let Ok(mut g) = self.inner.write() {
            *g = Box::new(KeywordIndex::new());
            for doc in docs {
                g.upsert(doc);
            }
        }
        self.mark_ready();
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner
            .read()
            .map(|g| g.backend_name())
            .unwrap_or("unavailable")
    }
}

// ── AMA-3: CompositeDistance ──────────────────────────────────────────────────

/// AMA-3: Composite retrieval distance — blends semantic, temporal, causal, structural, trust.
///
/// Final distance: `D = α·D_semantic + β·D_temporal + γ·D_causal + δ·D_struct + ε·D_trust`
/// where all weights sum to 1.0 (normalised in `retrieve_composite`).
#[derive(Debug, Clone)]
pub struct CompositeDistance {
    /// Semantic similarity weight (default 0.50)
    pub alpha: f32,
    /// Temporal recency weight (default 0.20)
    pub beta: f32,
    /// Causal chain distance weight (default 0.10)
    pub gamma: f32,
    /// Structural proximity weight (default 0.10)
    pub delta: f32,
    /// Trust score weight (default 0.10)
    pub epsilon: f32,
}

impl Default for CompositeDistance {
    fn default() -> Self {
        Self { alpha: 0.50, beta: 0.20, gamma: 0.10, delta: 0.10, epsilon: 0.10 }
    }
}

impl CompositeDistance {
    /// Compute the composite score for a candidate document.
    ///
    /// - `semantic_score`: keyword/embedding similarity (0.0–1.0, higher = closer)
    /// - `ts_ms`: packet timestamp in epoch milliseconds
    /// - `now_ms`: current time in epoch milliseconds
    /// - `decay_window_ms`: temporal decay window (default: 7 days = 604_800_000 ms)
    /// - `causal_hops`: number of causal chain links to query origin (0 = direct cause)
    /// - `struct_hops`: number of graph_links hops (0 = direct neighbor)
    /// - `trust_score`: packet trust_score field (0.0–1.0)
    pub fn score(
        &self,
        semantic_score: f32,
        ts_ms: i64,
        now_ms: i64,
        decay_window_ms: i64,
        causal_hops: u32,
        struct_hops: u32,
        trust_score: f32,
    ) -> f32 {
        // D_temporal: recency penalty — older packets score lower
        let age_ms = (now_ms - ts_ms).max(0) as f32;
        let d_temporal = 1.0 - (age_ms / decay_window_ms.max(1) as f32).min(1.0);

        // D_causal: fewer hops = closer (0 hops = 1.0, each hop halves)
        let d_causal = 1.0 / (1.0 + causal_hops as f32);

        // D_struct: structural proximity
        let d_struct = 1.0 / (1.0 + struct_hops as f32);

        // D_trust: direct from packet
        let d_trust = trust_score.clamp(0.0, 1.0);

        // Normalise weights
        let total = self.alpha + self.beta + self.gamma + self.delta + self.epsilon;
        let (α, β, γ, δ, ε) = if total > 0.0 {
            (self.alpha / total, self.beta / total, self.gamma / total,
             self.delta / total, self.epsilon / total)
        } else {
            (0.2, 0.2, 0.2, 0.2, 0.2)
        };

        α * semantic_score + β * d_temporal + γ * d_causal + δ * d_struct + ε * d_trust
    }
}

/// AMA-3: Composite retrieval over a `VectorIndex`.
///
/// Runs keyword query, then re-scores results using `CompositeDistance`.
/// `doc_ts_fn`: closure mapping CID → timestamp_ms (from kernel packet store).
/// `doc_trust_fn`: closure mapping CID → trust_score.
pub fn retrieve_composite(
    index: &dyn VectorIndex,
    query: &str,
    namespace: &str,
    top_k: usize,
    weights: &CompositeDistance,
    now_ms: i64,
    decay_window_ms: i64,
    doc_ts_fn: impl Fn(&str) -> i64,
    doc_trust_fn: impl Fn(&str) -> f32,
) -> Vec<IndexedDoc> {
    // Step 1: semantic candidates (up to 4× top_k for re-ranking)
    let candidates = index.query(query, namespace, top_k * 4);

    // Step 2: composite re-score
    let mut rescored: Vec<IndexedDoc> = candidates.into_iter().map(|mut doc| {
        let ts = doc_ts_fn(&doc.cid);
        let trust = doc_trust_fn(&doc.cid);
        doc.score = weights.score(doc.score, ts, now_ms, decay_window_ms, 0, 0, trust);
        doc
    }).collect();

    // Step 3: sort by composite score descending
    rescored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    rescored.truncate(top_k);
    rescored
}
