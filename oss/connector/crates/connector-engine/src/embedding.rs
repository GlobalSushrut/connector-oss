//! AMA-4: EmbeddingBackend trait — pluggable text embedding for offline retrieval.
//!
//! Agents cannot be migrated to regions without LLM access and still retrieve memories
//! unless embeddings are stored on MemPacket at write time.
//!
//! Backends:
//!   - `LocalMiniLMBackend`  — zero API call; deterministic hash-based stub (real ONNX at T2)
//!   - `OpenAIEmbeddingBackend` — text-embedding-3-small via OpenAI API
//!   - `OllamaEmbeddingBackend` — local Ollama instance (nomic-embed-text default)

use std::sync::Arc;

// =============================================================================
// Core trait
// =============================================================================

/// Synchronous embedding backend — produces a fixed-dimension float vector from text.
pub trait EmbeddingBackend: Send + Sync {
    /// Model identifier / backend name (e.g. "all-MiniLM-L6-v2", "text-embedding-3-small")
    fn model_id(&self) -> &str;

    /// Output dimension of this backend's embeddings
    fn dim(&self) -> usize;

    /// Embed a single text string.  Returns `Err` only on hard failure (network error,
    /// model not loaded).  Never panics.
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;

    /// Batch embed — default impl calls `embed` per item; override for efficiency.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
}

// =============================================================================
// Error type
// =============================================================================

#[derive(Debug, Clone)]
pub enum EmbeddingError {
    /// Model / ONNX runtime not available
    ModelNotLoaded(String),
    /// Network / HTTP error (OpenAI / Ollama backends)
    NetworkError(String),
    /// Input text is empty — callers should skip embedding empty packets
    EmptyInput,
    /// Response parse error
    ParseError(String),
}

impl std::fmt::Display for EmbeddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbeddingError::ModelNotLoaded(m) => write!(f, "model not loaded: {}", m),
            EmbeddingError::NetworkError(e)   => write!(f, "network error: {}", e),
            EmbeddingError::EmptyInput         => write!(f, "empty input text"),
            EmbeddingError::ParseError(e)      => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for EmbeddingError {}

// =============================================================================
// AMA-4 Backend 1: LocalMiniLMBackend
// Zero-dependency stub that produces deterministic 384-dim pseudo-embeddings.
// Production: swap body for ONNX inference via `ort` crate (T2 milestone).
// =============================================================================

/// Local embedding backend — deterministic 384-dim hash-based stub.
/// In production this will load `all-MiniLM-L6-v2` via ONNX Runtime.
/// The stub is *deterministic*: same text → same vector, enabling offline comparison.
pub struct LocalMiniLMBackend {
    dim: usize,
}

impl LocalMiniLMBackend {
    pub fn new() -> Self {
        Self { dim: 384 }
    }
}

impl Default for LocalMiniLMBackend {
    fn default() -> Self { Self::new() }
}

impl EmbeddingBackend for LocalMiniLMBackend {
    fn model_id(&self) -> &str { "all-MiniLM-L6-v2-stub" }
    fn dim(&self) -> usize { self.dim }

    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() { return Err(EmbeddingError::EmptyInput); }

        // Deterministic pseudo-embedding using FNV-1a inspired mixing.
        // Each dimension is seeded from (text_hash XOR dim_index) to spread values across [-1,1].
        let base: u64 = text.bytes().fold(0xcbf29ce484222325u64, |h, b| {
            h.wrapping_mul(0x100000001b3).wrapping_add(b as u64)
        });

        let vec: Vec<f32> = (0..self.dim)
            .map(|i| {
                let mixed = base
                    .wrapping_mul(i as u64 + 1)
                    .wrapping_add(0x9e3779b97f4a7c15);
                // Map to [-1, 1] via bit manipulation
                let raw = ((mixed >> 33) as f32) / (u32::MAX as f32);
                raw * 2.0 - 1.0
            })
            .collect();

        // L2-normalize
        let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
        Ok(vec.into_iter().map(|x| x / norm).collect())
    }
}

// =============================================================================
// AMA-4 Backend 2: OpenAIEmbeddingBackend
// Calls text-embedding-3-small synchronously (blocks on reqwest blocking client).
// Set OPENAI_API_KEY env var.
// =============================================================================

pub struct OpenAIEmbeddingBackend {
    api_key: String,
    model: String,
    dim: usize,
}

impl OpenAIEmbeddingBackend {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            model: "text-embedding-3-small".into(),
            dim: 1536,
        }
    }

    pub fn with_model(mut self, model: impl Into<String>, dim: usize) -> Self {
        self.model = model.into();
        self.dim = dim;
        self
    }

    pub fn from_env() -> Option<Self> {
        std::env::var("OPENAI_API_KEY").ok().map(Self::new)
    }
}

impl EmbeddingBackend for OpenAIEmbeddingBackend {
    fn model_id(&self) -> &str { &self.model }
    fn dim(&self) -> usize { self.dim }

    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() { return Err(EmbeddingError::EmptyInput); }

        // Use reqwest blocking (safe inside a tokio::task::spawn_blocking context).
        let client = reqwest::blocking::Client::new();
        let body = serde_json::json!({
            "model": self.model,
            "input": text,
        });

        let resp = client
            .post("https://api.openai.com/v1/embeddings")
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .map_err(|e| EmbeddingError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(EmbeddingError::NetworkError(format!("HTTP {}: {}", status, text)));
        }

        let json: serde_json::Value = resp.json()
            .map_err(|e| EmbeddingError::ParseError(e.to_string()))?;

        let embedding: Vec<f32> = json["data"][0]["embedding"]
            .as_array()
            .ok_or_else(|| EmbeddingError::ParseError("missing data[0].embedding".into()))?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if embedding.is_empty() {
            return Err(EmbeddingError::ParseError("empty embedding array".into()));
        }

        Ok(embedding)
    }
}

// =============================================================================
// AMA-4 Backend 3: OllamaEmbeddingBackend
// Uses local Ollama instance (default: nomic-embed-text, 768-dim).
// Set OLLAMA_HOST env var (default: http://localhost:11434).
// =============================================================================

pub struct OllamaEmbeddingBackend {
    host: String,
    model: String,
    dim: usize,
}

impl OllamaEmbeddingBackend {
    pub fn new(host: impl Into<String>, model: impl Into<String>, dim: usize) -> Self {
        Self { host: host.into(), model: model.into(), dim }
    }

    pub fn default_nomic() -> Self {
        let host = std::env::var("OLLAMA_HOST")
            .unwrap_or_else(|_| "http://localhost:11434".into());
        Self::new(host, "nomic-embed-text", 768)
    }

    pub fn from_env() -> Option<Self> {
        // Only activate if OLLAMA_HOST or OLLAMA_EMBED_MODEL is explicitly set
        let host = std::env::var("OLLAMA_HOST").ok()?;
        let model = std::env::var("OLLAMA_EMBED_MODEL")
            .unwrap_or_else(|_| "nomic-embed-text".into());
        let dim = std::env::var("OLLAMA_EMBED_DIM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(768usize);
        Some(Self::new(host, model, dim))
    }
}

impl EmbeddingBackend for OllamaEmbeddingBackend {
    fn model_id(&self) -> &str { &self.model }
    fn dim(&self) -> usize { self.dim }

    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() { return Err(EmbeddingError::EmptyInput); }

        let client = reqwest::blocking::Client::new();
        let body = serde_json::json!({
            "model": self.model,
            "prompt": text,
        });

        let url = format!("{}/api/embeddings", self.host);
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| EmbeddingError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(EmbeddingError::NetworkError(format!("HTTP {}: {}", status, text)));
        }

        let json: serde_json::Value = resp.json()
            .map_err(|e| EmbeddingError::ParseError(e.to_string()))?;

        let embedding: Vec<f32> = json["embedding"]
            .as_array()
            .ok_or_else(|| EmbeddingError::ParseError("missing embedding field".into()))?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if embedding.is_empty() {
            return Err(EmbeddingError::ParseError("empty embedding array".into()));
        }

        Ok(embedding)
    }
}

// =============================================================================
// EmbeddingRegistry — selects backend based on config / env
// =============================================================================

/// Shared embedding registry — wraps selected backend behind Arc for kernel use.
pub struct EmbeddingRegistry {
    pub backend: Arc<dyn EmbeddingBackend>,
}

impl EmbeddingRegistry {
    /// Build from environment:
    ///   OPENAI_API_KEY set  → OpenAI text-embedding-3-small
    ///   OLLAMA_HOST set     → Ollama nomic-embed-text
    ///   otherwise           → LocalMiniLMBackend (deterministic stub)
    pub fn from_env() -> Self {
        if let Some(openai) = OpenAIEmbeddingBackend::from_env() {
            eprintln!("[embedding] OpenAI backend selected ({})", openai.model_id());
            return Self { backend: Arc::new(openai) };
        }
        if let Some(ollama) = OllamaEmbeddingBackend::from_env() {
            eprintln!("[embedding] Ollama backend selected ({})", ollama.model_id());
            return Self { backend: Arc::new(ollama) };
        }
        eprintln!("[embedding] LocalMiniLM stub backend selected (set OPENAI_API_KEY or OLLAMA_HOST for real embeddings)");
        Self { backend: Arc::new(LocalMiniLMBackend::new()) }
    }

    pub fn model_id(&self) -> &str { self.backend.model_id() }
    pub fn dim(&self) -> usize { self.backend.dim() }

    pub fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.backend.embed(text)
    }
}
