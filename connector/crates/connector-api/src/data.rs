//! Data Plane — RAG, vector stores, embeddings configuration.
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! let pipe = Connector::pipeline("research")
//!     .data(|d| d
//!         .memory("postgres://host/db")
//!         .rag("docs", |r| r.source("./documents/").chunk_size(512))
//!         .vector_store("qdrant", "localhost:6333")
//!         .embeddings("openai", "text-embedding-3-small", "sk-...")
//!     )
//!     .build();
//! ```

use serde::{Deserialize, Serialize};

/// Data plane configuration — where information lives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataConfig {
    /// Memory store connection string
    pub memory_store: Option<String>,
    /// RAG pipeline configurations
    pub rag_pipelines: Vec<RagConfig>,
    /// Vector store configuration
    pub vector_store: Option<VectorStoreConfig>,
    /// Embedding model configuration
    pub embeddings: Option<EmbeddingConfig>,
}

/// RAG pipeline configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagConfig {
    /// Pipeline name
    pub name: String,
    /// Document sources (file paths or URLs)
    pub sources: Vec<String>,
    /// Chunk size in tokens
    pub chunk_size: usize,
    /// Chunk overlap in tokens
    pub chunk_overlap: usize,
    /// Top-K results to return
    pub top_k: usize,
    /// Minimum similarity score (0.0-1.0)
    pub min_score: f64,
    /// Enable reranking
    pub rerank: bool,
}

impl Default for RagConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            sources: Vec::new(),
            chunk_size: 512,
            chunk_overlap: 50,
            top_k: 5,
            min_score: 0.5,
            rerank: false,
        }
    }
}

/// Vector store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreConfig {
    /// Provider (qdrant, pinecone, weaviate, chroma, pgvector)
    pub provider: String,
    /// Connection URL
    pub url: String,
    /// Collection/index name
    pub collection: Option<String>,
    /// API key (for managed services)
    pub api_key: Option<String>,
}

/// Embedding model configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Provider (openai, cohere, local)
    pub provider: String,
    /// Model name
    pub model: String,
    /// API key
    pub api_key: String,
    /// Embedding dimensions (auto-detected if None)
    pub dimensions: Option<usize>,
}

/// Builder for DataConfig.
pub struct DataBuilder {
    config: DataConfig,
}

impl DataBuilder {
    pub fn new() -> Self {
        Self {
            config: DataConfig::default(),
        }
    }

    /// Set memory store connection.
    pub fn memory(mut self, connection: &str) -> Self {
        self.config.memory_store = Some(connection.to_string());
        self
    }

    /// Add a RAG pipeline.
    pub fn rag<F>(mut self, name: &str, f: F) -> Self
    where
        F: FnOnce(RagBuilder) -> RagBuilder,
    {
        let builder = f(RagBuilder::new(name));
        self.config.rag_pipelines.push(builder.build());
        self
    }

    /// Set vector store.
    pub fn vector_store(mut self, provider: &str, url: &str) -> Self {
        self.config.vector_store = Some(VectorStoreConfig {
            provider: provider.to_string(),
            url: url.to_string(),
            collection: None,
            api_key: None,
        });
        self
    }

    /// Set vector store with full config.
    pub fn vector_store_full(mut self, provider: &str, url: &str, collection: &str, api_key: &str) -> Self {
        self.config.vector_store = Some(VectorStoreConfig {
            provider: provider.to_string(),
            url: url.to_string(),
            collection: Some(collection.to_string()),
            api_key: Some(api_key.to_string()),
        });
        self
    }

    /// Set embedding model (cloud).
    pub fn embeddings(mut self, provider: &str, model: &str, api_key: &str) -> Self {
        self.config.embeddings = Some(EmbeddingConfig {
            provider: provider.to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            dimensions: None,
        });
        self
    }

    /// Use local TF-IDF embeddings (no API calls, works offline).
    pub fn embeddings_local(mut self) -> Self {
        self.config.embeddings = Some(EmbeddingConfig {
            provider: "local".to_string(),
            model: "tfidf".to_string(),
            api_key: String::new(),
            dimensions: None,
        });
        self
    }

    pub fn build(self) -> DataConfig {
        self.config
    }
}

/// Builder for RagConfig.
pub struct RagBuilder {
    config: RagConfig,
}

impl RagBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            config: RagConfig {
                name: name.to_string(),
                ..Default::default()
            },
        }
    }

    /// Add a document source (file path or URL).
    pub fn source(mut self, path: &str) -> Self {
        self.config.sources.push(path.to_string());
        self
    }

    /// Set chunk size in tokens.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.config.chunk_size = size;
        self
    }

    /// Set chunk overlap in tokens.
    pub fn chunk_overlap(mut self, overlap: usize) -> Self {
        self.config.chunk_overlap = overlap;
        self
    }

    /// Set top-K results.
    pub fn top_k(mut self, k: usize) -> Self {
        self.config.top_k = k;
        self
    }

    /// Set minimum similarity score.
    pub fn min_score(mut self, score: f64) -> Self {
        self.config.min_score = score;
        self
    }

    /// Enable reranking.
    pub fn rerank(mut self, enabled: bool) -> Self {
        self.config.rerank = enabled;
        self
    }

    pub fn build(self) -> RagConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_builder() {
        let data = DataBuilder::new()
            .memory("postgres://host/db")
            .rag("docs", |r| r
                .source("./documents/")
                .source("https://docs.example.com")
                .chunk_size(512)
                .top_k(10)
                .rerank(true)
            )
            .vector_store("qdrant", "localhost:6333")
            .embeddings("openai", "text-embedding-3-small", "sk-test")
            .build();

        assert_eq!(data.memory_store.as_deref(), Some("postgres://host/db"));
        assert_eq!(data.rag_pipelines.len(), 1);
        assert_eq!(data.rag_pipelines[0].name, "docs");
        assert_eq!(data.rag_pipelines[0].sources.len(), 2);
        assert_eq!(data.rag_pipelines[0].chunk_size, 512);
        assert!(data.rag_pipelines[0].rerank);
        assert_eq!(data.vector_store.as_ref().unwrap().provider, "qdrant");
        assert_eq!(data.embeddings.as_ref().unwrap().provider, "openai");
    }

    #[test]
    fn test_local_embeddings() {
        let data = DataBuilder::new()
            .embeddings_local()
            .build();

        assert_eq!(data.embeddings.as_ref().unwrap().provider, "local");
        assert_eq!(data.embeddings.as_ref().unwrap().model, "tfidf");
    }

    #[test]
    fn test_multiple_rag_pipelines() {
        let data = DataBuilder::new()
            .rag("docs", |r| r.source("./docs/"))
            .rag("papers", |r| r.source("./papers/").chunk_size(1024))
            .build();

        assert_eq!(data.rag_pipelines.len(), 2);
        assert_eq!(data.rag_pipelines[0].name, "docs");
        assert_eq!(data.rag_pipelines[1].name, "papers");
        assert_eq!(data.rag_pipelines[1].chunk_size, 1024);
    }
}
