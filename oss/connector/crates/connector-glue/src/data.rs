//! Data contracts for GLUE memory and knowledge operations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataInjection {
    Text(String),
    Json(serde_json::Value),
    Binary(Vec<u8>),
    PacketRefs(Vec<String>),
    BlobRef {
        uri: String,
        content_type: Option<String>,
    },
    AssetContainer {
        container_id: String,
        asset_ids: Vec<String>,
    },
    S3Object {
        bucket: String,
        key: String,
        version: Option<String>,
    },
    StreamBatch {
        stream: String,
        offset: Option<u64>,
        count: Option<usize>,
    },
    NamespaceSnapshot {
        namespace: String,
        limit: Option<usize>,
    },
}

impl DataInjection {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Json(_) => "json",
            Self::Binary(_) => "binary",
            Self::PacketRefs(_) => "packet_refs",
            Self::BlobRef { .. } => "blob_ref",
            Self::AssetContainer { .. } => "asset_container",
            Self::S3Object { .. } => "s3_object",
            Self::StreamBatch { .. } => "stream_batch",
            Self::NamespaceSnapshot { .. } => "namespace_snapshot",
        }
    }
    pub fn estimated_size_bytes(&self) -> usize {
        match self {
            Self::Text(v) => v.len(),
            Self::Json(v) => serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0),
            Self::Binary(v) => v.len(),
            Self::PacketRefs(v) => v.len() * 64,
            Self::BlobRef { uri, .. } => uri.len(),
            Self::AssetContainer { asset_ids, .. } => asset_ids.len() * 64,
            Self::S3Object { bucket, key, version } => bucket.len() + key.len() + version.as_deref().unwrap_or("").len(),
            Self::StreamBatch { .. } => 0,
            Self::NamespaceSnapshot { namespace, .. } => namespace.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVisibility {
    Private,
    Session,
    Shared,
    Ephemeral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryContract {
    pub namespace: String,
    pub visibility: MemoryVisibility,
    pub packet_type: String,
    pub memory_type: Option<String>,
    pub session_id: Option<String>,
    pub tags: Vec<String>,
    pub auto_enrich: bool,
    pub contradiction_check: bool,
}

impl MemoryContract {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: normalize_memory_namespace(namespace.into()),
            visibility: MemoryVisibility::Private,
            packet_type: "input".into(),
            memory_type: None,
            session_id: None,
            tags: Vec::new(),
            auto_enrich: true,
            contradiction_check: true,
        }
    }

    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.visibility = MemoryVisibility::Session;
        self.session_id = Some(session_id.into());
        self
    }

    pub fn packet_type(mut self, packet_type: impl Into<String>) -> Self {
        self.packet_type = packet_type.into();
        self
    }

    pub fn memory_type(mut self, memory_type: impl Into<String>) -> Self {
        self.memory_type = Some(memory_type.into());
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeStorageTier {
    Graph,
    ObjectStore,
    Stream,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KnowledgeSource {
    Namespace(String),
    Injection(DataInjection),
    CompiledKnowledge(String),
    Seed(String),
}

impl KnowledgeSource {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Namespace(_) => "namespace",
            Self::Injection(i) => i.kind(),
            Self::CompiledKnowledge(_) => "compiled_knowledge",
            Self::Seed(_) => "seed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeContract {
    pub namespace: String,
    pub source: KnowledgeSource,
    pub token_budget: usize,
    pub max_facts: usize,
    pub graph_ingest: bool,
    pub contradiction_detection: bool,
    pub storage_tier: KnowledgeStorageTier,
}

impl KnowledgeContract {
    pub fn new(namespace: impl Into<String>, source: KnowledgeSource) -> Self {
        Self {
            namespace: normalize_knowledge_namespace(namespace.into()),
            source,
            token_budget: 4096,
            max_facts: 20,
            graph_ingest: true,
            contradiction_detection: true,
            storage_tier: KnowledgeStorageTier::Hybrid,
        }
    }

    pub fn token_budget(mut self, token_budget: usize) -> Self {
        self.token_budget = token_budget;
        self
    }

    pub fn max_facts(mut self, max_facts: usize) -> Self {
        self.max_facts = max_facts;
        self
    }

    pub fn storage_tier(mut self, tier: KnowledgeStorageTier) -> Self {
        self.storage_tier = tier;
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeQuery {
    pub entities: Vec<String>,
    pub keywords: Vec<String>,
    pub token_budget: Option<usize>,
    pub max_facts: Option<usize>,
}

impl KnowledgeQuery {
    pub fn entity(mut self, entity: impl Into<String>) -> Self {
        self.entities.push(entity.into());
        self
    }

    pub fn keyword(mut self, keyword: impl Into<String>) -> Self {
        self.keywords.push(keyword.into());
        self
    }
}

pub fn normalize_memory_namespace(namespace: String) -> String {
    let trimmed = namespace.trim_start_matches('/').to_string();
    if trimmed.starts_with("m/") || trimmed.starts_with("k/") {
        trimmed
    } else {
        format!("m/{}", trimmed)
    }
}

pub fn normalize_knowledge_namespace(namespace: String) -> String {
    let trimmed = namespace.trim_start_matches('/').to_string();
    if trimmed.starts_with("k/") || trimmed.starts_with("m/") {
        trimmed
    } else {
        format!("k/{}", trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_memory_namespace() {
        assert_eq!(normalize_memory_namespace("claims".into()), "m/claims");
        assert_eq!(normalize_memory_namespace("/m/claims".into()), "m/claims");
    }

    #[test]
    fn normalizes_knowledge_namespace() {
        assert_eq!(normalize_knowledge_namespace("medical".into()), "k/medical");
        assert_eq!(normalize_knowledge_namespace("/k/medical".into()), "k/medical");
    }
}
