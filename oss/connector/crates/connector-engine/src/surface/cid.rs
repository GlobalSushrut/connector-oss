//! CID-Based Content Addressing — Every surface is content-addressed
//!
//! Following CNP/CLS patterns: surfaces get deterministic CIDs for caching,
//! deduplication, and proof chains.

use super::document::SurfaceDocument;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Content identifier for a surface document
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SurfaceCid {
    pub hash: String,
    pub version: u8,
}

impl SurfaceCid {
    /// Compute CID from surface document
    pub fn from_document(doc: &SurfaceDocument) -> Self {
        let canonical = serde_json::to_string(doc).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let hash = hasher.finalize();
        Self {
            hash: format!("soe1-sha256-{}", hex::encode(&hash[..16])),
            version: 1,
        }
    }

    /// Parse CID from string
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("soe1-sha256-") {
            Some(Self { hash: s.to_string(), version: 1 })
        } else {
            None
        }
    }

    /// Short display (first 12 chars of hash)
    pub fn short(&self) -> String {
        if self.hash.len() > 20 {
            format!("{}...", &self.hash[..20])
        } else {
            self.hash.clone()
        }
    }
}

impl std::fmt::Display for SurfaceCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}

/// Content-addressed surface with CID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressedSurface {
    pub cid: SurfaceCid,
    pub document: SurfaceDocument,
    pub generated_at: i64,
    pub ttl_ms: Option<u64>,
}

impl AddressedSurface {
    pub fn new(document: SurfaceDocument) -> Self {
        let cid = SurfaceCid::from_document(&document);
        Self {
            cid,
            document,
            generated_at: chrono::Utc::now().timestamp_millis(),
            ttl_ms: Some(60_000), // 1 minute default TTL
        }
    }

    pub fn with_ttl(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = Some(ttl_ms);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl_ms {
            let now = chrono::Utc::now().timestamp_millis();
            now - self.generated_at > ttl as i64
        } else {
            false
        }
    }
}

/// Surface cache with CID-based deduplication
pub struct SurfaceCache {
    entries: std::collections::HashMap<String, AddressedSurface>,
    max_entries: usize,
}

impl Default for SurfaceCache {
    fn default() -> Self { Self::new(1000) }
}

impl SurfaceCache {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: std::collections::HashMap::new(), max_entries }
    }

    pub fn get(&self, cid: &SurfaceCid) -> Option<&AddressedSurface> {
        self.entries.get(&cid.hash).filter(|s| !s.is_expired())
    }

    pub fn put(&mut self, surface: AddressedSurface) {
        if self.entries.len() >= self.max_entries {
            // Evict oldest
            let oldest = self.entries.iter()
                .min_by_key(|(_, s)| s.generated_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                self.entries.remove(&key);
            }
        }
        self.entries.insert(surface.cid.hash.clone(), surface);
    }

    pub fn invalidate(&mut self, cid: &SurfaceCid) {
        self.entries.remove(&cid.hash);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::builder::SurfaceBuilder;

    #[test]
    fn test_surface_cid() {
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").build();
        let cid = SurfaceCid::from_document(&doc);
        assert!(cid.hash.starts_with("soe1-sha256-"));
    }

    #[test]
    fn test_addressed_surface() {
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").build();
        let addressed = AddressedSurface::new(doc);
        assert!(!addressed.is_expired());
    }

    #[test]
    fn test_cache() {
        let mut cache = SurfaceCache::new(10);
        let doc = SurfaceBuilder::agent("test").judgment_ok("OK").build();
        let addressed = AddressedSurface::new(doc);
        let cid = addressed.cid.clone();
        cache.put(addressed);
        assert!(cache.get(&cid).is_some());
    }
}
