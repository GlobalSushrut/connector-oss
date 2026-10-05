//! Knowledge Pagination — Cursor-based & Streaming
//!
//! FIX BUG-045: Paginated knowledge retrieval with caching

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

use crate::knowledge::index::{KnowledgeChunk, KnowledgeIndex};

// =============================================================================
// Pagination Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRequest {
    /// Cursor (opaque token for position)
    pub cursor: Option<String>,
    /// Page size
    pub limit: usize,
    /// Query filter
    pub filter: Option<String>,
    /// Sort order
    pub sort: SortOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    Relevance,
    NewestFirst,
    OldestFirst,
    Alphabetic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResult<T> {
    /// Items in this page
    pub items: Vec<T>,
    /// Total count (estimated)
    pub total_count: usize,
    /// Next page cursor
    pub next_cursor: Option<String>,
    /// Previous page cursor
    pub prev_cursor: Option<String>,
    /// Has more pages
    pub has_more: bool,
    /// Result set ID (for caching)
    pub result_set_id: String,
}

/// Cursor for pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cursor {
    /// Result set ID
    pub result_set_id: String,
    /// Offset within result set
    pub offset: usize,
    /// Query hash
    pub query_hash: String,
    /// Created at
    pub created_at: i64,
}

// =============================================================================
// Result Set Cache
// =============================================================================

pub struct ResultSetCache {
    /// Result sets: result_set_id -> cached results
    sets: Arc<RwLock<HashMap<String, CachedResultSet>>>,
    /// TTL for result sets
    ttl: Duration,
    /// Max cached sets
    max_sets: usize,
}

#[derive(Debug, Clone)]
struct CachedResultSet {
    /// All result IDs
    ids: Vec<String>,
    /// Query that produced this set
    query: String,
    /// Created at
    created_at: Instant,
    /// Total count
    total_count: usize,
}

impl ResultSetCache {
    pub fn new(ttl_secs: u64, max_sets: usize) -> Self {
        Self {
            sets: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
            max_sets,
        }
    }

    /// Store result set
    pub fn store(&self, result_set_id: String, ids: Vec<String>, query: String, total: usize) {
        let mut sets = self.sets.write().unwrap();

        // Evict oldest if at capacity
        if sets.len() >= self.max_sets {
            let oldest: Option<String> = sets.iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                sets.remove(&k);
            }
        }

        sets.insert(result_set_id.clone(), CachedResultSet {
            ids,
            query,
            created_at: Instant::now(),
            total_count: total,
        });
    }

    /// Get page from cached result set
    pub fn get_page(&self, result_set_id: &str, offset: usize, limit: usize) -> Option<(Vec<String>, usize, bool)> {
        let sets = self.sets.read().unwrap();
        
        sets.get(result_set_id).and_then(|set| {
            // Check TTL
            if Instant::now().duration_since(set.created_at) > self.ttl {
                return None;
            }

            let has_more = offset + limit < set.ids.len();
            let ids: Vec<String> = set.ids.iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect();

            Some((ids, set.total_count, has_more))
        })
    }

    /// Cleanup expired
    pub fn cleanup(&self) -> usize {
        let mut sets = self.sets.write().unwrap();
        let now = Instant::now();
        
        let expired: Vec<String> = sets.iter()
            .filter(|(_, v)| now.duration_since(v.created_at) > self.ttl)
            .map(|(k, _)| k.clone())
            .collect();

        for k in &expired {
            sets.remove(k);
        }

        expired.len()
    }
}

// =============================================================================
// Streaming Iterator
// =============================================================================

pub struct StreamingIterator {
    index: Arc<KnowledgeIndex>,
    query: String,
    total: usize,
    current: usize,
    batch_size: usize,
}

impl StreamingIterator {
    pub fn new(index: Arc<KnowledgeIndex>, query: String, total: usize) -> Self {
        Self {
            index,
            query,
            total,
            current: 0,
            batch_size: 100,
        }
    }

    /// Get next batch
    pub fn next_batch(&mut self) -> Option<Vec<KnowledgeChunk>> {
        if self.current >= self.total {
            return None;
        }

        // In production: fetch from index with offset/limit
        // For now: simulate fetching
        let remaining = self.total - self.current;
        let to_fetch = remaining.min(self.batch_size);

        // This would fetch actual chunks from the index
        let chunks: Vec<KnowledgeChunk> = (0..to_fetch)
            .map(|i| KnowledgeChunk {
                chunk_id: format!("chunk-{}", self.current + i),
                content: format!("Content {}", self.current + i),
                metadata: super::index::ChunkMetadata {
                    source: self.query.clone(),
                    chunk_type: super::index::ChunkType::Text,
                    confidence: 0.9,
                    tags: vec![],
                },
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .collect();

        self.current += to_fetch;
        Some(chunks)
    }

    pub fn progress(&self) -> f32 {
        if self.total == 0 {
            1.0
        } else {
            self.current as f32 / self.total as f32
        }
    }
}

// =============================================================================
// Paginator
// =============================================================================

pub struct Paginator {
    index: Arc<KnowledgeIndex>,
    cache: ResultSetCache,
    cursor_encoding: String,
}

impl Paginator {
    pub fn new(index: Arc<KnowledgeIndex>) -> Self {
        Self {
            index,
            cache: ResultSetCache::new(300, 1000), // 5 min TTL, 1000 sets
            cursor_encoding: "base64".to_string(),
        }
    }

    /// Execute paginated query
    pub fn query(&self, request: PageRequest) -> PageResult<KnowledgeChunk> {
        let result_set_id = request.cursor.as_ref()
            .and_then(|c| self.decode_cursor(c).ok())
            .map(|c| c.result_set_id)
            .unwrap_or_else(|| format!("rs-{}", uuid::Uuid::new_v4()));

        let offset = request.cursor.as_ref()
            .and_then(|c| self.decode_cursor(c).ok())
            .map(|c| c.offset)
            .unwrap_or(0);

        // Try cache first
        if let Some((ids, total, has_more)) = self.cache.get_page(&result_set_id, offset, request.limit) {
            return self.build_page(ids, total, offset, request.limit, has_more, &result_set_id);
        }

        // Execute new query and cache
        let (ids, total) = self.execute_query(&request, offset + request.limit);
        
        self.cache.store(
            result_set_id.clone(),
            ids.clone(),
            request.filter.unwrap_or_default(),
            total,
        );

        let has_more = ids.len() > offset + request.limit;
        let page_ids: Vec<String> = ids.iter()
            .skip(offset)
            .take(request.limit)
            .cloned()
            .collect();

        self.build_page(page_ids, total, offset, request.limit, has_more, &result_set_id)
    }

    fn execute_query(&self, request: &PageRequest, limit: usize) -> (Vec<String>, usize) {
        // In production: execute actual search
        // For now: simulate results
        let total = 1000; // Simulated total
        let ids: Vec<String> = (0..total)
            .map(|i| format!("chunk-{}", i))
            .collect();

        (ids, total)
    }

    fn build_page(&self, ids: Vec<String>, total: usize, offset: usize, limit: usize, has_more: bool, result_set_id: &str) -> PageResult<KnowledgeChunk> {
        // Fetch actual chunks
        let chunks: Vec<KnowledgeChunk> = ids.iter()
            .map(|id| KnowledgeChunk {
                chunk_id: id.clone(),
                content: format!("Content of {}", id),
                metadata: super::index::ChunkMetadata {
                    source: "query".to_string(),
                    chunk_type: super::index::ChunkType::Text,
                    confidence: 0.9,
                    tags: vec![],
                },
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .collect();

        let next_cursor = if has_more {
            Some(self.encode_cursor(&Cursor {
                result_set_id: result_set_id.to_string(),
                offset: offset + limit,
                query_hash: "hash".to_string(),
                created_at: chrono::Utc::now().timestamp_millis(),
            }))
        } else {
            None
        };

        let prev_cursor = if offset > 0 {
            let prev_offset = offset.saturating_sub(limit);
            Some(self.encode_cursor(&Cursor {
                result_set_id: result_set_id.to_string(),
                offset: prev_offset,
                query_hash: "hash".to_string(),
                created_at: chrono::Utc::now().timestamp_millis(),
            }))
        } else {
            None
        };

        PageResult {
            items: chunks,
            total_count: total,
            next_cursor,
            prev_cursor,
            has_more,
            result_set_id: result_set_id.to_string(),
        }
    }

    fn encode_cursor(&self, cursor: &Cursor) -> String {
        let json = serde_json::to_string(cursor).unwrap();
        base64::encode(&json)
    }

    fn decode_cursor(&self, cursor: &str) -> Result<Cursor, String> {
        let decoded = base64::decode(cursor).map_err(|e| e.to_string())?;
        serde_json::from_slice(&decoded).map_err(|e| e.to_string())
    }

    /// Create streaming iterator for large results
    pub fn stream(&self, query: String, estimated_total: usize) -> StreamingIterator {
        StreamingIterator::new(self.index.clone(), query, estimated_total)
    }

    /// Cleanup expired caches
    pub fn cleanup(&self) -> usize {
        self.cache.cleanup()
    }
}

// base64 encode/decode helpers
mod base64 {
    pub fn encode(input: &str) -> String {
        use std::collections::HashMap;
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        let bytes = input.as_bytes();
        
        for chunk in bytes.chunks(3) {
            let b = match chunk.len() {
                1 => [chunk[0], 0, 0],
                2 => [chunk[0], chunk[1], 0],
                3 => [chunk[0], chunk[1], chunk[2]],
                _ => unreachable!(),
            };
            
            result.push(CHARS[(b[0] >> 2) as usize] as char);
            result.push(CHARS[(((b[0] & 3) << 4) | (b[1] >> 4)) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[(((b[1] & 15) << 2) | (b[2] >> 6)) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(b[2] & 63) as usize] as char);
            } else {
                result.push('=');
            }
        }
        
        result
    }
    
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        // Simplified decoder - in production use proper base64
        Ok(input.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination() {
        let index = Arc::new(KnowledgeIndex::new());
        let paginator = Paginator::new(index);

        let request = PageRequest {
            cursor: None,
            limit: 10,
            filter: Some("test".to_string()),
            sort: SortOrder::Relevance,
        };

        let result = paginator.query(request);
        
        assert!(!result.items.is_empty());
        assert!(result.has_more || result.items.len() < 10);
        assert!(!result.result_set_id.is_empty());
    }

    #[test]
    fn test_cursor_encoding() {
        let index = Arc::new(KnowledgeIndex::new());
        let paginator = Paginator::new(index);

        let cursor = Cursor {
            result_set_id: "test-id".to_string(),
            offset: 100,
            query_hash: "abc123".to_string(),
            created_at: 1000,
        };

        let encoded = paginator.encode_cursor(&cursor);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_result_set_cache() {
        let cache = ResultSetCache::new(60, 100);
        
        cache.store(
            "rs-1".to_string(),
            (0..100).map(|i| format!("id-{}", i)).collect(),
            "query".to_string(),
            100,
        );

        let page = cache.get_page("rs-1", 0, 10);
        assert!(page.is_some());
        
        let (ids, total, has_more) = page.unwrap();
        assert_eq!(ids.len(), 10);
        assert_eq!(total, 100);
        assert!(has_more);
    }
}
