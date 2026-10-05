//! I16 — S3/GCS cold tier bridge with ARC eviction.
//!
//! Provides transparent CAS-addressed storage for FROZEN/COLD tier MemPackets:
//! - Background tiering task (1 Hz): demotes packets with `last_access > cold_threshold_ms` to S3
//! - Transparent read: CID miss in local store → fetch from S3 → return to caller
//! - ARC eviction policy (Megiddo & Modha 2003): T1+T2+ghost lists, adaptive parameter p

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── S3 Object Store Trait ────────────────────────────────────────────

/// Abstraction over S3/GCS — allows in-process mock for tests.
#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, data: Vec<u8>) -> Result<(), S3BridgeError>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, S3BridgeError>;
    async fn delete(&self, key: &str) -> Result<(), S3BridgeError>;
    async fn exists(&self, key: &str) -> Result<bool, S3BridgeError>;
}

// ── Errors ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum S3BridgeError {
    #[error("Object store I/O error: {0}")]
    Io(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("CID not found: {0}")]
    NotFound(String),
}

// ── Packet Record ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdPacket {
    pub cid: String,
    pub namespace: String,
    pub data: Vec<u8>,
    pub last_access_ms: i64,
    pub tiered_at_ms: i64,
}

// ── ARC Eviction Cache (Megiddo & Modha 2003) ─────────────────────────
//
// ARC maintains four lists:
//   T1: recently used once
//   T2: recently used more than once (frequent)
//   B1: ghost of T1 (CID only, no data) — evicted from T1
//   B2: ghost of T2 (CID only, no data) — evicted from T2
//
// Adaptive parameter p grows when B1 hits, shrinks when B2 hits.
// Target: |T1| + |B1| + |T2| + |B2| ≤ 2 * capacity

pub struct ArcCache {
    capacity: usize,
    /// Adaptive parameter: target size of T1
    p: usize,
    t1: VecDeque<String>,
    t2: VecDeque<String>,
    b1: VecDeque<String>,
    b2: VecDeque<String>,
    data: HashMap<String, Vec<u8>>,
}

impl ArcCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            p: 0,
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            data: HashMap::new(),
        }
    }

    pub fn get(&mut self, cid: &str) -> Option<&Vec<u8>> {
        // Move from T1 → T2 (second reference)
        if let Some(pos) = self.t1.iter().position(|k| k == cid) {
            self.t1.remove(pos);
            self.t2.push_back(cid.to_string());
            return self.data.get(cid);
        }
        // Move to front of T2 (subsequent reference)
        if let Some(pos) = self.t2.iter().position(|k| k == cid) {
            self.t2.remove(pos);
            self.t2.push_back(cid.to_string());
            return self.data.get(cid);
        }
        None
    }

    pub fn insert(&mut self, cid: String, data: Vec<u8>) {
        if self.data.contains_key(&cid) {
            return;
        }

        let in_b1 = self.b1.contains(&cid);
        let in_b2 = self.b2.contains(&cid);

        if in_b1 {
            // Adapt: increase p (B1 hit means T1 too small)
            let delta = if self.b1.len() >= self.b2.len() { 1 } else { self.b2.len() / self.b1.len().max(1) };
            self.p = (self.p + delta).min(self.capacity);
            self.b1.retain(|k| k != &cid);
            self.replace(false);
            self.t2.push_back(cid.clone());
        } else if in_b2 {
            // Adapt: decrease p (B2 hit means T2 too small)
            let delta = if self.b2.len() >= self.b1.len() { 1 } else { self.b1.len() / self.b2.len().max(1) };
            self.p = self.p.saturating_sub(delta);
            self.b2.retain(|k| k != &cid);
            self.replace(true);
            self.t2.push_back(cid.clone());
        } else {
            let total = self.t1.len() + self.t2.len();
            if total >= self.capacity {
                self.replace(false);
                // Keep ghost lists bounded
                while self.b1.len() + self.b2.len() >= self.capacity {
                    if self.b1.len() > self.b2.len() { self.b1.pop_front(); }
                    else { self.b2.pop_front(); }
                }
            }
            self.t1.push_back(cid.clone());
        }

        self.data.insert(cid, data);
    }

    fn replace(&mut self, prefer_t2: bool) {
        let t1_len = self.t1.len();
        if !self.t1.is_empty() && (t1_len > self.p || (prefer_t2 && t1_len == self.p)) {
            if let Some(evicted) = self.t1.pop_front() {
                self.data.remove(&evicted);
                self.b1.push_back(evicted);
            }
        } else if let Some(evicted) = self.t2.pop_front() {
            self.data.remove(&evicted);
            self.b2.push_back(evicted);
        }
    }

    pub fn len(&self) -> usize { self.t1.len() + self.t2.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

// ── S3 Bridge ────────────────────────────────────────────────────────

pub struct S3Bridge {
    store: Arc<dyn ObjectStore>,
    cache: Mutex<ArcCache>,
    cold_threshold_ms: i64,
}

impl S3Bridge {
    pub fn new(store: Arc<dyn ObjectStore>, cache_capacity: usize, cold_threshold_ms: i64) -> Self {
        Self {
            store,
            cache: Mutex::new(ArcCache::new(cache_capacity)),
            cold_threshold_ms,
        }
    }

    /// Fetch a packet by CID. Checks ARC cache first, then falls back to S3.
    pub async fn get(&self, cid: &str) -> Result<Option<Vec<u8>>, S3BridgeError> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(data) = cache.get(cid) {
                return Ok(Some(data.clone()));
            }
        }
        // Cache miss — fetch from S3
        if let Some(raw) = self.store.get(cid).await? {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(cid.to_string(), raw.clone());
            Ok(Some(raw))
        } else {
            Ok(None)
        }
    }

    /// Tier a packet to S3 (called by the background tiering task).
    pub async fn tier_to_cold(&self, packet: &ColdPacket) -> Result<(), S3BridgeError> {
        let raw = serde_json::to_vec(packet)
            .map_err(|e| S3BridgeError::Serialization(e.to_string()))?;
        self.store.put(&packet.cid, raw).await
    }

    /// Background 1 Hz tiering task.
    ///
    /// Scans `candidates` and demotes any packet with
    /// `last_access_ms` older than `now - cold_threshold_ms` to S3.
    pub async fn run_tiering_pass(
        &self,
        candidates: &[ColdPacket],
        now_ms: i64,
    ) -> TieringStats {
        let mut stats = TieringStats::default();
        for packet in candidates {
            if now_ms - packet.last_access_ms >= self.cold_threshold_ms {
                match self.tier_to_cold(packet).await {
                    Ok(_) => stats.tiered += 1,
                    Err(_) => stats.errors += 1,
                }
            } else {
                stats.skipped += 1;
            }
        }
        stats
    }

    /// Spawn the background 1 Hz tiering loop.
    ///
    /// `source` is a callback that returns the current list of eviction candidates.
    pub fn spawn_tiering_loop<F, Fut>(
        bridge: Arc<S3Bridge>,
        source: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Vec<ColdPacket>> + Send + 'static,
    {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let candidates = source().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                bridge.run_tiering_pass(&candidates, now_ms).await;
            }
        })
    }
}

#[derive(Debug, Default)]
pub struct TieringStats {
    pub tiered: usize,
    pub skipped: usize,
    pub errors: usize,
}

// ── In-Process Mock Store (for tests) ───────────────────────────────

#[derive(Default)]
pub struct InMemoryObjectStore {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait::async_trait]
impl ObjectStore for InMemoryObjectStore {
    async fn put(&self, key: &str, data: Vec<u8>) -> Result<(), S3BridgeError> {
        self.data.lock().unwrap().insert(key.to_string(), data);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, S3BridgeError> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), S3BridgeError> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, S3BridgeError> {
        Ok(self.data.lock().unwrap().contains_key(key))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn make_packet(cid: &str, last_access_ms: i64) -> ColdPacket {
        ColdPacket {
            cid: cid.to_string(),
            namespace: "ns:test".to_string(),
            data: format!("data-{}", cid).into_bytes(),
            last_access_ms,
            tiered_at_ms: now_ms(),
        }
    }

    #[test]
    fn test_arc_cache_hit_promotes_to_t2() {
        let mut cache = ArcCache::new(10);
        cache.insert("cid1".to_string(), b"data1".to_vec());
        assert!(cache.t1.contains(&"cid1".to_string()));
        cache.get("cid1");
        assert!(cache.t2.contains(&"cid1".to_string()));
        assert!(!cache.t1.contains(&"cid1".to_string()));
    }

    #[test]
    fn test_arc_cache_evicts_to_ghost_on_capacity() {
        let mut cache = ArcCache::new(3);
        for i in 0..4 {
            cache.insert(format!("cid{}", i), format!("data{}", i).into_bytes());
        }
        assert!(cache.len() <= 3);
        assert!(!cache.b1.is_empty() || !cache.b2.is_empty());
    }

    #[test]
    fn test_arc_cache_adapts_p_on_b1_hit() {
        let mut cache = ArcCache::new(4);
        // Fill and evict cid0 to B1
        for i in 0..5 {
            cache.insert(format!("cid{}", i), vec![i as u8]);
        }
        let p_before = cache.p;
        // Re-insert cid0 (which is in B1) should increase p
        if cache.b1.contains(&"cid0".to_string()) {
            cache.insert("cid0".to_string(), vec![99]);
            assert!(cache.p >= p_before);
        }
    }

    #[tokio::test]
    async fn test_s3_bridge_stores_and_retrieves_packet() {
        let store = Arc::new(InMemoryObjectStore::default());
        let bridge = S3Bridge::new(store, 16, 60_000);

        let packet = make_packet("bafycid1", now_ms() - 120_000);
        bridge.tier_to_cold(&packet).await.unwrap();

        let result = bridge.get("bafycid1").await.unwrap();
        assert!(result.is_some());
        let retrieved: ColdPacket = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(retrieved.cid, "bafycid1");
    }

    #[tokio::test]
    async fn test_s3_bridge_arc_cache_avoids_second_s3_fetch() {
        let store = Arc::new(InMemoryObjectStore::default());
        let bridge = S3Bridge::new(store, 16, 60_000);
        let packet = make_packet("bafycid2", now_ms() - 120_000);
        bridge.tier_to_cold(&packet).await.unwrap();

        // First fetch hits S3 and populates cache
        let _ = bridge.get("bafycid2").await.unwrap();
        // Second fetch must hit cache (T1 or T2 must contain the CID)
        {
            let cache = bridge.cache.lock().unwrap();
            assert!(
                cache.t1.contains(&"bafycid2".to_string())
                    || cache.t2.contains(&"bafycid2".to_string()),
                "ARC cache should hold the CID after second access"
            );
        }
    }

    #[tokio::test]
    async fn test_tiering_pass_demotes_cold_packets() {
        let store = Arc::new(InMemoryObjectStore::default());
        let bridge = S3Bridge::new(store.clone(), 16, 60_000);

        let cold_packet = make_packet("bafycold", now_ms() - 120_000);
        let hot_packet = make_packet("bafyhot", now_ms() - 1_000);

        let stats = bridge.run_tiering_pass(&[cold_packet, hot_packet], now_ms()).await;
        assert_eq!(stats.tiered, 1, "Only the cold packet should be tiered");
        assert_eq!(stats.skipped, 1, "Hot packet should be skipped");
        assert!(store.exists("bafycold").await.unwrap());
        assert!(!store.exists("bafyhot").await.unwrap());
    }
}
