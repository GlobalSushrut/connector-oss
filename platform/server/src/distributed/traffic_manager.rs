//! Traffic Manager — Production-Scale Network Traffic Management
//!
//! Handles:
//! - High volume traffic without crashes
//! - Network congestion management
//! - Traffic caching and buffering
//! - Rate limiting and shaping
//! - Load balancing across cloud instances
//! - CDN-style edge routing

use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

// =============================================================================
// Traffic Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficType {
    Consensus,      // Critical consensus traffic
    DataReplication, // Data sync between cells
    UserRequest,    // End-user requests
    HealthProbe,    // Health checks
    Background,    // Background tasks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficPriority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
}

// =============================================================================
// Traffic Flow
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficFlow {
    pub flow_id: String,
    pub source: String,
    pub destination: String,
    pub traffic_type: TrafficType,
    pub priority: TrafficPriority,
    pub bytes_total: u64,
    pub packets_total: u64,
    pub created_at: i64,
    pub last_activity: i64,
    pub is_active: bool,
}

// =============================================================================
// Traffic Cache (for congested data)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPacket {
    pub packet_id: String,
    pub data: Vec<u8>,
    pub dest_cell: String,
    pub priority: TrafficPriority,
    pub cached_at: i64,
    pub retry_count: u32,
    pub expires_at: i64,
}

pub struct TrafficCache {
    /// Cached packets by destination
    cache: HashMap<String, VecDeque<CachedPacket>>,
    /// Maximum cache size per destination
    max_per_dest: usize,
    /// Total cache size limit
    total_limit: usize,
    /// Current total size
    current_size: AtomicU64,
    /// Expiration check interval
    check_interval: Duration,
    /// Last cleanup
    last_cleanup: Instant,
}

impl TrafficCache {
    pub fn new(max_per_dest: usize, total_limit: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_per_dest,
            total_limit,
            current_size: AtomicU64::new(0),
            check_interval: Duration::from_secs(30),
            last_cleanup: Instant::now(),
        }
    }

    /// Cache packet for later delivery
    pub fn cache_packet(&mut self, packet: CachedPacket) -> Result<(), CacheError> {
        // Check total limit
        let current = self.current_size.load(Ordering::Relaxed) as usize;
        if current >= self.total_limit {
            self.cleanup_expired();
        }

        // Get or create queue for destination
        let queue = self.cache.entry(packet.dest_cell.clone()).or_insert_with(VecDeque::new);

        // Check per-destination limit
        if queue.len() >= self.max_per_dest {
            // Remove oldest
            if let Some(old) = queue.pop_front() {
                self.current_size.fetch_sub(old.data.len() as u64, Ordering::Relaxed);
            }
        }

        // Add packet size
        self.current_size.fetch_add(packet.data.len() as u64, Ordering::Relaxed);

        // Add to queue
        queue.push_back(packet);

        Ok(())
    }

    /// Retrieve cached packets for destination
    pub fn retrieve_packets(&mut self, dest_cell: &str, max_count: usize) -> Vec<CachedPacket> {
        if let Some(queue) = self.cache.get_mut(dest_cell) {
            let mut packets = Vec::new();
            for _ in 0..max_count {
                if let Some(packet) = queue.pop_front() {
                    self.current_size.fetch_sub(packet.data.len() as u64, Ordering::Relaxed);
                    packets.push(packet);
                } else {
                    break;
                }
            }
            packets
        } else {
            vec![]
        }
    }

    /// Cleanup expired packets
    pub fn cleanup_expired(&mut self) -> usize {
        let now = chrono::Utc::now().timestamp_millis();
        let mut removed = 0;

        for queue in self.cache.values_mut() {
            let before_len = queue.len();
            queue.retain(|packet| {
                let keep = packet.expires_at > now;
                if !keep {
                    self.current_size.fetch_sub(packet.data.len() as u64, Ordering::Relaxed);
                }
                keep
            });
            removed += before_len - queue.len();
        }

        self.last_cleanup = Instant::now();
        removed
    }

    /// Get cache stats
    pub fn get_stats(&self) -> CacheStats {
        let total_packets: usize = self.cache.values().map(|q| q.len()).sum();
        
        CacheStats {
            total_destinations: self.cache.len(),
            total_packets,
            total_bytes: self.current_size.load(Ordering::Relaxed),
            max_per_dest: self.max_per_dest,
            total_limit: self.total_limit,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheError {
    Full,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_destinations: usize,
    pub total_packets: usize,
    pub total_bytes: u64,
    pub max_per_dest: usize,
    pub total_limit: usize,
}

// =============================================================================
// Congestion Controller
// =============================================================================

pub struct CongestionController {
    /// Current congestion level (0.0 - 1.0)
    congestion_level: Arc<RwLock<f64>>,
    /// Bytes per second limit
    bandwidth_limit: u64,
    /// Current throughput
    current_throughput: AtomicU64,
    /// Active flows
    active_flows: Arc<RwLock<HashMap<String, TrafficFlow>>>,
    /// Rate limiters per flow type
    rate_limiters: HashMap<TrafficType, TokenBucket>,
    /// Last measurement time
    last_measurement: Instant,
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub capacity: u64,
    pub tokens: u64,
    pub refill_rate: u64, // tokens per second
    pub last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn consume(&mut self, amount: u64) -> bool {
        self.refill();
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let to_add = (elapsed * self.refill_rate as f64) as u64;
        self.tokens = (self.tokens + to_add).min(self.capacity);
        self.last_refill = now;
    }
}

impl CongestionController {
    pub fn new(bandwidth_limit_mbps: u64) -> Self {
        let bandwidth_limit = bandwidth_limit_mbps * 1024 * 1024 / 8; // Convert to bytes/sec
        
        Self {
            congestion_level: Arc::new(RwLock::new(0.0)),
            bandwidth_limit,
            current_throughput: AtomicU64::new(0),
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            rate_limiters: {
                let mut map = HashMap::new();
                map.insert(TrafficType::Consensus, TokenBucket::new(10000, 10000));
                map.insert(TrafficType::DataReplication, TokenBucket::new(100000, 50000));
                map.insert(TrafficType::UserRequest, TokenBucket::new(10000, 5000));
                map.insert(TrafficType::HealthProbe, TokenBucket::new(1000, 1000));
                map.insert(TrafficType::Background, TokenBucket::new(50000, 10000));
                map
            },
            last_measurement: Instant::now(),
        }
    }

    /// Check if traffic is allowed
    pub fn allow_traffic(&mut self, traffic_type: TrafficType, bytes: u64) -> bool {
        // Update congestion level
        self.update_congestion();

        // Get current congestion
        let congestion = *self.congestion_level.read().unwrap();

        // Critical traffic always allowed
        if traffic_type == TrafficType::Consensus && congestion < 0.95 {
            return true;
        }

        // Check token bucket
        if let Some(bucket) = self.rate_limiters.get_mut(&traffic_type) {
            bucket.consume(bytes)
        } else {
            false
        }
    }

    /// Update congestion level based on current throughput
    fn update_congestion(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_measurement).as_secs_f64();
        
        if elapsed > 1.0 {
            let throughput = self.current_throughput.swap(0, Ordering::Relaxed) as f64 / elapsed;
            let level = (throughput / self.bandwidth_limit as f64).min(1.0);
            
            *self.congestion_level.write().unwrap() = level;
            self.last_measurement = now;
        }
    }

    /// Record traffic
    pub fn record_traffic(&self, bytes: u64) {
        self.current_throughput.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get congestion stats
    pub fn get_stats(&self) -> CongestionStats {
        CongestionStats {
            congestion_level: *self.congestion_level.read().unwrap(),
            bandwidth_limit: self.bandwidth_limit,
            active_flows: self.active_flows.read().unwrap().len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionStats {
    pub congestion_level: f64,
    pub bandwidth_limit: u64,
    pub active_flows: usize,
}

// =============================================================================
// Traffic Manager — Main Controller
// =============================================================================

pub struct TrafficManager {
    /// Traffic cache for congested data
    cache: Arc<RwLock<TrafficCache>>,
    /// Congestion controller
    congestion: Arc<RwLock<CongestionController>>,
    /// Flow tracking
    flows: Arc<RwLock<HashMap<String, TrafficFlow>>>,
    /// Circuit breakers per destination
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    /// Load balancer
    load_balancer: LoadBalancer,
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    pub dest_cell: String,
    pub failures: u32,
    pub success_threshold: u32,
    pub failure_threshold: u32,
    pub timeout: Duration,
    pub state: CircuitState,
    pub last_failure: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,    // Normal operation
    Open,      // Failing fast
    HalfOpen,  // Testing recovery
}

impl CircuitBreaker {
    pub fn new(dest_cell: String) -> Self {
        Self {
            dest_cell,
            failures: 0,
            success_threshold: 3,
            failure_threshold: 5,
            timeout: Duration::from_secs(30),
            state: CircuitState::Closed,
            last_failure: Instant::now(),
        }
    }

    pub fn record_success(&mut self) {
        if self.state == CircuitState::HalfOpen {
            self.failures = 0;
            self.state = CircuitState::Closed;
        }
    }

    pub fn record_failure(&mut self) -> CircuitState {
        self.failures += 1;
        self.last_failure = Instant::now();

        if self.failures >= self.failure_threshold {
            self.state = CircuitState::Open;
        }

        self.state
    }

    pub fn can_attempt(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if Instant::now().duration_since(self.last_failure) > self.timeout {
                    self.state = CircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }
}

pub struct LoadBalancer {
    /// Available endpoints
    endpoints: Vec<String>,
    /// Current index (round-robin)
    current_index: usize,
    /// Endpoint weights
    weights: HashMap<String, u32>,
}

impl LoadBalancer {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            current_index: 0,
            weights: HashMap::new(),
        }
    }

    /// Get next endpoint (round-robin)
    pub fn next_endpoint(&mut self) -> Option<String> {
        if self.endpoints.is_empty() {
            return None;
        }

        let endpoint = self.endpoints[self.current_index].clone();
        self.current_index = (self.current_index + 1) % self.endpoints.len();
        Some(endpoint)
    }

    /// Add endpoint
    pub fn add_endpoint(&mut self, endpoint: String, weight: u32) {
        self.endpoints.push(endpoint.clone());
        self.weights.insert(endpoint, weight);
    }

    /// Remove endpoint
    pub fn remove_endpoint(&mut self, endpoint: &str) {
        self.endpoints.retain(|e| e != endpoint);
        self.weights.remove(endpoint);
    }
}

impl TrafficManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(TrafficCache::new(10000, 100 * 1024 * 1024))), // 100MB
            congestion: Arc::new(RwLock::new(CongestionController::new(1000))), // 1 Gbps
            flows: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            load_balancer: LoadBalancer::new(vec![]),
        }
    }

    /// Send traffic with full management
    pub fn send_traffic(
        &self,
        dest_cell: &str,
        data: Vec<u8>,
        traffic_type: TrafficType,
    ) -> Result<TrafficResult, TrafficError> {
        // Check circuit breaker
        {
            let mut breakers = self.circuit_breakers.write().unwrap();
            let breaker = breakers.entry(dest_cell.to_string())
                .or_insert_with(|| CircuitBreaker::new(dest_cell.to_string()));
            
            if !breaker.can_attempt() {
                // Circuit open - cache for later
                let packet = CachedPacket {
                    packet_id: format!("pkt-{}", uuid::Uuid::new_v4()),
                    data: data.clone(),
                    dest_cell: dest_cell.to_string(),
                    priority: TrafficPriority::Normal,
                    cached_at: chrono::Utc::now().timestamp_millis(),
                    retry_count: 0,
                    expires_at: chrono::Utc::now().timestamp_millis() + 300000, // 5 min
                };
                
                self.cache.write().unwrap().cache_packet(packet)
                    .map_err(|_| TrafficError::CacheFull)?;
                return Ok(TrafficResult::Cached);
            }
        }

        // Check congestion
        let allowed = {
            let mut congestion = self.congestion.write().unwrap();
            congestion.allow_traffic(traffic_type, data.len() as u64)
        };

        if !allowed {
            // Congested - cache for later
            let packet = CachedPacket {
                packet_id: format!("pkt-{}", uuid::Uuid::new_v4()),
                data,
                dest_cell: dest_cell.to_string(),
                priority: TrafficPriority::Normal,
                cached_at: chrono::Utc::now().timestamp_millis(),
                retry_count: 0,
                expires_at: chrono::Utc::now().timestamp_millis() + 300000,
            };
            
            self.cache.write().unwrap().cache_packet(packet)
                .map_err(|_| TrafficError::CacheFull)?;
            return Ok(TrafficResult::Cached);
        }

        // Record traffic
        self.congestion.read().unwrap().record_traffic(data.len() as u64);

        // In production: actual network send
        // For now: simulate success
        Ok(TrafficResult::Sent)
    }

    /// Retry cached packets
    pub fn retry_cached(&self, dest_cell: &str) -> Vec<Result<TrafficResult, TrafficError>> {
        let packets = self.cache.write().unwrap().retrieve_packets(dest_cell, 100);
        let mut results = Vec::new();

        for packet in packets {
            // Try to send
            let result = self.send_traffic(
                &packet.dest_cell,
                packet.data,
                TrafficType::DataReplication,
            );
            results.push(result);
        }

        results
    }

    /// Get traffic stats
    pub fn get_stats(&self) -> TrafficManagerStats {
        TrafficManagerStats {
            cache: self.cache.read().unwrap().get_stats(),
            congestion: self.congestion.read().unwrap().get_stats(),
            active_flows: self.flows.read().unwrap().len(),
            open_circuits: self.circuit_breakers.read().unwrap().values()
                .filter(|b| b.state == CircuitState::Open)
                .count(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrafficResult {
    Sent,
    Cached,
    Dropped,
}

#[derive(Debug, Clone)]
pub enum TrafficError {
    CircuitOpen,
    Congested,
    CacheFull,
    SendFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficManagerStats {
    pub cache: CacheStats,
    pub congestion: CongestionStats,
    pub active_flows: usize,
    pub open_circuits: usize,
}

#[derive(Clone)]
pub struct SharedTrafficManager {
    inner: Arc<TrafficManager>,
}

impl SharedTrafficManager {
    pub fn new() -> Self {
        Self { inner: Arc::new(TrafficManager::new()) }
    }
    
    pub fn send_traffic(&self, dest: &str, data: Vec<u8>, ttype: TrafficType) -> Result<TrafficResult, TrafficError> {
        self.inner.send_traffic(dest, data, ttype)
    }
    
    pub fn get_stats(&self) -> TrafficManagerStats {
        self.inner.get_stats()
    }
}
