//! Telemetry & Real-Time Streams (Layer 4+) — sensor data, QoS, rate limiting.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::EntityId;
use crate::error::{ProtocolError, ProtoResult};

// ── QoS Profile ─────────────────────────────────────────────────────

/// Quality-of-Service profile for telemetry streams (DDS-inspired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QoSProfile {
    /// Best-effort: no guarantees, lowest overhead.
    BestEffort,
    /// Reliable: guaranteed delivery, at-least-once.
    Reliable,
    /// Realtime: bounded latency, may drop old samples.
    Realtime,
}

// ── Telemetry Sample ────────────────────────────────────────────────

/// A single telemetry data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub entity_id: EntityId,
    pub stream_id: String,
    pub timestamp_ns: u64,
    pub data: serde_json::Value,
    pub data_cid: String,
}

impl TelemetrySample {
    pub fn new(entity_id: EntityId, stream_id: &str, data: serde_json::Value) -> Self {
        let data_bytes = serde_json::to_vec(&data).unwrap_or_default();
        let hash = Sha256::digest(&data_bytes);
        let cid = format!("cid:{}", hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        Self {
            entity_id,
            stream_id: stream_id.to_string(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            data,
            data_cid: cid,
        }
    }
}

// ── Telemetry Stream ────────────────────────────────────────────────

/// Configuration for a telemetry stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub stream_id: String,
    pub entity_id: EntityId,
    pub qos: QoSProfile,
    pub max_rate_hz: u32,
    pub batch_size: usize,
}

// ── Rate Limiter ────────────────────────────────────────────────────

struct RateLimitEntry {
    max_per_second: u32,
    count_this_second: u32,
    second_start_ms: i64,
}

// ── Telemetry Manager ───────────────────────────────────────────────

/// Manages telemetry streams, subscriptions, and rate limiting.
pub struct TelemetryManager {
    streams: HashMap<String, StreamConfig>,
    subscribers: HashMap<String, Vec<EntityId>>,
    rate_limits: HashMap<String, RateLimitEntry>,
    sample_count: u64,
}

impl TelemetryManager {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            subscribers: HashMap::new(),
            rate_limits: HashMap::new(),
            sample_count: 0,
        }
    }

    /// Register a telemetry stream.
    pub fn register_stream(&mut self, config: StreamConfig) {
        let key = format!("{}:{}", config.entity_id, config.stream_id);
        self.rate_limits.insert(key.clone(), RateLimitEntry {
            max_per_second: config.max_rate_hz,
            count_this_second: 0,
            second_start_ms: chrono::Utc::now().timestamp_millis(),
        });
        self.streams.insert(config.stream_id.clone(), config);
    }

    /// Subscribe to a stream.
    pub fn subscribe(&mut self, stream_id: &str, subscriber: EntityId) -> ProtoResult<()> {
        if !self.streams.contains_key(stream_id) {
            return Err(ProtocolError::NotFound(format!("Stream {}", stream_id)));
        }
        self.subscribers.entry(stream_id.to_string()).or_default().push(subscriber);
        Ok(())
    }

    /// Publish a sample (with rate limiting).
    pub fn publish(&mut self, sample: &TelemetrySample) -> ProtoResult<()> {
        let stream = self.streams.get(&sample.stream_id)
            .ok_or_else(|| ProtocolError::NotFound(format!("Stream {}", sample.stream_id)))?;

        let key = format!("{}:{}", sample.entity_id, sample.stream_id);
        let now = chrono::Utc::now().timestamp_millis();

        if let Some(rl) = self.rate_limits.get_mut(&key) {
            if now - rl.second_start_ms >= 1000 {
                rl.count_this_second = 0;
                rl.second_start_ms = now;
            }
            if rl.count_this_second >= rl.max_per_second {
                return Err(ProtocolError::Envelope(format!(
                    "Rate limit exceeded for stream {} (max {} Hz)",
                    sample.stream_id, stream.max_rate_hz
                )));
            }
            rl.count_this_second += 1;
        }

        self.sample_count += 1;
        Ok(())
    }

    /// Get subscribers for a stream.
    pub fn get_subscribers(&self, stream_id: &str) -> Vec<&EntityId> {
        self.subscribers.get(stream_id)
            .map(|subs| subs.iter().collect())
            .unwrap_or_default()
    }

    pub fn stream_count(&self) -> usize { self.streams.len() }
    pub fn total_samples(&self) -> u64 { self.sample_count }
}

impl Default for TelemetryManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;

    fn sid(n: &str) -> EntityId { EntityId::new(EntityClass::Sensor, n) }
    fn aid(n: &str) -> EntityId { EntityId::new(EntityClass::Agent, n) }

    #[test]
    fn test_register_and_subscribe() {
        let mut mgr = TelemetryManager::new();
        mgr.register_stream(StreamConfig {
            stream_id: "temp".into(),
            entity_id: sid("s1"),
            qos: QoSProfile::Reliable,
            max_rate_hz: 100,
            batch_size: 10,
        });

        assert_eq!(mgr.stream_count(), 1);
        assert!(mgr.subscribe("temp", aid("a1")).is_ok());
        assert!(mgr.subscribe("missing", aid("a1")).is_err());
    }

    #[test]
    fn test_publish_sample() {
        let mut mgr = TelemetryManager::new();
        let sensor = sid("s1");
        mgr.register_stream(StreamConfig {
            stream_id: "temp".into(),
            entity_id: sensor.clone(),
            qos: QoSProfile::BestEffort,
            max_rate_hz: 1000,
            batch_size: 1,
        });

        let sample = TelemetrySample::new(sensor, "temp", serde_json::json!({"celsius": 22.5}));
        assert!(mgr.publish(&sample).is_ok());
        assert_eq!(mgr.total_samples(), 1);
    }

    #[test]
    fn test_rate_limiting() {
        let mut mgr = TelemetryManager::new();
        let sensor = sid("s1");
        mgr.register_stream(StreamConfig {
            stream_id: "fast".into(),
            entity_id: sensor.clone(),
            qos: QoSProfile::Realtime,
            max_rate_hz: 3,
            batch_size: 1,
        });

        for _ in 0..3 {
            let sample = TelemetrySample::new(sensor.clone(), "fast", serde_json::json!(1));
            assert!(mgr.publish(&sample).is_ok());
        }
        // 4th should be rate limited
        let sample = TelemetrySample::new(sensor, "fast", serde_json::json!(1));
        assert!(mgr.publish(&sample).is_err());
    }

    #[test]
    fn test_sample_cid() {
        let s = TelemetrySample::new(sid("s1"), "temp", serde_json::json!({"v": 1}));
        assert!(s.data_cid.starts_with("cid:"));
    }

    #[test]
    fn test_subscribers() {
        let mut mgr = TelemetryManager::new();
        mgr.register_stream(StreamConfig {
            stream_id: "imu".into(),
            entity_id: sid("s1"),
            qos: QoSProfile::Realtime,
            max_rate_hz: 100,
            batch_size: 1,
        });

        mgr.subscribe("imu", aid("a1")).unwrap();
        mgr.subscribe("imu", aid("a2")).unwrap();

        assert_eq!(mgr.get_subscribers("imu").len(), 2);
        assert_eq!(mgr.get_subscribers("missing").len(), 0);
    }
}
