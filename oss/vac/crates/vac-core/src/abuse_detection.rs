//! Abuse Detection & IP Rate Limiting
//!
//! This module implements abuse protection:
//! - Anomaly pattern detection
//! - IP-based rate limiting
//! - Behavioral analysis
//!
//! Design sources: Cloudflare, AWS WAF, fail2ban

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// =============================================================================
// Anomaly Detection
// =============================================================================

/// Anomaly type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Unusual request rate spike
    RateSpike,
    /// Unusual error rate
    ErrorSpike,
    /// Unusual payload size
    PayloadAnomaly,
    /// Unusual endpoint access pattern
    EndpointAnomaly,
    /// Credential stuffing attempt
    CredentialStuffing,
    /// Enumeration attack
    Enumeration,
    /// Scraping behavior
    Scraping,
    /// Bot-like behavior
    BotBehavior,
    /// Geographic anomaly
    GeoAnomaly,
    /// Time-based anomaly
    TimeAnomaly,
}

/// Anomaly severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity
    pub severity: AnomalySeverity,
    /// Source (IP, API key, agent ID)
    pub source: String,
    /// Description
    pub description: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Detected at timestamp
    pub detected_at: i64,
    /// Evidence
    pub evidence: HashMap<String, serde_json::Value>,
}

/// Request metrics for anomaly detection
#[derive(Debug, Clone, Default)]
pub struct RequestMetrics {
    /// Request count in window
    pub request_count: u64,
    /// Error count in window
    pub error_count: u64,
    /// Total payload bytes
    pub payload_bytes: u64,
    /// Unique endpoints accessed
    pub unique_endpoints: u32,
    /// 4xx error count
    pub client_errors: u64,
    /// 5xx error count
    pub server_errors: u64,
    /// Average response time (ms)
    pub avg_response_ms: u64,
    /// Window start time
    pub window_start: Option<Instant>,
}

impl RequestMetrics {
    pub fn new() -> Self {
        Self {
            window_start: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn record_request(&mut self, payload_size: u64, response_ms: u64, is_error: bool, status: u16) {
        self.request_count += 1;
        self.payload_bytes += payload_size;
        
        // Update average response time
        let total_ms = self.avg_response_ms * (self.request_count - 1) + response_ms;
        self.avg_response_ms = total_ms / self.request_count;
        
        if is_error {
            self.error_count += 1;
        }
        if status >= 400 && status < 500 {
            self.client_errors += 1;
        }
        if status >= 500 {
            self.server_errors += 1;
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.request_count == 0 { return 0.0; }
        self.error_count as f64 / self.request_count as f64
    }

    pub fn requests_per_second(&self) -> f64 {
        let elapsed = self.window_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(1.0);
        if elapsed < 0.001 { return 0.0; }
        self.request_count as f64 / elapsed
    }
}

/// Anomaly detector
#[derive(Debug)]
pub struct AnomalyDetector {
    /// Baseline metrics (normal behavior)
    baseline: RequestMetrics,
    /// Current metrics
    current: HashMap<String, RequestMetrics>,
    /// Detection thresholds
    thresholds: AnomalyThresholds,
    /// Detected anomalies
    anomalies: Vec<Anomaly>,
    /// Blocked sources
    blocked: HashMap<String, i64>,
}

/// Detection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    /// Rate spike multiplier (e.g., 5x normal)
    pub rate_spike_multiplier: f64,
    /// Error rate threshold (e.g., 0.5 = 50%)
    pub error_rate_threshold: f64,
    /// Max payload size (bytes)
    pub max_payload_bytes: u64,
    /// Max unique endpoints per minute
    pub max_endpoints_per_minute: u32,
    /// Credential stuffing threshold (failed auths)
    pub credential_stuffing_threshold: u32,
    /// Enumeration threshold (404s)
    pub enumeration_threshold: u32,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            rate_spike_multiplier: 5.0,
            error_rate_threshold: 0.5,
            max_payload_bytes: 10 * 1024 * 1024, // 10MB
            max_endpoints_per_minute: 100,
            credential_stuffing_threshold: 10,
            enumeration_threshold: 20,
        }
    }
}

impl AnomalyDetector {
    pub fn new(thresholds: AnomalyThresholds) -> Self {
        Self {
            baseline: RequestMetrics::new(),
            current: HashMap::new(),
            thresholds,
            anomalies: Vec::new(),
            blocked: HashMap::new(),
        }
    }

    /// Record a request and check for anomalies
    pub fn record(&mut self, source: &str, payload_size: u64, response_ms: u64, status: u16, _endpoint: &str) -> Vec<Anomaly> {
        let is_error = status >= 400;
        
        // Update metrics
        let metrics = self.current.entry(source.into()).or_insert_with(RequestMetrics::new);
        metrics.record_request(payload_size, response_ms, is_error, status);
        
        // Capture values needed for checks
        let rps = metrics.requests_per_second();
        let error_rate = metrics.error_rate();
        let request_count = metrics.request_count;
        let client_errors = metrics.client_errors;
        
        let baseline_rps = self.baseline.requests_per_second();
        
        // Check for anomalies
        let mut detected = Vec::new();
        
        // Rate spike
        if rps > baseline_rps * self.thresholds.rate_spike_multiplier {
            detected.push(self.create_anomaly(
                AnomalyType::RateSpike,
                AnomalySeverity::High,
                source,
                "Unusual request rate spike detected",
                0.8,
            ));
        }
        
        // Error spike
        if error_rate > self.thresholds.error_rate_threshold && request_count > 10 {
            detected.push(self.create_anomaly(
                AnomalyType::ErrorSpike,
                AnomalySeverity::Medium,
                source,
                "High error rate detected",
                0.7,
            ));
        }
        
        // Payload anomaly
        if payload_size > self.thresholds.max_payload_bytes {
            detected.push(self.create_anomaly(
                AnomalyType::PayloadAnomaly,
                AnomalySeverity::Medium,
                source,
                "Unusually large payload",
                0.9,
            ));
        }
        
        // Credential stuffing (many 401s)
        if status == 401 && client_errors > self.thresholds.credential_stuffing_threshold as u64 {
            detected.push(self.create_anomaly(
                AnomalyType::CredentialStuffing,
                AnomalySeverity::Critical,
                source,
                "Possible credential stuffing attack",
                0.85,
            ));
        }
        
        // Enumeration (many 404s)
        if status == 404 && client_errors > self.thresholds.enumeration_threshold as u64 {
            detected.push(self.create_anomaly(
                AnomalyType::Enumeration,
                AnomalySeverity::High,
                source,
                "Possible enumeration attack",
                0.75,
            ));
        }
        
        self.anomalies.extend(detected.clone());
        detected
    }

    fn create_anomaly(&self, anomaly_type: AnomalyType, severity: AnomalySeverity, source: &str, description: &str, confidence: f64) -> Anomaly {
        Anomaly {
            anomaly_type,
            severity,
            source: source.into(),
            description: description.into(),
            confidence,
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            evidence: HashMap::new(),
        }
    }

    /// Block a source
    pub fn block(&mut self, source: &str, until: i64) {
        self.blocked.insert(source.into(), until);
    }

    /// Check if source is blocked
    pub fn is_blocked(&self, source: &str) -> bool {
        if let Some(&until) = self.blocked.get(source) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            return now < until;
        }
        false
    }

    /// Get recent anomalies
    pub fn recent_anomalies(&self, limit: usize) -> Vec<&Anomaly> {
        self.anomalies.iter().rev().take(limit).collect()
    }

    /// Update baseline from current metrics
    pub fn update_baseline(&mut self) {
        // Average all current metrics into baseline
        if self.current.is_empty() { return; }
        
        let mut total_rps = 0.0;
        for metrics in self.current.values() {
            total_rps += metrics.requests_per_second();
        }
        
        // Simple baseline update (would be more sophisticated in production)
        self.baseline.request_count = (total_rps / self.current.len() as f64) as u64;
    }
}

// =============================================================================
// IP-Based Rate Limiting
// =============================================================================

/// IP rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRateLimitConfig {
    /// Requests per second limit
    pub requests_per_second: u32,
    /// Requests per minute limit
    pub requests_per_minute: u32,
    /// Requests per hour limit
    pub requests_per_hour: u32,
    /// Burst allowance
    pub burst_size: u32,
    /// Block duration (seconds) after limit exceeded
    pub block_duration_seconds: u64,
    /// Whitelist IPs
    pub whitelist: Vec<String>,
    /// Blacklist IPs
    pub blacklist: Vec<String>,
}

impl Default for IpRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 10,
            requests_per_minute: 300,
            requests_per_hour: 10000,
            burst_size: 20,
            block_duration_seconds: 300, // 5 minutes
            whitelist: vec![],
            blacklist: vec![],
        }
    }
}

/// IP rate limit entry
#[derive(Debug, Clone)]
struct IpRateLimitEntry {
    /// Requests in current second
    second_count: u32,
    /// Requests in current minute
    minute_count: u32,
    /// Requests in current hour
    hour_count: u32,
    /// Last request time
    last_request: Instant,
    /// Second window start
    second_start: Instant,
    /// Minute window start
    minute_start: Instant,
    /// Hour window start
    hour_start: Instant,
    /// Blocked until (epoch seconds)
    blocked_until: Option<i64>,
}

impl IpRateLimitEntry {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            second_count: 0,
            minute_count: 0,
            hour_count: 0,
            last_request: now,
            second_start: now,
            minute_start: now,
            hour_start: now,
            blocked_until: None,
        }
    }

    fn reset_windows(&mut self) {
        let now = Instant::now();
        
        if now.duration_since(self.second_start) >= Duration::from_secs(1) {
            self.second_count = 0;
            self.second_start = now;
        }
        
        if now.duration_since(self.minute_start) >= Duration::from_secs(60) {
            self.minute_count = 0;
            self.minute_start = now;
        }
        
        if now.duration_since(self.hour_start) >= Duration::from_secs(3600) {
            self.hour_count = 0;
            self.hour_start = now;
        }
    }
}

/// Rate limit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResult {
    /// Allowed
    pub allowed: bool,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Reset time (epoch seconds)
    pub reset_at: i64,
    /// Retry after (seconds)
    pub retry_after: Option<u64>,
    /// Limit that was exceeded
    pub exceeded_limit: Option<String>,
}

/// IP rate limiter
#[derive(Debug)]
pub struct IpRateLimiter {
    /// Configuration
    config: IpRateLimitConfig,
    /// Rate limit entries by IP
    entries: HashMap<String, IpRateLimitEntry>,
}

impl IpRateLimiter {
    pub fn new(config: IpRateLimitConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
        }
    }

    /// Check if request is allowed
    pub fn check(&mut self, ip: &str) -> RateLimitResult {
        // Check whitelist
        if self.config.whitelist.contains(&ip.to_string()) {
            return RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_at: 0,
                retry_after: None,
                exceeded_limit: None,
            };
        }

        // Check blacklist
        if self.config.blacklist.contains(&ip.to_string()) {
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at: 0,
                retry_after: Some(86400), // 24 hours
                exceeded_limit: Some("blacklist".into()),
            };
        }

        let entry = self.entries.entry(ip.into()).or_insert_with(IpRateLimitEntry::new);
        entry.reset_windows();

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Check if blocked
        if let Some(blocked_until) = entry.blocked_until {
            if now_epoch < blocked_until {
                return RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    reset_at: blocked_until,
                    retry_after: Some((blocked_until - now_epoch) as u64),
                    exceeded_limit: Some("blocked".into()),
                };
            }
            entry.blocked_until = None;
        }

        // Check limits
        if entry.second_count >= self.config.requests_per_second {
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at: now_epoch + 1,
                retry_after: Some(1),
                exceeded_limit: Some("requests_per_second".into()),
            };
        }

        if entry.minute_count >= self.config.requests_per_minute {
            let retry = 60 - entry.minute_start.elapsed().as_secs();
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at: now_epoch + retry as i64,
                retry_after: Some(retry),
                exceeded_limit: Some("requests_per_minute".into()),
            };
        }

        if entry.hour_count >= self.config.requests_per_hour {
            let retry = 3600 - entry.hour_start.elapsed().as_secs();
            return RateLimitResult {
                allowed: false,
                remaining: 0,
                reset_at: now_epoch + retry as i64,
                retry_after: Some(retry),
                exceeded_limit: Some("requests_per_hour".into()),
            };
        }

        // Increment counters
        entry.second_count += 1;
        entry.minute_count += 1;
        entry.hour_count += 1;
        entry.last_request = Instant::now();

        let remaining = self.config.requests_per_minute.saturating_sub(entry.minute_count);

        RateLimitResult {
            allowed: true,
            remaining,
            reset_at: now_epoch + (60 - entry.minute_start.elapsed().as_secs() as i64),
            retry_after: None,
            exceeded_limit: None,
        }
    }

    /// Block an IP
    pub fn block(&mut self, ip: &str, duration_seconds: u64) {
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64 + duration_seconds as i64;

        let entry = self.entries.entry(ip.into()).or_insert_with(IpRateLimitEntry::new);
        entry.blocked_until = Some(until);
    }

    /// Unblock an IP
    pub fn unblock(&mut self, ip: &str) {
        if let Some(entry) = self.entries.get_mut(ip) {
            entry.blocked_until = None;
        }
    }

    /// Add to whitelist
    pub fn whitelist(&mut self, ip: &str) {
        if !self.config.whitelist.contains(&ip.to_string()) {
            self.config.whitelist.push(ip.into());
        }
    }

    /// Add to blacklist
    pub fn blacklist(&mut self, ip: &str) {
        if !self.config.blacklist.contains(&ip.to_string()) {
            self.config.blacklist.push(ip.into());
        }
    }

    /// Get current config
    pub fn config(&self) -> &IpRateLimitConfig {
        &self.config
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_metrics() {
        let mut metrics = RequestMetrics::new();
        metrics.record_request(1000, 50, false, 200);
        metrics.record_request(2000, 100, true, 500);

        assert_eq!(metrics.request_count, 2);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.error_rate(), 0.5);
    }

    #[test]
    fn test_anomaly_detector() {
        let mut detector = AnomalyDetector::new(AnomalyThresholds {
            credential_stuffing_threshold: 3,
            ..Default::default()
        });

        // Simulate credential stuffing
        for _ in 0..5 {
            detector.record("attacker", 100, 50, 401, "/login");
        }

        let anomalies = detector.recent_anomalies(10);
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::CredentialStuffing));
    }

    #[test]
    fn test_ip_rate_limiter() {
        let config = IpRateLimitConfig {
            requests_per_second: 2,
            requests_per_minute: 10,
            requests_per_hour: 100,
            ..Default::default()
        };
        let mut limiter = IpRateLimiter::new(config);

        // First requests should be allowed
        let result = limiter.check("192.168.1.1");
        assert!(result.allowed);

        let result = limiter.check("192.168.1.1");
        assert!(result.allowed);

        // Third request in same second should be blocked
        let result = limiter.check("192.168.1.1");
        assert!(!result.allowed);
        assert_eq!(result.exceeded_limit, Some("requests_per_second".into()));
    }

    #[test]
    fn test_ip_whitelist_blacklist() {
        let mut config = IpRateLimitConfig::default();
        config.whitelist.push("10.0.0.1".into());
        config.blacklist.push("evil.ip".into());

        let mut limiter = IpRateLimiter::new(config);

        // Whitelisted IP always allowed
        let result = limiter.check("10.0.0.1");
        assert!(result.allowed);
        assert_eq!(result.remaining, u32::MAX);

        // Blacklisted IP always blocked
        let result = limiter.check("evil.ip");
        assert!(!result.allowed);
        assert_eq!(result.exceeded_limit, Some("blacklist".into()));
    }

    #[test]
    fn test_ip_blocking() {
        let mut limiter = IpRateLimiter::new(IpRateLimitConfig::default());

        limiter.block("bad.ip", 60);

        let result = limiter.check("bad.ip");
        assert!(!result.allowed);
        assert!(result.retry_after.is_some());

        limiter.unblock("bad.ip");
        let result = limiter.check("bad.ip");
        assert!(result.allowed);
    }

    #[test]
    fn test_anomaly_severity() {
        assert!(AnomalySeverity::Critical > AnomalySeverity::High);
        assert!(AnomalySeverity::High > AnomalySeverity::Medium);
        assert!(AnomalySeverity::Medium > AnomalySeverity::Low);
    }
}
