//! Prometheus-Compatible Metrics Export
//!
//! Provides observability for the agent infrastructure with metrics that can be
//! scraped by Prometheus or compatible monitoring systems.
//!
//! # Metric Types
//!
//! - **Counter** — Monotonically increasing value (e.g., total agents deployed)
//! - **Gauge** — Value that can go up or down (e.g., current running agents)
//! - **Histogram** — Distribution of values (e.g., agent startup latency)
//! - **Summary** — Similar to histogram with quantiles
//!
//! # Standard Metrics
//!
//! ```text
//! # HELP connector_agents_total Total number of agents deployed
//! # TYPE connector_agents_total counter
//! connector_agents_total{namespace="default",status="running"} 42
//!
//! # HELP connector_agent_startup_seconds Agent startup duration
//! # TYPE connector_agent_startup_seconds histogram
//! connector_agent_startup_seconds_bucket{le="0.5"} 10
//! connector_agent_startup_seconds_bucket{le="1.0"} 25
//! connector_agent_startup_seconds_bucket{le="5.0"} 40
//! connector_agent_startup_seconds_bucket{le="+Inf"} 42
//! connector_agent_startup_seconds_sum 85.5
//! connector_agent_startup_seconds_count 42
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// Metric Types
// ═══════════════════════════════════════════════════════════════════════

/// Counter metric (monotonically increasing)
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, v: u64) {
        self.value.fetch_add(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Gauge metric (can go up or down)
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Histogram metric (distribution of values)
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<(f64, AtomicU64)>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Create with default buckets (suitable for latency in seconds)
    pub fn new() -> Self {
        Self::with_buckets(&[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    }

    /// Create with custom buckets
    pub fn with_buckets(bounds: &[f64]) -> Self {
        let buckets = bounds.iter()
            .map(|&b| (b, AtomicU64::new(0)))
            .collect();
        Self {
            buckets,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Observe a value
    pub fn observe(&self, v: f64) {
        for (bound, count) in &self.buckets {
            if v <= *bound {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Store sum as fixed-point (multiply by 1000 for millisecond precision)
        self.sum.fetch_add((v * 1000.0) as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get bucket counts
    pub fn buckets(&self) -> Vec<(f64, u64)> {
        self.buckets.iter()
            .map(|(b, c)| (*b, c.load(Ordering::Relaxed)))
            .collect()
    }

    /// Get sum
    pub fn sum(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Get count
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Labeled Metrics
// ═══════════════════════════════════════════════════════════════════════

/// Labels for a metric
pub type Labels = HashMap<String, String>;

/// Counter with labels
#[derive(Debug, Default)]
pub struct CounterVec {
    metrics: std::sync::RwLock<HashMap<String, Counter>>,
    label_names: Vec<String>,
}

impl CounterVec {
    pub fn new(label_names: &[&str]) -> Self {
        Self {
            metrics: std::sync::RwLock::new(HashMap::new()),
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn key(&self, labels: &[&str]) -> String {
        labels.join("\x00")
    }

    pub fn with_label_values(&self, labels: &[&str]) -> CounterRef {
        let key = self.key(labels);
        {
            let metrics = self.metrics.read().unwrap();
            if metrics.contains_key(&key) {
                return CounterRef { vec: self, key };
            }
        }
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.entry(key.clone()).or_insert_with(Counter::new);
        }
        CounterRef { vec: self, key }
    }

    pub fn collect(&self) -> Vec<(Labels, u64)> {
        let metrics = self.metrics.read().unwrap();
        metrics.iter().map(|(key, counter)| {
            let values: Vec<&str> = key.split('\x00').collect();
            let labels: Labels = self.label_names.iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            (labels, counter.get())
        }).collect()
    }
}

pub struct CounterRef<'a> {
    vec: &'a CounterVec,
    key: String,
}

impl<'a> CounterRef<'a> {
    pub fn inc(&self) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(counter) = metrics.get(&self.key) {
            counter.inc();
        }
    }

    pub fn inc_by(&self, v: u64) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(counter) = metrics.get(&self.key) {
            counter.inc_by(v);
        }
    }
}

/// Gauge with labels
#[derive(Debug, Default)]
pub struct GaugeVec {
    metrics: std::sync::RwLock<HashMap<String, Gauge>>,
    label_names: Vec<String>,
}

impl GaugeVec {
    pub fn new(label_names: &[&str]) -> Self {
        Self {
            metrics: std::sync::RwLock::new(HashMap::new()),
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn key(&self, labels: &[&str]) -> String {
        labels.join("\x00")
    }

    pub fn with_label_values(&self, labels: &[&str]) -> GaugeRef {
        let key = self.key(labels);
        {
            let metrics = self.metrics.read().unwrap();
            if metrics.contains_key(&key) {
                return GaugeRef { vec: self, key };
            }
        }
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.entry(key.clone()).or_insert_with(Gauge::new);
        }
        GaugeRef { vec: self, key }
    }

    pub fn collect(&self) -> Vec<(Labels, u64)> {
        let metrics = self.metrics.read().unwrap();
        metrics.iter().map(|(key, gauge)| {
            let values: Vec<&str> = key.split('\x00').collect();
            let labels: Labels = self.label_names.iter()
                .zip(values.iter())
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            (labels, gauge.get())
        }).collect()
    }
}

pub struct GaugeRef<'a> {
    vec: &'a GaugeVec,
    key: String,
}

impl<'a> GaugeRef<'a> {
    pub fn set(&self, v: u64) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(gauge) = metrics.get(&self.key) {
            gauge.set(v);
        }
    }

    pub fn inc(&self) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(gauge) = metrics.get(&self.key) {
            gauge.inc();
        }
    }

    pub fn dec(&self) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(gauge) = metrics.get(&self.key) {
            gauge.dec();
        }
    }
}

/// Histogram with labels
#[derive(Debug)]
pub struct HistogramVec {
    metrics: std::sync::RwLock<HashMap<String, Histogram>>,
    label_names: Vec<String>,
    buckets: Vec<f64>,
}

impl HistogramVec {
    pub fn new(label_names: &[&str], buckets: &[f64]) -> Self {
        Self {
            metrics: std::sync::RwLock::new(HashMap::new()),
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            buckets: buckets.to_vec(),
        }
    }

    fn key(&self, labels: &[&str]) -> String {
        labels.join("\x00")
    }

    pub fn with_label_values(&self, labels: &[&str]) -> HistogramRef {
        let key = self.key(labels);
        {
            let metrics = self.metrics.read().unwrap();
            if metrics.contains_key(&key) {
                return HistogramRef { vec: self, key };
            }
        }
        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.entry(key.clone()).or_insert_with(|| Histogram::with_buckets(&self.buckets));
        }
        HistogramRef { vec: self, key }
    }
}

pub struct HistogramRef<'a> {
    vec: &'a HistogramVec,
    key: String,
}

impl<'a> HistogramRef<'a> {
    pub fn observe(&self, v: f64) {
        let metrics = self.vec.metrics.read().unwrap();
        if let Some(histogram) = metrics.get(&self.key) {
            histogram.observe(v);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Metrics Registry
// ═══════════════════════════════════════════════════════════════════════

/// Metric descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDescriptor {
    pub name: String,
    pub help: String,
    pub metric_type: MetricType,
    pub label_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

/// Connector metrics registry
pub struct MetricsRegistry {
    // ─── Counters ───────────────────────────────────────────
    /// Total agents deployed
    pub agents_deployed_total: CounterVec,
    /// Total agents terminated
    pub agents_terminated_total: CounterVec,
    /// Total stability blocks produced
    pub stability_blocks_total: Counter,
    /// Total healing actions taken
    pub healing_actions_total: CounterVec,
    /// Total syscalls processed
    pub syscalls_total: CounterVec,
    /// Total packets ingested
    pub packets_ingested_total: CounterVec,
    /// Total tokens consumed
    pub tokens_consumed_total: CounterVec,

    // ─── Gauges ─────────────────────────────────────────────
    /// Current running agents
    pub agents_running: GaugeVec,
    /// Current pending agents
    pub agents_pending: GaugeVec,
    /// Current failed agents
    pub agents_failed: GaugeVec,
    /// Current cell load
    pub cell_load: GaugeVec,
    /// Current memory usage bytes
    pub memory_usage_bytes: GaugeVec,

    // ─── Histograms ─────────────────────────────────────────
    /// Agent startup duration
    pub agent_startup_seconds: HistogramVec,
    /// Heartbeat latency
    pub heartbeat_latency_seconds: HistogramVec,
    /// Syscall duration
    pub syscall_duration_seconds: HistogramVec,
    /// Packet ingest duration
    pub packet_ingest_seconds: HistogramVec,

    // ─── Metadata ───────────────────────────────────────────
    /// Last scrape timestamp
    pub last_scrape_ms: AtomicU64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            // Counters
            agents_deployed_total: CounterVec::new(&["namespace", "cell"]),
            agents_terminated_total: CounterVec::new(&["namespace", "reason"]),
            stability_blocks_total: Counter::new(),
            healing_actions_total: CounterVec::new(&["action_type"]),
            syscalls_total: CounterVec::new(&["operation", "outcome"]),
            packets_ingested_total: CounterVec::new(&["namespace", "packet_type"]),
            tokens_consumed_total: CounterVec::new(&["namespace", "model"]),

            // Gauges
            agents_running: GaugeVec::new(&["namespace", "cell"]),
            agents_pending: GaugeVec::new(&["namespace"]),
            agents_failed: GaugeVec::new(&["namespace"]),
            cell_load: GaugeVec::new(&["cell"]),
            memory_usage_bytes: GaugeVec::new(&["namespace"]),

            // Histograms
            agent_startup_seconds: HistogramVec::new(
                &["namespace"],
                &[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            ),
            heartbeat_latency_seconds: HistogramVec::new(
                &["cell"],
                &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25],
            ),
            syscall_duration_seconds: HistogramVec::new(
                &["operation"],
                &[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1],
            ),
            packet_ingest_seconds: HistogramVec::new(
                &["namespace"],
                &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
            ),

            last_scrape_ms: AtomicU64::new(0),
        }
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // agents_deployed_total
        output.push_str("# HELP connector_agents_deployed_total Total agents deployed\n");
        output.push_str("# TYPE connector_agents_deployed_total counter\n");
        for (labels, value) in self.agents_deployed_total.collect() {
            output.push_str(&format!(
                "connector_agents_deployed_total{{namespace=\"{}\",cell=\"{}\"}} {}\n",
                labels.get("namespace").unwrap_or(&String::new()),
                labels.get("cell").unwrap_or(&String::new()),
                value
            ));
        }

        // agents_terminated_total
        output.push_str("# HELP connector_agents_terminated_total Total agents terminated\n");
        output.push_str("# TYPE connector_agents_terminated_total counter\n");
        for (labels, value) in self.agents_terminated_total.collect() {
            output.push_str(&format!(
                "connector_agents_terminated_total{{namespace=\"{}\",reason=\"{}\"}} {}\n",
                labels.get("namespace").unwrap_or(&String::new()),
                labels.get("reason").unwrap_or(&String::new()),
                value
            ));
        }

        // stability_blocks_total
        output.push_str("# HELP connector_stability_blocks_total Total stability blocks produced\n");
        output.push_str("# TYPE connector_stability_blocks_total counter\n");
        output.push_str(&format!("connector_stability_blocks_total {}\n", self.stability_blocks_total.get()));

        // agents_running
        output.push_str("# HELP connector_agents_running Current running agents\n");
        output.push_str("# TYPE connector_agents_running gauge\n");
        for (labels, value) in self.agents_running.collect() {
            output.push_str(&format!(
                "connector_agents_running{{namespace=\"{}\",cell=\"{}\"}} {}\n",
                labels.get("namespace").unwrap_or(&String::new()),
                labels.get("cell").unwrap_or(&String::new()),
                value
            ));
        }

        // cell_load
        output.push_str("# HELP connector_cell_load Current cell load percentage\n");
        output.push_str("# TYPE connector_cell_load gauge\n");
        for (labels, value) in self.cell_load.collect() {
            output.push_str(&format!(
                "connector_cell_load{{cell=\"{}\"}} {}\n",
                labels.get("cell").unwrap_or(&String::new()),
                value
            ));
        }

        self.last_scrape_ms.store(now_ms() as u64, Ordering::Relaxed);

        output
    }

    /// Export metrics as JSON
    pub fn export_json(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp_ms: now_ms(),
            counters: vec![
                ("agents_deployed_total".to_string(), self.agents_deployed_total.collect()),
                ("agents_terminated_total".to_string(), self.agents_terminated_total.collect()),
            ],
            gauges: vec![
                ("agents_running".to_string(), self.agents_running.collect()),
                ("cell_load".to_string(), self.cell_load.collect()),
            ],
            scalars: vec![
                ("stability_blocks_total".to_string(), self.stability_blocks_total.get()),
            ],
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics snapshot for JSON export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp_ms: i64,
    pub counters: Vec<(String, Vec<(Labels, u64)>)>,
    pub gauges: Vec<(String, Vec<(Labels, u64)>)>,
    pub scalars: Vec<(String, u64)>,
}

// ═══════════════════════════════════════════════════════════════════════
// Global Registry (singleton pattern)
// ═══════════════════════════════════════════════════════════════════════

use std::sync::OnceLock;

static GLOBAL_REGISTRY: OnceLock<MetricsRegistry> = OnceLock::new();

/// Get the global metrics registry
pub fn global_registry() -> &'static MetricsRegistry {
    GLOBAL_REGISTRY.get_or_init(MetricsRegistry::new)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(10);
        assert_eq!(gauge.get(), 10);

        gauge.inc();
        assert_eq!(gauge.get(), 11);

        gauge.dec();
        assert_eq!(gauge.get(), 10);
    }

    #[test]
    fn test_histogram() {
        let hist = Histogram::with_buckets(&[1.0, 5.0, 10.0]);

        hist.observe(0.5);
        hist.observe(3.0);
        hist.observe(7.0);
        hist.observe(15.0);

        let buckets = hist.buckets();
        assert_eq!(buckets[0].1, 1); // <= 1.0
        assert_eq!(buckets[1].1, 2); // <= 5.0
        assert_eq!(buckets[2].1, 3); // <= 10.0

        assert_eq!(hist.count(), 4);
    }

    #[test]
    fn test_counter_vec() {
        let counter_vec = CounterVec::new(&["namespace", "status"]);

        counter_vec.with_label_values(&["default", "running"]).inc();
        counter_vec.with_label_values(&["default", "running"]).inc();
        counter_vec.with_label_values(&["default", "failed"]).inc();

        let collected = counter_vec.collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_gauge_vec() {
        let gauge_vec = GaugeVec::new(&["cell"]);

        gauge_vec.with_label_values(&["cell-01"]).set(10);
        gauge_vec.with_label_values(&["cell-02"]).set(20);

        let collected = gauge_vec.collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_prometheus_export() {
        let registry = MetricsRegistry::new();

        registry.agents_deployed_total.with_label_values(&["default", "cell-01"]).inc();
        registry.agents_running.with_label_values(&["default", "cell-01"]).set(5);
        registry.stability_blocks_total.inc_by(100);

        let output = registry.export_prometheus();

        assert!(output.contains("connector_agents_deployed_total"));
        assert!(output.contains("connector_agents_running"));
        assert!(output.contains("connector_stability_blocks_total 100"));
    }

    #[test]
    fn test_json_export() {
        let registry = MetricsRegistry::new();

        registry.agents_deployed_total.with_label_values(&["default", "cell-01"]).inc();
        registry.stability_blocks_total.inc_by(50);

        let snapshot = registry.export_json();

        assert!(snapshot.timestamp_ms > 0);
        assert!(!snapshot.counters.is_empty());
        assert_eq!(snapshot.scalars[0].1, 50);
    }
}
