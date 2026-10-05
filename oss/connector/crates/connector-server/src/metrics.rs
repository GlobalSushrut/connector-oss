//! Prometheus metrics for Connector server.
//!
//! All metrics are kernel-verified — they come from real kernel audit data.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

pub struct Metrics {
    pub registry: Registry,
    pub pipeline_duration_ms: Histogram,
    pub trust_score: Gauge<f64, AtomicU64>,
    pub events_total: Counter,
    pub actions_authorized: Counter,
    pub actions_denied: Counter,
    pub memory_ops_total: Counter,
    pub warnings_total: Counter,
    pub errors_total: Counter,
    pub requests_total: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let pipeline_duration_ms = Histogram::new(
            exponential_buckets(1.0, 2.0, 15),
        );
        registry.register(
            "connector_pipeline_duration_ms",
            "Pipeline execution time in milliseconds",
            pipeline_duration_ms.clone(),
        );

        let trust_score = Gauge::<f64, AtomicU64>::default();
        registry.register(
            "connector_trust_score",
            "Current trust score (0-100)",
            trust_score.clone(),
        );

        let events_total = Counter::default();
        registry.register(
            "connector_events_total",
            "Total observation events",
            events_total.clone(),
        );

        let actions_authorized = Counter::default();
        registry.register(
            "connector_actions_authorized",
            "Authorized actions",
            actions_authorized.clone(),
        );

        let actions_denied = Counter::default();
        registry.register(
            "connector_actions_denied",
            "Denied actions",
            actions_denied.clone(),
        );

        let memory_ops_total = Counter::default();
        registry.register(
            "connector_memory_ops_total",
            "Memory operations",
            memory_ops_total.clone(),
        );

        let warnings_total = Counter::default();
        registry.register(
            "connector_warnings_total",
            "Warnings generated",
            warnings_total.clone(),
        );

        let errors_total = Counter::default();
        registry.register(
            "connector_errors_total",
            "Errors generated",
            errors_total.clone(),
        );

        let requests_total = Counter::default();
        registry.register(
            "connector_requests_total",
            "Total HTTP requests",
            requests_total.clone(),
        );

        Self {
            registry,
            pipeline_duration_ms,
            trust_score,
            events_total,
            actions_authorized,
            actions_denied,
            memory_ops_total,
            warnings_total,
            errors_total,
            requests_total,
        }
    }

    /// Update metrics from a PipelineOutput.
    pub fn record_output(&self, output: &connector_engine::PipelineOutput) {
        self.pipeline_duration_ms.observe(output.status.duration_ms as f64);
        self.trust_score.set(output.status.trust as f64);
        self.events_total.inc_by(output.events.len() as u64);
        self.actions_authorized.inc_by(output.aapi.authorized as u64);
        self.actions_denied.inc_by(output.aapi.denied as u64);
        self.memory_ops_total.inc_by(output.memory.created as u64 + output.memory.recalled as u64);
        self.warnings_total.inc_by(output.warnings.len() as u64);
        self.errors_total.inc_by(output.errors.len() as u64);
        self.requests_total.inc();
    }

    /// Encode metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).unwrap_or_default();
        buf
    }
}
