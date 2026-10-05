//! Telemetry & Metrics — Observability for SOE
//!
//! Following Connector patterns: every operation is measurable.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Surface operation metrics
#[derive(Debug, Default)]
pub struct SurfaceMetrics {
    pub renders: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub errors: AtomicU64,
    pub total_render_time_ms: AtomicU64,
    pub receipts_created: AtomicU64,
    pub exports: AtomicU64,
    pub time_travel_queries: AtomicU64,
    pub policy_denials: AtomicU64,
    pub stream_events: AtomicU64,
}

impl SurfaceMetrics {
    pub fn new() -> Self { Self::default() }

    pub fn record_render(&self, duration_ms: u64) {
        self.renders.fetch_add(1, Ordering::Relaxed);
        self.total_render_time_ms.fetch_add(duration_ms, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_receipt(&self) {
        self.receipts_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_export(&self) {
        self.exports.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_time_travel(&self) {
        self.time_travel_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_policy_denial(&self) {
        self.policy_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream_event(&self) {
        self.stream_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let renders = self.renders.load(Ordering::Relaxed);
        let total_time = self.total_render_time_ms.load(Ordering::Relaxed);
        MetricsSnapshot {
            renders,
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            total_render_time_ms: total_time,
            avg_render_time_ms: if renders > 0 { total_time / renders } else { 0 },
            receipts_created: self.receipts_created.load(Ordering::Relaxed),
            exports: self.exports.load(Ordering::Relaxed),
            time_travel_queries: self.time_travel_queries.load(Ordering::Relaxed),
            policy_denials: self.policy_denials.load(Ordering::Relaxed),
            stream_events: self.stream_events.load(Ordering::Relaxed),
            cache_hit_rate: {
                let hits = self.cache_hits.load(Ordering::Relaxed);
                let misses = self.cache_misses.load(Ordering::Relaxed);
                if hits + misses > 0 { (hits as f64 / (hits + misses) as f64) * 100.0 } else { 0.0 }
            },
        }
    }

    pub fn reset(&self) {
        self.renders.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.total_render_time_ms.store(0, Ordering::Relaxed);
        self.receipts_created.store(0, Ordering::Relaxed);
        self.exports.store(0, Ordering::Relaxed);
        self.time_travel_queries.store(0, Ordering::Relaxed);
        self.policy_denials.store(0, Ordering::Relaxed);
        self.stream_events.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub renders: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub errors: u64,
    pub total_render_time_ms: u64,
    pub avg_render_time_ms: u64,
    pub receipts_created: u64,
    pub exports: u64,
    pub time_travel_queries: u64,
    pub policy_denials: u64,
    pub stream_events: u64,
    pub cache_hit_rate: f64,
}

/// Global metrics instance
pub static METRICS: std::sync::LazyLock<Arc<SurfaceMetrics>> = 
    std::sync::LazyLock::new(|| Arc::new(SurfaceMetrics::new()));

/// Get global metrics
pub fn metrics() -> &'static SurfaceMetrics {
    &METRICS
}

/// Render timer for automatic duration tracking
pub struct RenderTimer {
    pub start: std::time::Instant,
}

impl RenderTimer {
    pub fn start() -> Self {
        Self { start: std::time::Instant::now() }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn finish(self) -> u64 {
        let duration = self.start.elapsed().as_millis() as u64;
        metrics().record_render(duration);
        duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics() {
        let m = SurfaceMetrics::new();
        m.record_render(100);
        m.record_render(200);
        m.record_cache_hit();
        m.record_cache_miss();
        
        let snap = m.snapshot();
        assert_eq!(snap.renders, 2);
        assert_eq!(snap.avg_render_time_ms, 150);
        assert_eq!(snap.cache_hit_rate, 50.0);
    }

    #[test]
    fn test_render_timer() {
        let timer = RenderTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let duration = timer.finish();
        assert!(duration >= 10);
    }
}
