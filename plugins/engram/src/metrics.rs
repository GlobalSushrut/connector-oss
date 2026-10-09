//! Prometheus metrics registration and helper macros for Engram.
//!
//! Exported metrics:
//!   engram_memory_writes_total         — counter, labels: namespace, memory_type
//!   engram_memory_recalls_total        — counter, labels: namespace
//!   engram_entropy_score               — gauge,   labels: namespace
//!   engram_knot_score                  — gauge,   labels: namespace
//!   engram_grounding_checks_total      — counter, labels: namespace, outcome (passed|blocked|flagged)
//!   engram_cot_steps_total             — counter, labels: namespace, outcome
//!   engram_consolidations_total        — counter, labels: namespace, initiated_by
//!   engram_errors_total                — counter, labels: code, status
//!   engram_request_duration_seconds    — histogram, labels: route, method, status

/// Increment memory write counter.
pub fn record_write(namespace: &str, memory_type: &str) {
    metrics::counter!("engram_memory_writes_total",
        "namespace"   => namespace.to_owned(),
        "memory_type" => memory_type.to_owned()
    ).increment(1);
}

/// Increment recall counter.
pub fn record_recall(namespace: &str) {
    metrics::counter!("engram_memory_recalls_total",
        "namespace" => namespace.to_owned()
    ).increment(1);
}

/// Set entropy gauge for a namespace.
pub fn set_entropy(namespace: &str, score: f64) {
    metrics::gauge!("engram_entropy_score",
        "namespace" => namespace.to_owned()
    ).set(score);
}

/// Set knot entropy gauge for a namespace.
pub fn set_knot(namespace: &str, score: f64) {
    metrics::gauge!("engram_knot_score",
        "namespace" => namespace.to_owned()
    ).set(score);
}

/// Record a grounding check outcome.
pub fn record_grounding(namespace: &str, outcome: &str) {
    metrics::counter!("engram_grounding_checks_total",
        "namespace" => namespace.to_owned(),
        "outcome"   => outcome.to_owned()
    ).increment(1);
}

/// Record a CoT step outcome.
pub fn record_cot_step(namespace: &str, outcome: &str) {
    metrics::counter!("engram_cot_steps_total",
        "namespace" => namespace.to_owned(),
        "outcome"   => outcome.to_owned()
    ).increment(1);
}

/// Record a consolidation run.
pub fn record_consolidation(namespace: &str, initiated_by: &str) {
    metrics::counter!("engram_consolidations_total",
        "namespace"    => namespace.to_owned(),
        "initiated_by" => initiated_by.to_owned()
    ).increment(1);
}
