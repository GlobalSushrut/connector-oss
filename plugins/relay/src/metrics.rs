//! Prometheus metrics for Relay.

use metrics::{counter, gauge, histogram};

pub fn register_all() {
    metrics::describe_counter!("relay_invocations_total",        "Total function invocations");
    metrics::describe_counter!("relay_errors_total",             "Total relay errors by code");
    metrics::describe_counter!("relay_budget_exceeded_total",    "Invocations blocked by budget gate");
    metrics::describe_counter!("relay_admission_denied_total",   "Invocations blocked by admission gate");
    metrics::describe_counter!("relay_cost_usd_total",           "Total USD cost attributed by relay");
    metrics::describe_histogram!("relay_invocation_latency_ms",  "Invocation latency in milliseconds");
    metrics::describe_gauge!("relay_functions_registered",       "Number of registered functions");
    metrics::describe_gauge!("relay_functions_healthy",          "Number of healthy functions");
}

pub fn record_invocation(function: &str, outcome: &str) {
    counter!(
        "relay_invocations_total",
        "function" => function.to_owned(),
        "outcome"  => outcome.to_owned(),
    ).increment(1);
}

pub fn record_cost(function: &str, cost_usd: f64) {
    counter!(
        "relay_cost_usd_total",
        "function" => function.to_owned(),
    ).absolute(cost_usd as u64);
}

pub fn record_latency(function: &str, latency_ms: i64) {
    histogram!(
        "relay_invocation_latency_ms",
        "function" => function.to_owned(),
    ).record(latency_ms as f64);
}

pub fn set_function_counts(total: i64, healthy: i64) {
    gauge!("relay_functions_registered").set(total as f64);
    gauge!("relay_functions_healthy").set(healthy as f64);
}
