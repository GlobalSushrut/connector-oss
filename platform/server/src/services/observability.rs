//! Native observability ringbuffer (Phase 1.10.1 starter).
//!
//! Keeps recent request-level samples in memory so operators can inspect latency/RPS/error
//! trends without external Prometheus/Grafana.

use std::collections::{BTreeMap, VecDeque};

use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::SharedState;

const DEFAULT_CAPACITY: usize = 2048;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeObsSample {
    pub ts_ms: i64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: u64,
    pub plugin_id: Option<String>,
}

#[derive(Debug)]
pub struct NativeObservabilityStore {
    cap: usize,
    samples: VecDeque<NativeObsSample>,
}

impl Default for NativeObservabilityStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl NativeObservabilityStore {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(128),
            samples: VecDeque::new(),
        }
    }

    pub fn record(&mut self, sample: NativeObsSample) {
        if self.samples.len() >= self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn snapshot(&self, last_n: usize) -> Vec<NativeObsSample> {
        let n = last_n.max(1).min(self.cap);
        let start = self.samples.len().saturating_sub(n);
        self.samples.iter().skip(start).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct NativeObsQuery {
    pub last_n: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct NativeChartPinRequest {
    pub chart_id: String,
    pub pinned: bool,
}

fn p95(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let idx = ((values.len() as f64) * 0.95).ceil() as usize;
    values[idx.saturating_sub(1).min(values.len() - 1)]
}

fn path_is_plugin_call(path: &str) -> Option<String> {
    let p = path.trim_end_matches('/');
    for prefix in ["/api/v1/plugins/", "/plugin/"] {
        if let Some(rest) = p.strip_prefix(prefix) {
            let seg = rest.split('/').next().unwrap_or("").trim();
            if !seg.is_empty() && seg != "status" && seg != "health" {
                return Some(seg.to_string());
            }
        }
    }
    None
}

pub fn plugin_id_from_path(path: &str) -> Option<String> {
    path_is_plugin_call(path)
}

/// `GET /api/v1/monitor/native` — in-process observability rollup.
pub async fn native_dashboard(
    State(state): State<SharedState>,
    Query(q): Query<NativeObsQuery>,
) -> Json<serde_json::Value> {
    let last_n = q.last_n.unwrap_or(400);
    let (samples, len, cap) = {
        let obs = state.observability.lock().unwrap();
        (obs.snapshot(last_n), obs.len(), obs.capacity())
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let recent_1m: Vec<_> = samples
        .iter()
        .filter(|s| now_ms.saturating_sub(s.ts_ms) <= 60_000)
        .cloned()
        .collect();
    let recent_5m: Vec<_> = samples
        .iter()
        .filter(|s| now_ms.saturating_sub(s.ts_ms) <= 300_000)
        .cloned()
        .collect();

    let mut by_plugin: BTreeMap<String, usize> = BTreeMap::new();
    let mut err_5m = 0usize;
    let mut lat_5m = Vec::new();
    for s in &recent_5m {
        if s.status >= 500 {
            err_5m += 1;
        }
        lat_5m.push(s.latency_ms);
        if let Some(pid) = s.plugin_id.as_ref() {
            *by_plugin.entry(pid.clone()).or_insert(0) += 1;
        }
    }
    let rps_1m = recent_1m.len() as f64 / 60.0;
    let err_rate_5m = if recent_5m.is_empty() {
        0.0
    } else {
        (err_5m as f64) / (recent_5m.len() as f64)
    };

    let microvm_rollup = {
        let host = state.kernel_host.lock().unwrap();
        host.microvm_rollup_json()
    };

    Json(json!({
        "ok": true,
        "native_observability": {
            "ringbuffer": {
                "capacity": cap,
                "stored": len,
                "returned": samples.len(),
                "window": format!("last {} samples", last_n),
            },
            "rollup": {
                "rps_1m": (rps_1m * 100.0).round() / 100.0,
                "requests_1m": recent_1m.len(),
                "requests_5m": recent_5m.len(),
                "errors_5xx_5m": err_5m,
                "error_rate_5m": (err_rate_5m * 10000.0).round() / 100.0, // percentage
                "latency_p95_ms_5m": p95(lat_5m),
            },
            "plugin_request_counts_5m": by_plugin,
            "microvm_rollup": microvm_rollup,
        },
        "samples": samples,
        "hint": "last_n controls returned samples. Values are in-process only (reset on restart)."
    }))
}

/// GET /api/v1/monitor/native/charts — native chart presets + pin state.
pub async fn native_charts(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let pin_key = "native_monitor";
    let pinned = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("_dashboard_pins", pin_key)
            .ok()
            .flatten()
            .and_then(|v| v.get("chart_ids").and_then(|x| x.as_array()).cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
    };
    Json(json!({
        "ok": true,
        "page": "monitor.native",
        "pinned_chart_ids": pinned,
        "charts": [
            {"id":"rps_1m","title":"RPS (1m)","source":"native_observability.rollup.rps_1m"},
            {"id":"latency_p95_5m","title":"Latency p95 (5m)","source":"native_observability.rollup.latency_p95_ms_5m"},
            {"id":"error_rate_5m","title":"Error rate % (5m)","source":"native_observability.rollup.error_rate_5m"},
            {"id":"plugin_request_counts_5m","title":"Plugin requests (5m)","source":"native_observability.plugin_request_counts_5m"},
            {"id":"microvm_by_core","title":"MicroVM usage by core","source":"native_observability.microvm_rollup.by_core"},
            {"id":"microvm_by_shard","title":"MicroVM usage by shard","source":"native_observability.microvm_rollup.by_shard"}
        ]
    }))
}

/// POST /api/v1/monitor/native/charts/pins — save pinned chart ids for native monitor page.
pub async fn set_native_chart_pin(
    State(state): State<SharedState>,
    Json(req): Json<NativeChartPinRequest>,
) -> Json<serde_json::Value> {
    if req.chart_id.trim().is_empty() {
        return Json(json!({"ok": false, "error": "chart_id required"}));
    }
    let pin_key = "native_monitor";
    let mut es = state.engine_store.lock().unwrap();
    let mut pins: Vec<String> = es
        .folder_get("_dashboard_pins", pin_key)
        .ok()
        .flatten()
        .and_then(|v| v.get("chart_ids").and_then(|x| x.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let id = req.chart_id.trim().to_string();
    if req.pinned {
        if !pins.iter().any(|p| p == &id) {
            pins.push(id.clone());
        }
    } else {
        pins.retain(|p| p != &id);
    }
    let _ = es.folder_put(
        "_dashboard_pins",
        pin_key,
        &json!({
            "chart_ids": pins,
            "updated_at": chrono::Utc::now().to_rfc3339()
        }),
    );
    Json(json!({"ok": true, "chart_id": id, "pinned": req.pinned}))
}
