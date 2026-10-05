//! Rollup metrics — observable retention behavior (§61).

use connector_trust::{ProofLevel, RollupMetrics, ROLLUP_METRICS_SCHEMA};

use crate::state::PlatformState;

pub const METRICS_FOLDER: &str = "agent_memory_rollup_metrics";

pub fn load(state: &PlatformState, agent_vid: &str) -> RollupMetrics {
    let Ok(es) = state.engine_store.lock() else {
        return RollupMetrics::new(agent_vid);
    };
    if let Ok(Some(v)) = es.folder_get(METRICS_FOLDER, agent_vid) {
        return serde_json::from_value(v).unwrap_or_else(|_| RollupMetrics::new(agent_vid));
    }
    RollupMetrics::new(agent_vid)
}

pub fn save(state: &PlatformState, metrics: &RollupMetrics) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            METRICS_FOLDER,
            &metrics.agent_vid,
            &serde_json::to_value(metrics).unwrap_or_default(),
        );
    }
}

pub fn record_moment(state: &PlatformState, agent_vid: &str, level: ProofLevel) {
    let mut m = load(state, agent_vid);
    match level {
        ProofLevel::P0Full => m.p0_moments += 1,
        ProofLevel::P1Distilled => m.p1_moments += 1,
        ProofLevel::P2Contextual => m.p2_moments += 1,
        ProofLevel::P3Commitment => m.p3_moments += 1,
    }
    save(state, &m);
}

pub fn health_json(state: &PlatformState, agent_vid: &str) -> RollupMetrics {
    let mut m = load(state, agent_vid);
    m.health = if m.fade_denied_count > 100 {
        "LOCKED".into()
    } else if m.bytes_faded_total > 0 {
        "HEALTHY".into()
    } else {
        "BACKLOG".into()
    };
    m.schema = ROLLUP_METRICS_SCHEMA.into();
    m
}
