//! WC handoff queue — durable platform-side correlation for custody projection (I-14 partial).

use connector_trust::{ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA};
use serde_json::json;

use crate::{
    state::PlatformState,
    substrate::artifact_log::append_artifact_record,
};

pub const HANDOFF_QUEUE_FOLDER: &str = "handoff_queue_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffStatus {
    Delivered,
    Pending,
    DeadLetter,
}

pub fn record_wc_proxy_success(
    state: &PlatformState,
    api_path: &str,
    tenant_id: Option<&str>,
    flow_id: Option<&str>,
) {
    let status = if api_path.contains("ingest") || api_path.contains("seal") {
        HandoffStatus::Delivered
    } else {
        HandoffStatus::Pending
    };
    let record_id = format!("handoff_{}", uuid::Uuid::new_v4());
    let status_str = match status {
        HandoffStatus::Delivered => "delivered",
        HandoffStatus::Pending => "pending",
        HandoffStatus::DeadLetter => "dead_letter",
    };
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        HANDOFF_QUEUE_FOLDER,
        &record_id,
        &json!({
            "schema": "handoff_queue.v1",
            "record_id": record_id,
            "target": "witnessctl",
            "api_path": api_path,
            "tenant_id": tenant_id,
            "fni_flow_id": flow_id,
            "status": status_str,
            "observed_at": chrono::Utc::now().to_rfc3339(),
            "note": "Platform projection; plugin TT→WC handoff remains separate",
        }),
    );
    drop(es);

    let artifact = ArtifactLogRecordV2 {
        schema: ARTIFACT_LOG_SCHEMA.into(),
        record_id: format!("wchoff_{record_id}"),
        artifact_class: ArtifactClass::Workflow,
        artifact_type: "witnessctl_handoff_projection".into(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        segment_id: None,
        principal_id: None,
        tenant_id: tenant_id.map(str::to_string),
        content_digest: None,
        payload: json!({
            "api_path": api_path,
            "status": status_str,
            "fni_flow_id": flow_id,
        }),
        contract_version: 2,
    };
    append_artifact_record(state, &artifact);
}

pub fn handoff_pending_ttl_secs() -> i64 {
    std::env::var("CONNECTOR_HANDOFF_PENDING_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}

/// Reap stale pending handoffs as dead_letter (evidence-required hygiene).
pub fn reap_stale_pending_handoffs(state: &PlatformState) {
    let ttl = handoff_pending_ttl_secs();
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(ttl);
    let mut es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(HANDOFF_QUEUE_FOLDER, None).unwrap_or_default();
    for k in keys {
        let Some(v) = es.folder_get(HANDOFF_QUEUE_FOLDER, &k).ok().flatten() else {
            continue;
        };
        if v.get("status").and_then(|s| s.as_str()) != Some("pending") {
            continue;
        }
        let observed = v
            .get("observed_at")
            .and_then(|s| s.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        if observed.is_some_and(|t| t < cutoff) {
            let mut updated = v.clone();
            if let Some(obj) = updated.as_object_mut() {
                obj.insert("status".into(), json!("dead_letter"));
                obj.insert(
                    "dead_letter_reason".into(),
                    json!("pending_ttl_exceeded"),
                );
            }
            let _ = es.folder_put(HANDOFF_QUEUE_FOLDER, &k, &updated);
        }
    }
}

pub fn record_tt_handoff_pending(
    state: &PlatformState,
    api_path: &str,
    tenant_id: Option<&str>,
    flow_id: Option<&str>,
) {
    let record_id = format!("handoff_{}", uuid::Uuid::new_v4());
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        HANDOFF_QUEUE_FOLDER,
        &record_id,
        &json!({
            "schema": "handoff_queue.v1",
            "record_id": record_id,
            "target": "witnessctl",
            "source": "tracetramp",
            "api_path": api_path,
            "tenant_id": tenant_id,
            "fni_flow_id": flow_id,
            "status": "pending",
            "observed_at": chrono::Utc::now().to_rfc3339(),
            "note": "TT admin forward on handoff/evidence path; WC ingest/seal clears pending",
        }),
    );
}

pub fn handoff_required_enabled() -> bool {
    matches!(
        std::env::var("CONNECTOR_HANDOFF_REQUIRED")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

pub fn handoff_pending_max() -> usize {
    std::env::var("CONNECTOR_HANDOFF_PENDING_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(50)
}

/// Fail-closed when required mode is on and pending handoffs exceed the cap.
pub fn handoff_backpressure_active(state: &PlatformState) -> bool {
    if !handoff_required_enabled() {
        return false;
    }
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(HANDOFF_QUEUE_FOLDER, None).unwrap_or_default();
    let mut pending = 0usize;
    for k in &keys {
        let Some(v) = es.folder_get(HANDOFF_QUEUE_FOLDER, k).ok().flatten() else {
            continue;
        };
        match v.get("status").and_then(|s| s.as_str()) {
            Some("delivered") | Some("dead_letter") => {}
            _ => pending += 1,
        }
    }
    pending >= handoff_pending_max()
}

pub fn handoff_queue_stats(state: &PlatformState) -> serde_json::Value {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(HANDOFF_QUEUE_FOLDER, None).unwrap_or_default();
    let mut delivered = 0usize;
    let mut pending = 0usize;
    let mut dead_letter = 0usize;
    for k in &keys {
        let Some(v) = es.folder_get(HANDOFF_QUEUE_FOLDER, k).ok().flatten() else {
            continue;
        };
        match v.get("status").and_then(|s| s.as_str()) {
            Some("delivered") => delivered += 1,
            Some("dead_letter") => dead_letter += 1,
            _ => pending += 1,
        }
    }
    json!({
        "schema": "handoff_queue_stats.v1",
        "total": keys.len(),
        "delivered": delivered,
        "pending": pending,
        "dead_letter": dead_letter,
        "evidence_required_mode": handoff_required_enabled(),
        "pending_max": handoff_pending_max(),
        "backpressure_active": handoff_backpressure_active(state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_pending_max_is_positive() {
        assert!(handoff_pending_max() >= 1);
    }
}
