//! Workflow projection adapters — durable substrate append for TT/WC proxy hops (I-14 partial).

use axum::http::HeaderMap;
use connector_trust::{ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA};
use serde_json::json;

use crate::{
    state::PlatformState,
    substrate::artifact_log::append_artifact_record,
};

pub fn record_tracetramp_admin_forward(
    state: &PlatformState,
    method: &str,
    admin_path: &str,
    tenant_id: Option<&str>,
    headers: &HeaderMap,
) {
    let flow_id = headers
        .get("x-connector-flow-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    let principal = crate::substrate::outbound::principal_from_inbound(headers)
        .map(|p| p.subject);
    let record = ArtifactLogRecordV2 {
        schema: ARTIFACT_LOG_SCHEMA.into(),
        record_id: format!("ttproj_{}", uuid::Uuid::new_v4()),
        artifact_class: ArtifactClass::Workflow,
        artifact_type: "tracetramp_projection".into(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        segment_id: None,
        principal_id: principal,
        tenant_id: tenant_id.map(str::to_string),
        content_digest: None,
        payload: json!({
            "method": method,
            "admin_path": admin_path,
            "fni_flow_id": flow_id,
            "projection": "platform_artifact_log",
            "handoff_note": "WC handoff remains plugin-side; platform records projection for durable correlation",
        }),
        contract_version: 2,
    };
    append_artifact_record(state, &record);
    if admin_path.contains("handoff")
        || admin_path.contains("witness")
        || admin_path.contains("evidence")
        || admin_path.contains("custody")
    {
        crate::substrate::handoff_queue::record_tt_handoff_pending(
            state,
            admin_path,
            tenant_id,
            flow_id.as_deref(),
        );
    }
}

pub fn record_witnessctl_forward(
    state: &PlatformState,
    method: &str,
    api_path: &str,
    tenant_id: Option<&str>,
    headers: &axum::http::HeaderMap,
) {
    let flow_id = headers
        .get("x-connector-flow-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    let principal = crate::substrate::outbound::principal_from_inbound(headers)
        .map(|p| p.subject);
    let record = ArtifactLogRecordV2 {
        schema: ARTIFACT_LOG_SCHEMA.into(),
        record_id: format!("wcproj_{}", uuid::Uuid::new_v4()),
        artifact_class: ArtifactClass::Workflow,
        artifact_type: "witnessctl_projection".into(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        segment_id: None,
        principal_id: principal,
        tenant_id: tenant_id.map(str::to_string),
        content_digest: None,
        payload: json!({
            "method": method,
            "api_path": api_path,
            "fni_flow_id": flow_id,
            "projection": "platform_artifact_log",
        }),
        contract_version: 2,
    };
    append_artifact_record(state, &record);
    crate::substrate::handoff_queue::record_wc_proxy_success(
        state,
        api_path,
        tenant_id,
        flow_id.as_deref(),
    );
}

pub fn projection_record_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys("artifact_log_v2", None)
        .map(|keys| {
            keys.iter()
                .filter(|k| k.starts_with("ttproj_") || k.starts_with("wcproj_"))
                .count()
        })
        .unwrap_or(0)
}
