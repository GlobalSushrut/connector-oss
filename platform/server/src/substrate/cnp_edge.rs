//! CNP edge records for external protocol virtualization (I-18 partial).

use connector_trust::{ArtifactClass, ArtifactLogRecordV2, ARTIFACT_LOG_SCHEMA};
use serde_json::json;

use crate::{
    protocol_gateway::GatewayContext,
    state::PlatformState,
    substrate::artifact_log::append_artifact_record,
};

/// Record a CNP edge for protocol gateway handlers (I-18).
pub fn record_gateway_handler(
    state: &PlatformState,
    ctx: &GatewayContext,
    route_path: &str,
) {
    record_protocol_edge(state, ctx, route_path, 200);
}

pub fn record_protocol_edge(
    state: &PlatformState,
    ctx: &GatewayContext,
    route_path: &str,
    status_code: u16,
) {
    let record = ArtifactLogRecordV2 {
        schema: ARTIFACT_LOG_SCHEMA.into(),
        record_id: format!("cnpedge_{}", uuid::Uuid::new_v4()),
        artifact_class: ArtifactClass::Audit,
        artifact_type: "cnp_edge".into(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        segment_id: None,
        principal_id: Some(ctx.peer.subject.clone()),
        tenant_id: None,
        content_digest: None,
        payload: json!({
            "protocol": ctx.peer.protocol,
            "auth_method": ctx.peer.auth_method,
            "route_path": route_path,
            "request_id": ctx.request_id,
            "status_code": status_code,
            "virtualization_scope": "protocol_gateway",
        }),
        contract_version: 2,
    };
    append_artifact_record(state, &record);
}

/// CNP edge for main REST `/protocols/*` handlers (I-18 REST parity).
pub fn record_rest_protocol_edge(
    state: &PlatformState,
    route_path: &str,
    protocol: &str,
    principal_id: Option<&str>,
    tenant_id: Option<&str>,
    status_code: u16,
) {
    let record = ArtifactLogRecordV2 {
        schema: ARTIFACT_LOG_SCHEMA.into(),
        record_id: format!("cnpedge_{}", uuid::Uuid::new_v4()),
        artifact_class: ArtifactClass::Audit,
        artifact_type: "cnp_edge".into(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        segment_id: None,
        principal_id: principal_id.map(str::to_string),
        tenant_id: tenant_id.map(str::to_string),
        content_digest: None,
        payload: json!({
            "protocol": protocol,
            "route_path": route_path,
            "status_code": status_code,
            "virtualization_scope": "rest_protocols",
        }),
        contract_version: 2,
    };
    append_artifact_record(state, &record);
}

pub fn cnp_edge_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys("artifact_log_v2", None)
        .map(|keys| keys.iter().filter(|k| k.starts_with("cnpedge_")).count())
        .unwrap_or(0)
}
