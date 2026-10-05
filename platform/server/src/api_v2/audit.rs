//! V2 Audit API — Audit log access
//!
//! Routes:
//!   GET    /api/v2/audit              — List audit entries
//!   GET    /api/v2/audit/:id          — Get audit entry details
//!   GET    /api/v2/audit/export       — Export audit log (OCSF format)

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use super::V2Response;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: String,
    pub timestamp: String,
    pub agent_pid: String,
    pub operation: String,
    pub outcome: String,
    pub duration_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub natural_language: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListAuditQuery {
    pub agent_id: Option<String>,
    pub operation: Option<String>,
    pub outcome: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ExportAuditQuery {
    pub format: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// GET /api/v2/audit — List audit entries
pub async fn list_audit(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ListAuditQuery>,
) -> V2Response<Vec<AuditEntry>> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    
    let entries: Vec<AuditEntry> = {
        let kernel = state.kernel.lock().unwrap();
        
        kernel.audit_log()
            .iter()
            .filter(|entry| {
                if let Some(ref agent_filter) = query.agent_id {
                    if entry.agent_pid != *agent_filter {
                        return false;
                    }
                }
                if let Some(ref op_filter) = query.operation {
                    let op_str = format!("{:?}", entry.operation);
                    if !op_str.contains(op_filter) {
                        return false;
                    }
                }
                if let Some(ref outcome_filter) = query.outcome {
                    let outcome_str = format!("{:?}", entry.outcome);
                    if !outcome_str.to_lowercase().contains(&outcome_filter.to_lowercase()) {
                        return false;
                    }
                }
                true
            })
            .skip(offset)
            .take(limit)
            .map(|entry| AuditEntry {
                audit_id: entry.audit_id.clone(),
                timestamp: super::format_iso8601(entry.timestamp),
                agent_pid: entry.agent_pid.clone(),
                operation: format!("{:?}", entry.operation),
                outcome: format!("{:?}", entry.outcome),
                duration_us: entry.duration_us.unwrap_or(0),
                target: entry.target.clone(),
                error: entry.error.clone(),
                natural_language: entry.natural_language.clone(),
            })
            .collect()
    };
    
    V2Response::success(entries)
}

/// GET /api/v2/audit/:id — Get audit entry details
pub async fn get_audit_entry(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Path(id): Path<String>,
) -> V2Response<AuditEntry> {
    let kernel = state.kernel.lock().unwrap();
    
    match kernel.audit_log().iter().find(|e| e.audit_id == id) {
        Some(entry) => {
            let audit = AuditEntry {
                audit_id: entry.audit_id.clone(),
                timestamp: super::format_iso8601(entry.timestamp),
                agent_pid: entry.agent_pid.clone(),
                operation: format!("{:?}", entry.operation),
                outcome: format!("{:?}", entry.outcome),
                duration_us: entry.duration_us.unwrap_or(0),
                target: entry.target.clone(),
                error: entry.error.clone(),
                natural_language: entry.natural_language.clone(),
            };
            V2Response::success(audit)
        }
        None => {
            V2Response {
                ok: false,
                data: None,
                error: Some(super::V2Error {
                    code: "audit_entry_not_found".to_string(),
                    message: format!("Audit entry '{}' not found", id),
                    hint: Some("Check that the audit ID is correct".to_string()),
                    reason: None,
                    example: None,
                    field: None,
                    expected: None,
                    received: None,
                    docs: "https://connector.ai/docs/errors/audit_entry_not_found".to_string(),
                    see_also: Vec::new(),
                }),
                meta: super::V2Meta::now(),
            }
        }
    }
}

/// GET /api/v2/audit/export — Export audit log
pub async fn export_audit(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    Query(query): Query<ExportAuditQuery>,
) -> V2Response<AuditExport> {
    let format = query.format.as_deref().unwrap_or("json");
    
    let entries: Vec<serde_json::Value> = {
        let kernel = state.kernel.lock().unwrap();
        
        kernel.audit_log()
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "audit_id": entry.audit_id,
                    "timestamp": entry.timestamp,
                    "agent_pid": entry.agent_pid,
                    "operation": format!("{:?}", entry.operation),
                    "outcome": format!("{:?}", entry.outcome),
                    "duration_us": entry.duration_us,
                    "target": entry.target,
                    "error": entry.error,
                    "natural_language": entry.natural_language,
                    "business_impact": entry.business_impact,
                })
            })
            .collect()
    };
    
    let export = AuditExport {
        format: format.to_string(),
        entry_count: entries.len(),
        entries,
        exported_at: super::format_iso8601(chrono::Utc::now().timestamp_millis()),
    };
    
    V2Response::success(export)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExport {
    pub format: String,
    pub entry_count: usize,
    pub entries: Vec<serde_json::Value>,
    pub exported_at: String,
}
